"""End-to-end tests for the encrypted backup service.

Run with the project virtualenv::

    .venv/bin/python -I -m unittest -v tests.test_service
"""

import hashlib
import os
import sys
import tempfile
import unittest
from unittest import mock

# Keep the suite usable under ``python -I`` (isolated mode): the tests
# directory's parent is the project root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backup_app.config import Config  # noqa: E402
from backup_app.service import (  # noqa: E402
    RESUME_CHUNK_SIZE,
    RESUME_RECORD_SIZE,
    KeyRemovalError,
    ResumeCorruptError,
    RotationInProgress,
    Service,
)


def make_config(base: str) -> Config:
    return Config(
        keystore_dir=os.path.join(base, "keystore"),
        volume_dir=os.path.join(base, "volumes"),
        db_path=os.path.join(base, "keystore", "backup.db"),
        rotation_interval=0.05,
        rotation_batch=2,
        max_content_length=64 * 1024 * 1024,
    )


def patterned_payload(size: int, seed: bytes = b"resume-seed") -> bytes:
    """Deterministic non-repeating bytes so slice comparisons are meaningful."""
    block = hashlib.sha256(seed).digest()
    return (block * (size // len(block) + 1))[:size]


class ServiceTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = make_config(self.tmp.name)
        self.svc = Service(self.cfg)

    def tearDown(self):
        self.tmp.cleanup()

    def upload(self, name, content):
        return self.svc.upload_backup(name, content)


class RoundtripTests(ServiceTestBase):
    def test_bootstrap_creates_single_active_kek(self):
        keys = self.svc.list_keys()
        self.assertEqual(1, len(keys))
        self.assertEqual("active", keys[0]["state"])
        # Raw key file exists with restricted permissions; DB holds no keys.
        files = os.listdir(self.cfg.keystore_dir)
        kek_files = [f for f in files if f.endswith(".kek")]
        self.assertEqual(1, len(kek_files))
        mode = os.stat(os.path.join(self.cfg.keystore_dir, kek_files[0])).st_mode & 0o777
        self.assertEqual(0o600, mode)

    def test_upload_download_roundtrip_restores_original(self):
        payload = b"hello encrypted world\n" * 100
        backup_id = self.upload("report.txt", payload)
        filename, restored = self.svc.download_backup(backup_id)
        self.assertEqual("report.txt", filename)
        self.assertEqual(payload, restored)

    def test_each_backup_has_independent_dek_and_distinct_blob(self):
        ids = [self.upload(f"f{i}.dat", b"same content" * 10) for i in range(3)]
        blobs = [
            open(os.path.join(self.cfg.volume_dir, bid + ".blob"), "rb").read()
            for bid in ids
        ]
        # GCM random nonce + unique DEK: identical plaintexts differ on disk.
        self.assertEqual(len(set(blobs)), 3)
        # Every blob lives on the volume, every wrapped DEK on the keystore DB.
        self.assertEqual([], [f for f in os.listdir(self.cfg.keystore_dir) if f.endswith(".blob")])
        self.assertEqual(3, len(os.listdir(self.cfg.volume_dir)))

    def test_tampered_blob_is_rejected(self):
        backup_id = self.upload("f.bin", b"integrity matters")
        path = os.path.join(self.cfg.volume_dir, backup_id + ".blob")
        with open(path, "r+b") as fh:
            fh.seek(-5, os.SEEK_END)
            fh.write(b"XXXXX")
        with self.assertRaises(Exception):
            self.svc.download_backup(backup_id)


class RotationTests(ServiceTestBase):
    def test_rotation_does_not_rewrite_ciphertext_blobs(self):
        payload = b"rotation must not touch my body" * 50
        backup_id = self.upload("body.txt", payload)
        blob_path = os.path.join(self.cfg.volume_dir, backup_id + ".blob")
        before = open(blob_path, "rb").read()
        mtime_before = os.stat(blob_path).st_mtime_ns

        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()

        after = open(blob_path, "rb").read()
        self.assertEqual(before, after)
        self.assertEqual(mtime_before, os.stat(blob_path).st_mtime_ns)
        # Still restores perfectly.
        _, restored = self.svc.download_backup(backup_id)
        self.assertEqual(payload, restored)

    def test_full_rotation_wraps_every_backup_with_new_kek(self):
        for i in range(5):
            self.upload(f"f{i}.log", f"payload-{i}".encode() * 20)

        job = self.svc.start_rotation()
        # Drive the worker logic manually in small batches.
        ticks = 0
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
            ticks += 1
            self.assertLess(ticks, 100)

        job_row = self.svc.get_key  # sanity: method exists
        self.assertIsNotNone(job_row)
        keys = {k["id"]: k for k in self.svc.list_keys()}
        self.assertEqual(2, len(keys))
        active = [k for k in keys.values() if k["state"] == "active"]
        retired = [k for k in keys.values() if k["state"] == "retired"]
        self.assertEqual(1, len(active))
        self.assertEqual(1, len(retired))

        # Each backup is recoverable under BOTH KEKs while the old file exists.
        for b in self.svc.list_backups():
            self.assertEqual(2, len(b["kek_ids"]))
            self.assertIn(active[0]["id"], b["kek_ids"])
            self.assertIn(retired[0]["id"], b["kek_ids"])
            # Recovery explicitly through the new KEK works.
            self._assert_recoverable_with(b["id"], active[0]["id"])

    def _assert_recoverable_with(self, backup_id, kek_id):
        import sqlite3

        from backup_app import crypto
        from backup_app.db import connect

        conn = connect(self.cfg.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM backups WHERE id = ?", (backup_id,)
            ).fetchone()
            wrap = conn.execute(
                "SELECT * FROM wrapped_keys WHERE backup_id = ? AND kek_id = ?",
                (backup_id, kek_id),
            ).fetchone()
            self.assertIsNotNone(wrap, "new KEK wrapper missing")
            kek = self.svc.keystore.load(kek_id)
            dek = crypto.unwrap_dek(kek, wrap["wrapped_dek"], backup_id, kek_id)
            with open(row["blob_path"], "rb") as fh:
                plaintext = crypto.decrypt(dek, fh.read(), crypto.file_aad(backup_id))
            self.assertGreater(len(plaintext), 0)
        finally:
            conn.close()

    def test_upload_during_rotation_uses_only_new_kek(self):
        old_backup = self.upload("old.txt", b"before rotation")
        self.svc.start_rotation()
        # Rotation exists but nothing processed yet.
        self.svc.rotation_tick(limit=1)

        # New upload while rotation is running: must go straight to the new KEK.
        new_backup = self.upload("new.txt", b"after rotation start")
        new_meta = next(b for b in self.svc.list_backups() if b["id"] == new_backup)
        old_meta = next(b for b in self.svc.list_backups() if b["id"] == old_backup)

        active = next(k for k in self.svc.list_keys() if k["state"] == "active")
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        self.assertEqual([active["id"]], new_meta["kek_ids"])
        self.assertNotIn(retired["id"], new_meta["kek_ids"])

        # Finish the rotation; the new backup must not have been counted into it.
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        job = self.svc._conn().execute(
            "SELECT * FROM rotation_jobs ORDER BY created_at LIMIT 1"
        ).fetchone()
        self.assertEqual(1, job["total_backups"])  # only the pre-rotation backup
        self.assertEqual(1, job["processed"])
        # And both downloads still work.
        self.assertEqual(b"before rotation", self.svc.download_backup(old_backup)[1])
        self.assertEqual(b"after rotation start", self.svc.download_backup(new_backup)[1])

    def test_cannot_start_two_rotations(self):
        self.upload("a.txt", b"a")
        self.svc.start_rotation()
        with self.assertRaises(RotationInProgress):
            self.svc.start_rotation()

    def test_rotation_resumes_after_simulated_process_restart(self):
        for i in range(6):
            self.upload(f"f{i}.dat", f"x{i}".encode() * 32)
        self.svc.start_rotation()
        self.svc.rotation_tick(limit=2)  # partial progress, then "crash"

        # A brand-new Service instance over the same files = process restart.
        svc2 = Service(self.cfg)
        job = svc2.current_rotation()
        self.assertIsNotNone(job, "rotation must survive restart")
        self.assertEqual("running", job["state"])
        self.assertEqual(2, job["processed"])

        while svc2.current_rotation() is not None:
            svc2.rotation_tick()

        for b in svc2.list_backups():
            active = next(k for k in svc2.list_keys() if k["state"] == "active")
            self.assertIn(active["id"], b["kek_ids"])
            svc2.download_backup(b["id"])  # full recovery works post-restart

    def test_interrupted_tick_is_idempotent(self):
        # Two backups; run a tick of one, then repeat: wrappers must not
        # duplicate and counters stay consistent.
        self.upload("a", b"aa")
        self.upload("b", b"bb")
        self.svc.start_rotation()
        self.svc.rotation_tick(limit=1)
        self.svc.rotation_tick(limit=1)
        self.svc.rotation_tick(limit=10)  # completion tick

        conn = self.svc._conn()
        counts = conn.execute(
            "SELECT backup_id, COUNT(*) AS n FROM wrapped_keys GROUP BY backup_id"
        ).fetchall()
        self.assertTrue(all(r["n"] == 2 for r in counts))
        job = conn.execute("SELECT * FROM rotation_jobs").fetchone()
        self.assertEqual("completed", job["state"])
        self.assertEqual(2, job["processed"])


class KeyRemovalTests(ServiceTestBase):
    def test_old_kek_cannot_be_removed_before_rotation_finishes(self):
        self.upload("a", b"a")
        self.svc.start_rotation()
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        with self.assertRaises(KeyRemovalError):
            self.svc.remove_key(retired["id"])
        self.assertNotIn(retired["id"], self.svc.removable_keys())

    def test_old_kek_removable_only_after_all_backups_have_new_wrapper(self):
        for i in range(3):
            self.upload(f"f{i}", f"p{i}".encode() * 8)
        self.svc.start_rotation()
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        active = next(k for k in self.svc.list_keys() if k["state"] == "active")
        self.assertNotIn(retired["id"], self.svc.removable_keys())

        self.svc.rotation_tick(limit=1)
        self.assertNotIn(retired["id"], self.svc.removable_keys())

        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        self.assertIn(retired["id"], self.svc.removable_keys())
        self.assertNotIn(active["id"], self.svc.removable_keys())  # active stays protected

    def test_removal_shreds_key_and_recovery_still_works_with_new_kek(self):
        payload = b"recover me after old key is gone"
        bid = self.upload("keep.bin", payload)
        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        old_path = self.svc.keystore._path(retired["id"])
        self.assertTrue(os.path.exists(old_path))

        self.svc.remove_key(retired["id"])

        self.assertFalse(os.path.exists(old_path))
        keys = self.svc.list_keys()
        self.assertEqual(1, len(keys))
        self.assertEqual("active", keys[0]["state"])
        # No wrapped row still references the destroyed KEK.
        leftovers = self.svc._conn().execute(
            "SELECT COUNT(*) AS n FROM wrapped_keys WHERE kek_id = ?", (retired["id"],)
        ).fetchone()["n"]
        self.assertEqual(0, leftovers)
        # The backup is still fully recoverable with the new master key.
        name, restored = self.svc.download_backup(bid)
        self.assertEqual(payload, restored)

    def test_active_kek_cannot_be_removed(self):
        active = next(k for k in self.svc.list_keys() if k["state"] == "active")
        with self.assertRaises(KeyRemovalError):
            self.svc.remove_key(active["id"])

    def test_remove_unknown_key(self):
        with self.assertRaises(KeyRemovalError):
            self.svc.remove_key("deadbeef" * 4)


class StorageSeparationTests(ServiceTestBase):
    def test_keystore_and_volume_hold_disjoint_material(self):
        self.upload("a", b"a" * 64)
        self.upload("b", b"b" * 64)
        keystore = set(os.listdir(self.cfg.keystore_dir))
        volume = set(os.listdir(self.cfg.volume_dir))
        # Ciphertext payloads only on the backup volume.
        self.assertTrue(all(f.endswith(".blob") for f in volume))
        self.assertEqual(2, len(volume))
        # Master keys + SQLite files only in the keystore.
        self.assertTrue(any(f.endswith(".kek") for f in keystore))
        self.assertIn("backup.db", keystore)
        self.assertTrue(keystore.isdisjoint(volume))

    def test_second_generation_rotation_then_remove_first_kek(self):
        # KEK1 -> rotate to KEK2, remove KEK1 -> rotate to KEK3, remove KEK2.
        first = self.upload("gen1", b"first generation")
        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        kek1_id = next(k["id"] for k in self.svc.list_keys() if k["state"] == "retired")
        self.svc.remove_key(kek1_id)

        second = self.upload("gen2", b"second generation")
        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        kek2_id = next(k["id"] for k in self.svc.list_keys() if k["state"] == "retired")
        # gen1 backup was wrapped under KEK2 and now needs a KEK3 wrapper before
        # KEK2 removal — the rotation job covers it automatically.
        self.svc.remove_key(kek2_id)

        self.assertEqual(b"first generation", self.svc.download_backup(first)[1])
        self.assertEqual(b"second generation", self.svc.download_backup(second)[1])
        self.assertEqual(1, len(self.svc.list_keys()))


class ResumePrepTests(ServiceTestBase):
    """Range-resume preparation: chunked re-encryption for partial downloads."""

    def _prepare(self, name="dump.bin", payload=None, size=200 * 1024 + 13):
        payload = patterned_payload(size) if payload is None else payload
        bid = self.upload(name, payload)
        self.assertEqual("preparing", self.svc.request_prepare(bid))
        self.assertEqual(1, self.svc.prep_tick())
        prep = self.svc.get_ready_prep(bid)
        self.assertIsNotNone(prep)
        self.assertEqual("ready", prep["state"])
        return bid, payload, prep

    def test_prepare_then_cross_chunk_range_roundtrip(self):
        bid, payload, prep = self._prepare()
        self.assertEqual(4, prep["chunk_count"])  # 200 KiB + 13 over 64 KiB chunks
        ranges = [
            (0, 1),                                    # first byte
            (0, len(payload)),                         # whole file via chunks
            (65500, 65536 + 65500),                    # crosses chunk boundary
            (RESUME_CHUNK_SIZE, 2 * RESUME_CHUNK_SIZE),  # exactly one chunk
            (12345, 12345 + 65536),                    # unaligned 64 KiB
            (len(payload) - 10, len(payload)),         # tail of last chunk
        ]
        for start, stop in ranges:
            self.assertEqual(
                payload[start:stop],
                self.svc.download_range(bid, start, stop),
                f"range {start}-{stop} mismatch",
            )

    def test_single_chunk_and_boundary_sized_files(self):
        for size in (1, RESUME_CHUNK_SIZE, RESUME_CHUNK_SIZE + 1, 2 * RESUME_CHUNK_SIZE):
            payload = patterned_payload(size, seed=f"s{size}".encode())
            bid = self.upload(f"f{size}", payload)
            self.svc.request_prepare(bid)
            self.svc.prep_tick()
            self.assertEqual(payload, self.svc.download_range(bid, 0, size))
            if size > 100:
                self.assertEqual(
                    payload[size - 100:], self.svc.download_range(bid, size - 100, size)
                )

    def test_range_read_amplification_bounded(self):
        # A contiguous 64 KiB request against a 15 MiB prepared backup must
        # read at most 512 KiB of ciphertext from the volume.
        size = 15 * 1024 * 1024
        bid, payload, _ = self._prepare(name="big.bin", size=size)
        reads = []
        real_read_at = Service._read_at

        def counting_read_at(fh, offset, length):
            reads.append(length)
            return real_read_at(fh, offset, length)

        offsets = [0, 1, 65536, 100_000, 7 * 1024 * 1024 + 123, size - 65536, size - 1]
        with mock.patch.object(Service, "_read_at", staticmethod(counting_read_at)):
            for off in offsets:
                stop = min(off + 65536, size)
                reads.clear()
                got = self.svc.download_range(bid, off, stop)
                self.assertEqual(payload[off:stop], got)
                self.assertLessEqual(
                    sum(reads), 512 * 1024, f"range at {off} read {sum(reads)} bytes"
                )
                # Sanity: two 64 KiB records are the worst case here.
                self.assertLessEqual(len(reads), 2)

    def test_prep_disk_overhead_bounded(self):
        bid, _, prep = self._prepare()
        blob_size = os.path.getsize(os.path.join(self.cfg.volume_dir, bid + ".blob"))
        prep_size = os.path.getsize(prep["prep_path"])
        self.assertLessEqual(prep_size, blob_size + 64 * 1024)
        # And no third file appeared on the volume.
        self.assertEqual(
            {bid + ".blob", bid + ".prep"}, set(os.listdir(self.cfg.volume_dir))
        )

    def test_preparation_does_not_touch_original_blob(self):
        payload = patterned_payload(100_000)
        bid = self.upload("keep.bin", payload)
        blob_path = os.path.join(self.cfg.volume_dir, bid + ".blob")
        with open(blob_path, "rb") as fh:
            before = fh.read()
        mtime = os.stat(blob_path).st_mtime_ns
        self.svc.request_prepare(bid)
        self.svc.prep_tick()
        with open(blob_path, "rb") as fh:
            self.assertEqual(before, fh.read())
        self.assertEqual(mtime, os.stat(blob_path).st_mtime_ns)

    def test_ready_prep_survives_restart(self):
        bid, payload, _ = self._prepare()
        svc2 = Service(self.cfg)  # simulated process restart
        self.assertIsNotNone(svc2.get_ready_prep(bid))
        self.assertEqual(payload[100:70000], svc2.download_range(bid, 100, 70000))

    def test_interrupted_preparation_retried_after_restart(self):
        payload = patterned_payload(150_000)
        bid = self.upload("crash.bin", payload)
        self.svc.request_prepare(bid)
        # Simulate a crash mid-write: a stale temp file plus a 'preparing' row.
        tmp_path = os.path.join(self.cfg.volume_dir, bid + ".prep.tmp")
        with open(tmp_path, "wb") as fh:
            fh.write(b"partial junk")
        prep_path = os.path.join(self.cfg.volume_dir, bid + ".prep")
        with open(prep_path, "wb") as fh:
            fh.write(b"stale output from killed run")

        svc2 = Service(self.cfg)  # restart cleans the leftovers
        self.assertFalse(os.path.exists(tmp_path))
        self.assertFalse(os.path.exists(prep_path))
        row = svc2._conn().execute(
            "SELECT state FROM resume_preps WHERE backup_id = ?", (bid,)
        ).fetchone()
        self.assertEqual("preparing", row["state"])  # retryable, not failed

        svc2.prep_tick()
        self.assertIsNotNone(svc2.get_ready_prep(bid))
        self.assertEqual(payload[10:80_000], svc2.download_range(bid, 10, 80_000))
        # The original download rules worked the whole time.
        self.assertEqual(payload, svc2.download_backup(bid)[1])

    def test_failed_preparation_keeps_full_download_and_retry(self):
        payload = patterned_payload(90_000)
        bid = self.upload("fragile.bin", payload)
        self.svc.request_prepare(bid)
        with mock.patch(
            "backup_app.service.crypto.encrypt", side_effect=RuntimeError("boom")
        ):
            self.svc.prep_tick()
        self.assertIsNone(self.svc.get_ready_prep(bid))
        row = self.svc._conn().execute(
            "SELECT state, error FROM resume_preps WHERE backup_id = ?", (bid,)
        ).fetchone()
        self.assertEqual("failed", row["state"])
        self.assertIn("boom", row["error"])
        # Original full download is unaffected by the failed preparation.
        self.assertEqual(payload, self.svc.download_backup(bid)[1])
        # No leftover temp/prep files after the failure.
        self.assertEqual([bid + ".blob"], os.listdir(self.cfg.volume_dir))
        # Retry succeeds.
        self.assertEqual("preparing", self.svc.request_prepare(bid))
        self.svc.prep_tick()
        self.assertIsNotNone(self.svc.get_ready_prep(bid))
        self.assertEqual(payload[:500], self.svc.download_range(bid, 0, 500))

    def test_corrupt_chunk_only_affects_overlapping_ranges(self):
        bid, payload, prep = self._prepare()
        # Flip one byte inside chunk 1's record on the volume.
        with open(prep["prep_path"], "r+b") as fh:
            fh.seek(RESUME_RECORD_SIZE + 20)
            byte = fh.read(1)
            fh.seek(RESUME_RECORD_SIZE + 20)
            fh.write(bytes([byte[0] ^ 0xFF]))

        with self.assertRaises(ResumeCorruptError):
            self.svc.download_range(bid, RESUME_CHUNK_SIZE, RESUME_CHUNK_SIZE + 1)
        # A range merely touching chunk 1 at its edge fails too...
        with self.assertRaises(ResumeCorruptError):
            self.svc.download_range(bid, RESUME_CHUNK_SIZE - 1, RESUME_CHUNK_SIZE + 1)
        # ...but ranges confined to healthy chunks are served normally.
        self.assertEqual(payload[0:100], self.svc.download_range(bid, 0, 100))
        self.assertEqual(
            payload[2 * RESUME_CHUNK_SIZE: 2 * RESUME_CHUNK_SIZE + 50],
            self.svc.download_range(bid, 2 * RESUME_CHUNK_SIZE, 2 * RESUME_CHUNK_SIZE + 50),
        )
        # The original blob is untouched: full download still verifies.
        self.assertEqual(payload, self.svc.download_backup(bid)[1])

    def test_old_kek_removal_keeps_resume_working(self):
        bid, payload, _ = self._prepare()
        self.svc.start_rotation()
        while self.svc.current_rotation() is not None:
            self.svc.rotation_tick()
        retired = next(k for k in self.svc.list_keys() if k["state"] == "retired")
        self.svc.remove_key(retired["id"])
        # Prepared chunks are encrypted under the backup DEK, which rotation
        # rewraps: resume keeps working with only the new master key.
        self.assertEqual(
            payload[65536:65636], self.svc.download_range(bid, 65536, 65636)
        )
        self.assertEqual(payload, self.svc.download_backup(bid)[1])

    def test_pause_blocks_prep_but_not_core_operations(self):
        bid, payload, _ = self._prepare()
        self.svc.set_prep_paused(True)
        try:
            # Queued preparations do not run while paused.
            payload2 = patterned_payload(5_000, seed=b"second")
            bid2 = self.upload("second.bin", payload2)  # upload works
            self.svc.request_prepare(bid2)
            self.assertEqual(0, self.svc.prep_tick())
            self.assertIsNone(self.svc.get_ready_prep(bid2))
            # Full downloads work.
            self.assertEqual(payload, self.svc.download_backup(bid)[1])
            # Ranged resume of an already-ready backup works.
            self.assertEqual(payload[5:55], self.svc.download_range(bid, 5, 55))
            # Master-key rotation runs to completion.
            self.svc.start_rotation()
            while self.svc.current_rotation() is not None:
                self.svc.rotation_tick()
            self.assertEqual(payload2, self.svc.download_backup(bid2)[1])
        finally:
            self.svc.set_prep_paused(False)
        # Unpaused: the queued preparation completes.
        self.assertEqual(1, self.svc.prep_tick())
        self.assertIsNotNone(self.svc.get_ready_prep(bid2))

    def test_pause_state_persists_across_restart(self):
        self.svc.set_prep_paused(True)
        svc2 = Service(self.cfg)
        self.assertTrue(svc2.prep_paused())
        svc2.set_prep_paused(False)
        self.assertFalse(Service(self.cfg).prep_paused())

    def test_no_plaintext_lands_on_either_volume(self):
        payload = b"A" * 200_000  # highly recognizable plaintext
        bid = self.upload("plain.bin", payload)
        self.svc.request_prepare(bid)
        self.svc.prep_tick()
        self.assertIsNotNone(self.svc.get_ready_prep(bid))
        marker = b"A" * 1024
        for directory in (self.cfg.volume_dir, self.cfg.keystore_dir):
            for name in os.listdir(directory):
                if name.endswith((".db-wal", ".db-shm")):
                    continue
                with open(os.path.join(directory, name), "rb") as fh:
                    self.assertNotIn(marker, fh.read(), f"plaintext leaked into {name}")

    def test_request_prepare_unknown_backup(self):
        with self.assertRaises(KeyError):
            self.svc.request_prepare("0" * 32)

    def test_range_rejected_when_not_ready(self):
        from backup_app.service import ResumeNotReady

        bid = self.upload("plain.bin", b"x" * 100)
        with self.assertRaises(ResumeNotReady):
            self.svc.download_range(bid, 0, 10)


if __name__ == "__main__":
    unittest.main(verbosity=2)
