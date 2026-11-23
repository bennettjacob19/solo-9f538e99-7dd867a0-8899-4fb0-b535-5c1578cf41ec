"""HTTP-level integration tests using Flask's test client.

These exercise the real app stack including the background RotationWorker,
upload parsing, downloads and flash-driven redirects.
"""

import hashlib
import io
import os
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backup_app.config import Config  # noqa: E402
from backup_app.web import create_app  # noqa: E402


def make_config(base: str) -> Config:
    return Config(
        keystore_dir=os.path.join(base, "keystore"),
        volume_dir=os.path.join(base, "volumes"),
        db_path=os.path.join(base, "keystore", "backup.db"),
        rotation_interval=0.05,
        rotation_batch=2,
        max_content_length=64 * 1024 * 1024,
        prep_interval=0.05,
    )


def patterned_payload(size: int, seed: bytes = b"web-resume") -> bytes:
    block = hashlib.sha256(seed).digest()
    return (block * (size // len(block) + 1))[:size]


def stop_workers():
    for t in threading.enumerate():
        if t.name in ("rotation-worker", "prep-worker"):
            t.request_stop()
            t.join(timeout=2)


class WebFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(make_config(self.tmp.name))
        self.client = self.app.test_client()
        self.svc = self.app.extensions["backup_service"]

    def tearDown(self):
        # The worker threads are daemons; stop them explicitly for clean output.
        stop_workers()
        self.tmp.cleanup()

    def test_health_and_index(self):
        self.assertEqual(200, self.client.get("/healthz").status_code)
        page = self.client.get("/")
        self.assertEqual(200, page.status_code)
        self.assertIn("加密备份控制台".encode(), page.data)

    def test_upload_then_download_restores_bytes(self):
        payload = b"web roundtrip\n" * 32
        resp = self.client.post(
            "/backups",
            data={"file": (io.BytesIO(payload), "docs.txt")},
            content_type="multipart/form-data",
            follow_redirects=False,
        )
        self.assertEqual(302, resp.status_code)

        backups = self.svc.list_backups()
        self.assertEqual(1, len(backups))
        bid = backups[0]["id"]

        dl = self.client.get(f"/backups/{bid}/download")
        self.assertEqual(200, dl.status_code)
        self.assertEqual(payload, dl.data)
        self.assertIn("docs.txt", dl.headers["Content-Disposition"])

    def test_rotation_progress_and_key_removal_via_http(self):
        for i in range(4):
            self.client.post(
                "/backups",
                data={"file": (io.BytesIO(f"p{i}".encode() * 16), f"f{i}")},
                content_type="multipart/form-data",
            )

        # Start rotation via HTTP; the background worker drives it to done.
        resp = self.client.post("/rotations")
        self.assertEqual(302, resp.status_code)

        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.svc.current_rotation() is None:
                break
            time.sleep(0.05)
        self.assertIsNone(self.svc.current_rotation(), "worker did not finish rotation")

        keys = self.svc.list_keys()
        retired = next(k["id"] for k in keys if k["state"] == "retired")
        self.assertIn(retired, self.svc.removable_keys())

        # Removal through the real endpoint must redirect (not 500).
        resp = self.client.post(f"/keys/{retired}/remove")
        self.assertEqual(302, resp.status_code)
        self.assertEqual(1, len(self.svc.list_keys()))

        # Every backup is still downloadable with only the new master key.
        for b in self.svc.list_backups():
            dl = self.client.get(f"/backups/{b['id']}/download")
            self.assertEqual(200, dl.status_code)
            self.assertEqual(len(dl.data), 16 * 2)

    def test_starting_second_rotation_is_rejected(self):
        self.svc.start_rotation()
        resp = self.client.post("/rotations", follow_redirects=True)
        self.assertEqual(200, resp.status_code)
        self.assertIn("already in progress".encode(), resp.data)

    def test_download_unknown_id_returns_404(self):
        self.assertEqual(404, self.client.get("/backups/" + "0" * 32 + "/download").status_code)

    def test_upload_without_file_is_rejected(self):
        resp = self.client.post("/backups", data={}, content_type="multipart/form-data")
        self.assertEqual(302, resp.status_code)
        self.assertEqual(0, len(self.svc.list_backups()))


class ResumeWebTests(unittest.TestCase):
    """HTTP Range resume: preparation entry point and 206 chunk serving."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app(make_config(self.tmp.name))
        self.client = self.app.test_client()
        self.svc = self.app.extensions["backup_service"]

    def tearDown(self):
        stop_workers()
        self.tmp.cleanup()

    def _upload(self, name="dump.sql", size=288_000):
        payload = patterned_payload(size)
        resp = self.client.post(
            "/backups",
            data={"file": (io.BytesIO(payload), name)},
            content_type="multipart/form-data",
        )
        self.assertEqual(302, resp.status_code)
        return self.svc.list_backups()[0]["id"], payload

    def _wait_ready(self, bid, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.svc.get_ready_prep(bid) is not None:
                return True
            time.sleep(0.05)
        return False

    def test_range_on_unprepared_backup_uses_original_rules(self):
        bid, payload = self._upload()
        resp = self.client.get(
            f"/backups/{bid}/download", headers={"Range": "bytes=100-199"}
        )
        # Original rules: the whole ciphertext is read and verified, then
        # send_file slices the verified plaintext.
        self.assertEqual(206, resp.status_code)
        self.assertEqual(payload[100:200], resp.data)
        self.assertEqual(f"bytes 100-199/{len(payload)}", resp.headers["Content-Range"])

    def test_prepare_via_http_then_cross_boundary_206(self):
        bid, payload = self._upload()
        resp = self.client.post(f"/backups/{bid}/prepare")
        self.assertEqual(302, resp.status_code)
        self.assertTrue(self._wait_ready(bid), "background prep worker did not finish")

        # A range crossing a 64 KiB chunk boundary is served from chunks.
        resp = self.client.get(
            f"/backups/{bid}/download", headers={"Range": "bytes=65500-131100"}
        )
        self.assertEqual(206, resp.status_code)
        self.assertEqual(payload[65500:131101], resp.data)
        self.assertEqual(
            f"bytes 65500-131100/{len(payload)}", resp.headers["Content-Range"]
        )
        self.assertEqual("bytes", resp.headers["Accept-Ranges"])
        self.assertIn("dump.sql", resp.headers["Content-Disposition"])

        # Suffix and open-ended forms work too.
        resp = self.client.get(f"/backups/{bid}/download", headers={"Range": "bytes=-64"})
        self.assertEqual(206, resp.status_code)
        self.assertEqual(payload[-64:], resp.data)
        resp = self.client.get(
            f"/backups/{bid}/download",
            headers={"Range": f"bytes={len(payload) - 32}-"}
        )
        self.assertEqual(206, resp.status_code)
        self.assertEqual(payload[-32:], resp.data)

        # Full download still verifies the whole original blob.
        resp = self.client.get(f"/backups/{bid}/download")
        self.assertEqual(200, resp.status_code)
        self.assertEqual(payload, resp.data)

    def test_unsatisfiable_range_gets_416(self):
        bid, payload = self._upload()
        self.client.post(f"/backups/{bid}/prepare")
        self.assertTrue(self._wait_ready(bid))
        resp = self.client.get(
            f"/backups/{bid}/download",
            headers={"Range": f"bytes={len(payload) + 10}-"},
        )
        self.assertEqual(416, resp.status_code)
        self.assertEqual(f"bytes */{len(payload)}", resp.headers["Content-Range"])

    def test_corrupt_chunk_yields_500_and_no_plaintext(self):
        bid, payload = self._upload()
        self.client.post(f"/backups/{bid}/prepare")
        self.assertTrue(self._wait_ready(bid))
        prep = self.svc.get_ready_prep(bid)
        with open(prep["prep_path"], "r+b") as fh:
            fh.seek(20)  # inside chunk 0's record
            byte = fh.read(1)
            fh.seek(20)
            fh.write(bytes([byte[0] ^ 0xFF]))

        resp = self.client.get(
            f"/backups/{bid}/download", headers={"Range": "bytes=0-99"}
        )
        self.assertEqual(500, resp.status_code)
        self.assertNotIn(payload[:100], resp.data)  # no plaintext leaked

        # A range that only touches healthy chunks is still served.
        resp = self.client.get(
            f"/backups/{bid}/download",
            headers={"Range": f"bytes={2 * 65536}-{2 * 65536 + 49}"},
        )
        self.assertEqual(206, resp.status_code)
        self.assertEqual(payload[2 * 65536: 2 * 65536 + 50], resp.data)

        # Full download from the untouched original blob still works.
        resp = self.client.get(f"/backups/{bid}/download")
        self.assertEqual(200, resp.status_code)
        self.assertEqual(payload, resp.data)

    def test_failed_preparation_keeps_original_download(self):
        bid, payload = self._upload()
        self.svc.set_prep_paused(True)  # hold the worker while we force a failure
        try:
            self.client.post(f"/backups/{bid}/prepare")
            with mock.patch(
                "backup_app.service.crypto.encrypt", side_effect=RuntimeError("boom")
            ):
                # Drive the preparation directly; prep_tick() itself would
                # honor the pause and skip the queue.
                self.svc._run_preparation(bid)
            row = self.svc._conn().execute(
                "SELECT state FROM resume_preps WHERE backup_id = ?", (bid,)
            ).fetchone()
            self.assertEqual("failed", row["state"])

            # The original link keeps serving per the original rules.
            resp = self.client.get(f"/backups/{bid}/download")
            self.assertEqual(200, resp.status_code)
            self.assertEqual(payload, resp.data)
            resp = self.client.get(
                f"/backups/{bid}/download", headers={"Range": "bytes=0-49"}
            )
            self.assertEqual(206, resp.status_code)
            self.assertEqual(payload[:50], resp.data)
        finally:
            self.svc.set_prep_paused(False)

        # Retried via the UI entry point, the preparation then succeeds.
        self.client.post(f"/backups/{bid}/prepare")
        self.assertTrue(self._wait_ready(bid))
        resp = self.client.get(
            f"/backups/{bid}/download", headers={"Range": "bytes=65536-65635"}
        )
        self.assertEqual(206, resp.status_code)
        self.assertEqual(payload[65536:65636], resp.data)

    def test_ready_backup_resumes_after_old_key_removed(self):
        bid, payload = self._upload()
        self.client.post(f"/backups/{bid}/prepare")
        self.assertTrue(self._wait_ready(bid))

        self.client.post("/rotations")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.svc.current_rotation() is None:
                break
            time.sleep(0.05)
        self.assertIsNone(self.svc.current_rotation())
        retired = next(k["id"] for k in self.svc.list_keys() if k["state"] == "retired")
        resp = self.client.post(f"/keys/{retired}/remove")
        self.assertEqual(302, resp.status_code)

        resp = self.client.get(
            f"/backups/{bid}/download", headers={"Range": "bytes=70000-70099"}
        )
        self.assertEqual(206, resp.status_code)
        self.assertEqual(payload[70000:70100], resp.data)

    def test_pause_keeps_upload_download_rotation_working(self):
        resp = self.client.post("/prepare/pause")
        self.assertEqual(302, resp.status_code)
        try:
            # Upload still works while preparation is paused.
            bid, payload = self._upload(name="during-pause.bin", size=50_000)
            # Queued preparation does not advance.
            self.client.post(f"/backups/{bid}/prepare")
            time.sleep(0.3)
            self.assertIsNone(self.svc.get_ready_prep(bid))
            # Full download still works.
            resp = self.client.get(f"/backups/{bid}/download")
            self.assertEqual(200, resp.status_code)
            self.assertEqual(payload, resp.data)
            # Master-key rotation completes.
            self.client.post("/rotations")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if self.svc.current_rotation() is None:
                    break
                time.sleep(0.05)
            self.assertIsNone(self.svc.current_rotation(), "rotation blocked by pause")
        finally:
            self.client.post("/prepare/resume")
        # After resuming, the queued preparation completes.
        self.assertTrue(self._wait_ready(bid))
        resp = self.client.get(
            f"/backups/{bid}/download", headers={"Range": "bytes=10-19"}
        )
        self.assertEqual(206, resp.status_code)
        self.assertEqual(payload[10:20], resp.data)

    def test_prepare_unknown_backup_404(self):
        resp = self.client.post("/backups/" + "0" * 32 + "/prepare")
        self.assertEqual(404, resp.status_code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
