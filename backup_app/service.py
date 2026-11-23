"""Backup service: upload/download plus master-key rotation lifecycle.

Design summary
--------------
* Each backup gets a unique DEK; the ciphertext blob is written once and is
  never rewritten during rotation.
* A DEK may have several wrapped copies, one per KEK that can recover the
  backup.  Rotation adds a copy under the new KEK; removing an old KEK deletes
  the copies under it.
* Rotation progress is fully persisted in ``rotation_jobs`` and
  ``wrapped_keys``.  A process restart resumes the same job; rewrapping a
  backup is idempotent thanks to the ``(backup_id, kek_id)`` unique index.
* Backups created after a rotation starts are encrypted directly under the
  new active KEK and never count into the rotation totals.

Resume preparation
------------------
Downloads of a prepared backup can serve HTTP Range requests by reading only
the ciphertext chunks that overlap the range.  Preparation re-encrypts the
verified plaintext into independent per-chunk GCM records (same DEK, so
rotation and old-key removal are unaffected) stored as ``<id>.prep`` on the
ciphertext volume.  A backup is served from chunks only while its
``resume_preps`` row says ``ready``; every other state falls back to the
original whole-blob download rules.  The original blob is never modified.
"""

import hashlib
import logging
import os
import threading
import uuid
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag

from . import crypto
from .db import connect, init_db
from .keystore import KeyStore

log = logging.getLogger(__name__)

# Plaintext bytes per prepared chunk.  Each stored record adds a 12-byte
# nonce and a 16-byte GCM tag, so a contiguous 64 KiB range request touches
# at most two records (~128 KiB of ciphertext), far below the 512 KiB read
# budget, and the whole prepared file stays within (original blob + 64 KiB)
# for any backup up to the 16 MiB upload limit.
RESUME_CHUNK_SIZE = 64 * 1024
GCM_TAG_SIZE = 16
RESUME_RECORD_OVERHEAD = crypto.NONCE_SIZE + GCM_TAG_SIZE
RESUME_RECORD_SIZE = RESUME_CHUNK_SIZE + RESUME_RECORD_OVERHEAD

PREP_SUFFIX = ".prep"
PREP_TMP_SUFFIX = ".prep.tmp"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id() -> str:
    return uuid.uuid4().hex


class RotationInProgress(Exception):
    pass


class KeyRemovalError(Exception):
    pass


class ResumeNotReady(Exception):
    """The backup has no usable prepared chunk file (yet)."""


class ResumeCorruptError(Exception):
    """A prepared chunk failed authentication or the chunk file is damaged."""


class Service:
    def __init__(self, config):
        self.config = config
        os.makedirs(config.volume_dir, exist_ok=True)
        self.keystore = KeyStore(config.keystore_dir)
        # Serializes writer transactions across request threads and the
        # background rotation worker. SQLite serializes the file itself; this
        # lock keeps multi-statement workflows coherent at the application
        # level.
        self._write_lock = threading.RLock()
        with connect(config.db_path) as conn:
            init_db(conn)
        self._cleanup_interrupted_preps()
        self.bootstrap()

    # ------------------------------------------------------------------ basics

    def _conn(self):
        return connect(self.config.db_path)

    def bootstrap(self) -> None:
        """Create the first master key on a brand-new deployment."""
        with self._write_lock, self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM master_keys").fetchone()
            if row["n"] == 0:
                key_id = new_id()
                self.keystore.generate(key_id)
                conn.execute(
                    "INSERT INTO master_keys (id, created_at, state) VALUES (?, ?, 'active')",
                    (key_id, utcnow()),
                )
                conn.commit()
                log.info("bootstrapped initial master key %s", key_id)

    def list_keys(self):
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT mk.*,
                       (SELECT COUNT(*) FROM wrapped_keys wk WHERE wk.kek_id = mk.id) AS wrap_count
                FROM master_keys mk ORDER BY mk.created_at
                """
            ).fetchall()
            return [dict(r) for r in rows]

    def get_active_kek(self, conn):
        row = conn.execute(
            "SELECT * FROM master_keys WHERE state = 'active' ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise RuntimeError("no active master key available")
        return dict(row)

    def get_key(self, key_id: str):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM master_keys WHERE id = ?", (key_id,)
            ).fetchone()
            return dict(row) if row else None

    # ------------------------------------------------------------------ upload

    def upload_backup(self, filename: str, data: bytes) -> str:
        if not filename:
            raise ValueError("filename is required")
        if len(data) == 0:
            raise ValueError("empty uploads are not allowed")
        filename = os.path.basename(filename)
        backup_id = new_id()

        with self._write_lock, self._conn() as conn:
            active = self.get_active_kek(conn)
            kek = self.keystore.load(active["id"])

            # Independent DEK per backup.
            dek = crypto.generate_key()
            blob = crypto.encrypt(dek, data, crypto.file_aad(backup_id))
            digest = hashlib.sha256(data).hexdigest()

            blob_path = os.path.join(self.config.volume_dir, backup_id + ".blob")
            self._write_blob(blob_path, blob)

            wrapped = crypto.wrap_dek(kek, dek, backup_id, active["id"])
            conn.execute(
                "INSERT INTO backups (id, filename, blob_path, size_bytes, sha256, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (backup_id, filename, blob_path, len(data), digest, utcnow()),
            )
            conn.execute(
                "INSERT INTO wrapped_keys (backup_id, kek_id, wrapped_dek, created_at)"
                " VALUES (?, ?, ?, ?)",
                (backup_id, active["id"], wrapped, utcnow()),
            )
            conn.commit()
        return backup_id

    @staticmethod
    def _write_blob(path: str, blob: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, blob)
            os.fsync(fd)
        finally:
            os.close(fd)

    # ---------------------------------------------------------------- download

    def list_backups(self):
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT b.*,
                       (SELECT GROUP_CONCAT(wk.kek_id)
                          FROM wrapped_keys wk WHERE wk.backup_id = b.id) AS kek_ids,
                       rp.state AS prep_state,
                       rp.error AS prep_error
                FROM backups b
                LEFT JOIN resume_preps rp ON rp.backup_id = b.id
                ORDER BY b.created_at DESC
                """
            ).fetchall()
            result = []
            for r in rows:
                item = dict(r)
                item["kek_ids"] = (r["kek_ids"] or "").split(",") if r["kek_ids"] else []
                result.append(item)
            return result

    def get_backup(self, backup_id: str):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM backups WHERE id = ?", (backup_id,)
            ).fetchone()
            return dict(row) if row else None

    def _unwrap_dek(self, conn, backup_id: str) -> bytes:
        """Recover a backup's DEK from any locally usable KEK wrapper."""
        wraps = conn.execute(
            "SELECT * FROM wrapped_keys WHERE backup_id = ? ORDER BY id",
            (backup_id,),
        ).fetchall()
        if not wraps:
            raise RuntimeError(f"backup {backup_id} has no wrapped data keys")

        last_error = None
        # Try every wrapper: with a rotation in progress the newest KEK may
        # not yet cover an old backup, so prefer whatever is locally
        # available and valid.
        for wrap in wraps:
            if not self.keystore.exists(wrap["kek_id"]):
                continue
            try:
                kek = self.keystore.load(wrap["kek_id"])
                return crypto.unwrap_dek(
                    kek, wrap["wrapped_dek"], backup_id, wrap["kek_id"]
                )
            except Exception as exc:  # InvalidTag etc.
                last_error = exc
                continue
        raise RuntimeError(
            f"no usable master key for backup {backup_id}: {last_error}"
        )

    def download_backup(self, backup_id: str):
        with self._write_lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM backups WHERE id = ?", (backup_id,)
            ).fetchone()
            if row is None:
                return None
            backup = dict(row)
            dek = self._unwrap_dek(conn, backup_id)

            with open(backup["blob_path"], "rb") as fh:
                stored = fh.read()
            plaintext = crypto.decrypt(dek, stored, crypto.file_aad(backup_id))
            if hashlib.sha256(plaintext).hexdigest() != backup["sha256"]:
                raise RuntimeError(f"integrity check failed for backup {backup_id}")
            return backup["filename"], plaintext

    # ------------------------------------------------------ resume preparation

    def _prep_path(self, backup_id: str) -> str:
        return os.path.join(self.config.volume_dir, backup_id + PREP_SUFFIX)

    def _cleanup_interrupted_preps(self) -> None:
        """Remove preparation leftovers that can never become valid.

        Runs once at startup (before any worker starts).  ``*.prep.tmp``
        files are crash leftovers by definition; a ``*.prep`` file only
        counts when its database row says ``ready`` — anything else is
        rewritten by the next preparation run, so delete it now to keep the
        extra disk usage bounded by one prepared file per backup.
        """
        with self._write_lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT state, prep_path FROM resume_preps"
            ).fetchall()
        keep = {r["prep_path"] for r in rows if r["state"] == "ready"}
        try:
            names = os.listdir(self.config.volume_dir)
        except FileNotFoundError:
            return
        for name in names:
            path = os.path.join(self.config.volume_dir, name)
            if name.endswith(PREP_TMP_SUFFIX):
                self._remove_quietly(path)
            elif name.endswith(PREP_SUFFIX) and path not in keep:
                self._remove_quietly(path)

    @staticmethod
    def _remove_quietly(path: str) -> None:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError:
            log.warning("could not remove stale preparation file %s", path)

    def prep_paused(self) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = 'prep_paused'"
            ).fetchone()
            return row is not None and row["value"] == "1"

    def set_prep_paused(self, paused: bool) -> None:
        with self._write_lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES ('prep_paused', ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                ("1" if paused else "0",),
            )
            conn.commit()

    def request_prepare(self, backup_id: str) -> str:
        """Queue a backup for resume preparation; returns the row's state.

        Idempotent: a backup that is already queued or ready keeps its
        state.  Failed preparations are reset to ``preparing`` so the worker
        retries them.
        """
        with self._write_lock, self._conn() as conn:
            backup = conn.execute(
                "SELECT sha256 FROM backups WHERE id = ?", (backup_id,)
            ).fetchone()
            if backup is None:
                raise KeyError(backup_id)
            row = conn.execute(
                "SELECT state FROM resume_preps WHERE backup_id = ?", (backup_id,)
            ).fetchone()
            if row is not None and row["state"] in ("preparing", "ready"):
                return row["state"]
            now = utcnow()
            conn.execute(
                """
                INSERT INTO resume_preps
                    (backup_id, state, chunk_size, chunk_count, prep_path,
                     sha256, error, created_at, updated_at)
                VALUES (?, 'preparing', ?, 0, ?, ?, NULL, ?, ?)
                ON CONFLICT(backup_id) DO UPDATE SET
                    state = 'preparing',
                    chunk_size = excluded.chunk_size,
                    chunk_count = 0,
                    prep_path = excluded.prep_path,
                    sha256 = excluded.sha256,
                    error = NULL,
                    updated_at = excluded.updated_at
                """,
                (
                    backup_id,
                    RESUME_CHUNK_SIZE,
                    self._prep_path(backup_id),
                    backup["sha256"],
                    now,
                    now,
                ),
            )
            conn.commit()
        return "preparing"

    def prep_tick(self, limit: int = 1) -> int:
        """Prepare up to ``limit`` queued backups; returns how many ran.

        Never raises out of a single backup's failure — the row is marked
        ``failed`` instead and the original download rules keep applying.
        """
        if self.prep_paused():
            return 0
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT backup_id FROM resume_preps WHERE state = 'preparing'"
                " ORDER BY created_at, backup_id LIMIT ?",
                (limit,),
            ).fetchall()
        done = 0
        for row in rows:
            if self.prep_paused():
                break
            self._run_preparation(row["backup_id"])
            done += 1
        return done

    def _run_preparation(self, backup_id: str) -> None:
        prep_path = self._prep_path(backup_id)
        tmp_path = prep_path + ".tmp"
        try:
            # Short read-only transaction; the heavy crypto below runs
            # outside every lock so uploads, downloads and rotation proceed.
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM backups WHERE id = ?", (backup_id,)
                ).fetchone()
                if row is None:
                    self._fail_prep(backup_id, "backup no longer exists")
                    return
                backup = dict(row)
                dek = self._unwrap_dek(conn, backup_id)

            # Verify the original first: the whole blob must decrypt and
            # match the recorded digest before anything is prepared.
            with open(backup["blob_path"], "rb") as fh:
                stored = fh.read()
            plaintext = crypto.decrypt(dek, stored, crypto.file_aad(backup_id))
            if hashlib.sha256(plaintext).hexdigest() != backup["sha256"]:
                raise RuntimeError("integrity check failed during preparation")

            size = len(plaintext)
            chunk_count = max(1, (size + RESUME_CHUNK_SIZE - 1) // RESUME_CHUNK_SIZE)

            # Bound the extra disk usage: drop any previous output before
            # writing the new one, so at most one prepared file per backup
            # (plus its in-flight temp file) ever exists.
            self._remove_quietly(tmp_path)
            self._remove_quietly(prep_path)

            fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                for idx in range(chunk_count):
                    chunk = plaintext[
                        idx * RESUME_CHUNK_SIZE: (idx + 1) * RESUME_CHUNK_SIZE
                    ]
                    record = crypto.encrypt(
                        dek, chunk, crypto.chunk_aad(backup_id, idx, backup["sha256"])
                    )
                    os.write(fd, record)
                os.fsync(fd)
            finally:
                os.close(fd)
            # The result is complete on disk only after the atomic rename.
            os.replace(tmp_path, prep_path)
            dir_fd = os.open(self.config.volume_dir, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except Exception as exc:
            self._remove_quietly(tmp_path)
            self._fail_prep(backup_id, str(exc))
            log.warning("preparation of backup %s failed: %s", backup_id, exc)
            return

        # Only now — original verified, file fully written — flip to ready.
        with self._write_lock, self._conn() as conn:
            conn.execute(
                "UPDATE resume_preps SET state = 'ready', chunk_count = ?,"
                " error = NULL, updated_at = ?"
                " WHERE backup_id = ? AND state = 'preparing'",
                (chunk_count, utcnow(), backup_id),
            )
            conn.commit()
        log.info("backup %s prepared for range resume (%d chunks)", backup_id, chunk_count)

    def _fail_prep(self, backup_id: str, error: str) -> None:
        with self._write_lock, self._conn() as conn:
            conn.execute(
                "UPDATE resume_preps SET state = 'failed', error = ?, updated_at = ?"
                " WHERE backup_id = ?",
                (error[:500], utcnow(), backup_id),
            )
            conn.commit()

    def get_ready_prep(self, backup_id: str):
        """Return the ready preparation row, or None.

        A row whose chunk file vanished from the volume is demoted to
        ``failed`` (retryable) so callers fall back to the original
        download rules.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM resume_preps WHERE backup_id = ? AND state = 'ready'",
                (backup_id,),
            ).fetchone()
        if row is None:
            return None
        row = dict(row)
        if not os.path.exists(row["prep_path"]):
            self._fail_prep(backup_id, "prepared chunk file is missing")
            return None
        return row

    @staticmethod
    def _record_length(index: int, chunk_count: int, size: int) -> int:
        if index == chunk_count - 1:
            return RESUME_RECORD_OVERHEAD + (
                size - (chunk_count - 1) * RESUME_CHUNK_SIZE
            )
        return RESUME_RECORD_SIZE

    @staticmethod
    def _read_at(fh, offset: int, length: int) -> bytes:
        fh.seek(offset)
        data = fh.read(length)
        if len(data) != length:
            raise ResumeCorruptError("prepared chunk file is truncated")
        return data

    def download_range(self, backup_id: str, start: int, stop: int) -> bytes:
        """Return plaintext for the half-open range ``[start, stop)``.

        Only the prepared chunks overlapping the range are read from the
        volume.  Every involved chunk must authenticate before anything is
        returned; on failure :class:`ResumeCorruptError` is raised and no
        plaintext leaves the service.
        """
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM backups WHERE id = ?", (backup_id,)
            ).fetchone()
            if row is None:
                raise KeyError(backup_id)
            backup = dict(row)
            prep = conn.execute(
                "SELECT * FROM resume_preps WHERE backup_id = ? AND state = 'ready'",
                (backup_id,),
            ).fetchone()
            if prep is None:
                raise ResumeNotReady(backup_id)
            prep = dict(prep)
            dek = self._unwrap_dek(conn, backup_id)

        size = backup["size_bytes"]
        if not (0 <= start < stop <= size):
            raise ValueError(f"invalid range {start}-{stop} for size {size}")

        chunk_count = prep["chunk_count"]
        first = start // RESUME_CHUNK_SIZE
        last = (stop - 1) // RESUME_CHUNK_SIZE
        out = bytearray()
        with open(prep["prep_path"], "rb") as fh:
            for idx in range(first, last + 1):
                record = self._read_at(
                    fh,
                    idx * RESUME_RECORD_SIZE,
                    self._record_length(idx, chunk_count, size),
                )
                try:
                    out += crypto.decrypt(
                        dek, record, crypto.chunk_aad(backup_id, idx, prep["sha256"])
                    )
                except InvalidTag as exc:
                    raise ResumeCorruptError(
                        f"prepared chunk {idx} of backup {backup_id}"
                        " failed authentication"
                    ) from exc
        base = first * RESUME_CHUNK_SIZE
        return bytes(out)[start - base: stop - base]

    # ---------------------------------------------------------------- rotation

    def current_rotation(self):
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM rotation_jobs WHERE state = 'running' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def start_rotation(self):
        with self._write_lock, self._conn() as conn:
            existing = conn.execute(
                "SELECT id FROM rotation_jobs WHERE state = 'running'"
            ).fetchone()
            if existing is not None:
                raise RotationInProgress("a rotation is already in progress")

            old = self.get_active_kek(conn)
            fresh_kek_id = new_id()
            self.keystore.generate(fresh_kek_id)
            conn.execute(
                "INSERT INTO master_keys (id, created_at, state) VALUES (?, ?, 'active')",
                (fresh_kek_id, utcnow()),
            )
            conn.execute(
                "UPDATE master_keys SET state = 'retired' WHERE id = ?", (old["id"],)
            )

            total = conn.execute(
                "SELECT COUNT(*) AS n FROM wrapped_keys WHERE kek_id = ?", (old["id"],)
            ).fetchone()["n"]
            job_id = new_id()
            conn.execute(
                "INSERT INTO rotation_jobs (id, old_kek_id, new_kek_id, state,"
                " total_backups, processed, created_at) VALUES (?, ?, ?, 'running', ?, 0, ?)",
                (job_id, old["id"], fresh_kek_id, total, utcnow()),
            )
            conn.commit()
            log.info(
                "rotation %s started: %s -> %s (%d backups)",
                job_id, old["id"], new_id, total,
            )
            return job_id

    def rotation_tick(self, limit: int = None) -> int:
        """Rewrap up to ``limit`` backups for the current rotation.

        Returns the number of backups processed in this tick.  Fully
        idempotent: re-execution after a crash only fills missing wrappers.
        """
        limit = limit or self.config.rotation_batch
        done = 0
        with self._write_lock, self._conn() as conn:
            job = conn.execute(
                "SELECT * FROM rotation_jobs WHERE state = 'running' ORDER BY created_at DESC LIMIT 1"
            ).fetchone()
            if job is None:
                return 0
            job = dict(job)

            if not self.keystore.exists(job["old_kek_id"]):
                # The old KEK is mandatory for rewrapping; keep the job alive
                # and surface the problem loudly instead of corrupting state.
                log.error("rotation %s cannot proceed: old KEK file missing", job["id"])
                return 0

            old_kek = self.keystore.load(job["old_kek_id"])
            new_kek = self.keystore.load(job["new_kek_id"])

            # Only pick backups that still lack a new-KEK wrapper. Once a
            # wrapper exists the backup leaves this set forever, so the job
            # is guaranteed to converge even if every tick is interrupted.
            targets = conn.execute(
                """
                SELECT DISTINCT old_w.backup_id
                FROM wrapped_keys old_w
                WHERE old_w.kek_id = ?
                  AND NOT EXISTS (
                        SELECT 1 FROM wrapped_keys new_w
                        WHERE new_w.backup_id = old_w.backup_id
                          AND new_w.kek_id = ?
                  )
                LIMIT ?
                """,
                (job["old_kek_id"], job["new_kek_id"], limit),
            ).fetchall()

            for t in targets:
                backup_id = t["backup_id"]
                wrap_row = conn.execute(
                    "SELECT * FROM wrapped_keys WHERE backup_id = ? AND kek_id = ?",
                    (backup_id, job["old_kek_id"]),
                ).fetchone()
                dek = crypto.unwrap_dek(
                    old_kek, wrap_row["wrapped_dek"], backup_id, job["old_kek_id"]
                )
                new_wrapped = crypto.wrap_dek(
                    new_kek, dek, backup_id, job["new_kek_id"]
                )
                # The unique (backup_id, kek_id) index makes a duplicate insert
                # from a crashed tick fail safely instead of double-wrapping.
                conn.execute(
                    "INSERT OR IGNORE INTO wrapped_keys (backup_id, kek_id, wrapped_dek, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (backup_id, job["new_kek_id"], new_wrapped, utcnow()),
                )
                conn.execute(
                    "UPDATE rotation_jobs SET processed = processed + 1 WHERE id = ?",
                    (job["id"],),
                )
                done += 1

            # processed equals the number of backups that now carry a new-KEK
            # wrapper; recompute it defensively in case a crash left the
            # counter behind.
            covered = conn.execute(
                """
                SELECT COUNT(DISTINCT old_w.backup_id) AS n
                FROM wrapped_keys old_w
                WHERE old_w.kek_id = ?
                  AND EXISTS (
                        SELECT 1 FROM wrapped_keys new_w
                        WHERE new_w.backup_id = old_w.backup_id
                          AND new_w.kek_id = ?
                  )
                """,
                (job["old_kek_id"], job["new_kek_id"]),
            ).fetchone()["n"]
            conn.execute(
                "UPDATE rotation_jobs SET processed = ? WHERE id = ?",
                (covered, job["id"]),
            )

            # A backup is "remaining" while it has an old-KEK wrapper but no
            # new-KEK wrapper yet. Old wrappers are intentionally retained
            # until the KEK is explicitly removed, so we cannot count on them
            # disappearing.
            remaining = conn.execute(
                """
                SELECT COUNT(*) AS n
                FROM wrapped_keys old_w
                WHERE old_w.kek_id = ?
                  AND NOT EXISTS (
                        SELECT 1 FROM wrapped_keys new_w
                        WHERE new_w.backup_id = old_w.backup_id
                          AND new_w.kek_id = ?
                  )
                """,
                (job["old_kek_id"], job["new_kek_id"]),
            ).fetchone()["n"]
            if remaining == 0:
                conn.execute(
                    "UPDATE rotation_jobs SET state = 'completed', completed_at = ? WHERE id = ?",
                    (utcnow(), job["id"]),
                )
                log.info("rotation %s completed", job["id"])
            conn.commit()
        return done

    # -------------------------------------------------------------- key removal

    def removable_keys(self):
        """KEKs that every dependent backup can recover without them."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT mk.id
                FROM master_keys mk
                WHERE mk.state = 'retired'
                  AND NOT EXISTS (SELECT 1 FROM rotation_jobs rj WHERE rj.state = 'running')
                  AND NOT EXISTS (
                        SELECT 1
                        FROM wrapped_keys wk
                        WHERE wk.kek_id = mk.id
                          AND NOT EXISTS (
                                SELECT 1 FROM wrapped_keys alt
                                WHERE alt.backup_id = wk.backup_id
                                  AND alt.kek_id <> mk.id
                                  AND EXISTS (SELECT 1 FROM master_keys m2 WHERE m2.id = alt.kek_id)
                          )
                  )
                """
            ).fetchall()
            return [r["id"] for r in rows]

    def remove_key(self, key_id: str) -> None:
        with self._write_lock, self._conn() as conn:
            key = conn.execute(
                "SELECT * FROM master_keys WHERE id = ?", (key_id,)
            ).fetchone()
            if key is None:
                raise KeyRemovalError("master key not found")
            if key["state"] == "active":
                raise KeyRemovalError("the active master key cannot be removed")
            running = conn.execute(
                "SELECT 1 FROM rotation_jobs WHERE state = 'running'"
            ).fetchone()
            if running:
                raise KeyRemovalError(
                    "wait for the running rotation to finish before removing a master key"
                )

            # Every backup wrapped by this KEK must have another wrapper whose
            # KEK still exists in the metadata table.
            stranded = conn.execute(
                """
                SELECT wk.backup_id
                FROM wrapped_keys wk
                WHERE wk.kek_id = ?
                  AND NOT EXISTS (
                        SELECT 1 FROM wrapped_keys alt
                        JOIN master_keys mk ON mk.id = alt.kek_id
                        WHERE alt.backup_id = wk.backup_id AND alt.kek_id <> ?
                  )
                """,
                (key_id, key_id),
            ).fetchall()
            if stranded:
                raise KeyRemovalError(
                    f"{len(stranded)} backup(s) still depend exclusively on this key"
                )

            conn.execute("DELETE FROM wrapped_keys WHERE kek_id = ?", (key_id,))
            conn.execute("DELETE FROM master_keys WHERE id = ?", (key_id,))
            conn.commit()

        # Metadata is gone first; only then shred the raw key material.
        self.keystore.destroy(key_id)
        log.info("master key %s removed", key_id)

    # ------------------------------------------------------------- dashboard

    def dashboard(self):
        with self._conn() as conn:
            stats = conn.execute(
                "SELECT COUNT(*) AS backups, COALESCE(SUM(size_bytes),0) AS total_bytes FROM backups"
            ).fetchone()
        return {
            "backups": self.list_backups(),
            "keys": self.list_keys(),
            "rotation": self.current_rotation(),
            "removable": set(self.removable_keys()),
            "backup_count": stats["backups"],
            "total_bytes": stats["total_bytes"],
            "prep_paused": self.prep_paused(),
        }
