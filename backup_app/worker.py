"""Background worker that drives rotation one batch at a time.

The worker performs no state of its own: every tick reads the persisted
rotation job from SQLite.  If the process is killed mid-rotation, a new
process simply picks the same job up on startup.
"""

import logging
import threading

log = logging.getLogger(__name__)


class RotationWorker(threading.Thread):
    def __init__(self, service, interval: float):
        super().__init__(name="rotation-worker", daemon=True)
        self._service = service
        self._interval = interval
        # Attribute names must not collide with threading.Thread internals
        # (Thread defines its own _stop() method).
        self._stop_event = threading.Event()

    def request_stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log.info("rotation worker started")
        while not self._stop_event.is_set():
            try:
                if self._service.current_rotation() is not None:
                    processed = self._service.rotation_tick()
                    if processed == 0:
                        # Job completed or no progress possible; back off.
                        self._stop_event.wait(self._interval)
                else:
                    self._stop_event.wait(self._interval)
            except Exception:
                log.exception("rotation tick failed; will retry")
                self._stop_event.wait(self._interval)
        log.info("rotation worker stopped")


class PrepWorker(threading.Thread):
    """Background worker that prepares backups for ranged resume.

    Like the rotation worker it keeps no state of its own: queued rows in
    ``resume_preps`` survive restarts, so an interrupted preparation is
    simply retried by whichever process runs next.  While preparation is
    paused the worker idles and never touches the database.
    """

    def __init__(self, service, interval: float):
        super().__init__(name="prep-worker", daemon=True)
        self._service = service
        self._interval = interval
        self._stop_event = threading.Event()

    def request_stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log.info("prep worker started")
        while not self._stop_event.is_set():
            try:
                if self._service.prep_paused():
                    self._stop_event.wait(self._interval)
                    continue
                processed = self._service.prep_tick()
                if processed == 0:
                    self._stop_event.wait(self._interval)
            except Exception:
                log.exception("prep tick failed; will retry")
                self._stop_event.wait(self._interval)
        log.info("prep worker stopped")
