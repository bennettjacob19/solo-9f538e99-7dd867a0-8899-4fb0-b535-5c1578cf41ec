"""Flask application: single-page backup console plus JSON API."""

import logging
import os
import urllib.parse

from flask import (
    Flask,
    Response,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from io import BytesIO

from werkzeug.http import parse_range_header

from .config import config_from_env
from .db import check_crypto_import
from .service import (
    KeyRemovalError,
    ResumeCorruptError,
    ResumeNotReady,
    RotationInProgress,
    Service,
)
from .worker import PrepWorker, RotationWorker

log = logging.getLogger(__name__)


def human_size(num: int) -> str:
    size = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def _attachment_disposition(filename: str) -> str:
    try:
        filename.encode("ascii")
    except UnicodeEncodeError:
        return "attachment; filename*=UTF-8''" + urllib.parse.quote(filename)
    safe = filename.replace("\\", "_").replace('"', "_")
    return f'attachment; filename="{safe}"'


def _range_not_satisfiable(size: int) -> Response:
    resp = Response(status=416)
    resp.headers["Content-Range"] = f"bytes */{size}"
    return resp


def _prepared_range_response(service, backup_id: str, range_header: str):
    """Build a 206 response from prepared chunks, or None to fall back.

    Falling back (None) means the caller serves the download by the
    original whole-blob rules.  Authentication failures never fall back:
    they abort with 500 so no unverified plaintext is ever sent.
    """
    backup = service.get_backup(backup_id)
    if backup is None:
        return None
    size = backup["size_bytes"]
    parsed = parse_range_header(range_header, size)
    if parsed is None or len(parsed.ranges) != 1:
        # Malformed or multi-range headers are left to the original path.
        return None
    start, stop = parsed.ranges[0]
    if start < 0:  # suffix form: the last -start bytes
        start, stop = max(size + start, 0), size
    else:
        stop = size if stop is None else min(stop, size)
    if start >= size or start >= stop:
        return _range_not_satisfiable(size)
    try:
        data = service.download_range(backup_id, start, stop)
    except (FileNotFoundError, ResumeNotReady):
        return None
    except ResumeCorruptError as exc:
        log.warning("range resume failed authentication: %s", exc)
        abort(500)
    resp = Response(data, status=206, mimetype="application/octet-stream")
    resp.headers["Content-Range"] = f"bytes {start}-{stop - 1}/{size}"
    resp.headers["Accept-Ranges"] = "bytes"
    resp.headers["ETag"] = f'"{backup["sha256"]}"'
    resp.headers["Content-Disposition"] = _attachment_disposition(backup["filename"])
    return resp


def create_app(config=None) -> Flask:
    config = config or config_from_env()
    check_crypto_import()

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.max_content_length
    # The UI only uses flash messages; an ephemeral secret is fine and avoids
    # persisting one next to the master keys.
    app.secret_key = os.urandom(32)
    app.jinja_env.filters["human_size"] = human_size

    service = Service(config)
    app.extensions["backup_service"] = service

    worker = RotationWorker(service, config.rotation_interval)
    worker.start()
    prep_worker = PrepWorker(service, config.prep_interval)
    prep_worker.start()

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.get("/")
    def index():
        return render_template("index.html", **service.dashboard())

    @app.post("/backups")
    def upload():
        upload = request.files.get("file")
        if upload is None or upload.filename == "":
            flash("请选择要上传的文件。", "error")
            return redirect(url_for("index"))
        data = upload.read()
        try:
            backup_id = service.upload_backup(upload.filename, data)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))
        flash(f"备份已创建：{backup_id[:8]}…（独立数据密钥加密）", "ok")
        return redirect(url_for("index"))

    @app.get("/backups/<backup_id>/download")
    def download(backup_id: str):
        range_header = request.headers.get("Range")
        if range_header and service.get_ready_prep(backup_id) is not None:
            prepared = _prepared_range_response(service, backup_id, range_header)
            if prepared is not None:
                return prepared
        # Original rules, unchanged: decrypt the whole blob, verify the
        # digest, and let send_file serve it (including its own Range
        # handling over the fully verified plaintext).
        result = service.download_backup(backup_id)
        if result is None:
            abort(404)
        filename, plaintext = result
        return send_file(
            BytesIO(plaintext),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=filename,
        )

    @app.post("/backups/<backup_id>/prepare")
    def prepare_resume(backup_id: str):
        try:
            state = service.request_prepare(backup_id)
        except KeyError:
            abort(404)
        if state == "ready":
            flash("该备份的续传准备已就绪，可直接断点续传。", "ok")
        else:
            flash("续传准备已排队：校验原件后逐块生成，期间原下载链接照常可用。", "ok")
        return redirect(url_for("index"))

    @app.post("/prepare/pause")
    def pause_prepare():
        service.set_prep_paused(True)
        flash("续传准备已暂停；上传、整份下载与主密钥轮换不受影响。", "ok")
        return redirect(url_for("index"))

    @app.post("/prepare/resume")
    def resume_prepare():
        service.set_prep_paused(False)
        flash("续传准备已恢复，后台继续处理队列。", "ok")
        return redirect(url_for("index"))

    @app.post("/rotations")
    def start_rotation():
        try:
            job_id = service.start_rotation()
            flash(f"密钥轮换已启动（任务 {job_id[:8]}…），后台逐份重包装数据密钥。", "ok")
        except RotationInProgress as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.post("/rotations/tick")
    def manual_tick():
        # Convenience endpoint for demos/tests; the worker already ticks.
        processed = service.rotation_tick()
        flash(f"本次轮换推进了 {processed} 份备份。", "ok")
        return redirect(url_for("index"))

    @app.post("/keys/<key_id>/remove")
    def remove_key(key_id: str):
        try:
            service.remove_key(key_id)
            flash(f"旧主密钥 {key_id[:8]}… 已移除，密钥文件已粉碎。", "ok")
        except KeyRemovalError as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.errorhandler(413)
    def too_large(_):
        flash(f"文件超过上限（{config.max_content_length // (1024 * 1024)} MB）。", "error")
        return redirect(url_for("index"))

    return app
