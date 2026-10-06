"""IEC 104 会话取证核验 HTTP 服务（仅用 Python 标准库）。"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from protocol import AuditError, ErrorCode, audit_request, http_status_for  # noqa: E402

SERVICE_NAME = "iec104-forensic-audit"
DEFAULT_PORT = 8080
MAX_BODY_BYTES = 8 * 1024 * 1024  # 5000 帧十六进制 APDU 的宽松上限

logger = logging.getLogger(SERVICE_NAME)


class AuditHandler(BaseHTTPRequestHandler):
    server_version = "IEC104Audit/1.0"

    def _write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - http.server 约定
        if self.path.split("?", 1)[0] == "/health":
            self._write_json(
                200,
                {
                    "status": "ok",
                    "service": SERVICE_NAME,
                    "checks": {"api": "ok"},
                },
            )
            return
        self._write_json(404, {"ok": False, "error": {"code": "NOT_FOUND",
                                                       "frameIndex": -1,
                                                       "message": "路径不存在"}})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] != "/api/iec104/sessions/audit":
            self._write_json(404, {"ok": False, "error": {"code": "NOT_FOUND",
                                                          "frameIndex": -1,
                                                          "message": "路径不存在"}})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._write_json(400, _simple_error("Content-Length 非法"))
            return
        if length <= 0:
            self._write_json(400, _simple_error("请求缺少请求体"))
            return
        if length > MAX_BODY_BYTES:
            self._write_json(413, _simple_error("请求体超过大小上限"))
            return

        raw = self.rfile.read(length)
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._write_json(400, _simple_error("请求体不是合法的 UTF-8 JSON"))
            return

        try:
            result = audit_request(body)
        except AuditError as exc:
            self._write_json(http_status_for(exc.code), exc.to_dict())
            return
        self._write_json(200, result)

    def log_message(self, fmt: str, *args) -> None:  # 统一走 logging
        logger.info("%s - %s", self.address_string(), fmt % args)


def _simple_error(message: str) -> dict:
    return {
        "ok": False,
        "error": {
            "code": ErrorCode.INVALID_REQUEST.value,
            "frameIndex": -1,
            "message": message,
        },
    }


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    port = int(os.environ.get("PORT", str(DEFAULT_PORT)))
    host = os.environ.get("HOST", "0.0.0.0")
    server = ThreadingHTTPServer((host, port), AuditHandler)

    def _shutdown(signum, frame):  # noqa: ARG001
        logger.info("收到信号 %s，开始关闭", signum)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    logger.info("%s 监听 http://%s:%d", SERVICE_NAME, host, port)
    try:
        server.serve_forever()
    except SystemExit:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
