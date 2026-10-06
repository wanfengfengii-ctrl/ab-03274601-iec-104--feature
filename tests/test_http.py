"""HTTP 层端到端测试：在后台线程启动真实服务进行请求。"""

import json
import os
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

import main  # noqa: E402

STARTDT_ACT = "680407000000"
STARTDT_CON = "68040b000000"
STOPDT_ACT = "680413000000"
STOPDT_CON = "680423000000"


def i_frame(send: int, recv: int = 0) -> str:
    body = bytes([(send << 1) & 0xFF, (send << 1) >> 8,
                  (recv << 1) & 0xFF, (recv << 1) >> 8,
                  0x01, 0x04, 0x03, 0x00, 0x00, 0x00])
    return (bytes([0x68, len(body)]) + body).hex()


def s_frame(recv: int) -> str:
    body = bytes([0x01, 0x00, (recv << 1) & 0xFF, (recv << 1) >> 8])
    return (bytes([0x68, 4]) + body).hex()


class HttpServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), main.AuditHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def _url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def _post(self, payload):
        req = urllib.request.Request(
            self._url("/api/iec104/sessions/audit"),
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_health(self):
        with urllib.request.urlopen(self._url("/health"), timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read())["status"], "ok")

    def test_legal_session(self):
        body = {
            "maxWindow": 4,
            "frames": [
                {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
                {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
                {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 3},
                {"direction": "server", "apdu": i_frame(0, 1), "capturedAtUs": 4},
                {"direction": "client", "apdu": "680401000200", "capturedAtUs": 5},
                {"direction": "client", "apdu": STOPDT_ACT, "capturedAtUs": 6},
                {"direction": "server", "apdu": STOPDT_CON, "capturedAtUs": 7},
            ],
        }
        status, data = self._post(body)
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        result = data["result"]
        self.assertEqual(result["iFrames"], {"client": 1, "server": 1})
        self.assertEqual(result["outstanding"], {"client": 0, "server": 0})
        self.assertEqual(result["handshakes"]["STARTDT"]["paired"], 1)
        self.assertEqual(result["handshakes"]["STOPDT"]["paired"], 1)

    def test_illegal_session_reports_stable_code_and_index(self):
        body = {
            "maxWindow": 4,
            "frames": [
                {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 1},
            ],
        }
        status, data = self._post(body)
        self.assertEqual(status, 422)
        self.assertFalse(data["ok"])
        self.assertEqual(data["error"]["code"], "I_FRAME_OUTSIDE_PHASE")
        self.assertEqual(data["error"]["frameIndex"], 0)
        self.assertNotIn("后续", data["error"]["message"])

    def test_ack_ahead_status_422(self):
        body = {
            "maxWindow": 4,
            "frames": [
                {"direction": "client", "apdu": STARTDT_ACT},
                {"direction": "server", "apdu": STARTDT_CON},
                {"direction": "server", "apdu": "680401000200"},  # S 帧 N(R)=1
            ],
        }
        status, data = self._post(body)
        self.assertEqual(status, 422)
        self.assertEqual(data["error"]["code"], "ACK_AHEAD")
        self.assertEqual(data["error"]["frameIndex"], 2)

    def test_bad_json_is_400(self):
        req = urllib.request.Request(
            self._url("/api/iec104/sessions/audit"),
            data=b"{not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("应当返回 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)

    def test_bad_request_body_400(self):
        status, data = self._post({"frames": [], "maxWindow": 4})
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_REQUEST")

    def test_ack_evidence_success(self):
        body = {
            "maxWindow": 8,
            "ackEvidence": {"maxDelayUs": 100, "captureEndAtUs": 220},
            "frames": [
                {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 0},
                {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 10},
                {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 100},
                {"direction": "client", "apdu": i_frame(1, 0), "capturedAtUs": 110},
                {"direction": "server", "apdu": i_frame(0, 2), "capturedAtUs": 200},
                {"direction": "client", "apdu": s_frame(1), "capturedAtUs": 220},
            ],
        }
        status, data = self._post(body)
        self.assertEqual(status, 200)
        result = data["result"]
        self.assertEqual(result["iFrames"], {"client": 2, "server": 1})
        self.assertEqual(
            result["ackEvidence"]["client"],
            [
                {"sendIndex": 2, "ackIndex": 4, "delayUs": 100},
                {"sendIndex": 3, "ackIndex": 4, "delayUs": 90},
            ],
        )
        self.assertEqual(
            result["ackEvidence"]["server"],
            [{"sendIndex": 4, "ackIndex": 5, "delayUs": 20}],
        )

    def test_ack_evidence_timeout_422(self):
        body = {
            "maxWindow": 8,
            "ackEvidence": {"maxDelayUs": 100, "captureEndAtUs": 1000},
            "frames": [
                {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 0},
                {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 10},
                {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 100},
                {"direction": "server", "apdu": s_frame(1), "capturedAtUs": 150},
                {"direction": "client", "apdu": i_frame(1, 0), "capturedAtUs": 160},
            ],
        }
        status, data = self._post(body)
        self.assertEqual(status, 422)
        self.assertEqual(data["error"]["code"], "I_ACK_TIMEOUT")
        self.assertEqual(data["error"]["frameIndex"], 4)

    def test_ack_evidence_bad_param_400(self):
        body = {
            "maxWindow": 8,
            "ackEvidence": {"maxDelayUs": 0, "captureEndAtUs": 10},
            "frames": [
                {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 0},
                {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 10},
            ],
        }
        status, data = self._post(body)
        self.assertEqual(status, 400)
        self.assertEqual(data["error"]["code"], "INVALID_REQUEST")

    def test_unknown_path_404(self):
        with self.assertRaises(urllib.error.HTTPError) as cm:
            urllib.request.urlopen(self._url("/nope"), timeout=5)
        self.assertEqual(cm.exception.code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
