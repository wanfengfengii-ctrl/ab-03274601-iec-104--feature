"""对运行中的服务执行合法/非法会话冒烟。

由 verify.sh 在一次性容器中调用，通过 HTTP 访问 API_URL。
任一断言失败即以非零退出码结束，并打印差异。
"""

import json
import os
import sys
import urllib.error
import urllib.request

API_URL = os.environ.get("API_URL", "http://api:8080").rstrip("/")
AUDIT_URL = API_URL + "/api/iec104/sessions/audit"


def i_frame(send: int, recv: int = 0) -> str:
    body = bytes(
        [(send << 1) & 0xFF, (send << 1) >> 8,
         (recv << 1) & 0xFF, (recv << 1) >> 8,
         0x01, 0x04, 0x03, 0x00, 0x00, 0x00]
    )
    return (bytes([0x68, len(body)]) + body).hex()


def s_frame(recv: int) -> str:
    body = bytes([0x01, 0x00, (recv << 1) & 0xFF, (recv << 1) >> 8])
    return (bytes([0x68, 4]) + body).hex()


STARTDT_ACT = "680407000000"
STARTDT_CON = "68040b000000"
STOPDT_ACT = "680413000000"
STOPDT_CON = "680423000000"


def post(payload):
    req = urllib.request.Request(
        AUDIT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def check(label, condition, detail=""):
    if not condition:
        print(f"[FAIL] {label} {detail}")
        sys.exit(1)
    print(f"[PASS] {label}")


def main() -> int:
    # 0. 健康检查
    with urllib.request.urlopen(API_URL + "/health", timeout=5) as resp:
        check("健康检查 /health 返回 200", resp.status == 200)

    # 1. 合法会话：启动 -> 双向 I 帧交换并互相确认 -> 停止
    legal = {
        "maxWindow": 4,
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 3},
            {"direction": "client", "apdu": i_frame(1, 0), "capturedAtUs": 4},
            {"direction": "server", "apdu": i_frame(0, 2), "capturedAtUs": 5},
            {"direction": "client", "apdu": s_frame(1), "capturedAtUs": 6},
            {"direction": "client", "apdu": STOPDT_ACT, "capturedAtUs": 7},
            {"direction": "server", "apdu": STOPDT_CON, "capturedAtUs": 8},
        ],
    }
    status, data = post(legal)
    check("合法会话返回 200", status == 200, f"实际 {status} {data}")
    check("合法会话 ok=true", data.get("ok") is True)
    result = data["result"]
    check("按方向统计 I 帧数",
          result["iFrames"] == {"client": 2, "server": 1},
          str(result["iFrames"]))
    check("最终待确认数为 0",
          result["outstanding"] == {"client": 0, "server": 0},
          str(result["outstanding"]))
    check("STARTDT 配对计数",
          result["handshakes"]["STARTDT"] == {"act": 1, "con": 1, "paired": 1},
          str(result["handshakes"]["STARTDT"]))
    check("STOPDT 配对计数",
          result["handshakes"]["STOPDT"] == {"act": 1, "con": 1, "paired": 1},
          str(result["handshakes"]["STOPDT"]))

    # 2. 非法会话：未启动即发 I 帧
    illegal_phase = {
        "maxWindow": 4,
        "frames": [
            {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 1},
        ],
    }
    status, data = post(illegal_phase)
    check("阶段违规返回 422", status == 422, f"实际 {status}")
    err = data.get("error", {})
    check("稳定错误码 I_FRAME_OUTSIDE_PHASE",
          err.get("code") == "I_FRAME_OUTSIDE_PHASE", str(err))
    check("定位到最早受影响帧下标 0", err.get("frameIndex") == 0, str(err))
    check("说明不包含对后续裁决的引用", "后续" not in err.get("message", ""),
          err.get("message"))

    # 3. 非法会话：确认号越过对端已发送数据
    illegal_ack = {
        "maxWindow": 4,
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "server", "apdu": s_frame(1), "capturedAtUs": 3},
        ],
    }
    status, data = post(illegal_ack)
    err = data.get("error", {})
    check("越界确认返回 422 且错误码/下标稳定",
          status == 422 and err.get("code") == "ACK_AHEAD"
          and err.get("frameIndex") == 2,
          f"{status} {err}")

    # 4. 非法 APDU：尾随字节
    illegal_apdu = {
        "maxWindow": 4,
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT + "ff",
             "capturedAtUs": 1},
        ],
    }
    status, data = post(illegal_apdu)
    err = data.get("error", {})
    check("尾随字节返回 INVALID_APDU 且下标为 0",
          status == 422 and err.get("code") == "INVALID_APDU"
          and err.get("frameIndex") == 0,
          f"{status} {err}")

    # 5. ackEvidence：累计确认 + 捎带确认，每个被覆盖的 I 帧各自形成证据
    evidence_session = {
        "maxWindow": 4,
        "ackEvidence": {"maxDelayUs": 1000, "captureEndAtUs": 500},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 100},
            {"direction": "client", "apdu": i_frame(1, 0), "capturedAtUs": 200},
            # server I0 捎带 N(R)=2，一次累计覆盖 client 的 I0/I1
            {"direction": "server", "apdu": i_frame(0, 2), "capturedAtUs": 300},
            # client S 帧确认 server 的 I0
            {"direction": "client", "apdu": s_frame(1), "capturedAtUs": 400},
        ],
    }
    status, data = post(evidence_session)
    check("证据会话返回 200", status == 200, f"实际 {status} {data}")
    evidence = data.get("result", {}).get("ackEvidence", {})
    check("累计确认覆盖的两帧各自留证",
          evidence.get("client") == [
              {"sendFrameIndex": 2, "firstAckFrameIndex": 4, "delayUs": 200},
              {"sendFrameIndex": 3, "firstAckFrameIndex": 4, "delayUs": 100},
          ],
          str(evidence.get("client")))
    check("捎带确认同样计时",
          evidence.get("server") == [
              {"sendFrameIndex": 4, "firstAckFrameIndex": 5, "delayUs": 100},
          ],
          str(evidence.get("server")))

    # 6. ackEvidence：确认时延恰好等于上限合法
    boundary_session = {
        "maxWindow": 4,
        "ackEvidence": {"maxDelayUs": 1000, "captureEndAtUs": 2000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 100},
            {"direction": "server", "apdu": s_frame(1), "capturedAtUs": 1100},
        ],
    }
    status, data = post(boundary_session)
    check("时延恰好等于上限返回 200", status == 200, f"实际 {status} {data}")
    delay = (data.get("result", {}).get("ackEvidence", {})
             .get("client", [{}])[0].get("delayUs"))
    check("边界时延记录为 1000 μs", delay == 1000, str(delay))

    # 7. ackEvidence：确认帧到达时已超限，定位最早超时发送帧
    late_ack = {
        "maxWindow": 4,
        "ackEvidence": {"maxDelayUs": 1000, "captureEndAtUs": 5000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 100},
            {"direction": "client", "apdu": i_frame(1, 0), "capturedAtUs": 200},
            # 同一累计确认：I0 等待 1001 μs 超时，I1 仅 901 μs
            {"direction": "server", "apdu": s_frame(2), "capturedAtUs": 1101},
        ],
    }
    status, data = post(late_ack)
    err = data.get("error", {})
    check("迟到确认返回 422 I_ACK_TIMEOUT 且定位最早超时帧",
          status == 422 and err.get("code") == "I_ACK_TIMEOUT"
          and err.get("frameIndex") == 2,
          f"{status} {err}")

    # 8. ackEvidence：截至 captureEndAtUs 仍未确认且已超限
    end_timeout = {
        "maxWindow": 4,
        "ackEvidence": {"maxDelayUs": 1000, "captureEndAtUs": 1201},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 100},
            {"direction": "client", "apdu": i_frame(1, 0), "capturedAtUs": 200},
            {"direction": "server", "apdu": s_frame(1), "capturedAtUs": 300},
            # I1(下标3) 始终未确认，到 1201 已等待 1001 μs
        ],
    }
    status, data = post(end_timeout)
    err = data.get("error", {})
    check("结束时未确认且超限返回 422 I_ACK_TIMEOUT（下标 3）",
          status == 422 and err.get("code") == "I_ACK_TIMEOUT"
          and err.get("frameIndex") == 3,
          f"{status} {err}")

    # 9. ackEvidence：启用后缺时间戳属请求结构错误
    missing_ts = {
        "maxWindow": 4,
        "ackEvidence": {"maxDelayUs": 1000, "captureEndAtUs": 100},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON},
        ],
    }
    status, data = post(missing_ts)
    err = data.get("error", {})
    check("启用证据后缺 capturedAtUs 返回 400 INVALID_REQUEST",
          status == 400 and err.get("code") == "INVALID_REQUEST"
          and err.get("frameIndex") == 1,
          f"{status} {err}")

    print("全部冒烟通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
