# IEC 60870-5-104 会话取证核验平台

对变电站抓包得到的 IEC 104 帧序列进行**可采信性核验**：不仅逐帧解析 APDU，
还重建双向发送/确认状态机与 STARTDT/STOPDT/TESTFR 握手阶段，确保遥控记录
不存在确认倒退、确认越界、窗口超限或传输阶段失序。

零第三方依赖，仅使用 Python 3.11 标准库。

## 接口

### `GET /health`

容器健康检查端点，返回：

```json
{ "status": "ok", "service": "iec104-forensic-audit", "checks": { "api": "ok" } }
```

### `POST /api/iec104/sessions/audit`

请求体：

| 字段 | 说明 |
| --- | --- |
| `frames` | 1–5000 帧，按 `capturedAtUs` 非递减排列 |
| `frames[].direction` | `"client"`（主站）或 `"server"`（子站），也接受 `master`/`slave`、`primary`/`secondary` 等别名 |
| `frames[].apdu` | 完整十六进制 APDU（起始符 0x68 + 长度 + 4 字节控制域 [+ ASDU]，允许空白分隔） |
| `frames[].capturedAtUs` | 可选，非负整数微秒时间戳；启用 `ackEvidence` 时每一帧都必须提供 |
| `maxWindow` | 最大未确认窗口，1–16383 |
| `ackEvidence` | 可选；启用逐帧确认时延取证，省略时请求与响应契约保持原样 |
| `ackEvidence.maxDelayUs` | 确认时延上限（微秒），1–60000000；时延恰好等于上限合法 |
| `ackEvidence.captureEndAtUs` | 捕获结束时间（微秒），不得早于末帧 `capturedAtUs` |

成功响应（200）：

```json
{
  "ok": true,
  "result": {
    "iFrames": { "client": 2, "server": 1 },
    "outstanding": { "client": 0, "server": 0 },
    "handshakes": {
      "STARTDT": { "act": 1, "con": 1, "paired": 1 },
      "STOPDT":  { "act": 1, "con": 1, "paired": 1 },
      "TESTFR":  { "act": 0, "con": 0, "paired": 0 }
    },
    "ackEvidence": {
      "client": [ { "sendIndex": 2, "ackIndex": 5, "delayUs": 100 } ],
      "server": []
    }
  }
}
```

- `iFrames`：按方向统计 I 帧数。
- `outstanding`：会话结束时各方向已发送但尚未被对端确认的 I 帧数。
- `handshakes`：三类 U 格式服务的 act、con 总数及成功反向配对次数。
- `ackEvidence`：仅在请求携带 `ackEvidence` 时返回。按发送方向列出每个
  **已确认** I 帧的证据：`sendIndex`（发送帧下标）、`ackIndex`（首次确认它的
  对端 I/S 帧下标）、`delayUs`（两帧 `capturedAtUs` 之差）。同一累计确认覆盖
  多个 I 帧时，每帧各自成条（`ackIndex` 相同），均可独立复核。

失败响应（4xx），`frameIndex` 为**最早受影响帧**的 0 基下标，`message`
只描述该帧本身，不包含对后续帧的裁决：

```json
{
  "ok": false,
  "error": { "code": "ACK_AHEAD", "frameIndex": 2, "message": "确认号越过对端已发送数据：……" }
}
```

### 稳定错误码

| 错误码 | HTTP | 含义 |
| --- | --- | --- |
| `INVALID_REQUEST` | 400 | 请求结构 / `maxWindow` / 帧数量 / 时间戳类型不合法 |
| `INVALID_APDU` | 422 | 起始符、长度字段非法，存在截断或尾随字节，S/U 帧携带 ASDU 等 |
| `INVALID_CONTROL_FIELD` | 422 | 控制域保留位非零或 U 功能码未知 |
| `FRAMES_NOT_ORDERED` | 422 | `capturedAtUs` 未按非递减排列 |
| `SEND_SEQUENCE_INVALID` | 422 | N(S) 未从 0 起、跳号或重复 |
| `ACK_BACKWARDS` | 422 | N(R) 相对本端此前的确认倒退 |
| `ACK_AHEAD` | 422 | N(R) 越过对端已发送的 I 帧数 |
| `WINDOW_EXCEEDED` | 422 | 发送后未确认 I 帧数超过 `maxWindow` |
| `HANDSHAKE_UNMATCHED` | 422 | act/con 缺少配对、同方向配对、con 无对应 act，或会话结束仍有 act 未配对（定位到该 act） |
| `HANDSHAKE_OVERLAP` | 422 | 上一个同类 act 尚未收到 con 又出现新的 act |
| `I_FRAME_OUTSIDE_PHASE` | 422 | I 帧出现在 STARTDT 确认之前或 STOPDT 确认之后 |
| `I_ACK_TIMEOUT` | 422 | 启用 `ackEvidence` 后，I 帧确认到达时时延超过 `maxDelayUs`，或截至 `captureEndAtUs` 仍未确认且已超限；`frameIndex` 为最早超时的发送帧 |

### 核验规则要点

- 双方 N(S) 在连接开始时均从 0 起，逐帧严格 +1（STOPDT 后重新 STARTDT 不重置）。
- N(R) 单调不倒退，且不得大于对端当前已发送 I 帧数。
- 每发送一帧 I 即检查本端未确认数 `已发送 - 已被确认`，超过窗口立即拒绝该帧。
- STARTDT/STOPDT/TESTFR 的 act 与 con 必须来自相反方向；同类 act 未确认前
  不得重发；会话结束仍悬挂的 act，定位到最早的那一帧。
- S 帧与 TESTFR 可在任意阶段出现；STARTDT con 之后、STOPDT con 之前才允许 I 帧。
- 启用 `ackEvidence` 时，对端 I/S 帧的 N(R) 首次越过某发送序号即认定该 I 帧
  获确认，按两帧 `capturedAtUs` 之差计时：确认到达时已超限，或截至
  `captureEndAtUs` 仍未确认且已超限，均判 `I_ACK_TIMEOUT` 并定位下标最早的
  超时发送帧；时延恰好等于 `maxDelayUs` 合法。

## 运行

```bash
# 宿主机端口可配置（默认 8080）
HOST_PORT=9090 docker compose up --build -d api

curl -s http://localhost:9090/health
```

也可直接本地运行（无需 Docker）：

```bash
PORT=8080 python3 app/main.py
```

## 一次性核验服务 verify

`verify` 服务在清洁启动后依次执行：单元/集成测试 → 等待 API 健康检查通过 →
合法会话与多类非法会话冒烟（含旧契约不含 `ackEvidence`、累计及捎带确认逐帧
成证、边界时延合法、确认到达超时与结束超时场景），最终以退出码报告
（0 成功，非 0 失败）：

```bash
docker compose up --build --force-recreate --exit-code-from verify verify
echo $?
```

无 Docker 的开发机上可直接执行同一脚本，它会在本地随机端口临时启动 API：

```bash
bash verify/run.sh
```

## 项目结构

```
app/
  protocol.py      # APDU 解析与会话状态机（核心）
  main.py          # 标准库 HTTP 服务
  healthcheck.py   # 容器健康检查探针
tests/             # 74 个单元 + HTTP 集成测试
verify/
  run.sh           # 一次性核验编排
  smoke.py         # 合法/非法会话 HTTP 冒烟
Dockerfile
docker-compose.yml
```

## 快速构造帧

- I 帧（N(S)=s, N(R)=r）：控制域前两字节 `2s` 小端，后两字节 `2r` 小端。
- S 帧（N(R)=r）：`68 04 01 00 <2r 小端>`。
- U 帧：STARTDT act/con `680407000000` / `68040b000000`；
  STOPDT `...13...` / `...23...`；TESTFR `...43...` / `...83...`。
