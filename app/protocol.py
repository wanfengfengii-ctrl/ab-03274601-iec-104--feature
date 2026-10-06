"""IEC 60870-5-104 会话状态机与 APDU 解析。

只依赖 Python 标准库。任何违规都抛出 :class:`AuditError`，携带稳定错误码、
最早受影响帧下标（0 起）与仅针对该帧本身的说明（不引用对后续帧的裁决）。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

START_BYTE = 0x68
MIN_APDU_LEN = 6  # 起始符(1) + 长度(1) + 控制域(4)
MAX_LENGTH_FIELD = 253  # 长度字段 = 控制域(4) + ASDU(<=249)
MAX_FRAMES = 5000
MIN_WINDOW = 1
MAX_WINDOW = 16383

CLIENT = "client"
SERVER = "server"
DIRECTIONS = (CLIENT, SERVER)

_DIRECTION_ALIASES = {
    "client": CLIENT,
    "c": CLIENT,
    "master": CLIENT,
    "primary": CLIENT,
    "server": SERVER,
    "s": SERVER,
    "slave": SERVER,
    "secondary": SERVER,
    "controlled": SERVER,
}


class ErrorCode(str, Enum):
    """对外稳定错误码，取值不得随实现随意改动。"""

    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_APDU = "INVALID_APDU"
    INVALID_CONTROL_FIELD = "INVALID_CONTROL_FIELD"
    FRAMES_NOT_ORDERED = "FRAMES_NOT_ORDERED"
    SEND_SEQUENCE_INVALID = "SEND_SEQUENCE_INVALID"
    ACK_BACKWARDS = "ACK_BACKWARDS"
    ACK_AHEAD = "ACK_AHEAD"
    WINDOW_EXCEEDED = "WINDOW_EXCEEDED"
    HANDSHAKE_UNMATCHED = "HANDSHAKE_UNMATCHED"
    HANDSHAKE_OVERLAP = "HANDSHAKE_OVERLAP"
    I_FRAME_OUTSIDE_PHASE = "I_FRAME_OUTSIDE_PHASE"


# 请求结构问题属于 400；其余为可定位到帧的协议违规，属于 422。
_HTTP_STATUS = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.INVALID_APDU: 422,
    ErrorCode.INVALID_CONTROL_FIELD: 422,
    ErrorCode.FRAMES_NOT_ORDERED: 422,
    ErrorCode.SEND_SEQUENCE_INVALID: 422,
    ErrorCode.ACK_BACKWARDS: 422,
    ErrorCode.ACK_AHEAD: 422,
    ErrorCode.WINDOW_EXCEEDED: 422,
    ErrorCode.HANDSHAKE_UNMATCHED: 422,
    ErrorCode.HANDSHAKE_OVERLAP: 422,
    ErrorCode.I_FRAME_OUTSIDE_PHASE: 422,
}


def http_status_for(code: ErrorCode) -> int:
    return _HTTP_STATUS[code]


class AuditError(Exception):
    def __init__(self, code: ErrorCode, frame_index: int, message: str):
        super().__init__(message)
        self.code = code
        self.frame_index = frame_index
        self.message = message

    def to_dict(self) -> dict:
        return {
            "ok": False,
            "error": {
                "code": self.code.value,
                "frameIndex": self.frame_index,
                "message": self.message,
            },
        }


@dataclass(frozen=True)
class ParsedFrame:
    kind: str  # "I" | "S" | "U"
    send_seq: Optional[int] = None
    recv_seq: Optional[int] = None
    u_type: Optional[str] = None  # STARTDT | STOPDT | TESTFR
    u_act: Optional[bool] = None


_U_FUNCTIONS = {
    0x04: ("STARTDT", True),   # 0x07
    0x08: ("STARTDT", False),  # 0x0B
    0x10: ("STOPDT", True),    # 0x13
    0x20: ("STOPDT", False),   # 0x23
    0x40: ("TESTFR", True),    # 0x43
    0x80: ("TESTFR", False),   # 0x83
}


def normalize_direction(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    return _DIRECTION_ALIASES.get(value.strip().lower())


def parse_apdu(raw_hex: object) -> ParsedFrame:
    """解析完整十六进制 APDU，仅接受 I/S/U 三种控制格式。

    起始符、长度、控制域必须合法，且长度字段与实际字节数严格一致
    （既不截断也无尾随字节）。
    """
    if not isinstance(raw_hex, str):
        raise AuditError(ErrorCode.INVALID_APDU, -1, "apdu 必须为十六进制字符串")
    text = "".join(raw_hex.split())
    try:
        data = bytes.fromhex(text)
    except ValueError:
        raise AuditError(
            ErrorCode.INVALID_APDU, -1, "APDU 不是合法的偶数位十六进制字符串"
        )

    if len(data) < MIN_APDU_LEN:
        raise AuditError(ErrorCode.INVALID_APDU, -1, "APDU 短于最小长度 6 字节")
    if data[0] != START_BYTE:
        raise AuditError(ErrorCode.INVALID_APDU, -1, "起始符不是 0x68")

    length = data[1]
    if length < 4:
        raise AuditError(
            ErrorCode.INVALID_APDU, -1, "长度字段小于控制域长度 4"
        )
    if length > MAX_LENGTH_FIELD:
        raise AuditError(
            ErrorCode.INVALID_APDU, -1, "长度字段超过上限 253"
        )
    # 长度只计控制域与 ASDU；整体必须恰为 2+length，拒绝截断与尾随字节。
    if len(data) != 2 + length:
        raise AuditError(
            ErrorCode.INVALID_APDU,
            -1,
            "长度字段与实际字节数不符（存在截断或尾随字节）",
        )

    b2, b3, b4, b5 = data[2], data[3], data[4], data[5]

    if b2 & 0x01 == 0x00:
        # I 格式：第 1 个八字节组最低位为 0
        send_seq = ((b3 << 8) | b2) >> 1
        recv_seq = ((b5 << 8) | b4) >> 1
        return ParsedFrame(kind="I", send_seq=send_seq, recv_seq=recv_seq)

    if b2 & 0x03 == 0x01:
        # S 格式：最低两位为 01
        if length != 4:
            raise AuditError(
                ErrorCode.INVALID_APDU,
                -1,
                "S 格式不携带 ASDU，长度字段必须恰为 4",
            )
        if b3 != 0:
            raise AuditError(
                ErrorCode.INVALID_CONTROL_FIELD,
                -1,
                "S 格式控制域的发送序号保留位非零",
            )
        recv_seq = ((b5 << 8) | b4) >> 1
        return ParsedFrame(kind="S", recv_seq=recv_seq)

    # U 格式：最低两位为 11
    if length != 4:
        raise AuditError(
            ErrorCode.INVALID_APDU,
            -1,
            "U 格式不携带 ASDU，长度字段必须恰为 4",
        )
    if b3 != 0 or b4 != 0 or b5 != 0:
        raise AuditError(
            ErrorCode.INVALID_CONTROL_FIELD,
            -1,
            "U 格式控制域的保留字节非零",
        )
    parsed = _U_FUNCTIONS.get(b2 & 0xFC)
    if parsed is None:
        raise AuditError(
            ErrorCode.INVALID_CONTROL_FIELD,
            -1,
            "U 格式功能码未知（不是 STARTDT/STOPDT/TESTFR 的 act 或 con）",
        )
    u_type, u_act = parsed
    return ParsedFrame(kind="U", u_type=u_type, u_act=u_act)


@dataclass
class _PeerState:
    next_send: int = 0  # 本端下一个应使用的 N(S)，双方均从 0 起
    last_ack: int = 0  # 本端已发布的最大 N(R)，确认号不得倒退


def _opposite(direction: str) -> str:
    return SERVER if direction == CLIENT else CLIENT


def audit_request(body: object) -> dict:
    """核验一次审计请求，成功返回结果字典，违规抛出 :class:`AuditError`。"""
    if not isinstance(body, dict):
        raise AuditError(ErrorCode.INVALID_REQUEST, -1, "请求体必须为 JSON 对象")

    max_window = body.get("maxWindow", body.get("maxUnconfirmedWindow"))
    if isinstance(max_window, bool) or not isinstance(max_window, int):
        raise AuditError(
            ErrorCode.INVALID_REQUEST, -1, "maxWindow 必须为整数"
        )
    if not (MIN_WINDOW <= max_window <= MAX_WINDOW):
        raise AuditError(
            ErrorCode.INVALID_REQUEST,
            -1,
            f"maxWindow 必须在 {MIN_WINDOW}..{MAX_WINDOW} 之间",
        )

    raw_frames = body.get("frames")
    if not isinstance(raw_frames, list) or not raw_frames:
        raise AuditError(
            ErrorCode.INVALID_REQUEST, -1, "frames 必须为包含 1 个以上帧的数组"
        )
    if len(raw_frames) > MAX_FRAMES:
        raise AuditError(
            ErrorCode.INVALID_REQUEST,
            -1,
            f"frames 数量超过上限 {MAX_FRAMES}",
        )

    frames: list[tuple[str, Optional[int], ParsedFrame]] = []
    previous_ts: Optional[int] = None
    for index, item in enumerate(raw_frames):
        if not isinstance(item, dict):
            raise AuditError(
                ErrorCode.INVALID_REQUEST, index, "每一帧必须为 JSON 对象"
            )
        direction = normalize_direction(item.get("direction"))
        if direction is None:
            raise AuditError(
                ErrorCode.INVALID_REQUEST,
                index,
                "direction 必须为 client 或 server（也接受 master/slave 等别名）",
            )
        captured_at = item.get("capturedAtUs")
        if captured_at is not None:
            if isinstance(captured_at, bool) or not isinstance(captured_at, int):
                raise AuditError(
                    ErrorCode.INVALID_REQUEST,
                    index,
                    "capturedAtUs 必须为整数微秒时间戳",
                )
            if captured_at < 0:
                raise AuditError(
                    ErrorCode.INVALID_REQUEST,
                    index,
                    "capturedAtUs 不能为负数",
                )
            if previous_ts is not None and captured_at < previous_ts:
                raise AuditError(
                    ErrorCode.FRAMES_NOT_ORDERED,
                    index,
                    "capturedAtUs 早于之前的帧，帧未按非递减顺序排列",
                )
            previous_ts = captured_at
        try:
            parsed = parse_apdu(item.get("apdu"))
        except AuditError as exc:
            # 解析期错误没有帧下标，在此绑定到当前帧。
            raise AuditError(exc.code, index, exc.message) from None
        frames.append((direction, captured_at, parsed))

    return _audit(frames, max_window)


def _audit(
    frames: list[tuple[str, Optional[int], ParsedFrame]], max_window: int
) -> dict:
    states = {CLIENT: _PeerState(), SERVER: _PeerState()}
    # 每类 U 服务至多一个待配对 act：(发起方向, 帧下标)。
    pending: dict[str, Optional[tuple[str, int]]] = {
        "STARTDT": None,
        "STOPDT": None,
        "TESTFR": None,
    }
    counts = {
        "i": {CLIENT: 0, SERVER: 0},
        "u_act": {"STARTDT": 0, "STOPDT": 0, "TESTFR": 0},
        "u_con": {"STARTDT": 0, "STOPDT": 0, "TESTFR": 0},
        "u_paired": {"STARTDT": 0, "STOPDT": 0, "TESTFR": 0},
    }
    started = False

    for index, (direction, _captured_at, frame) in enumerate(frames):
        peer = states[direction]
        remote = states[_opposite(direction)]

        if frame.kind == "U":
            assert frame.u_type is not None
            started = _apply_u(
                frame.u_type, bool(frame.u_act), direction, index,
                pending, counts, started,
            )
            continue

        # I 帧只能出现在 STARTDT 已确认、STOPDT 未确认的数据传送阶段；
        # 阶段判定先于序号/确认号核验，以便最早定位该帧。
        if frame.kind == "I" and not started:
            raise AuditError(
                ErrorCode.I_FRAME_OUTSIDE_PHASE,
                index,
                "I 帧出现在 STARTDT 确认之前或 STOPDT 确认之后的数据传送阶段之外",
            )

        # I/S 帧均携带 N(R)，先核验确认号。
        assert frame.recv_seq is not None
        ack = frame.recv_seq
        if ack < peer.last_ack:
            raise AuditError(
                ErrorCode.ACK_BACKWARDS,
                index,
                f"确认号倒退：本端此前已确认到 {peer.last_ack}，本帧 N(R)={ack}",
            )
        if ack > remote.next_send:
            raise AuditError(
                ErrorCode.ACK_AHEAD,
                index,
                f"确认号越过对端已发送数据：对端已发送 {remote.next_send} 个 I 帧，"
                f"本帧 N(R)={ack}",
            )
        peer.last_ack = ack

        if frame.kind == "S":
            continue

        assert frame.send_seq is not None
        if frame.send_seq != peer.next_send:
            raise AuditError(
                ErrorCode.SEND_SEQUENCE_INVALID,
                index,
                f"发送序号失序：期望 N(S)={peer.next_send}，本帧 N(S)={frame.send_seq}",
            )
        peer.next_send += 1
        counts["i"][direction] += 1

        outstanding = peer.next_send - remote.last_ack
        if outstanding > max_window:
            raise AuditError(
                ErrorCode.WINDOW_EXCEEDED,
                index,
                f"本端未确认 I 帧数达到 {outstanding}，"
                f"超过最大未确认窗口 {max_window}",
            )

    # 会话结束时仍有 act 未与相反方向 con 配对：定位最早的未配对 act。
    earliest: Optional[tuple[int, str]] = None
    for u_type, mark in pending.items():
        if mark is not None:
            act_index = mark[1]
            if earliest is None or act_index < earliest[0]:
                earliest = (
                    act_index,
                    f"会话结束时 {u_type} act 仍未收到相反方向的 con 配对",
                )
    if earliest is not None:
        raise AuditError(
            ErrorCode.HANDSHAKE_UNMATCHED, earliest[0], earliest[1]
        )

    return {
        "ok": True,
        "result": {
            "iFrames": {
                CLIENT: counts["i"][CLIENT],
                SERVER: counts["i"][SERVER],
            },
            "outstanding": {
                # client 已发送但 server 尚未确认的 I 帧数，反之亦然。
                CLIENT: states[CLIENT].next_send - states[SERVER].last_ack,
                SERVER: states[SERVER].next_send - states[CLIENT].last_ack,
            },
            "handshakes": {
                name: {
                    "act": counts["u_act"][name],
                    "con": counts["u_con"][name],
                    "paired": counts["u_paired"][name],
                }
                for name in ("STARTDT", "STOPDT", "TESTFR")
            },
        },
    }


def _apply_u(
    u_type: str,
    is_act: bool,
    direction: str,
    index: int,
    pending: dict,
    counts: dict,
    started: bool,
) -> bool:
    """处理一帧 U 格式原语，返回更新后的 started（数据传送阶段）状态。"""
    counts["u_act" if is_act else "u_con"][u_type] += 1
    mark = pending[u_type]

    if is_act:
        # TESTFR 可在任意阶段出现；STARTDT/STOPDT 的阶段合法性仅约束 I 帧，
        # 这里只禁止同一服务存在尚未配对的 act 时再次发起。
        if mark is not None:
            raise AuditError(
                ErrorCode.HANDSHAKE_OVERLAP,
                index,
                f"上一个 {u_type} act 尚未收到相反方向的 con，又出现新的 act",
            )
        pending[u_type] = (direction, index)
        return started

    # con 必须与相反方向上待配对的 act 成对。
    if mark is None:
        raise AuditError(
            ErrorCode.HANDSHAKE_UNMATCHED,
            index,
            f"{u_type} con 没有来自相反方向的待配对 act",
        )
    act_direction, _ = mark
    if act_direction != _opposite(direction):
        raise AuditError(
            ErrorCode.HANDSHAKE_UNMATCHED,
            index,
            f"{u_type} con 与 act 来自同一方向，act/con 必须由相反方向配对",
        )

    pending[u_type] = None
    counts["u_paired"][u_type] += 1
    if u_type == "STARTDT":
        return True
    if u_type == "STOPDT":
        return False
    return started
