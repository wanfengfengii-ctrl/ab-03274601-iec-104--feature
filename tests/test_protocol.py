"""IEC 104 会话核验单元测试。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

from protocol import (  # noqa: E402
    AuditError,
    ErrorCode,
    audit_request,
    parse_apdu,
)


def i_frame(send: int, recv: int = 0, asdu: bytes = b"\x01\x04\x03\x00\x00\x00") -> str:
    """构造 I 格式 APDU 的十六进制字符串。send/recv 为未左移的序号。"""
    b2 = (send << 1) & 0xFF
    b3 = (send << 1) >> 8
    b4 = (recv << 1) & 0xFF
    b5 = (recv << 1) >> 8
    body = bytes([b2, b3, b4, b5]) + asdu
    return (bytes([0x68, len(body)]) + body).hex()


def s_frame(recv: int) -> str:
    body = bytes([0x01, 0x00, (recv << 1) & 0xFF, (recv << 1) >> 8])
    return (bytes([0x68, 4]) + body).hex()


STARTDT_ACT = "680407000000"
STARTDT_CON = "68040b000000"
STOPDT_ACT = "680413000000"
STOPDT_CON = "680423000000"
TESTFR_ACT = "680443000000"
TESTFR_CON = "680483000000"


def f(direction: str, apdu: str, ts=None) -> dict:
    frame = {"direction": direction, "apdu": apdu}
    if ts is not None:
        frame["capturedAtUs"] = ts
    return frame


def audit(frames, window=12):
    return audit_request({"frames": frames, "maxWindow": window})


def expect_error(frames, code: ErrorCode, index: int, window=12):
    try:
        audit(frames, window)
    except AuditError as exc:
        assert exc.code is code, f"期望 {code}，实际 {exc.code}"
        assert exc.frame_index == index, (
            f"期望下标 {index}，实际 {exc.frame_index}（{exc.message}）"
        )
        return exc
    raise AssertionError(f"应当抛出 {code}，但核验通过了")


class ParseTests(unittest.TestCase):
    def test_valid_u_s_i(self):
        self.assertEqual(parse_apdu(STARTDT_ACT).u_type, "STARTDT")
        self.assertTrue(parse_apdu(STARTDT_ACT).u_act)
        self.assertFalse(parse_apdu(STARTDT_CON).u_act)
        self.assertEqual(parse_apdu(s_frame(3)).recv_seq, 3)
        parsed = parse_apdu(i_frame(5, 7))
        self.assertEqual((parsed.send_seq, parsed.recv_seq), (5, 7))

    def test_high_sequence_numbers(self):
        parsed = parse_apdu(i_frame(32767, 32767))
        self.assertEqual(parsed.send_seq, 32767)
        self.assertEqual(parsed.recv_seq, 32767)

    def test_bad_start_byte(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("690407000000")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)

    def test_length_mismatch_trailing(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("68040700000000")  # 尾随字节
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)

    def test_length_mismatch_truncated(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("680607000000")  # 声称 6 字节实际只有 4
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)

    def test_length_below_four(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("6803070000")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)

    def test_too_short(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("6804070000")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)

    def test_bad_hex(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("68 04 zz")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)

    def test_s_reserved_bit(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("680401010000")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_CONTROL_FIELD)

    def test_u_reserved_bytes(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("680407000001")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_CONTROL_FIELD)

    def test_u_unknown_function(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("6804c3000000")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_CONTROL_FIELD)

    def test_spaces_allowed_in_hex(self):
        self.assertEqual(parse_apdu("68 04 07 00 00 00").u_type, "STARTDT")

    def test_u_frame_with_asdu_rejected(self):
        # U 格式长度必须恰为 4，不能携带 ASDU
        with self.assertRaises(AuditError) as cm:
            parse_apdu("68050700000000")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)

    def test_s_frame_with_asdu_rejected(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("68050100000000")
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)

    def test_length_field_too_large(self):
        with self.assertRaises(AuditError) as cm:
            parse_apdu("68fe" + "00" * 254)
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_APDU)


class HappyPathTests(unittest.TestCase):
    def _minimal_start(self):
        return [
            f("client", STARTDT_ACT, 10),
            f("server", STARTDT_CON, 20),
        ]

    def test_start_stop_only(self):
        frames = self._minimal_start() + [
            f("client", STOPDT_ACT, 30),
            f("server", STOPDT_CON, 40),
        ]
        result = audit(frames)["result"]
        self.assertEqual(result["iFrames"], {"client": 0, "server": 0})
        self.assertEqual(result["outstanding"], {"client": 0, "server": 0})
        self.assertEqual(result["handshakes"]["STARTDT"],
                         {"act": 1, "con": 1, "paired": 1})
        self.assertEqual(result["handshakes"]["STOPDT"],
                         {"act": 1, "con": 1, "paired": 1})

    def test_full_data_exchange(self):
        frames = self._minimal_start()
        # client 发送 I0、I1，server 回 I0 并捎带确认，再互相确认干净
        frames += [
            f("client", i_frame(0, 0), 100),
            f("client", i_frame(1, 0), 200),
            f("server", i_frame(0, 2), 300),  # 确认 client 的 2 帧
            f("client", s_frame(1), 400),     # 确认 server 的 I0
        ]
        result = audit(frames, window=2)["result"]
        self.assertEqual(result["iFrames"], {"client": 2, "server": 1})
        self.assertEqual(result["outstanding"], {"client": 0, "server": 0})

    def test_final_outstanding_counts(self):
        frames = self._minimal_start() + [
            f("client", i_frame(0, 0), 100),
            f("client", i_frame(1, 0), 101),
            f("client", i_frame(2, 0), 102),
        ]
        result = audit(frames, window=3)["result"]
        self.assertEqual(result["outstanding"], {"client": 3, "server": 0})
        self.assertEqual(result["iFrames"]["client"], 3)

    def test_testfr_anywhere(self):
        frames = [
            f("client", TESTFR_ACT, 1),
            f("server", TESTFR_CON, 2),
        ] + self._minimal_start() + [
            f("client", i_frame(0, 0), 100),
            f("server", s_frame(1), 101),
            f("server", TESTFR_ACT, 102),
            f("client", TESTFR_CON, 103),
        ]
        result = audit(frames)["result"]
        self.assertEqual(result["handshakes"]["TESTFR"],
                         {"act": 2, "con": 2, "paired": 2})

    def test_equal_timestamps_are_nondecreasing(self):
        frames = self._minimal_start()
        frames.append(f("client", i_frame(0, 0), 20))  # 与 STARTDT_CON 同刻
        audit(frames)

    def test_slave_alias_direction(self):
        frames = [
            {"direction": "master", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "slave", "apdu": STARTDT_CON, "capturedAtUs": 2},
        ]
        self.assertTrue(audit(frames)["ok"])

    def test_restart_after_stop(self):
        # 同一连接上 STOPDT 后重新 STARTDT，序号继续而不归零。
        frames = self._minimal_start() + [
            f("client", i_frame(0, 0), 100),
            f("server", s_frame(1), 101),
            f("client", STOPDT_ACT, 102),
            f("server", STOPDT_CON, 103),
            f("client", STARTDT_ACT, 104),
            f("server", STARTDT_CON, 105),
            f("client", i_frame(1, 0), 106),  # 继续上一个发送序号
            f("server", s_frame(2), 107),
        ]
        result = audit(frames)["result"]
        self.assertEqual(result["iFrames"]["client"], 2)

    def test_window_boundary_allowed(self):
        frames = self._minimal_start()
        for n in range(8):
            frames.append(f("client", i_frame(n, 0), 100 + n))
        audit(frames, window=8)  # 恰好等于窗口，合法


class ViolationTests(unittest.TestCase):
    def _started(self):
        return [f("client", STARTDT_ACT, 1), f("server", STARTDT_CON, 2)]

    def test_send_seq_must_start_at_zero(self):
        frames = self._started() + [f("client", i_frame(1, 0), 3)]
        expect_error(frames, ErrorCode.SEND_SEQUENCE_INVALID, 2)

    def test_send_seq_gap(self):
        frames = self._started() + [
            f("client", i_frame(0, 0), 3),
            f("client", i_frame(2, 0), 4),
        ]
        expect_error(frames, ErrorCode.SEND_SEQUENCE_INVALID, 3)

    def test_send_seq_duplicate(self):
        frames = self._started() + [
            f("client", i_frame(0, 0), 3),
            f("client", i_frame(0, 0), 4),
        ]
        expect_error(frames, ErrorCode.SEND_SEQUENCE_INVALID, 3)

    def test_ack_ahead_of_sent(self):
        frames = self._started() + [
            f("client", i_frame(0, 0), 3),
            f("server", s_frame(1), 4),   # 合法：确认 1 帧
            f("server", s_frame(2), 5),   # 非法：client 只发了 1 帧
        ]
        expect_error(frames, ErrorCode.ACK_AHEAD, 4)

    def test_ack_backwards(self):
        frames = self._started() + [
            f("client", i_frame(0, 0), 3),
            f("server", s_frame(1), 4),      # server last_ack=1
            f("server", i_frame(0, 1), 5),
            f("client", i_frame(1, 1), 6),
            f("server", s_frame(0), 7),      # server 确认号从 1 倒退到 0
        ]
        expect_error(frames, ErrorCode.ACK_BACKWARDS, 6)

    def test_piggybacked_ack_ahead(self):
        frames = self._started() + [
            f("server", i_frame(0, 1), 3),  # server 的首帧却确认 client 的 1 帧
        ]
        expect_error(frames, ErrorCode.ACK_AHEAD, 2)

    def test_window_exceeded(self):
        frames = self._started()
        for n in range(3):
            frames.append(f("client", i_frame(n, 0), 10 + n))
        # 窗口为 2，第三帧后未确认数达到 3
        expect_error(frames, ErrorCode.WINDOW_EXCEEDED, 4, window=2)

    def test_window_cleared_by_ack(self):
        frames = self._started()
        frames += [
            f("client", i_frame(0, 0), 3),
            f("client", i_frame(1, 0), 4),
            f("server", s_frame(2), 5),  # 窗口清空
            f("client", i_frame(2, 0), 6),
            f("client", i_frame(3, 0), 7),
        ]
        audit(frames, window=2)  # 不抛异常即通过

    def test_i_before_startdt_con(self):
        frames = [
            f("client", STARTDT_ACT, 1),
            f("client", i_frame(0, 0), 2),
        ]
        expect_error(frames, ErrorCode.I_FRAME_OUTSIDE_PHASE, 1)

    def test_i_without_any_startdt(self):
        frames = [f("client", i_frame(0, 0), 1)]
        expect_error(frames, ErrorCode.I_FRAME_OUTSIDE_PHASE, 0)

    def test_i_after_stopdt_con(self):
        frames = self._started() + [
            f("client", i_frame(0, 0), 3),
            f("server", s_frame(1), 4),
            f("client", STOPDT_ACT, 5),
            f("server", STOPDT_CON, 6),
            f("client", i_frame(1, 0), 7),
        ]
        expect_error(frames, ErrorCode.I_FRAME_OUTSIDE_PHASE, 6)

    def test_i_between_stopdt_act_and_con(self):
        # I 帧只能在“启动已确认且尚未停止”阶段；STOPDT act 后 con 前，
        # 尚未确认停止，I 帧仍允许。
        frames = self._started() + [
            f("client", STOPDT_ACT, 3),
            f("client", i_frame(0, 0), 4),
            f("server", STOPDT_CON, 5),
        ]
        audit(frames)

    def test_handshake_same_direction_rejected(self):
        frames = [
            f("client", STARTDT_ACT, 1),
            f("client", STARTDT_CON, 2),  # con 必须来自相反方向
        ]
        expect_error(frames, ErrorCode.HANDSHAKE_UNMATCHED, 1)

    def test_con_without_act(self):
        frames = [f("server", TESTFR_CON, 1)]
        expect_error(frames, ErrorCode.HANDSHAKE_UNMATCHED, 0)

    def test_overlapping_act(self):
        frames = [
            f("client", TESTFR_ACT, 1),
            f("client", TESTFR_ACT, 2),  # 上一个尚未配对
        ]
        expect_error(frames, ErrorCode.HANDSHAKE_OVERLAP, 1)

    def test_unterminated_startdt_points_at_act(self):
        frames = [
            f("client", STARTDT_ACT, 1),  # 会话结束仍无 con，定位到该 act
        ]
        exc = expect_error(frames, ErrorCode.HANDSHAKE_UNMATCHED, 0)
        self.assertNotIn("后续", exc.message)

    def test_unterminated_earliest_of_many(self):
        frames = [
            f("client", TESTFR_ACT, 1),
            f("client", STARTDT_ACT, 2),
            f("server", TESTFR_CON, 3),
        ]
        # TESTFR 已配对，STARTDT act(下标1) 未配对
        expect_error(frames, ErrorCode.HANDSHAKE_UNMATCHED, 1)

    def test_timestamps_not_ordered(self):
        frames = self._started()
        frames[1] = f("server", STARTDT_CON, 5)
        frames.append(f("client", STOPDT_ACT, 4))  # 时间倒退
        expect_error(frames, ErrorCode.FRAMES_NOT_ORDERED, 2)

    def test_invalid_apdu_carries_index(self):
        frames = self._started() + [
            f("client", i_frame(0, 0), 3),
            f("server", "6804ffffffff", 4),  # U 功能码非法
        ]
        expect_error(frames, ErrorCode.INVALID_CONTROL_FIELD, 3)

    def test_trailing_byte_rejected(self):
        frames = [f("client", STARTDT_ACT + "ff", 1)]
        expect_error(frames, ErrorCode.INVALID_APDU, 0)

    def test_first_error_is_earliest_frame(self):
        # 下标 2 的窗口问题与下标 3 的倒序时间戳同时存在，应先报下标 2
        frames = self._started()
        frames += [
            f("client", i_frame(0, 0), 10),
            f("client", i_frame(1, 0), 11),
            f("client", i_frame(2, 0), 9),  # 时间戳倒序在解析期先被发现
        ]
        expect_error(frames, ErrorCode.FRAMES_NOT_ORDERED, 4, window=2)


class AckEvidenceTests(unittest.TestCase):
    """ackEvidence 逐帧确认时延取证。"""

    def _started(self, t0=0, t1=10):
        return [f("client", STARTDT_ACT, t0), f("server", STARTDT_CON, t1)]

    def audit_ack(self, frames, max_delay, capture_end, window=12):
        return audit_request({
            "frames": frames,
            "maxWindow": window,
            "ackEvidence": {
                "maxDelayUs": max_delay,
                "captureEndAtUs": capture_end,
            },
        })

    def expect_ack_timeout(self, frames, max_delay, capture_end, index, window=12):
        try:
            self.audit_ack(frames, max_delay, capture_end, window)
        except AuditError as exc:
            assert exc.code is ErrorCode.I_ACK_TIMEOUT, f"实际 {exc.code}"
            assert exc.frame_index == index, (
                f"期望下标 {index}，实际 {exc.frame_index}（{exc.message}）"
            )
            return exc
        raise AssertionError("应当抛出 I_ACK_TIMEOUT，但核验通过了")

    def test_old_contract_omits_ack_evidence(self):
        frames = self._started(1, 2) + [
            f("client", i_frame(0, 0), 3),
            f("server", s_frame(1), 4),
        ]
        self.assertNotIn("ackEvidence", audit(frames)["result"])
        # 完全不带时间戳同样保持旧契约
        bare = [
            {"direction": "client", "apdu": STARTDT_ACT},
            {"direction": "server", "apdu": STARTDT_CON},
            {"direction": "client", "apdu": i_frame(0, 0)},
            {"direction": "server", "apdu": s_frame(1)},
        ]
        self.assertNotIn("ackEvidence", audit(bare)["result"])

    def test_piggyback_and_cumulative_ack_evidence(self):
        frames = self._started(0, 10) + [
            f("client", i_frame(0, 0), 100),
            f("client", i_frame(1, 0), 110),
            f("client", i_frame(2, 0), 120),
            f("server", i_frame(0, 2), 200),  # 捎带并累计确认 client 的 I0、I1
            f("server", s_frame(3), 215),     # 确认 client 的 I2
            f("client", s_frame(1), 220),     # 确认 server 的 I0
        ]
        result = self.audit_ack(frames, 100, 220)["result"]
        self.assertEqual(
            result["ackEvidence"]["client"],
            [
                {"sendIndex": 2, "ackIndex": 5, "delayUs": 100},  # 恰等于上限
                {"sendIndex": 3, "ackIndex": 5, "delayUs": 90},
                {"sendIndex": 4, "ackIndex": 6, "delayUs": 95},
            ],
        )
        self.assertEqual(
            result["ackEvidence"]["server"],
            [{"sendIndex": 5, "ackIndex": 7, "delayUs": 20}],
        )
        # 原统计保持不变
        self.assertEqual(result["iFrames"], {"client": 3, "server": 1})
        self.assertEqual(result["outstanding"], {"client": 0, "server": 0})

    def test_delay_equal_to_limit_is_legal(self):
        frames = self._started(0, 10) + [
            f("client", i_frame(0, 0), 100),
            f("server", s_frame(1), 200),  # 时延恰好 100 微秒
        ]
        result = self.audit_ack(frames, 100, 200)["result"]
        self.assertEqual(
            result["ackEvidence"]["client"],
            [{"sendIndex": 2, "ackIndex": 3, "delayUs": 100}],
        )

    def test_ack_arrival_timeout_reports_send_frame(self):
        frames = self._started(0, 10) + [
            f("client", i_frame(0, 0), 100),
            f("server", s_frame(1), 201),  # 确认到达时时延 101 > 100
        ]
        exc = self.expect_ack_timeout(frames, 100, 201, 2)
        self.assertIn("101", exc.message)

    def test_earliest_timeout_across_directions(self):
        frames = self._started(0, 10) + [
            f("server", i_frame(0, 0), 20),
            f("client", i_frame(0, 0), 30),
            f("server", s_frame(1), 200),  # client I0 时延 170，超时（下标 3）
            f("client", s_frame(1), 300),  # server I0 时延 280，超时（下标 2）
        ]
        # 两个方向均有超时，定位下标最早的发送帧
        self.expect_ack_timeout(frames, 100, 300, 2)

    def test_end_of_capture_timeout(self):
        frames = self._started(0, 10) + [
            f("client", i_frame(0, 0), 100),
            f("server", s_frame(1), 150),
            f("client", i_frame(1, 0), 160),  # 至捕获结束未确认，等待 840 > 100
        ]
        exc = self.expect_ack_timeout(frames, 100, 1000, 4)
        self.assertIn("840", exc.message)

    def test_end_of_capture_reports_earliest_unacked(self):
        frames = self._started(0, 10) + [
            f("client", i_frame(0, 0), 100),
            f("client", i_frame(1, 0), 110),  # 两帧均未确认，定位最早的 I0
        ]
        self.expect_ack_timeout(frames, 100, 1000, 2)

    def test_unacked_within_limit_at_capture_end(self):
        frames = self._started(0, 10) + [
            f("client", i_frame(0, 0), 100),
            f("client", i_frame(1, 0), 150),  # 未确认但仅等待 50，未超限
        ]
        result = self.audit_ack(frames, 100, 200)["result"]
        # 未确认帧不形成证据
        self.assertEqual(result["ackEvidence"], {"client": [], "server": []})

    def test_unacked_equal_to_limit_at_capture_end(self):
        frames = self._started(0, 10) + [
            f("client", i_frame(0, 0), 100),  # 未确认，等待恰好 100，合法
        ]
        result = self.audit_ack(frames, 100, 200)["result"]
        self.assertEqual(result["ackEvidence"]["client"], [])

    def test_no_i_frames_empty_evidence(self):
        frames = self._started(0, 10) + [
            f("client", STOPDT_ACT, 20),
            f("server", STOPDT_CON, 30),
        ]
        result = self.audit_ack(frames, 100, 30)["result"]
        self.assertEqual(result["ackEvidence"], {"client": [], "server": []})

    def test_capture_end_must_cover_last_frame(self):
        frames = self._started(0, 10) + [f("client", i_frame(0, 0), 100)]
        with self.assertRaises(AuditError) as cm:
            self.audit_ack(frames, 100, 99)  # 早于末帧
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)
        self.audit_ack(frames, 100, 100)  # 等于末帧时间戳，合法

    def test_all_frames_need_timestamp_when_enabled(self):
        frames = self._started(0, 10)
        frames.append({"direction": "client", "apdu": i_frame(0, 0)})
        with self.assertRaises(AuditError) as cm:
            self.audit_ack(frames, 100, 100)
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)
        self.assertEqual(cm.exception.frame_index, 2)

    def test_ordering_still_enforced_when_enabled(self):
        frames = [f("client", STARTDT_ACT, 10), f("server", STARTDT_CON, 5)]
        try:
            self.audit_ack(frames, 100, 100)
        except AuditError as exc:
            self.assertEqual(exc.code, ErrorCode.FRAMES_NOT_ORDERED)
            self.assertEqual(exc.frame_index, 1)
        else:
            raise AssertionError("应当抛出 FRAMES_NOT_ORDERED")

    def test_ack_evidence_param_validation(self):
        base = {"frames": self._started(0, 10), "maxWindow": 12}
        for bad in ("x", [], 100):
            with self.assertRaises(AuditError) as cm:
                audit_request({**base, "ackEvidence": bad})
            self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)
        for bad_delay in (0, 60000001, 1.5, True, "100"):
            with self.assertRaises(AuditError) as cm:
                audit_request({**base, "ackEvidence": {
                    "maxDelayUs": bad_delay, "captureEndAtUs": 10}})
            self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)
        for bad_end in (-1, 1.5, False, "10"):
            with self.assertRaises(AuditError) as cm:
                audit_request({**base, "ackEvidence": {
                    "maxDelayUs": 100, "captureEndAtUs": bad_end}})
            self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)
        for missing in ({"maxDelayUs": 100}, {"captureEndAtUs": 10}, {}):
            with self.assertRaises(AuditError) as cm:
                audit_request({**base, "ackEvidence": missing})
            self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)
        # 边界值合法
        audit_request({**base, "ackEvidence": {
            "maxDelayUs": 1, "captureEndAtUs": 10}})
        audit_request({**base, "ackEvidence": {
            "maxDelayUs": 60000000, "captureEndAtUs": 10}})


class RequestValidationTests(unittest.TestCase):
    def test_empty_frames(self):
        with self.assertRaises(AuditError) as cm:
            audit_request({"frames": [], "maxWindow": 12})
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)

    def test_window_bounds(self):
        good = [f("client", TESTFR_ACT)]
        for bad in (0, -1, 16384):
            with self.assertRaises(AuditError) as cm:
                audit_request({"frames": good, "maxWindow": bad})
            self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)

    def test_window_boundary_values_accepted(self):
        paired = [f("client", TESTFR_ACT), f("server", TESTFR_CON)]
        audit_request({"frames": paired, "maxWindow": 1})
        audit_request({"frames": paired, "maxWindow": 16383})

    def test_too_many_frames(self):
        body = {"frames": [f("client", TESTFR_CON)] * 5001, "maxWindow": 12}
        with self.assertRaises(AuditError) as cm:
            audit_request(body)
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)

    def test_bad_direction(self):
        with self.assertRaises(AuditError) as cm:
            audit_request({"frames": [f("peer", TESTFR_ACT)], "maxWindow": 12})
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)
        self.assertEqual(cm.exception.frame_index, 0)

    def test_missing_apdu(self):
        with self.assertRaises(AuditError) as cm:
            audit_request({"frames": [{"direction": "client"}], "maxWindow": 12})
        self.assertEqual(cm.exception.frame_index, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
