"""Unit tests for batched X12 interchange auditing (batch=interchanges).

A batch body concatenates 1..16 complete interchanges separated only by
CR/LF; every ISA declares its own delimiters and ISA13 control numbers
must be unique within the batch.
"""

from __future__ import annotations

import hashlib
import unittest

from app.audit import (
    MAX_INTERCHANGES,
    MAX_MESSAGE_BYTES,
    EnvelopeError,
    audit,
    audit_batch,
)
from tests.test_audit import build_message, isa


def msg(control: str = "000000001", **kwargs) -> bytes:
    return build_message([[0]], control=control, **kwargs)


def expect_error(testcase: unittest.TestCase, raw: bytes, code: str):
    with testcase.assertRaises(EnvelopeError) as ctx:
        audit_batch(raw)
    testcase.assertEqual(ctx.exception.code, code)
    return ctx.exception


class BatchValidTests(unittest.TestCase):
    def test_single_interchange_in_batch_mode(self):
        raw = msg("000000001")
        result = audit_batch(raw)
        self.assertEqual(result.interchange_count, 1)
        self.assertEqual(result.group_count, 1)
        self.assertEqual(result.transaction_count, 1)
        self.assertEqual(
            [i.interchange_control_number for i in result.interchanges],
            ["000000001"],
        )
        self.assertEqual(result.sha256, hashlib.sha256(raw).hexdigest())
        only = result.interchanges[0]
        self.assertEqual(only.sha256, hashlib.sha256(raw).hexdigest())

    def test_single_mode_contract_unchanged(self):
        raw = msg("000000001")
        single = audit(raw)
        batched = audit_batch(raw).interchanges[0]
        self.assertEqual(
            single.interchange_control_number,
            batched.interchange_control_number,
        )
        self.assertEqual(single.group_count, batched.group_count)
        self.assertEqual(single.transaction_count, batched.transaction_count)
        self.assertEqual(single.sha256, batched.sha256)

    def test_two_interchanges_crlf(self):
        first = msg("000000001")
        second = build_message([[0, 2]], control="000000002")
        raw = first + b"\r\n" + second
        result = audit_batch(raw)
        self.assertEqual(result.interchange_count, 2)
        self.assertEqual(result.group_count, 2)
        self.assertEqual(result.transaction_count, 3)
        self.assertEqual(
            [i.interchange_control_number for i in result.interchanges],
            ["000000001", "000000002"],
        )
        self.assertEqual(
            result.interchanges[0].sha256, hashlib.sha256(first).hexdigest()
        )
        self.assertEqual(
            result.interchanges[1].sha256, hashlib.sha256(second).hexdigest()
        )
        self.assertEqual(result.sha256, hashlib.sha256(raw).hexdigest())

    def test_cr_lf_separator_variants(self):
        first = msg("000000001")
        second = msg("000000002")
        for gap in (b"\n", b"\r", b"\r\n", b"\n\r", b"\r\n\r\n", b"\n\n"):
            with self.subTest(gap=gap):
                result = audit_batch(first + gap + second)
                self.assertEqual(result.interchange_count, 2)

    def test_trailing_crlf_after_final_interchange(self):
        raw = msg("000000001") + b"\r\n"
        result = audit_batch(raw)
        self.assertEqual(result.interchange_count, 1)

    def test_different_delimiters_per_interchange(self):
        first = msg("000000001")
        second = build_message(
            [[1]],
            control="000000002",
            element="|",
            component="^",
            terminator="\n",
        )
        raw = first + b"\r\n" + second
        result = audit_batch(raw)
        self.assertEqual(result.interchange_count, 2)
        self.assertEqual(result.group_count, 2)
        self.assertEqual(result.transaction_count, 2)

    def test_foreign_terminator_byte_is_payload_in_next_interchange(self):
        # The first interchange terminates with '~'; the second uses LF and
        # carries '~' as ordinary payload data.  The delimiter switch must
        # not cause the two interchanges to be stitched together or split
        # wrongly.
        second = (
            isa("000000002", element="|", component="^", terminator="\n")
            + "GS|PO|S|R|D|T|2|X|V\n"
            + "ST|850|200\n"
            + "REF|A~B~C\n"
            + "SE|3|200\n"
            + "GE|1|2\n"
            + "IEA|1|000000002\n"
        ).encode("ascii")
        raw = msg("000000001") + b"\r\n" + second
        result = audit_batch(raw)
        self.assertEqual(result.interchange_count, 2)
        self.assertEqual(result.transaction_count, 2)

    def test_summaries_in_input_order_with_totals(self):
        raw = b"\n".join(
            [
                build_message([[0]], control="000000001"),
                build_message([[0, 0, 0]], control="000000002"),
                build_message([[0], [0]], control="000000003"),
            ]
        )
        result = audit_batch(raw)
        self.assertEqual(
            [i.interchange_control_number for i in result.interchanges],
            ["000000001", "000000002", "000000003"],
        )
        self.assertEqual(result.interchange_count, 3)
        # 1 + 1 + 2 groups and 1 + 3 + 2 transactions.
        self.assertEqual(result.group_count, 4)
        self.assertEqual(result.transaction_count, 6)

    def test_sixteen_interchanges_accepted(self):
        bodies = [
            build_message([[0]], control=f"{index:09d}")
            for index in range(1, MAX_INTERCHANGES + 1)
        ]
        raw = b"\n".join(bodies)
        result = audit_batch(raw)
        self.assertEqual(result.interchange_count, MAX_INTERCHANGES)
        self.assertEqual(result.group_count, MAX_INTERCHANGES)
        self.assertEqual(result.transaction_count, MAX_INTERCHANGES)


class BatchFramingTests(unittest.TestCase):
    def test_empty_body(self):
        error = expect_error(self, b"", "EMPTY_MESSAGE")
        self.assertEqual(error.segment, 1)
        self.assertEqual(error.interchange, 1)

    def test_too_large(self):
        expect_error(self, b"x" * (MAX_MESSAGE_BYTES + 1), "MESSAGE_TOO_LARGE")

    def test_adjacent_interchanges_without_separator(self):
        raw = msg("000000001") + msg("000000002")
        error = expect_error(self, raw, "INVALID_INTERCHANGE_SEPARATOR")
        # First interchange is six segments; the error is at the start of
        # the would-be second interchange.
        self.assertEqual(error.segment, 7)
        self.assertEqual(error.interchange, 2)

    def test_junk_between_interchanges(self):
        raw = msg("000000001") + b"X" + msg("000000002")
        error = expect_error(self, raw, "INVALID_INTERCHANGE_SEPARATOR")
        self.assertEqual(error.segment, 7)
        self.assertEqual(error.interchange, 2)

    def test_garbage_after_crlf_gap(self):
        raw = msg("000000001") + b"\r\nZZZ*1~\n" + msg("000000002")
        error = expect_error(self, raw, "INVALID_INTERCHANGE_SEPARATOR")
        self.assertEqual(error.segment, 7)
        self.assertEqual(error.interchange, 2)

    def test_tab_is_not_a_valid_separator(self):
        raw = msg("000000001") + b"\t\n" + msg("000000002")
        error = expect_error(self, raw, "INVALID_INTERCHANGE_SEPARATOR")
        self.assertEqual(error.interchange, 2)

    def test_seventeen_interchanges_rejected(self):
        raw = b"\n".join(
            [
                build_message([[0]], control=f"{index:09d}")
                for index in range(1, MAX_INTERCHANGES + 2)
            ]
        )
        error = expect_error(self, raw, "BATCH_LIMIT_EXCEEDED")
        self.assertEqual(error.interchange, 17)
        # Each minimal interchange is six segments: 16 * 6 + 1 = 97.
        self.assertEqual(error.segment, 97)

    def test_second_isa_bad_delimiter(self):
        second = bytearray(msg("000000002"))
        second[3] = ord("A")
        raw = msg("000000001") + b"\n" + bytes(second)
        error = expect_error(self, raw, "BAD_DELIMITER")
        self.assertEqual(error.segment, 7)
        self.assertEqual(error.interchange, 2)

    def test_second_isa_too_short(self):
        raw = msg("000000001") + b"\r\nISA*00"
        error = expect_error(self, raw, "ISA_TOO_SHORT")
        self.assertEqual(error.segment, 7)
        self.assertEqual(error.interchange, 2)

    def test_second_interchange_does_not_start_with_isa(self):
        # A non-ISA start after a CR/LF gap is stray content between
        # interchanges, not a malformed second interchange header.
        raw = msg("000000001") + b"\r\nGS*PO~"
        error = expect_error(self, raw, "INVALID_INTERCHANGE_SEPARATOR")
        self.assertEqual(error.segment, 7)
        self.assertEqual(error.interchange, 2)

    def test_second_isa_with_wrong_tag_but_right_length(self):
        # A 106-byte header whose tag is not ISA: the separator rule locates
        # the junk before the header itself is parsed.
        second = b"XXX" + msg("000000002")[3:]
        raw = msg("000000001") + b"\r\n" + second
        error = expect_error(self, raw, "INVALID_INTERCHANGE_SEPARATOR")
        self.assertEqual(error.segment, 7)
        self.assertEqual(error.interchange, 2)


class BatchContentTests(unittest.TestCase):
    def test_duplicate_interchange_control_number(self):
        raw = msg("000000001") + b"\r\n" + msg("000000001")
        error = expect_error(
            self, raw, "DUPLICATE_INTERCHANGE_CONTROL_NUMBER"
        )
        self.assertEqual(error.segment, 7)
        self.assertEqual(error.interchange, 2)

    def test_duplicate_control_number_reported_before_body_damage(self):
        # The second interchange reuses ISA13 and is also internally
        # damaged; the duplicate (locatable on the ISA itself) wins.
        damaged = msg("000000001").replace(b"SE*2*1001~", b"SE*9*1001~", 1)
        raw = msg("000000001") + b"\r\n" + damaged
        error = expect_error(
            self, raw, "DUPLICATE_INTERCHANGE_CONTROL_NUMBER"
        )
        self.assertEqual(error.interchange, 2)
        self.assertEqual(error.segment, 7)

    def test_duplicate_control_number_in_third_interchange(self):
        raw = b"\n".join(
            [
                msg("000000001"),
                msg("000000002"),
                msg("000000002"),
            ]
        )
        error = expect_error(
            self, raw, "DUPLICATE_INTERCHANGE_CONTROL_NUMBER"
        )
        self.assertEqual(error.interchange, 3)
        self.assertEqual(error.segment, 13)

    def test_damage_in_second_interchange_segment_count(self):
        # First interchange: six segments.  Second interchange: ISA, GS,
        # ST, BEG, SE(wrong), GE, IEA.
        second = build_message([[1]], control="000000002").replace(
            b"SE*3*1001~", b"SE*2*1001~", 1
        )
        raw = msg("000000001") + b"\r\n" + second
        error = expect_error(self, raw, "SEGMENT_COUNT_MISMATCH")
        # SE is local segment 5 in interchange 2 -> batch segment 6 + 5.
        self.assertEqual(error.segment, 11)
        self.assertEqual(error.interchange, 2)

    def test_damage_in_second_interchange_control_number(self):
        second = msg("000000002").replace(b"SE*2*1001~", b"SE*2*9999~", 1)
        raw = msg("000000001") + b"\r\n" + second
        error = expect_error(self, raw, "CONTROL_NUMBER_MISMATCH")
        self.assertEqual(error.segment, 10)
        self.assertEqual(error.interchange, 2)

    def test_damage_in_third_interchange_uses_batch_segment_number(self):
        third = msg("000000003").replace(b"GE*1*1~", b"GE*2*1~", 1)
        raw = b"\n".join(
            [msg("000000001"), msg("000000002"), third]
        )
        error = expect_error(self, raw, "GE_COUNT_MISMATCH")
        # Two prior six-segment interchanges; GE is local segment 5.
        self.assertEqual(error.segment, 17)
        self.assertEqual(error.interchange, 3)

    def test_clean_first_iea_does_not_mask_second_truncation(self):
        # The second interchange is truncated mid-way; its missing closing
        # segments must still be rejected.
        second = (
            isa("000000002")
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*1001~SE*2*1001~"
        ).encode("ascii")
        raw = msg("000000001") + b"\r\n" + second
        error = expect_error(self, raw, "MISSING_GE")
        self.assertEqual(error.interchange, 2)
        # The GS segment is local segment 2 in interchange 2.
        self.assertEqual(error.segment, 8)

    def test_clean_first_iea_does_not_mask_second_missing_terminator(self):
        second = msg("000000002")
        raw = msg("000000001") + b"\r\n" + second[:-1]
        error = expect_error(self, raw, "MISSING_TERMINATOR")
        self.assertEqual(error.interchange, 2)
        self.assertEqual(error.segment, 12)

    def test_error_in_first_interchange_still_attributed_to_one(self):
        first = msg("000000001").replace(b"GE*1*1~", b"GE*2*1~", 1)
        raw = first + b"\r\n" + msg("000000002")
        error = expect_error(self, raw, "GE_COUNT_MISMATCH")
        self.assertEqual(error.segment, 5)
        self.assertEqual(error.interchange, 1)

    def test_non_ascii_in_second_interchange_body(self):
        first = msg("000000001")
        second = bytearray(build_message([[1]], control="000000002"))
        # The BEG payload segment spans bytes 165..173 of the second
        # interchange (local segment 4, batch segment 10).
        second[168] = 0x80
        raw = first + b"\r\n" + bytes(second)
        error = expect_error(self, raw, "NON_ASCII")
        self.assertEqual(error.interchange, 2)
        self.assertEqual(error.segment, 10)

    def test_non_ascii_between_interchanges(self):
        # A non-ASCII byte in the gap is not a CR/LF separator.
        raw = msg("000000001") + b"\r\x80\n" + msg("000000002")
        error = expect_error(self, raw, "INVALID_INTERCHANGE_SEPARATOR")
        self.assertEqual(error.interchange, 2)
        self.assertEqual(error.segment, 7)

    def test_non_ascii_in_second_isa(self):
        second = bytearray(msg("000000002"))
        second[10] = 0x80
        raw = msg("000000001") + b"\r\n" + bytes(second)
        error = expect_error(self, raw, "NON_ASCII")
        self.assertEqual(error.interchange, 2)
        self.assertEqual(error.segment, 7)

    def test_first_interchange_never_closed_before_next_isa(self):
        # First interchange lacks its IEA but a second ISA follows.
        first = (
            isa("000000001")
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*1001~SE*2*1001~GE*1*1~"
        ).encode("ascii")
        raw = first + b"\r\n" + msg("000000002")
        error = expect_error(self, raw, "MISSING_IEA")
        self.assertEqual(error.interchange, 1)


if __name__ == "__main__":
    unittest.main()
