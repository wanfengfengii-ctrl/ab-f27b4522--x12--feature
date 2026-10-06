"""X12 interchange envelope auditing.

The auditor validates only the envelope structure (ISA/IEA, GS/GE, ST/SE):

* one ISA/IEA interchange per message (or, in batch mode, 1..16 complete
  interchanges delivered back-to-back in one body),
* 1..64 GS/GE functional groups per interchange,
* 1..500 ST/SE transaction sets per group,
* segments never interleave across the three envelope levels,
* paired control numbers match,
* SE segment counts, GE transaction counts and IEA group counts agree.

Delimiters are taken from the fixed-length ISA segment of every interchange
independently:

* element separator    = byte 4   (ISA byte offset 3),
* component separator  = byte 105 (ISA byte offset 104),
* segment terminator   = byte 106 (ISA byte offset 105).

Every error is reported at the first segment where it is locatable.  Because
segments are processed strictly in document order, an inner envelope error
(SE/GE level) is always raised before any later outer summary (IEA level)
could mask it.

Batch mode (``audit_batch`` / ``POST /api/x12/audit?batch=interchanges``)

* The body holds 1..16 complete interchanges, each with its own delimiters.
* Between interchanges only CR and LF bytes are permitted (any number,
  including none).
* ISA13 interchange control numbers must be unique within the batch.
* Errors carry a global, 1-based ``segment`` index counted from the ISA of
  the first interchange plus a 1-based ``interchange`` index, so a damaged
  later interchange is never hidden behind an earlier interchange that
  ended legally.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

MAX_MESSAGE_BYTES = 2 * 1024 * 1024  # 2 MiB

MAX_GROUPS = 64
MAX_TRANSACTIONS_PER_GROUP = 500
MAX_INTERCHANGES_PER_BATCH = 16

# Fixed element widths inside the 105-byte ISA payload (tag included).
ISA_FIELD_WIDTHS = (3, 2, 10, 2, 10, 2, 15, 2, 15, 6, 4, 1, 5, 9, 1, 1, 1)


class EnvelopeError(Exception):
    """Raised on the first envelope/framing violation.

    ``code`` is a stable, machine-readable error code and ``segment`` is the
    1-based segment index where the problem is locatable (1 for errors in
    the ISA header itself).  In batch mode ``segment`` is counted from the
    first segment of the whole batch and ``interchange`` is the 1-based
    index of the interchange the error belongs to; it stays ``None`` for
    single-message audits.
    """

    def __init__(
        self,
        code: str,
        message: str,
        segment: int = 1,
        interchange: int | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.segment = segment
        self.interchange = interchange


@dataclass(frozen=True)
class AuditResult:
    interchange_control_number: str
    group_count: int
    transaction_count: int
    sha256: str


@dataclass(frozen=True)
class BatchAuditResult:
    interchanges: tuple[AuditResult, ...]
    sha256: str

    @property
    def interchange_count(self) -> int:
        return len(self.interchanges)

    @property
    def group_count(self) -> int:
        return sum(item.group_count for item in self.interchanges)

    @property
    def transaction_count(self) -> int:
        return sum(item.transaction_count for item in self.interchanges)


@dataclass
class _Transaction:
    st_index: int
    control_number: bytes


@dataclass
class _Group:
    gs_index: int
    control_number: bytes
    transactions: list[_Transaction]


def _is_printable_punctuation(value: int) -> bool:
    if not 0x21 <= value <= 0x7E:
        return False
    ch = chr(value)
    return not (ch.isalnum() or ch == " ")


def _error(
    code: str,
    message: str,
    segment: int,
    interchange: int | None = None,
) -> EnvelopeError:
    return EnvelopeError(code, message, segment, interchange)


def _check_framing(raw: bytes) -> None:
    """Validate body-wide transport assumptions (empty/size/ASCII)."""
    if len(raw) == 0:
        raise _error("EMPTY_MESSAGE", "request body is empty", 1)
    if len(raw) > MAX_MESSAGE_BYTES:
        raise _error(
            "MESSAGE_TOO_LARGE",
            f"message exceeds {MAX_MESSAGE_BYTES} bytes",
            1,
        )
    try:
        raw.decode("ascii")
    except UnicodeDecodeError:
        raise _error("NON_ASCII", "message is not pure ASCII", 1) from None


def _read_isa(
    raw: bytes,
    start: int,
    segment: int,
    interchange: int | None,
) -> tuple[int, int, int, str]:
    """Validate one fixed-length ISA header at ``raw[start]``.

    Returns ``(element_separator, component_separator, segment_terminator,
    interchange_control_number)``.
    """
    if len(raw) - start < 106:
        raise _error(
            "ISA_TOO_SHORT",
            "ISA segment must be at least 106 bytes including terminator",
            segment,
            interchange,
        )
    if raw[start : start + 3] != b"ISA":
        raise _error(
            "MISSING_ISA",
            "an interchange must begin with an ISA segment",
            segment,
            interchange,
        )

    element_sep = raw[start + 3]
    component_sep = raw[start + 104]
    segment_terminator = raw[start + 105]

    if not _is_printable_punctuation(element_sep):
        raise _error(
            "BAD_DELIMITER", "invalid ISA element separator", segment, interchange
        )
    if not _is_printable_punctuation(component_sep):
        raise _error(
            "BAD_DELIMITER", "invalid ISA component separator", segment, interchange
        )
    # The terminator may additionally be CR or LF in line-oriented feeds.
    if not (
        _is_printable_punctuation(segment_terminator)
        or segment_terminator in (0x0D, 0x0A)
    ):
        raise _error(
            "BAD_DELIMITER", "invalid ISA segment terminator", segment, interchange
        )
    if len({element_sep, component_sep, segment_terminator}) != 3:
        raise _error(
            "BAD_DELIMITER",
            "element separator, component separator and segment terminator "
            "must be distinct",
            segment,
            interchange,
        )

    isa_core = raw[start : start + 105]
    isa_parts = isa_core.split(bytes([element_sep]))
    if len(isa_parts) != len(ISA_FIELD_WIDTHS) or any(
        len(part) != width
        for part, width in zip(isa_parts, ISA_FIELD_WIDTHS)
    ):
        raise _error(
            "ISA_MALFORMED",
            "ISA segment does not match its fixed-length element layout",
            segment,
            interchange,
        )
    # The terminator byte must not appear inside the ISA header; otherwise
    # the fixed-width payload would end a segment prematurely.
    if bytes([segment_terminator]) in isa_core:
        raise _error(
            "ISA_MALFORMED", "malformed ISA segment", segment, interchange
        )

    interchange_control = isa_parts[13].decode("ascii").strip()
    return element_sep, component_sep, segment_terminator, interchange_control


def _unclosed_error(
    state: "_EnvelopeState", segment: int
) -> EnvelopeError:
    """Build the truncation error for an interchange that ran out of input."""
    if state.current_txn is not None:
        return _error(
            "MISSING_SE",
            "transaction set was never closed with an SE segment",
            state.current_txn.st_index,
            state.interchange,
        )
    if state.current_group is not None:
        return _error(
            "MISSING_GE",
            "functional group was never closed with a GE segment",
            state.current_group.gs_index,
            state.interchange,
        )
    return _error(
        "MISSING_IEA",
        "interchange was never closed with an IEA segment",
        segment,
        state.interchange,
    )


class _EnvelopeState:
    """State machine for the GS/GE and ST/SE levels of one interchange."""

    def __init__(
        self,
        element_separator: int,
        interchange_control: str,
        interchange: int | None,
    ):
        self._element_sep = bytes([element_separator])
        self.interchange_control = interchange_control
        self.interchange = interchange
        self.groups: list[_Group] = []
        self.current_group: _Group | None = None
        self.current_txn: _Transaction | None = None
        self.closed = False

    def _err(self, code: str, message: str, segment: int) -> EnvelopeError:
        return _error(code, message, segment, self.interchange)

    @property
    def transaction_count(self) -> int:
        return sum(len(group.transactions) for group in self.groups)

    def feed(self, segment: int, token: bytes) -> None:
        """Process one stripped segment (ISA and IEA framing handled by the
        caller)."""
        parts = token.split(self._element_sep)
        tag = parts[0].strip()

        if tag == b"GS":
            if self.current_txn is not None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "GS encountered before the open ST/SE transaction was "
                    "closed",
                    segment,
                )
            if self.current_group is not None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "GS encountered before the previous GS/GE group was "
                    "closed",
                    segment,
                )
            if len(self.groups) >= MAX_GROUPS:
                raise self._err(
                    "GROUP_LIMIT_EXCEEDED",
                    f"an interchange may contain at most {MAX_GROUPS} groups",
                    segment,
                )
            if len(parts) < 9:
                raise self._err(
                    "GS_MALFORMED",
                    "GS segment must contain eight elements",
                    segment,
                )
            self.current_group = _Group(
                gs_index=segment,
                control_number=parts[6],
                transactions=[],
            )
            self.groups.append(self.current_group)

        elif tag == b"ST":
            if self.current_group is None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "ST encountered outside of a GS/GE group",
                    segment,
                )
            if self.current_txn is not None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "ST encountered before the previous ST/SE transaction "
                    "was closed",
                    segment,
                )
            if len(self.current_group.transactions) >= MAX_TRANSACTIONS_PER_GROUP:
                raise self._err(
                    "TRANSACTION_LIMIT_EXCEEDED",
                    "a group may contain at most "
                    f"{MAX_TRANSACTIONS_PER_GROUP} transactions",
                    segment,
                )
            if len(parts) < 3:
                raise self._err(
                    "ST_MALFORMED",
                    "ST segment must contain a control number (ST02)",
                    segment,
                )
            self.current_txn = _Transaction(
                st_index=segment,
                control_number=parts[2],
            )

        elif tag == b"SE":
            if self.current_group is None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "SE encountered without a matching GS group",
                    segment,
                )
            if self.current_txn is None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "SE encountered without a matching ST",
                    segment,
                )
            if len(parts) < 3:
                raise self._err(
                    "SE_MALFORMED",
                    "SE segment must contain SE01 (segment count) and SE02 "
                    "(control number)",
                    segment,
                )
            declared_count_raw = parts[1].decode("ascii")
            if not declared_count_raw.isdigit() or int(declared_count_raw) < 2:
                raise self._err(
                    "SE_MALFORMED",
                    "SE01 segment count must be an integer of at least 2",
                    segment,
                )
            declared_count = int(declared_count_raw)
            actual_count = segment - self.current_txn.st_index + 1
            if declared_count != actual_count:
                raise self._err(
                    "SEGMENT_COUNT_MISMATCH",
                    f"SE01 declares {declared_count} segments but the "
                    f"ST..SE envelope spans {actual_count}",
                    segment,
                )
            if parts[2] != self.current_txn.control_number:
                raise self._err(
                    "CONTROL_NUMBER_MISMATCH",
                    "SE02 control number does not match ST02",
                    segment,
                )
            self.current_group.transactions.append(self.current_txn)
            self.current_txn = None

        elif tag == b"GE":
            if self.current_group is None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "GE encountered without a matching GS",
                    segment,
                )
            if self.current_txn is not None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "GE encountered before the open ST/SE transaction was "
                    "closed with SE",
                    segment,
                )
            if len(parts) < 3:
                raise self._err(
                    "GE_MALFORMED",
                    "GE segment must contain GE01 (transaction count) and "
                    "GE02 (control number)",
                    segment,
                )
            txn_count = len(self.current_group.transactions)
            if txn_count == 0:
                raise self._err(
                    "ZERO_TRANSACTIONS",
                    "group contains no ST/SE transaction sets",
                    segment,
                )
            declared_raw = parts[1].decode("ascii")
            if not declared_raw.isdigit():
                raise self._err(
                    "GE_MALFORMED",
                    "GE01 transaction count must be an integer",
                    segment,
                )
            if int(declared_raw) != txn_count:
                raise self._err(
                    "GE_COUNT_MISMATCH",
                    f"GE01 declares {declared_raw} transactions but the "
                    f"group contains {txn_count}",
                    segment,
                )
            if parts[2] != self.current_group.control_number:
                raise self._err(
                    "CONTROL_NUMBER_MISMATCH",
                    "GE02 control number does not match GS06",
                    segment,
                )
            self.current_group = None

        elif tag == b"IEA":
            if self.current_txn is not None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "IEA encountered before the open ST/SE transaction was "
                    "closed with SE",
                    segment,
                )
            if self.current_group is not None:
                raise self._err(
                    "NESTING_VIOLATION",
                    "IEA encountered before the open GS/GE group was closed "
                    "with GE",
                    segment,
                )
            if len(parts) < 3:
                raise self._err(
                    "IEA_MALFORMED",
                    "IEA segment must contain IEA01 (group count) and IEA02 "
                    "(control number)",
                    segment,
                )
            if not self.groups:
                raise self._err(
                    "ZERO_GROUPS",
                    "interchange contains no GS/GE functional groups",
                    segment,
                )
            declared_raw = parts[1].decode("ascii")
            if not declared_raw.isdigit():
                raise self._err(
                    "IEA_MALFORMED",
                    "IEA01 group count must be an integer",
                    segment,
                )
            if int(declared_raw) != len(self.groups):
                raise self._err(
                    "IEA_COUNT_MISMATCH",
                    f"IEA01 declares {declared_raw} groups but the "
                    f"interchange contains {len(self.groups)}",
                    segment,
                )
            # ISA13 is a fixed 9-character, space-padded field; IEA02 is
            # variable width, so compare the trimmed values.
            if parts[2].decode("ascii").strip() != self.interchange_control:
                raise self._err(
                    "CONTROL_NUMBER_MISMATCH",
                    "IEA02 control number does not match ISA13",
                    segment,
                )
            self.closed = True

        else:
            # Any other segment is payload, which is only legal inside an
            # open transaction set.
            if self.current_txn is None:
                raise self._err(
                    "UNEXPECTED_SEGMENT",
                    f"segment {tag.decode('ascii', 'replace')!r} is not "
                    "allowed outside an ST/SE transaction",
                    segment,
                )


def audit(raw: bytes) -> AuditResult:
    """Audit a raw X12 message containing exactly one interchange."""

    _check_framing(raw)
    element_sep, _, segment_terminator, interchange_control = _read_isa(
        raw, 0, 1, None
    )

    element_sep_byte = bytes([element_sep])
    terminator_byte = bytes([segment_terminator])
    isa_core = raw[0:105]

    raw_tokens = raw.split(terminator_byte)
    if raw_tokens[0] != isa_core:
        # Only possible if the terminator byte occurs inside the ISA header,
        # which the fixed-width validation above normally catches first.
        raise _error("ISA_MALFORMED", "malformed ISA segment", 1)

    # A trailing terminator is mandatory; its absence usually means the
    # message was truncated.  CRLF/LF line endings after the final
    # terminator are tolerated.
    if raw_tokens[-1].strip(b" \t\r\n") != b"":
        raise _error(
            "MISSING_TERMINATOR",
            "final segment is missing its segment terminator; the message "
            "may be truncated",
            len(raw_tokens),
        )

    state = _EnvelopeState(element_sep, interchange_control, None)
    last_segment_index = max(len(raw_tokens) - 1, 1)

    for position, raw_token in enumerate(raw_tokens[1:], start=2):
        token = raw_token.strip(b" \t\r\n")

        # A final empty token is produced by the trailing segment terminator
        # (optionally followed by line breaks).  Any other blank token is an
        # empty segment.
        if not token:
            if position == len(raw_tokens):
                continue
            raise _error("EMPTY_SEGMENT", "empty segment encountered", position)

        tag = token.split(element_sep_byte, 1)[0].strip()

        if tag == b"ISA":
            raise _error(
                "MULTIPLE_INTERCHANGES",
                "a second ISA segment was found; exactly one interchange is "
                "allowed per message",
                position,
            )

        if state.closed:
            raise _error(
                "TRAILING_DATA",
                "data found after the IEA segment",
                position,
            )

        state.feed(position, token)

    if not state.closed:
        raise _unclosed_error(state, last_segment_index)

    return AuditResult(
        interchange_control_number=interchange_control,
        group_count=len(state.groups),
        transaction_count=state.transaction_count,
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def audit_batch(raw: bytes) -> BatchAuditResult:
    """Audit a batch of 1..16 complete, independently delimited interchanges.

    Between interchanges only CR/LF bytes are allowed.  Segment indices on
    raised errors are global (the first ISA of the batch is segment 1) and
    the interchange index is 1-based.
    """

    _check_framing(raw)

    results: list[AuditResult] = []
    seen_control_numbers: set[str] = set()

    pos = 0               # byte offset where the next ISA must begin
    base_segment = 0      # segments already consumed by earlier interchanges
    interchange_index = 0

    while pos < len(raw):
        interchange_index += 1
        if interchange_index > MAX_INTERCHANGES_PER_BATCH:
            raise _error(
                "INTERCHANGE_LIMIT_EXCEEDED",
                f"a batch may contain at most {MAX_INTERCHANGES_PER_BATCH} "
                "interchanges",
                base_segment + 1,
                interchange_index,
            )

        isa_segment = base_segment + 1
        element_sep, _, segment_terminator, control = _read_isa(
            raw, pos, isa_segment, interchange_index
        )
        if control in seen_control_numbers:
            raise _error(
                "DUPLICATE_CONTROL_NUMBER",
                f"interchange control number {control!r} is used by more "
                "than one interchange in this batch",
                isa_segment,
                interchange_index,
            )
        seen_control_numbers.add(control)

        state = _EnvelopeState(element_sep, control, interchange_index)
        terminator_byte = bytes([segment_terminator])

        cursor = pos + 106
        segment = isa_segment + 1
        last_real_segment = isa_segment
        end = len(raw)

        # Stream this interchange's segments with its own terminator and
        # stop the instant its IEA closes, so bytes belonging to the next
        # interchange (which may use a different terminator) are never
        # consumed here.
        while True:
            terminator_at = raw.find(terminator_byte, cursor)
            if terminator_at == -1:
                tail = raw[cursor:]
                if tail.strip(b" \t\r\n") != b"":
                    raise _error(
                        "MISSING_TERMINATOR",
                        "final segment is missing its segment terminator; "
                        "the interchange may be truncated",
                        segment,
                        interchange_index,
                    )
                # Raw input ends right after a terminator (optionally
                # followed by line breaks); the interchange itself was not
                # closed.
                break

            token = raw[cursor:terminator_at].strip(b" \t\r\n")
            if not token:
                raise _error(
                    "EMPTY_SEGMENT",
                    "empty segment encountered",
                    segment,
                    interchange_index,
                )
            last_real_segment = segment
            tag = token.split(bytes([element_sep]), 1)[0].strip()

            if tag == b"ISA":
                # The current interchange was never closed before the next
                # ISA began; attribute the truncation to it instead of
                # letting the valid boundary mask it.
                raise _unclosed_error(state, segment)

            state.feed(segment, token)
            if state.closed:
                end = terminator_at + 1
                break

            cursor = terminator_at + 1
            segment += 1

        if not state.closed:
            raise _unclosed_error(state, last_real_segment)

        results.append(
            AuditResult(
                interchange_control_number=control,
                group_count=len(state.groups),
                transaction_count=state.transaction_count,
                sha256=hashlib.sha256(raw[pos:end]).hexdigest(),
            )
        )

        base_segment = last_real_segment
        pos = end

        # Between interchanges only CR/LF are permitted.
        gap = pos
        while gap < len(raw) and raw[gap] in (0x0D, 0x0A):
            gap += 1
        if gap == len(raw):
            break
        pos = gap
        if raw[pos : pos + 3] != b"ISA":
            # If another ISA follows the junk this is a poisoned boundary
            # before that interchange; otherwise the bytes trail the last
            # (complete) interchange and are attributed to it.
            at = interchange_index if raw.find(b"ISA", pos) == -1 else interchange_index + 1
            raise _error(
                "INTERCHANGE_JUNK",
                "only CR/LF bytes are allowed between interchanges",
                base_segment + 1,
                at,
            )

    return BatchAuditResult(
        interchanges=tuple(results),
        sha256=hashlib.sha256(raw).hexdigest(),
    )
