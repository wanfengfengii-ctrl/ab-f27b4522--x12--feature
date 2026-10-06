"""HTTP smoke tests for POST /api/x12/audit.

Exercises the running API with both a valid envelope and a series of
damaged envelopes, asserting on HTTP status, stable error codes and the
first locatable segment index.  With ``?batch=interchanges`` it also
exercises multi-interchange batches: different per-ISA delimiters,
duplicate ISA13 control numbers and damage inside a later interchange.
Exits non-zero if any assertion fails.

Usage: python3 smoke_http.py [BASE_URL]
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.environ.get("BASE_URL", "http://localhost:8080")
).rstrip("/")

ENDPOINT = f"{BASE_URL}/api/x12/audit"
BATCH_ENDPOINT = f"{BASE_URL}/api/x12/audit?batch=interchanges"
MAX_BYTES = 2 * 1024 * 1024  # 2 MiB

failures: list[str] = []


def isa(control: str = "000000001") -> str:
    fields = [
        "00",
        " " * 10,
        "00",
        " " * 10,
        "ZZ",
        "SENDER".ljust(15),
        "ZZ",
        "PARTNER".ljust(15),
        " " * 6,
        " " * 4,
        "U",
        "00501",
        control.rjust(9),
        "0",
        "P",
        ":",
    ]
    return "ISA*" + "*".join(fields) + "~"


def isa_alt(control: str = "000000002") -> str:
    """ISA declaring |, ^ and LF as its delimiter set."""
    fields = [
        "00",
        " " * 10,
        "00",
        " " * 10,
        "ZZ",
        "SENDER".ljust(15),
        "ZZ",
        "PARTNER".ljust(15),
        " " * 6,
        " " * 4,
        "U",
        "00501",
        control.rjust(9),
        "0",
        "P",
        "^",
    ]
    return "ISA|" + "|".join(fields) + "\n"


GS = "GS*PO*SENDER*PARTNER*20240101*1200*1*X*005010~"
IEA = "IEA*1*000000001~"


def post(raw: bytes, content_type: str = "application/octet-stream", url: str = ENDPOINT):
    req = urllib.request.Request(
        url,
        data=raw,
        headers={"Content-Type": content_type},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name} {detail}")
        failures.append(name)


def scenario_valid():
    print("scenario: valid multi-group interchange")
    body = (
        isa()
        + "GS*PO*S*R*D*T*1*X*V~"
        + "ST*850*100~BEG*00~REF*A:B~SE*4*100~"
        + "GE*1*1~"
        + "GS*PO*S*R*D*T*2*X*V~"
        + "ST*850*200~SE*2*200~"
        + "ST*850*201~SE*2*201~"
        + "GE*2*2~"
        + "IEA*2*000000001~"
    ).encode("ascii")
    status, payload = post(body)
    check("http 200", status == 200, f"got {status} {payload}")
    check(
        "control number",
        payload.get("interchange_control_number") == "000000001",
        str(payload),
    )
    check("group count", payload.get("group_count") == 2, str(payload))
    check("transaction count", payload.get("transaction_count") == 3, str(payload))
    check(
        "sha256 of raw body",
        payload.get("sha256") == hashlib.sha256(body).hexdigest(),
        str(payload),
    )


def expect_envelope_error(name, body: bytes, status_code: int, code: str, segment: int):
    print(f"scenario: {name}")
    status, payload = post(body)
    error = payload.get("error", {})
    check("http status", status == status_code, f"got {status} {payload}")
    check("error code", error.get("code") == code, str(payload))
    check("segment index", error.get("segment") == segment, str(payload))
    check("message present", bool(error.get("message")), str(payload))


def scenario_damaged():
    expect_envelope_error(
        "truncated final segment (no terminator)",
        (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~IEA*1*000000001").encode(),
        422,
        "MISSING_TERMINATOR",
        6,
    )

    # Inner SE error plus deliberately wrong GE and IEA summaries: the
    # innermost, earliest error must not be masked.
    expect_envelope_error(
        "SE count wrong while GE/IEA summaries also wrong",
        (
            isa()
            + GS
            + "ST*850*100~BEG*00~SE*2*100~"   # actual span is 3
            + "GE*9*1~"
            + "IEA*9*000000001~"
        ).encode("ascii"),
        422,
        "SEGMENT_COUNT_MISMATCH",
        5,
    )

    expect_envelope_error(
        "SE control number mismatch",
        (isa() + GS + "ST*850*100~SE*2*999~GE*1*1~" + IEA).encode("ascii"),
        422,
        "CONTROL_NUMBER_MISMATCH",
        4,
    )

    expect_envelope_error(
        "GE transaction count mismatch",
        (
            isa()
            + GS
            + "ST*850*100~SE*2*100~"
            + "ST*850*200~SE*2*200~"
            + "GE*1*1~" + IEA
        ).encode("ascii"),
        422,
        "GE_COUNT_MISMATCH",
        7,
    )

    expect_envelope_error(
        "IEA group count mismatch",
        (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~IEA*2*000000001~").encode(),
        422,
        "IEA_COUNT_MISMATCH",
        6,
    )

    expect_envelope_error(
        "IEA control number mismatch",
        (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~IEA*1*000000999~").encode(),
        422,
        "CONTROL_NUMBER_MISMATCH",
        6,
    )

    expect_envelope_error(
        "interleaved levels (GE before SE)",
        (isa() + GS + "ST*850*100~GE*1*1~" + IEA).encode("ascii"),
        422,
        "NESTING_VIOLATION",
        4,
    )

    expect_envelope_error(
        "trailing data after IEA",
        (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~" + IEA + "ZZZ*1~").encode(),
        422,
        "TRAILING_DATA",
        7,
    )

    expect_envelope_error(
        "second ISA in one message",
        (isa() + isa()).encode("ascii"),
        422,
        "MULTIPLE_INTERCHANGES",
        2,
    )


def _single_interchange(control: str, *, alt: bool = False) -> bytes:
    """Build one minimal interchange (six segments)."""
    if alt:
        return (
            isa_alt(control)
            + "GS|PO|SENDER|RECEIVER|20240101|1200|2|X|005010\n"
            + "ST|850|2001\n"
            + "BEG|00\n"
            + "SE|3|2001\n"
            + "GE|1|2\n"
            + f"IEA|1|{control.rjust(9)}\n"
        ).encode("ascii")
    return (
        isa(control)
        + GS
        + "ST*850*1001~SE*2*1001~"
        + "GE*1*1~"
        + f"IEA*1*{control.rjust(9)}~"
    ).encode("ascii")


def scenario_batch():
    print("scenario: batch of two interchanges with different delimiters")
    first = _single_interchange("000000001")
    second = _single_interchange("000000002", alt=True)
    body = first + b"\r\n" + second
    status, payload = post(body, url=BATCH_ENDPOINT)
    check("http 200", status == 200, f"got {status} {payload}")
    interchanges = payload.get("interchanges", [])
    check("two summaries returned in order",
          [i.get("interchange_control_number") for i in interchanges]
          == ["000000001", "000000002"], str(payload))
    check("interchange_count", payload.get("interchange_count") == 2, str(payload))
    check("group total", payload.get("group_count") == 2, str(payload))
    check("transaction total", payload.get("transaction_count") == 2, str(payload))
    check(
        "batch sha256",
        payload.get("sha256") == hashlib.sha256(body).hexdigest(),
        str(payload),
    )
    check(
        "per-interchange sha256",
        interchanges[0].get("sha256") == hashlib.sha256(first).hexdigest()
        and interchanges[1].get("sha256") == hashlib.sha256(second).hexdigest(),
        str(payload),
    )

    print("scenario: single interchange stays compatible without batch param")
    status, payload = post(first)
    check("http 200", status == 200, f"got {status} {payload}")
    check("legacy response shape", "interchange_control_number" in payload
          and "interchanges" not in payload, str(payload))

    print("scenario: single interchange also accepted in batch mode")
    status, payload = post(first, url=BATCH_ENDPOINT)
    check("http 200", status == 200, f"got {status} {payload}")
    check("one summary", payload.get("interchange_count") == 1, str(payload))

    print("scenario: duplicate ISA13 control number rejected")
    body = first + b"\r\n" + _single_interchange("000000001")
    status, payload = post(body, url=BATCH_ENDPOINT)
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check("error code",
          error.get("code") == "DUPLICATE_INTERCHANGE_CONTROL_NUMBER", str(payload))
    check("segment at second ISA", error.get("segment") == 7, str(payload))
    check("interchange index", error.get("interchange") == 2, str(payload))

    print("scenario: damage in second interchange not masked by first IEA")
    damaged = _single_interchange("000000002").replace(
        b"SE*2*1001~", b"SE*9*1001~", 1
    )
    body = first + b"\r\n" + damaged
    status, payload = post(body, url=BATCH_ENDPOINT)
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check("error code", error.get("code") == "SEGMENT_COUNT_MISMATCH", str(payload))
    # 6 segments in interchange 1; SE is local segment 4 in interchange 2.
    check("batch-wide segment", error.get("segment") == 10, str(payload))
    check("interchange index", error.get("interchange") == 2, str(payload))

    print("scenario: stray characters between interchanges rejected")
    body = first + b"X" + _single_interchange("000000002")
    status, payload = post(body, url=BATCH_ENDPOINT)
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check("error code",
          error.get("code") == "INVALID_INTERCHANGE_SEPARATOR", str(payload))
    check("interchange index", error.get("interchange") == 2, str(payload))

    print("scenario: more than sixteen interchanges rejected")
    bodies = b"\n".join(
        _single_interchange(f"{index:09d}") for index in range(1, 18)
    )
    status, payload = post(bodies, url=BATCH_ENDPOINT)
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check("error code", error.get("code") == "BATCH_LIMIT_EXCEEDED", str(payload))
    check("interchange index", error.get("interchange") == 17, str(payload))

    print("scenario: unsupported batch parameter value rejected")
    status, payload = post(first, url=f"{BASE_URL}/api/x12/audit?batch=stream")
    check("http 400", status == 400, f"got {status} {payload}")
    check("error code",
          payload.get("error", {}).get("code") == "INVALID_BATCH_PARAMETER",
          str(payload))


def scenario_transport():
    print("scenario: wrong content type")
    status, payload = post(b"whatever", "text/plain")
    check("http 415", status == 415, f"got {status} {payload}")
    check(
        "error code",
        payload.get("error", {}).get("code") == "UNSUPPORTED_MEDIA_TYPE",
        str(payload),
    )

    print("scenario: empty body")
    status, payload = post(b"")
    check("http 400", status == 400, f"got {status} {payload}")
    check(
        "error code",
        payload.get("error", {}).get("code") == "EMPTY_MESSAGE",
        str(payload),
    )

    print("scenario: body over 2 MiB")
    status, payload = post(b"x" * (MAX_BYTES + 1))
    check("http 413", status == 413, f"got {status} {payload}")
    check(
        "error code",
        payload.get("error", {}).get("code") == "MESSAGE_TOO_LARGE",
        str(payload),
    )

    print("scenario: health endpoint")
    with urllib.request.urlopen(f"{BASE_URL}/health", timeout=5) as response:
        check("health 200", response.status == 200)


def main() -> int:
    print(f"Smoke testing X12 audit API at {ENDPOINT}")
    scenario_valid()
    scenario_damaged()
    scenario_batch()
    scenario_transport()
    print()
    if failures:
        print(f"{len(failures)} smoke check(s) FAILED: {', '.join(failures)}")
        return 1
    print("All HTTP smoke checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
