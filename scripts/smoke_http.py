"""HTTP smoke tests for POST /api/x12/audit.

Exercises the running API with both a valid envelope and a series of
damaged envelopes, asserting on HTTP status, stable error codes and the
first locatable segment index.  Exits non-zero if any assertion fails.

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
MAX_BYTES = 2 * 1024 * 1024  # 2 MiB

failures: list[str] = []


def isa(
    control: str = "000000001",
    element: str = "*",
    component: str = ":",
    terminator: str = "~",
) -> str:
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
        component,
    ]
    return "ISA" + element + element.join(fields) + terminator


GS = "GS*PO*SENDER*PARTNER*20240101*1200*1*X*005010~"
IEA = "IEA*1*000000001~"


def build_interchange(
    control: str = "000000001",
    *,
    element: str = "*",
    component: str = ":",
    terminator: str = "~",
    groups: list[list[int]] | None = None,
) -> str:
    """Build a complete interchange; groups list per-transaction payload counts."""
    if groups is None:
        groups = [[0]]
    segs = [isa(control, element, component, terminator)]
    for g_index, txns in enumerate(groups):
        segs.append(
            f"GS{element}PO{element}S{element}R{element}20240101{element}1200"
            f"{element}{g_index + 1}{element}X{element}005010" + terminator
        )
        for t_index, extra in enumerate(txns):
            t_ctrl = f"{g_index + 1}{t_index + 1:03d}"
            segs.append(f"ST{element}850{element}{t_ctrl}" + terminator)
            for i in range(extra):
                segs.append(f"BEG{i:02d}{element}00" + terminator)
            segs.append(
                f"SE{element}{2 + extra}{element}{t_ctrl}" + terminator
            )
        segs.append(
            f"GE{element}{len(txns)}{element}{g_index + 1}" + terminator
        )
    segs.append(
        f"IEA{element}{len(groups)}{element}{control.rjust(9)}" + terminator
    )
    return "".join(segs)


def post(raw: bytes, content_type: str = "application/octet-stream", query: str = ""):
    url = ENDPOINT + (f"?{query}" if query else "")
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


def scenario_batch():
    print("scenario: batch - single interchange compatibility")
    body = build_interchange().encode("ascii")
    status, payload = post(body, query="batch=interchanges")
    check("http 200", status == 200, f"got {status} {payload}")
    check("one interchange", payload.get("interchange_count") == 1, str(payload))
    check("batch group count", payload.get("group_count") == 1, str(payload))
    check(
        "batch transaction count",
        payload.get("transaction_count") == 1,
        str(payload),
    )
    check(
        "batch sha256 of whole body",
        payload.get("sha256") == hashlib.sha256(body).hexdigest(),
        str(payload),
    )
    summary = payload.get("interchanges", [{}])[0]
    check(
        "summary control number",
        summary.get("interchange_control_number") == "000000001",
        str(payload),
    )
    check(
        "per-interchange sha256",
        summary.get("sha256") == hashlib.sha256(body).hexdigest(),
        str(payload),
    )

    print("scenario: batch - distinct delimiters, order and totals")
    first = build_interchange(
        "000000001", groups=[[0], [1]]
    )  # 2 groups, 2 txns
    second = build_interchange(
        "000000002", element="|", component="^", terminator="\n", groups=[[0, 0]]
    )  # 1 group, 2 txns
    body = (first + "\r\n" + second).encode("ascii")
    status, payload = post(body, query="batch=interchanges")
    check("http 200", status == 200, f"got {status} {payload}")
    check(
        "control numbers in input order",
        [i.get("interchange_control_number") for i in payload.get("interchanges", [])]
        == ["000000001", "000000002"],
        str(payload),
    )
    check("interchange total", payload.get("interchange_count") == 2, str(payload))
    check("group total", payload.get("group_count") == 3, str(payload))
    check("transaction total", payload.get("transaction_count") == 4, str(payload))
    check(
        "batch sha256",
        payload.get("sha256") == hashlib.sha256(body).hexdigest(),
        str(payload),
    )

    print("scenario: batch - duplicate interchange control number")
    body = (
        build_interchange("000000007") + build_interchange("000000007")
    ).encode("ascii")
    status, payload = post(body, query="batch=interchanges")
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check("error code", error.get("code") == "DUPLICATE_CONTROL_NUMBER", str(payload))
    check("global segment", error.get("segment") == 7, str(payload))
    check("interchange index", error.get("interchange") == 2, str(payload))

    print("scenario: batch - junk between interchanges")
    body = (
        build_interchange("000000001") + " " + build_interchange("000000002")
    ).encode("ascii")
    status, payload = post(body, query="batch=interchanges")
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check("error code", error.get("code") == "INTERCHANGE_JUNK", str(payload))
    check("interchange index", error.get("interchange") == 2, str(payload))

    print("scenario: batch - 17 interchanges rejected")
    body = "".join(
        build_interchange(f"{i + 1:09d}") for i in range(17)
    ).encode("ascii")
    status, payload = post(body, query="batch=interchanges")
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check(
        "error code", error.get("code") == "INTERCHANGE_LIMIT_EXCEEDED", str(payload)
    )
    check("interchange index", error.get("interchange") == 17, str(payload))

    print("scenario: batch - damaged second interchange not masked")
    # First interchange is valid and closes cleanly; the second one has an
    # SE segment-count mismatch (declares 2, spans 3).
    first = build_interchange("000000001")
    second = (
        isa("000000002")
        + "GS*PO*S*R*20240101*1200*1*X*005010~"
        + "ST*850*100~BEG*00~SE*2*100~"
        + "GE*1*1~IEA*1*000000002~"
    )
    body = (first + second).encode("ascii")
    status, payload = post(body, query="batch=interchanges")
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check(
        "error code", error.get("code") == "SEGMENT_COUNT_MISMATCH", str(payload)
    )
    check("global segment", error.get("segment") == 11, str(payload))
    check("interchange index", error.get("interchange") == 2, str(payload))
    check("message present", bool(error.get("message")), str(payload))

    print("scenario: batch - second interchange truncated")
    second_truncated = (
        isa("000000002")
        + "GS*PO*S*R*20240101*1200*1*X*005010~"
        + "ST*850*100~SE*2*100~GE*1*1~"
    )
    body = (first + second_truncated).encode("ascii")
    status, payload = post(body, query="batch=interchanges")
    error = payload.get("error", {})
    check("http 422", status == 422, f"got {status} {payload}")
    check("error code", error.get("code") == "MISSING_IEA", str(payload))
    check("interchange index", error.get("interchange") == 2, str(payload))

    print("scenario: batch - invalid query value")
    status, payload = post(first.encode("ascii"), query="batch=yes")
    check("http 400", status == 400, f"got {status} {payload}")
    check(
        "error code",
        payload.get("error", {}).get("code") == "INVALID_BATCH_PARAMETER",
        str(payload),
    )

    print("scenario: batch - single interchange still audited without flag")
    # The batch parameter is opt-in: omitting it keeps the original contract.
    body = build_interchange("000000001").encode("ascii")
    status, payload = post(body)
    check("http 200", status == 200, f"got {status} {payload}")
    check(
        "legacy flat response",
        payload.get("interchange_control_number") == "000000001"
        and "interchanges" not in payload,
        str(payload),
    )


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
