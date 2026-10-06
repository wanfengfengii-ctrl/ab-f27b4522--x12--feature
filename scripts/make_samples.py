"""Generate sample X12 interchanges under samples/.

* ``sample.edi``       - a single valid interchange,
* ``batch.edi``        - two complete interchanges separated by CRLF, each
                         declaring its own delimiter set.
"""

from __future__ import annotations

import os


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
        "260106",          # ISA09 date YYMMDD
        "1200",            # ISA10 time HHMM
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
        "260106",
        "1200",
        "U",
        "00501",
        control.rjust(9),
        "0",
        "P",
        "^",
    ]
    return "ISA|" + "|".join(fields) + "\n"


def main() -> None:
    message = (
        isa()
        + "GS*PO*SENDER*PARTNER*20260106*1200*1*X*005010~"
        + "ST*850*0001~"
        + "BEG*00*NE*PO-0001**20260106~"
        + "REF*IA:ACME:42~"
        + "SE*4*0001~"
        + "GE*1*1~"
        + "IEA*1*000000001~"
    )
    second = (
        isa_alt()
        + "GS|PO|SENDER|PARTNER|20260106|1200|2|X|005010\n"
        + "ST|850|0002\n"
        + "BEG|00|NE|PO-0002||20260106\n"
        + "SE|3|0002\n"
        + "GE|1|2\n"
        + "IEA|1|000000002\n"
    )
    out_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"
    )
    os.makedirs(out_dir, exist_ok=True)
    for name, content in (
        ("sample.edi", message),
        ("batch.edi", message + "\r\n" + second),
    ):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="ascii", newline="") as handle:
            handle.write(content)
        print(f"wrote {path} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
