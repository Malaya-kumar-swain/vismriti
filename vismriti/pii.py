"""Indian personal-data detection and masking.

Vismriti does not try to be the best PII detector; good ones exist. This module
ships a dependency-free, checksum-validated baseline for Indian identifiers and
a small ``Detector`` interface so you can plug in Presidio, bharat-pii or a model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Protocol

# Verhoeff tables (used by UIDAI for the Aadhaar check digit).
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    """True if ``number`` (digits only) passes the Verhoeff checksum."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(number: str) -> str:
    """Check digit to append to ``number`` (used to generate synthetic test data)."""
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


# Devanagari, Bengali, Odia, Tamil, Telugu, Kannada, Gujarati, Gurmukhi digit blocks.
_INDIC_ZEROS = [0x0966, 0x09E6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0AE6, 0x0A66]
_DIGIT_MAP = {z + i: str(i) for z in _INDIC_ZEROS for i in range(10)}


def normalise_digits(text: str) -> str:
    """Map Indic-script digits to ASCII so identifiers written in Hindi or Odia still match.

    The mapping is one character to one character, so match offsets stay valid.
    """
    return text.translate(_DIGIT_MAP)


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int
    value: str


class Detector(Protocol):
    def detect(self, text: str) -> list[Finding]: ...


_UPI_HANDLES = (
    "upi|ybl|okhdfcbank|okicici|oksbi|okaxis|paytm|ibl|axl|apl|airtel|"
    "jio|freecharge|icici|sbi|hdfcbank|kotak|yesbank|indus|federal|barodampay|pnb"
)

_PATTERNS: dict[str, re.Pattern[str]] = {
    "AADHAAR": re.compile(r"(?<!\d)([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?!\d)"),
    "PAN": re.compile(r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z](?![A-Z0-9])"),
    "GSTIN": re.compile(r"(?<![A-Z0-9])\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z](?![A-Z0-9])"),
    "IFSC": re.compile(r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])"),
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "UPI": re.compile(rf"(?<![\w.])[\w.-]{{2,256}}@(?:{_UPI_HANDLES})(?!\w|\.\w)", re.I),
    "PHONE_IN": re.compile(r"(?<![\d+])(?:\+91[ -]?|0)?([6-9]\d{4})[ -]?(\d{5})(?!\d)"),
}


class IndianPIIDetector:
    """Regex + checksum detector for Indian identifiers. No network, no model.

    Aadhaar candidates must pass the Verhoeff checksum, which removes most false
    positives on other 12-digit numbers. Overlapping matches are resolved in favour
    of the earlier, longer, more specific type.
    """

    ORDER = ("AADHAAR", "GSTIN", "PAN", "IFSC", "EMAIL", "UPI", "PHONE_IN")

    def __init__(self, kinds: Iterable[str] | None = None):
        self.kinds = tuple(kinds) if kinds else self.ORDER

    def detect(self, text: str) -> list[Finding]:
        norm = normalise_digits(text)
        found: list[Finding] = []
        for kind in self.kinds:
            for m in _PATTERNS[kind].finditer(norm):
                if kind == "AADHAAR" and not verhoeff_valid("".join(m.groups())):
                    continue
                found.append(Finding(kind, m.start(), m.end(), text[m.start() : m.end()]))
        found.sort(key=lambda f: (f.start, -(f.end - f.start)))
        kept: list[Finding] = []
        for f in found:
            if kept and f.start < kept[-1].end:
                continue
            kept.append(f)
        return kept


def mask(text: str, detector: Detector | None = None) -> tuple[str, list[Finding]]:
    """Replace each finding with ``[KIND]``. Returns the masked text and the findings."""
    findings = (detector or IndianPIIDetector()).detect(text)
    out, last = [], 0
    for f in findings:
        out.append(text[last : f.start])
        out.append(f"[{f.kind}]")
        last = f.end
    out.append(text[last:])
    return "".join(out), findings
