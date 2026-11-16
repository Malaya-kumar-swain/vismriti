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


_B36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_valid(gstin: str) -> bool:
    """True if a 15-character GSTIN has the correct check character (base-36 weighted checksum)."""
    if len(gstin) != 15 or any(ch not in _B36 for ch in gstin):
        return False
    total = 0
    for i, ch in enumerate(gstin[:14]):
        product = _B36.index(ch) * (1 if i % 2 == 0 else 2)
        total += product // 36 + product % 36
    return _B36[(36 - total % 36) % 36] == gstin[14]


# Devanagari, Bengali, Odia, Tamil, Telugu, Kannada, Gujarati, Gurmukhi digit blocks.
_INDIC_ZEROS = [0x0966, 0x09E6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0AE6, 0x0A66]
_DIGIT_MAP = {z + i: str(i) for z in _INDIC_ZEROS for i in range(10)}


def normalise_digits(text: str) -> str:
    """Map Indic-script digits to ASCII so identifiers written in Hindi or Odia still match.

    The mapping is one character to one character, so match offsets stay valid.
    """
    return text.translate(_DIGIT_MAP)


# Invisible characters that copy-paste or attackers put inside identifiers.
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}
# Cyrillic letters that look identical to Latin ones (used to slip PAN, IFSC or UPI IDs past filters).
_LOOKALIKES = {
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T", "Х": "X",
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y",
}
_CHAR_MAP = {**{chr(k): v for k, v in _DIGIT_MAP.items()}, **_LOOKALIKES}


def normalise(text: str) -> tuple[str, list[int]]:
    """Undo common disguises before matching: Indic digits, look-alike letters and invisible characters.

    Returns the cleaned text and, for each of its characters, the position in the original text,
    so findings can be reported (and masked) at their true place in the original.
    """
    out: list[str] = []
    index: list[int] = []
    for i, ch in enumerate(text):
        if ord(ch) in _ZERO_WIDTH:
            continue
        out.append(_CHAR_MAP.get(ch, ch))
        index.append(i)
    return "".join(out), index


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
    # Groups may be separated by a space, a hyphen or a line break (numbers split across lines).
    "AADHAAR": re.compile(r"(?<!\d)([2-9]\d{3})(?:[ -]|\r?\n)?(\d{4})(?:[ -]|\r?\n)?(\d{4})(?!\d)"),
    "PAN": re.compile(r"(?<![A-Z0-9])[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z](?![A-Z0-9])"),
    "GSTIN": re.compile(r"(?<![A-Z0-9])\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z](?![A-Z0-9])"),
    "IFSC": re.compile(r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])"),
    "EMAIL": re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"),
    "UPI": re.compile(rf"(?<![\w.])[\w.-]{{2,256}}@(?:{_UPI_HANDLES})(?!\w|\.\w)", re.I),
    "PHONE_IN": re.compile(r"(?<![\d+])(?:\+91[ -]?|0)?([6-9]\d{4})[ -]?(\d{5})(?!\d)"),
}


class IndianPIIDetector:
    """Regex + checksum detector for Indian identifiers. No network, no model.

    Aadhaar candidates must pass the Verhoeff checksum and GSTIN candidates their check
    character, which removes most false positives on look-alike numbers. Overlapping matches are resolved in favour
    of the earlier, longer, more specific type.
    """

    ORDER = ("AADHAAR", "GSTIN", "PAN", "IFSC", "EMAIL", "UPI", "PHONE_IN")

    def __init__(self, kinds: Iterable[str] | None = None):
        self.kinds = tuple(kinds) if kinds else self.ORDER

    def detect(self, text: str) -> list[Finding]:
        norm, index = normalise(text)
        found: list[Finding] = []
        for kind in self.kinds:
            for m in _PATTERNS[kind].finditer(norm):
                if kind == "AADHAAR" and not verhoeff_valid("".join(m.groups())):
                    continue
                if kind == "GSTIN" and not gstin_valid(m.group(0)):
                    continue
                start, end = index[m.start()], index[m.end() - 1] + 1  # positions in the original text
                found.append(Finding(kind, start, end, text[start:end]))
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
