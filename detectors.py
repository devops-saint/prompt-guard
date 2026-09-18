"""
detectors.py

Entity detectors for the prompt guard. Each detector is a plain function that
takes text and returns a list of Match objects.
"""

from dataclasses import dataclass
import math
import re


@dataclass
class Match:
    entity_type: str   # e.g. "EMAIL", "PHONE", "SSN", "PAN"
    start: int
    end: int
    value: str
    confidence: float  # 0.0-1.0


# ---------------------------------------------------------------------------
# Structured PII: fixed-format patterns
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_PHONE_RE = re.compile(
    r"(?<!\d)(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
)

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_API_KEY_RE = re.compile(
    r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)

# Indian PAN Card: 5 letters, 4 numbers, 1 letter (e.g., chfpj0322j)
_PAN_RE = re.compile(r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]\b")


def _luhn_check(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"[ -]", "", number)]
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def detect_email(text: str):
    return [Match("EMAIL", m.start(), m.end(), m.group(), 0.95) for m in _EMAIL_RE.finditer(text)]


def detect_phone(text: str):
    out = []
    for m in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 10 <= len(digits) <= 13:
            out.append(Match("PHONE", m.start(), m.end(), m.group(), 0.75))
    return out


def detect_ssn(text: str):
    return [Match("SSN", m.start(), m.end(), m.group(), 0.9) for m in _SSN_RE.finditer(text)]


def detect_credit_card(text: str):
    out = []
    for m in _CREDIT_CARD_RE.finditer(text):
        candidate = re.sub(r"[ -]", "", m.group())
        if 13 <= len(candidate) <= 19 and _luhn_check(m.group()):
            out.append(Match("CREDIT_CARD", m.start(), m.end(), m.group(), 0.9))
    return out


def detect_ip_address(text: str):
    out = []
    for m in _IP_RE.finditer(text):
        octets = m.group().split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            out.append(Match("IP_ADDRESS", m.start(), m.end(), m.group(), 0.7))
    return out


def detect_api_key(text: str):
    return [Match("API_KEY", m.start(), m.end(), m.group(), 0.95) for m in _API_KEY_RE.finditer(text)]


def detect_pan(text: str):
    return [Match("PAN", m.start(), m.end(), m.group().upper(), 0.95) for m in _PAN_RE.finditer(text)]


# ---------------------------------------------------------------------------
# Entropy-based secret detection
# ---------------------------------------------------------------------------

_CANDIDATE_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/_=.\-]{20,}\b")

_ENTROPY_ALLOWLIST_RE = re.compile(
    r"^(https?://|www\.|[A-Za-z0-9.-]+\.(com|org|net|io|dev)\b)", re.IGNORECASE
)


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _has_mixed_character_classes(s: str) -> bool:
    classes = 0
    if re.search(r"[a-z]", s):
        classes += 1
    if re.search(r"[A-Z]", s):
        classes += 1
    if re.search(r"\d", s):
        classes += 1
    if re.search(r"[+/_=.\-]", s):
        classes += 1
    return classes >= 2


def detect_high_entropy_secret(text: str, min_length: int = 20, entropy_threshold: float = 3.5):
    out = []
    for m in _CANDIDATE_TOKEN_RE.finditer(text):
        candidate = m.group()
        if len(candidate) < min_length:
            continue
        if _ENTROPY_ALLOWLIST_RE.match(candidate):
            continue
        if not _has_mixed_character_classes(candidate):
            continue
        entropy = _shannon_entropy(candidate)
        if entropy >= entropy_threshold:
            out.append(Match("POTENTIAL_SECRET", m.start(), m.end(), candidate, 0.55))
    return out


# ---------------------------------------------------------------------------
# Name detection & dictionary matchers
# ---------------------------------------------------------------------------

_NAME_RE = re.compile(r"\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b")
_NAME_STOPWORDS = {
    "New York", "Los Angeles", "United States", "Silicon Valley", "New Delhi",
    "Hong Kong", "San Francisco", "North America", "South America",
}


def detect_name_heuristic(text: str):
    out = []
    for m in _NAME_RE.finditer(text):
        if m.group() in _NAME_STOPWORDS:
            continue
        out.append(Match("PERSON_NAME", m.start(), m.end(), m.group(), 0.4))
    return out


def build_dictionary_detector(entity_type: str, terms: list[str], case_sensitive: bool = False):
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(r"\b(" + "|".join(re.escape(t) for t in terms) + r")\b", flags)

    def _detect(text: str):
        return [Match(entity_type, m.start(), m.end(), m.group(), 0.85) for m in pattern.finditer(text)]

    return _detect


# Catches known single/lowercase first names that the two-word capitalized heuristic misses
detect_known_names = build_dictionary_detector(
    "PERSON_NAME",
    ["aayush", "harshal", "chetan", "amogh", "tiwari", "sumaan"],
    case_sensitive=False,
)

# Registry — pick up both PAN and single-name dictionary detectors automatically
ALL_DETECTORS = [
    detect_email,
    detect_phone,
    detect_ssn,
    detect_credit_card,
    detect_ip_address,
    detect_api_key,
    detect_high_entropy_secret,
    detect_pan,
    detect_name_heuristic,
    detect_known_names,
]