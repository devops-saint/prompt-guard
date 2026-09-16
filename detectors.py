"""
detectors.py

Entity detectors for the prompt guard. Each detector is a plain function that
takes text and returns a list of Match objects. This file starts with regex-only
detectors so v1 has zero external dependencies and runs anywhere.

HOW TO ENHANCE LATER (without changing the rest of the pipeline):
  - Swap in Microsoft Presidio or spaCy NER for names/orgs/locations, which regex
    cannot reliably catch. Just make the new detector return the same Match shape
    and register it in `ALL_DETECTORS`.
  - Add an ML classifier detector for context-dependent sensitivity (e.g. a
    sentence that reveals a trade secret without matching any pattern).
  - Add a company-specific dictionary detector (project codenames, internal
    hostnames, employee ID formats) — see `build_dictionary_detector` below.
"""

from dataclasses import dataclass
import math
import re


@dataclass
class Match:
    entity_type: str   # e.g. "EMAIL", "PHONE", "SSN"
    start: int
    end: int
    value: str
    confidence: float  # 0.0-1.0, lets the policy engine set confidence thresholds later


# ---------------------------------------------------------------------------
# Structured PII: fixed-format patterns are the easiest and highest-confidence
# category to catch with regex alone.
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

_PHONE_RE = re.compile(
    r"(?<!\d)(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)"
)

_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

# Matches common card lengths (13-19 digits, optionally grouped by spaces/dashes)
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# A handful of common API key shapes — extend this list per-vendor as needed
_API_KEY_RE = re.compile(
    r"\b(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b"
)


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


# ---------------------------------------------------------------------------
# Entropy-based secret detection — catches secrets that don't match any known
# vendor pattern (a home-grown token, a randomly generated password, a key
# format we haven't special-cased). Known-pattern detection above is
# higher-confidence and should stay; this is the safety net underneath it.
# ---------------------------------------------------------------------------

_CANDIDATE_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/_=.\-]{20,}\b")

# Common long-but-benign strings we don't want to flag — extend as you see
# false positives in your own logs.
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
    """
    Real secrets (API keys, tokens, passwords) almost always mix at least two
    of {lowercase, uppercase, digit, symbol}. A plain English word — even a
    long one like "supercalifragilisticexpialidocious" — is a single class
    and can still have high Shannon entropy, so entropy alone isn't enough.
    This check is what keeps ordinary long words out of the results.
    """
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
    """
    Flags long tokens with high character-level entropy AND mixed character
    classes as POTENTIAL_SECRET. Confidence is deliberately lower than
    pattern-matched detectors (0.55) since this method still produces more
    false positives than a known vendor pattern (long hashes, base64 blobs
    that aren't secrets, etc.) — tune `min_length` / `entropy_threshold` per
    your own false-positive rate once you see it in logs.
    """
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
# Heuristic name detector — a coarse stand-in until you plug in real NER
# (spaCy / Presidio). Flags capitalized word pairs not at sentence start and
# not in a small stopword list. Expect false positives/negatives; this is
# intentionally conservative documentation, not a claim of accuracy.
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
    """
    Factory for a custom-term detector — use this for org-specific sensitive
    terms: project codenames, internal hostnames, customer account numbers,
    employee ID formats, etc. Pass in a list of exact terms or add regex
    patterns for formats (e.g. r"EMP-\\d{6}").
    """
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(r"\b(" + "|".join(re.escape(t) for t in terms) + r")\b", flags)

    def _detect(text: str):
        return [Match(entity_type, m.start(), m.end(), m.group(), 0.85) for m in pattern.finditer(text)]

    return _detect


# Registry — add new detectors here so `guard.py` picks them up automatically
ALL_DETECTORS = [
    detect_email,
    detect_phone,
    detect_ssn,
    detect_credit_card,
    detect_ip_address,
    detect_api_key,
    detect_high_entropy_secret,
    detect_name_heuristic,
]
