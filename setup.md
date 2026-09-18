Setting up the Prompt Guard gateway and running it alongside a local Llama model on a fresh Windows PC requires configuring Python, installing Ollama, and launching the application server.

**Phase 1: Initial Setup (One-Time)**

1. **Install Python with PATH Configured:** 2 min.
Download the official Windows installer from [python.org/downloads](https://www.python.org/downloads/). Run the downloaded `.exe` file, ensure you check the box labeled **Add python.exe to PATH** on the first screen, and click **Install Now**.

*Verification:* Open a fresh PowerShell window and run `python --version` and `pip --version` to confirm both commands return version numbers.


2. **Disable Windows App Execution Aliases:** 1 min.
Open Windows **Settings** > **Apps** > **Advanced app settings** > **App execution aliases**. Scroll down and switch the toggles to **Off** for both `python.exe` and `python3.exe` (App Installer) so Windows does not redirect commands to the Microsoft Store.

*Verification:* Type `python` in PowerShell; it should launch the Python interactive prompt (`>>>`) instead of opening the Microsoft Store (type `exit()` and press Enter to return).


3. **Install Ollama and Pull Llama 3.2:** 3-5 min.
Download and run the installer from [ollama.com/download](https://ollama.com/download). Once installed, Ollama launches in the system tray and exposes a local API at `http://localhost:11434`. Open PowerShell and pull the model configured in `proxy.py`:

```powershell
ollama pull llama3.2

```

*Verification:* Run `ollama list` and verify `llama3.2` appears in the list of installed models.


4. **Place Project Files and Install Dependencies:** 2 min.
Place all project files (`proxy.py`, `guard.py`, `detectors.py`, `policy.py`, `policy.json`, `classifier.py`, `classification_policy.json`, `audit.py`, `vault.py`, `schema.py`, and `ui.html`) together in a dedicated directory (for example, `C:\prompt-guard`). Navigate into that directory in PowerShell and install the required libraries:

```powershell
cd C:\prompt-guard
python -m pip install fastapi uvicorn pydantic

```

*Verification:* Run `python -c "import fastapi, uvicorn, pydantic; print('Ready')"` and ensure it outputs `Ready` without errors.


---

**Phase 2: Routine Startup (Daily Use)**

Once the one-time installation is finished, use this sequence whenever you want to work with the project:

* **1. Confirm Ollama is running:** Ollama starts automatically with Windows, but you can confirm the background process is responding:
```powershell
curl http://localhost:11434

```




*Verification:* The command returns `Ollama is running`.

* **2. Start the Prompt Guard Proxy:** Open PowerShell, navigate to your project directory, and launch the server:
```powershell
cd C:\prompt-guard
python -m uvicorn proxy:app --reload --port 8080

```




*Verification:* Look for the log lines `Application startup complete` and `Uvicorn running on [http://127.0.0.1:8080](http://127.0.0.1:8080)`.

* **3. Access the Web Console:** Open your browser and navigate to:
```text
http://localhost:8080/

```




*Verification:* The web interface loads, allowing you to submit test prompts containing sensitive data and receive responses from your local model.

---

**Phase 3: Stopping the Services**

* **1. Stop the Proxy Server:** Click into the PowerShell terminal running Uvicorn and press `Ctrl + C`.
*Verification:* The console prints `Application shutdown complete` and returns to your standard command prompt `PS C:\prompt-guard>`.
* **2. Free Model VRAM (Optional):** To unload the model from system RAM/VRAM while keeping the background API alive, run:
```powershell
ollama stop llama3.2

```


*Verification:* Run `ollama ps` and confirm no models are listed under the active processes.
* **3. Shut Down Ollama Completely (Optional):** Right-click the Ollama llama icon in the Windows notification tray (bottom-right corner of the taskbar) and select **Quit Ollama**.
*Verification:* Running `curl http://localhost:11434` fails with a connection error.

--------------------------------------------------------------------------------

The Enterprise Prompt Guard sits as an intercepting gateway between a user and an LLM, sanitizing sensitive inputs, dispatching safe text to the model, and re-inserting real values into the final response.

**1. Request Ingestion**

* The user submits a prompt and destination (such as `any` or `approved_enterprise_ai`) through the web console (`ui.html`) or API (`proxy.py` via `/guard-and-call`).


* `proxy.py` passes the payload to the orchestrator, `PromptGuard` (`guard.py`).



**2. Dual-Layer Scanning**

* **Entity Detection (`detectors.py`):** Scans the text using regex for structured data (emails, phones, SSNs, Luhn-validated credit cards, IPs, API keys), heuristics for names, and Shannon entropy calculations for unknown random tokens. Matches below `min_confidence` are dropped, and overlaps are deduplicated by confidence score.


* **Sensitivity Classification (`classifier.py`):** Scans the entire prompt against keyword lists in `classification_policy.json` to assign a macro sensitivity tier: `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, or `SECRET`.



**3. Policy Gating**

* `guard.py` evaluates the results against rules in `policy.json` and destination permissions:


* If any detected entity requires a `block` action (e.g., credit cards, SSNs, API keys), the request halts immediately.


* If the destination cannot receive the prompt's sensitivity tier (e.g., a `CONFIDENTIAL` prompt routed to `any`), it blocks immediately.




* Blocked attempts emit an audit log and return rejection reasons without calling the model.



**4. Sanitization and Vaulting**

* For permitted prompts, `guard.py` processes replacements from right to left to keep string indices intact.


* Entities set to `mask` are replaced irreversibly (e.g., `[IP_ADDRESS]`).


* Entities set to `tokenize` are replaced with sequential placeholders (e.g., `{{PII_EMAIL_0001}}`), storing the real value in `InMemoryVault` (`vault.py`).



**5. Audit, Inference, and Rehydration**

* **Audit Logging (`audit.py`):** Generates a structured JSON record logging entity counts, actions taken, and sensitivity tiers—without recording the raw prompt or sensitive values.


* **LLM Call (`proxy.py` / `schema.py`):** Formats the sanitized text into a provider-agnostic `CanonicalPrompt` and dispatches it locally to Ollama (`http://localhost:11434/api/generate`).


* **Rehydration (`vault.py`):** When Ollama returns the generated response, `vault.rehydrate()` uses regex replacement to swap any echoed `{{PII_...}}` tokens back into the original plaintext values before the client receives the answer.

-------------------------------------------------------------------------------

# detectors.py

Production-ready entity detectors and masking engine for prompt guards and PII scanners.

Features:
  - Zero external dependencies required out of the box (standard library only).
  - Optional plug-and-play spaCy NER integration for named entities.
  - Contextual & heuristic name detection (catches single lowercase/capitalized names
    associated with identifiers or intro phrases like "name is X" or "X phone number").
  - Strict algorithmic validation (Luhn for Credit Cards, RFC-compliant SSN checks,
    ipaddress verification for IPv4/IPv6).
  - Expanded credential signatures (OpenAI, AWS, GitHub, Google, Slack, JWT).
  - Overlap resolution and an automated PII masking/redaction utility.
"""

from dataclasses import dataclass
import ipaddress
import math
import re
from typing import Callable, Dict, List, Optional


# Core Data Models



@dataclass
class Match:
    entity_type: str  # e.g., "EMAIL", "PHONE", "SSN", "PERSON_NAME"
    start: int  # Character start index (inclusive)
    end: int  # Character end index (exclusive)
    value: str  # Matched substring
    confidence: float  # Score from 0.0 to 1.0



# Structured PII Detectors: Regex Patterns + Algorithmic Verification


# RFC 5322 simplified email matcher with boundary constraints
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b", re.IGNORECASE
)

# Handles domestic/international numbers (E.164), extensions, dashes, spaces, and bare 10-digit formats
_PHONE_RE = re.compile(
    r"(?:(?:\+?([1-9]\d{0,2})[\s.-]?)?(?:\(?(\d{3})\)?[\s.-]?)?(\d{3})[\s.-]?(\d{4})"
    r"(?:\s*(?:ext|x|ext.)\s*(\d{1,5}))?)\b"
)

# Social Security Numbers: validates structure and excludes invalid SSA areas (000, 666, 900-999),
# groups (00), and serials (0000)
_SSN_RE = re.compile(
    r"\b(?!000|666|9\d{2})(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b"
)

# Matches card numbers between 13 and 19 digits with optional separators
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")

# Regex pattern for candidate IPv4 and IPv6 hex addresses
_IP_CANDIDATE_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}\b"
)

# Known high-assurance API keys, cloud credentials, and JWT patterns
_API_KEY_PATTERNS = [
    # OpenAI API Keys (legacy sk-... and project-scoped sk-proj-...)
    (r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b", "OPENAI_API_KEY", 0.98),
    # AWS Access Key IDs (AKIA, ASIA, etc.)
    (r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", "AWS_ACCESS_KEY_ID", 0.98),
    # GitHub Personal Access Tokens (classic and fine-grained)
    (r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b", "GITHUB_PAT", 0.99),
    # Google Cloud / Firebase API Keys
    (r"\bAIza[0-9A-Za-z-_]{35}\b", "GOOGLE_API_KEY", 0.98),
    # Slack bot, user, or app tokens
    (r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b", "SLACK_TOKEN", 0.98),
    # Standard JSON Web Token (header.payload.signature)
    (
        r"\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b",
        "JWT_TOKEN",
        0.95,
    ),
]
_COMPILED_API_KEYS = [
    (re.compile(pat), name, conf) for pat, name, conf in _API_KEY_PATTERNS
]


def _luhn_check(number_str: str) -> bool:
    """Verifies credit card validity using the Luhn mod-10 formula."""
    digits = [int(d) for d in re.sub(r"\D", "", number_str)]
    if not digits:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def detect_email(text: str) -> List[Match]:
    """Detects standard formatted email addresses."""
    return [
        Match("EMAIL", m.start(), m.end(), m.group(), 0.95)
        for m in _EMAIL_RE.finditer(text)
    ]


def detect_phone(text: str) -> List[Match]:
    """Detects phone numbers while excluding standalone numeric sequences that fail length criteria."""
    matches = []
    for m in _PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 10 <= len(digits) <= 15:
            matches.append(Match("PHONE", m.start(), m.end(), m.group(), 0.85))
    return matches


def detect_ssn(text: str) -> List[Match]:
    """Detects US Social Security Numbers, skipping non-issued area/group numbers."""
    return [
        Match("SSN", m.start(), m.end(), m.group(), 0.95)
        for m in _SSN_RE.finditer(text)
    ]


def detect_credit_card(text: str) -> List[Match]:
    """Detects card numbers and verifies them against the Luhn algorithm."""
    matches = []
    for m in _CREDIT_CARD_RE.finditer(text):
        candidate = re.sub(r"\D", "", m.group())
        if 13 <= len(candidate) <= 19 and _luhn_check(candidate):
            matches.append(Match("CREDIT_CARD", m.start(), m.end(), m.group(), 0.92))
    return matches


def detect_ip_address(text: str) -> List[Match]:
    """Detects IPv4 and IPv6 addresses verified through Python's standard ipaddress module."""
    matches = []
    for m in _IP_CANDIDATE_RE.finditer(text):
        val = m.group()
        try:
            ipaddress.ip_address(val)
            matches.append(Match("IP_ADDRESS", m.start(), m.end(), val, 0.90))
        except ValueError:
            continue
    return matches


def detect_api_key(text: str) -> List[Match]:
    """Identifies vendor-specific high-assurance API keys and signed tokens."""
    matches = []
    for pattern, key_type, confidence in _COMPILED_API_KEYS:
        for m in pattern.finditer(text):
            matches.append(Match(key_type, m.start(), m.end(), m.group(), confidence))
    return matches



# Name and Proper Noun Detectors (spaCy + Contextual + Heuristic)


# Optional spaCy integration
_SPACY_NLP = None
try:
    import spacy

    try:
        _SPACY_NLP = spacy.load("en_core_web_sm")
    except IOError:
        pass
except ImportError:
    pass

# Heuristics for titles and multi-token capitalized names
_NAME_HONORIFIC_RE = re.compile(
    r"\b(Mr\.|Mrs\.|Ms\.|Miss|Dr\.|Prof\.|Rev\.|Judge)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b"
)
_MULTI_WORD_NAME_RE = re.compile(
    r"\b([A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+)\b"
)

# 1. Matches introductory phrases: "name is john", "i am priya", "call me aayush"
_NAME_INTRODUCERS_RE = re.compile(
    r"\b(?:my\s+name\s+is|name\s+is|this\s+is|i\s+am|i'm|call\s+me|reach\s+out\s+to)\s+([A-Za-z]{2,25})\b",
    re.IGNORECASE,
)

# 2. Matches name followed by PII/contact markers (covers lowercase & single tokens,
#    e.g., "aayush phone number is...", "chetan's email is...", "priya contact:")
_NAME_PII_ASSOCIATION_RE = re.compile(
    r"\b([A-Za-z]{2,25})(?:'s)?\s+(?:phone(?:\s+number)?|mobile(?:\s+number)?|cell(?:\s+number)?|contact(?:\s+number)?|email(?:\s+address)?|address|ssn)\b",
    re.IGNORECASE,
)

# Words to ignore from contextual name matching to prevent false positives
_CONTEXT_NAME_STOPWORDS = {
    "my",
    "his",
    "her",
    "their",
    "our",
    "your",
    "its",
    "the",
    "a",
    "an",
    "this",
    "that",
    "any",
    "user",
    "client",
    "customer",
    "employee",
    "person",
    "contact",
    "phone",
    "cell",
    "mobile",
    "work",
    "home",
    "office",
    "primary",
    "secondary",
    "valid",
    "new",
    "old",
    "emergency",
    "registered",
    "confidential",
    "unknown",
}

_HEURISTIC_STOPWORDS = {
    "United States",
    "North America",
    "South America",
    "New York",
    "Los Angeles",
    "San Francisco",
    "Silicon Valley",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
    "Thank You",
    "Good Morning",
    "Terms Service",
    "Privacy Policy",
    "Customer Support",
}


def detect_contextual_names(text: str) -> List[Match]:
    """
    Catches single-token and lowercase names identified by semantic context
    (e.g., preceding 'phone number' or following 'name is').
    """
    matches = []

    # 1. Names following introductions ("my name is ...", "call me ...")
    for m in _NAME_INTRODUCERS_RE.finditer(text):
        name = m.group(1)
        if name.lower() not in _CONTEXT_NAME_STOPWORDS:
            matches.append(Match("PERSON_NAME", m.start(1), m.end(1), name, 0.78))

    # 2. Names preceding contact markers ("aayush phone number is ...")
    for m in _NAME_PII_ASSOCIATION_RE.finditer(text):
        name = m.group(1)
        if name.lower() not in _CONTEXT_NAME_STOPWORDS:
            matches.append(Match("PERSON_NAME", m.start(1), m.end(1), name, 0.80))

    return matches


def detect_names(text: str) -> List[Match]:
    """
    Detects person and organization names using spaCy NER if available,
    falling back to title patterns and multi-word capitalization heuristics.
    """
    if _SPACY_NLP is not None:
        doc = _SPACY_NLP(text)
        matches = []
        for ent in doc.ents:
            if ent.label_ in ("PERSON", "ORG"):
                matches.append(
                    Match(
                        entity_type="PERSON_NAME"
                        if ent.label_ == "PERSON"
                        else "ORGANIZATION",
                        start=ent.start_char,
                        end=ent.end_char,
                        value=ent.text,
                        confidence=0.88,
                    )
                )
        return matches

    matches = []

    # Honorific checks ("Dr. John Doe")
    for m in _NAME_HONORIFIC_RE.finditer(text):
        matches.append(Match("PERSON_NAME", m.start(), m.end(), m.group(), 0.85))

    # Multi-word capitalization checks
    for m in _MULTI_WORD_NAME_RE.finditer(text):
        val = m.group()
        if val in _HEURISTIC_STOPWORDS:
            continue

        # Ignore sentence-initial capitalization
        start_idx = m.start()
        prefix = text[:start_idx].rstrip()
        if not prefix or prefix[-1] in ".!?\n":
            continue

        matches.append(Match("PERSON_NAME", m.start(), m.end(), val, 0.55))

    return matches



# Entropy-Based Secret Detection


_CANDIDATE_TOKEN_RE = re.compile(r"\b[A-Za-z0-9+/_=.\-]{20,}\b")
_ENTROPY_ALLOWLIST_RE = re.compile(
    r"^(https?://|www\.|[A-Za-z0-9.-]+\.(com|org|net|io|dev|edu|gov)\b)",
    re.IGNORECASE,
)


def _shannon_entropy(s: str) -> float:
    """Calculates character-level Shannon entropy (bits per character)."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _has_mixed_character_classes(s: str) -> bool:
    """Verifies that the string mixes at least two character classes."""
    classes = sum(
        [
            bool(re.search(r"[a-z]", s)),
            bool(re.search(r"[A-Z]", s)),
            bool(re.search(r"\d", s)),
            bool(re.search(r"[+/_=.\-]", s)),
        ]
    )
    return classes >= 2


def detect_high_entropy_secret(
    text: str, min_length: int = 20, entropy_threshold: float = 3.5
) -> List[Match]:
    """Flags unmodeled high-entropy tokens as potential secrets."""
    matches = []
    for m in _CANDIDATE_TOKEN_RE.finditer(text):
        candidate = m.group()
        if len(candidate) < min_length or _ENTROPY_ALLOWLIST_RE.match(candidate):
            continue
        if not _has_mixed_character_classes(candidate):
            continue
        if _shannon_entropy(candidate) >= entropy_threshold:
            matches.append(
                Match("POTENTIAL_SECRET", m.start(), m.end(), candidate, 0.60)
            )
    return matches



# Custom Dictionary Detector Factory



def build_dictionary_detector(
    entity_type: str,
    terms: List[str],
    case_sensitive: bool = False,
    confidence: float = 0.85,
) -> Callable[[str], List[Match]]:
    """Factory for generating custom keyword or pattern detectors (e.g., employee names, codenames)."""
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(t) for t in terms) + r")\b", flags
    )

    def _detect(text: str) -> List[Match]:
        return [
            Match(entity_type, m.start(), m.end(), m.group(), confidence)
            for m in pattern.finditer(text)
        ]

    return _detect



# Pipeline Aggregation, Overlap Resolution & Masking



def resolve_overlaps(matches: List[Match]) -> List[Match]:
    """
    Resolves overlapping spans by prioritizing:
      1. Higher confidence matches.
      2. Longer spans if confidence is identical.
    """
    sorted_matches = sorted(
        matches, key=lambda m: (m.confidence, m.end - m.start), reverse=True
    )
    accepted_spans: List[Match] = []

    for match in sorted_matches:
        has_overlap = any(
            not (match.end <= existing.start or match.start >= existing.end)
            for existing in accepted_spans
        )
        if not has_overlap:
            accepted_spans.append(match)

    return sorted(accepted_spans, key=lambda m: m.start)


# Master registry containing all default detectors
ALL_DETECTORS = [
    detect_email,
    detect_phone,
    detect_ssn,
    detect_credit_card,
    detect_ip_address,
    detect_api_key,
    detect_names,
    detect_contextual_names,
    detect_high_entropy_secret,
]


def scan_pii(
    text: str,
    detectors: Optional[List[Callable[[str], List[Match]]]] = None,
    min_confidence: float = 0.50,
) -> List[Match]:
    """
    Executes all detectors on input text, filters by confidence,
    and removes overlapping detections.
    """
    active_detectors = detectors or ALL_DETECTORS
    raw_matches: List[Match] = []

    for detector in active_detectors:
        raw_matches.extend(detector(text))

    filtered = [m for m in raw_matches if m.confidence >= min_confidence]
    return resolve_overlaps(filtered)


def mask_pii(
    text: str,
    matches: Optional[List[Match]] = None,
    placeholder_format: str = "{{{{PII_{entity_type}_{index:04d}}}}}",
) -> str:
    """
    Replaces detected PII spans with formatted placeholders (e.g., {{PII_PHONE_0001}}).
    Replaces spans in reverse order so character offsets remain accurate throughout substitution.
    """
    if matches is None:
        matches = scan_pii(text)

    # Sort spans in reverse order based on start position
    sorted_matches = sorted(matches, key=lambda m: m.start, reverse=True)

    type_counts: Dict[str, int] = {}
    for m in sorted_matches:
        type_counts[m.entity_type] = type_counts.get(m.entity_type, 0) + 1

    masked_text = text
    for match in sorted_matches:
        idx = type_counts[match.entity_type]
        type_counts[match.entity_type] -= 1

        placeholder = placeholder_format.format(
            entity_type=match.entity_type,
            index=idx,
        )
        masked_text = (
            masked_text[: match.start] + placeholder + masked_text[match.end :]
        )

    return masked_text



# Verification & Self-Test


if __name__ == "__main__":
    # Test case 1: The user's exact case (lowercase single name + 10-digit phone)
    sample_1 = "aayush phone number is 8830164015"
    matches_1 = scan_pii(sample_1)
    masked_1 = mask_pii(sample_1, matches_1)

    print("=== Test Case 1 ===")
    print(f"Original: {sample_1}")
    print(f"Masked:   {masked_1}")
    for m in matches_1:
        print(f" -> Found {m.entity_type}: '{m.value}' (conf: {m.confidence})")

    print("\n=== Test Case 2 ===")
    # Test case 2: Introductions, credentials, cards, and IPs
    sample_2 = (
        "Hello, my name is John Doe and my colleague is Dr. Sarah Connor. "
        "Reach out at john.doe@enterprise.org or +1 (555) 321-9876. "
        "Our server is at 192.168.1.104. "
        "Do not store my SSN 123-45-6789 or card 4532-0150-1234-5678. "
        "The OpenAI token is sk-proj-abc123XYZ4567890abcdef1234567890abcdef."
    )
    matches_2 = scan_pii(sample_2)
    masked_2 = mask_pii(sample_2, matches_2)

    print(f"Masked:\n{masked_2}\n")
    print(f"Total entities detected: {len(matches_2)}")