# Enterprise Prompt Guard — v1

A working starting point for filtering PII/sensitive data out of prompts before
they reach any third-party LLM, with reversible tokenization so responses can
still be rehydrated for the end user.

This v1 is intentionally dependency-free (pure Python standard library) so it
runs anywhere with zero setup, and is structured so each piece can be upgraded
independently as your needs grow.

## What's here

| File | Purpose |
|---|---|
| `detectors.py` | Regex-based detection for email, phone, SSN, credit card, IP, API keys, a heuristic name detector, and an entropy-based detector for secrets that don't match a known pattern |
| `classifier.py` | Prompt-level sensitivity classification (`PUBLIC` → `SECRET`), independent of entity detection, plus a destination-vs-sensitivity allowlist |
| `classification_policy.json` | Editable config — sensitivity keywords and which destinations each level may reach |
| `policy.py` | Loads redaction rules from `policy.json`; decides allow/mask/tokenize/block per entity type |
| `policy.json` | Editable config — change entity-level rules here without touching code |
| `vault.py` | In-memory token store for reversible redaction (swap out before production) |
| `audit.py` | Structured, queryable audit record per request — logs categories and actions, never raw values or the original prompt |
| `schema.py` | Canonical, provider-agnostic prompt representation, plus a stub adapter per provider |
| `guard.py` | Orchestrates detect → classify → policy → redact/tokenize → destination check → audit → canonical output |
| `proxy.py` | FastAPI service exposing the guard over HTTP, plus a browser UI served at `/` |
| `ui.html` | Minimal browser console — calls `/guard-and-call` directly, not a simulation |
| `demo_cli.py` | Zero-setup script showing the pipeline end to end |
| `test_canary.py` | Regression suite — run after any change to detectors, classifier, or policy |

## Running against a real model (Ollama)

`call_llm()` in `proxy.py` now calls a locally running [Ollama](https://ollama.com)
instance instead of returning a stub response. This keeps every prompt inside
your own infrastructure end to end — the sanitized prompt never leaves the
machine, not even to a cloud LLM provider, which is the strongest version of
the original "don't leak data to third parties" goal.

```bash
# 1. Install Ollama (see https://ollama.com/download), then pull a model
ollama pull llama3.2

# 2. Ollama serves on localhost:11434 automatically after install.
#    Confirm it's running:
curl http://localhost:11434

# 3. Start the guard as usual
uvicorn proxy:app --reload --port 8080
```

Open `http://localhost:8080/`, run a prompt, and the "LLM response" you see
back is a real response from your local model — routed through detection,
classification, tokenization, and rehydration first.

If Ollama is running on a different host/port, set `OLLAMA_HOST` before
starting the proxy (`export OLLAMA_HOST=http://192.168.1.20:11434`). If
Ollama isn't running or the model hasn't been pulled, `call_llm()` returns a
clear inline error instead of crashing the request.

**Note on what Ollama does and doesn't give you:** it removes the "sent to a
cloud provider" risk entirely, but local models are generally weaker than
frontier cloud models, and you're now responsible for the hardware to run
them at whatever scale you need. This is a legitimate deployment choice for
CONFIDENTIAL/RESTRICTED-tier traffic specifically — nothing stops you from
routing PUBLIC/INTERNAL-tier prompts to a cloud provider and reserving Ollama
for the sensitive tiers, by branching on `sensitivity_level` in
`guard_and_call()`.

## What changed since the first version

The initial version only reasoned about individual entities (an email address,
a credit card number). Four additions close specific gaps that plain entity
detection cannot cover on its own:

- **Sensitivity classification** (`classifier.py`) catches prompts that carry
  no PII at all but are still sensitive by content — e.g. a description of
  internal system architecture. It assigns a level (`PUBLIC` through
  `SECRET`) and checks that level against the prompt's destination, so a
  CONFIDENTIAL prompt can be blocked from a public API while still being
  allowed to an approved enterprise model.
- **Entropy-based secret detection** (`detectors.py`) catches secrets that
  don't match any known vendor key format — a home-grown token, a randomly
  generated password — by flagging long strings with high character-level
  entropy *and* mixed character classes (the mixed-class check is what keeps
  ordinary long English words from being flagged).
- **A canary/regression test suite** (`test_canary.py`) — 19 cases covering
  entity detection, blocking, sensitivity classification, and the interaction
  between them. Run this after every change to detectors, classifier, or
  policy so a fix or new pattern can't silently regress later.
- **A structured audit record and canonical prompt schema** (`audit.py`,
  `schema.py`) — every request now produces a queryable JSON record
  (detections, actions, sensitivity, final decision) without ever storing the
  original prompt or raw matched values, plus a provider-agnostic
  `CanonicalPrompt` object that decouples the guard from any one LLM API
  format.

## Quick start

```bash
# CLI demo — no server, no dependencies beyond the standard library
python3 demo_cli.py

# HTTP proxy + browser UI — requires fastapi + uvicorn
pip install -r requirements.txt --break-system-packages
uvicorn proxy:app --reload --port 8080
```

Then open `http://localhost:8080/` in a browser for a working UI, or hit the
API directly:
```bash
curl -X POST localhost:8080/sanitize \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Email John Smith at john@acme.com about his refund"}'

# Regression suite
python3 -m unittest test_canary.py -v
```

To try the sensitivity classifier and destination checks, pass `destination`:

```bash
curl -X POST localhost:8080/sanitize \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Here is our internal architecture and customer list", "destination": "approved_enterprise_ai"}'
```

`destination` defaults to `"any"`, which only satisfies `PUBLIC`-level
content — anything classified `INTERNAL` or above will block unless you pass
one of the destinations defined in `classification_policy.json`.

## How it works

1. **Detect entities** — every registered detector in `detectors.py` scans the
   prompt (patterns, entropy, heuristic names). Overlapping matches are
   deduplicated, keeping the highest-confidence one.
2. **Classify sensitivity** — independently of entity detection,
   `classifier.py` scans the whole prompt for keywords/phrases and assigns a
   level from `PUBLIC` to `SECRET`. This is what catches sensitive content
   that contains no PII at all.
3. **Decide per entity** — `policy.py` looks up each detected entity type in
   `policy.json` and returns `allow`, `mask`, `tokenize`, or `block`.
4. **Check destination against sensitivity** — `classifier.py`'s destination
   policy checks whether the prompt's sensitivity level is permitted for
   where it's headed. A CONFIDENTIAL prompt can be blocked from a public API
   destination while still allowed to an approved enterprise model.
5. **Act** — `guard.py` applies the entity-level decision: masked entities
   become `[TYPE]`; tokenized entities become `{{PII_TYPE_0001}}` with the
   real value stored in the vault. If any entity is `block`-listed, or the
   destination check fails, the whole prompt is rejected — nothing is sent
   anywhere.
6. **Send** — the sanitized prompt goes to the LLM. The provider never sees
   the real value for anything tokenized or masked. `schema.py`'s
   `CanonicalPrompt` carries the sanitized text plus metadata in a
   provider-agnostic shape.
7. **Rehydrate** — when the response comes back, `guard.rehydrate()` swaps any
   tokens the model echoed back for their real values before showing the user.
8. **Audit** — every request produces a structured `AuditRecord` (`audit.py`):
   entity categories and actions, sensitivity level, final decision — never
   the raw prompt or matched values. This is your "what happened to my
   prompt?" trail.

## Known limitations in this v1 (by design, not oversight)

- **Name detection is a heuristic**, not real NER. It flags capitalized word
  pairs and will both miss names (single first names, non-Western name
  orders) and false-positive on things like product names. This is a
  placeholder — see "Enhance" below.
- **Sensitivity classification is keyword-based.** It will miss confidential
  content that doesn't use any of the configured phrases, and can false
  positive on incidental mentions (e.g. a prompt that mentions "roadmap" in
  passing). Same tier of technique as the regex detectors — see "Enhance".
- **Entropy-based secret detection will still have false positives** on
  things like long hashes or encoded IDs that aren't actually secrets. The
  mixed-character-class check narrows this significantly but doesn't
  eliminate it — tune thresholds against your own traffic.
- **The vault is in-memory** and resets whenever the process restarts. Fine
  for a demo, not for anything real — see "Enhance" below.
- **`call_llm()` in `proxy.py` is a stub.** Wire in your actual provider call
  when ready.
- **`CanonicalPrompt`'s `task`/`context`/`constraints` fields are empty.**
  Populating them well needs an LLM-based prompt optimizer, which is
  deliberately out of scope for this version — see the design note in
  `schema.py` for why that stage must run *after* sanitization, never before.

## How to enhance incrementally

Each of these is a scoped swap — you don't need to touch the pipeline
structure to do any of them:

1. **Better NER** — replace `detect_name_heuristic` with Microsoft Presidio or
   spaCy's NER model for names, organizations, and locations. Presidio also
   ships built-in recognizers for many of the regex patterns already here, so
   this can also consolidate `detectors.py`.
2. **Real vault** — replace `InMemoryVault` with a store that has encryption
   at rest and access controls separate from your main app database (e.g. a
   dedicated table with column-level encryption, or a KMS/Vault-backed
   key-value store). Add TTL/expiry per request.
3. **Org-specific terms** — use `build_dictionary_detector()` in
   `detectors.py` to flag project codenames, internal hostnames, or employee
   ID formats. Register the result in `ALL_DETECTORS`.
4. **Wire in a real LLM call** — replace `call_llm()` in `proxy.py` with your
   provider's SDK call.
5. **Structured audit logging** — replace the `logging` calls in `guard.py`
   with writes to your logging/SIEM pipeline, keeping the same "counts and
   categories, never raw values" discipline. This becomes your compliance
   audit trail with no further changes once regulatory requirements apply.
6. **Compliance-specific rules** — when that requirement lands, it's mostly
   `policy.json` changes (e.g. adding HIPAA's 18 identifiers as entity types)
   plus a deletion path on the vault for right-to-erasure requests — not a
   rebuild.
7. **Confidence tuning** — as you see false positives/negatives in logs,
   adjust `min_confidence` in `policy.json` or per-detector confidence values
   in `detectors.py`.
