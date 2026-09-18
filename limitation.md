
# L1 Deterministic Engine: Architecture & Scope Document

## 1. Executive Summary

The Level-1 (L1) Engine provides deterministic, sub-millisecond data loss prevention (DLP) and PII detection. Operating with zero external dependencies, L1 enforces strict mathematical checksums, exact pattern matches, and structural regular expressions directly on normalized text strings.

## 2. What L1 Covers

| Category | Entities Covered | Detection & Verification Mechanism |
| --- | --- | --- |
| **Anti-Evasion Normalization** | Unicode Homoglyphs, Zero-Width Characters | Unicode NFKC decomposition; strips `\u200B-\u200D`, `\uFEFF`, and bidirectional control tags. |
| **Payment Cards** | Visa, Mastercard, Amex, Discover, Diners Club | 13–19 digit format matching + **Luhn Algorithm (mod-10)** checksum verification. Skips mock sequences (`4242...`). |
| **Government IDs** | Indian Aadhaar | 12-digit format check + **Verhoeff Algorithm** validation (dihedral group $D_5$ permutation table). |
|  | Indian PAN Card | Strict structure: 5 alphabetic characters, 4 digits, 1 alphabetic character (`[A-Z]{5}[0-9]{4}[A-Z]`). |
|  | US Social Security Number (SSN) | Strict SSA area, group, and serial rules (rejects `000`, `666`, `900–999` areas, `00` groups, `0000` serials). |
| **Banking** | International Bank Account Numbers (IBAN) | Country-code format validation + **ISO 7064 Mod 97-10** algorithmic checksum check. |
| **Telecommunications** | Phone Numbers (Global & Local) | E.164 formats, parenthesis notation, grouped spaces/dashes, and unformatted 10–15 digit sequences. |
| **Electronic Mail** | Standard Email Addresses | RFC 5322 pattern extraction. |
| **Networking** | IPv4 & IPv6 Addresses | Regex candidate extraction followed by strict validation via Python's `ipaddress` library. Skips RFC 5737 documentation ranges. |
| **Secrets & Credentials** | Private Keys (PEM blocks) | Exact multiline matches for RSA, EC, DSA, and OpenSSH private key envelopes. |
|  | Database Connection Strings | Full URI matching capturing credentials across `postgres`, `mysql`, `mongodb`, and `redis`. |
|  | Known Cloud & API Tokens | Fixed prefixes: OpenAI (`sk-`, `sk-proj-`), AWS (`AKIA...`), GitHub (`ghp_...`), Google (`AIza...`), Slack (`xox...`), JWTs. |
|  | Unmodeled Tokens | Character-level **Shannon Entropy** calculation ($H \ge 3.6$) combined with mixed-character-class constraints. |
| **Contextual Names** | Single & Lowercase Names | Deterministic regex matching on immediate structural preambles: *"name is X"*, *"call me X"*, or *"X phone number is"*. |

---

## 3. What L1 Does NOT Cover

L1 deliberately excludes the following categories:

* **Arbitrary, Context-Free Proper Names:** Single-word capitalized or lowercase names appearing without an introductory trigger (e.g., *"Jordan went to the meeting with Paris"*).
* **Company & Organization Names:** Recognizing entities like *"Stripe"*, *"Alphabet"*, or *"Acme Corp"* when they appear as normal words in running prose.
* **Transliterated & Non-English Phrases:** Non-English semantic triggers (e.g., Hinglish *"mera naam X hai"*, German *"ich heisse X"*).
* **Phonetic & Leet-Speak Names:** Obfuscated, misspelled, or phonetically written personal names (e.g., *"Ayush"*, *"Aayuuush"*, *"J0hn"*).
* **Quasi-Identifiers & The Mosaic Effect:** Correlation of isolated attributes across multiple turns that collectively identify an individual (e.g., Job Title + Zip Code + Year of Birth).
* **Unstructured Physical Addresses:** Multiline street addresses without structured markers (e.g., *"Flat 402, Sunshine Apartments, MG Road"*).
* **Multimodal Assets:** Embedded text in raster images (PNG, JPEG), scanned PDF invoices, or raw audio waveforms.

---

## 4. Why These Exclusions Exist (The Technical Trade-Offs)

Understanding why L1 stops here is fundamental to systems design and the Chomsky hierarchy of languages:

### The Chomsky Hierarchy Boundary

L1 operates as a **Deterministic Finite Automaton (DFA)**. DFAs excel at Regular Languages ($Type\text{-}3$)—patterns that can be defined by state transitions without memory (such as fixed digit lengths, prefixes, and mathematical checksums).

Human language, syntax, and entity semantics belong to Context-Free ($Type\text{-}2$) and Context-Sensitive ($Type\text{-}1$) grammars. A DFA cannot answer the question: *"Is 'Amazon' referring to a rainforest, a retail company, or a Greek warrior?"* Answering that requires semantic attention heads (transformers) that evaluate surrounding context matrices.

### The False Positive Paradox in Pure Regex

If a deterministic regex is constructed to catch all single names by matching any capitalized or lowercase word, it matches standard common nouns (e.g., *"The"*, *"Bill"*, *"Will"*, *"May"*).

* **If you loosen the rules:** Standard user prompts are corrupted by aggressive over-redaction, rendering the downstream LLM incapable of understanding basic sentences.
* **If you tighten the rules:** Names without strict contextual markers slip past.

### Algorithmic Scope vs. Model Inference

Mathematical checksums (Luhn, Verhoeff, Mod-97) are exact: a string either satisfies the equation or it does not. Names, organizations, and addresses possess no mathematical invariants. They can only be caught through:

1. **L2 (Statistical Token Classification):** Quantized, lightweight NER models (spaCy, GLiNER) that assign token probabilities based on surrounding grammatical structure (10–25 ms).
2. **L3 (Semantic LLM Judges):** Specialized LLMs that evaluate semantic context and intent across conversational memory (150–300 ms).

L1 handles deterministic, mathematically verifiable patterns at line-speed ($<1\text{ ms}$ latency), leaving semantic interpretation to downstream layers.