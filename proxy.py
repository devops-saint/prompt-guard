"""
proxy.py

FastAPI proxy gateway with destination-based routing:
- 'approved_enterprise_ai': Direct Ollama AI few-shot prompt compression and rewriting.
- 'approved_enterprise_ai_restricted': Deterministic masking, vaulting, and rehydration via guard.sanitize().
- 'any' (Public AI): Deterministic masking, vaulting, and rehydration via guard.sanitize().
"""

from pathlib import Path
import json
import logging
import os
import re
import time
import traceback
import urllib.request
import urllib.error

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from guard import PromptGuard
from classifier import SensitivityClassifier

logger = logging.getLogger("prompt_guard.proxy")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Enterprise Prompt Guard")
guard = PromptGuard()
classifier = SensitivityClassifier.load()

_UI_HTML_PATH = Path(__file__).parent / "ui.html"
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception processing request: %s", exc)
    traceback.print_exc()
    return JSONResponse(
        status_code=200,
        content={
            "request_id": f"err_{int(time.time() * 1000)}",
            "blocked": True,
            "block_reasons": [f"Backend Exception: {type(exc).__name__} - {str(exc)}"],
            "sensitivity_level": "ERROR",
            "token_metrics": {
                "original_tokens": 0,
                "optimized_tokens": 0,
                "tokens_saved": 0,
                "percent_reduction": 0.0,
            },
        },
    )


def count_tokens_fast(text: str, model: str = "llama3.2") -> int:
    if not text or not text.strip():
        return 0

    try:
        req = urllib.request.Request(
            f"{OLLAMA_HOST}/api/tokenize",
            data=json.dumps({"model": model, "prompt": text}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if "tokens" in data:
                return len(data["tokens"])
    except Exception:
        pass

    tokens = re.findall(r"\w+|[^\w\s]", text, re.UNICODE)
    return max(1, len(tokens))


def compute_token_metrics(original_tokens: int, optimized_tokens: int) -> dict:
    saved = original_tokens - optimized_tokens
    pct = round((saved / original_tokens * 100), 1) if original_tokens > 0 else 0.0
    return {
        "original_tokens": original_tokens,
        "optimized_tokens": optimized_tokens,
        "tokens_saved": saved,
        "percent_reduction": pct,
    }


def call_llm(sanitized_prompt: str, model: str) -> tuple[str, int]:
    if not sanitized_prompt or not sanitized_prompt.strip():
        return "[Empty prompt sent to LLM]", 0

    payload = json.dumps({
        "model": model,
        "prompt": sanitized_prompt,
        "stream": False,
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip(), int(data.get("prompt_eval_count", 0))
    except Exception as e:
        logger.error("call_llm failure: %s", e)
        return (
            f"[Ollama error at {OLLAMA_HOST}: {e}. Ensure `ollama serve` is running and `{model}` is pulled.]",
            0,
        )


def sanitize_and_optimize_with_ollama(raw_prompt: str, model: str) -> str:
    """The older Ollama few-shot compression and rewrite pipeline."""
    system_prompt = (
        "You are an automated prompt compression and data-privacy engine.\n"
        "Your task is to rewrite the input into a concise, token-efficient instruction.\n"
        "Rules:\n"
        "1. Replace personal names with [NAME].\n"
        "2. Replace phone numbers with [PHONE].\n"
        "3. Replace street/physical addresses with [ADDRESS].\n"
        "4. Replace SSNs, IDs, bank details, and secrets with [ID].\n"
        "5. Replace emails with [EMAIL].\n"
        "6. Remove all polite phrasing, filler words, and conversational fluff.\n"
        "7. Output ONLY the final rewritten text. No quotes, no markdown, no preambles."
    )

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "Rewrite: Can you please draft a formal offer letter for candidate John Smith, SSN 000-45-6789, living at 2204 Cedar Grove Blvd, Minneapolis 55401, offering base compensation of $115,000 starting on October 1st, 2026?",
            },
            {
                "role": "assistant",
                "content": "Draft offer letter: candidate [NAME], ID [ID], address [ADDRESS], base compensation $115k, start date Oct 1, 2026.",
            },
            {
                "role": "user",
                "content": f"Rewrite: {raw_prompt}",
            },
        ],
        "stream": False,
        "options": {
            "temperature": 0.0,
            "top_p": 0.1,
            "num_predict": 256,
        },
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw_output = data.get("message", {}).get("content", "").strip()

            cleaned = re.sub(r"^```[a-zA-Z]*\n?", "", raw_output)
            cleaned = re.sub(r"\n?```$", "", cleaned)
            cleaned = re.sub(r"^(Output|Rewritten|Sanitized|Result):\s*", "", cleaned, flags=re.IGNORECASE)
            cleaned = cleaned.strip().strip('"').strip("'")

            if cleaned.lower().startswith(("i'm ready", "what's the", "please provide", "as an ai")):
                return raw_prompt

            return cleaned if cleaned else raw_prompt
    except Exception as e:
        logger.warning("Ollama rewrite failed (%s). Continuing with original prompt.", e)
        return raw_prompt


@app.get("/", response_class=HTMLResponse)
def ui():
    content = _UI_HTML_PATH.read_text(encoding="utf-8")
    return HTMLResponse(
        content=content,
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


class TokenCountRequest(BaseModel):
    prompt: str
    model: str = "llama3.2"


class GuardAndCallRequest(BaseModel):
    prompt: str
    model: str = "llama3.2"
    destination: str = "any"


@app.post("/count-tokens")
def count_tokens_endpoint(req: TokenCountRequest):
    return {"tokens": count_tokens_fast(req.prompt, req.model)}


@app.post("/guard-and-call")
def guard_and_call(req: GuardAndCallRequest):
    request_id = f"req_{int(time.time() * 1000)}"
    orig_tokens = count_tokens_fast(req.prompt, req.model)

    classification = classifier.classify(req.prompt)

    # 1. Hard block for SECRET keywords across all destinations
    if classification.level == "SECRET":
        return {
            "request_id": request_id,
            "blocked": True,
            "block_reasons": [
                f"SECRET content detected ({', '.join(classification.matched_terms)}) cannot be processed"
            ],
            "sensitivity_level": classification.level,
            "token_metrics": compute_token_metrics(orig_tokens, 0),
        }

    # 2. Branch: ONLY 'approved_enterprise_ai' uses the older few-shot Ollama rewriting
    if req.destination == "approved_enterprise_ai":
        if not classification.allowed_for(req.destination, classifier.destination_policy):
            return {
                "request_id": request_id,
                "blocked": True,
                "block_reasons": [
                    f"sensitivity {classification.level} not permitted for destination '{req.destination}'"
                ],
                "sensitivity_level": classification.level,
                "token_metrics": compute_token_metrics(orig_tokens, 0),
            }

        sanitized_prompt = sanitize_and_optimize_with_ollama(req.prompt, req.model)
        opt_tokens = count_tokens_fast(sanitized_prompt, req.model)
        raw_response, _ = call_llm(sanitized_prompt, req.model)

        return {
            "request_id": request_id,
            "blocked": False,
            "sensitivity_level": classification.level,
            "entity_counts": {"OLLAMA_AI_OPTIMIZED": 1},
            "sanitized_prompt": sanitized_prompt,
            "llm_response": raw_response,
            "token_metrics": compute_token_metrics(orig_tokens, opt_tokens),
        }

    # 3. All other destinations ('any' and 'approved_enterprise_ai_restricted') route through guard.sanitize()
    else:
        sanitized_result = guard.sanitize(req.prompt, request_id=request_id, destination=req.destination)

        if sanitized_result.blocked:
            return {
                "request_id": request_id,
                "blocked": True,
                "block_reasons": sanitized_result.block_reasons,
                "sensitivity_level": classification.level,
                "token_metrics": compute_token_metrics(orig_tokens, 0),
            }

        sanitized_prompt = sanitized_result.sanitized_prompt
        opt_tokens = count_tokens_fast(sanitized_prompt, req.model)
        raw_response, _ = call_llm(sanitized_prompt, req.model)
        final_response = guard.rehydrate(raw_response)

        return {
            "request_id": request_id,
            "blocked": False,
            "sensitivity_level": classification.level,
            "entity_counts": dict(sanitized_result.entity_counts),
            "sanitized_prompt": sanitized_prompt,
            "llm_response": final_response,
            "token_metrics": compute_token_metrics(orig_tokens, opt_tokens),
        }