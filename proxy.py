"""
proxy.py

A minimal HTTP proxy so apps stop calling LLM providers directly and route
through this guard instead. Run with:

    uvicorn proxy:app --reload --port 8080

Endpoints:
  GET  /               -> browser UI, calls the endpoints below directly
  POST /sanitize        { "prompt": "..." }              -> sanitized prompt + report
  POST /rehydrate        { "text": "..." }                 -> restores any tokens
  POST /guard-and-call    { "prompt": "...", "model": "..." } -> sanitizes, calls the
                            LLM provider (stubbed below), rehydrates the response

The /guard-and-call path is the real integration point: replace `call_llm()`
with your actual provider call once you're ready to wire this into production.
Keeping sanitize/rehydrate as separate endpoints also lets you call the guard
from a language other than Python (any app can hit this over HTTP).
"""

from pathlib import Path
import json
import os
import urllib.request
import urllib.error

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from guard import PromptGuard

app = FastAPI(title="Enterprise Prompt Guard")
guard = PromptGuard()  # one shared instance -> one shared in-memory vault for the demo

_UI_HTML = (Path(__file__).parent / "ui.html").read_text()

# Ollama runs locally and exposes its own HTTP API — no API key, nothing
# leaves the machine. Override via the OLLAMA_HOST env var if it's running
# elsewhere on your network (still keep it inside your own boundary).
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")


@app.get("/", response_class=HTMLResponse)
def ui():
    """
    Serves a minimal browser console for this deployment. It calls
    /guard-and-call directly — this is a real client of the API below, not a
    separate simulation. Replace with your own frontend once you have one;
    this exists so a deployed instance is usable in a browser out of the box.
    """
    return _UI_HTML


class SanitizeRequest(BaseModel):
    prompt: str
    request_id: str | None = None
    # "any" only satisfies PUBLIC-level content. Pass "approved_enterprise_ai"
    # or "approved_enterprise_ai_restricted" once you've defined real
    # destinations in classification_policy.json for your approved models.
    destination: str = "any"


class RehydrateRequest(BaseModel):
    text: str


class GuardAndCallRequest(BaseModel):
    prompt: str
    model: str = "llama3.2"  # must already be pulled: `ollama pull llama3.2`
    destination: str = "any"


def call_llm(sanitized_prompt: str, model: str) -> str:
    """
    Calls a locally running Ollama instance — the model runs on your own
    machine, so the sanitized prompt never leaves your infrastructure, not
    even to a cloud LLM provider. Requires Ollama running (`ollama serve`,
    usually automatic after install) and the model pulled ahead of time
    (`ollama pull llama3.2` or whichever model you pass in `model`).

    To use a cloud provider instead, replace this function's body with that
    provider's SDK call — everything upstream (detection, classification,
    policy, tokenization) stays exactly the same either way.
    """
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
            return data.get("response", "").strip()
    except urllib.error.URLError as e:
        return (
            f"[Ollama unreachable at {OLLAMA_HOST}: {e}. "
            f"Is `ollama serve` running, and has `{model}` been pulled?]"
        )


@app.post("/sanitize")
def sanitize(req: SanitizeRequest):
    result = guard.sanitize(
        req.prompt, request_id=req.request_id or "", destination=req.destination
    )
    return {
        "request_id": result.request_id,
        "blocked": result.blocked,
        "block_reasons": result.block_reasons,
        "sensitivity_level": result.sensitivity_level,
        "sanitized_prompt": result.sanitized_prompt,
        "entity_counts": dict(result.entity_counts),
    }


@app.post("/rehydrate")
def rehydrate(req: RehydrateRequest):
    return {"text": guard.rehydrate(req.text)}


@app.post("/guard-and-call")
def guard_and_call(req: GuardAndCallRequest):
    result = guard.sanitize(req.prompt, destination=req.destination)
    if result.blocked:
        return {
            "request_id": result.request_id,
            "blocked": True,
            "block_reasons": result.block_reasons,
            "sensitivity_level": result.sensitivity_level,
        }
    raw_response = call_llm(result.sanitized_prompt, req.model)
    final_response = guard.rehydrate(raw_response)
    return {
        "request_id": result.request_id,
        "blocked": False,
        "sensitivity_level": result.sensitivity_level,
        "entity_counts": dict(result.entity_counts),
        "sanitized_prompt": result.sanitized_prompt,
        "llm_response": final_response,
        "canonical_prompt": result.canonical_prompt.to_json() if result.canonical_prompt else None,
    }
