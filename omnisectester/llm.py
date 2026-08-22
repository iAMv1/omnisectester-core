"""Optional LLM analysis layer. Zero-cost deterministic default.

Activation requires ALL of:
  - CLI flag --llm
  - env OMNI_LLM_KEY (API key)
  - env OMNI_LLM_MODEL (e.g. "openai/gpt-4o-mini")

Speaks the OpenAI-compatible /chat/completions shape against
OMNI_LLM_BASE (default https://api.openai.com/v1). Deterministic scans
are never mutated: LLM output lands under result["llm_analysis"] only.
"""

import json
import os
import urllib.error
import urllib.request

DEFAULT_BASE = "https://api.openai.com/v1"

SYSTEM_PROMPT = (
    "You are a senior penetration tester reviewing a completed "
    "deterministic web-surface scan. Given the JSON below: "
    "(1) propose plausible attack-chain hypotheses combining findings, "
    "(2) list surface areas the scanner likely missed, "
    "(3) write a 5-line executive summary. Be concrete; no filler."
)


def available() -> bool:
    return bool(os.environ.get("OMNI_LLM_KEY") and os.environ.get("OMNI_LLM_MODEL"))


def analyze(result: dict, timeout: float = 30.0) -> dict:
    """Send compact scan facts for narrative/chaining analysis."""
    key = os.environ.get("OMNI_LLM_KEY")
    model = os.environ.get("OMNI_LLM_MODEL")
    base = os.environ.get("OMNI_LLM_BASE", DEFAULT_BASE)
    if not key or not model:
        return {"ok": False, "error": "OMNI_LLM_KEY/OMNI_LLM_MODEL not set"}

    compact = {
        "target": result.get("target"),
        "surface": result.get("surface"),
        "stats": result.get("stats"),
        "findings": [{"id": f.get("id"), "severity": f.get("severity"),
                      "title": f.get("title"), "cwe": f.get("cwe")}
                     for f in result.get("findings", [])],
    }
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(compact)},
        ],
        "temperature": 0.2,
    }).encode()

    req = urllib.request.Request(
        f"{base.rstrip('/')}/chat/completions", data=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {key}"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        text = data["choices"][0]["message"]["content"]
        return {"ok": True, "model": model, "analysis": text}
    except urllib.error.HTTPError as exc:
        detail = exc.read(200).decode(errors="replace")
        return {"ok": False, "error": f"LLM HTTP {exc.code}: {detail}"}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
