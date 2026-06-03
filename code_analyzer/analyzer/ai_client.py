"""
AI client — unified interface for Claude (Anthropic), OpenAI/GPT, and Ollama.
Each provider returns the same response shape:
  { issues, fixes, explanation, score, raw }
"""
import json
import re
from typing import Any

PROVIDERS = {
    "claude": {
        "name": "Claude (Anthropic)",
        "models": [
            "claude-sonnet-4-6",
            "claude-opus-4-8",
            "claude-haiku-4-5-20251001",
        ],
        "needs_key": True,
        "base_url": "https://api.anthropic.com",
    },
    "openai": {
        "name": "GPT (OpenAI)",
        "models": ["gpt-4o", "gpt-4o-mini", "o1-mini"],
        "needs_key": True,
        "base_url": "https://api.openai.com/v1",
    },
    "ollama": {
        "name": "Ollama (local)",
        "models": ["llama3", "codellama", "deepseek-coder", "mistral"],
        "needs_key": False,
        "base_url": "http://localhost:11434",
    },
}

# ── prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = (
    "You are an expert software engineer performing production-grade code review. "
    "Return ONLY valid JSON with this exact schema:\n"
    "{\n"
    '  "score": <int 0-100>,\n'
    '  "summary": "<one sentence>",\n'
    '  "issues": [ { "line": <int|null>, "severity": "critical|high|medium|low", '
    '"type": "<bug|security|perf|style|logic>", "message": "<description>", '
    '"fix": "<code snippet or instruction>" } ],\n'
    '  "explanation": "<plain-text explanation of the code>"\n'
    "}"
)

MODE_INSTRUCTIONS = {
    "review": "Review this code for bugs, security issues, performance problems, and style violations.",
    "fix":    "Find and fix all bugs, security vulnerabilities, and production-blocking issues. Show corrected code.",
    "explain": "Explain what this code does, its architecture, data flow, and design patterns used.",
    "security": "Perform a security audit: check for injection, auth flaws, insecure deserialization, secrets exposure, OWASP Top 10.",
}


def _build_prompt(code: str, lang: str, mode: str) -> str:
    instruction = MODE_INSTRUCTIONS.get(mode, MODE_INSTRUCTIONS["review"])
    return f"{instruction}\n\nLanguage: {lang}\n\n```{lang}\n{code}\n```"


def _parse_response(text: str) -> dict[str, Any]:
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return {
        "score": 0,
        "summary": "Could not parse AI response.",
        "issues": [],
        "explanation": text,
        "raw": text,
    }


# ── Claude ────────────────────────────────────────────────────────────────────

def _call_claude(code: str, lang: str, mode: str, api_key: str, model: str) -> dict:
    try:
        import anthropic
    except ImportError:
        return {"error": "anthropic package not installed. Run: pip install anthropic"}

    model = model or "claude-sonnet-4-6"
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _build_prompt(code, lang, mode)}],
    )
    text = message.content[0].text
    result = _parse_response(text)
    result["provider"] = "claude"
    result["model"] = model
    return result


# ── OpenAI / GPT ──────────────────────────────────────────────────────────────

def _call_openai(code: str, lang: str, mode: str, api_key: str, model: str, base_url: str) -> dict:
    try:
        from openai import OpenAI
    except ImportError:
        return {"error": "openai package not installed. Run: pip install openai"}

    model = model or "gpt-4o"
    client = OpenAI(api_key=api_key, base_url=base_url or None)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _build_prompt(code, lang, mode)},
        ],
        max_tokens=4096,
        response_format={"type": "json_object"},
    )
    text = response.choices[0].message.content
    result = _parse_response(text)
    result["provider"] = "openai"
    result["model"] = model
    return result


# ── Ollama (local) ────────────────────────────────────────────────────────────

def _call_ollama(code: str, lang: str, mode: str, model: str, base_url: str) -> dict:
    import urllib.request

    model = model or "codellama"
    base_url = (base_url or "http://localhost:11434").rstrip("/")
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": _build_prompt(code, lang, mode)},
        ],
        "stream": False,
    }).encode()

    req = urllib.request.Request(
        f"{base_url}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        text = data.get("message", {}).get("content", "")
        result = _parse_response(text)
        result["provider"] = "ollama"
        result["model"] = model
        return result
    except Exception as e:
        return {"error": f"Ollama unreachable: {e}"}


# ── public entry point ────────────────────────────────────────────────────────

def review_code(
    code: str,
    lang: str = "python",
    provider: str = "claude",
    api_key: str = "",
    model: str = "",
    base_url: str = "",
    mode: str = "review",
) -> dict[str, Any]:
    try:
        if provider == "claude":
            if not api_key:
                return {"error": "Claude API key required"}
            return _call_claude(code, lang, mode, api_key, model)
        elif provider == "openai":
            if not api_key:
                return {"error": "OpenAI API key required"}
            return _call_openai(code, lang, mode, api_key, model, base_url)
        elif provider == "ollama":
            return _call_ollama(code, lang, mode, model, base_url)
        else:
            return {"error": f"Unknown provider: {provider}"}
    except Exception as e:
        return {"error": str(e)}
