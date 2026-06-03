"""
Code Analysis Viewer — backend server
Flask app exposing REST + WebSocket endpoints for file browsing,
dependency analysis, and AI-assisted code review.
"""
import os
import json
import ast
import re
import asyncio
import threading
from pathlib import Path
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import importlib.util

app = Flask(__name__, static_folder="static")
CORS(app)

# ── helpers ──────────────────────────────────────────────────────────────────

def _safe_path(base: str, rel: str) -> Path | None:
    base_p = Path(base).resolve()
    target = (base_p / rel).resolve()
    if not str(target).startswith(str(base_p)):
        return None
    return target


def _language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".jsx": "jsx", ".tsx": "tsx", ".html": "html", ".css": "css",
        ".json": "json", ".md": "markdown", ".sh": "bash",
        ".yaml": "yaml", ".yml": "yaml", ".toml": "toml",
        ".rs": "rust", ".go": "go", ".c": "c", ".cpp": "cpp",
        ".java": "java", ".rb": "ruby", ".php": "php",
    }.get(ext, "plaintext")


# ── file tree ─────────────────────────────────────────────────────────────────

IGNORE = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    ".idea", ".vscode", "dist", "build", ".next", ".cache",
    "*.pyc", "*.pyo", "*.egg-info",
}


def _build_tree(root: Path, rel: Path = Path(".")) -> dict:
    full = root / rel
    name = full.name or str(root)
    if full.is_file():
        return {"type": "file", "name": name, "path": str(rel), "lang": _language(name)}
    if full.is_dir():
        children = []
        try:
            for child in sorted(full.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
                if child.name in IGNORE or child.name.startswith("."):
                    continue
                children.append(_build_tree(root, rel / child.name))
        except PermissionError:
            pass
        return {"type": "dir", "name": name, "path": str(rel), "children": children}
    return {"type": "unknown", "name": name, "path": str(rel)}


@app.route("/api/tree")
def api_tree():
    root = request.args.get("root", ".")
    try:
        tree = _build_tree(Path(root).resolve())
        return jsonify(tree)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# ── file content ──────────────────────────────────────────────────────────────

@app.route("/api/file")
def api_file():
    root = request.args.get("root", ".")
    path = request.args.get("path", "")
    target = _safe_path(root, path)
    if not target or not target.is_file():
        return jsonify({"error": "not found"}), 404
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
        return jsonify({
            "path": path,
            "content": content,
            "lang": _language(path),
            "lines": content.count("\n") + 1,
            "size": target.stat().st_size,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── dependency analysis ───────────────────────────────────────────────────────

from analyzer.dependency import analyze_dependencies

@app.route("/api/deps")
def api_deps():
    root = request.args.get("root", ".")
    try:
        graph = analyze_dependencies(Path(root).resolve())
        return jsonify(graph)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── AI analysis ───────────────────────────────────────────────────────────────

from analyzer.ai_client import review_code, PROVIDERS

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(force=True)
    code = data.get("code", "")
    lang = data.get("lang", "python")
    provider = data.get("provider", "claude")
    api_key = data.get("api_key", "")
    model = data.get("model", "")
    base_url = data.get("base_url", "")
    mode = data.get("mode", "review")  # review | fix | explain | security

    if not code.strip():
        return jsonify({"error": "no code provided"}), 400

    result = review_code(
        code=code, lang=lang, provider=provider,
        api_key=api_key, model=model, base_url=base_url, mode=mode
    )
    return jsonify(result)


@app.route("/api/providers")
def api_providers():
    return jsonify(PROVIDERS)


# ── static frontend ───────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)


if __name__ == "__main__":
    print("Code Analysis Viewer → http://localhost:5050")
    app.run(host="0.0.0.0", port=5050, debug=False)
