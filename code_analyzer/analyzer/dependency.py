"""
Dependency graph builder — walks a project tree and extracts
import relationships, function definitions, and class hierarchies.
"""
import ast
import re
from pathlib import Path
from typing import Any

IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "dist", "build"}

# ── colour palette for node types ────────────────────────────────────────────
COLORS = {
    "python":     "#4B8BBE",
    "javascript": "#F7DF1E",
    "typescript": "#3178C6",
    "html":       "#E34F26",
    "css":        "#264DE4",
    "json":       "#89D185",
    "markdown":   "#9B9B9B",
    "bash":       "#4EAA25",
    "other":      "#AAAAAA",
}

EXT_TO_LANG = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript",
    ".html": "html", ".css": "css", ".json": "json",
    ".md": "markdown", ".sh": "bash",
}


def _color(path: Path) -> str:
    lang = EXT_TO_LANG.get(path.suffix.lower(), "other")
    return COLORS.get(lang, COLORS["other"])


# ── Python import extractor ───────────────────────────────────────────────────

def _py_imports(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.append(node.module.split(".")[0])
    return imports


def _py_symbols(source: str) -> dict:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {"functions": [], "classes": [], "complexity": 0}
    functions, classes = [], []
    complexity = 1
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.append(node.name)
        elif isinstance(node, ast.AsyncFunctionDef):
            functions.append(f"async {node.name}")
        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                               ast.With, ast.Assert)):
            complexity += 1
    return {"functions": functions, "classes": classes, "complexity": complexity}


# ── JS/TS import extractor ────────────────────────────────────────────────────

_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+.*?\s+from\s+['"]([^'"]+)['"]|"""
    r"""require\s*\(\s*['"]([^'"]+)['"]\s*\))""",
    re.MULTILINE,
)


def _js_imports(source: str) -> list[str]:
    return [m.group(1) or m.group(2) for m in _JS_IMPORT_RE.finditer(source)]


def _js_symbols(source: str) -> dict:
    functions = re.findall(
        r"""(?:function\s+(\w+)|const\s+(\w+)\s*=\s*(?:async\s*)?\()""", source
    )
    classes = re.findall(r"class\s+(\w+)", source)
    complexity = 1 + len(re.findall(
        r"\b(?:if|for|while|catch|switch|&&|\|\||\?\?)\b", source
    ))
    fnames = [f[0] or f[1] for f in functions if f[0] or f[1]]
    return {"functions": fnames, "classes": classes, "complexity": complexity}


# ── main graph builder ────────────────────────────────────────────────────────

def analyze_dependencies(root: Path) -> dict[str, Any]:
    nodes: list[dict] = []
    edges: list[dict] = []
    path_to_id: dict[str, int] = {}
    node_id = 0

    all_files: list[Path] = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and not any(part in IGNORE_DIRS for part in p.parts):
            ext = p.suffix.lower()
            if ext in EXT_TO_LANG:
                all_files.append(p)

    # Build node list
    for fp in all_files:
        rel = str(fp.relative_to(root))
        path_to_id[rel] = node_id
        nodes.append({
            "id": node_id,
            "label": fp.name,
            "path": rel,
            "lang": EXT_TO_LANG.get(fp.suffix.lower(), "other"),
            "color": _color(fp),
            "size": fp.stat().st_size,
            "symbols": {},
        })
        node_id += 1

    # Extract imports → edges
    for fp in all_files:
        rel = str(fp.relative_to(root))
        src_id = path_to_id[rel]
        try:
            source = fp.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        ext = fp.suffix.lower()
        if ext == ".py":
            imports = _py_imports(source)
            nodes[src_id]["symbols"] = _py_symbols(source)
        elif ext in (".js", ".ts", ".jsx", ".tsx"):
            imports = _js_imports(source)
            nodes[src_id]["symbols"] = _js_symbols(source)
        else:
            imports = []

        nodes[src_id]["lines"] = source.count("\n") + 1

        for imp in imports:
            # Resolve relative imports to actual files in the project
            imp_clean = imp.lstrip("./")
            for other_rel, other_id in path_to_id.items():
                if other_id == src_id:
                    continue
                other_stem = Path(other_rel).stem
                if imp_clean == other_stem or other_rel.replace("/", ".").startswith(imp_clean):
                    edges.append({
                        "source": src_id,
                        "target": other_id,
                        "label": imp,
                    })
                    break

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "files": len(nodes),
            "edges": len(edges),
            "languages": list({n["lang"] for n in nodes}),
        },
    }
