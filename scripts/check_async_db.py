#!/usr/bin/env python3
"""AST guard: blocking DB calls must not run inside ``async def`` handlers.

Background: the GSP routers previously declared ``async def`` endpoints that
performed *synchronous* SQLAlchemy calls (``db.query`` / ``db.commit`` / ...).
FastAPI runs such handlers on the event loop, so every DB round-trip blocked
the whole process (including the ``/health/ready`` probe).  Handlers with no
``await`` are now plain ``def`` (FastAPI moves them to a threadpool).

This script fails the build if a new ``async def`` containing synchronous DB
calls is introduced, or if an ``@router`` endpoint is declared ``async def``
while its body never awaits anything (it should be plain ``def``).  Warnings
(async/sync mixing, never-awaiting async endpoints) are treated as failures
too: once code has been migrated to plain ``def`` / threadpool helpers, any
regression must turn CI red instead of degrading to an advisory note.

Usage:
    python scripts/check_async_db.py                 # scan app/gsp
    python scripts/check_async_db.py app/legacy.py   # scan extra file(s)
Exit code 0 = clean; 1 = violations found (failures or warnings).
"""

from __future__ import annotations

import ast
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

DB_ATTRS = {
    "query", "commit", "add", "execute", "flush", "rollback", "delete", "refresh",
    "add_all", "bulk_save_objects",
}
ROUTER_METHODS = {"get", "post", "put", "delete", "patch"}


def _iter_default_glob() -> list[pathlib.Path]:
    """Scan every FastAPI route file: all of app/ (gsp routers, legacy.py,
    application.py) plus integration_router and main.  async def handlers that
    call synchronous SQLAlchemy block the event loop, so cover the whole app."""
    paths = list((ROOT / "app").rglob("*.py"))
    for extra in ("main.py",):
        p = ROOT / extra
        if p.exists():
            paths.append(p)
    return sorted(paths)


def analyse(source: str, path: str) -> list[str]:
    findings: list[str] = []
    tree = ast.parse(source, filename=path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        body_nodes = [n for n in ast.walk(node)]
        has_await = any(isinstance(n, ast.Await) for n in body_nodes)
        db_calls = {
            (n.lineno, n.attr)
            for n in body_nodes
            if isinstance(n, ast.Attribute)
            and n.attr in DB_ATTRS
            and isinstance(n.value, ast.Name)
            and n.value.id == "db"
        }
        is_router_ep = any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name)
            and d.func.value.id == "router"
            and d.func.attr in ROUTER_METHODS
            for d in node.decorator_list
        )
        if db_calls and not has_await:
            loc = ", ".join(f"L{ln}:{attr}" for ln, attr in sorted(db_calls))
            findings.append(
                f"[FAIL] {path}:{node.lineno} async def {node.name} calls sync DB "
                f"({loc}) with no await - use plain 'def' so FastAPI runs it in a threadpool"
            )
        elif db_calls and has_await:
            loc = ", ".join(f"L{ln}:{attr}" for ln, attr in sorted(db_calls))
            findings.append(
                f"[WARN] {path}:{node.lineno} async def {node.name} mixes await with "
                f"sync DB calls ({loc}) - refactor to async SQLAlchemy or plain def"
            )
        elif is_router_ep and not has_await and not db_calls:
            # endpoint declared async without awaiting anything and without DB;
            # it still occupies the event loop for its whole body -> prefer def
            findings.append(
                f"[WARN] {path}:{node.lineno} @router endpoint {node.name} is "
                "'async def' but never awaits - declare it as plain 'def'"
            )
    return findings


def main() -> int:
    paths: list[pathlib.Path] = []
    for raw in sys.argv[1:]:
        paths.append(pathlib.Path(raw).resolve())
    if not paths:
        paths = _iter_default_glob()

    failures: list[str] = []
    warnings: list[str] = []
    for p in paths:
        if not p.exists():
            failures.append(f"[FAIL] {p}: file not found")
            continue
        for finding in analyse(p.read_text(encoding="utf-8-sig"), str(p.relative_to(ROOT))):
            (warnings if finding.startswith("[WARN]") else failures).append(finding)

    for line in warnings:
        print(f"  [WARN] {line[6:]}")
    for line in failures:
        print(line)
    print(f"\ncheck_async_db: {len(failures)} failure(s), {len(warnings)} warning(s).")
    # Fail-closed: warnings are regressions of the same class (sync DB work or
    # blocking bodies on the event loop) and must also turn CI red.
    return 1 if (failures or warnings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
