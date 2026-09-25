# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""No function rebinds `log` in a module whose logger is `log` (it would shadow it)."""

from __future__ import annotations

import ast

from conftest import ROOT


def test_no_function_shadows_the_module_logger() -> None:
    offenders = []
    for path in ROOT.rglob("*.py"):
        if any(part in {".git", "tests", "venv", ".venv"} for part in path.parts):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not any(isinstance(n, ast.Assign) and any(getattr(t, "id", None) == "log" for t in n.targets) for n in tree.body):
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for node in ast.walk(fn):
                names: list[str] = []
                if isinstance(node, ast.Assign):
                    names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.With):
                    names = [i.optional_vars.id for i in node.items if isinstance(i.optional_vars, ast.Name)]
                elif isinstance(node, ast.For) and isinstance(node.target, ast.Name):
                    names = [node.target.id]
                elif isinstance(node, ast.arg):
                    names = [node.arg]
                if "log" in names:
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno} in {fn.name}")
    assert not offenders, offenders
