# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The installed open61850 is at least the version requirements.txt asks for.

Without this check the suite runs against whatever version is installed
and can pass on a library older than the one PO is written for.
"""

from __future__ import annotations

import importlib.metadata
import re

from conftest import ROOT


def _version(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", text)[:3])


def test_installed_open61850_is_at_least_the_minimum() -> None:
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    match = re.search(r"^open61850(?:\[[^\]]*\])?>=(\S+)", text, re.MULTILINE)
    assert match, "requirements.txt does not give open61850 a minimum with >="
    installed = importlib.metadata.version("open61850")
    assert _version(installed) >= _version(match.group(1)), (
        f"open61850 {installed} is installed, requirements.txt asks for "
        f"{match.group(1)} or later: run pip install -U -r requirements.txt"
    )
