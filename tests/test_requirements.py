# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""The installed open61850 is the one requirements.txt pins.

Without this check the suite runs against whatever version is installed
and can pass on a library older than the one PO is written for.
"""

from __future__ import annotations

import importlib.metadata
import re

from conftest import ROOT


def test_installed_open61850_matches_the_pin() -> None:
    text = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    match = re.search(r"^open61850(?:\[[^\]]*\])?==(\S+)", text, re.MULTILINE)
    assert match, "requirements.txt does not pin open61850 with =="
    installed = importlib.metadata.version("open61850")
    assert installed == match.group(1), (
        f"open61850 {installed} is installed, requirements.txt pins "
        f"{match.group(1)}: run pip install -r requirements.txt"
    )
