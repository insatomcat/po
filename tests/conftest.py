# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Shared test setup.

The application modules rely on ``sys.path`` tweaks (top-level ``iec_data``,
``goose/`` and ``goose_listener/`` on the path) and import scapy at module
level. The tests reproduce the path layout of ``po_service.py`` and
install an inert stand-in for scapy when it is not installed, so
the pure codecs can be exercised on any machine. Nothing here sends or
captures packets.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).resolve().parent / "data"

for sub in ("", "goose", "goose_listener", "svgenerator", "svlistener_view"):
    p = str(ROOT / sub) if sub else str(ROOT)
    if p not in sys.path:
        sys.path.insert(0, p)


def _install_stub(name: str, attrs: dict[str, object]) -> None:
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    sys.modules[name] = module


if importlib.util.find_spec("scapy") is None:
    def _no_network(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("scapy stub: sending is not available in tests")

    _install_stub("scapy", {})
    _install_stub(
        "scapy.all",
        {"Dot1Q": None, "Ether": None, "Raw": None, "sendp": _no_network},
    )
