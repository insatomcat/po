from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, List, Optional

from .types import GooseFrame


@dataclass
class GooseStatistics:
    total_frames: int = 0
    per_src: Counter = field(default_factory=Counter)
    per_app_id: Counter = field(default_factory=Counter)


class GooseAnalyzer:
    """Fonctions d'analyse simple sur des trames GOOSE."""

    def __init__(self) -> None:
        self.frames: List[GooseFrame] = []

    def add_frame(self, frame: GooseFrame) -> None:
        self.frames.append(frame)

    def extend(self, frames: Iterable[GooseFrame]) -> None:
        self.frames.extend(frames)

    def stats(self) -> GooseStatistics:
        s = GooseStatistics()
        s.total_frames = len(self.frames)
        for f in self.frames:
            s.per_src[f.src_mac] += 1
            s.per_app_id[f.app_id] += 1
        return s

    def pretty_print(self, limit: Optional[int] = None) -> str:
        lines: List[str] = []
        frames = self.frames if limit is None else self.frames[:limit]

        for f in frames:
            pdu = f.pdu
            ts: Optional[datetime] = pdu.timestamp if pdu else None  # type: ignore[assignment]
            ts_str = ts.isoformat() if ts else "-"
            if pdu:
                line = (
                    f"[{ts_str}] {f.src_mac} -> {f.dst_mac} "
                    f"APPID=0x{f.app_id:04X} gocbRef={pdu.gocb_ref} "
                    f"stNum={pdu.st_num} sqNum={pdu.sq_num}"
                )
            else:
                line = (
                    f"[{ts_str}] {f.src_mac} -> {f.dst_mac} "
                    f"APPID=0x{f.app_id:04X} (PDU non décodé)"
                )
            lines.append(line)

        return "\n".join(lines)

