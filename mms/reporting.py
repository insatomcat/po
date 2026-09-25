# Copyright 2026 Florent Carli
# SPDX-License-Identifier: Apache-2.0

"""Report handling of the MMS service, on top of open61850.mms.

- Which report control blocks to subscribe to, and which instance.
- Data set members and their types, read from the IED.
- Text rendering for the log stream.
- VictoriaMetrics lines, kept identical to the series po has always
  written: ``mms_report_value{rpt_id, data_set, member[, component]}``.
"""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass, field
from datetime import timezone
from typing import Optional

from open61850.data import ArrayData, BitStringData, BoolData, FloatData, IECData, IntData, StructureData, UIntData
from open61850.display import format_value
from open61850.mms import DataAccessError, MmsClient, MmsError, MmsType, ObjectName, OptFlds, Report, TrgOps, rcb
from open61850 import scl
from open61850.mms.types import StructureType, label

# --- settings -----------------------------------------------------------------

TRIGGER_TOKENS = {
    "dchg": "data_change",
    "qchg": "quality_change",
    "dupd": "data_update",
    "integrity": "integrity",
    "gi": "general_interrogation",
}
DEFAULT_TRIGGERS = "integrity,gi"  # what po has always written (TrgOps 020c)

# OptFlds po has always written (067b00): the header layout Grafana series rely on.
LEGACY_OPT_FLDS = OptFlds(
    sequence_number=True, report_time_stamp=True, reason_for_inclusion=True, data_set_name=True,
    buffer_overflow=True, entry_id=True,
)


def parse_triggers(text: Optional[str]) -> TrgOps:
    """``"integrity,gi"`` -> TrgOps. Tokens: dchg, qchg, dupd, integrity, gi."""
    tokens = [t.strip().lower() for t in (text or DEFAULT_TRIGGERS).split(",") if t.strip()]
    unknown = [t for t in tokens if t not in TRIGGER_TOKENS]
    if unknown:
        raise ValueError(f"unknown trigger option(s) {unknown}; use {', '.join(TRIGGER_TOKENS)}")
    return TrgOps(**{TRIGGER_TOKENS[t]: True for t in tokens})


def rcb_settings(triggers: Optional[str], integrity_ms: int = 2000) -> rcb.RcbSettings:
    return rcb.RcbSettings(
        trg_ops=parse_triggers(triggers),
        opt_flds=LEGACY_OPT_FLDS,
        intg_pd_ms=integrity_ms,
        resv_tms=5,
        purge_buf=True,
        entry_id=bytes(8),
    )


# --- which blocks -------------------------------------------------------------


@dataclass
class RcbGroup:
    """The instances of one report control block, in preference order."""

    base: ObjectName  # domain and item without instance number
    instances: list[ObjectName]

    @property
    def name(self) -> str:
        """The block name the filter applies to: ``CB_LDPX_DQPO_DEP1``."""
        return self.base.item.rsplit("$", 1)[-1]


def groups_from_scl(ied: "scl.SclIed", domains: Optional[list[str]] = None) -> list[RcbGroup]:
    """Every report control block of an SCL IED, restricted to ``domains`` when given."""
    return [
        RcbGroup(block.base, block.instances())
        for block in ied.report_controls
        if domains is None or block.domain in domains
    ]


def groups_from_names(domain: str, names: list[str]) -> list[RcbGroup]:
    """Report control blocks found by GetNameList, grouped by instance (two-digit suffix)."""
    groups: dict[str, list[str]] = {}
    for name in sorted(n for n in names if rcb.is_rcb_name(n)):
        groups.setdefault(rcb.instance_base(name), []).append(name)
    return [RcbGroup(ObjectName(base, domain), [ObjectName(n, domain) for n in items]) for base, items in groups.items()]


def parse_rcb_filter(text: Optional[str]) -> list[str]:
    """``"CB_LDPX_*, CB_LDADD_*"`` -> patterns; empty means every block."""
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def plan_subscriptions(
    groups: list[RcbGroup],
    *,
    patterns: Optional[list[str]] = None,
    wanted: Optional[list[str]] = None,
    previous: Optional[list[str]] = None,
) -> tuple[list[list[ObjectName]], list[str]]:
    """Candidate instances per selected block, most preferred first, and what was not found.

    ``patterns`` (shell-style, ``*`` and ``?``) select blocks by name, instance
    number excluded; ``wanted`` is the older list of block names (a trailing
    instance number marks the preferred instance). With neither, every block
    is selected. Instances used before (``previous``, ``domain/item`` or bare
    item) come first, so a reconnection keeps the same RptID.
    """
    used = set(previous or [])

    def order(group: RcbGroup, preferred: Optional[str] = None) -> list[ObjectName]:
        first = [i for i in group.instances if str(i) in used or i.item in used]
        chosen = [i for i in group.instances if i.item == preferred]
        return list(dict.fromkeys(first + chosen + group.instances))

    plan: list[list[ObjectName]] = []
    missing: list[str] = []
    if wanted is not None:
        seen: set[str] = set()
        for request in wanted:
            base = rcb.instance_base(request)
            matches = [g for g in groups if g.base.item in (base, request) and str(g.base) not in seen]
            if not matches:
                if not any(g.base.item in (base, request) for g in groups):
                    missing.append(request)
                continue
            for group in matches:
                seen.add(str(group.base))
                plan.append(order(group, request))
        return plan, missing

    for pattern in patterns or []:
        if not any(fnmatch.fnmatchcase(g.name, pattern) for g in groups):
            missing.append(pattern)
    for group in groups:
        if not patterns or any(fnmatch.fnmatchcase(group.name, p) for p in patterns):
            plan.append(order(group))
    return plan, missing


# --- data sets ----------------------------------------------------------------


def member_label(name: ObjectName) -> str:
    """``BAYMMXU1$MX$A$phsA`` -> ``A.phsA``: the SCL FCDA label (doName[.daName])."""
    parts = name.item.split("$")
    return ".".join(parts[2:]) if len(parts) > 2 else name.item


@dataclass
class MemberInfo:
    name: ObjectName
    label: str
    mms_type: Optional[MmsType] = None


@dataclass
class DataSetInfo:
    reference: str
    members: list[MemberInfo] = field(default_factory=list)


def parse_reference(reference: str) -> ObjectName:
    domain, _, item = reference.partition("/")
    return ObjectName(item, domain) if item else ObjectName(domain)


def load_data_set(client: MmsClient, reference: str, fallback_labels: Optional[list[str]] = None) -> DataSetInfo:
    """Members and types of a data set, read from the IED.

    If the IED does not answer, ``fallback_labels`` (from an SCL file) name the
    members instead, without types.
    """
    try:
        names = client.get_data_set_members(parse_reference(reference))
    except MmsError:
        labels = fallback_labels or []
        return DataSetInfo(reference, [MemberInfo(ObjectName(lbl), lbl) for lbl in labels])
    members = []
    for name in names:
        try:
            mms_type: Optional[MmsType] = client.get_type(name)
        except (MmsError, DataAccessError):
            mms_type = None
        members.append(MemberInfo(name, member_label(name), mms_type))
    return DataSetInfo(reference, members)


# --- text ---------------------------------------------------------------------


def format_report(report: Report, data_set: Optional[DataSetInfo]) -> list[str]:
    lines = [
        f"REPORT {report.rpt_id} seq={report.seq_num} time={report.time_of_entry} "
        f"ds={report.data_set} bufOvfl={report.buf_ovfl}"
    ]
    members = data_set.members if data_set else []
    for entry in report.entries:
        member = members[entry.index] if entry.index < len(members) else None
        name = str(member.name) if member else f"[{entry.index}]"
        reasons = [k for k, v in vars(entry.reason).items() if v] if entry.reason else []
        lines.append(f"  {name} ({','.join(reasons)})")
        value = entry.value
        if isinstance(value, DataAccessError):  # a server may send one in place of a member's value
            lines.append(f"      access error: {value}")
        else:
            lines.append(f"      {format_value(value, member.mms_type if member else None)}")
    return lines


# --- VictoriaMetrics ----------------------------------------------------------

_TS_MS_MIN_2000 = 946684800000
_LEGACY_HEADER_ENTRIES = 8  # RptID..Inclusion with po's OptFlds


def _escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _numbers(value: IECData) -> list[float]:
    """Numeric leaves in order; booleans count as 0/1, strings, bit strings and times are skipped."""
    if isinstance(value, BoolData):
        return [1.0 if value.value else 0.0]
    if isinstance(value, (IntData, UIntData, FloatData)):
        return [float(value.value)]
    if isinstance(value, StructureData):
        return [n for m in value.members for n in _numbers(m)]
    if isinstance(value, ArrayData):
        return [n for e in value.elements for n in _numbers(e)]
    return []


def _numeric_paths(value: IECData, mms_type: Optional[MmsType]) -> list[str]:
    return [path for path, leaf in label(value, mms_type) if _numbers(leaf)]


def _dbpos_state(value: BitStringData) -> float:
    first = value.value[0] if value.value else 0
    if first & 0x80:
        return 2.0  # on / closed
    if first & 0x40:
        return 1.0  # off / open
    return 0.0  # intermediate


def _pos_components(value: IECData, mms_type: Optional[MmsType]) -> dict[str, float]:
    """state and orCat of a DPC Pos, as po has always exported them."""
    comps: dict[str, float] = {}
    leaves = dict(label(value, mms_type))
    if isinstance(mms_type, StructureType):
        or_cat = leaves.get("origin.orCat")
        st_val = leaves.get("stVal")
    elif isinstance(value, StructureData) and value.members and isinstance(value.members[0], StructureData):
        origin = value.members[0].members
        or_cat = origin[0] if origin else None
        st_val = value.members[1] if len(value.members) > 1 else None
    else:
        return comps
    if isinstance(or_cat, (IntData, UIntData)):
        comps["orCat"] = float(or_cat.value)
    if isinstance(st_val, BitStringData):
        comps["state"] = _dbpos_state(st_val)
    return comps


def _default_components(member: str, count: int) -> Optional[list[str]]:
    if count == 2 and any(p in member for p in ("phsA", "phsB", "phsC")):
        return ["mag", "ang"]
    return None


def report_to_lines(report: Report, data_set: Optional[DataSetInfo], now: Optional[float] = None) -> list[str]:
    """Prometheus lines for one report, compatible with po's historical series."""
    ts_ms = int((now if now is not None else time.time()) * 1000)
    if report.time_of_entry is not None:
        toe = report.time_of_entry
        toe_ms = int((toe if toe.tzinfo else toe.replace(tzinfo=timezone.utc)).timestamp() * 1000)
        if toe_ms >= _TS_MS_MIN_2000:
            ts_ms = toe_ms
    base = f'rpt_id="{_escape(report.rpt_id)}",data_set="{_escape(report.data_set or "unknown")}"'

    def line(member: str, number: float, component: Optional[str] = None) -> str:
        comp = f',component="{_escape(component)}"' if component is not None else ""
        return f'mms_report_value{{{base},member="{_escape(member)}"{comp}}} {number} {ts_ms}'

    lines: list[str] = []
    if report.seq_num is not None:
        lines.append(line("SeqNum", float(report.seq_num)))
    if report.buf_ovfl is not None:
        lines.append(line("BufOvfl", 1.0 if report.buf_ovfl else 0.0))

    members = data_set.members if data_set else []
    for entry in report.entries:
        info = members[entry.index] if entry.index < len(members) else None
        member = info.label if info else f"entry_{_LEGACY_HEADER_ENTRIES + entry.index}"
        mms_type = info.mms_type if info else None
        value = entry.value
        if isinstance(value, DataAccessError):
            continue

        if member.startswith("Pos"):
            comps = _pos_components(value, mms_type)
            if comps:
                lines += [line(member, num, name) for name, num in comps.items()]
                continue

        # The measured value is the first component of a (value, q, t...) structure.
        part, part_type = value, mms_type
        if isinstance(value, StructureData) and len(value.members) >= 3:
            part = value.members[0]
            part_type = mms_type.components[0][1] if isinstance(mms_type, StructureType) and mms_type.components else None
        nums = _numbers(part)
        if not nums:
            continue
        if len(nums) == 1:
            lines.append(line(member, nums[0]))
            continue
        names: Optional[list[str]] = None
        if part_type is not None:
            paths = _numeric_paths(part, part_type)
            heads = [p.split(".", 1)[0] for p in paths]
            names = heads if len(set(heads)) == len(heads) else paths
        if names is None or len(names) != len(nums):
            names = _default_components(member, len(nums)) or [str(i) for i in range(len(nums))]
        lines += [line(member, num, name) for name, num in zip(names, nums)]
    return lines

