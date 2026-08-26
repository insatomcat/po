#!/usr/bin/env python3
"""Opérations exécutées sur le nœud cible (localement ou via SSH stdin).

stdlib uniquement. Entrée : argv[1]=op, argv[2]=JSON ou base64(JSON).
Sortie : un objet JSON sur stdout.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

PID_FILE = Path("/tmp/po-stress-ng.pid")
LOG_FILE = Path("/tmp/po-stress-ng.log")
SPEC_FILE = Path("/tmp/po-stress-ng.spec.json")
PERF_FILE = Path("/tmp/po-stress-perf.csv")


def parse_cpu_list(raw: str | None) -> list[int]:
    text = (raw or "").strip()
    if not text or text in (".", "n/a", "N/A"):
        return []
    out: set[int] = set()
    for part in text.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            out.update(range(lo, hi + 1))
        else:
            try:
                out.add(int(token))
            except ValueError:
                continue
    return sorted(out)


def _read_text(path: str | Path) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _cmdline_value(key: str) -> str:
    cmdline = _read_text("/proc/cmdline")
    match = re.search(rf"(?:^|\s){re.escape(key)}=(\S+)", cmdline)
    return match.group(1) if match else ""


def _online_cpus() -> list[int]:
    listed = parse_cpu_list(_read_text("/sys/devices/system/cpu/online"))
    if listed:
        return listed
    n = os.cpu_count() or 1
    return list(range(n))


def _proc_stat_counters(cpu_ids: list[int]) -> dict[int, tuple[int, int]]:
    """idle, total par CPU depuis /proc/stat."""
    wanted = set(cpu_ids)
    found: dict[int, tuple[int, int]] = {}
    try:
        lines = Path("/proc/stat").read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {cid: (0, 0) for cid in cpu_ids}
    for line in lines:
        if not line.startswith("cpu") or line.startswith("cpu "):
            continue
        parts = line.split()
        try:
            cid = int(parts[0][3:])
        except ValueError:
            continue
        if cid not in wanted:
            continue
        nums = [int(x) for x in parts[1:] if x.isdigit()]
        if len(nums) < 5:
            continue
        idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
        found[cid] = (idle, sum(nums))
    for cid in cpu_ids:
        found.setdefault(cid, (0, 0))
    return found


def _read_ctxt() -> int:
    try:
        for line in Path("/proc/stat").read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("ctxt "):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _read_vmstat() -> dict[str, int]:
    wanted = {"pgpgin", "pgpgout", "pswpin", "pswpout", "pgfault", "pgmajfault"}
    out: dict[str, int] = {}
    try:
        for line in Path("/proc/vmstat").read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in wanted:
                try:
                    out[parts[0]] = int(parts[1])
                except ValueError:
                    continue
    except OSError:
        pass
    return out


def _sys_counters() -> dict[str, int]:
    vm = _read_vmstat()
    return {
        "ctxt": _read_ctxt(),
        "pgfault": int(vm.get("pgfault") or 0),
        "pgmajfault": int(vm.get("pgmajfault") or 0),
        "pgpgin": int(vm.get("pgpgin") or 0),
        "pgpgout": int(vm.get("pgpgout") or 0),
    }


def _parse_perf_csv(text: str) -> dict[str, float] | None:
    """Dernier intervalle `perf stat -I 1000 -x,` (count = déjà un débit /s)."""
    misses = None
    refs = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        count: float | None = None
        event = ""
        if len(parts) >= 4:
            try:
                ts = float(parts[0])
                cnt = float(parts[1])
            except ValueError:
                ts, cnt = None, None
            if ts is not None and ts < 1e12:
                count = cnt
                event = (parts[3] if len(parts) > 3 else parts[2]).lower()
        if count is None:
            try:
                count = float(parts[0])
            except ValueError:
                continue
            event = (parts[2] if len(parts) > 2 else "").lower()
        if "cache-misses" in event:
            misses = count
        elif "cache-references" in event:
            refs = count
    if misses is None:
        return None
    out: dict[str, float] = {"cache_miss_s": float(misses)}
    if refs and refs > 0:
        out["cache_ref_s"] = float(refs)
        out["cache_miss_pct"] = round(100.0 * float(misses) / float(refs), 1)
    return out


def _perf_open_hw(config: int, cpu: int) -> int | None:
    """Ouvre un compteur PMU hardware (cache-misses / cache-references)."""
    import ctypes

    class Attr(ctypes.Structure):
        _fields_ = [
            ("type", ctypes.c_uint32),
            ("size", ctypes.c_uint32),
            ("config", ctypes.c_uint64),
            ("sample_period", ctypes.c_uint64),
            ("sample_type", ctypes.c_uint64),
            ("read_format", ctypes.c_uint64),
            ("bits", ctypes.c_uint64),
            ("wakeup_events", ctypes.c_uint32),
            ("bp_type", ctypes.c_uint32),
            ("bp_addr", ctypes.c_uint64),
            ("bp_len", ctypes.c_uint64),
            ("branch_sample_type", ctypes.c_uint64),
            ("sample_regs_user", ctypes.c_uint64),
            ("sample_stack_user", ctypes.c_uint32),
            ("clockid", ctypes.c_int32),
            ("sample_regs_intr", ctypes.c_uint64),
            ("aux_watermark", ctypes.c_uint32),
            ("sample_max_stack", ctypes.c_uint16),
            ("reserved2", ctypes.c_uint16),
        ]

    machine = os.uname().machine
    nr = {"x86_64": 298, "aarch64": 241, "arm64": 241}.get(machine)
    if nr is None:
        return None
    attr = Attr()
    attr.type = 0
    attr.size = ctypes.sizeof(Attr)
    attr.config = config
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.syscall(
        ctypes.c_long(nr),
        ctypes.byref(attr),
        ctypes.c_int(-1),
        ctypes.c_int(cpu),
        ctypes.c_int(-1),
        ctypes.c_ulong(0),
    )
    if fd < 0:
        return None
    return int(fd)


def _pmu_cache_sample(cpus: list[int], duration: float = 0.05) -> dict[str, float] | None:
    import struct

    if not cpus:
        return None
    fds_m: list[int] = []
    fds_r: list[int] = []
    try:
        for cpu in cpus[:48]:
            fm = _perf_open_hw(3, cpu)
            fr = _perf_open_hw(2, cpu)
            if fm is not None:
                fds_m.append(fm)
            if fr is not None:
                fds_r.append(fr)
        if not fds_m:
            return None
        time.sleep(max(0.02, duration))
        def _sum(fds: list[int]) -> int:
            total = 0
            for fd in fds:
                raw = os.read(fd, 8)
                if len(raw) == 8:
                    total += struct.unpack("Q", raw)[0]
            return total
        dt = max(0.02, duration)
        misses = _sum(fds_m) / dt
        refs = _sum(fds_r) / dt if fds_r else 0.0
        out: dict[str, float] = {"cache_miss_s": misses}
        if refs > 0:
            out["cache_ref_s"] = refs
            out["cache_miss_pct"] = round(100.0 * misses / refs, 1)
        return out
    except OSError:
        return None
    finally:
        for fd in fds_m + fds_r:
            try:
                os.close(fd)
            except OSError:
                pass


def _cache_metrics(stress: dict[str, Any] | None) -> dict[str, Any]:
    want_cache = bool(stress and "cache" in (stress.get("workloads") or []))
    try:
        if PERF_FILE.exists() and (time.time() - PERF_FILE.stat().st_mtime) < 4:
            parsed = _parse_perf_csv(_read_text(PERF_FILE))
            if parsed:
                parsed["cache_source"] = "perf"
                return parsed
    except OSError:
        pass
    if not want_cache:
        return {}
    cpus = []
    for item in (stress or {}).get("cpus") or []:
        try:
            cpus.append(int(item))
        except (TypeError, ValueError):
            continue
    sampled = _pmu_cache_sample(cpus or _online_cpus()[:8])
    if sampled:
        sampled["cache_source"] = "pmu"
        return sampled
    return {"cache_unavailable": True}


def _isolated_cpus(online: list[int]) -> list[int]:
    isolated = set(parse_cpu_list(_read_text("/sys/devices/system/cpu/isolated")))
    isolated.update(parse_cpu_list(_cmdline_value("isolcpus")))
    isolated.update(parse_cpu_list(_cmdline_value("nohz_full")))
    isolated.update(parse_cpu_list(_cmdline_value("rcu_nocbs")))
    isolated.update(parse_cpu_list(_read_text("/sys/devices/system/cpu/nohz_full")))
    return sorted(cid for cid in isolated if cid in online)


def _cpu_topology(cid: int) -> dict[str, int | None]:
    base = Path(f"/sys/devices/system/cpu/cpu{cid}")
    def _ival(rel: str) -> int | None:
        raw = _read_text(base / rel)
        try:
            return int(raw)
        except ValueError:
            return None

    socket = _ival("topology/physical_package_id")
    core = _ival("topology/core_id")
    numa = None
    try:
        for child in Path("/sys/devices/system/node").glob("node*"):
            if (child / f"cpu{cid}").exists() or (base / child.name).exists():
                try:
                    numa = int(child.name[4:])
                    break
                except ValueError:
                    continue
    except OSError:
        pass
    if numa is None:
        for child in base.glob("node*"):
            try:
                numa = int(child.name[4:])
                break
            except ValueError:
                continue
    return {"socket": socket, "core": core, "numa": numa}


def _run(cmd: list[str], timeout: float = 8.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} introuvable"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as exc:
        return 1, "", str(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def format_cpu_list(cpus: list[int]) -> str:
    if not cpus:
        return ""
    ordered = sorted(set(int(c) for c in cpus))
    ranges: list[str] = []
    start = prev = ordered[0]
    for cid in ordered[1:]:
        if cid == prev + 1:
            prev = cid
            continue
        ranges.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = cid
    ranges.append(f"{start}-{prev}" if start != prev else str(start))
    return ",".join(ranges)


def parse_seapath_alloc_text(text: str) -> dict[str, Any] | None:
    """Parse the human output of `seapath-alloc` (isolated / free / actors)."""
    if not text or "Isolated:" not in text:
        return None
    isolated: list[int] = []
    free_logical: list[int] = []
    free_physical: list[int] = []
    actors: list[dict[str, Any]] = []
    current_vm: dict[str, Any] | None = None
    section = ""
    cpu_re = re.compile(r"cpus=([0-9,\-]+)")

    for raw in text.splitlines():
        line = raw.rstrip()
        if line.startswith("Isolated:"):
            isolated = parse_cpu_list(line.split(":", 1)[1])
            continue
        if line.startswith("Free logical:"):
            free_logical = parse_cpu_list(line.split(":", 1)[1])
            continue
        if line.startswith("Free physical"):
            free_physical = parse_cpu_list(line.split(":", 1)[1])
            continue
        if line.startswith("Active actors:"):
            section = "actors"
            current_vm = None
            continue
        if line.startswith("Slots:"):
            section = "slots"
            current_vm = None
            continue
        if section != "actors":
            continue
        vm_header = re.match(r"^  VM\s+(.+):\s*$", line)
        if vm_header:
            current_vm = {
                "kind": "vm",
                "name": vm_header.group(1).strip(),
                "cpus": [],
                "threads": [],
            }
            actors.append(current_vm)
            continue
        if current_vm is not None and line.startswith("    "):
            mcpu = cpu_re.search(line)
            cpus = parse_cpu_list(mcpu.group(1) if mcpu else "")
            name = line.strip()
            if mcpu:
                name = line.strip()[: line.strip().find("cpus=")].strip()
            current_vm["threads"].append({"name": name, "cpus": cpus})
            current_vm["cpus"] = sorted(set(current_vm["cpus"]) | set(cpus))
            continue
        current_vm = None
        if not line.startswith("  ") or line.startswith("    "):
            continue
        mcpu = cpu_re.search(line)
        if not mcpu:
            continue
        rest = line.strip()
        kind_m = re.match(r"^(\S+)\s+(.+)$", rest)
        if not kind_m:
            continue
        kind = kind_m.group(1).lower()
        name_and_more = kind_m.group(2)
        name = name_and_more[: name_and_more.find("cpus=")].strip() if "cpus=" in name_and_more else name_and_more
        actors.append({
            "kind": kind,
            "name": name,
            "cpus": parse_cpu_list(mcpu.group(1)),
            "threads": [],
        })

    if not isolated and not actors:
        return None
    return {
        "isolated": isolated,
        "free_logical": free_logical,
        "free_physical": free_physical,
        "actors": actors,
        "source": "seapath-alloc",
    }


def _cpus_field(value: Any) -> list[int]:
    if isinstance(value, list):
        out: list[int] = []
        for item in value:
            if isinstance(item, int):
                out.append(item)
            else:
                out.extend(parse_cpu_list(str(item)))
        return sorted(set(out))
    if isinstance(value, (int, str)):
        return parse_cpu_list(str(value))
    return []


def _normalize_seapath_json(data: dict[str, Any]) -> dict[str, Any] | None:
    isolated = _cpus_field(data.get("isolated") or data.get("Isolated"))
    free_logical = _cpus_field(
        data.get("free_logical") or data.get("freeLogical") or data.get("Free logical")
    )
    free_physical = _cpus_field(
        data.get("free_physical")
        or data.get("free_physical_pairs")
        or data.get("freePhysicalPairs")
    )
    raw_actors = data.get("actors") or data.get("active_actors") or []
    actors: list[dict[str, Any]] = []
    if isinstance(raw_actors, dict):
        raw_actors = [{"name": k, **(v if isinstance(v, dict) else {"cpus": v})} for k, v in raw_actors.items()]
    if isinstance(raw_actors, list):
        for item in raw_actors:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind") or item.get("type") or "actor").lower()
            if kind == "vm" or item.get("vm") or str(item.get("name") or "").startswith("VM "):
                kind = "vm"
            name = str(item.get("name") or item.get("vm") or item.get("label") or kind)
            if name.lower().startswith("vm "):
                kind = "vm"
                name = name[3:].strip()
            cpus = _cpus_field(item.get("cpus") or item.get("cpu"))
            threads = []
            for th in item.get("threads") or item.get("tasks") or []:
                if not isinstance(th, dict):
                    continue
                tcpus = _cpus_field(th.get("cpus") or th.get("cpu"))
                threads.append({"name": str(th.get("name") or ""), "cpus": tcpus})
                cpus = sorted(set(cpus) | set(tcpus))
            actors.append({"kind": kind, "name": name, "cpus": cpus, "threads": threads})
    if not isolated and not actors:
        return None
    return {
        "isolated": isolated,
        "free_logical": free_logical,
        "free_physical": free_physical,
        "actors": actors,
        "source": "seapath-alloc",
    }


def _seapath_alloc_status() -> dict[str, Any] | None:
    if not shutil.which("seapath-alloc"):
        return None
    for args in (
        ["seapath-alloc", "--json"],
        ["seapath-alloc", "-j"],
        ["seapath-alloc"],
    ):
        code, out, _ = _run(args, timeout=8)
        if code != 0 or not (out or "").strip():
            continue
        stripped = out.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                raw = json.loads(stripped)
            except json.JSONDecodeError:
                raw = None
            if isinstance(raw, dict):
                parsed = _normalize_seapath_json(raw)
                if parsed:
                    return parsed
        parsed = parse_seapath_alloc_text(out)
        if parsed:
            return parsed
    return None


def _virsh_domains() -> list[str]:
    code, out, _ = _run(["virsh", "list", "--name"])
    if code != 0:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _parse_affinity_map(text: str) -> dict[int, list[int]]:
    mapping: dict[int, list[int]] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        left, right = line.split(":", 1)
        digits = re.findall(r"\d+", left)
        if not digits:
            continue
        vcpu = int(digits[-1])
        cpus = parse_cpu_list(right)
        if cpus:
            mapping[vcpu] = cpus
    return mapping


def _virsh_vcpu_cpus(domain: str) -> list[int]:
    code, out, _ = _run(["virsh", "vcpupin", domain])
    if code != 0:
        return []
    cpus: set[int] = set()
    for pinned in _parse_affinity_map(out).values():
        cpus.update(pinned)
    return sorted(cpus)


def _qemu_fallback_vms() -> list[dict[str, Any]]:
    code, out, _ = _run(["ps", "-eo", "pid=,args="], timeout=5)
    if code != 0:
        return []
    vms: list[dict[str, Any]] = []
    seen_pids: set[int] = set()
    for line in out.splitlines():
        raw = line.strip()
        if "qemu-system" not in raw and "qemu-kvm" not in raw:
            continue
        parts = raw.split(None, 1)
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        if pid in seen_pids:
            continue
        seen_pids.add(pid)
        args = parts[1] if len(parts) > 1 else ""
        name = ""
        m = re.search(r"-name\s+(?:guest=)?([^,\s]+)", args)
        if m:
            name = m.group(1)
        if not name:
            name = f"qemu:{pid}"
        tcode, tout, _ = _run(["taskset", "-cp", str(pid)], timeout=3)
        cpus = parse_cpu_list(tout.split(":")[-1] if tcode == 0 else "")
        # Affinité large = cpuset de la VM, pas le pinning vCPU : on ignore.
        if len(cpus) > 8:
            cpus = []
        vms.append({"name": name, "cpus": cpus, "source": "qemu"})
    return vms


def _discover_vms(online: list[int]) -> list[dict[str, Any]]:
    domains = _virsh_domains()
    vms: list[dict[str, Any]] = []
    if domains:
        for domain in domains:
            cpus = [c for c in _virsh_vcpu_cpus(domain) if c in online]
            vms.append({"name": domain, "cpus": cpus, "source": "libvirt"})
        return vms
    vms = _qemu_fallback_vms()
    for vm in vms:
        vm["cpus"] = [c for c in vm["cpus"] if c in online]
    return vms


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _self_allowed_cpus() -> set[int]:
    try:
        text = Path("/proc/self/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    for line in text.splitlines():
        if line.startswith("Cpus_allowed_list:"):
            return set(parse_cpu_list(line.split(":", 1)[1]))
    return set()


def _isolated_set(online: list[int]) -> set[int]:
    sea = _seapath_alloc_status()
    if sea and sea.get("isolated"):
        return {int(c) for c in sea["isolated"] if int(c) in online}
    return set(_isolated_cpus(online))


def _stress_ng_argv(
    binary: str,
    n: int,
    workloads: list[str],
    cpu_load: int,
    timeout_s: int,
    taskset: list[int] | None,
    log_file: Path,
) -> list[str]:
    cmd = [binary]
    if "cpu" in workloads:
        cmd += ["--cpu", str(n), "--cpu-load", str(cpu_load)]
    if "cache" in workloads:
        cmd += ["--cache", str(n)]
    if "vm" in workloads:
        cmd += ["--vm", str(max(1, (n + 1) // 2)), "--vm-bytes", "64M"]
    if "switch" in workloads:
        cmd += ["--switch", str(n)]
    if not any(w in workloads for w in ("cpu", "cache", "vm", "switch")):
        cmd += ["--cpu", str(n), "--cpu-load", str(cpu_load)]
    if taskset:
        cmd += ["--taskset", ",".join(str(c) for c in taskset)]
    if timeout_s > 0:
        cmd += ["--timeout", f"{timeout_s}s"]
    cmd += ["--log-file", str(log_file), "--metrics-brief"]
    return cmd


def _without_taskset(cmd: list[str]) -> list[str]:
    out: list[str] = []
    skip = False
    for arg in cmd:
        if skip:
            skip = False
            continue
        if arg == "--taskset":
            skip = True
            continue
        out.append(arg)
    return out


def _wrap_isolated_cmd(cpu: int, inner: list[str], allowed: set[int]) -> list[str]:
    """isolcpus n'exécute un process sur un cœur isolé que si l'affinité est exclusive.

    Si le cpuset SSH n'inclut pas ce CPU, seapath-run l'alloue (slot exclusive_logical).
    """
    if cpu in allowed:
        return inner
    sea = shutil.which("seapath-run")
    if not sea:
        return inner
    # seapath-run choisit un CPU libre : ne pas re-taskset vers un autre cœur.
    return [sea, f"po-stress-{cpu}", "exclusive_logical", "OTHER", "0", "--"] + _without_taskset(inner)


def _kill_pid(pid: int) -> bool:
    if not _pid_alive(pid):
        return False
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            os.killpg(pid, sig)
        except OSError:
            try:
                os.kill(pid, sig)
            except OSError:
                return False
        for _ in range(20):
            if not _pid_alive(pid):
                return True
            time.sleep(0.05)
        if not _pid_alive(pid):
            return True
    try:
        os.killpg(pid, signal.SIGKILL)
    except OSError:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            return False
    return not _pid_alive(pid)


def _read_spec() -> dict[str, Any]:
    try:
        data = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _spec_pids(spec: dict[str, Any] | None) -> list[int]:
    if not spec:
        return []
    raw = spec.get("pids") or ([spec["pid"]] if spec.get("pid") else [])
    out: list[int] = []
    for item in raw:
        try:
            pid = int(item)
        except (TypeError, ValueError):
            continue
        if pid > 0 and pid not in out:
            out.append(pid)
    return out


def _current_stress() -> dict[str, Any] | None:
    spec = _read_spec()
    pids = _spec_pids(spec)
    if not pids:
        try:
            pid = int(_read_text(PID_FILE) or "0")
        except ValueError:
            pid = 0
        if pid:
            pids = [pid]
    alive = [p for p in pids if _pid_alive(p)]
    if not alive:
        return None
    spec["pid"] = alive[0]
    spec["pids"] = alive
    return spec


def _stop_stress() -> dict[str, Any]:
    spec = _read_spec()
    pids = _spec_pids(spec)
    if not pids:
        try:
            pid = int(_read_text(PID_FILE) or "0")
        except ValueError:
            pid = 0
        if pid:
            pids = [pid]
    killed = [pid for pid in pids if _kill_pid(pid)]
    try:
        PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        SPEC_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    try:
        PERF_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    return {"stopped": True, "killed": killed, "was_running": bool(pids)}


def _popen_detached(cmd: list[str]) -> subprocess.Popen:
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def _start_stress(spec: dict[str, Any]) -> dict[str, Any]:
    existing = _current_stress()
    if existing:
        _stop_stress()

    cpus = sorted({int(c) for c in (spec.get("cpus") or []) if int(c) >= 0})
    if not cpus:
        return {"error": "Aucun CPU sélectionné"}
    workloads = [str(w) for w in (spec.get("workloads") or ["cpu"])]
    if not workloads:
        workloads = ["cpu"]
    if not any(w in workloads for w in ("cpu", "cache", "vm", "switch")):
        workloads = ["cpu"]
    cpu_load = max(1, min(100, int(spec.get("cpu_load") or 100)))
    timeout_s = max(0, int(spec.get("timeout_s") or 0))

    binary = shutil.which("stress-ng")
    if not binary:
        return {"error": "stress-ng introuvable sur la cible (apt/dnf install stress-ng)"}

    online = _online_cpus()
    isolated = _isolated_set(online)
    allowed = _self_allowed_cpus() or set(online)
    hk_cpus = [c for c in cpus if c not in isolated]
    isol_cpus = [c for c in cpus if c in isolated]

    try:
        LOG_FILE.write_text("", encoding="utf-8")
    except OSError:
        pass

    # Un masque unique HK+isolés laisse isolcpus tout placer sur le housekeeping.
    # HK : un stress-ng (ces cœurs sont schedulables). Isolés : 1 worker / CPU.
    cmds: list[list[str]] = []
    if hk_cpus:
        cmds.append(_stress_ng_argv(
            binary, len(hk_cpus), workloads, cpu_load, timeout_s, hk_cpus, LOG_FILE,
        ))
    for cpu in isol_cpus:
        inner = _stress_ng_argv(
            binary, 1, workloads, cpu_load, timeout_s, [cpu], LOG_FILE,
        )
        cmds.append(_wrap_isolated_cmd(cpu, inner, allowed))

    procs: list[subprocess.Popen] = []
    launched: list[list[str]] = []
    errors: list[str] = []
    for cmd in cmds:
        try:
            proc = _popen_detached(cmd)
        except OSError as exc:
            errors.append(f"{' '.join(cmd[:6])}: {exc}")
            continue
        procs.append(proc)
        launched.append(cmd)
        if Path(cmd[0]).name == "seapath-run":
            time.sleep(0.05)

    if not procs:
        return {"error": "Impossible de lancer stress-ng: " + ("; ".join(errors) or "aucun process")}

    time.sleep(0.25)
    pids = [p.pid for p in procs]
    dead = [p for p in procs if p.poll() is not None]
    if len(dead) == len(procs):
        tail = _read_text(LOG_FILE)
        return {
            "error": f"stress-ng s'est arrêté immédiatement: {tail or dead[0].returncode}",
            "cmd": launched[0],
            "cmds": launched,
        }

    if "cache" in workloads:
        perf = shutil.which("perf")
        if perf:
            try:
                PERF_FILE.write_text("", encoding="utf-8")
            except OSError:
                pass
            pcmd = [
                perf, "stat", "-I", "1000", "-x,",
                "-e", "cache-misses,cache-references",
                "-C", ",".join(str(c) for c in cpus),
                "-o", str(PERF_FILE),
                "--", "sleep", "8640000",
            ]
            try:
                proc = _popen_detached(pcmd)
                procs.append(proc)
                launched.append(pcmd)
                pids.append(proc.pid)
            except OSError as exc:
                errors.append(f"perf: {exc}")

    payload = {
        "pid": pids[0],
        "pids": pids,
        "cpus": cpus,
        "workloads": workloads,
        "cpu_load": cpu_load,
        "timeout_s": timeout_s,
        "started_at": time.time(),
        "cmd": launched[0],
        "cmds": launched,
        "hk_cpus": hk_cpus,
        "isolated_cpus": isol_cpus,
    }
    try:
        PID_FILE.write_text(str(pids[0]), encoding="utf-8")
        SPEC_FILE.write_text(json.dumps(payload), encoding="utf-8")
    except OSError as exc:
        return {"error": f"stress-ng lancé (pid {pids[0]}) mais pidfile illisible: {exc}", **payload}
    if errors:
        payload["warning"] = "; ".join(errors)
    return payload


def _cpu_rows(
    online: list[int],
    isolated: list[int],
    vms: list[dict[str, Any]],
    *,
    free_logical: list[int] | None = None,
    actors: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    isolated_set = set(isolated)
    vm_by_cpu: dict[int, list[str]] = {}
    for vm in vms:
        for cid in vm.get("cpus") or []:
            vm_by_cpu.setdefault(int(cid), []).append(str(vm.get("name") or "?"))
    actor_by_cpu: dict[int, list[str]] = {}
    actor_kind_by_cpu: dict[int, str] = {}
    for actor in actors or []:
        kind = str(actor.get("kind") or "actor").lower()
        if kind == "vm":
            continue
        label = str(actor.get("name") or kind)
        for cid in actor.get("cpus") or []:
            actor_by_cpu.setdefault(int(cid), []).append(label)
            actor_kind_by_cpu.setdefault(int(cid), kind)
    housekeeping_set = set(online) - isolated_set if isolated_set else set(online) - set(vm_by_cpu)
    if free_logical is None:
        free_set = isolated_set - set(vm_by_cpu) - set(actor_by_cpu)
    else:
        free_set = set(free_logical)
    counters = _proc_stat_counters(online)
    rows = []
    for cid in online:
        topo = _cpu_topology(cid)
        vm_names = vm_by_cpu.get(cid, [])
        actor_names = actor_by_cpu.get(cid, [])
        role = "housekeeping"
        if vm_names:
            role = "vm"
        elif actor_names:
            kind = actor_kind_by_cpu.get(cid, "actor")
            role = kind if kind in ("irq", "run", "quadlet") else "actor"
        elif cid in free_set:
            role = "isolated_free"
        elif cid in isolated_set:
            role = "isolated_busy"
        rows.append({
            "id": cid,
            "online": True,
            "role": role,
            "isolated": cid in isolated_set,
            "housekeeping": cid in housekeeping_set,
            "vm_names": vm_names,
            "actor_names": actor_names,
            "socket": topo["socket"],
            "core": topo["core"],
            "numa": topo["numa"],
            "idle": counters[cid][0],
            "total": counters[cid][1],
        })
    return rows


def probe() -> dict[str, Any]:
    online = _online_cpus()
    sea = _seapath_alloc_status()
    actors: list[dict[str, Any]] = []
    free_logical: list[int] | None = None
    free_physical: list[int] = []
    if sea:
        isolated = [c for c in sea["isolated"] if c in online] or _isolated_cpus(online)
        free_logical = [c for c in sea["free_logical"] if c in online]
        free_physical = [c for c in sea["free_physical"] if c in online]
        vms = []
        for actor in sea["actors"]:
            actor["cpus"] = [c for c in actor.get("cpus") or [] if c in online]
            if actor.get("kind") == "vm":
                vms.append({
                    "name": actor.get("name") or "VM",
                    "cpus": actor["cpus"],
                    "source": "seapath-alloc",
                })
            else:
                actors.append(actor)
        source = "seapath-alloc"
    else:
        isolated = _isolated_cpus(online)
        vms = _discover_vms(online)
        source = "sysfs"
    rows = _cpu_rows(online, isolated, vms, free_logical=free_logical, actors=actors)
    vm_cpus = sorted({c for vm in vms for c in vm.get("cpus") or []})
    hk = sorted(r["id"] for r in rows if r["housekeeping"])
    unassigned = sorted(free_logical) if free_logical is not None else sorted(
        r["id"] for r in rows if r["role"] == "isolated_free"
    )
    available = sorted(
        r["id"] for r in rows if r["role"] in ("housekeeping", "isolated_free")
    )
    occupied = sorted(
        r["id"] for r in rows if r["role"] not in ("housekeeping", "isolated_free")
    )
    stress = _current_stress()
    return {
        "hostname": socket.gethostname(),
        "nproc": len(online),
        "cpus": rows,
        "vms": vms,
        "actors": actors,
        "isolated": isolated,
        "housekeeping": hk,
        "unassigned_isolated": unassigned,
        "free_logical": unassigned,
        "free_logical_label": format_cpu_list(unassigned),
        "free_physical": free_physical,
        "vm_cpus": vm_cpus,
        "occupied": occupied,
        "available": available,
        "non_vm": available,
        "cpu_source": source,
        "stress_ng": shutil.which("stress-ng"),
        "isolcpus": (
            format_cpu_list(isolated) if sea
            else (_cmdline_value("isolcpus") or _read_text("/sys/devices/system/cpu/isolated"))
        ),
        "nohz_full": _cmdline_value("nohz_full"),
        "running": stress is not None,
        "stress": stress,
        "sys": _sys_counters(),
        "local_time": time.time(),
    }


def stats() -> dict[str, Any]:
    online = _online_cpus()
    counters = _proc_stat_counters(online)
    stress = _current_stress()
    log_tail = ""
    try:
        data = LOG_FILE.read_text(encoding="utf-8", errors="replace")
        log_tail = data[-2000:] if data else ""
    except OSError:
        pass
    sys_snap = _sys_counters()
    sys_snap.update(_cache_metrics(stress))
    return {
        "hostname": socket.gethostname(),
        "cpus": [{"id": cid, "idle": counters[cid][0], "total": counters[cid][1]} for cid in online],
        "running": stress is not None,
        "stress": stress,
        "sys": sys_snap,
        "log_tail": log_tail,
        "local_time": time.time(),
    }


def dispatch(op: str, spec: dict[str, Any] | None = None) -> dict[str, Any]:
    spec = spec or {}
    if op == "probe":
        return probe()
    if op == "stats":
        return stats()
    if op == "start":
        return _start_stress(spec)
    if op == "stop":
        return _stop_stress()
    if op == "status":
        stress = _current_stress()
        return {"running": stress is not None, "stress": stress}
    return {"error": f"opération inconnue: {op}"}


def main() -> int:
    op = sys.argv[1] if len(sys.argv) > 1 else "probe"
    spec: dict[str, Any] = {}
    if len(sys.argv) > 2:
        raw = sys.argv[2]
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = json.loads(base64.b64decode(raw).decode("utf-8"))
        if isinstance(parsed, dict):
            spec = parsed
    try:
        result = dispatch(op, spec)
    except Exception as exc:  # noqa: BLE001 - renvoyer l'erreur à po_service
        result = {"error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(json.dumps(result, ensure_ascii=False))
    sys.stdout.write("\n")
    return 0 if not result.get("error") else 1


if __name__ == "__main__":
    raise SystemExit(main())
