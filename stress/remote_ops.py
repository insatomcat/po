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


def _read_spec() -> dict[str, Any]:
    try:
        data = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _current_stress() -> dict[str, Any] | None:
    try:
        pid = int(_read_text(PID_FILE) or "0")
    except ValueError:
        pid = 0
    if not pid or not _pid_alive(pid):
        return None
    spec = _read_spec()
    spec["pid"] = pid
    return spec


def _stop_stress() -> dict[str, Any]:
    spec = _current_stress()
    killed = []
    if spec and spec.get("pid"):
        pid = int(spec["pid"])
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                os.kill(pid, sig)
            except OSError:
                break
            for _ in range(20):
                if not _pid_alive(pid):
                    break
                time.sleep(0.05)
            if not _pid_alive(pid):
                killed.append(pid)
                break
        if _pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
                killed.append(pid)
            except OSError:
                pass
    try:
        PID_FILE.unlink(missing_ok=True)
    except OSError:
        pass
    return {"stopped": True, "killed": killed, "was_running": spec is not None}


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
    cpu_load = max(1, min(100, int(spec.get("cpu_load") or 100)))
    timeout_s = max(0, int(spec.get("timeout_s") or 0))
    n = len(cpus)

    binary = shutil.which("stress-ng")
    if not binary:
        return {"error": "stress-ng introuvable sur la cible (apt/dnf install stress-ng)"}

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
        workloads = ["cpu"]
    cmd += ["--taskset", ",".join(str(c) for c in cpus)]
    if timeout_s > 0:
        cmd += ["--timeout", f"{timeout_s}s"]
    cmd += ["--log-file", str(LOG_FILE), "--metrics-brief"]

    try:
        LOG_FILE.write_text("", encoding="utf-8")
    except OSError:
        pass

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return {"error": f"Impossible de lancer stress-ng: {exc}"}

    payload = {
        "pid": proc.pid,
        "cpus": cpus,
        "workloads": workloads,
        "cpu_load": cpu_load,
        "timeout_s": timeout_s,
        "started_at": time.time(),
        "cmd": cmd,
    }
    try:
        PID_FILE.write_text(str(proc.pid), encoding="utf-8")
        SPEC_FILE.write_text(json.dumps(payload), encoding="utf-8")
    except OSError as exc:
        return {"error": f"stress-ng lancé (pid {proc.pid}) mais pidfile illisible: {exc}", **payload}
    if proc.poll() is not None:
        tail = _read_text(LOG_FILE)
        return {"error": f"stress-ng s'est arrêté immédiatement: {tail or proc.returncode}"}
    return payload


def _cpu_rows(online: list[int], isolated: list[int], vms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    isolated_set = set(isolated)
    vm_by_cpu: dict[int, list[str]] = {}
    for vm in vms:
        for cid in vm.get("cpus") or []:
            vm_by_cpu.setdefault(int(cid), []).append(str(vm.get("name") or "?"))
    housekeeping_set = set(online) - isolated_set if isolated_set else set(online) - set(vm_by_cpu)
    counters = _proc_stat_counters(online)
    rows = []
    for cid in online:
        topo = _cpu_topology(cid)
        vm_names = vm_by_cpu.get(cid, [])
        role = "housekeeping"
        if vm_names:
            role = "vm"
        elif cid in isolated_set:
            role = "isolated_free"
        rows.append({
            "id": cid,
            "online": True,
            "role": role,
            "isolated": cid in isolated_set,
            "housekeeping": cid in housekeeping_set,
            "vm_names": vm_names,
            "socket": topo["socket"],
            "core": topo["core"],
            "numa": topo["numa"],
            "idle": counters[cid][0],
            "total": counters[cid][1],
        })
    return rows


def probe() -> dict[str, Any]:
    online = _online_cpus()
    isolated = _isolated_cpus(online)
    vms = _discover_vms(online)
    rows = _cpu_rows(online, isolated, vms)
    vm_cpus = sorted({c for vm in vms for c in vm.get("cpus") or []})
    hk = sorted(r["id"] for r in rows if r["housekeeping"])
    unassigned = sorted(r["id"] for r in rows if r["role"] == "isolated_free")
    stress = _current_stress()
    return {
        "hostname": socket.gethostname(),
        "nproc": len(online),
        "cpus": rows,
        "vms": vms,
        "isolated": isolated,
        "housekeeping": hk,
        "unassigned_isolated": unassigned,
        "vm_cpus": vm_cpus,
        "stress_ng": shutil.which("stress-ng"),
        "isolcpus": _cmdline_value("isolcpus") or _read_text("/sys/devices/system/cpu/isolated"),
        "nohz_full": _cmdline_value("nohz_full"),
        "running": stress is not None,
        "stress": stress,
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
    return {
        "hostname": socket.gethostname(),
        "cpus": [{"id": cid, "idle": counters[cid][0], "total": counters[cid][1]} for cid in online],
        "running": stress is not None,
        "stress": stress,
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
