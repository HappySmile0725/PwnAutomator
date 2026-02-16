#!/usr/bin/env python3
"""Helpers to locate Ghidra debugger Python packages."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Optional


def _is_valid_ghidra_home(path: Path) -> bool:
    if not path.exists():
        return False
    probe = path / "Ghidra" / "Debug" / "Debugger-agent-gdb"
    return probe.exists()


def discover_ghidra_home(explicit_home: Optional[str] = None) -> Optional[str]:
    candidates = []
    if explicit_home:
        candidates.append(Path(explicit_home))

    env_home = os.environ.get("GHIDRA_HOME")
    if env_home:
        candidates.append(Path(env_home))

    here = Path(__file__).resolve()
    # .../mcps/ghidra_tools/debug_bridge/adapters
    mcps_dir = here.parents[3]
    if mcps_dir.exists():
        candidates.extend(sorted(mcps_dir.glob("ghidra_*_PUBLIC"), reverse=True))

    for cand in candidates:
        if _is_valid_ghidra_home(cand):
            return str(cand)
    return None


def build_ghidra_env(explicit_home: Optional[str] = None) -> Dict[str, str]:
    env = dict(os.environ)
    home = discover_ghidra_home(explicit_home)
    if not home:
        return env

    home_path = Path(home)
    gdb_mod = home_path / "Ghidra" / "Debug" / "Debugger-agent-gdb"
    trace_mod = home_path / "Ghidra" / "Debug" / "Debugger-rmi-trace"
    gdb_src = gdb_mod / "pypkg" / "src"
    trace_src = trace_mod / "pypkg" / "src"

    py_paths = [str(gdb_src), str(trace_src)]
    old_pythonpath = env.get("PYTHONPATH", "")
    if old_pythonpath:
        py_paths.append(old_pythonpath)
    env["PYTHONPATH"] = os.pathsep.join(py_paths)

    env["GHIDRA_HOME"] = str(home_path)
    env["MODULE_Debugger_rmi_trace_HOME"] = str(trace_mod)
    env["MODULE_Debugger_agent_gdb_HOME"] = str(gdb_mod)
    return env

