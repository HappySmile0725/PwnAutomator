# -*- coding: utf-8 -*-
import os
import jarray
from ghidra.app.decompiler import DecompInterface

try:
    INTEGER_TYPES = (int, long)
except NameError:
    INTEGER_TYPES = (int,)

HEX_CHARS = set("0123456789abcdefABCDEF")
WINDOWS_DRIVE_LETTERS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class GhidraContext(object):
    program = None
    fm = None
    mem = None
    listing = None
    addr_factory = None
    decomp = None

    @staticmethod
    def init(program):
        GhidraContext.program = program
        GhidraContext.fm = program.getFunctionManager()
        GhidraContext.mem = program.getMemory()
        GhidraContext.listing = program.getListing()
        GhidraContext.addr_factory = program.getAddressFactory()
        GhidraContext.decomp = None

    @staticmethod
    def ensure_decomp():
        if GhidraContext.decomp is None:
            decomp = DecompInterface()
            decomp.openProgram(GhidraContext.program)
            GhidraContext.decomp = decomp
        return GhidraContext.decomp

    @staticmethod
    def addr(addr_str):
        space = GhidraContext.addr_factory.getDefaultAddressSpace()

        if addr_str is None:
            raise ValueError("address required")

        if isinstance(addr_str, INTEGER_TYPES):
            return space.getAddress(int(addr_str))

        text = str(addr_str).strip()
        if not text:
            raise ValueError("address required")

        addr = GhidraContext.addr_factory.getAddress(text)
        if addr is not None:
            return addr

        if text.startswith("0x") and _is_hex_text(text[2:]):
            return space.getAddress(int(text, 16))

        if _is_hex_text(text):
            return space.getAddress(int(text, 16))

        if text.isdigit():
            return space.getAddress(int(text, 10))

        raise ValueError("invalid address: %s" % text)

    @staticmethod
    def read_bytes(addr, size):
        buf = jarray.zeros(size, "b")
        GhidraContext.mem.getBytes(addr, buf)
        return [(b & 0xff) for b in buf]


def _is_hex_text(text):
    if not text:
        return False
    for ch in text:
        if ch not in HEX_CHARS:
            return False
    return True


def _normalize_path_text(path):
    return str(path or "").strip().replace("\\", "/")


def _to_wsl_path(path):
    text = _normalize_path_text(path)
    if len(text) >= 3 and text[1] == ":" and text[0] in WINDOWS_DRIVE_LETTERS:
        drive = text[0].lower()
        tail = text[2:].lstrip("/")
        if tail:
            return "/mnt/%s/%s" % (drive, tail)
        return "/mnt/%s" % drive
    return text


def _candidate_paths(path):
    text = _to_wsl_path(path)
    if not text:
        return []

    base = os.path.basename(text)
    cwd = os.getcwd()
    project_root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

    candidates = [text, os.path.abspath(text), os.path.realpath(text)]
    if base:
        candidates.extend([
            os.path.join(cwd, base),
            os.path.join(cwd, "test", base),
            os.path.join(project_root, "test", base),
        ])

    ordered = []
    seen = set()
    for cand in candidates:
        norm = os.path.normpath(cand)
        if norm in seen:
            continue
        seen.add(norm)
        ordered.append(norm)
    return ordered


def find_existing_path(path):
    for cand in _candidate_paths(path):
        if os.path.exists(cand):
            return cand
    return None


def resolve_path(path):
    if not path:
        return None

    found = find_existing_path(path)
    if found:
        return found

    return os.path.normpath(_to_wsl_path(path))
