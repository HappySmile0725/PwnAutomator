# -*- coding: utf-8 -*-
import os
from utils import GhidraContext as ctx, resolve_path, find_existing_path


class DebugHandler:
    """dynamic debug commands via debug bridge"""

    @staticmethod
    def _bridge(cmd, args):
        return ctx.bridge_call(cmd, args or {})

    @staticmethod
    def _normalize_path_arg(payload, key):
        if payload.get(key):
            payload[key] = resolve_path(payload[key])
        return payload

    @staticmethod
    def _prepare_args(args):
        out = dict(args or {})

        for key in ("binary", "cwd", "gdb_path"):
            if out.get(key):
                out[key] = resolve_path(out[key])

        if out.get("binary"):
            return out

        binary = DebugHandler._resolve_current_binary(out)
        if binary:
            out["binary"] = binary
        return out

    @staticmethod
    def _resolve_current_binary(args):
        env_binary = os.environ.get("GHIDRA_MCP_BINARY_PATH")
        if env_binary:
            resolved_env = resolve_path(env_binary)
            if resolved_env and os.path.exists(resolved_env):
                return resolved_env

        executable_path = ctx.program.getExecutablePath()
        if executable_path:
            resolved = resolve_path(str(executable_path))
            if os.path.exists(resolved):
                return resolved

        program_name = str(ctx.program.getName() or "").strip()
        if not program_name:
            return None

        if args.get("cwd"):
            from_cwd = find_existing_path(os.path.join(args["cwd"], program_name))
            if from_cwd:
                return from_cwd

        found = find_existing_path(program_name)
        if found:
            return found

        return resolve_path(program_name)

    @staticmethod
    def open(args):
        payload = DebugHandler._prepare_args(args)
        return DebugHandler._bridge("debug.open", payload)

    @staticmethod
    def open_current(args):
        payload = DebugHandler._prepare_args(args)
        return DebugHandler._bridge("debug.open", payload)

    @staticmethod
    def run(args):
        payload = dict(args or {})
        if not payload.get("binary"):
            binary = DebugHandler._resolve_current_binary(payload)
            if binary and os.path.exists(binary):
                payload["binary"] = binary
        return DebugHandler._bridge("debug.run", payload)

    @staticmethod
    def attach(args):
        payload = DebugHandler._prepare_args(args)
        return DebugHandler._bridge("debug.attach", payload)

    @staticmethod
    def close(args):
        return DebugHandler._bridge("debug.close", args)

    @staticmethod
    def list_sessions(args):
        return DebugHandler._bridge("debug.list", args)

    @staticmethod
    def status(args):
        return DebugHandler._bridge("debug.status", args)

    @staticmethod
    def break_set(args):
        return DebugHandler._bridge("debug.break.set", args)

    @staticmethod
    def break_del(args):
        return DebugHandler._bridge("debug.break.del", args)

    @staticmethod
    def break_list(args):
        return DebugHandler._bridge("debug.break.list", args)

    @staticmethod
    def cont(args):
        return DebugHandler._bridge("debug.cont", args)

    @staticmethod
    def stepi(args):
        return DebugHandler._bridge("debug.stepi", args)

    @staticmethod
    def nexti(args):
        return DebugHandler._bridge("debug.nexti", args)

    @staticmethod
    def interrupt(args):
        return DebugHandler._bridge("debug.interrupt", args)

    @staticmethod
    def stdin_write(args):
        return DebugHandler._bridge("debug.stdin.write", args)

    @staticmethod
    def regs(args):
        return DebugHandler._bridge("debug.regs", args)

    @staticmethod
    def mem(args):
        return DebugHandler._bridge("debug.mem", args)

    @staticmethod
    def bt(args):
        return DebugHandler._bridge("debug.bt", args)

    @staticmethod
    def context(args):
        return DebugHandler._bridge("debug.context", args)

    @staticmethod
    def read_stdout(args):
        return DebugHandler._bridge("debug.read_stdout", args)

    @staticmethod
    def events_poll(args):
        return DebugHandler._bridge("debug.events.poll", args)
        
    @staticmethod
    def restart_server(args):
        if not ctx.bridge_client:
            return {"ok": False, "error": "Bridge client not initialized"}
        success = ctx.bridge_client.restart()
        if success:
            return {"ok": True, "result": "restarted"}
        return {"ok": False, "error": "failed to restart bridge (port may still be occupied)"}

    @staticmethod
    def cmd(args):
        return DebugHandler._bridge("debug.cmd", args)

    @staticmethod
    def ropgadget_chall(args):
        payload = dict(args or {})
        payload = DebugHandler._normalize_path_arg(payload, "path")
        if not payload.get("path"):
            binary = DebugHandler._resolve_current_binary(payload)
            if binary and os.path.exists(binary):
                payload["path"] = binary
        return DebugHandler._bridge("debug.ropgadget.chall", payload)

    @staticmethod
    def ropgadget_libc(args):
        payload = dict(args or {})
        payload = DebugHandler._normalize_path_arg(payload, "path")
        return DebugHandler._bridge("debug.ropgadget.libc", payload)



COMMANDS = {
    "debug.open": DebugHandler.open,
    "debug.open.current": DebugHandler.open_current,
    "debug.run": DebugHandler.run,
    "debug.attach": DebugHandler.attach,
    "debug.close": DebugHandler.close,
    "debug.list": DebugHandler.list_sessions,
    "debug.status": DebugHandler.status,
    "debug.break.set": DebugHandler.break_set,
    "debug.break.del": DebugHandler.break_del,
    "debug.break.list": DebugHandler.break_list,
    "debug.cont": DebugHandler.cont,
    "debug.stepi": DebugHandler.stepi,
    "debug.nexti": DebugHandler.nexti,
    "debug.interrupt": DebugHandler.interrupt,
    "debug.stdin.write": DebugHandler.stdin_write,
    "debug.regs": DebugHandler.regs,
    "debug.mem": DebugHandler.mem,
    "debug.bt": DebugHandler.bt,
    "debug.read_stdout": DebugHandler.read_stdout,
    "debug.events.poll": DebugHandler.events_poll,
    "debug.context": DebugHandler.context,
    "debug.cmd": DebugHandler.cmd,
    "debug.ropgadget.chall": DebugHandler.ropgadget_chall,
    "debug.ropgadget.libc": DebugHandler.ropgadget_libc,
}
