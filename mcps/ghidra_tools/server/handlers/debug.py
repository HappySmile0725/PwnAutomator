# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, sys.path[0] + "/..")
from utils import GhidraContext as ctx


class DebugHandler:
    """dynamic debug commands via debug bridge"""

    @staticmethod
    def _resolve_binary(args):
        args = args or {}
        if args.get("binary"):
            return args

        out = {}
        for k in args:
            out[k] = args[k]

        try:
            p = ctx.program.getExecutablePath()
            if p:
                out["binary"] = str(p)
                return out
        except:
            pass

        # Fallback: name only (may work if cwd contains binary)
        out["binary"] = str(ctx.program.getName())
        return out

    @staticmethod
    def open(args):
        payload = DebugHandler._resolve_binary(args)
        return ctx.bridge_call("debug.open", payload)

    @staticmethod
    def open_current(args):
        payload = DebugHandler._resolve_binary(args)
        return ctx.bridge_call("debug.open", payload)

    @staticmethod
    def attach(args):
        return ctx.bridge_call("debug.attach", args)

    @staticmethod
    def close(args):
        return ctx.bridge_call("debug.close", args)

    @staticmethod
    def list_sessions(args):
        return ctx.bridge_call("debug.list", args)

    @staticmethod
    def status(args):
        return ctx.bridge_call("debug.status", args)

    @staticmethod
    def break_set(args):
        return ctx.bridge_call("debug.break.set", args)

    @staticmethod
    def break_del(args):
        return ctx.bridge_call("debug.break.del", args)

    @staticmethod
    def break_list(args):
        return ctx.bridge_call("debug.break.list", args)

    @staticmethod
    def cont(args):
        return ctx.bridge_call("debug.cont", args)

    @staticmethod
    def stepi(args):
        return ctx.bridge_call("debug.stepi", args)

    @staticmethod
    def nexti(args):
        return ctx.bridge_call("debug.nexti", args)

    @staticmethod
    def interrupt(args):
        return ctx.bridge_call("debug.interrupt", args)

    @staticmethod
    def regs(args):
        return ctx.bridge_call("debug.regs", args)

    @staticmethod
    def mem(args):
        return ctx.bridge_call("debug.mem", args)

    @staticmethod
    def bt(args):
        return ctx.bridge_call("debug.bt", args)

    @staticmethod
    def events_poll(args):
        return ctx.bridge_call("debug.events.poll", args)

    @staticmethod
    def trace_connect(args):
        return ctx.bridge_call("debug.trace.connect", args)

    @staticmethod
    def trace_disconnect(args):
        return ctx.bridge_call("debug.trace.disconnect", args)

    @staticmethod
    def trace_start(args):
        return ctx.bridge_call("debug.trace.start", args)

    @staticmethod
    def trace_stop(args):
        return ctx.bridge_call("debug.trace.stop", args)

    @staticmethod
    def trace_sync_enable(args):
        return ctx.bridge_call("debug.trace.sync_enable", args)

    @staticmethod
    def trace_sync_disable(args):
        return ctx.bridge_call("debug.trace.sync_disable", args)

    @staticmethod
    def trace_sync_synth_stopped(args):
        return ctx.bridge_call("debug.trace.sync_synth_stopped", args)

    @staticmethod
    def trace_put_all(args):
        return ctx.bridge_call("debug.trace.put_all", args)


COMMANDS = {
    "debug.open": DebugHandler.open,
    "debug.open.current": DebugHandler.open_current,
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
    "debug.regs": DebugHandler.regs,
    "debug.mem": DebugHandler.mem,
    "debug.bt": DebugHandler.bt,
    "debug.events.poll": DebugHandler.events_poll,
    "debug.trace.connect": DebugHandler.trace_connect,
    "debug.trace.disconnect": DebugHandler.trace_disconnect,
    "debug.trace.start": DebugHandler.trace_start,
    "debug.trace.stop": DebugHandler.trace_stop,
    "debug.trace.sync_enable": DebugHandler.trace_sync_enable,
    "debug.trace.sync_disable": DebugHandler.trace_sync_disable,
    "debug.trace.sync_synth_stopped": DebugHandler.trace_sync_synth_stopped,
    "debug.trace.put_all": DebugHandler.trace_put_all,
}
