from . import GdbHandler
import gdb

GDB_ERROR = getattr(gdb, "error", RuntimeError)
MEMORY_ERROR = getattr(gdb, "MemoryError", GDB_ERROR)

REG_NAMES = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eflags"]
CONTEXT_REGS = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rip",
    "eflags",
]


def _hex(value):
    return "0x%x" % int(value)


class StateHandler(GdbHandler):
    """Handle register/memory/backtrace/context queries."""

    def handle_regs(self, args):
        """Return selected register values as hexadecimal strings."""
        regs = {}
        
        for reg in REG_NAMES:
            value = self._eval_register(reg)
            
            if value is not None:
                regs[reg] = _hex(value)
                
        return self.ok(regs)

    def handle_mem(self, args):
        """Read raw inferior memory and return a hex string."""
        args = args or {}
        addr_raw = args.get("addr")
        
        if addr_raw is None:
            return self.err("addr required")
        
        try:
            addr = int(str(addr_raw), 0)
            size = int(args.get("size", 64))
            
        except (TypeError, ValueError):
            return self.err("invalid addr or size")

        try:
            mem = gdb.selected_inferior().read_memory(addr, size)
        except (GDB_ERROR, MEMORY_ERROR) as exc:
            return self.err(exc)
        
        return self.ok({"addr": _hex(addr), "hex": mem.tobytes().hex()})

    def handle_bt(self, args):
        """Return the current call stack from newest to oldest frame."""
        frames = []
        frame = gdb.newest_frame()
        
        while frame:
            frames.append({"addr": hex(frame.pc()), "func": frame.name() or "??"})
            frame = frame.older()
            
        return self.ok(frames)

    def handle_context(self, args):
        """Return registers, near-PC disassembly, and stack bytes."""
        return self.ok(self._collect_context())

    def handle_status(self, args):
        """Return process liveness and PID of current inferior."""
        inf = gdb.selected_inferior()
        pid = getattr(inf, "pid", 0) or 0
        running = bool(inf.is_valid() and pid > 0 and self.server.inferior_running)
        
        return self.ok({"running": running, "pid": pid, "pid_hex": _hex(pid) if pid > 0 else "0x0"})

    def _collect_context(self):
        """Build a compact execution context snapshot."""
        regs = []
        
        for reg_name in CONTEXT_REGS:
            value = self._eval_register_str(reg_name)
            if value is not None:
                regs.append({"name": reg_name, "value": value})

        pc = self._eval_register("pc")
        sp = self._eval_register("sp")
        if pc is None or sp is None:
            return {"registers": regs, "code": [], "stack": "", "pc": "0x0", "sp": "0x0", "state": "stopped"}

        return {
            "registers": regs,
            "code": self._disassemble(pc),
            "stack": self._read_stack(sp),
            "pc": _hex(pc),
            "sp": _hex(sp),
            "state": "running" if self.server.inferior_running else "stopped",
        }

    def _eval_register(self, reg_name):
        """Read one register and convert it to an integer."""
        try:
            return int(gdb.parse_and_eval("$" + reg_name))
        
        except GDB_ERROR:
            return None

    def _eval_register_str(self, reg_name):
        """Read one register and keep its original GDB string form."""
        try:
            return _hex(gdb.parse_and_eval("$" + reg_name))
        
        except GDB_ERROR:
            return None

    def _disassemble(self, pc):
        """Disassemble a few instructions around PC."""
        try:
            arch = gdb.selected_frame().architecture()
            disasm = arch.disassemble(pc, count=8)
            
        except GDB_ERROR:
            return []
        
        return [{"address": _hex(insn["addr"]), "inst": insn["asm"]} for insn in disasm]

    def _read_stack(self, sp):
        """Read a small stack window at SP as hex."""
        try:
            mem = gdb.selected_inferior().read_memory(sp, 128)
            
        except (GDB_ERROR, MEMORY_ERROR):
            return ""
        
        return mem.tobytes().hex()
