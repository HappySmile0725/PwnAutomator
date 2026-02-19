from . import GdbHandler
import gdb

HEX_CHARS = set("0123456789abcdefABCDEF")


def _is_hex_text(text):
    if not text:
        return False
    for ch in text:
        if ch not in HEX_CHARS:
            return False
    return True


def _normalize_breakpoint_location(location):
    text = str(location or "").strip()
    if not text:
        return ""

    if text.startswith("*"):
        return text

    if ":" in text:
        # Ghidra-style address like "ram:00401234" -> absolute address expression.
        suffix = text.rsplit(":", 1)[1]
        if _is_hex_text(suffix):
            return "*0x" + suffix

    if text.startswith("0x") and _is_hex_text(text[2:]):
        return "*" + text

    if _is_hex_text(text):
        return "*0x" + text

    return text


class BreakpointsHandler(GdbHandler):
    """Handle create/delete/list breakpoint commands."""

    def handle_break_set(self, args):
        args = args or {}
        location = args.get("location")
        
        if not location:
            return self.err("location required")
        
        location = _normalize_breakpoint_location(location)
        if not location:
            return self.err("location required")
        
        bp = gdb.Breakpoint(location)
        
        return self.ok({"number": bp.number, "location": location, "resolved": bp.location})

    def handle_break_del(self, args):
        args = args or {}
        
        try:
            number = int(args.get("breakpoint"))
            
        except (TypeError, ValueError):
            return self.err("valid breakpoint id required")

        for bp in gdb.breakpoints() or []:
            if bp.number == number:
                bp.delete()
                return self.ok({"deleted": number})
            
        return self.err("Breakpoint not found")

    def handle_break_list(self, args):
        bps = gdb.breakpoints() or []
        
        return self.ok(
            [{"number": bp.number, "location": bp.location, "enabled": bp.enabled} for bp in bps])
