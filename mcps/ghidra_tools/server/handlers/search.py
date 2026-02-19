# -*- coding: utf-8 -*-
import jarray
from utils import GhidraContext as ctx

HEX_CHARS = set("0123456789abcdefABCDEF")


def _to_non_negative_int(value, default):
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    return default


def _parse_byte_token(token):
    text = str(token).strip()
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    if len(text) == 0 or len(text) > 2:
        return None
    for ch in text:
        if ch not in HEX_CHARS:
            return None
    return int(text, 16)


def _to_signed_byte(value):
    if value <= 0x7F:
        return value
    return value - 0x100


def _addr_hex(addr):
    return "0x%x" % int(addr.getOffset())


class SearchHandler:
    """search cmds"""
    
    @staticmethod
    def func_by_pattern(args):
        """search functions by name pattern"""
        args = args or {}
        pattern = args.get("pattern", "").lower()
        result = []
        
        for func in ctx.fm.getFunctions(True):
            if pattern in func.getName().lower():
                result.append({
                    "addr": _addr_hex(func.getEntryPoint()),
                    "name": func.getName()
                })
        
        return result
    
    @staticmethod
    def string(args):
        """string search"""
        args = args or {}
        pattern = args.get("pattern", "").lower()
        max_results = _to_non_negative_int(args.get("max", 50), 50)

        result = []

        # Avoid version-specific DefinedDataIterator helpers and walk defined data directly.
        it = ctx.listing.getDefinedData(True)
        while it.hasNext():
            data = it.next()

            has_string_value = getattr(data, "hasStringValue", None)
            is_string = bool(has_string_value()) if callable(has_string_value) else False

            if not is_string:
                dt = data.getDataType()
                get_display_name = getattr(dt, "getDisplayName", None)
                dt_name = str(get_display_name() if callable(get_display_name) else dt).lower()
                if ("string" in dt_name) or ("unicode" in dt_name):
                    is_string = True

            if not is_string:
                continue

            value_obj = data.getValue()
            val = str(value_obj) if value_obj is not None else str(data.getDefaultValueRepresentation())

            if pattern in val.lower():
                result.append({
                    "addr": _addr_hex(data.getAddress()),
                    "value": val
                })
                if len(result) >= max_results:
                    break
        
        return result
    
    @staticmethod
    def bytes_pattern(args):
        """specific byte pattern search"""
        args = args or {}
        pattern = str(args.get("pattern", "")).strip()  # ex: "90 90 90"
        max_results = _to_non_negative_int(args.get("max", 20), 20)

        if not pattern:
            return {"error": "pattern required"}

        tokens = pattern.split()
        if not tokens:
            return {"error": "pattern required"}

        # parse pattern
        bytes_list = []
        for token in tokens:
            parsed = _parse_byte_token(token)
            if parsed is None:
                return {"error": "invalid pattern token: %s" % token}
            bytes_list.append(parsed)

        search_bytes = jarray.array([_to_signed_byte(b) for b in bytes_list], 'b')
        
        result = []
        mem = ctx.mem
        
        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            
            start = block.getStart()
            end = block.getEnd()
            
            addr = mem.findBytes(start, end, search_bytes, None, True, None)
            while addr and len(result) < max_results:
                result.append(_addr_hex(addr))
                addr = mem.findBytes(addr.add(1), end, search_bytes, None, True, None)
        
        return result
    
    @staticmethod
    def xrefs_to(args):
        """specific address to references search"""
        args = args or {}
        addr = ctx.addr(args.get("addr"))
        result = []
        
        refs = ctx.program.getReferenceManager().getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = ctx.fm.getFunctionContaining(from_addr)
            result.append({
                "from": _addr_hex(from_addr),
                "func": func.getName() if func else None,
                "type": str(ref.getReferenceType())
            })
        
        return result
    
    @staticmethod
    def xrefs_from(args):
        """specific address from references search"""
        args = args or {}
        addr = ctx.addr(args.get("addr"))
        result = []
        
        refs = ctx.program.getReferenceManager().getReferencesFrom(addr)
        for ref in refs:
            to_addr = ref.getToAddress()
            func = ctx.fm.getFunctionContaining(to_addr)
            result.append({
                "to": _addr_hex(to_addr),
                "func": func.getName() if func else None,
                "type": str(ref.getReferenceType())
            })
        
        return result

# handlers
COMMANDS = {
    "search.func": SearchHandler.func_by_pattern,
    "search.str": SearchHandler.string,
    "search.bytes": SearchHandler.bytes_pattern,
    "search.xrefs_to": SearchHandler.xrefs_to,
    "search.xrefs_from": SearchHandler.xrefs_from,
}
