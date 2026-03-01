# -*- coding: utf-8 -*-
from utils import GhidraContext as ctx


def _addr_hex(addr):
    return "0x%x" % int(addr.getOffset())


def _decompile_func(func):
    decomp = ctx.ensure_decomp()
    result = decomp.decompileFunction(func, 30, None)
    if not (result and result.decompileCompleted()):
        return None
    return {
        "name": func.getName(),
        "addr": _addr_hex(func.getEntryPoint()),
        "code": result.getDecompiledFunction().getC(),
    }


class DecompileHandler:
    """decompile cmds"""
    
    @staticmethod
    def by_addr(args):
        """decompile by address"""
        addr = ctx.addr(args.get("addr"))
        func = ctx.fm.getFunctionContaining(addr)
        
        if func is None:
            return {"error": "No function at address: %s" % args.get("addr")}
        
        decompiled = _decompile_func(func)
        if decompiled:
            return decompiled
        return {"error": "Decompilation failed"}
    
    @staticmethod
    def by_name(args):
        """decompile by function name"""
        name = args.get("name")
        
        for func in ctx.fm.getFunctions(True):
            if func.getName() == name:
                decompiled = _decompile_func(func)
                if decompiled:
                    decompiled["name"] = name
                    return decompiled
                return {"error": "Decompilation failed"}
        
        return {"error": "Function not found: %s" % name}

COMMANDS = {
    "decompile.addr": DecompileHandler.by_addr,
    "decompile.name": DecompileHandler.by_name,
}
