# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, sys.path[0] + "/..")
from utils import GhidraContext as ctx

class DecompileHandler:
    """decompile cmds"""
    
    @staticmethod
    def by_addr(args):
        """decompile by address"""
        addr = ctx.addr(args.get("addr"))
        func = ctx.fm.getFunctionContaining(addr)
        
        if func is None:
            return {"error": "No function at address: %s" % args.get("addr")}
        
        result = ctx.decomp.decompileFunction(func, 30, None)
        
        if result and result.decompileCompleted():
            return {
                "name": func.getName(),
                "addr": str(func.getEntryPoint()),
                "code": result.getDecompiledFunction().getC()
            }
        return {"error": "Decompilation failed"}
    
    @staticmethod
    def by_name(args):
        """decompile by function name"""
        name = args.get("name")
        
        for func in ctx.fm.getFunctions(True):
            if func.getName() == name:
                result = ctx.decomp.decompileFunction(func, 30, None)
                if result and result.decompileCompleted():
                    return {
                        "name": name,
                        "addr": str(func.getEntryPoint()),
                        "code": result.getDecompiledFunction().getC()
                    }
                return {"error": "Decompilation failed"}
        
        return {"error": "Function not found: %s" % name}

# handlers
COMMANDS = {
    "decompile.addr": DecompileHandler.by_addr,
    "decompile.name": DecompileHandler.by_name,
}