# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, sys.path[0] + "/..")
from utils import GhidraContext as ctx

class FunctionsHandler:
    """functions cmds"""
    
    @staticmethod
    def list_all(args):
        """all functions info"""
        result = []
        for f in ctx.fm.getFunctions(True):
            name = f.getName()
            result.append({
                "addr": str(f.getEntryPoint()),
                "name": name,
                "has_symbol": not name.startswith("FUN_"),
                "size": f.getBody().getNumAddresses()
            })
        return result
    
    @staticmethod
    def get_by_name(args):
        """info by function name"""
        name = args.get("name")
        funcs = ctx.fm.getFunctions(True)
        for f in funcs:
            if f.getName() == name:
                return {
                    "addr": str(f.getEntryPoint()),
                    "name": f.getName(),
                    "size": f.getBody().getNumAddresses(),
                    "params": [str(p) for p in f.getParameters()],
                    "return_type": str(f.getReturnType())
                }
        return {"error": "Function not found: %s" % name}
    
    @staticmethod
    def get_by_addr(args):
        """info by address"""
        addr = ctx.addr(args.get("addr"))
        func = ctx.fm.getFunctionContaining(addr)
        if func:
            return {
                "addr": str(func.getEntryPoint()),
                "name": func.getName(),
                "size": func.getBody().getNumAddresses(),
                "params": [str(p) for p in func.getParameters()],
                "return_type": str(func.getReturnType())
            }
        return {"error": "No function at address"}

# handlers
COMMANDS = {
    "func.list": FunctionsHandler.list_all,
    "func.name": FunctionsHandler.get_by_name,
    "func.addr": FunctionsHandler.get_by_addr,
}