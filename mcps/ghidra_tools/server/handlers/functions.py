# -*- coding: utf-8 -*-
from utils import GhidraContext as ctx


def _addr_hex(addr):
    return "0x%x" % int(addr.getOffset())


def _function_payload(func):
    return {
        "addr": _addr_hex(func.getEntryPoint()),
        "name": func.getName(),
        "size": func.getBody().getNumAddresses(),
        "params": [str(p) for p in func.getParameters()],
        "return_type": str(func.getReturnType()),
    }


class FunctionsHandler:
    """functions cmds"""
    
    @staticmethod
    def list_all(args):
        """all functions info"""
        result = []
        for func in ctx.fm.getFunctions(True):
            name = func.getName()
            result.append({
                "addr": _addr_hex(func.getEntryPoint()),
                "name": name,
                "has_symbol": not name.startswith("FUN_"),
                "size": func.getBody().getNumAddresses()
            })
        return result
    
    @staticmethod
    def get_by_name(args):
        """info by function name"""
        name = args.get("name")
        for func in ctx.fm.getFunctions(True):
            if func.getName() == name:
                return _function_payload(func)
        return {"error": "Function not found: %s" % name}
    
    @staticmethod
    def get_by_addr(args):
        """info by address"""
        addr = ctx.addr(args.get("addr"))
        func = ctx.fm.getFunctionContaining(addr)
        if func:
            return _function_payload(func)
        return {"error": "No function at address"}

COMMANDS = {
    "func.list": FunctionsHandler.list_all,
    "func.name": FunctionsHandler.get_by_name,
    "func.addr": FunctionsHandler.get_by_addr,
}
