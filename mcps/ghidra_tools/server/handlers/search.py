# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, sys.path[0] + "/..")
from utils import GhidraContext as ctx
import jarray

class SearchHandler:
    """search cmds"""
    
    @staticmethod
    def func_by_pattern(args):
        """search functions by name pattern"""
        pattern = args.get("pattern", "").lower()
        result = []
        
        for f in ctx.fm.getFunctions(True):
            if pattern in f.getName().lower():
                result.append({
                    "addr": str(f.getEntryPoint()),
                    "name": f.getName()
                })
        
        return result
    
    @staticmethod
    def string(args):
        """string search"""
        from ghidra.program.util import DefinedDataIterator
        
        pattern = args.get("pattern", "").lower()
        result = []
        
        for data in DefinedDataIterator.definedStrings(ctx.program):
            val = str(data.getValue())
            if pattern in val.lower():
                result.append({
                    "addr": str(data.getAddress()),
                    "value": val
                })
                if len(result) >= 50:  # limit results
                    break
        
        return result
    
    @staticmethod
    def bytes_pattern(args):
        """specific byte pattern search"""
        from ghidra.program.model.mem import MemoryBytePatternSearcher
        
        pattern = args.get("pattern")  # ex: "90 90 90"
        max_results = args.get("max", 20)
        
        # parse pattern
        bytes_list = [int(b, 16) for b in pattern.split()]
        search_bytes = jarray.array([b & 0xff for b in bytes_list], 'b')
        
        result = []
        mem = ctx.mem
        
        for block in mem.getBlocks():
            if not block.isInitialized():
                continue
            
            start = block.getStart()
            end = block.getEnd()
            
            addr = mem.findBytes(start, end, search_bytes, None, True, None)
            while addr and len(result) < max_results:
                result.append(str(addr))
                addr = mem.findBytes(addr.add(1), end, search_bytes, None, True, None)
        
        return result
    
    @staticmethod
    def xrefs_to(args):
        """specific address to references search"""
        from ghidra.program.model.symbol import ReferenceManager
        
        addr = ctx.addr(args.get("addr"))
        result = []
        
        refs = ctx.program.getReferenceManager().getReferencesTo(addr)
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = ctx.fm.getFunctionContaining(from_addr)
            result.append({
                "from": str(from_addr),
                "func": func.getName() if func else None,
                "type": str(ref.getReferenceType())
            })
        
        return result
    
    @staticmethod
    def xrefs_from(args):
        """specific address from references search"""
        addr = ctx.addr(args.get("addr"))
        result = []
        
        refs = ctx.program.getReferenceManager().getReferencesFrom(addr)
        for ref in refs:
            to_addr = ref.getToAddress()
            func = ctx.fm.getFunctionContaining(to_addr)
            result.append({
                "to": str(to_addr),
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