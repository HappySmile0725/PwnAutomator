# -*- coding: utf-8 -*-
import jarray

class GhidraContext:
    program = None
    mem = None
    listing = None
    fm = None
    af = None
    decomp = None
    
    @classmethod
    def init(cls, currentProgram):
        from ghidra.app.decompiler import DecompInterface
        
        cls.program = currentProgram
        cls.mem = currentProgram.getMemory()
        cls.listing = currentProgram.getListing()
        cls.fm = currentProgram.getFunctionManager()
        cls.af = currentProgram.getAddressFactory()
        cls.decomp = DecompInterface()
        cls.decomp.openProgram(currentProgram)
    
    @classmethod
    def addr(cls, s):
        """str → Address convert"""
        return cls.af.getAddress(s)
    
    @classmethod
    def read_bytes(cls, addr, size):
        """read byte array from memory"""
        data = jarray.zeros(size, 'b')
        cls.mem.getBytes(addr, data)
        return [(b & 0xff) for b in data]