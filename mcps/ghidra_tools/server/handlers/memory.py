# -*- coding: utf-8 -*-
import sys
sys.path.insert(0, sys.path[0] + "/..")
from utils import GhidraContext as ctx

class MemoryHandler:
    """memory read commands"""
    
    @staticmethod
    def read_hex(args):
        """read hex"""
        addr = ctx.addr(args.get("addr"))
        size = args.get("size", 8)
        data = ctx.read_bytes(addr, size)
        
        chunks = []
        for i in range(0, size, 8):
            chunk = data[i:i+8]
            # little-endian
            hex_str = "".join("%02x" % b for b in reversed(chunk))
            chunks.append("0x" + hex_str)
        
        return {"addr": str(addr), "value": " ".join(chunks)}
    
    @staticmethod
    def read_dec(args):
        """read decimal"""
        addr = ctx.addr(args.get("addr"))
        size = args.get("size", 8)
        data = ctx.read_bytes(addr, size)
        
        val = 0
        for i, b in enumerate(data):
            val |= (b << (i * 8))
        
        return {"addr": str(addr), "value": val}
    
    @staticmethod
    def read_str(args):
        """read string"""
        addr = ctx.addr(args.get("addr"))
        maxlen = args.get("maxlen", 256)
        
        out = []
        for i in range(maxlen):
            b = ctx.mem.getByte(addr.add(i)) & 0xff
            if b == 0:
                break
            out.append(chr(b) if 0x20 <= b <= 0x7e else "\\x%02x" % b)
        
        return {"addr": str(addr), "value": "".join(out)}
    
    @staticmethod
    def read_asm(args):
        """read assembly instructions"""
        addr = ctx.addr(args.get("addr"))
        count = args.get("count", 5)
        
        result = []
        cur = addr
        for _ in range(count):
            ins = ctx.listing.getInstructionAt(cur)
            if ins is None:
                break
            
            bytes_str = " ".join("%02x" % (b & 0xff) for b in ins.getBytes())
            result.append({
                "addr": str(cur),
                "bytes": bytes_str,
                "mnemonic": ins.getMnemonicString(),
                "operands": ins.toString()
            })
            cur = cur.add(ins.getLength())
        
        return result

# handlers
COMMANDS = {
    "mem.hex": MemoryHandler.read_hex,
    "mem.dec": MemoryHandler.read_dec,
    "mem.str": MemoryHandler.read_str,
    "mem.asm": MemoryHandler.read_asm,
}