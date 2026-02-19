# -*- coding: utf-8 -*-
from utils import GhidraContext as ctx


def _addr_hex(addr):
    return "0x%x" % int(addr.getOffset())


def _value_hex(value):
    return "0x%x" % int(value)


def _to_positive_int(value, default_value):
    text = str(value).strip()
    if text.isdigit():
        parsed = int(text)
        if parsed > 0:
            return parsed
    return default_value


def _parse_addr(args):
    try:
        return ctx.addr(args.get("addr")), None
    except BaseException as exc:
        return None, "invalid address: %s" % str(exc)


def _read_bytes(addr, size):
    try:
        return ctx.read_bytes(addr, size), None
    except BaseException as exc:
        return None, "unable to read memory at %s: %s" % (_addr_hex(addr), str(exc))


class MemoryHandler:
    """memory read commands"""
    
    @staticmethod
    def read_hex(args):
        """read hex"""
        addr, addr_err = _parse_addr(args)
        if addr_err:
            return {"error": addr_err}

        size = _to_positive_int(args.get("size", 8), 8)
        data, read_err = _read_bytes(addr, size)
        if read_err:
            return {"error": read_err}
        
        chunks = []
        for i in range(0, size, 8):
            chunk = data[i:i + 8]
            
            hex_str = "".join("%02x" % b for b in reversed(chunk))
            chunks.append("0x" + hex_str)
        
        return {"addr": _addr_hex(addr), "value": " ".join(chunks)}
    
    @staticmethod
    def read_dec(args):
        """read integer value (hex-first)"""
        addr, addr_err = _parse_addr(args)
        if addr_err:
            return {"error": addr_err}

        size = _to_positive_int(args.get("size", 8), 8)
        data, read_err = _read_bytes(addr, size)
        if read_err:
            return {"error": read_err}
        
        val = 0
        for i, b in enumerate(data):
            val |= (b << (i * 8))
        
        return {"addr": _addr_hex(addr), "value": _value_hex(val), "value_dec": val}
    
    @staticmethod
    def read_str(args):
        """read string"""
        addr, addr_err = _parse_addr(args)
        if addr_err:
            return {"error": addr_err}

        maxlen = _to_positive_int(args.get("maxlen", 256), 256)
        data, read_err = _read_bytes(addr, maxlen)
        if read_err:
            return {"error": read_err}

        out = []
        for b in data:
            if b == 0:
                break
            out.append(chr(b) if 0x20 <= b <= 0x7e else "\\x%02x" % b)
        
        return {"addr": _addr_hex(addr), "value": "".join(out)}
    
    @staticmethod
    def read_asm(args):
        """read assembly instructions"""
        addr, addr_err = _parse_addr(args)
        if addr_err:
            return {"error": addr_err}

        count = _to_positive_int(args.get("count", 5), 5)
        
        result = []
        cur = addr
        try:
            for _ in range(count):
                ins = ctx.listing.getInstructionAt(cur)
                if ins is None:
                    break
                
                bytes_str = " ".join("%02x" % (b & 0xff) for b in ins.getBytes())
                result.append({
                    "addr": _addr_hex(cur),
                    "bytes": bytes_str,
                    "mnemonic": ins.getMnemonicString(),
                    "operands": ins.toString()
                })
                cur = cur.add(ins.getLength())
        except BaseException as exc:
            return {"error": "unable to decode instruction at %s: %s" % (_addr_hex(cur), str(exc))}
        
        return result

COMMANDS = {
    "mem.hex": MemoryHandler.read_hex,
    "mem.dec": MemoryHandler.read_dec,
    "mem.str": MemoryHandler.read_str,
    "mem.asm": MemoryHandler.read_asm,
}
