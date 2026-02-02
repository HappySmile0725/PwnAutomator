# @author
# @category Analysis
# @runtime Jython
# -*- coding: utf-8 -*-

from ghidra.program.model.address import Address
from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.model.listing import Instruction

def parse_addr(s):
    return currentProgram.getAddressFactory().getAddress(s)

def read_hex(mem, addr, size=8):
    data = mem.getBytes(addr, size)
    return "0x" + "".join(["%02x" % (b & 0xff) for b in data])

def read_dec(mem, addr, size=8):
    data = mem.getBytes(addr, size)
    val = 0
    for i in range(size - 1, -1, -1):
        val = (val << 8) | (data[i] & 0xff)
    return str(val)

def read_str(mem, addr, maxlen=256):
    out = []
    for i in range(maxlen):
        b = mem.getByte(addr.add(i))
        if b == 0:
            break
        out.append(chr(b & 0xff))
    return "".join(out)

def read_insn(listing, addr, count=1):
    lines = []
    cur = addr
    for _ in range(count):
        ins = listing.getInstructionAt(cur)
        if ins is None:
            break
        lines.append("%s: %s" % (ins.getAddress(), ins.toString()))
        nxt = ins.getNext()
        if nxt is not None:
            cur = nxt.getAddress()
        else:
            cur = cur.add(ins.getLength())
    return "\n".join(lines)

def main():
    args = getScriptArgs()
    if len(args) < 2:
        printerr("Usage: ReadMemory.py <addr> <hex|dec|str|ins> [size|count|maxlen]")
        printerr("  hex/dec: [size] default=8 (bytes)")
        printerr("  str:     [maxlen] default=256")
        printerr("  ins:     [count] default=1 (instructions)")
        return

    if currentProgram is None:
        printerr("No program context. Use -import or -process.")
        return

    addr_str = args[0]
    mode = args[1].strip().lower()

    mem = currentProgram.getMemory()
    listing = currentProgram.getListing()
    addr = parse_addr(addr_str)

    try:
        if addr is None:
            printerr("Invalid address: %s" % addr_str)
            return

        if not mem.contains(addr):
            printerr("Address not mapped: %s" % addr)
            return

        if mode == "hex":
            size = int(args[2]) if len(args) >= 3 else 8
            print("%s = %s" % (addr, read_hex(mem, addr, size)))

        elif mode == "dec":
            size = int(args[2]) if len(args) >= 3 else 8
            print("%s = %s" % (addr, read_dec(mem, addr, size)))

        elif mode == "str":
            maxlen = int(args[2]) if len(args) >= 3 else 256
            print("%s = \"%s\"" % (addr, read_str(mem, addr, maxlen)))

        elif mode == "ins" or mode == "asm":
            count = int(args[2]) if len(args) >= 3 else 1
            out = read_insn(listing, addr, count)
            if out:
                print(out)
            else:
                printerr("No instruction at %s" % addr)

        else:
            printerr("Unknown mode: %s (use hex|dec|str|ins)" % mode)

    except MemoryAccessException:
        printerr("Memory access error at %s" % addr)
    except Exception as e:
        printerr("Error: %s" % str(e))

main()
