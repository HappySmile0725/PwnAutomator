# -*- coding: utf-8 -*-
# @author
# @category Analysis
# @runtime Jython

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import SymbolType

def resolve_target_to_function(target):
    t = target.strip()

    fm = currentProgram.getFunctionManager()
    symtab = currentProgram.getSymbolTable()

    # 1) Address form: 0x...
    if t.lower().startswith("0x"):
        addr = currentProgram.getAddressFactory().getAddress(t)
        if addr is None:
            return None
        f = getFunctionAt(addr)
        if f is None:
            f = getFunctionContaining(addr)
        return f

    # 2) Name/symbol: search symbols, prefer function symbols
    it = symtab.getSymbols(t).iterator()
    best_addr = None

    while it.hasNext():
        sym = it.next()
        st = sym.getSymbolType()
        if st == SymbolType.FUNCTION:
            best_addr = sym.getAddress()
            break
        if best_addr is None:
            best_addr = sym.getAddress()

    if best_addr is None:
        return None

    f = getFunctionAt(best_addr)
    if f is None:
        f = getFunctionContaining(best_addr)
    return f

def decompile_function(func, timeout_sec):
    ifc = DecompInterface()
    if not ifc.openProgram(currentProgram):
        printerr("Failed to open program in decompiler")
        return

    res = ifc.decompileFunction(func, timeout_sec, ConsoleTaskMonitor())
    if not res.decompileCompleted():
        printerr("Decompile failed for %s" % func.getName())
        return

    cfunc = res.getDecompiledFunction()
    print(cfunc.getC())

def main():
    if currentProgram is None:
        printerr("No program context. Use -import or -process.")
        return

    args = getScriptArgs()
    if len(args) < 1:
        printerr("Usage: decompile.py <addr|symbol> [timeout_sec]")
        printerr("  ex) decompile.py 0x4014c7")
        printerr("  ex) decompile.py main 60")
        return

    target = args[0]
    timeout_sec = int(args[1]) if len(args) >= 2 else 30

    func = resolve_target_to_function(target)
    if func is None:
        printerr("Could not resolve to a function: %s" % target)
        return

    decompile_function(func, timeout_sec)

main()
