# @author 
# @category Analysis
# @runtime Jython
# -*- coding: utf-8 -*-
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.symbol import SourceType

def main():
    fm = currentProgram.getFunctionManager()
    it = fm.getFunctions(True)

    while it.hasNext() and not monitor.isCancelled():
        f = it.next()
        ea = f.getEntryPoint()

        name = None
        try:
            sym = f.getSymbol()
            if sym is not None:
                name = sym.getName()
        except:
            name = None

        if name:
            print("{}\t{}".format(ea, name))
        else:
            print("{}".format(ea))

main()
