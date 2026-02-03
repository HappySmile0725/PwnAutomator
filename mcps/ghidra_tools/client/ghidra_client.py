#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import json

class GhidraMCP:
    def __init__(self, host='127.0.0.1', port=9999):
        self.host = host
        self.port = port
    
    def call(self, cmd, **args):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        sock.send(json.dumps({"cmd": cmd, "args": args}).encode())
        data = sock.recv(65536).decode()
        sock.close()
        
        res = json.loads(data)
        if res.get("ok"):
            return res.get("result")
        raise Exception(res.get("error"))
    
    # 편의 메서드
    def meta(self, binary_path=None):
        if binary_path:
            return self.call("meta", binary_path=binary_path)
        return self.call("meta")
    
    def functions(self):
        return self.call("func.list")
    
    def func(self, name=None, addr=None):
        if name:
            return self.call("func.name", name=name)
        return self.call("func.addr", addr=addr)
    
    def hex(self, addr, size=8):
        return self.call("mem.hex", addr=addr, size=size)
    
    def dec(self, addr, size=8):
        return self.call("mem.dec", addr=addr, size=size)
    
    def string(self, addr, maxlen=256):
        return self.call("mem.str", addr=addr, maxlen=maxlen)
    
    def asm(self, addr, count=5):
        return self.call("mem.asm", addr=addr, count=count)
    
    def decompile(self, name=None, addr=None):
        if name:
            return self.call("decompile.name", name=name)
        return self.call("decompile.addr", addr=addr)
    
    def search_func(self, pattern):
        return self.call("search.func", pattern=pattern)
    
    def search_str(self, pattern):
        return self.call("search.str", pattern=pattern)
    
    def search_bytes(self, pattern, max=20):
        return self.call("search.bytes", pattern=pattern, max=max)
    
    def xrefs_to(self, addr):
        return self.call("search.xrefs_to", addr=addr)
    
    def xrefs_from(self, addr):
        return self.call("search.xrefs_from", addr=addr)


if __name__ == "__main__":
    g = GhidraMCP()
    
    # example usage
    print("=== Meta ===")
    print(g.meta())
    
    print("\n=== Functions ===")
    for f in g.functions():
        print(f"{f['addr']}\t{f['name']}")
    
    print("\n=== Decompile main ===")
    print(g.decompile(name="main")["code"])
    
    print("\n=== Search 'main' ===")
    print(g.search_func("main"))
