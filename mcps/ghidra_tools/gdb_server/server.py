import gdb
import socket
import json
import os
import sys
import threading
import time
import select
import io

HOST = '0.0.0.0'
PORT = 19090

class GdbMcpServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.threads = []
        
        # Output capture mechanism (Pipe)
        # We create a pipe. The write end (out_w) will be passed to the inferior.
        # The read end (out_r) will be read by a thread in this server.
        self.out_r, self.out_w = os.pipe()
        self.output_buffer = io.BytesIO()
        self.output_lock = threading.Lock()

    def start(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            print(f"[GDB-MCP] Listening on {self.host}:{self.port}")
            
            # Thread 1: Socket Accept Loop
            t_accept = threading.Thread(target=self.accept_loop)
            t_accept.daemon = True
            t_accept.start()
            self.threads.append(t_accept)

            # Thread 2: Output Reader Loop
            t_output = threading.Thread(target=self.output_reader_loop)
            t_output.daemon = True
            t_output.start()
            self.threads.append(t_output)
            
        except OSError as e:
            if e.errno == 98:
                # Silent exit as requested by user (utils.py will connect to the existing instance)
                return
            else:
                print(f"[GDB-MCP] Bind error: {e}")

    def accept_loop(self):
        while self.running:
            try:
                # Use select to allow timeout/checking running flag
                r, _, _ = select.select([self.sock], [], [], 1.0)
                if r:
                    conn, addr = self.sock.accept()
                    print(f"[GDB-MCP] Connected {addr}")
                    t = threading.Thread(target=self.handle_client, args=(conn,))
                    t.daemon = True
                    t.start()
                    self.threads.append(t)
            except Exception as e:
                # print(f"[GDB-MCP] Accept error: {e}")
                pass

    def output_reader_loop(self):
        # Read from pipe non-blocking
        while self.running:
            try:
                r, _, _ = select.select([self.out_r], [], [], 0.1)
                if r:
                    data = os.read(self.out_r, 4096)
                    if data:
                        with self.output_lock:
                            self.output_buffer.write(data)
            except Exception:
                pass

    def handle_client(self, conn):
        buffer = ""
        while self.running:
            try:
                data = conn.recv(65536)
                if not data: break
                buffer += data.decode('utf-8')
                
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if not line.strip(): continue
                    
                    try:
                        req = json.loads(line)
                        self.dispatch_request(conn, req)
                    except Exception as e:
                        print(f"[GDB-MCP] Request handling error: {e}")
                        self.send_response(conn, {"ok": False, "error": str(e)})
                        
            except Exception as e:
                 # print(f"[GDB-MCP] Connection error: {e}")
                 break
        conn.close()

    def send_response(self, conn, resp):
        try:
            conn.sendall((json.dumps(resp) + "\n").encode('utf-8'))
        except: pass

    def dispatch_request(self, conn, req):
        def gdb_task():
            try:
                resp = self.process_request(req)
                self.send_response(conn, resp)
            except Exception as e:
                self.send_response(conn, {"ok": False, "error": f"Exec error: {e}"})

        gdb.post_event(gdb_task)

    def process_request(self, req):
        cmd = req.get('cmd')
        args = req.get('args', {})
        
        # Redirect output to our pipe using /proc/self/fd/N
        # self is GDB (parent). The child inherits, so this works.
        redirect_cmd = f"> /proc/self/fd/{self.out_w} 2>&1 &"

        if cmd == "bridge.ping":
            return {"ok": True, "result": {"alive": True, "mode": "in-process-threaded-pipe"}}
            
        elif cmd == "debug.open":
            binary = args.get('binary')
            argv = args.get('argv', [])
            gdb.execute(f"file {binary}")
            if argv:
                gdb.execute(f"set args {' '.join(argv)}")
            
            if args.get('auto_run'):
                gdb.execute(f"run {redirect_cmd}") 
                
            return {"ok": True, "result": {"status": "opened"}}

        elif cmd == "debug.run":
            gdb.execute(f"run {redirect_cmd}")
            return {"ok": True, "result": {"status": "running"}}
            
        elif cmd == "debug.read_stdout":
            with self.output_lock:
                current_bytes = self.output_buffer.getvalue()
                # Determine if we should clear it. Usually yes, to emulate a stream.
                # If we want to return "new content", we clear.
                self.output_buffer.seek(0)
                self.output_buffer.truncate(0)
            
            # Decode bytes to string
            try:
                decoded = current_bytes.decode('utf-8', errors='replace')
            except:
                decoded = current_bytes.decode('latin-1')
                
            return {"ok": True, "result": {"output": decoded}}

        elif cmd == "debug.attach":
            gdb.execute(f"attach {args.get('pid')}")
            return {"ok": True, "result": {"status": "attached"}}
            
        elif cmd == "debug.list":
            try:
                inf = gdb.selected_inferior()
                pid = inf.pid
                return {"ok": True, "result": [{"id": "1", "pid": pid, "status": "running" if inf.is_valid() else "stopped"}]}
            except:
                return {"ok": True, "result": []}
            
        elif cmd == "debug.cont":
            gdb.execute("continue&") 
            return {"ok": True, "result": {"status": "running"}}

        elif cmd == "debug.interrupt":
            gdb.execute("interrupt") 
            return {"ok": True, "result": {"status": "interrupted"}}

        elif cmd == "debug.stepi":
            gdb.execute("stepi")
            return {"ok": True, "result": {"status": "stepped"}}

        elif cmd == "debug.nexti":
            gdb.execute("nexti")
            return {"ok": True, "result": {"status": "stepped"}}

        elif cmd == "debug.break.set":
            loc = args.get('location')
            if loc.startswith('*'): loc = loc[1:]
            bp = gdb.Breakpoint(loc)
            return {"ok": True, "result": {"number": bp.number, "location": loc}}

        elif cmd == "debug.break.del":
            num = int(args.get('breakpoint'))
            found = False
            for bp in gdb.breakpoints() or []:
                if bp.number == num:
                    bp.delete()
                    found = True
                    break
            if found: return {"ok": True, "result": {"deleted": num}}
            return {"ok": False, "error": "Breakpoint not found"}

        elif cmd == "debug.break.list":
            bps = []
            if gdb.breakpoints():
                for bp in gdb.breakpoints():
                    bps.append({
                        "number": bp.number, 
                        "location": bp.location, 
                        "enabled": bp.enabled
                    })
            return {"ok": True, "result": bps}

        elif cmd == "debug.regs":
            regs = {}
            try:
                for r in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eflags"]:
                    try: val = gdb.parse_and_eval(f"${r}")
                    except: continue
                    regs[r] = int(val)
            except: pass
            return {"ok": True, "result": regs}

        elif cmd == "debug.mem":
            addr = int(args.get('addr'), 16)
            size = int(args.get('size', 64))
            try:
                inf = gdb.selected_inferior()
                mem = inf.read_memory(addr, size)
                return {"ok": True, "result": {"hex": mem.tobytes().hex()}}
            except Exception as e:
                return {"ok": False, "error": str(e)}

        elif cmd == "debug.bt":
            frames = []
            try:
                f = gdb.newest_frame()
                while f:
                    name = f.name() or "??"
                    frames.append({
                        "addr": hex(f.pc()),
                        "func": name,
                    })
                    f = f.older()
            except: pass
            return {"ok": True, "result": frames}

        elif cmd == "debug.context":
            return {"ok": True, "result": self.get_context()}
            
        elif cmd == "debug.cmd":
             val = gdb.execute(args.get('cmd'), to_string=True)
             return {"ok": True, "result": {"output": val}}

        elif cmd == "debug.stdin.write":
            data = args.get('data', '')
            append_newline = args.get('append_newline', False)
            if append_newline:
                data += '\n'
            
            try:
                inf = gdb.selected_inferior()
                pid = inf.pid
                if not pid or pid == 0:
                     return {"ok": False, "error": "No inferior running"}
                
                # Write to /proc/PID/fd/0 for WSL/Linux
                fd_path = f"/proc/{pid}/fd/0"
                with open(fd_path, "wb") as f:
                    f.write(data.encode('utf-8'))
                    f.flush()
                
                return {"ok": True, "result": {"written": len(data)}}
            except Exception as e:
                return {"ok": False, "error": f"Stdin write failed: {e}"}

        return {"ok": False, "error": f"Unknown command: {cmd}"}

    def get_context(self):
        regs = []
        common_regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags"]
        
        for rname in common_regs:
            try:
                val = gdb.parse_and_eval(f"${rname}")
                regs.append({"name": rname, "value": str(val)})
            except: pass
                
        pc = int(gdb.parse_and_eval("$pc"))
        sp = int(gdb.parse_and_eval("$sp"))
        
        code = []
        try:
             arch = gdb.selected_frame().architecture()
             disasm = arch.disassemble(pc, count=8)
             for insn in disasm:
                 code.append({"address": hex(insn['addr']), "inst": insn['asm']})
        except: pass

        stack = ""
        try:
            inf = gdb.selected_inferior()
            mem = inf.read_memory(sp, 128)
            stack = mem.tobytes().hex()
        except: pass

        return {
            "registers": regs,
            "code": code,
            "stack": stack,
            "pc": hex(pc),
            "sp": hex(sp),
            "state": "stopped"
        }

if __name__ == "__main__":
    server = GdbMcpServer(HOST, PORT)
    server.start()
