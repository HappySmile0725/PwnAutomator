import gdb
import json
import errno
import fcntl
import os
import pty
import select
import socket
import sys
import threading
from collections import deque

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from handlers.breakpoints import BreakpointsHandler
from handlers.execution import ExecutionHandler
from handlers.io import IOHandler
from handlers.management import ManagementHandler
from handlers.state import StateHandler

HOST = '0.0.0.0'
PORT = 19090

class GdbMcpServer:
    """Serve MCP debug commands over TCP from inside a GDB process."""

    def __init__(self, host, port):
        """Initialize server socket state, handlers, and event queue."""
        self.host = host
        self.port = port
        self.sock = None
        self.running = False
        self.event_queue = deque()
        self.event_lock = threading.Lock()
        self.io_lock = threading.Lock()
        self.sessions = {}
        self.inferior_running = False
        self.tty_master_fd = None
        self.tty_slave_fd = None
        self.tty_slave_path = None

        self.configure_gdb()
        self.init_handlers()
        self.register_event_handlers()

    def configure_gdb(self):
        """Disable interactive prompts that can block MCP command handling."""
        gdb.execute("set confirm off")
        gdb.execute("set pagination off")
        self.reset_tty()

    @staticmethod
    def _set_nonblocking(fd):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def reset_tty(self):
        """Create a fresh PTY pair for inferior stdin/stdout/stderr."""
        with self.io_lock:
            if self.tty_master_fd is not None:
                os.close(self.tty_master_fd)
                self.tty_master_fd = None
            if self.tty_slave_fd is not None:
                os.close(self.tty_slave_fd)
                self.tty_slave_fd = None

            master_fd, slave_fd = pty.openpty()
            self._set_nonblocking(master_fd)
            self.tty_master_fd = master_fd
            self.tty_slave_fd = slave_fd
            self.tty_slave_path = os.ttyname(slave_fd)

    def read_tty_output(self, max_bytes):
        """Read currently available inferior PTY output without blocking."""
        if self.tty_master_fd is None:
            return b""

        chunks = []
        total = 0
        limit = int(max_bytes) if int(max_bytes) > 0 else 65536

        with self.io_lock:
            while total < limit:
                try:
                    chunk = os.read(self.tty_master_fd, min(4096, limit - total))
                except OSError as exc:
                    if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK, errno.EIO):
                        break
                    raise

                if not chunk:
                    break

                chunks.append(chunk)
                total += len(chunk)
                if len(chunk) < 4096:
                    break

        return b"".join(chunks)

    def write_tty_input(self, payload):
        """Write bytes to inferior PTY stdin without blocking."""
        if self.tty_master_fd is None:
            raise OSError(errno.ENXIO, "tty not initialized")

        with self.io_lock:
            return os.write(self.tty_master_fd, payload)

    def tty_target_path(self):
        """Return a stable path that GDB can use for inferior-tty."""
        if self.tty_slave_fd is not None:
            proc_fd_path = "/proc/%d/fd/%d" % (os.getpid(), self.tty_slave_fd)
            if os.path.exists(proc_fd_path):
                return proc_fd_path

        if self.tty_slave_path and os.path.exists(self.tty_slave_path):
            return self.tty_slave_path

        return ""

    def init_handlers(self):
        """Instantiate handlers and bind command routing table."""
        self.mgmt = ManagementHandler(self)
        self.ex = ExecutionHandler(self)
        self.bp = BreakpointsHandler(self)
        self.st = StateHandler(self)
        self.io = IOHandler(self)

        self.cmd_map = {
            "bridge.ping": self.mgmt.handle_ping,
            "debug.open": self.mgmt.handle_open,
            "debug.attach": self.mgmt.handle_attach,
            "debug.list": self.mgmt.handle_list,
            "debug.close": self.mgmt.handle_close,
            
            "debug.run": self.ex.handle_run,
            "debug.cont": self.ex.handle_cont,
            "debug.interrupt": self.ex.handle_interrupt,
            "debug.stepi": self.ex.handle_stepi,
            "debug.nexti": self.ex.handle_nexti,
            
            "debug.break.set": self.bp.handle_break_set,
            "debug.break.del": self.bp.handle_break_del,
            "debug.break.list": self.bp.handle_break_list,
            
            "debug.regs": self.st.handle_regs,
            "debug.mem": self.st.handle_mem,
            "debug.bt": self.st.handle_bt,
            "debug.context": self.st.handle_context,
            "debug.status": self.st.handle_status,
            
            "debug.read_stdout": self.io.handle_read_stdout,
            "debug.stdin.write": self.io.handle_stdin_write,
            "debug.cmd": self.io.handle_cmd,
            "debug.events.poll": self.io.handle_events_poll
        }

    def register_event_handlers(self):
        """Forward core GDB async events into the server queue."""

        def push_event(event_type, event):
            with self.event_lock:
                self.event_queue.append({"type": event_type, "payload": str(event)})

        def on_stop(event):
            self.inferior_running = False
            push_event("stop", event)

        def on_cont(event):
            self.inferior_running = True
            push_event("continue", event)

        def on_exit(event):
            self.inferior_running = False
            push_event("exit", event)

        gdb.events.stop.connect(on_stop)
        gdb.events.cont.connect(on_cont)
        gdb.events.exited.connect(on_exit)

    def start(self):
        """Bind and start the client accept loop thread."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            print(f"[GDB-MCP] Listening on {self.host}:{self.port}", flush=True)

            threading.Thread(target=self.accept_loop, daemon=True).start()
            
        except OSError as e:
            if getattr(e, "errno", None) == 98:
                return
            
            print(f"[GDB-MCP] Bind error: {e}", flush=True)

    def accept_loop(self):
        """Accept clients and assign a daemon thread per connection."""
        while self.running:
            try:
                r, _, _ = select.select([self.sock], [], [], 1.0)
                if r:
                    conn, addr = self.sock.accept()
                    print(f"[GDB-MCP] Connected {addr}")
                    threading.Thread(target=self.handle_client, args=(conn,), daemon=True).start()
                    
            except OSError:
                if not self.running:
                    break

    def handle_client(self, conn):
        """Read JSONL requests from one client and dispatch each command."""
        buffer = ""
        while self.running:
            try:
                data = conn.recv(65536)
            except OSError:
                break

            if not data:
                break
            buffer += data.decode("utf-8", "replace")

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    self.dispatch_request(conn, json.loads(line))
                except ValueError as exc:
                    self.send_response(conn, {"ok": False, "error": "Invalid JSON: " + str(exc)})

        conn.close()

    def send_response(self, conn, resp):
        """Send a single JSON response line to a client."""
        try:
            conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
            
        except OSError:
            pass

    def dispatch_request(self, conn, req):
        """Queue request execution onto the main GDB event loop."""
        def gdb_task():
            try:
                resp = self.process_request(req)
                self.send_response(conn, resp)
                
            except Exception as exc:
                self.send_response(conn, {"ok": False, "error": f"Exec error: {exc}"})

        gdb.post_event(gdb_task)

    def process_request(self, req):
        """Route a command name to its handler function."""
        cmd = req.get("cmd")
        args = req.get("args", {})

        handler = self.cmd_map.get(cmd)
        if handler:
            return handler(args)

        return {"ok": False, "error": f"Unknown command: {cmd}"}

if __name__ == "__main__":
    server = GdbMcpServer(HOST, PORT)
    server.start()
