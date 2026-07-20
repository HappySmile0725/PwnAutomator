# Payload Rules

The MCP payload writer wraps the submitted body automatically:

```python
from pwn import *
import os
p = remote(os.environ['PWN_AUTOMATOR_REMOTE_HOST'], int(os.environ['PWN_AUTOMATOR_REMOTE_PORT']))
e = ELF('./<active binary>', checksec=False)
libc = ELF('./libc.so.6', checksec=False) if os.path.exists('./libc.so.6') else e.libc

<submitted payload body>

p.interactive()
```

Submit only the exploit body.

- Use the existing `p` tube, `e` ELF object, and `libc` ELF object.
- The existing `p` tube is already connected to the published Docker challenge service.
- Do not add `remote(...)`, `process(...)`, `p.interactive()`, local respawn loops, or `p.close()`.
- Do not hardcode `/workspace/...` or host absolute binary paths.
- If you define `exploit(p)` or another entry function, call it once at top level.
- Keep payloads concise and evidence-driven.

Use pwno dynamic-analysis tools for debugger evidence. Payload bodies should stay minimal and should not add pause-based debugger attach scaffolding unless explicitly requested.
