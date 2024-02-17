#!/usr/bin/env python3
import pwn 

def start(argv=[], *a, **kw):
    if pwn.args.GDB: # use the gdb script, sudo apt install gdbserver
        return pwn.gdb.debug([binPath] + argv, gdbscript=gdbscript, *a, **kw, aslr=True)
    elif pwn.args.REMOTE: # ['server', 'port']
        return pwn.remote(sys.argv[1], sys.argv[2], *a, **kw)
    else: # run locally, no GDB
        return pwn.process([binPath]+argv, *a, **kw, aslr=True)

binPath=""
isRemote = pwn.args.REMOTE

gdbscript = '''

'''.format(**locals())

elf = pwn.context.binary = pwn.ELF(binPath, checksec=False)

io=start()
payload = b'define_payload'
io.sendline(payload)
io.interactive()
