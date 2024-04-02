## Steps

### entry_stub_create

- Define number of bytes to save as 24.
  mmap 24 bytes of rwx memory (ask ai to do this. calling this as trampoline)
  in the stub struct, declare original_entry as original
- Borrow code from write absolute jump to jump to encryptedaddr+12 (original+12)
  memcpy the jmp_template you made to trampoline+12
  declare stub.trampoline as the mmapped trampoline.

### entry_stub_hook

- write_absolute_jump from stub's original entry to wrapper function

### load function

- call entry_stub_create on the arguments &stub and the address of encryptedprint
- call entry_stub_hook on the arguments &stub and the address of myencryptedprint
