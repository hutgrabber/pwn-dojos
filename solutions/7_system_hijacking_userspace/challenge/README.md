# Linux Hijacking
## Homework - Entry Stub Trampoline

Everything you need is located here: 
- `/flag`
- `/challenge/homework`
- `/challenge/Makefile`
- `/challenge/entrystub.c`

`/flag` is read-only by root, and `/challenge/homework` is setuid root. 

To run this homework, you will want to do the following `/challenge/homework /path/to/your/sharedlibrary`. 

You will need to copy the `Makefile` and `entrystub.c` to your directory and work with it there. You might find it useful to work with this in practice mode before running it in `play` mode.

Here is the technical steps that you will need to achieve. 
1. Reverse engineer the homework file. You will want to look at encryptedPrint and see how it functions. The flag gets passed into it. 
3. Get the main image address. You will need to read /proc/self/maps, read out a certain amount of bytes (I did 0x1000), and call strtol on it. The reason we do this is because we want to get the beginning address listed in /proc/self/maps. 
    - Example: If the very first line of /proc/self/maps contains 0x12345678-0x87654321, we are trying to store 0x12345678 in a pointer.  

3. You will need to patch out the first couple of instructions in encryptedPrint to have the jump. You will then need to store the instructions you patched out somewhere. We will use these instructions as our trampoline in the next step. 

4. In entrystub.c create a function that has the same parameters as encryptedPrint (I gave you myEncryptedPrint) which just dumps the flag (this is the first parameter). 
    - Once you are done, you are going to jump to your trampoline, then jump to your original function.
    - myEncryptedFunction will call your stub.trampoline via a function pointer.  
    - To create this, we will utilize entryStubCreate function and the instructionLength functions. 

Execution order: 
1. You will want to call entryStubCreate and then call entryStubHook. 

The end result should be your flag. 


