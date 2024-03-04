# Bypassing Mitigations
## Homework

For this homework, you are going perform a ret2libc to be able to bypass NX and ASLR. There are also other things that you may need to bypass as well. 

Everything you need is located here: 
- `/flag`
- `/challenge/homework`

`/flag` is read-only by root, and `/challenge/homework` is setuid root. The binary will take care of setting the effective and real id to root when you do the challenge. 
