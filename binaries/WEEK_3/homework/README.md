# Dynamic Memory Vulnerabilities 
## Classwork

Everything you need is located here: 
- `/flag`
- `/challenge/homework`

`/flag` is read-only by root, and `/challenge/classwork` is setuid root. The binary will take care of setting the effective and real id to root when you do the challenge. 

You *may* need to LD_PRELOAD an older version of libc (which I have provided). 

In order to do this, run the following command. 
1. Run the following `LD_PRELOAD=/challenge/libc-2.27.so /challenge/homework

You can also enable this in pwntools by setting the `env` parameter for the `process` function. 
