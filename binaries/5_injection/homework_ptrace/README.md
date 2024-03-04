# Injection 
## Homework - ptrace injecmtion

Everything you need is located here: 
- `/flag`
- `/challenge/homework`

`/flag` is read-only by root, and `/challenge/homework` is setuid root. 

The program **will not** take of care of setting the real UID and effective UID to be the same. Either set this or utilize a method other than creating a shell to get the flag (I recommend to `cat` the flag instead).
