# Bypassing Mitigations
## Classwork

This challenge contains a format string vulnerability. Your objective is to get a shell from the vulnerability!

Everything you need is located here: 
- `/flag`
- `/challenge/fmtstr`

`/flag` is read-only by root, and `/challenge/fmtstr` is setuid root. The binary will take care of setting the effective and real id to root when you do the challenge. 
