# Linux Hijacking
## Homework - Entry Stub Trampoline

Everything you need is located here: 
- `/flag`
- `/challenge/ih.h`
- `/challenge/Makefile`

For this homework assignment, you need to create a kernel module, that registers an interrupt handler. The handler should do the following:

- Register an interrupt. Setup either a tasklet or workqueue to defer work.
- Increment a counter each time it is called. Synchronization needs to be ensured. (Aka spin-lock, or something like that). No RACE_CONDITIONS.
    - This is non-deferred work
- Define deferred work which prints the current value of the counter, and the current time.

Submit code to ELMS. 