# Linux Hijacking
## Homework - Entry Stub Trampoline

Everything you need is located here: 
- `/flag`
- `/challenge/flagdriver.h`
- `/challenge/flag.h`
- `/challenge/Makefile`

For this homework assignment, you need to create a kernel module, that creates a character device. The character device should do the following:

- Register the character device. The `flag.h` contains a major and minor number for you. Utilize `register_chrdev_region`, `cdev_add`, and `cdev_init` to regsiter it. 

- Create an `open`, `release`, `llseek`, `read`, and `write` function. 
    - `open` should read in the flag to the device buffer.
    - `release` should clear the buffer
    - `llseek` will seek to the part of the buffer (refer to `man llseek` to see desire behavior)
    - `read` will read buffer from current position
    - `write` write to buffer at current position.

To interact with it, you will need to create a userspace piece. 

First you need to do `sudo mknod <name> c MAJOR MINOR` to create a device inode. You can then create userspace, which will open this device inode (via open system call) and interact with it via the correct system calls. 

An alternative to creating a character device is by utilizing `proc_create`. This creates a file in `/proc` that interacts almost the same as a character device. 

***Note: There is an experimental build_ko_module python script that you can try to use for building the kernel module. You will need to either run it in the /challenge directory or via sudo***

Submit code to ELMS. 