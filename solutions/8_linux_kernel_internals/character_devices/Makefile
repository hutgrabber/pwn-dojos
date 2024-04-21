CC=gcc
CFLAGS=-Wall -Werror -Wextra

obj-m += flagdriver.o

.PHONY: all clean

all: flagdriver flaguser 

flagdriver: flagdriver.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

flaguser: flagdevice.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm flaguser
