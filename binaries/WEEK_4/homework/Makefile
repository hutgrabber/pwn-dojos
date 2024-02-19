CC = gcc
CFLAGS=-Wall -fno-pic -no-pie

BUILDDIR = build
EXEC:= $(BUILDDIR)/limited_resources
SRCS:= main.c
HDRS:= $(wildcard *.h)
OBJS:= $(SRCS:%.c=$(BUILDDIR)/%.o)
LIBS:= -lpthread -lseccomp

all: $(EXEC)

$(BUILDDIR)/%.o: %.c $(HDRS)
	@mkdir -p $(BUILDDIR)
	$(CC) -c $(CFLAGS) -o $@ $< 

$(EXEC): $(OBJS)
	$(CC) -o $@ $^ $(LIBS) $(CFLAGS)
	@echo flag{fff72b3993166a9a46b7294eabf72715} > flag.txt 

clean:
	rm -rf $(BUILDDIR)
