CC = gcc
LIB = libentrystub.so

.PHONY:	template solution clean

solution: $(LIB)

$(LIB): entrystub.o
	$(CC) -shared -o $@ $< -ldl -L/opt/capstone -lcapstone

entrystub.o: entrystub.c
	$(CC) -c -fPIC -o $@ $<

clean:
	rm -f $(EXEC) $(LIB) *.o
