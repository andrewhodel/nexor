CC=gcc
CFLAGS=-lm -fPIC -Wall -I.

nexor:
	# compile object file nexor.o
	$(CC) $(CFLAGS) -c nexor.c
	# compile nexor program
	$(CC) -o nexor nexor.o $(CFLAGS)
	# compile shared object library
	$(CC) -shared -Wl,-soname,libnexor.so -o libnexor.so *.o

clean:
	rm -f *.o
	rm -f nexor
	rm -f libnexor.so

install:
	cp libnexor.so /usr/lib/
	cp nexor /usr/bin/
	cp nexor.h /usr/include/

uninstall:
	rm -f /usr/lib/libnexor.so
	rm -f /usr/bin/nexor
	rm -f /usr/include/nexor.h
