SRCS = sslscan.c
BINPATH = /usr/bin/
MANPATH = /usr/share/man/
LIBS = -lssl -lcrypto

all:
	gcc -g -Wall $(CFLAGS) $(LDFLAGS) $(LIBS) -o sslscan $(SRCS)

install:
	cp sslscan $(BINPATH)
	cp sslscan.1 $(MANPATH)man1

uninstall:
	rm -f $(BINPATH)sslscan
	rm -f $(MANPATH)man1/sslscan.1

clean:
	rm -f sslscan
