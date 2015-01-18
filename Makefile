SRCS = sslscan.c
OBJS = sslscan
BINPATH = /usr/bin/
MANPATH = /usr/share/man/
CFLAGS += -I/opt/local/include
LDFLAGS += -L/opt/local/lib
LDLIBS += -lssl -lcrypto

all: sslscan

install:
	cp sslscan $(BINPATH)
	cp sslscan.1 $(MANPATH)man1

uninstall:
	rm -f $(BINPATH)sslscan
	rm -f $(MANPATH)man1/sslscan.1

clean:
	rm -f $(OBJS)
