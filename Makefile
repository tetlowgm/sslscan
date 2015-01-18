PROG = sslscan
SRCS = $(PROG).c
OBJS = $(PROG).o
MAN = $(PROG).1
PREFIX ?= /usr/local
BINPATH ?= $(PREFIX)/bin
MANPATH ?= $(PREFIX)/man/man1
CFLAGS += -Wall -I/opt/local/include
LDFLAGS += -L/opt/local/lib
LDLIBS += -lssl -lcrypto

.PHONY: all install uninstall clean

all: $(PROG)

$(PROG): $(OBJS)

install:
	install -m 0755 $(PROG) $(BINPATH)/$(PROG)
	install -m 0644 $(MAN) $(MANPATH)/$(MAN)

uninstall:
	rm -f $(BINPATH)/$(PROG)
	rm -f $(MANPATH)/$(MAN)

clean:
	rm -f $(PROG) $(OBJS)
