PROG = sslscan
SRCS = $(PROG).c
OBJS = $(PROG).o
MAN = $(PROG).1
PREFIX ?= /usr/local
BINPATH ?= $(PREFIX)/bin
MANPATH ?= $(PREFIX)/man/man1
CFLAGS += -Wall -Wno-deprecated-declarations
LDLIBS += -lssl -lcrypto

.PHONY: all install uninstall clean

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $> $^ $(LDLIBS) -o $@

install:
	install -s -m 0755 $(PROG) $(DESTDIR)$(BINPATH)/$(PROG)
	install -m 0644 $(MAN) $(DESTDIR)$(MANPATH)/$(MAN)

clean:
	rm -f $(PROG) $(OBJS)
