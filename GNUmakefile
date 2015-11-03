PROG =	sslscan
OBJS =	$(PROG).o \
	 connect.o
PREFIX ?= /usr/local
BINPATH ?= $(PREFIX)/bin
MANPATH ?= $(PREFIX)/man/man1
CFLAGS += -Wall
LDLIBS += -lssl -lcrypto

.PHONY: all install clean

all: $(PROG)

$(PROG): $(OBJS)

install:
	install -s -m 0755 $(PROG) $(DESTDIR)$(BINPATH)/$(PROG)

clean:
	rm -f $(PROG) $(OBJS)
