PROG = sslscan
OBJS = $(PROG).o
PREFIX ?= /usr/local
BINPATH ?= $(PREFIX)/bin
MANPATH ?= $(PREFIX)/man/man1
CFLAGS += -Wall
LDLIBS += -lssl -lcrypto

# Linux is lame and doesn't have strlcpy and strlcat.
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S), Linux)
	LDLIBS += -lbsd
endif

.PHONY: all install clean

all: $(PROG)

$(PROG): $(OBJS)

install:
	install -s -m 0755 $(PROG) $(DESTDIR)$(BINPATH)/$(PROG)

clean:
	rm -f $(PROG) $(OBJS)
