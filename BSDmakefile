PROG=	sslscan
SRCS=	sslscan.c	\
	connect.c
NO_MAN=

DESTDIR= /usr/local/bin
DPADD=	${LIBSSL} ${LIBCRYPTO}
LDADD=	-lssl -lcrypto

.include <bsd.prog.mk>
