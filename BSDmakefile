PROG=	sslscan
SRCS=	sslscan.c	\
	connect.c
MK_MAN=	no

DESTDIR= /usr/local/bin
DPADD=	${LIBSSL} ${LIBCRYPTO}
LDADD=	-lssl -lcrypto

.include <bsd.prog.mk>
