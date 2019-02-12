/*-
 *  Copyright (c) 2015 Gordon Tetlow
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 *  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 *  SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "sslscan_priv.h"

#ifndef BUFSIZ
#define BUFSIZ 1024
#endif

extern enum	starttls_enum tlstype;
extern bool	proxydns;
extern enum	proxy_enum proxytype;
extern struct sslhost proxy;

static void	ftpconnect(int);
static void	mysqlconnect(int);
static void	smtpconnect(int);
static int	socksconnect(struct sslhost *);
static int	tcpconnect(struct sslhost *, bool);

int
hostconnect(struct sslhost *h)
{
	int fd = -1;

	switch (proxytype) {
	case PROXY_NULL:
		fd = tcpconnect(h, false);
		break;
	case PROXY_SOCKS5:
		fd = socksconnect(h);
		break;
	}

	switch (tlstype) {
	case TLS_FTP:
		ftpconnect(fd);
		break;
	case TLS_MYSQL:
		mysqlconnect(fd);
		break;
	case TLS_NONE:
		/* Don't actually need to do anything. */
		break;
	case TLS_SMTP:
		smtpconnect(fd);
		break;
	}

	return(fd);
}

static void
ftpconnect(int fd)
{
	char buf[BUFSIZ];
	int ret;

	memset(buf, 0, BUFSIZ);
	ret = recv(fd, buf, BUFSIZ - 1, 0);
	if (ret == -1)
		err(EX_PROTOCOL, "FTP STARTTLS failure");
	else if (ret < 3 || strncmp(buf, "220", 3) != 0)
		err(EX_PROTOCOL, "FTP STARTTLS failure");

	ret = send(fd, "AUTH TLS\r\n", 10, 0);
	if (ret == -1 || ret != 10)
		err(EX_PROTOCOL, "FTP STARTTLS failure");

	memset(buf, 0, BUFSIZ);
	ret = recv(fd, buf, BUFSIZ - 1, 0);
	if (ret == -1)
		err(EX_PROTOCOL, "FTP STARTTLS failure");
	else if (ret < 3 || sscanf(buf, "234") != 0)
		err(EX_PROTOCOL, "FTP server doesn't appear to support STARTTLS");
}

static void
mysqlconnect(int fd)
{
	/*
	 * See MySQL internal documentation site about handshake setup.
	 * https://dev.mysql.com/doc/internals/en/ssl-handshake.html
	 * https://dev.mysql.com/doc/internals/en/ssl.html
	 * https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeResponse
	 * https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
	 *
	 * These particular bytes were ripped from the wire on a client connecting
	 * to a server with SSL enabled.
	 */
	const char mysqlssl[] = { 0x20, 0x00, 0x00, 0x01, 0x85, 0xae, 0x7f, 0x00,
                                  0x00, 0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x00, 0x00, 0x00, 0x00};
	char buf[BUFSIZ];
	int ret;

	memset(buf, 0, BUFSIZ);
	ret = recv(fd, buf, BUFSIZ - 1, 0);
	if (ret == -1)
		err(EX_PROTOCOL, "MySQL STARTTLS failure");

	ret = send(fd, mysqlssl, sizeof(mysqlssl), 0);
	if (ret == -1 || ret != 36)
		err(EX_PROTOCOL, "MySQL STARTTLS failure");
}

static void
smtpconnect(int fd)
{
	char buf[BUFSIZ];
	int ret;

	memset(buf, 0, BUFSIZ);
	ret = recv(fd, buf, BUFSIZ - 1, 0);
	if (ret == -1)
		err(EX_PROTOCOL, "SMTP STARTTLS failure");
	else if (ret < 3 || strncmp(buf, "220", 3) != 0)
		err(EX_PROTOCOL, "SMTP STARTTLS failure");

	ret = send(fd, "EHLO sslscan\r\n", 14, 0);
	if (ret == -1 || ret != 14)
		err(EX_PROTOCOL, "SMTP STARTTLS failure");

	memset(buf, 0, BUFSIZ);
	ret = recv(fd, buf, BUFSIZ - 1, 0);
	if (ret == -1)
		err(EX_PROTOCOL, "SMTP STARTTLS failure");
	else if (ret < 3 || sscanf(buf, "250-STARTTLS") != 0)
		err(EX_PROTOCOL, "SMTP server doesn't appear to support STARTTLS");

	ret = send(fd, "STARTTLS\r\n", 10, 0);
	if (ret == -1 || ret != 10)
		err(EX_PROTOCOL, "SMTP STARTTLS failure");

	memset(buf, 0, BUFSIZ);
	ret = recv(fd, buf, BUFSIZ - 1, 0);
	if (ret == -1)
		err(EX_PROTOCOL, "SMTP STARTTLS failure");
	else if (ret < 3 || strncmp(buf, "220", 3) != 0)
		err(EX_PROTOCOL, "SMTP STARTTLS failure");
}

static int
socksconnect(struct sslhost *h)
{
	int fd, ret, i;
	size_t len, hlen;
	uint16_t hport;
	struct servent *e;
	struct sockaddr_in *addr_in;
	struct sockaddr_in6 *addr_in6;
	unsigned char socksbuf[600];

	fd = tcpconnect(&proxy, true);
	memset(&socksbuf, 0, 600);

	/* From RFC 1928:
	 * +----+----------+----------+
	 * |VER | NMETHODS | METHODS  |
	 * +----+----------+----------+
	 * | 1  |    1     | 1 to 255 |
	 * +----+----------+----------+
	 */
	len = 0;
	socksbuf[len++] = 0x05; /* VER */
	socksbuf[len++] = 0x01; /* NMETHODS */
	socksbuf[len++] = 0x00; /* METHODS - X'00' == NO AUTHENTICATION REQUIRED */
	ret = send(fd, &socksbuf, len, 0);
	if (ret == -1)
		err(EX_UNAVAILABLE, "Unable to send initial SOCKS5 request");
	if (ret != len)
		errx(EX_PROTOCOL, "Unable to send full request to SOCKS5 server");

	ret = recv(fd, &socksbuf, 600, 0);
	if (ret == -1)
		err(EX_PROTOCOL, "SOCKS5 connect failure");
	else if (ret < 2 || socksbuf[0] != 0x05 || socksbuf[1] != 0x00)
		errx(EX_PROTOCOL, "SOCKS5 connect failure");

	/* +----+-----+-------+------+----------+----------+
	 * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	 * +----+-----+-------+------+----------+----------+
	 * | 1  |  1  | X'00' |  1   | Variable |    2     |
	 * +----+-----+-------+------+----------+----------+
	 */
	len = 0;
	socksbuf[len++] = 0x05; /* VER */
	socksbuf[len++] = 0x01; /* CMD - X'01' == CONNECT */
	socksbuf[len++] = 0x00; /* RSV - Reserved always X'00' */
	if (proxydns) {
		hlen = strlen(h->name);

		socksbuf[len++] = 0x03; /* ATYP - X'03' == DOMAINNAME */
		socksbuf[len++] = hlen;
		memcpy(socksbuf + len, h->name, hlen);
		len += hlen;
	} else {
		switch (h->hostinfo->ai_family) {
		case AF_INET:
			addr_in = (struct sockaddr_in*)h->hostinfo->ai_addr;

			socksbuf[len++] = 0x01; /* ATYP - X'01' == IP V4 address */
			for(i = 0; i < 4; i++)
				socksbuf[len++] = ((unsigned char*)&addr_in->sin_addr.s_addr)[i];
			break;
		case AF_INET6:
			addr_in6 = (struct sockaddr_in6*)h->hostinfo->ai_addr;

			socksbuf[len++] = 0x04; /* ATYP - X'04' == IP V6 address */
			for(i = 0; i < 16; i++)
				socksbuf[len++] = ((unsigned char*)&addr_in6->sin6_addr.s6_addr)[i];
			break;
		default:
			errx(EX_SOFTWARE, "Unknown proxy address family");
		}
	}

	if (h->port[0] >= '0' && h->port[0] <= '9') {
		if ((hport = strtol(h->port, NULL, 0)) == 0)
			err(EX_UNAVAILABLE, "Unable to resolve proxy port");
	} else {
		if ((e = getservbyname(h->port, NULL)) == NULL)
			errx(EX_UNAVAILABLE, "Unable to resolve proxy port");
		hport = ntohs((uint16_t)e->s_port);
	}
	socksbuf[len++] = (unsigned char)((hport >> 8) & 0xff);
	socksbuf[len++] = (unsigned char)(hport & 0xff);

	ret = send(fd, &socksbuf, len, 0);
	if (ret == -1)
		err(EX_UNAVAILABLE, "Unable to send initial SOCKS5 request");
	if (ret != len)
		errx(EX_PROTOCOL, "Unable to send full request to SOCKS5 server");

	ret = recv(fd, &socksbuf, 10, 0);
	if (ret == -1)
		err(EX_PROTOCOL, "SOCKS5 connect failure");
	else if (ret < 10 || socksbuf[0] != 0x05 || socksbuf[1] != 0x00)
		errx(EX_PROTOCOL, "SOCKS5 connect failure: %d", socksbuf[1]);
	return(fd);
}

static int
tcpconnect(struct sslhost *h, bool hardfail)
{
	int fd;

	fd = socket(h->hostinfo->ai_family, h->hostinfo->ai_socktype, h->hostinfo->ai_protocol);
	if (fd < 0)
		errx(EX_OSERR, "Could not open socket.");

	/* Should this be a bail or warn and continue? */
	if ((connect(fd, h->hostinfo->ai_addr, h->hostinfo->ai_addrlen)) < 0) {
		if (hardfail)
			err(EX_UNAVAILABLE, "Could not open a connection to %s:%s", h->name, h->port);
		else {
			warn("Could not open a connection to %s:%s", h->name, h->port);
			return(-1);
		}
	}

	return(fd);
}
