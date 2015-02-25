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
#include <getopt.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/* Linux is lame and doesn't have strlcpy and strlcat. */
#ifdef __linux__
#include <bsd/string.h>
#endif

/*
 * OpenSSL 1.0.0 introduced const qualifiers for SSL_METHOD. Try
 * to surpress warnings for it for both versions.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define SSL_CONST const
#else
#define SSL_CONST
#endif

/* Maximum length of the cipher string. */
#define CIPHERSTRLEN 4096

#define SSLSCAN_ALL 0xFF
#define SSLSCAN_NONE 0x0
/*
 * The high order bit tells us if the user requested a specific
 * SSL protocol version, or just the default/masked-out protocols.
 * We use this for warnings later on.
 */
#define SSLSCAN_USER_UNSET 0x80
#define SSLSCAN_SSLv2 0x01
#define SSLSCAN_SSLv3 0x02
#define SSLSCAN_TLSv1 0x04
#define SSLSCAN_TLSv1_1 0x08
#define SSLSCAN_TLSv1_2 0x10

bool	 cflag = false;			/* Print the cipher string.	*/
bool	 printfail = false;		/* Print failed ciphers.	*/
int	 sslversion = SSLSCAN_ALL;
SSL_CTX	*ssl_ctx;

struct sslhost {
	const char *name;
	const char *port;
	struct addrinfo *hostinfo;
};

enum	{ PROXY_NULL, PROXY_SOCKS5 } proxytype = PROXY_NULL;
bool	proxydns = false;		/* Should we proxy DNS requests. */
struct sslhost proxy;

static int	hostconnect(struct sslhost *);
static int	socksconnect(struct sslhost *);
static SSL *	sslsetup(SSL_CONST SSL_METHOD *, const char *);
static int	tcpconnect(struct sslhost *, bool);
static void	testciphers(struct sslhost *, SSL_CONST SSL_METHOD *, char *, char *);
static bool	testhost(const char *, const char *);
static void	unsupportedcipherlist(SSL_CONST SSL_METHOD *, const char *);
static void	usage(void);

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
hostconnect(struct sslhost *h)
{
	switch (proxytype) {
	case PROXY_NULL:
		return(tcpconnect(h, false));
		break;
	case PROXY_SOCKS5:
		return(socksconnect(h));
		break;
	default:
		return(-1);
	}
}

static SSL *
sslsetup(SSL_CONST SSL_METHOD *meth, const char *ciphers)
{
	SSL *ssl;

	if (SSL_CTX_set_ssl_version(ssl_ctx, meth) == 0)
		errx(EX_SOFTWARE, "Could not set SSL version: %s", ERR_error_string(ERR_get_error(), NULL));

	if (SSL_CTX_set_cipher_list(ssl_ctx, ciphers) == 0)
		errx(EX_SOFTWARE, "Could not set SSL cipher: %s", ERR_error_string(ERR_get_error(), NULL));

	if ((ssl = SSL_new(ssl_ctx)) == NULL)
		errx(EX_SOFTWARE, "Could not create SSL object: %s", ERR_error_string(ERR_get_error(), NULL));

	return ssl;
}

static void
unsupportedcipherlist(SSL_CONST SSL_METHOD *meth, const char *ciphers)
{
	int i;
	STACK_OF(SSL_CIPHER) *clist;
	SSL_CIPHER *cipher;
	SSL *ssl;

	ssl = sslsetup(meth, ciphers);
	clist = SSL_get_ciphers(ssl);

	for(i = 0; i < sk_SSL_CIPHER_num(clist); i++) {
		cipher = sk_SSL_CIPHER_value(clist, i);
		printf("    Unsupported %-7s  %3d bits  %s\n", SSL_get_version(ssl), SSL_CIPHER_get_bits(cipher, NULL), SSL_CIPHER_get_name(cipher));
	}
	SSL_free(ssl);
}

static void
testciphers(struct sslhost *h, SSL_CONST SSL_METHOD *meth, char *ciphers, char *cstr)
{
	int fd, ret;
	SSL *ssl;
	BIO *bio;

	ssl = sslsetup(meth, ciphers);

	if ((fd = hostconnect(h)) < 0)
		return;

	if ((bio = BIO_new_socket(fd, BIO_NOCLOSE)) == NULL)
		errx(EX_SOFTWARE, "Could not create BIO: %s", ERR_error_string(ERR_get_error(), NULL));

	SSL_set_bio(ssl, bio, bio);
	ret = SSL_connect(ssl);

	if (ret == 1) {
		printf("    Accepted    %-7s  %3d bits  %s\n", SSL_get_version(ssl), SSL_get_cipher_bits(ssl, NULL), SSL_get_cipher_name(ssl));
		strlcat(ciphers, ":!", CIPHERSTRLEN);
		strlcat(ciphers, SSL_get_cipher_name(ssl), CIPHERSTRLEN);
		if (cstr[0] != '\0')
			strlcat(cstr, ":", CIPHERSTRLEN);
		strlcat(cstr, SSL_get_cipher_name(ssl), CIPHERSTRLEN);
		SSL_shutdown(ssl);
	}
	SSL_free(ssl);
	close(fd);

	if (ret == 1)
		testciphers(h, meth, ciphers, cstr);
}

static bool
testhost(const char *host, const char *port)
{
	int error;
	struct sslhost h;
	struct addrinfo hints;
	char cipherstr[CIPHERSTRLEN], cstr[CIPHERSTRLEN];

	h.name = host;
	h.port = port;

	if (proxy.name == NULL || proxydns == false) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		error = getaddrinfo(h.name, h.port, &hints, &(h.hostinfo));
		if (error) {
			warnx("Could not resolve hostname %s: %s", h.name, gai_strerror(error));
			return(false);
		}
	} else
		h.hostinfo = NULL;

	printf("Testing host: %s:%s", host, port);
	if (proxy.name)
		printf(" via proxy %s:%s", proxy.name, proxy.port);
	printf("\n");

	/* Test for server preferred ciphers. */
	printf("  Server cipher order:\n");
#define SCAN_PROTO(proto) 								\
	do { if (sslversion & SSLSCAN_##proto) {					\
		strlcpy(cipherstr, "ALL:COMPLEMENTOFALL", CIPHERSTRLEN);		\
		strlcpy(cstr, "", CIPHERSTRLEN);					\
		testciphers(&h, proto##_client_method(), cipherstr, cstr);		\
		if (printfail)								\
			unsupportedcipherlist(proto##_client_method(), cipherstr);	\
		if (cflag && cstr[0] != '\0')						\
			printf("  " #proto " Cipher String:\n    %s\n", cstr);		\
	} } while(0)
#ifdef SSL_TXT_TLSV1_2
	SCAN_PROTO(TLSv1_2);
#endif
#ifdef SSL_TXT_TLSV1_1
	SCAN_PROTO(TLSv1_1);
#endif
#ifdef SSL_TXT_TLSV1
	SCAN_PROTO(TLSv1);
#endif
#if defined(SSL_TXT_SSLV3) && !defined(OPENSSL_NO_SSL3)
	SCAN_PROTO(SSLv3);
#endif
#if defined(SSL_TXT_SSLV2) && !defined(OPENSSL_NO_SSL2)
	SCAN_PROTO(SSLv2);
#endif
#undef SCAN_PROTO

	freeaddrinfo(h.hostinfo);
	return(true);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: sslscan [options] [host[:port] ...]\n\n");
	fprintf(stderr, "  -c, --cipher         Output per-protocol OpenSSL-compatible cipher string.\n");
	fprintf(stderr, "  -x, --proxy <proxy>  Use a proxy to connect to the server. Valid formats:\n");
	fprintf(stderr, "                       socks5://localhost:1080/ -- Uses SOCKS5 proxy.\n");
	fprintf(stderr, "                       socks5h://localhost:1080/ -- Uses SOCKS5 proxy with DNS tunnelling.\n");
	fprintf(stderr, "  --show-failed        List only all ciphers (default lists accepted ciphers).\n");
	fprintf(stderr, "  --ssl2, --ssl3, --tls1, --tls1.1, --tls1.2\n");
	fprintf(stderr, "                       Check specified protocol version.\n");
	fprintf(stderr, "  --no-ssl2, --no-ssl3, --no-tls1, --no-tls1.1, --no-tls1.2\n");
	fprintf(stderr, "                       Don't check specified protocol version.\n");
	fprintf(stderr, "Unless specified, all SSL protocol versions are checked.\n");
	fprintf(stderr, "SSL protocol version support dependent on OpenSSL library support.\n");
	fprintf(stderr, "  Supported protocol versions:");
#ifdef SSL_TXT_TLSV1_2
	fprintf(stderr, " TLSv1.2");
#endif
#ifdef SSL_TXT_TLSV1_1
	fprintf(stderr, " TLSv1.1");
#endif
#ifdef SSL_TXT_TLSV1
	fprintf(stderr, " TLSv1.0");
#endif
#if defined(SSL_TXT_SSLV3) && !defined(OPENSSL_NO_SSL3)
	fprintf(stderr, " SSLv3");
#endif
#if defined(SSL_TXT_SSLV2) && !defined(OPENSSL_NO_SSL2)
	fprintf(stderr, " SSLv2");
#endif
	fprintf(stderr, "\n");

	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int ch, i, status;
	int sslflag = SSLSCAN_NONE, nosslflag = SSLSCAN_NONE;
	char *host, *port, *chp, *xarg = NULL;
	struct addrinfo hints;

	struct option opts[] = {
		{ "cipher",	no_argument,	NULL, 'c' },
		{ "help",	no_argument,	NULL, 'h' },
		{ "no-failed",	no_argument,	(int *)&printfail, false },
		{ "no-ssl2",	no_argument,	&nosslflag, SSLSCAN_SSLv2 },
		{ "no-ssl3",	no_argument,	&nosslflag, SSLSCAN_SSLv3 },
		{ "no-tls1",	no_argument,	&nosslflag, SSLSCAN_TLSv1 },
		{ "no-tls1.0",	no_argument,	&nosslflag, SSLSCAN_TLSv1 },
		{ "no-tls1.1",	no_argument,	&nosslflag, SSLSCAN_TLSv1_1 },
		{ "no-tls1.2",	no_argument,	&nosslflag, SSLSCAN_TLSv1_2 },
		{ "proxy",	required_argument, NULL, 'x' },
		{ "show-failed", no_argument,	(int *)&printfail, true },
		{ "ssl2",	no_argument,	&sslflag, SSLSCAN_SSLv2 },
		{ "ssl3",	no_argument,	&sslflag, SSLSCAN_SSLv3 },
		{ "tls1",	no_argument,	&sslflag, SSLSCAN_TLSv1 },
		{ "tls1.0",	no_argument,	&sslflag, SSLSCAN_TLSv1 },
		{ "tls1.1",	no_argument,	&sslflag, SSLSCAN_TLSv1_1 },
		{ "tls1.2",	no_argument,	&sslflag, SSLSCAN_TLSv1_2 },
		{ NULL,		0,		NULL, 0 }
	};

	while ((ch = getopt_long(argc, argv, "?chx:", opts, NULL)) != -1)
		switch(ch) {
		case 0:
			if (sslflag != SSLSCAN_NONE) {
				if (sslversion & SSLSCAN_USER_UNSET)
					sslversion = SSLSCAN_NONE;
				sslversion |= sslflag;
				sslflag = SSLSCAN_NONE;
			} else if (nosslflag != SSLSCAN_NONE) {
				sslversion &= ~nosslflag;
				sslflag = SSLSCAN_NONE;
			}
			break;
		case 'c':
			cflag = true;
			break;
		case 'x':
			xarg = optarg;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	proxy.name = NULL;
	proxy.port = NULL;
	proxy.hostinfo = NULL;

	if (xarg) {
		if (strncmp(xarg, "socks5://", 9) == 0) {
			xarg += 9;
			proxytype = PROXY_SOCKS5;
			proxydns = false;
		} else if (strncmp(xarg, "socks5h://", 10) == 0) {
			xarg += 10;
			proxytype = PROXY_SOCKS5;
			proxydns = true;
		} else {
			fprintf(stderr, "Unrecognized proxy option: %s\n", xarg);
			usage();
		}

		switch (proxytype) {
		case PROXY_SOCKS5:
			/* XXX: User:pass support? */
			if (strchr(xarg, '@') != NULL)
				errx(EX_SOFTWARE, "SOCKS5 proxy authentication not supported.");

			proxy.port = "socks";
			/* Check for a raw IPv6 address enclosed in brackets [::1]. */
			if (xarg[0] == '[') {
				/* That said, we don't actually want the brackets. */
				proxy.name = xarg+1;
				chp = strchr(xarg, ']');
				if (chp != NULL)
					*chp = '\0';
				if (*(chp+1) == ':') {
					chp += 2;
					proxy.port = strsep(&chp, "/");
				}
			} else {
				proxy.name = strsep(&xarg, ":/");
				if (xarg && xarg[0])
					proxy.port = strsep(&xarg, "/");
			}

			printf("proxy: %s, port: %s\n", proxy.name, proxy.port);
			memset(&hints, 0, sizeof(hints));
			hints.ai_family = PF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			status = getaddrinfo(proxy.name, proxy.port, &hints, &(proxy.hostinfo));
			if (status)
				errx(EX_NOHOST, "Could not resolve proxy host %s: %s", proxy.name, gai_strerror(status));
			break;
		default:
			; /* Nothing; */
		}
	}

	SSL_load_error_strings();
	SSL_library_init();

	if ((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
		errx(EX_SOFTWARE, "Could not create SSL_CTX object: %s", ERR_error_string(ERR_get_error(), NULL));

	status = 0;
	for (i = 0; i < argc; i++) {
		/* XXX: There is probably a better way to detect a raw IPv6 address. */
		port = "https";
		/* Check for a raw IPv6 address enclosed in brackets [::1]. */
		if (argv[i][0] == '[') {
			/* That said, we don't actually want the brackets. */
			host = argv[i]+1;
			chp = strchr(argv[i], ']');
			if (chp != NULL)
				*chp = '\0';
			if (*(chp+1) == ':')
				port = chp+2;
		} else {
			host = strsep(&argv[i], ":");
			if (argv[i] && argv[i][0])
				port = argv[i];
		}
		if (testhost(host, port) == false)
			status++;
	}

	SSL_CTX_free(ssl_ctx);

	if (status == 0)
		return(0);
	else
		return(EX_SOFTWARE);
}
