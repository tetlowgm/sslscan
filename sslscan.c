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

#include <sys/queue.h>

#include <err.h>
#include <getopt.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

/*
 * OpenSSL 1.0.0 introduced const qualifiers for SSL_METHOD. Try
 * to surpress warnings for it for both versions.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define SSL_CONST const
#else
#define SSL_CONST
#endif

#define SSLSCAN_ALL 0xFF
#define SSLSCAN_NONE 0x0
/*
 * The high order bit tells us if the user requested a specific
 * SSL protocol version, or just the default/masked-out protocols.
 * We use this for warnings later on.
 */
#define SSLSCAN_USER_UNSET 0x80
#define SSLSCAN_SSLV2 0x01
#define SSLSCAN_SSLV3 0x02
#define SSLSCAN_TLSV1 0x04
#define SSLSCAN_TLSV1_1 0x08
#define SSLSCAN_TLSV1_2 0x10

bool	 printcert = false;
bool	 printfail = false;
int	 sslversion = SSLSCAN_ALL;
SSL_CTX	*ssl_ctx;

struct sslhost {
	const char *name;
	const char *port;
	struct addrinfo *hostinfo;
};

struct sslcipher {
	STAILQ_ENTRY(sslcipher) entries;
	const char *name;
	int bits;
	SSL_CONST SSL_METHOD *method;
};
STAILQ_HEAD(,sslcipher) cipherlist;

static bool	checkcipher(struct sslhost *, SSL_CONST SSL_METHOD *, struct sslcipher *);
static void	initcipherlist(SSL_CONST SSL_METHOD *);
static int	tcpconnect(struct sslhost *);
static bool	testhost(const char *, const char *);
static void	usage(void);

static void
initcipherlist(SSL_CONST SSL_METHOD *meth)
{
	struct sslcipher *c;
	int i;
	STACK_OF(SSL_CIPHER) *clist;
	SSL *ssl;

	if ((ssl = SSL_new(ssl_ctx)) == NULL)
		errx(EX_SOFTWARE, "Could not create SSL object: %s", ERR_error_string(ERR_get_error(), NULL));

	if (SSL_set_ssl_method(ssl, meth) == 0)
		errx(EX_SOFTWARE, "Could not set SSL method: %s", ERR_error_string(ERR_get_error(), NULL));

	for(clist = SSL_get_ciphers(ssl), i = 0; i < sk_SSL_CIPHER_num(clist); i++) {
		c = malloc(sizeof(struct sslcipher));
		c->name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(clist, i));
		c->bits = SSL_CIPHER_get_bits(sk_SSL_CIPHER_value(clist, i), NULL);
		c->method = meth;
		STAILQ_INSERT_TAIL(&cipherlist, c, entries);
	}
	SSL_free(ssl);
}

static int
tcpconnect(struct sslhost* h)
{
	int fd;

	/* If OpenSSL didn't suck so bad, I wouldn't have to do a lot of this myself. */
	fd = socket(h->hostinfo->ai_family, h->hostinfo->ai_socktype, h->hostinfo->ai_protocol);
	if (fd < 0)
		errx(EX_OSERR, "Could not open socket.");

	/* Should this be a bail or warn and continue? */
	if ((connect(fd, h->hostinfo->ai_addr, h->hostinfo->ai_addrlen)) < 0) {
		warn("Could not open a connection to %s:%s", h->name, h->port);
		return(-1);
	}

	return(fd);
}

static bool
checkcipher(struct sslhost *h, SSL_CONST SSL_METHOD *meth, struct sslcipher *cipher)
{
	int fd, ret, bits;
	bool print;
	char *reason;
	const char *name;
	SSL *ssl;
	BIO *bio;

	if ((ssl = SSL_new(ssl_ctx)) == NULL)
		errx(EX_SOFTWARE, "Could not create SSL object: %s", ERR_error_string(ERR_get_error(), NULL));

	if (SSL_set_ssl_method(ssl, meth) == 0)
		errx(EX_SOFTWARE, "Could not set SSL method: %s", ERR_error_string(ERR_get_error(), NULL));

	if (cipher != NULL && (SSL_set_cipher_list(ssl, cipher->name) == 0))
		errx(EX_SOFTWARE, "Could not set SSL cipher: %s", ERR_error_string(ERR_get_error(), NULL));

	if ((fd = tcpconnect(h)) < 0)
		return(false);

	if ((bio = BIO_new_socket(fd, BIO_NOCLOSE)) == NULL)
		errx(EX_SOFTWARE, "Could not create BIO: %s", ERR_error_string(ERR_get_error(), NULL));

	SSL_set_bio(ssl, bio, bio);
	ret = SSL_connect(ssl);

	switch (ret) {
	case 1:
		/* If cipher is NULL, then we are doing default, we don't need to say if it was accepted or not. */
		print = true;
		reason = cipher ? "Accepted " : "";
		name = SSL_get_cipher_name(ssl);
		bits = SSL_get_cipher_bits(ssl, NULL);
		break;
	case 0:
		print = false;
		reason = "Rejected ";
		if (cipher) {
			name = cipher->name;
			bits = cipher->bits;
		}
		break;
	default:
		print = false;
		reason = "Failed   ";
		if (cipher) {
			name = cipher->name;
			bits = cipher->bits;
		}
	}

	if (print || (printfail && cipher)) {
		printf("    %s%-7s  %3d bits  %s\n", reason, SSL_get_version(ssl), bits, name);
		SSL_shutdown(ssl);
	}

	/* SSL_free takes care of the BIO (and probably closing the fd, no harm there though). */
	SSL_free(ssl);
	close(fd);

	return(true);
}

static bool
testhost(const char *host, const char *port)
{
	bool status = true;
	int error;
	struct sslcipher *cp;
	struct sslhost h;
	struct addrinfo hints;

	h.name = host;
	h.port = port;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo(h.name, h.port, &hints, &(h.hostinfo));
	if (error) {
		warnx("Could not resolve hostname %s: %s", h.name, gai_strerror(error));
		return(false);
	}

	printf("Testing host: %s:%s\n", host, port);

	/* Test for server preferred ciphers. */
	printf("  Preferred server ciphers:\n");
#ifdef SSL_TXT_TLSV1_2
	if (status && (sslversion & SSLSCAN_TLSV1_2))
		status = checkcipher(&h, TLSv1_2_client_method(), NULL);
#endif
#ifdef SSL_TXT_TLSV1_1
	if (status && (sslversion & SSLSCAN_TLSV1_1))
		status = checkcipher(&h, TLSv1_1_client_method(), NULL);
#endif
#ifdef SSL_TXT_TLSV1
	if (status && (sslversion & SSLSCAN_TLSV1))
		status = checkcipher(&h, TLSv1_client_method(), NULL);
#endif
#ifdef SSL_TXT_SSLV3
	if (status && (sslversion & SSLSCAN_SSLV3))
		status = checkcipher(&h, SSLv3_client_method(), NULL);
#endif
#ifdef SSL_TXT_SSLV2
	if (status && (sslversion & SSLSCAN_SSLV2))
		status = checkcipher(&h, SSLv2_client_method(), NULL);
#endif
	printf("\n");

	/* Test all ciphers. */
	printf("  Supported server ciphers:\n");
	STAILQ_FOREACH(cp, &cipherlist, entries) {
		if (status)
			status = checkcipher(&h, cp->method, cp);
	}

	freeaddrinfo(h.hostinfo);
	return(true);
}

static void
usage(void)
{
	fprintf(stderr, "Usage: sslscan [options] [host[:port] ...]\n\n");
	fprintf(stderr, "  --show-failed        List only all ciphers (default lists accepted ciphers).\n");
	fprintf(stderr, "  --show-cert          Print SSL certificate information.\n");
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
#ifdef SSL_TXT_SSLV3
	fprintf(stderr, " SSLv3");
#endif
#ifdef SSL_TXT_SSLV2
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
	char *host, *port, *chp;

	struct option opts[] = {
		{ "help",	no_argument,	NULL, 'h' },
		{ "no-cert",	no_argument,	(int *)&printcert, false },
		{ "no-failed",	no_argument,	(int *)&printfail, false },
		{ "no-ssl2",	no_argument,	&nosslflag, SSLSCAN_SSLV2 },
		{ "no-ssl3",	no_argument,	&nosslflag, SSLSCAN_SSLV3 },
		{ "no-tls1",	no_argument,	&nosslflag, SSLSCAN_TLSV1 },
		{ "no-tls1.0",	no_argument,	&nosslflag, SSLSCAN_TLSV1 },
		{ "no-tls1.1",	no_argument,	&nosslflag, SSLSCAN_TLSV1_1 },
		{ "no-tls1.2",	no_argument,	&nosslflag, SSLSCAN_TLSV1_2 },
		{ "show-failed", no_argument,	(int *)&printfail, true },
		{ "show-cert",	no_argument,	(int *)&printcert, true },
		{ "ssl2",	no_argument,	&sslflag, SSLSCAN_SSLV2 },
		{ "ssl3",	no_argument,	&sslflag, SSLSCAN_SSLV3 },
		{ "tls1",	no_argument,	&sslflag, SSLSCAN_TLSV1 },
		{ "tls1.0",	no_argument,	&sslflag, SSLSCAN_TLSV1 },
		{ "tls1.1",	no_argument,	&sslflag, SSLSCAN_TLSV1_1 },
		{ "tls1.2",	no_argument,	&sslflag, SSLSCAN_TLSV1_2 },
		{ NULL,		0,		NULL, 0 }
	};

	while ((ch = getopt_long(argc, argv, "?bh", opts, NULL)) != -1)
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
		case 'h':
		case '?':
		default:
			usage();
		}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		usage();

	SSL_load_error_strings();
	SSL_library_init();

	if ((ssl_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
		errx(EX_SOFTWARE, "Could not create SSL_CTX object: %s", ERR_error_string(ERR_get_error(), NULL));

	/* For the SSL_CTX, we want *ALL* ciphers. Even the ones that aren't in ALL (seriously?). */
	if ((SSL_CTX_set_cipher_list(ssl_ctx, "ALL:COMPLEMENTOFALL")) == 0)
		errx(EX_SOFTWARE, "Could not set cipher list: %s", ERR_error_string(ERR_get_error(), NULL));

	STAILQ_INIT(&cipherlist);
#ifdef SSL_TXT_TLSV1_2
	initcipherlist(TLSv1_2_client_method());
#endif
#ifdef SSL_TXT_TLSV1_1
	initcipherlist(TLSv1_1_client_method());
#endif
#ifdef SSL_TXT_TLSV1
	initcipherlist(TLSv1_client_method());
#endif
#ifdef SSL_TXT_SSLV3
	initcipherlist(SSLv3_client_method());
#endif
#ifdef SSL_TXT_SSLV2
	initcipherlist(SSLv2_client_method());
#endif

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

	if (status == 0)
		return(0);
	else
		return(EX_SOFTWARE);
}
