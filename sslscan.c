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

#include <err.h>
#include <getopt.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#if 0
/*
 * OpenSSL 1.0.0 introduced const qualifiers for SSL_METHOD. Try
 * to surpress warnings for it for both versions.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define SSL_CONST const
#else
#define SSL_CONST
#endif
#endif /* 0 */

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

static int	testhost(const char *host, const char *port);
static void	usage(void);

static int
testhost(const char *host, const char *port)
{
	printf("Testing host: %s:%s\n", host, port);
	return(0);
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
#ifdef SSL_TXT_SSLV2
	fprintf(stderr, " SSLv2");
#endif
#ifdef SSL_TXT_SSLV3
	fprintf(stderr, " SSLv3");
#endif
#ifdef SSL_TXT_TLSV1
	fprintf(stderr, " TLSv1.0");
#endif
#ifdef SSL_TXT_TLSV1_1
	fprintf(stderr, " TLSv1.1");
#endif
#ifdef SSL_TXT_TLSV1_2
	fprintf(stderr, " TLSv1.2");
#endif
	fprintf(stderr, "\n");

	exit(EX_USAGE);
}

int
main(int argc, char *argv[])
{
	int ch, i, status;
	int sslflag = SSLSCAN_NONE, nosslflag = SSLSCAN_NONE;
	char *host, *port;

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

	status = 0;
	for (i = 0; i < argc; i++) {
		/* XXX: Check for an IPv6 address. This fails spectacularly on IPv6 addresses. */
		host = strsep(&argv[i], ":");
		if (argv[i] && argv[i][0])
			port = argv[i];
		else
			port = "443";
		status += testhost(host, port);
	}

	if (status == 0)
		return(0);
	else
		return(EX_SOFTWARE);
}
