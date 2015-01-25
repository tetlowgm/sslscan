/***************************************************************************
 *   sslscan - A SSL cipher scanning tool                                  *
 *   Copyright 2007-2009 by Ian Ventura-Whiting (Fizz)                     *
 *   fizz@titania.co.uk                                                    *
 *   Copyright 2015 by Gordon Tetlow                                       *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.  *
 *                                                                         *
 *   In addition, as a special exception, the copyright holders give       *
 *   permission to link the code of portions of this program with the      *
 *   OpenSSL library under certain conditions as described in each         *
 *   individual source file, and distribute linked combinations            *
 *   including the two.                                                    *
 *   You must obey the GNU General Public License in all respects          *
 *   for all of the code used other than OpenSSL.  If you modify           *
 *   file(s) with this exception, you may extend this exception to your    *
 *   version of the file(s), but you are not obligated to do so.  If you   *
 *   do not wish to do so, delete this exception statement from your       *
 *   version.  If you delete this exception statement from all source      *
 *   files in the program, then also delete it here.                       *
 ***************************************************************************/

// Includes...
#include <sys/types.h>
#include <sys/stat.h>
#ifdef __FreeBSD__
#define _WITH_GETLINE
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <err.h>
#include <getopt.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define mode_single 0
#define mode_multiple 1

#define BUFFERSIZE 1024

/*
 * OpenSSL 1.0.0 introduce const qualifiers for SSL_METHOD. Try
 * to surpress warnings for it for both versions.
 */
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
#define SSL_CONST const
#else
#define SSL_CONST
#endif

#define ssl_all 0
/* SSLv2 support is removed in 1.1.0 */
#ifdef SSL_TXT_SSLV2
#define ssl_v2 1
#endif
#ifdef SSL_TXT_SSLV3
#define ssl_v3 2
#endif
#ifdef SSL_TXT_TLSV1
#define tls_v1 3
#endif
/* TLSv1.1 appeared in 1.0.1 */
#ifdef SSL_TXT_TLSV1_1
#define tls_v11 4
#endif
/* TLSv1.2 appeared in 1.0.1 */
#ifdef SSL_TXT_TLSV1_2
#define tls_v12 5
#endif

#define VERSION "1.8.3"

const char *program_version = "sslscan version " VERSION "\nhttp://www.titania.co.uk\nCopyright (C) Ian Ventura-Whiting 2009\n";
const char *xml_version = VERSION;


struct sslCipher
{
	// Cipher Properties...
	const char *name;
	char *version;
	int bits;
	char description[512];
	SSL_CONST SSL_METHOD *sslMethod;
	struct sslCipher *next;
};

struct sslCheckOptions
{
	// Program Options...
	char *host;
	int port;
	bool failed;
	bool starttls;
	int sslVersion;
	bool pout;
	bool sslbugs;
	bool http;
	bool printcert;

	// File Handles...
	FILE *xmlOutput;

	// TCP Connection Variables...
	struct hostent *hostStruct;
	struct sockaddr_in serverAddress;

	// SSL Variables...
	SSL_CTX *ctx;
	struct sslCipher *ciphers;
	char *clientCertsFile;
	char *privateKeyFile;
	char *privateKeyPassword;
};


// Adds Ciphers to the Cipher List structure
void
populateCipherList(struct sslCheckOptions *options, SSL_CONST SSL_METHOD *sslMethod)
{
	// Variables...
	struct sslCipher *sslCipherPointer;
	int loop;
	STACK_OF(SSL_CIPHER) *cipherList;
	SSL *ssl = NULL;

	// Setup Context Object...
	options->ctx = SSL_CTX_new(sslMethod);
	if (options->ctx == NULL)
		errx(EX_SOFTWARE, "Could not create SSL_CTX object.");

	if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") == 0)
		errx(EX_SOFTWARE, "Could not set cipher list.");

	// Create new SSL object
	ssl = SSL_new(options->ctx);
	if (ssl == NULL)
		errx(EX_SOFTWARE, "Could not create SSL object.");

	// Get List of Ciphers
	cipherList = SSL_get_ciphers(ssl);

	// Create Cipher Struct Entries...
	for (loop = 0; loop < sk_SSL_CIPHER_num(cipherList); loop++)
	{
		// Create Structure...
		if (options->ciphers == 0)
		{
			options->ciphers = malloc(sizeof(struct sslCipher));
			sslCipherPointer = options->ciphers;
		}
		else
		{
			sslCipherPointer = options->ciphers;
			while (sslCipherPointer->next != 0)
				sslCipherPointer = sslCipherPointer->next;
			sslCipherPointer->next = malloc(sizeof(struct sslCipher));
			sslCipherPointer = sslCipherPointer->next;
		}

		// Init
		memset(sslCipherPointer, 0, sizeof(struct sslCipher));

		// Add cipher information...
		sslCipherPointer->sslMethod = sslMethod;
		sslCipherPointer->name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(cipherList, loop));
		sslCipherPointer->version = SSL_CIPHER_get_version(sk_SSL_CIPHER_value(cipherList, loop));
		SSL_CIPHER_description(sk_SSL_CIPHER_value(cipherList, loop), sslCipherPointer->description, sizeof(sslCipherPointer->description) - 1);
		sslCipherPointer->bits = SSL_CIPHER_get_bits(sk_SSL_CIPHER_value(cipherList, loop), NULL);
	}

	// Free objects
	SSL_free(ssl);
	SSL_CTX_free(options->ctx);
}

// Create a TCP socket
int tcpConnect(struct sslCheckOptions *options)
{
	// Variables...
	int socketDescriptor;
	char buffer[BUFFERSIZE];
	struct sockaddr_in localAddress;
	int status;

	// Create Socket
	socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
	if(socketDescriptor < 0)
		errx(EX_OSERR, "Could not open socket.");

	// Configure Local Port
	localAddress.sin_family = AF_INET;
	localAddress.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddress.sin_port = htons(0);
	status = bind(socketDescriptor, (struct sockaddr *) &localAddress, sizeof(localAddress));
	if(status < 0)
		errx(EX_OSERR, "Could not bind to port.");

	// Connect
	status = connect(socketDescriptor, (struct sockaddr *) &options->serverAddress, sizeof(options->serverAddress));
	/* Should this be a bail or warn and continue? */
	if(status < 0)
	{
		warnx("Could not open a connection to host %s on port %d.", options->host, options->port);
		return 0;
	}

	// If STARTTLS is required...
	if (options->starttls)
	{
		memset(buffer, 0, BUFFERSIZE);
		recv(socketDescriptor, buffer, BUFFERSIZE - 1, 0);
		if (strncmp(buffer, "220", 3) != 0)
		{
			close(socketDescriptor);
			warnx("%s:%d does not appear to be an SMTP service.", options->host, options->port);
			return 0;
		}
		send(socketDescriptor, "EHLO titania.co.uk\r\n", 20, 0);
		memset(buffer, 0, BUFFERSIZE);
		recv(socketDescriptor, buffer, BUFFERSIZE - 1, 0);
		if (strncmp(buffer, "250", 3) != 0)
		{
			close(socketDescriptor);
			warnx("The SMTP service on %s:%d did not respond with status 250 to our HELO.", options->host, options->port);
			return 0;
		}
		send(socketDescriptor, "STARTTLS\r\n", 10, 0);
		memset(buffer, 0, BUFFERSIZE);
		recv(socketDescriptor, buffer, BUFFERSIZE - 1, 0);
		if (strncmp(buffer, "220", 3) != 0)
		{
			close(socketDescriptor);
			warnx("The SMTP service on %s:%d does not appear to support STARTTLS.", options->host, options->port);
			return 0;
		}
	}

	// Return
	return socketDescriptor;
}


// Private Key Password Callback...
static int password_callback(char *buf, int size, int rwflag, void *userdata)
{
	strncpy(buf, (char *)userdata, size);
	buf[strlen(userdata)] = 0;
	return strlen(userdata);
}


// Load client certificates/private keys...
void
loadCerts(struct sslCheckOptions *options)
{
	// Variables...
	PKCS12 *pk12 = NULL;
	FILE *pk12File = NULL;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	STACK_OF(X509) *ca = NULL;

	// Configure PKey password...
	if (options->privateKeyPassword != 0)
	{
		SSL_CTX_set_default_passwd_cb_userdata(options->ctx, (void *)options->privateKeyPassword);
		SSL_CTX_set_default_passwd_cb(options->ctx, password_callback);
	}

	// Seperate Certs and PKey Files...
	if ((options->clientCertsFile != 0) && (options->privateKeyFile != 0))
	{
		// Load Cert...
		if (!(SSL_CTX_use_certificate_file(options->ctx, options->clientCertsFile, SSL_FILETYPE_PEM) ||
		      SSL_CTX_use_certificate_file(options->ctx, options->clientCertsFile, SSL_FILETYPE_ASN1) ||
		      SSL_CTX_use_certificate_chain_file(options->ctx, options->clientCertsFile)))
			errx(EX_SOFTWARE, "Could not configure certificate(s).");

		// Load PKey...
		if (!(SSL_CTX_use_PrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_PEM) ||
		      SSL_CTX_use_PrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_ASN1) ||
		      SSL_CTX_use_RSAPrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_PEM) ||
		      SSL_CTX_use_RSAPrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_ASN1)))
			errx(EX_SOFTWARE, "Could not configure private key.");
	}
	else if (options->privateKeyFile != 0) // PKCS Cert and PKey File...
	{
		pk12File = fopen(options->privateKeyFile, "rb");
		if (pk12File == NULL)
			errx(EX_NOINPUT, "Could not open PKCS#12 file.");

		pk12 = d2i_PKCS12_fp(pk12File, NULL);
		if (!pk12)
			errx(EX_IOERR, "Could not read PKCS#12 file.");

		if (!PKCS12_parse(pk12, options->privateKeyPassword, &pkey, &cert, &ca))
			errx(EX_SOFTWARE, "Error parsing PKCS#12. Are you sure that password was correct?");

		if (!SSL_CTX_use_certificate(options->ctx, cert))
			errx(EX_SOFTWARE, "Could not configure certificate.");

		if (!SSL_CTX_use_PrivateKey(options->ctx, pkey))
			errx(EX_SOFTWARE, "Could not configure private key.");

		PKCS12_free(pk12);
		fclose(pk12File);
	}

	// Check Cert/Key...
	if (!SSL_CTX_check_private_key(options->ctx))
		errx(EX_SOFTWARE, "Private key does not match certificate.");
}


// Test a cipher...
bool testCipher(struct sslCheckOptions *options, struct sslCipher *sslCipherPointer)
{
	// Variables...
	int cipherStatus;
	bool status = true;
	int socketDescriptor = 0;
	SSL *ssl = NULL;
	BIO *cipherConnectionBio;
	BIO *stdoutBIO = NULL;
	char requestBuffer[200];
	char buffer[50];
	int resultSize = 0;

	// Create request buffer...
	memset(requestBuffer, 0, 200);
	snprintf(requestBuffer, 199, "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n", options->host);

	// Connect to host
	socketDescriptor = tcpConnect(options);
	if (socketDescriptor == 0)
		return false;

	if (SSL_CTX_set_cipher_list(options->ctx, sslCipherPointer->name) == 0)
		errx(EX_SOFTWARE, "Could not set cipher %s.", sslCipherPointer->name);

	// Create SSL object...
	ssl = SSL_new(options->ctx);
	if (ssl == NULL)
		errx(EX_SOFTWARE, "Could not create SSL object.");

	// Connect socket and BIO
	cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

	// Connect SSL and BIO
	SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

	// Connect SSL over socket
	cipherStatus = SSL_connect(ssl);

	// Show Cipher Status
	if ((options->failed) || (cipherStatus == 1))
	{
		if (options->xmlOutput != 0)
			fprintf(options->xmlOutput, "  <cipher status=\"");
		if (cipherStatus == 1)
		{
			if (options->xmlOutput != 0)
				fprintf(options->xmlOutput, "accepted\"");
			if (options->pout)
				printf("|| Accepted || ");
			else
				printf("    Accepted  ");
			if (options->http)
			{

				// Stdout BIO...
				stdoutBIO = BIO_new(BIO_s_file());
				BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);

				// HTTP Get...
				SSL_write(ssl, requestBuffer, sizeof(requestBuffer));
				memset(buffer ,0 , 50);
				resultSize = SSL_read(ssl, buffer, 49);
				if (resultSize > 9)
				{
					int loop = 0;
					for (loop = 9; (loop < 49) && (buffer[loop] != 0) && (buffer[loop] != '\r') && (buffer[loop] != '\n'); loop++)
					{ }
					buffer[loop] = 0;

					// Output HTTP code...
					if (options->pout)
						printf("%s || ", buffer + 9);
					else
					{
						printf("%s", buffer + 9);
						loop = strlen(buffer + 9);
						while (loop < 17)
						{
							loop++;
							printf(" ");
						}
					}
					if (options->xmlOutput != 0)
						fprintf(options->xmlOutput, " http=\"%s\"", buffer + 9);
				}
				else
				{
					// Output HTTP code...
					if (options->pout)
						printf("|| || ");
					else
						printf("                 ");
				}
			}
		}
		else if (cipherStatus == 0)
		{
			if (options->xmlOutput != 0)
				fprintf(options->xmlOutput, "rejected\"");
			if (options->http)
			{
				if (options->pout)
					printf("|| Rejected || N/A || ");
				else
					printf("    Rejected  N/A              ");
			}
			else
			{
				if (options->pout)
					printf("|| Rejected || ");
				else
					printf("    Rejected  ");
			}
		}
		else
		{
			if (options->xmlOutput != 0)
				fprintf(options->xmlOutput, "failed\"");
			if (options->http)
			{
				if (options->pout)
					printf("|| Failed || N/A || ");
				else
					printf("    Failed    N/A              ");
			}
			else
			{
				if (options->pout)
					printf("|| Failed || ");
				else
					printf("    Failed    ");
			}
		}
		if (options->xmlOutput != 0)
			fprintf(options->xmlOutput, " sslversion=\"%s\" bits=\"%d\" cipher=\"%s\" />\n",
				SSL_get_version(ssl), sslCipherPointer->bits, sslCipherPointer->name);
		if (options->pout)
			printf("%s || %d || %s ||\n", SSL_get_version(ssl), sslCipherPointer->bits, sslCipherPointer->name);
		else
			printf("%-7s  %3d bits  %s\n", SSL_get_version(ssl), sslCipherPointer->bits, sslCipherPointer->name);
	}

	// Disconnect SSL over socket
	if (cipherStatus == 1)
		SSL_shutdown(ssl);

	// Free SSL object
	SSL_free(ssl);

	// Disconnect from host
	close(socketDescriptor);

	return status;
}


// Test for prefered ciphers
int defaultCipher(struct sslCheckOptions *options, SSL_CONST SSL_METHOD *sslMethod)
{
	// Variables...
	int cipherStatus;
	int socketDescriptor = 0;
	SSL *ssl = NULL;
	BIO *cipherConnectionBio;

	// Connect to host
	socketDescriptor = tcpConnect(options);
	if (socketDescriptor == 0)
		return false;

	// Setup Context Object...
	options->ctx = SSL_CTX_new(sslMethod);
	if (options->ctx == NULL)
		errx(EX_SOFTWARE, "Could not create CTX object.");

	if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") == 0)
		errx(EX_SOFTWARE, "Could not set cipher.");

	// Load Certs if required...
	if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
		loadCerts(options);

	// Create SSL object...
	ssl = SSL_new(options->ctx);
	if (ssl == NULL)
		errx(EX_SOFTWARE, "Could not create SSL object.");

	// Connect socket and BIO
	cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

	// Connect SSL and BIO
	SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

	// Connect SSL over socket
	cipherStatus = SSL_connect(ssl);
	if (cipherStatus == 1)
	{
		if (options->xmlOutput != 0)
			fprintf(options->xmlOutput, "  <defaultcipher sslversion=\"%s\" bits=\"%d\" cipher=\"%s\" />\n",
				SSL_get_version(ssl), SSL_get_cipher_bits(ssl,NULL), SSL_get_cipher_name(ssl));

		if (options->pout)
			printf("|| %s || %d || %s ||\n", SSL_get_version(ssl), SSL_get_cipher_bits(ssl,NULL), SSL_get_cipher_name(ssl));
		else
			printf("    %-7s  %3d bits  %s\n", SSL_get_version(ssl), SSL_get_cipher_bits(ssl,NULL), SSL_get_cipher_name(ssl));

		// Disconnect SSL over socket
		SSL_shutdown(ssl);
	}

	// Free SSL object
	SSL_free(ssl);
			
	// Free CTX Object
	SSL_CTX_free(options->ctx);
	
	// Disconnect from host
	close(socketDescriptor);

	return true;
}


// Get certificate...
bool getCertificate(struct sslCheckOptions *options)
{
	// Variables...
	int cipherStatus = 0;
	bool status = true;
	int socketDescriptor = 0;
	SSL *ssl = NULL;
	BIO *cipherConnectionBio = NULL;
	BIO *stdoutBIO = NULL;
	BIO *fileBIO = NULL;
	X509 *x509Cert = NULL;
	EVP_PKEY *publicKey = NULL;
	SSL_CONST SSL_METHOD *sslMethod = NULL;
	ASN1_OBJECT *asn1Object = NULL;
	X509_EXTENSION *extension = NULL;
	char buffer[1024];
	long tempLong = 0;
	int tempInt = 0;
	int tempInt2 = 0;
	long verifyError = 0;

	// Connect to host
	socketDescriptor = tcpConnect(options);
	if (socketDescriptor == 0)
		return false;

	// Setup Context Object...
	sslMethod = SSLv23_method();
	options->ctx = SSL_CTX_new(sslMethod);
	if (options->ctx == NULL)
		errx(EX_SOFTWARE, "Could not create CTX object.");

	if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") == 0)
		errx(EX_SOFTWARE, "Could not set cipher.");

	// Load Certs if required...
	if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
		loadCerts(options);

	// Create SSL object...
	ssl = SSL_new(options->ctx);
	if (ssl == NULL)
		errx(EX_SOFTWARE, "Could not create SSL object.");

	// Connect socket and BIO
	cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

	// Connect SSL and BIO
	SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

	// Connect SSL over socket
	cipherStatus = SSL_connect(ssl);
	if (cipherStatus != 1)
	{
		warnx("Unable to connect.");
		status = false;
		goto failed;
	}

	// Setup BIO's
	stdoutBIO = BIO_new(BIO_s_file());
	BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
	if (options->xmlOutput != 0)
	{
		fileBIO = BIO_new(BIO_s_file());
		BIO_set_fp(fileBIO, options->xmlOutput, BIO_NOCLOSE);
	}

	// Get Certificate...
	printf("\n  SSL Certificate:\n");
	if (options->xmlOutput != 0)
		fprintf(options->xmlOutput, "  <certificate>\n");
	x509Cert = SSL_get_peer_certificate(ssl);
	if (x509Cert == NULL)
	{
		warnx("Unable to get certificate.");
		status = false;
		goto failed2;
	}

	//SSL_set_verify(ssl, SSL_VERIFY_NONE|SSL_VERIFY_CLIENT_ONCE, NULL);

	// Cert Version
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VERSION))
	{
		tempLong = X509_get_version(x509Cert);
		printf("    Version: %lu\n", tempLong);
		if (options->xmlOutput != 0)
			fprintf(options->xmlOutput, "   <version>%lu</version>\n", tempLong);
	}

	// Cert Serial No.
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SERIAL))
	{
		tempLong = ASN1_INTEGER_get(X509_get_serialNumber(x509Cert));
		if (tempLong < 1)
		{
			printf("    Serial Number: -%lu\n", tempLong);
			if (options->xmlOutput != 0)
				fprintf(options->xmlOutput, "   <serial>-%lu</serial>\n", tempLong);
		}
		else
		{
			printf("    Serial Number: %lu\n", tempLong);
			if (options->xmlOutput != 0)
				fprintf(options->xmlOutput, "   <serial>%lu</serial>\n", tempLong);
		}
	}

	// Signature Algo...
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SIGNAME))
	{
		printf("    Signature Algorithm: ");
		i2a_ASN1_OBJECT(stdoutBIO, x509Cert->cert_info->signature->algorithm);
		printf("\n");
		if (options->xmlOutput != 0)
		{
			fprintf(options->xmlOutput, "   <signature-algorithm>");
			i2a_ASN1_OBJECT(fileBIO, x509Cert->cert_info->signature->algorithm);
			fprintf(options->xmlOutput, "</signature-algorithm>\n");
		}
	}

	// SSL Certificate Issuer...
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_ISSUER))
	{
		X509_NAME_oneline(X509_get_issuer_name(x509Cert), buffer, sizeof(buffer) - 1);
		printf("    Issuer: %s\n", buffer);
		if (options->xmlOutput != 0)
			fprintf(options->xmlOutput, "   <issuer><![CDATA[%s]]></issuer>\n", buffer);
	}

	// Validity...
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VALIDITY))
	{
		printf("    Not valid before: ");
		ASN1_TIME_print(stdoutBIO, X509_get_notBefore(x509Cert));
		if (options->xmlOutput != 0)
		{
			fprintf(options->xmlOutput, "   <not-valid-before>");
			ASN1_TIME_print(fileBIO, X509_get_notBefore(x509Cert));
			fprintf(options->xmlOutput, "</not-valid-before>\n");
		}
		printf("\n    Not valid after: ");
		ASN1_TIME_print(stdoutBIO, X509_get_notAfter(x509Cert));
		printf("\n");
		if (options->xmlOutput != 0)
		{
			fprintf(options->xmlOutput, "   <not-valid-after>");
			ASN1_TIME_print(fileBIO, X509_get_notAfter(x509Cert));
			fprintf(options->xmlOutput, "</not-valid-after>\n");
		}
	}

	// SSL Certificate Subject...
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SUBJECT))
	{
		X509_NAME_oneline(X509_get_subject_name(x509Cert), buffer, sizeof(buffer) - 1);
		printf("    Subject: %s\n", buffer);
		if (options->xmlOutput != 0)
			fprintf(options->xmlOutput, "   <subject><![CDATA[%s]]></subject>\n", buffer);
	}

	// Public Key Algo...
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_PUBKEY))
	{
		printf("    Public Key Algorithm: ");
		i2a_ASN1_OBJECT(stdoutBIO, x509Cert->cert_info->key->algor->algorithm);
		printf("\n");
		if (options->xmlOutput != 0)
		{
			fprintf(options->xmlOutput, "   <pk-algorithm>");
			i2a_ASN1_OBJECT(fileBIO, x509Cert->cert_info->key->algor->algorithm);
			fprintf(options->xmlOutput, "</pk-algorithm>\n");
		}

		// Public Key...
		publicKey = X509_get_pubkey(x509Cert);
		if (publicKey == NULL)
		{
			printf("    Public Key: Could not load\n");
			if (options->xmlOutput != 0)
				fprintf(options->xmlOutput, "   <pk error=\"true\" />\n");
		}
		else
		{
			switch (publicKey->type)
			{
				case EVP_PKEY_RSA:
					printf("    RSA Public Key: (%d bit)\n", BN_num_bits(publicKey->pkey.rsa->n));
					if (options->xmlOutput != 0)
						fprintf(options->xmlOutput, "   <pk error=\"false\" type=\"RSA\" bits=\"%d\">\n<![CDATA[", BN_num_bits(publicKey->pkey.rsa->n));
					RSA_print(stdoutBIO, publicKey->pkey.rsa, 6);
					if (options->xmlOutput != 0)
					{
						RSA_print(fileBIO, publicKey->pkey.rsa, 4);
						fprintf(options->xmlOutput, "]]>\n   </pk>\n");
					}
					break;
				case EVP_PKEY_DSA:
					printf("    DSA Public Key:\n");
					if (options->xmlOutput != 0)
						fprintf(options->xmlOutput, "   <pk error=\"false\" type=\"DSA\">\n");
					DSA_print(stdoutBIO, publicKey->pkey.dsa, 6);
					if (options->xmlOutput != 0)
					{
						DSA_print(fileBIO, publicKey->pkey.dsa, 4);
						fprintf(options->xmlOutput, "   </pk>\n");
					}
					break;
#ifndef OPENSSL_NO_EC
				case EVP_PKEY_EC:
					printf("    EC Public Key:\n");
					if (options->xmlOutput != 0)
						fprintf(options->xmlOutput, "   <pk error=\"false\" type=\"EC\">\n");
					EC_KEY_print(stdoutBIO, publicKey->pkey.ec, 6);
					if (options->xmlOutput != 0)
					{
						EC_KEY_print(fileBIO, publicKey->pkey.ec, 4);
						fprintf(options->xmlOutput, "   </pk>\n");
					}
					break;
#endif /* OPENSSL_NO_EC */
				default:
					printf("    Public Key: Unknown\n");
					if (options->xmlOutput != 0)
						fprintf(options->xmlOutput, "   <pk error=\"true\" type=\"unknown\" />\n");
					break;
			}

			EVP_PKEY_free(publicKey);
		}
	}

	// X509 v3...
	if (!(X509_FLAG_COMPAT & X509_FLAG_NO_EXTENSIONS))
	{
		if (sk_X509_EXTENSION_num(x509Cert->cert_info->extensions) > 0)
		{
			printf("    X509v3 Extensions:\n");
			if (options->xmlOutput != 0)
				fprintf(options->xmlOutput, "   <X509v3-Extensions>\n");
			for (tempInt = 0; tempInt < sk_X509_EXTENSION_num(x509Cert->cert_info->extensions); tempInt++)
			{
				// Get Extension...
				extension = sk_X509_EXTENSION_value(x509Cert->cert_info->extensions, tempInt);

				// Print Extension name...
				printf("      ");
				asn1Object = X509_EXTENSION_get_object(extension);
				i2a_ASN1_OBJECT(stdoutBIO, asn1Object);
				tempInt2 = X509_EXTENSION_get_critical(extension);
				BIO_printf(stdoutBIO, ": %s\n", tempInt2 ? "critical" : "");
				if (options->xmlOutput != 0)
				{
					fprintf(options->xmlOutput, "    <extension name=\"");
					i2a_ASN1_OBJECT(fileBIO, asn1Object);
					BIO_printf(fileBIO, "\"%s><![CDATA[", tempInt2 ? " level=\"critical\"" : "");
				}

				// Print Extension value...
				if (!X509V3_EXT_print(stdoutBIO, extension, X509_FLAG_COMPAT, 8))
				{
					printf("        ");
					M_ASN1_OCTET_STRING_print(stdoutBIO, extension->value);
				}
				if (options->xmlOutput != 0)
				{
					if (!X509V3_EXT_print(fileBIO, extension, X509_FLAG_COMPAT, 0))
						M_ASN1_OCTET_STRING_print(fileBIO, extension->value);
					fprintf(options->xmlOutput, "]]></extension>\n");
				}
				printf("\n");
			}
			if (options->xmlOutput != 0)
				fprintf(options->xmlOutput, "   </X509v3-Extensions>\n");
		}
	}

	// Verify Certificate...
	printf("  Verify Certificate:\n");
	verifyError = SSL_get_verify_result(ssl);
	if (verifyError == X509_V_OK)
		printf("    Certificate passed verification\n");
	else
		printf("    %s\n", X509_verify_cert_error_string(verifyError));

	// Free X509 Certificate...
	X509_free(x509Cert);

failed2:
	if (options->xmlOutput != 0)
		fprintf(options->xmlOutput, "  </certificate>\n");

	// Free BIO
	BIO_free(stdoutBIO);
	if (options->xmlOutput != 0)
		BIO_free(fileBIO);

	// Disconnect SSL over socket
	SSL_shutdown(ssl);

failed:
	// Free SSL object
	SSL_free(ssl);

	// Free CTX Object
	SSL_CTX_free(options->ctx);

	// Disconnect from host
	close(socketDescriptor);

	return status;
}


// Test a single host and port for ciphers...
bool testHost(struct sslCheckOptions *options)
{
	// Variables...
	struct sslCipher *sslCipherPointer;
	bool status = true;

	// Resolve Host Name
	options->hostStruct = gethostbyname(options->host);
	if (options->hostStruct == NULL)
	{
		warnx("Could not resolve hostname %s: %s", options->host, hstrerror(h_errno));
		return false;
	}

	// Configure Server Address and Port
	options->serverAddress.sin_family = options->hostStruct->h_addrtype;
	memcpy((char *) &options->serverAddress.sin_addr.s_addr, options->hostStruct->h_addr_list[0], options->hostStruct->h_length);
	options->serverAddress.sin_port = htons(options->port);

	// XML Output...
	if (options->xmlOutput != 0)
		fprintf(options->xmlOutput, " <ssltest host=\"%s\" port=\"%d\">\n", options->host, options->port);

	// Test supported ciphers...
	printf("Testing SSL server %s on port %d\n\n", options->host, options->port);
	printf("  Supported Server Cipher(s):\n");
	if ((options->http) && (options->pout))
		printf("|| Status || HTTP Code || Version || Bits || Cipher ||\n");
	else if (options->pout)
		printf("|| Status || Version || Bits || Cipher ||\n");
	sslCipherPointer = options->ciphers;
	while ((sslCipherPointer != 0) && status)
	{
		// Setup Context Object...
		options->ctx = SSL_CTX_new(sslCipherPointer->sslMethod);
		if (options->ctx == NULL)
			errx(EX_SOFTWARE, "Could not create CTX object.");

		// SSL implementation bugs/workaround
		if (options->sslbugs)
			SSL_CTX_set_options(options->ctx, SSL_OP_ALL | 0);
		else
			SSL_CTX_set_options(options->ctx, 0);

		// Load Certs if required...
		if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
			loadCerts(options);

		// Test
		status = testCipher(options, sslCipherPointer);

		// Free CTX Object
		SSL_CTX_free(options->ctx);
	
		sslCipherPointer = sslCipherPointer->next;
	}

	if (status)
	{
		// Test preferred ciphers...
		printf("\n  Preferred Server Cipher(s):\n");
		if (options->pout)
			printf("|| Version || Bits || Cipher ||\n");
		switch (options->sslVersion)
		{
			case ssl_all:
#ifdef SSL_TXT_SSLV2
				status = status ? defaultCipher(options, SSLv2_client_method()) : false;
#endif
#ifdef SSL_TXT_SSLV3
				status = status ? defaultCipher(options, SSLv3_client_method()) : false;
#endif
#ifdef SSL_TXT_TLSV1
				status = status ? defaultCipher(options, TLSv1_client_method()) : false;
#endif
#ifdef SSL_TXT_TLSV1_1
				status = status ? defaultCipher(options, TLSv1_1_client_method()) : false;
#endif
#ifdef SSL_TXT_TLSV1_2
				status = status ? defaultCipher(options, TLSv1_2_client_method()) : false;
#endif
				break;
#ifdef SSL_TXT_SSLV2
			case ssl_v2:
				status = defaultCipher(options, SSLv2_client_method());
				break;
#endif
#ifdef SSL_TXT_SSLV3
			case ssl_v3:
				status = defaultCipher(options, SSLv3_client_method());
				break;
#endif
#ifdef SSL_TXT_TLSV1
			case tls_v1:
				status = defaultCipher(options, TLSv1_client_method());
				break;
#endif
#ifdef SSL_TXT_TLSV1_1
			case tls_v11:
				status = defaultCipher(options, TLSv1_1_client_method());
				break;
#endif
#ifdef SSL_TXT_TLSV1_2
			case tls_v12:
				status = defaultCipher(options, TLSv1_2_client_method());
				break;
#endif
		}
	}

	if (status && options->printcert)
	{
		status = getCertificate(options);
	}

	// XML Output...
	if (options->xmlOutput != 0)
		fprintf(options->xmlOutput, " </ssltest>\n");

	// Return status...
	return status;
}

static void
usage(void)
{
	fprintf(stderr, "Usage: sslscan [options] [host:port | host]\n\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  --targets=<file>     A file containing a list of hosts to check. Hosts can\n");
	fprintf(stderr, "                       be supplied with ports (i.e. host:port).\n");
	fprintf(stderr, "  --show-failed        List only all ciphers (default lists accepted ciphers).\n");
	fprintf(stderr, "  --show-cert          Print SSL certificate information.\n");
#ifdef SSL_TXT_SSLV2
	fprintf(stderr, "  --ssl2               Only check SSLv2 ciphers.\n");
#endif
#ifdef SSL_TXT_SSLV3
	fprintf(stderr, "  --ssl3               Only check SSLv3 ciphers.\n");
#endif
#ifdef SSL_TXT_TLSV1
	fprintf(stderr, "  --tls1               Only check TLSv1.0 ciphers.\n");
#endif
#ifdef SSL_TXT_TLSV1_1
	fprintf(stderr, "  --tls1.1             Only check TLSv1.1 ciphers.\n");
#endif
#ifdef SSL_TXT_TLSV1_2
	fprintf(stderr, "  --tls1.2             Only check TLSv1.2 ciphers.\n");
#endif
	fprintf(stderr, "  --pk=<file>          A file containing the private key or a PKCS#12 file\n");
	fprintf(stderr, "                       containing a private key/certificate pair.\n");
	fprintf(stderr, "  --pkpass=<password>  The password for the private key or PKCS#12 file.\n");
	fprintf(stderr, "  --certs=<file>       A file containing PEM/ASN.1 client certificates.\n");
	fprintf(stderr, "  --starttls           If a STARTTLS is required to kick an SMTP service\n");
	fprintf(stderr, "                       into action.\n");
	fprintf(stderr, "  --http               Test an HTTP connection.\n");
	fprintf(stderr, "  --bugs               Enable SSL implementation bug work-arounds.\n");
	fprintf(stderr, "  --xml=<file>         Output results to an XML file.\n");
	fprintf(stderr, "  --version            Display the program version.\n");
	fprintf(stderr, "  --help               Display the help text you are now reading.\n");
	fprintf(stderr, "\nExample:\n");
	fprintf(stderr, "  sslscan 127.0.0.1\n");
	exit(EX_USAGE);
}

int main(int argc, char *argv[])
{
	// Variables...
	struct sslCheckOptions options;
	struct sslCipher *sslCipherPointer;
	bool status = true;
	int mode = mode_single;
	int ch;
	FILE *targetsFile;
	char *xmlfile = NULL;
	char *targetfile = NULL;
	char *line = NULL;
	size_t linecapp = 0;
	ssize_t linelen;

	struct option opts[] = {
		{ "bugs",	no_argument,		(int *)&options.sslbugs, true },
		{ "certs",	required_argument,	NULL,	'c' },
		{ "help",	no_argument,		NULL,	'h' },
		{ "http",	no_argument,		(int *)&options.http, true },
		{ "no-failed",	no_argument,		(int *)&options.failed, false },
		{ "show-failed", no_argument,		(int *)&options.failed, true },
		{ "show-cert", no_argument,		(int *)&options.printcert, true },
		{ "pipe",	no_argument,		NULL,	'p' },
		{ "pk",		required_argument,	NULL,	'k' },
		{ "pk-pass",	required_argument,	NULL,	'l' },
#ifdef SSL_TXT_SSLV2
		{ "ssl2",	no_argument,		&options.sslVersion, ssl_v2 },
#endif
#ifdef SSL_TXT_SSLV3
		{ "ssl3",	no_argument,		&options.sslVersion, ssl_v3 },
#endif
		{ "starttls",	no_argument,		(int *)&options.starttls, true },
		{ "targets",	required_argument,	NULL,	't' },
#ifdef SSL_TXT_TLSV1
		{ "tls1",	no_argument,		&options.sslVersion, tls_v1 },
		{ "tls1.0",	no_argument,		&options.sslVersion, tls_v1 },
#endif
#ifdef SSL_TXT_TLSV1_1
		{ "tls1.1",	no_argument,		&options.sslVersion, tls_v11 },
#endif
#ifdef SSL_TXT_TLSV1_2
		{ "tls1.2",	no_argument,		&options.sslVersion, tls_v12 },
#endif
		{ "version",	no_argument,		NULL,	'V' },
		{ "xml",	required_argument,	NULL,	'x' },
		{ NULL,		0,			NULL,	0 }
	};

	// Init...
	memset(&options, 0, sizeof(struct sslCheckOptions));
	/* Some of these are already technically false due to the memset, seatbelts.... */
	options.port = 443;
	options.host = "127.0.0.1";
	options.failed = false;
	options.starttls = false;
	options.sslVersion = ssl_all;
	options.pout = false;
	options.sslbugs = false;
	options.http = false;
	options.printcert = false;

	SSL_library_init();

	while((ch = getopt_long(argc, argv, "Vhp", opts, NULL)) != -1)
		switch(ch) {
			case 'V':
				fprintf(stderr, "%s", program_version);
				return EX_USAGE;
			case 'c':
				options.clientCertsFile = optarg;
				break;
			case 'h':
				usage();
				break;
			case 'k':
				options.privateKeyFile = optarg;
				break;
			case 'l':
				options.privateKeyPassword = optarg;
				break;
			case 'p':
				options.pout = true;
				break;
			case 't':
				mode = mode_multiple;
				targetfile = optarg;
				break;
			case 'x':
				xmlfile = optarg;
				break;
			default:
				break;
		}
	argc -= optind;
	argv += optind;

	// Host (maybe port too)...
	if ((mode == mode_single) && (argc == 1))
	{
		// Get host...
		options.host = strsep(argv, ":");
		if (argv[0] && argv[0][0])
			options.port = atoi(argv[0]);
	} else if (mode == mode_multiple) { /* FALLTHROUGH */ }

	// Not too sure what the user is doing...
	else
		usage();

	// Open XML file output...
	if (xmlfile != NULL)
	{
		options.xmlOutput = fopen(xmlfile, "w");
		if (options.xmlOutput == NULL)
			errx(EX_CANTCREAT, "Could not open XML output file %s.\n", xmlfile);

		// Output file header...
		fprintf(options.xmlOutput, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<document title=\"SSLScan Results\" version=\"%s\" web=\"http://www.titania.co.uk\">\n", xml_version);
	}

	SSLeay_add_all_algorithms();
	ERR_load_crypto_strings();

	// Build a list of ciphers...
	switch (options.sslVersion)
	{
		case ssl_all:
#ifdef SSL_TXT_SSLV2
			populateCipherList(&options, SSLv2_client_method());
#endif
#ifdef SSL_TXT_SSLV3
			populateCipherList(&options, SSLv3_client_method());
#endif
#ifdef SSL_TXT_TLSV1
			populateCipherList(&options, TLSv1_client_method());
#endif
#ifdef SSL_TXT_TLSV1_1
			populateCipherList(&options, TLSv1_1_client_method());
#endif
#ifdef SSL_TXT_TLSV1_2
			populateCipherList(&options, TLSv1_2_client_method());
#endif
			break;
#ifdef SSL_TXT_SSLV2
		case ssl_v2:
			populateCipherList(&options, SSLv2_client_method());
			break;
#endif
#ifdef SSL_TXT_SSLV3
		case ssl_v3:
			populateCipherList(&options, SSLv3_client_method());
			break;
#endif
#ifdef SSL_TXT_TLSV1
		case tls_v1:
			populateCipherList(&options, TLSv1_client_method());
			break;
#endif
#ifdef SSL_TXT_TLSV1_1
		case tls_v11:
			populateCipherList(&options, TLSv1_1_client_method());
			break;
#endif
#ifdef SSL_TXT_TLSV1_2
		case tls_v12:
			populateCipherList(&options, TLSv1_2_client_method());
			break;
#endif
	}

	// Do the testing...
	if (mode == mode_single)
		status = testHost(&options);
	else
	{
		// Open targets file...
		targetsFile = fopen(targetfile, "r");
		if (targetsFile == NULL)
			errx(EX_NOINPUT, "Could not open targets file %s.\n", targetfile);

		while ((linelen = getline(&line, &linecapp, targetsFile)) > 0)
		{
			// Get host...
			options.host = strsep(&line, ":\n");
			if (line && line[0])
				options.port = atoi(line);

			// Test the host...
			status = testHost(&options);
		}
		if (!feof(targetsFile))
			err(EX_IOERR, NULL);
	}

	// Free Structures
	while (options.ciphers != 0)
	{
		sslCipherPointer = options.ciphers->next;
		free(options.ciphers);
		options.ciphers = sslCipherPointer;
	}

	// Close XML file, if required...
	if (xmlfile != NULL)
	{
		fprintf(options.xmlOutput, "</document>\n");
		fclose(options.xmlOutput);
	}

	if (status)
		return 0;
	else
		return EX_SOFTWARE;
}

