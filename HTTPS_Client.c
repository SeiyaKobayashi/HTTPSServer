
// HTTPS (HTTP over SSL) Client written in c

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL   -1

int OpenConnection(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }

    sd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    addr.sin_port = htons(port);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void) {
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();       // add all algorithms to the table (digests & ciphers)
    SSL_load_error_strings();       // add all error messages
    method = TLSv1_2_client_method();       // create a new server-method instance
    ctx = SSL_CTX_new(method);      // create a new SSL_CTX instance from method

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void ShowCerts(SSL* ssl) {
    X509 *cert;
    char *line;

    // return a pointer to the X509 certificate that the peer presented
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No client certificates configured.\n");
}

int main(int count, char *strings[]) {
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;

    if (count != 3) {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

    // register the available SSL/TLS ciphers and digests
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];

    ctx = InitCTX();　     // initialize SSL
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);       // create a new SSL connection state
    SSL_set_fd(ssl, server);      // attach the socket descriptor

    if (SSL_connect(ssl) == FAIL)
        ERR_print_errors_fp(stderr);
    else {
        char *msg = "Hello???";

        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);
        SSL_write(ssl, msg, strlen(msg));       //encrypt and send message
        bytes = SSL_read(ssl, buf, sizeof(buf));      //get reply and decrypt
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        SSL_free(ssl);
    }

    close(server);      // close the socket
    SSL_CTX_free(ctx);      // release context
    return 0;
}
