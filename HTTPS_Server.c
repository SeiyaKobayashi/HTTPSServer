
// HTTPS (HTTP over SSL) Server written in c

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL  -1

int OpenListener(int port) {
    int sd;       // int variable to store the socket descriptor
    struct sockaddr_in addr;

    sd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&addr, 0, sizeof(struct sockaddr_in));       // is bzero() obsolete?
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Error in binding port");
        abort();
    }
    if (listen(sd, 5) < 0) {
        perror("Error in listening port");
        abort();
    }

    return sd;
}

int isRootUser() {
    if (getuid() != 0)
        return 0;
    else
        return 1;
}

SSL_CTX* InitServerCTX(void) {
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();       // add all algorithms to the table (digests & ciphers)
    SSL_load_error_strings();       // add all error messages
    method = TLSv1_2_server_method();       // create a new server-method instance
    ctx = SSL_CTX_new(method);      // create a new SSL_CTX instance from method

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    // load the first certificate stored in Cerfile into ctx
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // add the first private key found in Keyfile to ctx
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    // verify a private key with the corresponding certificate loaded into ctx
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
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
        printf("No certificates found.\n");
}

// serve the connections
void Servlet(SSL* ssl) {
    char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";

    if (SSL_accept(ssl) == FAIL)      // handle errors in accept
        ERR_print_errors_fp(stderr);
    else {
        ShowCerts(ssl);
        bytes = SSL_read(ssl, buf, sizeof(buf));      // read sizeof(buf) bytes from ssl into buf
        if (bytes > 0) {      // if successful
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf);      // construct reply
            SSL_write(ssl, reply, strlen(reply));       // send reply
        }
        else
            ERR_print_errors_fp(stderr);
    }

    sd = SSL_get_fd(ssl);       // get socket connection
    SSL_free(ssl);      // release SSL state
    close(sd);      // close connection
}

int main(int count, char *strings[]) {
    SSL_CTX *ctx;
    int server;
    char *portnum;

    if(!isRootUser()) {
        printf("This program has to be run as a root user!!");
        exit(0);
    }
    if (count != 2) {
        printf("Usage: %s <portnum>\n", strings[0]);
        exit(0);
    }

    // register the available SSL/TLS ciphers and digests
    SSL_library_init();

    portnum = strings[1];
    ctx = InitServerCTX();      // initialize SSL
    LoadCertificates(ctx, "mycert.pem", "mycert.pem");
    server = OpenListener(atoi(portnum));       // create a server socket
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);       // get new SSL state with context
        SSL_set_fd(ssl, client);      // set connection socket to SSL state
        Servlet(ssl);
    }

    close(server);      // close server socket
    SSL_CTX_free(ctx);      // release context
}
