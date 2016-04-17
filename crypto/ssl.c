//
// Created by srbvsr on 4/15/16.
//
#include "com.h"
#include "../include/network.h"
#include "../include/config.h"

void handleErrors(void) {
    //ERR_print_errors_fp(stderr);
    //abort();
}

/* A 128 bit key */
//unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
unsigned char key[128];

/* A 128 bit IV */
//unsigned char *iv = (unsigned char *)"01234567890123456";
unsigned char iv[128];
static const SSL_METHOD *meth;
static BIO *bio_err = NULL;
static BIO *bio_fd = NULL;
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;

void ssl_init() {

    memset(key, '\x20', 128);
    memset(iv, 0, 128);

    /* Initialise the library */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    /* Create the context */
    meth = SSLv23_method();
    ctx = SSL_CTX_new(meth);
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    return;
}
bool ssl_cert_init() {

    /* Load certificate into the SSL context */
    if (*config.certfile) {
        if (SSL_CTX_use_certificate_file(ctx, config.certfile,
                                         SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors(bio_err);
            return false;
        }
    }
    /* Load private key into SSL context */
    if (*config.keyfile) {
        if (SSL_CTX_use_PrivateKey_file(ctx, config.keyfile,
                                        SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors(bio_err);
            return false;
        }
    }
    if (*config.cacertfile) {
        /* Load trusted CA. */
        if (!SSL_CTX_load_verify_locations(ctx, config.cacertfile, NULL)) {
            ERR_print_errors(bio_err);
            return false;
        }
    }
}
int ssl_server() {

    int err;
    int cli_sock, cli_len;
    struct sockaddr_in sa_cli;

    /* Intialize tcp socket and wait for connection */
    tcp_listen();
    cli_sock = accept(net_fd, (struct sockaddr *)&sa_cli, &cli_len);
    do_debug("Connection received from %s:%d\n", inet_ntoa(sa_cli.sin_addr),
             ntohs(sa_cli.sin_port));

    /* Set client fd into BIO context */
    bio_fd = BIO_new(BIO_s_socket());
    BIO_set_fd(bio_fd, cli_sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio_fd, bio_fd);

    err = SSL_accept(ssl);
    return 0;

}
int ssl_client() {

    int err;
    /* Connect to server tcp connect socket */
    tcp_connect();

    /* Set  net_fd into BIO context */
    bio_fd = BIO_new(BIO_s_socket());
    BIO_set_fd(bio_fd, net_fd, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio_fd, bio_fd);

    err = SSL_connect(ssl);
}
