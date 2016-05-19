//
// Created by srbvsr on 4/15/16.
//
#include "sslutil.h"
#include "../include/network.h"
#include "../include/config.h"
#include "msgproto.h"
#include <stdio.h>
#include <pthread.h>

void handleErrors(void) {
    //ERR_print_errors_fp(stderr);
    //abort();
}

struct session_param sslparam;
static const SSL_METHOD *meth;
static SSL_CTX *ctx = NULL;
SSL *ssl = NULL;

static BIO *tcpconn = NULL;     /* BIO for client tcp connect socket */
static BIO *tcplisten = NULL;   /* BIO for server tcp listen socket*/

static BIO *bio_err = NULL;

void get_sessionparam(struct session_param *param) {

    memcpy(param, &sslparam, sizeof(sslparam));
    return;
}
void ssl_init() {

    memset(&sslparam, 0, sizeof(sslparam));
    /* Initialise the library */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    ERR_load_BIO_strings();

    /* Create the context */
    if ((meth = SSLv23_method()) == NULL) {
        do_debug("Error SSLv23_method\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    if((ctx = SSL_CTX_new(meth)) == NULL) {
        do_debug("Error SSL_CTX_new\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    do_debug("SSL Context INIT Success\n");

    /* Initialize certificates */
    if(!ssl_cert_init()) {
        do_debug("Certificate Load Fail\n");
        exit(1);
    }
    /*
    if((ssl = SSL_new(ctx)) == NULL) {
        do_debug("Error SSL_new\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
     */
    do_debug("SSL Structure INIT Success\n");
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
        do_debug("Server Certificate Load Success: %s\n", config.certfile);
    }
    /* Load private key into SSL context */
    if (*config.keyfile) {
        if (SSL_CTX_use_PrivateKey_file(ctx, config.keyfile,
                                        SSL_FILETYPE_PEM) <= 0) {
            ERR_print_errors(bio_err);
            return false;
        }
        do_debug("Server Key Load Success: %s\n", config.keyfile);
    }
    if (*config.cacertfile) {
        /* Load trusted CA. */
        if (!SSL_CTX_load_verify_locations(ctx, config.cacertfile, NULL)) {
            ERR_print_errors(bio_err);
            return false;
        }
        do_debug("Certificate Chain Load Success: %s\n", config.cacertfile);
    }
    SSL_CTX_set_verify_depth(ctx, 2);
    return true;
}
static void ssl_print_peer(BIO *sbio) {

    struct sockaddr saddr;
    socklen_t saddrlen = sizeof(saddr);
    struct sockaddr_in *s;
    int fd;

    BIO_get_fd(sbio, &fd);
    getpeername(fd, &saddr, &saddrlen);
    s = (struct sockaddr_in *)&saddr;

    log_debug("Connection established at %s:%d\n", inet_ntoa(s->sin_addr),
            ntohs(s->sin_port));
    return;
}
static void print_cert() {

    X509 *cert = NULL;
    char *str = NULL;
    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server Certificate\n");
        str = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        if (str == NULL)
            return;
        log_debug("%s subject: %s\n", __FUNCTION__, str);
        free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        if (str == NULL)
            return;
        log_debug("%s issuer: %s\n", __FUNCTION__, str);
        free(str);

        X509_free(cert);
    }
}
static bool ssl_verify_cert() {
    X509 *cert = NULL;
    X509_NAME *subject = NULL;
    char cnvalue[256];
    unsigned char *last;
    int i, k;
    bool ret = false;
    long err;

    cert = SSL_get_peer_certificate(ssl);

    if (cert == NULL)
        return ret;
    X509_VERI
    if ((err = SSL_get_verify_result(ssl)) != X509_V_OK) {
        //ERR_print_errors_fp(stdout);
        fprintf(stdout, "-Error: peer certificate: %s\n", X509_verify_cert_error_string(err));
        log_debug("%s Certificate Verification Falied\n", __FUNCTION__);
        goto done;
    }
    print_cert();

    if ((subject = X509_get_subject_name(cert)) == NULL) {
        log_debug("%s:%d Unable to get subject name\n", __FUNCTION__, __LINE__);
        goto done;
    }
    memset(cnvalue, 0, 256);
    if (X509_NAME_get_text_by_NID(subject, NID_commonName, cnvalue, 256) < 0) {
        log_debug("%s: Unable to retrieve CommonName\n", __FUNCTION__);
        goto done;
    }

    last = strrchr(cnvalue, '.');
    for (i = (char *)last - cnvalue - 1; i >= 0; i--)
        if (cnvalue[i] == '.')
            break;

    last = strrchr(config.hostname, '.');
    for (k = last - config.hostname - 1; k >= 0; k--)
        if (config.hostname[k] == '.')
            break;

    if (strlen(cnvalue + i + 1) != strlen(config.hostname + k + 1)) {
        log_debug("%s: Certificate Common Name %s validation failed\n", __FUNCTION__, cnvalue);
        goto done;
    }
    if (memcmp(cnvalue + i + 1, config.hostname + k + 1, strlen(cnvalue + i + 1))) {
        log_debug("%s Certificate Common Name %s validation failed\n", __FUNCTION__, cnvalue);
        goto done;
    }
    log_debug("%s Certificate Common Name validation success\n");
    /* Certificate validation success */
    ret = true;
done:
    X509_free(cert);
    return ret;

}
void *ssl_server_to_client(void *arg) {

    BIO *clientsock = (BIO *)arg;
    int err;

    if((ssl = SSL_new(ctx)) == NULL) {
        do_debug("Error SSL_new\n");
        ERR_print_errors_fp(stderr);
        //exit(1);
    }
    SSL_set_bio(ssl, clientsock, clientsock);

    ssl_print_peer(clientsock);

    if((err = SSL_accept(ssl)) < 0) {
        do_debug("SSL Handshake failed\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    if(listen_msg()) {
        printf("SSL_shutdown received\n");
        SSL_clear(ssl);
    }
    else
        SSL_shutdown(ssl);

    if (clientsock)
        BIO_free(clientsock);

    return NULL;
}

bool ssl_server() {

    int err;
    int cli_sock, cli_len;
    struct sockaddr_in sa_cli;
    BIO *accept = NULL;
    char port[3];
    pthread_t clientthread[SSL_TOTAL_CLIENT];
    int i = 0;

    sprintf(port, "%d", config.ssl_port);
    tcplisten = BIO_new_accept(port);
    if (!tcplisten) {
        do_debug("Error BIO_new_accept\n");
        return false;
    }
    /* Required twice */
    if (BIO_do_accept(tcplisten) <= 0) {
        do_debug("Error accepting connection\n");
        return false;
    }
    while(i < SSL_TOTAL_CLIENT) {
        if (BIO_do_accept(tcplisten) <= 0) {
            do_debug("Error accepting connection\n");
            return false;
        }
        accept = BIO_pop(tcplisten);
        pthread_create(&clientthread[i++], NULL, ssl_server_to_client, accept);

    }

    if (tcplisten)
        BIO_free(tcplisten);

    return 0;
}
bool ssl_client(char *username, char *passwd) {

    char port[3];
    unsigned long ip;
    bool ret = false;
    unsigned int id;
    SSL_SESSION *sslsession;

    hostname_to_ip(config.hostname, config.gateway);
    ip = inet_addr(config.gateway);
    sprintf(port, "%d", config.ssl_port);

    tcpconn = BIO_new(BIO_s_connect());
    if (!tcpconn) {
        log_debug("%s:%d Error BIO_new_connect\n", __FUNCTION__, __LINE__);
        goto done;
    }
    BIO_set_conn_ip(tcpconn, &ip);
    BIO_set_conn_port(tcpconn, port);

    if (BIO_do_connect(tcpconn) <= 0) {
        do_debug("Error connecting to remote gateway\n");
        goto done;
    }
    ssl_print_peer(tcpconn);
    /* Set the SSL to tcp connection socket */
    if((ssl = SSL_new(ctx)) == NULL) {
        log_debug("%s:%d Error SSL_new\n", __FUNCTION__, __LINE__);
        ERR_print_errors_fp(stderr);
        goto done;
    }
    SSL_set_bio(ssl, tcpconn, tcpconn);

    if(SSL_connect(ssl) < 0) {
        do_debug("%s:%d SSL Handshake failed\n", __FUNCTION__, __LINE__);
        ERR_print_errors_fp(stderr);
        goto done;
    }
    sslsession = SSL_get_session(ssl);
    SSL_SESSION_get_id(sslsession, &sslparam.id);

    if(ssl_verify_cert() &&
            (ssl_client_init_vpn(username, passwd, &sslparam) != 1)) {

        do_debug("SSL TUN CONTROL PATH INIT failed\n");
        if (ssl) {
            SSL_shutdown(ssl);
            //SSL_clear(ssl);
            ssl = NULL;
        }
        if (tcpconn)
            BIO_free(tcpconn);
        goto done;
    }
    ret = true;
done:
    return ret;
}
void ssl_client_exit() {

    int err = 1;

    /* Send tun down message to server */
    ssl_client_down_vpn(&sslparam);

    /* Bring down the datapath tunnel */
    ssl_close_datapath(true);
    if (ssl) {
        err = SSL_shutdown(ssl);
        ssl = NULL;
        SSL_RET_CHK(err);
    }
    if (tcpconn)
        BIO_free(tcpconn);
}
void ssl_exit() {
    int err;

    ssl_client_exit();
    if (ssl)
        SSL_free(ssl);
    if (ctx)
        SSL_CTX_free(ctx);
}
void ssl_client_key_change() {

    if (ssl_change_preshare_key(&sslparam))
        log_debug("Change PRE-SHARED KEY Sucess\n");
    else
        log_debug("Change PRE-SHARED KEY failed\n");

    return;
}
