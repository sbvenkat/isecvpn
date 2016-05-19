//
// Created by srbvsr on 4/16/16.
//
#ifndef ISECVPN_SSL_H
#define ISECVPN_SSL_H

#include "common.h"
#include "config.h"

#define KEYLEN 16
#define IVLEN 16
#define SSL_TOTAL_CLIENT 10
struct session_param {
    unsigned int id;
    unsigned char key[KEYLEN];
    //unsigned char iv[IVLEN];
};

void ssl_init();
bool ssl_cert_init();
bool ssl_server();
bool ssl_client(char *username, char *passwd);
void ssl_client_exit();
void ssl_client_key_change();
void ssl_exit();
void ssl_connect(const char *host, unsigned int port);
void get_sessionparam(struct session_param *param);

#endif //ISECVPN_SSL_H
