//
// Created by srbvsr on 4/16/16.
//

#ifndef ISECVPN_SSL_H
#define ISECVPN_SSL_H

#include "common.h"
#include "config.h"

void ssl_init();
bool ssl_cert_init();
int ssl_server();
int ssl_client();
void ssl_connect(const char *host, unsigned int port);

#endif //ISECVPN_SSL_H
