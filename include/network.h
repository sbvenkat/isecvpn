//
// Created by srbvsr on 4/16/16.
//

#ifndef ISECVPN_NETWORK_H_H
#define ISECVPN_NETWORK_H_H

#include "common.h"
#include "config.h"
#include "util.h"
#include <netdb.h>
#include <netinet/in.h>

struct datatunnel {
    unsigned short dataport;
    unsigned char  remoteip[20];
    unsigned char client;
};
int udp_tunbind(int port, int *fd);
int hostname_to_ip(char *hostname, char *ip);
bool udp_close(int *fd);
bool tcp_connect();
bool tcp_listen();

#endif //ISECVPN_NETWORK_H_H
