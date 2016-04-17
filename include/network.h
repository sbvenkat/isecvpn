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

int data_fd;    /* UDP file descriptor for data communication */
int net_fd;     /* TCP file descriptor for control communication */

bool tcp_connect();
bool tcp_listen();
bool udp_connect();

#endif //ISECVPN_NETWORK_H_H
