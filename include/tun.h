//
// Created by srbvsr on 4/14/16.
//

#ifndef ISECVPN_TUN_H
#define ISECVPN_TUN_H

#include "common.h"
#include "config.h"
#include <linux/if.h>
#include <linux/if_tun.h>

extern int tun_fd;

#define TUNFLAGS IFF_TUN

struct tunintf {
    char tun_name[64];
    char tun_ip[64];
    char tun_route[64];
    unsigned char tun_flags;
};

bool tun_alloc(struct tunintf *tunparam, int *fd);
bool tun_close(struct tunintf *tunparam, int *fd);

#endif //ISECVPN_TUN_H
