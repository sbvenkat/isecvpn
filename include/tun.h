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

bool tun_alloc(int flags);
int cread(int fd, char *buf, int n);
int cwrite(int fd, char *buf, int n);
int read_n(int fd, char *buf, int n);

#endif //ISECVPN_TUN_H
