//
// Created by srbvsr on 4/14/16.
//

#ifndef ISECVPN_UTIL_H
#define ISECVPN_UTIL_H

#include "common.h"
#include "config.h"
#include "ssl.h"
#include "tun.h"

void my_err(char *msg, ...);
void do_debug(char *msg, ...);
void init(const char *config_file);

extern int debug;

#endif //ISECVPN_UTIL_H
