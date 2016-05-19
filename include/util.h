//
// Created by srbvsr on 4/14/16.
//

#ifndef ISECVPN_UTIL_H
#define ISECVPN_UTIL_H

#include "common.h"
#include "config.h"
#include "ssl.h"
#include "tun.h"


#define MAX_INPUT_LEN 100
#define LOGFILE   "vpnlog.txt"
#define STATFILE  "statlog.txt"

void my_err(char *msg, ...);
void do_debug(char *msg, ...);
void log_stat(char *msg, ...);
void log_debug(char *msg, ...);
void log_debug_hex(char *buf, unsigned int len);
void vpn_init(const char *config_file);
void get_tunparam(struct tunintf *tunparam);
void read_input(char *str);
void read_passwd(char *str);
extern int debug;

#endif //ISECVPN_UTIL_H
