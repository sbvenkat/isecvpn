//
// Created by srbvsr on 4/14/16.
//

#ifndef ISECVPN_CONFIG_H
#define ISECVPN_CONFIG_H

#include "common.h"

#define MAX_CONFIG_VARIABLE_LEN 20
#define CONFIG_LINE_BUFFER_SIZE 100
#define MAX_LLIST_NAME_LEN 256
#define MAX_OUT_NAME_LEN 256

struct config_struct {
    unsigned int ssl_port;
    unsigned int data_port;
    unsigned char gateway[20];
    unsigned char tunintf[20];
    unsigned char tunip[20];
    unsigned char tunroute[20];
    unsigned char certfile[100];
    unsigned char keyfile[100];
    unsigned char cacertfile[100];
};

extern struct config_struct config;

void read_config_file(const char* config_filename);

#endif //ISECVPN_CONFIG_H
