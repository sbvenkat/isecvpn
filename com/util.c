//
// Created by srbvsr on 4/14/16.
//
#include "../include/util.h"
#include <linux/if_tun.h>

int debug = 1;
/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

    va_list argp;

    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
}
/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...) {

    va_list argp;

    if (debug) {
        va_start(argp, msg);
        vfprintf(stderr, msg, argp);
        va_end(argp);
    }
}
void init(const char *config_file) {

    /*Read the configuration file and populate config_struct */
    memset(&config , 0, sizeof(struct config_struct));
    read_config_file(config_file);

    /* Initialize ssl library */
    ssl_init();

    /* initialize tun interface */
    tun_alloc(IFF_TUN | IFF_NO_PI);
    do_debug("Successfully connected to interface %s\n", config.tunintf);

}
