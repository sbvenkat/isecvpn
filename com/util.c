//
// Created by srbvsr on 4/14/16.
//
#include "../include/util.h"
#include <termios.h>

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
void log_debug(char *msg, ...) {

    va_list argp;
    FILE *fp = NULL;

    if (!(fp = fopen(LOGFILE, "a"))) {
        do_debug("Unable to open log file\n");
        return;
    }

    if (debug) {
        va_start(argp, msg);
        vfprintf(fp, msg, argp);
        va_end(argp);
    }

    fclose(fp);
}
void log_debug_hex(char *buf, unsigned int len) {

    FILE *fp = NULL;
    int i = 0;

    if (!(fp = fopen(LOGFILE, "a"))) {
        do_debug("Unable to open log file\n");
        return;
    }
    for (; i < len; i++)
        fprintf(fp, "%01X", buf[i]);
    fprintf(fp, "\n");

    fclose(fp);
}
void log_stat(char *msg, ...) {

    va_list argp;
    FILE *fp = NULL;

    if (!(fp = fopen(STATFILE, "a"))) {
        do_debug("Unable to open stat log file\n");
        return;
    }

    if (debug) {
        va_start(argp, msg);
        vfprintf(fp, msg, argp);
        va_end(argp);
    }

    fclose(fp);
}
void get_tunparam(struct tunintf *tunparam) {

    if (!tunparam)
        return;

    memset(tunparam, 0, sizeof(struct tunintf));

    sprintf(tunparam->tun_name, "%s", config.tunintf);
    sprintf(tunparam->tun_ip, "%s", config.tunip);
    sprintf(tunparam->tun_route, "%s", config.tunroute);
    tunparam->tun_flags = TUNFLAGS;

    return;
}
void read_input(char *input) {
    char *buf = NULL;
    size_t len;
    memset(input, 0, MAX_INPUT_LEN);
    if(getline(&buf, &len, stdin) != -1) {
        sprintf(input, "%s", buf);
        free(buf);
    }
    input[strcspn(input, "\n")] = 0;
    return;
}
void read_passwd(char *input)
{
    struct termios oldattr, newattr;
    char *buf = NULL;
    size_t len;

    memset(input, 0, MAX_INPUT_LEN);
    tcgetattr(STDIN_FILENO, &oldattr);
    newattr = oldattr;
    newattr.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newattr);
    if(getline(&buf, &len, stdin) != -1) {
        sprintf(input, "%s", buf);
        free(buf);
    }
    input[strcspn(input, "\n")] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
    return ;
}
void vpn_init(const char *config_file) {

    /*Read the configuration file and populate config_struct */
    memset(&config , 0, sizeof(struct config_struct));
    read_config_file(config_file);

    /* Initialize ssl library */
    ssl_init();

}
