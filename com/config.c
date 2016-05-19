//
// Created by srbvsr on 4/14/16.
//
#include "../include/config.h"

struct config_struct config;

void debug_print_config() {

    if (config.data_port)
        printf("DATAPORT=%d\n", config.data_port);
    if (*config.gateway)
        printf("GATEWAY=%s\n", config.gateway);
    if (*config.tunintf)
        printf("TUNINTF=%s\n", config.tunintf);
    if (*config.tunip)
        printf("TUNIP=%s\n", config.tunip);
    if (*config.tunroute)
        printf("TUNROUTE=%s\n", config.tunroute);
    if (*config.certfile)
        printf("CERTFILE=%s\n", config.certfile);
    if (*config.keyfile)
        printf("KEYFILE=%s\n", config.keyfile);
    if (*config.cacertfile)
        printf("CACERTFILE=%s\n", config.cacertfile);

    return;
}
void read_config_file(const char* config_filename) {

    FILE *fp;
    char buf[CONFIG_LINE_BUFFER_SIZE];
    char *del = "=";
    char *token;

    if ((fp=fopen(config_filename, "r")) == NULL) {
        fprintf(stderr, "Failed to open config file %s\n", config_filename);
        exit(EXIT_FAILURE);
    }
    while (!feof(fp)) {
        fgets(buf, CONFIG_LINE_BUFFER_SIZE, fp);
        if (buf[0] == '#' || strlen(buf) < 4) {
            continue;
        }
        if ((token = strtok(buf, del)) == NULL)
            continue;
        if (!strcmp(token, "DATAPORT")) {
            token = strtok(NULL, del);
            config.data_port = atoi(token);
        } else if (!strcmp(token, "SSLPORT")) {
                token = strtok(NULL, del);
                config.ssl_port = atoi(token);
        } else if (!strcmp(token, "HOSTNAME")) {
            token = strtok(NULL, del);
            strncpy(config.hostname, token, 100);
            config.hostname[strcspn(config.hostname, "\n")] = 0;
        } else if (!strcmp(token, "TUNINTF")) {
            token = strtok(NULL, del);
            strncpy(config.tunintf, token, 20);
            config.tunintf[strcspn(config.tunintf, "\n")] = 0;
        } else if (!strcmp(token, "TUNIP")) {
            token = strtok(NULL, del);
            strncpy(config.tunip, token, 20);
            config.tunip[strcspn(config.tunip, "\n")] = 0;
        } else if (!strcmp(token, "TUNROUTE")) {
            token = strtok(NULL, del);
            strncpy(config.tunroute, token, 20);
            config.tunroute[strcspn(config.tunroute, "\n")] = 0;
        } else if (!strcmp(token, "CERTFILE")) {
            token = strtok(NULL, del);
            strncpy(config.certfile, token, 100);
            config.certfile[strcspn(config.certfile, "\n")] = 0;
        } else if (!strcmp(token, "KEYFILE")) {
            token = strtok(NULL, del);
            strncpy(config.keyfile, token, 100);
            config.keyfile[strcspn(config.keyfile, "\n")] = 0;
        } else if (!strcmp(token, "CACERTFILE")) {
            token = strtok(NULL, del);
            strncpy(config.cacertfile, token, 100);
            config.cacertfile[strcspn(config.cacertfile, "\n")] = 0;
        } else if (!strcmp(token, "SERVERCN")) {
            token = strtok(NULL, del);
            strncpy(config.servercn, token, 100);
            config.servercn[strcspn(config.servercn, "\n")] = 0;
        } else
            printf("Invalid parameter %s\n", token);
    }
    fclose(fp);
    //debug_print_config();
    return;
}

