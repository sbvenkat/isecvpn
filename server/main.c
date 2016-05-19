//
// Created by srbvsr on 4/14/16.
//

#include "../include/common.h"
#include "../include/util.h"

void print_usage() {

    printf("##################################\n");
    printf("1. Server configuration\n");
    printf("2. Start ISECVPN\n");
    printf("3. Exit ISECVPN\n");
    printf("Action: ");
    return;
}
int main(int argc, char *argv[]) {

    char userinput[MAX_INPUT_LEN];
    char c;
    int DEBUG = 1;

    printf("##################################\n");
    printf("       ISECVPN SERVER             \n");
    print_usage();

    while (1) {
        read_input(userinput);
        switch (userinput[0]) {
            case '1' :
                printf("File name : ");
                read_input(userinput);
                /* Initialize config structure and SSL library */
                vpn_init(userinput);
                break;
            case '2' :
                printf("Initiating ISECVPN server\n");
                ssl_server();
                break;
            case '3' :
                printf("Exit ISECVPN\n");
                ssl_exit();
                exit(1);
                break;
            default:
                break;
        }
        print_usage();
    }
}
