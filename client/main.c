//
// Created by srbvsr on 4/14/16.
//
#include "../include/common.h"
#include "../include/util.h"
#include "../include/network.h"

void print_usage() {

    printf("##################################\n");
    printf("1. Client configuration\n");
    printf("2. Start ISECVPN\n");
    printf("3. Change SSL KEY\n");
    printf("4. Stop ISECVPN\n");
    printf("5. Exit ISECVPN\n");
    printf("Action: ");
    return;
}
int main(int argc, char *argv[]) {

    char userinput[MAX_INPUT_LEN];
    char username[80];
    char passwd[80];
    char c;
    size_t len;

    printf("##################################\n");
    printf("       ISECVPN CLIENT             \n");
    print_usage();

    memset(username, 0, 80);
    memset(passwd, 0, 80);
    while (1) {
        read_input(userinput);
        switch (userinput[0]) {
            case '1' :
                printf("File name : ");
                read_input(userinput);
                /* Initialize config structure and SSL library */
                vpn_init(userinput);
                break;
            case '2':
                printf("User name : ");
                read_input(userinput);
                memcpy(username, userinput, strlen(userinput));
                printf("Password : ");
                read_passwd(userinput);
                memcpy(passwd, userinput, strlen(userinput));
                if(ssl_client(username, passwd))
                    printf("ISECVPN TUN Established\n");
                else
                    printf("ISECVPN TUN Failed\n");
                memset(passwd, 0, 80);
                memset(username, 0, 80);
                break;
            case '3':
                log_debug("Change PRE-SHARED KEY\n");
                ssl_client_key_change();
                break;
            case '4':
                printf("Tunnel tear down\n");
                break;
            case '5' :
                printf("Exit ISECVPN\n");
                ssl_client_exit();
                exit(1);
                break;
            default:
                break;
        }
        print_usage();
    }
}

