//
// Created by srbvsr on 4/14/16.
//

#include "../include/common.h"
#include "../include/util.h"

int main(int argc, char *argv[]) {

    struct sockaddr_in sin, sout, from;
    const char *conf_file = "serv.conf";
    int recv, fromlen, soutlen;
    char c;
    fd_set fdset;
    int DEBUG = 1;

    init(conf_file);
    ssl_server();
}
/*
int temp() {


    fromlen = sizeof(from);
    while (1) {
        recv = recvfrom(net_fd, buf, sizeof(buf), 0, (struct sockaddr *)&from,
                        &fromlen);
        if (recv < 0)
            PERROR("recvfrom()");
        if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD)) == 0)
            break;
        printf("Bad Magic received\n");
    }

    recv = sendto(net_fd, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&from, fromlen);
    if (recv < 0)
        PERROR("sendto");

    printf("Connection with %s:%i established\n", inet_ntoa(from.sin_addr),
           ntohs(from.sin_port));

    while (1) {
        FD_ZERO(&fdset);
        FD_SET(tap_fd, &fdset);
        FD_SET(net_fd, &fdset);

        if (select(tap_fd + net_fd +1, &fdset, NULL, NULL, NULL) < 0)
            PERROR("select");

        if (FD_ISSET(tap_fd, &fdset)) {
            if (DEBUG)
                write(1,">", 1);
            l = read(tap_fd, buf, sizeof(buf));
            if (l < 0)
                PERROR("read");
            if (sendto(net_fd, buf, l, 0, (struct sockaddr *)&from, fromlen) < 0) PERROR("sendto");
        } else {
            if (DEBUG)
                write(1,"<", 1);
            l = recvfrom(net_fd, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &soutlen);

            if ((sout.sin_addr.s_addr != from.sin_addr.s_addr) ||
                    (sout.sin_port != from.sin_port))
                printf("Got packet from  %s:%i instead of %s:%i\n",
                       inet_ntoa(sout.sin_addr), ntohs(sout.sin_port),
                       inet_ntoa(from.sin_addr), ntohs(from.sin_port));
            if (write(tap_fd, buf, l) < 0)
                PERROR("write");
        }
    }
    return 0;
}
 */