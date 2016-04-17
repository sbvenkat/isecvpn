//
// Created by srbvsr on 4/14/16.
//
#include "../include/common.h"
#include "../include/util.h"
#include "../include/network.h"

int main(int argc, char *argv[]) {

    struct sockaddr_in sin, sout, from;
    const char *conf_file = "client.conf";
    int recv, fromlen, soutlen;
    char c;
    fd_set fdset;
    int DEBUG = 1;

    init(conf_file);
    ssl_client();

}

/*
int test() {
    while (1) {
        FD_ZERO(&fdset);
        FD_SET(tap_fd, &fdset);
        FD_SET(net_fd, &fdset);
        if (select(tap_fd + net_fd + 1, &fdset, NULL, NULL, NULL) < 0)
            PERROR("select");
        if (FD_ISSET(tap_fd, &fdset)) {
            if (DEBUG)
                write(1,">", 1);
            l = read(tap_fd, buf, sizeof(buf));
            if (l < 0)
                PERROR("read");
            if (sendto(net_fd, buf, l, 0, (struct sockaddr *)&from, fromlen) < 0)
                PERROR("sendto");
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
