//
// Created by srbvsr on 4/16/16.
//
#include "../include/network.h"
static int net_fd;
static int data_fd;
bool tcp_listen() {

    struct sockaddr_in sa_serv;

    if ((net_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        PERROR("tcp_listen()");

    memset(&sa_serv, 0, sizeof(struct sockaddr_in));
    sa_serv.sin_family = AF_INET;
    sa_serv.sin_port = htons(config.ssl_port);
    sa_serv.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(net_fd, (struct sockaddr *)&sa_serv, sizeof(sa_serv)) < 0)
        PERROR("tcp_listen bind");

    if (listen(net_fd, 5) < 0)
        PERROR("tcp_listen listen");

    return true;
}
bool tcp_connect() {

    struct sockaddr_in serv_addr;

    memset(&serv_addr, 0, sizeof(struct sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(config.ssl_port);
    inet_aton(config.gateway, &serv_addr.sin_addr);

    if ((net_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        PERROR("tcp socket()");

    if (connect(net_fd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in)) < 0)
        PERROR("tcp connect()");

    do_debug("Connected to %s:%d\n", inet_ntoa(serv_addr.sin_addr),
             ntohs(serv_addr.sin_port));

    return true;
}
int udp_tunbind(int port, int *fd) {

    struct sockaddr_in sin;

    // Initialize the UDP socket for data communication
    if ((*fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        do_debug("UDP socket error\n");
        return 0;
    }

    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(port);
    if (bind(*fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        do_debug("UDP tun bind failed\n");
        return 0;
    }
    return 1;
}
bool udp_close(int *fd) {

    bool ret = true;

    if (close(*fd) < 0) {
        do_debug("UDP socket close error\n");
        ret = false;
    }
    return ret;
}

int hostname_to_ip(char *hostname , char *ip)
{
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_in *h;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ( (rv = getaddrinfo( hostname , "http" , &hints , &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        h = (struct sockaddr_in *) p->ai_addr;
        strcpy(ip , inet_ntoa( h->sin_addr ) );
    }

    freeaddrinfo(servinfo); // all done with this structure
    return 0;
}

