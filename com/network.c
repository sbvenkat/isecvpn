//
// Created by srbvsr on 4/16/16.
//
#include "../include/network.h"

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

bool udp_connect() {

    struct sockaddr_in sin, sout;
    int sout_len, ret;
    char MAGIC_WORD[] = "Wazaaaaaaaaaaahhhh";
    char buf[1024];

    // Initialize the UDP socket for data communication
    if ((data_fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        PERROR("socket()");

    memset(&sin, 0, sizeof(struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(config.data_port);
    if (bind(data_fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        PERROR("bind()");

    sout_len = sizeof(sout);
    //Connect to server
    sout.sin_family = AF_INET;
    sout.sin_port = htons(config.data_port);
    inet_aton(config.gateway, &sout.sin_addr);

    ret = sendto(data_fd, MAGIC_WORD, sizeof(MAGIC_WORD), 0, (struct sockaddr *)&sout,
              sizeof(sout));
    if (ret < 0)
        PERROR("sendto");

    ret = recvfrom(data_fd, buf, sizeof(buf), 0, (struct sockaddr *)&sout, &sout_len);
    if (ret < 0)
        PERROR("recvfrom");

    if (strncmp(MAGIC_WORD, buf, sizeof(MAGIC_WORD) != 0)) {
        printf("Bad magic word for peer\n");
        return false;
    }
    return true;
}