//
// Created by srbvsr on 4/14/16.
//
#include "../include/tun.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

int debug;
char *progname;
int tun_fd = 0;
/*
void setip(const char *dev, const char *ipstr) {

    struct ifreq ifr;
    struct sockaddr_in addr;
    int stat, sd;

    memset(&ifr, 0, sizeof(ifr));
    memset(&addr, 0, sizeof(addr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    addr.sin_family = AF_INET;
    sd = socket(addr.sin_family, SOCK_DGRAM, 0);

    stat = inet_pton(addr.sin_family, ipstr, &addr.sin_addr);

    if ((stat == 0) || (stat == -1)) {
        printf("Invalid ip address for tun device\n");
        return;
    }

    ifr.ifr_addr = *(struct sockaddr *) &addr;

    if (ioctl(sd, SIOCSIFADDR, (void *) &ifr) == -1)
        printf("Unable to configure ip address for tun device\n");

    return;
}
*/
/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
bool tun_alloc(int flags) {

    struct ifreq ifr;
    int err;
    char cmd[1024];

    if ((tun_fd = open("/dev/net/tun", O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return false;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags;

    if (*config.tunintf) {
        strncpy(ifr.ifr_name, config.tunintf, IFNAMSIZ);
    }

    if ((err = ioctl(tun_fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(tun_fd);
        return err;
    }
    memset(cmd, 0, 1024);
    sprintf(cmd, "ip addr add %s dev %s", config.tunip, config.tunintf);
    system(cmd);
    memset(cmd, 0, 1024);
    sprintf(cmd, "ifconfig %s up", config.tunintf);
    system(cmd);
    //strcpy(dev, ifr.ifr_name);
    return true;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n) {

    int nread;

    if ((nread = read(fd, buf, n)) < 0) {
        perror("Reading data");
        exit(1);
    }
    return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n) {

    int nwrite;

    if ((nwrite = write(fd, buf, n)) < 0) {
        perror("Writing data");
        exit(1);
    }
    return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

    int nread, left = n;

    while (left > 0) {
        if ((nread = cread(fd, buf, left)) == 0) {
            return 0;
        } else {
            left -= nread;
            buf += nread;
        }
    }
    return n;
}

