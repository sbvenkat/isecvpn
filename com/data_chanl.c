//
// Created by srbvsr on 4/21/16.
//
#include "../include/data_chanl.h"
#include "../crypto/sslutil.h"
#include "../include/tun.h"
#include "../include/network.h"
#include "../crypto/cryptoinfra.h"

#include <sys/select.h>
#include <pthread.h>


static struct session_param sslparam;
static struct tunintf tunparam;
static struct datatunnel datatunparam;

static int tunfd;
static int udpfd;

static pthread_t datathread;
static pthread_mutex_t tunmutex = PTHREAD_MUTEX_INITIALIZER;
static unsigned char datatun = ENCDECR_START;

/* Context for encryption and decryption */
static EVP_CIPHER_CTX ctxenc;
static EVP_CIPHER_CTX ctxdec;
static EVP_MD_CTX ctxhmac;

/* Sockaddr structure */
struct sockaddr_in sout;    /* Outbound */

void encdecr_stop() {

    pthread_mutex_lock(&tunmutex);
    datatun = ENCDECR_STOP;
    pthread_mutex_unlock(&tunmutex);

    return;
}
bool encdecr_check() {

    bool ret = true;
    pthread_mutex_lock(&tunmutex);
    if (datatun == ENCDECR_STOP)
        ret = false;
    pthread_mutex_unlock(&tunmutex);
    return ret;
}
void *datatun_enc_decry(void *arg) {

    int maxfd;
    fd_set rset;
    char readbuf[MAX_PACKET_LEN], *sendbuf = NULL;
    unsigned short sendlen;
    int readlen;
    int ret, sinlen;
    socklen_t soutlen, sreadlen;
    struct sockaddr_in sread;
    char magicword[20] = "wzzzzzaaaah";

    memset(&sread, 0, sizeof(sread));
    memset(&sout, 0, sizeof(sout));
    maxfd = tunfd > udpfd ? tunfd + 1 : udpfd + 1;
    soutlen = sizeof(struct sockaddr_in);
    sreadlen = sizeof(struct sockaddr_in);

    if (datatunparam.client) {
        /* Client side */
        sout.sin_family = AF_INET;
        sout.sin_port = htons(datatunparam.dataport);
        inet_aton(datatunparam.remoteip, &sout.sin_addr);

        encrypt(magicword, strlen(magicword), &sendbuf, &sendlen, &sslparam);
        if (sendto(udpfd, sendbuf, sendlen, 0, (struct sockaddr *)&sout, soutlen) < 0) {
            perror("sendto()");
        }
        if (sendbuf)
            free(sendbuf);
    } else {
        /* Server side */
        if ((readlen = recvfrom(udpfd, readbuf, MAX_PACKET_LEN, 0, (struct sockaddr *)&sout, &soutlen)) < 0 ) {
            log_stat("%s Error read ecnrypt on server\n", __FUNCTION__);
        }
        decrypt(readbuf, readlen, &sendbuf, &sendlen, &sslparam);
        if(sendbuf)
            free(sendbuf);
        /*
        if ((ret = write(tunfd, sendbuf, sendlen)) < 0) {
            do_debug("Write plain text error\n");
        }
         */
    }

    while(1) {
        if(!encdecr_check()) {
            log_stat("%s Exiting the thread\n", __FUNCTION__);
            pthread_exit(NULL);
        }
        /* Check for data on descriptors, encrypt or decrypt */
        FD_ZERO(&rset);
        FD_SET(tunfd, &rset);
        FD_SET(udpfd, &rset);
        if (select(maxfd, &rset, NULL, NULL, NULL) < 0) {
            log_debug("%s select error\n", __FUNCTION__);
            perror("select():");
        }

        if (FD_ISSET(tunfd, &rset)) { /* Received plain text on tun */
            memset(readbuf, 0, MAX_PACKET_LEN);
            if ((readlen = read(tunfd, readbuf, MAX_PACKET_LEN)) < 0 ) {
                log_stat("%s Error read plain text\n", __FUNCTION__);
                continue;
            }
            log_stat("%s:%d read %d from tunfd\n", __FUNCTION__, __LINE__, readlen);
            /* Encrypt and send on udp tunnel */
            encrypt(readbuf, readlen, &sendbuf, &sendlen, &sslparam);
            if (sendto(udpfd, sendbuf, sendlen, 0, (struct sockaddr *)&sout, soutlen) < 0) {
                log_stat("%s Error sendto encrypt text", __FUNCTION__);
                perror("sendto()");
            }
            log_stat("%s:%d sent %d to udpfd\n", __FUNCTION__, __LINE__, sendlen);
            if (sendbuf)
                free(sendbuf);
        }
        if (FD_ISSET(udpfd, &rset)) { /* Received Encrypted text on udp */
            memset(readbuf, 0, MAX_PACKET_LEN);
            if ((readlen = recvfrom(udpfd, readbuf, MAX_PACKET_LEN, 0, (struct sockaddr *)&sread, &sreadlen)) < 0) {
                perror("recvfrom():");
                log_stat("%s Error read encrypt text\n", __FUNCTION__);
                continue;
            }
            log_stat("%s:%d read %d from udpfd\n", __FUNCTION__, __LINE__, readlen);
            /* Decrypt and send on tun device */
            decrypt(readbuf, readlen, &sendbuf, &sendlen, &sslparam);
            if ((ret = write(tunfd, sendbuf, sendlen)) < 0) {
                log_stat("%s Write plain text error\n", __FUNCTION__);
            }
            log_stat("%s:%d write %d to tunfd\n", __FUNCTION__, __LINE__, ret);
            if (sendbuf)
                free(sendbuf);
        }
    }
}

int datatun_start(struct datatunnel *param) {

    int ret = 1;
    int ret1;

    if (!udp_tunbind(param->dataport, &udpfd)) {
        do_debug("UDP bind failed exit process\n");
        return -1;
    }
    ret1 = pthread_create(&datathread, NULL, datatun_enc_decry, NULL);
    return ret;
}
int datatun_down() {

}
int datatun_end() {

    int ret = 1;

    log_debug("%s Stop encypt decrypt thread \n", __FUNCTION__);
    encdecr_stop();
    log_debug("%s Stop tunnel\n", __FUNCTION__);
    tun_close(&tunparam, &tunfd);
    log_debug("%s Stop UDP\n", __FUNCTION__);
    udp_close(&udpfd);
    close(ipcfd[0]);
    close(ipcfd[1]);

    return ret;
}
static void print_hex(char *buf, int len) {

    int i = 0;
    for (; i < len; i++)
        printf("%02X", buf[i]);
    printf("\n");
}
void datapath_process() {

    int ret;
    char *recvbuf = NULL;
    struct datatun_msg dtunmsg;
    unsigned short port;

    memset(&dtunmsg, 0, sizeof(dtunmsg));
    while (1) {

        if ((ret = read(ipcfd[0], (char *)&dtunmsg, sizeof(struct datatun_msg))) == -1) {
            perror("Data chanl process read():");
            continue;
        }
        if (dtunmsg.msglen != 0) {
            recvbuf = malloc(dtunmsg.msglen);
            if ((ret = read(ipcfd[0], recvbuf, dtunmsg.msglen)) == -1) {
                log_debug("%s: Data Chanl message %d read fail\n", __FUNCTION__, dtunmsg.msgtype);
                perror("Data chanl process read():");
            }
        }
        switch (dtunmsg.msgtype) {
            case DATATUN_KEYIV:
                /* Copy data to global variable sslparam */
                memcpy(&sslparam, recvbuf, sizeof(sslparam));
                log_debug("%s: Recv MSG DATATUN_KEYIV\n", __FUNCTION__);
                log_debug_hex(sslparam.key, 16);
                break;
            case DATATUN_INIT:
                /* Copy data to global variable tunparam */
                memcpy(&tunparam, recvbuf, sizeof(tunparam));
                log_debug("%s: Recv MSG DATATUN_INIT\n", __FUNCTION__);
                log_debug("%s: TUN PARAM %s, %s\n", __FUNCTION__, tunparam.tun_ip, tunparam.tun_name);
                /*Open tun device and set global descriptor tunfd*/
                if (!tun_alloc(&tunparam, &tunfd)) {
                    log_debug("TUN device creation failed\n");
                }
                break;
            case DATATUN_START:
                log_debug("%s: Recv DATATUN_START\n", __FUNCTION__);
                memcpy(&datatunparam, recvbuf, sizeof(datatunparam));
                log_debug("%s: Datapath on Port %d, IP %s\n", __FUNCTION__, datatunparam.dataport,
                          datatunparam.remoteip);
                datatun_start(&datatunparam);
                break;
            case DATATUN_STOP:
                encdecr_stop();
                datatun_down();
                break;
            case DATATUN_KEYCHG:
                log_debug("%s: Recv DATATUN_KEYCHG\n", __FUNCTION__);
                memcpy(&sslparam, recvbuf, sizeof(sslparam));
                log_debug_hex(sslparam.key, 16);
                break;
            case DATATUN_END:
                log_debug("%s:%d Datapath end msg recv\n", __FUNCTION__, __LINE__);
                datatun_end();
                exit(1);
                break;
            default:
                break;
        }
        if (!recvbuf)
            free(recvbuf);
        memset(&dtunmsg, 0, sizeof(dtunmsg));
    }
}
