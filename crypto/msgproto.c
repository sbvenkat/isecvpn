//
// Created by srbvsr on 4/20/16.
//
#include "msgproto.h"
#include "sslutil.h"
#include "../include/util.h"

static void print_hex(char *buf, int len) {

    int i = 0;
    for (; i < len; i++)
        printf("%02X", buf[i]);
    printf("\n");
}
static unsigned char *exch_msg(char *buf, unsigned int *resptype) {

    int err;
    struct msgheader *hdr = (struct msgheader *)buf;
    struct msgheader resphdr;
    unsigned char *respbuf;

    err = SSL_write(ssl, buf, hdr->msglen + sizeof(struct msgheader));
    if (err <= 0) {
        do_debug("%s : MSG %d send error \n", __FUNCTION__, hdr->msgtype);
        return NULL;
    }
    memset(&resphdr, 0, sizeof(resphdr));
    SSL_read(ssl, (char *)&resphdr, sizeof(resphdr));

    *resptype = resphdr.msgtype;
    if (resphdr.msglen == 0)
        return NULL;
    respbuf = malloc(resphdr.msglen);
    err = SSL_read(ssl, respbuf, resphdr.msglen);
    if (err <= 0) {
        do_debug("%s: MSG %d response receive error\n", __FUNCTION__, resphdr.msgtype);
        return NULL;
    }
    return respbuf;

}
int form_msg_send(char *msg_buf, unsigned int msg_buf_len, unsigned int mtype) {

    unsigned int resptype;
    char send_buf[1024];
    char *resp_buf = NULL;
    struct msgheader *hdr;
    unsigned char *data = NULL;
    int ret = 1;

    memset(send_buf, 0, 1024);
    hdr = (struct msgheader *)send_buf;
    data = (unsigned char *)(send_buf + sizeof(struct msgheader));

    hdr->msgtype = mtype;
    if (msg_buf) {
        //strncpy(data, msg_buf, strlen(msg_buf));
        memcpy(data, msg_buf, msg_buf_len);
        hdr->msglen = msg_buf_len + 1;
    } else
        hdr->msglen = 0;

    resp_buf = exch_msg(send_buf, &resptype);
    switch (resptype) {
        case MSG_FAIL:
            ret = -1;
            break;
        case MSG_ACK:
            //process response message from server
            break;
        default:
            break;
    }
    if (!resp_buf)
        free(resp_buf);
    return ret;

}
void respond_msgtype(unsigned int msgtype) {

    struct msgheader resphdr;

    memset(&resphdr, 0, sizeof(resphdr));
    resphdr.msgtype = msgtype;
    resphdr.msglen = 0;

    SSL_write(ssl, (char *)&resphdr, sizeof(resphdr));
    return;
}
void set_sslparam_key(char *buf, int len) {

    log_debug("%s KEY received\n", __FUNCTION__);
    memcpy(sslparam.key, buf, len);
    log_debug_hex(sslparam.key, KEYLEN);
    return;
}
/*
void set_sslparam_iv(char *buf, int len) {

    log_debug("%s IV received\n", __FUNCTION__);
    memcpy(sslparam.iv, buf, len);
    log_debug_hex(sslparam.iv, IVLEN);
    return;
}
 */
int process_msgtype(unsigned int msgtype) {

    int ret = 1;
    switch (msgtype) {
        case TUN_UP:
            log_debug("%s Recv TUN  UP message\n", __FUNCTION__);
            ssl_init_datapath(false);
            respond_msgtype(MSG_ACK);
            break;
        case TUN_DOWN:
            log_debug("%s RECV TUN down message\n", __FUNCTION__);
            ssl_close_datapath(true);
            respond_msgtype(MSG_ACK);
            break;
        default:
            log_debug("%s Invalid message type\n", __FUNCTION__);
            break;
    }
    return ret;
}
int process_msg(char *recvbuf, struct msgheader *msg) {

    int ret = 1;
    int chk = 1;
    switch (msg->msgtype) {
        case AUTH_REQ:
            log_debug("%s: Recv MSG CLIENT AUTH REQ\n", __FUNCTION__);
            chk = ssl_validate_user(recvbuf);
            if (chk)
                respond_msgtype(MSG_ACK);
            else {
                respond_msgtype(MSG_FAIL);
                ret = 0;
            }
            break;
        case KEY_EXCH:
            log_debug("%s: Recv MSG KEY Exch\n", __FUNCTION__);
            set_sslparam_key(recvbuf, msg->msglen - 1);
            respond_msgtype(MSG_ACK);
            break;
        case IV_EXCH:
            log_debug("%s: Recv MSG IV Exch\n", __FUNCTION__);
            //set_sslparam_iv(recvbuf, msg->msglen -1);
            respond_msgtype(MSG_ACK);
            break;
        case KEY_CHANGE:
            log_debug("%s: Recv MSG KEY_CHANGE\n", __FUNCTION__);
            set_sslparam_key(recvbuf, msg->msglen - 1);
            ssl_keychg_datapath();
            respond_msgtype(MSG_ACK);
            break;
        default:
            log_debug("%s Invalid message type\n", __FUNCTION__);
            respond_msgtype(MSG_FAIL);
            break;
    }
    return ret;
}
int listen_msg() {

    int ret;
    int err;
    struct msgheader recvhdr;
    unsigned char *recvbuf = NULL;

    memset(&recvhdr, 0, sizeof(struct msgheader));
    while (1) {
        err = SSL_read(ssl, (char *)&recvhdr, sizeof(recvhdr));
        if (err <= 0)
            break;
        log_debug("%s MSG RCV type %d, len %d\n", __FUNCTION__, recvhdr.msgtype, recvhdr.msglen);
        if (!recvhdr.msglen) {
            ret = process_msgtype(recvhdr.msgtype);
        } else {
            recvbuf = malloc(recvhdr.msglen);
            err = SSL_read(ssl, recvbuf, recvhdr.msglen);
            log_debug("%s SSL read msg %d bytes %d\n", __FUNCTION__, recvhdr.msgtype, err);
            if (err <= 0) {
                log_debug("%s Error reading msg %d data \n", __FUNCTION__, recvhdr.msgtype);
                continue;
            }
            ret = process_msg(recvbuf, &recvhdr);
            free(recvbuf);
        }
        if (!ret)
            break;
        memset(&recvhdr, 0, sizeof(struct msgheader));
    }
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}
