//
// Created by srbvsr on 4/20/16.
//

#ifndef ISECVPN_MSGPROTO_H
#define ISECVPN_MSGPROTO_H

#include "../include/ssl.h"

#define MSG_ACK     0x1000
#define MSG_FAIL    0x2000

#define AUTH_REQ    0x0001
#define KEY_EXCH    0x0002
#define IV_EXCH     0x0004
#define KEY_CHANGE  0x0008

#define TUN_INIT    0x0010
#define TUN_UP      0x0020
#define TUN_DOWN    0x0040

struct msgheader {
    unsigned int msgtype;
    unsigned int msglen;
};

extern struct session_param sslparam;
int listen_msg();
int form_msg_send(char *msg_buf, unsigned int msg_buf_len, unsigned int mtype);

#endif //ISECVPN_MSGPROTO_H
