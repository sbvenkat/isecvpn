//
// Created by srbvsr on 4/15/16.
//

#ifndef ISECVPN_COM_H
#define ISECVPN_COM_H

#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "../include/common.h"
#include "../include/ssl.h"

#define PASSWORD_FILE           "shadow"
#define SSL_HMAC_DIGEST_TYPE    "SHA256"
#define SSL_SALT_LENGTH         16

#define DATATUN_KEYIV   0x0001
#define DATATUN_KEYCHG  0x0002
#define DATATUN_INIT    0x0004
#define DATATUN_START   0x0010
#define DATATUN_STOP    0x0020
#define DATATUN_END     0x0040

#define RET_CHK(err, s) if (err == -1) { perror(s); exit(1); }
#define SSL_RET_CHK(err) if ((err) == -1) { ERR_print_errors_fp(stderr); }
#define CHK_ERR_RET(err, s) if (err <= 0) {log_debug(s); return err;}

struct datatun_msg {
    unsigned int msgtype;
    unsigned int msglen;
};

void handleErrors(void);
int gen_random_bytes(char *buf, int bytes);
void ssl_enc_decry_init();

extern SSL *ssl;
extern int ipcfd[2];

int ssl_client_init_vpn(char *username, char *passwd, struct session_param *sslparam);
int ssl_validate_user(char *userpasswd);
int ssl_client_down_vpn(struct session_param *sslparam);
int ssl_init_datapath(bool client);
int ssl_close_datapath(bool client);
int ssl_change_preshare_key(struct session_param *sslparam);
void ssl_keychg_datapath();

#endif //ISECVPN_COM_H
