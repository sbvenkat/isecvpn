//
// Created by srbvsr on 4/21/16.
//

#ifndef ISECVPN_CRYPTOINFRA_H
#define ISECVPN_CRYPTOINFRA_H

#include "../include/ssl.h"
#include "sslutil.h"
#include <openssl/hmac.h>

#define CRYPTO_BLOCK_SIZE   16
#define HMAC_LEN            16
#define CIPHER_IV_LEN      16

struct sslvpnhdr {
    unsigned int id;
    unsigned int seq;
    char cipheriv[CIPHER_IV_LEN];
};

struct cipherbuf {
    struct sslvpnhdr *hdr;
    char *ciphertext;
    char *hmac;
};

int encrypt(char *inbuf, unsigned short inlen, char **outbuf, unsigned short *outlen,
            struct session_param *sslparam);
int decrypt(char *inbuf, unsigned short inlen, char **outbuf, unsigned short *outlen,
            struct session_param *sslparam);

#endif //ISECVPN_CRYPTOINFRA_H
