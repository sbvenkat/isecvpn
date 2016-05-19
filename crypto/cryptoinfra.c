//
// Created by srbvsr on 4/21/16.
//

#include "cryptoinfra.h"
static unsigned int sequence = 10000;

static void print_hex(char *buf, int len) {

    int i = 0;
    for (; i < len; i++)
        printf("%02X", buf[i]);
    printf("\n");
}
int encrypt(char *plaintext, unsigned short plaintext_len, char **outbuf, unsigned short *outlen,
            struct session_param *sslparam) {

    struct cipherbuf cbuf;
    char *temptext;
    char hmac[EVP_MAX_MD_SIZE];
    EVP_CIPHER_CTX ctxenc;
    unsigned int templen, hmaclen;
    unsigned int cbuflen, temptext_len, ciphertext_len;

    /* Max packet length post encryption */
    cbuflen = sizeof(struct sslvpnhdr) + 2 + plaintext_len + EVP_MAX_MD_SIZE + EVP_MAX_BLOCK_LENGTH;
    cbuf.hdr = (struct sslvpnhdr *)malloc(cbuflen);
    memset((char *)cbuf.hdr, 0, cbuflen);

    /* Frame the header */
    cbuf.hdr->id = sslparam->id;
    cbuf.hdr->seq = sequence++;
    gen_random_bytes(cbuf.hdr->cipheriv, CIPHER_IV_LEN);

    /* Temporary plain text with 2B hdr + plaintext */
    temptext = malloc(plaintext_len + 2);
    memset(temptext, 0, plaintext_len + 2);
    memcpy(temptext, &plaintext_len, 2);
    memcpy(temptext + 2, plaintext, plaintext_len);

    /* Encrypt the  temptext buffer */
    cbuf.ciphertext = (char *)cbuf.hdr + sizeof(struct sslvpnhdr);
    EVP_EncryptInit(&ctxenc, EVP_aes_128_cbc(), sslparam->key, cbuf.hdr->cipheriv);
    if (!EVP_EncryptUpdate(&ctxenc, cbuf.ciphertext, &templen, temptext, 2 + plaintext_len)) {
        printf("Encryption failed\n");
    }
    ciphertext_len = templen;
    if (!EVP_EncryptFinal(&ctxenc, (cbuf.ciphertext + ciphertext_len), &templen)) {
        printf("Encryption failed\n");
    }
    ciphertext_len += templen;

    /*Calculate HMAC on encrypt text and copy to cipherbuf*/
    HMAC(EVP_sha256(), sslparam->key, KEYLEN, cbuf.ciphertext, ciphertext_len, hmac, &hmaclen);
    cbuf.hmac = cbuf.ciphertext + ciphertext_len;
    memcpy(cbuf.hmac, hmac, hmaclen);

    /* Assign the cipher text to output buffer */
    *outbuf = (char *)cbuf.hdr;
    *outlen = sizeof(struct sslvpnhdr) + ciphertext_len + hmaclen;

    free(temptext);
    return 1;
}
int decrypt(char *inbuf, unsigned short inlen, char **plaintext, unsigned short *plaintext_len,
            struct session_param *sslparam) {

    struct cipherbuf cbuf;
    char final[EVP_MAX_BLOCK_LENGTH];
    char *temptext, *actualtext;
    unsigned short ciphertext_len, temptext_len, actualtext_len;
    unsigned int cbuflen, templen;
    char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmaclen;
    EVP_CIPHER_CTX ctxdec;
    const EVP_MD *md;

    cbuf.hdr = (struct sslvpnhdr *)inbuf;
    cbuflen = inlen;

    /* Verify sequence number */
    //TODO

    /*Verify HMAC */
    cbuf.hmac = (char *)cbuf.hdr + cbuflen - EVP_MD_size((md = EVP_get_digestbyname("SHA256")));
    cbuf.ciphertext = (char *)cbuf.hdr + sizeof(struct sslvpnhdr);
    ciphertext_len = cbuf.hmac - cbuf.ciphertext;
    HMAC(md, sslparam->key, KEYLEN, cbuf.ciphertext, ciphertext_len, hmac, &hmaclen);
    if (memcmp(cbuf.hmac, hmac, hmaclen)) {
        printf("HMAC verification valied\n");
        log_debug_hex(hmac, hmaclen);
        print_hex(cbuf.hmac, hmaclen);
        print_hex(sslparam->key, KEYLEN);
        *plaintext = NULL;
        *plaintext_len = 0;
        return 1;
    }

    /* Decrypt ciphertext */
    temptext = malloc(ciphertext_len);
    EVP_DecryptInit(&ctxdec, EVP_aes_128_cbc(), sslparam->key, cbuf.hdr->cipheriv);
    if (!EVP_DecryptUpdate(&ctxdec, temptext, &templen, cbuf.ciphertext, ciphertext_len)) {
        printf("Decryption failed \n");
    }
    temptext_len = templen;
    if (EVP_DecryptFinal(&ctxdec, final, &templen) < 0) {
        printf("Decryption final failed\n");
    }
    memcpy(temptext + temptext_len, final, templen);
    temptext_len += templen;

    /* Extract the datalength the first 2 bytes and copy data */
    memcpy(&actualtext_len, temptext, 2);
    actualtext = malloc(actualtext_len);
    memcpy(actualtext, temptext + 2, actualtext_len);

    free(temptext);
    *plaintext = actualtext;
    *plaintext_len = actualtext_len;

    return 1;
}
