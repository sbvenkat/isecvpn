//
// Created by srbvsr on 4/20/16.
//
#include "sslutil.h"
#include "../include/util.h"
#include "msgproto.h"
#include "../include/data_chanl.h"
#include "../include/tun.h"
#include "../include/network.h"
#include <sys/wait.h>

int ipcfd[2];
static int datapid;

/*
 * INPUT FORMAT : username:password
 * */
int ssl_validate_user(char *userpasswd) {

    FILE *fp = NULL;
    char buf[256];
    char user[80];
    char passwd[80];
    char readuser[80];
    char calhmac[EVP_MAX_MD_SIZE];
    unsigned int calhamclen;
    const EVP_MD *m;
    int hmaclen;
    char c;
    int readuserlen;
    int success = 0, i;
    EVP_MD_CTX *mdctx;
    char saltpasswd[SSL_SALT_LENGTH + 80];

    m = EVP_get_digestbyname(SSL_HMAC_DIGEST_TYPE);
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, m, NULL);
    hmaclen = EVP_MD_size(m);

    /* Extract username and password */
    memset(user, 0, 80);
    memset(passwd, 0, 80);
    i = strcspn(userpasswd, ":");
    strncpy(user, userpasswd, i);
    strncpy(passwd, userpasswd + i + 1, strlen(userpasswd) - i - 1);
    log_debug("%s User verification request for %s\n", __FUNCTION__, user);

    if ((fp = fopen(PASSWORD_FILE, "r")) == NULL) {
        do_debug("Password file not found");
        return -1;
    }
    while((c = fgetc(fp)) != EOF) {

        memset(readuser, 0, 80);
        readuserlen = 0;
        readuser[readuserlen++] = c;
        while((c = fgetc(fp)) != ':')
            readuser[readuserlen++] = c;

        /* Read salt and hmac */
        memset(buf, 0, 256);
        fread(buf, 1, hmaclen + SSL_SALT_LENGTH, fp);

        if ((strlen(user) == readuserlen) && !memcmp(user, readuser, readuserlen)) {
            //User entry exist
            //Create SALT+Password anc calculate hash
            memset(saltpasswd, 0, SSL_SALT_LENGTH + 80);
            memcpy(saltpasswd, buf, SSL_SALT_LENGTH);
            memcpy(saltpasswd + SSL_SALT_LENGTH, passwd, strlen(passwd));
            EVP_DigestUpdate(mdctx, saltpasswd, SSL_SALT_LENGTH + strlen(passwd));
            EVP_DigestFinal_ex(mdctx, calhmac, &calhamclen);

            if(!memcmp(calhmac, buf + SSL_SALT_LENGTH, hmaclen)) {
                //User verify success
                success = 1;
                break;
            }

        }
        c = fgetc(fp);
    }
    EVP_MD_CTX_destroy(mdctx);
    fclose(fp);
    if (!success)
        log_debug("%s: User validation failed %s\n", __FUNCTION__, user);
    return success;
}

static int ssl_datapath_msg_send(char *buf, int len, unsigned int mtype) {

    int ret = 1;
    struct datatun_msg *dtunmsg;
    unsigned char *data;
    unsigned char *sendbuf = NULL;

    sendbuf = malloc(len + sizeof(struct datatun_msg));
    dtunmsg = (struct datatun_msg *)sendbuf;
    data = (sendbuf + sizeof(struct datatun_msg));
    dtunmsg->msgtype = mtype;
    if (buf) {
        memcpy(data, buf, len);
        dtunmsg->msglen = len;
    } else
        dtunmsg->msglen = 0;

    if ((ret = write(ipcfd[1], sendbuf, sizeof(struct datatun_msg) + len)) <= 0) {
        do_debug("Data Tun Message %d send failed\n", mtype);
        ret = -1;
    }

    if (!sendbuf)
        free(sendbuf);

    return ret;
}
void ssl_datapath_msg_exch(bool client) {

    struct tunintf tunparam;
    struct session_param sslparam;
    struct datatunnel datatunparam;

    memset(&sslparam, 0, sizeof(sslparam));
    get_sessionparam(&sslparam);
    ssl_datapath_msg_send((char *)&sslparam, sizeof(sslparam), DATATUN_KEYIV);

    memset(&tunparam, 0, sizeof(tunparam));
    get_tunparam(&tunparam);
    ssl_datapath_msg_send((char *)&tunparam, sizeof(tunparam), DATATUN_INIT);

    memset(&datatunparam, 0, sizeof(datatunparam));
    datatunparam.dataport = config.data_port;
    if (client) {
        sprintf(datatunparam.remoteip, "%s", config.gateway);
    }

    datatunparam.client = client;
    ssl_datapath_msg_send((char *)&datatunparam, sizeof(datatunparam), DATATUN_START);

    return;
}
int ssl_init_datapath(bool client) {

    int err;

    err = pipe(ipcfd);
    //CHK_ERR_EXIT(err, " build data channel pipe fail");
    if ((datapid = fork()) == 0) {
        /* Child process handling data encrypt/decrypt*/
        datapath_process();
    } else {
        /* Parent */
        ssl_datapath_msg_exch(client);
    }
}
int ssl_close_datapath(bool client) {

    int err = 1;
    int status;
    if ((err = ssl_datapath_msg_send(NULL, 0, DATATUN_END)) < 0) {
        do_debug("Datapath end msg failed\n");
    }
    close(ipcfd[0]);
    close(ipcfd[1]);

    waitpid(datapid, &status, 0);
    return err;
}
int gen_random_bytes(char *buf, int bytes) {

    int ret;
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    ret = fread(buf, 1, bytes, fp);
    if (ret != bytes)
        do_debug("Error getting random bytes\b");
    fclose(fp);

    return ret;
}
int ssl_client_init_vpn(char *user, char *passwd, struct session_param *sslparam) {

    unsigned char auth[256];
    int err;

    memset(auth, 0 , 256);
    sprintf(auth, "%s:%s", user, passwd);
    log_debug("%s: MSG AUTH REQ SENT %s\n", __FUNCTION__, user);
    err = form_msg_send(auth, strlen(auth), AUTH_REQ);
    CHK_ERR_RET(err, "MSG AUTH REQ RESP FAIL\n");
    memset(auth, 0, 256);

    gen_random_bytes(sslparam->key, KEYLEN);
    log_debug("%s: MSG KEY EXCH sent\n", __FUNCTION__);
    err = form_msg_send(sslparam->key, KEYLEN, KEY_EXCH);
    CHK_ERR_RET(err, "MSG KEY EXCH RESP FAIL\n");
    log_debug("%s: MSG KEY EXCH RESP ACK\n", __FUNCTION__);

    /*
    gen_random_bytes(sslparam->iv, IVLEN);
    do_debug("MSG IV EXCH SENT\n");
    err = form_msg_send(sslparam->iv, IVLEN, IV_EXCH);
    CHK_ERR_RET(err, "MSG IV EXCH RESP FAIL\n");
    do_debug("MSG IV EXCH RESP ACK\n");
    */

    log_debug("%s: MSG TUN UP SENT\n", __FUNCTION__);
    err = form_msg_send(NULL, 0, TUN_UP);
    CHK_ERR_RET(err, "Tunnel UP request failed\n");
    log_debug("%s: MSG TUN UP RESP ACK\n", __FUNCTION__);

    ssl_init_datapath(true);

    return 1;
}
int ssl_client_down_vpn(struct session_param *sslparam) {

    int err = 1;

    log_debug("%s MSG TUN DOWN SENT\n", __FUNCTION__);
    err = form_msg_send(NULL, 0, TUN_DOWN);
    CHK_ERR_RET(err, "Tunnel DOWN request failed\n");
    log_debug("%s MSG TUN DOWN RESP ACK\n", __FUNCTION__);

    return err;
}
int ssl_change_preshare_key(struct session_param *sslparam) {

    int err;

    memset(sslparam->key, 0, KEYLEN);
    gen_random_bytes(sslparam->key, KEYLEN);
    log_debug("MSG KEY EXCH sent\n");
    log_debug_hex(sslparam->key, KEYLEN);
    err = form_msg_send(sslparam->key, KEYLEN, KEY_CHANGE);
    CHK_ERR_RET(err, "MSG KEY CHNG RESP FAIL\n");
    log_debug("MSG KEY EXCH RESP ACK\n");

    ssl_keychg_datapath();
    return err;
}
void ssl_keychg_datapath() {

    struct session_param sslparam;

    memset(&sslparam, 0, sizeof(sslparam));
    get_sessionparam(&sslparam);
    ssl_datapath_msg_send((char *)&sslparam, sizeof(sslparam), DATATUN_KEYCHG);

    return;
}
