//
// Created by srbvsr on 4/27/16.
//

#include <string.h>
#include <stdio.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/err.h>


#define SALT_LEN 16

struct userentry {
    char *username;
    char *salt;
    char *hmac;
};

int gen_random_bytes(char *buf, int bytes) {

    int ret;
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    ret = fread(buf, 1, bytes, fp);
    fclose(fp);

    return ret;
}
int validate_user(char *user, char *passwd) {

    FILE *fp;
    char buf[256];
    char readuser[80];
    char calhmac[EVP_MAX_MD_SIZE];
    unsigned int calhamclen;
    const EVP_MD *m;
    int hmaclen;
    char c;
    int readuserlen;
    int success = 0;
    EVP_MD_CTX *mdctx;
    char saltpasswd[SALT_LEN + 80];

    m = EVP_get_digestbyname("SHA256");
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, m, NULL);
    hmaclen = EVP_MD_size(m);

    fp = fopen("shadow", "r");
    while((c = fgetc(fp)) != EOF) {
        memset(readuser, 0, 80);
        readuserlen = 0;
        readuser[readuserlen++] = c;
        while((c = fgetc(fp)) != ':')
            readuser[readuserlen++] = c;

        /* Read salt and hmac */
        memset(buf, 0, 256);
        fread(buf, 1, hmaclen + SALT_LEN, fp);

        if ((strlen(user) == readuserlen) && !memcmp(user, readuser, readuserlen)) {
            //User entry exist
            //Calculate hmac on sent password
            memset(saltpasswd, 0, SALT_LEN + 80);
            memcpy(saltpasswd, buf, SALT_LEN);
            memcpy(saltpasswd + SALT_LEN, passwd, strlen(passwd));

            EVP_DigestUpdate(mdctx, saltpasswd, SALT_LEN + strlen(passwd));
            EVP_DigestFinal_ex(mdctx, calhmac, &calhamclen);
            //HMAC(m, buf, SALT_LEN, passwd, strlen(passwd), calhmac, &calhamclen);
            if(!memcmp(calhmac, buf + SALT_LEN, hmaclen)) {
                //User verify success
                success = 1;
                break;
            }

        }
        c = fgetc(fp);
    }
    EVP_MD_CTX_destroy(mdctx);
    fclose(fp);
    return success;
}

int store_user(char *user, char *passwd) {

    FILE *fp;
    char salt[SALT_LEN];
    char buf[256];
    char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmaclen;
    struct userentry uentry;
    unsigned int totallen;
    const EVP_MD *m;
    EVP_MD_CTX *mdctx;
    char saltpasswd[SALT_LEN + 80];

    memset(buf, 0, 256);
    memset(salt, 0, SALT_LEN);
    memset(saltpasswd, 0, SALT_LEN + 80);

    //gen_random_bytes(salt, SALT_LEN);
    gen_random_bytes(saltpasswd, SALT_LEN);
    memcpy(saltpasswd + SALT_LEN, passwd, strlen(passwd));

    m = EVP_get_digestbyname("SHA256");
    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, m, NULL);
    EVP_DigestUpdate(mdctx, saltpasswd, SALT_LEN + strlen(passwd));
    EVP_DigestFinal_ex(mdctx, hmac, &hmaclen);
    EVP_MD_CTX_destroy(mdctx);

    //HMAC(EVP_sha256(), salt, SALT_LEN, passwd, strlen(passwd), hmac, &hmaclen);
    uentry.username = buf;
    uentry.salt = uentry.username + strlen(user) + 1;
    uentry.hmac = uentry.salt + SALT_LEN;

    memcpy(uentry.username, user, strlen(user));
    memcpy(uentry.salt - 1, ":", 1);
    memcpy(uentry.salt, saltpasswd, SALT_LEN);
    memcpy(uentry.hmac, hmac, hmaclen);

    totallen = strlen(user) + SALT_LEN + hmaclen + 1;
    buf[totallen++] = '\n';

    fp = fopen("shadow", "a");
    fwrite(buf, totallen, 1, fp);
    fclose(fp);
}

int main(int argc, char *argv[]) {

    char user[80];
    char passwd[80];

    OpenSSL_add_all_digests();
    /*
    memset(user, 0, 80);
    memset(passwd, 0, 80);
    sprintf(user, "%s", "alice");
    sprintf(passwd, "%s", "alice123");
    store_user(user, passwd);

    memset(user, 0, 80);
    memset(passwd, 0, 80);
    sprintf(user, "%s", "mike");
    sprintf(passwd, "%s", "mike123");
    store_user(user, passwd);

    memset(user, 0, 80);
    memset(passwd, 0, 80);
    sprintf(user, "%s", "shanoy");
    sprintf(passwd, "%s", "shanoy123");
    store_user(user, passwd);

    memset(user, 0, 80);
    memset(passwd, 0, 80);
    sprintf(user, "%s", "sbvenkat");
    sprintf(passwd, "%s", "sbvenkat123");
    store_user(user, passwd);
    */
    if(validate_user("ali", "alice123") )
        printf("User verify success for alice\n");
    else
        printf("User verify fail for alcie\n");
    if(validate_user("alice", "alice123") )
        printf("User verify success for alice\n");
    else
        printf("User verify fail for alcie\n");

    if (validate_user("shanoy", "shanoy123"))
        printf("user verify success for shanoy\n");
    else
        printf("user verify faile for shanoy\n");
    if (validate_user("kevindu", "alice123"))
        printf("user verify success for kevindu\n");
    else
        printf("user verify faile for kevindu\n");

    return 0;
}