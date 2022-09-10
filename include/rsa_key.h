#ifndef _RSA_KEY_H__
#define _RSA_KEY_H__

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define KEY_LENGTH 1024
#define PRI_KEY_FILE "prikey.pem"
#define PUB_KEY_FILE "pubkey.pem"

void generate_rsa_key(char **out_pri_key, char **out_pub_key);

#endif

