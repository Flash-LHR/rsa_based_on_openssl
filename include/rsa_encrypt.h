#ifndef _RSA_ENCRYPT_H__
#define _RSA_ENCRYPT_H__

#include "rsa_key.h"

void rsa_public_encrypt(const unsigned char *plain_text, 
		size_t plain_text_len, 
		unsigned char **cipher_text, 
		size_t *cipher_text_len, 
		const char *pub_key);

void rsa_private_decrypt(const unsigned char *ciper_text, 
		size_t cipher_text_len, 
		unsigned char **plain_text, 
		size_t *plain_text_len, 
		const char *pri_key);

#endif
