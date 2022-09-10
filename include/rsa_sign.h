#ifndef _RSA_SIGN_H__
#define _RSA_SIGN_H__

#include "rsa_key.h"

void rsa_private_encrypt(const unsigned char *plain_text, 
		size_t plain_text_len, 
		unsigned char **cipher_text, 
		size_t *ciper_text_len, 
		const char *pri_key);

void rsa_public_decrypt(const unsigned char *ciper_text, 
		size_t cipher_text_len, 
		unsigned char **plain_text, 
		size_t *plain_text_len, 
		const char *pub_key);

#endif
