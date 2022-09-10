#include "rsa_encrypt.h"

void rsa_public_encrypt(const unsigned char *plain_text, 
		size_t plain_text_len, 
		unsigned char **cipher_text, 
		size_t *ciper_text_len, 
		const char *pub_key)
{
	BIO *key_bio = BIO_new_mem_buf((unsigned char*)pub_key, -1);
	RSA *rsa = RSA_new();
	rsa = PEM_read_bio_RSA_PUBKEY(key_bio, &rsa, NULL, NULL);
	size_t key_len = RSA_size(rsa);
	size_t block_len = key_len - RSA_PKCS1_PADDING_SIZE;
	*ciper_text_len = (plain_text_len + block_len - 1) / block_len * key_len;
	*cipher_text = (unsigned char*)malloc(*ciper_text_len);

	size_t plain_text_pos = 0, cipher_text_pos = 0, block_cnt = 0;
	while(plain_text_pos < plain_text_len) {
		size_t cur_plain_block_size = plain_text_len - plain_text_pos;
		if(cur_plain_block_size > block_len)
			cur_plain_block_size = block_len;
		RSA_public_encrypt(cur_plain_block_size, 
				plain_text + plain_text_pos, 
				*cipher_text + cipher_text_pos, 
				rsa, 
				RSA_PKCS1_PADDING);
		plain_text_pos += cur_plain_block_size;
		cipher_text_pos += key_len;

		++block_cnt;
		printf("[INFO] block #%lu: plaintext block size is %lu, ciphertext block size is %lu\n", 
				block_cnt, cur_plain_block_size, key_len);
	}

	BIO_free_all(key_bio);
	RSA_free(rsa);
}

void rsa_private_decrypt(const unsigned char *ciper_text, 
		size_t cipher_text_len, 
		unsigned char **plain_text, 
		size_t *plain_text_len, 
		const char *pri_key)
{
	BIO *key_bio = BIO_new_mem_buf((unsigned char*)pri_key, -1);
	RSA *rsa = RSA_new();
	rsa = PEM_read_bio_RSAPrivateKey(key_bio, &rsa, NULL, NULL);
	size_t key_len = RSA_size(rsa);
	*plain_text_len = 0;
	*plain_text = (unsigned char*)malloc(cipher_text_len);

	size_t plain_text_pos = 0, cipher_text_pos = 0, block_cnt = 0;
	while(cipher_text_pos < cipher_text_len) {
		size_t cur_plain_block_size = 
			RSA_private_decrypt(key_len, 
					ciper_text + cipher_text_pos, 
					*plain_text + plain_text_pos, 
					rsa, 
					RSA_PKCS1_PADDING);
		plain_text_pos += cur_plain_block_size;
		cipher_text_pos += key_len;

		++block_cnt;
		printf("[INFO] block #%lu: plaintext block size is %lu, ciphertext block size is %lu\n", 
				block_cnt, cur_plain_block_size, key_len);
	}
	*plain_text_len = plain_text_pos;

	BIO_free_all(key_bio);
	RSA_free(rsa);
}
