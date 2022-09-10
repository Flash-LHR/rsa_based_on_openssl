#include "rsa_key.h"
#include "rsa_encrypt.h"
#include "rsa_sign.h"
#include <string.h>

void test_rsa_encrypt(const char *content, 
		size_t content_size, 
		const char *pri_key, 
		const char *pub_key) {
	printf("[test rsa encrypt]\n");
	printf("\n1. Encrypt\n");
	unsigned char *plain_text = (unsigned char*)malloc(content_size);
	memcpy(plain_text, content, content_size);
	size_t plain_text_len = content_size;
	printf("\nRSA plaintext length is %lu\n", plain_text_len);
	printf("The RSA plaintext is as follows:\n");
	BIO_dump_fp(stdout, plain_text, plain_text_len);
	unsigned char *cipher_text = NULL;
	size_t cipher_text_len = 0;
	rsa_public_encrypt(plain_text, 
			plain_text_len, 
			&cipher_text, 
			&cipher_text_len, 
			pub_key);
	printf("\nRSA ciphertext length is %lu\n", cipher_text_len);
	printf("The RSA ciphertext is as follows:\n");
	BIO_dump_fp(stdout, cipher_text, cipher_text_len);

	printf("\n2. Decrypt\n");
	unsigned char *r_plain_text = NULL;
	size_t r_plain_text_len = 0;
	rsa_private_decrypt(cipher_text, 
			cipher_text_len, 
			&r_plain_text, 
			&r_plain_text_len, 
			pri_key);
	printf("\nRSA plaintext length is %lu\n", r_plain_text_len);
	printf("The RSA plaintext is as follows:\n");
	BIO_dump_fp(stdout, r_plain_text, r_plain_text_len);

	free(plain_text);
	free(cipher_text);
	free(r_plain_text);
}

void test_rsa_sign(const char *content, 
		size_t content_size, 
		const char *pri_key, 
		const char *pub_key) {
	printf("[test rsa sign]\n");
	printf("\n1. Signature\n");
	unsigned char *plain_text = (unsigned char*)malloc(content_size);
	memcpy(plain_text, content, content_size);
	size_t plain_text_len = content_size;
	printf("\nRSA plaintext length is %lu\n", plain_text_len);
	printf("The RSA plaintext is as follows:\n");
	BIO_dump_fp(stdout, plain_text, plain_text_len);
	unsigned char *cipher_text = NULL;
	size_t cipher_text_len = 0;
	rsa_private_encrypt(plain_text, 
			plain_text_len, 
			&cipher_text, 
			&cipher_text_len, 
			pri_key);
	printf("\nRSA ciphertext length is %lu\n", cipher_text_len);
	printf("The RSA ciphertext is as follows:\n");
	BIO_dump_fp(stdout, cipher_text, cipher_text_len);

	printf("\n2. Signature verification\n");
	unsigned char *r_plain_text = NULL;
	size_t r_plain_text_len = 0;
	rsa_public_decrypt(cipher_text, 
			cipher_text_len, 
			&r_plain_text, 
			&r_plain_text_len, 
			pub_key);
	printf("\nRSA plaintext length is %lu\n", r_plain_text_len);
	printf("The RSA plaintext is as follows:\n");
	BIO_dump_fp(stdout, r_plain_text, r_plain_text_len);

	free(plain_text);
	free(cipher_text);
	free(r_plain_text);
}

int main() {
	char *pri_key = NULL, *pub_key = NULL;
	generate_rsa_key(&pri_key, &pub_key);
	printf("\nrsa private key:\n%s", pri_key);
	printf("\nrsa public key:\n%s\n", pub_key);
	char content[] = "RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem that is widely used for secure data transmission. It is also one of the oldest. The acronym \"RSA\" comes from the surnames of Ron Rivest, Adi Shamir and Leonard Adleman, who publicly described the algorithm in 1977. An equivalent system was developed secretly in 1973 at GCHQ (the British signals intelligence agency) by the English mathematician Clifford Cocks. That system was declassified in 1997.\n";
	//test_rsa_encrypt(content, strlen(content), pri_key, pub_key);
	test_rsa_sign(content, strlen(content), pri_key, pub_key);
	free(pri_key);
	free(pub_key);
	return 0;
}
