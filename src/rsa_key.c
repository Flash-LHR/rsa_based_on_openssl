#include "rsa_key.h"

void generate_rsa_key(char **out_pri_key, char **out_pub_key)
{
	RSA *key_pair = RSA_generate_key(KEY_LENGTH, RSA_3, NULL, NULL);
	BIO *pri = BIO_new(BIO_s_mem()), *pub = BIO_new(BIO_s_mem());
	PEM_write_bio_RSAPrivateKey(pri, key_pair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSA_PUBKEY(pub, key_pair);
	size_t pri_len = BIO_pending(pri), pub_len = BIO_pending(pub);
	char *pri_key = (char*)malloc(pri_len + 1), 
		 *pub_key = (char*)malloc(pub_len + 1);
	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);
	pri_key[pri_len] = '\0', pub_key[pub_len] = '\0';
	*out_pri_key = pri_key, *out_pub_key = pub_key;

	FILE *pri_file = fopen(PRI_KEY_FILE, "w");
	fprintf(pri_file, "%s", pri_key);
	fclose(pri_file);
	FILE *pub_file = fopen(PUB_KEY_FILE, "w");
	fprintf(pub_file, "%s", pub_key);
	fclose(pub_file);

	printf("RSA parameters are as follows:\n");
	RSA_print_fp(stdout, key_pair, 0);

	RSA_free(key_pair);
	BIO_free_all(pri);
	BIO_free_all(pub);
}
