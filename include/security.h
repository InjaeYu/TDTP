#ifndef _TDTP_SECURITY_H_
#define _TDTP_SECURITY_H_

#define SEC_ADD "tdtps"

typedef struct _sec_key {
	unsigned char key[25];
	unsigned char iv[17];
	unsigned char aad[14];
} sec_key_t;

int calc_sha256_data(char *data, size_t len, char *out);
int calc_sha256_file(char *path, char *out);
int EVP_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
		int aad_len, unsigned char *key, unsigned char *iv, unsigned ciphertext, unsigned char *tag);
int EVP_decrypt(unsigned char *ciphertext, int plaintext_len, unsigned char *aad,
		int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,	unsigned char *plaintext);

#endif /* _TDTP_SECURITY_H_ */
