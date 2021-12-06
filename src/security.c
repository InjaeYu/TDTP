#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "security.h"
#include "common.h"

static void sha256_to_str(unsigned char *hash, char *output)
{
	int i = 0;
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
		sprintf(output + (i * 2), "%02x", hash[i]);
	output[64] = 0;
}

int calc_sha256_data(char *data, size_t length, char *output)
{
	SHA256_CTX c;
	unsigned char hash[SHA256_DIGEST_LENGTH];
	memset(hash, 0x00, sizeof(hash));

	SHA256_Init(&c);
	SHA256_Update(&c, data, length);
	SHA256_Final(hash, &c);
	sha256_to_str(hash, output);
	return 0;
}

int calc_sha256_file(char *path, char *output)
{
	FILE *fp = fopen(path, "rb");
	if(!fp) return -1;

	int len = 0;
	char buf[1024];
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX c;

	SHA256_Init(&c);
	memset(hash, 0x00, sizeof(hash));

	while(!feof(fp)) {
		memset(buf, 0x00, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		SHA256_Update(&c, buf, len);
	}
	fclose(fp);
	SHA256_Final(hash, &c);
	sha256_to_str(hash, output);
	return 0;
}

int EVP_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
		int aad_len, unsigned char *key, unsigned char *iv,
		unsigned char *ciphertext, unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, ciphertext_len = 0;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return -1;

	/* Set IV length if default 12 bytes (96 bits) is not appropriate */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		return -1;

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(aad && aad_len > 0)
	{
		if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
			return -1;
	}

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(plaintext)
	{
		if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
			return -1;

		ciphertext_len = len;
	}

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in GCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		return -1;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int EVP_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
		int aad_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
		unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0, plaintext_len = 0, ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		return -1;

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		return -1;

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

	/* Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if(aad && aad_len > 0)
	{
		if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
			return -1;
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(ciphertext)
	{
		if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
			return -1;

		plaintext_len = len;
	}

	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		return -1;

	/* Finalise the decryption. A positive return value indicates success,
	 * anything else is a failure - the plaintext is not trustworthy.
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		// BIO_dump_fp(stdout, ciphertext, ciphertext_len); /* Debuging source */
		/* Verify failed */
		return -1;
	}
}
