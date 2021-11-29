#include <stdio.h>
#include <stdlib.h> // srand(), rand()
#include <string.h> // memset()
#include <time.h> // time()
#include <sys/types.h> // getpid()
#include <unistd.h> // getpid()
#include "common.h"
#include "hash_table.h"

void print_data(tdtp_data_t *data, char *ip_addr)
{
	int i = 0;
	printf("Data ");
	for(i=0;i<39;i++) printf("-");
	printf("\n");
	if(ip_addr != NULL) printf("source ip  : %s\n", ip_addr);
	printf("id         : %d\n", data->id);
	printf("cmd_type   : %d\n", data->cmd_type);
	printf("data_index : %d\n", data->data_index);
	printf("data_len   : %d\n", data->len);
	printf("hash_index : %d %d %d\n", data->hash_index[0], data->hash_index[1], data->hash_index[2]);
	printf("data_hash  : %s\n", data->data_hash);
	for(i=0;i<44;i++) printf("-");
	printf("\n\n");
}

int calc_key(tdtp_data_t *data, sec_key_t *key)
{
	memset(key, 0x00, sizeof(sec_key_t));
	sprintf((char *)key->key, "%x%x%x", H_TABLE[data->hash_index[0]], H_TABLE[data->hash_index[1]], H_TABLE[data->hash_index[2]]);
	sprintf((char *)key->iv, "%x%x", H_TABLE[data->hash_index[2]], H_TABLE[data->hash_index[0]]);
	sprintf((char *)key->aad, "%x%s", H_TABLE[data->hash_index[1]], SEC_ADD);
	return 0;
}

int data_encrypt(tdtp_data_t *data, int data_len)
{
	unsigned char *plain_data = (unsigned char *)malloc(sizeof(data->data));
	if(plain_data == NULL) return -1;
	int len = 0, enc_len = 0;
	sec_key_t key;
	memset(plain_data, 0x00, sizeof(data->data));

	calc_key(data, &key);

	if(data_len == 0) len = sizeof(data->data);

	memcpy(plain_data, data->data, len);
	enc_len = EVP_encrypt(plain_data, len, key.aad, strlen((char *)key.aad), key.key, key.iv, (unsigned char *)data->data, data->tag);

	if(enc_len < 0) {
		data->len = 0;
		free(plain_data);
		return -1;
	}

	data->len = enc_len;
	free(plain_data);
	return 0;
}

int data_decrypt(tdtp_data_t *data)
{
	if(data->len == 0) return 0;
	unsigned char *cipher_data = (unsigned char*)malloc(sizeof(data->data));
	if(cipher_data == NULL) return -1;
	int len = 0;
	sec_key_t key;
	memset(cipher_data, 0x00, sizeof(data->data));

	calc_key(data, &key);

	memcpy(cipher_data, data->data, data->len);
	memset(data->data, 0x00, sizeof(data->data));
	len = EVP_decrypt(cipher_data, data->len, key.aad, strlen((char *)key.aad), data->tag, key.key, key.iv, (unsigned char *)data->data);

	if(len < 0) {
		free(cipher_data);
		return -1;
	}

	data->len = len;
	free(cipher_data);
	return 0;
}

int init_h_index(tdtp_data_t *data) {
	int i = 0;
	srand(time(NULL) + getpid());
	for(i=0; i<(sizeof(data->hash_index) / sizeof(data->hash_index[0])); i++)
		data->hash_index[i] = ((rand() / (i + 1)) + getpid()) % HTB_SIZE;
	return 0;
}

int init_data(tdtp_data_t *data, unsigned int cmd_type)
{
	memset(data, 0x00, sizeof(*data));
	srand(time(NULL) + getpid());

	data->id = (rand() + getpid()) % MAX_ID;
	data->cmd_type = cmd_type;
	data->data_index = 0;
	data->len = 0;
	init_h_index(data);
	return 0;
}

int data_set(tdtp_data_t *data, char *payload, int len)
{
	/*
		len == 0 : payload is bit data
		len != 0 : payload is string data
	*/

	data->len = 0;
	memset(data->hash_index, 0x00, sizeof(data->hash_index));
	init_h_index(data);
	memset(data->data_hash, 0x00, sizeof(data->data_hash));
	memset(data->data, 0x00, sizeof(data->data));
	if(payload == NULL) return 0;

	char hash[65];
	memset(hash, 0x00, sizeof(hash));

	if(len != 0)
		memcpy(data->data, payload, len);
	else
		memcpy(data->data, payload, sizeof(data->data));

	if(data_encrypt(data, len) , 0) return -1;
	calc_sha256_data(data->data, sizeof(data), hash);
	memcpy(data->data_hash, hash, sizeof(data->data_hash));
	return 0;
}

int data_hash_check(tdtp_data_t *data)
{
	if(strlen(data->data) == 0) return 0;
	char hash[65];
	memset(hash, 0x00, sizeof(hash));
	calc_sha256_data(data->data, sizeof(data->data), hash);
	if(strcmp(data->data_hash, hash) == 0)
		return 0;
	else
		return -1;
}

int send_data(int sock, struct sockaddr_in *addr, tdtp_data_t *data, char *payload, int len)
{
	if(sock <= 0 || data == NULL) return -1;

	int ret = 0, d_size = sizeof(data->data);
	while(len > 0 || payload == NULL) {
		if(len > d_size) {
			data_set(data, payload, d_size);
		} else {
			data_set(data, payload, len);
		}

		if(addr != NULL) { // UDP
			ret += SENDTO(sock, *data, *addr);
		} else { // TCP
			ret += SEND(sock, *data);
		}

		if(payload == NULL)
			break;
		data->data_index += 1;
		len -= d_size;
	}

	return ret;
}

int recv_data(int sock, struct sockaddr_in *addr, tdtp_data_t *data, int cmd_type, int d_id)
{
	if(sock <= 0 || data == NULL) return -1;

	int ret = 0;

	memset(data, 0x00, sizeof(*data));

	if(addr != NULL) { // UDP
		socklen_t addr_size = sizeof(*addr);
		ret += RECVFROM(sock, *data, addr, addr_size);
	} else { // TCP
		ret += RECV(sock, *data);
	}

	if(ret >= 0) {
		if(d_id != 0) {
			if(data->id != d_id) {
				ERR_PRINT_F("%% Error : Data id mismatch\n");
				return -2;
			}
		}

		if(data->cmd_type == CMD_DISCONNECT) {
			printf("Recevie disconnect flag\n");
			return -2;
		}

		if(cmd_type != 0) {
			if(data->cmd_type != cmd_type)
				return -2;
		}

		if(data_hash_check(data) < 0) {
			ERR_PRINT("Receive data hash error\n");
			return -1;
		}

		if(data_decrypt(data) < 0) {
			ERR_PRINT("Receive data decryt error\n");
			return -1;
		}

		if(data->cmd_type >= CMD_ERR_START) {
			if(strlen(data->data) > 0)
				printf("%s\n", data->data);
			return -3;
		}

	}

	return ret;
}

int send_error(int sock, struct sockaddr_in *addr, tdtp_data_t *data, int err, char *payload)
{
	if(sock <= 0 || data == NULL) return -1;

	int i = 0, len = 0;

	if(payload != NULL)
		len = strlen(payload);

	for(i = CMD_ERR_START; i < CMD_END; i++)
		if(i == err)
			break;

	if(i == err)
		data->cmd_type = err;
	else
		data->cmd_type = CMD_ERR_UNKNOWN;

	return send_data(sock, addr, data, payload, len);
}

int disconnect(int sock, struct sockaddr_in *addr, tdtp_data_t *data)
{
	if(sock <= 0 || data == NULL) return -1;

	data->cmd_type = CMD_DISCONNECT;
	return send_data(sock, addr, data, NULL, 0);
}
