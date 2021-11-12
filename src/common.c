#include <stdio.h>
#include <stdlib.h> // srand(), rand()
#include <string.h> // memset()
#include <time.h> // time()
#include <sys/type.h> // getpid()
#include <unistd.h> // getpid()
#include "common.h"

typedef struct _tdtp_list {
	cmd_type_t type;
	int debug;      // Debug command flag
	char proto[4];  // TCP, UDP
	char help[65]; // Help string
	char data[128];
} tdtp_list_t;

static tdtp_list_t cmd_list[CMD_DISCONNECT - 1] = {
	{CMD_GET_FILE, 0, "TCP", "Get file", "<File name> <Save path>"},
	{CMD_PUT_FILE, 0, "TCP", "Put file", "<File name> <Save path>"},
};

void print_cmd_help(int debug) {
	int i = 0;
	printf("%-3s  %-5s  %-64s  %s\n", "CMD", "Proto", "Description", "Data");
	printf("---  -----  ");
	for(i=0;i<64;i++) printf("-");
	printf("  ");
	for(i=0;i<32;i++) printf("-");
	printf("\n");
	for(i = 0; i < CMD_DISCONNECT; i++) {
		if(cmd_list[i].debug <= debug) {
			printf("%3d   %-4s  %-64s  %s\n", cmd_list[i].type, cmd_list[i].proto, cmd_list[i].help, cmd_list[i].data);
		}
	}
	printf("\n");
}

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
	sprintf(key->key, "%x%x%x", data->hash_index[0], data->hash_index[1], data->hash_index[2]);
	sprintf(key->iv, "%x%x", data->hash_index[2], data->hash_index[0]);
	sprintf(key->aad, "%x%s", data->hash_index[1], SEC_ADD);
	return 0;
}

int data_encrypt(tdtp_data_t *data, int len)
{
	unsigned char *plain_data = (unsigned char *)malloc(sizeof(data->data) * sizeof(char));
	if(plain_data == NULL) return -1;
	int enc_len = 0;

	return 0;
}

int init_data(tdtp_data_t *data, unsigned int cmd_type)
{
	memset(data, 0x00, sizeof(*data));
	srand(time(NULL) + getpid());

	data->id = (rand() + getpid()) % MAX_ID;
	data->cmd_tpye = cmd_type;
	return 0;
}

int data_set(tdtp_data_t *data, char *payload, int len)
{
	/*
		len == 0 : payload is bit data
		len != 0 : payload is string data
	*/

	data->len = 0;
	memset(data->hash_index, 0x00, sizeof(data->hash_index / data->hash_index[0]));
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
