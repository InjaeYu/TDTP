#ifndef _TDTP_COMMON_H_
#define _TDTP_COMMON_H_

#include <errno.h>
#include <netinet/in.h> // struct sockaddr_in
#include "version.h"
#include "security.h"
#include "htb_id.h"

#define TDTP_PORT 52625
#define TDTP_DIR "/tmp/tdtp"

#define PROTO_UDP 0
#define PROTO_TCP 1

#define DATA_MAX_LEN 1024

// TCP
#define SEND(S,D) send(S, &D, sizeof(D), 0)
#define RECV(S,D) recv(S, &D, sizeof(D), 0)
// UDP
#define SENDTO(S,D,C) sendto(S, &D, sizeof(D), 0, (struct sockaddr*)&C, sizeof(C))
#define RECVFROM(S,D,C,L) recvfrom(S, &D, sizeof(D), 0, (struct sockaddr*)&C, &L)

// Error
/*
#if 0
#define ERR_PRINT_F(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define ERR_PRINT_F(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#endif
#define ERR_PRINT(fmt, ...) ERR_PRINT_F("%% Error : "fmt, ##__VA_ARGS__)
*/
#if 0
#define ERR_PRINT_F(fmt, args...) printf(fmt, ##args)
#else
#define ERR_PRINT_F(fmt, args...) fprintf(stderr, fmt, ##args)
#endif
#define ERR_PRINT(fmt, args...) ERR_PRINT_F("%% Error(%d) : "fmt, errno, ##args)

// Data
#define DATA_SET(S, D, L) data_set(S, D, L)
#define DATA_SET_S(S, D)  DATA_SET(S, D, strlen(D))
#define DATA_SET_B(S, D)  DATA_SET(S, D, 0)
#define DATA_CLEAR(S)     DATA_SET(S, NULL, 0)

#define MAX_ID 10000 + 1

typedef struct _tdtp_data {
	unsigned int id;            // 데이터 ID
	unsigned int cmd_type;      // 명령 타입
	unsigned int data_index;    // 데이터 index
	unsigned int len;           // 데이터 길이
	unsigned int hash_index[3]; // 공유키 index
	unsigned char tag[16];      // 암호문 및 ADD 변조 확인용
	char data_hash[65];         // 데이터 무결성 확인용 해쉬값
	char data[DATA_MAX_LEN];            // 암호화된 데이터
} tdtp_data_t;

typedef enum _cmd_tpye {
	CMD_START,               //  0, start index, hello type
	CMD_CHECK_TDTP,          //  1
	CMD_FILE_TRANSFER,       //  2
	CMD_DISCONNECT,          //  3, command success, disconnection
	CMD_WAIT,                //  4, wait for a timeout, command is being processed

	CMD_ERR_START,           //  5, start error type
	CMD_ERR_COMMON,          //  6, common error
	CMD_ERR_UNKNOWN_CMD,     //  7, unknown command
	CMD_ERR_DECRYPT,         //  8, data decrypt error
	CMD_ERR_HASH,            //  9, diffrent hash
	CMD_ERR_UNKNOWN,         //  10, unknown error
	CMD_END                  //  11, last index
} cmd_type_t;

void print_data(tdtp_data_t *data, char *ip_addr);
int init_h_index(tdtp_data_t *data);
int init_data(tdtp_data_t *data, unsigned int cmd_type);
int data_set(tdtp_data_t *data, char *payload, int len);
int send_data(int sock, struct sockaddr_in *addr, tdtp_data_t *data, char *payload, int len);
int recv_data(int sock, struct sockaddr_in *addr, tdtp_data_t *data, int cmd_type, int d_id);
int send_error(int sock, struct sockaddr_in *addr, tdtp_data_t *data, int err, char *payload);
int disconnect(int sock, struct sockaddr_in *addr, tdtp_data_t *data);

#endif /* _TDTP_COMMON_H */
