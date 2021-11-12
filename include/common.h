#ifndef _TDTP_COMMON_H_
#define _TDTP_COMMON_H_

#include "version.h"
#include "security.h"

#define TDTP_PORT 52625
#define TDTP_DIR "/tmp/tdtp"

#define PROTO_UDP 0
#define PROTO_TCP 1

#define MAX_ID 10000 + 1

typedef struct _tdtp_data {
	unsigned int id;            // 데이터 ID
	unsigned int cmd_type;      // 명령 타입
	unsigned int len;           // 데이터 길이
	unsigned int data_index;    // 데이터 index
	unsigned int hash_index[3]; // 공유키 index
	char tag[16];               // 암호문 및 ADD 변조 확인용
	char data_hash[65];         // 데이터 무결성 확인용 해쉬값
	char data[1024];            // 암호화된 데이터
} tdtp_data_t;

typedef enum _cmd_tpye {
	CMD_START,               //  0, start index, hello type
	CMD_GET_FILE,            //  1
	CMD_PUT_FILE,            //  2
	CMD_DISCONNECT,          //  3, command success, disconnection
	CMD_WAIT,                //  4, wait for a timeout, command is being processed

	CMD_ERR_START,           //  5, start error type
	CMD_ERR_UNKNOWN_CMD,     //  6, unknown command
	CMD_ERR_DECRYPT,         //  7, data decrypt error
	CMD_ERR_HASH,            //  8, diffrent hash
	CMD_ERR_UNKNOWN,         //  9, unknown error
	CMD_END                  // 10, last index
} cmd_type_t;


#endif /* _TDTP_COMMON_H */
