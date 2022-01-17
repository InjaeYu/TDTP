# TDTP(Trivial Data Transfer Protocol)

TCP 및 UDP를 이용하여 간단한 데이터 통신을 위한 서버/클라이언트

신뢰성이 중요한 데이터는 TCP를 사용\
신뢰성이 중요하지 않고 간단한 데이터는 UDP 사용

빌드 환경
 - Ubuntu 20.04.2 LTS
 - gcc version 9.3.0

빌드 의존성
 - apt-get install libssl-dev

빌드 방법
 - make htb_init : hash table header
 - make server : tdtpd (server daemon)
 - make client : tdtp_client (client program)
 - make all : htb_init + server + client
 - make clean : clean

기본 설정
 - Port : 52625
 - Directory : /tmp/tdtp (server daemon 동작시 자동 생성)

데이터 포맷
```c
typedef struct _tdtp_data {
	unsigned int id;            // 데이터 ID
	unsigned int cmd_type;      // 명령 타입
	unsigned int data_index;    // 데이터 index
	unsigned int len;           // 데이터 길이
	unsigned int hash_index[3]; // 공유키 index
	unsigned char tag[16];      // 암호문 및 ADD 변조 확인용
	char data_hash[65];         // 데이터 무결성 확인용 해쉬값
	char data[DATA_MAX_LEN];    // 암호화된 데이터
} tdtp_data_t;
```

데이터 암/복호화 방식
- OpenSSL library의 EVP 함수를 이용하여 data 부분을 AES256 암호화 알고리즘을 사용하여 암/복호화
- AES256 암/복호화시 사용하는 hash value는 [util/htb_creater.c](util/htb_creater.c)를 사용하여 생성되는 "hash_table.h" 헤더 파일에서 index로 값을 갖고와 사용
