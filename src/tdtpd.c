#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <libgen.h> // basename()
#include "common.h"

#define TDTPD_NAME "tdtpd"
#define TDTPD_PID  "/var/run/tdtpd.pid"

// Macro functions
#define PID_REGISTER(P)												\
	do {															\
		pid_t pid = getpid();										\
		FILE *fp_pid = fopen((P), "w");								\
		if (fp_pid != NULL) {										\
			chmod((P), (S_IROTH | S_IRGRP | S_IRUSR | S_IWUSR));	\
			fprintf(fp_pid, "%d\n", (int)pid);						\
			fclose(fp_pid);											\
		}															\
	} while(0)

// Structure
typedef struct _udp_proc_arg {
	struct sockaddr_in client_addr;
	tdtp_data_t recv_d;
} udp_proc_arg_t;

typedef struct _tcp_proc_arg {
	int client_sock;
	struct sockaddr_in client_addr;
} tcp_proc_arg_t;

// Server socket & pthread variable

int sock_udp, sock_tcp, port;
struct sockaddr_in server_addr_udp, server_addr_tcp;
pthread_mutex_t pthread_mutex;

static void help_msg()
{
	printf("\n");
	printf("TDTPD version  : %s\n", TDTP_VER);
	printf("Hash table id  : %s\n", HTB_ID);
	printf("\n");
	printf("Usage : %s [-h] [-f] [-p N]\n", TDTPD_NAME);
	printf("Options\n");
	printf("  -h        Help\n");
	printf("  -f        Foreground\n");
	printf("  -p N      Open N port(default : %d)\n", TDTP_PORT);
	printf("\n");
}

static int process_dupe_check()
{
	FILE *fp;
	char buf[128];
	int legacy_pid = 0;

	fp = fopen(TDTPD_PID, "r");
	if(fp) {
		if(fgets(buf, sizeof(buf), fp) == NULL) {
			ERR_PRINT("PID get error\n");
			fclose(fp);
			return -1;
		}
		legacy_pid = atoi(buf);
		fclose(fp);

		sprintf(buf, "/proc/%d", legacy_pid);
		if(!access(buf, 0)) return 1;
		unlink(TDTPD_PID);
	} else {
		int cnt = 0;
		sprintf(buf, "pidof %s | tr ' ' '\n' | wc -l", TDTPD_NAME);
		fp = popen(buf, "r");
		if(fp) {
			if(fgets(buf, sizeof(buf), fp) == NULL) {
				ERR_PRINT("PID get error\n");
				pclose(fp);
				return -1;
			}
			pclose(fp);
			if(cnt < 2) return 0;
			return 1;
		}
	}

	return 0;
}

int header_sync(tdtp_data_t *send, tdtp_data_t *recv)
{
	memset(send, 0x00, sizeof(*send));

	send->id = recv->id;
	send->cmd_type = recv->cmd_type;
	send->data_index = 1;
	init_h_index(send);

	return 0;
}

// Hash table id check function
int check_htb_id(int sock, tdtp_data_t *recv_d, struct sockaddr_in *addr)
{
	int ret = 0;
	tdtp_data_t send_d;
	header_sync(&send_d, recv_d);

	if(strcmp(recv_d->data, HTB_ID) != 0) {
		send_data(sock, addr, &send_d, "mismatch", strlen("mismatch"), 1);
		ret = -1;
	} else {
		send_data(sock, addr, &send_d, NULL, 0, 1);
	}

	return ret;
}

// Action function
int proc_check_tdtp(struct sockaddr_in client_addr, tdtp_data_t recv_d, int d_id)
{
	tdtp_data_t send_d;
	memset(&send_d, 0x00, sizeof(send_d));

	header_sync(&send_d, &recv_d);
	send_data(sock_udp, &client_addr, &send_d, TDTP_VER, strlen(TDTP_VER), 1);

	return 0;
}


int proc_file_transfer(int client_sock, tdtp_data_t recv_d, int d_id)
{
	tdtp_data_t send_d;
	int ret = 0;
	FILE *fp;
	size_t len = 0;
	char opt[4], f_hash_a[65], f_hash_b[65];
	char buf[2048], f_path[1500], s_path[1500];

	memset(&send_d, 0x00, sizeof(send_d));
	memset(opt, 0x00, sizeof(opt));
	memset(f_hash_a, 0x00, sizeof(f_hash_a));
	memset(f_hash_b, 0x00, sizeof(f_hash_b));
	memset(buf, 0x00, sizeof(buf));
	memset(f_path, 0x00, sizeof(f_path));
	memset(s_path, 0x00, sizeof(s_path));

	// Header sync & command data parsing
	header_sync(&send_d, &recv_d);
	sscanf(recv_d.data, "%s %s %s", opt, f_path, s_path);

	// Option check
	if((strcmp(opt, "get") != 0) && (strcmp(opt, "put") != 0)) {
		ERR_PRINT_F("%% Error : Invalid command option\n");
		send_error(client_sock, NULL, &send_d, CMD_ERR_UNKNOWN_CMD, "Invalid command option");
		return -1;
	}

	// Main proccess
	if(strcmp(opt, "get") == 0) {
		// Put file (Server -> Client)
		memset(buf, 0x00, sizeof(buf));
		sprintf(buf, "%s/%s", TDTP_DIR, f_path);
		memset(f_path, 0x00, sizeof(f_path));
		strcpy(f_path, buf);

		// Calc file hash
		memset(buf, 0x00, sizeof(buf));
		if(calc_sha256_file(f_path, buf) < 0) {
			ERR_PRINT_F("%% Error : File not found(%s)\n", f_path);
			send_error(client_sock, NULL, &send_d, CMD_ERR_COMMON, "File not found");
			return -1;
		}
		send_data(client_sock, NULL, &send_d, buf, 64, 1);

		// Send file
		fp = fopen(f_path, "rb");
		if(fp != NULL) {
			while(!feof(fp)) {
				memset(buf, 0x00, sizeof(buf));
				len = fread(buf, 1, sizeof(send_d.data), fp);
				send_data(client_sock, NULL, &send_d, buf, len, 1);
			}
			fclose(fp);
		} else {
			ERR_PRINT("File open error(%s)\n", f_path);
			send_error(client_sock, NULL, &send_d, CMD_ERR_COMMON, "File open error");
			return -1;
		}

		disconnect(client_sock, NULL, &send_d);
	} else {
		// Get file (Client -> Server)

		// Save path check
		if(s_path[0] == '/' || (s_path[0] == '.' && s_path[1] == '.')) {
			ERR_PRINT_F("%% Error : Cannot use \'/\' or \"..\" as the starting path\n");
			send_error(client_sock, NULL, &send_d, CMD_ERR_COMMON, "Cannot use \'/\' or \"..\" as the starting path");
			return -1;
		}

		// 저장경로가 '/'로 끝나는 경우, 기존 파일명을 사용
		if(s_path[strlen(s_path) - 1] == '/') {
			char *tmp_spath, *tmp_fpath;
			tmp_spath = (char *)malloc(strlen(s_path) * sizeof(char));
			tmp_fpath = (char *)malloc(strlen(f_path) * sizeof(char));
			if(tmp_spath == NULL) {
				ERR_PRINT("Memory allocation error\n");
				send_error(client_sock, NULL, &send_d, CMD_ERR_UNKNOWN, "Memory allocation error");
				return -1;
			}
			if(tmp_fpath == NULL) {
				ERR_PRINT("Memory allocation error\n");
				send_error(client_sock, NULL, &send_d, CMD_ERR_UNKNOWN, "Memory allocation error");
				free(tmp_spath);
				return -1;
			}
			strcpy(tmp_spath, s_path);
			strcpy(tmp_fpath, f_path);
			sprintf(s_path, "%s%s", tmp_spath, basename(tmp_fpath));
			free(tmp_spath);
			free(tmp_fpath);
		}

		memset(buf, 0x00, sizeof(buf));
		sprintf(buf, "%s/%s", TDTP_DIR, s_path);
		memset(s_path, 0x00, sizeof(s_path));
		strcpy(s_path, buf);

		// Get file hash value
		if(recv_data(client_sock, NULL, &recv_d, CMD_FILE_TRANSFER, d_id, 0) < 0)
			return -1;
		sscanf(recv_d.data, "%s", f_hash_a);

		// Receive file
		fp = fopen(s_path, "wb");
		if(fp != NULL) {
			while((ret = recv_data(client_sock, NULL, &recv_d, CMD_FILE_TRANSFER, d_id, 0)) > 0)
				fwrite(recv_d.data, 1, recv_d.len, fp);
			fclose(fp);
			if(ret < 0) {
				printf("ret : %d\n", ret);
				unlink(s_path);
				return -1;
			}
		} else {
			ERR_PRINT("File open error(%s)\n", s_path);
			return -1;
		}

		// Calc file hash
		if(calc_sha256_file(s_path, f_hash_b) < 0) {
			ERR_PRINT_F("%% Error : File not found\n");
			unlink(s_path);
			return -1;
		}

		// Compare file hashes
		if(strncmp(f_hash_a, f_hash_b, 64) != 0) {
			printf("Receive file hash   : %s\n", f_hash_a);
			printf("Calculate file hash : %s\n", f_hash_b);
			ERR_PRINT_F("%% Error : Different file hash\n");
			unlink(s_path);
			return -1;
		}

		printf("Done\n");
	}

	return 0;
}

// Action thread
void* udp_action_thread(void *arg)
{
	int d_id = 0;
	udp_proc_arg_t t_arg;
	struct sockaddr_in client_addr;
	tdtp_data_t recv_d, send_d;

	memcpy(&t_arg, arg, sizeof(t_arg));
	memcpy(&client_addr, &t_arg.client_addr, sizeof(client_addr));
	memcpy(&recv_d, &t_arg.recv_d, sizeof(recv_d));
	memset(&send_d, 0x00, sizeof(send_d));

#if 0 /* 데이터가 평문이 아닌이상 hash table이 다른 경우, 복호화가 불가능하기에 의미 없음 */
	// Check hash table id 
	if(check_htb_id(sock_udp, &recv_d, &client_addr) < 0) {
		printf("Hash table id mismatch\n");
		return 0;
	}

	if(recv_data(sock_udp, &client_addr, &recv_d, 0, 0, 0) < 0)
		return -1;
#endif

	d_id = recv_d.id;

	switch(recv_d.cmd_type) {
		case CMD_START:
		case CMD_END:
		case CMD_DISCONNECT:
			break;
		case CMD_CHECK_TDTP:
			proc_check_tdtp(client_addr, recv_d, d_id);
			break;
		default:
			header_sync(&send_d, &recv_d);
			send_error(sock_udp, NULL, &send_d, CMD_ERR_UNKNOWN_CMD, "Invalid command type");
			break;
	}
	return 0;
}

void* tcp_action_thread(void *arg)
{
	int client_sock = 0, d_id = 0;
	tcp_proc_arg_t t_arg;
	struct sockaddr_in client_addr;
	tdtp_data_t recv_d, send_d;

	memcpy(&t_arg, arg, sizeof(t_arg));
	client_sock = t_arg.client_sock;
	memcpy(&client_addr, &t_arg.client_addr, sizeof(client_addr));
	memset(&recv_d, 0x00, sizeof(recv_d));
	memset(&send_d, 0x00, sizeof(send_d));

	if(recv_data(client_sock, NULL, &recv_d, 0, 0, 0) < 0)
		return (void *)-1;
	printf("Receive ");
	print_data(&recv_d, inet_ntoa(client_addr.sin_addr));
	d_id = recv_d.id;

#if 0 /* 데이터가 평문이 아닌이상 hash table이 다른 경우, 복호화가 불가능하기에 의미 없음 */
	// Check hash table id 
	if(check_htb_id(client_sock, &recv_d, &client_addr) < 0) {
		printf("Hash table id mismatch\n");
		return 0;
	}

	if(recv_data(client_sock, NULL, &recv_d, 0, 0, 0) < 0)
		return -1;
#endif

	switch(recv_d.cmd_type) {
		case CMD_START:
		case CMD_END:
		case CMD_DISCONNECT:
			break;
		case CMD_FILE_TRANSFER:
			proc_file_transfer(client_sock, recv_d, d_id);
			break;
		default:
			header_sync(&send_d, &recv_d);
			send_error(client_sock, NULL, &send_d, CMD_ERR_UNKNOWN_CMD, "Invalid command type");
			break;
	}
	return 0;
}

// Server thread
void* udp_server_thread(void *arg)
{
	// Pthread init
	pthread_t thread;
	pthread_attr_t attr;
	udp_proc_arg_t t_arg;
	if(pthread_attr_init(&attr) != 0) {
		ERR_PRINT("UDP pthread attribute init error\n");
		return (void *)-1;
	}
	if(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
		ERR_PRINT("UDP pthread attribute set error\n");
		return (void *)-1;
	}

	// Client variable
	struct sockaddr_in client_addr;

	// Server socket varialbe
	int on = 1;
	tdtp_data_t recv_d, last_d;

	// Create server socket
	if((sock_udp = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		ERR_PRINT("UDP socket create error");
		return (void *)-1;
	}

	// Enable reuse address option
	if(setsockopt(sock_udp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		close(sock_udp);
		ERR_PRINT("UDP socket option(1) set error");
		return (void *)-1;
	}
	if(setsockopt(sock_udp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		close(sock_udp);
		ERR_PRINT("UDP socket option(2) set error");
		return (void *)-1;
	}

	server_addr_udp.sin_family = AF_INET;
	server_addr_udp.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr_udp.sin_port = htons(port);

	// Bind
	if(bind(sock_udp, (struct sockaddr *)&server_addr_udp, sizeof(server_addr_udp)) < 0) {
		close(sock_udp);
		ERR_PRINT("UDP socket bind error");
		return (void *)-1;
	}

	memset(&last_d, 0x00, sizeof(last_d));
	while(1) {
		memset(&recv_d, 0x00, sizeof(recv_d));

		// Wait request
		if(recv_data(sock_udp, &client_addr, &recv_d, 0, 0, 0) < 0)
			continue;

		/* Duplicate data check
		   - UDP 통신은 흐름제어가 없기에 목적지까지 도달 가능한 모든 경로에 데이터 전송
		   - 위 특징으로 인하여 경로가 여러개인 경우 중복된 데이터를 받는 경우 발생
		   - 따라서 최근 받은 데이터와 중복되는 데이터를 받는 경우 드랍
		*/
		if(last_d.id == 0) {
			memcpy(&last_d, &recv_d, sizeof(last_d));
		} else {
			if(memcmp(&last_d, &recv_d, sizeof(last_d)) == 0) {
				printf("Duplicate packet detected, dropped\n");
				continue;
			} else {
				memcpy(&last_d, &recv_d, sizeof(last_d));
			}
		}
		printf("Receive ");
		print_data(&recv_d, inet_ntoa(client_addr.sin_addr));

		// Action thread
		memcpy(&t_arg.client_addr, &client_addr, sizeof(t_arg.client_addr));
		memcpy(&t_arg.recv_d, &recv_d, sizeof(recv_d));

		if(pthread_create(&thread, &attr, udp_action_thread, &t_arg) != 0) {
			//close(sock_udp);
			ERR_PRINT("UDP action thread create error\n");
			continue;
			//return (void *)-1;
		}
	}

	close(sock_udp);
	if(pthread_attr_destroy(&attr) != 0) {
		ERR_PRINT("UDP pthread attribute destroy error");
		return (void *)-1;
	}

	return 0;
}

// TCP thread
void* tcp_server_thread(void *arg)
{
	// Pthread init
	pthread_t thread;
	pthread_attr_t attr;
	tcp_proc_arg_t t_arg;
	if(pthread_attr_init(&attr) != 0) {
		ERR_PRINT("TCP pthread attribute init error\n");
		return (void *)-1;
	}
	if(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
		ERR_PRINT("TCP pthread attribute set error\n");
		return (void *)-1;
	}

	// Client variable
	int client_sock;
	struct sockaddr_in client_addr;
	socklen_t client_addr_size = sizeof(client_addr);

	// Server socket variable
	int on = 1;

	// Create server socket
	if((sock_tcp = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		ERR_PRINT("TCP socket create error\n");
		return (void *)-1;
	}

	// Enable reuse address option
	if(setsockopt(sock_tcp, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) <0) {
		close(sock_tcp);
		ERR_PRINT("TCP socket option(1) set error\n");
		return (void *)-1;
	}

	server_addr_tcp.sin_family = AF_INET;
	server_addr_tcp.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr_tcp.sin_port = htons(port);

	// Bind
	if(bind(sock_tcp, (struct sockaddr *)&server_addr_tcp, sizeof(server_addr_tcp)) < 0) {
		close(sock_tcp);
		ERR_PRINT("TCP socket bind error\n");
		return (void *)-1;
	}

	// Listen
	if(listen(sock_tcp, 10) < 0) {
		close(sock_tcp);
		ERR_PRINT("TCP socket listen error\n");
		return (void *)-1;
	}

	while(1) {
		// Wait request
		client_sock = accept(sock_tcp, (struct sockaddr *)&client_addr, &client_addr_size);
		if(client_sock == -1) {
			ERR_PRINT("TCP accept error\n");
			continue;
		}

		// Action thread
		t_arg.client_sock = client_sock;
		memcpy(&t_arg.client_addr, &client_addr, sizeof(struct sockaddr_in));

		if(pthread_create(&thread, &attr, tcp_action_thread, &t_arg) != 0) {
			//close(sock_tcp);
			close(client_sock);
			ERR_PRINT("TCP action pthread create error");
			continue;
			//return (void *)-1;
		}
	}

	close(sock_tcp);
	close(client_sock);
	pthread_mutex_destroy(&pthread_mutex);
	if(pthread_attr_destroy(&attr) != 0) {
		ERR_PRINT("TCP pthread attribute destroy error");
		return (void *)-1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	// Option check
	int opt, foreground = 0;
	port = 0;

	while((opt = getopt(argc, argv, "fhp:")) != -1) {
		switch(opt) {
			case 'f':
				foreground = 1;
				break;
			case 'p':
				port = atoi(optarg);
				if(port < 1 || port > 65535) {
					ERR_PRINT("Port range : 1 ~ 65535\n");
					return -1;
				}
				break;
			case 'h':
			default:
				help_msg();
				return 0;
				break;
		}
	}
	if(!port) port = TDTP_PORT;

	// Directory check
	if(access(TDTP_DIR, 0) != 0) {
		if(mkdir(TDTP_DIR, 0777) != 0) {
			ERR_PRINT("fail create tdtp dir : %s\n", TDTP_DIR);
			return -1;
		}
	}

	// Duplicate check
	int ret = 0;
	ret = process_dupe_check();
	if(ret == 1) {
		printf("Already %s started\n", TDTPD_NAME);
		return 0;
	} else if (ret == -1) {
		return 0;
	}

	if(!foreground) {
		if(daemon(0,0) < 0) {
			ERR_PRINT("Daemonized error\n");
			return -1;
		}
	}
	PID_REGISTER(TDTPD_PID);

	// Pthread init
	pthread_t tcp_thread, udp_thread;
	pthread_mutex_init(&pthread_mutex, NULL);

	// Pthread create
	if(pthread_create(&udp_thread, NULL, udp_server_thread, NULL) != 0) {
		ERR_PRINT("UDP pthread create error\n");
		return -1;
	}

	if(pthread_create(&tcp_thread, NULL, tcp_server_thread, NULL) != 0) {
		ERR_PRINT("TCP pthread create error\n");
		return -1;
	}

	// Pthread join
	pthread_join(udp_thread, NULL);
	pthread_join(tcp_thread, NULL);

	return 0;
}
