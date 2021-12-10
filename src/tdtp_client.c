#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include "common.h"
#include "security.h"

#define TDTPC_NAME "tdtp_client"

#define RECV_TIMEOUT 1 // sec
#define RECV_MAX_CNT 1 // retry count N

typedef struct _tdtp_list {
	cmd_type_t type;
	int debug;      // Debug command flag
	int proto;      // TCP, UDP
	char help[65];  // Help string
	char data[128];
} tdtp_list_t;

static tdtp_list_t cmd_list[CMD_DISCONNECT - 1] = {
	{CMD_CHECK_TDTP,    0, PROTO_UDP, "Check TDTP server", ""},
	{CMD_FILE_TRANSFER, 0, PROTO_TCP, "File transfer",     "<get | put> <File path> <Save path>"},
};

// Client socket variable
int sock;
struct sockaddr_in server_addr;
socklen_t server_addr_size = sizeof(server_addr);
int verbose_f = 0, d_id = 0;

void help_msg()
{
	printf("\n");
	printf("TDTP client version : %s\n", TDTP_VER);
	printf("Hash table id       : %s\n", HTB_ID);
	printf("\n");
	printf("Usage : %s [-h] [-v] -c N -i IP[:port] DATA\n", TDTPC_NAME);
	printf("Options\n");
	printf("  -h           Help\n");
	printf("  -v           Verbose\n");
	printf("  -c N         Command number\n");
	printf("  -i IP[:port] Server ip address & port(option)\n");
	printf("  DATA         Command data\n");
	printf("\n");
}

void print_cmd_help(int debug) {
	int i = 0;
	printf("%-3s  %-5s  %-32s  %s\n", "CMD", "Proto", "Description", "Data");
	printf("---  -----  ");
	for(i=0;i<32;i++) printf("-");
	printf("  ");
	for(i=0;i<32;i++) printf("-");
	printf("\n");
	for(i = 0; i < CMD_DISCONNECT - 1; i++) {
		if(cmd_list[i].debug <= debug) {
			printf("%3d   %-4s  %-32s  %s\n", cmd_list[i].type, cmd_list[i].proto == PROTO_UDP ? "UDP" : cmd_list[i].proto == PROTO_TCP ? "TCP" : "Unk", cmd_list[i].help, cmd_list[i].data);
		}
	}
	printf("\n");
}


int check_ip_form(char *ip_ori)
{
	if(strlen(ip_ori) > 15) return -1;
	int i = 0, cnt = 0;
	for(i=0; i<strlen(ip_ori); i++)
		if(ip_ori[i] == '.') cnt += 1;
	if(cnt != 3) return -1;

	char ip_tmp[16], *chr_ptr;
	memset(ip_tmp, 0x00, sizeof(ip_tmp));
	strcpy(ip_tmp, ip_ori);

	i = 0;
	chr_ptr = strtok(ip_tmp, ".");
	while(chr_ptr != NULL) {
		if((i == 0 || i == 3) && (atoi(chr_ptr) < 1 || atoi(chr_ptr) > 255)) return -1;
		else if(atoi(chr_ptr) < 0 || atoi(chr_ptr) > 255) return -1;
		chr_ptr = strtok(NULL, ".");
		i++;
	}
	return 0;
}

int check_protocol(int cmd)
{
	int i = 0;
	for(i = CMD_START; i < CMD_DISCONNECT - 1; i++)
		if(cmd_list[i].type == cmd) return cmd_list[i].proto;
	return -1;
}

int check_need_data(int cmd)
{
	int i = 0;
	for(i = CMD_START; i < CMD_DISCONNECT - 1; i++)
		if(cmd_list[i].type == cmd) return strlen(cmd_list[i].data);
	return -1;
}

int print_recv_data_by_type(tdtp_data_t *recv_d, int cmd_type)
{
	int re_cnt = 0, proto = check_protocol(cmd_type);
	struct sockaddr_in *addr_p;

	if(proto < 0)
		return -1;

	if(proto == PROTO_UDP)
		addr_p = &server_addr;
	else
		addr_p = NULL;

	while(1) {
		re_cnt = 0;
		memset(recv_d, 0x00, sizeof(*recv_d));
		while(recv_data(sock, addr_p, recv_d, cmd_type, d_id, verbose_f) == -1 && re_cnt <= RECV_MAX_CNT) {
			re_cnt += 1;
			if(re_cnt <= RECV_MAX_CNT)
				printf("Retry... (%d/%d)\n", re_cnt, RECV_MAX_CNT);
			if(re_cnt > RECV_MAX_CNT)
				break;
		}

		if(re_cnt > RECV_MAX_CNT || recv_d->cmd_type != cmd_type)
			break;

		printf("%s", recv_d->data);
	}

	return 0;
}

// Hash table id check function
int check_htb_id(int protocol)
{
	int ret = 0;
	struct sockaddr_in *addr_p;
	tdtp_data_t send_d, recv_d;

	memset(&send_d, 0x00, sizeof(send_d));
	memset(&recv_d, 0x00, sizeof(recv_d));

	if(protocol == PROTO_UDP)
		addr_p = &server_addr;
	else
		addr_p = NULL;

	// Init data
	if(init_data(&send_d, CMD_START) < 0) {
		ERR_PRINT_F("%% Error : Data init error\n");
		return -1;
	}
	d_id = send_d.id;

	// Send data
	if(send_data(sock, addr_p, &send_d, HTB_ID, strlen(HTB_ID), verbose_f) < 0) {
		ERR_PRINT("Send error\n");
		return -1;
	}

	// Receive data
	if((ret = recv_data(sock, addr_p, &recv_d, 0, d_id, verbose_f)) < 0) {
		if(ret == -1)
			ERR_PRINT("Receive error\n");
		else if(ret == -2) {
			if(verbose_f) {
				printf("Send ID : %d\n", send_d.id);
				printf("Recv ID : %d\n", recv_d.id);
			}
		}
		return -1;
	}

	// Check result
	if(strcmp(recv_d.data, "mismatch") == 0) {
		ERR_PRINT_F("%% Error : Hash table ID mismatch\n");
		return -1;
	}

	return 0;
}

// Action functions
int proc_check_tdtp(char *data)
{
	int ret = 0, count = 0, re_cnt = 0;
	tdtp_data_t send_d, recv_d;

	// Init data
	if(init_data(&send_d, CMD_CHECK_TDTP) < 0) {
		ERR_PRINT_F("%% Error : Data init error\n");
		send_error(sock, &server_addr, &send_d, CMD_ERR_COMMON, "Data init error");
		return -1;
	}
	d_id = send_d.id;

	send_data(sock, &server_addr, &send_d, NULL, 0, verbose_f);

	do {
		if((ret = recv_data(sock, &server_addr, &recv_d, CMD_CHECK_TDTP, d_id, verbose_f)) >= 0) {
			re_cnt = 0;
			count += 1;
			printf("%d : %s (ver : %s)\n", count, inet_ntoa(server_addr.sin_addr), strlen(recv_d.data) == 0 ? "Unknown" : recv_d.data);
		} else if (ret == -1) {
			re_cnt += 1;
		}
	} while(re_cnt < 1); // Wait 1sec

	return 0;
}


int proc_file_transfer(char *cmd)
{
	// cmd : <get | put> <file path> <save path>
	tdtp_data_t send_d, recv_d;
	FILE *fp;
	size_t len = 0;
	char opt[4], f_hash_a[65], f_hash_b[65];
	char buf[1024], f_path[1024], s_path[1024];

	memset(&send_d, 0x00, sizeof(send_d));
	memset(&recv_d, 0x00, sizeof(recv_d));
	memset(opt, 0x00, sizeof(opt));
	memset(f_hash_a, 0x00, sizeof(f_hash_a));
	memset(f_hash_b, 0x00, sizeof(f_hash_b));
	memset(buf, 0x00, sizeof(buf));
	memset(f_path, 0x00, sizeof(f_path));
	memset(s_path, 0x00, sizeof(s_path));

	sscanf(cmd, "%s %s %s", opt, f_path, s_path);
	if(verbose_f) {
		printf("Option    : %s\n", opt);
		printf("File path : %s\n", f_path);
		printf("Save path : %s\n", s_path);
	}

	// Option check
	if((strcmp(opt, "get") != 0) && (strcmp(opt, "put") != 0)) {
		ERR_PRINT_F("%% Error : Invalid command option\n");
		send_error(sock, NULL, &send_d, CMD_DISCONNECT, "Invalid command option");
		return -1;
	}

	// put인 경우에 한하여 저장경로 확인
	if(strcmp(opt, "put") == 0) {
		if(s_path[0] == '/' || (s_path[0] == '.' && s_path[1] == '.')) {
			ERR_PRINT_F("%% Error : Save path cannot start with \'/\' or \"..\" in the put option\n");
			return -1;
		}
	}

	// Init data
	if(init_data(&send_d, CMD_FILE_TRANSFER) < 0) {
		ERR_PRINT_F("%% Error : Data init error\n");
		send_error(sock, NULL, &send_d, CMD_ERR_COMMON, "Data init error");
		return -1;
	}
	d_id = send_d.id;

	// Send command
	send_data(sock, NULL, &send_d, cmd, strlen(cmd), verbose_f);

	// Main proccess
	if(strcmp(opt, "get") == 0) {
		// Get file (Server -> Client)
		// Get file hash value
		if(recv_data(sock, NULL, &recv_d, CMD_FILE_TRANSFER, d_id, verbose_f) < 0)
			return -1;
		sscanf(recv_d.data, "%s", f_hash_a);

		// Receive file
		fp = fopen(s_path, "wb");
		if(fp != NULL) {
			while(recv_data(sock, NULL, &recv_d, CMD_FILE_TRANSFER, d_id, verbose_f) > 0) {
				fwrite(recv_d.data, 1, recv_d.len, fp);
			}
			fclose(fp);
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
		if(verbose_f) {
			printf("Receive file hash   : %s\n", f_hash_a);
			printf("Calculate file hash : %s\n", f_hash_b);
		}

		// Compare file hashes
		if(strncmp(f_hash_a, f_hash_b, 64) != 0) {
			ERR_PRINT_F("%% Error : Different file hash\n");
			unlink(s_path);
			return -1;
		}

		printf("Done\n");
	} else {
		// Put file (Client -> Server)
		// Calc file hash
		memset(buf, 0x00, sizeof(buf));
		if(calc_sha256_file(f_path, buf) < 0) {
			ERR_PRINT_F("%% Erorr : File not found(%s)\n", f_path);
			send_error(sock, NULL, &send_d, CMD_ERR_COMMON, "File not found");
			return -1;
		}
		send_data(sock, NULL, &send_d, buf, 64, verbose_f);

		// Send file
		fp = fopen(f_path, "rb");
		if(fp != NULL) {
			while(!feof(fp)) {
				memset(buf, 0x00, sizeof(buf));
				len = fread(buf, 1, sizeof(buf), fp);
				send_data(sock, NULL, &send_d, buf, len, verbose_f);
			}
			fclose(fp);
		} else {
			ERR_PRINT("File open error(%s)\n", f_path);
			send_error(sock, NULL, &send_d, CMD_ERR_COMMON, "File open error");
			return -1;
		}

		disconnect(sock, NULL, &send_d);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	// Option check
	int opt = 0, cmd_type = 0, proto = 0, port = 0, offset = 0;
	char ip_addr[16];
	char data[DATA_MAX_LEN];

	memset(ip_addr, 0x00, sizeof(ip_addr));
	memset(data, 0x00, sizeof(data));

	while((opt = getopt(argc, argv, "hvc:i:")) != -1) {
		switch(opt) {
			case 'h':
				help_msg();
				if(argv[optind] != NULL) {
					if(strcmp(argv[optind], "debug") == 0)
						print_cmd_help(1);
					else
						print_cmd_help(0);
				} else {
					print_cmd_help(0);
				}
				return 0;
				break;
			case 'v':
				verbose_f = 1;
				break;
			case 'c':
				if(optarg[0] == '-') {
					help_msg();
					return -1;
				}
				cmd_type = atoi(optarg);
				if(cmd_type < CMD_START + 1 || cmd_type >= CMD_DISCONNECT) {
					ERR_PRINT_F("%% Error : Command range over (range : %d ~ %d)\n", CMD_START + 1, CMD_DISCONNECT - 1);
					return -1;
				}
				break;
			case 'i':
				if(strchr(optarg, ':') != NULL) {
					snprintf(ip_addr, strchr(optarg, ':') - optarg + 1, "%s", optarg);
					if(check_ip_form(ip_addr)) {
						ERR_PRINT_F("%% Error : Invalid IP address format\n");
						return -1;
					}
					port = atoi(strchr(optarg, ':') + 1);
				} else {
					if(check_ip_form(optarg)) {
						ERR_PRINT_F("%% Error : Invalid IP address format\n");
						return -1;
					}
					snprintf(ip_addr, strlen(optarg) + 1, "%s", optarg);
				}
				break;
			default:
				help_msg();
				return -1;
				break;
		}
	}
	if(strlen(ip_addr) < 1) strcpy(ip_addr, "127.0.0.1");
	if(port == 0) port = TDTP_PORT;
	if(cmd_type == 0) {
		help_msg();
		return 0;
	}

	if(check_need_data(cmd_type) > 0) {
		if(optind >= argc) {
			print_cmd_help(0);
			return 0;
		}
		while(optind < argc) {
			if((strlen(argv[optind]) + strlen(data) + 1) >= sizeof(data)) {
				ERR_PRINT_F("%% Error : Data max length over (max length : %lu)\n", sizeof(data) - 1);
				return -1;
			}
			offset += sprintf(data + offset, "%s ", argv[optind]);
			optind++;
		}
		data[strlen(data) - 1] = '\0';
	}

	proto = check_protocol(cmd_type);

	if(verbose_f) {
		printf("Options ------------------------------------\n");
		printf("Protocol : %s\n", proto == PROTO_UDP ? "UDP" : proto == PROTO_TCP ? "TCP" : "Unknown");
		printf("Command  : %d\n", cmd_type);
		printf("IP addr  : %s:%d\n", ip_addr, port);
		printf("Data     : %s\n", data);
		printf("--------------------------------------------\n");
	}

	// Main proccess
	int ret = 0, on = 1;
	int syn_re_cnt = 1; // 1 : ~3s timeout, 2 : ~7s timeout, 3 : ~15s timeout / 0 : ~127s
	struct timeval optval = {RECV_TIMEOUT, 0}; // {sec, usec}
	memset(&server_addr, 0x00, sizeof(server_addr));

	// Create server socket
	if(proto == PROTO_UDP) {
		if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			ERR_PRINT("Socket create error\n");
			return -1;
		}
		setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	} else if(proto == PROTO_TCP) {
		if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			ERR_PRINT("Socket create error\n");
			return -1;
		}
		setsockopt(sock, IPPROTO_TCP, TCP_SYNCNT, &syn_re_cnt, sizeof(syn_re_cnt));
	}
	// Set recv timeout option
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &optval, sizeof(optval));

	// Write server info
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = inet_addr(ip_addr);

	// TCP connect
	if(proto == PROTO_TCP) {
		if(connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
			ERR_PRINT("Connect fail\n");
			close(sock);
			return -1;
		}
	}

#if 0 /* 데이터가 평문이 아닌이상 hash table이 다른 경우, 복호화가 불가능하기에 의미 없음 */
	// Check hash table id
	if(check_htb_id(proto) < 0) {
		close(sock);
		return -1;
	}
#endif

	// Action according to command
	ret = 0;
	switch(cmd_type) {
		case CMD_FILE_TRANSFER:
			ret = proc_file_transfer(data);
			break;
		case CMD_CHECK_TDTP:
			// timeout => 1 sec
			optval.tv_sec  = 1;
			optval.tv_usec = 0;
			setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &optval, sizeof(optval));
			ret = proc_check_tdtp(data);
			break;
		default:
			ret = 0;
			break;
	}
	close(sock);
	usleep(100000); // 0.1 sec

	return ret;
}
