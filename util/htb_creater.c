#include <stdio.h>
#include <string.h>
#include <stdlib.h> // srand(), rand()
#include <time.h> // time()
#include <sys/types.h> // getpid()
#include <unistd.h> // getpid()
#include <errno.h>

#define MAX_HASH_CNT 1024

int make_hash_id()
{
	FILE *fp = fopen("./htb_id.h", "w");
	if(fp == NULL) {
		fprintf(stderr, "File create error : %s(%d)\n", strerror(errno), errno);
		return -1;
	}

	fprintf(fp, "#ifndef __HASH_ID_H_\n");
	fprintf(fp, "#define __HASH_ID_H_\n");
	fprintf(fp, "\n");
	fprintf(fp, "#define HTB_ID \"%08x\"\n", rand());
	fprintf(fp, "\n");
	fprintf(fp, "#endif /* __HASH_ID_H_ */\n");
	fclose(fp);

	return 0;
}

int make_hash_table()
{
	FILE *fp = fopen("./hash_table.h", "w");
	if(fp == NULL) {
		fprintf(stderr, "File create error : %s(%d)\n", strerror(errno), errno);
		return -1;
	}

	int i = 0;
	fprintf(fp, "#ifndef __HASH_TABLE_H_\n#define __HASH_TABLE_H_\n\n");
	fprintf(fp, "#define HTB_SIZE %d\n", MAX_HASH_CNT);
	fprintf(fp, "#define H_TABLE _hash_table\n");
	fprintf(fp, "\n");
	fprintf(fp, "unsigned int _hash_table[%d] = {\n", MAX_HASH_CNT);
	for(i = 0; i < MAX_HASH_CNT; i++) {
		if(i > 0 && i % 5 == 0) fprintf(fp, "\n");
		fprintf(fp, "0x%08x", rand());
		if(i != MAX_HASH_CNT - 1) fprintf(fp, ", ");
	}
	fprintf(fp, "};\n\n");
	fprintf(fp, "#endif /* __HASH_TABLE_H_ */");
	fclose(fp);

	return 0;
}

int main()
{
	srand(time(NULL) + getpid());

	if(make_hash_table() < 0)
		return -1;

	if(make_hash_id() < 0)
		return -1;

	return 0;
}
