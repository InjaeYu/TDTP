#include <stdio.h>
#include <string.h>
#include <stdlib.h> // srand(), rand()
#include <time.h> // time()
#include <sys/types.h> // getpid()
#include <unistd.h> // getpid()
#include <errno.h>

#define MAX_HASH_CNT 1024

int main()
{
	FILE *fp = fopen("./hash_table.h", "w");
	if(fp == NULL) {
		fprintf(stderr, "File create error : %s(%d)\n", strerror(errno), errno);
		return -1;
	}

	int i = 0;
	srand(time(NULL) + getpid());
	fprintf(fp, "#ifndef __HASH_TABLE_H_\n#define __HASH_TABLE_H_\n\nstatic unsigned int _hash_table[%d] = {\n", MAX_HASH_CNT);
	for(i = 0; i < MAX_HASH_CNT; i++) {
		if(i > 0 && i % 5 == 0) fprintf(fp, "\n");
		fprintf(fp, "0x%08x", rand());
		if(i != MAX_HASH_CNT - 1) fprintf(fp, ", ");
	}
	fprintf(fp, "};\n\n#endif /* __HASH_TABLE_H_ */");
	fclose(fp);
	return 0;
}
