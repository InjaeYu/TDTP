TOPDIR:=${CURDIR}
export TOPDIR

SERVER = tdtpd
CLIENT = tdtp_client
HTB_CREATER = htb_creater
HTB_H = hash_table.h
TDTP_BD=\"$(shell date '+%Y-$m-$d %T')\"

.SUFFIXES: .c .o
CC = gcc

CFLAGS = -Wall -O2
CPPFLAGS = -Iinclude/ -DTDTP_BD="$(TDTP_BD)"
LDFLAGS = -lcrypto -lpthread

SRC_DIR = $(TOPDIR)/src
OBJ_DIR = $(TOPDIR)/obj
INC_DIR = $(TOPDIR)/include
UTIL_DIR = $(TOPDIR)/util
BIN_DIR = $(TOPDIR)/bin
export SRC_DIR OBJ_DIR INC_DIR UTIL_DIR

SERVER = tdtpd
CLIENT = tdtp_client

SRCS = $(notdir $(wildcard $(SRC_DIR)/*.c))
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

OBJECTS = $(patsubst %.o,$(OBJ_DIR)/%.o,$(OBJS))
COMMON_OBJ = $(filter-out $(SERVER).% $(CLIENT).%, $(OBJECTS))
SERVER_OBJ = $(filter $(SERVER).%, $(OBJECTS))
CLIENT_OBJ = $(filter $(CLIENT).%, $(OBJECTS))

all: htb_init server client

$(OBJ_DIR)/%.o: $(SERVER_SRC_DIR)/%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@ -MD $(LDFLAGS)

htb_init: $(UTIL_DIR)/$(HTB_CREATER).c
	@if [ ! -d $(BIN_DIR) ]; then \
		mkdir $(BIN_DIR); \
	fi
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$(HTB_CREATER) $<
	@cd $(INC_DIR); $(BIN_DIR)/$(HTB_CREATER)

server: $(SERVER_OBJ)
	@if [ ! -d $(BIN_DIR) ]; then \
		mkdir $(BIN_DIR); \
	fi
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$(SERVER) $(SERVER_OBJ) $(LDFLAGS)

client: $(CLIENT_OBJ)
	@if [ ! -d $(BIN_DIR) ]; then \
		mkdir $(BIN_DIR); \
	fi
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$(CLIENT) $(CLIENT_OBJ) $(LDFLAGS)

clean:
	$(RM) $(OBJECTS) $(DEPS) $(SERVER) $(CLIENT) $(INC_DIR)/$(HTB_H) $(BIN_DIR)/*

.PHONY: all htb_init server client clean

-include $(DEPS)
