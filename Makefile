TOPDIR:=${CURDIR}

SERVER = tdtpd
CLIENT = tdtp_client
HTB_CREATER = htb_creater
HTB_H = hash_table.h htb_id.h
TDTP_BD=\"$(shell date '+%Y-%m-%d %T')\"

SRC_DIR = $(TOPDIR)/src
OBJ_DIR = $(TOPDIR)/obj
INC_DIR = $(TOPDIR)/include
UTIL_DIR = $(TOPDIR)/util
BIN_DIR = $(TOPDIR)/bin

.SUFFIXES: .c .o
CC = gcc

CFLAGS := -Wall -O2
CPPFLAGS := -I$(INC_DIR) -DTDTP_BD="$(TDTP_BD)"
LDFLAGS := -lcrypto -lpthread

#SRCS = $(notdir $(wildcard $(SRC_DIR)/*.c))
#OBJS = $(SRCS:.c=.o)
SRCS = $(wildcard $(SRC_DIR)/*.c)
COMMON_SRC = $(filter-out %/$(SERVER).c %/$(CLIENT).c, $(SRCS))
SERVER_SRC = $(filter %/$(SERVER).c, $(SRCS))
CLIENT_SRC = $(filter %/$(CLIENT).c, $(SRCS))

OBJS = $(patsubst %.o,$(OBJ_DIR)/%.o,$(notdir $(SRCS:.c=.o)))
COMMON_OBJ = $(filter-out %/$(SERVER).o %/$(CLIENT).o, $(OBJS))
SERVER_OBJ = $(filter %/$(SERVER).o, $(OBJS))
CLIENT_OBJ = $(filter %/$(CLIENT).o, $(OBJS))

all: directory htb_init server client

show:
	@echo SRCS : $(SRCS)
	@echo COMMON_SRC  : $(COMMON_SRC)
	@echo SERVER_SRC  : $(SERVER_SRC)
	@echo CLIENT_SRC  : $(CLIENT_SRC)
	@echo OBJS : $(OBJS)
	@echo COMMON_OBJ  : $(COMMON_OBJ)
	@echo SERVER_OBJ  : $(SERVER_OBJ)
	@echo CLIENT_OBJ  : $(CLIENT_OBJ)

directory:
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(OBJ_DIR)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@if [ ! -d $(OBJ_DIR) ]; then mkdir -p $(OBJ_DIR); fi
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(BIN_DIR)/$(HTB_CREATER): $(UTIL_DIR)/$(HTB_CREATER).c
	@if [ ! -d $(BIN_DIR) ]; then mkdir -p $(BIN_DIR); fi
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$(HTB_CREATER) $<

$(patsubst %.h,$(INC_DIR)/%.h,$(HTB_H)): $(BIN_DIR)/$(HTB_CREATER)
	@cd $(INC_DIR); $(BIN_DIR)/$(HTB_CREATER)

htb_init: $(patsubst %.h,$(INC_DIR)/%.h,$(HTB_H))

server: htb_init $(SERVER_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$(SERVER) $(SERVER_OBJ) $(COMMON_OBJ) $(LDFLAGS)

client: htb_init $(CLIENT_OBJ) $(COMMON_OBJ)
	$(CC) $(CFLAGS) -o $(BIN_DIR)/$(CLIENT) $(CLIENT_OBJ) $(COMMON_OBJ) $(LDFLAGS)

clean:
	$(RM) -r $(OBJS) $(patsubst %.h,$(INC_DIR)/%.h,$(HTB_H)) $(BIN_DIR)

.PHONY: all htb_init server client clean show directory
