# Define the compiler
CC = gcc

# Define the directories
CODE_DIR = code
CLIENT_DIR = client
SERVER_DIR = server

# Define the source files
CLIENT_SRC = $(CODE_DIR)/FTPClient.c
SERVER_SRC = $(CODE_DIR)/FTPServer.c

# Define the target executables
CLIENT_EXE = $(CLIENT_DIR)/client
SERVER_EXE = $(SERVER_DIR)/server

# Define the compiler flags
CFLAGS = -Wall -Wextra -Werror

# Default target
all: $(CLIENT_EXE) $(SERVER_EXE)

# Compile client
$(CLIENT_EXE): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $@ $<

# Compile server
$(SERVER_EXE): $(SERVER_SRC)
	$(CC) $(CFLAGS) -o $@ $<

# Clean up the executables
clean:
	rm -f $(CLIENT_EXE) $(SERVER_EXE)

.PHONY: all clean
