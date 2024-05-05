CC = g++
FORMAT = clang-format
CFLAGS = -Wall -std=c++2a 
LDFLAGS = -lssl -lcrypto -L/path/to/openssl/lib

BIN_DIR = bin
SRC_DIR = src

all: $(BIN_DIR)/myproxy

$(BIN_DIR)/myproxy: $(SRC_DIR)/myproxy.cpp | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN_DIR)/*.o $(BIN_DIR)/myproxy

format:
	$(FORMAT) -i -style=file $(SRC_DIR)/*.[ch]
