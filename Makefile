CC = g++
CFLAGS = -Wall -std=c++17 -Iinclude
LIBS = -lpcap

SRC = src/main.cpp src/sniffer.cpp src/parser.cpp src/logger.cpp src/cli.cpp
OBJ = $(SRC:.cpp=.o)
EXEC = sniff

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $(EXEC) $(LIBS)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC)
