CC = gcc
CFLAGS = -g -fsanitize=address,undefined -Wall

all: client server

client: client.o
	$(CC) $(CFLAGS) -o client client.o

server: server.o
	$(CC) $(CFLAGS) -o server server.o

client.o: client.c protocol.h
	$(CC) $(CFLAGS) -c client.c -o client.o

server.o: server.c protocol.h
	$(CC) $(CFLAGS) -c server.c -o server.o

clean:
	rm -f *.o client server

.PHONY: all clean