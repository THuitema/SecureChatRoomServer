CC = gcc
CFLAGS = -g -Wall -fsanitize=address,undefined
all: client server

client: client.o packet.o
	$(CC) $(CFLAGS) -o client client.o packet.o

server: server.o packet.o
	$(CC) $(CFLAGS) -o server server.o packet.o

client.o: client.c protocol.h
	$(CC) $(CFLAGS) -c client.c -o client.o

server.o: server.c protocol.h
	$(CC) $(CFLAGS) -c server.c -o server.o

packet.o: packet.c protocol.h
	$(CC) $(CFLAGS) -c packet.c

clean:
	rm -f *.o client server

.PHONY: all clean