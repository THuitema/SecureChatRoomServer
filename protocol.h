#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>

#define MAX_DATA_SIZE 128
#define USERNAME_LEN 16
#define MAX_PACKET_SIZE 148 // 4 + 16 + 128

#define PORT "3050"

struct packet {
  uint32_t len;
  char username[USERNAME_LEN + 1];
  char data[MAX_DATA_SIZE + 1];
};

int send_packet(int fd, struct packet *pack);
int read_packet(int fd, struct packet *pack);

