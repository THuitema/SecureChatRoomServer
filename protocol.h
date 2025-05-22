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
#define MAX_PACKET_SIZE 136 // 4 + 4 + 128
#define TYPE_SERVER 1
#define TYPE_CLIENT 2

#define PORT "3050"

struct packet {
  uint32_t type;
  uint32_t len;
  char data[MAX_DATA_SIZE + 1];
};

int send_packet(int fd, struct packet *pack);
int read_packet(int fd, struct packet *pack);

