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

#define MAX_DATA_SIZE 128
#define MSG_TYPE_CLIENT 1
#define MSG_TYPE_SERVER 2

#define PORT "3050"

struct MessageHeader {
  uint32_t type; // uint32_t is 4 bytes
  uint32_t length;
};

struct Message {
  struct MessageHeader header;
  char data[MAX_DATA_SIZE];
};

// Convert sockaddr to sockaddr_in or sockaddr_in6 (equivalent structs that are easier to work with)
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*) sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*) sa)->sin6_addr);
}