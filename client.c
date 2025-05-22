/*
** client.c -- user can send messages, encapsulated as packets when sent to server
*/


#include "protocol.h"

#define SERVER 0
#define STDIN 1 

int setup_client(char *host) {
  struct addrinfo hints, *servinfo, *p;
  int rv, sockfd;
  char conn_ip[INET6_ADDRSTRLEN];

  // set hints struct
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  // get remote server network
  if ((rv = getaddrinfo(host, PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    exit(1);
  }

  // loop through all network results and connect to first one
  for (p = servinfo; p != NULL; p = p->ai_next) {
    // create client socket
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    // connect socket to host
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("client: connect");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "client: failed to connect\n");
    exit(1);
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), conn_ip, sizeof conn_ip);
  printf("client: connecting to %s\n", conn_ip);

  freeaddrinfo(servinfo);

  return sockfd;
}

void read_packet(int fd, char *buffer) {
  // pick approach to read in packet. read type, length, then the data
  // print the data
  int msg_bytes;
  
  if ((msg_bytes = recv(fd, buffer, MAX_DATA_SIZE-1, 0)) == -1) {
    perror("recv");
    exit(1);
  }

  buffer[msg_bytes] = '\0';
}

void send_packet(int fd, char *buffer) {
  // create packet by adding type, length, and data
  // print packet details & total size on various inputs by user before sending to server
  // write sendall() like in Beej 
  // add user ip field to packet?
  printf("message: %s", buffer);
  printf("message length: %zu\n", strlen(buffer));
}


int main(int argc, char *argv[]) {
  int sockfd;
  int fd_count = 2;
  struct pollfd *pfds = malloc(sizeof *pfds * fd_count);
  char buffer[MAX_DATA_SIZE];

  if (argc != 2) {
    fprintf(stderr, "usage: missing client hostname\n");
    exit(1);
  }

  // Setup the file descriptor array for our socket connecting to server, and for standard input
  sockfd = setup_client(argv[1]);
  pfds[SERVER].fd = sockfd;
  pfds[SERVER].events = POLLIN;
  pfds[SERVER].revents = 0;

  pfds[STDIN].fd = fileno(stdin);
  pfds[STDIN].events = POLLIN;
  pfds[STDIN].revents = 0;
  
  // Main loop
  while (1) {
    int poll_count = poll(pfds, fd_count, -1);

    if (poll_count == -1) {
      perror("poll");
      exit(1);
    }

    // Check if server has sent data
    if (pfds[SERVER].revents & (POLLIN | POLLHUP)) {
      read_packet(pfds[0].fd, buffer);
      printf("server: %s\n", buffer);
    }

    // Check if user has data to send
    if (pfds[STDIN].revents & (POLLIN | POLLHUP)) {
      if (fgets(buffer, MAX_DATA_SIZE, stdin) == NULL) {
        perror("stdin");
        continue;
      }
      buffer[strcspn(buffer, "\n")] = 0; // removes \n character at end of input string
      send_packet(sockfd, buffer);
    }
  }

} 







