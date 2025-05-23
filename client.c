/*
** client.c -- user can send messages, encapsulated as packets when sent to server
*/
#include "protocol.h"

#define SERVER 0
#define STDIN 1 

// Convert sockaddr to sockaddr_in or sockaddr_in6 (equivalent structs that are easier to work with)
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*) sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

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

int main(int argc, char *argv[]) {
  int sockfd;
  int fd_count = 2;
  struct pollfd *pfds = malloc(sizeof *pfds * fd_count);
  char buffer[MAX_DATA_SIZE];

  if (argc != 3) {
    fprintf(stderr, "required fields: [hostname] [username]\n");
    exit(1);
  }

  char *username_arg = argv[2];
  if (strlen(username_arg) > USERNAME_LEN) {
    fprintf(stderr, "error: username must be less than or equal to %d characters", USERNAME_LEN);
    exit(1);
  }

  char username[USERNAME_LEN + 1];
  strncpy(username, username_arg, USERNAME_LEN);
  username[USERNAME_LEN] = '\0';
  

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
      struct packet *pack = malloc(sizeof(struct packet));
      if (read_packet(pfds[0].fd, pack) <= 0) {
        fprintf(stderr, "client: recv"); // ERROR HAPPENING HERE
        exit(1);
      }
      printf("<%s>: %s\n", pack->username, pack->data);
    }

    // Check if user has data to send
    if (pfds[STDIN].revents & (POLLIN | POLLHUP)) {
      if (fgets(buffer, MAX_DATA_SIZE, stdin) == NULL) {
        perror("stdin");
        continue;
      }

      buffer[strcspn(buffer, "\n")] = 0; // removes \n character at end of input string

      // Don't send info if user just pressed enter key and nothing else
      if (strlen(buffer) == 0) {
        continue;
      }

      struct packet *pack = malloc(sizeof(struct packet));
      pack->len = strlen(buffer);
      strncpy(pack->username, username, USERNAME_LEN + 1);
      strncpy(pack->data, buffer, strlen(buffer));

      if (send_packet(sockfd, pack) == -1) {
        fprintf(stderr, "client: send");
        exit(1);
      }
      free(pack);
    }
  }

} 
