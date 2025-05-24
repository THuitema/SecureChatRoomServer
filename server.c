/*
** server.c -- decodes packets from user into messages, and prints them
*/

#include "protocol.h"

#define MAX_QUEUE_SIZE 10

// Convert sockaddr to sockaddr_in or sockaddr_in6 (equivalent structs that are easier to work with)
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*) sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

// Performs server network setup, including ggathering address info for network, creating socket, and binding to port
int setup_server() {
  struct addrinfo hints, *servinfo, *p;
  int rv, sockfd;
  int yes=1;

  // set hints struct
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;  // TCP connection
  hints.ai_flags = AI_PASSIVE;  // use our computer's IP address for the server

  // get info about our computer's network and place in servinfo struct
  if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    exit(1);
  }

  // loop through all results about our computer's network info and bind to the first one that doesn't cause errors
  for (p = servinfo; p != NULL; p = p->ai_next) {
      // create socket for the server
      if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
        perror("server: socket");
        continue;
      }

      if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        perror("setsockopt");
        exit(1);
      }

      // Disable the "address already in use" error message
      setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

      // tells OS that our server socket will listen for incoming connections on port 3490
      if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
        close(sockfd);
        perror("server: bind");
        continue;
      }

      break;
  }

  // Check for error when binding
  if (p == NULL) {
    fprintf(stderr, "server: failed to bind\n");
    exit(1);
  }

  freeaddrinfo(servinfo);  // all done with this struct

  // Begin listening for incoming connections
  if (listen(sockfd, MAX_QUEUE_SIZE) == -1) {
    close(sockfd);
    perror("server: listen");
    exit(1);
  }

  return sockfd;
}

// Add a new file descriptor to the set for poll()
void add_client(struct pollfd *pfds[], int newfd, int *fd_count, int *fd_size) {
  // If we don't have room, realloc twice the current size of the array
  if (*fd_count == *fd_size) {
    *fd_size *= 2;
    *pfds = realloc(*pfds, sizeof(**pfds) * (*fd_size));
  }

  (*pfds)[*fd_count].fd = newfd;
  (*pfds)[*fd_count].events = POLLIN;
  (*pfds)[*fd_count].revents = 0;
  (*fd_count)++;

  // Send welcome message
  char msg[] = "Welcome to the chat room!";

  struct message_packet *pack = malloc(sizeof(struct message_packet));
  pack->type = PACKET_MESSAGE;
  pack->len = strlen(msg);
  strcpy(pack->username, "server");
  strncpy(pack->data, msg, strlen(msg));

  if (send_packet(newfd, PACKET_MESSAGE, pack) == -1) {
    fprintf(stderr, "server: send");
    exit(1);
  }
  free(pack);
}

// Remove client by swapping with the last fd in the array, then decrementing fd_count
void remove_client(struct pollfd pfds[], int remove_index, int *fd_count) {
  pfds[remove_index] = pfds[*fd_count - 1]; 
  (*fd_count)--;
}

int main(void) {
  int serverfd, newfd;
  struct sockaddr_storage conn_addr;
  socklen_t addrlen;

  // char buffer[MAX_DATA_SIZE];
  char conn_ip[INET6_ADDRSTRLEN];

  int fd_count = 0;
  int fd_size = 5;
  struct pollfd *pfds = malloc(sizeof *pfds * fd_size);

  serverfd = setup_server();

  pfds[0].fd = serverfd;
  pfds[0].events = POLLIN;
  fd_count = 1;

  // main loop
  while (1) {
    int poll_count = poll(pfds, fd_count, -1);

    if (poll_count == -1) {
      perror("server: poll");
      exit(1);
    }

    // run through existing connections looking for data to read
    for (int i = 0; i < fd_count; i++) {
      if (pfds[i].revents & (POLLIN | POLLHUP)) {
        

        // If server if ready to read, then accept new connection
        if (pfds[i].fd == serverfd) {
          addrlen = sizeof conn_addr;
          newfd = accept(serverfd, (struct sockaddr *)&conn_addr, &addrlen);

          if (newfd == -1) {
            perror("server: accept");
          } else {
            add_client(&pfds, newfd, &fd_count, &fd_size);

            printf("server: new connection from %s on socket %d\n",
              inet_ntop(conn_addr.ss_family, get_in_addr((struct sockaddr*)&conn_addr), conn_ip, INET6_ADDRSTRLEN),
              newfd);
          }
        } else { 
          // Handle regular client connection
          int sender_fd = pfds[i].fd;
          int type;

          if ((type = read_packet_type(sender_fd)) <= 0) {
            if (type == 0) {
              printf("server: socket %d hung up\n", sender_fd);
            } else {
              perror("server");
            }

            close(sender_fd);
            remove_client(pfds, i, &fd_count);
            i--; // so we examine the fd we just swapped into this index
          } else if (type == PACKET_MESSAGE) {
            // Read message packet from client

            struct message_packet *pack = malloc(sizeof(struct message_packet));
            int rv = read_packet(sender_fd, PACKET_MESSAGE, pack);

            // Check for error or connection closed by client
            if (rv <= 0) {
              if (rv == 0) {
                printf("server: socket %d hung up\n", sender_fd);
              } else {
                perror("server");
              }

              close(sender_fd);
              remove_client(pfds, i, &fd_count);
              i--; // so we examine the fd we just swapped into this index
            } else {
              printf("<%s> %s\n", pack->username, pack->data);

              // Broadcast data to everyone, except the listener and the sender
              for(int j = 0; j < fd_count; j++) {
                int dest_fd = pfds[j].fd;
                if (dest_fd != serverfd && dest_fd != sender_fd) {

                  if (send_packet(dest_fd, PACKET_MESSAGE, pack) == -1) {
                    fprintf(stderr, "server: send");
                    free(pack);
                    exit(1);
                  }
                }
              }

              free(pack);
            }
          } else if (type == PACKET_CLIENT_HELLO) {
            // New client packet (username & public key)
            struct client_hello_packet *hello_pack = malloc(sizeof(struct client_hello_packet));
            int rv = read_packet(sender_fd, PACKET_CLIENT_HELLO, hello_pack);
            
            // **** Add client to client array, storing fd, username, public key

            // Check for error or connection closed by client
            if (rv <= 0) {
              if (rv == 0) {
                printf("server: socket %d hung up\n", sender_fd);
              } else {
                perror("server");
              }

              close(sender_fd);
              remove_client(pfds, i, &fd_count);
              i--; // so we examine the fd we just swapped into this index
            } else {
              // Broadcast to room that new user has joined
              char buffer[MAX_DATA_SIZE + 1];
              snprintf(buffer, sizeof(buffer), "%s has joined the room!", hello_pack->username);

              struct message_packet *pack = malloc(sizeof(struct message_packet));
              pack->type = PACKET_MESSAGE;
              pack->len = strlen(buffer);
              strcpy(pack->username, "server");
              strncpy(pack->data, buffer, strlen(buffer));

              for(int j = 0; j < fd_count; j++) {
                int dest_fd = pfds[j].fd;
                if (dest_fd != serverfd && dest_fd != sender_fd) {

                  if (send_packet(dest_fd, PACKET_MESSAGE, pack) == -1) {
                    fprintf(stderr, "server: send");
                    free(pack);
                    free(hello_pack);
                    exit(1);
                  }
                }
              }
              free(pack);
              free(hello_pack);
            }
          } else {
            fprintf(stderr, "server: invalid packet type\n");
          }
        }
        
      }
    }
  }
}