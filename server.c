/*
** server.c -- decodes packets from user into messages, and prints them
*/

#include "protocol.h"
#include <sodium.h>

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

// Add a new file descriptor to the set for poll(). Called after server accept()'s connection
void add_fd(struct pollfd *pfds[], struct user_info *users[], int newfd, int *fd_count, int *fd_size) {
  // If we don't have room, realloc twice the current size of the array
  if (*fd_count == *fd_size) {
    *fd_size *= 2;
    *pfds = realloc(*pfds, sizeof(**pfds) * (*fd_size));
    *users = realloc(*users, sizeof(**users) * (*fd_size));
  }

  (*pfds)[*fd_count].fd = newfd;
  (*pfds)[*fd_count].events = POLLIN;
  (*pfds)[*fd_count].revents = 0;

  (*fd_count)++;
}

void add_user_info(struct user_info *users[], struct hello_packet *pack, int newfd, int fd_count, int fd_size) {
  (*users)[fd_count-1].fd = newfd;
  strncpy((*users)[fd_count-1].username, pack->username, USERNAME_LEN+1);
  (*users)[fd_count-1].public_key_len = pack->public_key_len;
  memcpy((*users)[fd_count-1].public_key, pack->public_key, PUBLIC_KEY_LEN);
}

void remove_user(struct pollfd pfds[], struct user_info users[], int index, int *fd_count) {
  int user_fd = users[index].fd;

  // broadcast message that user has left
  struct goodbye_packet *pack = malloc(sizeof(struct goodbye_packet));
  pack->type = PACKET_GOODBYE;
  strncpy(pack->username, users[index].username, USERNAME_LEN + 1);

  for (int i = 1; i < *fd_count; i++) { // server fd is index 0
    int dest_fd = pfds[i].fd;
    if (dest_fd != user_fd) {
      if (send_packet(dest_fd, PACKET_GOODBYE, pack) == -1) {
        fprintf(stderr, "server: send");
        free(pack);
        exit(1);
      }
    }
  }
  free(pack);

  users[index] = users[*fd_count - 1];
  pfds[index] = pfds[*fd_count - 1]; 
  (*fd_count)--;
}

// Lookup user by username and return its fd. Returns -1 if not found
int get_fd(struct user_info users[], char *username, int fd_count) {
  if (!username) {
    return -1;
  }

  for (int i = 0; i < fd_count; i++) {
    if (strcmp(users[i].username, username) == 0) {
      return users[i].fd;
    }
  }

  return -1;
}

int main(void) {
  int serverfd, newfd;
  struct sockaddr_storage conn_addr;
  socklen_t addrlen;

  char conn_ip[INET6_ADDRSTRLEN];

  int fd_count = 0;
  int fd_size = 5;
  struct pollfd *pfds = malloc(sizeof *pfds * fd_size);
  struct user_info *users = malloc(sizeof *users * fd_size);

  serverfd = setup_server();

  pfds[0].fd = serverfd;
  pfds[0].events = POLLIN;
  memset(&users[0], 0, sizeof(struct user_info));
  fd_count = 1;

  // Confirm sodium library initialized
  if (sodium_init() < 0) {
    exit(1);
  } 

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
            add_fd(&pfds, &users, newfd, &fd_count, &fd_size);
            
            printf("server: new connection from %s on socket %d\n",
              inet_ntop(conn_addr.ss_family, get_in_addr((struct sockaddr*)&conn_addr), conn_ip, INET6_ADDRSTRLEN),
              newfd);
          }
        } else { 
          // Handle regular user connection
          int sender_fd = pfds[i].fd;
          int type;

          if ((type = read_packet_type(sender_fd)) <= 0) {
            if (type == 0) {
              printf("server: socket %d hung up\n", sender_fd);
            } else {
              perror("server");
            }

            close(sender_fd);
            remove_user(pfds, users, i, &fd_count);
            i--; // so we examine the fd we just swapped into this index
          } else if (type == PACKET_MESSAGE) {
            // Read message packet from user

            struct message_packet *pack = malloc(sizeof(struct message_packet));
            int rv = read_packet(sender_fd, PACKET_MESSAGE, pack);

            // Check for error or connection closed by user
            if (rv <= 0) {
              if (rv == 0) {
                printf("server: socket %d hung up\n", sender_fd);
              } else {
                perror("server");
              }

              close(sender_fd);
              remove_user(pfds, users, i, &fd_count);
              i--; // so we examine the fd we just swapped into this index
            } else {
              printf("<from:%s> <to:%s> \"%s\"\n", pack->sender, pack->receiptient, pack->message);

              // Send message to receiptient without decrypting message
              int dest_fd;
              if ((dest_fd = get_fd(users, pack->receiptient, fd_count)) == -1) {
                fprintf(stderr, "server: get_fd\n");
                free(pack);
              }

              if (send_packet(dest_fd, PACKET_MESSAGE, pack) == -1) {
                fprintf(stderr, "server: send\n");
                free(pack);
                exit(1);
              }
              free(pack);
            }
          } else if (type == PACKET_HELLO) {
            // New user packet (username & public key)
            struct hello_packet *hello_pack = malloc(sizeof(struct hello_packet));
            int rv = read_packet(sender_fd, PACKET_HELLO, hello_pack);

            // Check for error or connection closed by user
            if (rv <= 0) {
              if (rv == 0) {
                printf("server: socket %d hung up\n", sender_fd);
              } else {
                perror("server");
              }

              close(sender_fd);
              remove_user(pfds, users, i, &fd_count);
              i--; // so we examine the fd we just swapped into this index
            } else {
              add_user_info(&users, hello_pack, newfd, fd_count, fd_size);     

              // Broadcast hello packet to all other users, and send hello packet to new user for each existing user
              for (int j = 0; j < fd_count; j++) {
                int dest_fd = pfds[j].fd;
                if (dest_fd != serverfd && dest_fd != sender_fd) {
                  if (send_packet(dest_fd, PACKET_HELLO, hello_pack) == -1) {
                    fprintf(stderr, "server: send");
                    free(hello_pack);
                    exit(1);
                  }
                  
                  // Send hello packet to new user for each existing user
                  struct hello_packet *existing_user_hello = malloc(sizeof(struct hello_packet));
                  existing_user_hello->type = PACKET_HELLO;
                  strncpy(existing_user_hello->username, users[j].username, USERNAME_LEN + 1);
                  existing_user_hello->public_key_len = users[j].public_key_len;
                  memcpy(existing_user_hello->public_key, users[j].public_key, users[j].public_key_len);
                  
                  if (send_packet(sender_fd, PACKET_HELLO, existing_user_hello) == -1) {
                    fprintf(stderr, "server: send existing user hello\n");
                    free(existing_user_hello);
                    free(hello_pack);
                    exit(1);
                  }
                  free(existing_user_hello);
                }
              }
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