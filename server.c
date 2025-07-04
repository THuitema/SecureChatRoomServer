#include "protocol.h"

#define MAX_QUEUE_SIZE 10

// Convert sockaddr to sockaddr_in or sockaddr_in6 (equivalent structs that are easier to work with)
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*) sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

// Performs server network setup, including gathering address info for network, creating socket, and binding to port
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
    fprintf(stderr, "ERROR (getaddrinfo) %s\n", gai_strerror(rv));
    exit(1);
  }

  // loop through all results about our computer's network info and bind to the first one that doesn't cause errors
  for (p = servinfo; p != NULL; p = p->ai_next) {
      // create socket for the server
      if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
        perror("socket");
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
        perror("bind");
        continue;
      }

      break;
  }

  // Check for error when binding
  if (p == NULL) {
    fprintf(stderr, "ERROR (bind): failed to bind\n");
    exit(1);
  }

  freeaddrinfo(servinfo);  // all done with this struct

  // Begin listening for incoming connections
  if (listen(sockfd, MAX_QUEUE_SIZE) == -1) {
    close(sockfd);
    perror("listen");
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

// Store hello_packet information internally in users[]
void add_user_info(struct user_info *users[], struct hello_packet *pack, int newfd, int fd_count, int fd_size) {
  (*users)[fd_count-1].fd = newfd;
  strncpy((*users)[fd_count-1].username, pack->username, USERNAME_LEN+1);
  memcpy((*users)[fd_count-1].public_key, pack->public_key, crypto_kx_PUBLICKEYBYTES);
  memcpy((*users)[fd_count-1].id_public_key, pack->id_public_key, crypto_sign_PUBLICKEYBYTES);
  memcpy((*users)[fd_count-1].signature, pack->signature, crypto_sign_BYTES);
}

// Broadcast goodbye_packet to all other users, and remove user from users[] and pfds[] by index
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
        fprintf(stderr, "ERROR (send)");
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

  // main loop
  while (1) {
    int poll_count = poll(pfds, fd_count, -1);

    if (poll_count == -1) {
      perror("poll");
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
            perror("accept");
          } else {
            add_fd(&pfds, &users, newfd, &fd_count, &fd_size);
            
            printf("NEW CONNECTION <ip:%s> <socket:%d>\n",
              inet_ntop(conn_addr.ss_family, get_in_addr((struct sockaddr*)&conn_addr), conn_ip, INET6_ADDRSTRLEN),
              newfd);
          }
        } else { 
          // Handle regular user connection
          int sender_fd = pfds[i].fd;
          int type;

          if ((type = read_packet_type(sender_fd)) <= 0) {
            if (type == 0) {
              printf("HANG UP <socket:%d>\n", sender_fd);
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
                printf("HANG UP <socket:%d>\n", sender_fd);
              } else {
                perror("server");
              }

              close(sender_fd);
              remove_user(pfds, users, i, &fd_count);
              i--; // so we examine the fd we just swapped into this index
            } else {
              // NOTE: server only has access to sender, receiptient. Cannot decrypt the message
              printf("MESSAGE <from:%s> <to:%s> <bytes:%d>\n", pack->sender, pack->receiptient, pack->len);

              // Send message to receiptient without decrypting message
              int dest_fd;
              if ((dest_fd = get_fd(users, pack->receiptient, fd_count)) == -1) {
                fprintf(stderr, "ERROR (get_fd)\n");
                free(pack);
              }

              // Route packet to the correct receiptient
              if (send_packet(dest_fd, PACKET_MESSAGE, pack) == -1) {
                fprintf(stderr, "ERROR (send)\n");
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
                printf("HANG UP <socket:%d>\n", sender_fd);
              } else {
                perror("server");
              }

              close(sender_fd);
              remove_user(pfds, users, i, &fd_count);
              i--; // so we examine the fd we just swapped into this index
            } else {
              add_user_info(&users, hello_pack, newfd, fd_count, fd_size);     

              // Send server info packet to new user
              struct serv_info_packet *info_pack = malloc(sizeof(struct serv_info_packet));
              info_pack->type = PACKET_SERV_INFO;
              info_pack->num_users = fd_count - 2; // minus 2 for server and the user itself
              if (send_packet(sender_fd, PACKET_SERV_INFO, info_pack) == -1) {
                fprintf(stderr, "[ERROR] send server info\n");
                free(info_pack);
                exit(1);
              }

              // Broadcast hello packet to all other users, and send hello packet from each existing user to new user
              for (int j = 0; j < fd_count; j++) {
                int dest_fd = pfds[j].fd;
                if (dest_fd != serverfd && dest_fd != sender_fd) {
                  // Send hello packet from new user to existing user
                  if (send_packet(dest_fd, PACKET_HELLO, hello_pack) == -1) {
                    fprintf(stderr, "ERROR (send)");
                    free(hello_pack);
                    exit(1);
                  }
                  
                  // Send hello packet from existing user to new user
                  struct hello_packet *existing_user_hello = malloc(sizeof(struct hello_packet));
                  existing_user_hello->type = PACKET_HELLO;
                  existing_user_hello->user_status = EXISTING_USER;
                  strncpy(existing_user_hello->username, users[j].username, USERNAME_LEN + 1);
                  memcpy(existing_user_hello->public_key, users[j].public_key, crypto_kx_PUBLICKEYBYTES);
                  memcpy(existing_user_hello->id_public_key, users[j].id_public_key, crypto_sign_PUBLICKEYBYTES);
                  memcpy(existing_user_hello->signature, users[j].signature, crypto_sign_BYTES);
                  
                  if (send_packet(sender_fd, PACKET_HELLO, existing_user_hello) == -1) {
                    fprintf(stderr, "ERROR (send): send existing user hello\n");
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
            fprintf(stderr, "ERROR: invalid packet type\n");
          }
        }
      }
    }
  }
}