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
    fprintf(stderr, "[ERROR] getaddrinfo - %s\n", gai_strerror(rv));
    exit(1);
  }

  // loop through all network results and connect to first one
  for (p = servinfo; p != NULL; p = p->ai_next) {
    // create client socket
    if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("socket");
      continue;
    }

    // connect socket to host
    if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sockfd);
      perror("connect");
      continue;
    }

    break;
  }

  if (p == NULL) {
    fprintf(stderr, "[ERROR] failed to connect\n");
    exit(1);
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), conn_ip, sizeof conn_ip);

  freeaddrinfo(servinfo);

  return sockfd;
}

void add_user(struct user_info *users[], struct hello_packet *pack, int *user_count, int *user_size, char *username, unsigned char *pub_key, unsigned char *sec_key) {
  // If we don't have room, realloc twice the current size of the array
  if (*user_count == *user_size) {
    *user_size *= 2;
    *users = realloc(*users, sizeof(**users) * (*user_size));
  }

  (*users)[*user_count].fd = -1; // we don't care about this for client side, server handles file desciptors
  strncpy((*users)[*user_count].username, pack->username, USERNAME_LEN+1);
  memcpy((*users)[*user_count].public_key, pack->public_key, crypto_kx_PUBLICKEYBYTES);

  unsigned char rx_key[crypto_kx_SESSIONKEYBYTES]; // for decrypting messages from peer
  unsigned char tx_key[crypto_kx_SESSIONKEYBYTES]; // for encrypting messages to peer
  int rv = strcmp(username, pack->username);

  if (rv == 0) {
    fprintf(stderr, "[ERROR] add_user - key exchange failed (usernames matched)\n");
    exit(1);
  } else if (rv < 0) {
    if (crypto_kx_client_session_keys(rx_key, tx_key, pub_key, sec_key, pack->public_key) != 0) {
      fprintf(stderr, "[ERROR] add_user - key exchange failed\n");
      exit(1);
    }
  } else {
    if (crypto_kx_server_session_keys(rx_key, tx_key, pub_key, sec_key, pack->public_key) != 0) {
      fprintf(stderr, "[ERROR] add_user - key exchange failed\n");
      exit(1);
    }
  }
  memcpy((*users)[*user_count].tx_key, tx_key, crypto_kx_SESSIONKEYBYTES);
  memcpy((*users)[*user_count].rx_key, rx_key, crypto_kx_SESSIONKEYBYTES);

  (*user_count)++;
}

int remove_user(struct user_info users[], char *username, int *user_count) {
  if (!username) {
    return -1;
  }

  for (int i = 0; i < *user_count; i++) {
    if (strcmp(users[i].username, username) == 0) {
      // Swap with last user and decrement count
      users[i] = users[*user_count - 1];
      (*user_count)--;
      return 1;
    }
  }

  return -1;
}

void compute_fingerprint(unsigned char *id_public_key) {
  unsigned char hash[crypto_generichash_BYTES_MIN];  // crypto_hash_sha256_BYTES
  crypto_generichash(hash, crypto_generichash_BYTES_MIN, id_public_key, crypto_sign_PUBLICKEYBYTES, NULL, 0);
  // crypto_hash_sha256(hash, id_public_key, crypto_sign_PUBLICKEYBYTES);

  // Print in hexadecimal
  for (int i = 0; i < crypto_generichash_BYTES_MIN; i++) {
    printf("%02x", hash[i]);
    // if ((i+1) % 8 == 0) {
    //   printf("\n");
    // }
  }
  // printf("\n");
}

int send_client_hello(int sockfd, char *username, unsigned char public_key[], unsigned char id_public_key[], unsigned char id_secret_key[]) {
  // Send client join packet to server, containing username and public key
  struct hello_packet *pack = malloc(sizeof(struct hello_packet));

  pack->type = PACKET_HELLO;
  pack->user_status = NEW_USER;
  strncpy(pack->username, username, USERNAME_LEN + 1);
  memcpy(pack->public_key, public_key, crypto_kx_PUBLICKEYBYTES);
  memcpy(pack->id_public_key, id_public_key, crypto_sign_PUBLICKEYBYTES);

  if (crypto_sign_detached(pack->signature, NULL, public_key, crypto_kx_PUBLICKEYBYTES, id_secret_key) == -1) {
    fprintf(stderr, "[ERROR] crypto_sign_detached\n");
    exit(1);
  }

  if (send_packet(sockfd, PACKET_HELLO, pack) < 0) {
    free(pack);
    return -1;
  }
  free(pack);
  return 1;
}

int get_user_rxkey(unsigned char *key, struct user_info users[], char *username, int user_count) {
  if (!username) {
    return -1;
  }

  for (int i = 0; i < user_count; i++) {
    if (strcmp(users[i].username, username) == 0) {
      memcpy(key, users[i].rx_key, crypto_kx_SESSIONKEYBYTES);
      return 1;
    }
  }
  return -1;
}

int main(int argc, char *argv[]) {
  int sockfd;
  const int fd_count = 2; // one for server, one for stdin (user input)
  struct pollfd *pfds = malloc(sizeof *pfds * fd_count);
  char buffer[MAX_MESSAGE_LEN];

  int user_count = 0;
  int user_size = 5;
  int existing_users = -1;
  struct user_info *users = malloc(sizeof *users * user_size);

  if (argc != 3) {
    fprintf(stderr, "[ERROR] missing required field(s) - [hostname] [username]\n");
    exit(1);
  }

  char *username_arg = argv[2];
  if (strlen(username_arg) > USERNAME_LEN) {
    fprintf(stderr, "[ERROR] username must be less than or equal to %d characters", USERNAME_LEN);
    exit(1);
  }

  char username[USERNAME_LEN + 1];
  strncpy(username, username_arg, USERNAME_LEN);
  username[USERNAME_LEN] = '\0';
  
  sockfd = setup_client(argv[1]);

  // Confirm sodium library initialized
  if (sodium_init() < 0) {
    exit(1);
  } 

  unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
  unsigned char secret_key[crypto_kx_SECRETKEYBYTES];
  crypto_kx_keypair(public_key, secret_key);
  unsigned char id_public_key[crypto_sign_PUBLICKEYBYTES];
  unsigned char id_secret_key[crypto_sign_SECRETKEYBYTES];
  crypto_sign_keypair(id_public_key, id_secret_key);

  printf("--- SYSTEM NOTICE ---\n\n");
  printf("Welcome to the secure chat room.\n");
  printf("This server implements end-to-end encryption and manual public key verification.\n\n");

  // printf("To leave the room at any time, type \\leave\n\n");

  printf("Your safety number: ");
  compute_fingerprint(id_public_key);
  printf("\n\n");

  // printf("IMPORTANT:\n");
  // printf("- Verify this number with others if they ask. Do NOT share it in the chat (use Discord, phone call, etc.)\n");
  // printf("- Verify each existing user's safety number (below) matches with what you see.\n");
  // printf("- If ANY number does not match, someone may be impersonating or intercepting messages.\n");

  // printf("\nExisting Users (if any exist):\n");
  if (send_client_hello(sockfd, username, public_key, id_public_key, id_secret_key) < 0) {
    fprintf(stderr, "[ERROR] send client hello\n");
    exit(1);
  }

  // Setup the file descriptor array for our socket connecting to server, and for standard input
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
      int type;
      
      if ((type = read_packet_type(sockfd)) <= 0) {
        if (type == 0) { // server has disconnected
          close(sockfd);
          fprintf(stderr, "Server has disconnected, bye!\n");
          exit(1);
        }
        fprintf(stderr, "[ERROR] read_packet_type\n");
      } else if (type == PACKET_MESSAGE) {

        // Read message from server
        struct message_packet *pack = malloc(sizeof(struct message_packet));
        if (read_packet(pfds[SERVER].fd, PACKET_MESSAGE, pack) <= 0) {
          close(sockfd);
          fprintf(stderr, "[ERROR] recv PACKET_MESSAGE");
          exit(1);
        }

        // Decrypt message using shared key
        unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
        if (get_user_rxkey(rx_key, users, pack->sender, user_count) == -1) {
          fprintf(stderr, "[ERROR] retrieve rx_key\n");
          exit(1);
        }
        int message_len = pack->len - crypto_secretbox_MACBYTES;
        unsigned char decrypted[message_len + 1];
        if (crypto_secretbox_open_easy(decrypted, pack->message, pack->len, pack->nonce, rx_key) != 0) {
          fprintf(stderr, "[ERROR] crypto_secretbox_open_easy - decryption failed\n");
          exit(1);
        }
        decrypted[message_len] = '\0';

        printf("<%s>: %s\n", pack->sender, decrypted);

      } else if (type == PACKET_HELLO) {
        if (existing_users == -1) {
          fprintf(stderr, "[ERROR] reading PACKET_HELLO before receiving PACKET_SERV_INFO\n");
          close(sockfd);
          exit(1);
        }

        // read packet in and add to users (function similar to add_fd, but dont edit pfds)
        struct hello_packet *hello_pack = malloc(sizeof(struct hello_packet));
        if (read_packet(pfds[SERVER].fd, PACKET_HELLO, hello_pack) <= 0) {
          fprintf(stderr, "[ERROR] recv PACKET_HELLO\n");
          close(sockfd);
          free(hello_pack);        
          exit(1);
        }

        // Verify signature of packet
        if (crypto_sign_verify_detached(hello_pack->signature, hello_pack->public_key, crypto_kx_PUBLICKEYBYTES, hello_pack->id_public_key) == -1) {
          fprintf(stderr, "[ERROR] Signature verification failed. Aborting connection.\n");
          exit(1);
        }

        // Get fingerprint of that user
        if (hello_pack->user_status == EXISTING_USER) {
          printf("- %s: ", hello_pack->username);
          compute_fingerprint(hello_pack->id_public_key);
          existing_users--;
          if (existing_users == 0) {
            printf("\n\nUse a trusted method (e.g. phone call or another app) to verify these numbers.\n\n");
            printf("Type \\leave to exit if any numbers don't match or anything else looks suspicious\n\n");
            printf("--- END OF NOTICE ---\n\n");
          }

        } else {
          printf("\n--- New user joined: %s ---\n", hello_pack->username);
          printf("--- Their safety number (verify with trusted method): ");
          compute_fingerprint(hello_pack->id_public_key);
          printf(" ---\n\n");
        }

        add_user(&users, hello_pack, &user_count, &user_size, username, public_key, secret_key);
        free(hello_pack);    

      } else if (type == PACKET_GOODBYE) {

        struct goodbye_packet *pack = malloc(sizeof(struct goodbye_packet));
        if (read_packet(pfds[SERVER].fd, PACKET_GOODBYE, pack) <= 0) {
          close(sockfd);
          fprintf(stderr, "[ERROR] recv PACKET_GOODBYE\n");
          free(pack);
          exit(1);
        }

        // remove the user from users (search by username)
        if (remove_user(users, pack->username, &user_count) == -1) {
          fprintf(stderr, "[ERROR] remove_user\n");
          close(sockfd);
          exit(1);
        }
        printf("--- %s left the room ---\n", pack->username);

        free(pack);

      } else if (type == PACKET_SERV_INFO) {
        struct serv_info_packet *pack = malloc(sizeof(struct serv_info_packet));
        if (read_packet(pfds[SERVER].fd, PACKET_SERV_INFO, pack) <= 0) {
          close(sockfd);
          fprintf(stderr, "[ERROR] recv PACKET_SERV_INFO\n");
          free(pack);
          exit(1);
        }

        existing_users = pack->num_users;

        if (existing_users == 0) {
          printf("You are the only participant in the room.\n\n");
          printf("Use a trusted method (e.g. phone call or another app) to verify these numbers.\n\n");
          printf("Type \\leave to exit if any numbers don't match or anything else looks suspicious\n\n");
          printf("--- END OF NOTICE ---\n\n");
        } else if (existing_users == 1) {
          printf("There is %d existing participant: \n", existing_users); 
        } else {
          printf("There are %d existing participants: \n", existing_users);
        }
      }
      
      else {
        fprintf(stderr, "[ERROR] invalid packet type, type=%d\n", type);
      }
      
    }

    // Check if user has data to send
    if (pfds[STDIN].revents & (POLLIN | POLLHUP)) {
      if (fgets(buffer, MAX_MESSAGE_LEN, stdin) == NULL) {
        perror("stdin");
        continue;
      }

      buffer[strcspn(buffer, "\n")] = 0; // removes \n character at end of input string

      // Don't send info if user just pressed enter key and nothing else
      if (strlen(buffer) == 0) {
        continue;
      }

      // Check for exit command
      if (strcmp(buffer, "\\leave") == 0) {
        close(sockfd);
        printf("You have disconnected.\n");
        return 0;
      }

      // Create packet for each user
      for (int i = 0; i < user_count; i++) {
        // Encrypt message using the shared key between the two clients
        unsigned char ciphertext[crypto_secretbox_MACBYTES + strlen(buffer)];
        unsigned char nonce[crypto_secretbox_NONCEBYTES];
        randombytes_buf(nonce, sizeof nonce);

        if (crypto_secretbox_easy(ciphertext, (const unsigned char *)buffer, strlen(buffer), nonce, users[i].tx_key) != 0) {
          fprintf(stderr, "[ERROR] crypto_secretbox_easy - error encrypting message\n");
          exit(1);
        }

        struct message_packet *pack = malloc(sizeof(struct message_packet));
        pack->type = PACKET_MESSAGE;
        strncpy(pack->sender, username, USERNAME_LEN + 1);
        strncpy(pack->receiptient, users[i].username, USERNAME_LEN + 1);
        memcpy(pack->nonce, nonce, crypto_secretbox_NONCEBYTES);
        pack->len = sizeof ciphertext;
        memcpy(pack->message, ciphertext, sizeof ciphertext);

        if (send_packet(sockfd, PACKET_MESSAGE, pack) == -1) {
          fprintf(stderr, "[ERROR] send");
          free(pack);
          exit(1);
        }

        free(pack);
      }
    }
  }
} 
