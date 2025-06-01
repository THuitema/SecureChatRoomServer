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
#include <sodium.h>

#define MAX_MESSAGE_LEN 1024
#define USERNAME_LEN 16
#define NEW_USER 1
#define EXISTING_USER 2
#define PORT "3050"
#define PACKET_HELLO 1
#define PACKET_MESSAGE 2
#define PACKET_GOODBYE 3
#define PACKET_SERV_INFO 4

// Users send this when the join the server. It is broadcasting to all existing users in the server
struct hello_packet {
  uint32_t type;
  uint32_t user_status;
  char username[USERNAME_LEN + 1];
  unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
  unsigned char id_public_key[crypto_sign_PUBLICKEYBYTES];
  unsigned char signature[crypto_sign_BYTES];
};

// Encrypted message from sender to receiptient. 
struct message_packet {
  uint32_t type;
  char sender[USERNAME_LEN + 1];
  char receiptient[USERNAME_LEN + 1];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  uint32_t len;
  unsigned char message[MAX_MESSAGE_LEN + crypto_secretbox_MACBYTES]; // encypted
};

// Server broadcasts this to users when they detect a user has disconnected
struct goodbye_packet {
  uint32_t type;
  char username[USERNAME_LEN + 1];
};

// First packet server sends to user when they join. Just contains number of users in server
struct serv_info_packet {
  uint32_t type;
  uint32_t num_users;
};

// Internal user info storage by clients. Server does not have access to tx_key or rx_key, which is sensitive info
struct user_info {
  int fd;
  char username[USERNAME_LEN + 1];
  unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
  unsigned char tx_key[crypto_kx_SESSIONKEYBYTES]; // encrypting to peer
  unsigned char rx_key[crypto_kx_SESSIONKEYBYTES]; // decrypting from peer
  unsigned char id_public_key[crypto_sign_PUBLICKEYBYTES];
  unsigned char signature[crypto_sign_BYTES];
};

int send_packet(int fd, uint32_t type, void *pack);
int read_packet(int fd, uint32_t expected_type, void *pack);
int read_packet_type(int fd);

