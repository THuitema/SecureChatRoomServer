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
// #define PUBLIC_KEY_LEN 16

#define PORT "3050"
#define PACKET_HELLO 1
#define PACKET_MESSAGE 2
#define PACKET_GOODBYE 3

struct hello_packet {
  uint32_t type;
  char username[USERNAME_LEN + 1];
  // uint32_t public_key_len;
  unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
};

struct message_packet {
  uint32_t type;
  char sender[USERNAME_LEN + 1];
  char receiptient[USERNAME_LEN + 1];
  uint32_t len;
  char message[MAX_MESSAGE_LEN];
};

struct goodbye_packet {
  uint32_t type;
  char username[USERNAME_LEN + 1];
};

struct user_info {
  int fd;
  char username[USERNAME_LEN + 1];
  // uint16_t public_key_len;
  unsigned char public_key[crypto_kx_PUBLICKEYBYTES];
  unsigned char tx_key[crypto_kx_SESSIONKEYBYTES]; // encrypting to peer
  unsigned char rx_key[crypto_kx_SESSIONKEYBYTES]; // decrypting from peer
};

int send_packet(int fd, uint32_t type, void *pack); // struct packet *pack
int read_packet(int fd, uint32_t expected_type, void *pack);
int read_packet_type(int fd);

