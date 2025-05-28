#include "protocol.h"

int read_exact(int fd, void *buffer, int len);
int send_message_packet(int fd, struct message_packet *pack);
int send_hello_packet(int fd, struct hello_packet *pack);
int send_goodbye_packet(int fd, struct goodbye_packet *pack);
int read_message_packet(int fd, struct message_packet *pack);
int read_hello_packet(int fd, struct hello_packet *pack);
int read_goodbye_packet(int fd, struct goodbye_packet *pack);

int send_packet(int fd, uint32_t type, void *pack) {
  if (type == PACKET_MESSAGE) {
    return send_message_packet(fd, (struct message_packet *)pack);
  } else if (type == PACKET_HELLO) {
    return send_hello_packet(fd, (struct hello_packet *)pack);
  } else if (type == PACKET_GOODBYE) {
    return send_goodbye_packet(fd, (struct goodbye_packet *)pack);
  }
  return -1;
}

int send_message_packet(int fd, struct message_packet *pack) {
  if (pack->len > MAX_MESSAGE_LEN) {
    return -1;
  }

  uint32_t packet_size = 4 + (2*USERNAME_LEN) + crypto_secretbox_NONCEBYTES + 4 + pack->len; // 8 + USERNAME_LEN + pack->len;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  memcpy(buffer, &packet_type, 4);

  memcpy(buffer + 4, pack->sender, USERNAME_LEN);
  memcpy(buffer + 4 + USERNAME_LEN, pack->receiptient, USERNAME_LEN);


  memcpy(buffer + 4 + (2*USERNAME_LEN), pack->nonce, crypto_secretbox_NONCEBYTES);

  uint32_t message_len = htonl(pack->len); 
  memcpy(buffer + 4 + (2 * USERNAME_LEN) + crypto_secretbox_NONCEBYTES, &message_len, 4);
  memcpy(buffer + 4 + (2 * USERNAME_LEN) + crypto_secretbox_NONCEBYTES + 4, pack->message, pack->len);

  // repeat send() calls until all of packet is sent
  uint32_t bytes_sent = 0;
  uint32_t bytes_left = packet_size;
  uint32_t n;

  while (bytes_sent < packet_size) {
    n = send(fd, buffer + bytes_sent, bytes_left, 0);
    if (n == -1) {
      return -1;
    }
    bytes_sent += n;
    bytes_left -= n;
  }

  free(buffer);

  return 1;
}

int send_hello_packet(int fd, struct hello_packet *pack) {
  uint32_t packet_size = 4 + USERNAME_LEN + crypto_kx_PUBLICKEYBYTES;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  memcpy(buffer, &packet_type, 4);

  memcpy(buffer + 4, pack->username, USERNAME_LEN);

  // uint32_t len = htonl(pack->public_key_len);
  // memcpy(buffer + 4 + USERNAME_LEN, &len, 4);
  memcpy(buffer + 4 + USERNAME_LEN, pack->public_key, crypto_kx_PUBLICKEYBYTES);

  // repeat send() calls until all of packet is sent
  uint32_t bytes_sent = 0;
  uint32_t bytes_left = packet_size;
  uint32_t n;

  while (bytes_sent < packet_size) {
    n = send(fd, buffer + bytes_sent, bytes_left, 0);
    if (n == -1) {
      return -1;
    }
    bytes_sent += n;
    bytes_left -= n;
  }

  free(buffer);

  return 1;
}

int send_goodbye_packet(int fd, struct goodbye_packet *pack) {
  uint32_t packet_size = 4 + USERNAME_LEN;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  memcpy(buffer, &packet_type, 4);

  memcpy(buffer + 4, pack->username, USERNAME_LEN);

  // repeat send() calls until all of packet is sent
  uint32_t bytes_sent = 0;
  uint32_t bytes_left = packet_size;
  uint32_t n;

  while (bytes_sent < packet_size) {
    n = send(fd, buffer + bytes_sent, bytes_left, 0);
    if (n == -1) {
      return -1;
    }
    bytes_sent += n;
    bytes_left -= n;
  }

  free(buffer);

  return 1;
}


int read_packet(int fd, uint32_t expected_type, void *pack) {
  if (expected_type == PACKET_MESSAGE) {
    return read_message_packet(fd, (struct message_packet *)pack);
  } else if (expected_type == PACKET_HELLO) {
    return read_hello_packet(fd, (struct hello_packet *)pack);
  } else if (expected_type == PACKET_GOODBYE) {
    return read_goodbye_packet(fd, (struct goodbye_packet *)pack);
  }
  return -1;
}

int read_message_packet(int fd, struct message_packet *pack) {
  int rv;
  uint32_t len; 
  char sender[USERNAME_LEN + 1];
  char receiptient[USERNAME_LEN + 1];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];

  // read sender and receiptient fields
  if ((rv = read_exact(fd, sender, USERNAME_LEN)) <= 0) {
    return rv;
  }
  sender[USERNAME_LEN] = '\0';

  if ((rv = read_exact(fd, receiptient, USERNAME_LEN)) <= 0) {
    return rv;
  }
  receiptient[USERNAME_LEN] = '\0';

  if ((rv = read_exact(fd, nonce, crypto_secretbox_NONCEBYTES)) <= 0) {
    return rv;
  }

  // read length field
  if ((rv = read_exact(fd, &len, 4)) <= 0) {
    return rv;
  }
  len = ntohl(len);

  // if (len > MAX_MESSAGE_LEN) {
  //   return -1;
  // }
  // char *message = malloc(len + 1);
  unsigned char message[len];

  // read data field
  if ((rv = read_exact(fd, message, len)) <= 0) {
    return rv;
  }
  // message[len] = '\0';

  pack->type = PACKET_MESSAGE;
  strncpy(pack->sender, sender, USERNAME_LEN + 1);
  strncpy(pack->receiptient, receiptient, USERNAME_LEN + 1);
  memcpy(pack->nonce, nonce, sizeof nonce);
  pack->len = len;
  // strncpy(pack->message, message, len + 1);
  memcpy(pack->message, message, len);

  // free(message);
  return 1;
}

int read_hello_packet(int fd, struct hello_packet *pack) {
  int rv;
  char username[USERNAME_LEN + 1];
  // uint32_t len;

  // read username field
  if ((rv = read_exact(fd, username, USERNAME_LEN)) <= 0) {
    return rv;
  }
  username[USERNAME_LEN] = '\0';

  // read public key length field
  // if ((rv = read_exact(fd, &len, 4)) <= 0) {
  //   return rv;
  // }
  // len = ntohl(len);
  // if (len > crypto_kx_PUBLICKEYBYTES) {
  //   return -1;
  // }
  unsigned char *public_key = malloc(crypto_kx_PUBLICKEYBYTES);

  // read public key field
  if ((rv = read_exact(fd, public_key, crypto_kx_PUBLICKEYBYTES)) <= 0) {
    return rv;
  }

  pack->type = PACKET_HELLO;
  strncpy(pack->username, username, USERNAME_LEN + 1);
  // pack->public_key_len = len;
  memcpy(pack->public_key, public_key, crypto_kx_PUBLICKEYBYTES);
  
  free(public_key);
  return 1;
}

int read_goodbye_packet(int fd, struct goodbye_packet *pack) {
  int rv;
  char username[USERNAME_LEN + 1];

  // read username field
  if ((rv = read_exact(fd, username, USERNAME_LEN)) <= 0) {
    return rv;
  }
  username[USERNAME_LEN] = '\0';

  pack->type = PACKET_GOODBYE;
  strncpy(pack->username, username, USERNAME_LEN + 1);
  return 1;
}

int read_packet_type(int fd) {
  uint32_t type;
  int rv;

  if ((rv = read_exact(fd, &type, 4)) <= 0) {
    return rv;
  }

  type = ntohl(type);
  return type;
}


// Read exact number of bytes into buffer
int read_exact(int fd, void *buffer, int len) {
  int bytes;
  int total = 0;
  while (total < len) {
    if ((bytes = recv(fd, (char *)buffer + total, len - total, 0)) <= 0) {
      if (bytes == 0) {
        return 0;
      } 
      return -1;
    }
    total += bytes;
  }
  return 1;
}