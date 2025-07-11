#include "protocol.h"

int read_exact(int fd, void *buffer, int len);
int send_message_packet(int fd, struct message_packet *pack);
int send_hello_packet(int fd, struct hello_packet *pack);
int send_goodbye_packet(int fd, struct goodbye_packet *pack);
int send_serv_info_packet(int fd, struct serv_info_packet *pack);
int read_message_packet(int fd, struct message_packet *pack);
int read_hello_packet(int fd, struct hello_packet *pack);
int read_goodbye_packet(int fd, struct goodbye_packet *pack);
int read_serv_info_packet(int fd, struct serv_info_packet *pack);
int send_all(int fd, char *buffer, uint32_t packet_size);

// Send packet to socket with file descriptor fd
// Put packet type in type
// Packet info should already be stored in *pack
// *pack should type-cast to the correct format for the packet type (e.g. PACKET_MESSAGE should cast to struct message_packet)
// Returns 1 if successful, -1 if error
int send_packet(int fd, uint32_t type, void *pack) {
  if (type == PACKET_MESSAGE) {
    return send_message_packet(fd, (struct message_packet *)pack);
  } else if (type == PACKET_HELLO) {
    return send_hello_packet(fd, (struct hello_packet *)pack);
  } else if (type == PACKET_GOODBYE) {
    return send_goodbye_packet(fd, (struct goodbye_packet *)pack);
  } else if (type == PACKET_SERV_INFO) {
    return send_serv_info_packet(fd, (struct serv_info_packet *)pack);
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

  return send_all(fd, buffer, packet_size);
}

int send_hello_packet(int fd, struct hello_packet *pack) {
  uint32_t packet_size = 8 + USERNAME_LEN + crypto_kx_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  uint32_t user_status = htonl(pack->user_status);

  memcpy(buffer, &packet_type, 4);
  memcpy(buffer + 4, &user_status, 4);
  memcpy(buffer + 8, pack->username, USERNAME_LEN);
  memcpy(buffer + 8 + USERNAME_LEN, pack->public_key, crypto_kx_PUBLICKEYBYTES);
  memcpy(buffer + 8 + USERNAME_LEN + crypto_kx_PUBLICKEYBYTES, pack->id_public_key, crypto_sign_PUBLICKEYBYTES);
  memcpy(buffer + 8 + USERNAME_LEN + crypto_kx_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES, pack->signature, crypto_sign_BYTES);

  return send_all(fd, buffer, packet_size);
}

int send_goodbye_packet(int fd, struct goodbye_packet *pack) {
  uint32_t packet_size = 4 + USERNAME_LEN;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  memcpy(buffer, &packet_type, 4);

  memcpy(buffer + 4, pack->username, USERNAME_LEN);

  return send_all(fd, buffer, packet_size);
}

int send_serv_info_packet(int fd, struct serv_info_packet *pack) {
  uint32_t packet_size = 8;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  memcpy(buffer, &packet_type, 4);

  uint32_t num_users = htonl(pack->num_users);
  memcpy(buffer + 4, &num_users, 4);

  return send_all(fd, buffer, packet_size);
}

// repeat send() calls until all of packet is sent
int send_all(int fd, char *buffer, uint32_t packet_size) {
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

  return 1;
}

// Read packet from socket with file descriptor fd
// Put expected packet type in type 
// Packet info will be placed in *pack
// *pack should type-cast to the correct format for the packet type (e.g. PACKET_MESSAGE should cast to struct message_packet)
// Returns 1 if successful, 0 or -1 if error
int read_packet(int fd, uint32_t expected_type, void *pack) {
  if (expected_type == PACKET_MESSAGE) {
    return read_message_packet(fd, (struct message_packet *)pack);
  } else if (expected_type == PACKET_HELLO) {
    return read_hello_packet(fd, (struct hello_packet *)pack);
  } else if (expected_type == PACKET_GOODBYE) {
    return read_goodbye_packet(fd, (struct goodbye_packet *)pack);
  } else if (expected_type == PACKET_SERV_INFO) {
    return read_serv_info_packet(fd, (struct serv_info_packet *)pack);
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

  unsigned char message[len];

  // read data field
  if ((rv = read_exact(fd, message, len)) <= 0) {
    return rv;
  }

  pack->type = PACKET_MESSAGE;
  strncpy(pack->sender, sender, USERNAME_LEN + 1);
  strncpy(pack->receiptient, receiptient, USERNAME_LEN + 1);
  memcpy(pack->nonce, nonce, sizeof nonce);
  pack->len = len;
  memcpy(pack->message, message, len);

  return 1;
}

int read_hello_packet(int fd, struct hello_packet *pack) {
  int rv;
  char username[USERNAME_LEN + 1];

  // Read user type field
  uint32_t user_status;
  if ((rv = read_exact(fd, &user_status, 4)) <= 0) {
    return rv;
  }
  user_status = ntohl(user_status);

  // read username field
  if ((rv = read_exact(fd, username, USERNAME_LEN)) <= 0) {
    return rv;
  }
  username[USERNAME_LEN] = '\0';

  unsigned char *public_key = malloc(crypto_kx_PUBLICKEYBYTES);
  unsigned char *id_public_key = malloc(crypto_sign_PUBLICKEYBYTES);
  unsigned char *signature = malloc(crypto_sign_BYTES);

  // read public key field
  if ((rv = read_exact(fd, public_key, crypto_kx_PUBLICKEYBYTES)) <= 0) {
    return rv;
  }

  // read ID public key field
  if ((rv = read_exact(fd, id_public_key, crypto_sign_PUBLICKEYBYTES)) <= 0) {
    return rv;
  }

  // read signature field
  if ((rv = read_exact(fd, signature, crypto_sign_BYTES)) <= 0) {
    return rv;
  }

  pack->type = PACKET_HELLO;
  pack->user_status = user_status;
  strncpy(pack->username, username, USERNAME_LEN + 1);
  memcpy(pack->public_key, public_key, crypto_kx_PUBLICKEYBYTES);
  memcpy(pack->id_public_key, id_public_key, crypto_sign_PUBLICKEYBYTES);
  memcpy(pack->signature, signature, crypto_sign_BYTES); // HEAP OVERFLOW
  
  free(public_key);
  free(id_public_key);
  free(signature);

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

int read_serv_info_packet(int fd, struct serv_info_packet *pack) {
  int rv;

  uint32_t num_users;
  if ((rv = read_exact(fd, &num_users, 4)) <= 0) {
    printf("read exact error\n");
    return rv;
  }
  num_users = ntohl(num_users);

  pack->type = PACKET_SERV_INFO;
  pack->num_users = num_users;
  return 1;
}

// Reads and returns packet type (first 4 bytes of packet). If error, returns 0 or -1
int read_packet_type(int fd) {
  uint32_t type;
  int rv;

  if ((rv = read_exact(fd, &type, 4)) <= 0) {
    return rv;
  }

  type = ntohl(type);
  return type;
}

// Read exact number of bytes, specified by len, into *buffer
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