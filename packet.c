#include "protocol.h"

int read_exact(int fd, void *buffer, int len);
int send_message_packet(int fd, struct message_packet *pack);
int send_hello_packet(int fd, struct client_hello_packet *pack);
int read_message_packet(int fd, struct message_packet *pack);
int read_hello_packet(int fd, struct client_hello_packet *pack);

int send_packet(int fd, uint32_t type, void *pack) {
  if (type == PACKET_MESSAGE) {
    return send_message_packet(fd, (struct message_packet *)pack);
  } else if (type == PACKET_CLIENT_HELLO) {
    return send_hello_packet(fd, (struct client_hello_packet *)pack);
  }
  return -1;
}

int send_message_packet(int fd, struct message_packet *pack) {
  if (pack->len > MAX_DATA_SIZE) {
    return -1;
  }

  uint32_t packet_size = 8 + USERNAME_LEN + pack->len;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  memcpy(buffer, &packet_type, 4);
  uint32_t packet_len = htonl(pack->len); // should be 16 + data len
  memcpy(buffer + 4, &packet_len, 4);
  memcpy(buffer + 8, pack->username, USERNAME_LEN);
  memcpy(buffer + 8 + USERNAME_LEN, pack->data, pack->len);

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

int send_hello_packet(int fd, struct client_hello_packet *pack) {
  uint32_t packet_size = 4 + USERNAME_LEN + PUBLIC_KEY_LEN;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  memcpy(buffer, &packet_type, 4);

  memcpy(buffer + 4, pack->username, USERNAME_LEN);
  memcpy(buffer + 4 + USERNAME_LEN, pack->public_key, PUBLIC_KEY_LEN);

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
  } else if (expected_type == PACKET_CLIENT_HELLO) {
    return read_hello_packet(fd, (struct client_hello_packet *)pack);
  }
  return -1;
}

int read_message_packet(int fd, struct message_packet *pack) {
  int rv;
  uint32_t len; 
  char username[USERNAME_LEN + 1];

  // read length field
  if ((rv = read_exact(fd, &len, 4)) <= 0) {
    return rv;
  }

  // read username field
  if ((rv = read_exact(fd, username, USERNAME_LEN)) <= 0) {
    return rv;
  }
  username[USERNAME_LEN] = '\0';

  len = ntohl(len);

  if (len > MAX_DATA_SIZE) {
    return -1;
  }
  char *data = malloc(len + 1);

  // read data field
  if ((rv = read_exact(fd, data, len)) <= 0) {
    return rv;
  }
  data[len] = '\0';

  pack->type = PACKET_MESSAGE;
  pack->len = len;
  strncpy(pack->username, username, USERNAME_LEN + 1);
  strncpy(pack->data, data, len + 1);

  free(data);
  return 1;
}

int read_hello_packet(int fd, struct client_hello_packet *pack) {
  int rv;
  char username[USERNAME_LEN + 1];
  unsigned char public_key[PUBLIC_KEY_LEN];

  // read username field
  if ((rv = read_exact(fd, username, USERNAME_LEN)) <= 0) {
    return rv;
  }
  username[USERNAME_LEN] = '\0';

  // read public key field
  if ((rv = read_exact(fd, public_key, PUBLIC_KEY_LEN)) <= 0) {
    return rv;
  }

  pack->type = PACKET_CLIENT_HELLO;
  strncpy(pack->username, username, USERNAME_LEN + 1);
  memcpy(pack->public_key, public_key, PUBLIC_KEY_LEN);

  return 1;
}


int read_packet_type(int fd) {
  int type, rv;

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