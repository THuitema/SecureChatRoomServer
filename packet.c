#include "protocol.h"

int read_exact(int fd, void *buffer, int len);

int send_packet(int fd, struct packet *pack) {
  // add user ip field to packet?
  if (pack->len > MAX_DATA_SIZE) {
    return -1;
  }

  uint32_t packet_size = 8 + pack->len;
  char *buffer = malloc(packet_size);

  // write header, converting info to network byte order
  uint32_t packet_type = htonl(pack->type);
  uint32_t packet_len = htonl(pack->len);
  memcpy(buffer, &packet_type, 4);
  memcpy(buffer + 4, &packet_len, 4);
  memcpy(buffer + 8, pack->data, pack->len);

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
    printf("sent %d bytes\n", n);
  }

  free(buffer);

  return 1;
}

int read_packet(int fd, struct packet *pack) {
  int rv;

  uint32_t type, len;
  if (read_exact(fd, &type, 4) == -1) {
    return -1;
  }
  if (read_exact(fd, &len, 4) == -1) {
    return -1;
  }

  type = ntohl(type);
  len = ntohl(len);

  if (len > MAX_DATA_SIZE) {
    return -1;
  }
  char *data = malloc(len + 1);

  if ((rv = read_exact(fd, data, len)) <= 0) {
    return rv;
  }
  data[len] = '\0'; // to make it a string

  pack->type = type;
  pack->len = len;
  strncpy(pack->data, data, len + 1);

  free(data);

  return 1;
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