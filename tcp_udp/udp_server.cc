#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#define BUF_SIZE 256

using namespace std;

const int PORT = 8888;

int main(int argc, char* argv[]) {
  int server_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (server_socket == -1) {
    perror("Error creating socket");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(PORT);

  if (bind(server_socket, (struct sockaddr*)&server_addr,
           sizeof(server_addr)) == -1) {
    perror("Error binding socket");
    exit(EXIT_FAILURE);
  }

  char buf[BUF_SIZE];
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  while (true) {
    ssize_t received =
        recvfrom(server_socket, buf, BUF_SIZE, 0,
                 (struct sockaddr*)&client_addr, &client_addr_len);
    if (received == -1) {
      perror("Error receiving data");
      exit(EXIT_FAILURE);
    }

    buf[received] = '\0';
    printf("Received data from client: %s\n", buf);

    ssize_t sent = sendto(server_socket, buf, received, 0,
                          (struct sockaddr*)&client_addr, client_addr_len);
    if (sent == -1) {
      perror("Error sending data");
      exit(EXIT_FAILURE);
    }
  }

  close(server_socket);

  return 0;
}
