#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

const int BUF_SIZE = 256;
const int PORT = 8888;
const char* LOCAL_SERVER_ADDR = "127.0.0.1";
const char* COOL_SERVER_ADDR = "43.134.233.232";

using namespace std;

int main(int argc, char* argv[]) {
  int local_server = 0;
  if (argc == 2) {
    local_server = 1;
  }

  int client_socket = socket(AF_INET, SOCK_DGRAM, 0);
  if (client_socket == -1) {
    perror("Error creating socket");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr =
      inet_addr(local_server ? LOCAL_SERVER_ADDR : COOL_SERVER_ADDR);
  server_addr.sin_port = htons(PORT);

  char buf[BUF_SIZE] = {"testing"};

  ssize_t sent = sendto(client_socket, buf, strlen(buf), 0,
                        (struct sockaddr*)&server_addr, sizeof(server_addr));
  if (sent == -1) {
    perror("Error sending data");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in received_addr;
  socklen_t received_addr_len = sizeof(received_addr);

  std::cout << "waiting response..." << std::endl;

  ssize_t received =
      recvfrom(client_socket, buf, BUF_SIZE, 0,
               (struct sockaddr*)&received_addr, &received_addr_len);
  if (received == -1) {
    perror("Error receiving data");
    exit(EXIT_FAILURE);
  }

  buf[received] = '\0';
  printf("Received data from server: %s\n", buf);

  close(client_socket);

  return 0;
}
