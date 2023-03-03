#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <thread>

const int BUFFER_SIZE = 256;
const int PORT = 8888;
const char* SERVER_ADDR = "43.134.233.232";
// const char* SERVER_ADDR = "127.0.0.1";

using namespace std::chrono_literals;

using Clock = std::chrono::time_point<std::chrono::high_resolution_clock>;
using Duration = std::chrono::duration<double>;
Clock g_start_time;
Clock g_end_time;

int main(int argc, char** argv) {
  // Parse command line arguments
  const char* server_addr = argc > 1 ? argv[1] : SERVER_ADDR;
  int port = argc > 2 ? std::stoi(argv[2]) : PORT;

  // Create socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    std::cerr << "Error creating socket: " << strerror(errno) << std::endl;
    return 1;
  }

  while (true) {
    // Connect to server
    struct sockaddr_in server_addr_struct;
    server_addr_struct.sin_family = AF_INET;
    server_addr_struct.sin_addr.s_addr = inet_addr(server_addr);
    server_addr_struct.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr*)&server_addr_struct,
                sizeof(server_addr_struct)) == -1) {
      std::cerr << "Error connecting to server: " << strerror(errno)
                << std::endl;
      std::this_thread::sleep_for(1000ms);
      continue;
    }
    std::cout << "success" << std::endl;
    break;
  }

  char buffer[BUFFER_SIZE + 1];
  // Send data to server
  // Generate random data to send
  for (int i = 0; i < BUFFER_SIZE; i++) {
    buffer[i] = 'a' + rand() % 26;
  }
  g_start_time = std::chrono::high_resolution_clock::now();
  ssize_t bytes_sent = send(sockfd, buffer, BUFFER_SIZE, 0);
  if (bytes_sent == -1) {
    perror("send error");
    return 1;
  }

  ssize_t bytes_received = recv(sockfd, buffer, BUFFER_SIZE, 0);
  if (bytes_received == -1) {
    perror("recv error");
    return 2;
  }
  assert(bytes_sent == bytes_received);
  g_end_time = std::chrono::high_resolution_clock::now();
  Duration d = g_end_time - g_start_time;
  std::cout << d.count() << " s" << std::endl;

  close(sockfd);
  return 0;
}
