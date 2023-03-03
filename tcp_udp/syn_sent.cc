#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <thread>

const int BUFFER_SIZE = 1024;
const int PORT = 8888;
const char* SERVER_ADDR = "43.134.233.232";
// const char* SERVER_ADDR = "127.0.0.1";

using namespace std::chrono_literals;

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

  // force conection close with RST flag
  //  struct linger sl;
  //  sl.l_onoff = 1;
  //  sl.l_linger = 0;
  //  setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

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
    std::this_thread::sleep_for(1000ms);
  }
  return 0;
}
