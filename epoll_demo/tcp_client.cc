// g++ tcp_client.cc -pthread
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
const char* SERVER_ADDR = "127.0.0.1";

using namespace std::chrono_literals;

std::atomic<bool> stopSending(false);

void sendThread(int sockfd) {
  char buffer[BUFFER_SIZE];
  srand(time(NULL));
  unsigned long total = 0;
  while (!stopSending) {
    // Generate random data to send
    for (int i = 0; i < BUFFER_SIZE; i++) {
      buffer[i] = 'a' + rand() % 26;
    }

    // Send data to server
    ssize_t bytes_sent = send(sockfd, buffer, BUFFER_SIZE, 0);
    if (bytes_sent == -1) {
      std::cerr << "Error sending data: " << strerror(errno) << std::endl;
      break;
    }
    total += bytes_sent;
    std::cout << total << std::endl;
    std::this_thread::sleep_for(100ms);
  }
  close(sockfd);
}

void recvThread(int sockfd) {
  char buffer[BUFFER_SIZE];
  while (true) {
    // Receive data from server
    ssize_t bytes_received = recv(sockfd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received == -1) {
      std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
      break;
    } else if (bytes_received == 0) {
      std::cout << "Server disconnected." << std::endl;
      break;
    }

    // Print received data
    buffer[bytes_received] = '\0';
    // std::cout << "Received data: " << buffer << std::endl;
  }
  close(sockfd);
}

int main(int argc, char* argv[]) {
  // Parse command line arguments
  const char* server_addr = argc > 1 ? argv[1] : SERVER_ADDR;
  int port = argc > 2 ? std::stoi(argv[2]) : PORT;

  // Create socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    std::cerr << "Error creating socket: " << strerror(errno) << std::endl;
    return 1;
  }

  // Connect to server
  struct sockaddr_in server_addr_struct;
  server_addr_struct.sin_family = AF_INET;
  server_addr_struct.sin_addr.s_addr = inet_addr(server_addr);
  server_addr_struct.sin_port = htons(port);
  if (connect(sockfd, (struct sockaddr*)&server_addr_struct,
              sizeof(server_addr_struct)) == -1) {
    std::cerr << "Error connecting to server: " << strerror(errno) << std::endl;
    return 1;
  }

  // Start sender and receiver threads
  std::thread sender(sendThread, sockfd);
  // std::thread receiver(recvThread, sockfd);

  char ch;
  std::cin >> ch;
  if (ch == 'q') {
    stopSending = true;
  }

  // Wait for threads to finish
  sender.join();
  // receiver.join();

  return 0;
}
