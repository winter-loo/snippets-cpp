#include <arpa/inet.h>
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

const int BUFFER_SIZE = 1024;
const int PORT = 8888;
const char* SERVER_ADDR = "43.134.233.232";
// const char* SERVER_ADDR = "127.0.0.1";
const int MAX_EVENTS = 1024;

int g_epoll_fd;

using namespace std::chrono_literals;

int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl F_GETFL");
    return -1;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    perror("fcntl F_SETFL O_NONBLOCK");
    return -1;
  }
  return 0;
}

int g_bytes_recv = 0;
int g_bytes_sent = 0;
std::chrono::time_point<std::chrono::high_resolution_clock> g_start_time,
    g_end_time;
const int g_packet_count = 100;

void ReadFrom(int fd) {
  char buffer[BUFFER_SIZE + 1];
  std::cout << "readable..." << std::endl;
  // Receive data from server
  ssize_t bytes_received = recv(fd, buffer, BUFFER_SIZE, 0);
  if (bytes_received == -1) {
    std::cerr << "Error receiving data: " << strerror(errno) << std::endl;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      std::cout << "---------consumed all---------" << std::endl;
      return;
    } else if (errno == ECONNRESET) {
      // 连接被重置，关闭连接
      printf("client fd=%d reset the connection\n", fd);
    } else {
      perror("recv error");
    }
    close(fd);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    return;
  } else if (bytes_received == 0) {
    std::cout << "Server disconnected." << std::endl;
    close(fd);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    return;
  }

  g_bytes_recv += bytes_received;

  // Print received data
  // buffer[bytes_received] = '\0';
  // std::cout << "Received data: " << buffer << std::endl;
  std::cout << "...." << bytes_received << "/" << g_bytes_recv
            << " bytes received" << std::endl;
  if (g_bytes_recv == g_bytes_sent) {
    close(fd);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);

    g_end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> time_cost = g_end_time - g_start_time;
    std::cout << "send/recv " << g_packet_count << " packets takes "
              << time_cost.count() << " s" << std::endl;
    exit(0);
  }
}

void WriteTo(int fd) {
  char buffer[BUFFER_SIZE];
  std::cout << "writable...." << std::endl;
  // std::cout << "press any key to continue...." << std::endl;
  // std::cin.get();

  // Send data to server
  // Generate random data to send
  for (int i = 0; i < BUFFER_SIZE; i++) {
    buffer[i] = 'a' + rand() % 26;
  }
  ssize_t bytes_sent = send(fd, buffer, BUFFER_SIZE, 0);
  if (bytes_sent == -1) {
    std::cerr << "Error sending data: " << strerror(errno) << std::endl;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      std::cout << "---------not writable, send buffer full---------"
                << std::endl;
      return;
    } else if (errno == ECONNRESET) {
      // 连接被重置，关闭连接
      printf("client fd=%d reset the connection\n", fd);
    } else {
      perror("send error");
    }
    close(fd);
    epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    return;
  }
  g_bytes_sent += bytes_sent;
  std::cout << "...." << bytes_sent << "/" << g_bytes_sent << " bytes sent"
            << std::endl;
  if (g_bytes_sent >= BUFFER_SIZE * g_packet_count) {
    std::cout << "...send done!..." << std::endl;
    struct epoll_event ev;
    ev.data.fd = fd;
    ev.events = EPOLLIN;
    epoll_ctl(g_epoll_fd, EPOLL_CTL_MOD, fd, &ev);
  }
  // std::this_thread::sleep_for(500ms);
}

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
  set_nonblocking(sockfd);

  while (true) {
    // Connect to server
    struct sockaddr_in server_addr_struct;
    server_addr_struct.sin_family = AF_INET;
    server_addr_struct.sin_addr.s_addr = inet_addr(server_addr);
    server_addr_struct.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr*)&server_addr_struct,
                sizeof(server_addr_struct)) == -1) {
      if (errno == EINPROGRESS) {
        std::cerr << "Info connecting to server: " << strerror(errno)
                  << std::endl;
      } else {
        std::cerr << "Error connecting to server: " << strerror(errno)
                  << std::endl;
      }
      std::this_thread::sleep_for(1000ms);
      continue;
    }
    std::cout << "success" << std::endl;
    break;
  }

  struct epoll_event ev, events[MAX_EVENTS];
  int epoll_fd;
  // 创建 epoll 实例
  if ((g_epoll_fd = epoll_create1(0)) < 0) {
    perror("epoll_create1 error");
    exit(1);
  }
  // 将 socket 加入 epoll 实例中
  ev.events = EPOLLIN | EPOLLOUT;
  ev.data.fd = sockfd;
  if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
    perror("epoll_ctl error");
    exit(1);
  }

  char buffer[BUFFER_SIZE + 1];
  srand(time(NULL));

  g_start_time = std::chrono::high_resolution_clock::now();
  while (true) {
    int nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, -1);
    if (nfds < 0) {
      perror("epoll_wait error");
      exit(1);
    }
    std::cout << ".....epoll_wait wake up...." << std::endl;

    for (int i = 0; i < nfds; i++) {
      int flags = events[i].events;
      int fd = events[i].data.fd;

      if (flags & EPOLLIN) {  // readable
        ReadFrom(fd);
      }
      if (flags & EPOLLOUT) {
        WriteTo(fd);
      }
      
      if (flags & EPOLLIN ==  0 || flags & EPOLLOUT ==  0) {
        std::cout << "unnecessary wake up" << std::endl;
      }
    }
  }
  return 0;
}
