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

#include <chrono>
#include <thread>

#define PORT 8888
#define MAX_EVENTS 1024
#define BUF_SIZE 256

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

int main(int argc, char *argv[]) {
  int listen_fd, conn_fd, epoll_fd, nfds, i;
  struct epoll_event ev, events[MAX_EVENTS];
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);
  char buf[BUF_SIZE];

  // 创建监听 socket
  if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket error");
    exit(1);
  }

  // 绑定地址
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(PORT);
  if (bind(listen_fd, (struct sockaddr *)&addr, addr_len) < 0) {
    perror("bind error");
    exit(1);
  }

  // 开始监听
  if (listen(listen_fd, SOMAXCONN) < 0) {
    perror("listen error");
    exit(1);
  }

  // 创建 epoll 实例
  if ((epoll_fd = epoll_create1(0)) < 0) {
    perror("epoll_create1 error");
    exit(1);
  }

  // 将监听 socket 加入 epoll 实例中
  ev.events = EPOLLIN;
  ev.data.fd = listen_fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
    perror("epoll_ctl error");
    exit(1);
  }

  // 等待连接
  while (1) {
    nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    if (nfds < 0) {
      perror("epoll_wait error");
      exit(1);
    }

    for (i = 0; i < nfds; i++) {
      if (events[i].data.fd == listen_fd) {
        // 处理连接请求
        conn_fd = accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
        if (conn_fd < 0) {
          perror("accept error");
          exit(1);
        }

        // 将新连接的 socket 加入 epoll 实例中
        // use non default trigger mode: edge trigger
        // this mode requires non-block fd
        set_nonblocking(conn_fd);
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = conn_fd;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0) {
          perror("epoll_ctl error");
          exit(1);
        }

        printf("new client connected, fd=%d, address=%s:%d\n", conn_fd,
               inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
      } else {
        printf("wake up from epoll_wait for fd:%d\n", conn_fd);
        // 处理已连接的 socket 数据
        conn_fd = events[i].data.fd;
        memset(buf, 0, sizeof(buf));
        int total = 0;
        while (1) {
          int n = read(conn_fd, buf, sizeof(buf));
          if (n < 0) {
            if (errno == ECONNRESET) {
              // 连接被重置，关闭连接
              printf("client fd=%d reset the connection\n", conn_fd);
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
              printf("%d bytes consumed from fd:%d\n", total, conn_fd);
              break;
            } else {
              perror("read error");
            }
            close(conn_fd);
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn_fd, NULL);
            break;
          } else if (n == 0) {
            // 连接被关闭
            printf("client fd=%d closed the connection\n", conn_fd);
            close(conn_fd);
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, conn_fd, NULL);
            break;
          }

          total += n;
          // 处理接收到的数据
          // printf("received %d bytes data from client fd=%d: %s\n", n,
          // conn_fd, buf);
          printf("%d:%d...", conn_fd, total);
          fflush(stdout);
          std::this_thread::sleep_for(500ms);
          // echo back
          write(conn_fd, buf, n);
        }  // while (1)
      }
    }
  }

  return 0;
}
