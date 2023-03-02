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
#include <condition_variable>
#include <iostream>
#include <list>
#include <mutex>
#include <thread>
#include <unordered_map>

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

int g_epoll_fd;

void AcceptThread(int listen_fd) {
  int epoll_fd;
  struct epoll_event ev;
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

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

  while (1) {
    if (epoll_wait(epoll_fd, &ev, 1, -1) == -1) {
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }

    int conn_fd = accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
    if (conn_fd < 0) {
      perror("accept error");
      break;
    }

    // 将新连接的 socket 加入 epoll 实例中
    // use non default trigger mode: edge trigger
    // this mode requires non-block fd
    set_nonblocking(conn_fd);
    ev.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    ev.data.fd = conn_fd;
    if (epoll_ctl(g_epoll_fd, EPOLL_CTL_ADD, conn_fd, &ev) < 0) {
      perror("epoll_ctl error");
      exit(1);
    }

    printf("new client connected, fd=%d, address=%s:%d\n", conn_fd,
           inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
  }
}

class ThreadSafeReadyList {
 public:
  void Add(int id) {
    std::lock_guard<std::mutex> lock(mu_);
    ready_fds_.push_back(id);
    cv_.notify_one();
  }

  int Take() {
    std::lock_guard<std::mutex> lock(mu_);
    int fd = ready_fds_.front();
    ready_fds_.pop_front();
    return fd;
  }

  void Wait() {
    std::unique_lock<std::mutex> lk(mu_);
    // wait until queue is not empty
    cv_.wait(lk, [&] { return !ready_fds_.empty(); });
  }

 private:
  std::mutex mu_;
  std::condition_variable cv_;
  std::list<int> ready_fds_;
};

ThreadSafeReadyList g_queue;

void IoThread() {
  char buf[BUF_SIZE];

  while (1) {
    g_queue.Wait();

    int conn_fd = g_queue.Take();
    memset(buf, 0, sizeof(buf));
    int n = read(conn_fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == ECONNRESET) {
        // 连接被重置，关闭连接
        printf("\nclient fd=%d reset the connection\n", conn_fd);
      } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
        printf("\n%d bytes consumed from fd:%d\n", n, conn_fd);
        continue;
      } else {
        perror("read error");
      }
      close(conn_fd);
      epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, conn_fd, NULL);
      continue;
    } else if (n == 0) {
      // 连接被关闭
      printf("\nclient fd=%d closed the connection\n", conn_fd);
      close(conn_fd);
      epoll_ctl(g_epoll_fd, EPOLL_CTL_DEL, conn_fd, NULL);
      continue;
    }

    // 处理接收到的数据
    // clang-format off
    // printf("received %d bytes data from client fd=%d: %s\n", n, conn_fd, buf);
    // clang-format on
    printf("%d:%d...", conn_fd, n);
    fflush(stdout);
    std::this_thread::sleep_for(250ms);
    // echo back
    // write(conn_fd, buf, n);
    g_queue.Add(conn_fd);
  }
}

void IoNotificationThread() {
  struct epoll_event events[MAX_EVENTS];
  int nfds;
  // 等待连接
  while (1) {
    nfds = epoll_wait(g_epoll_fd, events, MAX_EVENTS, -1);
    if (nfds < 0) {
      perror("epoll_wait error");
      exit(1);
    }
    std::cout << "wake up from epoll wait...." << std::endl;

    for (int i = 0; i < nfds; i++) {
      g_queue.Add(events[i].data.fd);
    }
  }
}

int main(int argc, char *argv[]) {
  int listen_fd;
  struct sockaddr_in addr;
  socklen_t addr_len = sizeof(addr);

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
  if ((g_epoll_fd = epoll_create1(0)) < 0) {
    perror("epoll_create1 error");
    exit(1);
  }

  std::thread acceptor(AcceptThread, listen_fd);
  std::thread notifier(IoNotificationThread);
  std::thread worker(IoThread);

  acceptor.join();
  notifier.join();
  worker.join();

  return 0;
}
