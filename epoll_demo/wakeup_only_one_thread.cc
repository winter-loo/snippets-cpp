#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

#define MAX_EVENTS 10

int epoll_fd;

void* thread_func(void* arg) {
  char buf[1024] = {0};
  struct epoll_event event;
  while (1) {
    if (epoll_wait(epoll_fd, &event, 1, -1) == -1) {
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }
    printf("Thread %ld: Received event.\n", (long)arg);
    // Handle event here
    read(event.data.fd, buf, sizeof(buf));

    event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, event.data.fd, &event) == -1) {
      perror("epoll_ctl");
      exit(EXIT_FAILURE);
    }
  }
  return NULL;
}

int main() {
  epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1");
    exit(EXIT_FAILURE);
  }

  pthread_t thread1, thread2;
  if (pthread_create(&thread1, NULL, thread_func, (void*)1) != 0 ||
      pthread_create(&thread2, NULL, thread_func, (void*)2) != 0) {
    perror("pthread_create");
    exit(EXIT_FAILURE);
  }

  // Add file descriptor to epoll set
  struct epoll_event event;
  // from man epoll:
  // >> Since even with edge-triggered epoll, multiple events can be
  //    generated upon receipt of multiple chunks of data, the caller has
  //    the option to specify the EPOLLONESHOT flag, to tell epoll to
  //    disable the associated file descriptor after the receipt of an
  //    event with epoll_wait(2).  When the EPOLLONESHOT flag is
  //    specified, it is the caller's responsibility to rearm the file
  //    descriptor using epoll_ctl(2) with EPOLL_CTL_MOD.
  event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
  event.data.fd = STDIN_FILENO;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &event) == -1) {
    perror("epoll_ctl");
    exit(EXIT_FAILURE);
  }

  // Wait for threads to finish
  if (pthread_join(thread1, NULL) != 0 || pthread_join(thread2, NULL) != 0) {
    perror("pthread_join");
    exit(EXIT_FAILURE);
  }

  return 0;
}
