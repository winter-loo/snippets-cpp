#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

#define MAX_EVENTS 10

int epoll_fd;

void* thread_func(void* arg) {
  struct epoll_event events[MAX_EVENTS];
  char buf[1024] = {0};
  while (1) {
    int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    if (num_events == -1) {
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }
    printf("Thread %ld: Received %d events.\n", (long)arg, num_events);
    // Handle events here
    for (int i = 0; i < num_events; i++) {
      int fd = events[i].data.fd;
      read(fd, buf, sizeof(buf));
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

  // Add file descriptors to epoll set
  struct epoll_event event;
  // level trigger by default
  event.events = EPOLLIN;
  event.data.fd = STDIN_FILENO;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &event) == -1) {
    perror("epoll_ctl");
    exit(EXIT_FAILURE);
  }

  event.data.fd = STDOUT_FILENO;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDOUT_FILENO, &event) == -1) {
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
