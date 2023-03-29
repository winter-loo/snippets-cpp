#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <iostream>

#define MAX_EVENTS 10
#define SERVER_PORT 1500
#define SERVER_ADDR "127.0.0.1"

int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        std::cerr << "Error creating socket\n";
        return 1;
    }

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDR, &serv_addr.sin_addr);


    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        if (errno != EINPROGRESS) {
          std::cerr << "Error connecting to server\n";
          return 1;
        }
    }
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        std::cerr << "Error creating epoll instance\n";
        return 1;
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
    ev.data.fd = sockfd;

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sockfd, &ev) < 0) {
        std::cerr << "Error adding socket to epoll instance\n";
        return 1;
    }

    while (true) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (nfds < 0) {
            std::cerr << "Error in epoll_wait\n";
            return 1;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLERR || events[i].events & EPOLLHUP) {
                std::cerr << "Error on socket " << events[i].data.fd << "\n";
                close(events[i].data.fd);
                continue;
            }

            if (events[i].events & EPOLLOUT) {
                std::cout << "Connection established\n";
                close(events[i].data.fd);
                return 0;
            }
        }
    }
}

