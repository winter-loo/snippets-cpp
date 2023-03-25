#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <list>
#include <thread>
#include <unordered_map>
#include <vector>

static int SetNonblocking(int fd) {
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

class DnsResolver {
 public:
  bool Resolve(const std::string& hostname) {
    struct addrinfo hints, *result, *rp;

    // Set up hints structure for getaddrinfo()
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Stream socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0; /* Any protocol */

    // Perform DNS lookup using getaddrinfo()
    int s = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (s != 0) {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
      return false;
    }

    // Iterate through the list of IP addresses returned by getaddrinfo()
    for (rp = result; rp != NULL; rp = rp->ai_next) {
      if (rp->ai_family != AF_INET) continue;          // Only need IPv4 address
      if ((rp->ai_flags & AI_PASSIVE) != 0) continue;  // Skip wildcard address
      auto addr = ((struct sockaddr_in*)(rp->ai_addr))->sin_addr;
      if (addr.s_addr == 0) continue;  // Skip wildcard address
      addresses_.push_back(inet_ntoa(addr));
    }
    std::sort(addresses_.begin(), addresses_.end());

    freeaddrinfo(result);
    return true;
  }

  std::string NextAddress() {
    if (idx_in_use_ < addresses_.size()) {
      return addresses_[idx_in_use_++];
    }

    return {};
  }

  static void Test() {
    DnsResolver r;
    if (r.Resolve("www.google.com")) {
      std::string address = r.NextAddress();
      while (!address.empty()) {
        std::cout << address << std::endl;
        address = r.NextAddress();
      }
    }
  }

 private:
  std::vector<std::string> addresses_;
  size_t idx_in_use_{};
};

enum class EventSourceKind { Listening, Timer, Signal, IO };

class EventSourceId {
 public:
  EventSourceId() = default;
  EventSourceId(int i) : id_(i) {}

  bool operator==(EventSourceId other) const { return id_ == other.id_; }

  operator int() const { return id_; }

 private:
  uint32_t id_{};
};

namespace std {
template <>
struct hash<EventSourceId> {
  size_t operator()(const EventSourceId& id) const {
    return hash<uint32_t>()(id);
  }
};
}  // namespace std

enum class Event {
  Read = EPOLLIN,
  Write = EPOLLOUT,
};
class Eoi {
 public:
  Eoi() : e_(0) {}
  Eoi(Event e) { e_ = static_cast<uint32_t>(e); }
  Eoi(unsigned int e) : e_(e) {}
  operator uint32_t() const { return e_; }

 private:
  uint8_t e_;
};
Eoi operator|(Event a, Event b) { return Eoi(a) | Eoi(b); }

enum class EventStatusKind { NoMore, HasMore };

struct StatusHasMore {
  uint64_t n_rx;
  uint64_t n_tx;
};
struct StatusNoMore {};

union StatusDetail {
  StatusHasMore has_more;
  StatusNoMore no_more;
};

struct EventStatus {
  EventStatusKind kind;
  StatusDetail detail;
};

EventStatus CreateStatusHasMore(uint64_t n_rx = 0, uint64_t n_tx = 0) {
  return EventStatus{
    kind : EventStatusKind::HasMore,
    detail : StatusDetail{has_more : StatusHasMore{n_rx : n_rx, n_tx : n_tx}}
  };
}
EventStatus CreateStatusNoMore() {
  return EventStatus{
    kind: EventStatusKind::NoMore
  };
}

struct EventSource {
  EventSourceId id;
  // events of interested
  Eoi eoi;
  EventSourceKind kind;
  EventStatus (*read)(EventSourceId, void*);
  EventStatus (*write)(EventSourceId, void*);
  void* obj;

  EventSource(EventSourceId id) : id(id) {}
  bool operator==(const EventSource& other) const { return id == other.id; }
};

class EventSourceList {
 public:
  EventSourceList() = default;

  static EventSourceList& Global() {
    static EventSourceList g;
    return g;
  }

  ~EventSourceList() {
    while (!sources_.empty()) {
      auto p = sources_.back();
      delete p;
      sources_.pop_back();
    }
  }

  EventSource* CreateEventSource(EventSourceId id) {
    auto es = new EventSource(id);
    auto it = sources_.insert(sources_.end(), es);
    lut_.insert({id, it});
    return es;
  }

  void RemoveEventSource(const EventSource* es) {
    auto it = lut_.find(es->id);
    if (it != lut_.end()) {
      delete *it->second;
      sources_.erase(it->second);
    }
  }

 private:
  using EsList = std::list<EventSource*>;
  using LookupTable = std::unordered_map<EventSourceId, EsList::iterator>;
  EsList sources_;
  LookupTable lut_;
};

class EventCenter {
 public:
  bool Build() {
    if ((epoll_fd_ = epoll_create1(0)) < 0) {
      perror("epoll_create1 error");
      return false;
    }
    return true;
  }
  bool Add(EventSource* es) {
    struct epoll_event ev;
    ev.events = es->eoi;
    ev.data.ptr = es;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, es->id, &ev) < 0) {
      perror("epoll_ctl add error");
      return false;
    }
    return true;
  }
  bool Remove(EventSource* es) {
    if (-1 == epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, es->id, NULL)) {
      perror("epoll_ctl del error");
      return false;
    }
    return true;
  }

  void HandleEventStatus(const EventStatus& status, EventSource* es) {
    switch (status.kind) {
      case EventStatusKind::NoMore: {
        std::cout << "fd " << es->id << " no more data" << std::endl;
        Remove(es);
        close(es->id);
        EventSourceList::Global().RemoveEventSource(es);
        break;
      }
      case EventStatusKind::HasMore: {
        std::cout << "fd " << es->id << " has more" << std::endl;
        break;
      }
      default:
        break;
    }
  }

  bool Run() {
    pending_ = true;
    AddSignalForQuit();

    // TODO: how could I know how many events need be waited for
    constexpr const int kMaxEvents = 1024;
    struct epoll_event ev, events[kMaxEvents];
    int nfds;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    while (pending_) {
      std::cout << "epoll wait..." << std::endl;
      nfds = epoll_wait(epoll_fd_, events, kMaxEvents, -1);
      if (nfds < 0) {
        perror("epoll_wait error");
        return false;
      }
      std::cout << "kernel says " << nfds << " fd ready..." << std::endl;
      for (int i = 0; i < nfds; i++) {
        int flags = events[i].events;
        EventSource* es = static_cast<EventSource*>(events[i].data.ptr);
        int readable = flags & EPOLLIN;
        int writable = flags & EPOLLOUT;

        if (es->eoi & readable) {
          EventStatus s = es->read(es->id, es->obj);
          HandleEventStatus(s, es);
        }

        if (es->eoi & writable) {
          EventStatus s = es->write(es->id, es->obj);
          HandleEventStatus(s, es);
        }

        if (!readable && !writable) {
          std::cout << "unnecessary wake up" << std::endl;
        }
      }
    }

    return true;
  }

 private:
  void AddSignalForQuit() {
    sigset_t mask;
    int sfd;

    // Clear the signal set
    sigemptyset(&mask);

    // Add the signals that you want to handle to the signal set
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    // Block the signals in the signal set to avoid race conditions
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
      perror("sigprocmask");
      exit(1);
    }

    // Create a signal file descriptor
    sfd = signalfd(-1, &mask, 0);
    if (sfd == -1) {
      perror("signalfd");
      exit(1);
    }

    auto es = EventSourceList::Global().CreateEventSource(sfd);
    es->eoi = Event::Read;
    es->kind = EventSourceKind::Signal;
    es->read = EventCenter::QuitWrapper;
    es->obj = this;
    Add(es);
  }

  static EventStatus QuitWrapper(EventSourceId, void* obj) {
    static_cast<EventCenter*>(obj)->Quit();
    return EventStatus{kind : EventStatusKind::NoMore};
  }

  void Quit() {
    std::cout << "quit now" << std::endl;
    pending_ = false;
  }

 private:
  int epoll_fd_;
  bool pending_;
};

class Message {
 public:
  Message() {
    // greater than MSS
    buf_.resize(2048);
  }

  void Insert(const char* buf, size_t len) {
    buf_.assign(buf, buf + len);
    in_use_ = len;
  }

  void Append(const std::string& s) {}
  void Append(const char* buf, size_t len) {
    buf_.insert(buf_.end(), buf, buf + len);
    in_use_ += len;
  }

  const char* data() const { return buf_.data(); }

  char* data() { return buf_.data() + in_use_; }

  size_t size() const { return in_use_; }

  size_t available() const { return buf_.size() - in_use_; }

  size_t& in_use() { return in_use_; }

  void drain(std::string& s) {
    s.assign(data(), data() + in_use());
    in_use_ = 0;
  }


 private:
  size_t in_use_{};
  std::vector<char> buf_;
};

class TcpChannelId {
 public:
  TcpChannelId(EventSourceId id) : id_(id) {}
  TcpChannelId(int id) : id_(id) {}

  operator int() const { return id_; }

 private:
  uint32_t id_;
};

class TcpChannel {
 public:
  TcpChannel(TcpChannelId id) : id_(id) {}
  int Send() { return send(id_, msg_for_send_.data(), msg_for_send_.in_use(), 0); }

  int Recv() {
    ssize_t n = recv(id_, msg_for_recv_.data(), msg_for_recv_.available(), 0);
    if (n < 0) {
      perror("recv error");
    }
    msg_for_recv_.in_use() += n;
    std::cout << n << " bytes received" << std::endl;
    std::string out;
    msg_for_recv_.drain(out);
    std::cout << out << std::endl;

    msg_for_send_.Insert(msg_for_recv_.data(), msg_for_recv_.in_use());
    n = Send();
    std::cout << n << " bytes sent..." << std::endl;

    return n;
  }

  static EventStatus RecvWrapper(EventSourceId id, void* obj) {
    int n = static_cast<TcpChannel*>(obj)->Recv();
    return n <= 0 ? CreateStatusNoMore() : CreateStatusHasMore(n, 0);
  }

  static EventStatus SendWrapper(EventSourceId id, void* obj) {
    int n = static_cast<TcpChannel*>(obj)->Send();
    return CreateStatusHasMore(0, n);
  }

 private:
  Message msg_for_recv_;
  Message msg_for_send_;
  TcpChannelId id_;
};

class TcpServer {
 public:
  TcpServer(EventCenter* ec) : ec_(ec) {}

  bool Listen(int port, const std::string& address = "*") {
    int listen_fd, epoll_fd, conn_fd, nfds, i;
    struct epoll_event ev, events[1];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if ((listen_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      perror("socket error");
      return false;
    }

    int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        return false;
    }


    // 绑定地址
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr =
        (address == "*") ? htonl(INADDR_ANY) : inet_addr(address.c_str());
    addr.sin_port = htons(port);
    if (bind(listen_fd, (struct sockaddr*)&addr, addr_len) < 0) {
      perror("bind error");
      return false;
    }

    // 开始监听
    if (listen(listen_fd, SOMAXCONN) < 0) {
      perror("listen error");
      return false;
    }

    auto es = EventSourceList::Global().CreateEventSource(listen_fd);
    es->eoi = Event::Read;
    es->kind = EventSourceKind::Listening;
    es->read = TcpServer::AcceptWrapper;
    es->obj = this;
    ec_->Add(es);
    return true;
  }

  static EventStatus AcceptWrapper(EventSourceId id, void* obj) {
    static_cast<TcpServer*>(obj)->Accept(id);
    return CreateStatusHasMore();
  }

 private:
  void Accept(EventSourceId listen_fd) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int conn_fd = accept(listen_fd, (struct sockaddr*)&addr, &addr_len);
    if (conn_fd < 0) {
      perror("accept error");
      exit(1);
    }
    printf("new client connected, fd=%d, address=%s:%d\n", conn_fd,
           inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    TcpChannel* chan = new TcpChannel(conn_fd);
    auto es = EventSourceList::Global().CreateEventSource(conn_fd);
    // es->eoi = Event::Read | Event::Write;
    es->eoi = Event::Read;
    es->kind = EventSourceKind::IO;
    es->read = TcpChannel::RecvWrapper;
    es->write = TcpChannel::SendWrapper;
    es->obj = chan;
    ec_->Add(es);
  }

 private:
  EventCenter* ec_;
  bool pending_{false};
};

int main() {
  // TcpSocket sock;
  // sock.Connect("www.google.com", 80);

  // TcpSocket server;
  // server.Listen("*", 8118);

  EventCenter ec;
  ec.Build();

  TcpServer server(&ec);
  if (!server.Listen(8118)) {
    return 1;
  }

  if (!ec.Run()) {
    std::cout << "Ooops...." << std::endl;
  }

  return 0;
}
