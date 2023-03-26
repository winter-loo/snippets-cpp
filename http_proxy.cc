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
#include <functional>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
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
  Eoi operator&(Event e) const {
    return e_ & Eoi(e).e_;
  }
  Eoi operator|(Event e) const {
    return e_ | (uint8_t)e;
  }
  Eoi& operator|=(Event e) {
    e_ = (uint8_t) e | e_;
    return *this;
  }

 private:
  uint8_t e_;
};
Eoi operator|(Event a, Event b) { return Eoi(a) | Eoi(b); }

enum class EventStatus { NoMore, RecvMore, MoreSent, AllSent };

struct EventSource {
  EventSourceId id;
  // events of interested
  Eoi eoi;
  EventStatus (*read_handler)(EventSourceId, void*);
  EventStatus (*write_handler)(EventSourceId, void*);
  void* obj;

  EventSource(EventSourceId id) : id(id) {}
  bool operator==(const EventSource& other) const { return id == other.id; }
};

template <typename T>
class FastList {
 public:
  FastList() = default;

  ~FastList() {
    while (!elements_.empty()) {
      auto p = elements_.back();
      delete p;
      elements_.pop_back();
    }
  }

  T* Add(uint32_t id) {
    auto e = new T(id);
    auto it = elements_.insert(elements_.end(), e);
    lut_.insert({id, it});
    return e;
  }

  void Remove(const T* e) {
    Remove(e->id);
  }

  void Remove(uint32_t id) {
    auto it = lut_.find(id);
    if (it != lut_.end()) {
      delete *it->second;
      elements_.erase(it->second);
    }
  }

  T* Find(uint32_t id) {
    auto it = lut_.find(id);
    if (it != lut_.end()) {
      return *it->second;
    }
    return nullptr;
  }

 private:
  using PointerList = std::list<T*>;
  using LookupTable = std::unordered_map<uint32_t, typename PointerList::iterator>;
  PointerList elements_;
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
  EventSource* CreateEvent(EventSourceId id) { return events_.Add(id); }
  EventSource* Find(EventSourceId id) { return events_.Find(id); }

  bool Add(EventSource* es, bool add = true) {
    struct epoll_event ev;
    ev.events = es->eoi;
    ev.data.ptr = es;
    int op = add ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (epoll_ctl(epoll_fd_, op, es->id, &ev) < 0) {
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

  using OnCloseHandle = std::function<void(uint32_t)>;
  void OnClose(OnCloseHandle func) {
    on_close_ = func;
  }

  void HandleEventStatus(const EventStatus& status, EventSource* es) {
    switch (status) {
      case EventStatus::NoMore: {
        std::cout << "fd " << es->id << " no more data" << std::endl;
        Remove(es);
        close(es->id);
        events_.Remove(es);
        on_close_(es->id);
        break;
      }
      case EventStatus::MoreSent: {
        if (!(es->eoi & Event::Write)) {
          es->eoi |= Event::Write;
          Add(es, false);
        }
        break;
      }
      case EventStatus::AllSent: {
        if (es->eoi & Event::Write) {
          es->eoi = Event::Read;
          Add(es, false);
        }
        break;
      }
      case EventStatus::RecvMore: {
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
        if (errno == EINTR) continue;
        perror("epoll_wait error");
        return false;
      }
      std::cout << "kernel says " << nfds << " fd ready..." << std::endl;
      for (int i = 0; i < nfds; i++) {
        int flags = events[i].events;
        EventSource* es = static_cast<EventSource*>(events[i].data.ptr);
        int readable = flags & EPOLLIN;
        int writable = flags & EPOLLOUT;

        if (es->eoi & readable && es->read_handler) {
          EventStatus s = es->read_handler(es->id, es->obj);
          HandleEventStatus(s, es);
        }

        if (es->eoi & writable && es->write_handler) {
          EventStatus s = es->write_handler(es->id, es->obj);
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

    auto es = CreateEvent(sfd);
    es->eoi = Event::Read;
    es->read_handler = EventCenter::QuitWrapper;
    es->obj = this;
    Add(es);
  }

  static EventStatus QuitWrapper(EventSourceId, void* obj) {
    static_cast<EventCenter*>(obj)->Quit();
    return EventStatus::NoMore;
  }

  void Quit() {
    std::cout << "quit now" << std::endl;
    pending_ = false;
  }

 private:
  FastList<EventSource> events_;
  int epoll_fd_;
  bool pending_;
  OnCloseHandle on_close_;
};

class Message {
 public:
  Message() {
    // greater than MSS
    buf_.resize(8192);
  }

  void Insert(const char* buf, size_t len) {
    buf_.assign(buf, buf + len);
    in_use_ = len;
  }

  void Append(const std::string& s) {}
  void Append(const char* buf, size_t len) {
    if (in_use_ + len > buf_.size()) {
      buf_.resize(std::max(in_use_ + len, buf_.size() * 2));
    }
    memcpy(data(), buf, len);
    in_use_ += len;
  }

  const char* to_send() const { return buf_.data() + n_sent_; }
  size_t n_to_send() const { return in_use_ - n_sent_; }
  void add_n_sent(int n) { n_sent_ += n; }

  const char* const_data() const { return buf_.data(); }

  char* data() { return buf_.data() + in_use_; }

  size_t in_use() const { return in_use_; }

  size_t available() const { return buf_.size() - in_use_; }

  void add_in_use(int n) { in_use_ += n; }

  void drain(std::string& s) {
    s.assign(const_data(), const_data() + in_use());
    in_use_ = 0;
  }

  void drain() { in_use_ = 0; }

 private:
  size_t in_use_{};
  size_t n_sent_{};
  std::vector<char> buf_;
};

class TcpChannelId {
 public:
  TcpChannelId(EventSourceId id) : id_(id) {}
  TcpChannelId(int id) : id_(id) {}

  operator int() const { return id_; }
  operator EventSourceId() const { return id_; }

 private:
  uint32_t id_;
};

class TcpChannel {
 public:
  TcpChannel(TcpChannelId id) : id_(id), tx_status_(EventStatus::AllSent) {}

  EventStatus Send() {
    int n = send(id_, msg_tx_.to_send(), msg_tx_.n_to_send(), 0);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        tx_status_ = EventStatus::MoreSent;
      } else {
        perror("send error");
        tx_status_ =  EventStatus::NoMore;
      }
    } else if (n == 0) {
      std::cout << "writable but nothing to send..." << std::endl;
      tx_status_ = EventStatus::AllSent;
    } else {
      msg_tx_.add_n_sent(n);
      std::cout << n << " bytes sent..." << std::endl;
      tx_status_ = HasPendingData() ? EventStatus::MoreSent : EventStatus::AllSent;
    }

    return tx_status_;
  }

  bool HasPendingData() {
    return msg_tx_.n_to_send() > 0;
  }

  // level-trigger
  EventStatus Recv() {
    EventStatus status;
    ssize_t n = recv(id_, msg_rx_.data(), msg_rx_.available(), 0);
    if (n <= 0) {
      if (n < 0) perror("recv error");
      return EventStatus::NoMore;
    }
    msg_rx_.add_in_use(n);
    std::cout << n << " bytes received" << std::endl;

    if (msg_tx_.in_use() == 0) {
      msg_tx_.Insert(msg_rx_.const_data(), msg_rx_.in_use());
    } else {
      msg_tx_.Append(msg_rx_.const_data(), msg_rx_.in_use());
    }

    if (tx_status_ != EventStatus::MoreSent) Send();

    std::ofstream ofs("hello.cc", std::ios::app);
    ofs.write(msg_rx_.const_data(), msg_rx_.in_use());
    ofs.close();

    msg_rx_.drain();

    return tx_status_;
  }

  static EventStatus RecvWrapper(EventSourceId id, void* obj) {
    return static_cast<TcpChannel*>(obj)->Recv();
  }

  static EventStatus SendWrapper(EventSourceId id, void* obj) {
    return static_cast<TcpChannel*>(obj)->Send();
  }

 private:
  Message msg_rx_;
  Message msg_tx_;
  EventStatus tx_status_;
  TcpChannelId id_;
};

class TcpServer {
 public:
  TcpServer(EventCenter* ec) : ec_(ec) {
    ec_->OnClose([this](uint32_t id){
      RemoveClient(id);
    });
  }

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
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
        0) {
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

    auto es = ec_->CreateEvent(listen_fd);
    es->eoi = Event::Read;
    es->read_handler = TcpServer::AcceptWrapper;
    es->obj = this;
    ec_->Add(es);
    return true;
  }

  static EventStatus AcceptWrapper(EventSourceId id, void* obj) {
    static_cast<TcpServer*>(obj)->Accept(id);
    return EventStatus::RecvMore;
  }

  void RemoveClient(TcpChannelId id) {
    clients_.Remove(id);
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

    int sndbuf_size = 2920;  // set the buffer size to 4KB
    int result = setsockopt(conn_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf_size,
                            sizeof(sndbuf_size));
    if (result == -1) {
      perror("setsockopt(with SO_SNDBUF)");
      return;
    }
    int actual_sndbuf = 0;
    socklen_t optlen = sizeof(actual_sndbuf);
    int rc =
        getsockopt(conn_fd, SOL_SOCKET, SO_SNDBUF, &actual_sndbuf, &optlen);
    if (rc < 0) {
      perror("getsockopt");
      exit(EXIT_FAILURE);
    }
    printf("Send buffer size: %d\n", actual_sndbuf);

    SetNonblocking(conn_fd);

    auto chan = clients_.Add(conn_fd);
    auto es = ec_->CreateEvent(conn_fd);
    es->eoi = Event::Read;
    es->read_handler = TcpChannel::RecvWrapper;
    es->write_handler = TcpChannel::SendWrapper;
    es->obj = chan;
    ec_->Add(es);
  }

 private:
  EventCenter* ec_;
  FastList<TcpChannel> clients_;
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
