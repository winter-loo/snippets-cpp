#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <signal.h>
#include <stdlib.h>
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
#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <memory>
#include <thread>
#include <unordered_map>
#include <vector>

static bool SetNonblocking(int fd, bool val = true) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl F_GETFL");
    return false;
  }
  int blocking = val ? O_NONBLOCK : ~O_NONBLOCK;
  if (fcntl(fd, F_SETFL, flags | blocking) == -1) {
    perror("fcntl F_SETFL O_NONBLOCK");
    return false;
  }
  return true;
}

class DnsResolver {
 public:
  bool Resolve(const std::string &hostname) {
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
      auto addr = ((struct sockaddr_in *)(rp->ai_addr))->sin_addr;
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
  size_t operator()(const EventSourceId &id) const {
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
  Eoi operator&(Event e) const { return e_ & Eoi(e).e_; }
  Eoi operator|(Event e) const { return e_ | (uint8_t)e; }
  Eoi &operator|=(Event e) {
    e_ = (uint8_t)e | e_;
    return *this;
  }

 private:
  uint8_t e_;
};
Eoi operator|(Event a, Event b) { return Eoi(a) | Eoi(b); }

enum class EventStatus { NoMore, MoreToRecv, MoreToSend, AllSent };

struct EventSource {
  EventSourceId id;
  // events of interested
  Eoi eoi;
  EventStatus (*read_handler)(EventSourceId, void *);
  EventStatus (*write_handler)(EventSourceId, void *);
  void *obj;

  EventSource(EventSourceId id) : id(id) {}
  bool operator==(const EventSource &other) const { return id == other.id; }
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

  T *Add(uint32_t id) {
    auto e = new T(id);
    auto it = elements_.insert(elements_.end(), e);
    lut_.insert({id, it});
    return e;
  }

  void Remove(const T *e) { Remove(e->id); }

  void Remove(uint32_t id) {
    auto it = lut_.find(id);
    if (it != lut_.end()) {
      T *p = *it->second;
      elements_.erase(it->second);
      lut_.erase(it);
      delete p;
    }
  }

  T *Find(uint32_t id) {
    auto it = lut_.find(id);
    if (it != lut_.end()) {
      return *it->second;
    }
    return nullptr;
  }

 private:
  using PointerList = std::list<T *>;
  using LookupTable =
      std::unordered_map<uint32_t, typename PointerList::iterator>;
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
  EventSource *CreateEvent(EventSourceId id) { return events_.Add(id); }
  EventSource *Find(EventSourceId id) { return events_.Find(id); }

  bool Add(EventSource *es, bool add = true) {
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
  bool Remove(EventSource *es) {
    if (-1 == epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, es->id, NULL)) {
      perror("epoll_ctl del error");
      return false;
    }
    return true;
  }

  using OnCloseHandle = std::function<void(uint32_t)>;
  void OnClose(OnCloseHandle func) { on_close_ = func; }

  bool HandleEventStatus(const EventStatus &status, EventSource *es) {
    switch (status) {
      case EventStatus::NoMore: {
        std::cout << "fd " << es->id << " no more data" << std::endl;
        Remove(es);
        close(es->id);
        if (on_close_) on_close_(es->id);
        events_.Remove(es);
        return false;
      }
      case EventStatus::MoreToSend: {
        if (!(es->eoi & Event::Write)) {
          std::cout << "******install write handler" << std::endl;
          es->eoi |= Event::Write;
          Add(es, false);
        }
        break;
      }
      case EventStatus::AllSent: {
        if (es->eoi & Event::Write) {
          std::cout << "******remove write handler" << std::endl;
          es->eoi = Event::Read;
          Add(es, false);
        }
        break;
      }
      case EventStatus::MoreToRecv: {
        std::cout << "fd " << es->id << " has more" << std::endl;
        break;
      }
      default:
        break;
    }
    return true;
  }

  bool Run() {
    pending_ = true;
    AddSignalForQuit();

    // TODO: how could I know how many events need be waited for
    constexpr const int kMaxEvents = 1024;
    struct epoll_event events[kMaxEvents];
    int nfds;

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
        EventSource *es = static_cast<EventSource *>(events[i].data.ptr);
        int readable = flags & EPOLLIN;
        int writable = flags & EPOLLOUT;

        if (es->eoi & readable && es->read_handler) {
          EventStatus s = es->read_handler(es->id, es->obj);
          if (!HandleEventStatus(s, es)) continue;
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

  static EventStatus QuitWrapper(EventSourceId, void *obj) {
    static_cast<EventCenter *>(obj)->Quit();
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
  Message() { buf_.resize(8192); }

  void Insert(const char *buf, size_t len) {
    buf_.assign(buf, buf + len);
    in_use_ = len;
  }

  void Append(const char *buf, size_t len) {
    if (in_use_ + len > buf_.size()) {
      buf_.resize(std::max(in_use_ + len, buf_.size() * 2));
    }
    memcpy(data(), buf, len);
    in_use_ += len;
  }

  const char *to_send() const { return buf_.data() + n_sent_; }
  size_t n_to_send() const { return in_use_ - n_sent_; }
  void add_n_sent(int n) { n_sent_ += n; }

  const char *const_data() const { return buf_.data(); }

  char *data() { return buf_.data() + in_use_; }

  size_t in_use() const { return in_use_; }

  size_t available(bool expand = false) {
    auto ans = buf_.size() - in_use_;
    if (ans == 0 && expand) {
      buf_.resize(buf_.size() * 2);
      ans = buf_.size() - in_use_;
    }
    return ans;
  }

  void add_in_use(int n) { in_use_ += n; }

  void drain(std::string &s) {
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

using MsgParseFn = std::function<void(Message &, Message &)>;

class TcpChannel {
 public:
  TcpChannel(TcpChannelId id)
      : expand_rx_buffer_(false), id_(id), tx_status_(EventStatus::AllSent) {}

  void SetMsgParser(MsgParseFn fn) { parse_fn_ = fn; }
  void SetExpandRxBuffer(bool expand) { expand_rx_buffer_ = expand; }

  EventStatus Send() {
    int n = send(id_, msg_tx_.to_send(), msg_tx_.n_to_send(), MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EPIPE) {
        tx_status_ = EventStatus::MoreToSend;
      } else {
        perror("send error");
        tx_status_ = EventStatus::NoMore;
      }
    } else if (n == 0) {
      std::cout << "writable but nothing to send..." << std::endl;
      tx_status_ = EventStatus::AllSent;
    } else {
      msg_tx_.add_n_sent(n);
      std::cout << n << " bytes sent..." << std::endl;
      tx_status_ =
          HasPendingData() ? EventStatus::MoreToSend : EventStatus::AllSent;
    }

    return tx_status_;
  }

  bool HasPendingData() { return msg_tx_.n_to_send() > 0; }

  // level-trigger
  EventStatus Recv() {
    ssize_t n =
        recv(id_, msg_rx_.data(), msg_rx_.available(expand_rx_buffer_), 0);
    if (n <= 0) {
      if (n < 0) perror("recv error");
      return EventStatus::NoMore;
    }
    msg_rx_.add_in_use(n);
    std::cout << n << " bytes received" << std::endl;

    if (parse_fn_) parse_fn_(msg_rx_, msg_tx_);

    // std::cout.write(msg_rx_.const_data(), msg_rx_.in_use());
    // std::cout.flush();

    // if (msg_tx_.in_use() == 0) {
    //   msg_tx_.Insert(msg_rx_.const_data(), msg_rx_.in_use());
    // } else {
    //   msg_tx_.Append(msg_rx_.const_data(), msg_rx_.in_use());
    // }

    if (msg_tx_.n_to_send() > 0 && tx_status_ != EventStatus::MoreToSend)
      Send();

    // std::ofstream ofs("hello.cc", std::ios::app);
    // ofs.write(msg_rx_.const_data(), msg_rx_.in_use());
    // ofs.close();

    // msg_rx_.drain();

    return tx_status_;
  }

  Message &msg_tx() { return msg_tx_; }

  static EventStatus RecvWrapper(EventSourceId id, void *obj) {
    return static_cast<TcpChannel *>(obj)->Recv();
  }

  static EventStatus SendWrapper(EventSourceId id, void *obj) {
    return static_cast<TcpChannel *>(obj)->Send();
  }

 private:
  bool expand_rx_buffer_;
  Message msg_rx_;
  Message msg_tx_;
  TcpChannelId id_;
  EventStatus tx_status_;
  MsgParseFn parse_fn_;
};

class TcpServer {
 public:
  TcpServer(EventCenter *ec) : ec_(ec) {
    ec_->OnClose([this](uint32_t id) { RemoveClient(id); });
  }

  void OnMessage(MsgParseFn parse_fn) { parse_fn_ = parse_fn; }

  bool Listen(int port, const std::string &address = "*") {
    int listen_fd;
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
    if (bind(listen_fd, (struct sockaddr *)&addr, addr_len) < 0) {
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

  static EventStatus AcceptWrapper(EventSourceId id, void *obj) {
    static_cast<TcpServer *>(obj)->Accept(id);
    return EventStatus::MoreToRecv;
  }

  void RemoveClient(TcpChannelId id) { clients_.Remove(id); }

 private:
  void Accept(EventSourceId listen_fd) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int conn_fd = accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
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
    chan->SetMsgParser(parse_fn_);

    auto es = ec_->CreateEvent(conn_fd);
    es->eoi = Event::Read;
    es->read_handler = TcpChannel::RecvWrapper;
    es->write_handler = TcpChannel::SendWrapper;
    es->obj = chan;
    ec_->Add(es);
  }

 private:
  EventCenter *ec_;
  FastList<TcpChannel> clients_;
  bool pending_{false};
  MsgParseFn parse_fn_;
};

class TcpSocket {
 public:
  using SocketHandle = int;

 private:
  TcpSocket() {
    // Create a socket
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ == -1) {
      std::cerr << "Error creating socket: " << strerror(errno) << std::endl;
    }
  }

 public:
  static TcpSocket Create() { return TcpSocket(); }

  operator SocketHandle() { return sockfd_; }
  operator TcpChannelId() { return sockfd_; }
  operator EventSourceId() { return sockfd_; }

  __attribute__((always_inline)) bool Good() { return sockfd_ != -1; }

  bool SetNonblocking(bool val = true) {
    return ::SetNonblocking(sockfd_, val);
  }

  bool SetSendBufferSize(int n = 16 * 1024) {
    int result = setsockopt(sockfd_, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n));
    if (result == -1) {
      perror("setsockopt(with SO_SNDBUF)");
      return false;
    }
    return true;
  }

  int GetSendBufferSize() {
    int actual_sndbuf = 0;
    socklen_t optlen = sizeof(actual_sndbuf);
    int rc =
        getsockopt(sockfd_, SOL_SOCKET, SO_SNDBUF, &actual_sndbuf, &optlen);
    if (rc < 0) {
      perror("getsockopt");
      return -1;
    }
    return actual_sndbuf;
  }

  bool SetReuse() {
    int reuse = 1;
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
        0) {
      perror("setsockopt(SO_REUSEADDR) failed");
      return false;
    }
    return true;
  }

 private:
  SocketHandle sockfd_;
};

bool IsDotDecimalFormat(std::string ipAddress) {
  int dotCount = 0;
  int num = 0;
  int len = ipAddress.length();

  for (int i = 0; i < len; i++) {
    char c = ipAddress[i];

    // check if character is a digit
    if (isdigit(c)) {
      num = num * 10 + (c - '0');

      // check if number is within range of 0 to 255
      if (num < 0 || num > 255) {
        return false;
      }
    }
    // check if character is a dot
    else if (c == '.') {
      // check if there are more than 3 dots
      if (++dotCount > 3) {
        return false;
      }
      num = 0;  // reset number for next octet
    }
    // invalid character
    else {
      return false;
    }
  }

  // check if there are exactly 3 dots
  if (dotCount != 3) {
    return false;
  }

  return true;
}

class TcpClient {
 public:
  TcpClient(EventCenter *ec) : ec_(ec), sock_(TcpSocket::Create()) {
    if (sock_.Good()) sock_.SetNonblocking();
  }

  bool Connect(const std::string &addr, int port) {
    if (!sock_.Good()) return false;
    std::string ip = addr;
    if (!IsDotDecimalFormat(addr)) {
      if (!dns_.Resolve(addr)) {
        return false;
      }
      ip = dns_.NextAddress();
    }

    es_ = ec_->CreateEvent(sock_);
    es_->eoi = Event::Write;
    es_->write_handler = TcpClient::OnConnectWrapper;
    es_->obj = this;
    ec_->Add(es_);

    // Connect to server
    struct sockaddr_in server_addr_struct;
    server_addr_struct.sin_family = AF_INET;
    server_addr_struct.sin_addr.s_addr = inet_addr(ip.c_str());
    server_addr_struct.sin_port = htons(port);
    if (connect(sock_, (struct sockaddr *)&server_addr_struct,
                sizeof(server_addr_struct)) == -1) {
      if (errno != EINPROGRESS) {
        std::cerr << "Error connecting to server: " << strerror(errno)
                  << std::endl;
        return false;
      }
    }
    return true;
  }

  static EventStatus OnConnectWrapper(EventSourceId id, void *obj) {
    (void)id;
    static_cast<TcpClient *>(obj)->OnConnected();
    return EventStatus::MoreToRecv;
  }

  void OnConnected() {
    std::cout << "Established\n" << std::endl;
    if (chan_ == nullptr) {
      chan_ = new TcpChannel(sock_);
      chan_->SetMsgParser(parse_fn_);
      // chan_->SetExpandRxBuffer(true);
    }

    es_->eoi = Event::Read;
    es_->read_handler = TcpChannel::RecvWrapper;
    es_->write_handler = TcpChannel::SendWrapper;
    es_->obj = chan_;
    ec_->Add(es_, false);

    if (chan_->HasPendingData()) {
      EventStatus status = chan_->Send();
      if (status == EventStatus::MoreToSend) {
        es_->eoi |= Event::Write;
        ec_->Add(es_, false);
      }
    }
  }

  ~TcpClient() {
    if (chan_) {
      delete chan_;
      chan_ = nullptr;
    }
  }

  void OnMessage(MsgParseFn parse_fn) { parse_fn_ = parse_fn; }

  void Send(const char *data, size_t len) {
    if (chan_ == nullptr) {
      chan_ = new TcpChannel(sock_);
      chan_->SetMsgParser(parse_fn_);
    }
    Message &msg_tx = chan_->msg_tx();
    msg_tx.Append(data, len);

    // check whether connection established
    if (es_ && (es_->eoi & Event::Read)) {
      EventStatus status = chan_->Send();
      if (status == EventStatus::MoreToSend) {
        es_->eoi |= Event::Write;
        ec_->Add(es_, false);
      }
    }
  }

 private:
  DnsResolver dns_;
  EventCenter *ec_;
  EventSource *es_;
  TcpSocket sock_;
  TcpChannel *chan_;
  MsgParseFn parse_fn_;
};

class HttpProxyServer {
 public:
  HttpProxyServer(EventCenter *ec) {
    using namespace std::placeholders;
    server_ = std::make_unique<TcpServer>(ec);
    server_->OnMessage(
        std::bind(&HttpProxyServer::ParseTcpMessage, this, _1, _2));

    start_req_body_ = false;
  }

  bool Start(int port, const char *address = "*") {
    return server_->Listen(port, address);
  }

  constexpr static const char *kHost = "Host: ";
  constexpr static const int kLenHost = sizeof(kHost);
  constexpr static const char *kContentLength = "Content-Length: ";
  constexpr static const int kLenContentLength = sizeof(kContentLength);

  constexpr static const int kHostnameMaxLen = 64;

  inline bool LineOfHost(const char *line, int len) {
    return len > kLenHost && strncmp(kHost, line, kLenHost) == 0;
  }

  inline bool LineOfContentLength(const char *line, int len) {
    return len > kLenContentLength &&
           strncmp(kContentLength, line, kLenContentLength) == 0;
  }

 private:
  void ParseTcpMessage(Message &msg_rx, Message &msg_tx) {
    for (; !start_req_body_ && nrx_ + 1 < msg_rx.in_use(); nrx_++) {
      const char *p = msg_rx.const_data();
      if (*(p + nrx_) == '\r' && *(p + nrx_ + 1) == '\n') {
        int len = nrx_ - line_start_;
        if (LineOfHost(p + line_start_, len)) {
          len = std::min(len - kLenHost, kHostnameMaxLen - 1);
          strncpy(hostname_, p + line_start_ + kLenHost, len);
          std::cout << "+++ " << kHost << hostname_ << std::endl;
        } else if (LineOfContentLength(p + line_start_, len)) {
          assert(len - kLenContentLength + 1 > 0);
          char content_len[len - kLenContentLength + 1] = {0};
          strncpy(content_len, p + line_start_ + kLenContentLength,
                  len - kLenContentLength);
          req_body_len_ = atoi(content_len);
          std::cout << "+++ " << kContentLength << req_body_len_ << std::endl;
        } else if (len == 0) {
          start_req_body_ = req_body_len_ > 0;
        }
        line_start_ = nrx_ + 2;
      }
    }
    if (line_start_ + req_body_len_ <= msg_rx.in_use()) {
      // received complete http request message
      std::cout << "********** received http request ********" << std::endl;
      std::cout.write(msg_rx.const_data(), line_start_ + req_body_len_);
      std::cout << "*****************************************" << std::endl;
      std::cout.flush();

      msg_rx.drain();

      // connect to host
      if (strlen(hostname_) > 0) {
      }
      // receive data from host
      // response to client
    }
  }

 private:
  using TcpServerPtr = std::unique_ptr<TcpServer>;
  TcpServerPtr server_;
  char hostname_[kHostnameMaxLen] = {0};
  size_t nrx_{};
  size_t line_start_{};
  int req_body_len_{};
  bool start_req_body_{};
};

class HttpClient {
 public:
  HttpClient(EventCenter *ec) : ec_(ec) {
    using namespace std::placeholders;
    client_ = std::make_unique<TcpClient>(ec_);
    client_->OnMessage(std::bind(&HttpClient::ParseTcpMessage, this, _1, _2));
  }

  bool Connect(const std::string &addr, int port) {
    return client_->Connect(addr, port);
  }

  void SendHttpRequest(const std::string &http_req) {
    client_->Send(http_req.c_str(), http_req.size());
  }

 private:
  void ParseTcpMessage(Message &msg_rx, Message &msg_tx) {
    (void)msg_tx;

    std::cout.write(msg_rx.const_data(), msg_rx.in_use());
    std::cout.flush();

    msg_rx.drain();
  }

 public:
 private:
  using TcpClientPtr = std::unique_ptr<TcpClient>;
  TcpClientPtr client_;
  EventCenter *ec_;
};

int main() {
  EventCenter ec;
  ec.Build();

  // HttpProxyServer s(&ec);
  // if (!s.Start(8000)) {
  //   return 1;
  // }

  HttpClient c(&ec);
  if (!c.Connect("www.google.com", 80)) {
    return 1;
  }
  std::string http_req =
      "GET / HTTP/1.1\r\n"
      "Host: www.google.com\r\n"
      "\r\n";
  c.SendHttpRequest(http_req);

  if (!ec.Run()) {
    std::cout << "Ooops...." << std::endl;
  }

  return 0;
}
