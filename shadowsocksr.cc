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
#include <map>
#include <memory>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

namespace Clock {
using std_clock = std::chrono::high_resolution_clock;
using milliseconds = std::chrono::milliseconds;
using time_point = std_clock::time_point;

// only for testing
milliseconds time_passed_{};

time_point Now() {
  return std_clock::now() + time_passed_;
}

bool IsSet(time_point t) {
  return t.time_since_epoch() != std_clock::time_point::duration::zero();
}

int Duration(time_point other) {
  return std::chrono::duration_cast<milliseconds>(Now() - other).count();
}

void TimePassed(milliseconds ms) {
  time_passed_ = ms;
}
};  // namespace Clock

// https://base64.guru/learn/base64-algorithm/decode
//
// Support encoding scheme
//  * [base64](https://datatracker.ietf.org/doc/html/rfc4648#section-4)
//  * [base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5)
//
// Implementation
// https://github.com/ReneNyffenegger/cpp-base64/blob/master/base64.cpp#L163
// converting six-bit bytes into eight-bit bytes.
//
std::string B64Decode(const std::string& encoded) {
  auto IndexOf = [&](char ch) {
    if (ch >= 'A' && ch <= 'Z')
      return ch - 'A';
    else if (ch >= 'a' && ch <= 'z')
      return ch - 'a' + 26;
    else if (ch >= '0' && ch <= '9')
      return ch - '0' + 52;
    else if (ch == '+' || ch == '-')
      return 62;
    else if (ch == '/' || ch == '_')
      return 63;
    else
      return -1;
  };

  std::string decoded;
  size_t encoded_len = encoded.size();
  size_t pos = 0;
  decoded.reserve(encoded_len / 4 * 3);
  int i1 = -1, i2 = -1, i3 = -1, i4 = -1;
  char c;

  while (pos < encoded_len) {
    i1 = IndexOf(encoded[pos]);
    if (i1 == -1)
      return {};
    if (pos + 1 < encoded_len) {
      i2 = IndexOf(encoded[pos + 1]);
      if (i2 == -1)
        return {};
      c = (i1 << 2) + ((i2 & 0x30) >> 4);
      decoded.push_back(c);

      if (pos + 2 < encoded_len) {
        i3 = IndexOf(encoded[pos + 2]);
        if (i3 == -1)
          return {};
        c = ((i2 & 0x0f) << 4) + ((i3 & 0x3c) >> 2);
        decoded.push_back(c);

        if (pos + 3 < encoded_len) {
          i4 = IndexOf(encoded[pos + 3]);
          if (i4 == -1)
            return {};
          c = ((i3 & 0x03) << 6) + i4;
          decoded.push_back(c);
        }
      }
    }
    pos += 4;
  }
  return decoded;
}

void Test_B64Decode() {
  int test_case = 0;
  auto TestOutput = [&](const std::string& answer, const std::string& expected) {
    std::cout << "case " << ++test_case << ": ";
    if (answer != expected) {
      std::cerr << "FAILED" << std::endl;
      std::cerr << "answer:\n" << answer << std::endl;
      std::cerr << "expected:\n" << expected << std::endl;
    } else {
      std::cout << "PASSED" << std::endl;
    }
  };

  std::cout << "B64Decode Test\n";

  std::string encoded =
      "dDMuZnJlZWdyYWRlbHkueHl6OjIwMDIyOm9yaWdpbjphZXMtMjU2LWNmYjp0bHMxLjJfdGlja2V0X2F1dGg6Wkc5dVozUmhhWGRoYm1jdVkyOXQv"
      "P29iZnNwYXJhbT0mcmVtYXJrcz1hSFIwY0hNNkx5OW5hWFJvZFdJdVkyOXRMMEZzZG1sdU9UazVPUzl1WlhjdGNHRmpMM2RwYTJrZzVyU2I1cDJK"
      "NTUtMk1WTlRVZw";
  std::string expected =
      "t3.freegradely.xyz:20022:origin:aes-256-cfb:tls1.2_ticket_auth:ZG9uZ3RhaXdhbmcuY29t/"
      "?obfsparam=&remarks=aHR0cHM6Ly9naXRodWIuY29tL0FsdmluOTk5OS9uZXctcGFjL3dpa2kg5rSb5p2J55-2MVNTUg";
  std::string decoded = B64Decode(encoded);
  TestOutput(decoded, expected);

  encoded = "ZG9uZ3RhaXdhbmcuY29t";
  expected = "dongtaiwang.com";
  decoded = B64Decode(encoded);
  TestOutput(decoded, expected);

  encoded = "aHR0cHM6Ly9naXRodWIuY29tL0FsdmluOTk5OS9uZXctcGFjL3dpa2kg5rSb5p2J55-2MVNTUg";
  expected = "https://github.com/Alvin9999/new-pac/wiki 洛杉矶1SSR";
  decoded = B64Decode(encoded);
  TestOutput(decoded, expected);
}

struct SsrNode {
  // ip or domain
  std::string address;
  int port;
  std::string method;
  std::string obfs;
  std::string password;
  std::string protocol;
  std::string obfs_param;
  std::string protocol_param;
  std::string remarks;
  std::string group;
};

void Split(const std::string& str, const std::string& delimiter, std::vector<std::string>& fields) {
  size_t pos = 0, ppos = 0;
  while (true) {
    pos = str.find(delimiter, pos);
    if (pos == std::string::npos)
      break;
    fields.emplace_back(str.substr(ppos, pos - ppos));
    pos = pos + 1;
    ppos = pos;
  }
  fields.emplace_back(str.substr(ppos));
}

void Test_Split() {
  std::vector<std::string> fields;
  std::string input = "=";
  Split(input, "=", fields);
  assert(fields.size() == 2);
  assert(fields[0].empty());
  assert(fields[1].empty());

  fields.clear();
  input = "123=";
  Split(input, "=", fields);
  assert(fields.size() == 2);
  assert(fields[0] == "123");
  assert(fields[1].empty());

  fields.clear();
  input = "123=456";
  Split(input, "=", fields);
  assert(fields.size() == 2);
  assert(fields[0] == "123");
  assert(fields[1] == "456");
}

bool ParseSsrURL(const std::string& ssr_url, SsrNode& node) {
  const static char kSsrUrlPrefix[] = "ssr://";
  const size_t kPrefixLen = sizeof(kSsrUrlPrefix) - 1;
  if (ssr_url.size() < kPrefixLen + 1 || 0 != ssr_url.find(kSsrUrlPrefix)) {
    // ssr_url begins with ssr://
    return false;
  }

  std::string decoded = B64Decode(ssr_url.substr(kPrefixLen));
  if (decoded.empty()) {
    // failed to decode
    return false;
  }

  std::vector<std::string> fields;
  Split(decoded, ":", fields);
  if (fields.size() < 5)
    return false;
  node.address = fields[0];
  node.port = std::stoi(fields[1]);
  node.protocol = fields[2];
  node.method = fields[3];
  node.obfs = fields[4];
  std::string last_field = fields[5];
  fields.clear();
  Split(last_field, "/?", fields);
  if (fields.size() < 2)
    return false;
  node.password = B64Decode(fields[0]);
  last_field = fields[1];
  fields.clear();
  Split(last_field, "&", fields);
  std::vector<std::string> kvs;
  for (auto& fld : fields) {
    Split(fld, "=", kvs);
    if (kvs.size() != 2)
      continue;
    if (kvs[0] == "obfsparam") {
      node.obfs_param = kvs[1];
    } else if (kvs[0] == "protoparam") {
      node.protocol_param = kvs[1];
    } else if (kvs[0] == "remarks") {
      node.remarks = kvs[1];
    } else if (kvs[0] == "group") {
      node.group = kvs[1];
    }
  }

  return true;
}

void Test_ParseSsrURL() {
  const std::string ssr_url =
      "ssr://"
      "dDMuZnJlZWdyYWRlbHkueHl6OjIwMDIyOm9yaWdpbjphZXMtMjU2LWNmYjp0bHMxLjJfdGlja2V0X2F1dGg6Wkc5dVozUmhhWGRoYm1jdVkyOXQv"
      "P29iZnNwYXJhbT0mcmVtYXJrcz1hSFIwY0hNNkx5OW5hWFJvZFdJdVkyOXRMMEZzZG1sdU9UazVPUzl1WlhjdGNHRmpMM2RwYTJrZzVyU2I1cDJK"
      "NTUtMk1WTlRVZw";
  SsrNode node;
  assert(ParseSsrURL(ssr_url, node));
  assert(node.address == "t3.freegradely.xyz");
  assert(node.port == 20022);
  assert(node.method == "aes-256-cfb");
  assert(node.protocol == "origin");
  assert(node.obfs == "tls1.2_ticket_auth");
  assert(node.password == "dongtaiwang.com");
}

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
      if (rp->ai_family != AF_INET)
        continue;  // Only need IPv4 address
      if ((rp->ai_flags & AI_PASSIVE) != 0)
        continue;  // Skip wildcard address
      auto addr = ((struct sockaddr_in*)(rp->ai_addr))->sin_addr;
      if (addr.s_addr == 0)
        continue;  // Skip wildcard address
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
  size_t operator()(const EventSourceId& id) const { return hash<uint32_t>()(id); }
};
}  // namespace std

class TimedEventList {
 public:
  struct TimedEvent {
    Clock::time_point tp;
    std::list<EventSourceId>::iterator pos;
  };
  TimedEventList() {}

  void Add(EventSourceId id) {
    auto it = tps_.find(id);
    if (it != tps_.end()) {
      it->second.tp = Clock::Now();
      events_.erase(it->second.pos);
      auto pos = events_.insert(events_.end(), *it->second.pos);
      it->second.pos = pos;
    } else {
      auto pos = events_.insert(events_.end(), id);
      tps_.insert({id, {Clock::Now(), pos}});
    }
  }

  int RemainingEvents() { return events_.size(); }

  void Remove(EventSourceId id) {
    auto it = tps_.find(id);
    if (it == tps_.end()) {
      return;
    }
    events_.erase(it->second.pos);
    tps_.erase(it);
  }

  using OnEventExpired = std::function<void(EventSourceId)>;
  void RemoveExpiredEvent(int idle_duration, OnEventExpired expired_fn) {
    while (!events_.empty()) {
      auto id = events_.front();
      if (idle_duration <= Clock::Duration(tps_[id].tp)) {
        expired_fn(id);
        Remove(id);
      } else {
        break;
      }
    }
  }

 private:
  std::list<EventSourceId> events_;
  std::unordered_map<EventSourceId, TimedEvent> tps_;
};

void Test_TimedEventList() {
  TimedEventList tel;

  tel.Add(1);
  tel.Add(2);

  Clock::TimePassed(Clock::milliseconds(10));

  std::vector<EventSourceId> expired;
  tel.RemoveExpiredEvent(8, [&](EventSourceId id) { expired.push_back(id); });
  assert(expired.size() == 2);
  assert(expired[0] == EventSourceId(1));
  assert(expired[1] == EventSourceId(2));

  expired.clear();
  Clock::TimePassed(Clock::milliseconds(0));

  tel.Add(1);
  tel.Add(2);
  Clock::TimePassed(Clock::milliseconds(10));
  tel.RemoveExpiredEvent(16, [&](EventSourceId id) { expired.push_back(id); });
  assert(expired.size() == 0);

  Clock::TimePassed(Clock::milliseconds(20));
  tel.Add(3);
  tel.RemoveExpiredEvent(12, [&](EventSourceId id) { expired.push_back(id); });
  assert(expired.size() == 2);
  assert(expired[0] == EventSourceId(1));
  assert(expired[1] == EventSourceId(2));
  assert(tel.RemainingEvents() == 1);
}

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
  Eoi& operator|=(Event e) {
    e_ = (uint8_t)e | e_;
    return *this;
  }

 private:
  uint8_t e_;
};
Eoi operator|(Event a, Event b) {
  return Eoi(a) | Eoi(b);
}

enum class IoEventStatus {
  // no more incoming data, should shutdown read channel at least
  NoMoreRecv,
  // expect more incoming data
  MoreToRecv,
  // write channel shutdown or error occured
  // should shutdown write channel now
  NoMoreSend,
  // cannot send all data at once, should wait for writable event
  MoreToSend,
  // all data sent, should not wait for writeable event
  AllSent
};
enum class EventKind { kSignal, kListen, kConn };

struct EventSource {
  EventSourceId id;
  EventKind kind;
  // events of interested
  Eoi eoi;
  IoEventStatus (*read_handler)(EventSourceId, void*);
  IoEventStatus (*write_handler)(EventSourceId, void*);
  void* obj;

  EventSource(EventSourceId id) : id(id), kind(EventKind::kConn) {}
  bool operator==(const EventSource& other) const { return id == other.id; }
};

class TcpSocket {
 public:
  using SocketHandle = int;
  static const int kBad = -1;

  TcpSocket() {
    // Create a socket
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ == -1) {
      std::cerr << "Error creating socket: " << strerror(errno) << std::endl;
    }
  }

  TcpSocket(SocketHandle h) : sockfd_(h) {}

 public:
  operator SocketHandle() { return sockfd_; }
  operator EventSourceId() { return sockfd_; }

  __attribute__((always_inline)) bool Good() { return sockfd_ != kBad; }

  bool SetNonblocking(bool val = true) { return ::SetNonblocking(sockfd_, val); }

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
    int rc = getsockopt(sockfd_, SOL_SOCKET, SO_SNDBUF, &actual_sndbuf, &optlen);
    if (rc < 0) {
      perror("getsockopt");
      return -1;
    }
    return actual_sndbuf;
  }

  bool SetReuse() {
    int reuse = 1;
    if (setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
      perror("setsockopt(SO_REUSEADDR) failed");
      return false;
    }
    return true;
  }

  bool Bind(const std::string& ipv4, int port) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    // 绑定地址
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (ipv4 == "*") ? htonl(INADDR_ANY) : inet_addr(ipv4.c_str());
    addr.sin_port = htons(port);
    if (bind(sockfd_, (struct sockaddr*)&addr, addr_len) < 0) {
      perror("bind error");
      return false;
    }
    return true;
  }

  bool Listen(int queue_size = SOMAXCONN) {
    if (listen(sockfd_, queue_size) < 0) {
      perror("listen error");
      return false;
    }
    return true;
  }

  TcpSocket Accept() {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    int conn_fd = accept(sockfd_, (struct sockaddr*)&addr, &addr_len);
    if (conn_fd < 0) {
      perror("accept error");
      return TcpSocket(TcpSocket::kBad);
    }
    printf("new client connected, fd=%d, address=%s:%d\n", conn_fd, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
    return TcpSocket(conn_fd);
  }

  void Close() { close(sockfd_); }

  void ShutdownReadChannel() { shutdown(sockfd_, SHUT_RD); }
  void ShutdownWriteChannel() { shutdown(sockfd_, SHUT_WR); }
  void ShutdownChannel() { shutdown(sockfd_, SHUT_RDWR); }

  IoEventStatus Write(const char* buf, size_t* buf_len) {
    if (!buf_len || *buf_len <= 0) {
      return IoEventStatus::AllSent;
    }
    size_t n = send(sockfd_, buf, *buf_len, MSG_NOSIGNAL);
    if (n < 0) {
      *buf_len = 0;
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return IoEventStatus::MoreToSend;
      } else {
        perror("send error");
        return IoEventStatus::NoMoreSend;
      }
    }
    auto s = n < *buf_len ? IoEventStatus::MoreToSend : IoEventStatus::AllSent;
    *buf_len = n < 0 ? 0 : n;
    return s;
  }

  IoEventStatus Read(char* buf, size_t* buf_len) {
    if (!buf_len || *buf_len <= 0) {
      return IoEventStatus::MoreToRecv;
    }
    ssize_t n = recv(sockfd_, buf, *buf_len, 0);
    if (n <= 0) {
      *buf_len = 0;
      if (n < 0)
        perror("recv error");
      return IoEventStatus::NoMoreRecv;
    }

    *buf_len = n;
    return IoEventStatus::MoreToRecv;
  }

 private:
  SocketHandle sockfd_;
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

  void Remove(uint32_t id) {
    auto it = lut_.find(id);
    if (it != lut_.end()) {
      T* p = *it->second;
      elements_.erase(it->second);
      lut_.erase(it);
      delete p;
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
  static const int kNoTimeout = -1;
  EventCenter() {
    if ((epoll_fd_ = epoll_create1(0)) < 0) {
      perror("epoll_create1 error");
      good_ = false;
    }
    good_ = true;
  }
  bool good() { return good_; }
  EventSource* CreateEvent(EventSourceId id) { return events_.Add(id); }
  EventSource* Find(EventSourceId id) { return events_.Find(id); }

  bool Add(EventSource* es) {
    struct epoll_event ev;
    ev.events = es->eoi;
    ev.data.ptr = es;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, es->id, &ev) < 0) {
      perror("epoll_ctl add error");
      return false;
    }
    if (es->kind == EventKind::kConn) {
      timed_events_.Add(es->id);
    }
    return true;
  }
  bool Modify(EventSource* es) {
    struct epoll_event ev;
    ev.events = es->eoi;
    ev.data.ptr = es;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_MOD, es->id, &ev) < 0) {
      perror("epoll_ctl mod error");
      return false;
    }
    return true;
  }
  bool Remove(EventSourceId id) {
    if (-1 == epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, id, NULL)) {
      perror("epoll_ctl del error");
      return false;
    }
    return true;
  }

  void SetTimeout(int timeout_ms) { timeout_ms_ = timeout_ms; }

  using OnCloseHandle = std::function<void(uint32_t)>;
  void OnClose(OnCloseHandle func) { on_close_ = func; }

  void Clean(EventSourceId id) {
    std::cout << "clean resource with event " << id << std::endl;
    Remove(id);
    if (on_close_)
      on_close_(id);
    events_.Remove(id);
  }

  [[nodiscard]] bool HandleEventStatus(const IoEventStatus& status, EventSource* es) {
    switch (status) {
      case IoEventStatus::NoMoreRecv: {
        std::cout << "fd " << es->id << " no more incoming data, ";
        // if is in writing state, only shutdown read channel;
        if (es->eoi & Event::Write) {
          std::cout << "shutdown read channel" << std::endl;
          TcpSocket(es->id).ShutdownReadChannel();
          // only care writeable event now
          es->eoi = Event::Write;
          Modify(es);
        } else {
          std::cout << "clean resource" << std::endl;
          Clean(es->id);
          // event cleaned, do no handle other events
          return false;
        }
      }
      case IoEventStatus::NoMoreSend: {
        if (es->eoi & Event::Read) {
          std::cout << "fd " << es->id << ", no more send, shutdown write channel" << std::endl;
          TcpSocket(es->id).ShutdownWriteChannel();
          // only care read event now
          es->eoi = Event::Read;
          Modify(es);
        } else {
          std::cout << "fd " << es->id << ", no more send, clean resource" << std::endl;
          Clean(es->id);
          // event cleaned, do no handle other events
          return false;
        }
        break;
      }
      case IoEventStatus::MoreToSend: {
        if (!(es->eoi & Event::Write)) {
          std::cout << "****** fd " << es->id << " install write handler" << std::endl;
          es->eoi |= Event::Write;
          Modify(es);
        }
        break;
      }
      case IoEventStatus::AllSent: {
        // if read channel has shutdown and all data sent, clean resource now
        if (!(es->eoi & Event::Read)) {
          std::cout << "fd " << es->id << " all data sent, clean resource" << std::endl;
          Clean(es->id);
          // event cleaned, do no handle other events
          return false;
        } else {
          std::cout << "****** fd " << es->id << " remove write handler" << std::endl;
          es->eoi = Event::Read;
          Modify(es);
        }
        break;
      }
      case IoEventStatus::MoreToRecv: {
        std::cout << "fd " << es->id << " has more" << std::endl;
        break;
      }
      default:
        break;
    }
    return true;
  }

  bool EnableTimeout() { return timeout_ms_ != kNoTimeout; }

  bool Run() {
    pending_ = true;
    AddSignalForQuit();

    // TODO: how could I know how many events need be waited for
    constexpr const int kMaxEvents = 1024;
    struct epoll_event events[kMaxEvents];
    int nfds;

    while (pending_) {
      std::cout << "epoll wait..." << std::endl;
      nfds = epoll_wait(epoll_fd_, events, kMaxEvents, timeout_ms_);
      if (!Clock::IsSet(last_wake_up_time_)) {
        last_wake_up_time_ = Clock::Now();
      }
      if (nfds < 0) {
        if (errno == EINTR)
          continue;
        perror("epoll_wait error");
        return false;
      }
      std::cout << "kernel says " << nfds << " fd ready..." << std::endl;
      for (int i = 0; i < nfds; i++) {
        // TODO: handle EPOLLHUP, EPOLLERR
        int flags = events[i].events;
        EventSource* es = static_cast<EventSource*>(events[i].data.ptr);
        int readable = flags & EPOLLIN;
        int writable = flags & EPOLLOUT;

        // update time with triggering event
        if (es->kind == EventKind::kConn)
          timed_events_.Add(es->id);

        if (es->eoi & readable && es->read_handler) {
          std::cout << "fd " << es->id << " readable..." << std::endl;
          IoEventStatus s = es->read_handler(es->id, es->obj);
          if (!HandleEventStatus(s, es))
            continue;
        }

        if (es->eoi & writable && es->write_handler) {
          std::cout << "fd " << es->id << " writeable..." << std::endl;
          IoEventStatus s = es->write_handler(es->id, es->obj);
          if (!HandleEventStatus(s, es))
            continue;
        }

        if (!readable && !writable) {
          std::cout << "unnecessary wake up" << std::endl;
        }
      }

      // process expired clients
      if (EnableTimeout()) {
        timed_events_.RemoveExpiredEvent(timeout_ms_, [&](EventSourceId id) {
          std::cout << "expired id " << id << std::endl;
          Clean(id);
        });
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
    es->kind = EventKind::kSignal;
    es->eoi = Event::Read;
    es->read_handler = EventCenter::QuitWrapper;
    es->obj = this;
    Add(es);
  }

  static IoEventStatus QuitWrapper(EventSourceId, void* obj) {
    static_cast<EventCenter*>(obj)->Quit();
    return IoEventStatus::NoMoreRecv;
  }

  void Quit() {
    std::cout << "quit now" << std::endl;
    pending_ = false;
  }

 private:
  bool good_{false};
  int timeout_ms_{kNoTimeout};
  Clock::time_point last_wake_up_time_;
  FastList<EventSource> events_;
  TimedEventList timed_events_;
  int epoll_fd_;
  bool pending_;
  OnCloseHandle on_close_;
};
using EventCenterPtr = std::shared_ptr<EventCenter>;

class Message {
 public:
  Message() { buf_.resize(8192); }

  int Insert(const char* buf, size_t len) {
    buf_.assign(buf, buf + len);
    in_use_ = len;
    return len;
  }

  int Append(const char* buf, size_t len) {
    if (in_use_ + len > buf_.size()) {
      buf_.resize(std::max(in_use_ + len, buf_.size() * 2));
    }
    memcpy(data(), buf, len);
    in_use_ += len;
    return len;
  }

  const char* to_send() const { return buf_.data() + n_sent_; }
  size_t n_to_send() const { return in_use_ - n_sent_; }
  void add_n_sent(int n) { n_sent_ += n; }

  // 已经接收尚未读取的消息
  const char* not_read() const { return buf_.data() + n_read_; }
  size_t n_to_read() const { return in_use_ - n_read_; }
  size_t n_read() const { return n_read_; }
  void add_n_read(int n) { n_read_ += n; }
  // 已经接收的消息
  const char* recvd() const { return buf_.data(); }

  size_t in_use() const { return in_use_; }
  void add_in_use(int n) { in_use_ += n; }

  // TODO: rename
  char* data() { return buf_.data() + in_use_; }
  size_t available(bool expand = false) {
    auto ans = buf_.size() - in_use_;
    if (ans == 0 && expand) {
      buf_.resize(buf_.size() * 2);
      ans = buf_.size() - in_use_;
    }
    return ans;
  }

  void drain() {
    in_use_ = 0;
    n_sent_ = 0;
    n_read_ = 0;
  }

 private:
  size_t in_use_{};
  size_t n_sent_{};
  size_t n_read_{};
  std::vector<char> buf_;
};

using MsgParseFn = std::function<void(Message&, Message&)>;

class TcpChannel {
 public:
  TcpChannel(TcpSocket s) : expand_rx_buffer_(false), sock_(s), tx_status_(IoEventStatus::AllSent) {}

  // 通过自定义的 MsgParseFn 实现各种协议的处理
  void SetMsgParser(MsgParseFn fn) { parse_fn_ = fn; }
  void SetExpandRxBuffer(bool expand) { expand_rx_buffer_ = expand; }

  IoEventStatus Send() {
    size_t n = msg_tx_.n_to_send();
    tx_status_ = sock_.Write(msg_tx_.to_send(), &n);
    msg_tx_.add_n_sent(n);
    return tx_status_;
  }

  bool HasPendingData() { return msg_tx_.n_to_send() > 0; }

  // level-trigger
  IoEventStatus Recv() {
    size_t n = msg_rx_.available(expand_rx_buffer_);
    auto s = sock_.Read(msg_rx_.data(), &n);
    if (s == IoEventStatus::NoMoreRecv) {
      return s;
    }
    msg_rx_.add_in_use(n);
    std::cout << n << " bytes received" << std::endl;

    if (parse_fn_)
      parse_fn_(msg_rx_, msg_tx_);

    // std::cout.write(msg_rx_.const_data(), msg_rx_.in_use());
    // std::cout.flush();

    // if (msg_tx_.in_use() == 0) {
    //   msg_tx_.Insert(msg_rx_.const_data(), msg_rx_.in_use());
    // } else {
    //   msg_tx_.Append(msg_rx_.const_data(), msg_rx_.in_use());
    // }

    if (msg_tx_.n_to_send() > 0 && tx_status_ != IoEventStatus::MoreToSend)
      Send();

    // std::ofstream ofs("hello.cc", std::ios::app);
    // ofs.write(msg_rx_.const_data(), msg_rx_.in_use());
    // ofs.close();

    // msg_rx_.drain();

    return tx_status_;
  }

  Message& msg_tx() { return msg_tx_; }

  static IoEventStatus RecvWrapper(EventSourceId, void* obj) { return static_cast<TcpChannel*>(obj)->Recv(); }

  static IoEventStatus SendWrapper(EventSourceId, void* obj) { return static_cast<TcpChannel*>(obj)->Send(); }

 private:
  bool expand_rx_buffer_;
  Message msg_rx_;
  Message msg_tx_;
  TcpSocket sock_;
  IoEventStatus tx_status_;
  MsgParseFn parse_fn_;
};

template <typename T>
struct SettingItem {
  bool enabled;
  T value;

  SettingItem() : enabled(false) {}
  SettingItem(T value) : enabled(true), value(value) {}
  T& get() { return value; }

  void operator=(const SettingItem<T>& other) {
    if (!other.enabled || this == &other)
      return;
    this->enabled = other.enabled;
    this->value = other.value;
  }
};

struct TcpServerSetting {
  SettingItem<std::string> address{"*"};
  SettingItem<int> port{1080};
  SettingItem<bool> nonblocking{true};
  // 0: epoll_wait return immediately
  // positive: epoll_wait block until time passed
  // negative: epoll_wait block until events generated
  SettingItem<int> close_idle_client_in_ms{-1};
  SettingItem<EventCenterPtr> ec;
  SettingItem<MsgParseFn> parse_fn;

  void operator=(const TcpServerSetting& other) {
    if (&other == this)
      return;
    this->address = other.address;
    this->port = other.port;
    this->nonblocking = other.nonblocking;
    this->ec = other.ec;
    this->close_idle_client_in_ms = other.close_idle_client_in_ms;
    this->parse_fn = other.parse_fn;
  }
};

class TcpServer {
 public:
  TcpServer() {}

  void SetSetting(TcpServerSetting ss) { setting_ = ss; }

  void BeforeRun() {
    if (setting_.ec.get() == nullptr) {
      setting_.ec = std::make_shared<EventCenter>();
      assert(setting_.ec.get()->good());
      has_own_ec_ = true;
      setting_.ec.get()->SetTimeout(setting_.close_idle_client_in_ms.get());
    }
    setting_.ec.get()->OnClose([this](uint32_t id) { RemoveClient(id); });
  }

  void AfterRun() {}

  bool Run() {
    BeforeRun();
    if (!Listen(setting_.port.get(), setting_.address.get())) {
      return false;
    }
    if (has_own_ec_) {
      setting_.ec.get()->Run();
    }
    AfterRun();
    return true;
  }

 private:
  bool Listen(int port, const std::string& address = "*") {
    if (!sock_lsn_.Good()) {
      return false;
    }
    if (!sock_lsn_.SetReuse()) {
      return false;
    }
    if (!sock_lsn_.Bind(setting_.address.get(), setting_.port.get())) {
      return false;
    }
    if (!sock_lsn_.Listen()) {
      return false;
    }
    std::cout << "server listen fd is: " << sock_lsn_ << std::endl;

    auto es = setting_.ec.get()->CreateEvent(sock_lsn_);
    es->kind = EventKind::kListen;
    es->eoi = Event::Read;
    es->read_handler = TcpServer::AcceptWrapper;
    es->obj = this;
    setting_.ec.get()->Add(es);
    return true;
  }

  static IoEventStatus AcceptWrapper(EventSourceId id, void* obj) {
    static_cast<TcpServer*>(obj)->Accept(id);
    return IoEventStatus::MoreToRecv;
  }

  void RemoveClient(TcpSocket id) {
    id.Close();
    clients_.Remove(id);
  }

  void Accept(EventSourceId) {
    TcpSocket client = sock_lsn_.Accept();

    // set the buffer size to 4KB
    int sndbuf_size = 2920;
    client.SetSendBufferSize(sndbuf_size);
    printf("Send buffer size: %d\n", client.GetSendBufferSize());
    client.SetNonblocking();

    auto chan = clients_.Add(client);
    chan->SetMsgParser(setting_.parse_fn.get());

    auto es = setting_.ec.get()->CreateEvent(client);
    es->eoi = Event::Read;
    es->read_handler = TcpChannel::RecvWrapper;
    es->write_handler = TcpChannel::SendWrapper;
    es->obj = chan;
    setting_.ec.get()->Add(es);
  }

 private:
  bool pending_{false};
  bool has_own_ec_{false};
  TcpSocket sock_lsn_;
  FastList<TcpChannel> clients_;
  TcpServerSetting setting_;
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
  TcpClient(EventCenter* ec) : ec_(ec) {
    if (sock_.Good())
      sock_.SetNonblocking();
  }

  bool Connect(const std::string& addr, int port) {
    if (!sock_.Good())
      return false;
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
    if (connect(sock_, (struct sockaddr*)&server_addr_struct, sizeof(server_addr_struct)) == -1) {
      if (errno != EINPROGRESS) {
        std::cerr << "Error connecting to server: " << strerror(errno) << std::endl;
        return false;
      }
    }
    return true;
  }

  static IoEventStatus OnConnectWrapper(EventSourceId id, void* obj) {
    (void)id;
    static_cast<TcpClient*>(obj)->OnConnected();
    return IoEventStatus::MoreToRecv;
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
    ec_->Modify(es_);

    if (chan_->HasPendingData()) {
      IoEventStatus status = chan_->Send();
      if (status == IoEventStatus::MoreToSend) {
        es_->eoi |= Event::Write;
        ec_->Modify(es_);
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

  void Send(const char* data, size_t len) {
    if (chan_ == nullptr) {
      chan_ = new TcpChannel(sock_);
      chan_->SetMsgParser(parse_fn_);
    }
    Message& msg_tx = chan_->msg_tx();
    msg_tx.Append(data, len);

    // check whether connection established
    if (es_ && (es_->eoi & Event::Read)) {
      IoEventStatus status = chan_->Send();
      if (status == IoEventStatus::MoreToSend) {
        es_->eoi |= Event::Write;
        ec_->Modify(es_);
      }
    }
  }

 private:
  DnsResolver dns_;
  EventCenter* ec_;
  EventSource* es_;
  TcpSocket sock_;
  TcpChannel* chan_;
  MsgParseFn parse_fn_;
};

void RunTcpServer() {
  TcpServer server;
  TcpServerSetting ss;
  ss.port = 8000;
  ss.close_idle_client_in_ms = 5000;
  server.SetSetting(ss);
  server.Run();
}

void EchoProtocol(Message& msg_rx, Message& msg_tx) {
  int n = msg_tx.Append(msg_rx.not_read(), msg_rx.n_to_read());
  msg_rx.add_n_read(n);
}

void RunEchoServer() {
  TcpServer server;
  TcpServerSetting ss;
  ss.port = 8000;
  ss.parse_fn = MsgParseFn(EchoProtocol);
  server.SetSetting(ss);
  server.Run();
}

class FileResponse {
 public:
  enum class Stage { kSendingData = 0 };
  enum class Status {
    // everything works fine
    kCode_200,
    // bad request
    kCode_400,
    // not found
    kCode_404
  };
  friend std::ostream& operator<<(std::ostream& os, Status s) {
    if (s == Status::kCode_200) {
      os << "200";
    } else if (s == Status::kCode_400) {
      os << "400";
    } else if (s == Status::kCode_404) {
      os << "404";
    }
    return os;
  }

  using FileContent = std::vector<char>;

  void SetStatus(Status s) { status_ = s; }

  size_t n_sent() { return n_sent_; }

  void set_tot_len(int len) { tot_len_ = len; }

  void set_payload_len(int len) {
    payload_len_ = len;
    payload_.resize(len);
  }

  void add_n_sent(int len) { n_sent_ += len; }

  FileContent& payload() { return payload_; }

  bool Good() { return status_ == Status::kCode_200; }

  void ToMessage(Message& tx) {
    // 当前实现是一次性发送文件内容
    std::stringstream ss;
    ss << status_;
    ss << " " << payload_len_ << "\n";
    std::string status_line(ss.str());
    tx.Append(status_line.c_str(), status_line.size());
    tx.Append(payload_.data(), payload_.size());
  }

 private:
  Status status_{Status::kCode_200};
  // 待发送文件的总长度
  int tot_len_{};
  // 已发送的数据长度
  int n_sent_{};
  // 该次发送的数据的长度
  int payload_len_{};
  FileContent payload_;
};

class FileRequest {
 public:
  enum class Stage {
    // clang-format off
    kRequestLineGetting = 0,
    kRequestLineParsing,
    kDataWaiting,
    kDone,
    kError = 100
    // clang-format on
  };
  enum class FileOp {
    // GET /path/to/file Range
    //
    // get content from a file,
    // if third parameter does not exist, read whole file;
    // otherwise, read specified range parts
    kGet,
    // DEL /path/to/file Mark
    //
    // delete file or mark deletion.
    // if third parameter does not exit, delete file from disk in 7 days
    // otherwise delete immediatly
    kDelete,
    // APP /path/to/file ContentLen
    //.....
    // append some content to file.
    // if file does not exist, create it.
    // third parameter specifies how much data write to the file.
    // data comes from next line and after
    kAppend
  };

  static constexpr int kRequestLineMaxLen = 1024;
  static constexpr int kOffsetToEOF = -1;
  static constexpr int kDefaultKeepDays = 7;

  union FileOpParam {
    struct {
      size_t offset;
      size_t len;
    } for_get;

    struct {
      // 0 => delete immediatly
      // other => keep file for that days
      int keep_days;
    } for_delete;

    struct {
      size_t len;
    } for_append;
  };

  using FilePath = std::string;

  FileRequest(FileResponse& resp) : resp_(resp) {}
  FileRequest(const char* line, int len, FileResponse& resp) : resp_(resp) { ParseLine(line, len); }
  bool ParseLine(const char* line, int len) {
    std::string req;
    req.assign(line, line + len);
    std::vector<std::string> fields;
    Split(req, " ", fields);
    if (fields.size() < 2) {
      set_stage(FileRequest::Stage::kError);
      // could comment below line
      resp_.SetStatus(FileResponse::Status::kCode_400);
      return false;
    }
    auto op_str = fields[0];
    path_ = fields[1];
    if (op_str == "GET") {
      // has the third field
      if (fields.size() == 3) {
        std::string range = fields[2];
        fields.clear();
        Split(range, "-", fields);
        // allowd form: 100-1124, -, 100-
        if (fields.size() == 2) {
          int range_start = atoi(fields[0].c_str());
          param_.for_get.offset = range_start;
          if (fields[1].empty()) {
            param_.for_get.len = kOffsetToEOF;
          } else {
            param_.for_get.len = atoi(fields[1].c_str()) - range_start;
          }
        } else {
          // set default value
          param_.for_get.offset = 0;
          param_.for_get.len = kOffsetToEOF;
        }
      }
      ReadFile();
    } else if (op_str == "DEL") {
      // has the third field
      if (fields.size() == 3) {
        param_.for_delete.keep_days = atoi(fields[2].c_str());
      } else {
        // set default value
        param_.for_delete.keep_days = kDefaultKeepDays;
      }
      DeleteFile();
    } else if (op_str == "APP") {
      if (fields.size() != 3) {
        set_stage(FileRequest::Stage::kError);
        resp_.SetStatus(FileResponse::Status::kCode_400);
        return false;
      }
      int len = atoi(fields[2].c_str());
      if (len == 0) {
        set_stage(FileRequest::Stage::kError);
        resp_.SetStatus(FileResponse::Status::kCode_400);
        return false;
      }
      param_.for_append.len = len;
      AppendToFile();
    } else {
      // no such operation
      set_stage(FileRequest::Stage::kError);
      resp_.SetStatus(FileResponse::Status::kCode_400);
      return false;
    }
    return true;
  }

  // TODO: First, send status and its partial content
  // Then, send partial content until complete
  void ReadFile() {
    if (in_.is_open()) {
      in_.close();
    }
    in_.open(path_);
    if (!in_.good()) {
      set_stage(FileRequest::Stage::kError);
      resp_.SetStatus(FileResponse::Status::kCode_400);
      return;
    }
    in_.seekg(0, std::ios::end);
    size_t file_size = in_.tellg();
    in_.seekg(0, std::ios::beg);

    resp_.set_tot_len(file_size);
    resp_.set_payload_len(file_size);
    // expect whole file content in one read system call
    // TODO:
    in_.read(resp_.payload().data(), resp_.payload().size());

    set_stage(FileRequest::Stage::kDone);
    resp_.SetStatus(FileResponse::Status::kCode_200);
  }

  void DeleteFile() {
    if (param_.for_delete.keep_days == 0) {
      // delete immediatly
      if (0 != remove(path_.c_str())) {
        set_stage(FileRequest::Stage::kError);
        resp_.SetStatus(FileResponse::Status::kCode_400);
        return;
      }
    } else {
      // do not delete the file until days passed
    }
    set_stage(FileRequest::Stage::kDone);
    resp_.SetStatus(FileResponse::Status::kCode_200);
  }

  void AppendToFile() {
    out_.open(path_, std::ios::app);
    if (!out_.good()) {
      set_stage(FileRequest::Stage::kError);
      resp_.SetStatus(FileResponse::Status::kCode_400);
      return;
    }
    // TODO:
    set_stage(FileRequest::Stage::kDataWaiting);
  }

  void WriteToFile() { out_.open(path_); }

  void OnData(const char* data, size_t len) {
    if (n_recvd_ + len <= param_.for_append.len) {
      out_.write(data, len);
      n_recvd_ += len;
      if (n_recvd_ == param_.for_append.len) {
        set_stage(FileRequest::Stage::kDone);
        resp_.SetStatus(FileResponse::Status::kCode_200);
      }
    } else {
      set_stage(FileRequest::Stage::kError);
      resp_.SetStatus(FileResponse::Status::kCode_400);
    }
  }

  Stage stage() { return stage_; }
  void set_stage(Stage s) { stage_ = s; }

  bool RequestLineTooLong(int n) {
    return stage() == FileRequest::Stage::kRequestLineGetting && n > FileRequest::kRequestLineMaxLen;
  }

 private:
  FileOp op_;
  FilePath path_;
  FileOpParam param_;
  Stage stage_{Stage::kRequestLineGetting};
  std::ofstream out_;
  std::ifstream in_;
  FileResponse& resp_;
  size_t n_recvd_{};
};

class FileService {
 public:
  FileService() {}

  bool Run() {
    ss_.port = 8000;
    MsgParseFn fn = std::bind(&FileService::OnMessage, this, std::placeholders::_1, std::placeholders::_2);
    ss_.parse_fn = fn;
    server_.SetSetting(ss_);
    return server_.Run();
  }

  void OnMessage(Message& msg_rx, Message& msg_tx) {
    if (req_ == nullptr && resp_ == nullptr) {
      resp_ = new FileResponse{};
      req_ = new FileRequest(*resp_);
    }
    if (req_->stage() == FileRequest::Stage::kRequestLineGetting) {
      for (size_t i = msg_rx.n_read(); i < msg_rx.in_use(); i++) {
        if (req_->RequestLineTooLong(i)) {
          req_->set_stage(FileRequest::Stage::kError);
          resp_->SetStatus(FileResponse::Status::kCode_400);
          break;
        }
        if (msg_rx.recvd()[i] == '\n') {
          req_->set_stage(FileRequest::Stage::kRequestLineParsing);
          msg_rx.add_n_read(i - msg_rx.n_read() + 1);
          break;
        }
      }
    }
    if (req_->stage() == FileRequest::Stage::kRequestLineParsing) {
      size_t line_len = msg_rx.n_read();
      req_->ParseLine(msg_rx.recvd(), line_len);
    }
    if (req_->stage() == FileRequest::Stage::kDataWaiting) {
      req_->OnData(msg_rx.recvd(), msg_rx.in_use());
      msg_rx.drain();
    }
    if (req_->stage() == FileRequest::Stage::kDone || req_->stage() == FileRequest::Stage::kError) {
      resp_->ToMessage(msg_tx);
      delete req_;
      req_ = nullptr;
      delete resp_;
      resp_ = nullptr;
    }
  }

 private:
  FileResponse* resp_{};
  FileRequest* req_{};
  TcpServer server_;
  TcpServerSetting ss_;
};

void RunFileServer() {
  FileService().Run();
}

int main() {
  // EventCenter ec;
  // ec.Build();

  // HttpProxyServer s(&ec);
  // if (!s.Start(8000)) {
  //   return 1;
  // }

  // HttpClient c(&ec);
  // if (!c.Connect("www.google.com", 80)) {
  //   return 1;
  // }
  // std::string http_req =
  //     "GET / HTTP/1.1\r\n"
  //     "Host: www.google.com\r\n"
  //     "\r\n";
  // c.SendHttpRequest(http_req);

  // if (!ec.Run()) {
  //   std::cout << "Ooops...." << std::endl;
  // }

  RunFileServer();

  // Test_B64Decode();
  // Test_Split();
  // Test_ParseSsrURL();
  // Test_TimedEventList();

  return 0;
}
