#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

// const char* host = "google.com";
const char* host = "chat.openai.com";
const char* path = "/";

int main() {
  // Create socket
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    std::cerr << "Error creating socket" << std::endl;
    return 1;
  }

  // Get IP address from host name
  struct hostent* server = gethostbyname(host);
  if (server == nullptr) {
    std::cerr << "Error getting host address" << std::endl;
    return 1;
  }
  char server_ip[16] = { '\0' };
  inet_ntop(server->h_addrtype, server->h_addr, server_ip, sizeof(server_ip));
  std::cout << "server ip: " << server_ip << std::endl;

  struct sockaddr_in server_addr {};
  std::memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  std::memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
  server_addr.sin_port = htons(443);

  // Connect to server
  if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) <
      0) {
    std::cerr << "Error connecting to server" << std::endl;
    return 1;
  }

  // Initialize SSL context
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (ctx == nullptr) {
    std::cerr << "Error initializing SSL context" << std::endl;
    return 1;
  }

  // configuration for SSL_CTX
  // SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);
  // SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

  // Create SSL object and attach it to the socket
  SSL* ssl = SSL_new(ctx);
  if (ssl == nullptr) {
    std::cerr << "Error creating SSL object" << std::endl;
    SSL_CTX_free(ctx);
    return 1;
  }
  if (SSL_set_fd(ssl, sockfd) == 0) {
    std::cerr << "Error attaching SSL object to socket" << std::endl;
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
  }

  /* Set hostname for SNI */
  SSL_set_tlsext_host_name(ssl, host);

  ERR_clear_error();
  // Perform SSL handshake
  int ret = SSL_connect(ssl);
  if (ret <= 0) {
    std::cerr << "Error performing SSL handshake" << std::endl;
    ERR_print_errors_fp(stderr);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
  }

  // Send HTTPS request
  std::string request = "GET " + std::string(path) + " HTTP/1.1\r\n";
  request += "Host: " + std::string(host) + "\r\n";
  request += "Connection: close\r\n";
  request += "\r\n";

  // if (send(sockfd, request.c_str(), request.size() <= 0, 0)) {
  //   std::cerr << "Error sending HTTPS request" << std::endl;
  //   close(sockfd);
  //   return 1;
  // }

  if (SSL_write(ssl, request.c_str(), request.size()) <= 0) {
    std::cerr << "Error sending HTTPS request" << std::endl;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
  }

  // Receive HTTPS response
  char buf[1024];
  int nread;
  // while ((nread = read(sockfd, buf, sizeof(buf))) > 0) {
  //   std::cout << std::string(buf, nread);
  // }
  // if (nread < 0) {
  //   std::cerr << "Error receiving HTTPS response" << std::endl;
  //   close(sockfd);
  //   return 1;
  // }
  while ((nread = SSL_read(ssl, buf, sizeof(buf))) > 0) {
    std::cout << std::string(buf, nread);
  }
  if (nread < 0) {
    std::cerr << "Error receiving HTTPS response" << std::endl;
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
  }

  // Shutdown SSL connection and cleanup
  SSL_shutdown(ssl);
  SSL_free(ssl);
}
