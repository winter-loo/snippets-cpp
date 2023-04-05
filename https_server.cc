#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>

void handle_ssl_connection(SSL* ssl) {
  char buffer[4096];
  int bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
  if (bytes_read <= 0) {
    ERR_print_errors_fp(stderr);
    return;
  }
  buffer[bytes_read + 1] = '\0';

  std::cout << "Received data:\n" << buffer << std::endl;

  const char* response =
      "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello "
      "World!</body></html>";
  SSL_write(ssl, response, strlen(response));
}

void handle_tcp_connection(int sockfd, SSL_CTX* ssl_ctx) {
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);

  int clientfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
  if (clientfd < 0) {
    perror("Failed to accept connection");
    return;
  }

  SSL* ssl = SSL_new(ssl_ctx);
  if (!ssl) {
    perror("Failed to create SSL object");
    return;
  }

  SSL_set_fd(ssl, clientfd);
  if (SSL_accept(ssl) <= 0) {
    ERR_print_errors_fp(stderr);
    return;
  }

  handle_ssl_connection(ssl);
}

SSL_CTX* create_ssl_context(const char* cert_file, const char* key_file) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ctx;
}

#define MAX_CLIENTS 10

int create_tcp_socket(int port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("Failed to create socket");
    exit(EXIT_FAILURE);
  }

  int opt = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
                 sizeof(opt))) {
    perror("Failed to set socket options");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in serv_addr;
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    perror("Failed to bind socket");
    exit(EXIT_FAILURE);
  }

  if (listen(sockfd, MAX_CLIENTS) < 0) {
    perror("Failed to listen to socket");
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

int main() {
  const char* cert_file =
      "/home/lighthouse/ssl_certs/ldd.cool_nginx/ldd.cool_bundle.crt";
  const char* key_file =
      "/home/lighthouse/ssl_certs/ldd.cool_nginx/ldd.cool.key";

  int sockfd = create_tcp_socket(8000);
  SSL_CTX* ssl_ctx = create_ssl_context(cert_file, key_file);
  handle_tcp_connection(sockfd, ssl_ctx);
  return 0;
}
