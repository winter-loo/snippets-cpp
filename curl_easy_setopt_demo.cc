#include <cstdarg>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

// c style
typedef struct {
  void* p;
  size_t n;
} CURL_slice;

// c++ style
struct CURL_easy {
  long dns_cache_timeout;
  char* ssl_cipher_list;
  bool enable_quic;
  std::vector<int> codes;
};

enum CURLoption { CURLOPT_ENABLE_QUIC, CURLOPT_SSL_CIPHER_LIST, CURLOPT_DNS_CACHE_TIMEOUT, CURLOPT_CODES };

void curl_easy_setopt(CURL_easy* data, CURLoption tag, ...) {
  va_list arg;
  va_start(arg, tag);

  switch (tag) {
    case CURLOPT_DNS_CACHE_TIMEOUT:
      data->dns_cache_timeout = va_arg(arg, long);
      break;

    case CURLOPT_ENABLE_QUIC:
      data->enable_quic = va_arg(arg, long) != 0 ? true : false;
      break;
    case CURLOPT_SSL_CIPHER_LIST:
      data->ssl_cipher_list = va_arg(arg, char*);
      break;
    case CURLOPT_CODES: {
      int* elements = va_arg(arg, int*);
      while (*elements != -1) {
        data->codes.push_back(*elements);
        ++elements;
      }
      break;
    }
    default:
      break;
  }

  va_end(arg);
}

void curl_easy_get(CURL_easy* data, CURLoption tag, ...) {
  va_list arg;
  void* paramp;
  va_start(arg, tag);
  paramp = va_arg(arg, void*);
  // result = Curl_getinfo(data, info, paramp);

  switch (tag) {
    case CURLOPT_DNS_CACHE_TIMEOUT:
      *(long*)paramp = data->dns_cache_timeout;
      break;
    case CURLOPT_ENABLE_QUIC:
      *(long*)paramp = data->enable_quic;
      break;
    case CURLOPT_SSL_CIPHER_LIST:
      *(char**)paramp = data->ssl_cipher_list;
      break;

    case CURLOPT_CODES: {
      CURL_slice* s = (CURL_slice*)paramp;
      s->p = data->codes.data();
      // data copy
      s->n = data->codes.size();
      break;
    }
    default:
      break;
  }
  va_end(arg);
}

int main() {
  CURL_easy curl;
  CURL_easy curl2;
  curl2.dns_cache_timeout = 20;
  curl_easy_setopt(&curl, CURLOPT_DNS_CACHE_TIMEOUT, curl2.dns_cache_timeout);
  curl_easy_setopt(&curl, CURLOPT_ENABLE_QUIC, 1);
  curl_easy_setopt(&curl, CURLOPT_SSL_CIPHER_LIST, "rc4;aes-cfb-256");
  int codes[] = {1, 3, 8, 90, 12, 18, -1};
  curl_easy_setopt(&curl, CURLOPT_CODES, codes);

  char* ssl_cipher_list;
  curl_easy_get(&curl, CURLOPT_SSL_CIPHER_LIST, &ssl_cipher_list);
  std::cout << ssl_cipher_list << std::endl;

  long dns_cache_timeout;
  curl_easy_get(&curl, CURLOPT_DNS_CACHE_TIMEOUT, &dns_cache_timeout);
  std::cout << dns_cache_timeout << std::endl;

  std::cout << curl.codes.size() << std::endl;
  for (auto i : curl.codes) {
    std::cout << i << " ";
  }
  std::cout << std::endl;

  CURL_slice s_codes;
  curl_easy_get(&curl, CURLOPT_CODES, &s_codes);
  std::cout << s_codes.n << std::endl;
  int* p = (int*)s_codes.p;
  for (int i = (int)s_codes.n - 1; i >= 0; i--) {
    std::cout << p[i] << " ";
  }
  std::cout << std::endl;

  return 0;
}
