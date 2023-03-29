// https://curl.se/libcurl/c/libcurl-tutorial.html
// https://curl.se/docs/sslcerts.html
// BUILDING
//
//   g++ demo_libcurl.cc -Iinclude/ -Llib -lcurl
//
// OS: Amazon Linux 2
// HttpsServer: minio server
// self signed certificate
//
#include <string.h>

#include <iostream>
#include <string>

#include "curl/curl.h"

size_t ReadRequestBody(char *buffer, size_t size, size_t nitems,
                       void *userdata) {
  const char request_body[] =
      "{"
      "\"accessKey\": \"admin\","
      "\"secretKey\": \"password\""
      "}";
  memcpy(buffer, request_body, sizeof(request_body));
  return sizeof(request_body);
}

size_t WriteResponseBody(char *buffer, size_t size, size_t nmemb, void *userp) {
  // char* payload = (char *)buffer;
  // for (size_t i = 0; i < size * nmemb; i++) {
  //     printf("%c", payload[i]);
  // }
  // printf("%c", '\n');
  std::string *response_body = reinterpret_cast<std::string *>(userp);
  response_body->append(buffer, size * nmemb);
  return size * nmemb;
}

int main() {
  curl_global_init(CURL_GLOBAL_ALL);

  CURL *curl_handle = curl_easy_init();

  std::string response_body;

  curl_easy_setopt(curl_handle, CURLOPT_URL,
                   "https://10.18.1.182:9001/api/v1/login");
  curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1l);
  curl_easy_setopt(curl_handle, CURLOPT_POST, 1l);
  curl_easy_setopt(curl_handle, CURLOPT_CAINFO,
                   "/etc/pki/ca-trust/source/anchors/public.crt");
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteResponseBody);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response_body);
  curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION, ReadRequestBody);
  // curl_easy_setopt(curl_handle, CURLOPT_READDATA, request_body);

  struct curl_slist *headers = nullptr;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

  curl_easy_perform(curl_handle);

  std::cout << ">>>>>>>>>> Response Body >>>>>>>>>>>" << std::endl;
  std::cout << response_body << std::endl;
  std::cout << "<<<<<<<<<< Response Body <<<<<<<<<<<" << std::endl;

  curl_slist_free_all(headers);
  curl_global_cleanup();
  return 0;
}
