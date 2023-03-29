#include <string.h>

#include <chrono>
#include <iostream>

int main() {
  // delete memory
  char *buf = new char[4096];

  buf[0] = 'a';
  buf[4095] = 'z';
  buf[4096] = '\0';

  auto t0 = std::chrono::high_resolution_clock::now();
  delete buf;
  auto t1 = std::chrono::high_resolution_clock::now();

  std::chrono::duration<double> dura = (t1 - t0);
  std::cout << dura.count() << "s\n";

  // copy memory
  char *buf2 = new char[4096];
  t0 = std::chrono::high_resolution_clock::now();
  memcpy(buf2, buf, 4096);
  t1 = std::chrono::high_resolution_clock::now();
  dura = (t1 - t0);
  std::cout << dura.count() << "s\n";
  return 0;
}
