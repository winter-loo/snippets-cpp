#include <chrono>
#include <iostream>

int main() {
  auto now = std::chrono::steady_clock::now();
  std::cout << now.time_since_epoch().count() << std::endl;
  std::chrono::microseconds us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch());
  std::cout << us.count() << std::endl;
  return 0;
}
