#include <atomic>
#include <iomanip>
#include <iostream>
#include <memory>

int main() {
  bool expected = true;
  std::atomic<bool> b{true};
  std::cout << b.is_lock_free() << std::endl;
  if (b.compare_exchange_weak(expected, false)) {
    std::cout << "b set to desired value: " << b;
  } else {
    std::cout
        << "not equal, expected value is updated to atomic variable value: "
        << expected;
  }
  std::cout << std::endl;
  return 0;
}
