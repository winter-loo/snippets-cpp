#include <iostream>
#include <string>

struct Foo {
  std::string s;
  char i;
};

struct Foo2 {
  char i;
  std::string s;
};

int main() {
  std::cout << sizeof(std::string) << std::endl; // 32
  std::cout << sizeof(Foo) << std::endl; // 40
  std::cout << sizeof(Foo2) << std::endl; // 40
  return 0;
}
