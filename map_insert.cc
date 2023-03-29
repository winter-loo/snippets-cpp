#include <iostream>
#include <map>

int main() {
  std::map<int, int> mnumbers;
  mnumbers.insert({1, 2});
  // 第二次 insert 不会生效
  mnumbers.insert({1, 3});

  for (auto &it : mnumbers) {
    std::cout << it.first << ": " << it.second << std::endl;
  }
  return 0;
}
