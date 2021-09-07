#include "static_constexpr.h"
#include <iostream>

// must-have definition
// static
constexpr const char Foo::kTraceCategory[];

void Foo::Hello() {
  std::cout << kTraceCategory << std::endl;
}

int main() {
  Foo f;
  f.Hello();
  return 0;
}
