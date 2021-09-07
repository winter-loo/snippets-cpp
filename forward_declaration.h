#pragma once

namespace internal {
class Foo;
}

class Bar {
 public:
  Bar();
 private:
  void Handle(const internal::Foo);
};
