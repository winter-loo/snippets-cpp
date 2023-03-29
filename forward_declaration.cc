#include "forward_declaration.h"

namespace internal {
class Foo {};
}  // namespace internal

Bar::Bar() {}

void Bar::Handle(const internal::Foo foo) {}
