#include <iomanip>
#include <iostream>
#include <memory>

#define CHECK_ATOMIC(atomic_type_validity)                    \
  std::cout << #atomic_type_validity << ":" << std::boolalpha \
            << atomic_type_validity << std::endl;

int main() {
  CHECK_ATOMIC(ATOMIC_BOOL_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_CHAR_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_CHAR16_T_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_CHAR32_T_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_WCHAR_T_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_SHORT_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_INT_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_LONG_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_LLONG_LOCK_FREE);
  CHECK_ATOMIC(ATOMIC_POINTER_LOCK_FREE);
  return 0;
}
