#pragma once

class Foo {
 public:
  static constexpr const char kTraceCategory[] = "partition_alloc";
  // using the second definition, you do not have a definition in .cc file
  // it is a real compile-time string constant
  //
  // static constexpr const char * const kTraceCategory = "partition_alloc";

  void Hello();
};
