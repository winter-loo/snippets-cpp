cmake_minimum_required(VERSION 3.12)

project(fun)

set(CMAKE_CXX_STANDARD 14)

message(INFO "...${CMAKE_CXX_FLAGS}...")

add_executable(main main.cc)

add_subdirectory(third_party/abseil-cpp)

add_executable(demo_absl_optional demo_absl_optional.cc)
target_link_libraries(demo_absl_optional absl::optional)
