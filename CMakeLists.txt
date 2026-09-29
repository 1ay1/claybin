cmake_minimum_required(VERSION 3.25)
project(claybin LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(CLAYBIN_TESTS "build tests" ON)

add_library(claybin STATIC
  src/bpf/emit.cpp
)
target_include_directories(claybin PUBLIC include)
target_compile_options(claybin PRIVATE
  -Wall -Wextra -Wconversion -Wshadow -Wold-style-cast
  -fno-exceptions -fno-rtti
)
# the whole point: no libseccomp, no libcap, no libmount. raw syscalls only.
target_link_libraries(claybin PUBLIC)

if(CLAYBIN_TESTS)
  enable_testing()
  add_library(claybin_test_support INTERFACE)
  target_include_directories(claybin_test_support INTERFACE tests/support)

  function(claybin_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE claybin claybin_test_support)
    target_compile_options(${name} PRIVATE -Wall -Wextra -fno-exceptions -fno-rtti)
    add_test(NAME ${name} COMMAND ${name})
  endfunction()

  claybin_test(lattice_laws_test)
  claybin_test(fs_algebra_test)
  claybin_test(bpf_emit_test)
  claybin_test(policy_typestate_test)
endif()
