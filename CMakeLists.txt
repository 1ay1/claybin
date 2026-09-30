cmake_minimum_required(VERSION 3.25)
project(claybin LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# claybin is built on std::expected -- Result<T> and Status are aliases for it,
# and every fallible operation returns one. a toolchain without it fails with a
# few hundred lines of "no template named 'Result'", which says nothing useful.
#
# this check exists because CI hit exactly that: Ubuntu's default clang pairs
# with a libstdc++ too old for <expected>, and the build failed deep in
# bpf/emit.cpp rather than at configure time with a sentence anyone could act
# on. -std=c++23 alone does not imply the LIBRARY has it.
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-std=c++23")
check_cxx_source_compiles("
  #include <expected>
  int main() { std::expected<int, char> e{1}; return e.has_value() ? 0 : 1; }
" CLAYBIN_HAS_EXPECTED)
unset(CMAKE_REQUIRED_FLAGS)
if(NOT CLAYBIN_HAS_EXPECTED)
  message(FATAL_ERROR
    "this compiler's standard library has no working <expected>.\n"
    "claybin needs it: Result<T> and Status are aliases for std::expected.\n"
    "known-good: gcc 13+, or clang 17+ built against libstdc++ 13+ or libc++ 16+.\n"
    "with clang on a distro whose default libstdc++ is older, either install a\n"
    "newer libstdc++ or add -stdlib=libc++ to CMAKE_CXX_FLAGS.")
endif()

option(CLAYBIN_TESTS "build tests" ON)

add_library(claybin STATIC
  src/bpf/emit.cpp
  src/plan/compile.cpp
  src/broker/notify.cpp
  src/core/fd.cpp
  src/plan/probe.cpp
  src/windows/compile.cpp
)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(claybin PRIVATE src/linux/apply.cpp src/linux/spawn.cpp src/linux/cgroup.cpp)
endif()
target_include_directories(claybin PUBLIC include)
target_compile_options(claybin PRIVATE
  -Wall -Wextra -Wconversion -Wshadow -Wold-style-cast
  -fno-exceptions -fno-rtti
)
# the whole point: no libseccomp, no libcap, no libmount. raw syscalls only.
target_link_libraries(claybin PUBLIC)

add_executable(claybin-audit tools/claybin_audit.cpp)
target_link_libraries(claybin-audit PRIVATE claybin)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(claybin-run tools/claybin_run.cpp)
  target_link_libraries(claybin-run PRIVATE claybin)
endif()

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
  claybin_test(readme_example_test)
  claybin_test(plan_test)
  claybin_test(mount_algebra_test)
  claybin_test(shapes_test)
  claybin_test(windows_backend_test)
  claybin_test(compile_fuzz_test)

  # the syscall tables get an extra translation unit: it compiles the aarch64
  # profile block on whatever host is building, so those ~130 numbers are
  # actually exercised rather than just present.
  add_executable(syscall_table_test tests/syscall_table_test.cpp
                                    tests/profiles_aarch64.cpp)
  target_link_libraries(syscall_table_test PRIVATE claybin claybin_test_support)
  target_compile_options(syscall_table_test PRIVATE -Wall -Wextra -fno-exceptions -fno-rtti)
  add_test(NAME syscall_table_test COMMAND syscall_table_test)

  # the aarch64 tables have never executed -- no hardware, no cross toolchain --
  # so they get a second, INDEPENDENT check: dump what they permit and resolve
  # every number through the kernel's own header. the C++ test above shares an
  # author (and any misreading) with the tables; this does not.
  add_executable(clay_dump_aarch64 tests/dump_aarch64.cpp)
  target_link_libraries(clay_dump_aarch64 PRIVATE claybin)
  add_test(NAME aarch64_audit
           COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/aarch64_audit.sh
                   $<TARGET_FILE:clay_dump_aarch64>)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    claybin_test(escape_test)
    claybin_test(escape_corpus_test)
    claybin_test(mount_test)
    claybin_test(cgroup_test)
    claybin_test(broker_test)

    # differential conformance against the real bwrap. skips itself when bwrap
    # is not installed, because the whole point is comparing against it rather
    # than against our own idea of what it does.
    add_test(NAME conformance
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/conformance.sh
                     $<TARGET_FILE:claybin-run>)
  endif()
endif()
