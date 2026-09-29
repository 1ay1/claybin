cmake_minimum_required(VERSION 3.25)
project(claybin LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(CLAYBIN_TESTS "build tests" ON)

add_library(claybin STATIC
  src/bpf/emit.cpp
  src/plan/compile.cpp
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
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    claybin_test(escape_test)
    claybin_test(escape_corpus_test)
    claybin_test(mount_test)
    claybin_test(cgroup_test)

    # differential conformance against the real bwrap. skips itself when bwrap
    # is not installed, because the whole point is comparing against it rather
    # than against our own idea of what it does.
    add_test(NAME conformance
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/conformance.sh
                     $<TARGET_FILE:claybin-run>)
  endif()
endif()
