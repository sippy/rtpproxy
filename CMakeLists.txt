cmake_minimum_required(VERSION 3.10)

# set the project name
project(SPMCQueue)

# specify the C standard
set(CMAKE_C_STANDARD 99)

include(CheckIPOSupported)

add_library(SPMCQueue SHARED src/SPMCQueue.c)
add_library(SPMCQueue_static STATIC src/SPMCQueue.c)
set_target_properties(SPMCQueue_static PROPERTIES OUTPUT_NAME SPMCQueue)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(SPMCQueue PRIVATE -fvisibility=hidden)
  target_compile_options(SPMCQueue_static PRIVATE -fvisibility=hidden)
endif()

target_compile_definitions(SPMCQueue PRIVATE SPMC_BUILD_SHARED SPMC_EXPORTS)

if(UNIX AND NOT APPLE)
  target_link_options(SPMCQueue PRIVATE
    "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/symbols.map")
endif()

check_ipo_supported(RESULT ipo_supported OUTPUT ipo_error)
if(ipo_supported)
  message(STATUS "IPO/LTO supported; enabling it for optimized builds")
else()
  message(STATUS "IPO/LTO not supported: ${ipo_error}")
endif()

if(ipo_supported)
  set_target_properties(SPMCQueue PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
  set_target_properties(SPMCQueue_static PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
endif()

# Enable testing via CTest
enable_testing()

# Create a test executable
add_executable(spmc_bench_test src/spmc_bench_test.c)
add_executable(spmc_queue_test src/spmc_queue_test.c)

if(ipo_supported)
  set_target_properties(spmc_bench_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
  set_target_properties(spmc_queue_test PROPERTIES
    INTERPROCEDURAL_OPTIMIZATION_RELEASE ON
    INTERPROCEDURAL_OPTIMIZATION_RELWITHDEBINFO ON
    INTERPROCEDURAL_OPTIMIZATION_MINSIZEREL ON)
endif()

# Link the test executable against our library and pthread
target_link_libraries(spmc_bench_test SPMCQueue pthread)
target_link_libraries(spmc_queue_test SPMCQueue)

# Add the test
add_test(NAME SPMCTest COMMAND spmc_bench_test)
add_test(NAME SPMCQueueUnitTest COMMAND spmc_queue_test)
