cmake_minimum_required(VERSION 3.10)

# set the project name
project(SPMCQueue)

# specify the C standard
set(CMAKE_C_STANDARD 99)

# add the executable
add_library(SPMCQueue src/SPMCQueue.c)

# Enable testing via CTest
enable_testing()

# Create a test executable
add_executable(spmc_bench_test src/spmc_bench_test.c)

# Link the test executable against our library and pthread
target_link_libraries(spmc_bench_test SPMCQueue pthread)

# Add the test
add_test(NAME SPMCTest COMMAND spmc_bench_test)
