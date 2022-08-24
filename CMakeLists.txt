cmake_minimum_required(VERSION 3.12)
project(apix)

set(CMAKE_MACOSX_RPATH 1)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall")
option(BUILD_DEBUG "Build with debug info." OFF)
if (BUILD_DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
    message(STATUS "Build with -g for debug")
else ()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    message(STATUS "Build without -g but with -O3 for release")
endif ()

option(BUILD_STATIC "Build static library" ON)
option(BUILD_SHARED "Build shared library" ON)

include_directories(src)
add_subdirectory(src)

option(BUILD_TESTS "Build all tests." OFF)
if (BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()

option(BUILD_DEMOS "Build all demos." OFF)
if (BUILD_DEMOS)
    add_subdirectory(demos)
endif ()
