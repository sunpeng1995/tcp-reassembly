cmake_minimum_required(VERSION 2.8)

project(DST)

set(CMAKE_BUILD_TYPE "Debug")
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -std=c++11 -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O2 -std=c++11")

include_directories(include)
file(COPY test/ DESTINATION ./test/)

add_executable(resession src/main.cpp src/ReSession.cpp)
add_library(res SHARED src/ReSession.cpp src/toPython.cpp)