cmake_minimum_required(VERSION 3.20)

project(rerskt)

add_library(
    rerskt
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/rerskt.cpp
)

target_link_libraries(
    rerskt
    PUBLIC
    hashfunc
    utility
)

target_include_directories(
    rerskt
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(test_rerskt ${CMAKE_CURRENT_SOURCE_DIR}/src/test_rerskt.cpp)

target_link_libraries(
    test_rerskt
    PUBLIC
    rerskt
    mylibpcap
)