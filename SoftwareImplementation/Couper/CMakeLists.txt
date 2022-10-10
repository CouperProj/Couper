cmake_minimum_required(VERSION 3.20)

project(Couper)

add_library(
    Couper
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Couper.cpp
)

target_include_directories(
    Couper
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    Couper
    PUBLIC
    hashfunc
    utility
)

# test executable
add_executable(test_Couper ${CMAKE_CURRENT_SOURCE_DIR}/src/test_Couper.cpp)

target_link_libraries(
    test_Couper
    PRIVATE
    Couper
    mylibpcap
)