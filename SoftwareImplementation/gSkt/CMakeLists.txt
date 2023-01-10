cmake_minimum_required(VERSION 3.20)

project(gSkt)

add_library(
    ${PROJECT_NAME}
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/gSkt.cpp
)

target_include_directories(
    ${PROJECT_NAME}
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    ${PROJECT_NAME}
    PUBLIC
    hashfunc
    utility
)

add_executable(
    test_gSkt
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test_gSkt.cpp
)

target_link_libraries(
    test_gSkt
    PUBLIC
    ${PROJECT_NAME}
    mylibpcap
)