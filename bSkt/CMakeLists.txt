cmake_minimum_required(VERSION 3.20)

project(bSkt)

add_library(
    ${PROJECT_NAME}
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/bSkt.cpp
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
    test_bSkt
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test_bSkt.cpp
)

target_link_libraries(
    test_bSkt
    PUBLIC
    ${PROJECT_NAME}
    mylibpcap
)