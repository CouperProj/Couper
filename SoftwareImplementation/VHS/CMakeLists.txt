cmake_minimum_required(VERSION 3.20)

project(VHS)

add_library(
    ${PROJECT_NAME}
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/VHS.cpp
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
    test_VHS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test_VHS.cpp
)

target_link_libraries(
    test_VHS
    PUBLIC
    ${PROJECT_NAME}
    mylibpcap
    utility
)