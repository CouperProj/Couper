cmake_minimum_required(VERSION 3.20)

project(hashfunc)

add_library(
    hashfunc
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/MurmurHash3.cpp
)

target_include_directories(
    hashfunc
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)