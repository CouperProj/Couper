cmake_minimum_required(VERSION 3.20)
project(Vector_BF)

add_library(
    ${PROJECT_NAME}
    SHARED 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Vector_BF.cpp
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
    Couper
)

add_executable(
    test_VBF ${CMAKE_CURRENT_SOURCE_DIR}/src/test_VBF.cpp
)

target_link_libraries(
    test_VBF
    PUBLIC
    ${PROJECT_NAME}
    mylibpcap
)