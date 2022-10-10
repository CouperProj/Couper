CMAKE_MINIMUM_REQUIRED(VERSION 3.20)

project(CDS)

add_library(
    ${PROJECT_NAME}
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/cds.cpp
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
    test_CDS
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test_cds.cpp
)

target_link_libraries(
    test_CDS
    PUBLIC
    ${PROJECT_NAME}
    mylibpcap
)