CMAKE_MINIMUM_REQUIRED(VERSION 3.20)

project(utility)

add_library(
    ${PROJECT_NAME}
    INTERFACE
)

target_include_directories(
    ${PROJECT_NAME}
    INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    ${PROJECT_NAME}
    INTERFACE
    mylibpcap
)