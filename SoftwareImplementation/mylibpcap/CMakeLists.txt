cmake_minimum_required(VERSION 3.20)

project(mylibpcap)

add_library(
    mylibpcap
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/mylibpcap.cpp
)

set(PATH_TO_LABPCAP  /home/xun/libpcap/libpcap-1.10.1)    # e.g. PATH_TO_LIB_PCAP == /home/username/libpcap/libpcap-1.10.1

target_include_directories(
    mylibpcap
    PUBLIC
    ${PATH_TO_LABPCAP} 
    ${CMAKE_CURRENT_SOURCE_DIR}/include/shared
)

target_link_libraries(
    mylibpcap 
    PUBLIC
    ${PATH_TO_LABPCAP}/libpcap.so.1.10.1
)