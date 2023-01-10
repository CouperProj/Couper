cmake_minimum_required(VERSION 3.20)

project(CardinalityEstimation)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/mylibpcap)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/MurmurHash3)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Couper)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/gSkt)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/rerskt)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/VHS)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/util)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/SpreadSketch)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Vector_BF)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/CDS) 