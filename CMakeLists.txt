cmake_minimum_required(VERSION 3.0)

project(encrypt)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup()

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/src/common)
include_directories(${CMAKE_SOURCE_DIR}/src/secret_key_generator)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INSTALL_PREFIX ${CMAKE_SOURCE_DIR}/out)

aux_source_directory(${CMAKE_SOURCE_DIR}/src SRCS)
aux_source_directory(${CMAKE_SOURCE_DIR}/src/common SRCS)
aux_source_directory(${CMAKE_SOURCE_DIR}/src/secret_key_generator SRCS)

# if(BUILD_EXAMPLE)
    add_subdirectory(example)
# endif()

# if(BUILD_TEST)
    add_subdirectory(test)
# endif()
