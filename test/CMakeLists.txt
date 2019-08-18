include_directories(${CMAKE_SOURCE_DIR}/test)

aux_source_directory(${CMAKE_SOURCE_DIR}/test SRCS)

add_executable(catch_test ${SRCS})

target_link_libraries(catch_test ${CONAN_LIBS})
