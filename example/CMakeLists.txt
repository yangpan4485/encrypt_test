aux_source_directory(${CMAKE_SOURCE_DIR}/example SRCS)

add_executable(encrypt_test ${SRCS})

target_link_libraries(encrypt_test ${CONAN_LIBS})
