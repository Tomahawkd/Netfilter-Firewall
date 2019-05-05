set(LIBEMU_DIR ../../lib/target/libemu)

include_directories(${LIBEMU_DIR}/include)
link_directories(${LIBEMU_DIR}/lib)

add_executable(test test_emu.c detection.h)
target_link_libraries(test emu)