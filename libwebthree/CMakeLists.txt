add_library(webthree WebThree.cpp WebThree.h)
target_include_directories(webthree PRIVATE ../utils ../build/deps/include/libff ../build/deps/include/libsnark)
target_link_libraries(webthree PUBLIC ethereum p2p devcore)
