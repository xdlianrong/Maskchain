add_library(msksnark interface.cpp interface.h uint256.h)

target_include_directories(msksnark PRIVATE ../build/deps/include ../build/deps/include/libff ../build/deps/include/libsnark ../build/deps/include/libfqfft)

target_link_libraries(msksnark PRIVATE ff ssl snark bitcoin_crypto bitcoin_util bitcoin_common bitcoin_zmq gmp gmpxx)
