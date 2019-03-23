file(GLOB sources "*.cpp" "*.h")
INCLUDE_DIRECTORIES("../libsnark/libff-n" "../libsnark/libsnark/src" "../libsnark/libsnark/third_party" "../libsnark/libff/src" "../libsnark/libff/third_party" "../libsnark/libfqfft/src" "../libsnark/zcash_w/src")

LINK_DIRECTORIES("../libsnark/build/src" "../libsnark/build/third_party" "../libff/build/src" "../zcash_w/build")


add_library(ethcore ${sources})

target_include_directories(ethcore PRIVATE "${UTILS_INCLUDE_DIR}")
target_link_libraries(ethcore PUBLIC devcrypto devcore pthread ssl crypto snark ff zm gmp stdc++ procps gmpxx bitcoin_crypto bitcoin_util bitcoin_common bitcoin_zmq zcash)
