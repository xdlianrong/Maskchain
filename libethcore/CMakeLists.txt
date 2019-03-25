file(GLOB sources "./*.cpp" "./*.h")
INCLUDE_DIRECTORIES("../libsnark/donator2" "../libsnark/libff-n" "../libsnark/libsnark/src" "../libsnark/libsnark/third_party" "../libsnark/libff/src" "../libsnark/libff/third_party" "../libsnark/libfqfft/src" "../libsnark/zcash_w/src")

LINK_DIRECTORIES("../libsnark/build" "../libsnark/libsnark/build/src" "../libsnark/libsnark/build/third_party" "../libsnark/libff/build/src" "../libsnark/zcash_w/build")


add_library(ethcore ${sources})

target_include_directories(ethcore PRIVATE "${UTILS_INCLUDE_DIR}")
target_link_libraries(ethcore PUBLIC devcrypto devcore msksnark pthread ssl crypto snark ff zm gmp stdc++ procps gmpxx bitcoin_crypto bitcoin_util bitcoin_common bitcoin_zmq zcash)
