add_compile_options(-std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb)

INCLUDE_DIRECTORIES("../libff-n" "../libsnark/src" "../libsnark/third_party" "../libff/src" "../libff/third_party" "../libfqfft/src" "../zcash_w/src")

add_library(msksnark STATIC ../donator2/interface.h)

LINK_DIRECTORIES("../libsnark/build/src" "../libsnark/build/third_party" "../libff/build/src" "../zcash_w/build")

target_link_libraries(msksnark pthread ssl crypto snark ff zm gmp stdc++ procps gmpxx bitcoin_crypto bitcoin_util bitcoin_common bitcoin_zmq zcash)
