add_compile_options(-std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb)

#INCLUDE_DIRECTORIES("./libsnark/src" "./libsnark/third_party" "./libff-n" "./libff/src" "./libff/third_party" "./libfqfft/src" "./zcash_w/src" "./zcash_w/src/crypto")
INCLUDE_DIRECTORIES("./libsnark/src" "./libsnark/third_party" "./libff/src" "./libff/third_party" "./libfqfft/src" "./zcash_w/src" "./donator2" "./zcash_w/src/crypto")
add_library(msksnark STATIC "donator2/fuckaround.cpp" "donator2/interface.h")

LINK_DIRECTORIES("./" "./libsnark/build/src" "./libsnark/build/third_party" "./libff/build/src" "./zcash_w/build" "./donator2")

target_link_libraries(msksnark pthread ssl crypto snark ff zm gmp stdc++ procps gmpxx bitcoin_crypto bitcoin_util bitcoin_common bitcoin_zmq zcash)
