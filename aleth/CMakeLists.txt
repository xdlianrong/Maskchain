set(
    sources
    AccountManager.cpp AccountManager.h
    main.cpp
    MinerAux.h
)
LINK_DIRECTORIES("/usr/local/lib" "../libsnark/build")
INCLUDE_DIRECTORIES("../libsnark/donator2" "../libsnark/libff-n" "../libsnark/libsnark/src" "../libsnark/libsnark/third_party" "../libsnark/libff/src" "../libsnark/libff/third_party" "../libsnark/libfqfft/src" "../libsnark/zcash_w/src")
LINK_DIRECTORIES("../libsnark/libsnark/build" "../libsnark/libsnark/build/src" "../libsnark/libsnark/build/third_party" "../libsnark/libff/build/src" "../libsnark/zcash_w/build")

add_executable(aleth ${sources})
target_link_libraries(
    aleth ethereum ethashseal evm web3jsonrpc webthree ethcore devcore Boost::program_options libmsksnark.a pthread ssl crypto snark ff zm gmp stdc++ procps gmpxx bitcoin_crypto bitcoin_util bitcoin_common bitcoin_zmq zcash
)

target_include_directories(aleth PRIVATE ../utils)

if(MINIUPNPC)
    target_compile_definitions(aleth PRIVATE ETH_MINIUPNPC)
endif()

install(TARGETS aleth DESTINATION bin)
