file(GLOB sources "*.cpp" "*.h")

add_library(ethereum ${sources})

LINK_DIRECTORIES("/usr/local/lib" "../libsnark/build")
INCLUDE_DIRECTORIES("../libsnark/donator2" "../libsnark/libff-n" "../libsnark/libsnark/src" "../libsnark/libsnark/third_party" "../libsnark/libff/src" "../libsnark/libff/third_party" "../libsnark/libfqfft/src" "../libsnark/zcash_w/src")
LINK_DIRECTORIES("../libsnark/build" "../libsnark/libsnark/build" "../libsnark/libsnark/build/src" "../libsnark/libsnark/build/third_party" "../libsnark/libff/build/src" "../libsnark/zcash_w/build")


target_include_directories(ethereum PRIVATE "${UTILS_INCLUDE_DIR}")
target_link_libraries(ethereum PUBLIC evm ethcore p2p devcrypto devcore msksnark PRIVATE jsoncpp_lib_static Snappy::snappy Boost::fiber Boost::context)
