file(GLOB sources "*.cpp")
file(GLOB headers "*.h")

add_library(devcore ${sources} ${headers})

LINK_DIRECTORIES("/usr/local/lib" "../libsnark/build")
INCLUDE_DIRECTORIES("../libsnark/donator2" "../libsnark/libff-n" "../libsnark/libsnark/src" "../libsnark/libsnark/third_party" "../libsnark/libff/src" "../libsnark/libff/third_party" "../libsnark/libfqfft/src" "../libsnark/zcash_w/src")
LINK_DIRECTORIES("../libsnark/build" "../libsnark/libsnark/build" "../libsnark/libsnark/build/src" "../libsnark/libsnark/build/third_party" "../libsnark/libff/build/src" "../libsnark/zcash_w/build")

# Needed to prevent including system-level boost headers:
target_include_directories(devcore SYSTEM PUBLIC ${Boost_INCLUDE_DIR} PRIVATE ../utils)

target_link_libraries(devcore PUBLIC aleth-buildinfo Boost::filesystem Boost::system Boost::log Boost::thread Threads::Threads PRIVATE ethash::ethash)

find_package(LevelDB)
target_include_directories(devcore SYSTEM PUBLIC ${LEVELDB_INCLUDE_DIRS})
target_link_libraries(devcore PRIVATE ${LEVELDB_LIBRARIES})
