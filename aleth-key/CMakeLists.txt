add_executable(aleth-key KeyAux.h main.cpp)
LINK_DIRECTORIES(
	../build/deps/lib
)
target_include_directories(aleth-key PRIVATE ../build/deps/include ../build/deps/include/libff ../build/deps/include/libsnark)
target_link_libraries(aleth-key PRIVATE msksnark ethcore devcore Boost::program_options)
install(TARGETS aleth-key EXPORT alethTargets DESTINATION bin)
