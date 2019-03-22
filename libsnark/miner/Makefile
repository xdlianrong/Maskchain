OPTIONS = -std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb
INCLUDE = -I../libsnark/src -I../libsnark/third_party -I../libff/src -I../libff/third_party -I../libfqfft/src  -I../zcash_w/src
LIBPATH = -L../libsnark/build/src -L../libsnark/build/third_party -L../libff/build/src -L../zcash_w/build
LIBS    = -lpthread -lsnark -lff -lzm -lgmp -lstdc++ -lprocps -lgmpxx -lbitcoin_crypto -lbitcoin_util -lbitcoin_common -lbitcoin_zmq -lzcash
GCC		= g++

miner: main.cpp 
	$(GCC) $< -o $@ $(OPTIONS) $(INCLUDE) $(LIBPATH) $(LIBS) 