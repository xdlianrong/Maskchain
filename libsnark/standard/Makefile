OPTIONS = -std=c++11 -DCURVE_ALT_BN128 -ggdb
INCLUDE = -I../libsnark/src -I../libsnark/third_party -I../libff/src -I../libff/third_party -I../libfqfft/src
LIBPATH = -L../libsnark/build/src -L../libsnark/build/third_party
LIBS    = -lsnark -lff -lzm -lgmp -lstdc++ -lprocps -lgmpxx
GCC			= g++

example: simple_example.hpp simple_example.tcc main.cpp
	$(GCC) main.cpp -o $@ $(OPTIONS) $(INCLUDE) $(LIBPATH) $(LIBS)
