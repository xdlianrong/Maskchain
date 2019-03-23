
#include <ctime>
#include "common/default_types/ec_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

#include "crypto/sha256.h"
#include "uint256.h"

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

#include <iostream>
#include <string>  
#include <cstring>  
#include <cassert>  
#include <sys/time.h>
#include <fstream>


using namespace std;
using namespace libsnark;
using namespace libff;

using ppT = default_r1cs_ppzksnark_pp; 
using FieldT = ppT::Fp_type;

