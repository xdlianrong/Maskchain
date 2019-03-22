#include <ctime>
#include "common/default_types/ec_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

#include "crypto/sha256.h"
#include "uint256.h"

#include <iostream>
#include <sys/time.h>
#include <fstream>

using namespace std;
using namespace libsnark;
using namespace libff;

using ppT = default_r1cs_ppzksnark_pp; 
int main()
    { 
    using ppT = default_r1cs_ppzksnark_pp; 
    ppT::init_public_params();
    using FieldT = ppT::Fp_type;
    typedef bigint<alt_bn128_r_limbs> bigint_r;
    char g_c[]="11112222333344445555666677778888999900001111";
    char sk[]="1234567891";
    FieldT g=bigint_r(g_c);
    FieldT Gsk = bigint_r(sk);//私钥
    FieldT Gpk = g ^ Gsk.as_bigint();//公钥

    //char Gpk_c[]="13123878885223272777090078949016337436257895988363033133970297130706679003319";
    //FieldT Gpk=bigint_r(Gpk_c);

    cout<<Gpk<<endl;
    }