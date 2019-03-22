#include <iostream>
#include "common/default_types/ec_pp.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

using namespace std;
using namespace libsnark;
using namespace libff;

using ppT = default_r1cs_ppzksnark_pp;
using FieldT = ppT::Fp_type;
typedef bigint<alt_bn128_r_limbs> bigint_r;
//bigint 属于 mod p 的素数域， p为 2^253 ~ 2^254 之间的素数 
int main() {
  
  ppT::init_public_params(); 

  const FieldT g = bigint_r("2");//生成元

  FieldT r_max0 = bigint_r("251");//最大指数
  FieldT x_max0 = g ^ r_max0.as_bigint();

  FieldT r_max1 = bigint_r("252");//最大指数
  FieldT x_max1 = g ^ r_max1.as_bigint();
  

  FieldT r_max2 = bigint_r("253");//最大指数
  FieldT x_max2 = g ^ r_max2.as_bigint();
 

  FieldT r_max3 = bigint_r("254");//最大指数
  FieldT x_max3 = g ^ r_max3.as_bigint();
  
  FieldT r_max4 = bigint_r("21888242871839275222246405745257275088548364400416034343698204186575808495617");//最大指数
  FieldT x_max4 = g ^ r_max4.as_bigint();
  
  x_max0.print();
  x_max1.print();
  x_max2.print();
  x_max3.print();
  x_max4.print();

  r_max4=r_max4-1;
  r_max4.print();
  r_max4=r_max4+1;
  r_max4.print();

  return 0;
}
