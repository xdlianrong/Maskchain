/** @file
 *****************************************************************************
 Unit tests for gadgetlib1 - main() for running all tests
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#include <iostream>
#include <ctime>
#include "common/default_types/ec_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"



using namespace std;
using namespace libsnark;
using namespace libff;


using ppT = default_r1cs_ppzksnark_pp;
using FieldT = ppT::Fp_type;
typedef bigint<alt_bn128_r_limbs> bigint_r;



template<typename FieldT>
class exp_gadget : public gadget<FieldT> {
private:
    /* S_i = \sum_{k=0}^{i+1} A[i] * B[i] */
    pb_variable_array<FieldT> _A;
    pb_variable_array<FieldT> temp1;
    pb_variable_array<FieldT> temp2;
    pb_variable_array<FieldT> temp3;
    FieldT g;
public:
    const pb_linear_combination_array<FieldT> A;
    const pb_variable<FieldT> result;

    exp_gadget(FieldT g, protoboard<FieldT>& pb,
                         const pb_linear_combination_array<FieldT> &A,//y
                         const pb_variable<FieldT> &result,
                         const std::string &annotation_prefix="") :
        gadget<FieldT>(pb, annotation_prefix), A(A), g(g), result(result)
    {
        // assert(A.size() >= 1);
        // assert(A.size() == B.size());

        // S.allocate(pb, A.size()-1, FMT(this->annotation_prefix, " S"));
        _A.allocate(pb, A.size(), FMT(this->annotation_prefix, " _A"));
        temp1.allocate(pb, A.size(), FMT(this->annotation_prefix, " temp1"));
        temp2.allocate(pb, A.size(), FMT(this->annotation_prefix, " temp2"));
        temp3.allocate(pb, A.size()-2, FMT(this->annotation_prefix, " temp3"));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};
template<typename FieldT>
void exp_gadget<FieldT>::generate_r1cs_constraints()
{
    
    for (size_t i = 0; i < A.size(); ++i)
    {
      this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(FieldT::one() - A[i], FieldT::one(), _A[i]),
        FMT(this->annotation_prefix, " S_%zu", i));
      this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(A[i], g ^ ((FieldT::one()*2) ^ bigint_r(i)).as_bigint(), temp1[i]),
        FMT(this->annotation_prefix, " S_%zu", i));
      this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(_A[i] + temp1[i] , FieldT::one(), temp2[i]),
        FMT(this->annotation_prefix, " S_%zu", i));     
    }
    for (size_t i = 0; i < temp3.size()+1; ++i)
    {
      this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(i==0 ? temp2[0] : temp3[i-1], temp2[i+1], i==temp3.size() ? result : temp3[i]),
        FMT(this->annotation_prefix, " S_%zu", i));
    }

}

template<typename FieldT>
void exp_gadget<FieldT>::generate_r1cs_witness()
{
    FieldT total = FieldT::one();
    for (size_t i = 0; i < A.size(); ++i)
    {
        A[i].evaluate(this->pb);
        this->pb.val(_A[i]) = FieldT::one() - this->pb.lc_val(A[i]);
        this->pb.val(temp1[i]) = this->pb.lc_val(A[i]) * (g ^ ((FieldT::one()*2) ^ bigint_r(i)).as_bigint());
        this->pb.val(temp2[i]) = this->pb.lc_val(_A[i]) + this->pb.val(temp1[i]) ;
    }
    for (size_t i = 0; i < temp3.size()+1; ++i){
      this->pb.val(i == temp3.size() ? result : temp3[i]) = (i==0 ? this->pb.val(temp2[0]) : this->pb.val(temp3[i-1]) ) * this->pb.val(temp2[i+1]);
    }
    
}


int main() {

  ppT::init_public_params(); 

  
  const FieldT g = bigint_r("10");//生成元
  const FieldT Gsk = bigint_r("123456789");//私钥
  const FieldT Gpk = g ^ Gsk.as_bigint();//公钥
  
  
  //电路设计
  protoboard<FieldT> pb;
  pb_variable_array<FieldT> random_y;
  pb_variable<FieldT> message;
  pb_variable<FieldT> crypto1;
  pb_variable<FieldT> crypto2;
  pb_variable<FieldT> result1;
  pb_variable<FieldT> result2;

  crypto1.allocate(pb,"crypto1");
  crypto2.allocate(pb,"crypto2");
  random_y.allocate(pb,253,"random_y");
  message.allocate(pb,"message");
  result1.allocate(pb,"result1");
  result2.allocate(pb,"result2");

  //约束：random_y[i]是布尔值
  for(int i=0; i<253;i++){
    generate_boolean_r1cs_constraint(pb,pb_linear_combination<FieldT>(random_y[i]));
  }
  
  //约束：g ^ y == c1
  exp_gadget<FieldT> exp1(g,pb,random_y,result1,"qwe");
  exp1.generate_r1cs_constraints();
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result1, FieldT::one(), crypto1),FMT(" S_%zu"));
  
  //约束：m * (Gpk ^ y) == c2
  exp_gadget<FieldT> exp2(Gpk,pb,random_y,result2,"qwe");
  exp2.generate_r1cs_constraints();
  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result2, message, crypto2),FMT(" S_%zu"));


  //产生密钥对
  auto cs = pb.get_constraint_system();
  auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

  
  
  //证明者
  //选取随机数y
  srand(unsigned(time(0)));
  vector<FieldT> Y;
  FieldT y = FieldT::zero();
  for(int i=0;i<253;i++){
    Y.push_back(FieldT::one()*(rand()%2));
    y += Y[i] * ((FieldT::one()*2) ^ bigint_r(i));
  }

  //明文m
  FieldT m = bigint_r("111111111111111");

  //生成密文c1，c2
  FieldT c1 = g ^ y.as_bigint();
  FieldT c2 = m * (Gpk ^ y.as_bigint());

  //生成证明
  for(int i=0;i<253;i++){
    pb.val(random_y[i]) = Y[i];
  }
  pb.val(crypto1) = g ^ y.as_bigint();
  pb.val(crypto2) = (Gpk ^ y.as_bigint()) * m;
  pb.val(message) = m;
  exp1.generate_r1cs_witness();
  exp2.generate_r1cs_witness();

  auto pi = pb.primary_input();
  auto ai = pb.auxiliary_input();
  auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
  

  //验证者

  if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi,proof)) {
    cout << "Verified!" << endl;
  } 
  else {
    cout << "Failed to verify!" << endl;
  }
  

   //监管者
  //解密
  FieldT s = c1 ^ Gsk.as_bigint();
  (c2 * s.inverse()).print();

  m.print();

  return 0;
  }
  

