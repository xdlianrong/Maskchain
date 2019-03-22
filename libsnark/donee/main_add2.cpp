#include <iostream>
#include "common/default_types/ec_pp.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

using namespace std;
using namespace libsnark;

 #include <fstream>
/**
 * In this example, we show a very simple zero-knowledge proving procedure
 * using the r1cs ppzksnark proof system.
 *
 * In this simple example, we show that given vector x = (1,1,1,1,1,1,1,1,1,1)
 * we know another vector a such that: inner_product(x,a)=0
 * (yes, I know this is a trivial problem, but let's just focus on the ideas)
 */
  //验证者通过vk来区分，证明者是否使用的是同一个电路，也就是说vk必须是可信的，
  //证明者构造一个另外的电路，提供证明，验证者可以通过可信的vk和这个证明来验证，
  //证明者更换电路，或本身证明有问题，都能被验证出来
int main() {
  
  constexpr size_t dimension = 1; // Dimension of the vector
  using ppT = default_r1cs_ppzksnark_pp; // Use the default public parameters
  ppT::init_public_params(); // Initialize the libsnark

  using FieldT = ppT::Fp_type; // ppT is a specification for a collection of types, among which Fp_type is the base field
  const auto one = FieldT::one(); // constant
 
  protoboard<FieldT> pb; // The board to allocate gadgets
  pb_variable<FieldT> A; // The input wires (anchor) for x
  pb_variable<FieldT> B; // The input wires (anchor) for a
  pb_variable<FieldT> C; // The input wires (anchor) for a
  
  C.allocate(pb, "C");
  A.allocate(pb, "A");
  B.allocate(pb, "B");
  

  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(A+B,1, C),FMT(" S_%zu"));
  
  pb.set_input_sizes(dimension);
 
  
  //验证方从此注释
  //-----constructed----------------
  auto cs = pb.get_constraint_system();

  auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

  
  pb.val(A)=one;
  pb.val(B)=one;
  pb.val(C)=one+one;
   

  auto pi = pb.primary_input();
  auto ai = pb.auxiliary_input();

 
  r1cs_ppzksnark_proof<ppT> proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);

  proof.print_size();

  stringstream ss("");
  string proof_str;
  ss<<proof;
  proof_str=ss.str();

  //-----store-vk---------------
   ofstream out_vk("ser_vk_jimmyshi.data",ios::binary);
  if(!out_vk.is_open())
  {
    cout<<"file path error"<<endl;
  }
    
  out_vk<<keypair.vk;
  out_vk.flush();

  ofstream out_pk("ser_pk_jimmyshi.data",ios::binary);
  if(!out_pk.is_open())
  {
    cout<<"file path error"<<endl;
  }

  out_pk<<keypair.pk;
  out_pk.flush();

  //-------store-proof------------
  ofstream out_proof("ser_proof_old.data",ios::binary);
  if(!out_proof.is_open())
  {
    cout<<"file path error"<<endl;
  }
    
  out_proof<<proof;
  out_proof.flush();
  
  //-------------------------------------------
  //验证方从此注释
 

  //--------verify-----------------------------

  r1cs_ppzksnark_proof<ppT> proof1;
  r1cs_ppzksnark_verification_key<ppT> vk1;
  //-------load-vk------------
  //ifstream in_vk("ser_vk_old.data",ios::binary);
  ifstream in_vk("ser_vk_old.data",ios::binary);
  if(!in_vk.is_open())
  {
   cout<<"file open error"<<endl;
  }
  
  in_vk>>vk1;
  in_vk.close();

  /*
  //-------load-proof------------
  ifstream in_proof("ser_proof_old.data",ios::binary);
  if(!in_proof.is_open())
  {
   cout<<"file open error"<<endl;
  }
  
  in_proof>>proof1;
  in_proof.close();
  */
  cout<<"-------proof_str size "<<proof_str.size()<<endl;
  cout<<proof_str<<endl;
  stringstream ss1("");
  ss1<<proof_str;
  ss1>>proof1;
  cout<<proof1<<endl;
  //proof1=proof;

  cout<<"-----------------------------------------"<<endl;
  //proof1.print_size();

  pb.val(C)=one;

  auto pi_v = pb.primary_input();                

  //if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi_v,proof)) {
  if(r1cs_ppzksnark_verifier_strong_IC<ppT>(vk1,pi_v,proof1)) {
    cout << "Verified!" << endl;
  } else {
    cout << "Failed to verify!" << endl;
    }

  
  return 0;
}
