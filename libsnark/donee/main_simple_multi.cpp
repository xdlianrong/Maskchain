#include <iostream>
#include "common/default_types/ec_pp.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

using namespace std;
using namespace libsnark;

/**
 * In this example, we show a very simple zero-knowledge proving procedure
 * using the r1cs ppzksnark proof system.
 *
 * In this simple example, we show that given vector x = (1,1,1,1,1,1,1,1,1,1)
 * we know another vector a such that: inner_product(x,a)=0
 * (yes, I know this is a trivial problem, but let's just focus on the ideas)
 */

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
  

  pb.add_r1cs_constraint(r1cs_constraint<FieldT>(A, B, C),FMT(" S_%zu"));
  pb.set_input_sizes(dimension);

  auto cs = pb.get_constraint_system();

  auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

  
  pb.val(A)=one;
  pb.val(B)=one+one;
  pb.val(C)=one+one;
   

  auto pi = pb.primary_input();
  auto ai = pb.auxiliary_input();

  auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);

  pb.val(C)=one;

  pi = pb.primary_input();                

  if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi,proof)) {
    cout << "Verified!" << endl;
  } else {
    cout << "Failed to verify!" << endl;
    }

  
  return 0;
}
