#include "common/default_types/ec_pp.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp"
#include "simple_example.hpp"

using namespace std;
using namespace libsnark;

int main() {
	const size_t num_constraints = 2;
	libff::init_alt_bn128_params();
	auto r1cs = gen_r1cs_example_from_protoboard<default_r1cs_ppzksnark_pp::Fp_type> (
			num_constraints
	);
	run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(r1cs,true);
	return 0;
}
