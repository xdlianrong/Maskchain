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
class Msg
{
private:
   uint256 sn_old;
   uint256 new_comm;
   std::vector<bool>  c1_result1;
   std::vector<bool>  c1_result2;
   std::vector<bool>  c1_result3;
   std::vector<bool>  c2_result1;
   std::vector<bool>  c2_result2;
   std::vector<bool>  c2_result3;
   r1cs_ppzksnark_proof<ppT> proof;
public:
    void setsn_old(uint256 sn)
    {
        sn_old=sn;
    }
    void setnew_comm(uint256 com)
    {
        new_comm=com;
    }
    void setc1_result1(std::vector<bool>  c1_res1)
    {
        c1_result1=c1_res1;
    }
    void setc1_result2(std::vector<bool>  c1_res2)
    {
        c1_result2=c1_res2;
    }
    void setc1_result3(std::vector<bool>  c1_res3)
    {
        c1_result3=c1_res3;
    }
    void setc2_result1(std::vector<bool>  c2_res1)
    {
        c2_result1=c2_res1;
    }
    void setc2_result2(std::vector<bool>  c2_res2)
    {
        c2_result2=c2_res2;
    }
    void setc2_result3(std::vector<bool>  c2_res3)
    {
        c2_result3=c2_res3;
    }
    void setproof(r1cs_ppzksnark_proof<ppT> pro)
    {
        proof=pro;
    }
    uint256 getsn_old()
    {
        return sn_old;
    }
    uint256 getnew_comm()
    {
        return new_comm;
    }
    std::vector<bool>  getc1_result1()
    {
        return c1_result1;
    }
    std::vector<bool>  getc1_result2()
    {
        return c1_result2;
    }
    std::vector<bool>  getc1_result3()
    {
        return c1_result3;
    }
    std::vector<bool>  getc2_result1()
    {
        return c2_result1;
    }
    std::vector<bool>  getc2_result2()
    {
        return c2_result2;
    }
    std::vector<bool>  getc2_result3()
    {
        return c2_result3;
    }
    r1cs_ppzksnark_proof<ppT> getproof()
    {
        return proof;
    }
};
int main()
{
    Msg mess;
}