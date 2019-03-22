/** @file
 *****************************************************************************
 Unit tests for gadgetlib1 - main() for running all tests
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/


#include <ctime>
//#include "common/default_types/r1cs_ppzksnark_pp.hpp"
//#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
//#include "gadgetlib1/gadget.hpp"
//#include "gadgetlib1/gadgets/basic_gadgets.hpp"

#include "common/default_types/ec_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

//#include "util.h"
#include "crypto/sha256.h"
#include "uint256.h"

#include <iostream>
#include <sys/time.h>

using namespace std;
using namespace libsnark;
//using namespace libff;

using ppT = default_r1cs_ppzksnark_pp; // Use the default public parameters
using FieldT = ppT::Fp_type; 
//typedef signed long long int64_t;

/*
uint256 Note::cm() const {
    unsigned char discriminant = 0xb0;

    CSHA256 hasher;
    hasher.Write(&discriminant, 1);
    hasher.Write(a_pk.begin(), 32);

    auto value_vec = convertIntToVectorLE(value);

    hasher.Write(&value_vec[0], value_vec.size());
    hasher.Write(rho.begin(), 32);
    hasher.Write(r.begin(), 32);

    uint256 result;
    hasher.Finalize(result.begin());

    return result;
}

*/

void test_hash()
{
    
    CSHA256 hasher;
    
    uint256 left = uint256S("426bc2d84dc8678281e8957a409ec148e6cffbe8afe6ba4f9c6f1978dd7af7e9");
    uint256 right = uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 hash = uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");
        
    hasher.Write(left.begin(), 32);
    hasher.Write(right.begin(), 32);
    uint256 result;
    hasher.Finalize(result.begin());

    //cout<<result.ToString();
    if(result== hash){
        cout<<"ok";
    }else{
        cout<<"fail";
    }
   //uint256_to_bool_vector
}

std::vector<unsigned char> convertIntToVectorLE(const uint64_t val_int) {
    std::vector<unsigned char> bytes;

    for(size_t i = 0; i < 8; i++) {
        bytes.push_back(val_int >> (i * 8));
    }

    return bytes;
}

std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes) {
    std::vector<bool> ret;
    ret.resize(bytes.size() * 8);

    unsigned char c;
    for (size_t i = 0; i < bytes.size(); i++) {
        c = bytes.at(i);
        for (size_t j = 0; j < 8; j++) {
            ret.at((i*8)+j) = (c >> (7-j)) & 1;
        }
    }

    return ret;
}
//uint256->vector<bool>->pb_variable_array<FieldT>，使用fill_with_bits：
//zk_vpub_old.fill_with_bits(this->pb,uint64_to_bool_vector(vpub_old)));
std::vector<bool> uint256_to_bool_vector(uint256 input) {
    std::vector<unsigned char> input_v(input.begin(), input.end());

    return convertBytesVectorToVector(input_v);
}

template<typename FieldT>
linear_combination<FieldT> packed_addition(pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return pb_packing_sum<FieldT>(pb_variable_array<FieldT>(
        input_swapped.rbegin(), input_swapped.rend()
    ));
}



uint256 combine(const uint256& a, const uint256& b)
{
    uint256 res ;

    CSHA256 hasher;
    hasher.Write(a.begin(), 32);
    hasher.Write(b.begin(), 32);
    hasher.FinalizeNoPadding(res.begin());

    return res;
}


template<typename FieldT>
class comment_gadget  {
private:
       
    std::shared_ptr< sha256_two_to_one_hash_gadget<FieldT> > f1;
    std::shared_ptr< sha256_two_to_one_hash_gadget<FieldT> > f2;

public:
    const pb_linear_combination_array<FieldT> A;
    const pb_variable<FieldT> apk;
    const pb_variable<FieldT> v;
    const pb_variable<FieldT> r;
    const pb_variable<FieldT> result;

    comment_gadget(protoboard<FieldT>& pb,
                         std::shared_ptr<digest_variable<FieldT>> left1,
                         std::shared_ptr<digest_variable<FieldT>> right1,
                         std::shared_ptr<digest_variable<FieldT>> output1,
                         std::shared_ptr<digest_variable<FieldT>> left2,
                         std::shared_ptr<digest_variable<FieldT>> right2,
                         std::shared_ptr<digest_variable<FieldT>> output2,
                         const std::string &annotation_prefix="")
    {
        /*
        u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
        u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");
        u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
        u4=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d3");

        u_12=combine(u1,u2);
        u_34=combine(u3,u4);
        */

       f1.reset(new sha256_two_to_one_hash_gadget<FieldT>(pb, *left1, *right1, *output1, "f"));
       f2.reset(new sha256_two_to_one_hash_gadget<FieldT>(pb, *left2, *right2, *output2, "f"));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
void comment_gadget<FieldT>::generate_r1cs_constraints()
{
    f1->generate_r1cs_constraints();
    f2->generate_r1cs_constraints();
}

template<typename FieldT>
void comment_gadget<FieldT>::generate_r1cs_witness()
{

    /*
    libff::bit_vector left1_bv =  uint256_to_bool_vector(u1);
    libff::bit_vector right1_bv = uint256_to_bool_vector(u2);
    libff::bit_vector out1_bv = uint256_to_bool_vector(u_12);
    
    libff::bit_vector left2_bv =  uint256_to_bool_vector(u3);
    libff::bit_vector right2_bv = uint256_to_bool_vector(u4);
    libff::bit_vector out2_bv = uint256_to_bool_vector(u_34);

    left1.generate_r1cs_witness(left1_bv);
    right1.generate_r1cs_witness(right1_bv);
    f1->generate_r1cs_witness();
    output1.generate_r1cs_witness(out1_bv);
   

    left2.generate_r1cs_witness(left2_bv);
    right2.generate_r1cs_witness(right2_bv);  
    f2->generate_r1cs_witness();
    output2.generate_r1cs_witness(out2_bv);
    */
}


template<typename FieldT>
void testcm(uint256 apk,int64_t v,uint256 r){

    

    /*
    protoboard<FieldT> pb;

    digest_variable<FieldT> left(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output(pb, SHA256_digest_size, "output");

    sha256_two_to_one_hash_gadget<FieldT> f(pb, left, right, output, "f");
    f.generate_r1cs_constraints();

   
    uint256 left_u=apk;
    auto value_vec1 = convertIntToVectorLE(v);//8个字节
    auto value_vec2 = convertIntToVectorLE(v);//8个字节
    auto value_vec3 = convertIntToVectorLE(v);//8个字节
    auto value_vec4 = convertIntToVectorLE(v);//8个字节

    uint256 right_u=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 hash_u=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");
   
   

    CSHA256 hasher;
    hasher.Write(apk.begin(), 32);
    hasher.Write(right_u.begin(), 32);
    uint256 result_u;
    hasher.FinalizeNoPadding(result_u.begin());
        
    
    const libff::bit_vector left_bv = libff::int_list_to_bits({0x426bc2d8, 0x4dc86782, 0x81e8957a, 0x409ec148, 0xe6cffbe8, 0xafe6ba4f, 0x9c6f1978, 0xdd7af7e9}, 32);
    const libff::bit_vector right_bv = libff::int_list_to_bits({0x038cce42, 0xabd366b8, 0x3ede7e00, 0x9130de53, 0x72cdf73d, 0xee825114, 0x8cb48d1b, 0x9af68ad0}, 32);
    const libff::bit_vector result_bv = libff::int_list_to_bits({0xeffd0b7f, 0x1ccba116, 0x2ee816f7, 0x31c62b48, 0x59305141, 0x990e5c0a, 0xce40d33d, 0x0b1167d1}, 32);

    left.generate_r1cs_witness(left_bv);
    right.generate_r1cs_witness(right_bv);
  
    f.generate_r1cs_witness();
    output.generate_r1cs_witness(result_bv);

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
    */
}
template<typename FieldT>
class digest_selector_gadget : public gadget<FieldT> {
public:
    size_t digest_size;
    digest_variable<FieldT> input;
    pb_linear_combination<FieldT> is_right;
    digest_variable<FieldT> left;
    digest_variable<FieldT> right;

    digest_selector_gadget(protoboard<FieldT> &pb,
                           const size_t digest_size,
                           const digest_variable<FieldT> &input,
                           const pb_linear_combination<FieldT> &is_right,
                           const digest_variable<FieldT> &left,
                           const digest_variable<FieldT> &right,
                           const std::string &annotation_prefix):
    gadget<FieldT>(pb, annotation_prefix), digest_size(digest_size)
        , input(input), is_right(is_right), left(left), right(right)
    {
    }

    void generate_r1cs_constraints()
    {
        for (size_t i = 0; i < digest_size; ++i)
        {
            /*
            input = is_right * right + (1-is_right) * left
            input - left = is_right(right - left)
            */
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(is_right, right.bits[i] - left.bits[i], input.bits[i] - left.bits[i]),
                                        FMT(this->annotation_prefix, " propagate_%zu", i));
        }
    }

    void generate_r1cs_witness()
    {
        is_right.evaluate(this->pb);

        assert(this->pb.lc_val(is_right) == FieldT::one() || this->pb.lc_val(is_right) == FieldT::zero());
        if (this->pb.lc_val(is_right) == FieldT::one())
        {
            for (size_t i = 0; i < digest_size; ++i)
            {
                this->pb.val(right.bits[i]) = this->pb.val(input.bits[i]);
            }
        }
        else
        {
            for (size_t i = 0; i < digest_size; ++i)
            {
                this->pb.val(left.bits[i]) = this->pb.val(input.bits[i]);
            }
        }
    }
};


class MerklePath{
    public:
    std::vector<uint256> nodeHashList;
    std::vector<uint256> parentList;
    std::vector<int> pathisrightList;
    uint256 root;
    uint256 leaf;
};
MerklePath getMerkleTreePath(){

    //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");
    uint256 u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    uint256 u4=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d3");

    uint256 u5=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a10");
    uint256 u6=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b116721");
    uint256 u7=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a32");
    uint256 u8=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b116743");

    uint256 u9=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af18ad0");
    uint256 u10=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b2167d1");
    uint256 u11=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9a368ad2");
    uint256 u12=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b4167d3");

    uint256 u13=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9a568a10");
    uint256 u14=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9a568a10");
    uint256 u15=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9a568a10");
    uint256 u16=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9a568a10");

    //中间节点
    uint256 u_12=combine(u1,u2);
    uint256 u_34=combine(u3,u4);

    uint256 u_56=combine(u5,u6);
    uint256 u_78=combine(u7,u8);

    uint256 u_1234=combine(u_12,u_34);
    uint256 u_5678=combine(u_56,u_78);

    uint256 u_910=combine(u9,u10);
    uint256 u_1112=combine(u11,u12);

    uint256 u_1314=combine(u13,u14);
    uint256 u_1516=combine(u15,u16);

    uint256 u_912=combine(u_910,u_1112);
    uint256 u_1316=combine(u_1314,u_1516);

    uint256 u_1_8=combine(u_1234,u_5678);
    uint256 u_9_16=combine(u_912,u_1316);

    //根
    uint256 root=combine(u_1_8,u_9_16);

    std::vector<uint256> nodelist;
    std::vector<uint256> parentList;
    std::vector<int> pathisrightList;

    nodelist.push_back(u3);
    nodelist.push_back(u4);

    parentList.push_back(u_34);
    pathisrightList.push_back(0);

    nodelist.push_back(u_12);
    nodelist.push_back(u_34);

    parentList.push_back(u_1234);
    pathisrightList.push_back(1);

    nodelist.push_back(u_1234);
    nodelist.push_back(u_5678);
    
    parentList.push_back(u_1_8);
    pathisrightList.push_back(0);

    nodelist.push_back(u_1_8);
    nodelist.push_back(u_9_16);
    
    parentList.push_back(root);
    pathisrightList.push_back(0);
  
    MerklePath mp;
    mp.nodeHashList=nodelist;
    mp.parentList=parentList;
    mp.pathisrightList=pathisrightList;
    mp.root=root;
    mp.leaf=u3;

    return mp;
}

#define TREE_DEEPTH 4
template<typename FieldT>
class tree_gadget : public gadget<FieldT> {
private:
    
    std::vector<digest_variable<FieldT>> child;
    std::vector<digest_variable<FieldT>> parent;
    std::vector<digest_variable<FieldT>> input;
    pb_variable_array<FieldT> is_right;

    std::shared_ptr<digest_variable<FieldT>> leaf;
    std::shared_ptr<digest_variable<FieldT>> root;

    std::vector<sha256_two_to_one_hash_gadget<FieldT>> hasher;
    std::vector<digest_selector_gadget<FieldT>> selector;
public:
    tree_gadget(protoboard<FieldT>& pb, const std::string &annotation_prefix="") :
    gadget<FieldT>(pb, annotation_prefix)
    {
        is_right.allocate(pb,TREE_DEEPTH,"is_right");
       
        for(size_t i=0;i<2*TREE_DEEPTH;i++){
            child.push_back(digest_variable<FieldT>(this->pb, SHA256_digest_size, "child"));
        }
       
        for(size_t i=0;i<TREE_DEEPTH;i++){
           
            parent.push_back(digest_variable<FieldT>(this->pb, SHA256_digest_size, "parent"));

            input.push_back(digest_variable<FieldT>(this->pb, SHA256_digest_size, "input"));
            hasher.push_back(sha256_two_to_one_hash_gadget<FieldT>(this->pb, child[i*2], child[i*2+1], parent[i], "hasher"));
            selector.push_back(digest_selector_gadget<FieldT>(this->pb,SHA256_digest_size,input[i],pb_linear_combination<FieldT>(is_right[i]),child[i*2],child[i*2+1],"selector"));
        }
      
        leaf.reset(new digest_variable<FieldT>(this->pb, SHA256_digest_size, "leaf") );
        root.reset(new digest_variable<FieldT>(this->pb, SHA256_digest_size, "root") );
       
    }

    void add_digest_equal(digest_variable<FieldT> &d1,digest_variable<FieldT> &d2){
        for(size_t i=0;i<256;i++){
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(d1.bits[i]
            , FieldT::one(), d2.bits[i]),FMT(" S_%zu"));
        }
    }

    void generate_r1cs_constraints(){

        for(size_t i=0;i<TREE_DEEPTH;i++){
           generate_boolean_r1cs_constraint(this->pb,pb_linear_combination<FieldT>(is_right[i]));
        }
        
        for(size_t i=0;i<TREE_DEEPTH;i++){
           hasher[i].generate_r1cs_constraints();
           selector[i].generate_r1cs_constraints();
        } 
        
        for(size_t i=0;i<TREE_DEEPTH;i++){
          if(i==0){
                add_digest_equal(input[0],*leaf);
          }
          else if(i== TREE_DEEPTH-1){
                add_digest_equal(*root,parent[TREE_DEEPTH-1]);

                add_digest_equal(input[i],parent[i-1]);
          }else{
                add_digest_equal(input[i],parent[i-1]);
          }
   
        }
       

    }

    void generate_r1cs_witness(std::vector<uint256> child_ui256_list,std::vector<uint256> parent_ui256_list
                                ,std::vector<int> path
                                ,uint256 leaf_ui256
                                ,uint256 root_ui256){
        
      
        libff::bit_vector bv_l;
        libff::bit_vector bv_r;
        libff::bit_vector bv_p;
        
        leaf->generate_r1cs_witness(uint256_to_bool_vector(leaf_ui256));
        root->generate_r1cs_witness(uint256_to_bool_vector(root_ui256));

        for(size_t i=0;i<TREE_DEEPTH;i++){
            bv_l =  uint256_to_bool_vector(child_ui256_list[i*2]);
            bv_r =  uint256_to_bool_vector(child_ui256_list[i*2+1]);
            bv_p =  uint256_to_bool_vector(parent_ui256_list[i]);
            
            if(path[i] ==1){
                this->pb.val(is_right[i])=FieldT::one();
                input[i].generate_r1cs_witness(bv_r);
            }
            if(path[i] ==0){
                this->pb.val(is_right[i])=FieldT::zero();
                input[i].generate_r1cs_witness(bv_l);
            }

            selector[i].generate_r1cs_witness();

            child[i*2].generate_r1cs_witness(bv_l);
            child[i*2+1].generate_r1cs_witness(bv_r);
            hasher[i].generate_r1cs_witness();
            parent[i].generate_r1cs_witness(bv_p);
            
        } 
    }
};



template<typename FieldT>
void test_tree()
{
    using ppT = default_r1cs_ppzksnark_pp; 

    struct timeval tvafter,tvpre;
    struct timezone tz;

    protoboard<FieldT> pb;

    tree_gadget<FieldT> tree_gad(pb, "tree");
    cout<<"0"<<endl;
    tree_gad.generate_r1cs_constraints();
    cout<<"1"<<endl;
    auto cs = pb.get_constraint_system();
    cout<<"2"<<endl;
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
    cout<<"3"<<endl;
    MerklePath path=getMerkleTreePath();
    cout<<"4"<<endl;
    tree_gad.generate_r1cs_witness(path.nodeHashList,path.parentList
                                ,path.pathisrightList
                                ,path.leaf
                                ,path.root);
    cout<<"5"<<endl;
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    
   
    gettimeofday (&tvpre , &tz);

    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi,proof)) {
    cout << "Verified!" << endl;
    } else {
    cout << "Failed to verify!" << endl;
    }

    gettimeofday (&tvafter , &tz);
    cout << "time "<<(tvafter.tv_sec-tvpre.tv_sec)*1000+(tvafter.tv_usec-tvpre.tv_usec)/1000<< endl;
    /*
    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }*/
}

template<typename FieldT>
void test_two_to_one()
{
    using ppT = default_r1cs_ppzksnark_pp; 

    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");
    uint256 u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    uint256 u4=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d3");

    uint256 u_12=combine(u1,u2);
    uint256 u_34=combine(u3,u4);


    struct timeval tvafter,tvpre;
    struct timezone tz;

    

    protoboard<FieldT> pb;

     //---------1-----------------
    digest_variable<FieldT> left1(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right1(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output1(pb, SHA256_digest_size, "output");

    digest_variable<FieldT> left2(pb, SHA256_digest_size, "left");
    digest_variable<FieldT> right2(pb, SHA256_digest_size, "right");
    digest_variable<FieldT> output2(pb, SHA256_digest_size, "output");


    sha256_two_to_one_hash_gadget<FieldT> f1(pb, left1, right1, output1, "f");
    sha256_two_to_one_hash_gadget<FieldT> f2(pb, left2, right2, output2, "f");
    
    

    f1.generate_r1cs_constraints();
    f2.generate_r1cs_constraints();

   
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

    libff::bit_vector left1_bv =  uint256_to_bool_vector(u1);
    libff::bit_vector right1_bv = uint256_to_bool_vector(u2);
    libff::bit_vector out1_bv = uint256_to_bool_vector(u_12);
    
    libff::bit_vector left2_bv =  uint256_to_bool_vector(u3);
    libff::bit_vector right2_bv = uint256_to_bool_vector(u4);
    libff::bit_vector out2_bv = uint256_to_bool_vector(u_34);

    left1.generate_r1cs_witness(left1_bv);
    right1.generate_r1cs_witness(right1_bv);
    f1.generate_r1cs_witness();
    output1.generate_r1cs_witness(out1_bv);
   

    left2.generate_r1cs_witness(left2_bv);
    right2.generate_r1cs_witness(right2_bv);  
    f2.generate_r1cs_witness();
    output2.generate_r1cs_witness(out2_bv);

    
    
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    
   
    gettimeofday (&tvpre , &tz);

    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi,proof)) {
    cout << "Verified!" << endl;
    } else {
    cout << "Failed to verify!" << endl;
    }

    gettimeofday (&tvafter , &tz);
    cout << "time "<<(tvafter.tv_sec-tvpre.tv_sec)*1000+(tvafter.tv_usec-tvpre.tv_usec)/1000<< endl;
    /*
    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }*/
}

int main(void)
{
    
    ppT::init_public_params();

    test_tree<FieldT>();
    //test_two_to_one< FieldT >();
    /*
    uint256 apk=uint256S("1");
    uint256 r=uint256S("1");
    int64_t v=3;
    testcm< FieldT >(apk,v,r);
    */
    /*
     libff::start_profiling();
     libff::default_ec_pp::init_public_params();
     test_two_to_one<libff::Fr<libff::default_ec_pp> >();
    */

    
}

