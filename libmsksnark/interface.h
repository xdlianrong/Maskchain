#ifndef  INTERFACE_HPP_
#define  INTERFACE_HPP_

#include <ctime>
#include "common/default_types/ec_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"/*以上引用均来自donator2同级别的libsnark*/

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
#include <cstdint>

// 注意空间
using ppT = libsnark::default_r1cs_ppzksnark_pp; 
using FieldT = ppT::Fp_type;


namespace msk{

typedef libff::bigint<libff::alt_bn128_r_limbs> bigint_r;

static char g_c[45]="11112222333344445555666677778888999900001111";
static char sk[11]="1234567891";    
static FieldT g=bigint_r(msk::g_c);
static FieldT Gsk= bigint_r(msk::sk) ;//私钥
static FieldT Gpk= msk::g ^ msk::Gsk.as_bigint();
static uint256 z;
static uint256 Spk;   
static const int64_t n=0;

//void isSnarkOk();

uint256 one_hash(const unsigned char *data, size_t len);

//std::vector<unsigned char> convertIntToVectorLE(const uint64_t val_int);

static std::vector<unsigned char> convertIntToVectorLE(const uint64_t val_int) {
    std::vector<unsigned char> bytes;
    for(size_t i = 0; i < 8; i++) {
        bytes.push_back(val_int >> (i * 8));
    }
    return bytes;
}

//std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes);
//uint256->vector<bool>->libsnark::pb_variable_array<FieldT>，使用fill_with_bits：
//zk_vpub_old.fill_with_bits(this->pb,uint64_to_bool_vector(vpub_old)));
static std::vector<bool> convertBytesVectorToVector(const std::vector<unsigned char>& bytes) {
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
std::vector<bool> uint256_to_bool_vector(uint256 input);

//std::vector<bool> uint64_to_bool_vector(uint64_t input);
static std::vector<bool> uint64_to_bool_vector(uint64_t input) {
    auto num_bv = msk::convertIntToVectorLE(input);
    
    return msk::convertBytesVectorToVector(num_bv);
}
template<typename T>
T swap_endianness_u64(T v) {
    if (v.size() != 64) {
        throw std::length_error("invalid bit length for 64-bit unsigned integer");
    }
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            std::swap(v[i*8 + j], v[((7-i)*8)+j]);
        }
    }
    return v;
}

template<typename FieldT>
libsnark::linear_combination<FieldT> packed_addition(libsnark::pb_variable_array<FieldT> input) {
    auto input_swapped = swap_endianness_u64(input);

    return libsnark::pb_packing_sum<FieldT>(libsnark::pb_variable_array<FieldT>(
        input_swapped.rbegin(), input_swapped.rend()
    ));
}

//------------公私匙部分-----------------------------
//用户公钥由私钥哈希而来
template<typename FieldT>
class prf_gadget : libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher;

public:
    prf_gadget(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable_array<FieldT>& a_sk,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : libsnark::gadget<FieldT>(pb) {

        //H(a_sk,a_sk)
        block.reset(new libsnark::block_variable<FieldT>(pb, {
            a_sk,
            a_sk
        }, ""));

        libsnark::pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block->bits,
            *result,
        ""));

    }

    void generate_r1cs_constraints() {
        hasher->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher->generate_r1cs_witness();
    }
};
static uint256 combine(const uint256& a, const uint256& b)
{
    uint256 res ;

    CSHA256 hasher;
    hasher.Write(a.begin(), 32);
    hasher.Write(b.begin(), 32);
    hasher.FinalizeNoPadding(res.begin());

    return res;
}
//uint256 prf(uint256 a_sk);

template<typename FieldT>
class sn_gadget : libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher;

public:
    sn_gadget(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable_array<FieldT>& a_sk,
        libsnark::pb_variable_array<FieldT>& r,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : libsnark::gadget<FieldT>(pb) {
       
        //H(a_sk,r)
        block.reset(new libsnark::block_variable<FieldT>(pb, {
            a_sk,
            r
        }, ""));

        libsnark::pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block->bits,
            *result,
        ""));
    }

    void generate_r1cs_constraints() {
        hasher->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher->generate_r1cs_witness();
    }
};

//uint256 sn(uint256 a_sk,uint256 r);

static uint256 prf(uint256 a_sk){
    CSHA256 hasher;
   
    uint256 result;

    //H(a_sk a_sk)
    hasher.Write(a_sk.begin(), 32);
    hasher.Write(a_sk.begin(), 32);
    hasher.FinalizeNoPadding(result.begin());
  
    return result;
}

static uint256 sn(uint256 a_sk,uint256 r){
    CSHA256 hasher;
  
    uint256 result;

    //H(a_sk r)
    hasher.Write(a_sk.begin(), 32);
    hasher.Write(r.begin(), 32);
    hasher.FinalizeNoPadding(result.begin());
  
    return result;
}

static uint256 cm(uint256 a_pk, int64_t v, uint256 r) {
    CSHA256 hasher1;
    CSHA256 hasher2;

    uint256 imt;
    uint256 result;

    //H(a_pk )
    hasher1.Write(a_pk.begin(), 32);

    //H(apk,v,v,v,v)
    auto value_vec = msk::convertIntToVectorLE(v);
    hasher1.Write(&value_vec[0], value_vec.size());
    hasher1.Write(&value_vec[0], value_vec.size());
    hasher1.Write(&value_vec[0], value_vec.size());
    hasher1.Write(&value_vec[0], value_vec.size());
    hasher1.FinalizeNoPadding(imt.begin());

    //H( H(apk,v,v,v,v),r)
    hasher2.Write(imt.begin(), 32);
    hasher2.Write(r.begin(), 32);
    hasher2.FinalizeNoPadding(result.begin());
  
    return result;
}

static void outBoolVector(std::vector<bool> &v){
     for(size_t i=0;i<v.size();i++){

        std::cout<<v[i]<<" , ";
    }
    std::cout<<std::endl;
}

template<typename FieldT>
class comm_gadget : libsnark::gadget<FieldT> {
private:
    std::shared_ptr<libsnark::block_variable<FieldT>> block1;
    std::shared_ptr<libsnark::block_variable<FieldT>> block2;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<libsnark::digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<libsnark::sha256_compression_function_gadget<FieldT>> hasher2;

public:
    comm_gadget(
        libsnark::protoboard<FieldT> &pb,
        libsnark::pb_variable_array<FieldT>& a_pk,
        libsnark::pb_variable_array<FieldT>& v,
        libsnark::pb_variable_array<FieldT>& r,
        std::shared_ptr<libsnark::digest_variable<FieldT>> result
    ) : libsnark::gadget<FieldT>(pb) {

        intermediate_hash.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        std::cout<<"com1 "<<std::endl;
        //H(a_pk,v)
        block1.reset(new libsnark::block_variable<FieldT>(pb, {
            a_pk,
            v,
            v,
            v,
            v
        }, ""));
        std::cout<<"com2 "<<std::endl;
        libsnark::pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        ""));
        std::cout<<"com3 "<<std::endl;
        libsnark::pb_variable_array<FieldT> intermediate_block;
        intermediate_block.insert(intermediate_block.end(), (*intermediate_hash).bits.begin(), (*intermediate_hash).bits.end());
        std::cout<<"com4 "<<std::endl;
        //H(H(a_pk,v),r)
        block2.reset(new libsnark::block_variable<FieldT>(pb, {
            intermediate_block,
            r
        }, ""));
        std::cout<<"com5 "<<std::endl;
        hasher2.reset(new libsnark::sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block2->bits,
            *result,
        ""));
        std::cout<<"com6 "<<std::endl;
    }

    void generate_r1cs_constraints() {
        hasher1->generate_r1cs_constraints();
        hasher2->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() {
        hasher1->generate_r1cs_witness();
        hasher2->generate_r1cs_witness();
    }
};


uint256 cm(uint256 a_pk, int64_t v, uint256 r);

void outBoolVector(std::vector<bool> &v);


template<typename FieldT>
FieldT convertBoolVectorToFp(std::vector<bool> &bv){
    FieldT result=0;
    FieldT r=2;
    for(size_t i=0;i<bv.size();i++){

        if(bv[i]){
            result+=r^i;
        }
    }
    return result;
}

template<typename FieldT>
std::vector<bool> convertFpToBoolVector(FieldT fp){
    FieldT r=2,tmp;
    FieldT zero=0;
    std::vector<bool> bv;
    
    while(fp!=zero){
        tmp=modelFp(fp,r);
        if(tmp == zero){
            bv.push_back(0);
        }else{
            bv.push_back(1);
        }
        
        fp=divFp(fp,r);
    }

    return bv;
}


//十六进制字符串转换为字节流  
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen);

//void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen );

static void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )  
{  
    int  i;  
    char szTmp[3];  
  
    for( i = 0; i < nSrcLen; i++ )  
    {  
        sprintf( szTmp, "%02x", (unsigned char) sSrc[i] );  
        memcpy( &sDest[i * 2], szTmp, 2 );  
    }  
    return ;  
}
#define bigint_len 32

//通过拷贝二进制数组构造bigint
void byteToBigint(bigint_r &b,unsigned char *bytebuf);

void byteToint64(uint64_t &i64,unsigned char* buf);

uint256 byteToUint256(unsigned char *bytebuf);

//二进制字节数组转换为Fp
template<typename FieldT>
FieldT byteToFp(unsigned char* bytebuf){
    bigint_r b;
    memcpy(&b.data[0],bytebuf,bigint_len);
    FieldT fp=b;
    return b; 
}

template<typename FieldT>
FieldT hexStrToFp(char* bytebuf){
    unsigned char buf[64];
    HexStrToByte(bytebuf, buf, 2*bigint_len);
    
    return byteToFp<FieldT>(buf); 
}

//fp转换为16进制字符串
template<typename FieldT>
void fpToHexStr(FieldT &b,char *hex){
    Hex2Str((char*)&b.as_bigint().data[0],  hex, bigint_len);
}

//fp转换为16进制字符串
template<typename FieldT>
void fpToByte(FieldT &b,unsigned char *bytebuf){
    memcpy((char*)bytebuf,(char*)&b.as_bigint().data[0], bigint_len);
}



template<typename FieldT>
class Elgamal_2apk_3v{

    FieldT c1_tmp1,c2_tmp1;
    FieldT c1_tmp2,c2_tmp2;
    FieldT c1_tmp3,c2_tmp3;

    std::string c1_tmp1_bigintstr1,c2_tmp1_bigintstr1;
    std::string c1_tmp2_bigintstr2,c2_tmp2_bigintstr2;
    std::string c1_tmp3_bigintstr3,c2_tmp3_bigintstr3;

    char encrypted_hex_str[64*6+1];
    unsigned char encrypted_data[32*6];

    unsigned char tmp1[32];
    unsigned char tmp2[32];
    unsigned char tmp3[32];

    unsigned char buf[96];

   

public:   
    
    FieldT g;//生成元
    FieldT Gsk;//私钥
    FieldT Gpk;//公钥


    uint256 apk_s;
    uint256 apk_r;
    uint64_t v_1;
    uint64_t v_2;
    uint64_t v_3;

    //明文m
    FieldT m1;
    FieldT m2;
    FieldT m3;

    //随机数对应的向量
    std::vector<FieldT> v_y1;
    std::vector<FieldT> v_y2;
    std::vector<FieldT> v_y3;

    //加密的结果
    FieldT c1_result1,c2_result1;
    FieldT c1_result2,c2_result2;
    FieldT c1_result3,c2_result3;

    int _encrypt_data_len_;

public:
   
    Elgamal_2apk_3v(){
        _encrypt_data_len_=32*6;
        g=bigint_r("11112222333344445555666677778888999900001111");
        Gsk = bigint_r("123456789");//私钥
        Gpk = g ^ Gsk.as_bigint();//公钥
    }

    //设置生成元
    void setG(FieldT sg){
        g=sg;
    }

    //设置公钥
    void setPk(FieldT pk){
        Gpk=pk;
    }

    //设置私钥
    void setSk(FieldT sk){
        Gsk = sk;//私钥
        Gpk = g ^ Gsk.as_bigint();//公钥
    }

    // apk_s付款方公钥，apk_r收款方公钥
    // v_p实付金额,v_c找零金额，譬如总金额5,找零3，则实付2
    void encrypt(uint256 apk_s,uint256 apk_r,uint64_t v_1,uint64_t v_2,uint64_t v_3){
    
        std::cout<<"before encrypt:"<<std::endl;
        std::cout<<apk_s.ToString()<<std::endl;
        std::cout<<apk_r.ToString()<<std::endl;

        std::cout<<v_1<<std::endl;
        std::cout<<v_2<<std::endl;

        fillBuf(apk_s,apk_r,v_1,v_2,v_3);
        splitBuf_31();

        //明文m
        m1 = byteToFp<FieldT>(tmp1);
        m2 = byteToFp<FieldT>(tmp2);
        m3 = byteToFp<FieldT>(tmp3);

        FieldT y1=getRandom(v_y1);
        FieldT y2=getRandom(v_y2);
        FieldT y3=getRandom(v_y3);

        //生成密文c1，c2
        c1_tmp1 = g ^ y1.as_bigint();
        c2_tmp1 = m1 * (Gpk ^ y1.as_bigint());

       
        //生成密文c1，c2
        c1_tmp2 = g ^ y2.as_bigint();
        c2_tmp2 = m2 * (Gpk ^ y2.as_bigint());

       
        //生成密文c1，c2
        c1_tmp3 = g ^ y3.as_bigint();
        c2_tmp3 = m3 * (Gpk ^ y3.as_bigint());
      
        c1_result1=c1_tmp1;
        c2_result1=c2_tmp1;

        c1_result2=c1_tmp2;
        c2_result2=c2_tmp2;

        c1_result3=c1_tmp3;
        c2_result3=c2_tmp3;

        fpToByte<FieldT>(c1_tmp1,encrypted_data);
        fpToByte<FieldT>(c2_tmp1,&encrypted_data[32]);

        fpToByte<FieldT>(c1_tmp2,&encrypted_data[32*2]);
        fpToByte<FieldT>(c2_tmp2,&encrypted_data[32*3]);

        fpToByte<FieldT>(c1_tmp3,&encrypted_data[32*4]);
        fpToByte<FieldT>(c2_tmp3,&encrypted_data[32*5]);


        encrypted_hex_str[64*6]=0;

        fpToHexStr<FieldT>(c1_tmp1,encrypted_hex_str);
        fpToHexStr<FieldT>(c2_tmp1,&encrypted_hex_str[64]);

        fpToHexStr<FieldT>(c1_tmp2,&encrypted_hex_str[64*2]);
        fpToHexStr<FieldT>(c2_tmp2,&encrypted_hex_str[64*3]);

        fpToHexStr<FieldT>(c1_tmp3,&encrypted_hex_str[64*4]);
        fpToHexStr<FieldT>(c2_tmp3,&encrypted_hex_str[64*5]);
    }
     unsigned char getEncryptedData(unsigned char *buf){
        memcpy(buf,encrypted_data,32*6);
    }
       void setEncryptedData(unsigned char *data){
        c1_tmp1 = byteToFp<FieldT>(data);
        c2_tmp1 = byteToFp<FieldT>(&data[32]);
        
        c1_tmp2 = byteToFp<FieldT>(&data[32*2]);
        c2_tmp2 = byteToFp<FieldT>(&data[32*3]);

        c1_tmp3 = byteToFp<FieldT>(&data[32*4]);
        c2_tmp3 = byteToFp<FieldT>(&data[32*5]);
        
        c1_result1=c1_tmp1;
        c2_result1=c2_tmp1;

        c1_result2=c1_tmp2;
        c2_result2=c2_tmp2;

        c1_result3=c1_tmp3;
        c2_result3=c2_tmp3;

    }
protected:
    
    void fillBuf(uint256 apk_s,uint256 apk_r,uint64_t v_1,uint64_t v_2,uint64_t v_3){
        //清空
        memset(buf,0,96);
        
        //写数据
        memcpy(buf,apk_s.begin(),32);
        memcpy(buf+32,apk_r.begin(),32);
        memcpy(buf+32+32,&v_1,8);
        memcpy(buf+32+32+8,&v_2,8);
        memcpy(buf+32+32+8+8,&v_3,8);
    }
    
    void fillTmp_31to32(unsigned char *src_31,unsigned char *dest_32){
        memset(dest_32,0,32);
        for(size_t i=0; i<31; i++){
            dest_32[i]=src_31[i];
        }
    }
    void splitBuf_31(){
        fillTmp_31to32(buf,tmp1);
        fillTmp_31to32(buf+31,tmp2);
        fillTmp_31to32(buf+31+31,tmp3);
    }
    FieldT getRandom(std::vector<FieldT> &Y){
        srand(unsigned(time(0)));
        FieldT y = FieldT::zero();
        for(int i=0;i<253;i++){
            Y.push_back(FieldT::one()*(rand()%2));
            y += Y[i] * ((FieldT::one()*2) ^ bigint_r(i));
        }
        return y;
    }
    void restoreFromByteBuf(unsigned char *bytebuf){
       
        std::cout<<"before restore:"<<std::endl;
        std::cout<<"restore from buf:"<<std::endl;

        apk_s=*(uint256*)bytebuf;
        apk_r=*(uint256*)(bytebuf+32);
        
        v_1=*(uint64_t*)&bytebuf[32+32];
        v_2=*(uint64_t*)&bytebuf[32+32+8];
        v_3=*(uint64_t*)&bytebuf[32+32+8+8];
       
    }
};


template<typename FieldT>
class exp_gadget : public libsnark::gadget<FieldT> {
private:
    libsnark::pb_variable_array<FieldT> _A;
    libsnark::pb_variable_array<FieldT> temp1;
    libsnark::pb_variable_array<FieldT> temp2;
    libsnark::pb_variable_array<FieldT> temp3;
    //FieldT g;
    libsnark::pb_variable<FieldT> g;
public:
    const libsnark::pb_linear_combination_array<FieldT> A;
    const libsnark::pb_variable<FieldT> result;

    //exp_gadget(FieldT g, libsnark::protoboard<FieldT>& pb,
    exp_gadget(libsnark::pb_variable<FieldT> &g, libsnark::protoboard<FieldT>& pb,
                         const libsnark::pb_linear_combination_array<FieldT> &A,//y
                         const libsnark::pb_variable<FieldT> &result,
                         const std::string &annotation_prefix="") :
        libsnark::gadget<FieldT>(pb, annotation_prefix), A(A), g(g), result(result)
    {
        
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
        libsnark::r1cs_constraint<FieldT>(FieldT::one() - A[i], FieldT::one(), _A[i]),
        FMT(this->annotation_prefix, " S_%zu", i));
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(A[i], this->pb.val(g) ^ ((FieldT::one()*2) ^ bigint_r(i)).as_bigint(), temp1[i]),
        FMT(this->annotation_prefix, " S_%zu", i));
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(_A[i] + temp1[i] , FieldT::one(), temp2[i]),
        FMT(this->annotation_prefix, " S_%zu", i));     
    }
    for (size_t i = 0; i < temp3.size()+1; ++i)
    {
      this->pb.add_r1cs_constraint(
        libsnark::r1cs_constraint<FieldT>(i==0 ? temp2[0] : temp3[i-1], temp2[i+1], i==temp3.size() ? result : temp3[i]),
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
        this->pb.val(temp1[i]) = this->pb.lc_val(A[i]) * (this->pb.val(g) ^ ((FieldT::one()*2) ^ bigint_r(i)).as_bigint());
        this->pb.val(temp2[i]) = this->pb.lc_val(_A[i]) + this->pb.val(temp1[i]) ;
    }
    for (size_t i = 0; i < temp3.size()+1; ++i){
      this->pb.val(i == temp3.size() ? result : temp3[i]) = (i==0 ? this->pb.val(temp2[0]) : this->pb.val(temp3[i-1]) ) * this->pb.val(temp2[i+1]);
    }
}

template<typename FieldT>
class binary_gadget : public libsnark::gadget<FieldT> {
private:
    libsnark::pb_variable_array<FieldT> temp1;
    libsnark::pb_variable_array<FieldT> temp2;
    FieldT g;
public:
    const libsnark::pb_linear_combination_array<FieldT> A;
    const libsnark::pb_variable<FieldT> result;

    binary_gadget(libsnark::protoboard<FieldT>& pb,
                         const libsnark::pb_linear_combination_array<FieldT> &A,//y
                         const libsnark::pb_variable<FieldT> &result,
                         const std::string &annotation_prefix="") :
        libsnark::gadget<FieldT>(pb, annotation_prefix), A(A), result(result)
    {
        g=FieldT::one()*2;
        temp1.allocate(pb, A.size(), FMT(this->annotation_prefix, " temp1"));
        temp2.allocate(pb, A.size(), FMT(this->annotation_prefix, " temp2"));
       
    }

    void generate_r1cs_constraints()
    {
        for (size_t i = 0; i < A.size(); ++i)
        {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>( A[i] * (g ^ i) , FieldT::one(), temp1[i]),FMT(this->annotation_prefix, " S_%zu", i));     
        }
        for (size_t i = 0; i < temp2.size(); ++i)
        {
        this->pb.add_r1cs_constraint(
            libsnark::r1cs_constraint<FieldT>(i==0 ? temp1[0]: temp2[i-1]+temp1[i]
                                , FieldT::one(), i==temp2.size()-1 ? result : temp2[i]),
            FMT(this->annotation_prefix, " S_%zu", i));
        }
    }

    void generate_r1cs_witness()
    {
        for (size_t i = 0; i < A.size(); ++i)
        {
            A[i].evaluate(this->pb);
            this->pb.val(temp1[i]) = this->pb.lc_val(A[i]) * (g ^ i);
        }
    
        for (size_t i = 0; i < temp2.size(); ++i){
        this->pb.val(i == temp2.size()-1 ? result : temp2[i]) = (i==0 ? this->pb.val(temp1[0]) : this->pb.val(temp2[i-1])+this->pb.val(temp1[i]) ) ;
            
        }
       
    }
};

template<typename FieldT>
class elgamal_gadget : public libsnark::gadget<FieldT>{
    //FieldT g;
    //FieldT pk;
    libsnark::pb_variable<FieldT> g;
    libsnark::pb_variable<FieldT> pk;
    libsnark::pb_variable<FieldT> result1_1;
    libsnark::pb_variable<FieldT> result1_2;
  
    libsnark::pb_variable<FieldT> result2_1;
    libsnark::pb_variable<FieldT> result2_2;

    libsnark::pb_variable<FieldT> result3_1;
    libsnark::pb_variable<FieldT> result3_2;

    std::shared_ptr<exp_gadget<FieldT>> exp1_1;
    std::shared_ptr<exp_gadget<FieldT>> exp1_2;

    std::shared_ptr<exp_gadget<FieldT>> exp2_1;
    std::shared_ptr<exp_gadget<FieldT>> exp2_2;

    std::shared_ptr<exp_gadget<FieldT>> exp3_1;
    std::shared_ptr<exp_gadget<FieldT>> exp3_2;

    std::shared_ptr<binary_gadget<FieldT>> binary1;
    std::shared_ptr<binary_gadget<FieldT>> binary2;
    std::shared_ptr<binary_gadget<FieldT>> binary3;

    libsnark::pb_variable_array<FieldT> random_y1;
    libsnark::pb_variable_array<FieldT> random_y2;
    libsnark::pb_variable_array<FieldT> random_y3;

    libsnark::pb_variable_array<FieldT> m;  
    libsnark::pb_variable_array<FieldT> c1;  
    libsnark::pb_variable_array<FieldT> c2;

    libsnark::pb_variable_array<FieldT> apk1_array;
    libsnark::pb_variable_array<FieldT> apk2_array;
    libsnark::pb_variable_array<FieldT> v1_array;
    libsnark::pb_variable_array<FieldT> v2_array;
    libsnark::pb_variable_array<FieldT> v3_array;

    libsnark::pb_variable_array<FieldT> m1_array;
    libsnark::pb_variable_array<FieldT> m2_array;
    libsnark::pb_variable_array<FieldT> m3_array;

    libsnark::pb_variable<FieldT> m1_binary_result;
    libsnark::pb_variable<FieldT> m2_binary_result;
    libsnark::pb_variable<FieldT> m3_binary_result;

public:
    elgamal_gadget(libsnark::protoboard<FieldT> &pb,
                        //FieldT &sg,  //生成元
                        //FieldT &gpk,
                        libsnark::pb_variable<FieldT> &sg,
                        libsnark::pb_variable<FieldT> &gpk,
                        libsnark::pb_variable_array<FieldT> &ran_y1,//第一个明文加密随机数
                        libsnark::pb_variable_array<FieldT> &ran_y2,//第二个明文加密随机数
                        libsnark::pb_variable_array<FieldT> &ran_y3,//第三个明文加密随机数
                        libsnark::pb_variable_array<FieldT> &m_arr,   //明文列表
                        libsnark::pb_variable_array<FieldT> &c1_arr,  //密文1列表
                        libsnark::pb_variable_array<FieldT> &c2_arr,  //密文2列表
                        libsnark::pb_variable_array<FieldT> &apk1_arr,
                        libsnark::pb_variable_array<FieldT> &apk2_arr,
                        libsnark::pb_variable_array<FieldT> &v1_arr,
                        libsnark::pb_variable_array<FieldT> &v2_arr,
                        libsnark::pb_variable_array<FieldT> &v3_arr
        )
        :libsnark::gadget<FieldT>(pb){
        this->g=sg;
        this->pk=gpk;

        this->random_y1=ran_y1;
        this->random_y2=ran_y2;
        this->random_y3=ran_y3;
        this->m=m_arr;
        this->c1=c1_arr;
        this->c2=c2_arr;

        apk1_array=apk1_arr;
        apk2_array=apk2_arr;
        v1_array=v1_arr;
        v2_array=v2_arr;
        v3_array=v3_arr;

        result1_1.allocate(this->pb,"result1");
        result1_2.allocate(this->pb,"result2");

        result2_1.allocate(this->pb,"result1");
        result2_2.allocate(this->pb,"result2");

        result3_1.allocate(this->pb,"result1");
        result3_2.allocate(this->pb,"result2");

        m1_array.allocate(this->pb,248,"m1_array");
        m2_array.allocate(this->pb,248,"m2_array");
        m3_array.allocate(this->pb,248,"m3_array");

        m1_binary_result.allocate(this->pb,"m1_binary_result");;
        m2_binary_result.allocate(this->pb,"m2_binary_result");;
        m3_binary_result.allocate(this->pb,"m3_binary_result");;

        exp1_1.reset(new exp_gadget<FieldT>(g,pb,random_y1,result1_1,"exp"));
        exp1_2.reset(new exp_gadget<FieldT>(pk,pb,random_y1,result1_2,"exp"));

        exp2_1.reset(new exp_gadget<FieldT>(g,pb,random_y2,result2_1,"exp"));
        exp2_2.reset(new exp_gadget<FieldT>(pk,pb,random_y2,result2_2,"exp"));

        exp3_1.reset(new exp_gadget<FieldT>(g,pb,random_y3,result3_1,"exp"));
        exp3_2.reset(new exp_gadget<FieldT>(pk,pb,random_y3,result3_2,"exp"));
        
        binary1.reset(new binary_gadget<FieldT>(pb,m1_array,m1_binary_result,"binary gadget"));
        binary2.reset(new binary_gadget<FieldT>(pb,m2_array,m2_binary_result,"binary gadget"));
        binary3.reset(new binary_gadget<FieldT>(pb,m3_array,m3_binary_result,"binary gadget"));
    }
   

    void generate_r1cs_constraints(){

        //约束：random_y[i]是布尔值
        for(int i=0; i<253;i++){
            generate_boolean_r1cs_constraint(this->pb,libsnark::pb_linear_combination<FieldT>(random_y1[i]));
            generate_boolean_r1cs_constraint(this->pb,libsnark::pb_linear_combination<FieldT>(random_y2[i]));
            generate_boolean_r1cs_constraint(this->pb,libsnark::pb_linear_combination<FieldT>(random_y3[i]));
        }
        
        //apk1，前31字节
        for(int i=0;i<31*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m1_array[i], FieldT::one(), apk1_array[j-off]),FMT(" S_%zu"));
            //m1_array[i]=apk1_array[j-off];
        }
    
        //apk1，后1个字节
        for(int i=0;i<1*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m2_array[i], FieldT::one(), apk1_array[31*8+j-off]),FMT(" S_%zu"));
            //m2_array[i]=apk1_array[31*8+j-off];
        }
        
        //apk2，前30字节
        for(int i=0;i<30*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m2_array[1*8+i], FieldT::one(), apk2_array[j-off]),FMT(" S_%zu"));
            //m2_array[1*8+i]=apk2_array[j-off];
        }
    
        //apk2,后2个字节，
        for(int i=0;i<2*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m3_array[i], FieldT::one(), apk2_array[30*8+j-off]),FMT(" S_%zu"));
            //m3_array[i]=apk2_array[30*8+j-off];
        }
        
        //v1,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m3_array[2*8+i], FieldT::one(), v1_array[j-off]),FMT(" S_%zu"));
            //m3_array[2*8+i]=v1_array[j-off];
        }
    
        //v2,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m3_array[2*8+8*8+i], FieldT::one(), v2_array[j-off]),FMT(" S_%zu"));
            //m3_array[2*8+8*8+i]=v2_array[j-off];
        }
    
        //v3,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m3_array[2*8+8*8+8*8+i], FieldT::one(), v3_array[j-off]),FMT(" S_%zu"));
            //m3_array[2*8+8*8+8*8+i]=v3_array[j-off]; 
        }

        
        //密文等于明文加密
        //约束：g ^ y == c1
        exp1_1->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(result1_1, FieldT::one(), c1[0]),FMT(" S_%zu"));

        exp2_1->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(result2_1, FieldT::one(), c1[1]),FMT(" S_%zu"));

        exp3_1->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(result3_1, FieldT::one(), c1[2]),FMT(" S_%zu"));
        
        //约束：m * (Gpk ^ y) == c2
        exp1_2->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(result1_2, m[0], c2[0]),FMT(" S_%zu"));

        exp2_2->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(result2_2, m[1], c2[1]),FMT(" S_%zu"));

        exp3_2->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(result3_2, m[2], c2[2]),FMT(" S_%zu"));

        //明文等于apk和v的组合
        binary1->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m1_binary_result, FieldT::one(), m[0]),FMT(" S_%zu"));

        binary2->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m2_binary_result, FieldT::one(), m[1]),FMT(" S_%zu"));

        binary3->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(m3_binary_result, FieldT::one(), m[2]),FMT(" S_%zu"));

    }

    void generate_r1cs_witness(){
       
        //apk1，前31字节
        for(int i=0;i<31*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.val(m1_array[i])=this->pb.val(apk1_array[j-off]);
        }
        
        //apk1，后1个字节
        for(int i=0;i<1*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.val(m2_array[i])=this->pb.val(apk1_array[31*8+j-off]);
        }
        
        //apk2，前30字节
        for(int i=0;i<30*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.val(m2_array[1*8+i])=this->pb.val(apk2_array[j-off]);
        }
    
        //apk2,后2个字节，
        for(int i=0;i<2*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.val(m3_array[i])=this->pb.val(apk2_array[30*8+j-off]);
        }
        
        //v1,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.val(m3_array[2*8+i])=this->pb.val(v1_array[j-off]);
        }
    
        //v2,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.val(m3_array[2*8+8*8+i])=this->pb.val(v2_array[j-off]);
        }
    
        //v3,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.val(m3_array[2*8+8*8+8*8+i])=this->pb.val(v3_array[j-off]);
        }
        

        exp1_1->generate_r1cs_witness();
        exp1_2->generate_r1cs_witness();

        exp2_1->generate_r1cs_witness();
        exp2_2->generate_r1cs_witness();
        
        exp3_1->generate_r1cs_witness();
        exp3_2->generate_r1cs_witness();

        binary1->generate_r1cs_witness();
        binary2->generate_r1cs_witness();
        binary3->generate_r1cs_witness();
    }
};


//-----------Mekeltree部分------------------------
#define TREE_DEEPTH 4
struct node     //定义二叉树节点数据结构
{
	node *parent;  
    node *left;
	node *right;
	uint256 data;
};

class MerkleTreePath{
public:
    std::vector<uint256> nodeHashList;
    std::vector<uint256> parentList;
    std::vector<int> pathisrightList;
    uint256 root;
    uint256 leaf;
};

uint256 combine(const uint256& a, const uint256& b);


// merkle tree 的定义及实现，需要找时间进行分离和结构改善。
class MerkleTree{
private:
    int _DEEPTH;
	std::vector<node> Tree;  //存储树的向量
    uint256 _d_leaf;
    int index;

    //更新树
	void updateTree() {
        int nodeNum;         //计算已更新节点所在的那层以及以下各层的节点数和
        for (int j = _DEEPTH; j >1; j--)
        {
            nodeNum = (pow(2, j)*(1 - pow(2, _DEEPTH - j))) / (1 - 2);
            (*Tree.at(index).parent).data = msk::combine((*(*Tree.at(index).parent).left).data , (*(*Tree.at(index).parent).right).data);  //更新父节点的值
            index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
        }
        std::cout << "update done" << std::endl;
    }        
	void findLeafIndex(int leaf);      //给定一个叶节点的值，返回其在树中的索引
	void getNodeHashList(uint256 leaf) {
        for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
        {
            if (Tree.at(index).data == leaf)
                break;
            if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
            {
                std::cout << "ERROR" << std::endl;
                return;
            }
        }

        int nodeNum;
        for (int j = _DEEPTH; j > 1; j--)
        {
            //判断index对应的叶节点是左节点还是右节点
            if (index % 2 == 0)   //左节点
            {
                nodeHashList.push_back(Tree.at(index).data);
                nodeHashList.push_back(Tree.at(index+1).data);
            }
            else    //右节点
            {
                nodeHashList.push_back(Tree.at(index-1).data);
                nodeHashList.push_back(Tree.at(index).data);
            }
            nodeNum = (pow(2, j)*(1 - pow(2, _DEEPTH - j))) / (1 - 2);
            index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
        }
    }
	void getParentList(uint256 leaf) {
        for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
        {
            if (Tree.at(index).data == leaf)
                break;
            if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
            {
                std::cout << "ERROR" << std::endl;
                return;
            }
        }
        int nodeNum;
        for (int j = _DEEPTH; j > 1; j--)
        {
            nodeNum = (pow(2, j)*(1 - pow(2, _DEEPTH - j))) / (1 - 2);
            index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
            parentList.push_back(Tree.at(index).data);
        }
    }
	void getPathisrightList(uint256 leaf) {
        for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
        {
            if (Tree.at(index).data == leaf)
                break;
            if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
            {
                std::cout << "ERROR" << std::endl;
                return;
            }
        }
        int nodeNum;
        for (int j = _DEEPTH; j > 1; j--)
        {
            if (index % 2 == 0)   //左节点
            {
                pathisrightList.push_back(0);
            }
            else    //右节点
            {
                pathisrightList.push_back(1);
            }
            nodeNum = (pow(2, j)*(1 - pow(2, _DEEPTH - j))) / (1 - 2);
            index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
        }
    }

public:
    void inite(int deep)
    {_DEEPTH=deep+1;
    _d_leaf=uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    };
	std::vector<uint256> nodeHashList;   //存储需要被哈希的节点值
	std::vector<uint256> parentList;    //父节点列表
	std::vector<int> pathisrightList;    //存储节点是左节点还是右节点

    //从叶节点开始由下到上创建并初始化二叉树
	void creatTree() {
        //初始化节点
        for (int i = 0; i < ((int)pow(2, _DEEPTH) - 1); i++)  
        {
            node initNode;
            initNode = { NULL, NULL, NULL, _d_leaf };     //节点的默认值
            Tree.push_back(initNode);
        }

        //创建树
        int nodeNum = 0;   //存储创建树的过程中已被创建过关系的节点数量
        for (int j = _DEEPTH; j >0; j--)
        {
            int parentIndex, childIndex;
            for (int i = nodeNum; i < nodeNum + (int)pow(2, j - 1); i++)
            {
                if (i < (int)pow(2, _DEEPTH - 1))
                {
                    parentIndex = nodeNum + (int)pow(2, j - 1) + (i - nodeNum) / 2;   //父节点的索引
                    Tree.at(i).parent = &Tree[parentIndex];
                    //cout << Tree.at(i).data << std::endl;
                }
                else if (i == pow(2, _DEEPTH) - 2)
                {
                    childIndex = (i - (int)pow(2, _DEEPTH - 1)) * 2;
                    Tree.at(i).left = &Tree.at(childIndex);
                    Tree.at(i).right = &Tree.at(childIndex + 1);
                    Tree.at(i).data = msk::combine(Tree.at(childIndex).data , Tree.at(childIndex + 1).data); //父节点的data值为左右孩子节点的data相加
                    //cout << Tree.at(i).data << std::endl;
                }
                else
                {
                    parentIndex = nodeNum + (int)pow(2, j - 1) + (i - nodeNum) / 2;
                    Tree.at(i).parent = &Tree.at(parentIndex);
                    childIndex = (i - (int)pow(2, _DEEPTH - 1)) * 2;         //孩子节点的索引
                    Tree.at(i).left = &Tree.at(childIndex);  
                    Tree.at(i).right = &Tree.at(childIndex+1);
                    Tree.at(i).data = msk::combine(Tree.at(childIndex).data , Tree.at(childIndex + 1).data);  
                }
            }
            nodeNum = nodeNum + pow(2, j - 1);
        }
    }

    //查找叶节点中未被更新的节点，并将其值更新为naeleaf
	void addLeaf(uint256 newLeaf) {
        for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
        {
            if (Tree.at(index).data == _d_leaf)
                break;
            if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到，则置index为NULL
            {
                std::cout << "ERROR" << std::endl;
                return;
            }
        }
        Tree.at(index).data = newLeaf;   //更新节点的值
        std::cout << index<< std::endl;
        updateTree();      //更新树
        std::cout << "add leaf done" << std::endl;
    }

    //将指定位置的叶子结点恢复默认值
	void deleteLeafValue(uint256 deleteLeaf) {
        for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
        {
            if (Tree.at(index).data == deleteLeaf)
                break;
            if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
            {
                std::cout << "ERROR" << std::endl;
                return;
            }
        }
        Tree.at(index).data = _d_leaf;    //更新节点的值
        updateTree();      //更新树
    }
	
	uint256  getRoot() {
        return Tree.back().data;
    }
	MerkleTreePath getPath(uint256 leaf) {
        MerkleTreePath path;
        for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  
        {
            if (Tree.at(index).data == leaf)
                break;
            if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
            {
                std::cout << "ERROR" << std::endl;
                return path;
            }
        }
        getNodeHashList(leaf);
        getParentList(leaf);
        getPathisrightList(leaf);
        
        path.nodeHashList=nodeHashList;
        path.parentList=parentList;
        path.pathisrightList=pathisrightList;
        path.root=Tree.back().data;
        path.leaf=leaf;

        return path;
    }
	
	void printTree() {
        for (int i = 0; i < Tree.size(); i++)
        {
            std::cout << Tree[i].data.ToString() << std::endl;
        }
    }
};


template<typename FieldT>
class digest_selector_gadget : public libsnark::gadget<FieldT> {
public:
    size_t digest_size;
    libsnark::digest_variable<FieldT> input;
    libsnark::pb_linear_combination<FieldT> is_right;
    libsnark::digest_variable<FieldT> left;
    libsnark::digest_variable<FieldT> right;

    digest_selector_gadget(libsnark::protoboard<FieldT> &pb,
                           const size_t digest_size,
                           const libsnark::digest_variable<FieldT> &input,
                           const libsnark::pb_linear_combination<FieldT> &is_right,
                           const libsnark::digest_variable<FieldT> &left,
                           const libsnark::digest_variable<FieldT> &right,
                           const std::string &annotation_prefix):
    libsnark::gadget<FieldT>(pb, annotation_prefix), digest_size(digest_size)
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
            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(is_right, right.bits[i] - left.bits[i], input.bits[i] - left.bits[i]),
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
static MerkleTreePath getMerkleTreePath_apk_s(uint256 ask_s, uint256 apk_r){
    //叶子
    MerkleTree apks;
    MerkleTreePath mps;
    apks.inite(4);

    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 apk_s=msk::prf(ask_s);

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 u3=apk_r;
    uint256 u4=apk_s;

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

    apks.creatTree();
    apks.addLeaf(u1);
    apks.addLeaf(u2);
    apks.addLeaf(u3);
    apks.addLeaf(u4);
    apks.addLeaf(u5);
    apks.addLeaf(u6);
    apks.addLeaf(u7);
    apks.addLeaf(u8);
    apks.addLeaf(u9);
    apks.addLeaf(u10);
    apks.addLeaf(u11);
    apks.addLeaf(u12);
    apks.addLeaf(u13);
    apks.addLeaf(u14);
    apks.addLeaf(u15);
    apks.addLeaf(u16);
    mps=apks.getPath(u4);
    return mps;
}

static MerkleTreePath getMerkleTreePath_apk_r(uint256 apk_r){

    //叶子
    MerkleTree apkr;
    MerkleTreePath mpr;
    apkr.inite(4);

     //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=msk::prf(ask_s);

    uint64_t v_1=5;
    uint64_t v_2=0;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 u3=apk_r;
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

    apkr.creatTree();
    apkr.addLeaf(u1);
    apkr.addLeaf(u2);
    apkr.addLeaf(u3);
    apkr.addLeaf(u4);
    apkr.addLeaf(u5);
    apkr.addLeaf(u6);
    apkr.addLeaf(u7);
    apkr.addLeaf(u8);
    apkr.addLeaf(u9);
    apkr.addLeaf(u10);
    apkr.addLeaf(u11);
    apkr.addLeaf(u12);
    apkr.addLeaf(u13);
    apkr.addLeaf(u14);
    apkr.addLeaf(u15);
    apkr.addLeaf(u16);
    mpr=apkr.getPath(u3);
    return mpr;
}


static MerkleTreePath getMerkleTreePath(uint256 ask_s,uint64_t v_1,uint256 old_r)
{  //叶子
    MerkleTree cmt;
    MerkleTreePath mp;
    cmt.inite(4);
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 apk_s=msk::prf(ask_s);

    uint256 u3=msk::cm(apk_s,v_1,old_r);
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
    
   
    cmt.creatTree();
    cmt.addLeaf(u1);
    cmt.addLeaf(u2);  
    cmt.addLeaf(u3);
    cmt.addLeaf(u4);   
    cmt.addLeaf(u5);
    cmt.addLeaf(u6);  
    cmt.addLeaf(u7);
    cmt.addLeaf(u8); 
    cmt.addLeaf(u9);
    cmt.addLeaf(u10);  
    cmt.addLeaf(u11);
    cmt.addLeaf(u12);   
    cmt.addLeaf(u13);
    cmt.addLeaf(u14);  
    cmt.addLeaf(u15);
    cmt.addLeaf(u16); 
    mp=cmt.getPath(u3);
    return mp;
}


static MerkleTreePath getMerkleTreePath_lb(uint256 ask_s,uint64_t v1,uint64_t v2,uint256 old_r){

    //叶子
    MerkleTree cmt;
    MerkleTreePath mp;
    cmt.inite(4);
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 apk_s=msk::prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");


    uint256 u3=msk::cm(apk_s,v1+v2,old_r);
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
     
    cmt.creatTree();
    cmt.addLeaf(u1);
    cmt.addLeaf(u2);  
    cmt.addLeaf(u3);
    cmt.addLeaf(u4);   
    cmt.addLeaf(u5);
    cmt.addLeaf(u6);  
    cmt.addLeaf(u7);
    cmt.addLeaf(u8); 
    cmt.addLeaf(u9);
    cmt.addLeaf(u10);  
    cmt.addLeaf(u11);
    cmt.addLeaf(u12);   
    cmt.addLeaf(u13);
    cmt.addLeaf(u14);  
    cmt.addLeaf(u15);
    cmt.addLeaf(u16); 
    mp=cmt.getPath(u3);
    return mp;
}


static std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )  
{
    if (strPemFileName.empty() || strData.empty())  
    {  
        assert(false);  
        return "";  
    }  
    FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");  
    if( hPubKeyFile == NULL )  
    {  
        assert(false);  
        return "";   
    }  
    std::string strRet;  
    RSA* pRSAPublicKey = RSA_new();  
    if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)  
    {  
        assert(false);  
        return "";  
    }  
  
    int nLen = RSA_size(pRSAPublicKey);  
    char* pEncode = new char[nLen + 1];  
    int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);  
    if (ret >= 0)  
    {  
        strRet = std::string(pEncode, ret);  
    }  
    delete[] pEncode;  
    RSA_free(pRSAPublicKey);  
    fclose(hPubKeyFile);  
    CRYPTO_cleanup_all_ex_data();   
    return strRet;  
}  
//MerkleTreePath getMerkleTreePath_apk_s(uint256 ask_s, uint256 apk_r);

//MerkleTreePath getMerkleTreePath_apk_r(uint256 apk_r);

//MerkleTreePath getMerkleTreePath(uint256 ask_s,uint64_t v_1,uint256 old_r);

//MerkleTreePath getMerkleTreePath_lb(uint256 ask_s,uint64_t v1,uint64_t v2,uint256 old_r);

template<typename FieldT>
class tree_gadget : public libsnark::gadget<FieldT> {
private:
    
    std::vector<libsnark::digest_variable<FieldT>> child;
    std::vector<libsnark::digest_variable<FieldT>> parent;
    std::vector<libsnark::digest_variable<FieldT>> input;
    libsnark::pb_variable_array<FieldT> is_right;

    std::shared_ptr<libsnark::digest_variable<FieldT>> leaf;
    std::shared_ptr<libsnark::digest_variable<FieldT>> root;

    std::vector<libsnark::sha256_two_to_one_hash_gadget<FieldT>> hasher;
    std::vector<digest_selector_gadget<FieldT>> selector;
public:
    tree_gadget(libsnark::protoboard<FieldT>& pb, std::shared_ptr<libsnark::digest_variable<FieldT>> root_dg, std::shared_ptr<libsnark::digest_variable<FieldT>> leaf_dg,const std::string &annotation_prefix="") :
    libsnark::gadget<FieldT>(pb, annotation_prefix)
    {
        is_right.allocate(pb,TREE_DEEPTH,"is_right");
       
        for(size_t i=0;i<2*TREE_DEEPTH;i++){
            child.push_back(libsnark::digest_variable<FieldT>(this->pb, libsnark::SHA256_digest_size, "child"));
        }
       
        for(size_t i=0;i<TREE_DEEPTH;i++){
           
            parent.push_back(libsnark::digest_variable<FieldT>(this->pb, libsnark::SHA256_digest_size, "parent"));

            input.push_back(libsnark::digest_variable<FieldT>(this->pb, libsnark::SHA256_digest_size, "input"));
            hasher.push_back(libsnark::sha256_two_to_one_hash_gadget<FieldT>(this->pb, child[i*2], child[i*2+1], parent[i], "hasher"));
            selector.push_back(digest_selector_gadget<FieldT>(this->pb,libsnark::SHA256_digest_size,input[i],libsnark::pb_linear_combination<FieldT>(is_right[i]),child[i*2],child[i*2+1],"selector"));
        }

        root=root_dg;
        leaf=leaf_dg;

        //leaf.reset(new libsnark::digest_variable<FieldT>(this->pb, libsnark::SHA256_digest_size, "root") );
        //root.reset(new libsnark::digest_variable<FieldT>(this->pb, libsnark::SHA256_digest_size, "root") ); 
    }

    void add_digest_equal(libsnark::digest_variable<FieldT> &d1,libsnark::digest_variable<FieldT> &d2){
        for(size_t i=0;i<256;i++){
            this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(d1.bits[i]
            , FieldT::one(), d2.bits[i]),FMT(" S_%zu"));
        }
    }

    void generate_r1cs_constraints(){

        for(size_t i=0;i<TREE_DEEPTH;i++){
           generate_boolean_r1cs_constraint(this->pb,libsnark::pb_linear_combination<FieldT>(is_right[i]));
        }
        std::cout<<"11"<<std::endl;
        for(size_t i=0;i<TREE_DEEPTH;i++){
           hasher[i].generate_r1cs_constraints();
           selector[i].generate_r1cs_constraints();
        } 
        std::cout<<"22"<<std::endl;
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
       std::cout<<"33"<<std::endl;

    }

    void generate_r1cs_witness(std::vector<uint256> child_ui256_list,std::vector<uint256> parent_ui256_list
                                ,std::vector<int> path){
        
      
        libff::bit_vector bv_l;
        libff::bit_vector bv_r;
        libff::bit_vector bv_p;
        
        //leaf->generate_r1cs_witness(uint256_to_bool_vector(leaf_ui256));
        //root->generate_r1cs_witness(uint256_to_bool_vector(root_ui256));

        for(size_t i=0;i<TREE_DEEPTH;i++){
            bv_l =  msk::uint256_to_bool_vector(child_ui256_list[i*2]);
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
class joinsplit_gadget_z : libsnark::gadget<FieldT> {
private:
    //FieldT g;
    //FieldT Gpk;
    libsnark::pb_variable<FieldT> g;
    libsnark::pb_variable<FieldT> Gpk;
    // sk pk
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk_s;//私钥  
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk_s;//公钥
    std::shared_ptr<prf_gadget<FieldT>> prf_gad;
    
    //sn
    std::shared_ptr<libsnark::digest_variable<FieldT>> sn_old;//序列号  
    std::shared_ptr<sn_gadget<FieldT>> sn_gad;

    // commitment
    libsnark::pb_variable_array<FieldT> v_old;               //金额
    std::shared_ptr<libsnark::digest_variable<FieldT>> r_old;    //随机数
    std::shared_ptr<libsnark::digest_variable<FieldT>> commitment_old;//老承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_old;

    // merkle tree
    std::shared_ptr<tree_gadget<FieldT>> tree_gad_cm;//承诺树
    std::shared_ptr<libsnark::digest_variable<FieldT>> root_cm;//根

    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_s;//付款方
    std::shared_ptr<libsnark::digest_variable<FieldT>> root_apk_s;//根

    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_r;//收款方
    std::shared_ptr<libsnark::digest_variable<FieldT>> root_apk_r;//根

    // balance
    libsnark::pb_variable_array<FieldT> v_new;

    // new commitment
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk_r;//收款方公钥
    std::shared_ptr<libsnark::digest_variable<FieldT>> r_new; //新的随机数
    std::shared_ptr<libsnark::digest_variable<FieldT>> commitment_new;//新承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_new;


    //elgamal   
  
    //3次加密的随机数
    libsnark::pb_variable_array<FieldT> random_y1;
    libsnark::pb_variable_array<FieldT> random_y2;
    libsnark::pb_variable_array<FieldT> random_y3;

    libsnark::pb_variable_array<FieldT> m;    //明文列表
    libsnark::pb_variable_array<FieldT> c1;   //密文1列表
    libsnark::pb_variable_array<FieldT> c2;   //密文2列表

    libsnark::pb_variable_array<FieldT> apk1_array;//付款方公约
    libsnark::pb_variable_array<FieldT> apk2_array;//收款方公约

    //金额
    libsnark::pb_variable_array<FieldT> v1_array; 
    libsnark::pb_variable_array<FieldT> v2_array; 
    libsnark::pb_variable_array<FieldT> v3_array;

    
    std::shared_ptr<elgamal_gadget<FieldT>> elgamal_gad;

    int dimension;

public:
    joinsplit_gadget_z(libsnark::protoboard<FieldT> &pb,FieldT &sg,FieldT &gpk) : libsnark::gadget<FieldT>(pb) {
        //公共参数长度：sn256+老承诺哈希树根256+新承诺256+付款方256+收款方256+6个密文+生成元+监管公钥
        dimension=256+256+256+256+256+6+1+1;

        //分配顺序
        sn_old.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        root_cm.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        root_apk_s.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        root_apk_r.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));

        commitment_new.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        
        c1.allocate(pb,3,"c1");
        c2.allocate(pb,3,"c2");

        g.allocate(pb,"g");
        Gpk.allocate(pb,"Gpk");
        
        this->pb.val(this->g)=sg;
        this->pb.val(this->Gpk)=gpk;

        //ask,apk,prf
        a_sk_s.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        a_pk_s.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        prf_gad.reset(new prf_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            a_pk_s
        ));
        std::cout<<"ask,apk,prf"<<std::endl;

        //comment
        v_old.allocate(pb, 64);
        
        r_old.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        commitment_old.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        comm_gad_old.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_s->bits,
            v_old,
            r_old->bits,
            commitment_old
        ));

        a_pk_r.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        v_new.allocate(pb, 64);
        r_new.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        //commitment_new.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        comm_gad_new.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_r->bits,
            v_new,
            r_new->bits,
            commitment_new
        ));
        std::cout<<"comment"<<std::endl;

        //sn
        sn_gad.reset(new sn_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            r_old->bits,
            sn_old
        ));
        std::cout<<"sn"<<std::endl;

        //merkle tree
        
        tree_gad_cm.reset(new tree_gadget<FieldT>(pb,root_cm,commitment_old,""));
        tree_gad_apk_s.reset(new tree_gadget<FieldT>(pb,root_apk_s,a_pk_s,""));
        tree_gad_apk_r.reset(new tree_gadget<FieldT>(pb,root_apk_r,a_pk_r,""));
        std::cout<<"tree"<<std::endl;

        //elgamal
        
        m.allocate(pb,3,"m");
        
        random_y1.allocate(pb,253,"random_y1");
        random_y2.allocate(pb,253,"random_y2");
        random_y3.allocate(pb,253,"random_y3");

        apk1_array.allocate(pb,256,"m1_array");
        apk2_array.allocate(pb,256,"m2_array");
        v1_array.allocate(pb,64,"m3_array");
        v2_array.allocate(pb,64,"m1_array");
        v3_array.allocate(pb,64,"m2_array");

        elgamal_gad.reset(new elgamal_gadget<FieldT> (pb,g,  //生成元
                        Gpk,        
                        random_y1,
                        random_y2,
                        random_y3,
                        m,   
                        c1,  
                        c2,  
                        a_pk_s->bits,
                        a_pk_r->bits,
                        v_old,  //整币转账
                        v2_array,
                        v3_array
                    ));
                std::cout<<"elg"<<std::endl;
    }

    void generate_r1cs_constraints() {
        //设置公共参数的长度
        this->pb.set_input_sizes(dimension);

        // sk ,pk
        prf_gad->generate_r1cs_constraints();
        sn_gad->generate_r1cs_constraints();
        
        //comment
        comm_gad_old->generate_r1cs_constraints();
        comm_gad_new->generate_r1cs_constraints();
        
        // value == new_value
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
            1,
            packed_addition(v_old),
            packed_addition(v_new)
        ));
        

        //merkletree
        tree_gad_cm->generate_r1cs_constraints();
        tree_gad_apk_s->generate_r1cs_constraints();
        tree_gad_apk_r->generate_r1cs_constraints();
        
        //
        elgamal_gad->generate_r1cs_constraints();
       
       
    }

    void generate_r1cs_witness(
        uint256& ask,
        uint256& a_pk,
        uint256& apk_r,
        uint256& old_sn,
        uint64_t value,
        uint256& old_r,
        uint256& old_comm,
        uint256 &cm_rt,
        uint256 &apk_s_rt,
        uint256 &apk_r_rt,
        MerkleTreePath &cm_path,
        MerkleTreePath &apk_s_path,
        MerkleTreePath &apk_r_path,
        uint256& new_comm,
        uint256& new_r,
        Elgamal_2apk_3v<FieldT> &elg
    ) {  
        //apk,ask,prf
        a_sk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(ask)); 
        prf_gad->generate_r1cs_witness();
        a_pk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(a_pk));
        
        
        //sn
        r_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(old_r));
        sn_gad->generate_r1cs_witness();
        sn_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(old_sn));

        
        //comment
        v_old.fill_with_bits(this->pb, uint64_to_bool_vector(value));
        
        comm_gad_old->generate_r1cs_witness();
        commitment_old->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(old_comm)
        );
       
        a_pk_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_r));
        v_new.fill_with_bits(this->pb, uint64_to_bool_vector(value));
        r_new->bits.fill_with_bits(this->pb, uint256_to_bool_vector(new_r));
        comm_gad_new->generate_r1cs_witness();
        commitment_new->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(new_comm)
        );

        
    
        root_cm->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cm_rt));
        root_apk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_s_rt));
        root_apk_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_r_rt));

        //merkle tree
        tree_gad_cm->generate_r1cs_witness(
                                cm_path.nodeHashList
                                ,cm_path.parentList
                                ,cm_path.pathisrightList);
        tree_gad_apk_s->generate_r1cs_witness(
                                apk_s_path.nodeHashList
                                ,apk_s_path.parentList
                                ,apk_s_path.pathisrightList);
        tree_gad_apk_r->generate_r1cs_witness(
                                apk_r_path.nodeHashList
                                ,apk_r_path.parentList
                                ,apk_r_path.pathisrightList);
        //elgamal
        for(int i=0;i<253;i++){
            this->pb.val(random_y1[i])=elg.v_y1[i];
            this->pb.val(random_y2[i])=elg.v_y2[i];
            this->pb.val(random_y3[i])=elg.v_y3[i];
        }
    
        this->pb.val(c1[0]) = elg.c1_result1;
        this->pb.val(c2[0]) = elg.c2_result1;
        this->pb.val(m[0]) = elg.m1;
        
        this->pb.val(c1[1]) = elg.c1_result2;
        this->pb.val(c2[1]) = elg.c2_result2;
        this->pb.val(m[1]) = elg.m2;

        this->pb.val(c1[2]) = elg.c1_result3;
        this->pb.val(c2[2]) = elg.c2_result3;
        this->pb.val(m[2]) = elg.m3;
        
        elgamal_gad->generate_r1cs_witness();
        
    }
};


typedef struct transferOne{
     uint256 SNold;/*老随机数*/
     uint256 krnew;/*新承诺*/
     libsnark::r1cs_ppzksnark_proof<ppT> pi;/*整币证明*/
     //unsigned char *data;/*加密数据*/
     unsigned char data[32*6];/*加密数据*/
     libsnark::r1cs_ppzksnark_verification_key<ppT> vk;
     uint256 c_rt;  // 承诺rt
     uint256 s_rt;  // 发送者的公钥树根
     uint256 r_rt;; // 接收者的公钥树根
}tr;



template<typename FieldT>
   transferOne test_js_z( uint256 apk_r, uint256 old_r,uint256 new_r,uint64_t v_1,uint256 ask_s)   
{
    uint64_t n=0;
    uint256 apk_s=prf(ask_s);

    uint256 old_comm=cm(apk_s,v_1,old_r);
    uint256 new_comm=cm(apk_r,v_1,new_r);           // 一个币的承诺，由这个币的持有者公钥、币的币值、这个币的【上一个持有者为当前持有者产生的】随机数经过运算构成。

    uint256 old_sn=sn(ask_s,old_r);

    unsigned char data[32*6];

    Elgamal_2apk_3v<FieldT> elg;

    elg.setG(g);
    
    elg.setPk(Gpk);

    elg.encrypt(apk_s,apk_r,v_1,n,n);//加密


    libsnark::protoboard<FieldT> pb;

    std::cout<<"1"<<std::endl;

    joinsplit_gadget_z<FieldT> js_gad_z(pb,g,Gpk);      
    //joinsplit_gadget_z<FieldT> js_gad_z(pb,g);   
    std::cout<<"2"<<std::endl;
    

    js_gad_z.generate_r1cs_constraints();
    std::cout<<"3"<<std::endl;
    //产生密钥对
    std::cout<<"miyao"<<std::endl;
    auto cs = pb.get_constraint_system();
    std::cout<<"miyao"<<std::endl;
    auto keypair = libsnark::r1cs_ppzksnark_generator<ppT>(cs);
    std::cout<<"miyao"<<std::endl;
    MerkleTreePath cm_path=getMerkleTreePath(ask_s,v_1,old_r);
    uint256 cm_rt=cm_path.root;
    
    MerkleTreePath apk_s_path=getMerkleTreePath_apk_s(ask_s,apk_r);
    uint256 apk_s_rt=apk_s_path.root;

    MerkleTreePath apk_r_path=getMerkleTreePath_apk_r(apk_r);
    uint256 apk_r_rt=apk_r_path.root;
    
    js_gad_z.generate_r1cs_witness(
        ask_s,
        apk_s,
        apk_r,
        old_sn,
        v_1,
        old_r,
        old_comm,
        cm_rt,
        apk_s_rt,
        apk_r_rt,
        cm_path,
        apk_s_path,
        apk_r_path,
        new_comm,
        new_r,
        elg
    ) ;
  
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    auto proof = libsnark::r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    transferOne t;
    t.pi=proof;
    t.vk=keypair.vk;
    t.c_rt= cm_rt;
    t.s_rt=apk_s_rt;
    t.r_rt=apk_r_rt;
    t.SNold=old_sn;
    t.krnew=new_comm;
    elg.getEncryptedData(t.data);
    return t;
}

template<typename FieldT>
class joinsplit_gadget_l : libsnark::gadget<FieldT> {
private:
    //FieldT g;
    //FieldT Gpk;
    libsnark::pb_variable<FieldT> g;
    libsnark::pb_variable<FieldT> Gpk;

    // sk pk
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_sk_s;//私钥  
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk_s;//公钥
    std::shared_ptr<prf_gadget<FieldT>> prf_gad;
    
    //sn
    std::shared_ptr<libsnark::digest_variable<FieldT>> sn_old;//序列号  
    std::shared_ptr<sn_gadget<FieldT>> sn_gad;

    // commitment
    libsnark::pb_variable_array<FieldT> v_old;               //金额
    std::shared_ptr<libsnark::digest_variable<FieldT>> r_old;    //随机数
    std::shared_ptr<libsnark::digest_variable<FieldT>> commitment_old;//老承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_old;

    // merkle tree
    std::shared_ptr<tree_gadget<FieldT>> tree_gad_cm;//承诺树
    std::shared_ptr<libsnark::digest_variable<FieldT>> root_cm;//公钥

    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_s;//付款方
    std::shared_ptr<libsnark::digest_variable<FieldT>> root_apk_s;//根
    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_r;//收款方
    std::shared_ptr<libsnark::digest_variable<FieldT>> root_apk_r;//根

    // balance
    libsnark::pb_variable_array<FieldT> v_new1,v_new2;

    // new commitment
    std::shared_ptr<libsnark::digest_variable<FieldT>> a_pk_r;//收款方公钥
    
    std::shared_ptr<libsnark::digest_variable<FieldT>> r_new1; //新的随机数
    std::shared_ptr<libsnark::digest_variable<FieldT>> commitment_new1;//新承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_new1;

    std::shared_ptr<libsnark::digest_variable<FieldT>> r_new2; //新的随机数
    std::shared_ptr<libsnark::digest_variable<FieldT>> commitment_new2;//新承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_new2;


    //elgamal   
  
    //3次加密的随机数
    libsnark::pb_variable_array<FieldT> random_y1;
    libsnark::pb_variable_array<FieldT> random_y2;
    libsnark::pb_variable_array<FieldT> random_y3;

    libsnark::pb_variable_array<FieldT> m;    //明文列表
    libsnark::pb_variable_array<FieldT> c1;   //密文1列表
    libsnark::pb_variable_array<FieldT> c2;   //密文2列表

    libsnark::pb_variable_array<FieldT> apk1_array;//付款方公约
    libsnark::pb_variable_array<FieldT> apk2_array;//收款方公约

    //金额
    libsnark::pb_variable_array<FieldT> v1_array; 
    libsnark::pb_variable_array<FieldT> v2_array; 
    libsnark::pb_variable_array<FieldT> v3_array;

    ;
    std::shared_ptr<elgamal_gadget<FieldT>> elgamal_gad;

    int dimension;
public:
    joinsplit_gadget_l(libsnark::protoboard<FieldT> &pb,FieldT &sg,FieldT &gpk) : libsnark::gadget<FieldT>(pb) {
        //公共参数长度：序列号256+老承诺哈希树根256+付款方256+收款方256+2*新承诺256+6个密文
        dimension=256+256+256+256+256+256+6+1+1;

        //分配顺序
        sn_old.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        root_cm.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        root_apk_s.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        root_apk_r.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));

        commitment_new1.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        commitment_new2.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));

        c1.allocate(pb,3,"c1");
        c2.allocate(pb,3,"c2");

        g.allocate(pb,"g");
        Gpk.allocate(pb,"Gpk");
        
        this->pb.val(this->g)=sg;
        this->pb.val(this->Gpk)=gpk;

        //ask,apk,prf
        a_sk_s.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        a_pk_s.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        prf_gad.reset(new prf_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            a_pk_s
        ));
        std::cout<<"ask,apk,prf"<<std::endl;

        //comment
        v_old.allocate(pb, 64);
        
        r_old.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        commitment_old.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        comm_gad_old.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_s->bits,
            v_old,
            r_old->bits,
            commitment_old
        ));

        //新承诺
        a_pk_r.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        
        v_new1.allocate(pb, 64);
        r_new1.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        //commitment_new1.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        comm_gad_new1.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_r->bits,
            v_new1,
            r_new1->bits,
            commitment_new1
        ));

        v_new2.allocate(pb, 64);
        r_new2.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        //commitment_new2.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        comm_gad_new2.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_r->bits,
            v_new2,
            r_new2->bits,
            commitment_new2
        ));
        std::cout<<"comment"<<std::endl;

        //sn
        
        sn_gad.reset(new sn_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            r_old->bits,
            sn_old
        ));
        std::cout<<"sn"<<std::endl;

        //merkle tree
        //root.reset(new libsnark::digest_variable<FieldT>(pb, 256, ""));
        tree_gad_cm.reset(new tree_gadget<FieldT>(pb,root_cm,commitment_old,""));
        tree_gad_apk_s.reset(new tree_gadget<FieldT>(pb,root_apk_s,a_pk_s,""));
        tree_gad_apk_r.reset(new tree_gadget<FieldT>(pb,root_apk_r,a_pk_r,""));
        std::cout<<"tree"<<std::endl;

        //elgamal
        //c1.allocate(pb,3,"c1");
        //c2.allocate(pb,3,"c2");
        m.allocate(pb,3,"m");
        
        random_y1.allocate(pb,253,"random_y1");
        random_y2.allocate(pb,253,"random_y2");
        random_y3.allocate(pb,253,"random_y3");

        apk1_array.allocate(pb,256,"m1_array");
        apk2_array.allocate(pb,256,"m2_array");
        v1_array.allocate(pb,64,"m3_array");
        v2_array.allocate(pb,64,"m1_array");
        v3_array.allocate(pb,64,"m2_array");

        elgamal_gad.reset(new elgamal_gadget<FieldT> (pb,g,  //生成元
                        Gpk,        
                        random_y1,
                        random_y2,
                        random_y3,
                        m,   
                        c1,  
                        c2,  
                        a_pk_s->bits,
                        a_pk_r->bits,
                        v_new1,  //整币转账
                        v_new2,
                        v3_array
                    ));
                std::cout<<"elg"<<std::endl;
    }

    void generate_r1cs_constraints() {
        //设置公共参数的长度
        this->pb.set_input_sizes(dimension);

        // sk ,pk
        prf_gad->generate_r1cs_constraints();
        sn_gad->generate_r1cs_constraints();
        
        //comment
        comm_gad_old->generate_r1cs_constraints();
        
        comm_gad_new1->generate_r1cs_constraints();
        comm_gad_new2->generate_r1cs_constraints();

        // value == new_value
        
        this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(
            1,
            packed_addition(v_old),
            packed_addition(v_new1)+packed_addition(v_new2)
        ));

        //merkletree
        tree_gad_cm->generate_r1cs_constraints();
        tree_gad_apk_s->generate_r1cs_constraints();
        tree_gad_apk_r->generate_r1cs_constraints();
        
        
        elgamal_gad->generate_r1cs_constraints();
       
       
    }

    void generate_r1cs_witness(
        uint256& ask,
        uint256& a_pk,
        uint256& apk_r,
        uint256& old_sn,
        uint64_t value1,//应付
        uint64_t value2,//找零
        uint256& old_r,
        uint256& old_comm,
        uint256& cm_rt,
        uint256& apk_s_rt,
        uint256& apk_r_rt,
        MerkleTreePath& cm_path,
        MerkleTreePath& apk_s_path,
        MerkleTreePath& apk_r_path,
        uint256& new_comm1,
        uint256& new_r1,
        uint256& new_comm2,
        uint256& new_r2,
        Elgamal_2apk_3v<FieldT>& elg
    ) {  
        //apk,ask,prf
        a_sk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(ask)); 
        prf_gad->generate_r1cs_witness();
        a_pk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(a_pk));
        
        
        //sn
        r_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(old_r));
        sn_gad->generate_r1cs_witness();
        sn_old->bits.fill_with_bits(this->pb, uint256_to_bool_vector(old_sn));

        
        //comment
        v_old.fill_with_bits(this->pb, uint64_to_bool_vector(value1+value2));
        
        comm_gad_old->generate_r1cs_witness();
        commitment_old->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(old_comm)
        );
       
        a_pk_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_r));

        v_new1.fill_with_bits(this->pb, uint64_to_bool_vector(value1));
        r_new1->bits.fill_with_bits(this->pb, uint256_to_bool_vector(new_r1));
        comm_gad_new1->generate_r1cs_witness();
        commitment_new1->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(new_comm1)
        );
        
        v_new2.fill_with_bits(this->pb, uint64_to_bool_vector(value2));
        r_new2->bits.fill_with_bits(this->pb, uint256_to_bool_vector(new_r2));
        comm_gad_new2->generate_r1cs_witness();
        commitment_new2->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(new_comm2)
        );
    
        root_cm->bits.fill_with_bits(this->pb, uint256_to_bool_vector(cm_rt));
        root_apk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_s_rt));
        root_apk_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_r_rt));

        //merkle tree
        tree_gad_cm->generate_r1cs_witness(
                                cm_path.nodeHashList
                                ,cm_path.parentList
                                ,cm_path.pathisrightList);
        tree_gad_apk_s->generate_r1cs_witness(
                                apk_s_path.nodeHashList
                                ,apk_s_path.parentList
                                ,apk_s_path.pathisrightList);
        tree_gad_apk_r->generate_r1cs_witness(
                                apk_r_path.nodeHashList
                                ,apk_r_path.parentList
                                ,apk_r_path.pathisrightList);
        
        //elgamal
        for(int i=0;i<253;i++){
            this->pb.val(random_y1[i])=elg.v_y1[i];
            this->pb.val(random_y2[i])=elg.v_y2[i];
            this->pb.val(random_y3[i])=elg.v_y3[i];
        }
    
        this->pb.val(c1[0]) = elg.c1_result1;
        this->pb.val(c2[0]) = elg.c2_result1;
        this->pb.val(m[0]) = elg.m1;
        
        this->pb.val(c1[1]) = elg.c1_result2;
        this->pb.val(c2[1]) = elg.c2_result2;
        this->pb.val(m[1]) = elg.m2;

        this->pb.val(c1[2]) = elg.c1_result3;
        this->pb.val(c2[2]) = elg.c2_result3;
        this->pb.val(m[2]) = elg.m3;
        
        elgamal_gad->generate_r1cs_witness();
        
    }
};

typedef struct transferZero{
      uint256 SNold;/*老序列号*/
      uint256 krnew;/*接收方新承诺*/
      uint256 ksnew;/*发送方新承诺*/
      libsnark::r1cs_ppzksnark_proof<ppT> pi;/*零币证明*/
      unsigned char data[32*6];
      libsnark::r1cs_ppzksnark_verification_key<ppT> vk;/*加密数据*/
      uint256 c_rt;
      uint256 s_rt;
      uint256 r_rt;
}trs;

template<typename FieldT>
transferZero test_js_l(uint256 apk_r/*接收方公钥*/,uint256 new_r1/*新随机数1*/,uint256 new_r2/*新随机数2*/,uint64_t v_1,uint256 ask_s/*发送方私钥*/,uint256 old_r/*老随机数*/,uint64_t v_2) 
{
     uint64_t n=0;
    uint256 apk_s=prf(ask_s);
    uint256 old_comm=cm(apk_s,v_1+v_2,old_r);

    uint256 new_comm1=cm(apk_r,v_1,new_r1);
    uint256 new_comm2=cm(apk_r,v_2,new_r2);

    uint256 old_sn=sn(ask_s,old_r);

    unsigned char data[32*6];

    Elgamal_2apk_3v<FieldT> elg;

    elg.setG(g);
    
    elg.setPk(Gpk);

    elg.encrypt(apk_s,apk_r,v_1,v_2,n);//加密


 
    libsnark::protoboard<FieldT> pb;

    std::cout<<"1"<<std::endl;

    joinsplit_gadget_l<FieldT> js_gad_l(pb,g,Gpk);        
    std::cout<<"2"<<std::endl;
    //pb.set_input_sizes(dimension);

    js_gad_l.generate_r1cs_constraints();
    std::cout<<"3"<<std::endl;
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = libsnark::r1cs_ppzksnark_generator<ppT>(cs);
   
    MerkleTreePath cm_path=getMerkleTreePath_lb(ask_s,v_1,v_2,old_r);
    uint256 cm_rt=cm_path.root;
    
    MerkleTreePath apk_s_path=getMerkleTreePath_apk_s(ask_s,apk_r);
    uint256 apk_s_rt=apk_s_path.root;
    
    MerkleTreePath apk_r_path=getMerkleTreePath_apk_r(apk_r);
    uint256 apk_r_rt=apk_r_path.root;

    js_gad_l.generate_r1cs_witness(
        ask_s,
        apk_s,
        apk_r,
        old_sn,
        v_1,
        v_2,
        old_r,
        old_comm,
        cm_rt,
        apk_s_rt,
        apk_r_rt,
        cm_path,
        apk_s_path,
        apk_r_path,
        new_comm1,
        new_r1,
        new_comm2,
        new_r2,
        elg
    ) ;
  
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    auto proof = libsnark::r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
   
    transferZero tr;
    tr.pi=proof;
    tr.vk=keypair.vk;
    elg.getEncryptedData(tr.data);
    tr.c_rt= cm_rt;
    tr.s_rt=apk_s_rt;
    tr.r_rt=apk_r_rt;
    tr.SNold=old_sn;/*老序列号*/
    tr.krnew=new_comm2;/*接收方新承诺*/
    tr.ksnew=new_comm1;/*发送方新承诺*/
    return tr;
}

//加密
//std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData );
  
//解密
std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData );

typedef struct msgMintRequest{
    uint256 Upk;//用户公钥
    uint256 kmint;//承诺
    int64_t v;//金额
    uint256 p;//随机数
}msg;

msgMintRequest makeMintRequest(uint256 Usk/*用户私钥*/,uint256 p/*随机数*/, int64_t v/*金额*/);

typedef struct msgMint{
     uint256 kmint;
     unsigned char data[32*6];
     std::string Sigpub;
}ms;

msgMint makeMsgMint(uint256 kmint,int64_t v,uint256 upk);


template<typename FieldT>
transferZero makeTransferZero(uint256 Rpk/*接收方公钥*/,uint256 pr1/*新随机数1*/,uint256 pr2/*新随机数2*/,uint64_t vr,uint256 Ssk/*发送发私钥*/,uint256 ps,uint64_t vs)
{ 
    transferZero tmp3=test_js_l<FieldT>( Rpk, pr1,pr2,vr,Ssk,ps,vs);     
    return tmp3;
}

template<typename FieldT>
transferOne makeTransferOne(uint256 Rpk/*接收方公钥*/,uint256 ps/*老随机数*/,uint256 pr/*新随机数*/,uint64_t vr,uint256 Ssk/*发送方私钥*/)
{
    transferOne tmp4=test_js_z<FieldT>(Rpk,ps,pr,vr,Ssk);
    
    return tmp4;
      
}

template<typename FieldT>
bool transferZeroVerify(uint256 SNold ,uint256 krnew,uint256 ksnew,  unsigned char *data, libsnark::r1cs_ppzksnark_proof<ppT> pr,libsnark::r1cs_ppzksnark_verification_key<ppT> vk,uint256 cm_rt,uint256 apk_s_rt,uint256 apk_r_rt)
{ 

     std::vector<FieldT> pi_v;


    //---------------sn-------------
    std::vector<bool> sn_v=uint256_to_bool_vector(SNold );
    for(int i=0;i<256;i++){
        if(sn_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(sn_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //---老承诺哈希树的根--------------
    std::vector<bool> rt_v=uint256_to_bool_vector(cm_rt);
    for(int i=0;i<256;i++){
        if(rt_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(rt_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //---付款方哈希树的根--------------
    std::vector<bool> apk_s_rt_v=uint256_to_bool_vector(apk_s_rt);
    for(int i=0;i<256;i++){
        if(apk_s_rt_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(apk_s_rt_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }
    //---收款方哈希树的根--------------
    std::vector<bool> apk_r_rt_v=uint256_to_bool_vector(apk_r_rt);
    for(int i=0;i<256;i++){
        if(apk_r_rt_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(apk_r_rt_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //-------新承诺1---------------
    std::vector<bool> new_comm_v1=uint256_to_bool_vector(ksnew);
    for(int i=0;i<256;i++){
        if(new_comm_v1[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(new_comm_v1[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }
    std::vector<bool> new_comm_v2=uint256_to_bool_vector(krnew);
    for(int i=0;i<256;i++){
        if(new_comm_v2[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(new_comm_v2[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //---公钥和金额的密文-----------
    //通过密文byte流获得密文FieldT
    Elgamal_2apk_3v<FieldT> elg_v;
    //data[0]=0;
    elg_v.setEncryptedData(data);
    
    //pi_v.push_back(elg_v.c1_result1+bigint_r(1));
    pi_v.push_back(elg_v.c1_result1);
    pi_v.push_back(elg_v.c1_result2);
    pi_v.push_back(elg_v.c1_result3);

    pi_v.push_back(elg_v.c2_result1);
    pi_v.push_back(elg_v.c2_result2);
    pi_v.push_back(elg_v.c2_result3);

    //生成元和公钥
    pi_v.push_back(g);
    //pi_v.push_back(Gpk+bigint_r(1));
    pi_v.push_back(Gpk);

    //auto pi_v = pb.primary_input();
    if(libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(vk,pi_v,pr)) {
        std::cout << "\n\n============ Maskash Verified! ============\n\n" << std::endl;
        return 1;
    } 
    else {
        std::cout << "\n\n============ Failed to verify! ============\n\n" << std::endl;
        return 0;
    }
}
template<typename FieldT>
bool transferOneVerify(uint256 SNold,uint256 krnew, uint256 cm_rt,uint256 apk_s_rt,uint256 apk_r_rt,unsigned char *data,libsnark::r1cs_ppzksnark_verification_key<ppT> vk, libsnark::r1cs_ppzksnark_proof<ppT> pr)
{     
    std::vector<FieldT> pi_v;    

    //---------------sn-------------
    std::vector<bool> sn_v=uint256_to_bool_vector( SNold);
    for(int i=0;i<256;i++){
        if(sn_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(sn_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //---老承诺哈希树的根--------------
    std::vector<bool> rt_v=uint256_to_bool_vector(cm_rt);
    for(int i=0;i<256;i++){
        if(rt_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(rt_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //---付款方哈希树的根--------------
    std::vector<bool> apk_s_rt_v=uint256_to_bool_vector(apk_s_rt);
    for(int i=0;i<256;i++){
        if(apk_s_rt_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(apk_s_rt_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }
    //---收款方哈希树的根--------------
    std::vector<bool> apk_r_rt_v=uint256_to_bool_vector(apk_r_rt);
    for(int i=0;i<256;i++){
        if(apk_r_rt_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(apk_r_rt_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //-------新承诺---------------
    std::vector<bool> new_comm_v=uint256_to_bool_vector(krnew);
    for(int i=0;i<256;i++){
        if(new_comm_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(new_comm_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }
    Elgamal_2apk_3v<FieldT> G;
    //data[0]=0;
    G.setEncryptedData(data);
    G.setSk(Gsk);
    pi_v.push_back(G.c1_result1);
    pi_v.push_back(G.c1_result2);
    pi_v.push_back(G.c1_result3);

    pi_v.push_back(G.c2_result1);
    pi_v.push_back(G.c2_result2);
    pi_v.push_back(G.c2_result3);

    //生成元和公钥
    pi_v.push_back(g);
    //pi_v.push_back(Gpk+bigint_r(1));
    pi_v.push_back(Gpk);

    //auto pi_v = pb.primary_input();
    if(libsnark::r1cs_ppzksnark_verifier_strong_IC<ppT>(vk,pi_v,pr)) {
      std::cout<<"\n\n============ Maskash Verified! ============\n\n"<<std::endl;
      return 1;
    } 
    else {
      std::cout<<"\n\n============ Failed to verify! ============\n\n"<<std::endl;
      return 0;
    }
};

}


#endif
