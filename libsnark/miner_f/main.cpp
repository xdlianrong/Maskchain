/** @file
 *****************************************************************************
 Unit tests for gadgetlib1 - main() for running all tests
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/


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
#include <stdint.h>
#include <sstream>
#include <algorithm>
#include <pthread.h>  
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <semaphore.h>

//#define d_count 3  //捐款者数量
#define IPLIST "IPList.txt" //存放各个捐款者IP地址以及端口号的文件  
#define SYSTEMIPLIST   "../systemIPList.txt"  //存放捐赠平台（第一个），受捐者（第二个），矿工（第三个）的ip地址以及端口号


using namespace std;
using namespace libsnark;
using namespace libff;

using ppT = default_r1cs_ppzksnark_pp; 
using FieldT = ppT::Fp_type;

uint256 one_hash(const unsigned char *data, size_t len){
    CSHA256 hasher;
    hasher.Write(data, len);

    uint256 result;
    hasher.Finalize(result.begin());

    return result;
}

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

std::vector<bool> uint64_to_bool_vector(uint64_t input) {
    auto num_bv = convertIntToVectorLE(input);
    
    return convertBytesVectorToVector(num_bv);
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

//------------公私匙部分-----------------------------
//用户公钥由私钥哈希而来
template<typename FieldT>
class prf_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher;

public:
    prf_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT>& a_sk,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb) {

        //H(a_sk,a_sk)
        block.reset(new block_variable<FieldT>(pb, {
            a_sk,
            a_sk
        }, ""));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher.reset(new sha256_compression_function_gadget<FieldT>(
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
uint256 prf(uint256 a_sk){
    CSHA256 hasher;
   
    uint256 result;

    //H(a_sk a_sk)
    hasher.Write(a_sk.begin(), 32);
    hasher.Write(a_sk.begin(), 32);
    hasher.FinalizeNoPadding(result.begin());
  
    return result;
}
template<typename FieldT>
void test_rpf(){
    protoboard<FieldT> pb;

    std::shared_ptr<digest_variable<FieldT>> h_result;
    h_result.reset(new digest_variable<FieldT>(pb, 256, ""));

    pb_variable_array<FieldT> a_sk;
    a_sk.allocate(pb,256,"a_pk");
   

    uint256 ask_256_1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    uint256 ask_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
   

    a_sk.fill_with_bits(pb,uint256_to_bool_vector(ask_256));
   

    prf_gadget<FieldT> prf_gad(pb, a_sk,h_result);

    prf_gad.generate_r1cs_constraints();

    uint256 apk_256=prf(ask_256);
    //apk_256=uint256S("038cce42abd366b83ede7e009130de53722df73dee8251148cb48d1b9af68ad1");

    const libff::bit_vector prf_bv = uint256_to_bool_vector(apk_256);
  
    prf_gad.generate_r1cs_witness();

    (*h_result).generate_r1cs_witness(prf_bv);

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
}

//--------------SN序列号-----------------------------
//序列号由用户私钥和随机数哈希而成
template<typename FieldT>
class sn_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher;

public:
    sn_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT>& a_sk,
        pb_variable_array<FieldT>& r,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb) {
       
        //H(a_sk,r)
        block.reset(new block_variable<FieldT>(pb, {
            a_sk,
            r
        }, ""));

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher.reset(new sha256_compression_function_gadget<FieldT>(
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
uint256 sn(uint256 a_sk,uint256 r){
    CSHA256 hasher;
  
    uint256 result;

    //H(a_sk r)
    hasher.Write(a_sk.begin(), 32);
    hasher.Write(r.begin(), 32);
    hasher.FinalizeNoPadding(result.begin());
  
    return result;
}

template<typename FieldT>
void test_sn(){
    protoboard<FieldT> pb;

    std::shared_ptr<digest_variable<FieldT>> h_result;
    h_result.reset(new digest_variable<FieldT>(pb, 256, ""));

    pb_variable_array<FieldT> a_sk;
    a_sk.allocate(pb,256,"a_pk");
   
    pb_variable_array<FieldT> r;
    r.allocate(pb,256,"r");

    uint256 ask_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    uint256 r_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
   

    a_sk.fill_with_bits(pb,uint256_to_bool_vector(ask_256));
    r.fill_with_bits(pb,uint256_to_bool_vector(r_256));

    sn_gadget<FieldT> sn_gad(pb, a_sk,r,h_result);

    sn_gad.generate_r1cs_constraints();

    uint256 sn_256=sn(ask_256,r_256);
    //sn_256=uint256S("038cce42abd366b83ede7e009130de53722df73dee8251148cb48d1b9af68ad1");

    const libff::bit_vector sn_bv = uint256_to_bool_vector(sn_256);
  
    sn_gad.generate_r1cs_witness();

    (*h_result).generate_r1cs_witness(sn_bv);

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
}


//-----------------------承诺部分------------------------
template<typename FieldT>
class comm_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block1;
    std::shared_ptr<block_variable<FieldT>> block2;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher1;
    std::shared_ptr<digest_variable<FieldT>> intermediate_hash;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher2;

public:
    comm_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT>& a_pk,
        pb_variable_array<FieldT>& v,
        pb_variable_array<FieldT>& r,
        std::shared_ptr<digest_variable<FieldT>> result
    ) : gadget<FieldT>(pb) {

        intermediate_hash.reset(new digest_variable<FieldT>(pb, 256, ""));
        cout<<"com1 "<<endl;
        //H(a_pk,v)
        block1.reset(new block_variable<FieldT>(pb, {
            a_pk,
            v,
            v,
            v,
            v
        }, ""));
        cout<<"com2 "<<endl;
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        ""));
        cout<<"com3 "<<endl;
        pb_variable_array<FieldT> intermediate_block;
        intermediate_block.insert(intermediate_block.end(), (*intermediate_hash).bits.begin(), (*intermediate_hash).bits.end());
        cout<<"com4 "<<endl;
        //H(H(a_pk,v),r)
        block2.reset(new block_variable<FieldT>(pb, {
            intermediate_block,
            r
        }, ""));
        cout<<"com5 "<<endl;
        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block2->bits,
            *result,
        ""));
        cout<<"com6 "<<endl;
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


uint256 cm(uint256 a_pk, int64_t v, uint256 r) {
    CSHA256 hasher1;
    CSHA256 hasher2;

    uint256 imt;
    uint256 result;

    //H(a_pk )
    hasher1.Write(a_pk.begin(), 32);

    //H(apk,v,v,v,v)
    auto value_vec = convertIntToVectorLE(v);
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

template<typename FieldT>
void testcm(){
    
    protoboard<FieldT> pb;

    std::shared_ptr<digest_variable<FieldT>> h_result;
    h_result.reset(new digest_variable<FieldT>(pb, 256, ""));

    pb_variable_array<FieldT> a_pk;
    pb_variable_array<FieldT> v;
    pb_variable_array<FieldT> r;
    
    a_pk.allocate(pb,256,"a_pk");
    v.allocate(pb,64,"v");
    r.allocate(pb,256,"r");


    uint256 apk_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    int64_t v_64=5;
    uint256 r_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68aww");

    a_pk.fill_with_bits(pb,uint256_to_bool_vector(apk_256));
    v.fill_with_bits(pb,uint64_to_bool_vector(v_64));
    r.fill_with_bits(pb,uint256_to_bool_vector(r_256));

    comm_gadget<FieldT> commitment(pb, a_pk, v, r, h_result);

    commitment.generate_r1cs_constraints();

    uint256 cm_256=cm(apk_256,v_64,r_256);

    const libff::bit_vector commitment_bv = uint256_to_bool_vector(cm_256);
  
  
    commitment.generate_r1cs_witness();
    (*h_result).generate_r1cs_witness(commitment_bv);

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
}


//-----------Elgamal加密解密及其证明部分-----------------------------
void outBoolVector(std::vector<bool> &v){
     for(size_t i=0;i<v.size();i++){

        cout<<v[i]<<" , ";
    }
    cout<<endl;
}


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
/*
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
*/

//十六进制字符串转换为字节流  
void HexStrToByte(const char* source, unsigned char* dest, int sourceLen)  
{  
    short i;  
    unsigned char highByte, lowByte;  
          
    for (i = 0; i < sourceLen; i += 2)  
    {  
        highByte = toupper(source[i]);  
        lowByte  = toupper(source[i + 1]);  
      
        if (highByte > 0x39)  
            highByte -= 0x37;  
        else  
            highByte -= 0x30;  
      
        if (lowByte > 0x39)  
            lowByte -= 0x37;  
        else  
            lowByte -= 0x30;  
      
        dest[i / 2] = (highByte << 4) | lowByte;  
    }  
    return ;  
}  

//字节流转换为十六进制字符串  
/*
void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )  
{  
    int  i;  
    char szTmp[3];  
  
    for( i = 0; i < nSrcLen; i++ )  
    {  
        sprintf( szTmp, "%02X", (unsigned char) sSrc[i] );  
        memcpy( &sDest[i * 2], szTmp, 2 );  
    }  
    return ;  
}
*/
void Hex2Str( const char *sSrc,  char *sDest, int nSrcLen )  
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
typedef bigint<alt_bn128_r_limbs> bigint_r;
#define bigint_len 32

//通过拷贝二进制数组构造bigint
void byteToBigint(bigint_r &b,unsigned char *bytebuf){
    memcpy(&b.data[0],bytebuf,bigint_len);
}
void byteToBigintEx(bigint_r &b,unsigned char *bytebuf,int len){
    if(len>31){
        return;
    }
    memcpy(&b.data[0],bytebuf,bigint_len);
}
void byteToint64(uint64_t &i64,unsigned char* buf){
    memcpy(&i64,buf,8);
}

uint256 byteToUint256(unsigned char *bytebuf){
    char hex[65];
    hex[64]=0;
    Hex2Str((char*)bytebuf,hex,32);
    return uint256S(hex);
}

uint256 longToUint256(unsigned char *bytebuf){
    char hex[9];
    hex[8]=0;
    Hex2Str((char*)bytebuf,hex,4);
    return uint256S(hex); 
}
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

    string c1_tmp1_bigintstr1,c2_tmp1_bigintstr1;
    string c1_tmp2_bigintstr2,c2_tmp2_bigintstr2;
    string c1_tmp3_bigintstr3,c2_tmp3_bigintstr3;

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
    vector<FieldT> v_y1;
    vector<FieldT> v_y2;
    vector<FieldT> v_y3;

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
    
        cout<<"before encrypt:"<<endl;
        cout<<apk_s.ToString()<<endl;
        cout<<apk_r.ToString()<<endl;

        cout<<v_1<<endl;
        cout<<v_2<<endl;

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

    void decrypt(){
        c1_tmp1 = byteToFp<FieldT>(encrypted_data);
        c2_tmp1 = byteToFp<FieldT>(&encrypted_data[32]);
        
        c1_tmp2 = byteToFp<FieldT>(&encrypted_data[32*2]);
        c2_tmp2 = byteToFp<FieldT>(&encrypted_data[32*3]);

        c1_tmp3 = byteToFp<FieldT>(&encrypted_data[32*4]);
        c2_tmp3 = byteToFp<FieldT>(&encrypted_data[32*5]);
        
        /*
        c1_tmp1 = hexStrToFp<FieldT>(encrypted_hex_str);
        c2_tmp1 = hexStrToFp<FieldT>(&encrypted_hex_str[64]);

        c1_tmp2 = hexStrToFp<FieldT>(&encrypted_hex_str[64*2]);
        c2_tmp2 = hexStrToFp<FieldT>(&encrypted_hex_str[64*3]);

        c1_tmp3 = hexStrToFp<FieldT>(&encrypted_hex_str[64*4]);
        c2_tmp3 = hexStrToFp<FieldT>(&encrypted_hex_str[64*5]);
        */
       
        FieldT s1 = c1_tmp1 ^ Gsk.as_bigint();
        FieldT m1 = c2_tmp1 * s1.inverse();
        
        FieldT s2 = c1_tmp2 ^ Gsk.as_bigint();
        FieldT m2 = c2_tmp2 * s2.inverse();
       
        FieldT s3 = c1_tmp3 ^ Gsk.as_bigint();
        FieldT m3 = c2_tmp3 * s3.inverse();
       
        unsigned char buf_tmp[96];
        memset(buf_tmp,0,96);

        fpToByte(m1,buf_tmp);
        
        fpToByte(m2,buf_tmp+31);
        fpToByte(m3,buf_tmp+31+31);
        
        restoreFromByteBuf(buf_tmp);

    }

    void decryptHexStr(char *hexstr){
        
        c1_tmp1 = hexStrToFp<FieldT>(hexstr);
        c2_tmp1 = hexStrToFp<FieldT>(&hexstr[64]);

        c1_tmp2 = hexStrToFp<FieldT>(&hexstr[64*2]);
        c2_tmp2 = hexStrToFp<FieldT>(&hexstr[64*3]);

        c1_tmp3 = hexStrToFp<FieldT>(&hexstr[64*4]);
        c2_tmp3 = hexStrToFp<FieldT>(&hexstr[64*5]);
       
        FieldT s1 = c1_tmp1 ^ Gsk.as_bigint();
        m1 = c2_tmp1 * s1.inverse();
        
        FieldT s2 = c1_tmp2 ^ Gsk.as_bigint();
        m2 = c2_tmp2 * s2.inverse();

        FieldT s3 = c1_tmp3 ^ Gsk.as_bigint();
        m3 = c2_tmp3 * s3.inverse();
       
        unsigned char buf_tmp[96];
        memset(buf_tmp,0,96);

        fpToByte(m1,buf_tmp);
        fpToByte(m2,buf_tmp+31);
        fpToByte(m3,buf_tmp+31+31);
        
        restoreFromByteBuf(buf_tmp);
    }

    void decryptData(unsigned char *data){
        
        c1_tmp1 = byteToFp<FieldT>(data);
        c2_tmp1 = byteToFp<FieldT>(&data[32]);
        
        c1_tmp2 = byteToFp<FieldT>(&data[32*2]);
        c2_tmp2 = byteToFp<FieldT>(&data[32*3]);

        c1_tmp3 = byteToFp<FieldT>(&data[32*4]);
        c2_tmp3 = byteToFp<FieldT>(&data[32*5]);
        
        /*
        c1_tmp1 = hexStrToFp<FieldT>(encrypted_hex_str);
        c2_tmp1 = hexStrToFp<FieldT>(&encrypted_hex_str[64]);

        c1_tmp2 = hexStrToFp<FieldT>(&encrypted_hex_str[64*2]);
        c2_tmp2 = hexStrToFp<FieldT>(&encrypted_hex_str[64*3]);

        c1_tmp3 = hexStrToFp<FieldT>(&encrypted_hex_str[64*4]);
        c2_tmp3 = hexStrToFp<FieldT>(&encrypted_hex_str[64*5]);
        */
       
        FieldT s1 = c1_tmp1 ^ Gsk.as_bigint();
        m1 = c2_tmp1 * s1.inverse();
        
        FieldT s2 = c1_tmp2 ^ Gsk.as_bigint();
        m2 = c2_tmp2 * s2.inverse();
       
        FieldT s3 = c1_tmp3 ^ Gsk.as_bigint();
        m3 = c2_tmp3 * s3.inverse();
        
        unsigned char buf_tmp[96];
        memset(buf_tmp,0,96);

        fpToByte(m1,buf_tmp);
        fpToByte(m2,buf_tmp+31);
        fpToByte(m3,buf_tmp+31+31);
        
        restoreFromByteBuf(buf_tmp);

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
    char* getEncryptedHexStr(){
        return encrypted_hex_str;
    }
    string getEncryptedHexString(){
        return string(encrypted_hex_str);
    }
    unsigned char getEncryptedDataBegin(){
        return encrypted_data;
    }
    unsigned char getEncryptedData(unsigned char *buf){
        memcpy(buf,encrypted_data,32*6);
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
    FieldT getRandom(vector<FieldT> &Y){
        srand(unsigned(time(0)));
        FieldT y = FieldT::zero();
        for(int i=0;i<253;i++){
            Y.push_back(FieldT::one()*(rand()%2));
            y += Y[i] * ((FieldT::one()*2) ^ bigint_r(i));
        }
        return y;
    }
    void restoreFromByteBuf(unsigned char *bytebuf){
       
        cout<<"before restore:"<<endl;
        cout<<"restore from buf:"<<endl;

        apk_s=*(uint256*)bytebuf;
        apk_r=*(uint256*)(bytebuf+32);
        
        v_1=*(uint64_t*)&bytebuf[32+32];
        v_2=*(uint64_t*)&bytebuf[32+32+8];
        v_3=*(uint64_t*)&bytebuf[32+32+8+8];
       
    }
};

template<typename FieldT>
void test_elgamal(){
    
    uint256 apk_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint64_t v_1=5;
    uint64_t v_2=6;
    uint64_t v_3=8;

    unsigned char data[32*6];
    char g_c[]="11112222333344445555666677778888999900001111";
    char sk[]="1234567890";
    FieldT g=bigint_r(g_c);
    FieldT Gsk = bigint_r(sk);//私钥
    FieldT Gpk = g ^ Gsk.as_bigint();//公钥

    Elgamal_2apk_3v<FieldT> elg;
    elg.setG(g);
    elg.setPk(Gpk);

    elg.encrypt(apk_s,apk_r,v_1,v_2,v_3);//加密
    
    elg.getEncryptedData(data);//获取加密数据

    elg.setSk(Gsk);//设置私钥

    elg.decryptData(data);//解密
    //elg.decrypt();//用于内部算法测试

    cout<<elg.apk_s.ToString()<<endl;
    cout<<elg.apk_r.ToString()<<endl;
    cout<<elg.v_1<<endl;
    cout<<elg.v_2<<endl;
    cout<<elg.v_3<<endl;
}

/*
template<typename FieldT>
class exp_gadget : public gadget<FieldT> {
private:
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
*/

template<typename FieldT>
class exp_gadget : public gadget<FieldT> {
private:
    pb_variable_array<FieldT> _A;
    pb_variable_array<FieldT> temp1;
    pb_variable_array<FieldT> temp2;
    pb_variable_array<FieldT> temp3;
    //FieldT g;
    pb_variable<FieldT> g;
public:
    const pb_linear_combination_array<FieldT> A;
    const pb_variable<FieldT> result;

    //exp_gadget(FieldT g, protoboard<FieldT>& pb,
    exp_gadget(pb_variable<FieldT> &g, protoboard<FieldT>& pb,
                         const pb_linear_combination_array<FieldT> &A,//y
                         const pb_variable<FieldT> &result,
                         const std::string &annotation_prefix="") :
        gadget<FieldT>(pb, annotation_prefix), A(A), g(g), result(result)
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
        r1cs_constraint<FieldT>(FieldT::one() - A[i], FieldT::one(), _A[i]),
        FMT(this->annotation_prefix, " S_%zu", i));
      this->pb.add_r1cs_constraint(
        r1cs_constraint<FieldT>(A[i], this->pb.val(g) ^ ((FieldT::one()*2) ^ bigint_r(i)).as_bigint(), temp1[i]),
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
        this->pb.val(temp1[i]) = this->pb.lc_val(A[i]) * (this->pb.val(g) ^ ((FieldT::one()*2) ^ bigint_r(i)).as_bigint());
        this->pb.val(temp2[i]) = this->pb.lc_val(_A[i]) + this->pb.val(temp1[i]) ;
    }
    for (size_t i = 0; i < temp3.size()+1; ++i){
      this->pb.val(i == temp3.size() ? result : temp3[i]) = (i==0 ? this->pb.val(temp2[0]) : this->pb.val(temp3[i-1]) ) * this->pb.val(temp2[i+1]);
    }
}

template<typename FieldT>
class binary_gadget : public gadget<FieldT> {
private:
    pb_variable_array<FieldT> temp1;
    pb_variable_array<FieldT> temp2;
    FieldT g;
public:
    const pb_linear_combination_array<FieldT> A;
    const pb_variable<FieldT> result;

    binary_gadget(protoboard<FieldT>& pb,
                         const pb_linear_combination_array<FieldT> &A,//y
                         const pb_variable<FieldT> &result,
                         const std::string &annotation_prefix="") :
        gadget<FieldT>(pb, annotation_prefix), A(A), result(result)
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
            r1cs_constraint<FieldT>( A[i] * (g ^ i) , FieldT::one(), temp1[i]),FMT(this->annotation_prefix, " S_%zu", i));     
        }
        for (size_t i = 0; i < temp2.size(); ++i)
        {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(i==0 ? temp1[0]: temp2[i-1]+temp1[i]
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
class elgamal_gadget : public gadget<FieldT>{
    //FieldT g;
    //FieldT pk;
    pb_variable<FieldT> g;
    pb_variable<FieldT> pk;
    pb_variable<FieldT> result1_1;
    pb_variable<FieldT> result1_2;
  
    pb_variable<FieldT> result2_1;
    pb_variable<FieldT> result2_2;

    pb_variable<FieldT> result3_1;
    pb_variable<FieldT> result3_2;

    std::shared_ptr<exp_gadget<FieldT>> exp1_1;
    std::shared_ptr<exp_gadget<FieldT>> exp1_2;

    std::shared_ptr<exp_gadget<FieldT>> exp2_1;
    std::shared_ptr<exp_gadget<FieldT>> exp2_2;

    std::shared_ptr<exp_gadget<FieldT>> exp3_1;
    std::shared_ptr<exp_gadget<FieldT>> exp3_2;

    std::shared_ptr<binary_gadget<FieldT>> binary1;
    std::shared_ptr<binary_gadget<FieldT>> binary2;
    std::shared_ptr<binary_gadget<FieldT>> binary3;

    pb_variable_array<FieldT> random_y1;
    pb_variable_array<FieldT> random_y2;
    pb_variable_array<FieldT> random_y3;

    pb_variable_array<FieldT> m;  
    pb_variable_array<FieldT> c1;  
    pb_variable_array<FieldT> c2;

    pb_variable_array<FieldT> apk1_array;
    pb_variable_array<FieldT> apk2_array;
    pb_variable_array<FieldT> v1_array;
    pb_variable_array<FieldT> v2_array;
    pb_variable_array<FieldT> v3_array;

    pb_variable_array<FieldT> m1_array;
    pb_variable_array<FieldT> m2_array;
    pb_variable_array<FieldT> m3_array;

    pb_variable<FieldT> m1_binary_result;
    pb_variable<FieldT> m2_binary_result;
    pb_variable<FieldT> m3_binary_result;

public:
    elgamal_gadget(protoboard<FieldT> &pb,
                        //FieldT &sg,  //生成元
                        //FieldT &gpk,
                        pb_variable<FieldT> &sg,
                        pb_variable<FieldT> &gpk,
                        pb_variable_array<FieldT> &ran_y1,//第一个明文加密随机数
                        pb_variable_array<FieldT> &ran_y2,//第二个明文加密随机数
                        pb_variable_array<FieldT> &ran_y3,//第三个明文加密随机数
                        pb_variable_array<FieldT> &m_arr,   //明文列表
                        pb_variable_array<FieldT> &c1_arr,  //密文1列表
                        pb_variable_array<FieldT> &c2_arr,  //密文2列表
                        pb_variable_array<FieldT> &apk1_arr,
                        pb_variable_array<FieldT> &apk2_arr,
                        pb_variable_array<FieldT> &v1_arr,
                        pb_variable_array<FieldT> &v2_arr,
                        pb_variable_array<FieldT> &v3_arr
        )
        :gadget<FieldT>(pb){
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
            generate_boolean_r1cs_constraint(this->pb,pb_linear_combination<FieldT>(random_y1[i]));
            generate_boolean_r1cs_constraint(this->pb,pb_linear_combination<FieldT>(random_y2[i]));
            generate_boolean_r1cs_constraint(this->pb,pb_linear_combination<FieldT>(random_y3[i]));
        }
        
        //apk1，前31字节
        for(int i=0;i<31*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m1_array[i], FieldT::one(), apk1_array[j-off]),FMT(" S_%zu"));
            //m1_array[i]=apk1_array[j-off];
        }
    
        //apk1，后1个字节
        for(int i=0;i<1*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m2_array[i], FieldT::one(), apk1_array[31*8+j-off]),FMT(" S_%zu"));
            //m2_array[i]=apk1_array[31*8+j-off];
        }
        
        //apk2，前30字节
        for(int i=0;i<30*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m2_array[1*8+i], FieldT::one(), apk2_array[j-off]),FMT(" S_%zu"));
            //m2_array[1*8+i]=apk2_array[j-off];
        }
    
        //apk2,后2个字节，
        for(int i=0;i<2*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_array[i], FieldT::one(), apk2_array[30*8+j-off]),FMT(" S_%zu"));
            //m3_array[i]=apk2_array[30*8+j-off];
        }
        
        //v1,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_array[2*8+i], FieldT::one(), v1_array[j-off]),FMT(" S_%zu"));
            //m3_array[2*8+i]=v1_array[j-off];
        }
    
        //v2,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;

            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_array[2*8+8*8+i], FieldT::one(), v2_array[j-off]),FMT(" S_%zu"));
            //m3_array[2*8+8*8+i]=v2_array[j-off];
        }
    
        //v3,8个字节
        for(int i=0;i<8*8;i++){
            int j=((i/8)+1)*8-1;
            int off=i%8;
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_array[2*8+8*8+8*8+i], FieldT::one(), v3_array[j-off]),FMT(" S_%zu"));
            //m3_array[2*8+8*8+8*8+i]=v3_array[j-off]; 
        }

        
        //密文等于明文加密
        //约束：g ^ y == c1
        exp1_1->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result1_1, FieldT::one(), c1[0]),FMT(" S_%zu"));

        exp2_1->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result2_1, FieldT::one(), c1[1]),FMT(" S_%zu"));

        exp3_1->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result3_1, FieldT::one(), c1[2]),FMT(" S_%zu"));
        
        //约束：m * (Gpk ^ y) == c2
        exp1_2->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result1_2, m[0], c2[0]),FMT(" S_%zu"));

        exp2_2->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result2_2, m[1], c2[1]),FMT(" S_%zu"));

        exp3_2->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result3_2, m[2], c2[2]),FMT(" S_%zu"));

        //明文等于apk和v的组合
        binary1->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m1_binary_result, FieldT::one(), m[0]),FMT(" S_%zu"));

        binary2->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m2_binary_result, FieldT::one(), m[1]),FMT(" S_%zu"));

        binary3->generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_binary_result, FieldT::one(), m[2]),FMT(" S_%zu"));

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




template<typename FieldT>
void test_exp() {

    uint256 apk_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint64_t v_1=5;
    uint64_t v_2=6;
    uint64_t v_3=3;

    unsigned char data[32*6];
    char g_c[]="11112222333344445555666677778888999900001111";
    char sk[]="1234567891";
    FieldT g=bigint_r(g_c);
    FieldT Gsk = bigint_r(sk);//私钥
    FieldT Gpk = g ^ Gsk.as_bigint();//公钥

    Elgamal_2apk_3v<FieldT> elg;
    
    elg.setG(g);

    elg.setPk(Gpk);

    elg.encrypt(apk_s,apk_r,v_1,v_2,v_3);


    protoboard<FieldT> pb;
    pb_variable_array<FieldT> random_y;
    pb_variable<FieldT> message;
    pb_variable<FieldT> crypto1;
    pb_variable<FieldT> crypto2;
    pb_variable<FieldT> result1;
    pb_variable<FieldT> result2;

    pb_variable<FieldT> pb_g;    
    pb_variable<FieldT> pb_gpk;

    pb_g.allocate(pb,"crypto1");
    pb_gpk.allocate(pb,"crypto2");

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
    
   
    pb.val(pb_g) = g;
    pb.val(pb_gpk) = Gpk;

    //约束：g ^ y == c1
    exp_gadget<FieldT> exp1(pb_g,pb,random_y,result1,"qwe");
    exp1.generate_r1cs_constraints();
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result1, FieldT::one(), crypto1),FMT(" S_%zu"));
    
    //约束：m * (Gpk ^ y) == c2
    exp_gadget<FieldT> exp2(pb_gpk,pb,random_y,result2,"qwe");
    exp2.generate_r1cs_constraints();
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(result2, message, crypto2),FMT(" S_%zu"));


    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

    
    //生成证明
    for(int i=0;i<253;i++){
        pb.val(random_y[i]) = elg.v_y1[i];
    }
   

    //pb.val(crypto1) = elg.c1_result2+bigint_r("1"); 

    pb.val(crypto1) = elg.c1_result2;
    pb.val(crypto2) = elg.c2_result2;
    pb.val(message) = elg.m2;

    exp1.generate_r1cs_witness();
    exp2.generate_r1cs_witness();

    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    

    /***********************************************
     *                    验证者
    ************************************************/

    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi,proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    }
    
  
}



template<typename FieldT>
void test_exp_gadget() {

    uint256 apk_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint64_t v_1=5;
    uint64_t v_2=6;
    uint64_t v_3=7;

    uint256 apk_s1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint256 apk_r1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    uint64_t v_11=4;
    uint64_t v_21=5;
    uint64_t v_31=6;

    unsigned char data[32*6];
    char g_c[]="11112222333344445555666677778888999900001111";
    char sk[]="1234567891";
    FieldT g=bigint_r(g_c);
    FieldT Gsk = bigint_r(sk);//私钥
    FieldT Gpk = g ^ Gsk.as_bigint();//公钥

    Elgamal_2apk_3v<FieldT> elg;

    elg.setG(g);
    
    elg.setPk(Gpk);

    elg.encrypt(apk_s,apk_r,v_1,v_2,v_3);//加密

    elg.getEncryptedData(data);

    /***********************************************
     *                     电路设计
    ************************************************/

    protoboard<FieldT> pb;
    pb_variable<FieldT> pb_g;
    pb_variable<FieldT> pb_gpk;

    pb_variable_array<FieldT> random_y1;
    pb_variable_array<FieldT> random_y2;
    pb_variable_array<FieldT> random_y3;

    pb_variable_array<FieldT> m;
    pb_variable_array<FieldT> c1;
    pb_variable_array<FieldT> c2;

    pb_variable_array<FieldT> apk1_array;
    pb_variable_array<FieldT> apk2_array;

    pb_variable_array<FieldT> v1_array;
    pb_variable_array<FieldT> v2_array;
    pb_variable_array<FieldT> v3_array;

   

    int dimension=6;
    c1.allocate(pb,3,"c1");
    c2.allocate(pb,3,"c2");
    m.allocate(pb,3,"m");
    
    pb_g.allocate(pb,"c1");
    pb_gpk.allocate(pb,"c2");

    random_y1.allocate(pb,253,"random_y1");
    random_y2.allocate(pb,253,"random_y2");
    random_y3.allocate(pb,253,"random_y3");

    apk1_array.allocate(pb,256,"m1_array");
    apk2_array.allocate(pb,256,"m2_array");
    v1_array.allocate(pb,64,"m3_array");
    v2_array.allocate(pb,64,"m1_array");
    v3_array.allocate(pb,64,"m2_array");
  
    pb.val(pb_g) = g;
    pb.val(pb_gpk) = Gpk;

    elgamal_gadget<FieldT> elg_gadget(pb,pb_g,  //生成元
                        pb_gpk,        
                        random_y1,//第一个明文加密随机数
                        random_y2,//第二个明文加密随机数
                        random_y3,//第三个明文加密随机数
                        m,   //明文列表
                        c1,  //密文1列表
                        c2,  //密文2列表
                        apk1_array,
                        apk2_array,
                        v1_array,
                        v2_array,
                        v3_array
                        );
    pb.set_input_sizes(dimension);

    elg_gadget.generate_r1cs_constraints();

    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

    apk1_array.fill_with_bits(pb,uint256_to_bool_vector(apk_s));
    apk2_array.fill_with_bits(pb,uint256_to_bool_vector(apk_r));
    v1_array.fill_with_bits(pb,uint64_to_bool_vector(v_1));
    v2_array.fill_with_bits(pb,uint64_to_bool_vector(v_2));
    v3_array.fill_with_bits(pb,uint64_to_bool_vector(v_3));

    for(int i=0;i<253;i++){
        pb.val(random_y1[i])=elg.v_y1[i];
        pb.val(random_y2[i])=elg.v_y2[i];
        pb.val(random_y3[i])=elg.v_y3[i];
    }
  
    pb.val(c1[0]) = elg.c1_result1;
    pb.val(c2[0]) = elg.c2_result1;
    pb.val(m[0]) = elg.m1;
    
    pb.val(c1[1]) = elg.c1_result2;
    pb.val(c2[1]) = elg.c2_result2;
    pb.val(m[1]) = elg.m2;

    pb.val(c1[2]) = elg.c1_result3;
    pb.val(c2[2]) = elg.c2_result3;
    pb.val(m[2]) = elg.m3;
    
    elg_gadget.generate_r1cs_witness();
  
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    

    /***********************************************
     *                    验证者
    ************************************************/
    //密文作为公共输入
    //通过密文byte流获得密文FieldT
    Elgamal_2apk_3v<FieldT> elg_v;
    //data[0]=0;
    elg_v.setEncryptedData(data);
   
    std::vector<FieldT> pi_v;
    pi_v.push_back(elg_v.c1_result1);
    pi_v.push_back(elg_v.c1_result2);
    pi_v.push_back(elg_v.c1_result3);

    pi_v.push_back(elg_v.c2_result1);
    pi_v.push_back(elg_v.c2_result2);
    pi_v.push_back(elg_v.c2_result3);

    //auto pi_v = pb.primary_input();
    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi_v,proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    }
}


template<typename FieldT>
FieldT vectToFp(protoboard<FieldT> pb,pb_variable_array<FieldT> a){
    FieldT r=2,s,sum=0;
    for(int i=0;i<248;i++){
        s=pb.val(a[i]);
        sum=sum+s*(r^i);
    }

    return sum;
}

template<typename FieldT>
void test_var_array(){

    protoboard<FieldT> pb;

    pb_variable<FieldT> m1_result;
    pb_variable<FieldT> m1;
    pb_variable_array<FieldT> apk1_array;
    pb_variable_array<FieldT> apk2_array;

    pb_variable_array<FieldT> v1_array;
    pb_variable_array<FieldT> v2_array;
    pb_variable_array<FieldT> v3_array;

    pb_variable_array<FieldT> apk1_tmp;

    pb_variable_array<FieldT> m1_array;
    pb_variable_array<FieldT> m2_array;
    pb_variable_array<FieldT> m3_array;

    pb_variable_array<FieldT> m1_tmp;
    pb_variable_array<FieldT> m2_tmp;
    pb_variable_array<FieldT> m3_tmp;


    apk1_array.allocate(pb,256,"m1_array");
    apk2_array.allocate(pb,256,"m2_array");
    v1_array.allocate(pb,64,"m3_array");
    v2_array.allocate(pb,64,"m1_array");
    v3_array.allocate(pb,64,"m2_array");
   
    m1_array.allocate(pb,248,"m1_array");
    m2_array.allocate(pb,248,"m2_array");
    m3_array.allocate(pb,248,"m3_array");
    
    m1_tmp.allocate(pb,248,"m1_tmp");
    m2_tmp.allocate(pb,248,"m2_tmp");
    m3_tmp.allocate(pb,248,"m3_tmp");

    uint256 apk1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a11");
    uint256 apk2=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a22");
    uint64_t v1=5;
    uint64_t v2=0;
    uint64_t v3=0;

    unsigned char data[32*6];
    char g_c[]="1111222233334444555566667777888899990000111111";
    char sk[]="1234567891";
    FieldT g=bigint_r(g_c);
    FieldT Gsk = bigint_r(sk);//私钥
    FieldT Gpk = g ^ Gsk.as_bigint();//公钥

    Elgamal_2apk_3v<FieldT> elg;
    elg.encrypt(apk1,apk2,v1,v2,v3);

    apk1_array.fill_with_bits(pb,uint256_to_bool_vector(apk1));
    apk2_array.fill_with_bits(pb,uint256_to_bool_vector(apk2));
    v1_array.fill_with_bits(pb,uint64_to_bool_vector(v1));
    v2_array.fill_with_bits(pb,uint64_to_bool_vector(v2));
    v3_array.fill_with_bits(pb,uint64_to_bool_vector(v3));

    //apk1，前31字节
    for(int i=0;i<31*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;

        //pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m1_array[i], FieldT::one(), apk1_array[j-off]),FMT(" S_%zu"));
        m1_array[i]=apk1_array[j-off];
    }
   
    //apk1，后1个字节
    for(int i=0;i<1*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;

        //pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m2_array[i], FieldT::one(), apk1_array[31*8+j-off]),FMT(" S_%zu"));
        m2_array[i]=apk1_array[31*8+j-off];
    }
    
    //apk2，前30字节
    for(int i=0;i<30*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;

        //pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m2_array[1*8+i], FieldT::one(), apk2_array[j-off]),FMT(" S_%zu"));
        m2_array[1*8+i]=apk2_array[j-off];
    }
   
    //apk2,后2个字节，
     for(int i=0;i<2*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;

        //pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_array[i], FieldT::one(), apk2_array[30*8+j-off]),FMT(" S_%zu"));
        m3_array[i]=apk2_array[30*8+j-off];
    }
    
    //v1,8个字节
    for(int i=0;i<8*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;

        //pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_array[2*8+i], FieldT::one(), v1_array[j-off]),FMT(" S_%zu"));
        m3_array[2*8+i]=v1_array[j-off];
    }
   
    //v2,8个字节
    for(int i=0;i<8*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;

        //pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_array[2*8+8*8+i], FieldT::one(), v2_array[j-off]),FMT(" S_%zu"));
        m3_array[2*8+8*8+i]=v2_array[j-off];
      
    }
   
     //v3,8个字节
    for(int i=0;i<8*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;
        //pb.add_r1cs_constraint(r1cs_constraint<FieldT>(m3_array[2*8+8*8+8*8+i], FieldT::one(), v3_array[j-off]),FMT(" S_%zu"));
        m3_array[2*8+8*8+8*8+i]=v3_array[j-off]; 
    }

    //apk1，前31字节
    for(int i=0;i<31*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;
        m1_array[i]=apk1_array[j-off];
     
    }
   
    //apk1，后1个字节
    for(int i=0;i<1*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;
        m2_array[i]=apk1_array[31*8+j-off];
   
    }
    
    //apk2，前30字节
    for(int i=0;i<30*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;
        m2_array[1*8+i]=apk2_array[j-off];
      
    }
   
    //apk2,后2个字节，
     for(int i=0;i<2*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;
        m3_array[i]=apk2_array[30*8+j-off];
    }
    
    //v1,8个字节
    for(int i=0;i<8*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;
        m3_array[2*8+i]=v1_array[j-off];
      
    }
   
    //v2,8个字节
    for(int i=0;i<8*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;
        m3_array[2*8+8*8+i]=v2_array[j-off];
      
    }
   
     //v3,8个字节
    for(int i=0;i<8*8;i++){
        int j=((i/8)+1)*8-1;
        int off=i%8;
        m3_array[2*8+8*8+8*8+i]=v3_array[j-off];
      
       
    }
    cout<<"8888-------"<<endl;
    FieldT m1_fp=vectToFp<FieldT>(pb,m1_array);
    FieldT m2_fp=vectToFp<FieldT>(pb,m2_array);
    FieldT m3_fp=vectToFp<FieldT>(pb,m3_array);

    cout<<m1_fp<<","<<m2_fp<<","<<m3_fp<<endl;

    cout<<elg.m1<<","<<elg.m2<<","<<elg.m3<<endl;

    
}



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

class MerkleTree{

private:
    int _DEEPTH;
	vector<node> Tree;  //存储树的向量
    uint256 _d_leaf;
    int index;
	void updateTree();       //更新树  
	void findLeafIndex(int leaf);      //给定一个叶节点的值，返回其在树中的索引
	void getNodeHashList(uint256 leaf);
	void getParentList(uint256 leaf);
	void getPathisrightList(uint256 leaf);

public:
    MerkleTree(int deep){
        _DEEPTH=deep+1;
        _d_leaf=uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    }
	vector<uint256> nodeHashList;   //存储需要被哈希的节点值
	vector<uint256> parentList;    //父节点列表
	vector<int> pathisrightList;    //存储节点是左节点还是右节点

	void creatTree();     //从叶节点开始由下到上创建并初始化二叉树
	void addLeaf(uint256 newLeaf);        //查找叶节点中未被更新的节点，并将其值更新为naeleaf
	void deleteLeafValue(uint256 deleteLeaf);  //将指定位置的叶子结点恢复默认值
	
	uint256  getRoot();
	MerkleTreePath getPath(uint256 leaf);
	
	void printTree();
};

void MerkleTree::creatTree()   //从叶节点开始由下到上创建并初始化二叉树
{
    
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
				//cout << Tree.at(i).data << endl;
			}
			else if (i == pow(2, _DEEPTH) - 2)
			{
				childIndex = (i - (int)pow(2, _DEEPTH - 1)) * 2;
				Tree.at(i).left = &Tree.at(childIndex);
				Tree.at(i).right = &Tree.at(childIndex + 1);
				Tree.at(i).data = combine(Tree.at(childIndex).data , Tree.at(childIndex + 1).data); //父节点的data值为左右孩子节点的data相加
				//cout << Tree.at(i).data << endl;
			}
			else
			{
				parentIndex = nodeNum + (int)pow(2, j - 1) + (i - nodeNum) / 2;
				Tree.at(i).parent = &Tree.at(parentIndex);
				childIndex = (i - (int)pow(2, _DEEPTH - 1)) * 2;         //孩子节点的索引
				Tree.at(i).left = &Tree.at(childIndex);  
				Tree.at(i).right = &Tree.at(childIndex+1);
				Tree.at(i).data = combine(Tree.at(childIndex).data , Tree.at(childIndex + 1).data);  
			}
		}
		nodeNum = nodeNum + pow(2, j - 1);
	}
}

void MerkleTree::updateTree()   //根据被更新叶节点的索引来更新整个二叉树
{
	int nodeNum;         //计算已更新节点所在的那层以及以下各层的节点数和
	for (int j = _DEEPTH; j >1; j--)
	{
		nodeNum = (pow(2, j)*(1 - pow(2, _DEEPTH - j))) / (1 - 2);
		(*Tree.at(index).parent).data = combine((*(*Tree.at(index).parent).left).data , (*(*Tree.at(index).parent).right).data);  //更新父节点的值
		index = nodeNum + (int)pow(2, j - 1) + (index - nodeNum) / 2;  //计算父节点索引
	}
	cout << "update done" << endl;
}


void MerkleTree::addLeaf(uint256 newLeaf)
{
	for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == _d_leaf)
			break;
		if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到，则置index为NULL
		{
			cout << "ERROR" << endl;
			return;
		}
	}
	Tree.at(index).data = newLeaf;   //更新节点的值
	cout << index<< endl;
	updateTree();      //更新树
	cout << "add leaf done" << endl;
}

void MerkleTree::deleteLeafValue(uint256 deleteLeaf)
{
	for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == deleteLeaf)
			break;
		if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
			return;
		}
	}
	Tree.at(index).data = _d_leaf;    //更新节点的值
	updateTree();      //更新树
}

uint256 MerkleTree::getRoot()
{
	return Tree.back().data;
}

void MerkleTree::getNodeHashList(uint256 leaf)
{
	for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == leaf)
			break;
		if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
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

void MerkleTree::getParentList(uint256 leaf)
{
	for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == leaf)
			break;
		if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
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

void MerkleTree::getPathisrightList(uint256 leaf)
{
	for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  //寻找未被更新过的叶节点
	{
		if (Tree.at(index).data == leaf)
			break;
		if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
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

MerkleTreePath MerkleTree::getPath(uint256 leaf)
{
    MerkleTreePath path;
	for (index = 0; index < pow(2.0, _DEEPTH - 1); index++)  
	{
		if (Tree.at(index).data == leaf)
			break;
		if (index == pow(2, _DEEPTH - 1) - 1)   //若未找到
		{
			cout << "ERROR" << endl;
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

void MerkleTree::printTree()
{
	for (int i = 0; i < Tree.size(); i++)
	{
		cout << Tree[i].data.ToString() << endl;
	}
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
MerkleTreePath getMerkleTreePath_test_u3(){

    //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=0;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    //uint256 u3=cm(apk_s,v_1,old_r);
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
  
    MerkleTreePath mp;
    mp.nodeHashList=nodelist;
    mp.parentList=parentList;
    mp.pathisrightList=pathisrightList;
    mp.root=root;
    mp.leaf=u3;

    return mp;
}
MerkleTreePath getMerkleTreePath_trees(){
    MerkleTree tree(TREE_DEEPTH);
	tree.creatTree();
	//tree.printTree();
    
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

    tree.addLeaf(u1);
    tree.addLeaf(u2);
    tree.addLeaf(u3);
    tree.addLeaf(u4);
    tree.addLeaf(u5);
    tree.addLeaf(u6);
    tree.addLeaf(u7);
    tree.addLeaf(u8);

    tree.addLeaf(u9);
    tree.addLeaf(u10);
    tree.addLeaf(u11);
    tree.addLeaf(u12);
    tree.addLeaf(u13);
    tree.addLeaf(u14);
    tree.addLeaf(u15);
    tree.addLeaf(u16);

    return tree.getPath(u3);
}


MerkleTreePath getMerkleTreePath_apk_s(){

    //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=0;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 u3=apk_r;
    //uint256 u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    //uint256 u4=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d3");
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
    pathisrightList.push_back(1);

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
  
    MerkleTreePath mp;
    mp.nodeHashList=nodelist;
    mp.parentList=parentList;
    mp.pathisrightList=pathisrightList;
    mp.root=root;
    mp.leaf=u3;

    return mp;
}

MerkleTreePath getMerkleTreePath_apk_r(){

    //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=0;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 u3=apk_r;
    //uint256 u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
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
  
    MerkleTreePath mp;
    mp.nodeHashList=nodelist;
    mp.parentList=parentList;
    mp.pathisrightList=pathisrightList;
    mp.root=root;
    mp.leaf=u3;

    return mp;
}

MerkleTreePath getMerkleTreePath(){

    //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=0;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 u3=cm(apk_s,v_1,old_r);
    //uint256 u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
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
  
    MerkleTreePath mp;
    mp.nodeHashList=nodelist;
    mp.parentList=parentList;
    mp.pathisrightList=pathisrightList;
    mp.root=root;
    mp.leaf=u3;

    return mp;
}

MerkleTreePath getMerkleTreePath_lb(){

    //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=3;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 u3=cm(apk_s,v_1+v_2,old_r);
    //uint256 u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
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
  
    MerkleTreePath mp;
    mp.nodeHashList=nodelist;
    mp.parentList=parentList;
    mp.pathisrightList=pathisrightList;
    mp.root=root;
    mp.leaf=u3;

    return mp;
}

MerkleTreePath getMerkleTreePath_hb1(){

    //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=3;
    uint64_t v_3=0;

    uint256 old_r1=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 old_r2=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a66");

    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 u3=cm(apk_s,v_1,old_r1);
    //uint256 u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
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
  
    MerkleTreePath mp;
    mp.nodeHashList=nodelist;
    mp.parentList=parentList;
    mp.pathisrightList=pathisrightList;
    mp.root=root;
    mp.leaf=u3;

    return mp;
}

MerkleTreePath getMerkleTreePath_hb2(){

    //叶子
    uint256 u1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 u2=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d1");

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=3;
    uint64_t v_3=0;

    uint256 old_r1=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 old_r2=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a66");

    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 u3=cm(apk_s,v_1,old_r1);
    //uint256 u3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    //uint256 u4=uint256S("effd0b7f1ccba1162ee816f731c62b4859305141990e5c0ace40d33d0b1167d3");
    uint256 u4=cm(apk_s,v_2,old_r2);

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
    pathisrightList.push_back(1);

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
  
    MerkleTreePath mp;
    mp.nodeHashList=nodelist;
    mp.parentList=parentList;
    mp.pathisrightList=pathisrightList;
    mp.root=root;
    mp.leaf=u3;

    return mp;
}


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
    tree_gadget(protoboard<FieldT>& pb, std::shared_ptr<digest_variable<FieldT>> root_dg, std::shared_ptr<digest_variable<FieldT>> leaf_dg,const std::string &annotation_prefix="") :
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

        root=root_dg;
        leaf=leaf_dg;

        //leaf.reset(new digest_variable<FieldT>(this->pb, SHA256_digest_size, "root") );
        //root.reset(new digest_variable<FieldT>(this->pb, SHA256_digest_size, "root") ); 
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
        cout<<"11"<<endl;
        for(size_t i=0;i<TREE_DEEPTH;i++){
           hasher[i].generate_r1cs_constraints();
           selector[i].generate_r1cs_constraints();
        } 
        cout<<"22"<<endl;
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
       cout<<"33"<<endl;

    }

    void generate_r1cs_witness(std::vector<uint256> child_ui256_list,std::vector<uint256> parent_ui256_list
                                ,std::vector<int> path){
        
        libff::bit_vector bv_l;
        libff::bit_vector bv_r;
        libff::bit_vector bv_p;
        
        //leaf->generate_r1cs_witness(uint256_to_bool_vector(leaf_ui256));
        //root->generate_r1cs_witness(uint256_to_bool_vector(root_ui256));

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
    /*
    //测试二叉树
    MerkleTreePath path1=getMerkleTreePath_test_u3();
    MerkleTreePath path2=getMerkleTreePath_trees();
    cout<<"path1.nodeHashList[i]"<<endl;
    for(int i=0;i<path1.nodeHashList.size();i++){
        cout<<path1.nodeHashList[i].ToString()<<endl;
    }
    cout<<"path1.parentList[i]"<<endl;
    for(int i=0;i<path1.parentList.size();i++){
        cout<<path1.parentList[i].ToString()<<endl;
    }
    cout<<"path1.pathisrightList[i]"<<endl;
    for(int i=0;i<path1.pathisrightList.size();i++){
        cout<<path1.pathisrightList[i]<<endl;
    }
    cout<<"path2.nodeHashList[i]"<<endl;
    for(int i=0;i<path2.nodeHashList.size();i++){
        cout<<path2.nodeHashList[i].ToString()<<endl;
    }
    cout<<"path2.parentList[i]"<<endl;
    for(int i=0;i<path2.parentList.size();i++){
        cout<<path2.parentList[i].ToString()<<endl;
    }
    cout<<"path2.pathisrightList[i]"<<endl;
    for(int i=0;i<path2.pathisrightList.size();i++){
        cout<<path2.pathisrightList[i]<<endl;
    }*/
    
    protoboard<FieldT> pb;
    
    std::shared_ptr<digest_variable<FieldT>> leaf_p;
    std::shared_ptr<digest_variable<FieldT>> root_p;

    leaf_p.reset(new digest_variable<FieldT>(pb, 256, "left"));
    root_p.reset(new digest_variable<FieldT>(pb, 256, "rr"));

    tree_gadget<FieldT> tree_gad(pb, root_p,leaf_p,"tree");
    cout<<"0"<<endl;

    gettimeofday (&tvpre , &tz);

    tree_gad.generate_r1cs_constraints();
    
    gettimeofday (&tvafter , &tz);
    cout << "time "<<(tvafter.tv_sec-tvpre.tv_sec)*1000+(tvafter.tv_usec-tvpre.tv_usec)/1000<< endl;

    cout<<"1"<<endl;
    auto cs = pb.get_constraint_system();
    cout<<"2"<<endl;
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
    cout<<"3"<<endl;
    //MerkleTreePath path=getMerkleTreePath();
    MerkleTreePath path=getMerkleTreePath_trees();
    
    cout<<"4"<<endl;
    leaf_p->bits.fill_with_bits(pb, uint256_to_bool_vector(path.leaf));
    root_p->bits.fill_with_bits(pb, uint256_to_bool_vector(path.root));
    tree_gad.generate_r1cs_witness(path.nodeHashList,path.parentList
                                ,path.pathisrightList
                               );
    cout<<"5"<<endl;
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    
   
    

    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi,proof)) {
    cout << "Verified!" << endl;
    } else {
    cout << "Failed to verify!" << endl;
    }
}


//-------------------整体------------------------------

//整币交易
template<typename FieldT>
class joinsplit_gadget_z : gadget<FieldT> {
private:
    //FieldT g;
    //FieldT Gpk;
    pb_variable<FieldT> g;
    pb_variable<FieldT> Gpk;
    // sk pk
    std::shared_ptr<digest_variable<FieldT>> a_sk_s;//私钥  
    std::shared_ptr<digest_variable<FieldT>> a_pk_s;//公钥
    std::shared_ptr<prf_gadget<FieldT>> prf_gad;
    
    //sn
    std::shared_ptr<digest_variable<FieldT>> sn_old;//序列号  
    std::shared_ptr<sn_gadget<FieldT>> sn_gad;

    // commitment
    pb_variable_array<FieldT> v_old;               //金额
    std::shared_ptr<digest_variable<FieldT>> r_old;    //随机数
    std::shared_ptr<digest_variable<FieldT>> commitment_old;//老承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_old;

    // merkle tree
    std::shared_ptr<tree_gadget<FieldT>> tree_gad_cm;//承诺树
    std::shared_ptr<digest_variable<FieldT>> root_cm;//根

    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_s;//付款方
    std::shared_ptr<digest_variable<FieldT>> root_apk_s;//根

    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_r;//收款方
    std::shared_ptr<digest_variable<FieldT>> root_apk_r;//根

    // balance
    pb_variable_array<FieldT> v_new;

    // new commitment
    std::shared_ptr<digest_variable<FieldT>> a_pk_r;//收款方公钥
    std::shared_ptr<digest_variable<FieldT>> r_new; //新的随机数
    std::shared_ptr<digest_variable<FieldT>> commitment_new;//新承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_new;


    //elgamal   
  
    //3次加密的随机数
    pb_variable_array<FieldT> random_y1;
    pb_variable_array<FieldT> random_y2;
    pb_variable_array<FieldT> random_y3;

    pb_variable_array<FieldT> m;    //明文列表
    pb_variable_array<FieldT> c1;   //密文1列表
    pb_variable_array<FieldT> c2;   //密文2列表

    pb_variable_array<FieldT> apk1_array;//付款方公约
    pb_variable_array<FieldT> apk2_array;//收款方公约

    //金额
    pb_variable_array<FieldT> v1_array; 
    pb_variable_array<FieldT> v2_array; 
    pb_variable_array<FieldT> v3_array;

    
    std::shared_ptr<elgamal_gadget<FieldT>> elgamal_gad;

    int dimension;

public:
    joinsplit_gadget_z(protoboard<FieldT> &pb,FieldT &sg,FieldT &gpk) : gadget<FieldT>(pb) {
        //公共参数长度：sn256+老承诺哈希树根256+新承诺256+付款方256+收款方256+6个密文+生成元+监管公钥
        dimension=256+256+256+256+256+6+1+1;

        //分配顺序
        sn_old.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_cm.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_apk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_apk_r.reset(new digest_variable<FieldT>(pb, 256, ""));

        commitment_new.reset(new digest_variable<FieldT>(pb, 256, ""));
        
        c1.allocate(pb,3,"c1");
        c2.allocate(pb,3,"c2");

        g.allocate(pb,"g");
        Gpk.allocate(pb,"Gpk");
        
        this->pb.val(this->g)=sg;
        this->pb.val(this->Gpk)=gpk;

        //ask,apk,prf
        a_sk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        a_pk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        prf_gad.reset(new prf_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            a_pk_s
        ));
        cout<<"ask,apk,prf"<<endl;

        //comment
        v_old.allocate(pb, 64);
        
        r_old.reset(new digest_variable<FieldT>(pb, 256, ""));
        commitment_old.reset(new digest_variable<FieldT>(pb, 256, ""));
        comm_gad_old.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_s->bits,
            v_old,
            r_old->bits,
            commitment_old
        ));

        a_pk_r.reset(new digest_variable<FieldT>(pb, 256, ""));
        v_new.allocate(pb, 64);
        r_new.reset(new digest_variable<FieldT>(pb, 256, ""));
        //commitment_new.reset(new digest_variable<FieldT>(pb, 256, ""));
        comm_gad_new.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_r->bits,
            v_new,
            r_new->bits,
            commitment_new
        ));
        cout<<"comment"<<endl;

        //sn
        sn_gad.reset(new sn_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            r_old->bits,
            sn_old
        ));
        cout<<"sn"<<endl;

        //merkle tree
        
        tree_gad_cm.reset(new tree_gadget<FieldT>(pb,root_cm,commitment_old,""));
        tree_gad_apk_s.reset(new tree_gadget<FieldT>(pb,root_apk_s,a_pk_s,""));
        tree_gad_apk_r.reset(new tree_gadget<FieldT>(pb,root_apk_r,a_pk_r,""));
        cout<<"tree"<<endl;

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
                cout<<"elg"<<endl;
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
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
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

/*
void savePkToFile(std::string path, r1cs_ppzksnark_proving_key<ppT>& pk) {
    std::stringstream ss;
    ss << pk;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}
*/
void savePkToFile(std::string path, r1cs_ppzksnark_proving_key<ppT>& pk) {
  
    std::ofstream fh;
    fh.open(path, std::ios::binary);
   
    fh << pk;
    fh.flush();
    fh.close();
}
/*
void loadPkFromFile(std::string path, r1cs_ppzksnark_proving_key<ppT>& pk) {

    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        cout<<"could not load param file "<<endl;
    }

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    ss >> pk;

   
}*/
void loadPkFromFile(std::string path, r1cs_ppzksnark_proving_key<ppT>& pk) {

    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        cout<<"could not load param file "<<endl;
    }

    fh >> pk;

   
}
/*
void saveVkToFile(std::string path, r1cs_ppzksnark_verification_key<ppT>& vk) {
    std::stringstream ss;
    ss << vk;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}*/
void saveVkToFile(std::string path, r1cs_ppzksnark_verification_key<ppT>& vk) {
   
    std::ofstream fh;
    fh.open(path, std::ios::binary);
   
    fh << vk;
    fh.flush();
    fh.close();
}

/*
void loadVkFromFile(std::string path, r1cs_ppzksnark_verification_key<ppT>& vk) {

    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        cout<<"could not load param file "<<endl;
    }

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    ss >> vk;

   
}*/

void loadVkFromFile(std::string path, r1cs_ppzksnark_verification_key<ppT>& vk) {

   
    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        cout<<"could not load param file "<<endl;
    }
   
    fh >> vk;
   
}

template<typename FieldT>
void test_js_z() {

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=0;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 old_comm=cm(apk_s,v_1,old_r);
    uint256 new_comm=cm(apk_r,v_1,new_r);

    uint256 old_sn=sn(ask_s,old_r);

    unsigned char data[32*6];
    char g_c[]="11112222333344445555666677778888999900001111";
    char sk[]="1234567891";
    FieldT g=bigint_r(g_c);
    FieldT Gsk = bigint_r(sk);//私钥
    FieldT Gpk = g ^ Gsk.as_bigint();//公钥

    Elgamal_2apk_3v<FieldT> elg;

    elg.setG(g);
    
    elg.setPk(Gpk);

    elg.encrypt(apk_s,apk_r,v_1,v_2,v_3);//加密

    elg.getEncryptedData(data);


    protoboard<FieldT> pb;

    cout<<"1"<<endl;

    joinsplit_gadget_z<FieldT> js_gad_z(pb,g,Gpk);      
    //joinsplit_gadget_z<FieldT> js_gad_z(pb,g);   
    cout<<"2"<<endl;
    

    js_gad_z.generate_r1cs_constraints();
    cout<<"3"<<endl;
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
    
    /*
    //保存pk vk
    savePkToFile("pk.data", keypair.pk);
    saveVkToFile("vk.data", keypair.vk);

    //r1cs_ppzksnark_proving_key<ppT> pk;
    //r1cs_ppzksnark_verification_key<ppT> vk;
    //恢复pk vk
    loadPkFromFile("pk.data", keypair.pk);
    loadVkFromFile("vk.data", keypair.vk);
    */

    MerkleTreePath cm_path=getMerkleTreePath();
    uint256 cm_rt=cm_path.root;
    
    MerkleTreePath apk_s_path=getMerkleTreePath_apk_s();
    uint256 apk_s_rt=apk_s_path.root;

    MerkleTreePath apk_r_path=getMerkleTreePath_apk_r();
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
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    

    //保存/恢复proof
    /*
    stringstream ss("");
    string proof_str;
    ss<<proof;

    proof_str=ss.str();
    stringstream ss1("");
    ss1<<proof_str;
    ss1>>proof;
    */


    //验证方(矿工)
    
    //输入公共参数
    std::vector<FieldT> pi_v;

    //---------------sn-------------
    std::vector<bool> sn_v=uint256_to_bool_vector(old_sn);
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
    std::vector<bool> new_comm_v=uint256_to_bool_vector(new_comm);
    for(int i=0;i<256;i++){
        if(new_comm_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(new_comm_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //---公钥和金额的密文-----------
    //通过密文byte流获得密文FieldT
    Elgamal_2apk_3v<FieldT> elg_v;
    //data[0]=0;
    elg_v.setEncryptedData(data);
    elg_v.setSk(Gsk);

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
    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi_v,proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    }

    //监管
    Elgamal_2apk_3v<FieldT> elg_g;
    elg_g.setG(g);
    elg_g.setSk(Gsk);
    elg_g.decryptData(data);

    cout<<elg_g.apk_s.ToString()<<endl;
    cout<<elg_g.apk_r.ToString()<<endl;
    cout<<elg_g.v_1<<endl;
    cout<<elg_g.v_2<<endl;
    cout<<elg_g.v_3<<endl;
}


//找零币交易
template<typename FieldT>
class joinsplit_gadget_l : gadget<FieldT> {
private:
    //FieldT g;
    //FieldT Gpk;
    pb_variable<FieldT> g;
    pb_variable<FieldT> Gpk;

    // sk pk
    std::shared_ptr<digest_variable<FieldT>> a_sk_s;//私钥  
    std::shared_ptr<digest_variable<FieldT>> a_pk_s;//公钥
    std::shared_ptr<prf_gadget<FieldT>> prf_gad;
    
    //sn
    std::shared_ptr<digest_variable<FieldT>> sn_old;//序列号  
    std::shared_ptr<sn_gadget<FieldT>> sn_gad;

    // commitment
    pb_variable_array<FieldT> v_old;               //金额
    std::shared_ptr<digest_variable<FieldT>> r_old;    //随机数
    std::shared_ptr<digest_variable<FieldT>> commitment_old;//老承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_old;

    // merkle tree
    std::shared_ptr<tree_gadget<FieldT>> tree_gad_cm;//承诺树
    std::shared_ptr<digest_variable<FieldT>> root_cm;//公钥

    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_s;//付款方
    std::shared_ptr<digest_variable<FieldT>> root_apk_s;//根
    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_r;//收款方
    std::shared_ptr<digest_variable<FieldT>> root_apk_r;//根

    // balance
    pb_variable_array<FieldT> v_new1,v_new2;

    // new commitment
    std::shared_ptr<digest_variable<FieldT>> a_pk_r;//收款方公钥
    
    std::shared_ptr<digest_variable<FieldT>> r_new1; //新的随机数
    std::shared_ptr<digest_variable<FieldT>> commitment_new1;//新承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_new1;

    std::shared_ptr<digest_variable<FieldT>> r_new2; //新的随机数
    std::shared_ptr<digest_variable<FieldT>> commitment_new2;//新承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_new2;


    //elgamal   
  
    //3次加密的随机数
    pb_variable_array<FieldT> random_y1;
    pb_variable_array<FieldT> random_y2;
    pb_variable_array<FieldT> random_y3;

    pb_variable_array<FieldT> m;    //明文列表
    pb_variable_array<FieldT> c1;   //密文1列表
    pb_variable_array<FieldT> c2;   //密文2列表

    pb_variable_array<FieldT> apk1_array;//付款方公约
    pb_variable_array<FieldT> apk2_array;//收款方公约

    //金额
    pb_variable_array<FieldT> v1_array; 
    pb_variable_array<FieldT> v2_array; 
    pb_variable_array<FieldT> v3_array;

    ;
    std::shared_ptr<elgamal_gadget<FieldT>> elgamal_gad;

    int dimension;
public:
    joinsplit_gadget_l(protoboard<FieldT> &pb,FieldT &sg,FieldT &gpk) : gadget<FieldT>(pb) {
        //公共参数长度：序列号256+老承诺哈希树根256+付款方256+收款方256+2*新承诺256+6个密文
        dimension=256+256+256+256+256+256+6+1+1;

        //分配顺序
        sn_old.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_cm.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_apk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_apk_r.reset(new digest_variable<FieldT>(pb, 256, ""));

        commitment_new1.reset(new digest_variable<FieldT>(pb, 256, ""));
        commitment_new2.reset(new digest_variable<FieldT>(pb, 256, ""));

        c1.allocate(pb,3,"c1");
        c2.allocate(pb,3,"c2");

        g.allocate(pb,"g");
        Gpk.allocate(pb,"Gpk");
        
        this->pb.val(this->g)=sg;
        this->pb.val(this->Gpk)=gpk;

        //ask,apk,prf
        a_sk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        a_pk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        prf_gad.reset(new prf_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            a_pk_s
        ));
        cout<<"ask,apk,prf"<<endl;

        //comment
        v_old.allocate(pb, 64);
        
        r_old.reset(new digest_variable<FieldT>(pb, 256, ""));
        commitment_old.reset(new digest_variable<FieldT>(pb, 256, ""));
        comm_gad_old.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_s->bits,
            v_old,
            r_old->bits,
            commitment_old
        ));

        //新承诺
        a_pk_r.reset(new digest_variable<FieldT>(pb, 256, ""));
        
        v_new1.allocate(pb, 64);
        r_new1.reset(new digest_variable<FieldT>(pb, 256, ""));
        //commitment_new1.reset(new digest_variable<FieldT>(pb, 256, ""));
        comm_gad_new1.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_r->bits,
            v_new1,
            r_new1->bits,
            commitment_new1
        ));

        v_new2.allocate(pb, 64);
        r_new2.reset(new digest_variable<FieldT>(pb, 256, ""));
        //commitment_new2.reset(new digest_variable<FieldT>(pb, 256, ""));
        comm_gad_new2.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_r->bits,
            v_new2,
            r_new2->bits,
            commitment_new2
        ));
        cout<<"comment"<<endl;

        //sn
        
        sn_gad.reset(new sn_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            r_old->bits,
            sn_old
        ));
        cout<<"sn"<<endl;

        //merkle tree
        //root.reset(new digest_variable<FieldT>(pb, 256, ""));
        tree_gad_cm.reset(new tree_gadget<FieldT>(pb,root_cm,commitment_old,""));
        tree_gad_apk_s.reset(new tree_gadget<FieldT>(pb,root_apk_s,a_pk_s,""));
        tree_gad_apk_r.reset(new tree_gadget<FieldT>(pb,root_apk_r,a_pk_r,""));
        cout<<"tree"<<endl;

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
                cout<<"elg"<<endl;
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
        
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
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

template<typename FieldT>
void test_js_l() {

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=3;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");

    uint256 new_r1=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");
    uint256 new_r2=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    uint256 old_comm=cm(apk_s,v_1+v_2,old_r);

    uint256 new_comm1=cm(apk_r,v_1,new_r1);
    uint256 new_comm2=cm(apk_r,v_2,new_r2);

    uint256 old_sn=sn(ask_s,old_r);

    unsigned char data[32*6];
    char g_c[]="11112222333344445555666677778888999900001111";
    char sk[]="1234567891";
    FieldT g=bigint_r(g_c);
    FieldT Gsk = bigint_r(sk);//私钥
    FieldT Gpk = g ^ Gsk.as_bigint();//公钥

    Elgamal_2apk_3v<FieldT> elg;

    elg.setG(g);
    
    elg.setPk(Gpk);

    elg.encrypt(apk_s,apk_r,v_1,v_2,v_3);//加密

    elg.getEncryptedData(data);


    protoboard<FieldT> pb;

    cout<<"1"<<endl;

    joinsplit_gadget_l<FieldT> js_gad_l(pb,g,Gpk);        
    cout<<"2"<<endl;
    //pb.set_input_sizes(dimension);

    js_gad_l.generate_r1cs_constraints();
    cout<<"3"<<endl;
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    MerkleTreePath cm_path=getMerkleTreePath_lb();
    uint256 cm_rt=cm_path.root;
    
    MerkleTreePath apk_s_path=getMerkleTreePath_apk_s();
    uint256 apk_s_rt=apk_s_path.root;
    
    MerkleTreePath apk_r_path=getMerkleTreePath_apk_r();
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
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    

    //验证方
    //验证方，公共参数
    std::vector<FieldT> pi_v;

    //---------------sn-------------
    std::vector<bool> sn_v=uint256_to_bool_vector(old_sn);
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
    std::vector<bool> new_comm_v1=uint256_to_bool_vector(new_comm1);
    for(int i=0;i<256;i++){
        if(new_comm_v1[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(new_comm_v1[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }
    std::vector<bool> new_comm_v2=uint256_to_bool_vector(new_comm2);
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
    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi_v,proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    }
  
   
}

//合并币
//找零币交易
template<typename FieldT>
class joinsplit_gadget_hb : gadget<FieldT> {
private:
    //FieldT g;
    //FieldT Gpk;
    pb_variable<FieldT> g;
    pb_variable<FieldT> Gpk;

    // sk pk
    std::shared_ptr<digest_variable<FieldT>> a_sk_s;//私钥  
    std::shared_ptr<digest_variable<FieldT>> a_pk_s;//公钥
    std::shared_ptr<prf_gadget<FieldT>> prf_gad;
    
    //sn
    std::shared_ptr<digest_variable<FieldT>> sn_old1;//序列号  
    std::shared_ptr<sn_gadget<FieldT>> sn_gad1;
    
    std::shared_ptr<digest_variable<FieldT>> sn_old2;//序列号  
    std::shared_ptr<sn_gadget<FieldT>> sn_gad2;

    // commitment
    pb_variable_array<FieldT> v_old1;                   //金额
    std::shared_ptr<digest_variable<FieldT>> r_old1;    //随机数
    std::shared_ptr<digest_variable<FieldT>> commitment_old1;//老承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_old1;

    pb_variable_array<FieldT> v_old2;                   //金额
    std::shared_ptr<digest_variable<FieldT>> r_old2;    //随机数
    std::shared_ptr<digest_variable<FieldT>> commitment_old2;//老承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_old2;


    // merkle tree
    std::shared_ptr<tree_gadget<FieldT>> tree_gad_cm1;  //承诺树
    std::shared_ptr<digest_variable<FieldT>> root_cm1;     //公钥

    std::shared_ptr<tree_gadget<FieldT>> tree_gad_cm2;  //承诺树
    std::shared_ptr<digest_variable<FieldT>> root_cm2;     //公钥

    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_s;//付款方
    std::shared_ptr<digest_variable<FieldT>> root_apk_s;//根
    std::shared_ptr<tree_gadget<FieldT>> tree_gad_apk_r;//收款方
    std::shared_ptr<digest_variable<FieldT>> root_apk_r;//根


    // balance
    pb_variable_array<FieldT> v_new;

    // new commitment
    std::shared_ptr<digest_variable<FieldT>> a_pk_r;//收款方公钥
    
    std::shared_ptr<digest_variable<FieldT>> r_new; //新的随机数
    std::shared_ptr<digest_variable<FieldT>> commitment_new;//新承诺
    std::shared_ptr<comm_gadget<FieldT>> comm_gad_new;

   
    //elgamal   
  
    //3次加密的随机数
    pb_variable_array<FieldT> random_y1;
    pb_variable_array<FieldT> random_y2;
    pb_variable_array<FieldT> random_y3;

    pb_variable_array<FieldT> m;    //明文列表
    pb_variable_array<FieldT> c1;   //密文1列表
    pb_variable_array<FieldT> c2;   //密文2列表

    pb_variable_array<FieldT> apk1_array;//付款方公约
    pb_variable_array<FieldT> apk2_array;//收款方公约

    //金额
    pb_variable_array<FieldT> v1_array; 
    pb_variable_array<FieldT> v2_array; 
    pb_variable_array<FieldT> v3_array;

    //
    std::shared_ptr<elgamal_gadget<FieldT>> elgamal_gad;
    int dimension;
public:
    joinsplit_gadget_hb(protoboard<FieldT> &pb,FieldT &sg,FieldT &gpk) : gadget<FieldT>(pb) {
        
        //公共参数长度：2*sn256+老承诺哈希树根256+付款方256+收款方256+新承诺256+6个密文
        dimension=256+256+256+256+256+256+256+6+1+1;

        //分配顺序
        sn_old1.reset(new digest_variable<FieldT>(pb, 256, ""));
        sn_old2.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_cm1.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_cm2.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_apk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        root_apk_r.reset(new digest_variable<FieldT>(pb, 256, ""));
        commitment_new.reset(new digest_variable<FieldT>(pb, 256, ""));
        
        c1.allocate(pb,3,"c1");
        c2.allocate(pb,3,"c2");

        g.allocate(pb,"g");
        Gpk.allocate(pb,"Gpk");
        
        this->pb.val(this->g)=sg;
        this->pb.val(this->Gpk)=gpk;


        //ask,apk,prf
        a_sk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        a_pk_s.reset(new digest_variable<FieldT>(pb, 256, ""));
        prf_gad.reset(new prf_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            a_pk_s
        ));

        cout<<"ask,apk,prf"<<endl;

        //comment
        v_old1.allocate(pb, 64);
        
        r_old1.reset(new digest_variable<FieldT>(pb, 256, ""));
        commitment_old1.reset(new digest_variable<FieldT>(pb, 256, ""));
        comm_gad_old1.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_s->bits,
            v_old1,
            r_old1->bits,
            commitment_old1
        ));

        v_old2.allocate(pb, 64);
        
        r_old2.reset(new digest_variable<FieldT>(pb, 256, ""));
        commitment_old2.reset(new digest_variable<FieldT>(pb, 256, ""));
        comm_gad_old2.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_s->bits,
            v_old2,
            r_old2->bits,
            commitment_old2
        ));

        //新承诺
        a_pk_r.reset(new digest_variable<FieldT>(pb, 256, ""));
        
        v_new.allocate(pb, 64);
        r_new.reset(new digest_variable<FieldT>(pb, 256, ""));
        //commitment_new.reset(new digest_variable<FieldT>(pb, 256, ""));
        comm_gad_new.reset(new comm_gadget<FieldT>(
            pb,
            a_pk_r->bits,
            v_new,
            r_new->bits,
            commitment_new
        ));
        cout<<"comment"<<endl;

        //sn
        
        sn_gad1.reset(new sn_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            r_old1->bits,
            sn_old1
        ));
        //sn_old2.reset(new digest_variable<FieldT>(pb, 256, ""));
        sn_gad2.reset(new sn_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            r_old2->bits,
            sn_old2
        ));
        cout<<"sn"<<endl;

        //merkle tree
        //root1.reset(new digest_variable<FieldT>(pb, 256, ""));
        tree_gad_cm1.reset(new tree_gadget<FieldT>(pb,root_cm1,commitment_old1,""));

        //root2.reset(new digest_variable<FieldT>(pb, 256, ""));
        tree_gad_cm2.reset(new tree_gadget<FieldT>(pb,root_cm2,commitment_old2,""));

        tree_gad_apk_s.reset(new tree_gadget<FieldT>(pb,root_apk_s,a_pk_s,""));
        tree_gad_apk_r.reset(new tree_gadget<FieldT>(pb,root_apk_r,a_pk_r,""));

        cout<<"tree"<<endl;

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
                        v_old1,  //整币转账
                        v_old2,
                        v3_array
                    ));
                cout<<"elg"<<endl;
    }

    void generate_r1cs_constraints() {

        this->pb.set_input_sizes(dimension);
        
        // sk ,pk
        prf_gad->generate_r1cs_constraints();
        sn_gad1->generate_r1cs_constraints();
        sn_gad2->generate_r1cs_constraints();
        
        //comment
        comm_gad_old1->generate_r1cs_constraints();
        comm_gad_old2->generate_r1cs_constraints();

        comm_gad_new->generate_r1cs_constraints();
      
        // value == new_value
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
            1,
            packed_addition(v_old1)+packed_addition(v_old2),
            packed_addition(v_new)
        ));

        //merkletree
        tree_gad_cm1->generate_r1cs_constraints();
        tree_gad_cm2->generate_r1cs_constraints();

        tree_gad_apk_s->generate_r1cs_constraints();
        tree_gad_apk_r->generate_r1cs_constraints();
        
        //
        elgamal_gad->generate_r1cs_constraints();  
    }
   
    void generate_r1cs_witness(
        uint256& ask,
        uint256& a_pk,
        uint256& apk_r,
        uint256& old_sn1,
        uint256& old_sn2,
        uint64_t value1,
        uint64_t value2,
        uint256& old_r1,
        uint256& old_comm1,
        uint256& old_r2,
        uint256& old_comm2,
        uint256 &rt1,
        MerkleTreePath &path1,
        uint256 &rt2,
        MerkleTreePath &path2,
        uint256& apk_s_rt,
        MerkleTreePath& apk_s_path,
        uint256& apk_r_rt,      
        MerkleTreePath& apk_r_path,
        uint256& new_comm,
        uint256& new_r,
        Elgamal_2apk_3v<FieldT> &elg
    ) {  
        //apk,ask,prf
        a_sk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(ask)); 
        prf_gad->generate_r1cs_witness();
        a_pk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(a_pk));
        
        
        //sn
        r_old1->bits.fill_with_bits(this->pb, uint256_to_bool_vector(old_r1));
        sn_gad1->generate_r1cs_witness();
        sn_old1->bits.fill_with_bits(this->pb, uint256_to_bool_vector(old_sn1));

        r_old2->bits.fill_with_bits(this->pb, uint256_to_bool_vector(old_r2));
        sn_gad2->generate_r1cs_witness();
        sn_old2->bits.fill_with_bits(this->pb, uint256_to_bool_vector(old_sn2));
        
        //comment
        v_old1.fill_with_bits(this->pb, uint64_to_bool_vector(value1));
        v_old2.fill_with_bits(this->pb, uint64_to_bool_vector(value2));
        
        comm_gad_old1->generate_r1cs_witness();
        commitment_old1->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(old_comm1)
        );
        comm_gad_old2->generate_r1cs_witness();
        commitment_old2->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(old_comm2)
        );
       
        a_pk_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_r));

        v_new.fill_with_bits(this->pb, uint64_to_bool_vector(value1+value2));
        r_new->bits.fill_with_bits(this->pb, uint256_to_bool_vector(new_r));
        comm_gad_new->generate_r1cs_witness();
        commitment_new->bits.fill_with_bits(
            this->pb,
            uint256_to_bool_vector(new_comm)
        );
        
        root_cm1->bits.fill_with_bits(this->pb, uint256_to_bool_vector(rt1));

        //merkle tree
        tree_gad_cm1->generate_r1cs_witness(
                                path1.nodeHashList
                                ,path1.parentList
                                ,path1.pathisrightList);
        
        root_cm2->bits.fill_with_bits(this->pb, uint256_to_bool_vector(rt2));
        tree_gad_cm2->generate_r1cs_witness(
                                path2.nodeHashList
                                ,path2.parentList
                                ,path2.pathisrightList);

        root_apk_s->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_s_rt));
        root_apk_r->bits.fill_with_bits(this->pb, uint256_to_bool_vector(apk_r_rt));

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

template<typename FieldT>
void test_js_hb() {

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
    uint256 apk_s=prf(ask_s);
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=3;
    uint64_t v_3=0;

    uint256 old_r1=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");
    uint256 old_r2=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a66");

    uint256 new_r=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");
    

    uint256 old_comm1=cm(apk_s,v_1,old_r1);
    uint256 old_comm2=cm(apk_s,v_2,old_r2);

    uint256 new_comm=cm(apk_r,v_1+v_2,new_r);
    

    uint256 old_sn1=sn(ask_s,old_r1);
    uint256 old_sn2=sn(ask_s,old_r2);

    unsigned char data[32*6];
    char g_c[]="11112222333344445555666677778888999900001111";
    char sk[]="1234567891";
    FieldT g=bigint_r(g_c);
    FieldT Gsk = bigint_r(sk);//私钥
    FieldT Gpk = g ^ Gsk.as_bigint();//公钥

    Elgamal_2apk_3v<FieldT> elg;

    elg.setG(g);
    
    elg.setPk(Gpk);

    elg.encrypt(apk_s,apk_r,v_1,v_2,v_3);//加密

    elg.getEncryptedData(data);


    protoboard<FieldT> pb;

    cout<<"1"<<endl;

    joinsplit_gadget_hb<FieldT> js_gad_hb(pb,g,Gpk);        
    cout<<"2"<<endl;
    //pb.set_input_sizes(dimension);

    js_gad_hb.generate_r1cs_constraints();
    cout<<"3"<<endl;
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    MerkleTreePath path1=getMerkleTreePath_hb1();
    uint256 rt1=path1.root;
    MerkleTreePath path2=getMerkleTreePath_hb2();
    uint256 rt2=path2.root;
   
     
    MerkleTreePath apk_s_path=getMerkleTreePath_apk_s();
    uint256 apk_s_rt=apk_s_path.root;
    
    MerkleTreePath apk_r_path=getMerkleTreePath_apk_r();
    uint256 apk_r_rt=apk_r_path.root;

    js_gad_hb.generate_r1cs_witness(
        ask_s,
        apk_s,
        apk_r,
        old_sn1,
        old_sn2,
        v_1,
        v_2,
        old_r1,
        old_comm1,
        old_r2,
        old_comm2,
        rt1,
        path1,
        rt2,
        path2,
        apk_s_rt,
        apk_s_path,
        apk_r_rt,
        apk_r_path,
        new_comm,
        new_r,
        elg
    ) ;
  
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    

        //验证方
    //验证方，公共参数
    std::vector<FieldT> pi_v;

    //---------------sn-------------
    std::vector<bool> sn_v1=uint256_to_bool_vector(old_sn1);
    for(int i=0;i<256;i++){
        if(sn_v1[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(sn_v1[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    std::vector<bool> sn_v2=uint256_to_bool_vector(old_sn2);
    for(int i=0;i<256;i++){
        if(sn_v2[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(sn_v2[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //---老承诺哈希树的根--------------
    std::vector<bool> rt_v1=uint256_to_bool_vector(rt1);
    for(int i=0;i<256;i++){
        if(rt_v1[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(rt_v1[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }
    std::vector<bool> rt_v2=uint256_to_bool_vector(rt2);
    for(int i=0;i<256;i++){
        if(rt_v2[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(rt_v2[i]==0){
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
    std::vector<bool> new_comm_v=uint256_to_bool_vector(new_comm);
    for(int i=0;i<256;i++){
        if(new_comm_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(new_comm_v[i]==0){
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
    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi_v,proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    } 
}


//-------------捐赠电路-----------------
#define _random_len_bit_ 248
#define _random_len_byte_ 31
#define _bigint_len_byte_ 32

/*
bigint_r get_random_bigint_248(){
        
        unsigned char buf_bit[_random_len_bit_];

        unsigned char buf_byte[_random_len_byte_];

        for(int i=0;i<_random_len_bit_;i++){
            buf_bit[i]=(rand()%2);
        }

        for(int j=0;j<_random_len_byte_;j++){
            buf_byte[j]=BitToByte(&buf_bit[j*8]);
        }
        
        bigint_r r=bigint_r("0");
        memcpy(&r.data[0],buf_byte,_random_len_byte_);
       
        return r;
}
*/

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
void ByteToBit(unsigned char ch, unsigned char bit[8])
{    
   for(int i = 0; i < 8; i++)
   {   
        bit[i] = (ch>>i)&1;   
   }   
}
unsigned char BitToByte(unsigned char bit[8])
{   
	unsigned char t=0;
    for(int i = 0; i < 8; i++)
    {   
        t = t|(bit[i]<<i);   
    }   
    return t;   
}

bigint_r get_random_bigint_248(){
     
        bigint_r r_o=bigint_r("0");
        r_o=r_o.randomize();

        bigint_r r=bigint_r("0");

        memcpy(&r.data[0],&r_o.data[0],_random_len_byte_);

        return r;
}
/*
std::vector<bool> bigintToUint256(unsigned char ch[32],unsigned char bit[256])
{   
    int i;   
    for(i = 0; i < _bigint_len_byte_; i++)
    {           
        ByteToBit(ch[i],&bit[8*i]);   
    }     
 }
*/
std::vector<bool> bigint_to_boolvector(bigint_r &br)
{   
    unsigned char bits[256];
    std::vector<bool> bv;
    unsigned char *buf=(unsigned char *)&br.data[0];
    for(int i = 0; i < _bigint_len_byte_; i++)
    {  
        ByteToBit(buf[i],&bits[8*i]);   
    } 
    for(int i=0;i<256;i++){
        //printf("%d ",bits[i]);; 
        bv.push_back(bits[i]);
    }
    //printf("\n");
    return bv;
}

uint256 bigint248_to_uint256(bigint_r bi){
        
    char hex[65];
    hex[64]=0;
    Hex2Str((char*)&bi.data[0],hex,32);
    return uint256S(hex);
}
/*
uint256 bigint248ToUint256(bigint_r r){
    char hex[65];
    hex[64]=0;
    Hex2Str(&r.data[0],hex,32);
    return uint256S(hex);
}*/

template<typename FieldT>
void test_tranlate(){

    bigint_r r1=get_random_bigint_248();

    r1.print();
    cout<<endl;
    uint256 u=bigint248_to_uint256(r1);
    cout<<u.ToString();
}
/*
template<typename FieldT>
class u256_to_bigint_gadget : gadget<FieldT> {
private: 
    pb_variable_array<FieldT> uint256_bv;
    pb_variable_array<FieldT> bigint_r_bv;
public:
    u256_to_bigint_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT>& u256_bv,//哈希结果
        pb_variable_array<FieldT>& bigint_bv//分量随机数  
    ) : gadget<FieldT>(pb) {

        uint256_bv=u256_bv;
        bigint_r_bv=bigint_bv;
    }

    void generate_r1cs_constraints() {

        for(int i=1;i<=256/8;i++){
            for(int j=0;j<8;j++){
                int k=256-8*i+7-j;
                int p=8*(i-1)+j;

                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(bigint_r_bv[p], FieldT::one(), uint256_bv[k]),FMT(" S_%zu"));
            }
            
        }

    }

    void generate_r1cs_witness() {
        
        for(int i=1;i<=256/8;i++){
            for(int j=0;j<8;j++){
                int k=256-8*i+7-j;
                int p=8*(i-1)+j;

                this->pb.val(bigint_r_bv[p])=this->pb.val(uint256_bv[k]);

            }
    
        }
       
    }
};

*/
template<typename FieldT>
class u256_to_bigint_gadget : gadget<FieldT> {
private: 
    pb_linear_combination_array<FieldT> uint256_bv;
    pb_linear_combination_array<FieldT> bigint_r_bv;
public:
    u256_to_bigint_gadget(
        protoboard<FieldT> &pb,
        const pb_linear_combination_array<FieldT> &u256_bv,
        const pb_linear_combination_array<FieldT> &bigint_bv
    ) : gadget<FieldT>(pb) {

        uint256_bv=u256_bv;
        bigint_r_bv=bigint_bv;
    }

    void generate_r1cs_constraints() {

        for(int i=1;i<=256/8;i++){
            for(int j=0;j<8;j++){
                int k=256-8*i+7-j;
                int p=8*(i-1)+j;

                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(bigint_r_bv[p], FieldT::one(), uint256_bv[k]),FMT(" S_%zu"));
            }
            
        }

    }

    void generate_r1cs_witness() {
        
        for(int i=1;i<=256/8;i++){
            for(int j=0;j<8;j++){
                int k=256-8*i+7-j;
                int p=8*(i-1)+j;

                uint256_bv[k].evaluate(this->pb);

                this->pb.lc_val(bigint_r_bv[p])=this->pb.lc_val(uint256_bv[k]);

            }
    
        }
       
    }
};

template<typename FieldT>
class bit_to_val_gadget : public gadget<FieldT> {
private:
    pb_variable_array<FieldT> temp1;
    pb_variable_array<FieldT> temp2;
    FieldT g;
    
    pb_linear_combination_array<FieldT> A;
    pb_variable<FieldT> result;
    //pb_variable<FieldT> result_r;
public:
    bit_to_val_gadget(protoboard<FieldT>& pb,
                         const pb_linear_combination_array<FieldT> &bits,//y
                         pb_variable<FieldT> &val
                         ) :
        gadget<FieldT>(pb),A(bits),result(val)
    {
        g=FieldT::one()*2;
       
        //A=bits;
        //result=val;
        //A.allocate(pb, bits.size(), FMT(this->annotation_prefix, " temp1"));
        temp1.allocate(pb, A.size(), FMT(this->annotation_prefix, " temp1"));
        temp2.allocate(pb, A.size(), FMT(this->annotation_prefix, " temp2"));

        cout<<endl;
        cout<<"----bit_to_val_gadget----------";
        cout<<endl;
        
        cout<<endl;
    }

    void generate_r1cs_constraints()
    {
        for (size_t i = 0; i < A.size(); ++i)
        {
        //A[i].evaluate(this->pb);
        this->pb.add_r1cs_constraint(
            // r1cs_constraint<FieldT>(temp1[i] , FieldT::one(), this->pb.lc_val(A[i]) * (g ^ i) ),FMT(this->annotation_prefix, " S_%zu", i));     
            r1cs_constraint<FieldT>(temp1[i] , FieldT::one(), A[i] * (g ^ i) ),FMT(this->annotation_prefix, " S_%zu", i));    
           
        }
        for (size_t i = 0; i < temp2.size(); ++i)
        {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(i==0 ? temp1[0]: temp2[i-1]+temp1[i]
                                , FieldT::one(), i==temp1.size()-1 ? result : temp2[i]),
            FMT(this->annotation_prefix, " S_%zu", i));
        }
        //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>( result_r , FieldT::one(), result));
    }

    void generate_r1cs_witness()
    {
       
        for (size_t i = 0; i < A.size(); ++i)
        {
            A[i].evaluate(this->pb);
            this->pb.val(temp1[i]) = this->pb.lc_val(A[i]) * (g ^ i);
        }
    
        for (size_t i = 0; i < temp2.size(); ++i){
            this->pb.val(i == temp1.size()-1 ? result : temp2[i]) = (i==0 ? this->pb.val(temp1[0]) : this->pb.val(temp2[i-1])+this->pb.val(temp1[i]) ) ;
            
        }
        cout<<"-------generate_r1cs_witness--result----"<<endl;
        cout<<this->pb.val(result)<<endl;
    }
};
/*
template<typename FieldT>
class bit_to_val_gadget : public gadget<FieldT> {
private:
    pb_variable_array<FieldT> temp1;
    pb_variable_array<FieldT> temp2;
    FieldT g;
    
    pb_variable_array<FieldT> A;
    pb_variable<FieldT> result;
    //pb_variable<FieldT> result_r;
public:
    bit_to_val_gadget(protoboard<FieldT>& pb,
                         pb_variable_array<FieldT> &bits,//y
                         pb_variable<FieldT> &val
                         ) :
        gadget<FieldT>(pb)
    {
        g=FieldT::one()*2;
       
        A=bits;
        result=val;
        //A.allocate(pb, bits.size(), FMT(this->annotation_prefix, " temp1"));
        temp1.allocate(pb, A.size(), FMT(this->annotation_prefix, " temp1"));
        temp2.allocate(pb, A.size(), FMT(this->annotation_prefix, " temp2"));

        cout<<endl;
        cout<<"----bit_to_val_gadget----------";
        cout<<endl;
        
        cout<<endl;
    }

    void generate_r1cs_constraints()
    {
        

        for (size_t i = 0; i < A.size(); ++i)
        {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(temp1[i] , FieldT::one(), this->pb.val(A[i]) * (g ^ i) ),FMT(this->annotation_prefix, " S_%zu", i));     
        }
        for (size_t i = 0; i < temp2.size(); ++i)
        {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(i==0 ? temp1[0]: temp2[i-1]+temp1[i]
                                , FieldT::one(), i==temp1.size()-1 ? result : temp2[i]),
            FMT(this->annotation_prefix, " S_%zu", i));
        }
        //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>( result_r , FieldT::one(), result));
    }

    void generate_r1cs_witness()
    {
       
        
        for (size_t i = 0; i < A.size(); ++i)
        {
            this->pb.val(temp1[i]) = this->pb.val(A[i]) * (g ^ i);
        }
    
        for (size_t i = 0; i < temp2.size(); ++i){
            this->pb.val(i == temp1.size()-1 ? result : temp2[i]) = (i==0 ? this->pb.val(temp1[0]) : this->pb.val(temp2[i-1])+this->pb.val(temp1[i]) ) ;
            
        }
        cout<<"-------generate_r1cs_witness--result----"<<endl;
        cout<<this->pb.val(result)<<endl;
    }
};
*/


template<typename FieldT>
void test_bit_to_val(){
    protoboard<FieldT> pb;

    std::vector<uint256> s_v_list;
    std::vector<bigint_r> s_v_bigint_r_list;
    
    bigint_r r2=get_random_bigint_248();
    bigint_r r3=get_random_bigint_248();
    uint256 r2_uint256=bigint248_to_uint256(r2);

    pb_variable<FieldT> pv;
    pv.allocate(pb,"");

    pb_variable<FieldT> result;
    result.allocate(pb,"");
    pb.val(result)=r2;

    pb_variable_array<FieldT> pva_bi;
    pva_bi.allocate(pb,256,"");
   

    pb_variable_array<FieldT> pva_u256;
    pva_u256.allocate(pb,256,"");
   
    cout<<"1"<<endl;
    
   
    bit_to_val_gadget<FieldT> sum_gadget1(pb,pva_bi,pv); 

    cout<<"2"<<endl;
    
    
    sum_gadget1.generate_r1cs_constraints();
      
    
    cout<<"3"<<endl;

    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    pva_bi.fill_with_bits(pb, bigint_to_boolvector(r2));

    sum_gadget1.generate_r1cs_witness();

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
    for(int i=0;i<256;i++){
        cout<<pb.val(pva_bi[i]);
    }   
    cout<<endl;
    cout<<endl;
    cout<<endl;

    cout<<pb.val(result)<<endl;
    cout<<pb.val(pv)<<endl;
    
}

/*
template<typename FieldT>
void test_bit_to_val(){
    protoboard<FieldT> pb;

    std::vector<uint256> s_v_list;
    std::vector<bigint_r> s_v_bigint_r_list;
    
    bigint_r r2=get_random_bigint_248();
    bigint_r r3=get_random_bigint_248();
    uint256 r2_uint256=bigint248_to_uint256(r2);

    pb_variable<FieldT> pv;
    pv.allocate(pb,"");

    pb_variable<FieldT> result;
    result.allocate(pb,"");
    pb.val(result)=r2;

    pb_variable_array<FieldT> pva_bi;
    pva_bi.allocate(pb,256,"");
   

    pb_variable_array<FieldT> pva_u256;
    pva_u256.allocate(pb,256,"");
   
    cout<<"1"<<endl;
    
    u256_to_bigint_gadget<FieldT> u256_to_b(pb,pva_u256,pva_bi);

    bit_to_val_gadget<FieldT> sum_gadget1(pb,pva_bi,pv); 

    cout<<"2"<<endl;

        
    u256_to_b.generate_r1cs_constraints();
    sum_gadget1.generate_r1cs_constraints();
    // pb.add_r1cs_constraint(r1cs_constraint<FieldT>( pv , FieldT::one(),result));     
        
    
    cout<<"3"<<endl;
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    // sum_gadget1.generate_r1cs_witness(pva);
    pva_u256.fill_with_bits(pb, uint256_to_bool_vector(r2_uint256));
    u256_to_b.generate_r1cs_witness();
    
    // for (size_t i = 0; i < 256; ++i)
    // {
    //     pb.lc_val(pva_bi[i]) = pb.val(pva_bi[i])==1 ? FieldT::one() : FieldT::zero();
    // }
    sum_gadget1.generate_r1cs_witness();

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
    for(int i=0;i<256;i++){
        cout<<pb.val(pva_bi[i]);
    }   
    cout<<endl;
    // cout<<pb.val(result)<<endl;
    // cout<<pb.val(pv)<<endl;
    
}
*/
template<typename FieldT>
class v_list_sum_gadget : public gadget<FieldT> {
private:
    pb_variable_array<FieldT> temp1;
    pb_variable_array<FieldT> temp2;
    FieldT g;
public:
    pb_variable_array<FieldT> v_lsit;
    pb_variable<FieldT> result;
   
    v_list_sum_gadget(protoboard<FieldT>& pb,
                         pb_variable_array<FieldT> &v_s,//y
                         pb_variable<FieldT> &sum
                         ) :
        gadget<FieldT>(pb)
    {
        g=FieldT::one()*2;
        result=sum;
        //result.allocate(pb,  FMT(this->annotation_prefix, " temp2"));
     
        v_lsit=v_s;
        temp1.allocate(pb, v_lsit.size(), FMT(this->annotation_prefix, " temp1"));  
    }

    void generate_r1cs_constraints()
    {
        
        for (size_t i = 0; i < temp1.size()-1; ++i)
        {
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(i==0 ? v_lsit[i]+v_lsit[i+1] : temp1[i-1]+v_lsit[i+1]
                                , FieldT::one(), i==temp1.size()-2 ? result : temp1[i]),
            FMT(this->annotation_prefix, " S_%zu", i));
        }
        //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>( result_r , FieldT::one(), result));
    }

    void generate_r1cs_witness()
    {
        for (size_t i = 0; i < temp1.size()-1; ++i)
        {
            this->pb.val(i==temp1.size()-2 ? result : temp1[i])=(i==0 ? this->pb.val(v_lsit[i])+this->pb.val(v_lsit[i+1]) : this->pb.val(temp1[i-1])+this->pb.val(v_lsit[i+1]));
        }  
    }
};

template<typename FieldT>
void test_sum_gadget_b(){
    protoboard<FieldT> pb;

    std::vector<uint256> s_v_list;
    std::vector<bigint_r> s_v_bigint_r_list;
    
    bigint_r r1=get_random_bigint_248();
    bigint_r r2=get_random_bigint_248();
    bigint_r r3=get_random_bigint_248();

    uint256 s_v_256_1=bigint248_to_uint256(r1);
    uint256 s_v_256_2=bigint248_to_uint256(r2);
    uint256 s_v_256_3=bigint248_to_uint256(r3);

    

    pb_variable<FieldT> pv;
    pv.allocate(pb,"");
    pb.val(pv)=r3;

    pb_variable_array<FieldT> pva;
    pva.allocate(pb,256,"");
    pva.fill_with_bits(pb, bigint_to_boolvector(r3));


    cout<<r3<<endl;
    cout<<pb.val(pv)<<endl;
  
    
    
    cout<<"1"<<endl;
    
    v_list_sum_gadget<FieldT> sum_gadget1(pb,pva,pv,"b"); 

    cout<<"2"<<endl;

    sum_gadget1.generate_r1cs_constraints();
    
    cout<<"3"<<endl;
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    sum_gadget1.generate_r1cs_witness();

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
    cout<<pb.val(pv)<<endl;
    
}

template<typename FieldT>
void test_sum_gadget_b_list(){
    protoboard<FieldT> pb;

    std::vector<uint256> s_v_list;
    std::vector<bigint_r> s_v_bigint_r_list;
    
    bigint_r r1=get_random_bigint_248();
    bigint_r r2=get_random_bigint_248();
    bigint_r r3=get_random_bigint_248();

    uint256 s_v_256_1=bigint248_to_uint256(r1);
    uint256 s_v_256_2=bigint248_to_uint256(r2);
    uint256 s_v_256_3=bigint248_to_uint256(r3);


    pb_variable<FieldT> pv;
    pv.allocate(pb,"");
    //pb.val(pv)=r3;

    pb_variable_array<FieldT> pva;
    pva.allocate(pb,3,"");

    //pva.fill_with_bits(pb, bigint_to_boolvector(r3));

    pb.val(pva[0])=1;
    pb.val(pva[1])=2;
    pb.val(pva[2])=3;
       
    v_list_sum_gadget<FieldT> sum_gadget1(pb,pva,pv,"b"); 

   
    sum_gadget1.generate_r1cs_constraints();
    
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    sum_gadget1.generate_r1cs_witness();

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }

    cout<<pb.val(pv)<<endl;
    
}

//--------------单个用户单个捐赠者的捐赠金额分量承诺---------------------
//金额求和门
template<typename FieldT>
class s_sum_gadget : gadget<FieldT> {
private:  
    std::vector<std::shared_ptr<binary_gadget<FieldT>>> binary_list;
    pb_variable_array<FieldT> s_v_array;
    pb_variable<FieldT> s_sum;
    pb_variable<FieldT> s_sum_tmp;
    size_t d_count;
public:
    s_sum_gadget(
        protoboard<FieldT> &pb,
        std::vector<pb_variable_array<FieldT>>& s_v, //分量金额，每个数字以数组形式
        pb_variable_array<FieldT>& s_v_l,
        FieldT& sum,                //分量和sum=s_v[0]+s_v[1]+...
        size_t d_c
    ) : gadget<FieldT>(pb) {

        d_count=d_c;
        s_v_array=s_v_l;
        //s_v_array.allocate(pb,d_count,"s_v_array");
        s_sum.allocate(pb,"sum");
        s_sum_tmp.allocate(pb,"sum");

        pb.val(s_sum)=sum;

        //构建，s_v[i] == s_v_array[i]
        for(size_t i=0;i<d_count;i++){
            std::shared_ptr<binary_gadget<FieldT>> binary_p;
            binary_p.reset(new binary_gadget<FieldT>(pb,s_v[i],s_v_array[i],"binary gadget"));
            binary_list.push_back(binary_p);
        }
    }

    void generate_r1cs_constraints() {

        //binary约束
        for(size_t i=0;i<d_count;i++){
            binary_list[i]->generate_r1cs_constraints();
        }

        //求和约束，s_sum=s_v_array[0]+s_v_array[1]+...
        /*
        for(size_t i=0;i<d_count;i++){
            s_sum_tmp=s_sum_tmp+s_v_array[0];
        }*/
        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(s_sum_tmp, FieldT::one(), s_sum),FMT(" S_%zu"));
    }

    void generate_r1cs_witness() {
       
       for(size_t i=0;i<d_count;i++){
            binary_list[i]->generate_r1cs_witness();
        }
    }
};


template<typename FieldT>
void test_sum_gadget(){
    protoboard<FieldT> pb;

    std::vector<uint256> s_v_list;
    std::vector<bigint_r> s_v_bigint_r_list;
    
    bigint_r r1=get_random_bigint_248();
    bigint_r r2=get_random_bigint_248();
    bigint_r r3=get_random_bigint_248();

    uint256 s_v_256_1=bigint248_to_uint256(r1);
    uint256 s_v_256_2=bigint248_to_uint256(r2);
    uint256 s_v_256_3=bigint248_to_uint256(r3);
    
    s_v_list.push_back(s_v_256_1);
    s_v_list.push_back(s_v_256_2);
    s_v_list.push_back(s_v_256_3);

    s_v_bigint_r_list.push_back(r1);
    s_v_bigint_r_list.push_back(r2);
    s_v_bigint_r_list.push_back(r3);

    std::vector<pb_variable_array<FieldT>> s_v; //分量金额，每个数字以数组形式
    pb_variable_array<FieldT> s_v_l;
    FieldT sum;
    //分量和sum=s_v[0]+s_v[1]+...

    for(size_t i=0;i<s_v_list.size();i++){
        pb_variable_array<FieldT> pva;
        pva.allocate(pb,256,"");
        pva.fill_with_bits(pb, uint256_to_bool_vector(s_v_list[i]));
        s_v.push_back(pva);
    }

    s_v_l.allocate(pb,s_v_list.size(),"");
    for(size_t i=0;i<s_v_list.size();i++){
        FieldT fp1=s_v_bigint_r_list[i];
        pb.val(s_v_l[i])=fp1;
        sum+=fp1;
    }

    size_t d_count=s_v_list.size();

    cout<<"1"<<endl;

    s_sum_gadget<FieldT> sum_gadget(pb,s_v,s_v_l,sum,d_count); 

    cout<<"2"<<endl;

    sum_gadget.generate_r1cs_constraints();
    
    cout<<"3"<<endl;
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    sum_gadget.generate_r1cs_witness();

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }

    //binary1.reset(new binary_gadget<FieldT>(pb,m1_array,m1_binary_result,"binary gadget"));
}



//承诺门：分量承诺由金额和随机数哈希而成
template<typename FieldT>
class single_d_single_splite_v_cm_gadget : gadget<FieldT> {
private:
    std::shared_ptr<block_variable<FieldT>> block;
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> hasher;
    std::shared_ptr<digest_variable<FieldT>> h_result;
public:
    single_d_single_splite_v_cm_gadget(
        protoboard<FieldT> &pb,
        pb_variable_array<FieldT>& s_v,//分量金额
        pb_variable_array<FieldT>& s_r,//分量随机数
        std::shared_ptr<digest_variable<FieldT>> result//哈希结果
    ) : gadget<FieldT>(pb) {
       
        //H(s_v,s_r)
        block.reset(new block_variable<FieldT>(pb, {
            s_v,
            s_r
        }, ""));

        h_result=result;

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block->bits,
            *result,
        ""));
    }

    void generate_r1cs_constraints() {
        hasher->generate_r1cs_constraints();
    }

    void generate_r1cs_witness(uint256 cm_256) {
        hasher->generate_r1cs_witness();
        (*h_result).generate_r1cs_witness(uint256_to_bool_vector(cm_256));
    }


    /*
    void generate_r1cs_witness(bigint_r cm_256) {
        hasher->generate_r1cs_witness();
       
        //(*h_result).generate_r1cs_witness(bigint_to_boolvector(cm_256));
        (*h_result).fill_with_bits(this->pb, bigint_to_boolvector(cm_256));
    }*/
};

uint256 single_d_single_v_cm(uint256 s_v,uint256 s_r){
    CSHA256 hasher;
  
    uint256 result;

    //H(s_v s_r)
    hasher.Write(s_v.begin(), 32);
    hasher.Write(s_r.begin(), 32);
    hasher.FinalizeNoPadding(result.begin());
  
    return result;
}

uint256 single_d_single_v_cm_bigint(bigint_r s_v,bigint_r s_r){
    CSHA256 hasher;
  
    //bigint_r result=get_random_bigint_248();
    uint256 result;
    //H(s_v s_r)
    hasher.Write((unsigned char *)&s_v.data[0], 32);
    //cout<<"bigint_r 1"<<endl;
    hasher.Write((unsigned char *)&s_r.data[0], 32);
    //cout<<"bigint_r 2"<<endl;
    hasher.FinalizeNoPadding(result.begin());
    //cout<<"bigint_r 3"<<endl;
    return result;
}

template<typename FieldT>
void test_single_d_single_v_cm(){
    protoboard<FieldT> pb;

    std::shared_ptr<digest_variable<FieldT>> h_result;
    h_result.reset(new digest_variable<FieldT>(pb, 256, ""));

    pb_variable_array<FieldT> pb_s_v;
    pb_s_v.allocate(pb,256,"a_pk");
   
    pb_variable_array<FieldT> pb_s_r;
    pb_s_r.allocate(pb,256,"r");

    uint256 s_v_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    uint256 s_r_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
   

    pb_s_v.fill_with_bits(pb,uint256_to_bool_vector(s_v_256));
    pb_s_r.fill_with_bits(pb,uint256_to_bool_vector(s_r_256));

    single_d_single_splite_v_cm_gadget<FieldT> cm_gad(pb, pb_s_v, pb_s_r, h_result);

    cm_gad.generate_r1cs_constraints();

    uint256 cm_256=single_d_single_v_cm(s_v_256,s_r_256);
    //uint256 cm_256=single_d_single_v_cm(s_v_256,s_v_256);
    //uint256 cm_256=uint256S("038cce42abd366b83ede7e009130de53722df73dee8251148cb48d1b9af68ad1");

    //const libff::bit_vector cm_bv = uint256_to_bool_vector(cm_256);
  
    cm_gad.generate_r1cs_witness(cm_256);

    //(*h_result).generate_r1cs_witness(cm_bv);

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
}

template<typename FieldT>
void test_single_d_single_v_cm_bigint(){
    protoboard<FieldT> pb;

    
    pb_variable_array<FieldT> pb_s_v_u256;
    pb_s_v_u256.allocate(pb,256,"a_pk");
   
    pb_variable_array<FieldT> pb_s_v_bi;
    pb_s_v_bi.allocate(pb,256,"r");

    pb_variable_array<FieldT> pb_s_v_bi_bit;
    pb_s_v_bi_bit.allocate(pb,256,"r");

    //bigint_r s_v_bi=get_random_bigint_248();
    bigint_r s_v_bi=4;

    uint256 s_v_256=bigint248_to_uint256(s_v_bi);
    
    pb_s_v_bi_bit.fill_with_bits(pb,bigint_to_boolvector(s_v_bi));

    pb_s_v_u256.fill_with_bits(pb,uint256_to_bool_vector(s_v_256));

    
    u256_to_bigint_gadget<FieldT> u256_t_bt(pb, pb_s_v_u256, pb_s_v_bi);
    u256_t_bt.generate_r1cs_constraints();
    
    u256_t_bt.generate_r1cs_witness();

    for(int i=0;i<256;i++){

        cout<<pb.val(pb_s_v_u256[i]); 
       
        if(((i+1)%8)==0){
             cout<<",";
        }
    }

    cout << endl;
    cout << endl;
    
    for(int i=0;i<256;i++){
        cout<<pb.val(pb_s_v_bi[i]);
      
        if(((i+1)%8)==0){
             cout<<",";
        }
    }
    //pb_s_v_bi_bit
    cout << endl;
    cout << endl;
    for(int i=0;i<256;i++){
        cout<<pb.val(pb_s_v_bi_bit[i]);
      
        if(((i+1)%8)==0){
             cout<<",";
        }
    }
    cout << endl;
    cout << endl;

    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
}


//单个捐赠者，收到其他用户的分金额后，求和，出证明的电路
template<typename FieldT>
class single_sum_gadget : gadget<FieldT> {
private:

    int dimension;
    std::shared_ptr<single_d_single_splite_v_cm_gadget<FieldT>> sdsv_cm_gadget;//付款方

    //std::shared_ptr<digest_variable<FieldT>> splited_cm;  //承诺
    //std::shared_ptr<digest_variable<FieldT>> splited_r;   //随机数
    //pb_variable_array<FieldT> splited_v;   //金额

    std::shared_ptr<digest_variable<FieldT>> splited_cm;  //承诺
    pb_variable_array<FieldT> splited_r;   //随机数
    pb_variable_array<FieldT> splited_v;   //金额

public:
    single_sum_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb) {
        
        //公共参数长度：2*sn256+老承诺哈希树根256+付款方256+收款方256+新承诺256+6个密文
        //dimension=256+256+256+256+256+256+256+6+1+1;

        dimension=256;
        splited_cm.reset(new digest_variable<FieldT>(pb, 256, ""));  //承诺
        splited_r.allocate(pb, 256);   //随机数
        splited_v.allocate(pb, 256);   //金额

        sdsv_cm_gadget.reset(new single_d_single_splite_v_cm_gadget<FieldT>(pb,splited_v,splited_r,splited_cm));

    }

    void generate_r1cs_constraints() {

        this->pb.set_input_sizes(dimension);
        sdsv_cm_gadget->generate_r1cs_constraints();

    }
   
    void generate_r1cs_witness(
        uint256& s_cm,  //承诺
        uint256& s_r,   //随机数
        uint256& s_v    //金额
    ) {
        
        splited_cm->bits.fill_with_bits(this->pb, uint256_to_bool_vector(s_cm));
        splited_r.fill_with_bits(this->pb, uint256_to_bool_vector(s_r));
        splited_v.fill_with_bits(this->pb, uint256_to_bool_vector(s_v));

        sdsv_cm_gadget->generate_r1cs_witness(s_cm);

    }
};

//捐赠者证明自己拿了正确回馈的
template<typename FieldT>
class single_d_reward_gadget : gadget<FieldT> {
private:

    size_t dimension;//公共参数的长度
    size_t d_count; //捐赠者的数目

    std::vector<std::shared_ptr<single_d_single_splite_v_cm_gadget<FieldT>>> sdsv_cm_gadget_list;//承诺门
    std::vector<std::shared_ptr<u256_to_bigint_gadget<FieldT>>> u256_to_bi_list;    //256->bigint，bit
    std::vector<std::shared_ptr<bit_to_val_gadget<FieldT>>> bit_to_val_list;    //bigint，bit->bigint
    std::shared_ptr<v_list_sum_gadget<FieldT>> v_list_sum;    //求和门

    std::vector<std::shared_ptr<digest_variable<FieldT>>> splited_cm_list;  //承诺
    std::vector<pb_variable_array<FieldT>> splited_r_list;   //随机数
    std::vector<pb_variable_array<FieldT>> splited_v_list;   //金额uint256
    std::vector<pb_variable_array<FieldT>> splited_v_list_bigint;   //金额bigint形式

    std::vector<pb_variable_array<FieldT>> splited_v_list_bigint_1;   //金额bigint形式

    pb_variable_array<FieldT> splited_v_list_single;   //单个金额bigint形式

    //捐赠者获得的回馈金额=总回馈金额*(自己的捐款金额/总捐赠金额)
    //回馈对应的承诺
    std::shared_ptr<single_d_single_splite_v_cm_gadget<FieldT>> reward_cm_gadget;//承诺门
    std::shared_ptr<digest_variable<FieldT>> reward_cm;  //承诺
    pb_variable_array<FieldT> reward_r;
    std::shared_ptr<u256_to_bigint_gadget<FieldT>> reward_u256_to_bi;   //256->bigint，bit
    std::shared_ptr<bit_to_val_gadget<FieldT>> reward_bit_to_val;       //bigint，bit->bigint

    pb_variable<FieldT> total_d_v;  //总捐赠金额
    pb_variable<FieldT> total_r_v;  //总回馈金额

    pb_variable<FieldT> self_d_v; //自己的捐款金额
    pb_variable_array<FieldT> reward_v_bits;   //回馈金额
    pb_variable_array<FieldT> reward_v_bits_bigint;   //回馈金额
    pb_variable<FieldT> reward_v;   //回馈金额
    pb_variable<FieldT> temp;       //证明回馈符合关系的中间量
  
public:
   
    single_d_reward_gadget(protoboard<FieldT> &pb, size_t d_c) : gadget<FieldT>(pb) { 
        //公共参数长度：d_c个承诺
        d_count=d_c;

        dimension=256*(d_count+1)+2;//自己捐款的分量的承诺+自己奖励的承诺+总捐款额+总奖励额

        cout<<"1 1"<<endl;

        //承诺分配
        for(size_t i=0;i<d_count;i++){
            std::shared_ptr<digest_variable<FieldT>> splited_cm_p;
            splited_cm_p.reset(new digest_variable<FieldT>(pb, 256, ""));
            splited_cm_list.push_back(splited_cm_p);  
        }

        //
        reward_cm.reset(new digest_variable<FieldT>(pb, 256, ""));
 
        total_d_v.allocate(pb, "total_d_v");  //总捐赠金额
        total_r_v.allocate(pb, "total_r_v");  //总回馈金额

        temp.allocate(pb, "t_sum");//中间验证量

        self_d_v.allocate(pb, "self_d_v"); //自己的捐款金额
       
        cout<<"1 2"<<endl;

        //随机数 
        for(size_t i=0;i<d_count;i++){
            pb_variable_array<FieldT> splited_r;
            splited_r.allocate(pb, 256);     
            splited_r_list.push_back(splited_r);
        }

        //金额
        for(size_t i=0;i<d_count;i++){
            pb_variable_array<FieldT> splited_v;
            splited_v.allocate(pb, 256);   
            splited_v_list.push_back(splited_v);
        }

        //金额bigint
        for(size_t i=0;i<d_count;i++){
            pb_variable_array<FieldT> splited_v_bi;
            splited_v_bi.allocate(pb, 256);   
            splited_v_list_bigint.push_back(splited_v_bi);
        }

        //单个金额bigint
        splited_v_list_single.allocate(pb, d_count); 

        //回馈承诺的金额和随机数
        reward_r.allocate(pb, 256);
        reward_v.allocate(pb);
        reward_v_bits.allocate(pb, 256);
        reward_v_bits_bigint.allocate(pb, 256);

        //门
        cout<<"1 3"<<endl;
        for(size_t i=0;i<d_count;i++){
            std::shared_ptr<single_d_single_splite_v_cm_gadget<FieldT>> sdsv_cm_gadget;
            sdsv_cm_gadget.reset(new single_d_single_splite_v_cm_gadget<FieldT>(pb,splited_v_list[i],splited_r_list[i],splited_cm_list[i]));
            sdsv_cm_gadget_list.push_back(sdsv_cm_gadget);
        }

        reward_cm_gadget.reset(new single_d_single_splite_v_cm_gadget<FieldT>(pb,reward_v_bits,reward_r,reward_cm));
        
        cout<<"1 4"<<endl;

        //u256->bigint
        //bit序列->单个金额
        for(size_t i=0;i<d_count;i++){
            //u256->bigint,bit 
            std::shared_ptr<u256_to_bigint_gadget<FieldT>> u256_to_bigint;
            u256_to_bigint.reset(new u256_to_bigint_gadget<FieldT>(pb,splited_v_list[i],splited_v_list_bigint[i]));
            u256_to_bi_list.push_back(u256_to_bigint);
        }

        for(size_t i=0;i<d_count;i++){
            //bit序列->单个金额
            std::shared_ptr<bit_to_val_gadget<FieldT>> bit_to_v;
            bit_to_v.reset(new bit_to_val_gadget<FieldT>(pb,splited_v_list_bigint[i],splited_v_list_single[i]));
            bit_to_val_list.push_back(bit_to_v);
        }

        //自己的金额求和
        v_list_sum.reset(new v_list_sum_gadget<FieldT>(pb,splited_v_list_single,self_d_v));

        reward_u256_to_bi.reset(new u256_to_bigint_gadget<FieldT>(pb,reward_v_bits,reward_v_bits_bigint));

        reward_bit_to_val.reset(new bit_to_val_gadget<FieldT>(pb,reward_v_bits_bigint,reward_v));
    
    }

    void generate_r1cs_constraints() {

        this->pb.set_input_sizes(dimension);

        //承诺
        for(size_t i=0;i<d_count;i++){
            sdsv_cm_gadget_list[i]->generate_r1cs_constraints();
        }
        
        reward_cm_gadget->generate_r1cs_constraints();

       
        //金额
        for(size_t i=0;i<d_count;i++){
            u256_to_bi_list[i]->generate_r1cs_constraints();
        }
        
        
        for(size_t i=0;i<d_count;i++){
            bit_to_val_list[i]->generate_r1cs_constraints();
        }
        
        v_list_sum->generate_r1cs_constraints();

        //回馈金额
        
        reward_u256_to_bi->generate_r1cs_constraints();
        
        reward_bit_to_val->generate_r1cs_constraints();

        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(self_d_v, total_r_v, temp)
        );
        this->pb.add_r1cs_constraint(
            r1cs_constraint<FieldT>(total_d_v,reward_v, temp)
        );

    }
   
    void generate_r1cs_witness(
        std::vector<uint256>& s_cm_l,  //承诺
        std::vector<uint256>& s_r_l,   //随机数
        std::vector<uint256>& s_v_l,    //金额
        uint256 r_cm,   //回馈的承诺
        uint256 r_r,    //回馈的随机数
        uint256 r_v,    //回馈的金额
        FieldT sum_d_v, //总捐款金额
        FieldT t_r_v   //总回馈金额
    ) {
        
        for(size_t i=0;i<d_count;i++){
         
            splited_r_list[i].fill_with_bits(this->pb, uint256_to_bool_vector(s_r_l[i]));
            splited_v_list[i].fill_with_bits(this->pb, uint256_to_bool_vector(s_v_l[i]));

            sdsv_cm_gadget_list[i]->generate_r1cs_witness(s_cm_l[i]); 
        }
       
        reward_r.fill_with_bits(this->pb, uint256_to_bool_vector(r_r));
        reward_v_bits.fill_with_bits(this->pb, uint256_to_bool_vector(r_v));
        reward_cm_gadget->generate_r1cs_witness(r_cm); 
         
        this->pb.val(total_r_v)=t_r_v;//总回馈额
        this->pb.val(total_d_v)=sum_d_v;//总捐款额

        //金额
        for(size_t i=0;i<d_count;i++){
            u256_to_bi_list[i]->generate_r1cs_witness();
        }
        
        for(size_t i=0;i<d_count;i++){
            bit_to_val_list[i]->generate_r1cs_witness();
        }
        
        v_list_sum->generate_r1cs_witness();
        
         
        reward_u256_to_bi->generate_r1cs_witness();

        
        reward_bit_to_val->generate_r1cs_witness();

        this->pb.val(temp)=this->pb.val(reward_v)*this->pb.val(total_d_v);
        cout<<"---temp----"<<this->pb.val(temp)<<endl;
        
    }
};

//捐赠者收到其他捐赠者的分量后，求和，出证明的门
template<typename FieldT>
class single_d_sum_gadget : gadget<FieldT> {
private:

    size_t dimension;//公共参数的长度
    size_t d_count; //捐赠者的数目

    std::vector<std::shared_ptr<single_d_single_splite_v_cm_gadget<FieldT>>> sdsv_cm_gadget_list;//承诺门
    std::vector<std::shared_ptr<u256_to_bigint_gadget<FieldT>>> u256_to_bi_list;    //256->bigint，bit
    std::vector<std::shared_ptr<bit_to_val_gadget<FieldT>>> bit_to_val_list;    //bigint，bit->bigint
    std::shared_ptr<v_list_sum_gadget<FieldT>> v_list_sum;    //求和门

    std::shared_ptr<single_d_single_splite_v_cm_gadget<FieldT>> simple_cm_gadget;//承诺门

    std::vector<std::shared_ptr<digest_variable<FieldT>>> splited_cm_list;  //承诺
    std::vector<pb_variable_array<FieldT>> splited_r_list;   //随机数
    std::vector<pb_variable_array<FieldT>> splited_v_list;   //金额uint256
    std::vector<pb_variable_array<FieldT>> splited_v_list_bigint;   //金额bigint形式

    std::vector<pb_variable_array<FieldT>> splited_v_list_bigint_1;   //金额bigint形式

    pb_variable_array<FieldT> splited_v_list_single;   //单个金额bigint形式
    pb_variable<FieldT> total_v;//总金额
    pb_variable<FieldT> sum_v;//总金额


public:
   
    single_d_sum_gadget(protoboard<FieldT> &pb, size_t d_c) : gadget<FieldT>(pb) { 
        //公共参数长度：d_c个承诺
        d_count=d_c;

        dimension=256*d_count+1;  

        cout<<"1 1"<<endl;

        //承诺分配
        for(size_t i=0;i<d_count;i++){
            std::shared_ptr<digest_variable<FieldT>> splited_cm_p;
            splited_cm_p.reset(new digest_variable<FieldT>(pb, 256, ""));
            splited_cm_list.push_back(splited_cm_p);  
        }

        //总金额
        sum_v.allocate(pb, "t_sum");
        total_v.allocate(pb, "t_sum");

        cout<<"1 2"<<endl;

        //随机数 
        for(size_t i=0;i<d_count;i++){
            pb_variable_array<FieldT> splited_r;
            splited_r.allocate(pb, 256);     
            splited_r_list.push_back(splited_r);
        }

        //金额
        for(size_t i=0;i<d_count;i++){
            pb_variable_array<FieldT> splited_v;
            splited_v.allocate(pb, 256);   
            splited_v_list.push_back(splited_v);
        }

        //金额bigint
        for(size_t i=0;i<d_count;i++){
            pb_variable_array<FieldT> splited_v_bi;
            splited_v_bi.allocate(pb, 256);   
            splited_v_list_bigint.push_back(splited_v_bi);
        }

        //单个金额bigint
        splited_v_list_single.allocate(pb, d_count); 

        //门
        cout<<"1 3"<<endl;
        for(size_t i=0;i<d_count;i++){
            std::shared_ptr<single_d_single_splite_v_cm_gadget<FieldT>> sdsv_cm_gadget;
            sdsv_cm_gadget.reset(new single_d_single_splite_v_cm_gadget<FieldT>(pb,splited_v_list[i],splited_r_list[i],splited_cm_list[i]));
            sdsv_cm_gadget_list.push_back(sdsv_cm_gadget);
        }

        cout<<"1 4"<<endl;

        //u256->bigint
        //bit序列->单个金额
        for(size_t i=0;i<d_count;i++){
           
            //u256->bigint,bit 
            std::shared_ptr<u256_to_bigint_gadget<FieldT>> u256_to_bigint;
            u256_to_bigint.reset(new u256_to_bigint_gadget<FieldT>(pb,splited_v_list[i],splited_v_list_bigint[i]));
            u256_to_bi_list.push_back(u256_to_bigint);

        }

        for(size_t i=0;i<d_count;i++){
            //bit序列->单个金额
            std::shared_ptr<bit_to_val_gadget<FieldT>> bit_to_v;
            bit_to_v.reset(new bit_to_val_gadget<FieldT>(pb,splited_v_list_bigint[i],splited_v_list_single[i]));
            bit_to_val_list.push_back(bit_to_v);
        }

        //金额求和
        v_list_sum.reset(new v_list_sum_gadget<FieldT>(pb,splited_v_list_single,total_v));
        
    }

    void generate_r1cs_constraints() {

        this->pb.set_input_sizes(dimension);

        //承诺
        for(size_t i=0;i<d_count;i++){
            sdsv_cm_gadget_list[i]->generate_r1cs_constraints();
        }
        
        //金额
        for(size_t i=0;i<d_count;i++){
            u256_to_bi_list[i]->generate_r1cs_constraints();
        }
        
        for(size_t i=0;i<d_count;i++){
            bit_to_val_list[i]->generate_r1cs_constraints();
        }
    
        v_list_sum->generate_r1cs_constraints();

        this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(total_v, FieldT::one(), sum_v),FMT(" S_%zu"));
        
    }
   
    void generate_r1cs_witness(
        std::vector<uint256>& s_cm_l,  //承诺
        std::vector<uint256>& s_r_l,   //随机数
        std::vector<uint256>& s_v_l,    //金额
        FieldT sum
    ) {
        
        for(size_t i=0;i<d_count;i++){
         
            splited_r_list[i].fill_with_bits(this->pb, uint256_to_bool_vector(s_r_l[i]));
            splited_v_list[i].fill_with_bits(this->pb, uint256_to_bool_vector(s_v_l[i]));

            sdsv_cm_gadget_list[i]->generate_r1cs_witness(s_cm_l[i]); 
        }

        this->pb.val(sum_v)=sum;

        //金额
        for(size_t i=0;i<d_count;i++){
            u256_to_bi_list[i]->generate_r1cs_witness();
        }
        
        for(size_t i=0;i<d_count;i++){
            
            bit_to_val_list[i]->generate_r1cs_witness();
        }
        
        v_list_sum->generate_r1cs_witness();
    }
};


template<typename FieldT>
void test_single_sum() {

    protoboard<FieldT> pb;

    uint256 s_v_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    uint256 s_r_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint256 cm_256=single_d_single_v_cm(s_v_256,s_r_256);

    uint256 cm_256_f=single_d_single_v_cm(s_v_256,s_v_256);


    single_sum_gadget<FieldT> s_sum_gadget(pb); 

    //cout<<"2"<<endl;
    //size_t dimension=256;
    size_t dimension=0;
    pb.set_input_sizes(dimension);

    s_sum_gadget.generate_r1cs_constraints();
    cout<<"3"<<endl;
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    s_sum_gadget.generate_r1cs_witness(
        cm_256,
        s_r_256,
        s_v_256
    );
  
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    

    //验证方
    //验证方，公共参数
    
    std::vector<FieldT> pi_v;
    
    //---------------sn-------------
    //std::vector<bool> pi_cm_v=uint256_to_bool_vector(cm_256_f);
    std::vector<bool> pi_cm_v=uint256_to_bool_vector(cm_256);
    for(int i=0;i<256;i++){
        if(pi_cm_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
        if(pi_cm_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
    }

    //auto pi_v = pb.primary_input();
    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi_v,proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    } 

    //binary1.reset(new binary_gadget<FieldT>(pb,m1_array,m1_binary_result,"binary gadget"));
}

template<typename FieldT>
void test_single_sum_list() {

    protoboard<FieldT> pb;

    std::vector<uint256> s_v_list;
    std::vector<uint256> s_r_list;
    std::vector<uint256> cm_list;

    bigint_r v1=1;
    bigint_r v2=2;
    bigint_r v3=3;

    
    uint256 s_v_256_1=bigint248_to_uint256(v1);
    uint256 s_r_256_1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint256 cm_256_1=single_d_single_v_cm(s_v_256_1,s_r_256_1);
   
    s_v_list.push_back(s_v_256_1);
    s_r_list.push_back(s_r_256_1);
    cm_list.push_back(cm_256_1);

    
    uint256 s_v_256_2=bigint248_to_uint256(v2);
    uint256 s_r_256_2=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a44");
    uint256 cm_256_2=single_d_single_v_cm(s_v_256_2,s_r_256_2);

    s_v_list.push_back(s_v_256_2);
    s_r_list.push_back(s_r_256_2);
    cm_list.push_back(cm_256_2);

    uint256 s_v_256_3=bigint248_to_uint256(v3);
    uint256 s_r_256_3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af65644");
    uint256 cm_256_3=single_d_single_v_cm(s_v_256_3,s_r_256_3);

    
    s_v_list.push_back(s_v_256_3);
    s_r_list.push_back(s_r_256_3);
    cm_list.push_back(cm_256_3);

    size_t d_count=3;

    pb_variable<FieldT> sum;

    single_d_sum_gadget<FieldT> sd_sum_gadget(pb,d_count);

    sum.allocate(pb,"sum");
    FieldT fv1,fv2,fv3;
    fv1=v1;
    fv2=v2;
    fv3=v3;
    FieldT sum_ft=fv1+fv2+fv3;
      
    cout<<"1"<<endl;

    pb_variable<FieldT> total_v;//总金额
    pb_variable<FieldT> sum_v;//总金额

    cout<<"2"<<endl;
    
    sd_sum_gadget.generate_r1cs_constraints();
    cout<<"3"<<endl;

    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    sd_sum_gadget.generate_r1cs_witness(
        cm_list,
        s_r_list,
        s_v_list,
        sum_ft
    );
    
    
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    

    //验证方
    //验证方，公共参数
    
    std::vector<FieldT> pi_v;
    
    //---------------验证cm-------------
    for(size_t j=0;j<d_count;j++){
        std::vector<bool> pi_cm_v=uint256_to_bool_vector(cm_list[j]);
        for(int i=0;i<256;i++){

            if(pi_cm_v[i]==1){
                pi_v.push_back(FieldT::one());
            }
            
            if(pi_cm_v[i]==0){
                pi_v.push_back(FieldT::zero());
            }
           
        }
    }

    //auto pi_v = pb.primary_input();
    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi_v,proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    } 
}

//----------单个捐赠者，分步实施，创建证明和验证--------------------------
std::vector<uint256> s_v_list;
std::vector<uint256> s_r_list;
std::vector<uint256> cm_list;

size_t d_count=3;   //捐赠者数目
FieldT s_sum;
char sds_vk_file[]="/home/mls/zksnark/libsnark-usage-example/donator2/vk.data";

//生成测试数据
void create_sds_testdata(){
    s_v_list.clear();
    s_r_list.clear();
    cm_list.clear();


    bigint_r v1=1;
    bigint_r v2=2;
    bigint_r v3=3;

    //uint256 s_v_256_1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad2");
    uint256 s_v_256_1=bigint248_to_uint256(v1);
    uint256 s_r_256_1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint256 cm_256_1=single_d_single_v_cm(s_v_256_1,s_r_256_1);
   
    s_v_list.push_back(s_v_256_1);
    s_r_list.push_back(s_r_256_1);
    cm_list.push_back(cm_256_1);

    //uint256 s_v_256_2=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a33");
    uint256 s_v_256_2=bigint248_to_uint256(v2);
    uint256 s_r_256_2=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a44");
    uint256 cm_256_2=single_d_single_v_cm(s_v_256_2,s_r_256_2);

    //uint256 cm_256_2_f=single_d_single_v_cm(s_v_256_2,s_v_256_2);

    s_v_list.push_back(s_v_256_2);
    s_r_list.push_back(s_r_256_2);
    cm_list.push_back(cm_256_2);

    //uint256 s_v_256_3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af62333");
    uint256 s_v_256_3=bigint248_to_uint256(v3);
    uint256 s_r_256_3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af65644");
    uint256 cm_256_3=single_d_single_v_cm(s_v_256_3,s_r_256_3);

    //uint256 cm_256_3_f=single_d_single_v_cm(s_v_256_3,s_v_256_3);

    s_v_list.push_back(s_v_256_3);
    s_r_list.push_back(s_r_256_3);
    cm_list.push_back(cm_256_3);

    FieldT fv1,fv2,fv3;
    fv1=v1;
    fv2=v2;
    fv3=v3;
    s_sum=fv1+fv2+fv3;
}

bool store_vk(char * vf_name,r1cs_ppzksnark_verification_key<ppT> vk){
  ofstream out_vk(vf_name,ios::binary);
  if(!out_vk.is_open())
  {
    cout<<"store vk ,file path error"<<endl;
    return false;
  }
    
  out_vk<<vk;
  out_vk.flush();
  return true;
}

bool load_vk(char * vf_name,r1cs_ppzksnark_verification_key<ppT>& vk){
  ifstream in_vk(vf_name,ios::binary);
  if(!in_vk.is_open())
  {
    cout<<"load vk ,file open error"<<endl;
    return false;
  }
  
  in_vk>>vk;
  in_vk.close();
  
  return true;
}
//获取证明
template<typename FieldT>
bool create_single_donator_sum_proof(std::vector<uint256> cm_l      //承诺列表
                                     ,std::vector<uint256> s_r_l    //随机树列表
                                     ,std::vector<uint256> s_v_l    //金额列表
                                     ,FieldT single_sum_v           //单个捐赠者的总金额
                                     ,r1cs_ppzksnark_proof<ppT>& proof) {

    protoboard<FieldT> pb;

    single_d_sum_gadget<FieldT> sd_sum_gadget(pb,d_count); 

    sd_sum_gadget.generate_r1cs_constraints();
    
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
    
    if(!store_vk(sds_vk_file,keypair.vk)){
        return false;
    }

    sd_sum_gadget.generate_r1cs_witness(
        cm_l,
        s_r_l,
        s_v_l,
        single_sum_v
    );
  
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();

    proof=r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);

    return true;
}

//构建公共参数
std::vector<FieldT> createPublicParam(std::vector<uint256> cm_l,FieldT sum){
    std::vector<FieldT> pi_v;
    
    //---------------验证cm-------------
    for(size_t j=0;j<d_count;j++){
        std::vector<bool> pi_cm_v=uint256_to_bool_vector(cm_l[j]);
        for(int i=0;i<256;i++){
            if(pi_cm_v[i]==1){
                pi_v.push_back(FieldT::one());
            }
            
            if(pi_cm_v[i]==0){
                pi_v.push_back(FieldT::zero());
            }
        }
    }

    //---------------验证和-------------

    pi_v.push_back(sum);

    return pi_v;
}
template<typename FieldT>
bool verify_single_donator_sum_proof(std::vector<FieldT> pi_v,r1cs_ppzksnark_proof<ppT> proof) {

    r1cs_ppzksnark_verification_key<ppT> vk;

    if(load_vk(sds_vk_file,vk)){
        return r1cs_ppzksnark_verifier_strong_IC<ppT>(vk,pi_v,proof);
    }else{
        return false;
    }
   
}

template<typename FieldT>
void test_single_sum_list_step() {

    create_sds_testdata();

    //证明方
    r1cs_ppzksnark_proof<ppT> proof;
    if(!create_single_donator_sum_proof<FieldT>(cm_list,s_r_list,s_v_list,s_sum,proof)){
        cout << "create proof failed!" << endl;
        return ;
    }

    //验证方
    if(verify_single_donator_sum_proof<FieldT>(createPublicParam(cm_list,s_sum),proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    } 
}


template<typename FieldT>
void test_single_reward_list() {

    protoboard<FieldT> pb;

    std::vector<uint256> s_v_list;
    std::vector<uint256> s_r_list;
    std::vector<uint256> cm_list;

    bigint_r v1=1;
    bigint_r v2=2;
    bigint_r v3=3;

    uint256 s_v_256_1=bigint248_to_uint256(v1);
    uint256 s_r_256_1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint256 cm_256_1=single_d_single_v_cm(s_v_256_1,s_r_256_1);
   
    s_v_list.push_back(s_v_256_1);
    s_r_list.push_back(s_r_256_1);
    cm_list.push_back(cm_256_1);

    uint256 s_v_256_2=bigint248_to_uint256(v2);
    uint256 s_r_256_2=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a44");
    uint256 cm_256_2=single_d_single_v_cm(s_v_256_2,s_r_256_2);

    s_v_list.push_back(s_v_256_2);
    s_r_list.push_back(s_r_256_2);
    cm_list.push_back(cm_256_2);

   
    uint256 s_v_256_3=bigint248_to_uint256(v3);
    uint256 s_r_256_3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af65644");
    uint256 cm_256_3=single_d_single_v_cm(s_v_256_3,s_r_256_3);


    s_v_list.push_back(s_v_256_3);
    s_r_list.push_back(s_r_256_3);
    cm_list.push_back(cm_256_3);

    size_t d_count=3;

    pb_variable<FieldT> sum;

    single_d_reward_gadget<FieldT> sd_reward_gadget(pb,d_count);

    sum.allocate(pb,"sum");
    FieldT fv1,fv2,fv3;
    fv1=v1;
    fv2=v2;
    fv3=v3;
    FieldT sum_ft=fv1+fv2+fv3;
   
    //回馈
    bigint_r r_v=2;
    uint256 r_v_256=bigint248_to_uint256(r_v);
    uint256 r_r_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af22222");
    uint256 cm_r=single_d_single_v_cm(r_v_256,r_r_256);

    cout<<"1"<<endl;

    cout<<"2"<<endl;
    
    sd_reward_gadget.generate_r1cs_constraints();
    cout<<"3"<<endl;

    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
   
    sd_reward_gadget.generate_r1cs_witness(
        cm_list,
        s_r_list,
        s_v_list,
        cm_r,
        r_r_256,
        r_v_256,
        36,
        12        
    );
    
    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
    
}
//生成测试数据
FieldT total_donator_v; //总捐款金额
FieldT total_reward_v;  //总奖励金额

uint256 reward_v_256;
uint256 reward_r_256;
uint256 cm_reward;
char reward_vk_file[]="/home/mls/zksnark/libsnark-usage-example/donator2/vk_reward.data";
void create_sds_testdata_reward(){
    s_v_list.clear();
    s_r_list.clear();
    cm_list.clear();

    bigint_r v1=1;
    bigint_r v2=2;
    bigint_r v3=3;

    uint256 s_v_256_1=bigint248_to_uint256(v1);
    uint256 s_r_256_1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint256 cm_256_1=single_d_single_v_cm(s_v_256_1,s_r_256_1);
   
    s_v_list.push_back(s_v_256_1);
    s_r_list.push_back(s_r_256_1);
    cm_list.push_back(cm_256_1);

    uint256 s_v_256_2=bigint248_to_uint256(v2);
    uint256 s_r_256_2=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a44");
    uint256 cm_256_2=single_d_single_v_cm(s_v_256_2,s_r_256_2);

    s_v_list.push_back(s_v_256_2);
    s_r_list.push_back(s_r_256_2);
    cm_list.push_back(cm_256_2);

    uint256 s_v_256_3=bigint248_to_uint256(v3);
    uint256 s_r_256_3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af65644");
    uint256 cm_256_3=single_d_single_v_cm(s_v_256_3,s_r_256_3);


    s_v_list.push_back(s_v_256_3);
    s_r_list.push_back(s_r_256_3);
    cm_list.push_back(cm_256_3);

    FieldT fv1,fv2,fv3;
    fv1=v1;
    fv2=v2;
    fv3=v3;
    s_sum=fv1+fv2+fv3;

    total_donator_v=36; //总捐款金额
    total_reward_v=12;  //总奖励金额

    bigint_r r_v=2;
    reward_v_256=bigint248_to_uint256(r_v);
    reward_r_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af22222");
    cm_reward=single_d_single_v_cm(reward_v_256,reward_r_256);
}

bool store_vk_reward(char * vf_name,r1cs_ppzksnark_verification_key<ppT> vk){
  ofstream out_vk(vf_name,ios::binary);
  if(!out_vk.is_open())
  {
    cout<<"store vk ,file path error"<<endl;
    return false;
  }
    
  out_vk<<vk;
  out_vk.flush();
  return true;
}

bool load_vk_reward(char * vf_name,r1cs_ppzksnark_verification_key<ppT>& vk){
  ifstream in_vk(vf_name,ios::binary);
  if(!in_vk.is_open())
  {
    cout<<"load vk ,file open error"<<endl;
    return false;
  }
  
  in_vk>>vk;
  in_vk.close();
  
  return true;
}
//获取证明
template<typename FieldT>
bool create_single_donator_reward_proof(std::vector<uint256> cm_list,//承诺列表
                                        std::vector<uint256> s_r_list,//随机树列表
                                        std::vector<uint256> s_v_list,//金额列表
                                        uint256 cm_r,   //承诺列表
                                        uint256 r_r_256,//随机树列表
                                        uint256 r_v_256,//金额列表
                                        FieldT t_d_v,   //总捐赠金额
                                        FieldT t_r_v,   //总奖励金额
                                        r1cs_ppzksnark_proof<ppT>& proof) {

    protoboard<FieldT> pb; 
    single_d_reward_gadget<FieldT> sd_reward_gadget(pb,d_count);

    sd_reward_gadget.generate_r1cs_constraints();
   
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

    if(!store_vk_reward(reward_vk_file,keypair.vk)){
        return false;
    }

    sd_reward_gadget.generate_r1cs_witness(
        cm_list,
        s_r_list,
        s_v_list,
        cm_r,
        r_r_256,
        r_v_256,
        t_d_v,
        t_r_v
    );
  
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();

    proof=r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);

    return true;
}

//构建公共参数
std::vector<FieldT> createPublicParam_reward(std::vector<uint256> cm_l
                                                ,uint256 cm_r//奖励承诺
                                                ,FieldT t_d_v//总捐款金额
                                                ,FieldT t_r_v//总奖励金额
                                                ){
    std::vector<FieldT> pi_v;
    
    //---------------验证cm-------------
    for(size_t j=0;j<d_count;j++){
        std::vector<bool> pi_cm_v=uint256_to_bool_vector(cm_l[j]);
        for(int i=0;i<256;i++){
            if(pi_cm_v[i]==1){
                pi_v.push_back(FieldT::one());
            }
            
            if(pi_cm_v[i]==0){
                pi_v.push_back(FieldT::zero());
            }
        }
    }
    
    //自己奖励的承诺，捐款者自己造，并公开
    std::vector<bool> pi_rcm_v=uint256_to_bool_vector(cm_r);
    for(int i=0;i<256;i++){

        if(pi_rcm_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
            
        if(pi_rcm_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
           
    }

    //---------------验证总和-------------
    pi_v.push_back(t_d_v);
    pi_v.push_back(t_r_v);

    return pi_v;
}
template<typename FieldT>
bool verify_single_donator_reward_proof(std::vector<FieldT> pi_v,r1cs_ppzksnark_proof<ppT> proof) {

    r1cs_ppzksnark_verification_key<ppT> vk;

    if(load_vk_reward(reward_vk_file,vk)){
        return r1cs_ppzksnark_verifier_strong_IC<ppT>(vk,pi_v,proof);
    }else{
        return false;
    }
   
}

template<typename FieldT>
void test_single_reward_list_step() {

    protoboard<FieldT> pb;

    std::vector<uint256> s_v_list;
    std::vector<uint256> s_r_list;
    std::vector<uint256> cm_list;

    bigint_r v1=1;
    bigint_r v2=2;
    bigint_r v3=3;

    uint256 s_v_256_1=bigint248_to_uint256(v1);
    uint256 s_r_256_1=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");
    uint256 cm_256_1=single_d_single_v_cm(s_v_256_1,s_r_256_1);
   
    s_v_list.push_back(s_v_256_1);
    s_r_list.push_back(s_r_256_1);
    cm_list.push_back(cm_256_1);

    uint256 s_v_256_2=bigint248_to_uint256(v2);
    uint256 s_r_256_2=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68a44");
    uint256 cm_256_2=single_d_single_v_cm(s_v_256_2,s_r_256_2);

   
    s_v_list.push_back(s_v_256_2);
    s_r_list.push_back(s_r_256_2);
    cm_list.push_back(cm_256_2);

    uint256 s_v_256_3=bigint248_to_uint256(v3);
    uint256 s_r_256_3=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af65644");
    uint256 cm_256_3=single_d_single_v_cm(s_v_256_3,s_r_256_3);

    s_v_list.push_back(s_v_256_3);
    s_r_list.push_back(s_r_256_3);
    cm_list.push_back(cm_256_3);

    size_t d_count=3;

    pb_variable<FieldT> sum;

    //single_d_sum_gadget<FieldT> sd_sum_gadget(pb,d_count,sum); 
    single_d_reward_gadget<FieldT> sd_reward_gadget(pb,d_count);

    sum.allocate(pb,"sum");
    FieldT fv1,fv2,fv3;
    fv1=v1;
    fv2=v2;
    fv3=v3;
    FieldT sum_ft=fv1+fv2+fv3;
    //pb.val(sum)=fv1+fv2+fv3;
   
    //回馈
    bigint_r r_v=2;
    uint256 r_v_256=bigint248_to_uint256(r_v);
    uint256 r_r_256=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af22222");
    uint256 cm_r=single_d_single_v_cm(r_v_256,r_r_256);

    FieldT t_d_v=36;//总捐款额
    FieldT t_r_v=12;//总反馈额

    cout<<"1"<<endl;

    cout<<"2"<<endl;
    
    sd_reward_gadget.generate_r1cs_constraints();
    cout<<"3"<<endl;

    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);

    sd_reward_gadget.generate_r1cs_witness(
        cm_list,
        s_r_list,
        s_v_list,
        cm_r,
        r_r_256,
        r_v_256,
        t_d_v,
        t_r_v
    );
    
    
    if(pb.is_satisfied()){
        cout << "Verified!" << endl;
    }else{
        cout << "Failed!" << endl;
    }
    
    
    auto pi = pb.primary_input();
    auto ai = pb.auxiliary_input();
    auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);
    

    //验证方
    //验证方，公共参数
    
    std::vector<FieldT> pi_v;
    
    //---------------验证cm-------------
    //自己捐款分量的承诺
    for(size_t j=0;j<d_count;j++){
        std::vector<bool> pi_cm_v=uint256_to_bool_vector(cm_list[j]);
        for(int i=0;i<256;i++){

            if(pi_cm_v[i]==1){
                pi_v.push_back(FieldT::one());
            }
            
            if(pi_cm_v[i]==0){
                pi_v.push_back(FieldT::zero());
            }
           
        }
    }

    //自己奖励的承诺，捐款者自己造，并公开
    std::vector<bool> pi_rcm_v=uint256_to_bool_vector(cm_r);
    for(int i=0;i<256;i++){

        if(pi_rcm_v[i]==1){
            pi_v.push_back(FieldT::one());
        }
            
        if(pi_rcm_v[i]==0){
            pi_v.push_back(FieldT::zero());
        }
           
    }

    //总捐款额
    pi_v.push_back(t_d_v);
    
    //总奖励额
    pi_v.push_back(t_r_v);


    if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi_v,proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    } 
}

template<typename FieldT>
void test_single_reward_list_step_fun() {

    create_sds_testdata_reward();

    //证明方
    r1cs_ppzksnark_proof<ppT> proof;
    if(!create_single_donator_reward_proof<FieldT>(cm_list,s_r_list,s_v_list
                                                ,cm_reward,reward_r_256,reward_v_256
                                                ,total_donator_v,total_reward_v,proof)){
        cout << "create proof failed!" << endl;
        return ;
    }

    //验证方,uint256 cm_r//奖励承诺 ,FieldT t_d_v//总捐款金额,FieldT t_r_v//总奖励金额
    if(verify_single_donator_reward_proof<FieldT>(createPublicParam_reward(cm_list,cm_reward
                                                                        ,total_donator_v,total_reward_v),proof)) {
        cout << "Verified!" << endl;
    } 
    else {
        cout << "Failed to verify!" << endl;
    } 
}




/*
 参考alt_bn128_init.hpp和alt_bn128_pp.hpp
 bigint_q和bigint_r相同
 alt_bn128_Fq和alt_bn128_Fr相同
 ，又等同 Fp_type和Fr_type
*/
/*
FieldT s3 = c1_tmp3 ^ Gsk.as_bigint();
FieldT m3 = c2_tmp3 * s3.inverse();

*/
//y^2=x^3+3;
/*
template<typename FieldT>
class Ecc_2apk_3v{

    int encode_size;
    public:

    FieldT alt_bn128_modulus_q;
    FieldT multiplicative_generator;
    
    void init(){
        encode_size=50;
        //bigint_q(...)也可以
        alt_bn128_modulus_q = bigint_r("21888242871839275222246405745257275088696311157297823662689037894645226208583");
        multiplicative_generator = bigint_r("3");
       
      }

    bool encode(FieldT m,FieldT *y,FieldT *x){
      FieldT x_t,y_t,y_t_2;

      for(int i=0;i<encode_size;i++){
          m=m+i;
          y_t_2=m^3+3;
          y_t=y_t_2;
        }
        

      return false;
    }
};
*/

//从IPList中读取用户的IP地址和端口号
//地址结构
struct Address
{
    string ip;
    uint16_t port;
};

//读取地址和端口号的函数。结果存入向量address中
class getAddress
{
public:
   vector<Address> address; //将读取的地址存入向量中
   bool getAddr(string inputfile)
   {
        bool flag = false; 
        ifstream ifs; 
        string lineBuffer = "";
        struct Address buf;
        //string ip; 
        //string port;  
        ifs.open(inputfile.c_str());
        if( !ifs.is_open() ) 
        {
            cout << "Fail to open the IP list" << endl;
            return false; 
        }
         // handle empty file 
        if ( getline(ifs, lineBuffer) ) 
        {
             istringstream iss(lineBuffer); 
             iss >> buf.ip;
             iss >> buf.port;  
             this->address.push_back(buf);
            //cout << ip << " " << port << endl;
        }
        else {
             cout << "This is an empty IP list" << endl;
             ifs.close();
             //cout << "inputFile has been closed" << endl; 
             return false; 
        }
        // continue to read data 
        while ( getline(ifs, lineBuffer) ) {
            istringstream iss(lineBuffer); 
            iss >> buf.ip;
            iss >> buf.port;  
            this->address.push_back(buf);
            //cout << ip << " " << port << endl;
            // count = count + 1;
        }
        ifs.close();
        //cout << "inputFile has been closed" << endl;
        //cout << "A number of " << count << " lines have been read" << endl;
        flag=true;
        return flag;
   }
};


//-----------------------捐款者功能部分------------------------------
//生成承诺(旧函数)
template<typename FieldT>
uint256 combine_donate(FieldT &v,bigint_r &r){
    FieldT rr;
    rr=r;
    uint256 left;
    uint256 right;
    uint256 out;
    unsigned char buf1[32];
    unsigned char buf2[32];
    fpToByte<FieldT>(v,buf1);
    fpToByte<FieldT>(rr,buf2);
    left=byteToUint256(buf1);
    right=byteToUint256(buf2);

    out=combine(left,right);

    return out;
}

//秘密共享信息结构
struct secret{
    unsigned int ident;       //用户身份标识符
    uint256 donateTry_share;  //秘密分割份额
    uint256 commitNonce;      //承诺随机数
    uint256 commitment;       //承诺
};

//两个全局向量
vector<secret> sendSecret;    //存储要发送给所有捐赠者的秘密分割信息
vector<secret> acceptSecret;  //存储所有捐赠者发送来的秘密分割信息

//秘密分割
//生成要发送给所有捐赠者的秘密分割信息，将其存入sendInfo
template<typename FieldT>
class secretDivide
{	
public: 
    unsigned int donate_try; //存储由捐款者输入的试捐金额
    unsigned int ident;       //存储由捐款者输入的身份标识符

    secretDivide(){}   //构造函数 
    
    //对输入的试捐金额进行分割，并且生成要发送给其余捐赠者的秘密分割信息
    void secretDivideFunc()  
    {
        //对分割的试捐金额进行验证，检验混淆后的分割金额之和是不是等于总的试捐金额
        FieldT sum_vertify=0;

        //将试捐金额平均分割
	    unsigned int mean;
        mean=(this->donate_try)/d_count; 
        cout<<"mean "<<mean<<endl;

        vector<bigint_r> bufnonce;  //存储D-1个混淆秘密分割的随机数
        bigint_r nonce_buf; 
        
        //为所有的捐赠者生成秘密分割信息，并放入向量sendSecret
	    for(int i=0;i<d_count;i++)
	    {
            struct secret buf;

            //---------1、身份标识--------
            buf.ident=this->ident; 
            
            //----------2、计算donateTry_share---------
            FieldT donateTry_share;  //FieldT类型的秘密分割份额
            donateTry_share=mean;   //先使用mean值对donateTry初始化
            if(i==d_count-1)
            {
                donateTry_share=this->donate_try-(d_count-1)*mean;  //对应不能整除的情况
                for(int j=0;j<d_count-1;j++)
                {
                    donateTry_share=donateTry_share-bufnonce.at(j);
                }
            }
            else{
                nonce_buf=get_random_bigint_248();
                bufnonce.push_back(nonce_buf);  //将生成的随机数存入向量中
                donateTry_share=donateTry_share+nonce_buf;   //对秘密分割金额进行混淆：均分的金额+随机数
            }

            //验证分量和
            sum_vertify=sum_vertify+donateTry_share;

            //将denoteTry转换为uint256型
            unsigned char bytebuf[32];
            fpToByte<FieldT>(donateTry_share,bytebuf);
            buf.donateTry_share=byteToUint256(bytebuf);
            
            //----------3、生成承诺随机数-------
            buf.commitNonce=bigint248_to_uint256(get_random_bigint_248());  //生成承诺随机数
            
            //----------4、生成承诺----------
            buf.commitment=single_d_single_v_cm(buf.donateTry_share,buf.commitNonce);
            
            sendSecret.push_back(buf);
            cout<<""<<buf.ident<<endl;
            cout<<""<<buf.donateTry_share.GetHex()<<endl;
            cout<<""<<buf.commitNonce.GetHex()<<endl;
            cout<<""<<buf.commitment.GetHex()<<endl;
        }
        
        cout<<"sum is "<<sum_vertify<<endl;
    }
};

sem_t s_to_a;

//接收其他捐赠者的秘密分割份额信息，存入向量acceptSecret
void* toAcceptShare(void* args)
{
     struct secret acceptbuf;
     int acceptfd,connfd;        
     socklen_t sendlen; 
     struct sockaddr_in acceptaddr,sendaddr;
     acceptfd = socket(AF_INET, SOCK_STREAM, 0); 
     bzero(&acceptaddr, sizeof(acceptaddr));
     acceptaddr.sin_family = AF_INET;
     acceptaddr.sin_addr.s_addr = htonl(INADDR_ANY);
     int ident=*((int*)args);
     getAddress addr;
     addr.getAddr(IPLIST);
     acceptaddr.sin_port = htons(addr.address.at(ident).port); //端口号与用户的身份一一对应
     if( bind(acceptfd, (struct sockaddr*) &acceptaddr, sizeof(acceptaddr))== -1 )  
     {  
        cout<<"From accept: bind error! "<<strerror(errno)<<errno<<endl;  
        exit(1);      
     }  
     cout<<"From accept: bind success"<<endl;  

     if( listen(acceptfd, d_count) == -1 )  
     {  
        cout<<"From accept: listen error! "<<strerror(errno)<<errno<<endl;     
        exit(1);  
     }  
     cout<<"From accept: listen......"<<endl;  
     
     sem_post (&s_to_a);

     for(;;)
     {
        sendlen = sizeof(sendaddr);
        if( (connfd = accept(acceptfd, (struct sockaddr*)&sendaddr, &sendlen)) == -1 )  
        {  
            cout<<"From accept: accept error! "<<strerror(errno)<<errno<<endl;
       	    exit(1);
        }  
        else
        {
            bzero(&acceptbuf,sizeof(acceptbuf));
            if(recv(connfd,&acceptbuf,sizeof(acceptbuf),0) == -1) 
            {
                 cout<<"From accept: recv error! "<<strerror(errno)<<errno<<endl;  
                 exit(1); 
            }
           
            acceptSecret.push_back(acceptbuf); //是乱序存入的
            cout<<"From accept: Have accepted the secret from "<<acceptbuf.ident<<endl;
            cout<<acceptbuf.ident<<endl;
            cout<<acceptbuf.donateTry_share.GetHex()<<endl;
            cout<<acceptbuf.commitNonce.GetHex()<<endl;
            cout<<acceptbuf.commitment.GetHex()<<endl;
            close(connfd);
        }
    }
     return (void*)0;
}

//对试捐金额进行秘密分割，并且将秘密分割份额发送给其余捐赠者
template<typename FieldT>
void shareSecret(unsigned int ident)
{
    cout<<"--------------Begin to donate(try)-------------"<<endl;
    sem_init (&s_to_a, 0, 0);

    cout<<"Please enter your donated amount: ";
    unsigned int donate_try; 
    cin>>donate_try;
    //generate secret division
    secretDivide<FieldT> secret_divide;
    secret_divide.donate_try=donate_try;
    secret_divide.ident=ident;
    secret_divide.secretDivideFunc();

    //begin to send and accept secret tuple
    //First,read address from ip list
    getAddress addr;
    addr.getAddr(IPLIST);
    //then create another thread for accepting other donors' secret tuples
    pthread_t threadId;
    int ret;
    ret = pthread_create(&threadId, NULL,toAcceptShare,(void*)&ident);
    if(ret != 0)
    {
        cout<< "create thread error!error is: "<<strerror(errno)<<errno<<endl;
    }

    sem_wait (&s_to_a);
    sem_destroy (&s_to_a);
    sleep(1);
    //send tuple to other donors at the same time 
    
    cout<<"Would you start denoting?/YES(Y),NO(N)"<<endl;
    while(1)
    {
        char agree;
        cin>>agree;
        if(agree=='Y') break;
    }
    int sendfd;
    //sendfd = socket(AF_INET, SOCK_STREAM, 0);   
   
    for(int i=0;i<d_count;i++)
    {
       sendfd = socket(AF_INET, SOCK_STREAM, 0);
   	   struct sockaddr_in acceptaddr;  
   	   bzero(&acceptaddr, sizeof(acceptaddr));

       //get destination's ip and port number
       string IP=addr.address.at(i).ip;  
       char *ips=&IP[0];  //convert string to char*
       uint16_t port=addr.address.at(i).port;
             
       //initialize the destination socket's sockaddr_in
   	   acceptaddr.sin_family = AF_INET;
       acceptaddr.sin_port = htons(port);  
   	   if(inet_aton(ips, &acceptaddr.sin_addr) <= 0)
   	   {
       	 	cout<<"From sender:   inet_aton error! "<<strerror(errno)<<errno<<endl;                        
        	exit(0);
   	   }
       //begin to connect to server(the receiver)
   	   if(connect(sendfd, (struct sockaddr*)& acceptaddr, sizeof(acceptaddr)) < 0)
       {   
            cout<<"From sender:   connect error! "<<strerror(errno)<<errno<<endl;
            cout<<"From sender:   connect error with "<<i<<endl;
            exit(0);
       }
       else
       {
            cout<<"From sender:   connect success with "<<i<<endl;
       }
       //begin to send information
       struct secret sendline;
      
       memcpy((unsigned char*)&sendline, (unsigned char*)&sendSecret.at(i),sizeof(secret));
      
       if (send(sendfd,&sendline,sizeof(secret), 0)<0)  
       {  
            cout<<"From sender:   send error! "<<strerror(errno)<<errno<<endl;  
            exit(1);  
       } 
       else
       {
            cout<<"From sender:   send to "<<i<<" success!"<<endl;
       }
       close(sendfd);
  	}
}

//收到各个捐赠者的秘密后，统计各个分值分量之和，并公布计算的和，和的零知识证明，以及收到的所有承诺
//定义一个结构体，存储公布的有关“秘密份额份额的和”的信息
template<typename FieldT>
struct secret_sum_and_proof
{
    unsigned int ident;  //生成这部分秘密分割份额求和，以及其证明和承诺的捐赠者的身份
    FieldT sum;          //秘密分割份额的和
    //uint256 zeroProve;   //这部分的零知识证明
    r1cs_ppzksnark_proof<ppT> zeroProve;
    vector<uint256> commitment;   //将收到的所有秘密分割份额的承诺都存入此向量中
};

//计算收到的秘密分割份额的和，并且将其写入文件
template<typename FieldT>
void gen_sum_and_proof(unsigned int ident)
{
    struct secret_sum_and_proof<FieldT> sum_publish; //需要写入文件的结构体
    
    //1、当前捐赠者身份标识
    sum_publish.ident=ident;
    sum_publish.sum=0;
    for(int i=0;i<d_count;i++)
    {
    //2、对收到的秘密分割份额进行求和
        //首先将uint256型的数据转换为FieldT，以便进行求和计算
        unsigned char bytebuf[32];
        FieldT donateTry_share_fp;  //存储转换格式后的秘密分割信息
        //HexStrToByte(acceptSecret.at(i).donateTry_share.GetHex(),bytebuf,64);
        //donateTry_share_fp = byteToFp<FieldT>(bytebuf);
        donateTry_share_fp=hexStrToFp<FieldT>(acceptSecret.at(i).donateTry_share.GetHex());
        sum_publish.sum = sum_publish.sum + donateTry_share_fp; //求和
    //4、将收到的承诺放入结构体的向量中
        sum_publish.commitment.push_back(acceptSecret.at(i).commitment);  //将acceptSecret中的承诺存入此向量
    }
       
    //unsigned char bytebuf[32];
    //fpToByte<FieldT>(sum_temp,bytebuf);
    //sum_publish.sum=byteToUint256(bytebuf);
    //3、生成和的零知识证明
    for(int i=0;i<d_count;i++)
    {
        cm_list.push_back(acceptSecret.at(i).commitment);
        s_r_list.push_back(acceptSecret.at(i).commitNonce);
        s_v_list.push_back(acceptSecret.at(i).donateTry_share);
    }
    if(!create_single_donator_sum_proof<FieldT>(cm_list,s_r_list,s_v_list,sum_publish.sum,sum_publish.zeroProve)){
        cout << "create proof failed!" << endl;
        return ;
    }
    
    //下面，将生成的sum_publish写入文件中，以便捐赠平台验证
    //这里将不同捐赠者的秘密分割份额存入不同的文件,文件名格式为：sum_prove_身份标识
    ostringstream fileName;
    fileName << "../sum_prove_" <<ident<<".txt"<< endl;
    ofstream out(fileName.str());
    if(!out.is_open())
    {
        cout<<"file path error!!"<<endl;
        return;
    }
    out<<sum_publish.ident<<"\t"<<sum_publish.sum<<"\t"<<sum_publish.zeroProve<<"\t";
    for(int j=0;j<d_count;j++)
    {
        out<<sum_publish.commitment.at(j).GetHex()<<"\t";
    }
    out.close();
}

//监听捐赠平台的消息，若有捐款请求到达，返回请求的捐款金额；
unsigned int getDonateReq()
{
    //定义一个套接字，用来接收捐赠平台的捐款请求信息;
}

//领取奖励
void getReward()
{
    
}

//-----------------------矿工功能部分------------------------------
//验证部分和
template<typename FieldT>
void verify_sum_proof()
{
    //对每个捐赠者的证明进行验证
    for(int i=0;i<d_count;i++)
    {
        string buffer = "";  
        ostringstream fileName;
        fileName << "../sum_prove_" <<i<<".txt"<< endl;
        ifstream in(fileName.str());
        
        //从文件中读取捐款者用户标识，部分和，部分和的证明，承诺列表
        unsigned int ident;    
        FieldT sum;      
        r1cs_ppzksnark_proof<ppT> proof;
        uint256 commit;
        string com_hex_str;
        vector<uint256> cm_list;

        if(!in.is_open())
        {
           cout<<"file path error!!"<<endl;
           return;
        }
        
        if ( getline(in, buffer) ) 
        {
            istringstream iss(buffer); 
            iss>>ident;
            iss>>sum;
            iss>>proof; 
            //读取承诺列表，将所有承诺放入cm_list
            for(int j=0;j<d_count;j++)
            {
                iss>>com_hex_str;
                //com_hex_str:string to char,char to byte,byte to uint256 
                const char *com_char=NULL;
                unsigned char *com_byte=NULL;
                com_char=com_hex_str.c_str();
                HexStrToByte(com_char,com_byte,strlen(com_char));
                commit=byteToUint256(com_byte);
                cm_list.push_back(commit);
            }
            cout<<ident<<"\t";//<<sum_str<<"\t"<<endl;
            cout<<sum<<endl;
        }
        else 
        {
            cout << "This is an empty file" << endl;
            in.close();
            cout << "inputFile has been closed" << endl; 
            return; 
        }
        //开始验证
        if(verify_single_donator_sum_proof<FieldT>(createPublicParam(cm_list,sum),proof)) {
            cout << "Donator "<<ident<<": verify pass!" << endl;
        } 
        else {
            cout << "Donator "<<ident<<": verify error!" << endl;
        } 

    }
}

//验证礼物
void verify_reward_proof(){


}

int main(void)
{
    ppT::init_public_params();
    verify_sum_proof<FieldT>();
    
    return 0;  
}

/*
int main(void)
{
    ppT::init_public_params();
   
    //test_single_d_single_v_cm<FieldT>();
    //test_single_sum<FieldT>();
    // test_bit_to_val<FieldT>();
    //test_single_sum_list<FieldT>();

    //test_single_sum_list_step<FieldT>();
    
    //test_single_reward_list<FieldT>();

    //test_single_reward_list_step<FieldT>();

    test_single_reward_list_step_fun<FieldT>();

    //test_sum_gadget<FieldT>();
    //test_tranlate<FieldT>();

    //test_sum_gadget_b<FieldT>();

    //test_single_d_single_v_cm_bigint<FieldT>();

    //test_sum_gadget_b_list<FieldT>();
    //return 0;
}
*/
/*
int main(void)
{
     ppT::init_public_params();
   
    FieldT g = bigint_r("12");
    FieldT one = bigint_r("1");
   

    FieldT q=bigint_r("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    FieldT q1=bigint_r("21888242871839275222246405745257275088548364400416034343698204186575808495616");

   
    cout << (g ^ q1.as_bigint())<<endl;

    //q=q+one;
    (q).print();
    (q+2).print();
    //(x_max4-one).print();  

    return 0;
}
*/