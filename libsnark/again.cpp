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

uint256 one_hash(const unsigned char *data, size_t len){
    CSHA256 hasher;
    hasher.Write(data, len);

    uint256 result;
    hasher.Finalize(result.begin());

    return result;
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

        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        hasher1.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block1->bits,
            *intermediate_hash,
        ""));
        pb_variable_array<FieldT> intermediate_block;
        intermediate_block.insert(intermediate_block.end(), (*intermediate_hash).bits.begin(), (*intermediate_hash).bits.end());
        //H(H(a_pk,v),r)
        block2.reset(new block_variable<FieldT>(pb, {
            intermediate_block,
            r
        }, ""));
        hasher2.reset(new sha256_compression_function_gadget<FieldT>(
            pb,
            IV,
            block2->bits,
            *result,
        ""));
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

void byteToint64(uint64_t &i64,unsigned char* buf){
    memcpy(&i64,buf,8);
}

uint256 byteToUint256(unsigned char *bytebuf){
    char hex[65];
    hex[64]=0;
    Hex2Str((char*)bytebuf,hex,32);
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
    
        /*cout<<"before encrypt:"<<endl;
        cout<<apk_s.ToString()<<endl;
        cout<<apk_r.ToString()<<endl;

        cout<<v_1<<endl;
        cout<<v_2<<endl;*/

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
        /*cout<<"11"<<endl;*/
        for(size_t i=0;i<TREE_DEEPTH;i++){
           hasher[i].generate_r1cs_constraints();
           selector[i].generate_r1cs_constraints();
        } 
        /*cout<<"22"<<endl;*/
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
       /*cout<<"33"<<endl;*/

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
        /*cout<<"ask,apk,prf"<<endl;*/

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
        /*cout<<"comment"<<endl;*/

        //sn
        sn_gad.reset(new sn_gadget<FieldT>(
            pb,
            a_sk_s->bits,
            r_old->bits,
            sn_old
        ));
        /*cout<<"sn"<<endl;*/

        //merkle tree
        
        tree_gad_cm.reset(new tree_gadget<FieldT>(pb,root_cm,commitment_old,""));
        tree_gad_apk_s.reset(new tree_gadget<FieldT>(pb,root_apk_s,a_pk_s,""));
        tree_gad_apk_r.reset(new tree_gadget<FieldT>(pb,root_apk_r,a_pk_r,""));
        /*cout<<"tree"<<endl;*/

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
                /*cout<<"elg"<<endl;*/
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
/*template<typename FieldT>
void out_proof()
{
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
    cout<<proof<<endl;
}
*/
int main(void)
{
    ppT::init_public_params();
    using FieldT = ppT::Fp_type;
    inhibit_profiling_info = true;
    inhibit_profiling_counters = true;
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

    /*cout<<"1"<<endl;*/

    joinsplit_gadget_z<FieldT> js_gad_z(pb,g,Gpk);      
    //joinsplit_gadget_z<FieldT> js_gad_z(pb,g);   
    /*cout<<"2"<<endl;*/
    

    js_gad_z.generate_r1cs_constraints();
    /*cout<<"3"<<endl;*/
    //产生密钥对
    auto cs = pb.get_constraint_system();
    auto keypair = r1cs_ppzksnark_generator<ppT>(cs);
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
    cout<<proof<<endl;

}
