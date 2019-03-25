#include <ctime>
#include "common/default_types/ec_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

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

#include "interface.h"

using namespace std;
using namespace libsnark;
using namespace libff;

using ppT = default_r1cs_ppzksnark_pp; 
using FieldT = ppT::Fp_type;

using namespace msk;

void isSnarkOk() {
    std::cout<<"\n\n\nNNNNNNMMMMMMMMSSSSSSSSLLLLLLLLL\n\n\n\n";
}

uint256 one_hash(const unsigned char *data, size_t len) {
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

std::vector<bool> msk::uint256_to_bool_vector(uint256 input) {
    std::vector<unsigned char> input_v(input.begin(), input.end());
    return msk::convertBytesVectorToVector(input_v);
}

std::vector<bool> uint64_to_bool_vector(uint64_t input) {
    auto num_bv = msk::convertIntToVectorLE(input);
    
    return msk::convertBytesVectorToVector(num_bv);
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

uint256 prf(uint256 a_sk){
    CSHA256 hasher;
   
    uint256 result;

    //H(a_sk a_sk)
    hasher.Write(a_sk.begin(), 32);
    hasher.Write(a_sk.begin(), 32);
    hasher.FinalizeNoPadding(result.begin());
  
    return result;
}

uint256 sn(uint256 a_sk,uint256 r){
    CSHA256 hasher;
  
    uint256 result;

    //H(a_sk r)
    hasher.Write(a_sk.begin(), 32);
    hasher.Write(r.begin(), 32);
    hasher.FinalizeNoPadding(result.begin());
  
    return result;
}

uint256 cm(uint256 a_pk, int64_t v, uint256 r) {
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

void outBoolVector(std::vector<bool> &v){
     for(size_t i=0;i<v.size();i++){

        cout<<v[i]<<" , ";
    }
    cout<<endl;
}

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

void byteToBigint(bigint_r &b,unsigned char *bytebuf){
    memcpy(&b.data[0],bytebuf,bigint_len);
}

void byteToint64(uint64_t &i64,unsigned char* buf){
    memcpy(&i64,buf,8);
}

uint256 byteToUint256(unsigned char *bytebuf){
    char hex[65];
    hex[64]=0;
    msk::Hex2Str((char*)bytebuf,hex,32);
    return uint256S(hex);
}

MerkleTreePath getMerkleTreePath_apk_s(uint256 ask_s, uint256 apk_r){
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

MerkleTreePath getMerkleTreePath_apk_r(uint256 apk_r){

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


MerkleTreePath getMerkleTreePath(uint256 ask_s,uint64_t v_1,uint256 old_r)
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


MerkleTreePath getMerkleTreePath_lb(uint256 ask_s,uint64_t v1,uint64_t v2,uint256 old_r){

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

char g_c[45]="11112222333344445555666677778888999900001111";
char sk[11]="1234567891";    
FieldT g=bigint_r(msk::g_c);
FieldT Gsk= bigint_r(msk::sk) ;//私钥
FieldT Gpk= msk::g ^ msk::Gsk.as_bigint();
uint256 z;
uint256 Spk;   
int64_t n=0;

std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )  
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

std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )  
{
    if (strPemFileName.empty() || strData.empty())  
    {  
        assert(false);  
        return "";  
    }  
    FILE* hPriKeyFile = fopen(strPemFileName.c_str(),"rb");  
    if( hPriKeyFile == NULL )  
    {  
        assert(false);  
        return "";  
    }  
    std::string strRet;  
    RSA* pRSAPriKey = RSA_new();  
    if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)  
    {  
        assert(false);  
        return "";  
    }  
    int nLen = RSA_size(pRSAPriKey);  
    char* pDecode = new char[nLen+1];  
  
    int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);  
    if(ret >= 0)  
    {  
        strRet = std::string((char*)pDecode, ret);  
    }  
    delete [] pDecode;  
    RSA_free(pRSAPriKey);  
    fclose(hPriKeyFile);  
    CRYPTO_cleanup_all_ex_data();   
    return strRet;  
} 

msgMintRequest makeMintRequest(uint256 Usk/*用户私钥*/,uint256 p/*随机数*/, int64_t v/*金额*/)
{
    msgMintRequest tmp1;
    tmp1.Upk=msk::prf(Usk);
    tmp1.kmint=msk::cm(tmp1.Upk,v,p);
    tmp1.v=v;
    tmp1.p=p;
    return tmp1;
}

msgMint makeMsgMint(uint256 kmint,int64_t v,uint256 upk)
{
    msgMint tmp2;
    string k;
    k=kmint.ToString();
    Elgamal_2apk_3v<FieldT> G1;
    G1.setG(msk::g);
    G1.setPk(msk::Gpk);
    G1.encrypt(upk,msk::z,v,msk::n,msk::n);/*z，n为数据格式不同的0，前面有定义*/
    G1.getEncryptedData(tmp2.data);//用setEncryptdata函数即可解密数据
    tmp2.Sigpub = msk::EncodeRSAKeyFile( "rsa_public_key.pem", k );//基于openssl库的公钥加密，用私钥解密。
    return tmp2;
}