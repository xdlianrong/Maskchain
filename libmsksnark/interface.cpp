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
#include <cstdint>

#include "interface.h"

using namespace std;
using namespace libsnark;
using namespace libff;

using ppT = default_r1cs_ppzksnark_pp; 
using FieldT = ppT::Fp_type;

using namespace msk;
/*
void isSnarkOk() {
    std::cout<<"\n\n\nNNNNNNMMMMMMMMSSSSSSSSLLLLLLLLL\n\n\n\n";
}
*/
uint256 one_hash(const unsigned char *data, size_t len) {
    CSHA256 hasher;
    hasher.Write(data, len);

    uint256 result;
    hasher.Finalize(result.begin());

    return result;
}




std::vector<bool> msk::uint256_to_bool_vector(uint256 input) {
    std::vector<unsigned char> input_v(input.begin(), input.end());
    return msk::convertBytesVectorToVector(input_v);
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
