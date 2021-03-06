/*
    This file is part of cpp-ethereum.
    cpp-ethereum is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    cpp-ethereum is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <boost/lexical_cast.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/algorithm/string.hpp>

#include "Transaction.h"

#include <libdevcore/Log.h>
#include <libethcore/Common.h>
#include <libevm/VMFace.h>

#include <json/json.h>
#include <functional>

#include <iostream>
#include <string>
#include <stdio.h>
#include <ostream>
#include <fstream>
#include <sstream>
#include <signal.h>
#include <stdlib.h>

namespace Json
{
    class Value;
}

namespace msk
{
class mskVerifier {
public:
    mskVerifier() {}

    mskVerifier(std::string _mskTxS) {
        std::string mskTxS;
        int decodeStatus = Base64Decode(_mskTxS, &mskTxS);
        if(decodeStatus==0) {std::cout<<"\n\n-----FAILED : MSKMSG DECODE-----\n\n";}
        bool verifyStatus = strTxToStructTx(mskTxS);
    }

    ~mskVerifier() {
        std::cout<<std::endl<<"mskVerifier Deconstructed"<<std::endl;
    }

    std::string exec(const char* cmd) {
        FILE* pipe = popen(cmd, "r");
        if (!pipe) return "ERROR";
        char buffer[128];
        std::string result = "";
        while(!feof(pipe)) {
            if(fgets(buffer, 128, pipe) != NULL)
            result += buffer;
        }
        pclose(pipe);
        return result;
    }

    // 这是一个用 boost 拼出来的 base64。
    // 可是 eth 自己本来也有 base64，要不要统一一下？
    bool Base64Decode( const std::string & input, std::string * output ) {
        typedef boost::archive::iterators::transform_width<boost::archive::iterators::binary_from_base64<std::string::const_iterator>, 8, 6> Base64DecodeIterator;
        std::stringstream result;
        try {
            copy( Base64DecodeIterator( input.begin() ), Base64DecodeIterator( input.end() ), std::ostream_iterator<char>( result ) );
        } catch ( ... ) {
            return false;
        }
        *output = result.str();
        return output->empty() == false;
    }

    bool strTxToStructTx(std::string _mskTxS) {
        std::string mskTxS;
        int decodeStatus = Base64Decode(_mskTxS, &mskTxS);
        //std::cout<<"\n\n\n\n\nFLAG  666\n\n\n\n\n\n\n\n\n";
        if(decodeStatus==0) {std::cout<<"\n\n-----FAILED : MSKMSG DECODE-----\n\n";}
        //std::cout<<mskTxS;

        if(mskTxS[0]=='M') {       // txType+||+kmintS+||+dataS+||+SigpubS
            mskTxS = mskTxS.substr(3);
            std::string kmintS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string dataS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string SigpubS = mskTxS.substr(0, mskTxS.length());
            this->m_msgMint.kmint = uint256S(kmintS);
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(dataS[i]);
                m_msgMint.data[i] = intToUsgnChar(tmp);
            }
            this->m_msgMint.Sigpub = SigpubS;
            // DEBUGGING!!!
            return 1;
            // 这下面一个丧心病狂的字符串处理，大概就是拆msk交易吧
        } else if(mskTxS[0]=='Z') { // txType+||+SNoldS+||+krnewS +||+ksnewS +||+proofS +||+dataS +||+\
                                        vkS +||+c_rtS +||+s_rtS+||+r_rtS;
            mskTxS = mskTxS.substr(3);
            std::string SNoldS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string krnewS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string ksnewS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string proofS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string dataS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string vkS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string c_rtS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string s_rtS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string r_rtS = mskTxS.substr(0, mskTxS.length());
/*
//==============================================================================
            std::fstream file; // 定义fstream对象
            file.open("./executiveSNold", std::ios::out); // 打开文件，并绑定到ios::out对象
            //string line;
            // 先获取cout、cin的buffer指针
            std::streambuf *stream_buffer_cout = std::cout.rdbuf();
            // 获取文件的buffer指针
            std::streambuf *stream_buffer_file = file.rdbuf();
            // cout重定向到文件
            std::cout.rdbuf(stream_buffer_file);
            std::cout<<SNoldS;
            // cout重定向到cout，即输出到屏幕
            std::cout.rdbuf(stream_buffer_cout);
            file.close(); // 关闭文件

            std::fstream file2; // 定义fstream对象
            file2.open("./executiveKrnew", std::ios::out); // 打开文件，并绑定到ios::out对象
            std::streambuf *stream_buffer_cout2 = std::cout.rdbuf();
            std::streambuf *stream_buffer_file2 = file2.rdbuf();
            std::cout.rdbuf(stream_buffer_file2);
            std::cout<<krnewS;
            std::cout.rdbuf(stream_buffer_cout2);
            file2.close(); // 关闭文件

            std::fstream file3; // 定义fstream对象
            file3.open("./executiveKsnew", std::ios::out); // 打开文件，并绑定到ios::out对象
            std::streambuf *stream_buffer_cout3 = std::cout.rdbuf();
            std::streambuf *stream_buffer_file3 = file3.rdbuf();
            std::cout.rdbuf(stream_buffer_file3);
            std::cout<<ksnewS;
            std::cout.rdbuf(stream_buffer_cout3);
            file3.close(); // 关闭文件

            std::fstream file4; // 定义fstream对象
            file4.open("./executivepi", std::ios::out); // 打开文件，并绑定到ios::out对象
            std::streambuf *stream_buffer_cout4 = std::cout.rdbuf();
            std::streambuf *stream_buffer_file4 = file4.rdbuf();
            std::cout.rdbuf(stream_buffer_file4);
            std::cout<<proofS;
            std::cout.rdbuf(stream_buffer_cout4);
            file4.close(); // 关闭文件

            std::fstream file5; // 定义fstream对象
            file5.open("./executiveData", std::ios::out); // 打开文件，并绑定到ios::out对象
            std::streambuf *stream_buffer_cout5 = std::cout.rdbuf();
            std::streambuf *stream_buffer_file5 = file5.rdbuf();
            std::cout.rdbuf(stream_buffer_file5);
            std::cout<<dataS;
            std::cout.rdbuf(stream_buffer_cout5);
            file5.close(); // 关闭文件

            std::fstream file6; // 定义fstream对象
            file6.open("./executiveVk", std::ios::out); // 打开文件，并绑定到ios::out对象
            std::streambuf *stream_buffer_cout6 = std::cout.rdbuf();
            std::streambuf *stream_buffer_file6 = file6.rdbuf();
            std::cout.rdbuf(stream_buffer_file6);
            std::cout<<vkS;
            std::cout.rdbuf(stream_buffer_cout6);
            file6.close(); // 关闭文件

            std::fstream file7; // 定义fstream对象
            file7.open("./executiveC", std::ios::out); // 打开文件，并绑定到ios::out对象
            std::streambuf *stream_buffer_cout7 = std::cout.rdbuf();
            std::streambuf *stream_buffer_file7 = file7.rdbuf();
            std::cout.rdbuf(stream_buffer_file7);
            std::cout<<c_rtS;
            std::cout.rdbuf(stream_buffer_cout7);
            file7.close(); // 关闭文件

            std::fstream file8; // 定义fstream对象
            file8.open("./executiveS", std::ios::out); // 打开文件，并绑定到ios::out对象
            std::streambuf *stream_buffer_cout8 = std::cout.rdbuf();
            std::streambuf *stream_buffer_file8 = file8.rdbuf();
            std::cout.rdbuf(stream_buffer_file8);
            std::cout<<s_rtS;
            std::cout.rdbuf(stream_buffer_cout8);
            file8.close(); // 关闭文件

            std::fstream file9; // 定义fstream对象
            file9.open("./executiveR", std::ios::out); // 打开文件，并绑定到ios::out对象
            std::streambuf *stream_buffer_cout9 = std::cout.rdbuf();
            std::streambuf *stream_buffer_file9 = file9.rdbuf();
            std::cout.rdbuf(stream_buffer_file9);
            std::cout<<r_rtS;
            std::cout.rdbuf(stream_buffer_cout9);
            file9.close(); // 关闭文件
//=============================================================================
*/
            this->m_transferZero.SNold = uint256S(SNoldS);
            this->m_transferZero.krnew = uint256S(krnewS);
            this->m_transferZero.ksnew = uint256S(ksnewS);
            this->m_transferZero.pi = stringToProof(proofS);
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(dataS[i]);
                m_transferZero.data[i] = intToUsgnChar(tmp);
            }
            this->m_transferZero.vk = stringToVerifyKey(vkS);
            this->m_transferZero.c_rt = uint256S(c_rtS);
            this->m_transferZero.s_rt = uint256S(s_rtS);
            this->m_transferZero.r_rt = uint256S(r_rtS);

            return transferZeroVerify<libsnark::default_r1cs_ppzksnark_pp::Fp_type>(this->m_transferZero.SNold,\
                                        this->m_transferZero.krnew,\
                                        this->m_transferZero.ksnew, this->m_transferZero.data,\
                                        this->m_transferZero.pi, this->m_transferZero.vk, \
                                        this->m_transferZero.c_rt, this->m_transferZero.s_rt, this->m_transferZero.r_rt);

        } else if(mskTxS[0]=='O') { //txType+||+SNoldS+||+krnewS +||+proofS +||+dataS +||+\
                                       vkS +||+c_rtS +||+s_rtS+||+r_rtS;
            mskTxS = mskTxS.substr(3);
            std::string SNoldS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string krnewS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string proofS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string dataS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string vkS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string c_rtS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string s_rtS = mskTxS.substr(0, mskTxS.find("||", 0));
            mskTxS = mskTxS.substr(mskTxS.find("||", 0)+2);
            std::string r_rtS = mskTxS.substr(0, mskTxS.length());

            this->m_transferOne.SNold = uint256S(SNoldS);
            this->m_transferOne.krnew = uint256S(krnewS);
            this->m_transferOne.pi = stringToProof(proofS);
            for(int i=0; i<192; i++) {
                int tmp = boost::lexical_cast<int>(dataS[i]);
                m_transferOne.data[i] = intToUsgnChar(tmp);
            }
            this->m_transferOne.vk = stringToVerifyKey(vkS);
            this->m_transferOne.c_rt = uint256S(c_rtS);
            this->m_transferOne.s_rt = uint256S(s_rtS);
            this->m_transferOne.r_rt = uint256S(r_rtS);
            //DEBUG!!!!!
            return 1;
        } else {
            std::cout<<"\n FAILED!!  strTxToStructTx and Verify \n";
            return 0;
        }
    }

    int usgnCharToInt(unsigned char _uc) {
        int tmp = _uc;
        return tmp;
    }

    unsigned char intToUsgnChar(int _int) {
        unsigned char tmp;
        tmp = _int;
        return tmp;
    }

    libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> stringToProof(std::string proofS) {
        libsnark::r1cs_ppzksnark_proof<libsnark::default_r1cs_ppzksnark_pp> tmpProof;
        std::stringstream ss("");
        ss<<proofS;
        ss>>tmpProof;
        return tmpProof;
    }

    libsnark::r1cs_ppzksnark_verification_key<libsnark::default_r1cs_ppzksnark_pp> stringToVerifyKey(std::string vkS) {
        libsnark::r1cs_ppzksnark_verification_key<libsnark::default_r1cs_ppzksnark_pp> tmpVk;
        std::stringstream ss("");
        ss<<vkS;
        ss>>tmpVk;
        return tmpVk;
    }

private:
    msgMint m_msgMint;
    transferZero m_transferZero;
    transferOne m_transferOne;
};

}

namespace dev
{

class OverlayDB;

namespace eth
{

class State;
class Block;
class BlockChain;
class ExtVM;
class SealEngineFace;
struct Manifest;

class StandardTrace
{
public:
    struct DebugOptions
    {
        bool disableStorage = false;
        bool disableMemory = false;
        bool disableStack = false;
        bool fullStorage = false;
    };

    StandardTrace();
    void operator()(uint64_t _steps, uint64_t _PC, Instruction _inst, dev::bigint _newMemSize,
        dev::bigint _gasCost, dev::bigint _gas, VMFace const* _vm, ExtVMFace const* _extVM);

    void setShowMnemonics() { m_showMnemonics = true; }
    void setOptions(DebugOptions _options) { m_options = _options; }

    Json::Value jsonValue() const { return m_trace; }
    std::string styledJson() const;
    std::string multilineTrace() const;

    OnOpFunc onOp()
    {
        return [=](uint64_t _steps, uint64_t _PC, Instruction _inst, dev::bigint _newMemSize,
                   dev::bigint _gasCost, dev::bigint _gas, VMFace const* _vm, ExtVMFace const* _extVM) {
            (*this)(_steps, _PC, _inst, _newMemSize, _gasCost, _gas, _vm, _extVM);
        };
    }

private:
    bool m_showMnemonics = false;
    std::vector<Instruction> m_lastInst;
    Json::Value m_trace;
    DebugOptions m_options;
};

/**
 * @brief Message-call/contract-creation executor; useful for executing transactions.
 *
 * Two ways of using this class - either as a transaction executive or a CALL/CREATE executive.
 *
 * In the first use, after construction, begin with initialize(), then execute() and end with finalize(). Call go()
 * after execute() only if it returns false.
 *
 * In the second use, after construction, begin with call() or create() and end with
 * accrueSubState(). Call go() after call()/create() only if it returns false.
 *
 * Example:
 * @code
 * Executive e(state, blockchain, 0);
 * e.initialize(transaction);
 * if (!e.execute())
 *    e.go();
 * e.finalize();
 * @endcode
 */
class Executive
{
public:
    /// Simple constructor; executive will operate on given state, with the given environment info.
    Executive(State& _s, EnvInfo const& _envInfo, SealEngineFace const& _sealEngine, unsigned _level = 0): m_s(_s), m_envInfo(_envInfo), m_depth(_level), m_sealEngine(_sealEngine) {}

    /** Easiest constructor.
     * Creates executive to operate on the state of end of the given block, populating environment
     * info from given Block and the LastHashes portion from the BlockChain.
     */
    Executive(Block& _s, BlockChain const& _bc, unsigned _level = 0);

    /** LastHashes-split constructor.
     * Creates executive to operate on the state of end of the given block, populating environment
     * info accordingly, with last hashes given explicitly.
     */
    Executive(Block& _s, LastBlockHashesFace const& _lh, unsigned _level = 0);

    /** Previous-state constructor.
     * Creates executive to operate on the state of a particular transaction in the given block,
     * populating environment info from the given Block and the LastHashes portion from the BlockChain.
     * State is assigned the resultant value, but otherwise unused.
     */
    Executive(State& io_s, Block const& _block, unsigned _txIndex, BlockChain const& _bc, unsigned _level = 0);

    Executive(Executive const&) = delete;
    void operator=(Executive) = delete;

    /// Initializes the executive for evaluating a transaction. You must call finalize() at some point following this.
    void initialize(bytesConstRef _transaction) { initialize(Transaction(_transaction, CheckTransaction::None)); }
    void initialize(Transaction const& _transaction);
    /// Finalise a transaction previously set up with initialize().
    /// @warning Only valid after initialize() and execute(), and possibly go().
    /// @returns true if the outermost execution halted normally, false if exceptionally halted.
    bool finalize();
    /// Begins execution of a transaction. You must call finalize() following this.
    /// @returns true if the transaction is done, false if go() must be called.
    bool execute();
    /// @returns the transaction from initialize().
    /// @warning Only valid after initialize().
    Transaction const& t() const { return m_t; }
    /// @returns the log entries created by this operation.
    /// @warning Only valid after finalise().
    LogEntries const& logs() const { return m_logs; }
    /// @returns total gas used in the transaction/operation.
    /// @warning Only valid after finalise().
    u256 gasUsed() const;

    owning_bytes_ref takeOutput() { return std::move(m_output); }

    /// Set up the executive for evaluating a bare CREATE (contract-creation) operation.
    /// @returns false iff go() must be called (and thus a VM execution in required).
    bool create(Address const& _txSender, u256 const& _endowment, u256 const& _gasPrice, u256 const& _gas, bytesConstRef _code, Address const& _originAddress);
    /// @returns false iff go() must be called (and thus a VM execution in required).
    bool createOpcode(Address const& _sender, u256 const& _endowment, u256 const& _gasPrice, u256 const& _gas, bytesConstRef _code, Address const& _originAddress);
    /// @returns false iff go() must be called (and thus a VM execution in required).
    bool create2Opcode(Address const& _sender, u256 const& _endowment, u256 const& _gasPrice, u256 const& _gas, bytesConstRef _code, Address const& _originAddress, u256 const& _salt);
    /// Set up the executive for evaluating a bare CALL (message call) operation.
    /// @returns false iff go() must be called (and thus a VM execution in required).
    bool call(Address const& _receiveAddress, Address const& _txSender, u256 const& _txValue, u256 const& _gasPrice, bytesConstRef _txData, u256 const& _gas);
    bool call(CallParameters const& _cp, u256 const& _gasPrice, Address const& _origin);
    /// Finalise an operation through accruing the substate into the parent context.
    void accrueSubState(SubState& _parentContext);

    /// Executes (or continues execution of) the VM.
    /// @returns false iff go() must be called again to finish the transaction.
    bool go(OnOpFunc const& _onOp = OnOpFunc());

    /// Operation function for providing a simple trace of the VM execution.
    OnOpFunc simpleTrace();

    /// @returns gas remaining after the transaction/operation. Valid after the transaction has been executed.
    u256 gas() const { return m_gas; }

    /// @returns the new address for the created contract in the CREATE operation.
    Address newAddress() const { return m_newAddress; }

    /// @returns The exception that has happened during the execution if any.
    TransactionException getException() const noexcept { return m_excepted; }

    /// Collect execution results in the result storage provided.
    void setResultRecipient(ExecutionResult& _res) { m_res = &_res; }

    /// Revert all changes made to the state by this execution.
    void revert();

private:
    /// @returns false iff go() must be called (and thus a VM execution in required).
    bool executeCreate(Address const& _txSender, u256 const& _endowment, u256 const& _gasPrice, u256 const& _gas, bytesConstRef _code, Address const& _originAddress);

    State& m_s;							///< The state to which this operation/transaction is applied.
    // TODO: consider changign to EnvInfo const& to avoid LastHashes copy at every CALL/CREATE
    EnvInfo m_envInfo;					///< Information on the runtime environment.
    std::shared_ptr<ExtVM> m_ext;		///< The VM externality object for the VM execution or null if no VM is required. shared_ptr used only to allow ExtVM forward reference. This field does *NOT* survive this object.
    owning_bytes_ref m_output;			///< Execution output.
    ExecutionResult* m_res = nullptr;	///< Optional storage for execution results.

    unsigned m_depth = 0;				///< The context's call-depth.
    TransactionException m_excepted = TransactionException::None;	///< Details if the VM's execution resulted in an exception.
    int64_t m_baseGasRequired;			///< The base amount of gas requried for executing this transaction.
    u256 m_gas = 0;						///< The gas for EVM code execution. Initial amount before go() execution, final amount after go() execution.
    u256 m_refunded = 0;				///< The amount of gas refunded.

    Transaction m_t;					///< The original transaction. Set by setup().
    LogEntries m_logs;					///< The log entries created by this transaction. Set by finalize().

    u256 m_gasCost;
    SealEngineFace const& m_sealEngine;

    bool m_isCreation = false;
    Address m_newAddress;
    size_t m_savepoint = 0;

    Logger m_execLogger{createLogger(VerbosityDebug, "exec")};
    Logger m_detailsLogger{createLogger(VerbosityTrace, "exec")};
    Logger m_vmTraceLogger{createLogger(VerbosityTrace, "vmtrace")};

    //msk::mskVerifier m_mskVerifier;  make it temporary
};

}
}

