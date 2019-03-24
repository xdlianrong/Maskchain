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
/** @file TransactionBase.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include <libdevcore/vector_ref.h>
#include <libdevcore/Log.h>
#include <libdevcrypto/Common.h>
#include <libethcore/Exceptions.h>
#include "TransactionBase.h"
#include "EVMSchedule.h"

#include "../libsnark/donator2/interface.hpp"

using namespace std;
using namespace dev;
using namespace dev::eth;
using namespace msk;

/*
* Maskash marsCatXdu
* web3的 signTransaction 调用了这个
* 该构造器改造中，正在改造 sign(_s)
*/ 
TransactionBase::TransactionBase(TransactionSkeleton const& _ts, Secret const& _s):
	m_type(_ts.creation ? ContractCreation : MessageCall),
	m_nonce(_ts.nonce),
	m_value(_ts.value),
	m_receiveAddress(_ts.to),
	m_gasPrice(_ts.gasPrice),
	m_gas(_ts.gas),
	m_data(_ts.data),
	m_maskashMsg(_ts.maskashMsg),
	m_sender(_ts.from)
{
	/*  Maskash 零知识证明套装测试点，测试完成
	msk::isSnarkOk();
	ppT::init_public_params();
    inhibit_profiling_info = true;
    inhibit_profiling_counters = true;

    uint256 ask_s=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad0");
   
    uint256 apk_r=uint256S("038cce42abd366b83ede7e009130de5372cdf73dee8251148cb48d1b9af68ad1");

    uint64_t v_1=5;
    uint64_t v_2=3;
    uint64_t v_3=0;

    uint256 old_r=uint256S("038cce42abd366b83ede8e009130de5372cdf73dee2251148cb48d1b4af68a45");

    uint256 new_r1=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");
    uint256 new_r2=uint256S("038cce42abd366b83ede9e009130de5372cdf73dee3251148cb48d1b5af68ad0");

    transferZero tr= makeTransferZero<FieldT>( apk_r, new_r1,new_r2,v_1,ask_s,old_r,v_2);
    bool t=transferZeroVerify<FieldT>(tr.SNold ,tr.krnew,tr.ksnew, tr.data, tr.pi,tr.vk,tr.c_rt,tr.s_rt,tr.r_rt);
    cout<<t<<endl;
	*/

	if (_s)
		sign(_s);
}

/*
* Maskash marsCatXdu
* 从 RLP 构造交易，接收广播的交易应该也是走的这里
*/ 
TransactionBase::TransactionBase(bytesConstRef _rlpData, CheckTransaction _checkSig)
{
	RLP const rlp(_rlpData);
	try
	{
		if (!rlp.isList())
			BOOST_THROW_EXCEPTION(InvalidTransactionFormat() << errinfo_comment("transaction RLP must be a list"));

		m_nonce = rlp[0].toInt<u256>();
		m_gasPrice = rlp[1].toInt<u256>();
		m_gas = rlp[2].toInt<u256>();
		m_type = rlp[3].isEmpty() ? ContractCreation : MessageCall;
		m_receiveAddress = rlp[3].isEmpty() ? Address() : rlp[3].toHash<Address>(RLP::VeryStrict);
		m_value = rlp[4].toInt<u256>();

		if (!rlp[5].isData())
			BOOST_THROW_EXCEPTION(InvalidTransactionFormat() << errinfo_comment("transaction data RLP must be an array"));

		m_data = rlp[5].toBytes();

		int const v = rlp[6].toInt<int>();
		h256 const r = rlp[7].toInt<u256>();
		h256 const s = rlp[8].toInt<u256>();

		m_maskashMsg = rlp[9].toString();

		if (isZeroSignature(r, s))
		{
			m_chainId = v;
			m_vrs = SignatureStruct{r, s, 0};
		}
		else
		{
			if (v > 36)
				m_chainId = (v - 35) / 2; 
			else if (v == 27 || v == 28)
				m_chainId = -4;
			else
				BOOST_THROW_EXCEPTION(InvalidSignature());

			m_vrs = SignatureStruct{r, s, static_cast<byte>(v - (m_chainId * 2 + 35))};

			if (_checkSig >= CheckTransaction::Cheap && !m_vrs->isValid())
				BOOST_THROW_EXCEPTION(InvalidSignature());
		}

		if (_checkSig == CheckTransaction::Everything)
			m_sender = sender();

		if (rlp.itemCount() > 10) // Maskash marsCatXdu 整数从9改为10
			BOOST_THROW_EXCEPTION(InvalidTransactionFormat() << errinfo_comment("too many fields in the transaction RLP"));
	}
	catch (Exception& _e)
	{
		_e << errinfo_name("invalid transaction format: " + toString(rlp) + " RLP: " + toHex(rlp.data()));
		throw;
	}
}

Address const& TransactionBase::safeSender() const noexcept
{
	try
	{
		return sender();
	}
	catch (...)
	{
		return ZeroAddress;
	}
}

Address const& TransactionBase::sender() const
{
	if (!m_sender)
	{
		if (hasZeroSignature())
			m_sender = MaxAddress;
		else
		{
			if (!m_vrs)
				BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

			auto p = recover(*m_vrs, sha3(WithoutSignature));
			if (!p)
				BOOST_THROW_EXCEPTION(InvalidSignature());
			m_sender = right160(dev::sha3(bytesConstRef(p.data(), sizeof(p))));
		}
	}
	return m_sender;
}

SignatureStruct const& TransactionBase::signature() const
{ 
	if (!m_vrs)
		BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

	return *m_vrs;
}

// Maskash marsCatXdu rlp 工作的一部分？
void TransactionBase::sign(Secret const& _priv)
{
	auto sig = dev::sign(_priv, sha3(WithoutSignature));	// dev::sign 来自 devcrypto 中的 common
	SignatureStruct sigStruct = *(SignatureStruct const*)&sig;
	if (sigStruct.isValid())
		m_vrs = sigStruct;
}

// Maskash marsCatXdu 看起来就非常像是干了 RLP 的活
void TransactionBase::streamRLP(RLPStream& _s, IncludeSignature _sig, bool _forEip155hash) const
{
	if (m_type == NullTransaction)
		return;

	_s.appendList((_sig || _forEip155hash ? 3 : 0) + 7); // 结尾的 6 改成 7 
	_s << m_nonce << m_gasPrice << m_gas;
	if (m_type == MessageCall)
		_s << m_receiveAddress;
	else
		_s << "";
	_s << m_value << m_data;

	if (_sig)
	{
		if (!m_vrs)
			BOOST_THROW_EXCEPTION(TransactionIsUnsigned());// 只有签名后的交易才会序列化

		if (hasZeroSignature())
			_s << m_chainId;
		else
		{
			int const vOffset = m_chainId * 2 + 35;
			_s << (m_vrs->v + vOffset);
		}
		_s << (u256)m_vrs->r << (u256)m_vrs->s;    // 原有的第九个元素到此填完
	}
	else if (_forEip155hash)
		_s << m_chainId << 0 << 0;

	_s<<m_maskashMsg;		// 添加到最后面
}

static const u256 c_secp256k1n("115792089237316195423570985008687907852837564279074904382605163141518161494337");

void TransactionBase::checkLowS() const
{
	if (!m_vrs)
		BOOST_THROW_EXCEPTION(TransactionIsUnsigned());

	if (m_vrs->s > c_secp256k1n / 2)
		BOOST_THROW_EXCEPTION(InvalidSignature());
}

void TransactionBase::checkChainId(int chainId) const
{
	if (m_chainId != chainId && m_chainId != -4)
		BOOST_THROW_EXCEPTION(InvalidSignature());
}

int64_t TransactionBase::baseGasRequired(bool _contractCreation, bytesConstRef _data, EVMSchedule const& _es)
{
	int64_t g = _contractCreation ? _es.txCreateGas : _es.txGas;

	// Calculate the cost of input data.
	// No risk of overflow by using int64 until txDataNonZeroGas is quite small
	// (the value not in billions).
	for (auto i: _data)
		g += i ? _es.txDataNonZeroGas : _es.txDataZeroGas;
	return g;
}

h256 TransactionBase::sha3(IncludeSignature _sig) const
{
	if (_sig == WithSignature && m_hashWith)
		return m_hashWith;

	RLPStream s;
	streamRLP(s, _sig, m_chainId > 0 && _sig == WithoutSignature);

	auto ret = dev::sha3(s.out());
	if (_sig == WithSignature)
		m_hashWith = ret;
	return ret;
}

/// 构造：购币者发送给铸币者的 铸币请求 的核心信息
std::string TransactionBase::makeMintReqString(uint256 Usk, uint256 p, uint256 v) {
	msk::msgMintRequest mintReq = msk::makeMintRequest(uint256 Usk, uint256 p, uint256 v);
	return mskTxTmp;
}

/// 构造：铸币者发送到网络的 铸币交易 的核心信息
std::string TransactionBase::makeMintReqString(uint256 kmint, uint256 v, uint256 upk) {
	msk::msgMint mintMsg = msk::makeMsgMint(uint256 kmint, uint256 v, uint256 upk);
	return mskTxTmp;
}

/// 构造：零币转账发起者发送到网络的核心信息
std::string TransactionBase::makeTransferZero(uint256 Rpk, uint256 pr, uint256 vr, uint256 Ssk, uint256 ps, uint256 vs) {
	msk::transferZero transerZ = msk::makeTransferZero(uint256 Rpk, uint256 pr, uint256 vr, uint256 Ssk, uint256 ps, uint256 vs);
	return mskTxTmp;
}	

/// 构造：整币转账发起者发送到网络的核心信息
std::string TransactionBase::makeTransferOne(uint256 Rpk, uint256 pr, uint256 vr, uint256 Ssk) {
	msk::transferOne transferO = msk::makeTransferOne(uint256 Rpk, uint256 pr, uint256 vr, uint256 Ssk);
	return mskTxTmp;
}