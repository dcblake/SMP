/*****************************************************************************
File:     CM_Signature.cpp
Project:  Certificate Management Library
Contents: Implementation of the SignedAsnObj class

Created:  January 2000
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  28 April 2004

Version:  2.4

*****************************************************************************/

////////////////////
// Included Files //
////////////////////
#include "CM_internal.h"


// Using declarations
using namespace CML;
using namespace CML::Internal;


//////////////////////
// Type Definitions //
//////////////////////
struct SigHashAlg
{
    const char*	sigHashOID;
    const char*	hashOID;
    const char*	sigOID;
};

struct CAPI_AlgInfo
{
    const char*	algOID;
	ALG_ID		msAlgID;
};

struct PKCS11AlgInfo
{
    const char*	sigHashOID;
	CK_MECHANISM_TYPE mechanism;
	CK_KEY_TYPE	keyType;
};


/////////////////////////
// Function Prototypes //
/////////////////////////
static void convertAsnIntToBytes(ASN::Bytes& bytes,
								 const SNACC::AsnInt& hugeInt, int mult);


//////////////////////
// Global Variables //
//////////////////////
const unsigned int gSHA1_HASH_LEN = 160 / 8;
const unsigned int gSHA256_HASH_LEN = 256 / 8;
const unsigned int gSHA384_HASH_LEN = 384 / 8;

static SigHashAlg SigHashAlg_table[] = {
	{ SNACC::id_dsa_with_sha1,		SNACC::id_sha1,	SNACC::id_dsa },
	{ SNACC::md2WithRSAEncryption,	SNACC::md2,		SNACC::rsaEncryption },
	{ gRSA_MD4_OID,					gMD4_OID,		SNACC::rsaEncryption },
	{ SNACC::md5WithRSAEncryption,	SNACC::md5,		SNACC::rsaEncryption },
	{ SNACC::sha1WithRSAEncryption,	SNACC::id_sha1,	SNACC::rsaEncryption },
	{ SNACC::ecdsa_with_SHA1,		SNACC::id_sha1,	SNACC::id_ecPublicKey },
	{ SNACC::ecdsa_with_SHA256,		SNACC::id_sha256, SNACC::id_ecPublicKey },
	{ SNACC::ecdsa_with_SHA384,		SNACC::id_sha384, SNACC::id_ecPublicKey },
	{ gMOSAIC_DSA_OID,				SNACC::id_sha1,	gDSA_KEA_OID },
	{ gOIW_DSA,						SNACC::id_sha1,	SNACC::id_dsa },
	{ NULL,							NULL,			NULL }
};

#ifdef WIN32
static CAPI_AlgInfo CAPI_Alg_table[] = {
	{ SNACC::id_dsa,				CALG_DSS_SIGN },
	{ SNACC::rsaEncryption,			CALG_RSA_SIGN },
	{ gDSA_KEA_OID,					CALG_DSS_SIGN },
	{ SNACC::id_sha1,				CALG_SHA1 },
	{ SNACC::md5,					CALG_MD5 },
	{ SNACC::md2,					CALG_MD2, },
	{ gMD4_OID,						CALG_MD4 },
	{ SNACC::id_ecPublicKey,		0 },
	{ SNACC::id_sha256,				0 },
	{ SNACC::id_sha384,				0 },
	{ NULL,							0 }
};
#endif


static PKCS11AlgInfo PKCS11Alg_table[] = {
	{ SNACC::id_dsa_with_sha1,		CKM_DSA_SHA1,		CKK_DSA },
	{ SNACC::sha1WithRSAEncryption,	CKM_SHA1_RSA_PKCS,	CKK_RSA },
	{ SNACC::md5WithRSAEncryption,	CKM_MD5_RSA_PKCS,	CKK_RSA },
	{ SNACC::md2WithRSAEncryption,	CKM_MD2_RSA_PKCS,	CKK_RSA },
	{ SNACC::ecdsa_with_SHA1,		CKM_ECDSA_SHA1,		CKK_EC },
	{ SNACC::ecdsa_with_SHA256,		CKM_ECDSA_SHA256,	CKK_EC },
	{ SNACC::ecdsa_with_SHA384,		CKM_ECDSA_SHA384,	CKK_EC },
	{ gMOSAIC_DSA_OID,				CKM_DSA_SHA1,		CKK_DSA },
	{ gOIW_DSA,						CKM_DSA_SHA1,		CKK_DSA },
	{ gRSA_MD4_OID,					0,					CKK_RSA },
	{ NULL,							0,					0 }
};



///////////////////////////////////////
// SignedAsnObj class implementation //
///////////////////////////////////////
SignedAsnObj::SignedAsnObj(const ASN::Bytes& asn)
{
	Decode(asn);
}


SignedAsnObj::SignedAsnObj(const ASN::Bytes& asn, const ASN::AlgID& sigAlg) :
m_sigData(asn), m_sig(sigAlg)
{
}


SignedAsnObj& SignedAsnObj::operator=(const ASN::Bytes& asn)
{
	Decode(asn);
	return *this;
}


ulong SignedAsnObj::Decode(const ASN::Bytes& asn)
{
	m_sigData.Clear();
	m_sig.Clear();

	try {
		// Load the encoded data into an AsnBuf
		SNACC::AsnBuf asnBuf((char*)asn.GetData(), asn.Len());;
		
		// Decode the SIGNED macro SEQ tag
		SNACC::AsnLen numDec = 0;
		SNACC::AsnTag tag = SNACC::BDecTag(asnBuf, numDec);
		if (tag != MAKE_TAG_ID(SNACC::UNIV, SNACC::CONS, SNACC::SEQ_TAG_CODE))
			throw CML_ERR(CM_ASN_ERROR);
		
		// Decode and check the length
		SNACC::AsnLen seqLen = SNACC::BDecLen(asnBuf, numDec);
		if ((seqLen != INDEFINITE_LEN) && (numDec + seqLen != asn.Len()))
			throw CML_ERR(CM_ASN_ERROR);
		
		// Save start of ToBeSigned portion for later
		SNACC::AsnLen tbsOffset = numDec;
		numDec = 0;
		
		// Decode the tag on the ToBeSigned portion
		SNACC::BDecTag(asnBuf, numDec);
		
		// Decode and check the length on the ToBeSigned portion
		SNACC::AsnLen tbsLen = SNACC::BDecLen(asnBuf, numDec);
		if (tbsLen == INDEFINITE_LEN)
			throw CML_ERR(CM_ASN_ERROR);
		
		// Initialize the signed data member variable
		m_sigData.Set(numDec + tbsLen, asn.GetData() + tbsOffset);
		
		// Skip over the ToBeSigned content
		asnBuf.skip(tbsLen);

		// Decode the signature
		m_sig.Decode(asnBuf, numDec);

		// Check that the entire sequence was decoded
		if (seqLen == INDEFINITE_LEN)
			seqLen = numDec + tbsLen;
		else if (seqLen != numDec + tbsLen)
			throw CML_ERR(CM_ASN_ERROR);
		if (tbsOffset + seqLen != asn.Len()) 
			throw CML_ERR(CM_ASN_ERROR);
		
		return asn.Len();
	}
 	catch (SNACC::SnaccException& ) {
		m_sigData.Clear();
		m_sig.Clear();
		throw CML_ERR(CM_ASN_ERROR);
	}
	catch (...) {
		m_sigData.Clear();
		m_sig.Clear();
		throw;
	}
}

ulong SignedAsnObj::Encode(ASN::Bytes& asn) const
{
	try {
		// Create the AsnBuffer
		SNACC::AsnBuf asnBuf;
		SNACC::AsnLen numEncoded = 0;

		// Encode the signature value
		numEncoded += m_sig.Encode(asnBuf);

		// Encode the ToBeSigned data
		asnBuf.PutSegRvs(m_sigData.GetData(), m_sigData.Len());
		numEncoded += m_sigData.Len();

		// Encode the outer SEQ length and tag
		numEncoded += SNACC::BEncDefLen(asnBuf, numEncoded);
		numEncoded += BEncTag1(asnBuf, SNACC::UNIV, SNACC::CONS,
			SNACC::SEQ_TAG_CODE);

		// Set the encoded object into the asn parameter
		asn.SetFromBuf(asnBuf, numEncoded);

		return numEncoded;
	}
	catch (SNACC::SnaccException& ) {
		throw CML_ERR(CM_ASN_ERROR);
	}
}


short SignedAsnObj::Sign(const CM_CryptoToken& tokenHandle,
						 CK_OBJECT_HANDLE pkcs11Key,
						 const ASN::AlgID* pSigAlg)
{
	// Set the signature algorithm, if specified
	if (pSigAlg != NULL)
		m_sig = *pSigAlg;

	return SignBytes(m_sigData, m_sig, tokenHandle, pkcs11Key);
} // end of SignedAsnObj::Sign()


short SignedAsnObj::VerifySignature(ulong sessionID,
									const ASN::PublicKeyInfo& publicKey,
									const ASN::Bytes* parameters) const
{
	// Get the Session from the session ID
	ASN::ReadLock lock = AcquireSessionReadLock(sessionID);
	const Internal::Session& session = Internal::GetSessionFromRef(sessionID);

	// Verify the signature
	return session.VerifySignature(m_sigData, m_sig, publicKey,
		parameters);
}


short SignedAsnObj::VerifySignature(ulong sessionID, SearchBounds boundsFlag,
									const CML::Certificate& signersCert,
									ErrorInfoList* pErrors) const
{
	ValidatedKey validKey;
	short err = signersCert.Validate(sessionID, boundsFlag, pErrors,
		&validKey);
	if ((err == CM_NO_ERROR) || (err == CM_PATH_VALIDATION_ERROR))
	{
		// Check key usage extension if present and the ErrorInfoList
		// parameter is present
		if ((signersCert.base().exts.pKeyUsage != NULL) && (pErrors != NULL))
		{
			SNACC::KeyUsage& keyUse = *signersCert.base().exts.pKeyUsage;
			if (!keyUse.GetBit(SNACC::KeyUsage::digitalSignature) &&
				!keyUse.GetBit(SNACC::KeyUsage::nonRepudiation) &&
				!keyUse.GetBit(SNACC::KeyUsage::keyCertSign) &&
				!keyUse.GetBit(SNACC::KeyUsage::cRLSign))
				pErrors->AddError(CM_INVALID_KEY_USE, signersCert.base());
		}

		short sigErr = VerifySignature(sessionID, validKey);
		if ((sigErr == CM_NO_ERROR) && (err == CM_PATH_VALIDATION_ERROR))
			sigErr = CM_PATH_VALIDATION_ERROR;
		return sigErr;
	}
	return err;
}


short SignedAsnObj::VerifySignature(const CM_CryptoToken& tokenHandle,
									const ASN::PublicKeyInfo& publicKey,
									const ASN::Bytes* parameters) const
{
	// Create the token object
	switch (tokenHandle.type)
	{
	case CM_PKCS11:
		{
			PKCS11_Handle token(tokenHandle.handle.hPKCS);
			return token.Verify(m_sigData, m_sig, publicKey, parameters);
		}
		break;

#ifdef WIN32
	case CM_MS_CSP:
		{
			MS_CSP_Handle token(tokenHandle.handle.hCSP);
			return token.Verify(m_sigData, m_sig, publicKey, parameters);
		}
		break;
#endif // WIN32

	default:
		return CM_INVALID_PARAMETER;
	}
}


////////////////////////////////////
// Signature class implementation //
////////////////////////////////////
Signature& Signature::operator=(const ASN::AlgID& algorithm)
{
	m_sigAlg = algorithm;
	m_value.Clear();
	m_capiValue.Clear();
	return *this;
}


void Signature::Clear()
{
	m_sigAlg.Clear();
	m_value.Clear();
	m_capiValue.Clear();
}


ulong Signature::Decode(const SNACC::AsnBuf& asnBuf,
						SNACC::AsnLen& bytesDecoded)
{
	Clear();
	ulong numDec = 0;

	try {
		// Decode the algorithm
		SNACC::AlgorithmIdentifier snaccAlgID;
		snaccAlgID.BDec(asnBuf, numDec);

		// Copy the SNACC Algorithm Identifier into the AlgID
		m_sigAlg = snaccAlgID;

		// Determine the hash and signature algorithms present
		const char* pHashAlg = NULL;
		const char* pSigAlg = SplitSigHashAlg(m_sigAlg.algorithm, &pHashAlg);

		// Decode the signature value
		SNACC::AsnBits snaccBits;
		snaccBits.BDec(asnBuf, numDec);
		if ((snaccBits.BitLen() % 8) != 0)
			throw CML_ERR(CM_ASN_ERROR);

		// Set the big-endian signature value and reversed value
		if ((pSigAlg == NULL) || (strcmp(pSigAlg, SNACC::rsaEncryption) == 0))
		{
			// Copy the big-endian value and reverse the CAPI value
			m_value = snaccBits;
			m_capiValue = m_value;
			m_capiValue.Reverse();
		}
		else if (strcmp(pSigAlg, SNACC::id_dsa) == 0)
		{
			// Determine size of hash from OID, default is SHA1
			unsigned int hashLen = gSHA1_HASH_LEN;
			if (strcmp(pHashAlg, SNACC::id_sha256) == 0)
				hashLen = gSHA256_HASH_LEN;
			else if (strcmp(pHashAlg, SNACC::id_sha384) == 0)
				hashLen = gSHA384_HASH_LEN;

			// Create a temporary buffer from the contents of the BIT STRING
			SNACC::AsnRvsBuf asnStream((char*)snaccBits.data(),
				snaccBits.length());
			SNACC::AsnBuf bitsBuf(&asnStream);

			// Decode the DSS signature value
			SNACC::Dss_Sig_Value snaccSig;
			SNACC::AsnLen nSigValueDec = 0;
			snaccSig.BDec(bitsBuf, nSigValueDec);

			// Convert the R and S values to Bytes objects
			m_value.SetFromInt(snaccSig.r, hashLen);
			ASN::IntBytes s(snaccSig.s, hashLen);

			// Concatenate the R and S values and reverse each half of the
			// CAPI value
			m_value += s;
			m_capiValue = m_value;
			m_capiValue.ReverseHalves();
		}
		else if (strcmp(pSigAlg, SNACC::id_ecPublicKey) == 0)
		{
			// Determine size of hash from OID, default is SHA1
			unsigned int hashLen = gSHA1_HASH_LEN;
			if (strcmp(pHashAlg, SNACC::id_sha256) == 0)
				hashLen = gSHA256_HASH_LEN;
			else if (strcmp(pHashAlg, SNACC::id_sha384) == 0)
				hashLen = gSHA384_HASH_LEN;

			// Create a temporary buffer from the contents of the BIT STRING
			SNACC::AsnRvsBuf asnStream((char*)snaccBits.data(),
				snaccBits.length());
			SNACC::AsnBuf bitsBuf(&asnStream);

			// Decode the ECDSA signature value
			SNACC::ECDSA_Sig_Value snaccSig;
			SNACC::AsnLen nSigValueDec = 0;
			snaccSig.BDec(bitsBuf, nSigValueDec);

			// Convert the R and S values to Bytes objects
			m_value.SetFromInt(snaccSig.r, hashLen);
			ASN::IntBytes s(snaccSig.s, hashLen);

			// Concatenate the R and S values and reverse each half of the
			// CAPI value
			m_value += s;
			m_capiValue = m_value;
			m_capiValue.ReverseHalves();
		}
		else if (strcmp(pSigAlg, gDSA_KEA_OID) == 0)
		{
			// Copy the big-endian value and reverse each half of the
			// CAPI value
			m_value = snaccBits;
			m_capiValue = m_value;
			m_capiValue.ReverseHalves();
		}
		else
		{
			// Copy the big-endian value and reverse the CAPI value
			m_value = snaccBits;
			m_capiValue = m_value;
			m_capiValue.Reverse();
		}

		// Update the number of bytes decoded and return
		bytesDecoded += numDec;
		return numDec;
	}
 	catch (SNACC::SnaccException& ) {
		bytesDecoded += numDec;
		Clear();
		throw CML_ERR(CM_ASN_ERROR);
	}
	catch (...) {
		bytesDecoded += numDec;
		Clear();
		throw;
	}
}


SNACC::AsnLen Signature::Encode(SNACC::AsnBuf& asnBuf) const
{
	// Get the SNACC form of the algorithm identifier
	SNACC::AlgorithmIdentifier snaccAlg;
	m_sigAlg.FillSnacc(snaccAlg);

	// Encode the signature value into the BIT STRING
	SNACC::AsnBits snaccBits;
	EncodeValue(snaccBits);

	// Encode the BIT STRING into the AsnBuf
	SNACC::AsnLen numEncoded = snaccBits.BEnc(asnBuf);

	// Encode the AlgorithmIdentifier
	numEncoded += snaccAlg.BEnc(asnBuf);

	// Return the number of bytes encoded
	return numEncoded;
} // end of Signature::Encode()


void Signature::EncodeValue(ASN::Bytes& asn) const
{
	// Encode the signature value into the BIT STRING
	SNACC::AsnBits snaccBits;
	EncodeValue(snaccBits);

	// Set the Bytes to the encoded BIT STRING
	asn = snaccBits;

} // end of Signature::EncodeValue()


void Signature::EncodeValue(SNACC::AsnBits& asnBits) const
{
	// Determine the type of signature algorithm present
	const char* pSigAlg = SplitSigHashAlg(m_sigAlg.algorithm);

	// Encode the BIT STRING according to the algorithm
	if ((pSigAlg == NULL) || (strcmp(pSigAlg, SNACC::rsaEncryption) == 0))
	{
		// Just copy the signature value into the BIT STRING
		asnBits.Set(m_value.GetData(), m_value.BitLen());
	}
	else if (strcmp(pSigAlg, SNACC::id_dsa) == 0)
	{
		// Fill in the SNACC form of the DSS signature value
		SNACC::Dss_Sig_Value snaccSig;
		ulong rLen = m_value.Len() / 2;
		snaccSig.r.Set(m_value.GetData(), rLen, true);
		snaccSig.s.Set(m_value.GetData() + rLen, rLen, true);

		// Encode the DSS signature value
		SNACC::AsnBuf asnBuf;
		SNACC::AsnLen numEnc = snaccSig.BEnc(asnBuf);

		// Get a copy of the encoded value
		uchar* pBuf = (uchar*)asnBuf.GetSeg(numEnc);

		try {
			// Copy the encoded signature value into the BIT STRING
			asnBits.Set(pBuf, numEnc * 8);

			// Delete the temporary memory buffer
			delete[] pBuf;
		}
		catch (...) {
			delete[] pBuf;
			throw;
		}
	}
	else if (strcmp(pSigAlg, SNACC::id_ecPublicKey) == 0)
	{
		// Fill in the SNACC form of the ECDSA signature value
		SNACC::ECDSA_Sig_Value snaccSig;
		ulong rLen = m_value.Len() / 2;
		snaccSig.r.Set(m_value.GetData(), rLen, true);
		snaccSig.s.Set(m_value.GetData() + rLen, rLen, true);

		// Encode the ECDSA signature value
		SNACC::AsnBuf asnBuf;
		SNACC::AsnLen numEnc = snaccSig.BEnc(asnBuf);

		// Get a copy of the encoded value
		uchar* pBuf = (uchar*)asnBuf.GetSeg(numEnc);

		try {
			// Copy the encoded signature value into the BIT STRING
			asnBits.Set(pBuf, numEnc * 8);

			// Delete the temporary memory buffer
			delete[] pBuf;
		}
		catch (...) {
			delete[] pBuf;
			throw;
		}
	}
	else if (strcmp(pSigAlg, gDSA_KEA_OID) == 0)
	{
		// Just copy the signature value into the BIT STRING
		asnBits.Set(m_value.GetData(), m_value.BitLen());
	}
	else
	{
		// Just copy the signature value into the BIT STRING
		asnBits.Set(m_value.GetData(), m_value.BitLen());
	}
} // end of Signature::EncodeValue()


void Signature::Set(ulong sigLen, const uchar* sigValue, bool isBigEndian)
{
	// Determine the signature algorithm used
	const char* pSigAlg = SplitSigHashAlg(m_sigAlg.algorithm);

	ASN::IntBytes* pValueToReverse = &m_capiValue;
	if (isBigEndian)
	{
		m_value.Set(sigLen, sigValue);
		m_capiValue = m_value;
	}
	else
	{
		m_capiValue.Set(sigLen, sigValue);
		m_value = m_capiValue;
		pValueToReverse = &m_value;
	}

	// Reverse the other value
	if ((pSigAlg == NULL) || (strcmp(pSigAlg, SNACC::rsaEncryption) == 0))
	{
		pValueToReverse->Reverse();
	}
	else if ((strcmp(pSigAlg, SNACC::id_dsa) == 0) ||
		(strcmp(pSigAlg, SNACC::id_ecPublicKey) == 0) ||
		(strcmp(pSigAlg, gDSA_KEA_OID) == 0))
	{
		pValueToReverse->ReverseHalves();
	}
	else	// Unknown algorithm
		pValueToReverse->Reverse();

} // end of Signature::Set()


/////////////////////////////
// CML::Internal functions //
/////////////////////////////
short Internal::SignBytes(const ASN::Bytes& dataToSign,
						  Signature& signature,
						  const CM_CryptoToken& tokenHandle,
						  CK_OBJECT_HANDLE pkcs11Key)
{
	// Create the token object
	switch (tokenHandle.type)
	{
	case CM_PKCS11:
		{
			PKCS11_Handle token(tokenHandle.handle.hPKCS);
			return token.Sign(pkcs11Key, dataToSign, signature);
		}
		break;

#ifdef WIN32
	case CM_MS_CSP:
		{
			MS_CSP_Handle token(tokenHandle.handle.hCSP);
			return token.Sign(dataToSign, signature);
		}
		break;
#endif // WIN32

	default:
		return CM_INVALID_PARAMETER;
	}
}


short CML::Internal::VerifySignature(ulong sessionID, const ASN::Bytes& asnObj,
									 const ASN::PublicKeyInfo& pubKey,
									 const ASN::Bytes* pubKeyParams)
{
	try {
		SignedAsnObj signedObj(asnObj);
		return signedObj.VerifySignature(sessionID, pubKey, pubKeyParams);
	}
	catch (ASN::Exception& cmlErr) {
		return cmlErr;
	}
	catch (...) {
		return CM_ASN_ERROR;
	}
}


/************************************************************************
 FUNCTION:  CML::Internal::SplitSigHashAlg()
 
 Description: This function will look up the signature and hash OID in
 the table and return the signature OID string, and if requested,
 set the supplied hash OID string.  NULL is returned for both if the
 input OID is not supported.
*************************************************************************/
const char* CML::Internal::SplitSigHashAlg(const SNACC::AsnOid& sigHashAlg,
										   const char** ppHashAlg)
{
	SigHashAlg* pEntry;
	for (pEntry = SigHashAlg_table; (pEntry->sigHashOID != NULL) &&
		(sigHashAlg != pEntry->sigHashOID); pEntry++)
		;

	if (ppHashAlg != NULL)
		*ppHashAlg = pEntry->hashOID;

	return pEntry->sigOID;

} // end of CML::Internal::SplitSigHashAlg()

#ifdef WIN32
ALG_ID CML::Internal::GetCAPI_AlgID(const SNACC::AsnOid& alg)
{
	CAPI_AlgInfo* pEntry;
	for (pEntry = CAPI_Alg_table; (pEntry->algOID != NULL) &&
		(alg != pEntry->algOID); pEntry++)
		;

	return pEntry->msAlgID;
} // end of CML::Internal::GetCAPI_AlgID()
#endif


CK_MECHANISM_TYPE Internal::GetPKCSMechanismType(const SNACC::AsnOid& sigHashAlg,
												 CK_KEY_TYPE& keyType)
{
	PKCS11AlgInfo* pEntry;
	for (pEntry = PKCS11Alg_table; (pEntry->sigHashOID != NULL) &&
		(sigHashAlg != pEntry->sigHashOID); pEntry++)
		;

	keyType = pEntry->keyType;

	return pEntry->mechanism;
} // end of Internal::GetPKCSMechanismType()


// end of CM_Signature.cpp
