/*****************************************************************************
File:     CM_Certificate.cpp
Project:  Certificate Management Library
Contents: Implementation of the Certificate class.

Created:  20 March 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  12 March 2004

Version:  2.4

*****************************************************************************/


////////////////////
// Included Files //
////////////////////
#include "CM_cache.h"


// Using declarations
using namespace CML;
using namespace CML::Internal;
using ASN::Cert;
using ASN::Bytes;



//////////////////////////////////////
// Certificate class implementation //
//////////////////////////////////////
Certificate::Certificate(const Cert& cert) : Cert(cert)
{
	Cert::Encode(encCert);
}


Certificate::Certificate(const Bytes& asn) : Cert(asn)
{
	encCert = asn;
}


Certificate::Certificate(const Bytes_struct& asn)
{
	encCert.Set(asn.num, asn.data);
	Cert::operator=(encCert);
}


Certificate& Certificate::operator=(const Cert& cert)
{
	Cert::operator=(cert);
	Cert::Encode(encCert);
	return *this;
}


Certificate& Certificate::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


ulong Certificate::Decode(const Bytes& asn)
{
	encCert = asn;
	return Cert::Decode(asn);
}


ulong Certificate::Encode(Bytes& asn) const
{
	asn = encCert;
	return asn.Len();
}


bool Certificate::IsValid(ulong sessionID) const
{
	// Find this cert in the cache
	const CachedCertRef* pCachedCert =
		GetCertCache(sessionID).FindCert(encCert);

	// If this cert was not found, return not valid.
	if (pCachedCert == NULL)
		return false;

	// Found this cert. Check to see if it has errors.
	if (pCachedCert->GetRef().HasPathErrors() || pCachedCert->GetRef().HasCertErrors())
	{
		// Has errors, return not valid.
		delete pCachedCert;
		return false;
	}
	
	// This cert was found and has no errors, return valid.
	delete pCachedCert;
	return true;
}


short Certificate::Sign(const CM_CryptoToken& tokenHandle,
						CK_OBJECT_HANDLE pkcs11Key, const ASN::AlgID* pSigAlg)
{
	// If the existing algorithm is to be used, just check that both signature
	// algorithms match
	if (pSigAlg == NULL)
	{
		if (signature != algorithm)
			return CM_SIGNATURE_ALG_MISMATCH;
	}
	// else if the existing algorithms are not set to the specified one,
	// set them and re-encode the certificate
	else if ((*pSigAlg != signature) || (*pSigAlg != algorithm))
	{
		// Set the signature algorithm to the specified algorithm if present
		signature = *pSigAlg;
		algorithm = *pSigAlg;

		// Re-encode the certificate
		Cert::Encode(encCert);
	}
	// else the algorithms are already set

	// Construct a SignedAsnObj from the encoded certficate
	SignedAsnObj signedCert(encCert);

	// Sign the cert
	short cmErr = signedCert.Sign(tokenHandle, pkcs11Key);
	if (cmErr == CM_NO_ERROR)
	{
		// Encode the cert's signature value and update the cert
		signedCert.GetSignature().EncodeValue(sigValue);

		// Re-encode the certificate
		Cert::Encode(encCert);
	}

	return cmErr;
} // end of Certificate::Sign()


//////////////////////////////////////////////////////////////////////////////
// FUNCTION:  Certificate::Validate()
// 
// Description: Validate a certificate
//
// Inputs: 
//    ulong            sessionID        - CML Session ID
//    SearchBounds     boundsFlag       - Search local,remote,both or until found
//	   CertPath*	     optPath          - Optional path to use for validating
//	   bool	           performRevChecking - If true, perform revocation checking
//	   const ASN::Time* pValidationTime  - Optional. Points to a date/time that 
//                                      must be used when checking revocation
//                                      status
// Outputs:
//    ErrorInfoList *pErrors        -  List of errors found while validating
//	   ValidatedKey* pValidKey       -  To be filled in with validation info

// Return Value: 
//	   short result - result of Validation checking
/////////////////////////////////////////////////////////////////////////////

short Certificate::Validate(ulong sessionID, SearchBounds boundsFlag,
							ErrorInfoList* pErrors, ValidatedKey* pValidKey,
							CertPath* optPath, const ASN::Time* pValidationTime,
                     bool performRevChecking ) const
{
	CertPath thePath(*this);
	short result = thePath.BuildAndValidate(sessionID, boundsFlag, pErrors, 0,
		pValidKey, pValidationTime, performRevChecking );

	// Get the optional path if requested
	if (optPath != NULL)
		*optPath = thePath;

	return result;
}


short Certificate::VerifySignature(ulong sessionID,
								   const ValidatedKey& signersKey) const
{
	SignedAsnObj signedCert(encCert);
	return signedCert.VerifySignature(sessionID, signersKey);
}


short Certificate::VerifySignature(ulong sessionID,
								   const ASN::PublicKeyInfo& publicKey,
								   const Bytes* parameters) const
{
	SignedAsnObj signedCert(encCert);
	return signedCert.VerifySignature(sessionID, publicKey, parameters);
}


short Certificate::VerifySignature(ulong sessionID, SearchBounds boundsFlag,
								   Certificate& signersCert) const
{
	SignedAsnObj signedCert(encCert);
	return signedCert.VerifySignature(sessionID, boundsFlag, signersCert);
}



// end of CM_Certificate.cpp
