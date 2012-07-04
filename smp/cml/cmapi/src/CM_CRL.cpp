/*****************************************************************************
File:     CM_crl.cpp
Project:  Certificate Management Library
Contents: Routines to interface with the CRL Service DLL.

Created:  19 December 2003
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  15 March 2004
               21 September 2005 for Requirement 5

Version:  2.4

*****************************************************************************/


/* ------------- */
/* Include Files */
/* ------------- */
#include "CM_cache.h"
#include "crlapi.h"
#ifdef HPUX32
	#include <dl.h>			// Needed for dynamic loading of CRL library
#elif !defined(WIN32)
	#include <dlfcn.h>		// Needed for dynamic loading of CRL library
#endif


// Using declarations
using namespace CML;
using namespace CML::Internal;
using ASN::Bytes;
using ASN::CertificateList;
using ASN::GenNames;
using ASN::GenName;


//////////////////////
// Type Definitions //
//////////////////////
typedef short (*PExtCRLInitFn)(ulong *session, CRLDLLInitSettings_struct *serverSettings);
typedef short (*PExtCRLDestroyFn)(ulong *session);
typedef void (*PExtCRLEmptyCacheFn)(ulong session);

typedef std::list<CRL> CrlList;


/////////////////////////
// Function Prototypes //
/////////////////////////
static CachedCertList* findCRLIssuerInCache(const CRL& crl, ulong sessionID);
static short findCRLIssuer(const ASN::CertificateList& crl, ulong sessionID,
						   SearchBounds searchFlag, CertList& certList);
static short findValidCRLIssuer(const CertificateList& crl, ulong sessionID,
								SearchBounds boundsFlag,
								ValidatedKey& issuersKey,
								CertPath& issuersPath, ErrorInfoList* pErrors,
                        const ASN::Time* pValidationTime,
								bool performRevChecking);
static HINSTANCE link2CRL(const char* libName, ulong& sessionID, const ulong cmlSessionID,
						  const time_t crlCacheTTL, const time_t crlGracePeriod,
						  RevCallbackFunctions& revFuncs, const CallbackFunctions& srlFuncs);
static void unlinkCRL(HINSTANCE hDLL, ulong* sessionID);


//////////////////////
// Global Variables //
//////////////////////
const char* gCrlLibName = LIB_PREFIX "crlapi" DEBUG_INDICATOR LIB_EXT;


//////////////////////////////
// CRL class implementation //
//////////////////////////////
CRL::CRL(const CertificateList& crl) : CertificateList(crl)
{
	CertificateList::Encode(encCrl);
}


CRL::CRL(const Bytes& asn) : CertificateList(asn), encCrl(asn)
{
}


CRL& CRL::operator=(const CertificateList& crl)
{
	CertificateList::operator=(crl);
	CertificateList::Encode(encCrl);
	return *this;
}


CRL& CRL::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


ulong CRL::Decode(const Bytes& asn)
{
	encCrl = asn;
	return CertificateList::Decode(asn);
}


ulong CRL::Encode(Bytes& asn) const
{
	asn = encCrl;
	return asn.Len();
}


short CRL::Sign(const CM_CryptoToken& tokenHandle, CK_OBJECT_HANDLE pkcs11Key,
				const ASN::AlgID* pSigAlg)
{
	// If the existing algorithm is to be used, just check that both signature
	// algorithms match
	if (pSigAlg == NULL)
	{
		if (signature != algorithm)
			return CM_SIGNATURE_ALG_MISMATCH;
	}
	// else if the existing algorithms are not set to the specified one,
	// set them and re-encode the CRL
	else if ((*pSigAlg != signature) || (*pSigAlg != algorithm))
	{
		// Set the signature algorithm to the specified algorithm if present
		signature = *pSigAlg;
		algorithm = *pSigAlg;

		// Re-encode the CRL
		CertificateList::Encode(encCrl);
	}
	// else the algorithms are already set

	// Construct a SignedAsnObj from the encoded CRL
	SignedAsnObj signedCRL(encCrl);

	// Sign the CRL
	short cmErr = signedCRL.Sign(tokenHandle, pkcs11Key);
	if (cmErr == CM_NO_ERROR)
	{
		// Encode the CRL's signature value and update the CRL
		signedCRL.GetSignature().EncodeValue(sigValue);

		// Re-encode the CRL
		CertificateList::Encode(encCrl);
	}

	return cmErr;
} // end of CRL::Sign()

////////////////////////////////////////////////////////////////////////////////// /// FUNCTION:  Certificate::Validate()
// 
// Description: Validate a certificate
//
// Inputs: 
//   ulong            sessionID       - CML Session ID
//   SearchBounds     boundsFlag      - Search local, remote, both or until found
//	  Certificate*     pSigner         - Optional signer
//	  bool             tryOtherSigners - try multiple signers
//	  const ASN::Time* pValidationTime - Optional. Points to a date/time that 
//                                      must be used when checking revocation
//                                      status
//
// Outputs:
//   ErrorInfoList    *pErrors        -  List of errors found while validating
//
// Return Value: 
//   short            result          - result of CRL Validation
//
//////////////////////////////////////////////////////////////////////
short CRL::Validate(ulong sessionID, SearchBounds boundsFlag,
					ErrorInfoList* pErrors, const Certificate* pSigner,
					bool tryOtherSigners, 
					const ASN::Time* pValidationTime) const
{
	// Try the supplied signer's certificate first, if present
	ValidatedKey signersKey;
	ErrorInfoList crlErrors;
	short cmlErr = CM_PATH_VALIDATION_ERROR;
	if (pSigner != NULL)
	{
		// Check that the cert could have issued the CRL
		if (IsIssuer(pSigner->base()))
		{
			cmlErr = pSigner->Validate(sessionID, boundsFlag,
				                        &crlErrors, &signersKey, 
                                    NULL, pValidationTime, true);
			// If an error occurred, and additional issuers should be
			// tried, set the pSigner pointer to NULL
			if (tryOtherSigners && (cmlErr != CM_NO_ERROR))
				pSigner = NULL;
		}
	}

	// Find the CRL issuer's certificate(s)
	CertList certList;
	if (pSigner == NULL)
	{
		short err = findCRLIssuer(*this, sessionID, boundsFlag, certList);
		if (err != CM_NO_ERROR)
		{
			if (pErrors != NULL)
				pErrors->AddError(CM_ISSUER_CERT_NOT_FOUND, issuer);
			return CM_NO_PATH_FOUND;
		}
	}

	// Try to validate the CRL issuer's certificate(s)
	CertList::const_iterator iCert;
	for (iCert = certList.begin(); (iCert != certList.end()) &&
		(cmlErr != CM_NO_ERROR); ++iCert)
	{
		try {
			crlErrors.clear();
				
			// Validate the CRL issuer's certificate
			cmlErr = iCert->Validate(sessionID, boundsFlag,
				&crlErrors, &signersKey, NULL, pValidationTime, true);
			if ((cmlErr != CM_NO_ERROR) && !tryOtherSigners)
			{
				// If an error occurred and no more signer certs will
				// be tried, break out of the loop
				break;
			}
		}
		catch (...) {
			// Skip this cert
		}
	}

	// Add any path building/validation errors to the supplied error list
	if (pErrors != NULL)
		pErrors->Splice(pErrors->end(), crlErrors);

	// Return if a path to the CRL issuer's cert could not be built
	if ((cmlErr != CM_NO_ERROR) && (cmlErr != CM_PATH_VALIDATION_ERROR))
		return cmlErr;
	
	// Validate the CRL
	short valErr = Validate(sessionID, signersKey, pErrors, pValidationTime);
	if ((cmlErr == CM_NO_ERROR) && (valErr == CM_NO_ERROR))
	{
		return CM_NO_ERROR;
	}

	return CM_PATH_VALIDATION_ERROR;
}

////////////////////////////////////////////////////////////////////////////
// FUNCTION:  CRL::Validate
// 
// Description: Validate a certificate
//
// Inputs: 
//   ulong            sessionID       - CML Session ID
//   SearchBounds     boundsFlag      - Search local, remote, both or until found
//	  CertPath&	       issuerPath      - Path to use for validating
//	  bool	          performRevChecking - If true, perform revocation checking
//	  const ASN::Time* pValidationTime - Optional. Points to a date/time  
//                                      that must be used when checking
//                                      revocation status
//
// Outputs:
//   ErrorInfoList *pErrors        -  List of errors found while validating
//	  ValidatedKey* pValidKey       -  To be filled in with validation info
//
// Return Value: 
//	short result - result of Validation checking
//
//////////////////////////////////////////////////////////////////////////////
short CRL::Validate(ulong sessionID, SearchBounds boundsFlag,
					CertPath& issuerPath, ErrorInfoList* pErrors,
					const ASN::Time* pValidationTime, 
               bool performRevChecking) const
{
	// Search the cache for the CRL issuer's certificate
	ValidatedKey issuersKey;
	CachedCertList* pCachedCerts = findCRLIssuerInCache(*this, sessionID);

	short cmlErr = CM_NO_ERROR;
	if (pCachedCerts != NULL)
	{
		try {
			ErrorInfoList crlErrors;
			
			// Try to validate the CRL using each of the cached issuer certs
			CachedCertList::iterator iCert = pCachedCerts->begin();
			while (iCert != pCachedCerts->end())
			{
				// Get the issuer's validated public key
				iCert->GetRef().ExportPathResults(issuersKey);
				
				// Clear the temporary errors
				crlErrors.clear();
				
				// Validate the CRL
				cmlErr = Validate(sessionID, issuersKey, &crlErrors, pValidationTime);
				
				// Check that the CRL's signature was valid
				ErrorInfoList::const_iterator iError;
				for (iError = crlErrors.begin(); (iError != crlErrors.end()) &&
					(iError->error != CM_CRL_SIGNATURE_INVALID); ++iError)
					;

				// If the CRL's signature was valid, get the cached path and
				// return
				if (iError == crlErrors.end())
				{
					// Get the cached path and destroy the cached cert list
					iCert->GetRef().GetPath(issuerPath);
					delete pCachedCerts;

					// Add any errors to the supplied error list
					if (pErrors != NULL)
						pErrors->Splice(pErrors->end(), crlErrors);

					return cmlErr;
				}

				// Try the next cached cert
				++iCert;
			}

			// Delete the list of cached certs
			delete pCachedCerts;
		}
		catch (...) {
			delete pCachedCerts;
			throw;
		}
	}

	// Find and validate the CRL issuer
	cmlErr = findValidCRLIssuer(base(), sessionID, boundsFlag, issuersKey,
		issuerPath, pErrors, pValidationTime, performRevChecking);

	// Return if a path to the CRL issuer's cert could not be built
	if ((cmlErr != CM_NO_ERROR) && (cmlErr != CM_PATH_VALIDATION_ERROR))
		return cmlErr;
	
	// Validate the CRL
	short valErr = Validate(sessionID, issuersKey, pErrors);
	if ((cmlErr == CM_NO_ERROR) && (valErr == CM_NO_ERROR))
		return CM_NO_ERROR;

	return CM_PATH_VALIDATION_ERROR;
}

/////////////////////////////////////////////////////////////////////////
// FUNCTION:  CRL::Validate
// 
// Description: Validate path using the issuers key
//
// Inputs: 
//   ulong            sessionID       - CML Session ID
//   ValidatedKey&    issuersKey      - Key of issueing certificate
//	  const ASN::Time* pValidationTime - Optional. Points to a date/time  
//                                      that must be used when checking
//                                      revocation status
//
// Outputs:
//    ErrorInfoList*  pErrors         - List of errors found while validating
//
// Return Value: 
//	   short           result          - result of Validation checking
//
///////////////////////////////////////////////////////////////////////////
short CRL::Validate(ulong sessionID, const ValidatedKey& issuersKey,
					ErrorInfoList* pErrors, 
					const ASN::Time* pValidationTime) const
{
	ErrorInfoList crlErrors;

	// Check that the two signature algorithms on the CRL are the same
	if (signature != algorithm)
	{
		if (pErrors == NULL)
			return CM_PATH_VALIDATION_ERROR;
		else
			crlErrors.AddError(CM_CRL_SIG_ALG_MISMATCH, issuer);
	}

	// Check the signature on the CRL
	try {
		short cmlError = VerifySignature(sessionID, issuersKey);
		if (cmlError != CM_NO_ERROR)
		{
			if (pErrors == NULL)
				return CM_PATH_VALIDATION_ERROR;
			else
			{
				if (cmlError == CM_NO_TOKENS_SUPPORT_SIG_ALG)
					cmlError = CM_NO_TOKENS_SUPPORT_CRL_SIG_ALG;
				else
					cmlError = CM_CRL_SIGNATURE_INVALID;
				crlErrors.AddError(cmlError, issuer);
			}
		}
	}
	catch (...) {
		if (pErrors == NULL)
			return CM_PATH_VALIDATION_ERROR;
		else
			crlErrors.AddError(CM_CRL_SIGNATURE_INVALID, issuer);
	}

	// Check that the CRL is still current
	if (nextUpdate != NULL)
	{
		ASN::Time adjustedTime(time(NULL) - GetCRLGracePeriod(sessionID));
		// If time stamp time is set, use it for comparison
		if (pValidationTime != NULL)
			adjustedTime = *pValidationTime;
		if (adjustedTime > *nextUpdate)
		{
			if (pErrors == NULL)
				return CM_PATH_VALIDATION_ERROR;
			else
				crlErrors.AddError(CM_CRL_OUT_OF_DATE, issuer, *nextUpdate);
		}
	}

	// Check that there aren't any unrecognized critical extensions
	ASN::UnknownExtensions::const_iterator i = crlExts.unknownExts.begin();
	for ( ; i != crlExts.unknownExts.end(); i++)
	{
		if (i->critical)
		{
			if (pErrors == NULL)
				return CM_PATH_VALIDATION_ERROR;
			else
				crlErrors.AddError(CM_UNRECOGNIZED_CRITICAL_CRL_EXT, issuer,
					i->OID());
		}
	}

	// Check that this validated key may be used to sign CRLs
	if ((issuersKey.pKeyUsage != NULL) &&
		!issuersKey.pKeyUsage->GetBit(SNACC::KeyUsage::cRLSign))
	{
		if (pErrors == NULL)
			return CM_PATH_VALIDATION_ERROR;
		else
			crlErrors.AddError(CM_INVALID_KEY_USE, issuer);
	}

	// Return CM_NO_ERROR if no errors have occurred
	if (crlErrors.empty())
		return CM_NO_ERROR;

	// Add the errors to the supplied error list
	if (pErrors != NULL)
		pErrors->Splice(pErrors->end(), crlErrors);
	return CM_PATH_VALIDATION_ERROR;
}


short CRL::VerifySignature(ulong sessionID,
						   const ValidatedKey& signersKey) const
{
	SignedAsnObj signedCrl(encCrl);
	return signedCrl.VerifySignature(sessionID, signersKey);
}


bool CRL::IsIssuer(const ASN::Cert& issuer) const
{
	// Check that CRL issuer's name matches the cert issuer's name
	if (base().issuer != issuer.subject)
		return false;

	// Check that the signature and public key algorithms are consistent
	if (issuer.pubKeyInfo != SplitSigHashAlg(base().signature.algorithm))
		return false;

	// Check that the authority key identifier if present matches the issuer
	if (base().crlExts.pAuthKeyID != NULL)
	{
		const ASN::AuthKeyIdExtension& authID = *base().crlExts.pAuthKeyID;

		// If the key identifier member is present, check it against the
		// issuer's subject key identifier
		if ((authID.keyID != NULL) && (issuer.exts.pSubjKeyID != NULL))
		{
			if (*authID.keyID != *issuer.exts.pSubjKeyID)
				return false;
		}

		// If the issuer name is present, check it against the issuer's
		// issuer name
		if ((authID.authCertIssuer != NULL) &&
			!authID.authCertIssuer->IsPresent(issuer.issuer))
			return false;

		// If the serial number is present, check it against the issuer's
		// serial number
		if ((authID.authCertSerialNum != NULL) &&
			(*authID.authCertSerialNum != issuer.serialNumber))
			return false;
	}

	// Check that the issuer's key is authorized to sign CRLs
	if ((issuer.exts.pKeyUsage != NULL) &&
		!issuer.exts.pKeyUsage->GetBit(SNACC::KeyUsage::cRLSign))
		return false;

	return true;
}

/////////////////////////////////////
// CrlSession class implementation //
/////////////////////////////////////
CrlSession::CrlSession(const ulong cmlSessionID, time_t crlCacheTTL, time_t crlGracePeriod,
					   RevCallbackFunctions& revFuncs, const CallbackFunctions& srlFuncs)
{
	// Initialize members
	crlLibHandle = NULL;
	sessionID = 0;
		
	// Link to the CRL
	crlLibHandle = link2CRL(gCrlLibName, sessionID, cmlSessionID, crlCacheTTL, crlGracePeriod,
		revFuncs, srlFuncs);
	revFuncs.extRevHandle = &sessionID;
}


CrlSession::~CrlSession()
{
#ifndef ENABLE_STATIC
	// Release the SRL library
	if (crlLibHandle != NULL)
		FreeLibrary((HINSTANCE)crlLibHandle);
#endif //ENABLE_STATIC
}


void CrlSession::Release()
{
	if (crlLibHandle != NULL)
		unlinkCRL((HINSTANCE)crlLibHandle, &sessionID);
}


void CrlSession::EmptyCache() const
{
#ifndef ENABLE_STATIC
	if (crlLibHandle != NULL)
	{
#ifdef HPUX32
		PExtCRLEmptyCacheFn fpCRLEmptyCache;
		shl_findsym((HINSTANCE*)&crlLibHandle, "CRL_EmptyCRLCache", TYPE_PROCEDURE, &fpCRLEmptyCache);
		
#else
		PExtCRLEmptyCacheFn fpCRLEmptyCache = (PExtCRLEmptyCacheFn)GetProcAddress((HINSTANCE)crlLibHandle,"CRL_EmptyCRLCache");
#endif
		if (fpCRLEmptyCache != NULL)
			fpCRLEmptyCache(sessionID);
	}
#else //ENABLE_STATIC
	CRL_EmptyCRLCache(sessionID);
#endif //ENABLE_STATIC

}


////////////////////////////
// findCRLIssuerInCache() //
////////////////////////////
CachedCertList* findCRLIssuerInCache(const CRL& crl, ulong sessionID)
{
	// Acquire a read lock to the session
	ASN::ReadLock cacheLock = AcquireSessionReadLock(sessionID);

	// Find all of the cached certs with the CRL issuer's DN
	CachedCertList* pCertList = GetCertCache(sessionID).Find(crl.base().issuer,
		false);

	// Remove the list any cached certs that couldn't have signed the CRL
	if (pCertList != NULL)
	{
		CachedCertList::iterator iCert = pCertList->begin();
		while (iCert != pCertList->end())
		{
			if (!crl.IsIssuer(iCert->GetRef().base()))
			{
				// Remove this cert from the list
				iCert = pCertList->erase(iCert);
			}
			else	// Move to the next cert in the list
				++iCert;
		}
	}

	return pCertList;

} // end of findCRLIssuerInCache()


/////////////////////
// findCRLIssuer() //
/////////////////////
short findCRLIssuer(const CertificateList& crl, ulong sessionID,
					SearchBounds searchFlag, CertList& certList)
{
	// Get the signature algorithm used to sign the CRL
	const char* pSigAlg = SplitSigHashAlg(crl.signature.algorithm);
	if (pSigAlg == NULL)
		throw CML_ERR(CM_NOT_IMPLEMENTED);

	// Fill in the CertMatchData
	CertMatchData matchInfo;
	memset(&matchInfo, 0, sizeof(CertMatchData));
	SNACC::AsnOid pubKeyOID(pSigAlg);
	matchInfo.pPubKeyOID = &pubKeyOID;
	matchInfo.canSignCRLs = true;
	if (crl.crlExts.pAuthKeyID != NULL)
	{
		matchInfo.pSubjKeyID = crl.crlExts.pAuthKeyID->keyID;
		if (crl.crlExts.pAuthKeyID->authCertIssuer != NULL)
		{
			GenNames::const_iterator iGN =
				crl.crlExts.pAuthKeyID->authCertIssuer->Find(GenName::X500);
			if (iGN != crl.crlExts.pAuthKeyID->authCertIssuer->end())
			{
				matchInfo.pIssuer = iGN->GetName().dn;
				matchInfo.pSerialNum = crl.crlExts.pAuthKeyID->authCertSerialNum;
			}
		}
	}

	// Request the issuer cert(s)
	ASN::BytesList encCertList;
	short cmlErr = RequestCerts(sessionID, encCertList, crl.issuer, searchFlag,
		&matchInfo);
	if (cmlErr != CM_NO_ERROR)
		return cmlErr;

	// Decode each of the issuer certs and add them to the list
	ASN::BytesList::const_iterator i; 
	for (i = encCertList.begin(); i != encCertList.end(); ++i)
	{
		try {
			certList.push_back(*i);
		}
		catch (...) {
			// Skip over this cert
		}
   }

	// If the CRL contains an authority key identifier extension with a
	// key identifier, move to the head of the list any certs which include a
	// subject key identifier and give preference to certs that are self signed
	// as well
	if ((crl.crlExts.pAuthKeyID != NULL) &&
		(crl.crlExts.pAuthKeyID->keyID != NULL))
	{
		CertList::iterator iCert = certList.begin();
		CertList::iterator iInsertLoc = certList.begin();
		while (iCert != certList.end())
		{
			if (iCert->base().exts.pSubjKeyID != NULL)
			{
				if (iCert != iInsertLoc)
					// but do not put it before any certs that
					// are self signed and have a key identifier.
					while (iInsertLoc != certList.end())
					{
						if ((iInsertLoc->base().exts.pSubjKeyID) && 
							(iInsertLoc->base().subject == iInsertLoc->base().issuer))
							iInsertLoc++;
						else
						{
                     // Splice self signed certs at beginning of list, all others
                     // get spliced at insertLoc.
                     if (iCert->base().subject == iCert->base().issuer)
                        certList.splice(certList.begin(), certList, iCert++);
                     else
                        certList.splice(iInsertLoc, certList, iCert++);
							break;
						}
					}
				else
				{
					++iCert;
					// advance to the insert location to the next cert only if the 
					// insert location is a cert key id and is self signed
					if ((iInsertLoc != certList.end()) &&
						(iInsertLoc->base().exts.pSubjKeyID) && 
						(iInsertLoc->base().subject == iInsertLoc->base().issuer))
							iInsertLoc++;				
            }
			}
			else
				++iCert;
		}
	}

   if (certList.empty())
		return CM_NOT_FOUND;

	return CM_NO_ERROR;
} // end of findCRLIssuer()



/////////////////////////////////////////////////////////////////////////
// FUNCTION:  findValidCRLIssuer
// 
// Description: Out of a list of certs, find a valid Issuer for the CRL
//
// Inputs: 
//
//   CertificateList& crl		           - List of crl issuer certificates
//	  ulong            sessionID          - CML Session ID
//   SearchBounds     boundsFlag         - Search local, remote, both 
//	                                        or until found
//	  bool	          performRevChecking - If true, perform revocation checking
//	  const ASN::Time* pValidationTime    - Optional. Points to a date/time  
//                                         that must be used when checking
//                                         revocation status
//
// Outputs:
//
//	   ErrorInfoList*  pErrors            -  List of errors
//	   CertPath&	    issuersPath        - Empty CertPath to be filled in
//	   ValidatedKey&   issuersKey         - To be filled in with validation info

// Return Value: 
//    short           result             - result of Validation checking
//
////////////////////////////////////////////////////////////////////////////////
short findValidCRLIssuer(const CertificateList& crl, ulong sessionID,
						 SearchBounds boundsFlag, ValidatedKey& issuersKey,
						 CertPath& issuersPath, ErrorInfoList* pErrors,
						 const ASN::Time* pValidationTime, bool performRevChecking )
{
	// Find the CRL issuer's certificate(s)
	CertList certList;
	short cmlErr = findCRLIssuer(crl, sessionID, boundsFlag, certList);
	if (cmlErr != CM_NO_ERROR)
	{
		if (pErrors != NULL)
			pErrors->AddError(CM_ISSUER_CERT_NOT_FOUND, crl.issuer);
		return CM_NO_PATH_FOUND;
	}

	// Try to validate the CRL issuer's certificate(s)
	ErrorInfoList issuerErrors;
	CertList::const_iterator iCert = certList.begin();
	cmlErr = CM_PATH_VALIDATION_ERROR;
	while ((iCert != certList.end()) && (cmlErr != CM_NO_ERROR))
	{
		try {
			issuerErrors.clear();
				
			// Validate the CRL issuer's certificate
			cmlErr = iCert->Validate(sessionID, boundsFlag, &issuerErrors,
				&issuersKey, &issuersPath, pValidationTime, performRevChecking);
		}
		catch (...) {
			// Skip this cert
		}

		// Move to the next cert in the list
		++iCert;
	}

	// Add any path building/validation errors to the supplied error list
	if (pErrors != NULL)
		pErrors->Splice(pErrors->end(), issuerErrors);

	return cmlErr;
} // end of findValidCRLIssuer()


////////////////
// link2CRL() //
////////////////
HINSTANCE link2CRL(const char* libName, ulong& sessionID, const ulong cmlSessionID,
				   const time_t crlCacheTTL, const time_t crlGracePeriod,
				   RevCallbackFunctions& revFuncs, const CallbackFunctions& srlFuncs)
{
	HINSTANCE hDLL = NULL;
#ifndef ENABLE_STATIC
	// Check parameters
	if (libName == NULL)
		throw CML_ERR(CM_NULL_POINTER);

	// Load the CRL library
	hDLL = LoadLibrary(libName);
	if (hDLL == NULL)
		throw CML_ERR(CM_CRL_INITIALIZATION_FAILED);

	// Set the callback function pointers
#ifdef HPUX32
	shl_findsym(&hDLL, "CRL_RequestRevokeStatus", TYPE_PROCEDURE,
		&revFuncs.pCheckStatus);
	shl_findsym(&hDLL, "CRL_FreeRevokeStatus", TYPE_PROCEDURE,
		&revFuncs.pFreeStatus);

	PExtCRLInitFn fpCRLInit;
	shl_findsym(&hDLL, "CRL_Init", TYPE_PROCEDURE, &fpCRLInit);

#else
	revFuncs.pCheckStatus = (ExtCheckRevStatusFP)GetProcAddress(hDLL,
		"CRL_RequestRevokeStatus");
	revFuncs.pFreeStatus = (ExtFreeRevStatusFP)GetProcAddress(hDLL,
		"CRL_FreeRevokeStatus");

	PExtCRLInitFn fpCRLInit = (PExtCRLInitFn)GetProcAddress(hDLL,"CRL_Init");

#endif

	if ((revFuncs.pCheckStatus == NULL) || (revFuncs.pFreeStatus == NULL) ||
		(fpCRLInit == NULL))
	{
		FreeLibrary(hDLL);
		throw CML_ERR(CM_CRL_INITIALIZATION_FAILED);
	}

#else //ENABLE_STATIC
	revFuncs.pCheckStatus = CRL_RequestRevokeStatus;
	revFuncs.pFreeStatus = CRL_FreeRevokeStatus;
	PExtCRLInitFn fpCRLInit = CRL_Init;
#endif //ENABLE_STATIC

	CRLDLLInitSettings_struct crlSettings;
	crlSettings.boundsFlag = CM_SEARCH_UNTIL_FOUND;
	crlSettings.cmlSessionID = cmlSessionID;
	if (crlCacheTTL != 0)
		crlSettings.crlRefreshPeriod = crlCacheTTL;
	else
		crlSettings.crlRefreshPeriod = SECONDS_IN_DAY;
	crlSettings.crlList = NULL;
	crlSettings.srlFuncs = (SRLCallbackFunctions*)&srlFuncs;
	if (crlGracePeriod != 0)
		crlSettings.crlGracePeriod = crlGracePeriod;
	else
		crlSettings.crlGracePeriod = 0;

	// Initialize the CRL service
	short crlErr = fpCRLInit(&sessionID, &crlSettings);
	if (crlErr != CRL_SUCCESS)
	{
#ifndef ENABLE_STATIC
		FreeLibrary(hDLL);
#endif
		throw CML_ERR(CM_CRL_INITIALIZATION_FAILED);
	}

	return hDLL;
} // end of link2CRL()


/////////////////
// unlinkCRL() //
/////////////////
void unlinkCRL(HINSTANCE hDLL, ulong* pSessionID)
{
	// Destroy the CRL session
	if (pSessionID != NULL)
	{
		PExtCRLDestroyFn fpCRLDestroy = NULL;

#ifdef ENABLE_STATIC
		fpCRLDestroy = (PExtCRLDestroyFn)CRL_Destroy;
#elif defined(HPUX32)
		shl_findsym(&hDLL, "CRL_Destroy", TYPE_PROCEDURE, &fpCRLDestroy);
#else
		fpCRLDestroy = (PExtCRLDestroyFn)GetProcAddress(hDLL, "CRL_Destroy");
#endif

		if (fpCRLDestroy != NULL)
			fpCRLDestroy(pSessionID);
	}
}



// end of CM_crl.cpp
