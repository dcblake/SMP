/*****************************************************************************
File:     CM_infc.cpp
Project:  Certificate Management Library
Contents: Many of the API functions and some low-level functions to manage
		  session creation and deletion, and other miscellaneous functions.

Created:  March 1997
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	18 May 2004

Version:  2.4

Description: This file contains the following CM API functions:
			 CM_CreateSession
			 CM_CreateSessionExt
			 CM_DestroySession
			 CM_GetCertID
			 CM_GetEncodedDN
			 CM_GetErrInfo
			 CM_SetPolicy
			 CML::SetTrustedCerts
			 CM_SetTrustedCerts
			 CML::SetTrustAnchors
			 CM_ValidateSignature
*****************************************************************************/


////////////////////
// Included Files //
////////////////////
#include "CM_cache.h"


// Using declarations
using namespace CML;
using namespace CML::Internal;
using CML::ASN::Bytes;
using CML::ASN::GenName;


///////////////////////
// Defined Constants //
///////////////////////
const time_t DEFAULT_CACHE_TTL	= 86400;	// Seconds in 1 day (60 * 60 * 24)


//////////////////////
// Type Definitions //
//////////////////////
typedef struct
{
	void				*extHandle;	/* Handle to external library for callbacks */
	ExtGetObjFuncPtr	pGetObj;	/* External get callback function pointer*/
	ExtUrlGetObjFuncPtr	pUrlGetObj;	/* External URL get callback function pointer */
	ExtFreeObjFuncPtr	pFreeObj;	/* External free callback function pointer */
	void				*pTokenObj;	/* Pointer to crypto token object */
	RevocationPolicy	revPolicy;  /* How certificate revocation is to be done */
	EncCert_LL			*trustedCerts; /* The list of trusted certs for the session */
	ushort				nCacheSize;	/* Maximum number of certs to store in cache */
	time_t				cacheTTL;	/* Maximum time that certs will be cached */
	ushort				nMaxPaths;	/* Maximum number of paths to try and build */
} v1InitSettings_struct;

typedef struct
{
	size_t				cbSize;		/* Size of this structure (in bytes) */
	void*				extHandle;	/* Handle to retrieval callback library */
	ExtGetObjFuncPtr	pGetObj;	/* External get callback function pointer*/
	ExtUrlGetObjFuncPtr	pUrlGetObj;	/* External URL get callback function pointer */
	ExtFreeObjFuncPtr	pFreeObj;	/* External free callback function pointer */
	void*				pTokenObj;	/* Pointer to crypto token object */
	RevocationPolicy	revPolicy;  /* How certificate revocation is to be done */
	EncCert_LL*			trustedCerts;	/* List of trusted certs for the session */
	ushort		nCertCacheSize;		/* Maximum number of certs to store in cache */
	time_t		certCacheTTL;		/* Maximum time that certs will be cached */
	ushort		nMaxPaths;			/* Maximum number of paths to try and build */
	ushort		nCrlCacheSize;		/* Maximum number of CRLs to store in cache */
	time_t		crlCacheTTL;		/* Maximum time that CRLs will be cached */
} v2InitSettings_struct;

/* Cryptographic Token Interface Library (CTIL) bit mask */
typedef struct
{
	unsigned int defCTIL	: 1;	/* Default CTIL */
	unsigned int cryptopp	: 1;	/* Crypto++ CTIL */
	unsigned int msCapi 	: 1;	/* Microsoft CAPI CTIL */
	unsigned int pkcs11 	: 1;	/* PKCS #11 CTIL */
	unsigned int bsafe		: 1;	/* RSA BSAFE CTIL */
} CryptoTokenBitMask;

typedef struct
{
	size_t				cbSize;		/* Size of this structure (in bytes) */
	void*				extHandle;	/* Handle to retrieval callback library */
	ExtGetObjFuncPtr	pGetObj;	/* External get callback function pointer*/
	ExtUrlGetObjFuncPtr	pUrlGetObj;	/* External URL get callback function pointer */
	ExtFreeObjFuncPtr	pFreeObj;	/* External free callback function pointer */
	void*				pTokenObj;	/* Pointer to crypto token object */
	RevocationPolicy	revPolicy;  /* How certificate revocation is to be done */
	EncCert_LL*	trustedCerts;		/* List of trusted certs for the session */
	ushort		nCertCacheSize;		/* Maximum number of certs to store in cache */
	time_t		certCacheTTL;		/* Maximum time that certs will be cached */
	ushort		nMaxPaths;			/* Maximum number of paths to try and build */
	ushort		nCrlCacheSize;		/* Maximum number of CRLs to store in cache */
	time_t		crlCacheTTL;		/* Maximum time that CRLs will be cached */
	CryptoTokenBitMask tokensToUse;	/* CTIL tokens to load and use */
} v3InitSettings_struct;	// First used in CML v2.3

/////////////////////////
// Function Prototypes //
/////////////////////////
ulong CMU_AddASession(const InitSettings_struct& settings);
short CMU_RemoveASession(ulong *sessionRefID);
static short cvtAsnBuf2BytesStruct(SNACC::AsnBuf buf, Bytes_struct **bytes);


/*  
Function: CM_CreateSession()
 This routine is called upon to start up a session with the certificate manager.
 The session returned is used in all further calls to the certificate
 manager.
 When you are done using the certificate manager make sure you release the
 session using the CM_DestroySession() routine.

 NOTE: At this time the routine is not full featured.

 parameters:

    cm_session (input/output) = ptr to storage for a session ref/context value.
       Will be filled in by this routine upon sucessful completion.

 returns:
    CM_NO_ERROR      - shut down fine
    CM_INVALID_PARAMETER   - bad paramenter sent to this routine

    other pass thru values from db routines.
    other pass thru values from configuration loading routines.

-----------------------------------------------------------------------
*/
short CM_CreateSession(ulong *cm_session)
{
	InitSettings_struct settings;
	memset(&settings, 0, sizeof(InitSettings_struct));
	settings.cbSize = sizeof(InitSettings_struct);
	settings.revPolicy = CM_REVCRL;
	settings.nCertCacheSize = DEFAULT_CACHE_OBJS;
	settings.certCacheTTL = DEFAULT_CACHE_TTL;
	settings.crlCacheTTL = DEFAULT_CACHE_TTL;

	return CM_CreateSessionExt(cm_session, &settings);

} // end of CM_CreateSession()


/*  
Function: CM_CreateSessionExt()
 This routine is called upon to start up a session with the certificate manager. This
 function is similar to the CM_CreateSession() function, but sets up the InitSettings
 structure.
 The session returned is used in all further calls to the certificate
 manager.
 When you are done using the certificate manager make sure you release the
 session using the CM_DestroySession() routine.

 NOTE: At this time the routine is not full featured.

 parameters:

    cm_session (input/output) = ptr to storage for a session ref/context value.
       Will be filled in by this routine upon sucessful completion.

    pSettings (input) = pointer to the InitSettings_struct structure
 returns:
    CM_NO_ERROR      - shut down fine
    CM_INVALID_PARAMETER   - bad paramenter sent to this routine

    other pass thru values from db routines.
    other pass thru values from configuration loading routines.

-----------------------------------------------------------------------
*/
short CM_CreateSessionExt(ulong *cm_session, InitSettings_struct *pSettings)
{
	// Check parameters
	if ((cm_session == NULL) || (pSettings == NULL))
		return CM_INVALID_PARAMETER;

	// Initialize result
	*cm_session = 0;

	try {
		// Create a new session using the InitSettings_struct
		// Convert the structure if necessary
		switch (pSettings->cbSize)
		{
		case sizeof(InitSettings_struct):
			// Create the session
			*cm_session = CMU_AddASession(*pSettings);
			break;

		case sizeof(v3InitSettings_struct):
			{
				// Copy the old settings into a new structure
				v3InitSettings_struct& v3Settings =
					*(v3InitSettings_struct*)pSettings;

				// Check if any CTILs are present or requested
				if (v3Settings.pTokenObj != NULL)
					return CM_INVALID_PARAMETER;
				if (v3Settings.tokensToUse.defCTIL ||
					v3Settings.tokensToUse.cryptopp ||
					v3Settings.tokensToUse.msCapi ||
					v3Settings.tokensToUse.pkcs11 ||
					v3Settings.tokensToUse.bsafe)
					return CM_INVALID_PARAMETER;

				InitSettings_struct curSettings;
				memset(&curSettings, 0, sizeof(InitSettings_struct));
				curSettings.cbSize = sizeof(InitSettings_struct);
				curSettings.extHandle = v3Settings.extHandle;
				curSettings.pGetObj = v3Settings.pGetObj;
				curSettings.pUrlGetObj = v3Settings.pUrlGetObj;
				curSettings.pFreeObj = v3Settings.pFreeObj;
				curSettings.revPolicy = v3Settings.revPolicy;
				curSettings.trustedCerts = v3Settings.trustedCerts;
				curSettings.nCertCacheSize = v3Settings.nCertCacheSize;
				curSettings.certCacheTTL = v3Settings.certCacheTTL;
				curSettings.nMaxPaths = v3Settings.nMaxPaths;
				curSettings.nCrlCacheSize = v3Settings.nCrlCacheSize;
				curSettings.crlCacheTTL = v3Settings.crlCacheTTL;

				// Create the session
				*cm_session = CMU_AddASession(curSettings);
			}
			break;

		case sizeof(v2InitSettings_struct):
			{
				// Copy the old settings into a new structure
				v2InitSettings_struct& v2Settings =
					*(v2InitSettings_struct*)pSettings;

				// Check if any CTILs are present
				if (v2Settings.pTokenObj != NULL)
					return CM_INVALID_PARAMETER;

				InitSettings_struct curSettings;
				memset(&curSettings, 0, sizeof(InitSettings_struct));
				curSettings.cbSize = sizeof(InitSettings_struct);
				curSettings.extHandle = v2Settings.extHandle;
				curSettings.pGetObj = v2Settings.pGetObj;
				curSettings.pUrlGetObj = v2Settings.pUrlGetObj;
				curSettings.pFreeObj = v2Settings.pFreeObj;
				curSettings.revPolicy = v2Settings.revPolicy;
				curSettings.trustedCerts = v2Settings.trustedCerts;
				curSettings.nCertCacheSize = v2Settings.nCertCacheSize;
				curSettings.certCacheTTL = v2Settings.certCacheTTL;
				curSettings.nMaxPaths = v2Settings.nMaxPaths;
				curSettings.nCrlCacheSize = v2Settings.nCrlCacheSize;
				curSettings.crlCacheTTL = v2Settings.crlCacheTTL;

				// Create the session
				*cm_session = CMU_AddASession(curSettings);
			}
			break;

		default:
			{
				// Copy the old settings into a new structure
				v1InitSettings_struct& oldSettings =
					*(v1InitSettings_struct*)pSettings;

				// Check if any CTILs are present
				if (oldSettings.pTokenObj != NULL)
					return CM_INVALID_PARAMETER;

				InitSettings_struct curSettings;
				memset(&curSettings, 0, sizeof(InitSettings_struct));
				curSettings.cbSize = sizeof(InitSettings_struct);
				curSettings.extHandle = oldSettings.extHandle;
				curSettings.pGetObj = oldSettings.pGetObj;
				curSettings.pUrlGetObj = oldSettings.pUrlGetObj;
				curSettings.pFreeObj = oldSettings.pFreeObj;
				curSettings.revPolicy = oldSettings.revPolicy;
				curSettings.trustedCerts = oldSettings.trustedCerts;
				curSettings.nCertCacheSize = oldSettings.nCacheSize;
				curSettings.certCacheTTL = oldSettings.cacheTTL;
				curSettings.nMaxPaths = oldSettings.nMaxPaths;

				// Create the session
				*cm_session = CMU_AddASession(curSettings);
			}
			break;
		}

		return CM_NO_ERROR;
	}
	catch (ASN::Exception& cmlErr) {
		return cmlErr;
	}
	catch (SNACC::SnaccException& ) {
		return CM_ASN_ERROR;
	}
	catch (...) {
		RETURN(CM_UNKNOWN_ERROR);
	}
} // end of CM_CreateSessionExt()


/************************************************************************
 FUNCTION:  CM_DestroySession()
 
 Description: This function terminates a session with the Certificate
 Management Library that was previously created with a call to
 CM_CreateSession() or CM_CreateSessionExt().  The contents of the 
 session parameter will be set to zero.
*************************************************************************/
short CM_DestroySession(ulong *cm_session)
{
	if (cm_session == NULL)
		return CM_INVALID_PARAMETER;

	return CMU_RemoveASession(cm_session);
}


/************************************************************************
 FUNCTION:  CM_SetPolicy()
 
 Description: This function set the initial path processing settings for
 the specified session.
*************************************************************************/
short CM_SetPolicy(ulong cm_session, PolicyData_struct *polyData)
{
	// Check parameters
	if (polyData == NULL)
		return CM_INVALID_PARAMETER;

	try {
		ASN::OIDList policyList;
		Policy_struct* pTemp = polyData->initialPolicy;
		while (pTemp != NULL)
		{
			policyList.push_back(pTemp->policy_id);
			pTemp = pTemp->next;
		}

		if (policyList.empty())
			policyList.push_back(SNACC::anyPolicy);

		CML::SetPolicy(cm_session, policyList,
			(polyData->reqExplicitPol != FALSE),
			(polyData->inhibitPolMapping != FALSE),
			(polyData->inhibitAnyPolicy != FALSE));

		return CM_NO_ERROR;
	}
	catch (ASN::Exception& cmlErr) {
		return cmlErr;
	}
	catch (SNACC::SnaccException& ) {
		return CM_ASN_ERROR;
	}
	catch (...) {
		RETURN(CM_UNKNOWN_ERROR);
	}
} // end of CM_SetPolicy()


/************************************************************************
 FUNCTION:  CM_ValidateSignature()
 
 Description: This function verifies the signature on an arbitrary ASN.1
 encoded object using the supplied public key.  The object must be of
 the SIGNED parameterized type.
*************************************************************************/
short CM_ValidateSignature(ulong sessionID, Bytes_struct* asnPtr,
						   ValidKey_struct* valPubKey)
{
	if ((asnPtr == NULL) || (asnPtr->data == NULL) || (valPubKey == NULL))
		return CM_INVALID_PARAMETER;

	try {
		Bytes encData(asnPtr->num, asnPtr->data);

		SignedAsnObj signedObj(encData);
		return signedObj.VerifySignature(sessionID, *valPubKey);
	}
	catch (ASN::Exception& cmlErr) {
		return cmlErr;
	}
	catch (SNACC::SnaccException& ) {
		return CM_ASN_ERROR;
	}
	catch (...) {
		RETURN(CM_UNKNOWN_ERROR);
	}
}


/************************************************************************
 FUNCTION:  CM_GetCertID()
 
 Description: This function retrieves the ASN.1 encoded issuer DN, serial
 number, and subject key identifier from the specified certificate.
 If the subject key identifier extension is not present in the 
 certificate, the subjectUniqueIdentifier, if present, is returned
 (encoded in an OCTET STRING).  If neither are present and the
 certificate is a Fortezza version 1 certificate, the Fortezza Key
 Material Identifier (KMID), encoded in an OCTET STRING, is returned,
 otherwise NULL is returned.
*************************************************************************/
short CM_GetCertID(Bytes_struct* asn1cert, Bytes_struct **issuerDN,
				   Bytes_struct **serialNum, Bytes_struct **subjID)
{
	// Check parameters
	if ((asn1cert == NULL) || (asn1cert->data == NULL) || (issuerDN == NULL) ||
		(serialNum == NULL) || (subjID == NULL))
		return CM_INVALID_PARAMETER;
	
	// Initialize results
	*issuerDN = NULL;
	*serialNum = NULL;
	*subjID = NULL;
	
	try {
		// Convert the encoded cert to a Bytes object
		Bytes tmpBytes(asn1cert->num, asn1cert->data);
		
		// Decode the certificate
		ASN::Cert cert(tmpBytes);
			
		try {
			// Encode the issuer name and serial number
			SNACC::AsnBuf tmpBuf;
			cert.issuer.Encode(tmpBytes);
			*issuerDN = tmpBytes.GetBytesStruct();
			
			cert.serialNumber.BEnc(tmpBuf);
			short err = cvtAsnBuf2BytesStruct(tmpBuf, serialNum);
			if (err != CM_NO_ERROR)
				throw CML_ERR(CM_NULL_POINTER);

			// If the Subject Key Identifier Extension is present, encode it.
			// If not, and this is a Fortezza v1 cert, use the KMID
			if (cert.exts.pSubjKeyID != NULL)
			{
				short err = CM_NO_ERROR;
				tmpBuf.ResetMode(std::ios_base::out);
				
				cert.exts.pSubjKeyID->BEnc(tmpBuf);
				err = cvtAsnBuf2BytesStruct(tmpBuf, subjID);
				if (err != CM_NO_ERROR)
					throw CML_ERR(CM_NULL_POINTER);
			}
			else if ((cert.pubKeyInfo == gDSA_KEA_OID) && (cert.version == 0))
			{
				Pub_key_struct cmPubKey;
				cert.pubKeyInfo.FillPubKeyStruct(cmPubKey);
				if (cmPubKey.key.combo == NULL)
					throw CML_ERR(CM_NULL_POINTER);
				
				try {
					tmpBytes.Set(CM_KMID_LEN, cmPubKey.key.combo->kmid);
					*subjID = tmpBytes.GetBytesStruct();
				}
				catch (...) {
					CMASN_FreePubKeyContents(&cmPubKey);
					throw;
				}
			}
			
			return CM_NO_ERROR;
		}
		catch (...) {
			CM_FreeBytes(issuerDN);
			CM_FreeBytes(serialNum);
			CM_FreeBytes(subjID);
			throw;
		}
	}
	catch (ASN::Exception& cmlErr) {
		return cmlErr;
	}
	catch (SNACC::SnaccException& ) {
		return CM_ASN_ERROR;
	}
	catch (...) {
		RETURN(CM_UNKNOWN_ERROR);
	}
}


/////////////////////////////////////////
// TokenException class implementation //
/////////////////////////////////////////
TokenException::TokenException(unsigned long errCode, const char* fileName,
							   long lineNum, bool isWinError) :
ASN::ExceptionString(CM_CRYPTO_TOKEN_ERROR, fileName, lineNum, NULL, NULL),
errorCode(errCode), isWindowsError(isWinError)
{
	// Build the hexadeceimal string version of the error code
	char tmp[10];
	sprintf(tmp, "%x", errorCode);

	// Build the error string
	m_whatStr = CMU_GetErrorString(CM_CRYPTO_TOKEN_ERROR);
	m_whatStr += " 0x";
	m_whatStr += tmp;
	if (isWindowsError)
		m_whatStr += " (see winerror.h)";
	else // PKCS#11
		m_whatStr += " (see pkcs11t.h)";
}


////////////////////////////////////////
// ErrorInfoList class implementation //
////////////////////////////////////////
bool ErrorInfoList::AddError(short errCode, const ASN::DN& dn,
							 const char* optInfo)
{
	// Create temporary error
	ErrorInfo tempErr(errCode, dn, optInfo);

	for (iterator i = begin(); i != end(); i++)
	{
		if (*i == tempErr)
			return false;
	}

	// Add the error to the list
	push_back(tempErr);
	return true;
}


bool ErrorInfoList::AddError(short errCode, const ASN::Cert& subjCert,
			  const char* optInfo)
{
	// Create temporary error
	ErrorInfo tempErr(errCode, subjCert, optInfo);

	for (iterator i = begin(); i != end(); i++)
	{
		if (*i == tempErr)
			return false;
	}

	// Add the error to the list
	push_back(tempErr);
	return true;
}


bool ErrorInfoList::AddError(const RevInfo& revInfo, const ASN::Cert& revCert)
{
	// Initialize default revocation error and additional info string
	short revErr = CM_CERT_REVOKED;
	char revStr[CM_TIME_LEN + 1];
	if (revInfo.revDate)
	{
		memcpy(revStr, revInfo.revDate, CM_TIME_LEN);
		revStr[CM_TIME_LEN] = 0;
	}
	else
		revStr[0] = 0;
	
	// If the reason code is present, use its value as the error
	if (revInfo.revReason)
	{
		switch ((int)*(revInfo.revReason))
		{
		case SNACC::CRLReason::keyCompromise:
		case SNACC::CRLReason::cACompromise:
			revErr = CM_KEY_COMPROMISED;
			break;
		case SNACC::CRLReason::affiliationChanged:
			revErr = CM_CERT_AFFILIATION_CHANGED;
			break;
		case SNACC::CRLReason::superseded:
			revErr = CM_CERT_SUPERSEDED;
			break;
		case SNACC::CRLReason::cessationOfOperation:
			revErr = CM_CERT_NO_LONGER_NEEDED;
			break;
		case SNACC::CRLReason::certificateHold:
			revErr = CM_CERT_ON_HOLD;
			break;
		case SNACC::CRLReason::privilegeWithdrawn:
			revErr = CM_CERT_PRIVILEGE_WITHDRAWN;
			break;
		case SNACC::CRLReason::unspecified:
		case SNACC::CRLReason::removeFromCRL:	// only in delta CRLs
		case SNACC::CRLReason::aaCompromise:	// not used in CRLs
		default:
			break;	// just use generic error code
		}
	}

	// Add the error to the list
	bool result = AddError(revErr, revCert, revStr);

	// Add an error for each critical unknown extension that is present
	Unkn_extn_LL* pExt = revInfo.pRespExts;
	while(pExt)
	{
		if (pExt->critical)
		{
			AddError(CM_UNRECOGNIZED_CRITICAL_CRL_ENTRY_EXT, revCert,
				pExt->oid);
		}
		pExt = pExt->next;
	}

	return result;
}

bool ErrorInfoList::ErrorIsCRLOutOfDate(const ErrorInfoList& errorList) 
{
	// Return proper value when no errors are present
	if (errorList.empty())
		return false;

	ErrorInfoList::const_iterator iError;
	// Check each error to see if there are any errors other than CM_CRL_OUT_DATE
	// and CM_CRL_PATH_NOT_VALID. If so return status to caller.
	for (iError = errorList.begin(); iError != errorList.end(); ++iError)
	{
		if (iError->error != CM_CRL_OUT_OF_DATE)
			return false;
	}
	return true;
}
	
void ErrorInfoList::Insert(const ErrorInfoList& other)
{
	for (const_iterator i = other.begin(); i != other.end(); i++)
	{
		bool errorAlreadyExists = false;
		for (iterator j = begin(); (j != end()) && !errorAlreadyExists; j++)
		{
			if (*i == *j)
				errorAlreadyExists = true;
		}

		// If the error doesn't already exist in this list, add it
		if (!errorAlreadyExists)
			push_back(*i);
	}
}


void ErrorInfoList::Splice(iterator it, ErrorInfoList& other)
{
	// Remove from the other list any errors which are already present in
	// this list
	iterator i = other.begin();
	while (i != other.end())
	{
		iterator j;
		for (j = begin(); (j != end()) && (*i != *j); ++j)
			;

		if (j == end())
			++i;
		else
			i = other.erase(i);
	}

	// Call the base class to splice the remaining Errors into this list
	splice(it, other);
}


ErrorInfoList::operator ErrorInfo_List*() const
{
	ErrorInfo_List* pList = NULL;
	try {
		for (const_reverse_iterator i = rbegin(); i != rend(); i++)
		{
			ErrorInfo_List* pNew = *i;
			pNew->next = pList;
			pList = pNew;
		}
		return pList;
	}
	catch (...) {
		CM_FreeErrInfo(&pList);
		throw;
	}
}



////////////////////////////////////
// ErrorInfo class implementation //
////////////////////////////////////
ErrorInfo::ErrorInfo()
{
	error = CM_UNKNOWN_ERROR;
}

ErrorInfo::ErrorInfo(short errCode, const ASN::DN& errorDN,
					 const char* optInfo)
{
	error = errCode;
	*name.insert(name.end(), ASN::GenName()) = errorDN;
	if (optInfo != NULL)
		extraInfo = optInfo;
}


ErrorInfo::ErrorInfo(short errCode, const ASN::Cert& cert,
					 const char* optInfo)
{
	error = errCode;

	if (!cert.subject.IsEmpty())
		*name.insert(name.end(), ASN::GenName()) = cert.subject;
	else if (cert.exts.pSubjAltNames != NULL)
		name = *cert.exts.pSubjAltNames;

	if (optInfo != NULL)
		extraInfo = optInfo;
}


ErrorInfo::operator ErrorInfo_List*() const
{
	static GenName::Type nameFormTable[] = { GenName::X500, GenName::RFC822,
		GenName::DNS, GenName::URL, GenName::REG_OID, (GenName::Type)-1 };

	ErrorInfo_List* pResult = (ErrorInfo_List*)calloc(1, sizeof(ErrorInfo_List));
	if (pResult == NULL)
		throw CML_MEMORY_ERR;

	pResult->error = error;

	try {
		// Find the best name form to use for this subject.  The name form
		// search is prioritized to select certain name forms first
		// (see above table).
		for (GenName::Type* pNameType = nameFormTable; (pResult->dn == NULL) &&
			(*pNameType != (GenName::Type)-1); pNameType++)
		{
			ASN::GenNames::const_iterator iGN = name.Find(*pNameType);
			if (iGN != name.end())
			{
				switch (*pNameType)
				{
				case GenName::X500:
					if (iGN->GetName().dn == NULL)
						throw CML_ERR(CM_NULL_POINTER);
					pResult->dn = strdup(*iGN->GetName().dn);
					break;

				case GenName::RFC822:
				case GenName::DNS:
				case GenName::URL:
					if (iGN->GetName().name == NULL)
						throw CML_ERR(CM_NULL_POINTER);
					pResult->dn = strdup(iGN->GetName().name);
					break;

				case GenName::REG_OID:
					if (iGN->GetName().regID == NULL)
						throw CML_ERR(CM_NULL_POINTER);
					pResult->dn = strdup(*iGN->GetName().regID);
					break;
				}

				if (pResult->dn == NULL)
					throw CML_MEMORY_ERR;
			}
		} // end of for loop

		if (pResult->dn == NULL)
		{
			pResult->dn = strdup("<UNKNOWN>");
			if (pResult->dn == NULL)
				throw CML_MEMORY_ERR;
		}

		if (extraInfo.length() > 0)
		{
			pResult->xinfo = strdup(extraInfo.c_str());
			if (pResult->xinfo == NULL)
				throw CML_MEMORY_ERR;
		}

		return pResult;
	}
	catch (...) {
		CM_FreeErrInfo(&pResult);
		throw;
	}
}


bool ErrorInfo::operator==(const ErrorInfo& rhs) const
{
	if (this == &rhs)
		return true;

	return ((error == rhs.error) && (name == rhs.name) &&
		(extraInfo == rhs.extraInfo));
}


bool ErrorInfo::operator<(const ErrorInfo& rhs) const
{
	if (this == &rhs)
		return false;

	if (name < rhs.name)
		return true;
	else if (name > rhs.name)
		return false;

	if (error < rhs.error)
		return true;
	else if (error > rhs.error)
		return false;

	return (extraInfo < rhs.extraInfo);
}



short CM_GetEncodedDN(Bytes_struct* asn1cert, Bytes_struct **encodedDN)
{
	// Check parameters
	if ((asn1cert == NULL) || (asn1cert->data == NULL) || (encodedDN == NULL))
		return CM_INVALID_PARAMETER;

	// Initialize result
	*encodedDN = NULL;

	try {
		Bytes encCert(asn1cert->num, asn1cert->data);
		ASN::Cert cert(encCert);
		
		Bytes encDN;
		cert.subject.Encode(encDN);
		
		*encodedDN = encDN.GetBytesStruct();
		
		return CM_NO_ERROR;
	}
	catch (ASN::Exception& cmlErr) {
		return cmlErr;
	}
	catch (SNACC::SnaccException& ) {
		return CM_ASN_ERROR;
	}
	catch (...) {
		RETURN(CM_UNKNOWN_ERROR);
	}
}


/************************************************************************
 FUNCTION:  CML::SetTrustedCerts()
 
 Description:  This function loads the list of certificates into the
 cache as trust anchors for the given session.  If the list of extended
 errors is provided, any validation errors are stored in the list.
 CM_NO_ERROR is returned if all of the certificates load successfully.
 If any of the certificates have errors, then CM_TRUSTED_CERT_ERROR
 is returned.  Exceptions are thrown for fatal errors.
*************************************************************************/
short CML::SetTrustedCerts(ulong sessionID, const ASN::BytesList& trustedCerts,
						   ErrorInfoList* pErrInfo)
{
	// Check parameter
	if (trustedCerts.empty())
		throw CML_ERR(CM_INVALID_PARAMETER);

	// Empty error list if present
	if (pErrInfo != NULL)
		pErrInfo->clear();

	// Acquire global session lock
	ASN::ReadLock lock = AcquireSessionReadLock(sessionID);

	// Empty CRL cache if CrlSession was initialized by CM_CreateSession_Ext
	const CrlSession* pCRL = GetSessionFromRef(sessionID).GetCRLSession();
	if (pCRL)
		pCRL->EmptyCache();

	// Load the trusted certs
	return GetCertCache(sessionID).LoadTrustAnchors(trustedCerts, pErrInfo);

} // end of CML::SetTrustedCerts()


short CM_SetTrustedCerts(ulong sessionID, EncCert_LL* trustedCerts,
						 ErrorInfo_List** errInfo)
{
	// Check parameters
	if (trustedCerts == NULL)
		return CM_INVALID_PARAMETER;

	try {
		// Acquire global session lock
		ASN::ReadLock lock = AcquireSessionReadLock(sessionID);

		// Empty CRL cache if CrlSession was initialized by CM_CreateSession_Ext
		const CrlSession* pCRL = GetSessionFromRef(sessionID).GetCRLSession();
		if (pCRL)
			pCRL->EmptyCache();

		// Load the trusted certs
		return GetCertCache(sessionID).LoadTrustedCerts(trustedCerts, errInfo);
	}
	catch (ASN::Exception& cmlErr) {
		return cmlErr;
	}
	catch (SNACC::SnaccException& ) {
		return CM_ASN_ERROR;
	}
	catch (...) {
		RETURN(CM_UNKNOWN_ERROR);
	}
}


/************************************************************************
 FUNCTION:  CML::SetTrustAnchors()
 
 Description:  This function loads the list of trust anchors into the
 cache for the given session.  If the list of extended errors is provided,
 any validation errors are stored in the list.
 CM_NO_ERROR is returned if all of the certificates load successfully.
 If any of the certificates have errors, then CM_TRUSTED_CERT_ERROR
 is returned.  Exceptions are thrown for fatal errors.
*************************************************************************/
short CML::SetTrustAnchors(ulong sessionID,
						   const TrustAnchorList& trustAnchors,
						   ErrorInfoList* pErrInfo)
{
	try {
		// Acquire global session lock
		ASN::ReadLock lock = AcquireSessionReadLock(sessionID);
		
		// Load the trusted certs
		return GetCertCache(sessionID).LoadTrustAnchors(trustAnchors,
			pErrInfo);
	}
	catch (ASN::Exception& cmlErr) {
		return cmlErr;
	}
	catch (SNACC::SnaccException& ) {
		return CM_ASN_ERROR;
	}
	catch (...) {
		RETURN(CM_UNKNOWN_ERROR);
	}
}


short cvtAsnBuf2BytesStruct(SNACC::AsnBuf buf, Bytes_struct **bytes)
{
	if (buf.length() > 0)
	{
		*bytes = (Bytes_struct *)malloc (sizeof (Bytes_struct));
		if (*bytes == NULL)
			return CM_NULL_POINTER;
		(*bytes)->num = buf.length();
		(*bytes)->data = (uchar *)malloc ((*bytes)->num);
		if ((*bytes)->data == NULL)
			return CM_NULL_POINTER;
		buf.GetSeg((char*)(*bytes)->data, (*bytes)->num);
	}
	else
		*bytes = NULL;
	return CM_NO_ERROR;
}


// end of CM_infc.cpp
