/*****************************************************************************
File:     CM_RetrieveKey.cpp
Project:  Certificate Management Library
Contents: Retrieve Key function and X.509 Certificate path validation routines

Created:  3 April 1997
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  27 Jan 2005

Version:  2.5

*****************************************************************************/

////////////////////
// Included Files //
////////////////////
#include "PathBuild.h"
#ifdef WIN32
	#ifndef NOTHREADS
		#include <process.h>					// Needed for threads
	#endif //NOTHREADS
#else // !WIN32
	#include "ctype.h"							// Needed for unix systems
	#ifndef NOTHREADS
		#include <pthread.h>					// Needed for threads
	#endif // NOTHREADS
#endif // WIN32

// Using declarations
using namespace CML;
using namespace CML::Internal;
using ASN::GenName;

//Internal Types
typedef struct {
	const RevCallbackFunctions* m_revFuncs;// Pointer to callback functions
	RevStatus_LL* m_revStatus;             // Revocation status for certs
	short m_returnVal;                     // return status
	CM_TimePtr m_pValidationTime;          // Optional time to use when validating
	CM_BOOL m_wantBack;                    // specifies whether or not to 
                                          // return revocation data
   EncRevObject_LL* m_pRevocationData;    // revocation data
} RevThreadArgs;


///////////////////////
// Defined Constants //
///////////////////////
const float MIN_PATH_PROBABILITY = (float)0.1;

const char gEXT_KEY_USE_EntrustCA[]		= "1.2.840.113533.7.74.3";
const char gEXT_KEY_USE_msCTLSigning[]	= "1.3.6.1.4.1.311.10.3.1";


/////////////////////////
// Function Prototypes //
/////////////////////////
static bool areCommPrivsSubset(const SNACC::CommPrecFlags& subjPrivs,
							   const ASN::AttributeList& caConstraints);
static bool areKmFlagsSubset(const SNACC::KmPrivFlagsSeqOf* pSubj,
							 const SNACC::KmPrivFlagsSeqOf* pIssuer);
static bool arePrivsSubset(const SNACC::PrivilegeFlags& subjPrivs,
						   const ASN::AttributeList& caConstraints);
static bool areSigFlagsSubset(const SNACC::SigPrivFlagsSeqOf* pSubj,
							  const SNACC::SigPrivFlagsSeqOf* pIssuer);
static void buildFortezzaPubKey(ASN::Bytes& pubKey, ASN::Bytes& params,
								const Pub_key_struct& cmPubKey);
static short checkCaConst(bool isCA, const ASN::AttributeList* pSubjAttribs,
						  const ASN::AttributeList* pIssuerAttribs);
static void checkExtKeyUsage(const ASN::ExtKeyUsageExtension& extKeyUse,
							 ErrorInfoList& errors, const ASN::Cert& cert);
static void cvtBytesToHugeInt(SNACC::AsnInt& hugeInt,
							  const Bytes_struct& bytes);
static void cvtPolicyStructToList(ASN::CertPolicyList& list,
								  const Policy_struct* policyList);
static void fillSnaccNoticeNumbers(SNACC::NoticeReferenceSeqOf& snacc,
								   const Bytes_struct_LL* pNumList);
static bool isCAConstraintsSubset(const ASN::AttributeList& subj,
								  const ASN::AttributeList& issuer);
static RevStatus_LL* buildRevStatus(const BaseNodePtrDeck& path);
static void freeRevStatus(RevStatus_LL** pRevocationData);

namespace CML {
void UpdateCertStatus(ulong sessionID, const ASN::Bytes& certBytes, const ASN::BytesList& issuerList,
								  ErrorInfoList* pCertErrors, ErrorInfoList* pPathErrors);
}
#ifndef NOTHREADS
#ifdef WIN32 
unsigned __stdcall checkRevStatus(void* inargs);
#else //WIN32
void *checkRevStatus(void* inargs);
#endif //WIN32
#else //NOTHREADS
void checkRevStatus(void* inargs);
#endif //NOTHREADS

///////////////////////////////////////
// ValidatedKey class implementation //
///////////////////////////////////////
ValidatedKey::ValidatedKey()
{
	// Initialize pointers and boolean flags
	pKeyUsage = NULL;
	pExtKeyUsage = NULL;
	explicitPolicyFlag = false;
}


ValidatedKey::ValidatedKey(const ValidatedKey& that)
{
	pKeyUsage = NULL;
	pExtKeyUsage = NULL;
	operator=(that);
}


ValidatedKey::ValidatedKey(const ValidKey_struct& valKey)
{
	// Initialize pointers
	pKeyUsage = NULL;
	pExtKeyUsage = NULL;

	// Check input ValidKey_struct parameter
	if ((valKey.key.oid == NULL) || (valKey.key.key.y == NULL))
		throw CML_ERR(CM_INVALID_PARAMETER);

	// Set the public key algorithm
	m_pubKeyInfo.algorithm = valKey.key.oid;
		
	// Set the public key and parameters
	if ((m_pubKeyInfo.algorithm == gDSA_OID) ||
		(m_pubKeyInfo.algorithm == gOIW_DSA))
	{
		// Check that the required parameters are present
		if (valKey.key.params.dsa == NULL)
			throw CML_ERR(CM_INVALID_PARAMETER);
		
		// Load the SNACC DSAParameters
		SNACC::Dss_Parms dsaParams;
		cvtBytesToHugeInt(dsaParams.p, valKey.key.params.dsa->p);
		cvtBytesToHugeInt(dsaParams.q, valKey.key.params.dsa->q);
		cvtBytesToHugeInt(dsaParams.g, valKey.key.params.dsa->g);

		// Allocate memory for the parameters
		m_pubKeyInfo.algorithm.parameters = new ASN::Bytes;
		if (m_pubKeyInfo.algorithm.parameters == NULL)
			throw CML_MEMORY_ERR;
		
		// Encode the parameters
		m_pubKeyInfo.algorithm.parameters->Encode(dsaParams,
			"SNACC::Dss_Parms");
		
		// Encode the DSA public key
		SNACC::DSAPublicKey pubKey;
		cvtBytesToHugeInt(pubKey, *valKey.key.key.y);
		m_pubKeyInfo.key.Encode(pubKey, "SNACC::DSAPublicKey");
	}
	else if (m_pubKeyInfo.algorithm == gRSA_OID)
	{
		// Allocate memory for the parameters
		m_pubKeyInfo.algorithm.parameters = new ASN::Bytes;
		if (m_pubKeyInfo.algorithm.parameters == NULL)
			throw CML_MEMORY_ERR;
		
		// Encode the parameters
		SNACC::AsnNull rsaParams;
		m_pubKeyInfo.algorithm.parameters->Encode(rsaParams, "SNACC::AsnNull");
		
		// Encode the RSA public key
		SNACC::RSAPublicKey rsaPubKey;
		cvtBytesToHugeInt(rsaPubKey.modulus, valKey.key.key.rsa->modulus);
		cvtBytesToHugeInt(rsaPubKey.publicExponent,
			valKey.key.key.rsa->publicExponent);
		m_pubKeyInfo.key.Encode(rsaPubKey, "SNACC::RSAPublicKey");
	}
	else if ((m_pubKeyInfo.algorithm == gOLD_DH_OID) ||
		(m_pubKeyInfo.algorithm == gANSI_DH_OID))
	{
		if (valKey.key.params.encoded != NULL)
		{
			// Copy the encoded DH parameters
			m_pubKeyInfo.algorithm.parameters = new
				ASN::Bytes(*valKey.key.params.encoded);
			if (m_pubKeyInfo.algorithm.parameters == NULL)
				throw CML_MEMORY_ERR;
		}
		
		// Encode the DH public key
		SNACC::DHPublicKey pubKey;
		cvtBytesToHugeInt(pubKey, *valKey.key.key.y);
		m_pubKeyInfo.key.Encode(pubKey, "SNACC::DHPublicKey");
	}
	else if (m_pubKeyInfo.algorithm == gKEA_OID)
	{
		if (valKey.key.params.kea != NULL)
		{
			// Allocate memory for the encoded KEA parameters
			m_pubKeyInfo.algorithm.parameters = new ASN::Bytes;
			if (m_pubKeyInfo.algorithm.parameters == NULL)
				throw CML_MEMORY_ERR;
			
			// Encode the KEA parameters
			SNACC::AsnOcts keaParams((const char*)valKey.key.params.kea->data,
				valKey.key.params.kea->num);
			m_pubKeyInfo.algorithm.parameters->Encode(keaParams,
				"SNACC::AsnOcts");
		}
		
		// Copy the KEA public key
		m_pubKeyInfo.key = *valKey.key.key.y;
	}
	else if (m_pubKeyInfo.algorithm == gDSA_KEA_OID)
	{
		// Check that the required parameters are present
		if (valKey.key.params.dsa_kea == NULL)
			throw CML_ERR(CM_INVALID_PARAMETER);
		
		// Allocate memory for the parameters
		m_pubKeyInfo.algorithm.parameters = new ASN::Bytes;
		if (m_pubKeyInfo.algorithm.parameters == NULL)
			throw CML_MEMORY_ERR;
		
		// Build the encoded Fortezza public key and parameters
		buildFortezzaPubKey(m_pubKeyInfo.key,
			*m_pubKeyInfo.algorithm.parameters, valKey.key);
	}
	else if (m_pubKeyInfo.algorithm == gEC_KEY_OID)
	{
		// Check that the required parameters are present
		if (valKey.key.params.encoded == NULL)
			throw CML_ERR(CM_INVALID_PARAMETER);
		
		// Copy the encoded parameters
		m_pubKeyInfo.algorithm.parameters = new
			ASN::Bytes(*valKey.key.params.encoded);
		if (m_pubKeyInfo.algorithm.parameters == NULL)
			throw CML_MEMORY_ERR;
		
		// Copy the elliptic curve public key
		m_pubKeyInfo.key = *valKey.key.key.y;
	}
	else
	{
		// If the parameters are present, copy them
		if (valKey.key.params.encoded != NULL)
		{
			m_pubKeyInfo.algorithm.parameters = new
				ASN::Bytes(*valKey.key.params.encoded);
			if (m_pubKeyInfo.algorithm.parameters == NULL)
				throw CML_MEMORY_ERR;
		}

		// Copy the encoded public key
		m_pubKeyInfo.key = *valKey.key.key.encoded;
	}

	// Set the authority and user-constrained-policy-sets and
	// require-explicit-policy flag
	cvtPolicyStructToList(authPolicies, valKey.caPolicies);
	cvtPolicyStructToList(userPolicies, valKey.userPolicies);
	if (valKey.explicitPolFlag == FALSE)
		explicitPolicyFlag = false;
	else
		explicitPolicyFlag = true;
	
	// Set the policy mappings
	const Pol_maps_struct* pMapping = valKey.mappings;
	while (pMapping != NULL)
	{
		mappings.push_back(ASN::PolicyMapping(pMapping->issuer_pol_id,
			pMapping->subj_pol_id));
		pMapping = pMapping->next;
	}
		
	// If the key usage is present, create and set a new KeyUsageExtension
	if (valKey.keyUse != NULL)
	{
		pKeyUsage = new ASN::KeyUsageExtension();
		if (pKeyUsage == NULL)
			throw CML_MEMORY_ERR;
		
		if (valKey.keyUseCritical)
			pKeyUsage->critical = true;
		
		// Set the key usage bits
		ushort mask = 1;
		for (unsigned int i = SNACC::KeyUsage::digitalSignature; i <
			SNACC::KeyUsage::decipherOnly; i++)
		{
			if ((*valKey.keyUse & mask) != 0)
				pKeyUsage->SetBit(i);
			mask <<= 1;
		}
	}
		
	// If the extended key usage is present, create and set a new
	// ExtKeyUsageExtension
	if (valKey.extKeyUsage != NULL)
	{
		pExtKeyUsage = new ASN::ExtKeyUsageExtension();
		if (pExtKeyUsage == NULL)
			throw CML_MEMORY_ERR;
		
		if (valKey.extKeyUsageCritical)
			pExtKeyUsage->critical = true;
		
		// Set the Key Purpose OIDs
		const Ext_key_use_LL* pOid = valKey.extKeyUsage;
		while (pOid != NULL)
		{
			pExtKeyUsage->push_back(pOid->oid);
			pOid = pOid->next;
		}
	}

   // Copy the revocation data list
   m_revDataList = *valKey.m_pRevocationData;
}


ValidatedKey::~ValidatedKey()
{
	if (pKeyUsage != NULL)
		delete pKeyUsage;
	if (pExtKeyUsage != NULL)
		delete pExtKeyUsage;
}


ValidatedKey& ValidatedKey::operator=(const ValidatedKey& that)
{
	if (this != &that)
	{
		if (pKeyUsage != NULL)
		{
			delete pKeyUsage;
			pKeyUsage = NULL;
		}
		if (pExtKeyUsage != NULL)
		{
			delete pExtKeyUsage;
			pExtKeyUsage = NULL;
		}

		m_pubKeyInfo = that.m_pubKeyInfo;
		authPolicies = that.authPolicies;
		userPolicies = that.userPolicies;
		explicitPolicyFlag = that.explicitPolicyFlag;
		mappings = that.mappings;
      m_revDataList = that.m_revDataList;

		if (that.pKeyUsage != NULL)
		{
			pKeyUsage = new ASN::KeyUsageExtension(*that.pKeyUsage);
			if (pKeyUsage == NULL)
				throw CML_MEMORY_ERR;
		}

		if (that.pExtKeyUsage != NULL)
		{
			pExtKeyUsage = new ASN::ExtKeyUsageExtension(*that.pExtKeyUsage);
			if (pExtKeyUsage == NULL)
				throw CML_MEMORY_ERR;
		}
	}
	return *this;
}


void ValidatedKey::Clear()
{
	m_pubKeyInfo.Clear();

	authPolicies.clear();
	userPolicies.clear();
	explicitPolicyFlag = false;
	mappings.clear();
	m_revDataList.Clear();

	if (pKeyUsage != NULL)
	{
		delete pKeyUsage;
		pKeyUsage = NULL;
	}
	if (pExtKeyUsage != NULL)
	{
		delete pExtKeyUsage;
		pExtKeyUsage = NULL;
	}
}


ValidKey_struct* ValidatedKey::GetValidKeyStruct() const
{
	if (IsEmpty())
		throw CML_ERR(CM_INVALID_PARAMETER);

	ValidKey_struct* result = (ValidKey_struct*)calloc(1,
		sizeof(ValidKey_struct));
	if (result == NULL)
		throw CML_MEMORY_ERR;

	try {
		m_pubKeyInfo.FillPubKeyStruct(result->key);
		
		result->keyUseCritical = FALSE;
		if (pKeyUsage != NULL)
		{
			Extn_struct* pExtn = pKeyUsage->GetExtensionStruct();
			result->keyUse = (ushort*)pExtn->value;
			free(pExtn->oid);
			free(pExtn);

			if (pKeyUsage->critical)
				result->keyUseCritical = TRUE;
		}

		result->caPolicies = authPolicies.GetPolicyList();
		result->userPolicies = userPolicies.GetPolicyList();

		if (explicitPolicyFlag)
			result->explicitPolFlag = TRUE;
		else
			result->explicitPolFlag = FALSE;

		Pol_maps_struct* prevMap = NULL;
		for (ASN::PolicyMappingList::const_iterator iMap = mappings.begin();
			iMap != mappings.end(); iMap++)
		{
			if (prevMap == NULL)
				prevMap = result->mappings = iMap->GetPolicyMapping();
			else
				prevMap = prevMap->next = iMap->GetPolicyMapping();
		}

		result->extKeyUsageCritical = FALSE;
		if (pExtKeyUsage != NULL)
		{
			Ext_key_use_LL* prevOid = NULL;
			for (ASN::ExtKeyUsageExtension::const_iterator iOid =
				pExtKeyUsage->begin(); iOid != pExtKeyUsage->end(); iOid++)
			{
				Ext_key_use_LL* pNew =
					(Ext_key_use_LL*)malloc(sizeof(Ext_key_use_LL));
				if (pNew == NULL)
					throw CML_MEMORY_ERR;

				pNew->next = NULL;
				
				if (prevOid == NULL)
					result->extKeyUsage = pNew;
				else
					prevOid->next = pNew;
				prevOid = pNew;

				pNew->oid = iOid->GetChar();
			}
			if (pExtKeyUsage->critical)
				result->extKeyUsageCritical = TRUE;
		}

      // Get the "C" form of the revocation data
      result->m_pRevocationData = m_revDataList.GetEncRevObject_LL();

		return result;
	}
	catch (...) {
		CM_FreeValidKey(&result);
		throw;
	}
}


bool ValidatedKey::IsEmpty() const
{
	return ((m_pubKeyInfo.algorithm.algorithm.Len() == 0) ||
		(m_pubKeyInfo.key.Len() == 0));
}

/////////////////////////////////////////////
// RevocationDataList class implementation //
/////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Function:      operator=()
// Description:   Assign (to this list) from the "C" form of the list.
// Inputs:        EncRevObject_LL& that
// Outputs:       (none)
// Return value:  A reference to the list being filled in (this).
///////////////////////////////////////////////////////////////////////////////
RevocationDataList& RevocationDataList::operator=(const EncRevObject_LL& that)
{
   const encRevObject_LL* pRevObject = &that;
   if (pRevObject != NULL)
   {
      if (pRevObject->m_typeMask == REV_CRL_TYPE)
         m_type = RevocationDataList::CRL;
      else 
         m_type = RevocationDataList::OCSP_RESP;
      while (pRevObject != NULL)
      {
         push_back(pRevObject->m_encObj);
         pRevObject = pRevObject->m_pNext;
      }
   }
   return *this;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      GetEncRevObject_LL()
// Description:   Create and return the "C" form (EncRevObject_LL) of the 
//                RevocationDataList
// Inputs:        (none)
// Outputs:       (none)
// Return value:  A pointer to the head of the list of encoded revocation
//                data (CRLs or OCSP responses). NULL if no objects were
//                in the list.
///////////////////////////////////////////////////////////////////////////////
EncRevObject_LL* RevocationDataList::GetEncRevObject_LL() const
{
   EncRevObject_LL* pList = NULL;
	
	try 
   {
		RevocationDataList::const_reverse_iterator i;
		for (i = rbegin(); i != rend(); ++i)
		{
         // Create space for a new item in the list
			EncRevObject_LL* pNew = (EncRevObject_LL*)calloc(1, 
                                                   sizeof(EncRevObject_LL));
         if (pNew == NULL)
            throw CM_MEMORY_ERROR;
         // Set the typemask
         if (m_type == RevocationDataList::CRL)
            pNew->m_typeMask = REV_CRL_TYPE;
         else 
            pNew->m_typeMask = REV_OCSP_TYPE;
         // Add the encoded CRL or OCSP response to the new item
         i->FillBytesStruct(pNew->m_encObj);
			pNew->m_pNext = pList;
			pList = pNew;
		}
		return pList;
	}
	catch (...) {
		CMU_FreeRevocationData(pList);
		throw;
	}
}

///////////////////////////////////////
// CachableCert class implementation //
///////////////////////////////////////
CachableCert::CachableCert(Certificate cert, PolicyTable authSet, 
							ASN::PolicyMappingList mappings, 
							bool explicitPolFlag,
							ASN::Time expireTime, 
							short error, 
							ErrorInfoList certErrors, 
							ErrorInfoList pathErrors) :
m_cert(cert), m_authSet(authSet), m_mappings(mappings), 
m_explicitPolFlag(explicitPolFlag), m_expireTime(expireTime),
m_error(error)
{
	m_certErrors = certErrors;
	m_pathErrors = pathErrors;
}


/************************************************************************
 FUNCTION:  CM_RetrievePath()
 
 Description: This function will retrieve the public key from the
 provided ASN.1 encoded certificate or certification path, validate the
 key in accordance with the X.509 standard, and return the public key and
 optional certification path to the application.
 CM_NO_ERROR is returned if the path is successfully built and validated.
 CM_PATH_VALIDATION_ERROR is returned if the path can be built, but was
 not valid.  CM_NO_PATH_FOUND is returned if the path cannot be built.
 Other errors may be returned if a fatal error occurs.
 If CM_PATH_VALIDATION_ERROR occurs, then the extended path errors are
 stored in the session and can be retrieved using CM_GetErrInfo().
*************************************************************************/
short CM_RetrievePath(ulong sessionID, Bytes_struct* asn1data, short asn1Type,
					  Cert_path_LL **decPath, ValidKey_struct **validKey,
					  SearchBounds boundsFlag)
{
	short errCode = CM_PATH_VALIDATION_ERROR;

	// Check parameters
	if ((asn1data == NULL) || (validKey == NULL))
		return CM_INVALID_PARAMETER;
	if ((asn1Type != CM_CERT_TYPE) && (asn1Type != CM_CERTPATH_TYPE))
		return CM_INVALID_PARAMETER;
	if ((boundsFlag < CM_SEARCH_LOCAL) || (boundsFlag > CM_SEARCH_UNTIL_FOUND))
		return CM_INVALID_PARAMETER;

	// Initialize validKey result and, if present, the decPath parameter
	*validKey = NULL;
	if (decPath != NULL)
		*decPath = NULL;

	try {
		// Initialize the cert path
		CertPath thePath(*asn1data, (asn1Type != CM_CERT_TYPE));

		// Build and validate the cert path
		ValidatedKey keyObj;
		ErrorInfoList errors;
		errCode = thePath.BuildAndValidate(sessionID, boundsFlag,
			&errors, MIN_PATH_PROBABILITY, &keyObj, NULL, true);

		// Get the ValidKey_struct form of the ValidatedKey
		*validKey = keyObj.GetValidKeyStruct();
		(*validKey)->errors = errors;

		// If a valid or invalid path was successfully built...
		if ((errCode == CM_NO_ERROR) || (errCode == CM_PATH_VALIDATION_ERROR))
		{
			// Get the decoded certification path (if requested)
			if (decPath != NULL)
				*decPath = thePath.base().GetCertPathList();
		}
	}
	catch (ASN::Exception& e) {
		CM_FreeValidKey(validKey);
		return e;
	}
	catch (SNACC::SnaccException& ) {
		CM_FreeValidKey(validKey);
		return CM_ASN_ERROR;
	}
	catch (...) {
		CM_FreeValidKey(validKey);
		RETURN(CM_UNKNOWN_ERROR);
	}

	return errCode;
} // end of CM_RetrievePath()

					  
/************************************************************************
 FUNCTION:  CM_RetrieveKey()
 
 Description: This function will retrieve the public key from the
 provided ASN.1 encoded certificate or certification path, validate the
 key in accordance with the X.509 standard, and return the public key to
 the application.
 CM_NO_ERROR is returned if the path is successfully built and validated.
 CM_PATH_VALIDATION_ERROR is returned if the path can be built, but was
 not valid.  CM_NO_PATH_FOUND is returned if the path cannot be built.
 Other errors may be returned if a fatal error occurs.
 If CM_PATH_VALIDATION_ERROR occurs, then the extended path errors are
 stored in the session and can be retrieved using CM_GetErrInfo().
*************************************************************************/
short CM_RetrieveKey(ulong sessionID, Bytes_struct* asn1data, short asn1Type,
    ValidKey_struct **valid_key, SearchBounds searchFlag)
{
	return CM_RetrievePath(sessionID, asn1data, asn1Type, NULL, valid_key,
		searchFlag);
} // end of CM_RetrieveKey()



/************************************************************************
 FUNCTION:  CML::Internal::ValidateCert()
 
 Description: This function performs the X.509 certification path
 processing of the target certificate using the issuer certificate and
 supplied stat variables.
 CM_NO_ERROR is returned if the cert is successfully validated.
 CM_PATH_VALIDATION_ERROR is returned if the cert is not valid, the
 specific errors are returned in the certErrors and pathErrors lists.
 If a fatal error occurs, an exception is thrown.
*************************************************************************/
short CML::Internal::ValidateCert(ulong sessionID, const Certificate& target,
								  const Certificate& issuer,
								  SearchBounds searchFlag,
								  StateVars& pathVars,
								  ErrorInfoList& certErrors,
								  ErrorInfoList& pathErrors,
								  bool isEndCert,
								  bool disableRevChecking)
{
	// Check that the two signature algorithms on the cert are the same
	if (target.base().signature != target.base().algorithm)
		certErrors.AddError(CM_SIGNATURE_ALG_MISMATCH, target.base());

	// Acquire global session lock
	ASN::ReadLock lock = AcquireSessionReadLock(sessionID);

	// Check that the signature verifies unless the cert is already cached
	if (!GetCertCache(sessionID).IsCachedAndValid(target, issuer))
	{
		short errCode = VerifySignature(sessionID, target.GetEnc(),
			issuer.base().pubKeyInfo, pathVars.pParams);
		if (errCode == CM_NO_TOKENS_SUPPORT_SIG_ALG)
		{
			certErrors.AddError(CM_NO_TOKENS_SUPPORT_CERT_SIG_ALG,
				target.base());
		}
		else if (errCode != CM_NO_ERROR)
			pathErrors.AddError(CM_CERT_SIGNATURE_INVALID, target.base());
	}
	
	lock.Release();    // Release the lock

	// If validationTime exists, set curTime to time stamp time
   // Check that current date or time stamp time
	// falls within the validity period of the cert
	ASN::Time curTime;
	if (pathVars.m_pValidationTime != NULL)
	   curTime = *pathVars.m_pValidationTime;

	if (curTime < target.base().validity.notBefore)
	{
		certErrors.AddError(CM_CERT_NOT_YET_VALID, target.base(),
			target.base().validity.notBefore);
	}

	if (curTime > target.base().validity.notAfter)
	{
		certErrors.AddError(CM_CERT_EXPIRED, target.base(),
			target.base().validity.notAfter);
	}

	// Check that the certificate subject and issuer names chain correctly
	if ((target.base().issuer != issuer.base().subject) ||
		!CompareUniqueIDs(target.base().pIssuerUniqueID,
		issuer.base().pSubjectUniqueID))
		pathErrors.AddError(CM_NAME_MISMATCH, target.base());


	// For an intermediate certificate, the basic constraints extension must
	// be present and the CA flag set to true.
	if (!isEndCert && (target.base().version == SNACC::Version::v3))
	{
		if ((target.base().exts.pBasicCons == NULL) ||
			!target.base().exts.pBasicCons->isCA)
			pathErrors.AddError(CM_INVALID_CA, target.base());
	}

	// Check that the path length constraint has not been exceeded
	if (pathVars.maxPathDepth == 0)
		pathErrors.AddError(CM_PATH_LEN_EXCEEDED, issuer.base());

	// If this intermediate cert has a key usage extension, check that
	// the keyCertSign bit set
	if (!isEndCert && (target.base().exts.pKeyUsage != NULL))
	{
		if (!target.base().exts.pKeyUsage->GetBit(SNACC::KeyUsage::keyCertSign))
			pathErrors.AddError(CM_INVALID_KEY_USE, target.base());
	}

	// If this intermediate cert has an extended key usage extension, check
	// that it contains the anyExtendedKeyUsage OID
	if (!isEndCert && (target.base().exts.pExtKeyUsage != NULL))
	{
		checkExtKeyUsage(*target.base().exts.pExtKeyUsage, pathErrors,
			target.base());
	}

	// Set flag to indicate if this cert is a self-issued intermediate cert
	bool isSelfIssuedCA = !isEndCert && target.base().IsSelfIssued();

	// Process the certificate policies extension
	pathVars.authTable.ProcessPolicies(target.base().exts.pCertPolicies,
		pathVars.pathDepth, pathVars.inhibitAnyPolicy, isSelfIssuedCA);

   // Check for invalid policy mappings
   if ((target.base().exts.pPolicyMaps != NULL) &&
      (HasInvalidMappings(*target.base().exts.pPolicyMaps) == true))
      certErrors.AddError(CM_INVALID_POLICY_MAPPING, target.base());

	// If the certificate is not an intermediate self-issued certificate,
	// check that the subject name is within the permitted-subtrees
	// namespace and not within the excluded-subtrees namespace
	if (!isSelfIssuedCA)
	{
		if (!target.base().subject.IsEmpty())
		{
			// Check the subject DN
			if (!pathVars.permitted.IsNameWithin(target.base().subject) ||
				pathVars.excluded.IsNameWithin(target.base().subject, false))
				pathErrors.AddError(CM_INVALID_SUBJECT_NAME, target.base());
		}
		else if ((target.base().exts.pSubjAltNames == NULL) ||
			!target.base().exts.pSubjAltNames->critical)
		{
			// Since subject DN is absent, subject alt name extension must
			// be present and critical
			certErrors.AddError(CM_INVALID_SUBJECT_NAME, target.base());
		}
	}

	// Check that any subject alternative names are within the
	// permitted-subtrees namespace and not within the excluded-subtrees
	// namespace
	if (target.base().exts.pSubjAltNames != NULL)
	{
		try {
			const ASN::GenNames& subjNames = *target.base().exts.pSubjAltNames;
			if (!pathVars.permitted.AreNamesWithin(subjNames) ||
				pathVars.excluded.AreNamesWithin(subjNames, false))
				pathErrors.AddError(CM_INVALID_ALT_NAME, target.base());
		}
		catch (ASN::Exception& asnErr) {
			if (asnErr == CMLASN_NOT_IMPLEMENTED)
				pathErrors.AddError(CM_UNRECOGNIZED_ALT_NAME, target.base());
			else
				throw;
		}
	}

	// If the certificate is not an intermediate self-issued certificate,
	// for each set of required-name-forms, check that the cert contains a
	// subject name of one of the name forms
	if (!isSelfIssuedCA)
	{
		bool namePresent = true;
		ReqNameForms::const_iterator i = pathVars.reqNames.begin();
		for ( ; (i != pathVars.reqNames.end()) && namePresent; i++)
		{
			// If the X.500 name form is required and the subject DN is
			// present, continue on to the next set
			if (i->basicNames.GetBit(SNACC::BasicNameForms::directoryName) &&
				!target.base().subject.IsEmpty())
				continue;

			namePresent = i->IsNamePresent(target.base().exts.pSubjAltNames);
		}

		// If a required name form wasn't present, record the error
		if (!namePresent)
			pathErrors.AddError(CM_REQUIRED_NAME_MISSING, target.base());
	}

	// If the issuer of this certificate is not self-issued, perform the
	// SDN.706 checks of the MISSI subject directory attributes
	if (!issuer.base().IsSelfIssued())
	{
		short errCode = checkCaConst(isEndCert, target.base().exts.pSubjDirAtts,
			issuer.base().exts.pSubjDirAtts);
		if (errCode == CM_DMS_NO_CA_CONSTRAINTS)
			pathErrors.AddError(errCode, issuer.base());
		else if (errCode != CM_NO_ERROR)
			pathErrors.AddError(errCode, target.base());
		// else no error
	}

	// If this certificate contains one of the MISSI/DMS attributes, check that
	// the subject DN is present
	if ((target.base().exts.pSubjDirAtts != NULL) &&
		target.base().subject.IsEmpty())
	{
		const ASN::AttributeList& attribs = *target.base().exts.pSubjDirAtts;
		if ((attribs.Find(ASN::Attribute::CAClearanceConst) != attribs.end()) ||
			(attribs.Find(ASN::Attribute::SigOrKMPrivs) != attribs.end()) ||
			(attribs.Find(ASN::Attribute::CommPrivs) != attribs.end()))
			certErrors.AddError(CM_DMS_NULL_SUBJECT_DN, target.base());
	}

	// Check that there aren't any unrecognized critical extensions
	ASN::UnknownExtensions::const_iterator i =
		target.base().exts.unknownExts.begin();
	for ( ; i != target.base().exts.unknownExts.end(); i++)
	{
		if (i->critical)
		{
			certErrors.AddError(CM_UNRECOGNIZED_CRITICAL_CERT_EXT,
				target.base(), i->OID());
		}
	}

	// Return the correct error code
	if (certErrors.empty() && pathErrors.empty())
	{
		return CM_NO_ERROR;
	}

	return CM_PATH_VALIDATION_ERROR;
}

/************************************************************************
 FUNCTION:  CML::Internal::ValidateCertPath()
 
 Description: This function performs the X.509 certification path
 processing of the target certificate by supplying the issuer certificate and
 stat variables to CML::Interal::ValidateCert().
 CM_NO_ERROR is returned if the cert is successfully validated.
 CM_PATH_VALIDATION_ERROR is returned if the cert is not valid, the
 specific errors are returned in the certErrors and pathErrors lists.
 If a fatal error occurs, an exception is thrown.
*************************************************************************/
short ValidateCertPath(ulong sessionID, const BaseNodePtrDeck& curPath, 
					   PrintXML& logXML,SearchBounds boundsFlag, 
					   StateVars& pathVars, ErrorInfoList* pErrors,
					   bool performRevChecking, RevocationDataList* pRevDataList)
{
	CachedCertList issuerCerts;
	CachableCertList certsToBeCached;
   CM_Time tempValidationTime;
	RevThreadArgs args; // holder for arguments passed to revocation checking thread
	args.m_returnVal = CRL_RESP_INTERNAL_ERR;
	args.m_revStatus = NULL;
	args.m_revFuncs = NULL;
   args.m_pValidationTime = NULL;
   args.m_pRevocationData = NULL;

	// If validation time has been specified, copy to args.m_pValidationTime
	if (pathVars.m_pValidationTime != NULL)
	{
	   memcpy(&tempValidationTime, pathVars.m_pValidationTime, CM_TIME_LEN);
      args.m_pValidationTime = &tempValidationTime;
	}

	// If the CRL/OCSP responses should be returned set the wantBack flag
   if (pRevDataList == NULL)
      args.m_wantBack = FALSE;
   else
	   args.m_wantBack = TRUE;

	const bool revCheckingNeeded = ((GetSessionFromRef(sessionID).GetRevPolicy() != CM_REVNONE) &&
										performRevChecking);

	// Throw exception if the path is empty
	if ((curPath.size() < 2) || (curPath.front() == NULL) ||
		!curPath.front()->IsTrusted())
		throw CML_ERR(CM_UNKNOWN_ERROR);

	// Get a reference to the cached trust anchor
	const CachedCert& cachedTrustedCert =
		((const TrustedCertNode*)curPath.front())->m_cachedCert;

	// Initialize the list of issuer certs
	issuerCerts.assign(1, cachedTrustedCert);
	
	// Update the path expiration and trusted parameters path variables
	pathVars.pathExpiration = cachedTrustedCert.base().validity.notAfter;
	pathVars.pParams = cachedTrustedCert.base().pubKeyInfo.algorithm.parameters;
	
	/* Note: One must be added to the state variable, maxPathDepth, because of
	   the way the library checks for path limits.  Unlike X.509, maxPathDepth
	   indicates how many certs can follow (X.509 uses it to indicate how many
	   issuer certs can follow--a subtle but important difference). */
	if (cachedTrustedCert.maxPathLen != -1)
		pathVars.maxPathDepth = (short)(cachedTrustedCert.maxPathLen + 1);	
	
	// Set the permitted-subtrees state variable to the value in the trusted 
	// cert member variable if has a value
	if (!cachedTrustedCert.names.permitted.empty())
		pathVars.permitted.push_back(cachedTrustedCert.names.permitted);
	
	// Set the excluded-subtrees state variable to value in the trusted 
	// cert member variable if has a value
	if (!cachedTrustedCert.names.excluded.empty())
		pathVars.excluded = cachedTrustedCert.names.excluded;
	
	// Set the required-name-forms state variable to the value in the trusted
	// cert member variable if has a value
	if (!cachedTrustedCert.names.requiredNames.IsEmpty())
		pathVars.reqNames.push_back(cachedTrustedCert.names.requiredNames);

	// Check that the certificates in the path have not been revoked
#ifndef NOTHREADS
#ifdef WIN32
	HANDLE revThreadID = 0;
#else
	pthread_t revThreadID = 0;
#endif //WIN32
#endif //NOTHREADS
	if (revCheckingNeeded)
	{
		// Acquire global session lock
		ASN::ReadLock lock = AcquireSessionReadLock(sessionID);
		
		args.m_revStatus = buildRevStatus(curPath);
		args.m_revFuncs = &(GetRevCallbacksFromRef(sessionID));
		
		// Start thread that calls revocation callbacks
#ifndef NOTHREADS
#ifdef WIN32
      if ( (revThreadID = (HANDLE)_beginthreadex( NULL, 0, checkRevStatus,
                          &args, 0, NULL )) == NULL )
#else
		if (pthread_create(&revThreadID, NULL, checkRevStatus, &args) != 0)
#endif //WIN32
		{
			//failed to create thread
			throw CML_ERR(CM_UNKNOWN_ERROR);
		}
#else //NOTHREADS
      checkRevStatus(&args);
#endif //NOTHREADS
   }
	// Loop through the remaining certs starting with the second cert
	// validating each cert until the EE is reached ignoring revocation
	//
	short issuerErrors = CM_NO_ERROR;
	short subjError = CM_NO_ERROR;
	bool isLastCert = false;
	ErrorInfoList pathErrors;
	const BaseNode* issuerNode = curPath.front();
	BaseNodePtrDeck::const_iterator iNode;;
	for (iNode = curPath.begin() + 1; iNode != curPath.end(); ++iNode)
	{
		// Check that the BaseNode pointer is valid
		if (*iNode == NULL)
			throw CML_ERR(CM_NULL_POINTER);

		// Set flag to true when processing last cert
		if (iNode + 1 == curPath.end())
			isLastCert = true;

		// Validate this certificate
		ErrorInfoList perCertPathErrors;
		subjError = ValidateCert((*iNode)->m_hSession, (*iNode)->GetCert(),
			issuerNode->GetCert(), boundsFlag, pathVars, (*iNode)->m_certErrors,
			perCertPathErrors, isLastCert, performRevChecking);		
		
		// If there were errors and the first one was invalid signature,
		// then check if the link probability can be reset to 0
		if (!perCertPathErrors.empty() &&
			(perCertPathErrors.front().error == CM_CERT_SIGNATURE_INVALID))
		{
			// Set link probability to 0 if the issuer cert has parameters or 
			// if there were no path validation errors for the issuer
			if ((issuerNode->GetCert().base().pubKeyInfo.algorithm.parameters != NULL) ||
				(issuerErrors == CM_NO_ERROR))
				(*iNode)->FindAndZeroizeIssuer(issuerNode);
		}

		// Update the X.509 path variables
		pathVars.Update((*iNode)->GetCert().base(), isLastCert);
		
		// If this cert is the end certificate and the explicit-policy-indicator
		// is set, check that neither the authorities-constrained-policy-set
		// nor the user-constrained-policy-set is empty
		if (isLastCert && pathVars.explicitPolicy)
		{
			// Acquire global session lock
			ASN::ReadLock lock = AcquireSessionReadLock((*iNode)->m_hSession);
			
			if (pathVars.authTable.IsEmpty())
			{
				subjError = CM_PATH_VALIDATION_ERROR;
				perCertPathErrors.AddError(CM_INVALID_CERT_POLICY,
					(*iNode)->GetCert().base());
			}
			else if (pathVars.authTable.IsUserPolicySetEmpty(
				GetInitialPolicySet((*iNode)->m_hSession)))
			{
				subjError = CM_PATH_VALIDATION_ERROR;
				perCertPathErrors.AddError(CM_MISSING_USER_CERT_POLICY,
					(*iNode)->GetCert().base());
			}
			
			lock.Release();
			
		}
		
		// Add the cert and path errors to the local error list
		pathErrors.insert(pathErrors.end(), (*iNode)->m_certErrors.begin(),
			(*iNode)->m_certErrors.end());
		pathErrors.Splice(pathErrors.end(), perCertPathErrors);
		

		// Add this cert to the list of certs to be cached 
		certsToBeCached.push_back(CachableCert((*iNode)->GetCert(), 
			pathVars.authTable, pathVars.mappings, 
			pathVars.explicitPolicy, pathVars.pathExpiration, 
			subjError, (*iNode)->m_certErrors, pathErrors));

		// Update the issuer node and errors for the next loop
		issuerNode = *iNode;
		issuerErrors = subjError;
	}

	// Wait for the CRL revocation callbacks to complete only when the per validation revocation
	// checking has not been disabled.
	if (revCheckingNeeded)
	{
#ifndef NOTHREADS
		if (revThreadID != 0)
      {
#ifdef WIN32
         WaitForSingleObject(revThreadID, INFINITE);
         CloseHandle(revThreadID);
#else //WIN32
         pthread_join(revThreadID, NULL);
#endif //WIN32
      }
#endif //NOTHREADS
	}
	
	// Add any revocation specific errors to the errorInfoList if necessary and 
	// add certs to the cache
	RevStatus_LL* pRevStatus = args.m_revStatus;
	ErrorInfoList revPathErrors;
	CachableCertList::iterator iCert = certsToBeCached.begin();
	issuerErrors = CM_NO_ERROR;
	for (; iCert != certsToBeCached.end(); iCert++)
	{
		CachableCert& certToCache = *iCert;

		// Get the original subject error for this cert
		subjError = certToCache.m_error;
		
		// If revocotion checking was performed get errors if any
		if (revCheckingNeeded)
		{
			// If the cert in the revocation status structure is not the same as what was
			// in the original path, something is broken. Report the error and stop.
			if ((pRevStatus == NULL) || (ASN::Bytes (pRevStatus->encCert.num, pRevStatus->encCert.data) 
				!= certToCache.m_cert.GetEnc()))
			{
				subjError = CM_PATH_VALIDATION_ERROR;
				break;
			}
			
			// If the revocation callback failed report the error and stop
			if (args.m_returnVal != CRL_RESP_SUCCESS)
			{
				switch (args.m_returnVal)
				{
				case CRL_RESP_MALFORMED:
					revPathErrors.AddError(CM_REV_STATUS_NOT_AVAIL, certToCache.m_cert.base().subject,
						"CRL Server returned CRL_RESP_MALFORMED");
					break;
				case CRL_RESP_INTERNAL_ERR:
					revPathErrors.AddError(CM_REV_STATUS_NOT_AVAIL, certToCache.m_cert.base().subject,
						"CRL Server returned CRL_RESP_INTERNAL_ERR");
					break;
				case CRL_RESP_TRY_LATER:
					revPathErrors.AddError(CM_REV_STATUS_NOT_AVAIL, certToCache.m_cert.base().subject,
						"CRL Server returned CRL_RESP_TRY_LATER");
					break;
				}

				subjError = CM_PATH_VALIDATION_ERROR;
				break;
			}
			else if (pRevStatus->pRevInfo && (pRevStatus->pRevInfo->status == CM_STATUS_REVOKED))
			{					
				// Add the path errors to the local error list
				revPathErrors.AddError(*pRevStatus->pRevInfo, certToCache.m_cert.base());
				
				// If any cert is revoked update the return code.
				subjError = CM_PATH_VALIDATION_ERROR;
			}
			else if (pRevStatus->pRevInfo && (pRevStatus->pRevInfo->status == CM_STATUS_UNKNOWN))
			{
				// Add the path errors to the local error list
				revPathErrors.AddError(CM_REV_STATUS_NOT_AVAIL, certToCache.m_cert.base().subject);
				
				// If the CRL status is unkown for this cert update the return code.
				subjError = CM_PATH_VALIDATION_ERROR;
			}
			pRevStatus = pRevStatus->next;
			
			//Add the revocation errors to this cacheable cert
			certToCache.m_pathErrors.Insert(revPathErrors);
		}
		

		// Add this cert to the cache if it's issuer was cached
		// and not validated against a time stamp
		const CachedCertRef *pCertRef = NULL;
		if ((issuerErrors != CMI_VALID_CERT_NOT_CACHED) &&
			(issuerErrors != CMI_INVALID_CERT_NOT_CACHED) &&
			(pathVars.m_pValidationTime == NULL) &&
			(performRevChecking == true))
		{
			// Acquire global session lock
			ASN::ReadLock lock = AcquireSessionReadLock(sessionID);
			
			// Add this cert to the session cache
			pCertRef = GetCertCache(sessionID).
				Add(certToCache.m_cert, issuerCerts, certToCache.m_authSet,
				certToCache.m_mappings, certToCache.m_explicitPolFlag,
				certToCache.m_expireTime, certToCache.m_certErrors,
				certToCache.m_pathErrors, true);
		}

		// Set error code and log errors if needed
		// If cert was valid....
		if ((subjError == CM_NO_ERROR) && (issuerErrors == CM_NO_ERROR))			
		{
			logXML.WriteData(CM_LOG_LEVEL_1, "Cert subject=", certToCache.m_cert.base().subject,
				"serialNum", certToCache.m_cert.base().serialNumber, "state=", "valid");
		}
		// else if the cert issuer was valid and not cached then report same error for this
		// cert if valid and continue
		else if ((issuerErrors == CMI_VALID_CERT_NOT_CACHED) && (subjError == CM_NO_ERROR))
		{
			logXML.WriteData(CM_LOG_LEVEL_1, "Cert subject=", certToCache.m_cert.base().subject,
				"serialNum", certToCache.m_cert.base().serialNumber, "state=", "valid but not cached");
		}
		// else cert is invalid...
		else
		{
			subjError = CM_PATH_VALIDATION_ERROR;
			logXML.WriteData(CM_LOG_LEVEL_1, "Cert subject=", certToCache.m_cert.base().subject,
				"serialNum", certToCache.m_cert.base().serialNumber, "state=", "invalid");
		}
		
		// Add this cert to the issuer list
		if (pCertRef)
		{
			issuerCerts.push_back(*pCertRef);
			delete pCertRef;
		}
		else
		{
			// Change error since we could not cache the cert.
			if (subjError == CM_NO_ERROR)
				subjError = CMI_VALID_CERT_NOT_CACHED;
			else 
				subjError = CMI_INVALID_CERT_NOT_CACHED;
		}

		// Add the revocation errors to the local error list
		pathErrors.Insert(revPathErrors);

		// Save issuer error
		issuerErrors = subjError;
	}
	
   // Copy revocation data and free any revocation status data
	if (revCheckingNeeded)
	{
      bool copySucceeded = true;
      // If wantBacks were requested, copy out the revocation data
      if (pRevDataList != NULL)
      {
         try
         {
            *pRevDataList = *args.m_pRevocationData;
         } 
         catch (...)
         {
            // revocation data failed to copy
            copySucceeded = false;
         }
      }
		// Acquire global session lock
		ASN::ReadLock lock = AcquireSessionReadLock(sessionID);		

      // Free the RevInfo(s) and encoded revocation data
		const RevCallbackFunctions& revFuncs = GetRevCallbacksFromRef(sessionID);
		if (revFuncs.pFreeStatus)
			revFuncs.pFreeStatus(revFuncs.extRevHandle, args.m_revStatus,
                              &args.m_pRevocationData);

      // Free the rest of the revStatus_LL that this DLL allocated
		freeRevStatus(&args.m_revStatus);

      // If copying the CRL(s)/OCSP response(s) failed throw so that a permanent
      // error is reported.
      if (copySucceeded == false)
         throw CML_ERR(CM_MEMORY_ERROR);
	}
	
	// Add the path errors to the main error list
	if (pErrors != NULL)
	{
		pErrors->Splice(pErrors->end(), pathErrors);
	}
	
	return subjError;
} // end of ValidateCertPath()


////////////////////////////////////
// StateVars class implementation //
////////////////////////////////////
StateVars::StateVars(ulong sessionID, PathState &state,	
                     int pathLen, const ASN::Time* pValidationTime) : 
                     state(state), m_pValidationTime(pValidationTime)
{
	pParams = NULL;

	// Set the authority-constrained-policy table to the proper depth and
	// write any-policy in the zeroth and first columns of the zeroth row
	authTable.Init(pathLen - 1);

	// Initialize the explicit-policy-indicator, the
	// policy-mapping-inhibit-indicator, and the inhibit-any-policy-indicator
	// to the initial values in the session
	const Session& session = GetSessionFromRef(sessionID);
	ASN::ReadLock lock = AcquireSessionReadLock(sessionID);
	explicitPolicy = session.GetPolicySettings().requirePolicy;
	noPolicyMapping = session.GetPolicySettings().inhibitMapping;
	inhibitAnyPolicy = session.GetPolicySettings().inhibitAnyPolicy;

	// Initialize the path-depth to one
	pathDepth = 1;

	// Initialize the pending constraints to unset
	pendingExplicitPolicy = -1;
	pendingPolicyMapping = -1;
	pendingAnyPolicy = -1;

	// Initialize the path length constraint
	maxPathDepth = -1;
}


void StateVars::Update(const ASN::Cert& cert, bool isEE)
{
	// Set the max path length state variable for the next link in the path.
	// If present and if the cert is not self-issued, decrement by one.
	if ((maxPathDepth > 0) && !cert.IsSelfIssued())
		--maxPathDepth;

	// Set the path expiration time to the lesser of the current expiration
	// time and the cert's expiration time
	if (cert.validity.notAfter < pathExpiration)
		pathExpiration = cert.validity.notAfter;

	// Update the inherited parameters
	if (cert.pubKeyInfo.algorithm.ParametersArePresent())
		pParams = cert.pubKeyInfo.algorithm.parameters;
	else
	{
		// If the public key algorithm does not inherit parameters,
		// set the inherited parameters to NULL
		if ((cert.pubKeyInfo != gDSA_OID) &&
			(cert.pubKeyInfo != gOIW_DSA) &&
			(cert.pubKeyInfo != gEC_KEY_OID) &&
			(cert.pubKeyInfo != gDSA_KEA_OID))
			pParams = NULL;
	}
	
	// If the basic constraints extension is present and if a path length
	// constraint is specified, set the state variable to the lesser of the
	// current state variable and the path length constraint + 1.
	/* Note: One must be added to the state variable, maxPathDepth, because of
	the way the library checks for path limits.  Unlike X.509, maxPathDepth
	indicates how many certs can follow (X.509 uses it to indicate how many
	issuer certs can follow--a subtle but important difference). */
	if (cert.exts.pBasicCons != NULL)
	{
		short newPathLen = (short)cert.exts.pBasicCons->pathLen;
		if (cert.exts.pBasicCons->pathLen > SHRT_MAX)
			newPathLen = -1;

		if (newPathLen >= 0)	// If the path length is present...
		{
			++newPathLen;		// increment by one
			if ((maxPathDepth < 0) || (newPathLen < maxPathDepth))
				maxPathDepth = newPathLen;
		}
	}

	// If this cert is an intermediate cert, perform the following steps
	if (!isEE)
	{
		
		// If the name constraints extension is present...
		if (cert.exts.pNameCons != NULL)
		{
			// If the permittedSubtrees component is present, set the
			// permitted-subtrees state variable to the intersection of its
			// current value and the value in the extension
			// (just add the value to the lists of permitted subtrees in the
			// state variable)
			if (!cert.exts.pNameCons->permitted.empty())
				permitted.push_back(cert.exts.pNameCons->permitted);

			// If the excludedSubtrees component is present, set the
			// excluded-subtrees state variable to the union of its current
			// value and the value in the extension
			// (just append the value to the state variable)
			excluded.insert(excluded.end(),
				cert.exts.pNameCons->excluded.begin(),
				cert.exts.pNameCons->excluded.end());

			// If the requiredNameForms component is present, set the
			// required-name-forms state variable to the union of its
			// current value and the value in the extension
			// (just add the value to the lists of required name forms in the
			// state variable)
			if (!cert.exts.pNameCons->requiredNames.IsEmpty())
				reqNames.push_back(cert.exts.pNameCons->requiredNames);
		}

		// Process the policy mappings
		authTable.ProcessMappings(cert.exts.pPolicyMaps, pathDepth,
			noPolicyMapping, mappings);
		
		// If the policy-mapping-inhibit-indicator is not set
		if (!noPolicyMapping)
		{
			/* If the policy-mapping-inhibit-pending indicator is set and the
			certificate is not self-issued, decrement the value, and if the
			value is now zero, set the policy-mapping-inhibit-indicator. */
			if ((pendingPolicyMapping > 0) && !cert.IsSelfIssued())
			{
				if (--pendingPolicyMapping == 0)
					noPolicyMapping = true;
			}

			/* If the policy constraints extension is present and the
			inhibitPolicyMapping component is present:
			1. If the inhibitPolicyMapping is 0, set the policy-mapping-
			inhibit-indicator.
			2. If the inhibitPolicyMapping is not 0, set the policy-mapping-
			inhibit-pending value to the lesser of the SkipCerts value and the
			previous policy-mapping-inhibit-pending value (if previously set). */
			if (cert.exts.pPolicyCons != NULL)
			{
				long inhibitMappingSkipCertsValue =
					cert.exts.pPolicyCons->inhibitPolicyMapping;
				if (inhibitMappingSkipCertsValue > SHRT_MAX)
					inhibitMappingSkipCertsValue = -1;

				if (inhibitMappingSkipCertsValue == 0)
					noPolicyMapping = true;
				else if (inhibitMappingSkipCertsValue > 0)
				{
					if ((pendingPolicyMapping < 0) ||
						(inhibitMappingSkipCertsValue < pendingPolicyMapping))
					{
						pendingPolicyMapping =
							(short)inhibitMappingSkipCertsValue;
					}
				}
				// else inhibitPolicyMapping component is absent
			}
		} // end of if (!noPolicyMapping)

		// If the inhibit-any-policy-indicator is not set
		if (!inhibitAnyPolicy)
		{
			/* If the inhibit-any-policy-pending indicator is set and the
			certificate is not self-issued, decrement the value, and if the
			value is now zero, set the inhibit-any-policy-indicator. */
			if ((pendingAnyPolicy > 0) && !cert.IsSelfIssued())
			{
				if (--pendingAnyPolicy == 0)
					inhibitAnyPolicy = true;
			}

			/* If the inhibit any policy extension is present:
			1. If the SkipCerts value is 0, set the inhibit-any-policy-
			indicator.
			2. If the SkipCerts value is not 0, set the inhibit-any-policy-
			pending value to the lesser of the SkipCerts value and the
			previous inhibit-any-policy-pending value (if previously set). */
			if (cert.exts.pInhibitAnyPolicy != NULL)
			{
				long inhibitAnyPolicySkipCertsValue =
					cert.exts.pInhibitAnyPolicy->value;
				if (inhibitAnyPolicySkipCertsValue > SHRT_MAX)
					inhibitAnyPolicySkipCertsValue = -1;
				
				if (inhibitAnyPolicySkipCertsValue == 0)
					inhibitAnyPolicy = true;
				else if (inhibitAnyPolicySkipCertsValue > 0)
				{
					if ((pendingAnyPolicy < 0) ||
						(inhibitAnyPolicySkipCertsValue < pendingAnyPolicy))
					{
						pendingAnyPolicy =
							(short)inhibitAnyPolicySkipCertsValue;
					}
				}
				// else inhibitAnyPolicySkipCertsValue is excessively large
			}
		} // end of if (!inhibitAnyPolicy)

	} // end of intermediate cert processing

	// If the explicit-policy-indicator is not set:
	if (!explicitPolicy)
	{
		/* If the explict-policy-pending indicator is set and the certificate
		is not a self-issued intermediate cert, decrement the value, and if
		the value is now zero, set the explicit-policy-indicator. */
		if ((pendingExplicitPolicy > 0) && !cert.IsSelfIssued())
		{
			if (--pendingExplicitPolicy == 0)
				explicitPolicy = true;
		}

		/* If the policy constraints extension is present and the
		requireExplicitPolicy component is present:
		1. If the requireExplicitPolicy is 0, set the explicit-policy-indicator.
		2. If the requireExplicitPolicy is not 0, set the explicit-policy-
		pending value to the lesser of the SkipCerts value and the previous
		explicit-policy-pending value (if previously set). */
		if (cert.exts.pPolicyCons != NULL)
		{
			long requirePolicySkipCertsValue =
				cert.exts.pPolicyCons->requireExplicitPolicy;
			if (requirePolicySkipCertsValue > SHRT_MAX)
				requirePolicySkipCertsValue = -1;

			if (requirePolicySkipCertsValue == 0)
				explicitPolicy = true;
			else if (requirePolicySkipCertsValue > 0)
			{
				if ((pendingExplicitPolicy < 0) ||
					(requirePolicySkipCertsValue < pendingExplicitPolicy))
					pendingExplicitPolicy = (short)requirePolicySkipCertsValue;
			}
			// else requireExplicitPolicy component is absent
		}
	} // end of if (!explicitPolicy)

	// Increment the path depth
	++pathDepth;
}


////////////////////////////////////////////
// PermittedSubtrees class implementation //
////////////////////////////////////////////
bool PermittedSubtrees::IsNameWithin(const ASN::DN& dn) const
{
	// Check that the specified DN is within each permitted-subtrees set
	for (const_iterator i = begin(); i != end(); ++i)
	{
		if (!i->IsNameWithin(dn, true))
			return false;
	}

	return true;
}


bool PermittedSubtrees::AreNamesWithin(const ASN::GenNames& names) const
{
	// Check that the specified GenNames are within each permitted-subtrees set
	for (const_iterator i = begin(); i != end(); ++i)
	{
		if (!i->AreNamesWithin(names, true))
			return false;
	}

	return true;
}



/************************************************************************
 FUNCTION:  areCommPrivsSubset()
 
 Description: This function returns true if the subject's privileges are
 present in one of the issuer's CAConstraints, otherwise false is returned.
*************************************************************************/
bool areCommPrivsSubset(const SNACC::CommPrecFlags& subjPrivs,
						const ASN::AttributeList& caConstraints)
{
	// Find the issuer's CommPrivs constraints
	ASN::AttributeList::const_iterator iIssuerPrivs =
		caConstraints.Find(ASN::Attribute::CommPrivs);
	while (iIssuerPrivs != caConstraints.end())
	{
		if (iIssuerPrivs->GetValues().pCommPrivs != NULL)
		{
			const SNACC::CommPrecFlags& issPrivs =
				*iIssuerPrivs->GetValues().pCommPrivs;

			bool allBitsSet = true;
			for (unsigned int i = 0; i < subjPrivs.BitLen() && allBitsSet; i++)
			{
				if (subjPrivs.GetBit(i) && !issPrivs.GetBit(i))
					allBitsSet = false;
			}

			if (allBitsSet)
				return true;
		}

		iIssuerPrivs = caConstraints.FindNext(iIssuerPrivs,
			ASN::Attribute::CommPrivs);
	}

	return false;
} // end of areCommPrivsSubset()


/************************************************************************
 FUNCTION:  areKmFlagsSubset()
 
 Description: This function returns true if all of the subject's KM
 privileges are present in the issuer's privileges.
*************************************************************************/
bool areKmFlagsSubset(const SNACC::KmPrivFlagsSeqOf* pSubj,
					  const SNACC::KmPrivFlagsSeqOf* pIssuer)
{
	if (pSubj == NULL)
		return true;
	else if (pIssuer == NULL)
		return false;

	SNACC::KmPrivFlagsSeqOf::const_iterator i;
	for (i = pSubj->begin(); i != pSubj->end(); ++i)
	{
		SNACC::KmPrivFlagsSeqOf::const_iterator j = pIssuer->begin();
		while ((j != pIssuer->end()) && (*i != *j))
			++j;

		if (j == pIssuer->end())
			return false;
	}

	return true;
}


/************************************************************************
 FUNCTION:  arePrivsSubset()
 
 Description: This function returns true if the subject's privileges are
 present in one of the issuer's CAConstraints, otherwise false is returned.
*************************************************************************/
bool arePrivsSubset(const SNACC::PrivilegeFlags& subjPrivs,
					const ASN::AttributeList& caConstraints)
{
	// Find the issuer's constraints for the type of privileges
	// in the subject's privileges
	ASN::AttributeList::const_iterator iIssuerPrivs =
		caConstraints.Find(ASN::Attribute::SigOrKMPrivs);
	while (iIssuerPrivs != caConstraints.end())
	{
		if (iIssuerPrivs->GetValues().pSigKMPrivs != NULL)
		{
			const ASN::SigOrKMPrivileges& issPrivs =
				*iIssuerPrivs->GetValues().pSigKMPrivs;
			
			// For each value...
			ASN::SigOrKMPrivileges::const_iterator i = issPrivs.begin();
			for ( ; i != issPrivs.end(); i++)
			{
				if (i->choiceId == subjPrivs.choiceId)
				{
					if (subjPrivs.choiceId ==
						SNACC::PrivilegeFlags::sigFlagsCid)
					{
						if (areSigFlagsSubset(subjPrivs.sigFlags->sigPrivFlags,
							i->sigFlags->sigPrivFlags))
							return true;
					}
					else if (subjPrivs.choiceId == 
						SNACC::PrivilegeFlags::kmFlagsCid)
					{
						if (areKmFlagsSubset(subjPrivs.kmFlags->kmPrivFlags,
							i->kmFlags->kmPrivFlags))
							return true;
					}
				}
			}
		}

		iIssuerPrivs = caConstraints.FindNext(iIssuerPrivs,
			ASN::Attribute::SigOrKMPrivs);
	}

	return false;
} // end of arePrivsSubset()


/************************************************************************
 FUNCTION:  areSigFlagsSubset()
 
 Description: This function returns true if all of the subject's sig
 privileges are present in the issuer's privileges.
*************************************************************************/
bool areSigFlagsSubset(const SNACC::SigPrivFlagsSeqOf* pSubj,
					   const SNACC::SigPrivFlagsSeqOf* pIssuer)
{
	if (pSubj == NULL)
		return true;
	else if (pIssuer == NULL)
		return false;

	SNACC::SigPrivFlagsSeqOf::const_iterator i;
	for (i = pSubj->begin(); i != pSubj->end(); ++i)
	{
		SNACC::SigPrivFlagsSeqOf::const_iterator j = pIssuer->begin();
		while ((j != pIssuer->end()) && (*i != *j))
			++j;

		if (j == pIssuer->end())
			return false;
	}

	return true;
}


void buildFortezzaPubKey(ASN::Bytes& pubKey, ASN::Bytes& params,
						 const Pub_key_struct& cmPubKey)
{
	// Check that required parameters are present
	if ((cmPubKey.params.dsa_kea == NULL) || (cmPubKey.key.combo == NULL))
		throw CML_ERR(CM_INVALID_PARAMETER);
	
	const Mosaic_key_struct& comboKey = *cmPubKey.key.combo;
	
	// Build the Kea_Dss_Parms
	SNACC::Kea_Dss_Parms parms;
	if (comboKey.diff_kea == NULL)
	{
		// Initialize the Common_Parms choice
		parms.choiceId = SNACC::Kea_Dss_Parms::commonParmsCid;
		parms.commonParms = new SNACC::Fortezza_Parms;
		if (parms.commonParms == NULL)
			throw CML_MEMORY_ERR;
		
		parms.commonParms->p.Set((const char*)cmPubKey.params.dsa_kea->p.data,
			cmPubKey.params.dsa_kea->p.num);
		parms.commonParms->q.Set((const char*)cmPubKey.params.dsa_kea->q.data,
			cmPubKey.params.dsa_kea->q.num);
		parms.commonParms->g.Set((const char*)cmPubKey.params.dsa_kea->g.data,
			cmPubKey.params.dsa_kea->g.num);
	}
	else
	{
		// Initialize the Different_Parms choice
		parms.choiceId = SNACC::Kea_Dss_Parms::differentParmsCid;
		parms.differentParms = new SNACC::Different_Parms;
		if (parms.differentParms == NULL)
			throw CML_MEMORY_ERR;
		
		parms.differentParms->kea_Parms.p.Set((const char*)
			comboKey.diff_kea->p.data, comboKey.diff_kea->p.num);
		parms.differentParms->kea_Parms.q.Set((const char*)
			comboKey.diff_kea->q.data, comboKey.diff_kea->q.num);
		parms.differentParms->kea_Parms.g.Set((const char*)
			comboKey.diff_kea->g.data, comboKey.diff_kea->g.num);
		
		parms.differentParms->dss_Parms.p.Set((const char*)
			cmPubKey.params.dsa_kea->p.data, cmPubKey.params.dsa_kea->p.num);
		parms.differentParms->dss_Parms.q.Set((const char*)
			cmPubKey.params.dsa_kea->q.data, cmPubKey.params.dsa_kea->q.num);
		parms.differentParms->dss_Parms.g.Set((const char*)
			cmPubKey.params.dsa_kea->g.data, cmPubKey.params.dsa_kea->g.num);
	}
	
	// Encode the parameters
	params.Encode(parms, "SNACC::Kea_Dss_Parms");
	
	// Determine size of buffer required for public key and allocate it
	ulong keySize = comboKey.dsa_y.num + 2 + comboKey.kea_y.num + 2 +
		CM_KMID_LEN + 2 + comboKey.dsa_privs.num + 2 +
		comboKey.kea_privs.num + comboKey.kea_clearance.num;
	
	uchar *keyBuf = new uchar[keySize];
	if (keyBuf == NULL)
		throw CML_MEMORY_ERR;
	
	// Fill in the key buffer
	uchar* pBuf = keyBuf;
	*pBuf++ = comboKey.kea_ver;
	*pBuf++ = comboKey.kea_type;
	memcpy(pBuf, comboKey.kmid, CM_KMID_LEN);
	pBuf += CM_KMID_LEN;
	
	memcpy(pBuf, comboKey.kea_clearance.data, comboKey.kea_clearance.num);
	pBuf += comboKey.kea_clearance.num;
	
	memcpy(pBuf, comboKey.kea_privs.data, comboKey.kea_privs.num);
	pBuf += comboKey.kea_privs.num;
	
	*pBuf++ = 0x00;
	*pBuf++ = 0x80;
	
	memcpy(pBuf, comboKey.kea_y.data, comboKey.kea_y.num);
	pBuf += comboKey.kea_y.num;
	
	*pBuf++ = comboKey.dsa_ver;
	*pBuf++ = comboKey.dsa_type;
	
	memcpy(pBuf, comboKey.dsa_privs.data, comboKey.dsa_privs.num);
	pBuf += comboKey.dsa_privs.num;
	
	*pBuf++ = 0x00;
	*pBuf++ = 0x80;
	
	memcpy(pBuf, comboKey.dsa_y.data, comboKey.dsa_y.num);
	
	// Set the public key
	pubKey.Set(keySize, keyBuf);

   // Delete the temporary key buffer
   delete[] keyBuf;

} // end of buildFortezzaPubKey()


/************************************************************************
 FUNCTION:  checkCaConst()
 
 Description: This function performs the SDN.706 cert path processing of
 the subject's MISSI/DMS-unique attributes.
 If the SigOrKmPrivileges and/or CommPrivileges attributes are present,
 this function checks that those privileges are a subset of the issuer's
 CAClearanceConstraints privileges.
 If subject is a CA and if the subject has the CAClearanceConstraints
 attribute, then this function checks that the subject's privileges are
 a subset of the issuer's CAClearanceConstraints privileges.
 CM_NO_ERROR is returned if all of the checks pass, otherwise an error is
 returned.
*************************************************************************/
short checkCaConst(bool isCA, const ASN::AttributeList* pSubjAttribs,
				   const ASN::AttributeList* pIssuerAttribs)
{
	// If the subject directory attributes aren't present, just return
	if (pSubjAttribs == NULL)
		return CM_NO_ERROR;

	// Find the CAClearanceConstraints attribute in the issuer's cert
	const ASN::AttributeList* pCAConsts = NULL;
	if (pIssuerAttribs != NULL)
	{
		ASN::AttributeList::const_iterator iCAConst =
			pIssuerAttribs->Find(ASN::Attribute::CAClearanceConst);
		if ((iCAConst != NULL) && (iCAConst != pIssuerAttribs->end()))
			pCAConsts = iCAConst->GetValues().pCACons;
	}

	// If the subject cert is a CA, check that the CAClearanceConstraints
	// in the subject's cert (if present), is a subset of the issuer's
	// CAClearanceConstraints
	if (isCA)
	{
		// Find the CAClearanceConstraints in the subject's cert
		ASN::AttributeList::const_iterator iSubj =
			pSubjAttribs->Find(ASN::Attribute::CAClearanceConst);
		if (iSubj != pSubjAttribs->end())
		{
			if (iSubj->GetValues().pCACons != NULL)
			{
				// If the issuer cert does not have any CAClearanceConstraints,
				// return an error
				if (pCAConsts == NULL)
					return CM_DMS_NO_CA_CONSTRAINTS;

				// Check that the subject's CAClearanceConstraints are a subset
				// of the issuer's CAClearanceConstraints
				if (!isCAConstraintsSubset(*iSubj->GetValues().pCACons,
					*pCAConsts))
					return CM_INVALID_DMS_PRIVILEGE;
			}
		}
	}
   
	// Find the subject's SigOrKmPrivileges.  If present, check that the
	// privileges are a subset of the issuer's CAClearanceConstraints
	ASN::AttributeList::const_iterator iSubj =
		pSubjAttribs->Find(ASN::Attribute::SigOrKMPrivs);
	while (iSubj != pSubjAttribs->end())
	{
		// If the issuer cert does not have any CAClearanceConstraints,
		// return an error
		if (pCAConsts == NULL)
			return CM_DMS_NO_CA_CONSTRAINTS;
		
		if (iSubj->GetValues().pSigKMPrivs != NULL)
		{
			ASN::SigOrKMPrivileges::const_iterator iPriv;
			for (iPriv = iSubj->GetValues().pSigKMPrivs->begin(); iPriv !=
				iSubj->GetValues().pSigKMPrivs->end(); iPriv++)
			{
				// Check that the privileges asserted in the subject's
				// SNACC::PrivilegeFlags are a subset of the issuer's
				// constraints
				if (!arePrivsSubset(*iPriv, *pCAConsts))
					return CM_INVALID_DMS_PRIVILEGE;
			}
		}

		iSubj = pSubjAttribs->FindNext(iSubj, ASN::Attribute::SigOrKMPrivs);
	}

	// Find the subject's CommPrivileges.  If present, check that the
	// privileges are a subset of the issuer's CAClearanceConstraints
	iSubj = pSubjAttribs->Find(ASN::Attribute::CommPrivs);
	while (iSubj != pSubjAttribs->end())
	{
		// If the issuer cert does not have any CAClearanceConstraints,
		// return an error
		if (pCAConsts == NULL)
			return CM_DMS_NO_CA_CONSTRAINTS;
		
		if (iSubj->GetValues().pCommPrivs != NULL)
		{
			if (!areCommPrivsSubset(*iSubj->GetValues().pCommPrivs,
				*pCAConsts))
				return CM_INVALID_DMS_PRIVILEGE;
		}

		iSubj = pSubjAttribs->FindNext(iSubj, ASN::Attribute::CommPrivs);
	}

	return CM_NO_ERROR;
} // end of checkCaConst()


/************************************************************************
 FUNCTION:  checkExtKeyUsage()
 
 Description: This function checks that the anyExtendedKeyUsage OID is
 present in the extended key usage extension.  If not, either a single
 CM_INVALID_EXT_KEY_USE error or one or more CM_UNRECOGNIZED_EXT_KEY_USAGE
 errors are added to the list of errors.
*************************************************************************/
void checkExtKeyUsage(const ASN::ExtKeyUsageExtension& extKeyUse,
					  ErrorInfoList& errors, const ASN::Cert& cert)
{
	bool unknownKeyUse = false;

	std::list<SNACC::KeyPurposeId>::const_iterator i;
	for (i = extKeyUse.begin(); i != extKeyUse.end(); i++)
	{
		// If the anyExtendedKeyUsage OID is present, then the cert isn't
		// restricted to any other key usages present
		if (*i == SNACC::anyExtendedKeyUsage)
			return;

		// REN -- 11/1/2002 -- If the key usage is Entrust's unknown CA
		// key usage or Microsoft's certTrustListSigning, then just return
		// without reporting an error
		if ((*i == gEXT_KEY_USE_EntrustCA) ||
			(*i == gEXT_KEY_USE_msCTLSigning))
			return;
	}

	for (i = extKeyUse.begin(); i != extKeyUse.end(); i++)
	{
		// If the key usage isn't recognized, record an error with the OID.
		// This allows the application to recognize one of the OIDs and
		// possibly continue processing
		if ((*i != gEXT_KEY_USE_serverAuth) &&
			(*i != gEXT_KEY_USE_clientAuth) &&
			(*i != gEXT_KEY_USE_codeSigning) &&
			(*i != gEXT_KEY_USE_emailProtection) &&
			(*i != gEXT_KEY_USE_timeStamping) &&
			(*i != gEXT_KEY_USE_OCSPSigning))
		{
			unknownKeyUse = true;
			errors.AddError(CM_UNRECOGNIZED_EXT_KEY_USAGE, cert, *i);
		}
	}

	// If all of the key purposes are recognized, the record an error since
	// none of the recognized OIDs indicate a CA.
	if (!unknownKeyUse)
		errors.AddError(CM_INVALID_EXT_KEY_USE, cert);

} // end of checkExtKeyUsage()


void cvtBytesToHugeInt(SNACC::AsnInt& hugeInt, const Bytes_struct& bytes)
{
	// Check if there is any data to convert
	if ((bytes.num == 0) || (bytes.data == NULL))
		return;

	uchar* pBuf;
	ulong len = bytes.num;
	bool tempBufUsed = false;

	// If the sign bit is set, copy the data into a temporary buffer with
	// a leading zero byte
	if ((*bytes.data & 0x80) != 0)
	{
		len++;
		pBuf = new uchar[len];
		if (pBuf == NULL)
			throw CML_MEMORY_ERR;
		*pBuf = 0;
		memcpy(&pBuf[1], bytes.data, bytes.num);
		tempBufUsed = true;
	}
	else
	{
		// Just set pBuf to the data
		pBuf = (uchar*)bytes.data;

		// Skip over any zero bytes that need to be removed (unlikely)
		while ((*pBuf == 0) && (len > 1) && ((pBuf[1] & 0x80) == 0))
		{
			pBuf++;
			--len;
		}
	}

	try {
		hugeInt.Set((const unsigned char*)pBuf, len);
		if (tempBufUsed)
			delete[] pBuf;
	}
	catch (...) {
		if (tempBufUsed)
			delete[] pBuf;
		throw;
	}
} // end of cvtBytesToHugeInt()


void cvtPolicyStructToList(ASN::CertPolicyList& list,
						   const Policy_struct* policyList)
{
	try {
		list.clear();

		const Policy_struct* pPolicy = policyList;
		while (pPolicy != NULL)
		{
			ASN::CertPolicy tmpPolicy(pPolicy->policy_id);

			const Qualifier_struct* pQual = pPolicy->qualifiers;
			while (pQual != NULL)
			{
				ASN::PolicyQualifier tmpQual(pQual->qualifier_id);

				// Check that the qualifier is present
				if (pQual->qual.cpsURI == NULL)
					throw CML_ERR(CM_NULL_POINTER);

				if (pQual->flag == CM_QUAL_CPS)
				{
					// Encode the PKIX CPS pointer qualifier
					SNACC::IA5String cpsString(pQual->qual.cpsURI);
					tmpQual.qualifier = new ASN::Bytes;
					if (tmpQual.qualifier == NULL)
						throw CML_MEMORY_ERR;
					tmpQual.qualifier->Encode(cpsString, "SNACC::IA5String");
				}
				else if (pQual->flag == CM_QUAL_UNOTICE)
				{
					// Encode the PKIX user notice qualifier
					SNACC::UserNotice snacc;
					if (pQual->qual.userNotice->noticeRef != NULL)
					{
						// Set the optional NoticeReference
						snacc.noticeRef = new SNACC::NoticeReference;
						if (snacc.noticeRef == NULL)
							throw CML_MEMORY_ERR;

						// Set the organization DisplayText
						if (pQual->qual.userNotice->noticeRef->org == NULL)
							throw CML_ERR(CM_NULL_POINTER);
						snacc.noticeRef->organization.choiceId =
							SNACC::DisplayText::utf8StringCid;
						snacc.noticeRef->organization.utf8String = new
							SNACC::UTF8String(pQual->qual.userNotice->noticeRef->org);
						if (snacc.noticeRef->organization.utf8String == NULL)
							throw CML_MEMORY_ERR;

						// Set the noticeNumbers
						fillSnaccNoticeNumbers(snacc.noticeRef->noticeNumbers,
							pQual->qual.userNotice->noticeRef->notices);
					}

					if (pQual->qual.userNotice->explicitText != NULL)
					{
						// Set the optional DisplayText
						snacc.explicitText = new SNACC::DisplayText;
						if (snacc.explicitText == NULL)
							throw CML_MEMORY_ERR;

						snacc.explicitText->choiceId =
							SNACC::DisplayText::utf8StringCid;
						snacc.explicitText->utf8String = new
							SNACC::UTF8String(pQual->qual.userNotice->explicitText);
						if (snacc.explicitText->utf8String == NULL)
							throw CML_MEMORY_ERR;
					}
					
					tmpQual.qualifier = new ASN::Bytes;
					if (tmpQual.qualifier == NULL)
						throw CML_MEMORY_ERR;
					tmpQual.qualifier->Encode(snacc, "SNACC::UserNotice");
				}
				else if (pQual->flag == CM_QUAL_UNKNOWN)
				{
					// Copy the unknown encoded qualifier
					tmpQual.qualifier = new ASN::Bytes(*pQual->qual.unknown);
					if (tmpQual.qualifier == NULL)
						throw CML_MEMORY_ERR;
				}
				else
					throw CML_ERR(CM_UNKNOWN_ERROR);

				tmpPolicy.qualifiers.push_back(tmpQual);
				pQual = pQual->next;
			}

			list.push_back(tmpPolicy);

			pPolicy = pPolicy->next;
		}
	}
	catch (...) {
		list.clear();
		throw;
	}
} // end of cvtPolicyStructToList()


void fillSnaccNoticeNumbers(SNACC::NoticeReferenceSeqOf& snacc,
							const Bytes_struct_LL* pNumList)
{
	while (pNumList != NULL)
	{
		if (pNumList->bytes_struct == NULL)
			throw CML_ERR(CM_NULL_POINTER);
		
		SNACC::AsnInt& newInt = *snacc.append();
		newInt.Set(pNumList->bytes_struct->data, pNumList->bytes_struct->num);
		
		pNumList = pNumList->next;
	}
}


/************************************************************************
 FUNCTION:  isCAConstraintsSubset()
 
 Description: This function returns true if the subj CAConstraints is a
 subset of the issuer CAConstraints.  false is returned otherwise.  Only
 the SigOrKmPrivileges and CommPrivileges attributes are checked.
*************************************************************************/
bool isCAConstraintsSubset(const ASN::AttributeList& subj,
						   const ASN::AttributeList& issuer)
{
	// Loop through each of the subject's CAConstraints...
	ASN::AttributeList::const_iterator iSubj;
	for (iSubj = subj.begin(); iSubj != subj.end(); iSubj++)
	{
		if ((iSubj->GetType() == ASN::Attribute::SigOrKMPrivs) &&
			(iSubj->GetValues().pSigKMPrivs != NULL))
		{
			// Loop through each of the values
			ASN::SigOrKMPrivileges::const_iterator iValue =
				iSubj->GetValues().pSigKMPrivs->begin();
			for ( ; iValue != iSubj->GetValues().pSigKMPrivs->end(); iValue++)
			{
				if (!arePrivsSubset(*iValue, issuer))
					return false;
			}
		}
		else if ((iSubj->GetType() == ASN::Attribute::CommPrivs) &&
			(iSubj->GetValues().pCommPrivs != NULL))
		{
			if (!areCommPrivsSubset(*iSubj->GetValues().pCommPrivs, issuer))
				return false;
		}
		// else ignore the CAConstraint
	}

	return TRUE;
} // end of isCAConstraintsSubset()

//////////////////////////////////////////////////////////////////////////////////////////////////////
// Function:   checkRevStatus
// Description:   Calls revocation callback
// Inputs:        void* inargs
// Ouputs:        void* inargs
// Return value:  platform dependent
//////////////////////////////////////////////////////////////////////////////////////////////////////
#ifndef NOTHREADS
#ifdef WIN32 
unsigned __stdcall checkRevStatus(void* inargs)
#else //WIN32
void *checkRevStatus(void* inargs)
#endif //WIN32
#else //NOTHREADS
void checkRevStatus(void* inargs)
#endif //NOTHREADS
{
   RevThreadArgs* args = (RevThreadArgs*)inargs;

   if ((args->m_revFuncs != NULL) && (args->m_revFuncs->pCheckStatus != NULL))
   {
      args->m_returnVal = args->m_revFuncs->pCheckStatus(args->m_revFuncs->extRevHandle,
         0,
         args->m_revStatus,
         args->m_pValidationTime,
         args->m_wantBack, 
         &args->m_pRevocationData);
   }

#ifndef NOTHREADS
#ifdef WIN32
   _endthreadex( 0 );
#endif //WIN32
   return CM_NO_ERROR;
#endif
}

RevStatus_LL* buildRevStatus(const BaseNodePtrDeck& path)
{
   RevStatus_LL* pRevStatus = NULL;
   try 
   {   
      // Build the revStatus list leaving off the Trust Anchor
      BaseNodePtrDeck::const_reverse_iterator iNode;
      
      for (iNode = path.rbegin(); iNode != path.rend() - 1; ++iNode)
      {
         // Allocate and clear the memory for a new link
         RevStatus_LL* pTemp = (RevStatus_LL*)calloc(1, sizeof(revStatus_LL));
         if (pTemp == NULL)
            throw CML_MEMORY_ERR;
         
         // Add this link to the head of the list
         pTemp->next = pRevStatus;
         pRevStatus = pTemp;
         
         (*iNode)->GetCert().GetEnc().FillBytesStruct(pRevStatus->encCert);
      }  
      
      // Add the Trust Anchor as the issuer cert the first time through
      // the loop. Leave the issuer NULL for all successive iterations.
      pRevStatus->m_pEncIssuerCert = 
         (Bytes_struct*)calloc(1, sizeof(Bytes_struct));
      if (pRevStatus->m_pEncIssuerCert == NULL)
         throw CML_MEMORY_ERR;
      (*iNode)->GetCert().GetEnc().FillBytesStruct(*pRevStatus->m_pEncIssuerCert);      
   }
   catch(...)
   {
      freeRevStatus(&pRevStatus);
      pRevStatus = NULL;
   }
   return pRevStatus;      
      
}

void freeRevStatus(RevStatus_LL** pRevocationData)
{
   if (pRevocationData == NULL)
      return;

   RevStatus_LL* pResTemp = NULL;
   RevStatus_LL* pResults = *pRevocationData;

   while (pResults != NULL)
   {
      //Free the encoded cert
      if (pResults->encCert.data)
         free(pResults->encCert.data);
      pResults->encCert.num = 0;
      
      // Free the issuer cert
      if (pResults->m_pEncIssuerCert)
         CM_FreeBytes(&pResults->m_pEncIssuerCert);
      pResults->m_pEncIssuerCert = NULL;         
      
      pResTemp = pResults->next;
      pResults->next = NULL;
      free(pResults);
      pResults = pResTemp;
   }
   
   *pRevocationData = NULL;
}

// end of CM_RetrieveKey.cpp
