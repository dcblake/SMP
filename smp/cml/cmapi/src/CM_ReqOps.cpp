/*****************************************************************************
File:     CM_ReqOps.cpp
Project:  Certificate Management Library
Contents: CM_RequestCerts, CM_RequestCRLs, CM_RequestEncCertPath, and the
		  low-level functions they use.
		  Also contains CML::RequestCerts and CML::RequestCRLs

Created:  17 December 1997
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  16 April 2004

Version:  2.4

Description: This file contains both the high and low-level functions
that perform the retrieval and formatting of the requested objects from the
local database and a remote server.

*****************************************************************************/

/* -------------- */
/* Included Files */
/* -------------- */
#include "PathBuild.h"


// Using declarations
using namespace CML;
using namespace CML::Internal;
using namespace SNACC;
using CML::ASN::Bytes;
using CML::ASN::BytesList;
using CML::ASN::DN;


/* ------------------- */
/* Function Prototypes */
/* ------------------- */
static CertMatchData* buildCertMatchData(const CertMatch_struct& matchInfo);
static CRLMatchData* buildCRLMatchData(const CRLMatch_struct& matchInfo);
static bool buildDistPtName(bool canBeURL, std::string& localIssuer,
							const ASN::DistributionPoint& distPt,
							const DN* pIssuer);
static ASN::GenNames* buildGenNames(const Gen_names_struct* pGenNames);
static bool certMatches(const ASN::Cert& cert, const DN& subject,
						const CertMatchData* pMatchInfo);
static bool certsMatch(EncObject_LL* pObjList, const DN& subject,
					   BytesList& certList, const CertMatchData* pMatchInfo);
static void deleteCertMatchData(CertMatchData* pMatchInfo);
static void deleteCRLMatchData(CRLMatchData* pMatchInfo);
static short matchCRLs(EncObject_LL* pObjList, BytesList& crlList,
					   const CRLMatchData* pMatchInfo, bool updateCRLs);
static bool matchEmailAddress(const ASN::Cert& decCert, const char* emailAddr);

static bool matchPolices(const ASN::CertPolicyList& certPolicies,
						 const ASN::OIDList& acceptable);
static bool matchSubjKeyID(const ASN::Cert& decCert, const Bytes& subjKeyID);
static short setLocationMask(SearchBounds boundsFlag);
static short EncodeThePath(const CertPath& thePath, Bytes& encPath);


/****************************************************************************
 Function:  CML::RequestCerts()
 This function searches the requested search locations for certificates with
 the subject's distinguished name (DN).  If the optional CertMatchData is
 provided, then this function will filter any certificates found using the
 match criteria and return only those certificates that meet the criteria.
 Note:  Any certificates found are added to the existing list -- any existing
 objects in the list are left intact.
 This function returns CM_NO_ERROR if successful, or the appropriate error
 code.
*****************************************************************************/
short CML::RequestCerts(ulong sessionID, BytesList& certificateList,
						const DN& subject, SearchBounds boundsFlag,
						const CertMatchData* pMatchInfo)
{
	// Set the locMask based on the SearchBounds flag
	short locMask = setLocationMask(boundsFlag);
	if (locMask == 0)
		throw CML_ERR(CM_INVALID_PARAMETER);

	// Acquire global session lock
	ASN::ReadLock lock = AcquireSessionReadLock(sessionID);

	// Search the CertCache, if RAM_LOC is specified, for the desired certificates
	bool cachedCertsFound = false;
	if (locMask & RAM_LOC)
	{
		CachedCertList* pCertList = GetCertCache(sessionID).Find(subject,
			false);
		if (pCertList != NULL)
		{
			try {
				// Add any cached certificates that match the specified
				// criteria to the certificate list
				CachedCertList::const_iterator i;
				for (i = pCertList->begin(); i != pCertList->end(); ++i)
				{
					// Add only those certs that match, but aren't already
					// present in the list
					if (certMatches(i->GetRef().base(), subject, pMatchInfo) &&
						!itemPresentInList(certificateList, i->GetRef().GetEnc()))
					{
						certificateList.push_back(i->GetRef().GetEnc());
						cachedCertsFound = true;
					}
				}
			}
			catch (...) {
				delete pCertList;
				throw;
			}
			
			// Delete the cached cert list
			delete pCertList;
		}
	}

	// Get the CML callback functions from the sessionID
	const CallbackFunctions& funcs = GetCallbacksFromRef(sessionID);

	bool certsFound = false;
	while (!certsFound && (locMask != 0))
	{
		// Call the callback function to retrieve the certs
		EncObject_LL* pObjList = NULL;
		short err = funcs.pGetObj(funcs.extHandle, (char*)(const char*)subject,
			CROSS_CERT_TYPE | CA_CERT_TYPE | USER_CERT_TYPE, locMask,
			&pObjList);
		if (err != 0)
			return err;

		// Update the locMask
		if ((boundsFlag == CM_SEARCH_UNTIL_FOUND) && (pObjList != NULL))
		{
			short foundLoc = pObjList->locMask;
			do
			{
				locMask &= ~foundLoc;
				foundLoc >>= 1;
			} while (foundLoc > 0);
		}
		else
			locMask = 0;

		try {
			// Add any certificates found that match the specified criteria to
			// the certificate list
			certsFound = certsMatch(pObjList, subject, certificateList,
				pMatchInfo);

			// Free the list of cert objects from the callback function
			if (pObjList != NULL)
				funcs.pFreeObj(funcs.extHandle, &pObjList);
		}
		catch (...) {
			// Free the list of cert objects from the callback function
			funcs.pFreeObj(funcs.extHandle, &pObjList);
			throw;
		}
	}

	// Return the appropriate result
	if (!certsFound && !cachedCertsFound)
		return CM_NOT_FOUND;

	return CM_NO_ERROR;

} // end of CML::RequestCerts()



/****************************************************************************
 Function:  CML::RequestCRLs()
 This function searches the requested search locations for CRLs with
 the subject's distinguished name (DN).  If the optional CertMatchData is
 provided, then this function will filter any certificates found using the
 match criteria and return only those certificates that meet the criteria.
 Note:  Any certificates found are added to the existing list -- any existing
 objects in the list are left intact.
 This function returns CM_NO_ERROR if successful, or the appropriate error
 code.
*****************************************************************************/
short CML::RequestCRLs(ulong sessionID, BytesList& crlList,
					   const DN* pIssuer, SearchBounds boundsFlag,
					   const CRLMatchData* pMatchInfo,
					   const ASN::DistributionPoint* pDistPoint)
{
	// Check paramters
	if ((pIssuer == NULL) && (pDistPoint == NULL))
		throw CML_ERR(CM_INVALID_PARAMETER);

	// Set the locMask based on the SearchBounds flag
	short locMask = setLocationMask(boundsFlag);
	if (locMask == 0)
		throw CML_ERR(CM_INVALID_PARAMETER);

	// Acquire global session lock
	ASN::ReadLock lock = AcquireSessionReadLock(sessionID);

	// Get the CML callback functions from the sessionID
	const CallbackFunctions& funcs = GetCallbacksFromRef(sessionID);

	// Build local issuer name from the distribution point
	bool isURL = false;
	std::string localIssuer;
	if (pDistPoint == NULL)
		localIssuer = *pIssuer;
	else
	{
		// Build the local issuer string from the distribution point name
		// Return the URL flag
		isURL = buildDistPtName((funcs.pUrlGetObj != NULL), localIssuer,
			*pDistPoint, pIssuer);

		// If a name couldn't be built, return CM_NOT_FOUND
		if (localIssuer.empty())
			return CM_NOT_FOUND;
	}

	// Set flag to indicate if out-of-date CRLs should be updated from
	// directory
	bool updateCRLs = (boundsFlag == CM_SEARCH_UNTIL_FOUND);

	short retVal = CM_NOT_FOUND;
	while ((retVal != CM_NO_ERROR) && (locMask != 0))
	{
		// Call the correct callback function to retrieve the CRLs
		short err = 0;
		EncObject_LL* pObjList = NULL;
		if (isURL)
		{
			err = funcs.pUrlGetObj(funcs.extHandle, (char*)localIssuer.c_str(),
				DELTA_CRL_TYPE | CRL_TYPE | ARL_TYPE, locMask, &pObjList);
		}
		else
		{
			err = funcs.pGetObj(funcs.extHandle, (char*)localIssuer.c_str(),
				DELTA_CRL_TYPE | CRL_TYPE | ARL_TYPE, locMask, &pObjList);
		}
		if (err != 0)
			return err;
	
		// Update the locMask
		if (!isURL && (boundsFlag == CM_SEARCH_UNTIL_FOUND) &&
			(pObjList != NULL))
		{
			short foundLoc = pObjList->locMask;
			do
			{
				locMask &= ~foundLoc;
				foundLoc >>= 1;
			} while (foundLoc > 0);
		}
		else
			locMask = 0;

		try {
			// Add any CRLs that match the specified criteria to the CRL list
			short matchErr = matchCRLs(pObjList, crlList, pMatchInfo,
				updateCRLs);
			if (matchErr != CM_NOT_FOUND)
				retVal = matchErr;

			// Free the list of CRL objects from the callback function
			if (pObjList != NULL)
				funcs.pFreeObj(funcs.extHandle, &pObjList);
		}
		catch (...) {
			// Free the list of CRL objects from the callback function
			funcs.pFreeObj(funcs.extHandle, &pObjList);
			throw;
		}
	}

	if (retVal == CM_CRL_OUT_OF_DATE)
		retVal = CM_NO_ERROR;

	return retVal;
} // end of CML::RequestCRLs()



/****************************************************************************
 Function:  CM_RequestCerts()
 
 This function will search through available certificates for a match
 against the distinguished name (DN).  The caller can optionally provide
 matching criteria to indicate further specific info to match against reqested
 certificates (subject DN is still required).  All certificates found
 that meet the provided criteria will then be placed into a linked list for
 the caller.  If no matching certificates are available, or other errors
 occur, the caller will be notified with an error code and no certificates
 will be returned.
*****************************************************************************/
short CM_RequestCerts(ulong sessionID, CM_DN subject, 
					  CertMatch_struct *matchInfo, SearchBounds boundsFlag,
					  EncCert_LL **certificateList)
{
	// Check parameters
	if ((subject == NULL) || (certificateList == NULL))
		return CM_INVALID_PARAMETER;

	// Initialize result
	*certificateList = NULL;

	try {
		// Initialize BytesList for the encoded certs
		BytesList encCertList;

		// Initialize optional CertMatchData parameter
		CertMatchData* pMatchInfo = NULL;
		try
		{
			// Initialize the subject DN parameter
			DN subjDN(subject);

			if (matchInfo != NULL)
				pMatchInfo = buildCertMatchData(*matchInfo);

			// Call the C++ version of this function and free the match criteria
			short errCode = CML::RequestCerts(sessionID, encCertList, subjDN,
				boundsFlag, pMatchInfo);
			deleteCertMatchData(pMatchInfo);
			if (errCode != CM_NO_ERROR)
				return errCode;
		}
		catch (...) {
			deleteCertMatchData(pMatchInfo);
			throw;
		}

		// Create the resulting EncCert_LL
		EncCert_LL* prev = NULL;
		for (BytesList::iterator i = encCertList.begin(); i !=
			encCertList.end(); i++)
		{
			// Allocate and clear the memory for a new link in the list
			EncCert_LL* pNew = (EncCert_LL*)calloc(1, sizeof(EncCert_LL));
			if (pNew == NULL)
				throw CML_MEMORY_ERR;

			// Add this new link into the list
			if (prev == NULL)
				*certificateList = pNew;
			else
				prev->next = pNew;
			prev = pNew;

			// Copy the encoded certificate
			pNew->encCert.num = i->Len();
			pNew->encCert.data = (uchar*)malloc(pNew->encCert.num);
			if (pNew->encCert.data == NULL)
				throw CML_MEMORY_ERR;
			memcpy(pNew->encCert.data, i->GetData(), pNew->encCert.num);
		}

		if (*certificateList == NULL)
			return CM_NOT_FOUND;

		return CM_NO_ERROR;
	}
	catch (ASN::Exception& e) {
		CM_FreeEncCertList(certificateList);
		return e;
	}
	catch (SNACC::SnaccException& ) {
		CM_FreeEncCertList(certificateList);
		return CM_ASN_ERROR;
	}
	catch (...) {
		CM_FreeEncCertList(certificateList);
		RETURN(CM_UNKNOWN_ERROR);
	}
} // end of CM_RequestCerts()


/****************************************************************************
 Function:  CM_RequestCRLs()
 
 This function will search through available Certificate Revocation Lists
 (CRLs) retrieved from the entry identified by the issuer DN and/or
 CRL distribution point, one of which must be present.  The caller can
 optionally provide matching criteria to indicate further specific info
 to match against the requested CRLs.  All CRLs found that meet the provided
 criteria will then be placed into a linked list for the caller.  If no
 matching CRLs are available, or other errors occur, the caller will be
 notified with an error code and no CRLs will be returned.
*****************************************************************************/
short CM_RequestCRLs(ulong sessionID, CM_DN issuer, Dist_pts_struct *distPts, 
					 CRLMatch_struct *matchInfo, SearchBounds boundsFlag, 
					 EncCRL_LL **crlList)
{
	// Check parameters
	if (((issuer == NULL) && (distPts == NULL)) || (crlList == NULL))
		return CM_INVALID_PARAMETER;

	// Initialize result
	*crlList = NULL;

	try {
		// Initialize temporary variables
		DN* pIssuerDN = NULL;
		ASN::DistributionPoint* pDistPt = NULL;
		CRLMatchData* pMatchInfo = NULL;

		// Initialize BytesList for the encoded CRLs
		BytesList encCrlList;

		try {
			// Initialize the optional issuer DN parameter
			if (issuer != NULL)
			{
				pIssuerDN = new DN(issuer);
				if (pIssuerDN == NULL)
					throw CML_MEMORY_ERR;
			}
			
			// Initialize optional DistributionPoint parameters
			if (distPts != NULL)
			{
				pDistPt = new ASN::DistributionPoint;
				if (pDistPt == NULL)
					throw CML_MEMORY_ERR;
				
				// Initialize the DistributionPointName
				if (distPts->dpName.flag == CM_DIST_PT_FULL_NAME)
				{
					if (distPts->dpName.name.full == NULL)
						throw CML_ERR(CM_INVALID_PARAMETER);
					
					ASN::GenNames* pGNs = buildGenNames(distPts->dpName.name.full);
					pDistPt->distPoint = new ASN::DistPointName(*pGNs);
					delete pGNs;
					if (pDistPt->distPoint == NULL)
						throw CML_MEMORY_ERR;
				}
				else if (distPts->dpName.flag == CM_DIST_PT_RELATIVE_NAME)
				{
					if (distPts->dpName.name.relative == NULL)
						throw CML_ERR(CM_INVALID_PARAMETER);
					
					pDistPt->distPoint = new ASN::DistPointName(
						ASN::RelativeDN(distPts->dpName.name.relative,
						strlen(distPts->dpName.name.relative)));
					if (pDistPt->distPoint == NULL)
						throw CML_MEMORY_ERR;
				}
				
				// Initialize the CRL issuer field
				if (distPts->crl_issuer != NULL)
					pDistPt->crlIssuer = buildGenNames(distPts->crl_issuer);
			}
			
			// Initialize optional CRLMatchData parameter
			if (matchInfo != NULL)
				pMatchInfo = buildCRLMatchData(*matchInfo);
			
			// Call the C++ version of this function and free the temporary objects
			short errCode = CML::RequestCRLs(sessionID, encCrlList, pIssuerDN,
				boundsFlag, pMatchInfo, pDistPt);
			if (pIssuerDN)
				delete pIssuerDN;
			if (pDistPt)
				delete pDistPt;
			deleteCRLMatchData(pMatchInfo);
			if (errCode != CM_NO_ERROR)
				return errCode;
		}
		catch (...) {
			if (pIssuerDN)
				delete pIssuerDN;
			if (pDistPt)
				delete pDistPt;
			deleteCRLMatchData(pMatchInfo);
			throw;
		}
		
		// Create the resulting EncCRL_LL
		EncCRL_LL* prev = NULL;
		for (BytesList::iterator i = encCrlList.begin(); i != encCrlList.end();
			i++)
		{
			// Allocate and clear the memory for a new link in the list
			EncCRL_LL* pNew = (EncCRL_LL*)calloc(1, sizeof(EncCRL_LL));
			if (pNew == NULL)
				throw CML_MEMORY_ERR;
			
			// Add this new link into the list
			if (prev == NULL)
				*crlList = pNew;
			else
				prev->next = pNew;
			prev = pNew;
			
			// Copy the encoded CRL
			pNew->encCRL.num = i->Len();
			pNew->encCRL.data = (uchar*)malloc(pNew->encCRL.num);
			if (pNew->encCRL.data == NULL)
				throw CML_MEMORY_ERR;
			memcpy(pNew->encCRL.data, i->GetData(), pNew->encCRL.num);
		}

		// Return the appropriate result
		if (*crlList == NULL)
			return CM_NOT_FOUND;

		return CM_NO_ERROR;
	}
	catch (ASN::Exception& e) {
		CM_FreeEncCRLs(crlList);
		return e;
	}
	catch (SNACC::SnaccException& ) {
		CM_FreeEncCRLs(crlList);
		return CM_ASN_ERROR;
	}
	catch (...) {
		CM_FreeEncCRLs(crlList);
		RETURN(CM_UNKNOWN_ERROR);
	}
} // end of CM_RequestCRLs()


/* --------------------- */
/* CM_RequestEncCertPath */
/* --------------------- */
/*
short CM_RequestEncCertPath(ulong sessionID, Bytes_struct* subjectCert, 
							SearchBounds boundsFlag, Bytes_struct **encPath)

This function is used to retrieve an encoded certification path for the given
subject certificate.  If the complete certification path can not be found, 
or other errors occur, the caller will be notified with the appropriate 
error code, and no certification path will be returned.  The encoded path 
is generated up to a root cert (not necessarily trusted).

Parameters
	sessionID (input)
   		Session identifier (context) that was created by the calling app
    	when starting up a session with the CM.

	subjectCert (input)
        The certificate whose certification path is to be searched
        for and returned.

	boundsFlag (input) 
		Search bounding flag.  Indicates if the search should be
 		constrained to local only, remote only, both local and remote, or 
		until found.  {CM_SEARCH_LOCAL, CM_SEARCH_REMOTE, CM_SEARCH_BOTH, 
		CM_SEARCH_UNTIL_FOUND}

	encPath (input/output) 
		Address of the storage for a Bytes_struct pointer.  Upon success 
		this will contain a pointer to the ASN.1 encoded CertificationPath.
		The caller is responsible for calling CM_FreeBytes() once they are 
		done with it.

Return Value
	The funtion will return one of the following error codes:

        CM_NO_ERROR				No errors encountered
        CM_MEMORY_ERROR			Out of memory
        CM_INVALID_PARAMETER	Bad parameter passed in
		CM_SESSION_NOT_VALID	Session does not exist
        CM_NOT_FOUND			The certification path could not be found

-----------------------------------------------------------  
*/
short CM_RequestEncCertPath(ulong sessionID, Bytes_struct* subjectCert, 
							SearchBounds boundsFlag, Bytes_struct** encPath)
{
	// Check parameters
	if ((subjectCert == NULL) || (subjectCert->data == NULL) ||
		(encPath == NULL))
		return CM_INVALID_PARAMETER;

	// Initialize encPath
	*encPath = NULL;

	try {
		// Initialize a temporary Bytes object for the subject cert
		Bytes tmpCert(subjectCert->num, subjectCert->data);

		// Initialize the cert path
		CertPath thePath(tmpCert, false);

		// Build the cert path
		short errCode = thePath.Build(sessionID, boundsFlag);
		if (errCode != CM_NO_ERROR)
			return errCode;

		// Encode the path
		Bytes tmpEncPath;
		errCode = EncodeThePath(thePath, tmpEncPath);

		if (errCode != CM_NO_ERROR)
			return errCode;

		// Get the encoded path
		*encPath = tmpEncPath.GetBytesStruct();

		return CM_NO_ERROR;
	}
	catch (ASN::Exception& e) {
		return e;
	}
	catch (SNACC::SnaccException& ) {
		return CM_ASN_ERROR;
	}
	catch (...) {
		RETURN(CM_UNKNOWN_ERROR);
	}
}



////////////////////////
// Internal Functions //
////////////////////////
void addObjsToBytesSet(BytesSet& set, const EncObject_LL *pList)
{
	while (pList != NULL)
	{
		// Create a temporary Bytes object
		Bytes tempBytes(pList->encObj.num, pList->encObj.data);

		// Insert the object into the set
		set.insert(tempBytes);

		pList = pList->next;
	}
}


CertMatchData* buildCertMatchData(const CertMatch_struct& matchInfo)
{
	CertMatchData* pMatchData = new CertMatchData;
	if (pMatchData == NULL)
		throw CML_MEMORY_ERR;
	memset(pMatchData, 0, sizeof(CertMatchData));

	try {
		if (matchInfo.algOID != NULL)
		{
			pMatchData->pPubKeyOID = new SNACC::AsnOid(matchInfo.algOID);
			if (pMatchData->pPubKeyOID == NULL)
				throw CML_MEMORY_ERR;
		}

		if (matchInfo.validOnDate != NULL)
		{
			pMatchData->pValidOnDate = new ASN::Time(*matchInfo.validOnDate);
			if (pMatchData->pValidOnDate == NULL)
				throw CML_MEMORY_ERR;
		}

		if (matchInfo.issuer_DN != NULL)
		{
			pMatchData->pIssuer = new DN(matchInfo.issuer_DN);
			if (pMatchData->pIssuer == NULL)
				throw CML_MEMORY_ERR;
		}

		pMatchData->emailAddr = matchInfo.emailAddr;

		if (matchInfo.serialNum != NULL)
		{
			pMatchData->pSerialNum = new SNACC::AsnInt((const char *)matchInfo.serialNum->data, matchInfo.serialNum->num, true);
			if (pMatchData->pSerialNum == NULL)
				throw CML_MEMORY_ERR;
		}

		if (matchInfo.poly != NULL)
		{
			ASN::OIDList* pPolicyList = new ASN::OIDList;
			if (pPolicyList == NULL)
				throw CML_MEMORY_ERR;
			Policy_struct* pPolicy = matchInfo.poly;
			while (pPolicy != NULL)
			{
				pPolicyList->push_back(pPolicy->policy_id);
				pPolicy = pPolicy->next;
			}
			pMatchData->pPolicies = pPolicyList;
		}

		if (matchInfo.sub_kmid != NULL)
		{
			pMatchData->pSubjKeyID = new SNACC::AsnOcts((const char *)matchInfo.sub_kmid->data, matchInfo.sub_kmid->num);
			if (pMatchData->pSubjKeyID == NULL)
				throw CML_MEMORY_ERR;
		}

		return pMatchData;
	}
	catch (...) {
		deleteCertMatchData(pMatchData);
		throw;
	}
} // end of buildCertMatchData()


CRLMatchData* buildCRLMatchData(const CRLMatch_struct& matchInfo)
{
	// Allocate and clear the memory for the CRLMatchData
	CRLMatchData* pMatchData = new CRLMatchData;
	if (pMatchData == NULL)
		throw CML_MEMORY_ERR;
	memset(pMatchData, 0, sizeof(CRLMatchData));

	try {
		if (matchInfo.signature != NULL)
		{
			pMatchData->pSignature = new SNACC::AsnOid(matchInfo.signature);
			if (pMatchData->pSignature == NULL)
				throw CML_MEMORY_ERR;
		}

		if (matchInfo.issueAfter != NULL)
		{
			pMatchData->pIssuedAfter = new ASN::Time(*matchInfo.issueAfter);
			if (pMatchData->pIssuedAfter == NULL)
				throw CML_MEMORY_ERR;
		}

		if (matchInfo.issueBefore != NULL)
		{
			pMatchData->pIssuedBefore = new ASN::Time(*matchInfo.issueBefore);
			if (pMatchData->pIssuedBefore == NULL)
				throw CML_MEMORY_ERR;
		}

		if (matchInfo.onlyOne == FALSE)
			pMatchData->onlyOne = false;
		else
			pMatchData->onlyOne = true;

		return pMatchData;
	}
	catch (...) {
		deleteCRLMatchData(pMatchData);
		throw;
	}
} // end of buildCRLMatchData()


bool buildDistPtName(bool canBeURL, std::string& localIssuer,
					 const ASN::DistributionPoint& distPt, const DN* pIssuer)
{
	bool isIssuerURL = false;
	if (distPt.distPoint != NULL)
	{
		switch (distPt.distPoint->GetType())
		{
		case ASN::DistPointName::DIST_PT_FULL_NAME:
			{
				const ASN::GenNames& genNames =
					distPt.distPoint->GetFullName();
				ASN::GenNames::const_iterator i =
					genNames.Find(ASN::GenName::X500);
				if (i != genNames.end())
				{
					localIssuer = *i->GetName().dn;
				}
				else if (canBeURL)
				{
					i = genNames.Find(ASN::GenName::URL);
					if (i != genNames.end())
					{
						localIssuer = i->GetName().name;
						isIssuerURL = true;
					}
				}
			}
			break;
			
		case ASN::DistPointName::DIST_PT_REL_NAME:
			{
				DN fullName;
				if (distPt.crlIssuer != NULL)
				{
					const ASN::GenNames& genNames = *distPt.crlIssuer;
					ASN::GenNames::const_iterator i =
						genNames.Find(ASN::GenName::X500);
					if (i == genNames.end())
						throw CML_ERR(CM_ASN_ERROR);

					fullName = *i->GetName().dn;
				}
				else if (pIssuer != NULL)
					fullName = *pIssuer;
				else
					throw CML_ERR(CM_ASN_ERROR);

				// Build the complete DN
				fullName += distPt.distPoint->GetRelativeName();

				// Copy the string form into the local issuer string
				localIssuer = fullName;
			}
			break;

		default:
			throw CML_ERR(CM_INVALID_PARAMETER);

		} // end of switch statement
	}
	else if (distPt.crlIssuer != NULL)
	{
		const ASN::GenNames& genNames = *distPt.crlIssuer;
		ASN::GenNames::const_iterator i =
			genNames.Find(ASN::GenName::X500);
		if (i != genNames.end())
		{
			localIssuer = *i->GetName().dn;
		}
		else if (canBeURL)
		{
			// Look for a URL name
			i = genNames.Find(ASN::GenName::URL);
			if (i != genNames.end())
			{
				localIssuer = i->GetName().name;
				isIssuerURL = true;
			}
		}
	}
	else if (pIssuer != NULL)
	{
		localIssuer = *pIssuer;
	}
	else
		throw CML_ERR(CM_INVALID_PARAMETER);

	return isIssuerURL;
} // end of buildDistPtName()


ASN::GenNames* buildGenNames(const Gen_names_struct* pGenNames)
{
	// Construct a GenNames object
	ASN::GenNames* pResult = new ASN::GenNames;
	if (pResult == NULL)
		throw CML_MEMORY_ERR;

	ASN::GenName::Form genName;
	while (pGenNames != NULL)
	{
		switch (pGenNames->gen_name.flag)
		{
		case CM_RFC822_NAME:
			genName.name = pGenNames->gen_name.name.rfc822;
			pResult->push_back(ASN::GenName(genName, ASN::GenName::RFC822));
			break;

		case CM_DNS_NAME:
			genName.name = pGenNames->gen_name.name.dns;
			pResult->push_back(ASN::GenName(genName, ASN::GenName::DNS));
			break;

		case CM_URL_NAME:
			genName.name = pGenNames->gen_name.name.url;
			pResult->push_back(ASN::GenName(genName, ASN::GenName::URL));
			break;

		case CM_X500_NAME:
			pResult->push_back(DN(pGenNames->gen_name.name.dn));
			break;
		}

		// Move to next Gen_name_struct
		pGenNames = pGenNames->next;
	}

	return pResult;
} // end of buildGenNames()


bool certMatches(const ASN::Cert& cert, const DN& subject,
				 const CertMatchData* pMatchInfo)
{
	// Check that the subject DN in the cert matches the requested DN
	if (cert.subject != subject)
		return false;

	// If the match criteria is absent, just return true
	if (pMatchInfo == NULL)
		return true;

	// Compare the cert against the match criteria
	// 1. Public key algorithm
	if ((pMatchInfo->pPubKeyOID != NULL) &&
		(cert.pubKeyInfo != *pMatchInfo->pPubKeyOID))
		return false;
		
	// 2. Validity dates
	if ((pMatchInfo->pValidOnDate != NULL) &&
		!cert.validity.IsValid(*pMatchInfo->pValidOnDate))
		return false;
		
	// 3. Issuer DN
	if ((pMatchInfo->pIssuer != NULL) && (cert.issuer != *pMatchInfo->pIssuer))
		return false;
		
	// 4. E-mail address
	if ((pMatchInfo->emailAddr != NULL) &&
		!matchEmailAddress(cert, pMatchInfo->emailAddr))
		return false;
		
	// 5. Serial number
	if ((pMatchInfo->pSerialNum != NULL) &&
		(cert.serialNumber != *pMatchInfo->pSerialNum))
		return false;
		
	// 6. Certificate policies
	if (pMatchInfo->pPolicies != NULL)
	{
		if ((cert.exts.pCertPolicies == NULL) ||
			!matchPolices(*cert.exts.pCertPolicies, *pMatchInfo->pPolicies))
			return false;
	}
		
	// 7. Subject key identifier
	if ((pMatchInfo->pSubjKeyID != NULL) &&
		!matchSubjKeyID(cert, *pMatchInfo->pSubjKeyID))
		return false;
		
	// 8. Key usage (keyCertSign)
	if (pMatchInfo->canSignCerts)
	{
		if ((cert.exts.pKeyUsage != NULL) &&
			!cert.exts.pKeyUsage->GetBit(SNACC::KeyUsage::keyCertSign))
			return false;
	}
		
	// 9. Key usage (cRLSign)
	if (pMatchInfo->canSignCRLs)
	{
		if ((cert.exts.pKeyUsage != NULL) &&
			!cert.exts.pKeyUsage->GetBit(SNACC::KeyUsage::cRLSign))
			return false;
	}

	return true;
} // end of certMatches()


bool certsMatch(EncObject_LL* pObjList, const DN& subject, BytesList& certList,
				const CertMatchData* pMatchInfo)
{
	bool certsAdded = false;
	while (pObjList != NULL)
	{
		try {
			Bytes encCert;

			// Check the object's type
			if (pObjList->typeMask == CROSS_CERT_TYPE)
			{
				// Find the forward enocded certificate of the pair
				ulong nDec;
				EncCertPair_LL* pEncPair;
				if (CMASN_ParseCertPair(&pObjList->encObj, &nDec, &pEncPair) !=
					CMLASN_SUCCESS)
					continue;
				if (pEncPair->forward.data != NULL)
				{
					encCert.Set(pEncPair->forward.num,
						pEncPair->forward.data);
				}
				CMASN_FreeCertPairList(&pEncPair);
			}
			else if ((pObjList->typeMask & USER_CERT_TYPE) ||
				(pObjList->typeMask & CA_CERT_TYPE))
			{
				// Load the Bytes object with the encoded cert
				encCert.Set(pObjList->encObj.num, pObjList->encObj.data);
			}
			else
				throw CML_ERR(CM_INVALID_ENC_OBJ_TYPE);

			// Decode the cert
			ASN::Cert decCert(encCert);

			// If the cert matches the match criteria, add it to the list
			if (certMatches(decCert, subject, pMatchInfo))
			{
				// Only add the cert if its not already present in the list
				if (!itemPresentInList(certList, encCert))
				{
					certList.push_back(encCert);
					certsAdded = true;
				}
			}
		}
		catch (ASN::Exception& cmlErr) {
			if ((cmlErr == CM_MEMORY_ERROR) ||
				(cmlErr == CM_INVALID_ENC_OBJ_TYPE))
				throw;
			// else ignore all other errors -- just skip this cert
		}
		catch (...) {
			// ignore this error -- just skip this cert
		}

		// Move to next cert in the list
		pObjList = pObjList->next;
	}

	return certsAdded;
} // end of certsMatch()


void deleteCertMatchData(CertMatchData* pMatchInfo)
{
	if (pMatchInfo == NULL)
		return;

	delete pMatchInfo->pPubKeyOID;
	delete pMatchInfo->pValidOnDate;
	delete pMatchInfo->pIssuer;
	delete pMatchInfo->pSerialNum;
	delete pMatchInfo->pSubjKeyID;
	delete pMatchInfo->pPolicies;
	delete pMatchInfo;
}


void deleteCRLMatchData(CRLMatchData* pMatchInfo)
{
	if (pMatchInfo == NULL)
		return;

	delete pMatchInfo->pSignature;
	delete pMatchInfo->pIssuedAfter;
	delete pMatchInfo->pIssuedBefore;
	delete pMatchInfo;
}


short matchCRLs(EncObject_LL* pObjList, BytesList& crlList,
				const CRLMatchData* pMatchInfo, bool updateCRLs)
{
	// Most recently-issued CRL and its ThisUpdate time
	Bytes latestCrl;
	ASN::Time mostRecent(0);
	bool mostRecentTimeSet = false;

	short retVal = CM_NOT_FOUND;
	while (pObjList != NULL)
	{
		// Check the object's type
		if ((pObjList->typeMask != CRL_TYPE) &&
			(pObjList->typeMask != ARL_TYPE) &&
			(pObjList->typeMask != DELTA_CRL_TYPE))
			throw CML_ERR(CM_INVALID_ENC_OBJ_TYPE);

		try {
			// Construct a Bytes object from the encoded CRL
			Bytes encCrl(pObjList->encObj.num, pObjList->encObj.data);

			// Compare the CRL against the match criteria
			bool crlMatches = true;
			if (pMatchInfo != NULL)
			{
				// Decode the CRL
				ASN::CertificateList decCrl(encCrl);

				// Compare the decoded CRL against the criteria, if present
				// 1. Signature algorithm
				if ((pMatchInfo->pSignature != NULL) &&
					(decCrl.algorithm != *pMatchInfo->pSignature))
					crlMatches = false;

				// 2. Issued after specified date
				if (crlMatches && (pMatchInfo->pIssuedAfter != NULL) &&
					(decCrl.thisUpdate < *pMatchInfo->pIssuedAfter))
					crlMatches = false;

				// 3. Issued before specified date
				if (crlMatches && (pMatchInfo->pIssuedBefore != NULL) &&
					(decCrl.thisUpdate > *pMatchInfo->pIssuedBefore))
					crlMatches = false;

				// 4. onlyOne flag
				if (crlMatches && pMatchInfo->onlyOne)
				{
					/* With onlyOne set, the most appropriate CRL is selected
					based on the following table:

					after	before
					-----	------
					  y		  0		=> CRL issued after y date, closest to y date
					  y		  x     => most recent CRL issued after y, but no later than x date
					  0		  x		=> most recent CRL issued before x date
					  0		  0		=> most recent CRL for the particular issuer
					*/
					if ((pMatchInfo->pIssuedAfter != NULL) &&
						(pMatchInfo->pIssuedBefore == NULL))
					{
						// Special case: since it returns CRL closest to a
						// particular date, not the most recent
						if (!mostRecentTimeSet ||
							(decCrl.thisUpdate < mostRecent))
						{
							latestCrl = encCrl;
							mostRecent = decCrl.thisUpdate;
							mostRecentTimeSet = true;
						}
					}
					else if (decCrl.thisUpdate > mostRecent)
					{
						latestCrl = encCrl;
						mostRecent = decCrl.thisUpdate;
					}

					// Set to false so the CRL isn't added to the list
					crlMatches = false;
				}
				else if (crlMatches && updateCRLs)
				{
					// If the CRL hasn't expired, set the update flag to false
					if ((decCrl.nextUpdate == NULL) ||
						(*decCrl.nextUpdate > ASN::Time()))
						updateCRLs = false;
				}
			}
			else if (updateCRLs)
			{
				// Decode the CRL
				ASN::CertificateList decCrl(encCrl);

				// If the CRL hasn't expired, set the update flag to false
				if ((decCrl.nextUpdate == NULL) ||
					(*decCrl.nextUpdate > ASN::Time()))
					updateCRLs = false;
			}
			
			// If the CRL matches, add it to the list
			if (crlMatches)
			{
				// Check that this CRL is not already present
				BytesList::const_iterator i = crlList.begin();
				for ( ; (i != crlList.end()) && (*i != encCrl); ++i)
					;
				if (i == crlList.end())
				{
					crlList.push_back(encCrl);
					retVal = CM_NO_ERROR;
				}
			}
		}
		catch (ASN::Exception& cmlErr) {
			if (cmlErr == CM_MEMORY_ERROR)
				throw;
			// else ignore all other errors -- just skip this CRL
		}
		catch (...) {
			// ignore this error -- just skip this cert
		}

		// Move to next CRL in the list
		pObjList = pObjList->next;
	}

	// When the onlyOne match criteria was specified, add the most appropriate
	// CRL to the list
	if (latestCrl.Len() > 0)
	{
		crlList.push_back(latestCrl);
		updateCRLs = false;
		retVal = CM_NO_ERROR;
	}

	// If the matched CRLs (if any) are stale, set the return value
	// appropriately
	if (updateCRLs && (retVal == CM_NO_ERROR))
		retVal = CM_CRL_OUT_OF_DATE;

	return retVal;
} // end of matchCRLs()


bool matchEmailAddress(const ASN::Cert& decCert, const char* emailAddr)
{
	// Check if the email address matches any of the Subject Alt Names
	if (decCert.exts.pSubjAltNames != NULL)
	{
		ASN::GenNames::const_iterator i =
			decCert.exts.pSubjAltNames->Find(ASN::GenName::RFC822);
		while (i != decCert.exts.pSubjAltNames->end())
		{
			if (strcmp(i->GetName().name, emailAddr) == 0)
				return true;
			i = decCert.exts.pSubjAltNames->FindNext(i, ASN::GenName::RFC822);
		}
	}

	// Check if the email address is present in the subject DN
	const std::list<ASN::RelativeDN>& rdnList = decCert.subject.GetRDNList();
	for (std::list<ASN::RelativeDN>::const_iterator i = rdnList.begin(); i !=
		rdnList.end(); i++)
	{
		const char* rdnStr = *i;
		const char* match = striEnd(rdnStr, emailAddr);
		if (match != NULL)
		{
			if ((strncmp(rdnStr, "emailAddress=", 13) == 0) &&
				(match == (rdnStr + 13)))
				return true;
		}
	}

	return false;
}


bool matchPolices(const ASN::CertPolicyList& certPolicies,
				  const ASN::OIDList& acceptable)
{
	// Return true if the special any-policy OID is acceptable
	ASN::OIDList::const_iterator i;
	for (i = acceptable.begin(); i != acceptable.end(); i++)
	{
		if (*i == SNACC::anyPolicy)
			return true;
	}

	// Return true if at least one of the cert policies is an acceptable
	// policy
	ASN::CertPolicyList::const_iterator j;
	for (j = certPolicies.begin(); j != certPolicies.end(); j++)
	{
		for (i = acceptable.begin(); i != acceptable.end(); i++)
		{
			if (*j == *i)
				return true;
		}
	}

	return false;
}


bool matchSubjKeyID(const ASN::Cert& decCert, const Bytes& subjKeyID)
{
	if ((decCert.version == SNACC::Version::v1) &&
		(decCert.pubKeyInfo == gDSA_KEA_OID))
	{
		// Compare lengths
		if (subjKeyID.Len() != 8)
			return false;

		// Decode and convert the public key to a Pub_key_struct
		Pub_key_struct temp;
		try {
			decCert.pubKeyInfo.FillPubKeyStruct(temp);
		}
		catch (...) {
			return false;
		}

		// Compare the content of the KMID
		int result = memcmp(temp.key.combo->kmid, subjKeyID.GetData(), 8);
		CMASN_FreePubKeyContents(&temp);

		return (result == 0);
	}
	else if (decCert.exts.pSubjKeyID != NULL)
	{
		if (subjKeyID != *decCert.exts.pSubjKeyID)
			return false;
	}

	return true;
}


short setLocationMask(SearchBounds boundsFlag)
{
	switch (boundsFlag)
	{
	case CM_SEARCH_LOCAL:
		return RAM_LOC | CLIENT_LOC | SEARCH_UNTIL_FOUND;
	case CM_SEARCH_REMOTE:
		return SERVER_LOC | DSA_LOC | SEARCH_UNTIL_FOUND;
	case CM_SEARCH_BOTH:
		return RAM_LOC | CLIENT_LOC | SERVER_LOC | DSA_LOC | SEARCH_ALL_LOC;
	case CM_SEARCH_UNTIL_FOUND:
		return RAM_LOC | CLIENT_LOC | SERVER_LOC | DSA_LOC |
			SEARCH_UNTIL_FOUND;
	default:
		return 0;
	}
} // end of setLocationMask()


short EncodeThePath(const CertPath& thePath, Bytes& encPath)
{
	/* This function performs ASN.1 path encoding with root as top link,
	subject as last.  The function will do a forward encoding here, meaning
	the subject as usual starts the encoded data, then the ca, pca, paa. */

	// Get the User cert and CA Cert list
	const Bytes& UserCert = thePath.GetEncUserCert();
	const BytesList& CACerts = thePath.GetEncCACerts(); 
	
	// Create the ASN Buffer
	SNACC::AsnBuf asnBuf;

	ulong numEncoded = 0;
 	if (!CACerts.empty()) // CA Certs Optional
	{
		/*
		 * now loop through the CA certs
		 * Path should be User, CA, PCA, Root
		 */
		for (BytesList::const_reverse_iterator j = CACerts.rbegin(); 
				j != CACerts.rend(); j++)
		{
			ulong seqLen = 0; // This sequence length
			asnBuf.PutSegRvs((const char *)j->GetData(), j->Len());

			// Add in the choice and len
			seqLen += j->Len();
			seqLen += SNACC::BEncDefLen(asnBuf, j->Len());
			seqLen += BEncTag1(asnBuf, SNACC::CNTX, SNACC::CONS, 0);

			// Add in the sequence and length
			seqLen += SNACC::BEncDefLen(asnBuf, seqLen);
			seqLen += BEncTag1(asnBuf, SNACC::UNIV, SNACC::CONS, SNACC::SEQ_TAG_CODE);
			numEncoded += seqLen;

		}

		// Add in the CA Cert sequence
		numEncoded += SNACC::BEncDefLen(asnBuf, numEncoded);
		numEncoded += BEncTag1(asnBuf, SNACC::UNIV, SNACC::CONS, SNACC::SEQ_TAG_CODE);

	} // Endif for CA Certs

	// Add in the User cert
	asnBuf.PutSegRvs((const char *)UserCert.GetData(), UserCert.Len());
	numEncoded += UserCert.Len();

	// Add in the Cert Path sequence and length
	numEncoded += SNACC::BEncDefLen(asnBuf, numEncoded);
	numEncoded += BEncTag1(asnBuf, SNACC::UNIV, SNACC::CONS, SNACC::SEQ_TAG_CODE);

	// Set the Bytes Encoded path and return
	encPath.SetFromBuf(asnBuf, numEncoded);
	return CM_NO_ERROR;
}

// end of CM_ReqOps.cpp
