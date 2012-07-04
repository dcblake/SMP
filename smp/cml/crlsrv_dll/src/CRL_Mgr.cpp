/*****************************************************************************
File:     CRL_Mgr.cpp
Project:  CRL Management Library
Contents: Implementation of the CRL processing code. 

Created:  January 2004
Author:   Tom Horvath <Tom.Horvath@DigitalNet.com>

Last Updated:  27 Jan 2005

Version:  2.5

Description: This file contains the following CRL API functions:
	CRL_Destroy
	CRL_FreeRevokeStatus
	CRL_Init
	CRL_RequestRevokeStatus

*****************************************************************************/

////////////////////
// Included Files //
////////////////////
#include <memory.h>
#ifdef WIN32
	#ifndef NOTHREADS
		#include <process.h>						// needed for threads
	#endif //NOTHREADS
	#include <windows.h>
#else
	#ifndef NOTHREADS
		#include <pthread.h>						// needed for threads
    #endif //NOTHREADS
    #include <unistd.h>
#endif //WIN32

#include "CRL_SRVinternal.h"
#include "cmapi_cpp.h"
#include "srlapi.h"
#include "cmlasn.h"

#define PAUSE_TIME 5	// number of seconds to sleep before checking terminate flag

// Using declarations
using namespace CML;
using namespace CML::ASN;
using namespace CRLSRV;

//////////////////////
// Global Variables //
//////////////////////
static const RevocationReasons kAllReasons(true);
static CRL_MgrInfo gCRL_MgrInfo;

/////////////////////////
// Function Prototypes //
/////////////////////////
static short revCheckCRLIssuerPath(const CertPath& crlIssuerPath, RevocationState& state, const CRL& crl);
static const CachedCRLContext* chooseBestCRL(const CachedCRLCtxList& crlHeaders,
const RevocationReasons& reasons);
static const CachedCRLContext* SearchCRLHeaderCache(const DN& certIssuer, const CertType certType, 
							const RevocationReasons& reasons, 
							const DistributionPoint& distPt,
							 bool isDelta,
							bool isCritical,
							RevocationState& state);
static const AbstractCRLContext* validateCRL(const CRL& crl, short& cmlResult,
											 RevocationState& state);
static const AbstractCRLContext* chooseValidCRL(short& err, CertType certType,
						const DN& certIssuer,
						const DistributionPoint& distPt,
						const RevocationReasons& reasons,
						const BytesList& encCRLs,
						RevocationState& state,
						bool isDelta,
						bool isCritical);
static const AbstractCRLContext* findValidCRL(short& err, const CertType type,
					      const DN& certIssuer,
				     	  const DistributionPoint& distPt,
					      const RevocationReasons& reasons,
					      RevocationState& state,
					      bool isDelta,
					      bool isCritical);
static void processDistPt(const DistributionPoint& distPt, short& err, 
				   const Certificate& target, CertType certType,
				   RevocationReasons& checkedReasons,
				   RevInfo* pRevInfo,
				   RevocationState& state,
				   bool isDelta,
				   bool isCritical);
static CertType getCertType(const Certificate& decCert);
static bool getCurrentRevocationIssuer(const CRL& InCRL, const RevokedEntry& rev, 
								  bool isFirstEntry, char **currentIssuer);
static GenName getDistPtName(const CertificateList& crl);
static void findCRLIssuerByAIA(const RevocationState& state, CertList& certList);
static bool isCRLIssuerRevoked(const CRL& crl, const Cert& cert);
static short processWantBacks(const DBIdSet& crlDBIds, const ulong& crlSessionID,
                              EncRevObject_LL** pRevocationData);
static short CRL_CheckRevStatus(const Bytes& theData, RevInfo* pRevInfo, RevocationState& state);
static void CRL_InitCRLHeaderList(EncCert_LL* crlList);
ulong CRLU_AddASession(const CRLDLLInitSettings_struct& settings);
short CRLU_RemoveASession(ulong *sessionRefID);


///////////////////////////////////////////////////////////////////////////////
// FUNCTION:  CRL_RequestRevokeStatus()
// 
// Description: To get the revocation status of a cert, or a list of certs.
// 
// Inputs: 
//    void*         handle          - Handle to external library for callbacks
//    time_t        timeout         - Maximum time to continue revocation checking
//    RevStatus_LL* pRequestData    - List of certs for revocation checking
//    CM_TimePtr    pValidationTime - If not NULL, points to a date/time that must
//                                    be used when checking revocation status
//    CM_BOOL       wantBack        - Flag that specifies if encoded CRLs 
//                                    should be returned
// 
// Outputs:
//    RevStatus_LL* pRequestData    - List of certs & their revocation status
//    EncRevObject_LL** pRevocationData - The linked list of encoded CRLs
// 
// Return Value: 
//    short error status - defines found in crlapi.h
///////////////////////////////////////////////////////////////////////////////
short CRL_RequestRevokeStatus(void* handle, time_t timeout,
                              RevStatus_LL* pRequestData, 
                              CM_TimePtr pValidationTime,
                              CM_BOOL wantBack,
                              EncRevObject_LL** pRevocationData)
{
   short ret = CRL_RESP_SUCCESS;

   // Check for valid parameters
	if (pRequestData == NULL)
		return CRL_RESP_MALFORMED;
	if (handle == NULL)
		return CRL_RESP_MALFORMED;
   // Check for a valid session handle
   try
   {
      gCRL_MgrInfo.GetSession(*(ulong*)handle);
   }
   catch (...)
   {
      return CRL_RESP_INTERNAL_ERR;
   }

   DBIdSet allCrlDbIds; // DBIDs of the CRLs used to determine the revocation
                        // status of all of the certs in this request.

   try
   {
      // If a validation time was specified, save it in a Time object
      CML::ASN::Time* pTST = NULL;
      CML::ASN::Time tempTime;
      if (pValidationTime != NULL)
      {
         tempTime = *pValidationTime;
         pTST = &tempTime;
      }

      // Check the revocation status of each cert.
      RevStatus_LL* pData = pRequestData;
      while (pData != NULL)
      {
         // Do not use if RevInfo already exists.
         if (pData->pRevInfo != NULL)
         {
            ret = CRL_RESP_MALFORMED;
            break;
         }

         // Create a new RevInfo to be used for this certificate's status
         RevInfo* pRevInfo = (RevInfo*)calloc(1, sizeof(RevInfo));
         if (pRevInfo == NULL)
         {
            ret = CRL_RESP_INTERNAL_ERR;
            break;
         }

         RevocationState state(*(ulong *)handle, false, pTST);

         // Check the revocation status of this encoded cert
         CRL_CheckRevStatus(pData->encCert, pRevInfo, state);

         // Copy the DB IDs from the per certificate set to the outer set
         allCrlDbIds.Merge(state.m_CRLDbIds);

         // Add the RevInfo to the RevStatus linked list for this cert
         pData->pRevInfo = pRevInfo;
         pData = pData->next;
      }
   }
   catch (...)
   {
      ret = CRL_RESP_INTERNAL_ERR;
   }
   
   // Process want backs if requested
   if ((ret == CRL_RESP_SUCCESS) && (wantBack == TRUE))
   {
      if (processWantBacks(allCrlDbIds, *(ulong*)handle,
         pRevocationData) != CRL_SUCCESS)
      {
         ret = CRL_RESP_INTERNAL_ERR;
      }
   }
   
   if (ret != CRL_RESP_SUCCESS)
      CRL_FreeRevokeStatus(handle, pRequestData, pRevocationData);
   
   return ret;
}

/************************************************************************
 FUNCTION:  CRL_Init()
 
 Description: To initialize a CRL Service DLL session.
*************************************************************************/
short CRL_Init(ulong* crl_session, CRLDLLInitSettings_struct* pSettings)
{
	if ((crl_session == NULL) ||
		(pSettings == NULL) ||
		(pSettings->srlFuncs == NULL) ||
		(pSettings->srlFuncs->extHandle == NULL) ||
		(pSettings->srlFuncs->pFreeObj == NULL) ||
		(pSettings->srlFuncs->pGetObj == NULL))
		return CRL_INVALID_PARAMETER;

	// Initialize result
	*crl_session = 0;

	try
	{
		// Create a new session using the CRLDLLInitSettings_struct
		*crl_session = CRLU_AddASession(*pSettings);
	} 
	catch (...)
	{
		return CRL_INIT_ERROR;
	}
	
	return CRL_SUCCESS;
}

/************************************************************************
 FUNCTION:  CRL_EmptyCRLCache()
 
 Description: To empty the CRL Service DLL session's cache.
*************************************************************************/
void CRL_EmptyCRLCache(ulong crl_session)
{
	EmptyCRLCache(crl_session);
}

/************************************************************************
 FUNCTION:  CRL_Destroy()
 
 Description: To destroy a CRL Service DLL session and stop the service threads.
*************************************************************************/
short CRL_Destroy(ulong* crl_session)
{
	if (crl_session == NULL)
		return CRL_INVALID_PARAMETER;

	return CRLU_RemoveASession(crl_session);
}

//////////////////////////
// Supporting functions //
//////////////////////////
namespace std {
template <>
bool std::greater<CRL>::operator()(const CRL& x,
	const CRL& y) const
{
	return (x.base().thisUpdate > y.base().thisUpdate);
}
} // End namespace std

short CRL_CheckRevStatus(const Bytes& theData, RevInfo* pRevInfo, RevocationState& state)
{
	short err = CRL_SUCCESS;
	try
	{
		// Decode the certificate
		Certificate target(theData);
		
		// Determine the type of target cert (CA or EE or unknown)
		CertType certType = getCertType(target);

		// If the Cert is being processed earlier in the path, return 
		// CRL_ALREADY_PROCESSING, as validation we be complete later
		if (state.prevEncCerts.find(theData) != state.prevEncCerts.end())
		{
			if (pRevInfo)
				pRevInfo->status = CM_STATUS_UNKNOWN;
			return CRL_ALREADY_PROCESSING;
		}

		// Add this cert to the list of previous certs
		std::pair<BytesSet::iterator, bool> addResult = state.prevEncCerts.insert(theData);

		// Process the Freshest CRL extension if present
		RevocationReasons checkedReasons;
		if (target.base().exts.pFreshestCRL != NULL)
		{
			bool isCritical = target.base().exts.pFreshestCRL->critical;
			// Process each distribution point...
			std::list<DistributionPoint>::const_iterator iDP =
				target.base().exts.pFreshestCRL->begin();
			for ( ; (iDP != target.base().exts.pFreshestCRL->end()) &&
				(checkedReasons != kAllReasons); ++iDP)
			{
				// Process the delta CRL
				processDistPt(*iDP, err, target, certType, checkedReasons, 
					pRevInfo, state, true, isCritical);
				
				if (err == CRL_CERT_REVOKED)
				{
					// Remove this cert from the list of previous certs (if added)
					if (addResult.second)
					{
						state.prevEncCerts.erase(addResult.first);
					}
					return CRL_CERT_REVOKED;
				}
			}
		}

		
		// Process the CRL distribution points extension if present
		if (target.base().exts.pCrlDistPts != NULL)
		{
			bool isCritical = target.base().exts.pCrlDistPts->critical;
			// Process each distribution point...
			std::list<DistributionPoint>::const_iterator iDP =
				target.base().exts.pCrlDistPts->begin();
			for ( ; (iDP != target.base().exts.pCrlDistPts->end()) &&
				(checkedReasons != kAllReasons); ++iDP)
			{
				processDistPt(*iDP, err, target, certType, checkedReasons, 
							  pRevInfo, state, false, isCritical);

				if (err == CRL_CERT_REVOKED)
				{
					// Remove this cert from the list of previous certs (if added)
					if (addResult.second)
					{
						state.prevEncCerts.erase(addResult.first);
					}
					return CRL_CERT_REVOKED;
				}
			}
			
			// If the extension is flagged critical, check that the appropriate
			// key compromise reason code was checked
			if (target.base().exts.pCrlDistPts->critical)
			{
				bool reportErr = true;
				switch (certType)
				{
				case CACert:
					reportErr =
						!checkedReasons.GetBit(SNACC::ReasonFlags::cACompromise);
					break;
				case EndEntityCert:
					reportErr =
						!checkedReasons.GetBit(SNACC::ReasonFlags::keyCompromise);
					break;
				}
				
				if (reportErr)
				{
					// critical key comprise reason not checked, report error
					if (pRevInfo)
						pRevInfo->status = CM_STATUS_UNKNOWN;

					// Remove this cert from the list of previous certs (if added)
					if (addResult.second)
					{
						state.prevEncCerts.erase(addResult.first);
					}
					return CRL_CRITICAL_KEY_COMPROMISE_NOT_CHECKED;
				}
			}
		}
		
		// If not all of the revocation reasons have been checked, check the
		// complete CRL
		if (checkedReasons != kAllReasons)
		{
			// Process the distribution point for the issuer's complete CRL
			processDistPt(DistributionPoint(), err, target, certType, 
						  checkedReasons, pRevInfo, state, false, false);
		}
		
		// Remove this cert from the list of previous certs (if added)
		if (addResult.second)
		{
			state.prevEncCerts.erase(addResult.first);
		}
		
		if ((err == CRL_NOT_VALID) || (checkedReasons != kAllReasons))
		{
			// Not all reasons were checked, report Unknown status
			if (pRevInfo)
				pRevInfo->status = CM_STATUS_UNKNOWN;
			err = CRL_REV_REASONS_NOT_CHECKED;
		}
	}
	catch (...) {
		// Not all reasons were checked, report Unknown status
		if (pRevInfo)
			pRevInfo->status = CM_STATUS_UNKNOWN;
		return CRL_UNKNOWN_ERROR;
	}
	return err;
}

void CRL_InitCRLHeaderList(ulong crlSessionID, EncCert_LL* crlList)
{
	EncCert_LL* tmpCrlList = crlList;
	while (tmpCrlList)
	{
		try
		{
			// Validate the CRL
			short cmlErr = CM_NO_PATH_FOUND;
			CRL thisCRL(tmpCrlList->encCert);
			const bool stopRefresh = false;
			RevocationState state(crlSessionID, stopRefresh);
			// the CRL will be updated added to the cache by validateCRL()
			const AbstractCRLContext *pCRLCtx = validateCRL(thisCRL, cmlErr, state);
			if (pCRLCtx)
				delete pCRLCtx;
		}
		catch (...)
		{
			// Skip this CRL
		}
		tmpCrlList = tmpCrlList->next;
	}
}

const CachedCRLContext* chooseBestCRL(const CachedCRLCtxList& crlHeaders,
								 const RevocationReasons& reasons)
{
	if (crlHeaders.empty())
		return NULL;

	// Return the first CRL which matches all of the reasons
	CachedCRLCtxList::const_iterator i;
	for (i = crlHeaders.begin(); i != crlHeaders.end(); ++i)
	{
		if (*i != NULL)
		{
			if ((*i)->GetRef().m_pIssuingDistPtExt == NULL)
				return (*i);
			else
			{
				const IssuingDistPointExtension& issuingDP =
					*(*i)->GetRef().m_pIssuingDistPtExt;

				if (issuingDP.onlySomeReasons == NULL)
					return (*i);

				if ((*issuingDP.onlySomeReasons & reasons) == reasons)
					return (*i);
			}
		}
	}

	// None of the CRLs match all reasons, so return the first CRL
	return (crlHeaders.front());
}

const CachedCRLContext* SearchCRLHeaderCache(const DN& certIssuer, const CertType certType, 
					 const RevocationReasons& reasons, 
					 const DistributionPoint& distPt,
					 bool isDelta,
					 bool isCritical,
					 RevocationState& state)
{
	if (state.stopRefresh || state.m_pValidationTime != NULL)
		return NULL;

	CRLHeaderCache& crlCache = GetCRLCache(state.crlSessionID);
	if (crlCache.IsEmpty())
		return NULL;

	CachedCRLCtxList crlHeaders;

	// Search the CRL Header List for a CRLHeader with any of the 
	// distribution point names if present
	if (distPt.distPoint != NULL)
	{
		// Search using the distribution point name(s)
		switch (distPt.distPoint->GetType())
		{
		case DistPointName::DIST_PT_FULL_NAME:
			{
				const GenNames& fullName = distPt.distPoint->GetFullName();
				GenNames::const_iterator i = fullName.begin();
				for ( ; i != fullName.end(); ++i)
				{
					crlCache.Find(*i, crlHeaders, state.pCRLToRefresh);
				}
			}
			break;
			
		case DistPointName::DIST_PT_REL_NAME:
			{
				// Build the full distribution point name using either
				// the crlIssuer field (if present) or the cert issuer
				if (distPt.crlIssuer != NULL)
				{
					GenNames::const_iterator i =
						distPt.crlIssuer->Find(GenName::X500);
					while (i != distPt.crlIssuer->end())
					{
						// Build the full X.500 DN
						DN fullName(*i->GetName().dn);
						fullName += distPt.distPoint->GetRelativeName();
						crlCache.Find(fullName, crlHeaders, state.pCRLToRefresh);
						
						i = distPt.crlIssuer->FindNext(i,
							GenName::X500);
					}
				}
				else
				{
					DN fullName = certIssuer;
					fullName += distPt.distPoint->GetRelativeName();
					crlCache.Find(fullName, crlHeaders, state.pCRLToRefresh);
				}
			}
			break;
		}
		// If we did not find anything and the CDP is not critical, then also find CRLs
		// via the issuer since the CRLs technically do not need an IDP.
		if (crlHeaders.empty() && (!isCritical))
			crlCache.Find(certIssuer, crlHeaders, state.pCRLToRefresh);
	}
	else if (distPt.crlIssuer != NULL)	// Use cRLIssuer field
	{
		GenNames::const_iterator i = distPt.crlIssuer->begin();
		for ( ; i != distPt.crlIssuer->end(); ++i)
		{
			crlCache.Find(*i, crlHeaders, state.pCRLToRefresh);
		}
	}
	else	// Use the certificate issuer
		crlCache.Find(certIssuer, crlHeaders, state.pCRLToRefresh);

	// Remove from the list any CRLs whose scope doesn't cover the type
	// of certificate or the reasons of interest
	// Also verify that the validation time is valid for this CRL.
	if (!crlHeaders.empty())
	{
		CachedCRLCtxList::iterator i = crlHeaders.begin();
		while (i != crlHeaders.end())
		{
			if ((*i == NULL) ||	
				!(*i)->GetRef().MatchesScope(certType, certIssuer, &distPt, isCritical, &reasons) ||
				(isDelta && !(*i)->GetRef().m_pFreshestCRL))

			{
				delete *i;
				i = crlHeaders.erase(i);
			}
			else
				++i;
		}
		
		// Choose the best CRLHeader and return
		const CachedCRLContext* pCRLCtx = chooseBestCRL(crlHeaders, reasons);
		
		// clear up unused AbstractCRLContext memory
		i = crlHeaders.begin();
		while (i != crlHeaders.end())
		{
			if ((*i != pCRLCtx) && (*i != NULL))
			{
				delete *i;
				i = crlHeaders.erase(i);
			}
			else
				++i;
		}
		return pCRLCtx;
	}

	return NULL;
}

short revCheckCRLIssuerPath(const CertPath& crlIssuerPath, RevocationState& state, const CRL& crl) 
{
	ulong cmlSessionID = GetCMLSessionID(state.crlSessionID);
	// Check the revocation status of each of the CA certs in the issuer's path
	BytesList::const_reverse_iterator iCertBytes = crlIssuerPath.GetEncCACerts().rbegin();
	bool alreadyProcessing = false;
	
	for ( ; iCertBytes != crlIssuerPath.GetEncCACerts().rend(); ++iCertBytes)
	{
		// See if this certificate is cached and valid. If so, skip revocation
		// checks on the this certificate.
		bool skipCert = false;
		try 
		{
			Certificate decCert(*iCertBytes);
			if (decCert.IsValid(cmlSessionID))
				skipCert = true;
		}
		catch (...)	
		{
			// ignore
		}
			
		if (!skipCert)
		{
			short err = CRL_CheckRevStatus(*iCertBytes, NULL, state);
			// if this cert is already being processed, set flag 
			// so that CRL is not cached at this time
			if (err == CRL_ALREADY_PROCESSING)
			{
				alreadyProcessing = true;
			}
			// if there is any other error do not use this CRL and return a failure.
			else if (err != CRL_SUCCESS)
			{
				return err;
			}
		}
	}
	
	// Check the revocation status of the end entity CRL issuer cert itself
	// See if this certificate is cached and valid. If so, skip revocation
	// checks on the this certificate.
	bool skipCert = false;
	try 
	{
		Certificate decCert(crlIssuerPath.GetEncUserCert());
		if (decCert.IsValid(cmlSessionID))
			skipCert = true;
	}
	catch (...)	
	{
		// ignore
	}

	if (!skipCert)
	{
		short err = CRL_CheckRevStatus(crlIssuerPath.GetEncUserCert(), NULL, state);
		if (err == CRL_ALREADY_PROCESSING)
		{
			// If this is the last cert we are processing and there were no previous errors
			// then we should check if this CRL issuer cert is revoked. If not
			// the CRL can be cached.
			if ((state.prevEncCerts.size() == 1) &&
				(state.prevEncCerts.find(crlIssuerPath.GetEncUserCert()) != state.prevEncCerts.end()))
			{
				if (isCRLIssuerRevoked(crl, crlIssuerPath.base().userCert) == true)
					return CRL_PATH_NOT_FOUND;
			}
			else
			{
				alreadyProcessing = true;
			}
		}
		// if there is any other error do not use this CRL and return a failure (NULL)
		else if (err != CRL_SUCCESS)
		{
			return err;
		} 
	}
	
	if (alreadyProcessing)
		return CRL_ALREADY_PROCESSING;
	else
		return CRL_SUCCESS;
}

bool isCRLIssuerRevoked(const CRL& crl, const Cert& cert)
{
	// Check if the target cert is revoked
	ASN::Revocations::const_iterator iRev =
		crl.base().GetRevocations().IsRevoked(cert.serialNumber,
		cert.issuer, crl.base().issuer, crl.base().crlExts.pOrderedList);
	if (iRev != crl.base().GetRevocations().end())
	{
		// Target cert is revoked, so return the error
		return true;
	}
	return false;
}


const AbstractCRLContext* validateCRL(const CRL& crl, short& cmlResult,
									  RevocationState& state)
{
	cmlResult = CM_PATH_VALIDATION_ERROR;
	if (state.stopRefresh)
		return NULL;

	const AbstractCRLContext* pCRLCtx = NULL;
	ulong cmlSessionID = GetCMLSessionID(state.crlSessionID);
	const SearchBounds& boundsFlag = GetBoundsFlag(state.crlSessionID);
	CRLHeaderCache& crlHeaderCache = GetCRLCache(state.crlSessionID);

	// If the CRL is a previous to-be-validated CRL from earlier in the path,
	// set the result to CM_NO_ERROR, as it will be validated later
	if (state.prevEncCRLs.find(crl) != state.prevEncCRLs.end())
	{
		return generateTemporaryCRLCtx(crl, cmlResult, state);
	}

	// Validate the CRL without revocation checking
	CertPath crlIssuerPath;
	short valErr;
	try
	{
		valErr = crl.Validate(cmlSessionID, 
			boundsFlag, crlIssuerPath, NULL, state.m_pValidationTime, false);
	} 
	catch (...) 
	{
		valErr = CM_PATH_VALIDATION_ERROR;
	}
		
	if (valErr == CM_NO_ERROR)
	{
		// Add this CRL to the list of previous CRLs
		std::pair<BytesSet::iterator, bool> addResult = state.prevEncCRLs.insert(crl);

		// Complete validation of the CRL, by checking the revocation status of each
		// cert in the CRL Issuer's path
		short err = revCheckCRLIssuerPath(crlIssuerPath, state, crl);

		// Remove this CRL from the list of previous CRLs (if added)
		if (addResult.second)
			state.prevEncCRLs.erase(addResult.first);
		
		// if there were no errors except any cert in the path is already being processed
		// just return a CRL context, the CRL will be cached later.
		if (err == CRL_ALREADY_PROCESSING)
		{
			return generateTemporaryCRLCtx(crl, cmlResult, state);
		}
		// if there were no errors, add the CRL to the cache
		else if (err == CRL_SUCCESS)
		{	
			if (state.stopRefresh)
			{
				cmlResult = CM_PATH_VALIDATION_ERROR;
				return NULL;
			}
			// Add the CRL to the status cache as valid
			pCRLCtx = crlHeaderCache.Add(crl, true,
				GetCRLRefreshPeriod(state.crlSessionID),
				state.pCRLToRefresh);
			if ((pCRLCtx != NULL) || (state.pCRLToRefresh != NULL))
			{
				cmlResult = CM_NO_ERROR;
				return pCRLCtx;
			}
		}
	}

	cmlResult = CM_PATH_VALIDATION_ERROR;
	if (state.stopRefresh)
		return NULL;		
	// Add the CRL to the status cache as invalid
	return crlHeaderCache.Add(crl, false,
		GetCRLRefreshPeriod(state.crlSessionID),
		state.pCRLToRefresh);
} // end of validateCRL()

const AbstractCRLContext* chooseValidCRL(short& err, CertType certType,
								  const DN& certIssuer,
								  const DistributionPoint& distPt,
								  const RevocationReasons& reasons,
								  const BytesList& encCRLs,
								  RevocationState& state,
								  bool isDelta,
								  bool isCritical)
{
	// Decode each of the CRLs
	std::list<CRL> crls;
	BytesList::const_iterator i;
	for (i = encCRLs.begin(); i != encCRLs.end(); ++i)
	{
		try {
			CRL decCRL(*i);
			crls.push_back(decCRL);
		}
		catch (...) {
         // Skip this CRL
		}
	}

	// Remove from the list any CRLs that aren't of the proper scope
	std::list<CRL>::iterator iCrl = crls.begin(); 
	while (iCrl != crls.end())
	{
		// If the CRL is a delta CRL and a base CRL is requested, remove it or
		// if the CRL is a base CRL and a delta CRL is requested, remove it
		if ( ( (iCrl->base().IsDelta()) && !isDelta) ||
			 ( (!iCrl->base().IsDelta()) && isDelta) )
		{
			iCrl = crls.erase(iCrl);
			continue;
		}

		if (!iCrl->base().MatchesScope(certType, certIssuer,
			&distPt, isCritical, &reasons))
		{
			iCrl = crls.erase(iCrl);
			continue;
		}

		++iCrl;
	}

	// Sort the CRLs by thisUpdate time
	std::greater<CRL> sortByThisUpdate;
	crls.sort(sortByThisUpdate);

	// If a complete CRL is requested, move to the head of the list any CRLs
	// that include ALL of the requested revocation reasons
	if ((distPt.distPoint == NULL) && (distPt.reasons == NULL) &&
		(distPt.crlIssuer == NULL))
	{
		std::list<CRL>::iterator iInsertLoc = crls.begin();
		iCrl = crls.begin();
		while (iCrl != crls.end())
		{
			if ((iCrl->base().crlExts.pIssuingDP == NULL) ||
				(iCrl->base().crlExts.pIssuingDP->onlySomeReasons == NULL) ||
				((*iCrl->base().crlExts.pIssuingDP->onlySomeReasons &
					reasons) == reasons))
			{
				if (iCrl != iInsertLoc)
					crls.splice(iInsertLoc, crls, ++iCrl);
				else
				{
					++iCrl;
					++iInsertLoc;
				}
			}
			else
				++iCrl;
		}
	}

	// For each remaining CRL...
	std::list<CRL>::iterator iCRL;
	for (iCRL = crls.begin(); iCRL != crls.end(); ++iCRL)
	{
		short cmlErr = CM_NO_PATH_FOUND;
		// find the issuer and validate the CRL
		const AbstractCRLContext* pCRLCtx = validateCRL(*iCRL, cmlErr, state);
		// Convert the error to a CRL DLL error
		if (pCRLCtx)
		{
			if (cmlErr == CM_NO_ERROR)
				err = CRL_SUCCESS;
			else if (!pCRLCtx->GetRef().IsValid())
				err = CRL_NOT_VALID;
			else 
				err = CRL_PATH_NOT_FOUND;
			return pCRLCtx;
		}
	}
	err = CRL_PATH_NOT_FOUND;
	return NULL;
} // end of chooseValidCRL()

//////////////////////////////////////////////////////////////////////////
// FUNCTION:  findValidCRL
// 
// Description: Find valid CRLs for a certificate
//
// Inputs: 
//   CertType           type -       decoded cert
//   DN	               certIssuer - Issuer of the cert
//	  DistributionPoint& distPt     - Distribution point
//	  bool               isDelta    - is CRL a delta?
//	  bool               isCritical - is CRL critical?
//
// Outputs:
//	  short&      err            - error status - defines found in crlapi.h
//	  RevocationReasons& reasons - Reasons that cert was revoked
// 
// Return Value: AbstractCRLContext
///////////////////////////////////////////////////////////////////////////

const AbstractCRLContext* findValidCRL(short& err, const CertType type,
						const DN& certIssuer,
						const DistributionPoint& distPt,
						const RevocationReasons& reasons,
						RevocationState& state,
						bool isDelta,
						bool isCritical)
{
	// Search the CRL cache for the requested CRL
	const AbstractCRLContext* pCRLCtx = SearchCRLHeaderCache(certIssuer, type,
		reasons, distPt, isDelta, isCritical, state);

	if (pCRLCtx != NULL)
	{
		if (pCRLCtx->GetRef().IsValid())
			err = CRL_SUCCESS;
		else
			err = CRL_NOT_VALID;
		return pCRLCtx;
	}
	
	try {
		if (state.stopRefresh)
		{
			err = CRL_NOT_AVAIL;
			return NULL;
		}

		// Get the CML session ID and boundsFlag
		ulong cmlSessionID = GetCMLSessionID(state.crlSessionID);
		const SearchBounds& boundsFlag = GetBoundsFlag(state.crlSessionID);

		BytesList encCRLs;

      // Not found in the cache, search the callback locations
		// If time stamp time has been set, use it when requesting CRLs
		if (state.m_pValidationTime != NULL)
		{
         // Create a CRLMatched Data structure
		   CRLMatchData crlMatchData;
		   memset(&crlMatchData, 0, sizeof(CRLMatchData));
         crlMatchData.pIssuedBefore = state.m_pValidationTime;

		   RequestCRLs(cmlSessionID, encCRLs, &certIssuer,
			            boundsFlag, &crlMatchData, &distPt);
		}
		else 
		{
		   RequestCRLs(cmlSessionID, encCRLs, &certIssuer,
			            boundsFlag, NULL, &distPt);
		}

      // If no CRLs were returned, return an error
      if (encCRLs.size() == 0)
      {
         err = CRL_NOT_AVAIL;
         return NULL;
      }

		// Choose and validate the appropriate CRL from the list
      // First validate the base CRL
      const AbstractCRLContext* pBaseCRLCtx = chooseValidCRL(err, type, 
         certIssuer, distPt, reasons, encCRLs, state, false, isCritical);

      // If the cert has a freshest CRL extension (isDelta == true) or the CRL has the 
      // freshest CRL extension, locate and process the delta CRL.
      if (isDelta || ((pBaseCRLCtx != NULL) && 
                       pBaseCRLCtx->GetRef().m_pFreshestCRL != NULL))
		{
			if (pBaseCRLCtx != NULL)
			{
				// If the CRL is not valid, no need to continue
				if (err == CRL_NOT_VALID)
				{
					delete pBaseCRLCtx;
					return NULL;
				}
				// Free the CRL Header context if it not a TemporaryCRLContext.  
            // Otherwise we have to pass it validateCRL() so that the Temporary
            // CRL header can be updated with a delta CRL.
				if (pBaseCRLCtx->IsCRLCached())
				{
					delete pBaseCRLCtx;
					pBaseCRLCtx = NULL;
				}
				// Save the CRL Header context in the state so the base CRL is 
            // updated from the delta CRL. This value pointer will only be 
            // set if we are processing a TemporaryCRLContext.
				state.pBaseCRLCtx = pBaseCRLCtx;
				// The base CRL was found and valid, now validate the delta CRL
				pCRLCtx = chooseValidCRL(err, type, certIssuer, distPt, reasons,
					encCRLs, state, true, isCritical);
				// If we were not able to validate the delta CRL, delete the Base CRL's TemporaryCRLContext
				if (pCRLCtx == NULL)
				{
					delete state.pBaseCRLCtx;
				}
				state.pBaseCRLCtx = NULL;
			}		
		}
      else
         pCRLCtx = pBaseCRLCtx;

      if (pCRLCtx != NULL)
			return pCRLCtx;

		err = CRL_NOT_AVAIL;
		return NULL;
	}
	catch (...) {
		// return an error since the CRL was not found
		err = CRL_NOT_AVAIL;
		return NULL;
	}
}

///////////////////////////////////////////////////////////////////////////
// FUNCTION:  processDistPt
// 
// Description: Process the Cert distribution point
//
// Inputs: 
//   DistributionPoint& distPt     - distribution point
//   Certificate&       cert       - certificate
//	  CertType           certType   - type of certificate
//	  RevocationState&   state      - revocation state
//	  bool               isDelta    - Is this a delta crl?
//	  bool               isCritical - Is this critical?
//
// Outputs:
//	  short&             err            - error status - defines found in crlapi.h
//	  RevocationReasons& checkedReasons - reasons that were checked
//	  RevInfo            pRevInfo       - Revocation Information for the cert
// 
///////////////////////////////////////////////////////////////////////////////
void processDistPt(const DistributionPoint& distPt, short& err, 
				   const Certificate& target, CertType certType,
				   RevocationReasons& checkedReasons,
				   RevInfo* pRevInfo,
				   RevocationState& state,
				   bool isDelta,
				   bool isCritical)
{
	// Compute the reasons to check for this distribution point
	RevocationReasons reasonsToCheck = ~checkedReasons;
	if (distPt.reasons != NULL)
		reasonsToCheck &= *distPt.reasons;
	
	// While the target certificate isn't revoked and not all reasons in the
	// distribution point have been checked...
	bool isRevoked = false;
	RevocationReasons distPtReasonsChecked;
	while (!isRevoked && (distPtReasonsChecked != reasonsToCheck))
	{
		const AbstractCRLContext* pCRLCtx = findValidCRL(err, certType, 
			target.base().issuer, distPt, ~distPtReasonsChecked,
			state, isDelta, isCritical);
		
		// If a valid CRL context was found, check to see if cert is revoked
		if (pCRLCtx == NULL)
		{
			break;
		}
		if (err == CRL_NOT_VALID)
		{
			delete pCRLCtx;
			break;
		}
		
		// Update the reasons to check
		if((pCRLCtx->GetRef().m_pIssuingDistPtExt != NULL) &&
			(pCRLCtx->GetRef().m_pIssuingDistPtExt->onlySomeReasons != NULL))
			distPtReasonsChecked |= *pCRLCtx->GetRef().m_pIssuingDistPtExt->onlySomeReasons &
				reasonsToCheck;
		else
			distPtReasonsChecked = reasonsToCheck;		
	
      // Check if target is revoked
      isRevoked = pCRLCtx->GetRef().CheckForRevocation(target, pRevInfo, 
         state.m_pValidationTime);
      if (isRevoked)
         err = CRL_CERT_REVOKED;

      // Add this CRL to the list of DBIDs in the revocation state object.
      if (pCRLCtx->GetRef().m_baseDBID != -1)
      {
         state.m_CRLDbIds.insert(pCRLCtx->GetRef().m_baseDBID);
         if (pCRLCtx->GetRef().m_deltaDBID != -1)
            state.m_CRLDbIds.insert(pCRLCtx->GetRef().m_deltaDBID);
      }

		delete pCRLCtx;		
	}
	
	// Update the checked reasons
	if (isRevoked)
		checkedReasons = kAllReasons;
	else
		checkedReasons |= distPtReasonsChecked;
	
} // end of processDistPt()

CertType getCertType(const Certificate& decCert)
{
	CertType certType = EndEntityCert;
	if (decCert.base().exts.pBasicCons != NULL)
	{
		if (decCert.base().exts.pBasicCons->isCA)
			certType = CACert;
		else
			certType = EndEntityCert;
	}
	else if (decCert.base().exts.pKeyUsage != NULL)
	{
		if (decCert.base().exts.pKeyUsage->GetBit(SNACC::KeyUsage::keyCertSign))
			certType = CACert;
		else
			certType = EndEntityCert;
	}
	return certType;
}

bool getCurrentRevocationIssuer(const CRL& InCRL, const RevokedEntry& rev, 
						   bool isFirstEntry, char **currentIssuer)
{
	// This is an indirect CRL so we need to decide which issuer name to return to the caller
	// so that it can be included in the key used to build the hash.
	char *theIssuer = NULL;
	// If this entry has a cert issuer name and it is different than the current issuer, use it
	if (rev.EntryExts().pCertIssuer)
	{
		// We will first attempt to get the name from the X500 name forms
		std::list<GenName>::const_iterator iName;
		iName = rev.EntryExts().pCertIssuer->Find(GenName::X500);
		// if we find atleast one X500 name
		if (iName != rev.EntryExts().pCertIssuer->end())
		{
			theIssuer = strdup((const char *)*iName->GetName().dn);
			if (theIssuer == NULL)
				return false;

			// Double check that there was one and only one name
			if ((++iName) != rev.EntryExts().pCertIssuer->end())
			{
				if (theIssuer)
					free (theIssuer);
				return false;
			}
			// If they are diffent, use the new name
			if ((*currentIssuer == NULL) || (memcmp(theIssuer, *currentIssuer, (strlen(theIssuer) > strlen(*currentIssuer)) ? 
				strlen(theIssuer) : strlen(*currentIssuer)) != 0))
			{
				if (*currentIssuer)
					free (*currentIssuer);
				*currentIssuer = theIssuer;
				return true;
			}
		}
		// Try for a URL
		else 
		{			
			iName =	rev.EntryExts().pCertIssuer->Find(GenName::URL);
			// if we find atleast one URL
			if (iName != rev.EntryExts().pCertIssuer->end())
			{
				theIssuer = strdup(iName->GetName().name);
				if (theIssuer == NULL)
					return false;

				// Double check that there was one and only one name
				if ((++iName) != rev.EntryExts().pCertIssuer->end())
				{
					if (theIssuer)
						free (theIssuer);
					return false;
				}
				// If they are diffent, use the new name
				if ((*currentIssuer == NULL) || (memcmp(theIssuer, *currentIssuer, (strlen(theIssuer) > strlen(*currentIssuer)) ? 
					strlen(theIssuer) : strlen(*currentIssuer)) != 0))
				{
					if (*currentIssuer)
						free (*currentIssuer);
					*currentIssuer = theIssuer;
					return true;
				}
			}
			else
			{
				// We could not get a name, so we cannot support this CRL
				return false;
			}
		}
	}
	// If we get here then the revoked entry did not have a name. In that case,
	// if this is the first entry in the CRL, then use the CRL issuer, otherwise
	// use the same issuer we used on the previous entry
	if (isFirstEntry)
	{
		*currentIssuer = strdup(InCRL.base().issuer);
		if (*currentIssuer == NULL)
			return false;

		return true;
	}
	else
	{
		// if we do not have a current issuer
		if (*currentIssuer == NULL || strlen (*currentIssuer) == 0)
			return false;

		// using the current issuer
		return true;
	}
}

GenName getDistPtName(const CertificateList& crl)
{
	if ((crl.crlExts.pIssuingDP != NULL) &&
		(crl.crlExts.pIssuingDP->distPoint != NULL))
	{
		const DistPointName& dpName = *crl.crlExts.pIssuingDP->distPoint;
		if (dpName.GetType() == DistPointName::DIST_PT_REL_NAME)
		{
			DN fullName(crl.issuer);
			fullName += dpName.GetRelativeName();
			return fullName;
		}
		else	// DIST_PT_FULL_NAME
		{
			// Return the first X.500 DN (if one is present)
			GenNames::const_iterator iGN =
				dpName.GetFullName().Find(GenName::X500);
			if (iGN != dpName.GetFullName().end())
				return *iGN;

			// Return the first URL (if one is present)
			iGN = dpName.GetFullName().Find(GenName::URL);
			if (iGN != dpName.GetFullName().end())
				return *iGN;
		}
	}

	return crl.issuer;
}

time_t cvtTimeToTime_T(const Time& inTime) 
{
	// NOTE: This routine depends on the format of CM_Time. If it changes
	// this routine will break.
	struct tm tm_time;
	memset(&tm_time, 0, sizeof(struct tm));
	char data[sizeof(CM_Time)];
	
	// convert the year
	strncpy(data, (const char *)inTime, 4);
	data[4] = 0;
	sscanf(data, "%d", &tm_time.tm_year);
	tm_time.tm_year -= 1900; // subtract 1900 to get number of years since 1900
	
	// convert the month
	strncpy(data, (const char *)inTime + 4, 2);
	data[2] = 0;
	sscanf(data, "%d", &tm_time.tm_mon);
	tm_time.tm_mon -= 1; // subtract 1 to get number of months since Jan
	
	// convert the day
	strncpy(data, (const char *)inTime + 6, 2);
	data[2] = 0;
	sscanf(data, "%d", &tm_time.tm_mday);
	
	// convert the hour
	strncpy(data, (const char *)inTime + 8, 2);
	data[2] = 0;
	sscanf(data, "%d", &tm_time.tm_hour);
	
	// convert the min
	strncpy(data, (const char *)inTime + 10, 2);
	data[2] = 0;
	sscanf(data, "%d", &tm_time.tm_min);
	
	// convert the sec
	strncpy(data, (const char *)inTime + 12, 2);
	data[2] = 0;
	sscanf(data, "%d", &tm_time.tm_sec);
	
	return mktime(&tm_time);
}

///////////////////////////////////////////////////////////////////////////////
// FUNCTION:  processWantBacks
// 
// Description: Create the linked list of encoded CRLs which is
//              to be returned with the revocation status request.
//
// Inputs: 
//    const DBIdSet& crlDBIds       - list of CRL DBIDs
//    const ulong& crlSessionID     - CRL session ID
//
// Outputs:
//    EncRevObject_LL** pRevocationData - list of encoded CRLs
// 
// Return Value:
//    short - CRL_SUCCESS       if no errors occurred otherwise
//            CRL_UNKNOWN_ERROR if a CRL could not be found
//            CRL_MEMORY_ERROR  if a memory error occurs
               
///////////////////////////////////////////////////////////////////////////////
short processWantBacks(const DBIdSet& crlDBIds, const ulong& crlSessionID,
                       EncRevObject_LL** pRevocationData)
{
   // Check parameters
   if (pRevocationData == NULL)
      return CRL_INVALID_PARAMETER;
   
   *pRevocationData = NULL;
   EncRevObject_LL* pRevObj = NULL;
   
   // Loop through each CRL DBID in the set of CRL DBIDs, retrieve the CRL
   // from the database, and add it to a new linked list.
   DBIdSet::const_iterator iCrlDbId = crlDBIds.begin();
   for (; iCrlDbId != crlDBIds.end(); ++iCrlDbId)
   {
      // Retrieve the CRL from the SRL database
      Bytes_struct* pData;
      try
      {
         int err = SRL_DatabaseRetrieve(GetLocalSRLSessionID(crlSessionID),
            SRL_DB_CRL, 0, &pData, *iCrlDbId);            
         if (err != SRL_SUCCESS)
            return CRL_UNKNOWN_ERROR;
      }
      catch (...)
      {
         return CRL_UNKNOWN_ERROR;
      }
      
      // Create space for the next item in the linked list
      EncRevObject_LL* pTempObj =
         (EncRevObject_LL*)calloc(1, sizeof(EncRevObject_LL));
      if (pTempObj == NULL)
      {
         SRL_FreeBytes(&pData);
         return CRL_MEMORY_ERROR;
      }

      // Add this link to the head of the list
      pTempObj->m_pNext = pRevObj;
      pRevObj = pTempObj;

      // Copy the encoded data
      pRevObj->m_encObj.data = (uchar*)malloc(pData->num);
      if (pRevObj->m_encObj.data == NULL)
      {
         SRL_FreeBytes(&pData);
         free(pTempObj);
         return CRL_MEMORY_ERROR;
      }
      memcpy(pRevObj->m_encObj.data, pData->data, pData->num);
      pRevObj->m_encObj.num = pData->num;

      // Set the type
      pRevObj->m_typeMask = REV_CRL_TYPE;

      // Free the temporary copy of the CRL returned by the SRL
      SRL_FreeBytes(&pData);
   }
   *pRevocationData = pRevObj;

   return CRL_SUCCESS;
}

////////////////////////////////
// Internal Support Functions //
////////////////////////////////
void CRLSRV::EmptyCRLCache(ulong sessionID)
{
	// Get the CRL session from the handle
	CRLSession& crlSession = gCRL_MgrInfo.GetSession(sessionID);
	crlSession.EmptyCache();
}

CRLHeaderCache& CRLSRV::GetCRLCache(ulong sessionID)
{
	// Get the CRL session from the handle
	CRLSession& crlSession = gCRL_MgrInfo.GetSession(sessionID);
	if (crlSession.GetCRLHeaderCache() == NULL)
		throw CRL_NULL_POINTER;
	return *crlSession.GetCRLHeaderCache();
}

ulong CRLSRV::GetCMLSessionID(ulong sessionID)
{
	// Get the CRL session from the handle
	CRLSession& crlSession = gCRL_MgrInfo.GetSession(sessionID);
	return crlSession.GetCMLSessionID();
}

const SearchBounds& CRLSRV::GetBoundsFlag(ulong sessionID)
{
	// Get the CRL session from the handle
	CRLSession& crlSession = gCRL_MgrInfo.GetSession(sessionID);
	return crlSession.GetBoundsFlag();
}

time_t CRLSRV::GetCRLRefreshPeriod(ulong sessionID)
{
	// Get the CRL session from the handle
	CRLSession& crlSession = gCRL_MgrInfo.GetSession(sessionID);
	return crlSession.GetCRLRefreshPeriod();
}

time_t CRLSRV::GetCRLGracePeriod(ulong sessionID)
{
	// Get the CRL session from the handle
	CRLSession& crlSession = gCRL_MgrInfo.GetSession(sessionID);
	return crlSession.GetCRLGracePeriod();
}

const SRLCallbackFunctions& CRLSRV::GetSRLFunc(ulong sessionID)
{
	// Get the CRL session from the handle
	CRLSession& crlSession = gCRL_MgrInfo.GetSession(sessionID);
	return crlSession.GetSRLFunc();
}

//////////////////////////////////////////////////////////////////////////////
// FUNCTION:  GetLocalSRLSessionID
// 
// Description: Get the local SRL session ID for a particular CRL session.
//
// Inputs: 
//   ulong sessionID           - CRL session ID
//
// Return Value: 
//	  ulong                     - the local SRL session ID
///////////////////////////////////////////////////////////////////////////////
ulong CRLSRV::GetLocalSRLSessionID(ulong sessionID)
{
   // Get the CRL session from the handle
   CRLSession& crlSession = gCRL_MgrInfo.GetSession(sessionID);
   return crlSession.GetLocalSRLSessionID();
}


const AbstractCRLContext* CRLSRV::generateTemporaryCRLCtx(const CRL& crl, short& cmlResult,
														  RevocationState& state)
{
	const AbstractCRLContext *pCtx = NULL;
	// If we already have a TemporaryCRLContext for the base CRL, just add the delta revocations
	if (state.pBaseCRLCtx)
	{
		if (((CRLHeader)state.pBaseCRLCtx->GetRef()).AddRevs2Hash(crl.base()) == false)
		{
			cmlResult = CM_PATH_VALIDATION_ERROR;
			return NULL;
		}
		pCtx = state.pBaseCRLCtx;
	}
	else
	{
		try
		{
			pCtx = new TemporaryCRLContext(crl.base());
		} 
		catch (...)
		{
			cmlResult = CM_PATH_VALIDATION_ERROR;
			return NULL;
		}
	}
	cmlResult = CM_NO_ERROR;
	return pCtx;
}

void CRLSRV::retrieveRemoteCRLs(const CRLHeader& crl, long typeMask, CrlList& crls, const bool& stopRefresh)
{		
	short srlErr = SRL_NOT_FOUND;
	short searchLoc = DSA_LOC;
	EncObject_LL *pObjList = NULL, *tmpObj = NULL;
	
	// get the Retrieval callback functions
	if (stopRefresh)
		return;
	const SRLCallbackFunctions& funcs = GetSRLFunc(crl.m_CRLSessionID);

	// If the CRL had an IssuingDistributionPoint get a CRL from it
	if (crl.m_pIssuingDistPtExt)
	{
		// Search using the distribution point names if present
		if (crl.m_pIssuingDistPtExt->distPoint != NULL)
		{
			// Search using the distribution point name(s)
			switch (crl.m_pIssuingDistPtExt->distPoint->GetType())
			{
			case DistPointName::DIST_PT_FULL_NAME:
				{
					const GenNames& fullName = crl.m_pIssuingDistPtExt->distPoint->GetFullName();
					GenNames::const_iterator j = fullName.begin();
					for ( ; j != fullName.end(); ++j)
					{
						// We will attempt to pull the CRL from X500 and URL name forms only
						if (j->GetType() == GenName::X500)
							srlErr = (funcs.pGetObj)(funcs.extHandle, (char*)(const char*)j->GetName().dn,
							typeMask, searchLoc, &pObjList);
						else if ((j->GetType() == GenName::URL) &&
							(funcs.pUrlGetObj != NULL))
						{
							srlErr = (funcs.pUrlGetObj)(funcs.extHandle,
								(char*)(const char*)j->GetName().name,
								typeMask, searchLoc, &pObjList);
						}
						else
							continue;
						
						if (srlErr == SRL_SUCCESS)
							break;
					}
				}
				break;
				
			case DistPointName::DIST_PT_REL_NAME:
				{
					// Build the full distribution point name using the crl's 
					// issuer
					DN fullName = crl.m_CRLIssuer;
					fullName += crl.m_pIssuingDistPtExt->distPoint->GetRelativeName();
					srlErr = (funcs.pGetObj)(funcs.extHandle, (char*)(const char*)fullName,
						typeMask, searchLoc, &pObjList);
				}
				break;
			}
		}
		else	// Use the crl's issuer
			srlErr = (funcs.pGetObj)(funcs.extHandle, (char*)(const char*)crl.m_CRLIssuer,
			typeMask, searchLoc, &pObjList);							
	}
	else // No IssuingDistributionPoint use the crl's issuer
	{
		srlErr = (funcs.pGetObj)(funcs.extHandle, (char*)(const char*)crl.m_CRLIssuer,
			typeMask, searchLoc, &pObjList);
	}

	if (srlErr == SRL_SUCCESS)
	{
		
		tmpObj = pObjList;
		while (tmpObj != NULL)
		{
			try {
				// decode each CRL
				Bytes decCRL(tmpObj->encObj);
				crls.push_back(decCRL);
			}
			catch (...)
			{
				// Skip this CRL
			}
			tmpObj = tmpObj->next;
		}
	}

	// Free the encode CRLs retrieved via the SRL
	(funcs.pFreeObj)(funcs.extHandle, &pObjList);

}

////////////////////
// CRLU Functions //
////////////////////
ulong CRLU_AddASession(const CRLDLLInitSettings_struct& settings)
{
	return gCRL_MgrInfo.AddSession(settings);

} // end of CMU_AddASession()


short CRLU_RemoveASession(ulong *sessionRefID)
{
	// Check parameter
	if (sessionRefID == NULL)
		return CM_INVALID_PARAMETER;

	// Reset the caller's sessionRefID to zero
	ulong tmpRefID = *sessionRefID;
	*sessionRefID = 0;

	try {
		gCRL_MgrInfo.DeleteSession(tmpRefID);
	}
	catch (...) {
		return CRL_SESSION_NOT_VALID;
	}

	return CRL_SUCCESS;
}

////////////////////////////
// C++ object definitions //
////////////////////////////

// CRLHeader definition
CRLHeader::CRLHeader()
{
	m_pIssuingDistPtExt = NULL;
	m_pFreshestCRL = NULL;
	m_pNextUpdate = NULL;
	m_revHashTable = NULL;
	m_pCrlNumber = NULL;
	m_pDeltaCrlNumber = NULL;
	m_pDeltaThisUpdate = NULL;
	m_pDeltaNextUpdate = NULL;
	m_CRLSessionID = 0;
	m_valid = false;
   m_baseDBID = -1;
   m_deltaDBID = -1;
}

bool CRLHeader::IsValid() const
{
	// CRLHeader should already have a read lock since this method
	// should be accessed through a CachedCRLContext.

	// If the CRL does not have a freshest CRL extension, then use the validity flag
	// as is becuase no Delta was needed
	if (m_pFreshestCRL == NULL)
	{
		return m_valid;
	}
	// It does have the freshest CRL extension. Check to see if the delta information is present.
	// If so, use the validity flag as is since we have both the base and delta information
	else if (m_pDeltaThisUpdate != NULL)
	{
		return m_valid;
	}
	else 
		return false;
}


bool CRLHeader::Init(const CRL& crl, ulong crlSessionID, 
					 bool valid, time_t maxTTL)
{
	// Never initialize a CRL header from a delta CRL
	if (crl.base().IsDelta())
	{
		return false;
	}

	m_CRLSessionID = crlSessionID;

	m_CRLIssuer = crl.base().issuer;

	m_ThisUpdate = crl.base().thisUpdate;

	if (crl.base().nextUpdate != NULL)
	{
		m_pNextUpdate = new Time(*crl.base().nextUpdate);
		if (m_pNextUpdate == NULL)
			return false;
	}

	if (crl.base().crlExts.pIssuingDP != NULL)
	{
		m_pIssuingDistPtExt = 
                  new IssuingDistPointExtension(*crl.base().crlExts.pIssuingDP);
		if (m_pIssuingDistPtExt == NULL)
			return false;
	}

	if (crl.base().crlExts.pCrlNumber != NULL)
	{
		m_pCrlNumber = new CRLNumberExtension(*crl.base().crlExts.pCrlNumber);
		if (m_pCrlNumber == NULL)
			return false;
	}

	if (crl.base().crlExts.pFreshestCRL != NULL)
	{
		m_pFreshestCRL = new FreshestCrlExtension(*crl.base().crlExts.pFreshestCRL);
		if (m_pFreshestCRL == NULL)
			return false;
	}

	m_revHashTable = CRLInitHash();
	if (m_revHashTable == NULL)
		return false;

	// Add the revocations from the CRL into the hash table
	if (AddRevs2Hash(crl.base()) == false)
		return false;

	if (valid)
		m_valid = true;

   // No need to set the expiration time or add this CRL to the 
   // database for Temporary CRL Headers 
	if (crlSessionID == 0)
		return true;

   Bytes_struct* pCRL = NULL;
   try
   {
      // Add the CRL to the SRL database and record the DBID of this CRL
      // in the base CRL DBID member
      pCRL = ((const ASN::Bytes&)crl).GetBytesStruct();
      if (pCRL == NULL)
         throw CRL_NULL_POINTER;

      if (SRL_DatabaseAdd(GetLocalSRLSessionID(m_CRLSessionID), pCRL,
         SRL_CRL_TYPE) != SRL_SUCCESS)
         throw CRL_UNKNOWN_ERROR;

      long dbID = -1;
      if (SRL_GetDBID(GetLocalSRLSessionID(m_CRLSessionID), SRL_CRL_TYPE, pCRL,
         &dbID) != SRL_SUCCESS)
         throw CRL_UNKNOWN_ERROR;

      m_baseDBID = dbID;
      m_deltaDBID = -1;

      SRL_FreeBytes(&pCRL);
   }
   catch (...)
   {
      if (pCRL != NULL)
         SRL_FreeBytes(&pCRL);
      return false;
   }

	// Get the current date + time to live
	ASN::Time ttlTime(time(NULL) + maxTTL);

	ASN::Time adjCRLNextUpdate;
	// Set the adjusted CRL Next Update time. It may be adjusted due to a positive grace period,
	// or the nextUpdateTime was in the past. If it was in the past, then use the maxTTL passed in.
	if (m_pNextUpdate != NULL)
	{
		time_t crlGracePeriod = GetCRLGracePeriod(crlSessionID);
		if (crlGracePeriod > 0)
			adjCRLNextUpdate = Time(cvtTimeToTime_T(*m_pNextUpdate) + crlGracePeriod);
		else
			adjCRLNextUpdate = *m_pNextUpdate;
		if (adjCRLNextUpdate < Time())
			adjCRLNextUpdate = ttlTime;
	}
	
	// Set the object's expiration time to the lesser of the expiration time
	// and the time to live
	if ((m_pNextUpdate == NULL) || (ttlTime < adjCRLNextUpdate))
		m_validUntil = ttlTime;
	else
		m_validUntil = adjCRLNextUpdate;	

	return true;
}

bool CRLHeader::IsExpired(bool crlLockNeeded) const
{

	if (crlLockNeeded)
	{
		// Lock the mutex
		ASN::ReadLock lock = m_mutex.AcquireReadLock();

		ASN::Time curtime;
		return (curtime > m_validUntil);
	}
	else
	{
		ASN::Time curtime;
		return (curtime > m_validUntil);
	}
}

void CRLHeader::Refresh(const bool& stopRefresh)
{
	// This CRLHeader was locked by caller
	try
	{
		
		bool processDelta = false;

		// Retrieve any base CRL's associated with this CRL Header
		CrlList decCRLs;
		retrieveRemoteCRLs(*this, CRL_TYPE | ARL_TYPE, decCRLs, stopRefresh);
		
		// If we did not find any CRLs just return
		if (decCRLs.empty())
			return;
		
		// Sort the CRLs by thisUpdate time
		std::greater<CRL> sortByThisUpdate;
		decCRLs.sort(sortByThisUpdate);
		
		// Loop through each (base) CRL retrieved
		CrlList::const_iterator iCRL;
		for (iCRL = decCRLs.begin(); iCRL != decCRLs.end(); ++iCRL)
		{
			// Ignore Delta CRLs
			if (iCRL->base().IsDelta())
				continue;
			
			// Ignore CRLs that are not the same scope
			if (!IsSameCRL(iCRL->base(), false))
				continue;
			
			// Only use this CRL if it is newer than the one we currently have or
			// when this one is expired and the CRL is the same as the one one we
			// already have. 
			if ((iCRL->base().thisUpdate > m_ThisUpdate) ||
				(IsExpired(false) && (iCRL->base().thisUpdate == m_ThisUpdate)))
			{
				// Validate the CRL
				RevocationState state(m_CRLSessionID, stopRefresh);
				state.pCRLToRefresh = this;
				short cmlErr = CM_NO_PATH_FOUND;
				validateCRL(*iCRL, cmlErr, state);
				processDelta = true;
			}			
		}
		
		// If this is a base CRL, find and validate the delta CRLs and update the CRL Header if
		// we updated the base CRL
		if ((m_pFreshestCRL != NULL) && processDelta && m_valid)
		{
			decCRLs.clear();		
			
			// Retrieve any delta CRL's associated with this CRL Header
			retrieveRemoteCRLs(*this, DELTA_CRL_TYPE, decCRLs, stopRefresh);
			
			// Sort the CRLs by thisUpdate time
			std::greater<CRL> sortByThisUpdate;
			decCRLs.sort(sortByThisUpdate);
			
			// Loop through each CRL retrieved
			CrlList::const_iterator iCRL;
			bool update = false;
			for (iCRL = decCRLs.begin(); iCRL != decCRLs.end(); ++iCRL)
			{
				// Ignore Base CRLs
				if (!(iCRL->base().IsDelta()))
					continue;
				
				// Ignore CRLs that are not the same scope
				if (!IsSameCRL(iCRL->base(), false))
					continue;
				
				// Only use this delta CRL if it is newer than what we currently have
				if (m_pDeltaThisUpdate != NULL)
				{
					if (iCRL->base().thisUpdate > *m_pDeltaThisUpdate)
					{
						update = true;
					}	
				}
				else if (iCRL->base().thisUpdate > m_ThisUpdate)
				{
					update = true;
				}
				
				if (update)
				{
					// Validate the CRL
					RevocationState state(m_CRLSessionID, stopRefresh);
					state.pCRLToRefresh = this;
					short cmlErr = CM_NO_PATH_FOUND;
					
					// The CRL will be updated automatically by validateCRL()
					validateCRL(*iCRL, cmlErr, state);
				}
			}
		}
	}
	catch (...)
	{
		std::cerr << "Unexpected exception caught in CRLHeader::Refresh(), "
					  "not refreshing this item\n";
	}
}

CRLHeader::~CRLHeader()
{
	// Lock the mutex
	ASN::MutexLock lock = m_mutex.AcquireLock();
	Clear();
}

void CRLHeader::Clear()
{
	// Mutex is locked by the caller

	m_valid = false;
	m_ThisUpdate = Time(NULL);
	m_validUntil = Time(NULL);
	if (m_pIssuingDistPtExt != NULL)
		delete m_pIssuingDistPtExt;
	m_pIssuingDistPtExt = NULL;
	if (m_pFreshestCRL != NULL)
		delete m_pFreshestCRL;
	m_pFreshestCRL = NULL;
	if (m_pNextUpdate != NULL)
		delete m_pNextUpdate;
	m_pNextUpdate = NULL;
	if (m_pCrlNumber != NULL)
		delete m_pCrlNumber;
	m_pCrlNumber = NULL;
	if (m_pDeltaCrlNumber != NULL)
		delete m_pDeltaCrlNumber;
	m_pDeltaCrlNumber = NULL;
	if (m_pDeltaThisUpdate != NULL)
		delete m_pDeltaThisUpdate;
	m_pDeltaThisUpdate = NULL;
	if (m_pDeltaNextUpdate != NULL)
		delete m_pDeltaNextUpdate;
	m_pDeltaNextUpdate = NULL;
	if (m_revHashTable != NULL)
		CRLDestroyHash(m_revHashTable);
	m_revHashTable = NULL;
   m_baseDBID = -1;
   m_deltaDBID = -1;
}

// If the CRL is a delta CRL, then this method will check to see if this CRL Header represents
// the matching base CRL otherwise, it determines if the CRL Header and the CRL are the same
bool CRLHeader::IsSameCRL(const CertificateList& crl, bool crlLockNeeded) const
{
	if (crlLockNeeded)
	{
		//Sychronize on the CRLHeader mutex.
		ReadLock lock = m_mutex.AcquireReadLock();
		// Call private form of this method
		return PrivateIsSameCRL(crl);
	}
	else
		return PrivateIsSameCRL(crl);
}


// Private form of this method
bool CRLHeader::PrivateIsSameCRL(const CertificateList& crl) const
{
	IssuingDistPointExtension *thisIDP = m_pIssuingDistPtExt;
	IssuingDistPointExtension *crlIDP = crl.crlExts.pIssuingDP;

	// IssuingDistributionPoint must be present or absent in both the CRL and this
	// CRL header for this CRL to be considered a match
	if ( ((thisIDP != NULL) && (crlIDP == NULL)) ||
		 ((thisIDP == NULL) && (crlIDP != NULL)) )
	{
		return false;
	}

	// The IssuingDistributionPoints, if present, must be identical 
	if ( ((thisIDP != NULL) && (crlIDP != NULL)) &&
		 (!(*thisIDP == *crlIDP)) )
	{
		return false;
	}

	// They must both be signed by the same issuer
	if (m_CRLIssuer != crl.issuer)
	{
		return false;
	}

	return true;
}

bool CRLHeader::MatchesScope(CertType certType, const DN& certIssuer,
							 const DistributionPoint* pDistPt,
							 bool isCritical,
							 const RevocationReasons* pReasons) const
{
	// CRLHeader should already have a read lock since this method
	// should be accessed through a CachedCRLContext.

	// This CRL does not match scope if the the CRL distribution point passed
	// in is critical and the CRL does not contain an issuing 
	// distibution point.
	if ((pDistPt->distPoint != NULL) && (isCritical) && (m_pIssuingDistPtExt == NULL))
		return false;

	// If the crlIssuer field is absent from the CRL distribution point, check
	// the issuer of the CRL is the same as the issuer of the cert
	if ((pDistPt == NULL) || (pDistPt->crlIssuer == NULL))
	{
		if (m_CRLIssuer != certIssuer)
			return false;

		// If this is a complete CRL, return true
		if (m_pIssuingDistPtExt == NULL)
			return true;
	}
	else
	{
		// Check that the issuer of the CRL is one of the names in the
		// crlIssuer field and the indirectCRL flag is set
		if (!pDistPt->crlIssuer->IsPresent(m_CRLIssuer))
			return false;
		if ((m_pIssuingDistPtExt == NULL) || !m_pIssuingDistPtExt->indirectCRL)
			return false;
	}

	const IssuingDistPointExtension& idp = *m_pIssuingDistPtExt;

	// Check if the CRL covers revocations for this type of cert
	if (idp.onlyContainsAuthorityCerts && (certType != CACert))
		return false;
	else if (idp.onlyContainsUserCerts && (certType != EndEntityCert))
		return false;
	else if (idp.onlyContainsAttributeCerts)
		return false;

	// Check if the CRL covers revocations for the specified reasons
	static const RevocationReasons kNULL_Reasons;
	if (idp.onlySomeReasons != NULL)
	{
		if ((pDistPt != NULL) && (pDistPt->reasons != NULL))
			pReasons = pDistPt->reasons;
		
		if (pReasons != NULL)
		{
			if ((*idp.onlySomeReasons & *pReasons) == kNULL_Reasons)
				return false;
		}
	}

	// If the distribution points are specified, check that one of the
	// names in the distribution point field matches one of the IDP names
	if ((pDistPt != NULL) && (idp.distPoint != NULL))
	{
		// Find the full distribution point names in the distribution
		// point or the crlIssuer fields, or build the full names from
		// the relative name
		const GenNames* pDpNames = NULL;
		std::list<DN> dpDNs;
		if (pDistPt->distPoint != NULL)
		{
			if (pDistPt->distPoint->GetType() ==
				DistPointName::DIST_PT_FULL_NAME)
				pDpNames = &pDistPt->distPoint->GetFullName();
			else	// DIST_PT_REL_NAME
			{
				// Distribution point is relative to either the crlIssuer
				// (if present) or the certificate issuer
				if (pDistPt->crlIssuer != NULL)
				{
					// Copy each of the X.500 DNs into the dpDN list
					GenNames::const_iterator iGN =
						pDistPt->crlIssuer->Find(GenName::X500);
					while (iGN != pDistPt->crlIssuer->end())
					{
						dpDNs.push_back(*iGN->GetName().dn);
						iGN = pDistPt->crlIssuer->FindNext(iGN,
							GenName::X500);
					}
				}
				else	// Copy the cert issuer DN into the dpDN list
					dpDNs.push_back(certIssuer);
				
				// Append the relative name to each of the DNs in the dpDN
				// list
				std::list<DN>::iterator iDN;
				for (iDN = dpDNs.begin(); iDN != dpDNs.end(); ++iDN)
					*iDN += pDistPt->distPoint->GetRelativeName();
			}
		}
		else if (pDistPt->crlIssuer != NULL)
			pDpNames = pDistPt->crlIssuer;
		else	// Distribution point is just the certificate issuer
			dpDNs.push_back(certIssuer);
		
		// Check that one of the distribution point names in the IDP
		// matches a name from the cert's distribution points
		if (idp.distPoint->GetType() == DistPointName::DIST_PT_FULL_NAME)
		{
			if (pDpNames != NULL)
			{
				if (!pDpNames->IsOnePresent(idp.distPoint->GetFullName()))
					return false;
			}
			else
			{
				bool matchFound = false;
				std::list<DN>::const_iterator iDN = dpDNs.begin();
				for ( ; (iDN != dpDNs.end()) && !matchFound; ++iDN)
				{
					if (idp.distPoint->GetFullName().IsPresent(*iDN))
						matchFound = true;
				}
				if (!matchFound)
					return false;
			}
		}
		else	// DIST_PT_REL_NAME
		{
			// Build full IDP name
			DN fullIDPName = m_CRLIssuer;
			fullIDPName += idp.distPoint->GetRelativeName();
			if (pDpNames != NULL)
			{
				if (!pDpNames->IsPresent(fullIDPName))
					return false;
			}
			else
			{
				bool matchFound = false;
				std::list<DN>::const_iterator iDN = dpDNs.begin();
				for ( ; (iDN != dpDNs.end()) && !matchFound; ++iDN)
				{
					if (*iDN == fullIDPName)
						matchFound = true;
				}
				if (!matchFound)
					return false;
			}
		}
	}
	else if (pDistPt == NULL)	// Check this complete CRL
	{
		if (idp.distPoint != NULL)
		{
			// REN -- 2/1/2002 -- Temporary fix for new PKIX part 1 profile:
			// According to X.509, complete CRLs should not have a
			// distribution point in the IDP extension, but PKIX part 1
			// currently allows a DP if it matches the cert issuer's DN.
			//
			// Check that if a complete CRL has a DP name, that it matches
			// the cert issuer's DN
			if (idp.distPoint->GetType() == DistPointName::DIST_PT_FULL_NAME)
			{
				if (!idp.distPoint->GetFullName().IsPresent(certIssuer))
					return false;
			}
			else	// DIST_PT_REL_NAME
			{
				DN fullIssuer = m_CRLIssuer;
				fullIssuer += idp.distPoint->GetRelativeName();
				if (fullIssuer != certIssuer)
					return false;
			}
		}
	}

	return true;
} // end of MatchesScope()

bool CRLHeader::UpdateHeaderFromDelta(const CRL& crl, bool valid,
									  time_t maxTTL, bool crlLockNeeded)
{
	if (crlLockNeeded)
	{
		//Sychronize on the CRLHeader mutex.
		MutexLock lock = m_mutex.AcquireLock();
		return PrivateUpdateHeaderFromDelta(crl, valid, maxTTL);
	}
	else
		return PrivateUpdateHeaderFromDelta(crl, valid, maxTTL);
}

bool CRLHeader::PrivateUpdateHeaderFromDelta(const CRL& crl, bool valid, time_t maxTTL)
{
	// If this is not a delta CRL do not try to update this header.
	if (crl.base().crlExts.pDeltaCRL == NULL)
	{
		return false;
	}

	// Make sure this Delta CRL is in the same stream as the base CRL
	if ((m_pCrlNumber != NULL) && (*m_pCrlNumber < *crl.base().crlExts.pDeltaCRL))
	{		
		return false;
	}

	// Make sure the Base Update time is appropriate
	if ((crl.base().crlExts.pBaseUpdate != NULL) && 
      (ASN::Time(*crl.base().crlExts.pBaseUpdate) > ASN::Time()))
	{
		return false;
	}

	// Make sure the time this new delta CRL was issued is later then the previous delta, or
	// if there was not a previous delta, then the base CRL
	if (m_pDeltaThisUpdate != NULL)
	{
		// there was a previous delta, is this one newer
		if (*m_pDeltaThisUpdate > crl.base().thisUpdate)
			return false;
	}
	else
	{
		// no previous delta, see if this delta is newer than the base
		if (m_ThisUpdate > crl.base().thisUpdate)
			return false;
	}

	// If this delta CRL has a CRL number, make sure the CRL number in this new delta CRL 
	// is later then the previous delta, or if there was not a previous delta, then the base CRL
	if (crl.base().crlExts.pCrlNumber != NULL)
	{
		if (m_pDeltaCrlNumber != NULL)
		{
			// there was a previous delta CRL number, is this one newer
			if ((*crl.base().crlExts.pCrlNumber < *m_pDeltaCrlNumber) ||
             (*crl.base().crlExts.pCrlNumber == *m_pDeltaCrlNumber))
				return false;
		} 
		else if (m_pCrlNumber != NULL)
		{
			// no previous delta CRL number, see if this delta is newer than the base
			if (*crl.base().crlExts.pCrlNumber < *m_pCrlNumber)
				return false;
		}
	}

	// Add the revocations from the CRL into the hash table, if it fails then
	// set m_valid to false so it is not used until the next refresh occurs
	if (AddRevs2Hash(crl.base()) == false)
	{
		m_valid = false;
		return false;
	}

	// update the delta CRL fields
	// This update
	if (m_pDeltaThisUpdate != NULL)
		delete m_pDeltaThisUpdate;

	m_pDeltaThisUpdate = new Time(crl.base().thisUpdate);
	if (m_pDeltaThisUpdate == NULL)
	{
		m_valid = false;
		return false;
	}

	// Next Update
	if (m_pDeltaNextUpdate != NULL)
	{
		delete m_pDeltaNextUpdate;
		m_pDeltaNextUpdate = NULL;
	}

	if (crl.base().nextUpdate != NULL)
	{		
		m_pDeltaNextUpdate = new Time(*crl.base().nextUpdate);
		if (m_pDeltaNextUpdate == NULL)
		{
			m_valid = false;
			return false;
		}
	}

	// CRL number
	if (m_pDeltaCrlNumber != NULL)
	{
		delete m_pDeltaCrlNumber;
		m_pDeltaCrlNumber = NULL;
	}

	if (crl.base().crlExts.pCrlNumber != NULL)
	{		
		m_pDeltaCrlNumber = new CRLNumberExtension(*crl.base().crlExts.pCrlNumber);
		if (m_pDeltaCrlNumber == NULL)
		{
			m_valid = false;
			return false;
		}
	}

   // Add the CRL to the SRL database and record the DBID of this CRL
   // in the delta CRL DBID member
   Bytes_struct* pCRL = ((const ASN::Bytes&)crl).GetBytesStruct();
   if (pCRL == NULL)
      return false;
   if (SRL_DatabaseAdd(GetLocalSRLSessionID(m_CRLSessionID), pCRL,
                       SRL_CRL_TYPE) != SRL_SUCCESS)
   {
      SRL_FreeBytes(&pCRL);
      return false;
   }
   long dbID = -1;
   if (SRL_GetDBID(GetLocalSRLSessionID(m_CRLSessionID), SRL_CRL_TYPE, pCRL,
                   &dbID) != SRL_SUCCESS)
   {
      SRL_FreeBytes(&pCRL);
      return false;
   }
   SRL_FreeBytes(&pCRL);
   m_deltaDBID = dbID;

	// If everything has gone well so far then set this CRL header status to valid
	if (m_valid && valid)
		m_valid = true;
	return true;
}

void CRLHeader::UpdateHeader(const CRL& crl, bool valid, 
							 time_t maxTTL, bool crlLockNeeded)
{
	if (crlLockNeeded)
	{
		//Sychronize on the CRLHeader mutex.
		MutexLock lock = m_mutex.AcquireLock();
		PrivateUpdateHeader(crl, valid, maxTTL);
	}
	else
		PrivateUpdateHeader(crl, valid, maxTTL);
}


void CRLHeader::PrivateUpdateHeader(const CRL& crl, bool valid, time_t maxTTL)
{
	Clear();
	Init(crl, m_CRLSessionID, valid, maxTTL);
}

bool CRLHeader::AddRevs2Hash(const CertificateList& InCRL)
{
	// CRL Header should already be locked by caller
	bool revsAdded = true;
	const Revocations& ThisRevocation = InCRL.GetRevocations();
	
	if (!ThisRevocation.empty())
	{
		// We hash the serial number for non-indirect CRLs and the issuer + the serial number for indirect CRLs
		char *currentIssuer = NULL;
		
		// For each revocation in the list
		// add it to the hash
		// 
		for (Revocations::const_iterator iRev = ThisRevocation.begin();
		iRev != ThisRevocation.end(); ++iRev)
		{
			Bytes *SerNum = new Bytes((iRev->SerialNum()).length(), (iRev->SerialNum()).c_str());
			if (SerNum == NULL)
			{
				return false;
			}
			int hlen = 0;
			// If this is an indirect CRL then use the issuer in the key
			if (InCRL.crlExts.pIssuingDP &&
             InCRL.crlExts.pIssuingDP->indirectCRL)
			{
				if (getCurrentRevocationIssuer(InCRL, *iRev, (iRev == ThisRevocation.begin()),
					&currentIssuer) == false)
				{
					// We could not get the name from the revoked entry for some reason
					if (currentIssuer)
						free(currentIssuer);
					delete SerNum;
					return false;
				}
				hlen = strlen(currentIssuer) + SerNum->Len();
			}
			else
				hlen = SerNum->Len();
			char *key = (char *) calloc (1, hlen);
			if (key == NULL)
			{
				free (currentIssuer);
				delete SerNum;
				return false;
			}
			// If this is an indirect CRL then use the issuer in the key
			if (InCRL.crlExts.pIssuingDP &&
             InCRL.crlExts.pIssuingDP->indirectCRL)
			{
				memcpy(key, currentIssuer, strlen(currentIssuer));
				memcpy(key+strlen(currentIssuer), (char *)SerNum->GetData(), SerNum->Len());
			}
			else
				memcpy(key, (char *)SerNum->GetData(), SerNum->Len());
			
			// Get the hash value
			ulong h;
			h = CRLMakeHash (key, hlen);
			
			// Insert the data
			RevCerts_LL *revCert = iRev->GetRevCertsStruct();
			if (revCert == NULL)
			{
				free (currentIssuer);
				delete SerNum;
				free (key);
				return false;
			}
			// Build the data to be stored
			Revocation *thisRev = new Revocation;
			if (thisRev == NULL)
			{
				free (currentIssuer);
				delete SerNum;
				free (key);
				FreeRevCerts_LL(revCert);
				return false;
			}
			thisRev->Set(key, hlen, SerNum, revCert);
			// Store the data but break if it fails
			if ((revsAdded = CRLInsert(m_revHashTable, thisRev, h)) == false)
			{
				free (currentIssuer);
				delete SerNum;
				free (key);
				FreeRevCerts_LL(revCert);
				delete thisRev;
				return false;
			}
		}
		
		if (currentIssuer)
			free (currentIssuer);
		
	} // Endif empty revocation
	
	return revsAdded;
}

//////////////////////////////////////////////////////////////////////////////
// FUNCTION:  CheckForRevocation
// 
// Description: Get the revocation status of a cert
//
// Inputs: 
//   Certificate&    cert            - decoded cert
//
//	  CML::ASN::Time* pValidationTime - If not NULL, points to a date/time that must
//                                  be used when checking revocation status
//
// Outputs:
//	  RevInfo*        pRevInfo        - Revocation information for the cert
// Return Value: 
//	  bool                            - revocation status
///////////////////////////////////////////////////////////////////////////////
bool CRLHeader::CheckForRevocation(const Certificate& decCert, RevInfo* pRevInfo,
								   const CML::ASN::Time* pValidationTime) const
{
	// CRLHeader should already have a read lock since this method
	// should be accessed through a CachedCRLContext.

	int hlen = 0;
	bool isRevoked = false;
	// Check the Revocations
	char *hashValue = NULL, *key = NULL;
	// Check to see if this CRL Header represents an indirect CRL
	if (m_pIssuingDistPtExt && m_pIssuingDistPtExt->indirectCRL)
		hlen = strlen(decCert.base().issuer) + decCert.base().serialNumber.length();
	else
		hlen = decCert.base().serialNumber.length();
	key = (char *)calloc(1, hlen);
	if (key == NULL)
		throw CRL_MEMORY_ERROR;
	hashValue = key;
	// Only include the issuer if indirect CRL
	if (m_pIssuingDistPtExt && m_pIssuingDistPtExt->indirectCRL)
	{
		memcpy(hashValue, decCert.base().issuer, strlen(decCert.base().issuer));
		hashValue += strlen(decCert.base().issuer);
	}
	memcpy(hashValue, (char *)decCert.base().serialNumber.c_str(), decCert.base().serialNumber.length());
	ulong hash = CRLMakeHash(key, hlen);

	// See if we can find it in the hash
	Revocation *value = NULL;
	bool HashStatus =  CRLCheckForAndReturnValue (m_revHashTable, hash, key, hlen, &value);	

	if (key)
		free (key);
	
	// Check to see if we found this cert revoked
	if (HashStatus)
	{
		//Cert is potentially revoked
		const RevCerts_LL *theRevocations = value->GetRevocation();
		while (theRevocations != NULL)
		{
			bool revoked = true;
			// Check the Revocation date and make sure
			// it is within range for the revocation, if not
			// then the cert is still good.
			if (theRevocations->revDate != NULL)
			{
				// If validation time has been set, use it 
				if (pValidationTime != NULL)
				{
					Time tstDate (*pValidationTime);
					Time revDate((char *)theRevocations->revDate);		
					// If tstDate < the revDate then it hasn't expired
					if (tstDate < revDate)
						revoked = false;
				}
				else // compare against current time
				{
					Time revDate((char *)theRevocations->revDate);
                    // If revdate >= the current time then it hasn't expired
					if (Time() < revDate)
						revoked = false;
				}
			}
			if (revoked == true)
			{
				isRevoked = true;				
				// Fill in the RevInfo structure if needed
				if (pRevInfo && isRevoked)
				{
					pRevInfo->status = CM_STATUS_REVOKED;
					if (theRevocations->exts != NULL)
					{
						if (theRevocations->exts->reasonCode != NULL)
						{
							// Cert Revoked, fill in the reason
							short *pReasonCode = (short*)calloc(1, sizeof(short));
							if (pReasonCode == NULL)
								throw CRL_MEMORY_ERROR;
							*pReasonCode = *(short*)theRevocations->exts->reasonCode->value;
							pRevInfo->revReason = pReasonCode;
							
						}
						
						// Fill in the revocation date
						if (theRevocations->revDate)
						{						
							CM_TimePtr pRevDate = (CM_TimePtr)calloc(1, sizeof(CM_Time));
							if (pRevDate == NULL)
								throw CRL_MEMORY_ERROR;
							memcpy(pRevDate, theRevocations->revDate, sizeof(CM_Time));
							pRevInfo->revDate = pRevDate;
						}

						// Fill in the times from the actual CRL (stored in the CRLHeader)
						memcpy(pRevInfo->thisUpdate, m_ThisUpdate, sizeof(CM_Time));
						if (m_pNextUpdate)
						{
							pRevInfo->nextUpdate = (CM_TimePtr)calloc(1, sizeof(CM_Time));
							if (pRevInfo->nextUpdate == NULL)
								throw CRL_MEMORY_ERROR;
							memcpy(*pRevInfo->nextUpdate, *m_pNextUpdate, sizeof(CM_Time));
						}
					}
					
					// We should have enough information to report to the caller, return
					return isRevoked;
				}
			}
			theRevocations = theRevocations->next;
		}
	}
	return isRevoked;
}

// Revocation definition
Revocation::Revocation()
{
	m_serialNumber = NULL;
	m_key = NULL;
	m_keyLen = 0;
	m_revCert = NULL;
}

Revocation::~Revocation()
{
	if (m_key != NULL)
		free (m_key);
	if (m_serialNumber != NULL)
		delete m_serialNumber;
	if (m_revCert != NULL)
		FreeRevCerts_LL(m_revCert);
}

void Revocation::SetSerialNumber(Bytes *SerialNumber) 
{
	m_serialNumber = SerialNumber;
}

const Bytes *Revocation::GetSerialNumber()
{
	return m_serialNumber; 
}

const char *Revocation::GetKey()
{
	return m_key;
}

size_t Revocation::GetKeyLen()
{
	return m_keyLen;
} 

void Revocation::SetKey(char *key)
{
	m_key = key;
}

void Revocation::Set (char *key, size_t keyLen, Bytes *SerNum, 
				 RevCerts_LL *revs)
{
	if (key != NULL)
		m_key = key;
	m_keyLen = keyLen;
	if (SerNum != NULL)
		m_serialNumber = SerNum;
	if (revs != NULL)
		m_revCert = revs;
}

RevCerts_LL *Revocation::GetRevocation()
{
	return m_revCert;
}

// CachedCRLContext definition
CachedCRLContext::CachedCRLContext(const CRLHeader& crlHeader) : m_crlHeader(crlHeader),
m_CRLHeaderLock(crlHeader.m_mutex.AcquireReadLock())
{
}

CachedCRLContext::CachedCRLContext(const CachedCRLContext& that) :
m_crlHeader(that.m_crlHeader), m_CRLHeaderLock(that.m_CRLHeaderLock)
{
}

CachedCRLContext::~CachedCRLContext()
{
}

// TemporaryCRLContext definition
TemporaryCRLContext::TemporaryCRLContext(const CRL& crl)
{
	// If we are unable to initialize the header from the CRL throw an exception
	if (m_crlHeader.Init(crl, 0, true, 0) == false)
		throw;
}

TemporaryCRLContext::TemporaryCRLContext(const TemporaryCRLContext& that) :
m_crlHeader(that.m_crlHeader)
{
}

TemporaryCRLContext::~TemporaryCRLContext()
{
}

// CRLHeaderCache Definition
const CachedCRLContext* CRLHeaderCache::Add(const CRL& crl, bool valid,
											time_t maxTTL, CRLHeader* pCrlToUpdate)
{
	// If we were given a reference to an already cached CRL Header
	// then just update it and return. Cache is alread locked by 
	// CRLHeaderCache::Refresh
	if (pCrlToUpdate != NULL)
	{
		if (crl.base().IsDelta())
			// Add the delta CRL to the base
			pCrlToUpdate->UpdateHeaderFromDelta(crl, valid, maxTTL, false);
		else
			// CRL must have changed in some way, refresh it
			pCrlToUpdate->UpdateHeader(crl, valid, maxTTL, false);
		return NULL;
	}

	//Sychronize on the cache mutex.
	MutexLock lock = m_cacheMutex.AcquireLock();
	
	//
	// Go through the Header list to see if this CRL
	// exists already, if it doesn't add it to our list
	//
	CrlGNIndex::size_type num = m_crlsByGN.count(getDistPtName(crl.base()));
	CrlGNIndex::const_iterator j = m_crlsByGN.find(getDistPtName(crl.base()));
	if ((num != 0) && (j != m_crlsByGN.end()))
	{
		for (CrlGNIndex::size_type i = 0; i < num; ++i, ++j)
		{
			if (j->second->IsSameCRL(crl.base()) == true)
			{
				// Found this CRL in the Header List, update the information
				if (crl.base().IsDelta())
            {
					// Add the delta CRL to the base
					if (j->second->UpdateHeaderFromDelta(crl, valid, maxTTL) == false)
                  return NULL;
            }
				else
					// CRL must have changed in some way, refresh it
					j->second->UpdateHeader(crl, valid, maxTTL);
				return new CachedCRLContext(*j->second);
			}
		}		
	}

	// Create a new CRLHeader for this CRL and add to cache
	push_back(CRLHeader());
	CRLHeader& newCRLHeader = back();

	// initialize the CRL Header from the CRL
	if (newCRLHeader.Init(crl, m_crlSessionID, valid, maxTTL) == false)
	{
		pop_back();
		return NULL;
	}

	// add the CRL Header to the index by its name(s)
	bool added = false;
	if ((crl.base().crlExts.pIssuingDP != NULL) &&
		(crl.base().crlExts.pIssuingDP->distPoint != NULL))
	{
		const DistPointName& dpName = *crl.base().crlExts.pIssuingDP->distPoint;
		if (dpName.GetType() == DistPointName::DIST_PT_REL_NAME)
		{
			DN fullName(crl.base().issuer);
			fullName += dpName.GetRelativeName();
			m_crlsByGN.insert(CrlGNIndex::value_type(fullName, &newCRLHeader));
			added = true;
		}
		else	// DIST_PT_FULL_NAME
		{
			// Add by X.500 DN (if present)
			GenNames::const_iterator iGN =
				dpName.GetFullName().Find(GenName::X500);
			for (;iGN != dpName.GetFullName().end(); ++iGN)
			{
				m_crlsByGN.insert(CrlGNIndex::value_type(*iGN, &newCRLHeader));
				added = true;
			}

			// Add by URL (if present)
			iGN = dpName.GetFullName().Find(GenName::URL);
			for (;iGN != dpName.GetFullName().end(); ++iGN)
			{
				m_crlsByGN.insert(CrlGNIndex::value_type(*iGN, &newCRLHeader));
				added = true;
			}
		}
	}

	// if not added, then just use the CRL issuer
	if (!added)
		m_crlsByGN.insert(CrlGNIndex::value_type(crl.base().issuer, &newCRLHeader));

	return new CachedCRLContext(newCRLHeader);
}

void CRLHeaderCache::Find(const GenName& distPtName, CachedCRLCtxList& crlHeaders,
						  CRLHeader *pCRLToRefresh) const
{
	//Sychronize on the cache mutex.
	ReadLock lock = m_cacheMutex.AcquireReadLock();

	// Get the number of cached CRLs from the specified distribution point
	// and the first one
	CrlGNIndex::size_type num = m_crlsByGN.count(distPtName);
	CrlGNIndex::const_iterator iCrl = m_crlsByGN.find(distPtName);
	if ((num == 0) || (iCrl == m_crlsByGN.end()))
		return;

	for (CrlGNIndex::size_type i = 0; i < num; ++i, ++iCrl)
	{
		bool lockNeeded = true;
		if (iCrl->second == NULL)
			throw CRL_NULL_POINTER;

		// Do not re-lock this CRL Header if it is the one being
		// updated by the refresh thread.
		if (iCrl->second == pCRLToRefresh)
			lockNeeded = false;

		// Do not include CRLs that have passed their time to live
		if (iCrl->second->IsExpired(lockNeeded))
			continue;

		// Add a pointer to the cached CRL to the resulting list
		CachedCRLContext *pCRLCtx = new CachedCRLContext(*iCrl->second);
		crlHeaders.push_back(pCRLCtx);
	}
}

void CRLHeaderCache::Empty()
{
	// Set flag to stop the refresh as we are about to clear the cache
	m_stopRefresh = true;

	//Sychronize on the cache mutex.
	MutexLock lock = m_cacheMutex.AcquireLock();

	m_crlsByGN.clear();
	clear();
}

void CRLHeaderCache::Refresh()
{
	bool finished = false;
	bool firstTime = true;
	CRLHeaderCache::iterator iCrlHdr;
	
	// Loop through each CRLHeader in the cache and call its Update method
	do {
		// Lock the cache mutex
		MutexLock cacheLock = m_cacheMutex.AcquireLock();

		if (!firstTime)
		{
			if (iCrlHdr != end() && (size() != 0))
				++iCrlHdr;
		}
		else
		{
			iCrlHdr = begin();
			firstTime = false;
		}
		// If we are not at the end, then refresh this CRLHeader
		if (iCrlHdr == end() || (size() == 0))
			finished = true;
		// If the cached was recently emptied, then stop
		else if (m_stopRefresh == true)
		{
			m_stopRefresh = false;
			finished = true;
		}
		else
		{
			// Refresh the CRL Header 
			MutexLock headerLock = iCrlHdr->m_mutex.AcquireLock();
			cacheLock.Release();
			iCrlHdr->Refresh(m_stopRefresh);
		}
				
	} while (!finished);
}

//////////////////////////////////////
// CRL_MgrInfo class implementation //
//////////////////////////////////////
ulong CRL_MgrInfo::AddSession(const CRLDLLInitSettings_struct& settings)
{
	ulong ref = 0;
	try {
		// Acquire or lock the mutex
		MutexLock lock = mMutex.AcquireLock();
		
		// Create a unique ref id for this session
		ref = GenRandomSessionID(&settings);
		if (ref == 0)
			throw CRL_MEMORY_ERROR;

		// Insert a new session into the map
		CRLSession& newSession = m_sessions[ref];

		// Initialize the session
		newSession.Initialize(ref, settings);
		return ref;
	}
	catch (...) {
		DeleteSession(ref);
		throw CRL_INIT_ERROR;
	}
} // end of CRL_MgrInfo::AddSession()

void CRL_MgrInfo::DeleteSession(ulong sessionID)
{
	// Acquire a read lock on the session so we
	// can stop the service thread
	ReadLock rlock = mMutex.AcquireReadLock();
	SessionMap::iterator i = m_sessions.find(sessionID);

	if (i == m_sessions.end())
		throw CRL_SESSION_NOT_VALID;
	i->second.StopServiceThread();
	rlock.Release();

	// Acquire or lock the mutex
	MutexLock rwlock = mMutex.AcquireLock();
	ulong numErased = m_sessions.erase(sessionID);

	if (numErased == 0)
		throw CRL_SESSION_NOT_VALID;

   // Remove temporary SRL databases used by the session
   std::stringstream sessionStr;
   sessionStr << sessionID;
   std::string certDBFile = "cert_" + sessionStr.str() + ".db";
   std::string crlDBFile = "crl_" + sessionStr.str() + ".db";
   unlink(certDBFile.c_str());
   unlink(crlDBFile.c_str());
}

CRLSession& CRL_MgrInfo::GetSession(ulong sessionID)
{
	// Acquire or lock the mutex
	ReadLock lock = mMutex.AcquireReadLock();

	SessionMap::iterator i = m_sessions.find(sessionID);

	if (i == m_sessions.end())
		throw CRL_SESSION_NOT_VALID;

	return i->second;
}

ulong CRL_MgrInfo::GenRandomSessionID(const void *address) const
{
	// NOTE:  CRL_MgrInfo must be locked!!

	// Check parameter
	if (address == NULL)
		return 0;

	// Hash the address
	Bytes inputBytes(sizeof(void*), (const uchar*)&address);
	Bytes hash;
	inputBytes.Hash(hash);
	ulong sessionID = *(ulong*)hash.GetData();

	/* If the sessionID already exists, shift it right until a unique value
	is found  */
	bool sessionExists;
	do
	{
		SessionMap::const_iterator i = m_sessions.find(sessionID);
		if (i == m_sessions.end())
			sessionExists = false;
		else
		{
			sessionExists = true;
			sessionID >>= 1;
		}
	} while (sessionExists && (sessionID != 0));

	return sessionID;
} // end of CRL_MgrInfo::GenRandomSessionID()

//////////////////////////////////
// CRLSession class implementation //
//////////////////////////////////
CRLSession::CRLSession()
{
	pCrlHeaderCache = NULL;
   m_localSRLSessionID = 0;
#ifndef NOTHREADS
	serviceThreadID = 0;
	terminateSvcThread = false;
#endif //WIN32
}

// Copy constructor exists only to compile SessionMap class
// Not actually used
CRLSession::CRLSession(const CRLSession& that)
{
	pCrlHeaderCache = NULL;
   m_localSRLSessionID = that.m_localSRLSessionID;
#ifndef NOTHREADS
	serviceThreadID = 0;
	terminateSvcThread = false;
#endif //WIN32
}

#ifndef NOTHREADS
#ifdef WIN32 
DWORD WINAPI CRLSession::ServiceThread(void* inargs)
#else //WIN32
void *CRLSession::ServiceThread(void* inargs)
#endif //WIN32
{
	time_t lastRefreshTime = 0;
	time_t lastSleep = time(NULL);
	time_t sleepPeriod = ((CRLSession*)inargs)->crlRefreshPeriod;
	
	for (; (sleepPeriod != 0) ;)
	{
		if (((CRLSession*)inargs)->terminateSvcThread == true)
			return 0;

		// If the last sleep period has passed by - don't sleep
		if ((lastSleep + sleepPeriod) > time(NULL))
		{
			int i;
			// start a loop which checks periodically to see if we need to terminate
			for (i = 0; i < (sleepPeriod/PAUSE_TIME); ++i)
			{
				if (((CRLSession*)inargs)->terminateSvcThread == true)
					return 0;
#ifdef WIN32
				Sleep(PAUSE_TIME * 1000);
#else
				usleep(PAUSE_TIME * 1000000);
#endif
			}
		}
		lastSleep = time(NULL);
		if (sleepPeriod != LONG_MAX)
		{
			// Check the refresh period, if expired - refresh
			if  ((lastRefreshTime + sleepPeriod) <  time(NULL))
			{
				((CRLSession*)inargs)->pCrlHeaderCache->Refresh();
			}			
		}
	}
	return 0;
}
#endif //NOTHREADS

CRLSession::~CRLSession()
{

	// Make sure the Service Thread has terminated
	StopServiceThread();

	// delete the CRL Header Cache
	if (pCrlHeaderCache)
		delete pCrlHeaderCache;

   // Destroy the temporary SRL session which was used to store and
   // retrieve CRLs for the life of this session.
   SRL_DestroySession(&m_localSRLSessionID);
}

void CRLSession::StopServiceThread()
{
#ifndef NOTHREADS
	// Set flag to stop the service thread
	terminateSvcThread = true;
	if (pCrlHeaderCache)
		pCrlHeaderCache->m_stopRefresh = true;
	
	// Wait for thread to terminate
	if (serviceThreadID)
	{
#ifdef WIN32
		WaitForSingleObject(serviceThreadID, INFINITE);
		CloseHandle(serviceThreadID);
#else //WIN32
		pthread_join(serviceThreadID, NULL);
#endif //WIN32
	}
	serviceThreadID = 0;
#endif //NOTHREADS
}

void CRLSession::Initialize(ulong crlSessionID, const CRLDLLInitSettings_struct& settings)
{
	//
	// Initialize session settings
	//
	
	boundsFlag = settings.boundsFlag;
	cmlSessionID = settings.cmlSessionID;
	crlRefreshPeriod = settings.crlRefreshPeriod;
	crlGracePeriod = settings.crlGracePeriod;
	srlFuncs = settings.srlFuncs;

   // Create a temporary SRL session which will be used to store and
   // retrieve CRLs for the life of this session.
   std::stringstream sessionStr;
   sessionStr << crlSessionID;
   std::string certDBFile = "cert_" + sessionStr.str() + ".db";
   std::string crlDBFile = "crl_" + sessionStr.str() + ".db";

   SRL_InitSettings_struct srlSettings;
   srlSettings.LDAPinfo = NULL;
   srlSettings.CertFileName = (char *)certDBFile.c_str();
   srlSettings.CRLFileName = (char *)crlDBFile.c_str();
   srlSettings.crlRefreshPeriod = LONG_MAX;
   srlSettings.removeStaleCRL = FALSE;
      
   if (SRL_CreateSession(&m_localSRLSessionID, &srlSettings) != SRL_SUCCESS)
      throw CRL_INIT_ERROR;   

	// Initialize the global CRL header table	
	pCrlHeaderCache = new CRLHeaderCache(crlSessionID);
	if (pCrlHeaderCache == NULL)
		throw CRL_MEMORY_ERROR;

	// Initialize CRL Issuer List
	if (settings.crlList != NULL)
		CRL_InitCRLHeaderList(crlSessionID, settings.crlList);

#ifndef NOTHREADS
	// launch the thread that will keep this CRL Headers up-to-date otherwise
	// CRL's will be updated when they become out of date.
#if defined(WIN32)
	if ( (serviceThreadID = CreateThread(NULL, 0, CRLSession::ServiceThread,				
		this, 0, NULL)) == NULL )
#else
	if (pthread_create(&serviceThreadID, NULL, CRLSession::ServiceThread, this) != 0)
#endif //WIN32
	{
		//failed to create thread
		throw CRL_INIT_ERROR;
	}
#endif //NOTHREADS

} // end of Session::Initialize()

void CRLSession::EmptyCache()
{
	if (pCrlHeaderCache)
		pCrlHeaderCache->Empty();
}

//////////////////////////////////
// DBIdSet class implementation //
//////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
// Function:      Merge()
// Description:   Copy items from another set into this set.
// Inputs:        const DBIdSet& that - set to copy from
// Ouputs:        (none)
// Return value:  void
////////////////////////////////////////////////////////////////////////////////
void DBIdSet::Merge(const DBIdSet& that)
{
   DBIdSet::const_iterator iDBId;
   for (iDBId = that.begin(); iDBId != that.end(); ++iDBId)
      insert(*iDBId);
}


