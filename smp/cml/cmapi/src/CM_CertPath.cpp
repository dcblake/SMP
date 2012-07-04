/*****************************************************************************
File:     CM_CertPath.cpp
Project:  Certificate Management Library
Contents: Implementation of the Cert Path classes

Created:  20 March 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	27 Jan 2005

Version:  2.5

*****************************************************************************/


////////////////////
// Included Files //
////////////////////
#include "PathBuild.h"


// Using CML and CML::Internal namespaces
using namespace CML;
using namespace CML::Internal;

// Using the following CML::ASN names
using ASN::Bytes;
using ASN::BytesList;
using ASN::DN;
using ASN::GenNames;
using ASN::CertificationPath;
using ASN::CertPair;
using ASN::CertPoliciesExtension;


///////////////////////
// Defined Constants //
///////////////////////
const float kMIN_LOC_PROBABILITY = (float)0.50;
const float kMIN_PATH_PROB_VARIANCE = (float)0.10;


/////////////////////////
// Function Prototypes //
/////////////////////////
short ValidateCertPath(ulong sessionID, const BaseNodePtrDeck& curPath,
                       PrintXML& logXML, SearchBounds boundsFlag, 
                       StateVars& pathVars, ErrorInfoList* pErrors,
                       bool performRevChecking,
                       RevocationDataList* revDataList);

static float comparePolicySets(const ASN::Cert& subjCert,
							 const ASN::Cert& issuerCert);
static int compareAuthKeyID(const ASN::AuthKeyIdExtension& authKeyExt,
							const SNACC::AsnOcts* pSubjKeyID,
							const GenNames* pSubjAltNames,
							const DN& issuerName, const SNACC::AsnInt& serialNum);
static void parseForwardCerts(BytesList& encCertList,
							  const Bytes& asnPath);
static ulong parseForwardCertPair(BytesList& encCertList, uchar* buf,
								  ulong maxLen);
bool hasExcludedError(const ErrorInfoList& errorList);

void logErrors(const ErrorInfoList& errorList, const PrintXML& logXML);

///////////////////////////////////
// CertPath class implementation //
///////////////////////////////////
CertPath::CertPath()
{
	state = NULL;
	curPath = NULL;
	m_logXML = NULL;
}


CertPath::CertPath(const Certificate& subject) :
CertificationPath(subject.base()), encUserCert(subject.GetEnc())
{
	state = NULL;
	curPath = NULL;
	m_logXML = NULL;
}


CertPath::CertPath(const CertificationPath& certPath) :
CertificationPath(certPath)
{
	state = NULL;
	curPath = NULL;
	m_logXML = NULL;

	certPath.userCert.Encode(encUserCert);

	for (std::list<CertPair>::const_iterator i = caCerts.begin(); i !=
		caCerts.end(); i++)
	{
		if (i->forward == NULL)
			break;

		Bytes encCert;
		i->forward->Encode(encCert);
		encCACerts.push_back(encCert);
	}
}


CertPath::CertPath(const Bytes& asn, bool isCertPath)
{
	state = NULL;
	curPath = NULL;
	m_logXML = NULL;

	if (isCertPath)
		Decode(asn);
	else
	{
		userCert = asn;
		encUserCert = asn;
	}
}


CertPath::CertPath(const CertPath& other) : CertificationPath(other),
encUserCert(other.encUserCert), encCACerts(other.encCACerts)
{
	state = NULL;
	curPath = NULL;
	m_logXML = NULL;
}


CertPath::~CertPath()
{
	if (state != NULL)
	{
		delete state;
		state = NULL;
	}
	if (curPath != NULL)
	{
		delete curPath;
		curPath = NULL;
	}
	if (m_logXML != NULL)
	{
		delete m_logXML;
		m_logXML = NULL;
	}
}


CertPath& CertPath::operator=(const CertificationPath& certPath)
{
	if (state != NULL)
	{
		delete state;
		state = NULL;
	}
	if (curPath != NULL)
	{
		delete curPath;
		curPath = NULL;
	}
	if (m_logXML != NULL)
	{
		delete m_logXML;
		m_logXML = NULL;
	}

	encCACerts.clear();

	CertificationPath::operator=(certPath);
	certPath.userCert.Encode(encUserCert);

	for (std::list<CertPair>::const_iterator i = caCerts.begin(); i !=
		caCerts.end(); i++)
	{
		if (i->forward == NULL)
			break;

		Bytes encCert;
		i->forward->Encode(encCert);
		encCACerts.push_back(encCert);
	}

	return *this;
}


CertPath& CertPath::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


CertPath& CertPath::operator=(const CertPath& other)
{
	if (state != NULL)
	{
		delete state;
		state = NULL;
	}
	if (curPath != NULL)
	{
		delete curPath;
		curPath = NULL;
	}
	if (m_logXML != NULL)
	{
		delete m_logXML;
		m_logXML = NULL;
	}

	CertificationPath::operator=(other);
	encUserCert = other.encUserCert;
	encCACerts = other.encCACerts;
	return *this;
}

/////////////////////////////////////////////////////////////////////////////
// FUNCTION:  CertPath::Build()
// 
// Description: Build a Path
//
// Inputs: 
//    ulong         sessionID       - CML Session ID
//    SearchBounds  boundsFlag      - Search local, remote, both or until found
//	   float 	     minProb         - minimum probability to use when building path
//	   ASN::Time*    pValidationTime - Optional. Points to a date/time that 
//                                    must be used when checking revocation
//                                    status
//
// Outputs:
//    ErrorInfoList *pErrors        - List of errors found while validatin
//
// Return Value: 
//	   short status                  - status of path building
//
/////////////////////////////////////////////////////////////////////////////////
short CertPath::Build(ulong sessionID, SearchBounds boundsFlag, float minProb,
					  ErrorInfoList* pErrors, const ASN::Time* pValidationTime)
{
	if (state != NULL)
	{
		delete state;
		state = NULL;
	}

	if (curPath != NULL)
	{
		delete curPath;
		curPath = NULL;
	}

	InitLogSettings(sessionID);
	state = new PathState(sessionID, boundsFlag, encUserCert, 
						  encCACerts, *m_logXML, pValidationTime);
	curPath = new PathStack;

	if (state == NULL)
		throw CML_MEMORY_ERR;

	return BuildNext(minProb, pErrors);
}


short CertPath::BuildNext(float minProb, ErrorInfoList* pErrors)
{
	if (state == NULL)
		throw CML_ERR(CM_INVALID_PARAMETER);
	if (m_logXML == NULL)
		throw CML_ERR(CM_NULL_POINTER);

	try {
		// Check that the minProb is in the correct range
		if ((minProb < 0) || (minProb > 1))
			throw CML_ERR(CM_INVALID_PARAMETER);

	    m_logXML->WriteBegin(CM_LOG_LEVEL_1, "PathBuild", 2,
			"Building path for", userCert.subject, 
			"serialNum =", &userCert.serialNumber);

		// Use the path state to build the next path
		short err = state->BuildNext(*curPath, minProb, pErrors);

	    m_logXML->WriteEnd(CM_LOG_LEVEL_1, "PathBuild", 2);
		if (err != CM_NO_ERROR)
			return err;

		// Set the cert path from the path state results
		SetPathFromState();
		return CM_NO_ERROR;
	}
	catch (...) {
		if (state != NULL)
		{
			delete state;
			state = NULL;
		}
		if (curPath != NULL)
		{
			delete curPath;
			curPath = NULL;
		}
	    m_logXML->WriteEnd(CM_LOG_LEVEL_1, "PathBuild", 2);
		throw;
	}
}

////////////////////////////////////////////////////////////////////////////////
// FUNCTION:  CertPath::BuildAndValidate()
// 
// Description: Build and Validate a certificate
//
// Inputs: 
//    ulong         sessionID       - CML Session ID
//    SearchBounds  boundsFlag      - Search local, remote, both or until found
//	   float	        minProb         - Min Probability of acceptable paths
//	   bool	        performRevChecking - If true, perform revocation checking
//	   ASN::Time*    pValidationTime -  Optional. Points to a date/time that 
//                                     must be used when checking revocation
//                                     status
//                                    
// Outputs:
//    ErrorInfoList *pErrors        -  List of errors found while validating
//	   ValidatedKey* pValidKey       -  To be filled in with validation info
//
// Return Value: 
//	   short result - result of Validation checking
//
//////////////////////////////////////////////////////////////////////////////
short CertPath::BuildAndValidate(ulong sessionID, SearchBounds boundsFlag,
								 ErrorInfoList* pErrors, float minProb,
								 ValidatedKey* pValidKey,
								 const ASN::Time* pValidationTime, 
                         bool performRevChecking)
{
	try {
		// Get the maximum number of paths to build
		ushort maxPaths = GetMaxPaths(sessionID);

		// Clear the path validation error list if present
		if (pErrors != NULL)
			pErrors->clear();

		// Initialize the log settings
		InitLogSettings(sessionID);
		const char* pBuildAndValidateString = "Build and Validate";
		if (performRevChecking == false)
		{
			pBuildAndValidateString =
				"Build and Validate (Revocation checking disabled)";
		}

		// Initialize the path count and error results
		ushort nPaths = 0;
		bool resultsSaved = false;
		bool overwritePathAndErrors = false;
		ErrorInfoList tempErrors;
		short buildErr, valErr = CM_NO_PATH_FOUND;
		do
		{
			// Write the BuildandValidate tag to the log file
			m_logXML->WriteBegin(CM_LOG_LEVEL_1, "BuildAndValidate", 1,
				pBuildAndValidateString, "", "serialNum=",
				&userCert.serialNumber);

			// Save the current clock
			clock_t start = clock();

			// Build the path
			if (nPaths == 0)
				buildErr = Build(sessionID, boundsFlag, minProb, pErrors,
				                 pValidationTime);
			else
				buildErr = BuildNext(minProb);

			// If path successfully built, validate it
			if (buildErr == CM_NO_ERROR)
			{
				++nPaths;

				if (! tempErrors.empty())
					tempErrors.clear();

				valErr = Validate(&tempErrors, pValidKey, performRevChecking);			

				if (valErr != CM_NO_ERROR)
				{
					// If a path validation error occurred, and we do not have results from a 
					// previous iteration save the results
					if (!resultsSaved || overwritePathAndErrors)
					{
						overwritePathAndErrors = hasExcludedError(tempErrors);
						// If this path has an excluded error and a path was 
						// already saved do not overwrite it
						if (!resultsSaved || (resultsSaved && !overwritePathAndErrors))
						{
							resultsSaved = state->SaveResults(*curPath, pValidKey);
							if (pErrors != NULL)
								*pErrors = tempErrors;
						}
					}
				}			
			}
			clock_t finish = clock();
			m_logXML->WriteInfo(CM_LOG_LEVEL_1, "BuildAndValidateElapsedTime", 
				((float)(finish - start) / CLOCKS_PER_SEC));				
			
			m_logXML->WriteEnd(CM_LOG_LEVEL_1, "BuildAndValidate", 1);
			
		} while ((nPaths < maxPaths) && (buildErr == CM_NO_ERROR) &&
			(valErr != CM_NO_ERROR) && (valErr != CMI_CACHED_PATH_VALIDATION_ERROR));
		
#if defined(WIN32) && defined(_DEBUG)
		if ((IsDebuggerPresent() == TRUE) && (nPaths > 1))
		{
			char debugStr[256];
			sprintf(debugStr, " %d paths built for %s\n", nPaths,
				(const char*)userCert.subject);
			OutputDebugString(debugStr);
		}
#endif
		// If an error occurred, restore the results from the first path
		// validation
		if (valErr != CM_NO_ERROR)
		{
			// Restore the results from the first path validation, if saved
			state->RestoreResults(*curPath, pValidKey, resultsSaved);

			// If a build error occurred, set the error result
			if (valErr == CM_NO_PATH_FOUND)
				valErr = buildErr;
			else
				// Set the cert path from the path state results
				SetPathFromState();
		}
		else if (pErrors != NULL)	// no error occurred, so clear the first errors
			pErrors->clear();

		// Reset the err code when an invalid cached path was returned
		if (valErr == CMI_CACHED_PATH_VALIDATION_ERROR)
			valErr = CM_PATH_VALIDATION_ERROR;

		return valErr;
	}
	catch (...)
	{
		if (state != NULL)
		{
			delete state;
			state = NULL;
		}
		if (curPath != NULL)
		{
			delete curPath;
			curPath = NULL;
		}
		throw;
	}
}


ulong CertPath::Decode(const Bytes& asn)
{
	if (state != NULL)
	{
		delete state;
		state = NULL;
	}
	if (curPath != NULL)
	{
		delete curPath;
		curPath = NULL;
	}
	if (m_logXML != NULL)
	{
		delete m_logXML;
		m_logXML = NULL;
	}

	ulong numDec = CertificationPath::Decode(asn);

	parseForwardCerts(encCACerts, asn);
	encUserCert = encCACerts.front();
	encCACerts.pop_front();

	return numDec;
}


ulong CertPath::Encode(Bytes& asn) const
{
	return CertificationPath::Encode(asn);
}

void CertPath::InitLogSettings(ulong sessionID)
{
	if (m_logXML != NULL)
		return;

	// Acquire global session lock
	ASN::ReadLock lock = CML::Internal::AcquireSessionReadLock(sessionID);
	
	CMLogLevel level = GetLogLevel(sessionID);
	char *filename = GetNextLogFile(sessionID, level);

	m_logXML = new PrintXML(filename, level);
	if (m_logXML == NULL)
		throw CML_MEMORY_ERR;

	if (filename)
		free (filename);

}

short CertPath::Validate(ErrorInfoList* pErrors,
						 ValidatedKey* pValidKey,
						 bool performRevChecking) const
{
	// Check that the path has been built
	if (state == NULL)
		throw CML_ERR(CM_INVALID_PARAMETER);
	if (m_logXML == NULL)
		throw CML_ERR(CM_NULL_POINTER);

	// Reset the path validation errors and validated public key information
	if (pErrors != NULL)
		pErrors->clear();
	if (pValidKey != NULL)
		pValidKey->Clear();

	if (performRevChecking)
		m_logXML->WriteBegin(CM_LOG_LEVEL_1, "PathValidate", 2, "Validate Path");
	else
		m_logXML->WriteBegin(CM_LOG_LEVEL_1, "PathValidate", 2, "Validate Path  (Revocation checking disabled)");
	try {
		clock_t start = clock();

		// Validate the path
		short err = state->ValidatePath(*curPath, pErrors, pValidKey,
			performRevChecking);
			
		clock_t finish = clock();
		m_logXML->WriteInfo(CM_LOG_LEVEL_1, "ValidateElapsedTime", 
			((float)(finish - start) / CLOCKS_PER_SEC));				

		m_logXML->WriteEnd(CM_LOG_LEVEL_1, "PathValidate", 2);

		if (err == CM_NO_ERROR)
			m_logXML->WriteData(CM_LOG_LEVEL_1, "SUCCESS --- Path Validation Succeeded!");
		else
		{
			m_logXML->WriteData(CM_LOG_LEVEL_1, "FAILURE --- Path Validation Failed!");
			if (pErrors != NULL)
				logErrors(*pErrors, *m_logXML);	
		}
		return err;
	}
	catch (...) {
		if (pErrors != NULL)
			pErrors->clear();
		if (pValidKey != NULL)
			pValidKey->Clear();
		m_logXML->WriteEnd(CM_LOG_LEVEL_1, "PathValidate", 2);
		throw;
	}
}


void CertPath::SetPathFromState(void)
{
	try {
		// Retrieve the list of certs in the path from the state (ordered from
		// subject to trust anchor)
		CertPtrList path;
		curPath->GetForwardPath(state->GetCurrentIssuer(), path);

		// Remove the encoded and decoded CA certs in the existing path
		caCerts.clear();
		encCACerts.clear();

		// Copy the encoded and decoded subject and issuer certs
		for (CertPtrList::const_iterator i = path.begin(); i != path.end(); i++)
		{
			if (*i == NULL)
				throw CML_ERR(CM_NULL_POINTER);
				
			if (i == path.begin())	// First cert is the subject cert
			{
				encUserCert = (*i)->GetEnc();
				userCert = (*i)->base();
			}
			else
			{
				encCACerts.push_back((*i)->GetEnc());
				caCerts.push_back(CertPair(&(*i)->base(), NULL));
			}
		}
	}
	catch (...) {
		if (state != NULL)
		{
			delete state;
			state = NULL;
		}
		caCerts.clear();
		encCACerts.clear();
		throw;
	}
}


////////////////////////////////////
// PathState class implementation //
////////////////////////////////////

PathState::PathState(
    ulong sessionID,			     // CML Session ID
	 SearchBounds boundsFlag,    // Search local,remote, both or until found
    const Bytes& userCert,      // User certificate
	 const BytesList& caCerts,   // CA certificates
	 PrintXML& logXML,           // Used when saving info to log file
	 const ASN::Time* pValidationTime) : // Opt time to use for validation
m_sessionID(sessionID), m_searchFlag(boundsFlag), 
m_certPool(sessionID, boundsFlag, pValidationTime), m_logXML(logXML)
{
	// Initialize the current location
	m_curLoc = Location::Application;

	// Load the ASN.1 encoded certs into the CertPool
	m_pSubj.push_back(m_certPool.Add(userCert, caCerts));
}


short PathState::BuildNext(PathStack& curPath, float minProb, ErrorInfoList* pErrors)
{
	short result;
	
	m_logXML.WriteData(CM_LOG_LEVEL_2, "Current Location:", (const char *)m_curLoc);
	clock_t start = clock();

	do
	{
		// Read Locking cert cache for call to IsDNTrusted(). Add a RefClass to contain
		// Trusted certs later.
		ASN::ReadLock sessionLock = AcquireSessionReadLock(m_sessionID);
		ASN::ReadLock certCacheLock = GetCertCache(m_sessionID).AcquireReadLock();
		sessionLock.Release();

		// clear the current path for this new build
		curPath.Clear();

		// Build the next path
		result = GetCurrentIssuer()->BuildNextPath(m_certPool, m_curLoc, curPath, m_logXML, minProb);
		certCacheLock.Release();

		if (result == CM_NO_PATH_FOUND)
		{
			// Update the current location
			if (!m_curLoc.UpdateLoc(Location::X500_DSA, m_searchFlag))
			{
				if (pErrors != NULL)
				{
					m_logXML.WriteSimpleBegin(CM_LOG_LEVEL_1, "DetermineError");
					GetCurrentIssuer()->DetermineError(*pErrors, curPath, m_logXML, minProb);
					m_logXML.WriteEnd(CM_LOG_LEVEL_1, "DetermineError");
				}

				clock_t finish = clock();
				m_logXML.WriteInfo(CM_LOG_LEVEL_1, "BuildElapsedTime", 
					((float)(finish - start) / CLOCKS_PER_SEC));				
				m_logXML.WriteData(CM_LOG_LEVEL_1, "FAILURE --- No path built!");
				return CM_NO_PATH_FOUND;
			}
	        m_logXML.WriteData(CM_LOG_LEVEL_2, "Location switched to:", (const char *)m_curLoc);
		}
	} while (result == CM_NO_PATH_FOUND);

	clock_t finish = clock();
	m_logXML.WriteInfo(CM_LOG_LEVEL_1, "BuildElapsedTime", 
		((float)(finish - start) / CLOCKS_PER_SEC));				

	if (result == CMI_CERT_HAS_ERRORS)
	{
		result = CM_NO_PATH_FOUND;
		m_logXML.WriteData(CM_LOG_LEVEL_1, "FAILURE --- No path built!");
	}

	if (result == CM_NO_ERROR) {
		m_logXML.WriteData(CM_LOG_LEVEL_1, "SUCCESS --- Path built!");
	}
	return result;
} // end of PathState::BuildNext()


void PathState::RestoreResults(PathStack& curPath, ValidatedKey* pValidKey, bool pathWasSaved)
{
	// Clear the validated key
	if (pValidKey != NULL)
		pValidKey->Clear();

	try {
		// Reset the path if successfully built
		if (pathWasSaved)
		{
			// Save the path before popping the EE
			curPath = m_firstPath;
			if (GetCurrentIssuer() != m_firstPath.PopBottom())
				throw CML_ERR(CM_UNKNOWN_ERROR);
			m_firstPath.Clear();
		}
		
		// if necessary, copy the public key and parameters
		if (pValidKey != NULL)
		{
			pValidKey->m_pubKeyInfo = GetCurrentIssuer()->GetCert().base().pubKeyInfo;
			if (pValidKey->m_pubKeyInfo.algorithm.parameters == NULL)
			{
				pValidKey->m_pubKeyInfo.algorithm.parameters =
					m_firstResults.pParams;
			}
			else if (m_firstResults.pParams != NULL)
				delete m_firstResults.pParams;
			
			m_firstResults.pParams = NULL;
			
			// Copy the saved path results, if a path was built
			if (pathWasSaved)
			{
				pValidKey->authPolicies = m_firstResults.authPolicies;
				pValidKey->userPolicies = m_firstResults.userPolicies;
				pValidKey->mappings = m_firstResults.mappings;
				pValidKey->explicitPolicyFlag = m_firstResults.explicitPolicyFlag;
			}
			
			// Copy the Key Usage Extension, if present
			if (GetCurrentIssuer()->GetCert().base().exts.pKeyUsage != NULL)
			{
				pValidKey->pKeyUsage = new ASN::KeyUsageExtension(
					*GetCurrentIssuer()->GetCert().base().exts.pKeyUsage);
				if (pValidKey->pKeyUsage == NULL)
					throw CML_MEMORY_ERR;
			}
			
			// Copy the Extended Key Usage Extension, if present
			if (GetCurrentIssuer()->GetCert().base().exts.pExtKeyUsage != NULL)
			{
				pValidKey->pExtKeyUsage = new ASN::ExtKeyUsageExtension(
					*GetCurrentIssuer()->GetCert().base().exts.pExtKeyUsage);
				if (pValidKey->pExtKeyUsage == NULL)
					throw CML_MEMORY_ERR;
			}
         // Copy the OCSP/CRL responses if wantBack was requested in session
         if (GetWantBackStatus(m_sessionID) == true)
         {	    
            pValidKey->m_revDataList = m_firstResults.m_revDataList;
         }
		}
	}
	catch (...) {
		if (pValidKey != NULL)
			pValidKey->Clear();
		throw;
	}
} // end of PathState::RestoreResults()


bool PathState::SaveResults(PathStack& curPath, const ValidatedKey* pValidKey)
{
	// Delete the previous path and parameters
	m_firstPath.Clear();
	delete m_firstResults.pParams;
	m_firstResults.pParams = NULL;
   m_firstResults.m_revDataList.Clear();

	// Copy the path results
	if (pValidKey != NULL)
	{
		m_firstResults.authPolicies = pValidKey->authPolicies;
		m_firstResults.userPolicies = pValidKey->userPolicies;
		m_firstResults.mappings = pValidKey->mappings;
		m_firstResults.explicitPolicyFlag = pValidKey->explicitPolicyFlag;
		
		// Copy the public key parameters if present
		if (pValidKey->m_pubKeyInfo.algorithm.parameters != NULL)
		{
			m_firstResults.pParams = new
				ASN::Bytes(*pValidKey->m_pubKeyInfo.algorithm.parameters);
			if (m_firstResults.pParams == NULL)
				throw CML_MEMORY_ERR;
		}
		// Copy the OCSP/CRL responses if wantBack was requested in session
		if (GetWantBackStatus(m_sessionID) == true)
		{	    
         m_firstResults.m_revDataList = pValidKey->m_revDataList;
		}
	}

	m_firstPath = curPath;

	return true;
} // end of PathState::SaveResults()


short PathState::ValidatePath(PathStack& curPath, ErrorInfoList* pErrors,
							  ValidatedKey* pValidKey,
							  bool performRevChecking) const

{
   bool timeStampFlag = false;

	if (GetCurrentIssuer() == NULL)
		throw CML_ERR(CM_NULL_POINTER);

	const ASN::Cert& subjCert = GetCurrentIssuer()->GetCert().base(); 
	if (m_certPool.m_pValidationTime != NULL) 
		 timeStampFlag = subjCert.validity.IsValid(*m_certPool.m_pValidationTime);

   // Check the cache for the subject certificate as long as CRLs/OCSP
   // responses are not requested.
   if (GetWantBackStatus(m_sessionID) == false) 
	{
	   // Check if the subject cert is in the cache
	   if (!timeStampFlag && GetCurrentIssuer()->IsCached())
	   {
		   const CachedCertNode* pCachedSubj = (const CachedCertNode*)GetCurrentIssuer();
		   // Read lock the cert
		   ASN::ReadLock lock = pCachedSubj->m_cachedCert.m_internalMutex.AcquireReadLock();
		   const bool certLockNeeded = false;

 		   ErrorInfoList certErrors;
		   ErrorInfoList pathErrors;
		   bool hasCertErrors = pCachedSubj->HasCertErrors(&certErrors, 
                                                         certLockNeeded);
		   bool hasPathErrors = pCachedSubj->HasPathErrors(&pathErrors, 
                                                         certLockNeeded);
		   // Check for errors
         if (hasCertErrors || hasPathErrors)
         {
            // Since errors are present, only use the cached certficate when 
            // the revocation checking override flag is enabled. Failing
            // to do so may result in a valid path not being found when
            // CRL issuer paths are being validated by the CRL library.
            if (performRevChecking == true)
            {
               // Export the path results from the cache if requested
               if (pValidKey != NULL)
               {
                  pCachedSubj->m_cachedCert.ExportPathResults(*pValidKey, certLockNeeded);
               }
               
               // If the cert has errors, then return the errors if requested
               if (pErrors != NULL)
               {
                  pErrors->Splice(pErrors->end(), certErrors);
                  pErrors->Splice(pErrors->end(), pathErrors);
               }
               
               return CMI_CACHED_PATH_VALIDATION_ERROR;
            }
         }
         // Otherwise return a valid status
		   else
         {
            // Export the path results from the cache if requested
            if (pValidKey != NULL)
            {
               pCachedSubj->m_cachedCert.ExportPathResults(*pValidKey, certLockNeeded);
            }

			   return CM_NO_ERROR;
		   }
	   }
	}

	// Initialize the X.509 path variables
	StateVars pathVars(m_sessionID, const_cast<PathState&>(*this),
		curPath.Size(), m_certPool.m_pValidationTime);

   // If revocation data was requested and the ValidatedKey is present, 
   // pass the address of the revocation data list found in the ValidatedKey
   // to ValidateCertPath().
   RevocationDataList* pRevDataList = NULL;
   if ((GetWantBackStatus(m_sessionID) == true) && (pValidKey != NULL))
      pRevDataList = &pValidKey->m_revDataList;

	// Validate each certificate in the path
	short errCode = ValidateCertPath(m_sessionID, curPath.Deck(), m_logXML,
                                    m_searchFlag, pathVars, pErrors,
                                    performRevChecking, pRevDataList);

	// Reset the error code if the certificate wasn't cached
	if (errCode == CMI_VALID_CERT_NOT_CACHED)
		errCode = CM_NO_ERROR;
	else if (errCode == CMI_INVALID_CERT_NOT_CACHED)
		errCode = CM_PATH_VALIDATION_ERROR;

	// Fill in the path processing outputs, if requested
	if (pValidKey != NULL)
	{
		const ASN::Cert& subjCert = GetCurrentIssuer()->GetCert().base();

		// Copy the public key
		pValidKey->m_pubKeyInfo = subjCert.pubKeyInfo;

		// If the public key parameters were inherited, copy the
		// inherited parameters
		if ((pValidKey->m_pubKeyInfo.algorithm.parameters == NULL) &&
			(pathVars.pParams != NULL))
		{
			pValidKey->m_pubKeyInfo.algorithm.parameters =
				new ASN::Bytes(*pathVars.pParams);
			if (pValidKey->m_pubKeyInfo.algorithm.parameters == NULL)
				throw CML_MEMORY_ERR;
		}

		// Get the authority-constrained-policy-set
		pathVars.authTable.GetAuthPolicySet(pValidKey->authPolicies);
		
		// Acquire global session lock
		ASN::ReadLock lock = CML::Internal::AcquireSessionReadLock(m_sessionID);

		// Calculate the user-acceptable-policy-set
		pValidKey->userPolicies = pValidKey->authPolicies &
			GetInitialPolicySet(m_sessionID);

		lock.Release();
		
		// Copy the policy mapping details
		pValidKey->mappings = pathVars.mappings;
		
		// Set the explicit-policy-indicator
		pValidKey->explicitPolicyFlag = pathVars.explicitPolicy;

		// Copy the key usage extension
		if (subjCert.exts.pKeyUsage != NULL)
		{
			pValidKey->pKeyUsage = new
				ASN::KeyUsageExtension(*subjCert.exts.pKeyUsage);
			if (pValidKey->pKeyUsage == NULL)
				throw CML_MEMORY_ERR;
		}

		// Copy the extended key usage extension
		if (subjCert.exts.pExtKeyUsage != NULL)
		{
			pValidKey->pExtKeyUsage = new
				ASN::ExtKeyUsageExtension(*subjCert.exts.pExtKeyUsage);
			if (pValidKey->pExtKeyUsage == NULL)
				return CML_MEMORY_ERR;
		}
	}

	return errCode;
} // end of PathState::ValidatePath()

bool PathState::PushIssuer(const ASN::Bytes& userCert)
{
	// Add this cert to the node pool.
	BaseNode* pnode = m_certPool.Add(userCert, ASN::BytesList());
	//Push this issuer onto the stack only if it is not already on the stack.
	std::deque<BaseNode*>::const_iterator iCert;
	for (iCert = m_pSubj.begin(); iCert != m_pSubj.end(); iCert++)
	{
		if (*iCert == pnode)
			//issuer already on stack
			return false;
	}
	m_pSubj.push_back(pnode);
	return true;
}



///////////////////////////////////
// NodePool class implementation //
///////////////////////////////////
NodePool::NodePool(
   ulong sessionID,               // CML Session ID
   SearchBounds boundsFlag,       // Search local,remote,both or until found 
   const ASN::Time* pValidationTime) :  // Optional time to use for validation
m_searchLocs(boundsFlag), m_hSession(sessionID), m_pValidationTime(pValidationTime) 
{
}


NodePool::~NodePool()
{
	BaseNodeDN_Map::iterator iPool;
	for (iPool = m_pool.begin(); iPool != m_pool.end(); ++iPool)
	{
		if (iPool->second != NULL) {
			delete iPool->second;
			iPool->second = NULL;
		}
	}
}

BaseNode* NodePool::Add(const Bytes& subject, const BytesList& issuers)
{
	BaseNode* pSubjNode = FindInPool(subject);
	if (pSubjNode == NULL)
	{
		// Construct the subject BaseNode and add it to the pool
		pSubjNode = BaseNode::Construct(m_hSession, subject);
		// If the time stamp time was set, verify that time stamp
		// time falls within the cert's validity period.  If not,
		// don't insert into the pool.
	   if (m_pValidationTime != NULL)
		{
	      const ASN::Cert& byteCert = pSubjNode->GetCert().base(); 
		   if (byteCert.validity.IsValid(*m_pValidationTime))
			   InsertInPool(pSubjNode);
		}
		else
         InsertInPool(pSubjNode);
	}

	// Process each of the certs in the issuers list
	BaseNode* pPrevNode = pSubjNode;
	for (BytesList::const_iterator i = issuers.begin(); i != issuers.end(); ++i)
	{
		// Create a new BaseNode for this issuer certificate
		BaseNode* pNewNode = BaseNode::Construct(m_hSession, *i);
		// If the time stamp time exists, check to see if it falls
		// within the certificate's validity period.  If not,
		// do not find or add to the pool.
      if ((m_pValidationTime == NULL) || 
           pNewNode->GetCert().base().validity.IsValid(*m_pValidationTime))
		{
		   // Add the new BaseNode to the pool (if not already present)
		   BaseNode* pExistingNode =
			   FindInPool(pNewNode->GetCert().base().subject, *i);
		   if (pExistingNode != NULL)
		   {
			   // Delete this existing cert
			   delete pNewNode;

			   // Set the node pointer to the existing node
			   pNewNode = pExistingNode;
		   }
		   else
			   InsertInPool(pNewNode);

		   // Add this new node as the previous node's issuer
		   pPrevNode->AddIssuer(pNewNode);
		   pPrevNode = pNewNode;
		}
	}
		
	return pSubjNode;
} // end of NodePool::Add()


BaseNode* NodePool::Add(const CachedCert& cachedCert)
{
	// If the cert is already in the path pool, just return it
	BaseNode* pNode = FindInPool(cachedCert.base().subject,
		cachedCert.GetEncCert());
	if (pNode != NULL)
		return pNode;

	// Create a new CachedCertNode or TrustedCertNode for this certificate
	// or cross certificate
	CachedCertNode* pNewNode;
	if (cachedCert.IsTrusted())
		pNewNode = new TrustedCertNode(m_hSession, cachedCert);
	else
		pNewNode = new CachedCertNode(m_hSession, cachedCert);
	if (pNewNode == NULL)
		throw CML_MEMORY_ERR;

	// Add the new CachedCertNode to the pool and return it
	InsertInPool(pNewNode);
	return pNewNode;
} // end of NodePool::Add()


BaseNodePtrList* NodePool::GetCerts(const DN& dn, Location& lastLoc,
									const Location& curLoc,
									const ASN::PkixAIAExtension* pAIA,
									PrintXML& logXML)
{
	// Loop through the locations from the last location up to and including
	// the current location
	BaseNodePtrList* pCertsFound = NULL;
	do
	{
		// Update the last location, return NULL if it can't be updated
		if (!lastLoc.UpdateLoc(curLoc, m_searchLocs))
			return NULL;

		logXML.WriteData(CM_LOG_LEVEL_4, "Searching location:", (const char *)lastLoc);

		// Search the location specified in lastLoc
		if (lastLoc == Location::Cache)
		{
			// Acquire global session lock
			ASN::ReadLock lock = AcquireSessionReadLock(m_hSession);

			// Get the cert cache from the session ID
			CertCache& certCache = GetCertCache(m_hSession);

			// Search the cache for all certs and add any certs found to the pool
			const CachedCertList* pCertList = certCache.Find(dn, true, false);
			if (pCertList != NULL)
			{
				try {
					pCertsFound = Add(*pCertList);
					delete pCertList;
				}
				catch (...) {
					delete pCertList;
					throw;
				}
			}
		}
		else if (lastLoc != Location::Application)
		{
			// Search using the AIA extension if it is present
			if (pAIA != NULL) 
			{
				ASN::PkixAIAExtension::const_iterator i = pAIA->begin();
				for ( ; (i != pAIA->end()) && (pCertsFound == NULL); i++)
				{
					// If the Acces Description contains CA issuer info in the
					// form of a URL, try to retrieve the certs from that URL
					if ((i->method == gAD_CA_ISSUERS_OID) &&
						(i->location.GetType() == ASN::GenName::URL))
					{
						// Acquire global session lock
						ASN::ReadLock lock = AcquireSessionReadLock(m_hSession);

						// Find the issuer certs and add them to the pool
						pCertsFound = Find(GetCallbacksFromRef(m_hSession),
							i->location.GetName().name, lastLoc);
					}
				}
			}

			// If nothing has been found, search using the DN and location
			if (pCertsFound == NULL)
			{
				// Acquire global session lock
				ASN::ReadLock lock = AcquireSessionReadLock(m_hSession);

				pCertsFound = Find(GetCallbacksFromRef(m_hSession), dn,
					lastLoc);
			}
		}
	}
	while ((pCertsFound == NULL) && (lastLoc != curLoc));

	return pCertsFound;
} // end of NodePool::GetCerts()


BaseNodePtrList* NodePool::Add(const EncObject_LL* pObjList)
{
	// Add the certificate objects found to the cache
	BaseNodePtrList tempList;
	EncCertPair_LL* pCrossCertPair = NULL;
	try {
		while (pObjList != NULL)
		{
			BaseNode* pNewNode = NULL;

			// If the cert object is a cross certificate, pull out the
			// forward element (if present)
			if (pObjList->typeMask == CROSS_CERT_TYPE)
			{
				ulong numDec;
				if ((CMASN_ParseCertPair(&pObjList->encObj, &numDec,
					&pCrossCertPair) != CMLASN_SUCCESS) ||
					(pCrossCertPair->forward.data == NULL))
				{
					CMASN_FreeCertPairList(&pCrossCertPair);
					pObjList = pObjList->next;
					continue;
				}

				pNewNode = FindInPool(pCrossCertPair->forward);
			}
			else
				pNewNode = FindInPool(pObjList->encObj);

			// If the cert is already present in the pool, 
			// add the existing BaseNode to the BaseNodePtrList 
			if (pNewNode != NULL)
			{
				// If the Time Stamp Time was set, add to BaseNodePtrList
				// if the Time Stamp Time falls within the cert's
				// validity period
			   if (m_pValidationTime != NULL)
				{
	            const ASN::Cert& subjCert = pNewNode->GetCert().base(); 
		         if (subjCert.validity.IsValid(*m_pValidationTime))
				      tempList.push_back(pNewNode);
				}
				else
				   tempList.push_back(pNewNode);
			}
			else
			{
				// Create a new BaseNode for this certificate or cross cert
				try {
					if (pCrossCertPair)
					{
						pNewNode = BaseNode::Construct(m_hSession,
							pCrossCertPair->forward);
					}
					else
					{
						pNewNode = BaseNode::Construct(m_hSession,
							pObjList->encObj);
					}
				}
				catch (...) {
					pNewNode = NULL;
				}

				if (pNewNode != NULL)
				{
			      // Add the new BaseNode to both the pool and the
					// BaseNodePtrList
				   // If the Time Stamp Time was set, add to pool 
					// and BaseNodePtrList if the time stamp time
				   // falls within the cert's validity period.
			      if (m_pValidationTime != NULL)
				   {
	                const ASN::Cert& subjCert = pNewNode->GetCert().base(); 
		             if (subjCert.validity.IsValid(*m_pValidationTime))
					    {
					       InsertInPool(pNewNode);
					       tempList.push_back(pNewNode);
					    }
				   }
					else
					{
					   InsertInPool(pNewNode);
					   tempList.push_back(pNewNode);
					}
				}
			}

			// Free the cross cert, if present
			if (pCrossCertPair)
				CMASN_FreeCertPairList(&pCrossCertPair);

			// Move to next cert object in the list
			pObjList = pObjList->next;
		}
	}
	catch (...) {
		if (pCrossCertPair)
			CMASN_FreeCertPairList(&pCrossCertPair);
		throw;
	}

	if (!tempList.empty())
	{
		// If any certs were added, create a new BaseNodePtrList to return to
		// the caller
		BaseNodePtrList* pList = new BaseNodePtrList();
		if (pList == NULL)
			throw CML_MEMORY_ERR;

		// Splice the added certs into the new list and return
		pList->splice(pList->end(), tempList);
		return pList;
	}
	else
		return NULL;
} // end of NodePool::Add()


BaseNodePtrList* NodePool::Add(const CachedCertList& cacheCertList)
{
	BaseNodePtrList* pList = NULL;
	try {
		// Create a new BaseNodePtrList
		pList = new BaseNodePtrList();
		if (pList == NULL)
			throw CML_MEMORY_ERR;

		// For each cached cert in the list...
		CachedCertList::const_iterator iCachedCert;
		for (iCachedCert = cacheCertList.begin(); iCachedCert != 
			cacheCertList.end(); ++iCachedCert)
		{
			// If the cert is already present in the path pool, just add the
			// existing BaseNode to the BaseNodePtrList
			BaseNode* pExistingNode = FindInPool(
				iCachedCert->GetRef().base().subject,
				iCachedCert->GetRef().GetEncCert());
			if (pExistingNode != NULL)
				pList->push_back(pExistingNode);
			else
			{
				// Create a new CachedCertNode or TrustedCertNode for this
				// certificate or cross cert
				CachedCertNode* pNewNode;
				if (iCachedCert->GetRef().IsTrusted())
					pNewNode = new TrustedCertNode(m_hSession, *iCachedCert);
				else
					pNewNode = new CachedCertNode(m_hSession, *iCachedCert);
				if (pNewNode != NULL)
				{
					// Add the new CachedCertNode to both the pool and the
					// BaseNodePtrList
					InsertInPool(pNewNode);
					pList->push_back(pNewNode);
				}
			}
		}

		return pList;
	}
	catch (...) {
		delete pList;
		throw;
	}
} // end of NodePool::Add()


BaseNodePtrList* NodePool::Find(const CallbackFunctions& funcs, const DN& dn,
								const Location& searchLoc)
{
	// Insert this DN and search location into the map of previous searches
	std::pair<DNLocationMap::iterator, bool> dnMapPair =
		m_prevSearches.insert(DNLocationMap::value_type(dn, searchLoc));
	if (dnMapPair.second == false)
	{
		// Since this DN is already present, check if this location has already
		// been searched
		if ((int)dnMapPair.first->second < (int)searchLoc)
		{
			// If not, just update the location from the previous search
			dnMapPair.first->second = searchLoc;
		}
		else // use the previous search results from the pool
		{
			BaseNodePtrList* pList = NULL;
			try {
				// Create a new BaseNodePtrList
				BaseNodePtrList* pList = new BaseNodePtrList();
				if (pList == NULL)
					throw CML_MEMORY_ERR;
				
				// Pull the results from the pool
				std::pair<BaseNodeDN_Map::iterator, BaseNodeDN_Map::iterator>
					itPair = m_pool.equal_range(dn);
				BaseNodeDN_Map::iterator i;
				for (i = itPair.first; i != itPair.second; ++i)
					pList->push_back(i->second);

				return pList;
			}
			catch (...) {
				delete pList;
			}
		}
	}

	// Request all cert types from the retrieval callback function
	EncObject_LL* pObjList = NULL;
	funcs.pGetObj(funcs.extHandle, (char*)(const char*)dn, CA_CERT_TYPE |
		CROSS_CERT_TYPE, searchLoc, &pObjList);
	if (pObjList == NULL)
		return NULL;

	// Add the certs to the pool and return the list
	try {
		BaseNodePtrList* pList = Add(pObjList);
		funcs.pFreeObj(funcs.extHandle, &pObjList);
		return pList;
	}
	catch (...) {
		funcs.pFreeObj(funcs.extHandle, &pObjList);
		return NULL;
	}
} // end of NodePool::Find()


BaseNodePtrList* NodePool::Find(const CallbackFunctions& funcs, char* url, const Location& searchLoc)
{
	// Check the parameters
	if ((url == NULL) || (funcs.pUrlGetObj == NULL))
		return NULL;

	// Request all CA certificates from the URL retrieval callback function
	EncObject_LL* pObjList = NULL;
	funcs.pUrlGetObj(funcs.extHandle, url, CA_CERT_TYPE, searchLoc, &pObjList);
	if (pObjList == NULL)
		return NULL;

	// Add the certs to the pool and return the list
	try {
		BaseNodePtrList* pList = Add(pObjList);
		funcs.pFreeObj(funcs.extHandle, &pObjList);
		return pList;
	}
	catch (...) {
		funcs.pFreeObj(funcs.extHandle, &pObjList);
		return NULL;
	}
} // end of NodePool::Find()


BaseNode* NodePool::FindInPool(const ASN::DN& dn, const ASN::Bytes& cert) const
{
	std::pair<BaseNodeDN_Map::const_iterator, BaseNodeDN_Map::const_iterator>
		itPair = m_pool.equal_range(dn);
	BaseNodeDN_Map::const_iterator iPool;
	for (iPool = itPair.first; iPool != itPair.second; ++iPool)
	{
		if (iPool->second == NULL)
			throw CML_ERR(CM_NULL_POINTER);

		// If the cert is present in the pool, return the pointer to the node
		if (*iPool->second == cert)
			return iPool->second;
	}

	return NULL;
} // end of NodePool::FindInPool()


BaseNode* NodePool::FindInPool(const Bytes_struct& encCert) const
{
	BaseNodeDN_Map::const_iterator i;
	for (i = m_pool.begin(); i != m_pool.end(); ++i)
	{
		if (i->second == NULL)
			throw CML_ERR(CM_NULL_POINTER);

		if (*i->second == encCert)
			return i->second;
	}

	return NULL;
} // end of NodePool::FindInPool()


BaseNode* NodePool::FindInPool(const ASN::Bytes& encCert) const
{
	BaseNodeDN_Map::const_iterator i;
	for (i = m_pool.begin(); i != m_pool.end(); ++i)
	{
		if (i->second == NULL)
			throw CML_ERR(CM_NULL_POINTER);

		if (*i->second == encCert)
			return i->second;
	}

	return NULL;
} // end of NodePool::FindInPool()



///////////////////////////////////
// BaseNode class implementation //
///////////////////////////////////
BaseNode::BaseNode(ulong sessionID) : m_hSession(sessionID)
{
	m_newAdded = false;
	m_iList = m_issuerList.end();
}


BaseNode* BaseNode::Construct(ulong sessionID, const Bytes& asn1Cert)
{
	// Search the cache to see if this cert is already present
	BaseNode *pNode;

	// Acquire global session lock
	ASN::ReadLock lock = AcquireSessionReadLock(sessionID);

	const CachedCertRef* pCachedCert =
		GetCertCache(sessionID).FindCert(asn1Cert, false);
	if (pCachedCert != NULL)
	{
		// If cert is cached, construct either a TrustedCertNode if the cert
		// is trusted, or just a CachedCertNode
		if (pCachedCert->GetRef().IsTrusted())
			pNode = new TrustedCertNode(sessionID, *pCachedCert);
		else
			pNode = new CachedCertNode(sessionID, *pCachedCert);
		delete pCachedCert;
		;
	}
	else
	{
		// Create a regular PathNode
		pNode = new PathNode(sessionID, asn1Cert);
	}

	if (pNode == NULL)
		throw CML_MEMORY_ERR;

	return pNode;
} // end of BaseNode::Construct()


PathLinkList::iterator BaseNode::AddIssuer(BaseNode* pIssuer)
{
	// Check parameter
	if (pIssuer == NULL)
		throw CML_ERR(CM_NULL_POINTER);
	
	// Loop through the existing issuer list
	PathLinkList::iterator iIssuer = m_issuerList.begin();
	while ((iIssuer != m_issuerList.end()) && (*iIssuer != pIssuer))
		++iIssuer;
	
	// If this issuer is not already present, add it
	if (iIssuer == m_issuerList.end())
	{
		// Add a new PathLink object to the issuer list for this issuer
		iIssuer = m_issuerList.insert(m_issuerList.end(),
			PathLink(pIssuer, *this));
	}

	return iIssuer;
}


void BaseNode::AddCachedIssuer(BaseNode* pIssuer, const PathStack& curPath,
							   float curProb)
{
	// Add this cached issuer to the issuer list and set it as the current
	// issuer
	m_iList = AddIssuer(pIssuer);
}


void BaseNode::DetermineError(ErrorInfoList& errors, PathStack& curPath, PrintXML& logXML,
							  float minProb, float curProb)
{
	// Add this node to the current path
	curPath.Push(this);

	// Reset the path probability for each of the existing issuers (if any)
	PathLinkList::iterator iLink;
	for (iLink = m_issuerList.begin(); iLink != m_issuerList.end(); ++iLink)
		iLink->SetPathProb(curPath, -1);

	// Choose the best issuer
	ChooseNextIssuer(curPath, logXML, curProb, minProb);
	if (m_iList == m_issuerList.end())
	{
		// No issuer found, record this error
		short err = CM_ISSUER_CERT_NOT_FOUND;
		if (!m_issuerList.empty())
			err = CM_PATH_BUILD_PROB_TOO_LOW;
		else if (GetCert().base().IsSelfIssued())
			err = CM_CROSS_CERT_NOT_FOUND;
		errors.AddError(err, GetCert().base().issuer);
	}
	else
	{
		// Determine the path error by following the best issuer
		m_iList->GetIssuerNode()->DetermineError(errors, curPath, logXML, minProb,
			curProb * m_iList->GetLinkProb());
	}

	// Remove this node from the current path
	curPath.Pop();

} // end of BaseNode::DetermineError()


bool BaseNode::FindAndZeroizeIssuer(const BaseNode* pIssuerNode)
{
	// Find the PathLink that leads to this node's issuer
	PathLinkList::iterator i;
	for (i = m_issuerList.begin(); i != m_issuerList.end(); ++i)
	{
		if (i->GetIssuerNode() == pIssuerNode)
		{
			i->ZeroizeLinkProb();
			return true;
		}
	}

	return false;
}


bool BaseNode::operator==(const BaseNode& rhs) const
{
	if (this == &rhs)
		return true;

	return (GetCert().GetEnc() == rhs.GetCert().GetEnc());
}


bool BaseNode::operator==(const Bytes& bytes) const
{
	return (GetCert().GetEnc() == bytes);
}


bool BaseNode::operator==(const Bytes_struct& bytes) const
{
	return (GetCert().GetEnc() == bytes);
}


short BaseNode::BuildCachedPath(NodePool& thePool, const Location& loc,
								PathStack& curPath, PrintXML& logXML, float curProb,
								const CachedCertList& cachedCerts,
								CachedCertList::const_reverse_iterator iCachedCert)
{
	// Check that cached cert iterator is valid
	if (iCachedCert == cachedCerts.rend())
		return CM_NO_PATH_FOUND;

	// Add this node to the current path
	curPath.Push(this);

	// printing current cert path
	logXML.WriteData(CM_LOG_LEVEL_2, "Adding Cached Node to Path");
	logXML.WriteSimpleBegin(CM_LOG_LEVEL_2, "Path_so_far");
	curPath.Print(logXML, CM_LOG_LEVEL_2);
	logXML.WriteEnd(CM_LOG_LEVEL_2, "Path_so_far"); 

	// Add the cached cert to the pool
	BaseNode* pIssuerNode = thePool.Add(*iCachedCert);
	
	// Set the cached cert as this cert's issuer
	AddCachedIssuer(pIssuerNode, curPath, curProb);

	// Build the remainder of the path
	short buildResult = pIssuerNode->BuildCachedPath(thePool, loc, curPath,
		logXML, curProb, cachedCerts, ++iCachedCert);
	
	// If no path was found, set the probability to zero
	if (buildResult != CM_NO_ERROR)
	{
		m_iList->SetPathProb(curPath, 0);
		curPath.Pop();
	}

	return buildResult;
}


short BaseNode::BuildNextPath(NodePool& thePool, const Location& loc,
							  PathStack& curPath, PrintXML& logXML, float minProb,
							  float curProb, float* pBestProb)
{
	// If this node has errors, return special CMI_CERT_HAS_ERRORS
	if (!m_certErrors.empty())
		return CMI_CERT_HAS_ERRORS;

	// Add this node to the current path
	curPath.Push(this);

	// printing current cert path
	logXML.WriteSimpleBegin(CM_LOG_LEVEL_2, "Path_so_far");
	curPath.Print(logXML, CM_LOG_LEVEL_2);
	logXML.WriteEnd(CM_LOG_LEVEL_2, "Path_so_far"); 

	// Loop until a path is found or there are no more issuer certs to choose
	short err;
	do
	{
		logXML.WriteInfo(CM_LOG_LEVEL_3, "CurrentProb", curProb);
		logXML.WriteInfo(CM_LOG_LEVEL_3, "MinProb", minProb);

		// Pick the next issuer and set the minimum probability for the next
		// pass
		float localMinProb = ChooseNextIssuer(curPath, logXML, curProb, minProb,
				thePool.m_searchLocs.IsLastLoc(m_lastLoc));

		// Build the next path if the current issuer iterator is set
		if (m_iList != m_issuerList.end())
		{
			err = m_iList->BuildNextPath(thePool, loc, curPath, logXML, localMinProb,
				curProb);
			if ((err != CM_NO_ERROR) && (err != CM_NO_PATH_FOUND))
			{
				// Fatal error occurred, so return
				curPath.Pop();
				return err;
			}
		}
		else
		{
			// Look for more issuers from the next loc
			if (loc != m_lastLoc)
			{
				// Reset the path probability for each of the existing issuers
				PathLinkList::iterator iLink = m_issuerList.begin();				
				for ( ; iLink != m_issuerList.end(); ++iLink)
					if (iLink->LeadsToCompletePath())
						iLink->SetPathProb(curPath, -1);				
					else
						iLink->ClearPaths();

				// Search for more issuer certs and update the last location
				err = FindIssuers(thePool, loc, curPath, logXML, curProb);
				if ((err == CM_NO_ERROR) || (err == CM_NOT_FOUND))
					m_iList = m_issuerList.begin();
				else
				{
					curPath.Pop();
					return err;
				}
			}

			// Set the error code to CM_NO_PATH_FOUND
			err = CM_NO_PATH_FOUND;
		}
	} while ((err != CM_NO_ERROR) && (m_iList != m_issuerList.end()));

	// If not successful, find the highest probability of the issuer paths
	float maxProb = 1;
	if (err != CM_NO_ERROR)
		maxProb = FindMaxProbability(curPath);

	// If the probability of the current path falls below the probability of the next best path,
	// then set error to special CMI_EXCEEDED_PROBABILITY
	if ((maxProb < minProb) && (pBestProb != NULL))
	{
		*pBestProb = maxProb;
		// printing current cert path
		logXML.WriteInfo(CM_LOG_LEVEL_3, "MaxProb", maxProb);
		logXML.WriteData(CM_LOG_LEVEL_2, "MaxProb less than MinProb - BACKING UP!!!!");
		err = CMI_EXCEEDED_PROBABILITY;
	}

	// Remove this node from the current path
	if (err != CM_NO_ERROR)
		curPath.Pop();

	return err;
} // end of BaseNode::BuildNextPath()


int BaseNode::AddIssuers(BaseNodePtrList& issuers, PathStack& curPath,
						 float curProb)
{
	int nAdded = 0;

	// Add the new issuer certificates to the list of potential issuers for
	// this cert
	BaseNodePtrList::iterator iNode;
	for (iNode = issuers.begin(); iNode != issuers.end(); ++iNode)
	{
		if (*iNode == NULL)
			throw CML_ERR(CM_NULL_POINTER);

		// If this issuer cert is the same as the current cert, skip over it
		if (operator==(**iNode))
			continue;

		// Loop through the existing issuer list
		PathLinkList::iterator iIssuer = m_issuerList.begin();
		while ((iIssuer != m_issuerList.end()) && (*iIssuer != *iNode))
			++iIssuer;

		// If this cert node is not already present, add it
		if (iIssuer == m_issuerList.end())
		{
			// Add a new PathLink object to the issuer list for this potential
			// issuer
			PathLinkList::iterator iNew =
				m_issuerList.insert(iIssuer, PathLink(*iNode, *this));
			nAdded++;
		}
	}

	return nAdded;
} // end of BaseNode::AddIssuers()


// Loop through the possible issuers and select the one with the highest
// probability of successfully building a path
float BaseNode::ChooseNextIssuer(const PathStack& path, PrintXML& logXML, float curProb,
								 float minProb, bool isLastLoc)
{
	// Initialize the high probability to the minimum probability
	float highProb = minProb;

	PathLinkList::iterator iTemp = m_issuerList.begin();
	m_iList = m_issuerList.end();

	// If the list is empty, return
	if ((iTemp == m_issuerList.end()) || ((!m_newAdded) && (!isLastLoc)))
		return minProb;

	logXML.WriteBegin(CM_LOG_LEVEL_5, "ChooseNextIssuer", 3, 
		"Choosing Issuer for", GetCert().base().subject.IsEmpty() ? 
		"CN=Subject name is empty" : GetCert().base().subject.GetRDNList().back(),
		"serialNum =", &GetCert().base().serialNumber);
	logXML.WriteData(CM_LOG_LEVEL_5, "Issuer DN is", GetCert().base().issuer);

		
	for (; iTemp != m_issuerList.end(); ++iTemp)
	{
		char* reason = CM_DEFAULT_REASON;
		// Only allow this issuer if...
		if ( (iTemp->LeadsToCompletePath()) ||			// allow this issuer if it leads to a complete path
			 (iTemp->IsPathInPathProbMap(path)) ||		// allow if path already in the Path Prob Map
			 (iTemp->IsNewSubject(path)) )				// allow if this path starts from a new end entity
		{
			// If the current location is not the last location to be searched, and
			// the probability of this link falls below the threshold, set this path's
			// probablility to 0. This will ensure we will not use this path until we are 
			// at the last location (done to help Entrust problem)
			if (!isLastLoc && (iTemp->GetLinkProb() < kMIN_LOC_PROBABILITY)) {
				iTemp->SetPathProb(path, 0);
				reason = CM_BELOWTHRESHOLD_REASON;
			// If this issuer is already in the path, reset its probability to zero so we do not try it 
			// again, atleast until we change locations.
			} else if (path.IsPresent(iTemp->GetIssuerNode())) {
				iTemp->SetPathProb(path, 0);
				reason = CM_REPEATED_REASON ;
			// Reduce the probability of this path by 75% if we violate the issuers path length constraint.
			} else {
				int pathLen = -1;
				if (iTemp->GetIssuerNode()->GetCert().base().exts.pBasicCons != NULL)
					pathLen = iTemp->GetIssuerNode()->GetCert().base().exts.pBasicCons->pathLen;
				// PathStack includes EE cert and pathLen from basic constraints extension only counts
				// CA certs so pathStack size must be decremented by one to get the number of CA certs
				if ((pathLen != -1) && ((path.Size() - 1) > pathLen)) {
					if (iTemp->GetPathProb(path) < 0) {
						float oldProb = iTemp->GeneratePathProbability(curProb);
						iTemp->SetPathProb(path, (oldProb * (float).25));
						reason = CM_PATHLENVIOLATION_REASON ;
					}
				}
			}

			float tempProb = iTemp->GetPathProb(path);
			if (tempProb < 0)
			{			
				// Add this path and probability to the list and recalculate
				// the probability
				iTemp->AddPath(path, curProb);
				tempProb = iTemp->GetPathProb(path);
			}
			
			if (tempProb > highProb)
			{
				// Set the min probability to the previous old high
				minProb = highProb;
				
				// Update the high probability and set this issuer as the best
				// choice so far
				highProb = tempProb;
				m_iList = iTemp;
			}
			else if ((tempProb == highProb) && (tempProb > 0))
			{
				// Set this issuer as the best choice, if one hasn't been seleted
				if (m_iList == m_issuerList.end())
					m_iList = iTemp;
				
				// Set the min probability to the previous old high
				minProb = highProb;			
			}
			else if (tempProb > minProb)
			{
				// Set the min probability to the previous old high
				minProb = tempProb;
			}
		}
		else
		{
			reason = CM_EXCLUDED_REASON;
		}

		char buf[7];
		sprintf(buf, "%.3f", iTemp->GetPathProb(path));
		logXML.WriteData(CM_LOG_LEVEL_5, "pathprob=", buf,
			"serialNum=", iTemp->GetIssuerNode()->GetCert().base().serialNumber,
			"issuer=", iTemp->GetIssuerNode()->GetCert().base().issuer.IsEmpty() ? 
			"CN=Issuer name is empty" : iTemp->GetIssuerNode()->GetCert().base().
			issuer.GetRDNList().back(),
			reason);
	}

	if (m_iList == m_issuerList.end())
		logXML.WriteData(CM_LOG_LEVEL_5, "No Issuer Chosen");
	else
		logXML.WriteData(CM_LOG_LEVEL_5, "Chosen Issuer is ", m_iList->GetIssuerNode()->GetCert().base().subject.IsEmpty() ?
		"CN=Subject name is empty" : m_iList->GetIssuerNode()->GetCert().base().subject.GetRDNList().back(),
			"serialNum=", m_iList->GetIssuerNode()->GetCert().base().serialNumber);
	logXML.WriteEnd(CM_LOG_LEVEL_5, "ChooseNextIssuer", 3);

	return minProb;
} // end of BaseNode::ChooseNextIssuer()


short BaseNode::FindIssuers(NodePool& thePool, const Location& loc,
							PathStack& curPath, PrintXML& logXML, float curProb)
{
	BaseNodePtrList* pIssuerList = NULL;
	int numFound = 0;
	logXML.WriteBegin(CM_LOG_LEVEL_4, "FindIssuers", 3, 
		"Requesting CA Certs for", GetCert().base().subject.IsEmpty() ?
		"CN=Subject name is empty" : GetCert().base().subject.GetRDNList().back(),
		"serialNum =", &GetCert().base().serialNumber);
	logXML.WriteData(CM_LOG_LEVEL_4, "Issuer DN is", GetCert().base().issuer);
	try {
		m_newAdded = false;
		do
		{
			// Request all certificate types from the pool of certificates
			pIssuerList = thePool.GetCerts(GetCert().base().issuer, m_lastLoc,
				loc, GetCert().base().exts.pAuthInfoAccess, logXML);
			if (pIssuerList == NULL)
				break;

			// Add them to the list of issuers for this node
			numFound = AddIssuers(*pIssuerList, curPath, curProb);
			if (numFound > 0)
				m_newAdded = true;
			delete pIssuerList;
		}
		while (!m_newAdded);

		logXML.WriteData(CM_LOG_LEVEL_4, numFound, " Issuers found");
		if (numFound > 0) {
			logXML.WriteSimpleBegin(CM_LOG_LEVEL_4, "Issuers_List");
			m_iList = m_issuerList.end();
			m_issuerList.sort();
			for (PathLinkList::iterator iLink = m_issuerList.begin(); iLink != m_issuerList.end(); ++iLink)
			{
				char buf[7];
				sprintf(buf, "%.3f", iLink->GetLinkProb());
				logXML.WriteData(CM_LOG_LEVEL_4, "linkprob=", buf,
										"serialNum=", iLink->GetIssuerNode()->GetCert().base().serialNumber,
										"issuer=", iLink->GetIssuerNode()->GetCert().base().issuer.IsEmpty() ?
										"CN=Issuer name is empty" : iLink->GetIssuerNode()->GetCert().base().issuer.GetRDNList().back());
			}
			logXML.WriteEnd(CM_LOG_LEVEL_4, "Issuers_List");
		}

		logXML.WriteEnd(CM_LOG_LEVEL_4, "FindIssuers", 3);
		// Return the appropriate result
		if (m_newAdded)
			return CM_NO_ERROR;
		else
			return CM_NOT_FOUND;
	}
	catch (ASN::Exception& cmlErr) {
		logXML.WriteEnd(CM_LOG_LEVEL_4, "FindIssuers", 3);
		delete pIssuerList;
		return cmlErr;
	}
	catch (SNACC::SnaccException& ) {
		logXML.WriteEnd(CM_LOG_LEVEL_4, "FindIssuers", 3);
		delete pIssuerList;
		return CM_ASN_ERROR;
	}
	catch (...) {
		logXML.WriteEnd(CM_LOG_LEVEL_4, "FindIssuers", 3);
		delete pIssuerList;
		throw;
	}
} // end of BaseNode::FindIssuers()


float BaseNode::FindMaxProbability(const PathStack& path)
{
	// Find the highest probability from the list of issuers for the given
	// partial path
	float maxProb = 0;
	PathLinkList::iterator iLink;
	for (iLink = m_issuerList.begin(); iLink != m_issuerList.end(); ++iLink)
	{
		float tempProb = iLink->GetPathProb(path);
		if (tempProb > maxProb)
			maxProb = tempProb;
	}
	return maxProb;
} // end of BaseNode::FindMaxProbability()



/////////////////////////////////////////
// CachedCertNode class implementation //
/////////////////////////////////////////
CachedCertNode::CachedCertNode(ulong sessionID, const CachedCert& cachedCert) :
BaseNode(sessionID), m_cachedCert(cachedCert), 
m_lock(m_cachedCert.m_mutex.AcquireReadLock())
{
	m_cachedPathUsed = false;
}

short CachedCertNode::BuildNextPath(NodePool& thePool, const Location& loc,
									PathStack& curPath, PrintXML& logXML, 
									float minProb, float curProb, float* pBestProb)
{
	if (!m_cachedPathUsed && (loc != Location::Application))
	{
		// Set flag to true
		m_cachedPathUsed = true;

		// lock mutex to m_path
		ASN::ReadLock lock = m_cachedCert.m_internalMutex.AcquireReadLock();
		try {
			// Build the cached path
			if (BuildCachedPath(thePool, loc, curPath, logXML, curProb,
				m_cachedCert.GetPath(), m_cachedCert.GetPath().rbegin()) ==
				CM_NO_ERROR)
				return CM_NO_ERROR;
		} catch (...)
		{
			lock.Release();
			throw;
		}
	}

	// Build the next path
	return BaseNode::BuildNextPath(thePool, loc, curPath, logXML, minProb, curProb,
		pBestProb);
}


bool CachedCertNode::IsCached() const
{
	return (!m_cachedCert.IsExpired());
}



//////////////////////////////////////////
// TrustedCertNode class implementation //
//////////////////////////////////////////
TrustedCertNode::TrustedCertNode(ulong sessionID,
								 const CachedCert& cachedCert) :
CachedCertNode(sessionID, cachedCert)
{
}


short TrustedCertNode::BuildCachedPath(NodePool& thePool, const Location& loc,
									   PathStack& curPath, PrintXML& logXML, float ,
									   const CachedCertList& cachedCerts,
									   CachedCertList::const_reverse_iterator iCachedCert)
{
	// Check that no more cached certs are in the list
	if (iCachedCert != cachedCerts.rend())
		return CM_NO_PATH_FOUND;

	return BuildNextPath(thePool, loc, curPath, logXML);
}

void TrustedCertNode::DeletePreviousPath(const PathStack& path)
{
	for (std::list<PathStack>::iterator iPath = m_prevPaths.begin();
	iPath != m_prevPaths.end(); ++iPath)
	{
		if (*iPath == path)
		{
			// Remove this path from the list
			m_prevPaths.erase(iPath);
			break;
		}
	}
}

short TrustedCertNode::BuildNextPath(NodePool& , const Location& ,
									 PathStack& curPath, PrintXML& logXML,
									 float , float , float* )
{
	curPath.Push(this);

	// Check if the path was previously built
	for (std::list<PathStack>::iterator iPath = m_prevPaths.begin();
		iPath != m_prevPaths.end(); ++iPath)
	{
		if (*iPath == curPath)
		{
			logXML.WriteSimpleBegin(CM_LOG_LEVEL_1, "Path_Already_Found");
			curPath.Print(logXML, CM_LOG_LEVEL_1);
			logXML.WriteEnd(CM_LOG_LEVEL_1, "Path_Already_Found");

			curPath.Pop();
			return CMI_PATH_ALREADY_FOUND;
		}
	}

	// Add this path to the list
	m_prevPaths.push_back(curPath);

	// printing final cert path
	logXML.WriteSimpleBegin(CM_LOG_LEVEL_1, "Final_Path");
	curPath.Print(logXML, CM_LOG_LEVEL_1);
	logXML.WriteEnd(CM_LOG_LEVEL_1, "Final_Path");

	return CM_NO_ERROR;
}


////////////////////////////////////
// PathLink class implementation //
////////////////////////////////////
PathLink::PathLink(BaseNode* pIssuerNode, const BaseNode& subjNode) :
	m_pIssuer(pIssuerNode)
{
	// Calculate and set the link probability
	short err = CalcLinkProbability(subjNode.GetCert().base());
	if (err != CM_NO_ERROR)
		throw CML_ERR(err);
	m_leadsToCompletePath = false;
}

void PathLink::AddPath(const PathStack& curPath, float curProb)
{
	// SetPathProb actually adds the path to the probability map
	SetPathProb(curPath,GeneratePathProbability(curProb));
}

short PathLink::BuildNextPath(NodePool& thePool, const Location& loc,
							  PathStack& curPath, PrintXML& logXML, 
							  float minProb, float curProb)
{
	// Build the next path to the issuer certificate
	float bestProb;
	short result = m_pIssuer->BuildNextPath(thePool, loc, curPath, logXML, minProb,
		GeneratePathProbability(curProb), &bestProb);

	switch (result)
	{
	case CM_NO_PATH_FOUND:
	case CMI_CERT_HAS_ERRORS:
		// Set this path's probability to zero
		SetPathProb(curPath, 0);
		return CM_NO_PATH_FOUND;

	case CMI_PATH_ALREADY_FOUND:
		// If the issuer's path was previously found, set the
		// path's probability to zero
		SetPathProb(curPath, 0);
		return CM_NO_PATH_FOUND;

	case CMI_EXCEEDED_PROBABILITY:
		// If the issuer's path exceeded the min probability, set
		// the path's probability to the new likelihood
		SetPathProb(curPath, bestProb);
		return CM_NO_PATH_FOUND;

	default:
		if (result == CM_NO_ERROR)
			m_leadsToCompletePath = true;
		return result;
	}
} // end of PathLink::BuildNextPath()


float PathLink::GetPathProb(const PathStack& pathSoFar) const
{
	PathProbMap::const_iterator iPair = m_pathProbs.find(pathSoFar);
	if (iPair == m_pathProbs.end())
		return -1;

	return iPair->second;
}


bool PathLink::IsPathInPathProbMap(const PathStack& pathSoFar) const
{
	PathProbMap::const_iterator iPair = m_pathProbs.find(pathSoFar);
	if (iPair == m_pathProbs.end())
		return false;
	else
		return true;
}

bool PathLink::IsNewSubject(const PathStack& pathSoFar) const
{
	const BaseNode* subject = pathSoFar.Deck().back();
	PathProbMap::const_iterator iMap;
	for (iMap = m_pathProbs.begin(); iMap != m_pathProbs.end(); ++iMap)
	{
		const BaseNode* subjectInMap = iMap->first.Deck().back();
		if (subject == subjectInMap)
			return false;
	}
	return true;
}


void PathLink::SetPathProb(const PathStack& path, float curProb)
{
	// Insert (if path is not already present in map)
	std::pair<PathProbMap::iterator, bool> iPair = m_pathProbs.insert(
		PathProbMap::value_type(path, curProb));

	// Otherwise, insert fails because path was already in the map so just update the probability.
	if (iPair.second == false)
		iPair.first->second = curProb;
}


float PathLink::GeneratePathProbability(float curProb) const
{
	return (curProb * m_linkProb);
}


short PathLink::CalcLinkProbability(const ASN::Cert& subjCert)
{
	const ASN::Cert& issuerCert = m_pIssuer->GetCert().base();

	// If the issuer's public key algorithm doesn't match the subject's
	// signature algorithm, set the link probability to zero
	try {
		if (issuerCert.pubKeyInfo !=
			SplitSigHashAlg(subjCert.signature.algorithm))
		{
			m_linkProb = 0;
			return CM_NO_ERROR;
		}
	}
	catch (...) {
		m_linkProb = 0;
		return CM_NO_ERROR;
	}

	// If the issuer's certificate is self-signed and not trusted, set the
	// link probability to zero
	if (IsSelfSigned(issuerCert, true) && !m_pIssuer->IsTrusted())
	{
		m_linkProb = 0;
		return CM_NO_ERROR;
	}

	float totalPoints = 0;
	float points = 0;

	// Award points based on whether the subject's authority key identifier
	// matches this cert's subject key identifier and issuer-serial
	totalPoints += 30;
	if (subjCert.exts.pAuthKeyID != NULL)
	{
		points += compareAuthKeyID(*subjCert.exts.pAuthKeyID,
			issuerCert.exts.pSubjKeyID, issuerCert.exts.pIssuerAltNames,
			issuerCert.issuer, issuerCert.serialNumber);
	}
	else	// Authority key identifier extension is absent
		points += 20;

	// Award points if the issuer name in the subject cert matches the subject
	// name in the issuer cert and the v2 Unique IDs if present, also match
	totalPoints += 20;
    if (subjCert.issuer == issuerCert.subject)
		points += 15;
	if (CompareUniqueIDs(subjCert.pIssuerUniqueID,
		issuerCert.pSubjectUniqueID))
		points += 5;

	// Award points if the issuer's cert is current
	totalPoints += 10;
	if (issuerCert.validity.IsValid())
		points += 10;

	// Award points if the issuer's cert is a CA certificate and has permission
	// to sign certificates
	totalPoints += 10;
	if ((issuerCert.version != SNACC::Version::v3) ||
		((issuerCert.exts.pBasicCons != NULL) &&
		issuerCert.exts.pBasicCons->isCA))
	{
		points += 5;
		if ((issuerCert.exts.pKeyUsage == NULL) ||
			issuerCert.exts.pKeyUsage->GetBit(SNACC::KeyUsage::keyCertSign))
			points += 5;
	}

	// Award points if this cert is in the cache or if the issuer cert's
	// issuer DN matches one of the trusted DNs
	totalPoints += 5;

	// Acquire global session lock
	ASN::ReadLock lock = AcquireSessionReadLock(m_pIssuer->m_hSession);

	if (m_pIssuer->IsTrusted())
		points += 5;
	else if (m_pIssuer->IsCached())
		points += 4;
	else if (GetCertCache(m_pIssuer->m_hSession).IsDnTrusted(issuerCert.issuer))
		points += 3;

	// Remove points if the cert has errors
	if (m_pIssuer->HasCertErrors() || m_pIssuer->HasPathErrors())
		points -= 2;

	lock.Release();  // Release the lock

	// Award points based upon the number of certificate policies that match between the subject and issuer	
	totalPoints += 15;
	
	// neither cert contains any policies or just the subject does not contain any policies
	if ( ((subjCert.exts.pCertPolicies == NULL) && (issuerCert.exts.pCertPolicies == NULL)) ||
		 (subjCert.exts.pCertPolicies == NULL) )
	{
		points += 15;
	// the issuer does not contain any policies the interesected set will always be null
	} else if (issuerCert.exts.pCertPolicies == NULL)
	{
		points += 0;
	// both certs contain policies, award points based upon the intersection of two policies
	} else {
		points += comparePolicySets(subjCert, issuerCert);
	}

	// Award points if the issuer cert does not contain any policy or name constraints
	totalPoints += 6;
	if ( (issuerCert.exts.pNameCons == NULL) ||
		 ( (issuerCert.exts.pNameCons->permitted.empty()) &&
		   (issuerCert.exts.pNameCons->excluded.empty()) &&
		   (issuerCert.exts.pNameCons->requiredNames.otherNames.empty()) &&
		   (issuerCert.exts.pNameCons->requiredNames.basicNames.IsEmpty()) ) )
		points += 3;

	if ( (issuerCert.exts.pPolicyCons == NULL) ||
		 ( (issuerCert.exts.pPolicyCons->requireExplicitPolicy == CM_NOT_SET) &&
		   (issuerCert.exts.pPolicyCons->inhibitPolicyMapping == CM_NOT_SET) ) )
		points += 3;


	// Subtract points if this cert is self-signed, but not trusted
	if (IsSelfSigned(issuerCert) && (issuerCert.exts.pAuthKeyID != NULL) &&
		!m_pIssuer->IsTrusted())
		points -= 10;

	// Calculate the probability
	if (points > totalPoints)
		m_linkProb = 1;
	else if (points < 0)
		m_linkProb = 0;
	else
		m_linkProb = points / totalPoints;

	return CM_NO_ERROR;
}


////////////////////////////////////
// PathStack class implementation // 
////////////////////////////////////
BaseNode* PathStack::PopBottom()
{
	if (empty())
		return NULL;

	BaseNode* pNode = back();
	pop_back();
	return pNode;
}

void PathStack::Print(PrintXML& logXML, CMLogLevel level) const
{
	for (const_iterator i = begin(); i != end(); ++i)
	{
		if (*i == NULL)
			throw CML_ERR(CM_NULL_POINTER);
		logXML.WriteData(level, "Cert subject=", (*i)->GetCert().base().subject,
			"serialNum=", (*i)->GetCert().base().serialNumber);
	}
}

bool PathStack::IsPresent(const BaseNode* pNode) const
// This function returns true if the specified cert is already present in the
// path.  True is also returned if the specified cert's issuer name matches the
// subject name of one of the certs already in the path (other than the target
// end entity).
{
	if (pNode == NULL)
		return false;

	const ASN::Cert& nodeCert = pNode->GetCert().base();
	for (PathStack::const_iterator iStack = begin(); iStack != end(); ++iStack)
	{
		// Return true if the cert is already present
		if (**iStack == *pNode)
			return true;

		// Return false if all of the certs in the path except the subject
		// cert have been checked
		if (*iStack == back())
			return false;

		// Check that the path doesn't chain back to a previous DN
		// (Self-issued certs and trusted certs are permitted)
		if (!pNode->IsTrusted() && (nodeCert.issuer != nodeCert.subject) &&
			(nodeCert.issuer == (*iStack)->GetCert().base().subject))
			return true;
	}

	return false;
}

/* FUNCTION:  PathStack::GetForwardPath()
 * This function builds and returns the list of certificates in the path from
 * this stack.  The certificates are returned in reverse order from trust
 * anchor to the subject cert.
 */
void PathStack::GetForwardPath(const BaseNode* pSubject,
							   CertPtrList& path) const
{
	// Check parameters
	if ((pSubject == NULL) || empty())
		throw CML_ERR(CM_UNKNOWN_ERROR);

	// Check that the subject matches the end entity of the current path
	if (pSubject != back())
		throw CML_ERR(CM_UNKNOWN_ERROR);

	for (const_reverse_iterator i = rbegin(); i != rend(); ++i)
	{
		if (*i == NULL)
			throw CML_ERR(CM_NULL_POINTER);
		// Skip certs that were created from a public key and DN
		if ((*i)->IsCreatedFromKey())
			continue;
		path.push_back(&(*i)->GetCert());
	}
} // end of PathStack::GetForwardPath()



bool PathStack::operator==(const PathStack& rhs) const
{
	if (this == &rhs)
		return true;

	if (size() != rhs.size())
		return false;

	PathStack::const_iterator iStack = begin();
	PathStack::const_iterator iRhsStack = rhs.begin();
	for ( ; (iStack != end()) && (iRhsStack != rhs.end()); ++iStack, ++iRhsStack)
	{
		if (*iStack != *iRhsStack)
			return false;
	}

	if ((iStack == end()) && (iRhsStack == rhs.end()))
		return true;
	else
		return false;
}


bool PathStack::operator<(const PathStack& rhs) const
{
	if (this == &rhs)
		return false;

	PathStack::const_iterator iStack = begin();
	PathStack::const_iterator iRhsStack = rhs.begin();
	while ((iStack != end()) && (iRhsStack != rhs.end()))
	{
		if (*iStack < *iRhsStack)
			return true;
		else if (*iStack > *iRhsStack)
			return false;

		++iStack;
		++iRhsStack;
	}

	if (iRhsStack == rhs.end())		// either both PathStack's are equal or
		return false;				//    rhs is shorter
	else
		return true;				// rhs is longer
}


///////////////////////////////////
// Location class implementation //
///////////////////////////////////
Location::Location(LocEnum location)
{
	if (location == AllSearched)
		throw CML_ERR(CM_INVALID_PARAMETER);

	if (location == Uninitialized)
		m_loc = 0;
	else
	{
		m_loc = 1;
		if (location != Application)
			m_loc <<= location - 1;
	}
}


Location::Location(short locMask)
{
	m_loc = locMask;
	m_loc <<= 2;
}


Location::Location(SearchBounds boundsFlag)
{
	switch (boundsFlag)
	{
	case CM_SEARCH_LOCAL:
		m_loc = RAM_LOC | CLIENT_LOC;
		break;
	case CM_SEARCH_REMOTE:
		m_loc = SERVER_LOC | DSA_LOC;
		break;
	case CM_SEARCH_UNTIL_FOUND:
		m_loc = RAM_LOC | CLIENT_LOC | SERVER_LOC | DSA_LOC;
		break;
	case CM_SEARCH_BOTH:
		m_loc = RAM_LOC | CLIENT_LOC | SERVER_LOC | DSA_LOC | SEARCH_ALL_LOC;
		break;
	default:
		throw CML_ERR(CM_INVALID_PARAMETER);
	}

	m_loc <<= 2;
}


bool Location::operator==(LocEnum location) const
{
	if (location == Uninitialized)
	{
		if (m_loc == 0)
			return true;
	}
	else if (location == AllSearched)
	{
		if (m_loc == -1)
			return true;
	}
	else
	{
		short mask = 1;
		if (location != Application)
			mask <<= location - 1;

		if ((m_loc & mask) == mask)
			return true;
	}

	return false;
}


bool Location::operator<(LocEnum location) const
{
	switch (location)
	{
	case Uninitialized:
		break;

	case AllSearched:
		if (m_loc != -1)
			return true;
		break;

	default:
		if (m_loc < (1 << (location - 1)))
			return true;
	}

	return false;
}


bool Location::operator>(LocEnum location) const
{
	switch (location)
	{
	case Uninitialized:
		if (m_loc != 0)
			return true;
		break;

	case AllSearched:
		break;

	default:
		if (m_loc > (1 << (location - 1)))
			return true;
	}

	return false;
}

Location::operator const char*() const
{
	if (IsSearchAllSet())
		return "All";

	switch (m_loc)
	{
	case 1:
		return "Application";

	case 2:
		return "Cache";

	case 4:
		return "RAM";

	case 8:
		return "Client";

	case 16:
		return "Server";

	case 32:
		return "X500_DSA";

	default:
		return "Invalid location";
	}
}

bool Location::IsLastLoc(const Location& theLoc) const
{
	if (theLoc.m_loc < 0)
		return true;
	if (theLoc.m_loc < 4)
		return false;

	long common = m_loc & theLoc.m_loc;
	if (common == 0)
		return true;

	if ((common << 1) < m_loc)
		return false;

	return true;
}


bool Location::IsSearchAllSet() const
{
	return ((m_loc & (SEARCH_ALL_LOC << 2)) != 0);
}


bool Location::UpdateLoc(const Location& furthestLoc,
						 const Location& searchLocs)
{
	if (m_loc < 0)
		return false;

	if (IsSearchAllSet())
	{
		m_loc = searchLocs.m_loc;
		return false;
	}
	do
	{
		if (m_loc == furthestLoc.m_loc)
			return false;
		else if (m_loc == 0)
		{
			m_loc = 1;
			return true;
		}
		else if (operator==(Location::Application))
		{
			m_loc <<= 1;
			return true;
		}
		else if (operator==(Location::Cache) && searchLocs.IsSearchAllSet())
			m_loc = searchLocs.m_loc;
		else
		{
			m_loc <<= 1;
			if (m_loc > (DSA_LOC << 2))
			{
				m_loc = -1;
				return false;
			}
		}
	} while ((searchLocs.m_loc & m_loc) == 0);

	return true;
}


Cert_path_LL* GetCertPathList(const ASN::CertificationPath& path)
{
	Cert_path_LL* result = (Cert_path_LL*)calloc(1, sizeof(Cert_path_LL));
	if (result == NULL)
		throw CML_MEMORY_ERR;

	try {
		// Get the Cert_struct form of the subject cert
		result->cert = path.userCert.GetCertStruct();

		// Build the list of the CA certs
		for (std::list<CertPair>::const_iterator i = path.caCerts.begin(); i !=
			path.caCerts.end(); i++)
		{
			if (i->forward == NULL)
				break;
			
			// Allocate and clear the memory for a new link
			Cert_path_LL* pNew = (Cert_path_LL*)calloc(1, sizeof(Cert_path_LL));
			if (pNew == NULL)
				throw CML_MEMORY_ERR;
			
			// Add this link to the head of the resulting list
			pNew->next = result;
			result = pNew;

			pNew->cert = i->forward->GetCertStruct();
		}

		return result;
	}
	catch (...) {
		CM_FreeCertPathLinkedList(&result);
		throw;
	}
}


////////////////////////
// Internal Functions //
////////////////////////

// Returns the number of points to award for this issuer based on the number
// certificate policies in both certs that match
float comparePolicySets(const ASN::Cert& subjCert,
					  const ASN::Cert& issuerCert)
{
	float points;
	bool hasAnyPolicy = false;
	ASN::CertPolicyList subjectPolicies = *subjCert.exts.pCertPolicies;
	ASN::CertPolicyList issuerPolicies = *issuerCert.exts.pCertPolicies;

	//process policy mappings if any on subject's policies
	if (issuerCert.exts.pPolicyMaps != NULL) {
		ASN::PolicyMappingList::const_iterator iMap;
		// loop through all policy mappings
		for (iMap = issuerCert.exts.pPolicyMaps->begin(); iMap != issuerCert.exts.pPolicyMaps->end(); ++iMap)
		{
			ASN::CertPolicyList::iterator iSubjPol;
			// loop through all policies in subject cert
			for (iSubjPol = subjectPolicies.begin(); iSubjPol != subjectPolicies.end(); iSubjPol++)
			{
				// check to see if subject contains the any policy
				if (*iSubjPol == SNACC::anyPolicy)
					hasAnyPolicy = true;
				// see if the policy being mapped matches a policy in the subject cert
				if (iMap->subjectPolicy == iSubjPol->policyId )
				{
					// policies match, replace subject's policy with that of the issuer's domain
					iSubjPol->policyId = iMap->issuerPolicy;
				}
			}
		}
	}
	
	// intersect the subject and issuer policies and calculate points
	ASN::CertPolicyList intersection = issuerPolicies & subjectPolicies;
	float numSubjPolicies = (float)subjectPolicies.size();
	float numIssuerPolicies = (float)issuerPolicies.size();
	float numIntersectedPolicies = (float)intersection.size();
	if (hasAnyPolicy)
		numSubjPolicies = numIntersectedPolicies;

	if ( ((numIssuerPolicies == 0) && (numSubjPolicies == 0)) ||
		 (numSubjPolicies == 0) )
		points = 15;
	else
		points = ((numIntersectedPolicies/numSubjPolicies) * 15);

	return points;
}

// Returns the number of points to award for this issuer based on how its
// subject key identifier (if present), issuer name, and serial number match
// the ones in the authority key identifier extension
int compareAuthKeyID(const ASN::AuthKeyIdExtension& authKeyExt,
					 const SNACC::AsnOcts* pSubjKeyID, const GenNames* pIssuerAltNames,
					 const DN& issuerName, const SNACC::AsnInt& serialNum)
{
	int keysMatch = 0;
	int namesMatch = 0;
	int serialNumsMatch = 0;

	if ((pSubjKeyID != NULL) && (authKeyExt.keyID != NULL))
	{
		if (*pSubjKeyID == *authKeyExt.keyID)
			keysMatch = 1;
		else
			keysMatch = -1;
	}

	if (authKeyExt.authCertIssuer != NULL)
	{
		try {
			// Compare the issuer names
			if (authKeyExt.authCertIssuer->IsPresent(issuerName) ||
				((pIssuerAltNames != NULL) &&
				authKeyExt.authCertIssuer->IsOnePresent(*pIssuerAltNames)))
				namesMatch = 1;
			else
				namesMatch = -1;
		}
		catch (...) {
			namesMatch = -1;
		}
	}
	
	if (authKeyExt.authCertSerialNum != NULL)
	{
		try {
			// Compare the serial numbers
			if (serialNum == *authKeyExt.authCertSerialNum)
				serialNumsMatch = 1;
			else
				serialNumsMatch = -1;
		}
		catch (...) {
			serialNumsMatch = 1;
		}
	}

	int points = 0;
	if (keysMatch > 0)
	{
		points += 30;
		points += namesMatch * 5;
		points += serialNumsMatch * 10;
	}
	else if (keysMatch == 0)
	{
		if ((namesMatch == 0) && (serialNumsMatch == 0))
			points = 20;
		else
		{
			points += namesMatch * 10;
			points += serialNumsMatch * 20;
		}
	}
	else	// keys don't match
		points -= 30;

	if (points > 30)
		points = 30;

	return points;
} // end of compareAuthKeyID()


void parseForwardCerts(BytesList& encCertList, const Bytes& asnPath)
{
	// Clear the encoded cert list
	encCertList.clear();

	// Copy the encoded cert path
	Bytes_struct* pathStruct = asnPath.GetBytesStruct();
	EncCertPair_LL* pPath;

	try {
		// Parse the encoded cert path
		ulong numDec;
		if (CMASN_ParseCertPath(pathStruct, &numDec, &pPath) != CMLASN_SUCCESS)
			throw CML_ERR(CM_ASN_ERROR);
		
		// Add each forward cert to the encCertList
		EncCertPair_LL* pPair = pPath;
		while (pPair != NULL)
		{
			encCertList.push_back(pPair->forward);
			pPair = pPair->next;
		}
		
		CMASN_FreeCertPairList(&pPath);
		CM_FreeBytes(&pathStruct);
	}
	catch (...) {
		CMASN_FreeCertPairList(&pPath);
		CM_FreeBytes(&pathStruct);
		encCertList.clear();
		throw;
	}
}

bool hasExcludedError(const ErrorInfoList& errorList) 
{
	bool result = false; //default - errors are not excluded except those checked in loop below
	ErrorInfoList::const_iterator iError;
	
	for (iError = errorList.begin(); iError != errorList.end(); ++iError)
	{
		if (iError->error == CM_CERT_SIGNATURE_INVALID)
			 return true;
	}
	return result;
}

void logErrors(const ErrorInfoList& errorList, const PrintXML& logXML)
{
	if (!errorList.empty())
	{
		logXML.WriteSimpleBegin(CM_LOG_LEVEL_1, "Error_Info_List");
		ErrorInfoList::const_iterator iError;	
		for (iError = errorList.begin(); iError != errorList.end(); ++iError)
		{
			logXML.WriteData(CM_LOG_LEVEL_1, "error=", CMU_GetErrorString(iError->error));
			GenNames::const_iterator iName = iError->name.begin();
			if (iName->GetType() == ASN::GenName::X500) {
				ASN::GenName::Form name = iName->GetName();
				DN dn = *name.dn;
				logXML.WriteData(CM_LOG_LEVEL_1, "dn=", dn);
			}
			if (!iError->extraInfo.empty())
				logXML.WriteData(CM_LOG_LEVEL_1, "extra info=", iError->extraInfo.c_str());					
		}
		logXML.WriteEnd(CM_LOG_LEVEL_1, "Error_Info_List");
	}
}
// end of CM_CertPath.cpp
