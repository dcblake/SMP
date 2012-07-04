/*****************************************************************************
File:     CM_cache.cpp
Project:  Certificate Management Library
Contents: Cache functions used to manage the key cache of previously validated
          public keys.

Created:  9 May 1997
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>
		  Tom Horvath <Tom.Horvath@DigitalNet.com>

Last Updated:	30 March 2004

Version:  2.4

*****************************************************************************/

////////////////////
// Included Files //
////////////////////

#include "CM_cache.h"
#include <string>

// Defines whether or not certs with errors are cached.
const bool ERRORS_ALLOWED = true;
// Maximum Time (in seconds) a cached certificate with errors can live in the cache.
const time_t MAX_ERROR_TTL = (30 * 60);

extern bool hasExcludedError(const CML::ErrorInfoList& errorList);


// Using declarations
using namespace CML;
using namespace CML::Internal;


/////////////////////////////////////////////////
// Implementation of the TrustAnchorList class //
/////////////////////////////////////////////////
TrustAnchorList& TrustAnchorList::operator=(const ASN::BytesList& trustedCerts)
{
	clear();
	ASN::BytesList::const_iterator i;
	for (i = trustedCerts.begin(); i != trustedCerts.end(); ++i)
		push_back(*i);
	return *this;
}



/////////////////////////////////////////////
// Implementation of the TrustAnchor class //
/////////////////////////////////////////////
TrustAnchor::TrustAnchor(const ASN::Bytes& encCert, bool useExts) :
m_encCert(encCert), m_createdFromKey(false)
{
	maxPathLen = -1;

	if (useExts)
	{
		ASN::Cert decCert(encCert);
		if ((decCert.exts.pBasicCons != NULL) &&
			(decCert.exts.pBasicCons->pathLen > 0))
			maxPathLen = (short)decCert.exts.pBasicCons->pathLen;

		if (decCert.exts.pNameCons != NULL)
			names = *decCert.exts.pNameCons;
	}
}


TrustAnchor::TrustAnchor(const ASN::Cert& cert, bool useExts) :
m_createdFromKey(false)
{
	maxPathLen = -1;
	cert.Encode(m_encCert);

	if (useExts)
	{
		if ((cert.exts.pBasicCons != NULL) &&
			(cert.exts.pBasicCons->pathLen > 0))
			maxPathLen = (short)cert.exts.pBasicCons->pathLen;

		if (cert.exts.pNameCons != NULL)
			names = *cert.exts.pNameCons;
	}
}


TrustAnchor::TrustAnchor(const ASN::PublicKeyInfo& key, const ASN::DN& dn,
						 const ASN::SubjKeyIdExtension* pSubjKeyIdExt) :
m_createdFromKey(true)
{
	maxPathLen = -1;

	ASN::Cert tempCert;
	tempCert.serialNumber = 1;
	tempCert.signature = tempCert.algorithm = SNACC::id_dsa_with_sha1;
	tempCert.issuer = tempCert.subject = dn;
	tempCert.pubKeyInfo = key;

	if (pSubjKeyIdExt != NULL)
	{
		tempCert.exts.pSubjKeyID = new ASN::SubjKeyIdExtension(*pSubjKeyIdExt);
		if (tempCert.exts.pSubjKeyID == NULL)
			throw CML_MEMORY_ERR;
	}
				
	tempCert.Encode(m_encCert);
}


///////////////////////////////////////
// Implementation of the Cache class //
///////////////////////////////////////
Cache::Cache(ulong sessionID, ushort maxObjs, time_t timeToLive)
{
	m_sessionID = sessionID;
	m_maxObjs = maxObjs;
	m_timeToLive = timeToLive;
}


///////////////////////////////////////////
// Implementation of the CertCache class //
///////////////////////////////////////////
CertCache::CertCache(ulong sessionID, ushort maxObjs, time_t timeToLive) :
Cache(sessionID, maxObjs, timeToLive)
{
	m_nMRUCerts = 0;

	if (maxObjs == 0)
		m_mruQueue = NULL;
	else
	{
		// Allocate and clear the memory for the MRU queue
		m_mruQueue = new CachedCert*[maxObjs];
		if (m_mruQueue == NULL)
			throw CML_MEMORY_ERR;
		memset(m_mruQueue, 0, sizeof(CachedCert*) * maxObjs);
	}
}


CertCache::~CertCache(void)
{
	EmptyEntireCache();
	
	// Release the MRU queue memory
	if (m_mruQueue != NULL)
		delete[] m_mruQueue;
}


// Adds a validated cert to the cache
const CachedCertRef* CertCache::Add(const CML::Certificate& validCert,
									const CachedCertList& issuerCerts,
									const PolicyTable& authSet,
									const ASN::PolicyMappingList& mappings,
									bool explicitPolFlag,
									const ASN::Time& expireTime,
									const ErrorInfoList& certErrors,
									const ErrorInfoList& pathErrors,
									bool isIssuer)
{
	//Sychronize on the cache mutex.
	ASN::MutexLock cachelock = m_CertCacheMutex.AcquireLock();

	// If the cache is disabled, just return
	if (m_maxObjs == 0)
		return NULL;
	
	// Make sure we are configured to cache certs with errors
	bool hasErrors = false;
	if ((!certErrors.empty()) || (!pathErrors.empty()))
	{
		if (ERRORS_ALLOWED != true)
			return NULL;
		hasErrors = true;
	}

	// Check if this cert is already cached
	CachedCert* pCacheCert = FindCertInternal(validCert.GetEnc());
	if (pCacheCert != NULL)
	{
		// Set this cert as the most recently used
		if (SetAsMRU(*pCacheCert))
		{
			// Lock this cert until we are done with it
			ASN::MutexLock certlock = pCacheCert->m_internalMutex.AcquireLock();
			const bool certLockNeeded = false;
			cachelock.Release();
			// Only update this cert if the cert already has errors and the new cert path
			// does not have any errors or the original cert contains excluded errors and 
			// the new cert path does not have any excluded errors
			ErrorInfoList origCertErrors;
			bool hasCertErrors = pCacheCert->HasCertErrors(&origCertErrors, certLockNeeded);
			ErrorInfoList origPathErrors;
			bool hasPathErrors = pCacheCert->HasPathErrors(&origPathErrors, certLockNeeded);
			if ((( hasCertErrors || hasPathErrors) && (hasErrors == false)) ||
				((hasExcludedError(origCertErrors) || hasExcludedError(origPathErrors)) &&
				 (!(hasExcludedError(pathErrors) || hasExcludedError(certErrors)))))
			{				
				// Acquire global session lock
				ASN::ReadLock sessionlock = CML::Internal::AcquireSessionReadLock(m_sessionID);
				
				// Update this cert's path and path results
				pCacheCert->UpdatePathResults(issuerCerts, authSet,
					GetInitialPolicySet(m_sessionID), mappings, 
					explicitPolFlag, certLockNeeded);
				
				// Update this cert's path and cert errors clearing any old ones
				pCacheCert->UpdateCertErrors(certErrors, true, certLockNeeded);
				pCacheCert->UpdatePathErrors(pathErrors, true, certLockNeeded);				
			}

			// Update this cert's expiration time if cert does not have any errors
			if (!pCacheCert->HasCertErrors(NULL, certLockNeeded) &&
				!pCacheCert->HasPathErrors(NULL, certLockNeeded) &&
				!hasErrors)
					pCacheCert->UpdateExpiration(&expireTime, m_timeToLive, hasErrors, certLockNeeded);
		}
		// else	cert is trusted, so not present in MRU queue
	}
	else
	{
		// Acquire global session lock
		ASN::ReadLock sessionlock = CML::Internal::AcquireSessionReadLock(m_sessionID);

		// Create a new cached cert object
		pCacheCert = CachedCert::Construct(validCert.GetEnc(), issuerCerts, authSet,
			GetInitialPolicySet(m_sessionID), mappings, explicitPolFlag, expireTime,
			m_timeToLive, certErrors, pathErrors);
		
		sessionlock.Release();

		if (pCacheCert == NULL)
			return NULL;

		// Check that space exists in the MRU queue
		bool spaceExists = true;
		if (m_nMRUCerts < m_maxObjs)
		{
			// Shift all of the existing certs in the queue down
			for (ushort i = m_nMRUCerts; i > 0; i--)
				m_mruQueue[i] = m_mruQueue[i - 1];
		}
		else	// MRU queue is full, remove the last unreferenced cert
			spaceExists = RemoveLeastUsed();

		// Only add this cert if space exists
		if (spaceExists)
		{
			// Insert this new cert object into the cache and the head of the
			// MRU queue
			m_certsByHash.insert(CertHashIndex::value_type(pCacheCert->GetHash(),
				pCacheCert));
			m_certsByDN.insert(CertDNIndex::value_type(pCacheCert->base().subject,
				pCacheCert));
			m_mruQueue[0] = pCacheCert;
			m_nMRUCerts++;
		}
		else
		{
			delete pCacheCert;
			return NULL;
		}
	}

	if (isIssuer)
		return new InternalCachedCertRef(*pCacheCert);
	else
		return new ExternalCachedCertRef(*pCacheCert, m_ExternalRefMutex);

}


// Checks if a DN is a trust anchor
bool CertCache::IsDnTrusted(const ASN::DN& dn)
{
	return (m_trustAnchors.find(dn) != m_trustAnchors.end());
}


bool CertCache::IsCachedAndValid(const Certificate& target,
						 const Certificate& issuer) const
{
	// Lock the cache's mutex
	ASN::ReadLock cachelock = m_CertCacheMutex.AcquireReadLock();

	// Check if this cert is already cached
	const CachedCert* pTarget = FindCertInternal(target.GetEnc());
	if (pTarget == NULL)
		return false;

	// Read lock the cert's mutex
	ASN::ReadLock certlock = pTarget->m_internalMutex.AcquireReadLock();
	const bool certLockNeeded = false;
	// Unlock the cache mutex
	cachelock.Release();
	bool result = false;
	try {
		const CachedCertList& targetPath = pTarget->GetPath();
		if (!targetPath.empty() &&
			(targetPath.back().GetRef().GetEnc() == issuer.GetEnc()))
			result = true;
	}
	catch (...) {
		throw;
	}

	return (result && !pTarget->HasPathErrors(NULL, certLockNeeded) &&
			!pTarget->HasCertErrors(NULL, certLockNeeded));

} // end of CertCache::IsCached()


// Empties the cert cache, but does not remove trusted certs
void CertCache::Empty(void)
{
	// Acquire the cert cache lock and external ref lock before continuing
	ASN::MutexLock internalCacheLock = m_CertCacheMutex.AcquireLock();
	ASN::MutexLock externalRefLock = m_ExternalRefMutex.AcquireLock();

	// For each cert in the MRU queue, release its issuer certs
	// (must be done before removal since the issuer cert may be removed before
	// a cert that references it)
	ushort i;
	for (i = 0; i < m_nMRUCerts; i++)
	{
		if (m_mruQueue[i] != NULL) {
			ASN::MutexLock lock = m_mruQueue[i]->m_internalMutex.AcquireLock();
			m_mruQueue[i]->ReleaseIssuers();
		}
	}

	// Remove each of the certs in the MRU queue
	for (i = 0; i < m_nMRUCerts; i++)
	{
		Remove(m_mruQueue[i], false);
		m_mruQueue[i] = NULL;
	}

	m_nMRUCerts = 0;
}


// Empties the entire cert cache, including trusted certs
void CertCache::EmptyEntireCache(void)
{
	// Acquire the cert cache lock and external ref lock before continuing
	ASN::MutexLock internalCacheLock = m_CertCacheMutex.AcquireLock();
	ASN::MutexLock externalRefLock = m_ExternalRefMutex.AcquireLock();

	// First release the references to the Issuers of each cert in the cert cache which 
	// will decrement the reference count (m_nReads) on each of the issuer certs
	CertHashIndex::iterator iHashPair;
	for (iHashPair = m_certsByHash.begin();
	iHashPair != m_certsByHash.end(); ++iHashPair)
	{
		ASN::MutexLock lock = iHashPair->second->m_internalMutex.AcquireLock();
		iHashPair->second->ReleaseIssuers();
	}


	// Delete each of the cached certs
	for (iHashPair = m_certsByHash.begin();
		iHashPair != m_certsByHash.end(); ++iHashPair)
	{
		if (iHashPair->second != NULL)
			delete iHashPair->second;
	}

	// Clear the indices
	m_certsByDN.clear();
	m_certsByHash.clear();

	// Clear the MRU queue, if present
	m_nMRUCerts = 0;
	if (m_mruQueue != NULL)
		memset(m_mruQueue, 0, sizeof(CachedCert*) * m_maxObjs);

	// Clear the trust anchor DN set
	m_trustAnchors.clear();
}


// Finds all cached certs with the specified subject DN
CachedCertList* CertCache::Find(const ASN::DN& subjectDN,
								bool includeBadCerts,
								bool lockNeeded) const
{
	if (lockNeeded)
	{
		ASN::ReadLock lock = m_CertCacheMutex.AcquireReadLock();
		return PrivateFind(subjectDN, includeBadCerts);
	}
	else
		return PrivateFind(subjectDN, includeBadCerts);
}

// Finds all cached certs with the specified subject DN (private form of method)
CachedCertList* CertCache::PrivateFind(const ASN::DN& subjectDN, bool includeBadCerts) const
{
	// Get the number of cached certs with the specified DN
	CertDNIndex::size_type num = m_certsByDN.count(subjectDN);
	if (num == 0)
		return NULL;

	// Find the first cached cert with the specified DN
	CertDNIndex::const_iterator iCert = m_certsByDN.find(subjectDN);
	if (iCert == m_certsByDN.end())
		return NULL;

	// Allocate memory for the resulting CachedCertList
	CachedCertList* pResult = new CachedCertList();
	if (pResult == NULL)
		throw CML_MEMORY_ERR;

	for (CertDNIndex::size_type i = 0; i < num; i++, iCert++)
	{
		// skip certs with errors if necessary
		if ((iCert->second->HasCertErrors() || iCert->second->HasPathErrors()) && (!includeBadCerts))
			continue;

		// Add the cached cert to the resulting list
		pResult->push_back(ExternalCachedCertRef(*iCert->second, m_ExternalRefMutex));
	}

	return pResult;
} // end of CertCache::Find()

// (Private) Finds a cert in the cache using its ASN.1 encoded form
CachedCert* CertCache::FindCertInternal(const ASN::Bytes& encCert) const
{
	// Hash the encoded cert
	ASN::Bytes hash;
	try {
		encCert.Hash(hash);
	}
	catch (...) {
		return NULL;
	}

	// Find the cert
	return FindCertByHashInternal(hash);
}

// Finds a cert in the cache using its ASN.1 encoded form (only called from outside the cache)
const CachedCertRef* CertCache::FindCert(const ASN::Bytes& encCert, bool lockNeeded) const
{
	if (lockNeeded)
	{
		ASN::ReadLock lock = m_CertCacheMutex.AcquireReadLock();
		return PrivateFindCert(encCert);
	}
	else
		return PrivateFindCert(encCert);
}
	
// Finds a cert in the cache using its ASN.1 encoded form (private form of this method)
const CachedCertRef* CertCache::PrivateFindCert(const ASN::Bytes& encCert) const
{
	CachedCert *pCert = FindCertInternal(encCert);
	if (pCert != NULL)
		return new ExternalCachedCertRef(*pCert, m_ExternalRefMutex);
	else
		return NULL;		
}

// Finds a cert in the cache using the hash value
CachedCert* CertCache::FindCertByHashInternal(const ASN::Bytes& hash) const
{
	CertHashIndex::const_iterator iCert = m_certsByHash.find(hash);
	if (iCert == m_certsByHash.end())
		return NULL;
	
	return iCert->second;
}


// Adds a list of trusted certs to the cache
short CertCache::LoadTrustedCerts(const EncCert_LL* trustedCerts,
								  ErrorInfo_List** errInfo)
{
	// Empty the entire cert & crl caches
	EmptyEntireCache();

	// Initialize the error list (if provided)
	if (errInfo != NULL)
		*errInfo = NULL;

	// Create a local ErrorInfoList object
	ErrorInfoList tempErrors;

	bool errorsOccurred = false;
	try {
		// Acquire the cert cache lock and external ref lock before continuing
		ASN::MutexLock internalCacheLock = m_CertCacheMutex.AcquireLock();
		ASN::MutexLock externalRefLock = m_ExternalRefMutex.AcquireLock();

		while (trustedCerts != NULL)
		{
			// Load this trusted certificate
			short result;
			if (errInfo == NULL)
			{
				result = LoadTrustAnchor(ASN::Bytes(trustedCerts->encCert),
					NULL);
			}
			else
			{
				result = LoadTrustAnchor(ASN::Bytes(trustedCerts->encCert),
					&tempErrors);
			}
			if (result == CM_TRUSTED_CERT_ERROR)
				errorsOccurred = true;
			else if (result != CM_NO_ERROR)
				return result;

			trustedCerts = trustedCerts->next;
		}		
	}
	catch (...) {
		EmptyEntireCache();
		throw;
	}

	// Convert the temporary errors into the C linked list
	if (errInfo != NULL)
		*errInfo = tempErrors;

	// Return the appropriate error
	if (errorsOccurred)
		return CM_TRUSTED_CERT_ERROR;

	return CM_NO_ERROR;
}


// Adds a list of trust anchors to the cache
short CertCache::LoadTrustAnchors(const TrustAnchorList& trustAnchors,
								  ErrorInfoList* pErrInfo)
{
	EmptyEntireCache();
	bool errorsOccurred = false;

	try {
		// Acquire the cert cache lock and external ref lock before continuing
		ASN::MutexLock internalCacheLock = m_CertCacheMutex.AcquireLock();
		ASN::MutexLock externalRefLock = m_ExternalRefMutex.AcquireLock();

		TrustAnchorList::const_iterator i;
		for (i = trustAnchors.begin(); i != trustAnchors.end(); ++i)
		{
			// Load this trust anchor
			short result = LoadTrustAnchor(*i, pErrInfo);
			if (result == CM_TRUSTED_CERT_ERROR)
				errorsOccurred = true;
			else if (result != CM_NO_ERROR)
				return result;
		}
	}
	catch (...) {
		EmptyEntireCache();
		throw;
	}

	if (errorsOccurred)
		return CM_TRUSTED_CERT_ERROR;

	return CM_NO_ERROR;
} // end of CertCache::LoadTrustAnchors()


// Adds a single trust anchor into the cache
short CertCache::LoadTrustAnchor(const TrustAnchor& trustAnchor,
								 ErrorInfoList* pErrList)
{
	const CachedCert *pTrustedCert = NULL;

	try {
		// Check if this trust anchor is already cached
		if ((pTrustedCert = FindCertInternal(trustAnchor)) == NULL)
		{
			// Construct a cert cache object
			CachedCert* pNew = CachedCert::Construct(m_sessionID, trustAnchor,
				pErrList);

			// Insert this new cert object into the cache
			// Note:  Since this cert is trusted, it isn't added to the
			// MRU array
			m_certsByHash.insert(CertHashIndex::value_type(pNew->GetHash(),
				pNew));
			m_certsByDN.insert(CertDNIndex::value_type(pNew->base().subject,
				pNew));
			m_trustAnchors.insert(pNew->base().subject);
		}
	}
	catch (ASN::Exception& cmlErr) {
		if (cmlErr == CM_TRUSTED_CERT_ERROR)
			return CM_TRUSTED_CERT_ERROR;
		else
			throw;
	}

	return CM_NO_ERROR;
} // end of CertCache::LoadTrustAnchor()


// Removes this cached cert from the cache and indices
void CertCache::Remove(CachedCert* pCachedCert, bool removeFromMruQueue)
{
	//Internal function only, mutex already locked in caller
	// Find and remove this cert from the CertDNIndex
	std::pair<CertDNIndex::iterator, CertDNIndex::iterator> range =
		m_certsByDN.equal_range(pCachedCert->base().subject);
	for (CertDNIndex::iterator iDN = range.first; iDN != m_certsByDN.end(); ++iDN)
	{
		if (pCachedCert == iDN->second)
		{
			m_certsByDN.erase(iDN);
			break;
		}
	}

	// Find and remove this cert from the CertHashIndex
	CertHashIndex::iterator iHash = m_certsByHash.find(pCachedCert->GetHash());
	if (iHash != m_certsByHash.end())
		m_certsByHash.erase(iHash);

	// If requested, find and remove this cert from the MRU queue
	if (removeFromMruQueue)
	{
		ushort i;
		for (i = 0; (i < m_nMRUCerts) && (m_mruQueue[i] != pCachedCert); i++)
			;
		if (m_mruQueue[i] == pCachedCert)
		{
			// If found, shift all of the lower certs up one
			for (; i < m_nMRUCerts - 1; i++)
				m_mruQueue[i] = m_mruQueue[i + 1];
			--m_nMRUCerts;
		}
	}

	// Release the issuer certs
	ASN::MutexLock lock = pCachedCert->m_internalMutex.AcquireLock();
	pCachedCert->ReleaseIssuers();
	lock.Release();

	// Delete the cached cert object
	delete pCachedCert;
}


// Removes the least used unreferenced cert in the cache
bool CertCache::RemoveLeastUsed(void)
{
	// Mutex must be locked by caller
	bool certRemoved = false;

	// Find the least used unreferenced cert
	for (ushort i = m_nMRUCerts; (i > 0) && !certRemoved; i--)
	{
		// If this cert is unreferenced, remove it
		if (! m_mruQueue[i - 1]->m_mutex.IsReferenced())
		{
			Remove(m_mruQueue[--i], false);
			certRemoved = true;

			// Shift all of the higher certs in the queue down
			for (; i > 0; i--)
				m_mruQueue[i] = m_mruQueue[i - 1];

			// Decrement the number of certs in the MRU queue
			--m_nMRUCerts;
		}
	}

	return certRemoved;
}


// Sets this cached cert as the most recently used
bool CertCache::SetAsMRU(const CachedCert& cachedCert) const
{
	// Find this cert in the MRU queue
	ushort i;
	for (i = 0; (i < m_nMRUCerts) && (m_mruQueue[i] != &cachedCert); i++)
		;

	// Shift all the certs higher in the MRU queue down one and move this cert
	// to the head of the queue
	if (m_mruQueue[i] == &cachedCert)
	{
		CachedCert *tmpCachedCertObj = m_mruQueue[i];
		for (; i > 0; i--)
			m_mruQueue[i] = m_mruQueue[i - 1];
		m_mruQueue[0] = tmpCachedCertObj;

		return true;
	}
	else
		return false;
}


//////////////////////////////////////////
// Implementation of the CacheObj class //
//////////////////////////////////////////
CacheObj::CacheObj(const ASN::Bytes& encObj)
{
	// Hash the encoded object and store the result
	encObj.Hash(m_hash);
}

// Returns true if the object has expired
bool CacheObj::IsExpired(void) const
{
	// Lock the mutex
	ASN::ReadLock lock = m_internalMutex.AcquireReadLock();

    ASN::Time curtime;
	return (curtime > m_validUntil);
}


// Updates the object's expiration time
void CML::Internal::CacheObj::UpdateExpiration(const ASN::Time* pNewExpireTime,
											   time_t ttl, bool hasErrors,
											   bool lockNeeded)
{
	if (lockNeeded)
	{
		// Lock the mutex
		ASN::MutexLock lock = m_internalMutex.AcquireLock();
		// Call the internal form of this method
		PrivateUpdateExpiration(pNewExpireTime, ttl, hasErrors);
	}
	else
		PrivateUpdateExpiration(pNewExpireTime, ttl, hasErrors);
}

// Updates the object's expiration time (called by the non-private form)
void CML::Internal::CacheObj::PrivateUpdateExpiration(const ASN::Time* pNewExpireTime,
											   time_t ttl, bool hasErrors)
{
	// Use the ttl passed in unless this cert has errors. If so, then
	// use the lesser of the ttl passed in or the defined maximum ttl
	// for certs with errors. 
	time_t maxTTL = ttl;
	if ((hasErrors == true) && (ttl > MAX_ERROR_TTL))
		maxTTL = MAX_ERROR_TTL;

	// Get the current date + time to live
	ASN::Time ttlTime(maxTTL + time(NULL));
	
	// Set the object's expiration time to the lesser of the expiration time
	// and the time to live
	if ((pNewExpireTime == NULL) || (ttlTime < *pNewExpireTime))
		m_validUntil = ttlTime;
	else
		m_validUntil = *pNewExpireTime;
}


////////////////////////////////////////////
// Implementation of the CachedCert class //
////////////////////////////////////////////
CachedCert::CachedCert(const ASN::Bytes& encCert) : CML::Certificate(encCert),
													CacheObj(encCert)
{
	// Initialize the path results
	m_pPathResults = NULL;
	m_createdFromKey = false;
}


CachedCert* CachedCert::Construct(const ASN::Bytes& encCert,
								  const CachedCertList& issuerCerts,
								  const PolicyTable& authSet,
								  const ASN::CertPolicyList& initialPolicySet,
								  const ASN::PolicyMappingList& mappings,
								  bool requireExplicitPolicy,
								  const ASN::Time& expireTime, time_t maxTTL,
								  const ErrorInfoList& certErrors, 
								  const ErrorInfoList& pathErrors)
{
	CachedCert* pCertObj = NULL;

	// Construct the CachedCert
	pCertObj = new CachedCert(encCert);
	if (pCertObj == NULL)
		throw CML_MEMORY_ERR;

	try {
		bool hasErrors = false;
		if ((!certErrors.empty()) || (!pathErrors.empty()))
			hasErrors = true;

		// Set the base CacheObj's hash and expiration time
		pCertObj->UpdateExpiration(&expireTime, maxTTL, hasErrors);

		// Update the path results
		pCertObj->UpdatePathResults(issuerCerts, authSet, initialPolicySet,
			mappings, requireExplicitPolicy);

		// Set the cert and path errors
		pCertObj->UpdateCertErrors(certErrors);
		pCertObj->UpdatePathErrors(pathErrors);

		return pCertObj;
	}
	catch (...) {
		delete pCertObj;
		return NULL;
//		throw;
	}
}


CachedCert* CachedCert::Construct(ulong sessionID, const TrustAnchor& trustedCert,
								  CML::ErrorInfoList* pErrInfo)
{
	// Initialize the error flag to false
	bool certHasErrors = false;

	CachedCert* pCertObj = NULL;
	try {
		// Construct the CachedCert
		pCertObj = new CachedCert(trustedCert);
		if (pCertObj == NULL)
			throw CML_MEMORY_ERR;

		// Set the flag that tells us how this CachedCert was created.
		pCertObj->m_createdFromKey = trustedCert.IsCreatedFromKey();

		// Check that the subject DN is present (both a PKIX requirement and
		// a CML limitation)
		if (pCertObj->subject.IsEmpty())
		{
			if (pErrInfo == NULL)
				throw CML_ERR(CM_INVALID_DN);
			pErrInfo->AddError(CM_INVALID_TRUSTED_CERT_DN, *pCertObj);
			certHasErrors = true;
		}

		// Check that the public key algorithm is a signature algorithm
		// and that the parameters are present if required
		if ((pCertObj->pubKeyInfo == gDSA_OID) ||
			(pCertObj->pubKeyInfo == gEC_KEY_OID) ||
			(pCertObj->pubKeyInfo == gOIW_DSA) ||
			(pCertObj->pubKeyInfo == gDSA_KEA_OID))
		{
			if (pCertObj->pubKeyInfo.algorithm.parameters == NULL)
			{
				if (pErrInfo == NULL)
					throw CML_ERR(CM_MISSING_PARAMETERS);
				pErrInfo->AddError(CM_TRUSTED_CERT_MISSING_PARAMETERS,
					pCertObj->subject);
				certHasErrors = true;
			}
		}
		else if (pCertObj->pubKeyInfo != gRSA_OID)
		{
			if (pErrInfo == NULL)
				throw CML_ERR(CM_NOT_SIG_KEY);
			pErrInfo->AddError(CM_TRUSTED_CERT_NOT_SIG_KEY,
				pCertObj->subject);
			certHasErrors = true;
		}		

		// Check the signature on the cert if it is self-signed
		if (IsSelfSigned(pCertObj->base()))
		{
			// Check that the two signature algorithms on the cert are the same
			if (pCertObj->signature != pCertObj->algorithm)
			{
				if (pErrInfo == NULL)
					throw CML_ERR(CM_TRUSTED_CERT_SIG_INVALID);
				pErrInfo->AddError(CM_SIGNATURE_ALG_MISMATCH,
					pCertObj->subject);
				certHasErrors = true;
			}

			// Verify the signature on the certificate
			short err = Internal::VerifySignature(sessionID,
				pCertObj->GetEnc(), pCertObj->pubKeyInfo);
			if (err == CM_SIGNATURE_INVALID)
			{
				if (pErrInfo == NULL)
					throw CML_ERR(CM_TRUSTED_CERT_SIG_INVALID);
				pErrInfo->AddError(CM_CERT_SIGNATURE_INVALID,
					pCertObj->subject);
				certHasErrors = true;
			}
			else if (err == CM_NO_TOKENS_SUPPORT_SIG_ALG)
			{
				if (pErrInfo == NULL)
					throw CML_ERR(err);
				pErrInfo->AddError(CM_NO_TOKENS_SUPPORT_CERT_SIG_ALG,
					pCertObj->subject);
				certHasErrors = true;
			}
			else if (err != CM_NO_ERROR)
				throw CML_ERR(err);
		}

		// Check that the cert is valid
		ASN::Time currentTime;
		if (currentTime < pCertObj->validity.notBefore)
		{
			if (pErrInfo == NULL)
				throw CML_ERR(CM_TRUSTED_CERT_NOT_YET_VALID);
			pErrInfo->AddError(CM_CERT_NOT_YET_VALID, pCertObj->subject);
			certHasErrors = true;
		}
		else if (currentTime > pCertObj->validity.notAfter)
		{
			if (pErrInfo == NULL)
				throw CML_ERR(CM_TRUSTED_CERT_EXPIRED);
			pErrInfo->AddError(CM_CERT_EXPIRED, pCertObj->subject);
			certHasErrors = true;
		}

		// If the trusted cert has errors, throw generic exception
		if (certHasErrors)
			throw CML_ERR(CM_TRUSTED_CERT_ERROR);

		// Set the expiration time of this cached cert to it's expiration time
		pCertObj->m_validUntil = pCertObj->validity.notAfter;

		// If there is a name constraint or max path length set in the TrustAnchor object
		// set them now in the cached cert.

		pCertObj->maxPathLen = trustedCert.maxPathLen;
		pCertObj->names = trustedCert.names;

		return pCertObj;

	} // end of try block
	catch (...) {
		delete pCertObj;
		throw;
	}
}


CachedCert::~CachedCert(void)
{
	ASN::MutexLock lock = this->m_internalMutex.AcquireLock();
	// Clear the list of issuer certificates
	m_path.clear();

	// Free the PathOutputs
	if (m_pPathResults != NULL)
		delete m_pPathResults;
}


void CachedCert::ExportPathResults(CML::ValidatedKey& validKey, bool lockNeeded) const
{
	if (lockNeeded)
	{
		// Read lock the mutex
		ASN::ReadLock lock = m_internalMutex.AcquireReadLock();
		// Call the internal form of this method
		PrivateExportPathResults(validKey);
	}
	else
		PrivateExportPathResults(validKey);
}

void CachedCert::PrivateExportPathResults(CML::ValidatedKey& validKey) const
{
	// Clear the validated key
	validKey.Clear();

	try {
		// Copy the public key
		validKey.m_pubKeyInfo = pubKeyInfo;
		
		// Copy the public key parameters, if required and not present in
		// the subject cert
		if ((validKey.m_pubKeyInfo.algorithm.parameters == NULL) &&
			((validKey.m_pubKeyInfo == gDSA_OID) ||
			(validKey.m_pubKeyInfo == gEC_KEY_OID) ||
			(validKey.m_pubKeyInfo == gKEA_OID) ||
			(validKey.m_pubKeyInfo == gOIW_DSA) ||
			(validKey.m_pubKeyInfo == gDSA_KEA_OID)))
		{
			validKey.m_pubKeyInfo.algorithm.parameters =
				GetPubKeyParameters(validKey.m_pubKeyInfo.algorithm.algorithm);
		}
		
		// Copy the cached path results
		if (m_pPathResults != NULL)
		{
			validKey.authPolicies = m_pPathResults->authPolicies;
			validKey.userPolicies = m_pPathResults->userPolicies;
			validKey.mappings = m_pPathResults->mappings;
			validKey.explicitPolicyFlag = m_pPathResults->explicitPolicyFlag;
		}

		// Copy the Key Usage extension if present
		if (exts.pKeyUsage != NULL)
		{
			validKey.pKeyUsage = new ASN::KeyUsageExtension(*exts.pKeyUsage);
			if (validKey.pKeyUsage == NULL)
				throw CML_MEMORY_ERR;
		}

		// Copy the Extended Key Usage extension if present
		if (exts.pExtKeyUsage != NULL)
		{
			validKey.pExtKeyUsage = new ASN::ExtKeyUsageExtension(*exts.pExtKeyUsage);
			if (validKey.pExtKeyUsage == NULL)
				throw CML_MEMORY_ERR;
		}
	}
	catch (...) {
		validKey.Clear();
		throw;
	}
} // end of CachedCert::ExportPathResults()


void CachedCert::GetPath(CertPath& thePath) const
{
	ASN::ReadLock lock = m_internalMutex.AcquireReadLock();

	// Construct a temporary CertificationPath object from the subject cert
	ASN::CertificationPath theAsnPath(base());

	// Add the issuer certs to the path
	// Since the issuers certs must be reverse order in the CertificationPath,
	// push each cert to the front of the path
	CachedCertList::const_iterator i;
	for (i = m_path.begin(); i != m_path.end(); ++i)
		theAsnPath.caCerts.push_front(&(const CachedCert&)(*i));

	thePath = theAsnPath;
}


// Finds and copies the parameters from the path for the specified OID
ASN::Bytes* CachedCert::GetPubKeyParameters(const char* pkOID) const
{
	const ASN::Cert* pCert = this;
	//CachedCertList::const_reverse_iterator iIssuer = m_path.rbegin(); //m_path is mutable
    CachedCertList::const_reverse_iterator iIssuer = m_path.rbegin();
	do
	{
		// Check that this cert's public key algorithm matches the specified
		// OID
		if (pCert->pubKeyInfo != pkOID)
			return NULL;

		// If this cert's parameters are present, copy them and return
		if (pCert->pubKeyInfo.algorithm.parameters != NULL)
		{
			ASN::Bytes* pResult = new ASN::Bytes(
				*pCert->pubKeyInfo.algorithm.parameters);
			if (pResult == NULL)
				throw CML_MEMORY_ERR;
			return pResult;
		}
		else	// Try the issuers' certs
		{
			// If no more issuers are left to try, set pCert to NULL
			if (iIssuer == m_path.rend())
				pCert = NULL;
			else
			{
				pCert = &((const CachedCert&)*iIssuer).base();
				iIssuer++;
			}
		}
	} while (pCert != NULL);

	return NULL;
} // end of CachedCert::GetPubKeyParameters()


bool CachedCert::HasCertErrors(ErrorInfoList* pErrors, bool lockNeeded) const
{
	if (lockNeeded)
	{
		// Read lock the mutex
		ASN::ReadLock lock = m_internalMutex.AcquireReadLock();
		// Call the internal form of this method
		return PrivateHasCertErrors(pErrors);
	}
	else
		return PrivateHasCertErrors(pErrors);
}

bool CachedCert::PrivateHasCertErrors(ErrorInfoList* pErrors) const
{
	bool hasErrors = (!m_certErrors.empty());
	if (hasErrors && (pErrors != NULL))
	// Return a copy the errors if requested
	{
		*pErrors = m_certErrors;
	}
	return hasErrors;
}


bool CachedCert::HasPathErrors(ErrorInfoList* pErrors, bool lockNeeded) const
{
	if (lockNeeded)
	{
		// Read lock the mutex
		ASN::ReadLock lock = m_internalMutex.AcquireReadLock();
		// Call the internal form of this method
		return PrivateHasPathErrors(pErrors);
	}
	else
		return PrivateHasPathErrors(pErrors);
}

bool CachedCert::PrivateHasPathErrors(ErrorInfoList* pErrors) const
{
	// Flag for the non-policy related errors
	bool hasErrors = (!m_pathErrors.empty()); 
	// Flag for the policy related errors
	bool hasPolicyError = false;

	// Return a copy the non-policy errors if requested
	if (hasErrors && (pErrors != NULL))
	{
		pErrors->Insert(m_pathErrors);
	}	

	// If the explicit-policy-indicator is set, check that
	// neither the authorities-constrained-policy-set
	// nor the user-constrained-policy-set is empty
	if (m_pPathResults && m_pPathResults->explicitPolicyFlag)
	{
		if (m_pPathResults->authPolicies.empty())
		{
			hasPolicyError = true;
			if (pErrors != NULL)
			{
				pErrors->AddError(CM_INVALID_CERT_POLICY,
					*this);
			}
		}
		else if (m_pPathResults->userPolicies.empty())
		{
			hasPolicyError = true;
			if (pErrors != NULL)
			{
				pErrors->AddError(CM_MISSING_USER_CERT_POLICY,
					*this);
			}
		}			
	}
	
	return (hasErrors || hasPolicyError);	
}
	
	
// Updates the cert errors associated with this cached cert
void CachedCert::UpdateCertErrors(const ErrorInfoList &certErrors, bool clear, bool lockNeeded)
{
	if (lockNeeded)
	{
		// Lock the mutex
		ASN::MutexLock lock = m_internalMutex.AcquireLock();
		// Call the internal form of this method
		PrivateUpdateCertErrors(certErrors, clear);
	}
	else
		PrivateUpdateCertErrors(certErrors, clear);
}


// Updates the cert errors associated with this cached cert (internal form of this method)
void CachedCert::PrivateUpdateCertErrors(const ErrorInfoList &certErrors, bool clear)
{
	if (clear)
		m_certErrors = certErrors;
	else
		m_certErrors.Insert(certErrors);
}


// Updates the path errors associated with this cached cert
void CachedCert::UpdatePathErrors(const ErrorInfoList &pathErrors, bool clear, bool lockNeeded)
{
	if (lockNeeded)
	{
		// Lock the mutex
		ASN::MutexLock lock = m_internalMutex.AcquireLock();
		// Call the internal form of this method
		PrivateUpdatePathErrors(pathErrors, clear);
	}
	else
		PrivateUpdatePathErrors(pathErrors, clear);
}
	
	
// Updates the path errors associated with this cached cert (internal form of this method)
void CachedCert::PrivateUpdatePathErrors(const ErrorInfoList &pathErrors, bool clear)
{
	if (clear)
		m_pathErrors = pathErrors;
	else
		m_pathErrors.Insert(pathErrors);
}


// Updates the path processing results and issuer certs
void CachedCert::UpdatePathResults(const CachedCertList& issuerCerts,
								   const PolicyTable& authSet,
								   const CML::ASN::CertPolicyList& initialPolicySet,
								   const CML::ASN::PolicyMappingList& mappings,
								   bool requireExplicitPolicy,
								   bool lockNeeded)
{
	if (lockNeeded)
	{
		// Lock the mutex
		ASN::MutexLock lock = m_internalMutex.AcquireLock();
		// Call the internal form of this method
		PrivateUpdatePathResults(issuerCerts, authSet, initialPolicySet,
								 mappings, requireExplicitPolicy);
	}
	else
		PrivateUpdatePathResults(issuerCerts, authSet, initialPolicySet,
								 mappings, requireExplicitPolicy);
}
	
	
// Updates the path processing results and issuer certs (internal form of this method)
void CachedCert::PrivateUpdatePathResults(const CachedCertList& issuerCerts,
								   const PolicyTable& authSet,
								   const CML::ASN::CertPolicyList& initialPolicySet,
								   const CML::ASN::PolicyMappingList& mappings,
								   bool requireExplicitPolicy)
{
	try {
		// Release the references to any existing issuer certs
		ReleaseIssuers();
		
		// Clear the existing PathOutputs
		if (m_pPathResults != NULL)
		{
			m_pPathResults->authPolicies.clear();
			m_pPathResults->userPolicies.clear();
			m_pPathResults->mappings.clear();
		}
		else
		{
			// Allocate memory for the path results
			m_pPathResults = new PathOutputs;
			if (m_pPathResults == NULL)
				throw CML_MEMORY_ERR;
		}
		
		// Copy the list of issuer certs
		m_path = issuerCerts;
		
		// Get the authority-constrained-policy-set
		authSet.GetAuthPolicySet(m_pPathResults->authPolicies);
		
		// Calculate the user-constrained-policy-set
		m_pPathResults->userPolicies = m_pPathResults->authPolicies &
			initialPolicySet;

		// Copy the policy mappings for this certificate
		m_pPathResults->mappings = mappings;

		// Copy the require-explicit-policy flag
		m_pPathResults->explicitPolicyFlag = requireExplicitPolicy;
		
	}
	catch (...) {
		// Release the references to any existing issuer certs
		ReleaseIssuers();

		// Delete the PathOutputs
		delete m_pPathResults;
		m_pPathResults = NULL;

		throw;
	}
}


// Releases the issuer certs
void CachedCert::ReleaseIssuers(void)
{
	// This cert must be locked prior to calling this method

	// Clear the list of issuer certificates
	// This will clear the destroy all the CachedCertRefs which will release decrement
	// the reference count (m_nReads)
	m_path.clear();
}


///////////////////////////////////////////////
// Implementation of the CachedCertRef class //
///////////////////////////////////////////////
CachedCertRef::CachedCertRef(const CachedCert& cachedCert) :
m_pCert(&cachedCert), m_cachedCertLock(cachedCert.m_mutex.AcquireReadLock())
{
}

CachedCertRef::CachedCertRef(const CachedCertRef& that) :
m_pCert(that.m_pCert), m_cachedCertLock(that.GetRef().m_mutex.AcquireReadLock())
{
}

///////////////////////////////////////////////////////
// Implementation of the InternalCachedCertRef class //
///////////////////////////////////////////////////////
InternalCachedCertRef::InternalCachedCertRef(const CachedCert& cachedCert) :
CachedCertRef(cachedCert)
{
}

InternalCachedCertRef::InternalCachedCertRef(const InternalCachedCertRef& that) :
CachedCertRef(that)
{
}

///////////////////////////////////////////////////////
// Implementation of the ExternalCachedCertRef class //
///////////////////////////////////////////////////////
ExternalCachedCertRef::ExternalCachedCertRef(const CachedCert& cachedCert, const ASN::ReadWriteMutex& cacheMutex) :
CachedCertRef(cachedCert), m_certCacheLock(cacheMutex.AcquireReadLock())
{
}

ExternalCachedCertRef::ExternalCachedCertRef(const ExternalCachedCertRef& that) :
CachedCertRef(that),m_certCacheLock(that.m_certCacheLock)
{
}

////////////////////////////////////////////////
// Implementation of the CachedCertList class //
////////////////////////////////////////////////
CachedCertList& CachedCertList::operator=(const CachedCertList& that)
{
	if (this != &that)
	{
		clear();

		CachedCertList::const_iterator i;
		for (i = that.begin(); i != that.end(); ++i)
			push_back(*i);
	}

	return *this;
}

bool CachedCertList::operator==(const CachedCertList& rhs) const
{
	CachedCertList::const_iterator iLHS = begin();
	CachedCertList::const_iterator iRHS = rhs.begin();

	do
	{
		// if both iterators are not at end or both are not valid return false
		if ((iLHS == end()) ^ (iRHS == rhs.end()))
			return false;

		// if both iterators do not point to the same cached item, return false
		if (iLHS->GetAddr() != iRHS->GetAddr())
			return false;

		iLHS++;
		iRHS++;

	// stop only when both iterators are at the end
	} while ((iLHS != end()) && (iRHS != rhs.end()));
	return true;
}


/************************************************************************
 FUNCTION:  CompareBytesPtrs()
 
 Description: This function compares the two Bytes_struct and returns true
 if they are identical, or false otherwise.
*************************************************************************/
bool CML::Internal::CompareBytesPtrs(const Bytes_struct *a,
									 const Bytes_struct *b)
{
	// If both pointers are the same, return true
	if (a == b)
		return true;

	// If one of the pointers is NULL, return false
	if ((a == NULL) || (b == NULL))
		return false;

	// If both are empty, return true
	if ((a->num == 0) && (b->num == 0))
		return true;

	// If the lengths aren't equal, return false
	if (a->num != b->num)
		return false;

	// If either one has invalid data, return false (the lengths must be 
	// positive and neither pointer can be NULL)
	if ((a->num < 0) || (a->data == NULL) || (b->data == NULL))
		return false;

	// Compare the data values, if they are identical, return true, else
	// return false
	if (memcmp(a->data, b->data, a->num) == 0)
		return true;
	else
		return false;
} // end of CompareBytesPtrs()


/************************************************************************
 FUNCTION:  CompareUniqueIDs()
 
 Description: This function compares the two optional ASN.1
 UniqueIdentifiers and returns true if they are identifical, or false
 otherwise.
*************************************************************************/
bool CML::Internal::CompareUniqueIDs(const SNACC::UniqueIdentifier* pFirstID,
									 const SNACC::UniqueIdentifier* pSecondID)
{
	if (pFirstID == pSecondID)
		return true;

	if ((pFirstID == NULL) || (pSecondID == NULL))
		return false;

	return (*pFirstID == *pSecondID);
}


/************************************************************************
 FUNCTION:  IsSelfSigned()
 
 Description:  This function returns true if the certificate appears to
 be self-signed, otherwise false is returned.  If the authKeyMustMatch
 parameter is true, then the authority key identifier must be present and
 match for true to be returned.
*************************************************************************/
bool CML::Internal::IsSelfSigned(const ASN::Cert& cert,
								 bool authKeyMustMatch)
{
	// Check that the cert is self-issued
	if (!cert.IsSelfIssued())
		return false;

	try {
		// Check that the public key algorithm matches the algorithm used to
		// sign the cert
		if (cert.pubKeyInfo != SplitSigHashAlg(cert.algorithm.algorithm))
			return false;
	}
	catch (...) {
		return false;
	}

	// Check if the authority key identifier extension matches if present
	if (cert.exts.pAuthKeyID != NULL)
	{
		const ASN::AuthKeyIdExtension& authKeyExt = *cert.exts.pAuthKeyID;

		// Compare the subject and issuer key identifiers, if both present
		if ((cert.exts.pSubjKeyID != NULL) && (authKeyExt.keyID != NULL) &&
			(*cert.exts.pSubjKeyID != *authKeyExt.keyID))
			return false;

		// Compare the serial number if present
		if ((authKeyExt.authCertSerialNum != NULL) &&
			*authKeyExt.authCertSerialNum != cert.serialNumber)
			return false;

		// Compare the issuer name if present
		if (authKeyExt.authCertIssuer != NULL)
		{
			if (authKeyExt.authCertIssuer->IsPresent(cert.issuer))
				return true;

			// Also check the issuer alternative names if present
			if ((cert.exts.pIssuerAltNames != NULL) &&
				authKeyExt.authCertIssuer->IsOnePresent(*cert.exts.pIssuerAltNames))
				return true;
			
			return false;
		}
	}
	else if (authKeyMustMatch)
		return false;

	return true;
}


#ifdef _OLD_CODE
TrustAnchor_LL* convertTrustAnchors(const EncCert_LL* pCerts)
{
	TrustAnchor_LL* pResult = NULL;
	TrustAnchor_LL* pPrev = NULL;
	while (pCerts != NULL)
	{
		TrustAnchor_LL* pNew = (TrustAnchor_LL*)
			calloc(1, sizeof(TrustAnchor_LL));
		if (pNew == NULL)
		{
			freeTrustAnchorWrappers(pResult);
			return NULL;
		}

		if (pPrev == NULL)
			pResult = pNew;
		else
			pPrev->next = pNew;
		pPrev = pNew;
		pNew->cbSize = sizeof(TrustAnchor_LL);
		pNew->anchorFlag = TrustAnchor_LL::CM_TRUSTED_CERT;
		pNew->anchor.encCert = pCerts->encCert;
		pNew->maxPathLen = -1;

		pCerts = pCerts->next;
	}

	return pResult;
}


void freeTrustAnchorWrappers(TrustAnchor_LL* pList)
{
	// Free the converted trust anchor wrapper structures
	while (pList != NULL)
	{
		TrustAnchor_LL* pNext = pList->next;
		free(pList);
		pList = pNext;
	}
}
#endif // _OLD_CODE


// end of CM_cache.cpp
