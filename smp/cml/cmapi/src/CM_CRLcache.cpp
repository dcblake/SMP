/*****************************************************************************
File:     CM_CRLcache.cpp
Project:  Certificate Management Library
Contents: Implementation of the CrlCache and CachedCRL classes.

Created:  20 May 2002
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	19 September 2003

Version:  2.3

*****************************************************************************/

////////////////////
// Included Files //
////////////////////
#include "CM_cache.h"



// Using declarations
using namespace CML;
using namespace CML::Internal;

#ifdef NOCRL
//////////////////////////////////////////
// Implementation of the CrlCache class //
//////////////////////////////////////////
CrlCache::CrlCache(ulong sessionID, ushort maxObjs, time_t timeToLive) :
Cache(sessionID, maxObjs, timeToLive)
{
	m_nMRUCrls = 0;

	if (maxObjs == 0)
		m_crls = NULL;
	else
	{
		// Allocate and clear the memory for the MRU CRL array
		m_crls = new CachedCRL*[maxObjs];
		if (m_crls == NULL)
			throw CML_MEMORY_ERR;
		memset(m_crls, 0, sizeof(CachedCRL*) * maxObjs);
	}
}

CrlCache::~CrlCache(void)
{
	// Acquire the lock on the mutex
	ASN::MutexLock lock = this->m_mutex.AcquireLock();

	// Release the MRU CRL array
	if (m_crls != NULL)
		delete[] m_crls;

	// Delete each of the cached certs
	for (CrlHashIndex::iterator iHashPair = m_crlsByHash.begin();
		iHashPair != m_crlsByHash.end(); ++iHashPair)
	{
		if (iHashPair->second != NULL)
			delete iHashPair->second;
	}

	// Clear the indices
	m_crlsByGN.clear();
	m_crlsByHash.clear();
}

// Adds a validated CRL to the cache
const CachedCRL* CrlCache::Add(const CML::CRL& validCRL,
							   const ASN::GenName& distPtName,
							   const ASN::Time* pExpireTime)
{
	// If the cache is disabled, just return
	if (m_maxObjs == 0)
		return NULL;

	// If this CRL is a delta CRL, just return
	if ((validCRL.base().crlExts.pDeltaCRL != NULL) ||
		(validCRL.base().crlExts.pBaseUpdate != NULL))
		return NULL;

	// Acquire the lock on the mutex
	ASN::MutexLock lock = this->m_mutex.AcquireLock();

	// Check if this CRL is already cached
	CachedCRL* pCachedCRL = PrivateFindCRL(validCRL);
	if (pCachedCRL != NULL)
	{
		// Set this CRL as the most recently used
		SetAsMRU(pCachedCRL);

		// Update this CRL's expiration time
		pCachedCRL->UpdateExpiration(pExpireTime, m_timeToLive);
	}
	else
	{
		// Create a new cached CRL object
		try {
			pCachedCRL = new CachedCRL(validCRL, distPtName, pExpireTime,
				m_timeToLive);
		}
		catch (...) {
			return NULL;
		}

		// Check that space exists in the MRU queue
		bool spaceExists = true;
		if (m_nMRUCrls < m_maxObjs)
		{
			// Shift all of the existing certs in the queue down
			for (ushort i = m_nMRUCrls; i > 0; i--)
				m_crls[i] = m_crls[i - 1];
		}
		else	// MRU CRL array is full, remove the last unreferenced CRL
			spaceExists = RemoveLeastUsed();

		// Only add this CRL if space exists
		if (spaceExists)
		{
			// Insert this new cached CRL object into the cache and the head
			// of the MRU array
			m_crlsByHash.insert(CrlHashIndex::value_type(pCachedCRL->GetHash(),
				pCachedCRL));
			m_crlsByGN.insert(CrlGNIndex::value_type(distPtName, pCachedCRL));
			m_crls[0] = pCachedCRL;
			m_nMRUCrls++;
		}
		else
		{
			delete pCachedCRL;
			pCachedCRL = NULL;
		}
	}

	return pCachedCRL;
} // end of CrlCache::Add()


// Checks if a CRL is in the cache
bool CrlCache::IsCached(const ASN::Bytes& hash)
{
	// Acquire the lock on the mutex
	ASN::MutexLock lock = this->m_mutex.AcquireLock();

	// Check if this CRL is already cached
	CachedCRL* pCachedCrl = FindCrlByHash(hash);
	if (pCachedCrl == NULL)
		return false;

	// Check if the cert has expired
	if (pCachedCrl->IsExpired())
		return false;

	// Set this CRL as the MRU
	SetAsMRU(pCachedCrl);
	return true;
}


// Empties the CRL cache
void CrlCache::Empty(void)
{
	// Acquire the lock on the mutex
	ASN::MutexLock lock = this->m_mutex.AcquireLock();

	// Remove each of the CRLs in the MRU array
	for (ushort i = 0; i < m_nMRUCrls; i++)
	{
		Remove(m_crls[i], false);
		m_crls[i] = 0;
	}

	m_nMRUCrls = 0;
}


// Finds all cached CRLs from the specified distribution point
CachedCrlList* CrlCache::Find(const ASN::GenName& distPtName,
							  CachedCrlList* pPrevList) const
{
	// Acquire the lock on the mutex
	ASN::MutexLock lock = this->m_mutex.AcquireLock();

	// Get the number of cached CRLs from the specified distribution point
	// and the first one
	CrlGNIndex::size_type num = m_crlsByGN.count(distPtName);
	CrlGNIndex::const_iterator iCrl = m_crlsByGN.find(distPtName);
	if ((num == 0) || (iCrl == m_crlsByGN.end()))
		return pPrevList;

	// If the previous list is NULL, allocate memory for the result
	if (pPrevList == NULL)
	{
		pPrevList = new CachedCrlList;
		if (pPrevList == NULL)
			throw CML_MEMORY_ERR;
	}

	for (CrlGNIndex::size_type i = 0; i < num; ++i)
	{
		if (iCrl->second == NULL)
			throw CML_ERR(CM_NULL_POINTER);

		// Add a pointer to the cached CRL to the resulting list
		pPrevList->push_back(iCrl->second);

		// Move to the next cached CRL
		++iCrl;
	}

	return pPrevList;
} // end of CrlCache::Find()


// Finds a CRL in the cache using its ASN.1 encoded form
CachedCRL* CrlCache::PrivateFindCRL(const ASN::Bytes& encCRL)
{
	// Hash the encoded CRL
	ASN::Bytes hash;
	encCRL.Hash(hash);

	// Find and return the CRL using its hash value
	return FindCrlByHash(hash);
}


// Finds a CRL in the cache using its ASN.1 encoded form
CachedCRL* CrlCache::FindCRL(const ASN::Bytes& encCRL)
{
	// Acquire the lock to the mutex
	ASN::MutexLock lock = this->m_mutex.AcquireLock();
	return PrivateFindCRL(encCRL);
}


// Finds a CRL in the cache using the hash value
CachedCRL* CrlCache::FindCrlByHash(const ASN::Bytes& hash) const
{
	CrlHashIndex::const_iterator iCrl = m_crlsByHash.find(hash);
	if (iCrl == m_crlsByHash.end())
		return NULL;
	else
		return iCrl->second;
}

// Removes this cached CRL from the cache and indices
void CrlCache::Remove(CachedCRL* pCachedCRL, bool removeFromMruQueue)
{
	// Find and remove this CRL from the CrlDNIndex
	for (CrlGNIndex::iterator iGN = m_crlsByGN.begin(); iGN !=
		m_crlsByGN.end(); ++iGN)
	{
		if (pCachedCRL == iGN->second)
		{
			m_crlsByGN.erase(iGN);
			break;
		}
	}

	// If requested, find and remove this CRL from the MRU array
	if (removeFromMruQueue)
	{
		ushort i;
		for (i = 0; (i < m_nMRUCrls) && (m_crls[i] != pCachedCRL); i++)
			;
		if (i < m_nMRUCrls)
		{
			// If found, shift all of the lower certs up one
			for (; i < m_nMRUCrls - 1; i++)
				m_crls[i] = m_crls[i + 1];
			--m_nMRUCrls;
		}
	}

	// Find and remove this CRL from the CrlHashIndex
	CrlHashIndex::iterator iHash = m_crlsByHash.find(pCachedCRL->GetHash());
	if (iHash != m_crlsByHash.end())
		m_crlsByHash.erase(iHash);

	// Delete the cached CRL
	delete pCachedCRL;

} // end of CrlCache::Remove()


// Removes the least used CRL in the cache
bool CrlCache::RemoveLeastUsed(void)
{
	bool crlRemoved = false;

	// Find the least used unreferenced cert
	for (ushort i = m_nMRUCrls; (i > 0) && !crlRemoved; i--)
	{
		// If this cert is unreferenced, remove it
		if (m_crls[i - 1]->m_mutex.IsReferenced())
		{
			Remove(m_crls[--i], false);
			crlRemoved = true;

			// Shift all of the higher certs in the queue down
			for (; i > 0; i--)
				m_crls[i] = m_crls[i - 1];

			// Decrement the number of certs in the MRU queue
			--m_nMRUCrls;
		}
	}

	return crlRemoved;
}


// Sets this cached CRL as the most recently used
bool CrlCache::SetAsMRU(CachedCRL* pCachedCRL) const
{
	// Find this CRL in the MRU queue
	ushort i;
	for (i = 0; (i < m_nMRUCrls) && (m_crls[i] != pCachedCRL); i++)
		;

	// Shift all the certs higher in the MRU queue down one and move this cert
	// to the head of the queue
	if (m_crls[i] == pCachedCRL)
	{
		for (; i > 0; i--)
			m_crls[i] = m_crls[i - 1];
		m_crls[0] = pCachedCRL;

		return true;
	}
	else
		return false;
}


///////////////////////////////////////////
// Implementation of the CachedCRL class //
///////////////////////////////////////////
CachedCRL::CachedCRL(const CRL& validCRL, const ASN::GenName& distPtName,
					 const ASN::Time* pExpireTime, time_t maxTTL) :
ASN::CertificateList(validCRL.base()), m_distPtName(distPtName),
CacheObj(validCRL)
{
	UpdateExpiration(pExpireTime, maxTTL);
}
#endif


// end of CM_CRLcache.cpp
