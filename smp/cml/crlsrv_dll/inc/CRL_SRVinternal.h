/*************************************************************************
File:     CRL_SRVinternal.h
Project:  Certificate Management Library
Contents: Header file for the internal (low-level) functions used in the
          Certificate Management Library

Created:  9 February 2004
Author:   Tom Horvath <Tom.Horvath@DigitalNet.com>

Last Updated:  27 Jan 2005

Version:  2.5

*****************************************************************************/
#ifndef _CRL_INTERNAL_H
#define _CRL_INTERNAL_H
#include "cmapi_cpp.h"
#include "cmlasn.h"
#include "crlapi.h"
#include <set>

#define CRL_ERR(err)			CRLException(err, __FILE__, __LINE__)


#ifndef uchar
   typedef unsigned char uchar;
#endif

#define CRL_ALREADY_PROCESSING							3000

namespace CRLSRV {

#define CRL_HASH_TABLESIZE 512
#define CRL_HASH_INDEXMASK 0x1FF
#define CRL_HASH_INDEXSHIFT 9

typedef void *HashTable[CRL_HASH_TABLESIZE];
typedef std::set<CML::ASN::Bytes> BytesSet;
typedef std::list<CML::CRL> CrlList;

// Forward declarations
class AbstractCRLContext;
class RevocationState;
class CRLHeader;

// DBIdSet Class Definition
class DBIdSet : public std::set<long>
{
public:
   //Copy items from another set into this set.
   void Merge(const DBIdSet& that);
};


// Revocation Class Definition
class Revocation
{
public:
	Revocation();
	~Revocation();
	void Set (char *key, size_t keyLen, CML::ASN::Bytes *SerNum, RevCerts_LL *revs);
	const char *GetKey();			// Get the issuer
	void SetKey(char *key);			// Set the issuer
	size_t GetKeyLen();				// Get the issuer byte length
	const CML::ASN::Bytes *GetSerialNumber(); // Get the serial number
	void SetSerialNumber(CML::ASN::Bytes *SerialNumber); // Set the serial number
	RevCerts_LL *GetRevocation();	// Get the revocation entry
private:
	// Member variables
	char					*m_key;			// The original unhashed value used to make the key
	size_t					m_keyLen;						
	const CML::ASN::Bytes	*m_serialNumber;// Serial Number of revoked cert
	RevCerts_LL				*m_revCert;		// Revocation entry


};


typedef struct Slot
{
	int    leaf;
	ulong   hash;
	Revocation *value;
	HashTable *table;
} Slot;


class RevocationState
{
public:
	RevocationState(
	   ulong sessionID,		                          // CML Session ID
	   const bool stopRefresh,                        // CRL Header Refresh flag
	   const CML::ASN::Time* pValidationTime = NULL) :// Optional TimeStamp time
	   crlSessionID(sessionID), stopRefresh(stopRefresh),
      m_pValidationTime(pValidationTime)	
	   { pBaseCRLCtx = NULL; pCRLToRefresh = NULL;}

	BytesSet prevEncCerts;        // previously encoded certs being processed
	BytesSet prevEncCRLs;         // previously encoded CRLs being processed
	const AbstractCRLContext* pBaseCRLCtx; // When a cert is already being
                                 // processed we use this field to hold the
                                 // TemporaryCRLContext the base CRL if a delta
                                 // is being processed
	CRLHeader* pCRLToRefresh;     // Address of the CRL being refreshed by 
											// CRL refresh thread
	const ulong crlSessionID;     // The CRL session ID to use
	const bool stopRefresh;       // Flag that specifies if the CRL Service 
											// Thread should stop refreshing CRL Headers
	const CML::ASN::Time* m_pValidationTime;  // Optional validation time to use when  
                                 // checking revocation.
   DBIdSet m_CRLDbIds;           // DBIDs of each CRL that was used to determine
                                 // revocation status of a single certificate.
};


class CRLHeader
{
public:
	CRLHeader();
	~CRLHeader();
	bool Init(const CML::CRL& crl, ulong crlSessionID, bool valid, time_t maxTTL);
   bool IsSameCRL(const CML::ASN::CertificateList& crl, bool crlLockNeeded = true) const;
	void UpdateHeader(const CML::CRL& crl, bool valid, 
					  time_t maxTTL, bool crlLockNeeded = true);
	bool UpdateHeaderFromDelta(const CML::CRL& crl, bool valid,
							   time_t maxTTL, bool crlLockNeeded = true);

	// These methods do not acquire a read lock, so a CachedCRLContext must be created first
	bool CheckForRevocation(const CML::Certificate& decCert, RevInfo* pRevInfo, 
		                     const CML::ASN::Time* pValidationTime) const;
	bool IsValid() const;
	bool IsExpired(bool crlLockNeeded = true) const;
	bool MatchesScope(CML::ASN::CertType certType, const CML::ASN::DN& certIssuer,
				  const CML::ASN::DistributionPoint* pDistPt, bool isCritical,
				  const CML::ASN::RevocationReasons* pReasons) const;
	void Refresh(const bool& stopRefresh);

	//Members
	// The Issuer DN from the Base CRL
	CML::ASN::DN					m_CRLIssuer;
	// This update time from Base CRL
	CML::ASN::Time					m_ThisUpdate;
	// Next update time from Base CRL
	CML::ASN::Time					*m_pNextUpdate;
	// Optional CRL Number from the Base CRL
	CML::ASN::CRLNumberExtension	*m_pCrlNumber;
	// Optional Issuing Distribution Point Extension from the Base and Delta CRL
	CML::ASN::IssuingDistPointExtension	*m_pIssuingDistPtExt;
	// Optional Delta CRL info from the base CRL
	CML::ASN::FreshestCrlExtension	*m_pFreshestCRL;

	// Optional CRL Number from the latest Delta CRL
	CML::ASN::CRLNumberExtension	*m_pDeltaCrlNumber;
	// Optional this update time from latest Delta CRL. This field will always be 
	// present after a delta CRL was processed
	CML::ASN::Time					*m_pDeltaThisUpdate;
	// Optional next update time from latest Delta CRL
	CML::ASN::Time					*m_pDeltaNextUpdate;

   // DBID of the base CRL with which this CRL Header is associated.
   long m_baseDBID;
   // DBID of the delta CRL with which this CRL Header is associated.
   long m_deltaDBID;

	// CRLHeader mutex used by CachedCRLContext for automatic read locking.	
	CML::ASN::ReadWriteMutex		m_mutex;
	
protected:
	ulong							m_CRLSessionID;		// Session ID to use when refreshing
	
private:
   bool AddRevs2Hash(const CML::ASN::CertificateList& InCRL);
	void Clear();
	void PrivateUpdateHeader(const CML::CRL& crl, 
							 bool valid, time_t maxTTL);
	bool PrivateUpdateHeaderFromDelta(const CML::CRL& crl,
									  bool valid, time_t maxTTL);
   bool PrivateIsSameCRL(const CML::ASN::CertificateList& crl) const;


	// Members
	HashTable						*m_revHashTable;	// The hash table holding all the revocations that this
	// Maximum time to live in the cache
	CML::ASN::Time					m_validUntil;
	// Tells whether or not this CRL Header is valid or not
	bool							m_valid;

	// Friends
	friend const AbstractCRLContext* generateTemporaryCRLCtx(const CML::CRL& crl, 
		short& cmlResult, RevocationState& state);
	friend void retrieveRemoteCRLs(const CRLHeader& crl, long typeMask, CrlList& crls, const bool& stopRefresh);
};


class AbstractCRLContext
{
public:
	virtual ~AbstractCRLContext()	{}
	virtual const CRLHeader& GetRef() const = 0;
	virtual bool IsCRLCached() const = 0;
};


class CachedCRLContext : public AbstractCRLContext
{
public:
	CachedCRLContext(const CRLHeader& crlHeader);
	CachedCRLContext(const CachedCRLContext& that);
	~CachedCRLContext();
	const CRLHeader& GetRef() const									{ return m_crlHeader; }
	bool IsCRLCached() const										{ return true; }

protected:
	// Members
	const CRLHeader& m_crlHeader;

private:
	CML::ASN::ReadLock m_CRLHeaderLock;		// Holds the automatic lock to the cached CRLHeader
};


class TemporaryCRLContext : public AbstractCRLContext
{
public:
	TemporaryCRLContext(const CML::CRL& crl);
	TemporaryCRLContext(const TemporaryCRLContext& that);
	~TemporaryCRLContext();
	const CRLHeader& GetRef() const									{ return m_crlHeader; }
	bool IsCRLCached() const										{ return false; }

protected:
	// Members
	CRLHeader m_crlHeader;
};


typedef std::multimap<CML::ASN::GenName, CRLHeader*> CrlGNIndex;
typedef std::list<const CachedCRLContext*> CachedCRLCtxList;


class CRLHeaderCache : protected std::list<CRLHeader>
{
public:
	CRLHeaderCache(ulong crlSessionID) : 
		m_crlSessionID(crlSessionID)					{ m_stopRefresh = false; }
	const CachedCRLContext* Add(const CML::CRL& crl, bool valid, 
								time_t maxTTL, CRLHeader* pCrlToUpdate = NULL);
	void Empty();
	void Find(const CML::ASN::GenName& issuer, CachedCRLCtxList& crlHeaders,
			  CRLHeader *pCRLToRefresh = NULL) const;
	bool IsEmpty() const								{ return empty(); }
	void Refresh();

	//Members
	bool						m_stopRefresh;		// set to true by Empty() when the cache is to be emptied  
													// and checked by Refresh() before refreshing the next CRL
													// also set to true with the CRLSession is being destructed
protected:	
	CrlGNIndex					m_crlsByGN;			// CRL Headers sorted by GenName
	CML::ASN::ReadWriteMutex	m_cacheMutex;		// Mutex used only by cache methods
	const ulong					m_crlSessionID;		// CRL session ID
};


// Session settings
class CRLSession
{
public:
   // Constructor/Destructor
   CRLSession();
   ~CRLSession();
   CRLSession(const CRLSession& that); // Needed by SessionMap
   void StopServiceThread();

   // Methods
   void EmptyCache();
   void Initialize(ulong crlSessionID, const CRLDLLInitSettings_struct& settings);
   const SearchBounds &GetBoundsFlag()	const    { return boundsFlag; }
   CRLHeaderCache *GetCRLHeaderCache() const    { return pCrlHeaderCache; }
   ulong GetCMLSessionID() const                { return cmlSessionID; }
   time_t GetCRLRefreshPeriod() const           { return crlRefreshPeriod; }
   time_t GetCRLGracePeriod() const             { return crlGracePeriod; }
   const SRLCallbackFunctions &GetSRLFunc() const  { return *srlFuncs; }
   ulong GetLocalSRLSessionID() const     { return m_localSRLSessionID; }

private:
   // Member variables
   SearchBounds   boundsFlag;       // SearchBounds used when calling CRL::Validate
   CRLHeaderCache *pCrlHeaderCache; // The RAM CRL Header cache
   ulong          cmlSessionID;     // CML Session ID 
   time_t         crlRefreshPeriod; // How long to wait between CRL updates 
   time_t         crlGracePeriod;   // Maximim time that a CRL is considered to be valid 
                                    // after the Next Update time has passed 
   SRLCallbackFunctions* srlFuncs;  // SRL callback functions
   ulong          m_localSRLSessionID; // SRL session used to store/retrieve CRLs
                                       // for this session only.

	// Methods
#ifndef NOTHREADS
	bool terminateSvcThread;			// Set to true when CRLSession is destructed
#ifdef WIN32 
	HANDLE serviceThreadID;
	static DWORD WINAPI ServiceThread(void* inargs);
#else //WIN32
	pthread_t serviceThreadID;
	static void* ServiceThread(void* inargs);
#endif //WIN32
#endif //NOTHREADS

};

// CRL_MgrInfo Class Definition
typedef std::map<ulong, CRLSession> SessionMap;

class CRL_MgrInfo
{
public:
	// Methods
	ulong AddSession(const CRLDLLInitSettings_struct& settings);
	void DeleteSession(ulong sessionID);
	CRLSession& GetSession(ulong sessionID);

private:
	ulong GenRandomSessionID(const void* address) const;

	SessionMap m_sessions;
	CML::ASN::ReadWriteMutex mMutex;
};


// Function Prototypes for Internal Use
void EmptyCRLCache(ulong sessionID);
CRLHeaderCache& GetCRLCache(ulong sessionID);
ulong GetCMLSessionID(ulong sessionID);
const SearchBounds &GetBoundsFlag(ulong sessionID);
time_t GetCRLRefreshPeriod(ulong sessionID);
time_t GetCRLGracePeriod(ulong sessionID);
const SRLCallbackFunctions &GetSRLFunc(ulong sessionID);
ulong GetLocalSRLSessionID(ulong sessionID);
const AbstractCRLContext* generateTemporaryCRLCtx(const CML::CRL& crl,
                short& cmlResult, RevocationState& state);

// Function Prototypes for hash routines
ulong CRLMakeHash(char *k, ulong length);
HashTable *CRLInitHash();
void CRLDestroyHash(HashTable *&pHashTbl);
bool CRLInsert (HashTable *table, Revocation *element, ulong hash);
bool CRLCheckForAndReturnValue (HashTable *table, ulong hash, char *key,
								int keylen, CRLSRV::Revocation **value);

// Function Prototypes for free routines
void FreeRevCerts_LL(RevCerts_LL *pRevEntries);

} // end namespace

#endif //_CRL_INTERNAL_H
