/*****************************************************************************
File:     CM_cache.h
Project:  Certificate Management Library
Contents: Header file for the internal cache classes and functions used in
		  the Certificate Management Library.

Created:  20 October 2000
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>
		  Tom Horvath <Tom.Horvath@DigitalNet.com>

Last Updated:	14 April 2004

Version:  2.4

*****************************************************************************/
#ifndef _CM_CACHE_H_
#define _CM_CACHE_H_

////////////////////
// Included Files //
////////////////////
#include "CM_internal.h"



// Begin CML namespace
namespace CML {

// Begin nested Internal namespace
namespace Internal {



///////////////////////
// Defined Constants //
///////////////////////
const time_t SECONDS_IN_DAY = 60 * 60 * 24;	// Number of seconds in 24 hours
const ushort DEFAULT_CACHE_OBJS	= 100;
const short CMI_CACHE_MISSING_ISSUER = 2001;


// Forward declarations
class CachedCert;


///////////////////////////////
// PolicyTable class definition
//
// Contains the X.509 authorities-
// constrained-policy-set path
// processing variable
//
class PolicyTable
{
public:
	// Constructor/Destructor
	PolicyTable()							{ m_depth = 0; }

	// Methods
	void Init(int numCerts);
	bool IsEmpty() const;
	bool IsUserPolicySetEmpty(const ASN::CertPolicyList& initialPolicySet) const;
	void GetAuthPolicySet(ASN::CertPolicyList& authSet) const;
	void ProcessMappings(const ASN::PolicyMappingList* pMappings,
		ushort nDepth, bool inhibitMapping,
		ASN::PolicyMappingList& mappingDetails);
	void ProcessPolicies(const ASN::CertPolicyList* pPolicies, ushort nDepth,
		bool inhibitAnyPolicy, bool isSelfIssuedCA);

protected:
	// Internal types
	typedef std::vector<ASN::CertPolicy>	PolicyRow;
	typedef std::vector<PolicyRow>			PolicyArray;

	// Class constant -- the special any-policy OID
	static const SNACC::AsnOid kAnyPolicy;

	// Member variables
	PolicyArray	m_table;
	ushort m_depth;
};


////////////////////////////
// Cache class definition //
////////////////////////////
class Cache
{
public:
	enum ObjType {
		CERT,
		TRUSTED_CERT
	};

	struct ObjId
	{
		Bytes_struct hash;
		CM_DN dn;
	};

	// Constructs a Cache object
	Cache(ulong sessionID, ushort maxObjs, time_t timeToLive);

	virtual void Empty(void) = 0;			// Empties the cache

protected:
	// Members
	ulong m_sessionID;			// Handle to the CM session
	ushort m_maxObjs;
	time_t m_timeToLive;
};


// CacheObj class definition
class CacheObj
{
public:
	// Constructor/Destructor
	CacheObj(const ASN::Bytes& encObj);
	// Gets the object's hash value
	const ASN::Bytes& GetHash(void) const				{ return m_hash; }
	// Returns true if the object has expired
	bool IsExpired(void) const;
	// Updates the object's expiration time
	void UpdateExpiration(const ASN::Time* pNewExpireTime, time_t ttl, bool hasErrors,
		bool lockNeeded = true);
	const ASN::Time& GetCurrentExpirationTime() const				{ return m_validUntil; }

	// Member
	ASN::ReadWriteMutex m_mutex;			// cached cert mutex used by CachedCertRefs  
											// for automatic read locking.
	ASN::ReadWriteMutex	m_internalMutex;	// this mutex was added so that a lock can be
											// achieved among methods that are in this class
											// and any derived classes.

protected:
	// Members
	ASN::Bytes m_hash;				// Hash of encoded object
	ASN::Time m_validUntil;	// Time when object is no longer valid

private:
	void PrivateUpdateExpiration(const ASN::Time* pNewExpireTime, time_t ttl, bool hasErrors);

};

//CachedCertRef - two cache reference classes derive from this base class
class CachedCertRef
{
public:
	// Constructors
	CachedCertRef(const CachedCert& cachedCert);
	CachedCertRef(const CachedCertRef& that);
	// Destructor
	virtual ~CachedCertRef()					{}

	// Conversion operator
	virtual operator const CachedCert&() const	{ return *m_pCert; }

	// Access the cached cert
	virtual const CachedCert& GetRef() const	{ return *m_pCert; }
	// Access the address of the cached cert
	virtual const CachedCert* GetAddr() const	{ return m_pCert; }

protected:
	// Members
	const CachedCert* m_pCert;		// Pointer to cached cert
	ASN::ReadLock m_cachedCertLock;	// Lock for cached cert
};

// InternalCachedCertRef class definition used to reference cached certs in the cert 
// cache itself
class InternalCachedCertRef : public CachedCertRef
{
public:
	// Constructors
	InternalCachedCertRef(const CachedCert& cachedCert);
	InternalCachedCertRef(const InternalCachedCertRef& that);
};

// ExternalCachedCertRef class definition used to reference cached certs in code that is 
// external to the cert cache
class ExternalCachedCertRef : public CachedCertRef
{
public:
	// Constructors
	ExternalCachedCertRef(const CachedCert& cachedCert, const ASN::ReadWriteMutex& cacheMutex);
	ExternalCachedCertRef(const ExternalCachedCertRef& that);

private:
	// Members
	ASN::ReadLock m_certCacheLock;			// Lock for entire cert cache
};


// CachedCertList class definition
class CachedCertList : public std::list<CachedCertRef>
{
public:
	// Assignment operator
	CachedCertList& operator=(const CachedCertList& that);
	// Comparison operators
	bool operator==(const CachedCertList& rhs) const;
};


// Other CachedCert type definitions
typedef std::map<ASN::Bytes, CachedCert*> CertHashIndex;
typedef std::multimap<ASN::DN, CachedCert*> CertDNIndex;
typedef std::set<ASN::DN> DnList;


// CertCache class definition
class CertCache : public Cache
{
public:
	// Constructors/Destructor
	CertCache(ulong sessionID, ushort maxObjs = DEFAULT_CACHE_OBJS,
		time_t timeToLive = SECONDS_IN_DAY);
	virtual ~CertCache(void);

	// Get a ReadLock on the cache
	ASN::ReadLock AcquireReadLock() const	{ return m_CertCacheMutex.AcquireReadLock(); }

	// Adds a validated cert to the cache
	const CachedCertRef* Add(const Certificate& validCert,
		const CachedCertList& issuerCerts, const PolicyTable& authSet,
		const ASN::PolicyMappingList& mappings, bool explicitPolFlag,
		const ASN::Time& expireTime, const ErrorInfoList& certErrors,
		const ErrorInfoList& pathErrors, bool isIssuer = false);

	// Checks if the target cert is valid (free of errors) and in the cache and
	// signed by the specified issuer
	bool IsCachedAndValid(const Certificate& target, const Certificate& issuer) const;

	// Checks if the DN matches the DN of one of the trust anchors
	bool IsDnTrusted(const ASN::DN& dn);

	// Empties the cert cache
	void Empty(void);

	// Finds all cached certs with the specified subject DN 
	CachedCertList* Find(const ASN::DN& subjectDN, bool includeBadCerts,
						 bool lockNeeded = true) const;

	// Finds a cert in the cache using its ASN.1 encoded form
	const CachedCertRef* FindCert(const ASN::Bytes& encCert, bool lockNeeded = true) const;

protected:
	// Members
	CertHashIndex m_certsByHash;			// Certs sorted by hash
	CertDNIndex m_certsByDN;				// Certs sorted by DN
	ushort m_nMRUCerts;						// Number of certs in MRU queue
	CachedCert** m_mruQueue;				// Certs ordered by MRU
	DnList m_trustAnchors;					// List of DNs of the trust anchors
	ASN::ReadWriteMutex m_CertCacheMutex;	// Mutex used only by Cert Cache methods
	ASN::ReadWriteMutex m_ExternalRefMutex;	// Mutex for External Cached Cert Refs


private:
	// Empty the entire cert cache (including the trusted certs)
	void EmptyEntireCache(void);

	// Finds a cert in the cache using the hash value (private form of method)
	CachedCert* FindCertByHashInternal(const ASN::Bytes& hash) const;

	// Finds a cert in the cache using its ASN.1 encoded form (private form of method)
	CachedCert* FindCertInternal(const ASN::Bytes& encCert) const;

	// Finds all cached certs with the specified subject DN (private form of method)
	CachedCertList* PrivateFind(const ASN::DN& subjectDN, bool includeBadCerts) const;

	// Finds a cert in the cache using its ASN.1 encoded form (private form of this method)
	const CachedCertRef* PrivateFindCert(const ASN::Bytes& encCert) const;



	// Load the list of trusted certs into the cache
	short LoadTrustedCerts(/*CM_TOKEN_TYPE *pTokObj,*/ const EncCert_LL* trustedCerts,
		ErrorInfo_List** errInfo = NULL);
	short LoadTrustAnchors(/*CM_TOKEN_TYPE *pTokObj,*/ const TrustAnchorList& trustAnchors,
		ErrorInfoList* pErrInfo = NULL);

	// Load a single trusted cert into the cache
	short LoadTrustAnchor(/*CM_TOKEN_TYPE *pTokObj,*/ const TrustAnchor& trustAnchor,
		ErrorInfoList* pErrList);

	// Removes this cached cert from the cache and indices - 
	// callers of this method *MUST* lock the cert cache mutex before calling this method!!!
	void Remove(CachedCert* pCachedCert, bool removeFromMruQueue = true);

	// Removes the least used unreferenced cert in the cache
	bool RemoveLeastUsed(void);

	// Sets this cached cert as the most recently used
	bool SetAsMRU(const CachedCert& pCachedCert) const;

	// Friend functions
	friend short CML::SetTrustedCerts(ulong sessionID,
		const ASN::BytesList& trustedCerts, ErrorInfoList* pErrInfo);
	friend short CML::SetTrustAnchors(ulong sessionID,
		const TrustAnchorList& trustAnchors, ErrorInfoList* pErrInfo);
	friend short ::CM_SetTrustedCerts(ulong sessionID,
		EncCert_LL* trustedCerts, ErrorInfo_List** errInfo);
	friend SrlSession::SrlSession(CallbackFunctions& cmlFuncs,
		EncCert_LL** ppTrustedSrlCerts,
		PExtFreeEncCertList* FreeEncCertListFP);
	friend void Session::Initialize(ulong sessionID,
		const InitSettings_struct& settings,
		ASN::MutexLock& mgrLock);
};


// CachedCert class definition
class CachedCert : public CacheObj, public Certificate
{
public:
	// Constructs this validated certificate object
	static CachedCert* Construct(const ASN::Bytes& encCert,
		const CachedCertList& issuerCerts, const PolicyTable& authSet,
		const ASN::CertPolicyList& initialPolicySet,
		const ASN::PolicyMappingList& mappings, bool requireExplicitPolicy,
		const ASN::Time& expireTime, time_t maxTTL,
		const ErrorInfoList& certErrors, const ErrorInfoList& pathErrors);
	virtual ~CachedCert(void);

	// Returns true if the cert has any cert or path errors
	bool HasCertErrors(ErrorInfoList* pErrors = NULL, bool lockNeeded = true) const;
	bool HasPathErrors(ErrorInfoList* pErrors = NULL, bool lockNeeded = true) const;

	// Returns true if the cached cert is trusted
	bool IsTrusted(void) const						{ return (m_pPathResults == NULL); }
	// Returns true if this cached cert was created from a trust anchor that was created from a public key and DN
	virtual bool IsCreatedFromKey()	const			{ return m_createdFromKey; }

	// Copies the cached path results (and public key parameters if necessary)
	// into the ValidKey_struct
	void ExportPathResults(ValidatedKey& validKey, bool lockNeeded = true) const;

	// Get the cached path
	const CachedCertList& GetPath() const			{ return m_path; } // Read lock the cert's mutex
																	   // before calling this GetPath()
	void GetPath(CertPath& thePath) const;

	// Gets the ASN.1 encoded cert
	const ASN::Bytes& GetEncCert() const			{ return encCert; }

	// Updates the path processing results and issuer certs
	void UpdatePathResults(const CachedCertList& issuerCerts,
		const PolicyTable& authSet, const ASN::CertPolicyList& initialPolicySet,
		const ASN::PolicyMappingList& mappings, bool requireExplicitPolicy,
		bool lockNeeded = true);

	// Replace path and cert errors
	void UpdateCertErrors(const ErrorInfoList& certErrors, bool clear = false,
		bool lockNeeded = true);
	void UpdatePathErrors(const ErrorInfoList& pathErrors, bool clear = false,
		bool lockNeeded = true);

	// Releases the references to the issuer certs
	void ReleaseIssuers(void);

	// Friends
	friend short CertCache::LoadTrustAnchor(/*CM_TOKEN_TYPE *pTokObj,*/ const TrustAnchor& trustAnchor,
		ErrorInfoList* pErrList);

	//Members
	short maxPathLen;							// Maximum length of paths (only for TrustAnchors)
	ASN::NameConstraintsExtension names;		// Name constraints for paths (only for TrustAnchors)

private:
	// Private constructor
	CachedCert(const ASN::Bytes& encCert);
	// Constructs this trusted certificate object
	static CachedCert* Construct(ulong sessionID,
		const TrustAnchor& trustedCert, ErrorInfoList* pErrInfo = NULL);
	// Finds and copies the parameters from the path for the specified OID
	ASN::Bytes* GetPubKeyParameters(const char* pkOID) const;
	
	// Internal version of public methods which do not lock the cert's mutex
	bool PrivateHasCertErrors(ErrorInfoList* pErrors = NULL) const;
	bool PrivateHasPathErrors(ErrorInfoList* pErrors = NULL) const;
	void PrivateUpdateCertErrors(const ErrorInfoList& certErrors, bool clear = false);
	void PrivateUpdatePathErrors(const ErrorInfoList& pathErrors, bool clear = false);
	void PrivateExportPathResults(ValidatedKey& validKey) const;
	void PrivateUpdatePathResults(const CachedCertList& issuerCerts,
		const PolicyTable& authSet, const ASN::CertPolicyList& initialPolicySet,
		const ASN::PolicyMappingList& mappings, bool requireExplicitPolicy);

	// Members
	PathOutputs* m_pPathResults;		// Results of validating this cert
	CachedCertList m_path;				// Issuer certs (starting from root)
	ErrorInfoList m_certErrors;			// Cert errors if any
	ErrorInfoList m_pathErrors;			// Path errors if any
	bool m_createdFromKey;						// Indicates if this cert was created from a DN & Key
};


} // end of nested Internal namespace
} // end of CML namespace



#endif /* _CM_CACHE_H_ */
