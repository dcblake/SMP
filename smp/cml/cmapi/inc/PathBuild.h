/*************************************************************************
File:     PathBuild.h
Project:  Certificate Management Library
Contents: Header file for the internal path building classes and functions
		  used in the Certificate Management Library

Created:  13 March 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  12 March 2004

Version:  2.4

*****************************************************************************/
#ifndef _PATH_BUILD_H
#define _PATH_BUILD_H


////////////////////
// Included Files //
////////////////////
#include "CM_cache.h"

#ifdef _MSC_VER
	#pragma warning(push, 3)			// Set warning level to 3 for STL headers
	#include <stack>
	#pragma warning(pop)				// Reset warning level
	#pragma warning(disable: 4512)		// Disable assignment op not generated warning
#else
	#include <stack>
#endif


// Begin CML namespace
namespace CML {

// Begin nested Internal namespace
namespace Internal {


///////////////////////
// Defined Constants //
///////////////////////
const short CMI_INITIAL_LOC		= 0x0100;		// External data passed in
const short CMI_CACHE_LOC		= 0x0200;		// CertCache location

const short CMI_PATH_ALREADY_FOUND		= 3001;
const short CMI_EXCEEDED_PROBABILITY	= 3002;
const short CMI_CERT_HAS_ERRORS			= 3003;
const short CMI_VALID_CERT_NOT_CACHED	= 3004;
const short CMI_INVALID_CERT_NOT_CACHED = 3005;
const short CMI_CACHED_PATH_VALIDATION_ERROR = 3006;


////////////////////////////////
// Type and Class Definitions //
////////////////////////////////
typedef std::list<const CML::Certificate*> CertPtrList;
typedef std::list<ASN::NameForms> ReqNameForms;

// Forward declarations
class BaseNode;
class NodePool;


// PermittedSubtrees class definition
// Contains the set of permitted subtrees specifications
// within which all subject names in the certs in the path must fall
class PermittedSubtrees : public std::list<ASN::GeneralSubtrees>
{
public:
	bool IsNameWithin(const ASN::DN& dn) const;
	bool AreNamesWithin(const ASN::GenNames& names) const;
};


// StateVars class definition
// Contains the X.509 path processing variables
// and variable initialization and update functions
class StateVars
{
public:
	// Constructor
	StateVars(
		ulong sessionID,            // CML Session ID
		PathState& state,			    // The state of the certification path
		int pathLen,                // The length of the path
		const ASN::Time* pValidationTime = NULL); // Opt time to use for validation

	// Methods
	void Update(const ASN::Cert& cert, bool isEE);

	// Member variables
	PolicyTable authTable;			// Authority-constrained-policy table
	PermittedSubtrees permitted;	// List of permitted subtrees
	ASN::GeneralSubtrees excluded;	// Excluded subtrees
	ReqNameForms reqNames;			// List of required-name-forms
	bool explicitPolicy;			// Explicit-policy-indicator flag
	bool noPolicyMapping;			// Policy-mapping-inhibit-indicator flag
	bool inhibitAnyPolicy;			// Inhibit-any-policy-indicator flag
	ushort pathDepth;				// Cert number currently being processed
	short pendingExplicitPolicy;	// Explicit-policy-pending value
	short pendingPolicyMapping;		// Policy-mapping-inhibit-pending value
	short pendingAnyPolicy;			// Inhibit-any-policy-pending value
	short maxPathDepth;				// Maximum path length permitted
	ASN::PolicyMappingList mappings; // Policy mappings that have occurred
	ASN::Time pathExpiration;		// Expiration time for the path
	ASN::Bytes* pParams;			// Optional inherited DSA parameters
	const ASN::Time* m_pValidationTime;// Optional time to use for valication
	PathState& state;				// PathState used when validating CRL issuer paths
};


// Location class definition
//
class Location
{
public:
	enum LocEnum
	{
		Uninitialized,
		Application,
		Cache,
		RAM,
		Client,
		Server,
		X500_DSA,
		AllSearched
	};

	Location(LocEnum location = Uninitialized);
	Location(short locMask);
	Location(SearchBounds boundsFlag);

	// Comparison operators
	bool operator==(const Location& rhs) const	{ return (m_loc == rhs.m_loc); }
	bool operator!=(const Location& rhs) const	{ return !operator==(rhs); }
	bool operator==(LocEnum location) const;
	bool operator!=(LocEnum location) const		{ return !operator==(location); }
	bool operator<(LocEnum location) const;
	bool operator>(LocEnum location) const;

	// Conversion operators
	operator const char*() const;

	// Convert the location into a short bitmask
	operator short() const						{ return short(m_loc >> 2); }

	bool IsLastLoc(const Location& theLoc) const;
	bool IsSearchAllSet() const;
	bool UpdateLoc(const Location& furthestLoc, const Location& searchLocs);

protected:
	long m_loc;		// Used as a bit mask to represent multiple locations
};


// List of BaseNode pointers
typedef std::list<BaseNode*> BaseNodePtrList;
typedef std::deque<BaseNode*> BaseNodePtrDeck;

// PathStack class definition
class PathStack : protected BaseNodePtrDeck
{
public:
	// Constructor
	PathStack()										{}
	virtual ~PathStack(void)						{ clear(); }

	// Operations
	void Clear(void)								{ clear(); }
	void Push(BaseNode* pNode)						{ push_front(pNode); }
	void Pop(void)									{ if (!empty()) pop_front(); }
	BaseNode* PopBottom(void);
	bool IsEmpty(void)								{ return empty(); }
	bool IsPresent(const BaseNode* pNode) const;
	size_type Size() const							{ return size(); }
	const BaseNodePtrDeck& Deck() const				{ return *this; }
	void GetForwardPath(const BaseNode* pSubject, CertPtrList& path) const;
	void Print(PrintXML& logXML, CMLogLevel level) const;

	// Comparison operators
	bool operator==(const PathStack& rhs) const;
	bool operator!=(const PathStack& rhs) const		{ return !operator==(rhs); }
	bool operator<(const PathStack& rhs) const;
};


// List of PathProbability objects
typedef std::map<PathStack, float> PathProbMap;


// PathLink class definition
class PathLink
{
public:
	// Constructors/Destructor
	PathLink(BaseNode* pIssuerNode, const BaseNode& subjNode);
	virtual ~PathLink(void)							{ m_pathProbs.clear(); }

	// Operators
	bool operator==(const BaseNode* pNode) const	{ return (m_pIssuer == pNode); }
	bool operator!=(const BaseNode* pNode) const	{ return (m_pIssuer != pNode); }
	bool operator<(const PathLink& rhs) const		{ return (m_linkProb < rhs.m_linkProb); }

	// Operations
	void AddPath(const PathStack& curPath, float curProb);
	void ClearPaths()								{ m_pathProbs.clear(); }
	short BuildNextPath(NodePool& thePool, const Location& loc,
		PathStack& curPath, PrintXML& logXML, float minProb, float curProb);
	BaseNode* GetIssuerNode() const					{ return m_pIssuer; }
	float GetLinkProb() const						{ return m_linkProb; }
	void ZeroizeLinkProb()							{ m_linkProb = 0; }
	float GetPathProb(const PathStack& pathSoFar) const;
	void SetPathProb(const PathStack& path, float curProb);
	bool IsPathInPathProbMap(const PathStack& pathSoFar) const;
	bool IsNewSubject(const PathStack& pathSoFar) const;
	float GeneratePathProbability(float curProb) const;
	bool LeadsToCompletePath() const				{ return m_leadsToCompletePath; }

private:
	// Members
	BaseNode* const m_pIssuer;			// Pointer to issuer's cert node
	float m_linkProb;					// Probability this CA issued the cert
	PathProbMap m_pathProbs;			// List of paths and their probabilities
	bool m_leadsToCompletePath;			// a valid path was found through this node

	// Private member function
	short CalcLinkProbability(const ASN::Cert& subjCert);

};


// List of PathLink objects
typedef std::list<PathLink> PathLinkList;

#define CM_DEFAULT_REASON			""
#define CM_BELOWTHRESHOLD_REASON	"(zeroized - below threshold)"
#define CM_REPEATED_REASON			"(zeroized - cert or DN repeated)"
#define CM_PATHLENVIOLATION_REASON	"(reduced - path length violated)"
#define CM_EXCLUDED_REASON			"(excluded)"

// BaseNode class definition
class BaseNode
{
public:
	// Constructors/Destructor
	static BaseNode* Construct(ulong sessionID,
		const ASN::Bytes& asn1Cert);
	virtual ~BaseNode()										{}

	// Operations
	// Function to add another BaseNode as an issuer of this one
	PathLinkList::iterator BaseNode::AddIssuer(BaseNode* pIssuer);
	// Function to add an issuer cert from a cached path
	void AddCachedIssuer(BaseNode* pIssuer, const PathStack& curPath,
		float curProb);
	void DetermineError(ErrorInfoList& errors, PathStack& curPath,
		PrintXML& logXML, float minProb = 0, float curProb = 1);
	bool FindAndZeroizeIssuer(const BaseNode* pIssuerNode);

	// Virtual functions
	virtual short BuildCachedPath(NodePool& thePool, const Location& loc,
		PathStack& curPath, PrintXML& logXML, float curProb, const CachedCertList& cachedCerts,
		CachedCertList::const_reverse_iterator iCachedCert);
	virtual short BuildNextPath(NodePool& thePool, const Location& loc,
		PathStack& curPath, PrintXML& logXML, float minProb = 0, float curProb = 1,
		float* pBestProb = NULL);
	virtual const Certificate& GetCert() const = 0;
	virtual bool HasCertErrors(ErrorInfoList *pErrors = NULL) const
				{ return false; }
	virtual bool HasPathErrors(ErrorInfoList *pErrors = NULL) const
				{ return false; }
	virtual bool IsCached() const							{ return false; }
	virtual bool IsTrusted() const							{ return false; }
	virtual bool IsCreatedFromKey() const					{ return false; }

	// Comparison operators
	bool operator==(const BaseNode& rhs) const;
	bool operator==(const ASN::Bytes& bytes) const;
	bool operator==(const Bytes_struct& bytes) const;

	// Public member variables
	const ulong m_hSession;			// Handle to CM session
	ErrorInfoList m_certErrors;		// List of X.509 errors caused by cert

protected:
	BaseNode(ulong sessionID);

	// Member variables
	PathLinkList m_issuerList;		// List of possible issuers
	PathLinkList::iterator m_iList;	// Current issuer
	Location m_lastLoc;				// Last location searched

private:
	// Function to add potential issuer certs to this PathNode
	int AddIssuers(BaseNodePtrList& issuers, PathStack& curPath,
		float curProb);
	float ChooseNextIssuer(const PathStack& path, PrintXML& logXML, float curProb,
		float minProb, bool isLastLoc = true);
	short FindIssuers(NodePool& thePool, const Location& loc,
		PathStack& curPath, PrintXML& logXML, float curProb);
	float FindMaxProbability(const PathStack& path);

	// Member variables
	bool m_newAdded;
};


// PathNode class definition
class PathNode : public BaseNode
{
public:
	// Constructor
	PathNode(ulong sessionID, const Certificate& cert) :
		BaseNode(sessionID), m_cert(cert)				{}

	// Operations
	virtual const Certificate& GetCert() const			{ return m_cert; }

	// Public member variable
	const Certificate m_cert;		// Decoded certificate
};


// CachedCertNode class definition
class CachedCertNode : public BaseNode
{
public:
	// Constructors/Destructor
	CachedCertNode(ulong sessionID, const CachedCert& cachedCert);

	// Operations
	virtual short BuildNextPath(NodePool& thePool, const Location& loc,
		PathStack& curPath, PrintXML& logXML, float minProb = 0, float curProb = 1,
		float* pBestProb = NULL);
	virtual const Certificate& GetCert() const		{ return m_cachedCert; }
	virtual bool HasCertErrors(ErrorInfoList *pErrors = NULL,
							   bool lockNeeded = true) const
											{ return m_cachedCert.HasCertErrors(pErrors, lockNeeded); }
	virtual bool HasPathErrors(ErrorInfoList *pErrors= NULL,
							   bool lockNeeded = true) const	
											{ return m_cachedCert.HasPathErrors(pErrors, lockNeeded); }
	virtual bool IsCached() const;
	virtual bool IsCreatedFromKey()	const			{ return m_cachedCert.IsCreatedFromKey(); }

	// Member variable
	const CachedCert& m_cachedCert;

protected:
	// Member variable
	ASN::ReadLock m_lock;

private:
	bool m_cachedPathUsed;		// Indicates cached path tried by BuildNext()
};


// TrustedCertNode class definition
class TrustedCertNode : public CachedCertNode
{
public:
	// Constructor
	TrustedCertNode(ulong sessionID, const CachedCert& cachedCert);

	void DeletePreviousPath(const PathStack& path);

	// Operations
	virtual short BuildCachedPath(NodePool& thePool, const Location& loc,
		PathStack& curPath, PrintXML& logXML, float curProb, const CachedCertList& cachedCerts,
		CachedCertList::const_reverse_iterator iCachedCert);
	virtual short BuildNextPath(NodePool& thePool, const Location& loc,
		PathStack& curPath, PrintXML& logXML, float minProb = 0, float curProb = 1,
		float* pBestProb = NULL);
	virtual bool IsTrusted(void) const				{ return true; }

protected:
	std::list<PathStack> m_prevPaths;		// List of previous paths
};


typedef std::multimap<ASN::DN, BaseNode*> BaseNodeDN_Map;
typedef std::map<ASN::DN, Location> DNLocationMap;	

// NodePool class definition
class NodePool
{
public:
	// Constructors/Destructor
	NodePool(
	   ulong sessionID,           // CML Session ID
	   SearchBounds boundsFlag,   // Search local, remote, both or until found
	   const ASN::Time* pValidationTime = NULL); // Opt time to use for validation
	virtual ~NodePool();

	// Operations
	BaseNode* Add(const ASN::Bytes& subject, const ASN::BytesList& issuers);
	BaseNode* Add(const CachedCert& cachedCert);
	BaseNodePtrList* GetCerts(const ASN::DN& dn, Location& lastLoc,
		const Location& curLoc, const ASN::PkixAIAExtension* pAIA,
		PrintXML& logXML);

	// Member variables
	const Location m_searchLocs;			// Locations to be searched
	const ASN::Time* m_pValidationTime; // If not NULL, validate cert at this time

private:
	BaseNodePtrList* Add(const EncObject_LL* pObjList);
	BaseNodePtrList* Add(const CachedCertList& cacheCertList);
	BaseNodePtrList* Find(const CallbackFunctions& funcs, const ASN::DN& dn,
		const Location& searchLoc);
	BaseNodePtrList* Find(const CallbackFunctions& funcs, char* url,
		const Location& searchLoc);
	BaseNode* FindInPool(const ASN::DN& dn, const ASN::Bytes& cert) const;
	BaseNode* FindInPool(const Bytes_struct& encCert) const;
	BaseNode* FindInPool(const ASN::Bytes& encCert) const;
	void InsertInPool(BaseNode* pNode)
	{
		m_pool.insert(BaseNodeDN_Map::value_type(pNode->GetCert().base().subject,
			pNode));
	}

	const ulong m_hSession;					// Handle to CM session
	BaseNodeDN_Map m_pool;					// Pool of BaseNode object pointers
	DNLocationMap m_prevSearches;			// Map of previous searches by DN
};


// PathState class definition
class PathState
{
public:
	// Constructors/Destructor
	PathState(
	   ulong sessionID,               // CML SessionID
	   SearchBounds boundsFlag,       // Search local, remote, both 
	                                  // or until found
	   const ASN::Bytes& userCert,    // Encoded User Certificate
	   const ASN::BytesList& caCerts, // List of encoded CA Certificates
	   PrintXML& logXML,              // Used to write info to log file
	   const ASN::Time* pValidationTime); // Optional time to use for validation

	// Operations
	short BuildNext(PathStack& curPath, float minProb = 0,
		ErrorInfoList* pErrors = NULL);
	void RestoreResults(PathStack& curPath, ValidatedKey* pValidKey,
		bool pathWasSaved);
	bool SaveResults(PathStack& curPath, const ValidatedKey* pValidKey);
	short ValidatePath(PathStack& curPath, ErrorInfoList* pErrors,
		ValidatedKey* pValidKey, bool performRevChecking) const;
	bool PushIssuer(const ASN::Bytes& userCert);	// returns whether or not the node was added
	void PopIssuer()							{ m_pSubj.pop_back(); }
	unsigned int GetStackSize()	const			{ return m_pSubj.size(); }
	BaseNode* GetCurrentIssuer() const			{ return m_pSubj.back(); }
	const ulong& GetSessionID() const			{ return m_sessionID; }

#if defined(WIN32) && defined(_DEBUG)
	const Certificate& GetSubjCert(void) const	{ return GetCurrentIssuer()->GetCert(); }
#endif

	PrintXML& m_logXML;
	RevocationPolicy	m_revPolicy; 

private:
	ulong m_sessionID;
	SearchBounds m_searchFlag;
	Location m_curLoc;				// Current search location
	NodePool m_certPool;
	std::deque<BaseNode*> m_pSubj;

	// Results from first validation
	PathStack m_firstPath;
	PathOutputs m_firstResults;
};

// CachableCert class defintion
class CachableCert
{
public:
	// Constructor
	CachableCert(Certificate cert, PolicyTable authSet, ASN::PolicyMappingList mappings,
				 bool explicitPolFlag, ASN::Time expireTime, short error, ErrorInfoList certErrors, 
				 ErrorInfoList pathErrors);
	
	// Members
	const Certificate m_cert;
	const PolicyTable m_authSet;
	const ASN::PolicyMappingList m_mappings;
	const bool m_explicitPolFlag;
	const ASN::Time m_expireTime;
	const short m_error;
	ErrorInfoList m_certErrors;
	ErrorInfoList m_pathErrors;
};

typedef std::list<CachableCert> CachableCertList;

/////////////////////////
// Function Prototypes //
/////////////////////////
short ValidateCert(ulong sessionID, const Certificate& target,
				   const Certificate& issuer, SearchBounds searchFlag,
				   StateVars& pathVars, ErrorInfoList& certErrors,
				   ErrorInfoList& pathErrors, bool isEndCert,
				   bool performRevChecking);

} // end of nested Internal namespace
} // end of CML namespace


#endif /* _PATH_BUILD_H */
