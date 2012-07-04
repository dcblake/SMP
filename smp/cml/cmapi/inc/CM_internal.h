/*************************************************************************
File:     CM_internal.h
Project:  Certificate Management Library
Contents: Header file for the internal (low-level) functions used in the
          Certificate Management Library

Created:  4 April 1997
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>
          Robin Moeller <Robin.Moeller@baesystems.com>

Last Updated:  27 Jan 2005

Version:  2.5

*****************************************************************************/
#ifndef _CM_INTERNAL_H
#define _CM_INTERNAL_H

////////////////////
// Included Files //
////////////////////
#ifdef _MSC_VER
	#pragma warning(disable: 4284)	// Disable list<T> when T not UDT warning
	#pragma warning(disable: 4702)	// Disable unreachable code warning
	#pragma warning(disable: 4710)	// Disable function not inlined warning
	#pragma warning(disable: 4786)	// Disable identifier truncated warning
	#pragma warning(push, 3)		// Set warning level to 3 for STL headers
	#include <set>
	#pragma warning(pop)			// Reset warning level
	#pragma warning(disable: 4018)	// Disable signed/unsigned mismatch warning
	#pragma warning(disable: 4146)	// Disable unary minus operator warning
#else
	#include <set>
#endif
	#include <stack>

// _WIN32_WINNT version must be set prior to #including cmlasn.h
#ifdef WIN32
	#define _WIN32_WINNT	0x0400	// Minimum Windows version required for
#endif								//    CryptoAPI (Win95 OSR2 or NT 4.0)

#include "cmlasn.h"

// Set Windows export declaration so data and functions are exported
#ifdef WIN32
	#undef CM_API
	#define CM_API	__declspec(dllexport)
#endif

#include "cmapi_cpp.h"


// For non-Windows platforms
#ifndef ALGIDDEF
	typedef unsigned int ALG_ID;
#endif
#ifndef HCRYPTKEY
	#define HCRYPTKEY ulong
#endif


//////////////////////////////
// Platform-specific Macros //
//////////////////////////////
#ifdef WIN32
	#define LIB_PREFIX				""
	#define LIB_EXT					".dll"
#elif defined(HPUX32)
	#define LoadLibrary(name)		shl_load(name, BIND_NONFATAL | DYNAMIC_PATH, 0L)
	#define FreeLibrary				shl_unload
	#define LIB_PREFIX				"lib"
	#define LIB_EXT					".sl"
	typedef shl_t HINSTANCE;
#else	// SOLARIS, LINUX or HPUX(64 bit)
	#define LoadLibrary(name)		dlopen(name, RTLD_NOW | RTLD_GLOBAL)
	#define GetProcAddress			dlsym
	#define FreeLibrary				dlclose
	#define LIB_PREFIX				"lib"
#ifdef HPUX
	#define LIB_EXT					".sl"
#else
	#define LIB_EXT					".so"
#endif
	typedef void* HINSTANCE;
#endif
#ifdef _DEBUG
	#define DEBUG_INDICATOR		"_d"
	#ifdef WIN32
		#include <crtdbg.h>
		#define RETURN(err)		_ASSERT(false)
	#else
		#define RETURN(err)		return (err)
	#endif // WIN32
#else
	#define DEBUG_INDICATOR		""
	#define RETURN(err)			return (err)
#endif


// Begin CML namespace
namespace CML {

// Begin nested Internal namespace
namespace Internal {


//////////////////////
// Exception Macros //
//////////////////////
#define CML_ERR(err)		CML::ASN::Exception((err), __FILE__, __LINE__,\
								CMU_GetErrorString(err))
#define CML_MEMORY_ERR		CML_ERR(CM_MEMORY_ERROR)
#define PKCS_ERR(err)		TokenException((err), __FILE__, __LINE__)
#define CAPI_ERR			TokenException(GetLastError(), __FILE__, __LINE__, true)


///////////////////////
// Defined Constants //
///////////////////////
const ulong UNIV_CONS_SEQ_TAG = MAKE_TAG_ID (SNACC::UNIV, SNACC::CONS,
											 SNACC::SEQ_TAG_CODE);
const ulong CNTX_CONS_ZERO_TAG = MAKE_TAG_ID (SNACC::CNTX, SNACC::CONS, 0);
const ulong CNTX_CONS_ONE_TAG = MAKE_TAG_ID (SNACC::CNTX, SNACC::CONS, 1);
#define CM_LOG_TIME_FORMAT	"%02d:%02d:%02d"
#define CM_MAX_NESTING		5


//////////////////////
// Type Definitions //
//////////////////////
typedef std::set<CML::ASN::Bytes> BytesSet;
typedef std::set<ALG_ID> AlgIdSet;


// Forward class declarations
class CertCache;
class CrlCache;


class PrintXML
{
public:
	PrintXML();
	// Construct from a file name and log level
	PrintXML(const char *filename, CMLogLevel level);
	// Destructor
	virtual ~PrintXML(void); 
	// Operator overloads
	PrintXML& operator=(const PrintXML& rhs);

	void WriteBegin(CMLogLevel level, const char *lpszTitle, int count,
		            const char *lpszName, const char *optString=NULL,
					const char *lpszName2=NULL, const SNACC::AsnInt *sn = NULL) const;
	void WriteSimpleBegin(CMLogLevel level, const char *lpszTitle) const;

	void WriteData(CMLogLevel level, const char *pszLog, const char *optString=NULL) const;
	void WriteData(CMLogLevel level, const char *pszLog, float fNum) const;
	void WriteData(CMLogLevel level, int iNum, const char *pszLog) const;
	void WriteData(CMLogLevel level, const char *lpszName, const char *val,
				   const char *lpszName2, const SNACC::AsnInt& sn,
				   const char *lpszName3=NULL, const char *optString=NULL,
				   const char *lpszName4=NULL) const;
	void WriteInfo(CMLogLevel level, const char *pszLog, float fNum) const;

	void WriteEnd(CMLogLevel level, const char *lpszTitle, int count = 0) const;
private:
	// Members
	mutable CMLogLevel m_level;
	mutable std::ostream *m_os;
	mutable int m_count[CM_MAX_NESTING];
	mutable std::stack<int> m_countQueue;
};


class LogSettings
{
public:
	LogSettings()
	{
		m_filename = strdup("cml-log");
		m_level = CM_LOG_LEVEL_0;
		m_count = 0;
	}
	~LogSettings()
	{
		free(m_filename);
	}

	void Init(CMLogLevel level, const char* logfile);
	CMLogLevel GetLogLevel() const			{return m_level;}	
	char* GetNextLogFile(CMLogLevel level) const;		

private:
	//Member variables
	char *m_filename;				// Base filename for log file
	CMLogLevel m_level;				// Log level
	mutable long m_count;			// Count appended to filename
	ASN::ReadWriteMutex m_mutex;	// Mutex for thread safe log file names
};


class PolicySettings
{
public:
	PolicySettings()
	{
		policyList.push_back(ASN::CertPolicy(SNACC::anyPolicy));
		requirePolicy = inhibitMapping = inhibitAnyPolicy = false;
	}

	// Member variables
	ASN::CertPolicyList policyList;	// Initial-policy-set
	bool requirePolicy;				// Initial-explicit-policy indicator
	bool inhibitMapping;			// Initial-inhibit-policy-mapping indicator
	bool inhibitAnyPolicy;			// Initial-inhibit-any-policy indicator
};


class PathOutputs
{
public:
	PathOutputs()				{ pParams = NULL; explicitPolicyFlag = false; }
	~PathOutputs()				{ delete pParams; }

	// Member variables
	ASN::CertPolicyList authPolicies;
	ASN::CertPolicyList userPolicies;
	ASN::PolicyMappingList mappings;
	bool explicitPolicyFlag;
	ASN::Bytes* pParams;
	RevocationDataList	m_revDataList; // Revocation Data (CRLs/OCSP responses)
};


// Forward declarations
class CertCache;
class SrlSession;
class CrlSession;


class CallbackFunctions
{
public:
	CallbackFunctions()
		{ extHandle = NULL; pGetObj = NULL; pFreeObj = NULL; pUrlGetObj = NULL;}

	// Member variables
	void				*extHandle;		// Handle to external library for callbacks
	ExtGetObjFuncPtr	pGetObj;		// External get callback function
	ExtFreeObjFuncPtr	pFreeObj;		// External free callback function
	ExtUrlGetObjFuncPtr	pUrlGetObj;		// External URL get callback function
};

class RevCallbackFunctions
{
public:
	RevCallbackFunctions()						
		{ extRevHandle = NULL; pCheckStatus = NULL; pFreeStatus = NULL; }

	// Member variables
	void				*extRevHandle;	// Handle to external library for callbacks
	ExtCheckRevStatusFP pCheckStatus;		// Check revocation status callback function
	ExtFreeRevStatusFP	pFreeStatus;		// Free revocation status callback function
};


class CryptoHandle
{
public:
	virtual ~CryptoHandle()					{}
	virtual short Verify(const ASN::Bytes& signedData,
		const Signature& signature, const ASN::PublicKeyInfo& pubKey,
		const ASN::Bytes* pubKeyParams) const = 0;
};


class CryptoHandles : public std::list<CryptoHandle*>
{
public:
	~CryptoHandles();
	CryptoHandles& operator=(const CM_CryptoTokenList& tokenHandles);

	void LoadDefaultToken();
	short Verify(const ASN::Bytes& signedData, const Signature& signature,
		const ASN::PublicKeyInfo& pubKey, const ASN::Bytes* pubKeyParams) const;
};


class PKCS11_Handle : public CryptoHandle
{
public:
	PKCS11_Handle(CM_PKCS11Token token, bool cmlCreated = false);
	virtual ~PKCS11_Handle();

	short Sign(CK_OBJECT_HANDLE hKey, const ASN::Bytes& dataToSign,
		Signature& signature) const;
	virtual short Verify(const ASN::Bytes& signedData,
		const Signature& signature, const ASN::PublicKeyInfo& pubKey,
		const ASN::Bytes* pubKeyParams) const;

private:
	ASN::Mutex m_mutex;			// Mutex for thread safe access to the token
	CK_SESSION_HANDLE m_handle;	// Handle to PKCS #11 token
	bool m_createdInternally;	// Indicates if the CML created this handle
	CK_FUNCTION_LIST* m_pFunc;	// Cryptoki token function pointers
};


class MS_CSP_Handle : public CryptoHandle
{
public:
	MS_CSP_Handle(HCRYPTPROV handle, bool cmlCreated = false);
	virtual ~MS_CSP_Handle();

	short LoadPublicKey(const ASN::PublicKeyInfo& pubKey,
		const ASN::Bytes* pubKeyParams, HCRYPTKEY* phKey) const;
	short Sign(const ASN::Bytes& dataToSign, Signature& signature) const;
	virtual short Verify(const ASN::Bytes& signedData,
		const Signature& signature, const ASN::PublicKeyInfo& pubKey,
		const ASN::Bytes* pubKeyParams) const;

private:
	HCRYPTPROV m_handle;		// Handle to MS CSP token
	bool m_createdInternally;	// Indicates if the CML created this handle
	AlgIdSet m_supportedAlgs;	// Set of supported algorithms
};


// Session settings
class Session
{
public:
	// Constructor/Destructor
	Session();
	Session(const Session& that);	// Needed by SessionMap
	~Session();

	// Methods
	void Initialize(ulong sessionID, const InitSettings_struct& settings, ASN::MutexLock& mgrLock);
	ushort GetMaxPaths() const				{ return nMaxPaths; }
	// Get the Callback functions
	const CallbackFunctions &GetFunc() const	{ return func; }
	// Get the Callback functions
	const RevCallbackFunctions &GetRevFunc() const	{ return revFunc; }
	// Get the Revocation Policy
	RevocationPolicy GetRevPolicy() const	{ return revPolicy; }
	// Get the RAM Cert Cache
	CertCache *GetCertCache() const	{ return pCertCache; }
	// Get the CRL refresh grace period
	time_t GetCRLGracePeriod() const { return crlGracePeriod; }
	// Get a pointer to the CRL session
	const CrlSession* GetCRLSession() const                     { return pCRL; }
	// Set the Log Settings
	short SetLogSettings(const CML_LogSettings_struct& logInfo);
	char* GetNextLogFile(CMLogLevel level) const;
	CMLogLevel GetLogLevel() const;
	// Get the Policy Settings
	const PolicySettings& GetPolicySettings() const  { return policySettings; }
	// Set the Policy Settings
	void SetPolicySettings(const ASN::OIDList &polList, bool reqPolicy,
									bool inhibitMap, bool inhibitAnyPol);
	// Verify a signature using this session's tokens
	short VerifySignature(const ASN::Bytes& signedData,
		const Signature& signature, const ASN::PublicKeyInfo& pubKey,
		const ASN::Bytes* pubKeyParams = NULL) const;
	// Get the want back setting. TRUE if CRLs/OCSP responses are requested.
   bool GetWantBackStatus() const { return m_returnRevData; }
	// Terminate this session and release the SRL and CRL sessions if present
	void Terminate();


private:
   // Member variables
   CallbackFunctions    func;          // Callback functions
   CryptoHandles        tokenList;     // List of token handles
   RevocationPolicy     revPolicy;     // Current revocation policy
   RevCallbackFunctions revFunc;       // Revocation Status Callback functions
   CertCache*           pCertCache;    // The RAM cert cache
//	char**					trustedDNs;    // Not used anymore  **LTV**
   LogSettings          logSettings;   // Current log settings
   PolicySettings       policySettings;// Current initial policy settings
   SrlSession*          pSRL;          // Optional SRL session object
   CrlSession*          pCRL;          // Optional CRL session object
   time_t               crlGracePeriod;// Maximim time that a CRL is considered to be valid
                                       // after the Next Update time has passed
   ushort               nMaxPaths;     // Maximum number of paths to try and build
   ASN::ReadWriteMutex  mMutex;        // Mutex for thread-safe code
   bool                 m_returnRevData;// Flag specifies whether or not to return
                                       // CRLs/OCSP response
	
	// Friend functions
	friend ASN::ReadLock AcquireSessionReadLock(ulong sessionID);
};


// Function Pointer Type Defintion for SRL_FreeEncCertList()
typedef short (*PExtFreeEncCertList)(EncCert_LL **pCertList);


// SRL Session settings
class SrlSession
{
public:
	SrlSession(CallbackFunctions& cmlFuncs, EncCert_LL** ppTrustedSrlCerts,
		PExtFreeEncCertList* FreeEncCertListFP);
	~SrlSession();
	const ulong GetSessionID() const { return sessionID; }
	void Release();

private:
	// Member variables
	void* srlLibHandle;
	ulong sessionID;
};


// CRL Session settings
class CrlSession
{
public:
	CrlSession(const ulong sessionID, time_t crlCacheTTL, time_t crlGracePeriod, 
		RevCallbackFunctions& cmlFuncs, const CallbackFunctions& srlFuncs);
	~CrlSession();
	void EmptyCache() const;
	const ulong GetSessionID() const { return sessionID; }
	void Release();

private:
	// Member variables
	void* crlLibHandle;
	ulong sessionID;
};



/////////////////////////
// Function Prototypes //
/////////////////////////
// Template function:  itemPresentInList()
// Returns true if the item is already present in the list, false otherwise
template <class T>
bool itemPresentInList(const std::list<T>& theList, const T& item)
{
	typename std::list<T>::const_iterator i;
	for (i = theList.begin(); i != theList.end(); ++i)
	{
		if (*i == item)
			return true;
	}
	return false;
};

// Other Prototypes
ASN::ReadLock AcquireSessionReadLock(ulong sessionID);
bool CompareBytesPtrs(const Bytes_struct *a, const Bytes_struct *b);
bool CompareUniqueIDs(const SNACC::UniqueIdentifier* pFirstID,
					  const SNACC::UniqueIdentifier* pSecondID);
ALG_ID GetCAPI_AlgID(const SNACC::AsnOid& alg);
CK_MECHANISM_TYPE GetPKCSMechanismType(const SNACC::AsnOid& sigHashAlg,
									   CK_KEY_TYPE& keyType);
const CallbackFunctions& GetCallbacksFromRef(ulong sessionID);
CertCache& GetCertCache(ulong sessionID);
CrlCache& GetCRLCache(ulong sessionID);
time_t GetCRLGracePeriod(ulong sessionID);
const ASN::CertPolicyList& GetInitialPolicySet(ulong sessionID);
CMLogLevel GetLogLevel(ulong sessionID);
ushort GetMaxPaths(ulong sessionID);
char* GetNextLogFile(ulong sessionID, CMLogLevel level);
const RevCallbackFunctions& GetRevCallbacksFromRef(ulong sessionID);
const Session& GetSessionFromRef(ulong sessionID);
bool GetWantBackStatus(ulong sessionID);
bool HasInvalidMappings(const ASN::PolicyMappingList& pPolicyMappings);
bool IsSelfSigned(const ASN::Cert& cert, bool authKeyMustMatch = false);
short SignBytes(const ASN::Bytes& dataToSign, Signature& signature,
				const CM_CryptoToken& tokenHandle, CK_OBJECT_HANDLE pkcs11Key);
const char* SplitSigHashAlg(const SNACC::AsnOid& sigHashAlg,
							const char** ppHashAlg = NULL);
short VerifySignature(ulong sessionID, const ASN::Bytes& asnObj,
					  const ASN::PublicKeyInfo& pubKey,
					  const ASN::Bytes* pubKeyParams = NULL);


} // end of nested Internal namespace
} // end of CML namespace

#endif // _CM_INTERNAL_H
