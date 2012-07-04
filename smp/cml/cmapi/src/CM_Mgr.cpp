/*****************************************************************************
File:     CM_Mgr.cpp
Project:  Certificate Management Library
Contents: Implementation of the CM_MgrInfo and Session classes to manage
		  library initialization and shutdown and session creation and
		  deletion.

Created:  March 1997
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	27 Jan 2005

Version:  2.5

Description: This file contains the following functions:
			 CML::SetPolicy
			 CM_SetLogSettings
			 CMU_AddASession
			 CMU_RemoveASession
			 CMU_GetErrorString
*****************************************************************************/

////////////////////
// Included Files //
////////////////////
#include "CM_cache.h"
#ifdef HPUX32
	#include <dl.h>			// Needed for dynamic loading of PKCS #11 library
#elif !defined(WIN32)
	#include <dlfcn.h>		// Needed for dynamic loading of PKCS #11 library
#endif


// Using declarations
using namespace CML;
using namespace CML::Internal;


///////////////////////
// Defined Constants //
///////////////////////
const ushort DEFAULT_MAX_PATHS	= 5;
static const char* DEFAULT_PKCS11_LIBRARY = LIB_PREFIX "pkcs11_cryptopp" DEBUG_INDICATOR LIB_EXT;

// For Windows platforms, uncomment following line to use specified PKCS #11
// library rather than default Window CAPI CSPs
// #define _USE_DEFAULT_PKCS11_LIBRARY


//////////////////////
// Type Definitions //
//////////////////////
typedef std::map<ulong, Session> SessionMap;

class CM_MgrInfo
{
public:
	// Default constructor
	CM_MgrInfo()				{ m_defaultPkcsLib = NULL; m_pGetFuncs = NULL; }
	// Destructor
	~CM_MgrInfo();

	// Methods
	ulong AddSession(const InitSettings_struct& settings);
	void DeleteSession(ulong sessionID);
	Session& GetSession(ulong sessionID);
	CM_GetFuncListFP InitDefaultPKCS11Lib(HMODULE& hDefaultToken);

private:
	ulong GenRandomSessionID(const void* address) const;

	SessionMap m_sessions;
	ASN::Mutex mMutex;
	HMODULE m_defaultPkcsLib;		// Handle to the default PKCS #11 library
	CM_GetFuncListFP m_pGetFuncs;	// Pointer to the default GetFuncList()
};


/* Record structure used in ErrorTable */
typedef struct
{
    short code;
    const char *string;
} ErrorEntry;


/////////////////////////
// Function Prototypes //
/////////////////////////
void CMU_ReleaseSRL(void *libHandle, ulong *srlSession);
static short createPublicKeyObj(CK_SESSION_HANDLE session,
								CK_FUNCTION_LIST* pFunc, CK_KEY_TYPE keyType,
								const Pub_key_struct& pubKey,
								CK_OBJECT_HANDLE& hPubKey);


//////////////////////
// Global Variables //
//////////////////////
static CM_MgrInfo gCM_MgrInfo;


/************************************************************************
 FUNCTION:  CML::SetPolicy()

 Description: This function set the initial path processing settings for
 the specified session.
*************************************************************************/
void CML::SetPolicy(ulong sessionID, const ASN::OIDList& policies,
					bool requireExplicitPolicy, bool inhibitPolicyMapping,
					bool inhibitAnyPolicy)
{
	// Check parameter
	if (policies.empty())
		throw CML_ERR(CM_INVALID_PARAMETER);

	// Get the CM session from the handle
	Session& session = gCM_MgrInfo.GetSession(sessionID);

	// Copy the settings
	session.SetPolicySettings(policies, requireExplicitPolicy,
		inhibitPolicyMapping, inhibitAnyPolicy);
}


/************************************************************************
 FUNCTION:  CM_SetLogSettings()

 Description: This function sets the log file name and level used when
 building and validating certificate paths.
*************************************************************************/
short CM_SetLogSettings(ulong cm_session, CML_LogSettings_struct *pLogInfo)
{
	// Check parameters
	if (pLogInfo == NULL)
		return CM_INVALID_PARAMETER;

	// Get the CM session from the handle
	Session& session = gCM_MgrInfo.GetSession(cm_session);

	// Copy the settings
	return session.SetLogSettings(*pLogInfo);
} // end of CM_SetLogSettings()



/////////////////////////////////////
// CM_MgrInfo class implementation //
/////////////////////////////////////
CM_MgrInfo::~CM_MgrInfo()
{
	// Call C_Finalize() if the default PKCS #11 library was initialized
	if (m_pGetFuncs != NULL)
	{
		// Call C_GetFunctionList() to get the function pointers
		CK_FUNCTION_LIST_PTR pFuncs;
		CK_RV rv = m_pGetFuncs(&pFuncs);

		// If successful, call C_Finalize() if present
		if ((rv == CKR_OK) && (pFuncs->C_Finalize != NULL))
			pFuncs->C_Finalize(NULL_PTR);

#ifndef ENABLE_STATIC
		// Free the PKCS #11 library
		FreeLibrary(m_defaultPkcsLib);
#endif
	}
}


ulong CM_MgrInfo::AddSession(const InitSettings_struct& settings)
{
	ulong ref = 0;
	try {
		// Acquire or lock the mutex
		ASN::MutexLock lock = mMutex.AcquireLock();

		// Create a unique ref id for this session
		ref = GenRandomSessionID(&settings);
		if (ref == 0)
			throw CML_MEMORY_ERR;

		// Insert a new session into the map
		Session& newSession = m_sessions[ref];

		// Initialize the session
		newSession.Initialize(ref, settings, lock);
		return ref;
	}
	catch (...) {
		DeleteSession(ref);
		throw;
	}
} // end of CM_MgrInfo::AddSession()


void CM_MgrInfo::DeleteSession(ulong sessionID)
{
	// Acquire or lock the mutex
	ASN::MutexLock lock = mMutex.AcquireLock();

	// Find the session
	SessionMap::iterator i = m_sessions.find(sessionID);
	if (i == m_sessions.end())
		throw CML_ERR(CM_SESSION_NOT_VALID);

	// Terminate the session
	i->second.Terminate();

	// Erase the entry
	m_sessions.erase(i);
}


Session& CM_MgrInfo::GetSession(ulong sessionID)
{
	// Acquire or lock the mutex
	ASN::MutexLock lock = mMutex.AcquireLock();

	SessionMap::iterator i = m_sessions.find(sessionID);

	if (i == m_sessions.end())
		throw CML_ERR(CM_SESSION_NOT_VALID);

	return i->second;
}


CM_GetFuncListFP CM_MgrInfo::InitDefaultPKCS11Lib(HMODULE& hDefaultToken)// CK_FUNCTION_LIST_PTR pPkcsFuncs)
{
#ifndef ENABLE_STATIC
	// Lock the mutex
	ASN::MutexLock lock = mMutex.AcquireLock();

	// Only load the default PKCS #11 library if it hasn't already been
	if (m_pGetFuncs == NULL)
	{
		// Load the default library
		m_defaultPkcsLib = LoadLibrary(DEFAULT_PKCS11_LIBRARY);
		if (m_defaultPkcsLib == NULL)
			throw CML_ERR(CM_DEFAULT_CRYPTO_TOKEN_ERR);

		try {
			// Get the address of the C_GetFunctionList() function
#ifdef HPUX32
			shl_findsym(&m_defaultPkcsLib, "C_GetFunctionList", TYPE_PROCEDURE,
				&m_pGetFuncs);
#else
			m_pGetFuncs = (CM_GetFuncListFP)GetProcAddress(m_defaultPkcsLib,
				"C_GetFunctionList");
#endif
			if (m_pGetFuncs == NULL)
				throw CML_ERR(CM_DEFAULT_CRYPTO_TOKEN_ERR);

			// Call C_GetFunctionList() to get the function pointers
			CK_FUNCTION_LIST_PTR pFuncs;
			CK_RV rv = m_pGetFuncs(&pFuncs);
			if (rv != CKR_OK)
				throw PKCS_ERR(rv);

			// Call C_Initialize() if present
			if (pFuncs->C_Initialize != NULL)
			{
				CK_C_INITIALIZE_ARGS initArgs;
				memset(&initArgs, 0, sizeof(CK_C_INITIALIZE_ARGS));
				initArgs.flags = CKF_OS_LOCKING_OK;
				CK_RV rv = pFuncs->C_Initialize(&initArgs);
				if (rv != CKR_OK)
					throw PKCS_ERR(rv);
			}
		}
		catch (...) {
			m_pGetFuncs = NULL;
			FreeLibrary(m_defaultPkcsLib);
			throw;
		}
	}

	hDefaultToken = m_defaultPkcsLib;
#endif //ENABLE_STATIC
	return m_pGetFuncs;
}


ulong CM_MgrInfo::GenRandomSessionID(const void *address) const
{
	// NOTE:  CM_MgrInfo must be locked!!

	// Check parameter
	if (address == NULL)
		return 0;

	// Hash the address
	CML::ASN::Bytes inputBytes(sizeof(void*), (const uchar*)&address);
	CML::ASN::Bytes hash;
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
} // end of CM_MgrInfo::GenRandomSessionID()



///////////////////
// CMU Functions //
///////////////////
ulong CMU_AddASession(const InitSettings_struct& settings)
{
	return gCM_MgrInfo.AddSession(settings);

} // end of CMU_AddASession()


short CMU_RemoveASession(ulong *sessionRefID)
{
	// Check parameter
	if (sessionRefID == NULL)
		return CM_INVALID_PARAMETER;

	// Reset the caller's sessionRefID to zero
	ulong tmpRefID = *sessionRefID;
	*sessionRefID = 0;

	try {
		gCM_MgrInfo.DeleteSession(tmpRefID);
	}
	catch (ASN::Exception& err) {
		return err;
	}

	return CM_NO_ERROR;
}


/////////////////////////////
// CML::Internal Functions //
/////////////////////////////
const CallbackFunctions& CML::Internal::GetCallbacksFromRef(ulong sessionID)
{
	// Get the CM session from the handle
	const Session& session = gCM_MgrInfo.GetSession(sessionID);

	// Check the required function pointers
	if ((session.GetFunc().pGetObj == NULL) || (session.GetFunc().pFreeObj == NULL))
		throw CML_ERR(CM_NULL_POINTER);

	return session.GetFunc();
}

const RevCallbackFunctions& CML::Internal::GetRevCallbacksFromRef(ulong sessionID)
{
	// Get the CM session from the handle
	const Session& session = gCM_MgrInfo.GetSession(sessionID);

	// Check the required function pointers
	if ((session.GetRevFunc().pCheckStatus == NULL) || (session.GetRevFunc().pFreeStatus == NULL))
		throw CML_ERR(CM_NULL_POINTER);

	return session.GetRevFunc();
}

ASN::ReadLock CML::Internal::AcquireSessionReadLock(ulong sessionID)
{
	// Get the CM session from the handle
	Session& session = gCM_MgrInfo.GetSession(sessionID);
	return session.mMutex.AcquireReadLock();
}


CertCache& CML::Internal::GetCertCache(ulong sessionID)
{
	// Get the CM session from the handle
	Session& session = gCM_MgrInfo.GetSession(sessionID);
	if (session.GetCertCache() == NULL)
		throw CML_ERR(CM_NULL_POINTER);
	return *session.GetCertCache();
}

const ASN::CertPolicyList& CML::Internal::GetInitialPolicySet(ulong sessionID)
{
	const Session& session = GetSessionFromRef(sessionID);
	return session.GetPolicySettings().policyList;
}

char* CML::Internal::GetNextLogFile(ulong sessionID, CMLogLevel level)
{
	const Session& session = GetSessionFromRef(sessionID);
	return session.GetNextLogFile(level);
}

CMLogLevel CML::Internal::GetLogLevel(ulong sessionID)
{
	const Session& session = GetSessionFromRef(sessionID);
	return session.GetLogLevel();
}

ushort CML::Internal::GetMaxPaths(ulong sessionID)
{
	const Session& session = GetSessionFromRef(sessionID);
	return session.GetMaxPaths();
}

const Session& CML::Internal::GetSessionFromRef(ulong sessionRefID)
{
	return gCM_MgrInfo.GetSession(sessionRefID);
}

time_t CML::Internal::GetCRLGracePeriod(ulong sessionID)
{
	// Acquire global session lock
	ASN::ReadLock lock = AcquireSessionReadLock(sessionID);

	const Session& session = GetSessionFromRef(sessionID);
	return session.GetCRLGracePeriod();
}

bool CML::Internal::GetWantBackStatus(ulong sessionID)
{
	const Session& session = GetSessionFromRef(sessionID);
	return session.GetWantBackStatus();
}



////////////////////////////////////
// LogSettings class implentation //
////////////////////////////////////
void LogSettings::Init(CMLogLevel level, const char* logfile)
{
	// Acquire a lock on the LogSettings
	ASN::MutexLock lock = m_mutex.AcquireLock();

	m_count = 1;
	if (logfile)
	{
		// Free the default filename
		free(m_filename);
		m_filename = strdup(logfile);
	}
    m_level = level;
}

// Platform independent way of finding out how many bytes
// are needed to store a long in a string representation
int numCharsInLong()
{
    int nbytes = sizeof(long);
    long num = 0x7F;
    int len = 0, i = 0;

    for (; i < (nbytes - 1); i++)
    {
        num = num << 8;
        num = num | 0xFF;
    }

    while (num > 10)
    {
        num = num / 10;
        len++;
    }
    return ++len;
}

char* LogSettings::GetNextLogFile(CMLogLevel level) const
{
	if (level == CM_LOG_LEVEL_0)
		return NULL;

	// Lock the LogSettings mutex to have exclusive access to the counter
	ASN::MutexLock lock = m_mutex.AcquireLock();

	// Create the numeric extension added to the base filename ("-xxx")
	char *extBuf = (char *)calloc(1, (numCharsInLong() + 2));
	if (extBuf == NULL)
		return m_filename;
	sprintf(extBuf, "-%ld", m_count++);

	// Encapsulate the base filename in std::string
	std::string fileAndExt(m_filename);
	// Add the numeric extension
	fileAndExt += extBuf;
	// Add the .xml file extension
	fileAndExt += ".xml";
	free(extBuf);
	return strdup(fileAndExt.c_str());
}

//////////////////////////////////
// Session class implementation //
//////////////////////////////////
Session::Session()
{
	// Initialize pointers
	pCertCache = NULL;
	pSRL = NULL;
	pCRL = NULL;
}

// Copy constructor exists only to compile SessionMap class
// Not actually used
Session::Session(const Session& that) : mMutex(that.mMutex)
{
	// Initialize pointers
	pCertCache = NULL;
	pSRL = NULL;
	pCRL = NULL;
}

Session::~Session()
{
	// Acquire a handle to the mutex
	ASN::MutexLock lock = mMutex.AcquireLock();

	delete pCertCache;
	delete pCRL;
	delete pSRL;
}

void Session::Initialize(ulong sessionID, const InitSettings_struct& settings,  ASN::MutexLock& mgrLock)
{
	// Acquire a handle to the session mutex
	ASN::MutexLock lock = mMutex.AcquireLock();
	// Release the CM_MgrInfo mutex
	mgrLock.Release();

	// Initialize member variables
	func.extHandle = settings.extHandle;
	func.pGetObj = settings.pGetObj;
	func.pFreeObj = settings.pFreeObj;
	func.pUrlGetObj = settings.pUrlGetObj;
	revFunc.extRevHandle = settings.extRevHandle;
	revFunc.pCheckStatus = settings.pCheckStatus;
	revFunc.pFreeStatus = settings.pFreeStatus;
	tokenList = settings.tokenList;
   if (settings.m_returnRevocationData == FALSE)
      m_returnRevData = false;
   else
      m_returnRevData = true;

	// Check that the retrieval callback function pointers are properly specified
	if ((func.pUrlGetObj != NULL) && (func.pGetObj == NULL))
		throw CML_ERR(CM_NO_GET_OBJ);
	else if ((func.pGetObj != NULL) && (func.pFreeObj == NULL))
		throw CML_ERR(CM_NO_FREE_OBJ);

	// Initialize trusted certs pointer and SRL_FreeEncCertList() function
	EncCert_LL* pTrustedCerts = settings.trustedCerts;
	PExtFreeEncCertList fpSRLFreeEncCertList = NULL;

	try {
		// Initialize the RAM cache
		pCertCache = new CertCache(sessionID, settings.nCertCacheSize,
			settings.certCacheTTL);
		if (pCertCache == NULL)
			throw CML_MEMORY_ERR;

		// Create a Storage and Retrieval library session if pGetObj
		// callback function not provided
		if (func.pGetObj == NULL)
		{
			pSRL = new SrlSession(func, &pTrustedCerts, &fpSRLFreeEncCertList);
			if (pSRL == NULL)
				throw CML_MEMORY_ERR;
		}

		// Set the revocation checking policy
		if (settings.revPolicy == 0)
			revPolicy = CM_REVCRL;
		else if ((settings.revPolicy == CM_REVNONE) ||
			(settings.revPolicy == CM_REVCRL))
			revPolicy = settings.revPolicy;
		else
			throw CML_ERR(CM_INVALID_PARAMETER);

		// Set the CRL freshness grace period
		if (settings.crlGracePeriod >= 0)
			// The grace period cannot be greater than the EPOCH time
			if (settings.crlGracePeriod > time(NULL))
				crlGracePeriod = time(NULL);
			else
				crlGracePeriod = settings.crlGracePeriod;
		else
			throw CML_ERR(CM_INVALID_PARAMETER);

		// Check that the revocation callback function pointers are properly specified
		if ((revFunc.pCheckStatus != NULL) && (revFunc.pFreeStatus == NULL) && (revPolicy == CM_REVCRL))
			throw CML_ERR(CM_REQ_CALLBACK_MISSING);

		// Create a Revocation library session if pCheckStatus
		// callback function not provided
		if ((revFunc.pCheckStatus == NULL) && (revPolicy == CM_REVCRL))
		{
			pCRL = new CrlSession(sessionID, settings.crlCacheTTL,
				crlGracePeriod, revFunc, func);
			if (pCRL == NULL)
				throw CML_MEMORY_ERR;
		}

		// Set the max paths setting
		if (settings.nMaxPaths == 0)
			nMaxPaths = DEFAULT_MAX_PATHS;
		else
			nMaxPaths = settings.nMaxPaths;

		// Load the trusted certs, if provided or retrieved from SRL
		if (pTrustedCerts != NULL)
		{
			// For now, release this Session's mutex so that we
			// can verify the signtaure on the trusted certs.
			// SignedAsnObj::VerifySignature() needs to obtain
			// a read lock on this Session in order to call
			// Session.VerifySignature().
			lock.Release();
			short err = pCertCache->LoadTrustedCerts(pTrustedCerts);
			if (err != CM_NO_ERROR)
				throw CML_ERR(err);
		}

		// If the trusted certs were retrieved from SRL, free them
		if ((fpSRLFreeEncCertList != NULL) && (settings.trustedCerts == NULL))
			fpSRLFreeEncCertList(&pTrustedCerts);
	}
	catch (...) {
		// If the trusted certs were retrieved from SRL, free them
		if ((fpSRLFreeEncCertList != NULL) && (settings.trustedCerts == NULL))
			fpSRLFreeEncCertList(&pTrustedCerts);

		delete pCertCache;
		pCertCache = NULL;
		if (pSRL)
		{
			delete pSRL;
			pSRL = NULL;
		}
		if (pCRL)
		{
			delete pCRL;
			pCRL = NULL;
		}
		throw;
	}
} // end of Session::Initialize()

// Set the log settings used when building and validating certificate paths
short Session::SetLogSettings(const CML_LogSettings_struct& logInfo)
{
	if (logInfo.cbSize != sizeof(CML_LogSettings_struct))
		return CM_INVALID_PARAMETER;

	if ((logInfo.filename == NULL) && (logInfo.level != CM_LOG_LEVEL_0))
		return CM_INVALID_PARAMETER;

	// Acquire write lock on session's mutex
	ASN::MutexLock lock = mMutex.AcquireLock();

	logSettings.Init(logInfo.level, logInfo.filename);

	return CM_NO_ERROR;
}

char* Session::GetNextLogFile(CMLogLevel level) const
{
	return logSettings.GetNextLogFile(level);
}

CMLogLevel Session::GetLogLevel() const
{
	return logSettings.GetLogLevel();
}

// Set private members of PolicySettings
void Session::SetPolicySettings(const ASN::OIDList &polList, bool reqPolicy,
								bool inhibitMap, bool inhibitAnyPol)
{
	// Acquire write lock on session's mutex
	ASN::MutexLock lock = mMutex.AcquireLock();

	// Check the cache pointers
	if (pCertCache == NULL)
		throw CML_ERR(CM_NULL_POINTER);

	// Empty the existing cert & CRL caches
	pCertCache->Empty();

	if (pCRL)
	{
		pCRL->EmptyCache();
	}

	// Clear the old policies and then copy in the new
	policySettings.policyList.clear();
	ASN::OIDList::const_iterator iPol;
	for (iPol = polList.begin(); iPol != polList.end(); iPol++)
	{
		policySettings.policyList.push_back(ASN::CertPolicy(*iPol));
	}

	policySettings.requirePolicy = reqPolicy;
	policySettings.inhibitMapping = inhibitMap;
	policySettings.inhibitAnyPolicy = inhibitAnyPol;
}


// Verify a signature using this session's tokens
short Session::VerifySignature(const ASN::Bytes& signedData,
							   const Signature& signature,
							   const ASN::PublicKeyInfo& pubKey,
							   const ASN::Bytes* pubKeyParams) const
{
	// Use the parameters in the algorithm identifier, if present
	if (signature.GetAlgorithm().ParametersArePresent())
		pubKeyParams = signature.GetAlgorithm().parameters;

	return tokenList.Verify(signedData, signature, pubKey, pubKeyParams);
}

void Session::Terminate()
{
	// Acquire a handle to the mutex
	ASN::MutexLock lock = mMutex.AcquireLock();

	// Release the CRL server session if present
	if (pCRL != NULL)
		pCRL->Release();

	// Release the SRL session if present
	if (pSRL != NULL)
		pSRL->Release();
}


////////////////////////////////////////
// CryptoHandles class implementation //
////////////////////////////////////////
CryptoHandles::	~CryptoHandles()
{
	for (iterator i = begin(); i != end(); ++i)
		delete *i;
}


CryptoHandles& CryptoHandles::operator=(const CM_CryptoTokenList& tokenHandles)
{
	// Delete any existing tokens
	for (iterator i = begin(); i != end(); ++i)
		delete *i;
	clear();

	// Loop through the provided token list
	const CM_CryptoTokenList* pToken = &tokenHandles;
	CryptoHandle* pNew;
	bool isFirst = true;
	while (pToken != NULL)
	{
		// Load the default token if no token specified by caller
		if (isFirst && (pToken->token.type == CM_DEFAULT_TOKEN) &&
			(pToken->next == NULL))
			LoadDefaultToken();
		else
		{
			switch (pToken->token.type)
			{
			case CM_NO_TOKEN:
				pNew = NULL;
				break;

			case CM_PKCS11:
				pNew = new PKCS11_Handle(pToken->token.handle.hPKCS);
				if (pNew == NULL)
					throw CML_MEMORY_ERR;
				break;

#ifdef WIN32
			case CM_MS_CSP:
				pNew = new MS_CSP_Handle(pToken->token.handle.hCSP);
				if (pNew == NULL)
					throw CML_MEMORY_ERR;
				break;
#endif

			default:
				throw CML_ERR(CM_INVALID_PARAMETER);
			}

			// Append the token to the list
			if (pNew != NULL)
				insert(end(), pNew);
		}

		// Move to the next token in the list
		pToken = pToken->next;
		isFirst = false;
	}

	return *this;
} // end of CryptoHandles::operator=()


void CryptoHandles::LoadDefaultToken()
{
#if defined(WIN32) && !defined(_USE_DEFAULT_PKCS11_LIBRARY)

	// Try to acquire a DSS provider
	HCRYPTPROV hProv;
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_DSS,
		CRYPT_VERIFYCONTEXT))
	{
		// Append new MS CAPI CSP to token list
		MS_CSP_Handle* pNew = new MS_CSP_Handle(hProv, true);
		if (pNew == NULL)
			throw CML_MEMORY_ERR;
		insert(end(), pNew);
	}

	static const char* kProvNameTable[] = {
		"Microsoft Strong Cryptographic Provider" /* MS_STRONG_PROV */,
		MS_ENHANCED_PROV,
		MS_DEF_PROV  };

	// Try to acquire each provider from the name table in turn
	static const int kNumElmts = sizeof(kProvNameTable) / sizeof(char*);
	for (int i = 0; i < kNumElmts; ++i)
	{
		if (CryptAcquireContext(&hProv, NULL, kProvNameTable[i], PROV_RSA_FULL,
			CRYPT_VERIFYCONTEXT))
		{
			// Append new MS CAPI CSP to token list
			MS_CSP_Handle* pNew = new MS_CSP_Handle(hProv, true);
			if (pNew == NULL)
				throw CML_MEMORY_ERR;
			insert(end(), pNew);
			return;
		}
	}

#else // PKCS #11

	// Initialize the default PKCS #11 library
	CM_PKCS11Token pkcsToken;
#ifndef ENABLE_STATIC
	pkcsToken.pGetFuncList = gCM_MgrInfo.InitDefaultPKCS11Lib(pkcsToken.hLibrary);
#else
	pkcsToken.pGetFuncList = C_GetFunctionList;
	pkcsToken.hLibrary = NULL;
#endif // ENABLE_STATIC

	// Call C_GetFunctionList() to get the function pointers
	CK_FUNCTION_LIST_PTR pFuncs;
	CK_RV retval = pkcsToken.pGetFuncList(&pFuncs);
	if (retval != CKR_OK)
		throw PKCS_ERR(retval);

#ifdef ENABLE_STATIC
	// Initialize the session if we linked statically.
	// Call C_Initialize() if present
	CK_C_INITIALIZE_ARGS initArgs;
	memset(&initArgs, 0, sizeof(CK_C_INITIALIZE_ARGS));
	initArgs.flags = CKF_OS_LOCKING_OK;
	CK_RV rv = pFuncs->C_Initialize(&initArgs);
	if (rv != CKR_OK)
		throw PKCS_ERR(rv);
#endif //ENABLE_STATIC

	// Call C_OpenSession()
	CK_FLAGS sessionFlags = CKF_SERIAL_SESSION;
	CK_RV rv = pFuncs->C_OpenSession(0, sessionFlags, NULL, NULL_PTR,
		&pkcsToken.session);
	if (rv != CKR_OK)
		throw PKCS_ERR(rv);

	// Append new PKCS #11 handle to list
	PKCS11_Handle* pNew = new PKCS11_Handle(pkcsToken, true);
	if (pNew == NULL)
		throw CML_MEMORY_ERR;
	insert(end(), pNew);

#endif // PKCS #11
} // end of CryptoHandles::LoadDefaultToken()


short CryptoHandles::Verify(const ASN::Bytes& signedData,
							const Signature& signature,
							const ASN::PublicKeyInfo& pubKey,
							const ASN::Bytes* pubKeyParams) const
{
	for (const_iterator i = begin(); i != end(); ++i)
	{
		if (*i == NULL)
			return CM_NULL_POINTER;

		try {
			short verifyResult = (*i)->Verify(signedData, signature, pubKey,
				pubKeyParams);
			if ((verifyResult == CM_NO_ERROR) ||
				(verifyResult == CM_SIGNATURE_INVALID))
				return verifyResult;
		}
		catch (...) {
		}
	}

	return CM_NO_TOKENS_SUPPORT_SIG_ALG;
}


////////////////////////////////////////
// PKCS11_Handle class implementation //
////////////////////////////////////////
PKCS11_Handle::PKCS11_Handle(CM_PKCS11Token token, bool cmlCreated)
{
#ifndef ENABLE_STATIC
	// If the C_GetFunctionList() function pointer wasn't provided,
	// get its address from the library handle
	if (token.pGetFuncList == NULL)
	{
#ifdef HPUX32
		shl_findsym(&token.hLibrary, "C_GetFunctionList", TYPE_PROCEDURE,
			&token.pGetFuncList);
#else
		token.pGetFuncList = (CM_GetFuncListFP)GetProcAddress(token.hLibrary,
			"C_GetFunctionList");
#endif
		if (token.pGetFuncList == NULL)
			throw CML_ERR(CM_CRYPTO_TOKEN_ERROR);
	}
#endif //ENABLE_STATIC

	m_handle = token.session;
	m_createdInternally = cmlCreated;

	CK_RV rv = token.pGetFuncList(&m_pFunc);
	if (rv != CKR_OK)
		throw PKCS_ERR(rv);
}


PKCS11_Handle::~PKCS11_Handle()
{
	if (m_createdInternally)
		m_pFunc->C_CloseSession(m_handle);
}


short PKCS11_Handle::Sign(CK_OBJECT_HANDLE hKey, const ASN::Bytes& dataToSign,
		   Signature& signature) const
{
	// Initialize the mechanism structure
	CK_KEY_TYPE keyType;
	CK_MECHANISM mechanism;
	mechanism.mechanism =
		GetPKCSMechanismType(signature.GetAlgorithm().algorithm, keyType);
	if (mechanism.mechanism == 0)
		return CM_NOT_IMPLEMENTED;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;

	// Lock the PKCS #11 token
	ASN::MutexLock lock = m_mutex.AcquireLock();

	// Initialize the sign operation
	CK_RV rv = m_pFunc->C_SignInit(m_handle, &mechanism, hKey);
	if (rv != CKR_OK)
		throw PKCS_ERR(rv);

	// Determine the size of the signature value
	CK_ULONG bufSize;
	rv = m_pFunc->C_Sign(m_handle, (CK_BYTE_PTR)dataToSign.GetData(),
		dataToSign.Len(),
		NULL_PTR, &bufSize);
	if (rv != CKR_BUFFER_TOO_SMALL)
		throw PKCS_ERR(rv);

	// Allocate the buffer for the signature value
	CK_BYTE_PTR pBuf = new CK_BYTE[bufSize];
	if (pBuf == NULL)
		throw CML_MEMORY_ERR;

	// Sign the data
	rv = m_pFunc->C_Sign(m_handle, (CK_BYTE_PTR)dataToSign.GetData(),
		dataToSign.Len(), pBuf, &bufSize);
	if (rv != CKR_OK)
		throw PKCS_ERR(rv);

	// Copy the signature value
	signature.Set(bufSize, pBuf);

	// Destroy the temporary buffer
	delete[] pBuf;

	return CM_NO_ERROR;
} // end of PKCS11_Handle::Sign()


short PKCS11_Handle::Verify(const ASN::Bytes& signedData,
							const Signature& signature,
							const ASN::PublicKeyInfo& pubKey,
							const ASN::Bytes* pubKeyParams) const
{
	// Initialize the mechanism structure
	CK_KEY_TYPE keyType;
	CK_MECHANISM mechanism;
	mechanism.mechanism =
		GetPKCSMechanismType(signature.GetAlgorithm().algorithm, keyType);
	if (mechanism.mechanism == 0)
		return CM_NOT_IMPLEMENTED;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;

	// Get the C Pub_key_struct from the public key and parameters
	Pub_key_struct pubKeyStruct;
	if (pubKeyParams != NULL)
	{
		// Create a temporary public key object in which to copy the
		// specified parameters
		ASN::PublicKeyInfo tempKey(pubKey);
		if (tempKey.algorithm.parameters == NULL)
		{
			// Create and copy the parameters if parameters don't exist
			tempKey.algorithm.parameters = new ASN::Bytes(*pubKeyParams);
			if (tempKey.algorithm.parameters == NULL)
				return CM_MEMORY_ERROR;
		}
		else	// Just copy the specified parameters
			*tempKey.algorithm.parameters = *pubKeyParams;

		tempKey.FillPubKeyStruct(pubKeyStruct);
	}
	else
		pubKey.FillPubKeyStruct(pubKeyStruct);

	// Lock the PKCS #11 token
	ASN::MutexLock lock = m_mutex.AcquireLock();

	// Create the public key object and free the Pub_key_struct
	CK_OBJECT_HANDLE hPubKey;
	short cmErr = createPublicKeyObj(m_handle, m_pFunc, keyType, pubKeyStruct,
		hPubKey);
	CMASN_FreePubKeyContents(&pubKeyStruct);
	if (cmErr != CM_NO_ERROR)
		return cmErr;

	// Initialize the verification operation
	CK_RV rv = m_pFunc->C_VerifyInit(m_handle, &mechanism, hPubKey);
	if (rv != CKR_OK)
	{
		m_pFunc->C_DestroyObject(m_handle, hPubKey);
		return CM_CRYPTO_TOKEN_ERROR;
	}

	// Verify the signature
	rv = m_pFunc->C_Verify(m_handle, (CK_BYTE_PTR)signedData.GetData(),
		signedData.Len(), (CK_BYTE_PTR)signature.GetValue().GetData(),
		signature.GetValue().Len());
	m_pFunc->C_DestroyObject(m_handle, hPubKey);
	if (rv == CKR_SIGNATURE_INVALID)
		return CM_SIGNATURE_INVALID;
	else if (rv == CKR_OK)
		return CM_NO_ERROR;
	else
		return CM_CRYPTO_TOKEN_ERROR;
}


short createPublicKeyObj(CK_SESSION_HANDLE session, CK_FUNCTION_LIST* pFunc,
						 CK_KEY_TYPE keyType, const Pub_key_struct& pubKey,
						 CK_OBJECT_HANDLE& hPubKey)
{
	// Initialize the public key template
	CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
	CK_BBOOL trueValue = TRUE;
	CK_ATTRIBUTE pubKeyTemplate[7] = {
		{ CKA_CLASS, &objClass, sizeof(objClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_VERIFY, &trueValue, sizeof(trueValue) },
		{ CKA_CLASS, NULL, 0 },
		{ CKA_CLASS, NULL, 0 },
		{ CKA_CLASS, NULL, 0 },
		{ CKA_CLASS, NULL, 0 } };
	ulong i = 3;

	// Add the algorithm-specific public key algorithms to the array
	if (strcmp(pubKey.oid, SNACC::rsaEncryption) == 0)
	{
		// Check key type
		if (keyType != CKK_RSA)
			return CM_SIGNATURE_INVALID;

		// Fill in the rest of the public key template
		pubKeyTemplate[i].type = CKA_MODULUS;
		pubKeyTemplate[i].pValue = pubKey.key.rsa->modulus.data;
		pubKeyTemplate[i].ulValueLen = pubKey.key.rsa->modulus.num;
		pubKeyTemplate[++i].type = CKA_PUBLIC_EXPONENT;
		pubKeyTemplate[i].pValue = pubKey.key.rsa->publicExponent.data;
		pubKeyTemplate[i].ulValueLen = pubKey.key.rsa->publicExponent.num;
	}
	else if (strcmp(pubKey.oid, SNACC::id_dsa) == 0)
	{
		// Check key type
		if (keyType != CKK_DSA)
			return CM_SIGNATURE_INVALID;

		// Check that the parameters are present
		if (pubKey.params.dsa == NULL)
			return CM_MISSING_PARAMETERS;

		// Fill in the rest of the public key template
		pubKeyTemplate[i].type = CKA_PRIME;
		pubKeyTemplate[i].pValue = pubKey.params.dsa->p.data;
		pubKeyTemplate[i].ulValueLen = pubKey.params.dsa->p.num;
		pubKeyTemplate[++i].type = CKA_SUBPRIME;
		pubKeyTemplate[i].pValue = pubKey.params.dsa->q.data;
		pubKeyTemplate[i].ulValueLen = pubKey.params.dsa->q.num;
		pubKeyTemplate[++i].type = CKA_BASE;
		pubKeyTemplate[i].pValue = pubKey.params.dsa->g.data;
		pubKeyTemplate[i].ulValueLen = pubKey.params.dsa->g.num;
		pubKeyTemplate[++i].type = CKA_VALUE;
		pubKeyTemplate[i].pValue = pubKey.key.y->data;
		pubKeyTemplate[i].ulValueLen = pubKey.key.y->num;
	}
	else if (strcmp(pubKey.oid, SNACC::id_ecPublicKey) == 0)
	{
		// Check key type
		if (keyType != CKK_EC)
			return CM_SIGNATURE_INVALID;

		// Check that the parameters are present
		if (pubKey.params.encoded == NULL)
			return CM_MISSING_PARAMETERS;

		// Fill in the rest of the public key template
		pubKeyTemplate[i].type = CKA_ECDSA_PARAMS;
		pubKeyTemplate[i].pValue = pubKey.params.encoded->data;
		pubKeyTemplate[i].ulValueLen = pubKey.params.encoded->num;
		pubKeyTemplate[++i].type = CKA_EC_POINT;
		pubKeyTemplate[i].pValue = pubKey.key.y->data;
		pubKeyTemplate[i].ulValueLen = pubKey.key.y->num;
	}
	else if (strcmp(pubKey.oid, gDSA_KEA_OID) == 0)
	{
		// Check key type
		if (keyType != CKK_DSA)
			return CM_SIGNATURE_INVALID;

		// Check that the parameters are present
		if (pubKey.params.dsa_kea == NULL)
			return CM_MISSING_PARAMETERS;

		// Fill in the rest of the public key template
		pubKeyTemplate[i].type = CKA_PRIME;
		pubKeyTemplate[i].pValue = pubKey.params.dsa_kea->p.data;
		pubKeyTemplate[i].ulValueLen = pubKey.params.dsa_kea->p.num;
		pubKeyTemplate[++i].type = CKA_SUBPRIME;
		pubKeyTemplate[i].pValue = pubKey.params.dsa_kea->q.data;
		pubKeyTemplate[i].ulValueLen = pubKey.params.dsa_kea->q.num;
		pubKeyTemplate[++i].type = CKA_BASE;
		pubKeyTemplate[i].pValue = pubKey.params.dsa_kea->g.data;
		pubKeyTemplate[i].ulValueLen = pubKey.params.dsa_kea->g.num;
		pubKeyTemplate[++i].type = CKA_VALUE;
		pubKeyTemplate[i].pValue = pubKey.key.combo->dsa_y.data;
		pubKeyTemplate[i].ulValueLen = pubKey.key.combo->dsa_y.num;
	}
	else
		return CM_NOT_IMPLEMENTED;

	// Create the public key object
	CK_RV rv = pFunc->C_CreateObject(session, pubKeyTemplate, ++i,
		&hPubKey);
	if (rv != CKR_OK)
		return CM_NOT_IMPLEMENTED;

	return CM_NO_ERROR;
} // end of createPublicKeyObj()



/////////////////
// Error Table //
/////////////////
static ErrorEntry gErrorTable[] = {
	{ CM_NO_ERROR,	"success" },
	{ CM_MEMORY_ERROR, "memory error" },
	{ CM_INVALID_PARAMETER, "invalid parameter" },
	{ CM_SESSION_NOT_VALID, "invalid session handle" },
	{ CM_NULL_POINTER, "internal error -- null pointer" },
	{ CM_NOT_IMPLEMENTED, "feature/algorithm not supported" },
//	{ CM_BAD_CONFIG_FILE, "invalid SRL configuration file" },
//	{ CM_CONFIG_NOT_FOUND, "missing SRL configuration file" },
//	{ CM_NOT_SELF_SIGNED, "trusted certificate not self-signed" },
	{ CM_ASN_ERROR, "error decoding ASN.1 object" },
	{ CM_MISSING_PARAMETERS, "algorithm parameters in trusted cert are missing" },
	{ CM_INVALID_DN, "incorrect string format of distinguished name" },
	{ CM_NOT_SIG_KEY, "trusted cert does not contain a signature key" },
	{ CM_NOT_FOUND, "object was not found" },
	{ CM_NO_PATH_FOUND, "no certification path could be built" },
//	{ CM_NO_ERROR_INFO, "no extended error information available" },
	{ CM_PATH_VALIDATION_ERROR, "error validating the certification path" },
	{ CM_NO_GET_OBJ, "missing retrieval callback function" },
	{ CM_REQ_CALLBACK_MISSING, "required callback function is missing" },
//	{ CM_NO_TRUSTED_CERTS, "no trusted certs have been specified"},
	{ CM_TRUSTED_CERT_ERROR, "error loading the trusted certs" },
	{ CM_TRUSTED_CERT_NOT_YET_VALID, "trusted cert is not valid yet" },
	{ CM_TRUSTED_CERT_EXPIRED, "trusted cert has expired" },
	{ CM_TRUSTED_CERT_SIG_INVALID, "trusted cert signature invalid" },
	{ CM_INVALID_ENC_OBJ_TYPE, "invalid type flag in EncObject_LL" },
	{ CM_INVALID_ENC_OBJ_LOC, "invalid location flag in EncObject_LL" },
	{ CM_NO_TOKENS_SUPPORT_SIG_ALG, "no token supports this signature algorithm" },
	{ CM_SIGNATURE_INVALID, "object signature invalid" },
//	{ CM_SIGN_OPERATION_FAILED, "sign operation failed" },
	{ CM_DEFAULT_CRYPTO_TOKEN_ERR, "error loading default crypto token" },
	{ CM_CRYPTO_TOKEN_ERROR, "crypto token returned error" },

//	{ CM_LDAP_DLL_INVALID, "SRL failed to load the LDAP DLL" },
//	{ CM_LDAP_UNAVAILABLE, "LDAP service unavailable" },
//	{ CM_LDAP_INITIALIZATION_FAILED, "SRL failed to initialize LDAP" },
//	{ CM_LDAP_BIND_FAILED, "SRL failed to bind to the LDAP server" },
//	{ CM_LDAP_SEARCH_FAILED, "error occurred while searching the LDAP server" },

	{ CM_SRL_INITIALIZATION_FAILED, "SRL library failed to initialize" },
	{ CM_CRL_INITIALIZATION_FAILED, "CRL server library failed to initialize" },

//	{ CM_DB_IO_ERROR, "SRL database I/O error" },
//	{ CM_DB_UNRECOGNIZED_FILE, "unrecognized SRL database file" },
//	{ CM_DB_ALREADY_EXISTS, "SRL database file already exists" },
//	{ CM_DB_FLUSH_FAILURE, "unable to flush the SRL database" },
//	{ CM_DB_INDEX_ERROR , "SRL database index error" },

/* Path validation errors */
	{ CM_SIGNATURE_ALG_MISMATCH, "mismatched certificate signature algorithms" },
	{ CM_CERT_SIGNATURE_INVALID, "certificate signature invalid" },
	{ CM_CERT_NOT_YET_VALID, "certificate is not valid yet" },
	{ CM_CERT_EXPIRED, "certificate has expired" },
	{ CM_NAME_MISMATCH, "names in cert path do not chain correctly" },
	{ CM_PATH_LEN_EXCEEDED, "path length exceeded" },
	{ CM_INVALID_CA, "invalid certificate authority" },
//	{ CM_INVALID_BASIC_CONSTRAINTS, "invalid basic constraints extension" },
//	{ CM_INVALID_NAME_CONSTRAINTS, "invalid name constraints extension" },
//	{ CM_INVALID_POLICY_CONSTRAINTS, "invalid policy constraints extension" },
//	{ CM_INVALID_POLICY_MAPPINGS, "invalid policy mappings extension" },
	{ CM_INVALID_CERT_POLICY, "required certificate policy missing" },
	{ CM_INVALID_SUBJECT_NAME, "invalid subject name" },
	{ CM_INVALID_KEY_USE, "invalid key usage specified" },
	{ CM_UNRECOGNIZED_ALT_NAME, "no recognized alternative name form" },
	{ CM_INVALID_ALT_NAME, "invalid alternative name" },
	{ CM_UNRECOGNIZED_CRITICAL_CERT_EXT, "unrecognized critical cert extension" },

	{ CM_REV_STATUS_NOT_AVAIL, "revocation status unknown for this certificate" },
	{ CM_CRL_SIG_ALG_MISMATCH, "mismatched CRL signature algorithms" },
	{ CM_CRL_SIGNATURE_INVALID, "CRL signature invalid" },
	{ CM_CRL_OUT_OF_DATE, "CRL has expired" },
	{ CM_CERT_REVOKED, "certificate has been revoked (unspecified reason)" },
	{ CM_KEY_COMPROMISED, "public key in certificate has been compromised" },
	{ CM_CERT_AFFILIATION_CHANGED, "certificate has been revoked (affiliation changed)" },
	{ CM_CERT_SUPERSEDED, "certificate has been revoked (superseded)" },
	{ CM_CERT_NO_LONGER_NEEDED, "certificate has been revoked (cessation of operations)" },
	{ CM_CERT_ON_HOLD, "certificate is on hold" },
	{ CM_UNRECOGNIZED_CRITICAL_CRL_EXT, "unrecognized critical CRL extension" },
	{ CM_UNRECOGNIZED_CRITICAL_CRL_ENTRY_EXT, "unrecognized critical CRL entry extension" },
	{ CM_UNRECOGNIZED_EXT_KEY_USAGE, "unrecognized extended key purpose" },
	{ CM_NO_TOKENS_SUPPORT_CERT_SIG_ALG, "no token supports the signature algorithm on this cert" },
	{ CM_NO_TOKENS_SUPPORT_CRL_SIG_ALG, "no token supports the signature algorithm on this CRL" },
	{ CM_CRITICAL_KEY_COMPROMISE_NOT_CHECKED, "CRL not found for critical key compromise reason"},
//	{ CM_REV_REASONS_NOT_CHECKED, "not all revocation reasons were checked for this cert"},
//	{ CM_INVALID_CRL, "invalid CRL" },
//	{ CM_INVALID_INDIRECT_CRL, "invalid indirect CRL" },
//	{ CM_CRL_PATH_NOT_FOUND, "unable to build the path for this CRL"},
//	{ CM_CRL_PATH_NOT_VALID, "error validating the path for this CRL"},
//	{ CM_UNRECOGNIZED_NAME_CONSTRAINTS, "unsupported critical name constraints form"},
//	{ CM_INVALID_EXT_KEY_USE, "invalid critical extended key usage" },
	{ CM_INVALID_TRUSTED_CERT_DN, "subject DN missing from trusted cert" },
//	{ CM_TRUSTED_CERT_NOT_SELF_SIGNED, "trusted certificate not self-signed" },
	{ CM_TRUSTED_CERT_NOT_SIG_KEY, "trusted cert does not contain a signature key" },
	{ CM_TRUSTED_CERT_MISSING_PARAMETERS, "algorithm parameters in trusted cert are missing" },
	{ CM_REQUIRED_NAME_MISSING, "missing required name form" },
	{ CM_ISSUER_CERT_NOT_FOUND, "issuer certificate not found" },
	{ CM_CROSS_CERT_NOT_FOUND, "cross certificate not found" },
	{ CM_PATH_BUILD_PROB_TOO_LOW, "probability of successful path build too low" },
	{ CM_CERT_PRIVILEGE_WITHDRAWN, "certificate has been revoked (privilege withdrawn)" },
	{ CM_MISSING_USER_CERT_POLICY, "user certificate policy missing" },
   { CM_INVALID_POLICY_MAPPING, "invalid policy mapping" },

	{ CM_INVALID_DMS_PRIVILEGE, "invalid privilege in DMS certificate"},
	{ CM_DMS_NULL_SUBJECT_DN, "subject DN missing from DMS certificate"},
	{ CM_DMS_NO_CA_CONSTRAINTS, "CA constraints missing from DMS certificate"},

	{ CM_UNKNOWN_ERROR, "internal error" }			/* Must be last element! */
};


const char* CMU_GetErrorString(short errorCode)
{
	ErrorEntry* pElmt = gErrorTable;
	for ( ; (pElmt->code != errorCode) && (pElmt->code != CM_UNKNOWN_ERROR);
		pElmt++)
		;

	if (pElmt->code != errorCode)
		return "unknown internal error";
	else
		return pElmt->string;
}



// end of CM_Mgr.cpp
