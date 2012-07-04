/************************ PKCS #11 General Purpose Functions ************************
 *
 * This source file contains the following general purpose functions:
 *  + C_Initialize
 *  + C_Finalize
 *  + C_GetInfo
 *  + C_GetFunctionList
 *
 */

#include "p11cryptopp_internal.h"
#include <time.h>


// CKManager class
class CKManager
{
public:
	CKManager()									{ m_isInitialized = false; }
	~CKManager()								{ m_isInitialized = false; }

	CK_RV Initialize(CK_C_INITIALIZE_ARGS_PTR pArgs);
	CK_RV Finalize(CK_VOID_PTR pReserved);
	bool IsInitialized() const					{ return m_isInitialized; }

	std::pair<SessionMap::iterator, bool> CreateSession();
	CKSessionClass* FindSession(CK_SESSION_HANDLE hSession);
	CK_RV RemoveSession(CK_SESSION_HANDLE hSession);
	CK_RV RemoveAllSessions(CK_SLOT_ID slotID);

private:
	// Private members
	bool m_isInitialized;
	SessionMap m_sessionMap;
};


// Global variables
static CKManager gManagerObject;
const char kManufacturerName[32] = "DigitalNet Govt Solutions, LLC";


/* C_Initialize()
 */
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	return gManagerObject.Initialize((CK_C_INITIALIZE_ARGS_PTR)pInitArgs);
}


/* C_Finalize()
 * C_Finalize is called to indicate that an application is finished with the Cryptoki library. It
 * should be the last Cryptoki call made by an application. The pReserved parameter is reserved
 * for future versions; for this version, it should be set to NULL_PTR (if C_Finalize is called 
 * with a non-NULL_PTR value for pReserved, it should return the value
 * CKR_ARGUMENTS_BAD.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	return gManagerObject.Finalize(pReserved);
}

/* C_GetInfo()
 * C_GetInfo returns general information about Cryptoki. pInfo points to the location 
 * that receives the information.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check that the info pointer is not NULL
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;

	// Fill in the CK_INFO fields
	pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 11;

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, kManufacturerName, strlen(kManufacturerName));

	pInfo->flags = 0;

	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	const char kLibDesc[32] = "PKCS#11 for Crypto++ v5.1";
	memcpy(pInfo->libraryDescription, kLibDesc, strlen(kLibDesc));

	pInfo->libraryVersion.major = 1;
	pInfo->libraryVersion.major = 0;

	return CKR_OK;
}

/* C_GetFunctionList()
 *
 * C_GetFunctionList obtains a pointer to the Cryptoki library’s list of function pointers.
 * ppFunctionList points to a value which will receive a pointer to the library’s
 *  CK_FUNCTION_LIST structure, which in turn contains function pointers for all the Cryptoki
 * API routines in the library. The pointer thus obtained may point into memory which is
 * owned by the Cryptoki library, and which may or may not be writable. Whether or not this
 * is the case, no attempt should be made to write to this memory.
 */

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	static CK_FUNCTION_LIST functionList =
	{
		/* Version */
		{ 2, 11 },
		/* General-purpose */
		C_Initialize,
		C_Finalize,
		C_GetInfo, C_GetFunctionList,
		/* Slot and token management */
		C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList,
		C_GetMechanismInfo, C_InitToken, C_InitPIN, C_SetPIN,
		/* Session management */
		C_OpenSession, C_CloseSession, C_CloseAllSessions, C_GetSessionInfo,
		C_GetOperationState, C_SetOperationState, C_Login, C_Logout,
		/* Object management */
		C_CreateObject, C_CopyObject, C_DestroyObject, C_GetObjectSize,
		C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit,
		C_FindObjects, C_FindObjectsFinal,
		/* Encryption and decryption */
		C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal,
		C_DecryptInit, C_Decrypt, C_DecryptUpdate, C_DecryptFinal,
		/* Message digesting */
		C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal,
		/* Signing and MACing */
		C_SignInit, C_Sign, C_SignUpdate, C_SignFinal,
		C_SignRecoverInit, C_SignRecover,
		/* Verifying signatures and MACs */
		C_VerifyInit, C_Verify, C_VerifyUpdate, C_VerifyFinal,
		C_VerifyRecoverInit, C_VerifyRecover,
		/* Dual-function cryptographic operations */
		C_DigestEncryptUpdate, C_DecryptDigestUpdate, C_SignEncryptUpdate,
		C_DecryptVerifyUpdate,
		/* Key management */
		C_GenerateKey, C_GenerateKeyPair, C_WrapKey, C_UnwrapKey, C_DeriveKey,
		/* Random number generation */
		C_SeedRandom, C_GenerateRandom,
		/* Parallel function management */
		C_GetFunctionStatus, C_CancelFunction,
		/* Functions added in for Cryptoki Version 2.01 or later */
		C_WaitForSlotEvent
	};

	if (ppFunctionList == NULL_PTR)
	{
		return CKR_ARGUMENTS_BAD;
	}

	*ppFunctionList = &functionList;
	return CKR_OK;

#ifdef _OLD_CODE
	/* General-purpose */
	(*ppFunctionList)->C_Initialize = C_Initialize;
	(*ppFunctionList)->C_Finalize = C_Finalize;
	(*ppFunctionList)->C_GetInfo = C_GetInfo;
	(*ppFunctionList)->C_GetFunctionList = C_GetFunctionList;
	/* Slot and token management */
	(*ppFunctionList)->C_GetSlotList = C_GetSlotList;
	(*ppFunctionList)->C_GetSlotInfo = C_GetSlotInfo;
	(*ppFunctionList)->C_GetTokenInfo = C_GetTokenInfo;
	(*ppFunctionList)->C_GetMechanismList = C_GetMechanismList;
	(*ppFunctionList)->C_GetMechanismInfo = C_GetMechanismInfo;
	(*ppFunctionList)->C_InitToken = C_InitToken;
	(*ppFunctionList)->C_InitPIN = C_InitPIN;
	(*ppFunctionList)->C_SetPIN = C_SetPIN;
	/* Session management */
	(*ppFunctionList)->C_OpenSession = C_OpenSession;
	(*ppFunctionList)->C_CloseSession = C_CloseSession;
	(*ppFunctionList)->C_CloseAllSessions = C_CloseAllSessions;
	(*ppFunctionList)->C_GetSessionInfo = C_GetSessionInfo;
	(*ppFunctionList)->C_GetOperationState = C_GetOperationState;
	(*ppFunctionList)->C_SetOperationState = C_SetOperationState;
	(*ppFunctionList)->C_Login = C_Login;
	(*ppFunctionList)->C_Logout = C_Logout;
	/* Object management */
	(*ppFunctionList)->C_CreateObject = C_CreateObject;
	(*ppFunctionList)->C_CopyObject = C_CopyObject;
	(*ppFunctionList)->C_DestroyObject = C_DestroyObject;
	(*ppFunctionList)->C_GetObjectSize = C_GetObjectSize;
	(*ppFunctionList)->C_GetAttributeValue = C_GetAttributeValue;
	(*ppFunctionList)->C_SetAttributeValue = C_SetAttributeValue;
	(*ppFunctionList)->C_FindObjectsInit = C_FindObjectsInit;
	(*ppFunctionList)->C_FindObjects = C_FindObjects;
	(*ppFunctionList)->C_FindObjectsFinal = C_FindObjectsFinal;
	/* Encryption and decryption */

	/* digest functions */
	(*ppFunctionList)->C_DigestInit = C_DigestInit;
    (*ppFunctionList)->C_Digest = C_Digest;
	(*ppFunctionList)->C_DigestUpdate = C_DigestUpdate;
	(*ppFunctionList)->C_DigestKey = C_DigestKey;
    (*ppFunctionList)->C_DigestFinal = C_DigestFinal;
	/* verify functions */
	(*ppFunctionList)->C_VerifyInit = C_VerifyInit;
	(*ppFunctionList)->C_Verify = C_Verify;
	(*ppFunctionList)->C_DigestInit = C_DigestInit;
	/* random functions */
	(*ppFunctionList)->C_SeedRandom = C_SeedRandom;
	(*ppFunctionList)->C_GenerateRandom = C_GenerateRandom;
	/* key functions */
//	(*ppFunctionList)->C_GenerateKey = C_GenerateKey;
//	(*ppFunctionList)->C_GenerateKeyPair = C_GenerateKeyPair;
	/* sign functions */
    (*ppFunctionList)->C_SignInit = C_SignInit;
	(*ppFunctionList)->C_Sign = C_Sign;
#endif // _OLD_CODE
}


////////////////////////////////////////////////////////////////
// Implementation of the CKManager class
CK_RV CKManager::Initialize(CK_C_INITIALIZE_ARGS_PTR pArgs)
{
	// Check that the library isn't already initialized
	if (m_isInitialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	/* PIERCE: seed random number generated with a better value
	 */
	
	/* seed random number generator with current time */
//	byte seed2[]={0xd5, 0x01, 0x4e, 0x4b, 0x60, 0xef, 0x2b, 0xa8, 0xb6, 0x21,
//		0x1b, 0x40, 0x62, 0xba, 0x32, 0x24, 0xe0, 0x42, 0x7d, 0xd3};
	
	// Seed random number generator with string form of current time
	time_t now;
	time(&now);
	gRNG.Put((const byte*)ctime(&now), 24);

	// Set the isInitialized member to true and return
	m_isInitialized = true;
	return CKR_OK;
}


CK_RV CKManager::Finalize(CK_VOID_PTR pReserved)
{
	// Check that the library is initialized
	if (!m_isInitialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check parameter
	if (pReserved != NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	// Delete all the open sessions
	m_sessionMap.clear();

	// Set the isInitialized member to false and return
	m_isInitialized = false;
	return CKR_OK;
}


std::pair<SessionMap::iterator, bool> CKManager::CreateSession()
{
	// Try to insert the new session into the session map
	CK_SESSION_HANDLE newHandle;
	CKSessionClass newSession;

	int numTries = 0;
	std::pair<SessionMap::iterator, bool> insertResult;
	do
	{
		// Create unique session handle
		newHandle = 0;
		for (size_t i = 0; i < sizeof(newHandle); ++i)
		{
			newHandle <<= 8;
			newHandle += gRNG.GenerateByte();
		}

		// Try to insert the new entry
		insertResult = m_sessionMap.insert(
			SessionMap::value_type(newHandle, newSession));

	} while (!insertResult.second && (++numTries < 100));

	return insertResult;
}


CKSessionClass* CKManager::FindSession(CK_SESSION_HANDLE hSession)
{
	SessionMap::iterator i = m_sessionMap.find(hSession);
	if (i == m_sessionMap.end())
		return NULL;

	return &i->second;
}


CK_RV CKManager::RemoveSession(CK_SESSION_HANDLE hSession)
{
	// Check that the library is initialized
	if (!m_isInitialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Erase the session from the map, return an error if not present
	if (m_sessionMap.erase(hSession) == 0)
		return CKR_SESSION_HANDLE_INVALID;

	return CKR_OK;
}


CK_RV CKManager::RemoveAllSessions(CK_SLOT_ID slotID)
{
	// Check that the library is initialized
	if (!m_isInitialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check that the slotID is valid
	if (slotID != 0)
		return CKR_SLOT_ID_INVALID;

	// Delete all the open sessions
	m_sessionMap.clear();

	return CKR_OK;
}


////////////////////////////////////////////////////////////////
// Internal Functions
bool LibraryIsInitialized()
{
	return gManagerObject.IsInitialized();
}


std::pair<SessionMap::iterator, bool> CreateNewSession()
{
	return gManagerObject.CreateSession();
}


CK_RV CloseSession(CK_SESSION_HANDLE hSession)
{
	return gManagerObject.RemoveSession(hSession);
}


CK_RV CloseAllSessions(CK_SLOT_ID slotID)
{
	return gManagerObject.RemoveAllSessions(slotID);
}


CKSessionClass* GetSessionFromHandle(CK_SESSION_HANDLE hSession)
{
	return gManagerObject.FindSession(hSession);
}
