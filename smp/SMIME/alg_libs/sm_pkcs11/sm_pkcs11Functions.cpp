
// sm_pkcs11Functions.cpp
#include "sm_pkcs11.h"

#if defined(_WIN32)
	#if defined(_AFXDLL)
	#else
		#include "windows.h"
	#endif
#else   //_WIN32
#include <dlfcn.h>
#endif  //_WIN32
_BEGIN_CERT_NAMESPACE

void CSM_Pkcs11::LoadDllFunctions(char * pDllName)
{
#if defined (_WINDOWS) || defined (WIN32)
	HINSTANCE hDLL;
#elif defined (SunOS) || defined (Linux)
	void *hDLL;
#endif

#if defined (_WINDOWS) || defined (WIN32)
   hDLL = LoadLibrary(pDllName);
#elif defined (SunOS) || defined (Linux)
	hDLL = dlopen(pDllName, RTLD_NOW);
#endif
	if (hDLL != NULL)
   {
      m_pPkcs11DllName = strdup(pDllName);
#if defined (_WINDOWS) || defined (WIN32)
      
      if ((sfl_c_getFunctionList = 
            (SFL_C_GetFunctionList)GetProcAddress(hDLL, "C_GetFunctionList")) != NULL)
      {
         CK_RV rv;
         CK_FUNCTION_LIST_PTR pFunctionList;

         // Determine which Pkcs11 functions are available by 
         // calling C_GetFunctionList. 
         if ((rv = sfl_c_getFunctionList(&pFunctionList)) == CKR_OK)
         {
            sfl_c_initialize = (SFL_C_Initialize) pFunctionList->C_Initialize;
            sfl_c_finalize = (SFL_C_Finalize) pFunctionList->C_Finalize;
            sfl_c_getInfo = (SFL_C_GetInfo) pFunctionList->C_GetInfo;
            sfl_c_getSlotList = (SFL_C_GetSlotList) pFunctionList->C_GetSlotList;
            sfl_c_getSlotInfo = (SFL_C_GetSlotInfo) pFunctionList->C_GetSlotInfo;
            sfl_c_getTokenInfo = (SFL_C_GetTokenInfo) pFunctionList->C_GetTokenInfo;
            sfl_c_getMechanismList = (SFL_C_GetMechanismList) pFunctionList->C_GetMechanismList;
            sfl_c_getMechanismInfo = (SFL_C_GetMechanismInfo) pFunctionList->C_GetMechanismInfo;
            sfl_c_initToken = (SFL_C_InitToken) pFunctionList->C_InitToken;
            sfl_c_initPIN = (SFL_C_InitPIN) pFunctionList->C_InitPIN;
            sfl_c_setPIN = (SFL_C_SetPIN) pFunctionList->C_SetPIN;
            sfl_c_openSession = (SFL_C_OpenSession) pFunctionList->C_OpenSession;
            sfl_c_closeSession = (SFL_C_CloseSession) pFunctionList->C_CloseSession;
            sfl_c_closeAllSessions = (SFL_C_CloseAllSessions) pFunctionList->C_CloseAllSessions;
            sfl_c_getSessionInfo = (SFL_C_GetSessionInfo) pFunctionList->C_GetSessionInfo;
            sfl_c_getOperationState = (SFL_C_GetOperationState) pFunctionList->C_GetOperationState;
            sfl_c_setOperationState = (SFL_C_SetOperationState) pFunctionList->C_SetOperationState;
            sfl_c_login = (SFL_C_Login) pFunctionList->C_Login;
            sfl_c_logout = (SFL_C_Logout) pFunctionList->C_Logout;
            sfl_c_createObject = (SFL_C_CreateObject) pFunctionList->C_CreateObject;
            sfl_c_copyObject = (SFL_C_CopyObject) pFunctionList->C_CopyObject;
            sfl_c_destroyObject = (SFL_C_DestroyObject) pFunctionList->C_DestroyObject;
            sfl_c_getObjectSize = (SFL_C_GetObjectSize) pFunctionList->C_GetObjectSize;
            sfl_c_getAttributeValue = (SFL_C_GetAttributeValue) pFunctionList->C_GetAttributeValue;
            sfl_c_setAttributeValue = (SFL_C_SetAttributeValue) pFunctionList->C_SetAttributeValue;
            sfl_c_findObjectsInit = (SFL_C_FindObjectsInit) pFunctionList->C_FindObjectsInit;
            sfl_c_findObjects = (SFL_C_FindObjects) pFunctionList->C_FindObjects;
            sfl_c_findObjectsFinal = (SFL_C_FindObjectsFinal) pFunctionList->C_FindObjectsFinal;
            sfl_c_encryptInit = (SFL_C_EncryptInit) pFunctionList->C_EncryptInit;
            sfl_c_encrypt = (SFL_C_Encrypt) pFunctionList->C_Encrypt;
            sfl_c_encryptUpdate = (SFL_C_EncryptUpdate) pFunctionList->C_EncryptUpdate;
            sfl_c_encryptFinal = (SFL_C_EncryptFinal) pFunctionList->C_EncryptFinal;
            sfl_c_decryptInit = (SFL_C_DecryptInit) pFunctionList->C_DecryptInit;
            sfl_c_decryptUpdate = (SFL_C_DecryptUpdate) pFunctionList->C_DecryptUpdate;
            sfl_c_decrypt = (SFL_C_Decrypt) pFunctionList->C_Decrypt;
            sfl_c_decryptFinal = (SFL_C_DecryptFinal) pFunctionList->C_DecryptFinal;
            sfl_c_digestInit = (SFL_C_DigestInit) pFunctionList->C_DigestInit;
            sfl_c_digest = (SFL_C_Digest) pFunctionList->C_Digest;
            sfl_c_digestUpdate = (SFL_C_DigestUpdate) pFunctionList->C_DigestUpdate;
            sfl_c_digestFinal = (SFL_C_DigestFinal) pFunctionList->C_DigestFinal;
            sfl_c_signInit = (SFL_C_SignInit) pFunctionList->C_SignInit;
            sfl_c_signUpdate = (SFL_C_SignUpdate) pFunctionList->C_SignUpdate;
            sfl_c_sign = (SFL_C_Sign) pFunctionList->C_Sign;
            sfl_c_signFinal = (SFL_C_SignFinal) pFunctionList->C_SignFinal;
            sfl_c_signRecoverInit = (SFL_C_SignRecoverInit) pFunctionList->C_SignRecoverInit;
            sfl_c_signRecover = (SFL_C_SignRecover) pFunctionList->C_SignRecover;
            sfl_c_verifyInit = (SFL_C_VerifyInit) pFunctionList->C_VerifyInit;
            sfl_c_verify = (SFL_C_Verify) pFunctionList->C_Verify;
            sfl_c_verifyUpdate = (SFL_C_VerifyUpdate) pFunctionList->C_VerifyUpdate;
            sfl_c_verifyFinal = (SFL_C_VerifyFinal) pFunctionList->C_VerifyFinal;
            sfl_c_verifyRecoverInit = (SFL_C_VerifyRecoverInit) pFunctionList->C_VerifyRecoverInit;
            sfl_c_verifyRecover = (SFL_C_VerifyRecover) pFunctionList->C_VerifyRecover;
            sfl_c_digestEncryptUpdate = (SFL_C_DigestEncryptUpdate) pFunctionList->C_DigestEncryptUpdate;
            sfl_c_decryptDigestUpdate = (SFL_C_DecryptDigestUpdate) pFunctionList->C_DecryptDigestUpdate;
            sfl_c_signEncryptUpdate = (SFL_C_SignEncryptUpdate) pFunctionList->C_SignEncryptUpdate;
            sfl_c_decryptVerifyUpdate = (SFL_C_DecryptVerifyUpdate) pFunctionList->C_DecryptVerifyUpdate;
            sfl_c_generateKey = (SFL_C_GenerateKey) pFunctionList->C_GenerateKey;
            sfl_c_generateKeyPair = (SFL_C_GenerateKeyPair) pFunctionList->C_GenerateKeyPair;
            sfl_c_wrapKey = (SFL_C_WrapKey) pFunctionList->C_WrapKey;
            sfl_c_unwrapKey = (SFL_C_UnwrapKey) pFunctionList->C_UnwrapKey;
            sfl_c_deriveKey = (SFL_C_DeriveKey) pFunctionList->C_DeriveKey;
            sfl_c_seedRandom = (SFL_C_SeedRandom) pFunctionList->C_SeedRandom;
            sfl_c_generateRandom = (SFL_C_GenerateRandom) pFunctionList->C_GenerateRandom;
            sfl_c_getFunctionStatus = (SFL_C_GetFunctionStatus) pFunctionList->C_GetFunctionStatus;
            sfl_c_cancelFunction = (SFL_C_CancelFunction) pFunctionList->C_CancelFunction;
         }
      }
      else
      {
         sfl_c_initialize = (SFL_C_Initialize)GetProcAddress(hDLL, "C_Initialize");
         sfl_c_finalize = (SFL_C_Finalize)GetProcAddress(hDLL, "C_Finalize");
         sfl_c_getInfo = (SFL_C_GetInfo)GetProcAddress(hDLL, "C_GetInfo");

         sfl_c_getSlotList = (SFL_C_GetSlotList)GetProcAddress(hDLL, "C_GetSlotList");
         sfl_c_getSlotInfo = (SFL_C_GetSlotInfo)GetProcAddress(hDLL, "C_GetSlotInfo");
         sfl_c_getTokenInfo = (SFL_C_GetTokenInfo)GetProcAddress(hDLL, "C_GetTokenInfo");
         sfl_c_getMechanismList = (SFL_C_GetMechanismList)GetProcAddress(hDLL, "C_GetMechanismList");
         sfl_c_getMechanismInfo = (SFL_C_GetMechanismInfo)GetProcAddress(hDLL, "C_GetMechanismInfo");
         sfl_c_initToken = (SFL_C_InitToken)GetProcAddress(hDLL, "C_InitToken");
         sfl_c_initPIN = (SFL_C_InitPIN)GetProcAddress(hDLL, "C_InitPIN");
         sfl_c_setPIN = (SFL_C_SetPIN)GetProcAddress(hDLL, "C_SetPIN");
         sfl_c_openSession = (SFL_C_OpenSession)GetProcAddress(hDLL, "C_OpenSession");
         sfl_c_closeSession = (SFL_C_CloseSession)GetProcAddress(hDLL, "C_CloseSession");
         sfl_c_closeAllSessions = (SFL_C_CloseAllSessions)GetProcAddress(hDLL, "C_CloseAllSessions");
         sfl_c_getSessionInfo = (SFL_C_GetSessionInfo)GetProcAddress(hDLL, "C_GetSessionInfo");
         sfl_c_getOperationState = (SFL_C_GetOperationState)GetProcAddress(hDLL, "C_GetOperationState");
         sfl_c_setOperationState = (SFL_C_SetOperationState)GetProcAddress(hDLL, "C_SetOperationState");
         sfl_c_login = (SFL_C_Login)GetProcAddress(hDLL, "C_Login");
         sfl_c_logout = (SFL_C_Logout)GetProcAddress(hDLL, "C_Logout");
         sfl_c_createObject = (SFL_C_CreateObject)GetProcAddress(hDLL, "C_CreateObject");
         sfl_c_copyObject = (SFL_C_CopyObject)GetProcAddress(hDLL, "C_CopyObject");
         sfl_c_destroyObject = (SFL_C_DestroyObject)GetProcAddress(hDLL, "C_DestroyObject");
         sfl_c_getObjectSize = (SFL_C_GetObjectSize)GetProcAddress(hDLL, "C_GetObjectSize");
         sfl_c_getAttributeValue = (SFL_C_GetAttributeValue)GetProcAddress(hDLL, "C_GetAttributeValue");
         sfl_c_setAttributeValue = (SFL_C_SetAttributeValue)GetProcAddress(hDLL, "C_SetAttributeValue");
         sfl_c_findObjectsInit = (SFL_C_FindObjectsInit)GetProcAddress(hDLL, "C_FindObjectsInit");
         sfl_c_findObjects = (SFL_C_FindObjects)GetProcAddress(hDLL, "C_FindObjects");
         sfl_c_findObjectsFinal = (SFL_C_FindObjectsFinal)GetProcAddress(hDLL, "C_FindObjectsFinal");
         sfl_c_encryptInit = (SFL_C_EncryptInit)GetProcAddress(hDLL, "C_EncryptInit");
         sfl_c_encrypt = (SFL_C_Encrypt)GetProcAddress(hDLL, "C_Encrypt");
         sfl_c_encryptUpdate = (SFL_C_EncryptUpdate)GetProcAddress(hDLL, "C_EncryptUpdate");
         sfl_c_encryptFinal = (SFL_C_EncryptFinal)GetProcAddress(hDLL, "C_EncryptFincal");
         sfl_c_decryptInit = (SFL_C_DecryptInit)GetProcAddress(hDLL, "C_DecryptInit");
         sfl_c_decrypt = (SFL_C_Decrypt)GetProcAddress(hDLL, "C_Decrypt");
         sfl_c_decryptUpdate = (SFL_C_DecryptUpdate)GetProcAddress(hDLL, "C_DecryptUpdate");
         sfl_c_decryptFinal = (SFL_C_DecryptFinal)GetProcAddress(hDLL, "C_DecryptFinal");
         sfl_c_digestInit = (SFL_C_DigestInit)GetProcAddress(hDLL, "C_DigestInit");
         sfl_c_digest = (SFL_C_Digest)GetProcAddress(hDLL, "C_Digest");
         sfl_c_digestUpdate = (SFL_C_DigestUpdate)GetProcAddress(hDLL, "C_DigestUpdate");
         sfl_c_digestKey = (SFL_C_DigestKey)GetProcAddress(hDLL, "C_DigestKey");
         sfl_c_digestFinal = (SFL_C_DigestFinal)GetProcAddress(hDLL, "C_DigestFinal");
         sfl_c_signInit = (SFL_C_SignInit)GetProcAddress(hDLL, "C_SignInit");
         sfl_c_sign = (SFL_C_Sign)GetProcAddress(hDLL, "C_Sign");
         sfl_c_signUpdate = (SFL_C_SignUpdate)GetProcAddress(hDLL, "C_SignUpdate");
         sfl_c_signFinal = (SFL_C_SignFinal)GetProcAddress(hDLL, "C_SignFinal");
         sfl_c_signRecoverInit = (SFL_C_SignRecoverInit)GetProcAddress(hDLL, "C_SignRecoverInit");
         sfl_c_signRecover = (SFL_C_SignRecover)GetProcAddress(hDLL, "C_SignRecover");
         sfl_c_verifyInit = (SFL_C_VerifyInit)GetProcAddress(hDLL, "C_VerifyInit");
         sfl_c_verify = (SFL_C_Verify)GetProcAddress(hDLL, "C_Verify");
         sfl_c_verifyUpdate = (SFL_C_VerifyUpdate)GetProcAddress(hDLL, "C_VerifyUpdate");
         sfl_c_verifyFinal = (SFL_C_VerifyFinal)GetProcAddress(hDLL, "C_VerifyFinal");
         sfl_c_verifyRecoverInit = (SFL_C_VerifyRecoverInit)GetProcAddress(hDLL, "C_VerifyRecoverInit");
         sfl_c_verifyRecover = (SFL_C_VerifyRecover)GetProcAddress(hDLL, "C_VerifyRecover");
         sfl_c_digestEncryptUpdate = (SFL_C_DigestEncryptUpdate)GetProcAddress(hDLL, "C_DigestEncryptUpdate");
         sfl_c_decryptDigestUpdate = (SFL_C_DecryptDigestUpdate)GetProcAddress(hDLL, "C_DecryptDigestUpdate");
         sfl_c_signEncryptUpdate = (SFL_C_SignEncryptUpdate)GetProcAddress(hDLL, "C_SignEncryptUpdate");
         sfl_c_decryptVerifyUpdate = (SFL_C_DecryptVerifyUpdate)GetProcAddress(hDLL, "C_DecryptVerifyUpdate");
         sfl_c_generateKey = (SFL_C_GenerateKey)GetProcAddress(hDLL, "C_GenerateKey");
         sfl_c_generateKeyPair = (SFL_C_GenerateKeyPair)GetProcAddress(hDLL, "C_GenerateKeyPair");
         sfl_c_wrapKey = (SFL_C_WrapKey)GetProcAddress(hDLL, "C_WrapKey");
         sfl_c_unwrapKey = (SFL_C_UnwrapKey)GetProcAddress(hDLL, "C_UnwrapKey");
         sfl_c_deriveKey = (SFL_C_DeriveKey)GetProcAddress(hDLL, "C_DeriveKey");
         sfl_c_seedRandom = (SFL_C_SeedRandom)GetProcAddress(hDLL, "C_SeedRandom");
         sfl_c_generateRandom = (SFL_C_GenerateRandom)GetProcAddress(hDLL, "C_GenerateRandom");
         sfl_c_getFunctionStatus = (SFL_C_GetFunctionStatus)GetProcAddress(hDLL, "C_GetFunctionStatus");
         sfl_c_cancelFunction = (SFL_C_CancelFunction)GetProcAddress(hDLL, "C_CancelFunction");
      }
#elif defined (SunOS) || defined (Linux)

      sfl_c_initialize = (SFL_C_Initialize)dlsym(hDLL, "C_Initialize");
      sfl_c_finalize = (SFL_C_Finalize)dlsym(hDLL, "C_Finalize");
      sfl_c_getInfo = (SFL_C_GetInfo)dlsym(hDLL, "C_GetInfo");
      sfl_c_getFunctionList = (SFL_C_GetFunctionList)dlsym(hDLL, "C_GetFunctionList");
      sfl_c_getSlotList = (SFL_C_GetSlotList)dlsym(hDLL, "C_GetSlotList");
      sfl_c_getSlotInfo = (SFL_C_GetSlotInfo)dlsym(hDLL, "C_GetSlotInfo");
      sfl_c_getTokenInfo = (SFL_C_GetTokenInfo)dlsym(hDLL, "C_GetTokenInfo");
      sfl_c_getMechanismList = (SFL_C_GetMechanismList)dlsym(hDLL, "C_GetMechanismList");
      sfl_c_getMechanismInfo = (SFL_C_GetMechanismInfo)dlsym(hDLL, "C_GetMechanismInfo");
      sfl_c_initToken = (SFL_C_InitToken)dlsym(hDLL, "C_InitToken");
      sfl_c_initPIN = (SFL_C_InitPIN)dlsym(hDLL, "C_InitPIN");
      sfl_c_setPIN = (SFL_C_SetPIN)dlsym(hDLL, "C_SetPIN");
      sfl_c_openSession = (SFL_C_OpenSession)dlsym(hDLL, "C_OpenSession");
      sfl_c_closeSession = (SFL_C_CloseSession)dlsym(hDLL, "C_CloseSession");
      sfl_c_closeAllSessions = (SFL_C_CloseAllSessions)dlsym(hDLL, "C_CloseAllSessions");
      sfl_c_getSessionInfo = (SFL_C_GetSessionInfo)dlsym(hDLL, "C_GetSessionInfo");
      sfl_c_getOperationState = (SFL_C_GetOperationState)dlsym(hDLL, "C_GetOperationState");
      sfl_c_setOperationState = (SFL_C_SetOperationState)dlsym(hDLL, "C_SetOperationState");
      sfl_c_login = (SFL_C_Login)dlsym(hDLL, "C_Login");
      sfl_c_logout = (SFL_C_Logout)dlsym(hDLL, "C_Logout");
      sfl_c_createObject = (SFL_C_CreateObject)dlsym(hDLL, "C_CreateObject");
      sfl_c_copyObject = (SFL_C_CopyObject)dlsym(hDLL, "C_CopyObject");
      sfl_c_destroyObject = (SFL_C_DestroyObject)dlsym(hDLL, "C_DestroyObject");
      sfl_c_getObjectSize = (SFL_C_GetObjectSize)dlsym(hDLL, "C_GetObjectSize");
      sfl_c_getAttributeValue = (SFL_C_GetAttributeValue)dlsym(hDLL, "C_GetAttributeValue");
      sfl_c_setAttributeValue = (SFL_C_SetAttributeValue)dlsym(hDLL, "C_SetAttributeValue");
      sfl_c_findObjectsInit = (SFL_C_FindObjectsInit)dlsym(hDLL, "C_FindObjectsInit");
      sfl_c_findObjects = (SFL_C_FindObjects)dlsym(hDLL, "C_FindObjects");
      sfl_c_findObjectsFinal = (SFL_C_FindObjectsFinal)dlsym(hDLL, "C_FindObjectsFinal");
      sfl_c_encryptInit = (SFL_C_EncryptInit)dlsym(hDLL, "C_EncryptInit");
      sfl_c_encrypt = (SFL_C_Encrypt)dlsym(hDLL, "C_Encrypt");
      sfl_c_encryptUpdate = (SFL_C_EncryptUpdate)dlsym(hDLL, "C_EncryptUpdate");
      sfl_c_encryptFinal = (SFL_C_EncryptFinal)dlsym(hDLL, "C_EncryptFincal");
      sfl_c_decryptInit = (SFL_C_DecryptInit)dlsym(hDLL, "C_DecryptInit");
      sfl_c_decrypt = (SFL_C_Decrypt)dlsym(hDLL, "C_Decrypt");
      sfl_c_decryptUpdate = (SFL_C_DecryptUpdate)dlsym(hDLL, "C_DecryptUpdate");
      sfl_c_decryptFinal = (SFL_C_DecryptFinal)dlsym(hDLL, "C_DecryptFinal");
      sfl_c_digestInit = (SFL_C_DigestInit)dlsym(hDLL, "C_DigestInit");
      sfl_c_digest = (SFL_C_Digest)dlsym(hDLL, "C_Digest");
      sfl_c_digestUpdate = (SFL_C_DigestUpdate)dlsym(hDLL, "C_DigestUpdate");
      sfl_c_digestKey = (SFL_C_DigestKey)dlsym(hDLL, "C_DigestKey");
      sfl_c_digestFinal = (SFL_C_DigestFinal)dlsym(hDLL, "C_DigestFinal");
      sfl_c_signInit = (SFL_C_SignInit)dlsym(hDLL, "C_SignInit");
      sfl_c_sign = (SFL_C_Sign)dlsym(hDLL, "C_Sign");
      sfl_c_signUpdate = (SFL_C_SignUpdate)dlsym(hDLL, "C_SignUpdate");
      sfl_c_signFinal = (SFL_C_SignFinal)dlsym(hDLL, "C_SignFinal");
      sfl_c_signRecoverInit = (SFL_C_SignRecoverInit)dlsym(hDLL, "C_SignRecoverInit");
      sfl_c_signRecover = (SFL_C_SignRecover)dlsym(hDLL, "C_SignRecover");
      sfl_c_verifyInit = (SFL_C_VerifyInit)dlsym(hDLL, "C_VerifyInit");
      sfl_c_verify = (SFL_C_Verify)dlsym(hDLL, "C_Verify");
      sfl_c_verifyUpdate = (SFL_C_VerifyUpdate)dlsym(hDLL, "C_VerifyUpdate");
      sfl_c_verifyFinal = (SFL_C_VerifyFinal)dlsym(hDLL, "C_VerifyFinal");
      sfl_c_verifyRecoverInit = (SFL_C_VerifyRecoverInit)dlsym(hDLL, "C_VerifyRecoverInit");
      sfl_c_verifyRecover = (SFL_C_VerifyRecover)dlsym(hDLL, "C_VerifyRecover");
      sfl_c_digestEncryptUpdate = (SFL_C_DigestEncryptUpdate)dlsym(hDLL, "C_DigestEncryptUpdate");
      sfl_c_decryptDigestUpdate = (SFL_C_DecryptDigestUpdate)dlsym(hDLL, "C_DecryptDigestUpdate");
      sfl_c_signEncryptUpdate = (SFL_C_SignEncryptUpdate)dlsym(hDLL, "C_SignEncryptUpdate");
      sfl_c_decryptVerifyUpdate = (SFL_C_DecryptVerifyUpdate)dlsym(hDLL, "C_DecryptVerifyUpdate");
      sfl_c_generateKey = (SFL_C_GenerateKey)dlsym(hDLL, "C_GenerateKey");
      sfl_c_generateKeyPair = (SFL_C_GenerateKeyPair)dlsym(hDLL, "C_GenerateKeyPair");
      sfl_c_wrapKey = (SFL_C_WrapKey)dlsym(hDLL, "C_WrapKey");
      sfl_c_unwrapKey = (SFL_C_UnwrapKey)dlsym(hDLL, "C_UnwrapKey");
      sfl_c_deriveKey = (SFL_C_DeriveKey)dlsym(hDLL, "C_DeriveKey");
      sfl_c_seedRandom = (SFL_C_SeedRandom)dlsym(hDLL, "C_SeedRandom");
      sfl_c_generateRandom = (SFL_C_GenerateRandom)dlsym(hDLL, "C_GenerateRandom");
      sfl_c_getFunctionStatus = (SFL_C_GetFunctionStatus)dlsym(hDLL, "C_GetFunctionStatus");
      sfl_c_cancelFunction = (SFL_C_CancelFunction)dlsym(hDLL, "C_CancelFunction");

#endif /* SunOS  & Windows dynamic loading of symbols */
   }
}
void CSM_Pkcs11::SetDllFunctions(CSM_Pkcs11 *pPkcs11)
{
   sfl_c_initialize = pPkcs11->sfl_c_initialize;
   sfl_c_finalize = pPkcs11->sfl_c_finalize;
   sfl_c_getInfo = pPkcs11->sfl_c_getInfo;
   sfl_c_getFunctionList = pPkcs11->sfl_c_getFunctionList;
   sfl_c_getSlotList = pPkcs11->sfl_c_getSlotList;
   sfl_c_getSlotInfo = pPkcs11->sfl_c_getSlotInfo;
   sfl_c_getTokenInfo = pPkcs11->sfl_c_getTokenInfo;
   sfl_c_getMechanismList = pPkcs11->sfl_c_getMechanismList;
   sfl_c_getMechanismInfo = pPkcs11->sfl_c_getMechanismInfo;
   sfl_c_initToken = pPkcs11->sfl_c_initToken;
   sfl_c_initPIN = pPkcs11->sfl_c_initPIN;
   sfl_c_setPIN = pPkcs11->sfl_c_setPIN;
   sfl_c_openSession = pPkcs11->sfl_c_openSession;
   sfl_c_closeSession = pPkcs11->sfl_c_closeSession;
   sfl_c_closeAllSessions = pPkcs11->sfl_c_closeAllSessions;
   sfl_c_getSessionInfo = pPkcs11->sfl_c_getSessionInfo;
   sfl_c_getOperationState = pPkcs11->sfl_c_getOperationState;
   sfl_c_setOperationState = pPkcs11->sfl_c_setOperationState;
   sfl_c_login = pPkcs11->sfl_c_login;
   sfl_c_logout = pPkcs11->sfl_c_logout;
   sfl_c_createObject = pPkcs11->sfl_c_createObject;
   sfl_c_copyObject = pPkcs11->sfl_c_copyObject;
   sfl_c_destroyObject = pPkcs11->sfl_c_destroyObject;
   sfl_c_getObjectSize = pPkcs11->sfl_c_getObjectSize;
   sfl_c_getAttributeValue = pPkcs11->sfl_c_getAttributeValue;
   sfl_c_setAttributeValue = pPkcs11->sfl_c_setAttributeValue;
   sfl_c_findObjectsInit = pPkcs11->sfl_c_findObjectsInit;
   sfl_c_findObjects = pPkcs11->sfl_c_findObjects;
   sfl_c_findObjectsFinal = pPkcs11->sfl_c_findObjectsFinal;
   sfl_c_encryptInit = pPkcs11->sfl_c_encryptInit;
   sfl_c_encrypt = pPkcs11->sfl_c_encrypt;
   sfl_c_encryptUpdate = pPkcs11->sfl_c_encryptUpdate;
   sfl_c_encryptFinal = pPkcs11->sfl_c_encryptFinal;
   sfl_c_decryptInit = pPkcs11->sfl_c_decryptInit;
   sfl_c_decrypt = pPkcs11->sfl_c_decrypt;
   sfl_c_decryptUpdate = pPkcs11->sfl_c_decryptUpdate;
   sfl_c_decryptFinal = pPkcs11->sfl_c_decryptFinal;
   sfl_c_digestInit = pPkcs11->sfl_c_digestInit;
   sfl_c_digest = pPkcs11->sfl_c_digest;
   sfl_c_digestUpdate = pPkcs11->sfl_c_digestUpdate;
   sfl_c_digestKey = pPkcs11->sfl_c_digestKey;
   sfl_c_digestFinal = pPkcs11->sfl_c_digestFinal;
   sfl_c_signInit = pPkcs11->sfl_c_signInit;
   sfl_c_sign = pPkcs11->sfl_c_sign;
   sfl_c_signUpdate = pPkcs11->sfl_c_signUpdate;
   sfl_c_signFinal = pPkcs11->sfl_c_signFinal;
   sfl_c_signRecoverInit = pPkcs11->sfl_c_signRecoverInit;
   sfl_c_signRecover = pPkcs11->sfl_c_signRecover;
   sfl_c_verifyInit = pPkcs11->sfl_c_verifyInit;
   sfl_c_verify = pPkcs11->sfl_c_verify;
   sfl_c_verifyUpdate = pPkcs11->sfl_c_verifyUpdate;
   sfl_c_verifyFinal = pPkcs11->sfl_c_verifyFinal;
   sfl_c_verifyRecoverInit = pPkcs11->sfl_c_verifyRecoverInit;
   sfl_c_verifyRecover = pPkcs11->sfl_c_verifyRecover;
   sfl_c_digestEncryptUpdate = pPkcs11->sfl_c_digestEncryptUpdate;
   sfl_c_decryptDigestUpdate = pPkcs11->sfl_c_decryptDigestUpdate;
   sfl_c_signEncryptUpdate = pPkcs11->sfl_c_signEncryptUpdate;
   sfl_c_decryptVerifyUpdate = pPkcs11->sfl_c_decryptVerifyUpdate;
   sfl_c_generateKey = pPkcs11->sfl_c_generateKey;
   sfl_c_generateKeyPair = pPkcs11->sfl_c_generateKeyPair;
   sfl_c_wrapKey = pPkcs11->sfl_c_wrapKey;
   sfl_c_unwrapKey = pPkcs11->sfl_c_unwrapKey;
   sfl_c_deriveKey = pPkcs11->sfl_c_deriveKey;
   sfl_c_seedRandom = pPkcs11->sfl_c_seedRandom;
   sfl_c_generateRandom = pPkcs11->sfl_c_generateRandom;
   sfl_c_getFunctionStatus = pPkcs11->sfl_c_getFunctionStatus;
   sfl_c_cancelFunction = pPkcs11->sfl_c_cancelFunction;
}

_END_CERT_NAMESPACE

// EOF sm_pkcs11Functions.cpp
