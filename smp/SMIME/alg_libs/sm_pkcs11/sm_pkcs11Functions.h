
#ifndef _SM_PKCS11FUNCTIONS_H_
#define _SM_PKCS11FUNCTIONS_H_

/* The packing convention for Cryptoki structures should be set.  
 * The Cryptoki convention on packing is that structures should 
 * be 1-byte aligned.
 *
 * In a Win32 environment, this might be done by using the
 * following preprocessor directive before including pkcs11.h
 * or pkcs11t.h and ..
 */
#ifdef WIN32
#pragma warning( disable : 4103 )
#pragma pack(push, cryptoki, 1)
#endif

#if defined(_WIN32)
	#if defined(_AFXDLL)
	#else
//		#include "windows.h"
	#endif
#endif

#include "pkcs11.h"
#include "pkcs11t.h"

/* calling conventions used by library */
#ifndef PKCS11_CALL
   #if defined( _WINDOWS ) || defined( _WIN32 )
      #define PKCS11_C __cdecl
      #ifndef _WIN32 
         #define __stdcall _far _pascal
         #define PKCS11_CALLBACK _loadds
      #else
         #define PKCS11_CALLBACK
      #endif /* _WIN32 */
      #define PKCS11_PASCAL __stdcall
      #define PKCS11_CALL PKCS11_PASCAL
   #else /* _WINDOWS */
      #define PKCS11_C
      #define PKCS11_CALLBACK
      #define PKCS11_PASCAL
      #define PKCS11_CALL
   #endif /* _WINDOWS */
#endif /* PKCS11_CALL */

/*
 * function prototypes 
 */

#ifndef PKCS11_API
   #if defined( _WINDOWS ) || defined( _WIN32 )
      #if defined(_WIN32)
         #define PKCS11_API(rt) __declspec( dllexport ) rt
      #else
         #define PKCS11_API(rt) rt
      #endif
   #else /* _WINDOWS */
      #define PKCS11_API(rt) rt
   #endif /* _WINDOWS */
#endif /* PKCS11_API */

typedef CK_RV (*SFL_C_Initialize) (CK_VOID_PTR pInitArgs);
typedef CK_RV (*SFL_C_Initialize) (CK_VOID_PTR pInitArgs);
typedef CK_RV (*SFL_C_Finalize) (CK_VOID_PTR pReserved);
typedef CK_RV (*SFL_C_GetInfo) (CK_INFO_PTR pInfo);
typedef CK_RV (*SFL_C_GetFunctionList) (CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV (*SFL_C_GetSlotList) (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,  CK_ULONG_PTR pulCount);
typedef CK_RV (*SFL_C_GetSlotInfo) (CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV (*SFL_C_GetTokenInfo) (CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV (*SFL_C_GetMechanismList)  (CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
typedef CK_RV (*SFL_C_GetMechanismInfo) (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pIfno);
typedef CK_RV (*SFL_C_InitToken) (CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_CHAR_PTR pLabel);
typedef CK_RV (*SFL_C_InitPIN) (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*SFL_C_SetPIN) (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef CK_RV (*SFL_C_OpenSession) (CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV (*SFL_C_CloseSession) (CK_SESSION_HANDLE hSession);
typedef CK_RV (*SFL_C_CloseAllSessions) (CK_SLOT_ID slotID);
typedef CK_RV (*SFL_C_GetSessionInfo) (CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV (*SFL_C_GetOperationState) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR  pulOperationStateLen);
typedef CK_RV (*SFL_C_SetOperationState) (CK_SESSION_HANDLE hSession, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncruptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV (*SFL_C_Login) (CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef CK_RV (*SFL_C_Logout) (CK_SESSION_HANDLE hSession);
typedef CK_RV (*SFL_C_CreateObject) (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulcount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV (*SFL_C_CopyObject) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (*SFL_C_DestroyObject) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV (*SFL_C_GetObjectSize) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
typedef CK_RV (*SFL_C_GetAttributeValue) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*SFL_C_SetAttributeValue) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*SFL_C_FindObjectsInit) (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef CK_RV (*SFL_C_FindObjects) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
typedef CK_RV (*SFL_C_FindObjectsFinal) (CK_SESSION_HANDLE hSession);
typedef CK_RV (*SFL_C_EncryptInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*SFL_C_Encrypt) (CK_SESSION_HANDLE  hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
typedef CK_RV (*SFL_C_EncryptUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*SFL_C_EncryptFinal) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR plastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPart);
typedef CK_RV (*SFL_C_DecryptInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*SFL_C_Decrypt) (CK_SESSION_HANDLE  hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*SFL_C_DecryptUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*SFL_C_DecryptFinal) (CK_SESSION_HANDLE  hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
typedef CK_RV (*SFL_C_DigestInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechansim);
typedef CK_RV (*SFL_C_Digest) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR  pulDigestLen);
typedef CK_RV (*SFL_C_DigestUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,  CK_ULONG ulPartLen);
typedef CK_RV (*SFL_C_DigestKey) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*SFL_C_DigestFinal) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef CK_RV (*SFL_C_SignInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*SFL_C_Sign) (CK_SESSION_HANDLE hSession , CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*SFL_C_SignUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*SFL_C_SignFinal) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*SFL_C_SignRecoverInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*SFL_C_SignRecover) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef CK_RV (*SFL_C_VerifyInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechansim, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*SFL_C_Verify) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*SFL_C_VerifyUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef CK_RV (*SFL_C_VerifyFinal) (CK_SESSION_HANDLE  hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef CK_RV (*SFL_C_VerifyRecoverInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef CK_RV (*SFL_C_VerifyRecover) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef CK_RV (*SFL_C_DigestEncryptUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*SFL_C_DecryptDigestUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR puPartLen);
typedef CK_RV (*SFL_C_SignEncryptUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (*SFL_C_DecryptVerifyUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef CK_RV (*SFL_C_GenerateKey) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*SFL_C_GenerateKeyPair) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR  pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef CK_RV (*SFL_C_WrapKey) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
typedef CK_RV (*SFL_C_UnwrapKey) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*SFL_C_DeriveKey) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechansim, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (*SFL_C_SeedRandom) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
typedef CK_RV (*SFL_C_GenerateRandom) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
typedef CK_RV (*SFL_C_GetFunctionStatus) (CK_SESSION_HANDLE hSession);
typedef CK_RV (*SFL_C_CancelFunction) (CK_SESSION_HANDLE hSession);

/*
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Initialize) (CK_VOID_PTR pInitArgs);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Finalize) (CK_VOID_PTR pReserved);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetInfo) (CK_INFO_PTR pInfo);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetFunctionList) (CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetSlotList) (CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,  CK_ULONG_PTR pulCount);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetSlotInfo) (CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetTokenInfo) (CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetMechanismList)  (CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetMechanismInfo) (CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pIfno);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_InitToken) (CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_CHAR_PTR pLabel);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_InitPIN) (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SetPIN) (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_OpenSession) (CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_CloseSession) (CK_SESSION_HANDLE hSession);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_CloseAllSessions) (CK_SLOT_ID slotID);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetSessionInfo) (CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetOperationState) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR  pulOperationStateLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SetOperationState) (CK_SESSION_HANDLE hSession, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncruptionKey, CK_OBJECT_HANDLE hAuthenticationKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Login) (CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Logout) (CK_SESSION_HANDLE hSession);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_CreateObject) (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulcount, CK_OBJECT_HANDLE_PTR phObject);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_CopyObject) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DestroyObject) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetObjectSize) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetAttributeValue) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SetAttributeValue) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_FindObjectsInit) (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_FindObjects) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_FindObjectsFinal) (CK_SESSION_HANDLE hSession);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_EncryptInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Encrypt) (CK_SESSION_HANDLE  hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_EncryptUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_EncryptFinal) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR plastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPart);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DecryptInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Decrypt) (CK_SESSION_HANDLE  hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DecryptUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DecryptFinal) (CK_SESSION_HANDLE  hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DigestInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechansim);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Digest) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR  pulDigestLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DigestUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,  CK_ULONG ulPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DigestKey) (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DigestFinal) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SignInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR  pMechanism, CK_OBJECT_HANDLE hKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Sign) (CK_SESSION_HANDLE hSession , CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SignUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SignFinal) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SignRecoverInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SignRecover) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_VerifyInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechansim, CK_OBJECT_HANDLE hKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_Verify) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_VerifyUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_VerifyFinal) (CK_SESSION_HANDLE  hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_VerifyRecoverInit) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_VerifyRecover) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DigestEncryptUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DecryptDigestUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR puPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SignEncryptUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DecryptVerifyUpdate) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GenerateKey) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GenerateKeyPair) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, CK_ATTRIBUTE_PTR  pPrivateKeyTemplate, CK_ULONG ulPrivateKeyAttributeCount, CK_OBJECT_HANDLE_PTR phPublicKey, CK_OBJECT_HANDLE_PTR phPrivateKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_WrapKey) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_UnwrapKey) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_DeriveKey) (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechansim, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_SeedRandom) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GenerateRandom) (CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_GetFunctionStatus) (CK_SESSION_HANDLE hSession);
typedef PKCS11_API(CK_RV) (PKCS11_CALL *SFL_C_CancelFunction) (CK_SESSION_HANDLE hSession);
*/
/*
class CSM_Pkcs11Functions 
{
public:

   char  *pkcs11DllName;
   void  *pkcs11LibHandle;

   CSM_Pkcs11Functions ();
   ~CSM_Pkcs11Functions ();

   SFL_C_Initialize sfl_c_initialize;
   SFL_C_Finalize sfl_c_finalize;
   SFL_C_GetInfo sfl_c_getInfo;
   SFL_C_GetFunctionList sfl_c_getFunctionList;
   SFL_C_GetSlotList sfl_c_getSlotList;
   SFL_C_GetSlotInfo sfl_c_getSlotInfo;
   SFL_C_GetTokenInfo sfl_c_getTokenInfo;

   SFL_C_GetMechanismList sfl_c_getMechanismList;
   SFL_C_GetMechanismInfo sfl_c_getMechanismInfo;
   SFL_C_InitToken sfl_c_initToken;
   SFL_C_InitPIN sfl_c_initPIN;
   SFL_C_SetPIN sfl_c_setPIN;
   SFL_C_OpenSession sfl_c_openSession;
   SFL_C_CloseSession sfl_c_closeSession;
   SFL_C_CloseAllSessions sfl_c_closeAllSessions;
   SFL_C_GetSessionInfo sfl_c_getSessionInfo;
   SFL_C_GetOperationState sfl_c_getOperationState;
   SFL_C_SetOperationState sfl_c_setOperationState;
   SFL_C_Login sfl_c_login;
   SFL_C_Logout sfl_c_logout;
   SFL_C_CreateObject sfl_c_createObject;
   SFL_C_CopyObject sfl_c_copyObject;
   SFL_C_DestroyObject sfl_c_destroyObject;
   SFL_C_GetObjectSize sfl_c_getObjectSize;
   SFL_C_GetAttributeValue sfl_c_getAttributeValue;
   SFL_C_SetAttributeValue sfl_c_setAttributeValue;
   SFL_C_FindObjectsInit sfl_c_findObjectsInit;
   SFL_C_FindObjects sfl_c_findObjects;
   SFL_C_FindObjectsFinal sfl_c_findObjectsFinal;
   SFL_C_EncryptInit sfl_c_encryptInit;
   SFL_C_Encrypt sfl_c_encrypt;
   SFL_C_EncryptUpdate sfl_c_encryptUpdate;
   SFL_C_EncryptFinal sfl_c_encryptFinal;
   SFL_C_DecryptInit sfl_c_decryptInit;
   SFL_C_Decrypt sfl_c_decrypt;
   SFL_C_DecryptUpdate sfl_c_decryptUpdate;
   SFL_C_DecryptFinal sfl_c_decryptFinal;
   SFL_C_DigestInit sfl_c_digestInit;
   SFL_C_Digest sfl_c_digest;
   SFL_C_DigestUpdate sfl_c_digestUpdate;
   SFL_C_DigestKey sfl_c_digestKey;
   SFL_C_DigestFinal sfl_c_digestFinal;
   SFL_C_SignInit sfl_c_signInit;
   SFL_C_Sign sfl_c_sign;
   SFL_C_SignUpdate sfl_c_signUpdate;
   SFL_C_SignFinal sfl_c_signFinal;
   SFL_C_SignRecoverInit sfl_c_signRecoverInit;
   SFL_C_SignRecover sfl_c_signRecover;
   SFL_C_VerifyInit sfl_c_verifyInit;
   SFL_C_Verify sfl_c_verify;
   SFL_C_VerifyUpdate sfl_c_verifyUpdate;
   SFL_C_VerifyFinal sfl_c_verifyFinal;
   SFL_C_VerifyRecoverInit sfl_c_verifyRecoverInit;
   SFL_C_VerifyRecover sfl_c_verifyRecover;
   SFL_C_DigestEncryptUpdate sfl_c_digestEncryptUpdate;
   SFL_C_DecryptDigestUpdate sfl_c_decryptDigestUpdate;
   SFL_C_SignEncryptUpdate sfl_c_signEncryptUpdate;
   SFL_C_DecryptVerifyUpdate sfl_c_decryptVerifyUpdate;
   SFL_C_GenerateKey sfl_c_generateKey;
   SFL_C_GenerateKeyPair sfl_c_generateKeyPair;
   SFL_C_WrapKey sfl_c_wrapKey;
   SFL_C_UnwrapKey sfl_c_unwrapKey;
   SFL_C_DeriveKey sfl_c_deriveKey;
   SFL_C_SeedRandom sfl_c_seedRandom;
   SFL_C_GenerateRandom sfl_c_generateRandom;
   SFL_C_GetFunctionStatus sfl_c_getFunctionStatus;
   SFL_C_CancelFunction sfl_c_cancelFunction;
};
*/

#endif /* _SM_PKCS11FUNCTIONS_H_ */

