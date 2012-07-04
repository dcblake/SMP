#ifndef NO_SCCS_ID
static char SccsId[ ] = "@(#) sm_pkcs11FunctionWrappers.cpp 1.4 08/08/00 09:52:22"; 
#endif

#include "sm_pkcs11.h"

_BEGIN_CERT_NAMESPACE


SM_RET_VAL CSM_Pkcs11::Initialize(CK_VOID_PTR pReserved)
{
   SM_RET_VAL status = SM_NO_ERROR;

   CK_RV rv;

   SME_SETUP("CSM_Pkcs11::Initialize");

   if (sfl_c_initialize != NULL)
   {
      if ((rv = sfl_c_initialize(pReserved)) != CKR_OK)
         SME_THROW(rv, "Unsuccessful sfl_c_initialize.", NULL);
   }
   else
      SME_THROW(0, "C_Initialize is not available.", NULL);

   SME_FINISH_CATCH;

   return status;
}
///////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::GetSlotList(CK_BBOOL tokenPresent, 
                               CK_SLOT_ID_PTR &pSlotList,
                               CK_ULONG &ulCount)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::GetSlotList");

   CK_RV rv;

   if (sfl_c_getSlotList != NULL)
   {
      if ((rv = sfl_c_getSlotList(tokenPresent, pSlotList, &ulCount)) == CKR_OK)
      {
         if (ulCount != 0)
         {     
            if (pSlotList == NULL)
            {
               // Allocate memory in pSlotList for a ulCount number of CK_SLOT_IDs.
               if ((pSlotList =
                      (CK_SLOT_ID_PTR) malloc(ulCount * sizeof(CK_SLOT_ID))) == NULL)
                   SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

               // This call will retrieve a list CK_SLOT_IDs with ulCount
               // number of elements into pSlotList.
               if ((rv = sfl_c_getSlotList(tokenPresent, pSlotList, &ulCount)) != CKR_OK)
                  SME_THROW(rv,"Unsuccessful sfl_c_getSlotList.", NULL);
            }
         }
		 else
            status = -2;   // JUST flag to indicate 0 slots.
            //SME_THROW(rv, "sfl_c_getSlotList Slot count of 0.  Cannot proceed without a slot list.", NULL);
      }
      else
         SME_THROW(rv, "Unsuccessful sfl_c_getSlotList.", NULL);
   }
   else
      SME_THROW(NULL, "C_GetSlotList function is not available.", NULL);

   SME_FINISH_CATCH;

   return status;
}
////////////////////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::CreateObject(CK_SESSION_HANDLE hSession,
                        CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulAttributeCount,
                        CK_OBJECT_HANDLE &hObject)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::CreateObject");

   CK_RV rv;

   if (sfl_c_createObject != NULL)
   {
      if ((rv = sfl_c_createObject(hSession, pTemplate, ulAttributeCount, &hObject)) != CKR_OK)
         status = rv;
   }
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
////////////////////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::FindObjects (CK_SESSION_HANDLE hSession,
                               CK_ATTRIBUTE_PTR pTemplate,
                               CK_ULONG ulAttributeCount,
                               CK_ULONG ulMaxObjectCount,
                               CK_ULONG &ulObjectCount,
                               CK_OBJECT_HANDLE_PTR &phObject)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::FindObjects");

   if (sfl_c_findObjectsInit != NULL)
   {
      // If ulAttributeCount = 0, all objects will be retrieved.
      if ((status = sfl_c_findObjectsInit(hSession, 
                                      pTemplate, 
                                      ulAttributeCount)) == CKR_OK)
      {
         if (phObject == NULL_PTR)
            if ((phObject = 
                     (CK_OBJECT_HANDLE_PTR) 
                        malloc(sizeof(CK_OBJECT_HANDLE) * ulMaxObjectCount)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

         if (sfl_c_findObjects != NULL)
         {
            if ((status = sfl_c_findObjects(hSession, phObject, 
                                   ulMaxObjectCount, &ulObjectCount)) == CKR_OK)
            {
               if (sfl_c_findObjectsFinal != NULL)
                  status = sfl_c_findObjectsFinal(hSession);
               else
                  status = SM_PKCS11_FUNCTION_NOT_AVAIL;
            }
         }
         else
            status = SM_PKCS11_FUNCTION_NOT_AVAIL;
      }
   }
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;
    
   SME_FINISH_CATCH;

   return status;
}
//////////////////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::GetAttributeValue (CK_SESSION_HANDLE hSession,
                            CK_OBJECT_HANDLE hObject,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulAttributeCount)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::GetAttributeValue");

   if (sfl_c_getAttributeValue != NULL)
      status = sfl_c_getAttributeValue(hSession, hObject, 
                                       pTemplate, ulAttributeCount);
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
//////////////////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::Verify(CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanismStruct,
                   CK_OBJECT_HANDLE hObject,
                   CK_BYTE_PTR pDigestData,
                   CK_ULONG ulDigestLen,
                   CK_BYTE_PTR pSignature,
                   CK_ULONG ulSignatureLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::Verify");

   if (sfl_c_verifyInit != NULL)
   {
      if ((status = 
         sfl_c_verifyInit(hSession, pMechanismStruct, hObject)) == SM_NO_ERROR)
      {
         if (sfl_c_verify != NULL)
            status = sfl_c_verify(hSession, pDigestData, ulDigestLen, 
                                                pSignature, ulSignatureLen);
         else
            status = SM_PKCS11_FUNCTION_NOT_AVAIL;
      }
   }
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
//////////////////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::Digest(CK_SESSION_HANDLE hSession, 
                         CK_MECHANISM_PTR pMechanism,
                         CK_BYTE_PTR pData,
                         CK_ULONG ulDataLen,
                         CSM_Buffer *&pDigest,
                         CK_ULONG &ulDigestLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::Digest");

   if (sfl_c_digestInit != NULL)
   {
      if ((status = sfl_c_digestInit(hSession, pMechanism)) == SM_NO_ERROR)
      {
         CK_BYTE_PTR pDigestBuffer = NULL_PTR;

         if ( sfl_c_digest != NULL )
         {
            if ( ( status = sfl_c_digest ( hSession, pData, ulDataLen, NULL, 
                                            &ulDigestLen ) ) == SM_NO_ERROR )
            {
                // We need a buffer of size ulDigestLen
                if ( pDigest == NULL ) 
                {
                    if ((pDigest = new CSM_Buffer ( ( size_t ) ulDigestLen ) ) == NULL )
                        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

                    pDigestBuffer = (CK_BYTE_PTR) pDigest->Access();
                } 
                else if ( pDigest->Length() == 0 ) 
                {
                    pDigest->Open(SM_FOPEN_WRITE);
                    pDigestBuffer = (CK_BYTE_PTR) pDigest->Alloc ( ( size_t ) ulDigestLen );
                } 
                else 
                {
                    // We already have a buffer
                    if ( pDigest->Length() < ulDigestLen )
                    status = CKR_BUFFER_TOO_SMALL;
                    else
                    pDigestBuffer = (CK_BYTE_PTR) pDigest->Access();
                }
                ulDigestLen = pDigest->Length();

                 if (sfl_c_digest != NULL)
                 {
                    if ((status = sfl_c_digest(hSession, pData, ulDataLen, 
                                              pDigestBuffer, &ulDigestLen)) == SM_NO_ERROR)
                    {
                       pDigest->Flush();
                       pDigest->Close();
                    }
                 }
                 else
                    status = SM_PKCS11_FUNCTION_NOT_AVAIL;
            } // END IF sfl_c_digest pointer call to get length of returned hash.
         }    // END IF sfl_c_digest not NULL
      }       // END IF sfl_c_digestInit
   }          // IF (sfl_c_digestInit != NULL)
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
/////////////////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::Sign(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hSigningKey,
                  CK_BYTE_PTR pData,
                  CK_ULONG ulDataLen,
                  CSM_Buffer *&pSignedData,
                  CK_ULONG &ulSignedDataLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::Sign");

   if (sfl_c_signInit != NULL)
   {
      if ((status = sfl_c_signInit(hSession, 
                                    pMechanism, hSigningKey)) == SM_NO_ERROR)
      {
         CK_BYTE_PTR pSignedDataBuffer = NULL_PTR;

         if (pSignedData == NULL_PTR)
         {
            if ((pSignedData = 
                     new CSM_Buffer((size_t) SM_PKCS11_BUFFER_SIZE)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

            pSignedDataBuffer = (CK_BYTE_PTR) pSignedData->Access();
         }
         else if (pSignedData->Length() == 0)
         {
            pSignedData->Open(SM_FOPEN_WRITE);
            pSignedDataBuffer = 
                 (CK_BYTE_PTR) pSignedData->Alloc((size_t) SM_PKCS11_BUFFER_SIZE);
         }

         if (sfl_c_sign != NULL)
         {
            if ((status = sfl_c_sign(hSession, pData, ulDataLen, 
                             pSignedDataBuffer, &ulSignedDataLen)) == SM_NO_ERROR)
            {
               pSignedData->Flush();
               pSignedData->Close();
            }
         }
         else
            status = SM_PKCS11_FUNCTION_NOT_AVAIL;
      }
   }
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
//////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::OpenSession (CK_SLOT_ID slotId,
                               CK_FLAGS flags,
                               CK_NOTIFY notify,
                               CK_VOID_PTR pApplication,
                               CK_SESSION_HANDLE_PTR phSession)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::OpenSession");

   if (sfl_c_openSession != NULL)
      status = sfl_c_openSession(slotId, flags, pApplication, notify, phSession);
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
SM_RET_VAL CSM_Pkcs11::Login (CK_SESSION_HANDLE hSession,
                         CK_USER_TYPE userType,
                         CK_CHAR_PTR pPin,
                         CK_ULONG ulPinLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::Login");

   if (sfl_c_login != NULL)
      status = sfl_c_login(hSession, userType, pPin, ulPinLen);
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
SM_RET_VAL CSM_Pkcs11::GenerateRandom(CK_SESSION_HANDLE hSession,
                                 CK_BYTE_PTR pRandomData,
                                 CK_ULONG ulRandomLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::GenerateRandom");

   if (sfl_c_generateRandom != NULL)
      status = sfl_c_generateRandom(hSession, pRandomData, ulRandomLen);
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
SM_RET_VAL CSM_Pkcs11::Decrypt(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_OBJECT_HANDLE hDecryptKey,
                          CK_BYTE_PTR pData,
                          CK_ULONG ulDataLen,
                          CSM_Buffer *&pDecryptedData,
                          CK_ULONG &ulDecryptedDataLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::Decrypt");

   if (sfl_c_decryptInit != NULL)
   {
      if ((status = 
            sfl_c_decryptInit(hSession, pMechanism, hDecryptKey)) == SM_NO_ERROR)
      {
         CK_BYTE_PTR pDecryptedDataBuffer = NULL_PTR;

         if (pDecryptedData == NULL)
         {
            if ((pDecryptedData = 
                     new CSM_Buffer((size_t) SM_PKCS11_BUFFER_SIZE)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

            pDecryptedDataBuffer = (CK_BYTE_PTR) pDecryptedData->Access();
         }
         else if (pDecryptedData->Length() == 0)
         {
            pDecryptedData->Open(SM_FOPEN_WRITE);
            pDecryptedDataBuffer = 
               (CK_BYTE_PTR) pDecryptedData->Alloc((size_t) SM_PKCS11_BUFFER_SIZE);
         }

         if ((status = sfl_c_decrypt(hSession, pData, ulDataLen,
                        pDecryptedDataBuffer, &ulDecryptedDataLen)) == SM_NO_ERROR)

         {
            pDecryptedData->Flush();
            pDecryptedData->Close();
         }
      }
   }
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}

SM_RET_VAL CSM_Pkcs11::Encrypt(CK_SESSION_HANDLE hSession, 
                          CK_MECHANISM_PTR pMechanism, 
                          CK_OBJECT_HANDLE hEncryptKey,
                          CK_BYTE_PTR pData, 
                          CK_ULONG ulDataLen, 
                          CSM_Buffer *&pEncryptedData, 
                          CK_ULONG &ulEncryptedDataLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::Encrypt");

   if (sfl_c_encryptInit != NULL)
   {
      if ((status = 
            sfl_c_encryptInit(hSession, pMechanism, hEncryptKey)) == SM_NO_ERROR)
      {
         CK_BYTE_PTR pEncryptedDataBuffer = NULL_PTR;

         if (pEncryptedData == NULL_PTR)
         {
            if ((pEncryptedData = 
                  new CSM_Buffer((size_t) SM_PKCS11_BUFFER_SIZE)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

            pEncryptedDataBuffer = (CK_BYTE_PTR) pEncryptedData->Access();
         }
         else if (pEncryptedData->Length() == 0)
         {
            pEncryptedData->Open(SM_FOPEN_WRITE);
            pEncryptedDataBuffer = 
               (CK_BYTE_PTR) pEncryptedData->Alloc((size_t) SM_PKCS11_BUFFER_SIZE);
         }

         if ((status = sfl_c_encrypt(hSession, pData, ulDataLen, 
                        pEncryptedDataBuffer, &ulEncryptedDataLen)) == SM_NO_ERROR)
         {
            pEncryptedData->Flush();
            pEncryptedData->Close();
         }
      }
   }
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
SM_RET_VAL CSM_Pkcs11::GenerateKey(CK_SESSION_HANDLE hSession,
                              CK_MECHANISM_PTR pMechanism,
                              CK_ATTRIBUTE_PTR pAttribute,
                              CK_ULONG ulAttributeSize,
                              CK_OBJECT_HANDLE_PTR phObject)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::GenerateKey");

   if (sfl_c_generateKey != NULL)
      status = sfl_c_generateKey(hSession, pMechanism, 
                                    pAttribute, ulAttributeSize, phObject);
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;
   
   SME_FINISH_CATCH;

   return status;
}
SM_RET_VAL CSM_Pkcs11::DeriveKey(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism,
                            CK_OBJECT_HANDLE hBaseKey,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulAttributeCount,
                            CK_OBJECT_HANDLE_PTR phDeriveKey)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::DeriveKey");

   if (sfl_c_deriveKey != NULL)
      status = sfl_c_deriveKey(hSession, pMechanism, hBaseKey, pTemplate,
                                                  ulAttributeCount, phDeriveKey);
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
SM_RET_VAL CSM_Pkcs11::WrapKey(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism,
                          CK_OBJECT_HANDLE hWrappingKey,
                          CK_OBJECT_HANDLE hKey,
                          CK_BYTE_PTR &pWrappedKey,
                          CK_ULONG_PTR pulWrappedKeyLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::WrapKey");

   if (sfl_c_wrapKey != NULL)
   {
      if ((status = sfl_c_wrapKey(hSession, pMechanism, hWrappingKey, hKey,
                              pWrappedKey, pulWrappedKeyLen)) == SM_NO_ERROR)
      {
         if (pWrappedKey == NULL_PTR)
         {
            if ((pWrappedKey = (CK_BYTE_PTR) malloc(*pulWrappedKeyLen)) == NULL_PTR)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         
            status = sfl_c_wrapKey(hSession, pMechanism, hWrappingKey, 
                                             hKey, pWrappedKey, pulWrappedKeyLen);
         }
      }
   }
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}
SM_RET_VAL CSM_Pkcs11::UnwrapKey(CK_SESSION_HANDLE hSession,
                            CK_MECHANISM_PTR pMechanism,
                            CK_OBJECT_HANDLE hUnWrappingKey,
                            CK_BYTE_PTR pWrappedKey,
                            CK_ULONG ulWrappedKeyLen,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulAttributeCount,
                            CK_OBJECT_HANDLE_PTR phKey)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::UnwrapKey");

   if (sfl_c_unwrapKey != NULL)
      status = sfl_c_unwrapKey(hSession, pMechanism, hUnWrappingKey,
                        pWrappedKey, ulWrappedKeyLen, 
                        pTemplate, ulAttributeCount, phKey);
   else
      status = SM_PKCS11_FUNCTION_NOT_AVAIL;

   SME_FINISH_CATCH;

   return status;
}

_END_CERT_NAMESPACE

// EOF sm_pkcs11FunctionWrappers.cpp
