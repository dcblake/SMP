
//  pkcs11_cryptopp.c
//
#include "pkcs11_cryptopp2.h"

using namespace CryptoPP;


//
// This routine looks for a specific session identifier.
CRYPTOPPP_SESSION_DEF *getSessionDef(CK_SESSION_HANDLE hSession)
{
  CRYPTOPPP_SESSION_DEF *pTmpSessionList2=pTopOfSessionList;
  while (pTmpSessionList2 != NULL && 
         pTmpSessionList2->pNext && 
         pTmpSessionList2->lSession != hSession)
  {
      pTmpSessionList2 = pTmpSessionList2->pNext;
  }     // END WHILE not at end-of-list

  return(pTmpSessionList2);
}   // END getSessionDef(...)


//
//
/*  C_Initialize */
CK_RV C_Initialize(
 CK_VOID_PTR pInitArgs
)
{
  CK_RV rv = CKR_OK;

  //RWC; no setup necessary at this time for NULL Crypto++ setup.
  //RWC; rv = CKR_FUNCTION_NOT_SUPPORTED;
  pTopOfSessionList = NULL; // INITIALLY empty.

  return rv;
}

/*  C_Finalize */
/* C_Finalize indicates that an application is done with the
 * Cryptoki library. */
CK_RV C_Finalize(
        CK_VOID_PTR pReserved
)
{
  CK_RV rv = CKR_OK;

  //RWC;rv = CKR_FUNCTION_NOT_SUPPORTED;
  //RWC;TBD; be sure to check and delete entries in 
  //pTopOfSessionList.

  return rv;
}

/*  C_InitToken */
CK_RV C_InitToken(
  CK_SLOT_ID     slotID,    /* ID of the token's slot */
  CK_CHAR_PTR    pPin,      /* the SO's initial PIN */
  CK_ULONG       ulPinLen,  /* length in bytes of the PIN */
  CK_CHAR_PTR    pLabel     /* 32-byte token label (blank padded) */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}


/*  C_DecryptInit */
CK_RV C_DecryptInit(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  return rv;
}

/*  C_Decrypt */
CK_RV C_Decrypt(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
        CK_ULONG          ulEncryptedDataLen,  /* gets c-text size */
        CK_BYTE_PTR       pData,               /* the plaintext data */
        CK_ULONG_PTR      pulDataLen           /* bytes of plaintext */
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DecryptUpdate */
CK_RV C_DecryptUpdate(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pEncryptedPart,
        CK_ULONG ulEncryptedPartLen,
        CK_BYTE_PTR pPart,
        CK_ULONG_PTR pulPartLen
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DecryptFinal */
CK_RV C_DecryptFinal(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pLastPart,
        CK_ULONG_PTR pulLastPartLen
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

//
//
/*  C_DigestInit */
CK_RV C_DigestInit(
      CK_SESSION_HANDLE hSession,
      CK_MECHANISM_PTR pMechanism
      )
{
  CK_RV rv = CKR_GENERAL_ERROR;

  //RWC;TBD;LOCK, in case used by same thread (must protect C_DigestInit,
  //  C_DigestUpdate, C_DigestFinal.
  // FIRST, locate session pointer
  CRYPTOPPP_SESSION_DEF *pTmpSessionList2 = getSessionDef(hSession);

  if (pTmpSessionList2)
  {
      // SECOND, perform specific digest operation
      if (pMechanism->mechanism == CKM_MD5_RSA_PKCS ||
          pMechanism->mechanism == CKM_MD5)
      {
          pTmpSessionList2->lDigestMechanism = pMechanism->mechanism;
          pTmpSessionList2->pHash = new MD5;
          rv = CKR_OK;
      }     // IF MD5
      else if (pMechanism->mechanism == CKM_SHA1_RSA_PKCS ||
               pMechanism->mechanism == CKM_DSA_SHA1 ||
               pMechanism->mechanism == CKM_SHA_1)
      {
          pTmpSessionList2->lDigestMechanism = pMechanism->mechanism;
          pTmpSessionList2->pHash = new SHA1;
          rv = CKR_OK;
      }     // IF SHA1
      /*RWC;not defined in our local pkcs11*.h file(s);
      else if (pMechanism->mechanism == CKM_SHA384_RSA_PKCS || 
               pMechanism->mechanism == CKM_SHA384)
      {
      }     // IF SHA384*/
      else
      {
          rv = CKR_MECHANISM_INVALID;
      }     // END IF digest check
  }
  else
  {
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;
  }         // END IF pTmpSessionList2

  //RWC;rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  return rv;
}       // END C_DigestInit(...)

//
//
/*  C_Digest */
CK_RV C_Digest(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pData,
        CK_ULONG ulDataLen,
        CK_BYTE_PTR pDigest,
        CK_ULONG_PTR pulDigestLen
      )
{
  CK_RV rv = CKR_OK;
  CRYPTOPPP_SESSION_DEF *pSession = getSessionDef(hSession);

  if (pSession == NULL)
      rv = CKR_SESSION_HANDLE_INVALID;
  else if (pSession->pHash == NULL)
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;  // DigestInit not called...
  else
  {
   if (pSession->pHash && pDigest == NULL)
   {                     // THEN just compute expected hash length.
      if (pulDigestLen == NULL)
          rv = CKR_ARGUMENTS_BAD;
      else
      {
          *pulDigestLen = pSession->pHash->DigestSize();
      }     // END if bad parameter check
   }     // IF pDigest
   else
   {
      if (pulDigestLen == NULL || pDigest == NULL || pData == NULL ||
          pSession->pHash == NULL)
          rv = CKR_ARGUMENTS_BAD;
      else
      {
          // create storage for the digest
          SecByteBlock digest(pSession->pHash->DigestSize());

          pSession->pHash->Update(pData, ulDataLen);
          pSession->pHash->Final(digest); // finish the digest
          memcpy(pDigest, digest.data(), *pulDigestLen/*digest.m_size*/);
      } // END IF bad argument test.
   }     // END IF pDigest
  }      // END IF digestInit called...
  //RWC;rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DigestUpdate */
CK_RV C_DigestUpdate(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pPart,
        CK_ULONG ulPartLen
      )
{
  CK_RV rv = CKR_OK;
  CRYPTOPPP_SESSION_DEF *pSession = getSessionDef(hSession);

  if (pSession == NULL)
      rv = CKR_SESSION_HANDLE_INVALID;
  else if (ulPartLen == NULL || pPart == NULL)
          rv = CKR_ARGUMENTS_BAD;
  else if (pSession->pHash == NULL)
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;  // DigestInit not called...
  else
    pSession->pHash->Update(pPart, ulPartLen);
  //RWC;rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DigestKey */
/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. */
CK_RV C_DigestKey(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DigestFinal */
CK_RV C_DigestFinal(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pDigest,
        CK_ULONG_PTR pulDigestLen
      )
{
  CK_RV rv = CKR_OK;

    CRYPTOPPP_SESSION_DEF *pSession = getSessionDef(hSession);

  if (pSession == NULL)
      rv = CKR_SESSION_HANDLE_INVALID;
  else if (pulDigestLen == NULL || *pulDigestLen == 0 || pDigest == NULL)
          rv = CKR_ARGUMENTS_BAD;
  else if (pSession->pHash == NULL)
      rv = CKR_CRYPTOKI_NOT_INITIALIZED;  // DigestInit not called...
  else
  {
      // create storage for the digest
      SecByteBlock digest(pSession->pHash->DigestSize());

      pSession->pHash->Final(digest); // finish the digest
      memcpy(pDigest, digest.data(), *pulDigestLen/*digest.m_size*/);
  }     // END IF parameter checks
  //RWC;rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DigestEncryptUpdate */
/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation. */
CK_RV C_DigestEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp1 = NULL_PTR;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DecryptDigestUpdate */
/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation. */
CK_RV C_DecryptDigestUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets plaintext len */
)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp1 = NULL_PTR;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SignEncryptUpdate */
/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation. */
CK_RV C_SignEncryptUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pPart,               /* the plaintext data */
  CK_ULONG          ulPartLen,           /* plaintext length */
  CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
)
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp1 = NULL_PTR;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}
 
/*  C_DecryptVerifyUpdate */
 /* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation. */
CK_RV C_DecryptVerifyUpdate(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
  CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* gets p-text length */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_EncryptInit */
CK_RV C_EncryptInit(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  return rv;
}

/*  C_Encrypt */
CK_RV C_Encrypt(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* the plaintext data */
        CK_ULONG          ulDataLen,           /* bytes of plaintext */
        CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
        CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_EncryptUpdate */
CK_RV C_EncryptUpdate(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pPart,
        CK_ULONG ulPartLen,
        CK_BYTE_PTR pEncryptedPart,
        CK_ULONG_PTR pulEncryptedPartLen
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_EncryptFinal */
CK_RV C_EncryptFinal(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pLastEncryptedPart,
        CK_ULONG_PTR pulLastEncryptedPartLen
      )
{
  CK_RV rv =CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetInfo */
CK_RV C_GetInfo(
 CK_INFO_PTR pInfo
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GenerateKey */
CK_RV C_GenerateKey(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phKey
      )
{
  CK_RV rv = CKR_OK;
  
  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GenerateKeyPair */
CK_RV C_GenerateKeyPair(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
        CK_ULONG ulPublicKeyAttributeCount,
        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
        CK_ULONG ulPrivateKeyAttributeCount,
        CK_OBJECT_HANDLE_PTR phPublicKey,
        CK_OBJECT_HANDLE_PTR phPrivateKey
	)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_WrapKey */
CK_RV C_WrapKey(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_UnwrapKey */
/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object. */
CK_RV C_UnwrapKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DeriveKey */
/* C_DeriveKey derives a key from a base key, creating a new key
 * object. */
CK_RV C_DeriveKey(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* key deriv. mech. */
  CK_OBJECT_HANDLE     hBaseKey,          /* base key */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_CreateObject */
CK_RV C_CreateObject(
        CK_SESSION_HANDLE hSession,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phObject
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_DestroyObject */
CK_RV C_DestroyObject(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_CopyObject */
CK_RV C_CopyObject(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount,
        CK_OBJECT_HANDLE_PTR phNewObject
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return CKR_OK;
}

/*  C_GetAttributeValue */
CK_RV C_GetAttributeValue(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SetAttributeValue */
CK_RV C_SetAttributeValue(
        CK_SESSION_HANDLE hSession,
        CK_OBJECT_HANDLE hObject,
        CK_ATTRIBUTE_PTR pTemplate,
        CK_ULONG ulCount
	)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
  
}

/*  C_FindObjectsInit */
/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template. */
CK_RV C_FindObjectsInit(
      CK_SESSION_HANDLE hSession,   /* the session's handle */
      CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
      CK_ULONG          ulCount     /* attrs in search template */
      )
{
  CK_RV rv =CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return CKR_OK;
}

/*  C_FindObjects */
/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles. */
CK_RV C_FindObjects(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
  CK_ULONG             ulMaxObjectCount,  /* max handles to get */
  CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_FindObjectsFinal */
/* C_FindObjectsFinal finishes a search for token and session
 * objects. */
CK_RV C_FindObjectsFinal(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetObjectSize */
/* C_GetObjectSize gets the size of an object in bytes. */
CK_RV C_GetObjectSize(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject,   /* the object's handle */
  CK_ULONG_PTR      pulSize    /* receives size of object */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetFunctionStatus */
CK_RV C_GetFunctionStatus(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_CancelFunction */
CK_RV C_CancelFunction(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_WaitForSlotEvent */
CK_RV C_WaitForSlotEvent(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pReserved   /* reserved.  Should be NULL_PTR */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SeedRandom */
CK_RV C_SeedRandom(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSeed,
        CK_ULONG ulSeedLen
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv; 
}

/*  C_GenerateRandom */
CK_RV C_GenerateRandom(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pRandomData,
        CK_ULONG ulRandomLen
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_OpenSession */
CK_RV C_OpenSession(
        CK_SLOT_ID slotID,
        CK_FLAGS flags,
        CK_VOID_PTR pApplication,
        CK_NOTIFY Notify,
        CK_SESSION_HANDLE_PTR phSession
      )
{
  CK_RV rv = CKR_OK;

  //RWC;rv = CKR_FUNCTION_NOT_SUPPORTED;
  CRYPTOPPP_SESSION_DEF *pTmpSessionList=new CRYPTOPPP_SESSION_DEF;
  CRYPTOPPP_SESSION_DEF *pTmpSessionList2;
  CK_SESSION_HANDLE hSession=111;

    memset(pTmpSessionList, '\0', sizeof(CRYPTOPPP_SESSION_DEF));
    if (pTopOfSessionList == NULL)
          pTopOfSessionList = pTmpSessionList;
    else
    {
          pTmpSessionList2 = pTopOfSessionList;
          hSession = pTmpSessionList2->lSession;
          while (pTmpSessionList2->pNext)
          {
              pTmpSessionList2 = pTmpSessionList2->pNext;
              hSession = pTmpSessionList2->lSession;    // GET last session value.
          }     // END WHILE not at end-of-list
          pTmpSessionList2->pNext = pTmpSessionList; // LOAD our new session
    }     // END IF pTmpSessionList
    hSession++;   // CREATE next 1-up value.
    pTmpSessionList->lSession = hSession;

  return rv;
}   // END C_OpenSession(...)

/*  C_CloseSession */
CK_RV C_CloseSession(
        CK_SESSION_HANDLE hSession
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv; 
}

/*  C_CloseAllSessions */
/* C_CloseAllSessions closes all sessions with a token. */
CK_RV C_CloseAllSessions(
  CK_SLOT_ID     slotID  /* the token's slot */
)
{
  CK_RV rv= CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetSessionInfo */
CK_RV C_GetSessionInfo(
        CK_SESSION_HANDLE hSession,
        CK_SESSION_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return CKR_OK;
}

/*  C_Login *//* C_Login logs a user into a token. */
CK_RV C_Login(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  return rv;
}

/*  C_Logout */
/* C_Logout logs a user out from a token. */
CK_RV C_Logout(
  CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetOperationState */
/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session. */
CK_RV C_GetOperationState(
  CK_SESSION_HANDLE hSession,             /* session's handle */
  CK_BYTE_PTR       pOperationState,      /* gets state */
  CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SetOperationState */
/* C_SetOperationState restores the state of the cryptographic
 * operation in a session. */
CK_RV C_SetOperationState(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR      pOperationState,      /* holds state */
  CK_ULONG         ulOperationStateLen,  /* holds state length */
  CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
  CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SignInit */
CK_RV C_SignInit(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  
  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_Sign */
CK_RV C_Sign(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* gets plaintext */
        CK_ULONG          ulDataLen,           /* gets p-text size */
        CK_BYTE_PTR       pSignature,          /* the Signature */
        CK_ULONG_PTR      pulSignatureLen      /* bytes of Signature */
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SignUpdate */
CK_RV C_SignUpdate(
        CK_SESSION_HANDLE hSession,  /* the session's handle */
        CK_BYTE_PTR pPart,           /* the data to sign */
        CK_ULONG ulPartLen           /* count of bytes to sign */
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SignFinal */
CK_RV C_SignFinal(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR pSignature,
        CK_ULONG_PTR pulSignatureLen
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SignRecoverInit */
/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_RV C_SignRecoverInit(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SignRecover */
/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_RV C_SignRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetSlotList */
CK_RV C_GetSlotList(
        CK_BBOOL tokenPresent,
        CK_SLOT_ID_PTR pSlotList,
        CK_ULONG_PTR pulCount
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return CKR_OK;  
}

/*  C_GetSlotInfo */
CK_RV C_GetSlotInfo(
        CK_SLOT_ID slotID,
        CK_SLOT_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetTokenInfo */
CK_RV C_GetTokenInfo(
        CK_SLOT_ID slotID,
        CK_TOKEN_INFO_PTR pInfo
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetMechanismList */
CK_RV C_GetMechanismList(
        CK_SLOT_ID slotID,
        CK_MECHANISM_TYPE_PTR pMechanismList,
        CK_ULONG_PTR pulCount
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_GetMechanismInfo */
CK_RV C_GetMechanismInfo(
        CK_SLOT_ID slotID,
        CK_MECHANISM_TYPE type,
        CK_MECHANISM_INFO_PTR pInfo
      )
{
  CK_RV rv=CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_InitPIN */
/* C_InitPIN initializes the normal user's PIN. */
CK_RV C_InitPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pPin,      /* the normal user's PIN */
  CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_SetPIN */
/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_RV C_SetPIN(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_VerifyInit */
CK_RV C_VerifyInit(
        CK_SESSION_HANDLE hSession,
        CK_MECHANISM_PTR pMechanism,
        CK_OBJECT_HANDLE hKey
      )
{
  CK_RV rv = CKR_OK;
  CK_BYTE_PTR tmp = NULL_PTR;

  rv = CKR_FUNCTION_NOT_SUPPORTED;
  
  return rv;
}

/*  C_Verify */
CK_RV C_Verify(
        CK_SESSION_HANDLE hSession,            /* session's handle */
        CK_BYTE_PTR       pData,               /* gets plaintext */
        CK_ULONG          ulDataLen,           /* gets p-text size */
        CK_BYTE_PTR       pSignature,          /* the Signature */
        CK_ULONG          ulSignatureLen      /* bytes of Signature */
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_VerifyUpdate */
CK_RV C_VerifyUpdate(
        CK_SESSION_HANDLE hSession,  /* the session's handle */
        CK_BYTE_PTR pPart,           /* the data to verify */
        CK_ULONG ulPartLen           /* count of bytes to verify */
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_VerifyFinal */
CK_RV C_VerifyFinal(
        CK_SESSION_HANDLE hSession,
        CK_BYTE_PTR       pSignature,
        CK_ULONG          ulSignatureLen
      )
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_VerifyRecoverInit */
/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_RV C_VerifyRecoverInit(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}

/*  C_VerifyRecover */
/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_RV C_VerifyRecover(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pSignature,      /* signature to verify */
  CK_ULONG          ulSignatureLen,  /* signature length */
  CK_BYTE_PTR       pData,           /* gets signed data */
  CK_ULONG_PTR      pulDataLen       /* gets signed data len */
)
{
  CK_RV rv = CKR_OK;

  rv = CKR_FUNCTION_NOT_SUPPORTED;

  return rv;
}



// EOF pkcs11_crytopp.c
