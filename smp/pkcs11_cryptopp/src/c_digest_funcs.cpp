/************************ PKCS #11 Message digesting Functions ************************
 *
 * This source file contains the following slot and token functions:
 *  + C_DigestInit
 *  + C_Digest
 *  + C_DigestUpdate
 *  + C_DigestKey
 *  + C_DigestFinal
 */


#include "p11cryptopp_internal.h"


/* C_DigestInit
 * initializes a message-digesting operation. hSession is the session’s handle;
 * pMechanism points to the digesting mechanism.
 */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism)  /* the digesting mechanism */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check that the mechanism argument isn't NULL
	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	// Find the specified session
	CKSessionClass* pSession = GetSessionFromHandle(hSession);
	if (pSession == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Clear the CryptoPP::HashTransformation object
	if (pSession->pHashObj != NULL)
	{
		delete pSession->pHashObj;
		pSession->pHashObj = NULL;
	}

	// Check that the mechanism parameter is absent
	if ((pMechanism->pParameter != NULL_PTR) || (pMechanism->ulParameterLen != 0))
		return CKR_MECHANISM_PARAM_INVALID;

	// Create the requested hash object
	switch (pMechanism->mechanism)
	{
	case CKM_SHA_1:
		pSession->pHashObj = new CryptoPP::SHA1;
		break;

	case CKM_SHA_256:
		pSession->pHashObj = new CryptoPP::SHA256;
		break;

	case CKM_SHA_384:
		pSession->pHashObj = new CryptoPP::SHA384;
		break;

	case CKM_MD2:
		pSession->pHashObj = new CryptoPP::MD2;
		break;

	case CKM_MD5:
		pSession->pHashObj = new CryptoPP::MD5;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	// Check that the HashTransformation object was created
	if (pSession->pHashObj == NULL)
		return CKR_HOST_MEMORY;

	return CKR_OK;
}


/* C_Digest
 * digests data in a single part. hSession is the session’s handle, pData points to the
 * data; ulDataLen is the length of the data; pDigest points to the location that receives the
 * message digest; pulDigestLen points to the location that holds the length of the message 
 * digest.
 */
CK_DEFINE_FUNCTION(CK_RV, C_Digest)(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pData,        /* data to be digested */
  CK_ULONG          ulDataLen,    /* bytes of data to digest */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen) /* gets digest length */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check the arguments
	if ((pData == NULL_PTR) || (ulDataLen == 0) || (pulDigestLen == NULL_PTR))
		return CKR_ARGUMENTS_BAD;

	// Find the specified session
	CKSessionClass* pSession = GetSessionFromHandle(hSession);
	if (pSession == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Check that the operation has been initialized
	if (pSession->pHashObj == NULL)
		return CKR_OPERATION_NOT_INITIALIZED;

	// Compute the hash value
	pSession->pHashObj->Update(pData, ulDataLen);

	// Return the size of the hash value
	CK_ULONG digestSpace = *pulDigestLen;
	*pulDigestLen = pSession->pHashObj->DigestSize();

	if (pDigest == NULL_PTR)
	{
		// Hash value is not requested, so just return
		return CKR_OK;
	}
	else if (*pulDigestLen > digestSpace)
	{
		// Hash value is too big to fit in available space, so return error
		return CKR_BUFFER_TOO_SMALL;
	}
	else	// Store the final hash value
		pSession->pHashObj->Final(pDigest);

	// Clear the CryptoPP::HashTransformation object
	delete pSession->pHashObj;
	pSession->pHashObj = NULL;

	return CKR_OK;
}


/* C_DigestUpdate
 * continues a multiple-part message-digesting operation, processing another
 * data part. hSession is the session’s handle, pPart points to the data part; ulPartLen is the
 * length of the data part.
 */
CK_DEFINE_FUNCTION(CK_RV,C_DigestUpdate)(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen)  /* bytes of data to be digested */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested. 
 */
CK_DEFINE_FUNCTION(CK_RV,C_DigestKey)(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hKey)       /* secret key to digest */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DigestFinal finishes a multiple-part message-digesting
 * operation. 
 */
CK_DEFINE_FUNCTION(CK_RV,C_DigestFinal)(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen)  /* gets byte count of digest */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
