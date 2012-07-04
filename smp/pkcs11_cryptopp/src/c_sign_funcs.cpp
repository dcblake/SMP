/************************ PKCS #11 Signing and MACing Functions ************************
 *
 * This source file contains the following functions:
 *  + C_SignInit
 *  + C_Sign
 *  + C_SignUpdate
 *  + C_SignFinal
 *  + C_SignRecoverInit
 *  + C_SignRecover
 */


#include "p11cryptopp_internal.h"


/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 *signature. */
CK_DEFINE_FUNCTION(CK_RV,C_SignInit)
(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check the mechanism argument
	if (pMechanism == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	// Find the specified session
	CKSessionClass* pSession = GetSessionFromHandle(hSession);
	if (pSession == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Clear the CryptoPP::PK_Signer object
	if (pSession->pSigner != NULL)
	{
		delete pSession->pSigner;
		pSession->pSigner = NULL;
	}

	// Find the specified private key object
	CKObjectMap::iterator iObj = pSession->m_objectMap.find(hKey);
	if (iObj == pSession->m_objectMap.end())
		return CKR_KEY_HANDLE_INVALID;
	if (iObj->second == NULL)
		return CKR_GENERAL_ERROR;
	if (iObj->second->m_class != CKO_PRIVATE_KEY)
		return CKR_KEY_HANDLE_INVALID;
	
	// Downcast the private key object
	const CKPrivateKeyObject* pKeyObj =
		dynamic_cast<const CKPrivateKeyObject*>(iObj->second);
	if (pKeyObj == NULL)
		return CKR_GENERAL_ERROR;
	
	// Check that the mechanism is consistent with the private key
	CK_RV rv = pKeyObj->CheckMechanism(*pMechanism);
	if (rv != CKR_OK)
		return rv;
	
	// Check the that private key supports signing
	if (!pKeyObj->m_canSign)
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	
	switch (pMechanism->mechanism)
	{
	case CKM_DSA_SHA1:
	case CKM_SHA1_RSA_PKCS:
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
		try {
			pSession->pSigner = pKeyObj->CreateSigner(*pMechanism);
		}
		catch (CK_RV rv) {
			return rv;
		}
		catch (...) {
			return CKR_GENERAL_ERROR;
		}
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

    return CKR_OK;

#ifdef _OLD_CODE

	CK_ULONG ret = CKR_OK;

	if (hSession < 1 || hSession > gSessionMap.size())
		return CKR_SESSION_HANDLE_INVALID;

	SessionMap::iterator i = gSessionMap.find(hSession);
	
	if (i == gSessionMap.end())
		return CKR_SESSION_HANDLE_INVALID;

	//CKObjectMap::iterator j;

	CK_OBJECT_CLASS objClass;
	CK_KEY_TYPE keyType;
	CK_BBOOL    bSign;
	/* check that the object supports this mechanism */
	CK_ATTRIBUTE mechTemplate[]=
	{	{CKA_CLASS, &objClass, sizeof(objClass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	    {CKA_SIGN, &bSign, sizeof(bSign)}
	  //  {CKA_VALUE, &keyValue[0], sizeof(keyValue)}
	};

	/* get lengths for attributes */
	ret = C_GetAttributeValue(hSession, hKey, &mechTemplate[0], 3);
	if (ret != CKR_OK)
		return ret;

	if ( mechTemplate[0].ulValueLen == (unsigned long)-1 ||
		 mechTemplate[1].ulValueLen == (unsigned long)-1 ||
		 mechTemplate[2].ulValueLen == (unsigned long)-1)
		 return CKR_OBJECT_HANDLE_INVALID;

	/* make private key is present and can sign */
	if (*((CK_OBJECT_CLASS_PTR) mechTemplate[0].pValue) != CKO_PRIVATE_KEY ||
		*((CK_BBOOL *) mechTemplate[2].pValue) != CK_TRUE)
	{
		CKR_OBJECT_HANDLE_INVALID;
	}
		
	switch(pMechanism->mechanism)
	{
		case CKM_DSA_SHA1:
			if (*((CK_KEY_TYPE *) mechTemplate[1].pValue) == CKK_DSA)
			{
				/* since this is a DSA key we'll need to retrieve the domain parameters and private key
				 * from the object
				 */
				i->second.pSigner = createDSASigner(hSession, hKey);
				if (i->second.pSigner == NULL)
					return CKR_OBJECT_HANDLE_INVALID;
#if 0
				/* create CryptoPP object for Signing */
				CryptoPP::ByteQueue bq;
				bq.LazyPut((byte *)mechTemplate[3].pValue, mechTemplate[3].ulValueLen);

				i->second.pSigner = new CryptoPP::DSA::Signer(bq);
				//i->second.pSigner = new CryptoPP::DSA::Signer((byte *)mechTemplate[3].pValue, mechTemplate[3].ulValueLen);
#endif
			}
			else 
			{
				return CKR_OBJECT_HANDLE_INVALID;
			}
			break;
		case CKM_SHA1_RSA_PKCS:
			{
				i->second.pSigner = initRSASigner(hSession, hKey);
			    //RSAObject<CryptoPP::RSASSA_PKCS1v15_SHA_Signer>::createSigner(hSession, hKey);
			}
			break;
		case CKM_MD2_RSA_PKCS:
			{
#if 0
				RSAObject<CryptoPP::RSASSA_PKCS1v15_MD2_Signer> rsaObj;
				i->second.pSigner = rsaObj.createSigner(hSession, hKey);
				//RSAObject<CryptoPP::RSASSA_PKCS1v15_MD2_Signer>::createSigner(hSession, hKey);
#endif
			}
			break;
		case CKM_MD5_RSA_PKCS:
			{
#if 0
				RSAObject<CryptoPP::RSASSA_PKCS1v15_MD5_Signer> rsaObj;
				i->second.pSigner = rsaObj.createSigner(hSession, hKey);
				//RSAObject<CryptoPP::RSASSA_PKCS1v15_MD5_Signer>::createSigner(hSession, hKey);
#endif
			}
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
#endif // _OLD_CODE
}


/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_Sign)
(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check the arguments
	if ((pData == NULL_PTR) || (ulDataLen == 0) || (pulSignatureLen == NULL_PTR))
		return CKR_ARGUMENTS_BAD;

	// Find the specified session
	CKSessionClass* pSession = GetSessionFromHandle(hSession);
	if (pSession == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Check that the operation has been initialized
	if (pSession->pSigner == NULL)
		return CKR_OPERATION_NOT_INITIALIZED;

	// Return the size of the signature value
	CK_ULONG signatureSpace = *pulSignatureLen;
	*pulSignatureLen = pSession->pSigner->SignatureLength();

	if (pSignature == NULL_PTR)
	{
		// Signature value is not requested, so just return
		return CKR_OK;
	}
	else if (*pulSignatureLen > signatureSpace)
	{
		// Signature value is too big to fit in available space, so return error
		return CKR_BUFFER_TOO_SMALL;
	}
	
	try {
		// Calculate the signature value
		pSession->pSigner->SignMessage(gRNG, pData, ulDataLen, pSignature);

		// Clear the CryptoPP::PK_Signer object
		delete pSession->pSigner;
		pSession->pSigner = NULL;

		return CKR_OK;
	}
	catch (...) {
		return CKR_FUNCTION_FAILED;
	}
}


/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data, 
 * and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_BYTE_PTR       pPart,     /* the data to sign */
		CK_ULONG          ulPartLen) /* count of bytes to sign */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignFinal finishes a multiple-part signature operation, 
 * returning the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(
		CK_SESSION_HANDLE hSession,        /* the session's handle */
		CK_BYTE_PTR       pSignature,      /* gets the signature */
		CK_ULONG_PTR      pulSignatureLen) /* gets signature length */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(
		CK_SESSION_HANDLE hSession,   /* the session's handle */
		CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
		CK_OBJECT_HANDLE  hKey)       /* handle of the signature key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(
		CK_SESSION_HANDLE hSession,        /* the session's handle */
		CK_BYTE_PTR       pData,           /* the data to sign */
		CK_ULONG          ulDataLen,       /* count of bytes to sign */
		CK_BYTE_PTR       pSignature,      /* gets the signature */
		CK_ULONG_PTR      pulSignatureLen) /* gets signature length */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
