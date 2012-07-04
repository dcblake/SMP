/************************ PKCS #11 Verifying signatures and MACs Functions ************************
 *
 * This source file contains the following slot and token functions:
 *  + C_VerifyInit
 *  + C_Verify
 *  + C_VerifyUpdate
 *  + C_VerifyFinal
 *  + C_VerifyRecoverInit
 *  + C_VerifyRecover
 */


#include "p11cryptopp_internal.h"


/* C_VerifyInit
 * initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 * be recovered from the signature (e.g. DSA). 
 */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey)        /* verification key */ 
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

	// Clear the CryptoPP::PK_Verifier object
	if (pSession->pVerifier != NULL)
	{
		delete pSession->pVerifier;
		pSession->pVerifier = NULL;
	}

	// Find the specified public key object
	CKObjectMap::iterator iObj = pSession->m_objectMap.find(hKey);
	if (iObj == pSession->m_objectMap.end())
		return CKR_KEY_HANDLE_INVALID;
	if (iObj->second == NULL)
		return CKR_GENERAL_ERROR;
	if (iObj->second->m_class != CKO_PUBLIC_KEY)
		return CKR_KEY_HANDLE_INVALID;

	// Downcast the public key object
	const CKPublicKeyObject* pPubKeyObj =
		dynamic_cast<const CKPublicKeyObject*>(iObj->second);
	if (pPubKeyObj == NULL)
		return CKR_GENERAL_ERROR;

	// Check that the mechanism is consistent with the public key
	CK_RV rv = pPubKeyObj->CheckMechanism(*pMechanism);
	if (rv != CKR_OK)
		return rv;

	// Check the that public key supports signature verification
	if (!pPubKeyObj->m_canVerify)
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
			pSession->pVerifier = pPubKeyObj->CreateVerifier(*pMechanism);
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

#if 0
				RSAObject<CryptoPP::RSASSA_PKCS1v15_MD2_Verifier> rsaObj;
				
				if (*((CK_KEY_TYPE *) mechTemplate[1].pValue) == CKK_RSA)
					i->second.pVerifier = rsaObj.createVerifier(hSession, hKey);
				//RSAObject<CryptoPP::RSASSA_PKCS1v15_MD2_Verifier>::createVerifier(hSession, hKey);

				RSAObject<CryptoPP::RSASSA_PKCS1v15_MD5_Verifier> rsaObj;
				
				if (*((CK_KEY_TYPE *) mechTemplate[1].pValue) == CKK_RSA)
					i->second.pVerifier = rsaObj.createVerifier(hSession, hKey);
				//RSAObject<CryptoPP::RSASSA_PKCS1v15_MD5_Verifier>::createVerifier(hSession, hKey);
			i->second.pVerifier = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA>::Verifier(bq);
			i->second.pVerifier = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier(bq);
			i->second.pVerifier = new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Verifier(bq);
#endif
}


/* C_Verify 
 * verifies a signature in a single-part operation, 
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_Verify)(
	CK_SESSION_HANDLE hSession,       /* the session's handle */
	CK_BYTE_PTR       pData,          /* signed data */
	CK_ULONG          ulDataLen,      /* length of signed data */
	CK_BYTE_PTR       pSignature,     /* signature */
	CK_ULONG          ulSignatureLen) /* signature length*/
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check the arguments
	if ((pData == NULL_PTR) || (ulDataLen == 0) || (pSignature == NULL_PTR) ||
		(ulSignatureLen == 0))
		return CKR_ARGUMENTS_BAD;

	// Find the specified session
	CKSessionClass* pSession = GetSessionFromHandle(hSession);
	if (pSession == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	// Check that the operation has been initialized
	if (pSession->pVerifier == NULL)
		return CKR_OPERATION_NOT_INITIALIZED;

	// Try to verify the signature
	CK_RV rv = CKR_SIGNATURE_INVALID;
	try {
		if (pSession->pVerifier->VerifyMessage(pData, ulDataLen, pSignature,
			ulSignatureLen) == true)
			rv = CKR_OK;
	}
	catch (...) {
		rv = CKR_GENERAL_ERROR;
	}

	// Clear the CryptoPP::PK_Verifier object
	delete pSession->pVerifier;
	pSession->pVerifier = NULL;

	// Return the result
	return rv;
}


/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data, 
 * and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_BYTE_PTR       pPart,     /* signed data */
		CK_ULONG          ulPartLen) /* length of signed data */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(
		CK_SESSION_HANDLE hSession,       /* the session's handle */
		CK_BYTE_PTR       pSignature,     /* signature to verify */
		CK_ULONG          ulSignatureLen) /* signature length */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
		CK_OBJECT_HANDLE  hKey)        /* verification key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(
		CK_SESSION_HANDLE hSession,        /* the session's handle */
		CK_BYTE_PTR       pSignature,      /* signature to verify */
		CK_ULONG          ulSignatureLen,  /* signature length */
		CK_BYTE_PTR       pData,           /* gets signed data */
		CK_ULONG_PTR      pulDataLen)      /* gets signed data len */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
