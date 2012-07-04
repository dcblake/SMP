#include "cryptoki.h"
#include "p11cryptopp_internal.h"
#include <memory>


CryptoPP::PK_Signer * initRSASigner (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV ret = CKR_OK;
	CryptoPP::Integer modulus, privateExponent;
	CK_ATTRIBUTE rsaTemplate[]=
	{
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PRIVATE_EXPONENT, NULL_PTR, 0}
	};

	try
	{
		ret = C_GetAttributeValue(hSession, hObject, &rsaTemplate[0], 2);
		if (ret != CKR_OK)
			return NULL;

		if (rsaTemplate[0].ulValueLen == (unsigned long)-1 || 
			rsaTemplate[1].ulValueLen == (unsigned long)-1)
			return NULL;

		rsaTemplate[0].pValue = malloc(rsaTemplate[0].ulValueLen);
		rsaTemplate[1].pValue = malloc(rsaTemplate[1].ulValueLen);
		std::auto_ptr<byte> pValue1((byte *)rsaTemplate[0].pValue);
		std::auto_ptr<byte> pValue2((byte *)rsaTemplate[1].pValue);
		
		ret = C_GetAttributeValue(hSession, hObject, &rsaTemplate[0], 2);
		if (ret != CKR_OK)
			return NULL;

		modulus.Decode((byte *) rsaTemplate[0].pValue, rsaTemplate[0].ulValueLen,
				CryptoPP::Integer::SIGNED);
		privateExponent.Decode((byte *) rsaTemplate[1].pValue,
				rsaTemplate[1].ulValueLen, CryptoPP::Integer::SIGNED);

		if (rsaTemplate[1].ulValueLen > 0)
		{
			CryptoPP::RSA::PrivateKey key;
			key.SetModulus(modulus);
			key.SetPrivateExponent(privateExponent);
			return new CryptoPP::RSASSA_PKCS1v15_SHA_Signer(key);
		}
	}
	catch(...)
	{
		/* do nothing */
	}
    return NULL;
}

CryptoPP::PK_Verifier * initRSAVerifier (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CK_RV ret = CKR_OK;
	CryptoPP::Integer modulus, publicExponent;
	CK_ATTRIBUTE rsaTemplate[]=
	{
		{CKA_MODULUS, NULL_PTR, 0},
		{CKA_PUBLIC_EXPONENT, NULL_PTR, 0}
	};

	try
	{
		ret = C_GetAttributeValue(hSession, hObject, &rsaTemplate[0], 2);
		if (ret != CKR_OK)
			return NULL;

		if (rsaTemplate[0].ulValueLen == (unsigned long)-1 || 
			rsaTemplate[1].ulValueLen == (unsigned long)-1)
			return NULL;

		rsaTemplate[0].pValue = malloc(rsaTemplate[0].ulValueLen);
		rsaTemplate[1].pValue = malloc(rsaTemplate[1].ulValueLen);
		std::auto_ptr<byte> pValue1((byte *)rsaTemplate[0].pValue);
		std::auto_ptr<byte> pValue2((byte *)rsaTemplate[1].pValue);
		
		ret = C_GetAttributeValue(hSession, hObject, &rsaTemplate[0], 2);
		if (ret != CKR_OK)
			return NULL;

		modulus.Decode((byte *) rsaTemplate[0].pValue, rsaTemplate[0].ulValueLen,
				CryptoPP::Integer::UNSIGNED);
		publicExponent.Decode((byte *) rsaTemplate[1].pValue, 
				rsaTemplate[1].ulValueLen, CryptoPP::Integer::UNSIGNED);

		return new CryptoPP::RSASSA_PKCS1v15_SHA_Verifier(modulus, publicExponent);
	}
	catch(...)
	{
	   /* do nothing */
	}
    return NULL;
}

