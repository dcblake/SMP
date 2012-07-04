/****************************************************************************
File:     CKSession.cpp
Project:  PKCS #11 Crypto++ Library
Contents: Source file for the internal classes and functions used in the
          PKCS #11 Crypto++ library

Created:  3 April 2004
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	9 April 2004

Version:  1.0

*****************************************************************************/

// Included Files
#include "p11cryptopp_internal.h"


/////////////////////////////////////////////////
// CKSessionClass implementation
//
CKSessionClass::~CKSessionClass()
{
		// Delete the crypto objects
		delete pHashObj;
		delete pSigner;
		delete pVerifier;

		// Delete the PKCS #11 objects in the map
		CKObjectMap::iterator i;
		for (i = m_objectMap.begin(); i != m_objectMap.end(); ++i)
		{
			delete i->second;
			i->second = NULL;
		}
}


CK_OBJECT_HANDLE CKSessionClass::AddObject(CKObject* pNewObject)
{
	CK_OBJECT_HANDLE newHandle = (CK_OBJECT_HANDLE)pNewObject;
	if (!m_objectMap.insert(CKObjectMap::value_type(newHandle, pNewObject)).second)
		throw CKR_FUNCTION_FAILED;

	return newHandle;
}


/////////////////////////////////////////////////
// CKObject class implementation
//
CK_RV CKObject::GetAttributeValue(CK_ATTRIBUTE& attribute) const
{
	switch (attribute.type)
	{
	case CKA_CLASS:
		return CopyAttributeValue(attribute, &m_class,
			sizeof(CK_OBJECT_CLASS));

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}


CKObject* CKObject::Construct(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	// Check the template for duplicate values (same type, different values)
	if (DuplicateValuesExist(pTemplate, ulCount))
		throw CKR_TEMPLATE_INCONSISTENT;

	// Find the new object's class
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_CLASS);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;

	switch (*(CK_OBJECT_CLASS*)pAttrib->pValue)
	{
	case CKO_PUBLIC_KEY:
		return CKPublicKeyObject::Construct(pTemplate, ulCount);

	case CKO_DATA:
	case CKO_CERTIFICATE:
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
	case CKO_HW_FEATURE:
	case CKO_DOMAIN_PARAMETERS:
		throw CKR_TEMPLATE_INCONSISTENT;
				
	default:
		throw CKR_ATTRIBUTE_VALUE_INVALID;
	}
}


bool CKObject::DuplicateValuesExist(CK_ATTRIBUTE_PTR pTemplate,
									CK_ULONG ulCount)
{
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		for (CK_ULONG j = i + 1; j < ulCount; ++j)
		{
			// If the types match, check if the values are the same
			if (pTemplate[i].type == pTemplate[j].type)
			{
				// If the lengths don't match return true
				if (pTemplate[i].ulValueLen != pTemplate[j].ulValueLen)
					return true;

				// If either value is NULL, return true
				if ((pTemplate[i].pValue == NULL_PTR) ||
					(pTemplate[j].pValue == NULL_PTR))
					return true;

				// If the values match, return true
				if (memcmp(pTemplate[i].pValue, pTemplate[j].pValue,
					pTemplate[i].ulValueLen) == 0)
					return true;
			}
		}
	}

	return false;
}


CK_RV CKObject::CopyAttributeValue(CK_ATTRIBUTE& attribute, const void* pValue,
								   size_t valueSize) const
{
	if (attribute.pValue == NULL_PTR)
	{
		attribute.ulValueLen = valueSize;
	}
	else if (attribute.ulValueLen < valueSize)
	{
		attribute.ulValueLen = (CK_ULONG)-1;
		return CKR_BUFFER_TOO_SMALL;
	}
	else
	{
		attribute.ulValueLen = valueSize;
		memcpy(attribute.pValue, pValue, valueSize);
	}
	return CKR_OK;
}


CK_ATTRIBUTE_PTR CKObject::FindAttribute(CK_ATTRIBUTE_PTR pTemplate,
										 CK_ULONG ulCount,
										 CK_ATTRIBUTE_TYPE type)
{
	for (CK_ULONG i = 0; i < ulCount; ++i)
	{
		if (pTemplate[i].type == type)
			return &pTemplate[i];
	}

	return NULL;
}


/////////////////////////////////////////////////
// CKStorageObject class implementation
//
CKStorageObject::CKStorageObject(CK_OBJECT_CLASS objClass,
								 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
								 CK_BBOOL isToken, CK_BBOOL isPrivate,
								 CK_BBOOL isModifiable) :
CKObject(objClass), m_isToken(isToken), m_isPrivate(isPrivate),
m_canChange(isModifiable)
{
	// Find the new storage object's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_LABEL);
	if (pAttrib != NULL)
		m_label.assign((char*)(CK_UTF8CHAR*)pAttrib->pValue, pAttrib->ulValueLen);

}


CK_RV CKStorageObject::GetAttributeValue(CK_ATTRIBUTE& attribute) const
{
	CK_RV rv = CKObject::GetAttributeValue(attribute);
	if (rv != CKR_ATTRIBUTE_TYPE_INVALID)
		return rv;

	switch (attribute.type)
	{
	case CKA_TOKEN:
		return CopyAttributeValue(attribute, &m_isToken, sizeof(CK_BBOOL));

	case CKA_PRIVATE:
		return CopyAttributeValue(attribute, &m_isPrivate, sizeof(CK_BBOOL));

	case CKA_MODIFIABLE:
		return CopyAttributeValue(attribute, &m_canChange, sizeof(CK_BBOOL));

	case CKA_LABEL:
		return CopyAttributeValue(attribute, m_label.data(), m_label.size());

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}


/////////////////////////////////////////////////
// CKKeyObject class implementation
//
CKKeyObject::CKKeyObject(CK_OBJECT_CLASS objClass, CK_KEY_TYPE keyType,
						 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
						 CK_MECHANISM_TYPE mechanism, CK_BBOOL isToken,
						 CK_BBOOL isPrivate, CK_BBOOL isModifiable) :
CKStorageObject(objClass, pTemplate, ulCount, isToken, isPrivate, isModifiable),
m_type(keyType), m_mech(mechanism)
{
	// Initialize default attributes
	memset(&m_startDate, 0, sizeof(CK_DATE));
	memset(&m_endDate, 0, sizeof(CK_DATE));
	m_derive = FALSE;
	if (m_mech == CK_UNAVAILABLE_INFORMATION)
		m_isLocal = FALSE;
	else
		m_isLocal = TRUE;

	// Find the new key's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_ID);
	if (pAttrib != NULL)
		m_id.assign((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_START_DATE);
	if (pAttrib != NULL)
		m_startDate = *(CK_DATE*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_END_DATE);
	if (pAttrib != NULL)
		m_endDate = *(CK_DATE*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_DERIVE);
	if (pAttrib != NULL)
		m_derive = *(CK_BBOOL*)pAttrib->pValue;
}


CK_RV CKKeyObject::GetAttributeValue(CK_ATTRIBUTE& attribute) const
{
	CK_RV rv = CKStorageObject::GetAttributeValue(attribute);
	if (rv != CKR_ATTRIBUTE_TYPE_INVALID)
		return rv;

	switch (attribute.type)
	{
	case CKA_KEY_TYPE:
		return CopyAttributeValue(attribute, &m_type, sizeof(CK_KEY_TYPE));

	case CKA_ID:
		return CopyAttributeValue(attribute, m_id.data(), m_id.size());

	case CKA_START_DATE:
		return CopyAttributeValue(attribute, &m_startDate, sizeof(CK_DATE));

	case CKA_END_DATE:
		return CopyAttributeValue(attribute, &m_endDate, sizeof(CK_DATE));

	case CKA_DERIVE:
		return CopyAttributeValue(attribute, &m_derive, sizeof(CK_BBOOL));

	case CKA_LOCAL:
		return CopyAttributeValue(attribute, &m_isLocal, sizeof(CK_BBOOL));

	case CKA_KEY_GEN_MECHANISM:
		return CopyAttributeValue(attribute, &m_mech,
			sizeof(CK_MECHANISM_TYPE));

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}


CK_RV CKKeyObject::CopyInteger(CK_ATTRIBUTE& attribute,
							   const CryptoPP::Integer& intValue) const
{
	CK_ULONG intSize = intValue.MinEncodedSize();
	if (attribute.pValue == NULL_PTR)
	{
		attribute.ulValueLen = intSize;
	}
	else if (attribute.ulValueLen < intSize)
	{
		attribute.ulValueLen = (CK_ULONG)-1;
		return CKR_BUFFER_TOO_SMALL;
	}
	else
	{
		attribute.ulValueLen = intSize;
		intValue.Encode((byte*)attribute.pValue, attribute.ulValueLen);
	}
	return CKR_OK;
}


/////////////////////////////////////////////////
// CKPublicKeyObject class implementation
//
CKPublicKeyObject::CKPublicKeyObject(CK_KEY_TYPE keyType,
									 CK_ATTRIBUTE_PTR pTemplate,
									 CK_ULONG ulCount,
									 CK_MECHANISM_TYPE mechanism,
									 CK_BBOOL isToken, CK_BBOOL isPrivate,
									 CK_BBOOL isModifiable) :
CKKeyObject(CKO_PUBLIC_KEY, keyType, pTemplate, ulCount, mechanism, isToken,
			isPrivate, isModifiable)
{
	// Can only be set to TRUE by the SO user
	m_isTrusted = FALSE;

	// Initialize default attributes
	m_canEncrypt = FALSE;
	m_canVerify = FALSE;
	m_canVerifyWithRecovery = FALSE;
	m_canWrap = FALSE;

	// Find the new public key's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_SUBJECT);
	if (pAttrib != NULL)
		m_subject.assign((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_ENCRYPT);
	if (pAttrib != NULL)
		m_canEncrypt = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_VERIFY);
	if (pAttrib != NULL)
		m_canVerify = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_VERIFY_RECOVER);
	if (pAttrib != NULL)
		m_canVerifyWithRecovery = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_WRAP);
	if (pAttrib != NULL)
		m_canWrap = *(CK_BBOOL*)pAttrib->pValue;
}


CK_RV CKPublicKeyObject::GetAttributeValue(CK_ATTRIBUTE& attribute) const
{
	CK_RV rv = CKKeyObject::GetAttributeValue(attribute);
	if (rv != CKR_ATTRIBUTE_TYPE_INVALID)
		return rv;

	switch (attribute.type)
	{
	case CKA_SUBJECT:
		return CopyAttributeValue(attribute, m_subject.data(),
			m_subject.size());

	case CKA_ENCRYPT:
		return CopyAttributeValue(attribute, &m_canEncrypt, sizeof(CK_BBOOL));

	case CKA_VERIFY:
		return CopyAttributeValue(attribute, &m_canVerify, sizeof(CK_BBOOL));

	case CKA_VERIFY_RECOVER:
		return CopyAttributeValue(attribute, &m_canVerifyWithRecovery, sizeof(CK_BBOOL));

	case CKA_WRAP:
		return CopyAttributeValue(attribute, &m_canWrap, sizeof(CK_BBOOL));

	case CKA_TRUSTED:
		return CopyAttributeValue(attribute, &m_isTrusted, sizeof(CK_BBOOL));

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}


CKObject* CKPublicKeyObject::Construct(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	// Initialize the default attributes
	CK_BBOOL isToken = FALSE;
	CK_BBOOL isPrivate = FALSE;
	CK_BBOOL isModifiable = TRUE;

	// Find the new public key's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_TOKEN);
	if (pAttrib != NULL)
		isToken = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_PRIVATE);
	if (pAttrib != NULL)
		isPrivate = *(CK_BBOOL*)pAttrib->pValue;
		
	pAttrib = FindAttribute(pTemplate, ulCount, CKA_MODIFIABLE);
	if (pAttrib != NULL)
		isModifiable = *(CK_BBOOL*)pAttrib->pValue;

	// Find the new public key's type
	pAttrib = FindAttribute(pTemplate, ulCount, CKA_KEY_TYPE);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;

	// Create the requested public key object if supported
	switch (*(CK_KEY_TYPE*)pAttrib->pValue)
	{
	case CKK_RSA:
		return new CKRSAPublicKeyObject(pTemplate, ulCount,
			CK_UNAVAILABLE_INFORMATION, isToken, isPrivate, isModifiable);
		break;
				
	case CKK_DSA:
		return new CKDSAPublicKeyObject(pTemplate, ulCount,
			CK_UNAVAILABLE_INFORMATION, isToken, isPrivate, isModifiable);
		break;
				
//	case CKK_EC:
//		return new CKECPublicKeyObject(pTemplate, ulCount,
//			CK_UNAVAILABLE_INFORMATION, isToken, isPrivate, isModifiable);
//		break;
				
	default:
		throw CKR_TEMPLATE_INCONSISTENT;
	}
}


/////////////////////////////////////////////////
// CKRSAPublicKeyObject class implementation
//
CKRSAPublicKeyObject::CKRSAPublicKeyObject(CK_ATTRIBUTE_PTR pTemplate,
										   CK_ULONG ulCount,
										   CK_MECHANISM_TYPE mechanism,
										   CK_BBOOL isToken,
										   CK_BBOOL isPrivate,
										   CK_BBOOL isModifiable) :
CKPublicKeyObject(CKK_RSA, pTemplate, ulCount, mechanism, isToken, isPrivate,
				  isModifiable)
{
	// Find the new RSA public key's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_MODULUS);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;
	modulus.Decode((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);
	modulusBits = pAttrib->ulValueLen * 8;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_PUBLIC_EXPONENT);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;
	publicExponent.Decode((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);
}


CK_RV CKRSAPublicKeyObject::CheckMechanism(const CK_MECHANISM& mechanism) const
{
	switch (mechanism.mechanism)
	{
	case CKM_MD2_RSA_PKCS:
	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
		if ((mechanism.pParameter == NULL_PTR) &&
			(mechanism.ulParameterLen == 0))
			return CKR_OK;
		else
			return CKR_MECHANISM_PARAM_INVALID;

	default:
		return CKR_MECHANISM_INVALID;
	}
}


CryptoPP::PK_Verifier* CKRSAPublicKeyObject::CreateVerifier(const CK_MECHANISM& mechanism) const
{
	switch (mechanism.mechanism)
	{
	case CKM_MD2_RSA_PKCS:
		return new CryptoPP::RSASSA_PKCS1v15_MD2_Verifier(modulus, publicExponent);

	case CKM_MD5_RSA_PKCS:
		return new CryptoPP::RSASSA_PKCS1v15_MD5_Verifier(modulus, publicExponent);

	case CKM_SHA1_RSA_PKCS:
		return new CryptoPP::RSASSA_PKCS1v15_SHA_Verifier(modulus, publicExponent);

	default:
		return NULL;
	}
}


CK_RV CKRSAPublicKeyObject::GetAttributeValue(CK_ATTRIBUTE& attribute) const
{
	CK_RV rv = CKPublicKeyObject::GetAttributeValue(attribute);
	if (rv != CKR_ATTRIBUTE_TYPE_INVALID)
		return rv;

	switch (attribute.type)
	{
	case CKA_MODULUS:
		return CopyInteger(attribute, modulus);

	case CKA_MODULUS_BITS:
		return CopyAttributeValue(attribute, &modulusBits, sizeof(CK_ULONG));

	case CKA_PUBLIC_EXPONENT:
		return CopyInteger(attribute, publicExponent);

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}


/////////////////////////////////////////////////
// CKDSAPublicKeyObject class implementation
//
CKDSAPublicKeyObject::CKDSAPublicKeyObject(CK_ATTRIBUTE_PTR pTemplate,
										   CK_ULONG ulCount,
										   CK_MECHANISM_TYPE mechanism,
										   CK_BBOOL isToken,
										   CK_BBOOL isPrivate,
										   CK_BBOOL isModifiable) :
CKPublicKeyObject(CKK_DSA, pTemplate, ulCount, mechanism, isToken, isPrivate,
				  isModifiable)
{
	// Find the new DSA public key's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_PRIME);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;
	p.Decode((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_SUBPRIME);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;
	q.Decode((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_BASE);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;
	g.Decode((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_VALUE);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;
	y.Decode((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);
}


CK_RV CKDSAPublicKeyObject::CheckMechanism(const CK_MECHANISM& mechanism) const
{
	switch (mechanism.mechanism)
	{
	case CKM_DSA_SHA1:
		if ((mechanism.pParameter == NULL_PTR) &&
			(mechanism.ulParameterLen == 0))
			return CKR_OK;
		else
			return CKR_MECHANISM_PARAM_INVALID;

	default:
		return CKR_MECHANISM_INVALID;
	}
}


CryptoPP::PK_Verifier* CKDSAPublicKeyObject::CreateVerifier(const CK_MECHANISM& mechanism) const
{
	switch (mechanism.mechanism)
	{
	case CKM_DSA_SHA1:
		return new CryptoPP::DSA::Verifier(p, q, g, y);

	default:
		throw CKR_MECHANISM_INVALID;
	}
}


CK_RV CKDSAPublicKeyObject::GetAttributeValue(CK_ATTRIBUTE& attribute) const
{
	CK_RV rv = CKPublicKeyObject::GetAttributeValue(attribute);
	if (rv != CKR_ATTRIBUTE_TYPE_INVALID)
		return rv;

	switch (attribute.type)
	{
	case CKA_PRIME:
		return CopyInteger(attribute, p);

	case CKA_SUBPRIME:
		return CopyInteger(attribute, q);

	case CKA_BASE:
		return CopyInteger(attribute, g);

	case CKA_VALUE:
		return CopyInteger(attribute, y);

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}


#ifdef _NOT_IMPLEMENTED
/////////////////////////////////////////////////
// CKECPublicKeyObject class implementation
//
CKECPublicKeyObject::CKECPublicKeyObject(CK_ATTRIBUTE_PTR pTemplate,
										 CK_ULONG ulCount,
										 CK_MECHANISM_TYPE mechanism,
										 CK_BBOOL isToken, CK_BBOOL isPrivate,
										 CK_BBOOL isModifiable) :
CKPublicKeyObject(CKK_EC, pTemplate, ulCount, mechanism, isToken, isPrivate,
				  isModifiable)
{
	// Find the new EC public key's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount,
		CKA_EC_PARAMS);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;
	ecParams.assign((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_EC_POINT);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;
	ecPoint.assign((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);
}


CK_RV CKECPublicKeyObject::CheckMechanism(const CK_MECHANISM& mechanism) const
{
	switch (mechanism.mechanism)
	{
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA_SHA256:
	case CKM_ECDSA_SHA384:
		if ((mechanism.pParameter == NULL_PTR) &&
			(mechanism.ulParameterLen == 0))
			return CKR_OK;
		else
			return CKR_MECHANISM_PARAM_INVALID;

	default:
		return CKR_MECHANISM_INVALID;
	}
}


CryptoPP::PK_Verifier* CKECPublicKeyObject::CreateVerifier(const CK_MECHANISM& mechanism) const
{
	switch (mechanism.mechanism)
	{
	case CKM_ECDSA_SHA1:
		return new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA>::Verifier(ecPoint, ecParams);

	case CKM_ECDSA_SHA256:
		return new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier(ecPoint, ecParams);

	case CKM_ECDSA_SHA384:
		return new CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::Verifier(ecPoint, ecParams);

	default:
		throw CKR_MECHANISM_INVALID;
	}
}


CK_RV CKECPublicKeyObject::GetAttributeValue(CK_ATTRIBUTE& attribute) const
{
	CK_RV rv = CKPublicKeyObject::GetAttributeValue(attribute);
	if (rv != CKR_ATTRIBUTE_TYPE_INVALID)
		return rv;

	switch (attribute.type)
	{
	case CKA_EC_PARAMS:
		return CopyAttributeValue(attribute, ecParams.data(), ecParams.size());

	case CKA_EC_POINT:
		return CopyAttributeValue(attribute, ecPoint.data(), ecPoint.size());

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}
#endif // _NOT_IMPLEMENTED


/////////////////////////////////////////////////
// CKPrivateKeyObject class implementation
//
CKPrivateKeyObject::CKPrivateKeyObject(CK_KEY_TYPE keyType,
									   CK_ATTRIBUTE_PTR pTemplate,
									   CK_ULONG ulCount,
									   CK_MECHANISM_TYPE mechanism,
									   CK_BBOOL isToken, CK_BBOOL isPrivate,
									   CK_BBOOL isModifiable) :
CKKeyObject(CKO_PRIVATE_KEY, keyType, pTemplate, ulCount, mechanism, isToken,
			isPrivate, isModifiable)
{
	// Initialize default attributes
	m_isSensitive = TRUE;
	m_canDecrypt = FALSE;
	m_canSign = FALSE;
	m_canSignWithRecovery = FALSE;
	m_canUnwrap = FALSE;
	m_isExtractable = FALSE;
	m_alwaysSensitive = TRUE;
	m_neverExtractable = TRUE;

	// Find the new public key's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_SUBJECT);
	if (pAttrib != NULL)
		m_subject.assign((CK_BYTE*)pAttrib->pValue, pAttrib->ulValueLen);

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_SENSITIVE);
	if (pAttrib != NULL)
	{
		m_isSensitive = *(CK_BBOOL*)pAttrib->pValue;
		if (!m_isSensitive)
			m_alwaysSensitive = FALSE;
	}

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_DECRYPT);
	if (pAttrib != NULL)
		m_canDecrypt = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_SIGN);
	if (pAttrib != NULL)
		m_canSign = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_SIGN_RECOVER);
	if (pAttrib != NULL)
		m_canSignWithRecovery = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_UNWRAP);
	if (pAttrib != NULL)
		m_canUnwrap = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_EXTRACTABLE);
	if (pAttrib != NULL)
	{
		m_isExtractable = *(CK_BBOOL*)pAttrib->pValue;
		if (m_isExtractable)
			m_neverExtractable = FALSE;
	}
}


CK_RV CKPrivateKeyObject::GetAttributeValue(CK_ATTRIBUTE& attribute) const
{
	CK_RV rv = CKKeyObject::GetAttributeValue(attribute);
	if (rv != CKR_ATTRIBUTE_TYPE_INVALID)
		return rv;

	switch (attribute.type)
	{
	case CKA_SUBJECT:
		return CopyAttributeValue(attribute, m_subject.data(),
			m_subject.size());

	case CKA_SENSITIVE:
		return CopyAttributeValue(attribute, &m_isSensitive, sizeof(CK_BBOOL));

	case CKA_DECRYPT:
		return CopyAttributeValue(attribute, &m_canDecrypt, sizeof(CK_BBOOL));

	case CKA_SIGN:
		return CopyAttributeValue(attribute, &m_canSign, sizeof(CK_BBOOL));

	case CKA_SIGN_RECOVER:
		return CopyAttributeValue(attribute, &m_canSignWithRecovery, sizeof(CK_BBOOL));

	case CKA_UNWRAP:
		return CopyAttributeValue(attribute, &m_canUnwrap, sizeof(CK_BBOOL));

	case CKA_EXTRACTABLE:
		return CopyAttributeValue(attribute, &m_isExtractable, sizeof(CK_BBOOL));

	case CKA_ALWAYS_SENSITIVE:
		return CopyAttributeValue(attribute, &m_alwaysSensitive, sizeof(CK_BBOOL));

	case CKA_NEVER_EXTRACTABLE:
		return CopyAttributeValue(attribute, &m_neverExtractable, sizeof(CK_BBOOL));

	default:
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
}


#ifdef _NOT_IMPLEMENTED
CKObject* CKPrivateKeyObject::Construct(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	// Initialize the default attributes
	CK_BBOOL isToken = FALSE;
	CK_BBOOL isPrivate = TRUE;
	CK_BBOOL isModifiable = TRUE;

	// Find the new public key's attributes
	CK_ATTRIBUTE_PTR pAttrib = FindAttribute(pTemplate, ulCount, CKA_TOKEN);
	if (pAttrib != NULL)
		isToken = *(CK_BBOOL*)pAttrib->pValue;

	pAttrib = FindAttribute(pTemplate, ulCount, CKA_PRIVATE);
	if (pAttrib != NULL)
		isPrivate = *(CK_BBOOL*)pAttrib->pValue;
		
	pAttrib = FindAttribute(pTemplate, ulCount, CKA_MODIFIABLE);
	if (pAttrib != NULL)
		isModifiable = *(CK_BBOOL*)pAttrib->pValue;

	// Find the new public key's type
	pAttrib = FindAttribute(pTemplate, ulCount, CKA_KEY_TYPE);
	if (pAttrib == NULL)
		throw CKR_TEMPLATE_INCOMPLETE;

	// Create the requested public key object if supported
	switch (*(CK_KEY_TYPE*)pAttrib->pValue)
	{
	case CKK_RSA:
		return new CKRSAPrivateKeyObject(pTemplate, ulCount,
			CK_UNAVAILABLE_INFORMATION, isToken, isPrivate, isModifiable);
		break;
				
	case CKK_DSA:
		return new CKDSAPrivateKeyObject(pTemplate, ulCount,
			CK_UNAVAILABLE_INFORMATION, isToken, isPrivate, isModifiable);
		break;
				
	case CKK_EC:
		return new CKECPrivateKeyObject(pTemplate, ulCount,
			CK_UNAVAILABLE_INFORMATION, isToken, isPrivate, isModifiable);
		break;
				
	default:
		throw CKR_TEMPLATE_INCONSISTENT;
	}
}
#endif // _NOT_IMPLEMENTED
