/****************************************************************************
File:     p11cryptopp_internal.h
Project:  PKCS #11 Crypto++ Library
Contents: Header file for the internal classes, types, and functions used in
		  the PKCS #11 Crypto++ library

Created:  6 September 2003
Author:   Pierce Leonberger <Pierce.Leonberger@DigitalNet.com>

Last Updated:	12 April 2004

Version:  1.0

*****************************************************************************/
#ifndef _P11CRYPTOPP_INTERNAL_H
#define _P11CRYPTOPP_INTERNAL_H

#ifdef _MSC_VER
	#pragma warning(disable: 4100)	// Disable unreferenced parameter warning
	#pragma warning(disable: 4512)	// Disable assignment op not generated warning
	#pragma warning(disable: 4514)	// Disable unreferenced inline function warning
	#pragma warning(disable: 4710)	// Disable function not inlined warning
	#pragma warning(disable: 4786)	// Disable debug identifer truncated warning
	#pragma warning(push, 3)
#endif
#include <map>
#include "cryptoki.h"
#include "cryptlib.h"
#include "queue.h"
#include "files.h"
#include "rsa.h"
#include "dsa.h"
#include "ecp.h"
#include "eccrypto.h"
#include "sha.h"
#include "md2.h"
#include "md5.h"
#include "randpool.h"
#include "rng.h"
#include "rijndael.h"
#include "cbcmac.h"
#include "modes.h"
#include "aes.h"
#ifdef _MSC_VER
	#pragma warning(pop)
#endif

#ifndef WIN32
	#include "asn-chartraits.h"		// Needed for char_traits<unsigned char>

#if defined(SunOS) || defined(SCO_SV) || defined(HPUX) || defined(HPUX32)
	namespace std
	{
		typedef basic_string<wchar_t> wstring;
	}
#endif // SunOS
#endif // !WIN32


typedef std::basic_string<byte>	ByteString;


class CKObject
{
public:
	CKObject(CK_OBJECT_CLASS objClass) : m_class(objClass)					{}
	virtual ~CKObject()														{}

	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

	// Members
	const CK_OBJECT_CLASS m_class;	// Type of object

	// Static constructor
	static CKObject* Construct(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

protected:
	CK_RV CopyAttributeValue(CK_ATTRIBUTE& attribute, const void* pValue,
		size_t valueSize) const;
	static CK_ATTRIBUTE_PTR FindAttribute(CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount, CK_ATTRIBUTE_TYPE type);

private:
	static bool DuplicateValuesExist(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
};


class CKStorageObject : public CKObject
{
public:
	CKStorageObject(CK_OBJECT_CLASS objClass, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount, CK_BBOOL isToken = FALSE, CK_BBOOL isPrivate = FALSE,
		CK_BBOOL isModifiable = TRUE);

	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

public:
	const CK_BBOOL	m_isToken;		// True if object's a token object, false if
									//    if it's a session object (default false)
	const CK_BBOOL	m_isPrivate;	// True if object is private
	const CK_BBOOL	m_canChange;	// True if object can be modified (default true)
	std::string		m_label;		// Description of the object


#ifdef _OLD_CODE
	CKObject() {pObject = NULL;}
	virtual ~CKObject() {delete pObject;}

	void setKey(CK_OBJECT_HANDLE hKey) {m_hKey = hKey;}
	void setTemplate(const CK_ATTRIBUTE_PTR pObjectTemplate, CK_ULONG ulObjectTemplateLen)
	{
		m_ulObjectTemplateLen = ulObjectTemplateLen;
		m_pObjectTemplate = (CK_ATTRIBUTE_PTR) calloc(1, sizeof(CK_ATTRIBUTE) * ulObjectTemplateLen);
		for (unsigned int i = 0; i < ulObjectTemplateLen; i++)
		{
			m_pObjectTemplate[i].type = pObjectTemplate[i].type;
			m_pObjectTemplate[i].ulValueLen = pObjectTemplate[i].ulValueLen;
			m_pObjectTemplate[i].pValue = (CK_VOID_PTR) calloc(1, m_pObjectTemplate[i].ulValueLen);
			memcpy(m_pObjectTemplate[i].pValue, pObjectTemplate[i].pValue, m_pObjectTemplate[i].ulValueLen);
		}
	}
	void getAttribute(CK_ATTRIBUTE_PTR attr)
	{
		bool found = false;
		for (unsigned int i = 0; i < m_ulObjectTemplateLen; i++)
		{
			if (m_pObjectTemplate[i].type == attr->type)
			{
				found = true;
				if (attr->pValue == NULL_PTR)
					attr->ulValueLen = m_pObjectTemplate[i].ulValueLen;
				else if (attr->ulValueLen < m_pObjectTemplate[i].ulValueLen)
					attr->ulValueLen = -1;
				else
				{
					attr->ulValueLen = m_pObjectTemplate[i].ulValueLen;
					attr->pValue = (CK_VOID_PTR) calloc(1, attr->ulValueLen);
					memcpy(attr->pValue, m_pObjectTemplate[i].pValue, attr->ulValueLen);
				}
				break;
			}
		}
		if (!found)
			attr->ulValueLen = -1;
	}

	CKObjectContainer *pObject;
	CK_OBJECT_HANDLE	 m_hKey;
	CK_ATTRIBUTE_PTR m_pObjectTemplate;
	CK_ULONG         m_ulObjectTemplateLen;
	CK_ULONG type;
#endif // _OLD_CODE
};


class CKKeyObject : public CKStorageObject
{
public:
	CKKeyObject(CK_OBJECT_CLASS objClass, CK_KEY_TYPE keyType,
		CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_MECHANISM_TYPE mechanism = CK_UNAVAILABLE_INFORMATION,
		CK_BBOOL isToken = FALSE, CK_BBOOL isPrivate = FALSE,
		CK_BBOOL isModifiable = TRUE);

	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

	// Members
	const CK_KEY_TYPE		m_type;	// Type of key
	const CK_MECHANISM_TYPE	m_mech;	// Key generation mechanism (only
									//    used when key generated locally)
	ByteString	m_id;				// Key identifier
	CK_DATE		m_startDate;		// Start date for the key
	CK_DATE		m_endDate;			// End date for the key
	CK_BBOOL	m_derive;			// True if key supports key derivation
									//    (default false)
protected:
	CK_RV CopyInteger(CK_ATTRIBUTE& attribute,
		const CryptoPP::Integer& intValue) const;

private:
	// Private member
	CK_BBOOL	m_isLocal;			// True if object was locally generated
};


class CKPublicKeyObject : public CKKeyObject
{
public:
	CKPublicKeyObject(CK_KEY_TYPE keyType, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount, CK_MECHANISM_TYPE mechanism = CK_UNAVAILABLE_INFORMATION,
		CK_BBOOL isToken = FALSE, CK_BBOOL isPrivate = FALSE,
		CK_BBOOL isModifiable = TRUE);

	virtual CK_RV CheckMechanism(const CK_MECHANISM& mechanism) const = 0;
	virtual CryptoPP::PK_Verifier* CreateVerifier(const CK_MECHANISM& mechanism) const = 0;
	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

	// Static constructor
	static CKObject* Construct(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

	// Members
	ByteString	m_subject;					// DER-encoding of the subject name
	CK_BBOOL	m_canEncrypt;				// True if key supports encryption
	CK_BBOOL	m_canVerify;				// True if key supports verification
	CK_BBOOL	m_canVerifyWithRecovery;	// True if key supports verification with recovery
	CK_BBOOL	m_canWrap;					// True if key supports wrapping other keys

private:
	// Private member
	CK_BBOOL	m_isTrusted;	// True if key is trusted by the application (SO user-only)
};


class CKRSAPublicKeyObject : public CKPublicKeyObject
{
public:
	CKRSAPublicKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_MECHANISM_TYPE mechanism, CK_BBOOL isToken, CK_BBOOL isPrivate,
		CK_BBOOL isModifiable);

	virtual CK_RV CheckMechanism(const CK_MECHANISM& mechanism) const;
	virtual CryptoPP::PK_Verifier* CreateVerifier(const CK_MECHANISM& mechanism) const;
	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

	// Static constructor
	static CKObject* Construct(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

private:
	// Members
	CryptoPP::Integer	modulus;
	CK_ULONG			modulusBits;
	CryptoPP::Integer	publicExponent;
};


class CKDSAPublicKeyObject : public CKPublicKeyObject
{
public:
	CKDSAPublicKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_MECHANISM_TYPE mechanism, CK_BBOOL isToken, CK_BBOOL isPrivate,
		CK_BBOOL isModifiable);

	virtual CK_RV CheckMechanism(const CK_MECHANISM& mechanism) const;
	virtual CryptoPP::PK_Verifier* CreateVerifier(const CK_MECHANISM& mechanism) const;
	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

	// Static constructor
	static CKObject* Construct(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

private:
	// Members
	CryptoPP::Integer	p;
	CryptoPP::Integer	q;
	CryptoPP::Integer	g;
	CryptoPP::Integer	y;
};


/*
class CKECPublicKeyObject : public CKPublicKeyObject
{
public:
	CKECPublicKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		CK_MECHANISM_TYPE mechanism, CK_BBOOL isToken, CK_BBOOL isPrivate,
		CK_BBOOL isModifiable);

	virtual CK_RV CheckMechanism(const CK_MECHANISM& mechanism) const;
	virtual CryptoPP::PK_Verifier* CreateVerifier(const CK_MECHANISM& mechanism) const;
	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

	// Static constructor
	static CKObject* Construct(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

private:
	// Members
	ByteString	ecParams;		// DER-encoding of ANSI X9.62 Parameters value
	ByteString	ecPoint;		// DER-encoding of ANSI X9.62 ECPoint value Q
};
*/


class CKPrivateKeyObject : public CKKeyObject
{
public:
	CKPrivateKeyObject(CK_KEY_TYPE keyType, CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount, CK_MECHANISM_TYPE mechanism = CK_UNAVAILABLE_INFORMATION,
		CK_BBOOL isToken = FALSE, CK_BBOOL isPrivate = TRUE,
		CK_BBOOL isModifiable = TRUE);

	virtual CK_RV CheckMechanism(const CK_MECHANISM& mechanism) const = 0;
	virtual CryptoPP::PK_Signer* CreateSigner(const CK_MECHANISM& mechanism) const = 0;
	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

	// Members
	ByteString	m_subject;				// DER-encoding of the subject name
	CK_BBOOL	m_isSensitive;			// True if key is sensitive
	CK_BBOOL	m_canDecrypt;			// True if key supports decryption
	CK_BBOOL	m_canSign;				// True if key supports signing
	CK_BBOOL	m_canSignWithRecovery;	// True if key supports signing with recovery
	CK_BBOOL	m_canUnwrap;			// True if key supports unwrapping other keys
	CK_BBOOL	m_isExtractable;		// True if key is extractable

private:
	// Private members
	CK_BBOOL	m_alwaysSensitive;		// True if the m_isSensitive flag has always been true
	CK_BBOOL	m_neverExtractable;		// True if the m_isExtractable flag has never been true
};


class CKRSAPrivateKeyObject : public CKPrivateKeyObject
{
public:
	CKRSAPrivateKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

	virtual CK_RV CheckMechanism(const CK_MECHANISM& mechanism) const;
	virtual CryptoPP::PK_Signer* CreateSigner(const CK_MECHANISM& mechanism) const;
	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

private:
	// Members
	CryptoPP::Integer	modulus;			// Modulus n
	CryptoPP::Integer	publicExponent;		// Public exponnet e
	CryptoPP::Integer	privateExponent;	// Private exponent d
	CryptoPP::Integer	prime_1;			// Prime p
	CryptoPP::Integer	prime_2;			// Prime q
	CryptoPP::Integer	exponent_1;			// Private exponent d mod p-1
	CryptoPP::Integer	exponent_2;			// Private exponent d mod q-1
	CryptoPP::Integer	coefficient;		// CRT coefficient inv q mod p
};


class CKDSAPrivateKeyObject : public CKPrivateKeyObject
{
public:
	CKDSAPrivateKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

	virtual CK_RV CheckMechanism(const CK_MECHANISM& mechanism) const;
	virtual CryptoPP::PK_Signer* CreateSigner(const CK_MECHANISM& mechanism) const;
	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

private:
	// Members
	CryptoPP::Integer	p;
	CryptoPP::Integer	q;
	CryptoPP::Integer	g;
	CryptoPP::Integer	x;
};


class CKECPrivateKeyObject : public CKPrivateKeyObject
{
public:
	CKECPrivateKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

	virtual CK_RV CheckMechanism(const CK_MECHANISM& mechanism) const;
	virtual CryptoPP::PK_Signer* CreateSigner(const CK_MECHANISM& mechanism) const;
	virtual CK_RV GetAttributeValue(CK_ATTRIBUTE& attribute) const;

private:
	// Members
	ByteString			ecParams;	// DER-encoding of ANSI X9.62 Parameters value
	CryptoPP::Integer	x;			// ANSI X9.62 private value d
};


//typedef std::pair<CK_ULONG, CKObject> CKObjectPair;

typedef std::map<CK_OBJECT_HANDLE, CKObject*> CKObjectMap;


class CKSessionClass
{
public:
	CKSessionClass()	{ pHashObj = NULL; pSigner = NULL; pVerifier = NULL; }
	~CKSessionClass();

	CK_OBJECT_HANDLE AddObject(CKObject* pNewObject);
	void SetNotificationCallbacks(CK_NOTIFY notifyFunction, CK_VOID_PTR appPtr) {
		m_notifyFuncPtr = notifyFunction; m_appPtr = appPtr; }
	
	CryptoPP::HashTransformation* pHashObj;
	CryptoPP::PK_Signer*		  pSigner;
	CryptoPP::PK_Verifier*		  pVerifier;
	CKObjectMap m_objectMap;

private:
	CK_NOTIFY m_notifyFuncPtr;
	CK_VOID_PTR m_appPtr;
};


typedef std::map<CK_SESSION_HANDLE, CKSessionClass> SessionMap;


// Function Prototypes
bool LibraryIsInitialized();
std::pair<SessionMap::iterator, bool> CreateNewSession();
CK_RV CloseSession(CK_SESSION_HANDLE hSession);
CK_RV CloseAllSessions(CK_SLOT_ID slotID);
CKSessionClass* GetSessionFromHandle(CK_SESSION_HANDLE hSession);


// Global Variables
extern CryptoPP::RandomPool gRNG;



#if 0
CryptoPP::DSA::Signer * createDSASigner(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CryptoPP::DSA::Verifier * createDSAVerifier(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

CryptoPP::PK_Verifier * initRSAVerifier (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
CryptoPP::PK_Signer * initRSASigner (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);


template <class T> class RSAObject
{
public:
	T * createSigner(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
	T * createVerifier(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
};
template <class T>
T * RSAObject<T>::createSigner(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
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

		if (rsaTemplate[0].ulValueLen == -1 || 
			rsaTemplate[1].ulValueLen == -1)
			return NULL;

		rsaTemplate[0].pValue = malloc(rsaTemplate[0].ulValueLen);
		rsaTemplate[1].pValue = malloc(rsaTemplate[1].ulValueLen);
		std::auto_ptr<byte> pValue1((byte *)rsaTemplate[0].pValue);
		std::auto_ptr<byte> pValue2((byte *)rsaTemplate[1].pValue);

		ret = C_GetAttributeValue(hSession, hObject, &rsaTemplate[0], 2);
		if (ret != CKR_OK)
			return NULL;

		modulus.Decode((byte *) rsaTemplate[0].pValue, rsaTemplate[0].ulValueLen, CryptoPP::Integer::SIGNED);
		privateExponent.Decode((byte *) rsaTemplate[0].pValue, rsaTemplate[0].ulValueLen, CryptoPP::Integer::SIGNED);

		if (rsaTemplate[1].ulValueLen > 0)
		{
			T *ret = new T;//(modulus, privateExponent, privateExponent);
			//T->Initialize(modulus, privateExponent, privateExponent);
			ret->GetKey().SetModulus(modulus);
			ret->GetKey().SetPublicExponent(privateExponent);
			return ret;
		}
	}
	catch(...)
	{
	   /* do nothing */	
	}
    return NULL;
}

template <class T>
T * RSAObject<T>::createVerifier(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
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

		if (rsaTemplate[0].ulValueLen == -1 || 
			rsaTemplate[1].ulValueLen == -1)
			return NULL;

		modulus.Decode((byte *) rsaTemplate[0].pValue, rsaTemplate[0].ulValueLen, CryptoPP::Integer::SIGNED);
		publicExponent.Decode((byte *) rsaTemplate[0].pValue, rsaTemplate[0].ulValueLen, CryptoPP::Integer::SIGNED);

		if (rsaTemplate[1].ulValueLen > 0)
			return new T(modulus, publicExponent);
	}
	catch(...)
	{
	   /* do nothing */	
	}
    return NULL;
}
#endif


// Global Variables
extern const char kManufacturerName[32];



#endif // _P11CRYPTOPP_INTERNAL_H
