#include "cryptoki.h"
#include "p11cryptopp_internal.h"
#include <memory>


CryptoPP::DSA::Signer * createDSASigner(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CryptoPP::DSA::Signer *ret = NULL;

	CK_ATTRIBUTE dsaTemplate[]=
	{
		{CKA_PRIME, NULL_PTR, 0},
		{CKA_SUBPRIME, NULL_PTR, 0},
		{CKA_BASE, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};

	/* call to get length of attribute values */
	if (C_GetAttributeValue(hSession, hObject, &dsaTemplate[0], 4) != CKR_OK)
		return NULL;

	if (dsaTemplate[0].ulValueLen == (unsigned long )-1 ||
		dsaTemplate[1].ulValueLen == (unsigned long)-1 ||
		dsaTemplate[2].ulValueLen == (unsigned long)-1 ||
		dsaTemplate[3].ulValueLen == (unsigned long)-1)
		return NULL;

	dsaTemplate[0].pValue = new byte[dsaTemplate[0].ulValueLen];
	dsaTemplate[1].pValue = new byte[dsaTemplate[1].ulValueLen];
	dsaTemplate[2].pValue = new byte[dsaTemplate[2].ulValueLen];
	dsaTemplate[3].pValue = new byte[dsaTemplate[3].ulValueLen];

	/* setup auto_ptr<> objects to handle the automatic cleanup
	 * of attribute values when the fall out of scope.
	 */
	std::auto_ptr<byte> pValue1((byte*)dsaTemplate[0].pValue);
	std::auto_ptr<byte> pValue2((byte*)dsaTemplate[1].pValue);
	std::auto_ptr<byte> pValue3((byte*)dsaTemplate[2].pValue);
	std::auto_ptr<byte> pValue4((byte*)dsaTemplate[3].pValue);

	/* get the attribute values
	 */
	if (C_GetAttributeValue(hSession, hObject, &dsaTemplate[0], 4) != CKR_OK)
		return NULL;

	/* double check that none of the attrbute value retrievals failed
	 */
	if (dsaTemplate[0].ulValueLen == -1 ||
		dsaTemplate[1].ulValueLen == -1 ||
		dsaTemplate[2].ulValueLen == -1 ||
		dsaTemplate[3].ulValueLen == -1)
		return NULL;

	CryptoPP::Integer p,q,g,x;

	try
	{
		p.Decode((byte *)dsaTemplate[0].pValue, dsaTemplate[0].ulValueLen,CryptoPP::Integer::UNSIGNED);
		q.Decode((byte *)dsaTemplate[1].pValue, dsaTemplate[1].ulValueLen,CryptoPP::Integer::UNSIGNED);
		g.Decode((byte *)dsaTemplate[2].pValue, dsaTemplate[2].ulValueLen,CryptoPP::Integer::UNSIGNED);
		x.Decode((byte *)dsaTemplate[3].pValue, dsaTemplate[3].ulValueLen,CryptoPP::Integer::UNSIGNED);
		ret = new CryptoPP::DSA::Signer(p,q,g,x);
	}
	catch(...)
	{
		return NULL;
	}

	return ret;
}

CryptoPP::DSA::Verifier * createDSAVerifier(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	CryptoPP::DSA::Verifier *ret = NULL;

	CK_ATTRIBUTE dsaTemplate[]=
	{
		{CKA_PRIME, NULL_PTR, 0},
		{CKA_SUBPRIME, NULL_PTR, 0},
		{CKA_BASE, NULL_PTR, 0},
		{CKA_VALUE, NULL_PTR, 0}
	};

	/* call to get length of attribute values */
	if (C_GetAttributeValue(hSession, hObject, &dsaTemplate[0], 4) != CKR_OK)
		return NULL;

	if (dsaTemplate[0].ulValueLen == (unsigned long)-1 ||
		dsaTemplate[1].ulValueLen == (unsigned long)-1 ||
		dsaTemplate[2].ulValueLen == (unsigned long)-1 ||
		dsaTemplate[3].ulValueLen == (unsigned long)-1)
		return NULL;

	dsaTemplate[0].pValue = new byte[dsaTemplate[0].ulValueLen];
	dsaTemplate[1].pValue = new byte[dsaTemplate[1].ulValueLen];
	dsaTemplate[2].pValue = new byte[dsaTemplate[2].ulValueLen];
	dsaTemplate[3].pValue = new byte[dsaTemplate[3].ulValueLen];

	/* setup auto_ptr<> objects to handle the automatic cleanup
	 * of attribute values when the fall out of scope.
	 */
	std::auto_ptr<byte> pValue1((byte*)dsaTemplate[0].pValue);
	std::auto_ptr<byte> pValue2((byte*)dsaTemplate[1].pValue);
	std::auto_ptr<byte> pValue3((byte*)dsaTemplate[2].pValue);
	std::auto_ptr<byte> pValue4((byte*)dsaTemplate[3].pValue);

	/* get the attribute values
	 */
	if (C_GetAttributeValue(hSession, hObject, &dsaTemplate[0], 4) != CKR_OK)
		return NULL;

	/* double check that none of the attrbute value retrievals failed
	 */
	if (dsaTemplate[0].ulValueLen == -1 ||
		dsaTemplate[1].ulValueLen == -1 ||
		dsaTemplate[2].ulValueLen == -1 ||
		dsaTemplate[3].ulValueLen == -1)
		return NULL;

	CryptoPP::Integer p,q,g,y;

	try
	{
		p.Decode((byte *)dsaTemplate[0].pValue, dsaTemplate[0].ulValueLen,CryptoPP::Integer::UNSIGNED);
		q.Decode((byte *)dsaTemplate[1].pValue, dsaTemplate[1].ulValueLen,CryptoPP::Integer::UNSIGNED);
		g.Decode((byte *)dsaTemplate[2].pValue, dsaTemplate[2].ulValueLen,CryptoPP::Integer::UNSIGNED);
		y.Decode((byte *)dsaTemplate[3].pValue, dsaTemplate[3].ulValueLen,CryptoPP::Integer::UNSIGNED);
		ret = new CryptoPP::DSA::Verifier(p,q,g,y);
	}
	catch(...)
	{
		return NULL;
	}

	return ret;
}
