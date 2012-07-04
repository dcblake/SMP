#ifdef _OLD_CODE

#include "cryptoki.h"
#include "p11cryptopp_internal.h"
#include <memory>

/************************ PKCS #11 Key Management Functions ************************
 *
 * This source file contains the following session management functions:
 * + C_GenerateKey
 * + C_GenerateKeyPair
 */

/* C_GenerateKey 
 * generates a secret key or set of domain parameters, creating a new object.
 * hSession is the session’s handle; pMechanism points to the generation mechanism; pTemplate
 * points to the template for the new key or set of domain parameters; ulCount is the number 
 * of attributes in the template; phKey points to the location that receives the handle of the 
 * new key or set of domain parameters.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey)        /* gets handle of new key */
{
	CK_RV ret = CKR_OK;

	SessionMap::iterator i = gSessionMap.find(hSession);	
	if (i == gSessionMap.end())
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism == NULL_PTR || pTemplate == NULL_PTR || ulCount < 1 || phKey == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	switch (pMechanism->mechanism)
	{
		case CKM_DSA_PARAMETER_GEN:
			{
				/** check template for PRIME length 
				/** DSA Parameter Generation **/
				CK_ULONG primeLength = 0;
				for (unsigned int i = 0; i < ulCount; i++)
				{
					if (pTemplate[i].type == CKA_PRIME_BITS)
					{
						primeLength = ((CK_ULONG *)pTemplate[i].pValue)[0];
						break;
					}
				}
				if (primeLength != 512 && primeLength != 1024)
					return CKR_KEY_SIZE_RANGE;

				CryptoPP::Integer p,q,g,h;
				int counter = 4096;
				CryptoPP::SecByteBlock seed(CryptoPP::SHA::DIGESTSIZE);
	       	
				/* generate p,q */
				do
				{
					gRNG.GenerateBlock(seed, CryptoPP::SHA::DIGESTSIZE);
				} while (!CryptoPP::DSA::GeneratePrimes(seed, CryptoPP::SHA::DIGESTSIZE * 8,
					counter, p, primeLength, q));

				/* calculate g */
				do
				{
					h.Randomize(gRNG, 2, p-2);
					g = CryptoPP::a_exp_b_mod_c(h, (p-1)/q, p);
				} while (g <= 1);
				/** DSA Parameter Generation **/

				/* create object */
			    /*	CKA_CLASS, CKA_KEY_TYPE, CKA_PRIME,
				 * CKA_SUBPRIME, CKA_BASE and CKA_PRIME_BITS
				 */
				CK_OBJECT_CLASS dsaParamsClass = CKO_DOMAIN_PARAMETERS;
				CK_KEY_TYPE dsaKeyType = CKK_DSA;
				
				
				CryptoPP::SecByteBlock dsaPrime(p.MinEncodedSize(CryptoPP::Integer::SIGNED));
			    CryptoPP::SecByteBlock dsaSubPrime(q.MinEncodedSize(CryptoPP::Integer::SIGNED));
				CryptoPP::SecByteBlock dsaBase(g.MinEncodedSize(CryptoPP::Integer::SIGNED));
				
				p.Encode(dsaPrime, p.MinEncodedSize(CryptoPP::Integer::SIGNED), CryptoPP::Integer::SIGNED);
				q.Encode(dsaSubPrime, q.MinEncodedSize(CryptoPP::Integer::SIGNED), CryptoPP::Integer::SIGNED);
				g.Encode(dsaBase, g.MinEncodedSize(CryptoPP::Integer::SIGNED), CryptoPP::Integer::SIGNED);

				CK_ATTRIBUTE primeTemplate[] = {
					{CKA_CLASS, &dsaParamsClass, sizeof(dsaParamsClass)},
					{CKA_KEY_TYPE, &dsaKeyType, sizeof(dsaKeyType)},
					{CKA_PRIME, dsaPrime.data(), dsaPrime.size()},
					{CKA_SUBPRIME, dsaSubPrime.data(), dsaSubPrime.size()},
					{CKA_BASE, dsaBase.data(), dsaBase.size()}};

				return(C_CreateObject(hSession, &primeTemplate[0], 5, phKey));
			}

			break;
		default:
			ret = CKR_MECHANISM_INVALID;
			break;
	}
	return ret;
}

/* C_GenerateKeyPair 
 * generates a public/private key pair, creating new key objects. hSession
 * is the session’s handle; pMechanism points to the key generation mechanism;
 * pPublicKeyTemplate points to the template for the public key; ulPublicKeyAttributeCount is
 * the number of attributes in the public-key template; pPrivateKeyTemplate points to the
 * template for the private key; ulPrivateKeyAttributeCount is the number of attributes in the
 * private-key template; phPublicKey points to the location that receives the handle of the new
 * public key; phPrivateKey points to the location that receives the handle of the new private key.
*/
CK_DEFINE_FUNCTION(CK_RV,C_GenerateKeyPair)(
  CK_SESSION_HANDLE    hSession,                    /* session handle */
  CK_MECHANISM_PTR     pMechanism,                  /* key-gen mech. */
  CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
  CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attrs. */
  CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for priv. key */
  CK_ULONG             ulPrivateKeyAttributeCount,  /* # priv. attrs. */
  CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
  CK_OBJECT_HANDLE_PTR phPrivateKey)                 /* gets priv. key handle */
{
	CK_RV ret;
	SessionMap::iterator i = gSessionMap.find(hSession);	
	if (i == gSessionMap.end())
		return CKR_SESSION_HANDLE_INVALID;

	if (pMechanism == NULL_PTR || pPublicKeyTemplate == NULL_PTR || pPrivateKeyTemplate == NULL_PTR ||
		ulPublicKeyAttributeCount < 1 || ulPrivateKeyAttributeCount < 1 || phPublicKey == NULL_PTR ||
		phPrivateKey == NULL)
		return CKR_ARGUMENTS_BAD;

	switch(pMechanism->mechanism)
	{
		case CKM_DSA_KEY_PAIR_GEN:
			{
				try
				{
					/* public key template must provie prime, subprime, and base */
					if (ulPublicKeyAttributeCount < 3 ||
						(pPublicKeyTemplate[0].type != CKA_PRIME ||
						 pPublicKeyTemplate[1].type != CKA_SUBPRIME ||
						 pPublicKeyTemplate[2].type != CKA_BASE ))
						return CKR_TEMPLATE_INCONSISTENT;

					CryptoPP::ByteQueue xQ, yQ;
					CryptoPP::Integer p,g,q;
					p.Decode((byte *)pPublicKeyTemplate[0].pValue, pPublicKeyTemplate[0].ulValueLen,CryptoPP::Integer::SIGNED);
					q.Decode((byte *)pPublicKeyTemplate[1].pValue, pPublicKeyTemplate[1].ulValueLen,CryptoPP::Integer::SIGNED);
					g.Decode((byte *)pPublicKeyTemplate[2].pValue, pPublicKeyTemplate[2].ulValueLen,CryptoPP::Integer::SIGNED);

					CryptoPP::DSA::Signer x(gRNG, p, q, g);
					const CryptoPP::Integer &privExponent = x.GetKey().GetPrivateExponent();
					CryptoPP::SecByteBlock privExponentBlock(privExponent.MinEncodedSize(CryptoPP::Integer::SIGNED));
                    privExponent.Encode(privExponentBlock, privExponent.MinEncodedSize(CryptoPP::Integer::SIGNED));
					const byte *xData = privExponentBlock.data();
					unsigned int xLen = privExponentBlock.size();

					CryptoPP::DSA::Verifier y(x);
					//y.GetKey().DEREncodeKey(yQ);
					//yQ.Get(yData, yLen);
					const CryptoPP::Integer &pubElement = y.GetKey().GetPublicElement();
					CryptoPP::SecByteBlock pubElementBlock(pubElement.MinEncodedSize(CryptoPP::Integer::SIGNED));
                    pubElement.Encode(pubElementBlock, pubElement.MinEncodedSize(CryptoPP::Integer::SIGNED));
					const byte *yData = pubElementBlock.data();
					unsigned int yLen = pubElementBlock.size();

					CK_OBJECT_CLASS xClass = CKO_PRIVATE_KEY;
					CK_KEY_TYPE xKeyType = CKK_DSA;
					CK_BBOOL ckTrue = CK_TRUE;
					CK_ATTRIBUTE xTemplate[]=
					{ {CKA_CLASS, &xClass, sizeof(xClass)},
					  {CKA_KEY_TYPE, &xKeyType, sizeof(xKeyType)},
                 {0, 0, 0},
                 {0, 0, 0},
                 {0, 0, 0},
					  {CKA_VALUE, (CK_VOID_PTR) xData, xLen},
					  {CKA_LOCAL, &ckTrue, sizeof(ckTrue)},  
					  {CKA_SIGN, &ckTrue, sizeof(ckTrue)} };

               xTemplate[2] = pPublicKeyTemplate[0]; /* P */
				   xTemplate[3] = pPublicKeyTemplate[1]; /* Q */
				   xTemplate[4] = pPublicKeyTemplate[2]; /* G */

					/* create the private key object */
					ret = C_CreateObject(hSession, &xTemplate[0], 8, phPrivateKey);
					if (ret != CKR_OK)
						return ret;

					CK_OBJECT_CLASS yClass = CKO_PUBLIC_KEY;
					CK_KEY_TYPE yKeyType = CKK_DSA;
					/* create the private key object */
					CK_ATTRIBUTE yTemplate[]=
					{
						{CKA_CLASS, &yClass, sizeof(yClass)},
						{CKA_KEY_TYPE, &yKeyType, sizeof(yKeyType)},
                  {0,0,0}, /* P */
                  {0,0,0}, /* Q */
                  {0,0,0}, /* G */
						{CKA_VALUE, (CK_VOID_PTR) yData, yLen},
						{CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
					};
               yTemplate[2] = pPublicKeyTemplate[0]; /* P */
					yTemplate[3] = pPublicKeyTemplate[1]; /* Q */
					yTemplate[4] = pPublicKeyTemplate[2]; /* G */

					ret = C_CreateObject(hSession, &yTemplate[0], 7, phPublicKey);
					if (ret != CKR_OK)
						return ret;
				}
				catch(...)
				{
					return CKR_FUNCTION_FAILED;
				}
			}
			break;
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			{
			CK_ULONG * pModulusBits = NULL_PTR;
			CK_BYTE  * pPublicExponent = NULL_PTR;
			for (unsigned int n = 0; n < ulPublicKeyAttributeCount; n++)
			{
         		if (pPublicKeyTemplate[n].type == CKA_MODULUS_BITS)
					pModulusBits = (CK_ULONG *) pPublicKeyTemplate[n].pValue;
				else if (pPublicKeyTemplate[n].type == CKA_PUBLIC_EXPONENT)
					pPublicExponent = (CK_BYTE *) pPublicKeyTemplate[n].pValue;
			}
			if (pModulusBits == NULL_PTR || pPublicExponent == NULL_PTR)
			{
				return CKR_TEMPLATE_INCONSISTENT;
			}
			//CryptoPP::RSA::Signer privateKey(gRNG, *pModulusBitsBits, *pPublicExponent);
			
			CryptoPP::ByteQueue xQ,yQ;

			CryptoPP::RSASSA_PKCS1v15_SHA_Signer x(gRNG, *pModulusBits, *pPublicExponent);
			//x.GetKey().DEREncode(xQ);
			CryptoPP::Integer privateModulus, privateExponent;
			privateModulus = x.GetKey().GetModulus();
			privateExponent = x.GetKey().GetPrivateExponent();
			//privateExponent = x.GetKey().GetPublicExponent();


			CryptoPP::SecByteBlock privateModulusBlock(privateModulus.MinEncodedSize(CryptoPP::Integer::SIGNED));
			CryptoPP::SecByteBlock privateExponentBlock(privateExponent.MinEncodedSize(CryptoPP::Integer::SIGNED));
			
			privateModulus.Encode(privateModulusBlock, privateModulus.MinEncodedSize(CryptoPP::Integer::SIGNED), 
				CryptoPP::Integer::SIGNED);
			privateExponent.Encode(privateExponentBlock, privateExponent.MinEncodedSize(CryptoPP::Integer::SIGNED), 
				CryptoPP::Integer::SIGNED);

			CryptoPP::RSASSA_PKCS1v15_SHA_Verifier y(x);

			CryptoPP::Integer publicModulus, publicExponent;
	
			publicModulus = y.GetKey().GetModulus();
			publicExponent = y.GetKey().GetPublicExponent();

			CryptoPP::SecByteBlock publicModulusBlock(publicModulus.MinEncodedSize(CryptoPP::Integer::SIGNED));
			CryptoPP::SecByteBlock publicExponentBlock(publicExponent.MinEncodedSize(CryptoPP::Integer::SIGNED));
			
			publicModulus.Encode(publicModulusBlock, publicModulus.MinEncodedSize(CryptoPP::Integer::SIGNED), 
				CryptoPP::Integer::SIGNED);
			publicExponent.Encode(publicExponentBlock, publicExponent.MinEncodedSize(CryptoPP::Integer::SIGNED), 
				CryptoPP::Integer::SIGNED);

			/*
			 * create private key object 
			 */

			CK_OBJECT_CLASS ckClass = CKO_PRIVATE_KEY;
			CK_KEY_TYPE rsaKeyType = CKK_RSA;
			CK_BBOOL ckTrue = CK_TRUE;
	
			CK_ATTRIBUTE xTemplate[]=
			{
				{CKA_CLASS, &ckClass, sizeof(ckClass)},
				{CKA_KEY_TYPE, &rsaKeyType, sizeof(rsaKeyType)},
				{CKA_MODULUS, privateModulusBlock.data(), privateModulusBlock.size()},
				{CKA_PRIVATE_EXPONENT, privateExponentBlock.data(), privateExponentBlock.size()},
				{CKA_SIGN, &ckTrue, sizeof(ckTrue)}
			};

			ret = C_CreateObject(hSession, &xTemplate[0], 5, phPrivateKey);
			if (ret != CKR_OK)
				return ret;
			
			/*
			 * create public key object
			 */			
			
			ckClass = CKO_PUBLIC_KEY;

			CK_ATTRIBUTE yTemplate[]=
			{
				{CKA_CLASS, &ckClass, sizeof(ckClass)},
				{CKA_KEY_TYPE, &rsaKeyType, sizeof(rsaKeyType)},
				{CKA_MODULUS, publicModulusBlock.data(), publicModulusBlock.size()},
				{CKA_PUBLIC_EXPONENT, publicExponentBlock.data(), publicExponentBlock.size()},
				{CKA_VERIFY, &ckTrue, sizeof(ckTrue)}
			};
			ret = C_CreateObject(hSession, &yTemplate[0], 5, phPublicKey);
			if (ret != CKR_OK)
				return ret;
			}
			break;
		default:
			return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}


#endif //NOTUSED
