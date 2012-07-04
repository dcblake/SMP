
//////////////////////////////////////////////////////////////////////////
// sm_free.cpp
//
// This CTI Library implements RSA using crypto++
// It will inherit SHA1 from the sm_common CTI
//  RWC; THIS VERSION integrates "crpypto++ 3.0".
//
//////////////////////////////////////////////////////////////////////////

#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#include <process.h>
#include <winsock2.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <setjmp.h>
#include <sys/stat.h>
#ifdef SM_FREE3_RSA_INCLUDED
#include "sm_free3.h"
#include "sm_cms.h"
#include "sm_VDASupport_asn.h"
#include "rsa.h"     // From cryptopp3.
#include "rc2.h"     // From cryptopp3.
#include "sm_vda_cbc.h"  // For use with unpadded encryption/decryption
#include "randpool.h"
extern RandomPool rndRandom;

#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif
#include "sm_AppLogin.h"
using CTIL::CSM_Buffer;
using namespace SNACC;

#ifdef CRYPTOPP_5_0
#include "pwdbased.h"
typedef CBC_Mode_ExternalCipher::Encryption CBCPaddedEncryptor;
typedef CBC_Mode_ExternalCipher::Decryption CBCPaddedDecryptor;
#endif // CRYPTOPP_5_0

_BEGIN_CERT_NAMESPACE

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::RSA_GenerateEMEK(
            CSM_Buffer *pRecipientIN, // input, Y of recipient, public key
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pData, // input, Content Encryption Key to be encrypted
            CSM_Buffer *pEMEK, // output, encrypted Content Encryption Key
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
            CSM_Buffer *pSubjKeyId) // output
{
   CSM_Buffer *pRecipient=NULL;  // COPY in case it has to be re-built (Crypto++5.0)
   SM_RET_VAL           status = 0;
   CryptoPP::ByteQueue  byteQueueBuffer;
   unsigned int         modulus;
   byte                 *pOutCipher = NULL;
 
   SME_SETUP("CSM_Free3::RSA_GenerateEMEK");

   // check incoming parameters
   if ((pRecipientIN == NULL) || (pEMEK == NULL) || (pData == NULL))
      SME_THROW(SM_FREE_MISSING_PARAM, "MISSING PARAMS", NULL);

#ifdef NODEF
   // decode the public key ?

   // RWC; ATTEMPTING different format form MS Outlook Express.
   RSAPublicKey SnaccRSAPublicKey;
   A_RSA_KEY rsaKey;

   DECODE_BUF(&SnaccRSAPublicKey, pRecipient);  // will create exception if 
                                                   //  decode fails.
   rsaKey.modulus.data = (unsigned char *)(char *)SnaccRSAPublicKey.modulus;
   rsaKey.modulus.len = SnaccRSAPublicKey.modulus.Len();
   rsaKey.exponent.data = (unsigned char *)(char *)SnaccRSAPublicKey.publicExponent;
   rsaKey.exponent.len = SnaccRSAPublicKey.publicExponent.Len();
#endif
#ifndef CRYPTOPP_5_0
        pRecipient = pRecipientIN;
#else   //  CRYPTOPP_5_0
        //RWC; Crypto++5.0 changed from just the bitstring to an ASN.1 encoded 
        //RWC;  SubjectPublicKeyInfo.
        SNACC::SubjectPublicKeyInfo SNACCsubjectPublicKeyInfo;
        SNACCsubjectPublicKeyInfo.algorithm.algorithm = SNACC::rsaEncryption; // OR rsa OID.
        CSM_Alg::LoadNullParams(&SNACCsubjectPublicKeyInfo.algorithm);
        /* USELESS; SNACC removes the 0x00//RWC; TRYING to fix a problem when the expoonent is only 1 byte, 
        //RWC;  artificially making it 2 bytes...
        SNACC::RSAPublicKey SnaccRSAPublicKey;
        DECODE_BUF(&SnaccRSAPublicKey, pRecipientIN);
        if (SnaccRSAPublicKey.publicExponent.Len() < 2)
        {   // THEN add a preceeding 0
            unsigned char pNewData[2];
            pNewData[0] = '\0';
            pNewData[1] = SnaccRSAPublicKey.publicExponent[0];
            SnaccRSAPublicKey.publicExponent.Set(pNewData, 2);
            pRecipient = NULL;
            ENCODE_BUF(&SnaccRSAPublicKey, pRecipient);
            if (pRecipient)
            {
              SNACCsubjectPublicKeyInfo.subjectPublicKey.Set(pRecipient->Access(), 
                                                             pRecipient->Length()*8);
              pRecipient = NULL;
            }   // END if pRecipient
        }       // END if modulus length < 2
        //RWC; END TRYING
        else*/
            SNACCsubjectPublicKeyInfo.subjectPublicKey.Set((const unsigned char*)
                                                       pRecipientIN->Access(), 
                                                       pRecipientIN->Length()*8);
        pRecipient = NULL;
        ENCODE_BUF(&SNACCsubjectPublicKeyInfo, pRecipient);
#endif  // CRYPTOPP_5_0

   // NOTE:  RSAES_OAEP_SHA_Encryptor needs a BufferedTransformation object
   // a ByteQueue is used for simple buffering into one of these objects
   // Prepare input into a bufferedTransformation object for encryption
   // with the recipient's public key
   // bufferedTransformation objects may assume that pointers to input
   // and output blocks are aligned on 32 bit boundaries
   byteQueueBuffer.Put((unsigned char *)pRecipient->Access(), pRecipient->Length());
   
   // create public key encryptor object
   // RSAES_OAEP_SHA_Encryptor rsaPub(buffer);
   RSAES_PKCS1v15_Encryptor rsaPub(byteQueueBuffer);

   // modulus = m_keygenParams.modulusBits 1024 / 8 = 128;
#ifndef CRYPTOPP_5_0
   modulus = rsaPub.CipherTextLength(); /*SM_FREE_DEFAULT_KEYBITS / 8;*/
#else // CRYPTOPP_5_0
   modulus = rsaPub.FixedCiphertextLength();//RWC;CiphertextLength(0); 
                /*RWC;???BASED on key I hope!!!??? */
#endif // CRYPTOPP_5_0
            // RWC;12/5/00; MADE modulus releative to key in recip cert.
   //RWC;Crypto++ 5.0 AccessKey()

   // get memory for the output cipher
   if ((pOutCipher = (byte *)calloc(1, modulus)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // inputs: m_pRng (random number), already done during login process
   //         pData to be encrypted, content encryption key
   //         length of data to be encrypted, 
   //         pOutCipher is output produced
   rsaPub.Encrypt(*m_pRng, (unsigned char *)pData->Access(), pData->Length(), pOutCipher);

   // transfer encrypted content encryption key to the output buffer
   SME(pEMEK->Open(SM_FOPEN_WRITE));
   SME(pEMEK->Write((char *)pOutCipher, modulus));  

   SME(pEMEK->Close());

   if (pOutCipher)
      free(pOutCipher);

   // RWC;2/7/00; If successful, load NULL PARAMS according to spec
   // ONLY FOR RSA.
   if (pParameters)
   {
       CSM_Buffer *pTmpBuf=CSM_AlgVDA::GetNullParams();
       *pParameters = *pTmpBuf;
       delete pTmpBuf;
   }

   
   SME_FINISH
   SME_CATCH_SETUP
      // put any local cleanup here
      status = -1;
      if (pRecipient && pRecipient != pRecipientIN)
          delete pRecipient;

   SME_FREE3_CATCH_FINISH

#ifdef WIN32
    pSubjKeyId;pUKM;pParameters; //AVOIDS warning.
#endif
    if (pRecipient != pRecipientIN) // ONLY delete if a new copy was made.
       delete pRecipient;

   return(status);
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::RSA_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output (MEK or special phrase)
{
   SM_RET_VAL   status            = 0;
   CryptoPP::ByteQueue            byteQueueBuffer;
   byte         *pchDecryptedData = NULL;
   unsigned int outLen;
   CSM_Buffer   *pbufX            = NULL; // temp spot for X value
   char         *pszPassword      = NULL; // temp spot for password
   Integer      x;                        // x value in integer form

   SME_SETUP("CSM_Free3::SMTI_RSA_ExtractMEK");

   // check incoming parameters
   if (/*(pOriginator == NULL) || */(pEMEK == NULL) || (pMEK == NULL))
      SME_THROW(SM_FREE_MISSING_PARAM, "Missing parameter, pEMEK or pMEK", NULL);

   // get the rsa private key
   // load current private key X
   SME(pszPassword = GetPassword()); // get the password
   // and then use the password to decrypt the EncryptedPrivateKeyInfo
   SME(pbufX = DecryptPrivateKey(pszPassword, m_pX));

   // Use the RSA private key associated with the public key used
   // to encrypt.
   byteQueueBuffer.Put((unsigned char *)pbufX->Access(), pbufX->Length());

   // NOTE:  RSAES_PKCS1v15_Decryptor needs a BufferedTransformation object
   // a ByteQueue is used for simple buffering into one of these objects
   // Prepare input into a bufferedTransformation object for decryption
   // bufferedTransformation objects may assume that pointers to input
   // and output blocks are aligned on 32 bit boundaries
   // byteQueueBuffer.Put((unsigned char *)pRecipient->Access(), pRecipient->Length());

   // decrypt the emek
#ifndef CRYPTOPP_5_0
   RSAES_PKCS1v15_Decryptor rsaPriv(byteQueueBuffer);
   pchDecryptedData = (byte *)calloc(1,pEMEK->Length());
   outLen = rsaPriv.Decrypt(( const byte *)pEMEK->Access(), pchDecryptedData); 
#else // CRYPTOPP_5_0/5_1
   RSAES_PKCS1v15_Decryptor  rsaPriv(byteQueueBuffer);
   //const PrivateKey &keyPrivate = rsaPriv.GetPrivateKey();
   //CryptoMaterial &cryptoMaterial = rsaPriv.AccessMaterial();
   //Key &key = rsaPriv.GetKey();
   long lCipherLength = rsaPriv.CiphertextLength(pEMEK->Length());
   long lPlainLength  = rsaPriv.MaxPlaintextLength(pEMEK->Length());
   //RWC;DOES NOT WORK;Attempt to encode value as an Cryptopp::Integer
   /*CryptoPP::Integer ciData((const unsigned char*)pEMEK->Access(), pEMEK->Length());
   unsigned char achData[1024];
   ciData.Encode(&achData[0], pEMEK->Length());*/
   pchDecryptedData = (byte *)calloc(1,rsaPriv.MaxPlaintextLength(pEMEK->Length()));
#ifdef CRYPTOPP_5_1
   DecodingResult drResult = rsaPriv.Decrypt(*m_pRng, ( const byte *)/*achData/*/pEMEK->Access(), 
                             pEMEK->Length(), pchDecryptedData); 
#else // CRYPTOPP_5_0
   DecodingResult drResult = rsaPriv.Decrypt(( const byte *)/*achData/*/pEMEK->Access(), 
                             pEMEK->Length(), pchDecryptedData); 
#endif // CRYPTOPP_5_1
   outLen = drResult.messageLength;
   // ProcessLastBlock(...) AND MinLastBlockSize(...)
#endif // CRYPTOPP_5_0

   if (outLen == 0)        // IT DIDN'T WORK!!!
   {
      SME_THROW(22, "Bad rsaPriv.Decrypt!", NULL);
   }

   // put the decrypted data pchDecryptedData into the MEK
   pMEK->Set((char *)pchDecryptedData, outLen);

   if (pchDecryptedData)
       free(pchDecryptedData);
   if (pszPassword)
       free(pszPassword);
   if (pbufX)
       delete pbufX;

   SME_FINISH
   SME_CATCH_SETUP
      // put any local cleanup here
   SME_FREE3_CATCH_FINISH

#ifdef WIN32
    pUKM;pParameters;pOriginator; //AVOIDS warning.
#endif
   return(status);
}       // END CSM_Free3::RSA_ExtractMEK(...)


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::RSAES_OAEP_GenerateEMEK(
            CSM_Buffer *pRecipientIN, // input, Y of recipient, public key
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pData, // input, Content Encryption Key to be encrypted
            CSM_Buffer *pEMEK, // output, encrypted Content Encryption Key
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
            CSM_Buffer *pSubjKeyId) // output
{
   CSM_Buffer *pRecipient=NULL;  // COPY in case it has to be re-built (Crypto++5.0)
   SM_RET_VAL           status = 0;
   CryptoPP::ByteQueue  byteQueueBuffer;
   unsigned int         modulus;
   byte                 *pOutCipher = NULL;
 
   SME_SETUP("CSM_Free3::RSA_GenerateEMEK");

   // check incoming parameters
   if ((pRecipientIN == NULL) || (pEMEK == NULL) || (pData == NULL))
      SME_THROW(SM_FREE_MISSING_PARAM, "MISSING PARAMS", NULL);

#ifdef CRYPTOPP_5_1
        //RWC; Crypto++5.0 changed from just the bitstring to an ASN.1 encoded 
        //RWC;  SubjectPublicKeyInfo.
        SNACC::SubjectPublicKeyInfo SNACCsubjectPublicKeyInfo;
        SNACCsubjectPublicKeyInfo.algorithm.algorithm = SNACC::rsaEncryption; // OR rsa OID.
        CSM_Alg::LoadNullParams(&SNACCsubjectPublicKeyInfo.algorithm);
        SNACCsubjectPublicKeyInfo.subjectPublicKey.Set((const unsigned char*)
                                                       pRecipientIN->Access(), 
                                                       pRecipientIN->Length()*8);
        pRecipient = NULL;
        ENCODE_BUF(&SNACCsubjectPublicKeyInfo, pRecipient);
#else   //  CRYPTOPP_5_0
      SME_THROW(SM_FREE_MISSING_PARAM, "RSAES_OAEP ONLY supported with Crypto++ 5.1!", NULL);
#endif  // CRYPTOPP_5_0
   byteQueueBuffer.Put((unsigned char *)pRecipient->Access(), pRecipient->Length());
   
   // create public key encryptor object
   RSAES_OAEP_SHA_Encryptor rsaPub(byteQueueBuffer);

   modulus = rsaPub.FixedCiphertextLength();

   // get memory for the output cipher
   if ((pOutCipher = (byte *)calloc(1, modulus)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // inputs: m_pRng (random number), already done during login process
   //         pData to be encrypted, content encryption key
   //         length of data to be encrypted, 
   //         pOutCipher is output produced
   rsaPub.Encrypt(*m_pRng, (unsigned char *)pData->Access(), pData->Length(), pOutCipher);

   // transfer encrypted content encryption key to the output buffer
   SME(pEMEK->Open(SM_FOPEN_WRITE));
   SME(pEMEK->Write((char *)pOutCipher, modulus));  

   SME(pEMEK->Close());

   if (pOutCipher)
      free(pOutCipher);

   // RWC;2/7/00; If successful, load NULL PARAMS according to spec
   // ONLY FOR RSA.
   if (pParameters)
   {
       CSM_Buffer *pTmpBuf=CSM_AlgVDA::GetNullParams();
       *pParameters = *pTmpBuf;
       delete pTmpBuf;
   }

   
   SME_FINISH
   SME_CATCH_SETUP
      // put any local cleanup here
      status = -1;
      if (pRecipient && pRecipient != pRecipientIN)
          delete pRecipient;

   SME_FREE3_CATCH_FINISH

#ifdef WIN32
    pSubjKeyId;pUKM;pParameters; //AVOIDS warning.
#endif
    if (pRecipient != pRecipientIN) // ONLY delete if a new copy was made.
       delete pRecipient;

   return(status);
}       // END CSM_Free3::RSAES_OAEP_GenerateEMEK(...)

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::RSAES_OAEP_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output (MEK or special phrase)
{
   SM_RET_VAL   status            = 0;
   CryptoPP::ByteQueue            byteQueueBuffer;
   byte         *pchDecryptedData = NULL;
   unsigned int outLen;
   CSM_Buffer   *pbufX            = NULL; // temp spot for X value
   char         *pszPassword      = NULL; // temp spot for password
   Integer      x;                        // x value in integer form

   SME_SETUP("CSM_Free3::SMTI_RSA_ExtractMEK");

   // check incoming parameters
   if (/*(pOriginator == NULL) || */(pEMEK == NULL) || (pMEK == NULL))
      SME_THROW(SM_FREE_MISSING_PARAM, "Missing parameter, pEMEK or pMEK", NULL);

   // get the rsa private key
   // load current private key X
   SME(pszPassword = GetPassword()); // get the password
   // and then use the password to decrypt the EncryptedPrivateKeyInfo
   SME(pbufX = DecryptPrivateKey(pszPassword, m_pX));

   // Use the RSA private key associated with the public key used
   // to encrypt.
   byteQueueBuffer.Put((unsigned char *)pbufX->Access(), pbufX->Length());

   // decrypt the emek
#ifdef CRYPTOPP_5_1
   RSAES_OAEP_SHA_Decryptor  rsaPriv(byteQueueBuffer);
   long lCipherLength = rsaPriv.CiphertextLength(pEMEK->Length());
   long lPlainLength  = rsaPriv.MaxPlaintextLength(pEMEK->Length());
   pchDecryptedData = (byte *)calloc(1,rsaPriv.MaxPlaintextLength(pEMEK->Length()));
   DecodingResult drResult = rsaPriv.Decrypt(*m_pRng, ( const byte *)/*achData/*/pEMEK->Access(), 
                             pEMEK->Length(), pchDecryptedData); 
   outLen = drResult.messageLength;
   // ProcessLastBlock(...) AND MinLastBlockSize(...)
#else // CRYPTOPP_5_0/5_1
      SME_THROW(22, "RSAES_OAEP_SHA_Decryptor ONLY supported with Crypto++ 5.1!", NULL);
#endif // CRYPTOPP_5_0

   if (outLen == 0)        // IT DIDN'T WORK!!!
   {
      SME_THROW(22, "Bad rsaPriv.Decrypt!", NULL);
   }

   // put the decrypted data pchDecryptedData into the MEK
   pMEK->Set((char *)pchDecryptedData, outLen);

   if (pchDecryptedData)
       free(pchDecryptedData);
   if (pszPassword)
       free(pszPassword);
   if (pbufX)
       delete pbufX;

   SME_FINISH
   SME_CATCH_SETUP
      // put any local cleanup here
   SME_FREE3_CATCH_FINISH

#ifdef WIN32
    pUKM;pParameters;pOriginator; //AVOIDS warning.
#endif
   return(status);
}       // END CSM_Free3::RSAES_OAEP_ExtractMEK(...)


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_VerifyRSA(
            CSM_Buffer *pSignerKeyIN, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
	const char* _func= "CSM_Free3::SMTI_VerifyRSA";
    CSM_Buffer *pSignerKey=NULL;
    RSASSA_PKCS1v15_SHA_Verifier *prsaPub=NULL;
    RSASSA_PKCS1v15_MD5_Verifier *prsaPubMD5=NULL;
	// Initialize return value
    SM_RET_VAL lRet = SM_NO_ERROR;


	try {
		// get the alg oid
		AsnOid algOid = pSignatureAlg->algorithm;
		AsnOid digOid;
		if (pDigestAlg)
			digOid = pDigestAlg->algorithm;
		else
			digOid = algOid;
        if (digOid == md5WithRSAEncryption ||
            digOid == md5WithRSAEncryptionOIW)
            digOid = md5;

		// digest incoming data
		CSM_Buffer bufferDigest;
        SME(CSM_Free3::SMTI_DigestData(pData, &bufferDigest, digOid));
	
		// prepare a bytequeue with the signers public key
		// NOTE:  RSASSA_PKCS1v15_SHA_Verifier needs a BufferedTransformation object
		// a ByteQueue is used for simple buffering into one of these objects
		// Prepare input into a bufferedTransformation object for encryption
		// with the recipient's public key
		// bufferedTransformation objects may assume that pointers to input
		// and output blocks are aligned on 32 bit boundaries
#ifndef CRYPTOPP_5_0
        pSignerKey = pSignerKeyIN;
#else   //  CRYPTOPP_5_0
        //RWC; Crypto++5.0 changed from just the bitstring to an ASN.1 encoded 
        //RWC;  SubjectPublicKeyInfo.
        //*** Incommin Key must always be reformatted
        SubjectPublicKeyInfo SNACCsubjectPublicKeyInfo;
        SNACCsubjectPublicKeyInfo.algorithm.algorithm = rsaEncryption; // OR rsa OID.
        CSM_Alg::LoadNullParams(&SNACCsubjectPublicKeyInfo.algorithm);
        SNACCsubjectPublicKeyInfo.subjectPublicKey.Set((const unsigned char *)
                                                       pSignerKeyIN->Access(), 
                                                       pSignerKeyIN->Length()*8);
        pSignerKey = NULL;
        ENCODE_BUF(&SNACCsubjectPublicKeyInfo, pSignerKey);
        lRet = SM_NO_ERROR;
#endif  // CRYPTOPP_5_0
		CryptoPP::ByteQueue publicKey;
		publicKey.Put((const byte*)pSignerKey->Access(), pSignerKey->Length());

		// determine rsa algorithm
		if (algOid == sha_1WithRSAEncryption ||
			algOid == sha_1WithRSAEncryption_ALT ||
			((algOid == rsaEncryption || algOid == rsa ||
			algOid == AsnOid("1.2.840.113549.1.2")) && 
			(digOid == sha_1 || digOid == sha_1WithRSAEncryption ) ) )
		{
			// prepare the DigestInfo object with null parameters 
			DigestInfo rsaDigestInfo;
			rsaDigestInfo.digestAlgorithm.algorithm = sha_1;
			CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm);
			rsaDigestInfo.digest.Set(bufferDigest.Access(), bufferDigest.Length());

			CSM_Buffer tempBuf;
			tempBuf.Encode(rsaDigestInfo);
            try
            {
                prsaPub = new RSASSA_PKCS1v15_SHA_Verifier(publicKey);
	        }
	        catch(CryptoPP::Exception &e)
	        {
#ifdef CRYPTOPP_5_0
                e.what();   // TO avoid compiler warning.
                //RWC; TRY using the key directly, not re-wrapped as PublicKeyInfo
                delete pSignerKey;
                pSignerKey = pSignerKeyIN;
		        CryptoPP::ByteQueue publicKey2;
		        publicKey2.Put((const byte*)pSignerKey->Access(), pSignerKey->Length());
                try
                {
                    prsaPub = new RSASSA_PKCS1v15_SHA_Verifier(publicKey2);
	            }
	            catch(CryptoPP::Exception &e)
	            {
#endif  //CRYPTOPP_5_0
                char pstrBuf[1024];
                strcpy(pstrBuf, "Crypto++ error: BAD RSA Public key.");
                int icount = strlen(e.what());
                if (icount < 1024 - strlen(pstrBuf))
                    strcat(pstrBuf, e.what());
                else
                    strncat(pstrBuf, e.what(), 1024 - strlen(pstrBuf));
                SME_THROW(22, pstrBuf, NULL);
            }       // END Catch
#ifdef CRYPTOPP_5_0
            }       // END Catch
#endif  //CRYPTOPP_5_0

			// verify the signature
            bool bVer = false;
#ifndef CRYPTOPP_5_0
			bVer = prsaPub->VerifyDigest((const byte *)tempBuf.Access(),
				(unsigned int)tempBuf.Length(),
				(unsigned char *)pSignature->Access());
#else // CRYPTOPP_5_0
            try {
#ifdef CRYPTOPP_5_1
                int iPubSigLen = prsaPub->SignatureLength();
#else  // CRYPTOPP_5_1
                int iPubSigLen = prsaPub->AccessDigestSignatureScheme().DigestSignatureLength(); //->SignatureLength();
#endif // CRYPTOPP_5_1
                if (pSignature->Length() >=  iPubSigLen + 1 ||
                    pSignature->Length() <=  iPubSigLen - 1)
                {
                    SME_THROW(22, "Bad public key length OR Signature length not valid!", NULL);
                }
                bVer = prsaPub->VerifyMessage((const byte *)pData->Access(),
				    (unsigned int)pData->Length(),
				    (const byte *)pSignature->Access()
#ifdef CRYPTOPP_5_1
                    ,pSignature->Length());
#else  // CRYPTOPP_5_1
                    );
#endif // CRYPTOPP_5_1
	        }
	        catch(CryptoPP::Exception &e)
	        {
                char pstrBuf[1024];
                strcpy(pstrBuf, "Crypto++ error: BAD RSA VerifyMessage. ");
                int icount = strlen(e.what());
                if (icount < 1024 - strlen(pstrBuf))
                    strcat(pstrBuf, e.what());
                else
                    strncat(pstrBuf, e.what(), 1024 - strlen(pstrBuf));
                SME_THROW(22, pstrBuf, NULL);
            }       // END Catch
#endif // CRYPTOPP_5_0
		
			if (!bVer)
				lRet = SM_FREE_VERIFY_FAILED;
            delete prsaPub;
            prsaPub = NULL;
		}
		else if (algOid == md5WithRSAEncryption ||
                 algOid == md5WithRSAEncryptionOIW ||
			((algOid == rsaEncryption || algOid == rsa ||
			algOid == AsnOid("1.2.840.113549.1.2")) && digOid == md5))
		{
			// prepare the DigestInfo object with null parameters
			DigestInfo rsaDigestInfo;
			rsaDigestInfo.digestAlgorithm.algorithm = md5;
			CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm);
			rsaDigestInfo.digest.Set(bufferDigest.Access(), bufferDigest.Length());

			CSM_Buffer tempBuf;
			tempBuf.Encode(rsaDigestInfo);
            // REN -- 9/5/03 -- ENCODE_BUF(&rsaDigestInfo, ptempBuf);
			/*RWC;11/15/02;if (!encodeBuf(rsaDigestInfo, tempBuf))
				SME_THROW(33, "Error encoding RSA DigestInfo", NULL);*/
            try 
            {
               prsaPubMD5 = new RSASSA_PKCS1v15_MD5_Verifier(publicKey);
	        }
	        catch(CryptoPP::Exception &e)
	        {
                char pstrBuf[1024];
                strcpy(pstrBuf, "Crypto++ error: BAD RSA Public key.");
                int icount = strlen(e.what());
                if (icount < 1024 - strlen(pstrBuf))
                    strcat(pstrBuf, e.what());
                else
                    strncat(pstrBuf, e.what(), 1024 - strlen(pstrBuf));
                SME_THROW(22, pstrBuf, NULL);
            }       // END Catch
		
			// verify the signature
            bool bVer=false;
#ifndef CRYPTOPP_5_0
			bVer = prsaPubMD5->VerifyDigest((const byte *)tempBuf.Access(),
				(unsigned int)tempBuf.Length(),
				(unsigned char *)pSignature->Access());
#else // CRYPTOPP_5_0
#ifdef CRYPTOPP_5_1
            try {
               bVer = prsaPubMD5->VerifyMessage((byte *)pData->Access(), 
                 (unsigned int)pData->Length(), 
                 (const byte *)pSignature->Access(), pSignature->Length());
            }
	        catch(CryptoPP::Exception &e)
	        {
                delete prsaPubMD5;
                char pstrBuf[1024];
                strcpy(pstrBuf, "Crypto++ error: BAD RSA VerifyDigest.");
                int icount = strlen(e.what());
                if (icount < 1024 - strlen(pstrBuf))
                    strcat(pstrBuf, e.what());
                else
                    strncat(pstrBuf, e.what(), 1024 - strlen(pstrBuf));
                SME_THROW(22, pstrBuf, NULL);
            }       // END Catch
#else   // CRYPTOPP_5_1
            try {
                DigestVerifier &dvVerifier = prsaPubMD5->AccessDigestSignatureScheme();
                bVer = dvVerifier.VerifyDigest((const byte *)tempBuf.Access(),
				    (unsigned int)tempBuf.Length(),
				    (const byte *)pSignature->Access());
            }
	        catch(CryptoPP::Exception &e)
	        {
                delete prsaPubMD5;
                char pstrBuf[1024];
                strcpy(pstrBuf, "Crypto++ error: BAD RSA VerifyDigest.");
                int icount = strlen(e.what());
                if (icount < 1024 - strlen(pstrBuf))
                    strcat(pstrBuf, e.what());
                else
                    strncat(pstrBuf, e.what(), 1024 - strlen(pstrBuf));
                SME_THROW(22, pstrBuf, NULL);
            }       // END Catch
#endif  // CRYPTOPP_5_1
#endif  // CRYPTOPP_5_0
		
			if (!bVer)
				lRet = SM_FREE_VERIFY_FAILED;
            delete prsaPubMD5;
            prsaPubMD5 = NULL;
		}
		else if (algOid == md2WithRSAEncryption ||
			((algOid == rsaEncryption || algOid == rsa ||
			algOid == AsnOid("1.2.840.113549.1.2")) && digOid == id_md2))
		{
			RSASSA_PKCS1v15_MD2_Verifier rsaPub(publicKey);
            bool bVer=false;
			// verify the signature
#ifndef CRYPTOPP_5_0
			bVer = rsaPub.VerifyDigest((const byte*)bufferDigest.Access(),
				(unsigned int) bufferDigest.Length(),
				(unsigned char *)pSignature->Access());
#else // CRYPTOPP_5_0
#ifdef CRYPTOPP_5_1
            try {
               bVer = rsaPub.VerifyMessage((byte *)pData->Access(), 
                 (unsigned int)pData->Length(), 
                 (const byte *)pSignature->Access(), pSignature->Length());
            }
	        catch(CryptoPP::Exception &e)
	        {
                char pstrBuf[1024];
                strcpy(pstrBuf, "Crypto++ error: BAD RSA VerifyDigest.");
                int icount = strlen(e.what());
                if (icount < 1024 - strlen(pstrBuf))
                    strcat(pstrBuf, e.what());
                else
                    strncat(pstrBuf, e.what(), 1024 - strlen(pstrBuf));
                SME_THROW(22, pstrBuf, NULL);
            }       // END Catch
#else  // CRYPTOPP_5_1
            DigestVerifier &dvVerifier = rsaPub.AccessDigestSignatureScheme();
            bVer = dvVerifier.VerifyDigest((const byte *)bufferDigest.Access(),
				(unsigned int) bufferDigest.Length(),
				(const byte *)pSignature->Access());
#endif // CRYPTOPP_5_1
#endif // CRYPTOPP_5_0
			if (!bVer)
				lRet = SM_FREE_VERIFY_FAILED;
		}
		else
		{
			SME_THROW(22, "RSA OID Unknown or Not Handled Yet!", NULL);
		
		}
	}
	catch (SNACC::SnaccException& snaccE) {
        if (prsaPub)
            delete prsaPub;
        if (prsaPubMD5)
            delete prsaPubMD5;
        if (pSignerKey != NULL && pSignerKey != pSignerKeyIN)
            delete pSignerKey; // THEN we created this local version.
		snaccE.push(STACK_ENTRY);
		throw;
	}
	catch(CryptoPP::Exception &e)
	{
        if (prsaPub)
            delete prsaPub;
        if (pSignerKey != NULL && pSignerKey != pSignerKeyIN)
            delete pSignerKey; // THEN we created this local version.
        if (prsaPubMD5)
            delete prsaPubMD5;
        char pstrBuf[1024];
        strcpy(pstrBuf, "Crypto++ error: CSM_Free3::SMTI_VerifyRSA. ");
        int icount = strlen(e.what());
        if (icount < 1024 - strlen(pstrBuf))
            strcat(pstrBuf, e.what());
        else
            strncat(pstrBuf, e.what(), 1024 - strlen(pstrBuf));
        SME_THROW(22, pstrBuf, NULL);
    }       // END Catch

    if (pSignerKey != NULL && pSignerKey != pSignerKeyIN)
        delete pSignerKey; // THEN we created this local version.
    return lRet;
}       // END CSM_Free3::SMTI_VerifyRSA(...)

//
//
Integer *sm_Free3CryptoppBERDecode(const char *ptr, unsigned long len)
{
    Integer *p=new Integer;
#if defined(CRYPTOPP_3_2)
    p->BERDecode((byte *)ptr);
#ifdef WIN32
   len;     //AVOIDS compiler warning.
#endif
#else       // DEFAULT
    CryptoPP::ByteQueue xBTQue;
    xBTQue.Put((unsigned char *)ptr, len);
    p->BERDecode(xBTQue);
#endif
    return(p);
}



// This global function group was create for convenience to generate
// appropriate logic (with #ifdefs) for the individual Crypto++ libs.
// This makes the code more readable, less #ifdefs sprinkled in code.
long sm_Free3CryptoppDEREncode(const Integer &xInt, unsigned char *ptr, unsigned long len)
{
    long nLen=0;
#if defined(CRYPTOPP_3_2)
   nLen = xInt.DEREncode(ptr);
#ifdef WIN32
   len;     //AVOIDS compiler warning.
#endif
#else       // DEFAULT
   CryptoPP::ByteQueue xBTQue;
   xInt.DEREncode(xBTQue);
   nLen = xBTQue.Get(ptr/*byte *outString*/, len/*unsigned int getMax*/);
#endif
   return(nLen);
}

extern "C" {
/////////////////////////////////////////////////////////////////////////////
// This function generates an encrypted private key info
CSM_Buffer *GLOBALWrapPrivateKey(CSM_Buffer &bufferX, char *pszPassword, 
                                 CSM_Alg *pXAlgId)
{
   AsnOid *poidXAlgId = new AsnOid(pXAlgId->algorithm);
   CSM_Buffer *pXAlgParams = NULL;
   PrivateKeyInfo snaccPrivateKeyInfo;
   EncryptedPrivateKeyInfo snaccEncryptedX;
   CSM_Buffer *pbufEncodedPrivateKey = NULL;
   CSM_Buffer *pbufEncryptedPrivateKey = NULL;
   CSM_Buffer *pK = NULL; // PBE Key
   int iterationCount =3;
   int version = 0;
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("WrapPrivateKey");

   /////////////////////////////////////////////
   // fill up the PrivateKeyInfo structure first

   // set the version
   snaccPrivateKeyInfo.version = version;

   // set the private key alg id
   snaccPrivateKeyInfo.privateKeyAlgorithm.algorithm = *(poidXAlgId);

   pXAlgParams = pXAlgId->GetParams();
   // read private key params
   if (pXAlgParams)
   {
      if ((snaccPrivateKeyInfo.privateKeyAlgorithm.parameters = new AsnAny) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
      SME(pXAlgParams->ConvertFileToMemory());
      SM_ASSIGN_ANYBUF((pXAlgParams), snaccPrivateKeyInfo.privateKeyAlgorithm.parameters);
    }

   // read private key
   char *ptr3=bufferX.Get();
   if (ptr3)
   {
       snaccPrivateKeyInfo.privateKey.Set(ptr3, bufferX.Length());
       free(ptr3);
   }

   ////////////////////////////////////
   // ASN.1 encode the private key info
   ENCODE_BUF((&snaccPrivateKeyInfo), pbufEncodedPrivateKey);

   ///////////////////////////////////////////////
   // encrypt pbufEncodedPrivateKey using password

   // create a salt value by concatenating the encoded PrivateKeyInfo onto
   // the password and then MD5 digesting the result
   CSM_Buffer bufferSaltInput, bufferSalt;
   SME(bufferSaltInput.Open(SM_FOPEN_WRITE));
   SME(bufferSaltInput.Write(pszPassword, strlen(pszPassword)));
   SME(bufferSaltInput.Write(pbufEncodedPrivateKey->Access(), 
         pbufEncodedPrivateKey->Length()));
   SME(bufferSaltInput.Close());
   
   AsnOid o(md5);
   CSM_Free3 FreeCTI;
   SME(FreeCTI.BTISetPreferredCSInstAlgs(&o, NULL, NULL, NULL));
   if ((status = FreeCTI.SMTI_DigestData(&bufferSaltInput, &bufferSalt)) 
       != SM_NO_ERROR)
      SME_THROW(status, "SMTI_DigestData returned error.", NULL);

   SME(pK = FreeCTI.GeneratePBEKey(&bufferSalt, iterationCount, 
      pszPassword));

   // the first 8 bytes of pK is the DES Key and the second 8 bytes is the IV
   // create our cipher
   DESEncryption encryption((const unsigned char*)pK->Access());
   // create cbc object
#ifndef CRYPTOPP_5_0
   CBCPaddedEncryptor cbc_encryption(
#else // CRYPTOPP_5_0
   CBC_Mode_ExternalCipher::Encryption  cbc_encryption(
#endif // CRYPTOPP_5_0
       encryption, (const unsigned char*)(pK->Access() + 8));

   CSM_Buffer bufEncryptedData;
   SME(FreeCTI.RawEncrypt(pbufEncodedPrivateKey, &bufEncryptedData, 
         &cbc_encryption));

   //////////////////////////////////////
   // load up the EncryptedPrivateKeyInfo

   // load the encrypted data
   snaccEncryptedX.encryptedData.Set(bufEncryptedData.Access(), 
         bufEncryptedData.Length());

   // fill and encode the encryption algorithm parameters
   PBEParameter snaccPBEParameter;
   char *ptr4=bufferSalt.Get();
   if (ptr4)
   {
       snaccPBEParameter.salt.Set(ptr4, bufferSalt.Length());
       free(ptr4);
   }
   snaccPBEParameter.iterationCount = iterationCount;
   CSM_Buffer *pbufEncryptionParams=NULL;
   ENCODE_BUF((&snaccPBEParameter), pbufEncryptionParams);

   // load the encryptionAlgorithm
   snaccEncryptedX.encryptionAlgorithm.algorithm = pbeWithMD5AndDES_CBC;
   if ((snaccEncryptedX.encryptionAlgorithm.parameters = new AsnAny) == NULL)
      SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
   SM_ASSIGN_ANYBUF(pbufEncryptionParams, snaccEncryptedX.encryptionAlgorithm.parameters);

   /////////////////////////////////////
   // encode the EncryptedPrivateKeyInfo
   ENCODE_BUF(&snaccEncryptedX, pbufEncryptedPrivateKey);

   if (pbufEncodedPrivateKey)
      delete pbufEncodedPrivateKey;
   if (pbufEncryptionParams)
      delete pbufEncryptionParams;
   if (poidXAlgId)
      delete poidXAlgId;
   if (pXAlgParams)
      delete pXAlgParams;
   if (pK)
      delete pK;

   SME_FINISH
   SME_CATCH_SETUP
      if (pbufEncodedPrivateKey)
         delete pbufEncodedPrivateKey;
      if (poidXAlgId)
         delete poidXAlgId;
      if (pXAlgParams)
         delete pXAlgParams;
      if (pK)
         delete pK;

   SME_FREE3_CATCH_FINISH

   return pbufEncryptedPrivateKey;
}       // END GLOBALWrapPrivateKey(...)


/////////////////////////////////////////////////////////////////////////////
//
//
long SFLFree3PKCS12Init2(CSM_CtilMgr &Csmime, char *pszINPassword, 
                         char *pszPFXFile, CSM_MsgCertCrls *pCertPathIN)
{
    long status=0;
    CSM_BufferLst::iterator itCertBuf;
    CSM_Buffer *pCertBufFIRST=NULL;
    CSM_Buffer *pPrivateKey=NULL;
    CSM_TokenInterface  *pTokenInterface=NULL;
    CSM_Alg *pPublicKeyAlg=NULL;
    char *pszPassword=NULL;
    CSM_PrivDataLst PrivateKeyList;
    char lpszID[50];
    static int count=0;
    CSM_Buffer PFXBuf(pszPFXFile);
    char *lpszPrivateKeyOut=NULL;
    /*
    int lPrivateKeyOutLen;
    char **lppszCertOut=NULL;
    int *lpCertOutLen=NULL;
    int lCertCount=0;
    char **lppszCRLOutRETURN;
    int *lpCRLOutLenRETURN;
    int lCRLCountRETURN;
    */
    SME_SETUP("SFLFree3PKCS12Init2");

    PFXBuf.ConvertFileToMemory();      // CHECK that the file exists first.

    // FIRST extract the private key and cert using Crypto++; use password as 
    //  specified, then change for our internal PKCS8.
    status = CSM_Free3::DecryptPKCS12PrivateKey(&PFXBuf, pszINPassword, PrivateKeyList);
#ifdef _DEBUG
    if (status)
    {
            std::cout << "ERROR in CSM_Free3::DecryptPKCS12PrivateKey, status=" <<  status 
            << " FILE=" << pszPFXFile << std::endl;
        if (status == -100) 
            status = 0;     // IGNORE if just the MAC address check, for testing DEBUG ONLY!
    }       // END if status
#endif

    // JAS: allow empty password; 19 Mar 2004
    if (pszINPassword == NULL) pszINPassword = "";
    if (strlen(pszINPassword) < 8) // IMPORTANT, change ONLY after PKCS12 
    {                              //   extracted.
        pszPassword = (char *)calloc(1, 9);
        strcpy(pszPassword, pszINPassword);
        memset(&pszPassword[strlen(pszINPassword)], 'X', 
            8 - strlen(pszINPassword)); // STRETCH to at least 8 chars.
    }
    else
    {
        pszPassword = (char *)calloc(1, strlen(pszINPassword)+1);
        strcpy(pszPassword, pszINPassword);
    }

    if (status == 0 && PrivateKeyList.size())   // ONLY if we have at lease 1 certificate
    {
       CSM_PrivDataLst::iterator itTmpPrivateKeySet;
       for (itTmpPrivateKeySet =  PrivateKeyList.begin();
            itTmpPrivateKeySet != PrivateKeyList.end();
            ++itTmpPrivateKeySet)
       {
            // SECOND, create appropriate data structures for Private key 
            //  and Cert(s).
            CSM_MsgCertCrls *pCertPath=new CSM_MsgCertCrls;
            if (itTmpPrivateKeySet->m_BufCertList.size())
            {
              itCertBuf = itTmpPrivateKeySet->m_BufCertList.begin();
              pCertBufFIRST = new CSM_Buffer(*itCertBuf);
              CSM_CertificateChoice *pCert=new CSM_CertificateChoice(
                              *pCertBufFIRST);
              pPublicKeyAlg = pCert->GetPublicKeyAlg();
              pCertPath->AddCert(pCert);  // MEMORY NO LONGER taken by "AddCert"
                                          //  DUPLICATES auto-removed.
              delete pCert;
              ++itCertBuf;
              for (; itCertBuf != itTmpPrivateKeySet->m_BufCertList.end();
                   ++itCertBuf)
              {
                 pCert = new CSM_CertificateChoice(*itCertBuf);
                 pCertPath->AddCert(pCert);    // MEMORY NO LONGER taken by "AddCert"
                 delete pCert;
              }            // END for each cert in this private key set.
            }              // END if cert buffer(s) in PKCS12 decrypt

            // NOW add optional user specified certs, expected to be cert-path.
            CSM_CertificateChoiceLst::iterator itCertChoice;
            if (pCertPathIN && pCertPathIN->AccessCertificates())
            {
              for (itCertChoice =  pCertPathIN->AccessCertificates()->begin(); 
                   itCertChoice != pCertPathIN->AccessCertificates()->end();
                   ++itCertChoice)
              {
                 pCertPath->AddCert(&(*itCertChoice)); // MEMORY NO LONGER taken by "AddCert"
              }            // END for each cert in this private key set.
            }       // END IF pCertPath

          // THIRD, we must re-wrap this clear private key in a format compatible with
          // the CTIL (a fudge, since we should directly interpret the PKCS12, but time
          // time presses on).
          // (NOTE::: IGNORE the CSM_CryptoKeysDSA class definition below, we simply 
          //  use the inherited component "CSM_CryptoKeysFree3Base" to wrap any clear
          //  Private key, including RSA.  We never defined an RSA class for Free3, 
          //  maybe later).
          if (itTmpPrivateKeySet->m_BufPriv.Length())
            pPrivateKey = new CSM_Buffer(itTmpPrivateKeySet->m_BufPriv);
          //pPrivateKey->ConvertMemoryToFile("./certs/config.d/PrivatePKCS12.bin");
                                //DEBUG send to file...
          //CSM_CryptoKeysDsaExport /*CSM_CryptoKeysFree3Base*/ A;
          CSM_Buffer *pPrivateKeyWrapped = NULL;
          if (pPrivateKey)
          {
             if (pPublicKeyAlg->algorithm == id_dsa)
             {             //RWC;remove wrapper, get just the key.
                PrivateKeyInfo SNACCPrivateKey;
                DECODE_BUF(&SNACCPrivateKey, pPrivateKey);
                delete pPrivateKey;
                pPrivateKey = new CSM_Buffer(
                   SNACCPrivateKey.privateKey.c_str(), 
                   SNACCPrivateKey.privateKey.Len());
             }
              // SIMPLY wrap this clear Key.
              pPrivateKeyWrapped  = /*A.*/GLOBALWrapPrivateKey(*pPrivateKey, pszPassword, 
                  pPublicKeyAlg );
          }

          // FINALLY, create login entry for this private key and cert.
          if (pCertBufFIRST) // && pPrivateKeyWrapped)
          {
              count++;
              sprintf(&lpszID[0], "PKCS12%d", count);
              pTokenInterface  = CSM_Free3::AddLoginStatic(NULL, *pCertBufFIRST,
                   pPrivateKeyWrapped, pszPassword, lpszID, pCertPath);
              delete pCertBufFIRST;    // DELETE User cert.
             // DO NOT FREE pCertPath, it is taken by AddLoginStatic(...)
              CERT::GLOBALAddLoginFinish(Csmime, pTokenInterface, lpszID, pCertPath);
          }

          if (pPrivateKeyWrapped)
              delete pPrivateKeyWrapped;
          pPrivateKeyWrapped = NULL;
          if (pPrivateKey)
              delete pPrivateKey;
          pPrivateKey = NULL;
          if (pPublicKeyAlg)
              delete pPublicKeyAlg;
          pPublicKeyAlg = NULL;

       }       // END for PrivateKeyList items.


       if (pszPassword)
           free(pszPassword);

    }          // IF PrivateKeyList.CountL()
    else
    {
       char buf[1000];
       if (status != 0)
       {
         sprintf(buf, "Bad PKCS12 Decode/Decrypt, file=%s.", pszPFXFile);
         SME_THROW(29, buf, NULL);
       }
       else    // Certificate count in PKCS12 was 0
       {
         sprintf(buf, "Certificate count in PKCS12 was 0, file=%s.", pszPFXFile);
         SME_THROW(status, buf, NULL);
       }
    }       // END if PrivateKeyList.CountL()

    SME_FINISH
    catch (FileException &fe)     // CATCH special exception.
    {
       if (lpszPrivateKeyOut)
           free(lpszPrivateKeyOut);
       if (pPrivateKey)
           delete pPrivateKey;
       if (pPublicKeyAlg)
           delete pPublicKeyAlg;
       if (pszPassword)
           free(pszPassword);

#ifdef WIN32
       fe;      // REMOVES compiler warning.
#endif //WIN32
       char buf[1000];
       sprintf(buf, "Missing PKCS12, file=%s.", pszPFXFile);
       SME_THROW(29, buf, NULL);
    }        // END catch (FileException &)
    SME_CATCH_SETUP  //{
       if (lpszPrivateKeyOut)
           free(lpszPrivateKeyOut);
       if (pPrivateKey)
           delete pPrivateKey;
       if (pPublicKeyAlg)
           delete pPublicKeyAlg;
       if (pszPassword)
           free(pszPassword);
      Exception.push(STACK_ENTRY);
      throw;
    }
   //SFL_CATCH_FINISH2
#ifndef _DEBUG
   catch (...) 
   {
       if (lpszPrivateKeyOut)
           free(lpszPrivateKeyOut);
       if (pPrivateKey)
           delete pPrivateKey;
       if (pPublicKeyAlg)
           delete pPublicKeyAlg;
       if (pszPassword)
           free(pszPassword);
      SME_THROW(33, "Unexpected exception thrown!", NULL);
   }
   //SFL_CATCH_FINISH_END
#endif      //_DEBUG



    return(status);
}        // END SFLFree3PKCS12Init2(...)


}       // END extern "C"

_END_CERT_NAMESPACE

#endif      // SM_FREE3_RSA_INCLUDED



//######################################################
_BEGIN_CERT_NAMESPACE

#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif

#define OIDSafeBag_certBag                "1.2.840.113549.1.12.10.1.3"
#define OIDSafeBag_keyBag                 "1.2.840.113549.1.12.10.1.1"
#define OIDSafeBag_pkcs8ShroudedKeyBag    "1.2.840.113549.1.12.10.1.2"
#define OIDSafeBagContent_x509Certificate "1.2.840.113549.1.9.22.1"

//
//
//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_Free3::GeneratePKCS12PBEKey(CSM_Buffer *pbufSalt, int nIterCount, 
                  int iID, char *pszPassword, AsnOid &o, int nKeyLength, 
                  int lPassword, int lBlockSize, long lRequested)
{
   CSM_Buffer *pK = NULL;
   CSM_Buffer *pKOut = NULL;
   CSM_Buffer *pTemp;
   int nLoop;
   int i;
   long status=0;

   SME_SETUP("CSM_Free3::GeneratePKCS12PBEKey");

   // create the DES key by concatentating bufferSalt onto the password
   // and then digesting the result nIterCount times

     /*if ( o == md5)
     {
          if (nKeyLength > 16)
          {
              SME_THROW(27, "CSM_Free3::GeneratePKCS12PBEKey: bad md5 length", NULL);
          }
     }
     else*/
     if (o == sha_1)
     {
          if (nKeyLength > 20)
          {
              SME_THROW(27, "bad sha1 length2", NULL);
          }
     }
     else
     {
          SME_THROW(27, "Non-supported Hash OID for PKCS12 PBE (ONLY SHA-1)", NULL);
     }

   // check length
   if (lPassword == 0)
     lPassword = strlen(pszPassword);
   //if (lPassword > nKeyLength) //pbufSalt->Length()))
   //   lPassword = nKeyLength; //pbufSalt->Length();

   const char *pSalt=pbufSalt->Access();
   char *pWorkingSalt_Password=(char *)calloc(1, lBlockSize*2);
   char *ptr2=pWorkingSalt_Password;
   char *pID=(char *)calloc(1, lBlockSize);
   memset(pID, iID, lBlockSize);
	for (i = 0; i < lBlockSize; i++) *ptr2++ = pSalt[i % pbufSalt->Length()];
    // JAS: only do this if password is non-empty, else leave clear.
    if (lPassword)
      for (i = 0; i < lBlockSize; i++) *ptr2++ = pszPassword[i % lPassword];
   if ((pKOut = new CSM_Buffer) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);

	for (;;) 
   {
      if ((pK = new CSM_Buffer) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);

      // PRE-INIT hash for PKCS12 PBE.
      SME(pK->Open(SM_FOPEN_WRITE));
      SME(pK->Write(pID, lBlockSize)); 
      SME(pK->Write(pWorkingSalt_Password, lBlockSize*2)); 
      pK->Close();

      for (nLoop = 0; nLoop < nIterCount; nLoop++)
      {
         if ((pTemp = new CSM_Buffer) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY ERROR!", NULL);
         if (o == sha_1)
         {
            SME((status=SMTI_DigestDataSHA1(pK, pTemp)));
         }     // IF o==sha_1
         else
         {
            SME((status=SMTI_DigestDataInternal(pK, pTemp, o)));
         }     // END if o==sha_1
         if (status != 0)
         {
            SME_THROW(SM_MEMORY_ERROR, "SMTI_DigestData alg not supported!", NULL);
         }
         // now, move digest result to K and empty temp
         delete (pK);
         pK = pTemp;
      }     // END for iteration loop

      SME(pKOut->Open(SM_FOPEN_APPEND));
      SME(pKOut->Write(pK->Access(), pK->Length())); 
      pKOut->Close();
  	   if (pKOut->Length() >= lRequested || lRequested == 0/*flag to IGNORE*/) 
      {
         delete pK;
         pK = NULL;
         break;
      }
      else     // IF enough data.
      {
         // Continue hash creation beyong default length
         //  (20 bytes hash ++; Big Integer math)
         long lHashLength=pK->Length(); 
         const char *pHash=pK->Access();
         char *pFinalKey=(char *)calloc(1, lBlockSize);
         int j;
		   for (j = 0; j < lBlockSize; j++) 
            pFinalKey[j] = pHash[j % lHashLength];
         //CryptoPP::ByteQueue binKey;
         //binKey.Put((unsigned char *)pFinalKey, lBlockSize);
                     //RWC;Careful, Big-endian order.
         Integer biKeyKeep(/*binKey*/(const unsigned char *)pFinalKey, lBlockSize/*, 
                        Integer::SIGNED*/);
                  //		Integer(BufferedTransformation &bt, unsigned int byteCount, Signedness s=UNSIGNED);
         /*&char *pTmpWorkingSalt_Password=(char *)calloc(1, lBlockSize*2);
         memcpy(pTmpWorkingSalt_Password, pWorkingSalt_Password, lBlockSize*2);
         for (j=0; j < lBlockSize; j++)      // REVERSE 1st half
            pTmpWorkingSalt_Password[lBlockSize-j-1] = pWorkingSalt_Password[j];
         for (j=0; j < lBlockSize; j++)      // REVERSE 2nd half
            pTmpWorkingSalt_Password[lBlockSize+lBlockSize-j-1] = 
               pWorkingSalt_Password[lBlockSize+j];*/
         biKeyKeep += Integer::One();
         Integer biKey;
		   for (j = 0; j < lBlockSize*2; j+=lBlockSize) 
         {
            biKey = biKeyKeep;
            //CryptoPP::ByteQueue binTmpQue;
            //binTmpQue.Put((unsigned char *)&pTmpWorkingSalt_Password[j], lBlockSize);
            Integer biTmp(/*binTmpQue*/(const unsigned char *)
                 &pWorkingSalt_Password[j], lBlockSize/*, Integer::SIGNED*/);
            biKey += biTmp;
            //RWC; NO CONVENIENT WAY TO GET RAW DATA BACK; must put them in 
            //RWC;  forward, but get them back backwards...
            for (int ii2=0; ii2 < lBlockSize; ii2++)
              pWorkingSalt_Password[j+lBlockSize-ii2-1] = biKey.GetByte(ii2);
                                    // RWC;WATCH OUT FOR "0" padding on MSB.
         }  // END for prep for next computation.
         //RWC;TBD; be sure to copy pTmpWorkingSalt_Password back to pWorkingSalt_Password.
         free(pFinalKey);
         delete(pK);
      }     // END if not enough data.
   }        // END for ;;
   free(pID);                       // Free ONLY at end...
   free(pWorkingSalt_Password);     // Free ONLY at end...

   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH
   
   return pKOut;
}

//////////////////////////////////////////////////////////////////////////
// THIS routine was updated to reflect ONLY PKCS12 decryption.
//  (different ASN.1 definitions from PKCS8, but similar algorithm processing).
long CSM_Free3::DecryptPKCS12PrivateKey(CSM_Buffer *pEncryptedPrivateKeyInfo, 
    const char *pszPassword, CSM_PrivDataLst &PrivList)//CSM_Buffer *pCert)
{
    PFX Pfx;
    EncryptedData *pencryptedData=NULL;
    CSM_Buffer *pencryptedDataBuf;
    SafeContents SeqContentInfos;  // Actually not SafeContents, but
                                    //   convenient definition.
    CSM_BufferLst BufPrivList;
    CSM_BufferLst BufCertList;
    long lStatus=-1;       // Default failure.
#ifdef _DEBUG
    long lStatus2=0;
#endif //_DEBUG


   SME_SETUP("CSM_Free3::DecryptPKCS12PrivateKey");

   // JAS: allow empty password; 19 Mar 2004
   if (pszPassword == NULL) pszPassword = "";
   if (pEncryptedPrivateKeyInfo == NULL)
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMS", NULL);

    DECODE_BUF(&Pfx, pEncryptedPrivateKeyInfo);
    if (Pfx.macData == NULL)
    {
        SME_THROW(SM_UNKNOWN_ERROR, 
                     "optional macData MUST be present (password)", NULL);
    }

    int iter = 1;       // DEFAULT
    if (Pfx.macData->macIterationCount)
        iter = *Pfx.macData->macIterationCount;
    CSM_Buffer bufSalt(Pfx.macData->macSalt.c_str(), Pfx.macData->macSalt.Len());
    CSM_Buffer *pBuf=NULL;
    CSM_Buffer *pBuf2=NULL;
    ENCODE_BUF(&Pfx.authSafe.content, pBuf);/*RWC;11/15/02;.GetUndecodedAny();*/
    if (pBuf)
    {
        AsnOcts SNACCOcts;
        DECODE_BUF(&SNACCOcts, pBuf);
        /****RWC;TMP;****/if (iter == 0) iter = 1;
        pBuf2 = new CSM_Buffer(SNACCOcts.c_str(), SNACCOcts.Len());
        CSM_Buffer *pBufComputedMac = ComputePkcs12MAC(bufSalt, 
                     Pfx.macData->safeMac.digestAlgorithm.algorithm, 
                     pszPassword, *pBuf2, iter);
        CSM_Buffer BufSafeMac(Pfx.macData->safeMac.digest.c_str(), 
            Pfx.macData->safeMac.digest.Len());
        if (pBufComputedMac && *pBufComputedMac != BufSafeMac)
        {
            //RWC;NOTE;I investigated this failure when processing .pfx files 
            //RWC;  from "MakeCert.exe"; IT IS NOT DUE TO BER vs DER encoding;
            //RWC;  the re-encoded result precisely matches the original encoding.
            //RWC;  NEED TO re-visit the MAC comparison logic...
#ifndef _DEBUG
                SME_THROW(30,"macData DOES NOT MATCH computed MAC!!!", NULL);
#else   //_DEBUG
                std::cout << "macData DOES NOT MATCH computed MAC (DEBUG IGNORES)!!!"  << std::endl;
                lStatus2 = -100;
#endif //_DEBUG
        }       // END IF 1st mac value check
        if (pBufComputedMac)
            delete pBufComputedMac;
        delete pBuf;
    }       // END IF pBuf MAC from PKCS12

    if (Pfx.authSafe.contentType == id_data)
    {
        if (pBuf2)
        {
#ifdef _DEBUG
           pBuf2->ConvertMemoryToFile("./tmpSm_free3InternalBuf2.out");
#endif //_DEBUG
           DECODE_BUF(&SeqContentInfos, pBuf2);
           delete pBuf2;
        }
        else            
        {
           SME_THROW(SM_UNKNOWN_ERROR, "Pfx.authSafe->content "
               "ASN.1 decode failure.", NULL);
        }
                        // From our class, should be decoded Octet String.

        SafeContents::iterator itSNACCCSafeBag;
        for (itSNACCCSafeBag = SeqContentInfos.begin();
             itSNACCCSafeBag != SeqContentInfos.end();
             ++itSNACCCSafeBag)
        {
         if (itSNACCCSafeBag->safeBagType == id_encryptedData)
         {
            pencryptedDataBuf = NULL;
            ENCODE_BUF(&itSNACCCSafeBag->safeBagContent, pencryptedDataBuf);
            /*RWC;11/15/02.GetUndecodedAny();
            if (pencryptedDataBuf != NULL)   // THEN decoded...
            {*/
               pencryptedData = new EncryptedData;
               DECODE_BUF(pencryptedData, pencryptedDataBuf);

            if (pencryptedData &&
                pencryptedData->encryptedContentInfo.contentType == id_data)
            {
                    CSM_Buffer *pbufEncryptedKey=NULL;
                    ENCODE_BUF(&pencryptedData->encryptedContentInfo, pbufEncryptedKey);
                    lStatus = DecryptPKCS12Cert( 
                       pbufEncryptedKey, pszPassword, BufPrivList, BufCertList);
                    if (lStatus != 0)
                    {
                       SME_THROW(lStatus, "DecryptPKCS12Cert error", NULL);
                    }      // END if pDecryptedPKCS12Cert.
                    delete pencryptedData;
                    if (pbufEncryptedKey)
                       delete pbufEncryptedKey;
            }
            else
            {
                SME_THROW(SM_UNKNOWN_ERROR, "EncryptedData.encryptedContentInfo"
                    " MUST be id-data", NULL);
            }
            if (pencryptedDataBuf)
               delete pencryptedDataBuf;
         }           // IF id_encryptedData
         else if (itSNACCCSafeBag->safeBagType == id_data)
         {
            /*SignedData *pSNACCSignedData;*/
            CSM_Buffer *pDataBuf = NULL;
            ENCODE_BUF(&itSNACCCSafeBag->safeBagContent, pDataBuf);//RWC;11/15/02;.GetUndecodedAny();
            if (pDataBuf != NULL)   // THEN decoded...
            {
               AsnOcts SNACCOcts;
               DECODE_BUF(&SNACCOcts, pDataBuf);
               pDataBuf->Set(SNACCOcts.c_str(), SNACCOcts.Len());
            }
            else
            {
               SME_THROW(44, "NEED TO ENCODE_BUF!!!!!", NULL);
            }
            if (pDataBuf)
            {
               lStatus = DecryptPKCS12_ProcessBags(*pDataBuf, pszPassword, 
                                                  BufPrivList, BufCertList);
               delete pDataBuf;
            }     // END if pSNACCSignedData

         }           // IF id_data
         else
         {
            SME_THROW(SM_UNKNOWN_ERROR, "MUST be EncryptedData", NULL);
         }
        }      // END FOR each SafeBag.
    }
    else
    {
        SME_THROW(SM_UNKNOWN_ERROR, 
                     "MUST be id-data ContentInfo", NULL);
    }

    // NOW that we have processed the list of potential private keys and certs
    //  align them if necessary.
    if (BufPrivList.size() && BufCertList.size()) // ONLY if at least 1 of each.
    {
       CSM_Buffer   *pBufPublicKeyFromCert;
       if (BufPrivList.size() == 1 && BufCertList.size() == 1)
       {
          CSM_PrivData *pPrivData = &(*PrivList.append());
          pPrivData->m_BufCertList = BufCertList;     //COPY ALL CERTS.
          pPrivData->m_BufPriv = *BufPrivList.begin(); //COPY only priv key.
          lStatus = 0;     // INDICATE at least 1 was matched.
          /*DEBUG CHECK of public/private keys.* /
          CSM_CertificateChoice CertChoice;
          CertChoice.SetEncodedCert(*BufPrivList.FirstL());
          pBufPublicKeyFromCert = CertChoice.GetPublicKey();
          */
       }
       else // IF BufPrivList.CountL() is not 1
       {          // HERE we must align the private key(s) with their 
                  //  respective certs.
          CSM_PrivData *pPrivData;
          CSM_BufferLst::iterator itTmpPriv, itTmpCert;
          CSM_CertificateChoice CertChoice;
          for (itTmpPriv =  BufPrivList.begin(); 
               itTmpPriv != BufPrivList.end();
               ++itTmpPriv)
          {             // FOR each private key, search for a corresponding cert.
             // FIRST determine public key matching this private key!
             for (itTmpCert =  BufCertList.begin(); 
                  itTmpCert != BufCertList.end();
                  ++itTmpCert)
             {             // FOR each private key, search for a corresponding cert.
                CertChoice.SetEncodedCert(*itTmpCert);
                pBufPublicKeyFromCert = CertChoice.GetPublicKey();
                lStatus = DecryptPKCS12_CheckPublicWithPrivate(
                                    *pBufPublicKeyFromCert, *itTmpPriv);
                if (lStatus == 0)
                {
                   pPrivData = &(*PrivList.append());
                   pPrivData->m_BufCertList.append(*itTmpCert);   //COPY.
                                 // BE SURE our EndEntity cert is 1st!!!
                   CSM_BufferLst::iterator itTmpBufP12Cert;
                   for (itTmpBufP12Cert =  BufCertList.begin(); 
                        itTmpBufP12Cert != BufCertList.end();
                        ++itTmpBufP12Cert)
                   {                // ONE is a duplicate, but will not make it
                                    //    into the actual login cert list.
                      pPrivData->m_BufCertList.append(*itTmpBufP12Cert); 
                   }    // END for each PKCS12 cert in list.
                   pPrivData->m_BufPriv = *itTmpPriv;          //COPY only priv key.
                   break;           // STOP checking for matching cert.
                }    // END if pBufPublicKeyFromPrivateKey
                else
                   delete pBufPublicKeyFromCert;
             }    // END for each cert in list.
          }    // END for each private key.
       }    //END if BufPrivList.CountL() == 1
    }    // END if 1 of each.

   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH

#ifdef _DEBUG
   if (lStatus2 != 0 && lStatus == 0)        // SUCCESSFUL except for the MAC check...
       lStatus = lStatus2;
#endif // _DEBUG

   return lStatus;
}     // END CSM_Free3::DecryptPKCS12PrivateKey(...)


//////////////////////////////////////////////////////////////////////////
//
long CSM_Free3::DecryptPKCS12_CheckPublicWithPrivate(
      CSM_Buffer &BufCheckPublic, CSM_Buffer &BufPrivateKey)
{
   Integer      *px;         // x value in integer form
   long lStatus=-1;
   CSM_Buffer *pBufRawPrivateKey;
   CSM_Buffer BufDerivedPublicKey;
   PrivateKeyInfo snaccX;
   char b[8192];
   int nLen;
   //RWC;CSM_SFLDSAPrivateKey *pdsaX=NULL;
   DSAPrivateKey *pdsaX=NULL;
   CryptoPP::Integer *pintDSAY;
   CryptoPP::Integer paramDSAP;
   CryptoPP::Integer paramDSAQ;
   CryptoPP::Integer paramDSAG;
   CryptoPP::ByteQueue  byteQueueBuffer;

   SME_SETUP("CSM_Free3::DecryptPKCS12_CheckPublicWithPrivate");

   // ASN.1 decode the private key
   DECODE_BUF(&snaccX, &BufPrivateKey);

   if (snaccX.privateKeyAlgorithm.algorithm ==  id_dsa_with_sha1 ||
       snaccX.privateKeyAlgorithm.algorithm ==  id_dsa)
   {
       pintDSAY = sm_Free3CryptoppBERDecode(BufCheckPublic.Access(), 
          BufCheckPublic.Length());
       //DSAPublicKey dsaY(*pP, *pQ, *pG, *py);

       pBufRawPrivateKey = new CSM_Buffer(snaccX.privateKey.c_str(), 
            snaccX.privateKey.Len());
       FREE_DSAParameters snaccDSAParams;
       DECODE_ANY(&snaccDSAParams, snaccX.privateKeyAlgorithm.parameters);
       // extract P
       long lParam = 128;
       if (snaccDSAParams.p.length() <= 64)
          lParam = 64;
       Integer *pTmpBI;
       pTmpBI = ComputeBigInteger(snaccDSAParams.p, lParam);
       paramDSAP = *pTmpBI; //RWC;.Decode(pbyte, snaccDSAParams.p.Len());
       delete pTmpBI;
       pTmpBI = ComputeBigInteger(snaccDSAParams.q, 20);
       paramDSAQ = *pTmpBI; //RWC;.Decode(pbyte, snaccDSAParams.q.Len());
       delete pTmpBI;
       pTmpBI = ComputeBigInteger(snaccDSAParams.g, lParam);
       paramDSAG = *pTmpBI; //RWC;.Decode(pbyte, snaccDSAParams.g.Len());
       delete pTmpBI;

       px = sm_Free3CryptoppBERDecode(pBufRawPrivateKey->Access(), pBufRawPrivateKey->Length());
       if (px && pintDSAY)
       {
          //RWC;pdsaX = new CSM_SFLDSAPrivateKey(paramDSAP, paramDSAQ, paramDSAG, *pintDSAY, *px);
          pdsaX = new DSAPrivateKey;
          pdsaX->AccessKey().Initialize(paramDSAP, paramDSAQ, paramDSAG, *px);
          CryptoPP::DSA::Verifier dsaPub(*pdsaX);
          dsaPub.DEREncode(byteQueueBuffer); 
          nLen = byteQueueBuffer.Get((unsigned char *)&b[0], 8192);
          BufDerivedPublicKey.Set((char *)(&b[0]), nLen);
          SubjectPublicKeyInfo snaccPKI;
          DECODE_BUF(&snaccPKI, &BufDerivedPublicKey);
          BufDerivedPublicKey.Set((const char *)snaccPKI.subjectPublicKey.data(), 
                                  snaccPKI.subjectPublicKey.length());   
                                  // RE-use buffer.
          if (BufDerivedPublicKey == BufCheckPublic)
              lStatus = 0;
       }

       if (pBufRawPrivateKey)
          delete pBufRawPrivateKey;
       if (px)
          delete px;        // Destroy Integer after load.
       if (pintDSAY)
          delete pintDSAY;

   }     // IF id_dsa
   else if (snaccX.privateKeyAlgorithm.algorithm ==  rsaEncryption ||
            snaccX.privateKeyAlgorithm.algorithm ==  rsa)
   {
      CryptoPP::ByteQueue ByteQue_privateKey;
      ByteQue_privateKey.Put((unsigned char *)BufPrivateKey.Access(), 
                                              BufPrivateKey.Length());
      RSASSA_PKCS1v15_SHA_Signer rsaPriv(ByteQue_privateKey);
      RSASSA_PKCS1v15_SHA_Verifier rsaPub(rsaPriv);
      rsaPub.DEREncode(byteQueueBuffer); 
      nLen = byteQueueBuffer.Get((unsigned char *)&b[0], 8192);
      BufDerivedPublicKey.Set((char *)(&b[0]), nLen);
      SubjectPublicKeyInfo snaccPKI;
      DECODE_BUF(&snaccPKI, &BufDerivedPublicKey);
      BufDerivedPublicKey.Set((const char *)snaccPKI.subjectPublicKey.data(), 
                              snaccPKI.subjectPublicKey.length());   
                              // RE-use buffer.
      if (BufDerivedPublicKey == BufCheckPublic)
          lStatus = 0;
   }     // IF rsa
   else
   {
      char pBuf[2048];
      sprintf(&pBuf[0], "privateKeyAlgorithm not supported, %s.", 
         snaccX.privateKeyAlgorithm.algorithm.GetChar());
      SME_THROW(27, pBuf, NULL);
   }     //END if dsa OR rsa

   SME_FINISH
   SME_CATCH_SETUP  // {
      lStatus = -1;
#ifdef WIN32
      Exception;        // removes compiler warning.
#endif // WIN32
      //const char *ptr=Exception.what();      //IGNORE error.
      // DO NOT THROW AN EXCEPTION HERE, just allow a return of an error.
   }     // END exception processing.
   //SME_FREE3_CATCH_FINISH

    return(lStatus);
}     // END DecryptPKCS12_GetPublicFromPrivate(...)

//////////////////////////////////////////////////////////////////////////
//
long CSM_Free3::DecryptPKCS12Cert(CSM_Buffer *pEncryptedPrivateKeyInfo, 
   const char *pszPasswordIn, CSM_BufferLst &BufPrivList, CSM_BufferLst &BufCertList)
{
   long lStatus=0;
   PBEParameter snaccEncryptionParams;
   AsnOid oidHash;
   long status=0;
   EncryptedContentInfo snaccEncryptedCI;
   CSM_Buffer *pbufEncodedPrivateKey=NULL;

   SME_SETUP("CSM_Free3::DecryptPKCS12Cert");

   if ((pEncryptedPrivateKeyInfo == NULL) || (pszPasswordIn == NULL))
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMS", NULL);

   // ASN.1 decode the EncryptedPrivateKeyInfo
   DECODE_BUF(&snaccEncryptedCI, pEncryptedPrivateKeyInfo);
   CSM_Buffer bufEncryptedKey(snaccEncryptedCI.encryptedContent->c_str(),
            snaccEncryptedCI.encryptedContent->Len());

#ifdef _DEBUG
   bufEncryptedKey.ConvertMemoryToFile("./tmpSm_free3InternalBuf3.out");
#endif
   pbufEncodedPrivateKey = DecryptPKCS12Blob(pszPasswordIn, 
         snaccEncryptedCI.contentEncryptionAlgorithm, bufEncryptedKey);
    //RWC;11/28/02;TBD; BAD DATA RETURNED, 1st buffer good, later bad?????
   //BROKEN!!!!
   if (pbufEncodedPrivateKey)
   {
#ifdef _DEBUG
       pbufEncodedPrivateKey->ConvertMemoryToFile("./tmpSm_free3InternalBuf4.out");
#endif
      // for debug only - to be taken out
      /*#ifdef _DEBUG
      pbufEncodedPrivateKey->ConvertMemoryToFile("./decryptedPrivateKey.log");
      #endif*/

      status = DecryptPKCS12_ProcessBags(*pbufEncodedPrivateKey, pszPasswordIn, 
         BufPrivList, BufCertList);

      delete pbufEncodedPrivateKey;

   }     // END IF pbufEncodedPrivateKey

   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH

   return lStatus;
}


//////////////////////////////////////////////////////////////////////////
// RETURNS decrypted Blob.
CSM_Buffer *CSM_Free3::DecryptPKCS12Blob(const char *pszPasswordIn, 
   AlgorithmIdentifier &EncryptionAlgorithm, CSM_Buffer &bufEncryptedKey)
{
   PBEParameter snaccEncryptionParams;
   RC2Decryption *pRC2Decryption = NULL;
   DESDecryption *pDESDecryption = NULL;
   DES_EDE3_Decryption *p3DESDecryption = NULL;
   CSM_Buffer *pbufEncodedEncryptionParams = NULL;
   CSM_Buffer *pK = NULL;
   CSM_Buffer *pIV = NULL;
   CBCPaddedDecryptor *cbc_decryption=NULL;
   int blocksize = 0;
   AsnOid oidHash;
   int iLength = 20;
   int iPBEKeyBits=SM_FREE_RC2_DEFAULT_PBE_KEYBITS;
   EncryptedContentInfo snaccEncryptedCI;
   long lRequestedLength=0;
   CSM_Buffer *pbufOut=NULL;
   char *pszPassword=NULL;
  
   SME_SETUP("CSM_Free3::DecryptPKCS12Blob");
  
    // JAS: allow empty password.
    long lPassword2;
    if (pszPasswordIn == NULL || !*pszPasswordIn)
    {
      lPassword2  = 2;
      pszPassword = (char *)calloc(1, 2);
    }
    else
    {
      // Create Unicode, null-terminated string.
      lPassword2=(strlen(pszPasswordIn)+1)*2;
      pszPassword=(char *)calloc(1, lPassword2);
      for (int iii=0; iii < strlen(pszPasswordIn); iii++)
          pszPassword[iii*2+1] = pszPasswordIn[iii];
    }

   if (EncryptionAlgorithm.algorithm != pbewithSHAAnd40BitRC2_CBC &&
       EncryptionAlgorithm.algorithm != pbeWithSHAAnd3_KeyTripleDES_CBC)
   {
      SME_THROW(33, "EncryptionAlgorithm not supported, ONLY pbewithSHAAnd40BitRC2_CBC.", NULL);
   }

   // extract the encryption algorithm parameters and asn.1 decode them
   SM_EXTRACT_ANYBUF(pbufEncodedEncryptionParams, 
         EncryptionAlgorithm.parameters);
   DECODE_BUF((&snaccEncryptionParams), pbufEncodedEncryptionParams);

   delete pbufEncodedEncryptionParams;
   pbufEncodedEncryptionParams = NULL;

   int nIterCount = snaccEncryptionParams.iterationCount;
   CSM_Buffer bufSalt(snaccEncryptionParams.salt.c_str(), 
         snaccEncryptionParams.salt.Len());

   if (EncryptionAlgorithm.algorithm == pbewithSHAAnd40BitRC2_CBC ||
       EncryptionAlgorithm.algorithm == pbeWithSHAAnd3_KeyTripleDES_CBC)
   {
       oidHash = sha_1;
       iLength = 20;
       blocksize = SM_COMMON_RC2_BLOCKSIZE;//iPBEKeyBits/8;
       if (EncryptionAlgorithm.algorithm == pbeWithSHAAnd3_KeyTripleDES_CBC)
          lRequestedLength = 24;    // MUST request larger value since SHA-1
                                    //  only provides 20 bytes...
      // generate the key using the salt, the iteration count, and the password
      SME(pK = GeneratePKCS12PBEKey(&bufSalt, nIterCount, 0x01, pszPassword, 
               oidHash, iLength, lPassword2, 0x40, lRequestedLength));

      //pK->SetLength(3); // SET only necessary key length.
      SME(pIV = GeneratePKCS12PBEKey(&bufSalt, nIterCount, 0x02, pszPassword, 
               oidHash, iLength, lPassword2, 0x40));
   }
   else
   {
      SME_THROW(22, "EncryptionAlgorithm not recognized!", NULL);
   }

   if (EncryptionAlgorithm.algorithm == pbewithSHAAnd40BitRC2_CBC)
   {
      iPBEKeyBits = 40;
      // create the rc2 cipher 
      pRC2Decryption = new RC2Decryption ((const unsigned char*)pK->Access(),
         (iPBEKeyBits/8), iPBEKeyBits);
 
      // create cbc object
      if (pIV == NULL)
         pIV = pK;
      cbc_decryption = new CBCPaddedDecryptor(*pRC2Decryption, 
         (const unsigned char *)pIV->Access());
   }
   else if (EncryptionAlgorithm.algorithm == pbeWithSHAAnd3_KeyTripleDES_CBC)
   {
      // create the 3DES cipher 
      /*char pKPBits[24];
      memcpy(pKPBits, pK->Access(), 20);
      memset(&pKPBits[20], '\0', 4);
      memcpy(&pKPBits[8], pK->Access(), 8);
      memcpy(&pKPBits[16], pK->Access(), 8);
      for (int iii=0; iii < 24; iii++)
         pKPBits[iii] = (p_pK[iii/8] & (1 << (iii % 8)));
         / * if (p_pK[iii/8] & (1 << (iii % 8)))
            pKPBits[iii] = 1;
         else
            pKPBits[iii] = 0;*/


      // BE SURE TO ADJUST THE PARITY!!!!!!
      unsigned char *ptr3=(unsigned char *)calloc(1, pK->Length());
      memcpy(ptr3, pK->Access(), pK->Length());
      for (int iii=0; iii < 24; iii++)
      {
         if (!CryptoPP::Parity((unsigned long)ptr3[iii]))
            ptr3[iii] ^= 0x01;
      }

      p3DESDecryption = new DES_EDE3_Decryption ((const unsigned char*)/*pKPBits*/ptr3/*pK->Access()*/);
      free(ptr3);

      // create cbc object
      if (pIV == NULL)
          pIV = pK;
      cbc_decryption = new CBCPaddedDecryptor(*p3DESDecryption, 
         (const unsigned char *)pIV->Access());
   }

   pbufOut=new CSM_Buffer;

   SME(RawDecrypt(&bufEncryptedKey, pbufOut, cbc_decryption, blocksize));
   if (pbufOut->Length() == 0)
   {
      delete pbufOut;
      pbufOut = NULL;      // FLAG missing or bad.
   }

   /*pbufOut->ConvertMemoryToFile("./decryptedBlob.log");*/

   if (pszPassword)
      free(pszPassword);
   if (pK)
      delete pK;
   if (pRC2Decryption)
       delete pRC2Decryption;
   if (pDESDecryption)
       delete pDESDecryption;
   if (p3DESDecryption)
      delete p3DESDecryption;
   if (cbc_decryption)
       delete cbc_decryption;
   if (pIV && pIV != pK)
       delete pIV;

   SME_FINISH
   SME_CATCH_SETUP
      if (pK)
         delete pK;
      if (pbufEncodedEncryptionParams)
         delete pbufEncodedEncryptionParams;
      if (pRC2Decryption)
         delete pRC2Decryption;
      if (pDESDecryption)
         delete pDESDecryption;
      if (p3DESDecryption)
         delete p3DESDecryption;
      if (pIV && pIV != pK)
          delete pIV;
      if (pbufOut)
         delete pbufOut;
      if (pszPassword)
         free(pszPassword);
   SME_FREE3_CATCH_FINISH

   return pbufOut;
}       // END CSM_Free3::DecryptPKCS12Blob(...)

//////////////////////////////////////////////////////////////////////////
//  PROCESS the safeBags ONLY, already un-encrypted.
long CSM_Free3::DecryptPKCS12_ProcessBags(CSM_Buffer &bufEncodedBags, 
         const char *pszPassword, CSM_BufferLst &BufPrivList, 
         CSM_BufferLst &BufCertList)
{
   long status=0;
   SafeContents SafeBags;

   SME_SETUP("CSM_Free3::DecryptPKCS12_ProcessBags");
   // ASN.1 decode the private key
   DECODE_BUF(&SafeBags, &bufEncodedBags);
   SafeContents::iterator itTmpSafeBag;
   AsnOid  oidSafeBag_certBag(OIDSafeBag_certBag);
   AsnOid  oidSafeBag_keyBag(OIDSafeBag_keyBag);
   AsnOid  oidSafeBag_pkcs8ShroudedKeyBag(OIDSafeBag_pkcs8ShroudedKeyBag);
   AsnOid  oidSafeBagContent_x509Certificate(OIDSafeBagContent_x509Certificate);
   for (itTmpSafeBag =  SafeBags.begin(); 
        itTmpSafeBag != SafeBags.end();
        ++itTmpSafeBag)
   {
      if (itTmpSafeBag->safeBagType == oidSafeBag_certBag)
      {
          CertCRLBag *pCertBag=NULL;
          CSM_Buffer *pBuf=NULL;
          ENCODE_BUF(&itTmpSafeBag->safeBagContent, pBuf);//RWC;11/15/02;.GetUndecodedAny();
          CSM_Buffer *pBuf2=NULL;
          if (pBuf)
          {
             pCertBag = new CertCRLBag;
             DECODE_BUF(pCertBag, pBuf);
             delete pBuf;
             pBuf = NULL;
          }

          if (pCertBag->bagId == oidSafeBagContent_x509Certificate)
          {
             ENCODE_BUF(&pCertBag->value, pBuf2);//RWC;11/15/02;.GetUndecodedAny();
             Certificate *pSNACCCert=NULL;
             if (pBuf2)
             {
                VDASafeBlob vDASafeBlob;

                //pBuf2->ConvertMemoryToFile("./CertSafeBag.bin");
                DECODE_BUF(&vDASafeBlob, pBuf2);
                delete pBuf2;
                pBuf2 = &(*BufCertList.append());
                //pBuf2=pCertBag->value.GetUndecodedAny();
                pBuf2->Set(vDASafeBlob.c_str(), vDASafeBlob.Len());
             }
             else    // IF ASN.1 decoded already.
             {
                pBuf2 = &(*BufCertList.append());
                pSNACCCert = (Certificate *)itTmpSafeBag->safeBagContent.value;
                pBuf2 = &(*BufCertList.append());
                ENCODE_BUF(pSNACCCert, pBuf2);
             }    // END if ASN.1 decoded already.

          }    // END if X.509 cert.
          else
          {
             SME_THROW(44, "PKCS12 Cert SafeBag not X.509 format!", NULL);
          }

          if (pCertBag)
          {
             delete pCertBag;
          }    // END if pBuf.
      }        // IF cert Bag.
      else if (itTmpSafeBag->safeBagType == oidSafeBag_keyBag)
      {
          CSM_Buffer *pBuf=NULL;
          ENCODE_BUF(&itTmpSafeBag->safeBagContent, pBuf);//RWC;11/15/02;.GetUndecodedAny();
          if (pBuf == NULL)
          {
             pBuf = new CSM_Buffer;
             ENCODE_BUF(&itTmpSafeBag->safeBagContent, pBuf);
          }    // END if ASN.1 decoded already.
          if (pBuf)
          {
             /**pPrivateBuf->ConvertMemoryToFile("./pPrivateKeyBuf.bin");*/
             PrivateKeyInfo snaccX;       //DEBUG
             CSM_Buffer *pBUF2 = &(*BufPrivList.append());  //Thank you Alan Borland, Protek
             *pBUF2 = *pBuf;                            //Thank you Alan Borland, Protek
             DECODE_BUF(&snaccX, pBUF2);   //DEBUG
             delete pBuf;

          }    // END if pBuf
      }
      else if (itTmpSafeBag->safeBagType == oidSafeBag_pkcs8ShroudedKeyBag)
      {                    //M_PKCS12_decrypt_skey
          CSM_Buffer *pBuf=NULL;
          ENCODE_BUF(&itTmpSafeBag->safeBagContent, pBuf);
          //RWC;DOES NOT WORK;
          //RWC; CSM_Buffer *pPrivateBuf = this->DecryptPrivateKey(pszPassword, pBuf);
          EncryptedPrivateKeyInfo snaccEncryptedX;
          // ASN.1 decode the EncryptedPrivateKeyInfo
          DECODE_BUF(&snaccEncryptedX, pBuf);
          CSM_Buffer bufEncryptedKey(snaccEncryptedX.encryptedData.c_str(),
                  snaccEncryptedX.encryptedData.Len());
          AlgorithmIdentifier DecryptAlgId;
          DecryptAlgId.algorithm = snaccEncryptedX.encryptionAlgorithm.algorithm;
          DecryptAlgId.parameters = snaccEncryptedX.encryptionAlgorithm.parameters;
          CSM_Buffer *pPrivateBuf = DecryptPKCS12Blob(pszPassword, DecryptAlgId
                                       , bufEncryptedKey);
          if (DecryptAlgId.parameters)
             DecryptAlgId.parameters = NULL; 
                              //CLEAR, since given away
          if (pPrivateBuf)
          {
#ifdef _DEBUG
             pPrivateBuf->ConvertMemoryToFile("./pPrivateKeyBuf.bin");
#endif
             /*PrivateKeyInfo snaccX;
               DECODE_BUF(&snaccX, pPrivateBuf);*/
             CSM_Buffer *pBUF2 = &(*BufPrivList.append());
             *pBUF2 = *pPrivateBuf;
             delete pPrivateBuf;
          }
          if (pBuf)
              delete pBuf;
      }
      else
      {
         SME_THROW(44, "PKCS12 SafeBag not supported!", NULL);
      }
   }           // END for each SafeBag.


   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH

   return status;
}        // END CSM_Free3::DecryptPKCS12_ProcessBags(...)

//
//  RETURNS computed MAC, or NULL if error.
CSM_Buffer *CSM_Free3::ComputePkcs12MAC(CSM_Buffer &bufSalt,    // IN/OUT
                                 const AsnOid &OidMac,          // IN
                                 const char *pszPassword,       // IN
                                 const CSM_Buffer &PKCS12Buf,   // IN
                                 const int iter)                // IN, OPTIONAL
{
   CSM_Buffer *pBufMacResult=NULL;

   // **** INITIALIZE Salt if necessary
    if (bufSalt.Length() == 0)
    {
       bufSalt.Set("        ", 8);  // PRE-initialize
       // create lLength random bytes of data
       #ifndef CRYPTOPP_5_0
       rndRandom2.GetBlock((unsigned char *)bufSalt.Access(), 8);
       #else // CRYPTOPP_5_0
       char *p=(char *)bufSalt.Access();
       for (int ii=0; ii < 8; ii++)
           p[ii] = (char)rndRandom.GenerateByte();
       #endif // CRYPTOPP_5_0
       //TEST;memcpy(p, "abcdefgh", 8);                      //RWC;TEST
    }       // END if bufSalt pre-filled

   // **** NOW, Setup password as Unicode string containing trailing '\0'.
   long lPassword2 = (strlen(pszPassword)+1)*2;
   char *pszPasswordMAC=(char *)calloc(1, lPassword2);
   for (int iii=0; iii < strlen(pszPassword); iii++)
        pszPasswordMAC[iii*2+1] = pszPassword[iii]; // MAKE Unicode...

   // **** GENERATE PKCS12 MAC Key
   /*CSM_Buffer *pK = = GeneratePKCS12PBEKey(&bufSalt, 1, / *PKCS12MACID* / 0x03, 
        pszPasswordMAC, Pfx.macData->safeMac.digestAlgorithm, 
        / *MACKEYLENGTH* /20, lPassword2, 0x40, / *MACKEYLENGTH* /20));
   b)	If the PFX PDU is to be authenticated with HMAC, then an SHA-1 
   HMAC is computed on the contents of the Data in T (i.e. excluding the 
   OCTET STRING tag and length bytes).  This is exactly what would be initially
   digested in step 5a) if public-key authentication were being used 
   (FROM pkcs12-v1.doc)*/
        // GENERATE PKCS12 MAC using SHA-1 digest algorithm.
   /* FROM Crypto++ 5.0
     struct PBKDF_TestTuple
     {
	    byte purpose;                   IN OUR CASE, 0x03.
	    unsigned int iterations;        IN OUR CASE, 1
	    const char *hexPassword, *hexSalt, *hexDerivedKey;
     };
        {3, 1, "0073006D006500670000", "3D83C0E4546AC140", "8D967D88F6CAA9D714800AB3D48051D63F73A312"},*/
   //RWC;WRONG;PKCS5_PBKDF2_HMAC<SHA1> pbkdf;
   PKCS12_PBKDF<SHA1> pbkdf;
   //string password, salt; RWC;EXPECTED RESULT IS derivedKey;
		SecByteBlock derived(20);
		pbkdf.GeneralDeriveKey(derived, 20/*?SHOULD BE SAME LENGTH AS SHA-1 LENGTH?*/,
            0x03, (const unsigned char *)pszPasswordMAC ,lPassword2, 
            (const unsigned char *)bufSalt.Access(), bufSalt.Length(), /*iterations*/iter);
        CSM_Buffer BufDerivedKey((const char *)(unsigned char *)derived, derived.size());
        /*In this version of this standard, SHA-1 is used for performing all 
          MACing, and so all MAC keys are 160 bits, 20 bytes. */
		//bool fail = memcmp(derived, derivedKey.data(), derived.size()) != 0;

    pBufMacResult = ComputePkcs12MACHash(OidMac, BufDerivedKey, PKCS12Buf);

    return(pBufMacResult);
}       // END CSM_Free3::ComputePkcs12MAC(...)



//
// RETURNS hash result, given hash OID and input data.
CSM_Buffer *CSM_Free3::ComputePkcs12MACHash(
        const AsnOid &OidMac,          // IN
        const CSM_Buffer &BufKey,      // IN
        const CSM_Buffer &BufText)     // IN
{
    CSM_Buffer *pBufMacResult=NULL;
    int i;
    /**** COMPUTE actual MAC using derived key above, and data parameter
    /*  FROM RFC2104 on HMAC
    We define two fixed and different strings ipad and opad as follows
   (the 'i' and 'o' are mnemonics for inner and outer):
                  ipad = the byte 0x36 repeated B times
                  opad = the byte 0x5C repeated B times.
   To compute HMAC over the data `text' we perform
                    H(K XOR opad, H(K XOR ipad, text))
   Namely,
    (1) append zeros to the end of K to create a B byte string
        (e.g., if K is of length 20 bytes and B=64, then K will be
         appended with 44 zero bytes 0x00)
    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
        (1) with ipad
    (3) append the stream of data 'text' to the B byte string resulting
        from step (2)
    (4) apply H to the stream generated in step (3)
    (5) XOR (bitwise exclusive-OR) the B byte string computed in
        step (1) with opad
    (6) append the H result from step (4) to the B byte string
        resulting from step (5)
    (7) apply H to the stream generated in step (6) and output
        the result
    */
    CSM_Buffer BFirstStage;
    CSM_Buffer B((size_t)64);
    char *ptr=(char *)B.Access();
    const char cIpad=0x36;
    const char cOpad=0x5c;
    // STEP 1-4
    memset(ptr, '\0', 64);   // PAD key with 0's to Data length
    memcpy(ptr, BufKey.Access(), BufKey.Length());
    for (i=0; i < 64; i++)
        ptr[i] ^= cIpad;
    B.Open(SM_FOPEN_APPEND);
    B.Write(BufText.Access(), BufText.Length()); //RWC; might be short if < key length.
    B.Close();
    if (OidMac == sha_1)
        SMTI_DigestDataSHA1(&B, &BFirstStage);  // FROM CSM_Common
    else if (OidMac == md5)
        SMTI_DigestDataInternal(&B, &BFirstStage, (AsnOid &)OidMac);
    // STEP 5+
    B.Alloc((size_t)64);    // RE-SET size of buffer (and buffer itself).
    B.SetLength(64);
    ptr = (char *)B.Access();
    memset(ptr, '\0', 64);
    memcpy(ptr, BufKey.Access(), BufKey.Length());
    for (i=0; i < 64; i++)
        ptr[i] ^= cOpad;
    B.Open(SM_FOPEN_APPEND);
    B.Write(BFirstStage.Access(), BFirstStage.Length());
    B.Close();
    pBufMacResult = new CSM_Buffer;
    if (OidMac == sha_1)
        SMTI_DigestDataSHA1(&B, pBufMacResult);  // FROM CSM_Common
    else if (OidMac == md5)
        SMTI_DigestDataInternal(&B, pBufMacResult, (AsnOid &)OidMac);

    return(pBufMacResult);
}       // END CSM_Free3::ComputePkcs12MACHash(...)




_END_CERT_NAMESPACE


// EOF sm_free3.cpp
