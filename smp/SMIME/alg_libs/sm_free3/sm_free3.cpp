
////////////////////////////////////////////////////////////////////////////////
//
// File:  sm_free.cpp
//
// Project:  Crypto++ Crypto Token Interface Library (CTIL), aka SM_Free3
//
// Contents:  This CTI Library implements DSA, 3DES, AES, and DH using
//            crypto++ and AES. It will inherit SHA1 from the sm_common 
//            CTI.  
//
// Author:  Robert.Colestock@getronicsgov.com
//           Sue Beauchamp <Sue.Beauchamp@it.baesystems.com> 
//  
// Last Updated:	16 December 2004
//                Req Ref:  SMP RTM #5
// 
////////////////////////////////////////////////////////////////////////////////

#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#include <process.h>
#include <winsock2.h>
#elif defined(SunOS) || defined (SOLARIS)
#include <unistd.h>
#include <arpa/inet.h>
#elif defined(Linux) || defined (SCO_SV) || defined (HPUX) || defined (HPUX32)
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include "sm_free3.h"
#include "sm_cms.h"
#include "rsa.h"     // From cryptopp3.
#include "rc2.h"     // From cryptopp3.
#include "eccrypto.h"
#include "ecp.h"
#include "ec2n.h"
#include "aes.h"         // for AES processing from cryptopp
#include "sm_aes_wrap.h" // for AES key wrapping functionality
#include "sm_free3_asn.h"
#include "sm_apiCert.h"
#include "sm_AppLogin.h"
#include "sm_common.h"
#include "pwdbased.h"
#include "randpool.h"
RandomPool rndRandom;


_BEGIN_CERT_NAMESPACE
using namespace SNACC;


//#define RC2BSAFE_TEST  // define to disable free rc2 library definitions
//END RWC;TMP
extern "C" {
#ifdef OPENSSL_PKCS12_ENABLED
#include "SFLpkcs12_support.h"
long SFLFree3PKCS12Init(CSM_CtilMgr &Csmime, char *pszPassword, char *pszPFXFile,
                        CSM_MsgCertCrls *pCertPathIN);
#endif
long SFLFree3PKCS12Init2(CSM_CtilMgr &Csmime, char *pszPassword, 
                         char *pszPFXFile, CSM_MsgCertCrls *pCertPath);
}
#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_Login(void)
{
   // TBD, anything useful to do here?
   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_Sign(
            CSM_Buffer *pData, // input, data to be signed
            CSM_Buffer *pEncryptedDigest, // signature output
            CSM_Buffer *pDigest) // digest
{
   CSM_Buffer          *pbufX = NULL; // temp spot for X value
   char                *pszPassword = NULL; // temp spot for password
   Integer             *px;                 // x value in integer form
   AsnOid             *pSigOID=NULL;
   AsnOid             *pDigOID=NULL;
   CryptoPP::ByteQueue privateKey;
   CSM_Buffer          bufferDigest;
   CSM_Buffer          *pTempDigest = &bufferDigest;
   CSM_Buffer          tmpEncryptedDigest;
   DigestInfo          rsaDigestInfo;
   CSM_Buffer          *pTempBuf = NULL;
   char *signature=NULL;
   pSigOID=GetPrefDigestEncryption();
   pDigOID=GetPrefDigest();

   SME_SETUP("CSM_Free3::SMTI_Sign");

   m_ThreadLock.threadLock();
   if ((pData == NULL) || (pEncryptedDigest == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL)

   // if pDigest was passed in, use it, otherwise, use local temp
   if (pDigest != NULL)
      pTempDigest = pDigest;

   // digest the incoming data
   if (pTempDigest == NULL || !pTempDigest->Length())
   {
        SME(CSM_Free3::SMTI_DigestData(pData, pTempDigest)); 
   }

   // prep the crypto++ DSA/RSA private key
   SME(pszPassword = GetPassword());
   SME(pbufX = DecryptPrivateKey(pszPassword, m_pX));
/*
#ifdef BOB_DEBUG
   pbufX->ConvertMemoryToFile("./PrivateKey.bin");
#endif //BOB_DEBUG*/

   if (*pSigOID ==  id_dsa_with_sha1 ||
       *pSigOID ==  id_dsa)
   {
      px = sm_Free3CryptoppBERDecode(pbufX->Access(), pbufX->Length());
      //RWC;1/23/00;x.BERDecode(pbyte);

      // m_DSAP, m_DSAQ, m_DSAG all come from the cert
      // m_DSAY comes from the cert, is not really necessary for this operation
      #ifndef CRYPTOPP_5_0
      DSAPrivateKey dsaX(m_DSAP, m_DSAQ, m_DSAG, m_DSAY, *px);
      #else // CRYPTOPP_5_0
      DSAPrivateKey dsaX(m_DSAP, m_DSAQ, m_DSAG, /*RWC;m_DSAY,*/ *px);
      #endif // CRYPTOPP_5_0
      delete px;        // Destroy Integer after load.

      // sign
      tmpEncryptedDigest.Open(SM_FOPEN_WRITE);
      char *pch = tmpEncryptedDigest.Alloc(SM_FREE_DSA_SIG_LEN);
      //RWC; updated "dsaX.Sign(...)" to"SignDigest(...)".
#ifndef CRYPTOPP_5_0
      dsaX.SignDigest(*m_pRng, (const byte *)pTempDigest->Access(),
            (unsigned int)pTempDigest->Length(), (unsigned char *)pch);
#else // CRYPTOPP_5_0
#ifdef CRYPTOPP_5_1
	   dsaX.SignMessage(*m_pRng, (const byte *)pData->Access(),
            (unsigned int)pData->Length(), (unsigned char *)pch);
#else  // CRYPTOPP_5_1
       dsaX.AccessDigestSignatureScheme().SignDigest
          (*m_pRng, (const byte *)pTempDigest->Access(),
            (unsigned int)pTempDigest->Length(), (unsigned char *)pch);
#endif  // CRYPTOPP_5_1
        #ifdef _DEBUG_NOT_PRINTED
         DSAPublicKey dsaPub(dsaX);
         bool bVer2=dsaPub.VerifyMessage((byte *)pData->Access(), 
             (unsigned int)pData->Length(), (unsigned char *)pch);
          ByteQueue bt2;
          dsaPub.AccessPublicKey().Save(bt2);
          unsigned char ppp[2048]; 
          int len=bt2.Get(ppp, 2048); 
          CSM_Buffer bufPublicKey((char *)ppp, len);
          bufPublicKey.ConvertMemoryToFile("./dsaPub_ForSigning.bin");
          Integer intPrivateKey = dsaX.AccessKey().GetPrivateExponent();
          ByteQueue bt3;
          intPrivateKey.DEREncode(bt3);
          len = bt3.Get(ppp, 2048); 
          CSM_Buffer bufPrivateKey((char *)ppp, len);
          bufPrivateKey.ConvertMemoryToFile("./dsaX.bin");
        #endif // _DEBUG_NOT_PRINTED
#endif // CRYPTOPP_5_0
      // now, pch has the signature, flush and close
      tmpEncryptedDigest.Flush();
      tmpEncryptedDigest.Close();
#ifdef FORTEZZA_DSA_VERSION
      *pEncryptedDigest = tmpEncryptedDigest;
#else
      // RWC; NOW SPLIT the signature into 2 values r=20 bytes, s=20bytes
      // RWC;  and encode them for DSA signatures accroding to PKIX.
      AsnInt bufR;
      AsnInt bufS;
      bufR.Set((unsigned char *)tmpEncryptedDigest.Access(), 
         tmpEncryptedDigest.Length()/2, true);
      bufS.Set((unsigned char *)&tmpEncryptedDigest.Access()
         [tmpEncryptedDigest.Length()/2], 
          tmpEncryptedDigest.Length()/2, true);
      Dss_Sig_Value SNACCDSA_r_s;   // in sm_free3_asn.asn
      SNACCDSA_r_s.r = bufR;
      SNACCDSA_r_s.s = bufS;
      ENCODE_BUF_NO_ALLOC(&SNACCDSA_r_s, pEncryptedDigest);
#endif          // FORTEZZA_DSA_VERSION
   }   
#ifdef SM_FREE3_RSA_INCLUDED
   else if ((*pSigOID == rsa && *pDigOID == sha_1) ||
             *pSigOID == rsaEncryption ||
            *pSigOID == sha_1WithRSAEncryption ||
            *pSigOID == sha_1WithRSAEncryption_ALT ||
            *pSigOID == md5WithRSAEncryption ||
            *pSigOID == AsnOid("1.2.840.113549.1.2") ) // bsafe rsa encryption oid
   {   
      // get the rsa private key into a crypto bytequeue
      // prepare the bytequeue with the RSA private key associated with  
      // the public key used to sign.
      privateKey.Put((unsigned char *)pbufX->Access(), pbufX->Length());
      if (*pSigOID == sha_1WithRSAEncryption ||
          *pDigOID == sha_1WithRSAEncryption ||
          *pSigOID == sha_1WithRSAEncryption_ALT ||
         (*pSigOID == AsnOid("1.2.840.113549.1.2") && *pDigOID == sha_1) ||
         (*pSigOID == rsaEncryption  && *pDigOID == sha_1))
      {
         // prepare the DigestInfo object with null parameters
         rsaDigestInfo.digestAlgorithm.algorithm = sha_1;
         CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm);
         rsaDigestInfo.digest.Set(pTempDigest->Access(), pTempDigest->Length());
         ENCODE_BUF(&rsaDigestInfo,pTempBuf);

         // NOTE:  RSASSA_PKCS1v15_SHA_Signer needs a BufferedTransformation object
         // a ByteQueue is used for simple buffering into one of these objects
         // Prepare input into a bufferedTransformation object for digesting
         // bufferedTransformation objects may assume that pointers to input
         // and output blocks are aligned on 32 bit boundaries
         RSASSA_PKCS1v15_SHA_Signer rsaPriv(privateKey);

         // get memory for the signature
         signature = (char *)calloc(1, rsaPriv.SignatureLength());

         // Use the digested data for signing
#ifndef CRYPTOPP_5_0
         SME(rsaPriv.SignDigest
             (*m_pRng, (const byte *)pTempBuf->Access(),
            (unsigned int)pTempBuf->Length(), (unsigned char *)signature));
#else  // CRYPTOPP_5_0
#ifdef CRYPTOPP_5_1
	     rsaPriv.SignMessage(*m_pRng, (const byte *)pData->Access(),
            (unsigned int)pData->Length(), (unsigned char *)signature);
#else  // CRYPTOPP_5_1
         rsaPriv.AccessDigestSignatureScheme().SignDigest
             (*m_pRng, (const byte *)pTempBuf->Access(),
            (unsigned int)pTempBuf->Length(), (unsigned char *)signature);
#endif  // CRYPTOPP_5_1
        #if defined(_DEBUG) && defined(CYRPTOPP_5_1)
         RSASSA_PKCS1v15_SHA_Verifier rsaPub(rsaPriv);
         bool bVer2=rsaPub.VerifyMessage((byte *)pData->Access(), 
             (unsigned int)pData->Length(), (unsigned char *)signature,
             rsaPub.SignatureLength());
        #endif // _DEBUG
#endif // CRYPTOPP_5_0

         // set the length of the signature
         pEncryptedDigest->Set(signature, rsaPriv.SignatureLength()); 
         free(signature);
      } 
      else if (*pSigOID == md5WithRSAEncryption || 
          *pDigOID == md5WithRSAEncryption || 
         (*pSigOID == rsa && *pDigOID == md5) ||
         (*pSigOID == AsnOid("1.2.840.113549.1.2") && *pDigOID == md5) ||
         (*pSigOID == rsaEncryption  && *pDigOID == md5))
      {
         // prepare the DigestInfo object with null parameters
         rsaDigestInfo.digestAlgorithm.algorithm = md5;
         CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm);
         rsaDigestInfo.digest.Set(pTempDigest->Access(), pTempDigest->Length());
         ENCODE_BUF(&rsaDigestInfo,pTempBuf);

         // RWC;##########################################################

         // NOTE:  RSASSA_PKCS1v15_SHA_Signer needs a BufferedTransformation object
         // a ByteQueue is used for simple buffering into one of these objects
         // Prepare input into a bufferedTransformation object for digesting
         // bufferedTransformation objects may assume that pointers to input
         // and output blocks are aligned on 32 bit boundaries
         RSASSA_PKCS1v15_MD5_Signer rsaPriv(privateKey);

         // get memory for the signature
         char *signature = (char *)calloc(1, rsaPriv.SignatureLength());

         // Use the digested data for signing
#ifndef CRYPTOPP_5_0
         SME(rsaPriv.SignDigest(*m_pRng, (const byte *)pTempBuf->Access(),
            (unsigned int)pTempBuf->Length(), (unsigned char *)signature));
#else  // CRYPTOPP_5_0
#ifdef CRYPTOPP_5_1
         SME(rsaPriv.SignMessage(*m_pRng, (const byte *)pData->Access(),
            (unsigned int)pData->Length(), (unsigned char *)signature));
#else // CRYPTOPP_5_1
         SME(rsaPriv.AccessDigestSignatureScheme().SignDigest(*m_pRng, (const byte *)pTempBuf->Access(),
            (unsigned int)pTempBuf->Length(), (unsigned char *)signature));
#endif // CRYPTOPP_5_1
#endif // CRYPTOPP_5_0

         // set the length of the signature
         pEncryptedDigest->Set(signature, rsaPriv.SignatureLength()); 
         free(signature);

      }
      else
      {
          char *ptr=pSigOID->GetChar();
          if (ptr) free(ptr);
          ptr=pDigOID->GetChar();
          if (ptr) free(ptr);
          SME_THROW(22, "RSA OID Unknown or Not Handled Yet!", NULL);
      }

      if (pTempBuf)
         delete pTempBuf;

   }        // IF processing RSA
#ifdef CRYPTOPP_5_1
   else if (*pSigOID == id_ecPublicKey ||
            *pSigOID == id_ecdsa_with_SHA384 ||
            *pSigOID == gECDSA_SHA1_OID)
   {
      ECIES<ECP>::Decryptor  *pcprivECP2 = NULL;
      ECIES<EC2N>::Decryptor *pcprivEC2N = NULL;
      ECDSA<ECP, SHA>::Signer *psprivECP2=NULL;
      ECDSA<ECP, SHA384>::Signer *pspriv_SHA384_ECP2=NULL;
      ECDSA<EC2N, SHA>::Signer *psprivEC2N=NULL;
      ECDSA<EC2N, SHA384>::Signer *pspriv_SHA384_EC2N=NULL;

      //if (m_pECParams && m_pX)
      if (m_pX)
		{
        // prep the crypto++ DSA/RSA private key
        char *pch;
        char *pszPassword = GetPassword();
        CSM_Buffer *pbufX = DecryptPrivateKey(pszPassword, m_pX);
        CryptoPP::ByteQueue bt5;
        bt5.Put((unsigned char *)pbufX->Access(), pbufX->Length());
        bool bECPFlag = true;        // ASSUME ECP type for encoded params (may not be true).
        try {
           pcprivECP2 = new ECIES<ECP>::Decryptor(bt5);
        }       // END try
        catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
        if (bECPFlag)               // PROCESS ECP private key...
        {
            tmpEncryptedDigest.Open(SM_FOPEN_WRITE);
            // NOW, create the signed result with the new signer private key.            
            if (*pSigOID != id_ecdsa_with_SHA384)
            {
                psprivECP2 = new ECDSA<ECP, SHA>::Signer(*pcprivECP2);
				pch = tmpEncryptedDigest.Alloc(psprivECP2->SignatureLength());
                psprivECP2->SignMessage(rndRandom, (byte *)pData->Access(), 
                    (unsigned int) pData->Length(), (unsigned char *) pch);
            }   // IF != SHA384
            else
            {
                pspriv_SHA384_ECP2 = new ECDSA<ECP, SHA384>::Signer(*pcprivECP2);
				pch = tmpEncryptedDigest.Alloc(pspriv_SHA384_ECP2->SignatureLength());
                pspriv_SHA384_ECP2->SignMessage(rndRandom, (byte *)pData->Access(), 
                    (unsigned int) pData->Length(), (unsigned char *) pch);
            }   // END IF SHA384
            tmpEncryptedDigest.Flush();
            tmpEncryptedDigest.Close();

				AsnInt bufR;
				AsnInt bufS;
				bufR.Set((unsigned char *)pch, tmpEncryptedDigest.Length()/2, true);
				bufS.Set((unsigned char *)&pch[tmpEncryptedDigest.Length()/2], 
				   tmpEncryptedDigest.Length()/2, true);

				ECDSA_Sig_Value SNACCECDSA_r_s;   // in sm_free3_asn.asn
				SNACCECDSA_r_s.r = bufR;
				SNACCECDSA_r_s.s = bufS;
				ENCODE_BUF_NO_ALLOC(&SNACCECDSA_r_s, pEncryptedDigest);
        }
        else                         // NOW, attempt EC2N ONLY if ECP fails.
        {                            //  (if EC2N fails, the failure is fatal!)
            CryptoPP::ByteQueue bt6;
            tmpEncryptedDigest.Open(SM_FOPEN_WRITE);
            //((char *)pbufX->Access())[0] = 'a'; //FORCE TO EXCEPTION IN CryptoPP
            bt6.Put((unsigned char *)pbufX->Access(), pbufX->Length());
            pcprivEC2N = new ECIES<EC2N>::Decryptor(/*rndRandom);,*/ bt6);

            // NOW, create the signed result with the new signer private key.            
            if (*pSigOID != id_ecdsa_with_SHA384)
            {
                psprivEC2N = new ECDSA<EC2N, SHA>::Signer(*pcprivEC2N);
                pch = tmpEncryptedDigest.Alloc(psprivEC2N->SignatureLength());
                psprivEC2N->SignMessage(rndRandom, (const byte *)pData->Access(),
                    (unsigned int)pData->Length(), (unsigned char *)pch);
            }       // IF != SHA384
            else
            {
                pspriv_SHA384_EC2N = new ECDSA<EC2N, SHA384>::Signer(*pcprivEC2N);
                            // ASK EC Signer about signature length...
                pch = tmpEncryptedDigest.Alloc(pspriv_SHA384_EC2N->SignatureLength());
                pspriv_SHA384_EC2N->SignMessage(rndRandom, (const byte *)pData->Access(),
                    (unsigned int)pData->Length(), (unsigned char *)pch);
            }       // END IF SHA384
            tmpEncryptedDigest.Flush();
            tmpEncryptedDigest.Close();

            // NOW, repackage signature result into an ASN.1 encoded format for S/MIME.
			AsnInt bufR;
			AsnInt bufS;
			bufR.Set((unsigned char *)pch, tmpEncryptedDigest.Length()/2, true);
			bufS.Set((unsigned char *)&pch[tmpEncryptedDigest.Length()/2], 
			   tmpEncryptedDigest.Length()/2, true);

			ECDSA_Sig_Value SNACCECDSA_r_s;   // in sm_free3_asn.asn
			SNACCECDSA_r_s.r = bufR;
			SNACCECDSA_r_s.s = bufS;
			ENCODE_BUF_NO_ALLOC(&SNACCECDSA_r_s, pEncryptedDigest);

            // DEBUG ONLY, verify actual result...
            #if defined(_DEBUG)
            if (*pSigOID != id_ecdsa_with_SHA384 && psprivEC2N)
            {
             ECDSA<EC2N, SHA>::Verifier spubEC2N(*psprivEC2N);
             bool bVer2=spubEC2N.VerifyMessage((byte *)pData->Access(), 
                 (unsigned int)pData->Length(), (unsigned char *)pch, 
                 psprivEC2N->SignatureLength());
             //if (!bVer)  THEN ERROR, FAILED...
             /*RWC;ONLY FOR 5.0;bVer2=spubEC2N.AccessDigestSignatureScheme().VerifyDigest
                 ((byte *)pTempDigest->Access(), 
                 (unsigned int)pTempDigest->Length(), (unsigned char *)pch);*/
            }   // END IF != SHA384
            #endif // _DEBUG
        }       // end if !bECPFlag

        // CLEANUP
        if (pcprivEC2N)
            delete pcprivEC2N;
        if (pcprivECP2)
            delete pcprivECP2;
        if (psprivECP2)
            delete psprivECP2;
        if (pspriv_SHA384_ECP2)
            delete pspriv_SHA384_ECP2;
        if (psprivEC2N)
            delete psprivEC2N;
        if (pspriv_SHA384_EC2N)
            delete pspriv_SHA384_EC2N;
        free(pszPassword);
        delete pbufX;
      }     // END IF m_pECParams
   }        // IF Elliptic Curve processing.
#endif  // CRYPTOPP_5_1
   else
      SME_THROW(22, "SigAlg NOT SUPPORTED IN Crypto++ 3 CTIL.\n", NULL);
#else
   else
      SME_THROW(22, "RSA NOT YET SUPPORTED IN Crypto++ 3 CTIL.\n", NULL);
#endif


   
   free (pszPassword);
   delete pbufX;
     if (pSigOID)
        delete pSigOID;

   //RWC;7/13/01;if (pTempDigest && pTempDigest != pDigest)
   //RWC;7/13/01;   delete pTempDigest;  //REMOVED since not dynamic.
   if (pDigOID)
       delete pDigOID;


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      if (pbufX)
         delete pbufX;
      if (pszPassword)
         free (pszPassword);
      if (pSigOID)
         delete pSigOID;
      if (pDigOID)
         delete pDigOID;
      if (signature)
         free(signature);
      m_ThreadLock.threadUnlock();
   SME_FREE3_CATCH_FINISH
   m_ThreadLock.threadUnlock();

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_Verify(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
    const char* _func= "CSM_Free3::SMTI_Verify";
    SM_RET_VAL lRet = SM_NO_ERROR;

    if ((pData == NULL) || (pSignerKey == NULL) || (pSignature == NULL) ||
        (pSignatureAlg == NULL || pDigestAlg == NULL))
        SME_THROW(SM_MISSING_PARAM, "Missing parameter", NULL);

    try {
        m_ThreadLock.threadLock();
        
#ifdef SM_FREE3_RSA_INCLUDED
        AsnOid algOid = pSignatureAlg->algorithm;
        
        // determine rsa or dsa and call appropriate verify routine
        if (algOid == sha_1WithRSAEncryption || algOid == rsa ||
            algOid == sha_1WithRSAEncryption_ALT || 
            algOid == AsnOid("1.2.840.113549.1.2") ||
            algOid == rsaEncryption ||
            algOid == md2WithRSAEncryption ||
            algOid == md5WithRSAEncryption ||
            algOid == md5WithRSAEncryptionOIW ||
            algOid == sha_1WithRSAEncryption_ALT)   // id-OIW-secsig-algorithm-sha1WithRSASig
        {
            lRet = SMTI_VerifyRSA(pSignerKey, pDigestAlg, pSignatureAlg, pData, pSignature);
        }
        else if (algOid == id_dsa_with_sha1 || algOid == id_dsa ||
            algOid == id_OIW_secsig_algorithm_dsa)
        {
            lRet = SMTI_VerifyDSA(pSignerKey, pDigestAlg, pSignatureAlg, pData, pSignature);
        }
        else if (algOid == id_ecPublicKey || algOid == gECDSA_SHA1_OID)
        {
            lRet = SMTI_VerifyECDSA(pSignerKey, pDigestAlg, pSignatureAlg, pData, pSignature);
        }
        else     // Try the CSM_Common supported classes.
        {
            lRet = CSM_Common::SMTI_Verify(pSignerKey, pDigestAlg, 
                pSignatureAlg, pData, pSignature);
        }
        
#else
        lRet = SMTI_VerifyDSA(pSignerKey, pDigestAlg, pSignatureAlg, pData, pSignature);
#endif

//        if (lRet != 0)
//            SME_THROW(lRet, "CSM_Free3 CTIL SMTI_Verify failed.", NULL);

        m_ThreadLock.threadUnlock();
        return lRet;
    }
    catch (SNACC::SnaccException& snaccE) {
        m_ThreadLock.threadUnlock();
        snaccE.push(STACK_ENTRY);
        throw;
    }
#ifdef _DEBUG_EC_TEST
    catch (...) {
        m_ThreadLock.threadUnlock();
        throw;
    }
#endif   // _DEBUG_EC_TEST
}       // END CSM_Free3::SMTI_Verify


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_VerifyDSA(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
   CSM_Buffer bufferDigest;
   CSM_Buffer Signature;
   SM_RET_VAL lRet = SM_NO_ERROR;
   Integer *pP=NULL, *pQ=NULL, *pG=NULL;
   CSM_Buffer *pParams;
   AsnOid             *pdigoid=NULL;

   SME_SETUP("CSM_Free3::SMTI_VerifyDSA");

   if (pDigestAlg)
   {              // UPDATE ONLY IF SPECIFIED, otherwise assume set by app.
      pdigoid = pDigestAlg->GetId();
      if (*pdigoid == md5WithRSAEncryption)    // IDIOTS creating certs.
          *pdigoid = md5;
    }

   // are there params in pSignatureAlg, if so, use them...
   if ((pParams = pSignatureAlg->GetParams()) != NULL &&
       !(pParams->Length() == 2 && pParams->Access()[0] == 0x05))
               // IGNORE if NULL ASN.1 encoded.
   {
      CSM_DSAParams dsaParameters;

      SME(dsaParameters.Decode(pParams));

      pP = new Integer((const unsigned char *)dsaParameters.P, dsaParameters.m_lParamLength);
      pQ = new Integer((const unsigned char *)dsaParameters.Q, SM_DSA_Q_LEN);
      pG = new Integer((const unsigned char *)dsaParameters.G, dsaParameters.m_lParamLength);
   }
   else
   {
      // p, q, and g come from this which was originally from a
      // decoded cert
      pP = new Integer(m_DSAP);
      pQ = new Integer(m_DSAQ);
      pG = new Integer(m_DSAG);
   }
   if (pParams)
      delete pParams;

   // prep the crypto++ DSA public key
   // Y comes from pSignerKey
   // convert CSM_Buffers into Integers for use by crypto++
   Integer *py = sm_Free3CryptoppBERDecode(pSignerKey->Access(), 
       pSignerKey->Length());
   /*RWC;1/23/00;Integer y;
   pbyte = (byte *)pSignerKey->Access();
   y.BERDecode(pbyte);*/

#if !defined(CRYPTOPP_5_0) && !defined(CRYPTOPP_5_1)
    CryptoPP::DSAPublicKey dsaY(*pP, *pQ, *pG, *py);
#else
    CryptoPP::DSA::Verifier dsaY(*pP, *pQ, *pG, *py);
#endif
   delete py;

   // digest incoming data
   SME(CSM_Free3::SMTI_DigestData(pData, &bufferDigest, *pdigoid));

   if (pSignature->Length() == 40 && 
       pSignatureAlg->algorithm != id_dsa_with_sha1 && 
       pSignatureAlg->algorithm != id_dsa)       // OLD STYLE DSA sig value.
          Signature = *pSignature;
   else
   {
      AsnInt bufR;
      AsnInt bufS; 
      Dss_Sig_Value SNACCDSA_r_s;   // in sm_free3_asn.asn
      // RWC; NOW recreate 2 values r=20 bytes, s=20bytes from
      // RWC;  encoded DSA signature accroding to PKIX.
      DECODE_BUF(&SNACCDSA_r_s, pSignature);
      bufR.Set(SNACCDSA_r_s.r.c_str(), SNACCDSA_r_s.r.length());
      bufS.Set(SNACCDSA_r_s.s.c_str(), SNACCDSA_r_s.s.length());
      // Load Signature with R and S.
      //ENCODE_BUF(&SNACCDSA_r_s.r, prBuf);
      //ENCODE_BUF(&SNACCDSA_r_s.s, psBuf);
      Signature.Open(SM_FOPEN_WRITE);
      unsigned char *pch = (unsigned char *)Signature.Alloc(SM_FREE_DSA_SIG_LEN);
      int startReadIndex=0;
      int startIndex = SM_FREE_DSA_SIG_LEN/2 - bufR.length();
      if (startIndex < 0)
      {
          startReadIndex = -startIndex;
          startIndex = 0;
      }
      memcpy(&pch[startIndex], &bufR.c_str()[startReadIndex], SM_FREE_DSA_SIG_LEN/2 - startIndex);
      startReadIndex = 0;
      startIndex = SM_FREE_DSA_SIG_LEN/2 - bufS.length();
      if (startIndex < 0)
      {
          startReadIndex = -startIndex;
          startIndex = SM_FREE_DSA_SIG_LEN/2;   // start exactly half way
      }
      else
          startIndex += SM_FREE_DSA_SIG_LEN/2;
      memcpy(&pch[startIndex], &bufS.c_str()[startReadIndex], SM_FREE_DSA_SIG_LEN - startIndex);
      //Integer r((const byte *)prBuf->Access()); // BER Encoded "r".
      //r.Encode(pch, SM_FREE_DSA_SIG_LEN/2);    
      //Integer s((const byte *)psBuf->Access()); // BER Encoded "s".;
      //s.Encode(&pch[SM_FREE_DSA_SIG_LEN/2], SM_FREE_DSA_SIG_LEN/2);
      Signature.Flush();
      Signature.Close();
   }
   // verify the signature
   //RWC; Updated "dsaY.Verify(...)" to "VerifyDigest(...)".
   bool bVer = 
#ifndef CRYPTOPP_5_0
       dsaY.VerifyDigest
       ((const byte *)bufferDigest.Access(),
         (unsigned int)bufferDigest.Length(),
         (unsigned char *)Signature.Access());
#else  // CRYPTOPP_5_0
#ifdef CRYPTOPP_5_1
       dsaY.VerifyMessage((const byte *)pData->Access(),
         (unsigned int)pData->Length(),
         (unsigned char *)Signature.Access(), Signature.Length());
#else  // CRYPTOPP_5_1
       dsaY.AccessDigestSignatureScheme().VerifyDigest
       ((const byte *)bufferDigest.Access(),
         (unsigned int)bufferDigest.Length(),
         (unsigned char *)Signature.Access());
#endif // CRYPTOPP_5_1
#endif // CRYPTOPP_5_0
   if (!bVer)
      lRet = SM_FREE_VERIFY_FAILED;


/*RWC;#if defined(CRYPTOPP_5_0) && defined(_DEBUG)
      ByteQueue bt2;
      dsaY.AccessPublicKey().Save(bt2);
      unsigned char ppp[2048]; 
      int len=bt2.Get(ppp, 2048); 
      CSM_Buffer bufPublicKey((char *)ppp, len);
      bufPublicKey.ConvertMemoryToFile("./dsaY.bin");
#endif  //_DEBUG*/

   // cleanup pP, pQ, and pG
   if (pP)
         delete pP;
   if (pQ)
         delete pQ;
   if (pG)
         delete pG;

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      // cleanup pP, pQ, and pG
      if (pP)
         delete pP;
      if (pQ)
         delete pQ;
      if (pG)
         delete pG;
   SME_FREE3_CATCH_FINISH     //RWC;TMP;
#ifdef RWC_TMP_DEBUG
   SFL_CATCH_FINISH2
      if (pP)
         delete pP;
      if (pQ)
         delete pQ;
      if (pG)
         delete pG;
   SFL_CATCH_FINISH_END
#endif    //RWC_TMP_DEBUG

   if (pdigoid)
      delete pdigoid;

   return lRet;
}       // END CSM_Free3::SMTI_VerifyDSA(...)

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_VerifyECDSA(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
#ifdef CRYPTOPP_5_1
   CSM_Buffer bufferDigest;
   CSM_Buffer Signature;
   SM_RET_VAL lRet = SM_NO_ERROR;
   CSM_Buffer *pParams=NULL;
    ECIES<ECP>::Decryptor      *pcpubECP = NULL;
    ECDSA<ECP, SHA>::Verifier  *pspubECP=NULL;
    ECDSA<EC2N, SHA>::Verifier *pspubEC2N=NULL;
    ECDSA<ECP, SHA384>::Verifier  *pspubECP384=NULL;
    ECDSA<EC2N, SHA384>::Verifier *pspubEC2N384=NULL;
    bool bVer;

   SME_SETUP("CSM_Free3::SMTI_VerifyECDSA");

#ifdef CHECK_ON_THIS
   // are there params in pSignatureAlg, if so, use them...
   if ((pParams = pSignatureAlg->GetParams()) != NULL &&
      !(pParams->Length() == 2 && pParams->Access()[0] == 0x05))
               // EC Params MUST NOT BE IN Algorithm according to spec 
               //   (always taken from public key).
   {
       //RWC;TBD; LOOK UP Params from issuer cert (MUST BE PRESENT!)
       SME_THROW(22, "EC PARAMS MUST BE ABSENT from message AlgorithmIdentifier.", NULL);
   }
   if (pParams)
      delete pParams;
#endif // CHECK_ON_THIS

   // digest incoming data
   SME(CSM_Free3::SMTI_DigestData(pData, &bufferDigest, pDigestAlg->algorithm));

       // prep the crypto++ public key
       // Y comes from pSignerKey
        SubjectPublicKeyInfo TmpSubjectPubInfo;
        CSM_AlgVDA *pAlg = new CSM_AlgVDA(*pSignatureAlg);
        if (pSignatureAlg->algorithm != id_ecPublicKey)
             pAlg->algorithm = id_ecPublicKey;  // USE raw ID since reconstructing 
                                            //  public key.
        TmpSubjectPubInfo.algorithm = *(AlgorithmIdentifier *)pAlg;   // EC alg with full params.
        delete pAlg;
        TmpSubjectPubInfo.subjectPublicKey.Set((const unsigned char *)pSignerKey->Access(), 
                                               pSignerKey->Length()*8);
        CSM_Buffer TmpSignerKey;
        TmpSignerKey.Encode(TmpSubjectPubInfo);
/*RWC;#ifdef _DEBUG
        TmpSignerKey.ConvertMemoryToFile("./ECDSA_PublicKeyReEncoded.bin");
#endif  //_DEBUG*/
        CryptoPP::ByteQueue bt5;
        //RWC;bt5.Put((unsigned char *)pSignerKey->Access(), pSignerKey->Length());
        bt5.Put((unsigned char *)TmpSignerKey.Access(), TmpSignerKey.Length());

        //*****************************
        // FIRST, determine type of message, initial declarations.
        bool bECPFlag = true;        // ASSUME ECP type for encoded params (may not be true).
        int iSignatureLength = -1;
        if (pSignatureAlg->algorithm != id_ecdsa_with_SHA384)
        {
            try {
               pspubECP = new ECDSA<ECP, SHA>::Verifier(bt5);
               iSignatureLength = pspubECP->SignatureLength();
            }       // END try
            catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
            if (!bECPFlag)
            {
                CryptoPP::ByteQueue bt6;
                bt6.Put((unsigned char *)TmpSignerKey.Access(), TmpSignerKey.Length());
                pspubEC2N =  new ECDSA<EC2N, SHA>::Verifier(bt6);
                iSignatureLength = pspubEC2N->SignatureLength();
            }   // END IF bECPFlag
        }       // IF id_ecdsa_with_SHA384
        else
        {
            try {
               pspubECP384 = new ECDSA<ECP, SHA384>::Verifier(bt5);
               iSignatureLength = pspubECP384->SignatureLength();
            }       // END try
            catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
            if (!bECPFlag)
            {
                CryptoPP::ByteQueue bt6;
                bt6.Put((unsigned char *)TmpSignerKey.Access(), TmpSignerKey.Length());
                pspubEC2N384 =  new ECDSA<EC2N, SHA384>::Verifier(bt6);
                iSignatureLength = pspubEC2N384->SignatureLength();
            }   // END IF bECPFlag
        }       // END IF id_ecdsa_with_SHA384

        //*****************************
        // NEXT, perform generic signature encoding details for Crypto++ format.
        CSM_Buffer Signature;
        if (pSignature->Length() == iSignatureLength)
        {           // THEN old-style ECDSA encoding (2 consecutive values) 
            Signature = *pSignature;
        }
        else
        {
          AsnInt bufR;
          AsnInt bufS; 
          ECDSA_Sig_Value SNACCECDSA_r_s;
          // RWC; NOW recreate 2 values r=expectedLength/2 bytes, s=expectedLength/2 
          // RWC; bytes from encoded DSA signature accroding to PKIX.
          // RWC;  (for ECDSA, may be more than 20 bytes).
          DECODE_BUF(&SNACCECDSA_r_s, pSignature);
          bufR.Set(SNACCECDSA_r_s.r.c_str(), SNACCECDSA_r_s.r.length());
          bufS.Set(SNACCECDSA_r_s.s.c_str(), SNACCECDSA_r_s.s.length());
          // Load Signature with R and S.
          Signature.Open(SM_FOPEN_WRITE);
          unsigned char *pch = (unsigned char *)Signature.Alloc(iSignatureLength);
          int startReadIndex = bufR.length() - iSignatureLength/2;
          int iPrePendZeros = 0;
          if (startReadIndex < 0)   // ASN.1 encoded integer could be short or longer in length
          {       
              iPrePendZeros = -startReadIndex;                  // THIS indicates zeros were removed, we must add back in.
              startReadIndex = 0;
          }
          memcpy(&pch[iPrePendZeros], &bufR.c_str()[startReadIndex], iSignatureLength/2 - iPrePendZeros);
          startReadIndex = bufS.length() - iSignatureLength/2;
          iPrePendZeros = 0;
          if (startReadIndex < 0)   // ASN.1 encoded integer could be short or longer in length
          {                         // THIS indicates zeros were removed, we must add back in.
             iPrePendZeros = -startReadIndex;
             startReadIndex = 0;
          }
          memcpy(&pch[iSignatureLength/2 + iPrePendZeros], &bufS.c_str()[startReadIndex], 
                      iSignatureLength/2 - iPrePendZeros);
          Signature.Flush();
          Signature.Close();
        }       // END IF iSignatureLength already (not ASN.1 decoded)

        //*****************************
        // NEXT, process actual verification, unique to the ECDSA type.
        if (bECPFlag && pspubECP)        // PROCESS SHA ECP key...
        {
            // verify the signature
            bVer = pspubECP->VerifyMessage((const byte *)pData->Access(),
                (unsigned int)pData->Length(),
                (unsigned char *)Signature.Access(), Signature.Length());
            delete pspubECP;
            pspubECP = NULL;
        }
        else if (!bECPFlag && pspubEC2N)  // OR, attempt SHA EC2N ONLY if ECP fails.
        {                            //  (if EC2N fails, the failure is fatal!)
            // verify the signature
            bVer = pspubEC2N->VerifyMessage((const byte *)pData->Access(),
                (unsigned int)pData->Length(),
                (unsigned char *)Signature.Access(), Signature.Length());
            delete pspubEC2N;
            pspubEC2N = NULL;
        }       // IF EC2N type EC curve check.
        else if (bECPFlag && pspubECP384)        // PROCESS SHA ECP key...
        {
            // verify the signature
            bVer = pspubECP384->VerifyMessage((const byte *)pData->Access(),
                (unsigned int)pData->Length(),
                (unsigned char *)Signature.Access(), Signature.Length());
            delete pspubECP384;
            pspubECP384 = NULL;
        }       // IF ECP SHA 384
        else if (!bECPFlag && pspubEC2N384)  // OR, attempt SHA EC2N ONLY if ECP fails.
        {                            //  (if EC2N fails, the failure is fatal!)
            // verify the signature
            bVer = pspubEC2N384->VerifyMessage((const byte *)pData->Access(),
                (unsigned int)pData->Length(),
                (unsigned char *)Signature.Access(), Signature.Length());
            delete pspubEC2N384;
            pspubEC2N384 = NULL;
        }       // IF EC2N SHA 384 type EC curve check.
        else
        {
            SME_THROW(22, "SMTI_VerifyECDSA: no ECP/EC2N public key instance created", NULL);
        }       // END IF no ECP/EC2N public key instance created...

   if (!bVer)
      lRet = SM_FREE_VERIFY_FAILED;


/*RWC;#if defined(CRYPTOPP_5_0) && defined(_DEBUG)
      ByteQueue bt2;
      dsaY.AccessPublicKey().Save(bt2);
      unsigned char ppp[2048]; 
      int len=bt2.Get(ppp, 2048); 
      CSM_Buffer bufPublicKey((char *)ppp, len);
      bufPublicKey.ConvertMemoryToFile("./dsaY.bin");
#endif  //_DEBUG*/

   // CLEANUP
    if (pcpubECP)
        delete pcpubECP;

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
     if (pcpubECP)
         delete pcpubECP;
     if (pspubECP)
         delete pspubECP;
   SME_FREE3_CATCH_FINISH     //RWC;TMP;
#ifdef RWC_TMP_DEBUG
   SFL_CATCH_FINISH2
     if (pcpubECP)
        delete pcpubECP;
     if (pspubECP)
         delete pspubECP;
   SFL_CATCH_FINISH_END
#endif    //RWC_TMP_DEBUG

#else   // CRYPTOPP_5_0
   SM_RET_VAL lRet = -1;        // INDICATE NOT SUPPORTED using Crypto++ < 5.0
#endif  // CRYPTOPP_5_0

   return lRet;
}       // END CSM_Free3::SMTI_VerifyECDSA(...)


//
//
CryptoPP::Integer *CSM_Free3::ComputeBigInteger(AsnInt/*RWC;BigIntegerStr*/ &snaccInteger, unsigned int len)
{
    Integer *pCryptoppInt=NULL;
      const char *ptr=NULL;
      CSM_Buffer bigIntBuf;
      size_t len2=snaccInteger.length();
      AsnInt BI((char *)snaccInteger.c_str(), len2);
      bool bDelete = false;     // Default to NOT delete memory from BigIntegerStr.

      if (BI.length() == len)
      {
          ptr = (const char *)BI.c_str();//RWC;.Get(ptr, len);
          bDelete = true;
      }
      else
      {
          size_t length=0;
          BI.getPadded((unsigned char *&)ptr, (size_t&)length, len);  // FORCE to new, appropriate length, 
                                    //   based on ASN.1 rules.
          //RWC;ptr = bigIntBuf.Access();
      }
      pCryptoppInt = new CryptoPP::Integer;
      pCryptoppInt->Decode((const unsigned char *)ptr, len);
      // RWC; "ptr" MUST not be freed, all memory from other classes here.
      //if (bDelete)
      //    free(ptr);
      return(pCryptoppInt);
}

//
//
CSM_Buffer *CSM_Free3::ComputeBigIntegerBuf(AsnInt &snaccInteger, unsigned int len)
{
    CSM_Buffer *pResultBuf=new CSM_Buffer;
      const char *ptr=NULL;
      char *pch;
      CSM_Buffer bigIntBuf;
      size_t len2=snaccInteger.length();
      AsnInt BI((char *)snaccInteger.c_str(), len2);
      bool bDelete = false;     // Default to NOT delete memory from BigIntegerStr.

      if (BI.length() == len)
      {
          ptr = (char *)BI.c_str();//RWC;.Get(ptr, len);
          //bDelete = true;
      }
      else
      {
          size_t length=0;
          BI.getPadded((unsigned char *&)ptr, (size_t&)length, len);  // FORCE to new, appropriate length, 
          //RWC;BI.Get(bigIntBuf, len);  // FORCE to new, appropriate length, 
                                    //   based on ASN.1 rules.
          //RWC;ptr = bigIntBuf.Access();
          bDelete = true;
      }
      // extract P
      pResultBuf->Open(SM_FOPEN_WRITE);
      pch = pResultBuf->Alloc(len);
      memcpy(pch, ptr, len);
      pResultBuf->Flush();
      pResultBuf->Close();
      if (bDelete && ptr != NULL)
         free((char *)ptr);

   return pResultBuf;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Free3::RawEncrypt(CSM_Buffer *pbufInput, CSM_Buffer *pbufOutput,
        #ifndef CRYPTOPP_5_0
         Filter *pCBCEncryption)   // Defaults to 3DES Content Enc
        #else   // CRYPTOPP_5_0
         StreamTransformation *pCBCEncryption)
        #endif  // CRYPTOPP_5_0
{
   RawEncrypt(pbufInput, pbufOutput, pCBCEncryption, 
      SM_COMMON_3DES_BLOCKSIZE);      // Default to 3DES content encryption.
}

void CSM_Free3::RawEncrypt(CSM_Buffer *pbufInput, CSM_Buffer *pbufOutput,
        #ifndef CRYPTOPP_5_0
         Filter *pCBCEncryption,
        #else   // CRYPTOPP_5_0
         StreamTransformation *pCBCEncryption,
        #endif  // CRYPTOPP_5_0
         int iINBlockLen)
{
   long lBlockLen;
   char *achIn=(char *)calloc(1,iINBlockLen + 1);
   char *achOut=(char *)calloc(1,iINBlockLen + 1);
   // achBuf is used for padding at end of encryption
   int getLength;

   SME_SETUP("CSM_Free3::RawEncrypt");

   // open input for reading
   SME(pbufInput->Open(SM_FOPEN_READ));

   // open output for writing
   SME(pbufOutput->Open(SM_FOPEN_WRITE));

   // read input, cbc encrypt it, and write encrypted
   // result to output WHILE we have full blocks
   while ((lBlockLen = pbufInput->cRead(&achIn[0], iINBlockLen)) == iINBlockLen)
   {
      // do cbc process
#ifndef CRYPTOPP_5_0
      pCBCEncryption->Put((const unsigned char *) &achIn[0], iINBlockLen);
      //RWC; "->Put(...) calls ProcessBuf(...);pCBCEncryption->ProcessBuf();
      getLength = pCBCEncryption->Get((unsigned char *) &achOut[0], iINBlockLen);
      if (getLength)
#else // CRYPTOPP_5_0
      pCBCEncryption->ProcessData((byte *)&achOut[0], (const byte *)&achIn[0], iINBlockLen);
      getLength = iINBlockLen;
#endif // CRYPTOPP_5_0
      {
        // now, write the block to pEncryptedData
        SME(pbufOutput->Write(&achOut[0], getLength));
      }
   }
#ifndef CRYPTOPP_5_0
      pCBCEncryption->Put((const unsigned char *) &achIn[0], lBlockLen );
      #ifdef CRYPTOPP_3_2
      pCBCEncryption->InputFinished();      // auto-Pad results.
      #else
      pCBCEncryption->MessageEnd();
      #endif
      getLength = pCBCEncryption->Get((unsigned char *) &achOut[0], 
          iINBlockLen);
#else // CRYPTOPP_5_0
    //RWC;PAD all blocks;if (lBlockLen)
    {
      // RWC; PAD FINAL BLOCK IF NECESSARY (I have not figured out how to make 
      // RWC;  Crypto++5.0 perform my padding for me yet.)
      //RWC; in 5.0 we need to pad before calling if padded encryptor used (? not sure why ?)
       long lExtra = lBlockLen % iINBlockLen;
       //RWC; include 0, pad with 8 bytes;if (lExtra > 0)
       {
           for (int ii = 0; ii < iINBlockLen-lExtra; ii++)
               achIn[iINBlockLen - 1 - ii] = iINBlockLen-lExtra;
       }        // END if lExtra
      pCBCEncryption->/*RWC;ProcessLastBlock*/ProcessData((byte *)&achOut[0], 
                                       (const byte *)&achIn[0], iINBlockLen );
      getLength = iINBlockLen; //lBlockLen;//pCBCEncryption->MinLastBlockSize();
    }   // IF if (lBlockLen)
#endif // CRYPTOPP_5_0
      if (getLength)
      {
         // write padded block to pEncryptedData
         SME(pbufOutput->Write(&achOut[0], getLength));
      }

   pbufInput->Close();
   pbufOutput->Close();
   free(achIn);
   free(achOut);

   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH
}


////////////////////////////////////////////////////////////////////////////////
//
// Function Name:  SMTI_Encrypt
// 
// Description:    This routine handles 3DES RC2 and AES content encryption algs.
//
// Inputs:   CSM_Buffer *pData               Input (data to be encrypted)
//           CSM_Buffer *pMEK                Key to encrypt with may be specified
//           CSM_Buffer *pIV                 Initialization Vector
//
// Outputs:  CSM_Buffer *pEncryptedData      Encrypted output
//           CSM_Buffer *pMEK                Encrypted Key
//           CSM_Buffer *pParameters         For KeyAgree algs
//
// Returns:  SM_NO_ERROR - If no exception occurred
//
////////////////////////////////////////////////////////////////////////////////.
SM_RET_VAL CSM_Free3::SMTI_Encrypt(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV)  // In, to avoid specific alg encoding by app.
{
   int i;
   int CBC_Length=0, CBC_KeyLength = 0;
   AsnOid *pPreferredOID = GetPrefContentEncryption();
   CSM_Buffer            paddedData;
   SM_RET_VAL            status = 0;
      
   // create our cipher
   DESEncryption *pencryptionDES=NULL;
   AESEncryption *pEncryptionAES=NULL;
#ifndef CRYPTOPP_5_0
   DES_EDE3_Encryption *pencryption=NULL;
#ifdef CRYPTOPP_3_2
   VDA_CBCNotPaddedEncryptor_3_2 *pcbc_NotPaddedEncryption=NULL;
   Filter *pcbc_encryption=NULL;
   CBCPaddedEncryptor *pcbc_PADencryption=NULL;
#else
   Filter *pcbc_encryption=NULL;
   CBCPaddedEncryptor *pcbc_PADencryption=NULL;
   CBCRawEncryptor *pcbc_NotPaddedEncryption=NULL;;
#endif
#else // CRYPTOPP_5_0
   //DES_EDE3 *pencryption=NULL;
   StreamTransformation *pcbc_encryption=NULL;
   //CBCRawEncryptor *pcbc_NotPaddedEncryption=NULL;;
   //SimpleKeyingInterface *pcbc_encryption=NULL;
#endif // CRYPTOPP_5_0
   bool deleteFlag=false;

   SME_SETUP("CSM_Free3::SMTI_Encrypt");

   // check incoming parameters
   if ((pData == NULL) || (pEncryptedData == NULL) ||
       (pParameters == NULL) || (pMEK == NULL))
      SME_THROW(SM_FREE_MISSING_PARAM, "MISSING Parameters", NULL);

   // check algorithm oids
   if (! ((*pPreferredOID == des_ede3_cbc) ||
          (*pPreferredOID == id_alg_CMS3DESwrap) ||
          (*pPreferredOID == dES_CBC) || 
          (*pPreferredOID == rc2_cbc) || 
          (*pPreferredOID == id_alg_CMSRC2wrap) ||
          (*pPreferredOID == id_aes128_CBC) ||
          (*pPreferredOID == id_aes256_CBC) ||
          (*pPreferredOID == id_aes192_CBC) ||
          (*pPreferredOID == id_aes128_wrap) ||
          (*pPreferredOID == id_aes192_wrap) ||
          (*pPreferredOID == id_aes256_wrap)) )   
   {
       // algorithm not valid
       if (pPreferredOID)
           delete pPreferredOID;
       return 2;
   }


   if (*pPreferredOID == des_ede3_cbc) 
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
   }
   else if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap)
   {
      CBC_Length = SM_COMMON_RC2_BLOCKSIZE; // 8
      CBC_KeyLength = SM_COMMON_RC2_KEYLEN; // byte count 16 
   }
   else if (*pPreferredOID == dES_CBC)
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = 8;                     // for DES.
   }
   else if (*pPreferredOID == id_aes128_CBC) 
   {
      CBC_Length = AES_128;
      CBC_KeyLength = AES_128/8;               // for AES 128/8 = 16
   }
   else if (*pPreferredOID == id_aes192_CBC)
   {
      CBC_Length = AES_128;
      CBC_KeyLength = AES_192/8;               // for AES 192/8 = 24.
   }
   else if (*pPreferredOID == id_aes256_CBC)
   {
      CBC_Length = AES_128;
      CBC_KeyLength = AES_256/8;               // for AES 256/8 = 32.
   }      
   else          // Default to 3DES length.
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
   }

   // generate the MEK ONLY if not provided.
   if (!pMEK->Length())
   {
      SME(SMTI_Random(NULL, pMEK, CBC_KeyLength));
   }
   else         // Adjust incomming MEK to proper length.
   {
       if (pMEK->Length() < (unsigned int)CBC_KeyLength)
       {
         CSM_Buffer tmpBuf((size_t)CBC_KeyLength);
            //RWC;NOT SURE WHY THIS WAS CHANGED EARLIER...(size_t)pMEK->Length());//RWC;CBC_KeyLength);
         memcpy((void *)tmpBuf.Access(), pMEK->Access(), pMEK->Length());
         pMEK->ReSet(tmpBuf);   // RESET to proper, minimum key length...
       }
   }

   // generate a IV
   if (pIV == NULL || !pIV->Length())
   {
      if (pIV == NULL)
      {
         deleteFlag = true;
         pIV = new CSM_Buffer;
      }
      SME(SMTI_Random(NULL, pIV, CBC_Length));
   }

   // RC2 content encryption or RC2 KEY WRAP OID)
   if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap) 
   {
      // create cbc object
      // create our cipher
      RC2Encryption encryption((const unsigned char*)pMEK->Access(),
             pMEK->Length(), CBC_KeyLength * 8);
#ifndef CRYPTOPP_5_0
      if (*pPreferredOID == rc2_cbc) // check for rc2 key wrap oid here 
      {
          pcbc_PADencryption=new CBCPaddedEncryptor(encryption,  
              (const unsigned char*)pIV->Access());
          pcbc_encryption = pcbc_PADencryption;
      }
      else
      {
          #ifdef CRYPTOPP_3_2
          // using the new vda defined class that will handle no padding
          // CBC_CTS_Encryptor cannot handle no padding
          pcbc_NotPaddedEncryption = new VDA_CBCNotPaddedEncryptor_3_2(encryption,
              (const unsigned char*)pIV->Access());
          #else
          pcbc_NotPaddedEncryption = new CBCRawEncryptor(encryption,
              (const unsigned char*)pIV->Access());
          #endif
          pcbc_encryption = pcbc_NotPaddedEncryption;
      }
#else // CRYPTOPP_5_0
      if (*pPreferredOID == rc2_cbc) // check for rc2 key wrap oid here 
      {
          //RWC;DOES NOT WORK, MUST USE EXTERNAL;
          //CBC_Mode/*CFB_Mode*/<RC2>::Encryption *pTmpEncryption = new CBC_Mode/*CFB_Mode*/<RC2>::Encryption;
          //pTmpEncryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), CBC_KeyLength, 
          //              (const unsigned char *)pIV->Access());
          CBC_Mode_ExternalCipher::Encryption *pTmpEncryption= new CBC_Mode_ExternalCipher::Encryption(
              encryption, (const unsigned char*)pIV->Access());
          pcbc_encryption = pTmpEncryption;
      }
      else
      {
          // RWC;1/10/02; TEMPORARY, MUST BE RE-Created to not pad data....
          //RWC;DOES NOT WORK, MUST USE EXTERNAL;
          //CBC_Mode/*CFB_Mode*/<RC2>::Encryption *pTmpEncryption = new CBC_Mode/*CFB_Mode*/<RC2>::Encryption;
          //pTmpEncryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), CBC_KeyLength, 
          //              (const unsigned char *)pIV->Access());
          CBC_Mode_ExternalCipher::Encryption *pTmpEncryption= new CBC_Mode_ExternalCipher::Encryption(
              encryption, (const unsigned char*)pIV->Access());
          pcbc_encryption = pTmpEncryption;
      }
#endif // CRYPTOPP_5_0

      SME(RawEncrypt(pData, pEncryptedData, pcbc_encryption, CBC_Length));
      LoadParams(*pIV, pParameters, CBC_KeyLength);

   }
   // AES content encryption or AES KEY WRAP OID)
   else if ((*pPreferredOID == id_aes128_CBC || *pPreferredOID == id_aes128_wrap) ||
            (*pPreferredOID == id_aes192_CBC || *pPreferredOID == id_aes192_wrap) ||
            (*pPreferredOID == id_aes256_CBC || *pPreferredOID == id_aes256_wrap) )
   { 
      pEncryptionAES = new AESEncryption((const unsigned char *)pMEK->Access(), 
                                      pMEK->Length(), CBC_KeyLength*8);

      CBC_Mode_ExternalCipher::Encryption *pTmpEncryption= 
               new CBC_Mode_ExternalCipher::Encryption(*pEncryptionAES, 
                  (const unsigned char *)pIV->Access());

      // assign to the streamTransformation variable
      pcbc_encryption = pTmpEncryption;

      // encrypt the data and load the parameters
      SME(RawEncrypt(pData, pEncryptedData, pcbc_encryption, CBC_Length));
      LoadParams(*pIV, pParameters);
   }     
   else     // RWC; DEFAULT; if (*pPreferredOID == des_ede3_cbc) 
   {
      // Check parity for incomming 3DES key.
      // RWC;4/4/01;CHECK to see if DES requires parity update, may need to be
      //   moved under "des_ede3_cbc" OID check!!!!!!!
      unsigned char *ptr3=(unsigned char *)pMEK->Access();
      for (i=0; i < (int)pMEK->Length(); i++)
      {
         if (!CryptoPP::Parity((unsigned long)ptr3[i]))
            ptr3[i] ^= 0x01;
      }

      // create cbc object
      if (*pPreferredOID == des_ede3_cbc) 
      {
#ifndef CRYPTOPP_5_0
          pencryption = new DES_EDE3_Encryption((const unsigned char*)pMEK->Access());
          pcbc_PADencryption=new CBCPaddedEncryptor(*pencryption,  
              (const unsigned char*)pIV->Access());
          pcbc_encryption = pcbc_PADencryption;
#else // CRYPTOPP_5_0
          //RWC;6667;SimpleKeyedTransformation<DES_EDE3> *pencryption2 = new SimpleKeyedTransformation<DES_EDE3>((const unsigned char*)pMEK->Access(), 24);
          //pencryption = new DES_EDE3((const unsigned char*)pMEK->Access(), 24);;
          //pencryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), 24);
          //CFB_Mode<DES_EDE3>::Encryption *pcbc_PADencryption 
          CBC_Mode/*CFB_Mode*/<DES_EDE3>::Encryption *pTmpEncryption = new CBC_Mode/*CFB_Mode*/<DES_EDE3>::Encryption;
          pTmpEncryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), CBC_KeyLength, 
                        (const unsigned char *)pIV->Access());
          pcbc_encryption = pTmpEncryption;
#endif // CRYPTOPP_5_0
      }
      else if (*pPreferredOID == dES_CBC)
      {
#ifndef CRYPTOPP_5_0
          pencryptionDES = new DESEncryption((const unsigned char*)
                                    pMEK->Access());
          pcbc_PADencryption=new CBCPaddedEncryptor(*pencryptionDES,  
              (const unsigned char*)pIV->Access());
          pcbc_encryption = pcbc_PADencryption;
#else  // CRYPTOPP_5_0
          //CFB_Mode<DES>::Encryption *pcbc_PADencryption 
          CBC_Mode/*CFB_Mode*/<DES>::Encryption *pTmpEncryption = new CBC_Mode/*CFB_Mode*/<DES>::Encryption;
          pTmpEncryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), CBC_KeyLength, 
                        (const unsigned char *)pIV->Access());
          pcbc_encryption = pTmpEncryption;
#endif // CRYPTOPP_5_0
      }
      else
      {
#ifndef CRYPTOPP_5_0
          pencryption = new DES_EDE3_Encryption((const unsigned char*)
                                    pMEK->Access());
          // using the new vda defined class that will handle no padding
          // CBC_CTS_Encryptor cannot handle no padding
          #ifdef CRYPTOPP_3_2
          pcbc_NotPaddedEncryption = new VDA_CBCNotPaddedEncryptor_3_2(*pencryption,
             (const unsigned char*)pIV->Access());
          #else
          pcbc_NotPaddedEncryption = new CBCRawEncryptor(*pencryption,
              (const unsigned char*)pIV->Access());
          pcbc_encryption = pcbc_NotPaddedEncryption;
          #endif
#else // CRYPTOPP_5_0
          // RWC;1/10/02; TEMPORARY, MUST BE RE-Created to not pad data....
          CBC_Mode/*CFB_Mode*/<DES_EDE3>::Encryption *pTmpEncryption = new CBC_Mode/*CFB_Mode*/<DES_EDE3>::Encryption;
          pTmpEncryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), CBC_KeyLength, 
                        (const unsigned char *)pIV->Access());
          pcbc_encryption = pTmpEncryption;
#endif // CRYPTOPP_5_0
      }

      // preform the encryption and load parameters
      SME(RawEncrypt(pData, pEncryptedData, pcbc_encryption, CBC_Length));
      LoadParams(*pIV, pParameters);
   }

#ifndef CRYPTOPP_5_0
    if (*pPreferredOID == rc2_cbc || *pPreferredOID == des_ede3_cbc ||
        *pPreferredOID == dES_CBC) 
    {
          delete pcbc_PADencryption;
    }
    else
    {
       delete pcbc_NotPaddedEncryption;
    }
    if (pencryption)
        delete pencryption;
#else // CRYPTOPP_5_0
    if (*pPreferredOID != rc2_cbc && *pPreferredOID != des_ede3_cbc && 
        *pPreferredOID != dES_CBC &&
          (*pPreferredOID != id_aes128_CBC) &&
          (*pPreferredOID != id_aes256_CBC) &&
          (*pPreferredOID != id_aes192_CBC) &&
          (*pPreferredOID != id_aes128_wrap) &&
          (*pPreferredOID != id_aes192_wrap) &&
          (*pPreferredOID != id_aes256_wrap))  // REMOVE padding...
       pEncryptedData->SetLength(pData->Length());   // IGNORE padding...
    delete pcbc_encryption;
#endif // CRYPTOPP_5_0
    if (pencryptionDES)
        delete pencryptionDES;
    if (pEncryptionAES)
        delete pEncryptionAES;
    if (pPreferredOID )
       delete pPreferredOID ;


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
       if (pPreferredOID )
          delete pPreferredOID ;
   SME_FREE3_CATCH_FINISH

   if (deleteFlag)
         delete pIV;

   return SM_NO_ERROR;
}


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
            CSM_Buffer *pSubjKeyId) // output
{
   SM_RET_VAL status = -1;
   AsnOid *pPreferredOID=this->GetPrefKeyEncryption();

   SME_SETUP("CSM_Free3::SMTI_GenerateEMEK");

   m_ThreadLock.threadLock();
#ifdef SM_FREE3_RSA_INCLUDED
   if (*pPreferredOID  != id_RSAES_OAEP)
       status = RSA_GenerateEMEK(pRecipient, pParameters, pMEK, pEMEK, 
            pUKM, pSubjKeyId); 
   else
       status = RSAES_OAEP_GenerateEMEK(pRecipient, pParameters, pMEK, pEMEK, 
            pUKM, pSubjKeyId); 
#else
   SME_THROW(SM_FREE_UNSUPPORTED_ALG, NULL, NULL);
#endif

   delete pPreferredOID;

   SME_FINISH
   SME_CATCH_SETUP
   m_ThreadLock.threadUnlock();
   SME_FREE3_CATCH_FINISH
   m_ThreadLock.threadUnlock();

   return status;
}

CSM_Buffer *CSM_Free3::SMTI_GenerateKeyWrapIV(
    long &lKekLength,   // OUT, returned algorithm specific length
    CSM_AlgVDA *pWrapAlg)   // OUT, returned since params are alg specific.
{
   CSM_Buffer *pIV=NULL;
   AsnOid *pPreferredOID = GetPrefContentEncryption();
   //RWC; Reversed order from MS Integration test with ESDH;
   //RWC;   char Ivhard[] = {(char)0x05,(char)0x21,(char)0xe8,(char)0x79,(char)0x2c,(char)0xa2,(char)0xdd,(char)0x4a};
   unsigned char Ivhard[] = {(unsigned char)0x4a,(unsigned char)0xdd,(unsigned char)0xa2,(unsigned char)0x2c,(unsigned char)0x79,(unsigned char)0xe8,(unsigned char)0x21,(unsigned char)0x05};
   AsnOid *ptmpOID=NULL;
   
   SME_SETUP("CSM_Free3::SMTI_GenerateKeyWrapIV");

   // RWC; a few adjustments, allowing the user to simply specify the content 
   //  encryption alg, we will adjust to the matching wrap alg (newer 
   //  requirement that the wrap alg match the content encryption alg).
   if (*pPreferredOID == des_ede3_cbc)
         ptmpOID = new AsnOid(id_alg_CMS3DESwrap);
   else if (*pPreferredOID == rc2_cbc)
         ptmpOID = new AsnOid(id_alg_CMSRC2wrap);
   else if (*pPreferredOID == id_aes256_CBC)
         ptmpOID = new AsnOid(id_aes256_CBC);  // ONLY 1 allowed
   else if ((*pPreferredOID  != id_alg_CMS3DESwrap) &&
           (*pPreferredOID  != id_alg_CMSRC2wrap) &&
           (*pPreferredOID  != id_aes256_CBC) )
   {
      char ptr[100];
      sprintf(ptr, "WRAP Algorithm NOT supported, %s", pPreferredOID->GetChar());
      SME_THROW(25, ptr, NULL);
   }
         //ptmpOID = new AsnOid(id_alg_CMS3DESwrap);
   if (ptmpOID)   // ADJUST if necessary to wrap Alg.
   {
         BTISetPreferredCSInstAlgs(NULL,NULL,NULL,ptmpOID);
         delete ptmpOID;
         delete pPreferredOID;
         pPreferredOID = GetPrefContentEncryption();
   }


   if (*pPreferredOID == id_alg_CMSRC2wrap) // check for rc2 key wrap
   {
       // LOAD hardcoded details.
      pIV = new CSM_Buffer((size_t)SM_COMMON_RC2_BLOCKSIZE);
   
      memcpy((void *)pIV->Access(), Ivhard, SM_COMMON_RC2_BLOCKSIZE);

      lKekLength = 128/8; //BYTES; RWC;SM_RSA_RC2_DEFAULT_KEYBITS;

      if (pWrapAlg)
      {
         CSM_Buffer *pTmpBuf=NULL; //=CSM_Alg::GetNullParams();
         RC2wrapParameter rc2Param=58;    // 128 effective bits
         ENCODE_BUF(&rc2Param, pTmpBuf);
         pWrapAlg->algorithm = *pPreferredOID;
         pWrapAlg->parameters = new AsnAny;
         SM_ASSIGN_ANYBUF(pTmpBuf, pWrapAlg->parameters);
         delete pTmpBuf;
      }
   }
   else if (*pPreferredOID == id_aes256_CBC) // AES 256 key encrypt key only  
                                             // oid name tbd id_xxxxx_AESWrap
   {

      // LOAD hardcoded details.
      // allocate memory for AES iv - 16 
      pIV = new CSM_Buffer((size_t)AES_IV_SIZE);
      // point ptr to initialized memory of the pIV
      unsigned char *ptr=(unsigned char *)pIV->Access();
      for (int i=0; i < AES_IV_SIZE; i++)
         ptr[i] = 0xA6; //RWC9;A6A6A6A6A6A6A6 Ivhard[i];
   
      lKekLength = AES_256/8;

      if (pWrapAlg)
      {
          pWrapAlg->algorithm = *pPreferredOID;
          pWrapAlg->parameters = new AsnAny;
          CSM_Buffer *pTmpBuf=CSM_Alg::GetNullParams();
          SM_ASSIGN_ANYBUF(pTmpBuf, pWrapAlg->parameters);
          delete pTmpBuf;
      }
   }
   else 
   {   
      // LOAD hardcoded details.
      pIV = new CSM_Buffer((size_t)SM_COMMON_3DES_BLOCKSIZE);
      unsigned char *ptr=(unsigned char *)pIV->Access();
      for (int i=0; i < SM_COMMON_3DES_BLOCKSIZE; i++)
         ptr[i] = Ivhard[i];
   
      lKekLength = SM_COMMON_3DES_KEYLEN;

      if (pWrapAlg)
      {
          pWrapAlg->algorithm = *pPreferredOID;
          pWrapAlg->parameters = new AsnAny;
          CSM_Buffer *pTmpBuf=CSM_Alg::GetNullParams();
          SM_ASSIGN_ANYBUF(pTmpBuf, pWrapAlg->parameters);
          delete pTmpBuf;
      }
   } // end id_alg_CMS3DESwrap


   if (pPreferredOID)
       delete pPreferredOID;

   SME_FINISH
   SME_CATCH_SETUP
      if (pPreferredOID)
         delete pPreferredOID;
   SME_FREE3_CATCH_FINISH

   return(pIV);
}

////////////////////////////////////////////////////////////////////////////////
//
// Function Name:  SMTI_GenerateKeyAgreement
//
// Description:  Function Generates the key agreement key.  After building it, 
//               the pbufKeyAgree parameter will hold the data.  It will be
//               adjusted according to the encryption oid and lKekLength.  RC@
//               and AES requires keyLength adjustment.
//
// Inputs:
//            CSM_Buffer *pRecipient        Y of recip
//            CSM_Buffer *pParameters       may be passed in for shared use
//                                          or for ESDH. (p, g, and/or IV).
//            CSM_Buffer *pUKM              may be passed in for shared use.
//                                          UserKeyMaterial (random number).
//            CSM_Buffer *pbufferIV         may be passed in for shared use.
//                               Initialization vector, part of DH params.
//            AsnOid *pEncryptionOID,       specified encryption of key,
//                         used here in key generation, but alg not implemented.
//            long lKekLength               key length, for OtherInfo load.
//
// Outputs:
//            CSM_Buffer *pParameters       may be passed in for shared use
//                                          or for ESDH. (p, g, and/or IV).
//            CSM_Buffer *pUKM              may be passed in for shared use.
//                                          UserKeyMaterial (random number).
//            CSM_Buffer *pbufferIV         may be passed in for shared use.
//                               Initialization vector, part of DH params.
//            CSM_Buffer *pbufKeyAgree,     encryption key for this recip.
//
// Returns:   status - 0 for success, otherwise unsuccessful
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_GenerateKeyAgreement(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            long lKekLength)        // Input, for OtherInfo load.
{
    long lStatus=0;
    AsnOid *poidKeyEncrypt = this->GetPrefKeyEncryption();
    SecByteBlock *pZZ=NULL;
    CSM_Buffer tempBuffer;
    CSM_Buffer k1, k2, TEK;
    AsnOid *pPreferredContentOID=NULL;
    CSM_Buffer *ptempBuff = NULL;
    int IVSize;
    AsnOid *pPrefDigest = NULL;
    CSM_Buffer *pbufX=NULL;

    SME_SETUP("CSM_Free3::SMTI_GenerateKeyAgreement");

   //###### START OF CODE
   // check incoming parameters
   if ((pParameters == NULL) || (pbufKeyAgree == NULL))
      SME_THROW(SM_MISSING_PARAM, "Missing parameter(s).", NULL);

   if (pEncryptionOID)
   {
     // RWC; a few adjustments, allowing the user to simply specify the content 
     //  encryption alg, we will adjust to the matching wrap alg (newer 
     //  requirement that the wrap alg match the content encryption alg).
     if (*pEncryptionOID == des_ede3_cbc)
         pPreferredContentOID = new AsnOid(id_alg_CMS3DESwrap);
     else if (*pEncryptionOID == rc2_cbc)
         pPreferredContentOID = new AsnOid(id_alg_CMSRC2wrap);
     else if (*pEncryptionOID == id_aes256_CBC)
         pPreferredContentOID = new AsnOid(id_aes256_CBC);  // ONLY 1 allowed
     else if ((*pEncryptionOID == id_alg_CMS3DESwrap) ||
           (*pEncryptionOID == id_alg_CMSRC2wrap) ||
           (*pEncryptionOID == id_aes256_CBC) )
          pPreferredContentOID = pEncryptionOID;
     else
     {
       char ptr[100];
       sprintf(ptr, "WRAP Algorithm NOT supported, %s", pEncryptionOID->GetChar());
       SME_THROW(25, ptr, NULL);
     }
   }
   else
      pPreferredContentOID = new AsnOid(id_alg_CMS3DESwrap);

   // determine size of iv for later use
   if (*pPreferredContentOID == id_alg_CMSRC2wrap)
   {
       IVSize = SM_COMMON_RC2_BLOCKSIZE;         // 8
   }
   else if (*pPreferredContentOID == id_aes256_CBC)  // oid name tbd id_xxxxx_AESWrap
   {
       IVSize = AES_IV_SIZE;                   // 16
   }
   else
   {
       IVSize = SM_COMMON_3DES_IVLEN;            // 8
   }

   //##### INITIALIZE IV buffer if necessary; NEEDS TO BE SET BEFORE Key Agree 
   //   create.
   if (!pbufferIV->Length())  // SHOULD be set before here, may be RC2
       SME(SMTI_Random(NULL, pbufferIV, IVSize));


    //###### CHECK for various supported KARI algs (DH, ESDH, ECDH (various types)).
    if (*poidKeyEncrypt == id_dhStatic ||      // Static Diffie-Hellman, use originator's params.
        *poidKeyEncrypt == id_alg_ESDH ||
        *poidKeyEncrypt == dh_public_number)
    {
        //##### GET private key
        if ((*poidKeyEncrypt == id_dhStatic ||      // Static Diffie-Hellman, use originator's params.
             *poidKeyEncrypt == dh_public_number) &&
             m_pX)    // LOCAL private key with params.
        {
            // prep the crypto++ DSA/RSA private key
            char *pszPassword = GetPassword();
            pbufX = DecryptPrivateKey(pszPassword, m_pX);
            free (pszPassword);
        }
        lStatus = SMTI_GenerateKeyAgreementDH(pRecipient, pParameters, //pUKM, 
                        pUKM, pbufferIV,  pPreferredContentOID,  pbufKeyAgree, /*lKekLength,*/ 
                        pbufX, *poidKeyEncrypt, lKekLength);
    }
    else if (*poidKeyEncrypt == dhSinglePass_stdDH_sha1kdf_scheme ||
             *poidKeyEncrypt == dhSinglePass_cofactorDH_sha1kdf_scheme)
    {       // COMPLETELY Ephemeral, no use of our private key...
        lStatus = SMTI_GenerateKeyAgreementECDH(pRecipient, pParameters,
               pUKM, pbufferIV,  pPreferredContentOID,  pbufKeyAgree, lKekLength);
    }
    else if (*poidKeyEncrypt == mqvSinglePass_sha1kdf_scheme)
    {
        if (m_pECParams && m_pX)    // LOCAL private key with params.
        {
            // prep the crypto++ DSA/RSA private key
            char *pszPassword = GetPassword();
            pbufX = DecryptPrivateKey(pszPassword, m_pX);
            free (pszPassword);
        }
        lStatus = SMTI_GenerateKeyAgreementECDH_MQV(pUKM, pRecipient, pParameters,
                        pbufferIV,  pPreferredContentOID,  pbufKeyAgree, pbufX);
    }

    if (pbufKeyAgree == NULL)
    {
        SME_THROW(22, "BAD Key Agreement Calculation!", NULL);
    }


   // now we need to encrypt the MEK with the TEK
   // generate a random IV OR use specified IV.
         // check the key oid for iv size to use

   // create our cipher
   // this should only use the first 24 bytes in TEK

   // NOW process the resulting data for the KeyWrap algorithm to encrypt.

   if (pbufKeyAgree->Length() > SM_COMMON_RC2_KEYLEN && 
      (*pPreferredContentOID == rc2_cbc || 
       *pPreferredContentOID  == id_alg_CMSRC2wrap))
       pbufKeyAgree->SetLength(SM_COMMON_RC2_KEYLEN);   // OVERRIDE RC2, force.
               // THIS OVERRIDE is necessary for RC2 DH key wrap compatibility.
   else if (pbufKeyAgree->Length() > lKekLength &&
           (*pPreferredContentOID == id_aes256_CBC   ||
            *pPreferredContentOID == id_aes256_wrap) ||
           (*pPreferredContentOID == id_aes192_CBC   ||
            *pPreferredContentOID == id_aes192_wrap) ||
           (*pPreferredContentOID == id_aes128_CBC   ||
            *pPreferredContentOID == id_aes128_wrap) )
      pbufKeyAgree->SetLength(lKekLength); // OVERRIDE AES , force.
               // THIS OVERRIDE is necessary for AES DH key wrap compatibility.

    if (poidKeyEncrypt)
      delete poidKeyEncrypt;
    if (pZZ)
        delete pZZ;
    if (pPreferredContentOID && pPreferredContentOID != pEncryptionOID)
        delete pPreferredContentOID;
    if (pPrefDigest)
    {
        BTISetPreferredCSInstAlgs(pPrefDigest, NULL, NULL, NULL); // set md5
        delete pPrefDigest;
    }
    if (pbufX)
        delete pbufX;


   SME_FINISH
   SME_CATCH_SETUP
      if (poidKeyEncrypt)
          delete poidKeyEncrypt;
      if (pZZ)
          delete pZZ;
      if (pPreferredContentOID && pPreferredContentOID != pEncryptionOID)
         delete pPreferredContentOID;
      if (pPrefDigest)
      {
         BTISetPreferredCSInstAlgs(pPrefDigest, NULL, NULL, NULL); // set md5
         delete pPrefDigest;
      }
   SME_FREE3_CATCH_FINISH

    return(lStatus);
}           // END CSM_Free3::SMTI_GenerateKeyAgreement(...)

//////////////////////////////////////////////////////////////////////////
long CSM_Free3::SMTI_GenerateKeyAgreementECDH_MQV(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            CSM_Buffer *pbufX)        // INPUT, clear private key
{
    long lStatus=0;
    SecByteBlock *pZZ=NULL;
    SimpleKeyAgreementDomain *pGenericECDH=NULL;
    SecByteBlock *ppriv1=NULL;
    SecByteBlock *ppub1=NULL;
    char achCounter1[] = {0x00, 0x00, 0x00, 0x01};
    char achCounter2[] = {0x00, 0x00, 0x00, 0x02};

    SME_SETUP("CSM_Free3::SMTI_GenerateKeyAgreementECDH_MQV");

#ifdef CRYPTOPP_5_0_NOT_YET
    if (m_pECParams == NULL)
    {
       SME_THROW(22, "Private key ECDH Parameters MUST BE PRESENT!", NULL);
    }
    if (pbufX == NULL)   // LOCAL private key with params.
    {
       SME_THROW(22, "Private key MUST BE PRESENT!", NULL);
    }       // END IF we have a private key

    AuthenticatedKeyAgreementDomain *pGenericAuthECDH=NULL;
    bool bECPFlag=true;  // EASIER to use flag than the keep checking OIDs.
    CryptoPP::ByteQueue bt5;
    bt5.Put((unsigned char *)pbufX->Access(), pbufX->Length());

    m_ThreadLock.threadLock();

        if (mqvSinglePass_sha1kdf_scheme) // NOT SURE YET...
        {
          try {
                pGenericAuthECDH = new ECMQV<ECP>::Domain(bt5);
                //pGenericECDH = pGenericAuthECDH;
          }       // END try
          catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
          if (!bECPFlag)               // Attempt EC2N private key...
          {
                pGenericAuthECDH = new ECMQV<EC2N>::Domain(bt5);
          }
        }       // END if 

   // Create storage for the resulting agreed upon key and clear it
   pZZ = new SecByteBlock(pGenericECDH->AgreedValueLength());

   memset(*pZZ, 0x00, pZZ->m_size);

   /* <FROM RFC3278>3.2  EnvelopedData using 1-Pass ECMQV
       ECMQV is specified in [SEC1] and [IEEE1363].
      <FROM X9.63> 5.9 One Pass MQV: 
      This scheme corresponds to the MQV1 scheme in ANSI X9.42.
      <FROM X9.42>  DETAILS ON MQV1 scheme; appears to not be present in Crypto++5.0.
        SHOULD BE ABLE TO BUILD A CUSTOM CLASS for MVQ1 from source of Agree(...)
        in mqv.h and X9.42 description, 4.5.2.2    dhMQV1.
For MQV2
ZMQV    = (gs ^ (SaSb)) mod ps    
        = ((tb(yb ^  )) ^ Sa ) mod ps ; by A    
        = ((ta(ya ^  )) ^ Sb ) mod ps ; by B
        where,    Sa = (ra +  xa) mod qs    Sb = (rb +  xb) mod qs
For MQV1
Algorithm dhMQV1 is appropriate for store-and-forward applications where only the 
protocol initiator can provide the ephemeral components ra and ta.  For dhMQV1, the 
calculation of ZMQV is as follows:
ZMQV    = (gs ^ (Saxb)) mod ps    
        = (yb ^ Sa ) mod ps ; by A    
        = ((ta(ya ^  )) ^ xb) mod ps ; by B
        where,    Sa = (ra +  xa) mod qs
   */
   bcheckResult = pGenericAuthECDH->Agree(*pZZ, 
        (const unsigned char *)pbufX->Access()/* *ppriv1*/,  
        (const unsigned char *)pOriginator->Access(),  0);
    /*bool Agree(byte *agreedValue,
        const byte *staticPrivateKey, const byte *ephemeralPrivateKey, 
        const byte *staticOtherPublicKey, const byte *ephemeralOtherPublicKey,
        bool validateStaticOtherPublicKey=true) const*/
   if (!bcheckResult)
      SME_THROW(22, "ECDH MQV Key Agreement Failure.", NULL);

   SME(BTISetPreferredCSInstAlgs((AsnOid *)&sha_1, NULL, NULL, NULL)); // set md5

   //###### time to generate the TEK
   // generate a random Ra, store in pUKM if we don't already have it
   if (pUKM && pUKM->Access() == NULL)  // Since UKM is optional it may not be
                                        //  passed in; FLAG to use is empty buf
      SME(SMTI_Random(NULL, pUKM, SM_FREE_RA_SIZE/8));
   // concatentate ZZ, encoded oid, counter1, Ra
   SME(tempBuffer.Open(SM_FOPEN_WRITE));
#ifndef CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->ptr, pZZ->size));
#else // CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->data(), pZZ->m_size));
#endif // CRYPTOPP_5_0
#ifdef OLD_DH
   SME(tempBuffer.Write((char *)(des_ede3_cbc.Str()), des_ede3_cbc.Len()));
   SME(tempBuffer.Write(achCounter1, 4));
   SME(tempBuffer.Write((pUKM->Access()), pUKM->Length()));
#else
   ptempBuff = EncodeOtherInfo(pUKM, achCounter1, *pPreferredContentOID, lKekLength);
   //ptempBuff->ConvertMemoryToFile("c:\\tmp\\OtherInfo1.out");
   SME(tempBuffer.Write((ptempBuff->Access()), ptempBuff->Length()));
   delete ptempBuff;
   ptempBuff = NULL;
#endif
   tempBuffer.Close();
   // now hash
   CSM_Free3::SMTI_DigestData(&tempBuffer, &k1);
   //tempBuffer.ConvertMemoryToFile("c:\\tmp\\OtherInfo2.out");

  // concatentate ZZ, encoded oid, counter2, Ra
  SME(tempBuffer.Open(SM_FOPEN_WRITE));
 #ifndef CRYPTOPP_5_0
  SME(tempBuffer.Write((char *)pZZ->ptr, pZZ->size));
#else // CRYPTOPP_5_0
  SME(tempBuffer.Write((char *)pZZ->data(), pZZ->m_size));
#endif // CRYPTOPP_5_0
   ptempBuff = EncodeOtherInfo(pUKM, achCounter2, *pPreferredContentOID, lKekLength);
   SME(tempBuffer.Write((ptempBuff->Access()), ptempBuff->Length()));
   delete ptempBuff;
   ptempBuff = NULL;
   tempBuffer.Close();
   // now hash
   CSM_Free3::SMTI_DigestData(&tempBuffer, &k2);

   // concatenate k1 and k2 to form 40 byte value, use first 24 bytes as TEK
   SME(TEK.Open(SM_FOPEN_WRITE));
   SME(TEK.Write(k1.Access(), k1.Length()));
   SME(TEK.Write(k2.Access(), k2.Length()));

   *pbufKeyAgree = TEK;         // RETURN to caller.
   if (pZZ)
      delete pZZ;
   

#else // CRYPTOPP_5_0
   //SME_THROW(22, "ECDH NOT ENABLED, MUST HAVE Crypto++ 5++!", NULL);
   SME_THROW(22, "MQV1 ECDH NOT ENABLED (Yet)!", NULL);
#endif // CRYPTOPP_5_0

    SME_FINISH
    SME_CATCH_SETUP
      if (pZZ)
          delete pZZ;
      m_ThreadLock.threadUnlock();
    SME_FREE3_CATCH_FINISH
    m_ThreadLock.threadUnlock();

    return(lStatus);
}           // END CSM_Free3::SMTI_GenerateKeyAgreementECDH_MQV(...)


//////////////////////////////////////////////////////////////////////////
long CSM_Free3::SMTI_GenerateKeyAgreementECDH(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            AsnOid *pEncryptionOID,  // IN, specified encryption of key,
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            long lKekLength)        // Input, for SharedInfo load.
{
    long lStatus = 0;
    SecByteBlock *pZZ=NULL;
    SimpleKeyAgreementDomain *pGenericECDH=NULL;
    SimpleKeyAgreementDomain *pGenericECDHKeyGeneration=NULL;
    SecByteBlock *ppriv1=NULL;
    SecByteBlock *ppub1=NULL;
    AsnOid *poidKeyEncrypt = this->GetPrefKeyEncryption();
     AsnOid *pPrefDigest = NULL;
    CSM_Buffer tempBuffer;
    CSM_Buffer *ptempBuff = NULL;
    CSM_Buffer *pTEK=NULL;

    SME_SETUP("CSM_Free3::SMTI_GenerateKeyAgreementECDH");

#ifdef CRYPTOPP_5_0
    bool bcheckResult;

    m_ThreadLock.threadLock();

    bool bECPFlag=true;  // EASIER to use flag than the keep checking OIDs.

    if (pParameters == NULL)
    {
       SME_THROW(22, "ECDH Parameters MUST BE PRESENT (for Ephemeral key construction)!", NULL);
    }
    if (pRecipient == NULL)
    {
       SME_THROW(22, "ECDH pRecipient MUST BE PRESENT (for Ephemeral key construction)!", NULL);
    }

        CryptoPP::ByteQueue bt7;
        bt7.Put((unsigned char *)pParameters->Access(), pParameters->Length());

        if (*poidKeyEncrypt == dhSinglePass_stdDH_sha1kdf_scheme)
        {
          try {
                CryptoPP::ByteQueue bt5=bt7;
                bECPFlag = true;
                ECDH<ECP, NoCofactorMultiplication>::Domain *pDomain = 
                    new ECDH<ECP, NoCofactorMultiplication>::Domain;
                pDomain->AccessGroupParameters().BERDecode(bt5);
                pGenericECDH = pDomain;
                // GENERATE non-Cofactor specific def to build key(s).
                //ECDH<ECP>::Domain *pDomain2 = new ECDH<ECP>::Domain;
                //bt5 = bt7;
                //pDomain2->AccessGroupParameters().BERDecode(bt5);
                pGenericECDHKeyGeneration = pDomain;//pDomain2;
          }       // END try
          catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
          if (!bECPFlag)               // Attempt EC2N private key...
          {
            CryptoPP::ByteQueue bt6=bt7;
            //bt6.Put((unsigned char *)pParameters->Access(), pParameters->Length());
            ECDH<EC2N, NoCofactorMultiplication>::Domain *pDomain = 
                new ECDH<EC2N, NoCofactorMultiplication>::Domain;
            pDomain->AccessGroupParameters().BERDecode(bt6);
            pGenericECDH = pDomain;
            // GENERATE non-Cofactor specific def to build key(s).
            //ECDH<EC2N>::Domain *pDomain2 = new ECDH<EC2N>::Domain;
            //bt6 = bt7;
            //pDomain2->AccessGroupParameters().BERDecode(bt6);
            pGenericECDHKeyGeneration = pDomain; //pDomain2;
          }
        }       // IF dhSinglePass_stdDH_sha1kdf_scheme
        else if (*poidKeyEncrypt == dhSinglePass_cofactorDH_sha1kdf_scheme)
        {
          bECPFlag = false;
          try {
                CryptoPP::ByteQueue bt5=bt7;
                bECPFlag = true;
                ECDH<ECP, CompatibleCofactorMultiplication>::Domain *pDomain = 
                    new ECDH<ECP, CompatibleCofactorMultiplication>::Domain;
                pDomain->AccessGroupParameters().BERDecode(bt5);
                pGenericECDH = pDomain;
          }       // END try
          catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
          if (!bECPFlag)               // Attempt EC2N private key...
          {
            CryptoPP::ByteQueue bt6=bt7;
            //bt6.Put((unsigned char *)pParameters->Access(), pParameters->Length());
            ECDH<EC2N, CompatibleCofactorMultiplication>::Domain *pDomain = 
                new ECDH<EC2N, CompatibleCofactorMultiplication>::Domain;
            pDomain->AccessGroupParameters().BERDecode(bt6);
            pGenericECDH = pDomain;
          }
          pGenericECDHKeyGeneration = pGenericECDH;//pDomain2;
        }       // END IF dhSinglePass_stdDH_sha1kdf_scheme

    if (pGenericECDH == NULL)
    {
       SME_THROW(22, "ECDH Ephemeral key construction FAILED!", NULL);
    }


   // GENERATE ephemeral key pair using incomming recipient's params
   //  (in construction of instance).
   if (m_pEphemeralDHY == NULL)   // ONLY if this is not a shared UKM 
   {                              //  OTHERWISE, re-use other keys.
       ppub1 = new SecByteBlock(pGenericECDH->PublicKeyLength());
       ppriv1 = new SecByteBlock(pGenericECDH->PrivateKeyLength());
       pGenericECDHKeyGeneration->GenerateKeyPair(rndRandom, *ppriv1, *ppub1); 
       if (m_pEphemeralDHX)
           delete m_pEphemeralDHX;
       m_pEphemeralDHY = new CSM_Buffer((const char *)ppub1->data(), ppub1->m_size );
       m_pEphemeralDHX = new CSM_Buffer((const char *)ppriv1->data(), ppriv1->m_size );
       if (m_pEphemeralAlg)
           delete m_pEphemeralAlg;
       AsnOid TmpAlg(id_ecPublicKey);
       m_pEphemeralAlg = new CSM_Alg(TmpAlg);  // NO PARAMS by specification.
   }
   else
   {        // LOAD original private key for re-use 
            //  (ignore public, not used here).
      ppriv1 = new SecByteBlock(m_pEphemeralDHX->Length());
      memcpy(ppriv1->begin(), m_pEphemeralDHX->Access(), ppriv1->m_size);
   }        // END IF Ephemeral Public key defined eariler.


   // Create storage for the resulting agreed upon key and clear it
   pZZ = new SecByteBlock(pGenericECDH->AgreedValueLength());

   memset(*pZZ, 0x00, pZZ->m_size);

   // generate the agreed upon key from this class (this X and
   // provided parameters) and the recipient's public key Y.
   // put the result in AgreedUponKey.  If pRecipient is NULL, then the
   // app is requesting a local key, so use this->m_DHY
   bcheckResult = pGenericECDH->Agree(*pZZ, *ppriv1,  (const unsigned char *)
       pRecipient->Access(),  0);
   if (!bcheckResult)
      SME_THROW(22, "ECDH Key Agreement Failure.", NULL);
#ifdef _DEBUG_TEST_AGREEMENT
    SecByteBlock ZZ2(pGenericECDH->AgreedValueLength());
    SecByteBlock ZZ3(pGenericECDH->AgreedValueLength());
    char *pszPassword = GetPassword();
    CSM_Buffer *pbufX = DecryptPrivateKey(pszPassword, m_pX);
    free (pszPassword);
    bcheckResult = pGenericECDH->Agree(ZZ2, (const unsigned char *)pbufX->Access(),  
                                            *ppub1,  0);
    delete pbufX;
    bcheckResult = pGenericECDHKeyGeneration->Agree(ZZ2, *ppriv1, 
                      (const unsigned char *)m_pBufY->Access(),  0);
    bcheckResult = pGenericECDH->Agree(ZZ3, *ppriv1, *ppub1, 0);
       SecByteBlock pub2(pGenericECDH->PublicKeyLength());
       SecByteBlock priv2(pGenericECDH->PrivateKeyLength());
       pGenericECDHKeyGeneration->GenerateKeyPair(rndRandom, priv2, pub2); 
    bcheckResult = pGenericECDH->Agree(ZZ2, *ppriv1, pub2, 0);
    bcheckResult = pGenericECDH->Agree(ZZ3, priv2, *ppub1, 0);
#endif      // _DEBUG

   SME(BTISetPreferredCSInstAlgs((AsnOid *)&sha_1, NULL, NULL, NULL)); // set md5

   //###### time to generate the TEK
   // generate a random Ra, store in pUKM if we don't already have it
   if (pUKM && pUKM->Access() == NULL)  // Since UKM is optional it may not be
                                        //  passed in; FLAG to use is empty buf
      SME(SMTI_Random(NULL, pUKM, SM_FREE_RA_SIZE/8));

   pTEK = ComputeSharedInfoKeyDerivationFunction(*pZZ, pUKM, 
                                           *pEncryptionOID, lKekLength);

   if (pTEK)
   {
       *pbufKeyAgree = *pTEK;         // RETURN to caller.
       delete pTEK;
   }
   if (pZZ)
      delete pZZ;
   

   delete pGenericECDH;
   if (ppub1)
       delete ppub1;
   if (ppriv1)
       delete ppriv1;
   if (poidKeyEncrypt)
       delete poidKeyEncrypt;


#else // CRYPTOPP_5_0
   SME_THROW(22, "ECDH NOT ENABLED, MUST HAVE Crypto++ 5++!", NULL);
#endif // CRYPTOPP_5_0

    SME_FINISH
    SME_CATCH_SETUP
      if (pZZ)
          delete pZZ;
      if (pGenericECDH)
          delete pGenericECDH;
      if (ppub1)
           delete ppub1;
      if (ppriv1)
           delete ppriv1;
      if (poidKeyEncrypt)
           delete poidKeyEncrypt;
      m_ThreadLock.threadUnlock();
    SME_FREE3_CATCH_FINISH
    m_ThreadLock.threadUnlock();

    return(lStatus);
}           // END CSM_Free3::SMTI_GenerateKeyAgreementECDH(...)

//////////////////////////////////////////////////////////////////////////
long CSM_Free3::SMTI_GenerateKeyAgreementDH(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            CSM_Buffer *pbufX,        // INPUT, clear private key
            AsnOid &oidKeyEncrypt,  // INPUT
            long lKekLength)        // Input, for OtherInfo load.
{
   long lStatus = 0;
   char *pbyte;
   CSM_Buffer tempBuffer;
   CSM_Buffer k1, k2, TEK;
   char achCounter1[] = {0x00, 0x00, 0x00, 0x01};
   char achCounter2[] = {0x00, 0x00, 0x00, 0x02};
   char *pszPassword = NULL; // temp spot for password
   int checkResult;
   // Params may be retrieved from the originator cert; CSInst/CTIL storage 
   //    OR passed in the case of ES-DH (recipient's DH Parameters).
   CSM_Buffer *pParamP; // local DH P Parameter
   CSM_Buffer *pParamG; // local DH G Parameter
   DH *pdhKeyAgreement = NULL;
   unsigned char achX[130];
   SecByteBlock *pZZ=NULL;
   DHParameters snaccDHParameters;
   AsnOid *pPreferredContentOID=NULL;
   CSM_Buffer *ptempBuff=NULL;

   SME_SETUP("CSM_Free3::SMTI_GenerateKeyAgreementDH");

   m_ThreadLock.threadLock();

   if (pEncryptionOID)
      pPreferredContentOID = pEncryptionOID;
   else
      pPreferredContentOID = GetPrefContentEncryption();

   // LOAD Our own originator params if not specified on input.
   if (!pParameters->Length())
   {
       pParamP = &m_ParamP;
       pParamG = &m_ParamG;
       // load current parameters
       Integer p((const unsigned char*)pParamP->Access(), pParamP->Length());
       Integer g((const unsigned char*)pParamG->Access(), pParamG->Length());
       pdhKeyAgreement = new DH(p, g);
   }
   else
   {
       DHParameters snaccDHParameters2;
       // For this ESDH processing, it is expected that the incomming parameters are
       //  already in the CMS Msg params ASN.1 format.
       //RWC;TBD;snaccDHParameters.iv.Set(bufferIV.Access(), bufferIV.Length());
       DECODE_BUF((&snaccDHParameters2), pParameters);
       Integer *pPI = ComputeBigInteger(snaccDHParameters2.p, 128);
       pParamP = ComputeBigIntegerBuf(snaccDHParameters2.p, 128);
       Integer *pGI = ComputeBigInteger(snaccDHParameters2.g, 128);
       pParamG = ComputeBigIntegerBuf(snaccDHParameters2.g, 128);
       //pParamP = new CSM_Buffer(snaccDHParameters.p, snaccDHParameters.p.Len());
       // load current parameters
       //Integer p((const unsigned char*)pParamP->Access(), pParamP->Length());
       //Integer g((const unsigned char*)pParamG->Access(), pParamG->Length());
       pdhKeyAgreement = new DH(*pPI, *pGI);
       delete pPI;
       delete pGI;
       if (snaccDHParameters2.iv.Len())   // use specified Initialization Vector
                                    //  (This is possible if RIs are sharing
                                    //  UKMs, algs & params, which are the IV).
            pbufferIV->Set(snaccDHParameters2.iv.c_str(), snaccDHParameters2.iv.Len());
   }



   if (oidKeyEncrypt == id_dhStatic || // Static Diffie-Hellman, use originator's params.
       oidKeyEncrypt == dh_public_number)
   {
       // create dh class and set it's p, g, and x.
       // note, being able to set the x like this requires modification
       // of the DH class in dh.h to make x public.
       Integer *pxInt; // then convert it into a Crypto++ Integer
       pxInt = sm_Free3CryptoppBERDecode(pbufX->Access(), pbufX->Length());
           //.BERDecode(pbyte);   //x.Encode(&achX[0], 128);
       //sm_Free3CryptoppDEREncode(*pxInt, &achX[0], 128);
       pxInt->Encode(&achX[0], 128);
       delete pxInt;
   }
   else if (oidKeyEncrypt == id_alg_ESDH)
               // Ephemeral-Static Diffie-Hellman, use passed params, NOT OUR OWN.
   {
     if (m_pEphemeralDHY == NULL)   // ONLY if this is not a shared UKM 
     {
       SecByteBlock priv1(pdhKeyAgreement->PrivateKeyLength());
       SecByteBlock pub1(pdhKeyAgreement->PublicKeyLength());
       pdhKeyAgreement->GenerateKeyPair(*m_pRng, priv1, pub1);
       SecByteBlock val(pdhKeyAgreement->AgreedValueLength());
       bool TestAgree = pdhKeyAgreement->Agree(val, priv1, pub1);
       if (!TestAgree)     // JUST test our own.
            SME_THROW(22, "*********DH Key TestAgree failed**********.", NULL);
       // NOW BEREncode DHX to be consistent with remainder of library.
       Integer y; // then convert it into a Crypto++ Integer
#ifndef CRYPTOPP_5_0
       y.Decode(pub1.ptr, pub1.size);
       char *ptr = (char *) calloc(1,pub1.size*2);
       int ii = sm_Free3CryptoppDEREncode(y, (unsigned char *)ptr,pub1.size*2);
                                        // Now, when extracted, DER encoded.
       m_pEphemeralDHX = new CSM_Buffer((char *)priv1.ptr, priv1.size );
                     // Ephermeral public key to be passed to recipient.
#else // CRYPTOPP_5_0
       y.Decode(pub1, pub1.m_size);
       char *ptr = (char *) calloc(1,pub1.m_size*2);
       int ii = sm_Free3CryptoppDEREncode(y, (unsigned char *)ptr,pub1.m_size*2);
                                        // Now, when extracted, DER encoded.
       m_pEphemeralDHX = new CSM_Buffer((char *)priv1.data(), priv1.m_size );
                     // Ephermeral public key to be passed to recipient.
#endif // CRYPTOPP_5_0
       m_pEphemeralDHY = new CSM_Buffer(ptr,ii); // sized for encoded int
       free(ptr);
       if (m_pEphemeralAlg)
           delete m_pEphemeralAlg;

       if (oidKeyEncrypt == id_dhStatic ||
           oidKeyEncrypt == dh_public_number)
           m_pEphemeralAlg = new CSM_Alg(oidKeyEncrypt);
       else if (oidKeyEncrypt == id_alg_ESDH)
       {
           AsnOid TmpDHOid(dh_public_number);
           m_pEphemeralAlg = new CSM_Alg(TmpDHOid);
       }
       if (m_pEphemeralAlg->parameters)
       {
           delete m_pEphemeralAlg->parameters;
           m_pEphemeralAlg->parameters = NULL;
       }        // END IF parameters present.
       //RWC;2/7/00; REMOVED due to specification; the remote end is expected to
       //RWC;  extract the params from the recipient certificate for processing
       //RWC;  with this dynamic public key.
       //RWC;m_pEphemeralAlg->parameters = new AsnAny;
       //RWC;SM_ASSIGN_ANYBUF(pParameters, m_pEphemeralAlg->parameters);
       //RWC;pParameters->SetLength(0);
     }
     Integer x; // then convert it into a Crypto++ Integer
     x.Decode((byte *)m_pEphemeralDHX->Access(), m_pEphemeralDHX->Length()); 
                                            // RWC; DO NOT USE BERDecode()...
     x.Encode(&achX[0], 128);
   }

   //RWC;dhKeyAgreement.x = x; // this can't be done with the default DH class,
   // TBD, need to find a way to load X into DH without modifying DH's 
   // declaration

   // Create storage for the resulting agreed upon key and clear it
   pZZ = new SecByteBlock(pdhKeyAgreement->AgreedValueLength());

 #ifndef CRYPTOPP_5_0
  memset(pZZ->ptr, 0x00, pZZ->size);
#else // CRYPTOPP_5_0
  memset(*pZZ, 0x00, pZZ->m_size);
#endif // CRYPTOPP_5_0

   // generate the agreed upon key from this class (this X and
   // provided parameters) and the recipient's public key Y.
   // put the result in AgreedUponKey.  If pRecipient is NULL, then the
   // app is requesting a local key, so use this->m_DHY
   Integer *pyInt;
   long len;
   if (pRecipient)
   {
      SME(pbyte = (char *)pRecipient->Access());
      len = pRecipient->Length();
   }
   else
   {
      if (m_pBufY)
      {
          SME(pbyte = (char *)m_pBufY->Access());
          len = m_pBufY->Length();
      }
      else
      {
           SME_THROW(22, "MUST HAVE DH Public Key for this feature!", NULL);
      }

   }
   pyInt = sm_Free3CryptoppBERDecode(pbyte, len);//y.BERDecode(pbyte);
   unsigned char achY[130];
   pyInt->Encode(&achY[0], 128);
   delete pyInt;
   //RWC; updated parameter list;dhKeyAgreement.Agree(&achY[0], ZZ);
   checkResult = pdhKeyAgreement->Agree(*pZZ, (const unsigned char *)
       &achX[0]/*RWC;pbufX->Access()*/, &achY[0],0);   // AgreekeyOut, PrivateKeyIn, PublicKeyIn
   if (!checkResult)
      SME_THROW(22, "DH Key Agreement Failure.", NULL);

/////RWC;TBD;CHECK THAT PRIVATE KEY MAY HAVE TO BE DECODED>>>>!!!!!????

   // ASN.1 encode the Parameters
   snaccDHParameters.p.Set((const unsigned char *)pParamP->Access(), pParamP->Length());
   snaccDHParameters.g.Set((unsigned char *)pParamG->Access(), pParamG->Length());
   snaccDHParameters.iv.Set((const char *)pbufferIV->Access(), pbufferIV->Length());
   ENCODE_BUF_NO_ALLOC(&snaccDHParameters, pParameters);

   if (pZZ == NULL)
   {
        SME_THROW(22, "BAD Key Agreement Calculation!", NULL);
   }        // END IF pZZ empty
   SME(BTISetPreferredCSInstAlgs((AsnOid *)&sha_1, NULL, NULL, NULL));
   //##### GENERATE the TEK, given the key agreement data
   // UKM is stored in the incoming pUKM
   // generate a random Ra, store in pUKM if we don't already have it
   if (pUKM && pUKM->Access() == NULL)  // Since UKM is optional it may not be
                                        //  passed in; FLAG to use is empty buf
      SME(SMTI_Random(NULL, pUKM, SM_FREE_RA_SIZE/8));

   // concatentate ZZ, encoded oid, counter1, Ra
   SME(tempBuffer.Open(SM_FOPEN_WRITE));
   #ifndef CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->ptr, pZZ->size));
   #else // CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->data(), pZZ->m_size));
   #endif // CRYPTOPP_5_0
   ptempBuff = EncodeOtherInfo(pUKM, achCounter1, *pPreferredContentOID, 
       lKekLength);
   //ptempBuff->ConvertMemoryToFile("c:\\tmp\\OtherInfo3.out");
   SME(tempBuffer.Write((ptempBuff->Access()), ptempBuff->Length()));
   delete ptempBuff;
   ptempBuff = NULL;
   tempBuffer.Close();
   // now hash
   CSM_Free3::SMTI_DigestData(&tempBuffer, &k1);
   //tempBuffer.ConvertMemoryToFile("c:\\tmp\\OtherInfo4.out");
   // concatentate ZZ, encoded oid, counter2, Ra
   SME(tempBuffer.Open(SM_FOPEN_WRITE));
   #ifndef CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->ptr, pZZ->size));
   #else // CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->data(), pZZ->m_size));
   #endif // CRYPTOPP_5_0
   ptempBuff = EncodeOtherInfo(pUKM, achCounter2, *pPreferredContentOID ,lKekLength);
   SME(tempBuffer.Write((ptempBuff->Access()), ptempBuff->Length()));
   delete ptempBuff;
   ptempBuff = NULL;
   tempBuffer.Close();
   // now hash
   CSM_Free3::SMTI_DigestData(&tempBuffer, &k2);

   // concatenate k1 and k2 to form 40 byte value, use first 24 bytes as TEK
   SME(TEK.Open(SM_FOPEN_WRITE));
   SME(TEK.Write(k1.Access(), k1.Length()));
   SME(TEK.Write(k2.Access(), k2.Length()));
   *pbufKeyAgree = TEK;

   if (pszPassword)
      free (pszPassword);
   delete pdhKeyAgreement;
   if (pParamP && pParamP != &m_ParamP)
       delete pParamP;
   if (pParamG && pParamG != &m_ParamG)
       delete pParamG;
   if (pZZ)
       delete pZZ;

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
      // figure out what we need to clean up and do it...
      // cleanup bufferIV?
      // close pMEK and pEMEK if necessary
      if (pszPassword)
         free (pszPassword);
      if (pZZ)
          delete pZZ;
      m_ThreadLock.threadUnlock();
   SME_FREE3_CATCH_FINISH
   m_ThreadLock.threadUnlock();

   return(lStatus);
}           // END CSM_Free3::SMTI_GenerateKeyAgreementDH(...)





////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  SMTI_GeneratePWRIKeyWrap
//
//  Description:  The key wrap algorithm encrypts a CEK (pData) with a KEK in a manner
//                which ensures that every bit of plaintext effects every bit
//                of ciphertest. The key wrap algorithm is perfomrd in two phases:
//
//                First phase which formats the CEK into a form suitable
//                for encryption by the KEK. 
//
//                Second phase build the KEK from
//                the pPassword if pPWRIDerivationAlg is input or 
//                use pUserKeyEncryptionKey directly if input as the KEK.
//                If neither the pPWRIDerivationAlg or pUserKeyEncryptionKey, this function
//                builds the KEK by defaulting the derivation Alg to id-PBKDF2.
//                
//                Then finally wraps the formatted CEK (pData) using the KEK.
//                 
//                      
//  Output:
//
//  Return:
//
SM_RET_VAL CSM_Free3::SMTI_GeneratePWRIKeyWrap(
            CSM_Buffer *pData, // IN  cek to be encrypted by KEK derived from password
            CSM_Buffer *pEncryptedData, // output double encrypted pData
            CSM_Buffer *pIV,  // IN, to avoid specific alg encoding by app.encryption alg iv
            CSM_Buffer *pPassword,   // IN    
            CSM_Buffer *pUserKeyEncryptionKey, // IN, Optional
            CSM_AlgVDA    *&pPWRIDerivationAlg,  // IN, OUT PWRI id-PBKDF2 for now, optional
            CSM_AlgVDA    *&pPWRIEncryptionAlg)  // IN, OUT PWRI id-alg-PWRI-KEK for now
{
   SM_RET_VAL status=0;
   CSM_Buffer *pCEKBlock = new CSM_Buffer;
   CSM_Buffer *pCEKTmp = new CSM_Buffer;
   CSM_Buffer PAD;
   CSM_Buffer *pbufEncodedEncryptionParams=NULL;
   int        nIterCount = 1;  // create in pwriDerivationAlg in parameter
   int        dkLen = 0;
   int        CBC_Length, CBC_KeyLength; 
   long       lStatus=0;
   unsigned char LENGTH;
   PKCS5_PBKDF2_HMAC<SHA1> pbkdf;
   PBKDF2_params snaccPBKDF2EncryptionParams;
   CSM_Buffer *pSalt   = NULL; // salt for derivation alg optional
   CSM_Buffer *pBufKey = NULL; // key-encryption key; either derived or user supplied


   SME_SETUP("CSM_Free3::SMTI_GeneratePWRIKeyWrap(...)");
 
   // Check incoming parameters
   if (pData && (pData->Length() == 0) ||
       pPassword && (pPassword->Length() == 0))
      SME_THROW(22, "No Data input!", NULL);
   if (pEncryptedData == NULL)
      SME_THROW(22, "No input parameter for Encrypted Data!", NULL);

   if (pPWRIEncryptionAlg != NULL)
   {   
      // check the id-Alg-PWRI-KEK and throw if not there
      if (pPWRIEncryptionAlg->algorithm != id_alg_PWRI_KEK)
         SME_THROW(22, "EncryptionAlgorithm Error!", NULL);

      // decode the key encryption alg params
      CSM_Buffer *pTmpCEAlgBuf = pPWRIEncryptionAlg->GetParams();
      
      // determine content encryption
      if (pTmpCEAlgBuf)
      {
         CSM_Alg CEAlg;
         DECODE_BUF(&CEAlg, pTmpCEAlgBuf);
         delete pTmpCEAlgBuf;
           
         // find algid before setting

          // we have to trick SMTI_Decrypt to not perform pad check
         if (CEAlg.algorithm == des_ede3_cbc || CEAlg.algorithm == id_alg_CMS3DESwrap) 
            BTISetPreferredCSInstAlgs(NULL, NULL, NULL, (AsnOid *)&id_alg_CMS3DESwrap);
      
         if (CEAlg.algorithm == rc2_cbc || CEAlg.algorithm == id_alg_CMSRC2wrap) 
            BTISetPreferredCSInstAlgs(NULL, NULL, NULL, (AsnOid *)&id_alg_CMSRC2wrap);
        
         // extract the iv - put it in pIV
         pIV = CEAlg.GetParams();
      }

   }

   // get the preferred content Encryption oid which may have been 
   // reset if the parameters were passed in pPWRIEncryptionAlg
   AsnOid     *pPreferredOID = GetPrefContentEncryption();

   // determine length of cbc block and key
   if (*pPreferredOID == des_ede3_cbc || *pPreferredOID == id_alg_CMS3DESwrap) 
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
   }
   else if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap)
   {
      CBC_Length = SM_COMMON_RC2_BLOCKSIZE; // 8
      CBC_KeyLength = SM_COMMON_RC2_KEYLEN; // byte count 16 
   }
   else if (*pPreferredOID == dES_CBC)
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = 8;                     // for DES.
   }
   else          // Default to 3DES length.
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
   }



   // **** INITIALIZE IV if necessary for encyrptionAlg 
   if (pIV == NULL || pIV->Length() == 0)
   {
      if (pIV == NULL)
         pIV = new CSM_Buffer;
      SME(SMTI_Random(NULL, pIV, CBC_Length));

   }       // END if pIV not pre-filled

   // check pPWRIDerivationAlg 
   if (pPWRIDerivationAlg == NULL && pUserKeyEncryptionKey != NULL)
   {
      // have a key-encryption key already - no need to derive one
      
      // check length
      if (pUserKeyEncryptionKey->Length() < CBC_KeyLength)
      {
         // too short - throw error
         char buf[100];
         sprintf(buf, "KeyEncryptionKey too short, key should be %d long", CBC_KeyLength);
         SME_THROW(22, buf, NULL);
         
      }
      else if (pUserKeyEncryptionKey->Length() > CBC_KeyLength)
      {
         // too long - truncate
         pBufKey = new CSM_Buffer(pUserKeyEncryptionKey->Access(),
            CBC_KeyLength);
      }
      else
      {
         // just right
         pBufKey = new CSM_Buffer(pUserKeyEncryptionKey->Access(), 
            pUserKeyEncryptionKey->Length());
      }

   }
   else if (pPWRIDerivationAlg == NULL && pUserKeyEncryptionKey == NULL)
   {   
      pPWRIDerivationAlg = new CSM_Alg;
  
      // no keyEncryptionalgorithm in config file
      // default to 1.2.840.113549.1.5.12 id-PBKDF2 for now
      AsnOid *pOID=new AsnOid(id_PBKDF2);
      pPWRIDerivationAlg->algorithm = *pOID;
      delete pOID;

      // set the parameters:
      if (pSalt == NULL)
      {
         pSalt = new CSM_Buffer;
         SME(SMTI_Random(NULL, pSalt, CBC_Length));

      }
      // set salt and iteration count
      snaccPBKDF2EncryptionParams.iterationCount = nIterCount;
      snaccPBKDF2EncryptionParams.salt.Set(pSalt->Access(), pSalt->Length());

      // set keyLength
    //  snaccPBKDF2EncryptionParams.keyLength = CBC_KeyLength;

      /*
      // set prf set
     // pOID=new AsnOid("1.2.840.113549.2.7");  // id-hmacWithSHA1
      snaccPBKDF2EncryptionParams.prf = new CSM_Alg;
      snaccPBKDF2EncryptionParams.prf->algorithm = *pPreferredOID; // 3des
      delete pPreferredOID;

      snaccPBKDF2EncryptionParams.prf->parameters = new AsnAny;
      CSM_Buffer *pTmpBuf=CSM_Alg::GetNullParams();
      
      SM_ASSIGN_ANYBUF(pTmpBuf, snaccPBKDF2EncryptionParams.prf->parameters);
      delete pTmpBuf;
      */      
      ENCODE_BUF(&snaccPBKDF2EncryptionParams, pbufEncodedEncryptionParams);

      if (pPWRIDerivationAlg->parameters == NULL)
          pPWRIDerivationAlg->parameters = new AsnAny;

      
      SM_ASSIGN_ANYBUF(pbufEncodedEncryptionParams, pPWRIDerivationAlg->parameters);
   
      // clean up
      delete pbufEncodedEncryptionParams;
      pbufEncodedEncryptionParams = NULL;
   }
   else
   {
      // use the data from the pPWRIDerivation input parameter

      // check the oid  and throw if not supported  id-PBKDF2
      if (pPWRIDerivationAlg->algorithm != id_PBKDF2)
         SME_THROW(22,"Key Derivation Algorithm not supported", NULL);

      // extract the data that the user might have set
      CSM_Buffer *pDerParamsBuf;
      
      // then access and set the salt (Salt) and iteration count
      if ((pDerParamsBuf = (*pPWRIDerivationAlg).GetParams()) == NULL)
         SME_THROW(22, "Unable to GetParams from Derivation Alg.", NULL);   

      SME(pDerParamsBuf->Decode(snaccPBKDF2EncryptionParams));
      if (pDerParamsBuf != NULL)
         delete pDerParamsBuf;

      // get the params into something that is useful
      nIterCount = snaccPBKDF2EncryptionParams.iterationCount;
      pSalt = new CSM_Buffer(snaccPBKDF2EncryptionParams.salt.c_str(), snaccPBKDF2EncryptionParams.salt.Len());

      // if the user has specified keyLength 
      // check to see if it is CBC_KeyLength and throw if not
 //?     if (snaccPBKDF2EncryptionParams.keyLength != CBC_KeyLength)
 //        SME_THROW(NULL, "PBKDF KeyLength error!", NULL);

      // if prf != PBKDF2-PRFS then throw sib tbd


      ENCODE_BUF(&snaccPBKDF2EncryptionParams, pbufEncodedEncryptionParams);

      if (pPWRIDerivationAlg->parameters == NULL)
          pPWRIDerivationAlg->parameters = new AsnAny;
  
      SM_ASSIGN_ANYBUF(pbufEncodedEncryptionParams, pPWRIDerivationAlg->parameters);
  
      // clean up
      delete pbufEncodedEncryptionParams;      
      pbufEncodedEncryptionParams = NULL;
   }
   
   // FIRST PHASE:  Create a formatted CEK block consisting of the following:
   // CEK byte count || check value || KEK || padding (if required)

   // prep for formatting the CEK block:
   // Step 1. Create LENGTH for padding with enough random padding data to make the 
   // CEK data block a multiple of the KEK block length and at least two
   // KEK cipher blocks long (the fact that 32 bits of count+check value are
   // used, means that even with a 40-bit CEK, the resulting data size
   // will always be at least two (64-bit) cipher blocks long)
   LENGTH = (unsigned char)pData->Length();

   // Step 2. build check value containing the bitwise complement of the first
   // three bytes of the CEK
   // get the first 3 bytes of the CEK
   unsigned char checkval[3];
   for (int i = 0; i < 3; ++i)
   {
      checkval[i] = (unsigned char)~pData->Access()[i];
   }
   
   // Step 4.  random Padding
   // pData->Length (3DES is 24) + 1 byte for CEK byte count + 3 bytes for Check Value
   SME(SMTI_Random(NULL, &PAD, 8 - ((pData->Length() + 4) % 8))); 

   //rfc3211 Steps to build pCEKICV out of incoming CEK.
   pCEKBlock = new CSM_Buffer();
   SME(pCEKBlock->Open(SM_FOPEN_WRITE));
   SME(pCEKBlock->Write((char *)&LENGTH, 1));              // Step 1. CEK byte count 
   SME(pCEKBlock->Write((char *)checkval, 3)); // Step 2. check value
   SME(pCEKBlock->Write(pData->Access(), pData->Length()));// Step 3. CEK
   SME(pCEKBlock->Write(PAD.Access(), PAD.Length()));      // Step 4. Padding
   pCEKBlock->Close();

   // SECOND PHASE: Derive the KEK from pPassword if necessary
   if (pUserKeyEncryptionKey == NULL)
   {
      // this probably shouldn't be here since a salt was needed above
      // to create the derivationAlgorthm set - just in case
      if (pSalt != NULL && pSalt->Length() == 0)
      {
         SME(SMTI_Random(NULL, pSalt, CBC_Length));
      }

      // string password, salt; EXPECTED RESULT IS derivedKey;
       SecByteBlock derived(CBC_KeyLength);
       pbkdf.GeneralDeriveKey(derived, 
         CBC_KeyLength,
         0x03,
         (const unsigned char *)pPassword->Access(),
         pPassword->Length(),                  // password length
         (const unsigned char *)pSalt->Access(), 
         pSalt->Length(),                         // salt length
         nIterCount);
        
      pBufKey = new CSM_Buffer((const char *)(unsigned char *)derived, derived.size());
   }

   if(*pPreferredOID == des_ede3_cbc ||
      *pPreferredOID == id_alg_CMS3DESwrap ||
      *pPreferredOID == dES_CBC)
   {
      // Check parity for incomming 3DES key.
      unsigned char *ptr3=(unsigned char *)pBufKey->Access();
      for (int i=0; i < (int)pBufKey->Length(); i++)
      {
         if (!CryptoPP::Parity((unsigned long)ptr3[i]))
            ptr3[i] ^= 0x01;
      }
   }

   // Encrypt the padded key pCEKBlock using the KEK (pBufKey)
   CSM_Buffer parameters;    
   CSM_Buffer TmpEncryptedData;

   SME(lStatus = SMTI_Encrypt(pCEKBlock, &TmpEncryptedData, &parameters, 
      pBufKey, pIV));
   
   // Without resetting the IV (that is , using the last ciphertest block
   // as the IV), encrypt the encrypted padded key a second time
   CSM_Buffer IV2(&TmpEncryptedData.Access()[TmpEncryptedData.Length() - CBC_Length], 
                  CBC_Length);
   
   CSM_Buffer TmpEncryptedData2;

   CSM_Buffer parameters2;

   SME(lStatus = SMTI_Encrypt(&TmpEncryptedData, &TmpEncryptedData2, &parameters2, 
      pBufKey, &IV2));
     
   SME(pEncryptedData->Open(SM_FOPEN_WRITE));

   // loading the second smti encrypt initilization vector
   SME(pEncryptedData->Write(IV2.Access(), IV2.Length()));            
   SME(pEncryptedData->Write(TmpEncryptedData2.Access(), TmpEncryptedData2.Length())); //
   pEncryptedData->Close();

   if (pPWRIEncryptionAlg != NULL)
   {
      delete pPWRIEncryptionAlg;
   }
   
  
   // get the details of the encryption
   pPWRIEncryptionAlg = new CSM_Alg;
   AsnOid *pOID=new AsnOid(id_alg_PWRI_KEK);
   pPWRIEncryptionAlg->algorithm = *pOID;
   delete pOID;

   // fill in the parameters
   pPWRIEncryptionAlg->parameters = new AsnAny;
   SNACC::AlgorithmIdentifier tmpAlg;
   tmpAlg.algorithm = *pPreferredOID;
   tmpAlg.parameters = new AsnAny;

   // assigning the parameters from the first smti encrypt
   SM_ASSIGN_ANYBUF(&parameters, tmpAlg.parameters);
   
   // encode the content algid
   CSM_Buffer tmpAlgBuf;
   tmpAlgBuf.Encode(tmpAlg);
   SM_ASSIGN_ANYBUF(&tmpAlgBuf, pPWRIEncryptionAlg->parameters);

   // Clean-up
   if (pBufKey)
   {
      delete pBufKey;
      pBufKey = NULL;
   }

   if (lStatus != 0)
   {
       SME_THROW(22, "CSM_Free3::SMTI_GeneratePWRIKeyWrap:Encrypt error", NULL);
   }

   SME_FINISH
   SME_CATCH_SETUP

   // Clean-up
   if (pBufKey)
   {
      delete pBufKey;
      pBufKey = NULL;
   }

   SME_FREE3_CATCH_FINISH

   return(status);
}       // END CSM_Free3::SMTI_GeneratePWRIKeyWrap(...)

////////////////////////////////////////////////////////////////////////////////
//
// Function Name:  SMTI_GenerateKeyWrap
//
// Description:    Function determine if the preferred algorithm is AES and if
//                 so then it calls the SM_AES_KeyWrap() function.  Otherwise 
//                 it will call the SMTI_GenerateKeyWrapInternal that takes care
//                 of RC2, DES, and 3DES algs.
//
// Inputs:
//          CSM_Buffer *pData            Data to be encrypted
//          CSM_Buffer *pMEK             Encryption Key
//          CSM_Buffer *pIV              Initialization vector
//
// Outputs:
//          CSM_Buffer *pEncryptedData   output
//          CSM_Buffer *pMEK             Encryption Key
//          CSM_Buffer *pParameters      For KeyAgree algs.
//
// Returns: status     if 0 - success, otherwise unsuccessful 
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_GenerateKeyWrap(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV)  // In, to avoid specific alg encoding by app.
{
   SM_RET_VAL status=0;
   CSM_Buffer *pCEKICV = NULL;
   CSM_Buffer Iv,PAD;  
   CSM_Buffer TEMP3;
   CSM_Buffer tmp;
   AsnOid    *pPreferredOID = this->GetPrefContentEncryption();
   long lStatus=0;

   SME_SETUP("CSM_Free3::SMTI_GenerateKeyWrap")

   if ((*pPreferredOID == id_aes256_CBC || *pPreferredOID == id_aes256_wrap) ||
      (*pPreferredOID == id_aes192_CBC || *pPreferredOID == id_aes192_wrap) ||
      (*pPreferredOID == id_aes128_CBC || *pPreferredOID == id_aes128_wrap))
   {
      // first check to make sure that the key is => pData
      if (pData->Length() > pMEK->Length())
      {
         SME_THROW(SM_AES_KEYLENGTH_ERROR, 
            "ERROR:  Data length is larger than AES key length!", NULL);
      } 

      // this call takes care of AES wrapping
      lStatus = SM_AES_KeyWrap(*pMEK, *pData, *pEncryptedData);
   }   
   else
   {
      // this call takes care of the DES, #3Des, and RC2
      lStatus = SMTI_GenerateKeyWrapInternal(pData, pEncryptedData, pParameters, 
                                          pMEK, pIV);
   }

   if (lStatus != 0)
   {
       SME_THROW(SM_FREE_UNSUPPORTED_ALG, 
           "CSM_Free3::SMTI_GenerateKeyWrap:Unsupported alg", NULL);
   }


   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH

   return(status);
}          // END CSM_Free3::SMTI_GenerateKeyWrap(...)
 
//
//  This logic is separated out to handle KARI and KEK CMS processing which
//  both use the same KeyWrap algorithm and processing.
SM_RET_VAL CSM_Free3::SMTI_GenerateKeyWrapInternal(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV)  // In, to avoid specific alg encoding by app.
{
   SM_RET_VAL status=0;
   CSM_Buffer *pCEKICV = NULL;
   CSM_Buffer Iv,PAD;  
   CSM_Buffer TEMP3;
   CSM_Buffer tmp;
   unsigned char LENGTH;
   AsnOid    *pPreferredOID = GetPrefContentEncryption();

   SME_SETUP("CSM_Free3::SMTI_GenerateKeyWrap")

   m_ThreadLock.threadLock();
   if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap) // key wrap for rc2_cbc
   {
      // CMS-13 Step 1 Create LENGTH
      LENGTH = (unsigned char)pData->Length();
      SME(SMTI_Random(NULL, &PAD, 8 - ((pData->Length() + 1) % 8)));

      //CMS-13 Step 3 build pCEKICV out of incomming CEK and ICV data.
      pCEKICV = new CSM_Buffer();
      SME(pCEKICV->Open(SM_FOPEN_WRITE));
      SME(pCEKICV->Write((char *)&LENGTH, 1));
      SME(pCEKICV->Write(pData->Access(), pData->Length()));
      SME(pCEKICV->Write(PAD.Access(), PAD.Length()));
      pCEKICV->Close();
   }
   else if (*pPreferredOID == des_ede3_cbc || *pPreferredOID == id_alg_CMS3DESwrap) 
   {   
      //CMS-11 Step 3 build pCEKICV out of incomming CEK and ICV data.
      pCEKICV = new CSM_Buffer();
      SME(pCEKICV->Open(SM_FOPEN_WRITE));
      SME(pCEKICV->Write(pData->Access(), pData->Length()));
      pCEKICV->Close();

   }
   else
       status = -1;     // ALG not supported.

   // Finish KeyWrap processing using the CSM_Common class.
   if (status == 0)
      status = CSM_Common::SMTI_GenerateKeyWrapFinish(pEncryptedData, pParameters,
            pMEK, pIV, pCEKICV);  // extra param is raw data in.
   if (pCEKICV)
       delete pCEKICV;
   if (pPreferredOID)
       delete pPreferredOID;

   SME_FINISH
   SME_CATCH_SETUP
       m_ThreadLock.threadUnlock();
       if (pCEKICV)
           delete pCEKICV;
       if (pPreferredOID)
           delete pPreferredOID;
   SME_FREE3_CATCH_FINISH
   m_ThreadLock.threadUnlock();

   return(status);
}           // END CSM_Free3::SMTI_GenerateKeyWrapInternal(...)

//
//  This logic is separated out to handle KARI and KEK CMS processing which
//  both use the same KeyWrap algorithm and processing.
SM_RET_VAL CSM_Free3::SMTI_ExtractKeyWrapFinish(
            CSM_Buffer *pData, // Output
            CSM_Buffer &CEKICVPAD)  // Input
{
   SM_RET_VAL status=0;
   CSM_Buffer CEK;
   unsigned int LENGTH=0;
   AsnOid *pPreferredOID = GetPrefContentEncryption();  

  
   SME_SETUP("CSM_Free3::SMTI_ExtractKeyWrapFinish");

   // determine 3des or rc2 loading of data to use 
   if (*pPreferredOID == id_alg_CMSRC2wrap)
   {
      LENGTH = (int)CEKICVPAD.Access()[0];

      // determine length of the key and set, then assign it to output pData parameter
      if (LENGTH <= CEKICVPAD.Length()-1 && (CEKICVPAD.Length()-(LENGTH+1)) < 8)
      {                  // Enough to contain CEK and Pad (less than 8 bytes)
         CEK.Set(&CEKICVPAD.Access()[1], LENGTH);
      }

      // CMS-13 STEP 10(RC2) use the CEK as the data to encrypt
      *pData = CEK;       // pass back to user.

   }   
   else if ((*pPreferredOID == id_aes128_wrap) ||// key wrap for Aes
            (*pPreferredOID == id_aes192_wrap) ||
            (*pPreferredOID == id_aes256_wrap) )
   {
      // code for AES/CryptoPP
      LENGTH = (int)CEKICVPAD.Access()[0];

      // determine length of the key and set, then assign it to output pData parameter
      if (LENGTH <= CEKICVPAD.Length()-1 && (CEKICVPAD.Length()-(LENGTH+1)) < 8)
      {                  // Enough to contain CEK and Pad (less than 8 bytes)
         CEK.Set(&CEKICVPAD.Access()[1], LENGTH);
      }

      // CMS-13 STEP 10(RC2) use the CEK as the data to encrypt
      *pData = CEK;       // pass back to user.

   }
   else // 3des
   {  
      // CMS-13 STEP 9(3DES) use the CEK as the data to encrypt
      *pData = CEKICVPAD;       // pass back to user.
      // NOW, set parity since this calculation does not produce parity proper 
      //  results for 3DES.  This logic was removed from 3DES decrypt in order
      //  to support Million Message Attack issues (RFC3218).
      unsigned char *ptr3=(unsigned char *)pData->Access();
      for (long ii=0; ii < pData->Length(); ii++)
          if (!CryptoPP::Parity((unsigned long)ptr3[ii]))
              ptr3[ii] ^= 0x01;
   }
   if (pPreferredOID)
       delete pPreferredOID;

   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH

   return(status);
}


//////////////////////////////////////////////////////////////////////////
//  This logic is separated out to handle PWRI Key Extract processing 
//
SM_RET_VAL CSM_Free3::SMTI_ExtractPWRIKeyWrap(
            CSM_Buffer &MEK, // Output
            const CSM_Buffer EncryptedData, // IN
            const CSM_Buffer Password, // IN password
            CSM_Buffer *pUserKeyEncryptionKey, // IN, Optional
                  CSM_AlgVDA    *pPWRIDerivationAlg,  // IN, OUT PWRI id-PBKDF2 for now optional
                  CSM_AlgVDA    *pPWRIEncryptionAlg)  // IN, OUT PWRI id-alg-PWRI-KEK for now
{
   SM_RET_VAL status = -1;
   CSM_Buffer *pIV = NULL;
   CSM_Buffer *pIV2 = NULL;
   CSM_Buffer *pSalt = NULL;
   CSM_Buffer TEMP3, TEMP2, TEMP1;
   CSM_Buffer *pIVParams = new CSM_Buffer();
   int        CBC_Length, CBC_KeyLength; 
   PKCS5_PBKDF2_HMAC<SHA1> pbkdf;
   PBKDF2_params snaccPBKDF2EncryptionParams;
   AsnOid     *pPreferredOID = NULL;
   CSM_Buffer *pBufKey = NULL;
   int i;

   SME_SETUP("CSM_Free3::SMTI_ExtractPWRIKeyWrap");
  
   m_ThreadLock.threadLock();

   if (EncryptedData.Length() == 0)
      SME_THROW(22, "No input parameter for Encrypted Data!", NULL); 
   if (pPWRIDerivationAlg == NULL && pUserKeyEncryptionKey == NULL)
      SME_THROW(22,"This ctil requires the pwri derivation algorithm or a user supplied key-encryption key", NULL);

   // get the 2nd iv from the encrypted alg params
   CSM_Buffer *pEncParms = pPWRIEncryptionAlg->GetParams();
   if (pEncParms)
   {
      CSM_Alg CEAlg;
      DECODE_BUF(&CEAlg, pEncParms);

      pIV2 = CEAlg.GetParams();

      pPreferredOID = new AsnOid(CEAlg.algorithm);

      // we have to trick SMTI_Decrypt to not perform pad check
      if (*pPreferredOID == des_ede3_cbc || *pPreferredOID == id_alg_CMS3DESwrap) 
         BTISetPreferredCSInstAlgs(NULL, NULL, NULL, (AsnOid *)&id_alg_CMS3DESwrap);
      
      if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap) 
         BTISetPreferredCSInstAlgs(NULL, NULL, NULL, (AsnOid *)&id_alg_CMSRC2wrap);
        
     delete pEncParms;
   } 

   if (pPreferredOID == NULL)
   {
      // get the preferred content Encryption oid
      pPreferredOID = GetPrefContentEncryption();
   }

   // determine length of key
   if (*pPreferredOID == des_ede3_cbc || *pPreferredOID == id_alg_CMS3DESwrap) 

   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
   }
   else if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap)
   {
      CBC_Length = SM_COMMON_RC2_BLOCKSIZE; // 8
      CBC_KeyLength = SM_COMMON_RC2_KEYLEN; // byte count 16 
   }
   else if (*pPreferredOID == dES_CBC)
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = 8;                     // for DES.
   }
   else          // Default to 3DES length.
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
   }     
   
   // decode the derivationAlgorithm and get the iv and iteration count
   // check the oid  and throw if not supported  id-PBKDF2
   if (pUserKeyEncryptionKey == NULL && pPWRIDerivationAlg->algorithm != id_PBKDF2)
      SME_THROW(22,"Key Derivation Algorithm not supported", NULL);

   if (pUserKeyEncryptionKey == NULL)
   {
      // extract the data that the user might have set for the key derivation
      CSM_Buffer *pDerParamsBuf = NULL;
      CSM_Buffer params;
        
      // then access and set the salt (Salt) and iteration count
      if ((pDerParamsBuf = (*pPWRIDerivationAlg).GetParams()) == NULL)
         SME_THROW(22, "Unable to GetParams from Derivation Alg.", NULL);   

      SME(pDerParamsBuf->Decode(snaccPBKDF2EncryptionParams));
      if (pDerParamsBuf != NULL)
         delete pDerParamsBuf;

      // get the params into something that is useful
      int nIterCount = snaccPBKDF2EncryptionParams.iterationCount;
      pSalt = new CSM_Buffer(snaccPBKDF2EncryptionParams.salt.c_str(), snaccPBKDF2EncryptionParams.salt.Len());

      // Derive the KEK from pPassword  
      // string password, salt; EXPECTED RESULT IS derivedKey;
       SecByteBlock derived(CBC_KeyLength);
       pbkdf.GeneralDeriveKey(derived, 
         CBC_KeyLength,
         0x03,  // id # for key derivation
         (const unsigned char *)Password.Access(),
         Password.Length(),                  // password length
         (const unsigned char *)pSalt->Access(), 
         pSalt->Length(),                         // salt length
         nIterCount);   
      pBufKey = new CSM_Buffer((const char *)(unsigned char *)derived, derived.size());
   }
   else
   {        
      // have a key-encryption key already - no need to derive one
      
      // check length
      if (pUserKeyEncryptionKey->Length() < CBC_KeyLength)
      {
         // too short - throw error
         char buf[100];
         sprintf(buf, "KeyEncryptionKey too short, key should be %d long", CBC_KeyLength);
         SME_THROW(22, buf, NULL);
         
      }
      else if (pUserKeyEncryptionKey->Length() > CBC_KeyLength)
      {
         // too long - truncate
         pBufKey = new CSM_Buffer(pUserKeyEncryptionKey->Access(),
            CBC_KeyLength);
      }
      else
      {
         // just right
         pBufKey = new CSM_Buffer(pUserKeyEncryptionKey->Access(), 
            pUserKeyEncryptionKey->Length());
      }

   }

   if (*pPreferredOID == des_ede3_cbc ||
       *pPreferredOID == id_alg_CMS3DESwrap ||
      *pPreferredOID == dES_CBC)
   {
      // Check parity for incomming 3DES key.
      unsigned char *ptr3=(unsigned char *)pBufKey->Access();
      for (i=0; i < (int)pBufKey->Length(); i++)
      {
         if (!CryptoPP::Parity((unsigned long)ptr3[i]))
            ptr3[i] ^= 0x01;
      }
   }     // END IF 3DES (ONLY)

   if (pSalt != NULL)
   {
      delete pSalt;
      pSalt = NULL;
   }

   // Key Unwrapping
   CSM_Buffer IV(&EncryptedData.Access()[0], CBC_Length);

   CSM_Buffer first_n_1thTextBlock(&EncryptedData.Access()[CBC_Length], 
                  EncryptedData.Length() - CBC_Length);

   LoadParams(IV, pIVParams); // load into CTIL Param format for Decrypt.

   // DECRYPT using pParameters
   SME(SMTI_Decrypt(pIVParams, &first_n_1thTextBlock, pBufKey, &TEMP1));

   if(pIVParams != NULL)
   {
      delete pIVParams;
      pIVParams = NULL;
   }


   // TEMP3 should hold the decrypted data on output
   //                iv     ciphertext key             output
   SME(SMTI_Decrypt(pIV2, &TEMP1,    pBufKey, &TEMP3));

   if (pIV!= NULL)
   {
      delete pIV;
      pIV = NULL;
   }

   if (pIV2!= NULL)
   {
      delete pIV2;
      pIV2 = NULL;
   }
   if (pPreferredOID!= NULL)
   {
      delete pPreferredOID;
      pPreferredOID = NULL;
   }

   if (pBufKey)
   {
      delete pBufKey;
      pBufKey = NULL;
   }

   // Key format verification:
   // 1a.  If the CEK byte count is less than the minimum allowed key size
   //      (usually 5 bytes for 40-bit keys) or greater that the wrapped
   //      CEK algorithm (eg not 16 or 24 bytes for triple DES), the 
   //      KEK was invalid
   unsigned int LENGTH = 0;
   LENGTH = (int)TEMP3.Access()[0];
   if (LENGTH > (TEMP3.Length() - 4))
      SME_THROW(22, "Error or Invalid Length KEK decryption", NULL);

   // 1b.  If the bitwise complement of the key check value doesn't match
   //      the first three bytes of the key, the KEK was invalid.
   // get the first 3 bytes of the mek
   // first 3 bytes of  MEK data used for bitwise complement
   unsigned char ucharBuf[3];
   ucharBuf[0] = (unsigned char)~TEMP3.Access()[1];
   ucharBuf[1] = (unsigned char)~TEMP3.Access()[2];
   ucharBuf[2] = (unsigned char)~TEMP3.Access()[3];

   // get the mek for output
   MEK.Open(SM_FOPEN_WRITE);
   MEK.Write(&TEMP3.Access()[4], TEMP3.Length() - 4); // cek plus padding
   MEK.Close();

   // bitwise complement check of first 3 bytes of key
   if (memcmp(ucharBuf, MEK.Access(),3) != 0)
      SME_THROW(22, "Error or Invalid CheckValue of PWRI decryption", NULL);

   // strip off the padding  size of MEK is LENGTH (1st byte of decrypted key)
   // reset the size of the MEK buffer
   MEK.SetLength(LENGTH);
   
   // check padding length against the cek byte cnt + check value + CEK 
   if ((TEMP3.Length() % (CBC_Length)) != 0)
      SME_THROW(22, "Error with pwri padding length.", NULL);
   
   status = 0;  // success 

   SME_FINISH
   SME_CATCH_SETUP
   
      // clean up     
      if (pBufKey)
      {
         delete pBufKey;
         pBufKey = NULL;
      }

      if (pIV != NULL)
      {
         delete pIV;
         pIV = NULL;
      }

      if (pSalt != NULL)
      {
         delete pSalt;
         pSalt = NULL;
      }
      if(pIVParams != NULL)
      {
         delete pIVParams;
         pIVParams = NULL;
      }

      if (pIV2!= NULL)
      {
         delete pIV2;
         pIV2 = NULL;
      }

      if (pPreferredOID!= NULL)
      {
         delete pPreferredOID;
         pPreferredOID = NULL;
      }

      m_ThreadLock.threadUnlock();

   SME_FREE3_CATCH_FINISH
      
   m_ThreadLock.threadUnlock();

   return status;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function Name:  SMTI_ExtractKeyWrap
//
// Description:    Function calls proper function according to preferred oid to
//                 extract the keywrap data from data input in pData.
//
// Inputs:
//                 CSM_Buffer* pEncryptedData,   data to extract from
//                 CSM_Buffer* pParameters,      for KeyAgree algs.
//                 CSM_Buffer* pTEK,             Token encryption key
//                 CSM_Buffer* pIV               initialization vector
//
// Outputs:
//                 CSM_Buffer *pData,            content encryption key
//
// Returns:        0 - successful otherwise unsuccessful
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_ExtractKeyWrap(
       CTIL::CSM_Buffer* pData,         // Output
       CTIL::CSM_Buffer* pEncryptedData,// input
       CTIL::CSM_Buffer* pParameters,   // IN, for KeyAgree algs.
       CTIL::CSM_Buffer* pTEK,          // in
       CTIL::CSM_Buffer* pIV)           // In

{
   SM_RET_VAL status=-1;      // return status
   AsnOid*    m_pKeyWrapOID = GetPrefContentEncryption(); // preferred oid

   SME_SETUP("CSM_Free3::SMTI_ExtractKeyWrap");

   // check incoming parameters
   if ((pEncryptedData == NULL)  || (pEncryptedData->Length() <= 0) ||
       (pTEK == NULL))
      SME_THROW(SM_MISSING_PARAM, "Missing Parameter", NULL);

   // if oid is AES SMTI_ExtractKeyWrap
   if (*m_pKeyWrapOID == id_aes128_CBC ||
       *m_pKeyWrapOID == id_aes192_CBC ||
       *m_pKeyWrapOID == id_aes256_CBC ||
       *m_pKeyWrapOID == id_aes128_wrap ||
       *m_pKeyWrapOID == id_aes192_wrap ||
       *m_pKeyWrapOID == id_aes256_wrap)
   {
      // sending in NULL for the IV parameter since the function will
      // build one of the correct size and data
      status = SM_AES_KeyUnwrap(*pTEK, *pEncryptedData, *pData, NULL);
   }
   else
   {
      // call the common keywrap function
      status = CSM_Common::SMTI_ExtractKeyWrap(pData, pEncryptedData, 
                                               pParameters, pTEK, pIV);
   }

   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH

   return status;

} // end SMTI_ExtractKeyWrap


//////////////////////////////////////////////////////////////////////////
// decrypt input into output using the provided cbc decryption
void CSM_Free3::RawDecrypt(CSM_Buffer *pbufInput, CSM_Buffer *pbufOutput,
      #ifndef CRYPTOPP_5_0
      Filter *pCBCDecryption)
      #else   // CRYPTOPP_5_0
      StreamTransformation  *pCBCDecryption)
      #endif  // CRYPTOPP_5_0
{
   RawDecrypt(pbufInput, pbufOutput, pCBCDecryption, 
      SM_COMMON_3DES_BLOCKSIZE);      // Default to 3DES content encryption.
}

//////////////////////////////////////////////////////////////////////////
// decrypt input into output using the provided cbc decryption with block
// length input parameter 
void CSM_Free3::RawDecrypt(CSM_Buffer *pbufInput, CSM_Buffer *pbufOutput,
      #ifndef CRYPTOPP_5_0
      Filter *pCBCDecryption,
      #else   // CRYPTOPP_5_0
      StreamTransformation  *pCBCDecryption,
      #endif  // CRYPTOPP_5_0
      int iINBlockLen)
{
   char *achIn     =(char *)calloc(1,iINBlockLen + 1);
   char *achOut    =(char *)calloc(1,iINBlockLen + 1);
   char *achInNext =(char *)calloc(1,iINBlockLen + 1);

   SM_RET_VAL lBlockLen;
   SM_RET_VAL lNextBlockLen = 0;
   long       getStatus;

   SME_SETUP("CSM_Free3::RawDecrypt");
   // open input for reading

   SME(pbufInput->Open(SM_FOPEN_READ));

   // open output for writing
   SME(pbufOutput->Open(SM_FOPEN_WRITE));

   // read input from pEncryptedData, cbc decrypt it, and write decrypted
   // result to pData WHILE we have full blocks
   // ...read first block then try to read the next block
   if ((lBlockLen = pbufInput->cRead(&achIn[0], iINBlockLen))
            == iINBlockLen)
   {
      lNextBlockLen = pbufInput->cRead(&achInNext[0], iINBlockLen);
   }
   while (lBlockLen == iINBlockLen)
   {
      // do cbc process
#ifndef CRYPTOPP_5_0
      pCBCDecryption->Put((const unsigned char *) &achIn[0], iINBlockLen);
      //RWC; "->Put(...) calls ProcessBuf(...);pCBCEncryption->ProcessBuf();
      getStatus = pCBCDecryption->Get((unsigned char *)&achOut[0],iINBlockLen);
#else // CRYPTOPP_5_0
      pCBCDecryption->ProcessData((byte *)&achOut[0], (const byte *)&achIn[0], iINBlockLen);
      getStatus = iINBlockLen;
#endif // CRYPTOPP_5_0
      if (getStatus) // ONLY if data is present; must prime the input first.
      {
         SME(pbufOutput->Write(&achOut[0], getStatus));
      }
      // do we currently have the last block?
      if (lNextBlockLen != iINBlockLen)
      {
         if (getStatus)
         {
#ifndef CRYPTOPP_5_0
            #ifdef CRYPTOPP_3_2
           pCBCDecryption->InputFinished();
            #else
           pCBCDecryption->MessageEnd();
            #endif
           getStatus = pCBCDecryption->Get((unsigned char *) &achOut[0], 
               iINBlockLen);
           while (getStatus)
           {
               SME(pbufOutput->Write(&achOut[0], getStatus));
               getStatus = pCBCDecryption->Get((unsigned char *) &achOut[0], 
                  iINBlockLen);
           }
#else // CRYPTOPP_5_0
           //pCBCDecryption->ProcessData((byte *)&achOut[0], (const byte *)&achIn[0], iINBlockLen);
           pCBCDecryption->ProcessLastBlock((byte *)&achOut[0], 
                                      (const byte *)&achIn[0], lNextBlockLen);
           getStatus = lNextBlockLen; // pCBCDecryption->MinLastBlockSize();
#endif // CRYPTOPP_5_0
         }      // END if (getStatus)
         lBlockLen = lNextBlockLen; // TERMINATE the while loop.
      }         // IF if (lNextBlockLen != iINBlockLen)
      else
      {
         // no, what is in achIn is not the final block, write it all
         // and move the next block into achIn
         memcpy(&achIn[0], &achInNext[0], iINBlockLen);
         // read the next block
         SME(lNextBlockLen = pbufInput->cRead(&achInNext[0], iINBlockLen));
      }     // END if (lNextBlockLen != iINBlockLen)
   }        // END while (lBlockLen == iINBlockLen)

   pbufInput->Close();
   pbufOutput->Close();
   free(achIn);
   free(achInNext);
   free(achOut);

   SME_FINISH_CATCH
}


////////////////////////////////////////////////////////////////////////////////
//
// Function Name:  SMTI_Decrypt
// 
// Description:    This routine handles 3DES RC2 and AES content decryption algs.
//
// Inputs:   CSM_Buffer *pEncryptedData      Input (data to be decrypted)
//           CSM_Buffer *pParameters         For KeyAgree algs
//           CSM_Buffer *pMEK                Key to encrypt with may be specified
//
// Outputs:  CSM_Buffer *pData               Decrypted output
//
// Returns:  SM_NO_ERROR - If no exception occurred
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_Decrypt(
            CSM_Buffer *pParameters, // input (initialization vector)
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK, // input (MEK or special phrase)
            CSM_Buffer *pData) // output (decrypted data)
{
   //char *pIV;
   int i;
   int CBC_Length, CBC_KeyLength; 
   RC2Decryption *prc2Decryption = NULL;
   AESDecryption* pAesDecryption = NULL;
#ifndef CRYPTOPP_5_0
   CBCPaddedDecryptor *pcbc_PADdecryption=NULL;
    #ifdef CRYPTOPP_3_2
   VDA_CBCNotPaddedDecryptor_3_2 *pcbc_NotPaddeddecryption=NULL;
    #else
   CBCRawDecryptor *pcbc_NotPaddeddecryption=NULL;
    #endif
   Filter *pcbc_decryption=NULL;
   DES_EDE3_Decryption *p3desDecryption = NULL;
   DESDecryption *pdesDecryption = NULL;
#else // CRYPTOPP_5_0
   StreamTransformation *pcbc_decryption=NULL;
#endif // CRYPTOPP_5_0
   CSM_Buffer *pParamDecodedBuf=NULL;
   CSM_Buffer *pIv = NULL;

   SME_SETUP("CSM_Free3::SMTI_DecryptCryptoPP");

   // check incoming parameters
   if (pData == NULL  || pEncryptedData == NULL 
       || pEncryptedData->Access() == NULL || pParameters == NULL
       || pMEK == NULL || pMEK->Access() == NULL)
      SME_THROW(SM_FREE_MISSING_PARAM, "MISSING Parameters", NULL);

   // check for valid MEK
   if (strncmp(pMEK->Access(), SM_FREE_FORTENC, 
         strlen(SM_FREE_FORTENC)) == 0)
      SME_THROW(SM_FREE_UNSUPPORTED_ALG, 
            "Cannot use skipjack MEK", NULL);
   
   AsnOid *pPreferredOID = GetPrefContentEncryption();

   // check algorithm oids
   if (! ((*pPreferredOID == des_ede3_cbc) ||
          (*pPreferredOID == id_alg_CMS3DESwrap) ||
          (*pPreferredOID == dES_CBC) || 
          (*pPreferredOID == rc2_cbc) || 
          (*pPreferredOID == id_alg_CMSRC2wrap) ||
          (*pPreferredOID == id_aes128_CBC) ||
          (*pPreferredOID == id_aes256_CBC) ||
          (*pPreferredOID == id_aes192_CBC) ||
          (*pPreferredOID == id_aes128_wrap) ||
          (*pPreferredOID == id_aes192_wrap) ||
          (*pPreferredOID == id_aes256_wrap)) )
   {
         // algorithm not valid
       if (pPreferredOID)
          delete (pPreferredOID);
       return 2;
   }

   // set block size and key length
   if (*pPreferredOID == des_ede3_cbc) 
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
   }
   else if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap )
   {
      CBC_Length = SM_COMMON_RC2_BLOCKSIZE; // 8
      CBC_KeyLength = SM_COMMON_RC2_KEYLEN; // 16 byte count 128 bits;
   }
   else if (*pPreferredOID == dES_CBC) 
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = 8;                    // FOR DES.
   } 
   else if (*pPreferredOID == id_aes128_CBC) 
   {
      CBC_Length = AES_128;
      CBC_KeyLength = AES_128/8;                   // for AES 128/8 = 16.
   }
   else if (*pPreferredOID == id_aes192_CBC)
   {
      CBC_Length = AES_128;
      CBC_KeyLength = AES_192/8;                  // for AES 192/8 = 24.
   }
   else if (*pPreferredOID == id_aes256_CBC)
   {
      CBC_Length = AES_128;
      CBC_KeyLength = AES_256/8;                  // for AES 256/8 = 32.
   }   
   else          // Default to 3DES length.
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
   } 

   // check for preferred oid content encryption or key wrap oid
   if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap)
   {  
      int keybits = 0;

      // decode the parameters to get the keybits and the IV  
      pIv = UnloadParams(pPreferredOID, *pParameters, keybits);

      if (keybits != 0)
      {
         CBC_KeyLength = keybits/8;  // bytes
      }
      
      if (pMEK->Length() < (unsigned int)CBC_KeyLength) // FIX IT;key should 
      {
         CSM_Buffer *pTmpBuf2=new CSM_Buffer((size_t)pMEK->Length());//RWC;CBC_KeyLength);
         pTmpBuf2->SetLength(CBC_KeyLength);
         memcpy((void *)pTmpBuf2->Access(), pMEK->Access(), pMEK->Length());
         char *ptr3=(char *)pTmpBuf2->Access();
         for (i=(int)pMEK->Length(); i < (int)pTmpBuf2->Length(); i++)
            ptr3[i] = '\0';      // zero fill key
         *pMEK = *pTmpBuf2;  //RWC; check for memory leak
         delete pTmpBuf2;
      }
 
      if (pIv->Access() == NULL)
         SME_THROW(22, "Missing IV in preparation for decryption!", NULL);

      // create cbc object           
      if (*pPreferredOID == rc2_cbc) 
      {
          prc2Decryption = new RC2Decryption((const unsigned char*)pMEK->Access(),
             pMEK->Length(), CBC_KeyLength * 8);
#ifndef CRYPTOPP_5_0
          // create the rc2 cipher using the mek
          pcbc_PADdecryption=new CBCPaddedDecryptor(*prc2Decryption, 
             (const  unsigned char *)pIv->Access());
          pcbc_decryption = pcbc_PADdecryption;
#else // CRYPTOPP_5_0
          //RWC;DOES NOT WORK, MUST USE EXTERNAL;
          //CBC_Mode/*CFB_Mode*/<RC2>::Decryption *pTmpDecryption = new CBC_Mode/*CFB_Mode*/<RC2>::Decryption;
          //pTmpDecryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), pMEK->Length()*8,//CBC_KeyLength, 
          //              (const unsigned char *)pIv->Access());
          //pTmpDecryption->SetKeyWithEffectiveKeyLength((const unsigned char*)pMEK->Access(), pMEK->Length(), CBC_KeyLength);
          CBC_Mode_ExternalCipher::Decryption *pTmpDecryption = new CBC_Mode_ExternalCipher::Decryption(*prc2Decryption, 
             (const  unsigned char *)pIv->Access());
          pcbc_decryption = pTmpDecryption;
#endif // CRYPTOPP_5_0
      }
      else      // NO PADDING on KeyWrap.
      {
          prc2Decryption = new RC2Decryption((const unsigned char*)pMEK->Access(),
             pMEK->Length()/*CBC_KeyLength*/, CBC_KeyLength * 8);
#ifndef CRYPTOPP_5_0
          // create the rc2 cipher using the mek
         #ifdef CRYPTOPP_3_2
         // using the new vda defined class that will handle no padding
         // CBC_CTS_Encryptor cannot handle no padding
         pcbc_NotPaddeddecryption=new VDA_CBCNotPaddedDecryptor_3_2(*prc2Decryption, 
            (const  unsigned char *)pIv->Access());
         #else
         pcbc_NotPaddeddecryption=new CBCRawDecryptor(*prc2Decryption, 
            (const  unsigned char *)pIv->Access());
         #endif
         pcbc_decryption = pcbc_NotPaddeddecryption;
#else // CRYPTOPP_5_0
          // RWC;1/10/02; TEMPORARY, MUST BE RE-Created to not pad data....
          //RWC;DOES NOT WORK, MUST USE EXTERNAL;
          //CBC_Mode/*CFB_Mode*/<RC2>::Decryption *pTmpDecryption = new CBC_Mode/*CFB_Mode*/<RC2>::Decryption;
          //pTmpDecryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), pMEK->Length()*8,//CBC_KeyLength, 
          //              (const unsigned char *)pIv->Access());
          //pTmpDecryption->SetKeyWithEffectiveKeyLength((const unsigned char*)pMEK->Access(), pMEK->Length(), CBC_KeyLength);
          CBC_Mode_ExternalCipher::Decryption *pTmpDecryption = new CBC_Mode_ExternalCipher::Decryption(*prc2Decryption, 
             (const  unsigned char *)pIv->Access());
          pcbc_decryption = pTmpDecryption;
#endif // CRYPTOPP_5_0

      } 
      
      // decrypt the data sending in the block length
      SME(RawDecrypt(pEncryptedData, pData, pcbc_decryption, CBC_Length));
   }
   else if ((*pPreferredOID == id_aes128_CBC || *pPreferredOID == id_aes128_wrap) ||
            (*pPreferredOID == id_aes192_CBC || *pPreferredOID == id_aes192_wrap) ||
            (*pPreferredOID == id_aes256_CBC || *pPreferredOID == id_aes256_wrap) )
   {
      int keybits = 0;

      // decode the parameters to get the keybits and the IV  
      pIv = UnloadParams(pPreferredOID, *pParameters, keybits);

      if (keybits != 0)
      {
         CBC_KeyLength = keybits/8;  // bytes
      }
 
      // check the IV 
      if (pIv->Access() == NULL)
         SME_THROW(22, "Missing IV in preparation for decryption!", NULL);

      // create a AESDecryption object using the MEK and length
      pAesDecryption = new AESDecryption((const unsigned char*)pMEK->Access(),
         pMEK->Length(), CBC_KeyLength * 8);

      // create the externlCipher object in CBC mode
      CBC_Mode_ExternalCipher::Decryption *pTmpDecryption = new   
         CBC_Mode_ExternalCipher::Decryption(*pAesDecryption, 
         (const  unsigned char *)pIv->Access());

      // point to the decryption object for use in decrypt call later
      pcbc_decryption = pTmpDecryption;

      // decrypt the data sending in the block length
      SME(RawDecrypt(pEncryptedData, pData, pcbc_decryption, CBC_Length));

   }
   else  // 3DES
   {
      // unload the parameters
      pParamDecodedBuf = UnloadParams(pPreferredOID, *pParameters);

      if (pParamDecodedBuf == NULL)
         SME_THROW(SM_FREE_PARAM_DEC_ERROR, "MUST HAVE 3DES PARAMS.", NULL);

      if (*pPreferredOID != dES_CBC &&
           pMEK->Length() < (unsigned int)CBC_KeyLength) //FIX IT;key should be
      {                                         //  24 for best encryption.
         CSM_Buffer *pTmpBuf2=new CSM_Buffer((size_t)CBC_KeyLength);//RWC;CBC_KeyLength);
         char *ptr3=(char *)pTmpBuf2->Access();
         memcpy(ptr3, pMEK->Access(), pMEK->Length());
         for (i=(int)pMEK->Length(); i < (int)pTmpBuf2->Length(); i++)
            ptr3[i] = 0x01;      // zero fill key
         *pMEK = *pTmpBuf2;  //RWC; check for memory leak
         delete pTmpBuf2;
      }

      // Check parity for incomming 3DES key.
      // RWC;4/4/01;CHECK to see if DES requires parity update, may need to be
      //   moved under "des_ede3_cbc" OID check!!!!!!!
      unsigned char *ptr3=(unsigned char *)pMEK->Access();
      for (i=0; i < (int)pMEK->Length(); i++)
      {
         if (!CryptoPP::Parity((unsigned long)ptr3[i]))
         {
            // THIS ERROR was made fatal to avoid Million Message Attacks, 
            //  RFC3218.
            #ifndef IGNORE_MILLION_MESSAGE_ATTACK_CHECK
                 // BREAK the MEK; make it a random value to finish operations,
                 //  According to RFC3218, consistent timing makes it difficult for
                 //  MMA to determine keys.  It will still break, but later in 
                 //  processing.
                #ifndef CRYPTOPP_5_0
                m_pRng->GetBlock((unsigned char *)ptr3, pMEK->Length());
                #else // CRYPTOPP_5_0
                for (long ii=0; ii < pMEK->Length(); ii++)
                   ptr3[ii] = (char)m_pRng->GenerateByte();
                #endif // CRYPTOPP_5_0
                for (long ii2=0; ii2 < (int)pMEK->Length(); ii2++)
                   if (!CryptoPP::Parity((unsigned long)ptr3[ii2]))
                       ptr3[ii2] ^= 0x01;
            #else  // IGNORE_MILLION_MESSAGE_ATTACK_CHECK
            ptr3[i] ^= 0x01;
            #endif // IGNORE_MILLION_MESSAGE_ATTACK_CHECK
         }
      }

      // create cbc object
      if (*pPreferredOID == des_ede3_cbc) 
      {
#ifndef CRYPTOPP_5_0
          // create our cipher
          p3desDecryption = new DES_EDE3_Decryption((const unsigned char*)pMEK->Access());
          pcbc_PADdecryption=new CBCPaddedDecryptor(*p3desDecryption,  
              (const unsigned char*)pParamDecodedBuf->Access());
          pcbc_decryption = pcbc_PADdecryption;
#else // CRYPTOPP_5_0
          CBC_Mode/*CFB_Mode*/<DES_EDE3>::Decryption *pTmpDecryption = new CBC_Mode/*CFB_Mode*/<DES_EDE3>::Decryption;
          pTmpDecryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), CBC_KeyLength, 
                        (const unsigned char *)pParamDecodedBuf->Access());
          pcbc_decryption = pTmpDecryption;
#endif // CRYPTOPP_5_0
      }
      else if (*pPreferredOID == dES_CBC) 
      {
#ifndef CRYPTOPP_5_0
          // create our cipher
          pdesDecryption = new DESDecryption((const unsigned char*)pMEK->Access());
          pcbc_PADdecryption=new CBCPaddedDecryptor(*pdesDecryption,  
              (const unsigned char*)pParamDecodedBuf->Access());
          pcbc_decryption = pcbc_PADdecryption;
#else // CRYPTOPP_5_0
          CBC_Mode/*CFB_Mode*/<DES>::Decryption *pTmpDecryption = new CBC_Mode/*CFB_Mode*/<DES>::Decryption;
          pTmpDecryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), CBC_KeyLength, 
                        (const unsigned char *)pParamDecodedBuf->Access());
          pcbc_decryption = pTmpDecryption;
#endif // CRYPTOPP_5_0
      }
      else      // NO PADDING on KeyWrap.
      {
#ifndef CRYPTOPP_5_0
          p3desDecryption = new DES_EDE3_Decryption((const unsigned char*)pMEK->Access());
          #ifdef CRYPTOPP_3_2
          // using the new vda defined class that will handle no padding
          // CBC_CTS_Encryptor cannot handle no padding
          pcbc_NotPaddeddecryption=new VDA_CBCNotPaddedDecryptor_3_2(*p3desDecryption, 
             (const  unsigned char *)pParamDecodedBuf->Access());
          #else
          pcbc_NotPaddeddecryption=new CBCRawDecryptor(*p3desDecryption, 
             (const  unsigned char *)pParamDecodedBuf->Access());
          #endif
          pcbc_decryption = pcbc_NotPaddeddecryption;
#else // CRYPTOPP_5_0
          // RWC;1/10/02; TEMPORARY, MUST BE RE-Created to not pad data....
          CBC_Mode/*CFB_Mode*/<DES_EDE3>::Decryption *pTmpDecryption = new CBC_Mode/*CFB_Mode*/<DES_EDE3>::Decryption;
          pTmpDecryption->SetKeyWithIV((const unsigned char*)pMEK->Access(), CBC_KeyLength, 
                        (const unsigned char *)pParamDecodedBuf->Access());
          pcbc_decryption = pTmpDecryption;
#endif // CRYPTOPP_5_0
      }

      // decrypt the data
      SME(RawDecrypt(pEncryptedData, pData, pcbc_decryption));

   } // end 3des perferred oid

   // clean up
#ifndef CRYPTOPP_5_0
   if (*pPreferredOID == des_ede3_cbc || *pPreferredOID == dES_CBC ||
       *pPreferredOID == rc2_cbc) 
   {
       delete pcbc_PADdecryption;
   }
   else      // NO PADDING on KeyWrap.
   {
       delete pcbc_NotPaddeddecryption;
   }
   if (pdesDecryption)
      delete pdesDecryption;

   if (p3desDecryption)
      delete p3desDecryption;
#else // CRYPTOPP_5_0
    if (*pPreferredOID == des_ede3_cbc || *pPreferredOID == dES_CBC ||
        *pPreferredOID == rc2_cbc || (*pPreferredOID == id_aes128_CBC) ||
          (*pPreferredOID == id_aes256_CBC) ||
          (*pPreferredOID == id_aes192_CBC) ||
          (*pPreferredOID == id_aes128_wrap) ||
          (*pPreferredOID == id_aes192_wrap) ||
          (*pPreferredOID == id_aes256_wrap))
   {
        // RWC; unpad logic due to lack of unpad logic in Crypto++ 
        //  (or at least I could not locate it).
       long lExtra = pData->Length() % CBC_Length;
       unsigned char *achIn = (unsigned char *)pData->Access();
       if (lExtra == 0) // IT IS PADDED, so remove the padding.
       {
           lExtra = achIn[pData->Length()-1];   // USE last byte as padding value

           if (lExtra <= CBC_Length)
           {
            for (int ii = 0; ii < lExtra; ii++)
               if (achIn[pData->Length()-1-ii] != lExtra)
               {
                   SME_THROW(22, "BAD Decryption Inner Pad value!", NULL);
               }
             pData->SetLength(pData->Length()-lExtra);  //SHRINK buffer returned.
           }    // END if (lExtra < 8)
           else
           {
               SME_THROW(22, "BAD Decryption Pad value!", NULL);
           }    // END IF pad value check
       }        // END if lExtra
    }       // END if PAD OID used.

    delete pcbc_decryption;
#endif // CRYPTOPP_5_0
   if (prc2Decryption)
      delete prc2Decryption;
   if (pAesDecryption)
      delete pAesDecryption;


   delete pPreferredOID;
   delete pParamDecodedBuf;

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
      // cleanup pMEK, in, out
      // close these if open
      if (pData)
        pData->Close();
      if (pEncryptedData)
        pEncryptedData->Close();
      if (pParamDecodedBuf)
         delete pParamDecodedBuf;
   SME_FREE3_CATCH_FINISH

   return SM_NO_ERROR;
}
 

////////////////////////////////////////////////////////////////////////////////
//
// Function Name:  SMTI_ExtractKeyAgreement
// 
// Description:    This routine calls function to extract the key according to
//                 preferred Key Encryption oid.
//
// Inputs:   CSM_Buffer * pOriginator   Y of originator
//           CSM_Buffer * pUKM          UserKeyMaterial (random number).
//           CSM_Buffer *pbufferIV      Initialization vector, part of DH params.
//           AsnOid * pEncryptionOID    specified encryption of key
//           long     lKekLength        length of key encryption key
//
// Outputs:  CSM_Buffer * pbufKeyAgree  encryption key for this recip
//           CSM_Buffer * pUKM          UserKeyMaterial (random number).
//           CSM_Buffer *pbufferIV      Initialization vector, part of DH params.
//
// Returns:  SM_NO_ERROR - If no exception occurred
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_ExtractKeyAgreement(
            CSM_Buffer *pOriginator, // input, Y of originator
            //CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  //RWC;TBD;REMOVE
                              // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            long lKekLength)        // Input, for OtherInfo load.                         
{
   CSM_Buffer *pbufX = NULL; // temp spot for X value
   char *pszPassword = NULL; // temp spot for password
   CSM_Buffer *pbufKeyAgree2=NULL;  // temp
   CSM_Buffer *ptempBuff = NULL;
   AsnOid *pPreferredContentOID=NULL;
   AsnOid *pPrefDigest = NULL;
   SecByteBlock *pZZ=NULL;
   AsnOid *poidKeyEncrypt = this->GetPrefKeyEncryption();

   SME_SETUP("CSM_Free3::SMTI_ExtractKeyAgreement");

   m_ThreadLock.threadLock();
   // check incoming parameters
   if ((pOriginator == NULL) || /*RWC;ESDH optional (pUKM == NULL) || */
       pbufKeyAgree == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   if (pEncryptionOID)
      pPreferredContentOID = pEncryptionOID;
   else
      pPreferredContentOID = GetPrefContentEncryption();
   SME(pPrefDigest = GetPrefDigest()); // save current digest alg
   SME(BTISetPreferredCSInstAlgs((AsnOid *)&sha_1, NULL, NULL, NULL)); // set md5

   // load current private key X
   SME(pszPassword = GetPassword()); // get the password
   // and then use the password to decrypt the EncryptedPrivateKeyInfo
   SME(pbufX = DecryptPrivateKey(pszPassword, m_pX));

   //###### CHECK for various supported KARI algs (DH, ESDH, ECDH (various types)).
   if (*poidKeyEncrypt == id_dhStatic ||      // Static Diffie-Hellman, use originator's params.
       *poidKeyEncrypt == id_alg_ESDH ||
       *poidKeyEncrypt == dh_public_number)
   {
       pbufKeyAgree2 = SMTI_ExtractKeyAgreementDH(pUKM, pPreferredContentOID, 
                                              lKekLength, pOriginator, pbufX);
       *pbufKeyAgree = *pbufKeyAgree2;
       delete pbufKeyAgree2;
   }        // IF DH/ESDH
   else if (*poidKeyEncrypt == dhSinglePass_stdDH_sha1kdf_scheme ||
            *poidKeyEncrypt == dhSinglePass_cofactorDH_sha1kdf_scheme)
   {
       pbufKeyAgree2 = SMTI_ExtractKeyAgreementECDH(pUKM, pPreferredContentOID, 
                                                lKekLength, pOriginator, pbufX);
       *pbufKeyAgree = *pbufKeyAgree2;
       delete pbufKeyAgree2;
   }        // IF ECDH dhSinglePass
   else if (*poidKeyEncrypt == mqvSinglePass_sha1kdf_scheme)
   {
   }        // END IF ECDH mqvSinglePass

   
   if (pbufKeyAgree->Length() > SM_COMMON_RC2_KEYLEN && 
      (*pPreferredContentOID == rc2_cbc || 
       *pPreferredContentOID  == id_alg_CMSRC2wrap))
       pbufKeyAgree->SetLength(SM_COMMON_RC2_KEYLEN);   // OVERRIDE RC2, force.
               // THIS OVERRIDE is necessary for RC2 DH key wrap compatibility.
   else if (pbufKeyAgree->Length() > lKekLength &&
            *pPreferredContentOID == id_aes128_CBC ||
            *pPreferredContentOID == id_aes192_CBC ||
            *pPreferredContentOID == id_aes256_CBC ||
            *pPreferredContentOID == id_aes128_wrap ||
            *pPreferredContentOID == id_aes192_wrap ||
            *pPreferredContentOID == id_aes256_wrap)
       pbufKeyAgree->SetLength(lKekLength);   // OVERRIDE AES, force.
   else if (*pPreferredContentOID == des_ede3_cbc || 
            *pPreferredContentOID  == id_alg_CMS3DESwrap)
   {        // PARITY SET logic for 3DES moved here for decryption to avoid
            //  Million Message Attacks RFC3218.
      // Check parity for incomming 3DES key.
      // RWC;4/4/01;CHECK to see if DES requires parity update, may need to be
      //   moved under "des_ede3_cbc" OID check!!!!!!!
      unsigned char *ptr3=(unsigned char *)pbufKeyAgree->Access();
      for (int ii=0; ii < (int)pbufKeyAgree->Length(); ii++)
      {
         if (!CryptoPP::Parity((unsigned long)ptr3[ii]))
            ptr3[ii] ^= 0x01;
      }     // END FOR each byte in 3DES MEK
   }        // END IF 3DES

   free (pszPassword);
   delete pbufX;
   if (pPreferredContentOID && pPreferredContentOID != pEncryptionOID)
       delete pPreferredContentOID;
   if (pPrefDigest)
   {
        BTISetPreferredCSInstAlgs(pPrefDigest, NULL, NULL, NULL);
        delete pPrefDigest;
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
      // figure out what we need to clean up and do it...
      // close pMEK and pEMEK if necessary
      if (pszPassword)
         free (pszPassword);
      if (pbufX)
         delete pbufX;
      if (pPreferredContentOID && pPreferredContentOID != pEncryptionOID)
         delete pPreferredContentOID;
      m_ThreadLock.threadUnlock();
   SME_FREE3_CATCH_FINISH
   m_ThreadLock.threadUnlock();

#ifdef WIN32
   pbufferIV; //AVOIDS warning.
#endif
   return SM_NO_ERROR;
}       // END CSM_Free3::SMTI_ExtractKeyAgreement(...)

//////////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_Free3::SMTI_ExtractKeyAgreementDH(
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            AsnOid *pPreferredContentOID, 
            long lKekLength,
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pbufX)        // INPUT, clear private key.
{
    CSM_Buffer *pbufKeyAgree=NULL;
    SecByteBlock *pZZ=NULL;
    Integer p((const unsigned char*)m_ParamP.Access(), m_ParamP.Length());
    Integer g((const unsigned char*)m_ParamG.Access(), m_ParamG.Length());
    bool bcheckResult;
    CSM_Buffer tempBuffer;
    CSM_Buffer *ptempBuff=NULL;
    char achCounter1[] = {0x00, 0x00, 0x00, 0x01};
    char achCounter2[] = {0x00, 0x00, 0x00, 0x02};
    CSM_Buffer k1, k2, TEK;

    SME_SETUP("CSM_Free3::SMTI_ExtractKeyAgreementDH");

    Integer *pxInt; // then convert it into a Crypto++ Integer
    pxInt = sm_Free3CryptoppBERDecode(pbufX->Access(), pbufX->Length());
        //x.BERDecode(pbyte);
    unsigned char achX[130];
    pxInt->Encode(&achX[0], 128);
    delete pxInt;

    // create dh class and set it's p, g, and x.
   // note, being able to set the x like this requires modification
   // of the DH class in dh.h to make x public.
   DH dhKeyAgreement(p, g);

   // Create storage for the resulting agreed upon key and clear it
   //RWC; Updated "dhKeyAgreement.AgreedKeyLength()" to "dhKeyAgreement.AgreedValueLength()()"
   pZZ = new SecByteBlock(dhKeyAgreement.AgreedValueLength());
   #ifndef CRYPTOPP_5_0
   memset(pZZ->ptr, 0x00, pZZ->size);
   #else // CRYPTOPP_5_0
   memset(*pZZ, 0x00, pZZ->m_size);
   #endif // CRYPTOPP_5_0

   // generate the agreed upon key from this class (this X and
   // provided parameters) and the recipient's public key Y.
   // put the result in AgreedUponKey
   Integer *pyInt;
   pyInt = sm_Free3CryptoppBERDecode(pOriginator->Access(), 
       pOriginator->Length());//y.BERDecode(pbyte);
   unsigned char achY[130];
   pyInt->Encode(&achY[0], 128);
   delete pyInt;
   bcheckResult = dhKeyAgreement.Agree(*pZZ,  //Out, Resulting agree key
                  &achX[0]/*RWC;(byte *)pbufX->Access()*/ // Input, Our private key
                 ,&achY[0]);               // Input, originator's public key.
    if (!bcheckResult)
      SME_THROW(22, "DH Key Agreement Failure.", NULL);

   if (pZZ == NULL)
   {
        SME_THROW(22, "BAD Key Agreement Calculation!", NULL);
   }        // END IF pZZ empty
   //##### GENERATE the TEK, given the key agreement data
   // UKM is stored in the incoming pUKM

   // concatentate ZZ, encoded oid, counter1, Ra
   SME(tempBuffer.Open(SM_FOPEN_WRITE));
   #ifndef CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->ptr, pZZ->size));
   #else // CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->data(), pZZ->m_size));
   #endif // CRYPTOPP_5_0
   ptempBuff = EncodeOtherInfo(pUKM, achCounter1, *pPreferredContentOID, 
       lKekLength);
   //ptempBuff->ConvertMemoryToFile("c:\\tmp\\OtherInfo3.out");
   SME(tempBuffer.Write((ptempBuff->Access()), ptempBuff->Length()));
   delete ptempBuff;
   ptempBuff = NULL;
   tempBuffer.Close();
   // now hash
   CSM_Free3::SMTI_DigestData(&tempBuffer, &k1);
   //tempBuffer.ConvertMemoryToFile("c:\\tmp\\OtherInfo4.out");
   // concatentate ZZ, encoded oid, counter2, Ra
   SME(tempBuffer.Open(SM_FOPEN_WRITE));
   #ifndef CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->ptr, pZZ->size));
   #else // CRYPTOPP_5_0
   SME(tempBuffer.Write((char *)pZZ->data(), pZZ->m_size));
   #endif // CRYPTOPP_5_0
   ptempBuff = EncodeOtherInfo(pUKM, achCounter2, *pPreferredContentOID ,lKekLength);
   SME(tempBuffer.Write((ptempBuff->Access()), ptempBuff->Length()));
   delete ptempBuff;
   ptempBuff = NULL;
   tempBuffer.Close();
   // now hash
   CSM_Free3::SMTI_DigestData(&tempBuffer, &k2);

   // concatenate k1 and k2 to form 40 byte value, use first 24 bytes as TEK
   SME(TEK.Open(SM_FOPEN_WRITE));
   SME(TEK.Write(k1.Access(), k1.Length()));
   SME(TEK.Write(k2.Access(), k2.Length()));
   pbufKeyAgree = new CSM_Buffer(TEK);

    if (pZZ)
        delete pZZ;

   SME_FINISH
   SME_CATCH_SETUP
    if (pZZ)
        delete pZZ;
   SME_FREE3_CATCH_FINISH

   return pbufKeyAgree;
}       // END IF CSM_Free3::SMTI_ExtractKeyAgreementDH(...)


//////////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_Free3::SMTI_ExtractKeyAgreementECDH(
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            AsnOid *pEncryptionOID,  // IN, specified encryption of key,
            long lKekLength,
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pbufX)        // INPUT, clear private key.
{
    CSM_Buffer tempBuffer;
    SecByteBlock *pZZ=NULL;
    SimpleKeyAgreementDomain *pGenericECDH=NULL;
    SecByteBlock *ppriv1=NULL;
    SecByteBlock *ppub1=NULL;
    AsnOid *poidKeyEncrypt = this->GetPrefKeyEncryption();
    bool bcheckResult;
    CSM_Buffer *pbufKeyAgree=NULL;

    SME_SETUP("CSM_Free3::SMTI_ExtractKeyAgreementECDH");


#ifdef CRYPTOPP_5_0
    if (m_pECParams == NULL)
    {
       SME_THROW(22, "Private key ECDH Parameters MUST BE PRESENT!", NULL);
    }
    if (pbufX == NULL)   // LOCAL private key with params.
    {
       SME_THROW(22, "Private key MUST BE PRESENT!", NULL);
    }       // END IF we have a private key

    bool bECPFlag=true;  // EASIER to use flag than the keep checking OIDs.

        CryptoPP::ByteQueue bt7;
        bt7.Put((unsigned char *)m_pECParams->Access(), m_pECParams->Length());

        if (*poidKeyEncrypt == dhSinglePass_stdDH_sha1kdf_scheme)
        {
          try {
                ECDH<ECP, NoCofactorMultiplication>::Domain *pDomain = 
                    new ECDH<ECP, NoCofactorMultiplication>::Domain;
                pDomain->AccessGroupParameters().BERDecode(bt7);
                pGenericECDH = pDomain;
          }       // END try
          catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
          if (!bECPFlag)               // Attempt EC2N private key...
          {
            CryptoPP::ByteQueue bt6;
            bt6.Put((unsigned char *)m_pECParams->Access(), m_pECParams->Length());
            ECDH<EC2N, NoCofactorMultiplication>::Domain *pDomain = 
                new ECDH<EC2N, NoCofactorMultiplication>::Domain;
            pDomain->AccessGroupParameters().BERDecode(bt6);
            pGenericECDH = pDomain;
          }
        }       // IF dhSinglePass_stdDH_sha1kdf_scheme
        else if (*poidKeyEncrypt == dhSinglePass_cofactorDH_sha1kdf_scheme)
        {
          bECPFlag = false;
          try {
                bECPFlag = true;
                ECDH<ECP, CompatibleCofactorMultiplication>::Domain *pDomain = 
                    new ECDH<ECP, CompatibleCofactorMultiplication>::Domain;
                pDomain->AccessGroupParameters().BERDecode(bt7);
                pGenericECDH = pDomain;
          }       // END try
          catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
          if (!bECPFlag)               // Attempt EC2N private key...
          {
            CryptoPP::ByteQueue bt6;
            bt6.Put((unsigned char *)m_pECParams->Access(), m_pECParams->Length());
            ECDH<EC2N, CompatibleCofactorMultiplication>::Domain *pDomain = 
                new ECDH<EC2N, CompatibleCofactorMultiplication>::Domain;
            pDomain->AccessGroupParameters().BERDecode(bt6);
            pGenericECDH = pDomain;
          }
        }       // END IF dhSinglePass_stdDH_sha1kdf_scheme

    if (pGenericECDH == NULL)
    {
       SME_THROW(22, "ECDH Ephemeral key construction FAILED!", NULL);
    }


   // Create storage for the resulting agreed upon key and clear it
   pZZ = new SecByteBlock(pGenericECDH->AgreedValueLength());

   memset(*pZZ, 0x00, pZZ->m_size);

   //ppriv1 = new SecByteBlock(pbufX->Length());
   //memcpy(ppriv1->begin(), pbufX->Access(), ppriv1->m_size);

   //##### GENERATE the agreed upon key from this class (this X and
   // provided parameters) and the originator's public key Y.
   // put the result in AgreedUponKey.
    bcheckResult = pGenericECDH->Agree(*pZZ, 
        (const unsigned char *)pbufX->Access()/* *ppriv1*/,  
        (const unsigned char *)pOriginator->Access(),  0);
    if (!bcheckResult)
      SME_THROW(22, "ECDH dhSinglePass_stdDH_sha1kdf_scheme/dhSinglePass_cofactorDH_sha1kdf_scheme Key Agreement Failure.", NULL);

   if (pZZ == NULL)
   {
        SME_THROW(22, "BAD Key Agreement Calculation!", NULL);
   }        // END IF pZZ empty

   //##### GENERATE the TEK, given the key agreement data
   // UKM is stored in the incoming pUKM
   pbufKeyAgree = ComputeSharedInfoKeyDerivationFunction(*pZZ, pUKM, 
                                           *pEncryptionOID, lKekLength);



   if (ppub1)
       delete ppub1;
   if (ppriv1)
       delete ppriv1;
   if (poidKeyEncrypt)
       delete poidKeyEncrypt;
   if (pZZ)
       delete pZZ;

#else // CRYPTOPP_5_0
   SME_THROW(22, "ECDH NOT ENABLED, MUST HAVE Crypto++ 5++!", NULL);
#endif // CRYPTOPP_5_0


   SME_FINISH
   SME_CATCH_SETUP
       if (ppub1)
           delete ppub1;
       if (ppriv1)
           delete ppriv1;
       if (poidKeyEncrypt)
           delete poidKeyEncrypt;
       if (pbufKeyAgree)
           delete pbufKeyAgree;
       if (pZZ)
           delete pZZ;
   SME_FREE3_CATCH_FINISH

   return pbufKeyAgree;
}       // END IF CSM_Free3::SMTI_ExtractKeyAgreementECDH(...)


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output (MEK or special phrase)
{
   SM_RET_VAL status = -1;
   AsnOid *pPreferredOID=this->GetPrefKeyEncryption();

   SME_SETUP("CSM_Free3::SMTI_ExtractMEK");

   m_ThreadLock.threadLock();
#ifdef SM_FREE3_RSA_INCLUDED
   if (*pPreferredOID  != id_RSAES_OAEP)
       status = RSA_ExtractMEK(pOriginator, pParameters, pEMEK, 
            pUKM, pMEK); 
   else
       status = RSAES_OAEP_ExtractMEK(pOriginator, pParameters, pEMEK, 
            pUKM, pMEK); 
#else
   SME_THROW(SM_FREE_UNSUPPORTED_ALG, NULL, NULL);
#endif

   delete pPreferredOID;

   SME_FINISH
   SME_CATCH_SETUP
   m_ThreadLock.threadUnlock();
   SME_FREE3_CATCH_FINISH
   m_ThreadLock.threadUnlock();

   return status;
}       // END CSM_Free3::SMTI_ExtractMEK(...)

//
//
CSM_AlgVDA *CSM_Free3::DeriveMsgAlgFromCert(CSM_AlgVDA &Alg)
{               // This call interprets KARI certificate params into CMS Msg
                //  Param format for algorithms.  It is up to the CTIL to 
                //  properly interpret algorithm specific formats for both.
   CSM_AlgVDA *pAlg=new CSM_AlgVDA(Alg);
   CSM_Buffer *pbufParams=NULL;
   CSM_Buffer *pParameters=NULL;
   long stat1;

   SME_SETUP("CSM_Free3::DeriveMsgAlgFromCert(Alg)");
   // The incomming parameters are from the certificate using a different 
   //  ASN.1 definition than the CMS encryption format.
   if (pAlg != NULL)
   {
      if (pAlg->algorithm == dh_public_number ||
          pAlg->algorithm == id_dhStatic)
      {                    // SUPPORT DH params from cert TO msg.
         DHParameters snaccDHParameters;      // ASN.1 Msg param format
         //DHPublicKeyParams snaccCertDHParams; // ASN.1 Cert param format
         DomainParameters snaccCertDHParams; // ASN.1 Cert param format
         SM_EXTRACT_ANYBUF(pbufParams, pAlg->parameters);  // Get cert params.
         DECODE_BUF_NOFAIL(&snaccCertDHParams, pbufParams, stat1);
         if (stat1 == 0)
         {
             snaccDHParameters.p = snaccCertDHParams.p;
             snaccDHParameters.g = snaccCertDHParams.g;
                        // IGNORE "q" for DH handling.
         }
         else       // OLD style for our test environment comaptibility.
         {
            DHPublicKeyParams snaccCertDHParams2; // ASN.1 Cert param format
            DECODE_BUF(&snaccCertDHParams2, pbufParams);
            snaccDHParameters.p = snaccCertDHParams2.p;
            snaccDHParameters.g = snaccCertDHParams2.g;
         }
         //Leave empty;snaccDHParameters.iv.Set();
         ENCODE_BUF((&snaccDHParameters), pParameters);
         if (pAlg->parameters->value != NULL)
             delete /*RWC;11/15/02;(AsnAnyBuffer *)*/pAlg->parameters->value;
         SM_ASSIGN_ANYBUF(pParameters, pAlg->parameters);
         if (pbufParams)
             delete pbufParams;
         if (pParameters)
             delete pParameters;
      }
      // else; return NULL indicating not supported for specified cert alg.
   }
   else
      SME_THROW(22, "Missing PublicKeyAlg in cert.", NULL);

   SME_FINISH_CATCH
   return(pAlg);
}

//
//
CSM_Alg *CSM_Free3::DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert)
{               // This call interprets KARI certificate params into CMS Msg
                //  Param format for algorithms.  It is up to the CTIL to 
                //  properly interpret algorithm specific formats for both.
   CSM_Alg *pAlg=NULL;
   CSM_Alg *pAlgReturn=NULL;

   SME_SETUP("CSM_Free3::DeriveMsgAlgFromCert");
   // The incomming parameters are from the certificate using a different 
   //  ASN.1 definition than the CMS encryption format.
   if ((pAlg = Cert.GetPublicKeyAlg()) != NULL)
   {
        pAlgReturn = (CSM_Alg *)DeriveMsgAlgFromCert(*(CSM_AlgVDA *)pAlg);
   }
   else
      SME_THROW(22, "Missing PublicKeyAlg in cert.", NULL);

   SME_FINISH_CATCH
   return(pAlgReturn);
}


//////////////////////////////////////////////////////////////////////////
// SMTI_DigestData uses CSM_Common for SHA1 and Crypto++ for MD5
SM_RET_VAL CSM_Free3::SMTI_DigestData(
            CSM_Buffer *pData, // input
            CSM_Buffer *pDigest) // output
{
   long lStatus;
   AsnOid *poidDigest=NULL;

   SME_SETUP("CSM_Free3::SMTI_DigestData");

   poidDigest = GetPrefDigest();
   m_ThreadLock.threadLock();

   lStatus = SMTI_DigestData(pData, pDigest, *poidDigest);

   delete poidDigest;

   SME_FINISH
   SME_CATCH_SETUP
      if (poidDigest)
         delete poidDigest;
      m_ThreadLock.threadUnlock();
   SME_FREE3_CATCH_FINISH
   m_ThreadLock.threadUnlock();

   return(lStatus);
}              // END CSM_Free3::SMTI_DigestData(...)

//////////////////////////////////////////////////////////////////////////
// SMTI_DigestData uses CSM_Common for SHA1 and Crypto++ for MD5
//  THIS routine is not used externally, IT DOES NOT LOCK, so that it can
//  be used by the Verify process.
SM_RET_VAL CSM_Free3::SMTI_DigestData(
            CSM_Buffer *pData, // input
            CSM_Buffer *pDigest, // output
            const AsnOid &oidDigest)
{
   long lStatus;

   SME_SETUP("CSM_Free3::SMTI_DigestData(...AsnOid)");

   lStatus = SMTI_DigestDataInternal(pData, pDigest, oidDigest);
   if (lStatus != 0)
   {
       if (oidDigest == gECDSA_SHA1_OID)
       {
          SME((lStatus = CSM_Common::SMTI_DigestData(pData, pDigest, sha_1)));
       }
       else
       {
          SME((lStatus = CSM_Common::SMTI_DigestData(pData, pDigest, oidDigest)));
       }        // END IF ECDSA OID.

	   if (lStatus != 0)
		{
			 SME_THROW(SM_FREE_UNSUPPORTED_ALG, "Unsupported alg", NULL);
		}
   }

   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH

   return(lStatus);
}              // END CSM_Free3::SMTI_DigestData(...)

//////////////////////////////////////////////////////////////////////////
// SMTI_DigestData uses CSM_Common for SHA1 and Crypto++ for MD5
SM_RET_VAL CSM_Free3::SMTI_DigestDataInternal(
            CSM_Buffer *pData, // input
            CSM_Buffer *pDigest, // output
            const AsnOid &oidDigest)  // input
{
   char *pchData;
   long lBytesRead;
   long status = -1;

   SME_SETUP("CSM_Free3::SMTI_DigestDataInternal");

   if (oidDigest == md5 ||
       oidDigest == md5WithRSAEncryption)
   {
      bool bLastBlock = false; // set to true when this is the last block
      // do MD5 digest
      MD5 md5;

      // now use md5 to do the actual hash/digest
      // open the input and block through it
      SME(pData->Open(SM_FOPEN_READ));
      while (!bLastBlock)
      {
#if defined(CRYPTOPP_3_2)
          int iDigestSize=MD5::DATASIZE;
#else
          int iDigestSize=MD5::DIGESTSIZE;
#endif
         SME(pchData = pData->nRead(iDigestSize, (SM_SIZE_T&)lBytesRead));
         if ((lBytesRead != iDigestSize) || (pchData == NULL))
            bLastBlock = true;
         md5.Update((const unsigned char *)pchData, lBytesRead);
      }
      // TBD, does the last block need to be padded???

      pData->Close(); // close the incoming data

      // create storage for the digest
      SecByteBlock digest(md5.DigestSize());

      md5.Final(digest); // finish the digest
      SME(pDigest->Open(SM_FOPEN_WRITE)); // open the digest buffer
       #ifndef CRYPTOPP_5_0
      SME(pDigest->Write((char *)digest.ptr, digest.size)); // write the digest
       #else // CRYPTOPP_5_0
      SME(pDigest->Write((char *)digest.data(), digest.m_size)); // write the digest
       #endif // CRYPTOPP_5_0
      pDigest->Close(); // close the digest buffer
      status = 0;
   }
   else if (oidDigest == id_md2 ||
            oidDigest == md2WithRSAEncryption)
   {
      bool bLastBlock = false; // set to true when this is the last block
      // do MD5 digest
      MD2 md2;

      // now use md5 to do the actual hash/digest
      // open the input and block through it
      SME(pData->Open(SM_FOPEN_READ));
      while (!bLastBlock)
      {
         SME(pchData = pData->nRead(MD2::DIGESTSIZE, (SM_SIZE_T&)lBytesRead));
         if ((lBytesRead != MD2::DIGESTSIZE) || (pchData == NULL))
            bLastBlock = true;
         md2.Update((const unsigned char *)pchData, lBytesRead);
      }
      // TBD, does the last block need to be padded???

      pData->Close(); // close the incoming data

      // create storage for the digest
      SecByteBlock digest(md2.DigestSize());

      md2.Final(digest); // finish the digest
      SME(pDigest->Open(SM_FOPEN_WRITE)); // open the digest buffer
       #ifndef CRYPTOPP_5_0
      SME(pDigest->Write((char *)digest.ptr, digest.size)); // write the digest
       #else // CRYPTOPP_5_0
      SME(pDigest->Write((char *)digest.data(), digest.m_size)); // write the digest
       #endif // CRYPTOPP_5_0
      pDigest->Close(); // close the digest buffer
      status = 0;
   }
	else if (oidDigest == SNACC::id_SHA384 ||
             oidDigest == SNACC::id_ecdsa_with_SHA384)
	{
		bool bLastBlock = false; // set to true when this is the last block
		CryptoPP::SHA384 sha384;

		int bytesProcessed=0;
		int loop = pData->Length() / sha384.DigestSize();

   	  SME(pData->Open(SM_FOPEN_READ));
      while (!bLastBlock)
      {
         SME(pchData = pData->nRead(sha384.DigestSize(), (SM_SIZE_T&)lBytesRead));
         if ((lBytesRead != sha384.DigestSize()) || (pchData == NULL))
            bLastBlock = true;
         sha384.Update((const unsigned char *)pchData, lBytesRead);
      }
		
		CryptoPP::SecByteBlock digest(sha384.DigestSize());
		sha384.Final(digest);

		SME(pDigest->Open(SM_FOPEN_WRITE)); // open the digest buffer
		SME(pDigest->Write((char *)digest.data(), digest.m_size)); 
		status = 0;
	}

   SME_FINISH
   SME_CATCH_SETUP
   SME_FREE3_CATCH_FINISH

   return status;
}           // END CSM_Free3::SMTI_DigestData(...)

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Free3::SMTI_Random(
            CSM_Buffer *pSeed,   // input
            CSM_Buffer *pRandom, // input/output
            SM_SIZE_T lLength)   // input
{
   char *p = NULL;

   SME_SETUP("CSM_Free3::SMTI_Random");

   // TBD:  Use pSeed

   if (pRandom == NULL)
      SME_THROW(SM_FREE_MISSING_PARAM, "MISSING Parameters", NULL);

   // open the buffer
   SME(pRandom->Open(SM_FOPEN_WRITE));
   // allocate memory for use in the buffer
   SME(p = pRandom->Alloc(lLength));

   // create lLength random bytes of data
    #ifndef CRYPTOPP_5_0
   m_pRng->GetBlock((unsigned char *)p, lLength);
    #else // CRYPTOPP_5_0
   for (long ii=0; ii < lLength; ii++)
       p[ii] = (char)m_pRng->GenerateByte();
    #endif // CRYPTOPP_5_0

   // flush and close
   pRandom->Flush();
   pRandom->Close();

   SME_FINISH
   SME_CATCH_SETUP
      // cleanup/catch logic goes here...
      // TBD, p may need to be cleaned up???
   SME_FREE3_CATCH_FINISH

#ifdef WIN32
    pSeed;    //AVOIDS warning.
#endif
   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
// in storing the password in this object, we attempt to provide a little
// extra protection by encrypting the password with a dynamically
// created key that can also be recreated.  Granted, this is not the
// most secure way in the world.  If anybody who reads this has an
// alternative and better solution, please let us know....
void CSM_Free3::SetPassword(char *pszPassword)
{
   AsnOid *pPrefDigest = NULL;
   AsnOid o(md5);
   SME_SETUP("CSM_Free3::SetPassword");

   if (pszPassword == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   int nPid = getpid();
   CSM_Buffer bufK1, bufK2, bufK3;
   CSM_Buffer bufP(pszPassword, strlen(pszPassword));

   SME(bufK1.Open(SM_FOPEN_WRITE));
   SME(bufK1.Write((char *)(&nPid), sizeof(int)));
   SME(bufK1.Write(m_pRandomData->Access(), m_pRandomData->Length()));
   SME(bufK1.Close());

   SME(pPrefDigest = GetPrefDigest()); // save current digest alg
   SME(BTISetPreferredCSInstAlgs(&o, NULL, NULL, NULL)); // set md5
   SME(CSM_Free3::SMTI_DigestData(&bufK1, &bufK2));
   // restore previous digest alg
   SME(BTISetPreferredCSInstAlgs(pPrefDigest, NULL, NULL, NULL));
   delete pPrefDigest;
   pPrefDigest = NULL;

#ifndef CRYPTOPP_5_0
   DESEncryption encryption((const unsigned char*)bufK2.Access());
   CBCPaddedEncryptor cbc_encryption(encryption, 
         (const unsigned char*)(bufK2.Access() + 8));

   SME(RawEncrypt(&bufK2, &bufK3,  &cbc_encryption));

   DESEncryption encryption2((const unsigned char*)bufK3.Access());
   CBCPaddedEncryptor cbc_encryption2(encryption2,
         (const unsigned char*)(bufK3.Access() + 8));
#else // CRYPTOPP_5_0
   CBC_Mode/*CFB_Mode*/<DES>::Encryption cbc_encryption;
   cbc_encryption.SetKeyWithIV((const unsigned char*)bufK2.Access(), 8, 
                (const unsigned char *)(bufK2.Access() + 8));
   SME(RawEncrypt(&bufK2, &bufK3,  &cbc_encryption));

   CBC_Mode/*CFB_Mode*/<DES>::Encryption cbc_encryption2;
   cbc_encryption2.SetKeyWithIV((const unsigned char*)bufK3.Access(), 8, 
                (const unsigned char*)(bufK3.Access() + 8));
#endif // CRYPTOPP_5_0

   if (m_pbufPassword)
      delete (m_pbufPassword);
   if ((m_pbufPassword = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME(RawEncrypt(&bufP, m_pbufPassword, &cbc_encryption2));

   SME_FINISH
   SME_CATCH_SETUP
      if (pPrefDigest)
         delete pPrefDigest;
   SME_FREE3_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
// see the comment block for SetPassword...
char* CSM_Free3::GetPassword()
{
   AsnOid *pPrefDigest = NULL;
   AsnOid o(md5);
   char *pRet = NULL;
   SME_SETUP("CSM_Free3::GetPassword");

   if (m_pbufPassword == NULL)
      SME_THROW(SM_MISSING_PARAM, "no password set yet", NULL);

   int nPid = getpid();
   CSM_Buffer bufK1, bufK2, bufK3;
   CSM_Buffer bufP;

   SME(bufK1.Open(SM_FOPEN_WRITE));
   SME(bufK1.Write((char *)(&nPid), sizeof(int)));
   SME(bufK1.Write(m_pRandomData->Access(), m_pRandomData->Length()));
   SME(bufK1.Close());

   SME(pPrefDigest = GetPrefDigest()); // save current digest alg
   SME(BTISetPreferredCSInstAlgs(&o, NULL, NULL, NULL)); // set md5
   SME(CSM_Free3::SMTI_DigestData(&bufK1, &bufK2));
   // restore previous digest alg
   SME(BTISetPreferredCSInstAlgs(pPrefDigest, NULL, NULL, NULL));

#ifndef CRYPTOPP_5_0
   DESEncryption encryption((const unsigned char*)bufK2.Access());
   CBCPaddedEncryptor cbc_encryption(encryption, 
         (const unsigned char*)(bufK2.Access() + 8));

   SME(RawEncrypt(&bufK2, &bufK3,  &cbc_encryption));

   DESDecryption decryption((const unsigned char*)bufK3.Access());
   CBCPaddedDecryptor cbc_decryption(decryption, 
         (const unsigned char *)bufK3.Access() + 8);
#else // CRYPTOPP_5_0
   CBC_Mode/*CFB_Mode*/<DES>::Encryption cbc_encryption;
   cbc_encryption.SetKeyWithIV((const unsigned char*)bufK2.Access(), 8, 
                (const unsigned char *)(bufK2.Access() + 8));
   SME(RawEncrypt(&bufK2, &bufK3,  &cbc_encryption));

   CBC_Mode/*CFB_Mode*/<DES>::Decryption cbc_decryption;
   cbc_decryption.SetKeyWithIV((const unsigned char*)bufK3.Access(), 8, 
                (const unsigned char*)(bufK3.Access() + 8));
   /*//RWC; in 5.0 we need to pad before calling if padded encryptor used (? not sure why ?)
   long lExtra = bufP.Length() % 8;
   if (lExtra > 0)
   {
       char pValue[20];
       sprintf(pValue, "%d", 8-lExtra);
       bufP.Open(SM_FOPEN_APPEND);
       for (int ii = 0; ii < 8-lExtra; ii++)
          bufP.Write((char *)pValue, 1);
       bufP.Close();
   }        // END if lAdd*/      
#endif // CRYPTOPP_5_0

   SME(RawDecrypt(m_pbufPassword, &bufP, &cbc_decryption));
#ifdef CRYPTOPP_5_0
    {
        // RWC; unpad logic due to lack of unpad logic in Crypto++ 
        //  (or at least I could not locate it).
       long lExtra = bufP.Length() % 8;
       char *achIn = (char *)bufP.Access();
       if (lExtra == 0) // IT IS PADDED, so remove the padding.
       {
           lExtra = achIn[bufP.Length()-1];   // USE last byte as padding value
           if (lExtra <= 8)
           {
            for (int ii = 0; ii < lExtra; ii++)
               if (achIn[bufP.Length()-1-ii] != lExtra)
               {
                   SME_THROW(22, "BAD Decryption Pad value!", NULL);
               }
            bufP.SetLength(bufP.Length()-lExtra);  //SHRINK buffer returned.
           }    // END if (lExtra < 8)
       }        // END if lExtra
    }       // END if PAD OID used.
#endif // CRYPTOPP_5_0

   if ((pRet = (char *)calloc(1, bufP.Length() + 1)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   memcpy(pRet, bufP.Access(), bufP.Length());
   
   // update the random data and reset the password
   delete m_pRandomData;
   if ((m_pRandomData = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   SME(SMTI_Random(NULL, m_pRandomData, SM_FREE_RANDSIZE));
   SME(SetPassword(pRet));

   if (pPrefDigest)
      delete pPrefDigest;

   SME_FINISH
   SME_CATCH_SETUP
      if (pPrefDigest)
         delete pPrefDigest;
   SME_FREE3_CATCH_FINISH

   return pRet;
}

//////////////////////////////////////////////////////////////////////////
CSM_Free3::~CSM_Free3()
{
   if (m_pbufPassword != NULL)
      delete m_pbufPassword;
   if (m_pAB)
      delete m_pAB;
   // RWC; DO NOT FREE Cipher; freed in "m_pRng".
   // RWC; if (m_pRandomCipher != NULL)
   // RWC;    delete m_pRandomCipher;
   if (m_pRng != NULL)
      delete m_pRng;  // TBD, this crashes???
   if (m_pszPrefix != NULL)
      free(m_pszPrefix);
   if (m_pRandomData != NULL)
      delete m_pRandomData;
   if (m_pX)
      delete m_pX;
   if (m_pEphemeralDHX)
       delete m_pEphemeralDHX;
   if (m_pEphemeralDHY)
       delete m_pEphemeralDHY;
   if (m_pEphemeralAlg)
       delete m_pEphemeralAlg;
   if (m_pCertPath)
       delete m_pCertPath;
   if (m_pECParams)
       delete m_pECParams;
}

void CSM_Free3::CSM_TokenInterfaceDestroy()
{
   delete this;
}


//////////////////////////////////////////////////////////////////////////
CSM_Free3::CSM_Free3(const AsnOid CertAlgOid){Setup(CertAlgOid);};
CSM_Free3::CSM_Free3() {Setup(id_dsa);};
void CSM_Free3::Setup(const AsnOid CertAlgOid)
{
   SME_SETUP("CSM_Free3::CSM_Free3");

   Clear();

   time_t t;
   time(&t); // use time to seed rng
   // store it in the seed member
   char pch[10];
   memcpy(&pch[0], &t, 4);
   memset(&pch[4], '\0', 4);
   m_seed.Set(&pch[0], 8);
   // use this key for the random cipher...TBD???
   byte rngKey[] = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0x12, 0x23, 0x77};

   // clear other members
   m_pbufPassword = NULL;
   m_pszPrefix = NULL;
   m_pAB = NULL;
   if ((m_pRandomData = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // construct random components
    #ifndef CRYPTOPP_5_0
   m_pRandomCipher = new DES(&rngKey[0], ENCRYPTION);;
    #else // CRYPTOPP_5_0
   m_pRandomCipher = new DES::Encryption(&rngKey[0]);;
    #endif // CRYPTOPP_5_0
   m_pRng = new X917RNG(m_pRandomCipher, (unsigned char *)m_seed.Access());

   // set up algs
   SME(SetDefaultOIDs(CertAlgOid));

   // load up some random data
   SME(SMTI_Random(NULL, m_pRandomData, SM_FREE_RANDSIZE));

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
#ifdef SEED_CODE_IN_PLACE
CSM_Free3::CSM_Free3(char *pszSeed)
{
   // store provided seed in the seed member
   m_seed.Set(pszSeed, strlen(pszSeed));
   // use this key for the random cipher...TBD???
   byte rngKey[] = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0x12, 0x23, 0x77};

   // clear other members
   m_pszPassword = NULL;
   m_pszPrefix = NULL;
   m_pAB = NULL;

   // construct random components
   m_pRandomCipher = new DES(&rngKey[0], ENCRYPTION);;
   m_pRng = new X917RNG(m_pRandomCipher, (unsigned char *)m_seed.Access());

   // set up algs
   SetDefaultOIDs();
}
#endif

//////////////////////////////////////////////////////////////////////////
void CSM_Free3::SetX(const CSM_Buffer &BufX)
{
   SME_SETUP("CSM_Free3::SetX");

   if (m_pX)
      delete m_pX;
   if ((m_pX = new CSM_Buffer(BufX)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// This routine expects BigIntegerStr values that may have a pre-pended 0,
//  be short of the required 128 bytes.  It will adjust the values for use
//  within this library.
void CSM_Free3::SetDHParams(CSM_Buffer *pP, CSM_Buffer *pG)
{
   SME_SETUP("CSM_Free3::SetDHParams");
   unsigned int length=0;
   unsigned char *ptr=NULL;

   if ((pP == NULL) || (pG == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   AsnInt BI;
   BI.Set((const unsigned char *)pP->Access(), pP->Length());
   BI.getPadded(ptr, (size_t&)length, 128);  // FORCE to new, appropriate length, 
   m_ParamP.Set((char *)ptr, 128);  // DO NOT FREE ptr.
   //RWC;BI.Get(m_ParamP, 128);
   BI.Set((const unsigned char *)pG->Access(), pG->Length());
   ptr = NULL;
   BI.getPadded(ptr, (size_t&)length, 128);  // FORCE to new, appropriate length, 
   m_ParamG.Set((char *)ptr, 128);  // DO NOT FREE ptr.
   //RWC;BI.Get(m_ParamG, 128);
   //SME(m_ParamP = *pP);
   //SME(m_ParamG = *pG);

   SME_FINISH_CATCH
}

//
void CSM_Free3::SetDHParams(AsnInt &P, AsnInt &G)
{
   SME_SETUP("CSM_Free3::SetDHParams");
   unsigned int length=0;
   char *ptr=NULL;

//   AsnInt BIP(P.c_str(), P.length());
//   AsnInt BIG(G.c_str(), G.length());
   AsnInt BIP(P);
   AsnInt BIG(G);
   BIP.getPadded((unsigned char *&)ptr, (size_t&)length, 128);  // FORCE to new, appropriate length, 
   m_ParamP.Set(ptr, 128);  // DO NOT DELETE ptr.
   ptr = NULL;
   //RWC;BIP.Get(m_ParamP, 128);
   BIG.getPadded((unsigned char *&)ptr, (size_t&)length, 128);  // FORCE to new, appropriate length, 
   m_ParamG.Set(ptr, 128);  // DO NOT DELETE ptr.
   //RWC;BIG.Get(m_ParamG, 128);
   //SME(m_ParamP = *pP);
   //SME(m_ParamG = *pG);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_Free3::SetBufY(const CSM_Buffer &BufY)
{
   SME_SETUP("CSM_Free3::SetBufY");

   m_pBufY = new CSM_Buffer(BufY);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_Free3::SetDSAY(const CSM_Buffer &BufY)
{

   SME_SETUP("CSM_Free3::SetDSAY");

   Integer *pTmpY=sm_Free3CryptoppBERDecode(BufY.Access(), BufY.Length());
   m_DSAY = *pTmpY;
   delete pTmpY;

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_Free3::SetDSAParams(CSM_Buffer *pP, CSM_Buffer *pQ, CSM_Buffer *pG)
{
   SME_SETUP("CSM_Free3::SetDSAParams");

   if ((pP == NULL) || (pQ == NULL) || (pG == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   m_DSAP.Decode((const byte *)pP->Access(), pP->Length());
   m_DSAQ.Decode((const byte *)pQ->Access(), pQ->Length());
   m_DSAG.Decode((const byte *)pG->Access(), pG->Length());

   SME_FINISH_CATCH
}

//
//
void CSM_Free3::SetDSAParams(AsnInt &P, AsnInt &Q, AsnInt &G)
{
    CryptoPP::Integer *pTmpBI;
    long lParam = 128;
    //
    if (P.length() <= 64)
       lParam = 64;
      pTmpBI = ComputeBigInteger(P, lParam);
      m_DSAP = *pTmpBI;
      delete pTmpBI;
      pTmpBI = ComputeBigInteger(Q, 20);
      m_DSAQ = *pTmpBI;
      delete pTmpBI;
      pTmpBI = ComputeBigInteger(G, lParam);
      m_DSAG = *pTmpBI;
      delete pTmpBI;
}

//////////////////////////////////////////////////////////////////////////
void SMFree3Init(CSM_CtilMgr *pCSMIME, char *pszPassword,
                     char *pszAddressBook, char *pszPrefix)
{
   CSM_CSInst *pNewInstance = NULL;
   List<MAB_Entrydef>::iterator itEntry;
   CSM_Free3 *pFree = NULL;
   CSM_CertificateChoice *pCertificateChoice;
   CSM_Buffer *pBuffer;
   long lCounter = 0;
   char szID[128];
   CSM_AlgLstVDA *pDigestAlgs=NULL;
   CSM_AlgLstVDA *pKeyEncryption=NULL;
   CSM_AlgLstVDA *pDigestEncryption=NULL;
   CSM_AlgLstVDA *pContentEncryption=NULL;
   AlgorithmIdentifier *pAlgID=NULL;

   SME_SETUP("SMFree3Init");

   if ((pCSMIME == NULL) || (pszPassword == NULL) || 
         (pszAddressBook == NULL) || (pszPrefix == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // initialize an address book from 
   MAB_AB_def AB(pszAddressBook);
   if (AB.m_pEntries == NULL)
      SME_THROW(SM_MAB_ERROR, "address book init failed", NULL);

   // now, go through the address book and build an instance for each
   // applicable entry
   for (itEntry =  AB.m_pEntries->begin();
        itEntry != AB.m_pEntries->end();
        ++itEntry)
   {
      if (itEntry->m_pPrivateOID != NULL) 
      {
         if ((*itEntry->m_pPrivateOID == dh_public_number) ||
               (*itEntry->m_pPrivateOID == id_dsa)   // id_dsa NOT WITH SHA1
                                                     //  since Certs ONLY here.
#ifdef SM_FREE3_RSA_INCLUDED
               || (*itEntry->m_pPrivateOID == rsaEncryption)
               || (*itEntry->m_pPrivateOID == rsa)
               || (*itEntry->m_pPrivateOID == AsnOid("1.2.840.113549.1.2"))
#endif
            )
         {
            // dh or dsa entry
            // create an instance
            if (pCSMIME->m_pCSInsts == NULL)
            {
               if ((pCSMIME->m_pCSInsts = new CSM_CtilInstLst
                   /*RWC;CSM_CSInstLst*/) == NULL)  //THIS list is the same
                                                    //  as CSM_CSInstLst.
                  SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
            }
            //RWC;5/12/02; SPECIAL NOTE; using SFL version of list here in order
            //  to specially load the CTIL MGR version of the list with the same
            //  sub-class pointer as the CSMIME libCert version.
            if ((pNewInstance = new CSM_CSInst) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
            // put it in the instance list in pCSMIME
            pCSMIME->m_pCSInsts->append(pNewInstance);
            // generate a new FREE CTI class
            if ((pFree = new CSM_Free3(id_dsa)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            // CSM_Free3 constructor set's Alg IDsa

             // JAS: added this.
             // From: "John Stark" <jas@xxxxxxxxxxxx> 
             // Date: Thu, 18 Mar 2004 23:34:58 -0000 
             //RWC;REMOVED due to interference with encrypt/decrypt;
             //RWC;REMOVED WE REQUIRE PRIVATE KEYS to be consistent.
             //RWC;REMOVED pFree->SetDefaultOIDs(rsa);   // Add RSA, DSA already present.

            pFree->SetCSInst(pNewInstance);   
                           // SINCE we generated a CSM_CSInst, not a CSM_CtilInst.
                           //  (THIS member is not used by the CTIL, but by the
                           //   application if a CSMIME (not CSM_CtilMgr) 
                           //   container is used for certificate access.

            // store other information in the Free CTI
            pFree->SetPassword(pszPassword);
            pFree->m_pAB = new MAB_AB_def(AB);
            if (itEntry->m_pPrivateInfo != NULL &&
               strcmp(itEntry->m_pPrivateInfo->Access(), "MAB_NULL") != 0)
               // store the private key info
               SME(pFree->SetX(*itEntry->m_pPrivateInfo));

            // store parameters and Y in the preferred Alg for this instance
            pAlgID = NULL;
            SME(pFree->GetParamsAndY(*itEntry->m_pCertFile, &AB, pAlgID));
            if (pAlgID)
              pFree->SetDefaultOIDs(pAlgID->algorithm);

            // now, fill in what we can in the instance
            // store token interface pointer
            pNewInstance->SetTokenInterface((CSM_TokenInterface *)pFree);
            // set an id
            sprintf(szID, "%s%ld", pszPrefix, lCounter);
            ++lCounter; // increment counter
            // TBD, scan all instances in pCSMIME to make sure this is a
            // unique ID
            pNewInstance->SetID(&szID[0]);
            // store the prefix
            pFree->m_pszPrefix = strdup(pszPrefix);
            // copy the CSMIME error buf
            //pNewInstance->m_pErrorBuf = pCSMIME->AccessErrorBuf();
            // store certificate
            if ((pBuffer = new CSM_Buffer(*(itEntry->m_pCertFile))) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
            CSM_CertificateChoiceLst *pNewCertList = new CSM_CertificateChoiceLst;
            if (pNewCertList == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            if ((pCertificateChoice = &(*pNewCertList->append())) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
            pCertificateChoice->SetEncodedCert(*pBuffer);
            // delete buffer since it was copied into pCertificateChoice
            delete (pBuffer); 
            pNewInstance->UpdateCertificates(pNewCertList);
            //delete pNewCertList; // IN THIS CASE; the cert buffer list is NOT copied.
            // store issuer and serial number
            pNewInstance->SetIssuerAndSerialNumber(itEntry->GetIssuer());
            // store crls??? TBD

            // RWC; Set custom parameters from cert algorithm if necessary.
            // pAlgID was set by GetParamsAndY.  We store the parameters in
            // the instance so they may be used as necessary later on
            pFree->BTIGetAlgIDs(&pDigestAlgs, &pDigestEncryption, 
                &pKeyEncryption, &pContentEncryption);   // DO NOT FREE!!!!
            if (pAlgID) // only do this if there is something in pAlgID
            {
               CSM_AlgLstVDA::iterator itTmpAlg;
               if (pAlgID->algorithm == id_dsa) // do DSA side
               {
                  // loop through digest encryption algs until we find DSA
                  for (itTmpAlg =  pDigestEncryption->begin(); 
                       itTmpAlg != pDigestEncryption->end() && 
                           *(itTmpAlg->AccessSNACCId()) != id_dsa; 
                       ++itTmpAlg);
                  if (itTmpAlg != pDigestEncryption->end())
                  {
                     // if we found one, store it
                    CSM_Alg *pA=new CSM_Alg(*pAlgID);  //NECESSARY for Unix compile.
                    *itTmpAlg = *pA;
                    delete pA;                     // since this instance will never do key encryption,
                     // we can clear that part
                     pFree->ClearKeyEncryptionCapability();
                     // reset digest encryption (which has parameters added),
                     pFree->BTISetAlgIDs(NULL, pDigestEncryption, 
                           NULL, NULL);
                  }
               }
            } // ENDIF pAlgID

            if (pDigestAlgs)
            {
               delete pDigestAlgs;
               pDigestAlgs = NULL;
            }
            if (pDigestEncryption)
            {
               delete pDigestEncryption;
               pDigestEncryption = NULL;
            }
            if (pKeyEncryption)
            {
               delete pKeyEncryption;
               pKeyEncryption = NULL;
            }
            if (pContentEncryption)
            {
               delete pContentEncryption;
               pContentEncryption = NULL;
            }
            if (pAlgID)
            {
               delete pAlgID;
               pAlgID = NULL;
            }
         }
      }
   }        // END FOR each entry in MAB


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_FREE3_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
// This function restores or sets the default OIDs in the BTI
//  THE PARAMETER designates the specific algorithms of the supported CTIL
//  list that are valid for this certificate:  RSA, DSA, DH or RSA ktri.
//  RWC;12/6/00; This method is now smart enough to pre-load existing algs if 
//      present OR load the initial algs.  This allows an app to load 
//      additional algs (e.g. for verify, DSA & RSA).
void CSM_Free3::SetDefaultOIDs(AsnOid CertAlgOid)
{
   AsnOid *pSignOid = NULL;
   AsnOid *pEncryptOid = NULL;

   SME_SETUP("CSM_Free3::SetDefaultOIDs");

   // TBD, these are probably not right
   // put the AsnOids in AsnOids
   AsnOid ENDOID("0.0.0");
   AsnOid oidHash[] = { 
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption, 
       md5, 
       md5WithRSAEncryption,
       id_md2,
       md2WithRSAEncryption,
       "1.3.14.3.2.12",
		 SNACC::id_SHA384,
		 SNACC::id_ecdsa_with_SHA384,
       ENDOID };
   AsnOid oidSignDSA[] = { 
       id_dsa,  
       id_dsa_with_sha1, 
       "1.3.14.3.2.12", 
       id_OIW_secsig_algorithm_dsa,
       ENDOID };
   AsnOid oidSignECDSA[] = { 
       id_ecPublicKey,
       gECDSA_SHA1_OID,
	   id_ecdsa_with_SHA384,
       ENDOID };
   AsnOid oidSignRSA[] = {
       rsa, 
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption,
       md5WithRSAEncryption,
       md5WithRSAEncryptionOIW,
       md2WithRSAEncryption,
       rsaEncryption,
       "1.2.840.113549.1.2",    // bsafe rsa encryption oid
       ENDOID };
   AsnOid oidContentEncrypt[] = { 
       des_ede3_cbc,
       id_alg_CMS3DESwrap,
       rc2_cbc,
       id_alg_CMSRC2wrap,
       dES_CBC,
       id_aes128_CBC,
       id_aes192_CBC,
       id_aes256_CBC,
       id_aes128_wrap,
       id_aes192_wrap,
       id_aes256_wrap,
       ENDOID };
   AsnOid oidKeyEncryptDH[] = { 
       id_dhStatic, 
       dh_public_number, 
       id_alg_ESDH,
       ENDOID };
   AsnOid oidKeyEncryptECDH[] = { 
       dhSinglePass_stdDH_sha1kdf_scheme, 
       dhSinglePass_cofactorDH_sha1kdf_scheme,
       mqvSinglePass_sha1kdf_scheme,
       id_ecPublicKey,
       ENDOID };
   AsnOid oidKeyEncryptRSA[] = { 
       rsa,
       rsaEncryption,
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption,
       "1.2.840.113549.1.2",    // bsafe rsa encryption oid
       id_RSAES_OAEP,
       ENDOID };
   CSM_AlgVDA *pAlg;
   int i;
   int bAlreadyLoaded = 0;  // FALSE initially.
   CSM_AlgLstVDA *pDigestAlgs = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pKeyEncryption = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pDigestEncryption = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pContentEncryption = new CSM_AlgLstVDA;
   BTIGetAlgIDs(&pDigestAlgs, &pDigestEncryption, &pKeyEncryption,
            &pContentEncryption);   // pre-load
   if (pDigestEncryption->size())
   {                // ONLY if already present.
        bAlreadyLoaded = true;
   }

   // Produce list of separate alg lists.
   if (!bAlreadyLoaded)
   {
       CSM_Common::SetDefaultOIDLists(pDigestAlgs, pDigestEncryption, 
          pKeyEncryption, pContentEncryption); //SET all CSM_Common supplied algs.
       for (i=0; oidHash[i] != ENDOID; i++)
       {
           pAlg = &(*pDigestAlgs->append());
           pAlg->algorithm = oidHash[i];
       }
       for (i=0; oidContentEncrypt[i] != ENDOID; i++)
       {
           pAlg = &(*pContentEncryption->append());
           pAlg->algorithm = oidContentEncrypt[i];
       }
   }

   if (CertAlgOid == id_dsa)
   {
     for (i=0; oidSignDSA[i] != ENDOID; i++)
     {
        pAlg = &(*pDigestEncryption->append());
        pAlg->algorithm = oidSignDSA[i];
     }
     pSignOid = new AsnOid(id_dsa_with_sha1);     
   }
   else if (CertAlgOid == rsa || 
            CertAlgOid == rsaEncryption ||
            CertAlgOid == md2WithRSAEncryption ||
            CertAlgOid == md5WithRSAEncryption ||
            CertAlgOid == sha_1WithRSAEncryption ||
            CertAlgOid == AsnOid( "1.2.840.113549.1.2"))
   {
     for (i=0; oidSignRSA[i] != ENDOID; i++)
     {
        pAlg = &(*pDigestEncryption->append());
        pAlg->algorithm = oidSignRSA[i];
     }
     pSignOid =  new AsnOid(CertAlgOid);
   }
   else if (CertAlgOid == id_ecPublicKey)
   {
     for (i=0; oidSignECDSA[i] != ENDOID; i++)
     {
        pAlg = &(*pDigestEncryption->append());
        pAlg->algorithm = oidSignECDSA[i];
     }
     pSignOid = new AsnOid(gECDSA_SHA1_OID);
     for (i=0; oidKeyEncryptECDH[i] != ENDOID; i++)
     {
        pAlg = &(*pKeyEncryption->append());
        pAlg->algorithm = oidKeyEncryptECDH[i];
     }
     pEncryptOid =  new AsnOid(CertAlgOid);
   }

   if (CertAlgOid == dh_public_number)
   {
     for (i=0; oidKeyEncryptDH[i] != ENDOID; i++)
     {
        pAlg = &(*pKeyEncryption->append());
        pAlg->algorithm = oidKeyEncryptDH[i];
     }
     pEncryptOid =  new AsnOid(CertAlgOid);
   }
   else if (CertAlgOid == rsa || 
            CertAlgOid == rsaEncryption ||
            CertAlgOid == md2WithRSAEncryption ||
            CertAlgOid == md5WithRSAEncryption ||
            CertAlgOid == sha_1WithRSAEncryption ||
            CertAlgOid == AsnOid( "1.2.840.113549.1.2"))
   {
     for (i=0; oidKeyEncryptRSA[i] != ENDOID; i++)
     {
        pAlg = &(*pKeyEncryption->append());
        pAlg->algorithm = oidKeyEncryptRSA[i];
     }
     pEncryptOid =  new AsnOid(CertAlgOid);
   }

   // put the CSM_AlgLsts in the base token interface
   SME(BTISetAlgIDs(pDigestAlgs, pDigestEncryption, pKeyEncryption, 
         pContentEncryption));
   if (pDigestAlgs)
   {
      delete pDigestAlgs;
      pDigestAlgs = NULL;
   }
   if (pDigestEncryption)
   {
      delete pDigestEncryption;
      pDigestEncryption = NULL;
   }
   if (pKeyEncryption)
   {
      delete pKeyEncryption;
      pKeyEncryption = NULL;
   }
   if (pContentEncryption)
   {
      delete pContentEncryption;
      pContentEncryption = NULL;
   }
   // make sha1, dsa, dh, and tdes the preferred algs
   AsnOid oidSha1(sha_1);
  // AsnOid oidDsa(id_dsa);
   AsnOid oidTdes(des_ede3_cbc);
   //AsnOid oidDh(id_dhStatic);
   AsnOid oidDhPublicNumber(dh_public_number);

   SME(BTISetPreferredCSInstAlgs(&oidSha1, pSignOid, pEncryptOid, &oidTdes));
   // set the local key alg
   SME(SetLocalKeyAlg(&oidDhPublicNumber));

   if (pSignOid)
      delete pSignOid;

   if (pEncryptOid)
      delete pEncryptOid;

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// ExtractParams ASN.1 decodes the provide any and sets the values into
// this object as appropriate
SM_RET_VAL CSM_Free3::ExtractParams(AlgorithmIdentifier *pAlgID)
{
   int stat1;

   // TBD, fully implement error handling

   SME_SETUP("CSM_Free3::ExtractParams");

   if ((pAlgID == NULL) || (pAlgID->parameters == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   if (pAlgID->algorithm == dh_public_number)
   {
      // ASN.1 decode pParams as DH parameters
      // store them in m_ParamP and m_ParamG
      DHPublicKeyParams snaccDHParams;
      DomainParameters snaccCertDHParams; // ASN.1 Cert param format
      CSM_Buffer *pTmpP;
      CSM_Buffer *pTmpG;
      CSM_Buffer *pTmpBuf=NULL;
      //DECODE_ANY((&snaccDHParams), (pAlgID->parameters));
      SM_EXTRACT_ANYBUF(pTmpBuf, pAlgID->parameters);
#ifdef _DEBUG
      pTmpBuf->ConvertMemoryToFile("./tmpExtractParams.bin");
#endif
      DECODE_BUF_NOFAIL(&snaccCertDHParams, pTmpBuf, stat1);
      if (stat1 == 0)   // This ASN.1 encoding (correct)
      {
         pTmpP = ComputeBigIntegerBuf(snaccCertDHParams.p, 128);
         pTmpG = ComputeBigIntegerBuf(snaccCertDHParams.g, 128);
      }
      else              // OLD SFL encoding of parameters (here for compat).
      {
         DECODE_ANY((&snaccDHParams), (pAlgID->parameters));
         pTmpP = ComputeBigIntegerBuf(snaccDHParams.p, 128);
         pTmpG= ComputeBigIntegerBuf(snaccDHParams.g, 128);
      }
      m_ParamP = *pTmpP;
      m_ParamG = *pTmpG;
      delete pTmpP;
      delete pTmpG;
      delete pTmpBuf;
   }
   else if (pAlgID->algorithm == id_dsa ||
            pAlgID->algorithm == id_dsa_with_sha1)
   {
      //byte *pbyte;
      // ASN.1 decode pParams as DSA parameters
      // store them in m_DSAP, m_DSAQ, and m_DSAG
      FREE_DSAParameters snaccDSAParams;
      DECODE_ANY((&snaccDSAParams), (pAlgID->parameters));
      // extract P
      long lParam = 128;
      if (snaccDSAParams.p.length() <= 64)
         lParam = 64;
      Integer *pTmpBI;
      pTmpBI = ComputeBigInteger(snaccDSAParams.p, lParam);
      //pbyte = (byte *)((char*)snaccDSAParams.p);
      m_DSAP = *pTmpBI; //RWC;.Decode(pbyte, snaccDSAParams.p.Len());
      delete pTmpBI;
      // extract Q
      pTmpBI = ComputeBigInteger(snaccDSAParams.q, 20);
      //pbyte = (byte *)((char*)snaccDSAParams.q);
      m_DSAQ = *pTmpBI; //RWC;.Decode(pbyte, snaccDSAParams.q.Len());
      delete pTmpBI;
      // extract G
      pTmpBI = ComputeBigInteger(snaccDSAParams.g, lParam);
      //pbyte = (byte *)((char*)snaccDSAParams.g);
      m_DSAG = *pTmpBI; //RWC;.Decode(pbyte, snaccDSAParams.g.Len());
      delete pTmpBI;
   }
   else if (pAlgID->algorithm == id_ecPublicKey || 
            pAlgID->algorithm == gECDSA_SHA1_OID)
   {
       SM_EXTRACT_ANYBUF(m_pECParams, pAlgID->parameters);
   }
   else
      SME_THROW(SM_FREE_UNSUPPORTED_ALG, "Algorithm unsupported to extract Params!", NULL);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_FREE3_CATCH_FINISH

   return SM_NO_ERROR;
}




//////////////////////////////////////////////////////////////////////////
// DecodeCertificate accepts a pointer to a Certificate that will
// receive the decoded certificate.  It needs the buffer containing
// the encoded certificate.  It returns a pointer to the issuer,
// a pointer to the subject key info alg id, and a pointer to the subject
// public key.
SM_RET_VAL CSM_Free3::DecodeCertificate(CSM_Buffer *pEncodedCert,
      Certificate *pSnaccCertificate, SNACC::Name **ppIssuer,
      AlgorithmIdentifier **ppAlgID, AsnBits **ppY)
{
   SME_SETUP("CSM_Free3::DecodeCertificate");

   if ((pEncodedCert == NULL) || (pSnaccCertificate == NULL)
         || (ppIssuer == NULL) || (ppAlgID == NULL) ||
         (ppY == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // decode the certificate
   DECODE_BUF(pSnaccCertificate, pEncodedCert);

   if (*ppAlgID != NULL)
      delete *ppAlgID;
   if ((*ppAlgID = new AlgorithmIdentifier) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   **ppAlgID = pSnaccCertificate->toBeSigned.subjectPublicKeyInfo.algorithm;
   if (*ppAlgID == NULL)
      SME_THROW(SM_CERT_DEC_ERROR, "Certificate missing subj pub key alg",
            NULL);
   *ppIssuer = &pSnaccCertificate->toBeSigned.issuer;
   if (*ppIssuer == NULL)
      SME_THROW(SM_CERT_DEC_ERROR, "Certificate missing issuer", NULL);
   *ppY = &(pSnaccCertificate->toBeSigned.subjectPublicKeyInfo.subjectPublicKey);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_FREE3_CATCH_FINISH

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
// GetParamsAndY accepts a buffer for the cert and an algId
// input parameters.  It decodes the certificate 
// and compares the OID in the parameters with the
// OIDs in this instance of CSM_Free3.  If this cert is a DH cert, then
// it extracts the parameters and puts them into the preferred key
// encryption CSM_Alg.  If this cert is a DSA cert, then it gets
// the parameters by going through the DSA cert chain (as necessary,
// searching the address book for issuers) and then puts the
// parameters into the preferred digest encryption CSM_Alg.
// It also extracts and stores the Y value from the cert
SM_RET_VAL CSM_Free3::GetParamsAndY(CSM_Buffer &bufferCert/*MAB_Entrydef *pEntry*/, MAB_AB_def *pAB,
    AlgorithmIdentifier *&pAlgID)
{
   SME_SETUP("CSM_Free3::GetParamsAndY");
   bool bUserMustHaveParams;
   SNACC::Name *pIssuer;
   AsnBits *pY;
   Certificate snaccCertificate;
   Certificate snaccIssuer;

   bufferCert.ConvertFileToMemory();
   if (bufferCert.Length() == 0)
          return -1;    // EMPTY Cert NOT Fatal error.

   // make a copy of the cert buffer and convert it to memory if necessary
   //RWC;bufferCert = *(pEntry->m_pCertFile);

   // decode the certificate
   SME(DecodeCertificate(&bufferCert, &snaccCertificate, &pIssuer,
         &pAlgID, &pY));

   // get the public key out of the cert and store it to be set soon
   CSM_Buffer bufferTemp((const char *)pY->data(), pY->length());

#ifdef SM_FREE3_RSA_INCLUDED
   if (pAlgID->algorithm == rsa ||
       pAlgID->algorithm == rsaEncryption ||
       pAlgID->algorithm == md2WithRSAEncryption ||
       pAlgID->algorithm == md5WithRSAEncryption ||
       pAlgID->algorithm == sha_1WithRSAEncryption ||
      (pAlgID->algorithm == AsnOid("1.2.840.113549.1.2")) )
   {
       bUserMustHaveParams = true;  // prevents further code execution if false
   }
   else
#endif
   {  // if not rsa do the following
      // this is just temporary until rsa if fully implemented in the free3 library

      // look at the subject public key OID to see if it is DH, if so, then
      // the parameters must be here, if not, then they may be here or they
      // may be in any one of the issuers...also, store the Y value
      if (pAlgID->algorithm == dh_public_number)
      {
         bUserMustHaveParams = true;
         SME(SetBufY(bufferTemp));
      }
      else if (pAlgID->algorithm == id_dsa || 
            pAlgID->algorithm == id_dsa_with_sha1)
      {
         bUserMustHaveParams = false;
         SME(SetDSAY(bufferTemp));
      }
      else if (pAlgID->algorithm == id_ecPublicKey ||
               pAlgID->algorithm == gECDSA_SHA1_OID)
      {
          bUserMustHaveParams = true;  // MAY have to change to "false" to 
                                       //  force path lookup.
         SME(SetBufY(bufferTemp));
      }
      else 
      {
         SME_THROW(SM_FREE_UNSUPPORTED_ALG, "Cert is not DSA or DH", NULL);
      }

      // extract (ASN.1 decode) the parameters and store them in this object
      // RWC;TBD; EC may have to look up params from issuer...
      CSM_Alg *pTmpAlg=new CSM_Alg(*pAlgID);
      if (!bUserMustHaveParams && m_pCertPath)
      {
         // find the parameters and store them
         CSM_CertificateChoice *pUserCert=new CSM_CertificateChoice(bufferCert);
         while (pTmpAlg != NULL && pTmpAlg->HasNullParams()  // MAY be NULL OR 0x0500 tag.
             && pUserCert != NULL)
         {
            // find the parameters by climbing the chain
            // find the issuer of this cert in the cert bucket
            CSM_DN *pIssDN=pUserCert->GetIssuer();
            CSM_CertificateChoice *pRootCert = m_pCertPath->FindCert(*pIssDN);
            delete pTmpAlg;
            pTmpAlg = NULL;
            if (pIssDN)
              delete pIssDN;
            if (pRootCert)
              pTmpAlg = pRootCert->GetPublicKeyAlg();
            //if (pAlgID->algorithm != id_dsa && 
            //   pAlgID->algorithm != id_dsa_with_sha1)
            //   SME_THROW(SM_FREE_ISSUER_NOT_DSA, NULL, NULL);
            delete pUserCert;
            pUserCert = pRootCert;      // In case we must search more than 1
         }
         if (pUserCert)
             delete pUserCert;
      }
      if (pTmpAlg && !pTmpAlg->HasNullParams())
      {
        SME(ExtractParams(*pTmpAlg));
        if (pAlgID->parameters)
            delete pAlgID->parameters;
        pAlgID->parameters = pTmpAlg->parameters;
        pTmpAlg->parameters = NULL; // BE sure not to delete param memory.
      }

      if (pTmpAlg)
          delete pTmpAlg;

   } // end else if not rsa

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_FREE3_CATCH_FINISH

#ifdef WIN32
    pAB;    //AVOIDS warning.
#endif
   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
// This CTI will override BTIFindAlgIds because in CEA and KEA's
// case, we only want to compare OIDs and are not interested in 
// comparing the parameters part of the AlgId
bool CSM_Free3::BTIFindAlgIds(CSM_AlgVDA *pdigestAlgID, 
            CSM_AlgVDA *pdigestEncryptionAlgID,
            CSM_AlgVDA *pkeyEncryptionAlgID,
            CSM_AlgVDA *pcontentEncryptionAlgID)
{
   CSM_AlgVDA *ptmpCEAlgID = NULL;
   CSM_AlgVDA *ptmpKEAlgID = NULL;
   bool bRet = false;

   SME_SETUP("CSM_Free3:BTIFindAlgIds");

   // if we have a content encryption AlgId, create a temporary AlgID with
   // only the OID from the one we got from the caller
   if (pcontentEncryptionAlgID)
   {
      AsnOid tmpoid = (*(pcontentEncryptionAlgID->AccessSNACCId()));
      if ((ptmpCEAlgID = new CSM_AlgVDA(tmpoid)) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "couldn't duplicate CEA OID", NULL);
   }

   // if we have a key encryption AlgId, create a temporary AlgID with
   // only the OID from the one we got from the caller
   if (pkeyEncryptionAlgID)
   {
      AsnOid tmpoid = (*(pkeyEncryptionAlgID->AccessSNACCId()));
      if ((ptmpKEAlgID = new CSM_AlgVDA(tmpoid)) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "couldn't duplicate KEA OID", NULL);
   }

   // call the lolevel BTIFindAlgIds with our modified CEA and/or KEA AlgId
   SME(bRet = CSM_BaseTokenInterface::BTIFindAlgIds(pdigestAlgID, 
         pdigestEncryptionAlgID, ptmpKEAlgID, ptmpCEAlgID));

   // delete the modified CE and/or KE Alg ID if it exists (cleanup)
   if (ptmpCEAlgID)
      delete ptmpCEAlgID;
   if (ptmpKEAlgID)
      delete ptmpKEAlgID;

   SME_FINISH_CATCH

   return bRet;
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_Free3::GeneratePBEKey(CSM_Buffer *pbufSalt, int nIterCount,
                                     char *pszPassword)
{
   CSM_Buffer *pK = NULL;
   AsnOid o(md5);

   pK = GeneratePBEKey(pbufSalt, nIterCount, pszPassword, o, 16);

   return pK;
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_Free3::GeneratePBEKey(CSM_Buffer *pbufSalt, int nIterCount, 
                  char *pszPassword, AsnOid &o, int nKeyLength, int lPassword)
{
   CSM_Buffer *pK = NULL;
   CSM_Buffer *pTemp;
   AsnOid *pPrefDigest = NULL;
   int nLoop;

   SME_SETUP("CSM_Free3::GeneratePBEKey");

   // create the DES key by concatentating bufferSalt onto the password
   // and then digesting the result nIterCount times
   if ((pK = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, "CSM_Free3::GeneratePBEKey: memory", NULL);

   if ((pTemp = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, "CSM_Free3::GeneratePBEKey: memory", NULL);

   SME(pK->Open(SM_FOPEN_WRITE));

     if ( o == md5)
     {
          if (nKeyLength > 16)
          {
              SME_THROW(27, "CSM_Free3::GeneratePBEKey: bad md5 length", NULL);
          }
     }
     else if (o == sha_1)
     {
          if (nKeyLength > 20)
          {
              SME_THROW(27, "CSM_Free3::GeneratePBEKey: bad sha1 length2", NULL);
          }
     }
     else
     {
          SME_THROW(27, "CSM_Free3::GeneratePBEKey: bad Hash OID", NULL);
     }

   // check length
   if (lPassword == 0)
     lPassword = strlen(pszPassword);;
   if (lPassword > nKeyLength) //pbufSalt->Length()))
      lPassword = nKeyLength; //pbufSalt->Length();
   SME(pK->Write(pszPassword, lPassword));
   if (pbufSalt->Length() > (unsigned int)(nKeyLength-lPassword))
   {
      SME(pK->Write(pbufSalt->Access(), nKeyLength-lPassword)); 
                                //pbufSalt->Length()))
   }
   else
   {
      SME(pK->Write(pbufSalt->Access(), pbufSalt->Length())); 
   }

 
   SME(pK->Close());

   SME(pPrefDigest = GetPrefDigest()); // save current digest alg
   SME(BTISetPreferredCSInstAlgs(&o, NULL, NULL, NULL)); // set md5

   for (nLoop = 0; nLoop < nIterCount; nLoop++)
   {
      SME(CSM_Free3::SMTI_DigestData(pK, pTemp));
      // now, move digest result to K and empty temp
      delete (pK);
      if ((pK = new CSM_Buffer(*pTemp)) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      delete (pTemp);
      if ((pTemp = new CSM_Buffer) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }
   // at this point, pK has the key, delete Temp
   delete (pTemp);

   // restore previous digest alg
   SME(BTISetPreferredCSInstAlgs(pPrefDigest, NULL, NULL, NULL));
   delete pPrefDigest;

   SME_FINISH
   SME_CATCH_SETUP
      if (pPrefDigest)
         delete pPrefDigest;
   SME_FREE3_CATCH_FINISH
   
   return pK;
}


//////////////////////////////////////////////////////////////////////////
// THIS routine handles ONLY PKCS8.
CSM_Buffer* CSM_Free3::DecryptPrivateKey(char *pszPassword, 
   CSM_Buffer *pEncryptedPrivateKeyInfo, long lPassword)
{
   EncryptedPrivateKeyInfo snaccEncryptedX;
   PBEParameter snaccEncryptionParams;
   PrivateKeyInfo snaccX;
   CSM_Buffer *pbufEncodedEncryptionParams = NULL;
   CSM_Buffer *pK = NULL;
   CSM_Buffer *pX = NULL;
   int blocksize = 0;
   AsnOid oidHash;
   int iLength = 20;
   int iPBEKeyBits=SM_FREE_RC2_DEFAULT_PBE_KEYBITS;
   long status=0;
#ifndef CRYPTOPP_5_0
   RC2Decryption *pRC2Decryption = NULL;
   CBCPaddedDecryptor *cbc_decryption = NULL;
   DESDecryption *pDESDecryption = NULL;
   DES_EDE3_Decryption *p3DESDecryption = NULL;
#else // CRYPTOPP_5_0
   StreamTransformation *cbc_decryption=NULL;
#endif // CRYPTOPP_5_0

   SME_SETUP("CSM_Free3::DecryptPrivateKey");

   if ((pEncryptedPrivateKeyInfo == NULL) || (pszPassword == NULL))
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMS", NULL);

   // ASN.1 decode the EncryptedPrivateKeyInfo
   DECODE_BUF(&snaccEncryptedX, pEncryptedPrivateKeyInfo);

   if ((snaccEncryptedX.encryptionAlgorithm.algorithm != pbeWithMD5AndDES_CBC) &&
       (snaccEncryptedX.encryptionAlgorithm.algorithm != pbeWithSHAAnd3_KeyTripleDES_CBC) &&
       (snaccEncryptedX.encryptionAlgorithm.algorithm != pbeWithMD5AndRC2_CBC) &&
       (snaccEncryptedX.encryptionAlgorithm.algorithm != pbewithSHAAnd40BitRC2_CBC) )
   {
      SME_THROW(SM_FREE_UNSUPPORTED_ALG, "unsupported password encryption",
            NULL);
   }

   // extract the encryption algorithm parameters and asn.1 decode them
   SM_EXTRACT_ANYBUF(pbufEncodedEncryptionParams, 
         snaccEncryptedX.encryptionAlgorithm.parameters);
   DECODE_BUF((&snaccEncryptionParams), pbufEncodedEncryptionParams);

   delete pbufEncodedEncryptionParams;
   pbufEncodedEncryptionParams = NULL;

   int nIterCount = snaccEncryptionParams.iterationCount;
   CSM_Buffer bufSalt(snaccEncryptionParams.salt.c_str(), 
         snaccEncryptionParams.salt.Len());

   if (snaccEncryptedX.encryptionAlgorithm.algorithm == pbeWithMD5AndRC2_CBC ||
       snaccEncryptedX.encryptionAlgorithm.algorithm == pbewithSHAAnd40BitRC2_CBC)
   {
      if (snaccEncryptedX.encryptionAlgorithm.algorithm == pbeWithMD5AndRC2_CBC)
      {
          oidHash = md5;
          iLength = 16;
          iPBEKeyBits = SM_FREE_RC2_DEFAULT_PBE_KEYBITS;
          blocksize = SM_COMMON_RC2_BLOCKSIZE;
         // generate the key using the salt, the iteration count, and the password
         SME(pK = GeneratePBEKey(&bufSalt, nIterCount, pszPassword, oidHash, iLength, lPassword));
      }
      else if (snaccEncryptedX.encryptionAlgorithm.algorithm == pbewithSHAAnd40BitRC2_CBC)
      {           //RWC; PRESENTLY SETUP ONLY for PKCS12 key generation.
          oidHash = sha_1;
          iLength = 20;
          iPBEKeyBits = 40;
          blocksize = SM_COMMON_RC2_BLOCKSIZE;//iPBEKeyBits/8;
         // generate the key using the salt, the iteration count, and the password
         SME(pK = GeneratePBEKey(&bufSalt, nIterCount, pszPassword, oidHash, iLength, lPassword));
      }

#ifndef CRYPTOPP_5_0
      // create the rc2 cipher 
      pRC2Decryption = new RC2Decryption ((const unsigned char*)pK->Access(),
          (iPBEKeyBits/8), iPBEKeyBits);   //128, 1024);
      // create cbc object
      cbc_decryption = new CBCPaddedDecryptor(*pRC2Decryption, 
         (const unsigned char *)pK->Access());
#else // CRYPTOPP_5_0
      CBC_Mode/*CFB_Mode*/<RC2>::Decryption *pTmpDecryption = new CBC_Mode/*CFB_Mode*/<RC2>::Decryption;
      pTmpDecryption->SetKeyWithIV((const unsigned char*)pK->Access(),
         (iPBEKeyBits/8),   //128, 1024);
         (const unsigned char *)pK->Access());
      cbc_decryption = pTmpDecryption;
#endif // CRYPTOPP_5_0

   }
   else if (snaccEncryptedX.encryptionAlgorithm.algorithm == pbeWithMD5AndDES_CBC)
   {
       oidHash = md5;
       iLength = 16;
       iPBEKeyBits = SM_FREE_RC2_DEFAULT_PBE_KEYBITS;

      // generate the key using the salt, the iteration count, and the password
      SME(pK = GeneratePBEKey(&bufSalt, nIterCount, pszPassword, oidHash, iLength, lPassword));

#ifndef CRYPTOPP_5_0
      // create our cipher
      pDESDecryption = new DESDecryption ((const unsigned char*)pK->Access());
      // create cbc object
      cbc_decryption = new CBCPaddedDecryptor (*pDESDecryption, 
         (const unsigned char *)pK->Access() + 8);
#else // CRYPTOPP_5_0
      CBC_Mode/*CFB_Mode*/<DES>::Decryption *pTmpDecryption = new CBC_Mode/*CFB_Mode*/<DES>::Decryption;
      pTmpDecryption->SetKeyWithIV((const unsigned char*)pK->Access(), 8, 
         (const unsigned char *)pK->Access()+8);
      cbc_decryption = pTmpDecryption;
#endif // CRYPTOPP_5_0

      blocksize = SM_COMMON_3DES_BLOCKSIZE;

   }
   else if (snaccEncryptedX.encryptionAlgorithm.algorithm == pbeWithSHAAnd3_KeyTripleDES_CBC)
   {
       oidHash = sha_1;
       iLength = 20;
       iPBEKeyBits = 24;

      // generate the key using the salt, the iteration count, and the password
      SME(pK = GeneratePBEKey(&bufSalt, nIterCount, pszPassword, oidHash, iLength, lPassword));

#ifndef CRYPTOPP_5_0
      // create our cipher
      p3DESDecryption = new DES_EDE3_Decryption ((const unsigned char*)pK->Access());
      // create cbc object
      cbc_decryption = new CBCPaddedDecryptor (*p3DESDecryption, 
         (const unsigned char *)pK->Access() + 8);
#else // CRYPTOPP_5_0
      CBC_Mode/*CFB_Mode*/<DES_EDE3>::Decryption *pTmpDecryption = new CBC_Mode/*CFB_Mode*/<DES_EDE3>::Decryption;
      pTmpDecryption->SetKeyWithIV((const unsigned char*)pK->Access(), 24, 
         (const unsigned char *)pK->Access()+8);
      cbc_decryption = pTmpDecryption;
#endif // CRYPTOPP_5_0

      blocksize = SM_COMMON_3DES_BLOCKSIZE;

   }
   else
   {
      SME_THROW(22, "EncryptionAlgorithm not recognized!", NULL);
   }

   // get the key to be decrypted
   CSM_Buffer bufEncryptedKey(snaccEncryptedX.encryptedData.c_str(),
            snaccEncryptedX.encryptedData.Len());
   CSM_Buffer bufEncodedPrivateKey;

   SME(RawDecrypt(&bufEncryptedKey, &bufEncodedPrivateKey, cbc_decryption, blocksize));

   /**RWC;
   #ifdef _DEBUG
   bufEncodedPrivateKey.ConvertMemoryToFile("./decryptedPrivateKey.log");
   #endif
   **/

   // ASN.1 decode the private key
   DECODE_BUF((&snaccX), &bufEncodedPrivateKey);

   if ((pX = new CSM_Buffer(snaccX.privateKey.c_str(), 
                            snaccX.privateKey.Len())) == NULL)
   {
      SME_THROW(SM_MEMORY_ERROR, "BAD new CSM_Buffer on privateKeyInfo", NULL);
   }    // END if new CSM_Buffer.

     // RWC;##########################################################
     // RWC;SPECIAL CHECK for odd private keys to remove a special 
     // RWC;  A0 tagged element (optional attributes) that causes the Crypto++ 
     // RWC;  library to crash.  (NOTE: This may be able to be removed in a
     // RWC;  future version).
     if (snaccX.privateKeyAlgorithm.algorithm == rsaEncryption ||
         snaccX.privateKeyAlgorithm.algorithm == AsnOid("1.2.840.113549.1.2"))
     {          // THEN delete optional attributes in PrivateKeyInfo...
        //#ifdef _DEBUG
        //      pX->ConvertMemoryToFile("./clearPrivateRSA.bin");
        //#endif //_DEBUG
         PrivateKeyInfo privateKeyInfo;
         long lstatus=0;
         DECODE_BUF_NOFAIL(&privateKeyInfo, pX, lstatus);
         if (lstatus == 0 && privateKeyInfo.attributes)
         {          // THEN delete the optional attributes, since it crashes
                    //  in the cyrpto++ library.
#ifndef CRYPTOPP_5_0    //NOT NECESSARY IN 5.0
             delete privateKeyInfo.attributes;
             delete pX;
             pX = NULL;
             privateKeyInfo.attributes = NULL;
             ENCODE_BUF(&privateKeyInfo, pX);  // reset/re-encode private key.
#endif // CRYPTOPP_5_0
         }  // END if attributes are present.
         else if (lstatus != 0)     // THEN we have the wrong format for private key.
         {
             privateKeyInfo.version = 0;
             privateKeyInfo.privateKeyAlgorithm.algorithm = rsaEncryption;
             CSM_Alg::LoadNullParams((AlgorithmIdentifier *)&privateKeyInfo.privateKeyAlgorithm);
             privateKeyInfo.privateKey.Set(pX->Access(), pX->Length());
             delete pX;
             pX = NULL;
             ENCODE_BUF(&privateKeyInfo, pX);  // reset/re-encode private key.
         }
     }      // END if rsaEncryption

   delete pK;

#ifndef CRYPTOPP_5_0
   if (pRC2Decryption)
       delete pRC2Decryption;
   if (pDESDecryption)
       delete pDESDecryption;
   if (p3DESDecryption)
       delete p3DESDecryption;
#endif // CRYPTOPP_5_0
   if (cbc_decryption)
       delete cbc_decryption;

   SME_FINISH
   SME_CATCH_SETUP
      if (pK)
         delete pK;
      if (pbufEncodedEncryptionParams)
         delete pbufEncodedEncryptionParams;
#ifndef CRYPTOPP_5_0
       if (pRC2Decryption)
           delete pRC2Decryption;
       if (pDESDecryption)
           delete pDESDecryption;
       if (p3DESDecryption)
           delete p3DESDecryption;
#endif // CRYPTOPP_5_0
   SME_FREE3_CATCH_FINISH

   return pX;
}       // END DecryptPrivateKey(...)

//////////////////////////////////////////////////////////////////////////
//
//
CSM_Buffer *CSM_Free3::GetDynamicPublicKey(CSM_AlgVDA &keyAlg)
{
   CSM_Buffer *ptmpBuf = NULL;

     if(m_pEphemeralAlg)
     {            // The alg params are in the CMS-10 msg format, not cert.
       keyAlg = *m_pEphemeralAlg;
     }

     if(m_pEphemeralDHY)
     {
       ptmpBuf = new CSM_Buffer(*m_pEphemeralDHY);
     }

     return(ptmpBuf);    // MAY be NULL if not generated yet.
}

void CSM_Free3::ClearDynamicKey()
{
                //  necessary for CTIL algs that generate dynamic keys;
                //   this reset will force generation of a new key.
    if (m_pEphemeralDHX)
    {
        delete m_pEphemeralDHX;
        m_pEphemeralDHX = NULL;
    }
    if (m_pEphemeralDHY)
    {
        delete m_pEphemeralDHY;
        m_pEphemeralDHY =NULL;
    }
}



#ifdef MAYBE
void CSM_Free3::sm_GenerateKeyIV(/*RWC;TBD;(char*,len)*/const char *passphrase, 
                                 const byte *salt, unsigned int saltLength, byte *key, byte *IV)
{
   unsigned int passphraseLength = strlen(passphrase);
   SecByteBlock temp(passphraseLength+saltLength);
   memcpy(temp, passphrase, passphraseLength);
   memcpy(temp+passphraseLength, salt, saltLength);
   SecByteBlock keyIV(KEYLENGTH+BLOCKSIZE);
   Mash(temp, passphraseLength + saltLength, keyIV, KEYLENGTH+BLOCKSIZE, MASH_ITERATIONS);
   memcpy(key, keyIV, KEYLENGTH);
   memcpy(IV, keyIV+KEYLENGTH, BLOCKSIZE);
}
#endif


//#########################################################################
//
CSM_Buffer* CSM_Free3::EncodeOtherInfo (CSM_Buffer *pUKM,
            char *counter, 
            const AsnOid &alg_OID, 
            long lKekLength)        // Input, for OtherInfo load.                         
{
    long tmplKekLength=0;

    //KeySpecificInfo *keyinfo = new KeySpecificInfo;
   AsnOcts  pubinfo;
   OtherInfo *other_info_buf = new OtherInfo;
   //AsnBuf *encoded_OtherInfo_buf = new AsnBuf;
   CSM_Buffer *pOtherInfo_Buffer = NULL;
   //char char_enc_buf[4096];

    SME_SETUP("CSM_Free3::EncodeOtherInfo");
   other_info_buf->keyInfo.algorithm = alg_OID;
   other_info_buf->keyInfo.counter.Set(counter,4);    
   if (pUKM && pUKM->Length())
   {
     other_info_buf->partyAInfo = new AsnOcts;
     other_info_buf->partyAInfo->Set(pUKM->Access(),pUKM->Length());
   }
   tmplKekLength = htonl(lKekLength*8);
   /*   suppPubInfo is the length of the generated KEK, in bits, represented
     as a 32 bit number in network byte order. E.g. for 3DES it
     would be the byte sequence 00 00 00 C0.
   // RWC; NOW, for MS integration tests, the integer is loaded with an
   // RWC;  ASN.1 encoded integer.
   AsnOcts b;
   b.Set((const char *)&tmplKekLength, 4);
   CSM_Buffer *pTmpBuf=NULL;
   ENCODE_BUF(&b, pTmpBuf);
   other_info_buf->suppPubInfo.Set(pTmpBuf->Access(), pTmpBuf->Length());
   delete pTmpBuf;*/
   other_info_buf->suppPubInfo.Set((char *)&tmplKekLength, 4);

   //RWC;other_info_buf->pubInfo = new AsnOcts;
   //RWC; other_info_buf->pubInfo->Set(UKM.Access(),UKM.Length());
   ENCODE_BUF(other_info_buf, pOtherInfo_Buffer);

   delete other_info_buf;
   //encoded_OtherInfo_buf->Init(&char_enc_buf[0], 4096);
    //encoded_OtherInfo_buf->ResetInWriteRvsMode();
   //other_info_buf->BEnc( *encoded_OtherInfo_buf);
    //OtherInfo_Buffer = encoded_OtherInfo_buf;

   SME_FINISH_CATCH
   return(pOtherInfo_Buffer);
}       // END CSM_Free3::EncodeOtherInfo(...)

//#########################################################################
/* <<< FROM RFC3278 >>>
   When using ECDH or ECMQV with EnvelopedData or AuthenticatedData, the
   key-encryption keys are derived by using the type:

      ECC-CMS-SharedInfo ::= SEQUENCE {
         keyInfo AlgorithmIdentifier,
         entityUInfo [0] EXPLICIT OCTET STRING OPTIONAL,
         suppPubInfo [2] EXPLICIT OCTET STRING   }

   The fields of ECC-CMS-SharedInfo are as follows:

      keyInfo contains the object identifier of the key-encryption
      algorithm (used to wrap the CEK) and NULL parameters.

      entityUInfo optionally contains additional keying material
      supplied by the sending agent.  When used with ECDH and CMS, the
      entityUInfo field contains the octet string ukm.  When used with
      ECMQV and CMS, the entityUInfo contains the octet string addedukm
      (encoded in MQVuserKeyingMaterial).

      suppPubInfo contains the length of the generated KEK, in bits,
      represented as a 32 bit number, as in [CMS-DH].  (E.g. for 3DES it
      would be 00 00 00 c0.)

   Within CMS, ECC-CMS-SharedInfo is DER-encoded and used as input to
   the key derivation function, as specified in [SEC1, Section 3.6.1].
   Note that ECC-CMS-SharedInfo differs from the OtherInfo specified in
   [CMS-DH].  Here, a counter value is not included in the keyInfo field
   because the key derivation function specified in [SEC1, Section
   3.6.1] ensures that sufficient keying data is provided.


   <<< FROM SEC1, 3.6.1 >>>
  3.6.1 ANSI X9.63 Key Derivation Function
Keying data should be calculated using ANSI-X9.63-KDF as follows:
Setup: Select one of the approved hash functions listed in Section 3.5. Let Hash denote 
the hash function chosen, hashlen denote the length in octets of hash values computed 
using Hash, and hashmaxlen denote the maximum length in octets of messages that can 
be hashed using Hash.

Input: The input to the key derivation function is:
1. An octet string Z which is the shared secret value.
2. An integer keydatalen which is the length in octets 
of the keying data to be generated.
3. (Optional) An octet string SharedInfo which consists of some data shared by the 
entities intended
to share the shared secret value Z.
Output: The keying data K which is an octet string of length keydatalen octets, or 
‘invalid’.
Actions: Calculate the keying data K as follows:
1. Check that Z || SharedInfo || +4 < hashmaxlen. If  || Z || + || SharedInfo ||+4. 
hashmaxlen, output ‘invalid’ and stop.
2. Check that keydatalen< hashlen.
3. Output K


  <<< FROM X9.63 Summary
3.8 Key Derivation Function (kdf)
The key derivation function is used by the key agreement schemes to compute keying data from
a shared secret value. The key derivation function will also be used by the asymmetric
encryption schemes. The key derivation function is a simple construction based on a hash
function.
Input:
· Shared value z
· Key length keydatalen
· Optional SharedInfo
Compute:
Set counter = 1
For i = 1 to (j = keydatalen/hashlen) , do:
  Hashi = H(Z || counter || [SharedInfo])
  Increment counter
  Increment i
Let HHashj denote Hashj if keydatalen/hashlen is an integer, and let it denote the
(keydatalen - (hashlen*j)) leftmost bits of Hashj otherwise
Set KeyData = Hash1||Hash2||…||Hashj-1||HHashj
Output: KeyData
*/
//
CSM_Buffer* CSM_Free3::ComputeSharedInfoKeyDerivationFunction(
            SecByteBlock &ZZ,       // INPUT
            CSM_Buffer *pUKM,       // INPUT
            const AsnOid &alg_OID,  // INPUT
            long lKekLength,        // INPUT, for SharedInfo load.                         
            bool bMQVFlag)          // INPUT, for special MQV SharedInfo load.
                                //RWC;TBD;MORE TO FOLLOW FOR MQV, need OriginatorPublicKey
{
    long tmplKekLength=0;
    CSM_Buffer k1, k2, tempBuffer;
    CSM_Buffer *pTEK=NULL;
    ECC_CMS_SharedInfo SNACC_ECC_CMS_SharedInfo;
    MQVuserKeyingMaterial SNACC_MQVuserKeyingMaterial;
    AsnOcts  pubinfo;
    CSM_Buffer *pSharedInfo_Buffer = NULL;

   SME_SETUP("CSM_Free3::ComputeSharedInfoKeyDerivationFunction");

   SNACC_ECC_CMS_SharedInfo.keyInfo.algorithm = alg_OID;
   if (pUKM && pUKM->Length())
   {
       if (!bMQVFlag)
       {
         SNACC_ECC_CMS_SharedInfo.entityUInfo = new AsnOcts;
         SNACC_ECC_CMS_SharedInfo.entityUInfo->Set(pUKM->Access(),pUKM->Length());
       }    // IF bMQVFlag
       else
       {
           //MQVuserKeyingMaterial
           SME_THROW(22, "MQV ECDH NOT supported yet!", NULL);
       }    // END IF bMQVFlag
   }
   tmplKekLength = htonl(lKekLength*8);
   /*   suppPubInfo is the length of the generated KEK, in bits, represented
     as a 32 bit number in network byte order. E.g. for 3DES it
     would be the byte sequence 00 00 00 C0.*/
   // RWC; NOW, for MS integration tests, the integer is loaded with an
   // RWC;  ASN.1 encoded integer.
   SNACC_ECC_CMS_SharedInfo.suppPubInfo.Set((char *)&tmplKekLength, 4);
   ENCODE_BUF(&SNACC_ECC_CMS_SharedInfo, pSharedInfo_Buffer);

   long tmplCounter, lLength;
   pTEK = new CSM_Buffer;
   for (int ii=0; ii < (lKekLength-1)/20+1; ii++)  // 20 is the SHA-1 length.
   {
       // concatentate ZZ, counter, SharedInfo
       SME(tempBuffer.Open(SM_FOPEN_WRITE));
       SME(tempBuffer.Write((char *)ZZ.data(), ZZ.m_size));
       tmplCounter = htonl(ii+1);
       SME(tempBuffer.Write((char *)&tmplCounter, sizeof(tmplCounter)));
       SME(tempBuffer.Write((pSharedInfo_Buffer->Access()), pSharedInfo_Buffer->Length()));
       tempBuffer.Close();
       // now hash
       CSM_Free3::SMTI_DigestData(&tempBuffer, &k1);
       if (pTEK->Length()+k1.Length() > lKekLength)
           lLength = lKekLength - pTEK->Length();
       else
           lLength = k1.Length();
       SME(pTEK->Open(SM_FOPEN_APPEND));
       SME(pTEK->Write(k1.Access(), lLength));  //WRITE exact length required.
       SME(pTEK->Close());
   }        // END FOR as many octets as necessary.
   delete pSharedInfo_Buffer;


   SME_FINISH_CATCH

   return(pTEK);
}       // END CSM_Free3::EncodeSharedInfo(...)


//////////////////////////////////////////////////////////////////////////
// 
CSM_Buffer* CSM_Free3::GetDSAY()
{
   int nLen = 0;
   byte b[2048];
   CSM_Buffer *pDSAPublicKey = new CSM_Buffer;

   SME_SETUP("CSM_Free3::GetDSAY");

   nLen = sm_Free3CryptoppDEREncode(m_DSAY, &b[0], 2048);
        //m_DSAY.DEREncode(&b[0]);
   pDSAPublicKey->Set((char *)(&b[0]), nLen);

   SME_FINISH
   SME_CATCH_SETUP

   SME_FREE3_CATCH_FINISH

   return pDSAPublicKey;
}

//
//
CSM_TokenInterface *CSM_Free3::AddLogin(
   CSM_Buffer &CertBuf,       // IN, public key and algs
   CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
   char *lpszPassword,        // IN, password to pbe decrypt privatekey
   char *lpszID)              // CTIL specific ID
{
    CSM_TokenInterface *pResultTI=NULL;
    
    pResultTI = AddLoginStatic(this, CertBuf, pSFLPrivateKey, lpszPassword, lpszID);

    return pResultTI;
}
//
//
CSM_TokenInterface *CSM_Free3::AddLoginStatic(CSM_Free3 *pFreeIn,
   CSM_Buffer &CertBuf,       // IN, public key and algs
   CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
   char *lpszPassword,        // IN, password to pbe decrypt privatekey
   char *lpszID,              // CTIL specific ID
   CSM_MsgCertCrls *pCertPath)
{
   CSM_TokenInterface *pTokenInterface=NULL;
   CSM_AlgLstVDA *pDigestAlgs=NULL;
   CSM_AlgLstVDA *pKeyEncryption=NULL;
   CSM_AlgLstVDA *pDigestEncryption=NULL;
   CSM_AlgLstVDA *pContentEncryption=NULL;
   AlgorithmIdentifier *pAlgID=NULL;
   CSM_Free3 *pFree=pFreeIn;


   SME_SETUP("CSM_Free3::AddLoginStatic");

   SME(CertBuf.ConvertFileToMemory());

   if (pFree == NULL)
   {  
      // THIS MEMORY will be returned in the CSM_Tokeninterface *.
      // generate a new FREE CTI class
      if ((pFree = new CSM_Free3(id_dsa)) == NULL)    // DEFAULT DSA
          SME_THROW(SM_MEMORY_ERROR, "AddLoginStatic: bad new CSM_Free3.", NULL);
         // CSM_Free3 constructor set's Alg IDs
     // JAS: added this.
     // From: "John Stark" <jas@xxxxxxxxxxxx> 
     // Date: Thu, 18 Mar 2004 23:34:58 -0000 
     //RWC;REMOVED due to interference with SFL logic, specifically Decryption
     //RWC;REMOVED  pFree->SetDefaultOIDs(rsa);   // Add RSA, DSA already present.
}

   //RWC;DISABLED; LOGIC FIXED TO ALLOW RE-ENTRANCY;
   //RWC:if (CertBuf.Length() == 0 && pSFLPrivateKey  == 0 &&
   //RWC:   (lpszPassword && strcmp(lpszPassword, "NULL") == 0))
   pFree->m_ThreadLock.threadUnlock();
                                //FREE this instance to be re-usable
                                //  in threads, they will be safe with
                                //  no private key references.

   if (pCertPath)
       pFree->m_pCertPath = pCertPath;  // Take memory from App.
   if (lpszPassword)
   {
      // store other information in the Free CTI
      pFree->SetPassword(lpszPassword);
   }
   if (pSFLPrivateKey)
   {
      SME(pFree->SetX(*pSFLPrivateKey));
   }

   // store parameters and Y in the preferred Alg for this instance
   pAlgID = NULL;
   SME(pFree->GetParamsAndY(CertBuf, NULL, pAlgID));
   if (pAlgID)
      pFree->SetDefaultOIDs(pAlgID->algorithm);
   else                             // MUST be NULL entry, no public key.
      pFree->SetDefaultOIDs(rsa);   // Add RSA, DSA already present.

   char *lpszTmpId;
   if (strcmp(lpszID, "NULL") != 0)
   {
       lpszTmpId = (char *)calloc(1, strlen("Free3") + strlen(lpszID)+1);
       strcpy(lpszTmpId, "FREE3");      // Set ID base name for instance.
       strcat(lpszTmpId, lpszID);
   }
   else
       lpszTmpId = strdup("FREE3");
   // store the prefix
   pFree->m_pszPrefix = lpszTmpId;
   // RWC; Set custom parameters from cert algorithm if necessary.
   // pAlgID was set by GetParamsAndY.  We store the parameters in
   // the instance so they may be used as necessary later on
   pFree->BTIGetAlgIDs(&pDigestAlgs, &pDigestEncryption, 
       &pKeyEncryption, &pContentEncryption);   
   if (pAlgID) // only do this if there is something in pAlgID
   {
       CSM_AlgLstVDA::iterator itTmpAlg;
      if (pAlgID->algorithm == id_dsa_with_sha1 ||
          pAlgID->algorithm == id_dsa) // do DSA side
      {
        if (pAlgID->parameters != NULL)
        {
         // loop through digest encryption algs until we find DSA
         for (itTmpAlg =  pDigestEncryption->begin(); 
              itTmpAlg != pDigestEncryption->end() && 
                  *itTmpAlg->AccessSNACCId() != id_dsa_with_sha1; 
              ++itTmpAlg);
   
         if (itTmpAlg != pDigestEncryption->end())
         {
            // if we found one, store it
            CSM_Alg *pA=new CSM_Alg(*pAlgID);  //NECESSARY for Unix compile.
            *itTmpAlg = *pA;
            delete pA;            // since this instance will never do key encryption,
            // we can clear that part
            pFree->ClearKeyEncryptionCapability();
            // reset digest encryption (which has parameters added),
            pFree->BTISetAlgIDs(NULL, pDigestEncryption, 
                  NULL, NULL);
         }
        }
        else     // CANNOT perform if there is a private key; MUST HAVE PARAMS.
        {
            if (pSFLPrivateKey)
            {
               SME_THROW(26, "MISSING DSA Params, with a private key login.", 
                   NULL);
            }
        }
      }

   }
   if (pDigestAlgs)
   {
      delete pDigestAlgs;
      pDigestAlgs = NULL;
   }
   if (pDigestEncryption)
   {
      delete pDigestEncryption;
      pDigestEncryption = NULL;
   }
   if (pKeyEncryption)
   {
      delete pKeyEncryption;
      pKeyEncryption = NULL;
   }
   if (pContentEncryption)
   {
      delete pContentEncryption;
      pContentEncryption = NULL;
   }
   if (pAlgID)
       delete pAlgID;
   pTokenInterface = pFree;  // setup for generic load into instance array

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_FREE3_CATCH_FINISH


   return(pTokenInterface);
}

// determines if preferred oid is RSA (which is key transfer) and returns false, else this
// returns true its a key agreement
bool CSM_Free3::SMTI_IsKeyAgreement() 
{  
   bool keyAgree = true;
   AsnOid *oidKE = NULL;

   oidKE = GetPrefKeyEncryption();
   if (*oidKE == rsa || *oidKE == AsnOid("1.2.840.113549.1.2") ||
       *oidKE == rsaEncryption ||  *oidKE == id_RSAES_OAEP)
   {
      keyAgree = false;
   }

   // clean up oid
   if (oidKE)
      delete oidKE;

   return (keyAgree);
}

_END_CERT_NAMESPACE
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;
extern "C" {

#ifndef NO_DLL

long Make_argv(char *string, int *pargc, char ***pargv);
void Delete_argv(int argc, char **pargv);

SM_FREE3DLL_API SM_RET_VAL DLLBuildTokenInterface(CSM_CtilMgr &Csmime, 
    char *lpszBuildArgs)
{
    SM_RET_VAL status = 0;
    int argc1=0;
    char **argv1=NULL;
    char ptr[30];

    SME_SETUP("DLLBuildTokenInterface");
    memset(ptr, '\0', 30);
    if (lpszBuildArgs && strlen(lpszBuildArgs))
    {
      for (int i=0; i < (int)strlen("sm_Free3DLL"); i++)
        ptr[i] = (char)toupper(lpszBuildArgs[i]);
      // Preliminary check that this request is for our library.
      if (strncmp(ptr, "SM_FREE3DLL", strlen("sm_Free3DLL")) == 0)
      {
        Make_argv(lpszBuildArgs, &argc1, &argv1);
        if (argc1 == 4 && strstr(lpszBuildArgs, ".p12") == NULL &&
                          strstr(lpszBuildArgs, ".pfx") == NULL) 
        {           // Handle Address Book setup.
           // Pass char *pszPassword, char *pszAddressBook, char *pszPrefix
           SMFree3Init(&Csmime, argv1[1], argv1[2], argv1[3]);
        }
        else if (argc1 >= 5 && strstr(lpszBuildArgs, ".p12") == NULL &&
                               strstr(lpszBuildArgs, ".pfx") == NULL)    
                               // Handle single login attempt.
        {
            CSM_Buffer *pCertBuf=NULL;
            CSM_Buffer *pPrivateKey=NULL;
            CSM_TokenInterface  *pTokenInterface;

            if (strcmp(argv1[1], "NULL") == 0)
                pCertBuf = new CSM_Buffer;  // ALLOW blank cert.
            else
                pCertBuf = new CSM_Buffer(argv1[1]);
            if (strcmp(argv1[2], "NULL") != 0)
                pPrivateKey = new CSM_Buffer(argv1[2]);
            CSM_MsgCertCrls *pCertPath=new CSM_MsgCertCrls;
            if (strcmp(argv1[1], "NULL") != 0)
            {               // Pre-load User cert, if present.
                CSM_CertificateChoice *pCert=new CSM_CertificateChoice(*pCertBuf);
                pCertPath->AddCert(pCert);
            }
            if (argc1 > 5)  // other parameters are cert path certs.
            {               // (MUST BE DONE BEFORE AddLoginStatic(...))
                for (int ii=5; ii < argc1; ii++)
                {
                  if (strcmp(argv1[ii], "SM_FREE3") != 0)
                  {             // IGNORE optionsl "SM_FREE3" string.
                    CSM_Buffer tmp_buf(argv1[ii]);
                    pCertPath->AddCert(
                        new CSM_CertificateChoice(tmp_buf));
                  }
                }
            }
            pTokenInterface  = CSM_Free3::AddLoginStatic(NULL, *pCertBuf,
                pPrivateKey, argv1[3], argv1[4], pCertPath);
            // DO NOT FREE pCertPath, it is taken by AddLoginStatic(...)
            GLOBALAddLoginFinish(Csmime, pTokenInterface, argv1[4], pCertPath);
            //delete pCertPath;
            if (pCertBuf)
                delete pCertBuf;
            if (pPrivateKey)
                delete pPrivateKey;
        }
        else if (argc1 == 3 || strstr(lpszBuildArgs, ".p12") != NULL ||
                               strstr(lpszBuildArgs, ".pfx") != NULL)    
                               // Handle PKCS12 (PFX) setup.
        {
            CSM_MsgCertCrls *pCertPath=NULL;
            if (argc1 > 3)  // other parameters are cert path certs.
            {               // (MUST BE DONE BEFORE AddLoginStatic(...))
                pCertPath=new CSM_MsgCertCrls;
                for (int ii=3; ii < argc1; ii++)
                {
                    CSM_Buffer tmp_buf(argv1[ii]);
                    pCertPath->AddCert(
                        new CSM_CertificateChoice(tmp_buf));
                }
            }
           // Pass char *pszPassword, char *pszPFXFile
#ifdef OPENSSL_PKCS12_ENABLED    // ONLY for backward compatibility!!!
           status = SFLFree3PKCS12Init(Csmime, argv1[2], argv1[1], pCertPath);
#else                            // DEFAULT!!!
           status = SFLFree3PKCS12Init2(Csmime, argv1[2], argv1[1], pCertPath);
           if (pCertPath)
               delete pCertPath;
#endif                           // OPENSSL_PKCS12_ENABLED
        }
        else    // OTHER MODELS to be supported.
        {
            status = -1;
        }
        Delete_argv(argc1, argv1);
        argv1 = NULL;
      }
      else
      {
        status = -1;
        //cout << "DLL1BuildTokenInterface failed!!!\n";
      }
    }
    else    // if buildargs present
    {
        CSM_Free3 *pF3TokenInterface;
          if ((pF3TokenInterface = new CSM_Free3(id_dsa)) == NULL)    // DEFAULT DSA
             SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
          pF3TokenInterface->SetDefaultOIDs(rsa);  // LOAD 2nd set of algs for verify.
          pF3TokenInterface->m_pszPrefix = strdup("Free3NULL");
          pF3TokenInterface->SMTI_Unlock();
                                        // FREE this instance to be re-usable 
                                        //  in threads, they will be safe with
                                        //  no private key references.
          GLOBALAddLoginFinish(Csmime, pF3TokenInterface, pF3TokenInterface->m_pszPrefix, NULL);
    }       // END if buildargs present.

    SME_FINISH
    SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      if (argv1)
         Delete_argv(argc1, argv1);
    SME_FREE3_CATCH_FINISH

    return(status);
}


SM_FREE3DLL_API char * DLLMallocDiag()
{
    return((char *) calloc(1,1));
}

SM_FREE3DLL_API char * DLLGetId()
{
    return(strdup("sm_FREE3DLL"));
}


#endif      // #ifndef NO_DLL


}   //extern "C"


// EOF sm_free3.cpp
