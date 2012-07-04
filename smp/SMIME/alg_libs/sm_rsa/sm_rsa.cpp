//////////////////////////////////////////////////////////////////////////
// sm_rsa.cpp
//
// This CTI Library implements RSA, RC2, MD5 and SHA1 using BSAFE.
//
//////////////////////////////////////////////////////////////////////////

// TBD, no surrender contexts are being used anywhere in this library,
// we may want to consider using them where appropriate in the future...


#if defined(WIN32)
#include <process.h>   // for getpid()
//RWC;#elif defined(SUNOS) || defined (SOLARIS) 
#else
#include <unistd.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <setjmp.h>
#include "sm_CryptoKeysRsaExport.h"
#include "sm_rsa.h"
#include "sm_rsa_asn.h"
#include "sm_VDASupport_asn.h"
#include "sm_AppLogin.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;
//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_Login(void)
{
   // TBD, anything useful to do here?
   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_Sign(
            CSM_Buffer *pData, // input, data to be signed
            CSM_Buffer *pEncryptedDigest, // signature
            CSM_Buffer *pDigest) // digest
{
   SME_SETUP("CSM_Rsa::SMTI_Sign");
   CSM_Buffer bufferDigest;
   CSM_Buffer *pTempDigest = &bufferDigest;
   B_ALGORITHM_OBJ digitalSigner = (B_ALGORITHM_OBJ)NULL_PTR;
   long status;
   unsigned int nSignatureLen;
   B_KEY_OBJ privateKey = (B_KEY_OBJ)NULL_PTR;
   unsigned char *pch;
   AsnOid *pDigestOID=NULL;

   if ((pData == NULL) || (pEncryptedDigest == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL)

   // if pDigest was passed in, use it, otherwise, use local temp
   if (pDigest != NULL)
      pTempDigest = pDigest;
     
   // get the decrypted private key
   SME(privateKey = GetBsafePrivateKey());

   // digest the incoming data (done twice - here and with B_SignUpdate)
   // TBD, if we have problems verifying the signature, look carefully
   // at this because technically, this digest is not used for the
   // signature, the digest internal to B_SignFinal is used...(they
   // should be the same, though...)
      if (pTempDigest == NULL || !pTempDigest->Length())
      {
        SME(SMTI_DigestData(pData, pTempDigest));
      }
      
   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&digitalSigner)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // Set the Algorithm Object using MD5 with RSA encryption
   // RWC; ?????? WHY HARDCODED TO MD5, should be preferred algorithm.
   pDigestOID = GetPrefDigest();
   if (*pDigestOID == md5 || *pDigestOID == md5WithRSAEncryption)
   {
     if ((status = B_SetAlgorithmInfo(digitalSigner, 
         AI_MD5WithRSAEncryption, NULL_PTR)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);
   }
   else if (*pDigestOID == sha_1 || *pDigestOID == sha_1WithRSAEncryption_ALT
       || *pDigestOID == sha_1WithRSAEncryption)

   {
     if ((status = B_SetAlgorithmInfo(digitalSigner, 
         AI_SHA1WithRSAEncryption, NULL_PTR)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);
   }
   else
      SME_THROW(status, "Unsupported DigestOID for B_SetAlgorithmInfo", 
         NULL);

   // Associate a key and algorithm method with the algorithm object
   // through B_SignInit.
   if ((status = B_SignInit(digitalSigner, privateKey, 
        m_pCHOOSER, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_SignInit failed", NULL);

   // Digest the data to sign with B_SignUpdate
   if ((status = (long)B_SignUpdate(digitalSigner, 
         (unsigned char *)pData->Access(),
         pData->Length(), (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_SignUpdate failed", NULL);

   // allocate memory to receive the signature
   if ((pch = (unsigned char *)calloc(1, 
         m_keygenParams.modulusBits / 8)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Encrypt the digest and output the result to the signature buffer.
   if ((status = (long)B_SignFinal(digitalSigner, (unsigned char *)pch, 
         &nSignatureLen, (m_keygenParams.modulusBits / 8), 
         (B_ALGORITHM_OBJ)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_SignFinal failed", NULL);
   
   // now, pch has the signature, write it to pEncryptedDigest
   SME(pEncryptedDigest->Open(SM_FOPEN_WRITE));
   SME(pEncryptedDigest->Write((char *)pch, nSignatureLen));
   SME(pEncryptedDigest->Close());
   free(pch);
   delete pDigestOID;

   // Destroy objects.
   B_DestroyAlgorithmObject(&digitalSigner);
   B_DestroyKeyObject(&privateKey);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_Verify(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA *pDigestAlg, // input
            CSM_AlgVDA *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
   long lRet = SM_NO_ERROR;
   SME_SETUP("CSM_Rsa::SMTI_Verify");
   AsnOid *poidDigestEnc = pSignatureAlg->GetId();

   if (*poidDigestEnc == rsa ||
       *poidDigestEnc == sha_1WithRSAEncryption_ALT ||
       *poidDigestEnc == sha_1WithRSAEncryption ||
       *poidDigestEnc == bsafe_id_rsa_encr ||
       *poidDigestEnc == rsaEncryption ||
       *poidDigestEnc == md5WithRSAEncryption)    // Check local supported verify...
   {
       lRet = SMTI_VerifyRSA(pSignerKey, (CSM_Alg *)pDigestAlg, (CSM_Alg *)pSignatureAlg, pData, 
           pSignature);
   }
   else     // Try the CSM_Common supported classes.
   {
       lRet = CSM_Common::SMTI_Verify(pSignerKey, pDigestAlg, 
           pSignatureAlg, pData, pSignature);
       if (lRet != 0)
       {
          SME_THROW(22, "Signature Algorithmn oid is not recognized!", NULL);
       }
   }
   if (poidDigestEnc)
       delete poidDigestEnc;
   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(lRet);
}


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_VerifyRSA(
            CSM_Buffer *pSignerKey, // input
            CSM_Alg    *pDigestAlg, // input
            CSM_Alg    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
   B_ALGORITHM_OBJ digitalVerifier = (B_ALGORITHM_OBJ)NULL_PTR;
   long status = SM_NO_ERROR;
   B_KEY_OBJ publicKey = (B_KEY_OBJ)NULL_PTR;
   ITEM itemSignerKey;

   SME_SETUP("CSM_Rsa::SMTI_VerifyNoOidCheck");

   if ((pData == NULL) || (pSignerKey == NULL) || (pSignature == NULL) ||
         /*RWC;(pDigestAlg == NULL) ||*/ (pSignatureAlg == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL)

   // check the signature alg    
   if (*(pSignatureAlg->AccessSNACCId()) != bsafe_id_rsa_encr &&
       *(pSignatureAlg->AccessSNACCId()) != rsaEncryption &&
       *(pSignatureAlg->AccessSNACCId()) != sha_1WithRSAEncryption &&
       *(pSignatureAlg->AccessSNACCId()) != md5WithRSAEncryption)
      SME_THROW(SM_RSA_UNSUPPORTED_ALG, NULL, NULL);

   //  TBD, Params?

   // Create a public Key Object
   if ((status = B_CreateKeyObject(&publicKey)) != 0)
      SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // ASN.1 decode the provided sender's public key into our public key object
   itemSignerKey.len = pSignerKey->Length();
   itemSignerKey.data = (unsigned char *)pSignerKey->Get();
   if ((status = (long)B_SetKeyInfo(publicKey, KI_RSAPublicBER,
         (POINTER)&itemSignerKey)) != 0)
   {              // RWC; ATTEMPTING different format form MS Outlook Express.
      RSAPublicKey SnaccRSAPublicKey;
      A_RSA_KEY rsaKey;

      DECODE_BUF(&SnaccRSAPublicKey, pSignerKey);  // will create exception if 
                                                   //  decode fails.
      rsaKey.modulus.data = (unsigned char *)SnaccRSAPublicKey.modulus.c_str();
      rsaKey.modulus.len = SnaccRSAPublicKey.modulus.length();
      rsaKey.exponent.data = (unsigned char *)SnaccRSAPublicKey.publicExponent.c_str();
      rsaKey.exponent.len = SnaccRSAPublicKey.publicExponent.length();
      if ((status = (long)B_SetKeyInfo(publicKey, KI_RSAPublic, 
         (POINTER)&rsaKey)) != 0)
        SME_THROW(status, "B_SetKeyInfo failed 2", NULL);
   }
  
   free(itemSignerKey.data);

    if ((status = (long)B_CreateAlgorithmObject (&digitalVerifier)) != 0)
         SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

    if (pDigestAlg == NULL ||
       *pDigestAlg->AccessSNACCId() == md5/*bsafe_id_md5*/)
    {
      // Set the Algorithm Object using SHA1 with RSA encryption
      if ((status = B_SetAlgorithmInfo(digitalVerifier, 
         AI_MD5WithRSAEncryption, NULL_PTR)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed 2", NULL);
    }
    else if (*pDigestAlg->AccessSNACCId() == sha_1/*bsafe_id_sha1*/ || 
             *pDigestAlg->AccessSNACCId() == sha_1WithRSAEncryption ||
             *pSignatureAlg->AccessSNACCId() == sha_1WithRSAEncryption)
    {
      // Set the Algorithm Object using MD5 with RSA encryption
      if ((status = B_SetAlgorithmInfo(digitalVerifier, 
         AI_SHA1WithRSAEncryption, NULL_PTR)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);
    }
    else if (pDigestAlg == NULL ||
        *pDigestAlg->AccessSNACCId() == md5WithRSAEncryption)    
    {      // Set the Algorithm Object using SHA1 with RSA encryption
      if ((status = B_SetAlgorithmInfo(digitalVerifier,
          AI_MD5WithRSAEncryption, NULL_PTR)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed 2", NULL);    
    }
    else
         SME_THROW(status, "Unsupported DigestAlgorithm for signature", NULL);


      // Create an Algorithm Object
   // Associate a key and algorithm method with the algorithm object
   // through B_VerifyInit.
   if ((status = B_VerifyInit(digitalVerifier, publicKey, 
         m_pCHOOSER, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_VerifyInit failed", NULL);

   // Digest the data that was signed with B_VerifyUpdate. 
   if ((status = (long)B_VerifyUpdate(digitalVerifier, 
         (unsigned char *)pData->Access(),
         pData->Length(), (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_VerifyUpdate failed", NULL);
      
   // Decrypt the signature and compare the result to the digest.
   if ((status = (long)B_VerifyFinal(digitalVerifier, 
         (unsigned char *)pSignature->Access(), 
         pSignature->Length(), (B_ALGORITHM_OBJ)NULL_PTR,
         (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_VerifyFinal failed", NULL);

   // Destroy objects.
   B_DestroyAlgorithmObject(&digitalVerifier);
   B_DestroyKeyObject(&publicKey);

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return status;
}

#ifdef CARL
/*  RC2 Key Wrap

   1.  Let the content-encryption key be called CEK, and let the length
       of the content-encryption key in octets be called LENGTH.
   2.  Compute an 8 octet key checksum value on CEK as described above
       in Section 12.6.1, call the result ICV.
   3.  Let CEKICV = LENGTH || CEK || ICV.  LENGTH is a single octet.
   4.  Let CEKICVPAD = CEKICV || PAD.  If the length of CEKICV is a
       multiple of 8, the PAD has a length of zero.  If the length of
       CEKICV is not a multiple of 8, then PAD contains the fewest
       number of random octets to make CEKICVPAD a multiple of 8.
  5A.  Generate 8 octets at random, call the result IV.
  5B.  Encrypt CEKICVPAD in CBC mode using the key-encryption key.
       Use the random value generated in the previous step as the
       initialization vector (IV).  Call the ciphertext TEMP1.
   6.  Let TEMP2 = IV || TEMP1.
   7.  Reverse the order of the octets in TEMP2.  That is, the most
       significant (first) octet is swapped with the least significant
       (last) octet, and so on.  Call the result TEMP3.
   8.  Encrypt TEMP3 in CBC mode using the key-encryption key.  Use
       an initialization vector (IV) of 0x4adda22c79e82105. */

//
//  This logic is separated out to handle KTRI KeyWrap algorithm and processing.
SM_RET_VAL CSM_Rsa::SMTI_GenerateKeyWrap(
            CSM_Buffer *pCEK, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyTransfer algs.
            CSM_Buffer *pMEK, // In; may be specified.
            CSM_Buffer *pIV)  // In, to avoid specific alg encoding by app.
{
   AsnOid *pPreferredOID = GetPrefContentEncryption();
   SM_RET_VAL status=0;
   CSM_Buffer *pCEKICV = NULL;
   CSM_Buffer Iv;  
   CSM_Buffer *pTEMP1 = NULL;  
   CSM_Buffer *pTEMP2 = NULL;
   CSM_Buffer TEMP3;
   CSM_Buffer tmp;
   char *pLENGTH = NULL;
   int i,j;

   SME_SETUP("CSM_Rsa::SMTI_GenerateKeyWrap");
   if (*pPreferredOID == id_alg_CMSRC2wrap) 
   {  
      pLENGTH = (char *) pCEK->Length();
      //CMS-11 Step 2 Create Checksum.
      // Compute 20 octet SHA1 message digest on the content-encryption key (CEK).
      char pICV[20];
      SHA1_InitializeHash();
      SHA1_GetHash(pCEK->Length(), (unsigned char *)pCEK->Access(), (unsigned char *)pICV);

      //CMS-11 Step 3 build pCEKICV out of incomming CEK and ICV data.
      pCEKICV = new CSM_Buffer();
      SME(pCEKICV->Open(SM_FOPEN_WRITE));
      SME(pCEKICV->Write(pLENGTH, 1));
      SME(pCEKICV->Write(pCEK->Access(), pCEK->Length()));
      SME(pCEKICV->Write((char *)pICV, 8));
      pCEKICV->Close();

   }
   else
      pCEKICV = pCEK;

   //CMS-11 Steps 5A Generate Random IV.
   SME(SMTI_Random(NULL, &Iv, SM_RSA_RC2_BLOCKSIZE));

   //CMS-11 Steps 4,5B Padding and Encryption is done by SMTI_Encrypt. 
   SME(status = SMTI_Encrypt(pCEKICV, pTEMP1, pParameters, 
      pMEK, &Iv));

   //CMS-11 Steps 6 Concatenate TEMP and Iv to make TEMP2.
   pTEMP2 = new CSM_Buffer();
   SME(pTEMP2->Open(SM_FOPEN_WRITE));
   SME(pTEMP2->Write(pTEMP1->Access(), pTEMP1->Length()));
   SME(pTEMP2->Write(Iv.Access(),Iv.Length()));
   pTEMP2->Close();

   //CMS-11 Steps 7 Reverse order of octets in TEMP2.
   char *pTemp2 = pTEMP2->Access();

   tmp = CSM_Buffer(pTEMP2->Length());
   char *pTemp3 = tmp.Access();

   for(i = pTEMP2->Length(),j = 0; i >= 0; i--,j++)
   {
      pTemp3[j] = pTemp2[i];
   }

   TEMP3 = CSM_Buffer(pTemp3);

   // CMS-11 Step 8 pIV is a constant loaded prior to
   // this call by SMTI_GenerateKeyWrapIV.
   SME(status = SMTI_Encrypt(&TEMP3, pEncryptedData, pParameters, 
      pMEK, pIV));


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(status);
}
#endif


//
//
SM_RET_VAL CSM_Rsa::SMTI_GenerateKeyWrap(
            CSM_Buffer *pCEK, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT.
            CSM_Buffer *pMEK, // In; may be specified.
            CSM_Buffer *pIV)  // In, to avoid specific alg encoding by app.
{
   SM_RET_VAL status=0;
   CSM_Buffer *pCEKICV = NULL;
   CSM_Buffer Iv,PAD;  
   CSM_Buffer TEMP3;
   CSM_Buffer tmp;
   unsigned char LENGTH;

   SME_SETUP("CSM_Rsa::SMTI_GenerateKeyWrap");

   // CMS-11 Step 1 Create LENGTH
   LENGTH = (unsigned char)pCEK->Length();

   SME(SMTI_Random(NULL, &PAD, 8 - ((pCEK->Length() + 1) % 8)));

   //CMS-11 Step 3 build pCEKICV out of incomming CEK and ICV data.
   pCEKICV = new CSM_Buffer();
   SME(pCEKICV->Open(SM_FOPEN_WRITE));
   SME(pCEKICV->Write((char *)&LENGTH, 1));
   SME(pCEKICV->Write(pCEK->Access(), pCEK->Length()));
   SME(pCEKICV->Write(PAD.Access(), PAD.Length()));
   pCEKICV->Close();

   // CMS-11 Finish KeyWrap processing using the CSM_Common class.
   status = CSM_Common::SMTI_GenerateKeyWrapFinish(pEncryptedData, pParameters,
            pMEK, pIV, pCEKICV);  // extra param is raw data in.
   delete pCEKICV;

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(status);
}


//
//  This logic is separated out to handle KARI and KEK CMS processing which
//  both use the same KeyWrap algorithm and processing.
SM_RET_VAL CSM_Rsa::SMTI_ExtractKeyWrapFinish(
            CSM_Buffer *pData, // Output
            CSM_Buffer &CEKICVPAD)  // Input
{
   SM_RET_VAL status=0;
   CSM_Buffer CEK;
   unsigned int LENGTH=0;

   SME_SETUP("CSM_Rsa::SMTI_ExtractKeyWrap");

   // UNWRAP STEP 6, 7; Decompose the CEKICVPAD into LENGTH, CEK, PAD.
   LENGTH = (int)CEKICVPAD.Access()[0];

   if (LENGTH <= CEKICVPAD.Length()-1 && (CEKICVPAD.Length()-(LENGTH+1)) < 8)
   {                  // Enough to contain CEK and Pad (less than 8 bytes)
      CEK.Set(&CEKICVPAD.Access()[1], LENGTH);
   }
//      else
//        SME_THROW(22, "KeyWrap Length > (CEKICVPAD.Length()-1-8); something is obviously wrong.\n",
//            NULL);

   *pData = CEK;       // pass back to user.


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(status);
}




CSM_Buffer *CSM_Rsa::SMTI_GenerateKeyWrapIV(
    long &lKekLength,   // OUT, returned algorithm specific length
    CSM_Alg *pWrapAlg)   // OUT, returned since params are alg specific.

{
   CSM_Buffer *pIV=NULL;
   AsnOid *pPreferredOID = GetPrefContentEncryption();

   SME_SETUP("CSM_Free3::SMTI_GenerateKeyWrapIV");
   if (*pPreferredOID != id_alg_CMSRC2wrap) 
   {
       AsnOid tmpOID(id_alg_CMSRC2wrap);
       BTISetPreferredCSInstAlgs(NULL,NULL,NULL,&tmpOID);
   }

                     // LOAD hardcoded details.
   pIV = new CSM_Buffer((size_t)SM_RSA_RC2_BLOCKSIZE);
   
//   char Ivhard[] = {0x4a,0xdd,0xa2,0x2c,0x79,0xe8,0x21,0x05};
   //RWC; reversed order due to MS Integration testing;
   //RWC;  char Ivhard[] = {(char)0x05,(char)0x21,(char)0xe8,(char)0x79,(char)0x2c,(char)0xa2,(char)0xdd,(char)0x4a};
   unsigned char Ivhard[] = {(unsigned char)0x4a,(unsigned char)0xdd,
       (unsigned char)0xa2,(unsigned char)0x2c,(unsigned char)0x79,
       (unsigned char)0xe8,(unsigned char)0x21,(unsigned char)0x05};
   
   memcpy((void *)pIV->Access(), Ivhard, SM_RSA_RC2_BLOCKSIZE);

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
   delete pPreferredOID;

   SME_FINISH
   SME_CATCH_SETUP
      if (pPreferredOID)
         delete pPreferredOID;
   SME_CATCH_FINISH

   return(pIV);
}


SM_RET_VAL CSM_Rsa::SMTI_Encrypt(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // output
            CSM_Buffer *pMEK, // output
            CSM_Buffer *pIV)  // In, to avoid specific alg encoding by app.
{
    SM_RET_VAL status=0;
    AsnOid *pPreferredOID = GetPrefContentEncryption();


   if (*pPreferredOID == id_alg_CMSRC2wrap ||
       *pPreferredOID == rc2_cbc ||
       *pPreferredOID == bsafe_id_rc2_encr)
   {             // CHECK our supported Content encyrpt algs.
        status = SMTI_EncryptRC2(pData, pEncryptedData, pParameters, 
            pMEK, pIV);
   }
   else
   {
        status = CSM_Common::SMTI_Encrypt(pData, pEncryptedData, pParameters, 
            pMEK, pIV);
   }
   if (pPreferredOID)
     delete pPreferredOID;

    return status;
}

//////////////////////////////////////////////////////////////////////////
//  Encryption using RC2
//  RWC; The RC2 parameter encoding may be different based on the preferred 
//  RWC;  algorithm.  This was implemented to provide backward compatibility
//  RWC;  with clients using the RC2-CBC OID instead of our default 
//  RWC;  bsafe-id-rc2-encr OID.  (e.g. specifically for MS Outlook Express
//  RWC;  Decrypting operations; the decode fails if the RC2 params are
//  RWC;  not encoded as RC2-CBC-Parameters).
SM_RET_VAL CSM_Rsa::SMTI_EncryptRC2(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // output
            CSM_Buffer *pMEK, // output
            CSM_Buffer *pIV)  // In, to avoid specific alg encoding by app.
{
   B_ALGORITHM_OBJ rc2Encrypter = (B_ALGORITHM_OBJ)NULL_PTR;
   long status;
   B_KEY_OBJ rc2Key = (B_KEY_OBJ)NULL_PTR;
   ITEM rc2KeyItem;
   unsigned int outputLenUpdate;
   unsigned int outputLenFinal;
   char *tmpout;
   char padout[8];
   AsnOid *pPreferredOID = GetPrefContentEncryption();
   bool bPadding=true;

   //RWC5;TBD; FIX IV processing to be allowed to be passed in....

   SME_SETUP("CSM_Rsa::SMTI_Encrypt");

   // check incoming parameters
   if ((pData == NULL) || (pEncryptedData == NULL) ||
       (pParameters == NULL) || (pMEK == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   if (*pPreferredOID == id_alg_CMSRC2wrap)
   {
       bPadding = false;
       m_rc2Params.effectiveKeyBits = 128;  //pMEK->Length() * 8;  
   }

   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&rc2Encrypter)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

    if(pIV == NULL || pIV->Length() == 0)
   // use the random number generator to produce the IV
   {
      CSM_Buffer temp;
      SME(SMTI_Random(NULL, &temp, SM_RSA_RC2_BLOCKSIZE));
      if (m_rc2Params.iv)
         free(m_rc2Params.iv);
      SME(m_rc2Params.iv = (unsigned char *)temp.Get());
   }
   else
   {
     if (m_rc2Params.iv)
        free(m_rc2Params.iv);
     m_rc2Params.iv = (unsigned char *)calloc(1,pIV->Length());
     memcpy(m_rc2Params.iv,pIV->Access(),pIV->Length());
     //if(pMEK && pMEK->Length() >= 64/8)
     //   m_rc2Params.effectiveKeyBits = 64;  //pMEK->Length() * 8;  
   }


   // Set the Algorithm Object
   if (bPadding)
   {
       status = B_SetAlgorithmInfo(rc2Encrypter, 
         AI_RC2_CBCPad, (POINTER)&m_rc2Params);
   }
   else     // Handle KeyWrap unpadded...
   {
       status = B_SetAlgorithmInfo(rc2Encrypter, 
         AI_RC2_CBC, (POINTER)&m_rc2Params);
   }
   if (status != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // Create a Key Object
   if ((status = B_CreateKeyObject(&rc2Key)) != 0)
         SME_THROW(status, "B_CreateKeyObject failed", NULL);

   if(pMEK == NULL || pMEK->Length() == 0)
   {
      // generate m_rc2Params.effectiveKeyBits/8 bytes of random data
      // that will be used as the MEK
      rc2KeyItem.len = m_rc2Params.effectiveKeyBits / 8;

      CSM_Buffer temp;
      SME(SMTI_Random(NULL, &temp, rc2KeyItem.len));
      SME(rc2KeyItem.data = (unsigned char *)temp.Get());
   }
   else
   {
     rc2KeyItem.len = pMEK->Length();
     rc2KeyItem.data = (unsigned char *)calloc(1, rc2KeyItem.len ); 
            // RWC; SET SIZE OF KEY TO effBits in case larger.pMEK->Length());
     //RWC;if (rc2KeyItem.len < pMEK->Length())
       memcpy(rc2KeyItem.data,pMEK->Access(), rc2KeyItem.len );
     //RWC;else
     //RWC;  memcpy(rc2KeyItem.data,pMEK->Access(), pMEK->Length());
   }

   // set the rc2Key with the MEK
   if ((status = (long)B_SetKeyInfo(rc2Key, KI_Item,
         (POINTER)&rc2KeyItem)) != 0)
      SME_THROW(status, "B_SetKeyInfo failed", NULL);

   // Set the Mek to be returned to the caller
   if(pMEK && pMEK->Length() == 0)
   {
     SME(pMEK->Set((char *)rc2KeyItem.data, (long unsigned int)rc2KeyItem.len));
   }

   // Initialize algorithmObject for encrypting data using the
   // algorithm specified by the previous call to B_SetAlgorithmInfo.
   if ((status = B_EncryptInit(rc2Encrypter, rc2Key, m_pCHOOSER,
      (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_EncryptInit failed", NULL);

   // open input for reading
   SME(pData->Open(SM_FOPEN_READ));

   // open output for writing
   if ((tmpout = (char *)calloc(1, pData->Length() + 8)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Update the encrypting process
   if ((status = (long)B_EncryptUpdate(rc2Encrypter, 
         (unsigned char *)tmpout, &outputLenUpdate,
         pData->Length() + 8, (unsigned char *)pData->Access(), 
         pData->Length(), (B_ALGORITHM_OBJ)NULL_PTR, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_EncryptUpdate failed", NULL);

   // Finalize the encrypting process 
   if ((status = (long)B_EncryptFinal(rc2Encrypter, 
         (unsigned char *)&padout[0], 
         &outputLenFinal, 8, 
         (B_ALGORITHM_OBJ)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_EncryptFinal failed", NULL);

   SME(pEncryptedData->Open(SM_FOPEN_WRITE));
   if (outputLenUpdate != 0)
      SME(pEncryptedData->Write(tmpout, outputLenUpdate));
   if (outputLenFinal > 0)
     SME(pEncryptedData->Write(padout, outputLenFinal));

   SME(pEncryptedData->Close());
   SME(pData->Close());
   free(tmpout);

   B_DestroyKeyObject(&rc2Key);
   B_DestroyAlgorithmObject(&rc2Encrypter);
   if (rc2KeyItem.data != NULL_PTR)
      free(rc2KeyItem.data);

   // load the pParamters


   // ASN.1 encode the parameters
   EncodeRC2Params(pParameters);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
      // flush and close if they've been opened
      delete pPreferredOID;
   SME_CATCH_FINISH

   delete pPreferredOID;
   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // output  UNUSED.
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // input/output
            CSM_Buffer *pSubjKeyId) // output
{
   B_ALGORITHM_OBJ rsaEncryptor = (B_ALGORITHM_OBJ)NULL_PTR;
   B_KEY_OBJ publicKey = (B_KEY_OBJ)NULL_PTR;
   ITEM itemRecipientKey;
   long status;
   unsigned int outputLenUpdate;
   unsigned int outputLenFinal;
   unsigned int modulus;
   char *tmpout;
   char  *padout;

   SME_SETUP("CSM_Rsa::SMTI_GenerateEMEK");

   // check incoming parameters
   if ((pRecipient == NULL) || (pEMEK == NULL) || (pMEK == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   // check for valid MEK
   if (strncmp(pMEK->Access(), SM_RSA_FORTENC, 
         strlen(SM_RSA_FORTENC)) == 0)
      SME_THROW(SM_RSA_UNSUPPORTED_ALG, 
            "Cannot Protect skipjack MEK", NULL);

   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&rsaEncryptor)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // Set the Algorithm Object
   if ((status = B_SetAlgorithmInfo(rsaEncryptor, 
         AI_PKCS_RSAPublic, NULL_PTR)) != 0)
      SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // Create a public Key Object
   if ((status = B_CreateKeyObject(&publicKey)) != 0)
      SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // ASN.1 decode the provided recipient's public key into our public 
   // key object
   itemRecipientKey.len = pRecipient->Length();
   itemRecipientKey.data = (unsigned char *)pRecipient->Get();
   if ((status = (long)B_SetKeyInfo(publicKey, KI_RSAPublicBER,
         (POINTER)&itemRecipientKey)) != 0)
   {              // RWC; ATTEMPTING different format form MS Outlook Express.
      RSAPublicKey SnaccRSAPublicKey;
      A_RSA_KEY rsaKey;

      DECODE_BUF(&SnaccRSAPublicKey, pRecipient);  // will create exception if 
                                                   //  decode fails.
      rsaKey.modulus.data = (unsigned char *)SnaccRSAPublicKey.modulus.c_str();
      rsaKey.modulus.len = SnaccRSAPublicKey.modulus.length();
      rsaKey.exponent.data = (unsigned char *)SnaccRSAPublicKey.publicExponent.c_str();
      rsaKey.exponent.len = SnaccRSAPublicKey.publicExponent.length();
      if ((status = (long)B_SetKeyInfo(publicKey, KI_RSAPublic, 
         (POINTER)&rsaKey)) != 0)
        SME_THROW(status, "B_SetKeyInfo failed 2", NULL);
   }
  
   // Encrypt using the recipient's RSA public key.
   if ((status = B_EncryptInit(rsaEncryptor, publicKey, 
         m_pCHOOSER, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_EncryptInit failed", NULL);

   // open input for reading
   SME(pMEK->Open(SM_FOPEN_READ));

   modulus = m_keygenParams.modulusBits / 8;

   // open output for writing
   if ((tmpout = (char *)calloc(1, modulus)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    if ((padout = (char *)calloc(1, modulus)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Update the encrypting process
   if ((status = (long)B_EncryptUpdate(rsaEncryptor, (unsigned char *)tmpout,
         &outputLenUpdate, modulus, (unsigned char *)pMEK->Access(),
         pMEK->Length(), m_randomAlgorithm,
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_EncryptUpdate failed", NULL);

   // Finalize the encrypting process 
   if ((status = (long)B_EncryptFinal(rsaEncryptor, 
         (unsigned char *)padout, &outputLenFinal, 
         modulus - outputLenUpdate, m_randomAlgorithm, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_EncryptFinal failed", NULL);

   SME(pEMEK->Open(SM_FOPEN_WRITE));
   if (outputLenUpdate != 0)
      SME(pEMEK->Write(tmpout, outputLenUpdate));
   SME(pEMEK->Write(padout, outputLenFinal));

   SME(pEMEK->Close());
   SME(pMEK->Close());
   free(tmpout);
   free(padout);
   if (itemRecipientKey.data)
      free(itemRecipientKey.data);

   B_DestroyAlgorithmObject(&rsaEncryptor);
   B_DestroyKeyObject(&publicKey);
   // RWC;2/7/00; If successful, load NULL PARAMS according to spec
   // ONLY FOR RSA.
   if (pParameters)
   {
       CSM_Buffer *pTmpBuf=CSM_Alg::GetNullParams();
       *pParameters = *pTmpBuf;
       delete pTmpBuf;
   }
   
   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
   SME_CATCH_FINISH

#ifdef WIN32
   pSubjKeyId;pUKM; //AVOIDS warning.
#endif //WIN32
   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_Decrypt(
            CSM_Buffer *pParameters, // input (initialization vector)
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK, // input (MEK or special phrase)
            CSM_Buffer *pData) // output (decrypted data)
{
    SM_RET_VAL status=0;
    AsnOid *pPreferredOID = GetPrefContentEncryption();

   if (*pPreferredOID == id_alg_CMSRC2wrap ||
       *pPreferredOID == rc2_cbc ||
       *pPreferredOID == bsafe_id_rc2_encr)
   {             // CHECK our supported Content encyrpt algs.
        status = SMTI_DecryptRC2(pParameters, pEncryptedData, 
            pMEK, pData);
   }
   else
   {
	  status = CSM_Common::SMTI_Decrypt(pParameters, pEncryptedData, 
          pMEK, pData);
   }
   if (pPreferredOID)
     delete pPreferredOID;


    return status;
}
//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_DecryptRC2(
            CSM_Buffer *pParameters, // input (initialization vector)
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK, // input (MEK or special phrase)
            CSM_Buffer *pData) // output (decrypted data)
{
   B_ALGORITHM_OBJ decryptionObject = (B_ALGORITHM_OBJ)NULL_PTR;
   long status;
   B_KEY_OBJ rc2Key = (B_KEY_OBJ)NULL_PTR;
   ITEM rc2KeyItem;
   char *pchDecryptedData;
   unsigned int outputLenUpdate;
   unsigned int outputLenFinal;
   SM_SIZE_T len;
   AsnOid *pPreferredOID = GetPrefContentEncryption();
   bool bPadding=true;

   SME_SETUP("CSM_Rsa::SMTI_Decrypt");

   // check incoming parameters
   if ((pData == NULL) || (pEncryptedData == NULL) || (pParameters == NULL)
         || (pMEK == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   if (*pPreferredOID == id_alg_CMSRC2wrap)
       bPadding = false;

   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&decryptionObject)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // ASN.1 decode the parameters that contain the IV and 
   // the effectiveKeyBits
   SME(DecodeRC2Params(*pParameters));

   // Set the Algorithm Object
   if (bPadding)
   {
      status = B_SetAlgorithmInfo(decryptionObject, 
         AI_RC2_CBCPad, (POINTER)&m_rc2Params);
   }
   else
   {
      status = B_SetAlgorithmInfo(decryptionObject, 
         AI_RC2_CBC, (POINTER)&m_rc2Params);
   }
   if (status != 0)
      SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // Create a Key Object
   if ((status = B_CreateKeyObject(&rc2Key)) != 0)
      SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // Set the key data from the incoming Mek
   rc2KeyItem.len = pMEK->Length();
   //JJ; RWC; rc2KeyItem.len = m_rc2Params.effectiveKeyBits / 8;
   //JJ; RWC; changed to take full pMEK length as per "Jacoby, Jeffrey" at RSA.
   //JJ:  This is the error.  It's possible and allowed that
   //JJ:  the rc2KeyItem.len may NOT be the same as ekb/8.  It
   //JJ:  very well could be greater.
   SME(rc2KeyItem.data = (unsigned char *)calloc(1,rc2KeyItem.len));
   //JJ; RWC; unsigned int tmpLen=rc2KeyItem.len;
   //JJ; RWC; if (tmpLen > pMEK->Length())
   //JJ; RWC;    tmpLen = pMEK->Length();   // ONLY get what is available.
   memcpy(rc2KeyItem.data, pMEK->Access(), rc2KeyItem.len);

   if ((status = (long)B_SetKeyInfo(rc2Key, KI_Item,
         (POINTER)&rc2KeyItem)) != 0)
      SME_THROW(status, "B_SetKeyInfo failed", NULL);

   //zeroize the key
   if (rc2KeyItem.data != NULL_PTR)
   {
      memset(rc2KeyItem.data, 0, rc2KeyItem.len);
      free(rc2KeyItem.data);
      rc2KeyItem.data = NULL_PTR;
      rc2KeyItem.len = 0;
   }

   // Initialize algorithmObject for decrypting data using the
   // algorithm specified by the previous call to B_SetAlgorithmInfo.
   if ((status = B_DecryptInit(decryptionObject, rc2Key, m_pCHOOSER,
      (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DecryptInit failed", NULL);

   // open input for reading
   SME(pEncryptedData->Open(SM_FOPEN_READ));

   // open output for writing
   SME(pData->Open(SM_FOPEN_WRITE));

   pchDecryptedData = (char *)calloc(1, pEncryptedData->Length());
   if (pchDecryptedData == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Update the decrypting process
   if ((status = (long)B_DecryptUpdate(decryptionObject, 
         (unsigned char *)pchDecryptedData, &outputLenUpdate,
         pEncryptedData->Length(),(unsigned char *)pEncryptedData->Access(), 
         pEncryptedData->Length(), (B_ALGORITHM_OBJ)NULL_PTR, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DecryptUpdate failed", NULL);

   outputLenFinal = pEncryptedData->Length() - outputLenUpdate;

   // Finalize the decrypting process 
   if ((status = (long)B_DecryptFinal(decryptionObject, 
         (unsigned char *)pchDecryptedData + outputLenUpdate, 
         &outputLenFinal, pEncryptedData->Length() - outputLenUpdate, 
         (B_ALGORITHM_OBJ)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
   {
      //RWC;CSM_Buffer bbb(pchDecryptedData, outputLenUpdate);
      //RWC;bbb.ConvertMemoryToFile("c:\\tmp\\SMIME_ED_decrypt.bin");
      SME_THROW(status, "B_DecryptFinal failed", NULL);
   }

   if (bPadding)
   {
       // Remove the padding
       len = pEncryptedData->Length() - (SM_RSA_MAXPAD - outputLenFinal);
       pData->Write(pchDecryptedData, len);
   }
   else
   {
       pData->Write(pchDecryptedData, outputLenUpdate);
   }

   SME(pEncryptedData->Close());
   SME(pData->Close());
   free(pchDecryptedData);

   B_DestroyAlgorithmObject(&decryptionObject);
   B_DestroyKeyObject(&rc2Key);

   SME_FINISH
   SME_CATCH_SETUP
      // close these if open
      pData->Close();
      pEncryptedData->Close();
      delete pPreferredOID;
   SME_CATCH_FINISH

   delete pPreferredOID;

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output (MEK or special phrase)
{
   B_ALGORITHM_OBJ rsaDecryptor = (B_ALGORITHM_OBJ)NULL_PTR;
   B_KEY_OBJ privateKey = (B_KEY_OBJ)NULL_PTR;
   long status;
   int i;
   char *ptr;
   char *pchDecryptedData;
   unsigned int outputLenUpdate;
   unsigned int outputLenFinal;

   SME_SETUP("CSM_Rsa::SMTI_ExtractMEK");

   // check incoming parameters
   if (/**RWC;(pOriginator == NULL) ||**/ (pEMEK == NULL) || (pMEK == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&rsaDecryptor)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // Set the Algorithm Object
   if ((status = B_SetAlgorithmInfo(rsaDecryptor, 
         AI_PKCS_RSAPrivate, NULL_PTR)) != 0)
      SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // get the decrypted private key
   SME(privateKey = GetBsafePrivateKey());

   // Use the RSA private key associated with the public key used
   // to encrypt.
   if ((status = B_DecryptInit(rsaDecryptor, privateKey, 
        m_pCHOOSER, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DecryptInit failed", NULL);

   // open input for reading
   SME(pEMEK->Open(SM_FOPEN_READ));

   // open output for writing
   SME(pMEK->Open(SM_FOPEN_WRITE));

   pchDecryptedData = pMEK->Alloc(pEMEK->Length());
   if (pchDecryptedData == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Update the decrypting process
   if ((status = (long)B_DecryptUpdate(rsaDecryptor, 
         (unsigned char *)pchDecryptedData, &outputLenUpdate,
         pEMEK->Length(),(unsigned char *)pEMEK->Access(), 
         pEMEK->Length(), (B_ALGORITHM_OBJ)NULL_PTR, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DecryptUpdate failed", NULL);

   outputLenFinal = pEMEK->Length() - outputLenUpdate;

   // Finalize the decrypting process 
   if ((status = (long)B_DecryptFinal(rsaDecryptor, 
         (unsigned char *)pchDecryptedData + outputLenUpdate, 
         &outputLenFinal, pEMEK->Length() - outputLenUpdate, 
         (B_ALGORITHM_OBJ)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_DecryptFinal failed", NULL);

   SME(pMEK->Flush());
   // RWC, padding needs to be removed...
   for (i=pMEK->Length()-1, ptr=(char *)pMEK->Access(); 
        i > 0 && ptr[i] == '\0'; i--);
   if (i > 0)
       pMEK->SetLength(i+1);    // RESET LENGTH...

   SME(pEMEK->Close());
   SME(pMEK->Close());

   B_DestroyAlgorithmObject(&rsaDecryptor);
   B_DestroyKeyObject(&privateKey);
   
   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
   SME_CATCH_FINISH
#ifdef WIN32
   pUKM;pParameters;pOriginator; //AVOIDS warning.
#endif //WIN32
   return SM_NO_ERROR;
}


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_DigestData(
            CSM_Buffer *pData, // input
            CSM_Buffer *pDigest) // output
{
   AsnOid *poidDigest=GetPrefDigest();
   B_ALGORITHM_OBJ digester = (B_ALGORITHM_OBJ)NULL_PTR;
   char *pchDigest;
   long status;
   unsigned int digestedDataLen=0;

   SME_SETUP("CSM_Rsa::SMTI_DigestData");

   if (*poidDigest == sha_1 || *poidDigest == sha_1WithRSAEncryption_ALT || 
       *poidDigest == sha_1WithRSAEncryption ||
       *poidDigest == md5 || *poidDigest == md5WithRSAEncryption)
   {
   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&digester)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   if (*poidDigest == sha_1 || *poidDigest == sha_1WithRSAEncryption_ALT || 
       *poidDigest == sha_1WithRSAEncryption)
   {
      // do SHA1 digest
      if ((status = B_SetAlgorithmInfo(digester, 
         AI_SHA1, NULL_PTR)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);
      digestedDataLen = 20;
   }
   else if (*poidDigest == md5 || *poidDigest == md5WithRSAEncryption)
   {
      // do MD5 digest
      if ((status = B_SetAlgorithmInfo(digester, 
         AI_MD5, NULL_PTR)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);
      digestedDataLen = 16;
   }

   SME(pDigest->Open(SM_FOPEN_WRITE)); // open the digest buffer
   pchDigest = pDigest->Alloc(digestedDataLen);
   if (pchDigest == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Initialize algorithmObject (digester) for computing the
   // message digest using the algorithm specified by previous call
   // to B_SetAlgorithmInfo.
   if ((status = (long)B_DigestInit(digester, (B_KEY_OBJ)NULL_PTR,
         m_pCHOOSER, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DigestInit failed", NULL);

   // Update the algorithmObject with the appropriate number of
   // bytes from the input data.
   if ((status = (long)B_DigestUpdate(digester, 
         (unsigned char *)pData->Access(),
         pData->Length(), (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DigestUpdate failed", NULL);

   // Finalize the digesting process for algorithmObject and write
   // the message digest to the output digest buffer.
   if ((status = (long)B_DigestFinal(digester, (unsigned char *)pchDigest, 
         &digestedDataLen, digestedDataLen, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_DigestFinal failed", NULL);

   // destroy AlgorithObject, zeroizing any sensitive information, 
   // freeing the memory the algorithm object occupied, and NULLING it out.
   B_DestroyAlgorithmObject(&digester);

   pDigest->Flush(); // flush the digest buffer
   pDigest->Close(); // close the digest buffer
   if (poidDigest)
      delete poidDigest;
   }
   else     // Attempt the CSM_Common algorithm set...
   {
      SME((status = CSM_Common::SMTI_DigestData(pData, pDigest)));
      if (status != 0)
      {
          SME_THROW(SM_RSA_UNSUPPORTED_ALG, 
              "CSM_RSA::SMTI_DigestData: unsupported algorithm.", NULL);
      }
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
      // close pData and pDigest as necessary
      B_DestroyAlgorithmObject(&digester);
      if (poidDigest)
         delete poidDigest;
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Rsa::SMTI_Random(
            CSM_Buffer *pSeed,   // input
            CSM_Buffer *pRandom, // input/output
            SM_SIZE_T lLength)   // input
{
   char *p = NULL;
   long status;

   SME_SETUP("CSM_Rsa::SMTI_Random");

   // TBD:  Use pSeed

   if (pRandom == NULL)
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   // open the buffer
   SME(pRandom->Open(SM_FOPEN_WRITE));
   // allocate memory for use in the buffer
   SME(p = pRandom->Alloc(lLength));

   // create lLength random bytes of data
   if ((status = (long)B_GenerateRandomBytes(m_randomAlgorithm, 
         (unsigned char *)p, lLength, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_GenerateRandomBytes failed", NULL);

   // flush and close
   pRandom->Flush();
   pRandom->Close();

   SME_FINISH
   SME_CATCH_SETUP
      // cleanup/catch logic goes here...
      // TBD, p may need to be cleaned up???
   SME_CATCH_FINISH

#ifdef WIN32
   pSeed; //AVOIDS warning.
#endif //WIN32
   return SM_NO_ERROR;
}

 //////////////////////////////////////////////////////////////////////////
// in storing the password in this object, we attempt to provide a little
// extra protection by encrypting the password with a dynamically
// created key that can also be recreated.  Granted, this is not the
// most secure way in the world.  If anybody who reads this has an
// alternative and better solution, please let us know....
void CSM_Rsa::SetPassword(char *pszPassword)
{
   AsnOid *pPrefDigest=NULL;
   AsnOid o(md5/*bsafe_id_md5*/);
   CSM_Buffer bufK1, bufK2, bufK3;
   B_ALGORITHM_OBJ rc2Encrypter = (B_ALGORITHM_OBJ)NULL_PTR;
   long status;
   B_KEY_OBJ rc2Key = (B_KEY_OBJ)NULL_PTR;
   ITEM rc2KeyItem;
   unsigned int outputLenUpdate;
   unsigned int outputLenFinal;
   char *tmpout;
   char padout[8];

   SME_SETUP("CSM_Rsa::SetPassword");

   if (pszPassword == NULL)
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&rc2Encrypter)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   int nPid = getpid();
   CSM_Buffer bufP(pszPassword, strlen(pszPassword));

   SME(bufK1.Open(SM_FOPEN_WRITE));
   SME(bufK1.Write((char *)(&nPid), sizeof(int)));
   SME(bufK1.Write(m_pRandomData->Access(), m_pRandomData->Length()));
   SME(bufK1.Close());

   SME(pPrefDigest = GetPrefDigest()); // save current digest alg
   SME(BTISetPreferredCSInstAlgs(&o, NULL, NULL, NULL)); // set md5
   SME(SMTI_DigestData(&bufK1, &bufK2));

   if (m_rc2Params.iv)
      free(m_rc2Params.iv);
   SME(m_rc2Params.iv = (unsigned char *)bufK2.Get());

   // restore previous digest alg
   SME(BTISetPreferredCSInstAlgs(pPrefDigest, NULL, NULL, NULL));
   delete pPrefDigest;
   pPrefDigest = NULL;

   // Set the Algorithm Object
   if ((status = B_SetAlgorithmInfo(rc2Encrypter, 
         AI_RC2_CBCPad, (POINTER)&m_rc2Params)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // Create a Key Object
   if ((status = B_CreateKeyObject(&rc2Key)) != 0)
         SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // generate m_rc2Params.effectiveKeyBits/8 bytes of random data
   rc2KeyItem.len = bufK2.Length();
   SME(rc2KeyItem.data = (unsigned char *)bufK2.Get());

   // set the rc2Key  
   if ((status = (long)B_SetKeyInfo(rc2Key, KI_Item,
         (POINTER)&rc2KeyItem)) != 0)
      SME_THROW(status, "B_SetKeyInfo failed", NULL);

   // Initialize algorithmObject for encrypting data using the
   // algorithm specified by the previous call to B_SetAlgorithmInfo.
   if ((status = B_EncryptInit(rc2Encrypter, rc2Key, m_pCHOOSER,
      (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_EncryptInit failed", NULL);

   if (m_pbufPassword)
      delete (m_pbufPassword);
   if ((m_pbufPassword = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // open input for reading
   SME(bufP.Open(SM_FOPEN_READ));

   // open output for writing
   if ((tmpout = (char *)calloc(1, bufP.Length() + 8)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Update the encrypting process
   if ((status = (long)B_EncryptUpdate(rc2Encrypter, 
         (unsigned char *)tmpout, &outputLenUpdate,
         bufP.Length() + 8, (unsigned char *)bufP.Access(), 
         bufP.Length(), (B_ALGORITHM_OBJ)NULL_PTR, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_EncryptUpdate failed", NULL);

   // Finalize the encrypting process 
   if ((status = (long)B_EncryptFinal(rc2Encrypter, 
         (unsigned char *)&padout[0], 
         &outputLenFinal, 8, 
         (B_ALGORITHM_OBJ)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_EncryptFinal failed", NULL);

   SME(m_pbufPassword->Open(SM_FOPEN_WRITE));
   if (outputLenUpdate != 0)
      SME(m_pbufPassword->Write(tmpout, outputLenUpdate));
   SME(m_pbufPassword->Write(padout, outputLenFinal));

    //zeroize the key
   if (rc2KeyItem.data != NULL_PTR)
   {
      memset(rc2KeyItem.data, 0, rc2KeyItem.len);
      free(rc2KeyItem.data);
      rc2KeyItem.data = NULL_PTR;
      rc2KeyItem.len = 0;
   }

   SME(m_pbufPassword->Close());
   SME(bufP.Close());
   free(tmpout);

   B_DestroyKeyObject(&rc2Key);
   B_DestroyAlgorithmObject(&rc2Encrypter);

   SME_FINISH
   SME_CATCH_SETUP
      if (pPrefDigest)
         delete pPrefDigest;
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
// see the comment block for SetPassword...
char* CSM_Rsa::GetPassword()
{
   AsnOid *pPrefDigest = NULL;
   AsnOid o(md5/*bsafe_id_md5*/);
   char *pRet = NULL;
   CSM_Buffer bufK1, bufK2, bufK3;
   CSM_Buffer bufP;
   B_ALGORITHM_OBJ decryptionObject = (B_ALGORITHM_OBJ)NULL_PTR;
   long status;
   B_KEY_OBJ rc2Key = (B_KEY_OBJ)NULL_PTR;
   ITEM rc2KeyItem;
   char *pchDecryptedData;
   unsigned int outputLenUpdate;
   unsigned int outputLenFinal;
   SM_SIZE_T len;

   SME_SETUP("CSM_Rsa::GetPassword");

   if (m_pbufPassword == NULL)
      SME_THROW(SM_RSA_MISSING_PARAM, "no password set yet", NULL);

   int nPid = getpid();

   SME(bufK1.Open(SM_FOPEN_WRITE));
   SME(bufK1.Write((char *)(&nPid), sizeof(int)));
   SME(bufK1.Write(m_pRandomData->Access(), m_pRandomData->Length()));
   SME(bufK1.Close());

   SME(pPrefDigest = GetPrefDigest()); // save current digest alg
   SME(BTISetPreferredCSInstAlgs(&o, NULL, NULL, NULL)); // set md5
   SME(SMTI_DigestData(&bufK1, &bufK2));

   if (m_rc2Params.iv)
      free(m_rc2Params.iv);
   SME(m_rc2Params.iv = (unsigned char *)bufK2.Get());

   // restore previous digest alg
   SME(BTISetPreferredCSInstAlgs(pPrefDigest, NULL, NULL, NULL));

   // Create a Key Object
   if ((status = B_CreateKeyObject(&rc2Key)) != 0)
         SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // generate m_rc2Params.effectiveKeyBits/8 bytes of random data
   rc2KeyItem.len = bufK2.Length();
   SME(rc2KeyItem.data = (unsigned char *)bufK2.Get());

   // set the rc2Key  
   if ((status = (long)B_SetKeyInfo(rc2Key, KI_Item,
         (POINTER)&rc2KeyItem)) != 0)
      SME_THROW(status, "B_SetKeyInfo failed", NULL);

   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&decryptionObject)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // Set the Algorithm Object
   if ((status = B_SetAlgorithmInfo(decryptionObject, 
         AI_RC2_CBCPad, (POINTER)&m_rc2Params)) != 0)
      SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

    //zeroize the key
   if (rc2KeyItem.data != NULL_PTR)
   {
      memset(rc2KeyItem.data, 0, rc2KeyItem.len);
      free(rc2KeyItem.data);
      rc2KeyItem.data = NULL_PTR;
      rc2KeyItem.len = 0;
   }

   // Initialize algorithmObject for decrypting data using the
   // algorithm specified by the previous call to B_SetAlgorithmInfo.
   if ((status = B_DecryptInit(decryptionObject, rc2Key, m_pCHOOSER,
      (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DecryptInit failed", NULL);
  
   // open input for reading
   SME(m_pbufPassword->Open(SM_FOPEN_READ));

   // open output for writing
   SME(bufP.Open(SM_FOPEN_WRITE));

   pchDecryptedData = (char *)calloc(1, m_pbufPassword->Length());
   if (pchDecryptedData == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Update the decrypting process
   if ((status = (long)B_DecryptUpdate(decryptionObject, 
         (unsigned char *)pchDecryptedData, &outputLenUpdate,
         m_pbufPassword->Length(),(unsigned char *)m_pbufPassword->Access(), 
         m_pbufPassword->Length(), (B_ALGORITHM_OBJ)NULL_PTR, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DecryptUpdate failed", NULL);

   outputLenFinal = m_pbufPassword->Length() - outputLenUpdate;

   // Finalize the decrypting process 
   if ((status = (long)B_DecryptFinal(decryptionObject, 
         (unsigned char *)pchDecryptedData + outputLenUpdate, 
         &outputLenFinal, m_pbufPassword->Length() - outputLenUpdate, 
         (B_ALGORITHM_OBJ)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_DecryptFinal failed", NULL);

   // Remove the padding
   len = m_pbufPassword->Length() - (SM_RSA_MAXPAD - outputLenFinal);
   bufP.Write(pchDecryptedData, len);

   SME(m_pbufPassword->Close());
   SME(bufP.Close());
   free(pchDecryptedData);

   B_DestroyAlgorithmObject(&decryptionObject);
   B_DestroyKeyObject(&rc2Key);

   if ((pRet = (char *)calloc(1, bufP.Length() + 1)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   memcpy(pRet, bufP.Access(), bufP.Length());
   
   // update the random data and reset the password
   delete m_pRandomData;
   if ((m_pRandomData = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   SME(SMTI_Random(NULL, m_pRandomData, SM_RSA_RANDSIZE));
   SME(SetPassword(pRet));

   if (pPrefDigest)
      delete pPrefDigest;

   SME_FINISH
   SME_CATCH_SETUP
      if (pPrefDigest)
         delete pPrefDigest;
   SME_CATCH_FINISH

   return pRet;
}

//////////////////////////////////////////////////////////////////////////
CSM_Rsa::~CSM_Rsa()
{
   B_DestroyAlgorithmObject(&m_randomAlgorithm);
   if (m_pbufPassword != NULL)
      delete m_pbufPassword;
   if (m_RSAX)
      delete m_RSAX;
   if (m_pAB)
      delete m_pAB;
   if (m_pszPrefix != NULL)
      free(m_pszPrefix);
   if (m_pRandomData != NULL)
      delete m_pRandomData;
   if (m_keygenParams.publicExponent.data)
      free(m_keygenParams.publicExponent.data);
   if (m_rc2Params.iv)
      free(m_rc2Params.iv);
}

//////////////////////////////////////////////////////////////////////////
void CSM_Rsa::CSM_TokenInterfaceDestroy()
{
   delete this;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Rsa::Clear()
{
   m_RSAX = NULL;
   m_pszPrefix = NULL;
   m_pRandomData = NULL;
   m_pbufPassword = NULL;
   memset(&m_rc2Params, 0, sizeof(A_RC2_CBC_PARAMS));
   memset(&m_rc2PBEParams, 0, sizeof(B_RC2_PBE_PARAMS));
   memset(&m_keygenParams, 0, sizeof(A_RSA_KEY_GEN_PARAMS));
   m_randomAlgorithm = (B_ALGORITHM_OBJ)NULL_PTR;
   m_pszPassword = NULL;
   m_pAB = NULL;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Rsa::SetCryptoDefaults()
{
   unsigned char f4Data[3] = {0x01, 0x00, 0x01};

   SME_SETUP("CSM_Rsa::SetCryptoDefaults");

   m_rc2Params.effectiveKeyBits = SM_RSA_RC2_DEFAULT_KEYBITS;
   m_rc2PBEParams.effectiveKeyBits = SM_RSA_RC2_DEFAULT_PBE_KEYBITS;
   m_rc2PBEParams.iterationCount = SM_RSA_DEFAULT_PBE_ITERATIONS;
   m_keygenParams.modulusBits = SM_RSA_DEFAULT_KEYLEN;
   if ((m_keygenParams.publicExponent.data = 
         (unsigned char *)calloc(1, 3)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   memcpy(m_keygenParams.publicExponent.data, &f4Data[0], 3);
   m_keygenParams.publicExponent.len = 3;

   // fill the chooser
   m_pCHOOSER[0] = &AM_MD5;
   m_pCHOOSER[1] = &AM_RSA_CRT_ENCRYPT;
   m_pCHOOSER[2] = &AM_RSA_CRT_DECRYPT;
   m_pCHOOSER[3] = &AM_RSA_ENCRYPT;
   m_pCHOOSER[4] = &AM_RSA_DECRYPT;
   m_pCHOOSER[5] = &AM_RC2_CBC_ENCRYPT;
   m_pCHOOSER[6] = &AM_RC2_CBC_DECRYPT;
   m_pCHOOSER[7] = &AM_SHA;
   m_pCHOOSER[8] = &AM_MD5_RANDOM;
   m_pCHOOSER[9] = &AM_RSA_KEY_GEN;
   m_pCHOOSER[10] = (B_ALGORITHM_METHOD *)NULL_PTR;

   SME_FINISH_CATCH
}

//
//
void CSM_Rsa::LoadParams(CSM_Buffer &IV, CSM_Buffer *pParameters)
{
   SME_SETUP("CSM_Rsa::LoadParams");

   if (m_rc2Params.iv)
      free(m_rc2Params.iv);
   if ((m_rc2Params.iv = (unsigned char *)calloc(1,IV.Length())) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   memcpy(m_rc2Params.iv, (char *)IV.Access(), IV.Length());
   m_rc2Params.effectiveKeyBits = 128; //RWC;IV.Length() * 8;

   EncodeRC2Params(pParameters);
     
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_Rsa::EncodeRC2Params(CSM_Buffer *out)
{
   RC2Parameters snaccParams;
   AsnOid *pPrefContentEncryption = NULL;
   RC2_CBC_parameter snaccMSOEParams;  // OLD RSA Params encoding.
                                       //  (RWC;by MS Outlook Express).

   SME_SETUP("CSM_Rsa::EncodeRC2Params");

   if ((pPrefContentEncryption=GetPrefContentEncryption()) != NULL && 
      *pPrefContentEncryption == rc2_cbc)    // RWC; Use alt parameter encoding
   {
       if (m_rc2Params.effectiveKeyBits == 40)   // MSOE old use!!
           snaccMSOEParams.rc2ParameterVersion = 160;
       else if (m_rc2Params.effectiveKeyBits == 64)   // MSOE old use!!
           snaccMSOEParams.rc2ParameterVersion = 120;
       else if (m_rc2Params.effectiveKeyBits == 128)   // MSOE old use!!
           snaccMSOEParams.rc2ParameterVersion = 58;
       else
          snaccMSOEParams.rc2ParameterVersion = m_rc2Params.effectiveKeyBits;
       snaccMSOEParams.iv.Set((char *)m_rc2Params.iv, SM_RSA_RC2_BLOCKSIZE);
      ENCODE_BUF_NO_ALLOC((&snaccMSOEParams), (out));
   }
   else                                      // RWC; Use default.
   {
      snaccParams.iv.Set((char *)m_rc2Params.iv, SM_RSA_RC2_BLOCKSIZE);
      snaccParams.keyBits = m_rc2Params.effectiveKeyBits;
      ENCODE_BUF_NO_ALLOC((&snaccParams), (out));
   }
   delete pPrefContentEncryption;

   SME_FINISH_CATCH
}

//
//
CSM_AlgVDA *CSM_Rsa::DeriveMsgAlgFromCert(CSM_AlgVDA &Alg) 
{   
	return new CSM_AlgVDA(Alg); 
}

//
//
CSM_Alg *CSM_Rsa::DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert)
{               // This call interprets KTRI certificate params into CMS Msg
                //  Param format for algorithms.  It is up to the CTIL to 
                //  properly interpret algorithm specific formats for both.
   CSM_Alg *pAlg=NULL;

   SME_SETUP("CSM_Rsa::DeriveMsgAlgFromCert");
   // The incomming parameters are from the certificate using a different 
   //  ASN.1 definition than the CMS encryption format.
   if ((pAlg = Cert.GetPublicKeyAlg()) == NULL)
      SME_THROW(22, "Missing PublicKeyAlg in cert.", NULL);

   SME_FINISH_CATCH
   return(pAlg);
}

//////////////////////////////////////////////////////////////////////////
void CSM_Rsa::DecodeRC2Params(CSM_Buffer &in)
{
   RC2Parameters snaccParams;
   RC2_CBC_parameter snaccMSOEParams;  // OLD RSA Params encoding.
                                       //  (RWC;by MS Outlook Express).
   int status;
   //long papoose=1;      // BIG/LITTLE Endian test.

   SME_SETUP("CSM_Rsa::DecodeRC2Params");

   DECODE_BUF_NOFAIL((&snaccParams), (&in), status);
   if (status == 0)
   {
     if (m_rc2Params.iv)
        free(m_rc2Params.iv);
     if ((m_rc2Params.iv = (unsigned char *)calloc(1, 
           SM_RSA_RC2_BLOCKSIZE)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
     memcpy(m_rc2Params.iv, snaccParams.iv.c_str(), SM_RSA_RC2_BLOCKSIZE);
     m_rc2Params.effectiveKeyBits = snaccParams.keyBits;
   }
   else     // Re-attempt decode
   {
     DECODE_BUF_NOFAIL((&snaccMSOEParams), (&in), status);
     if (status == 0)
     {
       if (m_rc2Params.iv)
          free(m_rc2Params.iv);
       if ((m_rc2Params.iv = (unsigned char *)calloc(1, 
             SM_RSA_RC2_BLOCKSIZE)) == NULL)
          SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
       memcpy(m_rc2Params.iv, snaccMSOEParams.iv.c_str(), SM_RSA_RC2_BLOCKSIZE);
       /** RWC; FROM MS MSDN Docs:
         CRYPT_RC2_40BIT_VERSION   160   
         CRYPT_RC2_64BIT_VERSION   120   
         CRYPT_RC2_128BIT_VERSION   58   
       **/
       if (snaccMSOEParams.rc2ParameterVersion == 160)
          m_rc2Params.effectiveKeyBits = 40;   // MSOE old use!!
       else if (snaccMSOEParams.rc2ParameterVersion == 120)
          m_rc2Params.effectiveKeyBits = 64;   // MSOE old use!!
       else if (snaccMSOEParams.rc2ParameterVersion == 58)
          m_rc2Params.effectiveKeyBits = 128;   // MSOE old use!!
       else
          m_rc2Params.effectiveKeyBits = snaccMSOEParams.rc2ParameterVersion;
       //RWC;
     }
     else
         SME_THROW(34, "BAD MSOERC2Parameters SNACC Decode", NULL);\
   }
   /* run time check of LITTLE ENDIAN or BIG ENDIAN */
   // if(*(char *)&papoose == 1)

   SME_FINISH_CATCH 
}

//////////////////////////////////////////////////////////////////////////
CSM_Rsa::CSM_Rsa()
{
   time_t t;
   time(&t); // use time to seed randomAlgorithm
   long status;

   SME_SETUP("CSM_Rsa::CSM_Rsa");

   // clear and then set the crypto defaults
   Clear();
   SME(SetCryptoDefaults());

   // copy time structure into seed
   m_seed.Set((char *)(&t), sizeof(time_t)); 

   // construct random components
   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&m_randomAlgorithm)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // Set the Algorithm Object using AI_MD5Random
   if ((status = (long)B_SetAlgorithmInfo (m_randomAlgorithm,
         AI_MD5Random, NULL_PTR)) != 0)
      SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // Initialize randomAlgorithm for generating random bytes using
   // the algorithm specified by previous call to B_SetAlgorithmInfo.
   if ((status = (long)B_RandomInit(m_randomAlgorithm, 
         m_pCHOOSER, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_RandomInit failed", NULL);

   // Mix in a random seed to the algorithm object.
   if ((status = (long)B_RandomUpdate(m_randomAlgorithm, 
         (unsigned char *)m_seed.Access(),
         m_seed.Length(), (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_RandomUpdate failed", NULL);

   if ((m_pRandomData = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // set up algs
   SME(SetDefaultOIDs());

   // load up some random data
   SME(SMTI_Random(NULL, m_pRandomData, SM_RSA_RANDSIZE));

   SME_FINISH
   SME_CATCH_SETUP
      // cleanup/catch logic goes here...
      // TBD, p may need to be cleaned up???
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
void SMRsaInit(CSM_CtilMgr *pCtilMgr, char *pszPassword,
                     char *pszAddressBook, char *pszPrefix)
{
   CSM_CSInst *pNewInstance = NULL;
   List<MAB_Entrydef>::iterator itEntry;
   //CSMIME *pCSMIME2=(CSMIME *)pCSMIME;  // TO load both lists: CTIL and CSInst.
   CSM_Rsa *pRsa = NULL;
   CSM_CertificateChoice *pCertificateChoice;
   CSM_Buffer *pBuffer;
   long lCounter = 0;
   char szID[128];
   AlgorithmIdentifier *pAlgID=NULL;


   SME_SETUP("SMRsaInit");

   if ((pCtilMgr == NULL) || (pszPassword == NULL) || 
         (pszAddressBook == NULL) || (pszPrefix == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

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
         if (*itEntry->m_pPrivateOID == bsafe_id_rsa_encr ||
             *itEntry->m_pPrivateOID == rsaEncryption)
         {
            // rsa entry
            // put it in the instance list in pCtilMgr
            if (pCtilMgr->m_pCSInsts == NULL)
               if ((pCtilMgr->m_pCSInsts = new CSM_CtilInstLst)
                   /*RWC;CSM_CSInstLst)*/ == NULL) //Same as CSM_CSInstLst
                  SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
            //RWC;5/12/02; SPECIAL NOTE; using SFL version of list here in order
            //  to specially load the CTIL MGR version of the list with the same
            //  sub-class pointer as the CSMIME libCert version.
            if ((pNewInstance = new CSM_CSInst) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
            // put it in the instance list in pCSMIME
            pCtilMgr->m_pCSInsts->append(pNewInstance);
            // generate a new RSA CTI class
            if ((pRsa = new CSM_Rsa) == NULL)
            {
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            }
            // CSM_Rsa constructor set's Alg IDs
            pRsa->SetCSInst(pNewInstance);   
                           // SINCE we generated a CSM_CSInst, not a CSM_CtilInst.
                           //  (THIS member is not used by the CTIL, but by the
                           //   application if a CSMIME (not CSM_CtilMgr) 
                           //   container is used for certificate access.


            // store other information in the Rsa CTI
            pRsa->SetPassword(pszPassword);
            pRsa->m_pAB = new MAB_AB_def(AB);

            if (itEntry->m_pPrivateInfo != NULL &&
               strcmp(itEntry->m_pPrivateInfo->Access(), "MAB_NULL") != 0)
               // store the private key info as a RSA private key
               // convert X from entry file into m_RSAX
               SME(pRsa->SetX(itEntry->m_pPrivateInfo));

            // store parameters and Y in the preferred Alg for this instance
            pAlgID = NULL;
            CSM_Buffer *pbufferCert = itEntry->m_pCertFile;
            SME(pRsa->GetParamsAndY(pbufferCert, pAlgID));
            if (pAlgID)
            {
               delete pAlgID;
               pAlgID = NULL;
            }

            // now, fill in what we can in the instance
            // store token interface pointer
            pNewInstance->SetTokenInterface((CSM_TokenInterface *)pRsa);
            // set an id
            sprintf(szID, "%s%ld", pszPrefix, lCounter);
            ++lCounter; // increment counter
            // TBD, scan all instances in pCtilMgr to make sure this is a
            // unique ID
            pNewInstance->SetID(&szID[0]);
            // store the prefix
            pRsa->m_pszPrefix = strdup(pszPrefix);
            // copy the CSMIME error buf
            //pNewInstance->m_pErrorBuf = pCtilMgr->AccessErrorBuf();
            // store certificate
            if ((pBuffer = new CSM_Buffer(*(itEntry->m_pCertFile))) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
            CSM_CertificateChoiceLst *pNewCertLst = 
                  new CSM_CertificateChoiceLst;
            if ((pCertificateChoice = &(*pNewCertLst->append())) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            if (pNewCertLst == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
            pCertificateChoice->SetEncodedCert(*pBuffer);
            // delete buffer since it was copied into pCertificateChoice
            delete (pBuffer); 
            pNewInstance->UpdateCertificates(pNewCertLst);
            //delete pNewCertLst; // since NOT copied in UpdateCertificates(...).
            // store issuer and serial number
            pNewInstance->SetIssuerAndSerialNumber(itEntry->GetIssuer());

            // because RSA does both digest and key encryption, do not
            // try to disable key encryption
         }
      }
   }            // END FOR each entry in the MAB

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

}

  
//////////////////////////////////////////////////////////////////////////
// This function restores or sets the default OIDs in the BTI
void CSM_Rsa::SetDefaultOIDs()
{
   SME_SETUP("CSM_Rsa::SetDefaultOIDs");
   AsnOid ENDOID("0.0.0");
   AsnOid oidHash[] = { 
       sha_1, 
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption, 
       md5, 
       md5WithRSAEncryption,
       ENDOID };
   AsnOid oidSign[] = { 
       rsa, 
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption, 
       bsafe_id_rsa_encr,
       rsaEncryption,
       ENDOID };
   AsnOid oidContentEncrypt[] = { 
       //des_ede3_cbc,
       //id_alg_CMS3DESwrap,
       rc2_cbc,
       id_alg_CMSRC2wrap,
       bsafe_id_rc2_encr,
       ENDOID };
   AsnOid oidKeyEncrypt[] = { 
       rsa, 
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption, 
       bsafe_id_rsa_encr,
       rsaEncryption,
       ENDOID };
   CSM_AlgVDA *pAlg;
   int i;
   CSM_AlgLstVDA *pDigestAlgs = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pKeyEncryption = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pDigestEncryption = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pContentEncryption = new CSM_AlgLstVDA;

   CSM_Common::SetDefaultOIDLists(pDigestAlgs, pDigestEncryption, 
      pKeyEncryption, pContentEncryption); //SET all CSM_Common supplied algs.
   // Produce list of separate alg lists.
   for (i=0; oidHash[i] != ENDOID; i++)
   {
       pAlg = &(*pDigestAlgs->append());
       pAlg->algorithm = oidHash[i];
   }
   for (i=0; oidSign[i] != ENDOID; i++)
   {
       pAlg = &(*pDigestEncryption->append());
       pAlg->algorithm = oidSign[i];
   }
   for (i=0; oidContentEncrypt[i] != ENDOID; i++)
   {
       pAlg = &(*pContentEncryption->append());
       pAlg->algorithm = oidContentEncrypt[i];
   }
   for (i=0; oidKeyEncrypt[i] != ENDOID; i++)
   {
       pAlg = &(*pKeyEncryption->append());
       pAlg->algorithm = oidKeyEncrypt[i];
   }

   // put the CSM_AlgLsts in the base token interface
   BTISetAlgIDs(pDigestAlgs, pDigestEncryption, pKeyEncryption, 
         pContentEncryption);
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
   // make Md5, RsaEncryption, RsaEncryption, and RC2Encryption the
   // preferred algs
   AsnOid oidMd5(md5/*bsafe_id_md5*/);
   AsnOid oidSha1(sha_1);
   AsnOid oidRsaEncr(rsaEncryption);
   AsnOid oidRc2Encr(bsafe_id_rc2_encr);
   BTISetPreferredCSInstAlgs(&oidSha1, &oidRsaEncr, &oidRsaEncr, &oidRc2Encr);
  
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_Rsa::SetX(CSM_Buffer *pX)
{
   SME_SETUP("CSM_Rsa::SetX");

   if (pX == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   if (m_RSAX)
      delete m_RSAX;
   if ((m_RSAX = new CSM_Buffer(*pX)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// DecodeCertificate accepts a pointer to a Certificate that will
// receive the decoded certificate.  It needs the buffer containing
// the encoded certificate.  It returns a pointer to the issuer,
// a pointer to the subject key info alg id, and a pointer to the subject
// public key.
SM_RET_VAL CSM_Rsa::DecodeCertificate(CSM_Buffer *pEncodedCert,
      Certificate *pSnaccCertificate, Name **ppIssuer,
      AlgorithmIdentifier **ppAlgID, AsnBits **ppY)
{
   SME_SETUP("CSM_Rsa::DecodeCertificate");

   if ((pEncodedCert == NULL) || (pSnaccCertificate == NULL)
         || (ppIssuer == NULL) || (ppAlgID == NULL) ||
         (ppY == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

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
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}


//////////////////////////////////////////////////////////////////////////
// GetParamsAndY accepts an address book entry and the address book as 
// input parameters.  It decodes the certificate referenced by the
// address book entry and compares the OID in the parameters with the
// OIDs in this instance of CSM_Free.  
// It also extracts and stores the Y value from the cert
SM_RET_VAL CSM_Rsa::GetParamsAndY(CSM_Buffer *pbufferCert,
    AlgorithmIdentifier *&pAlgID)
{
   Name *pIssuer;
   AsnBits *pY;
   Certificate snaccCertificate;

   SME_SETUP("CSM_Rsa::GetParamsAndY");

   // check incoming parameters
   if (pbufferCert == NULL)
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);
   if (pbufferCert->Length() == 0)
          return -1;    // EMPTY Cert NOT Fatal error.


   // make a copy of the cert buffer and convert it to memory if necessary
   pbufferCert->ConvertFileToMemory();

   // decode the certificate
   SME(DecodeCertificate(pbufferCert, &snaccCertificate, &pIssuer,
         &pAlgID, &pY));

   // get the public key out of the cert and store it to be set soon
   CSM_Buffer bufferTemp((const char *)pY->data(), pY->length());
   /*RWC;11/15/02;if (SM_AsnBits2Buffer(pY, &bufferTemp) != SM_NO_ERROR)
      SME_THROW(SM_RSA_PUT_Y_ERROR, "couldn't convert Y", NULL);
   // reverse bits for proper alignment
   SME(SM_BufferReverseBits(&bufferTemp));*/ 
   SME(m_RSAY.data = (unsigned char *)bufferTemp.Access());
   SME(m_RSAY.len = bufferTemp.Length());

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_Rsa::DecryptPrivateKey(char *pszPassword, 
                              CSM_Buffer *pEncryptedPrivateKeyInfo)
{
   BsafeEncryptedPrivateKeyInfo snaccEncryptedX;
   BsafePBEParameter snaccEncryptionParams;
   CSM_Buffer *pbufEncodedEncryptionParams = NULL;
   B_ALGORITHM_OBJ pbDecryption = (B_ALGORITHM_OBJ)NULL_PTR;
   long status;
   B_KEY_OBJ pbeKey = (B_KEY_OBJ)NULL_PTR;
   ITEM pbeKeyItem;
   char *pchDecryptedData;
   unsigned int outputLenUpdate;
   unsigned int outputLenFinal;
   SM_SIZE_T len;
   CSM_Buffer *bufEncodedPrivateKey = new CSM_Buffer;

   SME_SETUP("CSM_Rsa::DecryptPrivateKey");

   if ((pEncryptedPrivateKeyInfo == NULL) || (pszPassword == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   // ASN.1 decode the EncryptedPrivateKeyInfo
   DECODE_BUF((&snaccEncryptedX), pEncryptedPrivateKeyInfo);

   if (snaccEncryptedX.encryptionAlgorithm.algorithm != bsafepbeWithMD5AndDES_CBC 
      && snaccEncryptedX.encryptionAlgorithm.algorithm != pbeWithMD5AndRC2_CBC 
#ifndef TEMPORARY_CHECK_DUE_TO_VDA_ENVIRONMENT 
      && snaccEncryptedX.encryptionAlgorithm.algorithm != pbeWithMD5AndDES_CBC
#endif
          )
      SME_THROW(SM_RSA_UNSUPPORTED_ALG, "unsupported password encryption",
            NULL);

   // extract the encryption algorithm parameters and asn.1 decode them
   SM_EXTRACT_ANYBUF(pbufEncodedEncryptionParams, 
         snaccEncryptedX.encryptionAlgorithm.parameters);
   DECODE_BUF(&snaccEncryptionParams, pbufEncodedEncryptionParams);

   delete pbufEncodedEncryptionParams;
   pbufEncodedEncryptionParams = NULL;

   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&pbDecryption)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // Get the salt and iteration count
   if ((m_rc2PBEParams.salt = (unsigned char *)calloc(1, 
         SM_RSA_RC2_BLOCKSIZE)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   memcpy(m_rc2PBEParams.salt, snaccEncryptionParams.salt.c_str(), 
                SM_RSA_RC2_BLOCKSIZE);
   m_rc2PBEParams.iterationCount = snaccEncryptionParams.iterationCount;

   // Set the Algorithm Object
   if ((status = B_SetAlgorithmInfo(pbDecryption, 
         AI_MD5WithRC2_CBCPad, (POINTER)&m_rc2PBEParams)) != 0)
      SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // Create a Key Object
   if ((status = B_CreateKeyObject(&pbeKey)) != 0)
      SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // Set the key data from the incoming pszPassword
   pbeKeyItem.data = (unsigned char *)pszPassword;
   pbeKeyItem.len = strlen(pszPassword);
   pszPassword = NULL;

   if ((status = (long)B_SetKeyInfo(pbeKey, KI_Item,
         (POINTER)&pbeKeyItem)) != 0)
      SME_THROW(status, "B_SetKeyInfo failed", NULL);

   //zeroize the key
   if (pbeKeyItem.data != NULL_PTR)
   {
      memset(pbeKeyItem.data, 0, pbeKeyItem.len);
      free(pbeKeyItem.data);
      pbeKeyItem.data = NULL_PTR;
      pbeKeyItem.len = 0;
   }
   // Initialize algorithmObject for decrypting data using the
   // algorithm specified by the previous call to B_SetAlgorithmInfo.
   if ((status = B_DecryptInit(pbDecryption, pbeKey, m_pCHOOSER,
      (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DecryptInit failed", NULL);

   // get the key to be decrypted
   CSM_Buffer bufEncryptedKey(snaccEncryptedX.encryptedData.c_str(),
                              snaccEncryptedX.encryptedData.Len());

   // open input for reading
   SME(bufEncryptedKey.Open(SM_FOPEN_READ));

   // open output for writing
   SME(bufEncodedPrivateKey->Open(SM_FOPEN_WRITE));

   pchDecryptedData = (char *)calloc(1, bufEncryptedKey.Length());
   if (pchDecryptedData == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Update the decrypting process
   if ((status = (long)B_DecryptUpdate(pbDecryption, 
         (unsigned char *)pchDecryptedData, &outputLenUpdate,
         bufEncryptedKey.Length(),
         (unsigned char *)bufEncryptedKey.Access(), 
         bufEncryptedKey.Length(), (B_ALGORITHM_OBJ)NULL_PTR, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_DecryptUpdate failed", NULL);

   outputLenFinal = bufEncryptedKey.Length() - outputLenUpdate;

   // Finalize the decrypting process 
   if ((status = (long)B_DecryptFinal(pbDecryption, 
         (unsigned char *)pchDecryptedData + outputLenUpdate, 
         &outputLenFinal, bufEncryptedKey.Length() - outputLenUpdate, 
         (B_ALGORITHM_OBJ)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_DecryptFinal failed", NULL);

   // Remove the padding
   len = bufEncryptedKey.Length() - (SM_RSA_MAXPAD - outputLenFinal);
   //RWC5;bufEncodedPrivateKey->Alloc(len);
   bufEncodedPrivateKey->Write(pchDecryptedData, len);

   SME(bufEncryptedKey.Close());
   SME(bufEncodedPrivateKey->Close());
   free(pchDecryptedData);

   B_DestroyKeyObject(&pbeKey);
   B_DestroyAlgorithmObject(&pbDecryption);
   if (m_rc2PBEParams.salt)
      free(m_rc2PBEParams.salt);

   SME_FINISH
   SME_CATCH_SETUP
      if (pbufEncodedEncryptionParams)
         delete pbufEncodedEncryptionParams;
   SME_CATCH_FINISH

   return bufEncodedPrivateKey;
}
   
//////////////////////////////////////////////////////////////////////////
// RWC; NORMALLY, this call will not be used.  The model was changed to 
// RWC;  call a virtual function to destroy the individual RSA Instances.
void SMRsaShutdown(CSMIME *pCSMIME, char *pszPrefix)
{
   SME_SETUP("SMRsaShutdown");

   CSM_CtilInstLst::iterator itInst;

   if (pszPrefix == NULL)
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   // we can only shut down if there are instances to look at
   if (pCSMIME != NULL && pCSMIME->m_pCSInsts != NULL)
   {
      for (itInst =  pCSMIME->m_pCSInsts->begin();
           itInst != pCSMIME->m_pCSInsts->end();
           ++itInst)
      {
         // look at the instance ID, if it begins with the passed
         // in prefix, then this is an instance that we should try to
         // cleanup
         if (strstr((*itInst)->AccessID(), pszPrefix) == (*itInst)->AccessID())
         {
            delete (((CSM_Rsa *)(*itInst)->AccessTokenInterface()));
            (*itInst)->SetTokenInterface(NULL);
         }
      }
   }

   SME_FINISH_CATCH
}

B_KEY_OBJ CSM_Rsa::GetBsafePrivateKey()
{

   ITEM tmpItem;
   CSM_Buffer *pbufX = NULL;
   char *pszPassword = NULL; // temp spot for password
   long status;
   B_KEY_OBJ privateKey = (B_KEY_OBJ)NULL_PTR;

   SME_SETUP("GetBsafePrivateKey");

   // get the password to decrypt the private key
   SME(pszPassword = GetPassword());
   SME(pbufX = DecryptPrivateKey(pszPassword, m_RSAX));

   // tmpItem loaded for call to B_SetKeyInfo which requires third
   // parameter to be an ITEM
   SME(tmpItem.len = (unsigned int)pbufX->Length());
   SME(tmpItem.data = (unsigned char *)pbufX->Get());

  // Create a private Key Object and ASN.1 decode it from m_RSAX
   if ((status = B_CreateKeyObject(&privateKey)) != 0)
      SME_THROW(status, "B_CreateKeyObject failed", NULL);

   if ((status = (long)B_SetKeyInfo(privateKey, KI_PKCS_RSAPrivateBER,
         (POINTER)&tmpItem)) != 0)
      SME_THROW(status, "B_SetKeyInfo failed", NULL);

   if (pbufX)
      delete pbufX;
   if (tmpItem.data)
      free(tmpItem.data);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
     if (pbufX)
        delete pbufX;
   SME_CATCH_FINISH

   return privateKey;
}


//
//
CSM_TokenInterface *CSM_Rsa::AddLogin(
   CSM_Buffer &CertBuf,       // IN, public key and algs
   CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
   char *lpszPassword,        // IN, password to pbe decrypt privatekey
   char *lpszID)              // CTIL specific ID
{
    CSM_TokenInterface *pResultTI=NULL;
    
    pResultTI = AddLoginStatic(NULL, CertBuf, pSFLPrivateKey, lpszPassword, lpszID);

    return pResultTI;
}


CSM_TokenInterface *CSM_Rsa::AddLoginStatic(
   CSM_Rsa *pRsaIN,             // IN,OPTIONAL, input class instance.
   CSM_Buffer &CertBuf,       // IN, public key and algs
   CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
   char *lpszPassword,        // IN, password to pbe decrypt privatekey
   char *lpszID)              // CTIL specific ID
{
   CSM_TokenInterface *pTokenInterface=NULL;
   CSM_AlgLstVDA *pDigestAlgs=NULL;
   CSM_AlgLstVDA *pKeyEncryption=NULL;
   CSM_AlgLstVDA *pDigestEncryption=NULL;
   CSM_AlgLstVDA *pContentEncryption=NULL;
   AlgorithmIdentifier *pAlgID=NULL;
   CSM_Rsa *pRsa=pRsaIN;


   SME_SETUP("CSM_Rsa::AddLoginStatic");

        if (pRsa == NULL)
        {   // This memory will be passed back to the caller 
            //   through CSM_TokenInterface.
            // generate a new FREE CTI class
            if ((pRsa = new CSM_Rsa) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            // CSM_Free3 constructor set's Alg IDs
        }

            if (lpszPassword)
            {
               // store other information in the Free CTI
               pRsa->SetPassword(lpszPassword);
            }
            if (pSFLPrivateKey)
            {
               SME(pRsa->SetX(pSFLPrivateKey));
            }
            pRsa->SetDefaultOIDs();

            // store parameters and Y in the preferred Alg for this instance
            pAlgID = NULL;
            SME(pRsa->GetParamsAndY(&CertBuf, pAlgID));
            if (pAlgID)    // MEMORY leak cleanup.
            {
               delete pAlgID;
               pAlgID = NULL;
            }

            strcpy(lpszID, "RSA");      // Set ID base name for instance.
            // store the prefix
            pRsa->m_pszPrefix = strdup(lpszID);
            // RWC; Set custom parameters from cert algorithm if necessary.
            // pAlgID was set by GetParamsAndY.  We store the parameters in
            // the instance so they may be used as necessary later on
            pRsa->BTIGetAlgIDs(&pDigestAlgs, &pDigestEncryption, 
                &pKeyEncryption, &pContentEncryption);   
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
            pTokenInterface = pRsa;  // setup for generic load into instance 
                                      //  array.

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH


   return(pTokenInterface);
}



extern "C" {


#ifndef NO_DLL

SM_RSADLL_API CSM_CryptoKeysRsa * SM_BuildCryptoKeysRSA(CSM_CertificateChoice *pCert, 
    char *lpszPassword)
{
   CSM_CryptoKeysRsa *pRSA_CK;
   if(pCert == NULL)
   {
      pRSA_CK= new CSM_CryptoKeysRsaExport();
      pRSA_CK->SetPassword(lpszPassword);
   }
   else
      pRSA_CK= new CSM_CryptoKeysRsaExport(pCert, lpszPassword);

   return(pRSA_CK);
}

}   // END extern "C"

_END_CERT_NAMESPACE
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;

extern "C" {
long Make_argv(char *string, int *pargc, char ***pargv);
void Delete_argv(int argc, char **pargv);

SM_RSADLL_API SM_RET_VAL DLLBuildTokenInterface(CSM_CtilMgr &Csmime, 
    char *lpszBuildArgs)
{
    SM_RET_VAL status = 0;
    int argc1=0;
    char **argv1;
    char ptr[30];
    int localArgs = 0;

    memset(ptr, '\0', 30);
    if (lpszBuildArgs == NULL)
    {
	    localArgs = 1;
	    lpszBuildArgs = strdup ("sm_rsaDLL NULL NULL NULL sm_rsaDLL");
    }
    for (int i=0; i < (int)strlen("sm_RsaDLL"); i++)
        ptr[i] = (char)toupper(lpszBuildArgs[i]);
    // Preliminary check that this request is for our library.
    if (strncmp(ptr, "SM_RSADLL", strlen("sm_RsaDLL")) == 0)
    {
        Make_argv(lpszBuildArgs, &argc1, &argv1);
        if (argc1 == 4)
        {
           // Pass char *pszPassword, char *pszAddressBook, char *pszPrefix
           SMRsaInit(&Csmime, argv1[1], argv1[2], argv1[3]);
        }
        else if (argc1 == 5)    // Handle single login attempt.
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
            pTokenInterface  = CSM_Rsa::AddLoginStatic(NULL, *pCertBuf,
                pPrivateKey, argv1[3], argv1[4]);
            GLOBALAddLoginFinish(Csmime, pTokenInterface, argv1[4], *pCertBuf);
            if (pPrivateKey)
               delete pPrivateKey;
            if (pCertBuf)
               delete pCertBuf;
        }
        else    // OTHER MODELS to be supported.
        {
            status = -1;
        }
        Delete_argv(argc1, argv1);
    }
    else
    {
        status = -1;
        std::cout << "DLL1BuildTokenInterface failed!!!\n";
    }
    if (localArgs == 1)
	    delete lpszBuildArgs;
    //return new CSM_Free3;
    return(status);
}

SM_RSADLL_API char * DLLGetId()
{
    return(strdup("sm_RsaDLL"));
}


}       // extern "C".


#endif


// EOF sm_rsa.cpp

