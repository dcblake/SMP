//  sm_CryptoKeysFree3Base.cpp
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#endif

#include <string.h>
#include "sm_CryptoKeysDsaExport.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;

#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif


CSM_Buffer* CSM_CryptoKeysFree3Base::GetPrivateKeyWrapped()
{
   CSM_Buffer *ptmpX = NULL;

   ptmpX = m_FreeCTI.GetX();
   if (ptmpX)
      return new CSM_Buffer(*ptmpX);
   else
      return NULL;
}

CSM_Buffer* CSM_CryptoKeysFree3Base::WrapPrivateKey(CSM_Buffer &bufX)
{
   CSM_Alg *poidXAlgId;
   CSM_Buffer *ptmpBuf;
   char *pszPassword = m_FreeCTI.GetPassword();

   SME_SETUP("WrapPrivateKey");
   if (m_pCert)
   {
      poidXAlgId = m_pCert->GetPublicKeyAlg();
      if (poidXAlgId)
         SME(ptmpBuf = WrapPrivateKey(bufX, pszPassword, poidXAlgId));
   }
   else
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   if (poidXAlgId)
      delete poidXAlgId;
   if (pszPassword)
      free(pszPassword);

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return ptmpBuf;
}

/////////////////////////////////////////////////////////////////////////////
// This function generates an encrypted private key info
CSM_Buffer* CSM_CryptoKeysFree3Base::WrapPrivateKey(CSM_Buffer &bufferX,
         char *pszPassword, CSM_Alg *pXAlgId)
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
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
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
   SME(m_FreeCTI.BTISetPreferredCSInstAlgs(&o, NULL, NULL, NULL));
   if ((status = m_FreeCTI.SMTI_DigestData
                                 (&bufferSaltInput, &bufferSalt)) != SM_NO_ERROR)
      SME_THROW(status, "SMTI_DigestData returned error.", NULL);

   SME(pK = m_FreeCTI.GeneratePBEKey(&bufferSalt, iterationCount, 
      pszPassword));

   // the first 8 bytes of pK is the DES Key and the second 8 bytes is the IV
   // create our cipher
   DESEncryption encryption((const unsigned char*)pK->Access());
   // create cbc object
#ifdef RWC_NOT_IN_CRYPTOPP3
   CBCEncryption cbc_encryption(encryption, 
         (const unsigned char*)(pK->Access() + 8));
#else
#ifndef CRYPTOPP_5_0
   CBCPaddedEncryptor cbc_encryption(
#else // CRYPTOPP_5_0
   CBC_Mode_ExternalCipher::Encryption  cbc_encryption(
#endif // CRYPTOPP_5_0
       encryption, (const unsigned char*)(pK->Access() + 8));
#endif

   CSM_Buffer bufEncryptedData;
   SME(m_FreeCTI.RawEncrypt(pbufEncodedPrivateKey, &bufEncryptedData, 
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
   ENCODE_BUF((&snaccEncryptedX), pbufEncryptedPrivateKey);

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

   SME_CATCH_FINISH

   return pbufEncryptedPrivateKey;
}       // END WrapPrivateKey(...)

/////////////////////////////////////////////////////////////////////////////
// This function generates an encrypted private key info
CSM_Buffer* CSM_CryptoKeysFree3Base::WrapPrivateKeyInfo(CSM_Buffer &bufferX,
         char *pszPassword, CSM_Alg *pXAlgId)
{
   AsnOid *poidXAlgId = new AsnOid(pXAlgId->algorithm);
   CSM_Buffer *pXAlgParams = NULL;
   PrivateKeyInfo snaccPrivateKeyInfo;
   EncryptedPrivateKeyInfo snaccEncryptedX;
   CSM_Buffer *pbufEncodedPrivateKey = NULL;
   CSM_Buffer *pK = NULL; // PBE Key
   int version = 0;

   SME_SETUP("WrapPrivateKeyInfo");

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
      SM_ASSIGN_ANYBUF((pXAlgParams), 
            snaccPrivateKeyInfo.privateKeyAlgorithm.parameters);
    }

   // read private key
   snaccPrivateKeyInfo.privateKey.Set(bufferX.Get(), bufferX.Length());

   ////////////////////////////////////
   // ASN.1 encode the private key info
   ENCODE_BUF((&snaccPrivateKeyInfo), pbufEncodedPrivateKey);

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

   SME_CATCH_FINISH

   return pbufEncodedPrivateKey;
}

/////////////////////////////////////////////////////////////////////////////
// This function generates an decrypted private key info
CSM_Buffer* CSM_CryptoKeysFree3Base::GetPrivateKeyUnwrapped(char *pszPassword, 
         CSM_Buffer *pEncryptedPrivateKeyInfo)
{
   EncryptedPrivateKeyInfo snaccEncryptedX;
   PBEParameter snaccEncryptionParams;
   PrivateKeyInfo snaccX;
   CSM_Buffer *pbufEncodedEncryptionParams = NULL;
   CSM_Buffer *pK = NULL;
   CSM_Buffer *pX = NULL;

   SME_SETUP("CSM_CryptoKeysFree3Base::GetPrivateKeyUnwrapped");

   if ((pEncryptedPrivateKeyInfo == NULL) || (pszPassword == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // ASN.1 decode the EncryptedPrivateKeyInfo
   DECODE_BUF((&snaccEncryptedX), pEncryptedPrivateKeyInfo);

   if (snaccEncryptedX.encryptionAlgorithm.algorithm != pbeWithMD5AndDES_CBC)
      SME_THROW(SM_FREE_UNSUPPORTED_ALG, "unsupported password encryption",
            NULL);

   // extract the encryption algorithm parameters and asn.1 decode them
   SM_EXTRACT_ANYBUF(pbufEncodedEncryptionParams, 
         snaccEncryptedX.encryptionAlgorithm.parameters);
   DECODE_BUF(&snaccEncryptionParams, pbufEncodedEncryptionParams);

   delete pbufEncodedEncryptionParams;
   pbufEncodedEncryptionParams = NULL;

   int nIterCount = snaccEncryptionParams.iterationCount;
   CSM_Buffer bufSalt(snaccEncryptionParams.salt.c_str(), snaccEncryptionParams.salt.Len());

   // generate the key using the salt, the iteration count, and the password
   SME(pK = m_FreeCTI.GeneratePBEKey(&bufSalt, nIterCount, pszPassword));

   // create our cipher
   DESDecryption decryption((const unsigned char*)pK->Access());

   // create cbc object
#ifndef CRYPTOPP_5_0
   CBCPaddedDecryptor cbc_decryption(
#else // CRYPTOPP_5_0
   CBC_Mode_ExternalCipher::Decryption  cbc_decryption(
#endif // CRYPTOPP_5_0
       decryption, (const unsigned char *)pK->Access() + 8);

   // get the key to be decrypted
   CSM_Buffer bufEncryptedKey((char*)snaccEncryptedX.encryptedData.c_str(),
            snaccEncryptedX.encryptedData.Len());
   CSM_Buffer bufEncodedPrivateKey;

   SME(m_FreeCTI.RawDecrypt(&bufEncryptedKey, &bufEncodedPrivateKey, &cbc_decryption));
   //bufEncodedPrivateKey.ConvertMemoryToFile("lisa.txt");
   // ASN.1 decode the private key
   DECODE_BUF((&snaccX), &bufEncodedPrivateKey);

   // TBD, we may want to do something with the parameters

   if ((pX = new CSM_Buffer((char *)snaccX.privateKey.c_str(), 
         snaccX.privateKey.Len())) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   if (pK)
      delete pK;

   SME_FINISH
   SME_CATCH_SETUP
      if (pK)
         delete pK;
      if (pbufEncodedEncryptionParams)
         delete pbufEncodedEncryptionParams;
   SME_CATCH_FINISH

   return pX;

}

SubjectPublicKeyInfo* CSM_CryptoKeysFree3Base::LoadSNACCPublicKeyInfo(CSM_Buffer *AnyParams,
      CSM_Buffer *PubKey)
{
   SubjectPublicKeyInfo *subjPubKeyInfo = NULL;
   CSM_Buffer pTmpBufPubKey;    // ONLY used if necessary.
   SME_SETUP("CSM_CryptoKeysFree3Base::LoadSNACCPublicKeyInfo");

   subjPubKeyInfo = new SubjectPublicKeyInfo();
   subjPubKeyInfo->algorithm.algorithm = m_AlgOid;

   if (((strcmp(m_AlgOid.GetChar(),"id_dsa_with_sha1") == 0  ||
        strcmp(m_AlgOid.GetChar(),"id_dsa") == 0) &&
       AnyParams == NULL)  ||
      (strcmp(m_AlgOid.GetChar(),"1.2.840.10040.4.3") == 0))
      //RWC;DH;ALLOW TO LOAD PARAMS;(strcmp(m_AlgOid.GetChar(),"1.2.840.10046.2.1") == 0))
   {
      CSM_Alg::LoadNullParams(&subjPubKeyInfo->algorithm);
      subjPubKeyInfo->subjectPublicKey.Set((const unsigned char*)PubKey->Access(), PubKey->Length()*8);
   }
   else
   {
      if (AnyParams)
      {
          if (subjPubKeyInfo->algorithm.parameters == NULL)
             subjPubKeyInfo->algorithm.parameters= new AsnAny;
          SM_ASSIGN_ANYBUF(AnyParams,subjPubKeyInfo->algorithm.parameters);
      }     // END IF AnyParams
#ifndef CRYPTOPP_3_2
      if (strcmp(m_AlgOid.GetChar(),"2.5.8.1.1"/*"rsa"*/) == 0  ||
        strcmp(m_AlgOid.GetChar(),"1.2.840.113549.1.1.1"/*"rsaEncryption"*/) == 0)
      {
         // The newer version changed the returned format of the RSA key by wrapping in
         //  a PrivateKeyInfo, not just the raw RSA private key.  We must re-extract
         //  in order for the open SSL logic to properly recognize the RSA key.
         SubjectPublicKeyInfo snaccPKI;
         DECODE_BUF((&snaccPKI), PubKey);
         subjPubKeyInfo->subjectPublicKey = snaccPKI.subjectPublicKey;
      }
      else
#endif
      {
          subjPubKeyInfo->subjectPublicKey.Set((const unsigned char*)PubKey->Access(), 
            PubKey->Length()*8);
      }
   }


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
   return(subjPubKeyInfo);
}

_END_CERT_NAMESPACE

// EOF sm_CryptoKeysFree3Base.cpp
