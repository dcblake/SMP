//  sm_CryptoKeysRsa.cpp
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#include "sm_CryptoKeysRsaExport.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;


//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CryptoKeysRsaExport::GetPublicKey()        
{

   CSM_Buffer *bufPublicKey = new CSM_Buffer;

   SME_SETUP("CSM_CryptoKeys::GetRSAPublicKey");

   // Write the public key to a CSM_Buffer
   bufPublicKey->Set((char *)m_RsaCTI.m_RSAY.data, m_RsaCTI.m_RSAY.len);

   SME_FINISH_CATCH

   return bufPublicKey;


}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CryptoKeysRsaExport::GetPrivateKeyWrapped()
{
   CSM_Buffer *ptmpX = NULL;  // probably need to delete ptmpX

   ptmpX = m_RsaCTI.GetX();
   if (ptmpX)
      return new CSM_Buffer(*ptmpX);
   else
      return NULL;
}

CSM_Buffer* CSM_CryptoKeysRsaExport::WrapPrivateKey(CSM_Buffer &bufX)
{

   char *pszPassword = m_RsaCTI.GetPassword();

   return(WrapPrivateKey(bufX, pszPassword));
}


CSM_Buffer* CSM_CryptoKeysRsaExport::WrapPrivateKey(CSM_Buffer &bufferX, 
             char *pszPassword)
{
   SM_RET_VAL status = SM_NO_ERROR;
   BsafeEncryptedPrivateKeyInfo snaccEncryptedX;
   CSM_Buffer *pbufEncryptedPrivateKey=NULL;
   B_KEY_OBJ pbeKey = (B_KEY_OBJ)NULL_PTR;
   ITEM pbeKeyItem;
   B_ALGORITHM_OBJ pbEncrypter = (B_ALGORITHM_OBJ)NULL_PTR;
   CSM_Buffer *bufEncryptedData;
   unsigned int outputLenUpdate;
   unsigned int outputLenFinal;
   char *tmpout;
   char padout[8];
   BsafePBEParameter snaccPBEParameter;
   CSM_Buffer *pbufEncryptionParams=NULL;
   ITEM tmpItem;
   int iterationCount = 3;

   SME_SETUP("WrapPrivateKey");


   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&pbEncrypter)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // use the random number generator to produce the saltdata        
   {
      CSM_Buffer temp;
      SME(m_RsaCTI.SMTI_Random(NULL, &temp, SM_RSA_RC2_BLOCKSIZE));
      SME(m_RsaCTI.m_rc2PBEParams.salt = (unsigned char *)temp.Get());
   }

   // read the iteration count
   m_RsaCTI.m_rc2PBEParams.iterationCount = iterationCount;

   // set m_RSAX and set a temp item with the same values for BSAFE calls
   {
      SME(m_RsaCTI.SetX(&bufferX));
      SME(tmpItem.len = (unsigned int)bufferX.Length());
      SME(tmpItem.data = (unsigned char *)bufferX.Get());
   }

   // Set the Algorithm Object
   if ((status = B_SetAlgorithmInfo(pbEncrypter, 
         AI_MD5WithRC2_CBCPad, (POINTER)&m_RsaCTI.m_rc2PBEParams)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // Create a Key Object
   if ((status = B_CreateKeyObject(&pbeKey)) != 0)
         SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // Set the keyItem using the password
   pbeKeyItem.data = (unsigned char *)pszPassword;
   pbeKeyItem.len = strlen(pszPassword);

   // set the pbeKey with the password
   if ((status = (long)B_SetKeyInfo(pbeKey, KI_Item,
         (POINTER)&pbeKeyItem)) != 0)
      SME_THROW(status, "B_SetKeyInfo failed", NULL);

   // zeroize the memory
   memset(pbeKeyItem.data, 0, pbeKeyItem.len);

   // Initialize algorithmObject for encrypting data using the
   // algorithm specified by the previous call to B_SetAlgorithmInfo.
   if ((status = B_EncryptInit(pbEncrypter, pbeKey, m_RsaCTI.m_pCHOOSER,
      (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_EncryptInit failed", NULL);

   // open output for writing
   if ((tmpout = (char *)calloc(1, tmpItem.len + 8)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Update the encrypting process
   if ((status = (long)B_EncryptUpdate(pbEncrypter, 
         (unsigned char *)tmpout, &outputLenUpdate,
         tmpItem.len + 8, (unsigned char *)tmpItem.data, 
         tmpItem.len, (B_ALGORITHM_OBJ)NULL_PTR, 
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_EncryptUpdate failed", NULL);

   // Finalize the encrypting process 
   if ((status = (long)B_EncryptFinal(pbEncrypter, 
         (unsigned char *)&padout[0], 
         &outputLenFinal, 8, 
         (B_ALGORITHM_OBJ)NULL_PTR, (A_SURRENDER_CTX *)NULL_PTR)) != 0) 
      SME_THROW(status, "B_EncryptFinal failed", NULL);

   bufEncryptedData = new CSM_Buffer;
   SME(bufEncryptedData->Open(SM_FOPEN_WRITE));
   if (outputLenUpdate != 0)
      SME(bufEncryptedData->Write(tmpout, outputLenUpdate));
   SME(bufEncryptedData->Write(padout, outputLenFinal));

   SME(bufEncryptedData->Close());
   free(tmpout);


   // load the encrypted data
   snaccEncryptedX.encryptedData.Set(bufEncryptedData->Access(), 
         bufEncryptedData->Length());

   // fill and encode the encryption algorithm parameters
   snaccPBEParameter.salt.Set((const char *)m_RsaCTI.m_rc2PBEParams.salt,
                              SM_RSA_RC2_BLOCKSIZE);
   snaccPBEParameter.iterationCount = m_RsaCTI.m_rc2PBEParams.iterationCount;
   ENCODE_BUF((&snaccPBEParameter), pbufEncryptionParams);

   // load the encryptionAlgorithm
   snaccEncryptedX.encryptionAlgorithm.algorithm = bsafepbeWithMD5AndDES_CBC;
   if ((snaccEncryptedX.encryptionAlgorithm.parameters = new AsnAny) == NULL)
      SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
   SM_ASSIGN_ANYBUF(pbufEncryptionParams, 
         snaccEncryptedX.encryptionAlgorithm.parameters);

   /////////////////////////////////////
   // encode the EncryptedPrivateKeyInfo
   ENCODE_BUF((&snaccEncryptedX), pbufEncryptedPrivateKey);

   if (tmpItem.data)
      free(tmpItem.data);
   if (pbufEncryptionParams)
      delete pbufEncryptionParams;
   if (bufEncryptedData)
      delete bufEncryptedData;
   B_DestroyKeyObject(&pbeKey);
   B_DestroyAlgorithmObject(&pbEncrypter);
   //RWC;if (pbeKeyItem.data != NULL_PTR)
   //RWC;   free(pbeKeyItem.data);

   SME_FINISH_CATCH

   return pbufEncryptedPrivateKey;
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CryptoKeysRsaExport::GetPrivateKeyUnwrapped(char *pszPassword, 
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

   SME_SETUP("CSM_CryptoKeys::GetRSAPrivateKeyUnwrapped");

   if ((pEncryptedPrivateKeyInfo == NULL) || (pszPassword == NULL))
      SME_THROW(SM_RSA_MISSING_PARAM, NULL, NULL);

   // ASN.1 decode the EncryptedPrivateKeyInfo
   DECODE_BUF((&snaccEncryptedX), pEncryptedPrivateKeyInfo);

   if (snaccEncryptedX.encryptionAlgorithm.algorithm != bsafepbeWithMD5AndDES_CBC)
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
   if ((m_RsaCTI.m_rc2PBEParams.salt = (unsigned char *)calloc(1, 
         SM_RSA_RC2_BLOCKSIZE)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   memcpy(m_RsaCTI.m_rc2PBEParams.salt, snaccEncryptionParams.salt.c_str(), 
                      SM_RSA_RC2_BLOCKSIZE);
   m_RsaCTI.m_rc2PBEParams.iterationCount = 
      snaccEncryptionParams.iterationCount;

   // Set the Algorithm Object
   if ((status = B_SetAlgorithmInfo(pbDecryption, 
         AI_MD5WithRC2_CBCPad, (POINTER)&m_RsaCTI.m_rc2PBEParams)) != 0)
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
   if ((status = B_DecryptInit(pbDecryption, pbeKey, m_RsaCTI.m_pCHOOSER,
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
   bufEncodedPrivateKey->Alloc(len);
   bufEncodedPrivateKey->Write(pchDecryptedData, len);

   SME(bufEncryptedKey.Close());
   SME(bufEncodedPrivateKey->Close());
   free(pchDecryptedData);

   B_DestroyAlgorithmObject(&pbDecryption);
   if (m_RsaCTI.m_rc2PBEParams.salt)
      free(m_RsaCTI.m_rc2PBEParams.salt);

   SME_FINISH
   SME_CATCH_SETUP
      if (pbufEncodedEncryptionParams)
         delete pbufEncodedEncryptionParams;
   SME_CATCH_FINISH

   return bufEncodedPrivateKey;
}


//////////////////////////////////////////////////////////////////////////
// Most parameters are not used in the RSA version of GenerateKeys  - only
// the bufferX and bufferY parameters (all others are defaulted values.
SM_RET_VAL CSM_CryptoKeysRsaExport::GenerateKeys(CSM_Buffer *bufferX, 
      CSM_Buffer *bufferY, CSM_Buffer *P, CSM_Buffer *G, CSM_Buffer *Q, 
      int keybits, bool bParams, CSM_Buffer *)        
{

   SM_RET_VAL status = SM_NO_ERROR;
   B_ALGORITHM_OBJ keypairGenerator = (B_ALGORITHM_OBJ)NULL_PTR;
   B_KEY_OBJ publicKey = (B_KEY_OBJ)NULL_PTR; 
   B_KEY_OBJ privateKey = (B_KEY_OBJ)NULL_PTR; 
   ITEM *bsafePublicKeyBER;
   ITEM *bsafePrivateKeyBER;

   SME_SETUP("CSM_CryptoKeys::GenerateRSAKeys");

   // Create an Algorithm Object
   if ((status = (long)B_CreateAlgorithmObject (&keypairGenerator)) != 0)
      SME_THROW(status, "B_CreateAlgorithmObject failed", NULL);

   // Set the Algorithm Object using AI_RSAKeyGen
   if ((status = B_SetAlgorithmInfo(keypairGenerator, 
         AI_RSAKeyGen, (POINTER)&m_RsaCTI.m_keygenParams)) != 0)
         SME_THROW(status, "B_SetAlgorithmInfo failed", NULL);

   // Call B_GenerateInit.
   if ((status = B_GenerateInit(keypairGenerator,
        m_RsaCTI.m_pCHOOSER, (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_GenerateInit failed", NULL);

   // Create a public Key Object
   if ((status = B_CreateKeyObject(&publicKey)) != 0)
         SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // Create a private Key Object
   if ((status = B_CreateKeyObject(&privateKey)) != 0)
         SME_THROW(status, "B_CreateKeyObject failed", NULL);

   // generate the RSA key pair
   if ((status = (long)B_GenerateKeypair(keypairGenerator, 
         publicKey, privateKey, m_RsaCTI.m_randomAlgorithm,
         (A_SURRENDER_CTX *)NULL_PTR)) != 0)
      SME_THROW(status, "B_GenerateKeypair failed", NULL);

   // BER Encode the public key
   if ((status = B_GetKeyInfo((POINTER *)&bsafePublicKeyBER,
         publicKey, KI_RSAPublicBER)) != 0)
      SME_THROW(status, "B_GetKeyInfo failed", NULL);

   // BER Encode the private key
   if ((status = B_GetKeyInfo((POINTER *)&bsafePrivateKeyBER,
         privateKey, KI_PKCS_RSAPrivateBER)) != 0)
      SME_THROW(status, "B_GetKeyInfo failed", NULL);

   // Write the BER encoded public key to m_RSAY and save it to the buffer
   m_RsaCTI.m_RSAY.data = bsafePublicKeyBER->data;
   m_RsaCTI.m_RSAY.len = bsafePublicKeyBER->len;
   bufferY->Open(SM_FOPEN_WRITE);
   bufferY->Write((char *)bsafePublicKeyBER->data, bsafePublicKeyBER->len);
   bufferY->Close();

   // Write the BER encoded private key to m_RSAX and save it to the buffer
   bufferX->Open(SM_FOPEN_WRITE);
   bufferX->Write((char *)bsafePrivateKeyBER->data, bsafePrivateKeyBER->len);
   bufferX->Close();
   m_RsaCTI.SetX(bufferX);

   // Destroy objects
   B_DestroyAlgorithmObject(&keypairGenerator);
   B_DestroyAlgorithmObject(&publicKey);
   B_DestroyAlgorithmObject(&privateKey);

   SME_FINISH_CATCH

#ifdef WIN32
    bParams;keybits;Q;G;P;  //AVOIDS warning.
#endif // WIN32
   return status;
}

SubjectPublicKeyInfo* CSM_CryptoKeysRsaExport::LoadSNACCPublicKeyInfo(CSM_Buffer *AnyParams,
      CSM_Buffer *PubKey)
{
   SubjectPublicKeyInfo *subjPubKeyInfo = NULL;

   subjPubKeyInfo = new SubjectPublicKeyInfo();

   subjPubKeyInfo->algorithm.algorithm = m_AlgOid;

   if(AnyParams->Access() != NULL)
   {
      SM_ASSIGN_ANYBUF(AnyParams, subjPubKeyInfo->algorithm.parameters);
   }
   else
   {
      CSM_Alg::LoadNullParams(&subjPubKeyInfo->algorithm);
   }

   subjPubKeyInfo->subjectPublicKey.Set((const unsigned char *)PubKey->Access(), PubKey->Length()*8);

   return(subjPubKeyInfo);
}

_END_CERT_NAMESPACE

// EOF sm_CryptoKeysRsa.cpp
