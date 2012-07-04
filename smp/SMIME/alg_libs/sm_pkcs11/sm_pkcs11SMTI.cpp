#ifndef NO_SCCS_ID
static char SccsId[ ] = "@(#) sm_pkcs11SMTI.cpp 1.12 08/29/00 14:34:39"; 
#endif

#include "sm_pkcs11.h"
#include "sm_pkcs11Oids.h"
#include "sm_pkcs11DSASig.h"
#include "sm_Common.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;

//
//
SM_RET_VAL CSM_Pkcs11::SMTI_Login()
{
    SM_RET_VAL status = SM_NO_ERROR;

    return status;
}

// FUNCTION: SMTI_Sign()
//
// PURPOSE: To produce a digitial signature on the data pointed to by pDataIn.
//
// INPUT DESCRIPTION:
//   Type/Class     Name             I/O    Description
//
//   CSM_Buffer *   pDataIn           I     Binary or Ascii Data to be signed.
//   CSM_Buffer *   pEncryptedDigest  O     Signature Value
//   CSM_Buffer *   pDigest           O     Hash Value
//
SM_RET_VAL CSM_Pkcs11::SMTI_Sign(CSM_Buffer *pDataIn, 
                                 CSM_Buffer *pEncryptedDigest, 
                                 CSM_Buffer *pDigest) 
{ 
   SM_RET_VAL status = SM_NO_ERROR; 
   CSM_Buffer      *pHashValue = NULL; 
   AsnOid *pSigOID = NULL; 
   AsnOid * pDigOID = NULL; 
   CSM_Buffer tmpDigestBuf; 
   CSM_Buffer *pTempBuf = NULL; 
   DigestInfo2 rsaDigestInfo; 
   CK_MECHANISM_PTR pMechanismStruct = NULL_PTR; 
   CK_ULONG ulSignedDataLen; 

   SME_SETUP("CSM_Pkcs11::SMTI_Sign"); 

   if (pDigest == NULL) 
    pHashValue = &tmpDigestBuf; 
   else 
    pHashValue = pDigest; 

   // Make sure the hash buffer is not empty. 
   if (pHashValue->Length() == 0) 
      status = SMTI_DigestData(pDataIn, pHashValue); 

   pDigOID = GetPrefDigest(); 

   if (status == SM_NO_ERROR) 
   { 
      // Retrieve preferred DigestEncryption oid. 
      if ((pSigOID = GetPrefDigestEncryption()) != NULL) 
      { 
         // Use retrieve oid to access a PKCS11 corresponding mechanism. 
         if ((pMechanismStruct = GetMechanismStruct(pSigOID)) == NULL_PTR) 
            status = SM_PKCS11_UNSUPPORTED_ALG; 
      } 
      else 
         status = SM_PKCS11_UNSUPPORTED_ALG; 

      if (status == SM_NO_ERROR) 
      { 

                if (    *pSigOID == sha_1WithRSAEncryption || 
                                *pDigOID == sha_1WithRSAEncryption || 
                                *pSigOID == sha_1WithRSAEncryption_ALT || 
                                (*pSigOID == AsnOid("1.2.840.113549.1.2") && *pDigOID == sha_1) || 
                                (*pSigOID == rsaEncryption  && *pDigOID == sha_1)) 
                { 

                        // If this is RSA then we need to encrypt the digest and alg info for the signature 
                         
                        rsaDigestInfo.digestAlgorithm.algorithm = sha_1; 
                        CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm); 
                        rsaDigestInfo.digest.Set(pHashValue->Access(), pHashValue->Length()); 
                        ENCODE_BUF(&rsaDigestInfo,pTempBuf); 
                
                } else if (     *pSigOID == md5WithRSAEncryption || 
                                        *pDigOID == md5WithRSAEncryption || 
                                        (*pSigOID == rsa && *pDigOID == md5) || 
                                        (*pSigOID == AsnOid("1.2.840.113549.1.2") && *pDigOID == md5) || 
                                        (*pSigOID == rsaEncryption  && *pDigOID == md5)) 
                { 
 
                        // If this is RSA then we need to encrypt the digest and alg info for the signature 
 
                        rsaDigestInfo.digestAlgorithm.algorithm = md5; 
                        CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm); 
                        rsaDigestInfo.digest.Set(pHashValue->Access(), pHashValue->Length()); 
                        ENCODE_BUF(&rsaDigestInfo,pTempBuf); 
                } else { 
                        pTempBuf = new CSM_Buffer ( *pHashValue ); 
                } 

                // NOTE : Some mechanisms require parameters before the Sign 
                //        function can be called.  Currently (11.30.00) the only 
                //        sigining mechanisms supported by this CTIL are CKM_DSA 
                //        and CKM_RSA which do not require parameters. 

                if ((status = Sign(m_hSession, pMechanismStruct, m_hPrivateKey, 
                                                        (CK_BYTE_PTR) pTempBuf->Access(), pTempBuf->Length(), 
                                                        pEncryptedDigest, ulSignedDataLen)) != SM_NO_ERROR) 
                        SME_THROW(status, "C_Sign failed.", NULL); 

                pEncryptedDigest->SetLength((size_t) ulSignedDataLen); 

                // Perform unique computations for the mechansims that 
                // require them. 
                if ((*pMechanismStruct).mechanism == CKM_DSA) 
                { 
                
                        CSM_DSASignatureValue sigValue; 
                        sigValue.SetRS(pEncryptedDigest->Get()); 
                        sigValue.Encode(pEncryptedDigest); 
                } 
      
          } 

   } 

   if (pSigOID) 
      delete pSigOID; 
   if (pMechanismStruct) 
      free (pMechanismStruct); 
   if ( pTempBuf ) 
           delete pTempBuf; 
   if ( pDigOID ) 
           delete pDigOID; 

   SME_FINISH 
      SME_CATCH_SETUP 
      if (pSigOID) 
         delete pSigOID; 
          if ( pTempBuf ) 
                 delete pTempBuf; 
      if (pMechanismStruct) 
         free (pMechanismStruct); 
          if ( pDigOID ) 
                  delete pDigOID; 
   SME_CATCH_FINISH 

   return status; 
} 



//
//
SM_RET_VAL CSM_Pkcs11::SMTI_DigestData(CSM_Buffer *pDataIn, // input
                                       CSM_Buffer *pDigestOut) // output
{
   SM_RET_VAL status = SM_NO_ERROR;
   AsnOid *pDigestOid = NULL;
   
   CK_MECHANISM_PTR pMechanismStruct = NULL_PTR;
   CK_ULONG ulDigestLen;

   SME_SETUP("CSM_Pkcs11::SMTI_DigestData");

 
   if ((pDigestOid = GetPrefDigest()) != NULL)
   {
      if ((pMechanismStruct = GetMechanismStruct(pDigestOid)) == NULL_PTR)
         status = SM_PKCS11_UNSUPPORTED_ALG;
   }
   else
      status = SM_PKCS11_UNSUPPORTED_ALG;

   if (status == SM_NO_ERROR)
   {
      CK_ULONG ulDataLen = (CK_ULONG) pDataIn->Length();

      if ((status = Digest(m_hSession, pMechanismStruct,
                           (CK_BYTE_PTR) pDataIn->Access(), ulDataLen, 
                           pDigestOut, ulDigestLen)) != SM_NO_ERROR)
         SME_THROW(status, "C_Digest failed.", NULL);

      pDigestOut->SetLength((size_t) ulDigestLen);
   }

   if (pMechanismStruct)
      free (pMechanismStruct);
   if (pDigestOid)
      delete pDigestOid;

   SME_FINISH
   SME_CATCH_SETUP
      if (pDigestOid)
         delete pDigestOid;
      if (pMechanismStruct)
         free (pMechanismStruct);
   SME_CATCH_FINISH

   return status;
}

//
//
SM_RET_VAL CSM_Pkcs11::SMTI_Verify(CSM_Buffer *pSignerPublicKey,
                           CSM_AlgVDA *pDigestAlg,
                           CSM_AlgVDA *pSignatureAlg,
                           CSM_Buffer *pData,
                           CSM_Buffer *pSignature)
{
   SM_RET_VAL status = SM_NO_ERROR;

   AsnOid *pSigOid = NULL;
   CK_ATTRIBUTE_PTR pKeyTemplate = NULL_PTR;
   CK_BYTE_PTR pByteSignature = NULL_PTR;
   CK_MECHANISM_PTR pMechanismStruct = NULL_PTR;
   
   CSM_Buffer *pDigestOut = new CSM_Buffer();

   SME_SETUP("CSM_Pkcs11::SMTI_Verify");

   if (pDigestAlg)
      status = CSM_BaseTokenInterface::SMTI_DigestData(pData, pDigestOut, pDigestAlg->algorithm);
   else
      status = SMTI_DigestData(pData, pDigestOut);

   if (status == SM_NO_ERROR)
   {
      pSigOid = pSignatureAlg->GetId();

      if (*pSigOid == sha_1WithRSAEncryption || 
          *pSigOid == sha_1WithRSAEncryption_ALT || 
          *pSigOid == AsnOid("1.2.840.113549.1.2") ||
          *pSigOid == rsaEncryption ||
          *pSigOid == md5WithRSAEncryption ||
          *pSigOid == AsnOid("1.3.14.3.2.3") || //md5WithRSAEncryptionOIW ||
          *pSigOid == sha_1WithRSAEncryption_ALT)   // id-OIW-secsig-algorithm-sha1WithRSASig
          *pSigOid = rsaEncryption;
      else if (*pSigOid == id_dsa_with_sha1 || 
               *pSigOid == id_OIW_secsig_algorithm_dsa)
               *pSigOid = id_dsa;

      // Find signing mechanism using the Oid associated to the 
      // signature algorithm passed into this method.
      if ((pMechanismStruct = GetMechanismStruct(pSigOid)) == NULL_PTR)
         status = SM_PKCS11_UNSUPPORTED_ALG;

      if (status == SM_NO_ERROR)
      {
         CK_OBJECT_HANDLE hKey;

         CK_ULONG ulAttributeCount;
         CK_ULONG ulSignatureLen;

         AsnInt bigIntStr;
         unsigned char *ptmpPubKey;
         unsigned int length;
         CSM_DSAParams tmpDSAParams;
         RSAPublicKey SnaccRSAPublicKey;
         CK_BYTE_PTR pModulus = NULL_PTR;
         CK_ULONG ulModulusLen;
         CK_BYTE_PTR pExponent = NULL_PTR;
         CK_ULONG ulExponentLen;
         CK_BBOOL bFalse=false;
         char *pID="blah";
         CK_ULONG ulModulusBits;
         char *pStartDate="20000101";
         char *pEndDate="20060101";

         CK_BYTE_PTR p = NULL_PTR;
         CK_BYTE_PTR q = NULL_PTR;
         CK_BYTE_PTR g = NULL_PTR;
         CK_BBOOL isToken;
         CK_BBOOL canVerify;
         CK_OBJECT_CLASS keyClass;
         CK_KEY_TYPE keyType;

         if ((*pMechanismStruct).mechanism == CKM_DSA)
         {
            CSM_Buffer *pSignatureAlgParams = NULL;

            // Extract parameters from alg so a pkcs11 Object key
            // can be generated to Digest.
            if ((pSignatureAlgParams = pSignatureAlg->GetParams()) == NULL)
               SME_THROW(SM_PKCS11_VERIFY_ERROR, 
                                 "Unable to GetParams from signature Alg.", NULL);

            tmpDSAParams.Decode(pSignatureAlgParams);

            p = (CK_BYTE_PTR) tmpDSAParams.P;
            q = (CK_BYTE_PTR) tmpDSAParams.Q;
            g = (CK_BYTE_PTR) tmpDSAParams.G;

            keyClass = CKO_PUBLIC_KEY;
            keyType = CKK_DSA;
            CK_CHAR label[] = "A DSA public key object";
            CK_BYTE myId[] = {255};

            // Extract PublicKey value            
            //bigIntStr.Decode(pSignerPublicKey);
            DECODE_BUF(&bigIntStr, pSignerPublicKey);
            bigIntStr.getPadded(ptmpPubKey, length, 128);

            CK_ATTRIBUTE keyTemplate [] = {
               {CKA_CLASS, &keyClass, sizeof(keyClass)},
               {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
               {CKA_LABEL, label, sizeof(label) - 1},
               {CKA_PRIME, p, 128},
               {CKA_SUBPRIME, q, 20},
               {CKA_BASE, g, 128},
               {CKA_VALUE, ptmpPubKey, length},
               {CKA_ID, myId, sizeof(myId)}
            };

            // Divide keyTemplate size by the size of each attribute so
            // we can determine how many attributes were defined
            ulAttributeCount = sizeof(keyTemplate)   / sizeof(CK_ATTRIBUTE);      

            pKeyTemplate = (CK_ATTRIBUTE_PTR) malloc(sizeof(keyTemplate));
            memcpy(pKeyTemplate, keyTemplate, sizeof(keyTemplate));

            CSM_DSASignatureValue dsaSigValue(pSignature);
                  
            pByteSignature = (CK_BYTE_PTR)  dsaSigValue.GetRS();
            ulSignatureLen = 40; //(CK_ULONG) strlen((const char *) pByteSignature);
            /*   CK_BYTE_PTR pByteSignature = (CK_BYTE_PTR) pSignature->Access();
               CK_ULONG ulSignatureLen = (CK_ULONG) pSignature->Length();*/

            if (pSignatureAlgParams)
               delete pSignatureAlgParams;
         }
         else if ((*pMechanismStruct).mechanism == CKM_RSA_PKCS ||
                  (*pMechanismStruct).mechanism == CKM_RSA_9796)
         {
            keyClass = CKO_PUBLIC_KEY;
            keyType = CKK_RSA;

            if ((status = DecodeRSAPublicKey(pSignerPublicKey, pModulus, ulModulusLen,
                                       pExponent, ulExponentLen)) != SM_NO_ERROR)
               SME_THROW(-1, "Error decoding RSA Public Key.", NULL);

            isToken = true;
            canVerify = true;

            CK_ATTRIBUTE keyTemplate [] = {
               {CKA_CLASS, &keyClass, sizeof(keyClass)},
               {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
               {CKA_VERIFY, &canVerify, sizeof(canVerify)},
               {CKA_MODULUS, pModulus, ulModulusLen},
               {CKA_PUBLIC_EXPONENT, pExponent, ulExponentLen}
            };

            // Divide keyTemplate size by the size of each attribute so
            // we can determine how many attributes were defined
            ulAttributeCount = sizeof(keyTemplate)   / sizeof(CK_ATTRIBUTE);      

            pKeyTemplate = (CK_ATTRIBUTE_PTR) malloc(sizeof(keyTemplate));
            memcpy(pKeyTemplate, keyTemplate, sizeof(keyTemplate));

            // Copy signature value into Pkcs11 byte array.
            pByteSignature = (CK_BYTE_PTR) pSignature->Get();
            ulSignatureLen = pSignature->Length();
         }

         if (pKeyTemplate == NULL_PTR)
            SME_THROW(SM_PKCS11_UNSUPPORTED_ALG, 
                              "Algorithm not supported by Pkcs11 CTIL.", NULL);

         // Create verify key object in token
         if ((status = CreateObject(m_hSession, pKeyTemplate, 
                                        ulAttributeCount, hKey)) != SM_NO_ERROR)
         {
           if (ulModulusLen & 0x01) // CHECK to see if preceeded by '0'
           {                        //  (RWC;specifically, this was necessary for 
                                    //   the GemPlus PKCS11 use).
                ulModulusBits = (ulModulusLen-1)*8;
                CK_ATTRIBUTE keyTemplate2 [] = {
                   {CKA_CLASS, &keyClass, sizeof(keyClass)},
                   {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
                   {CKA_TOKEN, &bFalse, sizeof(bFalse)},
                   //{CKA_VERIFY, &canVerify, sizeof(canVerify)},
                   //{CKA_VERIFY_RECOVER, &bFalse, sizeof(bFalse)},
                   {CKA_WRAP, &canVerify, sizeof(bFalse)},
                   {CKA_ENCRYPT, &canVerify, sizeof(bFalse)},
                   //{CKA_LOCAL, &canVerify, sizeof(canVerify)},
                   {CKA_MODIFIABLE, &canVerify, sizeof(canVerify)},
                   //{CKA_DERIVE, &bFalse, sizeof(bFalse)},
                   //{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
                   //INVALID;{CKA_EXTRACTABLE, &canVerify, sizeof(canVerify)},
                   //{CKA_ID, pID, strlen(pID)+1},
                   {CKA_LABEL, pID, strlen(pID)+1},
                   //{CKA_MODULUS_BITS, &ulModulusBits, 4},
                   //DOES NOT WORK;{CKA_START_DATE, pStartDate, sizeof(pStartDate)},
                   //DOES NOT WORK;{CKA_END_DATE, pEndDate, sizeof(pEndDate)},
                   //{CKA_SUBJECT, pID, strlen(pID)+1},
                   {CKA_MODULUS, (pModulus+1), ulModulusLen-1},
                   {CKA_PUBLIC_EXPONENT, pExponent, ulExponentLen}
                };
                ulAttributeCount = sizeof(keyTemplate2)   / sizeof(CK_ATTRIBUTE);      
                free(pKeyTemplate);
                pKeyTemplate = (CK_ATTRIBUTE_PTR) malloc(sizeof(keyTemplate2));
                memcpy(pKeyTemplate, keyTemplate2, sizeof(keyTemplate2));
           }
           if ((status = CreateObject(m_hSession, pKeyTemplate, 
                               ulAttributeCount, hKey)) != SM_NO_ERROR)
           {
              SME_THROW(status, "CreateObject failed.", NULL);
           }        // END IF CreateObject, 2nd time
         }          // END IF CreateObject, 1st time

         CK_ULONG ulDigestLen = (CK_ULONG) pDigestOut->Length();

         if ((status = Verify(m_hSession, pMechanismStruct, hKey, 
                              (CK_BYTE_PTR) pDigestOut->Access(), ulDigestLen, 
                              pByteSignature, ulSignatureLen)) != SM_NO_ERROR)
         {          //RWC;NOTE: ANOTHER nasty integration issue with various vendors
                    //  AND application use of flags.  Some set CKF_VERIFY on the
                    //  CKM_RSA_PKCS mechanism, some set it ONLY on CKM_MD5_RSA_PKCS
                    //  or CKM_SHA1_RSA_PKCS.  This means we must check both!!!
             CK_MECHANISM_PTR pMechanismStruct2 = NULL_PTR;
             if (*pSigOid == rsaEncryption && pDigestAlg->algorithm == sha_1)
                 *pSigOid = sha_1WithRSAEncryption; // FOR mechanism lookup only.
             if (*pSigOid == rsaEncryption && pDigestAlg->algorithm == md5)
                 *pSigOid = md5WithRSAEncryption;
             delete pSigOid;
             pSigOid = pSignatureAlg->GetId();  // re-align with actual signature.
             if ((pMechanismStruct2 = GetMechanismStruct(pSigOid)) != NULL_PTR &&
                ((*pMechanismStruct2).mechanism == CKM_MD5_RSA_PKCS ||
                 (*pMechanismStruct2).mechanism == CKM_SHA1_RSA_PKCS))
             {              // TRY AGAIN...
                 if ((status = Verify(m_hSession, pMechanismStruct2, hKey, 
                              (CK_BYTE_PTR) pDigestOut->Access(), ulDigestLen, 
                              pByteSignature, ulSignatureLen)) != SM_NO_ERROR)
                 {
                 }   // END IF Verify, 2nd cut
             }      // END IF pMechanismStruct2
             if (status != 0)
             {
                     //RWC;TEST, attempt verify with internal card public key...
                   CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
                   CK_ULONG ulAttributeCount;
                   CK_OBJECT_HANDLE_PTR phObject = NULL_PTR;
                   CK_ULONG ulObjectCount;
                   CK_ATTRIBUTE findKeyTemplate[] = {
                      {CKA_CLASS, &keyClass, sizeof(keyClass)}
                      /*{CKA_SUBJECT, m_pSubject, m_subjectLen},            
                      {CKA_ID, m_pId, m_idLen},                      
                      {CKA_LABEL, m_pLabel, m_labelLen}*/
                   };
                   ulAttributeCount = sizeof(findKeyTemplate) / sizeof (CK_ATTRIBUTE);
                  if ((status = FindObjects(m_hSession,
                                            findKeyTemplate,
                                            ulAttributeCount,
                                            1,  // COUNT to find...
                                            ulObjectCount,
                                            phObject)) == SM_NO_ERROR)
                  {
                        if (ulObjectCount == 1)
                        {
                         if ((status = Verify(m_hSession, pMechanismStruct, *phObject, 
                                      (CK_BYTE_PTR) pDigestOut->Access(), ulDigestLen, 
                                      pByteSignature, ulSignatureLen)) != SM_NO_ERROR)
                                SME_THROW(status, "Verify 3 failed.", NULL);
                        }
                  }
                  if (phObject)
                  {
                     free (phObject);
                     phObject = NULL_PTR;
                  }
                  ulAttributeCount--;
             }      // END IF status
             if (status != 0)
             {
                    SME_THROW(status, "Verify failed.", NULL);
             }       // END IF status
         }           // END IF Verify, 1st cut
      }              // END IF GetMechanismStruct(...)
   }                 // END IF SMTI_DigestData(...)

   if (pMechanismStruct)
      free (pMechanismStruct);
   if (pDigestOut)
      delete pDigestOut;
   if (pSigOid)
      delete pSigOid;
   if (pKeyTemplate)
      free (pKeyTemplate);
   if (pByteSignature)
      free (pByteSignature);

   SME_FINISH
   SME_CATCH_SETUP
      if (pMechanismStruct)
         free (pMechanismStruct);
      if (pDigestOut)
         delete pDigestOut;
      if (pSigOid)
         delete pSigOid;
      if (pKeyTemplate)
         free (pKeyTemplate);
      if (pByteSignature)
         free (pByteSignature);
   SME_CATCH_FINISH

   return status;
}
// Function: SMTI_Encrypt()
// Purpose : Encrypt pData 
//
SM_RET_VAL CSM_Pkcs11::SMTI_Encrypt(CSM_Buffer *pData, // input (data to be encrypted)
                           CSM_Buffer *pEncryptedData, // output
                           CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
                           CSM_Buffer *pMEK,           // In/output; may be specified.
                           CSM_Buffer *pIV)  // In, to avoid specific
{
   SM_RET_VAL status = SM_NO_ERROR;
   int blockLength;
   int keyLength = 0;
   bool deleteFlag;

   CSM_Buffer *pTmpData = new CSM_Buffer;
   AsnOid *pPrefContentEncryptOid = NULL;
   Skipjack_Parm   skipjackParams;

   CK_ATTRIBUTE_PTR pKeyTemplate = NULL_PTR;
   CK_MECHANISM_PTR pEncryptMechanism = NULL_PTR;
   CK_MECHANISM_PTR pKeyGenMechanism = NULL_PTR;

   SME_SETUP("CSM_Pkcs11::SMTI_Encrypt()");

   // check incoming parameters
   if ((pData == NULL) || (pEncryptedData == NULL) ||
       (pParameters == NULL) || (pMEK == NULL))
      SME_THROW(SM_PKCS11_MISSING_PARAM, NULL, NULL);

   if ((pPrefContentEncryptOid = GetPrefContentEncryption()) != NULL)
   {
      char *tmpString = pPrefContentEncryptOid->GetChar();
      // Match encryption oid with Pkcs11 mechanism supported by token.
      if ((pEncryptMechanism = GetMechanismStruct(pPrefContentEncryptOid)) == NULL)
         status = SM_PKCS11_UNSUPPORTED_ALG;
   }
   else
      status = SM_PKCS11_UNSUPPORTED_ALG;

   if (status == SM_NO_ERROR)
   {
      bool skipjackFlag;   // This flag will be used for IV processing.

      CK_KEY_TYPE keyType;
      CK_OBJECT_CLASS objClass;
      CK_ULONG ulDataLen;
      CK_ULONG ulEncryptedDataLen;
      CK_ULONG ulKeyAttributeCount;

      // Make local copy in case some padding is needed.
      *pTmpData = *pData;

      // sib if any token supports something other than skipjack then this code must be updated
      // to support it
      // ex:  if rsa encryption is allowed then this must be changed to support rsa encryption
      // might need to be added here
      if ((*pEncryptMechanism).mechanism == CKM_SKIPJACK_CBC64)
      {
         skipjackFlag = true;

         // Pad incoming data. All CBC64 algorithms should be
         // padded.
         //
         GeneratePad( *pTmpData, SM_PKCS11_CBC64_PADDING);

         blockLength = SM_PKCS11_SKIPJACK_IV_LEN + 
                                 strlen(SM_PKCS11_SKIPJACK_CONST_STRING);
         keyLength = 12;      // always 12 bytes 

         objClass = CKO_SECRET_KEY;
         keyType = CKK_SKIPJACK;
         CK_CHAR label[] = "SKIPJACK_KEY";

         CK_MECHANISM keyGenMechanism = {CKM_SKIPJACK_KEY_GEN, NULL_PTR, 0 };

         pKeyGenMechanism = (CK_MECHANISM_PTR) malloc (sizeof(keyGenMechanism));
         memcpy(pKeyGenMechanism, &keyGenMechanism, sizeof(keyGenMechanism));

         CK_ATTRIBUTE keyTemplate[] = {
            {CKA_CLASS, &objClass, sizeof(objClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_LABEL, label, sizeof(label)}
         };

         ulKeyAttributeCount = sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE);

         pKeyTemplate = (CK_ATTRIBUTE_PTR) malloc (sizeof(keyTemplate));
         memcpy(pKeyTemplate, keyTemplate, sizeof(keyTemplate));
      }
      else
         status = SM_PKCS11_UNSUPPORTED_ALG;

      if (status == SM_NO_ERROR)
      {
         CK_OBJECT_HANDLE hMEK;

         // generate the MEK ONLY if not provided.
         if (!pMEK->Length())
         {
            if ((status = GenerateKey(m_hSession, pKeyGenMechanism,
                                      pKeyTemplate, ulKeyAttributeCount,
                                                          &hMEK)) != SM_NO_ERROR)
               SME_THROW(status, "GenerateKey failed.", NULL);

            // Store MEK key handle in CSM_Buffer so the handle can
            // be accessed by the keyWrapping instance.
            // NOTE : This key handle will ONLY be valid if the instance
            //        doing the WrapKey shares the session with the instance
            //        that performed the Encrypt
            pMEK->Set((char *) &hMEK, sizeof(CK_OBJECT_HANDLE));
         }
         else         
         {
            // NOTE : THIS SECTION OF THE CODE HAS NOT BEEN TESTED (8/16/00)

            // Create Pkcs11 object using passed-in MEK
            CK_BYTE_PTR pMEKString = NULL_PTR;

            // Adjust incomming MEK to proper length.
            {
               if (pMEK->Length() < (unsigned int) keyLength)
               {
                  CSM_Buffer tmpBuf((size_t) keyLength);

                  memcpy((char *)tmpBuf.Access(), pMEK->Access(), pMEK->Length());

                  SME(pMEK->ReSet(tmpBuf));
               }
            }

            pMEKString = (CK_BYTE_PTR) pMEK->Get();

            CK_ATTRIBUTE_PTR pKeyObjTemplate = NULL_PTR;

            // Add one more attribute to template so the key value (in pMEK)
            // can be included.
            ulKeyAttributeCount++;

            if ((pKeyObjTemplate = (CK_ATTRIBUTE_PTR) malloc 
                          (ulKeyAttributeCount * sizeof(CK_ATTRIBUTE))) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

            // Copy original template into new one.
            memcpy (pKeyTemplate, pKeyObjTemplate, 
                             ((ulKeyAttributeCount - 1) * sizeof(CK_ATTRIBUTE)));

            // Define attribute for MEK value.
            CK_ATTRIBUTE MEKValueTemplate[] = {
               {CKA_VALUE, pMEKString, pMEK->Length()}
            };

            // Create temporary pointer so we can use it to advance to
            // beyond the current last attribute and then copy the new
            // attribute to the end of the template.
            CK_ATTRIBUTE_PTR pTmp = pKeyObjTemplate;

            for (CK_ULONG i = 0; i < ulKeyAttributeCount; i++)
               pTmp++;

            memcpy (&MEKValueTemplate, pTmp, sizeof(CK_ATTRIBUTE));

            if ((status = CreateObject(m_hSession, 
                                       pKeyObjTemplate, ulKeyAttributeCount, 
                                                            hMEK)) != SM_NO_ERROR)
               SME_THROW(status, "C_CreateObject failed.", NULL);

            CSM_Buffer tmpBuf;

            tmpBuf.Set((char *) &hMEK, sizeof(CK_OBJECT_HANDLE));
            // Store MEK key handle in CSM_Buffer so the handle can
            // be accessed by the keyWrapping instance.
            SME(pMEK->ReSet(tmpBuf));

            if (pKeyObjTemplate)
               free (pKeyObjTemplate);
         }

         // NOTE: All mechanisms (supported by the current Pkcs11 version (2.1)) 
         //       that contain an IV parameter as input require just the pointer
         //       to the memory location that will hold the value.  The IV value
         //       will be generated by the token during encryption.  This IV must
         //       then be extracted by the application so it can be used
         //       during decryption.

         if (pIV == NULL || !pIV->Length())
         {
            if (pIV == NULL)
            {
               deleteFlag = true;
               pIV = new CSM_Buffer;
            }

            // Include as a mechanism parameter.
            (*pEncryptMechanism).pParameter = (CK_BYTE_PTR) malloc (blockLength);
            (*pEncryptMechanism).ulParameterLen = (CK_ULONG) blockLength;
         }
         else
         {
            // NOTE : THIS CODE HAS NOT BEEN EXCERCISED because currently NONE 
            //        of the mechanisms supported by Pkcs11 (Version 2.1) take
            //        a previously generated IV value.

            // Use passed-in IV
            (*pEncryptMechanism).pParameter = (CK_BYTE_PTR) pIV->Get();
            (*pEncryptMechanism).ulParameterLen = (CK_ULONG) pIV->Length();
         }

         ulDataLen = (CK_ULONG) pTmpData->Length();

         if ((status = Encrypt(m_hSession, pEncryptMechanism, hMEK, 
                           (CK_BYTE_PTR) pTmpData->Access(), ulDataLen, 
                           pEncryptedData, ulEncryptedDataLen)) != SM_NO_ERROR)
            SME_THROW(status, "C_Encrypt failed", NULL);

         pEncryptedData->SetLength((size_t) ulEncryptedDataLen);

         // Load parameters
         if (skipjackFlag)
         {
            char *pTmp = NULL;

            if (strncmp((char *) (*pEncryptMechanism).pParameter, 
                           SM_PKCS11_SKIPJACK_CONST_STRING,
                              strlen(SM_PKCS11_SKIPJACK_CONST_STRING)) == 0)
            {
               pTmp = (char *) (*pEncryptMechanism).pParameter;

               // Advance pointer to the begining of the IV value (pass the 
               // constant string that CI_GenerateIV includes).
               pTmp = pTmp + (sizeof(char) * strlen(SM_PKCS11_SKIPJACK_CONST_STRING));
            }

            pIV->Set(pTmp, (*pEncryptMechanism).ulParameterLen - 
                                       strlen(SM_PKCS11_SKIPJACK_CONST_STRING));
         }

         CSM_Buffer *pLocalBuf = NULL;

         if ((pLocalBuf = new CSM_Buffer) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

         skipjackParams.initialization_vector.Set(pIV->Get(), pIV->Length());

         ENCODE_BUF( &skipjackParams, pLocalBuf);

         *pParameters = *pLocalBuf;

         delete pLocalBuf;
      }
   }

   if (deleteFlag)
      delete pIV;
   if (pPrefContentEncryptOid)
      delete pPrefContentEncryptOid;
   if (pTmpData)
      delete pTmpData;
   if (pEncryptMechanism)
      free (pEncryptMechanism);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
      // cleanup pMEK, IV, in, out (as necessary)
      // close these if open
      pData->Close();
      pEncryptedData->Close();
       if (deleteFlag)
          delete pIV;
       if (pPrefContentEncryptOid )
          delete pPrefContentEncryptOid ;
       if (pTmpData)
          delete pTmpData;
       if (pEncryptMechanism)
          free (pEncryptMechanism);
   SME_CATCH_FINISH

   return status;
}
void CSM_Pkcs11::GeneratePad(CSM_Buffer &data,
                               const int   padSize)
{
   char *pPadStr = NULL;
   int   padLength = 0;
   int   i = 0;

   SME_SETUP("CSM_Pkcs11::GeneratePad()");

   if (padSize < 1 || padSize > 8)
      SME_THROW(-1, "Invalid pad size", NULL);


   // If data is already on a padSize boundary pad
   // it with padSize number of bytes.
   //
   padLength = padSize - (data.Length() % padSize); 
   
   pPadStr = (char *) calloc(1, padLength+1);

   for (i=0; i < padLength; i++)
      pPadStr[i] = padLength; 

   data.Open(SM_FOPEN_APPEND);
   data.Write(&pPadStr[0], padLength); 
   data.Flush();
   data.Close();

   free(pPadStr);

   SME_FINISH_CATCH;
}
void CSM_Pkcs11::ExtractPad(CSM_Buffer &data)
{
   char padChar[2];
   long padLength;

   SME_SETUP("CSM_Pkcs11::ExtractPad()");

   // Determine pad size.
   data.Open(SM_FOPEN_READ);
   data.Seek(0, SEEK_END);
   data.cRead( &padChar[0], 1);
   data.Close();
   
   padLength = (long) padChar[0]; // convert to integer/long

   if (padLength < 1 || padLength > 8)
      SME_THROW(-1, "Invalid Padding", NULL);

   data.SetLength( data.Length() - padLength );

   SME_FINISH_CATCH;

}
// FUNCTION: SMTI_Decrypt()
//
// Purpose:  Decrypt pEncryptedData into pData
//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::SMTI_Decrypt(CSM_Buffer *pParameters,    // input, parameters for alg.
                           CSM_Buffer *pEncryptedData, // input (data to be decrypted)
                           CSM_Buffer *pMEK,           // input (MEK or special phrase)
                           CSM_Buffer *pData)         // output (decrypted data)
{
   SM_RET_VAL status = SM_NO_ERROR;

   Skipjack_Parm   skipjackParams;
   AsnOid *pPrefContentEncryptOid = NULL;

   CK_ULONG ulDataLen;
   CK_ULONG ulDecryptedDataLen;
   CK_MECHANISM_PTR pEncryptMechanism = NULL_PTR;

   SME_SETUP("CSM_Pkcs11::SMTI_Decrypt()");

   if (pEncryptedData == NULL || pParameters == NULL || 
                  pMEK == NULL || pData == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing Parameters", NULL);

   CK_OBJECT_HANDLE hDecryptKey;
   char * pTmphKey = NULL;

   {
      SME(pTmphKey = pMEK->Get());
      hDecryptKey = (CK_OBJECT_HANDLE) *pTmphKey;
   }

   if ((pPrefContentEncryptOid = GetPrefContentEncryption()) != NULL)
   {
      // Match encryption oid with Pkcs11 mechanism supported by token.
      if ((pEncryptMechanism = GetMechanismStruct(pPrefContentEncryptOid)) == NULL)
         status = SM_PKCS11_UNSUPPORTED_ALG;
   }
   else
      status = SM_PKCS11_UNSUPPORTED_ALG;

   if (status == SM_NO_ERROR)
   {
      if ((*pEncryptMechanism).mechanism == CKM_SKIPJACK_CBC64)
      {
         // Decode parmeters to get IV value used during Encryption.
         DECODE_BUF(&skipjackParams, pParameters);

         CK_BYTE iv[24];

         memcpy (iv, SM_PKCS11_SKIPJACK_CONST_STRING, 
                                 strlen(SM_PKCS11_SKIPJACK_CONST_STRING));

         memcpy(&iv[strlen(SM_PKCS11_SKIPJACK_CONST_STRING)], 
                           skipjackParams.initialization_vector.c_str(),
                           SM_PKCS11_SKIPJACK_IV_LEN);

         (*pEncryptMechanism).pParameter = iv;

         (*pEncryptMechanism).ulParameterLen = 
                              skipjackParams.initialization_vector.Len() +
                              strlen(SM_PKCS11_SKIPJACK_CONST_STRING);
      }
      else if ((*pEncryptMechanism).mechanism == CKM_RSA_PKCS ||
               (*pEncryptMechanism).mechanism == CKM_RSA_9796)
      {
         // RSA does not require special processing.
         (*pEncryptMechanism).pParameter = NULL;
         (*pEncryptMechanism).ulParameterLen = 0;
      }
      else
         status = SM_PKCS11_UNSUPPORTED_ALG;

      if (status == SM_NO_ERROR)
      {
         ulDataLen = pEncryptedData->Length();

         if ((status = Decrypt(m_hSession, pEncryptMechanism, hDecryptKey,
                               (CK_BYTE_PTR) pEncryptedData->Access(), ulDataLen, 
                               pData, ulDecryptedDataLen)) != SM_NO_ERROR)
            SME_THROW(status, "Decrypt failed.", NULL);

         pData->SetLength((size_t) ulDecryptedDataLen);

         // Pad incoming data. All CBC64 algorithms should be
         // padded to an 8 byte (64 bit) boundary.
         //
         ExtractPad(*pData);
      }
   }

   if (pEncryptMechanism)
      free (pEncryptMechanism);

   SME_FINISH
   SME_CATCH_SETUP
      if (pEncryptMechanism)
         free (pEncryptMechanism);
   SME_CATCH_FINISH

   return (status);
}
bool CSM_Pkcs11::SMTI_IsKeyAgreement()
{
   SM_RET_VAL status = SM_NO_ERROR;
   bool isKeyAgreement = false;

   SME_SETUP("CSM_Pkcs11::SMTI_IsKeyAgreement");

   CK_ULONG ulAttributeCount;
   CK_BBOOL isDerive;

   // The derive attribute indicates if the key supports keyAgreement.
   CK_ATTRIBUTE keyTemplate [] = {
      {CKA_DERIVE, &isDerive, sizeof(isDerive)}
   };

   // Devide the size of the template by the size of CK_ATTRIBUTE to determine
   // how many attributes were defined.
   ulAttributeCount = sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE);

   if ((status = GetAttributeValue(m_hSession, m_hPrivateKey,
                                   keyTemplate, ulAttributeCount)) == SM_NO_ERROR)
   {
      if (isDerive)
         isKeyAgreement = true;
   }

   SME_FINISH_CATCH;

   return isKeyAgreement;
}
SM_RET_VAL CSM_Pkcs11::SMTI_Random(CSM_Buffer *pSeed, // input  
                        CSM_Buffer *pRandom,          // input/output
                        SM_SIZE_T ILength)            // input
{
   SM_RET_VAL status = SM_NO_ERROR;
   CK_BYTE_PTR pRandomData = NULL_PTR;
   CK_ULONG ulRandomLen = (CK_ULONG) ILength;

   SME_SETUP("CSM_Pkcs11::SMTI_Random");

   CK_RV rv;

   if (pRandom == NULL)
      SME_THROW(SM_PKCS11_MISSING_PARAM, NULL, NULL);

   pRandomData = (CK_BYTE_PTR) malloc(ulRandomLen);

   if ((rv = GenerateRandom(m_hSession, pRandomData, ulRandomLen) == CKR_OK))
   {
      pRandom->Set((char *) pRandomData, (SM_SIZE_T) ulRandomLen);
   }
   else
   {
      status = -1;
   }

   SME_FINISH_CATCH;

   return status;
}
//////////////////////////////////////////////////////////////////////////////////
// This method only currently supports Fortezza as of 01-29-01
//////////////////////////////////////////////////////////////////////////////////
CSM_Buffer * CSM_Pkcs11::SMTI_GenerateKeyWrapIV(long &lkekLength, 
                                                CSM_AlgVDA *pWrapAlg)
{
   CSM_Buffer *pIV = NULL; // returned

   SME_SETUP("CSM_Pkcs11::SMTI_GenerateKeyWrapIV()");

   if (pWrapAlg != NULL)
      pWrapAlg->algorithm = id_fortezzaWrap80;

   lkekLength = -1;

   return pIV;

   SME_FINISH_CATCH;
}
///////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recipient, public key
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pData, // input, Content Encryption Key to be encrypted
            CSM_Buffer *pEMEK, // output, encrypted Content Encryption Key
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
            CSM_Buffer *pSubjKeyId) // output
{
   SM_RET_VAL status = SM_NO_ERROR;
   AsnOid *pKeyEncryptionOid;

   CK_MECHANISM_PTR pKeyMechanism = NULL_PTR;
   CK_ATTRIBUTE_PTR pPublicKeyTemplate = NULL_PTR;
   CK_ATTRIBUTE_PTR pMEKTemplate = NULL_PTR;

   CK_BYTE_PTR pWrappedKey = NULL_PTR;
   CK_BYTE_PTR pPublicKey = NULL_PTR;
   CK_BYTE_PTR pOutCipher = NULL_PTR;
   CK_BYTE_PTR pMEK = NULL_PTR;

   CK_ULONG ulPubKeyAttributeCount = 0;
   CK_ULONG ulMEKAttributeCount = 0;
   CK_ULONG publicKeyLength = 0;
   CK_ULONG MEKLength = 0;
   CK_ULONG ulWrappedKeyLen = 0;

   SME_SETUP("CSM_Pkcs11::SMTI_GenerateEMEK");

   // check incoming parameters
   if ((pRecipient == NULL) || (pEMEK == NULL) || (pData == NULL))
      SME_THROW(SM_PKCS11_MISSING_PARAM, NULL, NULL);

   if ((pKeyEncryptionOid = GetPrefKeyEncryption()) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   pPublicKey = (CK_BYTE_PTR) pRecipient->Access();
   publicKeyLength = (CK_ULONG) pRecipient->Length();

   pMEK = (CK_BYTE_PTR) pData->Access();
   MEKLength = (CK_ULONG) pData->Length();
   
   CK_OBJECT_CLASS SecretKeyClass;
   CK_OBJECT_CLASS PublicKeyClass;
   CK_KEY_TYPE keyType;
   CK_KEY_TYPE RSAkeyType;
   CK_OBJECT_HANDLE hPublicKey = SM_PKCS11_INVALID_HANDLE;
   CK_OBJECT_HANDLE hMEK = SM_PKCS11_INVALID_HANDLE;

   if ((pKeyMechanism = GetMechanismStruct(pKeyEncryptionOid)) == NULL)
      status = SM_PKCS11_UNSUPPORTED_ALG;

   CK_BYTE_PTR pModulus = NULL_PTR;
   CK_ULONG ulModulusLen = 0;
   CK_BYTE_PTR pExponent = NULL_PTR;
   CK_ULONG ulExponentLen = 0;
   CK_BBOOL canWrap;
   CK_BBOOL canEncrypt;
   CK_BBOOL canDecrypt;

   if ((*pKeyMechanism).mechanism == CKM_RSA_PKCS ||
       (*pKeyMechanism).mechanism == CKM_RSA_9796)
   {
      if ((status = DecodeRSAPublicKey(pRecipient, pModulus, ulModulusLen,
                                          pExponent, ulExponentLen)) == SM_NO_ERROR)
      {
         // Create object for recipients public key
         PublicKeyClass = CKO_PUBLIC_KEY;
         RSAkeyType = CKK_RSA;
         canWrap = TRUE;

         CK_ATTRIBUTE publicKeyTemplate[] = {
            {CKA_CLASS, &PublicKeyClass, sizeof(PublicKeyClass)},
            {CKA_KEY_TYPE, &RSAkeyType, sizeof(RSAkeyType)},
            {CKA_WRAP, &canWrap, sizeof(canWrap)},
            {CKA_MODULUS, pModulus, ulModulusLen},
            {CKA_PUBLIC_EXPONENT, pExponent, ulExponentLen}
         };

         ulPubKeyAttributeCount = sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE);

         pPublicKeyTemplate = (CK_ATTRIBUTE_PTR) malloc(sizeof(publicKeyTemplate));

         memcpy(pPublicKeyTemplate, publicKeyTemplate, sizeof(publicKeyTemplate));

         // Create Object for ContentEncryption key (MEK - MessageEncryptionKey)
         SecretKeyClass = CKO_SECRET_KEY;
         AsnOid *pSNACCPrefContent = this->GetPrefContentEncryption();
         keyType = 0;
         if (pSNACCPrefContent)
         {
             if (*pSNACCPrefContent == des_ede3_cbc)
                 keyType = CKK_DES3;
             else if (*pSNACCPrefContent == rc2_cbc)
                 keyType = CKK_RC2;
         }      // END if deferred OID.
         if (keyType == 0)  // THEN take a best-guest approace, since our API
                               //  does not provide this detail; it happens to be
                               //  necessary here (probably due to size).
         {
             if (MEKLength == 24)
                 keyType = CKK_DES3;
             else if (MEKLength == 5)
                 keyType = CKK_RC2;

         }      // END IF keyType == 0
         canEncrypt = TRUE;
         canDecrypt = TRUE;

         CK_ATTRIBUTE mekTemplate [] = {
            {CKA_CLASS, &SecretKeyClass, sizeof(SecretKeyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_VALUE, pMEK, MEKLength},
            {CKA_ENCRYPT, &canEncrypt, sizeof(canEncrypt)},
            {CKA_DECRYPT, &canDecrypt, sizeof(canDecrypt)}
         };

         ulMEKAttributeCount = sizeof(mekTemplate) / sizeof(CK_ATTRIBUTE);

         pMEKTemplate = (CK_ATTRIBUTE_PTR) malloc(sizeof(mekTemplate));

         memcpy(pMEKTemplate, mekTemplate, sizeof(mekTemplate));
      }
   }
   else
      SME_THROW(SM_PKCS11_UNSUPPORTED_ALG, "Key Encryption Alg not supported", NULL);

   if ((status = CreateObject(m_hSession, pPublicKeyTemplate, 
                              ulPubKeyAttributeCount, hPublicKey)) != SM_NO_ERROR)
   {
       if (ulModulusLen & 0x01) // CHECK to see if preceeded by '0'
       {                        //  (RWC;specifically, this was necessary for 
                                //   the DataKey PKCS11 use).
         CK_ATTRIBUTE publicKeyTemplate2[] = {
            {CKA_CLASS, &PublicKeyClass, sizeof(PublicKeyClass)},
            {CKA_KEY_TYPE, &RSAkeyType, sizeof(RSAkeyType)},
            {CKA_WRAP, &canWrap, sizeof(canWrap)},
            {CKA_MODULUS, (pModulus+1), ulModulusLen-1},
            {CKA_PUBLIC_EXPONENT, pExponent, ulExponentLen}
         };
         memcpy(pPublicKeyTemplate, publicKeyTemplate2, sizeof(publicKeyTemplate2));
         if ((status = CreateObject(m_hSession, pPublicKeyTemplate, 
                          ulPubKeyAttributeCount, hPublicKey)) != SM_NO_ERROR)
         {
            SME_THROW(status, "CreateObject failed for public key.", NULL);
         }  // END if CreateObject failure.
       }    // END IF preceding '0', try removing it.
   }        // END if CreateObject failure.

   if ((status = CreateObject(m_hSession, pMEKTemplate, 
                                 ulMEKAttributeCount, hMEK)) != SM_NO_ERROR)
      SME_THROW(status, "CreateObject for MEK.", NULL);

   if ((status = WrapKey(m_hSession, pKeyMechanism, hPublicKey,
                   hMEK, pWrappedKey, &ulWrappedKeyLen)) != SM_NO_ERROR)
      SME_THROW(status, "WrapKey failed.", NULL);

   pEMEK->Open(SM_FOPEN_WRITE);
   pEMEK->Write((char *) pWrappedKey, ulWrappedKeyLen);
   pEMEK->Close();

   if (pKeyMechanism)
      free (pKeyMechanism);
   if (pWrappedKey)
      free(pWrappedKey);
   if (pPublicKeyTemplate)
      free (pPublicKeyTemplate);
   if (pMEKTemplate)
      free (pMEKTemplate);

   SME_FINISH
   SME_CATCH_SETUP
      if (pKeyMechanism)
         free (pKeyMechanism);
      if (pWrappedKey)
         free(pWrappedKey);
      if (pPublicKeyTemplate)
         free (pPublicKeyTemplate);
      if (pMEKTemplate)
         free (pMEKTemplate);      
   SME_CATCH_FINISH

   return(status);
}
//////////////////////////////////////////////////////////////////////////
// FUNCTION: SMTI_GenerateKeyAgreement()
// 
// NOTE: KEA Public Keys are not encoded within the
//       SubjectPublicKeyInfo BITSTRING like DSA Public
//       Keys.
// 
// Fortezza CTIL ignores the following parameters for now:
//    pParameters
//    pEncryptionOID
//    pbufKeyAgree
//    lKekLength
//    
SM_RET_VAL CSM_Pkcs11::SMTI_GenerateKeyAgreement(
            CSM_Buffer *pPubKey,    // input, Y of recip
            CSM_Buffer *pParameters,   // IN,OUT may be passed in for shared
                                       //  use OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM,          // input/output may be passed in for shared
                                       //   use.  UserKeyMaterial (random number).
            CSM_Buffer *pIV,           // input/output may be passed in for
                                       //   shared use. Initialization vector,
                                       //   part of DH params.
            AsnOid *pEncryptionOID,   // IN, specified encryption of key,
                                       //   used here in key generation,
                                       //   but alg not implemented.
            CSM_Buffer *pbufKeyAgree,  // output, encryption key for this recip.
            long lKekLength)           // Input, for OtherInfo load.
                                       // alg encoding by app.
{
   SM_RET_VAL status = SM_NO_ERROR;

   AsnOid *poidKeyEncrypt = NULL;

   CK_ULONG ulKeyAttributeCount;
   CK_ATTRIBUTE_PTR pKeyAttrTemplate;
   CK_BYTE randomA[SM_PKCS11_CI_RA_SIZE];
   CK_BYTE randomB[SM_PKCS11_CI_RB_SIZE];
   CK_KEA_DERIVE_PARAMS params;
   CK_MECHANISM_PTR pKeyMechanism;

   SME_SETUP("CSM_Pkcs11::SMTI_GenerateKeyAgreement()");

   if (pPubKey == NULL || pUKM == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing Parameter", NULL);

   if ((poidKeyEncrypt = GetPrefKeyEncryption()) != NULL)
   {
      if ((pKeyMechanism = GetMechanismStruct(poidKeyEncrypt)) == NULL)
         status = SM_PKCS11_UNSUPPORTED_ALG;
   }
   else
      status = SM_PKCS11_UNSUPPORTED_ALG;

   if (status == SM_NO_ERROR)
   {
      if ((*pKeyMechanism).mechanism == CKM_KEA_KEY_DERIVE)
      {
         memset(randomB, 0, SM_PKCS11_CI_RB_SIZE);
         randomB[SM_PKCS11_CI_RB_SIZE - 1] = 1;

         params.isSender = TRUE;
         params.ulRandomLen = SM_PKCS11_CI_RA_SIZE;    
         params.pRandomA = randomA;
         params.pRandomB = randomB;
         params.ulPublicDataLen = (CK_ULONG) pPubKey->Length();
         params.pPublicData = (CK_BYTE_PTR) pPubKey->Get();

         (*pKeyMechanism).pParameter = &params;
         (*pKeyMechanism).ulParameterLen = sizeof(CK_KEA_DERIVE_PARAMS);

         CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
         CK_KEY_TYPE keyType = CKK_SKIPJACK;
         CK_CHAR label[] = "SKIPJACK TEK secret object";
         CK_BBOOL canWrap = TRUE;
         CK_BBOOL canUnwrap = TRUE;

         CK_ATTRIBUTE keyAttrTemplate [] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_LABEL, label, sizeof(label)},
            {CKA_WRAP, &canWrap, sizeof(canWrap)},
            {CKA_UNWRAP, &canUnwrap, sizeof(canUnwrap)}
         };

         ulKeyAttributeCount = sizeof(keyAttrTemplate) / sizeof(CK_ATTRIBUTE);

         pKeyAttrTemplate = (CK_ATTRIBUTE_PTR) malloc (sizeof(keyAttrTemplate));
         memcpy(pKeyAttrTemplate, &keyAttrTemplate, sizeof(keyAttrTemplate));
      }
      else
         status = SM_PKCS11_UNSUPPORTED_ALG;

      if (status == SM_NO_ERROR)
      {
         CK_OBJECT_HANDLE hPairWiseKey;

         if ((status = DeriveKey(m_hSession, pKeyMechanism, m_hPrivateKey,
                             pKeyAttrTemplate, ulKeyAttributeCount, 
                                                   &hPairWiseKey)) != SM_NO_ERROR)
            SME_THROW(status, "DeriveKey failed.", NULL);

         // Store the pairWise key handle in pubKeyAgree so it can 
         // be used in the wrapping operation.  The handle should NOT
         // be stored in the instance because their is no gurantee that
         // the same instance will be used for wrapping.
         // NOTE : The key handle stored in pbufKeyAgree will ONLY be useful
         //        when SMTI_GenerateKeyWrap is performed by an instance that 
         //        shares the SAME SESSION with the instance that is performing 
         //        the keyAgreement.
         pbufKeyAgree->Set((char *) &hPairWiseKey, sizeof(CK_OBJECT_HANDLE));
         pUKM->Set((char *) params.pRandomA,SM_PKCS11_CI_RA_SIZE);
      }
   }

   if (poidKeyEncrypt)
      delete poidKeyEncrypt;
   if (pKeyAttrTemplate)
      free (pKeyAttrTemplate);
   if (pKeyMechanism)
      free (pKeyMechanism);

   SME_FINISH
      SME_CATCH_SETUP
      if (poidKeyEncrypt)
         delete poidKeyEncrypt;
      if (pKeyAttrTemplate)
         free (pKeyAttrTemplate);
      if (pKeyMechanism)
         free (pKeyMechanism);
   SME_CATCH_FINISH;

   return status;
}   
///////////////////////////////////////////////////////////////////////////////////
// This method currently only supports SKIPJACK as of 1-29-01
///////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::SMTI_GenerateKeyWrap(CSM_Buffer *pData,
                                            CSM_Buffer *pEncryptedData,
                                            CSM_Buffer *pParameters,
                                            CSM_Buffer *pMEK,
                                            CSM_Buffer *pIV)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::SMTI_GenerateKeyWrap");

   if ((pEncryptedData == NULL) || (pData == NULL))
      SME_THROW(SM_MISSING_PARAM, "Missing required parameter", NULL);

   CK_OBJECT_HANDLE hMEK;
   CK_OBJECT_HANDLE hPairWiseKey;
   char * pTmphKey = NULL;

   // Get key handle stored in pData buffer.
   if ((pTmphKey = pData->Get()) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   hMEK = (CK_OBJECT_HANDLE) *pTmphKey;

   delete pTmphKey;

   // Getkey handle stored in pMEK
   SME(pTmphKey = pMEK->Get());
   hPairWiseKey = (CK_OBJECT_HANDLE) *pTmphKey;
   
   CK_BYTE_PTR pWrappedKey = NULL_PTR;
   CK_ULONG ulWrappedKeyLen;

   CK_MECHANISM wrapMechanism [] = {
         {CKM_SKIPJACK_WRAP, NULL_PTR, 0}
   };

   if ((status = WrapKey(m_hSession, wrapMechanism, hPairWiseKey,
                           hMEK, pWrappedKey, &ulWrappedKeyLen)) != SM_NO_ERROR)
      SME_THROW(status, "WrapKey failed.", NULL);

   pEncryptedData->Set((char *) pWrappedKey, ulWrappedKeyLen);
   
   SME_FINISH_CATCH;

   return status;
}
// FUNCTION: SMTI_ExtractKeyAgreement()
//
// PURPOSE: Reveal the recipient's KEK.
//
SM_RET_VAL CSM_Pkcs11::SMTI_ExtractKeyAgreement(
            CSM_Buffer *pOrigPubKey,   // input, Y of originator
            CSM_Buffer *pUKM,          // input/output may be passed in for shared use.
                                       //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,     // input/output may be passed in for
                                       //   shared use. Initialization vector,
                                       //   part of DH params.
            AsnOid *pEncryptionOID,   // IN, specified encryption of key,
                                       //   used here in key generation,
                                       //   but alg not implemented.
            CSM_Buffer *pbufKeyAgree,  // output, encryption key for this recip.
            long lKekLength)           // Output, from OtherInfo load.
{
   SM_RET_VAL status = SM_NO_ERROR;
   AsnOid *poidKeyEncrypt = NULL;

   CK_ATTRIBUTE_PTR pAttribute = NULL_PTR;
   CK_ULONG ulAttributeCount;
   CK_OBJECT_HANDLE hKey;
   CK_KEA_DERIVE_PARAMS params;
   CK_MECHANISM_PTR pKeyMechanism = NULL_PTR;

   SME_SETUP("CSM_Pkcs11::SMTI_ExtractKeyAgreement()");

   CK_BYTE randomA[SM_PKCS11_CI_RA_SIZE];
   CK_BYTE randomB[SM_PKCS11_CI_RB_SIZE];

   // check for required parameters
   if (pOrigPubKey == NULL || pUKM == NULL || pbufKeyAgree == NULL)
      SME_THROW(SM_MISSING_PARAM,"Missing Required Parameter", NULL);

   // Check UKM (Ra)
   if (pUKM->Length() != sizeof(randomA))
      SME_THROW(-1, "Invalid UKM (randomA) Length", NULL);

   if ((poidKeyEncrypt = GetPrefKeyEncryption()) != NULL)
   {
      if ((pKeyMechanism = GetMechanismStruct(poidKeyEncrypt)) == NULL)
         status = SM_PKCS11_UNSUPPORTED_ALG;
   }
   else
      status = SM_PKCS11_UNSUPPORTED_ALG;

   if (status == SM_NO_ERROR)
   {
      memcpy(randomA, pUKM->Access(), sizeof(randomA));

      memset(randomB, 0, sizeof(randomB));
      randomB[sizeof(randomB) - 1] = 1;

      if ((*pKeyMechanism).mechanism == CKM_KEA_KEY_DERIVE)
      {
         params.isSender = FALSE;    
         params.ulRandomLen = SM_PKCS11_CI_RA_SIZE;
         params.pRandomA = randomA;
         params.pRandomB = randomB;
         params.ulPublicDataLen = (CK_ULONG) pOrigPubKey->Length();
         params.pPublicData = (CK_BYTE_PTR) pOrigPubKey->Get();

         (*pKeyMechanism).pParameter = &params;
         (*pKeyMechanism).ulParameterLen = sizeof(CK_KEA_DERIVE_PARAMS);

         CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
         CK_KEY_TYPE keyType = CKK_SKIPJACK;
         CK_CHAR label[] = "SKIPJACK TEK secret object";
         CK_BBOOL canUnwrap = TRUE;
         CK_BBOOL canWrap = TRUE;

         CK_ATTRIBUTE keyAttrTemplate [] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_LABEL, label, sizeof(label)},
            {CKA_WRAP, &canWrap, sizeof(canWrap)},     // LTM; This might 
                                                         // need to be changed to succesfully decrypt
            {CKA_UNWRAP, &canUnwrap, sizeof(canUnwrap)}
         };

         ulAttributeCount = sizeof(keyAttrTemplate) / sizeof(CK_ATTRIBUTE);

         pAttribute = (CK_ATTRIBUTE_PTR) malloc (sizeof(keyAttrTemplate));
         memcpy(pAttribute, keyAttrTemplate, sizeof(keyAttrTemplate));
      }
      else
         status = SM_PKCS11_UNSUPPORTED_ALG;

      if (status == SM_NO_ERROR)
      {
         if ((status = DeriveKey(m_hSession, pKeyMechanism, m_hPrivateKey,
                           pAttribute, ulAttributeCount, &hKey)) != SM_NO_ERROR)
            SME_THROW(status, "DeriveKey failed.", NULL);

         pbufKeyAgree->Set((char *) &hKey, sizeof(CK_OBJECT_HANDLE));
      }
   }

   if (pKeyMechanism)
      free (pKeyMechanism);
   if (pAttribute)
      free (pAttribute);
   if (poidKeyEncrypt)
      delete poidKeyEncrypt;

   SME_FINISH
      SME_CATCH_SETUP
      if (pKeyMechanism)
         free (pKeyMechanism);
      if (pAttribute)
         free (pAttribute);
      if (poidKeyEncrypt)
         delete poidKeyEncrypt;
   SME_CATCH_FINISH

   return status;
}
// FUNCTION: SMTI_ExtractKeyWrap()
//
// PURPOSE: Unwrap MEK with KEK.  SMTI_ExtractKeyAgreement must
//          be called first.
//

SM_RET_VAL CSM_Pkcs11::SMTI_ExtractKeyWrap(
                        CSM_Buffer *pData,          // Output
                        CSM_Buffer *pEncryptedData, // input
                        CSM_Buffer *pParameters,    // Comes in NULL 7.28.00.
                        CSM_Buffer *pTEK,           // In
                        CSM_Buffer *pIV)            // Comes in NULL 7.28.00
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11::SMTI_ExtractKeyWrap()");

   if (pData == NULL || pEncryptedData == NULL || pTEK == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing required parameter", NULL);

   CK_OBJECT_HANDLE hUnwrappingKey;
   char * pTmphKey = NULL;

   {
      SME(pTmphKey = pTEK->Get());
      hUnwrappingKey = (CK_OBJECT_HANDLE) *pTmphKey;
   }

   CK_BYTE_PTR pWrappedKey = (CK_BYTE_PTR) pEncryptedData->Get();
   CK_ULONG ulWrappedKeyLen = pEncryptedData->Length();

   CK_ULONG ulKeyAttributeCount;
   CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
   CK_KEY_TYPE keyType = CKK_SKIPJACK;
   CK_CHAR label[] = "SKIPJACK MEK";
   CK_BBOOL canDecrypt = TRUE;
   CK_BBOOL canEncrypt = TRUE;

   CK_ATTRIBUTE keyTemplate [] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
      {CKA_DECRYPT, &canDecrypt, sizeof(canDecrypt)},
  //    {CKA_ENCRYPT, &canEncrypt, sizeof(canEncrypt)},
      {CKA_LABEL, label, (sizeof(label) - 1)}
   };

   ulKeyAttributeCount = sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE);

   CK_MECHANISM mechanism = {CKM_SKIPJACK_WRAP, NULL_PTR, 0};
   CK_OBJECT_HANDLE hKey = -1;

   if ((status = UnwrapKey(m_hSession, &mechanism, hUnwrappingKey,
                        pWrappedKey, ulWrappedKeyLen, 
                        keyTemplate, ulKeyAttributeCount, &hKey)) != SM_NO_ERROR)
      SME_THROW(status, "UnwrapKey failed.", NULL);

   pData->Set((char *) &hKey, sizeof(CK_OBJECT_HANDLE));

   return status;

   SME_FINISH_CATCH;
}   // END CSM_Pkcs11::SMTI_ExtractKeyWrap(...)

//
//
SM_RET_VAL CSM_Pkcs11::SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output (MEK or special phrase)
{
   SM_RET_VAL status = SM_NO_ERROR;
   AsnOid *pKeyEncryptionOid = NULL;
   CK_MECHANISM_PTR pMechanism = NULL_PTR;
   CK_ATTRIBUTE_PTR pKeyTemplate = NULL_PTR;

   SME_SETUP("CSM_Pkcs11::SMTI_ExtractMEK");

   // check incoming parameters
   if ((pEMEK == NULL) || (pMEK == NULL))
      SME_THROW(SM_PKCS11_MISSING_PARAM, NULL, NULL);

   CK_BYTE_PTR pWrappedKey = (CK_BYTE_PTR) pEMEK->Access();
   CK_ULONG ulWrappedKeyLen = pEMEK->Length();

   if ((pKeyEncryptionOid = GetPrefKeyEncryption()) != NULL)
   {
      if ((pMechanism = GetMechanismStruct(pKeyEncryptionOid)) == NULL)
      {
         //RWC;JUST TRY RSA directly; GemPlus sometimes causes a problem here
         //RWC;  for some reason, depending on the CA that loaded the smart card.
        delete pKeyEncryptionOid;
        pKeyEncryptionOid = new AsnOid(rsaEncryption);
        if ((pMechanism = GetMechanismStruct(pKeyEncryptionOid)) == NULL)
        {
           status = SM_PKCS11_UNSUPPORTED_ALG;
        }   // END IF GetMechanismStruct(RSA)
      }     // END IF GetMechanismStruct(...)
   }
   else
      status = SM_PKCS11_UNSUPPORTED_ALG;

   CK_ULONG ulKeyAttributeCount;
   CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
   CK_KEY_TYPE keyType;
   CK_BBOOL canDecrypt = TRUE;

   if (status == SM_NO_ERROR)
   {
      if ((*pMechanism).mechanism == CKM_RSA_PKCS ||
          (*pMechanism).mechanism == CKM_RSA_9796)
      {
         AsnOid *pSNACCPrefContent = this->GetPrefContentEncryption();
         keyType = 0;
         if (pSNACCPrefContent)
         {
             if (*pSNACCPrefContent == des_ede3_cbc)
                 keyType = CKK_DES3;
             else if (*pSNACCPrefContent == rc2_cbc)
                 keyType = CKK_RC2;
             else // TAKE A GUESS...
             {    //RWC; NECESSARY due to odd GemPlus behaviour.  Our SMTI 
                  //RWC;  interface is inadequate in this case since PKCS11 is
                  //RWC;  sensitive to the actual content encryption used.
                 if (pEMEK->Length() >= 128)
                     keyType = CKK_DES3;
                 else
                     keyType = CKK_RC2;
             }
             delete pSNACCPrefContent;
         }      // END if deferred OID.
         else
             keyType = CKK_RC2;
         CK_CHAR label[] = "RSA MEK";

         CK_ATTRIBUTE keyTemplate [] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
            {CKA_DECRYPT, &canDecrypt, sizeof(canDecrypt)},
            {CKA_LABEL, label, (sizeof(label) - 1)}
         };

         ulKeyAttributeCount = sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE);

         pKeyTemplate = (CK_ATTRIBUTE_PTR) malloc(sizeof(keyTemplate));
         memcpy(pKeyTemplate, keyTemplate, sizeof(keyTemplate));
      }
      else
         status = SM_PKCS11_UNSUPPORTED_ALG;
   }

   CK_OBJECT_HANDLE hKey = -1;

   if (status == SM_NO_ERROR)
   {
      // Decrypt the emek using private key handle previously obtained
      // when the current instance was created.
      if ((status = UnwrapKey(m_hSession, pMechanism, m_hPrivateKey,
                           pWrappedKey, ulWrappedKeyLen, 
                           pKeyTemplate, ulKeyAttributeCount, &hKey)) != SM_NO_ERROR)
         SME_THROW(status, "UnwrapKey failed.", NULL);


      // Try retrieving the key value so we can send it back to the calling 
      // module.  If the token does not allow the key value to be retrieve,
      // send back the key handle. (NOTE: The key handle will only be useful
      // if the Decryption will be performed by the same token that unwrapped
      // the key.)
      CK_ATTRIBUTE unwrappedKey [] = {
         {CKA_VALUE, NULL_PTR, 0}
      };

      if ((status = 
               GetAttributeValue(m_hSession, hKey, unwrappedKey, 1)) == SM_NO_ERROR)
      {
         CK_BYTE_PTR pValue = NULL_PTR;

         if ((pValue = (CK_BYTE_PTR) malloc (unwrappedKey[0].ulValueLen)) == NULL_PTR)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

         CK_ULONG keyLen = unwrappedKey[0].ulValueLen;

         CK_ATTRIBUTE keyTemplate [] = {
            {CKA_VALUE, pValue, keyLen}
         };

         if ((status = 
               GetAttributeValue(m_hSession, hKey, keyTemplate, 1)) == SM_NO_ERROR)
            pMEK->Set((char *) pValue, keyLen);
         else
            // NOTE : This should NOT, happen since the first GetAttribute was
            // successful; but, if it does happen, instead of erroing out now, 
            // send the key handle back and let the calling module deal with any 
            // errors that might occur later.
            pMEK->Set((char *) &hKey, sizeof(CK_OBJECT_HANDLE));

         free (pValue);
      }
      else
      {
         // put the key handle into the MEK buffer.
         pMEK->Set((char *) &hKey, sizeof(CK_OBJECT_HANDLE));
      }
   }

   // cleanup
   if (pMechanism)
      free(pMechanism);
   if (pKeyTemplate)
      free(pKeyTemplate);

   SME_FINISH
   SME_CATCH_SETUP
      
      // put any local cleanup here
      if (pMechanism)
         free(pMechanism);
      if (pKeyTemplate)
         free(pKeyTemplate);

   SME_CATCH_FINISH

   return(status);
}   // END CSM_Pkcs11::SMTI_ExtractMEK(...)


//
//
SM_RET_VAL CSM_Pkcs11::SMTI_GetStatus() 
{

        SM_RET_VAL status = SM_NO_ERROR; 

        CK_SESSION_INFO sessionInfo; 

        SME_SETUP("CSM_Pkcs11::SMTI_GetStatus"); 

                CK_RV rv = sfl_c_getSessionInfo ( m_hSession, &sessionInfo ); 

                status = rv; 

        SME_FINISH 
        SME_CATCH_SETUP 
        SME_CATCH_FINISH 

        return status; 

}   // END CSM_Pkcs11::SMTI_GetStatus() 



_END_CERT_NAMESPACE

// EOF sm_pkcs11SMTI.cpp
