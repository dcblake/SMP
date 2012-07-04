#ifndef WIN32
#include <stream.h>
#endif
//#include <string.h>
//#include <strstrea.h>
#include "sm_pkcs11Free3.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;

extern "C" {
SM_RET_VAL SMPkcs11Free3Init(void *pCSMIME, int slotId, char *pUserPin, char *pDllName)
{
   CSM_CtilMgr *pUseCSMIME = (CSM_CtilMgr *) pCSMIME;

   SME_SETUP("SMPkcs11Free3Init()");

   // generate a new fortezza class
   // Call Pkcs11 CTIL contructor to load up pCSMIME
   // with instances.
   CSM_Pkcs11Free3 pkcs11(pUseCSMIME, (CK_SLOT_ID) slotId, pUserPin, pDllName);

   return SM_NO_ERROR;   
   
   SME_FINISH_CATCH;
}
} // end extern 'C'

// Initialization routines (Constructors) for C++
//
CSM_Pkcs11Free3::CSM_Pkcs11Free3()                    
{
   SME_SETUP("CSM_Pkcs11Free3::CSM_Pkcs11Free3()");

   Clear();

   SME_FINISH_CATCH;
}
// Initialization routines (Constructors) for C++
//
CSM_Pkcs11Free3::CSM_Pkcs11Free3(CSM_CtilMgr *pCSMIME, 
                       CK_SLOT_ID slotId,
                       char *pUserPin, 
                       char *pDllName)
{
   SME_SETUP("CSM_Pkcs11Free3::CSM_Pkcs11Free3");
 
   SM_RET_VAL status = SM_NO_ERROR;

   Clear();
      
   LoadDllFunctions(pDllName);

   SME(status = Initialize());

   if (pCSMIME == NULL || pUserPin == NULL)
      SME_THROW(SM_MISSING_PARAM,NULL, NULL);

   SME(CreateInstances(pCSMIME, pUserPin, slotId));

   SME_FINISH_CATCH;
}

//
//
CSM_Pkcs11Free3::CSM_Pkcs11Free3 (CSM_Buffer &Certificate, CSM_Buffer *pPrivateKey, 
                        char *pPin, CK_SLOT_ID slotId)
{
    SME_SETUP("CSM_Pkcs11Free3::CSM_Pkcs11Free3");

    SM_RET_VAL status = SM_NO_ERROR;

    Clear();

    if (pPin)           // Pin for access to the token
        SetPin(pPin);
   
    // Convert file name into memory.
    Certificate.ConvertFileToMemory();

    SME(SetCertificate(Certificate));

    status = Initialize();

    SME_FINISH_CATCH;
}
CSM_Pkcs11Free3::~CSM_Pkcs11Free3()
{
}
void CSM_Pkcs11Free3::Clear()
{

}
CSM_Pkcs11 * CSM_Pkcs11Free3::GetInstancePointer()
{
   CSM_Pkcs11Free3 *pPkcs11Free3 = NULL;
   
   SME_SETUP("CSM_Pkcs11Free3::GetInstancePointer");

   if ((pPkcs11Free3 = new CSM_Pkcs11Free3()) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME_FINISH_CATCH;

   return (CSM_Pkcs11 *) pPkcs11Free3;
}
void CSM_Pkcs11Free3::LoadExtraOids()
{
   CSM_AlgLstVDA *pdigestAlgID = NULL;
   CSM_AlgLstVDA *pdigestEncryptionAlgID = NULL;
   CSM_AlgLstVDA *pkeyEncryptionAlgID = NULL;
   CSM_AlgLstVDA *pcontentEncryptionAlgID = NULL;
   CSM_Pkcs11SlotLst::iterator itSlot;
   CSM_AlgLstVDA::iterator itAlg;

   CSM_Free3::BTIGetAlgIDs(&pdigestAlgID,
                           &pdigestEncryptionAlgID,
                           &pkeyEncryptionAlgID,
                           &pcontentEncryptionAlgID);

   for (itSlot =  m_pSlotList->begin();
        itSlot != m_pSlotList->end();
        ++itSlot)
   {
       for (itAlg = pdigestAlgID->begin();
            itAlg != pdigestAlgID->end();
            ++itAlg)
       {
          itSlot->SetDigestAlgLst((CSM_Alg *)&(*itAlg));
       }

       for (itAlg =  pcontentEncryptionAlgID->begin();
            itAlg != pcontentEncryptionAlgID->end();
            ++itAlg)
       {
          itSlot->SetContentEncryptionAlgLst((CSM_Alg *)&(*itAlg));
       }
   }        // END FOR each slot
}           // END CSM_Pkcs11Free3::LoadExtraOids()

//
//
SM_RET_VAL CSM_Pkcs11Free3::SMTI_DigestData(CSM_Buffer *pDataIn, // input
                                       CSM_Buffer *pDigestOut) // output
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_DigestData");

   if ((status = CSM_Pkcs11::SMTI_DigestData(pDataIn, pDigestOut)) != SM_NO_ERROR)
      status = CSM_Free3::SMTI_DigestData(pDataIn, pDigestOut);

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return status;
}
SM_RET_VAL CSM_Pkcs11Free3::SMTI_Sign(CSM_Buffer *pDataIn,
                                      CSM_Buffer *pEncryptedDigest,
                                      CSM_Buffer *pDigest)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_Sign");

   status =  CSM_Pkcs11::SMTI_Sign(pDataIn, pEncryptedDigest, pDigest);

   SME_FINISH
      SME_CATCH_SETUP
      SME_CATCH_FINISH

   return status;
}
SM_RET_VAL CSM_Pkcs11Free3::SMTI_Verify(CSM_Buffer *pSignerPublicKey,
                           CSM_AlgVDA *pDigestAlg,
                           CSM_AlgVDA *pSignatureAlg,
                           CSM_Buffer *pData,
                           CSM_Buffer *pSignature)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_Verify");

   if ((status = CSM_Pkcs11::SMTI_Verify(pSignerPublicKey, pDigestAlg,
                                pSignatureAlg, pData, pSignature)) != SM_NO_ERROR)
      status = CSM_Free3::SMTI_Verify(pSignerPublicKey, pDigestAlg, pSignatureAlg,
                                                         pData, pSignature);

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return status;
}
// Function: SMTI_Encrypt()
// Purpose : Encrypt pData 
//
SM_RET_VAL CSM_Pkcs11Free3::SMTI_Encrypt(CSM_Buffer *pData,          // input (data to be encrypted)
                           CSM_Buffer *pEncryptedData, // output
                           CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
                           CSM_Buffer *pMEK,           // In/output; may be specified.
                           CSM_Buffer *pIV)  // In, to avoid specific
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_Encrypt()");

   if ((status = CSM_Pkcs11::SMTI_Encrypt(pData, pEncryptedData, 
                                      pParameters, pMEK, pIV)) != SM_NO_ERROR)
      status = CSM_Free3::SMTI_Encrypt(pData, pEncryptedData, 
                                                pParameters, pMEK, pIV);

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return status;
}
// FUNCTION: SMTI_Decrypt()
//
// Purpose:  Decrypt pEncryptedData into pData
//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11Free3::SMTI_Decrypt(CSM_Buffer *pParameters,    // input, parameters for alg.
                           CSM_Buffer *pEncryptedData, // input (data to be decrypted)
                           CSM_Buffer *pMEK,           // input (MEK or special phrase)
                           CSM_Buffer *pData)         // output (decrypted data)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_Decrypt()");

   if ((status = CSM_Pkcs11::SMTI_Decrypt(pParameters, pEncryptedData, 
                                                   pMEK, pData)) != SM_NO_ERROR)
   {
      AsnOid *pPrefContentEncryptOid = CSM_Pkcs11::GetPrefContentEncryption();
      CSM_Free3::BTISetPreferredCSInstAlgs(NULL, NULL, NULL, pPrefContentEncryptOid);
      status = CSM_Free3::SMTI_Decrypt(pParameters, pEncryptedData, pMEK, pData);
   }

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return status;
}
bool CSM_Pkcs11Free3::SMTI_IsKeyAgreement()
{
   bool isKeyAgreement = false;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_IsKeyAgreement");

   isKeyAgreement = CSM_Pkcs11::SMTI_IsKeyAgreement();

   SME_FINISH_CATCH;

   return isKeyAgreement;
}
SM_RET_VAL CSM_Pkcs11Free3::SMTI_Random(CSM_Buffer *pSeed, // input  
                        CSM_Buffer *pRandom,          // input/output
                        SM_SIZE_T ILength)            // input
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_Random");

   status = CSM_Free3::SMTI_Random(pSeed, pRandom, ILength);

   SME_FINISH_CATCH;

   return status;
}
CSM_Buffer * CSM_Pkcs11Free3::SMTI_GenerateKeyWrapIV(long &lkekLength, 
                                                  CSM_AlgVDA *pWrapAlg)
{
   CSM_Buffer *pIV = NULL; // returned

   SME_SETUP("CSM_Pkcs11Free3::SMTI_GenerateKeyWrapIV()");

   pIV = CSM_Pkcs11::SMTI_GenerateKeyWrapIV(lkekLength, pWrapAlg);

   return pIV;

   SME_FINISH_CATCH;

}
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
SM_RET_VAL CSM_Pkcs11Free3::SMTI_GenerateKeyAgreement(
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

   SME_SETUP("CSM_Pkcs11Free3::SMTI_GenerateKeyAgreement()");

   status = CSM_Pkcs11::SMTI_GenerateKeyAgreement(pPubKey, pParameters, pUKM, pIV,
                                           pEncryptionOID, pbufKeyAgree, lKekLength);

   SME_FINISH
      SME_CATCH_SETUP
   SME_CATCH_FINISH;

   return status;
}   
SM_RET_VAL CSM_Pkcs11Free3::SMTI_GenerateKeyWrap(CSM_Buffer *pData,
                                            CSM_Buffer *pEncryptedData,
                                            CSM_Buffer *pParameters,
                                            CSM_Buffer *pMEK,
                                            CSM_Buffer *pIV)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_GenerateKeyWrap");

   status = CSM_Pkcs11::SMTI_GenerateKeyWrap(pData, pEncryptedData, 
                                                   pParameters, pMEK, pIV);

   SME_FINISH_CATCH;

   return status;
}
// FUNCTION: SMTI_ExtractKeyAgreement()
//
// PURPOSE: Reveal the recipient's KEK.
//
SM_RET_VAL CSM_Pkcs11Free3::SMTI_ExtractKeyAgreement(
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

   SME_SETUP("CSM_Pkcs11Free3::SMTI_ExtractKeyAgreement()");

   status = CSM_Pkcs11::SMTI_ExtractKeyAgreement(pOrigPubKey, pUKM, pbufferIV, 
                                              pEncryptionOID, pbufKeyAgree, lKekLength);

   SME_FINISH
      SME_CATCH_SETUP
   SME_CATCH_FINISH

   return status;
}
// FUNCTION: SMTI_ExtractKeyWrap()
//
// PURPOSE: Unwrap MEK with KEK.  SMTI_ExtractKeyAgreement must
//          be called first.
//

SM_RET_VAL CSM_Pkcs11Free3::SMTI_ExtractKeyWrap(
                        CSM_Buffer *pData,          // Output
                        CSM_Buffer *pEncryptedData, // input
                        CSM_Buffer *pParameters,    // Comes in NULL 7.28.00.
                        CSM_Buffer *pTEK,           // In
                        CSM_Buffer *pIV)            // Comes in NULL 7.28.00
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_ExtractKeyWrap()");

   status = CSM_Pkcs11::SMTI_ExtractKeyWrap(pData, pEncryptedData, 
                                                   pParameters, pTEK, pIV);

   return status;

   SME_FINISH_CATCH;
}
SM_RET_VAL CSM_Pkcs11Free3::SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output (MEK or special phrase)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_ExtractMEK");

   status = CSM_Pkcs11::SMTI_ExtractMEK(pOriginator, pParameters, 
                                                      pEMEK, pUKM, pMEK);

   SME_FINISH
   SME_CATCH_SETUP
      // put any local cleanup here
   SME_CATCH_FINISH

   return status;
}
SM_RET_VAL CSM_Pkcs11Free3::SMTI_GenerateEMEK(CSM_Buffer *pRecipient,
                                              CSM_Buffer *pParameters,
                                              CSM_Buffer *pMEK,
                                              CSM_Buffer *pEMEK,
                                              CSM_Buffer *pUKM,
                                              CSM_Buffer *pSubjKeyId)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_Pkcs11Free3::SMTI_GenerateEMEK");

   status = CSM_Pkcs11::SMTI_GenerateEMEK(pRecipient, pParameters, pMEK, pEMEK, 
                                                pUKM, pSubjKeyId);

   SME_FINISH
      SME_CATCH_SETUP
   SME_CATCH_FINISH

   return status;
}
CSM_Alg * CSM_Pkcs11Free3::DeriveMsgAlgFromCert(CSM_CertificateChoice &cert)
{
   CSM_Alg *pAlg = NULL;

   pAlg = CSM_Pkcs11::DeriveMsgAlgFromCert(cert);

   return pAlg;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef NO_DLL
#ifdef WIN32
extern "C" {
   long Make_argv(char *string, int *pargc, char ***pargv);

   SM_PKCS11FREE3DLL_API SM_RET_VAL DLLBuildTokenInterface(CSM_CtilMgr &Csmime,
      char *lpszBuildArgs)
   {
      SM_RET_VAL status = 0;
      int argc1 = 0;
      char **argv1;
      char ptr[30];

      memset(ptr, '\0', 30);
      for (int i = 0; i < (int)strlen("sm_Pkcs11Free3DLL"); i++)
         ptr[i] = toupper(lpszBuildArgs[i]);
      // Preliminary check that this request if for out library
      if (strncmp(ptr, "SM_PKCS11FREE3DLL", strlen("sm_Pkcs11Free3DLL")) == 0)
      {
         Make_argv(lpszBuildArgs, &argc1, &argv1);
         if (argc1 == 4)
         {
            // Pass char *pszAddressBook, int slot#, char *pUserPin, char * dllName
            SMPkcs11Free3Init(&Csmime, atoi(argv1[1]), argv1[2], argv1[3]);
         }
         else
         {
            status = -1;
         }
      }
      else
      {
         status = -1;
         std::cout << "DLLBuildTokenInterface failed!!!\n";
      }

      return(status);
   }

   SM_PKCS11FREE3DLL_API char * DLLGetId()
   {
      return (strdup("sm_Pkcs11Free3DLL"));
   }
}

// THE FOLLOWING MUST BE called ONLY once in an application/DLL in order
// for force generation of the CSM_ListC code for the specified classes.
#endif
#endif

_END_CERT_NAMESPACE

// EOF sm_pkcs11Free3.cpp
