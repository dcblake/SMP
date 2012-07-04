#ifndef NO_SCCS_ID
static char SccsId[ ] = "@(#) sm_fort.cpp 1.32 09/26/00 07:06:58"; 
#endif


#ifndef WIN32
#include <stream.h>
#endif
#include <string.h>
#include "sm_fort.h"
//_BEGIN_CERT_NAMESPACE
using namespace CERT;
using namespace SNACC;

// static global which SHOULD only be accessible to this module.
static int socketCount = -1;

// Fortezza ID format: SLOT#:CERT LABEL
#define FORT_ID_SIZE 30


//
// This is the Initialization routine for C
//
extern "C" {
SM_FORTEZZADLL SM_RET_VAL SMFortezzaInit(void *pCSMIME, char *pszPin,
                         long nSocket)
{
   CSM_CtilMgr/*CSMIME*/ *pUseCSMIME = (CSM_CtilMgr *) pCSMIME;

   SME_SETUP("SMFortezzaInit()");

   // generate a new fortezza class
   // Call Fortezza CTIL contructor to load up pCSMIME
   // with instanaces.
   //
   CSM_Fortezza fortezza(pUseCSMIME, pszPin, nSocket);

   return SM_NO_ERROR;   
   
   SME_FINISH_CATCH;
}
} // end extern 'C'

CSM_Fortezza::CSM_Fortezza()
{
   InitMemberVariables();
}

void CSM_Fortezza::InitMemberVariables(void)
{
   long error = 0;
   m_nSignerIndex = -1;
   m_nEncryptorIndex = -1;
   bWeInitialized = true;
   mp_cardInfo = new CSM_FortezzaCardInfo; 

   SME_SETUP("CSM_Fortezza::InitMemberVariables");

   if (socketCount == -1)
   {
      if((error = CI_Initialize(&socketCount)) != CI_OK)
      {
         SME_THROW(error, "CI_Initialize() failed!", NULL);
      }
   }

   SME_FINISH_CATCH
}

// Initialization routines (Constructors) for C++
//

CSM_Fortezza::CSM_Fortezza(CSM_CtilMgr/*CSMIME*/ *pCSMIME, 
                           char   *pszPin,
                           long    nSocket)
{
   SME_SETUP("CSM_Fortezza::CSM_Fortezza");
 
   InitMemberVariables();


   if (pCSMIME == NULL)
      SME_THROW(SM_MISSING_PARAM,"pCSMIME is NULL", NULL);

   if (SetSocket(nSocket) != 0)
      SME_THROW(-1, "No Card Present", NULL);

   if (Login(pszPin) != 0)
      SME_THROW(-1, "Invalid Pin", NULL);

   SME(CreateInstances(pCSMIME));

   SME_FINISH_CATCH;
}

CSM_Fortezza::CSM_Fortezza(CSM_CtilMgr/*CSMIME*/ *pCSMIME, 
                           long    nSocket, 
                           long    slot)
{
   SME_SETUP("CSM_Fortezza::CSM_Fortezza");
 
   socketCount = 0;     // FLAG to allow soft-login, not initialize.
   InitMemberVariables();
    bWeInitialized = false; // OVERRIDE default, since this incarnation
                            //  does not initialize.

   if (pCSMIME == NULL)
      SME_THROW(SM_MISSING_PARAM,"pCSMIME is NULL", NULL);

   if (SetSocketNoOpen(nSocket) != 0)
      SME_THROW(-1, "No Card Present", NULL);

   //if (Login(pszPin) != 0)
   //   SME_THROW(-1, "Invalid Pin", NULL);

   SME(CreateInstances(pCSMIME, slot));

   SME_FINISH_CATCH;
}
CSM_Fortezza::CSM_Fortezza(CSM_FortezzaCardInfo &o)
{
   InitMemberVariables();
   mp_cardInfo->Set(o);
}
CSM_CSInst * CSM_Fortezza::SelectInstance(CSM_CtilMgr/*CSMIME*/ *pCSMIME, long certIndex)
{
   CSM_CtilInstLst::iterator itInst;
   CSM_CSInst *pInstCS = NULL;
   long  idIndex = 0;
   char *pId;
   CSMIME *pCSMIME2=(CSMIME *)pCSMIME;  // TO load both lists: CTIL and CSInst.

   for (itInst =  pCSMIME2->m_pCSInsts->begin();
        itInst != pCSMIME2->m_pCSInsts->end();
        ++itInst)
   {
      pId = strdup((*itInst)->AccessID());
      pId[3] = NULL;
      idIndex = atol(pId);

      if (idIndex == certIndex)
         break;
   }

   if (itInst != pCSMIME2->m_pCSInsts->end())
      pInstCS = (CSM_CSInst *)(*itInst)->AccessTokenInterface()->AccessCSInst();

   return pInstCS;

}
int CSM_Fortezza::GetSocketCount(void)
{

   return socketCount;
}

long CSM_Fortezza::SetSocketNoOpen(int socket)
{
   return (mp_cardInfo->SetSocketNoOpen(socket));

}

long CSM_Fortezza::SetSocket(int socket)
{
   // Call CSM_FortezzaCardInfo constructor.  Call
   // CSM_FortezzaCardInfo->SetSocket().  If it fails
   // there there is not a valid Fortezza card in 
   // the specified socket.
   //

   return (mp_cardInfo->SetSocket(socket));

}

void CSM_Fortezza::SetDigestOids(void)
{
   AsnOid sha1Oid(sha_1);
   CSM_AlgLstVDA *pDigestAlgLst = new CSM_AlgLstVDA;
   CSM_AlgVDA *psha1Digest = &(*pDigestAlgLst->append());

   *psha1Digest = sha1Oid;

   BTISetAlgIDs(pDigestAlgLst, NULL,
                NULL, NULL);

   BTISetPreferredCSInstAlgs(&sha1Oid,
            NULL,
            NULL,
            NULL);
   delete pDigestAlgLst;
}

void CSM_Fortezza::SetDigestEncryptionOids(void)
{
  
   CSM_AlgLstVDA *pDigestEncryptionAlgLst = new CSM_AlgLstVDA;
   CSM_AlgVDA *pdsaDE = &(*pDigestEncryptionAlgLst->append());
   CSM_AlgVDA *pdsaWithSha1DE = &(*pDigestEncryptionAlgLst->append());

   pdsaWithSha1DE->algorithm = id_dsa_with_sha1;
   pdsaDE->algorithm = id_dsa;

   BTISetAlgIDs(NULL, pDigestEncryptionAlgLst, NULL, NULL);

   SNACC::AsnOid SNACCSignOid(id_dsa_with_sha1);
   BTISetPreferredCSInstAlgs(NULL, &SNACCSignOid, NULL, NULL);
   delete pDigestEncryptionAlgLst;
}

void CSM_Fortezza::SetContentEncryptionOids(void)
{
   CSM_AlgLstVDA *pContentEncryptionAlgLst = new CSM_AlgLstVDA;
   CSM_AlgVDA *pFortezzaWrapAlg = &(*pContentEncryptionAlgLst->append());
   CSM_AlgVDA *pskipJackContentEncryption = &(*pContentEncryptionAlgLst->append());

   pskipJackContentEncryption->algorithm = id_fortezzaConfidentialityAlgorithm;
   // PIERCE:  Ack!!  I don't like mixing Wrap algorithms and content
   // encryption algorithms.  Should add a fifth alg. type to BaseTokenInterface.
   //
   pFortezzaWrapAlg->algorithm = id_fortezzaWrap80;

   BTISetAlgIDs(NULL, NULL, NULL, pContentEncryptionAlgLst );
   SNACC::AsnOid SNACCContentOid(id_fortezzaConfidentialityAlgorithm);
   BTISetPreferredCSInstAlgs(NULL, NULL, NULL,  &SNACCContentOid);
   delete pContentEncryptionAlgLst;
}

void CSM_Fortezza::SetKeyEncryptionOids(void)
{
   CSM_AlgLstVDA *pKeyEncrytionAlgLst = new CSM_AlgLstVDA;
   CSM_AlgVDA *pkeyExchangeKeyEncryption = &(*pKeyEncrytionAlgLst->append());

   pkeyExchangeKeyEncryption->algorithm = id_keyExchangeAlgorithm;

   BTISetAlgIDs(NULL, NULL, pKeyEncrytionAlgLst, NULL);
   SNACC::AsnOid SNACCKeyExchangeOid(id_keyExchangeAlgorithm);
   BTISetPreferredCSInstAlgs(NULL, NULL, &SNACCKeyExchangeOid, NULL);
   delete pKeyEncrytionAlgLst;
}


CSM_Buffer * CSM_Fortezza::GetEncodedPublicKey(void)
{
   CSM_Buffer *pCertBuf = NULL;
   CSM_Buffer *pEncodedPubKey = NULL;
   CSM_CertificateChoice *pCertChoice = NULL;
   unsigned char cert[CI_CERT_SIZE];
   int error = 0;
 
   SME_SETUP("CSM_Fortezza:GetEncodedPublicKey()");

   error = CI_GetCertificate(m_nSignerIndex, cert);
   if (error != CI_OK)
   {
      SME_THROW(error, "CI_GetCertificate() failed!", NULL);
   }

   pCertBuf = new CSM_Buffer((char *) cert, CI_CERT_SIZE);
   pCertChoice = new CSM_CertificateChoice( *pCertBuf );
   pEncodedPubKey = pCertChoice->GetPublicKey();

   delete pCertBuf;
   delete pCertChoice;
   return pEncodedPubKey;

   SME_FINISH_CATCH;
}

CSM_Buffer * CSM_Fortezza::DecodePublicKey(CSM_Buffer *pEncodedPubKey )
{  
   CSM_Buffer        *pPubKey = new CSM_Buffer;
   AsnInt     *pSnaccBigIntStr = new AsnInt;
   unsigned char *ptr=NULL;
   unsigned int length=0;

   SME_SETUP("CSM_Fortezza::DecodePublicKey()");

   DECODE_BUF( pSnaccBigIntStr, pEncodedPubKey );
   length = pSnaccBigIntStr->length();
   if (length <= 65)    // Smaller key length.
       pSnaccBigIntStr->getPadded/*GetUnSignedBitExtendedData/ *Get*/( ptr, length, 64);
   else                                 // Larger key length
       pSnaccBigIntStr->getPadded/*GetUnSignedBitExtendedData/ *Get*/( ptr, length, 128);
   if (ptr)
     pPubKey->Set((char *)ptr, length);

   delete pSnaccBigIntStr;
   return pPubKey;

   SME_FINISH_CATCH;
}

// FUNCTION: SMTI_Sign()
//
// PURPOSE: To produce a digitial signature on the data pointed to by pData.
//
// INPUT DESCRIPTION:
//   Type/Class     Name             I/O    Description
//
//   CSM_Buffer *   pData             I     Binary or Ascii Data to be signed.
//   CSM_Buffer *   pEncryptedDigest  O     Signature Value
//   CSM_Buffer *   pDigest           O     Hash Value
//
SM_RET_VAL CSM_Fortezza::SMTI_Sign(CSM_Buffer *pData,
                                   CSM_Buffer *pEncryptedDigest,
                                   CSM_Buffer *pDigest)
{
   long             error = SM_NO_ERROR;
   CSM_Buffer      *pHashValue = NULL;
   CI_SIGNATURE     pSignature;
   CSM_FortDSAParams dsaParams;
   CSM_DSASignatureValue sigValue;
   
   SME_SETUP("CSM_Fortezza::SMTI_Sign");

   if (pData == NULL || pEncryptedDigest == NULL)
      SME_THROW(SM_MISSING_PARAM,"Missing required parameters", NULL);

   error = CI_Lock(CI_BLOCK_LOCK_FLAG);
   if (error != CI_OK)
      SME_THROW(error, "CI_Lock() failed.", NULL);
      
   pHashValue = pDigest;

   if (pHashValue->Length() == 0)
   {
     // Call SMTI_Digest() from CSM_Common to produce the hash value
     //

     SME(SMTI_DigestData(pData, pHashValue));   
   }

   // Set signer index
   //
   error = CI_SetPersonality(m_nSignerIndex);
   if (error != CI_OK)
      SME_THROW(error, "CI_SetPersonality() failed.", NULL);
  
   if ( (error =  CI_Sign( (unsigned char *) pHashValue->Access(), 
                           (unsigned char *) pSignature )) != CI_OK )
      SME_THROW(error, "CI_Sign() failed!", NULL);

   sigValue.SetRS( (char *) pSignature);
   sigValue.Encode(pEncryptedDigest);

   CI_Unlock();
   
   SME_FINISH_CATCH;

   return SM_NO_ERROR;
}

// THIS CODE THE EVENTUALLY BE REMOVED IT
// SHOULDN'T BE USED.  WE SHOULD FORCE THE CALLER TO PASS IN
// PARAMETERS.
//
SM_RET_VAL CSM_Fortezza::GetParams(CSM_Buffer *&paramsBuf)
{
   CSM_CertificateChoice     *pCert = NULL;
   CSM_BufferLst::iterator   itCBuf;
   CSM_BufferLst             *pBufferLst = new CSM_BufferLst;
   const Certificate               *pSnaccCertificate = NULL;
   char                       nullParams[] = {0x05, 0x00};
   bool                       foundParams = false;

   SME_SETUP("CSM_Fortezza::GetParams()");

   SME(mp_cardInfo->GetUserPath( pBufferLst, m_nSignerIndex, true)); 
    
   for (itCBuf =  pBufferLst->begin();
        itCBuf != pBufferLst->end() && !foundParams;
        ++itCBuf)
   {
     pCert = new CSM_CertificateChoice;
     pCert->SetEncodedCert(*itCBuf);

     pSnaccCertificate = pCert->AccessSNACCCertificate();
     if (pSnaccCertificate->toBeSigned.subjectPublicKeyInfo.algorithm.parameters)
     {
        SM_EXTRACT_ANYBUF(paramsBuf, 
           pCert->AccessSNACCCertificate()->toBeSigned.subjectPublicKeyInfo.
           algorithm.parameters);

        // check for null params
        if (paramsBuf->Length() == 2)
        {
           if (memcmp(nullParams, paramsBuf->Access(), 2) != 0)
              delete paramsBuf;
        }   // END IF paramsBuf length
        else
           foundParams = true;
     }      // END IF parameters

     delete pCert;
   }        // END FOR GetUserPath buffer list.

   SME_FINISH_CATCH;
   
   return SM_NO_ERROR;
}   // CSM_Fortezza::GetParams(...)

//
//
SM_RET_VAL CSM_Fortezza::SMTI_Verify(CSM_Buffer *pEncodedPublicKey,
                                     CSM_AlgVDA    *pDigestAlg,
                                     CSM_AlgVDA    *pSignatureAlg,
                                     CSM_Buffer *pData,
                                     CSM_Buffer *pSignature)
{
   long error = SM_NO_ERROR;
   AsnOid *pSignOID=this->GetPrefDigestEncryption();
   SME_SETUP("CSM_Fortezza::SMTI_Verify");

   //char *ptr=pSignOID->GetOIDDescription();
   if (pSignOID && 
     (*pSignOID == id_dsa_with_sha1 ||
      *pSignOID == id_dsa))// && 
      //pEncodedPublicKey->Length() > 70) // RWC;FORTEZZA CTIL is not setup to 
                                 //  handle short DSA signatures (64bytes).
                                 //  (the public key is 64 bytes encoded as int).
    {
        error = SMTI_VerifyFORTEZZA(pEncodedPublicKey, pDigestAlg, pSignatureAlg, 
                    pData, pSignature);
    }
    else
    {
        error = CSM_Common::SMTI_Verify(pEncodedPublicKey, pDigestAlg, pSignatureAlg, 
                    pData, pSignature);
        if (error)
        {
            SME_THROW(error, "CSM_Fortezza::SMTI_Verify:Algorithm not supported", NULL);
        }
    }


   SME_FINISH_CATCH;
   return error;
}


// FUNCTION: SMTI_Verify()
//
// PURPOSE: To verify the signuature within a SignedData
//
// INPUTS:   pSignerPublicKey --> Signer's X.509 Certificate
//           pData      --> 
//
SM_RET_VAL CSM_Fortezza::SMTI_VerifyFORTEZZA(CSM_Buffer *pEncodedPublicKey,
                                     CSM_AlgVDA    *pDigestAlg,
                                     CSM_AlgVDA    *pSignatureAlg,
                                     CSM_Buffer *pData,
                                     CSM_Buffer *pSignature)
{
   long              error = SM_NO_ERROR;
   CSM_Buffer        hashValue;
   CSM_FortDSAParams FortDSAParams; 
   CSM_Buffer        *pParams = NULL;
   CSM_Buffer        *pLocalSignerPubKey = NULL;
   CSM_Buffer        *pLocalEncodedPubKey = NULL;
   CSM_DSASignatureValue dsaSigValue(pSignature);
   int              iPLength=0;
   
   SME_SETUP("CSM_Fortezza::SMTI_Verify");

   if ( (pParams = pSignatureAlg->GetParams()) == NULL)
   {
      SME_THROW(SM_MISSING_PARAM,"Sig. Alg. parameters missing.",
          NULL);
   }

   // Decode the parameters as DSA parameters.  The results are
   // stored in the three public members: P,Q,G of dsaParams.
   //
   SME(iPLength=FortDSAParams.Decode(pParams));

   // If NO public was passed in assume public key from current
   // instance.
   //
   if (pEncodedPublicKey == NULL)
   {
      pLocalEncodedPubKey = GetEncodedPublicKey();
      pLocalSignerPubKey = DecodePublicKey(pLocalEncodedPubKey);
   }
   else
      pLocalSignerPubKey = DecodePublicKey(pEncodedPublicKey);

#ifdef PIERCE
   // note sure why, but I think you need to set the personality
   // before you can verify a signature.
   //
   // make sure this is tested with both SPEX and Fortezza.  If 
   // the CI_SetPersonality() call is not necessary delete this code.
   //
   error = CI_SetPersonality(m_nSignerIndex);

   if (error != CI_OK)
      SME_THROW(error, "CI_SetPersonality() failed", NULL);
#endif
   
   if (pLocalSignerPubKey == NULL)
   {
      SME_THROW(-1, "Missing Public Key", NULL);
   }

   // Should I make sure the pSignerKey->oid is DSA-SHA1?  I don't think
   // so.  I believe that check should be at the SM_Verify() level?  For
   // now I won't check the oid.   PXL.
   //
  
   error = CI_Lock(CI_BLOCK_LOCK_FLAG);
   if (error != CI_OK)
      SME_THROW(error, "CI_Clock() failed.", NULL);

   // hash/digest in software (from CSM_Common)
   //
   SME( CSM_Common::SMTI_DigestDataSHA1(pData, &hashValue) );

   //RWC;6/13/01; This fails for some reason (documentation is useless) when
   //  iPLength is not 128 bytes.  Must be due to our private key login setup
   //  logic???@@#%$@$%@#$@  ALTERNATIVE option was to use internal 
   //  CSM_Common:SMTI_Verify(...) for DSA verification in these cases.....
   int iQLength = CI_Q_SIZE;
    error = CI_LoadDSAParameters(iPLength, iQLength, 
                                      (unsigned char *) FortDSAParams.P,
                                      (unsigned char *) FortDSAParams.Q, 
                                      (unsigned char *) FortDSAParams.G);
   if (error)
      SME_THROW(error, "CI_LoadDSAParameters().", NULL);

   // Get R & S and concatonate them into a CSM_Buffer
   //
   
   char *pTmpSig = dsaSigValue.GetRS();
   if ( (error = CI_VerifySignature( (unsigned char *) hashValue.Access(), 
            pLocalSignerPubKey->Length(), //RWC;Length may not be 128, 
                                          //  depends on pub key length
            (unsigned char *) pLocalSignerPubKey->Access(),
            (unsigned char *) pTmpSig )) != SM_NO_ERROR)
      SME_THROW(error, "CI_VerifySignature() failed.", NULL);

   CI_Unlock();
   free(pTmpSig);

   if (pLocalSignerPubKey)
      delete pLocalSignerPubKey;

   if (pParams != NULL)
       delete pParams;

   SME_FINISH_CATCH;

   pDigestAlg; //AVOIDS warning.
   return SM_NO_ERROR;
}

// FUNCTION: CreateInstances
//
// PURPOSE: Create an instance for each DSA and KEA certificate
//          on the Fortezza card.
//
SM_RET_VAL CSM_Fortezza::CreateInstances(CSM_CtilMgr/*CSMIME*/ *pCtilMgr, int iSlot)
{
   //CSM_CSInstLst    *pNewCsInsts = new CSM_CSInstLst;
   CSM_CSInst       *pNewNode = NULL;
   CSM_Fortezza     *pNewFort = NULL;
   CSM_BufferLst    *pCertBufLst = NULL;
   CSM_Buffer       *pNewCertBuf = NULL; 
   char             algStr[5];
   
   char instID[FORT_ID_SIZE+10];
   int  slot = 0;
   LabelType ue;

   // For Every user certifcate on the card create a new instance
   //
   slot = mp_cardInfo->GetSlot();
   if (iSlot != -1)
   {
      slot = iSlot;
      mp_cardInfo->SetSlot(slot);
   }
   while ( slot > 0)
   {
      ue = mp_cardInfo->GetUE();
      if (ue != BADLABEL)
      {
         pNewFort = new CSM_Fortezza;      
         
         pNewNode = new CSM_CSInst;//->AppendL();
 
         // copy cardinfo into new Fortezza instance
         if (pNewFort->mp_cardInfo == NULL)
            pNewFort->mp_cardInfo = new CSM_FortezzaCardInfo;
         pNewFort->mp_cardInfo->Set(*mp_cardInfo);

         //
         switch(ue)
         {
           case V3_DSA:
              sprintf(algStr, "DSA");
              pNewFort->SetSignerIndex(slot);
              pNewFort->SetDigestEncryptionOids();
              pNewFort->SetDigestOids();
            break;

           case V3_KEA:
              sprintf(algStr, "KEA");
              pNewFort->SetEncryptorIndex(slot);
              pNewFort->SetContentEncryptionOids();
              pNewFort->SetKeyEncryptionOids();
              pNewFort->SetDigestOids();
              //pNewNode->UseOriginatorSKI(true);
              break;

           case CA_DSA:
              sprintf(algStr, "DSA");
              pNewFort->SetSignerIndex(slot);
              // do not set DigestEncryptionOids  or
              // DigestOids.  The application must 
              // explicitly select these instances.
              //
              break;
         }
      
         sprintf(instID,"%02d:%s:%s", slot, algStr, mp_cardInfo->AccessLabel());
         pNewNode->SetID(instID);
         // Add user certificate to instance
         //
         // PIERCE added ability to load user path
         pCertBufLst = new CSM_BufferLst;

#ifndef ENABLE_COMPLETE_PATH
         pNewCertBuf = &(*pCertBufLst->append());
         pNewFort->mp_cardInfo->GetCertificate(*pNewCertBuf);
#else // COMPLETE PATH
            pNewFort->mp_cardInfo->GetUserPath(pCertBufLst, slot, true);
#endif

            pNewNode->SetCertificates(pCertBufLst);

            delete pCertBufLst;

            pNewNode->SetTokenInterface((CSM_TokenInterface *) pNewFort);
            pNewFort->SetCSInst(pNewNode);// Set CSM_CSInst for cert based access.
            if (pCtilMgr->m_pCSInsts == NULL)
            {
               pCtilMgr->m_pCSInsts = new CSM_CtilInstLst;
            }

            //RWC;5/12/02; SPECIAL NOTE; using SFL version of list here in order
            //  to specially load the CTIL MGR version of the list with the same
            //  sub-class pointer as the CSMIME libCert version.
            // put it in the instance list in pCSMIME
            pCtilMgr->m_pCSInsts->append(pNewNode);  // ADD to end of list.

      }        // END if ue!=BADLABEL
      if (iSlot == -1)
      {
          mp_cardInfo->NextSlot();
          slot = mp_cardInfo->GetSlot();
      }
      else     // END if iSlot==-1
      {
          //RWC;7/9/00; from Pitkin;
          // if ((slot = pNewFort->mp_cardInfo->GetSiblingIndex()) == iSlot ||
          if ((slot = mp_cardInfo->GetSiblingIndex()) == iSlot ||
               slot == -1 || (slot & 0xff) == 0xff)  // only load siblings.
               slot = -1;        // ONLY fill 1 slot as requested.
          else
               mp_cardInfo->SetSlot(slot);

      }        // END if iSlot==-1
   }           // END while slot>0


   return 0;
}
   

// FUNCTION: Login()
//
// PURPOSE: Open and the card and check the pin so that
//          crypto functions can be performed.
//
SM_RET_VAL CSM_Fortezza::Login(char *pszPin)
{
   long    error = SM_NO_ERROR;
   long    localSocket = mp_cardInfo->GetSocket();

   SME_SETUP("CSM_Fortezza::Login()");

   if (localSocket == -1)
      SME_THROW(SM_MISSING_PARAM, "Library not initialized", NULL);

   error = CI_CheckPIN(CI_USER_PIN, (unsigned char *) pszPin);
   
   if (error != 0)
      SME_THROW(FORT_INV_PIN, "PIN is incorrect", NULL);

   return error;

   SME_FINISH_CATCH;

}

SM_RET_VAL CSM_Fortezza::SMTI_Encrypt(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV)  // In, to avoid specific
{
   long error = 0;
   AsnOid *pEncryptionOID=this->GetPrefContentEncryption();
   SME_SETUP("CSM_Fortezza::SMTI_Encrypt()");

    if (pEncryptionOID && 
      (*pEncryptionOID == id_fortezzaConfidentialityAlgorithm ||
       *pEncryptionOID == id_fortezzaWrap80))
    {
        error = SMTI_EncryptFORTEZZA(pData, pEncryptedData, pParameters, pMEK, 
            pIV);
    }
    else
    {
        error = CSM_Common::SMTI_Encrypt(pData, pEncryptedData, pParameters, 
            pMEK, pIV);
        if (error)
        {
            SME_THROW(error, "CSM_Fortezza::SMTI_Encrypt:Algorithm not supported", NULL);
        }
    }

   SME_FINISH_CATCH;
   return (error);
}
   
// Function: SMTI_Encrypt()
// Purpose : Encrypt pData using Skip Jack CBC64
//
// Note    : pMEK and pIV are ignored.  Also note that will the Fortezza
//           card the raw MEK is not returned.  So it's left in the 
//           MEK_REG register so that it can be wrapped with the 
//           appropriate algorithm.
//
SM_RET_VAL CSM_Fortezza::SMTI_EncryptFORTEZZA(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV)  // In, to avoid specific
  
{
   long    error = 0;
   Skipjack_Parm   skipjackParams;
   CSM_Buffer       *pLocalBuf = new CSM_Buffer;
   CI_IV   iv;


   SME_SETUP("CSM_Fortezza::SMTI_Encrypt()");

   if (pData == NULL || pEncryptedData == NULL || pParameters == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing Parameters", NULL);

   error = CI_SetPersonality(m_nEncryptorIndex);
   if (error != CI_OK)
      SME_THROW(error, "CI_SetPersonality() failed", NULL);

   // Generate new message encryption key
   //
   CI_DeleteKey(MEK_REG);

   error = CI_GenerateMEK(MEK_REG,0);
   if (error != CI_OK)
      SME_THROW(error, "CI_GenerateMEK() failed!", NULL);

   error = CI_SetKey(MEK_REG);

   error = CI_GenerateIV(iv);

   // Store the IV in skipjacParams starting at byte postion 17.
   // Skip over the first 16 bytes "THIS IS NOT LEAF".  This
   // constant must be added on the CI_LoadIV().
   //
   skipjackParams.initialization_vector.Set( (char *) &iv[16],
      sizeof(CI_IV) - 16);

   ENCODE_BUF( &skipjackParams, pLocalBuf);

   *pParameters = *pLocalBuf;
   
   // use CIS_SJ_CBC64_MODE

   // Pad incoming data. All CBC64 algorithms should be
   // padded to an 8 byte (64 bit) boundary.
   //
   GeneratePad( *pData, 8);

   BlockEncryption(pData, pEncryptedData);

   delete pLocalBuf;

   SME_FINISH_CATCH;
   pIV;pMEK; //AVOIDS warning.
   return(SM_NO_ERROR);
}





SM_RET_VAL CSM_Fortezza::SMTI_Decrypt(
            CSM_Buffer *pParameters,    // input, parameters for alg.
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK,           // input (MEK or special phrase)
            CSM_Buffer *pData)         // output (decrypted data)
{
   long error = 0;
   AsnOid *pEncryptionOID=this->GetPrefContentEncryption();
   SME_SETUP("CSM_Fortezza::SMTI_Decrypt()");

    if (pEncryptionOID && 
      (*pEncryptionOID == id_fortezzaConfidentialityAlgorithm ||
       *pEncryptionOID == id_fortezzaWrap80))
    {
        error =SMTI_DecryptFORTEZZA(pParameters, pEncryptedData, pMEK, pData);
    }
    else
    {
        error = CSM_Common::SMTI_Decrypt(pParameters, pEncryptedData, pMEK,
            pData);
        if (error)
        {
            SME_THROW(error, "CSM_Fortezza::SMTI_Decrypt:Algorithm not supported", NULL);
        }
    }

   SME_FINISH_CATCH;
   return (error);
}
   
// FUNCTION: SMTI_Decrypt()
//
// Purpose:  Decrypt pEncryptedData into pData
//           SMTI_
//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Fortezza::SMTI_DecryptFORTEZZA(
            CSM_Buffer *pParameters,    // input, parameters for alg.
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK,           // input (MEK or special phrase)
            CSM_Buffer *pData)         // output (decrypted data)
{
   long error = 0;
   Skipjack_Parm   skipjackParams;
   CI_IV ciIV = "THIS IS NOT LEAF";


   SME_SETUP("CSM_Fortezza::SMTI_Encrypt()");

   if (pEncryptedData == NULL || pParameters == NULL ||
      pMEK == NULL || pData == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing Parameters", NULL);

   DECODE_BUF( &skipjackParams, pParameters );

   memcpy( &ciIV[16], skipjackParams.initialization_vector.c_str(), 8);

   error = CI_SetKey(MEK_REG);
   if (error != 0)
      SME_THROW(error,"CI_SetKey() failed", NULL);  
   
   error = CI_LoadIV( ciIV );
   if (error != CI_OK)
      SME_THROW(error, "CI_LoadIV() failed", NULL);

  
   BlockDecryption(pEncryptedData, pData);

   // Pad incoming data. All CBC64 algorithms should be
   // padded to an 8 byte (64 bit) boundary.
   //
   ExtractPad(*pData);

   SME_FINISH_CATCH;
   return (SM_NO_ERROR);
}


SM_RET_VAL CSM_Fortezza::SMTI_Random(
            CSM_Buffer *pSeed,
            CSM_Buffer *pRandom,
            SM_SIZE_T   lLength)
{
   // subbed out for now
   lLength;pRandom;pSeed; //AVOIDS warning.
   return (SM_NO_ERROR);
}

void CSM_Fortezza::GeneratePad(CSM_Buffer &data,
                               const int   padSize)
{
   char *pPadStr = NULL;
   int   padLength = 0;
   int   i = 0;

   SME_SETUP("CSM_Fortezza::GeneratePad()");

   if (padSize < 1 || padSize > 8)
      SME_THROW(FORT_INV_PADSIZE, "Invalid pad size", NULL);


   // If data is already on a padSize boundary pad
   // it with padSize number of bytes.
   //
   padLength = padSize - (data.Length() % padSize); 
   
   pPadStr = (char *) calloc(1, padLength+1);

   for (i=0; i < padLength; i++)
      pPadStr[i] = (char)padLength; 

   data.Open(SM_FOPEN_APPEND);
   data.Write(&pPadStr[0], padLength); 
   data.Flush();
   data.Close();

   free(pPadStr);

   SME_FINISH_CATCH;
}

void CSM_Fortezza::ExtractPad(CSM_Buffer &data)
{

   char padChar[2];
   long padLength;


   SME_SETUP("CSM_Fortezza::GeneratePad()");

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


// FUNCTION: SMTI_GenerateKeyWrapIV()
//
// PURPOSE : generate a random value (IV, or Ra in Fortezza's case)
//           which will me used to encrypt the MEK along with the 
//           receipient's public key (see SMTI_GenerateKeyAgreement()).
//


CSM_Buffer * CSM_Fortezza::SMTI_GenerateKeyWrapIV(long &lkekLength, 
                                                  CSM_AlgVDA *pWrapAlg)
{
   CSM_Buffer *pIV = NULL; // returned


   SME_SETUP("CSM_Fortezza::SMTI_GenerateKeyWrapIV()");

   if (pWrapAlg != NULL)
      pWrapAlg->algorithm = id_fortezzaWrap80;

   lkekLength = -1;

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
SM_RET_VAL CSM_Fortezza::SMTI_GenerateKeyAgreement(
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
   CI_RA Ra;
   CI_RB Rb;
   long error = 0;

   SME_SETUP("CSM_Fortezza::SMTI_GenerateKeyAgreement()");

   if (pPubKey == NULL || pUKM == NULL)
   {
      SME_THROW(SM_MISSING_PARAM, "Missing Parameter", NULL);
   }

   /* ignore 
   if (lKekLength != sizeof(CI_KEY))
      SME_THROW(FORT_INV_KEYSIZE, "Invalid KEK length", NULL);
   */

   // Check IV length
   //
   /* ignore
   if (pIV->Length() != sizeof (CI_RA))
      SME_THROW(FORT_INV_IV_SIZE, "IV (Ra) invalid length", NULL);
   */

   error = CI_SetPersonality(m_nEncryptorIndex);
   if (error != 0)
      SME_THROW(error, "CI_SetPersonality() failed", NULL);

   error = CI_DeleteKey(KEK_REG);
   if (error != 0)
      SME_THROW(error, "CI_DeleteKey(KEK_REG) failed", NULL);

   // If UKM provided is not the size of CI_RA then create a
   //    new UKM.
   // else use provided UKM
   //
   if (pUKM->Length() != sizeof(Ra))
   {
      error = CI_GenerateRa(Ra);

      if (error != CI_OK)
         SME_THROW(error, "CI_GenerateRa()", NULL);

      pUKM->Set( (char *) &Ra[0], sizeof(Ra));
   }

   memset((char *)Rb, 0, sizeof(Rb));
   Rb[sizeof(Rb) - 1] = 1;

   error = CI_GenerateTEK(CI_INITIATOR_FLAG, KEK_REG, 
      (unsigned char *)pUKM->Access(), Rb, 
      pPubKey->Length(), (unsigned char *) pPubKey->Access());

   if (error != CI_OK)
      SME_THROW(error, "CI_GenerateTEK() failed", NULL);


   return 0; 

   lKekLength;pbufKeyAgree;pEncryptionOID;pIV;pParameters; //AVOIDS warning.
   SME_FINISH_CATCH;
}   

// FUNCTION: SMTI_ExtractKeyAgreement()
//
// PURPOSE: Reveal the recipient's KEK.
//
SM_RET_VAL CSM_Fortezza::SMTI_ExtractKeyAgreement(
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
   CI_RA Ra;
   CI_RB Rb;

   long error = 0;

   SME_SETUP("CSM_Fortezza::SMTI_ExtractKeyAgreement()");

   // check for required parameters
   //
   if (pOrigPubKey == NULL || pUKM == NULL ||
      pbufKeyAgree == NULL)
   {
      SME_THROW(SM_MISSING_PARAM,"Missing Required Parameter", NULL);
   }


   // Check UKM (Ra)
   //
   if (pUKM->Length() != sizeof(CI_RA))
      SME_THROW(-1, "Invalid UKM (Ra) Length for Fortezza", NULL);

   // Make sure KEK_REG is empty
   error = CI_DeleteKey(KEK_REG);

   // Set Personality
   //
   error = CI_SetPersonality( m_nEncryptorIndex );
   if (error != CI_OK)
      SME_THROW(error, "CI_SetPersonality() failed", NULL);

   // Generate KEK
   //

   memset((char *)Rb, 0, sizeof(Rb));
   Rb[sizeof(Rb) - 1] = 1;
   memcpy(Ra, pUKM->Access(), sizeof(Ra));

   error = CI_GenerateTEK(CI_RECIPIENT_FLAG, KEK_REG, 
      Ra, Rb,
      pOrigPubKey->Length(),
      (unsigned char *) pOrigPubKey->Access());
   
   if (error != CI_OK)
      SME_THROW(-1, "CI_GenerateTEK() failed", NULL);

   return error;

   lKekLength;pEncryptionOID;pbufferIV; //AVOIDS warning.
   SME_FINISH_CATCH;
}
               

// FUNCTION: SMTI_GenerateKeyWrap()
//
// PURPOSE: Wrap the CEK.  Fortezza CTIL ignores the following:
//
// pData
// pParameters
// pMEK
// pIV
//
SM_RET_VAL CSM_Fortezza::SMTI_GenerateKeyWrap(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV)            // In, to avoid specific
{
   CI_KEY wrapped_cek;
   long error = 0;

   SME_SETUP("CSM_Fortezza::SMTI_GenerateKeyWrap()");

   if (pEncryptedData == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing required parameter", NULL);

   error = CI_WrapKey(KEK_REG, MEK_REG, wrapped_cek);
   
   if (error != CI_OK)
      SME_THROW(error, "CI_WrapKey() failed", NULL);

   pEncryptedData->Set( (char *) &wrapped_cek[0], sizeof(wrapped_cek));

   return 0;

   pIV;pMEK;pParameters;pData; //AVOIDS warning.
   SME_FINISH_CATCH;
}

// FUNCTION: SMTI_ExtractKeyWrap()
//
// PURPOSE: Unwrap MEK with KEK.  SMTI_ExtractKeyAgreement must
//          be called first.
//
// NOTE: Fortezza CTIL ignores the following parameters:
//
//        pParameters
//        pTEK
//
SM_RET_VAL CSM_Fortezza::SMTI_ExtractKeyWrap(
            CSM_Buffer *pData,          // Output
            CSM_Buffer *pEncryptedData, // input
            CSM_Buffer *pParameters,    // IN, for KeyAgree algs.
            CSM_Buffer *pTEK,           // output
            CSM_Buffer *pIV)            // In
{
   long error = 0;
   CI_KEY wrapped_cek;

   SME_SETUP("CSM_Fortezza::SMTI_ExtractKeyWrap()");

   if (pData == NULL || pEncryptedData == NULL )
      SME_THROW(SM_MISSING_PARAM, "Missing required parameter", NULL);

   error = CI_SetKey(KEK_REG);
   if (error != CI_OK)
      SME_THROW(error, "CI_SetKey(KEK_REG) failed", NULL);

   error = CI_DeleteKey(MEK_REG);
   if (error != CI_OK)
      SME_THROW(error, "CI_SetKey(MEK_REG) failed", NULL);

   // Check size of EMEK
   // 
   if (pEncryptedData->Length() != sizeof(CI_KEY))
      SME_THROW(-1, "Invalid size for EMEK", NULL);

   memcpy( &wrapped_cek[0], pEncryptedData->Access(), sizeof(CI_KEY));

   error = CI_UnwrapKey(KEK_REG, MEK_REG, wrapped_cek);

   if (error != CI_OK)
      SME_THROW(error, "CI_UnwrapKey() failed", NULL);

   return error;

   pIV;pTEK;pParameters;; //AVOIDS warning.
   SME_FINISH_CATCH;
      
}

//
//
CSM_Alg * CSM_Fortezza::DeriveMsgAlgFromCert(CSM_CertificateChoice &cert)
{ 
   CSM_Alg *pubKeyAlg = NULL;

   pubKeyAlg = cert.GetPublicKeyAlg();
 
    return(pubKeyAlg);
}



// RWC; Added for DLL updates.
//
//
SM_RET_VAL CSM_Fortezza::SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input, parameters for alg.
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output
{

   pMEK;pUKM;pEMEK;pParameters;pOriginator; //AVOIDS warning.
    return -1;      // NOT SUPPORTED BY THIS LIBRARY.
}

//
//
//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Fortezza::SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // input, parameters for alg.
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // output, ukm, if applicable
            CSM_Buffer *pSubjKeyId) // output
{
   pSubjKeyId;pUKM;pEMEK;pMEK;pParameters;pRecipient; //AVOIDS warning.
    return -1;
}

void CSM_Fortezza::BlockEncryption( CSM_Buffer *pData,          // input (data to be encrypted)
                                    CSM_Buffer *pEncryptedData) // output
{
   long             error = 0;
   unsigned long    blockSize = 0;
   unsigned long    largestBlockSize = 0;
   unsigned long    bytesRead = 0;
   unsigned long    totalBytesRead = 0;
   char            *block = NULL;

   SME_SETUP("CSM_Fortezza::BlockEncryption");

   largestBlockSize = blockSize = mp_cardInfo->GetLargestBlockSize();

   block = (char *) calloc(1, blockSize);

   if (pData->Length() > largestBlockSize )
   {
      pEncryptedData->Open(SM_FOPEN_WRITE);

      pData->Open(SM_FOPEN_READ);

      while (totalBytesRead != pData->Length())
      {
         bytesRead = pData->cRead( block, blockSize);
         totalBytesRead += bytesRead;

         error = CI_Encrypt(bytesRead, (unsigned char *) block, 
            (unsigned char *) block);
         if (error != CI_OK)
            SME_THROW(error, "CI_Encrypt() faile", NULL);

         pEncryptedData->Write(block, blockSize);

         blockSize = (pData->Length() - totalBytesRead);

         if (blockSize > largestBlockSize)
            blockSize = largestBlockSize;
      }
   }
   else
   {
      error = CI_Encrypt(pData->Length(), (unsigned char *) pData->Access(), 
         (unsigned char *) block);
      if (error != CI_OK)
         SME_THROW(error, "CI_Encrypt() failed", NULL);

      pEncryptedData->Set(block, pData->Length());

   }

   SME_FINISH_CATCH;
}

void CSM_Fortezza::BlockDecryption(CSM_Buffer *pEncryptedData, CSM_Buffer *pData)
{
   long             error = 0;
   unsigned long    blockSize = 0;
   unsigned long    largestBlockSize = 0;
   unsigned long    bytesRead = 0;
   unsigned long    totalBytesRead = 0;
   char            *block = NULL;   


   SME_SETUP("CSM_Fortezza::BlockDecryption");

   largestBlockSize = blockSize = mp_cardInfo->GetLargestBlockSize();

   block = (char *) calloc(1, blockSize);

   if (pEncryptedData->Length() > largestBlockSize )
   {
      pData->Open(SM_FOPEN_WRITE);

      pEncryptedData->Open(SM_FOPEN_READ);

      while (totalBytesRead != pEncryptedData->Length())
      {
         bytesRead = pEncryptedData->cRead( block, blockSize);
         totalBytesRead += bytesRead;

         error = CI_Decrypt(bytesRead, (unsigned char *) block, 
            (unsigned char *) block);
         if (error != CI_OK)
            SME_THROW(error, "CI_Decrypt() failed", NULL);

         pData->Write(block, blockSize);

         blockSize = (pEncryptedData->Length() - totalBytesRead);

         if (blockSize > largestBlockSize)
            blockSize = largestBlockSize;
      }
   }
   else
   {
      error = CI_Decrypt(pEncryptedData->Length(), 
         (unsigned char *) pEncryptedData->Access(), 
         (unsigned char *) block);
      if (error != CI_OK)
         SME_THROW(error, "CI_Encrypt() failed", NULL);

      pData->Set(block, pEncryptedData->Length());

   }

   SME_FINISH_CATCH;
}

void CSM_Fortezza::SMTI_DeleteMEK()
{
   CI_DeleteKey(MEK_REG);
}

//_END_CERT_NAMESPACE
#ifndef WIN32
    using namespace CERT;
#endif
    using namespace CTIL;
    using namespace SNACC;

#ifndef NO_DLL
extern "C" {
long Make_argv(char *string, int *pargc, char ***pargv);
void Delete_argv(int argc, char **pargv);

#define SM_FORTDLL_STR "SM_FORTDLL"

SM_FORTEZZADLL SM_RET_VAL DLLBuildTokenInterface(CSM_CtilMgr/*CSMIME*/ &Csmime, 
    char *lpszBuildArgs)
{
    SM_RET_VAL status = 0;
    int argc1=0;
    char **argv1;
    char ptr[30];
    long nSocket=0;

    memset(ptr, '\0', 30);
    for (int i=0; i < (int)strlen(SM_FORTDLL_STR); i++)
        ptr[i] = (char)toupper(lpszBuildArgs[i]);
    // Preliminary check that this request is for our library.
    if (strncmp(ptr, SM_FORTDLL_STR, strlen(SM_FORTDLL_STR)) == 0)
    {
        Make_argv(lpszBuildArgs, &argc1, &argv1);
        if (argc1 >= 2)
        {
           // Pass char *pszPassword, char *pszAddressBook, char *pszPrefix
           if (argc1 > 2)
             nSocket = atoi(argv1[2]);
		   CERT::SMFortezzaInit((void *)&Csmime, argv1[1], nSocket);
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
    //return new CSM_Free3;
    return(status);
}

SM_FORTEZZADLL char * DLLGetId()
{
    return(strdup(SM_FORTDLL_STR));
}

}       // END extern "C"

#endif

// EOF sm_fort.cpp
