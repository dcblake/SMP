
#pragma warning( disable : 4702 )   // MUST IGNORE, since even catch (...) 
                                    //  indicates "unreachable code", but 
                                    //  NULL pointer refs can crash.
//////////////////////////////////////////////////////////////////////////
// sm_Encrypt.cpp
// Implementation of the CSM_MsgToEncrypt and CSM_DataToEncrypt classes
// CSM_MsgToEncrypt is for high level use.  The application developer
// should not have to directly access the snacc generated classes.
// CSM_DataToEncrypt is for low level use.  The application may have
// to directly access the exposed snacc generated class.  Both
// classes have the purpose of generating valid CSM EnvelopedData
// ASN.1 encoded structures based on the provided input and the
// provided (and prepared) instances (contained in CSMIME)
//////////////////////////////////////////////////////////////////////////

#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
// CONSTRUCTORS
//////////////////////////////////////////////////////////////////////////
// empty constructor
CSM_MsgToEncrypt::CSM_MsgToEncrypt()
{
   Clear();
}

//////////////////////////////////////////////////////////////////////////
// incoming message is in pBlob
CSM_MsgToEncrypt::CSM_MsgToEncrypt(const CSM_Buffer *pBlob)
{
   Clear();
   SetEncapContentClear(*pBlob);
}

//////////////////////////////////////////////////////////////////////////
// incoming message is in a content info
CSM_MsgToEncrypt::CSM_MsgToEncrypt(const CSM_ContentInfoMsg *pCI)
{
   SME_SETUP("CSM_MsgToEncrypt::CSM_MsgToEncrypt(CSM_ContentInfoMsg)");

   Clear();

   if (pCI == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // TBD, what this is supposed to do is wrap whatever's in 
   // the CSM_ContentInfoMsg in a ContentInfo and then we set the type
   // as DATA.  Correct???
   SetEncapContentClear(*((CSM_ContentInfoMsg *)pCI)->AccessEncodedCI());

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// incoming message is in pContent
CSM_MsgToEncrypt::CSM_MsgToEncrypt(const CSM_Content *pContent)
{
   Clear();
   SetEncapContentClear(*pContent);
}

//////////////////////////////////////////////////////////////////////////
// Destructor
CSM_MsgToEncrypt::~CSM_MsgToEncrypt()
{
   if (m_poidContentEncrypt)
      delete (m_poidContentEncrypt);
   if (m_pMsgCrtCrls)
      delete (m_pMsgCrtCrls);
   if (m_pRecipients)
      delete m_pRecipients;
   if (m_pUnprotectedAttrs)
      delete m_pUnprotectedAttrs;
   if (m_pOPTIONALEncryptedContent)
       delete m_pOPTIONALEncryptedContent;
   if (m_poidEncryptionAlg)
      delete m_poidEncryptionAlg;
   if (m_poidDerivationAlg)
      delete m_poidDerivationAlg;

}

//////////////////////////////////////////////////////////////////////////
void CSM_MsgToEncrypt::Clear()
{
   m_bIncludeOrigCertsFlag = false;
   m_poidContentEncrypt = NULL;
   m_pMsgCrtCrls = NULL;
   m_pRecipients = NULL;
   m_pKeyEncryptionOID = NULL;
   m_pUnprotectedAttrs = NULL;
   m_bACLUseToValidate = false;
   m_bACLFatalFail = false;
   m_poidEncryptionAlg = NULL;
   m_poidDerivationAlg = NULL;
   m_bKTRI_RSAES_OAEPflag = false;
}       // END Clear()

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToEncrypt::Encrypt uses the content, m_pMsgCrtCrls
// and m_pRecipients to generate the EnvelopedData
// if m_pRecipients == NULL then we're doing a local key encryption
void CSM_MsgToEncrypt::Encrypt(CSMIME *pCSMIME)
{
   CSM_Alg *pContentEncryptionAlg=NULL;
   CSM_Buffer *pbufferResult=NULL;

   SME_SETUP("CSM_MsgToEncrypt::Encrypt");
   CSM_CtilInstLst::iterator itInst;
   CSM_CSInst *pInstCS;
   //RWC9;CSM_CertificateChoiceLst *pCertificates;

   // check to make sure everything is ready to roll
   if ((pCSMIME == NULL) || (pCSMIME->m_pCSInsts == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   if (m_poidContentEncrypt == NULL)
      SME_THROW(SM_ENCRYPTION_UNPREPARED, 
            "no content encryption oid specified", NULL);

   // in order to call CSM_DataToEncrypt::Encrypt we need pCSMIME which the
   // application gave us

   // we also need a CSM_MsgCertCrls which the application prepared.
   // if the app set m_bIncludeOrigCertsFlag then we need to put the certs
   // from each UseThis instance into the m_pMsgCrtCrls
   if (m_bIncludeOrigCertsFlag)
   {
      // the application has requested that we include the originator
      // certs, therefore, go through the instances and find all of them
      // that are marked with UseThis and include whatever certs are
      // present in the instance in this m_pMsgCrtCrls
      for (itInst =  pCSMIME->m_pCSInsts->begin();
           itInst != pCSMIME->m_pCSInsts->end();
           ++itInst)
      {
         // if this instance is used
         pInstCS = (CSM_CSInst *)(*itInst)->AccessTokenInterface()->AccessCSInst();
         if (pInstCS && pInstCS->IsThisUsed())
         {
            // if there are certificates in this instance
            if (pInstCS->HasCertificates())
            {
               // if this class already has certificates, they will be over-written
               pInstCS->LoadCertificates(m_pMsgCrtCrls);
               //RWC9;if ((m_pMsgCrtCrls = new CSM_MsgCertCrls(pCertificates))
               //RWC9;        == NULL)
               //RWC9;  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            }
         }        // END IF instance handles certificates AND Used.
      }           // END FOR each login instance in list.
   }        // END IF include originator certs

   // we will need to pass m_pRecipients to CSM_DataToEncrypt::Encrypt, the
   //    app must have prepared this...
   // we must pass the poidContentType to CSM_DataToEncrypt::Encrypt which
   //    is obtained via the inherited CSM_CommonData->GetEncapContent()->
   //    m_ContentType
   // we must pass the content to CSM_DataToEncrypt::Encrypt which
   //    is obtained via the inherited CSM_CommonData->GetEncapContent()->
   //    m_content
   // we must pass the content encryption oid to CSM_DataToEncrypt::Encrypt
   //    and the app must have set this with the SetContentEncryptOID member
   pContentEncryptionAlg = new CSM_Alg(*m_poidContentEncrypt);

   // setup a buffer to receive the result
   // TBD, what type of buffer?  for now, do memory...
   if ((pbufferResult = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // Add UnprotectedAttrs if presented by the caller,NEED to do before Encrypt
   if (m_pUnprotectedAttrs != NULL)
   {
      m_SnaccEnvelopedData.unprotectedAttrs = 
         m_pUnprotectedAttrs->GetSNACCUnprotectedAttributes(); 
   }
   if (this->m_bCMLUseToValidate)
   {
      long lstatus = CMLCheckoutCerts();
      if (lstatus != 0 && this->m_bCMLFatalFail)
      {
         char ptrData[4096];
         if (m_pszCMLError)
         {
             int icout=strlen(m_pszCMLError);
             strcpy(ptrData, "CML validation fails, FATAL flag set.");
             if (strlen(m_pszCMLError) > 4000)
               icout = 4000;
             strncat(ptrData, m_pszCMLError, icout);
         }
         else
             strcpy(ptrData, "CML validation fails, FATAL flag set.");
         SME_THROW(24, ptrData, NULL);
      }
   }
#ifdef ACL_USED
   if (this->m_bACLUseToValidate)
   {
      long lstatus = ACLCheckoutCerts();
      if (lstatus != 0 && this->m_bACLFatalFail)
      {
         char ptrData[4096];
         if (m_ACLInterface.m_lpszError)
         {
             int icout=strlen(m_ACLInterface.m_lpszError);
             strcpy(ptrData, "ACL validation fails, FATAL flag set.");
             if (strlen(m_ACLInterface.m_lpszError) > 4000)
               icout = 4000;
             strncat(ptrData, m_ACLInterface.m_lpszError, icout);
         }
         else
             strcpy(ptrData, "ACL validation fails, FATAL flag set.");
         SME_THROW(23, ptrData, NULL);
      }
   }
#endif //ACL_USED

   // everything should be ready to call CSM_DataToEncrypt::Encrypt now...
   SME(CSM_DataToEncrypt::Encrypt(pCSMIME, m_pMsgCrtCrls, m_pRecipients,
            (AsnOid *)&(AccessEncapContentFromAsn1()->m_contentType), 
            (CSM_Buffer *)&(AccessEncapContentFromAsn1()->m_content), pContentEncryptionAlg, 
            pbufferResult));

   // store the encoded blob
   SME(UpdateEncodedBlob(pbufferResult));
   if (pContentEncryptionAlg)
      delete pContentEncryptionAlg;


   SME_FINISH
   SME_CATCH_SETUP
      if (pbufferResult)
         delete pbufferResult;
      if (pContentEncryptionAlg)
         delete pContentEncryptionAlg;
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
//
//
long CSM_MsgToEncrypt::CMLCheckoutCerts()
{
   long lstatus=0;

   SME_SETUP("CSM_DataToEncrypt::CMLCheckoutCerts");

#ifdef CML_USED
   CSM_RecipientInfoLst::iterator itTmpRecip;
   // FOR this CML check operation, we add each recipient cert and validate.
   // The application may have pre-loaded the CML storage previous to calling
   //  Encrypt(...) with other information (e.g. issuer, CRLs, etc.).
   for (itTmpRecip =  m_pRecipients->begin(); 
        itTmpRecip != m_pRecipients->end();
        ++itTmpRecip)
   {
      // check for recipient cert
      if (itTmpRecip->m_pKEKDetails == NULL)     //Ignore KEK recip
      {
#ifdef RWC_DEBUG_TEST_RIDONLY   // TEST CML lookup based on RID ONLY!
         if (itTmpRecip->m_pCert)
         {
            CSM_Identifier *pTmpRid=itTmpRecip->m_pCert->GetRid(true);
            m_ACMLCert.m_pRID = new CSM_Identifier(*pTmpRid);
            delete pTmpRid;
            delete itTmpRecip->m_pCert;
            itTmpRecip->m_pCert = new CSM_CertificateChoice; // EMPTY
         }     // END if itTmpRecip->m_pCert
#endif //RWC_DEBUG_TEST_RIDONLY
         lstatus = CMLValidateCert(itTmpRecip->m_ACMLCert, itTmpRecip->m_pCert); 
                   // FROM CSM_CommonData, it will fill in a cert if necessary
                   //  from the RID AND return the ACMLCert with the cert
                   //  info filled in as well as an indication of success on
                   //  veification.
         if (lstatus != 0)
         {
            itTmpRecip->m_bCMLValidationFailed = true; // INDICATE specifically 
                                                // which CSM_RecipientInfo failed.
         }        // END if lstatus on CML VerifySignature()
      }  // END if cert for recipient.
   }     // END for each recipient.
#endif //CML_USED


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(lstatus);
}       // END CSM_MsgToEncrypt::CMLCheckoutCerts()


//////////////////////////////////////////////////////////////////////////
//
//
long CSM_MsgToEncrypt::ACLCheckoutCerts()
{
   long lstatus=0;

   SME_SETUP("CSM_MsgToEncrypt::ACLCheckoutCerts");

#ifdef ACL_USED
   CSM_RecipientInfoLst::iterator itTmpRecip;
   // FOR this ACL check operation, we add each recipient cert and validate.
   for (itTmpRecip =  m_pRecipients->begin();
        itTmpRecip != m_pRecipients->end();
        ++itTmpRecip)
   {
      // check for recipient cert
      if (itTmpRecip->m_pKEKDetails == NULL)     //Ignore KEK (non-cert) recips
      {
          if (itTmpRecip->m_pCert && itTmpRecip->m_pCert->AccessEncodedCert())
                                                // MUST have a cert...
          {
              lstatus = this->m_ACLInterface.Check_ACLOutgoingRecip(
                                     itTmpRecip->m_ACMLCert,
                                    *itTmpRecip->m_pCert->AccessEncodedCert());
             if (lstatus != 0)
             {
                itTmpRecip->m_bACLValidationFailed = true; // INDICATE specifically 
                                                    // which CSM_RecipientInfo failed.
             }        // END if lstatus on ACL validation
          }           // IF itTmpRecip->m_pCert
          else
          {
              if (this->m_bACLFatalFail)
              {
                  SME_THROW(25, "MISSING cert in recipient list, cannot ACL validate!", NULL);
              }
          }           // END if itTmpRecip->m_pCert
      }  // END if cert for recipient.
   }     // END for each recipient.
#endif //ACL_USED


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(lstatus);
}           // END CSM_MsgToEncrypt::ACLCheckoutCerts()




//////////////////////////////////////////////////////////////////////////
// LoadFromMsgCertCrls takes the certs, ACs and CRLs from the provided
// CSM_MsgCertCrls and puts it in decoded form into the EnvelopedData
void CSM_DataToEncrypt::LoadFromMsgCertCrls(CSM_MsgCertCrls *pMsgCertCrls)
{
   CSM_CertificateChoiceLst *pCerts = NULL;
   CSM_CertificateChoiceLst::iterator itCert;
   CSM_CertificateChoiceLst::iterator itAttrCert;
   CSM_CertificateChoiceLst::iterator itOtherCertFormat;
   CSM_CertificateChoiceLst::iterator itExtCert;
   AttributeCertificate   snaccAC;
   OtherCertificateFormat snaccOther;
   ExtendedCertificate    snaccExtCert;
   OriginatorInfo *pOI = NULL;
 
   bool bSomethingLoaded = false;
   CSM_RevocationInfoChoices *pRevocationInfoChoices;
   CSM_RevocationInfoChoices::iterator iRevInfoChoice;

   SME_SETUP("CSM_DataToEncrypt::LoadFromMsgCertCrls");

   if (pMsgCertCrls != NULL)
   {
      if ((pOI = m_SnaccEnvelopedData.originatorInfo = new OriginatorInfo)
            == NULL)
         SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
      // navigate pMsgCertCrls and store its components in the
      // appropriate places
      pCerts = pMsgCertCrls->AccessCertificates();
      // load certificates
      if (pCerts != NULL)
      {
         // create the certificate set
         if ((pOI->certs = new CertificateSet) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         // extract the Certs from the pCerts CSM_CertificateChoiceLst,
         // decode them, and store them in the certificateSet
         for (itCert = pCerts->begin(); 
              itCert != pCerts->end();
              ++itCert)
         {
            CertificateChoices &SnaccCertChoice = *pOI->certs->append();
            // set the type
            SnaccCertChoice.choiceId = CertificateChoices::certificateCid;
            // decode the current certificate
            if ((SnaccCertChoice.certificate = new Certificate) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
            DECODE_BUF(SnaccCertChoice.certificate,
                  (itCert->AccessEncodedCert()));
            bSomethingLoaded = true;
         }      // END FOR each cert in list
      }
      pCerts = pMsgCertCrls->AccessACs();
      // load ACs
      if (pCerts != NULL)
      {
         // create the certificate set if it isn't already created
         if (pOI->certs == NULL)
            if ((pOI->certs = new CertificateSet) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         // extract the ACs from the pCerts CSM_CertificateChoiceLst,
         // decode them, and store them in the certificateSet
         for (itAttrCert =  pCerts->begin(); 
              itAttrCert != pCerts->end();
              ++itAttrCert)
         {
            CertificateChoices &SnaccCertChoice = *pOI->certs->append();

            // set the type
            SnaccCertChoice.choiceId = CertificateChoices::v2AttrCertCid;
            
            // decode the current certificate 
            DECODE_BUF((&snaccAC), itAttrCert->AccessEncodedAttrCert());

            if ((SnaccCertChoice.v2AttrCert = new AttributeCertificate(snaccAC)) 
                == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
            bSomethingLoaded = true;
         }      // END FOR each AC in bucket.
      }

      pCerts = pMsgCertCrls->AccessOtherCertFormats();
      // load OtherCertificateFormat
      if (pCerts != NULL)
      {
         // create the certificate set if it isn't already created
         if (pOI->certs == NULL)
            if ((pOI->certs = new CertificateSet) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

         // extract the OtherCertificateFormat from the pCerts CSM_CertificateChoiceLst,
         // decode them, and store them in the certificateSet
         for (itOtherCertFormat =  pCerts->begin(); 
              itOtherCertFormat != pCerts->end();
              ++itOtherCertFormat)
         {
            CertificateChoices &SnaccCertChoice = *pOI->certs->append();

            // set the type
            SnaccCertChoice.choiceId = CertificateChoices::otherCid;
            
            // decode the current certificate 
            DECODE_BUF((&snaccOther), itOtherCertFormat->AccessEncodedOther());

            if ((SnaccCertChoice.other = new OtherCertificateFormat(snaccOther)) 
                == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
            bSomethingLoaded = true;
         }      // END FOR each OtherCertificateFormat in bucket.
      }

      pCerts = pMsgCertCrls->AccessExtCerts();
      // load ExtendedCertificates
      if (pCerts != NULL)
      {
         // create the certificate set if it isn't already created
         if (pOI->certs == NULL)
            if ((pOI->certs = new CertificateSet) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

         // extract the OtherCertificateFormat from the pCerts CSM_CertificateChoiceLst,
         // decode them, and store them in the certificateSet
         for (itExtCert =  pCerts->begin(); 
              itExtCert != pCerts->end();
              ++itExtCert)
         {
            CertificateChoices &SnaccCertChoice = *pOI->certs->append();

            // set the type
            SnaccCertChoice.choiceId = CertificateChoices::extendedCertificateCid;
            
            // decode the current certificate 
            DECODE_BUF((&snaccExtCert), itExtCert->AccessEncodedExtCert());

            if ((SnaccCertChoice.extendedCertificate = new ExtendedCertificate(snaccExtCert)) 
                == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
            bSomethingLoaded = true;
         }      // END FOR each OtherCertificateFormat in bucket.
      }

      // load crls
      pRevocationInfoChoices = pMsgCertCrls->AccessCRLLst();
      if (pRevocationInfoChoices != NULL)
      {
          if (pOI->crls == NULL)
              if ((pOI->crls = new RevocationInfoChoices) == NULL)
                  SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);

          pOI->crls = pRevocationInfoChoices->GetSNACCRevInfoChoices();
          bSomethingLoaded = true;
      }        

      // TBD, do ukms

      // if nothing was loaded, clear out the variable and return 
      // without error...this means something funky was passed in
      // but oh well...
      if (!bSomethingLoaded)
      {
         delete m_SnaccEnvelopedData.originatorInfo;
         m_SnaccEnvelopedData.originatorInfo = NULL;
      }
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      // cleanup based on bSomethingLoaded
   SME_CATCH_FINISH
}

void CSM_DataToEncrypt::SetRecipientInfo(CSM_CSInst &cInst, CSM_Buffer &UKMBuf,
                              CSM_RecipientIdentifier &rid,
                              CSM_Buffer &BufEMEK,
                              AsnOid &algID,
                              CSM_Buffer &bufParams)
{

   CSM_RecipientInfo *pRecipientInfo=NULL;
   CSM_Alg *pkeyEncryptionAlgId = NULL;


   SME_SETUP("CSM_DataToEncrypt::SetRecipientInfo"); 

   if(!m_bSharedUkms || !cInst.AccessTokenInterface()->SMTI_IsKeyAgreement())
   {
      pRecipientInfo = new CSM_RecipientInfo;
      if (pRecipientInfo == NULL)
             SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      if (cInst.AccessTokenInterface()->SMTI_IsKeyAgreement())
      {                          // RWC; Load appropriate RI info
         pRecipientInfo->choiceId = RecipientInfo::kariCid;
         pRecipientInfo->kari = new KeyAgreeRecipientInfo;
         pRecipientInfo->kari->version = 3;  // SEE ASN.1 specification

         if (UKMBuf.Length())
         {
            pRecipientInfo->kari->ukm = new UserKeyingMaterial;
            pRecipientInfo->kari->ukm->Set(UKMBuf.Access(), 
                                    UKMBuf.Length());
         }
      }     // IF IsKeyAgreement 2
      else                       // RWC; symmetric encryption alg, key transfer.
      {
         pRecipientInfo->choiceId = RecipientInfo::ktriCid;
         pRecipientInfo->ktri = new KeyTransRecipientInfo;
         pRecipientInfo->ktri->version = 0;  // SEE ASN.1 specification
      }     // END if IsKeyAgreement
   
     if (!cInst.AccessTokenInterface()->SMTI_IsKeyAgreement())
        pRecipientInfo->ktri->version = 2;  // SEE ASN.1 specification

     if (cInst.AccessTokenInterface()->SMTI_IsKeyAgreement())
     {
        CSM_Identifier *ptmpId = NULL;

        if(m_pKeyEncryptionOID == NULL)
        {
          // RWC; Load originator component of ->kari.
          ptmpId = cInst.GetRid();
        }
        else
        {
          CSM_Alg keyAlg;
          CSM_Buffer *pPubkey = cInst.AccessTokenInterface()->GetDynamicPublicKey(keyAlg);

          if(pPubkey)
          {
            ptmpId = new CSM_RecipientIdentifier(*pPubkey,keyAlg);
            delete pPubkey;
          }

        }
        /* temp variable */
        CSM_RecipientIdentifier tmprecip(*ptmpId);
        pRecipientInfo->SetOriginatorID(tmprecip);

        if(ptmpId != NULL)
          delete ptmpId;
     }      // IF IsKeyAgreement 3
     else
     {
      // set the version of the recipient info
      // TBD, currently we set the version to zero because 
      // OriginatorCert is defaulted to absent and RecipientIdentifier
      // defaults to issuerAndSerialNumber
      // RWC;pRecipientInfo->version = SM_ENV_DATA_PREV_VERSION;
      // TBD, eventually, add code to conditionally 
      // set SM_ENV_DATA_VERSION if conditions are met
      //pRecipientInfo->ktri->version = 2;  // SEE ASN.1 specification
     }      // END IF IsKeyAgrreement 3

      pRecipientInfo->SetEncryptedKey(BufEMEK);
      pRecipientInfo->SetRid(rid);
      pRecipientInfo->SetKeyEncryptionAlgorithm(algID, bufParams);
   
      m_SnaccEnvelopedData.recipientInfos.append(*pRecipientInfo);
   }     // IF !IsKeyAgreement()
   else              // Attempt to share UKM/KeyAgree Dynamic key.
   {
      // Loop through RecipientInfo for cInst KeyEncryptionAlgorithm
     // TBD

     pkeyEncryptionAlgId = CSM_SignBuf::GetPreferredKeyEncryptionAlg(cInst);

     RecipientInfos::iterator itTmpRIs;
     for (itTmpRIs = m_SnaccEnvelopedData.recipientInfos.begin();
          itTmpRIs != m_SnaccEnvelopedData.recipientInfos.end(); 
          ++itTmpRIs)
     {
        pRecipientInfo = new CSM_RecipientInfo(*itTmpRIs);
        if (pRecipientInfo)
        {
            /* temp variable */
            CSM_Alg tmpalg(*pRecipientInfo->AccesskeyEncryptionAlgorithm());
            if(*pkeyEncryptionAlgId == tmpalg)
            {
               m_SnaccEnvelopedData.recipientInfos.erase(itTmpRIs);  
                                  // SINCE we will be re-inserting a new entry.
                                  // KEEP "pRecipientInfo" for next conditional
            }   // IF tmpalg
            else
            {
                delete pRecipientInfo;
                pRecipientInfo = NULL;
            }   // END IF algs match
        }       // END IF pRecipientInfo
     }          // END FOR RIs

     if (pRecipientInfo != NULL)
     {
        //RecipientEncryptedKey &TmpRIKey ;
        if (pRecipientInfo->m_pRecipientEncryptedKeysIterator == NULL)
            pRecipientInfo->m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
        *pRecipientInfo->m_pRecipientEncryptedKeysIterator = pRecipientInfo->kari->recipientEncryptedKeys.append();
        pRecipientInfo->SetEncryptedKey(BufEMEK);
        pRecipientInfo->SetRid(rid);     
     }      // IF pRecipientInfo
     else if(pRecipientInfo == NULL)
     {
       //SharedUkms, but first RI in list, to be shared by others
         if ((pRecipientInfo = new CSM_RecipientInfo) /* *)m_SnaccEnvelopedData.
               recipientInfos.Append())*/ == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

         pRecipientInfo->kari = new KeyAgreeRecipientInfo;
         pRecipientInfo->choiceId = RecipientInfo::kariCid;
         pRecipientInfo->kari->version = 3;  // SEE ASN.1 specification

         if (UKMBuf.Length())
         {
             pRecipientInfo->kari->ukm = new UserKeyingMaterial;
             pRecipientInfo->kari->ukm->Set(UKMBuf.Access(), 
                                    UKMBuf.Length());
         }
            // RWC; Load originator component of ->kari.
         //CS pRecipientInfo->SetOriginatorCertID(*cInst.AccessIssuerAndSerialNumber());
         pRecipientInfo->SetEncryptedKey(BufEMEK);
         pRecipientInfo->SetRid(rid);
         pRecipientInfo->SetKeyEncryptionAlgorithm(algID,bufParams);
     }      // END if pRecipientInfo

     m_SnaccEnvelopedData.recipientInfos.append(*pRecipientInfo);
            // place new, or replace original SNACC RI.
     delete pRecipientInfo;   //DELETE working instance.

     if(pkeyEncryptionAlgId != NULL)
        delete pkeyEncryptionAlgId;

   }     // END if IsKeyAgreement

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      // cleanup based on bSomethingLoaded
   SME_CATCH_FINISH
}        //CSM_DataToEncrypt::SetRecipientInfo


CSM_DataToEncrypt::~CSM_DataToEncrypt()
{
   if (m_pKeyEncryptionOID)
      delete m_pKeyEncryptionOID;
   if (m_pKeyWrapOID)
      delete m_pKeyWrapOID;
   if (m_pImportedMEK)
      delete m_pImportedMEK;
}

//////////////////////////////////////////////////////////////////////////
void CSM_DataToEncrypt::AddRecipient(CSM_CSInst *pInst, 
                                   CSM_RecipientInfo *pRecip, 
                                   CSM_Buffer &bufMEK,
                                   CSM_RecipientInfoLst   *pRecipients,
                                   CSM_Alg *pContentEncryptionAlg)
{
   CSM_Alg *pAlg=NULL;

   SME_SETUP("CSM_DataToEncrypt::AddRecipient");
   if (pRecip->m_pCert != NULL)
       pAlg = pRecip->m_pCert->GetPublicKeyAlg();

   if (pInst == NULL)
      SME_THROW(SM_MISSING_PARAM, "No LOGIN Instance specified.", NULL);

   if (pRecip && pRecip->m_pPWRIDetails != NULL)
   {     
       // sending in the pContentEncryptionAlg
       // for default in case the KeyEncryptContentWrapOid not
       // given for PWRI
       AddRecipientPWRI(pInst, pRecip, bufMEK, pRecipients,pContentEncryptionAlg);
   }       
   else if (pRecip && pRecip->m_pKEKDetails == NULL && pAlg && 
       pAlg->algorithm != rsaEncryption &&  //RWC;AVOIDS false use of CTIL.
       pInst->AccessTokenInterface()->SMTI_IsKeyAgreement())
   {        // MUST check for KEK, since we use DH logins for KEK for processing.
       AddRecipientKARI(pInst, pRecip, bufMEK, pRecipients);
   }        // IF IsKeyAgreement
   else if (pRecip->m_pKEKDetails != NULL)
   {
       AddRecipientKEK(pInst, pRecip, bufMEK, pRecipients);
   }
   else if (pRecip && pRecip->m_pCert && pAlg &&
            pAlg->algorithm == rsaEncryption &&  //RWC;AVOIDS false use of CTIL.
           !pInst->AccessTokenInterface()->SMTI_IsKeyAgreement())
   {            // MUST have recipient certificate...
       AddRecipientKTRI(pInst, pRecip, bufMEK, pRecipients);
   }
   else if (pRecip && pRecip->m_pKEKDetails == NULL && pAlg &&
       pAlg->algorithm != rsaEncryption &&  //RWC;AVOIDS false use of CTIL.
       pInst->AccessTokenInterface()->SMTI_IsKeyAgreement())
   {
       AddRecipientLOCAL(pInst, pRecip, bufMEK, pRecipients);
   }
   else
   {
       SME_THROW(22, "CANNOT AddRecipient, inconsistent variables!", NULL);
   }        // END IF IsKeyAgreement




    if (pAlg)
        delete pAlg;



   SME_FINISH
   SME_CATCH_SETUP
    if (pAlg)
        delete pAlg;
   SME_CATCH_FINISH
}       // END CSM_DataToEncrypt::AddRecipient(...)


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
void CSM_DataToEncrypt::AddRecipientKARI(CSM_CSInst *pInst, 
                                   CSM_RecipientInfo *pRecip, 
                                   CSM_Buffer &bufMEK,
                                   CSM_RecipientInfoLst   *pRecipients)
{
   CSM_RecipientInfo tmpRecip;
   CSM_Alg *pAlg=NULL;
   CSM_Buffer bufSubjKeyId;
   CSM_RecipientIdentifier tmpRID;
   CSM_RecipientIdentifier *pTmpRid=NULL;
   CSM_CtilInst *pInstKeyWrap=NULL;
   CSM_Buffer bufKeyAgree;
   CSM_Buffer *pTmpIV=NULL;
   CSM_Buffer contentEncryptParams;
   CSM_Alg WrapAlg;
   long lKekLength=0;
   CSM_Buffer *pbufRecipKey=NULL;

   SME_SETUP("CSM_DataToEncrypt::AddRecipientKARI");

   if (pRecip)
       pRecip->choiceId = SNACC::RecipientInfo::kariCid;  // HARDCODE KARI for follow-on processing.
   //**** GET the public key algorithm for the recipient or local key or specified.
   if (m_pKeyEncryptionOID == NULL)
   {
      if (pRecip && pRecip->m_pCert)
      {
         SME(pAlg = pInst->DeriveMsgAlgFromCert(*pRecip->m_pCert));
      }
   }
   else           // USE specified algorithm, overriding certs (THEY BETTER BE
                  //  CONSISTENT WITHIN THE ALG LIBRARY).
   {
      if (pRecip && pRecip->m_pCert)
      {
         SME(pAlg = pInst->DeriveMsgAlgFromCert(*pRecip->m_pCert));
         pAlg->algorithm = *m_pKeyEncryptionOID;
                                 // KEEP Params, but override OID
         // NOW, load the recipient parameters, since at least
         //  one KeyEncryption alg uses the Recipient's Params (e.g. ESDH).
         //  It is assumed that since an appropriate CSM_CSInst/CTIL was chosen
         //  to process this recipient, that the new overridden 
         //  m_pKeyENcryptionOID is compatible with these recipient params!!!
         if (pAlg->parameters != NULL)
         {
            SM_EXTRACT_ANYBUF(pRecip->m_pbufParams, pAlg->parameters );
         }
      }
      else
      {
         if (pAlg)
            delete pAlg;   // Already created above; delete for memory mgmt.
         SME(pAlg = new CSM_Alg(*m_pKeyEncryptionOID));
      }
   }

   //**** UKM may be NULL the first time here, it will be loaded here for the
   //  next use.  (RWC;TBD; CLEANUP to not produce UKM under KEK build).
   if (!m_bNoUkmFlag && (pRecip == NULL || pRecip->m_pUkmBuf == NULL))
   {
      RecipientInfo *pSNACCRecipientInfo;

      if (pRecip == NULL)
         pRecip = &tmpRecip;  // Point to local working copy for processing.
      if(m_bSharedUkms && (pSNACCRecipientInfo = pRecip->
        GetSharedRI(m_SnaccEnvelopedData.recipientInfos, *pAlg, pRecipients)) 
           != NULL && 
           pSNACCRecipientInfo->choiceId == RecipientInfo::kariCid &&
           pSNACCRecipientInfo->kari->ukm && 
           pSNACCRecipientInfo->kari->ukm->Len())
      {
         //Preloading UKM from shared RecipientInfo
         pRecip->m_pUkmBuf = new CSM_Buffer(pSNACCRecipientInfo->kari->ukm->c_str(),
            pSNACCRecipientInfo->kari->ukm->Len());
      }
      else
        pRecip->m_pUkmBuf = new CSM_Buffer;     // Blank, to be filled in by SMTI.
                                    // RWC; DO NOT FREE if assigned or "new".
   }


     if (pAlg)
     {
        // FIRST, Set the appropriate algorithm for the KeyEncryption
        AsnOid  *pTmpKeyEncryptionOID=pAlg->GetId();
        pInst->SetPreferredCSInstAlgs(NULL, NULL, pTmpKeyEncryptionOID, NULL);
        delete pTmpKeyEncryptionOID;
     }
     if (pRecip->m_pbufParams == NULL)
        pRecip->m_pbufParams = new CSM_Buffer;

     //**** NEXT, perform the encryption process.
     if (pRecip && pRecip->m_pCert)
     { 
       SME(pbufRecipKey = pRecip->m_pCert->GetPublicKey());
       // normal way using a recipient
                  // Key agreement generation and Key Wrap are now separated in
                  //  CMS; this allows for example, DH KARI with 3DES/RC2/AES wrapping.
          // FIRST, determine an appropriate KeyWrap encryption engine (CTIL)
          if (m_pKeyWrapOID)  // Then look for a different potential SMTI
          {                   //  since the key wrap alg may not be in
                              //  this SMTI.  If not specified, default.
             //RWC;1/18/00;This condition should always be met now, since it is
             //RWC;         set in the Encrypt(...) method to Content Encryption
             //RWC;         OID to force alignment.
             WrapAlg.algorithm = (*m_pKeyWrapOID);

             //**** FIRST, check ours to see if we can do this.
             if (!pInst->FindAlgIds(NULL, NULL, NULL, &WrapAlg))
             {
               pInstKeyWrap = m_pCsmime->FindCSInstAlgIds(NULL, NULL, NULL, 
                  &WrapAlg);
               if (pInstKeyWrap == NULL)
               {
                  SME_THROW(SM_NO_SUPPORTING_INSTANCE, 
                     "No instance supports requested key wrap alg.", NULL);
               }
             }    // END if pInst wrap alg not found
             else
                pInstKeyWrap = pInst;  //  Encryption alg.
             pInstKeyWrap->SetPreferredCSInstAlgs(NULL, NULL, NULL, 
                m_pKeyWrapOID);  // SET for ALL conditions.
          }       // END if KeyWrapOID specified
          else                // Default to this CTIL instance Content 
          {
             pInstKeyWrap = pInst;  //  Encryption alg.
          }
          //**** SECOND, generate an appropriately sized initialization vector for 
          //  KeyWrap to be processed in the KeyAgree key generation call.
          //  NOTE: this may be overridden if the KARI params are present and
          //  already contain an IV; the KARI IV will be used.  If not already
          //  set, the default KeyWrap Alg will be set.
          pTmpIV = pInstKeyWrap->AccessTokenInterface()->SMTI_GenerateKeyWrapIV(
              lKekLength, &WrapAlg);

          //**** THIRD, generate KeyAgreement; may use settings determined from 
          //   above logic extracted from another RI/RIKEY  OR  create new 
          //   values for UKM and Paramate IV.
          if (!this->m_bSharedUkms) // FORCE new dynamic gen for ESDH...
              pInst->AccessTokenInterface()->ClearDynamicKey();
          SME(pInst->AccessTokenInterface()->SMTI_GenerateKeyAgreement(
            pbufRecipKey, pRecip->m_pbufParams, 
            pRecip->m_pUkmBuf, pTmpIV, m_pKeyWrapOID, &bufKeyAgree, lKekLength));
          // FOURTH, Call the Key Wrap encryption method.
          SME(pInstKeyWrap->AccessTokenInterface()->SMTI_GenerateKeyWrap(&bufMEK,
            &pRecip->m_bufEMEK, &contentEncryptParams, &bufKeyAgree, pTmpIV));
          // Override the parameters for Key Wrap, not necessary according to 
          //  CMS. (Encrypt always loads IV in parameters for 3DES).
          if (pRecip->m_pbufParams)    // Previously used for processing.
          {
             delete pRecip->m_pbufParams;
             pRecip->m_pbufParams = NULL;
          }
          ENCODE_BUF(&WrapAlg, pRecip->m_pbufParams);
                     // THE PARAMETER to the KeyAgree ALG is the KeyWrap Alg.

       delete pbufRecipKey;
       pbufRecipKey = NULL;
       //if (pbufKeyAgree)
       //   delete pbufKeyAgree;
       if (pTmpIV)
       {
         delete pTmpIV;
         pTmpIV = NULL;
       }
     }

      // get a pointer to the returned subject key id
      const char *pchSKID;
      SME(pchSKID = bufSubjKeyId.Access());


      //Load OriginatorIdentifier
      if(m_pKeyEncryptionOID == NULL)
      {
       // RWC; Load originator component of ->kari.
       CSM_Identifier *pTmpId=pInst->GetRid(this->m_bIssOrSki);
       if (pTmpId)
       {
          pRecip->m_pOrigRID = new CSM_RecipientIdentifier(*pTmpId);
          delete pTmpId;
       }    // END if pTmpId
      }
      else
      {
          CSM_Alg keyAlg;
          CSM_Buffer *pPubkey = pInst->AccessTokenInterface()->GetDynamicPublicKey(keyAlg);

          if(pPubkey)
          {
            if (keyAlg.algorithm == id_alg_ESDH &&  keyAlg.parameters != NULL)
            {                 // DO NOT SEND PARAMS FOR Ephemeral-Static DH.
                delete keyAlg.parameters;
                keyAlg.parameters = NULL;
            }
            pRecip->m_pOrigRID = new CSM_RecipientIdentifier(*pPubkey,keyAlg);
            delete pPubkey;
          }

      }

      // if we have a recipient, go with that recipient's issuer
      // and serial number as the rid
      if (pRecip && pRecip != &tmpRecip)   // NOT LOCAL COPY.
      {
        pTmpRid = pRecip->GetRid();
      }

      if (pRecip && pRecip != &tmpRecip && pTmpRid)   // NOT LOCAL COPY.
      {
       tmpRID = *pTmpRid;
       delete pTmpRid;
      }
      else if (pchSKID != NULL) // no recipient, but we have a skid,
         // use that as the rid
      {
         tmpRID.SetSubjectKeyIdentifier(bufSubjKeyId);
      }
      else // no recipient and no skid, use this instance's issuer
         // and serial number as the rid (MAY be localKey), but we error here.
      {
          SME_THROW(22, "MUST have Recipient Identifier!", NULL);
      }
 
      // Finish loading RecipientInfo information and load SNACC RecipienInfo
      //  (May load existing RI, not necessarily create a new RI.
      pRecip->choiceId = RecipientInfo::kariCid;    // PRE-Set as flag to create/load.
      pRecip->SetRid(tmpRID);
      if (pAlg)
        pRecip->m_pencryptionAlgOid = pAlg->GetId();

   pRecip->m_bIssOrSki = this->m_bIssOrSki;
   pRecip->LoadSNACCRecipientInfo(*pInst, m_SnaccEnvelopedData.recipientInfos, 
      m_bSharedUkms, *pAlg, pRecipients);

   // if the originator hasn't been included and the originator
   // should be included then find out if this recipient
   // is an originator
   // RWC;TBD; HANDLE KEK setup for a login, for now only recipients
   // RWC;TBD;   can be KEK, not the originator; expect "m_bAddOriginatorAsRecipient"
   // RWC;TBD;   to be false.
   if ((pRecip) && (!m_bOriginatorIncluded) && (m_bAddOriginatorAsRecipient))
   {
      // compare the recipient's issuer and serial number with
      // this instance's issuer and serial number or subject key id.
      CSM_Identifier *pTmpRID = pRecip->GetRid();
      CSM_Identifier *pTmpRIDInst = NULL;

      if (pTmpRID)
        pTmpRIDInst = pInst->GetRid(*pTmpRID);

      if (pTmpRIDInst && pTmpRID && *pTmpRIDInst == *pTmpRID)
         m_bOriginatorIncluded = true;

      if (pTmpRID) 
        delete pTmpRID;
      if(pTmpRIDInst)
         delete pTmpRIDInst;
   }

   if (pAlg)
      delete pAlg;

   SME_FINISH
   SME_CATCH_SETUP
      if (pAlg)
        delete pAlg;
      if (pTmpIV)
        delete pTmpIV;
      if (pbufRecipKey)
         delete pbufRecipKey;
   SME_CATCH_FINISH
}       // END CSM_DataToEncrypt::AddRecipientKARI(...)

//////////////////////////////////////////////////////////////////////////
void CSM_DataToEncrypt::AddRecipientKTRI(CSM_CSInst *pInst, 
                                   CSM_RecipientInfo *pRecip, 
                                   CSM_Buffer &bufMEK,
                                   CSM_RecipientInfoLst   *pRecipients)
{
   CSM_RecipientInfo tmpRecip;
   CSM_Alg *pAlg=NULL;
   CSM_Buffer bufSubjKeyId;
   CSM_RecipientIdentifier tmpRID;
   CSM_RecipientIdentifier *pTmpRid=NULL;
   CSM_Buffer *pbufRecipKey=NULL;

   SME_SETUP("CSM_DataToEncrypt::AddRecipientKTRI");

   if (pRecip)
       pRecip->choiceId = SNACC::RecipientInfo::ktriCid;  // HARDCODE KTRI for follow-on processing.
   // get the public key algorithm for the recipient or local key or specified.
      if (pRecip && pRecip->m_pCert)
      {
         SME(pAlg = pInst->DeriveMsgAlgFromCert(*pRecip->m_pCert));
      }

   // generate the EMEK
     if (pAlg)      // May not use key encryption, but content encryption (KEK).
     {
        // FIRST, Set the appropriate algorithm for the KeyEncryption
        AsnOid  *pTmpKeyEncryptionOID=pAlg->GetId();
        pInst->SetPreferredCSInstAlgs(NULL, NULL, pTmpKeyEncryptionOID, NULL);
        delete pTmpKeyEncryptionOID;
     }
     if (pRecip->m_pbufParams == NULL)
        pRecip->m_pbufParams = new CSM_Buffer;

     // NEXT, perform the encryption process.
     if (pRecip && pRecip->m_pCert)
     { 
        if (m_bKTRI_RSAES_OAEPflag)
        {
            AsnOid oidRSAES_OAEP(id_RSAES_OAEP);
            pInst->SetPreferredCSInstAlgs(NULL, NULL, &oidRSAES_OAEP, NULL);
        }       // IF m_bKTRI_RSAES_OAEPflag

       SME(pbufRecipKey = pRecip->m_pCert->GetPublicKey());
       // normal way using a recipient
       SME(pInst->AccessTokenInterface()->SMTI_GenerateEMEK(
            pbufRecipKey, pRecip->m_pbufParams, &bufMEK, &pRecip->m_bufEMEK, 
            NULL/*pRecip->m_pUkmBuf IGNORED*/, &bufSubjKeyId));
       delete pbufRecipKey;
       pbufRecipKey = NULL;
     }
     else
     {
         SME_THROW(26, "BAD instance for Key Transfer Recipient Info processing.", NULL);
     }

      // get a pointer to the returned subject key id
      const char *pchSKID;
      SME(pchSKID = bufSubjKeyId.Access());


      //Load OriginatorIdentifier
      if(m_pKeyEncryptionOID == NULL)
      {
       // RWC; Load originator component of ->kari.
       CSM_Identifier *pTmpId=pInst->GetRid(this->m_bIssOrSki);
       if (pTmpId)
       {
          pRecip->m_pOrigRID = new CSM_RecipientIdentifier(*pTmpId);
          delete pTmpId;
       }    // END if pTmpId
      }

      // if we have a recipient, go with that recipient's issuer
      // and serial number as the rid
      if (pRecip && pRecip != &tmpRecip)   // NOT LOCAL COPY.
      {
        pTmpRid = pRecip->GetRid();
      }

      if (pRecip && pRecip != &tmpRecip && pTmpRid)   // NOT LOCAL COPY.
      {
       tmpRID = *pTmpRid;
       delete pTmpRid;
      }
      else if (pchSKID != NULL) // no recipient, but we have a skid,
         // use that as the rid
      {
         tmpRID.SetSubjectKeyIdentifier(bufSubjKeyId);
      }
      else // no recipient and no skid
      {
          SME_THROW(22, "MUST have Recipient Identifier!", NULL);
      }
 
      // Finish loading RecipientInfo information and load SNACC RecipienInfo
      //  (May load existing RI, not necessarily create a new RI.
      pRecip->SetRid(tmpRID);
      if (pAlg)
      {
         if (this->m_bKTRI_RSAES_OAEPflag)
            pRecip->m_pencryptionAlgOid = new AsnOid(id_RSAES_OAEP);
         else
            pRecip->m_pencryptionAlgOid = pAlg->GetId();
      }     // END IF pAlg

   pRecip->m_bIssOrSki = this->m_bIssOrSki;
   pRecip->LoadSNACCRecipientInfo(*pInst, m_SnaccEnvelopedData.recipientInfos, 
      m_bSharedUkms, *pAlg, pRecipients);

   // if the originator hasn't been included and the originator
   // should be included then find out if this recipient
   // is an originator
   // RWC;TBD; HANDLE KEK setup for a login, for now only recipients
   // RWC;TBD;   can be KEK, not the originator; expect "m_bAddOriginatorAsRecipient"
   // RWC;TBD;   to be false.
   if ((pRecip) && (!m_bOriginatorIncluded) && (m_bAddOriginatorAsRecipient))
   {
      // compare the recipient's issuer and serial number with
      // this instance's issuer and serial number or subject key id.
      CSM_Identifier *pTmpRID = pRecip->GetRid();
      CSM_Identifier *pTmpRIDInst = NULL;

      if (pTmpRID)
        pTmpRIDInst = pInst->GetRid(*pTmpRID);

      if (pTmpRIDInst && pTmpRID && *pTmpRIDInst == *pTmpRID)
         m_bOriginatorIncluded = true;

      if (pTmpRID) 
        delete pTmpRID;
      if(pTmpRIDInst)
         delete pTmpRIDInst;
   }

   if (pAlg)
      delete pAlg;

   SME_FINISH
   SME_CATCH_SETUP
      if (pAlg)
        delete pAlg;
      if (pbufRecipKey)
         delete pbufRecipKey;
   SME_CATCH_FINISH
}       // END CSM_DataToEncrypt::AddRecipientKTRI(...)

//////////////////////////////////////////////////////////////////////////
void CSM_DataToEncrypt::AddRecipientKEK(CSM_CSInst *pInst, 
                                   CSM_RecipientInfo *pRecip, 
                                   CSM_Buffer &bufMEK,
                                   CSM_RecipientInfoLst   *pRecipients)
{
   CSM_RecipientInfo tmpRecip;
   CSM_RecipientIdentifier tmpRID;
   CSM_Buffer bufKeyAgree;
   CSM_Buffer *pTmpIV=NULL;
   CSM_Buffer contentEncryptParams;
   CSM_Alg AlgDummy;    // Place holder only.
   long lKekLength=0;

   SME_SETUP("CSM_DataToEncrypt::AddRecipientKEK");


       CSM_Alg WrapAlg;
       if (pRecip)
          pRecip->choiceId = RecipientInfo::kekriCid;   // HARDCODE for follow-on processing.
       // This RI simply encrypts the RI key using the specified content 
       //  encryption alg.
        // FIRST, Set the appropriate algorithm for the KeyEncryption
        AsnOid  *pTmpKeyEncryptionOID=pRecip->m_pKEKDetails->
            m_keyEncryptionAlgorithm.GetId();
        pInst->SetPreferredCSInstAlgs(NULL, NULL, NULL, pTmpKeyEncryptionOID);
        delete pTmpKeyEncryptionOID;

        // NEXT, encrypt the data with the user specified key data.  (GOOD LUCK
        //  attempting to figure out what this is really doing; carefully read
        //  the CMS specifications about the KEK concepts.)
        // encrypt the provided MEK used to encrypt the content.
        if (pRecip->m_pbufParams == NULL)
            pRecip->m_pbufParams = new CSM_Buffer;
       //SME(pInst->AccessTokenInterface()->SMTI_Encrypt(&bufMEK,
       //  &pRecip->m_bufEMEK, pRecip->m_pbufParams, 
       //  &pRecip->m_pKEKDetails->m_UserEncryptionData));
          pTmpIV = pInst->AccessTokenInterface()->SMTI_GenerateKeyWrapIV(lKekLength,
              &WrapAlg);
          SME(pInst->AccessTokenInterface()->SMTI_GenerateKeyWrap(&bufMEK,
              &pRecip->m_bufEMEK, &contentEncryptParams, 
              &pRecip->m_pKEKDetails->m_UserEncryptionData, pTmpIV));
          if (pRecip->m_pbufParams)    // Previously used for processing.
          {
             delete pRecip->m_pbufParams;
             pRecip->m_pbufParams = NULL;
          }
          //RWC;KEEP Parameters, even if NULL.
          SM_EXTRACT_ANYBUF(pRecip->m_pbufParams, WrapAlg.parameters);
      // Finish loading RecipientInfo information and load SNACC RecipienInfo
      //  (May load existing RI, not necessarily create a new RI.
      //pRecip->m_RID = pRecip->m_pKEKDetails->m_RID; 
                                         
      pRecip->m_pencryptionAlgOid = 
         pRecip->m_pKEKDetails->m_keyEncryptionAlgorithm.GetId();
      if (pTmpIV)
      {
         delete pTmpIV;
         pTmpIV = NULL;
      }

   pRecip->m_bIssOrSki = this->m_bIssOrSki;
   pRecip->LoadSNACCRecipientInfo(*pInst, m_SnaccEnvelopedData.recipientInfos, 
      m_bSharedUkms, AlgDummy, pRecipients);


   SME_FINISH
   SME_CATCH_SETUP
      if (pTmpIV)
        delete pTmpIV;
   SME_CATCH_FINISH
}       // END CSM_DataToEncrypt::AddRecipientKEK(...)

//////////////////////////////////////////////////////////////////////////
//
//  Function Name:  AddRecipientPWRI
//
//  Description:   Recipient information using a user-supplied password or
//                 previously agreed-upon key is represented in the type
//                 PasswordRecipientInfo.  Each instance of passwordRecipientInfo
//                 will transfer the content-encryption key (CEK) to one or 
//                 more recipients who have the previously agreed-upon password 
//
//
void CSM_DataToEncrypt::AddRecipientPWRI(CSM_CSInst *pInst, 
                                   CSM_RecipientInfo *pRecip, 
                                   CSM_Buffer &bufMEK,
                                   CSM_RecipientInfoLst   *pRecipients,
                                   CSM_Alg *pContentEncryptionAlg)
{
   CSM_RecipientInfo       tmpRecip;
   CSM_RecipientIdentifier tmpRID;
   CSM_Buffer              bufKeyAgree;
   CSM_Buffer              tmpIV;
   CSM_Alg                 AlgDummy;    // Place holder only.
   //M_Alg                 *pPWRIDerivationAlg = NULL;
  // CSM_Alg                 *pPWRIEncryptionAlg = NULL;
   long                    lStatus = 0;
   CSM_Alg WrapAlg;

   SME_SETUP("CSM_DataToEncrypt::AddRecipientPWRI");  

   if (pRecip)
      pRecip->choiceId = RecipientInfo::pwriCid;  // HARDCODE for follow-on processing.

   if (pRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm == NULL)
   {
      SNACC::AsnOid tmpOid(id_alg_PWRI_KEK);
      // set the keyEncryptionAlgorithm if not already
       pRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm = 
          new CSM_Alg(tmpOid);
   }

   if (pRecip->m_pPWRIDetails->m_pKeyEncryptContentWrapOid == NULL && 
      pContentEncryptionAlg != NULL)
   {
       // default to contentEncryptionAlg in case the KeyEncryptContentWrapOid not
       // given for PWRI
       pRecip->m_pPWRIDetails->m_pKeyEncryptContentWrapOid = 
          new AsnOid(pContentEncryptionAlg->algorithm);
   }

   if (pRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm->parameters == NULL &&
       pRecip->m_pPWRIDetails->m_pKeyEncryptContentWrapOid != NULL)
   {
       // set the parameters for the keyEncryptContentWrapOid Alg
       CSM_Alg tmpAlg(*pRecip->m_pPWRIDetails->m_pKeyEncryptContentWrapOid);
       CSM_Buffer tmpBuf;
       tmpBuf.Encode(tmpAlg);
       pRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm->parameters = new AsnAny;
       tmpBuf.Decode(*pRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm->parameters);
   }

   // NEXT, encrypt the data with the user specified key data.  (GOOD LUCK
   //  attempting to figure out what this is really doing; carefully read
   //  the CMS specifications about the PWRI concepts.)
   // encrypt the provided MEK used to encrypt the content.
   if (pRecip->m_pbufParams == NULL)
     pRecip->m_pbufParams = new CSM_Buffer;

   // NEEDED input for the SMTI_GeneratePWRIKeyWrap call
   //    mek                  - message encryption key data to encrypt 
   //    iv                   - salt   
   //    m_UserEncryptionData - password for key wrapping
   //    derivationAlg        - id-PBKDF2 for now
   //    EncryptionAlg        - id-alg-PWRI-KEK for now
   SME(lStatus = pInst->AccessTokenInterface()->SMTI_GeneratePWRIKeyWrap(&bufMEK, 
           &pRecip->m_bufEMEK, &tmpIV,  
           &pRecip->m_pPWRIDetails->m_UserEncryptionData,  // password
           pRecip->m_pPWRIDetails->m_pUserKeyEncryptionKey,
           (CSM_AlgVDA *&)pRecip->m_pPWRIDetails->m_pKeyDerivationAlgorithm, 
           (CSM_AlgVDA *&)pRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm));

   if (lStatus != 0)
      SME_THROW(22, "Error Generating PWRI Key Wrap", NULL);

   // assign the alg oids for recip
   pRecip->m_pKeyEncryptionAlgOid = 
      pRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm->GetId();   

   if (pRecip->m_pPWRIDetails->m_pKeyDerivationAlgorithm != NULL)
   {
      pRecip->m_pKeyDerivationAlgOid = 
         pRecip->m_pPWRIDetails->m_pKeyDerivationAlgorithm->GetId();
   }

          
   if (pRecip->m_pbufParams)    // Previously used for processing.
   {
      delete pRecip->m_pbufParams;
      pRecip->m_pbufParams = NULL;
   }
          
   //KEEP Parameters, even if NULL.
   SM_EXTRACT_ANYBUF(pRecip->m_pbufParams, pRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm->parameters);

   pRecip->LoadSNACCRecipientInfo(*pInst, m_SnaccEnvelopedData.recipientInfos, 
      m_bSharedUkms, AlgDummy, pRecipients);


   SME_FINISH
   SME_CATCH_SETUP
//      if (pTmpIV)
//        delete pTmpIV;
   SME_CATCH_FINISH
}       // END CSM_DataToEncrypt::AddRecipientPWRI(...)

//////////////////////////////////////////////////////////////////////////
void CSM_DataToEncrypt::AddRecipientLOCAL(CSM_CSInst *pInst, 
                                   CSM_RecipientInfo *pRecip, 
                                   CSM_Buffer &bufMEK,
                                   CSM_RecipientInfoLst   *pRecipients)
{
   CSM_RecipientInfo tmpRecip;
   const IssuerAndSerialNumber *pTmpIssSer;
   CSM_Alg *pAlg=NULL;
   CSM_RecipientIdentifier tmpRID;
   CSM_Buffer bufKeyAgree;
   CSM_Buffer *pTmpIV=NULL;
   CSM_Buffer contentEncryptParams;
   CSM_Alg WrapAlg;
   long lKekLength=0;
   CSM_Buffer *pbufRecipKey=NULL;

   SME_SETUP("CSM_DataToEncrypt::AddRecipientLOCAL");


   // get the public key algorithm for the recipient or local key or specified.
   if (m_pKeyEncryptionOID == NULL || !pInst->AccessTokenInterface()->SMTI_IsKeyAgreement())
   {
      AsnOid  *pOid=pInst->AccessTokenInterface()->GetLocalKeyAlg();
      SME(pAlg = new CSM_Alg(*pOid));
      delete pOid;
   }

   // The UKM may be NULL the first time here, it will be loaded here for the
   //  next use.  (RWC;TBD; CLEANUP to not produce UKM under KEK build).
   if (!m_bNoUkmFlag && (pRecip == NULL || pRecip->m_pUkmBuf == NULL))
   {
        pRecip->m_pUkmBuf = new CSM_Buffer;     // Blank, to be filled in by SMTI.
                                    // RWC; DO NOT FREE if assigned or "new".
   }


   // generate the EMEK
     if (pAlg)      // May not use key encryption, but content encryption (KEK).
     {
        // FIRST, Set the appropriate algorithm for the KeyEncryption
        AsnOid  *pTmpKeyEncryptionOID=pAlg->GetId();
        pInst->SetPreferredCSInstAlgs(NULL, NULL, pTmpKeyEncryptionOID, NULL);
        delete pTmpKeyEncryptionOID;
     }
     if (pRecip->m_pbufParams == NULL)
        pRecip->m_pbufParams = new CSM_Buffer;

     // NEXT, perform the encryption process.
        // alternate way using local key
          pTmpIV = pInst->AccessTokenInterface()->SMTI_GenerateKeyWrapIV(lKekLength);
          SME(pInst->AccessTokenInterface()->SMTI_GenerateKeyAgreement(
            NULL, pRecip->m_pbufParams, 
            pRecip->m_pUkmBuf, pTmpIV, m_pKeyWrapOID, &bufKeyAgree, lKekLength));
          SME(pInst->AccessTokenInterface()->SMTI_GenerateKeyWrap(&bufMEK,
            &pRecip->m_bufEMEK, &contentEncryptParams, &bufKeyAgree, pTmpIV));
          if (pRecip->m_pbufParams)    // Previously used for processing.
          {
             delete pRecip->m_pbufParams;
             pRecip->m_pbufParams = NULL;
          }
          pRecip->m_pbufParams = CSM_Alg::GetNullParams();

      //Load OriginatorIdentifier
      if(m_pKeyEncryptionOID == NULL)
      {
           // RWC; Load originator component of ->kari.
           CSM_Identifier *pTmpId=pInst->GetRid(this->m_bIssOrSki);
           if (pTmpId)
           {
              pRecip->m_pOrigRID = new CSM_RecipientIdentifier(*pTmpId);
              delete pTmpId;
           }    // END if pTmpId
      }

      if ((pTmpIssSer = pInst->AccessIssuerAndSerialNumber()->
            AccessSNACCIssuerAndSerialNumber()) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         CSM_IssuerAndSerialNumber tmpIss(*pTmpIssSer); 
         tmpRID.SetIssuerAndSerial(tmpIss);
 
      // Finish loading RecipientInfo information and load SNACC RecipienInfo
      //  (May load existing RI, not necessarily create a new RI.
      pRecip->SetRid(tmpRID);
      if (pAlg)
        pRecip->m_pencryptionAlgOid = pAlg->GetId();

   pRecip->m_bIssOrSki = this->m_bIssOrSki;
   pRecip->LoadSNACCRecipientInfo(*pInst, m_SnaccEnvelopedData.recipientInfos, 
      m_bSharedUkms, *pAlg, pRecipients);


   if (pAlg)
      delete pAlg;

   SME_FINISH
   SME_CATCH_SETUP
      if (pAlg)
        delete pAlg;
      if (pTmpIV)
        delete pTmpIV;
      if (pbufRecipKey)
         delete pbufRecipKey;
   SME_CATCH_FINISH
}       // END CSM_DataToEncrypt::AddRecipientLOCAL(...)

//////////////////////////////////////////////////////////////////////////
void CSM_DataToEncrypt::ProcessRecipients(CSMIME *pCSMIME,
                                        CSM_RecipientInfoLst *pRecipients,
                                        CSM_Buffer &bufMEK,
                                        CSM_Alg *pContentEncryptionAlg)
{
    CSM_RecipientInfoLst::iterator itTmpRecip;
   CSM_CSInst   *pTmpInstCS;
   CSM_CtilInstLst::iterator itTmpInst;
   CSM_Alg *pKeyAlgTmp = NULL;      // FOR key encryption (kari, ktri) recips
   CSM_Alg *pContentAlgTmp = NULL;  // FOR Content encryption (KEK) recip
   CSM_CtilInst *pTmpInstance2;

   SME_SETUP("CSM_DataToEncrypt::ProcessRecipients");

   m_bOriginatorIncluded = false;

   /////////////////////////////////////////////////
   // go through pRecipients and load RecipientInfos
   if (pRecipients) // normal recipient processing
   {
      for (itTmpRecip =  pRecipients->begin();
           itTmpRecip != pRecipients->end();
           ++itTmpRecip)
      {
         // setup recipient's Alg
         if (itTmpRecip->m_pKEKDetails)   //Handle KEK recip
         {
            pContentAlgTmp = new CSM_Alg(itTmpRecip->m_pKEKDetails->
               m_keyEncryptionAlgorithm);

            if ((pTmpInstance2 = pCSMIME->FindCSInstAlgIds(NULL, NULL, NULL,
               pContentAlgTmp)) == NULL)
              SME_THROW(SM_NO_SUPPORTING_INSTANCE, 
               "no instance supports requested kek encr alg", NULL);

            pTmpInstance2->SetUseThis();

            pKeyAlgTmp = NULL;
         }
         else if (itTmpRecip->m_pPWRIDetails)
         {
            if (itTmpRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm!= NULL &&
               itTmpRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm->parameters != NULL)
            {
               // do decode the params if present
               AlgorithmIdentifier tmpAlg;
               CSM_Buffer tmpBuf;
               tmpBuf.Encode(
                  *itTmpRecip->m_pPWRIDetails->m_pKeyEncryptionAlgorithm->parameters);
               tmpBuf.Decode(tmpAlg);
               pContentAlgTmp = new CSM_Alg(tmpAlg);
            }
            else
            {
               pContentAlgTmp = new CSM_Alg(*pContentEncryptionAlg);
            }
            
            if ((pTmpInstance2 = pCSMIME->FindCSInstAlgIds(NULL, NULL, NULL,
               pContentAlgTmp)) == NULL)
              SME_THROW(SM_NO_SUPPORTING_INSTANCE, 
               "no instance supports requested pwri encr alg", NULL);

            pTmpInstance2->SetUseThis();

            pKeyAlgTmp = NULL;

         }
         else if (itTmpRecip->m_pCert)       // Handle kari, ktri recips
         {
           SME(pKeyAlgTmp = itTmpRecip->m_pCert->GetPublicKeyAlg());
           pContentAlgTmp = NULL;
         }

         // find a UseThis instance that support's this recipient's KM Alg
         for (itTmpInst =  pCSMIME->m_pCSInsts->begin();
              itTmpInst != pCSMIME->m_pCSInsts->end();
              ++itTmpInst)
         {
            // is this instance marked for use?
            pTmpInstCS = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
            if (pTmpInstCS && pTmpInstCS->IsThisUsed())
            {
               // is this recipient's alg supported by this instance?
               if (pTmpInstCS->FindAlgIds(NULL,NULL,pKeyAlgTmp,pContentAlgTmp))
               {
                  // all conditions met, encrypt the MEK with this instance
                  // for this recipient... sending in the ContentEncryptionAlg
                  // for default in case the KeyEncryptContentWrapOid not
                  // given for PWRI
                  SME(AddRecipient(pTmpInstCS, &(*itTmpRecip), bufMEK, pRecipients, 
                     pContentEncryptionAlg));

                  // now that we've created the new recipient info, we don't 
                  // want to continue searching through the instances so
                  // break out of the instance loop and continue processing
                  // the recipients
                  break;
               }
            }        // END IF instance handles certificates AND Used.
         }           // END FOR each login instance in list.

       if (pKeyAlgTmp)
       {
           delete pKeyAlgTmp;
           pKeyAlgTmp = NULL;  // avoid re-deleting if errors occur.
       }
       if (pContentAlgTmp)
       {
          delete pContentAlgTmp;
          pContentAlgTmp = NULL;
       }

      }         // END FOR each RI in list.
   }
   else // no recipients, do local key encryption
   {
      // find a UseThis instance to do the key encryption
      for (itTmpInst =  pCSMIME->m_pCSInsts->begin();
           itTmpInst != pCSMIME->m_pCSInsts->end();
           ++itTmpInst)
      {
         // is this instance marked for use?
         pTmpInstCS = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
         if (pTmpInstCS && pTmpInstCS->IsThisUsed() && 
             pTmpInstCS->AccessTokenInterface()->SMTI_IsKeyAgreement())
         {                          // LOCAL KEY processing only for KeyAgree.
            // encrypt the MEK using a local key and this instance
            SME(AddRecipient(pTmpInstCS, NULL, // recip is null
                  bufMEK, pRecipients, NULL));
            // now that we've created the new recipient info, we don't 
            // want to continue searching through the instances so
            // break out of the instance loop and continue processing
            break;
         }      // END IF instance handles certificates AND Used.
      }         // END FOR each login instance in list.
   }

   // if we are supposed to add the originator and the originator hasn't 
   // already been included, then add it now
   if ((m_bAddOriginatorAsRecipient) && (!m_bOriginatorIncluded))
   {
      // first, find an originator (instance marked UseThis)
      for (itTmpInst =  pCSMIME->m_pCSInsts->begin();
           itTmpInst != pCSMIME->m_pCSInsts->end();
           ++itTmpInst)
      {
         pTmpInstCS = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
         if (pTmpInstCS && pTmpInstCS->IsThisUsed() && pTmpInstCS->IsEncrypter()) 
         {
            // create a temporary recipient from the user cert in
            // the originator's instance
            //RWC9;CSM_CertificateChoiceLst *pCerts = pTmpInstCS->AccessCertificates();
            //RWC9;if (pCerts == NULL) // no cert? break out and go on
            //RWC9;   break;
            const CSM_CertificateChoice *pCert = pTmpInstCS->AccessUserCertificate();
            CSM_RecipientInfo recipOriginator(*pCert);//RWC9;*(pCerts->First()));
            SME(AddRecipient(pTmpInstCS, &recipOriginator, bufMEK, pRecipients, NULL));
            break;
         }
      }         // END FOR each login instance in list.
   }
   
   SME_FINISH
   SME_CATCH_SETUP
      if (pKeyAlgTmp)
         delete pKeyAlgTmp;
   SME_CATCH_FINISH
}

////////////////////////////////////////////////////////////////////////////////
//
// Function Name GetEnvDataVersion()
//
// Description:
//
//        IF (originatorInfo is present) AND
//            ((any certificates with a type of other are present) OR
//            (any crls with a type of other are present))
//         THEN version is 4
//         ELSE
//            IF ((originatorInfo is present) AND
//               (any version 2 attribute certificates are present)) OR
//               (any RecipientInfo structures include pwri) OR
//               (any RecipientInfo structures include ori)
//            THEN version is 3
//            ELSE
//               IF (originatorInfo is absent) OR
//                  (unprotectedAttrs is absent) OR
//                  (all RecipientInfo structures are version 0)
//               THEN version is 0
//               ELSE version is 2
//
// Inputs:     NONE
//
// Outputs:    NONE
//
// Returns:    NONE
//
////////////////////////////////////////////////////////////////////////////////
long CSM_DataToEncrypt::GetEnvDataVersion()
{
   long lRet = SM_ENV_DATA_VERSION;
   bool bFoundCurVersion = false;
   RecipientInfos::iterator itRecipientInfo;

   SME_SETUP("CSM_DataToEncrypt::GetEnvDataVersion");

   // IF (originatorInfo is present) AND
   //            ((any certificates with a type of other are present) OR
   //            (any crls with a type of other are present))
   //         THEN version is 4
    if (m_SnaccEnvelopedData.originatorInfo != NULL) 
       
   {
      if (m_SnaccEnvelopedData.originatorInfo->certs != NULL)
      {
         CertificateSet::iterator itTmpCertSet;
         for (itTmpCertSet  = m_SnaccEnvelopedData.originatorInfo->certs->begin();
              itTmpCertSet != m_SnaccEnvelopedData.originatorInfo->certs->end();
              ++itTmpCertSet)
         {
            if (itTmpCertSet->choiceId == CertificateChoices::otherCid)
            {
               lRet = 4;
               bFoundCurVersion = true;
            }
         }
   
      }
      
      if (bFoundCurVersion == false && m_SnaccEnvelopedData.originatorInfo->crls != NULL)
      {
         RevocationInfoChoices::iterator itTmpCertSet;
         for (itTmpCertSet  = m_SnaccEnvelopedData.originatorInfo->crls->begin();
              itTmpCertSet != m_SnaccEnvelopedData.originatorInfo->crls->end();
              ++itTmpCertSet)
         {
            // Construct a temporary RevocationInfoChoice object
           RevocationInfoChoice tmpRevInfoChoice;

            // decode the RevocationInfoChoice
            unsigned long iBytesDecoded=0;
            try 
            {
               tmpRevInfoChoice.BDec(*(*itTmpCertSet).anyBuf, iBytesDecoded);
               if (tmpRevInfoChoice.choiceId == RevocationInfoChoice::otherCid)
               {		          
                  // there is an other crl
                  lRet = 4;
                  bFoundCurVersion = true;
               }
            }
            catch(...)
            {
               // do nothing - it could be a CRL list
            }
         }
      }

   } // end if there is OriginatorInfo
 
   for (itRecipientInfo = m_SnaccEnvelopedData.recipientInfos.begin();
        bFoundCurVersion != true && itRecipientInfo != m_SnaccEnvelopedData.recipientInfos.end();
        ++itRecipientInfo)
   {
      // check if RecipientInfo includes a pwri or
      // or RecipientInfo includes an ori - if so set to version 3
      if ((itRecipientInfo->choiceId == RecipientInfo::oriCid /*3*/) ||
          (itRecipientInfo->choiceId == RecipientInfo::pwriCid /*4*/) )
      {
          bFoundCurVersion = true;
          lRet = 3;  /* set version to 3 */
      }
      else if (itRecipientInfo->choiceId == RecipientInfo::ktriCid)
      {              // Key Transfer recipient.
          if (itRecipientInfo->ktri->version != 0)
              bFoundCurVersion = true;
      }
      else           // Key Agreement recipient.
      {
          bFoundCurVersion = true;
      }
   }        // END FOR each RI in list

   // from CMS: version in the syntax version number.  If originatorInfo
   // is present, then version shall be 2.  If any of the RecipientInfo
   // structures included have a version of 2, then the version shall be
   // 2.  If originatorInfo is absent and all of the RecipientInfo 
   // structures are version 0, then version shall be 0.
   if ((m_SnaccEnvelopedData.originatorInfo == NULL) &&
         (!bFoundCurVersion))
      lRet = SM_ENV_DATA_PREV_VERSION; // version 0
   else
   {
      // if lRet not already set to 3 - found pwri or ori previously
      if (lRet < 3 && m_SnaccEnvelopedData.originatorInfo && 
                      m_SnaccEnvelopedData.originatorInfo->certs)
      {
         lRet = SM_ENV_DATA_VERSION;  // set version to v2 - 1 

         // check if V2 AttributeCertificates are present, then version is 3
         CertificateSet::iterator itTmpCertSet;
         for (itTmpCertSet = m_SnaccEnvelopedData.originatorInfo->certs->begin();
             itTmpCertSet != m_SnaccEnvelopedData.originatorInfo->certs->end();
             ++itTmpCertSet)
         {
            if (itTmpCertSet->choiceId == CertificateChoices::v2AttrCertCid)
            {
               CSM_CertificateChoice *pAC = new CSM_CertificateChoice(*itTmpCertSet);

               if (pAC)
               {
                   if (pAC->AccessSNACCAttrCertificate() &&
                       pAC->AccessSNACCAttrCertificate()->toBeSigned.version &&
                       *pAC->AccessSNACCAttrCertificate()->toBeSigned.version == 1 /*V2*/)
                          lRet = 3;   // NEW for RFC3369
                   delete pAC;
               } // END IF pAC
            } // END IF attrCertCid
         }    // END FOR each originator cert
      }       // END IF lRet < 3 (version value)
   }          // END IF originatorInfo

   SME_FINISH_CATCH

   return lRet;
}

//////////////////////////////////////////////////////////////////////////
// CSM_DataToEncrypt::Encrypt uses the provided parameters and whatever
// is already available in the content and exposed m_SnaccEnvelopedData
// to generate the EnvelopedData.  If pRecipients == NULL then we're doing
// a local key encryption
void CSM_DataToEncrypt::Encrypt(CSMIME *pCSMIME,
                                    CSM_MsgCertCrls *pMsgCertCrls,
                                    CSM_RecipientInfoLst *pRecipients,
                                    AsnOid  *poidContentType,
                                    CSM_Buffer *pContent,
                                    CSM_Alg *pContentEncryptionAlg,
                                    CSM_Buffer *pOutputBuf)
{
   CSM_Buffer bufContentParameters, bufEncryptedContent, bufMEK;
   CSM_CtilInst *pTmpInstance;
   EncryptedContentInfo *pECI; // temporary snacc pointer
   AsnOid  oidOrigContent;
   AsnOid  *pTmpOid;
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_DataToEncrypt::Encrypt");

   // check incoming parameters and values
   if ((pCSMIME == NULL && m_pCsmime==NULL) || (pContent == NULL) || 
       (pOutputBuf == NULL) ||
       (pContentEncryptionAlg == NULL) || (pCSMIME->m_pCSInsts == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   if (m_pImportedMEK == NULL && pContent->Access() == NULL)
            // pContent is not used if MEK is imported (already encrypted).
      SME_THROW(SM_ENCRYPTION_UNPREPARED,
            "provided content is empty", NULL);
   // TBD, check pContentEncryptionAlg for something in it???
   if (pCSMIME)
      m_pCsmime = pCSMIME;

   // FIRST, see if this message has already been content encrypted.
   pECI = &m_SnaccEnvelopedData.encryptedContentInfo;
   if (pECI->encryptedContent == NULL || pECI->encryptedContent->Len() == 0)
   {                 // THEN build it, perform content encryption.
      // find the first pCSMIME->instance that can do the requested
      // content encryption algorithm
      //RWC:NOTE:: MUST BE CAREFUL HERE since some CTILs MUST have the content
      //   encrypttion performed by the exact same instance as the Key wrapping.
      if ((pTmpInstance = pCSMIME->FindCSInstAlgIds(NULL, NULL, NULL,
               pContentEncryptionAlg)) == NULL)
         SME_THROW(SM_NO_SUPPORTING_INSTANCE, 
               "no instance supports requested content encr alg", NULL);

      // lock the CTI
      SME(pCSMIME->InstanceLock(SM_INST_USE_THIS));

      // RWC; Before encrypting, set our preferred algorithm (just in case it is 
      // RWC;  not the default).
      pTmpInstance->GetPreferredCSInstAlgs(NULL, NULL, NULL, &oidOrigContent);
      pTmpOid = pContentEncryptionAlg->GetId();
      pTmpInstance->SetPreferredCSInstAlgs(NULL, NULL, NULL, pTmpOid);
      // RWC;1/17/00; THIS KeyWrap OID is defaulted to the Content Encryption alg.
      if (m_pKeyWrapOID == NULL)  // ONLY if not specified by the user
         m_pKeyWrapOID = pTmpOid; // memory given to new pointer.
      else
         delete pTmpOid;         // Deleted only if not assigned.
      ///////////////////////////////
      // OPTIONALLY encrypt the provided content
      if (m_pImportedMEK == NULL)
      {
          if ((status = pTmpInstance->AccessTokenInterface()->SMTI_Encrypt(pContent,
                &bufEncryptedContent, &bufContentParameters, &bufMEK)) != SM_NO_ERROR)
             SME_THROW(status, "SMTI_Encrypt returned error.", NULL);
      }     // IF m_pImportedMEK not present.
      else
      {
          SME_THROW(22, "MEK Imported, but encryptedContent not present!", NULL);
      }

      // RWC; Reset original perferred algorithm.
      pTmpInstance->SetPreferredCSInstAlgs(NULL, NULL, NULL, &oidOrigContent);

      ///////////////////////////////////////////////////////
      // load the encrypted content into m_SnaccEnvelopedData
      // store content type
      pECI->contentType.Set(*poidContentType);
      // store alg OID
      pECI->contentEncryptionAlgorithm.algorithm = (*pContentEncryptionAlg->AccessSNACCId());
      // store alg parameters
      if (bufContentParameters.Access() != NULL)
      {
         if ((pECI->contentEncryptionAlgorithm.parameters = new AsnAny) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
         SM_ASSIGN_ANYBUF((&bufContentParameters), 
               pECI->contentEncryptionAlgorithm.parameters);
      }
      // store encrypted content
      if ((pECI->encryptedContent = new EncryptedContent) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
      pECI->encryptedContent->Set(bufEncryptedContent.Access(), 
            bufEncryptedContent.Length());
   }     // IF content already encrypted for this message.
   else
   {
      ///////////////////////////////////////////////
      // IT IS EXPECTED THAT THE CALLING APPLICATION HAS SETUP the appropriate
      //    details to create a new RecipientInfo since already content encrypted.
      // Access IMPORTED MEK or error...
      if (this->m_pImportedMEK)
      {
         bufMEK = *m_pImportedMEK;  // pre-load from import definition...
      }
      else
      {
         SME_THROW(22, "CONTENT already encrypted but m_pImportedMEK not loaded!", 
            NULL);
      }
   }     // END if already encrypted...

   ///////////////////////////////////////////////
   // load up OriginatorInfo based on pMsgCertCrls
   // that were provided by the caller
   SME(LoadFromMsgCertCrls(pMsgCertCrls));

   /////////////////////////
   // Process the recipients sending in the contentEncryptionAlg for default of
   // keyEncryptionContentWrapOid in case none was specified for PWRI
   SME(ProcessRecipients(pCSMIME, pRecipients, bufMEK, pContentEncryptionAlg));

   // finished generating EMEKs, unlock the CTI
   SME(pCSMIME->InstanceUnlock(SM_INST_USE_THIS));

   ///////////////////////////////////////////////////////////
   // set the version for the enveloped data
   // loop through the recipient infos to find out if there is
   // a high version
   m_SnaccEnvelopedData.version = GetEnvDataVersion();

   if (!m_bIncludeContent && 
        m_SnaccEnvelopedData.encryptedContentInfo.encryptedContent)
   {
       // LOAD member variable with encrypted content before deleting.
       m_pOPTIONALEncryptedContent = new CSM_Buffer(
           m_SnaccEnvelopedData.encryptedContentInfo.encryptedContent->c_str(),
           m_SnaccEnvelopedData.encryptedContentInfo.encryptedContent->Len());
       delete m_SnaccEnvelopedData.encryptedContentInfo.encryptedContent;
       m_SnaccEnvelopedData.encryptedContentInfo.encryptedContent = NULL;
   }    // END if m_bIncludeContent
   // finished filling m_SnaccEnvelopedData, ASN.1 encode it...
   ENCODE_BUF_NO_ALLOC(&m_SnaccEnvelopedData, pOutputBuf);

   // TBD, any local cleanup necessary?

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      // unlock the CTI
   SME_CATCH_FINISH
}
//
void CSM_MsgToEncrypt::ReportMsgData(std::ostream &os)
{
   SME_SETUP("CSM_MsgToEncrypt::ReportMsgData(ostream &os)");

   os << "CSM_MsgToEncrypt::ReportMsgData(ostream &os)\n";
   os << m_SnaccEnvelopedData << "\n";
   

   if(m_pRecipients != NULL)
   {

     // Check actual message, not components of the CSM_ class.
     RecipientInfos::iterator itTmpRI;
     for (itTmpRI = m_SnaccEnvelopedData.recipientInfos.begin();
          itTmpRI != m_SnaccEnvelopedData.recipientInfos.end(); 
          ++itTmpRI)
        {

            CSM_RecipientInfo  recipInfo(*itTmpRI);
            CSM_RecipientIdentifier *tmpRID;

             tmpRID = recipInfo.GetRid();

             if (tmpRID != NULL)
                tmpRID->ReportMsgData(std::cout);

             if(tmpRID)
               delete tmpRID;


        }    // END FOR RecipientLst
   }         // END IF m_pRecipients

   os.flush();

   SME_FINISH_CATCH
}           // END CSM_MsgToEncrypt::ReportMsgData(...)


///////////////////////////////////////////////////////////////////////////
//
//
CSM_MsgToReEncrypt::CSM_MsgToReEncrypt(CSMIME &Csmime, CSM_MsgToDecrypt &DecryptedMsg)
{
   CSM_CertificateChoiceLst *pOrigCerts = NULL;

   SME_SETUP("CSM_MsgToReEncrypt::CSM_MsgToReEncrypt");

   // PRE-load raw SNACC decoded data
   CSM_MsgToEncrypt::m_SnaccEnvelopedData = DecryptedMsg.m_SnaccEnvelopedData;
   SetContentEncryptOID(&DecryptedMsg.m_SnaccEnvelopedData.
                 encryptedContentInfo.contentEncryptionAlgorithm.algorithm);
   m_pCsmime = &Csmime;
   SetAddOriginatorAsRecipient(false);

   // SETUP CSM_DataToDecrypt inherited class items
   CSM_DataToDecrypt::m_SnaccEnvelopedData = DecryptedMsg.m_SnaccEnvelopedData;
   m_pKEKDetailsLst = DecryptedMsg.m_pKEKDetailsLst;
   CSM_DataToDecrypt::m_pKeyWrapOID = DecryptedMsg.m_pKeyWrapOID;


   // re-DECRYPT the message to access the MEK, if possible (if not we exception).
   if (DecryptedMsg.m_pOriginatorInfo && 
       DecryptedMsg.m_pOriginatorInfo->m_pMsgCertCrls)
       pOrigCerts = DecryptedMsg.m_pOriginatorInfo->m_pMsgCertCrls->AccessCertificates();
   SetEncryptInternalData(DecryptedMsg, pOrigCerts); // USE previously processed recipient certs, etc.

   SME_FINISH_CATCH

}       // END CSM_MsgToReEncrypt::CSM_MsgToReEncrypt(...)

//
//
CSM_MsgToReEncrypt::~CSM_MsgToReEncrypt()
{
}


//
//
void CSM_MsgToReEncrypt::SetEncryptInternalData(CSM_MsgToDecrypt &DecryptedMsg,
                                          const CSM_CertificateChoiceLst *pCertList)
{
   CSM_Buffer bufPlainText;
   SME_SETUP("CSM_MsgToReEncrypt::SetEncryptInternalData");

   // At this point, we need the actual content encryption key (hopefully, we 
   //  can get it; if this application does not use a CTIL that allows a 
   //  separate content encryption key then we cannot re-encrypt in this 
   //  fashion).  (e.g. MS CAPI or Fortezza require that the content encryption
   //  key never be off the card/CAPI store, so it is not possible to extract it
   //  and re-encrypt to a new recipient).
   if (m_pRecipients)   //ONLY if something to attempt to decrypt...
   {
       this->m_bExportMEK = true;    // ask that the MEK be exported for our use.
       this->Decrypt(m_pCsmime, (CSM_CertificateChoiceLst *)pCertList, &bufPlainText, 
                                 m_pRecipients);
       // If we survived, now lets see if we were successful with any RecipientInfo(s)
       //CSM_Content *pContent = this->AccessEncapContent();
       if (bufPlainText.Length() &&  // BE sure decryption worked.
           m_pExportedMEK)           // Check that clear MEK available.
       {              // THEN we have succeeded, try to access the MEK used...
          m_pImportedMEK = new CSM_Buffer(*this->m_pExportedMEK);
       }     // END if encap content length.
   }        // END if m_pRecipients

   SME_FINISH_CATCH
}       // END CSM_MsgToReEncrypt::SetEncryptInternalData(...)

//
//
CSM_Buffer *CSM_MsgToReEncrypt::GetReEncryptedContentInfo()
{
    CSM_Buffer *pResultBuf=NULL;
    SME_SETUP("CSM_MsgToReEncrypt::GetReEncryptedContentInfo");

    if (m_pImportedMEK)
    {
        if (this->m_pRecipients != NULL) // ONLY re-encrypt if new recipient(s)
        {
           Encrypt(this->m_pCsmime);
        }       // IF any recipients.
        else
        {
            SME_THROW(22, "Existing login CTILs could not extract a clear MEK!", 
                      NULL);
        }
    }
    else        // JUST re-encode existing entry.
    {
        CSM_Buffer *pEDBuf=NULL;
        ENCODE_BUF(&this->CSM_DataToEncrypt::m_SnaccEnvelopedData, pEDBuf);
        SME(CSM_MsgToEncrypt::UpdateEncodedBlob(pEDBuf));     // DO NOT DELETE memory.
    }       // END if any recipients.

    pResultBuf = this->GetEncodedContentInfo();

    SME_FINISH_CATCH

    return(pResultBuf);
}       // END GetReEncryptedContentInfo()

//
//
CSM_Buffer *CSM_MsgToReEncrypt::GetReEncodedContentInfo()
{
    CSM_Buffer *pResultBuf=NULL;
    SME_SETUP("CSM_MsgToReEncrypt::GetReEncodedContentInfo");

    CSM_Buffer *pEDBuf=NULL;
    ENCODE_BUF(&this->CSM_DataToEncrypt::m_SnaccEnvelopedData, pEDBuf);
    SME(CSM_MsgToEncrypt::UpdateEncodedBlob(pEDBuf));     // DO NOT DELETE memory.
    pResultBuf = this->GetEncodedContentInfo();

    SME_FINISH_CATCH

    return(pResultBuf);
}       // END GetReEncodedContentInfo()

_END_SFL_NAMESPACE




// EOF sm_Encrypt.cpp
