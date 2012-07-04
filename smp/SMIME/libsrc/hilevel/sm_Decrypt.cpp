
//////////////////////////////////////////////////////////////////////////
// sm_Decrypt.cpp
// Implementation of the CSM_MsgToDecrypt and CSM_DataToDecrypt classes.
// CSM_MsgToDecrypt is for high level use.  The app developer should
// not have to directly access the snacc generated classes.
// CSM_DataToDecrypt is for low level use.  The app may have to
// directly access the exposed snacc generated class.  Both
// classes have the purpose of decrypting a CMS EnvelopedData
// based on the provided input (primarily the marked sessions
// in the CSMIME).
//////////////////////////////////////////////////////////////////////////

#include <string.h>
#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToDecrypt Constructors
//////////////////////////////////////////////////////////////////////////
CSM_MsgToDecrypt::CSM_MsgToDecrypt(CSMIME *pCSMIME, const CSM_Buffer *pBlob)
{
   SME_SETUP("CSM_MsgToDecrypt::CSM_MsgToDecrypt(csmime)");

   Clear();
   if (pBlob)
   {
      CSM_CommonData::SetEncodedBlob(pBlob);
      if (pCSMIME)
         SME(PreProc(pCSMIME, pBlob));
   }
   SME_FINISH_CATCH;
}

//
//
CSM_MsgToDecrypt::CSM_MsgToDecrypt(const CSM_ContentInfoMsg *pCIM)
{
   CSM_Buffer *pbufEncodedBlob;

   SME_SETUP("CSM_MsgToDecrypt::CSM_MsgToDecrypt(pCIM)");

   Clear();
   if (pCIM)
   {
      SME(pbufEncodedBlob = new CSM_Buffer(((CSM_ContentInfoMsg *)pCIM)->AccessEncapContentFromAsn1()->m_content));//>AccessEncodedBlob());
      if (pbufEncodedBlob)
      {
          // ASN.1 decode the provided pbufEnvelopedData
          DECODE_BUF((&m_SnaccEnvelopedData), pbufEncodedBlob);

          SME(this->SetEncodedBlob(((CSM_ContentInfoMsg *)pCIM)->AccessEncodedBlob()));
          delete pbufEncodedBlob;
      }
   }
   SME_FINISH_CATCH
}

CSM_MsgToDecrypt::CSM_MsgToDecrypt(CSMIME *pCSMIME, const CSM_ContentInfoMsg *pCIM)
{
   CSM_Buffer *pbufEncodedBlob;

   SME_SETUP("CSM_MsgToDecrypt::CSM_MsgToDecrypt(pCSMIME, pCIM)");

   Clear();
   if (pCIM)
   {
      pbufEncodedBlob = new CSM_Buffer(((CSM_ContentInfoMsg *)pCIM)->AccessEncapContentFromAsn1()->m_content);

      // ASN.1 decode the provided pbufEnvelopedData
      DECODE_BUF((&m_SnaccEnvelopedData), pbufEncodedBlob);

      SME(UpdateEncodedBlob(pbufEncodedBlob));

      if (pCSMIME)
         SME(PreProc(pCSMIME));
   }
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
CSM_MsgToDecrypt::~CSM_MsgToDecrypt()
{
   if (m_pOriginatorInfo)
      delete m_pOriginatorInfo;
   if (m_pRecipients)
      delete m_pRecipients;
   if (m_pACLOriginatorCertBuf)
      delete m_pACLOriginatorCertBuf;
   if (m_poidEncryptionAlg)
      delete m_poidEncryptionAlg;
   if (m_poidDerivationAlg)
      delete m_poidDerivationAlg;

}

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToDecrypt::Decrypt
//////////////////////////////////////////////////////////////////////////
void CSM_MsgToDecrypt::Decrypt(CSMIME *pCSMIME)
{
   CSM_CertificateChoiceLst *pOrigCerts = NULL;
   CSM_Buffer bufPlainText;
   CSM_RecipientInfo *pRecipInfo=NULL;
   SME_SETUP("CSM_MsgToDecrypt::Decrypt");

   // load m_pOriginatorInfo into pOrigCerts
   if ((m_pOriginatorInfo) && (m_pOriginatorInfo->m_pMsgCertCrls))
      pOrigCerts = m_pOriginatorInfo->m_pMsgCertCrls->AccessCertificates();

   // call low level decrypt
   SME(CSM_DataToDecrypt::Decrypt(pCSMIME, pOrigCerts, &bufPlainText, m_pRecipients));

   // create content from the decrypted plain text
   SetEncapContentFromAsn1((const CSM_Buffer &)bufPlainText, 
      m_SnaccEnvelopedData.encryptedContentInfo.contentType);

   SME_FINISH
   SME_CATCH_SETUP
      if (pRecipInfo)
         delete pRecipInfo;      // CLEAR tmp CSM_RecipientInfo.
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToDecrypt::PreProc-s
//////////////////////////////////////////////////////////////////////////
void CSM_MsgToDecrypt::PreProc(CSMIME *pCSMIME)
{
   SME_SETUP("CSM_MsgToDecrypt::PreProc csmime");
   // call lower level PreProc that will process with pCSMIME
   SME(CSM_DataToDecrypt::PreProc(pCSMIME));
   // generate the m_pOriginatorInfo from the SNACC originatorInfo
   // for the application's convenience
   if (m_SnaccEnvelopedData.originatorInfo != NULL)
   {
     SME(m_pOriginatorInfo = new CSM_OriginatorInfo(m_SnaccEnvelopedData.
         originatorInfo));
   }
   // generate the m_pRecipients from the SNACC recipientInfos
   // for the application's convenience
   SME(AddSNACCRecipients());

   SME_FINISH_CATCH
}

void CSM_MsgToDecrypt::PreProc(CSMIME *pCSMIME, const CSM_Buffer *pBlob)
{
   SME_SETUP("CSM_MsgToDecrypt::PreProc buf csmime");
   // Decode the provided blob
   CSM_DataToDecrypt::Decode(pBlob);
   // call other high level PreProc that will generate m_pRecipients
   // and m_pOriginatorInfo for application's use
   SME(PreProc(pCSMIME));
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_MsgToDecrypt::AddSNACCRecipients()
{
   CSM_RecipientInfo *pRI;

   SME_SETUP("CSM_MsgToDecrypt::AddSNACCRecipients");

   pRI = GetFirstRecipientInfo();
   while (pRI != NULL)    // This loop now reflects that there can be multiple
                          //  recipients in a single RecipientInfo (sharing the
                          //  same UMK).
   {
      if (m_pRecipients == NULL)
      {
         if ((m_pRecipients = new CSM_RecipientInfoLst) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      }
      CSM_RecipientInfo *pTmpRi = &(*m_pRecipients->append());
      pTmpRi->AssignSNACCRI(*pRI);

      //RWC; DUE TO a change in how the present CURR value is identified, we 
      //RWC;  must re-align the newly created value here (not stored in eSNACC).
        if (pRI->choiceId == RecipientInfo::kariCid)
        {         // MUST check again for Kari, since may have moved to new RI.
          //RWC Set curr in new to same index entry.
          if (pTmpRi->m_pRecipientEncryptedKeysIterator == NULL)
              pTmpRi->m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
          for (RecipientEncryptedKeys::iterator TmpRecipientEncryptedKeysIterator=
                             pRI->kari->recipientEncryptedKeys.begin();
               TmpRecipientEncryptedKeysIterator != pRI->kari->recipientEncryptedKeys.end();
               ++TmpRecipientEncryptedKeysIterator)
          {
                   if (pRI->m_pRecipientEncryptedKeysIterator && 
                       TmpRecipientEncryptedKeysIterator == *pRI->m_pRecipientEncryptedKeysIterator)
                       break;
                   else
                       ++*pTmpRi->m_pRecipientEncryptedKeysIterator; // KEEP counting new Key(s)
          }     // END FOR any original iterators.
        }   // END IF kari

      delete pRI;    // ALWAYS copied.
      pRI = GetNextRecipientInfo();
   }

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToDecrypt::ReportMsgData
//////////////////////////////////////////////////////////////////////////
void CSM_MsgToDecrypt::ReportMsgData(std::ostream &os)
{

   CSM_RecipientInfoLst::iterator itRecipInfo;
   int i;
   bool bDecrypted=false;
   unsigned char *ptr=NULL;
   CSM_RecipientIdentifier *tmpRID=NULL;

   SME_SETUP("CSM_MsgToDecrypt::ReportMsgData");

   os << m_SnaccEnvelopedData << "\n";
   

   if (m_pRecipients)
   {
     // RWC; NOW check which RecipientInfo was decrypted, inform tester, then
     // RWC;  decrypt remaining entries.
     for (i=0, itRecipInfo = m_pRecipients->begin();
          itRecipInfo != m_pRecipients->end();
          ++itRecipInfo, i++)
        {
           if (itRecipInfo->WasDecrypted())
           {
              bDecrypted = true;
              if (itRecipInfo->choiceId !=  RecipientInfo::pwriCid)
              {
                 tmpRID = itRecipInfo->GetRid();
                 tmpRID->ReportMsgData(os);
                 if(tmpRID)
                   delete tmpRID;
                 tmpRID = NULL;
              } // END if WasDecrypted()
           }    // END IF ! pwri
        }       // END For RecipientLst.
   }            // END if m_pRecipients

   if (bDecrypted)      // If any RecipientInfo was successful...
   {
       os << "##### DECRYPTED CONTENT #######\n";
       ReportCommonData(os);
       os << "\n##### END DECRYPTED CONTENT #######\n";
   }        // END if bDecrypted

   os.flush();

   //RWC;10/10/02;if(pRecipInfo)
   //RWC;10/10/02;   delete pRecipInfo;

   SME_FINISH
   SME_CATCH_SETUP
      //RWC;10/10/02;if(pRecipInfo)
      //RWC;10/10/02;   delete pRecipInfo;
      if(tmpRID)
         delete tmpRID;
      if (ptr)
         free (ptr);
   SME_CATCH_FINISH

}

//////////////////////////////////////////////////////////////////////////
//  CSM_MsgToDecrypt::ACLCheckoutCerts:  This method is intended to be called 
//  after the content has been decrypted and processed, thereby filling in the
//  RecipientInfo certifiate(s) and Originator information.  The intended 
//  architecture implies that the application would use CSM_MsgToVerify to 
//  extract the security label SignedAttribute from the SignerInfo and provide
//  it to the CSM_MsgToDecrypt::m_ACLInterface instance for proper ACL processing.
long CSM_MsgToDecrypt::ACLCheckoutCerts()
{
   long lstatus = -2;
#ifdef ACL_USED
   CSM_RecipientInfoLst::iterator itRI;
   SME_SETUP("CSM_MsgToDecrypt::ACLCheckoutCerts");

   // OPTIONALLY ACL validate the originator AND Recipient(s).
   //IGNORED, since this is an explicit application call!;if (this->m_bACLUseToValidate)
   for (itRI =  m_pRecipients->begin();
        itRI != m_pRecipients->end();
        ++itRI)
      // This loop now reflects that there can be multiple
      //  recipients in a single RecipientInfo (sharing the
      //  same UMK).
   {        // RWC;NOTE; potential errors to "m_ACLInterface" are accummulated.
          acl::SPIF *pspif=NULL;// TO BE FILLED in by Recip check, if available
                                //  to be used for OPTIONAL Orig check if 
                                //  performed.
          // FIRST, check recipient(s) (normally ourselves).
          if (itRI->WasDecrypted())  // ONLY ACL validate decrypted recipients.
          {
               if (itRI->m_pCert != NULL && 
                   itRI->m_pCert->AccessEncodedCert() != NULL)
               {
                   if (m_lCmlSessionId)
                      lstatus = CMLValidateCert(itRI->m_ACMLCert, itRI->m_pCert);
                                // IN THIS SPECIFIC CASE, CML was not previously called...
                   if (lstatus == 0 && this->m_ACLInterface.GetACLSessionId() &&
                       itRI->m_pCert)
                      lstatus = this->m_ACLInterface.Check_ACLIncommingRecip(
                       itRI->m_ACMLCert, *itRI->m_pCert->AccessEncodedCert(), pspif);
                   else if (m_bACLFatalFail)
                   {
                       SME_THROW(22, "ACL VALIDATION could not be performed, fatal flag.", NULL);
                   }  // END IF  m_bCMLFatalFail
               }        // END if m_pCert for RI present.


              // SECOND, check originator, ONLY if KARI, pspif filled in, AND
              //   not pre-designated by application in m_pACLOriginatorBuf.
              if(lstatus == 0)            // IF still processing ACL validation...
              {
                 if (m_pACLOriginatorCertBuf != NULL && pspif != NULL)
                                // pspif MUST be provided by Recipient processing.
                 {              // THEN check user specified originator (e.g. for RSA).
                     if (m_pACMLOriginatorCert == NULL)
                     {          // ATTEMPT to validate; RWC; THIS MEANS THIS MESSAGE
                                //  IS NOT KARI, but the user wants the originator
                                //  ACL validated anyway, usually a signer...
                         CSM_CertificateChoice *pCertFound=NULL;

                         m_pACMLOriginatorCert = new CM_SFLCertificate(*m_pACLOriginatorCertBuf);
                         //RWC;m_pACMLOriginatorCert->m_pRID = new CSM_Identifier(*pRI_RID);
                         lstatus = CMLValidateCert(*m_pACMLOriginatorCert, pCertFound); 
                         if (lstatus != 0)
                         {
                            if (m_pACMLOriginatorCert)
                            {
                                delete m_pACMLOriginatorCert;
                                m_pACMLOriginatorCert = NULL;
                            }
                            if (m_bCMLFatalFail)
                            {
                                SME_THROW(22, m_pszCMLError, NULL);
                            }  // END IF  m_bCMLFatalFail
                         }     // END if lstatus != 0 && m_bCMLFatalFail
                     }         // END IF m_pACMLOriginatorCert...

                     if (m_pACMLOriginatorCert != NULL) // IF NOW not NULL.
                         lstatus = this->m_ACLInterface.Check_ACLIncommingOrig(
                                *m_pACMLOriginatorCert, *m_pACLOriginatorCertBuf, *pspif);
                 }  // IF KARI.
                 else if (itRI->choiceId == RecipientInfo::kariCid &&
                          pspif != NULL)
                    //this->m_pOriginatorInfo->AccessCertificates() != NULL) // MAY BE IN MESSAGE.
                 {                 // ELSE check KARI originator, if we have certificate.
                    CSM_CertificateChoiceLst *pCertList=NULL;
                    if (m_pOriginatorInfo->m_pMsgCertCrls != NULL)
                        pCertList = m_pOriginatorInfo->m_pMsgCertCrls->AccessCertificates();
                    CSM_Alg Alg1(*itRI->AccesskeyEncryptionAlgorithm());
                    CSM_CertificateChoice *pOrigCertChoice=GetOrigPublicCert(
                        *itRI, pCertList, Alg1);
                    if (pOrigCertChoice && m_pACMLOriginatorCert)
                       lstatus = this->m_ACLInterface.Check_ACLIncommingOrig(
                            *m_pACMLOriginatorCert, *pOrigCertChoice->AccessEncodedCert(),
                            *pspif);
                    else
                        lstatus = -1;   // FAILED to find originator cert.
                                //*pTmpRi->m_pCert->AccessEncodedCert(), *pspif);
                 }  // END if KARI and NOT user specified cert for originator.
              }     // END if intermediate lstatus error check
          }     // END WasDecrypted()
         char ptrData[4096];
         if (lstatus != 0 && this->m_bACLFatalFail) 
         {
            if (m_ACLInterface.m_lpszError)
            {
                 int icout=strlen(m_ACLInterface.m_lpszError);
                 strcpy(ptrData, "ACL validation fails, FATAL flag set.");
                 if (strlen(m_ACLInterface.m_lpszError) > 4000)
                   icout = 4000;
                 strncat(ptrData, m_ACLInterface.m_lpszError, icout);
             }
             else
                 strcpy(ptrData, "ACL validation fails, FATAL flag set (no error string).");
             SME_THROW(25, ptrData, NULL);
         }      // END ACL lstatus failure check.

      delete pspif;
   }            // END FOR itRI != NULL
   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
#endif // ACL_USED

   return(lstatus);
}       // END CSM_DataToDecrypt::ACLCheckoutCerts()


//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt:: Constructors
//////////////////////////////////////////////////////////////////////////
CSM_DataToDecrypt::CSM_DataToDecrypt(const CSM_Buffer *pbufEnvelopedData)
{
   SME_SETUP("CSM_DataToDecrypt::CSM_DataToDecrypt buf");
   
   Clear();
   if (pbufEnvelopedData == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // ASN.1 decode the provided pbufEnvelopedData
   DECODE_BUF((&m_SnaccEnvelopedData), pbufEnvelopedData);

   SME_FINISH_CATCH
}

CSM_DataToDecrypt::CSM_DataToDecrypt(CSMIME *pCSMIME, const CSM_Buffer *pbufEnvelopedData)
{
   SME_SETUP("CSM_DataToDecrypt::CSM_DataToDecrypt(pCSMIME, pbufEnvelopedData");

   Clear();
   if ((pbufEnvelopedData == NULL) || (pCSMIME == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // ASN.1 decode the provided pbufEnvelopedData
   DECODE_BUF((&m_SnaccEnvelopedData), pbufEnvelopedData);

   SME(PreProc(pCSMIME));

   SME_FINISH_CATCH
}



//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt::PreProc
//////////////////////////////////////////////////////////////////////////
void CSM_DataToDecrypt::PreProc(CSMIME *pCSMIME)
{
    CSM_CtilInstLst::iterator itTmpInst;
   CSM_RecipientInfo *pRI=NULL;

   SME_SETUP("CSM_DataToDecrypt::PreProc csmime");

   if (pCSMIME == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing pCSMIME parameter!", NULL);

   // using the provided instances, try to find applicable ones...
   if (pCSMIME->m_pCSInsts != NULL)
   {
      // what was used to encrypt the content?
      // construct a temporary alg to hold the content encryption alg
      CSM_Alg tmpCEAlg(m_SnaccEnvelopedData.encryptedContentInfo.
            contentEncryptionAlgorithm);

      for (itTmpInst =  pCSMIME->m_pCSInsts->begin();
           itTmpInst != pCSMIME->m_pCSInsts->end();
           ++itTmpInst)
      {
         // RWC; NO:this instance will only be applicable if it supports the
         // RWC; NO:content encryption algorithm used in this enveloped data
         // RWC; NO:if (itTmpInst->FindAlgIds(NULL, NULL, NULL, &tmpCEAlg))
         if (!((*itTmpInst)->IsApplicable()))    // ONLY check if not checked yet.
         {
            // look through the recipientInfos while there are more to look
            // at AND while this instance is not marked applicable
            KeyEncryptionAlgorithmIdentifier *pkeyEncryptionAlgorithm;
            RecipientInfos::iterator SNACC_RI1;
            for (SNACC_RI1 = m_SnaccEnvelopedData.recipientInfos.begin();
                 SNACC_RI1 != m_SnaccEnvelopedData.recipientInfos.end();
                 ++SNACC_RI1)
            {
               pRI = new CSM_RecipientInfo(*SNACC_RI1);
               if (pRI != NULL)
               {
                   pkeyEncryptionAlgorithm = pRI->AccesskeyEncryptionAlgorithm();
                   if (pkeyEncryptionAlgorithm == NULL)
                   {
                      delete pRI;
                      pRI = NULL;    // pre-init in case none left.
                      SME_THROW(SM_ENV_DATA_DEC_ERROR,
                            "recipientInfo->keyEncryptionAlgorithm missing",
                            NULL);
                   }     // END if pkeyEncryptionAlgorithm
               
                   // construct a temp alg to hold this recipient's key enc alg
                   CSM_Alg tmpKEAlg(*(pkeyEncryptionAlgorithm));
                   if ((*itTmpInst)->FindAlgIds(NULL, NULL, &tmpKEAlg, NULL))                                              
                       (*itTmpInst)->SetApplicable();  // this instance is applicable

                   // get the next recipientInfo
                   delete pRI;
                   pRI = NULL;    // pre-init in case none left.
               }  // END IF pRI
            }     // END FOR each RI in SNACC list
         }        // END if !((*itTmpInst)->IsApplicable())
      }        // END FOR each login in list.
   }           // END if m_pCSInsts

   SME_FINISH
   SME_CATCH_SETUP
      if (pRI)
         delete pRI;
   SME_CATCH_FINISH
}        // END CSM_DataToDecrypt::PreProc(...)

//
//
void CSM_DataToDecrypt::PreProc(const CSM_Buffer *pbufEnvelopedData,
                                    CSMIME *pCSMIME)
{
   SME_SETUP("CSM_DataToDecrypt::PreProc buf csmime");
   if ((pbufEnvelopedData == NULL) || (pCSMIME == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   // ASN.1 decode the provided pbufEnvelopedData
   Decode(pbufEnvelopedData);
   // call preproc that does the real work
   SME(PreProc(pCSMIME));
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt::Decode
//////////////////////////////////////////////////////////////////////////
void CSM_DataToDecrypt::Decode(const CSM_Buffer *pbufEnvelopedData)
{
   SME_SETUP("CSM_DataToDecrypt::Decode");

   if (pbufEnvelopedData)
      DECODE_BUF((&m_SnaccEnvelopedData), pbufEnvelopedData);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt::TryThisInstance
//////////////////////////////////////////////////////////////////////////
// this function uses the provided instance, finds a matching recipient,
// and attempts to decrypt the EMEK resulting in the MEK...success returns
// the MEK
CSM_Buffer *CSM_DataToDecrypt::TryThisInstance(CSMIME *m_pCsmime,CSM_CSInst *pInst, 
      CSM_CertificateChoiceLst *pOrigCerts, CSM_RecipientInfoLst *pRecipients)
{
   CSM_Buffer *pMEK = NULL;
   CSM_Buffer *pUKM = NULL;
   CSM_Buffer *pOrigKey = NULL;
   CSM_RecipientInfoLst::iterator itRI;
   CSM_Buffer bufKeyAgree;
   CSM_Alg WrapAlg, CEAlg;
   CSM_Buffer *pTmpBuf=NULL;
   CSM_Alg *pKeyAgreeAlg=NULL;
   CSM_CtilInst *pInstKeyWrap=NULL;
   CSM_Alg tmpCEAlg(m_SnaccEnvelopedData.encryptedContentInfo.contentEncryptionAlgorithm);
   CSM_Identifier *pTmpRIDInst = NULL;
   CSM_RecipientIdentifier *pTmpRID=NULL;
   AsnOid  *pTmpKEKOID=NULL;
   CSM_Buffer  *pPWRIpassword = NULL;
   CSM_Buffer  *pPWRIKeyEncryptionKey = NULL;
   long lStatus = 0;

   SME_SETUP("CSM_DataToDecrypt::TryThisInstance");

   if (pInst == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   if (pRecipients == NULL)
       return(pMEK);

   // if we are here, pInst was marked applicable or UseThis,
   // see if there is a recipientInfo that matches what
   // this instance can support...
   KeyEncryptionAlgorithmIdentifier *pkeyEncryptionAlgorithm;
   //RWC;10/10/02;m_SnaccEnvelopedData.recipientInfos.SetCurrToFirst();
   for (itRI =  pRecipients->begin();
        itRI != pRecipients->end();
        ++itRI)
   {
      pOrigKey = NULL;
      pUKM = NULL;
      pTmpRID = itRI->GetRid();

      // if we have a pwri then get the password for the key
      if (itRI->choiceId == RecipientInfo::pwriCid)
         pPWRIpassword = new CSM_Buffer(m_pPWRIDetails->m_UserEncryptionData.Access(),
                                        m_pPWRIDetails->m_UserEncryptionData.Length());
                               
      // get the user key-encryption key if supplied
      if (m_pPWRIDetails && m_pPWRIDetails->m_pUserKeyEncryptionKey != NULL)
         pPWRIKeyEncryptionKey = new CSM_Buffer(
            m_pPWRIDetails->m_pUserKeyEncryptionKey->Access(),
            m_pPWRIDetails->m_pUserKeyEncryptionKey->Length());

      itRI->UnloadSNACCRecipientInfo();   // UPDATE all class member vars, independent
                                    //  of RecipientInfo type (kari,ktri,kekri)

      // TBD, there are probably memory leaks in the loops below...
      // look at pOrigAlg and pOrigKey memory usage...
      pkeyEncryptionAlgorithm = itRI->AccesskeyEncryptionAlgorithm();
      if (pkeyEncryptionAlgorithm != NULL)
      {
         // does this instance support the current recipient info's alg?
         CSM_Alg tmpAlg(*(pkeyEncryptionAlgorithm));
         CSM_Alg *pKeyAlg=NULL;
         CSM_Alg *pKEKAlg=NULL;
         if (itRI->choiceId == RecipientInfo::kekriCid)
            pKEKAlg = &tmpAlg;
         else if (itRI->choiceId == RecipientInfo::pwriCid)
         {
            // get the content encryption Alg from the keyEncryptionAlgorithm
            CSM_Buffer *pTmpCEAlgBuf;
            pTmpCEAlgBuf = itRI->m_pPWRIDetails->m_pKeyEncryptionAlgorithm->GetParams();
            if (pTmpCEAlgBuf)
            {
               DECODE_BUF(&CEAlg, pTmpCEAlgBuf);
              // delete pTmpCEAlgBuf;
           
               m_pKeyWrapOID=new AsnOid (CEAlg.algorithm);// may not need this 
               pKEKAlg = &CEAlg;
            } 
            else
            {
               SME_THROW(22, "Error getting content encryption alg from PWRI Recipient Info", NULL);
            }
         }
         else
            pKeyAlg = &tmpAlg;

         if (pInst->FindAlgIds(NULL, NULL, pKeyAlg, pKEKAlg))
         {
            // alg match, try to match issuer/serial number in recipient
            // with issuer/serial number in this instance...

            if (itRI->m_pPWRIDetails == NULL)  //  bypass if pwri - it doesn't have a rid
               pTmpRIDInst = pInst->GetRid(*pTmpRID);
            
            if (itRI->m_pKEKDetails == NULL && itRI->m_pPWRIDetails == NULL &&
                pTmpRIDInst && pTmpRID && *pTmpRIDInst == *pTmpRID &&
                pInst->IsEncrypter())
            {
               // RWC; FIRST align the new instance to decrypt the content, it may not be 
               // RWC;  the same instance as the RecipientInfo token.
               // RWC; IMPORTANT::This logic was split from the content decryption location
               if (pInst->FindAlgIds(NULL, NULL, NULL, &tmpCEAlg))
               {                // IF in our particular inst.
                  AsnOid  *pTmpContentOID = tmpCEAlg.GetId();
               // RWC;  because some CTILs need this information to decrypt the RIs (e.g. 
               // RWC;  MS CAPI CTIL requires the correct algorithm for the BLOB key
               // RWC;  creation AND requires that the content decryption be 
               // RWC;  performed by the exact same instance.).
                  pInst->SetPreferredCSInstAlgs(NULL, NULL, NULL, pTmpContentOID);
                  delete pTmpContentOID;
               }        // END if our instance can do the content encryption alg.

               // get the UKM by searching for matching alg OID
               // RWC7; TBD; LOGIC NOT IN PLACE to handle multiple recips in single 
               // RWC7; TBD;  RecipientInfo sharing a single UKM!!!! Update 
               // RWC7; TBD;  CSM_RecipientInfo to assist.  Assumption here is 1 for 1.

               // create a buffer to receive the MEK
               if ((pMEK = new CSM_Buffer) == NULL)
                  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

               // decrypt the EMEK to get the MEK
               if (pInst->AccessTokenInterface()->SMTI_IsKeyAgreement())
               {
                  pOrigKey = GetOrigPublicKey(*itRI, pOrigCerts, tmpAlg);

                  // FIRST, gather info necessary to extract KeyAgree key to 
                  //  unwrap MEK.
                  pKeyAgreeAlg=
                     new CSM_Alg(*itRI->AccesskeyEncryptionAlgorithm());

                  // SECOND, determine an appropriate KeyWrap encryption engine (CTIL)
                  if (pKeyAgreeAlg->parameters)
                  {
                      SM_EXTRACT_ANYBUF(pTmpBuf, pKeyAgreeAlg->parameters);
                        // SHOULD also be in "itRI->m_pbufParams

                      DECODE_BUF(&WrapAlg, pTmpBuf);
                      delete pTmpBuf;
                      m_pKeyWrapOID=new AsnOid (WrapAlg.algorithm);

                      // PIERCE 7-16-99
                      // If this instance doesn't support the KeyWrap find 
                     // an instance that does
                      //
                      if ( pInst->FindAlgIds(NULL, NULL, NULL, &WrapAlg) == 
                           false)
                      {
                         
                         pInstKeyWrap = m_pCsmime->FindCSInstAlgIds(NULL, NULL,
                                        NULL, &WrapAlg);
                         
                         // If an instance wasn't found assume the current 
                         // instance can handle it.
                         //
                         if (pInstKeyWrap == NULL)
                            pInstKeyWrap = pInst;
                      }
                      else
                         pInstKeyWrap = pInst;

                      pInstKeyWrap->SetPreferredCSInstAlgs(NULL, NULL, NULL, 
                         m_pKeyWrapOID);
                  }
                  else                // Default to this CTIL instance Content 
                  {
                    pInstKeyWrap = pInst;  //  Encryption alg.
                  }         // END IF pKeyAgreeAlg->parameters

                  pInst->SetPreferredCSInstAlgs(NULL, NULL, 
                      &pKeyAgreeAlg->algorithm, NULL);


                  if(pInstKeyWrap)
                  {
                      long lKekLength;
                      // Make a dummy call to get the length for proper keyAgree extraction 
                      //   (for gen of OtherInfo).
                      CSM_Buffer *pTmpIV = pInstKeyWrap->AccessTokenInterface()
                          ->SMTI_GenerateKeyWrapIV(lKekLength);
                      // THIRD, generate the key to unwrap the MEK.
                      SME(pInst->AccessTokenInterface()->SMTI_ExtractKeyAgreement(
                         pOrigKey, itRI->m_pUkmBuf, NULL, m_pKeyWrapOID, &bufKeyAgree, lKekLength));
                      // FOURTH, unwrap the MEK to be used to decrypt the content.
                      pInstKeyWrap->SetPreferredCSInstAlgs(NULL, NULL, NULL, m_pKeyWrapOID);
                      SME(pInstKeyWrap->AccessTokenInterface()->SMTI_ExtractKeyWrap(pMEK,  
                         &itRI->m_bufEMEK, itRI->m_pbufParams, &bufKeyAgree, 
                         pTmpIV));

                      delete pTmpIV;

					  /*RWC;MAKE SPECIFIC TO CTIL, SINCE FORTEZZA RETURNS 0 LENGTH MEK
                        RWC; DUE TO ALGORITHM DETAILS;if (pMEK->Length() == 0)
						  SME_THROW(22,"Bad MEK Length returned!",NULL);*/

                  }

                  // else MAY BE LOCALly encrypted.
                  delete pKeyAgreeAlg;
               }           // IF isKeyAgreement
               else        // MUST be KTRI
               {
                  if (pKeyAlg->algorithm == id_RSAES_OAEP)
                  {         // FLAG the CTIL to perform RSAES-OAEP alg, 
                            //   not RSA encryption.
                     pInst->SetPreferredCSInstAlgs(NULL, NULL, &pKeyAlg->algorithm, NULL);
                  }
                  else
                  {         // JUST in case the previous run used RSAES_OAEP.
                     AsnOid rsaOid(rsaEncryption);
                     pInst->SetPreferredCSInstAlgs(NULL, NULL, &rsaOid, NULL);
                  } // END IF id_RSAES_OAEP
                  SME(pInst->AccessTokenInterface()->SMTI_ExtractMEK(pOrigKey, 
                     itRI->m_pbufParams, &itRI->m_bufEMEK, itRI->m_pUkmBuf, pMEK));
               }           // END IF isKeyAgreement
               // RWC, code that marks
               //   the decrypted recipient with WasDecrypted
               itRI->SetDecryptedFlag(true);
               if (itRI->m_pCert == NULL && pInst->HasCertificates() && 
                   pInst->AccessUserCertificate()->AccessEncodedCert())
                                // THEN load cert from decryption instance for
                                //   possible ACL validation check later.
                   itRI->m_pCert = new CSM_CertificateChoice(  
                     *pInst->AccessUserCertificate()->AccessEncodedCert());

            }
            else if (itRI->choiceId == RecipientInfo::kekriCid)
            {
              pTmpKEKOID = pKEKAlg->GetId();
              pInst->SetPreferredCSInstAlgs(NULL, NULL, NULL, pTmpKEKOID);
              delete pTmpKEKOID;
              pTmpKEKOID = NULL;

              // BEFORE atempting RecipieintInfo token decryption, we need to
              //  get the associated private key alternative from the applicaion
              //  provided KEK data structures, or ERROR.  The ID/password
              // associated will allow the following decryption to work.
              if (determineKEKUserEncryptionData(*itRI))
              {
               // create a buffer to receive the MEK
               if ((pMEK = new CSM_Buffer) == NULL)
                  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

                 // decrypt the EMEK using a content encryption alg.
                 //SME(pInst->AccessTokenInterface()->SMTI_Decrypt(
                 //  itRI->m_pbufParams, &itRI->m_bufEMEK, 
                 //  &itRI->m_pKEKDetails->m_UserEncryptionData, pMEK));
                 pKeyAgreeAlg=
                     new CSM_Alg(*itRI->AccesskeyEncryptionAlgorithm());
                        // IN, specified encryption of key,
                        //   used here in key generation, but alg not implemented.
                  if (pKeyAgreeAlg->parameters)
                  {
                      m_pKeyWrapOID=new AsnOid (pKeyAgreeAlg->algorithm);
                      pInst->SetPreferredCSInstAlgs(NULL, NULL, NULL, m_pKeyWrapOID);
                      SME(pInst->AccessTokenInterface()->SMTI_ExtractKeyWrap(pMEK,  
                         &itRI->m_bufEMEK, NULL/*itRI->m_pbufParams*/, 
                         &itRI->m_pKEKDetails->m_UserEncryptionData, 
                         NULL));
                  }     // END if pKeyAgreeAlg->parameters
                  itRI->SetDecryptedFlag(true);
                  delete pKeyAgreeAlg;
                  pKeyAgreeAlg = NULL;
              }      // END if determineKEKUserEncryptionData for kekri
            }        // END if choiceId == RecipientInfo:: kekri/ktri/kari
            else if (itRI->choiceId == RecipientInfo::pwriCid)
            {
               // create a buffer to receive the MEK
               if ((pMEK = new CSM_Buffer) == NULL)
                  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

               // Key Unwrapping
               // get back the MEK 
               if (pPWRIKeyEncryptionKey && pPWRIKeyEncryptionKey->Length() != 0)
               {
                  // have a user supplied key-encryption key
                  lStatus = SME(pInst->AccessTokenInterface()->SMTI_ExtractPWRIKeyWrap(
                         *pMEK,
                         itRI->m_bufEMEK,
                         *pPWRIpassword,       /* password */
                         pPWRIKeyEncryptionKey, /* user supplied key=encryption key */
                         itRI->m_pPWRIDetails->m_pKeyDerivationAlgorithm,
                         itRI->m_pPWRIDetails->m_pKeyEncryptionAlgorithm));
                  if (lStatus)
                  {
                    SME_THROW(22, "Error extracting the PWRI MEK", NULL);
                  }
               }
               else
               {
                  // have to derive the key-encryption key
                  lStatus = SME(pInst->AccessTokenInterface()->SMTI_ExtractPWRIKeyWrap(
                         *pMEK,
                         itRI->m_bufEMEK,
                         *pPWRIpassword,       /* password */
                         itRI->m_pPWRIDetails->m_pUserKeyEncryptionKey,
                         itRI->m_pPWRIDetails->m_pKeyDerivationAlgorithm,
                         itRI->m_pPWRIDetails->m_pKeyEncryptionAlgorithm));
                  if (lStatus)
                  {
                    SME_THROW(22, "Error extracting the PWRI MEK", NULL);
                  }
               }
                if (lStatus != 0)
                   SME_THROW(22, "Error Generating PWRI Key Wrap", NULL);

                itRI->SetDecryptedFlag(true);

            }        // END if choiceId == RecipientInfo:: kekri/ktri/kari/pwri

           }         // END if FindAlgIds

           if (pTmpRIDInst)
           {
               delete pTmpRIDInst;
               pTmpRIDInst = NULL;
           }      // END if pTmpRIDInst
      }           // END if pkeyEncryptionAlgorithm 
      if (pTmpRID) 
      {
          delete pTmpRID;
          pTmpRID = NULL;
      }     // END if pTmpRID.
   
      // continue looking through the recipient's until we have data
      // in the MEK buffer or until we run out of recipients
      if (pOrigKey)
         delete pOrigKey;
      if (pUKM)
         delete pUKM;

   }        // END FOR each RI in list.

   if (pPWRIpassword)
      delete pPWRIpassword;
      
   SME_FINISH
   SME_CATCH_SETUP
      if (pMEK)
         delete pMEK;
      if (pTmpRIDInst)
         delete pTmpRIDInst;
      if (pTmpRID) 
         delete pTmpRID;
      if (pKeyAgreeAlg)
         delete pKeyAgreeAlg;
      if (pTmpKEKOID)
          delete pTmpKEKOID;

   SME_CATCH_FINISH

   return pMEK;
}     // END CSM_DataToDecrypt::TryThisInstance(...)

//
//
bool CSM_DataToDecrypt::determineKEKUserEncryptionData(CSM_RecipientInfo &RI)
{
   bool found = false;
   CSM_KEKDetailsLst::iterator itTmpKEK;

   if (m_pKEKDetailsLst)
   {
      for (itTmpKEK =  m_pKEKDetailsLst->begin(); 
           itTmpKEK != m_pKEKDetailsLst->end() && 
               RI.m_pKEKDetails->m_UserEncryptionData.Length() == 0; 
           ++itTmpKEK)
      {
         if (itTmpKEK->m_RID == RI.m_pKEKDetails->m_RID)
         {
            RI.m_pKEKDetails->m_UserEncryptionData = itTmpKEK->m_UserEncryptionData;
            found = true;
         }
      }
   }

   return(found);
}


//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt::Decrypt
//////////////////////////////////////////////////////////////////////////
void CSM_DataToDecrypt::Decrypt(CSMIME *pCSMIME,
                                    CSM_CertificateChoiceLst *pOrigCerts,
                                    CSM_Buffer *pbufDecryptedContent, 
                                    CSM_RecipientInfoLst *pRecipients)
{
    CSM_CtilInstLst::iterator itInst;
   CSM_CSInst   *pInstCS;
   CSM_CtilInst *pInst2;
   CSM_Buffer *pbufMEK = NULL;
   CSM_Buffer *pbufParameters=NULL;
   CSM_Alg tmpCEAlg(m_SnaccEnvelopedData.encryptedContentInfo.contentEncryptionAlgorithm);
   //CSM_Recipient *tmpRecip;

   SME_SETUP("CSM_DataToDecrypt::Decrypt");

   // check the incoming parameters
   if ((pCSMIME == NULL) || (pCSMIME->m_pCSInsts == NULL) || 
         (pbufDecryptedContent == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   
   // lock the CTIs
   SME(pCSMIME->InstanceLock(SM_INST_APPLICABLE | SM_INST_USE_THIS));

   // give priority to instances marked UseThis...search for an instance
   // marked UseThis
   for (itInst =  pCSMIME->m_pCSInsts->begin();
        itInst != pCSMIME->m_pCSInsts->end();
        ++itInst)
   {
      pInstCS = (CSM_CSInst *)(*itInst)->AccessTokenInterface()->AccessCSInst();
      if (pInstCS && pInstCS->IsThisUsed())
      {
         SME(if ((pbufMEK = TryThisInstance(pCSMIME, pInstCS, pOrigCerts, pRecipients)) != 
                  NULL) break;);
      }        // END IF instance handles certificates.
   }           // END FOR each instance in list.

   // if we don't have an mek, search for an applicable instance to try
   if (pbufMEK == NULL) 
   {
       for (itInst =  pCSMIME->m_pCSInsts->begin();
            itInst != pCSMIME->m_pCSInsts->end();
            ++itInst)
      {
         pInstCS = (CSM_CSInst *)(*itInst)->AccessTokenInterface()->AccessCSInst();
         if (pInstCS && pInstCS->IsApplicable())
         {
            SME(if ((pbufMEK = TryThisInstance(pCSMIME, pInstCS, pOrigCerts, pRecipients)) != 
                     NULL) break;);
         }        // END IF instance handles certificates.
      }           // END FOR each instance in list.
   }              // END IF pbufMEK == NULL

   // now, we either have an MEK or we don't.  If we don't then there was
   // no instance marked UseThis or Applicable that had everything
   // necessary to decrypt the EMEK
   if (pbufMEK == NULL)
   {
      SME_THROW(SM_NO_SUPPORTING_INSTANCE, "couldn't decrypt any RecipientInfo!", NULL);
   }        // IF pbufMEK
   else
   {        // SUCCESSFUL in extracting the MEK from at least 1 login.
      // RWC; For the special case where the application requests the MEK be 
      //  exported, we check.  Also, some CTILs cannot export the MEK in the
      //  clear, this is checked as well.  We do not throw an exception if the
      //  export was requested, but we cannot comply, it is up to the 
      //  application to check the m_p
      if (m_bExportMEK && 
          pbufMEK->Length() && pbufMEK->Length() > 4) // SPECIAL case where a CTIL
                                                  //  might pass a handle (e.g.
                                                  //  sm_capi CTIL) OR a blank MEK.
      {
          if (m_pExportedMEK)
          {
              delete m_pExportedMEK;        // DELETE previous, if present.
              m_pExportedMEK = NULL;
          }
          m_pExportedMEK = new CSM_Buffer(*pbufMEK);  // COPY for export.
      }     // END MEK export requested and available.
   }        // END pbufMEK.



   // RWC; FIRST align the new instance to decrypt the content, it may not be 
   // RWC;  the same instance as the RecipientInfo token.  If the content 
   // RWC;  decryption OID is present in the token instance, it was already 
   // RWC;  set in the TryThisInstance(...) method.
   // RWC; IMPORTANT::This logic was split from the content decryption location
   // RWC;  because some CTILs need this information to decrypt the RIs (e.g. 
   // RWC;  MS CAPI CTIL requires the correct algorithm for the BLOB key
   // RWC;  creation AND requires that the content decryption be 
   // RWC;  performed by the exact same instance.).
   if (!(*itInst)->FindAlgIds(NULL, NULL, NULL, &tmpCEAlg))  // IF not in ours
   {           // ONLY re-align to another instance if we have to.
      pInst2 = pCSMIME->FindCSInstAlgIds(NULL, NULL, NULL, &tmpCEAlg);
      if (pInst2 == NULL)
         SME_THROW(SM_MISSING_PARAM, "NO CSInstance to process ContentEncryption",
           NULL);
   }        // IF our instance can do the content encryption alg.
   else
   {
      pInst2 = &(*(*itInst));      // hopefully the default case.
   }        // END if our instance can do the content encryption alg.
   AsnOid  *pTmpContentOID = tmpCEAlg.GetId();
   pInst2->SetPreferredCSInstAlgs(NULL, NULL, NULL, pTmpContentOID);
   delete pTmpContentOID;

   // Extract the content encryption parameters
   if (m_SnaccEnvelopedData.encryptedContentInfo.contentEncryptionAlgorithm.
       parameters)
       SM_EXTRACT_ANYBUF(pbufParameters, m_SnaccEnvelopedData.
         encryptedContentInfo.contentEncryptionAlgorithm.parameters);
   // create a buffer holding the encrypted content
   CSM_Buffer bufContent;
   if (m_SnaccEnvelopedData.encryptedContentInfo.encryptedContent)
   {            // CHECK since content is OPTIONAL
       bufContent.Set(m_SnaccEnvelopedData.
         encryptedContentInfo.encryptedContent->c_str(), m_SnaccEnvelopedData.
         encryptedContentInfo.encryptedContent->Len());
   }        // IF encrypted content in EnvelopedData
   else if (m_pOPTIONALEncryptedContent)
   {            // LOAD application provided encrypted content (hopefully it 
                //  correctly matches this message.
       bufContent.Set(m_pOPTIONALEncryptedContent->Access(), 
                      m_pOPTIONALEncryptedContent->Length());
   }        // END IF encrypted content in EnvelopedData

   // check to see if we have content to decrypt
   if (bufContent.Access() == NULL)
      SME_THROW(22,"Error, NO Content to decrypt!", NULL);

   // decrypt the content
   SME(pInst2->AccessTokenInterface()->SMTI_Decrypt(
         pbufParameters, &bufContent, pbufMEK, pbufDecryptedContent));

   // unlock the CTI
   SME(pCSMIME->InstanceUnlock(SM_INST_APPLICABLE | SM_INST_USE_THIS));

   if (pbufMEK)
      delete pbufMEK;
   if (pbufParameters)
      delete pbufParameters;

   SME_FINISH
   SME_CATCH_SETUP
      if (pbufMEK)
         delete pbufMEK;
      if (pbufParameters)
         delete pbufParameters;
      // catch/cleanup logic as necessary
      // unlock the CTI if necessary
   SME_CATCH_FINISH
}       // END CSM_DataToDecrypt::Decrypt(..)


//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt::GetFirstRecipientInfo
//
//  Describes 2 uses of RecipientInfo to contain encrypted key information.
/**
It provides the capability to specify that the originator's Ra (aka UKM) will be re-used
for multiple recipients when a key agreement algorithm is used (i.e. a
single RecipientInfo structure is used for all recipients; a separate
RecipientEncryptedKey SEQUENCE is used for each recipient's key).  It also
provides the capability to specify that a unique originator Ra will be used
for each recipient when a key agreement algorithm is used (i.e. a separate
RecipientInfo structure is used for each recipient).  The latter option
requires more overhead because the KeyAgreeRecipientInfo (i.e. version,
originatorCert, keyEncryptionAlgorithm) must be repeated for each
recipient's key.  But that is OK with me because the increased overhead
might discourage people from using the latter option.**/
CSM_RecipientInfo *CSM_DataToDecrypt::GetFirstRecipientInfo()
{
   CSM_RecipientInfo *pSNACCRi=NULL;


   SME_SETUP("CSM_DataToDecrypt::GetFirstRecipientInfo");

      m_SNACCRiIterator = m_SnaccEnvelopedData.recipientInfos.begin();
      if (m_SNACCRiIterator != m_SnaccEnvelopedData.recipientInfos.end())
      {
         pSNACCRi = new CSM_RecipientInfo(*m_SNACCRiIterator);
         if (m_SNACCRiIterator->choiceId == RecipientInfo::kariCid)  
                                     // CHECK if there are any other recipients
         {                              //  in this particular recipient info that
                                    //  share the same UKM/Random Number.
              if (m_pRecipientEncryptedKeysIterator == NULL)
                 m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
              *m_pRecipientEncryptedKeysIterator = m_SNACCRiIterator->kari->recipientEncryptedKeys.begin();
              *pSNACCRi->m_pRecipientEncryptedKeysIterator = pSNACCRi->kari->recipientEncryptedKeys.begin();
                    // RESET the temporary, working copy iterator as well.
         }
         // BE SURE TO INIT OTHER MEMORY
      }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return(pSNACCRi);
}     // END CSM_DataToDecrypt::GetFirstRecipientInfo(...)

//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt::GetNextRecipientInfo
//
CSM_RecipientInfo *CSM_DataToDecrypt::GetNextRecipientInfo()
{
   CSM_RecipientInfo *pSNACCRi=NULL;
   RecipientInfo *ptmpSNACCRi=NULL;

   SME_SETUP("CSM_DataToDecrypt::GetNextRecipientInfo");

     RecipientInfo &tmpSNACCRi = *m_SNACCRiIterator;
     ptmpSNACCRi = &tmpSNACCRi;

     if (tmpSNACCRi.choiceId == RecipientInfo::ktriCid)
     {                     // SIMPLY Get next direct recipientInfo.
        ++m_SNACCRiIterator;
        if (m_SNACCRiIterator != m_SnaccEnvelopedData.recipientInfos.end())
        {
           pSNACCRi = new CSM_RecipientInfo(*m_SNACCRiIterator);
        }       // END IF m_pRecipientEncryptedKeysIterator
        else
           pSNACCRi = NULL;
     }
     else if (tmpSNACCRi.choiceId == RecipientInfo::kariCid)
     {                              // CHECK if there are any other recipients
                                    //  in this particular recipient info that
                                    //  share the same UKM/Random Number.
        if (m_pRecipientEncryptedKeysIterator &&
            *m_pRecipientEncryptedKeysIterator != tmpSNACCRi.kari->recipientEncryptedKeys.end())
        {       // THEN go to the next encrypted key within an RI
           ++*m_pRecipientEncryptedKeysIterator;
        }
        if (m_pRecipientEncryptedKeysIterator == NULL ||
            *m_pRecipientEncryptedKeysIterator == tmpSNACCRi.kari->recipientEncryptedKeys.end())
        {       // THEN go to the next RI, not the next encrypted key within an RI
           ++m_SNACCRiIterator;
           if (m_SNACCRiIterator != m_SnaccEnvelopedData.recipientInfos.end())
           {
               RecipientInfo &tmpSNACCRi2 = *m_SNACCRiIterator;
               if (tmpSNACCRi2.choiceId == RecipientInfo::kariCid)
                                         // CHECK if there are any other recipients
               {                         //  in this particular recipient info that
                                         //  share the same UKM/Random Number.
                  if (m_pRecipientEncryptedKeysIterator == NULL)
                      m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
                  *m_pRecipientEncryptedKeysIterator = tmpSNACCRi2.kari->recipientEncryptedKeys.begin();
               }    // END IF kari
               ptmpSNACCRi = &tmpSNACCRi2;
           }        // IF next RI
           else
           {
               ptmpSNACCRi = NULL;
           }        // END IF next RI
        }           // END IF present kari keys finished.
        if (ptmpSNACCRi)
        {
            pSNACCRi = new CSM_RecipientInfo(*ptmpSNACCRi); // ALWAYS generate new instance.
                                // IF KARI, then the key list iterator is reset to the 1st.
            if (ptmpSNACCRi->choiceId == RecipientInfo::kariCid)
            {         // MUST check again for Kari, since may have moved to new RI.
              //RWC Set curr in new to same index entry.
              if (pSNACCRi->m_pRecipientEncryptedKeysIterator == NULL)
                  pSNACCRi->m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
              for (RecipientEncryptedKeys::iterator TmpRecipientEncryptedKeysIterator=
                                 ptmpSNACCRi->kari->recipientEncryptedKeys.begin();
                   TmpRecipientEncryptedKeysIterator != ptmpSNACCRi->kari->recipientEncryptedKeys.end();
                   ++TmpRecipientEncryptedKeysIterator)
              {
                       if (m_pRecipientEncryptedKeysIterator && 
                           TmpRecipientEncryptedKeysIterator == *m_pRecipientEncryptedKeysIterator)
                           break;
                       else
                           ++*pSNACCRi->m_pRecipientEncryptedKeysIterator; // KEEP counting new Key(s)
              }     // END FOR any original iterators.
            }   // END IF kari
        }       // END IF ptmpSNACCRi
     }          // END IF ktri OR kari

   SME_FINISH
   SME_CATCH_SETUP
      if (pSNACCRi)
         delete pSNACCRi;
   SME_CATCH_FINISH

   return(pSNACCRi);
}           // END CSM_DataToDecrypt::GetNextRecipientInfo(...)


//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt::GetOrigPublicKey
//  This method assumes that SNACCRecipInfo is choiceId KARI.  There may or
//  may not be a certificate associated.  If CML is enabled AND there is a 
//  certificate, then it is validated.
CSM_CertificateChoice *CSM_DataToDecrypt::GetOrigPublicCert(RecipientInfo &SNACCRecipInfo, 
                                                 CSM_CertificateChoiceLst *pOrigCerts,
                                                 CSM_Alg &keyEncryptionAlg)
{
   CSM_Alg *pOrigAlg = NULL;
   AsnOid  *p1=NULL;
   AsnOid  *p2=NULL;
   CSM_RecipientIdentifier *pRI_RID=NULL;
   CSM_CertificateChoiceLst::iterator itCert;
   CSM_CertificateChoice *pCertFound=NULL;
   CSM_Identifier *pCertRid;

   SME_SETUP("CSM_DataToDecrypt::GetOrigPublicCert");

   if(SNACCRecipInfo.kari->originator.choiceId == 
        OriginatorIdentifierOrKey::issuerAndSerialNumberCid)
   {
     if (SNACCRecipInfo.kari->originator.issuerAndSerialNumber)
     {
        CSM_IssuerAndSerialNumber IssAndSN(
              *SNACCRecipInfo.kari->originator.issuerAndSerialNumber);
        pRI_RID = new CSM_RecipientIdentifier(IssAndSN);
     }
   }
   else if (SNACCRecipInfo.kari->originator.choiceId == 
        OriginatorIdentifierOrKey::subjectKeyIdentifierCid)
   {
     if (SNACCRecipInfo.kari->originator.subjectKeyIdentifier)
     {
        CSM_Buffer ski((const char *)
           SNACCRecipInfo.kari->originator.subjectKeyIdentifier->c_str(),
           SNACCRecipInfo.kari->originator.subjectKeyIdentifier->Len());
        pRI_RID = new CSM_RecipientIdentifier(ski);
     }
   }
     if (pRI_RID && pOrigCerts)
     {
        for (itCert =  pOrigCerts->begin();
             itCert != pOrigCerts->end();
             ++itCert)
        {
          pCertRid = itCert->GetRid(*pRI_RID);
          SME(pOrigAlg = itCert->GetPublicKeyAlg());
          if (*(pOrigAlg->AccessSNACCId()) == *(keyEncryptionAlg.AccessSNACCId()) 
             && pCertRid && *pCertRid == *pRI_RID )
          {
             // this originator cert's subject public key OID
             // match this recipient's keyEncryptionAlgorithm
             // OID
             pCertFound = &(*itCert);
          }    // END if cert found.
          delete pOrigAlg;
          pOrigAlg = NULL;
          if (pCertRid)
             delete pCertRid;
        }       // END FOR each cert in list.

     // LOOK for this originator cert in message supplied list, if available.
     if (pRI_RID && pCertFound == NULL && 
         m_SnaccEnvelopedData.originatorInfo &&
         m_SnaccEnvelopedData.originatorInfo->certs)
     {
       CSM_CertificateChoice *pCert;
       // look for a public key in m_SnaccEnvelopedData.
       // originatorInfo->certs
       CertificateSet::iterator itTmpCertSet;
       for (itTmpCertSet  = m_SnaccEnvelopedData.originatorInfo->certs->begin();
            itTmpCertSet != m_SnaccEnvelopedData.originatorInfo->certs->end();
            ++itTmpCertSet)
       {
          if (itTmpCertSet->choiceId == CertificateChoices::certificateCid)
          {
             pCert = new CSM_CertificateChoice(*itTmpCertSet);
             pCertRid = pCert->GetRid(*pRI_RID);
             SME(pOrigAlg = pCert->GetPublicKeyAlg());
             if (*(pOrigAlg->AccessSNACCId()) == *(keyEncryptionAlg.AccessSNACCId()) 
                && pCertRid && *pCertRid == *pRI_RID )
             {
                // this originator cert's subject public key OID
                // match this recipient's keyEncryptionAlgorithm
                // OID
                pCertFound = pCert;
                 delete pOrigAlg;
                 if (pCertRid)
                    delete pCertRid;
                 break;
             }    // END if cert found.
             delete pOrigAlg;
             pOrigAlg = NULL;
             if (pCertRid)
                delete pCertRid;
             if (pCert)
                delete pCert;
          }    // END if cert choice (not CRL).
       }    // END FOR each originatorInfo cert.
     }      // END if still no cert, check m_SnaccEnvelopedData.originatorInfo

       if (pRI_RID)
          delete pRI_RID;
   }        // END if OriginatorIdentifierOrKey::originatorKeyCid



   SME_FINISH
   SME_CATCH_SETUP
      if (p1)
          delete p1;
      if (p2)
          delete p2;
      if (pOrigAlg)
          delete pOrigAlg;
      if (pRI_RID)
         delete pRI_RID;
   SME_CATCH_FINISH

   return(pCertFound);
}     // END CSM_DataToDecrypt::GetOrigPublicCert(...)


CSM_Buffer *CSM_DataToDecrypt::GetOrigPublicKey(RecipientInfo &SNACCRecipInfo, 
                                                 CSM_CertificateChoiceLst *pOrigCerts,
                                                 CSM_Alg &keyEncryptionAlg)
{
   CSM_CertificateChoice *pCertFound=NULL;
   CSM_Buffer *pOrigKey=NULL;

   SME_SETUP("CSM_DataToDecrypt::GetOrigPublicKey");

   //#############################
   // FIRST, check for a raw key in originator.
   if(SNACCRecipInfo.kari->originator.choiceId == 
        OriginatorIdentifierOrKey::originatorKeyCid)
   {
      pOrigKey = CSM_CertificateChoice::
         GetPublicKey(SNACCRecipInfo.kari->originator.
           originatorKey->publicKey);
   }     // IF OriginatorIdentifierOrKey::originatorKeyCid
   else
   {
     // yes, attempt to use this instance to extract the MEK
     // in order to call SMTI_ExtractMEK we need the
     // originator's public value, look for it in pOrigCerts
     // (list of certs provided by the caller) OR from the
     // internal optional Cert list.  Use pSnaccRI->originatorCert to
     // help identify what we need from pOrigCerts, search through pOrigCerts.
     // LOOK for this originator cert in user supplied list, if available.
      /////////////////////////////////////////////////////
       pCertFound = GetOrigPublicCert(SNACCRecipInfo, pOrigCerts, 
                    keyEncryptionAlg);

#ifdef CML_USED
       long lstatus=0;
       if (m_bCMLUseToValidate && m_lCmlSessionId != 0)
       {
         CSM_RecipientIdentifier *pRI_RID=NULL;
         if (SNACCRecipInfo.kari->originator.issuerAndSerialNumber)
         {
            CSM_IssuerAndSerialNumber IssAndSN(
                  *SNACCRecipInfo.kari->originator.issuerAndSerialNumber);
            pRI_RID = new CSM_RecipientIdentifier(IssAndSN);
         }      // END if issuerAndSerialNumber
         m_pACMLOriginatorCert = new CM_SFLCertificate;
         m_pACMLOriginatorCert->m_pRID = new CSM_Identifier(*pRI_RID);
         lstatus = CMLValidateCert(*m_pACMLOriginatorCert, pCertFound); 
         if (lstatus != 0)
         {
            if (m_pACMLOriginatorCert)
            {
                delete m_pACMLOriginatorCert;
                m_pACMLOriginatorCert = NULL;
            }
            if (m_bCMLFatalFail)
            {
                SME_THROW(22, m_pszCMLError, NULL);
            }  // END IF  m_bCMLFatalFail
         }     // END if lstatus != 0 && m_bCMLFatalFail
       }       // END if CML use
#endif //CML_USED

       // LASTLY, If we found the cert in any of these locations, use it.
       if (pCertFound)
       {
          //  get the public key out
          SME(pOrigKey = pCertFound->GetPublicKey());
       }     // END if pCertFound

   }        // END if public key directly presented.


   SME_FINISH
   SME_CATCH_SETUP
      if (pOrigKey)
          delete pOrigKey;
   SME_CATCH_FINISH
   return(pOrigKey);
}     // END CSM_DataToDecrypt::GetOrigPublicKey(...)

//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecrypt::~CSM_DataToDecrypt
//
CSM_DataToDecrypt::~CSM_DataToDecrypt()
{
   if (m_pKEKDetailsLst)
     delete m_pKEKDetailsLst;
   if (m_pPWRIDetails)
     delete m_pPWRIDetails;
   if (m_pKeyWrapOID)
     delete m_pKeyWrapOID;
   if (m_pExportedMEK)
       delete m_pExportedMEK;
   if (m_pOPTIONALEncryptedContent)
       delete m_pOPTIONALEncryptedContent;
   if (m_pRecipientEncryptedKeysIterator)
       delete m_pRecipientEncryptedKeysIterator;
#ifdef CML_USED
   if (m_pACMLOriginatorCert)
       delete m_pACMLOriginatorCert;
#endif //CML_USED
}     // END CSM_DataToDecrypt::~CSM_DataToDecrypt()



_END_SFL_NAMESPACE

// EOF sm_Decrypt.cpp
