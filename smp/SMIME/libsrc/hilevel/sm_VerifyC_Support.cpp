// sm_VerifyC_Support.cpp
// This file implements SM_VerifyC_Support which is a C wrapper for 
// CSM_MsgToVerify

#include <string.h>
#include "sm_api.h"
extern "C" {
#include "sm_apic.h"
}

    using namespace SFL;
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;

/* SM_VerifyC_Support verifys a CMS SignedData */
SM_RET_VAL SM_VerifyC_Support(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      SM_Content **pContent, /* input or output */
      Bytes_struct *pInput, /* ASN.1 encoded SignedData */
      SM_SignerInfoLst **pSignerInfos, /* optional list of SignerInfos */
      EncCert_LL **pCerts, /* list of certs */
      SM_BufferLst **pACs, /* list of attribute certs */
      EncCRL_LL **pCrls, /* list of crls */
      SM_Buffer *pSignedRec, /* Signed Receipt File Name */
      long *receiptreq,      /* is a receipt requested */
      CSM_MsgToVerify &smVerifyMsg)

{
   SM_RET_VAL lRet = SM_NO_ERROR;
   char *lpszError = "";     
   SM_SignerInfoLst *pTmpSignerInfos = NULL;
   CSM_Buffer *pbufInput = NULL;   
   const CSM_Content *pbufContent;
   CSM_CertificateChoiceLst *pCertLst = NULL;
   CSM_CertificateChoiceLst *pACertLst = NULL;
   CSM_RevocationInfoChoices *pRevInfoChoices = NULL;
   CSM_CertificateChoiceLst::iterator itTmpCert;
   CSM_CertificateChoiceLst::iterator itTmpAC;
   List<CSM_RevocationInfoChoice>::iterator itTmpCrl;
   EncCert_LL *pTmpCerts = NULL;
   SM_BufferLst *pTmpACerts = NULL;
   EncCRL_LL *pTmpCrls = NULL;
   CSM_AttribLst::iterator itTmpAttr;
   CSM_AttribLst *pSAttrLst = NULL;
   CSM_AttribLst *pUnSAttrLst = NULL;
   SM_AttribLst *pTmpSAttrs = NULL;
   SM_AttribLst *pTmpUnSAttrs = NULL;
   CSM_MsgSignerInfos::iterator itTmpSI;
   CSM_Buffer *pbuf;
   short count = 1;

   SME_SETUP("SM_VerifyC_Support");

   // check for missing parameters
   if ((pCSMIME == NULL) || (pInput == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // convert the input from the C Bytes_struct structure to a C++ CSM_Buffer
   pbufInput = new CSM_Buffer((char *)pInput->data, pInput->num);
   if (pbufInput == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // process the input as a content info
   CSM_ContentInfoMsg contentInfo(pbufInput);
   if (!contentInfo.IsSignedData())
      SME_THROW(SM_UNKNOWN_ERROR, "content doesn't contain a SignedData", NULL);
   delete pbufInput;

   // Pre Process the encoded blob as a content info
   SME(smVerifyMsg.PreProc((CSMIME *)pCSMIME, 
      &(contentInfo.AccessEncapContentFromAsn1()->m_content)));

   // set EnableReceipt to return a receipt if one is requested 
   if ((receiptreq) && (*receiptreq))
   {
      smVerifyMsg.EnableReceipt(true);
   }

   // pull out the inner content - if it's null, the content is separate
   // from the signed data
   if ((pbufContent = smVerifyMsg.AccessEncapContentFromAsn1()) != NULL && pContent && 
       (*pContent) != NULL)
   {
      // set up pContent as a Buffer and fill with the encapsulated content
      (*pContent)->bufContent.flag = SM_BUFFER_USED;
      if ((*pContent)->bufContent.data.pchData != NULL)
         free((*pContent)->bufContent.data.pchData);
      (*pContent)->bufContent.data.pchData = (char *)calloc(1,
         pbufContent->m_content.Length());
      SME(memcpy((*pContent)->bufContent.data.pchData, 
         pbufContent->m_content.Access(), pbufContent->m_content.Length()));
      SME((*pContent)->bufContent.data.lLength = 
         pbufContent->m_content.Length());

      /* set the content type */
      (*pContent)->poidType = pbufContent->m_contentType.GetChar();
   }
   else  if (pContent && (*pContent) != NULL)/* content was separate */
   {
      if ((*pContent)->bufContent.flag == SM_FILE_USED)
         pbuf = new CSM_Buffer((*pContent)->bufContent.data.pchData);
      else
         pbuf = new CSM_Buffer((*pContent)->bufContent.data.pchData,
                  (*pContent)->bufContent.data.lLength);
      if (pbuf == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

      // set the encapsulated content and the content type
      SME(smVerifyMsg.SetEncapContentFromAsn1(*pbuf));
      delete (pbuf);
   }

   // handle the SignerInfo
   if (smVerifyMsg.m_pSignerInfos != NULL)
   {
      pTmpSignerInfos = *pSignerInfos = (SM_SignerInfoLst *)calloc(1, 
         sizeof(SM_SignerInfoLst));
      for (itTmpSI =  smVerifyMsg.m_pSignerInfos->begin(); 
           itTmpSI != smVerifyMsg.m_pSignerInfos->end();
           ++itTmpSI)
      {
        if (count > 1)
        {
          pTmpSignerInfos->pNext = (SM_SignerInfoLst *)
            calloc(1, sizeof(SM_SignerInfoLst));
          pTmpSignerInfos = pTmpSignerInfos->pNext;
        }

        // load Signed Attributes
        if (itTmpSI->m_pSignedAttrs != NULL)
        {
          pSAttrLst = itTmpSI->m_pSignedAttrs->m_pAttrs;

          pTmpSAttrs = pTmpSignerInfos->pSignedAttrs = NULL;
          if (pSAttrLst != NULL)
          {
           /* get the first attribute */
            for (itTmpAttr =  pSAttrLst->begin();
                 itTmpAttr != pSAttrLst->end();
                 ++itTmpAttr)
            {
            /* calloc C version of attribute list if necessary */
              if (pTmpSAttrs == NULL)
               pTmpSAttrs = pTmpSignerInfos->pSignedAttrs = (SM_AttribLst *)
                  calloc(1, sizeof(SM_AttribLst));
              else
              {
               pTmpSAttrs->pNext = (SM_AttribLst *)calloc(1, 
                  sizeof(SM_AttribLst));
               pTmpSAttrs = pTmpSAttrs->pNext;
              }

              AsnOid *pOid = NULL;        
              CSM_Buffer *pEncodedAttr = NULL;

            /* Get oid and encoded buffer of attribute. 
              Set the C attribute list with the values. */
              itTmpAttr->GetEncodedAttr(pOid, pEncodedAttr);
              pTmpSAttrs->poidType = pOid->GetChar();
              pTmpSAttrs->buffer.flag = SM_BUFFER_USED;
              pTmpSAttrs->buffer.data.pchData = pEncodedAttr->Get(); 
              pTmpSAttrs->buffer.data.lLength = pEncodedAttr->Length();
              delete pOid;
              delete pEncodedAttr;
            }       // END FOR each attribute in list.
           }        // END IF pSAttrLst
        }           // END IF itTmpSI->m_pSignedAttrs

        // load Unsigned Attributes
        if (itTmpSI->m_pUnsignedAttrs != NULL)
        {
          pUnSAttrLst = itTmpSI->m_pUnsignedAttrs->m_pAttrs;

          pTmpUnSAttrs = pTmpSignerInfos->pUnSignedAttrs = NULL;
          if (pUnSAttrLst != NULL)
          {
           /* get the first attribute */
            for (itTmpAttr =  pSAttrLst->begin();
                 itTmpAttr != pSAttrLst->end();
                 ++itTmpAttr)
            {
            /* calloc C version of attribute list if necessary */
              if (pTmpUnSAttrs == NULL)
               pTmpUnSAttrs = pTmpSignerInfos->pUnSignedAttrs = (SM_AttribLst *)
                  calloc(1, sizeof(SM_AttribLst));
              else
              {
               pTmpUnSAttrs->pNext = (SM_AttribLst *)calloc(1, 
                  sizeof(SM_AttribLst));
               pTmpUnSAttrs = pTmpUnSAttrs->pNext;
              }

              AsnOid *pOid = NULL;        
              CSM_Buffer *pEncodedAttr = NULL;

            /* Get oid and encoded buffer of attribute.
              Set the C attribute list with the values. */
              itTmpAttr->GetEncodedAttr(pOid, pEncodedAttr);
              pTmpUnSAttrs->poidType = pOid->GetChar();
              pTmpUnSAttrs->buffer.flag = SM_BUFFER_USED;
              pTmpUnSAttrs->buffer.data.pchData = pEncodedAttr->Get(); 
              pTmpUnSAttrs->buffer.data.lLength = pEncodedAttr->Length();
              delete pOid;
              delete pEncodedAttr;
            }       // END FOR each attribute in list.
           }        // END IF pUnSAttrLst
        }           // END IF itTmpSI->m_pUnsignedAttrs
        count++;
     }
   }
      
   // load the certs, Attribute certs and crls if necessary
   if (smVerifyMsg.m_pMsgCertCrls != NULL)
   {
     // load the certs if there are any
     pCertLst = smVerifyMsg.m_pMsgCertCrls->AccessCertificates();

     pTmpCerts = *pCerts = NULL;
     if (pCertLst != NULL)
     {
        for (itTmpCert =  pCertLst->begin();
             itTmpCert != pCertLst->end();
             ++itTmpCert)
        {
          if (pTmpCerts == NULL)
            pTmpCerts = *pCerts = (EncCert_LL *)calloc(1, sizeof(EncCert_LL));
          else
          {
            pTmpCerts->next = (EncCert_LL *)calloc(1, sizeof(EncCert_LL));
            pTmpCerts = pTmpCerts->next;
          }
          pTmpCerts->encCert.data = 
             (uchar *)itTmpCert->AccessEncodedCert()->Get();
          pTmpCerts->encCert.num = 
             itTmpCert->AccessEncodedCert()->Length();
        }       // END FOR each cert in list.
      }         // END IF pCertLst

     // load the attribute certs if there are any
     pACertLst = smVerifyMsg.m_pMsgCertCrls->AccessACs();

     pTmpACerts = *pACs = NULL;
     if (pACertLst != NULL)
     {
        for (itTmpAC =  pACertLst->begin();
             itTmpAC != pACertLst->end();
             ++itTmpAC)
        {
          if (pTmpACerts == NULL)
            pTmpACerts = *pACs = (SM_BufferLst *)calloc(1, 
            sizeof(SM_BufferLst));
          else
          {
            pTmpACerts->pNext = (SM_BufferLst *)calloc(1,
               sizeof(SM_BufferLst));
            pTmpACerts = pTmpACerts->pNext;
          }
          pTmpACerts->buffer.flag = SM_BUFFER_USED;
          pTmpACerts->buffer.data.pchData =
             itTmpAC->AccessEncodedAttrCert()->Get();
          pTmpACerts->buffer.data.lLength = 
             itTmpAC->AccessEncodedAttrCert()->Length();
        }       // END FOR each AC cert in list.
      }         // END IF pACertLst

      // load the crls if there are any
      pRevInfoChoices = smVerifyMsg.m_pMsgCertCrls->AccessCRLLst();
      
      pTmpCrls = NULL;
      if (pRevInfoChoices != NULL)
      {
        for (itTmpCrl =  pRevInfoChoices->begin();
             itTmpCrl != pRevInfoChoices->end();
             ++pRevInfoChoices)
        {
          if (pTmpCrls == NULL)
            pTmpCrls =  (EncCRL_LL *)calloc(1, sizeof(EncCRL_LL));
          else
          {
            pTmpCrls->next = (EncCRL_LL *)calloc(1, sizeof(EncCRL_LL));
            pTmpCrls = pTmpCrls->next;
          }

          // get the CSM_RevocationinfoChoice as a CSM_Buffer and then Get the data
          pTmpCrls->encCRL.data = (uchar *)itTmpCrl->AccessEncodedRevInfo().Get();
          pTmpCrls->encCRL.num = itTmpCrl->AccessEncodedRevInfo().Length();
        }       // END FOR each CRL in list.
      }         // END IF pCrlLst
   }            // END IF smVerifyMsg.m_pMsgCertCrls

   SME_FINISH
   SME_CATCH_SETUP
      /* cleanup code */
      lRet = -1;
   SME_CATCH_FINISH_C2(lpszError);
   if (lpszError && strlen(lpszError))
       std::cout << lpszError;
   std::cout.flush();
   pSignedRec; //AVOIDS warning

   return lRet;
}


/* EOF sm_VerifyC_Support.cpp */
