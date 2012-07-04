// sm_SignC.cpp
// This file implements SM_Sign which is a C wrapper for CSM_MsgToSign

#include <string.h>
#include "sm_api.h"
extern "C" {
#include "sm_apic.h"
}

    using namespace SFL;
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;


extern "C" {
/* SM_Sign creates a CMS ContentInfo containing a SignedData */
SM_RET_VAL SM_Sign(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      SM_Content *pContent, /* content and type of content */
      SM_SignerInfoLst *pSignerInfos, /* optional list of SignerInfos */
      EncCert_LL *pCerts, /* list of certs */
      SM_BufferLst *pACs, /* list of attribute certs */
      EncCRL_LL *pCrls, /* list of crls */
      short bIncludeOrigCerts, /* include originator certs from CSMIME? */
      short bIncludeContent, /* include Content from CSMIME? */
      Bytes_struct *pOutput) /* ASN.1 encoded result */
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   char *lpszError = "";    /* should this be passed in? */
   CSM_Buffer *pbufContent = NULL;
   CSM_MsgToSign smSignMsg;

   SME_SETUP("SM_Sign");

   if ((pCSMIME == NULL) || (pContent == NULL) || (pOutput == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // prep the content
   if (pContent->bufContent.flag == SM_FILE_USED)
      pbufContent = new CSM_Buffer(pContent->bufContent.data.pchData);
   else
      pbufContent = new CSM_Buffer(pContent->bufContent.data.pchData,
               pContent->bufContent.data.lLength);
   if (pbufContent == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   
   // set the encapsulated content and the content type
   SME(smSignMsg.SetEncapContentClear(*pbufContent, AsnOid(pContent->poidType)));
   delete (pbufContent);

   // additional signatures ???

   // set optional flags to include originator certs 
   if (bIncludeOrigCerts)
      smSignMsg.SetIncludeOrigCertsFlag(true);
   else
      smSignMsg.SetIncludeOrigCertsFlag(false);

   // set optional flags to include content 
   if (bIncludeContent)
      smSignMsg.SetIncludeContentFlag(true);
   else
      smSignMsg.SetIncludeContentFlag(false);

   if (pSignerInfos)
   {
      // set signed attributes
      if (pSignerInfos->pSignedAttrs)
      {
         SM_AttribLst *pTempSAttr = pSignerInfos->pSignedAttrs;
         CSM_Attrib *pSAttr = NULL;
         CSM_Buffer *ptmp_buf;
         do
         {
            // Use AddAttrib to copy the attributes into the 
            // m_pSignedAttrs list
            ptmp_buf = new CSM_Buffer(pTempSAttr->buffer.data.pchData,
                  pTempSAttr->buffer.data.lLength);

            AsnOid tempoid(pTempSAttr->poidType);
            if ((pSAttr = new CSM_Attrib(tempoid, *ptmp_buf)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            if (smSignMsg.m_pSignedAttrs == NULL)
               if ((smSignMsg.m_pSignedAttrs = new CSM_MsgAttributes) == NULL)
                  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            SME(smSignMsg.m_pSignedAttrs->AddAttrib(*pSAttr));
          delete ptmp_buf;
         } while ((pTempSAttr = pTempSAttr->pNext) != NULL);
      }

      // set unsigned attributes
      if (pSignerInfos->pUnSignedAttrs)
      {
         SM_AttribLst *pTempUnSAttr = pSignerInfos->pUnSignedAttrs;
         CSM_Attrib *pUnSAttr = NULL;
         CSM_Buffer *ptmp_buf;
         do
         {
            // Use AddAttrib to copy the attributes into the 
            // m_pUnsignedAttrs list
            ptmp_buf = new CSM_Buffer(pTempUnSAttr->buffer.data.pchData,
                  pTempUnSAttr->buffer.data.lLength);
            AsnOid tmpoid2(pTempUnSAttr->poidType);
            if ((pUnSAttr = new CSM_Attrib(tmpoid2, *ptmp_buf)) == NULL) 
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            if (smSignMsg.m_pUnsignedAttrs == NULL)
               if ((smSignMsg.m_pUnsignedAttrs = new CSM_MsgAttributes) == NULL)
                  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            SME(smSignMsg.m_pUnsignedAttrs->AddAttrib(*pUnSAttr));
          delete ptmp_buf;
         } while ((pTempUnSAttr = pTempUnSAttr->pNext) != NULL);
      }
   }

   // set the certificates
   if (pCerts)
   {
      EncCert_LL *pTemp = pCerts;
      CSM_CertificateChoice *pCert = NULL;

      do
      {
         // Use AddCert to copy the certificates into the private 
         // m_pCerts member of m_pMsgCertCrls
         CSM_Buffer tmpbuf((char *)pTemp->encCert.data, pTemp->encCert.num);
         if ((pCert = new CSM_CertificateChoice(tmpbuf)) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         if (smSignMsg.m_pMsgCertCrls == NULL)
            if ((smSignMsg.m_pMsgCertCrls = new CSM_MsgCertCrls) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

         SME(smSignMsg.m_pMsgCertCrls->AddCert(pCert));
         delete pCert;
         pCert = NULL;  // sib 09/27/02 AddCert no longer deletes pCert

      } while ((pTemp = pTemp->next) != NULL);
   }

   // set the attribute certificates
   if (pACs)
   {
      SM_BufferLst *pTempAC = pACs;
      CSM_CertificateChoice *pAC = NULL;

      do
      {
         // Use AddCert to copy the Attribute certificates into the private 
         // m_pACs member of m_pMsgCertCrls
         CSM_Buffer tmpbuf(pTempAC->buffer.data.pchData,
            pTempAC->buffer.data.lLength);
         if ((pAC = new CSM_CertificateChoice(tmpbuf)) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         if (smSignMsg.m_pMsgCertCrls == NULL)
            if ((smSignMsg.m_pMsgCertCrls = new CSM_MsgCertCrls) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         SME(smSignMsg.m_pMsgCertCrls->AddCert(pAC));
        
         // sib 09/27/02 AddCert no longer deletes pAC;
         delete pAC;
         pAC = NULL;

      } while ((pTempAC = pTempAC->pNext) != NULL);
   }

   // set the crls
   if (pCrls)
   {
      if (smSignMsg.m_pMsgCertCrls == NULL)
      {
         if ((smSignMsg.m_pMsgCertCrls = new CSM_MsgCertCrls) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
      }

      EncCRL_LL *pTempCrl = pCrls;
      while (pTempCrl != NULL)
      {
         CSM_RevocationInfoChoice tempRevInfo(CML::CRL(pTempCrl->encCRL));
         smSignMsg.m_pMsgCertCrls->AddCRL(&tempRevInfo);
      }
   }

   // now call Sign
   SME(smSignMsg.Sign((CSMIME *)pCSMIME));

   // extract the result
   SME(pbufContent = smSignMsg.GetEncodedContentInfo());
   SME(pOutput->num = pbufContent->Length());
	size_t bufLen;
   SME(pOutput->data = (uchar *)pbufContent->Get(bufLen));

   delete pbufContent;

   SME_FINISH
   SME_CATCH_SETUP
      /* cleanup code */
      lRet = -1;
   SME_CATCH_FINISH_C2(lpszError);
   if (lpszError && strlen(lpszError))
       std::cout << lpszError;
   std::cout.flush();

   return lRet;
}

} // end extern 'C'

/* EOF sm_SignC.cpp */
