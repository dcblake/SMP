
// sm_PreProcC.cpp
// This file implements SM_PreProc which is a C wrapper for CSM_EncryptMsg or
// CSM_SignMsg PreProc methods

#include <string.h>
#include "sm_api.h"
extern "C" {
#include "sm_apic.h"
}

    using namespace SFL;
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;

SM_RET_VAL SM_PreProc(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      SM_Buffer *pbufInput, /* ASN.1 encoded ContentInfo */
      SM_StrLst **ppCerts, /* certs from the cert bag */
      SM_Content **ppContent) /* unprocessed content from pbufInput blob */
{
   CSM_Buffer *pbufBlob;
   SM_RET_VAL lRet = SM_NO_ERROR;
   const AsnOid  *poidContent;
   CSM_MsgCertCrls *pMsgCertCrls = NULL;
   CSM_MsgToDecrypt *psmDecryptMsg = NULL;
   CSM_MsgToVerify *psmVerifyMsg = NULL;
   char *lpszError = "";     

   SME_SETUP("SM_PreProc");

   if ((pbufInput == NULL) || (ppContent == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // convert incoming ASN.1 encoded blob into a buffer
   if (pbufInput->flag == SM_FILE_USED)
      pbufBlob = new CSM_Buffer(pbufInput->data.pchData);
   else
      pbufBlob = new CSM_Buffer(pbufInput->data.pchData, 
            pbufInput->data.lLength);
   if (pbufBlob == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // process the blob as a content info
   CSM_ContentInfoMsg contentInfo(pbufBlob);
   if (contentInfo.AccessEncapContentFromAsn1() == NULL)
      SME_THROW(SM_ASN1_DECODE_ERROR, "unable to process content", NULL);

   // allocate memory to return for the content
   if ((*ppContent = (SM_Content *)calloc(1, sizeof(SM_Content))) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   // store the oid of the content
   SME(poidContent = contentInfo.GetContentTypeFromAsn1());
   (*ppContent)->poidType = poidContent->GetChar();
   // store the content
   (*ppContent)->bufContent.flag = SM_BUFFER_USED;
   SME((*ppContent)->bufContent.data.pchData = 
         contentInfo.AccessEncapContentFromAsn1()->m_content.
         Get((*ppContent)->bufContent.data.lLength));

   // do the C++ pre-processing step based on the type of encapsulated
   // content and whether or not we have pCSMIME
   if (contentInfo.IsEnvelopedData())
   {
      if (pCSMIME)
      {
         SME(psmDecryptMsg = new CSM_MsgToDecrypt((CSMIME *)pCSMIME,
               &contentInfo));
      }
      else
      {
         SME(psmDecryptMsg = new CSM_MsgToDecrypt(&contentInfo));
      }

      if (psmDecryptMsg == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

      // get the originator certs if requested
      if ((ppCerts) && (psmDecryptMsg->m_pOriginatorInfo) && 
            (psmDecryptMsg->m_pOriginatorInfo->m_pMsgCertCrls))
         pMsgCertCrls = psmDecryptMsg->m_pOriginatorInfo->m_pMsgCertCrls;
   }
   else if (contentInfo.IsSignedData())
   {
      if (pCSMIME)
      {
         const CSM_Buffer *pEncodedBlob = contentInfo.AccessEncodedBlob();
         SME(psmVerifyMsg = new CSM_MsgToVerify((CSMIME *)pCSMIME, 
               pEncodedBlob));
      }
      else
      {
         SME(psmVerifyMsg = new CSM_MsgToVerify(&contentInfo));
      }

      if (psmVerifyMsg == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

      // get the originator certs if requested
      if ((ppCerts) && (psmVerifyMsg->m_pMsgCertCrls))
         pMsgCertCrls = psmVerifyMsg->m_pMsgCertCrls;
   }
   else
      SME_THROW(SM_INVL_PREPROC_TYPE, 
            "content type isn't enveloped or signed data", NULL);

   // move certs into destination to return them to the caller
   if ((ppCerts) && (pMsgCertCrls))
      SME(*ppCerts = pMsgCertCrls->GetStrLstOfCerts());

   // TBD, lots of cleanup to do such as psmDecryptMsg or psmVerifyMsg

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


/* EOF sm_PreProcC.cpp */
