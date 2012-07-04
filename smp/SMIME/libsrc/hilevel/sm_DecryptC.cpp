
// sm_DecryptC.cpp
// This file implements SM_Decrypt which is a C wrapper for CSM_MsgToDecrypt

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
/* SM_Decrypt decrypts a CMS EnvelopedData */
SM_RET_VAL SM_Decrypt(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      SM_Content **pContent, /* output */
      EncCert_LL **pRecipients, /* list of certs of recipients */
      Bytes_struct *pInput) /* ASN.1 encoded EnvelopedData */
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   char *lpszError = "";     
   CSM_Buffer *pbufInput = NULL;   
   CSM_MsgToDecrypt smDecryptMsg;
   const CSM_Content *pbufContent = NULL;
   CSM_RecipientInfoLst::iterator itTmpRecip;

   SME_SETUP("SM_Decrypt");

   // check for missing parameters
   if ((pCSMIME == NULL) || (*pContent == NULL) || (pInput == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // convert the input from the C Bytes_struct structure to a C++ CSM_Buffer
   pbufInput = new CSM_Buffer((char *)pInput->data, pInput->num);
   if (pbufInput == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // process the input as a content info
   CSM_ContentInfoMsg contentInfo(pbufInput);
   if (!contentInfo.IsEnvelopedData())
      SME_THROW(SM_UNKNOWN_ERROR, "content doesn't contain an EnvelopedData",
            NULL);
   delete(pbufInput);

   // Pre Process the encoded blob as a content info
   SME(smDecryptMsg.PreProc((CSMIME *)pCSMIME, 
      (CSM_Buffer *)&(contentInfo.AccessEncapContentFromAsn1()->m_content)));   

   // now call decrypt to decode ASN.1 Encoded Enveloped Data
   SME(smDecryptMsg.Decrypt((CSMIME *)pCSMIME));

   // pull out the inner content
   pbufContent = smDecryptMsg.AccessEncapContentFromAsn1();

#ifdef RWC_NO_OP_QUESTION
   EncCert_LL *pstrLstTemp = NULL;
   // fill recipients if there are any
   pstrLstTemp = *pRecipients = NULL;
   if (smDecryptMsg.m_pRecipients)
   {
      for (itTmpRecip =  smDecryptMsg.m_pRecipients->begin();
           itTmpRecip != smDecryptMsg.m_pRecipients->end();
           ++itTmpRecip)
      {
         if (pstrLstTemp == NULL)
            pstrLstTemp = *pRecipients = (EncCert_LL *)calloc(1, sizeof(EncCert_LL));
         else
         {
            pstrLstTemp->next = (EncCert_LL *)calloc(1, sizeof(EncCert_LL));
            pstrLstTemp = pstrLstTemp->next;
         }
//         pstrLstTemp->encCert.data = 
//          (uchar *)pTmpRecip->m_pCert->AccessEncodedCert()->Get();
//         pstrLstTemp->encCert.num =
//          pTmpRecip->m_pCert->AccessEncodedCert()->Length();
      }         // END FOR each RI in list.
   }
#endif // RWC_NO_OP_QUESTION

   // set up pContent as a Buffer and fill
   (*pContent)->bufContent.flag = SM_BUFFER_USED;
   (*pContent)->bufContent.data.pchData = (char *)calloc(1, pbufContent->m_content.Length());
   SME(memcpy((*pContent)->bufContent.data.pchData, pbufContent->m_content.Access(),
        pbufContent->m_content.Length()));
   SME((*pContent)->bufContent.data.lLength = pbufContent->m_content.Length());

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
/* EOF sm_DecryptC.cpp */
