// sm_VerRecC.cpp
// This file calls SM_VerifyC_Support which is a C wrapper for 
// CSM_ReceiptMsgToVerify

#include <string.h>
#include "sm_api.h"
extern "C" {
#include "sm_apic.h"
}

    using namespace SFL;
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;

/* prototype */
SM_RET_VAL SM_VerifyC_Support(
     SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */ 
     SM_Content **pContent, /* output */
     Bytes_struct *pInput, /* ASN.1 encoded Signed Receipt */
     SM_SignerInfoLst **pSignerInfos, /* optional list of SignerInfos */
     EncCert_LL **pCerts, /* list of certs */
     SM_BufferLst **pACs, /* list of attribute certs */
     EncCRL_LL **pCrls, /* list of crls */
     SM_Buffer *pSignedRec, /* Signed Receipt File Name */
     long *receiptreq,   /* is a receipt requested */
     CSM_MsgToVerify &smVerifyMsg);  


extern "C" {
/* SM_VerRec verifys a CMS Signed Receipt */
SM_RET_VAL SM_VerRec(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      Bytes_struct *pInput, /* ASN.1 encoded Signed Receipt */
      Bytes_struct *pOrigSD, /* Original Signed Data */
      SM_SignerInfoLst **pSignerInfos, /* optional list of SignerInfos */
      EncCert_LL **pCerts, /* list of certs */
      SM_BufferLst **pACs, /* list of attribute certs */
      EncCRL_LL **pCrls) /* list of crls */

{
   SM_RET_VAL lRet = SM_NO_ERROR;
   char *lpszError = "";     
   CSM_ReceiptMsgToVerify smRecVerifyMsg;
   CSM_Buffer *pbufOrig = NULL;   

   SME_SETUP("SM_VerRec");

   // Call SM_VerifyC_Support to decode ASN.1 Encoded Enveloped Data
   SME(SM_VerifyC_Support(pCSMIME, (SM_Content **) NULL, pInput, pSignerInfos,
      pCerts, pACs, pCrls, NULL, NULL, smRecVerifyMsg));

   // convert the original signed data from the C Bytes_struct structure 
   // to a C++ CSM_Buffer
   pbufOrig = new CSM_Buffer((char *)pOrigSD->data, pOrigSD->num);
   if (pbufOrig == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME(smRecVerifyMsg.SetOriginalMessage(pbufOrig));

   // now call CSM_VerifyReceiptMsg to decode the signed receipt
   SME(smRecVerifyMsg.Verify((CSMIME *)pCSMIME));

   // Receipts can't contain a receipt request - so no receipt processing
   // done.

   delete pbufOrig;

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


/* EOF sm_VerRecC.cpp */
