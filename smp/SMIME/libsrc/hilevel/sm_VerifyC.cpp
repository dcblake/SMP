// sm_VerifyC.cpp
// This file calls SM_VerifyC_Support which is a C wrapper for 
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

/* prototype */
SM_RET_VAL SM_VerifyC_Support(
     SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */ 
     SM_Content **pContent, /* output */
     Bytes_struct *pInput, /* ASN.1 encoded SignedData */
     SM_SignerInfoLst **pSignerInfos, /* optional list of SignerInfos */
     EncCert_LL **pCerts, /* list of certs */
     SM_BufferLst **pACs, /* list of attribute certs */
     EncCRL_LL **pCrls, /* list of crls */
     SM_Buffer *pSignedRec, /* Signed Receipt File Name */
     long *receiptreq,   /* is a receipt requested */
     CSM_MsgToVerify &smVerifyMsg);  


extern "C" {
/* SM_Verify verifys a CMS SignedData */
SM_RET_VAL SM_Verify(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      SM_Content **pContent, /* input or output */
      Bytes_struct *pInput, /* ASN.1 encoded SignedData */
      SM_SignerInfoLst **pSignerInfos, /* optional list of SignerInfos */
      EncCert_LL **pCerts, /* list of certs */
      SM_BufferLst **pACs, /* list of attribute certs */
      EncCRL_LL **pCrls, /* list of crls */
      SM_Buffer *pSignedRec, /* Signed Receipt File Name */
      long *receiptreq)      /* is a receipt requested */

{
   SM_RET_VAL lRet = SM_NO_ERROR;
   char *lpszError = "";     
   CSM_MsgToVerify smVerifyMsg;

   SME_SETUP("SM_Verify");


   // Call SM_VerifyC_Support to decode ASN.1 Encoded Enveloped Data
   SME(SM_VerifyC_Support(pCSMIME, pContent, pInput, pSignerInfos,
      pCerts, pACs, pCrls, pSignedRec, receiptreq, smVerifyMsg));

   // now call Verify to decode ASN.1 Encoded Enveloped Data
   SME(smVerifyMsg.Verify((CSMIME *)pCSMIME));

   // get the signed receipt if there is one
   if ((*receiptreq) && (smVerifyMsg.ReceiptFromUs((CSMIME *)pCSMIME)))
   {
      CSM_Buffer *pSRec = NULL;
     
      pSRec = smVerifyMsg.GetSignedReceipt((CSMIME *)pCSMIME, NULL, NULL);
      if (pSRec)
      {
          pSRec->ConvertMemoryToFile(pSignedRec->data.pchData);
          delete pSRec;
      }
   }


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


/* EOF sm_VerifyC.cpp */
