
// sm_EncryptC.cpp
// This file implements SM_Encrypt which is a C wrapper for CSM_MsgToEncrypt

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
/* SM_Encrypt creates a CMS ContentInfo containing an EnvelopedData */
SM_RET_VAL SM_Encrypt(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      SM_Content *pContent, /* content and type of content */
      SM_OID *poidContentEncryption, /* specified content encryption id */
      EncCert_LL *pRecipients, /* list of certs of recipients */
      short bIncludeOrigCerts, /* include originator certs from CSMIME? */
      short bIncludeOrigAsRecip, /* auto include originator as recip? */
      Bytes_struct *pOutput) /* ASN.1 encoded result */
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   char *lpszError = "";    /* should this be passed in? */
   CSM_Buffer *pbufContent;
   CSM_MsgToEncrypt smEncryptMsg;

   SME_SETUP("SM_Encrypt");

   if ((pCSMIME == NULL) || (pContent == NULL) || (pOutput == NULL) ||
         (poidContentEncryption == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // prep the content
   // TBD, how do we use pContent->poidType?
   if (pContent->bufContent.flag == SM_FILE_USED)
      pbufContent = new CSM_Buffer(pContent->bufContent.data.pchData);
   else
      pbufContent = new CSM_Buffer(pContent->bufContent.data.pchData,
               pContent->bufContent.data.lLength);
   if (pbufContent == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // set the encapsulated content
   SME(smEncryptMsg.SetEncapContentFromAsn1(*pbufContent));
   delete (pbufContent);
   pbufContent = NULL;


   // set content type and select content encryption OID
   AsnOid  oidContentEncryption(poidContentEncryption);
   AsnOid  oidContent(pContent->poidType);
   SME(smEncryptMsg.setContentType(oidContent));
   SME(smEncryptMsg.SetContentEncryptOID(&oidContentEncryption));

   // set optional flags to include originator certs and to include (or not
   // include) originator as a recipient
   if (bIncludeOrigCerts)
      smEncryptMsg.SetIncludeOrigCertsFlag(true);
   if (!bIncludeOrigAsRecip)
      smEncryptMsg.SetAddOriginatorAsRecipient(false);

   // set up recipients
   if (pRecipients)
   {
      EncCert_LL *pTemp = pRecipients;
      CSM_RecipientInfo *pRecipCert;

      do
      {
         // if recipients list already exists, append new recipient
         // based on cert buffer, otherwise, create the recipient
         // list with the cert buffer
         CSM_Buffer tmpbuf((char *)pTemp->encCert.data, pTemp->encCert.num); 
         if (smEncryptMsg.m_pRecipients == NULL)
            if ((smEncryptMsg.m_pRecipients = new CSM_RecipientInfoLst) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
         if ((pRecipCert = &(*smEncryptMsg.m_pRecipients->append())) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
         pRecipCert->m_pCert = new CSM_CertificateChoice(tmpbuf);
      } while ((pTemp = pTemp->next) != NULL);
   }

   // now call encrypt
   SME(smEncryptMsg.Encrypt((CSMIME *)pCSMIME));

   // extract the result
   SME(pbufContent = smEncryptMsg.GetEncodedContentInfo());
   SME(pOutput->num = pbufContent->Length());
	size_t bufLen;
   SME(pOutput->data = (uchar *)pbufContent->Get(bufLen));
   if (pbufContent)
      delete (pbufContent);


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

/* EOF sm_EncryptC.cpp */
