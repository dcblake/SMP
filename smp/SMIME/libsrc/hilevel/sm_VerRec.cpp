
//////////////////////////////////////////////////////////////////////////
// sm_VerRec.cpp
// This source file contains the implementations of the methods in
// CSM_ReceiptMsgToVerify, the high level class that verifies a signed
// receipt.
//////////////////////////////////////////////////////////////////////////

#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
CSM_ReceiptMsgToVerify::CSM_ReceiptMsgToVerify(const CSM_ContentInfoMsg *pCIM,
      CSMIME *pCSMIME)
{
   SME_SETUP("CSM_ReceiptMsgToVerify::CSM_ReceiptMsgToVerify(pCIM, pCSMIME)");

   if ((pCIM == NULL) || (pCSMIME == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   InitMembers();

   SME(PreProc(pCSMIME, &(((CSM_ContentInfoMsg *)pCIM)->AccessEncapContentFromAsn1()->m_content)));

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_ReceiptMsgToVerify::InitMembers(void)
{
   m_pbufOriginalMessage = NULL;
   m_lProcessingResults = 0;
}

//////////////////////////////////////////////////////////////////////////
void CSM_ReceiptMsgToVerify::SetOriginalMessage(CSM_Buffer *pOrigMsg)
{
   SME_SETUP("CSM_ReceiptMsgToVerify::SetOriginalMessage");

   if (pOrigMsg == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   if (m_pbufOriginalMessage)
      delete m_pbufOriginalMessage;

   if ((m_pbufOriginalMessage = new CSM_Buffer(*pOrigMsg)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_ReceiptMsgToVerify::GetOrigMsgSigDigest(
         CSM_MsgToVerify &smOrigMsg, // in
         Receipt &snaccReceipt, // in
         CSMIME *pCSMIME, // in
         CSM_Buffer &bufMsgSigDigest) // out
{
   CSM_MsgSignerInfos::iterator itTempMSI;
   SignedAttributes *pSignedAttribs = NULL;
   CSM_Buffer *pbufEncSignedAttribs = NULL;
   CSM_Alg *palgOrigDigest = NULL;
   AsnOid *pTmpOID = NULL;
   AsnOid *pHashOid = NULL;
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_ReceiptMsgToVerify::GetOrigMsgSigDigest");

   // use snaccReceipt to find the correct signer info from smOrigMsg
   if (smOrigMsg.m_pSignerInfos == NULL)
      SME_THROW(SM_ASN1_DECODE_ERROR, "no signer infos in orig msg", NULL);
   for (itTempMSI =  smOrigMsg.m_pSignerInfos->begin();
        itTempMSI != smOrigMsg.m_pSignerInfos->end();
        ++itTempMSI)
   {
      if (snaccReceipt.originatorSignatureValue ==
            itTempMSI->AccessSignerInfo()->signature)
         break;
   }        // END FOR each SI in list.

   // found signer info with original signature in it?
   if (itTempMSI == smOrigMsg.m_pSignerInfos->end())
   {
      SME_THROW(SM_NO_MATCHING_SIGNATURE, "GetOrigMsgSigDigest:  No match in signer infos ** All signer infos must match",
            NULL);
   }
   else
   {
      CSM_ReceiptRequest *pRecReq=
           itTempMSI->m_pSignedAttrs->GetReceiptRequest();
      CSM_Buffer TmpSCID;
      m_lProcessingResults |= origMsgSignatureChecked;  // Indicate signature =
      if (pRecReq)              // Check for receiptRequest Attribute
      {
          TmpSCID.Set(snaccReceipt.signedContentIdentifier.c_str(), 
                      snaccReceipt.signedContentIdentifier.Len());
          if (pRecReq->m_SignedContentIdentifier == TmpSCID)
              m_lProcessingResults |= origMsgIDChecked;
          delete pRecReq;
      }
   }

   // get the Signed attributes from the signer info from
   // the original message that matched the signature value in the
   // receipt and then ASN.1 encode them
   SME(ENCODE_BUF(itTempMSI->AccessSignerInfo()->signedAttrs, pbufEncSignedAttribs));

   // Get the digest algorithm that was used to generate the digest
   // used for the signature
   if ((palgOrigDigest = itTempMSI->GetDigestId()) == NULL)
      SME_THROW(SM_MEMORY_ERROR, "couldn't get digest alg", NULL);

   // find an instance that supports palgOrigDigest
   CSM_CtilInstLst::iterator itTmpInst;
   for (itTmpInst =  pCSMIME->m_pCSInsts->begin();
        itTmpInst != pCSMIME->m_pCSInsts->end();
        ++itTmpInst)
   {
      if ((*itTmpInst)->FindAlgIds(palgOrigDigest, NULL, NULL, NULL))
         break;
   }        // END FOR each login instance in list
   if (itTmpInst == pCSMIME->m_pCSInsts->end())
      SME_THROW(SM_NO_SUPPORTING_INSTANCE, 
            "no instance with requested digest alg", NULL);

   // digest the encoded attributes from the original message
   pTmpOID = (*itTmpInst)->AccessTokenInterface()->GetPrefDigest();
   pHashOid = palgOrigDigest->GetId();
   (*itTmpInst)->SetPreferredCSInstAlgs(pHashOid, NULL, NULL, NULL);
   if ((status = (*itTmpInst)->AccessTokenInterface()->SMTI_DigestData(
         pbufEncSignedAttribs, &bufMsgSigDigest)) != SM_NO_ERROR)
      SME_THROW(status, "SMTI_DigestData returned error.", NULL);

   (*itTmpInst)->SetPreferredCSInstAlgs(pTmpOID, NULL,
         NULL, NULL);
   if (pHashOid)
      delete pHashOid;
   if (palgOrigDigest)
      delete palgOrigDigest;
   if (pTmpOID)
      delete pTmpOID;
   if (pSignedAttribs)
      delete pSignedAttribs;
   if (pbufEncSignedAttribs)
      delete pbufEncSignedAttribs;


   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_ReceiptMsgToVerify::Verify(CSMIME *pCSMIME, 
        const CSM_Buffer &bufOrigMsgSigDigest, const AsnOid &oidDigestOid)
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   Receipt snaccReceipt;
   //CSM_ContentInfoMsg *pCIM;
   CSM_Buffer *pbufMsgSigDigest = NULL; 
   CSM_MsgSignerInfos::iterator itTempMSI;

   SME_SETUP("CSM_ReceiptMsgToVerify::Verify(OrigMsgSigDigest)");

   if ((pCSMIME == NULL) || (pCSMIME->m_pCSInsts == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // pre-proc was done by the constructor, so at this pointer, we
   // should have an ASN.1 decoded SignedData in this::CSM_VerifyData
   // ASN.1 decode the receipt
   // snaccReceipt must be filled in for GetOrigMsgSigDigest(...) 
   if (AccessEncapContentClear() != NULL)
   {
      SME(DECODE_BUF(&snaccReceipt, &AccessEncapContentClear()->m_content));
   }

   // check to make sure that we have some signer infos
   if (m_pSignerInfos == NULL)
      SME_THROW(SM_ASN1_DECODE_ERROR, "no signer infos in msg", NULL);

   SME(CSM_MsgToVerify::Verify(pCSMIME));
   if (this->CSM_MsgToVerify::m_lProcessingResults & msgSignatureVerified)
       this->m_lProcessingResults |= msgSignatureVerified;

   for (itTempMSI =  m_pSignerInfos->begin(); 
        itTempMSI != m_pSignerInfos->end();
        ++itTempMSI)
   {
      if (itTempMSI->AccessSignerInfo()->digestAlgorithm.algorithm == oidDigestOid)
      {                     // BE SURE we locate the specific digested result.
          // get the message signature digest Signed attribute
          // out of this message signer info
          if ((pbufMsgSigDigest = itTempMSI->m_pSignedAttrs->GetMsgSigDigest()) 
                == NULL)
             SME_THROW(SM_MEMORY_ERROR, "couldn't access msg sig digest attr",
                   NULL);

          // compare the original message's sig digest with this message's
          // sig digest, if they are different, fail...
          if (*pbufMsgSigDigest != bufOrigMsgSigDigest)
          {
             lRet = SM_VALRECERR_MSG_SIG_DIGEST;
             break;
          }
          else
          {
             this->m_lProcessingResults |= msgSigDigestChecked;
          }
          if (pbufMsgSigDigest)
             delete pbufMsgSigDigest;
      }     // END if oidDigestOid located

    }       // END FOR each SI in list


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return lRet;
}       // END CSM_ReceiptMsgToVerify::Verify(..., MsgSigDigest)


//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_ReceiptMsgToVerify::Verify(CSMIME *pCSMIME)
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   SNACC::Receipt snaccReceipt;
   //CSM_ContentInfoMsg *pCIM;
   CSM_Buffer *pbufMsgSigDigest = NULL; 
   CSM_Buffer bufOrigMsgSigDigest;
   CSM_MsgSignerInfos::iterator itTempMSI;
   CSM_MsgToVerify smOrigMsg;

   SME_SETUP("CSM_ReceiptMsgToVerify::Verify");

   if ((pCSMIME == NULL) || (pCSMIME->m_pCSInsts == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // pre-proc was done by the constructor, so at this pointer, we
   // should have an ASN.1 decoded SignedData in this::CSM_VerifyData
   // ASN.1 decode the receipt
   // snaccReceipt must be filled in for GetOrigMsgSigDigest(...) 
   if (AccessEncapContentClear() != NULL)
   {
      AccessEncapContentClear()->m_content.Decode(snaccReceipt);
   }

   // add content info wrap
   CSM_ContentInfoMsg contentInfo(m_pbufOriginalMessage);
   if (!contentInfo.IsSignedData())
      SME_THROW(SM_UNKNOWN_ERROR, "content doesn't contain a SignedData", NULL);

   // call preproc()
   smOrigMsg.PreProc(pCSMIME, &(contentInfo.AccessEncapContentFromAsn1()->m_content));

   // check to make sure that we have some signer infos
   if (m_pSignerInfos == NULL)
      SME_THROW(SM_ASN1_DECODE_ERROR, "no signer infos in msg", NULL);

   SME(CSM_MsgToVerify::Verify(pCSMIME));
   // TBD check that at least 1 signature was verified
   if (this->CSM_MsgToVerify::m_lProcessingResults & msgSignatureVerified)
       this->m_lProcessingResults |= msgSignatureVerified;

   // calculate the msg sig digest and the message digest using
   // data from the original message
   //SME(GetOriginalMsgInfo(smOrigMsg, snaccReceipt, pCSMIME, 
    //  bufOrigMsgSigDigest, bufOrigMessageDigest));
   SME(GetOrigMsgSigDigest(smOrigMsg, snaccReceipt, pCSMIME, 
      bufOrigMsgSigDigest));

   for (itTempMSI =  m_pSignerInfos->begin();
        itTempMSI != m_pSignerInfos->end();
        ++itTempMSI)
   {
      // get the message signature digest Signed attribute
      // out of this message signer info
      if ((pbufMsgSigDigest = itTempMSI->m_pSignedAttrs->GetMsgSigDigest()) 
            == NULL)
         SME_THROW(SM_MEMORY_ERROR, "couldn't access msg sig digest attr",
               NULL);

      // compare the original message's sig digest with this message's
      // sig digest, if they are different, fail...
      if (*pbufMsgSigDigest != bufOrigMsgSigDigest)
      {
         lRet = SM_VALRECERR_MSG_SIG_DIGEST;
         break;
      }
      else
      {
       this->m_lProcessingResults |= msgSigDigestChecked;
      }
      if (pbufMsgSigDigest)
         delete pbufMsgSigDigest;

    }       // END FOR each SI in list.


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return lRet;
}           // END CSM_ReceiptMsgToVerify::Verify(... original message)

//
//
void CSM_ReceiptMsgToVerify::ReportMsgData(std::ostream &os)
{
    os << "##### RECEIPT MESSAGE VERIFICATION #######\n";
    os << "   The msgSigDigest was ";
    if (!(m_lProcessingResults & msgSigDigestChecked))
        os << " NOT ";
    os << "SUCCESSFUL in the comparison to the original message.\n";
    os << "   The Original Message ID was ";
    if (!(m_lProcessingResults & origMsgIDChecked))
        os << " NOT ";
    os << "SUCCESSFUL in the comparison to the original message ID.\n";
    os << "   The Original Message Signature was ";
    if (!(m_lProcessingResults & origMsgSignatureChecked))
        os << " NOT ";
    os << "SUCCESSFUL in the comparison to the original message signature.\n";
}

_END_SFL_NAMESPACE

// EOF sm_VerRec.cpp
