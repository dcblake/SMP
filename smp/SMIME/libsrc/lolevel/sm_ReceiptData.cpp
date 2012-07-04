
#include <stdlib.h>
#include <malloc.h>
#ifdef WIN32
#include <string.h>
#else
#include <string>
#endif
#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

CSM_DataToReceipt::CSM_DataToReceipt()
{
  Clear();
}

//////////////////////////////////////////////////////////////////////////
CSM_DataToReceipt::~CSM_DataToReceipt()
{
   SME_SETUP("CSM_DataToReceipt::~CSM_DataToReceipt");
   if (m_pSnaccReceipt)
      delete m_pSnaccReceipt;
   if (m_pFirstRecReq)
      delete m_pFirstRecReq;
   if (m_pContentInfo)
      delete m_pContentInfo;
   if (m_pMust)
      delete m_pMust;

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// CSM_VerifyData::InitReceipt
//
// purpose of this function is to initialize the receipt with a SignerInfo.
// if the receipt has already been initialize it will be deleted and then
// initialized again.
//
SM_RET_VAL CSM_DataToReceipt::InitReceipt( CSMIME *pCSMIME ,   
                                SignedData *m_pSnaccSignedData,
                                 CSM_Buffer *pOriginalEncapContent)
{
   AsnOid  *pOid = NULL;
   CSM_ReceiptRequest *pRecReq = NULL;
   SignerInfo *p_snaccSI = NULL;
   CSM_Buffer *pD1 = NULL;
   CSM_Buffer *pMessageDigest = NULL;
   CSM_Attrib *pNewAttrib = NULL;
   CSM_Buffer *pD2 = NULL;
   CSM_CSInst *pInst = NULL;
   long status = 0;
   CSM_Buffer *pMsgSigDigest = NULL;
   AsnOid  *pTmpOID, *pHashOid;
 

   SME_SETUP("CSM_VerifyData::InitReceipt");

   if (m_pSnaccReceipt != NULL)
      delete m_pSnaccReceipt;
   else
      m_pSnaccReceipt = new Receipt; 

   // Set Receipt version feild to v1
   //
   m_pSnaccReceipt->version = 1;

   // Copy object identifier from the contentType attribute included in 
   // the original signedData singerInfo (p_SI) which includes the
   // receiptRequest attribute.  Copy it into the Receipt contentType.
   //
   // note: if there are any signed attributes present then the
   //       content type atttribute MUST be present (CMS 11.1)
   //
   pOid = m_pSIRecReq->m_pSignedAttrs->GetContentType();
   if (pOid == NULL)
   {
      SME_THROW(SM_MISSING_PARAM,"required attribute ContentType not present",
                NULL);
   } 
   //RWC;p_snaccOid = pOid->GetSNACCOid();
   m_pSnaccReceipt->contentType.Set( *pOid);
   delete pOid;

   // Copy the  original signedData signerInfo receiptRequest 
   // signedContentIdentifier into the Receipt singedContentIdentifier.
   // 
   pRecReq = m_pSIRecReq->m_pSignedAttrs->GetReceiptRequest();

   m_pSnaccReceipt->signedContentIdentifier.Set( 
            pRecReq->m_SignedContentIdentifier.Access(),
            pRecReq->m_SignedContentIdentifier.Length());
   delete pRecReq;
   // Copy the signature value from the original signedData signerInfo that
   // includes the receiptRequest attribute into the Receipt 
   // originatorSignatureValue.
   //
   p_snaccSI = m_pSIRecReq->AccessSignerInfo();
   m_pSnaccReceipt->originatorSignatureValue = p_snaccSI->signature; 

   // Load MUST Signedenticated attributes: msgSigDigest, messageDigest,
   // contentType.
   //

   // First MUST Signedenticated attribute is messageDigest
   //
   // ASN.1 DER encode Receipt and Digest it.  Load digested value
   // (messageDigest) into m_pMustAttribs member.
   //
   ENCODE_BUF(m_pSnaccReceipt, pD1);
   
   p_snaccSI = m_pSIRecReq->AccessSignerInfo();
  
   CSM_Alg alg1(p_snaccSI->digestAlgorithm);
   CSM_Alg alg2(p_snaccSI->signatureAlgorithm);

   SME(pInst = CSM_SignBuf::GetFirstInstance(pCSMIME, &alg1, &alg2));
   
   pMessageDigest = new CSM_Buffer;

   pTmpOID = pInst->AccessTokenInterface()->GetPrefDigest();
   pHashOid = alg1.GetId();
   pInst->SetPreferredCSInstAlgs(pHashOid, NULL, NULL, NULL);
   delete pHashOid;
   SME( status = pInst->AccessTokenInterface()->SMTI_DigestData( pD1, 
        pMessageDigest) );
   
   if (status != SM_NO_ERROR)
   {
      // PL: update error code
      SME_THROW(99, "Digest of Receipt failed!", NULL);
   }

   pNewAttrib = new CSM_Attrib;
   SME(pNewAttrib->SetMessageDigest(pMessageDigest));
   delete pMessageDigest;

   if (m_pMust == NULL)
      m_pMust = new CSM_MsgAttributes;

   m_pMust->AddAttrib( *pNewAttrib );
   delete pNewAttrib;

   // Second.  Load msgSigDigest attribute.  This value was calculated
   // during verify of the SignerInfo.  But currently there is no way to
   // pass back that digest so I'm going to recalculated it here.
   // 
   //
   pNewAttrib = new CSM_Attrib;
   
   SME(ENCODE_BUF(p_snaccSI->signedAttrs, pD2));
   
   pMsgSigDigest = new CSM_Buffer;

   SME( status = pInst->AccessTokenInterface()->SMTI_DigestData( pD2, 
        pMsgSigDigest) );
   pInst->SetPreferredCSInstAlgs(pTmpOID, NULL, NULL, NULL);
   delete pTmpOID;

   if (status != SM_NO_ERROR)
   {
      // PL: update error code
      SME_THROW(99, "Digest of SingerInfo Signed Attribtes Failed",
                NULL);
   }

   SME(pNewAttrib->SetMsgSigDigest(pMsgSigDigest));

   delete pMsgSigDigest;

   m_pMust->AddAttrib( *pNewAttrib );
   delete pNewAttrib;

   // get ContentInfo 
   if (m_pSnaccSignedData->encapContentInfo.eContent != NULL)
   {
      m_pContentInfo = new CSM_Buffer(
         m_pSnaccSignedData->encapContentInfo.eContent->c_str(),
         m_pSnaccSignedData->encapContentInfo.eContent->Len() );
   }
   else if (pOriginalEncapContent != NULL) 
      // MUST BE PRESENT if not in SD msg.
   {  // pOriginalEncapContent provided by caller.
      m_pContentInfo = new CSM_Buffer(*pOriginalEncapContent);
   }
   else
   {
      SME_THROW(SM_MISSING_PARAM, 
         "encapsulated content not present in MSG OR param", NULL);
   }

   if (pD2)
       delete pD2;
   if (pD1)
       delete pD1;

   SME_FINISH_CATCH
   
   return SM_NO_ERROR;
}

// This function will process the receipt request attribute if it is
// present in the SignerInfo.
//
//                                         
// This is the place to verify that the following               
// signed attributes are identical in each            
// signer info:
//   * security label
//   * ML expansion history
//   * receipt request (only if APP want to return receipt)
//
// For each SignerInfo that was verified and contains a
// a receipt request the receipt request attribute and
// mlExpansionHistory attributes must be identical in 
// each signer info. 
//

SM_RET_VAL CSM_DataToReceipt::ProcessRecReq(CSM_MsgSignerInfo *p_SI)
{

   AsnOid             RecReqOid(id_aa_receiptRequest);
   CSM_Attrib        *pTmpAttrib = NULL;
   CSM_Buffer        *pCurrRecReq = NULL;
   CSM_ReceiptRequest *pReceiptRequest;
   SM_RET_VAL        status=0;
   
   SME_SETUP("CSM_DataToReceipt::ProcessRecReq");

   if (p_SI->m_pSignedAttrs)
   {
     pReceiptRequest = p_SI->m_pSignedAttrs->GetReceiptRequest();
     if (pReceiptRequest)
     {
        pTmpAttrib = new CSM_Attrib(pReceiptRequest);
        pCurrRecReq = pTmpAttrib->m_pEncodedAttrib;

        // ML Expansion History Check is in the member function 
        // CSM_MsgToVerify:: ReceiptFromUs

        if (pCurrRecReq != NULL) 
        {
          if (m_pFirstRecReq == NULL)
          {
           m_pFirstRecReq = new CSM_Buffer(*pCurrRecReq);
           m_pSIRecReq = p_SI;
          }
          else if (m_pFirstRecReq != pCurrRecReq)
          {
           // If the first receipt request doesn't equal the
           // current receipt request error out.
           //
           if (m_pFirstRecReq->Compare(*pCurrRecReq) != 0)
           {
              SME_THROW(SM_RECREQ_ERROR, 
                      "Receipt Request Attribute not identical.", 
                      NULL);
           }
          }
        }
        delete pTmpAttrib;
        delete pReceiptRequest;
     }
     else
        status = 2;          // FLAG indicating no receipt was requested, 
                             //  not an error.
   }
   else
        status = SM_MISSING_PARAM; // RWC; indicate failure, missing Signed attrs.

   SME_FINISH_CATCH

   return(status);
}

_END_SFL_NAMESPACE

// EOF sm_ReceiptData.cpp
