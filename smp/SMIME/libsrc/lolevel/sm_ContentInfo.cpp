
//////////////////////////////////////////////////////////////////////////
// sm_ContentInfo.cpp
// This file provides the ContentInfo class support functionality.
//////////////////////////////////////////////////////////////////////////

#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
CSM_ContentInfoMsg::CSM_ContentInfoMsg()
{
   m_pSNACCContentInfo = NULL;
}

//////////////////////////////////////////////////////////////////////////
// This constructor builds a CSM_ContentInfo class from a SNACC ContentInfo
//  ASN.1 encoded Buffer (NOT CONTENT).
CSM_ContentInfoMsg::CSM_ContentInfoMsg(const SNACC::ContentInfo &SNACCCI)
{
   CSM_Buffer ContentBuf;
   AsnOcts SNACCOcts;

   SME_SETUP("CSM_ContentInfoMsg: ");

   m_pSNACCContentInfo = NULL;  // pre-initialize

   ContentBuf.Encode((ContentInfo &)SNACCCI);
   SME(SetEncodedCI(ContentBuf));

   SME_FINISH
   SME_CATCH_SETUP
      if (m_pSNACCContentInfo)
          delete m_pSNACCContentInfo;
   SME_CATCH_FINISH
}


//////////////////////////////////////////////////////////////////////////
// This constructor builds a CSM_ContentInfo class from a SNACC ContentInfo
//  ASN.1 encoded Buffer (NOT CONTENT).
CSM_ContentInfoMsg::CSM_ContentInfoMsg(CSM_Buffer *pMessageBuf)
{
   CSM_Buffer ContentBuf;
   AsnOcts SNACCOcts;

   SME_SETUP("CSM_ContentInfoMsg: CSM_Buffer");

   m_pSNACCContentInfo = NULL;  // pre-initialize

   SME(SetEncodedBlob(pMessageBuf));
   
   if (pMessageBuf == NULL)
      SME_THROW(SM_MEMORY_ERROR, "pMessageBuf parameter is NULL", NULL);
   if ((m_pSNACCContentInfo = new ContentInfo) == NULL)
      SME_THROW(SM_MEMORY_ERROR, "MALLOC FAILURE", NULL);

   CSM_Buffer *pA= &ContentBuf;
   SME(DECODE_BUF(m_pSNACCContentInfo, pMessageBuf));
   SME(SM_EXTRACT_ANYBUF(pA, &m_pSNACCContentInfo->content));
   if (m_pSNACCContentInfo->contentType == id_data)    
   {               // perform decode of OCTET STRING
      DECODE_BUF(&SNACCOcts, &ContentBuf);
      ContentBuf.Set(SNACCOcts.c_str(), SNACCOcts.Len());
         
         // Only assigne Octet contents, already decoded for user.
   }
   AsnOid  tmpoid(m_pSNACCContentInfo->contentType);

   SME(SetEncapContentFromAsn1(ContentBuf, tmpoid));

   SME_FINISH
   SME_CATCH_SETUP
      if (m_pSNACCContentInfo)
          delete m_pSNACCContentInfo;
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
CSM_ContentInfoMsg::~CSM_ContentInfoMsg()
{
   if (m_pSNACCContentInfo)
      delete m_pSNACCContentInfo;
}

//////////////////////////////////////////////////////////////////////////
// indicates if the Outer Content Type is SignedData
bool CSM_ContentInfoMsg::IsSignedData()
{
   bool result=false;

   if (AccessEncapContentFromAsn1()->m_contentType == id_signedData)
      result = true;

   return(result);
}

//////////////////////////////////////////////////////////////////////////
// indicates if the Outer Content Type is EnvelopedData
bool CSM_ContentInfoMsg::IsEnvelopedData()
{
   bool result=false;

   if (AccessEncapContentFromAsn1()->m_contentType == id_envelopedData)
      result = true;

   return(result);
}

//////////////////////////////////////////////////////////////////////////
// indicates if the Outer Content Type is EncryptedData
bool CSM_ContentInfoMsg::IsEncryptedData()
{
   bool result=false;

   if (AccessEncapContentFromAsn1()->m_contentType == id_encryptedData)
      result = true;

   return(result);
}
//////////////////////////////////////////////////////////////////////////
// indicates if the Outer Content Type is Data
bool CSM_ContentInfoMsg::IsData()
{
   bool result=false;

   if (AccessEncapContentFromAsn1()->m_contentType == id_data)
      result = true;

   return(result);
}

//////////////////////////////////////////////////////////////////////////
// indicates if the Outer Content Type is compressedData
bool CSM_ContentInfoMsg::IsCompressedData()
{
   bool result=false;

   if (AccessEncapContentFromAsn1()->m_contentType == id_ct_compressedData)
      result = true;

   return(result);
}

//////////////////////////////////////////////////////////////////////////
// indicates if the Outer Content Type is TimeStampToken Data
bool CSM_ContentInfoMsg::IsTimeStampTokenData()
{
   bool result=false;

   if (AccessEncapContentFromAsn1()->m_contentType == id_aa_timeStampToken)
      result = true;

   return(result);
}



//////////////////////////////////////////////////////////////////////////
// indicates if the INNER (encapsulated) Content Type is Receipt
bool CSM_ContentInfoMsg::IsReceipt()
{
   CSM_Buffer *pContentBuf=NULL;
   SignedData snaccSD;
   bool result=false;
   long status;

   SME_SETUP("CSM_ContentInfoMsg::IsReceipt");

   // outer content must be a signeddata
   if (IsSignedData())
   {
      SME(SM_EXTRACT_ANYBUF(pContentBuf, &m_pSNACCContentInfo->content));
      //DECODE_BUF(&snaccSD, pContentBuf);
         SME(DECODE_BUF_NOFAIL(&snaccSD, pContentBuf, status));
#ifdef RWC_TEST_ANY_ENCAPCONTENT
        if (status != 0)
        {
            CSM_Buffer *pBuf=NULL;
            VDASignedDataReceiptOnly *pB = new VDASignedDataReceiptOnly;
            SME(DECODE_BUF(pB, pContentBuf));
            snaccSD.certificates = pB->certificates;
            pB->certificates = NULL;    // Take memory.
            snaccSD.crls = pB->crls;
            pB->crls = NULL;    // Take memory.
            snaccSD.signerInfos = pB->signerInfos;
            snaccSD.digestAlgorithms = pB->digestAlgorithms;
            snaccSD.version = pB->version;
            snaccSD.encapContentInfo->eContentType = 
                pB->encapContentInfo->eContentType;
            SM_EXTRACT_ANYBUF(pBuf, pB->encapContentInfo->eContent)
            if (pBuf)
            {
                snaccSD.encapContentInfo->eContent = new AsnOcts;
                snaccSD.encapContentInfo->eContent->
                    Set(pBuf->Access(), pBuf->Length());
                delete pBuf;
            }
            delete pB;
        }
#endif     //RWC_TEST_ANY_ENCAPCONTENT
     delete pContentBuf;
      if (snaccSD.encapContentInfo.eContentType == id_ct_receipt)
         result = true;
   }

   SME_FINISH_CATCH

   return(result);
}

//////////////////////////////////////////////////////////////////////////
// This method will encode the ASN.1 ContentInfo from the member variables
//  as necessary.  It is expected that any data changes will clear the 
//  "m_pEncodedBlob" member variable.
CSM_Buffer *CSM_ContentInfoMsg::AccessEncodedCI()
{
   AsnOcts SNACCOcts;
   CSM_Buffer *pTmpContentBuf=NULL;

   SME_SETUP("AccessEncodedCI");

   if (AccessEncapContentFromAsn1() != NULL)
   {                       // then attempt to encode the contents.
      if (m_pSNACCContentInfo != NULL)
         delete m_pSNACCContentInfo;

      if ((m_pSNACCContentInfo = new ContentInfo) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      m_pSNACCContentInfo->contentType = AccessEncapContentFromAsn1()->m_contentType;
      if (m_pSNACCContentInfo->contentType == id_data)    
      {               // perform encode of OCTET STRING
         SME(SNACCOcts.Set(AccessEncapContentFromAsn1()->m_content.Access(), 
               AccessEncapContentFromAsn1()->m_content.Length()));
         SME(ENCODE_BUF(&SNACCOcts, pTmpContentBuf));
      }
      else        // just send full existing ANY buffer.
         pTmpContentBuf = (CSM_Buffer *)&AccessEncapContentFromAsn1()->m_content;

      SME(SM_ASSIGN_ANYBUF(pTmpContentBuf, &m_pSNACCContentInfo->content));
      SME(ENCODE_BUF(m_pSNACCContentInfo, m_pEncodedBlob));
      if (pTmpContentBuf != &AccessEncapContentFromAsn1()->m_content)
         delete pTmpContentBuf;  // ONLY delete if id_data type.
   }

   SME_FINISH_CATCH

   return(m_pEncodedBlob);
}

//////////////////////////////////////////////////////////////////////////
void CSM_ContentInfoMsg::SetEncodedCI(const CSM_Buffer& buffer)
{
   CSM_Buffer TmpBuf;

   SME_SETUP("SetEncodedCI");

   // FIRST, clear commonData object and assign buffer of ASN.1 encoded ContentInfo
   ClearAll();
   if ((m_pEncodedBlob = new CSM_Buffer(buffer)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // NEXT, decode ContentInfo
   if (m_pSNACCContentInfo)
      delete m_pSNACCContentInfo;
   if ((m_pSNACCContentInfo = new ContentInfo) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   DECODE_BUF(m_pSNACCContentInfo, m_pEncodedBlob);

   // NOW, load up the content details.
   CSM_Buffer *pA = &TmpBuf;
   SME(SM_EXTRACT_ANYBUF(pA, &m_pSNACCContentInfo->content));
   SetEncapContentFromAsn1(TmpBuf, 
      AsnOid(m_pSNACCContentInfo->contentType));
    
   SME_FINISH_CATCH
}

_END_SFL_NAMESPACE

// EOF sm_ContentInfo.cpp
