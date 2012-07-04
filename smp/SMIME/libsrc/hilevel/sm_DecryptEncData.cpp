
//////////////////////////////////////////////////////////////////////////
// sm_DecryptEncData.cpp
// Implementation of the CSM_MsgToDecryptEncData and CSM_DataToDecryptEncData classes.
// CSM_MsgToDecryptEncData is for high level use.  The app developer should
// not have to directly access the snacc generated classes.
// CSM_DataToDecryptEncData is for low level use.  The app may have to
// directly access the exposed snacc generated class.  Both
// classes have the purpose of decrypting a CMS EncryptedData
// based on the provided input (primarily the marked sessions
// in the CSMIME).
//////////////////////////////////////////////////////////////////////////

#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;
using namespace CERT;

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToDecryptEncData Constructors
//////////////////////////////////////////////////////////////////////////
CSM_MsgToDecryptEncData::CSM_MsgToDecryptEncData(CSMIME *pCSMIME, const CSM_Buffer *pBlob)
{
   SME_SETUP("CSM_MsgToDecryptEncData::CSM_MsgToDecryptEncData(csmime)");

   Clear();
   if (pBlob)
   {
      SetEncodedBlob(pBlob);
      if (pCSMIME)
         SME(PreProc(pCSMIME, pBlob));
   }
   SME_FINISH_CATCH;
}

CSM_MsgToDecryptEncData::CSM_MsgToDecryptEncData(const CSM_ContentInfoMsg *pCIM)
{
   const CSM_Buffer *pbufEncodedBlob;

   SME_SETUP("CSM_MsgToDecryptEncData::CSM_MsgToDecryptEncData(pCIM)");

   Clear();
   if (pCIM)
   {
      SME(pbufEncodedBlob = ((CSM_ContentInfoMsg *)pCIM)->AccessEncodedBlob());

      // ASN.1 decode the provided pbufEncryptedData
      DECODE_BUF((&m_SnaccEncryptedData), pbufEncodedBlob);

      SME(SetEncodedBlob(pbufEncodedBlob));
   }
   SME_FINISH_CATCH
}

CSM_MsgToDecryptEncData::CSM_MsgToDecryptEncData(CSMIME *pCSMIME, const CSM_ContentInfoMsg *pCIM)
{
   const CSM_Buffer *pbufEncodedBlob;

   SME_SETUP("CSM_MsgToDecryptEncData::CSM_MsgToDecryptEncData(pCIM, pCSMIME)");

   Clear();
   if (pCIM)
   {
      SME(pbufEncodedBlob = ((CSM_ContentInfoMsg *)pCIM)->AccessEncodedBlob());

      // ASN.1 decode the provided pbufEncryptedData
      DECODE_BUF((&m_SnaccEncryptedData), pbufEncodedBlob);

      SME(SetEncodedBlob(pbufEncodedBlob));

      if (pCSMIME)
         SME(PreProc(pCSMIME));
   }
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
CSM_MsgToDecryptEncData::~CSM_MsgToDecryptEncData()
{
   if (m_pOriginatorInfo)
      delete m_pOriginatorInfo;
}

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToDecryptEncData::Decrypt
//////////////////////////////////////////////////////////////////////////
void CSM_MsgToDecryptEncData::Decrypt(CSMIME *pCSMIME, CSM_Buffer *pCek)
{
   CSM_Buffer bufPlainText;

   SME_SETUP("CSM_MsgToDecryptEncData::Decrypt");

   // call low level decrypt
   SME(CSM_DataToDecryptEncData::Decrypt(pCSMIME, &bufPlainText, pCek));

   // create content from the decrypted plain text
   AsnOid  oidContent(m_SnaccEncryptedData.encryptedContentInfo.contentType);
   CSM_Content content(&bufPlainText, oidContent);
   // store the content here
   SetEncapContentFromAsn1(content);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToDecryptEncData::PreProc-s
//////////////////////////////////////////////////////////////////////////
void CSM_MsgToDecryptEncData::PreProc(CSMIME *pCSMIME)
{
   SME_SETUP("CSM_MsgToDecryptEncData::PreProc csmime");
   // call lower level PreProc that will process with pCSMIME
   SME(CSM_DataToDecryptEncData::PreProc(pCSMIME));

   SME_FINISH_CATCH
}

void CSM_MsgToDecryptEncData::PreProc(CSMIME *pCSMIME, const CSM_Buffer *pBlob)
{
   SME_SETUP("CSM_MsgToDecryptEncData::PreProc buf csmime");
   // Decode the provided blob
   CSM_DataToDecryptEncData::Decode(pBlob);
   // call other high level PreProc that will generate m_pRecipients
   // and m_pOriginatorInfo for application's use
   SME(PreProc(pCSMIME));
   SME_FINISH_CATCH
}



//////////////////////////////////////////////////////////////////////////
// CSM_MsgToDecryptEncData::ReportMsgData
//////////////////////////////////////////////////////////////////////////
void CSM_MsgToDecryptEncData::ReportMsgData(std::ostream &os)
{

   SME_SETUP("CSM_MsgToDecryptEncData::ReportMsgData");

   os << "Reporting on m_SnaccEncryptedData:" << "\n";
   os << m_SnaccEncryptedData << "\n";
   os << "End report for m_SnaccEncryptedData!" << "\n";

   os.flush();

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

}


//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecryptEncData:: Constructors
//////////////////////////////////////////////////////////////////////////
CSM_DataToDecryptEncData::CSM_DataToDecryptEncData(const CSM_Buffer *pbufEncryptedData)
{
   SME_SETUP("CSM_DataToDecryptEncData::CSM_DataToDecryptEncData buf");
   
   if (pbufEncryptedData == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // ASN.1 decode the provided pbufEncryptedData
   DECODE_BUF((&m_SnaccEncryptedData), pbufEncryptedData);

   SME_FINISH_CATCH
}

CSM_DataToDecryptEncData::CSM_DataToDecryptEncData(CSMIME *pCSMIME,const CSM_Buffer *pbufEncryptedData)
{
   SME_SETUP("CSM_DataToDecryptEncData::CSM_DataToDecryptEncData buf csmime");

   if ((pbufEncryptedData == NULL) || (pCSMIME == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // ASN.1 decode the provided pbufEncryptedData
   DECODE_BUF((&m_SnaccEncryptedData), pbufEncryptedData);

   SME(PreProc(pCSMIME));

   SME_FINISH_CATCH
}



//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecryptEncData::PreProc
//////////////////////////////////////////////////////////////////////////
void CSM_DataToDecryptEncData::PreProc(CSMIME *pCSMIME)
{

   SME_SETUP("CSM_DataToDecryptEncData::PreProc csmime");

   if (pCSMIME == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing parameters", NULL);

   // using the provided instances, try to find applicable ones...
   if (pCSMIME->m_pCSInsts != NULL)
   {
      // what was used to encrypt the content?
   }

   SME_FINISH_CATCH
   // TBD, cleanup???
}

void CSM_DataToDecryptEncData::PreProc(const CSM_Buffer *pbufEncryptedData,
                                    CSMIME *pCSMIME)
{
   SME_SETUP("CSM_DataToDecryptEncData::PreProc buf csmime");
   if ((pbufEncryptedData == NULL) || (pCSMIME == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   // ASN.1 decode the provided pbufEncryptedData
   Decode(pbufEncryptedData);
   // call preproc that does the real work
   SME(PreProc(pCSMIME));
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecryptEncData::Decode
//////////////////////////////////////////////////////////////////////////
void CSM_DataToDecryptEncData::Decode(const CSM_Buffer *pbufEncryptedData)
{
   SME_SETUP("CSM_DataToDecryptEncData::Decode");

   if (pbufEncryptedData)
      DECODE_BUF((&m_SnaccEncryptedData), pbufEncryptedData);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// CSM_DataToDecryptEncData::Decrypt
//////////////////////////////////////////////////////////////////////////
void CSM_DataToDecryptEncData::Decrypt(CSMIME *pCSMIME,
                                    CSM_Buffer *pbufDecryptedContent, CSM_Buffer *pCek)
{
   CSM_CtilInst *pInst2;
   CSM_Buffer *pbufMEK = NULL;
   CSM_Buffer *pbufParameters=NULL;
   CSM_Alg tmpCEAlg(m_SnaccEncryptedData.encryptedContentInfo.
            contentEncryptionAlgorithm);

   SME_SETUP("CSM_DataToDecryptEncData::Decrypt");

   // check the incoming parameters
   if ((pCSMIME == NULL) || (pCSMIME->m_pCSInsts == NULL) || 
         (pbufDecryptedContent == NULL))
      SME_THROW(SM_MISSING_PARAM, "Missing Parameters", NULL);
   
   // check for the content encryption key supplied by the user
   if (pCek == NULL)
   {
      SME_THROW(SM_MISSING_PARAM, "Null input parameter for Cek", NULL);
   }

   // lock the CTIs
   SME(pCSMIME->InstanceLock(SM_INST_APPLICABLE | SM_INST_USE_THIS));

   // Extract the content encryption parameters
   if (m_SnaccEncryptedData.encryptedContentInfo.contentEncryptionAlgorithm.
       parameters)
       SM_EXTRACT_ANYBUF(pbufParameters, m_SnaccEncryptedData.
         encryptedContentInfo.contentEncryptionAlgorithm.parameters);
   // create a buffer holding the encrypted content
   CSM_Buffer bufContent(m_SnaccEncryptedData.
         encryptedContentInfo.encryptedContent->c_str(), m_SnaccEncryptedData.
         encryptedContentInfo.encryptedContent->Len());

   // Find an instance to use for this encryption alg 
   pInst2 = pCSMIME->FindCSInstAlgIds(NULL, NULL, NULL, &tmpCEAlg);

   if (pInst2 == NULL)
      SME_THROW(SM_MISSING_PARAM, "NO CSInstance to process ContentEncryption",
        NULL);

   AsnOid  *pTmpContentOID = tmpCEAlg.GetId();
   pInst2->SetPreferredCSInstAlgs(NULL, NULL, NULL, pTmpContentOID);

   // Check parity for incomming 3DES key.
   if (*pTmpContentOID == des_ede3_cbc)
   {
      // NOW, set parity since this calculation does not produce parity proper 
      //  results for 3DES.  This logic was removed from 3DES decrypt in order
      //  to support Million Message Attack issues (RFC3218).
      unsigned char *ptr3=(unsigned char *)pCek->Access();
      unsigned long value;
      unsigned int ii2;
      for (unsigned long ii=0; ii < pCek->Length(); ii++)
      {
          value = (unsigned long)ptr3[ii];
          for (ii2=8*sizeof(value)/2; ii2>0; ii2/=2)
		    value ^= value >> ii2;
          if (!(value & 1))   // IF ODD Parity, change LOWEST bit.
              ptr3[ii] ^= 0x01;
      }
   }        // END IF 3DES

   delete pTmpContentOID;

   // decrypt the content
   SME(pInst2->AccessTokenInterface()->SMTI_Decrypt(
         pbufParameters, &bufContent, pCek, pbufDecryptedContent));

   // unlock the CTI
   SME(pCSMIME->InstanceUnlock(SM_INST_APPLICABLE | SM_INST_USE_THIS));

   if (pbufMEK)
      delete pbufMEK;
   if (pbufParameters)
      delete pbufParameters;

   SME_FINISH
   SME_CATCH_SETUP
      if (pbufMEK)
         delete pbufMEK;
      if (pbufParameters)
         delete pbufParameters;
      // catch/cleanup logic as necessary
      // unlock the CTI if necessary
   SME_CATCH_FINISH
}

_END_SFL_NAMESPACE

// EOF sm_Decrypt.cpp
