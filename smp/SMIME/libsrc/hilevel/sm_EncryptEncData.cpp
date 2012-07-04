
#pragma warning( disable : 4702 )   // MUST IGNORE, since even catch (...) 
                                    //  indicates "unreachable code", but 
                                    //  NULL pointer refs can crash.
//////////////////////////////////////////////////////////////////////////
// sm_EncryptEncData.cpp
// Implementation of the CSM_MsgToEncryptEncData class
// CSM_MsgToEncryptEncData is for high level use.  The application developer
// should not have to directly access the snacc generated classes.
// The application may have
// to directly access the exposed snacc generated class.  Both
// classes have the purpose of generating valid CSM EncryptedData
// ASN.1 encoded structures based on the provided input and the
// provided (and prepared) instances (contained in CSMIME)
//////////////////////////////////////////////////////////////////////////

#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
// CONSTRUCTORS
//////////////////////////////////////////////////////////////////////////
// empty constructor
CSM_MsgToEncryptEncData::CSM_MsgToEncryptEncData()
{
   Clear();
}

//////////////////////////////////////////////////////////////////////////
// incoming message is in pBlob
CSM_MsgToEncryptEncData::CSM_MsgToEncryptEncData(const CSM_Buffer *pBlob)
{
   Clear();
   SetEncapContentClear(*pBlob);
}

//////////////////////////////////////////////////////////////////////////
// incoming message is in a content info
CSM_MsgToEncryptEncData::CSM_MsgToEncryptEncData(const CSM_ContentInfoMsg *pCI)
{
   SME_SETUP("CSM_MsgToEncryptEncData::CSM_MsgToEncryptEncData(CSM_ContentInfoMsg)");

   Clear();

   if (pCI == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // TBD, what this is supposed to do is wrap whatever's in 
   // the CSM_ContentInfoMsg in a ContentInfo and then we set the type
   // as DATA.  Correct???
   SetEncapContentFromAsn1(*((CSM_ContentInfoMsg *)pCI)->AccessEncodedCI());

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// incoming message is in pContent
CSM_MsgToEncryptEncData::CSM_MsgToEncryptEncData(const CSM_Content *pContent)
{
   Clear();
   SetEncapContentClear(*pContent);
}

//////////////////////////////////////////////////////////////////////////
// Destructor
CSM_MsgToEncryptEncData::~CSM_MsgToEncryptEncData()
{
   if (m_poidContentEncrypt)
      delete (m_poidContentEncrypt);
   if (m_pKeyEncryptionOID)
      delete m_pKeyEncryptionOID;
   if (m_pKeyWrapOID)
      delete m_pKeyWrapOID;
   if (m_pUnprotectedAttrs)
      delete m_pUnprotectedAttrs;
}

//////////////////////////////////////////////////////////////////////////
void CSM_MsgToEncryptEncData::Clear()
{
   m_poidContentEncrypt = NULL;
   m_pKeyEncryptionOID = NULL;
   m_pUnprotectedAttrs = NULL;
  //m_pCsmime=NULL;
   m_pKeyEncryptionOID = NULL; 
   m_pKeyWrapOID=NULL; 
   m_SnaccEncryptedData.unprotectedAttrs = NULL;

}

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToEncryptEncData::Encrypt uses the content to generate encryptedData
void CSM_MsgToEncryptEncData::Encrypt(CSMIME *pCSMIME, CSM_Buffer *pCek)
{
   SME_SETUP("CSM_MsgToEncryptEncData::Encrypt");
   CSM_Buffer *pbufferResult;

   // check to make sure everything is ready to roll
   if ((pCSMIME == NULL) || (pCSMIME->m_pCSInsts == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   if (m_poidContentEncrypt == NULL)
      SME_THROW(SM_ENCRYPTION_UNPREPARED, 
            "no content encryption oid specified", NULL);

   // in order to call DataEncrypt::Encrypt we need pCSMIME which the
   // application gave us
   // we must pass the cek provided by the user
   // we must pass the poidContentType to DataEncrypt which
   //    is obtained via the inherited CSM_CommonData->GetEncapContent()->
   //    m_ContentType
   // we must pass the content to DataEncrypt which
   //    is obtained via the inherited CSM_CommonData->GetEncapContent()->
   //    m_content
   // we must pass the content encryption oid to DataEncrypt
   //    and the app must have set this with the SetContentEncryptOID member
   CSM_Alg *pContentEncryptionAlg = new CSM_Alg(*m_poidContentEncrypt);

   // setup a buffer to receive the result
   // TBD, what type of buffer?  for now, do memory...
   if ((pbufferResult = new CSM_Buffer) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // everything should be ready to call DataEncrypt now...
   SME(DataEncrypt(pCSMIME, pCek,
            &(AccessEncapContentFromAsn1()->m_contentType), 
            &(AccessEncapContentFromAsn1()->m_content), pContentEncryptionAlg, // Access returns a const
            pbufferResult));

   // store the encoded blob
   SME(UpdateEncodedBlob(pbufferResult));

   delete pContentEncryptionAlg;
   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
// CSM_MsgToEncryptEncData::DataEncrypt uses the provided parameters and whatever
// is already available in the content and exposed m_SnaccEncryptedData
// to generate the EncryptedData.  
void CSM_MsgToEncryptEncData::DataEncrypt(CSMIME      *pCSMIME,
                                       CSM_Buffer  *pCek,
                                       const AsnOid      *poidContentType,
                                       const CSM_Buffer  *pContent,
                                       CSM_Alg     *pContentEncryptionAlg,
                                       CSM_Buffer  *pOutputBuf)
{
   CSM_Buffer           bufContentParameters, bufEncryptedContent, bufMEK;
   CSM_CtilInst           *pTmpInstance;
   EncryptedContentInfo *pECI; // temporary snacc pointer
   AsnOid               oidOrigContent;
   AsnOid               *pTmpOid;
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_MsgToEncryptEncData::DataEncrypt");

   // check incoming parameters and values
   if ((pCSMIME == NULL && m_pCsmime==NULL) || (pContent == NULL) || 
       (pOutputBuf == NULL) ||
       (pContentEncryptionAlg == NULL) || (pCSMIME->m_pCSInsts == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);
   if (pContent->Access() == NULL)
      SME_THROW(SM_ENCRYPTION_UNPREPARED,
            "provided content is empty", NULL);
   // TBD, check pContentEncryptionAlg for something in it???
   if (pCSMIME)
      m_pCsmime = pCSMIME;

   // find the first pCSMIME->instance that can do the requested
   // content encryption algorithm
   if ((pTmpInstance = pCSMIME->FindCSInstAlgIds(NULL, NULL, NULL,
            pContentEncryptionAlg)) == NULL)
      SME_THROW(SM_NO_SUPPORTING_INSTANCE, 
            "no instance supports requested cont encr alg", NULL);

   // lock the CTI
   SME(pCSMIME->InstanceLock(SM_INST_USE_THIS));

   // RWC; Before encrypting, set our preferred algorithm (just in case it is 
   // RWC;  not the default).
   pTmpInstance->GetPreferredCSInstAlgs(NULL, NULL, NULL, &oidOrigContent);
   pTmpOid = pContentEncryptionAlg->GetId();
   pTmpInstance->SetPreferredCSInstAlgs(NULL, NULL, NULL, pTmpOid);
   delete pTmpOid;
   ///////////////////////////////
   // encrypt the provided content
   if ((status = pTmpInstance->AccessTokenInterface()->SMTI_Encrypt(
      (CSM_Buffer *)pContent,
         &bufEncryptedContent, &bufContentParameters, pCek)) != SM_NO_ERROR)
      SME_THROW(status, "SMTI_Encrypt returned error.", NULL);

#ifdef _DEBUG_RWC
   CSM_Buffer ContentCheck;
   status = pTmpInstance->AccessTokenInterface()->SMTI_Decrypt(
         &bufContentParameters, &bufEncryptedContent, pCek, &ContentCheck);
   if (*pContent != ContentCheck)
       std::cout << "CSM_MsgToEncryptEncData::DataEncrypt: SMTI_Decrypt failed decrypting the encrypted result." 
                 << std::endl;
#endif //_DEBUG
   // RWC; Reset original perferred algorithm.
   pTmpInstance->SetPreferredCSInstAlgs(NULL, NULL, NULL, &oidOrigContent);

   ///////////////////////////////////////////////////////
   // load the encrypted content into m_SnaccEncryptedData
   // store content type
   pECI = &m_SnaccEncryptedData.encryptedContentInfo;
   pECI->contentType.Set(*poidContentType);
   // store alg OID
   pECI->contentEncryptionAlgorithm.algorithm = *pContentEncryptionAlg->AccessSNACCId();
   // store alg parameters
   if (bufContentParameters.Access() != NULL)
   {
      if ((pECI->contentEncryptionAlgorithm.parameters = new AsnAny) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
      SM_ASSIGN_ANYBUF((&bufContentParameters), 
            pECI->contentEncryptionAlgorithm.parameters);
   }
   // store encrypted content
   if ((pECI->encryptedContent = new EncryptedContent) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   pECI->encryptedContent->Set(bufEncryptedContent.Access(), 
         bufEncryptedContent.Length());
   
   // finished generating EMEKs, unlock the CTI
   SME(pCSMIME->InstanceUnlock(SM_INST_USE_THIS));

   ///////////////////////////////////////////////////////////
   // set the version for the encrypted data
   // check to see if there are unprotected attrs
   m_SnaccEncryptedData.version = GetEncDataVersion();

   // finished filling m_SnaccEncryptedData, ASN.1 encode it...
   ENCODE_BUF_NO_ALLOC((&m_SnaccEncryptedData), pOutputBuf);

   // TBD, any local cleanup necessary?

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      // unlock the CTI
   SME_CATCH_FINISH
}


//////////////////////////////////////////////////////////////////////////
void CSM_MsgToEncryptEncData::ReportMsgData(std::ostream &os)
{
   SME_SETUP("CSM_MsgToEncryptEncData::ReportMsgData(ostream &os)");

   os << "CSM_MsgToEncryptEncData::ReportMsgData(ostream &os)\n";
   os << "Reporting on m_SnaccEncryptedData\n";
   os << m_SnaccEncryptedData << "\n";
   os << "End report on m_SnaccEncryptedData\n";
   os.flush();

   SME_FINISH_CATCH
}


//////////////////////////////////////////////////////////////////////////
long CSM_MsgToEncryptEncData::GetEncDataVersion()
{
   long lRet = 0;

   SME_SETUP("CSM_MsgToEncryptEncData::GetEnvDataVersion()");

   // if there are any unprotected attributes
   if (m_SnaccEncryptedData.unprotectedAttrs != NULL)
      lRet = 2;      // set version to 2
   else 
      lRet = 0;      // version 0

   SME_FINISH_CATCH

   return lRet;
}

_END_SFL_NAMESPACE

// EOF sm_EncryptEncData.cpp
