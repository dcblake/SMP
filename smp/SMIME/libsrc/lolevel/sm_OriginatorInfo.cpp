
//////////////////////////////////////////////////////////////////////////
// sm_OriginatorInfo.cpp implements the methods in CSM_OriginatorInfo

#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
// CONSTRUCTORS
//////////////////////////////////////////////////////////////////////////

CSM_OriginatorInfo::CSM_OriginatorInfo(CSM_BufferLst *pCerts)
{
   Clear();
   m_pMsgCertCrls = new CSM_MsgCertCrls(pCerts);
}

CSM_OriginatorInfo::CSM_OriginatorInfo(CSM_CertificateChoiceLst *pCerts)
{
   Clear();
   m_pMsgCertCrls = new CSM_MsgCertCrls(pCerts);
}

CSM_OriginatorInfo::CSM_OriginatorInfo(CertificateSet *pSnaccCertSet)
{
   Clear();
   m_pMsgCertCrls = new CSM_MsgCertCrls(pSnaccCertSet);
}

CSM_OriginatorInfo::CSM_OriginatorInfo(OriginatorInfo *pSnaccOI)
{
   Clear();
   AddSNACCOrigInfo(pSnaccOI);
}

CSM_OriginatorInfo::~CSM_OriginatorInfo()
{
   if (m_pMsgCertCrls)
      delete m_pMsgCertCrls;
}

//////////////////////////////////////////////////////////////////////////
void CSM_OriginatorInfo::AddSNACCOrigInfo(OriginatorInfo *pOI)
{
   SME_SETUP("CSM_OriginatorInfo::AddSNACCOrigInfo");

   if (pOI == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   if (m_pMsgCertCrls == NULL)
   {
      if ((m_pMsgCertCrls = new CSM_MsgCertCrls) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }

   // add the certs and ACs
   if (pOI->certs)
      SME(m_pMsgCertCrls->SetSNACCCerts(pOI->certs));

   // add the crls
   if (pOI->crls)
   {
      SME(m_pMsgCertCrls->SetSNACCCRLst(pOI->crls));
   }


   // add the ukms
   //RWC;if (pOI->ukms)
   //RWC;  SME(SetSNACCUKMs(pOI->ukms));

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
CSM_DNLst* CSM_OriginatorInfo::GetOriginatorDns()
{
   SME_SETUP("CSM_OriginatorInfo::GetOriginatorDns");

   // TBD, implement this function
   if (1)
   {
     SME_THROW(SM_UNKNOWN_ERROR, "Not implemented yet", NULL);
   }

   SME_FINISH_CATCH
   return NULL;
}


#ifdef NOT_USED_IN_RECIPIENT_INFO
//////////////////////////////////////////////////////////////////////////
void CSM_OriginatorInfo::SetSNACCUKMs(UserKeyingMaterials *pUKMs)
{
   UserKeyingMaterial *pTmpSNACCUKM;
   CSM_UserKeyMaterial *pukmNew;

   SME_SETUP("CSM_OriginatorInfo::SetSNACCUKMs");

   if (pUKMs == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   for (pUKMs->SetCurrToFirst(), pTmpSNACCUKM = pUKMs->Curr();
         pTmpSNACCUKM; pTmpSNACCUKM = pUKMs->GoNext())
   {
      if ((pukmNew = new CSM_UserKeyMaterial(new CSM_Alg(*(pTmpSNACCUKM->
            algorithm)), new CSM_Buffer((char*)(pTmpSNACCUKM->ukm), 
            pTmpSNACCUKM->ukm.Len()))) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      if (m_pUKMs == NULL)
         if ((m_pUKMs = new CSM_UserKeyMaterials) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL)
      m_pUKMs->AppendL(pukmNew);
   }

   SME_FINISH_CATCH
}
#endif

_END_SFL_NAMESPACE

// EOF sm_OriginatorInfo.cpp
