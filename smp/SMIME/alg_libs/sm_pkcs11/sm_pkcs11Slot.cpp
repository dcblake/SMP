#ifndef NO_SCCS_ID
static char SccsId[ ] = "%Z% %M% %I% %G% %U%"; 
#endif

#include "sm_pkcs11.h"
_BEGIN_CERT_NAMESPACE

////////////////////////////////////////////////////////////////////////////////////
//
// CSM_Pkcs11Slot :
//
////////////////////////////////////////////////////////////////////////////////////
CSM_Pkcs11Slot::CSM_Pkcs11Slot()
{
    Clear();
}
CSM_Pkcs11Slot::CSM_Pkcs11Slot(CK_SLOT_ID slotId)
{
    Clear();

    SetSlotId(slotId);
}
void CSM_Pkcs11Slot::Clear()
{
    m_slotId = -1; 

    m_pDigestAlgLst = NULL; 
    m_pDigestEncryptionAlgLst = NULL; 
    m_pKeyEncryptionAlgLst = NULL; 
    m_pContentEncryptionAlgLst = NULL;
    m_pMechanismInfoLst = NULL;
}
CSM_Pkcs11Slot::~CSM_Pkcs11Slot()
{
    if (m_pMechanismInfoLst)
        delete m_pMechanismInfoLst;
    if (m_pContentEncryptionAlgLst)
        delete m_pContentEncryptionAlgLst;
    /*RWC;REMOVED 3/17/03 as per e-mail from William Adams, Nexot, Untested;
      Removed when m_pMechanismInfoLst deleted???
    if (m_pDigestAlgLst)
        delete m_pDigestAlgLst;
    if (m_pDigestEncryptionAlgLst)
        delete m_pDigestEncryptionAlgLst;
    if (m_pKeyEncryptionAlgLst)
        delete m_pKeyEncryptionAlgLst;*/
}
void CSM_Pkcs11Slot::SetSlotId(CK_SLOT_ID slotId)
{
    m_slotId = slotId;
}
CK_SLOT_INFO CSM_Pkcs11Slot::GetSlotInfo()
{
   CK_RV rv;
   CK_SLOT_INFO slotInfo;

   if ((rv = sfl_c_getSlotInfo(m_slotId, &slotInfo)) != CKR_OK)
      std::cout << "Unable to sfl_c_getSlotInfo.  Return value = " << rv << ".\n";

   return slotInfo;
}
CK_TOKEN_INFO CSM_Pkcs11Slot::GetTokenInfo()
{
   CK_RV rv;
   CK_TOKEN_INFO tokenInfo;

   if ((rv = sfl_c_getTokenInfo(m_slotId, &tokenInfo)) != CKR_OK)
      std::cout << "Unable to sfl_c_getTokenInfo.  Return value = " << rv << ".\n";

   return tokenInfo;
}
SM_RET_VAL CSM_Pkcs11Slot::LoadMechanisms ()
{
    SM_RET_VAL status = SM_NO_ERROR;

    CK_RV rv;
    CK_MECHANISM_TYPE_PTR pMechanismList = NULL_PTR;
    CK_ULONG ulCount;

    SME_SETUP("CSM_Pkcs11Slot::LoadMechanisms");

    // NOTE : Errors returned in rv might not be fatal; therefore they will
    //        only be logged into the output window using cout but not returned
    //        to the calling module.

    // Since pMechanismList is set to NULL_PTR, this call to sfl_c_getMechanismList 
    // sets ulCount to the number of mechanisms supported by the token (in m_slotId).
    if ((rv = sfl_c_getMechanismList(m_slotId, pMechanismList, &ulCount)) == CKR_OK)
    {
        if (ulCount > 0)
        {
            if ((pMechanismList = 
                  (CK_MECHANISM_TYPE_PTR) 
                        malloc(ulCount * sizeof(CK_MECHANISM_TYPE))) == NULL)
                SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

            // This call to sfl_c_getMechanismList returns a list of 
            // CK_MECHANISM_TYPE in pMechanismList
            if (rv = sfl_c_getMechanismList(m_slotId, pMechanismList, &ulCount) == CKR_OK)
                status = ProcessMechanismList(pMechanismList, ulCount);
            else
                std::cout << "Unsuccessful sfl_c_getMechanismList.  Return value = " << rv << ".\n";

            if (pMechanismList)
               free (pMechanismList);
        }
        else
           std::cout << "No mechanisms found in slot " << m_slotId << "./n";
    }
    else
       std::cout << "Unsuccessful sfl_c_getMechanismList.  Return value = " << rv << ".\n";
      

    SME_FINISH_CATCH

    return status;
}
SM_RET_VAL CSM_Pkcs11Slot::ProcessMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList, 
                                                CK_ULONG mechanismCount)
{
    SM_RET_VAL status = SM_NO_ERROR;
    CK_MECHANISM_TYPE_PTR pCurrMechanism;
    CSM_Pkcs11MechanismInfo *pMechanismInfo;

    SME_SETUP("CSM_Pkcs11Slot::ProcessMechanismList")

    pCurrMechanism = pMechanismList;

    for (CK_ULONG i = 0; i < mechanismCount; i++)
    {
        pMechanismInfo = NULL;

        if (m_pMechanismInfoLst == NULL)
            if ((m_pMechanismInfoLst = new CSM_Pkcs11MechanismInfoLst) == NULL)
                SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

        if ((pMechanismInfo = &(*m_pMechanismInfoLst->append())) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);

        pMechanismInfo->SetDllFunctions(sfl_c_getMechanismInfo);
        pMechanismInfo->SetSlotId(m_slotId);
        pMechanismInfo->LoadMechanismInfo(*pCurrMechanism);

        pCurrMechanism++; // Increase pointer to point to the next mechanismType
    }

    // Build algorithm list in this slot from all the mechanisms 
    // supported by the token.
    SetSlotAlgLst();

    SME_FINISH_CATCH

    return status;
}
//////////////////////////////////////////////////////////////////////////
void CSM_Pkcs11Slot::SetSlotAlgLst()
{
    SME_SETUP("CSM_Pkcs11Slot::SetSlotAlgLst");

    CSM_Pkcs11MechanismInfoLst::iterator itMechanism;

    // Collect all mechanisms (algorithms) supported in this slot.
    for (itMechanism =  m_pMechanismInfoLst->begin();
         itMechanism != m_pMechanismInfoLst->end();
         ++itMechanism)
    {                   
        if (itMechanism->AccessContentEncryptionAlg () != NULL)  
            SetContentEncryptionAlgLst(itMechanism->AccessContentEncryptionAlg ());

        if (itMechanism->AccessDigestAlg() != NULL)
            SetDigestAlgLst(itMechanism->AccessDigestAlg());

        if (itMechanism->AccessDigestEncryptionAlg() != NULL)           
            SetDigestEncryptionAlgLst(itMechanism->AccessDigestEncryptionAlg());

        if (itMechanism->AccessKeyEncryptionAlg() != NULL)
            SetKeyEncryptionAlgLst(itMechanism->AccessKeyEncryptionAlg());
    }

    SME_FINISH_CATCH
}
///////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11Slot::SetDigestAlgLst (CSM_Alg *pDigestAlg)
{
    SM_RET_VAL status = SM_NO_ERROR;

    SME_SETUP ("CSM_Pkcs11Slot::SetDigestAlgLst");

    if (m_pDigestAlgLst == NULL)
        if ((m_pDigestAlgLst = new CSM_AlgLstVDA) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    CSM_AlgVDA *pAlg = &(*m_pDigestAlgLst->append());
    *pAlg = *pDigestAlg;

    SME_FINISH_CATCH;

    return status;
}
SM_RET_VAL CSM_Pkcs11Slot::SetDigestEncryptionAlgLst (CSM_Alg *pDigestEncryptionAlg)
{
    SM_RET_VAL status = SM_NO_ERROR;

    SME_SETUP ("CSM_Pkcs11Slot::SetDigestEncryptionAlgLst");

    if (m_pDigestEncryptionAlgLst == NULL)
        if ((m_pDigestEncryptionAlgLst = new CTIL::CSM_AlgLstVDA) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    CSM_AlgVDA *pAlg = &(*m_pDigestEncryptionAlgLst->append());
    *pAlg = *pDigestEncryptionAlg;

    SME_FINISH_CATCH;

    return status;
}
SM_RET_VAL CSM_Pkcs11Slot::SetKeyEncryptionAlgLst (CSM_Alg *pKeyEncryptionAlg)
{
    SM_RET_VAL status = SM_NO_ERROR;

    SME_SETUP ("CSM_Pkcs11Slot::SetKeyEncryptionAlgLst")

    if (m_pKeyEncryptionAlgLst == NULL)
        if ((m_pKeyEncryptionAlgLst = new CTIL::CSM_AlgLstVDA) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    CSM_AlgVDA *pAlg = &(*m_pKeyEncryptionAlgLst->append());
    *pAlg = *pKeyEncryptionAlg;

    SME_FINISH_CATCH;

    return status;
}
SM_RET_VAL CSM_Pkcs11Slot::SetContentEncryptionAlgLst (CSM_Alg *pContentEncryptionAlg)
{
    SM_RET_VAL status = SM_NO_ERROR;

    SME_SETUP ("CSM_Pkcs11Slot::SetContentEncryptionAlgLst")

    if (m_pContentEncryptionAlgLst == NULL)
        if ((m_pContentEncryptionAlgLst = new CTIL::CSM_AlgLstVDA) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    CSM_AlgVDA *pAlg = &(*m_pContentEncryptionAlgLst->append());
    *pAlg = *pContentEncryptionAlg;

    SME_FINISH_CATCH;

    return status;
}
void CSM_Pkcs11Slot::SetDllFunctions(SFL_C_GetSlotList getSlotList,
                                 SFL_C_GetSlotInfo getSlotInfo,
                                 SFL_C_GetTokenInfo getTokenInfo,
                                 SFL_C_GetMechanismInfo getMechanismInfo,
                                 SFL_C_GetMechanismList getMechanismList)
{
   sfl_c_getSlotList = getSlotList;
   sfl_c_getSlotInfo = getSlotInfo;
   sfl_c_getTokenInfo = getTokenInfo;
   sfl_c_getMechanismInfo = getMechanismInfo;
   sfl_c_getMechanismList = getMechanismList;
}


_END_CERT_NAMESPACE

// EOF sm_pkcs11Slot.cpp
