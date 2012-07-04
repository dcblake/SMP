
#include "sm_apiCert.h"

#include <stdlib.h>
#include <malloc.h>
#include <time.h>

#ifdef SM_RSA_USED
#include "sm_rsa_asn.h"
#endif
_BEGIN_CERT_NAMESPACE 
using namespace SNACC;

CSM_CertificateList::CSM_CertificateList(const CSM_CertificateList &CertificateList)
{
    Clear();
   *this = CertificateList;
}

CSM_CertificateList &CSM_CertificateList::operator =(const CSM_CertificateList &CertificateListIn)
{
   if (m_pCRLBuffer)
      delete m_pCRLBuffer;
   if (m_pSNACCCRL)
      delete m_pSNACCCRL;

    m_pCRLBuffer = NULL;
    m_pSNACCCRL = NULL;
    if (CertificateListIn.m_pCRLBuffer)
       m_pCRLBuffer = new CSM_Buffer (*CertificateListIn.m_pCRLBuffer);
    if (CertificateListIn.m_pSNACCCRL)
    {
       m_pSNACCCRL = new CertificateList;
       *m_pSNACCCRL = *CertificateListIn.m_pSNACCCRL;
    }
    return(*this);
}

CSM_CertificateList::CSM_CertificateList(const CSM_Buffer &CRL)
{
   Clear();
   SetSNACCCRL(CRL);
}
//////////////////////////////////////////////////////////////////////////
CSM_CertificateList::CSM_CertificateList(const CertificateList &SNACCCRL)
{
   Clear();
   m_pSNACCCRL = new CertificateList;
   *m_pSNACCCRL = SNACCCRL;
}
CSM_CertificateList::~CSM_CertificateList()
{
    if (m_pSNACCCRL)
        delete m_pSNACCCRL;
    if (m_pCRLBuffer)
        delete m_pCRLBuffer;
}
void CSM_CertificateList::Clear()
{ 
    m_pCRLBuffer = NULL;
    m_pSNACCCRL = NULL;
}
void CSM_CertificateList::SetSNACCCRL(const CSM_Buffer &pCRL)
{
    if (m_pCRLBuffer == NULL)
        m_pCRLBuffer = new CSM_Buffer;

    *m_pCRLBuffer = pCRL;

    AccessSNACCCRL();
}
CertificateList *CSM_CertificateList::AccessSNACCCRL()
{
    SME_SETUP("CSM_CertificateList::AcessSNACCCRL");

    if (m_pSNACCCRL == NULL && m_pCRLBuffer != NULL)
    {
        Decode();
    }

    SME_FINISH_CATCH;

    return m_pSNACCCRL;
}
CSM_Buffer *CSM_CertificateList::AccessEncodedCRL() 
{ 
    SME_SETUP("CSM_CertificateList::AccessEncodedCRL");

    if (m_pCRLBuffer == NULL && m_pSNACCCRL != NULL)
       SME(ENCODE_BUF(m_pSNACCCRL, m_pCRLBuffer));
    
    SME_FINISH_CATCH;

    return m_pCRLBuffer; 
}
CSM_Buffer *CSM_CertificateList::GetEncodedCRL()
{
    CSM_Buffer *pBuf=NULL;

    if (AccessEncodedCRL() != NULL)
        pBuf = new CSM_Buffer(*AccessEncodedCRL());

    return pBuf;
}
//////////////////////////////////////////////////////////////////////////
// Make a copy of our SNACC CertificateList.
CertificateList *CSM_CertificateList::GetSNACCCRL()
{
    CertificateList *pSNACCCRL = new CertificateList;
    SME_SETUP("CSM_CertificateList::GetSNACCCRL");

    if (m_pSNACCCRL == NULL)
        Decode();
    if (m_pSNACCCRL)
        *pSNACCCRL = *AccessSNACCCRL();

    SME_FINISH_CATCH;
    return pSNACCCRL;
}
void CSM_CertificateList::Decode()
{
    SME_SETUP("CSM_CertificateList::Decode");

    if (m_pCRLBuffer != NULL)
    {
        if (m_pSNACCCRL)
            delete m_pSNACCCRL;

        if ((m_pSNACCCRL = new CertificateList) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

        //decode the certificateList (CRL)
        SME(DECODE_BUF(m_pSNACCCRL, m_pCRLBuffer));

    }
    else
       SME_THROW(SM_NO_CRL_SET, "encoded CRL missing", NULL);

   SME_FINISH_CATCH;
}
SM_RET_VAL CSM_CertificateList::Validate()
{
    SM_RET_VAL lStatus = SM_NO_ERROR;

    SME_SETUP("CSM_CertificateList::Validate");

    CSM_Buffer ptmpBuf(*m_pCRLBuffer);

    // Create SNACC CRL from input buffer 
    SetSNACCCRL(ptmpBuf);

    SME_FINISH
    SME_CATCH_SETUP

    SME_CATCH_FINISH

    return(lStatus);
}
CSM_DN *CSM_CertificateList::GetIssuer()
{
    CSM_DN *pIssuer = NULL;
    SME_SETUP("CSM_CertificateList::GetIssuer");

    if (m_pSNACCCRL == NULL)
        SME(Decode());

    if (m_pSNACCCRL != NULL)
    {
        if ((pIssuer = new CSM_DN(m_pSNACCCRL->toBeSigned.issuer))
            == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
    }

    SME_FINISH_CATCH;

    return pIssuer;
}

_END_CERT_NAMESPACE 

// EOF sm_CertificateList.cpp
