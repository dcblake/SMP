
// sm_Attr.cpp
// This support file handles the Attribute class functionality for the SMIME
//  library.

#include "sm_apiCert.h"
_BEGIN_CERT_NAMESPACE 
using namespace SNACC;

// The most recent changes to this source made use of the following version
// of the Enhanced Security Services for S/MIME Specifications.
// Internet Draft                              Editor: Paul Hoffman
// draft-ietf-smime-ess-12.txt                 Internet Mail Consortium
// March 29, 1999
// These changes include the CSM_AttribBase Check-Attr functions and the
// CSM_MsgAttributes Check-Attrs functions.

// NOTE:
// DESTRUCTOR IS MISSING CONDITIONS FOR id_aa_contentIdentifier,
// id_aa_signingCertificate, smimeCapabilities, id_aa_encrypKeyPref
CSM_AttribBase::CSM_AttribBase()
{
        Clear();
}

CSM_AttribBase::~CSM_AttribBase()
{
    SME_SETUP("CSM_AttribBase::~CSM_AttribBase");


    if (m_poid)
        delete m_poid;
    if (m_pEncodedAttrib)
        delete m_pEncodedAttrib;

    SME_FINISH_CATCH
}


//
//
CSM_AttribBase::CSM_AttribBase(AsnOid &attrType,CSM_Buffer &SNACCAnyBuf)
{
    SME_SETUP("CSM_AttribBase::CSM_AttribBase");

    Clear();
        m_poid = new AsnOid(attrType );
        if(m_pEncodedAttrib)
            free(m_pEncodedAttrib);
        m_pEncodedAttrib = new CSM_Buffer(SNACCAnyBuf);
    SME_FINISH_CATCH;
}

//
//
void CSM_AttribBase::GetEncodedAttr(CSM_Buffer *&pSNACCAnyBuf)
{
    if (pSNACCAnyBuf == NULL && m_pEncodedAttrib != NULL)
        pSNACCAnyBuf = new CSM_Buffer;
    if (m_pEncodedAttrib != NULL)
        *pSNACCAnyBuf = *m_pEncodedAttrib;
}

//
//
void CSM_AttribBase::GetEncodedAttr(AsnOid *&pOid, CSM_Buffer *&pSNACCAnyBuf)
{
    if (pOid == NULL)
        pOid = new AsnOid;
    if (m_poid != NULL)
        *pOid = *m_poid;

    if (pSNACCAnyBuf == NULL)
        pSNACCAnyBuf = new CSM_Buffer;
    if (m_pEncodedAttrib != NULL)
        *pSNACCAnyBuf = *m_pEncodedAttrib;

}

void CSM_AttribBase::Clear()
{
    m_poid = NULL;
    m_pEncodedAttrib = NULL;
}


//
//
bool CSM_AttribBase:: operator == (CSM_AttribBase &Attr)
{
    bool        result = true;

    if(m_poid && Attr.m_poid)
    {
        result = (*m_poid == *Attr.m_poid);
    }
    else
    {
        result = !(((m_poid == NULL) && Attr.m_poid) ||
            (m_poid && (Attr.m_poid == NULL)));
    }

    if(m_pEncodedAttrib && Attr.m_pEncodedAttrib)
    {
        result = (*m_pEncodedAttrib == *Attr.m_pEncodedAttrib);
    }
    else
    {
        result = !(((m_pEncodedAttrib == NULL) && Attr.m_pEncodedAttrib) ||
            (m_pEncodedAttrib && (Attr.m_pEncodedAttrib == NULL)));
    }

    return(result);
}


_END_CERT_NAMESPACE 

// EOF sm_AttrBase.cpp
