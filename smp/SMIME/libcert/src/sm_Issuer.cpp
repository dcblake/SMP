
#include <stdlib.h>
#include "sm_apiCert.h"
_BEGIN_CERT_NAMESPACE 
using namespace SNACC;
using CML::ASN::DN;

//////////////////////////////////////////////////////////////////////////
// sm_Issuer.cpp
// implementation of methods from:
//   CSM_IssuerAndSerialNumber
//   CSM_Recipient
//   CSM_Content
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// The following CSM_IssuerAndSerialNumber member functions are defined here:
// Constructors
// bool operator ==

//////////////////////////////////////////////////////////////////////////
// use this constructor to make a copy of the provided structure
// and put it into this structure
CSM_IssuerAndSerialNumber::CSM_IssuerAndSerialNumber()
{
   m_pSNACCIssSn = NULL;
}

//////////////////////////////////////////////////////////////////////////
CSM_IssuerAndSerialNumber::CSM_IssuerAndSerialNumber
      (const CSM_IssuerAndSerialNumber &IssSn)
{
   m_pSNACCIssSn = NULL;
   Set(*IssSn.AccessSNACCIssuerAndSerialNumber());
}

//////////////////////////////////////////////////////////////////////////
// use this constructor to make a copy of the provided structure
// and put it into this structure
CSM_IssuerAndSerialNumber::CSM_IssuerAndSerialNumber
      (const CSM_DN &dn, const CSM_Buffer &serial)
{
   m_pSNACCIssSn = NULL;
   SetIssuer(dn); 
   SetSerialNo(serial); 
}

//////////////////////////////////////////////////////////////////////////
// use this constructor to make a new m_pSNACCIssSn SNACC structure
CSM_IssuerAndSerialNumber::CSM_IssuerAndSerialNumber
      (const IssuerAndSerialNumber &SNACCIssSn)
{
   m_pSNACCIssSn = new IssuerAndSerialNumber;
   *m_pSNACCIssSn = SNACCIssSn;
}

//////////////////////////////////////////////////////////////////////////
// use this constructor to get the issuer and serial number
// from a given certificate
CSM_IssuerAndSerialNumber::CSM_IssuerAndSerialNumber
      (CSM_Buffer *SNACCCertBuf) 
{
   Certificate tmpSNACCCert;

   SME_SETUP("CSM_IssuerAndSerialNumber::CSM_IssuerAndSerialNumber");
   m_pSNACCIssSn = NULL;
   
   DECODE_BUF(&tmpSNACCCert, SNACCCertBuf);
   Set(tmpSNACCCert);
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
CSM_IssuerAndSerialNumber::CSM_IssuerAndSerialNumber(const Certificate &SNACCCert)
{
   m_pSNACCIssSn = NULL;
   Set(SNACCCert);
}

//////////////////////////////////////////////////////////////////////////
void CSM_IssuerAndSerialNumber::Set(const Certificate &SNACCCert) 
{
    SME_SETUP("CSM_IssuerAndSerialNumber::Set Certificate");
    if (m_pSNACCIssSn)
    {
        delete m_pSNACCIssSn;
        m_pSNACCIssSn = NULL;
    }    // END if m_pSNACCIssSn
    SetIssuer(SNACCCert.toBeSigned.issuer);
    SetSerialNo(SNACCCert.toBeSigned.serialNumber);
    SME_FINISH_CATCH
}
//////////////////////////////////////////////////////////////////////////
void CSM_IssuerAndSerialNumber::Set(const IssuerAndSerialNumber &SNACCIssAndSer) 
{
    SME_SETUP("CSM_IssuerAndSerialNumber::Set SNACC IssuerAndSerialNumber");
    if (m_pSNACCIssSn == NULL)
      m_pSNACCIssSn = new IssuerAndSerialNumber;
    *m_pSNACCIssSn = SNACCIssAndSer;
    SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// returns a new pointer to the CSM_DN class  
CSM_DN *CSM_IssuerAndSerialNumber::GetIssuer() 
{
    CSM_DN *pIssuer=NULL;
    
    SME_SETUP("CSM_IssuerAndSerialNumber::GetIssuer");
    if (m_pSNACCIssSn != NULL)
        pIssuer = new CSM_DN(m_pSNACCIssSn->issuer);

    SME_FINISH_CATCH
    return pIssuer;
}   

//////////////////////////////////////////////////////////////////////////
// returns a pointer to the CSM_Buffer class  
CSM_Buffer* CSM_IssuerAndSerialNumber::GetSerialNo() 
{
    CSM_Buffer *pSN=NULL;

    SME_SETUP("CSM_IssuerAndSerialNumber::GetSerialNo");
    if (m_pSNACCIssSn != NULL)
        pSN = new CSM_Buffer((const char *)m_pSNACCIssSn->serial.c_str(), 
         m_pSNACCIssSn->serial.length());

    SME_FINISH_CATCH
    return pSN;
}   

//////////////////////////////////////////////////////////////////////////
// set m_pIssuer private variable with a CSM_DN issuer
void CSM_IssuerAndSerialNumber::SetIssuer(const CSM_DN &Issuer) 
{
   SME_SETUP("CSM_IssuerAndSerialNumber::SetIssuer");
   Name *pTmpIssuer = Issuer.GetSnacc();
   if (pTmpIssuer != NULL)
   {
       if (m_pSNACCIssSn == NULL)
          m_pSNACCIssSn = new IssuerAndSerialNumber;
       m_pSNACCIssSn->issuer = *pTmpIssuer;
       delete pTmpIssuer;
   }        // END IF pTmpIssuer
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// set m_pIssuer private variable with a SNACC issuer
void CSM_IssuerAndSerialNumber::SetIssuer(const Name &SNACCIssuer)
{
   SME_SETUP("CSM_IssuerAndSerialNumber::SetIssuer");
   if (m_pSNACCIssSn == NULL)
      m_pSNACCIssSn = new IssuerAndSerialNumber;
   m_pSNACCIssSn->issuer = SNACCIssuer;
   SME_FINISH_CATCH
}     

//////////////////////////////////////////////////////////////////////////
void CSM_IssuerAndSerialNumber::SetSerialNo(const CSM_Buffer &SerialNo) 
{
   SME_SETUP("CSM_IssuerAndSerialNumber::SetSerialNo");
   if (m_pSNACCIssSn == NULL)
        m_pSNACCIssSn = new IssuerAndSerialNumber;
   m_pSNACCIssSn->serial.Set((const unsigned char *)SerialNo.Access(), SerialNo.Length());

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_IssuerAndSerialNumber::SetSerialNo(const CertificateSerialNumber &SNACCSerialNo) 
{
   SME_SETUP("CSM_IssuerAndSerialNumber::SetSerialNo SerialNumber");
   if (m_pSNACCIssSn == NULL)
        m_pSNACCIssSn = new IssuerAndSerialNumber;
   m_pSNACCIssSn->serial = SNACCSerialNo;

   SME_FINISH_CATCH
}

CSM_Buffer *CSM_IssuerAndSerialNumber::GetEncodedIss()
{
    CSM_Buffer *pBuf=NULL;

    SME_SETUP("CSM_IssuerAndSerialNumber::GetEncodedIss");
    if (m_pSNACCIssSn != NULL)
    {
        ENCODE_BUF(m_pSNACCIssSn, pBuf);
    }
    SME_FINISH_CATCH

    return pBuf;
}

//////////////////////////////////////////////////////////////////////////
// COMPARISON OPERATORS
bool CSM_IssuerAndSerialNumber::operator == 
      (const CSM_IssuerAndSerialNumber &issuer) 
{
   bool bRet = false;
   CSM_Buffer *pBuf1 = NULL;
   CSM_Buffer *pBuf2 = NULL;
   DN *pDn1=NULL;
   DN *pDn2=NULL;

   SME_SETUP("CSM_IssuerAndSerialNumber::operator ==");

   //SME(pBuf1 = this->GetEncodedIss());
   //SME(pBuf2 = issuer.GetEncodedIss());
   pDn1 = ((CSM_IssuerAndSerialNumber *)this)->GetIssuer();
   pDn2 = ((CSM_IssuerAndSerialNumber &)issuer).GetIssuer();
   SME(pBuf1 = this->GetSerialNo());
   SME(pBuf2 = ((CSM_IssuerAndSerialNumber &)issuer).GetSerialNo());
   if (pBuf1 && pBuf2) 
      bRet = (*pBuf1 == *pBuf2);
   else  
      bRet = false;

   /////DEBUG
   #ifdef DEBUG_KEEP
   const char *p1=*pDn1;
   const char *p2=*pDn2;
   free(p1);
   free(p2);
   #endif      // DEBUG
   /////DEBUG

   if (bRet && pDn1 && pDn2)    //BOTH conditions must be met
      bRet = ((*pDn1) == (*pDn2));
   else  
      bRet = false;

   if (pBuf1)
      delete pBuf1;
   if (pBuf2)
      delete pBuf2;
   if (pDn1)
      delete pDn1;
   if (pDn2)
      delete pDn2;

   SME_FINISH
   SME_CATCH_SETUP
       if (pBuf1)
          delete pBuf1;
       if (pBuf2)
         delete pBuf2;
      if (pDn1)
        delete pDn1;
      if (pDn2)
        delete pDn2;
   SME_CATCH_FINISH

   return(bRet);
}

//////////////////////////////////////////////////////////////////////////
bool CSM_IssuerAndSerialNumber::operator != 
      (const CSM_IssuerAndSerialNumber &issuer) 
{
    return(!(*this == issuer));
}
//////////////////////////////////////////////////////////////////////////
CSM_IssuerAndSerialNumber & CSM_IssuerAndSerialNumber::operator = 
   (const IssuerAndSerialNumber &SNACCISN) 
{
   SME_SETUP("CSM_IssuerAndSerialNumber::operator =");

   if (m_pSNACCIssSn == NULL)
      m_pSNACCIssSn = new IssuerAndSerialNumber;
   *m_pSNACCIssSn = SNACCISN;

   SME_FINISH_CATCH
   return *this;
}

//////////////////////////////////////////////////////////////////////////
CSM_IssuerAndSerialNumber & CSM_IssuerAndSerialNumber::operator = 
   (const CSM_IssuerAndSerialNumber &ISN) 
{
   SME_SETUP("CSM_IssuerAndSerialNumber::operator =");

   if (m_pSNACCIssSn != NULL)
      delete m_pSNACCIssSn;
   m_pSNACCIssSn = ((CSM_IssuerAndSerialNumber &)ISN).GetSNACCIssuerAndSerialNumber();

   SME_FINISH_CATCH
   return *this;
}

//////////////////////////////////////////////////////////////////////////
IssuerAndSerialNumber *
      CSM_IssuerAndSerialNumber::GetSNACCIssuerAndSerialNumber()
{
   IssuerAndSerialNumber *pSNACCIssSerNo=new IssuerAndSerialNumber;
   SME_SETUP("CSM_IssuerAndSerialNumber::GetSNACCIssuerAndSerialNumber");
   *pSNACCIssSerNo = *AccessSNACCIssuerAndSerialNumber();
   SME_FINISH_CATCH
   return(pSNACCIssSerNo);
}

//////////////////////////////////////////////////////////////////////////
const IssuerAndSerialNumber *
      CSM_IssuerAndSerialNumber::AccessSNACCIssuerAndSerialNumber() const 
{
   return(m_pSNACCIssSn);
}

_END_CERT_NAMESPACE 

// EOF sm_Issuer.cpp
