//////////////////////////////////////////////////////////////////////////////
// aclmatchinfo.cpp
// These routines support the MatchInfo Class
// CONSTRUCTOR(s):
//   MatchInfo()
// MEMBER FUNCTIONS:
//   setIssuerDN(CML::ASN::DN &dn)
//   setPolicyId(AsnOid &policyId)
//   setSubjectDN(CML::ASN::DN &dn)
//   setSerialNo(SNACC::AsnInt &serialNo)
//   setSubjectKeyId(CTIL::CSM_Buffer &ski)
//   setAuthorityKeyId(CTIL::CSM_Buffer &aki)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR:
//
MatchInfo::MatchInfo(void)
{
   m_pIssuerDN = NULL;
   m_pSubjectDN = NULL;
   m_pSki = NULL;
   m_pAki = NULL;
   m_pSerialNo = NULL;
   m_pPolicyId = NULL;
} // END OF CONSTRUCTOR

// DESTRUCTOR:
//
MatchInfo::~MatchInfo()
{
   if (m_pIssuerDN != NULL)
   {
      delete m_pIssuerDN;
      m_pIssuerDN = NULL;
   }
   if (m_pSubjectDN != NULL)
   {
      delete m_pSubjectDN;
      m_pSubjectDN = NULL;
   }
   if (m_pSki != NULL)
   {
      delete m_pSki;
      m_pSki = NULL;
   }
   if (m_pAki != NULL)
   {
      delete m_pAki;
      m_pAki = NULL;
   }
   if (m_pSerialNo != NULL)
   {
      delete m_pSerialNo;
      m_pSerialNo = NULL;
   }
   if (m_pPolicyId != NULL)
   {
      delete m_pPolicyId;
      m_pPolicyId = NULL;
   }
} // END OF DESTRUCTOR

// setIssuerDN:
//
void MatchInfo::setIssuerDN(const CML::ASN::DN &dn)
{
   if (m_pIssuerDN != NULL)
   {
      delete m_pIssuerDN;
   }
   m_pIssuerDN = new CML::ASN::DN(dn);
} // END OF MEMBER FUNCTION setIssuerDN

// setPolicyId:
//
void MatchInfo::setPolicyId(const AsnOid &policyId)
{
   if (m_pPolicyId != NULL)
   {
      delete m_pPolicyId;
   }
   m_pPolicyId = new AsnOid(policyId);
} // END OF MEMBER FUNCTION setPolicyId

// setSubjectDN:
//
void MatchInfo::setSubjectDN(const CML::ASN::DN &dn)
{
   if (m_pSubjectDN != NULL)
   {
      delete m_pSubjectDN;
   }
   m_pSubjectDN = new CML::ASN::DN(dn);
} // END OF MEMBER FUNCTION setSubjectDN

// setSerialNo:
//
void MatchInfo::setSerialNo(const SNACC::AsnInt &serialNo)
{
   if (m_pSerialNo != NULL)
   {
      delete m_pSerialNo;
   }
   m_pSerialNo = new AsnInt(serialNo);
} // END OF MEMBER FUNCTION setSerialNo

// setSubjectKeyId:
//
void MatchInfo::setSubjectKeyId(const SNACC::AsnOcts &ski)
{
   if (m_pSki != NULL)
   {
      delete m_pSki;
   }
   m_pSki = new SNACC::AsnOcts(ski);
} // END OF MEMBER FUNCTION setSubjectKeyId

// setAuthorityKeyId:
//
void MatchInfo::setAuthorityKeyId(const SNACC::AsnOcts &aki)
{
   if (m_pAki != NULL)
   {
      delete m_pAki;
   }
   m_pAki = new SNACC::AsnOcts(aki);
} // END OF MEMBER FUNCTION setAuthorityKeyId

_END_NAMESPACE_ACL
// EOF aclmatchinfo.cpp
