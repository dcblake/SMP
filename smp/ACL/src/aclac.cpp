//////////////////////////////////////////////////////////////////////////////
// aclac.cpp
// These routines support the AC Class
// CONSTRUCTOR(s):
//   AC(void)
//   AC(CSM_Buffer &encodedAC):Cacheable()
// DESTRUCTOR:
//   ~AC(void)
// MEMBER FUNCTIONS:
//   vValidate(Session *s, PublicKeyInfo &pubKeyInfo)
//   check(Session *s, SPIF &spif, SecurityLabel &label)
//   getIssuerName(void)
//   getSubjectName(void)
//   getPolicyIdList(void)
//   operator=(AC &that)
//   Print(ostream &os)
//   getDescription(ostream &os)
//   checkExtensions(void)
//   matches(MatchInfo &matchInfo)
//   getIssuerInfo(MatchInfo &matchInfo)
//   checkValidity(void)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR:
//
AC::AC(void):Cacheable(Cacheable::ACERT_ID)
{
   init();
} // END OF CONSTRUCTOR

// ALTERNATE CONSTRUCTOR:
//
AC::AC(const CML::ASN::Bytes &encodedAC):Cacheable(Cacheable::ACERT_ID)
{
   FUNC("AC::AC(const CML::ASN::Bytes &)");

   init();

   try
   {
      Decode(encodedAC);
   }
   catch(...)
   {
      throw ACL_EXCEPT(ACL_ASN_ERROR,"Error decoding attribute certificate");
   }
   // check for critical unknown extensions
   //
   checkExtensions();
   m_origObject = encodedAC;
   m_origObject.Hash(m_hash);
} // END OF ALTERNATE CONSTRUCTOR

AC::AC(const AC &that):Cacheable(Cacheable::ACERT_ID)
{
   init();
   *this = that;
} // END OF MEMBER FUNCTION SPIF

void AC::init()
{
   /* PL: dump this */
   m_pName = NULL;
   m_pIssuerName = NULL;
}

// DESTRUCTOR:
//
AC::~AC()
{
   if (m_policyIdList.size() > 0)
   {
      m_policyIdList.erase(m_policyIdList.begin(), m_policyIdList.end());
   }

   m_pIssuerName = NULL;
   
   if (m_pName != NULL)
   {
      delete m_pName;
      m_pName = NULL;
   }
} // END OF DESTRUCTOR

// vPathRules()
//    perform AC specific path validation logic.  For ACs nothing is done with the 
//    incoming certPath.
//
void AC::vPathRules(Session *s, const CML::ASN::CertificationPath &certPath)
{

   FUNC("AC::vPathRules");
   const AsnOidLst &certPolicyIdList = getPolicyIdList();
   AclString os;

   try
   {
       // PARAMETER CHECKS
       if (s == NULL)
       {
          throw ACL_EXCEPT(ACL_NULL_POINTER, "Session parameter is NULL");
       }

       // Trust check
       //
       // IF dms mode is on don't do trust check
       if (s->usingTrustList())
       {
          // Trust points must exist for all policies in the 
          // certificate.
          //
          CML::ASN::DN  tmpDN(this->getIssuerName());

		    AsnOidLst::const_iterator i;
          for(i = certPolicyIdList.begin(); i != certPolicyIdList.end(); i++)
          {
             // trust point doesn't exist throw an exception
             //
             if (s->findTrust(tmpDN, *i) == false)
             {
                this->getDescription(os);
                os << "Trust Error.";
                throw ACL_EXCEPT(ACL_TRUST_ERROR, os.str());
             }
          }
       }
   } // END OF TRY
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION vValidate

// check:
//
bool AC::check(Session *s, SPIF &spif, SecurityLabel &label)
{
   AC    *pTmpAC=NULL;
   SPIF  *pTmpSPIF=NULL;
   char   errStr[ACL_STR_BUF_LEN];
   AclString os;
   enum   ePID_Check_Status { NOCHECK=0, CACHEABLE_FAILED=1,
                              SPIF_FAILED=3, BOTH_FAILED=4 };

   FUNC("AC::check");

   // INITIALIZATION
   errStr[0]='\0';

   try
   {
       // PARAMETER CHECKS
       if (s == NULL)
       {
          throw ACL_EXCEPT(ACL_NULL_POINTER, "Session parameter is NULL");
       }

       // BUG FIX GOES HERE ************** PIERCE *******************

       // IF AC or SPIF could not be retrieved from Cache then we know it
       // hasn't been validated yet so don't try.  We know this because
       // validate() will add all validated objects to the cache.
       //
       s->setCacheMode(Session::LOCAL);

       // PULL THE MOST RECENT VERSION OF THIS AC FROM Cache
       pTmpAC = s->getAC(*this);
       // IF THIS AC WAS NOT IN Cache USE THE CURRENT ONE INSTEAD
       if (pTmpAC == NULL)
       {
          pTmpAC = (AC  *)this->clone();
       }

       // PULL THE MOST RECENT VERSION OF THE SPIF FROM Cache
       pTmpSPIF = s->getSPIF(spif);
       // IF THIS SPIF WAS NOT IN Cache USE THE CURRENT ONE INSTEAD
       if (pTmpSPIF == NULL)
       {
          pTmpSPIF = (SPIF *)spif.clone();
       }

       s->setCacheMode(Session::REMOTE);
       // 1. Check ClearanceInfo to determine if it's been validated
       if (! pTmpAC->isValid())
       {
          try
          {
             // build path for AC
             acl::MatchInfo mi;
             this->getIssuerInfo(mi);
             CCList *pCCList = s->getCC(mi);
             std::auto_ptr<CCList> apCCList(pCCList);

             // if more than one issuer cert is return than error out 
             if (pCCList == NULL || pCCList->size() != 1)
             {
                throw ACL_EXCEPT(ACL_AC_VAL_ERROR,"Multiple issuers found");
             }

             // build and validate issuer path 
             pTmpAC->validate(s);
          }
          catch (SnaccException &)
          {
             // Second chance
             //
             if (s->usingAutoRetrieve())
             {
                pTmpAC = NULL;
                pTmpAC = s->getAC(*this);
                if (pTmpAC == NULL)
                {
                   throw;
                }
                else
                {
                   pTmpAC->validate(s);
                }
             }
             else 
                throw;
          }
       }

       // 2. Check SPIF to determine if it's been validated
       if (! pTmpSPIF->isValid())
       {
          try
          {
             pTmpSPIF->validate(s);
          }
          catch (SnaccException &)
          {
             // Second  chance if autoRetrieve is anabled
             //
             if (s->usingAutoRetrieve())
             {
                pTmpSPIF = NULL;
                pTmpSPIF = s->getSPIF(spif);
                if (pTmpSPIF == NULL)
                {
                   throw;
                }
                else
                {
                   pTmpSPIF->validate(s);
                }
             } // END OF if (s->usingAutoRetrieve())
             else
                throw;
          } // END OF catch (SnaccException &)
       } // END OF if (! pTmpSPIF->isValid())

       try
       {
          pTmpAC->getClearance(label.getPolicyId());

          pTmpAC->acdf(s, *pTmpSPIF, label);
       }
       catch(SnaccException &)
       {
          // Second chance if autoRetrieve is enabled
          if (this->m_pSnaccClearance && s->usingAutoRetrieve())
          {     // RWC; if m_pSnaccClearance is NULL, then report error.
             pTmpAC = NULL;
             pTmpAC = s->getAC(*this);
             if (pTmpAC == NULL)
             {
                throw;
             }
             else
             {
                pTmpAC->acdf(s, *pTmpSPIF, label);
             }
          } // END OF if (s->usingAutoRetrieve())
          else
             throw;
       } // END OF catch(SnaccException &)
   } // END OF OUTER TRY
   catch (SnaccException &e)
   {
      s->setCacheMode(Session::LOCAL_THEN_REMOTE);
      e.push(STACK_ENTRY);
      throw;
   }
   return true;

} // END OF MEMBER FUNCTION check

// getIssuerName:
// INPUT:  NONE
// OUTPUT: NONE
// RETURN: CML::ASN::DN &
// THIS MEMBER FUNCTION EXTRACTS THE Issuer Directory Name FROM THE CURRENT
//   AC AND CREATES A Reference TO A NEW CML::ASN::DN WHICH IT RETURNS TO THE
//   CALLING FUNCTION
//
const CML::ASN::DN & AC::getIssuerName(void) const
{
   char       errStr[ACL_STR_BUF_LEN];
   bool       done = false;

   FUNC("AC::getIssuerName");

   // INITIALIZATION
   errStr[0]='\0';
   if (m_pIssuerName == NULL)
   {
       CML::ASN::GenNames::const_iterator i;

       for (i = issuer.issuerName.begin(); i != issuer.issuerName.end() &&
           !done; i++)
       {
           if (i->GetType() == CML::ASN::GenName::X500)
           {
               m_pIssuerName = i->GetName().dn;
               done = true;
           } // END OF if (i->GetType() == CML::ASN::GenName::X500)
       } // END OF FOR
   } // END OF if (m_pIssuerName == NULL)
  
   if (m_pIssuerName == NULL)
   {
      throw ACL_EXCEPT(ACL_NULL_POINTER, 
       "AttributeCertificate contains unsupported GenernalName for issuer");
   }

   return *m_pIssuerName;

} // END OF MEMBER FUNCTION getIssuerName

// getSubjectName:
// INPUT:  NONE
// OUTPUT: NONE
// RETURN: CML::ASN::DN &
// THIS MEMBER FUNCTION EXTRACTS THE Subject Directory Name FROM THE CURRENT
//   AC AND CREATES A Reference TO A NEW CML::ASN::DN WHICH IT RETURNS TO THE
//   CALLING FUNCTION
//    NOTE THAT THIS FUNCTION CURRENTLY ONLY PROVIDES A CML::ASN::DN FOR 
//    subjectName AND FURTHER ONLY A GeneralName WHICH IS A directoryName.
//
const CML::ASN::DN &AC::getSubjectName(void) const
{
   char       errStr[ACL_STR_BUF_LEN];
   bool       done = false;

   FUNC("AC::getSubjectName");

   // INITIALIZATION
   errStr[0]='\0';
   try
   {
       if (m_pName == NULL)
       {
          // FOR NOW WE ARE ONLY GOING TO SUPPORT subjectName AND NOT THE
          // OTHER TWO CHOICES (Holder AND IssuerSerial) -- TBD
          CML::ASN::GenNames::const_iterator i;

          for (i = holder.entityName.begin(); i != holder.entityName.end() &&
              !done; i++)
          {
              if (i->GetType() == CML::ASN::GenName::X500)
              {
                  m_pName = new CML::ASN::DN(*i->GetName().dn);
                  done = true;
              } // END OF if (i->GetType() == CML::ASN::GenName::X500)
          } // END OF FOR
       } // END OF if (m_pName == NULL)
       if (m_pName == NULL)
       {
          throw ACL_EXCEPT(ACL_NULL_POINTER, "AC Missing Subject Directory Name");
       } // END OF if (m_pName == NULL)
   } // END OF TRY
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   return *m_pName;

} // END OF MEMBER FUNCTION getSubjectName

// getPolicyIdList:
// INPUT:  NONE
// OUTPUT: NONE
// RETURN: AsnOidLst &
// THIS MEMBER FUNCTION LOOPS THROUGH THE CURRENT LIST OF ATTRIBUTES 
//   AND WHEN IT FINDS A CLEARANCE ATTRIBUTE 
//   IT DECODES THE ASSOCIATED VALUES INTO A SNACC List
//   FROM WHICH IN TURN IS EXTRACTED A NEW List of AsnOid PolicyIds 
//   WHICH IT RETURNS TO THE CALLING FUNCTION
//
const AsnOidLst & AC::getPolicyIdList(void) const
{
   char       errStr[ACL_STR_BUF_LEN];

   FUNC("AC::getPolicyIdList");

   // INITIALIZATION
   errStr[0]='\0';
   try
   {
       if (m_policyIdList.size() == 0)
       {
          CML::ASN::AttributeList::const_iterator i;

          for (i = attribs.begin(); i != attribs.end(); i++)
          {
              if (i->GetType() == CML::ASN::Attribute::Clearance)
              {
                  CML::ASN::ClearanceList::const_iterator j;
                  for (j = i->GetValues().pClearance->begin(); 
                       j != i->GetValues().pClearance->end(); j++)
                  {
                      m_policyIdList.push_back(j->policyId);
                  } // END OF INNER FOR
              } // END OF if (i->GetType() == CML::ASN::Attribute::Clearance)
          } // END OF OUTER FOR
       } // END OF if (m_policyIdList.size() == 0)
       if (m_policyIdList.size() < 1)
       {
          CML::ASN::DN tmpDN(this->getSubjectName());
          sprintf(errStr, "%s %s %s %s",
                  "Missing Clearance ",
                  "Attribute in (DN:",
                  (const char *)tmpDN, ") ");
          throw ACL_EXCEPT(ACL_NULL_POINTER, errStr);
       } // END OF if (m_policyIdList.size() < 1)
   } // END OF TRY
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return m_policyIdList;

} // END OF MEMBER FUNCTION getPolicyIdList

const SNACC::Clearance * AC::getClearance(const SNACC::AsnOid &policyId)
{
   FUNC("AC::getClearance()");

   CML::ASN::AttributeList::iterator i;
   try
   {

      for (i = attribs.begin(); i != attribs.end(); i++)
      {
         if (i->GetType() == CML::ASN::Attribute::Clearance)
         {
            CML::ASN::ClearanceList::const_iterator j;
            for (j = i->GetValues().pClearance->begin(); 
                 j != i->GetValues().pClearance->end(); j++)
            {
                if (j->policyId == policyId)
                {
                   if (m_pSnaccClearance)
                      delete m_pSnaccClearance;
                   m_pSnaccClearance = j->GetSnacc();
                   return m_pSnaccClearance;
                } // END OF if (j->policyId == policyId)
            } // END OF INNER FOR
         } // END OF if (i->GetType() == CML::ASN::Attribute::Clearance)
      } // END OF OUTER FOR
      // finished searching for Clearance attribute and it wasn't found
      //
      AclString errStr;
      this->getDescription(errStr);
      errStr << "\nMissing Policy for [" << policyId << "]\n";
      throw ACL_EXCEPT(ACL_MISSING_POLICY, errStr.str());
   } // END OF TRY
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   
}


// operator =:
//
AC &AC::operator=(const AC &that)
{
   this->Cacheable::operator=(that);
   this->ClearanceInfo::operator=(that);
   this->AttributeCert::operator=(that);

   return (*this);
} // END OF OPERATOR OVERLOAD = 

// FUNCTION: getDescription
//
// PURPOSE: Display debug information about a 
//          AttributeCertificate (AC).
//
void AC::getDescription(AclString &os) const
{
   CML::ASN::DN  tmpDN(this->getSubjectName());

   os << "\n** Attribute Certificate **:" 
      << "\n\tDN: " << (char *)(const char *)tmpDN;

   // Display Clearance IDs if present
   //
   try
   {
      bool firstTime = true;

      AsnOid *pOid = NULL;
      const AsnOidLst &oidList = this->getPolicyIdList();
	  AsnOidLst::const_iterator i;
      for (i = oidList.begin(); i != oidList.end(); i++)
      {
         AsnOid tmpOid(*i);
      
         if (firstTime)
         {
            firstTime = false;
            os << "\n\tOID(s):";
         }
         os << " " << (const char *) *i;
      } // END OF FOR
      os << "\n";
   } // END OF TRY
   catch (ACL_Exception *pE)
   {
      // don't display any policy ID information since
      // this is probably a CA, PCA, or ROOT certificate
      // in which case we don't care if it has a clearance
      // attribute.
      //
      delete pE;
   }
} // END OF MEMBER FUNCTION getDescription

// checkExtensions:
//
void AC::checkExtensions(void)
{
   FUNC("AC::checkExtensions");

   try
   {
      CML::ASN::UnknownExtensions::iterator i;
      for (i = exts.unknownExts.begin(); i != exts.unknownExts.end(); i++)
      {
         if (i->critical)
         {
            if ( ! (
               (i->OID() == id_ce_subjectDirectoryAttributes) ||
               (i->OID() == id_ce_subjectKeyIdentifier) ||
               (i->OID() == id_ce_keyUsage) ||
               (i->OID() == id_ce_privateKeyUsagePeriod) ||
               (i->OID() == id_ce_subjectAltName) ||
               (i->OID() == id_ce_issuerAltName) ||
               (i->OID() == id_ce_basicConstraints) ||
               (i->OID() == id_ce_nameConstraints) ||
               (i->OID() == id_ce_certificatePolicies) ||
               (i->OID() == id_ce_policyMappings) ||
               (i->OID() == id_ce_authorityKeyIdentifier) ||
               (i->OID() == id_ce_policyConstraints)) )
            {
               AsnOid tmpOid(i->OID());
               char errStr[ACL_STR_BUF_LEN];
               errStr[0]='\0';
               sprintf(errStr, "%s %s %s",
                       "Found Critical unknown extension\n\t(",
                       (const char *)tmpOid, ")");
               throw ACL_EXCEPT(ACL_AC_EXT_ERROR, errStr);
            } // END OF IF
         } // END OF if (i->critical)
      } // END OF FOR
   } // END OF TRY
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

} // END OF MEMBER FUNCTION checkExtensions


// matches:
//
bool AC::matches(const MatchInfo &matchInfo) const
{
   FUNC("AC::matches");
   
   int matchCount=0;
   try
   {
       const CML::ASN::DN *pIssuerDN = matchInfo.getIssuerDN();
       const CML::ASN::DN *pSubjectDN = matchInfo.getSubjectDN();
 //      const SNACC::AsnOcts *pSubjectKeyId = matchInfo.getSubjectKeyId();
       const SNACC::AsnOcts *pAuthorityKeyId = matchInfo.getAuthorityKeyId();
       const SNACC::AsnInt *pSerialNo = matchInfo.getSerialNo();
       const AsnOid *pPolicyId = matchInfo.getPolicyId();

       // Match on issuerDN
       //
       if (pIssuerDN != NULL)
       {
          if (this->getIssuerName() == *((CML::ASN::DN *) pIssuerDN))
          {
             matchCount++;
          } // END OF IF
          else
          {
             return false;
          } // END OF ELSE
       } // END OF if (pIssuerDN != NULL)

       // Match on subjectDN if present
       //
       if (pSubjectDN != NULL)
       {
          if (this->getSubjectName() == *((CML::ASN::DN *) pSubjectDN))
          {
             matchCount++;
          } // END OF IF
          else
          {
             return false;
          } // END OF ELSE
       } // END OF if (pSubjectDN != NULL)
  
       // look for authorityKeyIdentifier extensions.
       //
       if (pAuthorityKeyId != NULL)
       {
          if (exts.pAA_Id)
          {
              if (pAuthorityKeyId != NULL && 
                  exts.pAA_Id->OID() == id_ce_authorityKeyIdentifier)
              {
                 AuthorityKeyIdentifier *pSnaccAki;
                 pSnaccAki= 
                    (AuthorityKeyIdentifier *)exts.pAA_Id->OID().Clone();
              } // END OF IF
          } // END OF if (exts.pAA_Id)
       } // END OF if (pAuthorityKeyId != NULL)

       // Match on serialNo if present
       //
       if (pSerialNo != NULL)
       {
          if (serialNum == *pSerialNo)
             matchCount++;
       }

       // Match on policyId if present
       //
       if (pPolicyId != NULL)
       {
          const AsnOidLst &oidLst = getPolicyIdList();
		  AsnOidLst::const_iterator i;
          for (i = oidLst.begin(); i != oidLst.end(); i++)
          {
             if (*i == *pPolicyId)
             {
                matchCount++;
                break;
             } // END OF IF
          } // END OF FOR
       } // END OF if (pPolicyId != NULL)
       // For a certificate to match at least TWO matching items must be present.
       //
       if (matchCount >= 2)
       {
          return true;
       } // END OF IF
       else
       {
          return false;
       } // END OF ELSE
   } // END OF TRY
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION matches

// getIssuerInfo()
//
// this member is used to retrieve match information for the issuer of
// AC object.  This information is used as match creteria for 
// the issuer ceritificate.
//
void AC::getIssuerInfo(MatchInfo &matchInfo)
{
   // get issuer's DN
   //
   matchInfo.setSubjectDN(this->getIssuerName());
   
   // If the authority key identifier is present set
   // matchInfo's subject identifier to it.
   //

   if (exts.pAuthKeyID != NULL && exts.pAuthKeyID->keyID != NULL)
   {
      matchInfo.setSubjectKeyId(*exts.pAuthKeyID->keyID);
   }
}

// :checkValidity
//
bool AC::checkValidity(void)
{
   if (validity.IsValid())  
   {
      return true;
   }

   return false;
} // END OF MEMBER FUNCTION checkValidity

_END_NAMESPACE_ACL

// EOF aclac.cpp
