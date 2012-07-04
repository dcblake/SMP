//////////////////////////////////////////////////////////////////////////////
// aclclearcert.cpp
// These routines support the ClearanceCert Class
// CONSTRUCTOR(s):
//   ClearanceCert(void)
//   ClearanceCert(CSM_Buffer &encodedCC):Cacheable(),ClearanceInfo()
// DESTRUCTOR:
//   ~ClearanceCert()
// MEMBER FUNCTIONS:
//   check(Session *s, SPIF &spif, SecurityLabel &label)
//   acdf(s, *pTmpSPIF, label);
//   check(Session *s, SPIF &spif, SecurityLabel &label)
//   getIssuerName(void)
//   getSubjectName(void)
//   getPolicyIdList(void)
//   getCaClearance(AsnOid policyId)
//   getClearance(AsnOid &policyId);
//   Print(ostream &os)
//   getDescription(ostream &os)
//   checkExtensions(void)
//   intersect(Session *pSession, CSM_BufferLst *pIssuerLst)
//   operator= (ClearanceCert &that)
//   matches(MatchInfo &matchInfo)
//   getIssuerInfo(MatchInfo &matchInfo)
//   checkValidity(void)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR:
//
ClearanceCert::ClearanceCert(void):Cacheable(Cacheable::ACLRCERT_ID)
{
} // END OF CONSTRUCTOR

// ALTERNATE CONSTRUCTOR:
//
ClearanceCert::ClearanceCert(const CML::ASN::Bytes &encodedCC):Cacheable(Cacheable::ACLRCERT_ID)
{
   FUNC("ClearanceCert::ClearanceCert(const CML::ASN::Bytes &)");

   try
   {
      Decode(encodedCC);
   }
   catch(...)
   {
      throw ACL_EXCEPT(ACL_ASN_ERROR, "Error decoding certificate");
   }
   checkExtensions();
   m_origObject = encodedCC;
   m_origObject.Hash(m_hash);
} // END OF ALTERNATE CONSTRUCTOR

ClearanceCert::ClearanceCert(const CML::ASN::Cert &that):Cert(that),Cacheable(Cacheable::ACLRCERT_ID)
{
   checkExtensions();
   that.Encode(m_origObject);
}
// DESTRUCTOR:
//
ClearanceCert::~ClearanceCert()
{
   if (m_policyIdList.size())
      m_policyIdList.erase(m_policyIdList.begin(), m_policyIdList.end());
} // END OF DESTRUCTOR


bool ClearanceCert::validate(Session *pSession)
{
	// If alread valid just return
	if (isValid())
		return true;

	// If not using the CML, call the base Cacheable::validate() function
	if (!pSession->usingCML())
		return Cacheable::validate(pSession);
	else
	{
		// Use the CML to validate the path
		CML::CertPath certPath(m_origObject, false);
		if (certPath.BuildAndValidate(pSession->getCMLHandle(),
			CM_SEARCH_UNTIL_FOUND) != CM_NO_ERROR)
			return false;

		// Process any object specific path validation logic
		vPathRules(pSession, certPath.base());
	}

	return true;
}


// vPathRules:
//
void ClearanceCert::vPathRules(Session *s, const CML::ASN::CertificationPath &certPath)
{

   FUNC("ClearanceCert::vPathRules");

   AclString os;
   AsnOidLst certPolicyIdList;

   // Trust check
   //
   // IF dms mode is on don't do trust check
   try
   {
       if (s->usingTrustList())
       {
          // Trust points must exist for all policies in the 
          // certificate.
          //
          certPolicyIdList = this->getPolicyIdList();
          CML::ASN::DN  tmpDN(this->getIssuerName());

		    AsnOidLst::iterator pTmpPolicyId;
          for(pTmpPolicyId = certPolicyIdList.begin();
              pTmpPolicyId != certPolicyIdList.end();
              pTmpPolicyId++)
          {
             // trust point doesn't exist throw an exception
             //
             if (s->findTrust(tmpDN, *pTmpPolicyId) == false)
             {
                this->getDescription(os);
                os << "Trust Error.";
                throw ACL_EXCEPT(ACL_TRUST_ERROR, os.str());
             }
          }
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION vPathRules

// check:
//
bool ClearanceCert::check(Session *s, SPIF *&pSpif, SecurityLabel &label)
{
   ClearanceCert *pTmpCC=NULL;
   char   errStr[ACL_STR_BUF_LEN];
   bool   bDone=false;
   AclString os;
   AsnOidLst::const_iterator pCurrPolicyId;
   bool    bClearanceFound = false;
   SPIF    localSPIF;
   SPIF    *pTmpSPIF = NULL;
   bool    spifLdap = false;  // flag to indicate if Clearance has been retrieved from LDAP
   bool    ccLdap = false; // flag to indicate if SPIF has been retrieved from LDAP

   FUNC("ClearanceCert::check");

   // INITIALIZATION
   errStr[0]='\0';
   try
   {
       // PARAMETER CHECKS
       if (s == NULL)
       {
          throw ACL_EXCEPT(ACL_NULL_POINTER,"Session parameter is NULL.");
       }

       // IF ClearanceCert or SPIF could not be retrieved from Cache then we know
       // it hasn't been validated yet so don't try.  We know this because
       // validate() will add all validated objects to the cache.
       //
       s->setCacheMode(Session::LOCAL);

       // PULL THE MOST RECENT VERSION OF THIS AC FROM Cache
       pTmpCC = s->getCC(*this);

       // IF THIS AC WAS NOT IN Cache USE THE CURRENT ONE INSTEAD
       if (pTmpCC == NULL)
       {
          pTmpCC = (ClearanceCert *) this->clone();
       }

       // PULL THE MOST RECENT VERSION OF THE SPIF FROM Cache
       if (pSpif)
       {
          pTmpSPIF = s->getSPIF(*pSpif);

          // IF THIS SPIF WAS NOT IN Cache USE THE CURRENT ONE INSTEAD
          if (pTmpSPIF == NULL)
          {
             pTmpSPIF = (SPIF *) pSpif->clone();
          }
       }

       MatchInfo mi;
       mi.setPolicyId(label.getPolicyId());

       // IF SPIF was provided and doesn't match clearance asserted by
       // label throw an error.
       //
       if (label.isOutgoing() && pSpif != NULL && 
           pSpif->getPolicyId() != label.getPolicyId())
       {
          AclString o;
          AsnOid tmpOid(label.getPolicyId());
          o << "Outgoing Label and SPIF policy identifiers do not match:\n";
          o << "Security Label Policy: " << (const char *) tmpOid << "\n";
          pSpif->getDescription(o);
          throw ACL_EXCEPT(ACL_SPIF_CC_ERROR, o.str());
       }

       // All subsequent lookups will be from LDAP only.
       //
       s->setCacheMode(Session::REMOTE);

       while (bDone == false)
       {
          // 1. Check ClearanceInfo to determine if it's been validated
          if (! pTmpCC->isValid())
          {
             // Try to validate cert.  If validation fails attempt to retrieve
             // cert from LDAP.
             //
             try
             {
                pTmpCC->validate(s);
             }
             catch (SnaccException &)
             {
                // Second chance
                //
                if (s->usingAutoRetrieve() && !ccLdap)
                {
                   delete pTmpCC;
                   pTmpCC = NULL;
                   pTmpCC = s->getCC(*this);
                   if (pTmpCC == NULL)
                   {
                      throw;
                   }
                   else
                   {
                      pTmpCC->validate(s);
                      ccLdap = true;
                   }
                }
                else
                   throw;
             }
          }

          // IF SPIF was not provided look it up
          //
          if (pTmpSPIF == NULL)
          {
             spifLdap = true;
             localSPIF.getLatest(s, mi);
             pTmpSPIF = (SPIF *) localSPIF.clone();
          }

          try
          {
             // IF SPIF has not been validated try to validate it.
             //
             if (! pTmpSPIF->isValid())
               pTmpSPIF->validate(s);
          }
          catch (SnaccException &)
          {
             // Validate of SPIF failed.  Retrieve one from LDAP
             // and try to validate it.
             //
             // Second chance code.
             //
             if (s->usingAutoRetrieve() && !spifLdap)
             {
                delete pTmpSPIF;
                pTmpSPIF = NULL;
                try
                {
                   spifLdap = true;
                   pSpif->getLatest(s, mi);
                   pTmpSPIF = (SPIF *) pSpif->clone();
                }
                catch (...)
                {
                   // no nothing
                }
                if (pTmpSPIF == NULL)
                {
                   // latest SPIF could not be found in LDAP
                   // re-throw
                   //
                   throw;
                }
                else
                {
                   pTmpSPIF->validate(s);
                }
             }
             else
                throw;
          }

          // Using the list of clearances try to find a clearance attribute
          // that matches the SecurityLabel's security policy identifer.
          //
          for (pCurrPolicyId = pTmpCC->getPolicyIdList().begin();
               pCurrPolicyId != pTmpCC->getPolicyIdList().end() && ! bClearanceFound;
               pCurrPolicyId++)
          {
             if (*pCurrPolicyId == label.getPolicyId())
             {
                bClearanceFound = true;
                break;
             }
          }
          // If found use it to perform the ACDF.
          //
          if (bClearanceFound)
          {
             // Clearance was found that matches the label.
             //
             pTmpCC->getClearance(label.getPolicyId());


             // Try to perform an Access Control check.
             //
             try
             {
               pTmpCC->acdf(s, *pTmpSPIF, label);
               bDone = true;
             }
             catch (SnaccException &)
             {
                // IF not using AutoRetrieve re-throw
                if (! s->usingAutoRetrieve())
                   throw;

                // Second chance handling
                //
                // Access Control check failed. IF the ClearanceCert or SPIF 
                // have not been retrieved from LDAP then attempt to do so.
                // If object is not found on LDAP server then re-throw.
                // 
                // First check to see if ClearanceCert has been retrieved
                // If not query ldap for cert.
                //
                if (! ccLdap)
                {
                   delete pTmpCC;
                   pTmpCC = NULL;
                   ccLdap = true;
                   pTmpCC = s->getCC(*this);
                   if (pTmpCC == NULL)
                      throw;

                }
                // IF ClearanceCert has already been retrieved and SPIF
                // hasn't then try retrieving a new SPIF from LDAP.
                //
                else if (! spifLdap)
                {
                   delete pTmpSPIF;
                   pTmpSPIF = NULL;
                   try
                   {
                      spifLdap = true;
                      pSpif->getLatest(s, mi);
                      pTmpSPIF = (SPIF *) pSpif->clone();
                   }
                   catch (...)
                   {
                      // do nothing
                   }
                   if (pTmpSPIF == NULL)
                      throw;
                }
                else
                {
                   // both SPIF and ClearanceCert have been retrieved and
                   // access control check still fails.  re-throw
                   //
                   throw;
                }
             }
          }
          // ELSE if equivalencies are on try the first clearance attribute.
          // If unsuccessful proceed to the next clearance attribute until
          // success or all have been tried.
          //
          else if (s->usingEquivalencies())
          {
			 AsnOidLst::const_iterator pCurrPolicyId = pTmpCC->getPolicyIdList().begin();
             while ((bDone == false) &&
                    (pCurrPolicyId != pTmpCC->getPolicyIdList().end()))
             {
                // Try ACDF on this clearance and corresponding SPIF.  If
                // an error occurs proceed to the next clearance and
                // corresponding SPIF.
                //
                try
                {
                   AsnOid clearOid(*pCurrPolicyId);

                   // If spif was provided use it to retrieve the
                   // latest SPIF.
                   //
                   if (pSpif != NULL)
                   {
                      pSpif->validate(s);
                      pTmpCC->getClearance(*pCurrPolicyId);
                      pTmpCC->acdf(s, *pSpif, label);
					  operator=(*pTmpCC);
                   }
                   else
                   {
                      // If this is an Outgoing label retrieve
                      // the SPIF using the policy ID of the label.  When using
                      // an Outgoing label the SPIF MUST equal the policy ID of
                      // the label.
                      //
                      if (label.isOutgoing())
                      {
                         AsnOid tmpOid(label.getPolicyId());
                         mi.setPolicyId(tmpOid);
                      }
                      // Else use the policy id from the current clearance
                      // attribute to retrieve the SPIF.
                      //
                      else
                      {
                         mi.setPolicyId(clearOid);
                      }
                      localSPIF.getLatest(s, mi);
                      localSPIF.validate(s);
                      pTmpCC->getClearance(*pCurrPolicyId);
                      pTmpCC->acdf(s, localSPIF, label);
					  operator=(*pTmpCC);
                   }
                   bDone = true;
                }
                catch (ACL_Exception &)
                {
                   // If this is the last clearance re-throw the
                   // exception. Otherwise delete it and continue
                   // checking the remaining clearances.
                   //
				   pCurrPolicyId++;
                   if (pCurrPolicyId == pTmpCC->getPolicyIdList().end())
                   {
                      throw;
                   }
                }
             }

          }
          else
          {
             // ERROR
             //   Policy asserted in label is not found in the user's
             //   clearance(s) and equivalencies are turned off.
             //
             AsnOid tmpOid(label.getPolicyId());
             AclString errStr;

             errStr << "Clearance attribute for " << (const char *) tmpOid
                    << " not found, and equivalency mapping is disabled.\n";
             pTmpCC->getDescription(errStr);
             throw ACL_EXCEPT(ACL_CC_ERROR, errStr.str());
          }

          // IF successful
          //
          if (bDone)
          {
             // IF spif = NULL
             if (pSpif == NULL)
             {
                // clone localSPIF which allocates memory
                // for spif and copies the values from localSPIF
                pSpif = (SPIF *) localSPIF.clone();
             }
          }
       } // END OF WHILE

       // cleanup
       //
       if (pTmpCC != NULL)
          delete pTmpCC;

       if (pTmpSPIF != NULL)
          delete pTmpSPIF;
   }
   catch (SnaccException &e)
   {
      if (pTmpSPIF != NULL)
         delete pTmpSPIF;
      if (pTmpCC != NULL)
         delete pTmpCC;
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
//   ClearanceCert AND CREATES A reference TO A NEW CML::ASN::DN WHICH IT RETURNS
//   TO THE CALLING FUNCTION
//
const CML::ASN::DN &ClearanceCert::getIssuerName(void) const
{
   return (issuer);
} // END OF MEMBER FUNCTION getIssuerName

// getSubjectName:
// INPUT:  NONE
// OUTPUT: NONE
// RETURN: CML::ASN::DN &
// THIS MEMBER FUNCTION EXTRACTS THE Subject Directory Name FROM THE CURRENT
//   ClearanceCert AND CREATES A reference TO A NEW CML::ASN::DN WHICH IT RETURNS
//   TO THE CALLING FUNCTION
// NOTE:  NOTE THAT THIS FUNCTION CURRENTLY ONLY PROVIDES A CML::ASN::DN FOR A
//    AttributeCertificateInfoChoice WHICH USES subjectName AND FURTHER ONLY
//    A GeneralName WHICH IS A directoryName.
//
const CML::ASN::DN & ClearanceCert::getSubjectName(void) const
{
   return (subject);
} // END OF MEMBER FUNCTION getSubjectName

// getPolicyIdList:
// INPUT:  NONE
// OUTPUT: NONE
// RETURN: AsnOidLst &
// THIS MEMBER FUNCTION LOOPS THROUGH THE CURRENT LIST OF ATTRIBUTES
//   AND WHEN IT FINDS A CLEARANCE ATTRIBUTE (id_at_clearance)
//   IT DECODES THE ASSOCIATED VALUES INTO A SNACC List
//   FROM WHICH IN TURN IS EXTRACTED A NEW List of AsnOid PolicyIds
//   WHICH IT RETURNS TO THE CALLING FUNCTION
//
const AsnOidLst &ClearanceCert::getPolicyIdList(void) const
{
   char       errStr[ACL_STR_BUF_LEN];
   Clearance tmpSnaccClearance;

   FUNC("ClearanceCert::getPolicyIdList");

   // INITIALIZATION
   errStr[0]='\0';
   try
   {
       if (m_policyIdList.size() == 0)
       {
          if (exts.pSubjDirAtts != NULL)
          {
             CML::ASN::AttributeList::const_iterator i;
             for (i = exts.pSubjDirAtts->begin(); i != exts.pSubjDirAtts->end(); i++)
             {
                 if (i->GetType() == CML::ASN::Attribute::Clearance)
                 {
                    // THERE CAN BE MULTIPLE VALUES FOR THE CLEARANCE ATTRIBUTE
                    CML::ASN::ClearanceList::const_iterator j;
                    for (j = i->GetValues().pClearance->begin(); 
                        j != i->GetValues().pClearance->end(); j++)
                    {
                       if (j->policyId.Len() > 2)
                       {
                          m_policyIdList.push_back(j->policyId);
                       }
                    }
                 }
             }
          }
       }

       if (m_policyIdList.size() == 0)
       {
          CML::ASN::DN tmpDN(this->getSubjectName());
          sprintf(errStr, "%s %s %s%s",
                  "Missing Clearance",
                  "Attribute in\n\t(DN:",
                  (const char *)tmpDN, ") ");
          throw ACL_EXCEPT(ACL_NULL_POINTER, errStr);
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   return m_policyIdList;

} // END OF MEMBER FUNCTION getPolicyIdList

// getCaClearance:
// INPUT:  AsnOid policyId
// OUTPUT: NONE
// RETURN: Clearance
// THIS MEMBER FUNCTION LOOPS THROUGH THE CURRENT EXTENSIONS LOOKING
//   FOR THE CAClearanceConstraints OID.  WHEN FOUND, IT DECODES THE VALUE
//   WHICH SHOULD BE A SEQUENCE OF ATTRIBUTES.  IT THEN SEARCHES FOR A
//   CLEARANCE ATTRIBUTE (id_at_clearance) WHICH ALSO MATCHES THE policyId
//   WHICH WAS PASSED IN (FROM THE USER CERT).  IF A MATCH IS FOUND THEN
//   THE CLEARANCE ATTRIBUTE IS RETURNED.
//
const Clearance *ClearanceCert::getCaClearance(const AsnOid &policyId)
{
   char        errStr[ACL_STR_BUF_LEN];
   long        lCount=0;
   Clearance   *tmpSnaccClearance = NULL;

   FUNC("ClearanceCert::getCaClearance");

   // INITIALIZATION
   errStr[0]='\0';
   try
   {
       if (m_pSnaccClearance == NULL ||
           (m_pSnaccClearance->policyId != policyId))
       {
          /* IF the SubjectDirectoryAttributes EXTENSION is present
           */
          if (this->exts.pSubjDirAtts != NULL)
          {
             CML::ASN::AttributeList::const_iterator i;

             /* Loop through attributes looking for all CAClearanceAttributes
              */
              i = this->exts.pSubjDirAtts->Find(id_cAClearanceConstraints);
              if ( (i == exts.pSubjDirAtts->end())
                  || (i->GetValues().pCACons == NULL))
                  return NULL;

              CML::ASN::AttributeList::const_iterator j;
              j = i->GetValues().pCACons->Find(id_at_clearance);
              if ((j == i->GetValues().pCACons->end()) || 
                  (j->GetValues().pClearance == NULL))
                  return NULL;
              for (; j != i->GetValues().pCACons->end();
                   j = i->GetValues().pCACons->FindNext(j,
                       id_at_clearance) )
                   {
                      CML::ASN::ClearanceList::const_iterator k;
                      for (k = j->GetValues().pClearance->begin(); 
                           k != j->GetValues().pClearance->end(); k++)
                      {
                        if (k->policyId == policyId)
                        {
                           if (lCount == 0)
                              tmpSnaccClearance = k->GetSnacc();
                           lCount++;
                        }
                      }
                   }
          }

          if (lCount > 1)
          {
             AclString o;
             AsnOid tmpOid(policyId);
             CML::ASN::DN tmpDN(this->getSubjectName());

             o << "Multiple cAClearanceConstraints for:\n"
               << "Policy ID: " << (const char *) tmpOid << "\nIN:\n"
               << "Subject DN: " << (const char *)tmpDN << "\n";

             throw ACL_EXCEPT(ACL_CC_ERROR, o.str());
          }
          else if (lCount == 0)
          {
             return (const Clearance *) NULL;
          }
          else
          {
             /* Clearance was found and is in tmpSnaccClearance */
             if (m_pSnaccClearance)
                delete m_pSnaccClearance;
//             m_pSnaccClearance = new Clearance(tmpSnaccClearance);
             m_pSnaccClearance = tmpSnaccClearance;
          }
       }
   }
   catch (SnaccException &e)
   {
      if (tmpSnaccClearance != NULL)
         delete tmpSnaccClearance;
      e.push(STACK_ENTRY);
      throw;
   }

   return((const Clearance *)(m_pSnaccClearance));

} // END OF MEMBER FUNCTION getCaClearance

// getClearance:
// INPUT:  AsnOid &policyId
// OUTPUT: NONE
// RETURN: Clearance
// THIS MEMBER FUNCTION LOOPS THROUGH THE CURRENT EXTENSIONS LOOKING
//   FOR THE CAClearanceConstraints OID.  WHEN FOUND, IT DECODES THE VALUE
//   WHICH SHOULD BE A SEQUENCE OF ATTRIBUTES.  IT THEN SEARCHES FOR A
//   CLEARANCE ATTRIBUTE (id_at_clearance) WHICH ALSO MATCHES THE policyId
//   WHICH WAS PASSED IN (FROM THE USER CERT).  IF A MATCH IS FOUND THEN
//   THE CLEARANCE ATTRIBUTE IS RETURNED.  IF THE Clearance IS NOT
//   PRESENT A NULL POINTER WILL BE RETURNED.
//
const Clearance * ClearanceCert::getClearance(const AsnOid &policyId)
{
   char       errStr[ACL_STR_BUF_LEN];
   bool       done = false;
   Clearance *pSnaccClearance = NULL;

   FUNC("ClearanceCert::getClearance");

   // INITIALIZATION
   errStr[0]='\0';

   // IF the intersected clearances are present get the clearance attribute
   // from there.
   //
   try
   {
 /*      if (this->m_intersectedClearances.size() > 0)
       {
		  ClearanceList::iterator pClearance;
          for (pClearance = m_intersectedClearances.begin();
               ((pClearance != m_intersectedClearances.end()) && (! done));
			      pClearance++)
          {
             if (pClearance->policyId == policyId)
             {
                if (m_pSnaccClearance)
                   delete m_pSnaccClearance;
                m_pSnaccClearance = new Clearance;
                *m_pSnaccClearance = *pClearance;
                done = true;
             }
          }
       }
       else */
       if ((m_pSnaccClearance == NULL ||
           m_pSnaccClearance->policyId != policyId) && exts.pSubjDirAtts != NULL )
       {
          CML::ASN::SubjDirAttributesExtension::iterator i;

          for (i = exts.pSubjDirAtts->begin(); i != exts.pSubjDirAtts->end() && !done; i++)
          {
              if (i->GetType() == CML::ASN::Attribute::Clearance)
              {
                  CML::ASN::ClearanceList::const_iterator k;
                  for (k = i->GetValues().pClearance->begin();
                       k != i->GetValues().pClearance->end() && !done; k++)
                  {
                    if (k->policyId == policyId)
                    {
                       done = true;
                       pSnaccClearance = k->GetSnacc();
                    }
                  }
                  if (done)
                  {
                     if (m_pSnaccClearance != NULL)
                        delete m_pSnaccClearance;
                     m_pSnaccClearance = pSnaccClearance;
                  }
              }
          }
       }
       else if (m_pSnaccClearance != NULL)      // RWC;
           done = true;

       if (! done)
       {
          AsnOid tmpOid(policyId);
          char *pOidStr = tmpOid.GetChar();
          sprintf(errStr, "%s %s %s",
             "Missing Clearance Attribute for\n\t(",
             (char *)pOidStr, ")");
          free(pOidStr);
          throw ACL_EXCEPT(ACL_NULL_POINTER, errStr);
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return((const Clearance *)(m_pSnaccClearance));

} // END OF MEMBER FUNCTION getClearance

// FUNCTION: getDescription
//
// PURPOSE: Display debug information about a ClearanceCert.
//
void ClearanceCert::getDescription(AclString &os) const
{
   CML::ASN::DN  tmpDN(this->getSubjectName());

   os << "\n** Clearance Certificate **:"
      << "\n\tDN: " << (const char *)tmpDN;

   // Display Clearance IDs if present
   //
    bool firstTime = true;

	AsnOidLst::const_iterator pOid;
   const AsnOidLst &oidList = this->getPolicyIdList();
    for (pOid = oidList.begin(); pOid != oidList.end(); pOid++)
    {
        if (firstTime)
        {
        firstTime = false;
        os << "\n\tOID(s):";
        }
        os << " " << (const char *) *pOid;
    }
    os << "\n";
} // END OF MEMBER FUNCTION getDescription

// checkExtensions:
//
void ClearanceCert::checkExtensions(void)
{
   FUNC("ClearanceCert::checkExtensions");

   SNACC::Extensions *pExts = this->exts.GetSnacc();
   
   SNACC::Extension *pExt = NULL;

   // PIERCE: We can probably optimize this by simply looking for 
   //         critical extensions in this->exts.unknownExts
   //
   try
   {
       if (pExts != NULL)
       {
	      /* automatically handle delete of this pointer */
		  std::auto_ptr<SNACC::Extensions> pExtsA(pExts);

		  SNACC::Extensions::iterator pExt;
          for (pExt = pExts->begin(); pExt != pExts->end(); pExt++)
          {
             if ( (pExt->critical != NULL) && *pExt->critical == true)
             {
                if ( ! (
                   (pExt->extnId == id_ce_subjectDirectoryAttributes) ||
                   (pExt->extnId == id_ce_subjectKeyIdentifier) ||
                   (pExt->extnId == id_ce_keyUsage) ||
                   (pExt->extnId == id_ce_privateKeyUsagePeriod) ||
                   (pExt->extnId == id_ce_subjectAltName) ||
                   (pExt->extnId == id_ce_issuerAltName) ||
                   (pExt->extnId == id_ce_basicConstraints) ||
                   (pExt->extnId == id_ce_nameConstraints) ||
                   (pExt->extnId == id_ce_certificatePolicies) ||
                   (pExt->extnId == id_ce_policyMappings) ||
                   (pExt->extnId == id_ce_authorityKeyIdentifier) ||
                   (pExt->extnId == id_ce_policyConstraints)) )
                {
                   AsnOid tmpOid(pExt->extnId);
                   char errStr[ACL_STR_BUF_LEN];
                   errStr[0]='\0';
                   sprintf(errStr, "%s %s %s",
                           "Found Critical unknown extension\n\t(",
                           (const char *)tmpOid, ")");
                   throw ACL_EXCEPT(ACL_CC_EXT_ERROR, errStr);
                }
             }
          }
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

} // END OF MEMBER FUNCTION checkExtensions

void ClearanceCert::intersect(Session *pSession, const CML::ASN::CertificationPath &certPath)
{
   FUNC("ClearanceCert::intersect()");

   AsnOidLst::const_iterator pTmpPolicyId;
   //ClearanceList::iterator pUserClearance;
   Clearance *pUserClearance=new Clearance;
   SNACC::AsnBits *pUserClassList = NULL;

      for(pTmpPolicyId = getPolicyIdList().begin(); pTmpPolicyId != getPolicyIdList().end(); pTmpPolicyId++)
       {
          // Create new Clearance node
          //
          //pUserClearance = m_intersectedClearances.insert(m_intersectedClearances.end(), SNACC::Clearance());

          // Retrieve Clearance attribute from EE and copy it into
          // the new ClearanceList node.
          //
          *pUserClearance = *getClearance(*pTmpPolicyId);

          pUserClassList = this->getClassList();
          if (pUserClearance->securityCategories != NULL)
          {
             // IF securityCategories list contains more than one element
             //    throw an error.
             //
             if (pUserClearance->securityCategories->size() > 1)
             {
                 throw ACL_EXCEPT(ACL_CC_ERROR,
                     "SecurityCategories count > 1");
             }

             // There will be only one securityCategories
             //
			    SecurityCategorySet::iterator ptmpSecCatUser = pUserClearance->securityCategories->begin();

             // ASN.1 DECODE THE SECURITY CATEGORY VALUE
             //
             SSLPrivileges *pTmpSSLPrivsUser = (SSLPrivileges *)ptmpSecCatUser->value.value->Clone();

             // LOOP thru securityCategories SSLPrivileges (NamedTagSetPrivilege)
             // linked list:
             //
			    SSLPrivileges::iterator pSSLUser;
             for(pSSLUser = pTmpSSLPrivsUser->begin(); pSSLUser != pTmpSSLPrivsUser->end(); )
             {
                bool done = false;
                // Traverse tmpCCList to compute the intersection between this user's
                // Clearance attribute and those contained in the issuer list.
                std::list<CML::ASN::CertPair>::const_iterator pTmpCC;
                for (pTmpCC = certPath.caCerts.begin(); pTmpCC != certPath.caCerts.end() && done == false;
                     pTmpCC++)
                {
                   // Get the CA Clearance attribute.
                   ClearanceCert tmpCert(*pTmpCC->forward);
                   const Clearance *pCaClearance = tmpCert.getCaClearance(*pTmpPolicyId);

                   // If the CA's CAConstraints Clearance attribute was not found
                   //
                   if (pCaClearance == NULL)
                   {
                      // The First node in the CA list should be the CA.  It the CA
                      // doesn't have a CAConstraints Clearance attribute throw
                      // an error.
                      //
                      if (pTmpCC == certPath.caCerts.end())
                      {
                         AclString errStr;
                         AsnOid tmpOid(*pTmpPolicyId);
                         errStr << "cAConstraints missing Clearance for "
                                << (const char *) tmpOid << "\n" << "[" << pTmpCC->forward->subject << "] \n";
                         throw ACL_EXCEPT(ACL_CC_ERROR, errStr.str());

                      }

                      // otherwise stop searching CA List.
                      break;
                   }

                   // Compare the two classList bitstrings from pCaClearance
                   // and pUserClearance and make sure that all the bits that
                   // are turned on in pCaClearance are also turned on it
                   // pUserClearance.

                   AsnBits *pCaClassList = tmpCert.getClassList();

                   CAsnBits::And(pUserClassList, *pUserClassList,*pCaClassList);

                   delete pCaClassList;

                   // Traverse CA Clearance tag set's until you find one that
                   // matches the current tag set of this pUserClearance.
                   if (pCaClearance->securityCategories->size() > 1)
                   {
                      throw ACL_EXCEPT(ACL_CC_ERROR,
                          "Too many security_categories error::intersect");
                   }

				       SecurityCategories::iterator ptmpSecCatCA = pCaClearance->securityCategories->begin();

                   if (ptmpSecCatUser->type != ptmpSecCatCA->type)
                   {
                      AclString errStr;
                      AsnOid tmpOid1(ptmpSecCatUser->type);
                      AsnOid tmpOid2(ptmpSecCatCA->type);

                      errStr << "SecurityCategories type mismatch:\n"
                             << "End Entity : " << (const char *) tmpOid1 << "\n"
                             << "CA : " << (const char *) tmpOid2 << "\n";

                      throw ACL_EXCEPT(ACL_CC_ERROR, errStr.str());
                   }

                   //pTmpSSLPrivsCA = new SSLPrivileges;
                   SSLPrivileges *pTmpSSLPrivsCA = (SSLPrivileges *) ptmpSecCatCA->value.value->Clone();
                   // THE TYPE WILL BE id_missiSecurityCategories
                   // THE VALUE WILL CONTAIN THE ENCODED SSL PRIVILEGES
                   // ASN.1 DECODE THE SECURITY CATEGORY VALUE
               
                   /*if (decodeAny(*pTmpSSLPrivsCA, ptmpSecCatCA->value) != true)
                   {
                      throw ACL_EXCEPT(ACL_DECODE_ERROR,
                                "Error decoding SSL Privileges");
                   }*/

                   // LOOP thru securityCategories SSLPrivileges
                   // (NamedTagSetPrivilege) linked list:
				       SSLPrivileges::iterator pSSLCA;
                   bool tagSetFlag = false;
                   for(pSSLCA = pTmpSSLPrivsCA->begin(); pSSLCA != pTmpSSLPrivsCA->end() && !done; pSSLCA++)
                   {
                      // Compare tagset names
                      if (pSSLUser->tagSetName == pSSLCA->tagSetName)
                      {
                         tagSetFlag = true;

                         // Loop thru User SecurityTagPrivileges linked list:
						       SecurityTagPrivileges::iterator pSecTagPrivUser;
                         pSecTagPrivUser = pSSLUser->securityTagPrivileges.begin();
                         while(pSecTagPrivUser != pSSLUser->securityTagPrivileges.end())
                         {
                            // Loop thru CA SecurityTagPrivileges linked list:
                            bool tagTypeFlag = false;
                            bool done2 = false;

							       SecurityTagPrivileges::iterator pSecTagPrivCA;
                            for(pSecTagPrivCA = pSSLCA->securityTagPrivileges.begin();
                                (pSecTagPrivCA != pSSLCA->securityTagPrivileges.end() && done2 == false);
                                pSecTagPrivCA++)
                            {
                               if (pSecTagPrivUser->choiceId == pSecTagPrivCA->choiceId)
                               {
                                  tagTypeFlag = true;
                                  if (pSecTagPrivCA->choiceId ==
                                     SecurityTagPrivilege::restrictivebitMapCid)
                                  {
                                     CAsnBits::And(pSecTagPrivCA->restrictivebitMap,
                                                   *pSecTagPrivCA->restrictivebitMap,
                                                   *pSecTagPrivUser->restrictivebitMap);
                                  }
                                  if (pSecTagPrivCA->choiceId ==
                                     SecurityTagPrivilege::permissivebitMapCid)
                                  {
                                     CAsnBits::And(pSecTagPrivCA->permissivebitMap,
                                                   *pSecTagPrivCA->permissivebitMap,
                                                   *pSecTagPrivUser->permissivebitMap);
                                  }
                                  if (pSecTagPrivCA->choiceId ==
                                     SecurityTagPrivilege::enumeratedAttributesCid)
                                  {
                                     CSecurityTag::enumAnd(pSecTagPrivCA->enumeratedAttributes,
                                                   *pSecTagPrivCA->enumeratedAttributes,
                                                   *pSecTagPrivUser->enumeratedAttributes);
                                  }
                                  else
                                  {
                                     throw ACL_EXCEPT(ACL_CC_ERROR,
                                          "Invalid tag type.");
                                  }
                               }
                               if (tagTypeFlag == false)
                               {  // NULL out tagtype in user clearance
                                   pSecTagPrivUser = pSSLUser->securityTagPrivileges.erase(pSecTagPrivUser); //RemoveCurrFromList();
                                  // move to next tagType
                                  done2 = true;
                               }
                            }
                            if (!done2)
                            {
                               pSecTagPrivUser++;
                            }
                         }
                      }
                      if (tagSetFlag == false)
                      {
                         // NULL out tagset in user clearance
                         pSSLUser = pTmpSSLPrivsUser->erase(pSSLUser); // RemoveCurrFromList
                         // move to next tagset
                         done = true;
                      }
                   }
                   if (pTmpSSLPrivsCA)
                      delete pTmpSSLPrivsCA;
                }
                if (!done)
                    pSSLUser++;
             }
            if (pTmpSSLPrivsUser)
               delete pTmpSSLPrivsUser;
          }
       }

       if (pUserClassList)
       {
          delete pUserClassList;
       }

}

// operator=:
//
ClearanceCert & ClearanceCert::operator= (const ClearanceCert &that)
{
   clear();
   this->Cacheable::operator =(that);
   this->ClearanceInfo::operator =(that);
   this->Cert::operator=(that);

   return (*this);
} // END OF OPERATOR OVERLOAD =

// matches:
//
bool ClearanceCert::matches(const MatchInfo &matchInfo) const
{
   FUNC("ClearanceCert::matches");

   int matchCount = 0;
   try
   {
       const CML::ASN::DN *pIssuerDN = matchInfo.getIssuerDN();
       const CML::ASN::DN *pSubjectDN = matchInfo.getSubjectDN();
       const SNACC::AsnOcts *pSubjectKeyId = matchInfo.getSubjectKeyId();
       const SNACC::AsnOcts *pAuthorityKeyId = matchInfo.getAuthorityKeyId();

       // Match on issuerDN
       //
       if (pIssuerDN != NULL)
       {
          if (*pIssuerDN == issuer )

          {
             matchCount++;
          }
          else
          {
             return false;
          }
       }

       // Match on subjectDN if present
       //
       if (pSubjectDN != NULL)
       {
          if (*pSubjectDN == subject)
          {
             matchCount++;
          }
          else
          {
             return false;
          }
       }

       // IF Subject key identifier was supplied as match criteria look for it.
       //
       if (pSubjectKeyId != NULL)
       {
          if (exts.pSubjKeyID)
          {
              if (*exts.pSubjKeyID == *pSubjectKeyId)
				  matchCount++;
          }

       }

       // IF Authority key identifier was supplied as match criteria look for it.
       //
       if (pAuthorityKeyId != NULL)
       {
          if (exts.pAuthKeyID)
          {
             if (exts.pAuthKeyID->keyID != NULL)
             {
                 if (*exts.pAuthKeyID->keyID == *pAuthorityKeyId)
                    matchCount++;
             }
          }
       }

       // For a certificate to match at least TWO matching items must be present.
       //
       if (matchCount >= 1) //2) RWC;MODIFIED to 1 with the assumption that if
                            //   RWC; the user specified multiple entries, we 
                            //   RWC; would match all possible or error.
       {
          return true;
       }
       else
       {
          return false;
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION matches

// FUNCTION:: getIssuerInfo()
// PURPOSE: load matchInfo with information about the issuer of this object.
//
void ClearanceCert::getIssuerInfo(MatchInfo &matchInfo)
{
   FUNC("ClearanceCert::getIssuerInfo()");

   try
   {
       matchInfo.setSubjectDN(this->getIssuerName());
       if (this->exts.pAuthKeyID != NULL && this->exts.pAuthKeyID->keyID != NULL)
       {
          matchInfo.setSubjectKeyId(*this->exts.pAuthKeyID->keyID);
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
}

// checkValidity:
//
bool ClearanceCert::checkValidity(void)
{
   CML::ASN::Time currTime;

   return (validity.IsValid(currTime));
} // END OF MEMBER FUNCTION checkValidity



void ClearanceCert::clear(void)
{
   m_policyIdList.erase(m_policyIdList.begin(), m_policyIdList.end());
}

_END_NAMESPACE_ACL

// EOF aclclearcert.cpp
