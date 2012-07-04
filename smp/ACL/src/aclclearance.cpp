//////////////////////////////////////////////////////////////////////////////
// aclclearance.cpp
// These routines support the ClearanceInfo Class
// CONSTRUCTOR(s):
//   ClearanceInfo(void)
// DESTRUCTOR:
//   ~ClearanceInfo()
// MEMBER FUNCTIONS:
//   acdf(Session *s, SPIF &spif, SecurityLabel &label)
//   check(Session *s, SPIF &spif, SecurityLabel &label)
//   getSSLPrivs(SPIF &spif)
//   checkTagSetPriv(NamedTagSet &tagSet, NamedTagSetPrivilege &tagPriv,
//                   bool enumRestrictive)
//   checkSSL(StandardSecurityLabel &ssl, SPIF &spif)
//   getClassList(void)
//   operator=(ClearanceInfo &that)
//   getPolicyId(void)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR:
//
ClearanceInfo::ClearanceInfo(void)
{
   m_pSnaccClearance = NULL;
} // END OF CONSTRUCTOR

// DESTRUCTOR:
//
ClearanceInfo::~ClearanceInfo()
{
   if (m_pSnaccClearance != NULL)
   {
      delete m_pSnaccClearance;
      m_pSnaccClearance = NULL;
   }
} // END OF DESTRUCTOR


// acdf:
//
bool ClearanceInfo::acdf(Session *s, SPIF &spif, SecurityLabel &label)
{
   SPIF    *pTmpSPIF=NULL;
   char     errStr[ACL_STR_BUF_LEN];
   SecurityLabel   *pLbl = NULL;

   FUNC("ClearanceInfo::acdf");

   // INITIALIZATION
   errStr[0]='\0';

   pTmpSPIF = &spif;

   pLbl = &label;
   try
   {
       // EXTRACT THE SECURITY POLICY FROM THE SECURITY LABEL
       AsnOid tmpSecLabelPolicyId = pLbl->security_policy_identifier;

       if (m_pSnaccClearance == NULL)
             throw ACL_EXCEPT(ACL_AC_CHECK_ERROR, "no SnaccClearance present!");
       // EXTRACT THE SECURITY POLICY FROM THIS ClearanceInfo
       AsnOid tmpClearancePolicyId = m_pSnaccClearance->policyId;

       // EXTRACT THE SECURITY POLICY FROM THE SPIF
       const AsnOid tmpSPIFPolicyId = pTmpSPIF->getPolicyId();

       // Check the SECURITY LABEL/ClearanceInfo policy Id's
       if (tmpSecLabelPolicyId != tmpClearancePolicyId)
       {
          // Init remotePolicyId ref to tmpClearancePolicyId
          // this is the Outgoing label case.
          AsnOid remotePolicyId = tmpClearancePolicyId;

          // IF this is an OutgoingLabel the remotePolicyId is the
          // policy identifier from the clearance attribute.
          // ELSE if this is an IncomingLabel the remotePolicyId is
          // the security policy identifier asserted in the label.
          //
          if (label.isIncoming())
             remotePolicyId = pLbl->security_policy_identifier;

          // If equivalency mapping is enabled try to translate 
          // the label IF this is an INCOMING label.

          if (s->usingEquivalencies())
          {
             pLbl = label.equivLabels.translate(label, spif, remotePolicyId);
          }
          else
          {
             // 1. IF SECURITY POLICY IN ClearanceInfo FROM AC/
             //     ClearanceCertificate DOES NOT MATCH SECURITY
             //    POLICY ID IN SECURITY LABEL THROW AN ERROR
             sprintf(errStr, "%s (%s) %s (%s) %s",
                     "Security Label Policy ID",
                     (const char *) tmpSecLabelPolicyId,
                     "\n\tdoes not match ClearanceInfo Policy ID",
                     (const char *) tmpClearancePolicyId,
                     "\n\tin ClearanceInfo::acdf");
             throw ACL_EXCEPT(ACL_AC_AC_ERROR, errStr);
          }
       }

       // IF label->sec_class => 0 AND subj prbac->class1 bit
       // position indicated by sec_label->sec_class is not set to 1 (on) THEN 
       // user does not have appropriate Clearance ClassList authorization.  Throw
       // an error.
       //
       AsnBits *classList = getClassList();

       if (pLbl->security_classification != NULL)
       {
          if (*pLbl->security_classification >= 0)
          {
             if (CAsnBits::checkBit(*classList, *pLbl->security_classification)==false)
             {
               // Return INVALID_USER_CLEARANCE error code.
               //
               sprintf(errStr,"Invalid user clearance (%d)\n",
                       (int) *label.security_classification);
               delete classList;
               throw ACL_EXCEPT(ACL_AC_CHECK_ERROR, errStr);
             }
          }
          else
          {
             delete classList;
             throw ACL_EXCEPT(ACL_AC_CHECK_ERROR,
                "Security Classification is negative");
          }
       }
       delete classList;

       if (pLbl->security_categories != NULL)
       {
          // 3. Call SecurityLabel Function to check the security tag for
          // redundancy and also check to make sure the securityLevel is
          // equivalent to the security classification
          pLbl->tagAndLevelCheck();

          // 4. Call ClearanceInfo::checkSSL() pass it the spif and
          //    the result of label.getSSL()
          this->checkSSL(pLbl->getSSL(), *pTmpSPIF);
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return true;

} // END OF MEMBER FUNCTION acdf

// Low level Clearance check against spif and label.  Meant for applications that
// are checking at the Clearance level.  No assumptions are made as to what the
// clearance was contained in (i.e. AttributeCertificate, or V3Certficate).
//
bool ClearanceInfo::check(Session *s, SPIF &spif, SecurityLabel &label)
{
   FUNC("ClearanceInfo::check");

   try
   {
       // PARAMETER CHECKS
       if (s == NULL)
       {
          throw ACL_EXCEPT(ACL_NULL_POINTER, "Session parameter is NULL");
       }

       if (spif.isValid() == false)
       {
          MatchInfo mi;
          spif.getIssuerInfo(mi);
          spif.getLatest(s,mi);
       }

       acdf(s, spif, label);
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   return true;
} // END OF MEMBER FUNCTION check

// getSSLPrivs:
// INPUT:  SPIF &spif
// OUTPUT: NONE
// RETURN: SLLPrivileges *
// THIS MEMBER FUNCTION WILL EXTRACT THE SSL PRIVILEGES OUT OF THE CLEARANCE
//   ATTRIBUTE.
//
SSLPrivileges *ClearanceInfo::getSSLPrivs(SPIF &spif)
{
   SSLPrivileges *pTmpSSLPrivs=NULL;
   char           errStr[ACL_STR_BUF_LEN];

   FUNC("ClearanceInfo::getSSLPrivs");

   // INITIALIZATION
   errStr[0]='\0';

   try
   {
       if (this->m_pSnaccClearance->securityCategories == NULL)
          return (NULL);

	   SecurityCategorySet::iterator pTmpSecCat;
       if (this->m_pSnaccClearance->securityCategories->size() == 1)
       {
          pTmpSecCat = this->m_pSnaccClearance->securityCategories->begin();

          // IF AC security_categories prbacId != SPIF privilegeID THEN
          // (MissiSecurityCategories is not the SecurityCategory ANY field)
          // return RBAC_ID error.
          if (pTmpSecCat->type != spif.spiftoSign.privilegeID)
          {
              char errStr[ACL_STR_BUF_LEN];
              AsnOid tmpOid1(pTmpSecCat->type);
              AsnOid tmpOid2(spif.spiftoSign.privilegeID);
              sprintf(errStr,
                      "%s\n\tsecurity_categories prbacId=%s\n\tSPIF privilegeID=%s",
                      "RBAC_ID error:", (const char *) tmpOid1, (const char *) tmpOid2);
              // DO ANY ERROR HANDLING
              throw ACL_EXCEPT(ACL_AC_CHECK_ERROR, errStr);
          }
            
          pTmpSSLPrivs = (SSLPrivileges *) pTmpSecCat->value.value->Clone();
      
       } // IF THERE IS MORE THAN ONE THIS IS AN ERROR
       else if (this->m_pSnaccClearance->securityCategories->size() > 1)
       {
          sprintf(errStr, "%s %d %s\n\t%s\n\t%s %s %s %s\n",
                  "More than 1 (",
                  this->m_pSnaccClearance->securityCategories->size(),
                  ") Security Category detected",
                  "in Clearance Attribute for SPIF DN",
                  (const char *) spif.getIssuerName(), "and\n\tPolicy ID",
                  (const char *) this->m_pSnaccClearance->policyId,
                  "in ClearanceInfo::getSSLPrivs()");
          throw ACL_EXCEPT(ACL_SEC_CAT_ERROR, errStr);
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return(pTmpSSLPrivs);

} // END OF MEMBER FUNCTION getSSLPrivs

// checkTagSetPriv:
// INPUT:  NamedTagSet & (FROM THE SECURITY LABEL)
//         NamedTagSetPrivilege & (FROM THE AC CLEARANCE ATTRIBUTE)
//         enumRestrictive & (FROM THE SPIF - ONLY FOR ENUMERATED ATTRIBUTES)
// OUTPUT: NONE
// RETURN: true/false
// THIS MEMBER FUNCTION WILL COMPARE EACH OF THE PASSED TagSet.securityTags
//    TO THE tagPriv.securityTagPrivileges.  WHEN THE choiceId MATCH COMPARE
//    THE APPROPRIATE DATA MEMBERS.  NOTE: THE Security Tag CONTAINS A
//    freeFormFieldCid DATA MEMBER WHICH THE Security Tag Privilege DOES NOT
//    WE ARE IGNORING THIS DATA IF IT EXISTS.
//
bool ClearanceInfo::checkTagSetPriv(const NamedTagSet &tagSet,
                                    const NamedTagSetPrivilege &tagPriv,
                                    bool enumRestrictive)
{
   bool                  bResult=false;
   //const SecurityTag          *pTmpSSLSecTag=NULL;    // Security Tag from
                                                // Security Label
   SecurityTagPrivilege *pTmpACSecTagPriv=NULL; // Security Tag Privilege
                                                // from AC/ClearanceCertificate
                                                // Clearance Attribute
   char                  errStr[ACL_STR_BUF_LEN];
   char                  missingValue[80];
   int                   missingRestrictiveValue = -1;
   int                   missingRestrictiveEnumValue = -1;

   FUNC("ClearanceInfo::checkTagSetPriv");

   // INITIALIZATION
   errStr[0]='\0';

   try
   {
       // Step through the list of Security Tags from the Security Label
	   SNACC::SecurityTags::const_iterator pTmpSSLSecTag;
	   for (pTmpSSLSecTag = tagSet.securityTags.begin(); pTmpSSLSecTag != tagSet.securityTags.end(); 
		   pTmpSSLSecTag++)
       {
          // EACH Security Tag MAY BE ANY OF 4 TYPES (restrictivebitMapCid,
          // enumeratedAttributesCid, permissivebitMapCid or freeFormFieldCid)
          // ONLY THE FIRST THREE OF THESE COULD EXIST (NOT freeFormFieldCid)
          // IN THE Security Tag Privilege FROM AC/ClearanceCertificate
          // CLEARANCE ATTRIBUTE INGORE ANY freeFormFieldCid TYPE Security Tag
          if (pTmpSSLSecTag->choiceId != SecurityTag::freeFormFieldCid)
          {
             long lTagPrivFound=false;
             // STEP THROUGH THE LIST OF Security Tag
             // Privileges FROM AC/ClearanceCertificate CLEARANCE ATTRIBUTE

			 SNACC::SecurityTagPrivileges::const_iterator pTmpACSecTagPriv;
             for(pTmpACSecTagPriv = tagPriv.securityTagPrivileges.begin();
                 pTmpACSecTagPriv != tagPriv.securityTagPrivileges.end();
                 pTmpACSecTagPriv++)
             {
                // COMPARE THE TYPES
                if ((int)pTmpSSLSecTag->choiceId == (int)pTmpACSecTagPriv->choiceId)
                {
                   missingRestrictiveValue = -1;
                   missingRestrictiveEnumValue = 0;
                   bResult = false;
                   // IF A MATCH IS FOUND CALL THE APPROPRIATE COMPARISON
                   switch (pTmpSSLSecTag->choiceId)
                   {
                   case SecurityTag::restrictivebitMapCid:
                      // CALL restrictiveBitMapCmp() FUNCTION
                      {
                         missingRestrictiveValue = CSecurityTag::
                            restrictiveCheck(*pTmpACSecTagPriv->restrictivebitMap,
                               pTmpSSLSecTag->restrictivebitMap->attributeFlags);
                         if (missingRestrictiveValue == -1)
                           lTagPrivFound = true;
                      }
                      break;
                   case SecurityTag::enumeratedAttributesCid:
                      // CALL enumeratedAttributesCmp() FUNCTION
                      {
                         missingRestrictiveEnumValue = CSecurityTag::
                            enumeratedAttributesCheck(*pTmpSSLSecTag->
                               enumeratedAttributes,
                            *pTmpACSecTagPriv->enumeratedAttributes,
                            enumRestrictive);
                         if (missingRestrictiveEnumValue == 0)
                           lTagPrivFound = true;
                      }
                      break;
                   case SecurityTag::permissivebitMapCid:
                      // CALL permissiveBitMapCmp() FUNCTION
                      {
                         bResult = CSecurityTag::
                            permissiveCheck(*pTmpACSecTagPriv->permissivebitMap,
                            pTmpSSLSecTag->permissivebitMap->attributeFlags);
                         if (bResult == true)
                            lTagPrivFound = true;
                      }
                      break;
                   }
                   break; // tagtype was found break out of for loop
                }
             }
             if (lTagPrivFound == false)
             {
                AsnOid tmpOid2(tagPriv.tagSetName);
                // DID NOT FIND CORRESPONDING SecurityTagPrivilege
                // CREATE THE APPROPRIATE ERROR STRING (FILLED IN AC/ClearanceCert)
                switch (pTmpSSLSecTag->choiceId)
                {
                case SecurityTag::restrictivebitMapCid:
                   {
                      sprintf(errStr, "%s %s %s\n",
                              "Missing Restrictive SecurityTagPrivilege",
                              "\n\tfor TagName", (const char *)tmpOid2);
                      if (missingRestrictiveValue >= 0)
                      {
                         sprintf(missingValue,"\n\tmissing bit position %d\n",
                            missingRestrictiveValue);
                         strcat(errStr, missingValue);
                      }
                   }
                   break;
                case SecurityTag::enumeratedAttributesCid:
                   {
                      sprintf(errStr, "%s %s %s\n",
                              "Missing Enumerated SecurityTagPrivilege",
                              "\n\tfor TagName", (const char *)tmpOid2);
                      if (missingRestrictiveEnumValue > 0)
                      {
                         sprintf(missingValue,"\n\tmissing attribute 0x%04X\n",
                            missingRestrictiveEnumValue);
                         strcat(errStr, missingValue);
                      }
                   }
                   break;
                case SecurityTag::permissivebitMapCid:
                   {
                      sprintf(errStr, "%s %s %s\n",
                              "Missing Permissive SecurityTagPrivilege",
                              "\n\tfor TagName", (const char *)tmpOid2);
                   }
                   break;
                }
                throw ACL_EXCEPT(ACL_SEC_TAG_ERROR, errStr);
             }
          }
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   return(bResult);

} // END OF MEMBER FUNCTION checkTagSetPriv

// checkSSL:
// INPUT:  StandardSecurityLabel & (FROM THE SECURITY LABEL),
//         SPIF & (THE SPIF)
// OUTPUT: NONE
// RETURN: true/false
//
bool ClearanceInfo::checkSSL(const StandardSecurityLabel &ssl, SPIF &spif)
{
   StandardSecurityLabel::const_iterator pTagSet;
   SSLPrivileges *pTmpSSLprivs = this->getSSLPrivs(spif);
   bool found = false;
   char errStr[256];

   FUNC("ClearanceInfo::checkSSL");

   // Make sure the SecurityCategories type matches the privilegeID 
   // in the SPIF
   try
   {
       if (this->m_pSnaccClearance->securityCategories->begin()->type !=
          spif.spiftoSign.privilegeID)
       {
          AclString errStr;
          AsnOid tmpOid1(this->m_pSnaccClearance->securityCategories->begin()->type);
          AsnOid tmpOid2(spif.spiftoSign.privilegeID);
          errStr << "End Entity Clearance SecurityCategories type "
                 << "doesn't match SPIF's privilegeID:\n"
                 << "SPIF value : " << (const char *) tmpOid2 << "\n"
                 << "End Entity value : " << (const char *) tmpOid1;
          throw ACL_EXCEPT(ACL_SEC_CAT_ERROR,errStr.str());

       }
       // LOOP THROUGH EACH NAMED TAG SET IN THE STANDARD SECURITY LABEL
       for(pTagSet = ssl.begin(); pTagSet != ssl.end(); pTagSet++)
       {
          found = false;

		  SSLPrivileges::const_iterator pTagSetPriv;

          if (pTmpSSLprivs != NULL)
          {
             // LOOP THROUGH EACH NAMED TAG SET PRIVILEGE IN THE SSL PRIVILEGES
             for (pTagSetPriv = pTmpSSLprivs->begin(); pTagSetPriv != pTmpSSLprivs->end();
                  pTagSetPriv++)
             {
                // WHEN THE Tag Set Names OF EACH MATCH, CHECK THE PRIVILEGES
                if (pTagSetPriv->tagSetName == pTagSet->tagSetName)
                {
                   found = true;
                   checkTagSetPriv(*pTagSet, *pTagSetPriv,
                      spif.isEnumRestrictive(pTagSetPriv->tagSetName));
                }
             }
          }
          // if the tag set name in the label was not found in the Clearance
          // and there was something asserted in that tag set name then
          // return Tag Set Not Found error.
          //
          if (! found)
          {
             AsnBits     *pTmpBits = NULL;
             bool         error = false;
			 
			 SNACC::SecurityTags::const_iterator pSecTag;

             for (pSecTag = pTagSet->securityTags.begin();
                  (pSecTag != pTagSet->securityTags.end() && ! error);
                  pSecTag++)
             {
                pTmpBits = NULL;

                switch(pSecTag->choiceId)
                {
                   case (SecurityTag::restrictivebitMapCid):
                      {
                         pTmpBits = &pSecTag->restrictivebitMap->attributeFlags;
                         for (size_t i = 0;
                              i < (size_t)(pTmpBits->BitLen()) && ! error; i++)
                            if (CAsnBits::checkBit(*pTmpBits, i))
                               error = true;
                         break;
                      }
                   case (SecurityTag::permissivebitMapCid):
                      {
                         pTmpBits = &pSecTag->permissivebitMap->attributeFlags;
                         for (size_t i = 0;
                              i < (size_t)(pTmpBits->BitLen()) && ! error; i++)
                            if (CAsnBits::checkBit(*pTmpBits, i))
                               error = true;
                         break;
                      }
                   case (SecurityTag::enumeratedAttributesCid):
                      {
                         if (pSecTag->enumeratedAttributes->
                                 attributeFlags.size() > 0)
                            error = true;
                         break;
                      }
                }
             }
             // IF an attribute flag contained a value then return an
             // error.
             if (error)
             {
                AsnOid tmpOid(pTagSet->tagSetName);
                sprintf(errStr,
                        "Tag Set Name (%s)\n\tnot found", (const char *)tmpOid);
                throw ACL_EXCEPT(ACL_AC_CHECK_ERROR, errStr);
             }
          }
       }
       delete pTmpSSLprivs;
   }
   catch (SnaccException &e)
   {
      delete pTmpSSLprivs;
      e.push(STACK_ENTRY);
      throw;
   }
   return(true);

} // END OF MEMBER FUNCTION checkSSL

// getClassList:
//
AsnBits *ClearanceInfo::getClassList(void)
{
   char      errStr[ACL_STR_BUF_LEN];
   AsnBits   *retVal=NULL;
   Clearance tmpSnaccClearance;

   FUNC("ClearanceInfo::getClassList");

   // INITIALIZATION
   errStr[0]='\0';
   try
   {
       retVal = new AsnBits;
       if ((m_pSnaccClearance != NULL) && 
		   (m_pSnaccClearance->classList != NULL) &&
           (!m_pSnaccClearance->classList->IsEmpty()))

       {
          *retVal = *m_pSnaccClearance->classList;
       }
       else
       {
          retVal->Set(8);    // set length to 8 bits
          retVal->SetBit(1); // set unclassified bit
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return retVal;
} // END OF MEMBER FUNCTION getClassList()

// operator =:
//
ClearanceInfo & ClearanceInfo::operator=(const ClearanceInfo &that)
{
   // First delete all members
   if (this->m_pSnaccClearance != NULL)
   {
      delete this->m_pSnaccClearance;
      this->m_pSnaccClearance = NULL;
   }

   // Now copy members from that
   //
   if (that.m_pSnaccClearance != NULL)
   {
      this->m_pSnaccClearance = new Clearance;
      *(this->m_pSnaccClearance) = *(that.m_pSnaccClearance);
   }

   return(*this);
} // END OF MEMBER FUNCTION operator =

// getPolicyId:
//
AsnOid &ClearanceInfo::getPolicyId(void)
{
   FUNC("ClearanceInfo::getPolicyId");
   try
   {
       if ((this->m_pSnaccClearance != NULL)
        && (this->m_pSnaccClearance->policyId.Len() > 2))
       {
           return(m_pSnaccClearance->policyId);
       }
       else
       {
          throw ACL_EXCEPT(ACL_NULL_POINTER, "Missing Clearance Attribute");
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

} // END OF MEMBER FUNCTION getPolicyId()

_END_NAMESPACE_ACL

// EOF aclclearance.cpp

