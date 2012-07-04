//////////////////////////////////////////////////////////////////////////////
// acllabel.cpp
// These routines support the SecurityLabel Class
// CONSTRUCTOR(s):
//   SecurityLabel(void)
//   SecurityLabel(const CML::ASN::Bytes &b)
//   SecurityLabel(const ESSSecurityLabel &secLbl)
// DESTRUCTOR:
//   ~SecurityLabel(void)
// MEMBER FUNCTIONS:
//   operator=(const SecurityLabel &that)
//   getSSL(void)
//   FindTagSet(SNACC::StandardSecurityLabel *pSSL,
//   check(Session *s, SPIF &spif)
//   requiredCatCheck(RequiredCategories &reqCat, SPIF &spif,
//                    const SNACC::TagCategories *pSpifTagCat)
//   CreateErrorStringForLabel(char *errStrOut,
//                             const char *pszIncomingErrorDescription,
//                             const long ltagType, const long labelcert,
//                             const SPIF &spif, const AsnOid SNACCOid,
//                             const char *pszOptionalTagTypeDescriptionIN,
//                             const SNACC::TagCategories *pSpifTagCat)
//   excludedCatCheck(OptionalCategoryDataSeqOf &excCat, SPIF &spif)
//   findCat(SNACC::AsnOid &tagsetname, SNACC::TagTypeValue &tagtype,
//           SNACC::AsnInt &labelandcert)
//   tagAndLevelCheck(void)
//   isEquivApplicable(int applied)
//   getClassification(void)
//   getLabelString(const SPIF &spif)
//   getPolicyId(void)
//   setSSL(StandardSecurityLabel *pNewTagSets)
//   freeFormOnlyCheck(void)
//   isIncoming(void)
//   isOutgoing(void)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR:
//
SecurityLabel::SecurityLabel(void)
{
   // INITIALIZE DATA MEMBERS
   m_pSNACCTmpSSL = NULL;
   m_obsAccept = false;
} // END OF CONSTRUCTOR

// ALTERNATE CONSTRUCTOR:
//
SecurityLabel::SecurityLabel(const CML::ASN::Bytes &b)
{
   FUNC("SecurityLabel::SecurityLabel(const CML::ASN::Bytes &b)");

   m_pSNACCTmpSSL = NULL;
   m_obsAccept = false;

   try
   {
      b.Decode(*this);
   }
   catch(...)
   {
      throw ACL_EXCEPT(ACL_DECODE_ERROR,"Error decoding Security Label");
   }
} // END OF ALTERNATE CONSTRUCTOR

// ALTERNATE CONSTRUCTOR:
//
SecurityLabel::SecurityLabel(const ESSSecurityLabel &secLbl)
{
  m_pSNACCTmpSSL = NULL;
  m_obsAccept = false;
  ESSSecurityLabel::operator=(secLbl);
} // END OF ALTERNATE CONSTRUCTOR

// DESTRUCTOR:
//
SecurityLabel::~SecurityLabel(void)
{
   if (m_pSNACCTmpSSL != NULL)
   {
      delete m_pSNACCTmpSSL;
   }
} // END OF CONSTRUCTOR

// operator =:
//
SecurityLabel & SecurityLabel::operator=(const SecurityLabel &that)
{
   this->ESSSecurityLabel::operator=(that);
   m_pSNACCTmpSSL = NULL;
   return (*this);
} // END OF OPERATOR OVERLOAD =

// getSSL:
//
const StandardSecurityLabel & SecurityLabel::getSSL(void)
{
   StandardSecurityLabel::iterator pNewSecLblNTS;
   SecurityTags::iterator  pNewSecLblSecTag;

   FUNC("SecurityLabel::getSSL");
   try
   {
      // if we've already called getSSL() just return the previous result.
      //
      if (m_pSNACCTmpSSL != NULL)
      {
         return *m_pSNACCTmpSSL;
      }

      // check for NULL security_categories
      if (this->security_categories == NULL)
      {
         throw (EmptyList("Empty Security Categories List"));
      }

      SecurityCategories::iterator pTmpSecCat = this->security_categories->begin();

      // Check for MISSISecurityCategories.  If it is present the
      // security category count must be 1 and the type set to id_missiSecurityCategories.
      //
      if ((this->security_categories->size() == 1) &&
          (pTmpSecCat->type == id_missiSecurityCategories))
      {
         if (pTmpSecCat->value.value)
         {
            MissiSecurityCategories *pMSC=(MissiSecurityCategories *) pTmpSecCat->value.value;
            m_pSNACCTmpSSL = new StandardSecurityLabel;
            *m_pSNACCTmpSSL = *pMSC->prbacSecurityCategories;
            return(*m_pSNACCTmpSSL);
         }
         else if (pTmpSecCat->value.anyBuf)
         {
            SNACC::AsnLen bytesDecoded;
            m_pSNACCTmpSSL = new StandardSecurityLabel;
            m_pSNACCTmpSSL->BDec(*pTmpSecCat->value.anyBuf, bytesDecoded);
            return(*m_pSNACCTmpSSL);
         }
         else
         {
            char errStr[ACL_STR_BUF_LEN];
            errStr[0] = '\0';
            sprintf(&errStr[0], "Security category error.%s",
               "\n\tValue is NULL.");
            throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, &errStr[0]);
         }
      }

      // MISSI security categories were not found in the first security category
      // continue looking for NATO security categories.  If a MISSI security category
      // is found among them throw an exception.
      //

      m_pSNACCTmpSSL = new StandardSecurityLabel;

      for (pTmpSecCat = this->security_categories->begin();
           pTmpSecCat != this->security_categories->end();
           pTmpSecCat++)
      {
         // IF a MISSI Security Category is found throw an exception
         //
         if (pTmpSecCat->type == id_missiSecurityCategories)
         {
            char errStr[ACL_STR_BUF_LEN];
            errStr[0] = '\0';
            sprintf(&errStr[0], "Security category error.%s",
               "\n\tMissi and Nato security categories can not be together.");
            throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, &errStr[0]);
         }
         // ELSE IF a NATO RestrictiveTag
         //
         else if (pTmpSecCat->type == acl_id_restrictiveBitMap)
         {
            RestrictiveTag *pResTag = (RestrictiveTag *)pTmpSecCat->value.value;

            // Find a tagSet with a tagSetName of RestrictiveTag's tagName.  If found
            // append value to tagSet.  Otherwise create the tagSet then add the value.
            pNewSecLblNTS = FindTagSet(m_pSNACCTmpSSL, pResTag->tagName);

            // Tag set was not found so create it.
            if (pNewSecLblNTS == m_pSNACCTmpSSL->end())
            {
               pNewSecLblNTS = m_pSNACCTmpSSL->append();
            }

            // Search through existing pNewSecLblNTS to make sure there is not
            // already a RestrictiveTag in this tagSet.
            SecurityTags::iterator iSecTag;
            for (iSecTag = pNewSecLblNTS->securityTags.begin();
                 iSecTag != pNewSecLblNTS->securityTags.end(); iSecTag)
            {
               if (iSecTag->choiceId == SecurityTag::restrictivebitMapCid)
               {
                  AclString errStr;
                  errStr << "Restrictive tag already exists in tagset: \n"
                         << "   [" << pResTag->tagName << "] \n";
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr.str());
               }
            }

            pNewSecLblSecTag = pNewSecLblNTS->securityTags.append();
            pNewSecLblSecTag->choiceId = SecurityTag::restrictivebitMapCid;
            pNewSecLblSecTag->restrictivebitMap = new SecurityTagSeq;
            pNewSecLblSecTag->restrictivebitMap->attributeFlags = pResTag->attributeFlags;
         }
         else if (pTmpSecCat->type == acl_id_enumeratedAttributes)
         {
            EnumeratedTag *pEnumTag = (EnumeratedTag *)pTmpSecCat->value.value;
            pNewSecLblNTS = FindTagSet(m_pSNACCTmpSSL, pEnumTag->tagName);

            if (pNewSecLblNTS == m_pSNACCTmpSSL->end())
            {
               pNewSecLblNTS = m_pSNACCTmpSSL->append();
            }

            // Search through existing pNewSecLblNTS to make sure there is not
            // already an EnumeratedTag in this tagSet.
            SecurityTags::iterator iSecTag;
            for (iSecTag = pNewSecLblNTS->securityTags.begin();
                 iSecTag != pNewSecLblNTS->securityTags.end();
                 iSecTag++)
            {
               if (iSecTag->choiceId == SecurityTag::enumeratedAttributesCid)
               {
                  AclString errStr;
                  errStr << "Enumerated tag already exists in tagset: \n"
                         << "   [" << pEnumTag->tagName << "] \n";
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr.str());
               }
            }

            pNewSecLblSecTag = pNewSecLblNTS->securityTags.append();
            pNewSecLblSecTag->choiceId = SecurityTag::enumeratedAttributesCid;
            pNewSecLblSecTag->enumeratedAttributes = new SecurityTagSeq1;
            EnumeratedTagSetOf::iterator iAttr;

            for (iAttr = pEnumTag->attributeList.begin();
                 iAttr != pEnumTag->attributeList.end(); iAttr++)
            {
               pNewSecLblSecTag->enumeratedAttributes->attributeFlags.push_back(*iAttr);
            }
         }
         else if (pTmpSecCat->type == acl_id_permissiveBitMap)
         {
            PermissiveTag *pPermTag = (PermissiveTag *)pTmpSecCat->value.value;
            pNewSecLblNTS = FindTagSet(m_pSNACCTmpSSL, pPermTag->tagName);
            if (pNewSecLblNTS == m_pSNACCTmpSSL->end())
            {
               pNewSecLblNTS = m_pSNACCTmpSSL->append();
            }

            // Search through existing pNewSecLblNTS to make sure there is not
            // already a PermissiveTag in this tagSet.
            SecurityTags::iterator iSecTag;
            for (iSecTag = pNewSecLblNTS->securityTags.begin();
                 iSecTag != pNewSecLblNTS->securityTags.end(); iSecTag++)
            {
               if (iSecTag->choiceId == SecurityTag::permissivebitMapCid)
               {
                  AclString errStr;
                  errStr << "Permissive tag already exists in tagset: \n"
                         << "   [" << pPermTag->tagName << "] \n";
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr.str());
               }
            }

            pNewSecLblSecTag = pNewSecLblNTS->securityTags.append();
            pNewSecLblSecTag->choiceId = SecurityTag::permissivebitMapCid;
            pNewSecLblSecTag->permissivebitMap = new SecurityTagSeq2;
            pNewSecLblSecTag->permissivebitMap->attributeFlags = pPermTag->attributeFlags;
         }
         else if (pTmpSecCat->type == acl_id_freeFormField)
         {
            FreeFormField *pFFFTag = (FreeFormField *)pTmpSecCat->value.value;
            TagType7Data *pTmpType7 = new TagType7Data;
            pNewSecLblNTS = FindTagSet(m_pSNACCTmpSSL, pFFFTag->tagName);
            if (pNewSecLblNTS == m_pSNACCTmpSSL->end())
            {
               pNewSecLblNTS = m_pSNACCTmpSSL->append();
            }

            // Search through existing pNewSecLblNTS to make sure there is not
            // already a FreeFormField in this tagSet.
            SecurityTags::iterator iSecTag;
            for (iSecTag = pNewSecLblNTS->securityTags.begin();
                 iSecTag != pNewSecLblNTS->securityTags.end(); iSecTag++)
            {
               if (iSecTag->choiceId == SecurityTag::freeFormFieldCid)
               {
                  AclString errStr;
                  errStr << "FreeFormField already exists in tagset: \n"
                         << "   [" << pFFFTag->tagName << "] \n";
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr.str());
               }
            }

            pNewSecLblSecTag = pNewSecLblNTS->securityTags.append();

            pNewSecLblSecTag->choiceId = SecurityTag::freeFormFieldCid;
            pNewSecLblSecTag->freeFormField = new AsnAny;
            pNewSecLblSecTag->freeFormField->value = pTmpType7;
            if (pFFFTag->field.choiceId == Field::bitSetAttributesCid)
            {
               pTmpType7->choiceId = TagType7Data::bitSetAttributesCid;
               pTmpType7->bitSetAttributes = new AsnBits;
               *pTmpType7->bitSetAttributes = *pFFFTag->field.bitSetAttributes;
            }
            else if (pFFFTag->field.choiceId == Field::securityAttributesCid)
            {
               pTmpType7->choiceId = TagType7Data::securityAttributesCid;
               pTmpType7->securityAttributes = new TagType7DataSetOf;

               FieldSetOf::iterator iSecAttr;
               for (iSecAttr = pFFFTag->field.securityAttributes->begin();
                    iSecAttr != pFFFTag->field.securityAttributes->end();
                    iSecAttr++)
               {
                  pTmpType7->securityAttributes->push_back(*iSecAttr);
               }
            }
         }
         else
         {
            char errStr[ACL_STR_BUF_LEN];
            errStr[0] = '\0';
            sprintf(&errStr[0], "Unsupported security category.%s",
               "\n\tOnly id_missSecurityCategories or Nato security categories are supported");
            throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, &errStr[0]);
         }
      }// ENDLOOP
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return(*m_pSNACCTmpSSL);
} // END OF MEMBER FUNCTION getSSL

StandardSecurityLabel::iterator SecurityLabel::FindTagSet(SNACC::StandardSecurityLabel *pSSL,
                                                          SNACC::AsnOid &tagname)
{
    StandardSecurityLabel::iterator pNTS;

   FUNC("SecurityLabel::FindTagSet");
   try
   {
      for (pNTS = pSSL->begin(); pNTS != pSSL->end(); pNTS++)
      {
         if (pNTS->tagSetName == tagname)
         {
            return(pNTS);
         }
      }
      pNTS = pSSL->insert(pSSL->end(), NamedTagSet());
      pNTS->tagSetName = tagname;
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return(pNTS);
}

// check:
// Checks SecurityLabel for a valid combination of values
//
bool SecurityLabel::check(Session *s, SPIF &spif)
{
   AsnOidLst TagList;

   FUNC("SecurityLabel::check");
   try
   {
      // First check to see if spif has been validated.
      if ((s->m_disable_validation == false) && (spif.isValid() == false) )
      {
         char errStr[ACL_STR_BUF_LEN];
         errStr[0] = '\0';
         sprintf(&errStr[0], "SPIF must be validated prior to calling%s",
            "\n\tSecurityLabel::check");
         throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, &errStr[0]);
      }

      // If label PolicyId and SPIF policyId are equal
      if (this->security_policy_identifier == spif.getPolicyId())
      {
         // If securityClassification is set in the label
         //
         if (this->security_classification != NULL)
         {
            // Loop through the SPIF securityCLassifications to find a matching
            // securityClassification
            //
            SpiftoSignSeqOf::iterator pSecClass;
            SpiftoSignSeqOf::iterator pMatchClass;
            pMatchClass = spif.spiftoSign.securityClassifications.end();

            for (pSecClass = spif.spiftoSign.securityClassifications.begin();
                 pSecClass != spif.spiftoSign.securityClassifications.end();
                 pSecClass++)
            {
               if ((AsnIntType) pSecClass->labelAndCertValue ==
                   (AsnIntType)*this->security_classification)
               {
                  pMatchClass = pSecClass;
                  break;
               }
            } // ENDLOOP

            // IF pMatchClass == NULL THEN SPIF does not include the security
            // classification specified in the label return ACL_LABEL_ERROR
            //
            if (pMatchClass == spif.spiftoSign.securityClassifications.end())
            {
               char errStr[ACL_STR_BUF_LEN];
               errStr[0] = '\0';
               sprintf(&errStr[0],"SPIF does not contain classification %d",
                  (AsnIntType)*this->security_classification);

               throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, &errStr[0]);
            }

            // IF the required categories in the matching securityClassification
            // is not NULL then ensure they are present in the security label.
            //
            if (pMatchClass->requiredCategory != NULL)
            {
               requiredCatCheck(*pMatchClass->requiredCategory, spif);
            }

            // IF m_obsAccept != 1 AND pMatchClass->obsolete == 1 THEN return
            // OBS_CLASS error code.
            if ((this->m_obsAccept != true) && (pMatchClass->obsolete != NULL) &&
                (*pMatchClass->obsolete == 1) )
                throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR,
                "Obsolete class error::check");

         }  // end If securityClassification is set in the label

         // IF securityLabel security_categories != NULL THEN (for each security
         // category value: look up the value in the SPIF; ensure that none of the
         // excluded classifications/categories listed in the SPIF for the
         // value are present in the security label; ensure that the required
         // classification/categories listed in the SPIF for the value are
         // present in the security label; enforce singleCategorySelection
         // rule listed in the SPIF for the value; and, if obs_accept == 0,
         // reject a value that is marked as obsolete in the SPIF)
         if (this->security_categories != NULL)
         {

            // IF securityLabel security_categories->next != NULL THEN return
            // TOO_MANY_SEC_CATS error code.  (Note: SDN.801 states that there can
            // only be one securityCategory present in the securityLabel.)
            if (this->security_categories->size() > 1)
            {
               throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR,
                  "Too many security_categories error::check");
            }

            // IF securityLabel security_categories prbacId != SPIF rbac_id THEN
            // (MissiSecurityCategories is not the SecurityCategory ANY field)
            // return RBAC_ID error.
            SecurityCategories::iterator pTmpSecCat = this->security_categories->begin();
            if (pTmpSecCat->type != spif.spiftoSign.rbacId)
            {
               char errStr[ACL_STR_BUF_LEN];
               AsnOid tmpOid1(pTmpSecCat->type);
               AsnOid tmpOid2(spif.spiftoSign.rbacId);

               sprintf(errStr, "%s=%s%s=%s",
                  "RBAC ID error:\n\tsecurity_categories prbacId",
                  (const char *) tmpOid1, "\n\tSPIF rbac_id", (const char *) tmpOid2);

               // do any error handling
               throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
            }

            // LOOP thru securityLabel security_categories StandardSecurityLabel
            // (NamedTagSets) linked list:
            StandardSecurityLabel::const_iterator pSSL;
            for(pSSL = getSSL().begin(); pSSL != getSSL().end(); pSSL++)
            {
               // Append current securityLabel tagSetName OID to end
               // of tag_lst linked list.
               // LOOP thru TagList until end of list:

               AsnOidLst::iterator pTmpOid;

               for(pTmpOid = TagList.begin(); pTmpOid != TagList.end(); pTmpOid++)
               {
                  // IF current TagList->oid is identical to current
                  // securityLabel tagSetName THEN (there are two NamedTagSets
                  // with the same TagSetName within the same securityCategory,
                  // so that breaks the SDN.801 processing rules)
                  if (*pTmpOid == pSSL->tagSetName)
                  {
                     char errStr[ACL_STR_BUF_LEN];
                     AsnOid tmpOid1(*pTmpOid);
                     AsnOid tmpOid2(pSSL->tagSetName);
                     SecurityCategoryTagSet *pSPIFsecCatTags=NULL;

                     sprintf(errStr, "%s%s=%s%s=%s",
                        "Redundant Name (> 5000) error \n\t",
                        "Tag Set Name 1", (const char *) tmpOid1,
                        "\n\tTag Set Name 2", (const char *) tmpOid2);
                     char *ptr = PrintableLabel::DetermineSPIF_secCatTagSetString(
                                                  spif, pSSL->tagSetName,
                                                  pSPIFsecCatTags);
                     if (ptr)
                     {
                        strcat(errStr, "(SPIFsecCatTagSetString=");
                        strcat(errStr, ptr);
                        strcat(errStr, ")");
                        free(ptr);
                     }       // END IF ptr

                     // do any error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                  }
               }
               TagList.push_back(pSSL->tagSetName);

               // LOOP thru current securityLabel SecurityTags linked list:
               SecurityTags::const_iterator pSecTag;
               for(pSecTag = pSSL->securityTags.begin(); pSecTag != pSSL->securityTags.end(); pSecTag++)
               {
                  // Get tagType and check if current securityLabel
                  // SecurityTags securityLevel != to current
                  // securityLabel securityClass
                  if (pSecTag->choiceId == SecurityTag::restrictivebitMapCid)
                  {
                     // error if securityLevel != classification
                     if (this->security_classification == NULL &&
                         pSecTag->restrictivebitMap->securityLevel != NULL)
                     {
                        char errStr[ACL_STR_BUF_LEN];
                        AsnOid tmpOid(pSSL->tagSetName);
                        long sec_level = *pSecTag->restrictivebitMap->securityLevel;
                        sprintf(errStr,"Bad Security Level:%s %s %ld%s %s",
                           "\n\tsecurity label sec class == NULL",
                           "but restrictive security Level is",
                           sec_level, "\n\tTag Set Name =",
                           (const char *) tmpOid);

                        // do error handling
                        throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                     }
                     else if (this->security_classification != NULL &&
                              pSecTag->restrictivebitMap->securityLevel != NULL &&
                              (*pSecTag->restrictivebitMap->securityLevel !=
                              *this->security_classification))
                     {
                        char errStr[ACL_STR_BUF_LEN];
                        AsnOid tmpOid(pSSL->tagSetName);
                        long sec_class = *this->security_classification;
                        long sec_level = *pSecTag->restrictivebitMap->securityLevel;

                        sprintf(errStr,"Bad Security Level:%s %ld %s %ld%s %s",
                           "\n\tsecurity label sec class is", sec_class,
                           "but restrictive security Level is", sec_level,
                           "\n\tTag Set Name =", (const char *) tmpOid);

                        // do error handling
                        throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                     }
                     
                     // Check the bit string
                     checkBitString(pSecTag->restrictivebitMap->attributeFlags,
                                    pSSL->tagSetName, pSecTag->choiceId, spif);
                  }
                  else if (pSecTag->choiceId ==
                           SecurityTag::enumeratedAttributesCid)
                  {

                     // error if securityLevel != classification
                     if (this->security_classification == NULL &&
                         pSecTag->enumeratedAttributes->securityLevel != NULL)
                     {
                        char errStr[ACL_STR_BUF_LEN];
                        AsnOid tmpOid(pSSL->tagSetName);
                        long sec_level = *pSecTag->enumeratedAttributes->securityLevel;
                        sprintf(errStr, "%s%s %s %ld%s %s",
                           "Bad Security Level:\n\t",
                           "security label sec class == NULL",
                           "but enumerated security Level is", sec_level,
                           "\n\tTag Set Name =", (const char *) tmpOid);

                        // do error handling
                        throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                     }
                     else if (this->security_classification != NULL &&
                              pSecTag->enumeratedAttributes->securityLevel != NULL &&
                              (*pSecTag->enumeratedAttributes->securityLevel !=
                              *this->security_classification))
                     {
                        char errStr[ACL_STR_BUF_LEN];
                        AsnOid tmpOid(pSSL->tagSetName);
                        long sec_class = *this->security_classification;
                        long sec_level = *pSecTag->enumeratedAttributes->securityLevel;

                        sprintf(errStr, "%s%s %ld %s %ld%s %s",
                           "Bad Security Level:\n\t",
                           "security label sec class is", sec_class,
                           "but enumerated security Level is", sec_level,
                           "\n\tTag Set Name =", (const char *) tmpOid);

                        // do error handling
                        throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                     }

                     // Check the Security Attributes
                     checkSecurityAttributes(pSecTag->enumeratedAttributes->attributeFlags,
                                             pSSL->tagSetName, pSecTag->choiceId, spif);

                  }
                  else if (pSecTag->choiceId ==
                           SecurityTag::permissivebitMapCid)
                  {
                     // error if securityLevel != classification
                     if (this->security_classification == NULL &&
                         pSecTag->permissivebitMap->securityLevel != NULL)
                     {
                        char errStr[ACL_STR_BUF_LEN];
                        AsnOid tmpOid(pSSL->tagSetName);
                        long sec_level = *pSecTag->permissivebitMap->securityLevel;
                        sprintf(errStr, "%s%s %s %ld %s %s",
                           "Bad Security Level:\n\t",
                           "security label sec class == NULL",
                           "but permissive security Level is",
                           sec_level, "\n\tTag Set Name =",
                           (const char *) tmpOid);

                        // do error handling
                        throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                     }
                     else if (this->security_classification != NULL &&
                              pSecTag->permissivebitMap->securityLevel != NULL &&
                              (*pSecTag->permissivebitMap->securityLevel !=
                              *this->security_classification))
                     {
                        char errStr[ACL_STR_BUF_LEN];
                        AsnOid tmpOid(pSSL->tagSetName);
                        long sec_class = *this->security_classification;
                        long sec_level = *pSecTag->permissivebitMap->securityLevel;

                        sprintf(errStr, "%s%s %ld %s %ld%s %s",
                           "Bad Security Level:\n\t",
                           "security label sec class is", sec_class,
                           "but permissive security Level is",
                           sec_level, "\n\tTag Set Name =",
                           (const char *) tmpOid);

                        // do error handling
                        throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                     }
                     
                     // Check the bit string
                     checkBitString(pSecTag->permissivebitMap->attributeFlags,
                                    pSSL->tagSetName, pSecTag->choiceId, spif);

                  } // END IF SecurityTag::permissivebitMapCid
                  else if (pSecTag->choiceId ==
                           SecurityTag::freeFormFieldCid)
                  {
                     // Decode the Tag Type 7 data if necessary
                     TagType7Data& secTag = GetDecodedTagType7(*pSecTag->freeFormField);

                     // Check to see if this security tag is bitSet Attributes 
                     // or security Attributes
                     if (secTag.choiceId == TagType7Data::bitSetAttributesCid)
                     {
                        if (secTag.bitSetAttributes != NULL)
                        {
                           // Check the bit string
                           checkBitString(*secTag.bitSetAttributes, 
                              pSSL->tagSetName, pSecTag->choiceId, spif);
                        }
                     }
                     else
                     {
                        if (secTag.securityAttributes != NULL)
                        {
                           // Check the Security Attributes
                           checkSecurityAttributes(*secTag.securityAttributes,
                              pSSL->tagSetName, pSecTag->choiceId, spif);
                        }
                     }
                  }
                  else
                  {
                     // do error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR,
                        "Improper Security Tag Value::check");
                  }
               }

            }// END LOOP thru StandardSecurityLabel

         }  // end if security_categories != NULL
      }
      else
      {
         // PolicyId and SPIF policyId are not equal - return error
         char errStr[ACL_STR_BUF_LEN];
         AsnOid tmpOid1(spif.getPolicyId());
         AsnOid tmpOid2(this->security_policy_identifier);
         errStr[0]='\0';
         sprintf(errStr, "PolicyID's don't match. \n\tspif policyId=%s%s=%s",
            (const char *) tmpOid1, "\n\tseclbl policyId", (const char *) tmpOid2);
         throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
      }

   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   return(true);
} // END OF MEMBER FUNCTION check

// requiredCatCheck:
// This member ensures that the required categories listed in the SPIF are
// present in the security label.
//
void SecurityLabel::requiredCatCheck(RequiredCategories &reqCat, const SPIF &spif,
                                     const SNACC::TagCategories *pSpifTagCat)  // ONLY FOR REPORTING
{

   FUNC("SecurityLabel::requiredCatCheck");
   try
   {
      RequiredCategories::iterator iReqCat;
      for (iReqCat = reqCat.begin(); iReqCat != reqCat.end(); iReqCat++)
      {
         long found_cat = 0;
         long stop_search = 0;
         long found_cat_pif = 0;
         OptionalCategoryDataSeqOf::iterator pCatData;

         for (pCatData = iReqCat->categoryGroup.begin();
              pCatData != iReqCat->categoryGroup.end() && stop_search == 0;
              pCatData++)
         {
            // If the required category indicates that only the labelAndCertValue
            // is required ensure that the security label securityCategories
            // contains the requiredCategory securityCategoryTagSetName present
            // in the label.
            if (pCatData->categories.choiceId ==
                OptionalCategoryDataChoice::labelAndCertValueCid)
            {
               // Determine if the security label includes the current categoryGroup.
               // If findCat returns false throw an exception containing the
               // information that caused the failure.
               //
               if (findCat(pCatData->securityCategoryTagSetName, pCatData->tagType,
                   *pCatData->categories.labelAndCertValue) == false)
               {
                  if (iReqCat->operation == 3)
                  {
                     char errStr[ACL_STR_BUF_LEN*2];
                     int tagType = pCatData->tagType;
                     long labelcert = *pCatData->categories.labelAndCertValue;
                     CreateErrorStringForLabel(errStr,
                              "Missing required category:\n\tTag Set Name",
                              tagType, labelcert, spif, pCatData->securityCategoryTagSetName,
                              NULL, pSpifTagCat);       //  RWC;TESTED

                     // findCat failed, do error handling
                     throw ACL_EXCEPT(ACL_REQ_CAT_NOT_FOUND, errStr);
                  }
               }
               else  // findCat returned true value
               {
                  // Increment found_cat.
                  found_cat++;

                  //IF current reqCats->operation == 1 (onlyOne) THEN
                  if (iReqCat->operation == 1)
                  {
                     if (found_cat > 1)
                     {
                        char errStr[ACL_STR_BUF_LEN*2];
                        int tagType = pCatData->tagType;
                        long labelcert = *pCatData->categories.labelAndCertValue;
                        CreateErrorStringForLabel(errStr,
                              "operation == 1 and found_cat > 1:\n\tTag Set Name",
                              tagType, labelcert, spif, pCatData->securityCategoryTagSetName,
                              NULL, pSpifTagCat);       //  RWC;TESTED

                        // findCat failed, do error handling
                        throw ACL_EXCEPT(ACL_REQ_CAT_NOT_FOUND, errStr);
                     }
                  }
                  //Elseif current reqCats->operation == 2 (oneOrMore) THEN
                  else if (iReqCat->operation == 2)
                           stop_search = 1;
               }
            }
            // ELSE (current required category == 1 (allCid), so check
            //   all SecurityTag values in SPIF indicated by current
            //   requiredCategory categoryData for inclusion in security label)
            else
            {
               // SPIF sanity check - should never occur
               if (pCatData->categories.all == false)
               {
                  char errStr[ACL_STR_BUF_LEN*2];
                  sprintf(errStr, "%s %s",
                          "SPIF Consistency error: excludedCategory data choice",
                          "set to all and excludedCategory all set to false");
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
               }
               // Set found_cat_pif to 0.
               found_cat_pif = 0;

               //Loop thru SPIF SecurityCategoryTagSet linked list until
               //stop_search == 1 OR end of list:
               SecurityCategoryTagSets::iterator pSecTagSet;

               for (pSecTagSet = spif.spiftoSign.securityCategoryTagSets->begin();
                    pSecTagSet != spif.spiftoSign.securityCategoryTagSets->end() &&
                    stop_search == 0; pSecTagSet++)
               {
                  // if SPIF securityCategoryTagSetName equals requiredCategory
                  // securityCategoryTagSetName THEN (found correct SPIF
                  // SecurityCategoryTagSet for current requiredCategory
                  // NamedTagSet
                  if (pSecTagSet->securityCategoryTagSetName ==
                      pCatData->securityCategoryTagSetName)
                  {
                     // LOOP thru current SPIF securityCategoryTags linked
                     // list until stop_search == 1 OR end of list:
                     SecurityCategoryTagSetSeqOf::iterator pSecTag;
                     for (pSecTag = pSecTagSet->securityCategoryTags.begin();
                          pSecTag != pSecTagSet->securityCategoryTags.end() &&
                          stop_search == 0; pSecTag++)
                     {
                        // if SPIF tagType equals requiredCategory tagType
                        if (pSecTag->tagType == pCatData->tagType)
                        {
                           // Set found_cat_pif to 1.
                           found_cat_pif = 1;

                           // LOOP thru current SPIF tagCategories linked list
                           // until stop_search == 1 OR end of list:
                           SecurityCategoryTagSeqOf::iterator pTagCat;

                           for (pTagCat = pSecTag->tagCategories.begin();
                                pTagCat != pSecTag->tagCategories.end() &&
                                stop_search == 0; pTagCat++)
                           {
                              // Call findCat to determine if the security label
                              // includes the current SPIF labelAndCertValue
                              if (findCat(pSecTagSet->securityCategoryTagSetName,
                                  pSecTag->tagType,
                                  pTagCat->labelAndCertValue) == false)
                              {
                                 if (iReqCat->operation == 3)
                                 {
                                    // findCat failed, do error handling
                                    char errStr[ACL_STR_BUF_LEN*2];
                                    int tagType = pCatData->tagType;
                                    // SET labelAndCertValue TO -1 BECAUSE CHOICE IS allCid
                                    long labelcert = -1;
                                    CreateErrorStringForLabel(errStr,
                                          "Missing required category:\n\tTag Set Name",
                                          tagType, labelcert, spif, pCatData->securityCategoryTagSetName,
                                          NULL, pSpifTagCat);

                                    // findCat failed, do error handling
                                    throw ACL_EXCEPT(ACL_REQ_CAT_NOT_FOUND, errStr);
                                 }

                              }
                              else  // findCat returned true value
                              {
                                 // Increment found_cat.
                                 found_cat++;

                                 //IF current reqCats->operation == 1 (onlyOne)
                                 if (iReqCat->operation == 1)
                                 {
                                    if (found_cat > 1)
                                    {
                                       char errStr[ACL_STR_BUF_LEN*2];
                                       int tagType = pCatData->tagType;
                                       // SET labelAndCertValue TO -1 BECAUSE CHOICE IS allCid
                                       long labelcert = -1;
                                       CreateErrorStringForLabel(errStr,
                                              "operation == 1 and found_cat > 1:\n\tTag Set Name",
                                              tagType, labelcert, spif, pCatData->securityCategoryTagSetName,
                                              NULL, pSpifTagCat);

                                       // findCat failed, do error handling
                                       throw ACL_EXCEPT(ACL_REQ_CAT_NOT_FOUND, errStr);
                                    }
                                 }
                                 //Elseif current reqCats->operation == 2 (oneOrMore) THEN
                                 else if (iReqCat->operation == 2)
                                          stop_search = 1;
                              }
                           } // ENDLOOP
                        }
                     } // ENDLOOP
                  }
               } // ENDLOOP

               // IF found_cat_pif == 0 THEN (SPIF SecurityTag could not be
               // found in SPIF, so SPIF is erroneous)
               if (found_cat_pif == 0)
               {
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR,
                     "No Req Cats (>5000) error::requiredCatCheck");
                  // do error handling
               }
            }  // ENDELSE check all SecurityTags in SPIF indicated by req_cats
         }

         // IF found_cat == 0 THEN return ACL_REQ_CAT_NOT_FOUND error code.
         // (Note: In this case, the security label did not include any of
         // the Required Categories indicated by the SPIF for the chk_val
         // security label value, but that could be 1 or more possible
         // values.
         if (found_cat == 0)
         {
            AclString errStr;
            errStr << "Missing required category from OptionalCategoryGroup, operation = ";
               
            switch (iReqCat->operation)
            {
            case OptionalCategoryGroupInt::onlyOne:
               errStr << "onlyOne";
               break;
            case OptionalCategoryGroupInt::oneOrMore:
               errStr << "oneOrMore";
               break;
            case OptionalCategoryGroupInt::all:
               errStr << "all";
               break;
            }

            throw ACL_EXCEPT(ACL_REQ_CAT_NOT_FOUND, errStr.str());
         }
      }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION requiredCatCheck

// CreateErrorStringForLabel:
// Function which formats data to be used in an error string produced by
// a SecurityLabel check, which may be displayed to help a user correct
// the problem with the SecurityLabel.
//
// INPUT
// *errStrOut - will contain the formatted error string, the output from
//             this function
// *pszIncomingErrorDescription - Error condition description from calling
//                               function
// ltagType - TagType from SecurityLabel/SPIF
// labelcert - labelAndCertValue from SecurityLabel/SPIF.  If this
//             value is set to -1 it indicates a call from requiredCatCheck
//             where requiredCategories are set to all (choiceid == allCid)
// spif - SPIF used during this check
// SNACCOid - securityCategoryTagSetName from SPIF or tagSetName from
//            SecurityLabel which have been matched prior to the call of
//            this function
// *pszOptionalTagTypeDescriptionIN - TagType explanation string
// *pSpifTagCat - Tag Categories from the SPIF
//
// OUTPUT
// *errStrOut - formatted error string, including data passed in and
//              information determined in this function
// RETURN - void
//
void SecurityLabel::CreateErrorStringForLabel(
               char *errStrOut,     // MEMORY INPUT, DATA OUT from this method
               const char *pszIncomingErrorDescription,     // IN
               const int tagType,                           // IN
               const long labelcert,                        // IN
               const SPIF &spif,                            // IN
               const AsnOid SNACCOid,                       // IN
               const char *pszOptionalTagTypeDescriptionIN, // IN
               const SNACC::TagCategories *pSpifTagCat)     // IN
{
   errStrOut[0] = '\0';      // pre-initialize output data.
   SecurityCategoryTagSet *pSPIFsecCatTags=NULL;

   char *pszSPIF_secCattagSecSetString =
      PrintableLabel::DetermineSPIF_secCatTagSetString(
      spif, SNACCOid, pSPIFsecCatTags);
   if (pszSPIF_secCattagSecSetString == NULL)
      pszSPIF_secCattagSecSetString = "";
   char *pszSPIF_secCategoryName = "";
   char *pszSPIF_Working_secCategoryName = "";
   char *pszWorkingLabelDescription="";
   const char *pszOptionalTagTypeDescription="";

   if (pSPIFsecCatTags)
   {
      if (pszOptionalTagTypeDescriptionIN)
      {
         pszOptionalTagTypeDescription = pszOptionalTagTypeDescriptionIN;
      }
      bool bfoundMatchCat=false;
      SecurityCategoryTagSetSeqOf::iterator pSecCat;
      SecurityCategoryTagSeqOf::iterator pTagCats;

      // A labelAndCertValue of -1 INDICATES requiredCategories ARE SET TO ALL
      // SO THERE IS NO labelAndCertValue
      if (labelcert != -1)
      {
         for (pSecCat =  pSPIFsecCatTags->securityCategoryTags.begin();
              pSecCat != pSPIFsecCatTags->securityCategoryTags.end() && ! bfoundMatchCat;
              pSecCat++)
         {
            if (tagType == pSecCat->tagType)
            {
               for (pTagCats =  pSecCat->tagCategories.begin();
                    pTagCats != pSecCat->tagCategories.end();
                    pTagCats++)
               {
                  // IF current securityLabel bit position
                  // indicated by current tagCategories
                  // tag_label_cert is set to 1 THEN (found
                  // correct TagCategories) set pMatchCat
                  // to point to current SPIF tagCategories
                  if (labelcert == pTagCats->labelAndCertValue)
                  {
                      bfoundMatchCat = true;
                      break;
                  }
               } // END FOR each SPIF TagCat entry
            } // END IF tagType match
         } // END FOR each SPIF secCatTag entry
         if (bfoundMatchCat)
         {
            pszSPIF_secCategoryName =
               PrintableLabel::DetermineSPIF_secCategoryName(*pTagCats);
         }
      } // END OF CHECK FOR labelcert == -1
   } // END OF CHECK FOR pSPIFsecCatTags
   if (pszSPIF_secCategoryName == NULL)
   {
      pszSPIF_secCategoryName = "";
   }
   if (pSpifTagCat)
   {
      pszSPIF_Working_secCategoryName =
         PrintableLabel::DetermineSPIF_secCategoryName(*pSpifTagCat);
   }
   if (pszSPIF_Working_secCategoryName
    && pszSPIF_Working_secCategoryName[0] != '\0')
   {
      pszWorkingLabelDescription = "WHEN PROCESSING ";
   }
   else
   {
      pszSPIF_Working_secCategoryName = "";  //ALLOW to work with sprintf(...).
   }

   //***************************************
   if (labelcert == -1)
   {
      sprintf(errStrOut, "%s %s \n\t%s=%s(%s)%s=%ld %s %s",
         pszWorkingLabelDescription, pszSPIF_Working_secCategoryName,
         pszIncomingErrorDescription, (const char *) SNACCOid,
         pszSPIF_secCattagSecSetString, "\n\ttagType", tagType,
         pszOptionalTagTypeDescription, "\n\tlabelAndCertValue=allCid(TRUE)");
   }
   else
   {
      sprintf(errStrOut, "%s %s \n\t%s=%s(%s)%s=%ld %s %s=0x%02X(%s)",
         pszWorkingLabelDescription, pszSPIF_Working_secCategoryName,
         pszIncomingErrorDescription, (const char *) SNACCOid,
         pszSPIF_secCattagSecSetString, "\n\ttagType", tagType,
         pszOptionalTagTypeDescription, "\n\thex labelAndCertValue",
         labelcert, pszSPIF_secCategoryName);
   }
   //***************************************

   if (pszSPIF_secCattagSecSetString[0] != '\0')
   {
      free(pszSPIF_secCattagSecSetString);
   }
   if (pszSPIF_secCategoryName[0] != '\0')
   {
      free(pszSPIF_secCategoryName);
   }
   if (pszSPIF_Working_secCategoryName[0] != '\0')
   {
      free(pszSPIF_Working_secCategoryName);
   }

} // END OF MEMBER FUNCTION CreateErrorStringForLabel

// excludedCatCheck:
// This member ensures that none of the excluded categories listed in the SPIF
// are present in the security label.
//
void SecurityLabel::excludedCatCheck(OptionalCategoryDataSeqOf &excCat,
                                     const SPIF &spif)
{
   OptionalCategoryDataSeqOf::iterator pCatData;
   long found_cat = 0;

   FUNC("SecurityLabel::excludedCatCheck");
   try
   {
      // LOOP thru excCats (SEQUENCE of OptionalCategoryData linked list
      // until end of list:
      for (pCatData = excCat.begin(); pCatData != excCat.end(); pCatData++)
      {
         // If the excluded category indicates that only the labelAndCertValue
         // is required ensure that the security label securityCategories
         // contains the excludedCategory securityCategoryTagSetName present
         // in the label.
         if (pCatData->categories.choiceId ==
             OptionalCategoryDataChoice::labelAndCertValueCid)
         {
            // Call findCat to determine if the security label includes the current
            // excluded category security tag value.  If current excluded category
            // is found in the security label, then findCat returns NO_ERROR;
            // otherwise, an error code is returned.
            if (findCat(pCatData->securityCategoryTagSetName, pCatData->tagType,
                *pCatData->categories.labelAndCertValue) == true)
            {
               char errStr[ACL_STR_BUF_LEN];
               AsnOid tmpOid(pCatData->securityCategoryTagSetName);
               int tagType = pCatData->tagType;
               long labelcert = *pCatData->categories.labelAndCertValue;
               SecurityCategoryTagSet *pSPIFsecCatTags=NULL;

               char *pszSPIF_secCattagSecSetString =
                    PrintableLabel::DetermineSPIF_secCatTagSetString(
                                spif, pCatData->securityCategoryTagSetName,
                                pSPIFsecCatTags);
               if (pszSPIF_secCattagSecSetString == NULL)
                   pszSPIF_secCattagSecSetString = "";

               sprintf(errStr,"%s=%s(%s)\n\t%s=%ld\n\t%s=0x%02X",
                  "Excluded Category Found:\n\tTag Set Name",
                  (const char *)tmpOid, pszSPIF_secCattagSecSetString,
                  "tagType", tagType, "labelAndCertValue",
                  (unsigned int) labelcert);
               if (pszSPIF_secCattagSecSetString[0] != '\0')
                   free(pszSPIF_secCattagSecSetString);

               // findCat found excluded category, do error handling
               throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
            }
         }
         // ELSE check all SecurityTag values in SPIF indicated by current
         // excludedCategory for exclusion in SecurityLabel.
         //
         else if (pCatData->categories.choiceId ==
                  OptionalCategoryDataChoice::allCid)
         {
            // SPIF sanity check - should never occur
            if (pCatData->categories.all == false)
            {
               char errStr[ACL_STR_BUF_LEN*2];
               sprintf(errStr, "%s %s",
                       "SPIF Consistency error: excludedCategory data choice",
                       "set to all and excludedCategory all set to false");
               throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
            }
            // Set found_cat to 0.
            found_cat = 0;

            // Loop thru SPIF SecurityCategoryTagSet linked list until
            // found_cat != 0 OR end of list:
            SecurityCategoryTagSets::iterator pSecTagSet;
            for (pSecTagSet = spif.spiftoSign.securityCategoryTagSets->begin();
                 pSecTagSet != spif.spiftoSign.securityCategoryTagSets->end() &&
                 found_cat == 0; pSecTagSet++)
            {
               // if SPIF securityCategoryTagSetName equals excludedCategory
               // securityCategoryTagSetName THEN (found correct SPIF
               // SecurityCategoryTagSet for current requiredCategory
               // NamedTagSet
               if (pSecTagSet->securityCategoryTagSetName ==
                   pCatData->securityCategoryTagSetName)
               {
                  // LOOP thru current SPIF securityCategoryTags linked
                  // list until found_cat != 0 OR end of list:
                  SecurityCategoryTagSetSeqOf::iterator pSecTag;
                  for (pSecTag = pSecTagSet->securityCategoryTags.begin();
                       pSecTag != pSecTagSet->securityCategoryTags.end() &&
                       found_cat == 0; pSecTag++)
                  {
                     // if excludedCategory tagType equals SPIF tagType
                     if (pSecTag->tagType == pCatData->tagType)
                     {
                        // Set found_cat to 1.
                        found_cat = 1;

                        // LOOP thru current SPIF tagCategories linked list
                        // until end of list:
                        SecurityCategoryTagSeqOf::iterator pTagCat;
                        for (pTagCat = pSecTag->tagCategories.begin();
                             pTagCat != pSecTag->tagCategories.end(); pTagCat++)
                        {
                           // Call findCat to determine if the security label
                           // includes the current SPIF labelAndCertValue
                           if (findCat(pSecTagSet->securityCategoryTagSetName,
                               pSecTag->tagType,
                               pTagCat->labelAndCertValue) == true)
                           {
                              // findCat found excluded category, do error handling
                              char errStr[ACL_STR_BUF_LEN];
                              AsnOid tmpOid(pCatData->securityCategoryTagSetName);
                              int tagType = pCatData->tagType;
                              // DO NOT SET labelAndCertValue BECAUSE CHOICE IS allCid
                              // long labelcert = pTagCat->labelAndCertValue;
                              SecurityCategoryTagSet *pSPIFsecCatTags=NULL;

                              char *pszSPIF_secCattagSecSetString =
                                    PrintableLabel::DetermineSPIF_secCatTagSetString(
                                                spif, pCatData->securityCategoryTagSetName,
                                                pSPIFsecCatTags);
                              if (pszSPIF_secCattagSecSetString == NULL)
                                  pszSPIF_secCattagSecSetString = "";
                              char *pszSPIF_secCategoryName =
                                  PrintableLabel::DetermineSPIF_secCategoryName(*pTagCat);
                              if (pszSPIF_secCategoryName == NULL)
                                  pszSPIF_secCategoryName = "";
                              sprintf(errStr, "%s=%s(%s)%s=%ld%s=%s(%s)",
                                 "Excluded category found:\n\tTag Set Name",
                                 (const char *) tmpOid, pszSPIF_secCattagSecSetString,
                                 "\n\ttagType", tagType, "\n\tlabelAndCertValue",
                                 // DO NOT DISPLAY labelAndCertValue - CHOICE IS allCid
                                 // (unsigned int) labelcert, pszSPIF_secCattagSecSetString);
                                 "allCid(TRUE) ", pszSPIF_secCattagSecSetString);
                              if (pszSPIF_secCattagSecSetString[0] != '\0')
                                  free(pszSPIF_secCattagSecSetString);
                              if (pszSPIF_secCategoryName[0] != '\0')
                                  free(pszSPIF_secCategoryName);
                              throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                           }
                        } // ENDLOOP
                     } // ENDIF tagTypes match
                  } // ENDLOOP
               }
            } // ENDLOOP

            // IF found_cat == 0 THEN (SPIF excludedCategory SecurityTag could not
            // be found in SPIF, so SPIF is erroneous)
            if (found_cat == 0)
            {
               // do error handling
               throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR,
                  "PIF No Exc Cat (> 5000) error::excludedCatCheck");
            }
         }  // ENDELSE check all SecurityTags in SPIF indicated by excluded categories
         else
         {
            throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR,
               "Invalid OptionalCategoryDataChoice->choiceId::excludedCatCheck");
         }
      }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION excludedCatCheck

// findCat:
// This function determines if the securityLabel includes the categoryData
// security tag value.
bool SecurityLabel::findCat(SNACC::AsnOid &tagsetname, SNACC::TagTypeValue &tagtype,
                            SNACC::AsnInt &labelandcert)
{
   FUNC("SecurityLabel::findCat");

   try
   {
      //LOOP thru StandardSecurityLabel
      StandardSecurityLabel::const_iterator pNamedTagSet;

      for(pNamedTagSet = getSSL().begin(); pNamedTagSet != getSSL().end(); pNamedTagSet++)
      {
         // if the securityLabel tagSetName equals the tagsetname
         if (pNamedTagSet->tagSetName == tagsetname)
         {
            if (CSecurityTag::findLabelAndCertValue(pNamedTagSet->
                securityTags, labelandcert, tagtype) != pNamedTagSet->securityTags.end())
            {
               return(true);
            }
         }
      }
   }
   catch (InternalAclException &)
   {
   }

   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return(false);
} // END OF MEMBER FUNCTION findCat

// tagAndLevelCheck:
// This function checks for the tag redundancy error and checks to make sure
// the securityLevel equals the security classification
void SecurityLabel::tagAndLevelCheck(void)
{
   AsnOidLst TagList;

   FUNC("SecurityLabel::tagAndLevelCheck");

   try
   {
      if (this->security_categories != NULL)
      {
         // LOOP thru securityLabel security_categories StandardSecurityLabel
         // (NamedTagSets) linked list:

         StandardSecurityLabel::const_iterator pSSL;
         for(pSSL = getSSL().begin(); pSSL != getSSL().end(); pSSL++)
         {
            // Append current securityLabel tagSetName OID to end
            // of tag_lst linked list.
            // LOOP thru TagList until end of list:
            AsnOidLst::iterator pTmpOid;

            for(pTmpOid = TagList.begin(); pTmpOid != TagList.end(); pTmpOid++)
            {
               // IF current TagList->oid is identical to current
               // securityLabel tagSetName THEN (there are two NamedTagSets
               // with the same TagSetName within the same securityCategory,
               // so that breaks the SDN.801 processing rules) THEN
               if (*pTmpOid == pSSL->tagSetName)
               {
                  char errStr[ACL_STR_BUF_LEN];
                  AsnOid tmpOid1(*pTmpOid);
                  AsnOid tmpOid2(pSSL->tagSetName);

                  sprintf(errStr, "%s=%s%s=%s",
                     "Redundant Name (> 5000) error \n\tTag Set Name 1",
                     (const char *) tmpOid1, "\n\tTag Set Name 2",
                     (const char *) tmpOid2);

                  // do any error handling
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
               }
            }

            TagList.push_back(pSSL->tagSetName);

            // LOOP thru current securityLabel SecurityTags linked list:
            SecurityTags::const_iterator pSecTag;
            for(pSecTag = pSSL->securityTags.begin(); pSecTag != pSSL->securityTags.end(); pSecTag++)
            {
               // Get tagType and check if current securityLabel
               // SecurityTags securityLevel != to current
               // securityLabel securityClass
               if (pSecTag->choiceId == SecurityTag::restrictivebitMapCid)
               {
                  if ((this->security_classification == NULL) &&
                      (pSecTag->restrictivebitMap->securityLevel != NULL))
                  {
                     char errStr[ACL_STR_BUF_LEN];
                     AsnOid tmpOid(pSSL->tagSetName);
                     long sec_level = *pSecTag->restrictivebitMap->securityLevel;
                     sprintf(errStr, "%s%s %s %ld%s %s",
                        "Bad Security Level::tagAndLevelCheck:\n\t",
                        "security label sec class == NULL",
                        "but restrictive security Level is", sec_level,
                        "\n\tTag Set Name =", (const char *) tmpOid);

                     // do error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                  }
                  else if ((pSecTag->restrictivebitMap->securityLevel != NULL)
                           && (this->security_classification != NULL) &&
                           (*pSecTag->restrictivebitMap->securityLevel !=
                           *this->security_classification))
                  {
                     char errStr[ACL_STR_BUF_LEN];
                     AsnOid tmpOid(pSSL->tagSetName);
                     long sec_class = *this->security_classification;
                     long sec_level = *pSecTag->restrictivebitMap->securityLevel;

                     sprintf(errStr, "%s%s %ld %s %ld%s %s",
                        "Bad Security Level::tagAndLevelCheck:\n\t",
                        "security label sec class is", sec_class,
                        "but restrictive security Level is", sec_level,
                        "\n\tTag Set Name =", (const char *) tmpOid);

                     // do error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                  }
               }
               else if (pSecTag->choiceId ==
                        SecurityTag::enumeratedAttributesCid)
               {
                  if ((this->security_classification == NULL) &&
                      (pSecTag->enumeratedAttributes->securityLevel != NULL))
                  {
                     char errStr[ACL_STR_BUF_LEN];
                     AsnOid tmpOid(pSSL->tagSetName);
                     long sec_level = *pSecTag->enumeratedAttributes->securityLevel;
                     sprintf(errStr, "%s%s %s %ld%s %s",
                        "Bad Security Level::tagAndLevelCheck:\n\t",
                        "security label sec class == NULL",
                        "but enumerated security Level is", sec_level,
                        "\n\tTag Set Name =", (const char *) tmpOid);

                     // do error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                  }
                  else if ((pSecTag->enumeratedAttributes->securityLevel != NULL)
                           && (this->security_classification != NULL) &&
                           (*pSecTag->enumeratedAttributes->securityLevel !=
                           *this->security_classification) )
                  {
                     char errStr[ACL_STR_BUF_LEN];
                     AsnOid tmpOid(pSSL->tagSetName);
                     long sec_class = *this->security_classification;
                     long sec_level = *pSecTag->enumeratedAttributes->securityLevel;

                     sprintf(errStr, "%s%s %ld %s %ld%s %s",
                        "Bad Security Level::tagAndLevelCheck:\n\t",
                        "security label sec class is", sec_class,
                        "but enumerated security Level is", sec_level,
                        "\n\tTag Set Name =", (const char *) tmpOid);

                     // do error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                  }
               }
               else if (pSecTag->choiceId ==
                        SecurityTag::permissivebitMapCid)
               {
                  // error if securityLevel != classification

                  if ((this->security_classification == NULL) &&
                      (pSecTag->permissivebitMap->securityLevel != NULL))
                  {
                     char errStr[ACL_STR_BUF_LEN];
                     AsnOid tmpOid(pSSL->tagSetName);
                     long sec_level = *pSecTag->permissivebitMap->securityLevel;
                     sprintf(errStr, "%s%s %s %ld%s %s",
                        "Bad Security Level::tagAndLevelCheck:\n\t",
                        "security label sec class == NULL",
                        "but permissive security Level is", sec_level,
                        "\n\tTag Set Name =", (const char *) tmpOid);

                     // do error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                  }
                  else if ((pSecTag->permissivebitMap->securityLevel != NULL) &&
                           (this->security_classification != NULL) &&
                           (*pSecTag->permissivebitMap->securityLevel !=
                           *this->security_classification) )
                  {
                     char errStr[ACL_STR_BUF_LEN];
                     AsnOid tmpOid(pSSL->tagSetName);
                     long sec_class = *this->security_classification;
                     long sec_level = *pSecTag->permissivebitMap->securityLevel;

                     sprintf(errStr, "%s%s %ld %s %ld%s %s",
                        "Bad Security Level::tagAndLevelCheck:\n\t",
                        "security label sec class is", sec_class,
                        "but permissive security Level is", sec_level,
                        "\n\tTag Set Name =", (const char *) tmpOid);

                     // do error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
                  }
               }
               else if (pSecTag->choiceId ==
                        SecurityTag::freeFormFieldCid)
               {
                  // no securityLevel - do nothing
               }
               else
               {
                  // do error handling
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR,
                     "Improper Security Tag Value::tagAndLevelCheck");
               }
            }

         }// END LOOP thru StandardSecurityLabel
      }
   }
   catch (InternalAclException &)
   {
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

} // END OF MEMBER FUNCTION tagAndLevelCheck

// isEquivApplicable:
//
// applied        INTEGER {
//             encrypt  (0),
//             decrypt  (1),
//             both  (2) } }
//
bool SecurityLabel::isEquivApplicable(int applied)
{
   if (applied == 2 || ((isIncoming() && applied == 1) ||
       (isOutgoing() && applied == 0)))
      return true;
   else
      return false;
} // END OF MEMBER FUNCTION isEquivApplicable

// getClassification:
//
SecurityClassification & SecurityLabel::getClassification(void)
{
   if (this->security_classification == NULL)
   {
      this->security_classification = new SecurityClassification;
   }

   return (*this->security_classification);
} // END OF MEMBER FUNCTION getClassification

// getLabelString:
// Returns a null terminated string representation
// of the SecurityLabel as defined by SDN.801.
//
char * SecurityLabel::getLabelString(const SPIF &spif)
{
   PrintableLabel printableLabel(*this, spif);
   AclString      os;

   printableLabel.printLabel(os);
   os << "\0";  // TERMINATE string.
   char *ptr = (char *)calloc(1, os.length()+1);
   memcpy(ptr, os.str(), os.length());
   return (ptr);
} // END OF MEMBER FUNCTION getLabelString

// getPolicyId:
// Returns a reference to the security policy
// identifier contained within the SecurityLabel.
//
AsnOid & SecurityLabel::getPolicyId(void)
{
   return(this->security_policy_identifier);
} // END OF MEMBER FUNCTION getPolicyId

// setSSL:
//
void SecurityLabel::setSSL(StandardSecurityLabel *pNewTagSets)
{
   if (this->m_pSNACCTmpSSL != NULL)
   {
      delete this->m_pSNACCTmpSSL;
   }
   m_pSNACCTmpSSL = pNewTagSets;
} // END OF MEMBER FUNCTION setSSL

// freeFormOnlyCheck:
//
// Determines if this security label only contains freeForm security category
// data.  This member function is used to determine whether or not security
// categories should be translated.
bool SecurityLabel::freeFormOnlyCheck(void)
{
   StandardSecurityLabel::const_iterator pTagSet;
   bool retVal = true;;

   if (this->security_categories != NULL)
   {

      for (pTagSet = getSSL().begin(); pTagSet != getSSL().end(); pTagSet++)
      {
         if (! ((pTagSet->securityTags.size() == 1) &&
             (pTagSet->securityTags.begin()->choiceId == SecurityTag::freeFormFieldCid)))
         {
            retVal = false;
            break;
         }
      }
   }

   return retVal;
} // END OF MEMBER FUNCTION freeFormOnlyCheck

void SecurityLabel::checkBitString(const SNACC::AsnBits& attributeFlags,
                          const SNACC::TagSetName& tagSetName,
                          int tagType,
                          const SPIF &spif)
{   
   FUNC("SecurityLabel::checkBitString");
   AsnOid tagSetNameOid(tagSetName);
   
   // Set cat_count (local long) to 0.
   long cat_count = 0;
   
   // LOOP thru attributeFlags until end of array:
   size_t i = attributeFlags.BitLen();
   size_t j = 0;
   for (j = 0; j <= i; j++)
   {
      // IF current securityLabel bit position is set to 1 THEN:
      if (CAsnBits::checkBit(attributeFlags, j))
      {
         // LOOP thru SPIF SecurityCategoryTagSets linked list
         // until pMatchCat != NULL OR end of list:
         SecurityCategoryTagSets::iterator  pSecCatTag;
         SecurityCategoryTagSetSeqOf::iterator owner;
         SecurityCategoryTagSeqOf::iterator pMatchCat;
         bool foundMatchCat = false;
         
         for (pSecCatTag = spif.spiftoSign.securityCategoryTagSets->begin();
              pSecCatTag != spif.spiftoSign.securityCategoryTagSets->end() &&
              ! foundMatchCat; pSecCatTag++)
         {
            // IF current securityLabel tag_set_name == current
            // SPIF securityCategoryTagSetName THEN (found
            // correct SPIF SecurityCategoryTagSet)
            if (tagSetName == pSecCatTag->securityCategoryTagSetName)
            {
               // LOOP thru current SPIF securityCategoryTags
               // linked list until pMatchCat != NULL OR end of
               // list:
               SecurityCategoryTagSetSeqOf::iterator pSecCat;
               
               for (pSecCat = pSecCatTag->securityCategoryTags.begin();
                    pSecCat != pSecCatTag->securityCategoryTags.end() &&
                    ! foundMatchCat; pSecCat++)
               {
                  // IF current securityLabel tag_type ==
                  // current SPIF tag_type THEN (found correct
                  // SPIF SecurityCategoryTag)
                  if (CSecurityTag::isTagTypeEqual(tagType, *pSecCat))
                  {
                     // LOOP thru current SPIF tagCategories
                     // linked list until pMatchCat != NULL OR
                     // end of list:
                     SecurityCategoryTagSeqOf::iterator pTagCats;
                     
                     for (pTagCats = pSecCat->tagCategories.begin();
                          pTagCats != pSecCat->tagCategories.end();
                          pTagCats++)
                     {
                        // IF current securityLabel bit position
                        // indicated by current tagCategories
                        // tag_label_cert is set to 1 THEN (found
                        // correct TagCategories) set pMatchCat
                        // to point to current SPIF tagCategories
                        if (pTagCats->labelAndCertValue ==
                           (AsnIntType) j)
                        {
                           foundMatchCat = true;
                           pMatchCat = pTagCats;
                           owner = pSecCat;
                           break;
                        }
                     } // ENDLOOP
                  }
               } // ENDLOOP
            }
         } // ENDLOOP
         
         // IF pMatchCat == NULL THEN (SPIF does not include
         // securityLabel security category value so return error)
         if (! foundMatchCat)
         {
            char errStr[ACL_STR_BUF_LEN];
            long labelcert = j;
            SecurityCategoryTagSet *pSPIFsecCatTags=NULL;
            char *pszSPIF_secCattagSecSetString =
               PrintableLabel::DetermineSPIF_secCatTagSetString(
               spif, tagSetName, pSPIFsecCatTags);
            if (pszSPIF_secCattagSecSetString == NULL)
               pszSPIF_secCattagSecSetString = "";
            
            sprintf(errStr, "%s%s=%s(%s)%s=%ld %s %s%s=0x%02X",
               "Bad labelAndCert value:",
               "\n\tTag Set Name", (const char *) tagSetNameOid,
               pszSPIF_secCattagSecSetString,
               "\n\ttagType", tagType,
               "(0=restrictive, 1=enumerated,",
               "2=permissive, or 3=freeform)\n\t",
               "hex labelAndCertValue",
               (unsigned int) labelcert);
            if (pszSPIF_secCattagSecSetString[0] != '\0')
               free(pszSPIF_secCattagSecSetString);
            
            // do error handling
            throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
         }
         
         // Increment cat_count.
         cat_count++;
         
         // IF owner->singleCategorySelectionPolicy == 1 AND
         // cat_count > 1 THEN
         if ((owner->singleCategorySelectionPolicy != NULL) &&
            (*owner->singleCategorySelectionPolicy == 1) &&
            (cat_count > 1))
         {
            // do error handling
            char errStr[ACL_STR_BUF_LEN*2];
            long labelcert = j;
            CreateErrorStringForLabel(errStr,
               "Single category error\n\tTag Set Name",
               tagType, labelcert, spif, tagSetName,
               "(0=restrictive, 1=enumerated, 2=permissive, or 3=freeform)",
               &(*pMatchCat));
            
            throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
         }
         
         // IF pMatchCat->requiredClass != NULL AND pMatchCat->
         // requiredClass != securityLabel->sec_class THEN
         if ((pMatchCat->requiredClass != NULL) &&
            (*pMatchCat->requiredClass !=
            *this->security_classification))
         {
            // do error handling
            char errStr[ACL_STR_BUF_LEN*2];
            long labelcert = j;
            CreateErrorStringForLabel(errStr,
               "requiredClass doesn't match:\n\tTag Set Name",
               tagType, labelcert, spif, tagSetName,
               "(0=restrictive, 1=enumerated, 2=permissive, or 3=freeform)",
               &(*pMatchCat));       //  RWC;TESTED
            char errStr2[ACL_STR_BUF_LEN*2];
            
            sprintf(errStr2, "\n\trequiredClass=%d", (unsigned int)*pMatchCat->requiredClass);
            strcat(errStr, errStr2);     // ADD requiredClass description to error string.
            
            throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
         }
         
         if (this->security_classification != NULL)
         {
            // IF pMatchCat->excludedClass != NULL THEN
            if (pMatchCat->excludedClass != NULL)
            {
               // LOOP thru pMatchCat->excludedClass linked
               // list until end of list:
               TagCategoriesSeqOf2::iterator pOptClassData;
               
               for (pOptClassData = pMatchCat->excludedClass->begin();
                    pOptClassData != pMatchCat->excludedClass->end();
                    pOptClassData++)
               {
                  // IF current pMatchCat->excludedClass->
                  // pOptClassData == securityLabel->sec_class THEN
                  if (*pOptClassData ==
                     *this->security_classification)
                  {
                     AclString errStr;
                     long sec_class = *this->security_classification;
                     long labelcert = j;
                     
                     errStr << "Found Excluded Classification: "
                        << sec_class << "\n"
                        << "Excluded by:\n"
                        << "tag_set_name=" << (const char *) tagSetNameOid << "\n";
                     CSecurityTag::getTagTypeStr(tagType, errStr);
                     errStr << "\nLACV=" << labelcert;
                     // do error handling
                     throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr.str());
                  }
               } // ENDLOOP
            }  // ENDIF pMatchCat->excludedClass != NULL
         }
         
         // IF pMatchCat->excludedCategory != NULL then call
         // excludedCatCheck to ensure that none of the excluded
         // categories listed in the SPIF for the security
         // category value are present in the security label.
         if (pMatchCat->excludedCategory != NULL)
         {
            excludedCatCheck(*pMatchCat->excludedCategory, spif);
         }
         
         // IF pMatchCat->requiredCategory != NULL then call
         // requiredCatCheck to ensure that the required
         // categories listed in the SPIF for the security
         // category value are present in the security label.
         if (pMatchCat->requiredCategory != NULL)
         {
            requiredCatCheck(*pMatchCat->requiredCategory, spif, &(*pMatchCat));
         }
         
         // IF m_obsAccept != 1 AND pMatchCat->obsolete == 1 THEN
         if ((this->m_obsAccept != true) &&
            (pMatchCat->obsolete != NULL) &&
            (*pMatchCat->obsolete == 1))
         {
            char errStr[ACL_STR_BUF_LEN*2];
            long labelcert = j;
            CreateErrorStringForLabel(errStr,
               "Obsolete category error:\n\tTag Set Name",
               tagType, labelcert, spif,tagSetName,
               "(0=restrictive, 1=enumerated, 2=permissive, or 3=freeform)",
               &(*pMatchCat));
            
            // do error handling
            throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
         }
      }
   }
}

void SecurityLabel::checkSecurityAttributes(const AsnSetOf<SNACC::SecurityAttribute>& attributeFlags,
                          const SNACC::TagSetName& tagSetName,
                          int tagType,
                          const SPIF &spif)
{   
   FUNC("SecurityLabel::checkSecurityAttributes");
   AsnOid tagSetNameOid(tagSetName);

   // Set cat_count (local long) to 0.
   long cat_count = 0;
   
   // LOOP thru attributeFlags until end of array:
   SecurityTagSeq1SetOf::const_iterator iSecAttr = attributeFlags.begin();
   for(iSecAttr ; iSecAttr != attributeFlags.end(); iSecAttr++)
   {
      // LOOP thru SPIF SecurityCategoryTagSets linked list
      // until pMatchCat != NULL OR end of list:
      SecurityCategoryTagSets::iterator pSecCatTag;
      SecurityCategoryTagSetSeqOf::iterator owner;
      bool foundMatchCat = false;
      SecurityCategoryTagSeqOf::iterator pMatchCat;
      
      for (pSecCatTag = spif.spiftoSign.securityCategoryTagSets->begin();
           pSecCatTag != spif.spiftoSign.securityCategoryTagSets->end() &&
           ! foundMatchCat; pSecCatTag++)
      {
         // IF current securityLabel tag_set_name == current
         // SPIF securityCategoryTagSetName THEN (found
         // correct SPIF SecurityCategoryTagSet)
         if (tagSetName ==
            pSecCatTag->securityCategoryTagSetName)
         {
            // LOOP thru current SPIF securityCategoryTags
            // linked list until pMatchCat != NULL OR end of
            // list:
            SecurityCategoryTagSetSeqOf::iterator pSecCat;
            for (pSecCat = pSecCatTag->securityCategoryTags.begin();
                 pSecCat != pSecCatTag->securityCategoryTags.end() &&
                 ! foundMatchCat; pSecCat++)
            {
               // IF current securityLabel tag_type ==
               // current SPIF tag_type THEN (found correct
               // SPIF SecurityCategoryTag)
               if (CSecurityTag::isTagTypeEqual(tagType, *pSecCat))
               {
                  // LOOP thru current SPIF tagCategories
                  // linked list until pMatchCat != NULL OR
                  // end of list:
                  SecurityCategoryTagSeqOf::iterator pTagCats;
                  for (pTagCats = pSecCat->tagCategories.begin();
                       pTagCats != pSecCat->tagCategories.end() &&
                       ! foundMatchCat; pTagCats++)
                  {
                     // IF current SPIF labelAndCertValue ==
                     // current securityLabel SecurityAttribute
                     // (1rst array value) THEN (found correct
                     // SPIF TagCategories) set pMatchCat to
                     // point to current SPIF tagCategories
                     if (pTagCats->labelAndCertValue ==
                        *iSecAttr)
                     {
                        foundMatchCat = true;
                        pMatchCat = pTagCats;
                        owner = pSecCat;
                     }
                  } // ENDLOOP
               }
            } // ENDLOOP
         }
      } // ENDLOOP
      
      // IF pMatchCat == NULL THEN (SPIF does not include
      // securityLabel security category value so return error)
      if (!foundMatchCat)
      {
         char errStr[ACL_STR_BUF_LEN];
         long labelcert = *iSecAttr;
         
         sprintf(errStr, "%s%s=%s%s=%ld %s %s=0x%02X",
            "Bad labelAndCert value:\n\t",
            "Tag Set Name", (const char *) tagSetNameOid,
            "\n\ttagType", tagType,
            "(0=restrictive, 1=enumerated, 2=permissive,",
            "or 3=freeform)\n\thex labelAndCertValue",
            (unsigned int) labelcert);
         
         // do error handling
         throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
      }
      
      // Increment cat_count.
      cat_count++;
      
      // IF owner->singleCategorySelectionPolicy == 1 AND
      // cat_count > 1 THEN
      if ((owner->singleCategorySelectionPolicy != NULL) &&
         (*owner->singleCategorySelectionPolicy == 1) &&
         (cat_count > 1))
      {
         // do error handling
         char errStr[ACL_STR_BUF_LEN*2];
         long labelcert = *iSecAttr;
         CreateErrorStringForLabel(errStr,
            "Single category error:\n\tTag Set Name",
            tagType, labelcert, spif, tagSetName,
            "(0=restrictive, 1=enumerated, 2=permissive, or 3=freeform)",
            &(*pMatchCat));       //  RWC;TESTED
         
         throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
      }
      
      // IF pMatchCat->requiredClass != NULL AND pMatchCat->
      // requiredClass != securityLabel->sec_class THEN
      if ((pMatchCat->requiredClass != NULL) &&
         (*pMatchCat->requiredClass !=
         *security_classification))
      {
         char errStr[ACL_STR_BUF_LEN*2];
         long labelcert = *iSecAttr;
         CreateErrorStringForLabel(errStr,
            "requiredClass doesn't match:\n\tTag Set Name",
            tagType, labelcert, spif, tagSetName,
            "(0=restrictive, 1=enumerated, 2=permissive, or 3=freeform)",
            &(*pMatchCat));       //  RWC;TESTED
         
         throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
      }
      
      if (this->security_classification != NULL)
      {
         // IF pMatchCat->excludedClass != NULL THEN
         if (pMatchCat->excludedClass != NULL)
         {
            // LOOP thru pMatchCat->excludedClass linked list
            // until end of list:
            TagCategoriesSeqOf2::iterator pOptClassData;
            for (pOptClassData = pMatchCat->excludedClass->begin();
            pOptClassData != pMatchCat->excludedClass->end();
            pOptClassData++)
            {
               // IF current pMatchCat->excludedClass->
               // pOptClassData == securityLabel->sec_class THEN
               if (*pOptClassData ==
                  *security_classification)
               {
                  AclString errStr;
                  long sec_class = *security_classification;
                  long labelcert = *iSecAttr;
                  
                  errStr << "Found Excluded Classification: "
                     << sec_class << "\n"
                     << "Excluded by:\n"
                     << "tag_set_name=" << (const char *) tagSetNameOid << "\n";
                  CSecurityTag::getTagTypeStr(tagType, errStr);
                  errStr << "\nLACV=" << labelcert;
                  
                  // do error handling
                  throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr.str());
               }
            } // ENDLOOP
         }  // ENDIF pMatchCat->excludedClass != NULL
      }
      
      // IF pMatchCat->excludedCategory != NULL then call
      // excludedCatCheck to ensure that none of the excluded
      // categories listed in the SPIF for the security
      // category value are present in the security label.
      if (pMatchCat->excludedCategory != NULL)
      {
         excludedCatCheck(*pMatchCat->excludedCategory, spif);
      }
      
      // IF pMatchCat->requiredCategory != NULL then call
      // requiredCatCheck to ensure that the required
      // categories listed in the SPIF for the security
      // category value are present in the security label.
      if (pMatchCat->requiredCategory != NULL)
      {
         requiredCatCheck(*pMatchCat->requiredCategory, spif, &(*pMatchCat));
      }
      
      // IF m_obsAccept != 1 AND pMatchCat->obsolete == 1 THEN
      if ((this->m_obsAccept != true) &&
         (pMatchCat->obsolete != NULL) &&
         (*pMatchCat->obsolete == 1))
      {
         char errStr[ACL_STR_BUF_LEN*2];
         long labelcert = *iSecAttr;
         CreateErrorStringForLabel(errStr,
            "Obsolete category error:\n\tTag Set Name",
            tagType, labelcert, spif,tagSetName,
            "(0=restrictive, 1=enumerated, 2=permissive, or 3=freeform)",
            &(*pMatchCat));
         
         // do error handling
         throw ACL_EXCEPT(ACL_LABEL_CHECK_ERROR, errStr);
      }
   }
}

// isIncoming:
//
bool SecurityLabel::isIncoming(void)
{
   return false;
} // END OF MEMBER FUNCTION isIncoming

// isOutgoing:
//
bool SecurityLabel::isOutgoing(void)
{
   return false;
} // END OF MEMBER FUNCTION isOutgoing

// isIncoming:
//
bool IncomingLabel::isIncoming(void)
{ return true;} // END OF MEMBER FUNCTION isIncoming

// isOutgoing:
//
bool OutgoingLabel::isOutgoing(void)
{ return true;} // END OF MEMBER FUNCTION isOutgoing

void DecodeAsnAny(AsnAny& any, AsnType* pValue)
{
   // Decode the AsnAny
   SNACC::AsnLen bytesDecoded;
   any.value = pValue;
   try
   {
      any.value->BDec(*any.anyBuf, bytesDecoded);
   } 
   catch (...)
   {
      any.anyBuf->ResetMode();
      throw;
   }
   any.anyBuf->ResetMode();
}

TagType7Data& GetDecodedTagType7(AsnAny& any)
{
   FUNC("GetDecodedTagType7");
   if (any.value == NULL)
   {
      // Decode the TagType7 data
      try 
      {
         DecodeAsnAny(any, new TagType7Data);
      } 
      catch (...)
      {
         throw ACL_EXCEPT(ACL_DECODE_ERROR,"Error decoding Tag Type 7 data");
      }
   }
   return *((TagType7Data*)any.value);
}

// END OF acllabel.cpp

_END_NAMESPACE_ACL
