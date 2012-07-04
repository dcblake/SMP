//////////////////////////////////////////////////////////////////////////////
// aclsectag.cpp
// These routines support the CSecurityTag Class
// CONSTRUCTOR(s):
//   CSecurityTag()
// MEMBER FUNCTIONS:
//   enumAnd(SecTagPrivList *&results, SecTagPrivList &userEnum,
//                           SecTagPrivList &caEnum)
//   isTagTypeEqual(SecurityTag &secTag, SecurityCategoryTag &secCatTag)
//   findLabelAndCertValue(SecurityTags &o, AsnInt &labelAndCertValue,
//                                         TagTypeValue &tagtype)
//   permissiveCheck(AsnBits &permissive, AsnBits &labelValue)
//   restrictiveCheck(AsnBits &restrictive, AsnBits &labelValue)
//   enumeratedAttributesCheck(SecurityTagSeq1 &secTagEnumerated,
//          SecurityTagPrivilegeSetOf &secTagPrivEnumerated,
//          bool enumRestrictive)
//   addTagSet(StandardSecurityLabel *&pLblTagSets, AsnOid &spfTagSetOid,
//          AsnInt &labelAndCertValue, SecurityCategoryTag &spfCatTag)
//   Print (ostream &os) const
//////////////////////////////////////////////////////////////////////////////

#include <strstream>
#include "aclinternal.h"


_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR:
//
CSecurityTag::CSecurityTag()
{
} // END OF CONSTRUCTOR

// enumAnd:
//
// Compare the enumerated Attributes of the user certificate and the CA
//   (or PCA) certificate. Perform a bitwise and of the two (wherever the values
//   match, set the corresponding value in results).
//
// Note the typedef SecurityTagPrivilegeSetOf SecTagPrivList in aclinternal.h
//
void CSecurityTag::enumAnd(SecTagPrivList *&results, SecTagPrivList &userEnum,
                           SecTagPrivList &caEnum)
{
   results = new SecTagPrivList;
   SecTagPrivList::iterator pTmpUserSecAttr;
   SecTagPrivList::iterator pTmpCaSecAttr;

   // Loop through the User Certificate enumerated Attributes
   for(pTmpUserSecAttr = userEnum.begin(); pTmpUserSecAttr != userEnum.end(); pTmpUserSecAttr++)
   {
      // Loop through the CA Certificate enumerated Attributes
      for(pTmpCaSecAttr = caEnum.begin(); pTmpCaSecAttr != caEnum.end(); pTmpCaSecAttr++)
      {
         // Where the two match create the same attribute in the results
         if (*pTmpUserSecAttr == *pTmpCaSecAttr)
         {
            results->push_back(*pTmpUserSecAttr);
         }
      }
   }
} // END OF MEMBER FUNCTION enumAnd

// isTagTypeEqual:
//
// Compare tag_type in secTag and secCatTag and return true if they are equal.
//
bool CSecurityTag::isTagTypeEqual(const SecurityTag &secTag, SecurityCategoryTag &secCatTag)
{
   if (secTag.choiceId == SecurityTag::restrictivebitMapCid &&
      secCatTag.tagType == (AsnInt)TagTypeValue::restricted)
      return true;
   else if (secTag.choiceId == SecurityTag::enumeratedAttributesCid &&
      secCatTag.tagType == (AsnInt)TagTypeValue::enumerated)
      return true;
   else if (secTag.choiceId == SecurityTag::permissivebitMapCid &&
      secCatTag.tagType == (AsnInt)TagTypeValue::permissive)
      return true;
   return false;
} // END OF MEMBER FUNCTION isTagTypeEqual

// findLabelAndCertValue:
//
SecurityTags::const_iterator CSecurityTag::findLabelAndCertValue(const SecurityTags &o,
                                         const AsnIntType labelAndCertValue,
                                         const TagTypeValue &tagtype)
{
   FUNC("CSecurityTag::findLabelAndCertValue");

   SecurityTags::const_iterator pSecTag;
   try
   {
       for ( pSecTag = o.begin(); pSecTag != o.end(); pSecTag++)
       {
          if ( pSecTag->choiceId == restrictivebitMapCid &&
                tagtype == (AsnInt)TagTypeValue::restricted)
          {
             if (CAsnBits::checkBit(pSecTag->restrictivebitMap->attributeFlags,
                labelAndCertValue))
             {
                return pSecTag;
             }
          }
          else if (pSecTag->choiceId == enumeratedAttributesCid &&
             tagtype == (AsnInt)TagTypeValue::enumerated)
          {
             SecurityTagSeq1SetOf::iterator pAsnInt;

             for (pAsnInt = pSecTag->enumeratedAttributes->attributeFlags.begin();
                  pAsnInt != pSecTag->enumeratedAttributes->attributeFlags.end();
                  pAsnInt++)
             {
                 if (*pAsnInt == labelAndCertValue)
                 {
                    return pSecTag;
                 }
             }
          }
          else if (pSecTag->choiceId == permissivebitMapCid &&
             tagtype == (AsnInt)TagTypeValue::permissive)
          {
             if (CAsnBits::checkBit(pSecTag->permissivebitMap->attributeFlags,
                       (size_t )labelAndCertValue))
             {
                 return pSecTag;
             }
          }
          else if (pSecTag->choiceId == freeFormFieldCid &&
             tagtype == (AsnInt)TagTypeValue::tagType7)
          {

             // RWC;WRONG, COMES IN AS BUFFER
             // TagType7Data *tag7data =
             //    (TagType7Data *)pSecTag->freeFormField->value;
             TagType7Data tag7data;
             AsnBuf SNACCBuf;
             AsnLen bytesDecoded;
             pSecTag->freeFormField->BEnc(SNACCBuf);;
             tag7data.BDec(SNACCBuf, bytesDecoded);

             if (pSecTag->freeFormField->value == NULL)
             {
                throw ACL_EXCEPT(ACL_ASN_ERROR,
                   "Unable to decode Tag Type 7 (freeFormField)");
             }

             if (tag7data.choiceId == TagType7Data::bitSetAttributesCid)
             {
                if ( CAsnBits::checkBit( *tag7data.bitSetAttributes,
                   (size_t )labelAndCertValue))
                {
                   return pSecTag;
                }
             }
             else if (tag7data.choiceId == TagType7Data::securityAttributesCid)
             {
                TagType7DataSetOf::iterator pSecAtt;
                for (pSecAtt = tag7data.securityAttributes->begin();
                     pSecAtt != tag7data.securityAttributes->end();
                     pSecAtt++ )
                {
                   if ( *pSecAtt == labelAndCertValue )
                   {
                      return pSecTag;
                   }
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
   return o.end();
} // END OF MEMBER FUNCTION findLabelAndCertValue

// removeLabelAndCertValue:
//
bool CSecurityTag::removeLabelAndCertValue(SecurityTags &o,
                                           const AsnIntType labelAndCertValue,
                                           const TagTypeValue &tagtype)
{
   FUNC("CSecurityTag::removeLabelAndCertValue");

   SecurityTags::iterator pSecTag;
   try
   {
       for ( pSecTag = o.begin(); pSecTag != o.end(); pSecTag++)
       {
          if ( pSecTag->choiceId == restrictivebitMapCid &&
                tagtype == (AsnInt)TagTypeValue::restricted)
          {
             if (CAsnBits::checkBit(pSecTag->restrictivebitMap->attributeFlags,
                (size_t )labelAndCertValue))
             {
                pSecTag->restrictivebitMap->
                   attributeFlags.ClrBit(labelAndCertValue);
                return true;
             }
          }
          else if (pSecTag->choiceId == enumeratedAttributesCid &&
             tagtype == (AsnInt)TagTypeValue::enumerated)
          {
             SecurityTagSeq1SetOf::iterator pAsnInt;
             pAsnInt = pSecTag->enumeratedAttributes->attributeFlags.begin();
             while(pAsnInt != pSecTag->enumeratedAttributes->attributeFlags.end())
             {
                 if (*pAsnInt == labelAndCertValue)
                 {
                    pSecTag->enumeratedAttributes->attributeFlags.erase(pAsnInt);
                    return true;
                 }
                 else
                 {
                    pAsnInt++;
                 }
             }
          }
          else if (pSecTag->choiceId == permissivebitMapCid &&
             tagtype == (AsnInt)TagTypeValue::permissive)
          {
             if (CAsnBits::checkBit(pSecTag->permissivebitMap->attributeFlags,
                       (size_t )labelAndCertValue))
             {
                 pSecTag->permissivebitMap->
                   attributeFlags.ClrBit(labelAndCertValue);
                return true;
             }
          }
          else if (pSecTag->choiceId == freeFormFieldCid &&
             tagtype == (AsnInt)TagTypeValue::tagType7 && pSecTag->freeFormField)
          {

             // NOTE: For efficiency this should be done during the initial
             // decode.
             TagType7Data tag7data;
             AsnLen bytesDecoded;
             AsnBuf SNACCBuf;
             pSecTag->freeFormField->BEnc(SNACCBuf);

          if (SNACCBuf.length())//RWC;pSecTag->freeFormField->anyBuf != NULL)
          {
             //RWC;pSecTag->freeFormField->anyBuf->ResetMode(std::ios_base::in);
                 if (! tag7data.BDecPdu(/*RWC;*pSecTag->freeFormField->anyBuf*/SNACCBuf, bytesDecoded))
             {
               throw ACL_EXCEPT(ACL_ASN_ERROR,
                  "Unable to decode Tag Type 7 (freeFormField)");
             }
          }
          else
            throw ACL_EXCEPT(ACL_ASN_ERROR,
                  "Unable to decode Tag Type 7 (freeFormField)");


             if (tag7data.choiceId == TagType7Data::bitSetAttributesCid)
             {
                if ( CAsnBits::checkBit( *tag7data.bitSetAttributes,
                   (size_t )labelAndCertValue))
                {
                   tag7data.bitSetAttributes->ClrBit(labelAndCertValue);
                   return true;
                }
             }
             else if (tag7data.choiceId == TagType7Data::securityAttributesCid)
             {
                TagType7DataSetOf::iterator pSecAtt;
                pSecAtt = tag7data.securityAttributes->begin();
                while(pSecAtt != tag7data.securityAttributes->end())
                {
                   if ( *pSecAtt == labelAndCertValue )
                   {
                      tag7data.securityAttributes->erase(pSecAtt);
                      return true;
                   }
                   else
                   {
                     pSecAtt++;
                   }
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
   return false;
} // END OF MEMBER FUNCTION removeLabelAndCertValue

// permissiveCheck:
//
// returns true if there is common bit set between labelValue and permissive.
// returns false otherwise.
//
bool CSecurityTag::permissiveCheck(AsnBits &permissive, AsnBits &labelValue)
{
   size_t i = 0;
   bool found = false;
   bool atLeastOne = false;

   for (i = 0; ! found && i < (size_t)(labelValue.BitLen()); i++)
   {
      if (CAsnBits::checkBit(labelValue, i))
      {
         atLeastOne=true;
         if (CAsnBits::checkBit(permissive, i))
         {
            // found a bit that was set in both
            // so we are done.
            found = true;
         }
      }
   }

   // if there are no bits (or it's empty) set in the label's
   // permissive bit string then return true.
   //
   if (!atLeastOne)
      return true;
   else
      return found;
} // END OF MEMBER FUNCTION permissiveCheck

// restrictiveCheck:
//
// Return -1 if all the bits that are in labelValue are also set in
// restrictive bitmap.  Otherwise return the bit position that failed as an
// integer.
//
// NOTE: return values > 0 indicate an error
//
int CSecurityTag::restrictiveCheck(AsnBits &restrictive, AsnBits &labelValue)
{
   size_t i = 0;
   int retVal = -1; // default to success

   for (i = 0; retVal == -1 && i < (size_t)(labelValue.BitLen()); i++)
   {
      if (CAsnBits::checkBit(labelValue, i) &&
          ! CAsnBits::checkBit(restrictive, i) )
      {
         retVal = i; // return bit position that failed.
      }
   }
   return retVal;
} // END OF MEMBER FUNCTION restrictiveCheck

// enumeratedAttributesCheck:
//
// Return 0 if permissive or restrictive check passes.  Return
// the integer value of the attribute that failed on a restrictive
// check.  Return -1 when a permissive check fails.
//
int CSecurityTag::enumeratedAttributesCheck(SecurityTagSeq1 &secTagEnumerated,
                                SecurityTagPrivilegeSetOf
                                     &secTagPrivEnumerated,
                                bool enumRestrictive)
{
   bool done = false;
   long labelTagCount = secTagEnumerated.attributeFlags.size();
   long tagPrivFound = 0;
   int  retVal = 0; // default to success

   // Make sure all attributes in secTagPrivEnumerated
   // are also in secTagEnumerated.
   //

   // For each attribute each attribute in the
   // perform a restrictive or permissive check
   //
   SecurityTagSeq1SetOf::iterator i;
   SecurityTagPrivilegeSetOf::iterator j;
   for(i = secTagEnumerated.attributeFlags.begin();
       i != secTagEnumerated.attributeFlags.end();
       i++)
   {

      for(j = secTagPrivEnumerated.begin(); j != secTagPrivEnumerated.end(); j++)
      {
         // If this is a permissive check and any value in
         // the label also exists in the clearance attribute
         // then return true.
         //
         // If this is a restrictive check and any value in
         // the label is NOT present in the clearance
         // attribute then return false.
         //
//         SNACC::AsnInt iVal = *i;
//         SNACC::AsnInt jVal = *j;
         if (*i == *j)
         {
            tagPrivFound++;
            // if enum is not restrictive (permissive)
            // we only need to match one attribute don't
            // bother checking the rest.
            if (! enumRestrictive )
            {
               done = true;
            }
            break;
         }
      }
      // If the enum is restrictive and we have reached the end of the
      // TagSetPrivileges then there is no point in continuing, this is
      // a failure.  Or if the enum is permissive and we have found one
      // match there is no need to continue, this is successful.
      if (((enumRestrictive) && (j == secTagPrivEnumerated.end())) || done)
      {
         break;
      }
   }
   // IF enumerated attributes are restrictive and the number of
   // TagSetPrivileges found is not equal to the number of Security
   // Label TagSets then return the value of the missing TagSet.
   //
   if ((enumRestrictive) && (tagPrivFound != labelTagCount))
   {
      retVal = *i;
   }
   else
   {
      // IF enumerated attributes are permissive and NO values where
      // found then return -1 to indicate permissive check failure.
      if ((! enumRestrictive) && (tagPrivFound == 0))
      {
         retVal = -1;
      }
   }

   return retVal;
} // END OF MEMBER FUNCTION enumeratedAttributesCheck

void CSecurityTag::addTagSet(StandardSecurityLabel *&pLblTagSets, const AsnOid &spfTagSetOid,
                             const AsnIntType labelAndCertValue,
                             const SecurityCategoryTag &spfCatTag)
{
   StandardSecurityLabel::iterator pNewLblTagSet;
   SecurityTags::iterator pNewSecTag = NULL;
   SecurityTagSeq1SetOf *pEnumAtts = NULL;
   bool found = false;

   if (pLblTagSets == NULL)
   {
      pLblTagSets = new StandardSecurityLabel;
   }

   // FIND TagSet and corresponds to spfTagSetOid if present
   //
   StandardSecurityLabel::iterator pLblTagSet;
   for (pLblTagSet = pLblTagSets->begin(); pLblTagSet != pLblTagSets->end(); pLblTagSet++)
   {
      if (pLblTagSet->tagSetName == spfTagSetOid)
         break;
   }

   // IF tagSet is not present create a new node
   //
   if (pLblTagSet == pLblTagSets->end())
   {
      pNewLblTagSet = pLblTagSets->append();
      pNewSecTag = pNewLblTagSet->securityTags.append();
      found = true;
   }
   else
   {
      // TagSet already exists we don't need to allocate a new node for it.
      //

      // Now let's determine if the labelCertValue is already present.  If it is
      // do nothing.  If not, create a new SecurityTag node.
      //

      // Find tagType.
      SecurityTags::const_iterator i = findLabelAndCertValue(pLblTagSet->securityTags, labelAndCertValue,
         spfCatTag.tagType);

      if (i == pLblTagSet->securityTags.end())
      {
         pNewSecTag = pLblTagSet->securityTags.append();
         found = true;
      }
   }

   if (found)
   {
      switch(spfCatTag.tagType)
      {
      case 1:
         pNewSecTag->choiceId = SecurityTag::restrictivebitMapCid;
         if (pNewSecTag->restrictivebitMap == NULL)
            pNewSecTag->restrictivebitMap = new SecurityTagSeq;
         pNewSecTag->restrictivebitMap->attributeFlags.SetBit(labelAndCertValue);

         break;
      case 6:
         pNewSecTag->choiceId = SecurityTag::permissivebitMapCid;
         if (pNewSecTag->permissivebitMap == NULL)
            pNewSecTag->permissivebitMap = new SecurityTagSeq2;
         pNewSecTag->permissivebitMap->attributeFlags.SetBit(labelAndCertValue);
         break;
      case 2:
         // first determine if this value is already present
         //
         if (pNewSecTag->enumeratedAttributes == NULL)
         {
            pNewSecTag->enumeratedAttributes = new SecurityTagSeq1;
            pNewSecTag->choiceId = SecurityTag::enumeratedAttributesCid;
            pNewSecTag->enumeratedAttributes->attributeFlags.append(labelAndCertValue);
         }
         else
         {
            // enumerateAttributes are present.  If the labelAndCertValue is also
            // present then do nothing.
            //
            SNACC::SecurityTagSeq1SetOf::iterator pEnumAtt;
            bool foundEnumAtt = false;
            pEnumAtts = &pNewSecTag->enumeratedAttributes->attributeFlags;
            for (pEnumAtt = pEnumAtts->begin(); pEnumAtt != pEnumAtts->end(); pEnumAtt++)
            {
               if (*pEnumAtt == labelAndCertValue)
               {
                  foundEnumAtt = true;
                  break;
               }
            }
            if (! foundEnumAtt)
            {
               // labelAndCertValue was not found.  Add it.
               //
               pEnumAtt = pEnumAtts->append(labelAndCertValue);
            }
         }
         break;
      }
   }
}

void CSecurityTag::Print (AclString &os) const
{
  std::stringstream ss;
  switch (choiceId)
  {
    case restrictivebitMapCid:
      os << "restrictivebitMap: ";
      if (restrictivebitMap)
      {
        restrictivebitMap->attributeFlags.Print(ss);
        os.reserve(ss.str().length()+1);
        os.assign(ss.str().data(), ss.str().length());
        os << "\n";
        //ss.rdbuf()->freeze(0);
      }
      else
        os << " (empty)\n";
      break;

    case enumeratedAttributesCid:
      os << "enumeratedAttributes: ";
      if (enumeratedAttributes)
      {
         SecurityTagSeq1SetOf::iterator pSecAtt;
        for (pSecAtt = enumeratedAttributes->attributeFlags.begin();
             pSecAtt != enumeratedAttributes->attributeFlags.end(); pSecAtt++)
        {
           os << *pSecAtt;
        }
        os << "\n";
      }
      else
        os << " (empty)\n";
      break;

    case permissivebitMapCid:
      os << "permissivebitMap: ";
      if (permissivebitMap)
      {
         permissivebitMap->attributeFlags.Print(ss);
         os.reserve(ss.str().length() + 1);
         os.assign(ss.str().data(), ss.str().length());
         os << "\n";
         //ss.rdbuf()->freeze(0);
      }
      else
         os << " (empty)\n";
      break;

  } // end of switch
}

void CSecurityTag::getTagTypeStr(const SecurityTag &secTag, AclString &o)
{
   if (secTag.choiceId == enumeratedAttributesCid)
      o << "tag_type=2 (enumeratedAttributes)";
   else if (secTag.choiceId == permissivebitMapCid)
      o << "tag_type=6 (permissiveBitMap)";
   else if (secTag.choiceId == restrictivebitMapCid)
      o << "tag_type=1 (restrictiveBitMap)";
   else if (secTag.choiceId == freeFormFieldCid)
      o << "tag_type=7 (freeFormField)";
}

_END_NAMESPACE_ACL

// EOF aclsectag.cpp

