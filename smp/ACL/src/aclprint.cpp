//////////////////////////////////////////////////////////////////////////////
// aclprint.cpp
// These routines support the PrintableLabel Class
// CONSTRUCTOR(s):
//   PrintableLabel(void)
//   PrintableLabel(SecurityLabel &secLabel, SPIF &spif)
// DESTRUCTOR:
//   ~PrintableLabel()
// MEMBER FUNCTIONS:
//    getPolicyString(void)
//    getClassificationString(void)
//    getClassificationMarkingData(void)
//    getSecurityCatTagSetList(void)
//    getPrivacyMarkString(void)
//    printLabel(ostream &os)
//    getSecurityCatTagSetStr()
//    getSecurityCatTagList()
//
// These routines support the CMarkingData Class
// MEMBER FUNCTIONS:
//    getMarkingPhrase(void)
//    getMarkingCodes(void)
//
// These routines support the CSecurityCatTagSet Class
// MEMBER FUNCTIONS:
//    getSecCatTagSetNameOID(void)
//    getSecCatTagSetString(void)
//    getSecurityCatTagList(void)
//    removeLabelAndCertValue(int tagType, int spfLACV)
//
// These routines support the CSecurityCatTag Class
// MEMBER FUNCTIONS:
//    getSecurityCatTagNameString(void)
//    getTagType(void)
//    getMarkingCode(void)
//    getMarkingQualifierList(void)
//    getTagCategoryList(void)
//
// These routines support the CTagCategory Class
// MEMBER FUNCTIONS:
//    getSecCategoryNameString(void)
//    getLACV(void)
//    getMarkingData(void)
//
// These routines support the CMarkingQualifier Class
// MEMBER FUNCTIONS:
//    getMarkingQualifier(void)
//    getQualifierCode(void)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"
#include <strstream>

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL
// CONSTRUCTOR:
//
PrintableLabel::PrintableLabel(void)
{
   m_pSPIF = NULL;
} // END OF CONSTRUCTOR

// ALTERNATE CONSTRUCTOR:
//
PrintableLabel::PrintableLabel(SecurityLabel &secLabel, const SPIF &spif)
{
   m_SecLabel = secLabel;
   m_pSPIF = (SPIF *)spif.clone();
} // END OF ALTERNATE CONSTRUCTOR

// DESTRUCTOR:
//
PrintableLabel::~PrintableLabel()
{
   if (m_pSPIF != NULL)
   {
      delete m_pSPIF;
      m_pSPIF = NULL;
   }
} // END OF DESTRUCTOR

// getPolicyString:
// Returns a null terminated character string
// representing the security policy identifier.
//
char * PrintableLabel::getPolicyString(void)
{
   char *policyString=NULL;

   if (m_pSPIF == NULL)
   {
      return("");
   }

   int len = m_pSPIF->spiftoSign.securityPolicyIdData.objectIdName.length();
   if (len > 0)
   {
      policyString = new char[len+1];
      memset(policyString, 0, len+1);
      memcpy(policyString,
              m_pSPIF->spiftoSign.securityPolicyIdData.objectIdName.c_str(), len);
   }

   return(policyString);
} // END OF MEMBER FUNCTION getPolicyString

// getClassificationString:
// Returns a null terminated character string representing
// the security classification name, if present.
//
char * PrintableLabel::getClassificationString(void)
{
   SpiftoSignSeqOf::iterator  pSecClass;
   SpiftoSignSeqOf            *pClassifications=NULL;
   char                       *classificationString=NULL;

   FUNC("PrintableLabel::getClassificationString");
   try
   {
       // If security classification is empty, return NULL
       if (m_SecLabel.security_classification == NULL)
           return NULL;

       // Make a local pointer to the Security Classification list from this SPIF
       pClassifications = &m_pSPIF->spiftoSign.securityClassifications;

       if ((pClassifications != NULL) && (pClassifications->size() > 0))
       {
          // Set current to point to the first in the list

          // Loop through each Security Classification searching for a match between
          // the labelAndCertValue fromt the SPIF and the security_classification
          // value from the label.
          for (pSecClass = pClassifications->begin();
               pSecClass != pClassifications->end(); pSecClass++)
          {
             // When a match is found, create a copy of the Classification String
             // from the SPIF and break out of this loop.
             if (pSecClass->labelAndCertValue == *m_SecLabel.security_classification)
             {
                // COPY THE CLASSIFICATION NAME OUT OF THE APPROPRIATE FORMAT STRING.
                // O.K. this will seem strange.  The Classification Name can be
                // found in one of the following DirectoryString union of format
                // choices:  teletexString, printableString, universalString,
                // utf8String.  Since each of these types is derived from AsnOcts
                // and each is a pointer to the same data, by copying the contents of
                // one choice to a character string, we are in effect copying choices
                // which may have been any of the format selected.  This is why there
                // is no check here for the choiceId before doing this copy.
                //
                ;
                if (pSecClass->classificationName.teletexString->length() > 0)
                {
                   classificationString = strdup(pSecClass->classificationName.teletexString->c_str());
                }
                break;
             } // END IF (labelAndCertValue == security_classification)
          } // END FOR LOOP
       } // END OF NULL CONDITION
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   return(classificationString);
} // END OF MEMBER FUNCTION getClassificationString

// getMarkingData:
// Returns an ACL_List template of CMarkingData.
//   See CMarkingData for details.
//
CMarkingDataList * PrintableLabel::getMarkingData(void)
{
   SpiftoSignSeqOf::iterator   pSecClass;
   SpiftoSignSeqOf            *pClassifications=NULL;
   CMarkingDataList           *pCMarkingDataList=NULL;

   FUNC("PrintableLabel::getMarkingData");
   try
   {
       // If security classification is empty, return NULL
       if (m_SecLabel.security_classification == NULL)
           return NULL;

       // Make a local pointer to the Security Classification list from this SPIF
       pClassifications = &m_pSPIF->spiftoSign.securityClassifications;

       if ((pClassifications != NULL) && (pClassifications->size() > 0))
       {
          // Loop through each Security Classification searching for a match between
          // the labelAndCertValue fromt the SPIF and the security_classification
          // value from the label.
          for (pSecClass = pClassifications->begin();
               pSecClass != pClassifications->end(); pSecClass++)
          {
             // When a match is found, append to the supplied list each of the
             // MarkingData from the SPIF and break out of this loop.
             if (pSecClass->labelAndCertValue == *m_SecLabel.security_classification)
             {
                // markingData is optional so check it
                if ((pSecClass->markingData != NULL)
                 && (pSecClass->markingData->size() > 0))
                {
                   pCMarkingDataList = new CMarkingDataList;

                   SpifSecurityClassificationSeqOf1::iterator i;
                   for (i =  pSecClass->markingData->begin();
                        i != pSecClass->markingData->end(); i++)
                   {
                      pCMarkingDataList->push_back(*i);
                   }
                }
                break;  // MOVED BREAK OUTSIDE OF CONDITIONAL - BG
             } // END IF (labelAndCertValue == security_classification)
          } // END FOR LOOP
       } // END OF NULL CONDITIONAL
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   return(pCMarkingDataList);
} // END OF MEMBER FUNCTION getMarkingData

// getSecurityCatTagSetList:
//
// Order of Security Category Names (and associated marking phrases)
// should be determined by the Security Category Tag Sets found in the
// SPIF, according to SDN.801 Rev B Markings Clarifications
//
// "When creating marking information (i.e. a textual representation)
// from a SecurityLabel, the marking phrase or security category names
// produced will be ordered in the same order as indicated in the
// SecurityCategoryTagSet sequences found within the SPIF."
//
// Returns an ACL_List template of CSecurityCatTag.
//
CSecurityCatTagSetList * PrintableLabel::getSecurityCatTagSetList(void)
{
   CSecurityCatTagSetList   *pSecurityCatTagSetList=NULL;
   SecurityCategoryTagSets  *spfTagSets=NULL;
   SecurityCategoryTagSet    spfSecCatTagSet;
   SecurityCategoryTagSets::iterator spfTagSet;
   StandardSecurityLabel::const_iterator pLblTagSet;
   SecurityTags              lblTags;

   FUNC("PrintableLabel::getSecurityCatTagSetList");

   // TRAVERSE SPIF SecurityCatTagSets TagCategories and find the equivalent
   //          NamedTagSets (StandardSecurityLabel) in m_SecLabel and append
   //          them to a list of SecurityCatTagSet.

   try
   {
      spfTagSets = m_pSPIF->spiftoSign.securityCategoryTagSets;
      if (spfTagSets != NULL)
      {
         // TRAVERSE the SPIF SecurityCategoryTagSets
         for (spfTagSet = spfTagSets->begin();
              spfTagSet != spfTagSets->end(); spfTagSet++)
         {
            // Create a work copy of the SPIF Security Category Tag Set
            spfSecCatTagSet.SecurityCategoryTagSet::operator = (*spfTagSet);
            // TRAVERSE the Label NamedTagSets
            for (pLblTagSet = m_SecLabel.getSSL().begin();
                 pLblTagSet != m_SecLabel.getSSL().end(); pLblTagSet++)
            {
               lblTags = pLblTagSet->securityTags;
               //
               // Compare the securityCategoryTagSetName in the SPIF with the
               // corresponding TagSetName (OID) in the Label
               if (spfTagSet->securityCategoryTagSetName == pLblTagSet->tagSetName)
               {
                  // If there is a match, navigate to the SPIF Tag Categories
                  SecurityCategoryTagSetSeqOf::iterator pSpfSecCatTag;
                  // TRAVERSE securityCategoryTags
                  pSpfSecCatTag =  spfSecCatTagSet.securityCategoryTags.begin();
                  while (pSpfSecCatTag != spfSecCatTagSet.securityCategoryTags.end())
                  {
                     SNACC::SecurityCategoryTagSeqOf::iterator pSpfTagCats;
                     // TRAVERSE tagCategories
                     pSpfTagCats =  pSpfSecCatTag->tagCategories.begin();
                     while ( pSpfTagCats != pSpfSecCatTag->tagCategories.end() )
                     {
                        // removeLACV() will remove the LACV if it's found
                        // in the label securityTags.
                        //
                        if (! CSecurityTag::removeLabelAndCertValue(lblTags,
                                          pSpfTagCats->labelAndCertValue,
                                          pSpfSecCatTag->tagType))
                        {
                           // LACV was not found in label securityTags so
                           // remove it from the SPIF tagCategories.
                           //
                           pSpfTagCats = pSpfSecCatTag->tagCategories.erase(pSpfTagCats);
                        }
                        else
                        {
                           pSpfTagCats++;
                        }
                     } // FOR tagCategories
                     // If all of the tagCategories for the current
                     // securityCategoryTags have been exhausted then remove it.
                     //
                     if (pSpfSecCatTag->tagCategories.size() < 1)
                     {
                        pSpfSecCatTag = spfSecCatTagSet.securityCategoryTags.erase(pSpfSecCatTag);
                     }
                     else
                     {
                        pSpfSecCatTag++;
                     }
                  } // END WHILE securityCategoryTags
                  // If there are securityCategoryTags present in the current
                  // tagset being checked then add the tagSet to the list to be
                  // returned.
                  if (spfSecCatTagSet.securityCategoryTags.size() > 0)
                  {
                     // CONSTRUCT A CSecurityCatTagSet AND
                     // ADD IT TO THE LIST TO RETURN
                     if (pSecurityCatTagSetList == NULL)
                     {
                        pSecurityCatTagSetList = new CSecurityCatTagSetList;
                     }
                     pSecurityCatTagSetList->push_back(spfSecCatTagSet);
                  } // END OF IF spfSecCatTagSet securityCategoryTags size > 0
               } // END OF IF SPIF securityCategoryTagSetName and Label TagSetName
            } // END FOR Label NamedTagSets
         } // END FOR SPIF SecurityCategoryTagSets
      } // END OF CHECK FOR NULL
   } // END TRY BLOCK
   catch (InternalAclException &)
   {
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   if ((pSecurityCatTagSetList == NULL) || (pSecurityCatTagSetList->size() < 1))
   {
     return NULL;
   }

   return(pSecurityCatTagSetList);

} // END OF MEMBER FUNCTION getSecurityCatTagSetList

// getPrivacyMarkString:
// Returns a null terminated character string
// representing the privacy mark, if present.
//
char * PrintableLabel::getPrivacyMarkString(void)
{
   // No comparison, just from the label

   if (this->m_SecLabel.privacy_mark != NULL &&
       this->m_SecLabel.privacy_mark->pString != NULL)
   {
      return ((char *)this->m_SecLabel.privacy_mark->pString->c_str());
   }
   else
   {
      return (char *) 0;
   }
} // END OF MEMBER FUNCTION getPrivacyMarkString

// printLabel:
// Directs a formatted SecurityLabel string security
// to the ostream object 'os'. This string representation
// includes the security-classification and all security-category
// values present in the securityLabel (including applying
// all qualifiers such as prefix, suffix and separator).
// The security-policy-identifier and privacy-mark values
// are not included in this string.
//
// Note: iPosition changes donated by William Adams - NEXOR
//
// iPosition is defaulted to zero.  If not entered the function
// behaves as normal, if you enter a value of either 1,2,3,4 or 8 it will
// return the string for that marking code position.
//
void PrintableLabel::printLabel(AclString &os, int iPosition)
{
   char                   *pClassificationNameStr=NULL;
   CMarkingDataList       *pClassMarkingDataList=NULL;
   CMarkingDataList::iterator pClassMarkingData;
   char                   *pClassMarkingPhrase=NULL;
   AsnIntList             *pClassMarkingCodeList=NULL;
   bool                    bSuppressClassName=false;

   char                   *pSecCatNameStr=NULL;
   bool                    bNoNameDisplay=false;

   char                   *pTagCatMarkingPhrase=NULL;
   AsnIntList             *pTagCatMarkingCodeList=NULL;
   CMarkingQualifierList  *pCMarkingQualifierList=NULL;
   CTagCategoryList       *pCTagCategoryList=NULL;
   bool                    bNoMarkingDisplay=false;

   // This bool is set to false if the page position that was passed in to this function (iPosition)
   // equals the position specified in the marking code
   bool                 bWrongPosition = true;     // (NEXOR-wda) 20/8/01

   // This bool is used to check whether a position has been specified by the marking code since
   // if no specified position then the default position is bottom
   bool                 bPositionSpecified = false;   // (NEXOR-wda) 20/8/01

   CSecurityCatTagSetList *pCSecurityCatTagSetList=NULL;
   CSecurityCatTagSetList::iterator     pCSecurityCatTagSet;
   CSecurityCatTagList    *pCSecurityCatTagList=NULL;
   CSecurityCatTagList::iterator        pCSecurityCatTag;
   unsigned long           displayIndex=0;
//    std::string             classNameSeparator="//";
   std::string             separator="/";
   // String List to accumulate Classification Name Display Information
   StrList                *pClassStrList=NULL;
   StrList::iterator       pClassStr;
   // String List to accumulate Security Categories Display Information
   StrList                *pStrList=NULL;
   StrList::iterator       pStr;
   bool                    bpStrReady = false;
   StrList                *pClassMarkingPhraseStrList=NULL;

   FUNC("PrintableLabel::printLabel");
   try
   {
      pClassStrList = new StrList;

      // Start with the Classification Name and Marking Data associated with it
      pClassificationNameStr = getClassificationString();
      pClassMarkingDataList = getMarkingData();

      // Begin collecting Classification Name display information
      if ((pClassMarkingDataList != NULL)
       && (pClassMarkingDataList->size() > 0))
      {
         for(pClassMarkingData = pClassMarkingDataList->begin();
             pClassMarkingData != pClassMarkingDataList->end(); pClassMarkingData++)
         {
            pClassMarkingPhrase = pClassMarkingData->getMarkingPhrase();
            pClassMarkingCodeList = pClassMarkingData->getMarkingCodes();
            if ((pClassMarkingCodeList != NULL)
             && (pClassMarkingCodeList->size() > 0))
            {
               std::list<AsnInt>::iterator pClassMarkingCode;
               for(pClassMarkingCode = pClassMarkingCodeList->begin();
                   pClassMarkingCode != pClassMarkingCodeList->end(); pClassMarkingCode++)
               {
                  if (*pClassMarkingCode == (AsnInt)MarkingCode::suppressClassName)
                  {
                     bSuppressClassName=true;
                  }
                  if (*pClassMarkingCode == (AsnInt)MarkingCode::noNameDisplay)
                  {
                     bNoNameDisplay=true;
                  }
                  if (*pClassMarkingCode == (AsnInt)MarkingCode::noMarkingDisplay)
                  {
                     bNoMarkingDisplay=true;
                  }
                  /**********************************************
                  // Start of changes by William Adams - NEXOR   //
                  **********************************************/

                  /**********************************************************************************
                  // Check to see if any of the marking codes are equal to the position passed in //
                  **********************************************************************************/
                  if ( *pClassMarkingCode == iPosition )   // (NEXOR-wda) 20/8/01
                  {
                     bWrongPosition = false;
                  }

                  /**********************************************************************************
                  // Check to see if any of the marking code is top and bottom                 //
                  **********************************************************************************/
                  if ( *pClassMarkingCode == (AsnInt)MarkingCode::pageTopBottom )
                  {
                     if ( ( iPosition == 1 ) || ( iPosition == 2 ) )
                     {
                        bWrongPosition = false;
                     }
                  }
                  /**********************************************************************************
                  // Check to see if any of the marking codes specify a position               //
                  **********************************************************************************/
                  if ( ( *pClassMarkingCode == 1 ) || ( *pClassMarkingCode == 2 ) || ( *pClassMarkingCode == 3 ) || ( *pClassMarkingCode == 4 ) || ( *pClassMarkingCode == 8 ) ) // (NEXOR-wda) 20/8/01
                  {
                     bPositionSpecified = true;
                  }

                  /**********************************************
                  // End of changes by William Adams - NEXOR  //
                  **********************************************/
               }
               /**********************************************
               // Start of changes by William Adams - NEXOR //
               **********************************************/

               /**********************************************************************************
               // Set the display flags depending on requested position                   //
               // If the position asked for is not in the marking code then set display bools   //
               // false. Check that iPosition is not zero since this is the default value and   //
               // causes the behaviour to stay the same.                               //
               // !( !bPositionSpecified && ( iPosition == 2 ) ) checks that a position was  //
               // specified, if not and the bottom (default) position was asked for then dont   //
               // disable display of names.                                      //
               **********************************************************************************/
               if ( iPosition && bWrongPosition && !( !bPositionSpecified && ( iPosition == 2 ) ) ) // (NEXOR-wda) 20/8/01
               {

                  if ( ( iPosition == 4 ) || ( iPosition == 8 ) || bPositionSpecified )
                  {
                     bNoNameDisplay = true;
                  }
                  bNoMarkingDisplay = true;
               }

               /**********************************************
               // End of changes by William Adams - NEXOR   //
               **********************************************/

            }
            // PROCESS THE Marking Phrase INFORMATION
            if (bNoMarkingDisplay == false) // Display Marking Phrase
            {
               // CONSTRUCT A MarkingPhrase NODE
               if (pClassMarkingPhraseStrList == NULL)
               {
                  pClassMarkingPhraseStrList = new StrList;
               }
               pClassMarkingPhraseStrList->push_back(pClassMarkingPhrase);
            }
         } // END OF Marking Data LOOP
      } // END OF COLLECTION OF CLASSIFICATION INFORMATION

      /**********************************************
      // Start of changes by William Adams - NEXOR //
      **********************************************/
      /**********************************************************************************
      // Also do the check here since there is not always marking data on the          //
      // classification so the last check would have been skipped                   //
      **********************************************************************************/
      if ( bWrongPosition && iPosition ) // (NEXOR-wda) 20/8/01
      {

         if ( ( iPosition == 4 ) || ( iPosition == 8 ) || bPositionSpecified )
         {
            bNoNameDisplay = true;
         }
         bNoMarkingDisplay = true;
      }

      // reset boolean ready for category processing
      bWrongPosition = true;
      bPositionSpecified = false;

      /**********************************************
      // End of changes by William Adams - NEXOR   //
      **********************************************/

      // BUILD THE Classification INFORMATION PORTION OF THE LABEL STRING
      if (bSuppressClassName == false) // (9) Display Classification name
      {
         if (bNoNameDisplay == false) // (5) Display Classification Name
         {
            if (pClassificationNameStr != NULL)
            {
               pClassStr = pClassStrList->insert(pClassStrList->end(), pClassificationNameStr);
               bpStrReady = true;
            }
         }
      }

      if (bNoMarkingDisplay == false) // (6) Display Marking Phrase
      {
         // NOW APPEND THE MARKING PHRASE(S)
         if ((pClassMarkingPhraseStrList != NULL)
          && (pClassMarkingPhraseStrList->size() > 0))
         {
            StrList::iterator pClassMarkingPhraseStr;
            for (pClassMarkingPhraseStr = pClassMarkingPhraseStrList->begin();
                 pClassMarkingPhraseStr != pClassMarkingPhraseStrList->end();
                 pClassMarkingPhraseStr++)
            {
               pClassStr = pClassStrList->insert(pClassStrList->end(), *pClassMarkingPhraseStr);
            }
         }
      }

      pStrList = new StrList;

      // Begin collecting Security Category display information
      // Start by gathering the list of Security Category Tag Sets
      pCSecurityCatTagSetList = getSecurityCatTagSetList();
      if ((pCSecurityCatTagSetList != NULL)
       && (pCSecurityCatTagSetList->size() > 0))
      {
         // Loop through each Tag Set in the list
         for(pCSecurityCatTagSet =  pCSecurityCatTagSetList->begin();
             pCSecurityCatTagSet != pCSecurityCatTagSetList->end();
             pCSecurityCatTagSet++)
         {
            // Here we have access to each Security Category Tag Set Name OID
            // and to each Security Category Tag Set String
            //

            // Check for at least one Security Category Tag in the list
            pCSecurityCatTagList = pCSecurityCatTagSet->getSecurityCatTagList();
            if ((pCSecurityCatTagList != NULL)
             && (pCSecurityCatTagList->size() > 0))
            {
               // Each Security Category Tag contains Marking Qualifiers
               // and a sequence of TagCategories
               for(pCSecurityCatTag =  pCSecurityCatTagList->begin();
                   pCSecurityCatTag != pCSecurityCatTagList->end();
                   pCSecurityCatTag++)
               {
                  std::string       *pSecCatSeparator=NULL;
                  std::string       *pSecCatPrefix=NULL;
                  std::string       *pSecCatSuffix=NULL;
                  CTagCategoryList::iterator pCTagCategory;
                  CMarkingQualifierList::iterator pCMarkingQualifier;

                  pSecCatSeparator = new std::string("/");

                  // FOR THE PURPOSES OF THIS FUNCTION WE CAN IGNORE THIS Marking
                  // Code PORTION OF Marking Qualifiers.  ACCORDING TO THE
                  // SDN.801 Rev B Markings Clarifications DOCUMENT
                  // "Only one of marking codes 1,2,3,4, & 8 is allowed
                  // within MarkingQualifiers"; AND WITHIN THIS FUNCTION WE ARE
                  // IGNORING POSITIONING Marking Codes.

                  pCMarkingQualifierList = pCSecurityCatTag->getMarkingQualifierList();
                  // Check for a least one Marking Qualifier
                  if ((pCMarkingQualifierList != NULL)
                   && (pCMarkingQualifierList->size() > 0))
                  {
                     // Each Marking Qualifier contains a qualifier code and a
                     // Marking Qualifier
                     for(pCMarkingQualifier =  pCMarkingQualifierList->begin();
                         pCMarkingQualifier != pCMarkingQualifierList->end();
                         pCMarkingQualifier++)
                     {
                        char *tmpMarkingQualifier=NULL;
                        int   tmpQualifierCode=-1;
                        tmpMarkingQualifier =
                           pCMarkingQualifier->getMarkingQualifier();
                        tmpQualifierCode = pCMarkingQualifier->getQualifierCode();
                        if (tmpMarkingQualifier != NULL)
                        {
                           if (tmpQualifierCode != -1)
                           {
                              if (tmpQualifierCode ==
                                  QualifierCode::prefixQualifier)
                              {
                                 if (pSecCatPrefix != NULL)
                                 {
                                    delete pSecCatPrefix;
                                 }
                                 pSecCatPrefix = new std::string(tmpMarkingQualifier);
                              }
                              if (tmpQualifierCode ==
                                  QualifierCode::suffixQualifier)
                              {
                                 if (pSecCatSuffix != NULL)
                                 {
                                    delete pSecCatSuffix;
                                 }
                                 pSecCatSuffix = new std::string(tmpMarkingQualifier);
                              }
                              if (tmpQualifierCode ==
                                  QualifierCode::separatorQualifier)
                              {
                                 if (pSecCatSeparator != NULL)
                                 {
                                    delete pSecCatSeparator;
                                 }
                                 pSecCatSeparator = new std::string(tmpMarkingQualifier);
                              }
                           } // END OF CHECK FOR Qualifier Code
                           else
                           {
                              if (tmpMarkingQualifier != NULL)
                              {
                                 delete tmpMarkingQualifier;
                              }
                              // Error condition (there should never be a
                              // Marking Code without a Marking Qualifier)
                              throw ACL_EXCEPT(ACL_NO_MARKING_QUALIFIER,
                                 "Missing Marking Qualifier in Security Label");
                           }
                           if (tmpMarkingQualifier)
                           {
                              free(tmpMarkingQualifier);
                           }
                           tmpMarkingQualifier = NULL;
                        } // END OF CHECK FOR Marking Qualifier
                        else
                        {
                           if (tmpQualifierCode != -1)
                           {
                              // Error condition (there should never be a
                              // Marking Qualifier without a Marking Code)
                              throw ACL_EXCEPT(ACL_NO_MARKING_CODE,
                                   "Missing Marking Code in Security Label");
                           }
                        }
                     } // END OF Marking Qualifier List LOOP
                  } // END OF CHECK FOR Marking Qualifiers
                  if (pCMarkingQualifierList != NULL)
                  {
                     delete pCMarkingQualifierList;
                  }
                  // Check for TagCategories
                  // For each Tag Category collect the Security Category Name and
                  // all marking phrases (if there are any), as well as any
                  // Marking Codes associated with the marking phrases.

                  pCTagCategoryList = pCSecurityCatTag->getTagCategoryList();
                  if ((pCTagCategoryList != NULL)
                   && (pCTagCategoryList->size() > 0))
                  {
                     int tagCatIndex = 0;
                     for(tagCatIndex = 1,
                         pCTagCategory =  pCTagCategoryList->begin();
                         pCTagCategory != pCTagCategoryList->end();
                         pCTagCategory++, tagCatIndex++)
                     {
                        CMarkingDataList *pTagCatMarkingDataList=NULL;
                        CMarkingDataList::iterator pTagCatMarkingData;
                        bool              bTagCatSuppressClassName=false;
                        bool              bTagCatNoNameDisplay=false;
                        bool              bTagCatNoMarkingDisplay=false;
                        std::list<AsnInt>::iterator pTagCatMarkingCode;
                        std::string       separator="/";
                        StrList          *pMarkingPhraseStrList=NULL;

                        pSecCatNameStr = pCTagCategory->getSecCategoryNameString();

                        pTagCatMarkingDataList = pCTagCategory->getMarkingData();
                        if ((pTagCatMarkingDataList != NULL)
                         && (pTagCatMarkingDataList->size() > 0))
                        {
                           std::string *pTmpStr=NULL;
                           for(pTagCatMarkingData =  pTagCatMarkingDataList->begin();
                               pTagCatMarkingData != pTagCatMarkingDataList->end();
                               pTagCatMarkingData++)
                           {
                              pTagCatMarkingPhrase = pTagCatMarkingData->getMarkingPhrase();
                              // FOR DISPLAY
                              if (pTagCatMarkingPhrase != NULL)
                              {
                                 //
                                 // CONSTRUCT A MarkingPhrase NODE
                                 if (pMarkingPhraseStrList == NULL)
                                 {
                                    pMarkingPhraseStrList = new StrList;
                                 }
                                 // Accumulate each Marking Phrase'
                                 pMarkingPhraseStrList->push_back(pTagCatMarkingPhrase);
                              }
                              pTagCatMarkingCodeList = pTagCatMarkingData->getMarkingCodes();
                              if ((pTagCatMarkingCodeList != NULL)
                               && (pTagCatMarkingCodeList->size() > 0))
                              {
                                 for(pTagCatMarkingCode =  pTagCatMarkingCodeList->begin();
                                     pTagCatMarkingCode != pTagCatMarkingCodeList->end();
                                     pTagCatMarkingCode++)
                                 {
                                    if (*pTagCatMarkingCode == (AsnInt)MarkingCode::suppressClassName)
                                    {
                                       bTagCatSuppressClassName = true;
                                    }
                                    if (*pTagCatMarkingCode == (AsnInt)MarkingCode::noNameDisplay)
                                    {
                                       bTagCatNoNameDisplay = true;
                                    }
                                    if (*pTagCatMarkingCode == (AsnInt)MarkingCode::noMarkingDisplay)
                                    {
                                       bTagCatNoMarkingDisplay = true;
                                    }

                                    /**********************************************
                                    // Start of changes by William Adams - NEXOR //
                                    **********************************************/
                                    // Similar checks here for the categories as were done for the classifications
                                    if ( *pTagCatMarkingCode == iPosition ) // (NEXOR-wda) 20/8/01
                                    {
                                       bWrongPosition = false;
                                    }

                                    if ( *pTagCatMarkingCode == (AsnInt)MarkingCode::pageTopBottom )
                                    {
                                       if ( ( iPosition == 1 ) || ( iPosition == 2 ) )
                                       {
                                          bWrongPosition = false;
                                       }

                                    }
                                    if ((*pTagCatMarkingCode == 1 ) || ( *pTagCatMarkingCode == 2 )
                                     || ( *pTagCatMarkingCode == 3 ) || ( *pTagCatMarkingCode == 4 )
                                     || ( *pTagCatMarkingCode == 8 ) )
                                    {
                                       bPositionSpecified = true;
                                    }
                                    /**********************************************
                                    // End of changes by William Adams - NEXOR   //
                                    **********************************************/
                                 }
                                 if (pTagCatMarkingCodeList != NULL)
                                 {
                                    delete pTagCatMarkingCodeList;
                                 }
                              } // END OF Tag Category Marking Code LOOP
                           } // END OF Tag Category Marking Data LOOP
                        } // END OF CHECK FOR Marking Data

                        // PROCESSING ACCUMULATED Security Category INFORMATION
                        // (Security Category for Tag Category)
                        if (bTagCatSuppressClassName == true)
                        { // SET THE INDEX TO ELIMINATE THE Classification Name
                           displayIndex = 1;
                        }

                        /**********************************************
                        // Start of changes by William Adams - NEXOR //
                        **********************************************/

                        // (NEXOR-wda) 20/8/01
                        if ( iPosition && bWrongPosition && !( !bPositionSpecified && ( iPosition == 2 ) ) )
                        {
                           if ( ( iPosition == 4 ) || ( iPosition == 8 ) || bPositionSpecified )
                           {
                              bTagCatNoNameDisplay = true;
                           }
                           bTagCatNoMarkingDisplay = true;
                        }

                        bWrongPosition = true;
                        /**********************************************
                        // End of changes by William Adams - NEXOR   //
                        **********************************************/

                        // Display Security Category Name
                        if (bTagCatNoNameDisplay == false)
                        {  // Check Classification level Marking Code
                           if (bNoNameDisplay == false)
                           {
//                             // IF THIS IS NOT THE FIRST ITEM IN THE PRINTABLE STRING LIST
//                             if ((pClassStrList != NULL) || (pClassStrList->size() > 0))
//                              && (pCTagCategory == pCTagCategoryList->begin()))
//                             {
//                                // ADD THE Classification Name SEPARATOR TO THE LIST
//                                pStr = pStrList->insert(pStrList->end(), classNameSeparator);
//                             }
                              if (pCTagCategory != pCTagCategoryList->begin())
                              {
                                 // ADD THE SEPARATOR
                                 pStr = pStrList->insert(pStrList->end(), *pSecCatSeparator);
                              }
                              if ((pSecCatPrefix != NULL)
                               && (pCTagCategory == pCTagCategoryList->begin()))
                              {
                                 pStr = pStrList->insert(pStrList->end(), *pSecCatPrefix);
                              }
                              pStrList->push_back(pSecCatNameStr);
                           } // End of Classification level Marking Code Check
                        } // End of Security Category level Marking Code Check

                        if (bTagCatNoMarkingDisplay == false) // Display Marking Phrase
                        {
                           if ((pMarkingPhraseStrList != NULL)
                            && (pMarkingPhraseStrList->size() > 0))
                           {
                              StrList::iterator pMarkingPhraseStr;
                              for(pMarkingPhraseStr =  pMarkingPhraseStrList->begin();
                                  pMarkingPhraseStr != pMarkingPhraseStrList->end();
                                  pMarkingPhraseStr++)
                              {
                                 int same=0;
                                 // COMPARE THE CURRENT STRING TO THE LAST ONE IN THE LIST
                                 same = pMarkingPhraseStr->compare(pMarkingPhraseStrList->back());
//                                // IF THERE ARE ITEMS IN THE Classification Name STRING LIST
//                                // AND THIS IS THE FIRST ITEM IN THE PRINTABLE STRING LIST
//                                if ((pClassStrList != NULL) || (pClassStrList->size() > 0)
//                                 && (pStrList->size() == 0))
//                                {
//                                   // ADD THE Classification Name SEPARATOR TO THE LIST
//                                   pStr = pStrList->insert(pStrList->end(), classNameSeparator);
//                                }
                                 // IF THIS IS NOT THE FIRST ITEM IN THE LIST
                                 if (pStrList->size() > 0)
                                 {
                                    // ADD THE SEPARATOR
                                    pStr = pStrList->insert(pStrList->end(), *pSecCatSeparator);
                                 }
                                 // IS THIS THE FIRST Marking Phrase
                                 if ((pMarkingPhraseStr == pMarkingPhraseStrList->begin())
                                  && (pSecCatPrefix != NULL))
                                 {
                                    // ADD THE PREFIX SEPARATOR
                                    pStr = pStrList->insert(pStrList->end(), *pSecCatPrefix);
                                 }
                                 pStr = pStrList->insert(pStrList->end(), *pMarkingPhraseStr);
                                 if ((same == 0) && (pSecCatSuffix != NULL))
                                 {
                                    // ADD THE SUFFIX SEPARATOR
                                    pStr->append(*pSecCatSuffix);
                                 }
                              }
                           } // THERE WAS AT LEAST ONE Marking Phrase
                           else
                           { // THERE WAS NO Marking Phrase
                              if (pSecCatSuffix != NULL)
                              {
                                 CTagCategoryList::iterator pTmpTagCategory;
                                 pTmpTagCategory = pCTagCategoryList->end();
                                 pTmpTagCategory--;
                                 // ADD THE SUFFIX TO THE STRING LIST
                                 if ((pStrList->size() >  0)
                                  && (pCTagCategory == pTmpTagCategory))
                                 {
                                    pStr = pStrList->insert(pStrList->end(), *pSecCatSuffix);
                                 }
                              }
                           }
                        } // END OF CHECK FOR Marking Phrases
                        else
                        {  // DON'T DISPLAY THE Marking Phrase BUT NEED TO CHECK FOR SUFFIX
                           if (pSecCatSuffix != NULL)
                           {
                              CTagCategoryList::iterator pTmpTagCategory;
                              pTmpTagCategory = pCTagCategoryList->end();
                              pTmpTagCategory--;
                              // ADD THE SUFFIX TO THE STRING LIST
                              if ((pStrList->size() >  0)
                               && (pCTagCategory == pTmpTagCategory))
                              {
                                 pStr = pStrList->insert(pStrList->end(), *pSecCatSuffix);
                              }
                           }
                        } // END OF CHECK FOR Marking Phrases
                        if (pTagCatMarkingDataList != NULL)
                        {
                           delete pTagCatMarkingDataList;
                        }
                        if (pSecCatNameStr)
                        {
                           free(pSecCatNameStr);
                        }
                     } // END OF TAG CATEGORY
                  } // END OF IF pCTagCategoryList NOT NULL & SIZE > 0
                  if (pCTagCategoryList != NULL)
                  {
                     delete pCTagCategoryList;
                  }
                  if (pSecCatSeparator != NULL)
                  {
                     delete(pSecCatSeparator);
                  }
                  if (pSecCatPrefix != NULL)
                  {
                     delete(pSecCatPrefix);
                  }
                  if (pSecCatSuffix != NULL)
                  {
                     delete(pSecCatSuffix);
                  }
               }
               if (pCSecurityCatTagList != NULL)
               {
                  delete pCSecurityCatTagList;
               }
            }
         }
//           // THIS IS WHERE A SEPARATOR WOULD BE PRINTED IF ONE WERE TO BE
//           // ADDED BETWEEN Security Categories
//           if (pStrList->size() > 0)
//           {
//              // ADD THE SEPARATOR
//              pStr = pStrList->insert(pStrList->end(), *pSecCatSeparator);
//           }
         if (pCSecurityCatTagSetList != NULL)
         {
            delete pCSecurityCatTagSetList;
         }
      } // End collecting Security Category information

      // if displayIndex is not zero, set iterator pStr to list the list element
      // stored in the dipslayIndex position.  Is there a better way to do this?
      //
      pClassStr = pClassStrList->begin();
      if (displayIndex > 0)
      {
        for (pClassStr = pClassStrList->begin(); displayIndex != 0;
             displayIndex-- && pClassStr != pClassStrList->end(), pClassStr++);
      }
      for (pClassStr = pClassStrList->begin();
           pClassStr != pClassStrList->end(); pClassStr++)
      {
         os += *pClassStr;
      }

      for (pStr = pStrList->begin(); pStr != pStrList->end(); pStr++)
      {
         os += *pStr;
      }
      os << "\n";

      if (pClassStrList != NULL)
      {
         delete pClassStrList;
      }
      if (pStrList != NULL)
      {
         delete pStrList;
      }
      if (pClassificationNameStr != NULL)
      {
         free(pClassificationNameStr);
      }
      if (pClassMarkingDataList != NULL)
      {
         delete pClassMarkingDataList;
      }
      if (pClassMarkingPhraseStrList != NULL)
      {
         delete pClassMarkingPhraseStrList;
      }
      if (pClassMarkingPhrase != NULL)
      {
         free(pClassMarkingPhrase);
      }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

} // END OF MEMBER FUNCTION printLabel

//
//  Memory must be freed by calling routine.
char *PrintableLabel::DetermineSPIF_secCatTagSetString(
       const SPIF &SPIF_in,
       const SNACC::AsnOid &OIDCatTagSet,
       SecurityCategoryTagSet *&pSPIFsecCatTags)
{
    char *pszResult = NULL;
    SecurityCategoryTagSets  *pspfTagSets=NULL;
    SecurityCategoryTagSets::iterator itSpfTagSet;

     pspfTagSets = SPIF_in.spiftoSign.securityCategoryTagSets;
     // SecurityCategoryTagSets are optional so check them
     if (pspfTagSets != NULL && pspfTagSets->size())
     {
        for (itSpfTagSet =  pspfTagSets->begin();
             itSpfTagSet != pspfTagSets->end();
             itSpfTagSet++)
        {
           if (OIDCatTagSet == itSpfTagSet->securityCategoryTagSetName)
           {
               if (itSpfTagSet->secCatTagSetString)
                   pszResult = strdup(itSpfTagSet->secCatTagSetString->c_str());
               pSPIFsecCatTags = &(*itSpfTagSet);   // RETURN this entry to caller.
           }        // END IF found ours.
        }           // END FOR each TagSet in SPIF
     }              // END IF any TagSets in SPIF.

   return(pszResult);
}       // END PrintableLabel::::DetermineSPIF_secCatTagSetString(...)

//
//  Memory must be freed by calling routine.
char *PrintableLabel::DetermineSPIF_secCategoryName(const TagCategories &SPIFtagCat)
{
    char *pszResult = NULL;
    std::strstream tmpOs;

    SPIFtagCat.secCategoryName.Print(tmpOs);
    if (tmpOs.pcount())
    {
        pszResult = (char *)calloc(1, tmpOs.pcount()+1);
        memcpy(pszResult, tmpOs.str(), tmpOs.pcount());
        if (pszResult[strlen(pszResult)-1] == '\n')
            pszResult[strlen(pszResult)-1] = '\0';  // REMOVE trailing linefeed.
    }

   return(pszResult);
}       // END PrintableLabel::::DetermineSPIF_secCategoryName(...)

// getMarkingPhrase:
// Returns a null terminated character
// string representing the marking phrase.
//
char * CMarkingData::getMarkingPhrase(void)
{
    char    *pTmpMarkingPhraseStr=NULL;
    if (this->markingPhrase != NULL && this->markingPhrase->teletexString->length() > 0)
    {
       pTmpMarkingPhraseStr = strdup(this->markingPhrase->teletexString->c_str());
    }

   return(pTmpMarkingPhraseStr);
} // END OF MEMBER FUNCTION getMarkingPhrase

// getMarkingCodes:
// Returns list of marking codes.
//
AsnIntList * CMarkingData::getMarkingCodes(void)
{
   AsnIntList  *pTmpAsnIntList=NULL;
   MarkingDataSeqOf::iterator pTmpMarkingCode;

   // markingCode is optional so check it
   if ((this->markingCode != NULL) && (this->markingCode->size() > 0))
   {
      for(pTmpMarkingCode = this->markingCode->begin();
          pTmpMarkingCode != this->markingCode->end();
          pTmpMarkingCode++)
      {
         //
         // CONSTRUCT A CMarkingQualifier NODE
         if (pTmpAsnIntList == NULL)
         {
            pTmpAsnIntList = new AsnIntList;
         }
         // ADD THIS MarkingQualifier TO THE LIST
         pTmpAsnIntList->push_back(*pTmpMarkingCode);
      }
   }
   return(pTmpAsnIntList);
} // END OF MEMBER FUNCTION getMarkingCodes

// getSecCatTagSetNameOID:
// Returns a reference to the securityCategoryTagSetName OID.
//
AsnOid & CSecurityCatTagSet::getSecCatTagSetNameOID(void)
{
   return(this->securityCategoryTagSetName);
} // END OF MEMBER FUNCTION getSecCatTagSetNameOID

// getSecCatTagSetString:
// Returns a null terminated character string
// representing the securityCategoryTagSetString, if present.
//
char * CSecurityCatTagSet::getSecCatTagSetString(void)
{
   char    *pTmpSecCatTagSetStr=NULL;

   if (this->secCatTagSetString->length() > 0)
   {
      pTmpSecCatTagSetStr = strdup(this->secCatTagSetString->c_str());
   }

   return(pTmpSecCatTagSetStr);
} // END OF MEMBER FUNCTION getSecCatTagSetString

// getSecurityCatTagList:
// Returns an ACL_List template of CSecurityCatTag.
//
CSecurityCatTagList * CSecurityCatTagSet::getSecurityCatTagList(void)
{
   CSecurityCatTagList *pSecCatTagList=NULL;

   FUNC("CSecurityCatTagSet::getSecurityCatTagList");

   SecurityCategoryTagSetSeqOf::iterator  spfCatTag;
   // TRAVERSE NamedTagSets (StandardSecurityLabel) in m_SecLabel
   //          find equivalent tagCategories and append them to
   //          retVal.  Return retVal when done.
   //

   // TRAVERSE securityCategoryTags to find equivalentSecCategoryTags
   //
   try
   {
       for (spfCatTag = this->securityCategoryTags.begin();
            spfCatTag != this->securityCategoryTags.end(); spfCatTag++ )
       {

          // CONSTRUCT A CSecurityCatTag NODE
          if (pSecCatTagList == NULL)
          {
             pSecCatTagList = new CSecurityCatTagList;
          }
          // ADD THIS SecurityCategoryTag TO THE LIST
          pSecCatTagList->push_back(*spfCatTag);
       } // FOR securityCategoryTags
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return(pSecCatTagList);

} // END OF MEMBER FUNCTION getSecurityCatTagList

// removeLabelAndCertValue:
//
void CSecurityCatTagSet::removeLabelAndCertValue(int tagType,
                                                 int spfLACV)

{
   SecurityCategoryTagSetSeqOf::iterator pTmpSecCatTag;
   pTmpSecCatTag = this->securityCategoryTags.begin();
   while (pTmpSecCatTag != this->securityCategoryTags.end())
   {
      if (pTmpSecCatTag->tagType == (AsnInt) tagType)
      {
         SecurityCategoryTagSeqOf::iterator pTmpTagCats;
         pTmpTagCats = pTmpSecCatTag->tagCategories.begin();
         while(pTmpTagCats != pTmpSecCatTag->tagCategories.end())
         {
            if (pTmpTagCats->labelAndCertValue == spfLACV)
            {
               pTmpTagCats = pTmpSecCatTag->tagCategories.erase(pTmpTagCats);
            }
            else
            {
               pTmpTagCats++;
            }
         }
         if (pTmpSecCatTag->tagCategories.size() == 0)
         {
            pTmpSecCatTag = this->securityCategoryTags.erase(pTmpSecCatTag);
         }
         else
         {
            pTmpSecCatTag++;
         }
      }
   }
} // END OF MEMBER FUNCTION removeLabelAndCertValue

// getMarkingQualifierList:
// Returns an ACL_LIST template of CmarkingQualifier
//
CMarkingQualifierList * CSecurityCatTag::getMarkingQualifierList(void)
{

   CMarkingQualifierList *pMarkingQualifierList=NULL;

   FUNC("PrintableLabel::getMarkingQualifierList");
   try
   {
       if ((markingQualifiers != NULL) &&
           (markingQualifiers->qualifiers != NULL))
       {
          pMarkingQualifierList = new CMarkingQualifierList;

          MarkingQualifiersSeqOf::iterator  i;
          for (i = markingQualifiers->qualifiers->begin();
               i != markingQualifiers->qualifiers->end(); i++)
          {
            pMarkingQualifierList->push_back(*i);
          }
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

   return(pMarkingQualifierList);
} // END OF MEMBER FUNCTION getMarkingQualifierList

// getSecurityCatTagNameString:
// Returns a null terminated character string
// representing the SecurityCategorityTagName.
//
char * CSecurityCatTag::getSecurityCatTagNameString(void)
{
   char    *pTmpSecCatTagNameStr=NULL;

   if (this->securityCategoryTagName->length() > 0)
   {
      pTmpSecCatTagNameStr = strdup(this->securityCategoryTagName->c_str());
   }

   return(pTmpSecCatTagNameStr);
} // END OF MEMBER FUNCTION getSecurityCatTagNameString

// getTagType:
// Returns an int to indicate which tagType is present.
//
int CSecurityCatTag::getTagType(void)
{
   return(this->tagType);
} // END OF MEMBER FUNCTION getTagType

// getMarkingCode:
// Returns marking code:
//     pageTop = 1,
//     pageBottom = 2,
//     pageTopBottom = 3,
//     documentEnd = 4,
//     noNameDisplay = 5,
//     noMarkingDisplay = 6,
//     unused = 7,
//     documentStart = 8,
//     suppressClassName = 9
//     marking code not present = -1
//
int CSecurityCatTag::getMarkingCode(void)
{
   int retval=-1;
   if (this->markingQualifiers != NULL)
   {
      if (this->markingQualifiers->markingCode != NULL)
      {
         retval = (int )this->markingQualifiers->markingCode;
      }
   }
   return(retval);
} // END OF MEMBER FUNCTION getMarkingCode

// getTagCategoryList:
// Returns an ACL_LIST template of CTagCategory
//
CTagCategoryList * CSecurityCatTag::getTagCategoryList(void)
{
   SecurityCategoryTagSeqOf::iterator pTmpTagCats;
   CTagCategoryList *pTagCategoryList=NULL;
   // TRAVERSE tagCategories
   for(pTmpTagCats = this->tagCategories.begin();
       pTmpTagCats != this->tagCategories.end();
       pTmpTagCats++)
   {
      CTagCategory *pCTagCategory=NULL;
      // CONSTRUCT A CMarkingQualifier NODE
      if (pTagCategoryList == NULL)
      {
         pTagCategoryList = new CTagCategoryList;
      }
      // ADD THIS MarkingQualifier TO THE LIST
      pTagCategoryList->push_back(*pTmpTagCats);
   }
   return(pTagCategoryList);
} // END OF MEMBER FUNCTION getTagCategoryList

// getSecCategoryNameString:
// Returns a null terminated character string
// representing the secCategoryName in the SPIF.
//
char * CTagCategory::getSecCategoryNameString(void)
{
   char    *pTmpSecCatNameStr=NULL;

   if (this->secCategoryName.teletexString->length() > 0)
   {
      pTmpSecCatNameStr = strdup(this->secCategoryName.teletexString->c_str());
   }

   return(pTmpSecCatNameStr);
} // END OF MEMBER FUNCTION getSecCategoryNameString

// getLACV:
// Returns the integer value that corresponds to the
// Label And Cert Value contained in the TagCategories.
//
int CTagCategory::getLACV(void)
{
   return((int )this->labelAndCertValue);
} // END OF MEMBER FUNCTION getLACV

// getMarkingData:
// Returns an ACL_List template of CMarkingData.
// See CMarkingData for details.
//
CMarkingDataList * CTagCategory::getMarkingData(void)
{

   CMarkingDataList *pCMarkingDataList=NULL;
   // markingData is optional so check it
   if ((this->markingData != NULL)
    && (this->markingData->size() > 0))
   {
      pCMarkingDataList = new CMarkingDataList;

      TagCategoriesSeqOf1::iterator i;
      for (i = markingData->begin(); i != markingData->end(); i++)
      {
         pCMarkingDataList->push_back(*i);
      }
   }
   return(pCMarkingDataList);
} // END OF MEMBER FUNCTION getMarkingData

// getMarkingQualifier:
// Returns a null terminated character
// string representing the markingQualifier.
//
char * CMarkingQualifier::getMarkingQualifier(void)
{
   char    *pTmpMarkingQualifierStr=NULL;

   if (this->markingQualifier.teletexString->length() > 0)
   {
      pTmpMarkingQualifierStr = strdup(this->markingQualifier.teletexString->c_str());
   }

   return(pTmpMarkingQualifierStr);
} // END OF MEMBER FUNCTION getMarkingQualifier

// getQualifierCode:
// Returns a int to indicate one of the following qualifier codes.
//     prefixQualifier = 1,
//     suffixQualifier = 2,
//     separatorQualifier = 3
//     qualifier code not present = -1
//
int CMarkingQualifier::getQualifierCode(void)
{
   int retval=-1;
   if (this->qualifierCode != NULL)
   {
      retval = (int )this->qualifierCode;
   }
   return(retval);
} // END OF MEMBER FUNCTION getQualifierCode

// EOF aclprint.cpp

_END_NAMESPACE_ACL
