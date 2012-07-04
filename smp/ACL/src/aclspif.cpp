//////////////////////////////////////////////////////////////////////////////
// aclspif.cpp
// These routines support the SPIF Class
// CONSTRUCTOR(s):
//   SPIF(void)
//   SPIF(CTIL::CSM_Buffer &encodedSPIF):Cacheable()
// DESTRUCTOR:
//   ~SPIF(void)
// MEMBER FUNCTIONS:
//   isEnumRestrictive(AsnOid &tagSetNameOid)
//   vValidate(Session *s, PublicKeyInfo &pubKeyInfo)
//   operator =(SPIF &SPIF)
//   vPathRules(Session *pSession, CertificationPath *certPath)
//   checkSpifSigner(Session *pSession, CertificationPath *certPath)
//   getIssuerName(void)
//   getPolicyId(void)
//   Print(ostream &os)
//   getDescription(ostream &os)
//   getEquivalentPolicy(AsnOid &policyId)
//   getEquivalentClassification(SecurityLabel &lbl, AsnOid &remotePolicyId)  
//   getEquivalentTagSets(SecurityLabel &origLabel, AsnOid &remotePolicyId)
//   matches(MatchInfo &matchInfo)
//   operator= (SPIF &that)
//   getIssuerInfo(MatchInfo &matchInfo)
//   getLatest(Session *s, MatchInfo &matchInfo)
//   checkValidity(void)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// CONSTRUCTOR
//
SPIF::SPIF(void):Cacheable(Cacheable::ACSPIF_ID)
{
   m_pOriginatorDN = NULL;
} // END OF MEMBER FUNCTION SPIF

SPIF::SPIF(const SPIF &that):Cacheable(Cacheable::ACSPIF_ID)
{
   m_pOriginatorDN = NULL;
   *this = that;
} // END OF MEMBER FUNCTION SPIF

// DESTRUCTOR:
//
SPIF::~SPIF()
{
   if (m_pOriginatorDN != NULL)
   {
      delete m_pOriginatorDN;
      m_pOriginatorDN = NULL;
   }
} // END OF DESTRUCTOR

// ALTERNATE CONSTRUCTOR:
//
SPIF::SPIF(const CML::ASN::Bytes &encodedSPIF):Cacheable(Cacheable::ACSPIF_ID)
{
   FUNC("SPIF::SPIF()");

   try
    {
        m_pOriginatorDN = NULL;

        try
        {
            encodedSPIF.Decode(*this);
        }
        catch(...)
        {
            // THROW ERROR
            throw ACL_EXCEPT(ACL_ASN_ERROR,
               "Decode of SPIF failed, invalid format");
        }
        m_origObject = encodedSPIF;
        m_origObject.Hash(m_hash);
    }
    catch (SnaccException &e)
    {
      e.push(STACK_ENTRY);
      throw;
    }
} // END OF ALTERNATE CONSTRUCTOR


// isEnumRestrictive:
// FIND THE SPIF securityCategoryTagSet WHOSE securityCategoryTagSetName
// MATCHES tagSetNameOid AND RETURN true IF enumType IS 2 (restrictive)
// AND false if IT'S 1 (permissive).  IF enumType IS NOT PRESENT THROW ERROR.
// NOTE:  THIS FUNCTION DOES NOT CHECK SPECIFICALLY FOR enumType == 1
//        (permissive).  THE ASSUMPTION IS THAT IF IT IS NOT restrictive
//        IT MUST BE permissive.
//
bool SPIF::isEnumRestrictive(const AsnOid &tagSetNameOid)
{
    bool bResult=false;
    SecurityCategoryTagSetSeqOf::const_iterator pTmpSecCatTag;
    SecurityCategoryTagSets::const_iterator     pTmpSecCatTagSet;
    char errStr[ACL_STR_BUF_LEN];

    FUNC("SPIF::isEnumRestrictive");

    // INITIALIZATION
    errStr[0]='\0';

    // LOOP THROUGH THE Security Category Tag Sets LOOKING FOR THE
    // tagSetNameOid WHICH WAS PASSED IN
    try
    {
        for(pTmpSecCatTagSet = getSNACC()->spiftoSign.securityCategoryTagSets->begin();
            pTmpSecCatTagSet != getSNACC()->spiftoSign.securityCategoryTagSets->end();
            pTmpSecCatTagSet++)
        {
            // DOES THIS tagSetName MATCH THE tagSetNameOid FROM
            // THE LABEL (PASSED IN)
            if (pTmpSecCatTagSet->securityCategoryTagSetName == tagSetNameOid)
            {
                // LOOP THROUGH THE Security Category Tags
                for(pTmpSecCatTag = pTmpSecCatTagSet->securityCategoryTags.begin();
                    pTmpSecCatTag != pTmpSecCatTagSet->securityCategoryTags.end();
                    pTmpSecCatTag++)
                {
                    if (pTmpSecCatTag->tagType == (AsnInt)TagTypeValue::enumerated)
                    {
                       // IF THERE IS NO enumType GET OUT
                       if (pTmpSecCatTag->enumType == NULL)
                       {
                          sprintf(errStr, "%s %s %s",
                                  "Missing required element (enumType) within",
                                  "optional\n\telement (SecurityCategoryTag)",
                                  "for enumerated TagType");
                          throw ACL_EXCEPT(ACL_ASN_ERROR, errStr);
                       }

                       // IF THE enumType IS 2 IT IS RESTRICTIVE
                       // (OTHERWISE IT MUST BE PERMISSIVE)
                       //
                       if (*pTmpSecCatTag->enumType == 2)
                       {
                           bResult = true;
                       }
                       break;
                    }
                }
                break;
            }
        }
    }
    catch (SnaccException &e)
    {
      e.push(STACK_ENTRY);
      throw;
    }
    return bResult;

} // END OF MEMBER FUNCTION isEnumRestrictive


// vPathRules:
//
void SPIF::vPathRules(Session *pSession,
                      const CML::ASN::CertificationPath &certPath)
{
   FUNC("SPIF::vPathRules");

   if (pSession->usingTrustList())
   {
      if (pSession->findTrust(getIssuerName(), getPolicyId()) == false)
      {
         char errStr[256];
         sprintf(errStr, "SPIF Trust Error:\n\tDN:%s\n\tOID:%s\n",
               (const char *)getIssuerName(), (const char *) getPolicyId());
         throw ACL_EXCEPT(ACL_TRUST_ERROR, errStr);
      }
   }

   if (checkSpifSigner(pSession, certPath) == false)
      throw ACL_EXCEPT(ACL_SPIF_SIGNER, "checkSpifSigner returned FALSE");

} // END OF MEMBER FUNCTION vPathRules


// checkSpifSigner:
//
bool SPIF::checkSpifSigner(Session *pSession,
                      const CML::ASN::CertificationPath &certPath)
{
   const CML::ASN::Cert   *pIssuerCert = NULL;
   int                     privFlag=-1;
   char                    errStr[256];

   FUNC("SPIF::checkSpifSigner");

   // INITIALIZATION
   errStr[0]='\0';

   // Make sure keyId in SPIF matches subjectKeyIdentifier of issuer
   //
   try
   {
       if (certPath.userCert.exts.pSubjKeyID != NULL)
       {
          // Compare the decoded SubKeyIdentifier against the SPIF KeyId
          if (certPath.userCert.exts.pSubjKeyID->operator ==(
              this->getSNACC()->spiftoSign.versionInformation.keyIdentifier))
          {
             // Then this is the Certificate which issued this SPIF
             pIssuerCert = &certPath.userCert;
          }
       }
 
       if (pIssuerCert != NULL)
       {
          bool b_spifSignerOK = false;
          AsnLen bytesDecoded;
          SNACC::SpifSignerAttribute spifSigner;

          // IF the SPIF Signer Attribute is enabled check it
          // against the security policy of the SPIF.
          //
          if (pSession->usingSPIFSignerAttribute())
          {
             if (pIssuerCert->exts.pSubjDirAtts)
             {
                CML::ASN::AttributeList::const_iterator i;
                i = pIssuerCert->exts.pSubjDirAtts->Find(acl_id_at_spif_signer);
                SNACC::Attribute attr;

				if (i != pIssuerCert->exts.pSubjDirAtts->end())
				{
					i->FillSnaccAttribute(attr);

					AttributeSetOf::iterator j;
					for (j = attr.values.begin(); j != attr.values.end() && ! b_spifSignerOK; j++)
					{
						spifSigner.BDec(*j->anyBuf, bytesDecoded);

						SNACC::SpifSignerAttribute::iterator h;
						for (h = spifSigner.begin(); h != spifSigner.end(); h++)
						{
							if (*h == this->getPolicyId())
							{
								b_spifSignerOK = true;
								break;
							}
						}
					}
				}
             }
             if (!b_spifSignerOK)
             {
                AclString str;
                str << "Invalid or Missing SPIF signer attribute";
                getDescription(str);
                str << "Issuer Info:\n";
                str << "DN: " << (const char *) pIssuerCert->subject << "\n";
            
                throw ACL_EXCEPT(ACL_SPIF_SIGNER, str.str());
             }
          }
          // IF DMS mode is on check the PrivateKeyUsagePeriod
          //  
          if (pSession->m_dms_mode)
          {
             // check the issuer cert of a CA Clearance Constraints
             // that matches the security policy of the SPIF.
             //
             ClearanceCert tmpIssuerCert(*pIssuerCert);
             const Clearance *pTmpSnaccClearance = 
                tmpIssuerCert.getCaClearance(this->getPolicyId());

             if (pTmpSnaccClearance == NULL)
             {
                // THROW POLICY ID MIS-MATCH
                AsnOid tmpSPIFOid(this->getPolicyId());
                sprintf(errStr, "%s%s%s%s%s",
                       "No matching CA Clearance Constraint OID found\n",
                       "in Clearance Attribute of Issuer's Certificate."
                       "\nSPIF Policy ID (", (const char *)tmpSPIFOid, 
                       ")");
                throw ACL_EXCEPT(ACL_SPIF_PCA_POLICYID_ERROR, errStr);
             }

             /* IF PrivateKeyUsage period is present make sure 
              * it's current.
              */
             if (pIssuerCert->exts.pPrivKeyPeriod != NULL)
             {

                // Compare the decoded PrivateKeyUsagePeriod (notBefore and
                //   notAfter) to the SPIF CreateDate, to ensure it falls
                //   between the two
                // Compare the SPIF's creation date to ensure that it's within 
                // the privateKeyUsage period.

                if (! pIssuerCert->exts.pPrivKeyPeriod->IsWithin(spiftoSign.versionInformation.creationDate))
                {
                   sprintf(errStr, "%s %s",
                           "SPIF creationDate not within Certificate",
                           "Private Key Usage Period");
                   throw ACL_EXCEPT(ACL_SPIF_VAL_ERROR, errStr);
                }
             } /* End if PrivateKeyUsage period check */
         
             /* IF KeyUsage extension is present then make sure it has the 
              * nonRepudiation bit set.
              */

             if (pIssuerCert->exts.pKeyUsage != NULL)
             {
                if (!pIssuerCert->exts.pKeyUsage->GetBit(
                    (unsigned int) SNACC::KeyUsage::nonRepudiation))
                {
                   throw ACL_EXCEPT(ACL_SPIF_VAL_ERROR,
                        "Critical keyUsage nonRepudiation bit not set");
                }
             } /* End of KeyUsage check */
        
             /* SubjectDirectoryAttributes Extension check
              */
             if (pIssuerCert->exts.pSubjDirAtts != NULL)
             {
                CML::ASN::AttributeList::const_iterator i;
            
                /* Search through Subject Directory Attributes Extension
                 */
                  i = pIssuerCert->exts.pSubjDirAtts->Find(id_sigOrKMPrivileges);
                  if (i->GetType() == CML::ASN::Attribute::SigOrKMPrivs)
                  {
                      CML::ASN::SigOrKMPrivileges::const_iterator j;
                      for (j = i->GetValues().pSigKMPrivs->begin(); 
                           j != i->GetValues().pSigKMPrivs->end(); j++)
                      {
                          if (j->choiceId ==
                              PrivilegeFlags::sigFlagsCid)
                          {
                             if (j->sigFlags->sigPrivId ==
                                 id_sigPrivilegeId)
                             {
                                bool bFoundPCA = false;
                                SigPrivFlagsSeqOf::const_iterator k;
                                
                                for (k = j->sigFlags->sigPrivFlags->begin();
                                     k != j->sigFlags->sigPrivFlags->end(); k++)
                                {
                                   privFlag = *k;
                                   if (privFlag == 1) // PCA
                                   {
                                      bFoundPCA = true;
                                      break;
                                   }
                                }
                                if (bFoundPCA == false)
                                {
                                   throw ACL_EXCEPT(ACL_SPIF_VAL_ERROR,
                                      "Missing SigOrKM Privilege PCA Authorization");
                                }
                             }
                             else
                             {
                                throw ACL_EXCEPT(ACL_SPIF_VAL_ERROR,
                                    "Invalid SigOrKM Privilege ID");
                             }
                          } // END OF CHECK FOR sigFlags
                      }
                  }

                  
             } // END OF CHECK FOR Subject Directory Attributes
          }
       }
       else
       {
          // This means that the SPIF's VersionInformationData keyIdentifier
          // does not match the decoded SubKeyIdentifier from the PCA
          // certificate's subjectKeyIdentifier
          sprintf(errStr, "%s%s",
                  "SPIF's keyIdentifier does not match",
                  "\n\tIssuer Certificate subjectKeyIdentifier");
          throw ACL_EXCEPT(ACL_SPIF_VAL_ERROR, errStr);
       }
   }
   catch (SnaccException &)
   {
      return(false);
   }

   return(true);
} // END OF MEMBER FUNCTION checkSpifSigner

// getIssuerName:
//
const CML::ASN::DN & SPIF::getIssuerName(void) const
{
    FUNC("SPIF::getIssuerName");
    try
    {
        if (m_pOriginatorDN == NULL)
        {
           m_pOriginatorDN = new CML::ASN::DN;
           *m_pOriginatorDN = spiftoSign.versionInformation.originatorDistinguishedName;
        }
    }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
    return *m_pOriginatorDN;

} // END OF MEMBER FUNCTION getIssuerName

// getPolicyId:
// INPUT:  NONE
// OUTPUT: NONE
// RETURN: AsnOid &
// THIS MEMBER EXTRACTS A reference of an AsnOid PolicyId FROM THE Security
//   Policy Id Data OF THE spiftoSign WHICH IT RETURNS TO THE CALLING
//   FUNCTION
//
const AsnOid &SPIF::getPolicyId(void) const
{
    return (spiftoSign.securityPolicyIdData.objectId);
} // END OF MEMBER FUNCTION getPolicyId

// getDescription:
//
void SPIF::getDescription(AclString &os) const
{
    os << "\n** SPIF **:" 
       << "\n\tDN: " << (const char *)getPolicyId()
       << "\n\tOID: " << (const char *) getIssuerName()
       << "\n";
} // END OF MEMBER FUNCTION getDescription

// getEquivalentPolicy:
//
AsnOid & SPIF::getEquivalentPolicy(AsnOid &policyId)
{
   FUNC("SPIF::getEquivalentPolicy");
   
   bool found = false;
   try
   {
       if (getPolicyId() != policyId)
       {
          EquivalentPolicy *pTmpEquivPolicy=NULL;
          SNACC::EquivalentPolicies::iterator i;

          // search EquivalentPolicies sequence for policyId
          //
          for (i = spiftoSign.equivalentPolicies->begin();
               i != spiftoSign.equivalentPolicies->end(); i++)
          {
             if (i->securityPolicyId == policyId)
             {
                found = true;
                break;
             }
          }
      
       }

       if (! found )
       {
          AsnOid oid(policyId);
          char    errStr[256];
          sprintf(errStr, "SPIF does not contain an equivalency for %s",
                  (const char *) oid);
          throw ACL_EXCEPT(ACL_NO_EQUIV, errStr);
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return((AsnOid &)getPolicyId());
} // END OF MEMBER FUNCTION getEquivalentPolicy

// getEquivalentClassification:
//
int SPIF::getEquivalentClassification(SecurityLabel &lbl,
                                      AsnOid &remotePolicyId)  
{
   FUNC("SPIF::getEquivalentClassification");

   SpiftoSignSeqOf::iterator pSpifClass;
   SpifSecurityClassificationSeqOf::iterator pSpifEquivClass;
  
   if (lbl.security_classification != NULL)
   {
       // TRAVERSE spifClassifications
       try
       {
           for (pSpifClass = spiftoSign.securityClassifications.begin();
                pSpifClass != spiftoSign.securityClassifications.end(); pSpifClass++)
           {
              if (lbl.isOutgoing() && (lbl.getClassification() == pSpifClass->labelAndCertValue) ||
                  lbl.isIncoming() )
              {
                 if (pSpifClass->equivalentClassifications != NULL)
                 {
                    // TRAVERSE current spifClassification.equivalentClassifications
                    for (pSpifEquivClass = pSpifClass->equivalentClassifications->begin(); 
                         pSpifEquivClass != pSpifClass->equivalentClassifications->end(); pSpifEquivClass++)
                    {
                        // IF security policy identifier in 'this' equals current
                        // equivalentClassification security policy identifier
                        if (remotePolicyId == pSpifEquivClass->securityPolicyId)
                        {
                           if (lbl.isEquivApplicable(pSpifEquivClass->applied))
                           {
                              // found applicable security classification equivalency
                              // return equivalent classification if this is an OutgoingLabel
                              // return spif security classification if this is an IncomingLabel
                              if (lbl.isOutgoing())
                              {
                                 return pSpifEquivClass->labelAndCertValue;
                              }
                              else if( lbl.isIncoming() && 
                                 (lbl.getClassification() == pSpifEquivClass->labelAndCertValue))
                              {
                                 return pSpifClass->labelAndCertValue;
                              }
                           }
                        }
                    }
                 }
              }
           }  // end TRAVERSE spifClassifications

           char errStr[256];
           sprintf(errStr,"No classification '%d' equivalency for policy", 
                   (int)lbl.getClassification());

           throw ACL_EXCEPT(ACL_NO_EQUIV_CLASSIFICATION,errStr);
       }
       catch (SnaccException &e)
       {
          e.push(STACK_ENTRY);
          throw;
       }
   }
   return -1;
}  // END OF MEMBER FUNCTION getEquivalentClassification

// getEquivalentTagSets:
//
StandardSecurityLabel * SPIF::getEquivalentTagSets(SecurityLabel &origLabel,
                                                   AsnOid &remotePolicyId)
{
   FUNC("SPIF::getEquivalentTagSets");

   SecurityCategoryTagSets   *spfTagSets = NULL;
   SecurityCategoryTagSets::const_iterator spfTagSet;

   SecurityCategoryTagSetSeqOf::const_iterator spfCatTag;
   SecurityCategoryTagSeqOf::const_iterator spfTagCats; 
   TagCategoriesSeqOf::const_iterator spfEqvCatTag;
   StandardSecurityLabel    *pRetVal = NULL;  // return value
   StandardSecurityLabel::const_iterator pLblTagSet;
   SecurityTags              lblTags;
   bool                      foundLACV = false;
   // TRAVERSE NamedTagSets (StandardSecurityLabel) in origLabel
   //          find equivalent tagCategories and append them to
   //          retVal.  Return retVal when done.
   //
   try
   {
       for (pLblTagSet = origLabel.getSSL().begin(); 
            pLblTagSet != origLabel.getSSL().end();
            pLblTagSet++)
       {
          lblTags = pLblTagSet->securityTags;

          foundLACV = false;
   
          spfTagSets = this->spiftoSign.securityCategoryTagSets;
          for (spfTagSet = spfTagSets->begin();
               spfTagSet != spfTagSets->end() && !foundLACV;
               spfTagSet++ )
          {
             // TRAVERSE securityCategoryTags to find equivalentSecCategoryTags
             //
             for (spfCatTag = spfTagSet->securityCategoryTags.begin();
                  spfCatTag != spfTagSet->securityCategoryTags.end() && !foundLACV;
                  spfCatTag++)
             {

                // TRAVERSE tagCategories
                //
                for (spfTagCats = spfCatTag->tagCategories.begin(); 
                     spfTagCats != spfCatTag->tagCategories.end() && !foundLACV; 
                     spfTagCats++)
                {
                   if (spfTagCats->equivalentSecCategoryTags != NULL)
                   {
                      // TRAVERSE equivalentSecCategoryTags to determine if the
                      //          current pLblTagSet values are contained within it.
                      //
                      for (spfEqvCatTag = spfTagCats->equivalentSecCategoryTags->begin();
                           spfEqvCatTag != spfTagCats->equivalentSecCategoryTags->end() && !foundLACV;
                           spfEqvCatTag++)
                      {
                         // IF this is an OutgoingLabel and the current label
                         //    tagSet matches current spfCatTag then return
                         //    equivalent value in pRetVal
                         // OR if this is an IncomingLabel and current label
                         //    tagSet matches the current SPIF eqvCatTag then
                         //    LACV value from spfTagCats in pRetVal
                         //
                         if ( (origLabel.isOutgoing() && 
                               (pLblTagSet->tagSetName == spfTagSet->securityCategoryTagSetName)) ||
                              (origLabel.isIncoming() && 
                               (spfEqvCatTag->securityPolicyObjId == origLabel.security_policy_identifier) &&
                               (spfEqvCatTag->securityCategoryTagSetName == pLblTagSet->tagSetName)) )
                         {
                            // note: found equivalent category tag

                            // NOW check to see if this equivalency is applicable
                            // 
                            if (origLabel.isEquivApplicable(spfEqvCatTag->applied))
                            {
                               // note: equivalent category tag is applicable

                               // NOW check to see if the equivalency values are
                               //     present in in the pLblTagSet securityTags
                               //
                               //     note: findLabelAndCertValue will leave
                               //           the "curr" pointer of
                               //           pLblTagSet->securityTags pointing to the
                               //           securityTag that matched.
                               //
                              
                               SNACC::SecurityTags::const_iterator iLblTag;
                                                                 
                               if (origLabel.isIncoming())
                               {
                                   if (CSecurityTag::removeLabelAndCertValue(lblTags,
                                             spfEqvCatTag->labelAndCertValue,
                                             spfEqvCatTag->tagType))
                                   {
                                      CSecurityTag::addTagSet(pRetVal,
                                          spfTagSet->securityCategoryTagSetName, 
                                          spfTagCats->labelAndCertValue, *spfCatTag);
                             
                                      foundLACV = true;
                                   }
                               }
                               else if (origLabel.isOutgoing())
                               {
                                  if (CSecurityTag::removeLabelAndCertValue(lblTags,  
                                        spfTagCats->labelAndCertValue,
                                        spfCatTag->tagType))
                                  {
                                     CSecurityTag::addTagSet(pRetVal,
                                       spfEqvCatTag->securityCategoryTagSetName,
                                       spfEqvCatTag->labelAndCertValue, *spfCatTag);

                                    foundLACV = true;
                                 }
                               }
                            }
                         }
                      } // FOR equivalentSecCategoryTags
                   }
                } // FOR tagCategories
             } // FOR securityCategoryTags
          } // FOR spfTagSets
   
          if (foundLACV == false)
          {
             char errStr[512];
             AclString os;
             CSecurityTag secTag;
             AsnOid      lblPolicyId(origLabel.security_policy_identifier);
             AsnOid      lblTagSetName(pLblTagSet->tagSetName);
             AsnOid      spfPolicyId(this->getPolicyId());

             secTag.SecurityTag::operator=(*lblTags.begin());
             secTag.Print(os);
             sprintf(errStr, "%s %s %s %s\n\t%s",
                     "No equivalency in SPIF for Securitytag:\n\tpolicy id:",
                     (const char *) lblPolicyId, "\n\ttagSetName:",
                     (const char *)lblTagSetName, os.str());
             throw ACL_EXCEPT(ACL_NO_EQUIV, errStr);
          }
       } // FOR origLabel.getSSL()
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return pRetVal;
} // END OF MEMBER FUNCTION getEquivalentTagSets

// vGetAuthKeyId:
//
// AsnOcts * SPIF::vGetAuthKeyId(void)
// {
//    ACL_TRY("SPIF::vGetAuthKeyId");
// 
//    AsnOcts *pAuthKey = new AsnOcts(this->spiftoSign.versionInformation.keyIdentifier);
// 
//    return pAuthKey;
// 
//    ACL_ENDTRY_CATCH
// } // END OF MEMBER FUNCTION vGetAuthKeyId

// matches:
//
bool SPIF::matches(const MatchInfo &matchInfo) const
{
   FUNC("SPIF::matches");
   try
   {
       int matchCount = 0;
       const CML::ASN::DN *pIssuerDN = matchInfo.getIssuerDN();
       const SNACC::AsnOcts *pAuthorityKeyId = matchInfo.getAuthorityKeyId();
       const AsnOid *pPolicyId = matchInfo.getPolicyId();

       // Match on issuerDN
       //
       if (pIssuerDN != NULL)
       {
          if (*((CML::ASN::DN *)pIssuerDN) == this->getIssuerName())
          {
             matchCount++;
          }
          else
          {
             return false;
          }
       }

  
       // look for subjectKeyIdentifier or authorityKeyIdentifier extensions.
       //
       if (pAuthorityKeyId != NULL)
       {
          if (*pAuthorityKeyId == spiftoSign.versionInformation.keyIdentifier)
          {
             matchCount++;
          }
          else
          {
             return false;
          }
       }

       if (pPolicyId != NULL)
       {
          if ( *pPolicyId == getPolicyId())
          {
             matchCount++;
          }
          else
          {
             return false;
          }
       }

       // SPIFs must match by issuerDN, policyId, and keyIdentifier.
       if (matchCount > 0)
       {
          return true;
       }
   
       return false;
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION matches

// operator=:
//
SPIF & SPIF::operator= (const SPIF &that)
{
   Cacheable::operator =(that);
   Acspif::operator=(that);
   return (*this);
} // END OF MEMBER FUNCTION operator=

// getIssuerInfo:
//
void SPIF::getIssuerInfo(MatchInfo &matchInfo)
{
   matchInfo.setSubjectDN(this->getIssuerName());
   matchInfo.setSubjectKeyId(this->spiftoSign.versionInformation.keyIdentifier);
   AsnOid policyId(this->getPolicyId());
   matchInfo.setPolicyId(policyId);
} // END OF MEMBER FUNCTION getIssuerInfo

// getLatest:
//
void SPIF::getLatest(Session *s, MatchInfo &matchInfo)
{

   Session::CacheModeType old_mode = s->m_eCacheMode;
   FUNC("SPIF::getLatestSPIF");
   AclString os;

   try
   {
       if (s == NULL)
       {
          throw ACL_EXCEPT(ACL_NULL_POINTER,"Session pointer is NULL");
       }

       // only search cache (LOCAL) for SPIFs
       //
       s->setCacheMode(Session::LOCAL);
   
       SPIFList *pList = s->getSPIF(matchInfo);

       SPIFList::iterator pCurr;
       SPIFList::iterator pLatest;

       // Find most recent SPIF
       //
       if (pList != NULL)
       {
          pLatest = pList->begin();
          pCurr = pList->begin();
          pCurr++;
          for (; pCurr != pList->end(); pCurr++)
          {
               CML::ASN::Time latestTime(pLatest->spiftoSign.versionInformation.creationDate);
               CML::ASN::Time currTime(pCurr->spiftoSign.versionInformation.creationDate);
               if (latestTime < currTime)
               {
                  pLatest = pCurr;
               }
               else if (latestTime == currTime)
               {
                  throw ACL_EXCEPT(ACL_CACHE_ERROR,
                     "Multiple matching SPIFs found in cache with the same creationDate");
               }
          }
          *this  = *pLatest;
          delete pList;
       }
       else
       {
          os << "SPIF not found in cache.\0";
          throw ACL_EXCEPT(ACL_CACHE_ERROR, os.str());
       }
   }
   catch (SnaccException &e)
   {
      s->setCacheMode(old_mode);
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION getLatest

// checkValidity:
//
bool SPIF::checkValidity(void)
{
   CML::ASN::Time sysTime;
 
   // check the validity period of this SPIF
   if (sysTime < this->spiftoSign.
           versionInformation.creationDate)
   {
      return false;
   }

   return true;
} // END OF MEMBER FUNCTION checkValidity


_END_NAMESPACE_ACL

// EOF aclspif.cpp

