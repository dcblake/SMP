//////////////////////////////////////////////////////////////////////////////
// acltranslabel.cpp
// These routines support the TranslatedLabel Class
// CONSTRUCTOR(s):
//   TranslatedLabel(void)
// DESTRUCTOR(s):
//   ~TranslatedLabel(void)
// MEMBER FUNCTIONS:
//   translate(SecurityLabel &label, SPIF &localSPIF, AsnOid &remotePolicyId)
//   translateSecurityPolicy(SecurityLabel &origLabel, SPIF &spif,
//                           AsnOid &remotePolicyId)
//
// These routines support the OriginatorCert and RecipientCert Classes
// MEMBER FUNCTIONS:
//   check(Session *s, OutgoingLabel &outLabel, SPIF *pLocalSPIF)
//   check(Session *s, IncomingLabel &inLabel, SPIF &remoteSPIF)
//   check(Session *s, IncomingLabel &inLabel, SPIF *&pRemoteSPIF,
//                          SecurityLabel *&pEquivalentLabel)
//   check(Session *s, OutgoingLabel &outLabel, AsnOid &usedPolicy,
//                          const SPIF *pLocalSPIF)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// TranslatedLabel constructor
//
TranslatedLabel::TranslatedLabel()
{
   this->m_pNewTrnsLbl = NULL;
} // END OF CONSTRUCTOR

// DESTRUCTOR:
//
TranslatedLabel::~TranslatedLabel()
{
   if (m_pNewTrnsLbl != NULL)
      delete m_pNewTrnsLbl;
} // END OF DESTRUCTOR

// This function attempts to translate the incoming SecurityLabel given
// the local SPIF and remotePolicyId
//
SecurityLabel * TranslatedLabel::translate(SecurityLabel &label,
                                           SPIF &localSPIF,
                                           AsnOid &remotePolicyId)
{
   FUNC("TranslatedLabel::translate");

   // IF remotePolicyId is not in the same domain as the SecurityLabel
   // attempt to translate the label.
   // ELSE throw an error.
   //
   try
   {
       if (!(remotePolicyId == localSPIF.getPolicyId()))
       {
          // IF this is an OutgoingLabel then the policyId of 'label' and
          // 'localSPIF' must match.
          //
          if (label.isOutgoing())
          {
             if (!(localSPIF.getPolicyId() == label.security_policy_identifier))
             {
                throw ACL_EXCEPT(ACL_TRANS_ERROR,
                   "Can not translate an OutgoingLabel\n\tusing a SPIF in a different domain.");
             }
          }
          else if (label.isIncoming())
          {
             if (localSPIF.getPolicyId() == label.security_policy_identifier)
             {
                throw ACL_EXCEPT(ACL_TRANS_ERROR,
                   "Can not translate an IncomingLabel\n\tusing a SPIF in the same domain.");
             }
          }

          // newTransLbl.translateSecurityPolicy(SPIF &originatorSPIF)
          translateSecurityPolicy(label, localSPIF, remotePolicyId);
       }
       else
       {
          throw ACL_EXCEPT(ACL_TRANS_ERROR,
             "ERROR translating label.\n\tLabel security policy id matches SPIF.");
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
   return this->m_pNewTrnsLbl;
} // END OF MEMBER FUNCTION translate

// translateSecurityPolicy:
// This is a private member of SecurityLabel which begins the label translation
// process.  It determines if the security policy identifier contained in the
// current object is equivalent to policy defined by the SPIF.  If so, the
// translation process continues by calling translateClassificiation().
//
void TranslatedLabel::translateSecurityPolicy(SecurityLabel &origLabel,
                                              SPIF &spif, AsnOid &remotePolicyId)
{
   AsnOid   tmpSecLabelPolicyId;
   AsnOid   equivPolicyId;
   StandardSecurityLabel *pSSL = NULL;
   FUNC("SecurityLabel::translateSecurityPolicy");

   // IF security policy identifier in 'this' doesn't match security policy
   //   in 'spif' TRAVERSE equivalentPolicies in 'spif'
   // IF security policy identifier in 'this' is in equivalentPolicies
   //   call translateClassification()
   try
   {
          if (m_pNewTrnsLbl != NULL)
          delete m_pNewTrnsLbl;

       m_pNewTrnsLbl = new SecurityLabel;

       m_pNewTrnsLbl->security_policy_identifier =
          spif.getEquivalentPolicy(remotePolicyId);

       if (origLabel.security_classification != NULL)
       {
          m_pNewTrnsLbl->getClassification() =
              spif.getEquivalentClassification(origLabel, remotePolicyId);
       }

       if (origLabel.security_categories != NULL &&
           ! origLabel.freeFormOnlyCheck())
       {
          if ((pSSL = spif.getEquivalentTagSets(origLabel, remotePolicyId)) != NULL)
          {
             m_pNewTrnsLbl->setSSL(pSSL);
          }
          else
          {
             throw ACL_EXCEPT(ACL_NO_EQUIV, "No equivalencies for any of the NamedTagSets present in the security label");
          }
       }
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }

} // END OF MEMBER FUNCTION translateSecurityPolicy

SecurityLabel * TranslatedLabel::getLastTrnsLabel(void)
{
   SecurityLabel *pRetVal = m_pNewTrnsLbl;

   if (m_pNewTrnsLbl != NULL)
      m_pNewTrnsLbl = NULL;

   return pRetVal;
}

// check:
// This member verifies the originator's authorizations at the originator
// as defined in [SDN.801 section 6.1.2.3]. The security policy in the
// security label is required to match the security policy in one of the
// clearance attributes in the originator's certificate. The matching
// clearance attribute in the originator certificate will be used to
// perform the access control decision function on the originator.  If no
// match is found then the ACDF check fails.
//
void OriginatorCert::check(Session *s, OutgoingLabel &outLabel,
                           SPIF *pLocalSPIF)
{
   SPIF      *pOrigSPIF=NULL;
   SPIF      localSPIF;
   bool      equivFlag = s->usingEquivalencies();

   FUNC("OriginatorCert::check");
   try
   {
       s->enableEquivalencies(false);

       // IF local SPIF was not provided use the security label policy
       // identifier to retrieve the SPIF.
       //
       if (pLocalSPIF == NULL)
       {
          MatchInfo mi;
          SPIFList  sl;
          AsnOid   loid(outLabel.getPolicyId());
          mi.setPolicyId(loid);

          localSPIF.getLatest(s, mi);
       }
       else
       {
          localSPIF = *pLocalSPIF;
       }

       // set pOrigSPIF to local variable so I don't
       // have to worry about clean up.
       //
       pOrigSPIF = &localSPIF;

       ClearanceCert::check(s, pOrigSPIF, outLabel);
       s->enableEquivalencies(equivFlag);
   }
   catch (SnaccException &e)
   {
      s->enableEquivalencies(equivFlag);
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION check

// check:
// This member computes and verifies the originator's authorizations at the
// recipient as defined in section [SDN.801 sections 6.1.3.3-4].  Unlike the
// check above the SPIF parameter is required for this check.  The remoteSPIF
// should be the same SPIF that is returned from the
// RecipientCert::check(Session , IncomingLabel &, AsnOid &, SPIF &*).
//
void OriginatorCert::check(Session *s, IncomingLabel &inLabel,
                           SPIF &remoteSPIF)
{
   FUNC("OriginatorCert::check()");

   SPIF *pRemoteSPIF = &remoteSPIF;

   // The ACDF check MUST be performed using the Originator's
   // clearance that corresponds to the label.
   //
   try
   {
       if (getClearance(inLabel.getPolicyId())== NULL)
       {
          AclString o;
          AsnOid tmpOid(inLabel.getPolicyId());

          o << "OriginatorCert doesn't contain policy asserted in label:\n";
          o << "Label Policy : " << (const char *) tmpOid << "\n";
          this->getDescription(o);
          throw ACL_EXCEPT(ACL_CC_ERROR, o.str());
       }

       ClearanceCert::check(s, pRemoteSPIF, inLabel);
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION check

// check:
// This member computes and verifies the recipient's authorizations as
// defined in [SDN.801 sections 6.1.2.4-6].   If a clearance attribute
// is found in the recipient certificate that matches the security policy
// in the security label, then the matching clearance attribute in the
// recipient certificate is used to perform the ACDF check on the recipient.
// When no clearance attribute is found in the recipient certificate that
// matches the security policy in the security label and equivalency
// mappings are enabled, then the ACL tries each of the clearance attributes
// in the recipient certificate using equivalencies until the ACDF check
// passes or the clearance attributes are exhausted.  If the ACDF check for
// the recipient passes, the security policy used to pass the check is
// returned to the application. When the clearance attributes in the
// recipient's certificate are exhausted (none of them pass the ACDF check),
// then the check method fails for the recipient.
//
void RecipientCert::check(Session *s, OutgoingLabel &outLabel,
                          AsnOid &usedPolicy, SPIF *pLocalSPIF)
{
   AsnOid    labelPolicyId;
   AsnOidLst certPolicyIdList;
   SPIF      localSPIF;
   SPIF      *pRemoteSPIF = pLocalSPIF;

   FUNC("RecipientCert::check");
   try
   {
       ClearanceCert::check(s, pRemoteSPIF, outLabel);

       usedPolicy = this->ClearanceInfo::getPolicyId();

       if (pRemoteSPIF != NULL && (pLocalSPIF != pRemoteSPIF))
          delete pRemoteSPIF;
   }
   catch (SnaccException &e)
   {
      if (pRemoteSPIF != NULL && (pLocalSPIF != pRemoteSPIF))
         delete pRemoteSPIF;
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION check

// check:
// This member verifies the recipient's authorizations at the recipient as
// defined in section [SDN.801 sections 6.1.3.1-2]. If a clearance attribute
// is found in the recipient certificate that matches the security policy in
// the security label, then the matching clearance attribute in the recipient
// certificate will be used to perform the ACDF check on the recipient.  When
// no clearance attribute is found in the recipient certificate that matches
// the security policy in the security label and equivalency mappings are
// enabled, then the ACL tries each of the clearance attributes in the
// recipient certificate using equivalencies until the ACDF check passes or
// the clearance attributes are exhausted.  For each clearance attribute
// check, the ACL finds the SPIF in its internal cache that matches the
// security policy OID in the clearance attribute being checked.  When the
// clearance attributes in the recipient's certificate are exhausted (none
// of them pass the access control check), then the ACL check fails for the
// recipient.  If the ACDF check for the recipient passes, then the ACL
// provides a pointer to the SPIF used for the successful completion of the
// check.
//
void RecipientCert::check(Session *s, IncomingLabel &inLabel,
                          SPIF *&pRemoteSPIF,
                          SecurityLabel *&pEquivalentLabel)
{
   AsnOid    labelPolicyId = inLabel.getPolicyId();
   AsnOidLst certPolicyIdList;
   SPIF      localSPIF;

   FUNC("RecipientCert::check");
   try
   {
       ClearanceCert::check(s, pRemoteSPIF, inLabel);
       pEquivalentLabel = inLabel.equivLabels.getLastTrnsLabel();
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
} // END OF MEMBER FUNCTION check

_END_NAMESPACE_ACL

// EOF acltranslabel.cpp

