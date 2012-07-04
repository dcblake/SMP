//////////////////////////////////////////////////////////////////////////
//
// FILE:  sm_AC_Interface.h
//
// DESCRIPTION:   CLASS description for CM_Interface
//
//  The design intent of this include file definitions is to provide an 
//  Insecure class to initialize the CML/SRL sessions for an example 
//  demonstration.  It is intended to provide a minimal CML interface,
//  where the user is expected to provide a fully secure set of policy
//  definitions, etc. as described in the CML documentation.
//
//  The SFL use of these classes intends to load certificates from an
//  incomming message (e.g. in PreProc(...)) into the SRL, then access
//  these certificates in the actual Sign/Verify/Encrypt/Decrypt operations
//  after validation if requested.
//        
//
//////////////////////////////////////////////////////////////////////////
#ifndef __AC_INTERFACE_H
#define __AC_INTERFACE_H

#ifdef ACL_USED

#include "acl_api.h"

//_BEGIN_SFL_NAMESPACE
#ifndef NO_NAMESPACE
namespace SFL {
    using acl::SecurityLabel;
#endif // NO_NAMESPACE



//
//########################################################################
//  This class provides some ACL load/unload support.  It does not 
//  initialize the ACL session, but expects the application to 
//  provide a properly setup session set.  (See the 
//  ACL_INADEQUATE_InitInterface class for a demonstration setup.)
class ACL_Interface
{
private:
    acl::Session *m_pAclSessionId;        // EXPECTED from calling app.
    CTIL::CSM_Buffer *m_pACLMsgLabel;    // FROM a SignedData, BEFORE calling
                                          //  PreProc().
public:
    ACL_Interface() { m_pAclSessionId = NULL; m_lpszError=NULL; 
                      m_pACLMsgLabel=NULL; m_pEquivLabel=NULL; }
    ACL_Interface(acl::Session &AclSessionId, 
                  const CTIL::CSM_Buffer *pACLMsgLabel=NULL);
    ACL_Interface(const ACL_Interface &that);
   ~ACL_Interface();

   // member functions
   void setACLSession(const acl::Session &AclSessionId);
   void setACLMsgLabel(const CTIL::CSM_Buffer &ACLMsgLabel);
   acl::SPIF *lookupSpif(const SNACC::AsnOid &oidPolicyId);
   // THE following methods will return an error code if an ACL validation error is
   //  is encountered.  It is up to the calling application to check m_lpszError.
   long Check_ACLOutgoingRecip(const CM_SFLCertificate &ACMLCert,         // INPUT
                          const CTIL::CSM_Buffer &CertificateEncrypterB); // INPUT
   long Check_ACLIncommingRecip(const CM_SFLCertificate &ACMLCert,  // INPUT
                      const CTIL::CSM_Buffer &CertificateEncrypterB,// INPUT
                           acl::SPIF *&pspif);                 // RETURNED
   long Check_ACLIncommingOrig(const CM_SFLCertificate &ACMLCert,   // INPUT
                         const CTIL::CSM_Buffer &OrigCertificateB,  // INPUT
                         acl::SPIF &spif);// IN, MUST be same SPIF used for 
                                             // checking INCOMMING Recip 
                                             // (ourselves).
   long Check_ACLOutgoingOrig(const CM_SFLCertificate &ACMLCert,  // INPUT
                    const CTIL::CSM_Buffer &OrigCertificateB);    // INPUT

    acl::SecurityLabel *m_pEquivLabel;  // OPTIONAL, returned to user.
    SNACC::AsnOid m_usedPolicy;         // OPTIONAL, returned to user.
    const acl::Session *GetACLSessionId() { return m_pAclSessionId; }
    char *m_lpszError;

};          // END ACL_Interface

//_END_SFL_NAMESPACE
#ifndef NO_NAMESPACE
}          // END namespace
#endif // NO_NAMESPACE

#endif //ACL_USED


#endif      // __AC_INTERFACE_H
