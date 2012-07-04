
//
// sm_CM_AC_Support.h
// This utility include file provides the CML and ACL support classes to setup
//  minimal sessions.

#ifndef _SM_CM_AC_SUPPORT_H_
#define _SM_CM_AC_SUPPORT_H_

#ifdef CML_USED
//
//
//########################################################################
//  THIS SPECIAL CLASS is labelled as "INADEQUATE" to indicate that it is up to 
//  the user to properly initialize the CML session for the appropriate security 
//  policies.  WITHOUT PROPER SETUP, VALIDATION MAY RETURN INVALID RESULTS!!!
//  (see the CML API document for details).  This class is provided as a 
//  convenient test initialization, but labelled to warn users it is inadequate
//  for a proper security-minded application setup.  See the CML user's manual.
//  It does provide a demonstration of the minimum necessary to setup a CML 
//  session.
class CML_Interface
{
public:
	CML_Interface();
	~CML_Interface();

   short InitializeSessions(const char* ldapServerName, int ldapServerPort,
	   const CML::ASN::BytesList& trustedCertsList);
   void AddCRL2DB(const CML::ASN::Bytes& encCRL);
   bool UsingCML()				{ return (m_lCmlSessionId != 0); }
   ulong GetSRLSessionID()		{ return m_lSrlSessionId; }
   ulong GetCMLSessionID()		{ return m_lCmlSessionId; }

private:
	ulong m_lSrlSessionId;
	ulong m_lCmlSessionId;
	void* m_pCtilMgr;
};

#endif  // CML_USED

#ifdef ACL_USED
//
//
//########################################################################
//  THIS SPECIAL CLASS is labelled as "INADEQUATE" to indicate that it is up to 
//  the user to properly initialize the ACL session for the appropriate security.
//  WITHOUT PROPER SETUP, VALIDATION MAY RETURN INVALID RESULTS!!!
//  (see the ACL API document for details).  This class is provided as a 
//  convenient test initialization, but labelled to warn users it is inadequate
//  for a proper security-minded application setup.  See the ACL user's manual.
//  It does provide a demonstration of the minimum necessary to setup a ACL 
//  session.
class AC_INADEQUATE_InitInterface
{
private:
    CERT::CSMIME  *m_pCsmime;         // NEVER delete, always use application pointer.
   long    m_lCmlSessionId;    // OPTIONAL pointer to CML session, if active.
   bool    m_bInitAclSessionHere;
public:
   AC_INADEQUATE_InitInterface() { m_pAclSessionId = NULL; m_pCsmime = NULL; 
                                   m_lCmlSessionId = 0; m_szError = NULL;
                                   m_bInitAclSessionHere = false; }
   AC_INADEQUATE_InitInterface(CERT::CSMIME &Csmime, long lCmlSessionId=0, 
                               acl::Session *pAclSession=NULL)
   { m_pCsmime = &Csmime; m_lCmlSessionId = lCmlSessionId; 
     m_pAclSessionId = pAclSession; m_szError = NULL; }
   ~AC_INADEQUATE_InitInterface() 
   { if (m_szError) free(m_szError); 
     if (m_bInitAclSessionHere && m_pAclSessionId) delete m_pAclSessionId; }
                        // DO NOT DESTROY m_pCsmime NOR m_pAclSessionId.

   long initializeSessions(
       CTIL::CSM_BufferLst *pTrustedSPIFBufLst=NULL,     // OPTIONAL setup.
       CTIL::CSM_BufferLst *pTrustedCertsBufLst=NULL,    // OPTIONAL setup.
       acl::TrustList *pTrustList=NULL);    // OPTIONAL setup.
   void  destroyAclSession() { if (m_pAclSessionId) 
                                { delete m_pAclSessionId; m_pAclSessionId = NULL; } }
                            // THIS call is explicit, since it may not always
                            //  be destroyed on class instance destruction.
   void  setAclSession(const acl::Session &AclSession) { m_pAclSessionId = 
                                               (acl::Session *)&AclSession; }

   // This member variable is directly accessible by the user for custom 
   //  modifications to the ACL session.  There are too many detail to attempt
   //  to create another wrapper for all possible permutations.
   acl::Session *m_pAclSessionId;
   char *m_szError;     // ACL error string returned to user, if present.
};

#endif  // ACL_USED

#endif  //_SM_CM_AC_SUPPORT_H_


// sm_CM_AC_Support.h

