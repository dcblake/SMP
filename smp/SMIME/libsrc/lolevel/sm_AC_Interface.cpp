
//
//  sm_AC_Interface.cpp
//
//################

//#include <iostream>

#include "sm_api.h"

#include "sm_AC_Interface.h"

#ifdef ACL_USED

  using namespace SNACC;  using namespace CTIL;
  using namespace CERT;

using namespace acl;

_BEGIN_SFL_NAMESPACE

ACL_Interface::ACL_Interface(const ACL_Interface &that)
{
    m_usedPolicy = that.m_usedPolicy;
    if (that.m_pAclSessionId)
        m_pAclSessionId = that.m_pAclSessionId;
    if (that.m_lpszError)
        m_lpszError = strdup(that.m_lpszError);
    else
        m_lpszError = NULL;
    if (that.m_pACLMsgLabel)
       m_pACLMsgLabel = new CSM_Buffer(*that.m_pACLMsgLabel); 
    if (that.m_pEquivLabel)
    {
        m_pEquivLabel = new SecurityLabel;
       *m_pEquivLabel = *that.m_pEquivLabel;     
    }   // END If m_pEquivLabel
    else
        m_pEquivLabel = NULL;
}       // END ACL_Interface(const ACL_Interface &that)


///////////////////////////////////////////////////////////////////////////////
// THE following methods will return an error code if an ACL validation error is
//  is encountered.  It is up to the calling application to check m_lpszError.
long ACL_Interface::Check_ACLOutgoingRecip(const CM_SFLCertificate &ACMLCert, // INPUT
                           const CTIL::CSM_Buffer &CertificateEncrypterB)     // INPUT
{
   long lstatus = 0;
   RecipientCert *pTmpRC = NULL;
   SecurityLabel *pLabel=NULL;
   OutgoingLabel *pTmpLabel=NULL;
   SPIF spif;

   if (m_pAclSessionId == NULL || m_pACLMsgLabel == NULL)
   {
       this->m_lpszError = strdup("ACL_Interface::Check_ACLOutgoingRecip: NO ACL Session OR Msg Label present!");
       return(-1);
   }
   FUNC("ACL_Interface::Check_ACLOutgoingRecip(...)");
   try
   {
         CML::ASN::Bytes cmlBuf;
         cmlBuf.Set(m_pACLMsgLabel->Length(), (const unsigned char *)m_pACLMsgLabel->Access());
         pLabel = new SecurityLabel(cmlBuf);
         pTmpLabel = new OutgoingLabel(*pLabel);
         cmlBuf.Set(CertificateEncrypterB.Length(), (const unsigned char *)CertificateEncrypterB.Access());
         pTmpRC = new RecipientCert(cmlBuf);
         pTmpRC->intersect(this->m_pAclSessionId, ((CM_SFLCertificate &)ACMLCert).AccessCMLCert()->base());

         // FOR this recipient, check the label against its Clearance Extension
         pTmpRC->check(this->m_pAclSessionId, *pTmpLabel, m_usedPolicy, NULL/*&spif*/);

         if (pTmpRC != NULL)
            delete pTmpRC;

         if (pLabel)
            delete pLabel;
         if (pTmpLabel)
            delete pTmpLabel;      
   }
   catch (SnaccException &e)
   {
      if (pLabel)
         delete pLabel;
      if (pTmpRC != NULL)
         delete pTmpRC;
      if (this->m_lpszError == NULL)
         this->m_lpszError = (char *) calloc(1, 
              strlen(_func) + strlen(": errorCode=") + 
              strlen(e.what()) + 52);
       strcat(m_lpszError, _func);
       strcat(m_lpszError, ": errorCode=");
       sprintf(&m_lpszError[strlen(m_lpszError)], "%d\n", e.m_errorCode);
       strcat(m_lpszError, "     error=");
       strcat(m_lpszError, e.what());
       strcat(m_lpszError, "\n");
       //throw;
       lstatus = -1;
   }            // END catch(...)


   return(lstatus);
}   // END ACL_Interface::Check_ACLOutgoingRecip(...)


///////////////////////////////////////////////////////////////////////////////
long ACL_Interface::Check_ACLIncommingRecip(const CM_SFLCertificate &ACMLCert,
                           const CTIL::CSM_Buffer &CertificateEncrypterB,// INPUT
                           acl::SPIF *&pspif)                             // RETURNED
{
   long lstatus = 0;
   RecipientCert *pTmpRC = NULL;
   SecurityLabel *pLabel=NULL;
   IncomingLabel *pTmpLabel=NULL;

   if (m_pAclSessionId == NULL || m_pACLMsgLabel == NULL)
   {
       this->m_lpszError = strdup("ACL_Interface::Check_ACLIncommingRecip: NO ACL Session OR Msg Label present!");
       return(-1);
   }
   FUNC("ACL_Interface::Check_ACLIncommingRecip(...)");
   try
   {
         CML::ASN::Bytes cmlBuf;
         cmlBuf.Set(m_pACLMsgLabel->Length(), (const unsigned char *)m_pACLMsgLabel->Access());
         pLabel = new SecurityLabel(cmlBuf);
         pTmpLabel = new IncomingLabel(*pLabel);

         cmlBuf.Set(CertificateEncrypterB.Length(), (const unsigned char *)CertificateEncrypterB.Access());
        pTmpRC = new RecipientCert(cmlBuf);
        pTmpRC->intersect(this->m_pAclSessionId, ((CM_SFLCertificate &)ACMLCert).AccessCMLCert()->base());

        // FOR this recipient, check the label against its Clearance Extension
        //  (RWC; this routine throws an exception, it does not return 
        //   an error code).
        //pspif = new SPIF;
        pTmpRC->check(this->m_pAclSessionId, *pTmpLabel, pspif, m_pEquivLabel);

        if (pTmpRC != NULL)
           delete pTmpRC;
         if (pLabel)
            delete pLabel;
         if (pTmpLabel)
            delete pTmpLabel;      
   }
   catch (SnaccException &e)
   {
      if (pLabel)
         delete pLabel;
      if (pTmpRC != NULL)
         delete pTmpRC;
      if (this->m_lpszError == NULL)
         this->m_lpszError = (char *) calloc(1, 
              strlen(_func) + strlen(": errorCode=") + 
              strlen(e.what()) + 52);
       strcat(m_lpszError, _func);
       strcat(m_lpszError, ": errorCode=");
       sprintf(&m_lpszError[strlen(m_lpszError)], "%d\n", e.m_errorCode);
       strcat(m_lpszError, "     error=");
       strcat(m_lpszError, e.what());
       strcat(m_lpszError, "\n");
       //throw;
       lstatus = -1;
   }        // END catch(...)


   return(lstatus);
}       // END ACL_Interface::Check_ACLIncommingRecip(...)


///////////////////////////////////////////////////////////////////////////////
long ACL_Interface::Check_ACLIncommingOrig(const CM_SFLCertificate &ACMLCert,
                           const CTIL::CSM_Buffer &OrigCertificateB,      // INPUT
                           acl::SPIF &spif)// IN, MUST be same SPIF used for 
                                             // checking INCOMMING Recip 
                                             // (ourselves).
{
   long lstatus = 0;
   OriginatorCert  *pTmpOC = NULL;
   SecurityLabel *pLabel=NULL;
   IncomingLabel *pTmpLabel=NULL;

   if (m_pAclSessionId == NULL || m_pACLMsgLabel == NULL)
   {
       this->m_lpszError = strdup("ACL_Interface::Check_ACLIncommingOrig: NO ACL Session OR Msg Label present!");
       return(-1);
   }
   FUNC("ACL_Interface::Check_ACLIncommingOrig(...)");
   try
   {
         CML::ASN::Bytes cmlBuf;
         cmlBuf.Set(m_pACLMsgLabel->Length(), (const unsigned char *)m_pACLMsgLabel->Access());
         pLabel = new SecurityLabel(cmlBuf);
         pTmpLabel = new IncomingLabel(*pLabel);

            cmlBuf.Set(OrigCertificateB.Length(), (const unsigned char *)OrigCertificateB.Access());
            pTmpOC = new OriginatorCert(cmlBuf);
            pTmpOC->intersect(this->m_pAclSessionId, 
                      ((CM_SFLCertificate &)ACMLCert).AccessCMLCert()->base());

            // FOR this recipient, check the label against its Clearance Extension
            pTmpOC->check(this->m_pAclSessionId, *pTmpLabel, spif);

            if (pTmpOC != NULL)
               delete pTmpOC;

         if (pLabel)
            delete pLabel;
         if (pTmpLabel)
            delete pTmpLabel;      
   }
   catch (SnaccException &e)
   {
      if (pLabel)
         delete pLabel;
      if (pTmpOC != NULL)
         delete pTmpOC;
      if (this->m_lpszError == NULL)
         this->m_lpszError = (char *) calloc(1, 
              strlen(_func) + strlen(": errorCode=") + 
              strlen(e.what()) + 52);
       strcat(m_lpszError, _func);
       strcat(m_lpszError, ": errorCode=");
       sprintf(&m_lpszError[strlen(m_lpszError)], "%d\n", e.m_errorCode);
       strcat(m_lpszError, "     error=");
       strcat(m_lpszError, e.what());
       strcat(m_lpszError, "\n");
       //throw;
       lstatus = -1;
   }        // END catch(...)


   return(lstatus);
}       // END ACL_Interface::Check_ACLIncommingOrig(...)


///////////////////////////////////////////////////////////////////////////////
long ACL_Interface::Check_ACLOutgoingOrig(const CM_SFLCertificate& ACMLCert,		// INPUT
                                          const CTIL::CSM_Buffer& OrigCertificateB)	// INPUT
{
	// Check internal members
	if ((m_pAclSessionId == NULL) || (m_pACLMsgLabel == NULL))
	{
		m_lpszError = strdup("ACL_Interface::Check_ACLOutgoingOrig: NO ACL Session OR Msg Label present!");
		return -1;
	}

	FUNC("ACL_Interface::Check_ACLOutgoingOrig()");

	long lstatus = 0;
	try
	{
		// Construct the label and originator cert from their ASN.1-encoded forms
		OutgoingLabel outgoingLabel(CML::ASN::Bytes(m_pACLMsgLabel->Length(),
			(const uchar*)m_pACLMsgLabel->Access()));
		OriginatorCert origCert(CML::ASN::Bytes(OrigCertificateB.Length(),
			(const uchar*)OrigCertificateB.Access()));

		origCert.intersect(m_pAclSessionId, ACMLCert.AccessCMLCert()->base());

		// FOR this recipient, check the label against its Clearance Extension
		origCert.check(m_pAclSessionId, outgoingLabel, NULL/*spif*/);
	}
	catch (SnaccException& e)
	{
		if (m_lpszError == NULL)
		{
			m_lpszError = (char*)malloc(strlen(_func) + strlen(": errorCode=") +
				strlen(e.what()) + 52);
			strcpy(m_lpszError, _func);
		}
		else
			strcat(m_lpszError, _func);

		strcat(m_lpszError, ": errorCode=");
		sprintf(&m_lpszError[strlen(m_lpszError)], "%d\n", e.m_errorCode);
		strcat(m_lpszError, "     error=");
		strcat(m_lpszError, e.what());
		strcat(m_lpszError, "\n");

		//throw;
		lstatus = -1;
   }        // END catch(...)

	return(lstatus);
}	// END ACL_Interface::Check_ACLOutgoingOrig()


//
//
ACL_Interface::ACL_Interface(acl::Session &AclSessionId, 
              const CTIL::CSM_Buffer *pACLMsgLabel)
{ 
    setACLSession(AclSessionId); 
    m_lpszError=NULL; 
    m_pEquivLabel = NULL;
    if (pACLMsgLabel) 
        setACLMsgLabel(*pACLMsgLabel);
    else 
        m_pACLMsgLabel = NULL;
}

//
//
ACL_Interface::~ACL_Interface() 
{ 
    if (m_lpszError) 
        free(m_lpszError);
    if (m_pACLMsgLabel) 
        delete m_pACLMsgLabel;
    if (m_pEquivLabel)
        delete m_pEquivLabel;
    // DO NOT DESTOY m_pAclSessionId.
}

//
//
void ACL_Interface::setACLSession(const acl::Session &AclSessionId) 
{ 
    m_pAclSessionId = (acl::Session *)&AclSessionId; 
}

//
//
void ACL_Interface::setACLMsgLabel(const CTIL::CSM_Buffer &ACLMsgLabel)
{ 
    if (m_pACLMsgLabel) 
        delete m_pACLMsgLabel;
    m_pACLMsgLabel = new CSM_Buffer(ACLMsgLabel); 
}



//
//
acl::SPIF *ACL_Interface::lookupSpif(const SNACC::AsnOid &oidPolicyId)
{
    MatchInfo matchInfo;
    acl::SPIF *pSpif=NULL;
    matchInfo.setPolicyId(oidPolicyId);
    acl::SPIFList *pSpifList = m_pAclSessionId->getSPIF(matchInfo);
    if (pSpifList)
    {
        pSpif = &(*pSpifList->begin());
    }       // END if pSpifList
    return pSpif;
}

_END_SFL_NAMESPACE
#endif  // CML_USED

// END AC_Interface.cpp
