
// sm_CM_AC_Support.cpp
// This utility include file provides the CML and ACL support classes to setup
//  minimal sessions.

#include "sm_api.h"
#include "sm_CM_AC_Support.h"


using namespace SFL;



#ifdef CML_USED

///////////////////////////////////////////////////////////////////////////////
CML_Interface::CML_Interface()
{
	m_lSrlSessionId = 0;
	m_lCmlSessionId = 0;
	m_pCtilMgr = NULL;
}

///////////////////////////////////////////////////////////////////////////////
CML_Interface::~CML_Interface() 
{
	if (m_lSrlSessionId != 0)
		SRL_DestroySession(&m_lSrlSessionId);
	if (m_lCmlSessionId != 0)
		CM_DestroySession(&m_lCmlSessionId);
}

///////////////////////////////////////////////////////////////////////////////
short CML_Interface::InitializeSessions(const char* ldapServerName,
										int ldapServerPort,
										const CML::ASN::BytesList& trustedCertsList)
{
	// Destroy any sessions that already exist
	if (m_lSrlSessionId != 0)
		SRL_DestroySession(&m_lSrlSessionId);
	if (m_lCmlSessionId != 0)
		CM_DestroySession(&m_lCmlSessionId);

	// Initialize the LDAP server info
	LDAPServerInit_struct ldapServerInfo;
	ldapServerInfo.LDAPserver		= (char*)ldapServerName;
	ldapServerInfo.LDAPport			= ldapServerPort;

	// Initialize the LDAP settings
	LDAPInitSettings_struct ldapSettings;
	ldapSettings.SharedLibraryName	= LDAP_DLL_NAME;
	ldapSettings.LDAPServerInfo		= NULL; //RWC11;&ldapServerInfo;
	ldapSettings.LDAPFunctions		= NULL;
	ldapSettings.ldapID				= NULL;
	ldapSettings.timeout			= 0;

	// Initialize the SRL settings
	SRL_InitSettings_struct srlSettings;
	srlSettings.LDAPinfo			= &ldapSettings;
	srlSettings.CertFileName		= "certs.db";
	srlSettings.CRLFileName			= "crl.db";
	// srlSettings.crlRefreshPeriod	= 60 * 60 * 24;	// One day
   srlSettings.crlRefreshPeriod = LONG_MAX; // NO REFRESH
	srlSettings.removeStaleCRL		= TRUE;

	// Create the SRL session
	short status = SRL_CreateSession(&m_lSrlSessionId, &srlSettings);
	if (status != SRL_SUCCESS)
	{
		std::cout << "Error! SRL_CreateSession() returned: " << status << "\n";
		return status;
	}

	// Initialize the CML settings
	InitSettings_struct cmlSettings;
	memset(&cmlSettings, 0, sizeof(cmlSettings));
	cmlSettings.cbSize			= sizeof(InitSettings_struct);
	cmlSettings.extHandle		= &m_lSrlSessionId;
	cmlSettings.pGetObj			= (ExtGetObjFuncPtr)SRL_RequestObjs;
	cmlSettings.pUrlGetObj		= (ExtUrlGetObjFuncPtr)SRL_URLRequestObjs;
	cmlSettings.pFreeObj		= (ExtFreeObjFuncPtr)SRL_FreeObjs;
	//RWC;OPTIONAL CRL check;cmlSettings.revPolicy		= CM_REVCRL;
	cmlSettings.revPolicy		= CM_REVCRL;
	cmlSettings.nCertCacheSize	= 1000;
	cmlSettings.certCacheTTL	= 60 * 60 * 24;		// One day 
	cmlSettings.nMaxPaths		= 10;
	cmlSettings.nCrlCacheSize	= 20;
	cmlSettings.crlCacheTTL		= 60 * 60 * 24;		// One day
	cmlSettings.crlGracePeriod	= 60 * 60 * 3;		// Three hours
	//RWC;cmlSettings.tokenList.token.type = 0;	        // Use default token

	// Create the CML session
	status = CM_CreateSessionExt(&m_lCmlSessionId, &cmlSettings);
	if (status != CM_NO_ERROR)
	{
		std::cout << "Error! CM_CreateSessionExt() returned: " <<
			CMU_GetErrorString(status) << "\n";
		return status;
	}

	// Set this session's trusted certs
	CML::ErrorInfoList trustCertErrors;
	status = CML::SetTrustedCerts(m_lCmlSessionId, trustedCertsList,
		&trustCertErrors);
	if (status != CM_NO_ERROR)
	{
		std::cout << "Error! CML::SetTrustedCerts() returned: " <<
			CMU_GetErrorString(status) << "\n";

		// Display the errors
		CML::ErrorInfoList::iterator i;
		for (i = trustCertErrors.begin(); i != trustCertErrors.end(); ++i)
		{
			std::cout << "\tError: " << CMU_GetErrorString(i->error);
			std::cout << "\n\t\tDN: ";
			CML::ASN::GenNames::const_iterator iName =
				i->name.Find(CML::ASN::GenName::X500);
            if (iName != i->name.end() && iName->GetType() == CML::ASN::GenName::X500)
				std::cout << (const char *)*iName->GetName().dn;
			else
				std::cout << "<No DN present>";
			if (!i->extraInfo.empty())
				std::cout << "\n\t\tExtra info: " << i->extraInfo;
			std::cout << std::endl;
		}

		return status;
	}
    // ADD trusted root to the "cert.db" file for proper lookup.
    // 
/* sib 4/5/04 this is no longer necessary due to recent change in cml where the 
   root cert cache is now checked for certpath

	Bytes_struct encTrustedBytes = { 0, NULL };
	trustedCertsList.begin()->FillBytesStruct(encTrustedBytes);
	SRL_DatabaseAdd(m_lSrlSessionId, &encTrustedBytes, SRL_CERT_TYPE);
	free(encTrustedBytes.data);
*/
	return status;
}


///////////////////////////////////////////////////////////////////////////////
void CML_Interface::AddCRL2DB(const CML::ASN::Bytes& encCRL)
{
	if (m_lSrlSessionId == 0)
		return;

	Bytes_struct encCRLBytes = { 0, NULL };
	encCRL.FillBytesStruct(encCRLBytes);
	SRL_DatabaseAdd(m_lSrlSessionId, &encCRLBytes, SRL_CRL_TYPE);
	free(encCRLBytes.data);
}


#endif // CML_USED


#ifdef ACL_USED

using namespace acl;
long AC_INADEQUATE_InitInterface::initializeSessions(
       CTIL::CSM_BufferLst *pTrustedSPIFBufLst,     // OPTIONAL setup.
       CTIL::CSM_BufferLst *pTrustedCertsBufLst,    // OPTIONAL setup.
       acl::TrustList *pTrustList)    // OPTIONAL setup.
{
   long lstatus = 0;
   CSM_BufferLst::iterator itTmpBuf;
   
   FUNC("AC_INADEQUATE_InitInterface::initializeSession(...)");
   try
   {
      if (m_pAclSessionId == NULL)
      {                 // THEN load some initial values.
         m_pAclSessionId = new acl::Session;
         m_bInitAclSessionHere = true;
         m_pAclSessionId->m_dms_mode = false;//TMP;true;
          //
          m_pAclSessionId->enableCML(m_lCmlSessionId);
          m_pAclSessionId->enableSPIFSignerAttribute(false);//TMP;true);
          m_pAclSessionId->disableValidation(false);
          m_pAclSessionId->disableTrustList(false);
      }     // END if m_pAclSessionId is NULL

      if (pTrustList)
      {
          // LOAD ACL trust elements.
          acl::TrustList::iterator itTmpTrust;
          for (itTmpTrust = pTrustList->begin(); 
               lstatus == 0 && itTmpTrust != pTrustList->end();
               itTmpTrust++)
          {
                   lstatus = m_pAclSessionId->addTrust(
                       (CML::ASN::DN &)itTmpTrust->GetDN(), 
                       (SNACC::AsnOid &)itTmpTrust->GetOid());
          }         // END for each trust list element.
      }     // END if pTrustList

      if (pTrustedCertsBufLst)
      {
          CML::ASN::Bytes cmlBuf;
          for (itTmpBuf =  pTrustedCertsBufLst->begin(); 
               itTmpBuf != pTrustedCertsBufLst->end();
               ++itTmpBuf)
          {
              cmlBuf.Set(itTmpBuf->Length(), (const unsigned char *)itTmpBuf->Access());
              m_pAclSessionId->addCC(cmlBuf);
          }         // END for each SPIF buffer.
      }     // END if pTrustedCertsBufLst

      if (pTrustedSPIFBufLst)
      {
          CML::ASN::Bytes cmlBuf;
          for (itTmpBuf =  pTrustedSPIFBufLst->begin();
               itTmpBuf != pTrustedSPIFBufLst->end();
               ++itTmpBuf)
          {
              cmlBuf.Set(itTmpBuf->Length(), (const unsigned char *)itTmpBuf->Access());
              m_pAclSessionId->addSPIF(cmlBuf);
          }         // END for each SPIF buffer.
      }     // END if pTrustedSPIFBufLst


      //
   }
   catch (SNACC::SnaccException &e)
   {
       this->m_szError = (char *) calloc(1, strlen(_func) + 
              strlen(": errorCode=") + strlen(e.what()) + 52);
       strcpy(m_szError, _func);
       strcat(m_szError, ": errorCode=");
       sprintf(&m_szError[strlen(m_szError)], "%d\n", e.m_errorCode);
       strcat(m_szError, "     error=");
       strcat(m_szError, e.what());
       strcat(m_szError, "\n");
       lstatus = -1;
      //throw;
   }


   return(lstatus);
}     // END SMP_Check_SetupACLSession(...)


#endif  // ACL_USED

// EOF sm_CM_AC_Support.cpp

