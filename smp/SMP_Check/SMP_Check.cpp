// SMP_Check.cpp
//

//RWC; IF free3 CTIl is available, perform full test, otherwise 
//RWC;   comment next line out.
#define SM_FREE3_TEST
//#define SM_PKCS11_TEST
//#define SM_CAPI_TEST
//#define DISABLE_CML_ACL

#define CERT_ROOT       "./TestCARSA@test.gov.cer"
#define CERT_USER       "./Test1@Test1.sig"
#define CERT_USER_P12   "./Test1@Test1X_12.pfx"

#include "sm_api.h"
#include "sm_AppLogin.h"
#include "sm_CM_AC_Support.h"   // LOCAL test include file.

#ifndef LDAP_PORT
#define LDAP_PORT 389
#endif
using namespace SFL;
using namespace CERT;
using namespace CTIL;
using namespace SNACC;

#include <stdio.h>
#include "string.h"

extern "C" {
long DLLBuildTokenInterface(CTIL::CSM_CtilMgr &, char *);
}

void    checkCreate(CSMIME *pAppLogin, 
                       char *pszCertificateFileNamesForEncrypters[], 
                       const char *msgData, long msgLength, AsnOid *pmsgOid,
                       CSM_Buffer *pACLMsgLabel=NULL, acl::Session *pACLsession=NULL,
                       long lCMLSessionIdIN=0, long lSRLSessionIdIN=0);
void    checkRead(CSMIME *pAppLogin, 
                  const char *msgData=NULL, long msgLength=0, acl::Session *pACLsession=NULL,
                  long lCMLSessionIdIN=0, long lSRLSessionIdIN=0);
long SMP_Check_SetupCMLSession(CML_Interface& cmlSession);
long SMP_Check_SetupACLSession(CSMIME &CsmimeInstance, const long lCmlSessionId, 
                               AC_INADEQUATE_InitInterface *&pACL_Inadequate_Interface);// RETURNED


/*#ifdef RWC_REMOVE_SINCE_INTEGRATED
long SMP_Check_ACLOutgoingRecip(acl::Session &ACLsession, char *pszCertificateFileNamesForEncrypters[],
                        CSM_Buffer &ACLMsgLabel);
long SMP_Check_ACLIncommingRecip(acl::Session &ACLsession, char *pszCertificateFileNamesForEncrypters[],
                                 CSM_Buffer &ACLMsgLabel, acl::SPIF *&pspif);
long SMP_Check_ACLIncommingOrig(acl::Session &ACLsession, char *pszOrigCertificateFileName,
                        CSM_Buffer &ACLMsgLabel, 
                        acl::SPIF &spif);// IN, MUST be same SPIF used for 
                                    // checking INCOMMING Recip (ourselves).
#endif  // RWC_REMOVE_SINCE_INTEGRATED*/

int main(int argc, char* argv[])
{
    long msgLength=0;
    char *lpszError=NULL;
    AsnOid *pmsgOid=NULL;
    CSM_AppLogin *pAppLogin=NULL;
    const char *msgData=NULL;
    char *pszCertificateFileNamesForEncrypters[]={
       CERT_USER, 
       // "./mycert.dat",
       // "./GCLIB.dll-00-01CertRWC.out",
       ""};                            // NULL terminate array of data.
#ifdef _DEBUG
	#ifdef _UNIX
   		char *pCTILFree3="libsm_free3DLL_d";
	#else
   		char *pCTILFree3="sm_free3DLLd";
	#endif
#else
	#ifdef _UNIX
   		char *pCTILFree3="libsm_free3DLL";
	#else
   		char *pCTILFree3="sm_free3DLL";
	#endif
#endif
   CSM_Buffer EncapContentBuf;
   AC_INADEQUATE_InitInterface *pACL_Inadequate_Interface=NULL;
   CSM_Buffer ACLMsgLabel("./LABEL_ClearanceVersion.lbl");
   //CSM_Buffer *pACLMsgLabelIN=NULL;
   acl::SPIF *pRecipSpif=NULL;
   long lstatus = 0;

   SME_SETUP ("main")

#ifndef _DEBUG
#ifdef _WIN32
   char *pCTILFree3="sm_free3DLL";
#else
   char *pCTILFree3="libsm_free3DLL";
#endif		// _WIN32
#else
#ifdef _WIN32
   char *pCTILFree3="sm_free3DLLd";
#else
   char *pCTILFree3="libsm_free3DLL_d";
#endif          // _WIN32
#endif      //DEBUG

     ////////////////////////////////////////////////////////////////
     // SETUP login details.
     pAppLogin = new CSM_AppLogin;
     // FOR THE FOLLOWING AddLogin(...) calls, the DLL file can be in the 
     //  PATH, where you could simply specify "sm_fere3DLLd"
#ifdef ENABLE_STATIC
	  DLLBuildTokenInterface(*pAppLogin, "sm_free3DLL "CERT_USER_P12" password");
#elif defined (SM_CAPI_TEST)
   //RWC;NOTE; The CAPI CTIL will only work if an appropriate private key/cert 
   //  has been loaded into the MS Registry.  Also, you will probably have to 
   //  disable the CML and ACL checks since our CANNED data will not match your
   //  certificate.
   pAppLogin->AddLogin(pCTILFree3, "sm_capiDLL \"User Cert Name\" NULL FLAG=signer");
   pAppLogin->AddLogin(pCTILFree3, "sm_capiDLL \"User Cert Name\" NULL FLAG=encrypter");
#elif defined (SM_FREE3_TEST)
     pAppLogin->AddLogin(pCTILFree3, "sm_free3DLL "CERT_USER_P12" password");
     //pAppLogin->AddLogin(pCTILFree3, "sm_free3DLL ./AlicePrivRSASign.pri_12.pfx password");
     //pAppLogin->AddLogin(pCTILFree3, "sm_free3DLL ./DianePrivRSASignEncrypt.pri_12.pfx password");
#elif defined (SM_PKCS11_TEST)
     pAppLogin->AddLogin("sm_pkcs11Free3DLLd", "sm_pkcs11Free3DLL 0 1234 GCLIB.dll");
     //pAppLogin->AddLogin("sm_pkcs11DLLd", "sm_pkcs11DLL 0 1234 GCLIB.dll");
                        // SETUP GemPlus smartcard PKCS11 interface
     pAppLogin->AddLogin(pCTILFree3, NULL);     // FOR content encryption
     //RWC;TBD; Create default login only for verification only and indicate such!
#endif      // SM_FREE3_TEST  OR SM_PKCS11_TEST

	////////////////////////////////////////////////////////////////
	// SETUP CML AND ACL input session details
	CML_Interface cmlInterface;

#ifndef DISABLE_CML_ACL
	lstatus = SMP_Check_SetupCMLSession(cmlInterface);
	if (lstatus != 0)
	{
		std::cout << "error on SMP_Check_SetupCMLSession: lstatus=" <<
			lstatus <<  "\n";
	}

	lstatus = SMP_Check_SetupACLSession(*pAppLogin,
		cmlInterface.GetCMLSessionID(), pACL_Inadequate_Interface);
	if (lstatus != 0)
	{
		std::cout << "error on SMP_Check_SetupACLSession: lstatus=" <<
			lstatus << "\n";
		if (pACL_Inadequate_Interface->m_szError)
			std::cout << pACL_Inadequate_Interface->m_szError << "\n";
	}
#endif  // DISABLE_CML_ACL


	////////////////////////////////////////////////////////////////
	// PERFORM creation, sign and encrypt
	if (cmlInterface.UsingCML() && pACL_Inadequate_Interface)
	{
		checkCreate(pAppLogin, pszCertificateFileNamesForEncrypters,
			msgData, msgLength, pmsgOid, &ACLMsgLabel,
			pACL_Inadequate_Interface->m_pAclSessionId,
			cmlInterface.GetCMLSessionID(), cmlInterface.GetSRLSessionID());
	}
	else
	{
		checkCreate(pAppLogin, pszCertificateFileNamesForEncrypters,
			msgData, msgLength, pmsgOid, &ACLMsgLabel);
	}

	////////////////////////////////////////////////////////////////
	// CLEANUP.
   if (pACL_Inadequate_Interface)
      delete pACL_Inadequate_Interface;
   if (pAppLogin)
   {
       delete pAppLogin;
       pAppLogin = NULL;
   }
   pACL_Inadequate_Interface = NULL;
   std::cout.flush();

   
   //#############################################
   // SETUP login details for UNWRAP operation.
   pAppLogin = new CSM_AppLogin;
#ifdef SM_FREE3_TEST
#ifdef ENABLE_STATIC
   DLLBuildTokenInterface(*pAppLogin, 
		"sm_free3DLL "CERT_USER_P12" password");
#else
   pAppLogin->AddLogin(pCTILFree3, "sm_free3DLL "CERT_USER_P12" password");
#endif
#else //SM_FREE3_TEST
#ifdef SM_PKCS11_TEST
     pAppLogin->AddLogin("sm_pkcs11DLLd", "sm_pkcs11DLL 0 1234 GCLIB.dll");
                        // SETUP GemPlus smartcard PKCS11 interface
     pAppLogin->AddLogin(pCTILFree3, NULL);     // FOR content encryption
     //RWC;TBD; Create default login only for verification only and indicate such!
#endif      // SM_PKCS11_TEST
#endif      //SM_FREE3_TEST
   //pAppLogin->AddLogin(pCTILFree3, "sm_free3DLL ./DianePrivRSASignEncrypt.pri_12.pfx password");
#ifndef DISABLE_CML_ACL
   lstatus = SMP_Check_SetupACLSession(*pAppLogin, 
                    cmlInterface.GetCMLSessionID(), pACL_Inadequate_Interface);
#endif  // DISABLE_CML_ACL

	////////////////////////////////////////////////////////////////
	// PERFORM read, dedcrypt and verify.
	if (cmlInterface.UsingCML() && pACL_Inadequate_Interface)
	{
		checkRead(pAppLogin, NULL, 0,
			pACL_Inadequate_Interface->m_pAclSessionId,
			cmlInterface.GetCMLSessionID(), cmlInterface.GetSRLSessionID());
	}
	else
		checkRead(pAppLogin);


	////////////////////////////////////////////////////////////////
	// CLEANUP.
	if (pACL_Inadequate_Interface)
		delete pACL_Inadequate_Interface;
	if (pAppLogin)
	{
		delete pAppLogin;
		pAppLogin = NULL;
	}
	if (pRecipSpif)
		delete pRecipSpif;

	SME_FINISH
	SME_CATCH_SETUP
		Exception.getCallStack(std::cout);
		//RWC;NOTE; DO NOT DELETE pAppLogin inside this exception handler
		//RWC; in case exception thrown from a dynamically loaded CTIL.
	SME_CATCH_FINISH_C2(lpszError);

	if (lpszError)
	{
		std::cout << lpszError << "\n";
		std::cout.flush();
		free(lpszError);
	}

	if (pAppLogin)
	{
		delete pAppLogin;
		pAppLogin = NULL;
	}

	return 0;
}


//
//
long SMP_Check_SetupCMLSession(CML_Interface& cmlSession)
{
	SME_SETUP ("SMP_Check_SetupCMLSession");

	// Build list of trusted certs
	CML::ASN::BytesList trustedCerts;
	trustedCerts.push_back(CERT_ROOT);

	// Initialize the CML and SRL sessions
	long lstatus = cmlSession.InitializeSessions(NULL,
		LDAP_PORT, trustedCerts);
	if (lstatus != 0)
		SME_THROW(lstatus, "Unable to create CML or SRL session!", NULL);

	// Add the CRLs to the database
	cmlSession.AddCRL2DB("./RootTestNistCrl.out");
	//OPTIONAL;CSM_Buffer BufCert("./CAFile_NOT_NOW");
	//OPTIONAL;CMLInterface.dbAddCert(BufCert);

    //RWC; DEBUG CML validation to test trusted root cert (due to lack of 
    //RWC;  info from the ACL if it fails).
    #ifdef _DEBUG
    CSM_Buffer BufRootCert(CERT_ROOT);
    CM_SFLCertificate ACMLCert(BufRootCert);
    try {
            ACMLCert.m_lCmlSessionId = cmlSession.GetCMLSessionID();
            ACMLCert.m_lSrlSessionId = cmlSession.GetSRLSessionID();
            long lstatus2 = ACMLCert.Validate();
            //long lstatus2 = CMLValidateCert(ACMLCert, (CSM_CertificateChoice *)pCSInst->AccessUserCertificate()); 
            if (lstatus2 != 0 && ACMLCert.m_lpszError)
            {
               char pszBuf[1000];
               strncpy(pszBuf, ACMLCert.m_lpszError , 999);
               SME_THROW(lstatus2, pszBuf, NULL);
            }        // IF lstatus on CML VerifySignature()
    }       // END try
    catch(...)
    {       // Basically ignore here, leave actual error to appropriate library.
        if (ACMLCert.m_lpszError)
        {
           char pszBuf[1000];
           strcpy(pszBuf, "EXCEPTION::: ");
           strncat(pszBuf, ACMLCert.m_lpszError , 950);
           SME_THROW(33, pszBuf, NULL);
        }        // IF lstatus on CML VerifySignature()
    }
    #endif  // _DEBUG

	return lstatus;

	SME_FINISH_CATCH
} // end of SMP_Check_SetupCMLSession()


//
//
using namespace acl;
long SMP_Check_SetupACLSession(CSMIME &CsmimeInstance, const long lCmlSessionId, 
                               AC_INADEQUATE_InitInterface *&pACL_Inadequate_Interface)   // RETURNED
{
   long lstatus = 0;
                            // WE DO NOT PASS in an existing ACL session here.
   CTIL::CSM_BufferLst TrustedSPIFBufLst;
   CTIL::CSM_BufferLst TrustedCertsBufLst;
   acl::TrustList TrustList;


   pACL_Inadequate_Interface = new AC_INADEQUATE_InitInterface(CsmimeInstance, lCmlSessionId);
   // SETUP SPIFs
   CSM_Buffer *pBuf = &(*TrustedSPIFBufLst.append());
   pBuf->SetFileName("./tsp1pif1.spf");
   // SETUP trusted certs
   pBuf = &(*TrustedCertsBufLst.append());
   pBuf->SetFileName(CERT_USER);
   // SETUP trust list (OID and DN)
   AsnOid TmpPolicyId("2.16.840.1.101.2.1.12.0.1");
   SNACC::Certificate SNACCCert;
   pBuf->Decode(SNACCCert);
   CML::ASN::DN TmpDN(SNACCCert.toBeSigned.subject);
   acl::Trust *pTrust = &(*TrustList.insert(TrustList.end(), acl::Trust()));
   pTrust->setOID(TmpPolicyId);
   pTrust->setDN(TmpDN);
   CSM_Buffer BufRoot(CERT_ROOT);
   BufRoot.Decode(SNACCCert);
   CML::ASN::DN TmpDN2(SNACCCert.toBeSigned.subject);
   pTrust = &(*TrustList.insert(TrustList.end(), acl::Trust()));
   pTrust->setOID(TmpPolicyId);
   pTrust->setDN(TmpDN2);

   lstatus = pACL_Inadequate_Interface->initializeSessions(&TrustedSPIFBufLst,
        &TrustedCertsBufLst, &TrustList);

   return(lstatus);
}     // END SMP_Check_SetupACLSession(...)



// EOF SMP_Check.cpp

