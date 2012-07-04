// SMP_Check.cpp
//

#include "sm_api.h"
#include "sm_AppLogin.h"
#ifdef WIN32
  #include <crtdbg.h>        // For WIN32 memory leak checking
#endif


//RWC; IF free3 CTIl is available, perform full test, otherwise 
//RWC;   comment next line out.
#define SM_FREE3_TEST
//#define SM_PKCS11_TEST
//#define SM_CAPI_TEST

#if defined(SM_FREE3_TEST)
	#define CTIL_NAME  "sm_free3DLL"
#elif defined(SM_PKCS11_TEST)
	#define CTIL_NAME  "sm_pkcs11DLL"
#elif defined(SM_CAPI_TEST)
	#define CTIL_NAME  "sm_capiDLL"
#else
	#error Invalid CTIL specified for testing!
#endif

#ifdef WIN32
	#define LIB_PREFIX        ""
	#define LIB_EXT           ""
	#ifdef _DEBUG
		#define DEBUG_SUFFIX   "d"
	#else
		#define DEBUG_SUFFIX   ""
	#endif // _DEBUG
#else
	#define LIB_PREFIX        "lib"
	#define LIB_EXT           ""
	#ifdef _DEBUG
		#define DEBUG_SUFFIX   "_d"
	#else
		#define DEBUG_SUFFIX   ""
	#endif // _DEBUG
#endif

#define CTIL_FILE_NAME  LIB_PREFIX CTIL_NAME DEBUG_SUFFIX LIB_EXT

#define CERT_ROOT       "./TestCARSA@test.gov.cer"
#define CERT_USER       "./Test1@Test1.sig"
#define CERT_USER_P12   "./Test1@Test1X_12.pfx"


#ifndef LDAP_PORT
#define LDAP_PORT 389
#endif


// Using declarations
using namespace SFL;
using namespace CERT;
using namespace CTIL;
using namespace SNACC;


// Function Prototypes
extern "C" long DLLBuildTokenInterface(CTIL::CSM_CtilMgr& , char* );

void checkCreate(CSMIME* pAppLogin,
					  char* pszCertificateFileNamesForEncrypters[],
					  const char* msgData, long msgLength, AsnOid* pmsgOid,
					  CSM_Buffer* pACLMsgLabel = NULL,
					  acl::Session* pACLsession = NULL, long lCMLSessionIdIN = 0,
					  long lSRLSessionIdIN = 0);
void checkRead(CSMIME* pAppLogin, const char* msgData = NULL,
					long msgLength = 0, acl::Session* pACLsession = NULL,
					long lCMLSessionIdIN = 0, long lSRLSessionIdIN = 0);
short SMP_Check_SetupCMLSession(CM_Interface& cmlSession);
long SMP_Check_SetupACLSession(acl::Session& aclSession, CSMIME& CsmimeInstance,
										 long lCmlSessionId);


int main(int argc, char* argv[])
{
#ifdef WIN32
	long memAllocNum = 0;
	// Set the debug flags for memory leak checking
	_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);

	int debugFlag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	debugFlag = _CrtSetDbgFlag(debugFlag | _CRTDBG_LEAK_CHECK_DF );
//	debugFlag = _CrtSetDbgFlag(debugFlag |
//		_CRTDBG_DELAY_FREE_MEM_DF | _CRTDBG_CHECK_ALWAYS_DF);

	// Set a breakpoint on the allocation request number
	if (memAllocNum > 0)
		_CrtSetBreakAlloc(memAllocNum);
#endif // WIN32

   char* lpszError = NULL;
	CM_Interface cmlInterface;

	SME_SETUP("main")

	////////////////////////////////////////////////////////////////
	// SETUP login details.
	CSM_AppLogin appLogin;
	// FOR THE FOLLOWING AddLogin(...) calls, the DLL file can be in the
	//  PATH, where you could simply specify "sm_free3DLLd"
#ifdef SM_FREE3_TEST
	#ifdef ENABLE_STATIC
		DLLBuildTokenInterface(appLogin, CTIL_NAME " " CERT_USER_P12 " password");
	#else
		appLogin.AddLogin(CTIL_FILE_NAME, CTIL_NAME " " CERT_USER_P12 " password");
	#endif // ENABLE_STATIC
#elif defined(SM_CAPI_TEST)
	//RWC;NOTE; The CAPI CTIL will only work if an appropriate private key/cert
	//  has been loaded into the MS Registry.  Also, you will probably have to
	//  disable the CML and ACL checks since our CANNED data will not match your
	//  certificate.
	appLogin.AddLogin(CTIL_FILE_NAME, CTIL_NAME " \"User Cert Name\" NULL FLAG=signer");
	appLogin.AddLogin(CTIL_FILE_NAME, CTIL_NAME " \"User Cert Name\" NULL FLAG=encrypter");
#elif defined(SM_PKCS11_TEST)
	// SETUP GemPlus smartcard PKCS11 interface
	appLogin.AddLogin(CTIL_FILE_NAME, CTIL_NAME " 0 1234 GCLIB.dll");
	// FOR content encryption:
	appLogin.AddLogin(LIB_PREFIX "sm_free3DLL" DEBUG_SUFFIX LIB_EXT, NULL);
	//RWC;TBD; Create default login only for verification only and indicate such!
#endif

   ////////////////////////////////////////////////////////////////
	// SETUP CML AND ACL input session details
	long lstatus = SMP_Check_SetupCMLSession(cmlInterface);
	if (lstatus != 0)
	{
		std::cout << "error on SMP_Check_SetupCMLSession: lstatus=" <<
			lstatus <<  std::endl;
	}

	// Create and initialize an ACL session
	acl::Session aclSession;
	lstatus = SMP_Check_SetupACLSession(aclSession, appLogin,
		cmlInterface.GetCMLSessionID());
	if (lstatus != 0)
	{
		std::cout << "error on SMP_Check_SetupACLSession: lstatus=" <<
			lstatus << "\n";
	}


	////////////////////////////////////////////////////////////////
	// PERFORM creation, sign and encrypt
	const char* msgData = NULL;
	long msgLength = 0;
	CSM_Buffer ACLMsgLabel("./LABEL_ClearanceVersion.lbl");
	char *pszCertificateFileNamesForEncrypters[]= {
		CERT_USER,
//		"./mycert.dat",
//		"./GCLIB.dll-00-01CertRWC.out",
		NULL  // NULL terminate array of data.
	};

	if (cmlInterface.UsingCML())
	{
		checkCreate(&appLogin, pszCertificateFileNamesForEncrypters,
			msgData, msgLength, NULL, &ACLMsgLabel, &aclSession,
			cmlInterface.GetCMLSessionID(), cmlInterface.GetSRLSessionID());
	}
	else
	{
		checkCreate(&appLogin, pszCertificateFileNamesForEncrypters,
			msgData, msgLength, NULL, &ACLMsgLabel);
	}

   std::cout.flush();

	////////////////////////////////////////////////////////////////
	// PERFORM read, decrypt and verify
	if (cmlInterface.UsingCML())
	{
		checkRead(&appLogin, NULL, 0, &aclSession,
			cmlInterface.GetCMLSessionID(), cmlInterface.GetSRLSessionID());
	}
	else
		checkRead(&appLogin);


	////////////////////////////////////////////////////////////////
	// CLEANUP.
   SME_FINISH
	SME_CATCH_SETUP
		Exception.getCallStack(std::cout);
		//RWC;NOTE; DO NOT DELETE pAppLogin inside this exception handler
		//RWC; in case exception thrown from a dynamically loaded CTIL.
	SME_CATCH_FINISH_C2(lpszError);

	if (lpszError != NULL)
	{
		std::cout << lpszError << std::endl;
		free(lpszError);
	}

	// Destroy the CML and SRL sessions
	ulong cmlSession = cmlInterface.GetCMLSessionID();
	ulong srlSession = cmlInterface.GetSRLSessionID();
	CM_DestroySession(&cmlSession);
	SRL_DestroySession(&srlSession);

	return 0;
} // end of main()


//
//
short SMP_Check_SetupCMLSession(CM_Interface& cmlSession)
{
	SME_SETUP ("SMP_Check_SetupCMLSession");

	// Initialize the SRL settings without LDAP
	SRL_InitSettings_struct srlSettings = {
		NULL, "certs.db", "crl.db", LONG_MAX, TRUE };

	// srlSessionID must be declared static to be used in cmlSettings.extHandle
	static ulong srlSessionID;  

	// Create the SRL session
	short status = SRL_CreateSession(&srlSessionID, &srlSettings);
	if (status != SRL_SUCCESS)
		return status;

	// Initialize the CML settings
	InitSettings_struct cmlSettings;
	memset(&cmlSettings, 0, sizeof(cmlSettings));
	cmlSettings.cbSize         = sizeof(InitSettings_struct);
	cmlSettings.extHandle      = &srlSessionID;
	cmlSettings.pGetObj        = (ExtGetObjFuncPtr)SRL_RequestObjs;
	cmlSettings.pUrlGetObj     = (ExtUrlGetObjFuncPtr)SRL_URLRequestObjs;
	cmlSettings.pFreeObj       = (ExtFreeObjFuncPtr)SRL_FreeObjs;
	cmlSettings.revPolicy      = CM_REVCRL;
	cmlSettings.nCertCacheSize = 1000;
	cmlSettings.certCacheTTL   = 60 * 60 * 24;      // One day 
	cmlSettings.nMaxPaths      = 10;
	cmlSettings.nCrlCacheSize  = 20;
	cmlSettings.crlCacheTTL    = 60 * 60 * 24;      // One day
	cmlSettings.crlGracePeriod = 60 * 60 * 3;       // Three hours

	// Create the CML session
	ulong cmlSessionID;
	status = CM_CreateSessionExt(&cmlSessionID, &cmlSettings);
	if (status != CM_NO_ERROR)
	{
		SRL_DestroySession(&srlSessionID);
		return status;
	}

	// Build list of trusted certs
	CML::ASN::BytesList trustedCerts;
	trustedCerts.push_back(CERT_ROOT);

	// Set this session's trusted certs
	CML::ErrorInfoList trustedCertErrors;
	status = CML::SetTrustedCerts(cmlSessionID, trustedCerts,
		&trustedCertErrors);
	if (status != CM_NO_ERROR)
	{
		CM_DestroySession(&cmlSessionID);
		SRL_DestroySession(&srlSessionID);

		// Dump the errors to cout
		std::string errorString("Trusted cert errors:\n");
		CM_Interface::ConvertErrorList(errorString, trustedCertErrors);
		std::cout << errorString;

		return status;
	}

	// Set the CML and SRL session IDs into the interface class
	cmlSession.SetSessions(cmlSessionID, srlSessionID);

	// Add the CRLs to the database
	return cmlSession.dbAddCRL(CSM_Buffer("./RootTestNistCrl.out"));

	SME_FINISH_CATCH
} // end of SMP_Check_SetupCMLSession()


//
//
long SMP_Check_SetupACLSession(acl::Session& aclSession, CSMIME& CsmimeInstance,
										 long lCmlSessionId)
{
	// Initialize the ACL session
	aclSession.enableCML(lCmlSessionId);
	// Test cert doesn't have SPIF signer attribute in Subject Directory
	// Attributes extension, so disable following check
	aclSession.enableSPIFSignerAttribute(false);
	// Test cert doesn't have Non-repudiation key usage bit set, so disable
	// following check
	aclSession.enableDMS(false);
	aclSession.disableValidation(false);
	aclSession.disableTrustList(false);

	// Load the clearance certs into the ACL's cache
	aclSession.addCC(CERT_USER);

	// Load the SPIFs into the ACL's cache
	aclSession.addSPIF("./tsp1pif1.spf");

	// Load the SPIF signer DN for each security policy OID
	int result = aclSession.addTrust(CML::ASN::Cert(CERT_ROOT).subject,
		"2.16.840.1.101.2.1.12.0.1");
	
	return result;
} // END SMP_Check_SetupACLSession(...)


// EOF SMP_Check.cpp
