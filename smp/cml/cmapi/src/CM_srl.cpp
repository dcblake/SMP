/*****************************************************************************
File:     CM_srl.cpp
Project:  Certificate Management Library
Contents: Routines to interface with the Storage and Retrieval Library API

Created:  17 Nov 2000
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  29 October 2004

Version:  2.5

*****************************************************************************/

/* ------------- */
/* Include Files */
/* ------------- */
#include "CM_cache.h"
#include "srlapi.h"
#ifdef HPUX32
	#include <dl.h>			// Needed for dynamic loading of SRL
#elif !defined(WIN32)
	#include <dlfcn.h>		// Needed for dynamic loading of SRL
#endif
  

// Using declarations
using namespace CML;
using namespace CML::Internal;


//////////////////////
// Type Definitions //
//////////////////////
typedef short (*PExtCreateSessFn)(ulong *sessionID, SRL_InitSettings_struct *pSettings);
typedef short (*PExtDestroySessFn)(ulong *sessionID);
typedef short (*PExtGetTrustedCerts)(ulong sessionID, EncCert_LL **trustedCerts);


/////////////////////////
// Function Prototypes //
/////////////////////////
static HINSTANCE link2SRL(const char* libName, ulong& sessionID,
						  CallbackFunctions& funcs,
						  PExtGetTrustedCerts* ppGetCertsFn,
						  PExtFreeEncCertList* ppFreeCertsFn);
static void unlinkSRL(HINSTANCE hDLL, ulong* pSessionID);


//////////////////////
// Global Variables //
//////////////////////
const char* gLibName = LIB_PREFIX "srlapi" DEBUG_INDICATOR LIB_EXT;


/////////////////////////////////////
// SrlSession class implementation //
/////////////////////////////////////
SrlSession::SrlSession(CallbackFunctions& cmlFuncs,
					   EncCert_LL** ppTrustedSrlCerts,
					   PExtFreeEncCertList* FreeEncCertListFP)
{
	// Check parameters
	if ((ppTrustedSrlCerts == NULL) || (FreeEncCertListFP == NULL))
		throw CML_ERR(CM_NULL_POINTER);

	// Initialize members
	srlLibHandle = NULL;
	sessionID = 0;

	// Link to the SRL
	PExtGetTrustedCerts fpSRLGetTrustedCerts;
	srlLibHandle = link2SRL(gLibName, sessionID, cmlFuncs,
		&fpSRLGetTrustedCerts, FreeEncCertListFP);
	cmlFuncs.extHandle = &sessionID;
		
	// Get and load the trusted certs from the SRL (if not already present)
	if (*ppTrustedSrlCerts == NULL)
	{
		short srlErr = fpSRLGetTrustedCerts(sessionID, ppTrustedSrlCerts);
		if ((srlErr != SRL_SUCCESS) && (srlErr != SRL_NOT_FOUND))
		{
			unlinkSRL((HINSTANCE)srlLibHandle, &sessionID);
			throw CML_ERR(srlErr);
		}
	}
}


SrlSession::~SrlSession()
{
	if (srlLibHandle != NULL)
		unlinkSRL((HINSTANCE)srlLibHandle, &sessionID);
}


////////////////
// link2SRL() //
////////////////
HINSTANCE link2SRL(const char* libName, ulong& sessionID,
				   CallbackFunctions& funcs, PExtGetTrustedCerts* ppGetCertsFn,
				   PExtFreeEncCertList* ppFreeCertsFn)
{
	// Check parameters
	if ((libName == NULL) || (ppGetCertsFn == NULL) || (ppFreeCertsFn == NULL))
		throw CML_ERR(CM_NULL_POINTER);

	// Load the SRL library
	HINSTANCE hDLL = LoadLibrary(libName);
	if (hDLL == NULL)
		throw CML_ERR(CM_SRL_INITIALIZATION_FAILED);

	// Set the callback function pointers
#ifdef HPUX32
	shl_findsym(&hDLL, "SRL_RequestObjs", TYPE_PROCEDURE,
		(void*) &funcs.pGetObj);
	shl_findsym(&hDLL, "SRL_FreeObjs", TYPE_PROCEDURE,
		(void*) &funcs.pFreeObj);
	shl_findsym(&hDLL, "SRL_URLRequestObjs", TYPE_PROCEDURE,
		(void*) &funcs.pUrlGetObj);

	PExtCreateSessFn fpSRLCreateSession;
	shl_findsym(&hDLL, "SRL_CreateSession", TYPE_PROCEDURE,
		(void*) &fpSRLCreateSession);

	shl_findsym(&hDLL, "SRL_FreeEncCertList", TYPE_PROCEDURE,
		(void*) ppFreeCertsFn);

	shl_findsym(&hDLL, "SRL_GetTrustedCerts", TYPE_PROCEDURE,
		(void*) ppGetCertsFn);
#else

	funcs.pGetObj = (ExtGetObjFuncPtr)GetProcAddress(hDLL, "SRL_RequestObjs");
	funcs.pFreeObj = (ExtFreeObjFuncPtr)GetProcAddress(hDLL, "SRL_FreeObjs");
	funcs.pUrlGetObj = (ExtUrlGetObjFuncPtr)GetProcAddress(hDLL,
		"SRL_URLRequestObjs");

	PExtCreateSessFn fpSRLCreateSession = (PExtCreateSessFn)
		GetProcAddress(hDLL,"SRL_CreateSession");
	*ppFreeCertsFn = (PExtFreeEncCertList)GetProcAddress(hDLL,
		"SRL_FreeEncCertList");
	*ppGetCertsFn = (PExtGetTrustedCerts)GetProcAddress(hDLL,
		"SRL_GetTrustedCerts");
#endif

	if ((funcs.pGetObj == NULL) || (funcs.pFreeObj == NULL) ||
		(funcs.pUrlGetObj == NULL) || (fpSRLCreateSession == NULL) ||
		(*ppFreeCertsFn == NULL) || (*ppGetCertsFn == NULL))
	{
		FreeLibrary(hDLL);
		throw CML_ERR(CM_SRL_INITIALIZATION_FAILED);
	}

	// Initialize SRL session handle
	sessionID = 0;

	// Create an SRL session
	short srlErr = fpSRLCreateSession(&sessionID, NULL);
	if (srlErr != SRL_SUCCESS)
	{
      *ppFreeCertsFn = NULL;
		FreeLibrary(hDLL);
		throw CML_ERR(srlErr);
	}

	return hDLL;
} // end of link2SRL()


/////////////////
// unlinkSRL() //
/////////////////
void unlinkSRL(HINSTANCE hDLL, ulong* pSessionID)
{
	// Destroy the SRL session
	if (pSessionID != NULL)
	{
		PExtDestroySessFn fpSRL_DestroySession;
#ifdef HPUX32
		shl_findsym(&hDLL, "SRL_DestorySession", TYPE_PROCEDURE,
			(void*) &fpSRL_DestroySession);
#else
		fpSRL_DestroySession = (PExtDestroySessFn)
			GetProcAddress(hDLL, "SRL_DestroySession");
#endif
		if (fpSRL_DestroySession != NULL)
			fpSRL_DestroySession(pSessionID);
	}

	// Release the SRL library
	FreeLibrary(hDLL);
}
