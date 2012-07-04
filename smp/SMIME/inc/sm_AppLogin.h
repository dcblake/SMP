/* @(#) sm_AppLogin.h 1.10 09/21/00 10:46:11 */
//
//  sm_AppLogin.h
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the login classes to be 
//  used by less demanding SFL client applications as well as the simplified
//  "C" API interfaces.
//  NOTE:::  SFL client applications wishing to use this logic to support
//     new CTIL crypto interfaces should inherit this class and add their
//     specific login details instead of modifying this source; this will
//     allow the SFL updates to be absorbed directly by your applications
//     as future releases are made.
//  The "C" API setup functions are also contained in this source file.

#ifndef _SM_APP_LOGIN_H
#define _SM_APP_LOGIN_H
#include "sm_apiCert.h"

#if defined (WIN32) || defined (SunOS) || defined (Linux)
#include "sm_DLLInterface.h"
#endif
#ifdef WIN32
#pragma warning( disable : 4251 )
#endif

_BEGIN_CERT_NAMESPACE 


class LIBCERTDLL_API CSM_AppLogin: public CSMIME
{
private:
   long m_lCounter;     // For unique IDs during this session.
public:
   CSM_AppLogin() { m_lCounter=100; };
   CSM_AppLogin(char *lpszDLLName, char *lpszStartupArgs);
   ~CSM_AppLogin();
};

#ifdef WIN32
#pragma warning( default : 4251 )
#endif

// RWC; TMP definition in "sm_AppLogin.cpp" to support logins.
void LIBCERTDLL_API GLOBALAddLoginFinish(
   CTIL::CSM_CtilMgr &Csmime,
   CTIL::CSM_TokenInterface *pTokenInterface, // IN, actual instance, setup to 
                                        //  specific CTIL.
   char *lpszID,        // IN,OUT id of specific login.
   CSM_MsgCertCrls *pCertBufs);  // IN, convenient decode of cert

void LIBCERTDLL_API GLOBALAddLoginFinish(
   CTIL::CSM_CtilMgr &Csmime,
   CTIL::CSM_TokenInterface *pTokenInterface, // IN, actual instance, setup to 
                                        //  specific CTIL.
   char *lpszID,        // IN,OUT id of specific login.
   CTIL::CSM_Buffer &CertBuf);  // IN, convenient decode of cert

_END_CERT_NAMESPACE 

#endif //_SM_APP_LOGIN_H
// EOF sm_AppLogin.h
