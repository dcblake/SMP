
//
//  sm_AppLogin.cpp
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

#include <string.h>
#include "sm_AppLogin.h"

_BEGIN_CERT_NAMESPACE 
using namespace SNACC;
//
//
CSM_AppLogin::CSM_AppLogin(char *lpszDLLName, char *lpszBuildupArgs)
{
    SME_SETUP("CSM_AppLogin::CSM_AppLogin(DLLName,StartupArgs");

#if defined (WIN32) || defined (SunOS) || defined (Linux) || defined (SCO_SV)
    AddLogin(lpszDLLName, lpszBuildupArgs);
#else
    SME_THROW(22, "CSM_AppLogin:  DYNAMIC LOAD OF SMTI Libraries NOT YET SUPORTED."
        , NULL);
#endif

    SME_FINISH
    catch (SNACC::SnaccException &e)  
    {
        throw CTIL::CTILException(e);
    }       // END catch (...)
}

//
//
CSM_AppLogin::~CSM_AppLogin()
{
}

using namespace CTIL;
//////////////////////////////////////////////////////////////////
void GLOBALAddLoginFinish(
   CSM_CtilMgr &Csmime,
   CSM_TokenInterface *pTokenInterface, // IN, actual instance, setup to 
                                        //  specific CTIL.
   char *lpszID,        // IN,OUT id of specific login.
   CSM_Buffer &CertBuf)  // IN, convenient decode of cert
{
      CSM_MsgCertCrls a;
      CSM_CertificateChoice *pb = NULL;
      if (CertBuf.Length() > 0)
      {
          pb = new CSM_CertificateChoice(CertBuf);
          a.AddCert(pb);
          delete pb;   // sib 9/27/02 AddCert no longer deletes pb
      }
      GLOBALAddLoginFinish(Csmime, pTokenInterface, lpszID, &a);
}

// Perform CTIL independent operations
void GLOBALAddLoginFinish(
   CSM_CtilMgr &Csmime,
   CSM_TokenInterface *pTokenInterface, // IN, actual instance, setup to 
                                        //  specific CTIL.
   char *lpszID,        // IN,OUT id of specific login.
   CSM_MsgCertCrls *pCertBufs)  // IN, convenient decode of cert
{
   CSM_CSInst *pNewInstance = NULL;
   CSM_CertificateChoice CertificateChoice;
   CSM_CertificateChoiceLst *pNewCertList;

   SME_SETUP("GLOBALAddLoginFinish");
   if (pCertBufs && pCertBufs->AccessCertificates() &&
       pCertBufs->AccessCertificates()->size() > 0)
       CertificateChoice.SetEncodedCert(*pCertBufs->AccessCertificates()->begin()
            ->AccessEncodedCert());

   pNewInstance = new CSM_CSInst;   // BUILD cert-based instance.
   pTokenInterface->SetCSInst(pNewInstance); // ALLOW access to the CSM_CSInst 
                                             //  beyond CSM_TokenInterface.
                                             //  (This feature is optional, but
                                             //  necessary for cert access).
   GLOBALAddLoginFinishCTIL(Csmime, pNewInstance, pTokenInterface, lpszID);

          if (pCertBufs && pCertBufs->AccessCertificates() &&
              pCertBufs->AccessCertificates()->size() > 0)
          {
            pNewCertList = new CSM_CertificateChoiceLst(
                *pCertBufs->AccessCertificates());
            if (pNewCertList == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            //pNewCertList->AppendL(     // MUST NOT DESTROY MEMORY.
            //   new CSM_CertificateChoice(CertificateChoice));
            pNewInstance->UpdateCertificates(pNewCertList);
          }
          // store issuer and serial number
          if (pCertBufs && pCertBufs->AccessCertificates() &&
              pCertBufs->AccessCertificates()->size() > 0)
          {
              CSM_IssuerAndSerialNumber *pIssSN = 
                 CertificateChoice.GetIssuerAndSerialNumber();
              pNewInstance->SetIssuerAndSerialNumber(pIssSN);
              delete pIssSN;
          }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

}



_END_CERT_NAMESPACE 

// EOF sm_AppLogin.cpp
