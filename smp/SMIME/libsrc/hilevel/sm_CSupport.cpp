
//
//  sm_CSupport.cpp
//  These "C" API support functions provide the login and attribute functionality
//  for developers using the SFL "C" API.
//

/*extern "C" {
#include "sm_apic.h"
}*/
#include "sm_api.h"
#include "sm_AppLogin.h"

    using namespace SFL;
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;

extern "C" {

//
//
SM_RET_VAL SM_CreateCSMIME(
  SM_OBJECT **ppCSMIME,   /* OUT,Returned pointer to struct for crypto calls. */
  char *lpszDLLFile,      /* IN, DLL file load for Win32.*/
  char *lpszArgList)      /* IN, Argument list for DLL Load.*/
  //Bytes_struct *pCert,      /* IN, used to specify the algs for login.*/
  //Bytes_struct *pPrivateKey,  /* IN, OPTIONAL private key for
  //                             sign/encrypt/decrypt. 
  //                      (library can perform verification without key). */
  //char *lpszPassword)      /* IN, OPTIONAL, password to access "pPrivateKey" 
  //                          in SFL stored format (flavor of PKCS 8).  */
{
    SM_RET_VAL status=0;
    CSM_Buffer CertBuf;
    CSM_AppLogin *pAppLogin=NULL;
    char *lpszError=NULL;


    SME_SETUP("SM_CreateCSMIME");
    //if (pCert)
    {
        //CertBuf.Set((char *)pCert->data, pCert->num);
        //if (pPrivateKey)
        //{
        //  pPrivateKeyBuf = new CSM_Buffer((char *)pPrivateKey->data, pPrivateKey->num);
        //}
        //SME(pAppLogin=new CSM_AppLogin(CertBuf, pPrivateKeyBuf, lpszPassword));
        SME(pAppLogin=new CSM_AppLogin(lpszDLLFile, lpszArgList));
        if (ppCSMIME)
            *ppCSMIME = (SM_OBJECT *)pAppLogin;
    }
    //else
    //    status = -1;
    
    SME_FINISH
    SME_CATCH_SETUP
        if (pAppLogin)
            delete pAppLogin;
      /* cleanup code */
    SME_CATCH_FINISH_C2(lpszError);
    if (lpszError)
       free(lpszError);

    return(status);
}

//
//
SM_RET_VAL SM_AddLogin(
  SM_OBJECT **ppCSMIME,   /* OUT,Returned pointer to struct for crypto calls. */
  char *lpszDLLFile,      /* IN, DLL file load for Win32.*/
  char *lpszArgList)      /* IN, Argument list for DLL Load.*/
  //Bytes_struct *pCert,      /* IN, used to specify the algs for login.*/
  //Bytes_struct *pPrivateKey,  /* IN, OPTIONAL private key for
  //                             sign/encrypt/decrypt. 
  //                      (library can perform verification without key). */
  //char *lpszPassword)      /* IN, OPTIONAL, password to access "pPrivateKey" 
  //                          in SFL stored format (flavor of PKCS 8).  */
{
    SM_RET_VAL status=0;
    CSM_Buffer CertBuf;
    CSM_AppLogin *pAppLogin=NULL;
    char *lpszError=NULL;


    SME_SETUP("SM_AddLogin");
    if (/*pCert &&*/ ppCSMIME)
    {
        pAppLogin = (CSM_AppLogin *)*ppCSMIME;
        //CertBuf.Set((char *)pCert->data, pCert->num);
        //if (pPrivateKey)
        //{
        //  pPrivateKeyBuf = new CSM_Buffer((char *)pPrivateKey->data, pPrivateKey->num);
        //}
#ifdef WIN32
        SME(pAppLogin->AddLogin(lpszDLLFile, lpszArgList));
#endif
    }
    else
        status = -1;
    
    SME_FINISH
    SME_CATCH_SETUP
        if (pAppLogin)
            delete pAppLogin;
      /* cleanup code */
    SME_CATCH_FINISH_C2(lpszError);

    return(status);
}


}           // END extern "C"

// EOF sm_CSupport.cpp
