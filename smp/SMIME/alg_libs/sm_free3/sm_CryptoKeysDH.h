/* @(#) sm_CryptoKeysDH.h 1.4 11/29/99 16:52:18 */
//  This class definition handles the DSA CTIL supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#include "sm_CryptoKeys.h"

#ifndef SM_FREE3DLL_API
#ifdef WIN32
#ifdef SM_FREE3DLL_EXPORTS
#define SM_FREE3DLL_API __declspec(dllexport)
#else
#define SM_FREE3DLL_API __declspec(dllimport)
#endif
#else
#define SM_FREE3DLL_API
#endif
#endif
_BEGIN_CERT_NAMESPACE

class CSM_CryptoKeysDH 
{

public:
   // constructors
   CSM_CryptoKeysDH(CSM_CertificateChoice *pCert, 
      char *lpszPassword=NULL){   
#ifdef WIN32
       pCert;lpszPassword; /*AVOIDS warning*/
#endif
   }
   CSM_CryptoKeysDH(){};
      
   // Destructor
   virtual ~CSM_CryptoKeysDH(){}; 

   virtual SM_RET_VAL GenerateKeys(CSM_Buffer *bufferX, CSM_Buffer *bufferY, 
      CSM_Buffer *&pP, CSM_Buffer *&pG, CSM_Buffer *&pQ, 
      int keybits=0, bool bParams=false, CSM_Buffer *params=NULL) = 0;

   // Get Public Key
   virtual CSM_Buffer* GetPublicKey() = 0;        

   // Get Private Key Unwrapped
   virtual CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
         CSM_Buffer *pEncryptedPrivateKeyInfo) = 0;        

   // Get Private Key Wrapped
   virtual CSM_Buffer* GetPrivateKeyWrapped() = 0;

   virtual CSM_Buffer* WrapPrivateKey(CSM_Buffer &bufX) = 0;

   virtual CSM_Buffer* WrapPrivateKey(CSM_Buffer &bufferX, char *pszPassword,CSM_Alg *pXAlgId) = 0;

   virtual SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(CSM_Buffer *AnyParams,CSM_Buffer *PubKey) = 0;

   virtual void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword) = 0;

   virtual void SetPassword(char *lpszPassword) = 0;

   virtual CSM_Buffer* WrapPrivateKeyInfo(CSM_Buffer &bufferX,
      char *pszPassword, CSM_Alg *pXAlgId) = 0;

   virtual CSM_Buffer *WrapPkcs12(
       char *pBufX, char *pBufY, char *pCertFile,             // File Names
       char *pszPassword,
       CSM_Buffer &p, CSM_Buffer &g, CSM_Buffer &q,
       char *pencPrvKeyFilename=NULL)=0;  //OPTIONAL input.


}; 
      
extern "C"{
SM_FREE3DLL_API CSM_CryptoKeysDH * SM_BuildCryptoKeysDH(CSM_CertificateChoice *, char *);
}   // END extern "C"

_END_CERT_NAMESPACE

// EOF sm_CryptoKeysDH.h
