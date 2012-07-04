/* @(#) sm_CryptoKeysRsa.h 1.4 12/7/99 10:06:01 */
//  sm_CryptoKeysRsa.h
//
//  This class definition handles the RSA CTIL supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#include "sm_CryptoKeys.h"

#ifndef SM_RSADLL_API
#ifdef WIN32
#ifdef SM_RSADLL_EXPORTS
#define SM_RSADLL_API __declspec(dllexport)
#else
#define SM_RSADLL_API __declspec(dllimport)
#endif
#else
#define SM_RSADLL_API
#endif
#endif
using CTIL::CSM_Buffer;
_BEGIN_CERT_NAMESPACE


class SM_RSADLL_API CSM_CryptoKeysRsa 
{

public:
   // constructors
   CSM_CryptoKeysRsa(CSM_CertificateChoice *pCert, 
    char *lpszPassword=NULL){lpszPassword;pCert;/*AVOIDS warning.*/};
   CSM_CryptoKeysRsa(){};
      
   // Destructor
   virtual ~CSM_CryptoKeysRsa(){}; 

   virtual SM_RET_VAL GenerateKeys(CSM_Buffer *bufferX, CSM_Buffer *bufferY, 
      CSM_Buffer *P=NULL, CSM_Buffer *G=NULL, CSM_Buffer *Q=NULL, 
      int keybits=0, bool bParams=false, CSM_Buffer *params=NULL) = 0;

   // Get Public Key
   virtual CSM_Buffer* GetPublicKey() = 0;        
   // Get Private Key Unwrapped
   virtual CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
         CSM_Buffer *pEncryptedPrivateKeyInfo) = 0;        
   // Get Private Key Wrapped
   virtual CSM_Buffer* GetPrivateKeyWrapped() = 0;
   virtual CSM_Buffer* WrapPrivateKey(CSM_Buffer &bufX) = 0;
   virtual CSM_Buffer* WrapPrivateKey(CSM_Buffer &bufferX, char *pszPassword)=0;
   virtual SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(
      CSM_Buffer *AnyParams, CSM_Buffer *PubKey) = 0;
   virtual void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword) = 0;
   virtual void SetPassword(char *lpszPassword) = 0;
};       

extern "C"{
SM_RSADLL_API CSM_CryptoKeysRsa * SM_BuildCryptoKeysRSA(CSM_CertificateChoice *,
                                                        char *);
}   // END extern "C"

_END_CERT_NAMESPACE

// EOF sm_CryptoKeysRsa.h
