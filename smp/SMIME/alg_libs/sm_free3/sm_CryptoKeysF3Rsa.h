/* @(#) sm_CryptoKeysF3Rsa.h 1.5 11/15/00 15:06:22 */
//  This class definition handles the Rsa CTIL supported by the SFL.
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

class CSM_CryptoKeysF3Rsa 
{

public:
   // constructors
   CSM_CryptoKeysF3Rsa(CSM_CertificateChoice *pCert, 
      char *lpszPassword=NULL){
#ifdef WIN32
       pCert;lpszPassword; /*AVOIDS warning.*/
#endif
   };
   CSM_CryptoKeysF3Rsa(){};
      
   // Destructor
   virtual ~CSM_CryptoKeysF3Rsa(){}; 

   virtual SM_RET_VAL GenerateRsaKeys(CSM_Buffer *bufferX, CSM_Buffer *bufferY)=0;

   // Get Public Key
   virtual CSM_Buffer* GetPublicKey() = 0;        

   // Get Private Key Unwrapped
   virtual CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
         CSM_Buffer *pEncryptedPrivateKeyInfo) = 0;        

   // Get Private Key Wrapped
   virtual CSM_Buffer *GetPrivateKeyWrapped() = 0;

   virtual CSM_Buffer *WrapPrivateKey(CSM_Buffer &bufX) = 0;

   virtual CSM_Buffer *WrapPrivateKey(CSM_Buffer &bufferX, char *pszPassword,CSM_Alg *pXAlgId) = 0;

   virtual SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(CSM_Buffer *AnyParams,CSM_Buffer *PubKey) = 0;

   virtual void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword) = 0;

   virtual void SetPassword(char *lpszPassword) = 0;

   virtual CSM_Buffer *WrapPrivateKeyInfo(CSM_Buffer &bufferX,
         char *pszPassword, CSM_Alg *pXAlgId) = 0;
   virtual CSM_Buffer *WrapPkcs12(
       char *pBufX, char *pCertFile,             // File Names
       char *pszPassword,
       char *pencPrvKeyFilename=NULL)=0;  //OPTIONAL input.
};


extern "C"{
SM_FREE3DLL_API CSM_CryptoKeysF3Rsa * SM_BuildCryptoKeysF3Rsa(
   CSM_CertificateChoice *, char *);
}   // END extern "C"

_END_CERT_NAMESPACE

// EOF sm_CryptoKeysF3Rsa.h
