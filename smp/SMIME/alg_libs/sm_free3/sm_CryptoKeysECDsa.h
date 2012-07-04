/* @(#) sm_CryptoKeysECDsa.h  */
//  This class definition handles the ECDSA CTIL supported by the SFL.

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

class CSM_CryptoKeysECDsa 
{

public:
   // constructors
   CSM_CryptoKeysECDsa(CSM_CertificateChoice *pCert, 
      char *lpszPassword=NULL){
#ifdef WIN32
       pCert;lpszPassword; /*AVOIDS warning.*/
#endif
   };
   CSM_CryptoKeysECDsa(){};
      
   // Destructor
   virtual ~CSM_CryptoKeysECDsa(){}; 

   virtual SM_RET_VAL GenerateKeys(
      CSM_Buffer &bufferX, CSM_Buffer &bufferY,   // OUT
      CERT::CSM_ECParams &ECParams,  // IN
      CSM_Buffer *params=NULL  // OUT, OPTIONAL
      ) = 0;

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
       char *pBufX, char *pBufY, char *pCertFile,             // File Names
       char *pszPassword,
      CERT::CSM_ECParams &ECParams,       // IN
       char *pencPrvKeyFilename=NULL)=0;  //OPTIONAL input.

};

//
//
class CSM_CryptoKeysECDH: public CSM_CryptoKeysECDsa 
{
public:
   CSM_CryptoKeysECDH(){};
   virtual SM_RET_VAL GenerateKeys(
      CSM_Buffer &bufferX, CSM_Buffer &bufferY,   // OUT
      CERT::CSM_ECParams &ECParams,  // IN
      CSM_Buffer *params=NULL  // OUT, OPTIONAL
      ) = 0;

};      // END class CSM_CryptoKeysECDH


extern "C"{
SM_FREE3DLL_API CSM_CryptoKeysECDsa * SM_BuildCryptoKeysECDsa(CSM_CertificateChoice *, char *);
SM_FREE3DLL_API CSM_CryptoKeysECDH * SM_BuildCryptoKeysECDH(char *);
}   // END extern "C"

_END_CERT_NAMESPACE

// EOF sm_CryptoKeysECDsa.h
