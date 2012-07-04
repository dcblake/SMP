/* @(#) sm_CryptoKeysRsaExport.h 1.5 01/24/00 06:53:19 */
//  sm_CryptoKeysRsaExport.h
//
//  This class definition handles the RSA CTIL supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#include "sm_rsa.h"
#include "sm_rsa_asn.h"
#include "sm_CryptoKeysRsa.h"
_BEGIN_CERT_NAMESPACE


class SM_RSADLL_API CSM_CryptoKeysRsaExport : public CSM_CryptoKeysRsa,
                                public CSM_CryptoKeysBase
{
private:
      CSM_Rsa m_RsaCTI;     

public:
   // constructors
   CSM_CryptoKeysRsaExport(CSM_CertificateChoice *pCert, 
      char *lpszPassword=NULL)
   {SetCert(pCert,lpszPassword);} 

   CSM_CryptoKeysRsaExport() {m_AlgOid = SNACC::rsaEncryption; } 
      
   // Destructor
   ~CSM_CryptoKeysRsaExport(){}; 

   SM_RET_VAL GenerateKeys(CSM_Buffer *bufferX, CSM_Buffer *bufferY, 
      CSM_Buffer *P=NULL, CSM_Buffer *G=NULL, CSM_Buffer *Q=NULL, 
      int keybits=0, bool bParams=false, CSM_Buffer *params=NULL);

   // Get Public Key
   CSM_Buffer* GetPublicKey();        

   // Get Private Key Unwrapped
   CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
         CSM_Buffer *pEncryptedPrivateKeyInfo);        

   // Get Private Key Wrapped
   CSM_Buffer* GetPrivateKeyWrapped();

   CSM_Buffer* WrapPrivateKey(CSM_Buffer &bufX);

   CSM_Buffer* WrapPrivateKey(CSM_Buffer &bufferX, char *pszPassword);
   SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(CSM_Buffer *AnyParams,
         CSM_Buffer *PubKey);
   
   void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword)
   {m_AlgOid = SNACC::rsa; if (lpszPassword) m_RsaCTI.SetPassword(lpszPassword);
    pCert;/*AVOIDS warning.*/}
   
   void SetPassword(char *lpszPassword)
   {if (lpszPassword) m_RsaCTI.SetPassword(lpszPassword);}
};       

_END_CERT_NAMESPACE


// EOF sm_CryptoKeysRsaExport.h
