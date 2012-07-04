/* @(#) sm_CryptoKeysF3RsaExport.h 1.4 01/24/00 06:51:29 */
//  This class definition handles the Rsa CTIL supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#include "sm_free3.h"
#include "sm_free3_asn.h"
#include "sm_CryptoKeysDsaExport.h"
#include "sm_CryptoKeysF3Rsa.h"
_BEGIN_CERT_NAMESPACE

class CSM_CryptoKeysF3RsaExport : public CSM_CryptoKeysF3Rsa,
                                public CSM_CryptoKeysFree3Base
{
public:
   // constructors
   CSM_CryptoKeysF3RsaExport(CSM_CertificateChoice *pCert, 
      char *lpszPassword=NULL) 
   {SetCert(pCert,lpszPassword);} 

   CSM_CryptoKeysF3RsaExport() {m_AlgOid = SNACC::rsaEncryption; } 
      
   // Destructor
   ~CSM_CryptoKeysF3RsaExport(){}; 

   SM_RET_VAL GenerateKeys(CSM_Buffer *bufferX, CSM_Buffer *bufferY, 
      CSM_Buffer *P=NULL, CSM_Buffer *G=NULL, CSM_Buffer *Q=NULL, 
      int keybits=0, bool bParams=false, CSM_Buffer *params=NULL)
   {
       return GenerateRsaKeys(bufferX, bufferY);
   }

   SM_RET_VAL GenerateRsaKeys(CSM_Buffer *bufferX, CSM_Buffer *bufferY);

   // Get Public Key
   CSM_Buffer* GetPublicKey();
  
   // Get Private Key Unwrapped
   CSM_Buffer *GetPrivateKeyUnwrapped(char *pszPassword, 
      CSM_Buffer *pEncryptedPrivateKeyInfo)
   { 
      return CSM_CryptoKeysFree3Base::GetPrivateKeyUnwrapped(pszPassword, 
      pEncryptedPrivateKeyInfo); 
   }

   // Get Private Key Wrapped
   CSM_Buffer *GetPrivateKeyWrapped()
   {
      return CSM_CryptoKeysFree3Base::GetPrivateKeyWrapped();
   }

   CSM_Buffer *WrapPrivateKey(CSM_Buffer &bufX)
   {
      return CSM_CryptoKeysFree3Base::WrapPrivateKey(bufX);
   }

   CSM_Buffer *WrapPrivateKey(CSM_Buffer &bufferX, char *pszPassword, 
      CSM_Alg *poidXAlgId)
   {
       //TBD; extra processing for X_F3 file processing.
      return CSM_CryptoKeysFree3Base::WrapPrivateKey(bufferX, pszPassword, 
      poidXAlgId);
   }
   
   SNACC::SubjectPublicKeyInfo *LoadSNACCPublicKeyInfo(CSM_Buffer *AnyParams,CSM_Buffer *PubKey)
   {
      return CSM_CryptoKeysFree3Base::LoadSNACCPublicKeyInfo(AnyParams, PubKey);
   }

   void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword)
   {m_AlgOid = SNACC::rsaEncryption; if (lpszPassword) m_FreeCTI.SetPassword(lpszPassword);
#ifdef WIN32
      pCert; /*AVOIDS warning.*/
#endif
   }
   
   void SetPassword(char *lpszPassword)
   {if (lpszPassword) m_FreeCTI.SetPassword(lpszPassword);}

   CSM_Buffer* WrapPrivateKeyInfo(CSM_Buffer &bufferX, char *pszPassword, CSM_Alg *pXAlgId)
   {
	  return CSM_CryptoKeysFree3Base::WrapPrivateKeyInfo(bufferX, pszPassword, pXAlgId);
   }
   CSM_Buffer *WrapPkcs12(
       char *pBufX, char *pCertFile,             // File Names
       char *pszPassword, 
       char *pencPrvKeyFilename=NULL);  //OPTIONAL input.

}; 
      
_END_CERT_NAMESPACE

// EOF sm_CryptoKeysF3RsaExport.h
