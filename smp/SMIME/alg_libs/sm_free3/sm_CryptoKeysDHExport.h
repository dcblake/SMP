/* @(#) sm_CryptoKeysDHExport.h 1.3 11/29/99 16:44:45 */
//  This class definition handles the DH CTIL supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#include "sm_free3.h"
#include "sm_free3_asn.h"
#include "sm_CryptoKeysDH.h"
_BEGIN_CERT_NAMESPACE


class CSM_CryptoKeysDHExport : public CSM_CryptoKeysFree3Base,
                               public CSM_CryptoKeysDH 
                                
{
private:
      CSM_Free3 m_Free3CTI;     
      CryptoPP::DH *m_pDH;

public:
   // constructors
   CSM_CryptoKeysDHExport(CSM_CertificateChoice *pCert, 
      char *lpszPassword=NULL) 
   { m_pDH=NULL; SetCert(pCert,lpszPassword);} 

   CSM_CryptoKeysDHExport() { m_pDH=NULL; m_AlgOid = SNACC::dh_public_number; } 
      
   // Destructor
   ~CSM_CryptoKeysDHExport(){ if (m_pDH) delete m_pDH;}; 

   SM_RET_VAL GenerateKeys(CSM_Buffer *bufferX, CSM_Buffer *bufferY, 
      CSM_Buffer *&pP, CSM_Buffer *&pG, CSM_Buffer *&pQ, 
      int keybits=0, bool bParams=false, CSM_Buffer *params=NULL);

   // Get Public Key
   CSM_Buffer* GetPublicKey();
    
   // Get Private Key Unwrapped
   CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
      CSM_Buffer *pEncryptedPrivateKeyInfo)
   { 
      return CSM_CryptoKeysFree3Base::GetPrivateKeyUnwrapped(pszPassword, 
      pEncryptedPrivateKeyInfo); 
   }

   // Get Private Key Wrapped
   CSM_Buffer* GetPrivateKeyWrapped()
   {
      return CSM_CryptoKeysFree3Base::GetPrivateKeyWrapped();
   }

   CSM_Buffer* WrapPrivateKey(CSM_Buffer &bufX)
   {
      return CSM_CryptoKeysFree3Base::WrapPrivateKey(bufX);
   }

   CSM_Buffer* WrapPrivateKey(CSM_Buffer &bufferX, char *pszPassword, 
      CSM_Alg *poidXAlgId)
   {
      return CSM_CryptoKeysFree3Base::WrapPrivateKey(bufferX, pszPassword, 
      poidXAlgId);
   }

   SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(CSM_Buffer *AnyParams,CSM_Buffer *PubKey)
   {
      return CSM_CryptoKeysFree3Base::LoadSNACCPublicKeyInfo(AnyParams,PubKey);
   }

   void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword)
   {m_AlgOid = SNACC::dh_public_number; if (lpszPassword) m_Free3CTI.SetPassword(
    lpszPassword);  
#ifdef WIN32
    pCert; /*AVOIDS warning.*/
#endif
   }
   
   void SetPassword(char *lpszPassword)
   {if (lpszPassword) m_Free3CTI.SetPassword(lpszPassword);}

   CSM_Buffer* WrapPrivateKeyInfo(CSM_Buffer &bufferX, char *pszPassword, CSM_Alg *pXAlgId)
   {
	  return CSM_CryptoKeysFree3Base::WrapPrivateKeyInfo(bufferX, pszPassword, pXAlgId);
   }

   CSM_Buffer *WrapPkcs12(
       char *pBufX, char *pBufY, char *pCertFile,             // File Names
       char *pszPassword,
       CSM_Buffer &p, CSM_Buffer &g, CSM_Buffer &q,
       char *pencPrvKeyFilename=NULL);  //OPTIONAL input.
};       

_END_CERT_NAMESPACE


// EOF sm_CryptoKeysDHExport.h
