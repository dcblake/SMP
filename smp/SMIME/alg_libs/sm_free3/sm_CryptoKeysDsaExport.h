/* @(#) sm_CryptoKeysDsaExport.h 1.4 01/24/00 06:51:29 */
//  This class definition handles the DSA CTIL supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#ifndef __sm_CryptoKeysDsaExportDef
#define __sm_CryptoKeysDsaExportDef

#include "sm_free3.h"
#include "sm_free3_asn.h"
#include "sm_CryptoKeysDsa.h"
_BEGIN_CERT_NAMESPACE


class CSM_SFLDSAPrivateKey: public DSAPrivateKey
{   // THIS CLASS was created for the sole purpose of accessing the "protected"
    //  private key.  This trick allows direct access by this logic without
    //  modification to the cpypto ++ 3.0 library.
public:
    CSM_SFLDSAPrivateKey(RandomNumberGenerator &rng, unsigned int keybits):
      DSAPrivateKey(rng, keybits) 
      {};
#ifndef CRYPTOPP_5_0
    CSM_SFLDSAPrivateKey(RandomNumberGenerator &rng, const Integer &p, 
        const Integer &q, const Integer &g): DSAPrivateKey(rng, p, q, g),GDSADigestSigner(rng, p, q, g) 
    {};
    CSM_SFLDSAPrivateKey(const Integer &p, const Integer &q, const Integer &g, 
       const Integer &y, const Integer &x): DSAPrivateKey(p, q, g, y, x) {};
    Integer *Access_x() { return &m_x; }
    Integer *Access_y() { return &m_y; }
    Integer *Access_p() { return &m_p; }
    Integer *Access_q() { return &m_q; }
    Integer *Access_g() { return &m_g; }

#else  // CRYPTOPP_5_0
private:
    Integer m_CSMx;
    Integer m_CSMy;
    Integer m_CSMp;
    Integer m_CSMq;
    Integer m_CSMg;
public:
    CSM_SFLDSAPrivateKey(RandomNumberGenerator &rng, const Integer &p, 
        const Integer &q, const Integer &g) 
    {  AccessKey().Initialize(rng, p, q, g); 
    }
    CSM_SFLDSAPrivateKey(const Integer &p, const Integer &q, const Integer &g, 
       const Integer &y, const Integer &x)
    { 
        AccessKey().Initialize(p, q, g, x);
      //AccessPrivateKey().Load();///*RWC;NOT USED;AccessAbstractGroupParameters()*/.Initialize(p, q, g, x);
      //AccessPublicKey().Initialize(p, q, g, y);
    }
    SNACC::FREE_DSAParameters *GetParams();
    Integer *Access_x();
    Integer *Access_y();
    Integer *Access_p();
    Integer *Access_q();
    Integer *Access_g();
#endif // CRYPTOPP_5_0

};


class CSM_CryptoKeysFree3Base : public CSM_CryptoKeysBase
{
protected:
   CSM_Free3 m_FreeCTI;

public:

   CSM_CryptoKeysFree3Base(){};
   CSM_CryptoKeysFree3Base(CSM_CertificateChoice *pCert):
       CSM_CryptoKeysBase(pCert){};
   // Get Private Key Unwrapped
   CTIL::CSM_Buffer *GetPrivateKeyUnwrapped(char *pszPassword,
      CTIL::CSM_Buffer *pEncryptedPrivateKeyInfo);

   // Get Private Key Wrapped
   CTIL::CSM_Buffer* GetPrivateKeyWrapped();

   CTIL::CSM_Buffer* WrapPrivateKey(CTIL::CSM_Buffer &bufX);

   CTIL::CSM_Buffer* WrapPrivateKey(CTIL::CSM_Buffer &bufferX, char *pszPassword,
      CSM_Alg *poidXAlgId);

   SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(CTIL::CSM_Buffer *AnyParams,
        CTIL::CSM_Buffer *PubKey);

   CTIL::CSM_Buffer* WrapPrivateKeyInfo(CTIL::CSM_Buffer &bufferX, 
	   char *pszPassword, CSM_Alg *pXAlgId);
};

class CSM_CryptoKeysDsaExport : public CSM_CryptoKeysDsa,
                                virtual public CSM_CryptoKeysFree3Base
{
public:
   // constructors
   CSM_CryptoKeysDsaExport(CSM_CertificateChoice *pCert, 
      char *lpszPassword=NULL) 
   {SetCert(pCert,lpszPassword);} 

   CSM_CryptoKeysDsaExport() {m_AlgOid = SNACC::id_dsa; } 
      
   // Destructor
   ~CSM_CryptoKeysDsaExport(){}; 

   SM_RET_VAL GenerateKeys(CTIL::CSM_Buffer *bufferX, CTIL::CSM_Buffer *bufferY, 
      CTIL::CSM_Buffer *P=NULL, CTIL::CSM_Buffer *G=NULL, CTIL::CSM_Buffer *Q=NULL, 
      int keybits=0, bool bParams=false, CTIL::CSM_Buffer *params=NULL);

   // Get Public Key
   CTIL::CSM_Buffer* GetPublicKey();
  
   // Get Private Key Unwrapped
   CTIL::CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
      CTIL::CSM_Buffer *pEncryptedPrivateKeyInfo)
   { 
      return CSM_CryptoKeysFree3Base::GetPrivateKeyUnwrapped(pszPassword, 
      pEncryptedPrivateKeyInfo); 
   }

   // Get Private Key Wrapped
   CTIL::CSM_Buffer* GetPrivateKeyWrapped()
   {
      return CSM_CryptoKeysFree3Base::GetPrivateKeyWrapped();
   }

   CTIL::CSM_Buffer* WrapPrivateKey(CTIL::CSM_Buffer &bufX)
   {
      return CSM_CryptoKeysFree3Base::WrapPrivateKey(bufX);
   }

   CTIL::CSM_Buffer* WrapPrivateKey(CTIL::CSM_Buffer &bufferX, char *pszPassword, 
      CSM_Alg *poidXAlgId)
   {
      return CSM_CryptoKeysFree3Base::WrapPrivateKey(bufferX, pszPassword, 
      poidXAlgId);
   }
   
   SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(CTIL::CSM_Buffer *AnyParams,CTIL::CSM_Buffer *PubKey)
   {
      return CSM_CryptoKeysFree3Base::LoadSNACCPublicKeyInfo(AnyParams, PubKey);
   }

   void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword)
   {m_AlgOid = SNACC::id_dsa; if (lpszPassword) m_FreeCTI.SetPassword(lpszPassword);
#ifdef WIN32
      pCert; /*AVOIDS warning.*/
#endif
   }
   
   void SetPassword(char *lpszPassword)
   {if (lpszPassword) m_FreeCTI.SetPassword(lpszPassword);}

   CTIL::CSM_Buffer* WrapPrivateKeyInfo(CTIL::CSM_Buffer &bufferX, char *pszPassword, CSM_Alg *pXAlgId)
   {
	  return CSM_CryptoKeysFree3Base::WrapPrivateKeyInfo(bufferX, pszPassword, pXAlgId);
   }
   CTIL::CSM_Buffer *WrapPkcs12(
       char *pBufX, char *pBufY, char *pCertFile,             // File Names
       char *pszPassword, 
       CTIL::CSM_Buffer &p, CTIL::CSM_Buffer &q, CTIL::CSM_Buffer &g,
       char *pencPrvKeyFilename=NULL);  //OPTIONAL input.
   void ExtractDSAParams(CTIL::CSM_Buffer &Parameters, CTIL::CSM_Buffer *&pDSAP, 
       CTIL::CSM_Buffer *&pDSAQ, CTIL::CSM_Buffer *&pDSAG);


}; 
      
_END_CERT_NAMESPACE

#endif //__sm_CryptoKeysDsaExportDef

// EOF sm_CryptoKeysDsaExport.h
