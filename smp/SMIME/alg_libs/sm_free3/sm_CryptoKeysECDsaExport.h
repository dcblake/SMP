/* @(#) sm_CryptoKeysECDsaExport.h  */
//  This class definition handles the ECDSA CTIL supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 
//
//  Certain support commands were added to the Build Arguments of the sm_free3
//  CTIL in support of Eliptic Curve DSA algorithms.  If you input "LIST_OIDS"
//  as part of the argument, an exception will be thrown that lists all of the
//  supported OIDs and algorithms allowed.  "HELP" is also available for this
//  feature.  This was done due to the large 
//  number of built-in algorithms, as well as the complex nature of the
//  EC DSA input (2 types, several arguments each).

#ifndef __sm_CryptoKeysECDsaExportDef
#define __sm_CryptoKeysECDsaExportDef

#include "sm_free3.h"
#include "sm_free3_asn.h"
#include "sm_CryptoKeysECDsa.h"
#include "sm_CryptoKeysDsaExport.h"
_BEGIN_CERT_NAMESPACE

#ifdef CRYPTOPP_5_0


//
//
class CSM_CryptoKeysECDsaExport : public CSM_CryptoKeysECDsa,
                                  virtual public CSM_CryptoKeysFree3Base
{
public:
   // constructors
   CSM_CryptoKeysECDsaExport(CSM_CertificateChoice *pCert, char *lpszPassword=NULL) 
   {  SetCert(pCert,lpszPassword);  }

   CSM_CryptoKeysECDsaExport() {m_AlgOid = SNACC::id_ecPublicKey; } 
      
   // Destructor
   ~CSM_CryptoKeysECDsaExport(){}; 

   CSM_Buffer *DetermineECParams(
                CSM_ECParams &ECParams,      // IN, parameters to cnovert.
                bool &bECPFlag);             // OUT, indicates ECP or EC2N
   SM_RET_VAL GenerateKeys(
      CTIL::CSM_Buffer &bufferX, CTIL::CSM_Buffer &bufferY,   // OUT
      CERT::CSM_ECParams &ECParams,                           // IN
      CTIL::CSM_Buffer *params=NULL);                         // OUT, OPTIONAL
   SM_RET_VAL GenerateKeys(CTIL::CSM_Buffer *bufferX, CTIL::CSM_Buffer *bufferY, 
      CTIL::CSM_Buffer *P=NULL, CTIL::CSM_Buffer *G=NULL, CTIL::CSM_Buffer *Q=NULL, 
      int keybits=0, bool bParams=false, CTIL::CSM_Buffer *params=NULL) 
   { return -1; }


   void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword)
   { m_AlgOid = SNACC::id_ecPublicKey;
     if (lpszPassword) m_FreeCTI.SetPassword(lpszPassword);
#ifdef WIN32
      pCert; /*AVOIDS warning.*/
#endif
   }

   CTIL::CSM_Buffer* GetPublicKey() { return NULL; }
  
   CTIL::CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
      CTIL::CSM_Buffer *pEncryptedPrivateKeyInfo)
   { 
      return CSM_CryptoKeysFree3Base::GetPrivateKeyUnwrapped(pszPassword, 
      pEncryptedPrivateKeyInfo); 
   }

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

   void SetPassword(char *lpszPassword)
   {if (lpszPassword) m_FreeCTI.SetPassword(lpszPassword);}

   CTIL::CSM_Buffer* WrapPrivateKeyInfo(CTIL::CSM_Buffer &bufferX, char *pszPassword, CSM_Alg *pXAlgId)
   {
	  return CSM_CryptoKeysFree3Base::WrapPrivateKeyInfo(bufferX, pszPassword, pXAlgId);
   }
   CTIL::CSM_Buffer *WrapPkcs12(
       char *pBufX, char *pBufY, char *pCertFile,             // File Names
       char *pszPassword, 
       CERT::CSM_ECParams &ECParams,
       char *pencPrvKeyFilename=NULL);  //OPTIONAL input.

   
   //####################################
   void ECDSA_ListOids(std::ostream &os);
   const char *ECDSA_ListOids_Name(OID &oid);
   OID *ECDSA_StringToOid(const char *pszOidString,   // IN
                          bool &bECPFlag);            // OUT



}; 

//
//
class CSM_CryptoKeysECDHExport :  public CSM_CryptoKeysECDsaExport, 
                                  public CSM_CryptoKeysECDH,
                                  virtual public CSM_CryptoKeysFree3Base
{
public:
   // constructors
   CSM_CryptoKeysECDHExport() {m_AlgOid = SNACC::id_ecPublicKey; } 
      
   // Destructor
   ~CSM_CryptoKeysECDHExport(){}; 

   SM_RET_VAL GenerateKeys(
      CTIL::CSM_Buffer &bufferX, CTIL::CSM_Buffer &bufferY,   // OUT
      CERT::CSM_ECParams &ECParams,                           // IN
      CTIL::CSM_Buffer *params=NULL);                         // OUT, OPTIONAL


   // TAKE REMAINING VIRTUAL Methods from CSM_CryptoKeysECDsaExport

   CTIL::CSM_Buffer* GetPrivateKeyWrapped()
   {
      return CSM_CryptoKeysFree3Base::GetPrivateKeyWrapped();
   }
   CTIL::CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
      CTIL::CSM_Buffer *pEncryptedPrivateKeyInfo)
   { 
      return CSM_CryptoKeysFree3Base::GetPrivateKeyUnwrapped(pszPassword, 
      pEncryptedPrivateKeyInfo); 
   }
   CTIL::CSM_Buffer* WrapPrivateKey(CTIL::CSM_Buffer &bufferX, char *pszPassword, 
      CSM_Alg *poidXAlgId)
   {
      return CSM_CryptoKeysFree3Base::WrapPrivateKey(bufferX, pszPassword, 
      poidXAlgId);
   }
   CTIL::CSM_Buffer* WrapPrivateKey(CTIL::CSM_Buffer &bufX)
   {
      return CSM_CryptoKeysFree3Base::WrapPrivateKey(bufX);
   }
   SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(CTIL::CSM_Buffer *AnyParams,CTIL::CSM_Buffer *PubKey)
   {
      return CSM_CryptoKeysFree3Base::LoadSNACCPublicKeyInfo(AnyParams, PubKey);
   }
   void SetCert(CSM_CertificateChoice *pCert,char *lpszPassword)
   { m_AlgOid = SNACC::id_ecPublicKey;
     if (lpszPassword) m_FreeCTI.SetPassword(lpszPassword);
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
       CERT::CSM_ECParams &ECParams,
       char *pencPrvKeyFilename=NULL)  
   {  return CSM_CryptoKeysECDsaExport::WrapPkcs12(pBufX, pBufY, pCertFile, 
                                pszPassword, ECParams, pencPrvKeyFilename); };
   CTIL::CSM_Buffer* GetPublicKey() { return NULL; }

};

#endif // CRYPTOPP_5_0

      
_END_CERT_NAMESPACE

#endif //__sm_CryptoKeysDsaExportDef

// EOF sm_CryptoKeysDsaExport.h
