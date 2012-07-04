/* @(#) sm_CryptoKeys.h 1.6 06/27/00 12:38:43 */
//  sm_CryptoKeys.h
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 
#ifndef SM_CRYPTOKEYS
#define SM_CRYPTOKEYS 

#include "sm_apiCert.h"
#include "sm_VDASupport_asn.h"

#undef SM_FREE3DLL_API
#define SM_FREE3DLL_API

_BEGIN_CERT_NAMESPACE

class CSM_CryptoKeysBase
{
protected:
   CSM_CertificateChoice *m_pCert;  //need to initialize

public:
    SNACC::AsnOid   m_AlgOid;  // indicates RSA or Crypto++
   
   // constructor
   CSM_CryptoKeysBase(CSM_CertificateChoice *pCert){m_pCert = pCert;} 
   CSM_CryptoKeysBase(){ }; 
      
   // Destructor
   virtual ~CSM_CryptoKeysBase(){ }; 

   // Create crypto object
   static CSM_CryptoKeysBase *CreateCryptoObject(SNACC::AsnOid &AlgOid,
      CSM_CertificateChoice *pCert=NULL, char *lpszPassword=NULL);
   
   // Generate Keys 
   virtual SM_RET_VAL GenerateKeys(CTIL::CSM_Buffer *bufferX, CTIL::CSM_Buffer *bufferY, 
      CTIL::CSM_Buffer *P=NULL, CTIL::CSM_Buffer *G=NULL, CTIL::CSM_Buffer *Q=NULL, 
      int keybits=0, bool bParams=false, CTIL::CSM_Buffer *params=NULL) { return -1; }

   // Get Public Key
   virtual CTIL::CSM_Buffer* GetPublicKey() = 0;        

   // Get Private Key Unwrapped
   virtual CTIL::CSM_Buffer* GetPrivateKeyUnwrapped(char *pszPassword, 
         CTIL::CSM_Buffer *pEncryptedPrivateKeyInfo) = 0;        

   // Get Private Key Wrapped
   virtual CTIL::CSM_Buffer* GetPrivateKeyWrapped() = 0;

   virtual CTIL::CSM_Buffer* WrapPrivateKey(CTIL::CSM_Buffer &pbufX) = 0;

   virtual SNACC::SubjectPublicKeyInfo* LoadSNACCPublicKeyInfo(CTIL::CSM_Buffer *AnyParams,
      CTIL::CSM_Buffer *PubKey) = 0;
   static CTIL::CSM_Buffer *CSM_CryptoKeysBase::WrapPkcs12(
       char *pBufX, char *pCertFile,             // File Names
       char *pszPassword, 
       char *pencPrvKeyFilename=NULL);  //OPTIONAL input.
};




/* THIS class defines the various input parameters for Elliptic Curve
   crypto definitions.  There are 3 basic types: 
        Fp (Curves over Prime Fields)
        F2m ()
    All of the individual components are represented as strings to avoid
    the need for Crypto++ references (the only CTIL that implements ECDSA).
    There is an encoded parameter, m_pEncodedECParams.
*/
class CSM_ECParams {
private:
    CSM_Buffer *m_pEncodedECParams;
public:
    CSM_ECParams()
    { m_pEncodedECParams=NULL; m_pszModulus_p=NULL; m_pszType=NULL;
      m_pszR=NULL; m_pszTFields=NULL; m_pszA=NULL; m_pszB=NULL;
      /*m_pszSEED=NULL;*/ m_pszGx=NULL; m_pszGy=NULL;
      m_pECBuiltInOID=NULL; m_pSNACCParameters=NULL;
    }
    ~CSM_ECParams()
    {
        if (m_pECBuiltInOID)
            delete m_pECBuiltInOID;

        if (m_pEncodedECParams)
            delete m_pEncodedECParams; 

        if (m_pszModulus_p)
            delete m_pszModulus_p; 
        if (m_pszType)
            delete m_pszType;
        if (m_pszTFields)
            delete m_pszTFields;
        if (m_pszA)
            delete m_pszA;
        if (m_pszB)
            delete m_pszB;
        if (m_pszR)
            delete m_pszR;
        /*if (m_pszSEED)
            delete m_pszSEED;*/
        if (m_pszGx)
            delete m_pszGx;
        if (m_pszGy)
            delete m_pszGy;
    }

    // DEFINE 1st choice to identify an EC curve.
    char *m_pECBuiltInOID;

    // DEFINE 2nd choice to identify an EC curve.
    //   Private ASN.1 encoded buf of params.

    // DEFINE 3rd choice to identify an EC curve.
    //   3rd choice, USED for 3.1 ECP ONLY
    char *m_pszModulus_p;
    //   3rd choice, USED for 3.2 EC2N ONLY
    char *m_pszTFields;
    char *m_pszA;
    //    3rd choice (3.1/3.2) common definitions to both ECP/EC2N
    char *m_pszType;
    char *m_pszR;
    char *m_pszB;
    //char *m_pszSEED;      // PRESENTLY UNSUPPORTED...
    char *m_pszGx;
    char *m_pszGy;

    //
    //  DECLARE all SNACC decoded elements for convenience
    SNACC::EcpkParameters *m_pSNACCParameters;
        // choiceId:  ecParametersCid, namedCurveCid, implicitlyCACid

    //
    //
    const CSM_Buffer *GetEncodedECParams() { return m_pEncodedECParams; };
    void SetEncodedECParams(CSM_Buffer &BufEncodedEcParams) 
    { if (m_pEncodedECParams) delete m_pEncodedECParams;
      m_pEncodedECParams = new CSM_Buffer(BufEncodedEcParams); }
};

long EncryptPKCS12PrivateKey(
         CSM_Buffer *&pEncryptedPrivateKeyInfo, // OUT
         const char *pszPassword,               // IN
         CSM_PrivDataLst &PrivateKeyList);      // IN


_END_CERT_NAMESPACE


#endif //SM_CRYPTOKEYS

// EOF sm_CryptoKeys.h
