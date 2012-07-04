
//////////////////////////////////////////////////////////////////////////
// sm_capi.h
// Motorola developed CTIL utilizing the MS Windows CAPI interface.
// Supported algorithms:
//     Triple-DES and RC2 for encryption/decryption;
//     RSA (PKCS #1 v1.5) for key management; 
//     SHA-1 and MD5 for hashing; and
//     DSA and RSA (PKCS #1 v1.5) for signature generation/verification.
//  RWC:CHECK CAPI Version 2.
//
//////////////////////////////////////////////////////////////////////////

#ifndef _SM_CAPI_H_
#define _SM_CAPI_H_
#ifdef WIN32
/*// constant defines used in the free CTI
#define SM_FREE_BLOCK_SIZE 32767
//#define SM_FREE_3DES_KEYLEN 24
//#define SM_FREE_3DES_IVLEN 8
//#define SM_FREE_3DES_BLOCKSIZE 8
//#define SM_FREE_RC2_KEYLEN 16         // byte count 128 bits 
//#define SM_FREE_RC2_BLOCKSIZE  8
#define SM_FREE_RA_SIZE 512           // BITS for DH UKM.
#define SM_FREE_DSA_SIG_LEN 40
#define SM_FREE_FORTENC "FORTEZZA MEK: REG"
#define SM_FREE_RANDSIZE 100
#define SM_FREE_RC2_DEFAULT_PBE_KEYBITS 80  // this is actually bits
#define SM_FREE_DEFAULT_KEYBITS 1024  // this is actually bits
#define SM_FREE_RC2_DEFAULT_PBE_KEYLEN (80/8)  // this is actually bytes
*/
#define SM_CAPI_MISSING_PARAM       6000
#define SM_CAPI_FORTENC "FORTEZZA MEK: REG"
#define SM_CAPI_UNSUPPORTED_ALG     6002
#define SM_CAPI_PARAM_DEC_ERROR     6001


#include <stdio.h>
#ifndef _WIN32_WINNT
	#define _WIN32_WINNT 0x0400	// Minimum Windows version required for
#endif							      //    CryptoAPI (Win95 OSR2 or NT 4.0)
#include <windows.h>
#include <wincrypt.h>
#include "sm_common.h"
#include "sm_apiCert.h"

#ifndef CRYPT_ACQUIRE_COMPARE_KEY_FLAG
#define CRYPT_ACQUIRE_COMPARE_KEY_FLAG 0x4
#endif  //CRYPT_ACQUIRE_COMPARE_KEY_FLAG

//RWC2;#ifndef CALG_RC4
//RWC;NOTE; the following "SM_VDA_NOT_WIN2K" define may not be necessary on 
//  many newer platforms.  Especially if the MS MNDN Platform SDK is installed.
//RWC2;#define SM_VDA_NOT_WIN2K
//#if(_WIN32_WINNT >= 0x0500)
//RWC2;#include "wincryptRWC.h"
//RWC2;#endif //CALG_RC4
extern "C" {
typedef BOOL /*__stdcall WINAPI*/ (WINAPI * CryptAcquireCertificatePrivateKey_DEF)(
  PCCERT_CONTEXT pCert,        
  DWORD dwFlags,               
  void *pvReserved,            
  HCRYPTPROV *phCryptProv,     
  DWORD *pdwKeySpec,           
  BOOL *pfCallerFreeProv       
);
}

#include <string.h>
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
void HandleError(char *s);


//#include "sm_cms.h"

#ifdef WIN32
#ifdef SM_CAPIDLL_EXPORTS
#define SM_CAPIDLL_API __declspec(dllexport)
#else
#define SM_CAPIDLL_API __declspec(dllimport)
#endif
#else
#define SM_CAPIDLL_API
#endif
_BEGIN_CERT_NAMESPACE

#define OPTIONAL_DataKey_DLLFileName "BuildContainers.dll"
class SM_CAPIDLL_API CSM_Capi : virtual public CSM_Common
{
private:
   HCRYPTPROV  m_hInternalMSKey;
public:
   CSM_Capi(SNACC::AsnOid CertAlgOid);
   CSM_Capi();
   void Setup(SNACC::AsnOid CertAlgOid); 

   ~CSM_Capi();

    // DECLARE factory class to generate an appropriate CSM_Capi instance.
    //  (RWC; One is a virtual override for use by the application. the
    //   other is a static use for internal construction).
    /*CSM_TokenInterface *AddLogin(
       CSM_Buffer &CertBuf,       // IN, public key and algs
       CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
       char *lpszPassword,        // IN, password to pbe decrypt privatekey
       char *lpszID);             // CTIL specific ID*/
    static CSM_TokenInterface *AddLoginStatic(
        char *lpszCertSubjectName, // IN, OPTIONAL, UNUSED for now, "NULL"
        char *lpszProviderName,    // IN, OPTIONAL, "DATAKEY" or "MS_ENHANCED_PROV".
        CSM_MsgCertCrls *&pCertPath, // OUT, OPTIONAL for user cert if present.
        bool bUseInternalPublicKey=false,//IN, OPTIONAL for DEBUG only.
        char *lpszPin=NULL,          // IN, OPTIONAL (only for DataKey CSP).
        long lSocket=1,              // IN, OPTIONAL (only for DataKey CSP).
        char *pszFlag=NULL);         // IN, OPTIONAL, "signer" or "encrypter"

       /*CSM_Capi *pFree,          // IN,OPTIONAL, input class instance.
       CSM_Buffer &CertBuf,       // IN, public key and algs
       CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
       char *lpszPassword,        // IN, password to pbe decrypt privatekey
       char *lpszID,              // CTIL specific ID
       CSM_MsgCertCrls *pCertPath=NULL);*/

   // The SMTI_* functions below are the standard CTI API functions 
   // implemented according to the SFL CTI API Document
   SM_RET_VAL SMTI_Login(char *lpszSubjectName=NULL, char *lpszProviderName=NULL, bool bSigner=false);
   SM_RET_VAL SMTI_Sign(
            CSM_Buffer *pData, // input, data to be signed
            CSM_Buffer *pEncryptedDigest, // signature
            CSM_Buffer *pDigest); // digest
   SM_RET_VAL SMTI_Verify(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA *pDigestAlg, // input
            CSM_AlgVDA *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature); // input
   SM_RET_VAL SMTI_VerifyRSA(
            CSM_Buffer *pSignerKey, // input
            CSM_Alg    *pDigestAlg, // input
            CSM_Alg    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature); // input
   SM_RET_VAL SMTI_Encrypt(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV=NULL);// In, to avoid specific alg encoding by app.
      // This routine now handles 3DES and RC2 content encryption algs.
   SM_RET_VAL CSM_Capi::SMTI_EncryptCapi(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *&pIV);  // In, to avoid specific alg encoding by app.
   SM_RET_VAL SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN/OUT, may re-use
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // output
            CSM_Buffer *pSubjKeyId=NULL); // output
   SM_RET_VAL SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK); // output
   SM_RET_VAL RSA_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN/OUT, may re-use
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // output
            CSM_Buffer *pSubjKeyId=NULL); // output
   SM_RET_VAL RSA_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK); // output
   SM_RET_VAL SMTI_Decrypt(
            CSM_Buffer *pParameters, // input (initialization vector)
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK, // input (MEK or special phrase)
            CSM_Buffer *pData); // output (decrypted data)
   // This routine now handles 3DES and RC2 decryption algs.
   SM_RET_VAL SMTI_DecryptCapi(
            CSM_Buffer *pParameters, // input (initialization vector)
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK, // input (MEK or special phrase)
            CSM_Buffer *pData); // output (decrypted data)
   SM_RET_VAL SMTI_DigestData(
            CSM_Buffer *pData, // input
            CSM_Buffer *pDigest); // output
   SM_RET_VAL SMTI_Random(
            CSM_Buffer *pSeed, // input
            CSM_Buffer *pRandom, // input/output
            SM_SIZE_T lLength); // input
   // this CTI does nothing with locking/unlocking 
   SM_RET_VAL SMTI_Lock() { return SM_NO_ERROR; };
   SM_RET_VAL SMTI_Unlock() { return SM_NO_ERROR; };
   bool SMTI_IsKeyAgreement();         // FALSE indicates key transfer.
                                       // TRUE indicates key agreement 
                                       //  encryption, not key transfer.
   void CSM_TokenInterfaceDestroy();

   // The methods below this pointer are outside of the CTI API and are custom
   // to this CTI Class

   // This CTI will override BTIFindAlgIds because in CEA and KEA's
   // case, we only want to compare OIDs and are not interested in 
   // comparing the parameters part of the AlgId
   bool BTIFindAlgIds(CSM_AlgVDA *pdigestAlgID, 
            CSM_AlgVDA *pdigestEncryptionAlgID,
            CSM_AlgVDA *pkeyEncryptionAlgID,
            CSM_AlgVDA *pcontentEncryptionAlgID);

   // set or restore the default Alg OIDs
   void SetDefaultOIDs(const SNACC::AsnOid *pCertAlgOid=NULL);  // Param specifies this instance Algs.

   CSM_AlgVDA *DeriveMsgAlgFromCert(CSM_AlgVDA &Alg);
   CSM_Alg *DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert);
                // This call interprets KARI certificate params into CMS Msg
                //  Param format for algorithms.  It is up to the CTIL to 
                //  properly interpret algorithm specific formats for both.
   //////////////////////////////////////////////////////
   #ifdef FULL_MESSAGE_LEVEL_ENCRYPT_NOT_USED
   HCRYPTKEY ComputeInternalPasswordKey();
   long CapiMsgEncryptEncode(CSM_Buffer &CertBuf);
   #endif //FULL_MESSAGE_LEVEL_ENCRYPT_NOT_USED
   HCRYPTKEY FormatRSAPublicKeyHandle(CSM_Buffer &BufRsaPublicKey,
        DWORD dSpecKeyOrSignature);    // AT_SIGNATURE or AT_KEYEXCHANGE
   HCRYPTKEY FormatRSAPublicKeyHandleFromCert(CSM_Buffer &BufRsaPublicCert,
        DWORD dSpecKeyOrSignature);    // AT_SIGNATURE or AT_KEYEXCHANGE
   CSM_Buffer *ExtractRSAPublicKeyFromBlob(CSM_Buffer &BufRsaPublicKeyBlob);
   PCCERT_CONTEXT GetRecipientCert(CSM_Buffer &CertBuf);
   SM_RET_VAL SMTI_DigestDataInternal(
            CSM_Buffer *pData,   // Input
            CSM_Buffer *pDigest, // Output
            HCRYPTHASH &hHash);  // Output
   char *ConvertDNStringToCapiInternal(const char *lpszSFLDNStringInput);
   HCERTSTORE m_hStoreHandle;
   PCCERT_CONTEXT m_pSignerCertContext;
   //////////////////////////////////////////////////////

   char *m_pszPrefix; // ID Prefix specified by app
   char *m_pszProviderName;
   CSM_MsgCertCrls *m_pCertPath;
   static HMODULE m_hDataKeyModule;

private:
   CSM_Buffer *m_pbufPassword; // protected password
   CSM_Buffer *m_pRandomData;
   bool m_bUseInternalPublicKey; //DEBUG use only; "true" will allow the use
                                 //  of the internal CAPI public key for verify
                                 //  and decryption execution.  This allows for
                                 //  testing without certificates on various 
                                 //  Providers (e.g. MS, DataKey, etc.).

   void Clear() { m_pszPrefix = NULL; m_pbufPassword = NULL;
         m_pRandomData = NULL; m_pSignerCertContext = NULL; m_hStoreHandle = 0;
         m_pCertPath = NULL;  m_bUseInternalPublicKey = false; 
         m_bDataKeyCertificatesLoaded = false; m_lpszPin=NULL;
         m_pszProviderName = NULL;
         m_lSocket = 1; m_bSigner = true; m_hKeyEncryption = 0;}

   SM_RET_VAL ExtractParams(SNACC::AlgorithmIdentifier *pAlgID);
   SM_RET_VAL DecodeCertificate(CSM_Buffer *pEncodedCert,
         SNACC::Certificate *pSnaccCertificate, SNACC::Name **ppIssuer,
         SNACC::AlgorithmIdentifier **ppAlgID, SNACC::AsnBits **ppY);
   HCRYPTKEY ExtractRSAPublicKeyFromPKI(CSM_Buffer &BufPublicKeyInfo, 
          ALG_ID pCAPIAlg);  /*CALG_RSA_SIGN, CALG_RSA_KEYX*/
   bool bInTestDirectory();
   bool CompareCertToInternalKey(PCCERT_CONTEXT pCertContext, 
      bool bSigner,           // true requests Signer internal key,
                              // false requests Encrypters internal key.
      HCRYPTKEY *phKey=NULL,  // pCertContext public key handle.
      HCRYPTKEY *phKey2=NULL);// internal signer OR encyrpter's key handle.
                              //  (APP MUST DESTORY AND free(...) if present).
   bool TryToGetCertificate(bool bSigner, BYTE *&pbCertificate, DWORD &dwCertLength);
   // The following method and variable are used to load a DataKey smartcard 
   //  DLL and execute functions that will load certificates from the 
   //  smartcard to the system registry.  IT IS ONLY EXECUTED FOR DataKey.
   //  (The OPTIONAL_DataKey_DLLFileName and associated DataKey DLLs are 
   //   expected to be in the executable path).
   void OPTIONAL_DataKey_CertificateLoads();
   bool CheckThisPrivateKeyForSignEncyrpt(DWORD dwKeySpec, bool bSigner, 
          PCCERT_CONTEXT pCertContext);

   bool m_bDataKeyCertificatesLoaded;
   char *m_lpszPin;
   long m_lSocket;
   bool m_bSigner;
   HCRYPTKEY m_hKeyEncryption;     // ONLY 1 stored at a time; may cause a 
                                   //  memory leak if app uses 2 sets.
   //

   HCRYPTPROV m_hCryptProv;  //Session ID.
};


_END_CERT_NAMESPACE

#endif // WIN32

#endif // _SM_CAPI_H_

// EOF sm_CAPI.h
