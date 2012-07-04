/* @(#) sm_rsa.h 1.31 06/29/00 13:30:30 */

//////////////////////////////////////////////////////////////////////////
// sm_rsa.h
// 
// header file implementing BSAFE algorithms to include RSA, RC2, MD5 and SHA1.
//
// Should be directly included by the C++ app and the sm_rsa CTI Library
//
//////////////////////////////////////////////////////////////////////////

#ifndef _SM_RSA_H_
#define _SM_RSA_H_

#ifdef WIN32
#ifdef SM_RSADLL_EXPORTS
#define SM_RSADLL_API __declspec(dllexport)
#else
#define SM_RSADLL_API __declspec(dllimport)
#endif
#else
#define SM_RSADLL_API
#endif



// constant defines used in the rsa CTI
#define SM_RSA_RC2_BLOCKSIZE 8
#define SM_RSA_RC2_DEFAULT_KEYBITS 128  // keybits 16 bytes
#define SM_RSA_RC2_DEFAULT_PBE_KEYBITS 80  // this is actually bytes
#define SM_RSA_DEFAULT_PBE_ITERATIONS 5
#define SM_RSA_DEFAULT_KEYLEN 1024
#define SM_RSA_FORTENC "FORTEZZA MEK: REG"
#define SM_RSA_MAXPAD 8
#define SM_RSA_RANDSIZE 100

//////////////////////////////////////////////////////////////////////////
// SM_RSA errors 5000-5999

// parameter missing to a SMTI function
#define SM_RSA_MISSING_PARAM       5000
// occurs when unable to ASN.1 decode provided parameters
#define SM_RSA_PARAM_DEC_ERROR     5001
// occurs when caller requests CSM_Rsa to process or operate using an
// unsupported algorithm
#define SM_RSA_UNSUPPORTED_ALG     5002
// occurs when SMTI_Verify signature check fails
#define SM_RSA_VERIFY_FAILED       5003
// occurs when CSM_Rsa doesn't have a preferred digest alg set
#define SM_RSA_NO_DIGEST_ALG       5004
// occurs when CSM_Rsa can't find issuer of a user cert in the address book
#define SM_RSA_MAB_NO_ISSUER       5005
// occurs when the issuer from the address book is not a DSA cert
#define SM_RSA_ISSUER_NOT_DSA      5006
// occurs when the attempt to load a public value into the CSM_Rsa fails
#define SM_RSA_PUT_Y_ERROR         5007
// occurs when the rsa CTI is unable to ASN.1 decode a structure
// properly or fully
#define SM_RSA_DECODE_ERROR        5008


#include "sm_apiCert.h"

#undef NULL_PTR            // Undefine PKCS#11's definition

#include "sm_cms.h"
#include "sm_common.h"
#include "aglobal.h"
#include "bsafe.h"
#include "stdlibrf.h"
_BEGIN_CERT_NAMESPACE

class SM_RSADLL_API CSM_Rsa : public CSM_Common
{
private:
   SM_RET_VAL SMTI_ExtractKeyWrapFinish(
            CSM_Buffer *pData, // Output
            CSM_Buffer &CEKICVPAD);  // Input
public:
    // DECLARE factory class to generate an appropriate CSM_Rsa instance.
    //  (RWC; One is a virtual override for use by the application. the
    //   other is a static use for internal construction).
    CSM_TokenInterface *AddLogin(
       CSM_Buffer &CertBuf,       // IN, public key and algs
       CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
       char *lpszPassword,        // IN, password to pbe decrypt privatekey
       char *lpszID);             // CTIL specific ID
    static CSM_TokenInterface *AddLoginStatic(
       CSM_Rsa *pRsa,             // IN,OPTIONAL, input class instance.
       CSM_Buffer &CertBuf,       // IN, public key and algs
       CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
       char *lpszPassword,        // IN, password to pbe decrypt privatekey
       char *lpszID);             // CTIL specific ID

   // The SMTI_* functions below are the standard CTI API functions 
   // implemented according to the SFL CTI API Document
   SM_RET_VAL SMTI_Login(void);
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
            CSM_Buffer *pParameters, // output
            CSM_Buffer *pMEK,      // output
            CSM_Buffer *pIV=NULL);  // In, to avoid specific alg encoding by app.
   SM_RET_VAL SMTI_EncryptRC2(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // output
            CSM_Buffer *pMEK,      // output
            CSM_Buffer *pIV=NULL);  // In, to avoid specific alg encoding by app.
   SM_RET_VAL SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // output
            CSM_Buffer *pSubjKeyId); // output
   SM_RET_VAL SMTI_ExtractMEK(
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
   SM_RET_VAL SMTI_DecryptRC2(
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
   SM_RET_VAL SMTI_GenerateKeyWrap(
            CSM_Buffer *pCEK, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyTransfer algs.
            CSM_Buffer *pMEK, // In; may be specified.
            CSM_Buffer *pIV);  // In, to avoid specific alg encoding by app.
   CSM_Buffer* SMTI_GenerateKeyWrapIV(
    long &lKekLength,   // OUT, returned algorithm specific length
    CSM_Alg *pWrapAlg=NULL);  // OUT, returned since params are alg specific.

   void LoadParams(CSM_Buffer &IV, CSM_Buffer *pParameters);

   // this CTI does nothing with locking/unlocking 
   SM_RET_VAL SMTI_Lock() { return SM_NO_ERROR; };
   SM_RET_VAL SMTI_Unlock() { return SM_NO_ERROR; };
   bool SMTI_IsKeyAgreement() { return false; };  // THIS LIBRARY USES only RSA
                                       // TRUE indicates key agreement 
                                       //  encryption, not key transfer.
   CSM_Alg *DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert);
   CSM_AlgVDA *DeriveMsgAlgFromCert(CSM_AlgVDA &Alg);

   // The methods below this pointer are outside of the CTI API and are custom
   // to this CTI Class

   CSM_Rsa(); // default constructor
   ~CSM_Rsa(); // DESTRUCTOR
   void CSM_TokenInterfaceDestroy();

   // set or restore the default Alg OIDs
   void SetDefaultOIDs();

   char *GetPassword();  // unprotect and return password  
   void SetPassword(char *pszPassword);  // protect and store password

   // returns a decrypted private key
   B_KEY_OBJ GetBsafePrivateKey();

   // key material member access functions
   void SetX(CSM_Buffer *pX); // store EncryptedPrivateKeyInfo
   CSM_Buffer *GetX(){return m_RSAX;}

   // called by init
   SM_RET_VAL GetParamsAndY(CSM_Buffer *pEntry, SNACC::AlgorithmIdentifier *&pAlgID);

   // generates PBE key from salt and itercount (and password)
   CSM_Buffer* GeneratePBEKey(CSM_Buffer *pbufSalt, int nIterCount,
         char *pszPassword);
   // Load and decrypt a private key from an EncryptedPrivateKeyInfo
   CSM_Buffer* DecryptPrivateKey(char *pszPassword, 
         CSM_Buffer *pEncryptedPrivateKeyInfo);

   // TBD, following should be private, used for testing now...
   ITEM        m_RSAY;           // RSA Public Key
   char *m_pszPrefix;     // ID Prefix specified by app
   A_RC2_CBC_PARAMS m_rc2Params;
   B_RC2_PBE_PARAMS m_rc2PBEParams;
   A_RSA_KEY_GEN_PARAMS m_keygenParams;

   // random number generator
   B_ALGORITHM_OBJ m_randomAlgorithm;

   // CHOOSER for CSM_Rsa's use of BSAFE
   B_ALGORITHM_METHOD *m_pCHOOSER[20];

   MAB_AB_def *m_pAB;

private:
   char *m_pszPassword;
   CSM_Buffer *m_pbufPassword; // protected password
   CSM_Buffer m_seed;
   CSM_Buffer *m_pRandomData;
   CSM_Buffer *m_RSAX;           // RSA Private Key

   void Clear();
   void SetCryptoDefaults();
   void EncodeRC2Params(CSM_Buffer *out);
   void DecodeRC2Params(CSM_Buffer &in);
   SM_RET_VAL ExtractParams(SNACC::AlgorithmIdentifier *pAlgID);
   SM_RET_VAL DecodeCertificate(CSM_Buffer *pEncodedCert,
       SNACC::Certificate *pSnaccCertificate, SNACC::Name **ppIssuer,
       SNACC::AlgorithmIdentifier **ppAlgID, SNACC::AsnBits **ppY);
};

void SM_RSADLL_API SMRsaInit(CSM_CtilMgr *pCtilMgr, char *pszPassword,
                     char *pszAddressBook, char *pszPrefix);
void SM_RSADLL_API SMRsaShutdown(CSMIME *pCSMIME, char *pszPrefix);

_END_CERT_NAMESPACE

#endif // _SM_RSA_H_

// EOF sm_rsa.h
