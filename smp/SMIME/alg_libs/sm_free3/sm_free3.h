
/* @(#) sm_free3.h 1.31 06/27/00 12:38:19 */
////////////////////////////////////////////////////////////////////////////////
//
// File:  sm_free.h
//
// Project:  Crypto++ Crypto Token Interface Library (CTIL), aka SM_Free3
//
// Contents:  header file implementing freely distributable S/MIME v3 MUST 
// algorithms to include SHA1, DSA, DH, and 3DES.  
//
// Should be directly included by the C++ app and the sm_free CTI Library
//
// Author:  Robert.Colestock@getronicsgov.com
//           Sue Beauchamp <Sue.Beauchamp@it.baesystems.com> 
//  
// Last Updated:	16 December 2004
//                Req Ref:  SMP RTM #5
// 
////////////////////////////////////////////////////////////////////////////////
#ifndef _SM_FREE3_H_
#define _SM_FREE3_H_

// constant defines used in the free CTI
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

//////////////////////////////////////////////////////////////////////////
// SM_FREE errors 6000-6999

// parameter missing to a SMTI function
#define SM_FREE_MISSING_PARAM       6000
// occurs when unable to ASN.1 decode provided parameters
#define SM_FREE_PARAM_DEC_ERROR     6001
// occurs when caller requests CSM_Free to process or operate using an
// unsupported algorithm
#define SM_FREE_UNSUPPORTED_ALG     6002
// occurs when SMTI_Verify signature check fails
#define SM_FREE_VERIFY_FAILED       6003
// occurs when CSM_Free doesn't have a preferred digest alg set
#define SM_FREE_NO_DIGEST_ALG       6004
// occurs when CSM_Free can't find issuer of a user cert in the address book
#define SM_FREE_MAB_NO_ISSUER       6005
// occurs when the issuer from the address book is not a DSA cert
#define SM_FREE_ISSUER_NOT_DSA      6006
// occurs when the attempt to load a public value into the CSM_Free fails
#define SM_FREE_PUT_Y_ERROR         6007
// occurs when the pad values in the final block of encrypted data are
// incorrect...would probably occur if decrypt used the wrong MEK
#define SM_FREE_DECRYPT_PAD_ERROR   6008
// occurs when the free CTI is unable to ASN.1 decode a structure
// properly or fully
#define SM_FREE_DECODE_ERROR        6009
// sizes for AES processing
#define AES_IV_SIZE                 16
#define AES_128			            128
#define AES_192			            192
#define AES_256			            256

// SM_FREE Pad macro
#define SM_FREE_Pad(buf, size) {\
      unsigned int b = SM_FREE_3DES_BLOCKSIZE - \
            (size % SM_FREE_3DES_BLOCKSIZE); \
      memset(buf+size, (char) b, (size_t) b); \
      size += b;                     \
      }

#include "sm_apiCert.h"
#include "sm_common.h"

#include "sm_cms.h"
#include "sm_free3_asn.h"

#include "des.h" // TripleDES
#include "integer.h" // big integers
#include "dh.h" // DH key agreement

// DEFINE EITHER 5.0 or 5.1 references here...
//#define CRYPTOPP_5_0
//RWC;
#define CRYPTOPP_5_1



// RWC; DO NOT REMOVE/CHANGE THE FOLLOWING...  All 5.1 Crypto++ references
// RWC;  still use the 5.0 define.
#ifdef CRYPTOPP_5_1
#define CRYPTOPP_5_0    // RWC;NEEDS to be defined as well...
#endif      //CRYPTOPP_5_1

#include "rng.h" // random number generator
#include "modes.h" // CBCEncryption

#if !defined(CRYPTOPP_5_0) && !defined(CRYPTOPP_5_1)
#include "cbc.h"
#include "dsa.h" // DSA digest encryption
#else
//#define CRYPTOPP_MAINTAIN_BACKWARDS_COMPATIBILITY
#include "gfpcrypt.h"
typedef CryptoPP::DSA::Signer DSAPrivateKey;  //RWC;From dsa.h
typedef CryptoPP::DSA::Verifier DSAPublicKey;
#endif //CRYPTOPP_5_0
#include "sha.h" // SHA1
#include "md5.h"
#include "md2.h"

#include "dh2.h"

using namespace CryptoPP;
#ifdef WIN32
#ifdef SM_FREE3DLL_EXPORTS
#define SM_FREE3DLL_API __declspec(dllexport)
#else
#define SM_FREE3DLL_API __declspec(dllimport)
#endif
#else
#define SM_FREE3DLL_API
#endif
_BEGIN_CERT_NAMESPACE



//
//
class SM_FREE3DLL_API CSM_Free3 : virtual public CSM_Common
{
public:
   CSM_Free3(const SNACC::AsnOid CertAlgOid);
   CSM_Free3();
   void Setup(const SNACC::AsnOid CertAlgOid); 

   virtual ~CSM_Free3();

    // DECLARE factory class to generate an appropriate CSM_Free3 instance.
    //  (RWC; One is a virtual override for use by the application. the
    //   other is a static use for internal construction).
    CSM_TokenInterface *AddLogin(
       CSM_Buffer &CertBuf,       // IN, public key and algs
       CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
       char *lpszPassword,        // IN, password to pbe decrypt privatekey
       char *lpszID);             // CTIL specific ID
    static CSM_TokenInterface *AddLoginStatic(
       CSM_Free3 *pFree,          // IN,OPTIONAL, input class instance.
       CSM_Buffer &CertBuf,       // IN, public key and algs
       CSM_Buffer *pSFLPrivateKey,// IN, private key for signing/
                              //     encryption ops OPTIONAL
       char *lpszPassword,        // IN, password to pbe decrypt privatekey
       char *lpszID,              // CTIL specific ID
       CSM_MsgCertCrls *pCertPath=NULL);

   // The SMTI_* functions below are the standard CTI API functions 
   // implemented according to the SFL CTI API Document
   SM_RET_VAL SMTI_Login(void);
   SM_RET_VAL SMTI_Sign(
            CSM_Buffer *pData, // input, data to be signed
            CSM_Buffer *pEncryptedDigest, // signature
            CSM_Buffer *pDigest); // digest
   SM_RET_VAL SMTI_Verify(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature); // input
#ifdef SM_FREE3_RSA_INCLUDED
   SM_RET_VAL SMTI_VerifyRSA(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature); // input
#endif
   SM_RET_VAL SMTI_VerifyDSA(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature); // input
   SM_RET_VAL SMTI_VerifyECDSA(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature); // input
   SM_RET_VAL SMTI_Encrypt(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV=NULL);// In, to avoid specific alg encoding by app.
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
#ifdef SM_FREE3_RSA_INCLUDED
   SM_RET_VAL RSA_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN/OUT, may re-use
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // output
            CSM_Buffer *pSubjKeyId=NULL); // output
   SM_RET_VAL RSAES_OAEP_GenerateEMEK(
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
   SM_RET_VAL RSAES_OAEP_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK); // output (MEK or special phrase)
#endif
   SM_RET_VAL SMTI_Decrypt(
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
   SM_RET_VAL SMTI_GenerateKeyAgreement(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            SNACC::AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            long lKekLength);        // Input, for OtherInfo load.
   SM_RET_VAL SMTI_GenerateKeyWrap(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV); // In, to avoid specific alg encoding by app.
   SM_RET_VAL SMTI_ExtractKeyWrapFinish(
            CSM_Buffer *pData, // Output
            CSM_Buffer &CEKICVPAD);  // Input
   CSM_Buffer *SMTI_GenerateKeyWrapIV(
    long &lKekLength,   // OUT, returned algorithm specific length
    CSM_AlgVDA *pWrapAlg=NULL);  // OUT, returned since params are alg specific.

   SM_RET_VAL SMTI_GeneratePWRIKeyWrap(
            CSM_Buffer *pData, // input  cek to be encrypted by KEK derived from password
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pIV,  // In, to avoid specific alg encoding by app. salt
            CSM_Buffer *pPassword,          
            CSM_Buffer *pUserKeyEncryptionKey, // IN, Optional
            CSM_AlgVDA    *&pPWRIDerivationAlg,  // IN, PWRI id-PBKDF2 for now
            CSM_AlgVDA    *&pPWRIEncryptionAlg);  // IN, PWRI id-alg-PWRI-KEK for now

   SM_RET_VAL SMTI_ExtractPWRIKeyWrap(
            CSM_Buffer &MEK, // Output
            const CSM_Buffer EncryptedData, // input
            const CSM_Buffer Password, // IN password
            CSM_Buffer *pUserKeyEncryptionKey, // IN, Optional
                  CSM_AlgVDA    *pPWRIDerivationAlg,  // IN, OUT PWRI id-PBKDF2 for now
                  CSM_AlgVDA    *PWRIEncryptionAlg);   // IN, OUT PWRI id-alg-PWRI-KEK for now

   // added for extract keywrap AES using CryptoPP
   SM_RET_VAL SMTI_ExtractKeyWrap(
       CTIL::CSM_Buffer *pData,         // Output
       CTIL::CSM_Buffer *pEncryptedData,// input
       CTIL::CSM_Buffer *pParameters,   // IN, for KeyAgree algs.
       CTIL::CSM_Buffer *pTEK,          // output
       CTIL::CSM_Buffer *pIV);           // In

   SM_RET_VAL SMTI_ExtractKeyAgreement(
            CSM_Buffer *pOriginator, // input, Y of originator
            //CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            SNACC::AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            long lKekLength);       // Input, for OtherInfo load.
   // this CTI does nothing with locking/unlocking 
   SM_RET_VAL SMTI_Lock() { m_ThreadLock.threadLock(); return SM_NO_ERROR; };
   SM_RET_VAL SMTI_Unlock() { m_ThreadLock.threadUnlock(); return SM_NO_ERROR; };
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
   void SetDefaultOIDs(SNACC::AsnOid CertAlgOid);  // Param specifies this instance Algs.

   void SetPassword(char *pszPassword); // protect and store password
   char* GetPassword(); // unprotect and return password

   // key material member access functions
   void SetX(const CSM_Buffer &X); // store EncryptedPrivateKeyInfo
   CSM_Buffer *GetX(){return m_pX;}
   void SetDHParams(CSM_Buffer *pP, CSM_Buffer *pG);
   void SetDHParams(SNACC::AsnInt &P, SNACC::AsnInt &G);
   void SetBufY(const CSM_Buffer &BufY);
   CSM_Buffer *GetBufY(){CSM_Buffer *pBuf=NULL;
                          if (m_pBufY) pBuf = new CSM_Buffer(*m_pBufY);
                          return pBuf;}
   void SetDSAY(const CSM_Buffer &BufY);
   CSM_Buffer *GetDSAY();
   void SetDSAParams(CSM_Buffer *pP, CSM_Buffer *pQ, CSM_Buffer *pG);
   void SetDSAParams(SNACC::AsnInt &P, SNACC::AsnInt &Q, SNACC::AsnInt &G);

   // called by init
   SM_RET_VAL GetParamsAndY(CSM_Buffer &pCertBuf, MAB_AB_def *pAB,
         SNACC::AlgorithmIdentifier *&pAlgID);

   // encrypt input into output using the provided cbc encryption
   static void RawEncrypt(CSM_Buffer *pbufInput, CSM_Buffer *pbufOutput,
        #ifndef CRYPTOPP_5_0
         Filter *pCBCEncryption);   // Defaults to 3DES Content Enc
        #else   // CRYPTOPP_5_0
         StreamTransformation *pCBCEncryption);
        #endif  // CRYPTOPP_5_0
   static void RawEncrypt(CSM_Buffer *pbufInput, CSM_Buffer *pbufOutput,
        #ifndef CRYPTOPP_5_0
         Filter *pCBCEncryption, 
        #else   // CRYPTOPP_5_0
         StreamTransformation *pCBCEncryption, 
        #endif  // CRYPTOPP_5_0
         int iINBlockLen);
   // decrypt input into output using the provided cbc decryption
   static void RawDecrypt(CSM_Buffer *pbufInput, CSM_Buffer *pbufOutput,
        #ifndef CRYPTOPP_5_0
         Filter *pCBCDecryption);
        #else   // CRYPTOPP_5_0
         StreamTransformation  *pCBCDecryption);
        #endif  // CRYPTOPP_5_0
   static void RawDecrypt(CSM_Buffer *pbufInput, CSM_Buffer *pbufOutput,
        #ifndef CRYPTOPP_5_0
         Filter *pCBCDecryption, 
        #else   // CRYPTOPP_5_0
         StreamTransformation  *pCBCDecryption, 
        #endif  // CRYPTOPP_5_0
         int iINBlockLen);

   // generates PBE key from salt and itercount (and password)
   CSM_Buffer *GeneratePBEKey(CSM_Buffer *pbufSalt, int nIterCount,
         char *pszPassword);
   CSM_Buffer *GeneratePBEKey(CSM_Buffer *pbufSalt, int nIterCount, 
                  char *pszPassword, SNACC::AsnOid &o, int nKeyLength=16, 
                  int lPassword=0);
   static CSM_Buffer *GeneratePKCS12PBEKey(CSM_Buffer *pbufSalt, int nIterCount, 
          int iID, char *pszPassword, SNACC::AsnOid &o, int nKeyLength=16, 
          int lPassword=0, int lBlockSize=0x40, long lRequested=0);
   // Load and decrypt a private key from an EncryptedPrivateKeyInfo
   CSM_Buffer *DecryptPrivateKey(char *pszPassword, 
         CSM_Buffer *pEncryptedPrivateKeyInfo, long lPassword=0);

   // HANDLE PKCS12 files input, even those with multiple Private Keys.
   static long DecryptPKCS12PrivateKey( 
         CSM_Buffer *pEncryptedPrivateKeyInfo, 
         const char *pszPassword,
         CSM_PrivDataLst &PrivateKeyList);
   /*static void EncryptPKCS12CreatePrivSafeBag(
        const CSM_Buffer &BufPriv,   // IN, Private Key to be loaded
        const char *pszPasswordIN,   // IN, 
        SNACC::SafeContents &SafeBags,      // OUT, resulting PrivateKey added to SafeBag.
        SNACC::Attributes *pSNACCAttributes);// IN, Actual setting for this Private key's
                                      //   matching certificate(s).
   static long EncryptPKCS12PrivateKey( 
         CSM_Buffer *&pEncryptedPrivateKeyInfo, // OUT
         const char *pszPassword,               // IN
         CSM_PrivDataLst &PrivateKeyList);      // IN
   static CSM_Buffer *EncryptPKCS12CreateCertSafeBag(
        const CSM_PrivDataLst &PrivateKeyList, // IN, cert(s)/private Key list
        const char *pszPasswordIN,    // IN, 
        CSM_Buffer *&pencryptedPrivDataBuf);  // OUT, for private keys, encrypted 
                                  //  at the same time as the certificate 
                                  //  SafeBag(s).*/

   CSM_Buffer *GetDynamicPublicKey(CSM_AlgVDA &keyAlg); // May return Certs or pub key.
   void ClearDynamicKey();     // Defaults to do nothing; only
                //  necessary for CTIL algs that generate dynamic keys;
                //   this reset will force generation of a new key.

   CSM_AlgVDA *DeriveMsgAlgFromCert(CSM_AlgVDA &Alg);
   CSM_Alg *DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert);
                // This call interprets KARI certificate params into CMS Msg
                //  Param format for algorithms.  It is up to the CTIL to 
                //  properly interpret algorithm specific formats for both.

   CryptoPP::X917RNG *m_pRng; // random number generator
   char *m_pszPrefix; // ID Prefix specified by app
   MAB_AB_def *m_pAB;
   CSM_MsgCertCrls *m_pCertPath;
   static CSM_Buffer *ComputeBigIntegerBuf(SNACC::AsnInt &snaccInteger, unsigned int len);
   static CSM_Buffer *ComputePkcs12MAC(
                                 CSM_Buffer &bufSalt,            // IN/OUT
                                 const SNACC::AsnOid &sha_1,     // IN
                                 const char *pszPassword,        // IN
                                 const CSM_Buffer &PKCS12Buf,    // IN
                                 const int iter=1);              // IN, OPTIONAL

private:
   CSM_Buffer *m_pbufPassword; // protected password

   CSM_Buffer *m_pRandomData;
   CryptoPP::BlockTransformation *m_pRandomCipher;
   CSM_Buffer m_seed;

   CSM_Buffer *m_pX;    // DSA or DH EncryptedPrivateKeyInfo
   CSM_Buffer m_ParamP; // DH P Parameter
   CSM_Buffer m_ParamG; // DH G Parameter
   CSM_Buffer *m_pECParams; // Elliptic Curve Parameters
   CSM_Buffer *m_pBufY;    // DH and EC Y Buffer (public key)
   CryptoPP::Integer m_DSAP;      // DSA P Parameter
   CryptoPP::Integer m_DSAQ;      // DSA Q Parameter
   CryptoPP::Integer m_DSAG;      // DSA G Parameter
   CryptoPP::Integer m_DSAY;      // DSA Public Key

   CSM_Buffer *m_pEphemeralDHX;    // DH EncryptedPrivateKeyInfo
   CSM_Buffer *m_pEphemeralDHY;    // DH Y (public key)
   CSM_Alg *m_pEphemeralAlg;       // DH (Alg)
   //RWC;CSM_MsgCertCrls *m_pCertPath;

   void Clear() { m_pRng = NULL; m_pszPrefix = NULL; m_pbufPassword = NULL;
         m_pAB = NULL; m_pRandomData = NULL; 
         m_pRandomCipher = NULL; m_pX = NULL; 
         m_pEphemeralDHX=NULL; m_pEphemeralDHY=NULL; m_pEphemeralAlg=NULL;
         m_pCertPath = NULL;  m_pECParams = NULL;}

   SM_RET_VAL ExtractParams(SNACC::AlgorithmIdentifier *pAlgID);
   SM_RET_VAL DecodeCertificate(CSM_Buffer *pEncodedCert,
         SNACC::Certificate *pSnaccCertificate, SNACC::Name **ppIssuer,
         SNACC::AlgorithmIdentifier **ppAlgID, SNACC::AsnBits **ppY);
   SM_RET_VAL SMTI_GenerateKeyWrapInternal(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV); // In, to avoid specific alg encoding by app.
   long SMTI_GenerateKeyAgreementDH(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            SNACC::AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            CSM_Buffer *pbufX,        // INPUT, clear private key
            SNACC::AsnOid &oidKeyEncrypt,  // INPUT
            long lKekLength);        // Input, for OtherInfo load.
   long SMTI_GenerateKeyAgreementECDH(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            SNACC::AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            long lKekLength);         // Input, for SharedInfo load.
   long SMTI_GenerateKeyAgreementECDH_MQV(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,  // input/output may be passed in for shared use.
                              //   Initialization vector, part of DH params.
            SNACC::AsnOid *pEncryptionOID,  // IN, specified encryption of key,
                     //   used here in key generation, but alg not implemented.
            CSM_Buffer *pbufKeyAgree, // output, encryption key for this recip.
            CSM_Buffer *pbufX);        // INPUT, clear private key
   CSM_Buffer *SMTI_ExtractKeyAgreementDH(
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            SNACC::AsnOid *pPreferredContentOID,
            long lKekLength,
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pbufX);      // INPUT, clear private key.
   CSM_Buffer *SMTI_ExtractKeyAgreementECDH(
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
                              //   UserKeyMaterial (random number).
            SNACC::AsnOid *pPreferredContentOID,
            long lKekLength,
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pbufX);      // INPUT, clear private key.

   static long DecryptPKCS12_ProcessBags(CSM_Buffer &bufEncodedBags,
          const char *pszPassword, CSM_BufferLst &BufPrivList, 
          CSM_BufferLst &BufCertList);
   static CSM_Buffer *DecryptPKCS12Blob(const char *pszPasswordIn, 
       SNACC::AlgorithmIdentifier &EncryptionAlgorithm, 
       CSM_Buffer &bufEncryptedKey);
   static long DecryptPKCS12_CheckPublicWithPrivate(CSM_Buffer &BufCheckPublic,
                                             CSM_Buffer &BufPrivateKey);
   static CSM_Buffer *EncryptPKCS12Blob(const char *pszPasswordIn, 
       SNACC::AlgorithmIdentifier &EncryptionAlgorithm, 
       const CSM_Buffer &bufClearKey);
   static long DecryptPKCS12Cert(CSM_Buffer *pEncryptedPrivateKeyInfo, 
      const char *pszPasswordIn, CSM_BufferLst &BufPrivList, 
      CSM_BufferLst &BufCertList);
   static CSM_Buffer *EncryptPKCS12CreateCertSafeBag(
        const CSM_BufferLst &BufCertList,   // IN, cert(s) to be loaded
        const char *pszPassword);           // IN, 
public:     // RWC; for testing
   static CSM_Buffer *ComputePkcs12MACHash(const SNACC::AsnOid &OidMac,// IN
         const CSM_Buffer &BufKey,       // IN
         const CSM_Buffer &PKCS12Buf);   // IN
private:
   static SM_RET_VAL SMTI_DigestDataInternal(CSM_Buffer *pData,
                                 CSM_Buffer *pDigest, const SNACC::AsnOid &o);
   SM_RET_VAL SMTI_DigestData(
            CSM_Buffer *pData,       // input
            CSM_Buffer *pDigest,     // output
            const SNACC::AsnOid &o); // input
                    // THIS version does not lock, but will call CSM_Common.


   CSM_Buffer *EncodeOtherInfo (CSM_Buffer *UKM,
                          char *counter, 
                          const SNACC::AsnOid &alg_OID,
                          long lKekLength);        // Input, for OtherInfo load.
   CSM_Buffer *ComputeSharedInfoKeyDerivationFunction(
            SecByteBlock &ZZ,       // INPUT
            CSM_Buffer *pUKM,       // INPUT
            const SNACC::AsnOid &alg_OID,  // INPUT
            long lKekLength,        // INPUT, for SharedInfo load.                         
            bool bMQVFlag=false);   // INPUT, for special MQV SharedInfo load.
                                //RWC;TBD;MORE TO FOLLOW FOR MQV, need OriginatorPublicKey
                          

   static CryptoPP::Integer *ComputeBigInteger(SNACC::AsnInt &snaccInteger, unsigned int len);

};

void SM_FREE3DLL_API SMFree3Init(CSM_CtilMgr *pCSMIME, char *pszPassword,
                     char *pszAddressBook, char *pszPrefix);


// This global function group was create for convenience to generate
// appropriate logic (with #ifdefs) for the individual Crypto++ libs.
// This makes the code more readable, less #ifdefs sprinkled in code.
long SM_FREE3DLL_API sm_Free3CryptoppDEREncode(const Integer &xInt, 
        unsigned char *ptr, unsigned long len);
Integer SM_FREE3DLL_API *sm_Free3CryptoppBERDecode(const char *ptr, unsigned long len);

_END_CERT_NAMESPACE

#ifdef OPENSSL_PKCS12_ENABLED
extern "C" {
#ifdef _DEBUG      // ONLY in DEBUG mode to avoid security issues.
// This global exported function is intended for diagnostics only; it
//  will decode a PKCS12 file, and export the private key and certificate
//  in the clear in the same directory as the file, returning the cert and
//  clear private key file names.
SM_FREE3DLL_API int DLLSFLExportClearPKCS12(char *pszPassword,char *pszPFXFile,
    char *&lpszCertFile, char *&lpszClearPrivateKey);
#endif //_DEBUG

SM_FREE3DLL_API int DLLSFLCreatePKCS12(char *lpszCertFile, 
    char *lpszClearPrivateKey, char *pszPassword, char *pszPFXFile);
}       // END extern "C"
#endif  //OPENSSL_PKCS12_ENABLED

// THIS macro allows the sm_free3 logic to capture Crypto++ exceptions and 
//  repackage them into SnaccExceptions for consistency.
#ifdef _DEBUG      // ONLY in DEBUG mode to avoid security issues.
#define SME_FREE3_CATCH_FINISH \
      Exception.push(STACK_ENTRY);\
      throw;\
    }\
    catch (CryptoPP::Exception &e)\
    {  char buf[1024];\
       sprintf(buf, "CryptoPP::%s", e.what());\
       throw SNACC::SnaccException(STACK_ENTRY, buf, e.GetErrorType());\
    }
#else  // _DEBUG
#define SME_FREE3_CATCH_FINISH \
      Exception.push(STACK_ENTRY);\
      throw;\
    }\
    catch (CryptoPP::Exception &e)\
    {  char buf[1024];\
       sprintf(buf, "CryptoPP::%s", e.what());\
       throw SNACC::SnaccException(STACK_ENTRY, buf, e.GetErrorType());\
    }\
    catch (...) { SME_THROW(33, "Unexpected exception thrown!", NULL); }
#endif // _DEBUG


#endif // _SM_FREE3_H_

// EOF sm_free3.h
