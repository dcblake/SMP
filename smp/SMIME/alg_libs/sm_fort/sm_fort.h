/* @(#) sm_fort.h 1.22 09/26/00 07:13:52 */
// This crypto token library header is usually the only include that the C++
// application needs.  Directly included by the C++ app and the fortezza
// crypto token library.

#ifndef _SM_FORT_H_
#define _SM_FORT_H_


#ifndef SM_FORTEZZADLL
#ifdef WIN32
#ifdef SM_FORTEZZADLL_EXPORTS
#define SM_FORTEZZADLL __declspec(dllexport)
#else
#define SM_FORTEZZADLL __declspec(dllimport)
#endif
#else
#define SM_FORTEZZADLL
#endif
#endif

#include "sm_apiCert.h"
#include "sm_common.h"
#include "cryptint.h"
#include "sm_fortAsn.h"
//namespace CERT {
_BEGIN_CERT_NAMESPACE

#   define KEK_REG         2               /* programmer-defined location */
#   define MEK_REG         3               /* programmer-defined location */
#   define KS_REG          0               /* storage key, K(s), register */

//#ifndef SM_SPEXDLL_EXPORTS
extern "C" 
{
SM_FORTEZZADLL SM_RET_VAL SMFortezzaInit(void *pCSMIME, char *pszPin,
                         long nSocket);
}
//#endif

// error codes specific to the Fortezza CTI
//
// all Fortezza CTI error codes begin with 91000

                                      
#define  FORT_MISSING_PARAMS    91000
#define  FORT_INVALID_PIN_SIZE  91001
#define  FORT_INV_PARM          91002 
#define  FORT_INV_PADSIZE       91003
#define  FORT_UNSUPP_KEY_WRAP   91004
#define  FORT_INV_KEYSIZE       91005
#define  FORT_INV_IV_SIZE       91006
#define  FORT_INV_PIN           91007

// forward declarations
//
class CSM_FortezzaCardInfo;

class CSM_FortDSAParams;

enum LabelType 
{ 
  BADLABEL=-1, // invalid or unrecognized UE 
  V3_KEA=0, // V3 KEA Cert w/ private key 
  V3_DSA,   // V3 DSA Cert w/ private key
  RSA,      // RSA Cert w/ private key
  DH,        // DH Cert w/ private key
  CA_DSA    // CertificateAuthority DSA Key
};



// Generic base class suitable for Fortezza and SPEX CTIL
//
class SM_FORTEZZADLL CSM_FortezzaCardInfo
{
public:
   CSM_FortezzaCardInfo() {Clear();}
   CSM_FortezzaCardInfo(int nSocket);

   ~CSM_FortezzaCardInfo()
   { 
      free(mp_perList); 
   }
   
   void FirstSlot() // set current slot to 1st slot
       { m_currIndex = 0; }

   void LastSlot()  // set current slot to last slot
       { m_currIndex = m_config.CertificateCount; }

   SM_RET_VAL NextSlot();  // one up the current slot
   SM_RET_VAL GetSlot();   // get the current slot
   SM_RET_VAL ParentSlot(); // set current slot to parent
                            // of current slot
   SM_RET_VAL SetSlot(int nSlot); // set current slot to nSlot
   long       SetSocket(int socket);
   long       SetSocketNoOpen(int nSocket);
   long       GetSocket(void) { return m_nSocket; }
   long       GetSiblingIndex(void);
   long       GetLargestBlockSize(void) { return m_config.LargestBlockSize;}

   LabelType  GetUE(void); // return current UE
   char *     AccessLabel(void)
   { return (char *) &mp_perList[m_currIndex].CertLabel[8];}

   SM_RET_VAL GetUserPath(CSM_BufferLst *&pBufferLst, 
     int nUserSlot,
     bool rootFlag);

   SM_RET_VAL GetCertificate( CSM_Buffer &pBuffer );

//   CSM_FortezzaCardInfo * operator=(CSM_FortezzaCardInfo &o);
   void Set(const CSM_FortezzaCardInfo &o);

private:
   CI_PERSON *mp_perList;  // Personality List from certs on card
   int        m_currIndex; // current index into personality list
   CI_CONFIG  m_config;    // that can be passed to a 
   int        m_nSocket;

   void LoadPersonalities(void);
   void Clear(void);

protected:

   char * GetCertLabel(void);
};

class SM_FORTEZZADLL CSM_Fortezza : public CSM_Common
{
public:
   // -----------  CONSTRUCTORS ------------------
   
  
   // This constructor will login to the fortezza
   // card and load pCSMIME an instance for each
   // DSA and KEA certificate on the card.
   //
   CSM_Fortezza          (CSM_CtilMgr/*CSMIME*/ *pCSMIME,
                          char          *pszPin,
                          long           nSocket);
   CSM_Fortezza          (CSM_CtilMgr/*CSMIME*/ *pCSMIME, 
                          long    nSocket, 
                          long    slot);

   // Default constructor.  Not sure if I need 
   // this.
   //
   CSM_Fortezza();

   CSM_Fortezza(CSM_FortezzaCardInfo &o);
   ~CSM_Fortezza(){ if (mp_cardInfo) delete mp_cardInfo; }
   void CSM_TokenInterfaceDestroy() 
   {    delete this;  
   }

   void InitMemberVariables(void);

   /* Open socket, store socket count, get card configuration
    */
   SM_RET_VAL InitCard(long nSocket);


   // -------- VIRTUAL FUNCTION OVERRIDES ---------

   SM_RET_VAL SMTI_Sign  (CSM_Buffer *pData, // input
                          CSM_Buffer *pEncryptedDigest, // output
                          CSM_Buffer *pDigest); // output

   SM_RET_VAL SMTI_Verify(CSM_Buffer *pSignerPublicKey, // input
                          CSM_AlgVDA    *pDigestAlg,  // input
                          CSM_AlgVDA    *pSignatureAlg, // input
                          CSM_Buffer *pData, // input
                          CSM_Buffer *pSignature); // input
   SM_RET_VAL SMTI_VerifyFORTEZZA(CSM_Buffer *pSignerPublicKey, // input
                          CSM_AlgVDA    *pDigestAlg,  // input
                          CSM_AlgVDA    *pSignatureAlg, // input
                          CSM_Buffer *pData, // input
                          CSM_Buffer *pSignature); // input

   SM_RET_VAL SMTI_Encrypt(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV=NULL);  // In, to avoid specific
   SM_RET_VAL SMTI_EncryptFORTEZZA(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV=NULL);  // In, to avoid specific
  
   SM_RET_VAL SMTI_Decrypt(
            CSM_Buffer *pParameters,    // input, parameters for alg.
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK,           // input (MEK or special phrase)
            CSM_Buffer *pData);      // output (decrypted data)
   SM_RET_VAL SMTI_DecryptFORTEZZA(
            CSM_Buffer *pParameters,    // input, parameters for alg.
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK,           // input (MEK or special phrase)
            CSM_Buffer *pData);      // output (decrypted data)

   // PIERCE used the SMTI_DigestData from sm_common
   //
   // SM_RET_VAL SMTI_DigestData(
   //         CSM_Buffer *pData, // input
   //         CSM_Buffer *pDigest); // output

   SM_RET_VAL CSM_Fortezza::SMTI_Random(
            CSM_Buffer *pSeed,
            CSM_Buffer *pRandom,
            SM_SIZE_T lLength);

   
   // stubbed out
   SM_RET_VAL SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // input, parameters for alg.
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // output, ukm, if applicable
            CSM_Buffer *pSubjKeyId); // output
   
   SM_RET_VAL SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input, parameters for alg.
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK); // output

   CSM_Buffer *SMTI_GenerateKeyWrapIV(
           long &lKekLength,       // OUT, returned algorithm specific length
           CSM_AlgVDA *pWrapAlg=NULL); // OUT, returned since params are alg
   
 
   SM_RET_VAL SMTI_GenerateKeyWrap(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV);            // In, to avoid specific
                                        // alg encoding by app.
   SM_RET_VAL SMTI_ExtractKeyWrap(
            CSM_Buffer *pData,          // Output
            CSM_Buffer *pEncryptedData, // input
            CSM_Buffer *pParameters,    // IN, for KeyAgree algs.
            CSM_Buffer *pTEK,           // output
            CSM_Buffer *pIV);           // In

   SM_RET_VAL SMTI_GenerateKeyAgreement(
            CSM_Buffer *pRecipient,    // input, Y of recip
            CSM_Buffer *pParameters,   // IN,OUT may be passed in for shared
                                       //  use OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM,     // input/output may be passed in for shared
                                  //   use.  UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,     // input/output may be passed in for
                                       //   shared use. Initialization vector,
                                       //   part of DH params.
            SNACC::AsnOid *pEncryptionOID,   // IN, specified encryption of key,
                                       //   used here in key generation,
                                       //   but alg not implemented.
            CSM_Buffer *pbufKeyAgree,  // output, encryption key for this recip.
            long lKekLength);           // Input, for OtherInfo load.

   SM_RET_VAL SMTI_ExtractKeyAgreement(
            CSM_Buffer *pOriginator,   // input, Y of originator
            CSM_Buffer *pUKM,          // input/output may be passed in for shared use.
                                       //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,     // input/output may be passed in for
                                       //   shared use. Initialization vector,
                                       //   part of DH params.
            SNACC::AsnOid *pEncryptionOID,   // IN, specified encryption of key,
                                       //   used here in key generation,
                                       //   but alg not implemented.
            CSM_Buffer *pbufKeyAgree,  // output, encryption key for this recip.
            long lKekLength);           // Output, from OtherInfo load.

   void SMTI_DeleteMEK(); // DELETE key explicitely, not just on 
                                        //   next message.

   bool SMTI_IsKeyAgreement() { return true; }

   CSM_Alg * DeriveMsgAlgFromCert(CSM_CertificateChoice &cert);

   // ----------  MEMBER FUNCTIONS
   //

   SM_RET_VAL   GetParams(CSM_Buffer *&pParamsBuf);
   CSM_Buffer * GetEncodedPublicKey(void);
   CSM_Buffer * DecodePublicKey(CSM_Buffer *pEncodedPubKey);
   SM_RET_VAL   Login(char *pszPin);
   CSM_CSInst * SelectInstance(CSM_CtilMgr/*CSMIME*/ *pCSMIME, long nSignerIndex);

   // ----------MEMBER ACCESS FUNCTIONS -----------
 
   // This sets index (aka Personality) to be used
   // for digitial signatures.
   //
   void  SetSignerIndex(long nIndex)
   { m_nSignerIndex = nIndex; }

   // This sets index used for encryption.
   //
   void  SetEncryptorIndex(long nIndex)
   { m_nEncryptorIndex = nIndex; }

   long GetSignerIndex(void)
   { return m_nSignerIndex; }

   long GetEncryptorIndex(void)
   { return m_nEncryptorIndex; }

   int GetSocketCount(void);

   long SetSocket(int nSocket);
   long SetSocketNoOpen(int nSocket);

   SM_RET_VAL CreateInstances(CSM_CtilMgr/*CSMIME*/ *pCSMIME, int iSlot=-1);

//private:
//   int   m_nSignerIndex;
//   int   m_nEncryptorIndex;

protected:
   int   m_nSignerIndex;
   int   m_nEncryptorIndex;

   CSM_FortezzaCardInfo *mp_cardInfo;

   bool bWeInitialized; // Flag to indicate that this module initialized
                        //  the Fortezza card (to know if we should close).

   void BlockEncryption(CSM_Buffer *pData, CSM_Buffer *pEncryptedData);
   void BlockDecryption(CSM_Buffer *pEncryptedData, CSM_Buffer *pData);
   SM_RET_VAL GetUserPath(CSM_BufferLst *pUserPath);
   void GeneratePad(CSM_Buffer &data, const int padSize);
   void ExtractPad(CSM_Buffer &data);
   void SetKeyEncryptionOids(void);
   void SetContentEncryptionOids(void);
   void SetDigestEncryptionOids(void);
   void SetDigestOids(void);
 
};


// These classes are for handling Fortezza specific stuff within
// X.509 objects.

class SM_FORTEZZADLL CSM_FortDSAParams
{
    public: 
       char       *P;
       char       *Q;
       char       *G;
   
       CSM_FortDSAParams();
       ~CSM_FortDSAParams();
       SM_RET_VAL Decode(CSM_Buffer *pParams);
          
};


#define DSA_R_SIZE 20
#define DSA_S_SIZE 20

class SM_FORTEZZADLL CSM_DSASignatureValue : public SNACC::DSASignatureValue
{
private:
   SNACC::AsnInt mFixedR;
   SNACC::AsnInt mFixedS;
public:

   CSM_DSASignatureValue();
   CSM_DSASignatureValue(CSM_Buffer *asnSigValue);
   void Decode(CSM_Buffer *sigValue);
   void Encode(CSM_Buffer *sigValue);
   void SetRS(const char *buf);
   char * GetRS(void);  // return R & S concatenated
};

_END_CERT_NAMESPACE
//}

#endif // _SM_FORT_H_

// EOF sm_fort.h

