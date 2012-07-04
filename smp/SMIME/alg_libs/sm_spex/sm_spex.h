/* @(#) sm_spex.h 1.9 06/15/00 12:09:38 */

#ifndef _SM_SPEX_H_
#define _SM_SPEX_H_

#include "LynksApi.h"
#include "sm_fort.h"
_BEGIN_CERT_NAMESPACE

#ifdef WIN32
#ifdef SM_SPEXDLL_EXPORTS
#define SM_SPEXDLL_API __declspec(dllexport)
#else
#define SM_SPEXDLL_API __declspec(dllimport)
#endif
#else
#define SM_SPEXDLL_API
#endif

#define SM_SPEX_PARAM_DECODE_ERROR  50000

extern "C"
{
SM_RET_VAL SM_SPEXDLL_API SMSPEXInit(void *pCtilMgr, char *pszPin,
                      long nSocket);
}

// forward declaration
//
class CSM_SPEXCardInfo;

class SM_SPEXDLL_API CSM_SPEX : public CSM_Fortezza
{
public:
   // -----------  CONSTRUCTORS ------------------
   
  
   // This constructor will login to the fortezza
   // card and load pCtilMgr an instance for each
   // DSA and KEA certificate on the card.
   //
   CSM_SPEX (CTIL::CSM_CtilMgr *pCtilMgr,
             char        *pszPin,
             long        nSocket);

   // Default constructor.  Not sure if I need 
   // this.
   //
   CSM_SPEX();

   CSM_SPEX(CSM_FortezzaCardInfo &o) : CSM_Fortezza(o)
   {
     SetDefaultOids();
     m_hashMode = 0;
   };

   // -------- CSM_Fortezza member function overrides -----

   SM_RET_VAL SMTI_Sign  (CSM_Buffer *pData, // input
                          CSM_Buffer *pEncryptedDigest, // output
                          CSM_Buffer *pDigest); // output

   SM_RET_VAL SMTI_Verify(CSM_Buffer *pSignerPublicKey, // input
                    CSM_AlgVDA    *pDigestAlg,  // input
                    CSM_AlgVDA    *pSignatureAlg, // input
                          CSM_Buffer *pData, // input
                          CSM_Buffer *pSignature); // input

   SM_RET_VAL SMTI_DigestData(
           CSM_Buffer *pData, // input
           CSM_Buffer *pDigest); // output
   SM_RET_VAL SMTI_DigestDataSPEX(
           CSM_Buffer *pData, // input
           CSM_Buffer *pDigest); // output

   SM_RET_VAL SMTI_Encrypt(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV=NULL);  // In, to avoid specific
   SM_RET_VAL SMTI_EncryptSPEX(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV);       // In, to avoid specific
  
   SM_RET_VAL SMTI_Decrypt(
            CSM_Buffer *pParameters,    // input, parameters for alg.
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK,           // input (MEK or special phrase)
            CSM_Buffer *pData);      // output (decrypted data)
   SM_RET_VAL SMTI_DecryptSPEX(
            CSM_Buffer *pParameters,    // input, parameters for alg.
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK,           // input (MEK or special phrase)
            CSM_Buffer *pData);      // output (decrypted data)

   SM_RET_VAL SMTI_Random(
            CSM_Buffer *pSeed,
            CSM_Buffer *pRandom,
            SM_SIZE_T lLength);

   
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

   bool SMTI_IsKeyAgreement() { return false; }
   CSM_AlgVDA *DeriveMsgAlgFromCert(CSM_AlgVDA &Alg);


private:
   CSM_SPEXCardInfo *mp_cardInfo;  
   long m_hashMode;
   bool m_hashModeLock;
  
   
   void LockHashMode() { m_hashMode = 0; m_hashModeLock = true; }
   void UnLockHashMode() { m_hashMode = 0; m_hashModeLock = false; }

 //  SM_RET_VAL Login(char *pszPin);
   SM_RET_VAL CreateInstances(CTIL::CSM_CtilMgr *pCtilMgr); // override Fortezza

   bool       IsAlgSupported(const SNACC::AsnOid &oid, long algType);
   void       SetMode(const SNACC::AsnOid &oid, long modeType, long &mode);

protected:
   void       SetDefaultOids(void); // override Fortezza
   void       BlockDigest(CSM_Buffer *pData, CSM_Buffer *pHashValue);

};

class SM_SPEXDLL_API CSM_SPEXCardInfo : public CSM_FortezzaCardInfo
{
public:
   CSM_SPEXCardInfo() {};

   LabelType  GetUE(void);
};
   
_END_CERT_NAMESPACE

#endif // _SM_SPEX_H_


// EOF sm_spex.h