
#ifndef _SM_PKCS11FREE3_H
#define _SM_PKCS11FREE3_H

#pragma warning( disable : 4018 4146 4661)  //RWC; HOPEFULLY this still works fine...
#include "sm_free3.h"
    using namespace CERT;
    using namespace CTIL;
/*    using namespace SNACC;*/
#include "sm_pkcs11.h"

#ifndef NO_DLL
#ifdef WIN32
///////using namespace CryptoPP;
#ifdef SM_PKCS11FREE3DLL_EXPORTS
#define SM_PKCS11FREE3DLL_API __declspec(dllexport)
#else
#define SM_PKCS11FREE3DLL_API __declspec(dllimport)
#endif
#endif
#else
#define SM_PKCS11FREE3DLL_API
#endif
_BEGIN_CERT_NAMESPACE

////////////////////////////////////////////////////////////////////////////////////
//
// CSM_Pkcs11Free3
//
////////////////////////////////////////////////////////////////////////////////////
//
class SM_PKCS11FREE3DLL_API CSM_Pkcs11Free3 : public CSM_Pkcs11,
                                              public CSM_Free3
{
public :

    CSM_Pkcs11Free3();                      // Default constructor
    CSM_Pkcs11Free3(CSM_Buffer &Certificate,
               CSM_Buffer *pPrivateKey,
               char *pPin,
               CK_SLOT_ID slotId);
    CSM_Pkcs11Free3(CSM_CtilMgr *pCSMIME,
               CK_SLOT_ID slotId,
               char *pUserPin,
               char *pDllName);

   ~CSM_Pkcs11Free3();                  // Destructor
/*
    SM_RET_VAL CreateInstances(CSMIME *pCSMIME, 
                               char *pUserPin, 
                               int slotId);
*/
    SM_RET_VAL SMTI_DigestData(CSM_Buffer *pDataIn, // input
                               CSM_Buffer *pDigestOut); // output

    SM_RET_VAL SMTI_Login();
    SM_RET_VAL SMTI_Sign(CSM_Buffer *pDataIn,
                         CSM_Buffer *pEncryptedDigest,
                         CSM_Buffer *pDigest);

     SM_RET_VAL SMTI_Verify(
       CSM_Buffer *pSignerPublicKey,   // input
       CSM_AlgVDA    *pDigestAlg,         // input
       CSM_AlgVDA    *pSignatureAlg,      // input
       CSM_Buffer *pData,              // input
       CSM_Buffer *pSignature);         // input

     SM_RET_VAL SMTI_Encrypt(
       CSM_Buffer *pData,         // input (data to be encrypted)
       CSM_Buffer *pEncryptedData,// output
       CSM_Buffer *pParameters,   // OUT, for KeyAgree algs.
       CSM_Buffer *pMEK,          // In/output; may be specified.
       CSM_Buffer *pIV=NULL);     // In, to avoid specific
                                  // alg encoding by app.
     SM_RET_VAL SMTI_GenerateEMEK(
       CSM_Buffer *pRecipient,    // input, Y of recip
       CSM_Buffer *pParameters,   // output, parameters for alg.
       CSM_Buffer *pMEK,          // input, MEK or special phrase
       CSM_Buffer *pEMEK,         // output, encrypted MEK
       CSM_Buffer *pUKM,          // output, ukm, if applicable
       CSM_Buffer *pSubjKeyId=NULL); // output, if applicable

     SM_RET_VAL SMTI_ExtractMEK(
       CSM_Buffer *pOriginator,   // input, Y of originator
       CSM_Buffer *pParameters,   // input, parameters for alg.
       CSM_Buffer *pEMEK,         // input, encrypted MEK
       CSM_Buffer *pUKM,          // input
       CSM_Buffer *pMEK);       // output

     SM_RET_VAL SMTI_Decrypt(
       CSM_Buffer *pParameters,   // input, parameters for alg.
       CSM_Buffer *pEncryptedData,// input (data to be decrypted)
       CSM_Buffer *pMEK,          // input (MEK or special phrase)
       CSM_Buffer *pData);         // output (decrypted data)

     SM_RET_VAL SMTI_Random(
       CSM_Buffer *pSeed,         // input
       CSM_Buffer *pRandom,       // input/output
       SM_SIZE_T lLength);      // input

     SM_RET_VAL SMTI_GenerateKeyAgreement(
       CSM_Buffer *pRecipient,    // input, Y of recip
       CSM_Buffer *pParameters,   // IN,OUT may be passed in for shared
                                  //  use OR for ESDH. (p, g, and/or IV).
       CSM_Buffer *pUKM,          // input/output may be passed in for shared
                                  //   use.  UserKeyMaterial (random number).
       CSM_Buffer *pbufferIV,     // input/output may be passed in for
                                  //   shared use. Initialization vector,
                                  //   part of DH params.
       SNACC::AsnOid *pEncryptionOID,   // IN, specified encryption of key,
                                  //   used here in key generation,
                                  //   but alg not implemented.
       CSM_Buffer *pbufKeyAgree,  // output, encryption key for this recip.
       long lKekLength);           // Input, for OtherInfo load.

     SM_RET_VAL SMTI_GenerateKeyWrap(
       CSM_Buffer *pData,         // input (data to be encrypted)
       CSM_Buffer *pEncryptedData,// output
       CSM_Buffer *pParameters,   // OUT, for KeyAgree algs.
       CSM_Buffer *pMEK,          // In/output; may be specified.
       CSM_Buffer *pIV);          // In, to avoid specific
                                  // alg encoding by app.

     CSM_Buffer *SMTI_GenerateKeyWrapIV(
       long &lKekLength,          // OUT, returned algorithm specific length
       CSM_AlgVDA *pWrapAlg=NULL);   // OUT, returned since params are alg

     SM_RET_VAL SMTI_ExtractKeyAgreement(
       CSM_Buffer *pOriginator,   // input, Y of originator
    //       CSM_Buffer *pParameters, // IN,OUT may be passed in for shared
                                  //   use OR for ESDH. (p, g, and/or IV).
       CSM_Buffer *pUKM,          // input/output may be passed in for
                                  //   shared use.  UserKeyMaterial
                                  //   (random number).
       CSM_Buffer *pbufferIV,     // input/output may be passed in for
                                  //   shared use. Initialization vector,
                                  //   part of DH params.
       SNACC::AsnOid *pEncryptionOID,   // IN, specified encryption of key,
                                  //   used here in key generation,
                                  //   but alg not implemented.
       CSM_Buffer *pbufKeyAgree,  // output, encryption key for this recip.
       long lKekLength);          // Output, from OtherInfo load.

     SM_RET_VAL SMTI_ExtractKeyWrap(
       CSM_Buffer *pData,         // Output
       CSM_Buffer *pEncryptedData,// input
       CSM_Buffer *pParameters,   // IN, for KeyAgree algs.
       CSM_Buffer *pTEK,          // output
       CSM_Buffer *pIV);          // In

    // SMTI_Lock and SMTI_Unlock should be used by the calling hilevel
    // member to lock the crypto resource.  This is particularly applicable
    // to Encrypt/GenerateEMEK and ExtractMEK/Decrypt sequences...
     SM_RET_VAL SMTI_Lock() {return -1;}
     SM_RET_VAL SMTI_Unlock(){return -1;}

     bool SMTI_IsKeyAgreement();  // TRUE indicates key agreement
                                          //  encryption, not key transfer.

     void SMTI_DeleteMEK(){};

     void CSM_TokenInterfaceDestroy(){};

    //RWC; added to support E-S DH and public key, no cert features.
     CSM_Buffer *GetDynamicPublicKey(CSM_AlgVDA &Alg) {return NULL;}
                                           // May return Certs or pub key.
     void ClearDynamicKey() { };     // Defaults to do nothing; only
                //  necessary for CTIL algs that generate dynamic keys;
                //   this reset will force generation of a new key.
  //  void LoadParams(CSM_Buffer &IV, CSM_Buffer *pParameters) {};
      CSM_Alg *DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert);
      CSM_AlgVDA *DeriveMsgAlgFromCert(CSM_AlgVDA &Alg)  { return new CSM_AlgVDA(Alg);};


      void LoadExtraOids();
      CSM_Pkcs11 * GetInstancePointer();

private :

    ////////////////////////////////////////////////////////////////////////
    //  private methods
    ////////////////////////////////////////////////////////////////////////

    void Clear ();
};

_END_CERT_NAMESPACE

#endif

// EOF sm_pkcs11Free3.h

