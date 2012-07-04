
#ifndef _SM_PKCS11_H
#define _SM_PKCS11_H

#include "cryptoki.h"

#include "sm_apiCert.h"
#include "sm_common.h"
#include "sm_pkcs11Functions.h"
_BEGIN_CERT_NAMESPACE

#ifndef NO_DLL
#ifdef WIN32
#ifdef SM_PKCS11DLL_EXPORTS
#define SM_PKCS11DLL_API __declspec(dllexport)
#else
#define SM_PKCS11DLL_API __declspec(dllimport)
#endif  //SM_PKCS11DLL_EXPORTS
#else   //WIN32
#define SM_PKCS11DLL_API
#endif   //WIN32
#endif   //NO_DLL

/* and using the following preprocessor directive after including
 * pkcs11.h or pkcs11t.h:
 */
#ifdef WIN32
#pragma pack(pop, cryptoki)
#endif

// Pkcs11 error messages
#define SM_PKCS11_TOKEN_SELECT_ERROR        23000
#define SM_PKCS11_INITIALIZE_ERROR          23001
#define SM_PKCS11_SLOT_LIST_ERROR           23002
#define SM_PKCS11_NO_SLOTS_ERROR            23003
#define SM_PKCS11_SLOT_COUNT_ERROR          23004
#define SM_PKCS11_OPEN_SESSION_ERROR        23005
#define SM_PKCS11_LOGIN_ERROR               23006
#define SM_PKCS11_MISSING_PIN               23007
#define SM_PKCS11_INIT_PIN_ERROR            23008
#define SM_PKCS11_SIGN_ERROR                23009
#define SM_PKCS11_ENCRYPT_ERROR             23010
#define SM_PKCS11_DIGEST_ERROR              23011
#define SM_PKCS11_MECHANISM_COUNT_ERROR     23012
#define SM_PKCS11_GET_MECH_INFO_ERROR       23013
#define SM_PKCS11_UNSUPPORTED_ALG           23014
#define SM_PKCS11_OBJ_ERROR                 23015
#define SM_PKCS11_SFL_UNSUPPORTED_MECH      23016
#define SM_PKCS11_UNKNOWN_OBJECT_TYPE       23017
#define SM_PKCS11_CERT_ERROR                23018
#define SM_PKCS11_KEY_ERROR                 23019
#define SM_PKCS11_MISSING_PARAM             23020
#define SM_PKCS11_VERIFY_ERROR              23021
#define SM_PKCS11_GENERATE_KEY_ERROR        23022
#define SM_PKCS11_UNWRAP_KEY_ERROR          23023
#define SM_PKCS11_WRAP_KEY_ERROR            23024
#define SM_PKCS11_DERIVE_KEY_ERROR          23025
#define SM_PKCS11_DECRYPT_ERROR             23026
#define SM_PKCS11_GEN_RANDOM_NOT_AVAIL      23027
#define SM_PKCS11_FUNCTION_NOT_AVAIL        23028
#define SM_PKCS11_NONE_UNIQUE_PRIV_KEY      23029
#define SM_PKCS11_NO_PRIVATE_KEY            23030

// Definitions for object creation
#define SM_PKCS11_ENCRYPT_KEY          1
#define SM_PKCS11_DECRYPT_KEY          2
#define SM_PKCS11_SIGN_KEY             3
#define SM_PKCS11_VERIFY_KEY           4
#define SM_PKCS11_CERTIFICATE          5

#define SM_PKCS11_INVALID_HANDLE       (unsigned long)-1

// Fortezza-like parameters
#define SM_PKCS11_CI_RA_SIZE            128
#define SM_PKCS11_CI_RB_SIZE            SM_PKCS11_CI_RA_SIZE
#define SM_PKCS11_SKIPJACK_CONST_STRING "THIS IS NOT LEAF"

#define SM_PKCS11_CBC64_PADDING           8
#define SM_PKCS11_SKIPJACK_IV_LEN         8

#define SM_PKCS11_BUFFER_SIZE             65535

typedef unsigned char   SM_PKCS11_CI_RA[SM_PKCS11_CI_RA_SIZE];
typedef unsigned char   SM_PKCS11_CI_RB[SM_PKCS11_CI_RB_SIZE];

class CSM_Pkcs11Slot;
class CSM_Pkcs11MechanismInfo;
class CSM_Pkcs11;

typedef List<CSM_Pkcs11Slot> CSM_Pkcs11SlotLst;
typedef List<CSM_Pkcs11MechanismInfo> CSM_Pkcs11MechanismInfoLst;

////////////////////////////////////////////////////////////////////////////////////
//
// CSM_Pkcs11
//
////////////////////////////////////////////////////////////////////////////////////
class SM_PKCS11DLL_API CSM_Pkcs11 : virtual public CSM_Common
{
public :

    CSM_Pkcs11();                      // Default constructor
    CSM_Pkcs11(CSM_Buffer &Certificate,
               CSM_Buffer *pPrivateKey,
               char *pPin,
               CK_SLOT_ID slotId);
    CSM_Pkcs11(CSM_CtilMgr *pCSMIME,
               CK_SLOT_ID slotId,
               char *pUserPin,
               char *pDllName);

    virtual ~CSM_Pkcs11();                  // Destructor

    void SetPin (char *pPin);
    void SetUserType (CK_USER_TYPE userType) {m_userType = userType;}
    void GeneratePad(CSM_Buffer &data, const int padSize);
    void ExtractPad(CSM_Buffer &data);

    CK_SLOT_ID AccessSlotId() {return m_slotId;}
    CK_BYTE_PTR AccessId() {return m_pId;}

    CSM_CertificateChoice * AccessCertificateChoice() {return m_pCertificateChoice;}

    SM_RET_VAL SetCertificate(CSM_Buffer &bufferCert);
    SM_RET_VAL SetCertificate(CK_OBJECT_HANDLE hObject);
    SM_RET_VAL SetCertificate(SNACC::Certificate &snaccCert);

    CK_BYTE_PTR AccessSubject() {return m_pSubject;}
    void SetSubject(CK_BYTE_PTR pSubject) {m_pSubject = (CK_BYTE_PTR)strdup((const char *)pSubject);}

    void SetDefaultOIDs();
    bool IsOidSupported(SNACC::AsnOid oid);

    SM_RET_VAL SMTI_Login();
    SM_RET_VAL SMTI_Sign(CSM_Buffer *pDataIn,
                         CSM_Buffer *pEncryptedDigest,
                         CSM_Buffer *pDigest);
    SM_RET_VAL SMTI_DigestData(CSM_Buffer *pDataIn, // input
                               CSM_Buffer *pDigestOut); // output

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
     SM_RET_VAL SMTI_GetStatus();

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
     CSM_Alg *DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert);
  //  void LoadParams(CSM_Buffer &IV, CSM_Buffer *pParameters) {};
    CSM_AlgVDA *DeriveMsgAlgFromCert(CSM_AlgVDA &Alg);

    static CK_BBOOL Pkcs11LibIsInitialized;
   
    virtual void LoadExtraOids() {};
    virtual CSM_Pkcs11 * GetInstancePointer ();
    void sm_PKCS11_DUMP();
    void sm_PKCS11_DUMP_Attributes(CK_OBJECT_HANDLE hObject);
    int  sm_PKCS11_DUMP_GET_Attribute(CK_OBJECT_HANDLE hObject, 
        CK_ATTRIBUTE_TYPE lType, CK_VOID_PTR &pValue, CK_ULONG &ulValueLen, 
        char *pszType=NULL);

protected :

    void Clear ();
    void LoadDllFunctions(char *pDllName);
    void SetDllFunctions(CSM_Pkcs11 *);
    SM_RET_VAL Initialize ();
    SM_RET_VAL LoadSlotList ();
    SM_RET_VAL ProcessSlotList (CK_SLOT_ID_PTR, CK_ULONG);
    SM_RET_VAL SelectToken(CK_SLOT_ID_PTR);

    SM_RET_VAL CreateInstances (CSM_CtilMgr *pCSMIME, 
                        char *pUserPin, 
                        int slotId);

    CK_MECHANISM_PTR GetMechanismStruct(SNACC::AsnOid *pOid);
    CK_MECHANISM_INFO_PTR GetMechanismInfo(SNACC::AsnOid *pOid);

    SM_RET_VAL SetSlot(CK_SLOT_ID slotId);
    void SetSlotLst(CSM_Pkcs11SlotLst *pSlotList);
    void SetSession (CK_SESSION_HANDLE hSession) {m_hSession = hSession;}
    SM_RET_VAL SetPrivateKey();

    SM_RET_VAL SetAlgsAndOids();

    SM_RET_VAL DecodeRSAPublicKey(CSM_Buffer *pPublicKey,
                                          CK_BYTE_PTR &pModulus,
                                          CK_ULONG &ulModulusLen,
                                          CK_BYTE_PTR &pExponent,
                                          CK_ULONG &ulExponentLen);

    // The following set of methods are wrappers to all the PKCS11
    // function calls made in this class.

    SM_RET_VAL Initialize(CK_VOID_PTR pReserved);

    SM_RET_VAL GetSlotList(CK_BBOOL tokenPresent, 
                       CK_SLOT_ID_PTR &pSlotList, 
                       CK_ULONG &ulCount);

    SM_RET_VAL Login (CK_SESSION_HANDLE hSession,
                 CK_USER_TYPE userType,
                 CK_CHAR_PTR pPin,
                 CK_ULONG ulPinLen);

    SM_RET_VAL CreateObject (CK_SESSION_HANDLE hSession,
                        CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG ulAttributeCount,
                        CK_OBJECT_HANDLE &hObject);

    SM_RET_VAL FindObjects(CK_SESSION_HANDLE hSession,
                      CK_ATTRIBUTE_PTR pTemplate,
                      CK_ULONG ulAttributeCount,
                      CK_ULONG ulMaxObjectCount,
                      CK_ULONG &ulObjectCount,
                      CK_OBJECT_HANDLE_PTR &phObject);

    SM_RET_VAL GetAttributeValue (CK_SESSION_HANDLE hSession,
                             CK_OBJECT_HANDLE hObject,
                             CK_ATTRIBUTE_PTR pTemplate,
                             CK_ULONG ulAttributeCount);

    SM_RET_VAL Verify (CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hObject,
                  CK_BYTE_PTR pDigestData,
                  CK_ULONG ulDigestLen,
                  CK_BYTE_PTR pSignatureData,
                  CK_ULONG ulSignatureLen);

    SM_RET_VAL Digest (CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_BYTE_PTR pData, 
                  CK_ULONG ulDataLen, 
                  CSM_Buffer *&pDigest, 
                  CK_ULONG &ulDigestLen);

    SM_RET_VAL Sign (CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR pMechanism,
                 CK_OBJECT_HANDLE hSigningKey,
                 CK_BYTE_PTR pData,
                 CK_ULONG ulDataLen,
                 CSM_Buffer *&pSignedData,
                 CK_ULONG &ulSignedDataLen);

    SM_RET_VAL Encrypt (CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism,
                   CK_OBJECT_HANDLE hEncryptKey,
                   CK_BYTE_PTR pData,
                   CK_ULONG ulDataLen,
                   CSM_Buffer *&pEncryptedData,
                   CK_ULONG &ulEncryptedDataLen);

    SM_RET_VAL Decrypt (CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pmechanism,
                   CK_OBJECT_HANDLE hDecryptKey,
                   CK_BYTE_PTR pData,
                   CK_ULONG ulDataLen,
                   CSM_Buffer *&pDecryptedData,
                   CK_ULONG &ulDecryptedDataLen);

    SM_RET_VAL OpenSession (CK_SLOT_ID,
                       CK_FLAGS,
                       CK_NOTIFY,
                       CK_VOID_PTR,
                       CK_SESSION_HANDLE_PTR);

    SM_RET_VAL GenerateRandom (CK_SESSION_HANDLE,
                          CK_BYTE_PTR,
                          CK_ULONG);

    SM_RET_VAL GenerateKey (CK_SESSION_HANDLE,
                        CK_MECHANISM_PTR,
                        CK_ATTRIBUTE_PTR,
                        CK_ULONG,
                        CK_OBJECT_HANDLE_PTR);

    SM_RET_VAL DeriveKey (CK_SESSION_HANDLE hSession,
                     CK_MECHANISM_PTR pMechanism,
                     CK_OBJECT_HANDLE hKey, 
                     CK_ATTRIBUTE_PTR pAttribute,
                     CK_ULONG ulAttributeCount,
                     CK_OBJECT_HANDLE_PTR phKey);

    SM_RET_VAL WrapKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hWrappingKey,
                  CK_OBJECT_HANDLE hKey,
                  CK_BYTE_PTR &pWrappedKey,
                  CK_ULONG_PTR ulWrappedKeyLen);

    SM_RET_VAL UnwrapKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechansim,
                    CK_OBJECT_HANDLE hUnWrappingKey,
                    CK_BYTE_PTR pWrappedKey,
                    CK_ULONG ulWrappedKeyLen,
                    CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG  ulAttributeCount,
                    CK_OBJECT_HANDLE_PTR phKey);

    //////////////////////////////////////////////////////////////////


    ////////////////////////////////////////////////////////////////////////
    //  private members
    ////////////////////////////////////////////////////////////////////////

    CSM_CertificateChoice *m_pCertificateChoice;

    CK_SLOT_ID m_slotId;            // Slot selected for crypto operations.
    CK_SESSION_HANDLE m_hSession;   // Session assigned to this instance
    CK_USER_TYPE m_userType;
    CK_OBJECT_HANDLE m_hPinObject;       // Handle to User Pin to access token

    CK_BYTE_PTR m_pId;  // m_pId is used to store the CKA_ID attribute.  This 
                        // Attribute is intended as means of ditinguishing 
                        // multiple public-key/private-key pairs held by
                        // the same subject.  Since the keys are distinguished by 
                        // subject name as well as identifier, it is possible that 
                        // keys for different subjects may have the same CKA_ID 
                        // value.  NOTE: Cryptoki does NOT enforce this 
                        // association; in particular, an application may leave 
                        // the key identifier empty.

    CK_ULONG m_idLen;

    CK_BYTE_PTR m_pSubject;
    CK_ULONG m_subjectLen;

    CK_BYTE_PTR m_pLabel;
    CK_ULONG m_labelLen;

    CK_OBJECT_HANDLE m_hCertificate;
    CK_OBJECT_HANDLE m_hPrivateKey;
    CK_OBJECT_HANDLE m_hSecretKey;

    CSM_Pkcs11Slot *m_pSlot;               // Slot associated to instance
    /*static */ CSM_Pkcs11SlotLst *m_pSlotList;

   char  *m_pPkcs11DllName;
   void  *pkcs11LibHandle;

   SFL_C_Initialize sfl_c_initialize;
   SFL_C_Finalize sfl_c_finalize;
   SFL_C_GetInfo sfl_c_getInfo;
   SFL_C_GetFunctionList sfl_c_getFunctionList;
   SFL_C_GetSlotList sfl_c_getSlotList;
   SFL_C_GetSlotInfo sfl_c_getSlotInfo;
   SFL_C_GetTokenInfo sfl_c_getTokenInfo;

   SFL_C_GetMechanismList sfl_c_getMechanismList;
   SFL_C_GetMechanismInfo sfl_c_getMechanismInfo;
   SFL_C_InitToken sfl_c_initToken;
   SFL_C_InitPIN sfl_c_initPIN;
   SFL_C_SetPIN sfl_c_setPIN;
   SFL_C_OpenSession sfl_c_openSession;
   SFL_C_CloseSession sfl_c_closeSession;
   SFL_C_CloseAllSessions sfl_c_closeAllSessions;
   SFL_C_GetSessionInfo sfl_c_getSessionInfo;
   SFL_C_GetOperationState sfl_c_getOperationState;
   SFL_C_SetOperationState sfl_c_setOperationState;
   SFL_C_Login sfl_c_login;
   SFL_C_Logout sfl_c_logout;
   SFL_C_CreateObject sfl_c_createObject;
   SFL_C_CopyObject sfl_c_copyObject;
   SFL_C_DestroyObject sfl_c_destroyObject;
   SFL_C_GetObjectSize sfl_c_getObjectSize;
   SFL_C_GetAttributeValue sfl_c_getAttributeValue;
   SFL_C_SetAttributeValue sfl_c_setAttributeValue;
   SFL_C_FindObjectsInit sfl_c_findObjectsInit;
   SFL_C_FindObjects sfl_c_findObjects;
   SFL_C_FindObjectsFinal sfl_c_findObjectsFinal;
   SFL_C_EncryptInit sfl_c_encryptInit;
   SFL_C_Encrypt sfl_c_encrypt;
   SFL_C_EncryptUpdate sfl_c_encryptUpdate;
   SFL_C_EncryptFinal sfl_c_encryptFinal;
   SFL_C_DecryptInit sfl_c_decryptInit;
   SFL_C_Decrypt sfl_c_decrypt;
   SFL_C_DecryptUpdate sfl_c_decryptUpdate;
   SFL_C_DecryptFinal sfl_c_decryptFinal;
   SFL_C_DigestInit sfl_c_digestInit;
   SFL_C_Digest sfl_c_digest;
   SFL_C_DigestUpdate sfl_c_digestUpdate;
   SFL_C_DigestKey sfl_c_digestKey;
   SFL_C_DigestFinal sfl_c_digestFinal;
   SFL_C_SignInit sfl_c_signInit;
   SFL_C_Sign sfl_c_sign;
   SFL_C_SignUpdate sfl_c_signUpdate;
   SFL_C_SignFinal sfl_c_signFinal;
   SFL_C_SignRecoverInit sfl_c_signRecoverInit;
   SFL_C_SignRecover sfl_c_signRecover;
   SFL_C_VerifyInit sfl_c_verifyInit;
   SFL_C_Verify sfl_c_verify;
   SFL_C_VerifyUpdate sfl_c_verifyUpdate;
   SFL_C_VerifyFinal sfl_c_verifyFinal;
   SFL_C_VerifyRecoverInit sfl_c_verifyRecoverInit;
   SFL_C_VerifyRecover sfl_c_verifyRecover;
   SFL_C_DigestEncryptUpdate sfl_c_digestEncryptUpdate;
   SFL_C_DecryptDigestUpdate sfl_c_decryptDigestUpdate;
   SFL_C_SignEncryptUpdate sfl_c_signEncryptUpdate;
   SFL_C_DecryptVerifyUpdate sfl_c_decryptVerifyUpdate;
   SFL_C_GenerateKey sfl_c_generateKey;
   SFL_C_GenerateKeyPair sfl_c_generateKeyPair;
   SFL_C_WrapKey sfl_c_wrapKey;
   SFL_C_UnwrapKey sfl_c_unwrapKey;
   SFL_C_DeriveKey sfl_c_deriveKey;
   SFL_C_SeedRandom sfl_c_seedRandom;
   SFL_C_GenerateRandom sfl_c_generateRandom;
   SFL_C_GetFunctionStatus sfl_c_getFunctionStatus;
   SFL_C_CancelFunction sfl_c_cancelFunction;
};
////////////////////////////////////////////////////////////////////////////////////
//
// CSM_Pkcs11Slot
//
////////////////////////////////////////////////////////////////////////////////////
class SM_PKCS11DLL_API CSM_Pkcs11Slot
{
public :
    CSM_Pkcs11Slot();
    CSM_Pkcs11Slot(CK_SLOT_ID);
    ~CSM_Pkcs11Slot();

    SM_RET_VAL LoadMechanisms ();
    void SetDllFunctions(SFL_C_GetSlotList,
                         SFL_C_GetSlotInfo,
                         SFL_C_GetTokenInfo,
                         SFL_C_GetMechanismInfo,
                         SFL_C_GetMechanismList);

    void SetSlotId (CK_SLOT_ID);
    CK_SLOT_ID AccessSlotId () {return m_slotId;}
    CK_SLOT_INFO GetSlotInfo ();
    CK_TOKEN_INFO GetTokenInfo ();

    CSM_Pkcs11MechanismInfoLst * AccessMechanismLst() {return m_pMechanismInfoLst;}

    CSM_AlgLstVDA *AccessDigestAlgLst() {return m_pDigestAlgLst;}
    CSM_AlgLstVDA *AccessDigestEncryptionAlgLst () {return m_pDigestEncryptionAlgLst;}
    CSM_AlgLstVDA *AccessKeyEncryptionAlgLst () {return m_pKeyEncryptionAlgLst;}
    CSM_AlgLstVDA *AccessContentEncryptionAlgLst () {return m_pContentEncryptionAlgLst;}

    SM_RET_VAL SetDigestAlgLst (CSM_Alg *pDigestAlg);
    SM_RET_VAL SetDigestEncryptionAlgLst (CSM_Alg *pDigestEncryptionAlg);
    SM_RET_VAL SetKeyEncryptionAlgLst (CSM_Alg *pKeyEncryptionAlg);
    SM_RET_VAL SetContentEncryptionAlgLst (CSM_Alg *pContentEncryptionAlg);

private:

    ////////////////////////////////////////////////////////////////////
    // private methods
    ////////////////////////////////////////////////////////////////////

    void Clear();
    void SetSlotAlgLst();


    SM_RET_VAL ProcessMechanismList(CK_MECHANISM_TYPE_PTR,
                                    CK_ULONG mechanismCount);

    ////////////////////////////////////////////////////////////////////
    // private variables
    ////////////////////////////////////////////////////////////////////

    CK_SLOT_ID m_slotId;

    CSM_Pkcs11MechanismInfoLst *m_pMechanismInfoLst;

    CSM_AlgLstVDA *m_pDigestAlgLst;
    CSM_AlgLstVDA *m_pDigestEncryptionAlgLst;
    CSM_AlgLstVDA *m_pKeyEncryptionAlgLst;
    CSM_AlgLstVDA *m_pContentEncryptionAlgLst;

   SFL_C_GetSlotList sfl_c_getSlotList;
   SFL_C_GetSlotInfo sfl_c_getSlotInfo;
   SFL_C_GetTokenInfo sfl_c_getTokenInfo;
   SFL_C_GetMechanismInfo sfl_c_getMechanismInfo;
   SFL_C_GetMechanismList sfl_c_getMechanismList;
};
////////////////////////////////////////////////////////////////////////////////////
//
// CSM_Pkcs11MechanismInfo
//
////////////////////////////////////////////////////////////////////////////////////
class SM_PKCS11DLL_API CSM_Pkcs11MechanismInfo
{
public:
    CSM_Pkcs11MechanismInfo();
    ~CSM_Pkcs11MechanismInfo();

    void SetDllFunctions(SFL_C_GetMechanismInfo);

    CK_MECHANISM_INFO_PTR GetMechanismInfo();
    CK_MECHANISM_PTR GetMechanismStruct();

    void SetSlotId (CK_SLOT_ID slotId) {m_slotId = slotId;}
    CK_SLOT_ID AccessSlotId () {return m_slotId;}

    CSM_Alg * AccessDigestAlg() {return m_pDigestAlg;}
    CSM_Alg * AccessDigestEncryptionAlg() {return m_pDigestEncryptionAlg;}
    CSM_Alg * AccessKeyEncryptionAlg () {return m_pKeyEncryptionAlg;}
    CSM_Alg * AccessContentEncryptionAlg () {return m_pContentEncryptionAlg;}

    static SNACC::AsnOid * MatchMechTypeToOid (CK_MECHANISM_TYPE);
    void LoadMechanismStruct(CK_MECHANISM_TYPE mechanismType);
    SM_RET_VAL LoadMechanismInfo(CK_MECHANISM_TYPE &mechanismType);

    SNACC::AsnOid * AccessOid() {return m_pOid;}

private:

    ////////////////////////////////////////////////////////////////////
    // private methods
    ////////////////////////////////////////////////////////////////////

    void Clear ();

    ////////////////////////////////////////////////////////////////////
    // private variables
    ////////////////////////////////////////////////////////////////////

    SNACC::AsnOid *m_pOid;
    CSM_Alg *m_pDigestAlg;
    CSM_Alg *m_pDigestEncryptionAlg;
    CSM_Alg *m_pKeyEncryptionAlg;
    CSM_Alg *m_pContentEncryptionAlg;

    CK_SLOT_ID m_slotId;

    CK_MECHANISM_PTR m_pMechanismStruct;
    CK_MECHANISM_INFO_PTR m_pMechanismInfo;

    SFL_C_GetMechanismInfo sfl_c_getMechanismInfo;
};

_END_CERT_NAMESPACE

#endif // _SM_PKCS11_H
