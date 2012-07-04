
//////////////////////////////////////////////////////////////////////////
//
// FILE:  sm_api.h
// DESCRIPTION:
//    Includes class definitions, compiler defines, and prototypes that
// the application might use.  This file is included indirectly by the
// application through the CTI library header (e.g. sm_fort.h, sm_free.h)
//
//    The classes in this header consist of the following "categories":
// 1. General API Classes:  Classes that the application must interact
//    with such as CSMIME and CSInst
// 2. High Level Message Classes:  Classes that most applications will
//    interact with to work with CSM Objects such as CSM_MsgToSign,
//    CSM_MsgToVerify, CSM_MsgToEncrypt, CSM_MsgToDecrypt, and
//    CSM_ContentInfoMsg
// 3. Low Level message Classes:  Classes that a few applications may
//    choose to interact with instead of those mentioned in 2 above
//    because they want direct access to the SNACC classes.  These
//    classes include CSM_DataToSign, CSM_DataToVerify, CSM_DataToEncrypt, etc
// 4. Low Level Component Classes:  low level classes that the application
//    may use in conjunction with the high level classes such as
//    CSM_Buffer, AsnOid, and the attribute classes
// 5. Classes that the Application will not normally use but are defined
//    here for use by the SFL such as CSM_TokenInterface and
//    CSM_BaseTokenInterface
//
//////////////////////////////////////////////////////////////////////////
#ifndef _SM_API_H_
#define _SM_API_H_

// SPECIFY SPECIFIC OVERRIDE STRUCTURE ALIGNMENT FACTOR;
//  NECESSARY TO OVERRIDE ANY OTHER PROJECT SETTINGS in which this include may
//  be referenced.  This alignment forces all references to the SFL structures
//  to be consistent with the DLL/LIB objects
#ifdef WIN32
#pragma pack(8)
#endif
//
//

#ifndef CML_USED
#define CML_USED
#endif  //CML_USED
#ifndef ACL_USED
#define ACL_USED
#endif  //ACL_USED

#ifndef NO_NAMESPACE
#define _BEGIN_SFL_NAMESPACE namespace SFL { \
    using namespace CERT; \
    //using namespace CTIL;
    //using namespace SNACC;
#define _END_SFL_NAMESPACE }
#else
#define _BEGIN_SFL_NAMESPACE
#define _END_SFL_NAMESPACE
#endif

// VDA SFL headers
//#ifdef ulong        // RWC; FIX ulong expectation with cmlasn.h!???!!!?#$#$
//#undef ulong
//#endif
#include "sm_apiCert.h"
#include "sm_cms.h"
#include "sm_ess.h"
#include "sm_pkixtsp.h"
#include "sm_CM_Interface.h"
#include "sm_AC_Interface.h"


_BEGIN_SFL_NAMESPACE
//////////////////////////////////////////////////////////////////////////
// GENERAL PURPOSE DEFINES
#define SM_ISS_AND_SERIAL_NO     0   /* Recipient Identifier union choices */
#define SM_RKEY_ID               1
#define SM_MLKEY_ID              2
#define SM_FirstTierRecipients   2
#define SM_AllReceipts           1
#define SM_NoReceipt             0
#define SM_receiptList           -1

/////////////////////////////////////////////////////////////////////////
// TimeStamp Error codes

#define SM_NOT_SIGNED			      170	
#define SM_SNACCTST_ENCODE_ERR	   171
#define SM_CONTENT_HAS_NO_TSTINFO   172
#define SM_SIG_NOT_VERIFIED		   173	
#define SM_CONTENT_NOT_TSTINFO	   174
#define SM_NO_TSTINFO_CONTENT       175
#define SM_SIG_DOES_NOT_MATCH_HASH  176
#define SM_GENTIME_NOT_VERIFIED     177
#define SM_CML_NOT_AVAILABLE        178


// SM_ENV_DATA_VERSION is used if there is an originator info or if
// there is a recipient info with version SM_ENV_DATA_VERSION in the
// envelopedData
#define SM_ENV_DATA_VERSION      2
// otherwise, SM_ENV_DATA_PREV_VERSION is used
#define SM_ENV_DATA_PREV_VERSION 0

////////////////////////////////
// Forward Class Declarations //
////////////////////////////////
class CSM_SecCat;
class CSM_UserKeyMaterial;
class CSM_Recipient;
class CSM_MsgSignerInfo;
class CSM_MsgSignerInfos;
class CSM_MsgAttributes;
class CSM_ReceiptRequest;
class CSM_SigningCertificate;
class CSM_SecLbl;
class CSM_GeneralAsn;
class CSM_MsgToVerify;
class CSM_MsgToDecrypt;
class CSM_Attrib;
class CSM_OriginatorInfo;
class CSM_Content;
class CSM_HashDef;
class MAB_Entrydef;
class CSM_ContentReference;
class CSM_SmimeCapability;
class CSM_CertID;
class CSM_PolicyInfo;
class CSM_PolicyQualifierInfo;
class CSM_RecipientIdentifier;
class CSM_KEKDetails;
class CSM_PWRIDetails;
class CSM_RecipientInfo;
class CSM_Time;
class CSM_TimeStampToken;


//////////////////////////////////////////////////////////////////////////
// List Typedefs
typedef List<CSM_Attrib> CSM_AttribLst;
typedef List<CSM_HashDef> CSM_HashDefLst;
typedef List<CSM_MsgSignerInfo> CSM_MsgSignerInfoLst;
typedef List<CSM_SecCat> CSM_SecCatLst;
typedef List<CSM_RecipientInfo> CSM_RecipientInfoLst;
typedef List<CSM_UserKeyMaterial> CSM_UserKeyMaterials;
typedef List<CSM_SecLbl> CSM_EquivalentLabels;
typedef List<CSM_SmimeCapability> CSM_SmimeCapabilityLst;
typedef List<CSM_CertID> CSM_CertIDLst;
typedef List<CSM_PolicyInfo> CSM_PolicyInfoLst;
typedef List<CSM_PolicyQualifierInfo> CSM_PolicyQualifierLst;
typedef List<CSM_KEKDetails> CSM_KEKDetailsLst;
typedef List<CSM_PWRIDetails> CSM_PWRIDetailsLst;
typedef List<CSM_RecipientIdentifier> CSM_RecipientIDLst;

///////////////////////
// CLASS DEFINITIONS //
///////////////////////

/**************************************************************************/
/* Recipient Identifier structure                                         */
/**************************************************************************/
class CSM_RecipientIdentifier : public CSM_Identifier
{
private:

    // DATA MEMBERS
    CSM_Buffer                *m_pOrigPubKey;
    CSM_Alg                   *m_pOrigPubKeyAlg;
    CSM_Buffer                *m_pDate;
    CSM_Attrib                *m_pAttribs;

public:

    // CONSTRUCTORS
    CSM_RecipientIdentifier() { Clear(); }
    CSM_RecipientIdentifier(CSM_IssuerAndSerialNumber &isn):
    CSM_Identifier(isn)
    { Clear(); }
    CSM_RecipientIdentifier(const CSM_Identifier              &rid);
    CSM_RecipientIdentifier(const CSM_RecipientIdentifier     &rid);
    CSM_RecipientIdentifier(const CSM_Buffer                  &SubjKeyId,
                            CSM_Buffer                  *pDate = NULL,
                            CSM_Attrib                  *pAttrib = NULL);
    CSM_RecipientIdentifier(const CSM_Buffer &OrigPubKey,const CSM_Alg &OrigPubKeyAlg);
    CSM_RecipientIdentifier(const SNACC::KeyAgreeRecipientIdentifier &SNACCkarid);
    CSM_RecipientIdentifier(const SNACC::RecipientIdentifier         &SNACCrid);
    CSM_RecipientIdentifier(const SNACC::SignerIdentifier            &SNACCsid);
    CSM_RecipientIdentifier(const SNACC::KEKIdentifier               &SNACCkekid);
    CSM_RecipientIdentifier(const SNACC::OriginatorIdentifierOrKey   &SNACCOidOrKey);

    void Clear()
    {
        m_pOrigPubKey=NULL; m_pOrigPubKeyAlg=NULL;
        m_pDate=NULL; m_pAttribs = NULL;
    }

    //DESTRUCTORS
    ~CSM_RecipientIdentifier();

    // Get member functions return memory, the application MUST delete
    CSM_Buffer                  *GetOrigPubKey();
    CSM_Alg                     *GetOrigPubKeyAlg();
    CSM_Buffer                  *GetDate();
    CSM_Attrib                  *GetAttrib();

    // Access member functions do not return
    // memory so no deletions are necessary
    const CSM_Buffer                  *AccessOrigPubKey() const 
    { return m_pOrigPubKey; }
    const CSM_Alg                     *AccessOrigPubKeyAlg() const 
    { return m_pOrigPubKeyAlg; }
    const CSM_Buffer                  *AccessDate() const { return m_pDate; }
    const CSM_Attrib                  *AccessAttrib() const { return m_pAttribs; }

    // Get members that return SNACC Classes
    SNACC::KeyAgreeRecipientIdentifier *GetKeyAgreeRecipientIdentifier();
    SNACC::RecipientIdentifier         *GetRecipientIdentifier();
    SNACC::SignerIdentifier            *GetSignerIdentifier();
    SNACC::SignerIdentifier            *GetSignerIdentifier(bool bIssOrSki);
    SNACC::KEKIdentifier               *GetKEKIdentifier();
    SNACC::OriginatorIdentifierOrKey   *GetOrigIdentOrKey(CSM_CSInst *inst=NULL);


    //SNACC Operator overloads
    operator SNACC::KeyAgreeRecipientIdentifier *()
    { return(GetKeyAgreeRecipientIdentifier()); }
    operator SNACC::RecipientIdentifier *()
    { return(GetRecipientIdentifier()); }
    operator SNACC::SignerIdentifier *()
    { return(GetSignerIdentifier()); }
    operator SNACC::KEKIdentifier *()
    { return(GetKEKIdentifier()); }
    operator SNACC::OriginatorIdentifierOrKey *()
    { return(GetOrigIdentOrKey()); }

    // Comparison Operator Overload
    bool operator == (const CSM_RecipientIdentifier &CRid);

    // Assignment Operator Overload
    CSM_RecipientIdentifier &operator = (const CSM_RecipientIdentifier &Rid);

    // Set Members
    void SetOrigPubKey           (const CSM_Buffer       &origPubKey);
    void SetOrigPubKeyAlg        (const CSM_Alg          &origPubKeyAlg);
    void SetDate                 (const CSM_Buffer       &date);
    void SetAttrib               (const CSM_Attrib       &attr);

    //Output Member function
    void ReportMsgData(std::ostream &os);
};

//////////////////////////////////////////////////////////////////////////
class CSM_UserKeyMaterial
{
private:
    void Clear() { m_pAlgorithm = NULL; m_pUKM = NULL; }

public:
    CSM_UserKeyMaterial() { Clear(); }
    CSM_UserKeyMaterial(CSM_Alg *pAlg, CSM_Buffer *pUKM)
    { m_pAlgorithm = pAlg; m_pUKM = pUKM; }

    CSM_Alg *m_pAlgorithm;
    CSM_Buffer *m_pUKM;
};

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// SNACC LOW-LEVEL API CLASSES for SFL OPERATIONS
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

class CSM_DataToReceipt
{
private:
    void Clear()
    {
        m_pSnaccReceipt = NULL; m_pContentInfo = NULL; m_pFirstRecReq = NULL;
        m_pMust = NULL; m_pSIRecReq = NULL; m_ProcessReceipt = false;
    }

public:
    CSM_DataToReceipt();
    ~CSM_DataToReceipt();

    SM_RET_VAL InitReceipt(CSMIME *pCSMIME, SNACC::SignedData *m_pSnaccSignedData,
                           CSM_Buffer *pOriginalEncapContent);

    SM_RET_VAL ProcessRecReq(CSM_MsgSignerInfo *p_SI);

    bool        m_ProcessReceipt;
    SNACC::Receipt    *m_pSnaccReceipt;
    CSM_Buffer *m_pContentInfo;         // do not delete

    CSM_Buffer        *m_pFirstRecReq;  // do not delete
    CSM_MsgAttributes *m_pMust;
    CSM_MsgSignerInfo *m_pSIRecReq;     // pointer to Signer Info from which
                                        // the receipt will be generated
                                        // do not delete
};

//////////////////////////////////////////////////////////////////////////
// CSM_Content represents the inner (or encapsulated) content.  The inner
// content is the ContentInfo->[SignedData|EnvelopedData]->ContentInfo
class CSM_Content
{
public:
    // CONSTRUCTORS
    CSM_Content() { } // empty constructor
    CSM_Content(char *pszContent)       // construct DATA from null term string
    { SetContent(pszContent); }
    CSM_Content(CSM_Buffer *pContent)   // construct DATA from buffer
    { SetContent(pContent); }
    CSM_Content(CSM_Buffer *pContent, const SNACC::AsnOid &tOID)
    { SetContent(pContent, tOID); }
    CSM_Content(const char *pContentChar, long length, const SNACC::AsnOid tOID=SNACC::id_data)
    { SetContent(pContentChar, length, tOID); }
    CSM_Content(CSM_Content *pContent)  // construct from another CSM_Content
    { SetContent(pContent); }

    // Set functions
    void SetContent(char *pszContent);
    void SetContent(CSM_Buffer *pContent);
    void SetContent(CSM_Buffer *pContent, const SNACC::AsnOid &tOID);
    void SetContent(const char *pContentChar, long length, 
                    const SNACC::AsnOid tOID=SNACC::id_data);
    void SetContent(CSM_Content *pContent);

    SNACC::AsnOid m_contentType; // from ContentInfo->contentType
    CSM_Buffer m_content;  // used if CONTENT_DATA_DATA or CONTENT_DATA_ANY

};

//////////////////////////////////////////////////////////////////////////
// CSM_CommonData is inherited by all high level message classes as the
// component that stores content and anything else that ends up being
// common
class CSM_CommonData
{
private:

    // m_pContentFromASN1 contains content of signedData, envelopedData, or
    // receipt, or the ASN ANY data of an unknown; or the data content
    // of an OCTET STRING (usually a mime body part)
    CSM_Content *m_pContentFromAsn1;   

    // m_pContentClear contains content that is not compressed - it is clear
    CSM_Content *m_pContentClear; 

    bool m_bCompressDataFlag;     // IF true, use zlib functions to compress data


protected:
    short m_version;

    // m_pEncodedBlob is the actual encoded ASN.1 binary; used for input to
    // recipient (verify, decrypt) processing and output for originator
    // (sign, encrypt) processing
    CSM_Buffer *m_pEncodedBlob;

    void Clear()
    { m_pContentFromAsn1 = NULL; m_pContentClear=NULL;  
      m_lCmlSessionId = 0; m_lSrlSessionId = 0; m_pEncodedBlob = NULL; m_version = 0; 
      m_bCMLUseToValidate=false; m_bCMLFatalFail=false; m_pszCMLError=NULL; 
      m_bACLUseToValidate=false; m_bACLFatalFail = false; m_bCompressDataFlag = false;
      }

    void CSM_CommonData::ClearAll();


public:
    CSM_CommonData() { Clear(); }
    ~CSM_CommonData();

    // attribute members
    const CSM_Buffer *AccessEncodedBlob();
    CSM_Buffer *GetEncodedCI(SNACC::AsnOid *pType);
    void UpdateEncodedBlob(CSM_Buffer *pBlob);
    void SetEncodedBlob(const CSM_Buffer *pBlob);
    void SetEncapContentClear(const CSM_Content &EncapContent);
    void SetEncapContentClear(const CSM_Buffer &EncapContent, 
            const SNACC::AsnOid &OidType=SNACC::id_data);
                        // IN, OPTIONAL, Clear content oid if 
                        //   expected to be compressed
                        //  (We rely on flag to indicate compression
                        //   on creating messages, eg Sign)
    void SetEncapContentFromAsn1(const CSM_Buffer &EncapContent, 
                   const SNACC::AsnOid &OidType=SNACC::id_data);
    void SetEncapContentFromAsn1(const CSM_Content &EncapContent);
    void setContentType(const SNACC::AsnOid &oContentType);

    const CSM_Content *AccessEncapContentClear();      // returns inner m_pContentClear
    const CSM_Content *AccessEncapContentFromAsn1();   // returns inner m_pContentFromASN1
    const SNACC::AsnOid *GetContentTypeClear();
    const SNACC::AsnOid *GetContentTypeFromAsn1();
    bool GetCompressFlag();
    void SetCompressFlag(bool flag);
    CSM_Buffer *BuildCompressedData(); 
    long CompressData(const char *dataToCompress, unsigned long sourceLen, 
                      CSM_Buffer *&pCompressedDataBuf);
    long UncompressData(CSM_Buffer *pEncapContent, CSM_Buffer *&pUncompressedDataBuffer);
    void ReportCommonData(std::ostream &os);

#ifdef CML_USED
    long CMLValidateCert(
      CM_SFLCertificate &ACMLCert,      // IN, may have cert, or just RID.
      CERT::CSM_CertificateChoice *pCert=NULL);// IN, optional
                                    //  (will place inside ACMLCert OR
                                    //   RETURN if retrieved from CML)
#endif //CML_USED

    //  The following definitions are all OPTIONAL, if defined for the SFL lib.
    //  They support automatic CML validation.
    bool m_bCMLUseToValidate; // IF true, use CML to perform path validation.
    bool m_bCMLFatalFail;     // IF true, throw an exception if a CML 
                              //  validation error is encountered.
    unsigned long   m_lCmlSessionId;
    unsigned long   m_lSrlSessionId;
    char *m_pszCMLError;
    //RWC;TBD; determine the new form of CML error lists for validation errors.

    //  The following definitions are all OPTIONAL, if defined for the SFL lib.
    //  They support automatic ACL validation.
    bool m_bACLUseToValidate; // IF true, use ACL to perform Access Control validation.
    bool m_bACLFatalFail;     // IF true, throw an exception if an ACL 
                              //  error is encountered.
#ifdef ACL_USED
    ACL_Interface m_ACLInterface; // DEFINE ACL processing class.
#endif  // ACL_USED
};

//////////////////////////////////////////////////////////////////////////
// The application could use CSM_DataToVerify if it wants to directly
// manipulate the SignedData snacc class . . .
class CSM_DataToVerify: virtual public CSM_CommonData
{
private:
    void Clear() { m_pSnaccSignedData = NULL; m_lProcessingResults=0; 
                   m_pACLLocalCert = NULL;}

public:
    CSM_DataToVerify() { Clear(); }
    CSM_DataToVerify(const CSM_Buffer *pBlob) { Clear(); PreProc(pBlob); }
    CSM_DataToVerify(CSMIME *pCSMIME, const CSM_Buffer *pBlob)
    { Clear(); PreProc(pCSMIME, pBlob); }
    ~CSM_DataToVerify();

    // If the CSMIME parameter is specified, then all logon instances that can
    //  verify the message's signature will be marked with "Applicable" flag
    //  If the CSMIME parameter is not specified, then the message is simply
    //  decoded into the SNACC structure
    SM_RET_VAL PreProc(CSMIME *pCSMIME);
    SM_RET_VAL PreProc(const CSM_Buffer *pEncodedBlob);
    SM_RET_VAL PreProc(CSMIME     *pCSMIME,      // IN,logged-on Instance list
                       const CSM_Buffer *pEncodedBlob);// IN, SignedData/ContentInfo

    SM_RET_VAL Verify(
        CSMIME *pCSMIME,                  // IN, list of logons
        SNACC::SignerInfo *pSI,                  // IN, specific SignerInfo to process
        CSM_Buffer *pOriginalEncapContent,// IN, optional content if not in SD
        CSM_CertificateChoiceLst *pCerts, // IN, Originator(s) certs+++
        CSM_MsgAttributes *pSignedAttrs); // IN, optional signed attributes

    SM_RET_VAL Verify(
        CSMIME *pCSMIME,                  // IN, list of logons
        SNACC::SignerInfo *pSI,                  // IN, specific SignerInfo to process
        CSM_CertificateChoiceLst *pCerts, // IN, Originator(s) certs+++
        CSM_MsgAttributes *pSignedAttrs); // IN, optional signed attributes

    SM_RET_VAL Verify(
        CSM_CSInst *pCSInst,              // IN,logged-on Instance
        CSM_MsgCertCrls *pMsgCertCrls);   // IN,Originator(s) certs+++

    SM_RET_VAL Verify(
        CSMIME *pCSMIME,                  // IN, logged-on Instance list
        CSM_MsgCertCrls *pMsgCertCrls,    // IN, Originator(s) certs+++
        CSM_MsgSignerInfos *pMsgSignerInfos);// IN, wrapper for SNACC SIs

    SM_RET_VAL Verify(
        CSMIME *pCSMIME,                  // IN, logged-on Instance list
        CSM_Buffer *pOriginalEncapContent,// IN, optional content if not in SD
        CSM_MsgCertCrls *pMsgCertCrls,    // IN, Originator(s) certs+++
        CSM_MsgSignerInfos *pMsgSignerInfos);// IN, wrapper for SNACC SIs

    CSM_DataToReceipt m_Receipt;
    SNACC::SignedData *m_pSnaccSignedData; // SNACC generated class

    long m_lProcessingResults;  // Bits set according to enum below.
    enum { msgSignatureVerified=0x02,
           receiptProduced=0x04 };
    CSM_Buffer *m_pACLLocalCert;  // OPTIONAL ACL cert for proper
                                  //  validation; only used to get SPIF.
                                  //  Usually this cert is either the local
                                  //  signing OR encrypting cert, with a valid
                                  //  clearance attribute.

};

//////////////////////////////////////////////////////////////////////////
// The application could use CSM_DataToSign if it wants to directly
// manipulate the SignedData snacc class . . .
class CSM_DataToSign
{
public:
    SM_RET_VAL Sign(CSMIME *pCSMIME,              // IN,logged-on Instance list
                    CSM_MsgCertCrls *pMsgCertCrls,// IN,Originator(s) certs+++
                                                  //   (May be NULL)
                    CSM_Buffer *&pEncodedBlob);   // OUT, Resulting
                                                  //   SignedData/ContentInfo

    SNACC::SignedData m_SnaccSignedData; // SNACC generated class
};

// This class supports the CMS-10 specification for Key Encryption Key (KEK)
//  choice for encrypted RecipientInfos.  It contains specific details for the
//  encryption user data (not included in the message) as well as the content
//  encryption algorithm used for a specific RecipientInfo
class CSM_KEKDetails
{
public:
    CSM_KEKDetails() {}
    CSM_KEKDetails(const CSM_KEKDetails &kekDetails)
    {
        m_UserEncryptionData = kekDetails.m_UserEncryptionData;
        m_keyEncryptionAlgorithm = kekDetails.m_keyEncryptionAlgorithm;
        m_RID = kekDetails.m_RID;
    }

    CSM_Buffer m_UserEncryptionData; // Used for content encryption key
                                     //  (NOT SENT IN MESSAGE, INTERNAL ONLY)
    CSM_Alg m_keyEncryptionAlgorithm;// Expected to specify a content encryption
    CSM_RecipientIdentifier m_RID;   // supports our ID and optional date
                                     //  and attribute
};

// This class supports the CMS-10 specification for PasswordBasedRecipientInfo (PWRI)
//  choice for encrypted RecipientInfos.  It contains specific details for the
//  encryption user data (not included in the message) as well as the content
//  encryption algorithm used for a specific RecipientInfo
class CSM_PWRIDetails
{


public:
    CSM_PWRIDetails() 
    {  m_pKeyEncryptionAlgorithm = NULL; m_pKeyDerivationAlgorithm = NULL;
       m_pKeyEncryptContentWrapOid =NULL;   m_pUserKeyEncryptionKey = NULL;
    }



    CSM_PWRIDetails(CSM_PWRIDetails &pwriDetails)
    {
        m_UserEncryptionData = pwriDetails.m_UserEncryptionData;
        m_pKeyEncryptionAlgorithm = pwriDetails.m_pKeyEncryptionAlgorithm;
        m_pKeyDerivationAlgorithm = pwriDetails.m_pKeyDerivationAlgorithm;
        m_pKeyEncryptContentWrapOid = pwriDetails.m_pKeyEncryptContentWrapOid;
        m_pUserKeyEncryptionKey = pwriDetails.m_pUserKeyEncryptionKey;
    }

    ~CSM_PWRIDetails()
    {
       if (m_pKeyEncryptionAlgorithm)
          delete m_pKeyEncryptionAlgorithm;
       if (m_pKeyDerivationAlgorithm)
          delete m_pKeyDerivationAlgorithm;
       if (m_pKeyEncryptContentWrapOid)
          delete m_pKeyEncryptContentWrapOid;
       if (m_pUserKeyEncryptionKey)
          delete m_pUserKeyEncryptionKey;
       m_pKeyEncryptionAlgorithm = NULL; 
       m_pKeyDerivationAlgorithm = NULL;
       m_pKeyEncryptContentWrapOid =NULL;
       m_pUserKeyEncryptionKey = NULL;
    }



    CSM_Buffer m_UserEncryptionData; // Used for content encryption key
                                     //  (NOT SENT IN MESSAGE, INTERNAL ONLY)
    CSM_Alg    *m_pKeyEncryptionAlgorithm;// Expected to specify a key encryption Algorithm id
                                         //  id-PBKDF2 (1 2 840 113549 1 5 12)
    CSM_Alg    *m_pKeyDerivationAlgorithm;// Expected to specify a key Derivation Algorithm id 
                                         //  id--alg-PWRI-KEK (1 2 840 113549 1 9 16 3 9)
    SNACC::AsnOid *m_pKeyEncryptContentWrapOid; // Supporting Encryption Key wrap oid

    CSM_Buffer *m_pUserKeyEncryptionKey;   // Key-encryption key used if supplied from 
                                           // an external source, for ex. a hardware or 
                                           // crypto token such as a smartcard.  
                                           // See RFC3369 6.2.4
    
};

//
//
class CSM_RecipientInfo : public SNACC::RecipientInfo
{
private:
    bool m_bDecrypted;
    CSM_RecipientIdentifier  m_RID;        // Used in any of the RI choices
public:
    CSM_RecipientInfo()
    { Clear(); }
    CSM_RecipientInfo(const CSM_CertificateChoice &cert)
    {
        Clear();
        m_pCert = new CSM_CertificateChoice(cert);
    }
    CSM_RecipientInfo(const SNACC::RecipientInfo &SNACCRi)
    {
        Clear();
        AssignSNACCRI(SNACCRi);
    }
    CSM_RecipientInfo(const CSM_Buffer &Cert)
    {
        Clear();
        m_pCert = new CSM_CertificateChoice(Cert);
    }
    CSM_RecipientInfo(const CSM_RecipientInfo &RI);
    CSM_RecipientInfo & operator =(const CSM_RecipientInfo &RI);

    ~CSM_RecipientInfo();

    CSM_CertificateChoice   *m_pCert;      // Supporting Encryption
    CSM_Buffer              *m_pUkmBuf;    // Supporting Encrytpion
    SNACC::AsnOid           *m_pencryptionAlgOid; // Supporting Encryption
    SNACC::AsnOid           *m_pKeyDerivationAlgOid; // Supporting PWRI key derivation
    SNACC::AsnOid           *m_pKeyEncryptionAlgOid; // Supporting PWRI key encryption
    CSM_Buffer              *m_pbufParams; // Supporting Encryption
    CSM_Buffer              *m_pbufSharedUKMParams; // Supporting Encryption
    CSM_KEKDetails          *m_pKEKDetails;// Alternative to cert for
                                           // encrypt info
    CSM_PWRIDetails         *m_pPWRIDetails;// password recipient support for encrypted info
    CSM_RecipientIdentifier *m_pOrigRID;   // OriginatorID or Dynamic Public Key
    CSM_Buffer               m_bufEMEK;    // Used in all incarnations
    bool                     m_bCMLValidationFailed;
    bool                     m_bACLValidationFailed;
    bool                     m_bIssOrSki;
    SNACC::RecipientEncryptedKeys::iterator *m_pRecipientEncryptedKeysIterator;
#ifdef CML_USED
    CM_SFLCertificate        m_ACMLCert;
#endif  //CML_USED

    void Clear()
    {
        m_bDecrypted = false; m_pUkmBuf = NULL;            m_pCert=NULL;
        m_bIssOrSki = true;   m_pKEKDetails=NULL;          m_pPWRIDetails=NULL;
        m_pbufParams=NULL;    m_pencryptionAlgOid=NULL;
        m_pKeyDerivationAlgOid=NULL; m_pKeyEncryptionAlgOid=NULL;  m_pOrigRID=NULL; 
        m_pbufSharedUKMParams=NULL;  m_bCMLValidationFailed=false; m_bACLValidationFailed=false;
        m_pRecipientEncryptedKeysIterator = NULL;
    }

    SNACC::KeyEncryptionAlgorithmIdentifier *AccesskeyEncryptionAlgorithm();
    SNACC::KeyDerivationAlgorithmIdentifier *AccesskeyDerivationAlgorithm();
    SNACC::EncryptedKey *AccessEncryptedKey();
    SNACC::OriginatorIdentifierOrKey *AccessOriginatorCertID();
    CSM_RecipientIdentifier *GetRid();
    void SetKeyEncryptionAlgorithm(SNACC::AsnOid &SNACCAlgId, CSM_Buffer &Params);
    void SetRid(SNACC::RecipientIdentifier &SNACCRid);
    void SetRid(SNACC::KeyAgreeRecipientIdentifier &SNACCKARid);
    void SetRid(SNACC::IssuerAndSerialNumber &SNACCIssuer);
    void SetRid(CSM_Buffer &KeyId);
    void SetRid(CSM_RecipientIdentifier &Rid);
    void SetEncryptedKey(CSM_Buffer &bufEMEK);
    void GetEncryptedKey();
    SNACC::RecipientInfo *GetSharedRI(SNACC::RecipientInfos &SNACCRecipientInfos,
                               CSM_Alg &keyEncryptionAlgId,
                               CSM_RecipientInfoLst   *pRecipients);
    void SetOriginatorID(CSM_RecipientIdentifier &Orig);

    // The LoadSNACCRecipientInfo(. . .), must have the instance to properly
    //  load the SNACC RI.  It may load an existing RI with a new recipient
    void LoadSNACCRecipientInfo(
        CSM_CSInst           &csInst,       // IN for KeyAgree check
        SNACC::RecipientInfos       &SNACCRecipientInfos, // IN/OUT "this" is loaded
        bool                  bSharedUkms,  // IN flag to share Ukm, Dynamic key
        CSM_Alg              &ProcessingAlg,
        CSM_RecipientInfoLst *pRecipients);
    void UnloadSNACCRecipientInfo();

    bool operator == (CSM_RecipientIdentifier &SNACC_RID);
    bool operator == (CSM_RecipientInfo &SNACC_RI);
    bool operator == (SNACC::IssuerAndSerialNumber &SNACC_Issuer);

    bool WasDecrypted() { return m_bDecrypted; }
    void SetDecryptedFlag(bool bFlag) { m_bDecrypted=bFlag; }

    void AssignSNACCRI(const SNACC::RecipientInfo &SNACCRi);
    void SetEncryptedKey(SNACC::RecipientInfo &SNACCRecipientInfo);

};

//////////////////////////////////////////////////////////////////////////
// The application could use CSM_DataToDecryptEncData if it wants to directly
// manipulate the EncryptedData snacc class
class CSM_DataToDecryptEncData
{

public:
    // CONSTRUCTORS
    CSM_DataToDecryptEncData() {}
    CSM_DataToDecryptEncData(const CSM_Buffer *pbufEncryptedData);
    CSM_DataToDecryptEncData(CSMIME *pCSMIME, const CSM_Buffer *pbufEncryptedData);
    ~CSM_DataToDecryptEncData() {}

    SNACC::EncryptedData m_SnaccEncryptedData;   // SNACC

    void PreProc(CSMIME *pCSMIME);
    void PreProc(const CSM_Buffer *pbufEncryptedData, CSMIME *pCSMIME);
    void Decode(const CSM_Buffer *pbufEncryptedData);

    void Decrypt(CSMIME *pCSMIME,         // IN, including instances
                 CSM_Buffer *pbufDecryptedContent, // OUT, decrypted content
                 CSM_Buffer *Cek);

};

//////////////////////////////////////////////////////////////////////////
// The application could use CSM_DataToDecrypt if it wants to directly
// manipulate the EnvelopedData snacc class
// (RWC;NOTE: CSM_CommonData moved from CSM_MsgToDecrypt to make the newly 
//  added CML variables available when processing the originator information.) 
class CSM_DataToDecrypt: virtual public CSM_CommonData
{
private:
    CSM_Buffer *TryThisInstance(CSMIME *m_pCsmime, CSM_CSInst *pInst,
        CSM_CertificateChoiceLst *pOrigCerts, CSM_RecipientInfoLst *pRecipients);
    void Clear() { m_pKEKDetailsLst = NULL; m_pPWRIDetails = NULL; m_pKeyWrapOID = NULL; 
                   m_bExportMEK = false; m_pExportedMEK = NULL; 
                   m_pOPTIONALEncryptedContent = NULL; 
                   m_pRecipientEncryptedKeysIterator=NULL;  
#ifdef CML_USED
		   m_pACMLOriginatorCert = NULL; 
#endif  // CML_USED
    }
    SNACC::RecipientEncryptedKeys::iterator *m_pRecipientEncryptedKeysIterator;
    SNACC::RecipientInfos::iterator m_SNACCRiIterator;
#ifdef CML_USED
protected:
    CM_SFLCertificate *m_pACMLOriginatorCert;
#endif //CML_USED
public:
    // CONSTRUCTORS
    CSM_DataToDecrypt() { Clear(); }
    ~CSM_DataToDecrypt();
    CSM_DataToDecrypt(const CSM_Buffer *pbufEnvelopedData);
    CSM_DataToDecrypt(CSMIME *pCSMIME, const CSM_Buffer *pbufEnvelopedData);

    SNACC::EnvelopedData m_SnaccEnvelopedData;   // SNACC
    CSM_KEKDetailsLst *m_pKEKDetailsLst;
    CSM_PWRIDetails *m_pPWRIDetails;
    SNACC::AsnOid *m_pKeyWrapOID;
    // ONLY used in case the EncryptedContent is not in the decoded EnvelopedData.
    //  Loaded by the application.
    CSM_Buffer *m_pOPTIONALEncryptedContent;

    void PreProc(CSMIME *pCSMIME);
    void PreProc(const CSM_Buffer *pbufEnvelopedData, CSMIME *pCSMIME);
    void Decode(const CSM_Buffer *pbufEnvelopedData);

    // Decrypt the provided ASN.1 encoded EnvelopedData based on
    // the provided parameters
    void Decrypt(CSMIME     *pCSMIME,                 // IN including instances
                 CSM_CertificateChoiceLst *pOrigCerts,// IN originator certs
                 CSM_Buffer *pbufDecryptedContent,    // OUT decrypted content
                 CSM_RecipientInfoLst *pRecipients);
    CSM_RecipientInfo *GetFirstRecipientInfo();
    CSM_RecipientInfo *GetNextRecipientInfo();
    CSM_Buffer *GetOrigPublicKey(SNACC::RecipientInfo &SNACCRecipInfo,
                                  CSM_CertificateChoiceLst *pOrigCerts,
                                  CSM_Alg &keyEncryptionAlg);
    CSM_CertificateChoice *GetOrigPublicCert(SNACC::RecipientInfo &SNACCRecipInfo, 
                                             CSM_CertificateChoiceLst *pOrigCerts,
                                             CSM_Alg &keyEncryptionAlg);
    bool determineKEKUserEncryptionData(CSM_RecipientInfo &RI);

protected:
   // THESE 2 items default disabled, we do not like to make the MEK visible
   // any more than necessary.  They are present to support the special case
   // where an EnvelopedData is re-encrypted (e.g. MailListAgent processing).
   // In this case, a valid RI decrypts a message, then re-encrypts to new
   // recipient(s).  In this case it is not necessary to re-encrypt the
   // content, if we can access the MEK clearly.
   // (NOTE:: SOME CTILS CANNOT USE THIS FEATURE since the MEK is never
   //  available in the clear.)
   bool m_bExportMEK;
   CSM_Buffer *m_pExportedMEK;

};

//////////////////////////////////////////////////////////////////////////
// The application could use CSM_DataToEncrypt if it wants to directly
// manipulate the EnvelopedData snacc class
class CSM_DataToEncrypt
{
private:
    bool m_bOriginatorIncluded; // indicates if originator was included
    // below indicates if the originator should be included as recip
    bool m_bAddOriginatorAsRecipient;
    bool m_bIncludeContent;  // default is TRUE, IF FALSE, no content is encoded

    void LoadFromMsgCertCrls(CSM_MsgCertCrls *pMsgCertCrls);
    void AddRecipient(CSM_CSInst *pInst, CSM_RecipientInfo *pRecip,
                      CSM_Buffer &bufMEK, CSM_RecipientInfoLst *pRecipients,
                      CSM_Alg *pContentEncryptionAlg);
    void AddRecipientKARI(CSM_CSInst *pInst, CSM_RecipientInfo *pRecip,
                      CSM_Buffer &bufMEK, CSM_RecipientInfoLst *pRecipients);
    void AddRecipientKTRI(CSM_CSInst *pInst, CSM_RecipientInfo *pRecip,
                      CSM_Buffer &bufMEK, CSM_RecipientInfoLst *pRecipients);
    void AddRecipientKEK(CSM_CSInst *pInst, CSM_RecipientInfo *pRecip,
                      CSM_Buffer &bufMEK, CSM_RecipientInfoLst *pRecipients);
    void AddRecipientPWRI(CSM_CSInst *pInst, CSM_RecipientInfo *pRecip,
                      CSM_Buffer &bufMEK, CSM_RecipientInfoLst *pRecipients,
                      CSM_Alg *pContentEncryptionAlg);
    void AddRecipientLOCAL(CSM_CSInst *pInst, CSM_RecipientInfo *pRecip,
                      CSM_Buffer &bufMEK, CSM_RecipientInfoLst *pRecipients);
    long GetEnvDataVersion();

    void Clear()
    {
        m_bIssOrSki = true; m_bAddOriginatorAsRecipient=true; m_pCsmime=NULL;
        m_pKeyEncryptionOID = NULL; m_bOriginatorIncluded=false;
        m_pKeyWrapOID=NULL; m_bSharedUkms = false; m_bNoUkmFlag = false; 
        m_pImportedMEK = NULL; m_bIncludeContent = true;  
        m_pOPTIONALEncryptedContent = NULL;
    }

public:
    CSM_DataToEncrypt()
    { Clear(); }
    ~CSM_DataToEncrypt();

    SNACC::EnvelopedData m_SnaccEnvelopedData;// SNACC
    SNACC::AsnOid *m_pKeyEncryptionOID;      // OPTIONAL, usually extracted from Cert
                                       //  ES-DH KeyAgree uses same DH certs
    SNACC::AsnOid *m_pKeyWrapOID;
    bool m_bIssOrSki;         // true implies RID with IssuerAndSerialNumber
                              //   NOT SubjectKeyIdentifier
    void SetAddOriginatorAsRecipient(bool b)
    { m_bAddOriginatorAsRecipient = b; }
    bool GetAddOriginatorAsRecipient() { return m_bAddOriginatorAsRecipient; }
    void SetIncludeContentFlag(bool bFlag=true) { m_bIncludeContent = bFlag; }
    bool GetIncludeContentFlag() { return m_bIncludeContent; }

    bool m_bSharedUkms; // Shared or single UKM for each
                        // RecipientInfo
    CSMIME *m_pCsmime;  // To handle different CTILs for key agree/key wrap
    bool m_bNoUkmFlag;  // Flag to create msgs with no UserKeyMaterial Random.
    // ONLY used in case the EncryptedContent is not in the decoded EnvelopedData.
    //  Loaded by the application.
    bool m_bKTRI_RSAES_OAEPflag;        // FLAGS encryption to perform RSAES-OAEP
                                        //  encryption with RSA public key.
    CSM_Buffer *m_pOPTIONALEncryptedContent;

    // Encrypt and encode into private member pbfEncodedBlob
    void Encrypt(CSMIME *pCSMIME,                // IN,logged-on Instance list
                 CSM_MsgCertCrls *pMsgCertCrls,  // IN,Originator(s) certs
                                                 // (May be NULL)
                 CSM_RecipientInfoLst *pRecipients,// IN,Recipient Certs
                 SNACC::AsnOid *poidContentType,       // IN, content type
                 CSM_Buffer *pContent,           // IN, content for env. data
                 CSM_Alg *pContentEncryptionAlg, // IN, content encryption Alg
                 CSM_Buffer *pOutputBuf);        // OUT, resulting
                                                 // EnvelopedData/ContentInfo
    void ProcessRecipients(CSMIME                 *pCSMIME,
                           CSM_RecipientInfoLst   *pRecipients,
                           CSM_Buffer             &bufMEK,
                           CSM_Alg *pContentEncryptionAlg = NULL);


    void SetRecipientInfo(CSM_CSInst              &cInst,
                          CSM_Buffer              &UKMBuf,
                          CSM_RecipientIdentifier &rid,
                          CSM_Buffer              &BufEMEK,
                          SNACC::AsnOid                  &algID,
                          CSM_Buffer              &bufParams);
protected:
   // THIS item if normally NULL on input, we do not like to make the MEK visible
   // any more than necessary.  It is present to support the special case
   // where an EnvelopedData is re-encrypted (e.g. MailListAgent processing).
   // In this case, a valid RI decrypts a message, then re-encrypts to new
   // recipient(s).  In this case it is not necessary to re-encrypt the
   // content, if we can access the MEK clearly.
   // (NOTE:: SOME CTILS CANNOT USE THIS FEATURE since the MEK is never
   //  available in the clear.)
   // When this feature is not used, the MEK IS NOT STORED HERE FOR PROCESSING!
   CSM_Buffer *m_pImportedMEK;

};

//////////////////////////////////////////////////////////////////////////
// Intent of the CSM_ContentInfoMsg class is that an incomming message be
// processed to determine the type:  for example . . .
//    CSM_MsgToDecrypt *pEnvData;
//    CSM_ContentInfoMsg *pCIM = new CSM_ContentInfoMsg(CSM_BufFile *pMsg);
//    if (pCIM->GetContentType() == EnvelopedDataOID)
//       pEnvData = new CSM_MsgToDecrypt(pCIM, pCSMIME);
//    else . . .            // same for SignedData
//
class CSM_ContentInfoMsg : public CSM_CommonData
{
private:
    SNACC::ContentInfo *m_pSNACCContentInfo;
public:
    CSM_ContentInfoMsg();
    CSM_ContentInfoMsg(CSM_Buffer *pBuf);
    CSM_ContentInfoMsg(const SNACC::ContentInfo &SNACCCI);
    ~CSM_ContentInfoMsg();
    bool IsSignedData();
    bool IsEnvelopedData();
    bool IsEncryptedData();
    bool IsReceipt();
    bool IsData();
    bool IsCompressedData();
    bool IsTimeStampTokenData();
    CSM_Buffer *AccessEncodedCI();
    void SetEncodedCI(CSM_Buffer &Buffer);
};

//////////////////////////////////////////////////////////////////////////
// CSM_MsgSignedDataCommon
//  This class was created to allow common functionality between the
//  signing and verifying classes.
class CSM_MsgSignedDataCommon: virtual public CSM_CommonData
{
public:
   SM_RET_VAL CheckSignedDataAttrs(CSMIME *pCsmime, SNACC::SignerInfos &signerInfos,
	   CSM_Buffer *pbuf = NULL);
};

//////////////////////////////////////////////////////////////////////////
//  CSM_MsgToVerify
//  This class handles the decoding of an SMIME SignedData ASN.1 encoded
//  component.  It provides all data to the application
//  SignedData ::=
//  SEQUENCE {
//      version                Version,
//      digestAlgorithms       DigestAlgorithmIdentifiers,
//      contentInfo            ContentInfo,
//      certificates       [0] IMPLICIT CertificateSet OPTIONAL,
//      crls               [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//      signerInfos            SignerInfos }
//
class CSM_MsgToVerify : virtual public CSM_MsgSignedDataCommon, public CSM_DataToVerify
{
private:
    void Clear();
    void CSSIDCertCheck(CSM_RecipientIDLst *pCSSIDLst);

public:
    // constructors
    CSM_MsgToVerify();
    CSM_MsgToVerify(const CSM_ContentInfoMsg *pCIM); // extract content info for SD
    CSM_MsgToVerify(const CSM_Content *pMsgBlob);
    CSM_MsgToVerify(const CSM_Buffer *pBlob);
    // the constructor below also pre-processes the content using the
    // CSMIME/CSInst classes so it can mark applicable instances for use
    //
    CSM_MsgToVerify(CSMIME *pCSMIME, const CSM_Buffer *pBlob,       
       bool bCMLUseToValidate = false, 
       bool bCMLFatalFail=false, 
       unsigned long lCmlSessionId=0, 
       unsigned long lSrlSessionId=0);
    ~CSM_MsgToVerify();

    SNACC::SignedData *AccessSignedData() { return m_pSnaccSignedData; }

    // Pre-processing operational methods
    SM_RET_VAL PreProc(const CSM_Buffer *pCSMBlob);
    SM_RET_VAL PreProc(CSMIME *pCSMIME, const CSM_Buffer *pCSMBlob,
                       CSM_RecipientIDLst *pCSSIDLst=NULL);
    SM_RET_VAL PreProc(CSMIME *pCSMIME);

    // Signature verification operational methods
    SM_RET_VAL Verify(CSMIME *pCSMIME, bool bVerifyTST = true);
    SM_RET_VAL Verify(CSMIME *pCSMIME, CSM_Buffer &CSMBlob);
    SM_RET_VAL VerifyTimeStampToken(CSMIME *pCsmime, 
                                    std::ostream *pOstrm = NULL);                                                

    // Indicate that application what's to return a receipt if one is requested
    // m_ProcessReceipt is inherited from CSM_DataToVerify
    void EnableReceipt(bool flag) { m_Receipt.m_ProcessReceipt = flag; }
    SM_RET_VAL CheckSignedDataAttrs(CSMIME *pCsmime)
    { long lStatus=0;
      if (m_pSnaccSignedData) 
        lStatus=CSM_MsgSignedDataCommon::CheckSignedDataAttrs(pCsmime, 
                m_pSnaccSignedData->signerInfos); 
      return(lStatus);
    }    // END CheckSignedDataAttrs


    // Application can call this function to determine if a receipt request
    // was processed
    bool ReceiptRequested(void);

    // Determines if any of the certificates in the message belongs to this
    // SignerInfo component and loads it into the "m_pSignerInfos" class
    void SetSICerts(CSMIME *pCsmime);

    // generate and return the signed receipt
    CSM_Buffer *GetSignedReceipt(CSMIME *pCSMIME,
                                  CSM_MsgAttributes *pSignedAttrs,
                                  CSM_MsgAttributes *pUnsignedAttrs);
    bool ReceiptFromUs(CSMIME *pCsmime);
    void ReportMsgData(std::ostream &os);

    CSM_MsgCertCrls *m_pMsgCertCrls;     // handles all certs and CRLs ops for
                                         //  msg encoding/decoding
    CSM_MsgSignerInfos *m_pSignerInfos;  // handles all signerInfo processing

 	 CSM_CertificateChoice *m_pTimeStampCertificate; // signer's cert for TST
    CSM_RecipientIdentifier *m_pTimeStampSid;  // signer's sid for TimeStampToken
};

//////////////////////////////////////////////////////////////////////////
class CSM_HashDef
{
public:
    CSM_HashDef() { m_pOID = NULL; m_pHash = NULL; }
    CSM_HashDef(SNACC::AsnOid *pOID, CSM_Buffer *pBuf)
    { m_pOID = new SNACC::AsnOid(*pOID); m_pHash = new CSM_Buffer(*pBuf); }
    ~CSM_HashDef()
    {
        if (m_pOID) delete m_pOID;
        if (m_pHash) delete m_pHash;
    }

    SNACC::AsnOid *m_pOID;        // Hash encryption OID
    CSM_Buffer *m_pHash;    // Hash result for that Digest OID
};


//////////////////////////////////////////////////////////////////////////
//  CSM_MsgToSign
//  This class handles the creation of an SMIME SignedData ASN.1 encoded
//  component
//  (See comments above in CSM_MsgToVerify for the ASN.1 definition)
//  A number of elements of this message are loaded automatically by the
//  instances specified as a parameter to SM_Sign():
//  the DigestAlgorithms, originator certs, SignerInfos (based on sessions
//  and attributes)
class CSM_MsgToSign : virtual public CSM_MsgSignedDataCommon, protected CSM_DataToSign
{
private:
    // PRIVATE DATA MEMBER
    // TRUE indicates that the encoded results will include the specified
    // originator certs.  Cert path is included only if the caller has
    // loaded the entire set of certs using CSInst::UpdateCertificates
    bool m_bIncludeOrigCertsFlag;
    bool m_IncludeContent;

    // PRIVATE MEMBER FUNCTIONS
    SM_RET_VAL SignCalculateHash(CSM_CSInst *tmpCSInst,
                                 SNACC::SignedData *lpSignedData,
                                 CSM_HashDefLst *&pHash,
                                 CSM_Buffer *&pContent,
                                 CSM_Buffer *&pHashResult);
    virtual SM_RET_VAL PutSignerInfo(CSM_CSInst *pCSInst,
                                     SNACC::SignedData *lpSignData,
                                     SNACC::SignerInfo *&lpSignerInfo);

    void Clear()
    {
        m_IncludeContent = true; m_bIncludeOrigCertsFlag = false;
        m_pMsgCertCrls = NULL; m_pUnsignedAttrs = NULL;
        m_pSignedAttrs = NULL; m_bIssOrSki = true;
    }
    void AddDigestAlgorithm(SNACC::SignedData *lpSignedData,
                            SNACC::DigestAlgorithmIdentifier &digestAlgorithm);

protected:
    // PROTECTED MEMBER FUNCTIONS
    SM_RET_VAL PutSignerInfoCommon(CSM_CSInst *pCSInst,
                                   SNACC::SignedData *lpSignedData,
                                   SNACC::SignerInfo *&lpSNACCSignerInfo);

public:
    // CONSTRUCTORS
    CSM_MsgToSign() { Clear(); }
    CSM_MsgToSign(const CSM_Content  *pMsgBlob)       
    { Clear(); if (pMsgBlob) SetEncapContentClear(*pMsgBlob); }
    virtual ~CSM_MsgToSign();

    // PUBLIC DATA MEMBERS
    CSM_MsgCertCrls *m_pMsgCertCrls;    // handles all certs and CRLs ops for
                                        //   msg encoding/decoding
    CSM_MsgAttributes *m_pUnsignedAttrs;// message attributes, most are common
    CSM_MsgAttributes *m_pSignedAttrs;  // message attributes, most are common
                                        //   to all CSInstances
    bool m_bIssOrSki;

    // PUBLIC MEMBER FUNCTIONS
    SM_RET_VAL Sign(CSMIME *pCSMIME);

    void SetIncludeContentFlag(bool bFlag=true) { m_IncludeContent = bFlag; }
    bool GetIncludeContentFlag() { return m_IncludeContent; }
    bool GetIncludeOrigCertsFlag() { return m_bIncludeOrigCertsFlag; }
    CSM_Buffer *GetEncodedContentInfo();
    void SetIncludeOrigCertsFlag(bool bFlag)
    { m_bIncludeOrigCertsFlag = bFlag; }
    SM_RET_VAL UpdateSignedDataSIs(CSMIME *pCsmime);
    SM_RET_VAL ProduceSignerInfo(CSM_CSInst *pCSInst,
                                 SNACC::SignedData *pSignedData,
                                 SNACC::SignerInfo *&lpSNACCSignerInfo,
                                 CSM_Buffer *pDigestInput=NULL);
    SM_RET_VAL CheckSignedDataAttrs(CSMIME *pCsmime, CSM_Buffer *pbufError=NULL)
    { return CSM_MsgSignedDataCommon::CheckSignedDataAttrs(pCsmime, 
                  m_SnaccSignedData.signerInfos, pbufError); 
    }    // END CheckSignedDataAttrs
	SM_RET_VAL UpdateSigningTimeAttr(CSM_Buffer *pbufError=NULL);
    void SetVersion();
    void SetSignerInfoVersion(SNACC::SignerInfo &SnaccSI);
    SM_RET_VAL ExtractSignerInfo(SNACC::AsnOid &SignatureOid, 
        SNACC::SignerInfo *&pSNACCSignerInfo);
    static SM_RET_VAL ExtractSignerInfo(SNACC::SignedData &SNACCSignedData, 
        SNACC::AsnOid &SignatureOid, SNACC::SignerInfo *&pSNACCSignerInfo);
    const SNACC::SignerInfo *GetFirstSIWithThisDigestOid(SNACC::AsnOid &HashOid);
};

//////////////////////////////////////////////////////////////////////////
//  CSM_MsgToAddSignatures
//  This class handles the addition of a signature to an SMIME SignedData
//  ASN.1 encoded component
//  (See comments above in CSM_MsgToVerify for the ASN.1 definition)
//  A number of elements of this message are loaded automatically by the
//  instances
//  specified as a parameter to SM_Sign():  the DigestAlgorithms, originator
//  certs, SignerInfos (based on sessions and attributes)
//  This particular class contains elements of both the sign and verify
//  operations due to the odd nature of the update of an existing msg
//  In particular, pay attention to the Counter Signature comments, where
//  the original message SignerInfos must be navigated and signed in a
//  particular manner
//  FOR COUNTER SIGNATURE:  It is expected that the user will navigate the
//  SignerInfo list to locate the desired SI to counter sign, pass this SI
//  class pointer to the CSM_CounterSignature->generateCounterSignature()
//  function and CSM_CounterSignature->getCounterSignature() for the
//  attribute generation
class CSM_MsgToAddSignatures : public CSM_MsgToVerify, public CSM_MsgToSign
{
private:
    void Clear() { m_SignatureVerifyStatus = 0; }  // DEFAULT Not Verified

public:
    // CONSTRUCTORS
    CSM_MsgToAddSignatures() { Clear(); }
    CSM_MsgToAddSignatures(const CSM_Content *pMsgBlob)
    { Clear(); CSM_MsgToVerify::SetEncapContentFromAsn1(*pMsgBlob); }
    CSM_MsgToAddSignatures(const CSM_Buffer *pBlob)
    { Clear(); CSM_MsgToVerify::SetEncodedBlob(pBlob); }
    CSM_MsgToAddSignatures(CSMIME *pCSMIME, const CSM_Buffer *pBlob,
        bool bVerifySignatureFlag=false,       
       bool bCMLUseToValidate = false, 
       bool bCMLFatalFail=false, 
       long lCmlSessionId=0, 
       long lSrlSessionId=0);
    virtual ~CSM_MsgToAddSignatures(){};

    // PUBLIC DATA MEMBERS
    long m_SignatureVerifyStatus;  // Not Verified=0, Verified=1, Failed=-1
};

//////////////////////////////////////////////////////////////////////////
// The application would use CSM_ReceiptMsgToVerify after determining
// via CSM_ContentInfoMsg that it has a ContentInfo->SignedData->Receipt
class CSM_ReceiptMsgToVerify : public CSM_MsgToVerify
{
private:
    // contains encoded msg for rcpt processing
    CSM_Buffer *m_pbufOriginalMessage;

    void GetOrigMsgSigDigest(CSM_MsgToVerify &smOrigMsg,        // IN
                             SNACC::Receipt         &snaccReceipt,     // IN
                             CSMIME          *pCSMIME,          // IN
                             CSM_Buffer      &bufMsgSigDigest); // OUT

    void InitMembers();

public:
    CSM_ReceiptMsgToVerify() { InitMembers(); }
    CSM_ReceiptMsgToVerify(const CSM_ContentInfoMsg *pCIM, CSMIME *pCSMIME);
    ~CSM_ReceiptMsgToVerify()
    { if (m_pbufOriginalMessage) delete m_pbufOriginalMessage; }

    long m_lProcessingResults;  // Bits set according to enum below.
    enum { msgSigDigestChecked=0x10,
           origMsgIDChecked=0x20,
           origMsgSignatureChecked=0x40 };

    // Set original message for SM_ValReceipt() processing
    void SetOriginalMessage(CSM_Buffer *pOrigMsg);

    void ReportMsgData(std::ostream &os);
    SM_RET_VAL Verify(CSMIME *pCSMIME);
    SM_RET_VAL Verify(CSMIME *pCSMIME, const CSM_Buffer &bufOrigMsgSigDigest, 
                      const SNACC::AsnOid &oidDigestOid);
};

//////////////////////////////////////////////////////////////////////////
// The application would use CSM_MsgToDecrypt to decrypt the content in
// a ContentInfo/EnvelopedData
class CSM_MsgToDecrypt : public CSM_DataToDecrypt
{
private:
    void Clear() { m_pRecipients=NULL; m_pOriginatorInfo=NULL; 
                   m_pACLOriginatorCertBuf = NULL;    m_poidEncryptionAlg = NULL;
                   m_poidDerivationAlg = NULL; }

    void AddSNACCRecipients();

    SNACC::AsnOid *m_poidDerivationAlg; // Specified OID for PWRI Derivation Alg
    SNACC::AsnOid *m_poidEncryptionAlg; // Specified OID for PWRI Encryption Alg

public:
    CSM_MsgToDecrypt() { Clear(); }
    //RWC;CSM_MsgToDecrypt(CSM_Buffer *pBlob) : CSM_DataToDecrypt(pBlob)
    //RWC;{ Clear(); if (pBlob) UpdateEncodedBlob(pBlob); }
    CSM_MsgToDecrypt(CSMIME *pCSMIME,
                     const CSM_Buffer *pBlob);    // IN, ContentInfo wrapped ED
    CSM_MsgToDecrypt(const CSM_ContentInfoMsg *pCIM);
    CSM_MsgToDecrypt(CSMIME *pCSMIME, const CSM_ContentInfoMsg *pCIM);
    ~CSM_MsgToDecrypt();

    // operational member
    void Decrypt(CSMIME *pCSMIME);
    void PreProc(CSMIME *pCSMIME);
    void PreProc(CSMIME *pCSMIME, const CSM_Buffer *pBlob);
    long ACLCheckoutCerts();

    // PWRI DerivationAlg
    void SetDerivationAlgOID(SNACC::AsnOid *pOID)
    { m_poidDerivationAlg = new SNACC::AsnOid(*pOID); }
    SNACC::AsnOid *AccessDerivationAlgOID() { return m_poidDerivationAlg; }

    // PWRI EncryptionAlg
    void SetEncryptionAlgOID(SNACC::AsnOid *pOID)
    { m_poidEncryptionAlg = new SNACC::AsnOid(*pOID); }
    SNACC::AsnOid *AccessEncryptionAlgOID() { return m_poidEncryptionAlg; }

    // Output member
    void ReportMsgData(std::ostream &os);

    // Encapsulates the RecipientInfos from the EnvelopedData
    CSM_RecipientInfoLst *m_pRecipients;

    // Encapsulates the OriginatorInfo from the EnvelopedData
    CSM_OriginatorInfo *m_pOriginatorInfo;

    CSM_Buffer *m_pACLOriginatorCertBuf;// allows app to pre-specify originator
                            //  Certificate buffer.  ONLY 1 listed, since all 
                            //  RIs have only 1 potential originator KARI cert.

};

//////////////////////////////////////////////////////////////////////////
// The application would use CSM_MsgToDecryptEncData to decrypt the content in
// a ContentInfo/EncryptedData
class CSM_MsgToDecryptEncData : public CSM_CommonData,
                                public CSM_DataToDecryptEncData
{
private:
    void Clear() { m_pOriginatorInfo = NULL; }

public:
    CSM_MsgToDecryptEncData() { Clear(); }
    CSM_MsgToDecryptEncData(const CSM_Buffer *pBlob) : CSM_DataToDecryptEncData(pBlob)
    { Clear(); if (pBlob) SetEncodedBlob(pBlob); }
    CSM_MsgToDecryptEncData(CSMIME *pCSMIME,
                            const CSM_Buffer *pBlob);  // IN, ContentInfo wrapped EncryptedData
    CSM_MsgToDecryptEncData(const CSM_ContentInfoMsg *pCIM);
    CSM_MsgToDecryptEncData(CSMIME *pCSMIME, const CSM_ContentInfoMsg *pCIM);
    ~CSM_MsgToDecryptEncData();

    // operational member
    void Decrypt(CSMIME *pCSMIME, CSM_Buffer *pCek);
    void PreProc(CSMIME *pCSMIME);
    void PreProc(CSMIME *pCSMIME, const CSM_Buffer *pBlob);

    // Output member
    void ReportMsgData(std::ostream &os);

    // Encapsulates the OriginatorInfo from the EncryptedData
    CSM_OriginatorInfo *m_pOriginatorInfo;
};

//////////////////////////////////////////////////////////////////////////
//  CSM_MsgToEncryptEncData
class CSM_MsgToEncryptEncData : public CSM_CommonData
{
private:
    SNACC::AsnOid *m_poidContentEncrypt; // Specified OID for content encryption

    long GetEncDataVersion();

    void Clear();

public:
    CSM_MsgAttributes *m_pUnprotectedAttrs; // use for unprotected attributes
    SNACC::EncryptedData     m_SnaccEncryptedData; // SNACC
    SNACC::AsnOid     *m_pKeyEncryptionOID; // OPTIONAL, usually extracted from
    //   Cert.  ES-DH KeyAgree uses
    //   same DH certs
    SNACC::AsnOid     *m_pKeyWrapOID;       // SubjectKeyIdentifier
    CSMIME            *m_pCsmime;           // To handle different CTILs for
    //   key agree/key wrap

    CSM_MsgToEncryptEncData();
    CSM_MsgToEncryptEncData(const CSM_Buffer *pBlob);
    CSM_MsgToEncryptEncData(const CSM_ContentInfoMsg *pCI);
    CSM_MsgToEncryptEncData(const CSM_Content *pContent);
    ~CSM_MsgToEncryptEncData();

    // operational member
    void Encrypt(CSMIME *pCSMIME, CSM_Buffer *Cek);

    // Encrypt and encode into private member pbfEncodedBlob
    void DataEncrypt(CSMIME     *pCSMIME,        // IN,logged-on Instance list
                     CSM_Buffer *pCek,           // IN,Content Encryption Key
                     const SNACC::AsnOid    *poidContentType,// IN, content type
                     const CSM_Buffer *pContent,       // IN, content for env. data
                     CSM_Alg    *pContentEncryptionAlg, // IN, content
                                                        //   encryption Alg
                     CSM_Buffer *pOutputBuf);    // OUT, resulting
                                                 //   EncryptedData/ContentInfo
    CSM_Buffer *GetEncodedContentInfo()
    {
        SNACC::AsnOid oidEncryptedData(SNACC::id_encryptedData);
        return (GetEncodedCI(&oidEncryptedData));
    }
    void SetContentEncryptOID(SNACC::AsnOid *pOID)
    { m_poidContentEncrypt = new SNACC::AsnOid(*pOID); }
    SNACC::AsnOid *AccessContentEncryptOID() { return m_poidContentEncrypt; }
    void ReportMsgData(std::ostream &os);
};

//////////////////////////////////////////////////////////////////////////
//  CSM_MsgToEncrypt
class CSM_MsgToEncrypt : virtual public CSM_CommonData, public CSM_DataToEncrypt
{
private:
    SNACC::AsnOid *m_poidContentEncrypt; // Specified OID for content encryption
    SNACC::AsnOid *m_poidDerivationAlg; // Specified OID for PWRI Derivation Alg
    SNACC::AsnOid *m_poidEncryptionAlg; // Specified OID for PWRI Encryption Alg
    bool m_bIncludeOrigCertsFlag;

    void Clear();

public:
    CSM_MsgToEncrypt();
    CSM_MsgToEncrypt(const CSM_Buffer *pBlob);
    CSM_MsgToEncrypt(const CSM_ContentInfoMsg *pCI);
    CSM_MsgToEncrypt(const CSM_Content  *pContent);
    ~CSM_MsgToEncrypt();

    // operational member
    void Encrypt(CSMIME *pCSMIME);

    void SetIncludeOrigCertsFlag(bool bFlag)
    { m_bIncludeOrigCertsFlag = bFlag; }
    bool GetIncludeOrigCertsFlag() { return m_bIncludeOrigCertsFlag; }
    void SetAddOriginatorAsRecipient(bool b)
    { CSM_DataToEncrypt::SetAddOriginatorAsRecipient(b); }
    bool GetAddOriginatorAsRecipient()
    { return CSM_DataToEncrypt::GetAddOriginatorAsRecipient(); }
    CSM_Buffer *GetEncodedContentInfo()
    {
        SNACC::AsnOid oidEnvelopedData(SNACC::id_envelopedData);
        return (GetEncodedCI(&oidEnvelopedData));
    }
    void SetContentEncryptOID(SNACC::AsnOid *pOID)
    { m_poidContentEncrypt = new SNACC::AsnOid(*pOID); }
    SNACC::AsnOid *AccessContentEncryptOID() { return m_poidContentEncrypt; }

    // PWRI DerivationAlg
    void SetDerivationAlgOID(SNACC::AsnOid *pOID)
    { m_poidDerivationAlg = new SNACC::AsnOid(*pOID); }
    SNACC::AsnOid *AccessDerivationAlgOID() { return m_poidDerivationAlg; }

    // PWRI EncryptionAlg
    void SetEncryptionAlgOID(SNACC::AsnOid *pOID)
    { m_poidEncryptionAlg = new SNACC::AsnOid(*pOID); }
    SNACC::AsnOid *AccessEncryptionAlgOID() { return m_poidEncryptionAlg; }

    void ReportMsgData(std::ostream &os);
    long CMLCheckoutCerts();
    long ACLCheckoutCerts();


    CSM_MsgCertCrls *m_pMsgCrtCrls;
    CSM_RecipientInfoLst *m_pRecipients;
    CSM_MsgAttributes *m_pUnprotectedAttrs; // use for unprotected attributes

};

//////////////////////////////////////////////////////////////////////////
// SFL LOW-LEVEL MESSAGE COMPONENT CLASSES
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// TBD, move these to sm_list.cpp?
typedef CSM_BufferLst CSM_GeneralAsnLst;

//////////////////////////////////////////////////////////////////////////
// This class encapsulates the SignerInfos from SignedData
// This class is only used for verification, not production of SignedData
class CSM_MsgSignerInfo
{
private:
    SNACC::SignerInfo *m_pSignerInfo;   // from the SignerInfos above
    CSM_CertificateChoiceLst *m_pCerts;  // certs for public key of SignerInfo
    //   for verification (May be loaded
    //   by incomming SignedData message
    //   or application for processing
    //   convenience)
    bool m_Verified;     // indicates that this SignerInfo has been
    //   signature verified

    void Clear()
    {
        m_pSignerInfo = NULL; m_pCerts = NULL; m_Verified = false;
        m_pUnsignedAttrs = NULL; m_pSignedAttrs = NULL; m_lProcessingResults=0;
        m_pPreHashBuffer = NULL; m_bCMLValidationFailed = false;
    }

public:
    CSM_MsgSignerInfo() { Clear(); }
    CSM_MsgSignerInfo(SNACC::SignerInfo *pSignerInfo);
    ~CSM_MsgSignerInfo();

    SNACC::SignerInfo *AccessSignerInfo() { return m_pSignerInfo; }

    // The following member functions will extract the
    //  specified component from the present SignerInfo
    //  (as set by the above "set. . . Info()" calls)
    CSM_IssuerAndSerialNumber *GetIssuerAndSerial();
    CSM_RecipientIdentifier *GetSignerIdentifier();
    CSM_Alg *GetDigestId();
    CSM_Alg *GetSignatureId();

    void SetSignerInfo(SNACC::SignerInfo &iSignerInfo);

    // load certs to be used for signature verification
    void SetSignerInfoCerts(CSM_CertificateChoiceLst &Certs);
    void UpdateSignerInfoCerts(CSM_CertificateChoiceLst *pCerts);
    bool IsVerified() { return m_Verified; }
    void SetVerified(bool bVerified) { m_Verified = bVerified; }
    CSM_CertificateChoiceLst *AccessCerts();
    CSM_CertificateChoiceLst *GetCerts();
    SM_RET_VAL LoadSICertPath(CSM_MsgCertCrls *pMsgCertCrls);
    SM_RET_VAL VerifySignerInfoCSs(CSMIME *pCsmime,
                                   CSM_MsgCertCrls *pMsgCertCrls,
                                   std::ostream *pos=NULL);
    void ReportMsgData(std::ostream &os);
    SM_RET_VAL Verify(
       CSMIME                   *pCSMIME,     // IN list of logons
       CSM_Buffer               *pOriginalEncapContent,// IN optional content
       SNACC::EncapsulatedContentInfo  *encapContentInfo,// IN SNACC encapContentInfo
       CSM_CertificateChoiceLst *pCerts,      // IN Originator(s) certs+++
       CSM_MsgAttributes        *pSignedAttrs,// IN optional signed attributes
       CSM_Buffer            *pSignerPublicKey=NULL,// IN optional, if pre-processed
       CSM_Alg               *palgSig=NULL);  // IN optional, if pre-processed
    char *GetCSVerifyDescription(long Result);
    CSM_MsgSignerInfo &operator = (CSM_MsgSignerInfo &msgSI);

	 // need to make SetTimeStampAttr static because of inheritance 
    // issues when adding a TimeStampToken unsignedAttr to a SignerInfo
    static SM_RET_VAL SetTimeStampAttr(SNACC::SignerInfo &msgSI,SNACC::TimeStampToken &snaccTST);

    static SM_RET_VAL VerifyTimeStampToken(SNACC::SignerInfo &msgSI, CSMIME *pCsmime, 
                                    SNACC::TimeStampToken &snaccTST,
									CSM_CertificateChoice *pSigningCert,
                                    std::ostream *pOstrm = NULL,
									bool bCMLFatalFail=NULL,
									bool bCMLUseToValidate=NULL,
		   					   unsigned long ulCmlSessionId=NULL,
                           unsigned long ulSrlSessionId=NULL);  
                                          

    enum
    {
        ALL_SUCCEEDED,
        SOME_SUCCEEDED,
        SOME_FAILED,
        ALL_FAILED,
        NONE_PRESENT,
        NONE_VERIFIED
    };

    CSM_MsgAttributes *m_pUnsignedAttrs;// message attributes, most are common
    CSM_MsgAttributes *m_pSignedAttrs;  // message attributes, most are common
    CSM_Buffer *m_pPreHashBuffer;   // OPTIONAL, Pre-Loaded hash result, no
                                    //  need to re-calculate.

    long m_lProcessingResults;  // Bits set according to enum below.
    enum { messageDigestChecked=0x01,
           msgSignatureVerified=0x02 };
    bool m_bCMLValidationFailed;
};

//////////////////////////////////////////////////////////////////////////
class CSM_MsgSignerInfos : public CSM_MsgSignerInfoLst
{
private:
    // designates current SignerInfo with
    //  "flagApplicable" flag set by PreProc; this
    //  implies that this SignerInfo can be processed
    //  by the PreProc sessions
    SNACC::SignerInfos *m_pNextApplicableSignerInfo;

public:
    CSM_MsgSignerInfos() { m_pNextApplicableSignerInfo=NULL; }
    CSM_MsgSignerInfos(SNACC::SignerInfo *pSNACCSignerInfo)
    {
        m_pNextApplicableSignerInfo=NULL;
        CSM_MsgSignerInfo *pTmpSI=&(*append());
        pTmpSI->SetSignerInfo(*pSNACCSignerInfo);
    }
    CSM_MsgSignerInfos(CSM_MsgSignerInfo *pCSMSignerInfo)
    {
        m_pNextApplicableSignerInfo=NULL;
        if (pCSMSignerInfo->AccessSignerInfo())
        {
           CSM_MsgSignerInfo *pTmpSI=&(*append());
           pTmpSI->SetSignerInfo(*pCSMSignerInfo->AccessSignerInfo());
        }      // END if pCSMSignerInfo->AccessSignerInfo()
    }
    ~CSM_MsgSignerInfos() {}
    SM_RET_VAL VerifyMsgCSs(CSMIME *pCsmime, CSM_MsgCertCrls *pMsgCertCrls,
                            std::ostream *pos=NULL);
    void ReportMsgData(std::ostream &os);
};

// ***********************************************************************
// CSM_MsgToCounterSign
//
//   It is expected that the user will navigate the SignerInfo list to
//   locate the desired SI to counter sign, pass this SI class pointer
//   to the CSM_CounterSignature->ProduceCounterSignature() function
//   and CSM_CounterSignature->GetCounterSignature() for the attribute
//   generation
// ***********************************************************************
class CSM_MsgToCounterSign : public CSM_MsgToAddSignatures
{
private:
    // PRIVATE DATA MEMBERS
    bool m_bCSMultiValueAttrFlag;   // TRUE LOAD SET FOR MULTI-VALUE ATTRIBUTES
    CSM_RecipientIdentifier *m_pSID;// Signer ID

    // PRIVATE MEMBER FUNCTIONS
    SM_RET_VAL PutSignerInfo(CSM_CSInst *pCSInst,
                             SNACC::SignedData *lpSignData,
                             SNACC::SignerInfo *&lpSignerInfo);
    void Clear();

public:
    // CONSTRUCTORS
    CSM_MsgToCounterSign() { Clear(); }  // DEFAULT CONSTRUCTOR
    CSM_MsgToCounterSign(CSMIME *pCSMIME, CSM_Buffer *pBlob,
        bool bVerifySignatureFlag=false);
    virtual ~CSM_MsgToCounterSign();            // DESTRUCTOR

    // MEMBER FUNCTIONS
        // LOADS THE COUNTERSIGNATURE VALUE, POSSIBLY FROM AN EXTERNAL SOURCE
    SM_RET_VAL LoadCounterSignature(CSM_MsgSignerInfo &CSSignerinfo);
    SM_RET_VAL ProduceCounterSignature(CSMIME *pCSMIME);
    SM_RET_VAL SetSICounterSigner(CSM_RecipientIdentifier &);

    // PUBLIC DATA MEMBERS
    CSM_MsgSignerInfo m_CounterSignatureSI; // CounterSignature SignerInfo
};



////////////////////////////////////////////////////////////////////////////////
//
// Class:  CSM_MsgToTimeStamp
//
// Description:  Class that inherits the CSM_MsgToAddSignatures class and 
//               members that help build the TimeStampToken data
// 
// Member Functions:
//  Private:
//    CSM_RecipientIdentifier *m_pSID
//    Clear
//  Public:
//    CSM_MsgToTimeStamp constructors
//    ~CSM_MsgToTimeStamp destructor
//    operator =
//    SetTimeStamptoken
//    SetSID
//    LoadSignerInfoWithTST
//    VerifyTimeStampToken
//
// Member Variables:
//  Public:
//
////////////////////////////////////////////////////////////////////////////////
class CSM_MsgToTimeStamp : public CSM_MsgToAddSignatures
{
private:
    // PRIVATE DATA MEMBERS
    CSM_RecipientIdentifier *m_pSID;           // Signer ID

    void Clear();

public:
    // CONSTRUCTORS
    CSM_MsgToTimeStamp() { Clear(); }         // DEFAULT CONSTRUCTOR

    CSM_MsgToTimeStamp(CSMIME *pCSMIME,       // logins
       const CSM_Buffer &SDBlob,              // original SD
       bool bVerifySignatureFlag=false,
       bool bCMLUseToValidate = false, 
       bool bCMLFatalFail=false, 
       long lCmlSessionId=0, 
       long lSrlSessionId=0);      // verify flag for original SD

    virtual ~CSM_MsgToTimeStamp();            // DESTRUCTOR

    // MEMBER FUNCTIONS
    CSM_MsgToTimeStamp &operator = (const CSM_MsgToTimeStamp &MsgToTimeStamp);
    void SetTimeStamptoken();  // appends the TimeStampToken
    SM_RET_VAL SetSID(CSM_RecipientIdentifier &RecipId); // sets signer id member
    SM_RET_VAL LoadSignerInfoWithTST(SNACC::TimeStampToken &snaccTST);
    SNACC::SignerInfo *AccessSignerInfoToTimeStamp();
    SM_RET_VAL VerifyTimeStampToken(CSMIME *pCsmime,std::ostream *pOstrm=NULL);

    // PUBLIC DATA MEMBERS
};

/**************************************************************************/
/* The content type of the encapsulated content in the message - may      */
/* provide content type as an integer value (built_in) or as an OID       */
/* (external).                                                            */
/**************************************************************************/
class CSM_CntType
{
public:
    long m_BuiltIn; /* content type */
    SNACC::AsnOid m_External; /* object identifier (OID) (not ASN! encoded) */
    long m_Subtype; /* ContentType subtype */
};

/**************************************************************************/
/*  Handle SignerInfo authenticated and Unsigned Attributes.              */
/**************************************************************************/
/**************************************************************************/
/* Structure for signed receipt requested                                 */
/**************************************************************************/
class CSM_ReceiptRequest
{
private:
    SNACC::AllOrFirstTier *m_pallOrFirstTier;
    CSM_GeneralNames *m_pReceiptsFrom;
public:
    CSM_ReceiptRequest() { m_pallOrFirstTier=NULL; m_pReceiptsFrom=NULL; }
    CSM_ReceiptRequest(CSM_ReceiptRequest &CRecReq);
    ~CSM_ReceiptRequest();

    SNACC::AllOrFirstTier *AccessfirstTierRecipients() { return m_pallOrFirstTier; }
    CSM_GeneralNames *AccessReceiptsFrom() { return m_pReceiptsFrom; }

    void SetallReceipts();
    void SetfirstTierRecipients();
    void UpdateReceiptsFrom(CSM_GeneralNames *pReceiptDNs);

    CSM_Buffer m_SignedContentIdentifier;
    //CSM_GeneralNames m_ReceiptsTo;
    CSM_GeneralNamesLst m_ReceiptsTo;

    CSM_Buffer *GetEncodedReceiptRequest();

};

/**************************************************************************/
/*  CertID structure                                                      */
/**************************************************************************/
class CSM_CertID
{
public:
    CSM_CertID () { m_pIssuerSerial = NULL; };
    CSM_CertID (const CSM_CertID &CertId) 
    { m_pIssuerSerial = NULL; *this = CertId; }

    ~CSM_CertID () { if (m_pIssuerSerial) delete m_pIssuerSerial; 
       m_pIssuerSerial = NULL; }

    CSM_CertID &operator = (const CSM_CertID &ID);

    CSM_Buffer     m_CertHash;
    SNACC::IssuerSerial *m_pIssuerSerial;
};

/**************************************************************************/
/*  PolicyQualifierInfo structure                                         */
/**************************************************************************/
class CSM_PolicyQualifierInfo
{
public:
    CSM_PolicyQualifierInfo() { m_pQualifier=NULL; }
    CSM_PolicyQualifierInfo(const CSM_PolicyQualifierInfo &sPolicyQualifierInfo);
    ~CSM_PolicyQualifierInfo() { if (m_pQualifier) delete m_pQualifier; }

    CSM_PolicyQualifierInfo &operator =
        (const CSM_PolicyQualifierInfo &sPolicyQualifierInfo);

    SNACC::AsnOid m_PolicyQualifierId;
    //Value is expected to be ASN.1 Encoded
    CSM_Buffer *m_pQualifier;
};

/**************************************************************************/
/* Structure for Policy Info                                              */
/**************************************************************************/
class CSM_PolicyInfo
{
public:
    CSM_PolicyInfo() { m_pPolicyQualifiers = NULL; }
    CSM_PolicyInfo(const CSM_PolicyInfo &sPolicyInfo);
    ~CSM_PolicyInfo() { if (m_pPolicyQualifiers) delete m_pPolicyQualifiers; }

    CSM_PolicyInfo &operator = (const CSM_PolicyInfo &sPolicyInfo);

    SNACC::AsnOid          m_CertPolicyId;
    CSM_PolicyQualifierLst *m_pPolicyQualifiers;
};

/**************************************************************************/
/* Structure for signing certificate                                      */
/**************************************************************************/
class CSM_SigningCertificate
{
public:
    CSM_SigningCertificate() { m_pPolicies=NULL; }
    CSM_SigningCertificate(CSMIME &csmime, const CSM_Buffer &CertBuf, 
                        const CSM_IssuerAndSerialNumber &CertIssSN);
    CSM_SigningCertificate(const CSM_SigningCertificate &sCert);
    ~CSM_SigningCertificate() { if(m_pPolicies) delete m_pPolicies; }

    // sib TBD SM_RET_VAL LoadNextCertId(CSM_Buffer *CertFileName, CSMIME *pCsmime);
    SM_RET_VAL LoadNextCertId(const char *pszLogin, CSMIME *pCsmime);
    SM_RET_VAL LoadNextCertId(CSM_CertificateChoice *pCertChoice, CSMIME *pCsmime); 
    // may need LoadNextCertId(const char *pszLogin, const IssuerSerial *pIssSn, CSMIME *pCSMIME);
    
    SM_RET_VAL LoadPolicyLst(const char *policy, CSM_PolicyQualifierLst *pQualList);

    CSM_CertIDLst m_Certs;
    CSM_PolicyInfoLst *m_pPolicies;

    CSM_SigningCertificate &operator = (const CSM_SigningCertificate &sCert);
};

/**************************************************************************/
/*  SMIME Capabilities structure                                          */
/**************************************************************************/
class CSM_SmimeCapability
{
public:
    CSM_SmimeCapability() { m_pParameters=NULL; }
    CSM_SmimeCapability(const CSM_SmimeCapability &that) 
    { m_pParameters=NULL; *this = that; }
    ~CSM_SmimeCapability();
    CSM_SmimeCapability & operator = (const CSM_SmimeCapability &smimeCapability);
    SNACC::AsnOid m_capabilityID;
    //Params is expected to be ASN.1 Encoded
    CSM_Buffer *m_pParameters;
};

/**************************************************************************/
/*  Security Categories structure                                         */
/**************************************************************************/
class CSM_SecCat
{
public:
    CSM_SecCat() { m_pValue=NULL; }
    CSM_SecCat(const CSM_SecCat &that) 
    { m_pValue=NULL; *this = that; }
    ~CSM_SecCat();
    CSM_SecCat & operator = (const CSM_SecCat &secCat);
    SNACC::AsnOid m_Type;
    //Value is expected to be ASN.1 Encoded
    CSM_Buffer *m_pValue;
};

/**************************************************************************/
/* Structure def for Security Label none of this data is ASN1 encoded     */
/**************************************************************************/
class CSM_SecLbl
{
public:
    CSM_SecLbl()
    { m_plSecClass=NULL; m_pPmark=NULL; m_pSecCats=NULL; }
    CSM_SecLbl(const CSM_SecLbl &qqq);
    ~CSM_SecLbl();
    SNACC::AsnOid m_PolicyId;     /* Security Policy Identifier */
    long *m_plSecClass;        /* Security Classification */
    CSM_Buffer *m_pPmark;    /* Privacy Mark */
    CSM_SecCatLst *m_pSecCats;/* Security Categories */
    CSM_SecLbl &operator = (const CSM_SecLbl &pseclabel);
    SNACC::ESSSecurityLabel *GetSNACCSecLbl();

};

//////////////////////////////////////////////////////////////////////////
class CSM_GeneralAsn
{
public:
    SNACC::AsnOid m_AsnOid;       /** OID for Any in strList. **/
    CSM_BufferLst m_StrLst;

    CSM_GeneralAsn() {}
};


class CSM_ContentReference
{
public:
    SNACC::AsnOid    m_OID;         // OID describing the description
    CSM_Buffer m_SignedContentIdentifier;
    CSM_Buffer m_OriginatorSignatureValue;
};

//////////////////////////////////////////////////////////////////////////
class LIBCERTDLL_API CSM_Time
{
public:
   CSM_Time()
       { m_lpszTime = NULL; }
   CSM_Time(const CSM_Time &cTime)
   {
       m_lpszTime = NULL;
       *this = cTime;
   }
   CSM_Time(const char *lpszTime, int len, int iType);
   CSM_Time(const char *lpszTime, bool bUTCTime); // UTC interpreted if flag is true.
   ~CSM_Time() { if (m_lpszTime) free(m_lpszTime); }
   long m_type;         // DEFINED in sm_cms.asn: SigningTime::utcTimeCid,
                        //                        SigningTime::generalTimeCid

   char *m_lpszTime;
   CSM_Time &operator = (const CSM_Time &cTime)
   {
       if (m_lpszTime != NULL) free(m_lpszTime);
       if (cTime.m_lpszTime)
        m_lpszTime = strdup(cTime.m_lpszTime);
       else
        m_lpszTime = NULL;
       m_type = cTime.m_type;
       return(*this);
   }
   void SetTime(const char *lpszTime, bool bUTCTime);
};

//////////////////////////////////////////////////////////////////////////
class CSM_Attrib : public CSM_AttribBase
{
private:
    void ReportHexBuffer(std::ostream &os, char *ptr, int iLen);

public:
    CSM_Attrib();
    CSM_Attrib(const CSM_Attrib &Attrib);
    // The following constructor handles MessageDigest
    CSM_Attrib(CSM_Buffer *pMessageDigest);
    // TBD, there's no constructor to build a MsgSigDigest attribute
    CSM_Attrib(const CSM_Time &cSigningTime);
    CSM_Attrib(SNACC::Countersignature *pSNACCCounterSignature);
    CSM_Attrib(CSM_ReceiptRequest *pReceiptRequest);
    CSM_Attrib(CSM_SigningCertificate *pSigningCertificate);
    CSM_Attrib(SNACC::ContentHints &SNACCContentHints);
    CSM_Attrib(CSM_ContentReference *pContentReference);
    CSM_Attrib(CSM_SecLbl *pSecLbl);
    CSM_Attrib(CSM_SmimeCapabilityLst *pSmimeCapLst);
    CSM_Attrib(CSM_EquivalentLabels *pEquLbls);
    CSM_Attrib(SNACC::MLExpansionHistory *pMlLst);
    CSM_Attrib(CSM_GeneralAsnLst *pGeneralAsnLst);
    CSM_Attrib(SNACC::AsnOid *pContentType);
    CSM_Attrib(const SNACC::AsnOid &Oid,const CSM_Buffer &SNACCAnyBuf);
    CSM_Attrib(const SNACC::SMIMEEncryptionKeyPreference &sek);
    CSM_Attrib(SNACC::TimeStampToken *pTimeStampToken); 
    ~CSM_Attrib();

    //Clean out variables before usage
    void AttribDestroy(bool bDestroyEncoded=true);
    void Clear();

    // Variable used in navigating for CounterSignatures
    long m_lAttrValueIndex;
    long m_lMultiAttrIndex;

    union
    {
        CSM_Buffer *m_pMessageDigest;
        CSM_Buffer *m_pContentIdentifier;
        CSM_Buffer *m_pMsgSigDigest;
        CSM_Time *m_pSigningTime ;
        SNACC::Countersignature *m_pSNACCCounterSignature;
        CSM_ReceiptRequest *m_pReceiptRequest;
        CSM_SigningCertificate *m_pSigningCertificate;
        SNACC::ContentHints  *m_pContentHints;
        CSM_ContentReference *m_pContentReference;
        CSM_SecLbl *m_pSecurityLabel;
        CSM_EquivalentLabels *m_pEqulbls;
        CSM_SmimeCapabilityLst *m_pSmimeCapLst;
        SNACC::MLExpansionHistory *m_pSNACCMlExpHist;
        CSM_GeneralAsnLst *m_pGeneralAsnLst; // OID & ASN encoded data list
        SNACC::AsnOid *m_pContentType;
        SNACC::TimeStampToken *m_pTimeStampToken;  
    };

    void SetMessageDigest(CSM_Buffer *pMessageDigest);
    void SetContentIdentifier(CSM_Buffer *pContentIdentifierBuf);
    void SetMsgSigDigest(CSM_Buffer *pMsgSigDigest);
    void SetSigningTime(const CSM_Time &cSigningTime);
    void SetCounterSignature(SNACC::Countersignature *pSNACCCounterSignature);
    void SetReceiptRequest(CSM_ReceiptRequest *pReceiptRequest);
    void SetSigningCertificate(CSM_SigningCertificate *pSigningCertificate);
    void SetContentHints(SNACC::ContentHints &SNACCContentHints);
    void SetContentReference(CSM_ContentReference *pContentReference);
    void SetSecLbl(CSM_SecLbl *pSecLbl);
    void SetEquivalentLabels(CSM_EquivalentLabels *pEqulbls);
    void SetMLExpansionHistory(SNACC::MLExpansionHistory *pSNACCMlLst);
    void SetSMIMECapabilities(CSM_SmimeCapabilityLst *pSmimeCapLst);
    void SetContentType(SNACC::AsnOid *pContentType);
    void SetGeneralASN(CSM_GeneralAsnLst *pGeneralAsnLst);
    void SetSMIMEEncryptionKeyPreference(const SNACC::SMIMEEncryptionKeyPreference &sek);
    void SetTimeStampToken(SNACC::TimeStampToken *pTimeStampToken);  

    CSM_Attrib & operator=(const CSM_Attrib &Attrib);
    bool operator == (const CSM_Attrib &that);

    void Report(std::ostream &os);

    static void Load_GeneralName(CSM_DN *pDNS,SNACC::GeneralName *&pGenName);
    static void UnLoad_GeneralName(SNACC::GeneralName &GenName, CSM_DN *&pDNS);
    //Unloading AuthAttributes and UnsignedAttribues
    SM_RET_VAL SetAttribByOid(const SNACC::AsnOid &Oid,const CSM_Buffer &SNACCAnyBuf);

    char *GetGenNameString(CSM_GeneralName &GenName);

    // CHECK FUNCTIONS FOR VALID ATTRIBUTE VALUES
    bool CheckSignedAttr();
    bool CheckUnsignedAttr();
    bool CheckUnprotectedAttr();
    bool CheckCounterSignatureSignedAttr();
    bool CheckCounterSignatureUnsignedAttr();
    int  CheckSigningTime();   // returns 1 if valid; 0 if invalid but convertable; 
	                           // -1 if error and not convertable

	// optional CSInstance specification for Sign()
    char *m_pszCSInst;   // IDs the instance's SignerInfo to contain this attr;
                         //   MAY BE NULL to indicate all SignerInfos
};


//////////////////////////////////////////////////////////////////////////
// CSM_MsgAttributes represents the entire collection of either
// Signed or Unsigned attributes in a SignedData
class CSM_MsgAttributes
{
private:
    CSM_Buffer       *m_pEncodedAttrs;
    CSM_Buffer       *m_pEncodedAttrsFromMessage;
protected:
    void ExtractSNACCAttr(SNACC::Attribute &SNACCAttr, long lMultiAttrIndex);
public:
    // Constructors
    CSM_MsgAttributes();

    CSM_MsgAttributes(SNACC::UnsignedAttributes &SNACCUnsignedAttributes);
    CSM_MsgAttributes(SNACC::SignedAttributes &SNACCSignedAttributes);
    ~CSM_MsgAttributes();

    CSM_AttribLst    *m_pAttrs;

    long              m_lAttributeIndex;
    SNACC::Countersignature *m_pCurrentCS;

    // TBD? THERE IS NO FUNCTION TO 'Get' sMIMEEncryptionKeyPreference
    // Add individual attributes
    bool IsAllowedMultipleAttribs(SNACC::AsnOid &AttribOID);
    CSM_Buffer *GetMessageDigest();
    CSM_Buffer *GetMsgSigDigest();
    CSM_Buffer *GetContentIdentifier();
    CSM_Time *GetSigningTime();
    SNACC::Countersignature *GetCounterSignature();
    CSM_ReceiptRequest *GetReceiptRequest();
    CSM_SigningCertificate *GetSigningCertificate();
    SNACC::ContentHints *GetContentHints();
    CSM_ContentReference *GetContentReference();
    CSM_SecLbl *GetSecurityLabel();
    CSM_SmimeCapabilityLst *GetSmimeCapabilityLst();
    SNACC::SMIMEEncryptionKeyPreference *GetSMIMEEncryptionKeyPreference();
    CSM_EquivalentLabels *GetEquivalentLabels();
    SNACC::MLExpansionHistory *GetMailList();
    CSM_GeneralAsnLst *GetGeneralAsnLst();
    SNACC::AsnOid *GetContentType();
    SNACC::TimeStampToken *GetTimeStampToken();  

    SNACC::Countersignature *AccessFirstCS();
    SNACC::Countersignature *AccessNextCS();

    void AddAttrib(CSM_Attrib &Attrib);
    void UnLoadSNACCSignedAttrs(SNACC::SignedAttributes &SNACCSignedAttributes);
    void UnLoadSNACCUnsignedAttrs(SNACC::UnsignedAttributes &SNACCUnsignedAttributes);
    void UnLoadSNACCUnprotectedAttrs(SNACC::UnprotectedAttributes
        &SNACCUnprotectedAttributes);
    SNACC::SignedAttributes *GetSNACCSignedAttributes();
    SNACC::UnsignedAttributes *GetSNACCUnsignedAttributes();
    SNACC::UnprotectedAttributes *GetSNACCUnprotectedAttributes();
    bool CheckSignedAttrs(CSM_Buffer *pbuf=NULL);
    bool CheckUnsignedAttrs(CSM_Buffer *pbuf=NULL);
    bool CheckUnprotectedAttrs(CSM_Buffer *pbuf=NULL);
    // CHECK FOR VALID COUNTERSIGNATURE ATTRIBUTE
    // VALUES (Signing Time, Signing Certificate)
    bool CheckCounterSignatureSignedAttrs(CSM_Buffer *pbuf=NULL);
    bool CheckCounterSignatureUnsignedAttrs(CSM_Buffer *pbuf=NULL);
    CSM_Buffer *GetSignedEncodedAttrs();
    CSM_Buffer *GetUnsignedEncodedAttrs();
    CSM_Buffer *AccessEncodedAttrsFromMessage();   // DO NOT FREE RESULTS.
    void SetSignedEncodedAttrs(CSM_Buffer *pSignedBuf);
    void SetUnsignedEncodedAttrs(CSM_Buffer *pUnsignedBuf);
    void SetEncodedAttrsFromMessage(CSM_Buffer *pBuf);
    CSM_AttribLst::iterator *FindAttrib(const SNACC::AsnOid &coid);
    void Report(std::ostream &os);
};



//////////////////////////////////////////////////////////////////////////
class CSM_OriginatorInfo //RWC;10/9/02: private CSM_MsgCertCrls
{
private:
    void Clear() { m_pMsgCertCrls = NULL; }

public:
    CSM_MsgCertCrls *m_pMsgCertCrls;

    CSM_OriginatorInfo() { Clear(); }
    CSM_OriginatorInfo(CSM_BufferLst *pCerts);
    CSM_OriginatorInfo(CSM_CertificateChoiceLst *pCerts);
    CSM_OriginatorInfo(SNACC::CertificateSet *pSnaccCertSet);
    CSM_OriginatorInfo(SNACC::OriginatorInfo *pSnaccOI);
    ~CSM_OriginatorInfo();

    // AddSNACCOrigInfo adds the provided SNACC OriginatorInfo to
    // this class
    void AddSNACCOrigInfo(SNACC::OriginatorInfo *pOI);
    // GetOriginatorDns returns the DNs of each cert in this class
    CSM_DNLst *GetOriginatorDns();
    // SetSNACCUKMs adds the provided UserKeyingMaterials to m_pUKMs
};


//////////////////////////////////////////////////////////////////////////
// This class is unusual; it takes a decrypted message (assuming
// the login list contains a private key matching a RecipientInfo), then
// optionally delete 1 or more RIs, create a new RI, then
// re-encode the result LEAVING THE ENCRYPTED CONTENT INTACT (not re-computed/
// re-encrypted).
// For operational use, this class is treated as a CSM_MsgToEncrypt, with
// all API features intact for creating a new RecipientInfo in the message.
class CSM_MsgToReEncrypt: public CSM_MsgToEncrypt, private CSM_DataToDecrypt
{
public:
   //CSM_MsgToReEncrypt();
   CSM_MsgToReEncrypt(CSMIME &Csmime, CSM_MsgToDecrypt &DecryptedMsg);
   ~CSM_MsgToReEncrypt();
   // "GetReEncryptedContentInfo()" creates a new RecipientInfo, if requested 
   //   by the login list.  If a new RecipientInfo is not required, then simply
   //   call "GetEncodedContentInfo()" directly to re-encode the message.
   CSM_Buffer *GetReEncryptedContentInfo();
   CSM_Buffer *GetReEncodedContentInfo();

private:
   // The following call will not succeed if the decrypting CTIL is not
   //  capable of exporting a clear MEK (at this time only sm_rsa and sm_free3 
   //  can do this).  This call is only necessary if a new RecipientInfo is to
   //  be generated; DO NOT CALL THIS METHOD IF THE message is to simply be re-
   //  encoded with a few missing RecipientInfo(s).
   void SetEncryptInternalData(CSM_MsgToDecrypt &DecryptedMsg,
                         const CSM_CertificateChoiceLst *pCertList);
}; 

////////////////////////////////////////////////////////////////////////////////
//
// Class:  CSM_TimeStampTokenInfo
//
// Description:  Class that inherits the SNACC::TSTInfo class and 
//               members that help build the TSTInfo data
// 
// Member Functions:
//  Private:
//    Clear
//  Public:
//    CSM_TimeStampInfo constructors
//    ~CSM_TimeStampInfo destructor
//    operator =
//    GetUntrustedTime
//    LoadCertInfo
//    SetMessageImprint
//    GetFirstPolicyIdFromCert
//    SetSerialNumber
//
// Member Variables:
//  NONE
//
////////////////////////////////////////////////////////////////////////////////
class  CSM_TimeStampTokenInfo : public SNACC::TSTInfo
{
private:

public:

   CSM_TimeStampTokenInfo() {};                         // default constructor  
   CSM_TimeStampTokenInfo(SNACC::TimeStampReq &TSReq);  // constructor
   ~CSM_TimeStampTokenInfo() {};                        // destructor

   // get functions
   static CTIL::CSM_Buffer *GetUntrustedTime(void);  

   // load/set functions
   SM_RET_VAL LoadCertInfo(SNACC::GeneralName &snaccTsa);
   SM_RET_VAL SetMessageImprint();
   static SNACC::AsnOid *GetFirstPolicyIdFromCert(const SNACC::Certificate &Cert);  // set the policy id from the instance extension
   SM_RET_VAL SetSerialNumber(int serialNum);


};

////////////////////////////////////////////////////////////////////////////////
//
// Class:  CSM_TimeStampToken
//
// Description:  Class that inherits the SNACC::TSTInfo class and 
//               members that help build the TSTInfo data
// 
// Member Functions:
//  
//  Private:
//    clear
//
//  Public:
//    CSM_TimeStamp constructors
//    ~CSM_TimeStamp destructor
//    operator =
//    GetTimeStampTokenInfo
//    GetTimeStampToken
//
// Member Variables:
//
//  Private:
//    SNACC::TimeStampToken *m_pTimeStampToken
//    CSM_Buffer *m_pTimeStampTokenBuf;
//
//  Public:
//    SNACC::TSTInfo m_OID
//    CSM_Buffer     *m_pTimeStampTokenBuf;
//
////////////////////////////////////////////////////////////////////////////////
class  CSM_TimeStampToken
{
private:
   SNACC::TimeStampToken *m_pTimeStampToken;
   void Clear() { m_pTimeStampToken = NULL;   }

public:
   CSM_TimeStampToken() { Clear(); }
   CSM_TimeStampToken(const CSM_TimeStampToken &TSToken);
   CSM_TimeStampToken(const SNACC::TimeStampToken &TSToken);
   ~CSM_TimeStampToken() { if(m_pTimeStampToken) delete m_pTimeStampToken; }
   CSM_TimeStampToken &operator = (const CSM_TimeStampToken &TSToken);

   SNACC::AsnOid    m_OID;               // OID describing the buffer

   // member functions
   SNACC::TSTInfo            *GetTimeStampTokenInfo();

   // gets a copy of m_pTimeStampToken
   SNACC::TimeStampToken     *GetTimeStampToken(); 
   // points to m_pTimeStampToken
   SNACC::TimeStampToken     *AccessTimeStampToken();  

};

_END_SFL_NAMESPACE

#endif // _SM_API_H_
// EOF sm_api.h
