/* @(#) sm_apiCert.h 1.28 10/25/00 14:43:19 */

//////////////////////////////////////////////////////////////////////////
//
// FILE:  sm_apiCert.h
// DESCRIPTION:
//  This include file was created to allow a certain isolation from the
//  SFL definitions for shared lo-level operations.
//
//////////////////////////////////////////////////////////////////////////
#ifndef _SM_APICERT_H_
#define _SM_APICERT_H_

#define LIBCERTDLL_API     // HARD-CODE to enforce static build ONLY!
                           //  CHANGED from original design...  Applies to both
                           //  SNACC and internal definitions.

#ifndef LIBCERTDLL_API      // DEFINE on compile line to "" for Static refs
#ifdef WIN32
#ifdef LIBCERTDLL_EXPORTS
#define LIBCERTDLL_API __declspec(dllexport)
#else
#define LIBCERTDLL_API __declspec(dllimport)
#endif          // LIBCERTDLL_EXPORTS
#else           // Handle Unix...
#define LIBCERTDLL_API
#endif          // WIN32
#endif          // ifndef LIBCERTDLL_API

#ifndef NO_NAMESPACE
#ifdef PRE_R2_3
#define _BEGIN_CERT_NAMESPACE using namespace CTIL; \
    using CTIL::CSM_Buffer; \
    namespace CERT {     using CTIL::CSM_BufferLst;
#else   //PRE_R2_3
#define _BEGIN_CERT_NAMESPACE using namespace CTIL; \
    using CTIL::CSM_Buffer; \
    namespace CERT {
#endif //PRE_R2_3
#define _END_CERT_NAMESPACE }
#else
#define _BEGIN_CERT_NAMESPACE
#define _END_CERT_NAMESPACE
#endif


// SPECIFY SPECIFIC OVERRIDE STRUCTURE ALIGNMENT FACTOR;
//  NECESSARY TO OVERRIDE ANY OTHER PROJECT SETTINGS in which this include may
//  be referenced.  This alignment forces all references to the SFL structures
//  to be consistent with the DLL/LIB objects.
#ifdef WIN32
#pragma pack(8)
#pragma warning( disable : 4127 4710 )
#endif
//
//

#include "sm_apiCtilMgr.h"
#include "cmlasn.h"
#include "cmapi_cpp.h"         // for CML::CRL CLASS type

// SNACC Generated headers
#include "sm_VDASupport_asn.h"

_BEGIN_CERT_NAMESPACE 
//using CML::ASN::DN;
//typedef CML::ASN::DN CSM_DN;
typedef CML::ASN::DN CSM_DN;
typedef List<CSM_DN> CSM_DNLst;

#define SM_CERT_DEC_ERROR               2000
#define SM_NO_CERT_SET                  1007
#define SM_BAD_PUBLIC_VALUE             1008

class CSM_CertificateChoice;
class CSM_GeneralName;
class CSM_CertificateList;
class CSM_CSInst;
class MAB_Entrydef;
class CSM_GeneralNames;

//
//
class CSM_PrivData
{
public:
   CSM_Buffer    m_BufPriv;
   CSM_BufferLst m_BufCertList;
};
typedef List<CSM_PrivData> CSM_PrivDataLst;



// HERE IS A DECLARATION FOR A GLOBAL OVERRIDE OF THE INSERTION OPERATOR
//   This is so we can control output formatting regardless of where the
//   application directs the output (screen, file or memory).
//ostream LIBCERTDLL_API &operator << (std::ostream &os, char *a);

//////////////////////////////////////////////////////////////////////////
// List Typedefs
typedef List<CSM_CertificateChoice> CSM_CertificateChoiceLst;
typedef List<CSM_GeneralName> CSM_GeneralNameLst;
typedef List<CSM_GeneralNames> CSM_GeneralNamesLst; 
typedef List<CSM_CSInst> CSM_CSInstLst;

//////////////////////////////////////
// CLASS LIBCERTDLL_API DEFINITIONS //
//////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

/**************************************************************************/
//RWC; this additional (and confusing) duplicate CSM_Alg definition was created
//RWC;  to avoid compiler/linker issues when the CML defines AlgoritnmIdentifier.
//RWC;  This class is the same, the only functionality here is to allow easy
//RWC;  assignments to/from the CTIL::CSM_AlgVDA definition; 
//RWC;  Our SNACC::AlgorithmIdentiferVDA is the same as SNACC::AlgorithmIdentifier.
class CSM_Alg: public CTIL::CSM_AlgVDA
{
public:
   CSM_Alg() { };
   CSM_Alg(SNACC::AsnOid &AlgOid): CTIL::CSM_AlgVDA(AlgOid) { };
   CSM_Alg(SNACC::AlgorithmIdentifierVDA &SNACCAlgId): CTIL::CSM_AlgVDA(SNACCAlgId) { };
   CSM_Alg(SNACC::AlgorithmIdentifier &SNACCAlgId): CTIL::CSM_AlgVDA((SNACC::AlgorithmIdentifierVDA &)SNACCAlgId) { };
   CSM_Alg(SNACC::AsnOid &AlgOid, CTIL::CSM_Buffer &buffer): CTIL::CSM_AlgVDA(AlgOid, buffer) { };
   CSM_Alg(const CSM_Alg &alg): CTIL::CSM_AlgVDA(alg) { };
   //CTIL::CSM_AlgVDA & operator & () { return (CTIL::CSM_AlgVDA &)*this; }
   operator SNACC::AlgorithmIdentifier &  () { SNACC::AlgorithmIdentifierVDA *pTmp = this;
                                              return *(SNACC::AlgorithmIdentifier *)pTmp; }
   operator SNACC::AlgorithmIdentifier *  () { SNACC::AlgorithmIdentifierVDA *pTmp = this;
                                              return (SNACC::AlgorithmIdentifier *)pTmp; }
   static long LoadNullParams(SNACC::AlgorithmIdentifier *pAlg) { return 
       CTIL::CSM_AlgVDA::LoadNullParams((SNACC::AlgorithmIdentifierVDA *)pAlg); };
};


/**************************************************************************/
/* GeneralName structure                                                  */
/**************************************************************************/
class LIBCERTDLL_API CSM_GeneralName:public SNACC::GeneralName
{

public:
   // CONSTRUCTORS
   // use this constructor to create a complete empty structure
   CSM_GeneralName():SNACC::GeneralName(){};

   // use this constructor to make a copy of the provided structure
   // and put it into this structure
   CSM_GeneralName(SNACC::GeneralName &SNACCGenName);
   CSM_GeneralName(CSM_DN &dn);
   CSM_GeneralName(char *buffer, int cid);
   CSM_GeneralName(CSM_Buffer *pcsmb);
   // Destructor
   ~CSM_GeneralName(){};

   // These  Get ops return memory the application MUST delete.
   CSM_Buffer     *GetEncodedGenName();
   CSM_DN         *GetGenNameDN();
   char           *GetGenNameRFC822();
   char           *GetGenNameDNS();
   char           *GetGenNameURI();
   char           *GetGenNameString();
   char           *GetGenNameFormatString();  // gets the format of the key and string
   void           *SetFormatString(const char *pStr); // set the format like in cl_msgToSign FillLoadGenNameLst

   void SetEncodedGN     (CSM_Buffer &encCSMB);
   void SetGenNameDN     (CSM_DN     &dn);
   void SetGenNameRFC822 (char       *rfc822);
   void SetGenNameDNS    (char       *dns);
   void SetGenNameURI    (char       *uri);
   void SetGenNameOther  (char       *oid, char *value);
   // COMPARISON OPERATORS
   bool operator == (CSM_GeneralName &gn);
   bool operator != (CSM_GeneralName &gn);

   // Returns type of general name this is
   long m_GetType();

       // DEFINED in sm_x509cmn.h: GeneralName::otherNameCid,
       //                          GeneralName::rfc822NameCid,
       //                          GeneralName::dNSNameCid,
       //                          GeneralName::x400AddressCid,
       //                          GeneralName::directoryNameCid,
       //                          GeneralName::ediPartyNameCid,
       //                          GeneralName::uniformResourceIdentifierCid,
       //                          GeneralName::iPAddressCid,
       //                          GeneralName::registeredIDCid,

};

//////////////////////////////////////////////////////////////////////////
class LIBCERTDLL_API CSM_AttribBase
{
public:
   CSM_AttribBase();
   CSM_AttribBase(SNACC::AsnOid &Oid,CSM_Buffer &SNACCAnyBuf);
   ~CSM_AttribBase();

   //Clean out variables before usage.
   void Clear();

   //GetEncodedAttr returns info for both Auth and Unsigned Attributes.
   void GetEncodedAttr(SNACC::AsnOid *&pOid,CSM_Buffer *&pSNACCAnyBuf);
   void GetEncodedAttr(CSM_Buffer *&pSNACCAnyBuf);

   // Comparison Operator Overload
   bool operator == (CSM_AttribBase &Attr);
   SNACC::AsnOid    *m_poid;
   CSM_Buffer *m_pEncodedAttrib;
};

//////////////////////////////////////////////////////////////////////////
// IssuerAndSerialNumber
class LIBCERTDLL_API CSM_IssuerAndSerialNumber
{
private:
   //CSM_DN *m_pIssuer;        // Certificate Issuer Dn
   //CSM_Buffer *m_pSerialNo;  // Certificate Serial Number
    SNACC::IssuerAndSerialNumber *m_pSNACCIssSn;

public:
   // CONSTRUCTORS
   // use this constructor to create a complete empty structure
   CSM_IssuerAndSerialNumber();
   // use this constructor to make a copy of the provided structure
   // and put it into this structure
   CSM_IssuerAndSerialNumber(const CSM_DN &dn, const CSM_Buffer &serial);
   // use this constructor to get the issuer and serial number
   // from a given certificate
   CSM_IssuerAndSerialNumber(CSM_Buffer *SNACCCertBuf);
   CSM_IssuerAndSerialNumber(const SNACC::Certificate &SNACCCert);
   CSM_IssuerAndSerialNumber(const SNACC::IssuerAndSerialNumber &SNACCIssSn);
   CSM_IssuerAndSerialNumber(const CSM_IssuerAndSerialNumber &IssSn);
   ~CSM_IssuerAndSerialNumber() { if (m_pSNACCIssSn) delete m_pSNACCIssSn; }

   // These 3 Get??? ops return memory the application MUST delete.
   CSM_Buffer *GetEncodedIss();
   CSM_DN *GetIssuer() const;
   CSM_Buffer *GetSerialNo() const;

   void Set(const SNACC::Certificate &SNACCCert);    // Set both issuer and serialNo
   void Set(const SNACC::IssuerAndSerialNumber &SNACCIssAndSer);
   void SetIssuer(const CSM_DN &Issuer);
   void SetIssuer(const SNACC::Name &SNACCIssuer);
   void SetSerialNo(const CSM_Buffer &SerialNo);
   void SetSerialNo(const SNACC::CertificateSerialNumber &SNACCSerialNo);

   // COMPARISON OPERATORS
   bool operator == (const CSM_IssuerAndSerialNumber &issuer);
   bool operator == (CSM_IssuerAndSerialNumber &issuer) 
   { return (*this == (const CSM_IssuerAndSerialNumber &)issuer); };
   bool operator != (const CSM_IssuerAndSerialNumber &issuer);

   CSM_IssuerAndSerialNumber &operator = (const SNACC::IssuerAndSerialNumber &SNACCISN);
   CSM_IssuerAndSerialNumber &operator = (const CSM_IssuerAndSerialNumber &ISN);

   SNACC::IssuerAndSerialNumber *GetSNACCIssuerAndSerialNumber();
   const SNACC::IssuerAndSerialNumber *AccessSNACCIssuerAndSerialNumber() const;
};

/**************************************************************************/
/* Identifier structure                                                   */
/**************************************************************************/
class LIBCERTDLL_API CSM_Identifier
{
private:

   CSM_IssuerAndSerialNumber *m_pIssASN;
   CSM_Buffer                *m_pSubjKeyId;

public:

   // CONSTRUCTORS
   CSM_Identifier() { Clear(); };
   CSM_Identifier(const CSM_IssuerAndSerialNumber &isn)
   { Clear(); SetIssuerAndSerial(isn); }
   CSM_Identifier(const CSM_Identifier &rid);
   CSM_Identifier(const CSM_Buffer &SubjKeyId);

   void Clear()
   {
       m_pIssASN=NULL; m_pSubjKeyId=NULL;
   }

   //DESTRUCTORS
   ~CSM_Identifier();

   // Get member functions return memory, the application MUST delete.
   CSM_IssuerAndSerialNumber         *GetIssuerAndSerial();
   CSM_Buffer                        *GetSubjectKeyIdentifier();

   // Access member functions do not return
   // memory so no deletions are necessary.
   const CSM_IssuerAndSerialNumber *AccessIssuerAndSerial() const 
   { return m_pIssASN; }
   const CSM_Buffer *AccessSubjectKeyIdentifier() const 
   { return m_pSubjKeyId; }

   // Comparison Operator Overload
   bool operator == (CSM_Identifier &CRid);

   // Assignment Operator Overload
   CSM_Identifier &operator = (const CSM_Identifier &Rid);

   // Set Members
   void SetIssuerAndSerial      (const CSM_IssuerAndSerialNumber &iasn);
   void SetSubjectKeyIdentifier (const CSM_Buffer &subjKeyId);

};

//////////////////////////////////////////////////////////////////////////
// CSM_CertificateChoice class encapsulates a certificate
// CHOICE of certificate, extendedCertificate or attrCert
class LIBCERTDLL_API CSM_CertificateChoice
{
private:
   // these members are loaded after decoding the included cert
   mutable CSM_Buffer *m_pCert;       // ASN.1 encoded certificate
   mutable CSM_Buffer *m_pAttrCert;   // ASN.1 encoded V1 or V2 AttributeCertificate
   mutable CSM_Buffer *m_pOther;      // ASN.1 encoded other IETF RFC 3852
   mutable CSM_Buffer *m_pExtCert;    // ASN.1 encoded extended Certificate

   // these are the decoded certs, only one will be filled at any
   // given time
   mutable SNACC::Certificate *m_pSNACCCert; // ASN.1 decoded certificate
   mutable SNACC::AttributeCertificate *m_pSNACCAttrCert; // ASN.1 decoded V1 or V2 attrib cert

   // decoded OtherCertificateFormat, V1AttrCert,and ExtendedCert
   mutable SNACC::OtherCertificateFormat* m_pSNACCOtherCertFormat; 
   mutable SNACC::ExtendedCertificate* m_pSNACCExtCert;  // ASN.1 decoded Extended Cert 

   void Clear(); // initializes members - sets members to NULL
   
   // clears all members of memory and sets them to NULL
   void ClearAllMembers(); 

   void Decode() const; // decode m_pCert into m_pSnaccCert

public:
   SM_RET_VAL GetAttrCertSubjectIssuerUID(SNACC::UniqueIdentifier *&pIssuerUID);
   SM_RET_VAL GetAttrCertSubjectSerialNumber(SNACC::CertificateSerialNumber &);


   // [PIERCE] NOTE THIS IS VERY CONFUSING.
   //          I propose we remove all but the default
   //          constructor and stick with the SetEncodedXXXX()
   //

   CSM_CertificateChoice() { Clear(); }
   CSM_CertificateChoice(const CSM_Buffer &pCert);  // only does certificates
   CSM_CertificateChoice(const SNACC::CertificateChoices &SNACCCertChoices);
   CSM_CertificateChoice(const CSM_CertificateChoice &certChoice);
   CSM_CertificateChoice(const SNACC::Certificate &SNACCCert);
   CSM_CertificateChoice(char *lpszFile, long choiceId);
   ~CSM_CertificateChoice();
   CSM_CertificateChoice &operator= (const CSM_CertificateChoice &CertChoice);

   CSM_Buffer *GetEncodedCert();
   const CSM_Buffer *AccessEncodedCert() const;
   void SetEncodedCert(const CSM_Buffer &Cert);
   CSM_Buffer *GetEncodedAttrCert();
   const CSM_Buffer *AccessEncodedAttrCert() const;
   void SetEncodedAttrCert(const CSM_Buffer &AttrCert);
   void SetSNACCCertChoices(const SNACC::CertificateChoices &SNACCCertChoices);
   SNACC::Certificate *GetSNACCCertificate();
   const SNACC::Certificate *AccessSNACCCertificate() const;
   SNACC::AttributeCertificate *GetSNACCAttrCertificate();
   const SNACC::AttributeCertificate *AccessSNACCAttrCertificate() const;

   // processing for IETF RFC3852 "OtherCertificateFormat"
   CSM_Buffer*                          GetEncodedOther();
   const CSM_Buffer*                    AccessEncodedOther() const;
   void                                 SetEncodedOther(const CSM_Buffer &Other);
   SNACC::OtherCertificateFormat*       GetSNACCOtherCertificateFormat();
   const SNACC::OtherCertificateFormat* AccessSNACCOtherCertificateFormat() const;

   // processing for IETF RFC3852 "ExtendedCertificate" obsolete but carrying it through
   CSM_Buffer*                          GetEncodedExtCert();
   const CSM_Buffer*                    AccessEncodedExtCert() const;
   void                                 SetEncodedExtCert(const CSM_Buffer &Other);
   SNACC::ExtendedCertificate*       GetSNACCExtendedCertificate();
   const SNACC::ExtendedCertificate* AccessSNACCExtendedCertificate() const;

   SNACC::AsnOid *GetKeyOID();          // return the public key OID
   CSM_Buffer *GetPublicKey();    // return public value from cert
                                  // return public value from cert
   static CSM_Buffer *GetPublicKey(SNACC::AsnBits &SNACCpubkey);
   CSM_DN *GetIssuer(CSM_GeneralNameLst *pIssuers = NULL);
   CSM_Buffer *GetEncodedIssuer();  //return encoded issuer
   CSM_DN *GetSubject(CSM_GeneralNameLst *pIssuers = NULL);
   char *pszGetAltSubjectName_rfc822();
   CSM_Buffer *GetEncodedSubject(); //return encoded subject
   CSM_Buffer *GetSerial();       // return serial number of cert
   CSM_Alg *GetPublicKeyAlg();    // return subject public key alg
                                  //return recipient identifier
   CSM_Identifier *GetRid(bool m_bIssOrSki);
                                  //return recipient identifier
   CSM_Identifier *GetRid(CSM_Identifier &rid);
                                  //return issuer and serial
   CSM_IssuerAndSerialNumber *GetIssuerAndSerialNumber();
   CSM_Buffer *GetSubjectKeyIdentifier();
   long GetIssuersBaseCert( SNACC::IssuerSerial *&pIssSN);

   void UpdateSNACCCertificate(SNACC::Certificate *Cert);
   void UpdateSNACCAttrCertificate(SNACC::AttributeCertificate *pAttrCert);

   bool m_bIssOrSki;  //Indicates Issuer and Serial or Subject Key usage.
};

//////////////////////////////////////////////////////////////////////////
//
// CLASS Name:  CSM_RevocationInfoChoice
//
// Description:  
// 
// CSM_RevocationInfoChoice class will be a high level 
// wrapper class for the SNACC-generated RevocationInfoChoice class from
// IETR FRC3852.  This class contains member functions and member 
// variables that will support the SNACC::RevocationInfoChoice members:  
// crl certificateList and  other otherRevocationInfoFormat.  This class 
// will follow the CSM_CertificateChoices design methodology
//
//////////////////////////////////////////////////////////////////////////
class LIBCERTDLL_API CSM_RevocationInfoChoice
{
public:
   //	Default constructor
   CSM_RevocationInfoChoice(){ m_pOtherRevInfoFormatId=NULL; }  // default 

   // Constructors  
   CSM_RevocationInfoChoice(const SNACC::AsnAny& rSNACCAny);
   CSM_RevocationInfoChoice(const CML::CRL& rCmlCrl);

   CSM_RevocationInfoChoice(const SNACC::AsnOid& rOtherOid, // only other buffer 
                            const CSM_Buffer& rRevInfoBuf); // with oid

   CSM_RevocationInfoChoice(const CSM_Buffer& rRevInfoBuf); // may be CRL or
                                                            // RevocationInfoChoice 
   
   // Copy constructor to copy the contents
   CSM_RevocationInfoChoice(const CSM_RevocationInfoChoice& rRevInfoChoice);
                       
   //	Destructor
   ~CSM_RevocationInfoChoice();

   // operator =    assignment member
   CSM_RevocationInfoChoice& operator = (const CSM_RevocationInfoChoice& 
                                         rThatRevChoice);

   // Set function to set contents from a CML::CRL object
   void SetCrl(const CML::CRL& rCmlCrl);

   // Set function to set contents from a SNACC::AsnOid and a CSM::Buffer
   void SetEncodedRevInfo(const SNACC::AsnOid& rOtherOid, 
                          const CSM_Buffer& rEncodedRevInfo);

   // Fill function that encodes the contents and copies the  
   // encoded content into a SNACC::AsnAny
   void FillSnaccAny(SNACC::AsnAny& rSnaccAny) const;

   // Function to access the CSM_Buffer member 
   const CSM_Buffer& AccessEncodedRevInfo() const { return m_encodedRevInfo; }

   //	Function to access the AsnOid pointer member (as a const pointer)
   const SNACC::AsnOid* AccessOtherOid() const;

   // Decodes the encoded CRL and returns a pointer to it
   CML::CRL* GetCRL() const;
  
   // Decodes the SNACC::RevocationInfoChoice and returns a pointer to it
   SNACC::RevocationInfoChoice* GetSNACCRevInfoChoice() const;

   // Bool function that returns true when a CRL is present
   bool IsCrlPresent() const;

private:
   
   CSM_Buffer m_encodedRevInfo;           // ASN.1 encoded CRL or
                                           // encoded otherRevInfo

   SNACC::AsnOid* m_pOtherRevInfoFormatId; // oid for otherRevInfo
  
   // Clear function to delete the AsnOid member 
   //   and empty the CSM_Buffer member  
   void Clear();

}; // end of CLASS CSM_RevocationInfoChoices


////////////////////////////////////////////////////////////////////////////////
//
// Class Name:  CSM_RevocationInfoChoices
// 
// Description:
//
// This class will be publicly-inherited from an instantiation of the std::list
// std::list<CSM_RevocationInfoChoice> template.  
// 
////////////////////////////////////////////////////////////////////////////////
class LIBCERTDLL_API CSM_RevocationInfoChoices :
   public std::list<CSM_RevocationInfoChoice>
{
public:
   // constructors
   CSM_RevocationInfoChoices() {};
   CSM_RevocationInfoChoices(const SNACC::RevocationInfoChoices& rRevInfoChoice);
   CSM_RevocationInfoChoices(const CSM_BufferLst& rBufLst);

   // get a copy of the list as a pointer to a SNACC::RevocationInfoChoices
   SNACC::RevocationInfoChoices* GetSNACCRevInfoChoices(); 

};


//////////////////////////////////////////////////////////////////////////
class LIBCERTDLL_API CSM_MsgCertCrls
{
private:
   CSM_CertificateChoiceLst *m_pCerts; // certificates from PreProc or for
                                       //  sign/encrypt operations.
   CSM_CertificateChoiceLst *m_pACs;
                              // AttributeCertificates from PreProc or for
                              //  sign/encrypt operations.
   CSM_CertificateChoiceLst *m_pOtherCertFormats; // otherCertificateFormat 
                              // from PreProc or for sign/encrypt operations
   CSM_CertificateChoiceLst *m_pExtCerts;// for obsolete extCerts just passing
   CSM_RevocationInfoChoices *m_pCRLLst; // holds CRL and "other" types for 

   void Clear() { m_pCerts=NULL; m_pACs=NULL; m_pOtherCertFormats = NULL;
                  m_pExtCerts = NULL;m_pCRLLst = NULL; }

public:
   // constructors and destructor
   CSM_MsgCertCrls() { Clear(); }
   CSM_MsgCertCrls(CSM_CertificateChoiceLst *pCerts)
       { Clear(); SetCertificates(pCerts); }
   CSM_MsgCertCrls(CSM_BufferLst *pCerts)
       { Clear(); SetCertificates(pCerts); }
   CSM_MsgCertCrls(SNACC::CertificateSet *pCertificateSet)
       { Clear(); SetSNACCCerts(pCertificateSet); }
   CSM_MsgCertCrls(CSM_RevocationInfoChoices *pCRLs)
       { Clear (); SetCRLLst(pCRLs); }
   CSM_MsgCertCrls(SNACC::RevocationInfoChoices *pCRLs)
       { Clear (); SetSNACCCRLst(pCRLs); }
   ~CSM_MsgCertCrls();

   // Access return pointers to the data in this class
   CSM_CertificateChoiceLst *AccessCertificates() { return m_pCerts; }
   CSM_CertificateChoiceLst *AccessACs(){ return m_pACs; }

   // returns a pointer to m_pOtherCertFormats
   CSM_CertificateChoiceLst *AccessOtherCertFormats()
   { return m_pOtherCertFormats; }

   // returns a pointer to m_pExtCerts
   CSM_CertificateChoiceLst *AccessExtCerts()
   { return m_pExtCerts; }


   CSM_RevocationInfoChoices *AccessCRLLst() { return m_pCRLLst; }

   // get a SM_StrLst of encoded certs
   SM_StrLst *GetStrLstOfCerts();
   CSM_CertificateChoice *FindCert(CSM_IssuerAndSerialNumber &IssSN);
   CSM_CertificateChoice *FindCert(CSM_Buffer &SKI);
   CSM_CertificateChoice *FindCert(CSM_Identifier &RID);
   CSM_CertificateChoice *FindCert(CSM_DN &DN);
   CSM_CertificateChoice *FindCert(CSM_CertificateChoice &AttrCert);

   // SetCertificates from a CSM_BufferLst assumes that the
   // provided certs are regular certs and copies them into
   // m_pCerts
   void SetCertificates(CSM_BufferLst *pCertificateBufs);
   bool UpdateParams(CSM_Alg &alg, CSM_CertificateChoice &Cert, CSM_DN *pTopDN = NULL);

   // SetCertificates from a CSM_CertificateChoiceLst
   // copies the regular certs into m_pCerts and the
   // ACs into m_pACs
   void SetCertificates(CSM_CertificateChoiceLst *pCerts);

   // SetCRLs copies the provided CRLs into m_pCRLs
   void SetCRLLst(CSM_RevocationInfoChoices *pCRLs);
   void SetSNACCCRLst(SNACC::RevocationInfoChoices *pCRLs);

   // AddCert adds a single cert to the appropriate location
   void AddCert(CSM_CertificateChoice *pCert);
   void AddCRL(CSM_RevocationInfoChoice *pCRL);

   // use the Deletes to clear the appropriate components of this class
   void ClearCerts();
   void ClearACs();
   void ClearOtherCertFormats();
   void ClearExtCerts();
   void ClearCRLLst();

   // PutSNACCCerts decodes the certs in this class and loads
   // their decoded values into the provided (or allocated)
   // CertificateSet
   void PutSNACCCerts(SNACC::CertificateSet *&pCertificateSet);

   // PutSNACCCRLLst decodes the CRLs in this class and loads
   // their decoded values into the provided (or allocated)
   // RevocationInfoChoices List
   void PutSNACCCRLLst(SNACC::RevocationInfoChoices *&pCRLLst);

   // SetSNACCCerts places the provided snacc decoded certs
   // into this appropriately
   void SetSNACCCerts(SNACC::CertificateSet *pCertificateSet);

};

//////////////////////////////////////////////////////////////////////////
// CSM_CSInst is a "crypto service instance" or the class that provides
// access to the crypto services for an application and the SFL.
class LIBCERTDLL_API CSM_CSInst: public CSM_CtilInst
{
private:
   CSM_CertificateChoiceLst *m_pCertificates; // user cert always at top
   CSM_RevocationInfoChoices *m_pCRLs;    // list of CSM_RevocationInfoChoices
   CSM_IssuerAndSerialNumber *m_pIssuerAndSerialNumber;
   CSM_DN *m_pSubjectDN;
   CSM_Identifier/*RecipientIdentifier*/ *m_pIssOrSki;
   CSM_Identifier/*RecipientIdentifier*/ m_SNACCRid;
   bool m_bIssOrSki;

   enum OrigIdOrKey { ISSUER_AND_SERIAL=0, SUBJECT_KEY_ID, PUBLIC_KEY };
   OrigIdOrKey m_eOrigIdOrKey;

   void Clear()
   {
       m_bIssOrSki = true; 
       m_pCertificates = NULL; m_pCRLs = NULL; m_pIssuerAndSerialNumber = NULL;
       m_pSubjectDN = NULL; m_pIssOrSki = NULL; m_eOrigIdOrKey = ISSUER_AND_SERIAL; 
   }
   bool CheckSignerEncrypter(bool bSignerRequest=true);  // auto check for signer

public:
   CSM_CSInst();
   ~CSM_CSInst();

   CSM_CSInst *FindInstByDN(char *pDn);
   CSM_Alg *DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert);
  // Set m_bIssOrSki to use the originator's IssuerAndSerialNumber in the
   // OriginatorIdentifierOrKey field of the KeyAgreeRecipientInfo.  Set
   // it to false to use the originator's SubjectKeyIdentier (SKI) if
   // present.
   //
   void UseOriginatorSKI(bool flag)
      { if (flag) m_eOrigIdOrKey = SUBJECT_KEY_ID; }
   void UseOriginatorIssuerAndSerial(bool flag)
      { if (flag) m_eOrigIdOrKey = ISSUER_AND_SERIAL; }
   void UseOrignatorPublicKey(bool flag)
      { if (flag) m_eOrigIdOrKey = PUBLIC_KEY; }
   bool UseOriginatorSKI()
      { return (m_eOrigIdOrKey == SUBJECT_KEY_ID);}
   bool UseOriginatorIssuerAndSerial()
      { return (m_eOrigIdOrKey == ISSUER_AND_SERIAL); }
   bool UseOrignatorPublicKey()
      { return (m_eOrigIdOrKey == PUBLIC_KEY); }
   bool HasCertificates() { if (m_pCertificates) return true; 
                            else return false; }
   const CSM_CertificateChoice *AccessUserCertificate();
   void LoadCertificates(CSM_MsgCertCrls *&pMsgCertCrls);
   bool HasCRLs() { if (m_pCRLs) return true; 
                    else return false; }
   void LoadCRLs(SNACC::RevocationInfoChoices *&pSNACCCrls);

   //////////////////////////////////////
// keyUsageBits:   
//    digitalSignature  (0)
//    nonRepudiation    (1)     
//    keyEncipherment   (2)
//    dataEncipherment  (3),
//    keyAgreement      (4)
//    keyCertSign       (5)
//    cRLSign           (6)
//    encipherOnly      (7)
//    decipherOnly      (8)
/////////////////////////////////////
   enum
   {
      checkDigitalSignature  = 0,
      checkNonRepudiation    = 1,     
      checkKeyEncipherment   = 2,
      checkDataEncipherment  = 3,
      checkKeyAgreement      = 4,
      checkKeyCertSign       = 5,
      checkCRLSign           = 6,
      checkEncipherOnly      = 7,
      checkDecipherOnly      = 8,
   } checkKeyUsageFlagBits;  // used in CheckKeyUsageBit()

   // check keyUsage bit for sign, encrypt
   bool CheckKeyUsageBit(int checkBit);

   // IT IS NOT ADEQUATE TO CHECK "!IsSigner()" for an encrypter since
   //  certain RSA certificates do not have a keyUsage extension; these cases
   //  can imply both signing and encryption capability, so a cert would 
   //  indicate IsSigner() true, but still be capable of encrypting.
   bool IsSigner ();
   bool IsEncrypter ();
   bool IsTSA();

   // The following members can be used to set and get ASN.1 objects from this
   // instance
   // TBD, change these to add functions and adjust all other code as well
   void SetCertificates(CSM_BufferLst *pCertificateBufs);
   void SetCertificates(CSM_CertificateChoice *pCertificateChoice);
   void UpdateCertificates(CSM_CertificateChoiceLst *pCertificates);
   void UpdateCRLs(CSM_BufferLst *pCRLs);

   // work with the IssuerAndSerialNumber for an instance
   void SetIssuerAndSerialNumber(CSM_IssuerAndSerialNumber
                                 *pIssuerAndSerialNumber);
   CSM_IssuerAndSerialNumber *AccessIssuerAndSerialNumber();

   CSM_DN *AccessSubjectDN();
   CSM_Identifier *GetRid(int iStat);            // RETURN CSM_Identifier
   CSM_Identifier *GetRid(bool m_bIssOrSki);     // RETURN CSM_Identifier
   CSM_Identifier *GetRid();                     // RETURN CSM_Identifier
   CSM_Identifier *GetRid(CSM_Identifier &Rid);  // RETURN CSM_Identifier

};

//////////////////////////////////////////////////////////////////////////
// NOTE:: Parameters are not necessary for these algorithms:  Fortezza uses
//  the parameters from the Certpath, RSA and DH are included in the
//  certificate.  If the parameters are necessary in the future, it can be
//  added to the MAB data structures.
//
// MAB_Entrydef represents a single entry in the address book
class LIBCERTDLL_API MAB_Entrydef
{
private:
   // SNACC decoded cert, retained if decoded once.
   SNACC::Certificate *m_pCertificate;
   // issuer and serial number (for easy ID).
   CSM_IssuerAndSerialNumber *m_pIssuer;

   void Clear()
   {
       m_pCertificate = NULL; m_pIssuer = NULL;
       m_pszAlias = NULL; m_pszCertificateDN = NULL;
       m_pCertFile = NULL; m_pPrivateInfo = NULL;
       m_pPrivateOID = NULL;
   }

public:
   MAB_Entrydef() { Clear(); }
   MAB_Entrydef(const MAB_Entrydef &entry);
   ~MAB_Entrydef();

   MAB_Entrydef &operator = (const MAB_Entrydef &that);
   char *m_pszAlias; // alias name, main index to data.

   // X.500 DN used as the subject DN on this particular entry's
   // certificate.  The format of this dn string is
   // c=US@o=US Governement etc..
   char *m_pszCertificateDN;

   // relative path identifying the file containing the cert binary
   // MAB_AB_def.m_szGlobalPath is prepended to this file name
   CSM_Buffer *m_pCertFile;

   // information containing the private key for the cert if applicable
   // the m_pPrivateOID helps the CTI determine how to interpret this
   // information whether it be a slot number on a fortezza card or
   // a file name containing a PKCS#8 EncryptedPrivateKeyInfo
   CSM_Buffer *m_pPrivateInfo;

   // identifies the type of data stored in m_pPrivateInfo
   SNACC::AsnOid *m_pPrivateOID;

   // GetCertificate forces decoding of cert on first call,
   // otheriwse returns pointer to already decoded cert
   SNACC::Certificate *GetCertificate();

   // GetIssuer decodes and extracts the issuer serial number
   // on the first call, otherwise it uses what is available
   CSM_IssuerAndSerialNumber *GetIssuer();
};

//////////////////////////////////////////////////////////////////////////
// MAB_AB_def represents the address book
class LIBCERTDLL_API MAB_AB_def
{
public:
   enum { // types used with FindRecord
      MABTYPE_DN,
      MABTYPE_ALIAS
   };

   List<MAB_Entrydef> *m_pEntries; // list of entries in address book
   char m_szGlobalPath[256]; // global path to files of AB Entry.
   char m_szCrlPath[256]; // global path to crl files

   // constructors and destructors
   MAB_AB_def(); // create empty mab
   MAB_AB_def(char *pszFileName); // create mab from file
   MAB_AB_def(MAB_AB_def &mab); // copy constructor
   ~MAB_AB_def();

   // Init reads the mab file into this class
   SM_RET_VAL Init(char *pszFileName);
   // returns the cert for the specified DN
   SM_RET_VAL FindCertDN(char *pszDN, CSM_Buffer *result);
   // returns the specified record (MAB_Entrydef class)
   MAB_Entrydef *FindRecord(char *pszID, long lType);
   // returns the cert with the specified alias
   SM_RET_VAL FindCertAlias(char *pszAlias, CSM_Buffer *result);
   // returns the cert with the specified issuer and serial number
   SM_RET_VAL FindIssuer(CSM_IssuerAndSerialNumber &csmIssuer,
                         CSM_Buffer *result);
   SM_RET_VAL FindSKI(CSM_Buffer &csmSKI, CSM_Buffer *result);
   SM_RET_VAL FillCertPath(CSM_CertificateChoice *pCertToPath,
                           CSM_MsgCertCrls *pMsgCertCrls);
};

//////////////////////////////////////////////////////////////////////////
// CSM_CertificateList class encapsulates a CRL.
class LIBCERTDLL_API CSM_CertificateList
{
protected:
   // these members are loaded after decoding the included cert
   CSM_Buffer *m_pCRLBuffer;       // ASN.1 encoded CRL

   // these are the decoded CRLs, only one will be filled at any
   // given time
   SNACC::CertificateList *m_pSNACCCRL; // ASN.1 decoded CRL

   void Clear(); // clear members
   void Decode(); // decode m_pCert into m_pSnaccCert

public:

   CSM_CertificateList() { Clear(); }
   CSM_CertificateList(const CSM_Buffer &pCRL);
   CSM_CertificateList(const SNACC::CertificateList &SNACCCRL);
   // Copy constructor
   CSM_CertificateList(const CSM_CertificateList &CRL);
   ~CSM_CertificateList();

   CSM_DN *GetIssuer();

   SM_RET_VAL Validate();
   // Set m_pSNACCCRL from input buffer
   void SetSNACCCRL(const CSM_Buffer &pCRL);
   // Access to m_pSNACCCRL
   SNACC::CertificateList *AccessSNACCCRL();
   // Encode m_pSNACCCRL into a CSM_Buffer
   CSM_Buffer *AccessEncodedCRL();
   //
   CSM_Buffer *GetEncodedCRL();
   SNACC::CertificateList *GetSNACCCRL();
   CSM_CertificateList &operator =(const CSM_CertificateList &CertificateList);
};

/**************************************************************************/
/* CSM_GeneralNames structure                                             */
/**************************************************************************/
#ifdef WIN32
#pragma warning( disable : 4275 )
#endif
class LIBCERTDLL_API CSM_GeneralNames : public CSM_GeneralNameLst
{
public:
    // CONSTRUCTORS
    CSM_GeneralNames() {}
    CSM_GeneralNames(SNACC::GeneralNames &SNACCGNs);

    bool          FindSubjectDN(CSM_CSInst *inst);
    SNACC::GeneralNames *GetSNACCGeneralNames();
    void                 GetSNACCGeneralNames(SNACC::GeneralNames &gn);
    void         SetGeneralNames(SNACC::GeneralNames &SNACCTmpGNs);
};

#ifdef WIN32
#pragma warning( default : 4275 )
#endif
//////////////////////////////////////////////////////////////////////////
// CSMIME contains the CSInst instances as well as overall library
// information (including the error handling buffers)
class LIBCERTDLL_API CSMIME: public CSM_CtilMgr
{
private:
    CSM_CtilInstLst::iterator m_itInst;
public:
    // DATA MEMBER
    CSMIME();
    ~CSMIME();

    // ADDED BY PIERCE 7-13-99
    CSM_CSInst *FindInstByDN(char *pDn);
    CSM_CSInst *FindNextInstByDN(char *pDn);    
                    // INTENDED to be called after FindInstByDN(...).
   // The next method was created to differentiate between signer/encyrpter 
   //  using the same DN string.  If "bSignerFlag" is true, signer is returned, 
   //  if located.  (RWC; 5/29/02).
   CSM_CSInst *FindInstByDN_SignerOrEncrypter(char *pDn, bool bSignerFlag);
   void SetDefaultCTIL(); 
};

class LIBCERTDLL_API CSM_SignBuf
{
private:

public:
    CSM_SignBuf() {}
    static CSM_Alg *GetPreferredKeyEncryptionAlg(CSM_CSInst &cInst);

    // Set all CSInstances that can handle verification of the specified
    //  signature algIDs
    static long SetApplicableInstances(CSMIME *pCSMIME,
                                       CSM_Alg *pdigestAlgorithm,
                                       CSM_Alg *psignatureAlgorithm,
                                       CSM_GeneralNames *genNames = NULL,
                                       bool bSignerOnlyFlag=false);

    static void ClearEncryptApplicableInstances(CSMIME *pCSMIME);

    // Determine specific (1st in list) CSInstance for verification
    static CSM_CSInst *GetFirstInstance(CSMIME *pCSMIME,
                                        CSM_Alg *pdigestAlgorithm,
                                        CSM_Alg *psignatureAlgorithm);

    // IN, RecipientIdentifier
    static SM_RET_VAL LoadCertificatePath(CSM_Identifier  *pRid,
                                          // IN, Cert Bucket to search
                                          CSM_MsgCertCrls          *pCertCrls,
                                          // OUT, resulting CertPath
                                          CSM_CertificateChoiceLst *&pCertPath);

    // Sign buffer blob with specified CSInstance
    static long SignBuf(CSM_CSInst *pCSInst, // IN, Instance for hash/sig ops
                        CSM_Buffer *pSigContentBuf,// IN, buffer to hash/sign
                        CSM_Buffer *&pDigest,      // OUT, resulting hash value
                        CSM_Buffer *&pSigBuf,      // OUT, resulting signature
                        SNACC::AlgorithmIdentifier *&digestAlgorithm, // OUT, Actual
                                                   // hash AlgID used
                        SNACC::AlgorithmIdentifier *&signatureAlgorithm); // OUT,
                                                   // Actual sig AlgID used
};


_END_CERT_NAMESPACE 

#endif // _SM_APICERT_H_
// EOF sm_apiCert.h
