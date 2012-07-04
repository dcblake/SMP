// ACL API HEADER

#ifndef _aclapi_h_
#define _aclapi_h_

#ifndef ACL_API      // DEFINE on compile line to "" for Static refs
#ifdef WIN32
#ifdef ACL_EXPORTS
#define ACL_API __declspec(dllexport)
#else
#define ACL_API __declspec(dllimport)
#endif          // LIBCERTDLL_EXPORTS
#else           // Handle Unix...
#define ACL_API
#endif          // WIN32
#endif          // ifndef LIBCERTDLL_API

#ifndef NO_NAMESPACE
#define _USING_NAMESPACE_SNACC using namespace SNACC;
#define _USING_NAMESPACE_CTIL  using namespace CTIL;
#define _USING_NAMESPACE_ACL using namespace acl;
#define _BEGIN_NAMESPACE_ACL namespace acl {
#define _END_NAMESPACE_ACL }
#else
#define _USING_NAMESPACE_ACL
#define _USING_NAMESPACE_SNACC
#define _BEGIN_NAMESPACE_ACL
#define _END_NAMESPACE_ACL
#endif

#include "cmapi_cpp.h"
#include "srlapi.h"
#include "aclasn.h"

namespace acl {
class AclString;
}

#include "aclerror.h"

_BEGIN_NAMESPACE_ACL

// FORWARD DECLARATIONS
//
class ClearanceCert;
class SPIF;
class AC;
class Trust;
class TranslatedLabel;
class SecurityLabel;
class Session;
class PublicKeyInfo;
class ClearanceCert;
class IncomingLabel;
class OutgoingLabel;
class CMarkingData;
class CSecurityCatTag;
class CMarkingQualifier;
class CSecurityCatTagSet;
class CTagCategory;

// List template is defined in SNACC C++ runtime library
//
typedef CML::ASN::OIDList AsnOidLst;
typedef std::list<SPIF> SPIFList;
typedef std::list<AC> ACList;
typedef std::list<ClearanceCert> CCList;
typedef std::list<SNACC::Clearance> ClearanceList;
typedef std::list<Trust> TrustList;
typedef std::list<CSecurityCatTagSet> CSecurityCatTagSetList;
typedef std::list<SNACC::AsnInt> AsnIntList;
typedef std::list<CMarkingQualifier> CMarkingQualifierList;
typedef std::list<CTagCategory> CTagCategoryList;
typedef std::list<CSecurityCatTag> CSecurityCatTagList;
typedef std::list<CMarkingData> CMarkingDataList;
typedef std::list<std::string> StrList;
typedef std::list<Trust> TrustList;

class ACL_API MatchInfo
{
public:
   MatchInfo();
   // DESTRUCTOR
   ~MatchInfo(void);

   void setSubjectDN(const CML::ASN::DN &dn);
   void setIssuerDN(const CML::ASN::DN &dn);
   void setSubjectKeyId(const SNACC::AsnOcts &ski);
   void setAuthorityKeyId(const SNACC::AsnOcts &aki);
   void setSerialNo(const SNACC::AsnInt &serialNo);
   void setPolicyId(const SNACC::AsnOid &policyId);

   const CML::ASN::DN *getSubjectDN(void) const {return m_pSubjectDN;}
   const CML::ASN::DN *getIssuerDN(void) const {return m_pIssuerDN;}
   const SNACC::AsnOcts *getSubjectKeyId(void) const {return m_pSki;}
   const SNACC::AsnOcts *getAuthorityKeyId(void)const {return m_pAki;}
   const SNACC::AsnInt *getSerialNo(void) const {return m_pSerialNo;}
   const SNACC::AsnOid *getPolicyId(void) const {return m_pPolicyId;}

private:
   CML::ASN::DN *m_pIssuerDN;
   CML::ASN::DN *m_pSubjectDN;
   SNACC::AsnOcts *m_pSki;
   SNACC::AsnOcts *m_pAki;
   SNACC::AsnInt *m_pSerialNo;
   SNACC::AsnOid *m_pPolicyId;
};



class ACL_API Cacheable
{
public:
   enum CacheType {ACERT_ID=0, ACSPIF_ID, ACLRCERT_ID, UNKNOWN_ID=-1};
   
   Cacheable(const CacheType &cacheType);
   virtual ~Cacheable(void) {};

   mutable CML::ASN::Time m_expireTime;

   // PUBLIC MEMBER FUNCTIONS
   bool operator == (const Cacheable &that) const;
   Cacheable &operator = (const Cacheable &that);
   bool validate(Session *pSession);
   bool validate(Session *pSession, const CML::ASN::PublicKeyInfo &pubKeyInfo);
   bool isValid(void);

   const CML::ASN::Bytes &getHash(void);
   virtual bool matches(const MatchInfo &matchInfo) const=0;
   virtual Cacheable *clone(void) const=0;
   virtual void getIssuerInfo(MatchInfo &matchInfo)=0;
   virtual void getDescription(AclString &str) const=0;
   void updateTTL(unsigned long ttl) const;

   CacheType type;
protected:
   bool isExpired(void);
   CML::ASN::Bytes m_hash;
   CML::ASN::Bytes m_origObject;
   // PROTECTED DATA MEMBERS
   enum validFlags { VALID=0, NOT_VALID, TTL_EXPIRED } m_isValidFlag;

private:

   // PRIVATE MEMBER FUNCTIONS
   void init();
   //virtual bool vValidate(Session *pSession, const PublicKeyInfo &pubKeyInfo)=0;
   virtual void vPathRules(Session *pSession, const CML::ASN::CertificationPath &certPath){};

   virtual bool checkValidity(void)=0;
};

class CacheContainer
{
public:
   CacheContainer(const CacheContainer &that) { m_pObject = that.ref().clone(); }
   CacheContainer(const Cacheable &o) { m_pObject = o.clone(); }
   ~CacheContainer(){delete m_pObject; m_pObject = NULL;}
   const Cacheable & ref() const { return *m_pObject; }

private:
   Cacheable *m_pObject;
};

class ACL_API Trust
{

public:
   Trust(void) {};
   void setOID(const SNACC::AsnOid &oid){m_oid = oid;}
   void setDN(const CML::ASN::DN &dn){m_authorityDN = dn;}
   const SNACC::AsnOid &GetOid(void) {return m_oid;}
   const CML::ASN::DN &GetDN(void) {return m_authorityDN;}

private:
   SNACC::AsnOid m_oid;
   CML::ASN::DN  m_authorityDN;
};

typedef  void * LDAP_HANDLE;

typedef std::list<CacheContainer> AclCache;

class ACL_API Session
{

public:
   // PUBLIC DATA MEMBERS
   unsigned long m_Internal_CML_Session;
   unsigned long m_External_CML_Session;
   long m_ttl;
   bool m_dms_mode;
   bool m_disable_validation;
   bool m_disable_trustlist;
   bool m_bSpifSignerAttr;
   enum CacheModeType {LOCAL_THEN_REMOTE=0, LOCAL, REMOTE} m_eCacheMode;

   Session();
   // DESTRUCTOR
   ~Session(void);

   // This will probably change to a filename for the LDAP DLL.
   void enableLDAP(char *dllFilename, char *serverName,
      long portNumber);

   void enableDMS(bool flag) { m_dms_mode = flag; }

   void disableValidation(bool flag) { m_disable_validation = flag; }
   void disableTrustList(bool flag) { m_disable_trustlist = flag; }

   // Sets CML session to be used for signature checks and path
   // validation.
   void enableCML(long session);

   // Sets a flag to determine whether or not the ACl should
   // automatically retrieve an AC that fails a signature or
   // access control check.
   void enableAutoRetrieve(bool flag);

   // This enables use the use of the SPIF Signer Attribute which
   // will live in a Subject Directory Attributes extension in
   // a SPIF's issuer certificate.
   //
   void enableSPIFSignerAttribute(bool flag){m_bSpifSignerAttr = flag;}
   bool usingSPIFSignerAttribute(void) { return m_bSpifSignerAttr; }

   // Returns true if LDAP is being used and false if it is not.
   bool usingLDAP(void);

   // Returns true if CML is being used and false if it is not.
   bool usingCML(void);

   // Returns value true if autoRetrieve is enabled
   bool usingAutoRetrieve(void);
   bool usingTrustList(void) { return (! m_disable_trustlist); }

   bool usingEquivalencies(void) { return m_bUseEquivalencies;}
   void enableEquivalencies(bool flag){ m_bUseEquivalencies = flag;}

   // Read parameters from a configuration file
   long readConfig(char *pConfigFileName=NULL);

   // *************** CACHE MEMBER FUNCTIONS ***************

   // Add SPIF to cache. No validation performed.
   void addSPIF(const CML::ASN::Bytes &encodedSPIF);

   // Add AC to cache. No validation performed.
   void addAC(const CML::ASN::Bytes &encodedAC);

   // Add ClearanceCertificate to cache. No validation performed.
   void addCC(const CML::ASN::Bytes &encodedCC);

   // Retrieve SPIFs from cache
   SPIF *getSPIF(SPIF &spif);
   SPIFList *getSPIF(MatchInfo &matchInfo);

   // Retrieve ACs from cache
   AC *getAC(AC &ac);
   ACList *getAC(MatchInfo &matchInfo);

   // Retrieve ClearanceCertificates from cache
   ClearanceCert *getCC(ClearanceCert &cc);
   CCList *getCC(MatchInfo &matchInfo);

   // Retrieve generic cache item
   Cacheable *getCacheable(const Cacheable &cacheable);

   // Add the new DN and OID to the trust list if the DN and OID
   // do not already exist in the list
   int addTrust(const CML::ASN::DN& dn, const SNACC::AsnOid& oid);

   // Returns true if DN and OID are found in trust list
   bool findTrust(const CML::ASN::DN &DN, const SNACC::AsnOid &Id);

   void displayCache(AclString &str);
   void updateCache(const Cacheable &item);
   void removeCache(const Cacheable &item);
   void setCacheMode(CacheModeType mode)
   { m_eCacheMode = mode; }
   unsigned long getCMLHandle(void);

private:
   // PRIVATE DATA MEMBERS
   AclCache m_cache;
   /*AclCache *m_pCache; */
   ulong *m_pSRLsessionID;
   TrustList m_trustList;
   bool m_bAutoRetrieveFlag;
   bool m_bUseEquivalencies;

};


class ACL_API SPIF : public SNACC::Acspif, public Cacheable
{
public:

   // DEFAULT CONSTRUCTOR
   SPIF();
   SPIF(const SPIF &that);

   // ALTERNATE CONSTRUCTOR decodes buffer into itself
   SPIF(const CML::ASN::Bytes &encodedSPIF);

   // Destructor
   virtual ~SPIF(void);

   // PUBLIC MEMBER FUNCTIONS
   bool isEnumRestrictive(const SNACC::AsnOid &tagSetNameOid );

   void getDescription(AclString &str) const;

   bool checkSpifSigner(Session *pSession, const CML::ASN::CertificationPath &certPath);

   const CML::ASN::DN &getIssuerName(void) const;
   const SNACC::AsnOid &getPolicyId(void) const;

   // Return a pointer to the SNACC class
   const SNACC::Acspif *getSNACC(void)
   { return (const SNACC::Acspif *)this; }

   SNACC::AsnOid &getEquivalentPolicy(SNACC::AsnOid &policyId);
   int getEquivalentClassification(SecurityLabel &lbl, SNACC::AsnOid &remotePolicyId);
   SNACC::StandardSecurityLabel *getEquivalentTagSets(SecurityLabel &origLabel,
                                                SNACC::AsnOid &remotePolicyId);
   Cacheable *clone(void) const { SPIF *pSPIF = new SPIF; *pSPIF = *this; return pSPIF;}
   bool matches(const MatchInfo &matchInfo) const;
   SPIF &operator =(const SPIF &spif);
   void getIssuerInfo(MatchInfo &matchInfo);
   void getLatest(Session *s, MatchInfo &matchInfo);

private:
   // PRIVATE DATA MEMBER
   mutable CML::ASN::DN *m_pOriginatorDN;

   // PRIVATE MEMBER FUNCTIONS
   // verify the signature on this object.  The
   // public key and parameters used to sign this
   // object are retrieved from issuerPath.
   //
   bool vValidate(Session *session, const PublicKeyInfo &pubKeyInfo);
   void vPathRules(Session *pSession, const CML::ASN::CertificationPath &certPath);
   bool checkValidity(void);
};

class ACL_API ClearanceInfo
{
public:
   // DEFAULT CONSTRUCTOR
   //
   ClearanceInfo(void);

   // Destructor
   virtual ~ClearanceInfo(void);

   // PUBLIC MEMBER FUNCTIONS
   SNACC::SSLPrivileges *getSSLPrivs(SPIF &spif);

   // perform access control check of the Cacheable (AC/ClearanceCert)
   // against the SPIF and label that is passed in.  This is a wrapper around
   bool check(Session *s, SPIF &spif, SecurityLabel &label);

   // Return a pointer to the SNACC class
   const SNACC::Clearance *getSNACC(void)
   { return (const SNACC::Clearance *)m_pSnaccClearance; }

   ClearanceInfo &operator=(const ClearanceInfo &that);
   SecurityLabel *getLastEquivLabel(void);

   // All derived classes should implement getClearance() because
   // they may be storing the ClearanceAttribute differently.
   // Or perhaps have special rules that must be applied before
   // using the Clearance attribute for an ACDF
   //
   // virutal const Clearance *getClearance();

   SNACC::AsnBits *getClassList(void);

   // PUBLIC DATA MEMBER
   //
   SNACC::Clearance *m_pSnaccClearance;

private:
   // PRIVATE MEMBER FUNCTIONS
   bool checkSSL(const SNACC::StandardSecurityLabel &ssl, SPIF &spif);
   bool checkTagSetPriv(const SNACC::NamedTagSet &tagSet, const SNACC::NamedTagSetPrivilege &tagPriv,
                        bool enumRestrictive);

protected:
   // PROTECTED MEMBER FUNCTIONS
   // low level ACDF this is where the real access control is performed.
   //
   bool acdf(Session *s, SPIF &spif, SecurityLabel &label);
   SNACC::AsnOid &getPolicyId(void);

};

class ACL_API ClearanceCert : public CML::ASN::Cert, public ClearanceInfo,
                              public Cacheable
{
public:
   // DEFAULT CONSTRUCTOR
   //
   ClearanceCert(void);

   // ALTERNATE CONSTRUCTOR decodes buffer into itself
   //
   ClearanceCert(const CML::ASN::Bytes &encodedCC);
   ClearanceCert(const CML::ASN::Cert &that);

   // Destructor
   virtual ~ClearanceCert(void);

   // PUBLIC MEMBER FUNCTIONS

   // Returns a pointer to the Clearance object found in the
   // clearance constraint extension within this object.
   const SNACC::Clearance *getCaClearance(const SNACC::AsnOid &policyId);

   // Returns a pointer to a SNACC Clearance extension found within the
   // extensions based on the supplied Policy ID.  If the Clearance is
   // not present a NULL pointer will be returned.
   const SNACC::Clearance *getClearance(const SNACC::AsnOid &policyId);

   // Return a pointer to the SNACC class
   // PIERCE: use CML's getSnacc() instead;
   //SNACC::Certificate *getSNACC(void);

   //Intersect function - pIssuerLst is optional
   void intersect(Session *pSession, const CML::ASN::CertificationPath &certPath);
   ClearanceCert &operator=(const ClearanceCert &);

   // Build and validate an X.509 certification path to this ClearanceCert
   bool validate(Session *pSession);

   // Generic check that will perform access control check of this
   // ClearanceCert against the SPIF and label that is passed in.
   bool check(Session *s, SPIF *&pSpif, SecurityLabel &label);

   Cacheable *clone(void) const {ClearanceCert *pCC = new ClearanceCert; *pCC = *this; return pCC;}
   bool matches(const MatchInfo &matchInfo) const;

   void getDescription(AclString &str) const;

   const CML::ASN::DN &getIssuerName(void) const;
   const AsnOidLst &getPolicyIdList(void) const;
   const CML::ASN::DN &getSubjectName(void) const;
   void getIssuerInfo(MatchInfo &matchInfo);
   bool checkValidity(void);
   const CML::ASN::Bytes& getEncodedCC(void) const	{ return m_origObject; }

private:
   // PRIVATE MEMBER FUNCTIONS
   void clear(void);
   void checkExtensions(void);
   // verify the signature on this object.  The
   // public key and parameters used to sign this
   // object are retrieved from issuerPath.
   //
   bool vValidate(Session *s, const PublicKeyInfo &pubKeyInfo);
   void vPathRules(Session *pSession, const CML::ASN::CertificationPath &certPath);
   // PRIVATE DATA MEMBERS
   //
   mutable AsnOidLst m_policyIdList;
   //ClearanceList m_intersectedClearances;
   //ClearanceList *m_pIntersectedClearances;
   //SNACC::Certificate *m_pSnaccCert;
};

class ACL_API OriginatorCert : public ClearanceCert
{
public:
   // PUBLIC MEMBER FUNCTIONS
   OriginatorCert(const CML::ASN::Bytes &o):ClearanceCert(o){};

   // See acltranslabel.cpp for Source
   // Originator performs ACDF on himself check.
   // pLocalSPIF is an optional parameter.
   //
   void check(Session *s, OutgoingLabel &outLabel,
              SPIF *pLocalSPIF=NULL);

   // Originator performs ACDF on himself check.
   void check(Session *s, IncomingLabel &inLabel, SPIF &remoteSPIF);
};

class ACL_API RecipientCert: public ClearanceCert
{
public:
   // PUBLIC MEMBER FUNCTIONS
   RecipientCert(const CML::ASN::Bytes &o):ClearanceCert(o){};
   // Implements SNDN.801 PRBAC check for the recipient at the originator.
   void check(Session *s, OutgoingLabel &outLabel, SNACC::AsnOid &usedPolicy,
              SPIF *pLocalSPIF=NULL);
   // Implements SNDN.801 PRBAC check for the recipient at the recipient.
   void check(Session *s, IncomingLabel &inLabel, SPIF *&pRemoteSPIF,
              SecurityLabel *&pEquivalentLabel);
};

class ACL_API AC : public CML::ASN::AttributeCert, public ClearanceInfo,
                   public Cacheable
{

public:
   // DEFAULT CONSTRUCTOR
   //
   AC();

   // ALTERNATE CONSTRUCTOR decodes buffer into itself
   //
   AC(const CML::ASN::Bytes &encodedAC);
   AC(const AC &that);
   
   // DESTRUCTOR
   virtual ~AC(void);

   // PUBLIC MEMBER FUNCTIONS

   // perform access control check of this AC
   // against the SPIF and label that is passed in.
   bool check(Session *s, SPIF &spif, SecurityLabel &label);

   void getDescription(AclString &str) const;

   virtual const CML::ASN::DN &getIssuerName(void) const;
   const AsnOidLst &getPolicyIdList(void) const;
   const CML::ASN::DN &getSubjectName(void) const;

   // Returns a pointer to a SNACC Clearance extension found within the
   // extensions based on the supplied Policy ID.  If the Clearance is
   // not present a NULL pointer will be returned.
   const SNACC::Clearance *getClearance(const SNACC::AsnOid &policyId);

   // Return a pointer to the CML::ASN class
   const CML::ASN::AttributeCert *getSNACC(void)
   { return (const CML::ASN::AttributeCert *)this; }

   Cacheable *clone(void) const {return new AC(*this);}
   bool matches(const MatchInfo &matchInfo) const;
   AC &operator=(const AC &);
   virtual void getIssuerInfo(MatchInfo &matchInfo);

private:
   // PRIVATE MEMBER FUNCTIONS
   void checkExtensions(void);
   // verify the signature on this object.  The
   // public key and parameters used to sign this
   // object are retrieved from issuerPath.
   //
   //bool vValidate(Session *s, const PublicKeyInfo &pubKeyInfo);
   void vPathRules(Session *pSession, const CML::ASN::CertificationPath &certPath);

   // PRIVATE DATA MEMBERS
   //
   mutable AsnOidLst m_policyIdList;
   mutable CML::ASN::DN *m_pIssuerName;
   mutable CML::ASN::DN *m_pName;

   bool checkValidity(void);
   void init();
};

class ACL_API TranslatedLabel
{
public:
   // DEFAULT CONSTRUCTOR
   TranslatedLabel(void);
   // DESTRUCTOR
   ~TranslatedLabel(void);

   // PUBLIC MEMBER FUNCTIONS
   SecurityLabel *translate(SecurityLabel &label, SPIF &originatorSPIF,
                             SNACC::AsnOid &remotePolicyId);
   SecurityLabel *getLastTrnsLabel(void);

private:
   // PRIVATE DATA MEMBER
   SecurityLabel *m_pNewTrnsLbl;  // current

   // PRIVATE MEMBER FUNCTION
   void translateSecurityPolicy(SecurityLabel &origLabel, SPIF &spif,
                                SNACC::AsnOid &remotePolicyId);
};

class ACL_API SecurityLabel : public SNACC::ESSSecurityLabel
{

public:
   // DEFAULT CONSTRUCTOR
   SecurityLabel();

   // ALTERNATE CONSTRUCTOR decodes the buffer into class
   SecurityLabel(const CML::ASN::Bytes &encodedLabel);
   SecurityLabel(const SNACC::ESSSecurityLabel &secLbl);

   // DESTRUCTOR
   virtual ~SecurityLabel(void);

   // PUBLIC MEMBER FUNCTIONS

   // perform validity check on this label
   // using the SPIF that is passed in.
   bool check(Session *s, SPIF &spif);

   // Return a pointer to the SNACC class
   const SNACC::ESSSecurityLabel *getSNACC(void)
   { return (const SNACC::ESSSecurityLabel *)this; }

   void tagAndLevelCheck(void);

   // Return a pointer to a decoded StandardSecurityLabel
   const SNACC::StandardSecurityLabel  &getSSL(void);
   SNACC::SecurityClassification &getClassification(void);

   // Returns a null terminated string representation
   // of the SecurityLabel as defined by SDN.801.
   char *getLabelString(const SPIF &spif);

   // Returns a reference to the security policy
   // identifier contained within the SecurityLabel.
   SNACC::AsnOid &getPolicyId(void);

   SNACC::StandardSecurityLabel::iterator FindTagSet(SNACC::StandardSecurityLabel *pSSL, 
	   SNACC::AsnOid &tagname);

   void setSSL(SNACC::StandardSecurityLabel *pNewTagSets);

   bool isEquivApplicable(int applied);
   bool freeFormOnlyCheck(void);
   virtual bool isOutgoing(void);
   virtual bool isIncoming(void);
   SecurityLabel &operator=(const SecurityLabel &);

   // PUBLIC DATA MEMBERS
   TranslatedLabel equivLabels;
   bool m_obsAccept;

private:
   // PRIVATE MEMBER FUNCTIONS
   void requiredCatCheck(SNACC::RequiredCategories &reqCat, const SPIF &spif, 
                         const SNACC::TagCategories *pSpifTagCat=NULL); //ONLY FOR REPORTING
   void excludedCatCheck(SNACC::OptionalCategoryDataSeqOf &excCat, const SPIF &spif);
   bool findCat(SNACC::AsnOid &tagsetname, SNACC::TagTypeValue &tagtype,
                SNACC::AsnInt &labelandcert);
   void checkBitString(const SNACC::AsnBits& attributeFlags,
                       const SNACC::TagSetName& tagSetName,
                       int tagType,
                       const SPIF &spif);
   void checkSecurityAttributes(const AsnSetOf<SNACC::SecurityAttribute>& attributeFlags,
                          const SNACC::TagSetName& tagSetName,
                          int tagType,
                          const SPIF &spif);
   void CreateErrorStringForLabel(
       char *errStrOut,        // MEMORY INPUT, DATA OUT from this method
       const char *pszIncommingErrorDescription,             // IN
       const int tagType,                                    // IN
       const long labelcert,                                 // IN
       const SPIF &spif,                                     // IN
       const SNACC::AsnOid SNACCOid,                         // IN
       const char *pszOptionalTagTypeDescriptionIN=NULL,     // IN
       const SNACC::TagCategories *pSpifTagCat=NULL);        // IN

   // PRIVATE DATA MEMBER
   SNACC::StandardSecurityLabel *m_pSNACCTmpSSL;
};

class ACL_API OutgoingLabel : public SecurityLabel
{
public:
   // PUBLIC MEMBER FUNCTIONS
   OutgoingLabel(const CML::ASN::Bytes &encodedLabel):SecurityLabel(encodedLabel){};
   OutgoingLabel(const SNACC::ESSSecurityLabel &secLbl):SecurityLabel(secLbl){};
   bool isOutgoing(void);
};

class ACL_API IncomingLabel : public SecurityLabel
{
public:
   // PUBLIC MEMBER FUNCTIONS
   IncomingLabel(const SNACC::ESSSecurityLabel &secLbl):SecurityLabel(secLbl){};
   IncomingLabel(const CML::ASN::Bytes &encodedLabel):SecurityLabel(encodedLabel){};
   bool isIncoming(void);
};

class ACL_API PrintableLabel
{
public:
   // DEFAULT CONSTRUCTOR
   PrintableLabel(void);

   // DESTRUCTOR
   ~PrintableLabel(void);

   // ALTERNATE CONSTRUCTOR Creates a PrintableLabel object from a
   // SecurityLabel and optional SPIF.
   PrintableLabel(SecurityLabel &secLabel, const SPIF &spif);

   // PUBLIC MEMBER FUNCTIONS
   // Returns a null terminated character string
   // representing the security policy identifier.
   char *getPolicyString(void);

   // Returns a null terminated character string
   // representing the privacy mark, if present.
   char *getPrivacyMarkString(void);

   // Returns a null terminated character string representing
   // the security classification name, if present.
   char *getClassificationString(void);

   // Returns an ACL_List template of CMarkingData.
   CMarkingDataList *getMarkingData(void);

   // Returns an ACL_List template of CSecurityCatTag.
   CSecurityCatTagSetList *getSecurityCatTagSetList(void);

   // Directs a formatted SecurityLabel string security
   // to the ostream object 'os'. This string representation
   // includes the security-classification and all security-category
   // values present in the securityLabel (including applying
   // all qualifiers such as prefix, suffix and separator).
   // The security-policy-identifier and privacy-mark values
   // are not included in this string.
   void printLabel(AclString &str, int iPosition=0);
   static char *DetermineSPIF_secCatTagSetString(const SPIF &SPIF_in, 
           const SNACC::AsnOid &OIDCatTagSet,
           SNACC::SecurityCategoryTagSet *&pSPIFsecCatTags); //RETURNED
   static char *DetermineSPIF_secCategoryName(
                             const SNACC::TagCategories &SPIFtagCat);

   // PUBLIC DATA MEMBERS
   SecurityLabel m_SecLabel;
   SPIF *m_pSPIF;
};

class ACL_API CMarkingData : public SNACC::MarkingData
{
public:
   CMarkingData(const SNACC::MarkingData &o):MarkingData(o){};
   // PUBLIC MEMBER FUNCTIONS
   // Returns a null terminated character
   // string representing the marking phrase.
   char *getMarkingPhrase(void);
   // Returns list of marking codes.
   AsnIntList *getMarkingCodes(void);
};

class ACL_API CSecurityCatTagSet : public SNACC::SecurityCategoryTagSet
{
public:
   CSecurityCatTagSet(const SNACC::SecurityCategoryTagSet &o):SecurityCategoryTagSet(o){};
   // PUBLIC MEMBER FUNCTIONS
   // Returns a reference to the securityCategoryTagSetName OID.
   SNACC::AsnOid &getSecCatTagSetNameOID(void);
   // Returns a null terminated character string
   // representing the securityCategoryTagSetString, if present.
   char *getSecCatTagSetString(void);
   // Returns an ACL_List template of CSecurityCatTag.
   CSecurityCatTagList *getSecurityCatTagList(void);
   void removeLabelAndCertValue(int tagType, int spfLACV);
};

class ACL_API CSecurityCatTag : public SNACC::SecurityCategoryTag
{
public:
   CSecurityCatTag(const SNACC::SecurityCategoryTag &o):SecurityCategoryTag(o){};
   // PUBLIC MEMBER FUNCTIONS
   // Returns marking code.
   int getMarkingCode(void);

   // Returns an ACL_LIST template of CmarkingQualifier
   CMarkingQualifierList *getMarkingQualifierList(void);

   // Returns a null terminated character string
   // representing the SecurityCategorityTagName.
   char *getSecurityCatTagNameString(void);

   // Returns an int to indicate which tagType is present.
   int getTagType(void);

   // Returns an ACL_LIST template of CTagCategory
   CTagCategoryList *getTagCategoryList(void);
};

class ACL_API CTagCategory : public SNACC::TagCategories
{
public:
   CTagCategory(const SNACC::TagCategories &o):TagCategories(o){};
   // PUBLIC MEMBER FUNCTIONS
   // Returns a null terminated character string
   // representing the secCategoryName in the SPIF.
   char *getSecCategoryNameString(void);
   // Returns the integer value that corresponds to the
   // Label And Cert Value contained in the TagCategories.
   int getLACV(void);
   // Returns an ACL_List template of CMarkingData.
   // See CMarkingData for details.
   CMarkingDataList *getMarkingData(void);
};

class ACL_API CMarkingQualifier : public SNACC::MarkingQualifier
{
public:
   CMarkingQualifier(const SNACC::MarkingQualifier &o):MarkingQualifier(o){};
   // PUBLIC MEMBER FUNCTIONS
   // Returns a null terminated character
   // string representing the markingQualifier.
   char *getMarkingQualifier(void);
   // Returns a ACL_LIST template of AsnInt.
   int getQualifierCode(void);
};

class ACL_API AclString : public std::string
{
public:
   char * str() { return((char *)c_str()); }
   ACL_API friend AclString& operator<<(AclString&,const char *);
   ACL_API friend AclString& operator<<(AclString&,long);
};

_END_NAMESPACE_ACL

#endif

// EOF aclapi.h
