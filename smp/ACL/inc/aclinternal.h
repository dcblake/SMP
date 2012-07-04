
#ifndef _aclinternal_h_
#define _aclinternal_h_

#include "acl_api.h"
#include "aclerror.h"
#include "aclintexcept.h"
#include <memory>
#include <string>
#include <time.h>
#include "srlapi.h"

// -----------------------------------------------------------------------
// File:     aclinternal.h
// Project:  Attribute Certificate Library
// Contents: Header file for the internal (low-level) functions used in the
//           Attribute Certificate Library
//
// -----------------------------------------------------------------------

// maximum length of a line in a configuration file
#define ACL_MAX_LINE_LEN  ACL_KW_VAL_SZ + ACL_KW_SZ + 2

// -------------------------
// Variable Type Definitions
// -------------------------

#ifndef uchar
    #define uchar unsigned char
#endif
#ifndef ushort
    #define ushort unsigned short
#endif
#ifndef ulong
    #define ulong unsigned long
#endif

_BEGIN_NAMESPACE_ACL

// do some typedefs to cleanup the code
typedef SNACC::SpiftoSignSeqOf  SpifSecurityClassifications;
//typedef SpiftoSignSeqOf1 SecurityCategoryTagSets;
//typedef SpiftoSignSeqOf2 EquivalentPolicies;
typedef SNACC::SpifSecurityClassificationSeqOf EquivalentClassifications;

// Configuration Reading Functionality
typedef char Keyword[ACL_KW_SZ];
typedef char KwValue[ACL_KW_VAL_SZ];
typedef char Section[ACL_SECT_SZ];

typedef SNACC::SecurityTagPrivilegeSetOf SecTagPrivList;



// ACL_API AclString& operator<<(AclString&,char *);
// ACL_API AclString& operator<<(AclString&,long);

//////////////////////////////////////////////////////////////////////////
// this file includes prototypes of test functions

class ConfigFile
{
private:
   FILE *fp;
   char *m_pSection;
   bool m_bSeekToTop;

public:
   ConfigFile(void);
   ConfigFile(char *fn);
   ~ConfigFile(void);
   int GetKwValue(char *keyword, KwValue value, char *section=NULL);
   int GetGlobalKwValue(char *keyword, KwValue value);
   void setSection(char *section);
   void seekToTop(bool flag) { m_bSeekToTop = flag; }
   bool seekToTop(void) { return m_bSeekToTop; }
   bool getNextLine(char line[]);
   bool seekToSection(char *section);
};


typedef short (*DLLvalidateSignature_DEF)(ulong sessionID, Bytes_struct *asnPtr,
                                          ValidKey_struct *valPubKey);

typedef short (*DLLretrieveKey_DEF)(ulong sessionID, unsigned char *asn1data,
                                    short asn1Type, ValidKey_struct **validKey,
                                    SearchBounds boundsFlag);

typedef short (*DLLrequestCerts_DEF)(ulong sessionID, char *subject,
                                     CertMatch_struct *matchInfo,
                                     SearchBounds boundsFlag,
                                     EncCert_LL **certificateList);

typedef short (*DLLrequestEncCertPath_DEF)(ulong sessionID,
                                     unsigned char *subjectCert,
                                     SearchBounds boundsFlag,
                                     Bytes_struct **encPath);

typedef void (*DLLfreeValidKey_DEF)(ulong sessionID, ValidKey_struct **key);

typedef void (*DLLfreeEncCertList_DEF)(ulong sessionID, EncCert_LL **listhead);

typedef void (*DLLfreeBytes_DEF)(ulong sessionID, Bytes_struct **bytes);

// Structure to hold information about the CML session including pointers
// to the CML functions that are used by the Cert Mgmt library
typedef struct CMLinfo_struct
{
   char *lpszCMLDllName;          // Name of CML DLL
   unsigned long *sessionId;
   DLLretrieveKey_DEF pDLLretrieveKey;   // Function pointer to retrieveKey()
   DLLrequestCerts_DEF pDLLrequestCerts; // Function pointer to requestCerts()
   DLLrequestEncCertPath_DEF pDLLrequestEncCertPath; // Function pointer to requestEncCertPath()
   DLLfreeValidKey_DEF pDLLfreeValidKey; // Function pointer to CM_FreeValidKey()
   DLLfreeEncCertList_DEF pDLLfreeEncCertList; // Function pointer to CM_FreeEncCertList()
   DLLfreeBytes_DEF pDLLfreeBytes; // Function pointer to CM_FreeBytes()
   DLLvalidateSignature_DEF pDLLvalidateSignature;
#ifdef WIN32
    HINSTANCE CMLDLLInstance;     // MS CALL. DLL Load instance.
#else
    void *CMLDLLInstance;         // Unix CALL. DLL Load instance.
#endif
} CMLinfo_struct;

// -------------------
// Function Prototypes
// -------------------
CML::ASN::BytesList *LdapRequest(CML::ASN::DN *pSnaccDN, 
                     long objectFlag, ulong *sessionID);
short cvt_Name2cStr(char **cm_name, SNACC::Name *theName);

class CSecurityTag : public SNACC::SecurityTag
{
public:
   // DEFAULT CONSTRUCTOR DOES NOTHING
   CSecurityTag(void);

   //    CSecurityTag(SNACC::SecurityTagsetOf &o);
   //    CSecurityTag(SecurityTagPrivilege &o);

   // all stubbed out for now  (note: need to check choiceId to see if we
   // are dealing with restrictivebitMapCid, or enumeratedAttributesCid, or
   // permissivebitMapCid
   //
   //    static bool findLabelAndCertValue (SNACC::SecurityTag &secTag,
   //                                       SNACC::AsnInt &labelAndCertValue );
   static void CSecurityTag::enumAnd(SecTagPrivList *&results,
                              SecTagPrivList &userEnum,
                              SecTagPrivList &caEnum);
   
   static SNACC::SecurityTags::const_iterator findLabelAndCertValue(const SNACC::SecurityTags &o,
                                         const AsnIntType labelAndCertValue,
                                         const SNACC::TagTypeValue &tagtype);
/*   static bool findLabelAndCertValue(const SNACC::SecurityTags &secTags,
                                     AsnIntType labelAndCertValue,
                                     SNACC::TagTypeValue &tagtype);
  
  */
  static bool removeLabelAndCertValue(SNACC::SecurityTags &secTags,
                                      const AsnIntType labelAndCertValue,
                                      const SNACC::TagTypeValue &tagtype);
   static bool isTagTypeEqual(const SNACC::SecurityTag &secTag,
                              SNACC::SecurityCategoryTag &secCatTag);
   static bool permissiveCheck(SNACC::AsnBits &permissive, 
                               SNACC::AsnBits &labelValue);
   static int restrictiveCheck(SNACC::AsnBits &restrictive,
                               SNACC::AsnBits &labelValue);
   static int enumeratedAttributesCheck(SNACC::SecurityTagSeq1 &secTagEnumerated,
                                        SNACC::SecurityTagPrivilegeSetOf
                                        &secTagPrivEnumerated,
                                        bool enumRestrictive);
   static void addTagSet(SNACC::StandardSecurityLabel *&pLblTagSets,
                         const SNACC::AsnOid &spfTagSetOid, 
                         const AsnIntType labelAndCertValue,
                         const SNACC::SecurityCategoryTag &spfCatTag);
   static void getTagTypeStr(const SNACC::SecurityTag &secTag, AclString &o);
   void Print (AclString &os) const;
};

class CAsnBits
{
public:
   // DEFAULT CONSTRUCTOR DOES NOTHING
   CAsnBits(void){};
   static void And(SNACC::AsnBits *result, SNACC::AsnBits &userBits,
                   SNACC::AsnBits &caBits);
   static bool checkBit(SNACC::AsnBits &bits, AsnIntType bit);
   static bool isEmpty(SNACC::AsnBits &bits);

};

_END_NAMESPACE_ACL

#endif
