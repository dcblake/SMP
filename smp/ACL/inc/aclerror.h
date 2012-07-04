/* @(#) aclerror.h 1.15 05/18/99 17:54:55 */

#ifndef _ACL_ERROR_H_
#define _ACL_ERROR_H_

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

// Error constants
#define ACL_NO_ERROR                    0
#define ACL_MEMORY_ERROR                1
#define ACL_THREAD_ERROR                2
#define ACL_NULL_POINTER                4
#define ACL_ASN_ERROR                   5
#define ACL_CFG_ERROR                   6
#define ACL_DECODE_ERROR                7
#define ACL_ENCODE_ERROR                8

// AC errors
#define ACL_AC_CHECK_ERROR             10
#define ACL_AC_VAL_ERROR               11
#define ACL_AC_EXT_ERROR               12
#define ACL_AC_NULL_POINTER            14
#define ACL_AC_NOT_VALID_ERROR         15

// ClearanceCert errors
#define ACL_CC_VAL_ERROR               16
#define ACL_CC_EXT_ERROR               17
#define ACL_CC_NULL_POINTER            18
#define ACL_CC_NOT_VALID_ERROR         19

// Security Label errors
#define ACL_LABEL_CHECK_ERROR          20
#define ACL_REQ_CAT_NOT_FOUND          21
#define ACL_EXC_CAT_FOUND              22
#define ACL_NO_MARKING_QUALIFIER       23
#define ACL_NO_MARKING_CODE            24

// TRUST errors
#define ACL_TRUST_ERROR                30
#define ACL_TRUST_EXISTS               31

// LDAP errors
#define ACL_LDAP_DLL_NOT_FOUND         40   // Can't find the LDAP library
#define ACL_LDAP_DLL_INVALID           41   // Problem linking to LDAP library
#define ACL_LDAP_UNAVAILABLE           42
#define ACL_LDAP_INITIALIZATION_FAILED 43   // Unable to initialize LDAP library
#define ACL_LDAP_CONNECTION_FAILED     44
#define ACL_LDAP_BIND_FAILED           45
#define ACL_LDAP_SEARCH_FAILED         46
#define ACL_SRL_INVALID_PARAMETER      47

// SPIF errors
#define ACL_SPIF_VAL_ERROR             50
#define ACL_SPIF_NULL_POINTER          54
#define ACL_SPIF_NOT_VALID_ERROR       55
#define ACL_NO_EQUIV_POLICY            56
#define ACL_NO_EQUIV_CLASSIFICATION    57
#define ACL_SPIF_PCA_POLICYID_ERROR    58
#define ACL_SPIF_SIGNER                59  // SPIF Signer Attribute check failed

// CML related errors
#define ACL_CML_ERROR                  60

// Access Control errors                   // REASON FOR FAILURE
#define ACL_AC_AC_ERROR                61  // AC POLICY ID FAILED
#define ACL_AC_CC_ERROR                62  // CLEARANCECERT POLICY ID FAILED
#define ACL_AC_SPIF_ERROR              63  // SPIF POLICY ID FAILED
#define ACL_AC_SPIF_AC_ERROR           64  // AC AND SPIF POLICY ID FAILED
#define ACL_AC_SPIF_CC_ERROR           65  // CC AND SPIF POLICY ID FAILED
#define ACL_SEC_CAT_ERROR              66  // SECURITY CATEGORY ERROR (getSSLPrivs)
#define ACL_SEC_TAG_ERROR              67  // SECURITY TAG ERROR (checkTagSetPriv)

#define ACL_SPIF_CC_ERROR              69  // SPIF POLICY ID FAILED IN CC::check

// Validation error
#define ACL_VAL_ERROR                  70
#define ACL_NOT_VALID_TIME             71

// Clearance Cert intersect related errors
//
#define ACL_NO_CA_CERTS                80 // CertPath return by CML with no CA certs
#define ACL_NO_FORWARD_CERT            81 // CertPath is missing forward component
#define ACL_CC_ERROR                   82 // Clearance cert error

// DMS support related errors
#define ACL_NO_EQUIV                   90 // No equivalency mapping
#define ACL_TRANS_ERROR                91 // Can't translate label if spif policy equals label

// Label related errors
#define ACL_NO_TAG_SETS               100 // No Standard Security Label (TagSets) present
#define ACL_NO_SEC_CATS               101 // No Security Categories present

// Cache related errors
#define ACL_CACHE_ERROR               200 // Generic error for cache
#define ACL_NO_SPIF                   201 // SPIF NOT FOUND
#define ACL_NO_CC                     202 // ClearanceCert NOT FOUND
#define ACL_NO_AC                     203 // AttributeCertificate NOT FOUND

// General Access Control errors
#define ACL_MISSING_POLICY            204 // Clearance for policy not found

// Other constants
#define ACL_PATH_LEN                  512   // size paths & file names
#define ACL_STR_BUF_LEN               512
#define ACL_KMID_LEN                    8   // Length of Mosaic KMID (in bytes)
// Config Read constants
#define ACL_DEFAULT_CFG_FILE "acl.cfg"
#define ACL_KW_SZ                      40  // maximum length of the Keyword
#define ACL_KW_VAL_SZ                 512  // maximum length of the Keyword Value
#define ACL_SECT_SZ                    40  // maximum length of the Section label

_BEGIN_NAMESPACE_ACL

//////////////////////////////////////////////////////////////////////////
// ACL_Exception is the class used to throw exceptions
class ACL_API ACL_Exception : public SNACC::SnaccException
{
public:
   ACL_Exception(const CML::ASN::Exception &cmlErr, 
                 long lineNo, const char *pszFuncName,
                 const char *pszFileName) throw(); 
   
   ACL_Exception(const char *file, long line_number, const char *function=NULL,
                 const char *whatStr=NULL, long errorCode=DEFAULT_ERROR_CODE) 
                 throw();

   ACL_Exception(long err_num=DEFAULT_ERROR_CODE) throw();

   ACL_Exception(const ACL_Exception &o);

   virtual ~ACL_Exception() throw();

   const CML::ASN::Exception * getCMLError(void);
   ACL_Exception &             operator=(const ACL_Exception &o);

   void setErrorString(const char *errStr);

private:

   CML::ASN::Exception *m_pCMLerror;
};

#define ACL_EXCEPT(errno, s) ACL_Exception(STACK_ENTRY,s, errno) 


_END_NAMESPACE_ACL

#endif // _ACL_ERROR_H_
