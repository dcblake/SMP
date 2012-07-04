/*****************************************************************************
File:     cmapi.h
Project:  Certificate Management Library
Contents: Header file for the X.509 Certificate Management Library

Created:  9 February 1997
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>
          Tom Horvath <Tom.Horvath@DigitalNet.com>
          Robin Moeller <Robin.Moeller@baesystems.com>

Last Updated:	27 Jan 2005

Version:  2.5

*****************************************************************************/
#ifndef _CMAPI_H
#define _CMAPI_H


/* ------------- */
/* Include Files */
/* ------------- */
#include <stdlib.h>
#include <time.h>
#ifdef WIN32
	#ifndef _WIN32_WINNT
		#define _WIN32_WINNT 0x0400	// Minimum Windows version required for
	#endif							//    CryptoAPI (Win95 OSR2 or NT 4.0)
	#pragma warning(push, 3)
	#include <windows.h>			// Needed for HMODULE and HCRYPTPROV
	#pragma warning(pop)
	#pragma warning(disable: 4514)
#endif
#include "cryptoki.h"
#include "cmlasn_c.h"
#include "cmapiCallbacks.h"


#if __cplusplus
extern "C" {
#endif


/* ----------------- */
/* Defined Constants */
/* ----------------- */
#ifndef TRUE
#error TRUE not defined!
   #define TRUE    1
#endif
#ifndef FALSE
   #define FALSE   0
#endif

/* Define HMODULE and MS CryptoAPI handle if not defined */
#ifndef WIN32
	#define HMODULE void*
	#define HCRYPTPROV unsigned long
#elif !defined(HCRYPTPROV)
	#define HCRYPTPROV unsigned long
#endif


/* Error constants */
#define CM_NO_ERROR						0

#define CM_MEMORY_ERROR					1
#define CM_INVALID_PARAMETER			2
#define CM_SESSION_NOT_VALID			3
#define CM_NULL_POINTER					4
#define CM_NOT_IMPLEMENTED				5
/* Obsolete:  #define CM_BAD_CONFIG_FILE				6 */
/* Obsolete:  #define CM_CONFIG_NOT_FOUND				7 */
/* Obsolete:  #define CM_NOT_SELF_SIGNED				8 */
#define CM_ASN_ERROR					9
/* Errors 10 and 11 are obsolete */
#define CM_MISSING_PARAMETERS			12
#define CM_INVALID_DN					13
#define CM_NOT_SIG_KEY					14
#define CM_UNKNOWN_ERROR				19
#define CM_NOT_FOUND					20
#define CM_NO_PATH_FOUND				21
/* Obsolete:  #define CM_NO_ERROR_INFO					22 */
#define CM_PATH_VALIDATION_ERROR		23
/* Error 24 is obsolete */
#define CM_NO_GET_OBJ					25
#define CM_NO_FREE_OBJ					26
#define CM_REQ_CALLBACK_MISSING			26
/* Obsolete:  #define CM_NO_TRUSTED_CERTS				27 */
#define CM_TRUSTED_CERT_ERROR			28
#define CM_TRUSTED_CERT_NOT_YET_VALID	29
#define CM_TRUSTED_CERT_EXPIRED			30
#define CM_TRUSTED_CERT_SIG_INVALID		31
#define CM_INVALID_ENC_OBJ_TYPE			32
#define CM_INVALID_ENC_OBJ_LOC			33
#define CM_NO_TOKENS_SUPPORT_SIG_ALG	34
#define CM_SIGNATURE_INVALID			35
/* Obsolete:  #define CM_SIGN_OPERATION_FAILED			36 */
#define CM_DEFAULT_CRYPTO_TOKEN_ERR		37
#define CM_CRYPTO_TOKEN_ERROR			38

/* Obsolete:  #define CM_LDAP_DLL_INVALID				41 */
/* Obsolete:  #define CM_LDAP_UNAVAILABLE				42 */
/* Obsolete:  #define CM_LDAP_INITIALIZATION_FAILED		43 */
/* Obsolete:  #define CM_LDAP_CONNECTION_FAILED			44 */
/* Obsolete:  #define CM_LDAP_BIND_FAILED				45 */
/* Obsolete:  #define CM_LDAP_SEARCH_FAILED				46 */

/* S&R Library errors */
/* Errors 47 - 49 are obsolete */
#define CM_SRL_INITIALIZATION_FAILED	50	/* S&R library failed to initialize */
/* Obsolete:  #define CM_DB_IO_ERROR					60 */
/* Obsolete:  #define CM_DB_UNRECOGNIZED_FILE			61 */
/* Obsolete:  #define CM_DB_ALREADY_EXISTS				62 */
/* Obsolete:  #define CM_DB_FLUSH_FAILURE				63 */
/* Obsolete:  #define CM_DB_INDEX_ERROR					64 */

/* Cert Path Validation Errors */
#define CM_NON_FATAL_LOW						100

#define CM_SIGNATURE_ALG_MISMATCH				100
#define CM_CERT_SIGNATURE_INVALID				101
#define CM_CERT_NOT_YET_VALID					102
#define CM_CERT_EXPIRED							103
#define CM_NAME_MISMATCH						104
#define CM_PATH_LEN_EXCEEDED					105
#define CM_INVALID_CA							106
/* Errors 107-110 are obsolete */
#define CM_INVALID_CERT_POLICY					111
#define CM_INVALID_SUBJECT_NAME					112
#define CM_INVALID_KEY_USE						113
#define CM_UNRECOGNIZED_ALT_NAME				114
#define CM_INVALID_ALT_NAME						115
#define CM_UNRECOGNIZED_CRITICAL_CERT_EXT		116

#define CM_CRL_NOT_AVAIL						117		/* Obsolete */
#define CM_REV_STATUS_NOT_AVAIL					117
#define CM_CRL_SIG_ALG_MISMATCH					118
#define CM_CRL_SIGNATURE_INVALID				119
#define CM_CRL_OUT_OF_DATE						120
#define CM_CERT_REVOKED							121		/* unspecified reason */
#define CM_KEY_COMPROMISED						122
#define CM_CERT_AFFILIATION_CHANGED				123
#define CM_CERT_SUPERSEDED						124
#define CM_CERT_NO_LONGER_NEEDED				125		/* cessationOfOperation */
#define CM_CERT_ON_HOLD							126
#define CM_UNRECOGNIZED_CRITICAL_CRL_EXT		127
#define CM_UNRECOGNIZED_CRITICAL_CRL_ENTRY_EXT	128
#define CM_UNRECOGNIZED_EXT_KEY_USAGE			129
#define CM_NO_TOKENS_SUPPORT_CERT_SIG_ALG		130
#define CM_NO_TOKENS_SUPPORT_CRL_SIG_ALG		131
#define CM_CRITICAL_KEY_COMPROMISE_NOT_CHECKED	132
/* Obsolete:  #define CM_REV_REASONS_NOT_CHECKED			133	*/
/* Obsolete:  #define CM_INVALID_CRL						134 */
/* Errors 135-138 are obsolete */
/* Obsolete:  #define CM_CRL_PATH_NOT_FOUND					139 */
/* Obsolete:  #define CM_CRL_PATH_NOT_VALID					140 */
#define CM_CRL_INITIALIZATION_FAILED			141	/* CRL library failed to initialize */
#define CM_INVALID_EXT_KEY_USE					142
#define CM_INVALID_TRUSTED_CERT_DN				143
/* Obsolete:  #define CM_TRUSTED_CERT_NOT_SELF_SIGNED		144 */
#define CM_TRUSTED_CERT_NOT_SIG_KEY				145
#define CM_TRUSTED_CERT_MISSING_PARAMETERS		146
#define CM_REQUIRED_NAME_MISSING				147
#define CM_ISSUER_CERT_NOT_FOUND				148
#define CM_CROSS_CERT_NOT_FOUND					149
#define CM_PATH_BUILD_PROB_TOO_LOW				150
#define CM_CERT_PRIVILEGE_WITHDRAWN				151
#define CM_MISSING_USER_CERT_POLICY				152
#define CM_INVALID_POLICY_MAPPING            153

/* Error codes for DMS Subject Directory Attribute checking */
#define CM_INVALID_DMS_PRIVILEGE       160 /* Equivalent to MISSI PRBAC_AUTH error */
#define CM_DMS_NULL_SUBJECT_DN         161 /* DMS cannot have NULL subject DN's */
#define CM_DMS_NO_CA_CONSTRAINTS       162 /* Cert did not contain CA Constraints */

#define CM_NON_FATAL_HIGH              199

/* ASN.1 encoded buffer types */
#define CM_CERT_TYPE       1
#define CM_CERTPATH_TYPE   2

/* Misc constants */
#define CM_NOT_PRESENT     -128
#define CM_SET             1
#define CM_NOT_SET         -1



/* ------------------------- */
/* Variable Type Definitions */
/* ------------------------- */
typedef enum SearchBounds {
    CM_SEARCH_LOCAL = 1,    /* Search only the local database */
    CM_SEARCH_REMOTE,       /* Search only the remote data store */
    CM_SEARCH_BOTH,         /* Search both the local & remote data stores */
    CM_SEARCH_UNTIL_FOUND   /* Search the local and stop if object found */
} SearchBounds;

/* CertMatch_struct
 * This structure is used to allow a request for certificates using more
 * info than just the DN of the subject.  The user would fill in the fields
 * of interest with the appropriate values for info they want the target
 * cert(s) to match against during a search.  For those fields that the
 * user does care about, they should be filled with NULLs.
 */
typedef struct
{
	CM_OID			algOID;     /* C string - public key algorithm oid */
	CM_TimePtr		validOnDate;/* C string - cert valid on this date */
	CM_DN			issuer_DN;     /* C string - DN of the cert issuer */
	char			*emailAddr;    /* C string - RFC822 e-mail address */
	Bytes_struct	*serialNum;	/* serial number of the certificate */
	Policy_struct	*poly;      /* policy for this cert */
	Bytes_struct	*sub_kmid;  /* subject unique key material identifier */
	short			pkey_len;      /* Obsolete */
} CertMatch_struct;

/* struct to use when requesting CRL's.  Set the fields you don't
 * want to match on to empty (null).  Signature is the alg that
 * was used to sign the CRL.  Fill in issue after date to get CRL's that
 * were issued from that date upwards.  Fill in issue before date with a
 * date you don't want any crl's after.
 *
 *  sig    after  before   (with "onlyOne" set to FALSE)
 * -----   ----  -----
 *   0      0      0  => all crls for an issuer
 *   x      0      0  => all crls for issuer with x sig
 *   x      y      0  => all crls for issuer with x sig from y date up
 *   x      y      z  => "" from y date but no later than z date
 *   x      0      z  => all crls for issuer with x sig prev to z date
 *   etc.
 *
 * The "onlyOne" flag, if true indicates that only 1 CRL should be returned.
 * Which one is dependant on the date fields settings.
 *
 * after   before  (with "onlyOne" set to TRUE)
 * -----   ------
 *  y        0       => CRL issued after y date, closest to y date
 *  y        x       => most recent CRL issued after y, but no later than x date
 *  0        x       => most recent CRL issued before x date
 *  0        0       => most recent CRL for the particular issuer
 *
 */
typedef struct
{
	CM_OID		signature;		/* Algorithm used by issuer to sign CRL */
	CM_TimePtr	issueAfter;		/* C string - issued on or after this date */
	CM_TimePtr	issueBefore;	/* C string - issued on or before this date */
	CM_BOOL		onlyOne;       /* set to TRUE if you only want 1 match returned */
} CRLMatch_struct;

typedef struct
{
   Policy_struct	*initialPolicy;      /* Initial policy set for this session
                                        * (NULL indicates any-policy) */
   CM_BOOL			reqExplicitPol;      /* Initial-explicit-policy flag */
   CM_BOOL			inhibitPolMapping;   /* Initial-policy-mapping-inhibit flag */
   CM_BOOL			inhibitAnyPolicy;    /* Initial-inhibit-any-policy flag */
} PolicyData_struct;

/* Path Validation Error list */
typedef struct errorInfo_List
{
   CM_DN dn;                     /* DN from cert/origin of error */
   char *xinfo;                  /* extra/specific info for the error */
   short error;                  /* the error value */
   struct errorInfo_List *next;	/* next in list if any, else null */
} ErrorInfo_List;

/* Valid Public Key structure */
typedef struct
{
	Pub_key_struct key;				/* Validated public key */
	ushort *keyUse;					/* Intended use of key */
	CM_BOOL keyUseCritical;			/* Key Usage Criticality */
	Policy_struct *caPolicies;		/* Policies key is constrained by */
	Policy_struct *userPolicies;	/* Policies acceptable to the user */
	CM_BOOL explicitPolFlag;		/* TRUE if each cert must contain an
                                  * acceptable policy */
	Pol_maps_struct *mappings;		/* Details of any policy mappings */
	Ext_key_use_LL *extKeyUsage;	/* Extended Key Usage NULL if not present */
	CM_BOOL extKeyUsageCritical;	/* Extended Key Usage criticality */
	ErrorInfo_List *errors;			/* Path validation errors, NULL if none */
	EncRevObject_LL* m_pRevocationData; /* CRLs or OCSP responses used during 
                                        * path validation */

} ValidKey_struct;


/* Revocation policy settings */
typedef enum
{
    CM_REVNONE = 1,
    CM_REVCRL
} RevocationPolicy; 

/* Cryptographic token interface types */
typedef enum
{
	CM_DEFAULT_TOKEN,	/* Indicates default token should be loaded and used */
	CM_NO_TOKEN,		/* Indicates no token is present or will be used */
	CM_PKCS11,			/* Indicates PKCS #11 token */
	CM_MS_CSP			/* Indicates Microsoft CSP token */
} CM_TokenHandleType;

/* Function Pointer type for PKCS11 C_GetFunctionList */
typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, CM_GetFuncListFP)
	(CK_FUNCTION_LIST_PTR_PTR);

/* PKCS #11 token handle */
typedef struct
{
	HMODULE				hLibrary;      /* Optional handle to PKCS #11 library */
	CM_GetFuncListFP	pGetFuncList;  /* Optional ptr to C_GetFunctionList() */
	CK_SESSION_HANDLE	session;       /* PKCS #11 session */
} CM_PKCS11Token;

/* Cryptographic token handle */
typedef struct
{
	CM_TokenHandleType	type; /* Indicates type of handle in union */
	union tokenHandleUnion
	{
		CM_PKCS11Token	hPKCS;   /* Handle to PKCS #11 token */
		HCRYPTPROV		hCSP;    /* Handle to Microsoft CSP */
	} handle;
} CM_CryptoToken;

/* Cryptographic token handle list */
typedef struct CM_tokenList
{
	CM_CryptoToken token;			/* Crypto token */
	struct CM_tokenList* next;		/* Next token handle in list */
} CM_CryptoTokenList;

/* Logging levels */
#define CM_LOG_LEVEL_0		0	/* logging disabled */
#define CM_LOG_LEVEL_1		1	/* basic logging of paths built and validation information */
#define CM_LOG_LEVEL_2		2	/* log path discovery information in addition */
#define CM_LOG_LEVEL_3		3	/* show current and minimum probability in addition */
#define CM_LOG_LEVEL_4		4	/* show link probabilities in addition */
#define CM_LOG_LEVEL_5		5	/* show path probabilities in addition */
typedef unsigned int CMLogLevel;

typedef struct
{
	size_t		cbSize;		/* Size of this structure (in bytes) */
	char		*filename;     /* The path name of the log file (must be unique in a multi-threaded app) */
	CMLogLevel	level;		/* Log level defined by CMLogLevel */
} CML_LogSettings_struct;

/* Session initialization settings */
typedef struct
{
	size_t				cbSize;     /* Size of this structure (in bytes) */
	void*				extHandle;     /* Handle to retrieval callback library */
	ExtGetObjFuncPtr	pGetObj;    /* External get callback function pointer*/
	ExtUrlGetObjFuncPtr	pUrlGetObj;	/* External URL get callback function pointer */
	ExtFreeObjFuncPtr	pFreeObj;	/* External free callback function pointer */
	void*				pTokenObj;     /* Obsolete -- use tokenList instead */
	RevocationPolicy	revPolicy;  /* How certificate revocation is to be done */
	EncCert_LL*	trustedCerts;		/* List of trusted certs for the session */
	ushort		nCertCacheSize;   /* Maximum number of certs to store in cache */
	time_t		certCacheTTL;		/* Maximum time that certs will be cached */
	ushort		nMaxPaths;			/* Maximum number of paths to try and build */
	ushort		nCrlCacheSize;		/* Obsolete -- use revocation callbacks */
	time_t		crlCacheTTL;		/* Maximum time that CRLs will be cached */
	time_t		crlGracePeriod;   /* Maximim time that a CRL is considered to be valid
                                  * after the Next Update time has passed */
	unsigned int         tokensToUse;/* Obsolete -- use tokenList instead */
	CM_CryptoTokenList   tokenList;	/* Cryptographic tokens to use */
	void*       extRevHandle;        /* Handle to revocation status callback library */
	ExtCheckRevStatusFP  pCheckStatus;	/* Check revocation status callback function */
	ExtFreeRevStatusFP   pFreeStatus;	/* Free revocation status callback function */
	CM_BOOL     m_returnRevocationData; /* Flag specifies whether or not to return
                                        * CRLs/OCSP responses. Default is FALSE. */
} InitSettings_struct;

/* ------------------- */
/* Function Prototypes */
/* ------------------- */

/* Session Management Functions */ 
CM_API_FN(short) CM_CreateSession(ulong *sessionID);
CM_API_FN(short) CM_CreateSessionExt(ulong *sessionID,
									 InitSettings_struct* pSettings);
CM_API_FN(short) CM_DestroySession(ulong *sessionID);
CM_API_FN(short) CM_SetPolicy(ulong sessionID,
							  PolicyData_struct* policySettings);
CM_API_FN(short) CM_SetTrustedCerts(ulong sessionID,
									EncCert_LL* trustedCerts,
									ErrorInfo_List** errInfo);
CM_API_FN(short) CM_SetLogSettings(ulong sessionID,
								   CML_LogSettings_struct *logInfo);

/* Certificate Operations Functions */
CM_API_FN(short) CM_GetCertID(Bytes_struct* asn1cert, Bytes_struct **issuerDN,
							  Bytes_struct **serialNum, Bytes_struct **subjID);
CM_API_FN(short) CM_GetEncodedDN(Bytes_struct* asn1cert,
								 Bytes_struct **encodedDN);
CM_API_FN(short) CM_RequestCerts(ulong sessionID, CM_DN subject,
								 CertMatch_struct *matchInfo,
								 SearchBounds boundsFlag,
								 EncCert_LL **certificateList);
CM_API_FN(short) CM_RequestCRLs(ulong sessionID, CM_DN issuer,
								Dist_pts_struct *distPts,
								CRLMatch_struct *matchInfo,
								SearchBounds boundsFlag, EncCRL_LL **crlList);
CM_API_FN(short) CM_RequestEncCertPath(ulong sessionID,
									   Bytes_struct* subjectCert,
									   SearchBounds boundsFlag,
									   Bytes_struct **encPath);
CM_API_FN(short) CM_RetrieveKey(ulong sessionID, Bytes_struct* asn1data,
								short asn1Type, ValidKey_struct **validKey,
								SearchBounds boundsFlag);
CM_API_FN(short) CM_RetrievePath(ulong sessionID, Bytes_struct* asn1data,
								short asn1Type, Cert_path_LL **decPath,
								ValidKey_struct **validKey, 
								SearchBounds boundsFlag);
CM_API_FN(short) CM_ValidateSignature(ulong sessionID, Bytes_struct* asnPtr,
									  ValidKey_struct *valPubKey);


/* Memory Management Functions */
CM_API_FN(void) CM_FreeBytes(Bytes_struct **data);
CM_API_FN(void) CM_FreeEncCertList(EncCert_LL **listHead);
CM_API_FN(void) CM_FreeEncCRLs(EncCRL_LL **listHead);
CM_API_FN(void) CM_FreeErrInfo(ErrorInfo_List **errInfo);
CM_API_FN(void) CM_FreeValidKey(ValidKey_struct **key);


/* Experimental Functions */
CM_API_FN(void) CMU_FreeRevocationData(EncRevObject_LL* revDataList);
CM_API_FN(const char*) CMU_GetErrorString(short errorCode);


#if __cplusplus
}	/* end of extern "C" */
#endif


#endif
