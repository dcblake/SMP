/*****************************************************************************
File:		srlapi.h
Project:	Storage & Retrieval library
Contents:	Header file for the Storage & Retrieval library

Created:	14 November 2000
Author:		Robin Moeller <Robin.Moeller@digitalnet.com>

Last Updated:	11 May 2004

Version:	2.4

*****************************************************************************/
#ifndef _SRL_RET_H
#define _SRL_RET_H

/* ------------- */
/* Include Files */
/* ------------- */
#include "cmapi.h"
#include "SRL_ldap.h"


/* Set the SRL Library calling convention and return type */
#if defined (_WINDOWS) || defined (WIN32)
	#define SRL_CALL	__cdecl
	#define SRL_API(type)	__declspec(dllexport) type _cdecl
	#ifndef _SRL_INTERNAL_H
		#define SRL_IMPORT	__declspec(dllimport)
	#else
		#define SRL_IMPORT	__declspec(dllexport)
	#endif
#else
	#define SRL_API(type)	type
	#define SRL_IMPORT extern
#endif


#if __cplusplus
extern "C" {
#endif


/* Error constants */
#define SRL_SUCCESS						0
#define SRL_MEMORY_ERROR				201
#define SRL_INVALID_PARAMETER			202
#define SRL_SESSION_NOT_VALID			203
#define SRL_NULL_POINTER				204
/* Obsolete:  #define SRL_NOT_IMPLEMENTED				205 */
/* Obsolete:  #define SRL_BAD_CONFIG_FILE				206 */
#define SRL_CONFIG_NOT_FOUND			207
#define SRL_ASN_ERROR					208
#define SRL_NOT_SELF_SIGNED				209
#define SRL_NOT_SIG_KEY					210
#define SRL_MISSING_PARAMETERS			211
#define SRL_INVALID_DN					212
#define SRL_CERT_NOT_YET_VALID			213
#define SRL_CERT_EXPIRED				214
#define SRL_UNKNOWN_ERROR				215
#define SRL_NOT_FOUND					216
#define SRL_UNDEFINED_TYPE				217
#define SRL_UNKNOWN_OBJECT				218
#define SRL_NO_DB						219

/* LDAP Errors */
#define SRL_LDAP_LOAD_FAILED			240
#define SRL_LDAP_INIT_FAILED			241
#define SRL_LDAP_UNAVAILABLE			242
#define SRL_LDAP_CONNECTION_FAILED		243
#define SRL_LDAP_BIND_FAILED			244
#define SRL_LDAP_SEARCH_FAILED			245
#define SRL_NOT_LDAP_URL				246		/* Obsolete */
#define SRL_INVALID_URL					246 
#define SRL_LDAP_PARSE_ERROR			247		/* Obsolete */
#define SRL_URL_PARSE_ERROR				247
#define SRL_LDAP_FUNCTION_NOT_SPECIFIED 248
#define SRL_TCP_CONNECTION_FAILED		249
#define SRL_FTP_ERROR					250
#define SRL_HTTP_ERROR					251

/* Database related errors */
#define SRL_DB_IO_ERROR					260	/* open/read/write/seek/delete/insert errs */
#define SRL_DB_UNRECOGNIZED_FILE		261	/* file does not appear to be a db file */
#define SRL_DB_ALREADY_EXISTS			262	/* can't replace existing with new file */
#define SRL_DB_FLUSH_FAILURE			263	/* unable to compact/flush db file */
#define SRL_DB_INDEX_ERROR				264	/* indexing error during item deletion */


/* ------------------------- */
/* Variable Type Definitions */
/* ------------------------- */

/* LDAP Function Pointer Types */
typedef LDAP_API(LDAP *) (LDAP_CALL *SRL_LDAP_initFp)(const char *defhost, 
         int defport);
typedef LDAP_API(LDAP *) (LDAP_CALL *SRL_LDAP_openFp)(const char *host, int port);
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_setOptionFp)(LDAP *ld, int option, 
         void *optdata);
typedef LDAP_API(LDAPMessage *) (LDAP_CALL *SRL_LDAP_firstEntryFp)(LDAP *ld,
         LDAPMessage *chain);
typedef LDAP_API(LDAPMessage *) (LDAP_CALL *SRL_LDAP_nextEntryFp)(LDAP *ld, 
         LDAPMessage *entry);
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_countEntriesFp)(LDAP *ld, 
         LDAPMessage *chain);
typedef LDAP_API(struct berval **) (LDAP_CALL  *SRL_LDAP_getValuesLenFp)(LDAP *ld,
         LDAPMessage *entry,const char *target);
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_countValuesLenFp)(struct berval **vals);
typedef LDAP_API(void) (LDAP_CALL *SRL_LDAP_valueFreeLenFp)(struct berval **vals);
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_msgfreeFp)(LDAPMessage *lm);
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_searchFp) (LDAP *ld, const char *base, int scope,
					    const char* filter, char **attrs, int attrsonly );
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_unbindFp)(LDAP *ld);
//added per request Entrust CRW 03/16/2002
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_simpleBindFp)(LDAP *ld,const char *who, 
         const char *passwd);
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_resultFp)(LDAP *ld,int msgid, int all, struct timeval* timeout, LDAPMessage** result); 
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_abandonFp)(LDAP *ld,int msgid);
typedef LDAP_API(int) (LDAP_CALL *SRL_LDAP_result2errorFp)( LDAP *ld, LDAPMessage *r, int freeit );

/* CML Retrieval Session settings */
/* Structure to hold information about the LDAP session including pointers 
to the LDAP functions that are used by the Cert Mgmt library. */
typedef struct
{
	char	*LDAPserver;		/* LDAP Server Name */
	long	LDAPport;			/* LDAP Port Number */
} LDAPServerInit_struct;

#define SRL_LDAP_FUNC_VER   2

typedef struct
{
	int							StructVersion;
	SRL_LDAP_initFp			    init;
	SRL_LDAP_setOptionFp        set_option;
	SRL_LDAP_firstEntryFp		first_entry;
	SRL_LDAP_nextEntryFp        next_entry;
	SRL_LDAP_countEntriesFp     count_entries;
	SRL_LDAP_getValuesLenFp     get_values_len;
	SRL_LDAP_countValuesLenFp	count_values_len;
	SRL_LDAP_valueFreeLenFp     value_free_len;
	SRL_LDAP_msgfreeFp			msgfree;
	SRL_LDAP_searchFp			search;
	SRL_LDAP_unbindFp			unbind;
	SRL_LDAP_simpleBindFp		simple_bind;
	SRL_LDAP_resultFp			result;
	SRL_LDAP_abandonFp			abandon;
	SRL_LDAP_result2errorFp		result2error;
} LDAPFuncPtr_struct;

typedef struct {
	 uchar	*hostname;		/* Host Name */
	 int	port;			/* Host port number */
	 CM_DN	URL_DN;			/* The DN (optional) */
	 int	options;		/* Options */
	 char	**attributes;	/* Null terminated array of attributes (optional) */
	 int	scope;			/* LDAP Scope (optional) */
	 uchar	*filter;		/* URL Filters (optional) */
} SRL_URLDescriptor_struct;

typedef struct
{
	char					*SharedLibraryName;	/* Name of LDAP Windows DLL */
	LDAPServerInit_struct	*LDAPServerInfo;	/* Server Information Pointer */
	LDAPFuncPtr_struct		*LDAPFunctions;		/* Pointer to the LDAP Fuction Pointer structure */
	LDAP					*ldapID;
	long					timeout;			/* How long to wait for LDAP results in seconds
												   0 = use LDAP_DEFAULT_TIMEOUT */
} LDAPInitSettings_struct;

typedef enum AsnTypeFlag {
	SRL_CERT_TYPE = USER_CERT_TYPE,
	SRL_CA_CERT_TYPE = CA_CERT_TYPE,
	SRL_CRL_TYPE = CRL_TYPE,
	SRL_ARL_TYPE = ARL_TYPE,
	SRL_DELTA_CRL_TYPE = DELTA_CRL_TYPE,
	SRL_CERT_PATH_TYPE,
	SRL_TRUSTED_CERT_TYPE
} AsnTypeFlag;


/* This structure is used when stepping through a database that
 * contains certificates. The fields of the struct are filled in
 * with some of the info that a particular cert contains.
 * Note: Some of these items are from the Certificate Template
 */
typedef struct dbCertEntryInfo_LL
{
	uchar			tver;			/* used for db template versioning info */
	long			DBid;			/* Database ID of the object */
	uchar			CertType;		/* Type of cert (Cert Authority, User) */
	CM_OID			algOID;			/* C string - public key algorithm oid */
	CM_TimePtr		validFrom;		/* C string - cert valid on this date */
	CM_TimePtr		validTill;		/* C string - up to and including this date (used for TTL) */
	CM_DN			issuer_DN;		/* C string - DN of the cert issuer */
	char			*emailAddr;		/* C string - RFC822 e-mail address */
	Bytes_struct	*serialNum;		/* serial number of the certificate */
	Policy_struct	*poly;			/* policy for this cert */
	Bytes_struct	*sub_kmid;		/* subject unique key material identifier */
	CM_BOOL			trusted;		/* TRUE/FALSE - is pub key a "trusted" key */
	short			pkey_len;		/* length of public key in BITS */
	Bytes_struct	*db_kid;		/* hash value added to keying ID */
	struct dbCertEntryInfo_LL *next;
} dbCertEntryInfo_LL;

/* this struct is used for the same purpose as above, but for
 * CRL entries in a database.
 * Note: Some of these items are from the CRL template
 */
typedef struct dbCRLEntryInfo_LL
{
	uchar			tver;		   /* used for db template versioning info */
	long			DBid;		   /* Database ID of the object */
	uchar			CRLType;	   /* CRL Type (CRL, ARL, DELTA) */
	CM_OID			signature;	   /* Algorithm used by issuer to sign CRL */
	CM_Time			issueDate;	   /* C string - crl valid on this date */
	CM_Time			nextDate;	   /* C string or NULL (optional) next update  */
	Bytes_struct	*db_kid;	   /* hash value added to keying ID */
	time_t			RefreshTime;  /* Refresh time for this CRL */
	struct dbCRLEntryInfo_LL *next;
} dbCRLEntryInfo_LL;

typedef union
{
		dbCertEntryInfo_LL	*certs;	/* cert info LL if typeflag == SRL_CERT_TYPE */
		dbCRLEntryInfo_LL	*crls;	/* crl info LL if typeflag == SRL_CRL_TYPE */
} dbEntryInfo;

/* this struct is used when passing the one of the above two info structs back
 * to an application. Since there may be one or more db entries for a
 * particular DN, information for all the entries for a particular DN
 * are grouped into a linked list.
 */
typedef struct dbEntryInfo_LL
{
	CM_DN   entry_DN;      /* if cert then subject DN, if CRL then issuer DN */

	/* gathering info for entries is optional, so provide fields to hook
	 * the entry name with it's information if requested. (entry_info will
	 * be null if no info requested)
	 */
	dbEntryInfo	info;
	struct dbEntryInfo_LL *next;	/* next link in list */
} dbEntryInfo_LL;

/* Data Base Type Flags */
typedef enum DBTypeFlag {
	SRL_DB_CERT,
	SRL_DB_CRL
} DBTypeFlag;

typedef struct
{
	DBTypeFlag typeflag;		/* Indicates if list contains cert or crl info */
	dbEntryInfo_LL *entryList;	/* List of entry names, with optional info */
} dbEntryList_struct;


typedef struct
{
	CM_OID		  algOID;		/* Subject public key algorithm OID */
	CM_TimePtr	  validOnDate;	/* Cert valid on this date */
	CM_DN		  issuerDN;		/* DN of the cert issuer */
	char		  *emailAddr;	/* Subject's RFC822 e-mail address */
	Bytes_struct  *serialNum;	/* Serial number of the cert */
	Policy_struct *policies;	/* Cert must contain one of the policies */
	Bytes_struct  *subjKMID;	/* Key material ID of the public key */
	short		  pkeyLen;		/* Length of public key in BITS */
	AsnTypeFlag	  CertType;		/* Type of search either
									SRL_CERT_TYPE = USER_CERT_TYPE,
									SRL_CA_CERT_TYPE = CA_CERT_TYPE */
} SRL_CertMatch_struct;

typedef struct
{
	CM_OID	signature;		/* Algorithm used by issuer to sign the CRL */
	CM_TimePtr issueAfter;	/* Issued on or after this date */
	CM_TimePtr issueBefore; /* Issued on or before this date */
	CM_BOOL    onlyOne;		/* Set to True if only one match returned */
} SRL_CRLMatch_struct;

typedef struct
{
	DBTypeFlag	dbType;			/* Type of match info in union */
	union matchInfo
	{
		SRL_CertMatch_struct	*cert;	/* Search Criteria for certs */
		SRL_CRLMatch_struct		*crl;	/* Search criteria for CRLs */
	} matchInfo;
} dbSearch_struct;


typedef struct
{
	LDAPInitSettings_struct		*LDAPinfo;		  /* Pointer to the LDAP Information for this session */
	char						*CertFileName;	  /* Cert DB file name */
	char						*CRLFileName;	  /* CRL DB File name (optional) */
	time_t						crlRefreshPeriod; /* Maximum time a CRL lives in DB before trying to update */
	CM_BOOL						removeStaleCRL;	  /* True = Remove stale CRL's False = Don't remove */
} SRL_InitSettings_struct;


/* ------------------- */
/* Function Prototypes */
/* ------------------- */
SRL_API(short) SRL_CreateSession(ulong *sessionID,
								 SRL_InitSettings_struct *pSettings);
SRL_API(short) SRL_DatabaseAdd(ulong sessionID, Bytes_struct *asn1Obj,
							   AsnTypeFlag type);
SRL_API(short) SRL_DatabaseFlush(ulong sessionID, DBTypeFlag dbType);
SRL_API(short) SRL_DatabaseList(ulong sessionID, dbEntryList_struct **dblist,
								DBTypeFlag dbType, CM_BOOL detailsFlag);
SRL_API(short) SRL_DatabaseRemove(ulong sessionID, DBTypeFlag entryType,
								  dbEntryInfo_LL *entryInfo, long DBid);
SRL_API(short) SRL_DatabaseRetrieve(ulong sessionID, DBTypeFlag entryType,
									dbEntryInfo *entryInfo,
									Bytes_struct **entryData, long DBid);
SRL_API(short) SRL_DatabaseSearch(ulong sessionID, CM_DN dn, DBTypeFlag dbType,
								  dbSearch_struct *searchInfo,
								  EncObject_LL **objlist);
SRL_API(short) SRL_DestroySession(ulong *sessionID);
SRL_API(void) SRL_FreeBytes(Bytes_struct **data);
SRL_API(void) SRL_FreeDBListing(dbEntryList_struct **dbList);
SRL_API(void) SRL_FreeEncCertList(EncCert_LL **pCertList);
SRL_API(void) SRL_FreeObjs(ulong *sessionID, EncObject_LL **objList);
SRL_API(short) SRL_GetTrustedCerts(ulong sessionID, EncCert_LL **pCertList);
SRL_API(short) SRL_RequestObjs(ulong *sessionID, CM_DN dn, long typeMask,
							short locMask, EncObject_LL **pObjList);
SRL_API(short) SRL_URLRequestObjs(ulong *sessionID, char *url, long typeMask,
							short locMask, EncObject_LL **pObjList);
SRL_API(short) SRL_ChangeLDAPInfo (ulong sessionID, LDAPInitSettings_struct *NewSettings);
SRL_API(short) SRL_GetDBID (ulong sessionID, AsnTypeFlag type, Bytes_struct *Object, 
							long *DBid);


#ifdef  __cplusplus
}
#endif /* __cplusplus */

#endif	/* _SRL_RET_H */
