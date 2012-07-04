/*****************************************************************************
File:     cmapiCallbacks.h
Project:  Certificate Management Library
Contents: Header file for constants and types used in the callback functions
		  for the X.509 Certificate Management Library

Created:  9 February 1997
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	27 Jan 2005

Version:  2.5

*****************************************************************************/
#ifndef _CM_CALLBACKS_H
#define _CM_CALLBACKS_H


#ifndef _CMLASN_C_H
#ifdef WIN32
	#define CM_CALL			__cdecl
#else
	#define CM_CALL
#endif
#ifndef uchar
   typedef unsigned char uchar;
#endif


typedef struct
{
    long num;               /* Number of bytes of data */
    uchar *data;
} Bytes_struct;
#endif


/* EncCert_LL
 * This structure is used for linked lists of asn.1 encoded certificates.
 * Useful when a search returns more than one. */
typedef struct EncCert_LL
{
	Bytes_struct		encCert;	   /* Pointer & len of the ASN.1 encoded cert */
	struct EncCert_LL	*next;		/* next in linked list, NULL if last */
} EncCert_LL;

typedef struct EncCRL_LL
{
	Bytes_struct		encCRL;		/* Pointer & len of the ASN.1 encoded CRL */
	struct EncCRL_LL	*next;		/* next in linked list, NULL if last */
} EncCRL_LL;

typedef struct encOCSPResp_LL
{
	Bytes_struct            m_encCRL;   /* Pointer & len of the ASN.1 encoded
                                        * OCSP response */
	struct encOCSPResp_LL*  m_pNext;   /* next in linked list, NULL if last */
} EncOCSPResp_LL;

/* Location Mask Flags (new in v1.5)
These flags are used as input to the ext_get_objects() callback function and
are returned in the EncObject_LL to indicate where the object was found.
The last two flags are used in combination with the first flags to indicate 
when the search should stop.  Either the search results will be returned once 
an object is found (the default), or all specified locations will be searched 
before returning.  Example:  CLIENT_LOC | SERVER_LOC | SEARCH_ALL. */
#define RAM_LOC				0x0001   /* Object found in (or requested from) RAM cache */
#define CLIENT_LOC			0x0002   /* Object found in (or requested from) local disk */
#define SERVER_LOC			0x0004   /* Object found in (or requested from) server */
#define DSA_LOC				0x0008   /* Object found in (or requested from) X.500 DSA */

#define SEARCH_UNTIL_FOUND	0x0000   /* Stop search once object is found */
#define SEARCH_ALL_LOC		0x4000   /* Search all specfied locations */




/* Type Mask Flags For CMAPI 
These flags are used as input to the ext_get_objects() callback function and 
are returned in the EncObject_LL to indicate the type of ASN.1 encoded 
object present in the link. */
#define USER_CERT_TYPE  0x0001L  /* User certificate requested (or found) */
#define CA_CERT_TYPE    0x0002L  /* CA certificate requested (or found) */
#define CROSS_CERT_TYPE 0x0004L  /* Cross certificate pair requested (or found) */
#define CRL_TYPE        0x0008L  /* Certificate Revocation List requested (or found) */
#define ARL_TYPE        0x0010L  /* Authority Revocation List requested (or found) */
#define DELTA_CRL_TYPE  0x0020L  /* Delta CRL requested (or found) */
#define SPIF_TYPE       0x0040L  /* MISSI SPIF requested (or found) */
#define AC_TYPE         0x0080L  /* Attribute Certificate Type */
#define ACRL_TYPE       0x0100L  /* Attribute Certificate Revocation List */
#define AARL_TYPE       0x0200L  /* Attribute Authority Revocation List */
#define AAAC_TYPE       0x0400L  /* Attribute Authority Attribute Cert */
#define ADC_TYPE        0x0800L  /* Attribute Descriptor Cert */ 

/* Linked list of ASN.1 encoded objects returned from the directory */
typedef struct EncObject_LL
{
	Bytes_struct	encObj;     /* ASN.1 encoded object */
	long			   typeMask;   /* Type of object in encObj (see flags) */
	short			   locMask;    /* Location where object was found (see flage) */
	struct EncObject_LL* next; /* Next item in list */
} EncObject_LL;

/* Callback function pointer types */
typedef short (CM_CALL *ExtGetObjFuncPtr)(void* extHandle, char* dn,
										  long typeMask, short locMask,
										  EncObject_LL **objList);
typedef short (CM_CALL *ExtUrlGetObjFuncPtr)(void* extHandle, char* url,
											 long typeMask, short locMask,
											 EncObject_LL** ppObjList);
typedef void (CM_CALL *ExtFreeObjFuncPtr)(void* extHandle,
										  EncObject_LL** ppObjList);

/* CRL revocation callback return values */
typedef enum
{
   CRL_RESP_SUCCESS = 0,
   CRL_RESP_MALFORMED,
   CRL_RESP_INTERNAL_ERR,
   CRL_RESP_TRY_LATER
} CRLResponseCode;

/* Revocation status codes */
typedef enum
{
   CM_STATUS_GOOD = 0,
   CM_STATUS_REVOKED,
   CM_STATUS_UNKNOWN
} CertStatusCode;

/* Revocation status information */
typedef struct
{
	CertStatusCode	status;
	CM_TimePtr		revDate;
	short*			revReason;
   CM_Time			thisUpdate;
   CM_TimePtr		nextUpdate;
	Unkn_extn_LL*	pRespExts;			/* response extensions */
} RevInfo;

/* Linked list of the certs and their revocation status */
typedef struct revStatus_LL
{
   Bytes_struct   encCert;          /* encoded certificate */
   Bytes_struct*  m_pEncIssuerCert; /* (optional) issuer of encCert */
   Unkn_extn_LL*  pReqExts;         /* per cert request extensions */
   RevInfo*       pRevInfo;         /* revocation status information */
   struct revStatus_LL* next;       /* pointer to next item in list */
} RevStatus_LL;

/* 
 * Type Flag For Revocation Status Callback 
 * These flags are returned in the EncRevObject_LL to indicate the type of 
 * ASN.1 encoded object present in the link. 
 */
typedef enum
{
   REV_CRL_TYPE = 1,	/* Certificate Revocation List(s) returned */
   REV_OCSP_TYPE		/* OCSP Response(s) returned */
} RevObjectType;

/*
 * Linked list of ASN.1 encoded CRLs or OCSP responses returned from the
 * revocation status callback
 */
typedef struct encRevObject_LL
{
   Bytes_struct   m_encObj;         /* ASN.1 encoded object */
   RevObjectType  m_typeMask;       /* Type of object in encObj (see flags) */
   struct encRevObject_LL* m_pNext; /* Next link in list */
} EncRevObject_LL;

/* CRL checking callback function pointer types */
typedef short (CM_CALL *ExtCheckRevStatusFP) 
   (
      void* extHandle,                 /* Handle to external library
                                        * for callbacks */
      time_t timeout,                  /* Maximum time to continue checking */
      RevStatus_LL* pCertsToCheck,     /* Certificates to be revocation 
                                        * checked */
      CM_TimePtr pValidationTime,      /* Optional time for validation */
      CM_BOOL wantBack,                /* Flag specified whether or not to
                                        * return revocation data */
      EncRevObject_LL** pRevocationData/* Revocation data */
   );
 
typedef void (CM_CALL *ExtFreeRevStatusFP)
   (
      void* extHandle,                 /* Handle to external library  
                                        * for callbacks */
      RevStatus_LL* pResults,          /* Certificates to be checked */
      EncRevObject_LL** pRevocationData/* Revocation data */
   );

#endif /* _CM_CALLBACKS_H */
