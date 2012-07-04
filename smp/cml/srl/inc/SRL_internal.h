/*****************************************************************************
File:     SRL_internal.h
Project:  Storage & Retrieval library
Contents: Header file for the Storage & Retrieval library

Created:  14 November 2000
Author:   C C McPherson <Clyde.McPherson@getroinicsgov.com

Last Updated:	26 April 2004

Version:  2.4

*****************************************************************************/
#ifndef _SRL_INTERNAL_H
#define _SRL_INTERNAL_H

#include "srlapi.h"
#include "SRL_db.h"
#include "SRL_ldap.h"


#if __cplusplus
extern "C" {
#endif

#ifndef INDEFINITE_LEN
#define INDEFINITE_LEN  ~0UL
#endif

#ifndef UNIV_CONS_SEQ_TAG
/* [0 0] [1] + 16 => 0x20 + 0x10 */
#define UNIV_CONS_SEQ_TAG         (ulong)0x30000000
#endif

#ifndef CNTX_CONS_ZERO_TAG
/* [1 0] [1] + 0 => 0xA0 + 0x00 */
#define CNTX_CONS_ZERO_TAG         (ulong)0xA0000000
#endif

#ifndef CNTX_CONS_ONE_TAG
/* [1 0] [1] + 0 => 0xA0 + 0x01 */
#define CNTX_CONS_ONE_TAG         (ulong)0xA1000000
#endif

#ifndef UNIV_PRIM_BITSTRING_TAG
/* [0 0] [0] + 3 => 0x00 + 0x03 */
#define UNIV_PRIM_BITSTRING_TAG      (ulong)0x03000000
#endif

#ifndef UNIV_CONS_BITSTRING_TAG
/* [0 0] [1] + 3 => 0x20 + 0x03 */
#define UNIV_CONS_BITSTRING_TAG      (ulong)0x23000000
#endif

#ifndef EOC_TAG_ID
#define EOC_TAG_ID 0
#endif

#ifndef UNIV_PRIM_INT_TAG
/* [0 0] [0] + 3 => 0x00 + 0x02  */
#define UNIV_PRIM_INT_TAG         (ulong)0x02000000
#endif

#ifndef CNTX_CONS_ZERO_TAG
#define CNTX_CONS_ZERO_TAG         (ulong)0xA0000000
#endif

#ifdef _WINDOWS
		#define DEC_IMPORT	__declspec(dllimport)
#else
	#define DEC_IMPORT extern
#endif
typedef uchar *ASN1_Data;	/* ASN.1 buffer */

#define SRL_HASH_LEN 20

typedef struct SRL_CertList
{
    Cert_struct *cert;
    ASN1_Data asn1cert;
    struct SRL_CertList *next;
} SRL_CertList;

typedef struct LDAPServerInfo_struct
{
	char	*LDAPserver;		 /* LDAP Server Name */
	long	LDAPport;			 /* LDAP Port Number */
} LDAPServerInfo_struct;

typedef struct LDAPIdInfo_struct
{
	LDAP *ldapID;				/* LDAP ID */
	CM_BOOL internal;			/* internal set to true if ldapID was not passed in */
} LDAPIdInfo_struct;
	
typedef struct LDAPInfo_struct
{
	LDAPFuncPtr_struct		*LDAPFunctions;		/* Pointer to the LDAP Fuction Pointer structure */
	LDAPServerInfo_struct	*LDAPServerInfo;	/* Server Information Pointer */
	LDAPIdInfo_struct		*ldapIDinfo;		/* Information on the LDAP ID */
	char				*SharedLibraryName;		/* Name of LDAP Windows DLL */
	void				*ldaplibHandle;
	long					timeout;			/* How long to wait for LDAP results */
} LDAPInfo_struct;


typedef struct Config_struct
{
   short            useLDAP;
   char*            certFName;
   char*            CRLFName;
   char*            path;
} Config_struct;


typedef struct SRLSession_struct
{
   char				  *CertFileName;
   char				  *CRLFileName;
   time_t			  crlRefreshPeriod;
   CM_BOOL			  removeStaleCRL;
   char				  *path;
   ulong              db_certRefSession;
   ulong              db_CRLRefSession;
   Config_struct      config;
   ulong              CMLHandle;   /* Handle to CML library for callbacks */
   LDAPInfo_struct	  *ldapInfo;   /* If so, the necessary info for contact */
   /* Perhaps more to come! */
} SRLSession_struct;



 /* a structure to hold the sessions information for the
 * cert mgr library.  groups the session ref id with
 * the session struct pointers */
typedef struct SRLSessions_Info_LL
{
	SRLSession_struct			*sessionInfo;
	ulong 						sessionRefID;
	struct SRLSessions_Info_LL		*next;
} SRLSessions_Info_LL;


/* a structure to hold the management information for the
 * Retrieval mgr library. */
typedef struct SRLMgrInfo_struct
{
	short 				sessionCount;	/* num sessions currently */
	SRLSessions_Info_LL	*sessionsList;	/* linked list of session info */
	LDAPInfo_struct		ldapInfo;		/* LDAP information */


/* these would be copied to the session config struct when a
 * session is added giving the new session a copy of the default
 * settings.
 */
	CM_BOOL	useLDAP;
	char	*certFName;
	char	*CRLFName;
	char 	*path;				/* all use same path  */
} SRLMgrInfo_struct;


  
/* Ftp_Access() type codes */
#define FTP_DIR 1
#define FTP_DIR_VERBOSE 2
#define FTP_FILE_READ 3
#define FTP_FILE_WRITE 4

/* Ftp_Access() mode codes */
#define FTP_ASCII 'A'
#define FTP_IMAGE 'I'
#define FTP_TEXT FTP_ASCII
#define FTP_BINARY FTP_IMAGE

#define SETSOCKOPT_OPTVAL_TYPE (void *)

#define FTP_BUFSIZ 8192

#define FTP_CONTROL 0
#define FTP_READ 1
#define FTP_WRITE 2
#define HTTP_READ 3

/* default port values */
#define FTP_PORT		21
#define HTTP_PORT		80
#define LDAP_PORT       389

/* HTTP retrieval types */
#define HTTP_HEADERS                    0
#define HTTP_CONTENT_FIRST              1
#define HTTP_CONTENT                    2

struct NetBuf {
    char *cput;
	char *cget;
    int handle;
    int cavail;
	int cleft;
    char *buf;
    int dir;
    char response[256];
};

typedef struct NetBuf netbuf;

/* ------------------- */
/* Function Prototypes */
/* ------------------- */
short F_sha1_hash(uchar *msgdata, long msgsize, unsigned char *hashValue);
short SRLi_genname2str (Gen_names_struct *gennames, char **in_str);
short SRLi_isDN(char a);
short SRLi_RetParseRDNSeq(char *string, RDN_LL **dn);
short db_Open(ulong *db_session, char *filename, long access, long blocksize);
short SRLi_DatabaseAdd(ulong sessionID, Bytes_struct *asn1Obj,
					   AsnTypeFlag type, const char *kid_str);
short SRLi_DatabaseRemove(ulong sessionID, DBTypeFlag entryType,
								  dbEntryInfo_LL *entryInfo, long DBid);

///* Function prototypes for those that are used only within this file */
short SRLi_AsnGetLength(uchar *asn1data, ulong *numBytes);
short DB2SRLerr(short db_err);
Policy_struct *SRLi_GetPolyPtr(Cert_struct *dec_cert);
int SRLDNcmp(CM_DN dn1, CM_DN dn2);



typedef short (*PExportedDNMatchFn) (const char *dn1, const char *dn2);
short SRLi_GetRemoteSPIFs(ulong sessionID, CM_DN issuer, int typeMask, EncObject_LL **spifs);
short SRLi_GetRemoteCerts(ulong sessionID, CM_DN subject, int typeMask, EncObject_LL **certs);
short SRLi_GetRemoteURLCerts(ulong sessionID, char *pUrlToFind, int typeMask,
							 short locMask, EncObject_LL **certs);
short SRLi_GetRemoteACs(ulong sessionID, CM_DN issuer, int typeMask, EncObject_LL **acs);
short SRLi_GetRemoteURLCRLs(ulong sessionID, char *url, int typeMask,
							short locMask, EncObject_LL **crls);
short SRLi_GetRemoteCRLs(ulong sessionID, CM_DN issuer, int typeMask, EncObject_LL **crls);
short SRLi_GetRetSessionFromRef(SRLSession_struct **session, ulong sessionRefID);
short SRLi_RemoveDupesInSameObject(EncObject_LL *checkList);
void SRLi_FreeCRLEntryInfo_LL(dbCRLEntryInfo_LL *listhead);
void SRLi_FreedbCertEntryLL(dbCertEntryInfo_LL *certInfoTop);
void SRLi_FreeRDN_LL(RDN_LL **rdn);
void SRLi_FreeObjList(EncObject_LL **objList);
short addCertPair2List(ulong sessionID, Bytes_struct *adata,
							  EncObject_LL **list);
short SRLi_AsnGetLength(uchar *asn1data, ulong *numBytes);

short ASN_SRLDecTag(uchar  *b, ulong*   bytesDecoded, ulong *tag);
short ASN_SRL_DecLen(uchar *b, ulong* bytesDecoded, ulong *len);
short   SRLi_GetSRTime(char *cm_time);
short SRLi_GetLDAPSessionStatus (ulong sessionID);

short SRLi_LdapURLRead(ulong sessionID, SRL_URLDescriptor_struct *inDesc,
					 LDAPInfo_struct *ldapInfo, int typeMask, AsnTypeFlag objType,  EncObject_LL **result);
short SRLi_LdapRead(ulong sessionID, LDAPInfo_struct *f, LDAP *ldapID, char *dn,
				   char *attrs[], LDAPMessage **result);
short SRLi_GetLDAPSessionStatus (ulong sessionID);

short SRLi_RetBreakUpCertPair(uchar *asndata, ulong elmtLen1, 
							  ulong *decodedLen, SRL_CertList **hcpath);
short SRLi_DecodeCertList(ulong cm_session, SRL_CertList *brokenPathList);
short SRLi_AddCertListToDB(ulong cm_session, SRL_CertList *dec_cpathenum, AsnTypeFlag TypeFlag );
short SRLi_BreakUpCertPair(uchar *asndata, ulong elmtLen1, ulong *decodedLen, SRL_CertList **hcpath);
void SRLi_FreeBrokenCertList(ulong cm_session, SRL_CertList **cp);
void SRLi_FreeObjList (EncObject_LL **the_object);
void SRLi_FreeBytes(Bytes_struct *bytes);
void SRLi_FreeURLDescriptor(SRL_URLDescriptor_struct **URLDesc);
void SRL_FreeBytesContents(Bytes_struct bytes);
void SRLi_FreeObjlst(EncObject_LL *objList);
void SRL_FreeEncCRLs(EncCRL_LL **listhead);
void SRLi_FreeInitSettings (SRL_InitSettings_struct *settings);
void SRLi_FreeLDAPinfo(LDAPInfo_struct **LDAPinfo);
short SRLi_CopyLDAPinfo(LDAPInfo_struct **ldapInfo, LDAPInitSettings_struct *LDAPinfo);
short SRLi_Link2LDAP(LDAPInfo_struct *f);
short SRLi_BuildCertIndexTemplate(Cert_struct *dec_cert, Bytes_struct *ciTemplate, short trustedFlag,
Bytes_struct *certData, enum AsnTypeFlag TypeFlag);

short	SRLi_BuildCRLIndexTemplate(CRL_struct *dec_crl, Bytes_struct *ciTemplate, 
								   Bytes_struct *, enum AsnTypeFlag TypeFlag);
short SRLi_AddCertToDB(ulong rt_session, Bytes_struct *asn1data, Cert_struct *dec_cert, short trustedFlag,
					   enum AsnTypeFlag TypeFlag, const char *kid_str);
short SRLi_AsnGetLength(uchar *asn1data, ulong *numBytes);
short SRLi_DB2CMerr(short db_err);
Policy_struct *SRLi_GetPolyPtr(Cert_struct *dec_cert);
short SRLi_AddCRLToDB(ulong rt_session, Bytes_struct *asn1data, CRL_struct *dec_crl, enum AsnTypeFlag TypeFlag,
					  const char *kidstr);
int SRLDNcmp(CM_DN dn1, CM_DN dn2);

LDAPInfo_struct *SRLi_CopyLDAPInfo();

short SRLi_LdapConnect(LDAPInfo_struct *f);
LDAP *SRLi_LdapInit(LDAPInfo_struct *f);
short SRLi_GetSessionFromRef(SRLSession_struct **session, ulong sessionRefID);
short CMU_F_SHA1(Bytes_struct *msgdata,Bytes_struct *hashValue);
short SRLi_CopyBytes(Bytes_struct *old, Bytes_struct **new_bytes);
short SRLi_CopyBytesContent(Bytes_struct *pDest, const Bytes_struct *pSrc);
short SRLi_FilterRemoteCertsList(EncObject_LL **remoteListPtr,EncObject_LL *localList,
	CM_DN subject, SRL_CertMatch_struct *matchInfo);
CM_BOOL isLittleEndian();
void SRLi_FlipLongs(void *data, long numlongs);
void SRLi_FlipShorts(void *data, long numshorts); 

#if __cplusplus
	 }
#endif

#endif
