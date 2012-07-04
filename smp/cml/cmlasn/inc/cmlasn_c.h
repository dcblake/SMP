/*****************************************************************************
File:     cmlasn_c.h
Project:  Certificate Management Library
Contents: Header file for the C interface to the X.509 Certificate Management
		  ASN.1 Library

Created:  21 March 2002
Author:   Rich Nicholas <Richard.Nicholas@GetronicsGov.com>

Last Updated:	23 October 2003

Version:  2.4

*****************************************************************************/
#ifndef _CMLASN_C_H
#define _CMLASN_C_H

/* Set the CM Library calling convention and return type */
#if defined (_WINDOWS) || defined (WIN32)
	#define CM_CALL _cdecl
	#ifndef CM_API
		#define CM_API  __declspec(dllimport) 
	#endif
#else
	#define CM_CALL
	#define CM_API 
#endif
#define CM_API_FN(type)         CM_API type  CM_CALL



/* -------------- */
/* Included Files */
/* -------------- */
#include <stdlib.h>
#include <time.h>

#if __cplusplus
extern "C" {
#endif


/* ----------------- */
/* Defined Constants */
/* ----------------- */
#ifndef TRUE
   #define TRUE    1
#endif
#ifndef FALSE
   #define FALSE   0
#endif

/* Error constants */
#define CMLASN_SUCCESS					0
#define CMLASN_MEMORY_ERROR				1
#define CMLASN_INVALID_PARAMETER		2
#define CMLASN_NULL_POINTER				4
#define CMLASN_NOT_IMPLEMENTED			5
#define CMLASN_DECODE_ERROR				9
#define CMLASN_SNACC_ERROR				10
#define CMLASN_FILE_IO_ERROR			11
#define CMLASN_INVALID_DN				13
#define CMLASN_UNKNOWN_ERROR			19

/* Misc constants */
#define CM_TIME_LEN				16      /* Format: "yyyymmddhhmmssZ" + NULL */
#define CM_KMID_LEN				8       /* Length of Mosaic KMID (in bytes) */
#define CM_HASH_LEN				20		/* Length of SHA-1 hash value */

#define CM_NOT_PRESENT			-128
#define CM_SET					1
#define CM_NOT_SET				-1


/* ------------------------- */
/* Variable Type Definitions */
/* ------------------------- */

typedef unsigned char uchar;
#if defined (WIN32) || defined (SCO_SV) || defined(HPUX) || defined(HPUX32)
   typedef unsigned short ushort;
   typedef unsigned long ulong;
#endif

//typedef uchar *ASN1_Data;	/* ASN.1 buffer */
typedef char CM_BOOL;		/* Boolean value, either TRUE or FALSE */
typedef char *CM_OID;		/* Object Identifier string (NULL-terminated)
							   in decimal dot notation, ex. "2.5.29.36"   */
typedef char *CM_DN;		/* Distinguished Name string (NULL-terminated)
							   formatted according to RFC 2253, 
							   ex. "CN=John Smith,O=XYZ Corp.,C=US"   */
typedef char *CM_UTF8String; /* String formatted in UTF8 Format */

typedef char CM_Time[CM_TIME_LEN];	/* CM time string "yyyymmddhhmmssZ" */
typedef CM_Time *CM_TimePtr;		/* Pointer to CM time string */

typedef uchar CM_HashValue[CM_HASH_LEN];	/* SHA-1 hash value */

typedef struct rdn_LL
{
    char *rdn;
    struct rdn_LL *next;
} RDN_LL;

typedef struct
{
    long num;
    uchar *data;
} Bytes_struct;

typedef struct bytes_struct_LL
{
	Bytes_struct *bytes_struct;
	struct bytes_struct_LL *next;
} Bytes_struct_LL;

typedef struct encCertPair
{
	Bytes_struct forward;		/* Absent when num = 0 and data = NULL */
	Bytes_struct reverse;		/* Absent when num = 0 and data = NULL */
	struct encCertPair* next;
} EncCertPair_LL;

typedef struct
{
   Bytes_struct p;          /* prime modulus used for DSS or KEA */
   Bytes_struct q;          /* prime divisor used for DSS or KEA */
   Bytes_struct g;          /* SSO-generated value used for DSS or KEA */
}  Pqg_params_struct;

typedef struct
{
    Bytes_struct publicExponent;
    Bytes_struct modulus;
} RSAPublicKey_struct;

typedef struct
{
    Bytes_struct dsa_y;             /* Public key for DSA key */
    Bytes_struct kea_y;             /* Public key for KEA key */
    uchar kmid[CM_KMID_LEN];        /* Key material ID */
    uchar dsa_ver;                  /* Version of DSA public key */
    uchar dsa_type;                 /* Type of DSA public key */
    Bytes_struct dsa_privs;         /* Privileges for DSA public key */
    uchar kea_ver;                  /* Version of KEA public key */
    uchar kea_type;                 /* Type of KEA public key */
    Bytes_struct kea_privs;         /* Privileges for KEA public key */
    Bytes_struct kea_clearance;     /* Clearances set for KEA public key */
    Pqg_params_struct *diff_kea;    /* KEA parameters--only present if */
} Mosaic_key_struct;                /*    different than the DSA parameters */

typedef struct
{
    CM_OID oid;                     /* Algorithm OID */
    union paramsUnion				/* Algorithm parameters (optional) */
    {
        Pqg_params_struct *dsa;     /* Used for DSA parameters */
        Bytes_struct *kea;          /* Used for KEA ID parameter */
        Bytes_struct *encoded;      /* Encoded parameters (DH, ECDSA, ECDH) */
        Pqg_params_struct *dsa_kea; /* Used for Fortezza v1 DSA parameters */
    } params;                       /*   (or common DSA & KEA parameters)  */
    union keyUnion
    {
        Bytes_struct *y;            /* Public key for DSA, KEA, DH */
        RSAPublicKey_struct *rsa;   /* Public key for RSA */
        Mosaic_key_struct *combo;   /* Public keys for Fortezza v1 certs */
        Bytes_struct *encoded;		/* Encoded public key for ECDSA and ECDH */
    } key;
} Pub_key_struct;

typedef struct
{
    Bytes_struct r;
    Bytes_struct s;
} Dsa_sig_struct;

typedef struct
{
    CM_OID alg;					/* Algorithm used by issuer to sign cert */
    union sigValueUnion			/* Signature value */
    {
        Dsa_sig_struct *dsa;	/* Used for DSA and ECDSA signatures */
        Bytes_struct *rsa;		/* Used for RSA signatures */
        Bytes_struct *encoded;	/* Used for unknown signature algorithms */
    } value;
} Sig_struct;

/* ----- Extensions ------ */
typedef struct
{
    CM_OID oid;
    Bytes_struct *data;
} Any_struct;

typedef struct
{
    char *name_assigner;            /* Name assigner */
    char *party_name;               /* Party name */
} Edi_name_struct;

/* General Name Types */
#define CM_OTHER_NAME		1
#define CM_RFC822_NAME		2
#define CM_DNS_NAME			3
#define CM_X400_ADDR		4
#define CM_X500_NAME		5
#define CM_EDI_NAME			6
#define CM_URL_NAME			7
#define CM_IP_ADDR			8
#define CM_REG_OID			9

typedef struct
{
    short flag;						/* Indicates type of name in union */
    union nameUnion
	{
        Any_struct *other_name;		/* Other name (ANY) */
        char *rfc822;				/* RFC 822 e-mail address */
        char *dns;					/* DNS name */
        char *x400;					/* X.400 OR Address */
        CM_DN dn;					/* X.500 Distinguished Name */
        Edi_name_struct *ediParty;	/* EC/EDI party name */
        char *url;					/* Uniform resource identifier (URL) */
        char *ip;					/* IP address */
        CM_OID oid;					/* Registered OID */
    } name;
} Gen_name_struct;

typedef struct gen_names_struct
{
    Gen_name_struct gen_name;
    struct gen_names_struct *next;
} Gen_names_struct;

typedef struct
{
    Bytes_struct *id;               /* Key identifier (optional) */
    Gen_names_struct *issuer;       /* Certificate issuer (optional) */
    Bytes_struct *serial_num;       /* Serial number of issuer's cert */
} Auth_key_struct;                  /*  (present or absent with issuer name) */

typedef struct oid_LL
{
   CM_OID oid;						/* OID */
   struct oid_LL *next;				/* Next OID in linked list */
} CM_OID_LL;

typedef CM_OID_LL Ext_key_use_LL;	/* List of key purpose OIDs */

typedef struct
{
    CM_TimePtr not_before;			/* Format "yyyymmddhhmmssZ" (optional) */
    CM_TimePtr not_after;			/* Format "yyyymmddhhmmssZ" (optional) */
} Priv_key_val_struct;

typedef struct
{
	CM_UTF8String org;				/* Organization name */
	Bytes_struct_LL *notices;		/* Link list of notice numbers */
} NoticeRef;

typedef struct
{
	NoticeRef* noticeRef;			/* Notice Reference (optional) */
	CM_UTF8String explicitText;		/* Explicit text (optional) */
} CMUserNotice;

typedef enum qualifierFlag {
	CM_QUAL_CPS = 1,
	CM_QUAL_UNOTICE,
	CM_QUAL_UNKNOWN
} QualifierFlag;

typedef struct qualifier_struct
{
	QualifierFlag flag;				/* Indicates type of qualifier in union */
    CM_OID qualifier_id;			/* Policy qualifier OID */
	union qualifierUnion
	{
		char* cpsURI;				/* PKIX CPS URI qualifier */
		CMUserNotice* userNotice;	/* PKIX user notice qualifier */
		Bytes_struct* unknown;		/* Unrecognized qualifier */
	} qual;
    struct qualifier_struct *next;
} Qualifier_struct;

typedef struct policy_struct
{
    CM_OID policy_id;				/* Certificate policy OID */
    Qualifier_struct *qualifiers;	/* Pointer to first policy qualifier */
    struct policy_struct *next;
} Policy_struct;

typedef struct pol_maps_struct
{
    CM_OID issuer_pol_id;			/* Policy OID from issuer's domain */
    CM_OID subj_pol_id;				/* Policy OID from subject's domain */
    struct pol_maps_struct *next;
} Pol_maps_struct;

typedef struct
{
	ulong num;		/* Number of long integers in array */
	long *array;	/* Array of long integers */
} LongArray;

typedef struct sec_tags_LL
{
	short tagType;					/* Indicates Tag Type */
	union {
		Bytes_struct	*bitFlags;	/* Attribute Flags BIT STRING; Present if
									 * tagType == 1 or 6 */
		LongArray		*intFlags;	/* Attribute Flags SET OF Integers; Present
									 * if tagType == 2 */
	} values;
   struct sec_tags_LL *next;
} Sec_tags;

typedef struct ssl_privs_LL
{
   CM_OID   tagSetName;			/* TagSetName OID */
   Sec_tags *tagSetPrivs;		/* List of security tag privileges */
   struct ssl_privs_LL *next;
} Ssl_privs;

typedef struct secCat_LL
{
	enum {
		PRBAC_TYPE = 1,
		OTHER_TYPE
	} type;							/* Indicates type of value in union */
	CM_OID				oid;		/* Security category OID */
	union categoryUnion
	{
		Ssl_privs		*prbac;		/* MISSI SSLPrivileges */
		Bytes_struct	*other;		/* Other security category value */
	} value;
	struct secCat_LL	*next;
} SecCat_LL;

typedef struct
{
   CM_OID  policyID;		/* policyID OID */
   Bytes_struct *classList;	/* classList BIT STRING    */
                            /* Bit Definitions:                     */
                            /* 0:Unmarked      1:unclass            */
                            /* 2:Restricted    3:confidential       */
                            /* 4:secret        5:topSecret          */
                            /* 6:SBU                                */
   SecCat_LL *categories;	/* List of Security Categories (optional) */
} Clearance_struct;

/*  SigOrKMPrivileges Attribute */
typedef struct
{
	enum {
		SIG_FLAGS = 1,
		KM_FLAGS
	} type;				/* Indicates whether sig or KM flags are present */
	LongArray *privs;	/* OPTIONAL Dynamically allocated array of longs */
						/* indicating privileges. See SDN.702 for most */
						/* recent list of values. These were assigned as of */
						/* the ICD date: Sig values: 0:orgRelease; 1:PCA; */
						/* 2:Obsolete; 3:Guard; 4:PLMA; 5:LMA; 6:MFI; */
						/* 7:DSA; 8:MLA; 9:domainManager; */
						/* 10:securityOfficer; 11:SRA; 12:acAdmin; 13:ORA; */
						/* 14:MTA; 15:MS; 16:auditManager; 17:netManager; */
						/* 18:rekeyManager. KM Values: 0:rekeyManager; */
						/* 1:Guard; 2:auditManager; 3:readOnly; */
						/* 4:netManager; 5:MLA; 6:MFL. */
} Priv_flags;

typedef enum
{
	PRBACINFO			= 1,
	CACONSTRAINTS,
	COMMPRIV,
	SIGORKMPRIVILEGES,
	UNKNOWN
} SubDirType;

typedef struct ca_const_LL			/* Linked list of cAClearanceConstraints */
{
	SubDirType ca_type;				/* Flag indicating value in the union */
	union caConstUnion
	{
		Clearance_struct *prbac_infop;	/* Clearance Attribute */
		Priv_flags   *priv_flags;	/* sigOrKMPrivleges Attribute */
		Bytes_struct *comm_priv;	/* Comm Privileges BIT STRING */
									/* Bit values: 0:deferred; 1:routine; */
									/* 2:priority; 3:immediate; 4:flash; */
									/* 5:override; 6:ecp; 7:critic */
	} ca_val;
	struct ca_const_LL *next;
} Ca_const;

typedef struct attributes_struct
{
	CM_OID				oid;		/* Attribute OID */
	SubDirType			type;		/* Flag indicating type of value in union */
	union attributeUnion
	{
		Clearance_struct *prbac_infop;	/* Subject PRBAC Information */
		Ca_const		*ca_const; 		/* Sequence of PRBAC CA Constraints */
		Priv_flags		*priv_flags; 	/* SigOrKMPrivileges */
		Bytes_struct	*comm_priv;		/* Communication Privileges BIT STRING */
										/* Bit values: 0:deferred; 1:routine; */
										/* 2:priority; 3:immediate; 4:flash; */
										/* 5:override; 6:ecp; 7:critic */
		Bytes_struct_LL	*unkn;			/* Unknown attribute values (ASN.1 encoded) */
	} values;						/* Attribute values */
	struct attributes_struct *next;
} Attributes_struct;

typedef struct
{
    CM_BOOL cA_flag;			/* Indicates whether this is a CA cert */
    short max_path;				/* Path length constraint (Optional)    */
} Basic_cons_struct;			/*    Set to CM_NOT_PRESENT if not used */

typedef struct subtree_struct
{
    Gen_name_struct base;
    short min;
    short max;						/* (Optional) Set to CM_NOT_PRESENT if */
    struct subtree_struct *next;	/*    no maximum */
} Subtree_struct;

/* Required Basic Name Form Flags */
#define CM_BASIC_NAME_RFC822	0x0001
#define CM_BASIC_NAME_DNS		0x0002
#define CM_BASIC_NAME_X400		0x0004
#define CM_BASIC_NAME_X500		0x0008
#define CM_BASIC_NAME_EDI		0x0010
#define CM_BASIC_NAME_URL		0x0020
#define CM_BASIC_NAME_IP_ADDR	0x0040
#define CM_BASIC_NAME_REG_OID	0x0080

typedef struct
{
   Subtree_struct *permitted;		/* Permitted subtrees */
   Subtree_struct *excluded;		/* Excluded subtrees */
	ushort *basicNames;				/* Required basic name forms (optional)
										-- used as a bit map, see flags */
	CM_OID_LL *otherNames;			/* Required other name forms (optional) */
} Name_cons_struct;

typedef struct
{
    short req_explicit_pol;         /* Require explicit policy (optional) */
    short inhibit_mapping;          /* Inhibit policy mapping (optional) */
} Pol_cons_struct;                  /*    Set to either CM_SET or CM_NOT_SET */

/* Distribution Point and Issuing Distribution Point Flags */
#define CM_DIST_PT_FULL_NAME			0
#define CM_DIST_PT_RELATIVE_NAME		1

typedef struct
{
	char flag;						/* Indicates which name is in the union */
	union dpNameUnion
	{
		Gen_names_struct* full;		/* Present when flag = CM_DIST_PT_FULL_NAME */
		char* relative;				/*    when flag = CM_DIST_PT_RELATIVE_NAME */
	} name;							/*	  when flag = CM_NOT_PRESENT - Both */
} Dist_pt_name;						/*		are absent (pointer is NULL) */

/* Reason Flags (used in CRL Distribution Point, Issuing Distribution Point, 
and CRL Scope extensions */
#define CM_CRL_DIST_PT_UNUSED					0x0001
#define CM_CRL_DIST_PT_KEY_COMPROMISE			0x0002
#define CM_CRL_DIST_PT_CA_COMPROMISE			0x0004
#define CM_CRL_DIST_PT_AFFILIATION_CHANGED		0x0008
#define CM_CRL_DIST_PT_SUPERSEDED				0x0010
#define CM_CRL_DIST_PT_CESSATION_OF_OPERATION	0x0020
#define CM_CRL_DIST_PT_CERTIFICATE_HOLD			0x0040
#define CM_CRL_DIST_PT_PRIVILEGE_WITHDRAWN		0x0080
#define CM_CRL_DIST_PT_AA_COMPROMISE			0x0100

#define CM_ALL_REASONS  (CM_CRL_DIST_PT_KEY_COMPROMISE | CM_CRL_DIST_PT_CA_COMPROMISE | \
		CM_CRL_DIST_PT_AFFILIATION_CHANGED | CM_CRL_DIST_PT_SUPERSEDED | \
		CM_CRL_DIST_PT_CESSATION_OF_OPERATION | CM_CRL_DIST_PT_CERTIFICATE_HOLD |\
		CM_CRL_DIST_PT_PRIVILEGE_WITHDRAWN | CM_CRL_DIST_PT_AA_COMPROMISE)

typedef struct dist_pts_LL
{
	Dist_pt_name dpName;			/* Distribution point name (optional) */
    ushort *reasons;                /* Reason flags (optional) 
										-- used as a bit map, see flags */
    Gen_names_struct *crl_issuer;   /* CRL Issuer (optional) */
    struct dist_pts_LL *next;
} Dist_pts_struct;

typedef struct
{
	Dist_pt_name dpName;			/* Distribution point name */
    CM_BOOL only_users_flag;		/* CRL only contains user certs */
    CM_BOOL only_cAs_flag;			/* CRL only contains CA certs */
    ushort *reasons;				/* Reason codes (optional)
										-- used as a bit map, see flags */
    CM_BOOL indirect_flag;			/* Indicates this is an indirect CRL */
	CM_BOOL onlyACsFlag;			/* CRL only contains attribute certs */
} Iss_pts_struct;

typedef struct accessDescript_LL
{
	CM_OID method;					/* Access method */
	Gen_name_struct loc;			/* Access location */
	struct accessDescript_LL* next;
} AccessDescript_LL;

typedef struct
{
	Bytes_struct* startingNum;		/* Starting number (optional) */
	Bytes_struct* endingNum;		/* Ending number (optional) */
	Bytes_struct* modulus;			/* Modulus to reduce by (optional) */
} CM_NumberRange;

typedef struct
{
	Bytes_struct	*crlStreamID;	/* Optional ID for the base CRL's stream */
	Bytes_struct	crlNum;			/* The base CRL number */
	CM_Time			thisUpdate;		/* The base CRL's issue date */
} CM_BaseRevocationInfo;

/* Certificate Type Flags (used in CRL Scope and Status Referral extensions */
#define CM_CERT_TYPE_USER				0x01
#define CM_CERT_TYPE_AUTHORITY			0x02
#define CM_CERT_TYPE_ATTRIBUTE			0x04

typedef struct per_auth_scope_LL
{
	Gen_name_struct* authName;			/* Authority name (optional) 
											(if NULL, defaults to CRL issuer) */
	Dist_pt_name dpName;				/* Distribution point name (optional) */
	uchar* onlyContains;				/* Types of certs revoked (optional)
											-- used as a bit map, see flags */
	ushort* onlySomeReasons;			/* Revocation reasons used (optional)
											-- used as a bit map, see flags */
	CM_NumberRange* serialNumRange;		/* Range of serial number (optional) */
	CM_NumberRange* subjKeyIdRange;		/* Range of subject public key (optional) */
	Gen_names_struct* nameSubtrees;		/* Range of subject name (optional) */
	CM_BaseRevocationInfo* baseRevInfo;	/* Base CRL info for this delta (optional) */
	struct per_auth_scope_LL* next;
} PerAuthScope_LL;

typedef struct
{
	Gen_name_struct deltaLoc;		/* Delta CRL location */
	CM_TimePtr issueDate;			/* Date delta CRL issued (optional) */
} DeltaInfo;

typedef struct
{
	Gen_name_struct* issuer;		/* Signer of the CRL (optional) */
	Gen_name_struct* location;		/* Referral location (optional) */
	DeltaInfo* deltaRef;			/* Alternative delta CRL info (optional) */
	PerAuthScope_LL *crlScope;		/* Scope of the CRL */
	CM_TimePtr lastUpdate;			/* Date of most recently issued CRL (optional) */
	CM_TimePtr lastChangedCRL;		/* Date of most recently issued CRL that */
} CRL_referral;						/*    has changed (optional) */

/* CRL Status Referral Flags */
#define CM_CRL_REFERRAL		0
#define CM_OTHER_REFERRAL	1

typedef struct status_referral_LL
{
	char flag;					/* Indicates which referral is present */
	union referralUnion
	{
		CRL_referral *crl;		/* CRL referral (when flag = CM_CRL_REFERRAL) */
		Any_struct *other;		/* non-CRL referral (when flag = CM_OTHER_REFERRAL) */
	} ref;
	struct status_referral_LL* next;
} StatusReferral_LL;

/* Key Usage Flags */
#define CM_DIGITAL_SIGNATURE	0x0001
#define CM_NON_REPUDIATION		0x0002
#define CM_KEY_ENCIPHERMENT		0x0004
#define CM_DATA_ENCIPHERMENT	0x0008
#define CM_KEY_AGREEMENT		0x0010
#define CM_KEY_CERT_SIGN		0x0020
#define CM_CRL_SIGN				0x0040
#define CM_ENCIPHER_ONLY		0x0080
#define CM_DECIPHER_ONLY		0x0100

/* Certificate Revocation Reason Codes (used in the CRL Entry extension) */
#define CM_CRL_UNSPECIFIED				0
#define CM_CRL_KEY_COMPROMISE			1
#define CM_CRL_CA_COMPROMISE			2
#define CM_CRL_AFFILIATION_CHANGED		3
#define CM_CRL_SUPERSEDED				4
#define CM_CRL_CESSATION_OF_OPERATION	5
#define CM_CRL_CERTIFICATE_HOLD			6
#define CM_CRL_REMOVE_FROM_CRL			8
#define CM_CRL_PRIVILEGE_WITHDRAWN		9
#define CM_CRL_AA_COMPROMISE			10

/* Ordered List constants */
#define CM_ORDERED_BY_SERIAL_NUM		0
#define	CM_ORDERED_BY_DATE				1

/* Extn_struct carries the OID and criticality flag and value for each
extension, whether present in a certificate, CRL, or CRL entry.  The value
is a void pointer which points to the type or structure appropriate for the
extension.  The following table lists each extension and its associated type:
	Authority Key Identifier            Auth_key_struct
	Subject Key Identifier              Bytes_struct
	Key Usage                           ushort -- used as a bit map, see flags
	Extended Key Usage					Ext_key_use_LL
	Private Key Usage Period            Priv_key_val_struct
	Certificate Policies                Policy_struct
	Policy Mappings                     Pol_maps_struct
	Subject Alternate Names             Gen_names_struct
	Issuer Alternate Names              Gen_names_struct
	Subject Directory Attributes        Attributes_struct
	Basic Constraints                   Basic_cons_struct
	Name Constraints                    Name_cons_struct
	Policy Constraints                  Pol_cons_struct
	CRL Number                          Bytes_struct
	Reason Code                         short -- see Reason Code constants
	Hold Instruction Code               CM_OID (NULL-terminated string)
	Invalidity Date                     CM_Time (NULL-terminated string)
	CRL Distribution Points             Dist_pts_struct
	Issuing Distribution Point          Iss_pts_struct
	Certificate Issuer                  Gen_names_struct
	Delta CRL Indicator                 Bytes_struct
	Authority Information Access		AccessDescript_LL
	Inhibit Any Policy					ushort
	CRL Scope							PerAuthScope_LL
	Status Referral						StatusReferral_LL
	CRL Stream Identifier				Bytes_struct
	Ordered List						short -- see Ordered List constants
	Delta Information					DeltaInfo
	Base Update							CM_Time
	Freshest CRL						Dist_pts_struct
	Subject Information Access			AccessDescript_LL
*/
typedef struct
{
    CM_OID oid;			/* Object Identifier for this extension */
    CM_BOOL critical;	/* Indicates whether the extension is critical */
    void *value;		/* Pointer to one of the above types/structures */
} Extn_struct;

typedef struct unkn_extn_LL
{
    CM_OID oid;            /* Object Identifier for this extension */
    CM_BOOL critical;      /* Indicates whether the extension is critical */
    Bytes_struct *value;   /* ASN.1 encoded extension value */
    struct unkn_extn_LL *next;
} Unkn_extn_LL;

/* CRL Entry Extensions */
typedef struct
{
    Extn_struct *reasonCode;            /* Reason Code */
    Extn_struct *instrCodeOid;          /* Hold Instruction Code */
    Extn_struct *invalDate;             /* Invalidity Date */
    Extn_struct *certIssuer;            /* Certificate Issuer */
    Unkn_extn_LL *unknown;              /* Used for unrecognized extensions */
} CRL_entry_exts_struct;

/* CRL Extensions */
typedef struct
{
    Extn_struct *authKeyID;             /* Authority Key Identifier */
    Extn_struct *issuerAltName;         /* Issuer Alternate Names */
    Extn_struct *crlNum;                /* CRL Number */
    Extn_struct *issDistPts;            /* Issuing Distribution Point */
    Extn_struct *deltaCRL;              /* Delta CRL Indicator */
	Extn_struct *scope;					/* CRL Scope */
	Extn_struct *statusRef;				/* Status Referral */
	Extn_struct *streamId;				/* CRL Stream Identifier */
	Extn_struct *ordered;				/* Ordered List */
	Extn_struct *deltaInfo;				/* Delta Information */
	Extn_struct *baseUpdate;			/* Base Update */
	Extn_struct *freshCRL;				/* Freshest CRL */
    Unkn_extn_LL *unknown;              /* Used for unrecognized extensions */
} CRL_exts_struct;

/* Certificate Extensions */
typedef struct
{
    Extn_struct *authKeyID;             /* Authority Key Identifier */
    Extn_struct *subjKeyID;             /* Subject Key Identifier */
    Extn_struct *keyUsage;              /* Key Usage */
	Extn_struct *extKeyUse;				/* Extended Key Usage */
    Extn_struct *privKeyVal;            /* Private Key Usage Period */
    Extn_struct *certPolicies;          /* Certificate Policies */
    Extn_struct *policyMaps;            /* Policy Mappings */
    Extn_struct *subjAltName;           /* Subject Alternate Names */
    Extn_struct *issuerAltName;         /* Issuer Alternate Names */
    Extn_struct *subjDirAtts;           /* Subject Directory Attributes */
    Extn_struct *basicCons;             /* Basic Constraints */
    Extn_struct *nameCons;              /* Name Constraints */
    Extn_struct *policyCons;            /* Policy Constraints */
    Extn_struct *distPts;               /* CRL Distribution Points */
	Extn_struct *aia;					/* PKIX Authority Information Access */
	Extn_struct *inhibitAnyPol;			/* Inhibit Any Policy */
	Extn_struct *freshCRL;				/* Freshest CRL */
	Extn_struct *sia;					/* PKIX Subject Information Access */
    Unkn_extn_LL *unknown;              /* Used for unrecognized extensions */
} Cert_exts_struct;

/* X.509 Certificate */
typedef struct
{
    short version;				/* Version 1, 2, or 3 */
    Bytes_struct serial_num;	/* Certificate serial number */
    CM_OID signature;			/* Algorithm used by issuer to sign cert */
    CM_DN issuer;				/* Issuer's Distinguished Name */
    CM_Time val_not_before;		/* Start of cert's validity period */
    CM_Time val_not_after;		/* End of cert's validity period */
    CM_DN subject;				/* Subject's Distinguished Name */
    Pub_key_struct pub_key;		/* Subject public key, alg OID, & parameters */
    Bytes_struct *issuer_id;	/* Issuer Unique Identifier (optional) */
    Bytes_struct *subj_id;		/* Subject Unique Identifier (optional) */
    Cert_exts_struct *exts;		/* Extensions (optional) */
    Sig_struct sig;				/* SIGNED macro components */
} Cert_struct;

typedef struct revCerts_LL
{
    Bytes_struct serialNum;         /* Serial of revoked certificate */
    CM_TimePtr revDate;				/* Date certificate was revoked */
    CRL_entry_exts_struct *exts;    /* CRL entry extensions (optional) */
    struct revCerts_LL *next;       /* Next entry */
} RevCerts_LL;

/* X.509 Certificate Revocation List (CRL) */
typedef struct
{
    short version;				/* Version 1 or 2 */
    CM_OID signature;			/* Algorithm used by issuer to sign CRL */
    CM_DN issuer;				/* Issuer's Distinguished Name */
    CM_Time thisUpdate;			/* Date this CRL was issued */
    CM_TimePtr nextUpdate;		/* Date next CRL will be issued (optional) */
    RevCerts_LL *revoked;		/* Linked list of revoked certs (optional) */
    CRL_exts_struct *exts;		/* CRL Extensions (optional) */
    Sig_struct sig;				/* SIGNED macro components */
} CRL_struct;

/* X.509 certification path */
typedef struct Cert_path_LL		/* Linked list of decoded certficates */
{								/*  that comprise a certification path */
    Cert_struct *cert;
    struct Cert_path_LL *next;
} Cert_path_LL;



/* ------------------- */
/* Function Prototypes */
/* ------------------- */
CM_API_FN(short) CM_DecodeCert(Bytes_struct* encodedCert,
							   Cert_struct **decCert);
CM_API_FN(short) CM_DecodeCertPath(Bytes_struct* encodedPath,
								   Cert_path_LL **decCertPath);
CM_API_FN(short) CM_DecodeCRL(Bytes_struct* encodedCRL, CRL_struct **decCRL);
CM_API_FN(short) CM_DecodeCRL2(Bytes_struct* encodedCRL, CRL_struct **decCRL,
							   CM_BOOL decRevoked, CM_BOOL decExts);
CM_API_FN(short) CM_DecodeDN(Bytes_struct* encodedDN, char **decodedDN);
CM_API_FN(void) CM_FreeCert(Cert_struct **decCert);
CM_API_FN(void) CM_FreeCertPathLinkedList(Cert_path_LL **decCertPath);
CM_API_FN(void) CM_FreeCRL(CRL_struct **decCRL);
CM_API_FN(void) CM_FreeString(char **string);
CM_API_FN(short) CM_HashData(Bytes_struct* pData, CM_HashValue hash);


/* Experimental Functions */
CM_API_FN (void) CMASN_FreePolicySet(Policy_struct *policyList);
CM_API_FN (void) CMASN_FreePubKeyContents(Pub_key_struct *key);
CM_API_FN (const char*) CMASN_GetErrorString(short errorCode);
CM_API_FN (short) CMASN_ParseCertPath(const Bytes_struct* encodedPath,
									 ulong* numDecoded,
									 EncCertPair_LL** encCerts);
CM_API_FN (short) CMASN_ParseCertPair(const Bytes_struct* encodedPair,
									 ulong* numDecoded,
									 EncCertPair_LL** encCerts);
CM_API_FN (void) CMASN_FreeCertPairList(EncCertPair_LL** encCerts);
CM_API_FN (void) CMASN_FreeBytesContents(Bytes_struct* bytes);


/* ---------------- */
/* Global Variables */
/* ---------------- */

/* Algorithm OIDs */
CM_API extern const char
	gDSA_OID[], 			/* "1.2.840.10040.4.1" */
	gDSA_SHA1_OID[],		/* "1.2.840.10040.4.3" */
	gSHA1_OID[],			/* "1.3.14.3.2.26" */
	gRSA_OID[], 			/* "1.2.840.113549.1.1.1" */
	gRSA_MD2_OID[], 		/* "1.2.840.113549.1.1.2" */
	gRSA_MD4_OID[], 		/* "1.2.840.113549.1.1.3" */
	gRSA_MD5_OID[], 		/* "1.2.840.113549.1.1.4" */
	gRSA_SHA1_OID[],		/* "1.2.840.113549.1.1.5" */
	gOLD_DH_OID[],			/* "1.2.840.113549.1.3.1" */
	gMD2_OID[], 			/* "1.2.840.113549.2.2" */
	gMD4_OID[], 			/* "1.2.840.113549.2.4" */
	gMD5_OID[], 			/* "1.2.840.113549.2.5" */
	gMOSAIC_DSA_OID[],		/* "2.16.840.1.101.2.1.1.19" */
	gDSA_KEA_OID[], 		/* "2.16.840.1.101.2.1.1.20" */
	gKEA_OID[], 			/* "2.16.840.1.101.2.1.1.22" */
	gOIW_DSA[], 			/* "1.3.14.3.2.12" OIW DSA OID */
	gANSI_DH_OID[],			/* "1.2.840.10046.2.1" */
	gEC_KEY_OID[], 			/* "1.2.840.10045.2.1" */
	gECDSA_SHA1_OID[],		/* "1.2.840.10045.4.1" */
	gECDSA_SHA256_OID[],	/* "1.2.840.10045.4.2" */
	gECDSA_SHA384_OID[];	/* "1.2.840.10045.4.3" */

/* X.509 Extension OIDs */
CM_API extern const char
	gSUBJ_DIR_ATTRIBS[],	/* "2.5.29.9" */
	gSUBJ_KEY_ID[], 		/* "2.5.29.14" */
	gKEY_USAGE[],			/* "2.5.29.15" */
	gPRIV_KEY_USAGE[],		/* "2.5.29.16" */
	gSUBJ_ALT_NAME[],		/* "2.5.29.17" */
	gISSUER_ALT_NAME[], 	/* "2.5.29.18" */
	gBASIC_CONST[], 		/* "2.5.29.19" */
	gCRL_NUM[], 			/* "2.5.29.20" */
	gREASON_CODE[], 		/* "2.5.29.21" */
	gINSTRUCT_CODE[],		/* "2.5.29.23" */
	gINVALID_DATE[],		/* "2.5.29.24" */
	gDELTA_CRL_NUM[],		/* "2.5.29.27" */
	gISSUING_DIST_PT[], 	/* "2.5.29.28" */
	gCERT_ISSUER[], 		/* "2.5.29.29" */
	gNAME_CONST[],			/* "2.5.29.30.1" */
	gCRL_DISTRO_PTS[],		/* "2.5.29.31" */
	gCERT_POLICIES[],		/* "2.5.29.32" */
	gPOL_MAPPINGS[],		/* "2.5.29.33" */
	gAUTH_KEY_ID[], 		/* "2.5.29.35" */
	gPOLICY_CONST[],		/* "2.5.29.36" */
	gEXT_KEY_USE[], 		/* "2.5.29.37" */
	gEXT_CRL_STREAM_ID[],	/* "2.5.29.40" */
	gEXT_CRL_SCOPE[],		/* "2.5.29.44" */
	gEXT_STATUS_REFS[], 	/* "2.5.29.45" */
	gEXT_FRESHEST_CRL[],	/* "2.5.29.46" */
	gEXT_ORDERED_LIST[],	/* "2.5.29.47" */
	gEXT_BASE_UPDATE[], 	/* "2.5.29.51" */
	gEXT_DELTA_INFO[],		/* "2.5.29.53" */
	gEXT_INHIBIT_POL[]; 	/* "2.5.29.54" */

/* X.509 Any Policy OID */
CM_API extern const char gANY_POLICY_OID[];		/* "2.5.29.32.0" */

/* X.509 Any Extended Key Usage OID */
CM_API extern const char gANY_KEY_USE_OID[];	/* "2.5.29.37.0" */

/* PKIX Extension OIDs */
CM_API extern const char
	gEXT_PKIX_AIA[],					/* "1.3.6.1.5.5.7.1.1" */
	gEXT_PKIX_SIA[];					/* "1.3.6.1.5.5.7.1.11" */

/* PKIX Qualifier OIDs */
CM_API extern const char
	gQT_CPS_QUALIFIER_OID[],			/* "1.3.6.1.5.5.7.2.1" */
	gQT_UNOTICE_QUALIFIER_OID[];		/* "1.3.6.1.5.5.7.2.2" */

/* PKIX Extended Key Usage OIDs */
CM_API extern const char
	gEXT_KEY_USE_serverAuth[],			/* "1.3.6.1.5.5.7.3.1" */
	gEXT_KEY_USE_clientAuth[],			/* "1.3.6.1.5.5.7.3.2" */
	gEXT_KEY_USE_codeSigning[],			/* "1.3.6.1.5.5.7.3.3" */
	gEXT_KEY_USE_emailProtection[],		/* "1.3.6.1.5.5.7.3.4" */
	gEXT_KEY_USE_timeStamping[],		/* "1.3.6.1.5.5.7.3.8" */
	gEXT_KEY_USE_OCSPSigning[];			/* "1.3.6.1.5.5.7.3.9" */

/* Server Gated Crypto (SGC) Extended Key Usage OIDs */
CM_API extern const char
   gEXT_KEY_USE_VeriSignSGC[],      /* "2.16.840.1.113733.1.8.1" */
   gEXT_KEY_USE_NetscapeSGC[],      /* "2.16.840.1.113730.4.1" */
   gEXT_KEY_USE_MicrosoftSGC[];     /* "1.3.6.1.4.1.311.10.3.3" */

/* ANSI x9 Hold Instruction OIDs */
CM_API extern const char
	gHOLD_CALL_ISSUER_OID[],			/* "1.2.840.10040.2.2" */
	gHOLD_REJECT_OID[];					/* "1.2.840.10040.2.3" */

/* PKIX Access Descriptor OIDs */
CM_API extern const char
	gAD_OCSP_OID[],						/* "1.3.6.1.5.5.7.48.1" */
	gAD_CA_ISSUERS_OID[],				/* "1.3.6.1.5.5.7.48.2" */
	gAD_TIME_STAMPING_OID[],			/* "1.3.6.1.5.5.7.48.3" */
	gAD_CA_REPOSITORY_OID[];			/* "1.3.6.1.5.5.7.48.5" */

/* SDN 702 Subject Directory Attribute OIDs */
//CM_API extern const char
CM_API extern const char
	gCACLEARANCECONSTRAINT[],			/* "2.16.840.1.101.2.1.5.60" */
	gSIGORKMPRIVILEGES[],				/* "2.16.840.1.101.2.1.5.55" */
	gCOMMPRIVILEGES[],					/* "2.16.840.1.101.2.1.5.56" */
	gSUBJDIRPRBACINFOOID[],				/* "2.5.4.55 */
	gMISSI_SSL_PRIVS[],					/* "2.16.840.1.101.2.1.8.2" */
	gCLEARANCE_ATTRIBUTE[];				/* "2.5.4.55 */


#if __cplusplus
}	/* end of extern "C" */
#endif


#endif /* _CMLASN_C_H */
