/*****************************************************************************
File:     CM_globals.c
Project:  Certificate Management Library
Contents: File containing all of the exported global variables used in the
          Certificate Management ASN.1 Library

Created:  17 April 1997
Author:   Rich Nicholas <Richard.Nicholas@GetronicsGov.com>

Last Updated:  23 October 2003

Version:  2.4

*****************************************************************************/

/* Define the CML ASN import/export modifier */
#ifdef WIN32
	#define CM_API		__declspec(dllexport)
#endif


/* Include Files */
#include "cmlasn_c.h"


/* Algorithm OIDs */
const char gDSA_OID[]	= "1.2.840.10040.4.1",
	gDSA_SHA1_OID[]		= "1.2.840.10040.4.3",
	gSHA1_OID[]			= "1.3.14.3.2.26",
	gRSA_OID[]			= "1.2.840.113549.1.1.1",
	gRSA_MD2_OID[]		= "1.2.840.113549.1.1.2",
	gRSA_MD4_OID[]		= "1.2.840.113549.1.1.3",
	gRSA_MD5_OID[]		= "1.2.840.113549.1.1.4",
	gRSA_SHA1_OID[]		= "1.2.840.113549.1.1.5",
	gOLD_DH_OID[]		= "1.2.840.113549.1.3.1",
	gMD2_OID[]			= "1.2.840.113549.2.2",
	gMD4_OID[]			= "1.2.840.113549.2.4",
	gMD5_OID[]			= "1.2.840.113549.2.5",
	gMOSAIC_DSA_OID[]	= "2.16.840.1.101.2.1.1.19",
	gDSA_KEA_OID[]		= "2.16.840.1.101.2.1.1.20",
	gKEA_OID[]			= "2.16.840.1.101.2.1.1.22",
	gOIW_DSA[]			= "1.3.14.3.2.12",
	gANSI_DH_OID[]		= "1.2.840.10046.2.1",
	gEC_KEY_OID[] 		= "1.2.840.10045.2.1",
	gECDSA_SHA1_OID[]	= "1.2.840.10045.4.1",
	gECDSA_SHA256_OID[]	= "1.2.840.10045.4.2",
	gECDSA_SHA384_OID[]	= "1.2.840.10045.4.3";

const char gSUBJ_DIR_ATTRIBS[]	= "2.5.29.9",
	gSUBJ_KEY_ID[]				= "2.5.29.14",
	gKEY_USAGE[]				= "2.5.29.15",
	gPRIV_KEY_USAGE[]			= "2.5.29.16",
	gSUBJ_ALT_NAME[]			= "2.5.29.17",
	gISSUER_ALT_NAME[] 			= "2.5.29.18",
	gBASIC_CONST[]				= "2.5.29.19",
	gCRL_NUM[]					= "2.5.29.20",
	gREASON_CODE[]				= "2.5.29.21",
	gINSTRUCT_CODE[]			= "2.5.29.23",
	gINVALID_DATE[]				= "2.5.29.24",
	gDELTA_CRL_NUM[]			= "2.5.29.27",
	gISSUING_DIST_PT[] 			= "2.5.29.28",
	gCERT_ISSUER[]				= "2.5.29.29",
	gNAME_CONST[]				= "2.5.29.30.1",
	gCRL_DISTRO_PTS[]			= "2.5.29.31",
	gCERT_POLICIES[]			= "2.5.29.32",
	gPOL_MAPPINGS[]				= "2.5.29.33",
	gAUTH_KEY_ID[] 				= "2.5.29.35",
	gPOLICY_CONST[]				= "2.5.29.36",
	gEXT_KEY_USE[] 				= "2.5.29.37",
	gEXT_CRL_STREAM_ID[]		= "2.5.29.40",
	gEXT_CRL_SCOPE[]			= "2.5.29.44",
	gEXT_STATUS_REFS[]			= "2.5.29.45",
	gEXT_FRESHEST_CRL[]			= "2.5.29.46",
	gEXT_ORDERED_LIST[]			= "2.5.29.47",
	gEXT_BASE_UPDATE[]			= "2.5.29.51",
	gEXT_DELTA_INFO[]			= "2.5.29.53",
	gEXT_INHIBIT_POL[]			= "2.5.29.54";

const char gANY_POLICY_OID[]	= "2.5.29.32.0";

const char gANY_KEY_USE_OID[]	= "2.5.29.37.0";

const char gEXT_PKIX_AIA[]		= "1.3.6.1.5.5.7.1.1",
	gEXT_PKIX_SIA[]				= "1.3.6.1.5.5.7.1.11";

const char gQT_CPS_QUALIFIER_OID[]	= "1.3.6.1.5.5.7.2.1",
	gQT_UNOTICE_QUALIFIER_OID[]		= "1.3.6.1.5.5.7.2.2";

const char gEXT_KEY_USE_serverAuth[]	= "1.3.6.1.5.5.7.3.1",
	gEXT_KEY_USE_clientAuth[]			= "1.3.6.1.5.5.7.3.2",
	gEXT_KEY_USE_codeSigning[]			= "1.3.6.1.5.5.7.3.3",
	gEXT_KEY_USE_emailProtection[]		= "1.3.6.1.5.5.7.3.4",
	gEXT_KEY_USE_timeStamping[]			= "1.3.6.1.5.5.7.3.8",
	gEXT_KEY_USE_OCSPSigning[]			= "1.3.6.1.5.5.7.3.9";

const char gHOLD_CALL_ISSUER_OID[]		= "1.2.840.10040.2.2",
	gHOLD_REJECT_OID[]					= "1.2.840.10040.2.3";

const char gAD_OCSP_OID[]				= "1.3.6.1.5.5.7.48.1",
	gAD_CA_ISSUERS_OID[]				= "1.3.6.1.5.5.7.48.2",
	gAD_TIME_STAMPING_OID[]				= "1.3.6.1.5.5.7.48.3",
	gAD_CA_REPOSITORY_OID[]				= "1.3.6.1.5.5.7.48.5";

const char gCACLEARANCECONSTRAINT[]		= "2.16.840.1.101.2.1.5.60",
	gSIGORKMPRIVILEGES[]				= "2.16.840.1.101.2.1.5.55",
	gSUBJDIRPRBACINFOOID[]				= "2.5.4.55",
	gCOMMPRIVILEGES[]					= "2.16.840.1.101.2.1.5.56",
	gMISSI_SSL_PRIVS[]					= "2.16.840.1.101.2.1.8.2",
	gCLEARANCE_ATTRIBUTE[]				= "2.5.4.55";

