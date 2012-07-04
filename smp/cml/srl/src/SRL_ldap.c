/*****************************************************************************
File:     SRL_ldap.c
Project:  Storage & Retrieval Library
Contents: Functions used to call the standard LDAP library.
		  NOTE: This file also contains logic to retrieve
		  CRL's and Certs via FTP & HTTP.

Created:  15 November 2000
Authors:  Clyde C. McPherson <Clyde.Mcpherson@GetronicsGov.com>
		  Shari Bodin <Shari.Bodin@GetronicsGov.com>
		  Robin Moeller <Robin.Moeller@DigitalNet.com>

Last Updated:  11 May 2004

Version:  2.4

*****************************************************************************/

/* Windows.h and LDAP32_DYNAMIC_BIND are only needed when dynamically binding
to the LDAP libraries at run-time.  Undefine LDAP32_DYNAMIC_BIND when
statically linking or dynamically linking at load-time. */
#define LDAP32_DYNAMIC_BIND	

#ifdef WIN32
	#include <process.h>	
	#ifdef _DEBUG					/* Include windows headers for debugging */
		#define _WIN32_WINNT	0x0500
		#pragma warning(disable: 4115)
		#include <windows.h>
		#include <winbase.h>
	#endif
#else
    #include <ctype.h>
    #include <unistd.h>
    #include <string.h>
	#define strnicmp strncasecmp
#if defined(HPUX32)
    #include <dl.h>
 	#define FreeLibrary shl_unload
#else
	#include <dlfcn.h>
	#define FreeLibrary dlclose
#endif /*HPUX*/
#endif /*WIN32*/

#include "SRL_internal.h"


/* ----------------- */
/* Defined Constants */
/* ----------------- */
#define URL_COLON "url:"
#define URLCOLON_LEN  sizeof(URL_COLON)-1
#define LDAPS_PREFIX "ldaps://"
#define LDAPS_PREFIX_LEN sizeof(LDAPS_PREFIX)-1
#define LDAPI_PREFIX "ldapi://"
#define LDAPI_PREFIX_LEN sizeof(LDAPI_PREFIX)-1
#define LDAP_PREFIX "ldap://"
#define LDAP_PREFIX_LEN sizeof(LDAP_PREFIX)-1
#define FTP_PREFIX "ftp://"
#define FTP_PREFIX_LEN sizeof (FTP_PREFIX)-1
#define HTTP_PREFIX "http://"
#define HTTP_PREFIX_LEN sizeof(HTTP_PREFIX)-1
#define LDAP_PREFIX_TYPE  1
#define FTP_PREFIX_TYPE   3
#define HTTP_PREFIX_TYPE  4
#define LDAP_DEFAULT_TIMEOUT 30

/* This source file uses the following LDAP error constants */
#define LDAP_SUCCESS                    0x00
#define LDAP_OPERATIONS_ERROR           0x01
#define LDAP_STRONG_AUTH_REQUIRED       0x08
#define LDAP_REFERRAL                   0x0a
#define LDAP_INAPPROPRIATE_AUTH         0x30
#define LDAP_INVALID_CREDENTIALS        0x31
#define LDAP_BUSY                       0x33
#define LDAP_UNAVAILABLE                0x34
#define LDAP_SERVER_DOWN                0x51
#define LDAP_AUTH_UNKNOWN               0x56
#define LDAP_CONNECT_ERROR              0x5b

/* for on/off options */
#define LDAP_OPT_ON     ((void *)1)
#define LDAP_OPT_OFF    ((void *)0)

/* Standard options */
#define LDAP_OPT_REFERRALS              0x08	/*  8 */
#define LDAP_OPT_PROTOCOL_VERSION	    0x11	/* 17 */

/* search scopes */
#define LDAP_SCOPE_BASE         0x00
#define LDAP_SCOPE_ONELEVEL     0x01
#define LDAP_SCOPE_SUBTREE      0x02

/* LDAP version */
#define LDAP_VERSION2   	2
#define LDAP_VERSION3   	3


/* ------------------- */
/* Function Prototypes */
/* ------------------- */
extern int Ftp_Connect(const char *host, int port, netbuf **nControl);
extern short Ftp_Get(const char *path, char mode, netbuf *nControl,
					 Bytes_struct *inBuf);
extern int Ftp_Login(const char *user, const char *pass, netbuf *nControl);
extern int Ftp_Socket_close(netbuf *nData);
extern void Ftp_Quit(netbuf *nControl);
extern int Http_Connect(const char *host, int port);
extern short Http_Get(const char *hostname, const char *path,
					  Bytes_struct *inbuf, int http_socket);
extern void Http_Quit(int http_socket);

static short addCert2List(ulong sessionID, struct berval *valp, int ,
						  EncObject_LL **list);
static short addCRL2List(ulong sessionID, struct berval *valp, int typeMask,
						 EncObject_LL **list);

void SRLi_LDAPBind(LDAPInfo_struct *f);
short SRLi_GetLDAPCertAttributes(ulong sessionID, LDAPInfo_struct *ldapInfo,
								  int typeMask, LDAPMessage *result,
								  EncObject_LL **certs);
short SRLi_GetLDAPCRLAttributes(ulong sessionID, LDAPInfo_struct *ldapInfo,
								 int typeMask,LDAPMessage *result,
								 EncObject_LL **crls);
short SRLi_GetLDAPACAttributes(ulong sessionID, LDAPInfo_struct *ldapInfo,
							   int typeMask,LDAPMessage *result,
							   EncObject_LL **acs);
short SRLi_GetLDAPSPIFAttributes(ulong sessionID, LDAPInfo_struct *ldapInfo,
								 int typeMask, LDAPMessage *result,
								 EncObject_LL **acs);
short SRLi_GetLDAPADCAttributes(ulong sessionID, LDAPInfo_struct *ldapInfo,
								int typeMask, LDAPMessage *result,
								EncObject_LL **acs);
short SRLi_GetLDAPAARLAttributes(ulong sessionID, LDAPInfo_struct *ldapInfo,
								 int typeMask, LDAPMessage *result,
								 EncObject_LL **acs);
short SRLi_GetLDAPAAACAttributes(ulong sessionID, LDAPInfo_struct *ldapInfo,
								 int typeMask, LDAPMessage *result,
								 EncObject_LL **acs);
short SRLi_GetLDAPACRLAttributes(ulong sessionID, LDAPInfo_struct *ldapInfo,
								 int typeMask, LDAPMessage *result,
								 EncObject_LL **acs);
short SRLi_BreakUpCertPair(uchar *asndata, ulong elmtLen1, ulong *decodedLen,
						   SRL_CertList **hcpath);

static uchar *dupHex2Bin(char *hex, ulong len);
static short SRLi_FTPURLRead(ulong sessionID, SRL_URLDescriptor_struct *inDesc,
							 EncObject_LL **result);
static short SRLi_HTTPURLRead(ulong sessionID, SRL_URLDescriptor_struct *inDesc,
							  EncObject_LL **result);
short SRLi_GetRemoteCerts(ulong sessionID, CM_DN subject, int typeMask,
						  EncObject_LL **certs);
short SRLi_GetRemoteACs(ulong sessionID, CM_DN issuer, int typeMask,
						EncObject_LL **acs);
short SRLi_GetRemoteCRLs(ulong sessionID, CM_DN issuer, int typeMask,
						 EncObject_LL **crls);
short SRLi_GetRemoteSPIFs(ulong sessionID, CM_DN issuer, int typeMask,
						  EncObject_LL **spifs);

static short prepData(struct berval *valp, Bytes_struct **odata);
static CM_BOOL SRLi_is_ldapurl(char *url);
int SRLi_url_parse (char *purl, SRL_URLDescriptor_struct **pURLDesc);
int SRLi_memicmp(char *mem1, char *mem2, int len);

//extern CM_FreeObjList (EncObject_LL *the_object)


/* ---------------- */
/* Global Variables */
/* ---------------- */

short threaderror = SRL_SUCCESS;

static char* certAttribs[] = {
	"userCertificate;binary",				/* 2.5.4.36 */
	"cACertificate;binary",					/* 2.5.4.37 */
	"userCertificate",						/* 2.5.4.36 */
	"cACertificate",						/* 2.5.4.37 */
	"mosaicKMandSigCertificate",			/* 2.16.840.1.101.2.1.5.5 */
	"sdnsKMandSigCertificate",				/* 2.16.840.1.101.2.1.5.3 */
	"fortezzaKMandSigCertificate",			/* 2.16.840.1.101.2.1.5.5 */
	"crossCertificatePair;binary",			/* 2.5.4.40 */
	"crossCertificatePair",					/* 2.5.4.40 */
	NULL };

static char* crlAttribs[] = {
	"certificateRevocationList;binary",		/* 2.5.4.39 */
	"authorityRevocationList;binary",		/* 2.5.4.38 */
	"certificateRevocationList",			/* 2.5.4.39 */
	"authorityRevocationList",				/* 2.5.4.38 */
	"deltaRevocationList;binary",			/* 2.5.4.53 */
	"deltaRevocationList",					/* 2.5.4.53 */
	"mosaicCertificateRevocationList",		/* 2.16.840.1.101.2.1.5.45 */
	"sdnsCertificateRevocationList",		/* 2.16.840.1.101.2.1.5.44 */
	"fortezzaCertificateRevocationList",	/* 2.16.840.1.101.2.1.5.45 */
	NULL };

	/*Attribute Certificates */
static char* acAttribs[] = {
	"attributeCertificate;binary",			/* 2.5.4.58 */
	"attributeCertificate",					/* 2.5.4.58 */
	NULL };

	/*Attribute Authority Attribute Cert */
static char* aaAttribs[] = {
	"aACertificate;binary",			/* 2.5.4.61 */
	"aACertificate",				/* 2.5.4.61 */
	NULL };

	/*Attribute Descriptor Cert*/
static char* adAttribs[] = {
	"attributeDescriptorCertificate;binary",		/* 2.5.4.62 */
	"attributeDescriptorCertificate",				/* 2.5.4.62 */
	NULL };

	/*Attribute Certificate Revocation List */
static char* acrListAttribs[] = {
	"attributeCertificateRevocationList;binary",	/* 2.5.4.59 */
	"attributeCertificateRevocationList",			/* 2.5.4.59 */
	NULL };

	/*Attribute Authority Revocation List*/
static char* aaListAttribs[] = {
	"attributeAuthorityRevocationList;binary",	/* 2.5.4.63 */
	"attributeAuthorityRevocationList",			/* 2.5.4.63 */
	NULL };

	/* SPIFs */
static char* spifAttribs[] = {
	"spif;binary",	/*  */
	"spif",			/*  */
	NULL };


/* -------------------- */
/* SRLi_GetRemoteCerts() */
/* -------------------- */
short SRLi_GetRemoteCerts(ulong sessionID, CM_DN subject, int typeMask, EncObject_LL **certs)
{
	LDAPInfo_struct *ldapInfo = NULL;
	short err = 0;
	LDAPMessage *result = NULL;
	SRLSession_struct *sessionInfo = NULL;

	/* Check parameters (these should never be NULL) */
	if ((subject == NULL) || (certs == NULL))
		return SRL_NULL_POINTER;

	/* Initialize linked list */
	*certs = NULL;

	/* Check session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if ((err = SRLi_GetRetSessionFromRef(&sessionInfo, sessionID)) != SRL_SUCCESS)
		return ((short)err);

	/* Get LDAP information (this should never be NULL) */
	ldapInfo = sessionInfo->ldapInfo;
	if (ldapInfo == NULL)
		return SRL_NULL_POINTER;

	/* Call LDAP Read */
	err = SRLi_LdapRead(sessionID, ldapInfo, ldapInfo->ldapIDinfo->ldapID, subject, 
		certAttribs, &result);
	if (err != SRL_SUCCESS)
		return err;

	if (result != NULL)
		err = SRLi_GetLDAPCertAttributes (sessionID, ldapInfo, typeMask, result, certs);

	return (err);
}


short SRLi_GetRemoteURLCerts(ulong sessionID, char *pUrlToFind, int typeMask,
							 short locMask, EncObject_LL **certs)
{
	LDAPInfo_struct *ldapInfo = NULL;
	short err = 0;
	int url_type = 0;
	short errCode;
    SRLSession_struct *session = NULL;
	SRL_URLDescriptor_struct *URLDesc = NULL;

	/* Check parameters (these should never be NULL) */
	if ((pUrlToFind == NULL) || (certs == NULL))
		return SRL_NULL_POINTER;

	/* Check session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	/* Initialize result */
    *certs = NULL;

	/* Get the Retrieval session */
	errCode =  SRLi_GetRetSessionFromRef(&session, sessionID);
	if(errCode != SRL_SUCCESS)
		return errCode;

	url_type = SRLi_url_parse (pUrlToFind, &URLDesc);
	if (url_type == SRL_INVALID_PARAMETER)
	{
		if (URLDesc != NULL)
			SRLi_FreeURLDescriptor(&URLDesc);
		return SRL_INVALID_URL;
	}

	/* ldap:// ldapi:// ldaps:// */
	if (((url_type == 1) || (url_type == 2)) && (locMask & DSA_LOC))
	{
		/* Point to the current sessions LDAP info */
	    ldapInfo = session->ldapInfo; 
		if (ldapInfo == NULL)
		{
			if (URLDesc != NULL)
				SRLi_FreeURLDescriptor(&URLDesc);			
			return SRL_NULL_POINTER;
		}
		/* Call LDAP URL Read */
		err = SRLi_LdapURLRead(sessionID,URLDesc, ldapInfo, typeMask, SRL_CERT_TYPE, certs);
	}
	/* ftp:// */
	else if ((url_type == 3) && (locMask & SERVER_LOC))
	{
		/* Call the FTP Read */
		err = SRLi_FTPURLRead(sessionID, URLDesc, certs);
		if (*certs != NULL)
			(*certs)->typeMask = SRL_CERT_TYPE;
	}
	/* http:// */
	else if ((url_type == 4) && (locMask & SERVER_LOC))
	{
		// Call the HTTP Read 
		err = SRLi_HTTPURLRead(sessionID, URLDesc, certs);
		if (*certs != NULL)
			(*certs)->typeMask = SRL_CERT_TYPE;
	}
	else
		err = SRL_INVALID_URL;

	// Free the URL Descriptor and continue
	if (URLDesc != NULL)
		SRLi_FreeURLDescriptor(&URLDesc);

	return err;
}

/* Routine to get the LDAP Returned Certificate attributes that are cert attributes */
short SRLi_GetLDAPCertAttributes (ulong sessionID, LDAPInfo_struct *ldapInfo,
							 int typeMask, LDAPMessage *result, EncObject_LL **certs)
{
	short err = 0;
	struct berval **encValues;
	int x, numValues;
	char **certAttribp;


	if (ldapInfo->LDAPFunctions->count_entries == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->msgfree == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->get_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->count_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->value_free_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);


	if (ldapInfo->LDAPFunctions->count_entries(ldapInfo->ldapIDinfo->ldapID, result) != 1)
	{
		ldapInfo->LDAPFunctions->msgfree(result);
		return SRL_LDAP_SEARCH_FAILED;
	}

	/* For each certificate attribute returned from the LDAP server,
	get the attribute's values and copy them to the encoded cert linked 
	list. */
	certAttribp = certAttribs;
	while (*certAttribp != NULL)
	{
		/* Pull out the values for this attribute type from the LDAP Read 
		result */
		encValues = ldapInfo->LDAPFunctions->get_values_len(ldapInfo->ldapIDinfo->ldapID, result, 
			*certAttribp);

		
		/* For each value of this attribute type... */
		numValues = ldapInfo->LDAPFunctions->count_values_len(encValues);
		for (x = 0; x < numValues; x++)
		{
			/* Check that the values really exist
			(Note:  This check shouldn't be needed -- it was added in case
			count_values_len returned an incorrect positive number.) */
			if (encValues == NULL)
				break;
			if (typeMask & CROSS_CERT_TYPE)
			{
				/* Call the appropriate low-level function to add the certificate 
					pair or single certificate to the list. */
				if (strncmp(*certAttribp, "crossCertificatePair", 20) == 0)
				{
					/* Add it to our Object List, also add CROSS_CERT_TYPE */
					err = addCert2List(sessionID, encValues[x], CROSS_CERT_TYPE, certs);
					
				}

			}
			if (typeMask & CA_CERT_TYPE)
			{
				if (strncmp(*certAttribp, "cACertificate", 13) == 0)
					/* Add this certificate value to the linked list */
					err = addCert2List(sessionID, encValues[x], CA_CERT_TYPE, certs);
			}
			if (typeMask & USER_CERT_TYPE)
			{
				/* Check for all other attributes */
				if (strncmp(*certAttribp, "userCertificate", 15) == 0)
					/* Add cert to list */
					err = addCert2List(sessionID, encValues[x], USER_CERT_TYPE, certs);
				else if (strncmp (*certAttribp,"mosaicKMandSigCertificate", 25) == 0)
					/* Add cert to list */
					err = addCert2List(sessionID, encValues[x], USER_CERT_TYPE, certs);
				else if (strncmp (*certAttribp,"sdnsKMandSigCertificate", 23) == 0)
					/* Add cert to list */
					err = addCert2List(sessionID, encValues[x], USER_CERT_TYPE, certs);
				else if (strncmp (*certAttribp,"fortezzaKMandSigCertificate", 27) == 0)
					/* Add cert to list */
					err = addCert2List(sessionID, encValues[x], USER_CERT_TYPE, certs);
			}
			if (err != SRL_SUCCESS)
			{
				ldapInfo->LDAPFunctions->value_free_len(encValues);

				ldapInfo->LDAPFunctions->msgfree(result);
				return err;
			}
		} /* end of for loop */ 


		/* Free the values for this attribute */
		ldapInfo->LDAPFunctions->value_free_len(encValues);

		certAttribp++;

	} /* end of while loop */

	/* Free LDAP result */
	ldapInfo->LDAPFunctions->msgfree(result);

	/* If the list is empty, then return SRL_NOT_FOUND */
	if (*certs == NULL)
		return SRL_NOT_FOUND;
	else
		return SRL_SUCCESS;

} /* end of SRLi_GetLDAPCertAttributes() */


/* ------------------- */
/* SRLi_GetRemoteURLCRLs() */
/* ------------------- */
short SRLi_GetRemoteURLCRLs(ulong sessionID, char *url, int typeMask,
							short locMask, EncObject_LL **crls)
{
	LDAPInfo_struct *ldapInfo;
	SRL_URLDescriptor_struct *URLDesc = NULL;
	short err;
	int url_type  = 0;
//	LDAPMessage *result = NULL;
	SRLSession_struct *sessionInfo = NULL;
	/* Check parameters (these should never be NULL) */
	if ((url == NULL) || (crls == NULL))
		return SRL_NULL_POINTER;

	/* Initialize linked list */
	*crls = NULL;

	/* Check session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if ((err = SRLi_GetRetSessionFromRef(&sessionInfo, sessionID)) != SRL_SUCCESS)
		return ((short)err);

	url_type = SRLi_url_parse(url, &URLDesc);
	if (url_type == SRL_INVALID_PARAMETER)
	{
		if (URLDesc != NULL)
			SRLi_FreeURLDescriptor(&URLDesc);
		return(SRL_INVALID_URL);
	}
	/* Call LDAP Read, FTP read or HTTP read according to the url type */

	if (((url_type == 1) || (url_type == 2)) && (locMask & DSA_LOC))
	{
		/* Get the global LDAP information  */
		ldapInfo = sessionInfo->ldapInfo;
		if (ldapInfo == NULL)
			return SRL_NULL_POINTER;

		err = SRLi_LdapURLRead(sessionID, URLDesc, ldapInfo, typeMask, SRL_CRL_TYPE,  crls);
	}
	else if ((url_type == 3) && (locMask & SERVER_LOC))
	{
		/* Call the FTP Read */
		err = SRLi_FTPURLRead(sessionID, URLDesc, crls);
		if (*crls != NULL)
			(*crls)->typeMask = SRL_CRL_TYPE;
	}
	else if ((url_type == 4) && (locMask & SERVER_LOC))
	{
		/* Call the HTTP Read */
		err = SRLi_HTTPURLRead(sessionID, URLDesc, crls);
		if (*crls != NULL)
			(*crls)->typeMask = SRL_CRL_TYPE;
    }
	else
		err = SRL_INVALID_URL;

	
	if (URLDesc != NULL)
		SRLi_FreeURLDescriptor(&URLDesc);

	return (err);
}

/* ------------------- */
/* SRLi_GetRemoteCRLs() */
/* ------------------- */
short SRLi_GetRemoteCRLs(ulong sessionID, CM_DN issuer, int typeMask, EncObject_LL **crls)
{
	LDAPInfo_struct *ldapInfo = NULL;
	short err = SRL_SUCCESS;
	LDAPMessage *result = NULL;
	SRLSession_struct *sessionInfo = NULL;
	/* Check parameters (these should never be NULL) */
	if ((issuer == NULL) || (crls == NULL))
		return SRL_NULL_POINTER;

	/* Initialize linked list */
	*crls = NULL;

	/* Check session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if ((err = SRLi_GetRetSessionFromRef(&sessionInfo, sessionID)) != SRL_SUCCESS)
		return ((short)err);

	/* Get the global LDAP information  */
	ldapInfo = sessionInfo->ldapInfo;
	if (ldapInfo == NULL)
		return SRL_NULL_POINTER;

	/* Call LDAP Read */
	err = SRLi_LdapRead(sessionID, ldapInfo, ldapInfo->ldapIDinfo->ldapID, issuer, 
		crlAttribs,  &result);
	if (err != SRL_SUCCESS)
		return err;
	if (result != NULL)
		err = SRLi_GetLDAPCRLAttributes (sessionID, ldapInfo, typeMask, result, crls);

	return (err);
}

short SRLi_GetLDAPCRLAttributes (ulong sessionID, LDAPInfo_struct *ldapInfo,
							  int typeMask, LDAPMessage *result, EncObject_LL **crls)
{
char **crlAttribp;
struct berval **encValues;
int x, numValues;
short err = 0;


	if (ldapInfo->LDAPFunctions->count_entries == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->get_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->count_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->msgfree == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->value_free_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);

	/* Check number of entries returned (should be only one, I think) */
	if (ldapInfo->LDAPFunctions->count_entries(ldapInfo->ldapIDinfo->ldapID, result) != 1)
	{
		ldapInfo->LDAPFunctions->msgfree(result);
		return SRL_LDAP_SEARCH_FAILED;
	}

	/* For each CRL attribute returned from the LDAP server, get the 
	attribute's values and copy them to the encoded CRL linked list. */
	crlAttribp = crlAttribs;
	while (*crlAttribp != NULL)
	{
		if (ldapInfo->LDAPFunctions->get_values_len == NULL)
			return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);

		/* Pull out the values for this attribute type from the LDAP Read 
		result */
		encValues = ldapInfo->LDAPFunctions->get_values_len(ldapInfo->ldapIDinfo->ldapID, result, 
			*crlAttribp);
		
		/* For each value of this attribute type... */
		numValues = ldapInfo->LDAPFunctions->count_values_len(encValues);
		for (x = 0; x < numValues; x++)
		{
			/* Check that the values really exist
			(Note:  This check shouldn't be needed -- it was added in case
			count_values_len returned an incorrect positive number.) */
			if (encValues == NULL)
				break;
			if (typeMask & CRL_TYPE)
			{
					if (strncmp(*crlAttribp, "certificateRevocationList", 25) == 0)
						/* Add this CRL value to the linked list */
						err = addCRL2List(sessionID, encValues[x], CRL_TYPE, crls);

					else if (strncmp(*crlAttribp, "mosaicCertificateRevocationList", 31) == 0)
						/* Add this CRL value to the linked list */
						err = addCRL2List(sessionID, encValues[x], CRL_TYPE, crls);

					else if (strncmp(*crlAttribp, "sdnsCertificateRevocationList", 28) == 0)
						/* Add this CRL value to the linked list */
						err = addCRL2List(sessionID, encValues[x], CRL_TYPE, crls);

					else if (strncmp(*crlAttribp, "fortezzaCertificateRevocationList", 33) == 0)
						/* Add this CRL value to the linked list */
						err = addCRL2List(sessionID, encValues[x], CRL_TYPE, crls);
			}
			if (typeMask & ARL_TYPE)
			{
					if (strncmp(*crlAttribp, "authorityRevocationList", 23) == 0)
						/* Add this CRL value to the linked list */
						err = addCRL2List(sessionID, encValues[x], ARL_TYPE, crls);
			}
			if (typeMask & DELTA_CRL_TYPE)
			{				
					if (strncmp(*crlAttribp, "deltaRevocationList", 19) == 0)
						/* Add this CRL value to the linked list */
						err = addCRL2List(sessionID, encValues[x], DELTA_CRL_TYPE, crls);
			}
			/* Add this CRL value to the linked list */
			if (err != SRL_SUCCESS)
			{
				ldapInfo->LDAPFunctions->value_free_len(encValues);
				ldapInfo->LDAPFunctions->msgfree(result);
				return err;
			}
		}

		/* Free the values for this attribute */
		ldapInfo->LDAPFunctions->value_free_len(encValues);

		crlAttribp++;

	} /* end of while loop */

	/* Free LDAP result */
	ldapInfo->LDAPFunctions->msgfree(result);

	/* If the list is empty, then return SRL_NOT_FOUND */
	if (*crls == NULL)
		return SRL_NOT_FOUND;
	else
		return SRL_SUCCESS;

} /* end of SRLi_GetLDAPCRLAttributes() */

/* -------------------- */
/* SRLi_GetRemoteACs() */
/* -------------------- */
short SRLi_GetRemoteACs(ulong sessionID, CM_DN issuer, int typeMask, EncObject_LL **acs)
{
	LDAPInfo_struct *ldapInfo = NULL;
	short err = 0;
	LDAPMessage *result = NULL;
	SRLSession_struct *sessionInfo = NULL;

	/* Check parameters (these should never be NULL) */
	if ((issuer == NULL) || (acs == NULL))
		return SRL_NULL_POINTER;

	/* Initialize linked list */
	*acs = NULL;

	/* Check session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if ((err = SRLi_GetRetSessionFromRef(&sessionInfo, sessionID)) != SRL_SUCCESS)
		return ((short)err);

	/* Get LDAP information (this should never be NULL) */
	ldapInfo = sessionInfo->ldapInfo;
	if (ldapInfo == NULL)
		return SRL_NULL_POINTER;

	/* Call LDAP Read */
	switch (typeMask)
	{ 
	case AC_TYPE:

		/*Attribute Certificates */
		err = SRLi_LdapRead(sessionID, ldapInfo, ldapInfo->ldapIDinfo->ldapID, issuer, 
							acAttribs, &result);
		if (err != SRL_SUCCESS)
			return err;

		if (result != NULL)
			err = SRLi_GetLDAPACAttributes (sessionID, ldapInfo, typeMask, result, acs);
		break;

	case ACRL_TYPE:

		/*Attribute Certificate Revocation List */
		err = SRLi_LdapRead(sessionID, ldapInfo, ldapInfo->ldapIDinfo->ldapID, issuer, 
							acrListAttribs, &result);
		if (err != SRL_SUCCESS)
			return err;

		if (result != NULL)
			err = SRLi_GetLDAPACRLAttributes (sessionID, ldapInfo, typeMask, result, acs);
		break;

	case AARL_TYPE:

		/*Attribute Authority Revocation List*/
		err = SRLi_LdapRead(sessionID, ldapInfo, ldapInfo->ldapIDinfo->ldapID, issuer, 
							aaListAttribs, &result);
		if (err != SRL_SUCCESS)
			return err;

		if (result != NULL)
			err = SRLi_GetLDAPAARLAttributes (sessionID, ldapInfo, typeMask, result, acs);
		break;

	case AAAC_TYPE:

		/*Attribute Authority Attribute Cert */
		err = SRLi_LdapRead(sessionID, ldapInfo, ldapInfo->ldapIDinfo->ldapID, issuer, 
							aaAttribs, &result);
		if (err != SRL_SUCCESS)
			return err;

		if (result != NULL)
			err = SRLi_GetLDAPAAACAttributes (sessionID, ldapInfo, typeMask, result, acs);
		break;

	case ADC_TYPE:

		/*Attribute Descriptor Cert*/
		err = SRLi_LdapRead(sessionID, ldapInfo, ldapInfo->ldapIDinfo->ldapID, issuer, 
							adAttribs, &result);
		if (err != SRL_SUCCESS)
			return err;

		if (result != NULL)
			err = SRLi_GetLDAPADCAttributes (sessionID, ldapInfo, typeMask, result, acs);
		break;

	default:

		err = SRL_UNDEFINED_TYPE;
		break;
	}

	return (err);
}

/* -------------------- */
/* SRLi_GetRemoteSPIFs() */
/* -------------------- */
short SRLi_GetRemoteSPIFs(ulong sessionID, CM_DN issuer, int typeMask, EncObject_LL **spifs)
{
	LDAPInfo_struct *ldapInfo = NULL;
	short err = 0;
	LDAPMessage *result = NULL;
	SRLSession_struct *sessionInfo = NULL;

	/* Check parameters (these should never be NULL) */
	if ((issuer == NULL) || (spifs == NULL))
		return SRL_NULL_POINTER;

	/* Initialize linked list */
	*spifs = NULL;

	/* Check session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if ((err = SRLi_GetRetSessionFromRef(&sessionInfo, sessionID)) != SRL_SUCCESS)
		return ((short)err);

	/* Get LDAP information (this should never be NULL) */
	/* Call LDAP Read */

	ldapInfo = sessionInfo->ldapInfo;
	if (ldapInfo == NULL)
		return SRL_NULL_POINTER;

	/* SPIFs */
	err = SRLi_LdapRead(sessionID, ldapInfo, ldapInfo->ldapIDinfo->ldapID, issuer, 
							spifAttribs, &result);
	if (err != SRL_SUCCESS)
		return err;

	if (result != NULL)
		err = SRLi_GetLDAPSPIFAttributes (sessionID, ldapInfo, typeMask, result, spifs);
		
	return (err);
}

/* Routine to get the LDAP Returned Attribute Certificate */
short SRLi_GetLDAPACAttributes (ulong sessionID, LDAPInfo_struct *ldapInfo,
							 int typeMask, LDAPMessage *result, EncObject_LL **acs)
{
	short err = 0;
	struct berval **encValues;
	int x, numValues;
	char **attribp;


	if (ldapInfo->LDAPFunctions->count_entries == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->msgfree == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->get_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->count_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->value_free_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);


	if (ldapInfo->LDAPFunctions->count_entries(ldapInfo->ldapIDinfo->ldapID, result) != 1)
	{
		ldapInfo->LDAPFunctions->msgfree(result);
		return SRL_LDAP_SEARCH_FAILED;
	}

	/* For each attribute certificate returned from the LDAP server,
	get the attribute's values and copy them to the encoded cert linked 
	list. */
	attribp = acAttribs;
	while (*attribp != NULL)
	{
		/* Pull out the values for this attribute type from the LDAP Read 
		result */
		encValues = ldapInfo->LDAPFunctions->get_values_len(ldapInfo->ldapIDinfo->ldapID, result, 
			*attribp);

		
		/* For each value of this attribute type... */
		numValues = ldapInfo->LDAPFunctions->count_values_len(encValues);
		for (x = 0; x < numValues; x++)
		{
			/* Check that the values really exist
			(Note:  This check shouldn't be needed -- it was added in case
			count_values_len returned an incorrect positive number.) */
			if (encValues == NULL)
				break;
			if (typeMask & AC_TYPE)
			{
				/* Call the appropriate low-level function to add the certificate 
					pair or single certificate to the list. */
				if (strncmp(*attribp, "attributeCertificate", 20) == 0)
				{
					/* Add it to our Object List, also add AC_TYPE */
					err = addCert2List(sessionID, encValues[x], AC_TYPE, acs);
					
				}

			}
			if (err != SRL_SUCCESS)
			{
				ldapInfo->LDAPFunctions->value_free_len(encValues);

				ldapInfo->LDAPFunctions->msgfree(result);
				return err;
			}
		} /* end of for loop */ 

		/* Free the values for this attribute */
		ldapInfo->LDAPFunctions->value_free_len(encValues);
		attribp++;

	} /* end of while loop */

	/* Free LDAP result */
	ldapInfo->LDAPFunctions->msgfree(result);

	/* If the list is empty, then return SRL_NOT_FOUND */
	if (*acs == NULL)
		return SRL_NOT_FOUND;
	else
		return SRL_SUCCESS;

} /* end of SRLi_GetLDAPACAttributes() */

/* Routine to get the LDAP Returned Attribute Certificate Revocation List  */
short SRLi_GetLDAPACRLAttributes (ulong sessionID, LDAPInfo_struct *ldapInfo,
							 int typeMask, LDAPMessage *result, EncObject_LL **acs)
{
	short err = 0;
	struct berval **encValues;
	int x, numValues;
	char **attribp;


	if (ldapInfo->LDAPFunctions->count_entries == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->msgfree == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->get_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->count_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->value_free_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);


	if (ldapInfo->LDAPFunctions->count_entries(ldapInfo->ldapIDinfo->ldapID, result) != 1)
	{
		ldapInfo->LDAPFunctions->msgfree(result);
		return SRL_LDAP_SEARCH_FAILED;
	}

	/* For each Attribute Certificate Revocation List  returned from the LDAP server,
	get the attribute's values and copy them to the encoded cert linked 
	list. */
	attribp = acrListAttribs;
	while (*attribp != NULL)
	{
		/* Pull out the values for this attribute type from the LDAP Read 
		result */
		encValues = ldapInfo->LDAPFunctions->get_values_len(ldapInfo->ldapIDinfo->ldapID, result, 
			*attribp);

		
		/* For each value of this attribute type... */
		numValues = ldapInfo->LDAPFunctions->count_values_len(encValues);
		for (x = 0; x < numValues; x++)
		{
			/* Check that the values really exist
			(Note:  This check shouldn't be needed -- it was added in case
			count_values_len returned an incorrect positive number.) */
			if (encValues == NULL)
				break;
			if (typeMask & ACRL_TYPE)
			{
				/* Call the appropriate low-level function to add the certificate 
					pair or single certificate to the list. */
				if (strncmp(*attribp, "attributeCertificateRevocationList", 34) == 0)
				{
					/* Add it to our Object List, also add ACRL_TYPE */
					err = addCert2List(sessionID, encValues[x], ACRL_TYPE, acs);
					
				}

			}
			if (err != SRL_SUCCESS)
			{
				ldapInfo->LDAPFunctions->value_free_len(encValues);

				ldapInfo->LDAPFunctions->msgfree(result);
				return err;
			}
		} /* end of for loop */ 

		/* Free the values for this attribute */
		ldapInfo->LDAPFunctions->value_free_len(encValues);
		attribp++;

	} /* end of while loop */

	/* Free LDAP result */
	ldapInfo->LDAPFunctions->msgfree(result);

	/* If the list is empty, then return SRL_NOT_FOUND */
	if (*acs == NULL)
		return SRL_NOT_FOUND;
	else
		return SRL_SUCCESS;

} /* end of SRLi_GetLDAPACRLAttributes() */

/* Routine to get the LDAP Returned Attribute Authority Attribute Cert  */
short SRLi_GetLDAPAAACAttributes (ulong sessionID, LDAPInfo_struct *ldapInfo,
							 int typeMask, LDAPMessage *result, EncObject_LL **acs)
{
	short err = 0;
	struct berval **encValues;
	int x, numValues;
	char **attribp;


	if (ldapInfo->LDAPFunctions->count_entries == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->msgfree == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->get_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->count_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->value_free_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);


	if (ldapInfo->LDAPFunctions->count_entries(ldapInfo->ldapIDinfo->ldapID, result) != 1)
	{
		ldapInfo->LDAPFunctions->msgfree(result);
		return SRL_LDAP_SEARCH_FAILED;
	}

	/* For each Attribute Authority Attribute Cert  returned from the LDAP server,
	get the attribute's values and copy them to the encoded cert linked 
	list. */
	attribp = aaAttribs;
	while (*attribp != NULL)
	{
		/* Pull out the values for this attribute type from the LDAP Read 
		result */
		encValues = ldapInfo->LDAPFunctions->get_values_len(ldapInfo->ldapIDinfo->ldapID, result, 
			*attribp);

		
		/* For each value of this attribute type... */
		numValues = ldapInfo->LDAPFunctions->count_values_len(encValues);
		for (x = 0; x < numValues; x++)
		{
			/* Check that the values really exist
			(Note:  This check shouldn't be needed -- it was added in case
			count_values_len returned an incorrect positive number.) */
			if (encValues == NULL)
				break;
			if (typeMask & AAAC_TYPE)
			{
				/* Call the appropriate low-level function to add the certificate 
					pair or single certificate to the list. */
				if (strncmp(*attribp, "aACertificate", 13) == 0)
				{
					/* Add it to our Object List, also add AAAC_TYPE */
					err = addCert2List(sessionID, encValues[x], AAAC_TYPE, acs);
					
				}

			}
			if (err != SRL_SUCCESS)
			{
				ldapInfo->LDAPFunctions->value_free_len(encValues);

				ldapInfo->LDAPFunctions->msgfree(result);
				return err;
			}
		} /* end of for loop */ 

		/* Free the values for this attribute */
		ldapInfo->LDAPFunctions->value_free_len(encValues);
		attribp++;

	} /* end of while loop */

	/* Free LDAP result */
	ldapInfo->LDAPFunctions->msgfree(result);

	/* If the list is empty, then return SRL_NOT_FOUND */
	if (*acs == NULL)
		return SRL_NOT_FOUND;
	else
		return SRL_SUCCESS;

} /* end of SRLi_GetLDAPAAACAttributes() */

/* Routine to get the LDAP Returned Attribute Authority Revocation List  */
short SRLi_GetLDAPAARLAttributes (ulong sessionID, LDAPInfo_struct *ldapInfo,
							 int typeMask, LDAPMessage *result, EncObject_LL **acs)
{
	short err = 0;
	struct berval **encValues;
	int x, numValues;
	char **attribp;


	if (ldapInfo->LDAPFunctions->count_entries == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->msgfree == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->get_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->count_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->value_free_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);


	if (ldapInfo->LDAPFunctions->count_entries(ldapInfo->ldapIDinfo->ldapID, result) != 1)
	{
		ldapInfo->LDAPFunctions->msgfree(result);
		return SRL_LDAP_SEARCH_FAILED;
	}

	/* For each Attribute Authority Revocation List  returned from the LDAP server,
	get the attribute's values and copy them to the encoded cert linked 
	list. */
	attribp = aaListAttribs;
	while (*attribp != NULL)
	{
		/* Pull out the values for this attribute type from the LDAP Read 
		result */
		encValues = ldapInfo->LDAPFunctions->get_values_len(ldapInfo->ldapIDinfo->ldapID, result, 
			*attribp);

		
		/* For each value of this attribute type... */
		numValues = ldapInfo->LDAPFunctions->count_values_len(encValues);
		for (x = 0; x < numValues; x++)
		{
			/* Check that the values really exist
			(Note:  This check shouldn't be needed -- it was added in case
			count_values_len returned an incorrect positive number.) */
			if (encValues == NULL)
				break;
			if (typeMask & AARL_TYPE)
			{
				/* Call the appropriate low-level function to add the certificate 
					pair or single certificate to the list. */
				if (strncmp(*attribp, "attributeAuthorityRevocationList", 32) == 0)
				{
					/* Add it to our Object List, also add AARL_TYPE */
					err = addCert2List(sessionID, encValues[x], AARL_TYPE, acs);
					
				}

			}
			if (err != SRL_SUCCESS)
			{
				ldapInfo->LDAPFunctions->value_free_len(encValues);

				ldapInfo->LDAPFunctions->msgfree(result);
				return err;
			}
		} /* end of for loop */ 

		/* Free the values for this attribute */
		ldapInfo->LDAPFunctions->value_free_len(encValues);
		attribp++;

	} /* end of while loop */

	/* Free LDAP result */
	ldapInfo->LDAPFunctions->msgfree(result);

	/* If the list is empty, then return SRL_NOT_FOUND */
	if (*acs == NULL)
		return SRL_NOT_FOUND;
	else
		return SRL_SUCCESS;

} /* end of SRLi_GetLDAPAARLAttributes() */

/* Routine to get the LDAP Returned Attribute Descriptor Certificate certs */
short SRLi_GetLDAPADCAttributes (ulong sessionID, LDAPInfo_struct *ldapInfo,
							 int typeMask, LDAPMessage *result, EncObject_LL **acs)
{
	short err = 0;
	struct berval **encValues;
	int x, numValues;
	char **attribp;


	if (ldapInfo->LDAPFunctions->count_entries == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->msgfree == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->get_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->count_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->value_free_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);


	if (ldapInfo->LDAPFunctions->count_entries(ldapInfo->ldapIDinfo->ldapID, result) != 1)
	{
		ldapInfo->LDAPFunctions->msgfree(result);
		return SRL_LDAP_SEARCH_FAILED;
	}

	/* For each Attribute Descriptor Certificate certs returned from the LDAP server,
	get the attribute's values and copy them to the encoded cert linked 
	list. */
	attribp = adAttribs;
	while (*attribp != NULL)
	{
		/* Pull out the values for this attribute type from the LDAP Read 
		result */
		encValues = ldapInfo->LDAPFunctions->get_values_len(ldapInfo->ldapIDinfo->ldapID, result, 
			*attribp);

		
		/* For each value of this attribute type... */
		numValues = ldapInfo->LDAPFunctions->count_values_len(encValues);
		for (x = 0; x < numValues; x++)
		{
			/* Check that the values really exist
			(Note:  This check shouldn't be needed -- it was added in case
			count_values_len returned an incorrect positive number.) */
			if (encValues == NULL)
				break;
			if (typeMask & ADC_TYPE)
			{
				/* Call the appropriate low-level function to add the certificate 
					pair or single certificate to the list. */
				if (strncmp(*attribp, "attributeDescriptorCertificate", 30) == 0)
				{
					/* Add it to our Object List, also add ADC_TYPE */
					err = addCert2List(sessionID, encValues[x], ADC_TYPE, acs);
					
				}

			}
			if (err != SRL_SUCCESS)
			{
				ldapInfo->LDAPFunctions->value_free_len(encValues);

				ldapInfo->LDAPFunctions->msgfree(result);
				return err;
			}
		} /* end of for loop */ 

		/* Free the values for this attribute */
		ldapInfo->LDAPFunctions->value_free_len(encValues);
		attribp++;

	} /* end of while loop */

	/* Free LDAP result */
	ldapInfo->LDAPFunctions->msgfree(result);

	/* If the list is empty, then return SRL_NOT_FOUND */
	if (*acs == NULL)
		return SRL_NOT_FOUND;
	else
		return SRL_SUCCESS;

} /* end of SRLi_GetLDAPADCAttributes() */

/* Routine to get the LDAP Returned SPIFs */
short SRLi_GetLDAPSPIFAttributes (ulong sessionID, LDAPInfo_struct *ldapInfo,
							 int typeMask, LDAPMessage *result, EncObject_LL **acs)
{
	short err = 0;
	struct berval **encValues;
	int x, numValues;
	char **attribp;


	if (ldapInfo->LDAPFunctions->count_entries == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->msgfree == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->get_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->count_values_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (ldapInfo->LDAPFunctions->value_free_len == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);


	if (ldapInfo->LDAPFunctions->count_entries(ldapInfo->ldapIDinfo->ldapID, result) != 1)
	{
		ldapInfo->LDAPFunctions->msgfree(result);
		return SRL_LDAP_SEARCH_FAILED;
	}

	/* For each SPIFs returned from the LDAP server,
	get the attribute's values and copy them to the encoded cert linked 
	list. */
	attribp = spifAttribs;
	while (*attribp != NULL)
	{
		/* Pull out the values for this attribute type from the LDAP Read 
		result */
		encValues = ldapInfo->LDAPFunctions->get_values_len(ldapInfo->ldapIDinfo->ldapID, result, 
			*attribp);

		
		/* For each value of this attribute type... */
		numValues = ldapInfo->LDAPFunctions->count_values_len(encValues);
		for (x = 0; x < numValues; x++)
		{
			/* Check that the values really exist
			(Note:  This check shouldn't be needed -- it was added in case
			count_values_len returned an incorrect positive number.) */
			if (encValues == NULL)
				break;
			if (typeMask & SPIF_TYPE)
			{
				/* Call the appropriate low-level function to add the certificate 
					pair or single certificate to the list. */
				if (strncmp(*attribp, "spif", 4) == 0)
				{
					/* Add it to our Object List, also add SPIF_TYPE */
					err = addCert2List(sessionID, encValues[x], SPIF_TYPE, acs);
					
				}

			}
			if (err != SRL_SUCCESS)
			{
				ldapInfo->LDAPFunctions->value_free_len(encValues);

				ldapInfo->LDAPFunctions->msgfree(result);
				return err;
			}
		} /* end of for loop */ 

		/* Free the values for this attribute */
		ldapInfo->LDAPFunctions->value_free_len(encValues);
		attribp++;

	} /* end of while loop */

	/* Free LDAP result */
	ldapInfo->LDAPFunctions->msgfree(result);

	/* If the list is empty, then return SRL_NOT_FOUND */
	if (*acs == NULL)
		return SRL_NOT_FOUND;
	else
		return SRL_SUCCESS;

} /* end of SRLi_GetLDAPSPIFAttributes() */

/* ----------------- */
/* SRLi_LdapConnect() */
/* ----------------- */
short SRLi_LdapConnect(LDAPInfo_struct *f)
{
	short err;
	/* Check parameter */
	if (f == NULL)
		return SRL_NULL_POINTER;

	/* Check that the LDAP library was properly initialized */
	if (f->ldapIDinfo->ldapID == NULL)
		return SRL_LDAP_UNAVAILABLE;

	/* Bind anonymously to the server */
	if (f->LDAPFunctions->simple_bind == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);

	SRLi_LDAPBind(f); // Errors are reported in threaderror variable

	err = threaderror;
	if ((err == LDAP_CONNECT_ERROR) || (err == LDAP_SERVER_DOWN) ||
		(err == LDAP_BUSY) || (err == LDAP_UNAVAILABLE))
		return SRL_LDAP_CONNECTION_FAILED;
	else if (err != LDAP_SUCCESS)
		return SRL_LDAP_BIND_FAILED;
	else if (err == SRL_LDAP_UNAVAILABLE)
		return err;
	else
		return SRL_SUCCESS;

}

void SRLi_LDAPBind(LDAPInfo_struct *f)
{
	int err = 0;
	struct timeval tv;
	LDAPMessage* result = NULL;
	int msgid = 0;

	msgid = f->LDAPFunctions->simple_bind(f->ldapIDinfo->ldapID, NULL, NULL);
	if (msgid != -1)
	{
		err = 0;
		if (f->timeout > 0)
			tv.tv_sec = f->timeout;
		else
			tv.tv_sec = LDAP_DEFAULT_TIMEOUT;

		tv.tv_usec = 0;

		err = f->LDAPFunctions->result(f->ldapIDinfo->ldapID, msgid, 0, &tv, &result);		
		
		if(result != NULL)
			f->LDAPFunctions->msgfree(result);
		if((err == 0 || err == -1))
		{
			if (f->LDAPFunctions->abandon)
				err = f->LDAPFunctions->abandon(f->ldapIDinfo->ldapID, msgid);
			threaderror = SRL_LDAP_UNAVAILABLE;
		}
	}
	else
	{
		threaderror = SRL_LDAP_UNAVAILABLE;
	}	
}

/* ----------------- */
/* SRLi_LdapInit() */
/* ----------------- */
LDAP *SRLi_LdapInit(LDAPInfo_struct *f)
{
	/* Check parameter */
	if (f == NULL)
		return NULL;
	if (f->LDAPFunctions->init == NULL)
		return (NULL);
	/* Initialize the LDAP library */
	f->ldapIDinfo->ldapID = f->LDAPFunctions->init((const char *)(f->LDAPServerInfo->LDAPserver), f->LDAPServerInfo->LDAPport);

	if (f->ldapIDinfo->ldapID != NULL)
	{
		// The ldap set_option is optional
		if (f->LDAPFunctions->set_option != NULL)
      {
         /* Set the version */
         int version = LDAP_VERSION3;
         f->LDAPFunctions->set_option(f->ldapIDinfo->ldapID, LDAP_OPT_PROTOCOL_VERSION, &version);

			/* Set the referral option */
			f->LDAPFunctions->set_option(f->ldapIDinfo->ldapID, LDAP_OPT_REFERRALS, LDAP_OPT_ON);
      }

		/* Enable caching of LDAP results 
		{FUTURE} -- need support of Netscape LDAP library
		*/
	}
	return f->ldapIDinfo->ldapID;

} /* end of SRLi_LdapInit() */


/* -------------- */
/* SRLi_LdapRead() */
/* -------------- */
short SRLi_LdapRead(ulong sessionID, LDAPInfo_struct *f, LDAP *ldapID, char *dn,
				   char *attrs[], LDAPMessage **result)
{
	int err;
	int msgid = 0;
	struct timeval tv;
	SRLSession_struct *sessionInfo;
	LDAPInfo_struct *LDAPTemp = NULL;
	LDAP *ldapIDTemp = NULL;
	LDAPMessage *pResult = NULL;
	/* Check parameters (these should never be NULL, but attrs can be) */
	if ((dn == NULL) || (result == NULL))
		return SRL_NULL_POINTER;
	/* Initialize the results pointer */
	*result = NULL;

	/* Check for a valid session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	/* Check that LDAP support was requested for this session (check the 
	useLDAP flag in the session_struct) */
	if ((err = SRLi_GetRetSessionFromRef(&sessionInfo, sessionID)) != SRL_SUCCESS)
		return ((short)err);

	if (sessionInfo->ldapInfo == NULL)
		return SRL_LDAP_UNAVAILABLE;

	if (f == NULL)
	{
		// Get LDAP info from Session reference
		LDAPTemp = sessionInfo->ldapInfo;
		if (LDAPTemp == NULL)
			return SRL_LDAP_UNAVAILABLE;
		ldapIDTemp = sessionInfo->ldapInfo->ldapIDinfo->ldapID;
		if (ldapID == NULL)
			return SRL_LDAP_UNAVAILABLE;
	}
	else
	{
		    // Just point to the LDAP information
			ldapIDTemp = ldapID;
			LDAPTemp = f;
			if (LDAPTemp == NULL)
				return SRL_LDAP_UNAVAILABLE;
	}


	/* Check that the LDAP library was properly initialized */
	if (ldapIDTemp == NULL)
		return SRL_LDAP_UNAVAILABLE;
	if (LDAPTemp->LDAPFunctions->search == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	if (LDAPTemp->LDAPFunctions->unbind == NULL)
		return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	/* Search for the entry and retrieve the selected attributes. */
	msgid = LDAPTemp->LDAPFunctions->search(ldapIDTemp, dn, LDAP_SCOPE_BASE, 
		"(objectclass=*)", attrs, FALSE);

	// Now get try to get the results
	if (LDAPTemp->timeout > 0)
		tv.tv_sec = LDAPTemp->timeout;
	else
		tv.tv_sec = LDAP_DEFAULT_TIMEOUT;

	tv.tv_usec = 0;

	err = LDAPTemp->LDAPFunctions->result( ldapIDTemp, msgid, 
												TRUE, &tv, &pResult);

	if ((err == -1) || ((err == 0) && (pResult == NULL))) 
		return SRL_LDAP_SEARCH_FAILED;

	// Check for LDAP Errors
	err = LDAPTemp->LDAPFunctions->result2error(ldapIDTemp, pResult, FALSE);

	if (err == LDAP_SERVER_DOWN)
	{
		if (LDAPTemp->ldapIDinfo->internal == TRUE)
		{
			/* This error occurs when the LDAP server is no longer up, but it
			once was.  The Netscape LDAP library v1.1 does not try to re-connect
			once this error is encountered.  So, this library will unbind from
			the server and re-initialize the conntection */
			LDAPTemp->LDAPFunctions->unbind(ldapID);

			LDAPTemp->ldapIDinfo->ldapID = SRLi_LdapInit(f);
		}
		return SRL_LDAP_CONNECTION_FAILED;
	}
	else if ((err == LDAP_OPERATIONS_ERROR) || (err == LDAP_REFERRAL))
	{
		if (LDAPTemp->ldapIDinfo->internal == TRUE)
		{

		/* These errors may occur when the client library has not yet bound
		to the LDAP server.  So when encountered, this library will re-bind to 
		the server and try the search again.
		Note: Referral error can occur if the server wants to pass a referral
		to the client, but the client hasn't bound yet. */
		err = SRLi_LdapConnect(f);
		if (err != SRL_SUCCESS)
			return ((short)err);
		
		/* Search for the entry and retrieve the selected attributes. */
		msgid = LDAPTemp->LDAPFunctions->search(ldapIDTemp, dn, LDAP_SCOPE_BASE, 
												"(objectclass=*)", attrs, FALSE);

		// Now get try to get the results
		err = LDAPTemp->LDAPFunctions->result( ldapIDTemp, msgid, 
												TRUE, &tv, &pResult);

		if (err == -1)
			return SRL_LDAP_SEARCH_FAILED;

		// Check for LDAP Errors
		err = LDAPTemp->LDAPFunctions->result2error(ldapIDTemp, pResult, FALSE);

		
		
		if (err != LDAP_SUCCESS)
			return SRL_LDAP_SEARCH_FAILED;
		}
		return SRL_LDAP_SEARCH_FAILED;
	}
	else if ((err == LDAP_CONNECT_ERROR) || (err == LDAP_BUSY) || 
		(err == LDAP_UNAVAILABLE))
		return SRL_LDAP_CONNECTION_FAILED;
	else if ((err == LDAP_STRONG_AUTH_REQUIRED) || (err == LDAP_AUTH_UNKNOWN) ||
		(err == LDAP_INAPPROPRIATE_AUTH) || (err == LDAP_INVALID_CREDENTIALS))
		return SRL_LDAP_BIND_FAILED;
	else if (err != LDAP_SUCCESS)
		return SRL_LDAP_SEARCH_FAILED;
	// Point to the results
	*result = pResult;
	return SRL_SUCCESS;

} /* end of SRLi_LdapRead() */

short SRLi_LdapURLRead(ulong sessionID, SRL_URLDescriptor_struct *inDesc,
					   LDAPInfo_struct *ldapInfo, int typeMask,
					   AsnTypeFlag objType, EncObject_LL **result)

{

	int err;
	int msgid = 0;
	struct timeval tv;
	LDAPMessage *pResult = NULL;

	LDAPInfo_struct URLldapInfo;
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	 /* initialize LDAP library and connect */
	 if (ldapInfo->LDAPFunctions->unbind == NULL)
		 return (SRL_LDAP_FUNCTION_NOT_SPECIFIED);
	 URLldapInfo.ldapIDinfo = (LDAPIdInfo_struct *)calloc(1, sizeof(LDAPIdInfo_struct));
	 if (URLldapInfo.ldapIDinfo == NULL)
	 {
		free (URLldapInfo.ldapIDinfo);
		 return (SRL_MEMORY_ERROR);
	 }


	// Fill in some of the LDAP information
	URLldapInfo.LDAPFunctions = ldapInfo->LDAPFunctions;
	URLldapInfo.ldapIDinfo->internal = TRUE;
	URLldapInfo.LDAPServerInfo = (LDAPServerInfo_struct *)calloc(1, 
									sizeof (LDAPServerInfo_struct));
	URLldapInfo.SharedLibraryName = ldapInfo->SharedLibraryName;
	URLldapInfo.LDAPFunctions = ldapInfo->LDAPFunctions;
	/* Bind to the LDAP server */
	if (inDesc->hostname[0] == 0)
	{
		// Set up this session's server (RFC 2255)
		if (ldapInfo->LDAPServerInfo->LDAPserver == NULL)
		{
			// error out
			free (inDesc->hostname);
			free (URLldapInfo.ldapIDinfo);
			free (URLldapInfo.LDAPServerInfo);
			return SRL_LDAP_UNAVAILABLE;
		}
		else
		{
			// Load in the default server
			URLldapInfo.LDAPServerInfo->LDAPserver =
				ldapInfo->LDAPServerInfo->LDAPserver;
		}
	}
	else
		URLldapInfo.LDAPServerInfo->LDAPserver = (char *)inDesc->hostname;


	URLldapInfo.LDAPServerInfo->LDAPport = inDesc->port;
	URLldapInfo.ldapIDinfo->ldapID = SRLi_LdapInit(&URLldapInfo);
	 if (URLldapInfo.ldapIDinfo->ldapID == NULL)
	 {
			free (URLldapInfo.ldapIDinfo);
			return(SRL_LDAP_INIT_FAILED);
	 }

	URLldapInfo.timeout = ldapInfo->timeout;

	err = SRLi_LdapConnect(&URLldapInfo);
	if (err != SRL_SUCCESS)
	{
		URLldapInfo.LDAPFunctions->unbind(URLldapInfo.ldapIDinfo->ldapID);
		free (URLldapInfo.ldapIDinfo);
		free (URLldapInfo.LDAPServerInfo);
		return ((short)err);
	}


	/* Search for the entry and retrieve the selected attributes. */
	msgid = URLldapInfo.LDAPFunctions->search(URLldapInfo.ldapIDinfo->ldapID,
										inDesc->URL_DN,
										inDesc->scope,
										(const char*)inDesc->filter,
										inDesc->attributes, FALSE);

	// Now get try to get the results
	if (URLldapInfo.timeout > 0)
		tv.tv_sec = URLldapInfo.timeout;
	else
		tv.tv_sec = LDAP_DEFAULT_TIMEOUT;
		
	tv.tv_usec = 0;

	err = URLldapInfo.LDAPFunctions->result(URLldapInfo.ldapIDinfo->ldapID, msgid, 
												TRUE, &tv, &pResult);

	if (err == -1)
	{
		free (URLldapInfo.LDAPServerInfo);
		free (URLldapInfo.ldapIDinfo);
		return SRL_LDAP_SEARCH_FAILED;
	}

	// Check for LDAP Errors
	err = URLldapInfo.LDAPFunctions->result2error(URLldapInfo.ldapIDinfo->ldapID, pResult, FALSE);


	if (err == LDAP_SERVER_DOWN)
	{
		/* This error occurs when the LDAP server is no longer up, but it
		once was.  The Netscape LDAP library v1.1 does not try to re-connect
		once this error is encountered.  So, this library will unbind from
		the server and re-initialize the conntection */
		
		URLldapInfo.LDAPFunctions->unbind(URLldapInfo.ldapIDinfo->ldapID);
		free (URLldapInfo.LDAPServerInfo);
		free (URLldapInfo.ldapIDinfo);
		return SRL_LDAP_CONNECTION_FAILED;
	}
	else if ((err == LDAP_OPERATIONS_ERROR) || (err == LDAP_REFERRAL))
	{
		/* These errors may occur when the client library has not yet bound
		to the LDAP server.  So when encountered, this library will re-bind to 
		the server and try the search again.
		Note: Referral error can occur if the server wants to pass a referral
		to the client, but the client hasn't bound yet. */
		URLldapInfo.LDAPFunctions->unbind(URLldapInfo.ldapIDinfo->ldapID);

		err = SRLi_LdapConnect(&URLldapInfo);
		if (err != SRL_SUCCESS)
		{
			URLldapInfo.LDAPFunctions->unbind(URLldapInfo.ldapIDinfo->ldapID);
			free (URLldapInfo.ldapIDinfo);
			free (URLldapInfo.LDAPServerInfo);
			return ((short)err);
		}
		
		err = URLldapInfo.LDAPFunctions->search(URLldapInfo.ldapIDinfo->ldapID,
												inDesc->URL_DN,
												inDesc->scope,
												(const char *)inDesc->filter,
												inDesc->attributes,
												FALSE);
		if (err != LDAP_SUCCESS)
		{
			URLldapInfo.LDAPFunctions->unbind(URLldapInfo.ldapIDinfo->ldapID);
			free (URLldapInfo.ldapIDinfo);
			free (URLldapInfo.LDAPServerInfo);
			return SRL_LDAP_SEARCH_FAILED;
		}
	}
	else if ((err == LDAP_CONNECT_ERROR) || (err == LDAP_BUSY) || 
		(err == LDAP_UNAVAILABLE))
	{
		URLldapInfo.LDAPFunctions->unbind(URLldapInfo.ldapIDinfo->ldapID);
		free (URLldapInfo.ldapIDinfo);
		free (URLldapInfo.LDAPServerInfo);
		return SRL_LDAP_CONNECTION_FAILED;
	}

	if (objType == SRL_CERT_TYPE)
		err = SRLi_GetLDAPCertAttributes (sessionID, &URLldapInfo, 
			                             typeMask, 
										 pResult, result);
	else if (objType == SRL_CRL_TYPE)

		err = SRLi_GetLDAPCRLAttributes (sessionID, &URLldapInfo, typeMask, pResult, result);


	URLldapInfo.LDAPFunctions->unbind(URLldapInfo.ldapIDinfo->ldapID);
	free (URLldapInfo.ldapIDinfo);
	free (URLldapInfo.LDAPServerInfo);
	return (short)err;
}

static short SRLi_FTPURLRead(ulong sessionID, SRL_URLDescriptor_struct *inDesc,
					 EncObject_LL **result)
{
	netbuf *FTPBuf = NULL;
	Bytes_struct theData;
	EncObject_LL *object = NULL;
	char mode = 'I';
	short ftp_status = 0;

	sessionID = sessionID;
	theData.data = NULL;
	theData.num = 0;

	if (!Ftp_Connect((const char *)inDesc->hostname, inDesc->port, &FTPBuf))
		return SRL_TCP_CONNECTION_FAILED;
	
	// Login to FTP anonymously
	if (!Ftp_Login("anonymous", "joesmith@js.com", FTPBuf))
		return SRL_INVALID_PARAMETER;

	// The URL_DN for FTP contains the path to get.
	ftp_status = Ftp_Get(inDesc->URL_DN, mode, FTPBuf, &theData);
	if (ftp_status == SRL_SUCCESS)
	{
		// Add it to the encoded object
		object = (EncObject_LL *)calloc (1, sizeof (EncObject_LL));
		if (object == NULL) {
			Ftp_Quit(FTPBuf);
			return SRL_MEMORY_ERROR;
		}
		object->encObj.data = theData.data;
		object->encObj.num = theData.num;
		object->locMask = SERVER_LOC;
	}
	else  // Retrieval failed
	{
		if (theData.data)
			free (theData.data);
		return ftp_status;
	}
	Ftp_Quit(FTPBuf);
	*result = object;
	return SRL_SUCCESS;

}


// SRLi_HTTPURLRead
//
// returns SRL_SUCCESS if URL was retrieved.
//         SRL_NOT_FOUND if URL wasn't found
//        

static short SRLi_HTTPURLRead(ulong sessionID, SRL_URLDescriptor_struct *inDesc,
					 EncObject_LL **result)
{

	Bytes_struct	theData;
	EncObject_LL	*object = NULL;
	int				http_sock;
	short			err;

	sessionID = sessionID;

	theData.data = NULL;
	theData.num = 0;

	if ((http_sock = Http_Connect((const char *)inDesc->hostname, inDesc->port)) == 0)
		return SRL_TCP_CONNECTION_FAILED;

	// Call HTTP Get to fill the buffer

	// The URL_DN for HTTP contains the path to get.
	if ((err = Http_Get((const char *)inDesc->hostname, inDesc->URL_DN, &theData, http_sock)) == SRL_SUCCESS)
	{
		// Add it to the encoded object
		object = (EncObject_LL *)calloc (1, sizeof (EncObject_LL));
		if (object == NULL)
			return SRL_MEMORY_ERROR;
		object->encObj.data = theData.data;
		object->encObj.num = theData.num;
		object->locMask = SERVER_LOC;
	}
	else
	{
		if (theData.data)
			free (theData.data);
	}

	Http_Quit(http_sock);
	*result = object;
	return err;

}



/* --------------- */
/* SRLi_Link2LDAP() */
/* --------------- */
short SRLi_Link2LDAP(LDAPInfo_struct *f)
{
#ifdef macintosh

	/* since we weak linked against the ldap lib, attempt to acertain
	 * as to whether or not the ldap DLL/shared lib code fragment is
	 * available.
	 */
	if((void *)ldap_init == (void *)kUnresolvedCFragSymbolAddress)
		return(SRL_LDAP_LOAD_FAILED);

	/*f->open = ldap_open; */
	f->LDAPFunctions->init = ldap_init;
	f->LDAPFunctions->set_option = ldap_set_option;
	f->LDAPFunctions->first_entry = ldap_first_entry;
	f->LDAPFunctions->next_entry = ldap_next_entry;
	f->LDAPFunctions->count_entries = ldap_count_entries;
	f->LDAPFunctions->get_values_len = ldap_get_values_len;
	f->LDAPFunctions->count_values_len = ldap_count_values_len;
	f->LDAPFunctions->value_free_len = ldap_value_free_len;
	f->LDAPFunctions->msgfree = ldap_msgfree;
	f->LDAPFunctions->search = ldap_search;
	f->LDAPFunctions->unbind = ldap_unbind;
	f->LDAPFunctions->result = ldap_result;
	f->LDAPFunctions->simple_bind = ldap_simple_bind;
	f->LDAPFunctions->abandon = ldap_abandon;
	f->LDAPFunctions->result2error = ldap_result2error;
	/* will fix this later - for now just check to see if the functions
	 * were resolved...
	 */
	if(f->init != NULL)
		return SRL_SUCCESS;
	else
		return SRL_LDAP_LOAD_FAILED;
		
#elif defined(LDAP32_DYNAMIC_BIND)	 /* windows LDAP32_DYNAMIC_BIND */
#if defined (_WINDOWS) || defined (WIN32)
	HINSTANCE hDLL;
#elif defined (SunOS) || defined (Linux) || defined (SCO_SV) || defined (HPUX)
	void *hDLL;
#elif defined (HPUX32)
    shl_t hDLL;
#endif

#if defined (_WINDOWS) || defined (WIN32)
	hDLL = LoadLibrary(f->SharedLibraryName);
#elif defined (SunOS) || defined (Linux) || defined (SCO_SV) || defined (HPUX)
	hDLL = dlopen(f->SharedLibraryName, RTLD_NOW);
#elif defined(HPUX32)
    hDLL = shl_load(f->SharedLibraryName, BIND_IMMEDIATE | DYNAMIC_PATH, 0L);
#endif
	if (hDLL != NULL)
	{
		if (f->LDAPFunctions == NULL)
			f->LDAPFunctions = (LDAPFuncPtr_struct *)calloc (1, sizeof (LDAPFuncPtr_struct));


#if defined(_WINDOWS) || defined (WIN32)

		f->LDAPFunctions->init = (SRL_LDAP_initFp)GetProcAddress(hDLL, "ldap_init");
		f->LDAPFunctions->set_option = (SRL_LDAP_setOptionFp)GetProcAddress(hDLL, 
			"ldap_set_option");
		f->LDAPFunctions->simple_bind = (SRL_LDAP_simpleBindFp)GetProcAddress(hDLL, 
			"ldap_simple_bind");
		f->LDAPFunctions->first_entry = (SRL_LDAP_firstEntryFp)GetProcAddress(hDLL, 
			"ldap_first_entry");
		f->LDAPFunctions->next_entry = (SRL_LDAP_nextEntryFp)GetProcAddress(hDLL, 
			"ldap_next_entry");
		f->LDAPFunctions->count_entries = (SRL_LDAP_countEntriesFp)GetProcAddress(hDLL, 
			"ldap_count_entries");
		f->LDAPFunctions->get_values_len = (SRL_LDAP_getValuesLenFp)GetProcAddress(hDLL, 
			"ldap_get_values_len");
		f->LDAPFunctions->count_values_len = (SRL_LDAP_countValuesLenFp)GetProcAddress(hDLL, 
			"ldap_count_values_len");
		f->LDAPFunctions->value_free_len = (SRL_LDAP_valueFreeLenFp)GetProcAddress(hDLL, 
			"ldap_value_free_len");
		f->LDAPFunctions->msgfree = (SRL_LDAP_msgfreeFp)GetProcAddress(hDLL, "ldap_msgfree");
		f->LDAPFunctions->search = (SRL_LDAP_searchFp)GetProcAddress(hDLL, 
			"ldap_search");
		f->LDAPFunctions->unbind = (SRL_LDAP_unbindFp)GetProcAddress(hDLL, "ldap_unbind");
		f->LDAPFunctions->abandon = (SRL_LDAP_abandonFp)GetProcAddress(hDLL, "ldap_abandon");
		f->LDAPFunctions->result = (SRL_LDAP_resultFp)GetProcAddress(hDLL, "ldap_result");
		f->LDAPFunctions->result2error = (SRL_LDAP_result2errorFp)GetProcAddress(hDLL, "ldap_result2error");

#elif defined (HPUX32)
             
		shl_findsym(&hDLL,"ldap_unbind", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->unbind);
		shl_findsym(&hDLL, "ldap_init", TYPE_PROCEDURE,
                  (void *) &f->LDAPFunctions->init);
		shl_findsym(&hDLL, "ldap_set_option", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->set_option);
		shl_findsym(&hDLL, "ldap_simple_bind", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->simple_bind);
		shl_findsym(&hDLL, "ldap_first_entry", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->first_entry);
		shl_findsym(&hDLL, "ldap_next_entry", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->next_entry);
		shl_findsym(&hDLL, "ldap_count_entries", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->count_entries);

		shl_findsym(&hDLL, "ldap_get_values_len", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->get_values_len);

		shl_findsym(&hDLL, "ldap_value_free_len", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->value_free_len);

		shl_findsym(&hDLL, "ldap_msgfree", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->msgfree);

		shl_findsym(&hDLL, "ldap_search", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->search);

		shl_findsym(&hDLL, "ldap_unbind", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->unbind);

		shl_findsym(&hDLL, "ldap_abandon", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->abandon);

		shl_findsym(&hDLL, "ldap_result", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->result);

		shl_findsym(&hDLL, "ldap_result2error", TYPE_PROCEDURE, 
                  (void *) &f->LDAPFunctions->result2error);
#else


		f->LDAPFunctions->init = (SRL_LDAP_initFp)dlsym(hDLL, "ldap_init");
		f->LDAPFunctions->set_option = (SRL_LDAP_setOptionFp)dlsym(hDLL, 
			"ldap_set_option");
		f->LDAPFunctions->simple_bind = (SRL_LDAP_simpleBindFp)dlsym(hDLL, 
			"ldap_simple_bind");
		f->LDAPFunctions->first_entry = (SRL_LDAP_firstEntryFp)dlsym(hDLL, 
			"ldap_first_entry");
		f->LDAPFunctions->next_entry = (SRL_LDAP_nextEntryFp)dlsym(hDLL, 
			"ldap_next_entry");
		f->LDAPFunctions->count_entries = (SRL_LDAP_countEntriesFp)dlsym(hDLL, 
			"ldap_count_entries");
		f->LDAPFunctions->get_values_len = (SRL_LDAP_getValuesLenFp)dlsym(hDLL, 
			"ldap_get_values_len");
		f->LDAPFunctions->count_values_len = (SRL_LDAP_countValuesLenFp)dlsym(hDLL, 
			"ldap_count_values_len");
		f->LDAPFunctions->value_free_len = (SRL_LDAP_valueFreeLenFp)dlsym(hDLL, 
			"ldap_value_free_len");
		f->LDAPFunctions->msgfree = (SRL_LDAP_msgfreeFp)dlsym(hDLL, "ldap_msgfree");
		f->LDAPFunctions->search = (SRL_LDAP_searchFp)dlsym(hDLL, 
			"ldap_search");
		f->LDAPFunctions->unbind = (SRL_LDAP_unbindFp)dlsym(hDLL, "ldap_unbind");
		f->LDAPFunctions->abandon = (SRL_LDAP_abandonFp)dlsym(hDLL, "ldap_abandon");
		f->LDAPFunctions->result = (SRL_LDAP_resultFp)dlsym(hDLL, "ldap_result");
		f->LDAPFunctions->result2error = (SRL_LDAP_result2errorFp)dlsym(hDLL, "ldap_result2error");

#endif /* SunOS  & Windows dynamic loading of symbols */
		if ((f->LDAPFunctions->init == NULL) || (f->LDAPFunctions->simple_bind == NULL) || 
			(f->LDAPFunctions->first_entry == NULL) || (f->LDAPFunctions->next_entry == NULL) ||
			(f->LDAPFunctions->count_entries == NULL) || (f->LDAPFunctions->get_values_len == NULL) ||
			(f->LDAPFunctions->count_values_len == NULL) || (f->LDAPFunctions->value_free_len == NULL) ||
			(f->LDAPFunctions->msgfree == NULL) || (f->LDAPFunctions->search == NULL) ||
			(f->LDAPFunctions->abandon == NULL) || (f->LDAPFunctions->result == NULL) ||
			(f->LDAPFunctions->result2error == NULL))

		{
			FreeLibrary(hDLL);
			return SRL_LDAP_LOAD_FAILED;
		}

		f->ldaplibHandle = hDLL;
		f->LDAPFunctions->StructVersion = SRL_LDAP_FUNC_VER;
		return SRL_SUCCESS;
	}
	else
		return SRL_LDAP_LOAD_FAILED;
 /* end of windows LDAP32_DYNAMIC_BIND */
 
#else
  int hDLL = 1; // Just for placement
	if (f->LDAPFunctions == NULL)
		f->LDAPFunctions = (LDAPFuncPtr_struct *)calloc (1, sizeof (LDAPFuncPtr_struct));
	f->LDAPFunctions->init = ldap_init;
	f->LDAPFunctions->set_option = ldap_set_option;
	f->LDAPFunctions->simple_bind = ldap_simple_bind;
	f->LDAPFunctions->first_entry = ldap_first_entry;
	f->LDAPFunctions->next_entry = ldap_next_entry;
	f->LDAPFunctions->count_entries = ldap_count_entries;
	f->LDAPFunctions->get_values_len = ldap_get_values_len;
	f->LDAPFunctions->count_values_len = ldap_count_values_len;
	f->LDAPFunctions->value_free_len = ldap_value_free_len;
	f->LDAPFunctions->msgfree = ldap_msgfree;
	f->LDAPFunctions->search = ldap_search;
	f->LDAPFunctions->unbind = ldap_unbind;
	f->LDAPFunctions->abandon = ldap_abandon;
	f->LDAPFunctions->result = ldap_result;
	f->LDAPFunctions->result2error = ldap_result2error;
	/* will fix this later - for now just check to see if the functions
	 * were resolved...
	 */
	if ((f->LDAPFunctions->init == NULL) || (f->LDAPFunctions->simple_bind == NULL) || 
		(f->LDAPFunctions->first_entry == NULL) || (f->LDAPFunctions->next_entry == NULL) ||
		(f->LDAPFunctions->count_entries == NULL) || (f->LDAPFunctions->get_values_len == NULL) ||
		(f->LDAPFunctions->count_values_len == NULL) || (f->LDAPFunctions->value_free_len == NULL) ||
		(f->LDAPFunctions->msgfree == NULL) || (f->LDAPFunctions->search == NULL) ||
		(f->LDAPFunctions->unbind == NULL) || 
		(f->LDAPFunctions->abandon == NULL) || (f->LDAPFunctions->result == NULL) ||
		(f->LDAPFunctions->result2error == NULL))
		return SRL_LDAP_LOAD_FAILED;
	else
	{
		f->ldaplibHandle = hDLL;
		return SRL_SUCCESS;
	}
		

#endif		/* end of platform specific ldap sharedlib / DLL resolving code */
} /* end of SRLi_Link2LDAP() */



/* ------------------- */
/* Low-level functions */
/* ------------------- */

static short addCert2List(ulong sessionID, struct berval *valp, int typeMask,
						  EncObject_LL **list)
{
	Bytes_struct *certp;
	EncObject_LL *tmpLink;
	short		err;
	
	/* Check session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	/* Check list parameter (should never be NULL) */
	if (list == NULL)
		return SRL_NULL_POINTER;

	if ((valp == NULL) || (valp->bv_len < 6))		/* Nothing to add */
		return SRL_SUCCESS;
	/* go prep the data (see if ascii or bin format we recognize)*/
	err = prepData(valp, &certp);
	if(err != SRL_SUCCESS)
		SRLi_FreeObjList(list);
	if(certp->data == NULL)
		return err;	/* no err  data not avail, or some error */
	

	/* Create a new link in the list, copy the pointer (data was copied 
	above), and add the new link to the top of the list. */
	tmpLink = (EncObject_LL *)malloc(sizeof(EncObject_LL));
	if (tmpLink == NULL)
	{
		free(certp->data);
		SRLi_FreeObjList(list);
		return SRL_MEMORY_ERROR;
	}
	tmpLink->encObj.data = certp->data;
	tmpLink->encObj.num = certp->num;
	tmpLink->locMask = DSA_LOC;
	tmpLink->typeMask = typeMask;
	
	tmpLink->next = *list;
	*list = tmpLink;
    free(certp);
	return SRL_SUCCESS;

} /* end of addCert2List() */


//old function define
// static short addCertPair2List(ulong sessionID, struct berval *valp,
//							  int typeMask, EncObject_LL **list)
short addCertPair2List(ulong sessionID, Bytes_struct *valp,
							  EncObject_LL **list)

{
	SRL_CertList *pairList, *pptr;
	ulong			declen, numBytes;
	EncObject_LL 		*tmpLink;
	uchar			*certp;
	short			err;	
	Bytes_struct	*adata = NULL;
	
	pairList = NULL;
	declen = 0;
	certp = 0;
	
	/* check for no data passed */
	if(valp == NULL)	return(SRL_SUCCESS);
	if(valp->data == NULL || valp->num < 6) return(SRL_SUCCESS);
	
	/* go prep the data (see if ascii or bin format we recognize) */
	err = prepData((struct berval *)valp, &adata);
	if(err != SRL_SUCCESS)
		SRLi_FreeObjList(list);
	if(adata->data == NULL)
		return err;	/* no err  data not avail, or some error */
		
	/* go split up the pair */
	err = SRLi_BreakUpCertPair(adata->data, adata->num, 
		&declen, &pairList);
		
	
	if((err != SRL_SUCCESS) ||	/* check result of cert pair splitting */
		(pairList == NULL)) /* nothing found */
	{
		free(adata->data);	/* no longer need this */
		return(err);
	}
	
		
	/* have a linked list of ptr's to the asn1 data for each cert of the
	 * pair. Add what ever came out of the splitting call for now.
	 */
	while(pairList->asn1cert != NULL)	/* have ptr */
	{

		tmpLink = (EncObject_LL *)calloc(1,sizeof(EncObject_LL));
		if (tmpLink == NULL)
		{
			SRLi_FreeObjList(list);
			SRLi_FreeBrokenCertList(sessionID, &pairList);
			return SRL_MEMORY_ERROR;
		}
		SRLi_AsnGetLength(pairList->asn1cert, &numBytes);
		tmpLink->encObj.data = (unsigned char *)calloc(1,numBytes);
		tmpLink->encObj.num = numBytes;
		tmpLink->locMask = DSA_LOC;
		tmpLink->typeMask = CROSS_CERT_TYPE;
		memcpy(tmpLink->encObj.data, pairList->asn1cert, numBytes);
		
		tmpLink->next = *list;
		*list = tmpLink;
		
		pptr = pairList->next;
		free(pairList);
		pairList = pptr;
		if(pairList == NULL)	break;	/* all done */
	}
	
	if(adata->data != NULL)
	{
		free(adata->data);
		free(adata);
	}
	return SRL_SUCCESS;
} /* end of addCertPair2List() */


static short addCRL2List(ulong sessionID, struct berval *valp, int typeMask,
						 EncObject_LL **list)
{
	EncObject_LL *tmpLink;
	Bytes_struct	*cdata = NULL;
	short			err;
	
	/* Check session handle */
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	/* Check list parameter (should never be NULL) */
	if (list == NULL)
		return SRL_NULL_POINTER;

	if ((valp == NULL) || (valp->bv_len < 6))		/* Nothing to add */
		return SRL_SUCCESS;

	/* go prep the data (see if ascii or bin format we recognize)*/
	err = prepData(valp, &cdata);
	if(err != SRL_SUCCESS)
		SRLi_FreeObjList( list);
		
	if(cdata->data == NULL)
		return err;	/* no err  data not avail, or some error */
		

	/* Create a new link in the list, copy the pointer (data was copied 
	above), and add the new link to the top of the list. */
	tmpLink = (EncObject_LL *)calloc(1, sizeof(EncObject_LL));
	if (tmpLink == NULL)
	{
		SRLi_FreeBytes(cdata);
		SRLi_FreeObjList( list);
		return SRL_MEMORY_ERROR;
	}
	tmpLink->encObj.data = cdata->data;
	tmpLink->encObj.num = cdata->num;
	tmpLink->locMask = DSA_LOC;
	tmpLink->typeMask = typeMask;
	tmpLink->next = *list;
	*list = tmpLink;
    free(cdata);

	return SRL_SUCCESS;

} /* end of addCRL2List() */


/* given the ldap retrieved data, format it for further use
 * into a bytes_struct.
 */
static short prepData(struct berval *valp, Bytes_struct **odata)
{
Bytes_struct *build_buff = NULL;

	build_buff = calloc (1, sizeof (Bytes_struct));
	/* if it appears to be straight asn.1 encoded, just make
	 * a copy for the caller.
	 */
	if (valp->bv_val[0] == 0x30)
	{
		/* Value starts with a SEQ tag -- probably asn.1 encoded */
		build_buff->data = malloc(valp->bv_len);
		if(build_buff->data == NULL)
			return(SRL_MEMORY_ERROR);
		
		memcpy(build_buff->data, valp->bv_val, valp->bv_len);
		build_buff->num = valp->bv_len;
		*odata = build_buff;
		return(SRL_SUCCESS);
	}
	else if (valp->bv_val[0] == '{')
	{
		/* Value may be an ASCII char string in the form: "{ASN}3082..."
		Skip over the leading {ASN} identifier and convert the hex string
		to binary */
		if ((valp->bv_val[1] == 'A') && (valp->bv_val[2] == 'S') &&
			(valp->bv_val[3] == 'N') && (valp->bv_val[4] == '}'))
		{
			build_buff->data = dupHex2Bin(&valp->bv_val[5], (valp->bv_len - 5));
			if (build_buff->data == NULL)
				return SRL_SUCCESS;
			
			build_buff->num = (valp->bv_len -5) /2 ;
		}
		/* else leave it empty, caller will know no resultant data came out */
		*odata = build_buff;
		return SRL_SUCCESS; /* no err either way */
	}
	else if ((valp->bv_val[0] == '3') && (valp->bv_val[1] == '0'))
	{
		/* Value is probably a hex string, so convert it to binary. */
		build_buff->data = dupHex2Bin(valp->bv_val, valp->bv_len);
		if (build_buff->data == NULL)
			return SRL_SUCCESS;
		build_buff->num = valp->bv_len /2;
	}
		
		/* else The cert is not in a format this function can process, so skip
		it.  The cert may be in the string-encoded format specified in 
		RFC 1778. */
	*odata = build_buff;
	return SRL_SUCCESS;

}

static uchar *dupHex2Bin(char *hex, ulong len)
{
	uchar *bin, 
		  *tmp;
	ulong x;
	
	/* Check if anything to convert */
	if ((hex == NULL) || (len == 0))
		return NULL;

	/* Allocate memory for the resulting binary data */
	if ((bin = (uchar *)malloc(len / 2)) == NULL)
		return NULL;

	tmp = bin;
	/* Convert the hex string to binary */
	for (x = 0; x < (len / 2); x++)
	{
		/* Convert the first character */
		if ((hex[0] >= '0') && (hex[0] <= '9'))
			*tmp = (uchar)((hex[0] - '0') << 4);
		else if ((hex[0] >= 'A') && (hex[0] <= 'F'))
			*tmp = (uchar)((hex[0] - 'A' + 10) << 4);
		else if ((hex[0] >= 'a') && (hex[0] <= 'f'))
			*tmp = (uchar)((hex[0] - 'a' + 10) << 4);
		else	/* invalid character */
		{
			free(bin);
			return NULL;
		}

		/* Convert the second character */
		if ((hex[1] >= '0') && (hex[1] <= '9'))
			*tmp |= (hex[1] - '0');
		else if ((hex[1] >= 'A') && (hex[1] <= 'F'))
			*tmp |= (hex[1] - 'A' + 10);
		else if ((hex[1] >= 'a') && (hex[1] <= 'f'))
			*tmp |= (hex[1] - 'a' + 10);
		else	/* invalid character */
		{
			free(bin);
			return NULL;
		}

		hex += 2;
		tmp++;
	}
	return bin;

} /* end of dupHex2Bin() */



/* used by the cert path code above, this deals with the cert pairs
 * themselves.
 */
short SRLi_BreakUpCertPair(uchar *asndata, ulong elmtLen1, ulong *decodedLen, SRL_CertList **hcpath)
{
    long    seqDone;
    ulong   tagId1, dec_count;
   ulong   certPairSeqLen;
    ulong   totalElmtsLen6;
    ulong   tagId6 = 0;
    ulong   elmtLen6;
    short   pair, err;
   SRL_CertList   *cpath;

    seqDone = FALSE;
    dec_count = 0;
    certPairSeqLen = 0;
   totalElmtsLen6 = 0;
   elmtLen6 = 0;
    
   err = ASN_SRLDecTag(asndata, &dec_count, &tagId1);
   if(err != SRL_SUCCESS)
      goto ErrorExit;

   *decodedLen += dec_count;      /* track what we've processed */
   asndata +=    dec_count;   /* inc ptr past what we've processed */
   dec_count = 0;   /* reset each time */

   if( (tagId1 == EOC_TAG_ID) && (elmtLen1 == INDEFINITE_LEN))
   {
      if(*asndata++ == 0)
      {
         *decodedLen++;   /* read one byte above */
         return(SRL_SUCCESS); /* got EOC so can exit this SET OF/SEQ OF's for loop*/
      }
      else
      {
         /* there should be an empty data element after an
          * EOC tag.  There isn't here, so report the
          * error.
          */
         err = SRL_ASN_ERROR;
         goto ErrorExit;
      }
   }

   if(tagId1 == UNIV_CONS_SEQ_TAG)   /* start of cert pair encoding */
   {
      /* use new len var since we don't want to screw up our while
       * loop's use of elmtLen1
       */
      err = ASN_SRL_DecLen(asndata, &dec_count, &certPairSeqLen);
      if(err != SRL_SUCCESS)
         goto ErrorExit;

        totalElmtsLen6 = 0;
      *decodedLen += dec_count;      /* track what we've processed */
      asndata +=    dec_count;   /* inc ptr past what we've processed */
      dec_count = 0;   /* reset each time */


/* now to handle the pairs of certificate elements */

       if ( (certPairSeqLen != INDEFINITE_LEN) && (totalElmtsLen6 == certPairSeqLen))
           seqDone = TRUE;
       else
       {
          /* the next tag should be either a cntx or eoc tag if no pairs are
           * here, and it was indef encoded.
           */
         err = ASN_SRLDecTag(asndata, &dec_count, &tagId6);
         if(err != SRL_SUCCESS)
            goto ErrorExit;
         totalElmtsLen6 += dec_count;
         asndata += dec_count;
         dec_count = 0;

           if ((certPairSeqLen == INDEFINITE_LEN) && (tagId6 == EOC_TAG_ID))
           {
              /* should be a zero byte here to terminate */
              if(*asndata++ != 0)
              {
                 /* have to clean up */
                err = SRL_ASN_ERROR;
               goto ErrorExit;
                }
                totalElmtsLen6++;
               seqDone = TRUE;
           }
       }

       /* to deal with the certificate pair, we will just loop twice, since
        * the internal code is mostly the same (context tags differ, and
        * end of decoding check is slightly diff..)
        */
       pair = 2;
       while(!seqDone && pair)      /* if we aren't done yet (errs break out of the loop) */
      {
         pair--;   /* dec each time through (loops 2 times) */

         /* if we have a forward, or reverse tag (context specific constructed) */
         if( (tagId6 == CNTX_CONS_ZERO_TAG) || (tagId6 == CNTX_CONS_ONE_TAG))
         {
            /* get len of cert element */
            err = ASN_SRL_DecLen(asndata, &dec_count, &elmtLen6);
            if(err != SRL_SUCCESS)
               goto ErrorExit;
            totalElmtsLen6 += dec_count;
            asndata += dec_count;
            dec_count = 0;

            if (elmtLen6 == INDEFINITE_LEN)
            {
               /* signed over data, no indef length allowed here */
                err = SRL_ASN_ERROR; /* Report error. */
               goto ErrorExit;
            }

            /* we should now be pointing at the start of a cert,
             * record it down below.
             *
             * we could read the seq of the cert here, but the
             * decoder will validate this when it does it's
             * job.  Fill in the cert link
             */
            cpath = (SRL_CertList *)malloc(sizeof(SRL_CertList));
            if(cpath == NULL)
            {
               err = SRL_MEMORY_ERROR;
               goto ErrorExit; /* clean up path */
            }

            cpath->asn1cert = asndata;   /*  cert start */
            cpath->next = *hcpath;      /* point at the prev top of list */
            cpath->cert = NULL;
            *hcpath = cpath;      /* top of the list right now */

            /* since we are skipping the actual decoding of the
             * cert here (till later) we need to update the
             * data ptr past the cert.
             */
            totalElmtsLen6 += elmtLen6;
            asndata += elmtLen6;

            /* see if we just ran by a reverse cert, if so we should be done */
            if(tagId6 == CNTX_CONS_ONE_TAG)
            {
               seqDone = TRUE;
               if ( certPairSeqLen == INDEFINITE_LEN )
               {
                  /* should be two zero bytes here, the
                   * EOC tag itself, and the empty data ender.
                   */
                  if((asndata[0] == 0) && (asndata[1] == 0))
                  {
                     totalElmtsLen6 += 2;
                     asndata += 2;
                  }
                  else
                     err = SRL_ASN_ERROR;
               }
               else if (totalElmtsLen6 != certPairSeqLen)
                  err = SRL_ASN_ERROR;
             }
            /* else we may have just processed the forward cert */
            else if ( (certPairSeqLen != INDEFINITE_LEN) && (totalElmtsLen6 == certPairSeqLen))
               seqDone = TRUE;
            else
            {
               /* just finished forward, get tag which may be the EOC or the
                * tag for a reverse.
                */
               err = ASN_SRLDecTag(asndata, &dec_count, &tagId6);
               if(err != SRL_SUCCESS)   goto ErrorExit;
               totalElmtsLen6 += dec_count;
               asndata += dec_count;
               dec_count = 0;

               if ((certPairSeqLen == INDEFINITE_LEN) && (tagId6 == EOC_TAG_ID))
               {
                    if(*asndata++ == 0)       /* should be a zero byte here to terminate */
                    {
                         totalElmtsLen6++;
                     seqDone = TRUE;
                      }
                      else err = SRL_ASN_ERROR;
               }
            }

            if(err != SRL_SUCCESS) /* see if we got an error */
               goto ErrorExit;  /* clean up mem we allocated for linked list */

          }/* end of either tag */
         else   /* neither tag, and we weren't done, therefore an error */
         {
            err = SRL_ASN_ERROR;
            goto ErrorExit;  /* clean up mem we allocated for linked list */
         }
      }/* end of while */

/* end of pairs of certificates handling */
      *decodedLen += totalElmtsLen6;

   }  /* end of tag check if */
   else  /* wrong tag */
   {
      err = SRL_ASN_ERROR;
      goto ErrorExit;
   }


   return(SRL_SUCCESS);
   
ErrorExit:
   
   
   return(err);

}


/*
 * Routine checks the LDAP Session settings for a valid LDAP connection.
 * If there is no valid LDAP connection, the routine tries to establish
 * a connection.
 */
short SRLi_GetLDAPSessionStatus (ulong sessionID)
{
short err = SRL_SUCCESS;
SRLSession_struct *session;
	err =  SRLi_GetRetSessionFromRef(&session, sessionID);
	if(err != SRL_SUCCESS)
		return err;

	/* If ldapInfo is NULL = No LDAP is available */
	if (session->ldapInfo == NULL)
		return (SRL_LDAP_UNAVAILABLE);

	/* Check the ldapID is not zero - We are already connected */
	if ((session->ldapInfo->ldapIDinfo != NULL) &&
		(session->ldapInfo->ldapIDinfo->ldapID != 0))
		return (SRL_SUCCESS);

	/* See if possibly we can connect to LDAP */

	/* Process the LDAP info from the Settings */
	if ((session->ldapInfo != NULL) &&
		(session->ldapInfo->SharedLibraryName != NULL) &&
		(session->ldapInfo->LDAPServerInfo != NULL))
	{
       /* Set up the session to use LDAP. */
	   if (session->ldapInfo->LDAPServerInfo->LDAPserver == NULL)
	   {
		   err = SRL_LDAP_INIT_FAILED;
		   goto CLEANUP;
	   }
	   if (session->ldapInfo->LDAPServerInfo->LDAPport == 0)
	   {
		   err = SRL_LDAP_INIT_FAILED;
		   goto CLEANUP;
	   }

	   /* Attempt to dynamically link to the specified LDAP library, 
	    * initialize the LDAP library, and bind to the specified server.
		*/

	   err = SRLi_Link2LDAP(session->ldapInfo);
	   if (err != SRL_SUCCESS)
		   goto CLEANUP;

	   if (session->ldapInfo->ldapIDinfo != NULL)
	   {
		   session->ldapInfo->ldapIDinfo = (LDAPIdInfo_struct *)calloc(1, sizeof(LDAPIdInfo_struct));
		   if (session->ldapInfo->ldapIDinfo == NULL)
			   return (SRL_MEMORY_ERROR);
	   }
	   session->ldapInfo->ldapIDinfo->ldapID = SRLi_LdapInit (session->ldapInfo);
		session->ldapInfo->ldapIDinfo->internal = TRUE;
	   err = SRLi_LdapConnect (session->ldapInfo);
	   if (err != SRL_SUCCESS)
		   goto CLEANUP;


	}
	else if ((session->ldapInfo != NULL) &&
			(session->ldapInfo->LDAPFunctions != NULL) &&
			(session->ldapInfo->LDAPServerInfo != NULL))
	{
		
		/* The LDAPServerInfo and LDAPFunctions are present.
		 * Attempt to initialize the LDAP library and bind to the 
		 * specified server using the provided LDAP function pointers.
		 */
	   if (session->ldapInfo->ldapIDinfo == NULL)
	   {
		   session->ldapInfo->ldapIDinfo = (LDAPIdInfo_struct *)calloc(1, sizeof(LDAPIdInfo_struct));
		   if (session->ldapInfo->ldapIDinfo == NULL)
			   return (SRL_MEMORY_ERROR);
	   }

		session->ldapInfo->ldapIDinfo->ldapID = SRLi_LdapInit (session->ldapInfo);
		if (session->ldapInfo->ldapIDinfo->ldapID == NULL)
		{
			err = SRL_LDAP_INIT_FAILED;
			goto CLEANUP;
		}
		err =  SRLi_LdapConnect (session->ldapInfo);
		if (err != SRL_SUCCESS)
			goto CLEANUP;

		session->ldapInfo->ldapIDinfo->internal = FALSE;

	}
	return (SRL_SUCCESS);

CLEANUP:
	SRLi_FreeLDAPinfo (&session->ldapInfo);
	return (err);

}

static CM_BOOL SRLi_isFTPurl(char *url)
{
		char *purl;
	int index;
	int uLen = strlen(url) + 1;
    if( url == NULL ) 
         return FALSE;
	purl = (char *)calloc (1, uLen);
	// Normalize the string
   	for (index = 0; index < uLen; index++)
	{
		purl[index] = (char)tolower(url[index]);
	}
		
		
	// Skip over the leading '<' if any
	if ( *purl == '<' ) 
            ++purl;

	// Check for  "URL:" 
    if ( strstr( purl, URL_COLON) != NULL ) 
            purl += URLCOLON_LEN;

    // Check for "ftp://" 
    if ( strstr( purl, "ftp://") != NULL ) 
	{
		free (purl);
		return TRUE;
	}
	free (purl);
    return FALSE;
}


static CM_BOOL SRLi_isHTTPurl(char *url)
{
		char *purl;
	int index;
	int uLen = strlen(url) + 1;
    if( url == NULL ) 
         return FALSE;
	purl = (char *)calloc (1, uLen);
	// Normalize the string
   	for (index = 0; index < uLen; index++)
	{
		purl[index] = (char)tolower(url[index]);
	}
		
		
	// Skip over the leading '<' if any
	if ( *purl == '<' ) 
            ++purl;

	// Check for  "URL:" 
    if ( strstr( purl, URL_COLON) != NULL ) 
            purl += URLCOLON_LEN;

    // Check for "http://" 
    if ( strstr( purl, "http://") != NULL ) 
	{
		free (purl);
		return TRUE;
	}
	free (purl);
    return FALSE;
}


static CM_BOOL SRLi_is_ldapurl(char *url)
{
	char *purl;
	int index;
	int uLen = strlen(url) + 1;
    if( url == NULL ) 
         return FALSE;
	purl = (char *)calloc (1, uLen);
	// Normalize the string
   	for (index = 0; index < uLen; index++)
	{
		purl[index] = (char)tolower(url[index]);
	}
		
		
	// Skip over the leading '<' if any
	if ( *purl == '<' ) 
            ++purl;

	// Check for  "URL:" 
    if ( strstr( purl, URL_COLON) != NULL ) 
            purl += URLCOLON_LEN;

    // Check for "ldap://" 
    if ( strstr( purl, "ldap://") != NULL ) 
	{
		free (purl);
		return TRUE;
	}

    /* Check for "ldaps://" */
    if ( strstr( purl, LDAPS_PREFIX ) != NULL )
	{
		free (purl);
		return TRUE;
	}


    /* Check for "ldapi://" prefix */
    if ( strstr( purl, LDAPI_PREFIX) != NULL) 
	{
		free (purl);
		return TRUE;
	}
	free (purl);
    return FALSE;
}

int SRLi_SkipPrefix(int PreFixType, char **p_inURL, int *enclosed)
{
	if ( *p_inURL == NULL )
		return 0;

     /* Skip over any leading '<'  */
     if ( **p_inURL == '<' ) {
         *enclosed = 1;
         ++*p_inURL;
     } else {
         *enclosed = 0;
     }

	 if (PreFixType == LDAP_PREFIX_TYPE)
	 {
		 /* Check for "URL:" */
		if (strlen(*p_inURL) >= URLCOLON_LEN)
		{
			if (SRLi_memicmp(*p_inURL, URL_COLON, URLCOLON_LEN) == 0)
				*p_inURL += URLCOLON_LEN;
		}
		 

		if (strlen(*p_inURL) >= LDAPS_PREFIX_LEN)
		{
			// Skip over the ldapi:// prefix
			if (SRLi_memicmp(*p_inURL, LDAPS_PREFIX, LDAPS_PREFIX_LEN) == 0)
			{
				*p_inURL += LDAPS_PREFIX_LEN;
				return 2;
			}
		}

		if (strlen(*p_inURL) >= LDAPI_PREFIX_LEN) 
		{
			// Skip over the ldapi:// prefix
			if (SRLi_memicmp(*p_inURL, LDAPI_PREFIX, LDAPI_PREFIX_LEN) == 0)
			{
				*p_inURL += LDAPI_PREFIX_LEN;
				return 1;
			}
		}

		if (strlen(*p_inURL) >= LDAP_PREFIX_LEN)
		{
			// Skip over the ldap:// prefix 
			if (SRLi_memicmp(*p_inURL, LDAP_PREFIX, strlen(LDAP_PREFIX)) == 0)
			{
				*p_inURL += LDAP_PREFIX_LEN;
				return 1;
			}
		} 
	}
	else if (PreFixType == FTP_PREFIX_TYPE)
	{
		if (strlen(*p_inURL) >= FTP_PREFIX_LEN)
		{
			*p_inURL += FTP_PREFIX_LEN;
			return 3;
		}
	}
	else if (PreFixType == HTTP_PREFIX_TYPE)
    {
		if (strlen(*p_inURL) >= HTTP_PREFIX_LEN)
		{
			*p_inURL += HTTP_PREFIX_LEN;
			return 4;
        }
    }
    return 0;    /* not an LDAP URL */
}

static char hex2char(char c1, char c2)
{
	char digit = 0;

	if ((c1 >= '0') && (c1 <= '9'))
		digit |= c1 - '0';
	else if ((c1 >= 'a') && (c1 <= 'f'))
		digit |= c1 - 'a' + 10;
	else if ((c1 >= 'A') && (c1 <= 'F'))
		digit |= c1 - 'A' + 10;

	digit <<= 4;

	if ((c2 >= '0') && (c2 <= '9'))
		digit |= c2 - '0';
	else if ((c2 >= 'a') && (c2 <= 'f'))
		digit |= c2 - 'a' + 10;
	else if ((c2 >= 'A') && (c2 <= 'F'))
		digit |= c2 - 'A' + 10;

	return digit;
}

int SRLi_hex_unescape(char *url)
{
    int x, y, badescape = 0, badpath = 0;

    for (x = 0, y = 0; url[y]; ++x, ++y) {
        if (url[y] != '%')
            url[x] = url[y];
        else {
            if (!isxdigit((int)url[y + 1]) || !isxdigit((int)url[y + 2])) {
                badescape = 1;
                url[x] = '%';
            }
            else {
                url[x] = hex2char(url[y + 1], url[y + 2]);
                y += 2;
                if (url[x] == '/' || url[x] == '\0')
                    badpath = 1;
            }
        }
    }
    url[x] = '\0';
    if ((badescape) || (badpath))
        return SRL_URL_PARSE_ERROR;
    else
        return SRL_SUCCESS;
}



//
// Return the prefix type:
// 1 = ldapi:// or ldap://
// 2 = ldaps://
// 3 = ftp://
//
int SRLi_url_parse (char *purl, SRL_URLDescriptor_struct **pURLDesc)
{
	SRL_URLDescriptor_struct *pDesc = NULL; // Working Structure
	char *tempCopy, *attributes, *port, *scope;
	char *dn, *filter, *tempattrs, *hostname;
	int     enclosed = 0, i, count,preFixType = 0, hasport = 0, defport = 0;

	if ( purl == NULL || pURLDesc == NULL )
		return SRL_INVALID_PARAMETER;

	if (SRLi_is_ldapurl(purl))
	{
		// Skip past the prefix
		preFixType = SRLi_SkipPrefix(LDAP_PREFIX_TYPE, &purl, &enclosed);	
		if (preFixType == 0)
			return SRL_INVALID_PARAMETER;
		defport = LDAP_PORT;
	}
	else if (SRLi_isFTPurl(purl))
	{
		preFixType = SRLi_SkipPrefix(FTP_PREFIX_TYPE, &purl, &enclosed);
		if (preFixType == 0)
			return SRL_INVALID_PARAMETER;
		defport = FTP_PORT;
	}
	else if (SRLi_isHTTPurl(purl))
	{
		preFixType = SRLi_SkipPrefix(HTTP_PREFIX_TYPE, &purl, &enclosed);
		if (preFixType == 0)
			return SRL_INVALID_PARAMETER;
		defport = HTTP_PORT;
    }
	else
		return SRL_INVALID_PARAMETER;



	pDesc = (SRL_URLDescriptor_struct *)calloc(1, sizeof (SRL_URLDescriptor_struct));
	if (pDesc == NULL)
		return SRL_MEMORY_ERROR;



	 /* 
	  * Okay let's get started with the parsing
	  * Once parsing is done the SRL URL Descriptor should
	  * be filled in with all the relative data
	  */
	port = NULL;
	if ((tempCopy = strdup(purl)) == NULL)
	{
		if (pDesc != NULL)
			free (pDesc);
		return SRL_MEMORY_ERROR;
	}

	// If enclosed in "<" ">" then skip
    if ( enclosed)
	{
		*port = purl[(strlen(tempCopy)-1)];
		if (*port == '>')
			*port = '\0';
	}
		

	// Load in the standard defaults per RFC2255
	pDesc->scope = LDAP_SCOPE_BASE;

	// Get the DN
	dn = strchr(purl, '/');
	if ((preFixType != 3) && (preFixType != 4)) // Ftp & Http need the slash
		dn++; // Skip over the "/"
	pDesc->URL_DN = strdup(dn);
	if (dn == NULL)
	{
		if (pDesc != NULL)
			free (pDesc);
		if (tempCopy != NULL)
			free (tempCopy);
		return SRL_URL_PARSE_ERROR;
	}


	// Load in the Host and port

	if (( port = strchr(tempCopy, ':' )) != NULL )
	{
		hasport = 1;
		*port++ = '\0';
		pDesc->port = atoi(port);
	}

	if (hasport == 1)
	{
		// Port was specified - get hostname
		if (*tempCopy == '\0')
			 pDesc->hostname = NULL;
		else
         pDesc->hostname = (uchar *)tempCopy;
	}
	else
	{
		// Port was not specified - get hostname
		pDesc->port = defport;
		hostname = strchr(tempCopy,'/');
		*hostname++ = '\0';
		pDesc->hostname = (uchar *)tempCopy;
	}
    SRLi_hex_unescape((char *)pDesc->hostname);

	// Now look for ? - Marks the end of the DN -> Attributes

	if ((attributes = strchr( pDesc->URL_DN, '?' )) != NULL ) 
	{
 
		 *attributes++ = '\0';

		 // Now check for ? -> Scope
		 if (( scope = strchr( attributes, '?' )) != NULL )
		 {
			*scope++ = '\0';

			// Check for ? -> Filter
			if (( filter = strchr( scope, '?' )) != NULL )
			{
				*filter++ = '\0';
				 if ( *filter != '\0' )
				 {
                     pDesc->filter = (uchar *)strdup(filter);
                     SRLi_hex_unescape((char *)pDesc->filter);
				 }
			} // Endif filter
			else
			{
				pDesc->filter = (uchar *)strdup("(objectClass=*)");
			}


			// Load in the Scope level based on the ascii
			if (SRLi_memicmp( scope, "one", strlen("one") ) == 0) 
					pDesc->scope = LDAP_SCOPE_ONELEVEL;
			else if (SRLi_memicmp( scope, "base", strlen("base")) == 0) 
					pDesc->scope = LDAP_SCOPE_BASE;
			else if (SRLi_memicmp( scope, "sub", strlen("sub")) == 0) 
					pDesc->scope = LDAP_SCOPE_SUBTREE;
		 } // Endif scope
		 else
		 {
				pDesc->filter = (uchar *)strdup("(objectClass=*)");
		 }


	} // Endif attributes
	else
	{
		pDesc->filter = (uchar *)strdup("(objectClass=*)");
	}



	// Reformat the DN (unescape it) and Attributes (null terminated array);
	if ( *pDesc->URL_DN == '\0' )
		pDesc->URL_DN = NULL;
	else
		SRLi_hex_unescape(pDesc->URL_DN);


	if (attributes != NULL  && *attributes != '\0')
	{

		// Count the number of attributes in the string
		for (count = 1, tempattrs = attributes; *tempattrs != '\0'; ++tempattrs)
		{
			// Comma seperates the attributes
			if (*tempattrs == ',')
				count ++;
		}

		// Whew, now allocate the attribute structure member
		pDesc->attributes = (char **)calloc(count+1, sizeof (char *));
		if (pDesc->attributes == NULL)
		{
			if (pDesc != NULL)
				free (pDesc);
			if (tempCopy != NULL)
				free (tempCopy);

			return SRL_MEMORY_ERROR;
		}

		// Load in the attributes

		for (i = 0, tempattrs = attributes; i < count; i++)
		{
			pDesc->attributes[i] = tempattrs;
			if ((tempattrs = strchr(tempattrs,',')) != NULL)
				*tempattrs++ =  '\0';
			// Unescape the string
			SRLi_hex_unescape(pDesc->attributes[i]);
		}
	} // Endif attribute if block

	*pURLDesc = pDesc;
	return preFixType;
}

