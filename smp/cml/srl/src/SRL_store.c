/*****************************************************************************
File:     SRL_store.c
Project:  Storiage & Retrieval Library
Contents: Low-level storage functions.

Created:  November 2000
Author:   Robin Moeller <Robin.Moeller@DigitalNet.com>

Last Updated:  21 January 2004

Version:  2.4

Description: This file contains routines which are used by the high level
interfacing routines related to storage and retrieval of certs, crls, etc.
Storage in this case means to local database (makes use of the db.c lib),
and retrieval from local storage (db files)....

SRLi_AddCertListToDB
SRLi_AddCertToDB
SRLi_AddCRLToDB
SRLi_BuildCertIndexTemplate
SRLi_BuildCRLIndexTemplate
SRLi_CertInfoFromTemplate
SRLi_CompareCMatch2Index
SRLi_CompareCRLMatch2Index
SRLi_CompareTemplateSearchCriteria
SRLi_CRLInfoFromTemplate
DB2SRLerr
SRLi_GetPolyPtr
SRLi_RetrieveTrustedList
SRLi_SortdbEntryLL
SRLi_TemplateFromCertInfo
SRLi_TemplateFromCRLInfo

*****************************************************************************/

/* Included Files */
#include <string.h>
#include "SRL_internal.h"
#include "SRL_db.h"
#include "cmapi.h"

#ifdef WIN32
#pragma warning(disable: 4127)
#endif

extern char DP_LDAP_URI[];
AsnTypeFlag SRLi_GetCertType (Cert_struct *dec_cert, enum AsnTypeFlag TypeFlag);
short SRLi_GetCertID(ulong sessionID, Bytes_struct *pObject, Cert_struct *dec_cert,CM_BOOL trustedFlag, AsnTypeFlag AsnType, Bytes_struct **CertID);
short SRLi_GetCRLID(ulong sessionID, uchar *pObject, CRL_struct *dec_crl, Bytes_struct **DBid);
static CM_BOOL SameIssuer(Cert_struct *cert);
static short SRLi_UpdateCRLTemplate(SRLSession_struct *srlSession, DB_Item *base_template, 
									DB_Item *Template, DB_Item *entry_kid, DB_Item *object);
static short SRLi_StripCRLRefreshTime( char **CRLtemplate, char *tempPtr, ulong len);
static short SRLi_GetMatchingCRLTemplate(DB_Data *ex_data, Bytes_struct *ciTemplate, DB_Data *matchingTemp);
short db_CalcHash(ulong db_session, DB_Kid *kid, DB_Kid *data, long norm_type, 
				  long *HashValue, long relatedHash, long storeFlag);
extern short db_GetHash(DB_Kid *kid, long norm_type, long *HashValue);
extern short db_Info(ulong db_session, DB_INFO_Struct **info);
extern short db_RetrieveHash(ulong db_session, DB_Kid *kid,  
				   long *HashValue);
extern short db_UpdateHeaderVersion (ulong db_session, char *path, char *dbfile);
PExportedDNMatchFn  CMU_DistinguishedNameMatch;
CM_BOOL SRLisLittleEndian();
//extern PExportedDNMatchFn  SRLi_DistinguishedNameMatch;
/* to handle updates to the way we format data for storage into the
 * db files, a version value is stored in the template along with the rest
 * of the info. This will allow us to handle old/new template formats for
 * existing db files.
 *
 * DB_TEMPLATE_FLAG = if the template read from the db file has this
 * flag, then we know there are version fields in the templates for
 * the cert and crl databases. If the DB_TEMPLATE_FLAG is not
 * found in the templates, then we are working with older db files,
 * and there are no versioning fields in the templates.
 * 
 * DB_NORMALIZED_FLAG = if the template read from the db file has
 * this added to the DB_TEMPLATE_FLAG, then we know that the related
 * KID (DN) has already been normalized.
 *
 * the cert template version for release 1.2 of the lib is 1
 * the crl template version for release 1.2 is still 0
 * (cm lib 1.1 templates are both considered version 0)
 *
 * cert template version 1 added an email address field
 *
 * cert template version 2 added a hash value field
 * crl template version 1 added a hash value field
 * (Will be rolled into next release beyond 1.2)
 *
 */
#define DB_TEMPLATE_FLAG		(uchar)0x01
#define DB_NORMALIZED_FLAG		(uchar)0x01

/* these two values will be incremented if fields are 
 * added to their respective formats...
 */
#define CRL_TEMPLATE_VERSION1   (uchar)0x01  // Original version
#define CERT_TEMPLATE_VERSION2	(uchar)0x02  // Normalized DN version
#define CERT_TEMPLATE_VERSION	(uchar)0x03  // CERT Type processing
#define CRL_TEMPLATE_VERSION3	(uchar)0x03	 // CRL Type and DP Name processing
#define CRL_TEMPLATE_VERSION4	(uchar)0x04	 // CRL Refresh Time processing
#define CRL_TEMPLATE_VERSION	(uchar)0x04	 // CRL Refresh Time processing



uchar SRLi_GetCRLType (CRL_struct *pCRL,enum AsnTypeFlag TypeFlag )
{
	unsigned char crl_type = (unsigned char)TypeFlag;
	if ((pCRL->exts) && (pCRL->exts->deltaCRL))
		crl_type = DELTA_CRL_TYPE;
	else if ((pCRL->exts) && (pCRL->exts->issDistPts) && (pCRL->exts->issDistPts->value))
	{
		/* Get the Issuing Distribution Point Pointer */
		Iss_pts_struct *IssDistPts = pCRL->exts->issDistPts->value;
		if (IssDistPts != NULL)
		{
			/*
			 * If the issuing points has only CA flag set, then
			 * the CRL type is a ARL
			 */
			if ((IssDistPts->only_cAs_flag) && 
				(IssDistPts->only_users_flag == 0))
				crl_type = ARL_TYPE;
			else if (IssDistPts->only_users_flag)
				crl_type = CRL_TYPE;
		}
		else
			// Default to value passed in
			crl_type = (unsigned char)TypeFlag;
		
	}
	else
		// Default to CRL_TYPE
		crl_type = (unsigned char)TypeFlag;
	return (crl_type);
}
/*
 * Retreive the CRL Issuer Name from the CRL, this includes
 * processing any issuing distribution points
 */
short SRLi_GetCRLIssuerName (CRL_struct *input_crl, char **crl_issuer)
{
char *the_issuer = NULL;
Iss_pts_struct *issDistPoint = NULL;
char *relativeName = NULL;
short err = 0;
	if (input_crl == NULL)
		return SRL_NULL_POINTER;
	/* see if we have info already existing, determine if we just
	 * add or replace.
	 */
	if (CRL_TEMPLATE_VERSION >= 2)
	{
		if (input_crl->exts != NULL)
		{
			if (input_crl->exts->issDistPts == NULL)
			{
				/* Grab the issuer from the issuer location */
				the_issuer = (char *)calloc (1,strlen(input_crl->issuer)+1);		/* the subjects DN */
				memcpy (the_issuer, input_crl->issuer, strlen(input_crl->issuer));

			}
			else if (input_crl->exts->issDistPts != NULL)
			{
				
				/*
				 * Issuing Distribution Points are present
				 * Process accordingly
				 */
				issDistPoint = input_crl->exts->issDistPts->value;
				switch(issDistPoint->dpName.flag)
				{
				   case CM_NOT_PRESENT:

						/* Case for there is no Dist. Pt. field in the IDP */
						the_issuer = (char *)calloc (1,strlen(input_crl->issuer) +1);		/* the subjects DN */
						memcpy (the_issuer, input_crl->issuer, strlen(input_crl->issuer));
						err = SRL_SUCCESS;
						break;

				   case CM_DIST_PT_FULL_NAME:
					   /*
						* Distribution Point based CRL/ARL with a full name
						*/

						/* Get the name of the issuer */
						err = SRLi_genname2str(issDistPoint->dpName.name.full,
							&the_issuer);
						if ((err == SRL_SUCCESS) && (the_issuer == NULL))
							err = SRL_INVALID_DN;
						break;

				   case CM_DIST_PT_RELATIVE_NAME:

					   /*
						* Distribution Point based CRL/ARL using a Relative name
						* copy the CRL Issuer and append on the Relative Name
						*/

					   relativeName = (char *)calloc(1,strlen(issDistPoint->dpName.name.relative) +
														strlen(input_crl->issuer) + 3);
					   if (relativeName == NULL)
						   err = SRL_MEMORY_ERROR;
					   else
					   {
						   strcpy(relativeName,issDistPoint->dpName.name.relative);
							(void)strcat(relativeName,",");
							(void)strcat(relativeName,input_crl->issuer);
							relativeName[strlen(relativeName)] = '\0';
							the_issuer = relativeName;
							err = SRL_SUCCESS;
					   }
						break;

				   default:
					   /* Illogical - should never get here */
						err = SRL_INVALID_DN;
						break;
				} /* End switch */
			} /* End if */
		} /*  extensions */
		else
		{
			/* No extensions */
			the_issuer = calloc (1, strlen (input_crl->issuer)+1);
			memcpy (the_issuer, input_crl->issuer, strlen(input_crl->issuer));
			err = SRL_SUCCESS;
		}
			} /* Endif template version */
	else
	{
		/* Use the previous version entry_kid */
		/* Grab the issuer from the issuer location */
		the_issuer = (char *)calloc (1, strlen(input_crl->issuer) +1);
		memcpy (the_issuer, input_crl->issuer, strlen (input_crl->issuer));
	}
	*crl_issuer = the_issuer;
	return (err);
}
/*

SRLi_AddCertListToDB()

short SRLi_AddCertListToDB(SRLSession_struct *session, SRL_CertList *dec_cpath )

This routine will walk thru the given certification path and add each cert to
the certificate database associated with the session.  Certs that already
exist in the database will be skipped if an exact match is found within the
path list.

paramters:
	session (input) = session ref

	dec_cpath (input) = linked list of cert path structs, containing both
		the ptrs to the decoded certs for the given path and ptrs to
		the asn.1 encoded versions of the certs.

returns:
	SRL_SUCCESS			- worked fine
	pass thru error codes from lower level routines....

*/
short SRLi_AddCertListToDB(ulong rt_session, SRL_CertList *dec_cpath, enum AsnTypeFlag TypeFlag )
{
	short			err = 0;
	Cert_struct		*this_decPtr;
	Bytes_struct	asn1data;


	/* walk through the linked list of certs and the linked list of
	 * encoded certs - add each to the db.
	 */
	asn1data.data = dec_cpath->asn1cert;
	this_decPtr = dec_cpath->cert;

	while((this_decPtr != NULL) && (asn1data.data != NULL))
	{
		/* add this cert to the database and create index info for it.
		 * If it already exists (exact match) then it will be skipped
		 * and SRL_SUCCESS is returned...
		 * For other errs will we will skip trying to add an further
		 * certs in the path.
		 */
		err = SRLi_AsnGetLength(asn1data.data, (ulong *)&asn1data.num);
		if(err != SRL_SUCCESS)
			break;	/* get out of town now */

		err = SRLi_AddCertToDB(rt_session, &asn1data, this_decPtr, FALSE, TypeFlag, NULL);

		if((err != SRL_SUCCESS) && (err != SRL_INVALID_DN))
			break;	/* get out of town now */
		else
			err = SRL_SUCCESS; // Ignore the SRL_INVALID_DN

		/* move onto next pair in the linked lists */
		dec_cpath = dec_cpath->next;

        if (dec_cpath != NULL)
        {
            asn1data.data = dec_cpath->asn1cert;
            this_decPtr = dec_cpath->cert;
        }
        else
            this_decPtr = NULL;
	}

	return(err);	/* tell caller the result */

}

short SRLi_AddCRLToDB(ulong rt_session, Bytes_struct *asn1data, CRL_struct *dec_crl, enum AsnTypeFlag TypeFlag,
					  const char* kid_str)
{
	Bytes_struct	ciTemplate, big_block;
	short			err, result;
	DB_Kid			entry_kid;
	DB_Data			entry_data, *ex_data = NULL, *compare_data = NULL;	/* existing data */
	DB_Data			matchingTemp;
	SRLSession_struct *session = NULL;
	/*
	 * The DNHashValue is used to store the DN hash value and
	 * the TempHashValue is used to store the Template hash value 
	 */
	long DNHashValue = 0,TempHashValue = 0, saveHash = 0;

	/* check params (here till done debugging) */
	if((rt_session == 0) || (asn1data == NULL) || (dec_crl == NULL))
		return(SRL_INVALID_PARAMETER);

	err =  SRLi_GetRetSessionFromRef(&session, rt_session);
	if(err != SRL_SUCCESS)
		return(err);
	/* create index info for the crl */
	err = SRLi_BuildCRLIndexTemplate(dec_crl, &ciTemplate, asn1data,
										 TypeFlag);
	if(err != SRL_SUCCESS)
		return(err);

	if (kid_str != NULL)
	{
		entry_kid.item_ptr = strdup(kid_str);
		entry_kid.item_len = strlen(kid_str)+1;
	}
	else
	{
		err = SRLi_GetCRLIssuerName(dec_crl, &entry_kid.item_ptr);
		entry_kid.item_len = strlen (entry_kid.item_ptr)+1;
		if (err != SRL_SUCCESS)
			return (err);
	}


	entry_data.item_len = ciTemplate.num;			/* the search/match data */
	entry_data.item_ptr = (char *) ciTemplate.data;

	if (err == 0)
	{
		// Get the Hash of the Template, for storage
		
		db_CalcHash (session->db_CRLRefSession, &entry_data, NULL, NORMALIZED,
				&TempHashValue, 0, DB_INSERT);
		saveHash = TempHashValue;
		/* 
		 * Insert into the db file associated with this session
		 * along with the hash of the Template
		 */
		err = db_StoreItem(session->db_CRLRefSession, &entry_kid, &entry_data, &TempHashValue, DB_INSERT);

		/* Store off the returned DN Hash Value */
		DNHashValue = TempHashValue;

	}
	/* check to see if we have an existing entry for the given DN */
	if(err == DB_NO_INSERT)
	{
		/* need to retrieve the current entry so we can determine if we
		 * need to add to it.
		 */
		err = db_GetEntry(session->db_CRLRefSession, TempHashValue, &entry_kid, &ex_data);
		err = DB2SRLerr(err);
		if(err != SRL_SUCCESS)
		{
			if(ciTemplate.data)
			{
				free(ciTemplate.data);
				ciTemplate.data = NULL;
			}
			if(entry_kid.item_ptr)
			{
				free(entry_kid.item_ptr);
				entry_kid.item_ptr = NULL;
			}
			return(err);	/* complete failure, tell caller */
		}

		/* 
		 * We now want to check the settings to see
		 * what we are suppose to do with the old entry
		 * If CRL is found, and removeStaleCRL is false
		 * then we just replace the Template. If removeStaleCRL is
		 * TRUE then we remove the old CRL, update the template and
		 * add the template back into the database.
		 */

		 memset (&matchingTemp, 0, sizeof (DB_Item));

		 // Try to get the matching Template
		 result = SRLi_GetMatchingCRLTemplate (ex_data, &ciTemplate, &matchingTemp);

		if(result == 0)	/* if exact match */
		{
			/* modification: Add additional check where we
			 * compare the asn.1 encoded data - if they
			 * match, then we will return. If there is some
			 * difference, we will replace the entry in the
			 * database with the passed in asn.1 data. At
			 * this point we are under the assumption that
			 * the passed in one must be good, and the
			 * current entry must have become corrupted
			 * somehow.
			 */
			
			saveHash = 0;
		   db_RetrieveHash(session->db_CRLRefSession, &matchingTemp,  
						  &saveHash);
	
			err = db_GetEntry(session->db_CRLRefSession, saveHash, &matchingTemp,  &compare_data);
			if(err != DB_NO_ERR)
			{
				if(compare_data != NULL)
				{
					if (compare_data->item_ptr)
						free(compare_data->item_ptr);
					free(compare_data);
					compare_data = NULL;
				}
				if(ex_data != NULL)
				{
					if (ex_data->item_ptr)
						free(ex_data->item_ptr);
					free(ex_data);
					ex_data = NULL;
				}
				if (ciTemplate.data)
				{
					free(ciTemplate.data);
					ciTemplate.data = NULL;
				}

				if(entry_kid.item_ptr)
				{
					free(entry_kid.item_ptr);
					entry_kid.item_ptr = NULL;
				}

				if(matchingTemp.item_ptr)
				{
					free(matchingTemp.item_ptr);
					matchingTemp.item_ptr = NULL;
				}

				return(DB2SRLerr(err));	/* complete failure, tell caller */
			}
			
			/* do a mem compare on the asn.1 data itself */
			if(asn1data->num == compare_data->item_len)	/* not different */
			{
				/* see if they are equal */
				if(memcmp(compare_data->item_ptr, asn1data->data, compare_data->item_len) == 0)
				{
					/* then exactly the same - Refresh the refresh time */
					err = SRLi_UpdateCRLTemplate(session, ex_data, 
												&matchingTemp, &entry_kid, 
												compare_data);

					if(compare_data)
					{
						free(compare_data->item_ptr);/* free up stuff we don't need anymore */
						free(compare_data);
						compare_data = NULL;
					}
					if(ex_data)
					{
						free(ex_data->item_ptr);
						free(ex_data);
						ex_data = NULL;
					}
					if(ciTemplate.data)
					{
						free(ciTemplate.data);
						ciTemplate.data = NULL;
					}
					if(entry_kid.item_ptr)
					{
						free(entry_kid.item_ptr);
						entry_kid.item_ptr = NULL;
					}
					if(matchingTemp.item_ptr)
					{
						free(matchingTemp.item_ptr);
						matchingTemp.item_ptr = NULL;
					}

					compare_data = NULL;
					ex_data = NULL;
					return(SRL_SUCCESS);
				}
				
			}
			if (compare_data)
			{
				if (compare_data->item_ptr)
					/* don't need the db copy of the asn.1 data, free it up */
					free(compare_data->item_ptr);
				free(compare_data);
				compare_data = NULL;
			}


			/* else they are different, do a replace. Need to 
			 * save out the asn.1 data using the entries
			 * template. Calculate the hash for matchingTemp and store
			 */


			db_CalcHash (session->db_CRLRefSession, &matchingTemp, 0, NORMALIZED,
				&TempHashValue, 0, DB_REPLACE);
			DNHashValue = TempHashValue;

			err = db_StoreItem(session->db_CRLRefSession, &matchingTemp, 
				(DB_Item*)asn1data, &TempHashValue, DB_REPLACE);
			
			if (ex_data)
			{
				if (ex_data->item_ptr)
					/* the existing dn template already contains a ref for this cert, and
					 * we know from our earlier comparison that they already match, so
					 * we only need to free up and return.
					 */
					free(ex_data->item_ptr);	/* got our own copy */
				free(ex_data);
				ex_data = NULL;
			}

			if (ciTemplate.data)
			{
				free(ciTemplate.data);
				ciTemplate.data = NULL;
			}

			if(matchingTemp.item_ptr)
			{
				free(matchingTemp.item_ptr);
				matchingTemp.item_ptr = NULL;
			}

			if(entry_kid.item_ptr)
			{
				free(entry_kid.item_ptr);
				entry_kid.item_ptr = NULL;
			}
			
			return(DB2SRLerr(err));

		}



		 /* create larger block that can contain old + new */
		big_block.num = ex_data->item_len + ciTemplate.num;

		big_block.data = malloc(big_block.num);

		if(big_block.data == NULL)
		{
			free(ciTemplate.data);
			free(ex_data->item_ptr);	/* got our own copy */
			free(ex_data);
			ex_data = NULL;
			return(SRL_MEMORY_ERROR);
		}

		memcpy(big_block.data, ex_data->item_ptr, ex_data->item_len);
		memcpy( &(big_block.data[ex_data->item_len]),
			ciTemplate.data, ciTemplate.num);
			TempHashValue = 0;
		db_CalcHash (session->db_CRLRefSession, &entry_kid, NULL, NORMALIZED,
				&TempHashValue, 0, DB_REPLACE);

		DNHashValue = TempHashValue;

		/* replace the old entry for this DN */
		err = db_StoreItem(session->db_CRLRefSession, &entry_kid, (DB_Item*)&big_block, 
			&DNHashValue, DB_REPLACE);

		/* clean up stuff we don't need anymore */
		if(big_block.data)
		{
			free(big_block.data);
			big_block.data = 0;
		}
		if(ex_data->item_ptr)
		{
			free(ex_data->item_ptr);
			free(ex_data);
			ex_data = 0;
		}
		err = DB2SRLerr(err);
		if(err != SRL_SUCCESS)
		{
			if(ciTemplate.data)
			{
				free(ciTemplate.data);
				ciTemplate.data = NULL;
			}
			return(err);

		}

		/* now fall down to below to store the raw asn.1 encoded crl
		 * into data base
		 */

	}
	err = DB2SRLerr(err);

	if(err == SRL_SUCCESS)
	{
		/* dn and searching template added ok.  Now we will add the asn.1
		 * encoded certificate to the database using the search template
		 * as the keying identifier.
		 */
		if(entry_kid.item_ptr)
			free(entry_kid.item_ptr);
		entry_kid.item_len = ciTemplate.num;			/* the search/match data */
		entry_kid.item_ptr = (char *) ciTemplate.data;

		entry_data.item_len = asn1data->num;		/* the asn1 encoded crl itself */
		entry_data.item_ptr = (char *) asn1data->data;


		/* insert into data base */
		err = db_StoreItem(session->db_CRLRefSession, &entry_kid, &entry_data, &DNHashValue, DB_INSERT);
		err = DB2SRLerr(err);

		if(ciTemplate.data)
		{
			free(ciTemplate.data);
			ciTemplate.data = NULL;
		}
	}

	return(err);	/* tell caller what the result is */



}


/*
 Function: SRLi_AddCertToDB()

 short SRLi_AddCertToDB(SessionStruct *session, Bytes_struct *asn1data, Cert_struct *dec_cert,
 short trustedFlag, const char *kid_str)

 This internal routine is called upon to add a certificate to the database associated
 with the given session.  The caller is providing the raw asn.1 data, and the decoded
 version of that data (certificate struct ptr).  This routine will create the index
 information for the given certificate, check to see if any entries exist for the
 subject's DN, and then add to database if it is not already in there.  For the case
 where the given DN already has an entry, we check to see if there is an exact match
 of the given certificate, if so then nothing is added. If the given certificate is
 different from any other certs listed in the index for the given DN, then the index
 info is updated to reflect that there is one more cert for the given DN, and then
 the certificate is added to the DB file.

 If the given certificate contains a public key which is to be considered
 trusted (for populating the key cache at startup), then this "trustedFlag" is
 set to TRUE, else it is set to FALSE.

 NOTE: in the case where the certificate already exists in the DB file, this
 routine will return SRL_SUCCESS even though we won't add the cert.

 parameters:
 		session (input) = the session ref for associated cert db to be added to

 		asn1data (input) = the asn.1 encoded version of the cert to add

 		dec_cert (input) = the decoded info struct ptr for the cert to add

 		trustedFlag (input) = TRUE if cert has special trusted status, else FALSE

		kid_str (input) = overrides the default the KID, needed to support URLs

 returns:
 		SRL_SUCCESS		- certificate added to db fine

 		other pass thru errors from the db routines (later)

 */
short SRLi_AddCertToDB(ulong rt_session, Bytes_struct *asn1data, Cert_struct *dec_cert, short trustedFlag,
					   enum AsnTypeFlag TypeFlag, const char *kid_str)
{
	Bytes_struct	ciTemplate, big_block;
	short			err, result;
	DB_Kid			entry_kid;
	DB_Data			entry_data, *ex_data, *compare_data;	/* existing data */
	SRLSession_struct *session;
	long TempHashValue = 0;
	long DNHashValue = 0;
#ifdef SCC_NO_USER_CERTIFICATE
	if (dec_cert &&
		dec_cert->exts &&
		dec_cert->exts->basicCons &&
		dec_cert->exts->basicCons->value &&
		((Basic_cons_struct *)dec_cert->exts->basicCons->value)->cA_flag == TRUE)
	{
		/* This certificate is an issuer certificate, so it's OK to store
		   it in the database. */
	}
    else if (dec_cert &&
                (0 == strcmp (dec_cert->subject, dec_cert->issuer)))
    {
                /* It's also OK to store any self-issued certificate. */
    }

	else {
		return SRL_SUCCESS;
	}
#endif

	err =  SRLi_GetRetSessionFromRef(&session, rt_session);
	if(err != SRL_SUCCESS)
		return(err);

	/* to start off our process of adding the indicated certificate to the
	 * local storage db file, we will create the index matching template info that
	 * can be searched on.  This is stored with with the user's DN as it's
	 * keying identifier.  If we are told that an entry exists for the given
	 * DN, we will need to do further work to see if this is a different
	 * cert.
	 */

	if ((dec_cert->subject[0] == '\0') || (dec_cert->subject[3] == '\0'))
		return (SRL_INVALID_DN);

	/* Get the certificate type based on the contents of  dec_cert */

	/* create an index matching template from the decoded cert data */
	err = SRLi_BuildCertIndexTemplate(dec_cert, &ciTemplate, trustedFlag, asn1data, TypeFlag);

	if(err != SRL_SUCCESS)
		return(err);

	if (kid_str != NULL)
	{
		/* attempt to insert an entry for the given cert using the name passed id */
		entry_kid.item_len = strlen(kid_str)+1;
		entry_kid.item_ptr = strdup(kid_str);
	}
	else
	{
		/* attempt to insert an entry for the given cert/DN */
		entry_kid.item_len = strlen(dec_cert->subject) +1;		/* the subjects DN */
		
		/* Copy the subject DN (since it will normalized) */
		entry_kid.item_ptr = calloc (1, strlen (dec_cert->subject)+1);
		if (entry_kid.item_ptr == NULL)
			return (SRL_MEMORY_ERROR);
		strcpy(entry_kid.item_ptr, dec_cert->subject);
	}

	entry_data.item_len = ciTemplate.num;			/* the search/match data */
	entry_data.item_ptr = (char *) ciTemplate.data;
	TempHashValue = 0;
	// Get the Hash of the Template, for storage
	db_CalcHash (session->db_certRefSession,&entry_data, NULL, NORMALIZED,
				&TempHashValue, 0, DB_INSERT);
	/*
	* Insert into the db file associated with this session
	* along with the related template hash - It will return
	* the DN Hash
	*/
	err = db_StoreItem(session->db_certRefSession, &entry_kid, &entry_data, 
						&TempHashValue, DB_INSERT);
	DNHashValue = TempHashValue;
	/* check to see if we have an existing entry for the given DN */
	if(err == DB_NO_INSERT)
	{
		/* need to retrieve the current entry so we can determine if we
		 * need to add to it.
		 */
		err = db_GetEntry(session->db_certRefSession, TempHashValue, &entry_kid, &ex_data);
		if(err != DB_NO_ERR)
		{
			if(ciTemplate.data)
			{
				free(ciTemplate.data);
				ciTemplate.data = NULL;
			}
			if(entry_kid.item_ptr)
			{
				free (entry_kid.item_ptr);
				entry_kid.item_ptr = NULL;
			}
			return(DB2SRLerr(err));	/* complete failure, tell caller */
		}

		/* got the entry, see if any of it matches our current cert
		 * that we are to add.  This has to be an EXACT match in order
		 * for us to decide not to add it.
		 */
		result = SRLi_CompareTemplateSearchCriteria(ex_data, &ciTemplate);

		if(result == 0)	/* if exact match */
		{
			if(entry_kid.item_ptr)
				free (entry_kid.item_ptr);
			/* modification: Add additional check where we
			 * compare the asn.1 encoded data - if they
			 * match, then we will return. If there is some
			 * difference, we will replace the entry in the
			 * database with the passed in asn.1 data. At
			 * this point we are under the assumption that
			 * the passed in one must be good, and the
			 * current entry must have become corrupted
			 * somehow.
			 */
			entry_kid.item_len = ciTemplate.num;			/* the search/match data */
			entry_kid.item_ptr = (char *) ciTemplate.data;
			err = db_GetEntry(session->db_certRefSession, 0, &entry_kid,  &compare_data);
			err = DB2SRLerr(err);
			if(err != DB_NO_ERR)
			{
				if(ciTemplate.data)
				{
					free(ciTemplate.data);
					ciTemplate.data = NULL;
				}
				return(DB2SRLerr(err));	/* complete failure, tell caller */
			}
			
			/* do a mem compare on the asn.1 data itself */
			if(asn1data->num == compare_data->item_len)	/* not different */
			{
				/* see if they are equal */
				if(memcmp(compare_data->item_ptr, asn1data->data, compare_data->item_len) == 0)
				{
					/* then exactly the same, no need to modify entry */
					if(compare_data)
					{
						free(compare_data->item_ptr);/* free up stuff we don't need anymore */
						free(compare_data);
						compare_data = NULL;
					}
					if(ex_data)
					{
						free(ex_data->item_ptr);
						free(ex_data);
						ex_data = NULL;
					}
					if(ciTemplate.data)
					{
						free(ciTemplate.data);
						ciTemplate.data = NULL;
					}

				
					/* we are not going to tell caller that they tried
					 * inserting something that already exists, just
					 * tell them no error. (could change later...)
					 */
					return(SRL_SUCCESS);
				}
				
			}
			/* don't need the db copy of the asn.1 data, free it up */
			if(compare_data)
			{
				free(compare_data->item_ptr);
				free(compare_data);
				compare_data = NULL;
			}

			TempHashValue = 0;
			// Get the Hash of the Template, for storage
			db_CalcHash (session->db_certRefSession,&entry_kid, &entry_data, NORMALIZED,
				&TempHashValue, 0, DB_REPLACE);
			DNHashValue = TempHashValue;

			/* else they are different, do a replace. Need to 
			 * save out the asn.1 data using the entries
			 * template.
			 */
			err = db_StoreItem(session->db_certRefSession, &entry_kid, (DB_Item*)asn1data, 
				&TempHashValue, DB_REPLACE);
			
			/* the existing dn template already contains a ref for this cert, and
			 * we know from our earlier comparison that they already match, so
			 * we only need to free up and return.
			 */
			if(ex_data)
			{
				free(ex_data->item_ptr);	/* got our own copy */
				free(ex_data);
				ex_data = NULL;
			}

            if(ciTemplate.data)
			{
				free(ciTemplate.data);
				ciTemplate.data = NULL;
			}
			
			return(DB2SRLerr(err));

		}

		/* at this point we know that the cert is not in the db yet,
		 * but we do have other entries for the user DN.  Append
		 * our search template on to the existing one(s), and rewrite
		 * this updated search template to the file.
		 */

		/* create larger block that can contain old + new */
		big_block.num = ex_data->item_len + ciTemplate.num;

		big_block.data = malloc(big_block.num);

		if(big_block.data == NULL)
		{
			if(ciTemplate.data)
			{
				free(ciTemplate.data);
				ciTemplate.data = NULL;
			}
			if(ex_data)
			{
				free(ex_data->item_ptr);	/* got our own copy */
				free(ex_data);
				ex_data = NULL;
			}
			if(entry_kid.item_ptr)
			{
				free (entry_kid.item_ptr);
				entry_kid.item_ptr = NULL;
			}
			return(SRL_MEMORY_ERROR);
		}

		memcpy(big_block.data, ex_data->item_ptr, ex_data->item_len);
		memcpy( &(big_block.data[ex_data->item_len]),
			ciTemplate.data, ciTemplate.num);

		// Get the Hash of the Template, for storage
		TempHashValue = 0;
		db_CalcHash (session->db_certRefSession,&entry_kid, &entry_data, NORMALIZED,
				&TempHashValue, 0, DB_REPLACE);
		DNHashValue = TempHashValue;


		/* replace the old entry for this DN (DNHaashValue gets reset here) */
		err = db_StoreItem(session->db_certRefSession, &entry_kid, (DB_Item*)&big_block, 
			&DNHashValue, DB_REPLACE);

		/* clean up stuff we don't need anymore */
		if(big_block.data)
		{
			free(big_block.data);
			big_block.data = 0;
		}
		if(ex_data)
		{
			free(ex_data->item_ptr);
			free(ex_data);
			ex_data = 0;
		}
		if(err != DB_NO_ERR)
		{
			if(ciTemplate.data)
			{
				free(ciTemplate.data);
				ciTemplate.data = NULL;
			}
			if(entry_kid.item_ptr)
			{
				free (entry_kid.item_ptr);
				entry_kid.item_ptr = NULL;
			}
			return(DB2SRLerr(err));

		}

		/* now fall down to below to store the raw asn.1 encoded cert
		 * into data base
		 */

	}

	if(err == DB_NO_ERR)
	{
		/* Free the normalized db kid */
		if (entry_kid.item_ptr != NULL)
			free (entry_kid.item_ptr);

		/* dn and searching template added ok.  Now we will add the asn.1
		 * encoded certificate to the database using the search template
		 * as the keying identifier.
		 */
		entry_kid.item_len = ciTemplate.num;			/* the search/match data */
		entry_kid.item_ptr = (char *) ciTemplate.data;

		entry_data.item_len = asn1data->num;		/* the asn1 encoded cert itself */
		entry_data.item_ptr = (char *) asn1data->data;
		// The storage of the Cert does require the template Hash

		/* insert into data base */
		err = db_StoreItem(session->db_certRefSession, &entry_kid, &entry_data, 
			&DNHashValue, DB_INSERT);

		if(ciTemplate.data)
		{
			free(ciTemplate.data);
			ciTemplate.data = NULL;
		}
	}

	return(DB2SRLerr(err));	/* tell caller what the result is */


}


/*
SRLi_BuildCertIndexTemplate()


short SRLi_BuildCertIndexTemplate(Cert_struct *dec_cert, Bytes_struct *ciTemplate,
 short trustedFlag, Bytes_struct *certData)


This routine is given a decoded certificate, it pulls out the information
that is used for searching the database, and stuffs it all into a datablock
for storage in the database file. (This is part of the index information for the
certifcate)

parameters:
	dec_cert (input) = ptr to the cert that info is being gathered from

	ciTemplate (input/output) = ptr to a Bytes_struct, will be filled with the
							length and data ptr as the template is built.

	trustedFlag (input) = if cert has special trusted status (pub key to be loaded into
							key cache with trusted status).
							
	(3Sep98 mod)
	certData (input) = ptr to Bytes_struct which contains the asn.1 encoded cert

returns:
	SRL_SUCCESS			- worked fine
	SRL_MEMORY_ERROR			- out of memory


*/
short SRLi_BuildCertIndexTemplate(Cert_struct *dec_cert, Bytes_struct *ciTemplate, short trustedFlag,
Bytes_struct *certData, enum AsnTypeFlag TypeFlag)
{
	uchar			*tempPtr;
	short			tempShort;
	long			len;
	uchar			pcount;
	uchar			cert_type;
	Policy_struct	*polyPtr;
	Bytes_struct	kmid;
	char			*email = NULL;
	Gen_names_struct *tmpGenName;
	short			err;
	RDN_LL			*parsedDN, *rdn;
	long			hashLen;
	CM_HashValue	hashValue;
    int debug_len = 0;
	
	ciTemplate->num = 4;	/* first 4 bytes used for length of template */
    debug_len = 4;
	/* first determine how much storage we will require */
	if(DB_TEMPLATE_FLAG == 1)
	{
		/* have a version field in the template */
		ciTemplate->num++;	/* it's one byte */
	}
		/*
	 * Check Template version, version 2 and greater added
	 * CRL Distribution Point processing, along with identifying
	 * the type of the CRL. DP's are now added according to the
	 * DP name.
	 */
	if ((DB_TEMPLATE_FLAG == 1) && (CERT_TEMPLATE_VERSION >= 3))
	{
		/* Add in the 1 byte Certificate type to the template */
		/* Certificate Type signifies Certificate Authority, or End Entitiy */
		ciTemplate->num ++;
	}

	ciTemplate->num += strlen(dec_cert->pub_key.oid) + 1;
	ciTemplate->num += strlen(dec_cert->val_not_before) + 1;
	ciTemplate->num += strlen(dec_cert->val_not_after) + 1;
	ciTemplate->num += strlen(dec_cert->issuer) + 1;	/* DN of issuer plus null */

	/* Find the e-mail address (either in subjAltName extension or subject DN)
	Note: The CM library only supports one e-mail address, so the first one
	in the subjAltName extension is the one used.  If none are present in the
	extension, then the subject DN is checked for one. */
	email = NULL;
	parsedDN = NULL;

	/* cert template version 1 includes an email address field */
		if ((dec_cert->exts != NULL) && (dec_cert->exts->subjAltName != NULL))
		{
			tmpGenName = dec_cert->exts->subjAltName->value;
			while ((tmpGenName != NULL) && (email == NULL))
			{
				if (tmpGenName->gen_name.flag == CM_RFC822_NAME)
					email = tmpGenName->gen_name.name.rfc822;
	
				tmpGenName = tmpGenName->next;
			}
	
		}
	
		if (email == NULL)
		{ 
		/*	email = strstr(dec_cert->subject, EMAIL_ADDR_OID); */
			email = strstr(dec_cert->subject, "emailAddress");
			
			if (email != NULL)
			{
				err = SRLi_RetParseRDNSeq(dec_cert->subject, &parsedDN);
				if (err != SRL_SUCCESS)
					return err;
	
				email = NULL;
				rdn = parsedDN;
	
				while ((rdn != NULL) && (email == NULL))
				{
				/*	email = strstr(rdn->rdn, EMAIL_ADDR_OID); */
					email = strstr(rdn->rdn, "emailAddress");
					rdn = rdn->next;
				}
	
				/* Move pointer to just after "OID=" */
				if (email != NULL)
					email += strlen("emailAddress") + 1;
			}
		}	
		/* Add the length of the e-mail address */
		if (email != NULL)
			ciTemplate->num += strlen(email) + 1;
		else
			ciTemplate->num++;		/* just terminating NULL */
			

	/* two bytes for key length in bits */
	ciTemplate->num += 2;

	/* a long for the length of the serial num, plus the bytes length of the
	 * serial numb itself.
	 */
	ciTemplate->num += 4;
	ciTemplate->num += dec_cert->serial_num.num;

	/* one byte for special trusted status flag */
	ciTemplate->num += 1;

	/* one byte for poly count */
	ciTemplate->num++;

	polyPtr = SRLi_GetPolyPtr(dec_cert);
	pcount = 0;

	while(polyPtr != NULL)	/* add length of each poly oid C string */
	{
		ciTemplate->num += strlen(polyPtr->policy_id) + 1;
		/* point to next if there is one */
		polyPtr = polyPtr->next;
		pcount++;
	}

	/* 4 bytes for optional subject kmid len in bytes */
	ciTemplate->num += 4;

	/* check the cert version, so we know where the kmid
	 * info should be.
	 */
	kmid.num = 0;	/* def to none */
	kmid.data = 0;

	if(dec_cert->version == 1)
	{
		/* check for mosaic algorithm */
		if(0 == strcmp(gDSA_KEA_OID, dec_cert->pub_key.oid))
		{
			kmid.num = CM_KMID_LEN;
			kmid.data = dec_cert->pub_key.key.combo->kmid;
		}
	}
	else	/* for ver 2 or 3 */
	{
		/* if version 3, first check for an extension */
		if (dec_cert->version == 3)
		{
		    if ((dec_cert->exts != NULL) && (dec_cert->exts->subjKeyID != NULL))
            {                           /* Subject Key ID extension present */
                kmid.num =
                    ((Bytes_struct *)dec_cert->exts->subjKeyID->value)->num;
                kmid.data =
                    ((Bytes_struct *)dec_cert->exts->subjKeyID->value)->data;
            }
        }
	}

	if(kmid.num != 0)  	/* inc by required amount if any */
	{
		ciTemplate->num += kmid.num;			/* data to store */
	}

	/* cert template version 2 added a hash value field */
		/* generate a hash of the raw asn.1 data - this should produce a very unique tag.
		 * For now, use SHA1 - change if you like
		 */
		/* err = SRLi_RSA_hash(certData, 5, &hashValue);  could use MD5 here... */
		err = CM_HashData(certData, hashValue);
		if(err != SRL_SUCCESS)
		{
			SRLi_FreeRDN_LL(&parsedDN);
			return(err);
		}
	
		ciTemplate->num += sizeof(long); /* inc count to handle hash size recording */
		ciTemplate->num += SRL_HASH_LEN; /* inc data count by size of hash */
	
	/* allocate memory for this block of data we will create */
	ciTemplate->data = (uchar *) malloc(ciTemplate->num);

	if(ciTemplate->data == NULL)
	{
		ciTemplate->num = 0;

		SRLi_FreeRDN_LL(&parsedDN);
		return(SRL_MEMORY_ERROR);
	}

	/* start with the length of the template block, this includes the
	 * length field itself in the byte count.
	 */
	tempPtr = (uchar *) ciTemplate->data;
	memcpy(tempPtr, &(ciTemplate->num), sizeof(long));
	if(SRLisLittleEndian())
		SRLi_FlipLongs(tempPtr, 1);
	
	/* set the template version flag  */
	tempPtr[0] = CERT_TEMPLATE_VERSION;
	
	tempPtr += 4;
	
	// this may be a bug
	*tempPtr++ = CERT_TEMPLATE_VERSION;	/* store the template version */


	/*
	 * Check Template version, version 3 and greater added
	 * Certificate Type processing.
	 */

		/* Add in the Cert type to the template */
		cert_type = (uchar) SRLi_GetCertType (dec_cert, TypeFlag);

		*tempPtr++ = cert_type;





	/* now copy the data to the block */
	len = strlen(dec_cert->pub_key.oid) + 1;
	memcpy(tempPtr, dec_cert->pub_key.oid, len);
	tempPtr += len;

	len = strlen(dec_cert->val_not_before) + 1;
	memcpy(tempPtr, dec_cert->val_not_before, len);
	tempPtr += len;

	len = strlen(dec_cert->val_not_after) + 1;
	memcpy(tempPtr, dec_cert->val_not_after, len);
	tempPtr += len;

	len = strlen(dec_cert->issuer) + 1;
	memcpy(tempPtr, dec_cert->issuer, len);
	tempPtr += len;


	/* cert template version 1 includes an email address field */
		/* Store the email address and free the parsed DN */
		if (email != NULL)
		{
			len = strlen(email) + 1;
			memcpy(tempPtr, email, len);
		}
		else
		{
			len = 1;
			*tempPtr = 0;
		}
	
		tempPtr += len;
		SRLi_FreeRDN_LL(&parsedDN);


	/* determine what key alg used so we know which pub key
	 * struct is currently in use.
	 */
	if((strcmp(dec_cert->pub_key.oid, gDSA_OID) == 0) ||
		(strcmp(dec_cert->pub_key.oid, gOIW_DSA) == 0) ||
		(strcmp(dec_cert->pub_key.oid, gKEA_OID) == 0)) // ||
// changed        (strcmp(dec_cert->pub_key.oid, gANSI_DH_OID) == 0)  ||
// changed		(strcmp(dec_cert->pub_key.oid, gOLD_DH_OID) == 0))
	{
		tempShort = (short) (dec_cert->pub_key.key.y->num * 8);
	}
	else if(strcmp(dec_cert->pub_key.oid, gRSA_OID) == 0)
	{
		/* rsa keys. */
		tempShort = (short) (dec_cert->pub_key.key.rsa->modulus.num * 8);
	}
	else	/* fortezza v.1 cert - combo keys. We will record kea len here (same as dsa right now) */
		tempShort = (short)(dec_cert->pub_key.key.combo->kea_y.num * 8);


	memcpy(tempPtr, (char *) &tempShort, 2);
	if (SRLisLittleEndian())
		SRLi_FlipShorts(tempPtr, 1);
	tempPtr += 2;

	/* store the cert serial numb len then val */
	memcpy(tempPtr, (char *) &(dec_cert->serial_num.num), 4);
	if (SRLisLittleEndian())
		SRLi_FlipLongs(tempPtr, 1);
	tempPtr += 4;

	memcpy(tempPtr, dec_cert->serial_num.data, dec_cert->serial_num.num);
	tempPtr += dec_cert->serial_num.num;

	/* one byte for special trusted status flag */
	*tempPtr++ = (uchar) (trustedFlag & 0x00FF);

	/* store the number of policies */
	*tempPtr++ = (uchar) (pcount & 0x00FF);
	polyPtr = SRLi_GetPolyPtr(dec_cert);

	while(pcount--)
	{
		len = strlen(polyPtr->policy_id) + 1;
		memcpy(tempPtr, polyPtr->policy_id, len);
		tempPtr += len;
		polyPtr = polyPtr->next;
	}

	len = 0;
	memcpy(tempPtr, &len, 4); /* default to no kmid */

	/* kmid is an optional field in ver 2/3 certs, in the case
	 * of a version 3 cert, this info can be put in an extension,
	 * in which case we will ignore the base cert field.  For
	 * version 1 certs, we need to get the kmid out of the
	 * key data area
	 */
	if(kmid.num != 0)
	{
		memcpy(tempPtr,  &(kmid.num), 4);
	if (SRLisLittleEndian())
		SRLi_FlipLongs(tempPtr, 1);
		tempPtr += 4;

		memcpy(tempPtr, kmid.data, kmid.num);
		tempPtr+= kmid.num;
	}
	else tempPtr += sizeof(long);
	
	
	/* cert template version 2 added a hash value field */
	
		/* store the calculated hash len and value */
		hashLen = SRL_HASH_LEN;
		memcpy(tempPtr, &hashLen, sizeof(long));
		
		if (SRLisLittleEndian())
			SRLi_FlipLongs(tempPtr, 1);
		tempPtr += sizeof(long);
	

		memcpy(tempPtr, &hashValue, SRL_HASH_LEN);
		tempPtr += SRL_HASH_LEN;

	/* all done here */
	return(SRL_SUCCESS);


}

/*
SRLi_BuildCRLIndexTemplate()


short SRLi_BuildCRLIndexTemplate(CRL_struct *dec_crl, Bytes_struct *ciTemplate)


This routine is given a decoded CRL, it pulls out the information
that is used for searching the database, and stuffs it all into a datablock
for storage in the database file. (This is part of the index information for the
CRL)


*/
short SRLi_BuildCRLIndexTemplate(CRL_struct *dec_crl, Bytes_struct *ciTemplate,
Bytes_struct *CRLData, enum AsnTypeFlag TypeMask)
{
	uchar			*tempPtr;
	long			len;
	uchar			crl_type = 0;
	time_t			RefreshTime = 0;
	long			hashLen;
	CM_HashValue	hashValue;
	short			err;

	ciTemplate->num = 4;	/* first 4 bytes used for length of template */
	if(DB_TEMPLATE_FLAG >= 1)
	{
		ciTemplate->num++;	/* add one byte for crl template version field */
	}
	
	/* first determine how much storage we will require */
	ciTemplate->num += strlen(dec_crl->signature) + 1;
	ciTemplate->num += strlen(dec_crl->thisUpdate) + 1;
	if(dec_crl->nextUpdate != 0)
		ciTemplate->num += strlen((const char *)dec_crl->nextUpdate) + 1;
	else
		ciTemplate->num += 	1;	/* write out a zero if nothing */

	/* crl template version 1 added a hash value field */
		/* generate a hash of the raw asn.1 data - this should produce a very unique tag.
		 * For now, use SHA1 - change if you like
		 */
		/* err = SRLi_RSA_hash(CRLData, 5, &hashValue);  could use MD5 here... */
		err = CM_HashData(CRLData, hashValue);
		if(err != SRL_SUCCESS)
			return(err);
	
		ciTemplate->num += sizeof(long); /* inc count to handle hash size recording */
		ciTemplate->num += SRL_HASH_LEN; /* inc data count by size of hash */

	/*
	 * Check Template version, version 2 and greater added
	 * CRL Distribution Point processing, along with identifying
	 * the type of the CRL. DP's are now added according to the
	 * DP name.
	 */
		/* Add in the 1 byte CRL type to the template */
		/* CRL Type signifies CRL, ARL, or Delta */
		ciTemplate->num ++;

	// Version 4 adds in the refresh time
	if (CRL_TEMPLATE_VERSION >= 4)
		ciTemplate->num += sizeof(time_t);


	/* allocate memory for this block of data we will create */
	ciTemplate->data = (uchar *) malloc(ciTemplate->num);

	if(ciTemplate->data == NULL)
	{
		ciTemplate->num = 0;
		return(SRL_MEMORY_ERROR);
	}
	/* now copy the data into the block we allocated */
	/* length of the block/template is first, includes the length field itself */
	tempPtr = (unsigned char *) ciTemplate->data;
	memcpy(tempPtr, &(ciTemplate->num), sizeof(long));
	if (SRLisLittleEndian())
		SRLi_FlipLongs(tempPtr, 1);

	/* put the template version flag in */
//	tempPtr[0] = DB_TEMPLATE_FLAG + DB_NORMALIZED_FLAG;
	tempPtr[0] = CRL_TEMPLATE_VERSION;
	tempPtr += 4;
	
		*tempPtr++ = CRL_TEMPLATE_VERSION;	/* store the template version */

		/*
	 * Check Template version, version 2 and greater added
	 * CRL Distribution Point processing, along with identifying
	 * the type of the CRL. DP's are now added according to the
	 * DP name.
	 */

		/* Add in the CRL type to the template */
		/* CRL Type signifies CRL, ARL, or Delta */
		crl_type = SRLi_GetCRLType (dec_crl, TypeMask);

		*tempPtr++ = crl_type;



	/* now copy the data to the block */
	len = strlen(dec_crl->signature) + 1;
	memcpy(tempPtr, dec_crl->signature, len);
	tempPtr += len;

	len = strlen(dec_crl->thisUpdate) + 1;
	memcpy(tempPtr, dec_crl->thisUpdate, len);
	tempPtr += len;

	if(dec_crl->nextUpdate != 0)	/* optional field */
	{
		len = strlen((const char *)dec_crl->nextUpdate) + 1;
		memcpy(tempPtr, dec_crl->nextUpdate, len);
		tempPtr += len;
	}
	else *tempPtr++ = 0;	/* write out zero - no next date field */

	/* crl template version 1 added a hash value field */
		/* store the calculated hash len and value */
		hashLen = SRL_HASH_LEN;
		memcpy(tempPtr, &hashLen, sizeof(long));
		
		if (SRLisLittleEndian())
			SRLi_FlipLongs(tempPtr, 1);
		tempPtr += sizeof(long);
	
		memcpy(tempPtr, &hashValue, SRL_HASH_LEN);
		tempPtr += SRL_HASH_LEN;

		if (CRL_TEMPLATE_VERSION >= 4)
		{
			// TEMPLATE3 added in a refresh time for CRL's
			RefreshTime = time(NULL);
			memcpy(tempPtr, &(RefreshTime), sizeof(time_t));
			if (SRLisLittleEndian())
				SRLi_FlipLongs(tempPtr, 1);

			tempPtr += sizeof(time_t);
		}
			


	/* all done here */
	return(SRL_SUCCESS);


}



/*
 short SRLi_UpdateCRLTemplate(CRL_struct *dec_crl, Bytes_struct *ciTemplate)

 This routine Updates the CRL Template and the associated object.
 Arguments:

  SRLSession_struct *session	Pointer to the SRL Session Structure
  DB_Item *base_template		The template was retrieved from the DB
  DB_Item *Template				The template that was matched from the DB
  DB_Item *entry_kid			The kid used to store the template
  DB_Item *object				The object to store.

*/
static short SRLi_UpdateCRLTemplate(SRLSession_struct *session, DB_Item *base_template, 
									DB_Item *Template, DB_Item *entry_kid, DB_Item *object)
{
	char *tempPtr = NULL;
	char	*template1 = NULL;
	char	*template2 = NULL;
	DB_Item templateToStore;
	DB_Item oldTemplate;

	time_t RefreshTime;
	long len, biglen, TempHashValue, DNHashValue, length;
	short err = 0;
	templateToStore.item_len = 0;
	templateToStore.item_ptr = NULL;
	// Function used to search the base template for the template
	// And when found:
	// 1. Update the CRL Refresh time
	// 2. Add it into the base template
	// 3. Remove the old template from the data base
	// 4. Add in the new template to the data base
	if (session == NULL)
		return SRL_INVALID_PARAMETER;
	if ((base_template == NULL) || (Template == NULL))
		return SRL_INVALID_PARAMETER;

	// Point to the Base Template
	tempPtr = base_template->item_ptr;

	// Get the total length
	biglen = base_template->item_len;


	// Copy into the old template (we have to delete)
	oldTemplate.item_len = base_template->item_len;
	oldTemplate.item_ptr = calloc(1, base_template->item_len);
	memcpy(oldTemplate.item_ptr, tempPtr, base_template->item_len);

	/*
	 * We can't call SRLi_GetMatchingCRLTemplate, because we need the
	 * Base template pointer to point to the actual match, so that
	 * we can modify the refresh time, and store back into the data
	 * base
	 */
	templateToStore.item_ptr = tempPtr;
	while (biglen != 0)
	{

		/* copy in this template size */
		memcpy(&len, tempPtr, sizeof(long)); /* length of this template in block */
		if (SRLisLittleEndian())
			SRLi_FlipLongs(&len, 1);
		len = len & 0x00FFFFFF;
		templateToStore.item_len = len;
		if(len == Template->item_len)
		{
			/* same size, do a straight comparison */
			if(memcmp(tempPtr, Template->item_ptr, len) == 0)	/* if they are equal */
			{
				RefreshTime = time(NULL);
				memcpy(tempPtr+(len-sizeof(time_t)), &(RefreshTime), sizeof(time_t));
				if (SRLisLittleEndian())
					SRLi_FlipLongs((tempPtr+(len-sizeof(time_t))), 1);
				break;
			}
		}
		else
		{
			/* Not so lucky!
			 * Strip out the Refresh Time
			 * and try again
			 */
			err = SRLi_StripCRLRefreshTime(&template1, tempPtr, len);
			if (err != SRL_SUCCESS)
				return -1;

			err = SRLi_StripCRLRefreshTime(&template2, Template->item_ptr,
											Template->item_len);
			if (err != SRL_SUCCESS)
				return -1;

			// Compare the striped templates
			if ((memcmp(template1, template2, len-(sizeof(time_t)))) == 0)
			{
				// MATCH Found, update the Refresh time
				RefreshTime = time(NULL);
				memcpy(tempPtr, &(RefreshTime), sizeof(time_t));
				if (SRLisLittleEndian())
					SRLi_FlipLongs((tempPtr+(len-sizeof(time_t))), 1);
				break;
			}
			if(template1)
			{
				free(template1);
				template1 = NULL;
			}
			if(template2)
			{
				free(template2);
				template2 = NULL;
			}
		} // End if

		/* move onto the next one, if there is one */
		tempPtr += len;
		templateToStore.item_ptr += len;
		biglen -= len;
	} // End while


	// Update the Time in the template to store
	if (templateToStore.item_ptr != NULL)
	{
		length = templateToStore.item_len;
		// Copy in the refresh time to the end
		memcpy(templateToStore.item_ptr+(length-sizeof(time_t)), &(RefreshTime), 
			sizeof(time_t));
		if (SRLisLittleEndian())
			SRLi_FlipLongs((templateToStore.item_ptr+(length-sizeof(time_t))), 1);
	}
	TempHashValue = 0;

	   db_RetrieveHash(session->db_CRLRefSession, entry_kid,  
						  &TempHashValue);


		/* replace the old entry for this DN */
		err = db_StoreItem(session->db_CRLRefSession, entry_kid, base_template, 
			&TempHashValue, DB_REPLACE);

		DNHashValue = TempHashValue;


		if (err != SRL_SUCCESS)
			return(DB2SRLerr(err));

		// Have to delete the object
		err = db_DeleteEntry(session->db_CRLRefSession, Template);

		// Store the object back in
	   err = db_StoreItem(session->db_CRLRefSession, &templateToStore, 
				(DB_Item*)object, &DNHashValue, DB_INSERT);



	free(oldTemplate.item_ptr);
	if (err != SRL_SUCCESS)
		return(DB2SRLerr(err));

	return SRL_SUCCESS;
}







static short SRLi_StripCRLRefreshTime( char **CRLtemplate, char *tempPtr, ulong len)
{
	/* Routine to strip out the refresh time from the CRL template */
	char *Ptr = NULL;
	*CRLtemplate = NULL;
	Ptr = calloc(1, len-(sizeof(time_t)));
	if (Ptr == NULL)
		return SRL_MEMORY_ERROR;

	memcpy(Ptr, tempPtr, len-sizeof(time_t));
	*CRLtemplate = Ptr;
	return SRL_SUCCESS;
}

static short SRLi_GetMatchingCRLTemplate(DB_Data *ex_data, Bytes_struct *ciTemplate, DB_Data *matchingTemp)
{
	char	*tempPtr = NULL;
	char	*template1 = NULL;
	char	*template2 = NULL;
	long	len, biglen;
	short	err = SRL_SUCCESS;

	/* basically step through the template chunks in the existing data
	 * and compare to the cert template provided by the caller.
	 * Do a comparison on ones that are of the same length, otherwise
	 * we know they are not same, and can skip to the next one.
	 */
	tempPtr = ex_data->item_ptr;
	biglen = ex_data->item_len;	/* length of the whole block of mem */

	// Strip out the Refresh time from the template

	while(biglen > 0)
	{
		/* copying to non-allocated block... */
		memcpy(&len, tempPtr, sizeof(time_t)); /* length of this template in block */
		if (SRLisLittleEndian())
			SRLi_FlipLongs(&len, 1);
		len = len & 0x00FFFFFF;

		if(len == ciTemplate->num)
		{
			/* same size, do a comparison */
			if(memcmp(tempPtr, ciTemplate->data, len) == 0)	/* if they are equal */
			{
				matchingTemp->item_ptr = (char *)calloc(1, len);
				if (matchingTemp->item_ptr == NULL)
					return -1;
				memcpy(matchingTemp->item_ptr, ex_data->item_ptr, len);
				matchingTemp->item_len = len;
				free (template2);
				return(0);
			}
			else
			{

				/* Not so lucky!
				* Strip out the Refresh Time
				* and try again
				*/
				err = SRLi_StripCRLRefreshTime(&template1, tempPtr, len);
				if (err != SRL_SUCCESS)
					return -1;
				err = SRLi_StripCRLRefreshTime(&template2, (char *)ciTemplate->data, len);

				// Compare the striped templates
				if ((memcmp(template1, template2, len-(sizeof(time_t)))) == 0)
				{
					// MATCH Found
					matchingTemp->item_ptr = (char *)calloc(1, len);
					if (matchingTemp->item_ptr == NULL)
						return -1;
					memcpy(matchingTemp->item_ptr, tempPtr, len);
					matchingTemp->item_len = len;

					if(template1)
					{
						free(template1);
						template1 = NULL;
					}
					if(template2)
					{
						free(template2);
						template2 = NULL;
					}
					return 0;
				} // Endif template1 and template2 compare
				if(template1)
				{
					free(template1);
					template1 = NULL;
				}
				if(template2)
				{
					free(template2);
					template2 = NULL;
				}
			}
		}

		/* move onto the next one, if there is one */
		tempPtr += len;
		biglen -= len;

	}
	if (template2)
	{
		free(template2);
		template2 = NULL;
	}
	/* didn't find a match */
	return(-1);	/* tell caller */


}

/*


SRLi_CompareTemplateSearchCriteria()

short SRLi_CompareTemplateSearchCriteria(DB_Data *ex_data, Bytes_struct *ciTemplate)

This low level utility routine is used to compare a read in search template block
from a database file against a given cert/crl template.  There are 1 or more
templates in the read in one, and we will tell caller if their ciTemplate
exatcly matches any of the ones from the file.  For an exact match we will
return 0.  For no match we return -1.

NOTE: No little endian conversion here - it is done when ciTemplate is built, thus
we don't have to worry about it...

Parameters:

	ex_data	(input) = existing db entry template data read from a db file

	ciTemplate(input) = template data from a cert/crl caller wishes to compare
						the existing search block against.


Returns:
	0		= ciTemplate exactly matches one of the templates in ex_data
	-1		= no match of ciTemplate within ex_data

*/

short SRLi_CompareTemplateSearchCriteria(DB_Data *ex_data, Bytes_struct *ciTemplate)
{
	char	*tempPtr;
	long	len, biglen;

	/* basically step through the template chunks in the existing data
	 * and compare to the cert template provided by the caller.
	 * Do a comparison on ones that are of the same length, otherwise
	 * we know they are not same, and can skip to the next one.
	 */
	tempPtr = ex_data->item_ptr;
	biglen = ex_data->item_len;	/* length of the whole block of mem */

	while(biglen > 0)
	{
		/* copying to non-allocated block... */
		memcpy(&len, tempPtr, 4); /* length of this template in block */
		if (SRLisLittleEndian())
			SRLi_FlipLongs(&len, 1);
		len = len & 0x00FFFFFF;

		if(len == ciTemplate->num)
		{
			/* same size, do a comparison */
			if(memcmp(tempPtr, ciTemplate->data, len) == 0)	/* if they are equal */
				return(0);
		}

		/* move onto the next one, if there is one */
		tempPtr += len;
		biglen -= len;

	}

	/* didn't find a match */
	return(-1);	/* tell caller */


}

/*
 * SRLi_CertInfoFromTemplate()
 *
 * short SRLi_CertInfoFromTemplate(dbCertEntryInfo_LL *certinfo,DB_Kid *tempKid)
 *
 * This routine parses out the information that is stored in the database
 * in an information template for a certificate, and puts it into a cert
 * info type structure for the caller.  The fields of the struct are
 * allocated within this routine as needed, those fields for which there
 * is no info in the cert for will be set to null.  (The caller should
 * call CM_FreeCertInfo() when they are done with the struct and it's contents)
 *
 *
 * parameters:
 *
 *		certinfo (input/output) - storage for a info struct ptr which will
 *				be filled in with the cert info as spec'd in the template
 *
 *		ctemplate (input) - the  db template info for the cert entry.
 *
 * returns:
 * 			SRL_SUCCESS - worked fine
 *			SRL_MEMORY_ERROR - out of memory
 *			SRL_INVALID_PARAMETER - null param passed into this routine
 *
 */
short SRLi_CertInfoFromTemplate(ulong db_session, dbCertEntryInfo_LL **certinfo,DB_Data *ctemplate)
{
	dbCertEntryInfo_LL	*theInfo, *prevInfo;
	long			blocklen, len, count, len2, hashValue = 0;
	uchar			*tempPtr, *st2;
	Policy_struct	*polyPtr, *tempPoly;
	uchar			tver, crtver;
	DB_Kid Tkid;

	/* check params */
	if((certinfo == 0) || (ctemplate == NULL))
		return(SRL_INVALID_PARAMETER);

	/* make sure caller has an empty struct to start with */
	*certinfo = 0;

	prevInfo = 0;
	theInfo = 0;

	blocklen = ctemplate->item_len;	/* length of all data */


	/* first 4 bytes are length of the first block of data */
	tempPtr = (uchar *) ctemplate->item_ptr;	/* start at the top */

	while(blocklen > 0)	/* till finished parsing out the fields */
	{
		if(theInfo == 0)	/* did we start the linked list yet */
		{
			theInfo = (dbCertEntryInfo_LL *) malloc(sizeof(dbCertEntryInfo_LL));
			if(theInfo == 0)
				return(SRL_MEMORY_ERROR);
			prevInfo = theInfo;	/* record for looping */
			prevInfo->DBid = 0;

		}
		else	/* more than one item's data in template, create link */
		{
			prevInfo->next = (dbCertEntryInfo_LL *) malloc(sizeof(dbCertEntryInfo_LL));
			if(prevInfo->next == 0)
				goto error_cleanup;

			prevInfo = prevInfo->next;	/* record for looping */
			prevInfo->DBid = 0;
		}
		prevInfo->algOID = 0;
		prevInfo->validFrom = 0;
		prevInfo->validTill = 0;
		prevInfo->issuer_DN = 0;
		prevInfo->emailAddr = 0;

		prevInfo->serialNum = 0;
		prevInfo->trusted = FALSE;
		prevInfo->poly = 0;
		prevInfo->sub_kmid = 0;
		prevInfo->pkey_len = 0;

		prevInfo->db_kid = 0;
		
		prevInfo->next = 0;

		memcpy((char *)&len, tempPtr, 4); 	/* length of just this block */
		if (SRLisLittleEndian())
			SRLi_FlipLongs(&len, 1);
		tver = (uchar)((len & 0xFF000000) >> 24);
		len = len & 0x00FFFFFF;

		// Get the hash of the template
		Tkid.item_len = len;
		Tkid.item_ptr = (char *)tempPtr;

	   db_RetrieveHash(db_session, &Tkid,  
						  &hashValue);
	   prevInfo->DBid = hashValue;

		blocklen -= len;	/* sub amount we are going to parse */

		tempPtr += 4;	/* move past length field */
		prevInfo->tver = tver;

		if (tver >= DB_TEMPLATE_FLAG)
			crtver = *tempPtr++;
		else
			crtver = 0;
		

		if(crtver >= 3)
			prevInfo->CertType = *tempPtr++; 
		else
			prevInfo->CertType = SRL_CERT_TYPE;  // Default cert type

		/* Get the Cert Type */
		/* the next field in the block is the public key algorithm oid */
        len = strlen((char *) tempPtr) + 1;	/* oid is null terminated string in block */

		prevInfo->algOID = (char *)malloc(len);
		if(prevInfo->algOID == 0)
			goto error_cleanup;

		memcpy(prevInfo->algOID, tempPtr, len);

		/* move onto next section in block, the validity dates as strings. First
		 * is the not before date, then the not after date.
		 */
		tempPtr += len;	/* skip the alg oid */
		len = strlen((char *)tempPtr) + 1;	/* get len of valid not before date string */

		prevInfo->validFrom = (CM_TimePtr )malloc(sizeof(CM_Time));
		if (prevInfo->validFrom == NULL)
			return SRL_MEMORY_ERROR;
		memcpy(*prevInfo->validFrom, tempPtr, len);

		st2 = &tempPtr[len];	/* offset to 2nd date string */
		len = strlen((char *)st2) + 1;		/* get len of valid not after date string */

		prevInfo->validTill = (CM_TimePtr)malloc(sizeof(CM_Time));
		if (prevInfo->validTill == NULL)
			return SRL_MEMORY_ERROR;
		memcpy(*prevInfo->validTill, st2, len);

		/* move past date fields to the issuer dn field in the info block */
		tempPtr = st2;	/* jump to not after string start */
		tempPtr += len;	/* jump past end of valid not after string */

		len = strlen((char *)tempPtr) + 1;	/* len of dn plus null char */

		prevInfo->issuer_DN = (char *)malloc(len);
		if(prevInfo->issuer_DN == 0)
			goto error_cleanup;
		memcpy(prevInfo->issuer_DN, tempPtr, len);

		/* move past issuer dn to the email address field in the info block */
		tempPtr += len;	/* jump past end of issuer dn string */


		if((tver >= DB_TEMPLATE_FLAG) && (CERT_TEMPLATE_VERSION >= 2))
		{
			len = strlen((char *)tempPtr) + 1;	/* len of email address + null */

			if (len > 1)	/* if email address is more than just the Null */
			{
				prevInfo->emailAddr = (char *)malloc(len);
				if (prevInfo->emailAddr == 0)
					goto error_cleanup;
				memcpy(prevInfo->emailAddr, tempPtr, len);
			}
			/* move past email address to the public key length in bits. This
			 * next field is a short (2 bytes).
			 */
			tempPtr += len;
		}
		
		len = 2;	/* key length in bits field is 2 bytes wide */
		memcpy(& (prevInfo->pkey_len), tempPtr, len);
		if (SRLisLittleEndian())
			SRLi_FlipShorts(&(prevInfo->pkey_len), 1);
		tempPtr += len;

		/* the cert serial number len and then value */
		len = 4;	/* read the length field from the block */
		memcpy(&len2, tempPtr, len);
		if (SRLisLittleEndian())
			SRLi_FlipLongs(&len2, 1);
		tempPtr += len;	/* skip length field, address serial num */

		prevInfo->serialNum  = (Bytes_struct *)malloc(sizeof(Bytes_struct));
		if(prevInfo->serialNum == 0)
			goto error_cleanup;
		prevInfo->serialNum->num = len2;
		prevInfo->serialNum->data = (uchar *)malloc(len2);
		if(prevInfo->serialNum->data == 0)
			goto error_cleanup;
		memcpy(prevInfo->serialNum->data, tempPtr, len2);

		/* move past the serial num value */
		tempPtr += len2;

		/* pull out the trusted status flag */
		prevInfo->trusted = (char)(*tempPtr++);

		/* move to the next field, which is a count of how many policy oid
		 * strings are concatenated together in the block. The count is
		 * held in a single byte
		 */

		count = *tempPtr;	/* get the policy oid string count */
		tempPtr++;	/* move past the count field */

		/* create linked list */
		if(count > 0)	/* do we need to create a list */
		{
			prevInfo->poly = (Policy_struct *) malloc(sizeof(Policy_struct));
			if(prevInfo->poly == 0)
				goto error_cleanup;
			polyPtr = prevInfo->poly;	/* start at top, and init fields */
			polyPtr->next = 0;
			polyPtr->qualifiers = 0;

			while(count--)
			{
				len = (strlen((char *)tempPtr) + 1);
				polyPtr->policy_id = malloc(len);
				if(polyPtr->policy_id == 0)
					goto error_cleanup;
				memcpy(polyPtr->policy_id, tempPtr, len);

				tempPtr += len;	/* move to start of next */
				if(count != 0)	/* if not the last one yet */
				{
					polyPtr->next = (Policy_struct *) malloc(sizeof(Policy_struct));
					if(polyPtr->next == 0)
						goto error_cleanup;
					polyPtr = polyPtr->next;	/* address next, and init fields */
					polyPtr->next = 0;
					polyPtr->qualifiers = 0;
					polyPtr->policy_id = 0;
				}
			}
		}

		/* the next field contains length of the subj id value  */
		memcpy(&len, tempPtr, 4); 		/* get length (4 bytes) */
		if (SRLisLittleEndian())
			SRLi_FlipLongs(&len, 1);
		tempPtr += 4;
		if(len > 0)	/* if there is a subj id val */
		{
			prevInfo->sub_kmid = (Bytes_struct *)malloc(sizeof(Bytes_struct));
			if(prevInfo->sub_kmid == 0)
				goto error_cleanup;
			prevInfo->sub_kmid->num = len;
			prevInfo->sub_kmid->data = (uchar *)malloc(len);
			if(prevInfo->sub_kmid->data == 0)
				goto error_cleanup;
			memcpy(prevInfo->sub_kmid->data, tempPtr, len);
			tempPtr+= len;
		}
		
		/* next part of the template will contain a length and hash */
		if((tver >= DB_TEMPLATE_FLAG) && (crtver >= CERT_TEMPLATE_VERSION2))
		{
		
			memcpy(&len, tempPtr, sizeof(long));
			if (SRLisLittleEndian())
				SRLi_FlipLongs(&len, 1);
			tempPtr += sizeof(long);
			prevInfo->db_kid = (Bytes_struct *)malloc(sizeof(Bytes_struct));
			if(prevInfo->db_kid == 0)
				goto error_cleanup;
			prevInfo->db_kid->num = len;
			prevInfo->db_kid->data = (uchar *) malloc(len);
			if(prevInfo->db_kid->data == 0)
				goto error_cleanup;
			memcpy(prevInfo->db_kid->data, tempPtr, len);
			
			tempPtr += len;	/* move forward - in prep for next if any */
		}
		

	} /* end of while loop */

	/* end of data held in info block, if we got here, then we must be
	 * done pulling stuff out of the template...
	 */
	*certinfo = theInfo;	/* give caller ref to the information */
	return(SRL_SUCCESS);

error_cleanup:
/*	put this code in CM_FreeCertInfoContents(dbCertEntryInfo_LL *certinfo)
    void CM_FreeCertInfoContents(dbCertEntryInfo_LL *certinfo)
    if(certinfo == 0) return;
*/

	while(theInfo != 0)
	{
		if(theInfo->algOID != 0)
			free(theInfo->algOID);
		if(theInfo->issuer_DN != 0)
			free(theInfo->issuer_DN);
		if(theInfo->emailAddr != 0)
	
			free(theInfo->emailAddr);
	
		if(theInfo->serialNum != 0)
		{
			if(theInfo->serialNum->data != 0)
				free(theInfo->serialNum->data);
			free(theInfo->serialNum);
		}
		if(theInfo->poly != 0)
		{
			tempPoly = theInfo->poly;
			while(tempPoly != 0)
			{
				theInfo->poly = tempPoly->next;
				if(tempPoly->policy_id != 0)
					free(tempPoly->policy_id);
					
				free(tempPoly);
				tempPoly = theInfo->poly;
			}
		}
		if(theInfo->sub_kmid != 0)
		{
			if(theInfo->sub_kmid->data != 0)
				free(theInfo->sub_kmid->data);
			free(theInfo->sub_kmid);
		}
		
		if(theInfo->db_kid != 0)
		{
			if(theInfo->db_kid->data != 0)
				free(theInfo->db_kid->data);
			free(theInfo->db_kid);
		}
		
	
		theInfo->algOID = 0;
		theInfo->validFrom = 0;
		theInfo->validTill = 0;
		theInfo->issuer_DN = 0;
	
		theInfo->emailAddr = 0;
		theInfo->serialNum = 0;
		theInfo->poly = 0;
		theInfo->sub_kmid = 0;
		theInfo->pkey_len = 0;
		theInfo->db_kid = 0;
	
		prevInfo = theInfo->next;
		
		free(theInfo);
		theInfo = prevInfo;
	
	}
	return(SRL_MEMORY_ERROR);

}


/*

  short SRLi_TemplateFromCertInfo(DB_Kid *kid, dbCertEntryInfo_LL *certinfo)

  This routine builds a db kid type template using the certinfo provided.
  The caller provides a ptr to an existing kid struct which this routine
  will fill in with a newly allocated buff.

  returns:
  		SRL_SUCCESS			- worked fine
  		SRL_INVALID_PARAMETER	- bad parameter passed to the routine
  		SRL_MEMORY_ERR		- out of memory.

 */

short SRLi_TemplateFromCertInfo(DB_Kid *kid, dbCertEntryInfo_LL *certinfo)
{
	long	len = 0;
	char	*tempPtr, pcount;
	Policy_struct	*polyPtr;

	if((kid == 0) || (certinfo == 0))
		return(SRL_INVALID_PARAMETER);

	kid->item_ptr = 0;	/* none yet */
	kid->item_len = 0;

	/* figure out the amount of storage the info will take up */
	len = 4;	/* template's start with their length */
	if(DB_TEMPLATE_FLAG == 1)
		len++;	/* we store a cert template version byte */
	len++; /* We store the cert type */
	len += strlen(certinfo->algOID) + 1;	/* add 1's here for null terminated c strings */
	len += strlen(certinfo->validFrom[0]) + 1;
	len += strlen(certinfo->validTill[0]) + 1;
	len += strlen(certinfo->issuer_DN) + 1;


	if(CERT_TEMPLATE_VERSION >= 1)	/* store email address */
	{
		if (certinfo->emailAddr != NULL)
			len += strlen(certinfo->emailAddr) + 1;
		else
			len++;
	}
	
	/* two bytes for key length in bits */
	len += 2;

	/* a long for the length of the serial num, plus the bytes length of the
	 * serial numb itself.
	 */
	len += 4;
	len += certinfo->serialNum->num;

	/* one byte for trust status */
	len += 1;

	/* one byte for poly count */
	len++;
	polyPtr = certinfo->poly;	/* traverse the linked list */
	pcount = 0;

	while(polyPtr != 0)
	{
		len += strlen(polyPtr->policy_id) + 1;
		/* point to next if there is one */
		polyPtr = polyPtr->next;
		pcount++;
	}
	/* 4 bytes for optional subject kmid len in bytes */
	len += 4;

	/* plus the actual length of the kmid data (if any) */
	if(certinfo->sub_kmid != 0)
		len += certinfo->sub_kmid->num;
		
	if(CERT_TEMPLATE_VERSION >= 2 && (certinfo->db_kid != 0))	/* store hash value */
	{
		len += sizeof(long);
		len += certinfo->db_kid->num;
	}

	/* allocate memory for this block of data we will create */
	kid->item_ptr = (char *) malloc(len);
	if(kid->item_ptr == 0)
		return(SRL_MEMORY_ERROR);

	kid->item_len = len;

	/* now fill it in with the data from the info fields */
	tempPtr = kid->item_ptr;
	memcpy(tempPtr, &len, sizeof(long));
	if (SRLisLittleEndian())
		SRLi_FlipLongs(tempPtr, 1);
	tempPtr[0] = certinfo->tver;
	
	tempPtr += 4;
	if(DB_TEMPLATE_FLAG == 1)
	{
		*tempPtr++ = CERT_TEMPLATE_VERSION;	/* store the template version */
	}
	
	/* Store the cert type */
	memcpy (tempPtr, (char *)&certinfo->CertType, 1);
	tempPtr++;
	len = strlen(certinfo->algOID) + 1;
	memcpy(tempPtr, certinfo->algOID, len);
	tempPtr += len;

	len = strlen(certinfo->validFrom[0]) + 1;
	memcpy(tempPtr, certinfo->validFrom, len);
	tempPtr += len;

	len = strlen(certinfo->validTill[0]) + 1;
	memcpy(tempPtr, certinfo->validTill, len);
	tempPtr += len;

	len = strlen(certinfo->issuer_DN) + 1;
	memcpy(tempPtr, certinfo->issuer_DN, len);
	tempPtr += len;

	if(CERT_TEMPLATE_VERSION >= 1)	/* store email address */
	{
		if (certinfo->emailAddr != NULL)
		{
			len = strlen(certinfo->emailAddr) + 1;
			memcpy(tempPtr, certinfo->emailAddr, len);
		}
		else
		{
			len = 1;
			*tempPtr = 0;
		}
		tempPtr += len;
	}

	len = 2;	/* short */
	memcpy(tempPtr, (char *) &certinfo->pkey_len, len);
	if (SRLisLittleEndian())
		SRLi_FlipShorts(tempPtr, 1);
	tempPtr += len;

	/* store the cert serial numb len then val */
	len = certinfo->serialNum->num;
	memcpy(tempPtr, (char *) &len, 4);
	if (SRLisLittleEndian())
		SRLi_FlipLongs(tempPtr, 1);
	tempPtr += 4;

	memcpy(tempPtr, certinfo->serialNum->data, len);
	tempPtr += len;

	*tempPtr++ = (char) (certinfo->trusted & 0x00FF);

	/* store the number of policies */
	*tempPtr++ = (char)(pcount & 0x00FF);

	polyPtr = certinfo->poly;

	while(pcount--)
	{
		len = strlen(polyPtr->policy_id) + 1;
		memcpy(tempPtr, polyPtr->policy_id, len);
		tempPtr += len;
		polyPtr = polyPtr->next;
	}

	/* init len field to zero, don't advance, overwrite in buffer below if need be */
	len = 0;
	memcpy(tempPtr, &len, 4);

	if(certinfo->sub_kmid != 0)
	{
		len = certinfo->sub_kmid->num;
		memcpy(tempPtr,  &len, 4);
		if (SRLisLittleEndian())
			SRLi_FlipLongs(tempPtr, 1);
		tempPtr += 4;

		memcpy(tempPtr, certinfo->sub_kmid->data, len);
		tempPtr += len;
		
	}
	else tempPtr+= 4;
	
	
	if(CERT_TEMPLATE_VERSION >= 2 && (certinfo->db_kid != 0))	/* store hash value */
	{
		/* next part of the template will contain a length and hash */
		len = certinfo->db_kid->num;
		memcpy(tempPtr,  &len, sizeof(long));
		if (SRLisLittleEndian())
			SRLi_FlipLongs(tempPtr, 1);
		tempPtr += sizeof(long);
	
		memcpy(tempPtr, certinfo->db_kid->data, len);
		tempPtr += len;
	}
	
	/* all done here */
	return(SRL_SUCCESS);

}

short SRLi_CRLInfoFromTemplate(ulong db_session, dbCRLEntryInfo_LL **crlinfo,DB_Data *ctemplate)
{
	dbCRLEntryInfo_LL *theInfo = NULL, *prevInfo = NULL;	/* resultant crl info */
	DB_Kid			Tkid;
	long			blocklen, len, hashValue = 0;
	uchar			*tempPtr;
	uchar			tver, crlver;

	if((crlinfo == 0) || (ctemplate == 0))
		return(SRL_INVALID_PARAMETER);

	*crlinfo = 0;	/* start caller with nothing */
	theInfo = 0;	/* didn't start our list yet */

	blocklen = ctemplate->item_len;	/* length of all data */

	/* first 4 bytes are length of the first block of data */
	tempPtr = (uchar *) ctemplate->item_ptr;	/* start at the top */

	while(blocklen > 0)	/* till finished parsing out the fields */
	{
		if(theInfo == 0)	/* did we start the linked list yet */
		{
			theInfo = (dbCRLEntryInfo_LL *) calloc(1,sizeof(dbCRLEntryInfo_LL));
			if(theInfo == 0)
				return(SRL_MEMORY_ERROR);
			prevInfo = theInfo;	/* record for looping */
			prevInfo->DBid = 0;


		}
		else	/* more than one item's data in template, create link */
		{
			prevInfo->next = (dbCRLEntryInfo_LL *) calloc(1,sizeof(dbCRLEntryInfo_LL));
			if(prevInfo->next == 0)
				goto errExit;

			prevInfo = prevInfo->next;	/* record for looping */
			prevInfo->DBid = 0;

		}
		prevInfo->signature = 0;
		prevInfo->CRLType = 0;
		prevInfo->nextDate[0] = 0;
		prevInfo->db_kid = 0;
		prevInfo->next = 0;

		memcpy((char *)&len, tempPtr, 4); 	/* length of just this block */
		if (SRLisLittleEndian())
			SRLi_FlipLongs(&len, 1);
		tver = (uchar)((len & 0xFF000000) >> 24);
		len = len & 0x00FFFFFF;
	
		blocklen -= len;	/* sub amount we are going to parse */

		// Retrieve the hash (DB id from the cache
		Tkid.item_len = len;
		Tkid.item_ptr = (char *)tempPtr;
		db_RetrieveHash(db_session, &Tkid,  
						  &hashValue);
	    prevInfo->DBid = hashValue;

		tempPtr += 4;	/* move past length field */
		prevInfo->tver = tver;


		if(tver >= DB_TEMPLATE_FLAG) /* do we have crl version field */
			crlver = *tempPtr++;
		else
			crlver = 0;

		if(tver >= 3) /* do we have crl type field */
			prevInfo->CRLType = *tempPtr++; 
		else
			prevInfo->CRLType = SRL_CRL_TYPE;
		

		/* the next field in the block is the signature algorithm oid */
		len = strlen((char *) tempPtr) + 1;	/* oid is null terminated string in block */

		prevInfo->signature = (char *)malloc(len);
		if(prevInfo->signature == 0)
			goto errExit;

		memcpy(prevInfo->signature, tempPtr, len);

		/* move onto next section in block, the validity dates as strings. First
		 * is the date issued, then the optional next update date.
		 */
		tempPtr += len;	/* skip the alg oid */
		len = strlen((char *)tempPtr) + 1;	/* get len of valid not before date string */

		memcpy(prevInfo->issueDate, tempPtr, len);

		tempPtr += len;	/* offset to 2nd date string */
		/* since this next date is optional, check for null in the next byte */
		if(*tempPtr != 0)	/* do we have a string */
		{
			len = strlen((char *)tempPtr) + 1;		/* get len of valid not after date string */
			memcpy(prevInfo->nextDate, tempPtr, len);

			/* inc past this string to next template */
			tempPtr += len;
		}
		else
		{
			tempPtr++;	/* inc past null string len */
			memset (&prevInfo->nextDate, 0, CM_TIME_LEN);
		}

		/* next part of the template will contain a length and hash */
		if((tver >= DB_TEMPLATE_FLAG) && (crlver >= CRL_TEMPLATE_VERSION1))
		{
		
			memcpy(&len, tempPtr, sizeof(long));
			if (SRLisLittleEndian())
				SRLi_FlipLongs(&len, 1);
			tempPtr += sizeof(long);
			prevInfo->db_kid = (Bytes_struct *)calloc(1,sizeof(Bytes_struct));
			if(prevInfo->db_kid == 0)
				goto errExit;
			prevInfo->db_kid->num = len;
			prevInfo->db_kid->data = (uchar *) malloc(len);
			if(prevInfo->db_kid->data == 0)
				goto errExit;
			memcpy(prevInfo->db_kid->data, tempPtr, len);
			
			tempPtr += len;	/* skip - in prep for next if any */


		}
		if (tver >= 4)
		{
			// Copy in the Refresh Time
			memcpy(&prevInfo->RefreshTime, tempPtr, sizeof(time_t));
			if (SRLisLittleEndian())
				SRLi_FlipLongs(&(prevInfo->RefreshTime), 1);

			tempPtr += sizeof(time_t);
		}

	} /* end of while loop */

	/* end of data held in info block, if we got here, then we must be
	 * done pulling stuff out of the template...
	 */

	*crlinfo = theInfo;	/* give caller the resultant info */
	return(SRL_SUCCESS);	/* tell it's all ok */

errExit:
	/* ran into problems, free up anything we allocated */
	prevInfo = theInfo;	/* start at top */

	while(theInfo != 0)
	{
		prevInfo = prevInfo->next;
		if(theInfo->signature != 0)
			free(theInfo->signature);


		free(theInfo);

		theInfo = prevInfo;	/* move onto next */
	}
	return(SRL_MEMORY_ERROR);
}

short SRLi_TemplateFromCRLInfo(DB_Kid *kid, dbCRLEntryInfo_LL *crlinfo)
{
	long	len;
	char	*tempPtr;

	if((kid == 0) || (crlinfo == 0))
		return(SRL_INVALID_PARAMETER);

	kid->item_ptr = 0;	/* none yet */
	kid->item_len = 0;

	/* figure out the amount of storage the info will take up */
	len = 4;	/* template's start with their length */
	if(DB_TEMPLATE_FLAG == 1)
		len++;		/* we store crl version template num in a byte */
	
	len += strlen(crlinfo->signature) + 1;	/* add 1's here for null terminated c strings */
	len += strlen(crlinfo->issueDate) + 1;
	if(crlinfo->nextDate != 0)
		len += strlen(crlinfo->nextDate) + 1;
	else
		len += 1;	/* write out one 0 byte */
		
	if((CRL_TEMPLATE_VERSION >= 1) && (crlinfo->db_kid != 0))	/* store hash value */
	{
		len += sizeof(long);
		len += crlinfo->db_kid->num;
	}	
	
	if ((crlinfo->tver >= CRL_TEMPLATE_VERSION) && (crlinfo->db_kid != 0))
		len++;  /* We store in the CRL Type (CRL ARL DELTA) */
	
	if (crlinfo->tver >= CRL_TEMPLATE_VERSION4)
		len += sizeof(time_t);

	/* allocate memory for this block of data we will create */
	kid->item_ptr = (char *) malloc(len);
	if(kid->item_ptr == 0)
		return(SRL_MEMORY_ERROR);

	kid->item_len = len;

	/* now fill it in with the data from the info fields */
	tempPtr = kid->item_ptr;
	memcpy(tempPtr, &len, sizeof(long));
	if (SRLisLittleEndian())
		SRLi_FlipLongs(tempPtr, 1);
	tempPtr[0] = crlinfo->tver;
	tempPtr += 4;
	
	if(DB_TEMPLATE_FLAG == 1)
	{
		if (crlinfo->tver == 2)
			*tempPtr++ = 1;
		else
			*tempPtr++ = CRL_TEMPLATE_VERSION;	/* store the version field */
	}

	if (crlinfo->tver >= CRL_TEMPLATE_VERSION)
		/* Now store in the CRL Type CRL, ARL, DELTA CRL */
		*tempPtr++ = crlinfo->CRLType;

	
	len = strlen(crlinfo->signature) + 1;
	memcpy(tempPtr, crlinfo->signature, len);
	tempPtr += len;

	len = strlen(crlinfo->issueDate) + 1;
	memcpy(tempPtr, crlinfo->issueDate, len);
	tempPtr += len;

	if(crlinfo->nextDate != 0)
	{
		len = strlen(crlinfo->nextDate) + 1;
		memcpy(tempPtr, crlinfo->nextDate, len);
		tempPtr += len;
	}
	else
		*tempPtr++ = 0;	/* write out one 0 byte */

	
	if((CRL_TEMPLATE_VERSION >= 1) && (crlinfo->db_kid != 0))	/* store hash value */
	{
		/* next part of the template will contain a length and hash */
		len = crlinfo->db_kid->num;
		memcpy(tempPtr,  &len, sizeof(long));
		if (SRLisLittleEndian())
			SRLi_FlipLongs(tempPtr, 1);
		tempPtr += sizeof(long);
	
		memcpy(tempPtr, crlinfo->db_kid->data, len);
		tempPtr += len;
	}

	if (CRL_TEMPLATE_VERSION >= 4) 
	{
		memcpy(tempPtr, &crlinfo->RefreshTime, sizeof(time_t));
		if (SRLisLittleEndian())
			SRLi_FlipLongs(tempPtr, 1);

		tempPtr += sizeof(time_t);
	}
	
	/* all done here */
	return(SRL_SUCCESS);
}


/*

Policy_struct *SRLi_GetPolyPtr(Cert_struct *dec_cert)

Given a decoded certificate it will return the head of the linked list
for the cert policy list to the caller.  If the certificate policies
extension is not present, then NULL will be returned.

*/
Policy_struct *SRLi_GetPolyPtr(Cert_struct *dec_cert)
{
    if ((dec_cert->exts != NULL) && (dec_cert->exts->certPolicies != NULL))
        return (dec_cert->exts->certPolicies->value);
    else
        return (NULL);
}

/*
 Function:
 SRLi_CompareCMatch2Index()

 short	SRLi_CompareCMatch2Index(CertMatch_struct *cmatch,DB_Kid *kidInfo, short trustedFlag)

This function is called upon to compare the matching criteria provided in
the cmatch structure against the actual keying identifier info in the
provided kidInfo.  All fields that are set in the cmatch structure are
used to filter on, those that are empty are ignored.  This routine will
return -1 if any of the fields in cmatch do not show up exactly as
speicified in the kidInfo.  Upon exact match, this routine will return a
value of 0 (meaning no diff).

Paramenters:
	cmatch (input) = information the caller wants to know if it appears
		in the provided kidinfo block.

	kidInfo (input) = actual keying identifier block of info from an
		existing certificate.

	trustedFlag (input) = if caller only wants certs that are special
		pub key trusted type. (TRUE). Otherwise (FALSE) return all
		matching certs.

returns:
	0		- An exact match has been confirmed
	-1		- provided kid does not match

NOTE:
	When matching against provided policy oids in the matching struct,
	the certs that are to be considered a match must contain at least
	one of the oids provided. This differs from the original code which
	only considered it a match if all the oids provided were found in
	the found certificates.
*/

short	SRLi_CompareCMatch2Index(CertMatch_struct *cmatch,DB_Kid *tempKid, short trustedFlag)
{
	long	len, len2, flag;
	char	*tempPtr, *st2, count;
	Policy_struct	*polyPtr;
	short		tmpShort;
	unsigned char		tver, crtver;
	/* need to step through the fields present in the kid, see if the
	 * match struct has any pref for that field and if so do a compare.
	 */

	/* first 4 bytes are length of the block */
	tempPtr = tempKid->item_ptr;	/* start at the top */
	tver = tempPtr[0];

	tempPtr += 4;	/* skip length */
	
	if(tver >= DB_TEMPLATE_FLAG)	/* have template version fields */
	{
		crtver = *tempPtr++;	/* read out cert template version field val */
	}
	else
		crtver = 0;
		
	/* the next field in the block is the public key algorithm oid, see
	 * if match had an alg oid.
	 */
	len = strlen(tempPtr) + 1;	/* oid is null terminated string in block */

	if(cmatch->algOID != NULL)
	{
		/* compare the given oid string against the cert block oid string */
		if(strcmp(tempPtr, cmatch->algOID ) != 0)
			return(-1);	/* didn't match, we can return right away */
	}

	/* move onto next section in block, the validity dates as strings. First
	 * is the not before date, then the not after date.
	 */
	tempPtr += len;	/* skip the alg oid */
	len = strlen(tempPtr) + 1;	/* get len of valid not before date string */
	st2 = &tempPtr[len];	/* offset to 2nd date string */
	len = strlen(st2) + 1;		/* get len of valid not after date string */

	if(cmatch->validOnDate != NULL)
	{
		/* caller has provided a single date they wish the cert of have been
		 * valid on.  Compare to the bounding info in the cert info block.
		 * caller date is of the form: "yyyymmdd"
		 * the stored cert dates are :
		 * "yyyymmddhhmmssZ"
		 */
		if(strlen((const char *)cmatch->validOnDate) != 8)
			return(SRL_INVALID_PARAMETER);

		/* see if nb falls after req date */
		if(strncmp(tempPtr ,(const char *)cmatch->validOnDate, 8)  > 0)
			return -1;	/* return right away since we don't match */

		/* see if na falls before req date */
		if(strncmp(st2, (const char *)cmatch->validOnDate, 8) < 0)
			return -1;	/* return right away, we don't match */

	} /* end of date checking */

	/* move past date fields to the issuer dn field in the info block */
	tempPtr = st2;	/* jump to not after string start */
	tempPtr += len;	/* jump past end of na string */

	len = strlen(tempPtr) + 1;	/* len of dn plus null char */
	/* do we compare issuer names */
	if(cmatch->issuer_DN != NULL)
	{	

		/* if(strcmp(tempPtr, cmatch->issuer_DN) != 0) */
		if (CMU_DistinguishedNameMatch(tempPtr, cmatch->issuer_DN) == FALSE)
		 	return -1;	/* didn't match, so we can return right away */
	}


	/* move past issuer dn to the email address field in the info block */
	tempPtr += len;

	/* do we compare e-mail addresses (only if present in both the given
	match info and the kid) */
	
	if((tver >= DB_TEMPLATE_FLAG) && (CERT_TEMPLATE_VERSION >= 1))
	{
		len = strlen(tempPtr) + 1;	/* len of email address + null */
	
		if ((cmatch->emailAddr != NULL) && (len > 1))
		{
			if (strcmp(tempPtr, cmatch->emailAddr) != 0)
	
				return -1;	/* didn't match, so return */
		}
		tempPtr += len;
		/* move past email address to the public key length in bits. This
		 * next field is a short (2 bytes).
		 */
		
	 }
	len = 2;	/* key length in bits field is 2 bytes wide */
	
	if(cmatch->pkey_len != 0)
	{
		memcpy((char *)&tmpShort, tempPtr, 2);

		if (SRLisLittleEndian())
			SRLi_FlipShorts(&tmpShort, 1);
		if(tmpShort != cmatch->pkey_len)
		{
			return -1;	/* didn't match, we can return right away */

		}
	}
	tempPtr += len;	/* move past the pkey length field */

	/* check against the cert serial number if one provided to match
	 * against.
	 */
	len = 4;	/* read the length field from the block */
	memcpy(&len2, tempPtr, len);
	if (SRLisLittleEndian())
		SRLi_FlipLongs(&len2, 1);
	tempPtr += len;	/* skip length field, address serial num */

	if(cmatch->serialNum != NULL)	/* did caller provide one */
	{
		/* compare lengths then the value */
		if(len2 != cmatch->serialNum->num)
			return(-1);	/* lengths differ, so value must be different */

		if(memcmp(tempPtr, cmatch->serialNum->data, len2) != 0)
			return(-1);	/* serial numbers are different */
	}

	/* move past the serial num value */
	tempPtr += len2;

	/* next field in the data is the trusted flag - at this time this
	 * info is not part of the matching criteria, so handle this directly
	 */
	if(trustedFlag == TRUE)
		if(*tempPtr == FALSE)
			return(-1);	/* they wanted trusted, this one is not */

	/* otherwise, they don't care if trusted or not */
	tempPtr++;	/* skip trust field */

	/* move to the next field, which is a count of how many policy oid
	 * strings are concatenated together in the block. The count is
	 * held in a single byte
	 */
	count = *tempPtr;	/* get the policy oid string count */
	tempPtr++;	/* move past the count field */

	if(cmatch->poly != NULL)	/* are we supposed to match agains poly oids */
	{
		/* if we have no count, then we can just return now */
		if(count == 0) /* no policy oids in target certs */
			return -1;

		/* loop through the linked list of caller provided matching polys
		 * and check to see if they are in the block info.
		 */

		/* start out figuring how many poly oid strings are provided in the
		 * matching template.
		 */
		polyPtr = cmatch->poly;
		len2 = 0;
		while(polyPtr != NULL)
		{
			len2++;	/* count of how many in linked list */
			polyPtr = polyPtr->next;
		}

		/* len2 indicates how many poly oids must be check for matches.*/

		/* loop through the linked list, and check to see if each appears
		 * in the cert's info block.
		 */
		/* tempPtr is pointing at the first poly oid string in the block */
		polyPtr = cmatch->poly;	/* start at top of linked list */
		st2 = tempPtr;	/* start with first string */

		flag = -1;	/* start with default of no matches found */
		while(polyPtr != NULL)	/* check for each one requested */
		{
			/* compare the requested poly against each string in the header,
			 * we must have one match in the set for the req poly.
			 */
			st2 = tempPtr;	/* start with first string */
			while(count)
			{
				if(strcmp(st2, polyPtr->policy_id) == 0)
				{
					flag = 0;	/* found a match */
					break;	/* get out of this while(count) loop */
				}
				count--;	/* one less header string */
				st2 += (strlen(st2) + 1);	/* skip to next string */
			}

			/* done comparing the given match poly against all header p oids,
			 * if one matched, we can exit checking now.
			 */
			if(flag == 0)
				break;	/* one matched, don't need to check others */

			/* else we didn't find a match yet, move onto next poly from the
			 * linked list
			 */
			polyPtr = polyPtr->next;

			/* restart the header string count */
			count = tempPtr[-1];
		}

		/* see if we found a match, if not then we can return now
		 * since no policy matches were found.
		 */
		if(flag == -1)
			return(-1);

		/* else, one of the requested policies was matched
		 * against.
		 */
	}

	/* skip over all the poly oid strings in header */
	count = tempPtr[-1];	/* how many strings in header */
	while(count--)
	{
		tempPtr += (strlen(tempPtr) + 1);	/* len plus null */
	}

	/* the next field contains length the subj id value  */
	memcpy(&len, tempPtr, 4); 		/* get length (4 bytes) */
	if (SRLisLittleEndian())
		SRLi_FlipLongs(&len, 1);
	tempPtr += 4;

	if(cmatch->sub_kmid != NULL)
	{
		if(len != 0) /* per rich req, if none in cert, match any in match provided info */
		{
			if(len != cmatch->sub_kmid->num)	/* are byte counts diff */
				return -1;	/* if len diff, then we know it doesn't match */

			if(memcmp(tempPtr, cmatch->sub_kmid->data, len) != 0)
				return(-1);	/* tell caller they don't match */
		}
	}

	/* end of data held in info block, if we got here, then we must
	 * have matched up.
	 */
	return(0);	/* tell caller they have a winner. */

}


/*
 * NOTE:
 * with the new filtering ability of the "onlyOne" flag, the caller can track the
 * date of the most recently matched crl. The filterInfo parm get's filled in with
 * the initially matched CRL date, then assuming the caller keeps that value around, they
 * will pass it back to us on subsequent calls for this routine to use in
 * comparisons.
 */
short	SRLi_CompareCRLMatch2Index(CRLMatch_struct *cmatch,DB_Kid *tempKid, char *filterInfo)
{
	long	len;
	char	*tempPtr, tver, crlver;

	/* need to step through the fields present in the kid, see if the
	 * match struct has any pref for that field and if so do a compare.
	 */

	/* first 4 bytes are length of the block */
	tempPtr = tempKid->item_ptr;	/* start at the top */
	tver = tempPtr[0];

	tempPtr += 4;	/* skip length */

	if(tver >= DB_TEMPLATE_FLAG)	/* do we have version field in template */
	{
		crlver = *tempPtr++;
	}
	else crlver = 0;
	
	/* the next field in the block is the signature key algorithm oid, see
	 * if match had an alg oid.
	 */
	len = strlen(tempPtr) + 1;	/* oid is null terminated string in block */

	if(cmatch->signature != NULL)
	{
		/* compare the given oid string against the crl block oid string */
		if(strcmp(tempPtr, cmatch->signature ) != 0)
			return(-1);	/* didn't match, we can return right away */
	}

	/* move onto next section in block, the validity dates as strings. First
	 * is the not before date, then the not after date.
	 */
	tempPtr += len;	/* skip the alg oid */
	len = strlen(tempPtr) + 1;	/* get len of valid not before date string */

	if(cmatch->issueAfter != NULL)
	{
		/* caller has provided a single date they wish the crl of have been
		 * issued on or after.  Compare to the bounding info in the crl info block.
		 */
		/* see if falls after req date */
		if(strcmp(tempPtr ,(const char *)cmatch->issueAfter)  < 0)
			return -1;	/* return right away since we don't match */

	} /* end of date checking */
	
	if(cmatch->issueBefore != NULL)
	{
		/* now check to see if it was issued before the date
		 * they specified (if they did specify a issuebefore date.)
		 */
			if(strcmp(tempPtr, (const char *)cmatch->issueBefore) > 0)
				return -1;	/* was not issued before the requested date, failure */
	}


	/* the crl was issued after the date the caller specified, 
	 * check to see if caller provided further filtering info,
	 * and they only want one crl returned. (Cut's down on having
	 * to build a big list, and then having to decode all after
	 * building the list when only one CRL is request by top caller.)
	 */
	if(cmatch->onlyOne)
	{
		if(filterInfo[0] == 0)	/* not set previously */
			strcpy(filterInfo, tempPtr);	/* record it now */
		
		else
		{
			
 /* after	before  (with "onlyOne" set to TRUE)
 * -----	------
 *  y		  0		=> CRL issued after y date, closest to y date
 *  y		  x     => most recent CRL issued after y, but no later than x date
 *  0		  x		=> most recent CRL issued before x date
 *  0		  0		=> most recent CRL for the particular issuer
 */

			if(cmatch->issueAfter && (cmatch->issueBefore == 0))
			{
				/* see if this date is closer than any previous found */
				if(strcmp(filterInfo, tempPtr) > 0)/* if last recorded is newer than this CRL */
					strcpy(filterInfo, tempPtr); /* this CRL is closer */
				else
					return(-1);	/* previously filtered one is closer */
			}
			else /* for other cases we want most recent (bounding done above if requested) */
			{
				if(strcmp(filterInfo, tempPtr) < 0) /* was prev older than this CRL */
					strcpy(filterInfo, tempPtr); /* this CRL is closer */
				else
					return(-1);	/* previously filtered one is closer */
		
			}
		
		}
	}	
	tempPtr += len;	/* skip the issue date of crl in the info block */


	/* end of data held in info block, if we got here, then we must
	 * have matched up.
	 */
	return(0);	/* tell caller they have a winner. */

}




/*
 *
 * This routine sorts the database list by DN - note that the dn's
 * are sorted alphabetically, but the info for the entry is not
 * changed (ex: if there are 5 certs for joe smith, the info for
 * the 5 certs is not sorted, it's in the original order. The
 * dn's are still hooked to their info.) This routine is used internally...
 *
 *
 *
 */
dbEntryInfo_LL *SRLi_SortdbEntryLL(dbEntryInfo_LL *theList)
{
	dbEntryInfo_LL    *low_list, *high_list, *current, *pivot, *temp;
	int     result;

    /* See if there are no more in list */
	if(theList == NULL)
        return(NULL);


    /* Scan forward, making sure we find one that is not equal to the
     * current link. (shouldn't have dupes, but who knows).  This
     * will give us initial starting points for splitting the rest
     * into two subgroups of links.
     */
    current = theList;
    do
    {
        current = current->next;
        if(NULL == current)
            return(theList);	/* hit the end here */
    }   while(0 == (result = SRLDNcmp(theList->entry_DN, current->entry_DN)));

	/* result > 0 => top of list dn greater than current dn
	 * result == 0 => top of list dn is same as current dn
	 * result < 0 => top of list dn less than current dn
	 *
	 * We will use the lower string of the dn's for comparing further on
	 * in the list and splitting it up into two groups.
	 */
    if(result > 0)
        pivot = current;		/* current dn is lower than top */
    else
        pivot = theList;		/* top of list dn is lower than current */

    /* now init the two splitter sublist pointers */
    low_list = high_list = NULL;

    /* Now we will separate the links into the two sublists */
    current = theList;	/* start at top, and split between our two lists */
    while(NULL != current)	/* as long as we have links to work on */
    {
        temp = current->next;	/* make copy of link before we overwrite this field */
//        if(strcmp(pivot->entry_DN, current->entry_DN) < 0)
       if(SRLDNcmp(pivot->entry_DN, current->entry_DN) < 0)
        {
            /* if current dn is higher, we will move it to the top
             * of the high list
             */
            current->next = high_list;
            high_list = current;	/* keep track of top of high list */
        }
        else
        {
            /* else current dn is lower, add it to the top of
             * the low list
             */
            current->next = low_list;
            low_list = current;	/* keep track of top of low list */
        }

        /* move onto the next link in the list (saved earlier) */
        current = temp;
    }

	/* ok - at this point we have split our list in two.  We
	 * will use recursion to sort the entries in each list.
	 */
    low_list  = SRLi_SortdbEntryLL(low_list);
    high_list = SRLi_SortdbEntryLL(high_list);

	/* we finished sorting the current chunk of links at this point.
	 * We need to append the high list to the end of the low list,
	 * so scan till we find the end of the low list.
	 */

    current = temp = low_list;
    while(TRUE)
    {
        current = current->next;
        if(NULL == current)
            break;
        temp = current;	/* move onto next one, record prev */
    }
	/* now just append and return the list we sorted */
    temp->next = high_list;

    return(low_list);	/* top of the lower ranking dn's */
}



short SRLi_isDN(char a)
{
	if((a >= 'A') && (a <= 'Z'))
		return(TRUE);
	
	if((a >= 'a') && (a <= 'z'))
		return(TRUE);
	
	if((a >= '0') && (a <= '9'))
		return(TRUE);
	
	return(FALSE);

}



short SRLi_genname2str (Gen_names_struct *gennames, char **in_str)
{
char *temp_str = NULL;
    if (gennames == NULL)
		return SRL_INVALID_PARAMETER;
	/* Loop through the Gen_names_struct link list */
    for (; gennames != NULL; gennames = gennames->next)
	{
		if (gennames->gen_name.flag == CM_X500_NAME)
		{
			temp_str = (char*)calloc(1, strlen(gennames->gen_name.name.dn) + 1);
			if (temp_str == NULL)
				return SRL_MEMORY_ERROR;
		    strcpy(temp_str, gennames->gen_name.name.dn);
			break;
		}
		if (gennames->gen_name.flag == CM_URL_NAME)
		{
			temp_str = (char *)calloc (1, strlen (gennames->gen_name.name.url)+1);
			if (temp_str == NULL)
				return SRL_MEMORY_ERROR;
			
			strcpy (temp_str, gennames->gen_name.name.url);
			/* We're done */
			break;	
		}

	} /* End for loop */
	*in_str = temp_str;
	return SRL_SUCCESS;

} /* end routine */


short SRLi_RetParseRDNSeq(char *string, RDN_LL **dn)
{
/* This function will parse the input string (a DN or an RDN) into separate
RDN components and copy them into a new linked list.  The new linked list will
be ordered from high to low (most general to most specific).  This function
will allocate memory for each link.  Once each RDN string is parsed, leading
and non-escaped trailing spaces will be removed.  If an error occurs (either 
a SRL_MEMORY_ERROR or a SRL_INVALID_DN), the allocated memory will be freed.
*/
    char commaFound;
    char *temp,
         *nextComma,
         *nextQuotes;
    short numToCopy,
		  numTrailing;
    RDN_LL *rdn,
           *prevLink;

    *dn = NULL;
	rdn = NULL;
    prevLink = NULL;

    if (string == NULL)
        return SRL_SUCCESS;

    while (*string != '\0')
    {
        /* Continue parsing the string until either the next non-escaped comma
        is found or no more commas can be found */
		nextComma = NULL;
        commaFound = FALSE;
        temp = string;
        while ((commaFound == FALSE) &&
            ((nextComma = strchr(temp, ',')) != NULL))
        {
            /* Found the next comma -- now check to see if it's escaped
            using double quotes.  Loop through any double quotes preceding the
            comma.
                If the quotes are escaped with a backslash, move past them and
                continue the loop.
                If not, then the comma is escaped with quotes, so move the
                temp to the end quotes mark.  Note: temp will now be greater
                than nextComma. */
            while (((nextQuotes = strchr(temp, '\"')) != NULL) &&
                (nextQuotes < nextComma))
            {
                if (temp[(nextQuotes - temp) - 1] != '\\')
                {
                    temp = strchr(++nextQuotes, '\"');
                    if (temp == NULL)   /* No matching end quotes! */
					{
						SRLi_FreeRDN_LL(&prevLink);
                        return SRL_INVALID_DN;
					}
                    else    /* Move temp past end quotes */
                        temp++;
                }
                else    /* This quotes mark is escaped */
                    temp = nextQuotes + 1;
            }

            /* Now check to see if the comma is escaped with a backslash.
            If not, set commaFound to TRUE.  If it is and temp hasn't moved
            past the comma, move the temp pointer past the comma for the
            next loop. */
            if (temp == nextComma)
                commaFound = TRUE;
            else if (temp < nextComma)
            {
                if (temp[(nextComma - temp) - 1] != '\\')
                    commaFound = TRUE;
                else
                    temp = nextComma + 1;
            }
            /* Else, temp > nextComma, so loop again */

        } /* While a non-escaped commma is not found */

        if (commaFound == TRUE)
            numToCopy = (short)(nextComma - string);
        else            /* Must be last RDN */
            numToCopy = (short)strlen(string);

		/* Skip past any leading spaces */
		while (*string == ' ')
		{
			string++;
			numToCopy--;
		}

		/* Ignore trailing non-escaped spaces (but keep track of how many for 
		later).  Must check that the string is at least 2 characters long.
		Note:  Trailing, escaped spaces are left alone (however, they should
		not be there in the first place). */
		numTrailing = 0;
		while ((numToCopy > 1) && (string[numToCopy - 1] == ' ') && 
			(string[numToCopy - 2] != '\\'))
		{
			numTrailing++;
			numToCopy--;
		}

		/* Allocate memory for the RDN and copy the string */
        if ((rdn = (RDN_LL *)malloc(sizeof(RDN_LL))) == NULL)
		{
			SRLi_FreeRDN_LL(&prevLink);
            return SRL_MEMORY_ERROR;
		}
        if ((rdn->rdn = (char *)malloc(numToCopy + 1)) == NULL)
		{
			free(rdn);
			SRLi_FreeRDN_LL(&prevLink);
            return SRL_MEMORY_ERROR;
		}
        strncpy(rdn->rdn, string, numToCopy); /* dad 7/31/97 */
        rdn->rdn[numToCopy] = '\0';
        rdn->next = prevLink;

        prevLink = rdn;

        /* Move string pointer to start of next RDN (since numToCopy may have 
		been decreased, if there were trailing spaces, add numTrailing as 
		well.  Move past the comma if this is not the end of the string. */
        string += numToCopy + numTrailing;
        if (*string != '\0')
            string++;

    } /* while not at end of string */

    *dn = rdn;

    return SRL_SUCCESS;
} /* end of SRLi_RetParseRDNSeq() */


AsnTypeFlag SRLi_GetCertType (Cert_struct *dec_cert, enum AsnTypeFlag TypeFlag)
{
	AsnTypeFlag cert_type = TypeFlag; // Set default to the TypeFlag
	/* Check for same issuer */
	if  ((dec_cert) && (SameIssuer (dec_cert)) )
	{
		cert_type = SRL_CA_CERT_TYPE;
		return cert_type;
	}

	if (dec_cert)
	{
		/*
		 * Check the type of the Certificate:
		 *  Version 3 Certs
		 *    If Basic Constraints are present and the CA flag is present = CA Cert
		 *    If CM_KEY_CERT_SIGN is set in Key Usage extension = CA Cert
		 *    If Issuer and Subject are the same = CA Cert
		 *	  Else  Cert is a End Entity
		 *
		 *  Version 1 or 2 Certs
		 *    Cert is unknown
		 *	  Except Fortezza cert CA if either the CA or PCA bit is set in the public 
		 *    key's DSS privileges.
		 */
		if (dec_cert->version == 3)
		{

			/* Check version 3 Certificates */
			if (dec_cert->exts &&
				dec_cert->exts->basicCons &&
				dec_cert->exts->basicCons->value &&
				((Basic_cons_struct *)dec_cert->exts->basicCons->value)->cA_flag == TRUE)
					cert_type = SRL_CA_CERT_TYPE;

			else if (dec_cert->exts &&
					dec_cert->exts->keyUsage &&
					(*(ushort *)dec_cert->exts->keyUsage->value & CM_KEY_CERT_SIGN))
						cert_type = SRL_CA_CERT_TYPE;

			else
				cert_type = SRL_CERT_TYPE;

		}
		if (dec_cert->version <= 2)
		{
				
			if ((strcmp(dec_cert->pub_key.oid, gMOSAIC_DSA_OID) == 0) &&
				(strcmp(dec_cert->pub_key.oid, gDSA_KEA_OID) == 0) )
			{
				/* v1 fortezza  cert*/
				/* Check the DSS Privileges for CA */
#define CertAuthority 0x03
#define PCAuthority 0x02
				if  (*(uchar  *) dec_cert->pub_key.key.combo->dsa_privs.data & (CertAuthority | PCAuthority) )
					cert_type = SRL_CA_CERT_TYPE;
			}
			else
			{
				// We don't know what type it is set both types
				cert_type = (unsigned char) SRL_CA_CERT_TYPE | SRL_CERT_TYPE ;
			}
		}
	}
	return cert_type;
}

static CM_BOOL SameIssuer(Cert_struct *cert)
{
	if ((cert->issuer == NULL) || (cert->subject == NULL))
		return FALSE;
	if (SRLDNcmp(cert->issuer, cert->subject) != 0)
		return FALSE;
	
	if ((cert->issuer_id == NULL) && (cert->subj_id == NULL))
		return TRUE;
	else if ((cert->issuer_id == NULL) || (cert->subj_id == NULL))
		return FALSE;
	else
	{
		if (cert->issuer_id->num != cert->subj_id->num)
			return FALSE;
		if (memcmp(cert->issuer_id->data, cert->subj_id->data,
			cert->subj_id->num) == 0)
			return TRUE;
		else
			return FALSE;
	}
}

