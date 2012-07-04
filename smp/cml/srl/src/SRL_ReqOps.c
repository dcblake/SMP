/*****************************************************************************
File:     SRL_ReqOps.c
Project:  Storage & Retrieval Library
Contents:  

Created:  13 November 2000
Author:   Shari Bodin <Shari.Bodin@DigitalNet.com>

Last Updated:  21 January 2004

Version:  2.4

Description: This file contains both the high and low-level functions
that perform the retrieval and formatting of the requested objects from the
local database and a remote server.

*****************************************************************************/

/* -------------- */
/* Included Files */
/* -------------- */
#include <string.h>
#include <limits.h>
#include "SRL_internal.h"


char DP_LDAP_URI[]	= "LDAP:///";



/*
 * External Functions
 */
extern short SRLi_GetLDAPSessionStatus(ulong sessionID);
/* ------------------- */
/* Function Prototypes */
/* ------------------- */
extern short db_RetrieveHash(ulong db_session, DB_Kid *kid,  
				   long *HashValue);
extern short SLRi_RefreshCRL(ulong sessionID, ulong crl_db_session, dbCRLEntryInfo_LL *oldCRLInfo, 
							 char *opt_kid, CM_BOOL isURL);
extern 	void db_lock();
extern 	void db_unlock();
short SRLi_GetAllCertsByMatchInfo (ulong session, SRL_CertMatch_struct *matchInfo, EncObject_LL **objectlist);

short SRLi_GetAllCRLsByMatchInfo (ulong sessionID, SRL_CRLMatch_struct *matchInfo,
								  EncObject_LL **objectlist);

short SRLi_GetAllCertificates (ulong sessionID, CM_DN subject_dn, 
				           long typeMask, short locMask, EncObject_LL** Obj_List,
						   char *url);

short SRLi_GetCRL (ulong sessionID, CM_DN issuer, 
				           long typeMask, short locMask, EncObject_LL** crlList,
						   char *url);
short SRLi_GetSPIFbyDN (ulong sessionID, CM_DN issuer, 
				           long typeMask, EncObject_LL** spifList);
short SRLi_GetACbyDN (ulong sessionID, CM_DN issuer, 
				           long typeMask, EncObject_LL** acList);
short SRLi_GetRemoteACs(ulong sessionID, CM_DN issuer, int typeMask, EncObject_LL **acs);
short SRLi_searchCRLbyDN (ulong sessionID, CM_DN issuer_dn, EncObject_LL** Obj_List);

short SRLi_GetAllCertURLByType (ulong sessionID, char *urlToFind, 
				           long typeMask,EncObject_LL** Obj_List);
short SRLi_RemoveDupesInSameList(EncObject_LL *checkList);
short SRLi_RemoveDupesInTwoLists(EncObject_LL *originalList, EncObject_LL **secondListPtr);


short SRLi_RemoveDupesInSameObject(EncObject_LL *checkList);
short SRLi_BuildObjectListFmCertList (EncObject_LL **Obj_List, EncCert_LL *cert_list, 
			                           long typeMask, short location);
short SRLi_BuildObjectListFmCRLList (EncObject_LL **Obj_List, EncCRL_LL *crl_list, 
			                           long typeMask, short location);
short SRLi_FilterRemoteObject(EncObject_LL **remoteObjPtr,EncObject_LL *localObjptr);
short SRLi_RemoveDupesInTwoObjects(EncObject_LL *originalList, EncObject_LL **secondListPtr);
short SRLi_searchCertByDN (SRLSession_struct *session, CM_DN subject_dn, 
				           long dbType, EncObject_LL** Obj_List);
short SRLi_FilterRemoteCRLsList(EncObject_LL **remoteListPtr,
							   EncObject_LL *localList,CM_DN issuer, 
							   SRL_CRLMatch_struct *matchInfo, char *mostRecent);
short SRLi_FilterRemoteCertsList(EncObject_LL **remoteListPtr,EncObject_LL *localList,
	CM_DN subject, SRL_CertMatch_struct *matchInfo);
static short SRLi_FilterObjectOnType(EncObject_LL *checkList, EncObject_LL **fileterdList, long typeMask);
//static CM_BOOL SRLi_MatchCertEntry (dbCertEntryInfo_LL *the_entry, SRL_CertMatch_struct *matchInfo);
CM_BOOL SRLi_MatchCertEntry (dbCertEntryInfo_LL *the_entry, SRL_CertMatch_struct *matchInfo,
							 long *DBid, uchar *CertType);
static CM_BOOL SRLi_MatchCRLEntry (dbCRLEntryInfo_LL *the_entry, SRL_CRLMatch_struct *matchInfo,
								   long *DBid);

CM_BOOL SRLisLittleEndian();
/* ------------- */
/* SRL Functions */
/* ------------- */


SRL_API (short) SRL_RequestObjs(ulong *sessionID, CM_DN dn, long typeMask,
								short locMask, EncObject_LL **pObjList)
{
	short error_return = 0;
	EncObject_LL *crlList = NULL;
	EncObject_LL *certList = NULL;
	EncObject_LL *acList = NULL;
	EncObject_LL *spifList  = NULL;

	if ((sessionID == NULL) || (*sessionID == 0))
		return SRL_SESSION_NOT_VALID;
	if ((dn == NULL) || (typeMask == 0) || (locMask == 0) || (pObjList == NULL))
		return SRL_INVALID_PARAMETER;

	/* Initialize result */
	*pObjList = NULL;

	switch (typeMask)
	{ 
		case USER_CERT_TYPE:
		case USER_CERT_TYPE | CA_CERT_TYPE:
		case USER_CERT_TYPE | CROSS_CERT_TYPE:
		case USER_CERT_TYPE | CROSS_CERT_TYPE | CA_CERT_TYPE:
		case CA_CERT_TYPE:
		case CA_CERT_TYPE | CROSS_CERT_TYPE:
        case CROSS_CERT_TYPE:
			error_return = SRLi_GetAllCertificates(*sessionID, dn, 
				typeMask, locMask, &certList, NULL);
			if (error_return == SRL_MEMORY_ERROR)
				return (error_return);
			/* Per ICD if error is not CM_MEMORY_ERROR, return CM_NO_ERROR */
			error_return = SRL_SUCCESS;
			*pObjList = certList;
            break;

        case CRL_TYPE:        /* Certificate Revocation List requested */
        case ARL_TYPE:        /* Authority Revocation List requested   */
		case DELTA_CRL_TYPE:  /* Delta Revocation List requested       */
		case CRL_TYPE | ARL_TYPE:
		case CRL_TYPE | DELTA_CRL_TYPE:
		case ARL_TYPE | DELTA_CRL_TYPE:
		case CRL_TYPE | ARL_TYPE | DELTA_CRL_TYPE:

			error_return = SRLi_GetCRL(*sessionID, dn, typeMask, locMask,
				&crlList, NULL);
			if (error_return == SRL_MEMORY_ERROR)
				return (error_return);
			/* Per ICD if error is not CM_MEMORY_ERROR, return CM_NO_ERROR */
			error_return = SRL_SUCCESS;
			*pObjList = crlList;
			break;

		case SPIF_TYPE:
			error_return = SRLi_GetSPIFbyDN(*sessionID, dn, typeMask,&spifList);
			if (error_return == SRL_MEMORY_ERROR)
				return (error_return);
			/* Per ICD if error is not CM_MEMORY_ERROR, return CM_NO_ERROR */
			error_return = SRL_SUCCESS;
			*pObjList = spifList;			
			break;

		case AC_TYPE | ACRL_TYPE | AARL_TYPE | AAAC_TYPE | ADC_TYPE:
			/* get either Attribute Certificates, Attribute Certificate Revocation List,
				Attribute Authority Revocation List, Attribute Authority Attribute Cert,
				Attribute Descriptor Cert */
			error_return = SRLi_GetACbyDN(*sessionID, dn, typeMask, &acList);
			if (error_return == SRL_MEMORY_ERROR)
				return (error_return);
			/* Per ICD if error is not CM_MEMORY_ERROR, return CM_NO_ERROR */
			error_return = SRL_SUCCESS;
			*pObjList = acList;			
			break;

		default:
			error_return = SRL_UNDEFINED_TYPE;
			break;
	} /* End case */

    return (error_return);
}


SRL_API(short) SRL_URLRequestObjs(ulong *sessionID, char *url, long typeMask,
								  short locMask, EncObject_LL **pObjList)
{
	short error_return = 0;
	EncObject_LL *crlList = NULL;
	EncObject_LL *certList = NULL;

	if ((sessionID == NULL) || (*sessionID == 0))
		return SRL_SESSION_NOT_VALID;
	if ((url == NULL) || (pObjList == NULL))
		return SRL_INVALID_PARAMETER;

	/* Initialize result */
	*pObjList = NULL;

	switch (typeMask)
	{ 
		case USER_CERT_TYPE:
		case USER_CERT_TYPE | CA_CERT_TYPE:
		case USER_CERT_TYPE | CROSS_CERT_TYPE:
		case USER_CERT_TYPE | CROSS_CERT_TYPE | CA_CERT_TYPE:
		case CA_CERT_TYPE:
		case CA_CERT_TYPE | CROSS_CERT_TYPE:
        case CROSS_CERT_TYPE:
			error_return = SRLi_GetAllCertificates(*sessionID, NULL, 
				typeMask, locMask, &certList, url);
			if (error_return == SRL_MEMORY_ERROR)
				return (error_return);
			/* Per ICD if error is not CM_MEMORY_ERROR, return CM_NO_ERROR */
			error_return = SRL_SUCCESS;
			*pObjList = certList;
            break;

        case CRL_TYPE:        /* Certificate Revocation List requested */
        case ARL_TYPE:        /* Authority Revocation List requested   */
		case DELTA_CRL_TYPE:  /* Delta Revocation List requested       */
		case CRL_TYPE | ARL_TYPE:
		case CRL_TYPE | DELTA_CRL_TYPE:
		case ARL_TYPE | DELTA_CRL_TYPE:
		case CRL_TYPE | ARL_TYPE | DELTA_CRL_TYPE:
			error_return = SRLi_GetCRL(*sessionID, NULL, typeMask, locMask,
				&crlList, url);
			if (error_return == SRL_MEMORY_ERROR)
				return (error_return);
			/* Per ICD if error is not CM_MEMORY_ERROR, return CM_NO_ERROR */
			error_return = SRL_SUCCESS;
			*pObjList = crlList;
			break;

		default:
			error_return = SRL_UNDEFINED_TYPE;
			break;
	} /* End case */
    return (error_return);
}


SRL_API(void) SRL_FreeObjs(ulong *sessionID, EncObject_LL **objList)
{
	sessionID = sessionID;
	SRLi_FreeObjList(objList);
}


/*
 * Description: Based on the Cert type passed in and the dn, retreive
 *              all certs
 *
 */
short SRLi_GetAllCertificates (ulong sessionID, CM_DN subject_dn, 
				           long typeMask, short locMask, EncObject_LL** Obj_List,
						   char *url)
{
	SRLSession_struct	*session;
	EncObject_LL		*foundCertsList, *atList, *remoteList, *filteredCertList = NULL;
	EncObject_LL      *certificateList;
	EncObject_LL *cert_pairptr = NULL;
	dbCertEntryInfo_LL  *CertInfo = NULL;
	short			err;
	DB_Kid			req_kid, tempKid;
	DB_Data			*found_data, *tempData;
	long			len, block_size;
	char			*tempPtr;
	foundCertsList = NULL;
	atList = NULL;
	remoteList = NULL;
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if (Obj_List == NULL)
		return SRL_INVALID_PARAMETER;

	*Obj_List = NULL;
	found_data = NULL;
	certificateList = NULL;	/* default to none found */

	err =  SRLi_GetSessionFromRef(&session, sessionID);
	if (err != SRL_SUCCESS)
		return(err);

	/* look up by issuer */
	if (subject_dn != NULL)
	{
		if (*subject_dn == '\0')	/* no empty names here */
			return SRL_INVALID_PARAMETER;
		
		req_kid.item_len = strlen(subject_dn)+1;
		req_kid.item_ptr = subject_dn;
	}
	/* look up by URL */
	else if (url != NULL)
	{
		if (*url == '\0')			/* no empty names here */
			return SRL_INVALID_PARAMETER;
		
		req_kid.item_len = strlen(url)+1;
		req_kid.item_ptr = url;
	}
	else
	{
		return(SRL_INVALID_PARAMETER);
	}

	foundCertsList = (EncObject_LL *) calloc(1, sizeof(EncObject_LL));

	if(foundCertsList == NULL)
		return(SRL_MEMORY_ERROR);

	atList = foundCertsList;	/* start the tracker at the top */

	/* see if caller wishes us to search locally, this includes
	 * search local only, search both (local & remote), and the
	 * search till first found flags.
	 */
	if (locMask & CLIENT_LOC)	/* the local type */
	{
		if (session->CertFileName != NULL)
		{
			db_lock("SRLi_GetAllCertificates", __LINE__);

			/* try to get a cert from the db file. See if the index
			 * contains any entries for the given subject DN.
			 */
			if (typeMask != CROSS_CERT_TYPE)
			{
				err = db_GetEntry(session->db_certRefSession, 0, &req_kid, &found_data);
				err = DB2SRLerr(err);
				/* return error codes other than no err, and item not found */
				if((err != SRL_SUCCESS) && (err != SRL_NOT_FOUND))
				{
					SRLi_FreeObjList(&foundCertsList);
					if(found_data != 0)
					{
						if(found_data->item_ptr != 0)
							free(found_data->item_ptr);
						free(found_data);
					}
					db_unlock("SRLi_GetAllCertificates", __LINE__);
					return(err);
				}
			}
			else /* db file does not support cross certs */
				err = SRL_NOT_FOUND;

			/* if item was not found locally, and user only wants to
			 * search locally, then return not found.
			 */
			if ((err == SRL_NOT_FOUND) && !(locMask & (SERVER_LOC | DSA_LOC)))
			{
				SRLi_FreeObjList(&foundCertsList);

				if (found_data != NULL)
				{
					/* free up the found data, we are done breaking it out */
					if(found_data->item_ptr != 0)
						free(found_data->item_ptr);
					free(found_data);
				}
				db_unlock("SRLi_GetAllCertificates", __LINE__);
				return SRL_SUCCESS;
			}

			/* if we found that one or more entries exist for the item
			 * in our index, step through and pull all out.  If there
			 * is match criteria, we may filter number of results we
			 * return in the list.
			 */

			if(err == SRL_SUCCESS)	/* did we find something */
			{
				/* how many items are represented in the index for this
				 * subject name...
				 */
				block_size = found_data->item_len;	/* total templates size */
				tempPtr = found_data->item_ptr;		/* point at first template */
				
				while(block_size > 0)
				{
					memcpy((char *)&len,tempPtr,4);		/* len of this template */
					if (SRLisLittleEndian())
						SRLi_FlipLongs((long *) &len, 1);
					len = len & 0x00FFFFFF;
					
					/* given the index info, go get the encoded cert */
					tempKid.item_len = len;
					tempKid.item_ptr = tempPtr;
					
					/* prep loop vars for next iteration in case we
					 * are filtering, allows us to skip out easily.
					 */
					block_size -= len;	/* done with this template */
					tempPtr += len;		/* move onto next one */
					
					/* Build a temporary Cert info structure to get the cert type */
					err = SRLi_CertInfoFromTemplate(session->db_certRefSession, &CertInfo, &tempKid);
					if (err != SRL_SUCCESS)
					{
						SRLi_FreedbCertEntryLL(CertInfo);
						SRLi_FreeObjList(&foundCertsList);
						free(found_data->item_ptr);
						free(found_data);
						db_unlock("SRLi_GetAllCertificates", __LINE__);
						return(err);
					}
					
					/* get the encoded cert for this entry */
					err = db_GetEntry(session->db_certRefSession, 0, &tempKid, &tempData);
					err = DB2SRLerr(err);
					
					if(err != SRL_SUCCESS)
					{
						SRLi_FreedbCertEntryLL(CertInfo);
						SRLi_FreeObjList(&foundCertsList);
						free(found_data->item_ptr);
						free(found_data);
						db_unlock("SRLi_GetAllCertificates", __LINE__);
						return(err);
					}
					
					/* scoop out the enc cert data into the linked list */
					if(atList->encObj.data == NULL)	/* first list entry */
					{
						atList->encObj.data = (uchar *) (tempData->item_ptr);
						atList->encObj.num = tempData->item_len;
						atList->locMask = CLIENT_LOC;
						atList->typeMask = CertInfo->CertType;
						free(tempData);	/* don't need the struct anymore */
					}
					else	/* else we are extending the list */
					{
						atList->next = (EncObject_LL *) calloc(1,sizeof(EncObject_LL));
						if(atList->next == NULL)
						{
							SRLi_FreedbCertEntryLL(CertInfo);
							SRLi_FreeObjList(&foundCertsList);
							free(found_data->item_ptr);
							free(found_data);
							free(tempData);
							db_unlock("SRLi_GetAllCertificates", __LINE__);
							return(SRL_MEMORY_ERROR);
						}
						atList = atList->next;	/* use the new we created */
						atList->encObj.data = (uchar *) (tempData->item_ptr);
						atList->encObj.num = tempData->item_len;
						atList->typeMask = CertInfo->CertType;
						atList->locMask = CLIENT_LOC;
						atList->next = 0;	/* no next one yet */
						free(tempData);	/* don't need the struct anymore */
					}
					if(CertInfo != NULL)
						SRLi_FreedbCertEntryLL(CertInfo);
					
					
				} /* end of while (we have items for this dn in db file) */
				
				// Now filter the Certs according to type
				err = SRLi_FilterObjectOnType(foundCertsList, &filteredCertList, typeMask);
				if (err != SRL_SUCCESS)
				{
					db_unlock("SRLi_GetAllCertificates", __LINE__);
					return (err);
				}
				
				SRLi_FreeObjlst (foundCertsList);
				foundCertsList = filteredCertList;
				
				err = SRLi_RemoveDupesInSameObject (foundCertsList);
				if (err != SRL_SUCCESS)
				{
					db_unlock("SRLi_GetAllCertificates", __LINE__);
					return (err);
				}

				*Obj_List = foundCertsList;
				if (found_data != 0)
				{
					/* free up the found data, we are done breaking it out */
					if(found_data->item_ptr != 0)
						free(found_data->item_ptr);
					free(found_data);
				}
			} /* end of if (we found something in local storage) */

			/* unlock the database */
			db_unlock("SRLi_GetAllCertificates", __LINE__);

		} /* End if cert file name != NULL */

	} /* end of if (ok to search local storage ) */

	/* Check if done */
	if (!(locMask & SEARCH_ALL_LOC))
	{
		/* if we found something we can return at this time */
		if(foundCertsList->encObj.data != NULL)
		{
			*Obj_List = foundCertsList;
			return(SRL_SUCCESS);
		}
	}

	/* start with none in the remote list */
	remoteList = NULL;
			
	/* see if we should search remote */
	if (locMask & (SERVER_LOC | DSA_LOC))
	{
		err = SRL_SUCCESS;
		
		if ((subject_dn != NULL) && (locMask & DSA_LOC))
		{
			/* make a call to the remote retrieval code - if ldap avail
			 * and it's all set up, it will attempt to retrieve in
			 * this example of ldap remote get code.
			 */
			if (session->ldapInfo == NULL)
				goto done;
			
			err = SRLi_GetLDAPSessionStatus(sessionID);
			if (err != SRL_SUCCESS)
				goto done;
			
			err = SRLi_GetRemoteCerts(sessionID, subject_dn, typeMask, &remoteList);
			
			/* since we don't consider Not finding something to be
			 * fatal, we will check for the case where either
			 * CM_NOT_FOUND, or CM_LDAP_SEARCH_FAILED was returned
			 * and just return whatever was already found locally
			 * if any. Otherwise we check for fatal, then
			 * drop down to the normal processing.
			 */
			if ((err == SRL_NOT_FOUND) || (err == SRL_LDAP_SEARCH_FAILED))
			{
				err = SRL_SUCCESS;
				goto done; /* do normal exit code */
			}
			
			/* if one of the other LDAP errors, return any local
			 * stuff, but tell caller about ldap error
			 */
			if ((err >= SRL_LDAP_LOAD_FAILED) && (err <= SRL_LDAP_FUNCTION_NOT_SPECIFIED))
			{
				if(foundCertsList->encObj.data == NULL)	/* no matches at all */
					SRLi_FreeObjList(&foundCertsList);
				
				*Obj_List = foundCertsList;
				return(err);
			}
			
			/* otherwise fatal, and return nothing (either local
			 * or remote).
			 */
			if(err != SRL_SUCCESS)
			{
				/* fatal error - throw away any previously found,
				 * and return error code to caller.
				 */
				SRLi_FreeObjList(&remoteList);
				SRLi_FreeObjList(&foundCertsList);
				return(err);
			}
		}
		else if (url != NULL)	/* search remotely at the specified URL */
		{
			err = SRLi_GetRemoteURLCerts(sessionID, url, typeMask, locMask, &remoteList);
			
			/* since we don't consider Not finding something to be
			 * fatal, we will check for the case where either
			 * SRL_NOT_FOUND, or SRL_LDAP_SEARCH_FAILED was returned
			 * and just return whatever was already found locally
			 * if any. Otherwise we check for fatal, then
			 * drop down to the normal processing.
			 */
			
			if(err == SRL_NOT_FOUND || err == SRL_LDAP_SEARCH_FAILED)
			{
				err = SRL_SUCCESS;
				goto done; /* do normal exit code */
			}
			
			/* if one of the other LDAP errors, return any local
			 * stuff, but tell caller about ldap error
			 */
			if ((err >= SRL_LDAP_LOAD_FAILED) && (err <= SRL_HTTP_ERROR))
			{
				if(foundCertsList->encObj.data == NULL)	/* no matches at all */
					SRLi_FreeObjList(&foundCertsList);
				
				*Obj_List = foundCertsList;
				return(err);
			}
			
			/* otherwise fatal, and return nothing (either local
			 * or remote).
			 */
			if(err != SRL_SUCCESS)
			{
				/* fatal error - throw away any previously found,
				 * and return error code to caller.
				 */
				SRLi_FreeObjList(&remoteList);
				SRLi_FreeObjList(&foundCertsList);
				*Obj_List = 0;
				return(err);
			}			
		}

		/* If we got back results for the given DN, attempt
		 * to add the items to our cert database that aren't
		 * already in there.
		 *
		 * NOTE: should we only add items that match against
		 * the search criteria, or all items returned from
		 * the remote request? For now I am only adding what
		 * is left after filtering....
		 */
		err = SRLi_FilterRemoteObject(&remoteList, foundCertsList);
		if(err != SRL_SUCCESS )
		{
			/* error - throw away any previously found,
			 * and return error code to caller.
			 */
			SRLi_FreeObjList(&remoteList);
			SRLi_FreeObjList(&foundCertsList);
			*Obj_List = 0;
			return(err);
		}
		
		/* add what is left to the database */
		atList = remoteList;
		while(atList != NULL)	/* travel through the list */
		{
			if (atList->typeMask == CROSS_CERT_TYPE)
			{
				err = addCertPair2List(1, &atList->encObj,
					&cert_pairptr);
				if (err == SRL_SUCCESS)
				{
					EncObject_LL *tmpPairList = cert_pairptr;
					while (tmpPairList != NULL)
					{	
						if (session->db_certRefSession != 0)
							/* Add to the Data Base */
							SRL_DatabaseAdd (sessionID, &tmpPairList->encObj,
								SRL_CA_CERT_TYPE); 
						tmpPairList = tmpPairList->next;
					}
					SRLi_FreeObjList(&cert_pairptr);
				}
			}
			else
			{
				if (session->db_certRefSession != 0)
				{
					db_lock("SRLi_GetAllCertificates", __LINE__);
					SRLi_DatabaseAdd(sessionID, &atList->encObj, atList->typeMask,
						req_kid.item_ptr);
					db_unlock("SRLi_GetAllCertificates", __LINE__);
				}
			}
			atList = atList->next;
		}
		
		/* append what is left in the remote list to the local list */
		if(foundCertsList->encObj.data)	/* is there a local list */
		{
			/* add any left in remote to local list */
			atList = foundCertsList;
			while(atList->next != NULL)
				atList = atList->next;	/* loop to last link */
			
			atList->next = remoteList;	/* append */
			
			remoteList = NULL;
			/* done here */
		}
		else if(remoteList != NULL)
		{
			SRLi_FreeObjList(&foundCertsList);
			foundCertsList = remoteList;
		}
	}
	
	/* all done here */
	
	/* exhausted the searching areas, time to collect our thoughts and
	* tell user what they've won.
	*/
	
done:
	if ( foundCertsList->encObj.data == NULL)	/* no matches at all */
	{
		SRLi_FreeObjList(&foundCertsList);
	}
	
	
	*Obj_List = foundCertsList;	/* give caller the linked list */
	
	return(SRL_SUCCESS);
}


short SRLi_GetCRL (ulong sessionID, CM_DN issuer, 
				   long typeMask, short locMask, EncObject_LL** crlList,
				   char *url)
{
	SRLSession_struct	*session;
	EncObject_LL	*foundCRLsList, *atList, *remoteList;
	short			err;
	DB_Kid			req_kid, tempKid;
	DB_Data			*found_data, *tempData;
	long			len, block_size;
	uchar			tver, CRLType;
	char			*tempPtr, *parsePtr;
	char			filterInfo[CM_TIME_LEN];
	dbCRLEntryInfo_LL *crlinfo = NULL, *tmpCRLInfo = NULL;
	CM_Time			today;
	short			expired = FALSE;
	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	filterInfo[0] = 0;

	found_data = 0;
	*crlList = NULL;	/* default to none found */
	err =  SRLi_GetSessionFromRef(&session, sessionID);
	if(err != SRL_SUCCESS)
		return(err);

	/* look up by issuer */
	if (issuer != NULL)
	{
		if(*issuer == 0)		/* no empty names here */
			return(SRL_INVALID_PARAMETER);
		
		req_kid.item_len = strlen(issuer)+1;
		req_kid.item_ptr = issuer;
	}
	/* look up by URL */
	else if (url != NULL)
	{
		if(*url == 0)		/* no empty names here */
			return(SRL_INVALID_PARAMETER);
		
		req_kid.item_len = strlen(url)+1;
		req_kid.item_ptr = url;
	}
	else
	{
		return(SRL_INVALID_PARAMETER);
	}

	foundCRLsList = (EncObject_LL *) calloc(1, sizeof(EncObject_LL));

	if(foundCRLsList == NULL)
		return(SRL_MEMORY_ERROR);

	/* init the head to empty */
	foundCRLsList->encObj.data = 0;
	foundCRLsList->next = 0;

	atList = foundCRLsList;	/* start the tracker at the top */

	/* see if caller wishes us to search locally, this includes
	 * search local only, search both (local & remote), and the
	 * search till first found flags.
	 */
    if (locMask & CLIENT_LOC)  /* Local type */
	{
		if (session->CRLFileName != NULL)
		{
			db_lock("SRLi_GetCRL", __LINE__);
			/* try to get a crl from the db file. See if the index
			 * contains any entries for the given issuer DN.
			 */
			err = db_GetEntry(session->db_CRLRefSession, 0, &req_kid, &found_data);
			err = DB2SRLerr(err);
			
			if ((session->crlRefreshPeriod < LONG_MAX) && (err == SRL_SUCCESS))
			{
				// Try to refresh the current CRL
				/*
				 * If the Refresh time + the refresh Period is greater than
				 *our current time, then try to refresh the CRL.
				 */
				
				SRLi_CRLInfoFromTemplate(session->db_CRLRefSession,
					&crlinfo, found_data);

				tmpCRLInfo = crlinfo;
				while (tmpCRLInfo)
				{
					/* Get today in CM_Time format */
					SRLi_GetSRTime(today);
					if (strcmp(tmpCRLInfo->nextDate, today) < 0)
					{
						/* Check for unspecified next update */
						if (tmpCRLInfo->nextDate[0] == 0)
							expired = FALSE;
						else
							expired = TRUE;
					}
					
					/* If app has refresh period setto LONG_MAX then override if
					 * crl is expired */
					if ((session->crlRefreshPeriod != LONG_MAX) ||
						(expired == TRUE))
					{
						
						if ((tmpCRLInfo->RefreshTime+session->crlRefreshPeriod < time(NULL)) ||
							(expired == TRUE))
						{
							// Refresh the CRL
							err = SLRi_RefreshCRL (sessionID, session->db_CRLRefSession, tmpCRLInfo, req_kid.item_ptr, (CM_BOOL)(url != NULL));
							
							if (err == SRL_SUCCESS)
							{
								if (found_data)
								{
									if (found_data->item_ptr)
										free (found_data->item_ptr);
									free(found_data);
								}
								// Data got refreshed get the entry again
								err = db_GetEntry(session->db_CRLRefSession, 0, &req_kid, &found_data);
								err = DB2SRLerr(err);
							} 
							else if (err == SRL_NOT_FOUND)
							{
								err = SRL_SUCCESS;
							}
						} /* endif check for refresh */
					} /* Endif check for refresh period */
					tmpCRLInfo = tmpCRLInfo->next;
				}
				if(crlinfo != NULL)
					SRLi_FreeCRLEntryInfo_LL(crlinfo);
			}
			
			/* if we found that one or more entries exist for the item
			 * in our index, step through and pull all out.  If there
			 * is match criteria, we may filter number of results we
			 * return in the list.
			 */
			if (err == SRL_SUCCESS)
			{
				/* how many items are represented in the index for this
				 * issuer name...
				 */
				block_size = found_data->item_len;	/* total templates size */
				tempPtr = found_data->item_ptr;		/* point at first template */
				
				
				while(block_size > 0)
				{
					memcpy((char *)&len,tempPtr,4);		/* len of this template */
					if (SRLisLittleEndian())
						SRLi_FlipLongs((long *) &len, 1);
					
					tver = (uchar)((len & 0xFF000000) >> 24);
					len = len & 0x00FFFFFF;
					
					/* given the index info, go get the encoded crl */
					tempKid.item_len = len;
					tempKid.item_ptr = tempPtr;
					parsePtr = tempPtr + 4;
					
					// Go past the version
					parsePtr++;
					
					/*
					 * Scoop out the CRL Type from the template
					 * if correct template version
					 */					
					
					if(tver >= 3) /* do we have crl version field */
					{
						CRLType = *parsePtr++;
						
					}
					else
						CRLType = CRL_TYPE;
					
					/* prep loop vars for next iteration in case we
					 * are filtering, allows us to skip out easily.
					 */
					block_size -= len;	/* done with this template */
					tempPtr += len;		/* move onto next one */
					
					
					/* get the encoded crl for this entry */
					err = db_GetEntry(session->db_CRLRefSession, 0, &tempKid, &tempData);
					err = DB2SRLerr(err);
					
					if(err != DB_NO_ERR)
					{
						SRLi_FreeObjList( &foundCRLsList);
						free(found_data->item_ptr);
						free(found_data);
						db_unlock("SRLi_GetCRL", __LINE__);
						return(err);
					}
					
					/* scoop out the enc crl data into the linked list */
					if(atList->encObj.data == NULL)	/* first list entry */
					{
						atList->locMask = CLIENT_LOC;
						atList->typeMask = CRLType;
						atList->encObj.data = (uchar *) (tempData->item_ptr);
						atList->encObj.num = tempData->item_len;
						free(tempData);	/* don't need the struct anymore */
					}
					else	/* else we are extending the list */
					{
						atList->next = (EncObject_LL *) malloc(sizeof(EncObject_LL));
						if(atList->next == NULL)
						{
							SRLi_FreeObjList( &foundCRLsList);
							free(found_data->item_ptr);
							free(found_data);
							free(tempData);
							db_unlock("SRLi_GetCRL", __LINE__);
							return(SRL_MEMORY_ERROR);
						}
						atList = atList->next;	/* use the new we created */
						atList->encObj.data = (uchar *) (tempData->item_ptr);
						atList->encObj.num = tempData->item_len;
						atList->locMask = CLIENT_LOC;
						atList->typeMask = CRLType;
						atList->next = 0;	/* no next one yet */
						free(tempData);	/* don't need the struct anymore */
					}
					
					
				} /* end of while (we have items for this dn in db file) */				
			} /* end of if (we found something in local storage) */

			/* Return the error unless nothing was found, but more locations
			remain to be searched */
			else if ((err != SRL_NOT_FOUND) || ((locMask ^ CLIENT_LOC) == 0))
			{
				SRLi_FreeObjList(&foundCRLsList);
				if(found_data != 0)
				{
					if(found_data->item_ptr != 0)
						free(found_data->item_ptr);
					free(found_data);
				}
				db_unlock("SRLi_GetCRL", __LINE__);

				/* Don't return SRL_NOT_FOUND PER DOCUMENT */
				if (err == SRL_NOT_FOUND)
					return SRL_SUCCESS;
				else
					return err;
			}
			
			if(found_data != 0)
			{
				/* free up the found data, we are done breaking it out */
				if(found_data->item_ptr != 0)
					free(found_data->item_ptr);
				free(found_data);
			}
			db_unlock("SRLi_GetCRL", __LINE__);			
		} /* end of if (ok to search local storage ) */
	}

	/* check to see if we were to return once we found something */
	if (!(locMask & SEARCH_ALL_LOC))
	{
		/* if we found something we can return at this time */
		if(foundCRLsList->encObj.data != NULL)
		{
			*crlList = foundCRLsList;	/* give caller the linked list */
			return(SRL_SUCCESS);
		}
	}

	/* see if we should search remote */
    if (locMask & (SERVER_LOC | DSA_LOC))
	{
		err = SRL_SUCCESS;
		
		// Check where to locate remote CRLs - either by a URL or the configured LDAP server
		if ((issuer != NULL) && (locMask & DSA_LOC))
		{
			/* make a call to the remote retrieval code - if ldap avail
			 * and it's all set up, it will attempt to retrieve in
			 * this example of ldap remote get code.
			 */
			if (session->ldapInfo == NULL)
				goto done;
			
			err = SRLi_GetLDAPSessionStatus(sessionID);
			if (err != SRL_SUCCESS)
				goto done;
			
			err = SRLi_GetRemoteCRLs(sessionID, issuer, typeMask, &remoteList);
			/* since we don't consider Not finding something to be
			 * fatal, we will check for the case where either
			 * SRL_NOT_FOUND, or SRL_LDAP_SEARCH_FAILED was returned
			 * and just return whatever was already found locally
			 * if any. Otherwise we check for fatal, then
			 * drop down to the normal processing.
			 */
			if(err == SRL_NOT_FOUND || err == SRL_LDAP_SEARCH_FAILED)
			{
				err = SRL_SUCCESS;
				goto done; /* do normal exit code */
			}
			
			/* if one of the other LDAP errors, return any local
			 * stuff, but tell caller about ldap error
			 */
			if ((err >= SRL_LDAP_LOAD_FAILED) && (err <= SRL_LDAP_FUNCTION_NOT_SPECIFIED))
			{
				if(foundCRLsList->encObj.data == NULL)	/* no matches at all */
					SRLi_FreeObjList( &foundCRLsList);
				
				return(err);
			}
			
			/* otherwise fatal, and return nothing (either local
			 * or remote).
			 */
			if(err != SRL_SUCCESS)
			{
				/* fatal error - throw away any previously found,
				 * and return error code to caller.
				 */
				SRLi_FreeObjList( &remoteList);
				SRLi_FreeObjList( &foundCRLsList);
				return(err);
			}
		} 
		else if (url != NULL) /* search remotely at the specified URL */
		{
			err = SRLi_GetRemoteURLCRLs(sessionID, url, typeMask, locMask,
				&remoteList);
			
			/* since we don't consider Not finding something to be
			 * fatal, we will check for the case where either
			 * SRL_NOT_FOUND, or SRL_LDAP_SEARCH_FAILED was returned
			 * and just return whatever was already found locally
			 * if any. Otherwise we check for fatal, then
			 * drop down to the normal processing.
			 */
			
			if(err == SRL_NOT_FOUND || err == SRL_LDAP_SEARCH_FAILED)
			{
				err = SRL_SUCCESS;
				goto done; /* do normal exit code */
			}
			
			/* if one of the other LDAP errors, return any local
			 * stuff, but tell caller about ldap error
			 */
			if ((err >= SRL_LDAP_LOAD_FAILED) && (err <= SRL_HTTP_ERROR))
			{
				if(foundCRLsList->encObj.data == NULL)	/* no matches at all */
					SRLi_FreeObjList(&foundCRLsList);
				
				*crlList = foundCRLsList;
				return(err);
			}
			
			/* otherwise fatal, and return nothing (either local
			 * or remote).
			 */
			if(err != SRL_SUCCESS)
			{
				/* fatal error - throw away any previously found,
				 * and return error code to caller.
				 */
				SRLi_FreeObjList(&remoteList);
				SRLi_FreeObjList(&foundCRLsList);
				return(err);
			}
		}
		
		/* If we got back results for the given DN, attempt
		 * to add the items to our CRL database that aren't
		 * already in there.
		 *
		 * NOTE: should we only add items that match against
		 * the search criteria, or all items returned from
		 * the remote request? For now I am only adding what
		 * is left after filtering....
		 */

		err = SRLi_FilterRemoteObject(&remoteList,foundCRLsList);
		if(err != SRL_SUCCESS )
		{
			/* error - throw away any previously found,
			 * and return error code to caller.
			 */
			SRLi_FreeObjList(&remoteList);
			SRLi_FreeObjList(&foundCRLsList);
			return(err);
		}


		/* add what is left to the database - */
		atList = remoteList;
		if (session->db_CRLRefSession != 0)
		{
			while(atList != NULL)	/* travel through the list */
			{
				db_lock("SRLi_GetCRL", __LINE__);
				SRLi_DatabaseAdd(sessionID, &atList->encObj, atList->typeMask,
					req_kid.item_ptr);
				db_unlock("SRLi_GetCRL", __LINE__);
				atList = atList->next;
			}
		}
		
		/* append what is left in the remote list to the local list */
		if(foundCRLsList->encObj.data)	/* is there a local list entry */
		{
			/* add any left in remote to local list */
			atList = foundCRLsList;
			while(atList->next != NULL)
				atList = atList->next;	/* loop to last link */
			
			atList->next = remoteList;	/* append */
			
			remoteList = NULL;
			/* done here */
		}
		else if (remoteList != NULL)
		{
			free(foundCRLsList);
			foundCRLsList = remoteList;
		}
		
		/* all done here */
		
	}

	/* exhausted the searching areas, time to collect our thoughts and
	 * tell user what they've won.
	 */
done:

	if(foundCRLsList->encObj.data == NULL)	/* no matches at all */
	{
		SRLi_FreeObjList(&foundCRLsList);
		return(SRL_NOT_FOUND);	/* or no err ??? */
	}

    *crlList = foundCRLsList;
	return(SRL_SUCCESS);
}

short SRLi_GetACbyDN (ulong sessionID, CM_DN issuer, 
				           long typeMask, EncObject_LL** acList)
{
	SRLSession_struct	*session;
	EncObject_LL	*foundACsList, *remoteList;
	short			err;


	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if (issuer == NULL) 
		return SRL_INVALID_PARAMETER;
		
	

	*acList = NULL;	/* default to none found */
	err =  SRLi_GetSessionFromRef(&session, sessionID);
	if(err != SRL_SUCCESS)
		return(err);

	if(*issuer == 0)		/* no empty names here */
		return(SRL_INVALID_PARAMETER);

	foundACsList = (EncObject_LL *) calloc(1, sizeof(EncObject_LL));

	if(foundACsList == NULL)
		return(SRL_MEMORY_ERROR);

	/* init the head to empty */
	foundACsList->encObj.data = 0;
	foundACsList->next = 0;

	err = SRL_SUCCESS;

	/* make a call to the remote retrieval code - if ldap avail
	 * and it's all set up, it will attempt to retrieve in
	 * this example of ldap remote get code.
	*/
	if (session->ldapInfo == NULL)
		goto done;

	err = SRLi_GetLDAPSessionStatus(sessionID);
	if (err != SRL_SUCCESS)
		goto done;

	err = SRLi_GetRemoteACs(sessionID, issuer, typeMask, &remoteList);


	/* since we don't consider Not finding something to be
	 * fatal, we will check for the case where either
	 * SRL_NOT_FOUND, or SRL_LDAP_SEARCH_FAILED was returned
	 * and just return whatever was already found locally
	 * if any. Otherwise we check for fatal, then
	 * drop down to the normal processing.
	*/
	if(err == SRL_NOT_FOUND || err == SRL_LDAP_SEARCH_FAILED)
	{
		err = SRL_SUCCESS;
		goto done; /* do normal exit code */
	}
		
	/* if one of the other LDAP errors, return any local
	 * stuff, but tell caller about ldap error
	 */
	if ((err >= SRL_LDAP_LOAD_FAILED) && (err <= SRL_LDAP_FUNCTION_NOT_SPECIFIED))
	{
		if(foundACsList->encObj.data == NULL)	/* no matches at all */
				SRLi_FreeObjList( &foundACsList);

		return(err);
	}

	/* otherwise fatal, and return nothing (either local
	 * or remote).
	 */
	if(err != SRL_SUCCESS)
	{
		/* fatal error - throw away any previously found,
		 * and return error code to caller.
		*/
		SRLi_FreeObjList( &remoteList);
		SRLi_FreeObjList( &foundACsList);
		return(err);
	}		
		

	free(foundACsList);
	foundACsList = remoteList;

	/* exhausted the searching areas, time to collect our thoughts and
	 * tell user what they've won.
	 */
done:

	if(foundACsList->encObj.data == NULL)	/* no matches at all */
	{
		SRLi_FreeObjList(&foundACsList);
		return(SRL_NOT_FOUND);	/* or no err ??? */
	}
	if (foundACsList != NULL)
	{
		err = SRLi_RemoveDupesInSameObject (foundACsList);
		if ((err != SRL_SUCCESS) && (foundACsList != NULL))
		{
			SRLi_FreeObjList(&foundACsList);
			return (err);
		}
	}
    *acList = foundACsList;
	return(SRL_SUCCESS);
}

short SRLi_GetSPIFbyDN (ulong sessionID, CM_DN issuer, 
				           long typeMask, EncObject_LL** spifList)
{
	SRLSession_struct	*session;
	EncObject_LL	*foundSPIFsList, *remoteList;
	short			err;


	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if (issuer == NULL) 
		return SRL_INVALID_PARAMETER;
		
	

	*spifList = NULL;	/* default to none found */
	err =  SRLi_GetSessionFromRef(&session, sessionID);
	if(err != SRL_SUCCESS)
		return(err);

	if(*issuer == 0)		/* no empty names here */
		return(SRL_INVALID_PARAMETER);

	foundSPIFsList = (EncObject_LL *) calloc(1, sizeof(EncObject_LL));

	if(foundSPIFsList == NULL)
		return(SRL_MEMORY_ERROR);

	/* init the head to empty */
	foundSPIFsList->encObj.data = 0;
	foundSPIFsList->next = 0;

	err = SRL_SUCCESS;

	/* make a call to the remote retrieval code - if ldap avail
	 * and it's all set up, it will attempt to retrieve in
	 * this example of ldap remote get code.
	*/
	if (session->ldapInfo == NULL)
		goto done;

	err = SRLi_GetLDAPSessionStatus(sessionID);
	if (err != SRL_SUCCESS)
		goto done;

	err = SRLi_GetRemoteSPIFs(sessionID, issuer, typeMask, &remoteList);


	/* since we don't consider Not finding something to be
	 * fatal, we will check for the case where either
	 * SRL_NOT_FOUND, or SRL_LDAP_SEARCH_FAILED was returned
	 * and just return whatever was already found locally
	 * if any. Otherwise we check for fatal, then
	 * drop down to the normal processing.
	*/
	if(err == SRL_NOT_FOUND || err == SRL_LDAP_SEARCH_FAILED)
	{
		err = SRL_SUCCESS;
		goto done; /* do normal exit code */
	}
		
	/* if one of the other LDAP errors, return any local
	 * stuff, but tell caller about ldap error
	 */
	if ((err >= SRL_LDAP_LOAD_FAILED) && (err <= SRL_LDAP_FUNCTION_NOT_SPECIFIED))
	{
		if(foundSPIFsList->encObj.data == NULL)	/* no matches at all */
				SRLi_FreeObjList( &foundSPIFsList);

		return(err);
	}

	/* otherwise fatal, and return nothing (either local
	 * or remote).
	 */
	if(err != SRL_SUCCESS)
	{
		/* fatal error - throw away any previously found,
		 * and return error code to caller.
		*/
		SRLi_FreeObjList( &remoteList);
		SRLi_FreeObjList( &foundSPIFsList);
		return(err);
	}		
		

	free(foundSPIFsList);
	foundSPIFsList = remoteList;

	/* exhausted the searching areas, time to collect our thoughts and
	 * tell user what they've won.
	 */
done:

	if(foundSPIFsList->encObj.data == NULL)	/* no matches at all */
	{
		SRLi_FreeObjList(&foundSPIFsList);
		return(SRL_NOT_FOUND);	/* or no err ??? */
	}
	if (foundSPIFsList != NULL)
	{
		err = SRLi_RemoveDupesInSameObject (foundSPIFsList);
		if ((err != SRL_SUCCESS) && (foundSPIFsList != NULL))
		{
			SRLi_FreeObjList(&foundSPIFsList);
			return (err);
		}
	}
    *spifList = foundSPIFsList;
	return(SRL_SUCCESS);
}

short SRLi_searchCRLbyDN (ulong sessionID, CM_DN issuer_dn, EncObject_LL** Obj_List)
{
	SRLSession_struct	*session;
	EncObject_LL	*foundCRLsList, *atList;
	short			err;
	DB_Kid			req_kid, tempKid;
	DB_Data			*found_data, *tempData;
	long			len, block_size;
	uchar			tver, CRLType;
	char			*tempPtr, *parsePtr;
	char			filterInfo[CM_TIME_LEN];


	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;

	if (issuer_dn == NULL) 
		return SRL_INVALID_PARAMETER;
		
	filterInfo[0] = 0;
	

	found_data = 0;
	*Obj_List = NULL;	/* default to none found */
	err =  SRLi_GetSessionFromRef(&session, sessionID);
	if(err != SRL_SUCCESS)
		return(err);

	if(*issuer_dn == 0)		/* no empty names here */
		return(SRL_INVALID_PARAMETER);

	foundCRLsList = (EncObject_LL *) calloc(1, sizeof(EncObject_LL));

	if(foundCRLsList == NULL)
		return(SRL_MEMORY_ERROR);

	/* init the head to empty */
	foundCRLsList->encObj.data = 0;
	foundCRLsList->next = 0;

	atList = foundCRLsList;	/* start the tracker at the top */

	/* see if caller wishes us to search locally, this includes
	 * search local only, search both (local & remote), and the
	 * search till first found flags.
	 */
	/* try to get a crl from the db file. See if the index
	 * contains any entries for the given issuer DN.
	 */
	req_kid.item_len = strlen(issuer_dn)+1;
	req_kid.item_ptr = issuer_dn;

	db_lock("SRLi_searchCRLbyDN", __LINE__);

	err = db_GetEntry(session->db_CRLRefSession, 0, &req_kid, &found_data);
	err = DB2SRLerr(err);

	/* return error codes other than no err, and item not found */
	if((err != SRL_SUCCESS) && (err != SRL_NOT_FOUND))
	{
		SRLi_FreeObjList(&foundCRLsList);
		if(found_data != 0)
		{
			if(found_data->item_ptr != 0)
				free(found_data->item_ptr);
			free(found_data);
		}
		db_unlock("SRLi_searchCRLbyDN", __LINE__);
		return(err);
	}


	/* if we found that one or more entries exist for the item
	* in our index, step through and pull all out.  If there
	* is match criteria, we may filter number of results we
	* return in the list.
	*/

	if(err == SRL_SUCCESS)	/* did we find something */
	{
		/* how many items are represented in the index for this
		* issuer name...
		*/
		block_size = found_data->item_len;	/* total templates size */
		tempPtr = found_data->item_ptr;		/* point at first template */


		while(block_size > 0)
		{
			memcpy((char *)&len,tempPtr,4);		/* len of this template */
			if (SRLisLittleEndian())
				SRLi_FlipLongs((long *) &len, 1);

			tver = (uchar)((len & 0xFF000000) >> 24);
			len = len & 0x00FFFFFF;

			/* given the index info, go get the encoded crl */
			tempKid.item_len = len;
			tempKid.item_ptr = tempPtr;
			parsePtr = tempPtr + 4;
			/*
			* Scoop out the CRL Type from the template
			* if correct template version */
			parsePtr++;

			if(tver >= 3) /* do we have crl version field */
			{
				CRLType = *parsePtr++;

			}
			else
				CRLType = CRL_TYPE;

			/* prep loop vars for next iteration in case we
			* are filtering, allows us to skip out easily.
			*/
			block_size -= len;	/* done with this template */
			tempPtr += len;		/* move onto next one */


			/* get the encoded crl for this entry */
			err = db_GetEntry(session->db_CRLRefSession, 0, &tempKid, &tempData);
			err = DB2SRLerr(err);

			if(err != DB_NO_ERR)
			{
				SRLi_FreeObjList( &foundCRLsList);
				free(found_data->item_ptr);
				free(found_data);
				db_unlock("SRLi_searchCRLbyDN", __LINE__);
				return(err);
			}

			/* scoop out the enc crl data into the linked list */
			if(atList->encObj.data == NULL)	/* first list entry */
			{
				atList->locMask = CLIENT_LOC;
				atList->typeMask = CRLType;
				atList->encObj.data = (uchar *) (tempData->item_ptr);
				atList->encObj.num = tempData->item_len;
				free(tempData);	/* don't need the struct anymore */
			}
			else	/* else we are extending the list */
			{
				atList->next = (EncObject_LL *) malloc(sizeof(EncObject_LL));
				if(atList->next == NULL)
				{
					SRLi_FreeObjList( &foundCRLsList);
					free(found_data->item_ptr);
					free(found_data);
					free(tempData);
					db_unlock("SRLi_searchCRLbyDN", __LINE__);
					return(SRL_MEMORY_ERROR);
				}
				atList = atList->next;	/* use the new we created */
				atList->encObj.data = (uchar *) (tempData->item_ptr);
				atList->encObj.num = tempData->item_len;
				atList->locMask = CLIENT_LOC;
				atList->typeMask = CRLType;
				atList->next = 0;	/* no next one yet */
				free(tempData);	/* don't need the struct anymore */
			}


		} /* end of while (we have items for this dn in db file) */

		if(found_data != 0)
		{
			/* free up the found data, we are done breaking it out */
			if(found_data->item_ptr != 0)
				free(found_data->item_ptr);
			free(found_data);
		}


	} /* end of if (ok to search local storage ) */


	if(foundCRLsList->encObj.data == NULL)	/* no matches at all */
	{
		SRLi_FreeObjList(&foundCRLsList);
		db_unlock("SRLi_searchCRLbyDN", __LINE__);
		return(SRL_NOT_FOUND);	/* or no err ??? */
	}

    *Obj_List = foundCRLsList;
	db_unlock("SRLi_searchCRLbyDN", __LINE__);
	return(SRL_SUCCESS);
}



SRL_API(short) SRL_DatabaseSearch(ulong sessionID, CM_DN dn, DBTypeFlag dbType,
								  dbSearch_struct *searchInfo,
								  EncObject_LL **objlist)
{
	SRLSession_struct	*session;
	SRL_CertMatch_struct *certMatchInfo;
	SRL_CRLMatch_struct *crlMatchInfo;
	EncObject_LL *object = NULL;
	short err = SRL_SUCCESS;
	EncObject_LL *currentEncCrl_LL = NULL;
	char			filterInfo[CM_TIME_LEN];

	if (sessionID == 0)
		return SRL_SESSION_NOT_VALID;
	if (objlist == NULL)
		return SRL_INVALID_PARAMETER;

	err =  SRLi_GetSessionFromRef(&session, sessionID);
	if(err != SRL_SUCCESS)
		return(err);

	if (dbType == SRL_DB_CERT)
	{
		if (session->db_certRefSession == 0)
			return SRL_NO_DB;
	}
	else
	{
		if (session->db_CRLRefSession == 0)
			return SRL_NO_DB;
	}
	if ((dn) && (dn[0] != 0)) 
	{
		if(dbType == SRL_DB_CERT)
		{
			err = SRLi_searchCertByDN (session, dn, dbType, &object);
			if(searchInfo != NULL)
			{
				certMatchInfo = searchInfo->matchInfo.cert;
				if(certMatchInfo != NULL)
				{
					err = SRLi_FilterRemoteCertsList(&object,NULL,
									dn, certMatchInfo);

				}
			}

		}
		else if(dbType == SRL_DB_CRL)
		{
			filterInfo[0] = 0;
			err = SRLi_searchCRLbyDN (sessionID, dn, &object);
			if(searchInfo != NULL)
			{
				crlMatchInfo = searchInfo->matchInfo.crl;
				if(crlMatchInfo != NULL)
				{
					currentEncCrl_LL = object;
					err = SRLi_FilterRemoteCRLsList(&currentEncCrl_LL,
							   NULL,dn, crlMatchInfo, filterInfo);
				}
			}
		}
	}
	else
	{
		if(searchInfo != NULL)
		{
			if(dbType == SRL_DB_CERT)
			{
				certMatchInfo = searchInfo->matchInfo.cert;
				if(certMatchInfo != NULL)
				{
					err = SRLi_GetAllCertsByMatchInfo(sessionID,certMatchInfo,
						&object);

				}
			}
			if (dbType == SRL_DB_CRL)
			{
				crlMatchInfo = searchInfo->matchInfo.crl;
				if (crlMatchInfo != NULL)
				{
					err = SRLi_GetAllCRLsByMatchInfo(sessionID, crlMatchInfo,
						&object);
				}
			}

		}
		else
			// The DN is NULL and the search critiera is NULL
			return (SRL_INVALID_PARAMETER);

	}
	if (object == NULL)
		err = SRL_NOT_FOUND; // No matching item was found in the database
	*objlist = object;

	return(err);
}

short SRLi_GetAllCRLsByMatchInfo (ulong sessionID, SRL_CRLMatch_struct *matchInfo,
								  EncObject_LL **objectlist)
{
	dbEntryList_struct *dblist = NULL;
	dbEntryInfo_LL *entryInfoList = NULL, *entryInfo = NULL;
	dbEntryInfo *dbEntry = NULL;
	dbCRLEntryInfo_LL *CRLEntry;
	Bytes_struct *CRL_data = NULL;
	EncCRL_LL *found_CRL = NULL;
	EncObject_LL *object = NULL;
	long DBid = 0;
	short err = SRL_SUCCESS;

	err = SRL_DatabaseList(sessionID, &dblist, SRL_DB_CRL, 1);
	if (dblist == NULL)
		return (SRL_NOT_FOUND);

		/* Point to the Entry List */
	entryInfoList = dblist->entryList;
	while (entryInfoList != NULL)
	{
		/* Point to the Cert entry information for this linked DN */
		CRLEntry = entryInfoList->info.crls;
		while (CRLEntry != NULL)
		{
			/*
			 * Does the cert entry match?
			 * If there is a match a dbEntryInfo_ll structure
			 * will return with the proper Certificate
			 * pointer passed
			 */

			DBid = 0;
			/* If match result is true, then retreive the cert for this entry */
			if (SRLi_MatchCRLEntry (CRLEntry, matchInfo, &DBid))
			{
				dbEntry = &entryInfoList->info;
				/* Get the Certificate associated with the Entryinfo */
				err = SRL_DatabaseRetrieve (sessionID, 
					SRL_DB_CRL, dbEntry, &CRL_data, DBid);
				if (err != SRL_SUCCESS)
					goto err_cleanup;

				if (CRL_data != NULL)
				{
					/* Build a EncCert Link list */
					found_CRL = (EncCRL_LL *)calloc (1, sizeof (EncCRL_LL));
					found_CRL->encCRL.data = CRL_data->data;
					found_CRL->encCRL.num = CRL_data->num;

				    /* Add it to the Object List */
					err = SRLi_BuildObjectListFmCRLList (&object, found_CRL, 
			                           USER_CERT_TYPE, CLIENT_LOC);
					if (err != SRL_SUCCESS)
						goto err_cleanup;
					object->locMask = CLIENT_LOC;
					free (found_CRL->encCRL.data);
					free (found_CRL);
					found_CRL = NULL;
					CRL_data->data = NULL;
					free(CRL_data);
				}
				
			}

			CRLEntry = CRLEntry->next;

		} /* End while */

		entryInfoList = entryInfoList->next;
	}
	err = SRL_SUCCESS;
	entryInfo = NULL;

err_cleanup:
	if (dblist != NULL)
		SRL_FreeDBListing(&dblist);
	if ((err != SRL_SUCCESS) && (CRL_data != NULL))
		SRLi_FreeBytes(CRL_data);
	if ((err != SRL_SUCCESS) && (object != NULL))
		SRLi_FreeObjList (&object);
	/* Pass the object list back to caller */
	if (object != NULL)
	{
		err = SRLi_RemoveDupesInSameObject (object);
		if ((err != SRL_SUCCESS) && (object != NULL))
		{
			SRLi_FreeObjList(&object);
			return (err);
		}
		*objectlist = object;
	}
	return(err);


}



			
short SRLi_GetAllCertsByMatchInfo (ulong sessionID, SRL_CertMatch_struct *matchInfo,
									EncObject_LL **objectlist)
{
	dbEntryList_struct *dblist = NULL;
	dbEntryInfo_LL *entryInfoList = NULL;
	dbCertEntryInfo_LL *CertEntry = NULL;
	dbEntryInfo *dbEntry = NULL;
	Bytes_struct *cert_data = NULL;
	EncCert_LL *found_cert = NULL;
	EncObject_LL *object = NULL;
	long DBid = 0;
	uchar CertType;
	short err = SRL_SUCCESS;

	/* Get a list of CERT entries */
	err = SRL_DatabaseList(sessionID, &dblist, SRL_DB_CERT, 1);
	if (dblist == NULL)
		return (SRL_NOT_FOUND);

	/* Point to the Entry List */
	entryInfoList = dblist->entryList;
	while (entryInfoList != NULL)
	{
		/* Point to the Cert entry information for this linked DN */
		CertEntry = entryInfoList->info.certs;
		while (CertEntry != NULL)
		{
			/*
			 * Does the cert entry match?
			 * If there is a match a dbEntryInfo_ll structure
			 * will return with the proper Certificate
			 * pointer passed
			 */


			/* If match result is true, then retreive the cert for this entry */
			DBid = 0;
			CertType = 0;
			if (SRLi_MatchCertEntry (CertEntry, matchInfo, &DBid, &CertType))
			{
				dbEntry = &entryInfoList->info;
				/* Get the Certificate associated with the Entryinfo */
				err = SRL_DatabaseRetrieve (sessionID, 
					SRL_DB_CERT, dbEntry, &cert_data, DBid);
				if (err != SRL_SUCCESS)
					goto err_cleanup;

				if (cert_data != NULL)
				{
					/* Build a EncCert Link list */
					found_cert = (EncCert_LL *)calloc (1, sizeof (EncCert_LL));
					found_cert->encCert.data = cert_data->data;
					found_cert->encCert.num = cert_data->num;

				    /* Add it to the Object List */
					err = SRLi_BuildObjectListFmCertList (&object, found_cert, 
			                           USER_CERT_TYPE, CLIENT_LOC);
					if (err != SRL_SUCCESS)
						goto err_cleanup;
					object->locMask = CLIENT_LOC;
					object->typeMask = CertType;
					free (found_cert);					
					found_cert = NULL;
					cert_data->data = NULL;
					free(cert_data);
				}
				
			}
			CertEntry = CertEntry->next;
		} /* End while */

		entryInfoList = entryInfoList->next;
	}
	err = SRL_SUCCESS;

err_cleanup:
	if (dblist != NULL)
		SRL_FreeDBListing(&dblist);
	if ((err != SRL_SUCCESS) && (cert_data != NULL))
		SRLi_FreeBytes(cert_data);
	if ((err != SRL_SUCCESS) && (object != NULL))
		SRLi_FreeObjList (&object);
	/* Pass the object list back to caller */
	if (object != NULL)
	{
		err = SRLi_RemoveDupesInSameObject (object);
		if ((err != SRL_SUCCESS) && (object != NULL))
		{
			SRLi_FreeObjList(&object);
			return (err);
		}
		*objectlist = object;
	}
	return(err);


}

short SRLi_searchCertByDN (SRLSession_struct *session, CM_DN subject_dn, 
				           long dbType, EncObject_LL** Obj_List)
{
	EncObject_LL		*foundCertsList, *atList, *remoteList;
	EncObject_LL      *certificateList;
	short			err;
	DB_Kid			req_kid, tempKid;
	DB_Data			*found_data, *tempData;
	long			len, block_size;
	char			*tempPtr;
	uchar			tver, CertType;
	foundCertsList = NULL;
	atList = NULL;
	remoteList = NULL;

	 *Obj_List = 0;
	found_data = 0;
	certificateList = NULL;	/* default to none found */

	foundCertsList = (EncObject_LL *) calloc(1, sizeof(EncObject_LL));

	if(foundCertsList == NULL)
		return(SRL_MEMORY_ERROR);


	atList = foundCertsList;	/* start the tracker at the top */

	req_kid.item_len = strlen(subject_dn)+1;
	req_kid.item_ptr = subject_dn;

	db_lock("SRLi_searchCertByDN", __LINE__);

	if ((dbType == SRL_DB_CERT))
	{
		err = db_GetEntry(session->db_certRefSession, 0, &req_kid, &found_data);
		err = DB2SRLerr(err);
						/* return error codes other than no err, and item not found */
		if((err != SRL_SUCCESS) && (err != SRL_NOT_FOUND))
		{
			SRLi_FreeObjList(&foundCertsList);
			if(found_data != 0)
			{
				if(found_data->item_ptr != 0)
						free(found_data->item_ptr);
				free(found_data);
			}
			db_unlock("SRLi_searchCertByDN", __LINE__);
			return(err);
		}
	}
	else /* Cross cert requested */
	{
		free (foundCertsList);
		found_data = NULL;
		db_unlock("SRLi_searchCertByDN", __LINE__);
		return (SRL_SUCCESS);
		
	}
	/* if we found that one or more entries exist for the item
	* in our index, step through and pull all out.  If there
	* is match criteria, we may filter number of results we
	* return in the list.
	*/

	if(err == SRL_SUCCESS)	/* did we find something */
	{
		/* how many items are represented in the index for this
		* subject name...
		*/
		block_size = found_data->item_len;	/* total templates size */
		tempPtr = found_data->item_ptr;		/* point at first template */

		while(block_size > 0)
		{
			memcpy((char *)&len, tempPtr, 4); 	/* length of just this block */
			if (SRLisLittleEndian())
				SRLi_FlipLongs((long *) &len, 1);
			tver = (uchar)((len & 0xFF000000) >> 24);

			// Get the length
			len = len & 0x00FFFFFF;
			/* given the index info, go get the encoded cert */
			tempKid.item_len = len;
			tempKid.item_ptr = tempPtr;
			// Get the Cert Type from the template
			if (tver >= 3)
			{
				CertType = tempPtr[5];
			}
			else
				CertType = SRL_CERT_TYPE; // Default to User cert

			/* prep loop vars for next iteration in case we
			* are filtering, allows us to skip out easily.
			*/
			block_size -= len;	/* done with this template */
			tempPtr += len;		/* move onto next one */



			/* get the encoded cert for this entry */
			err = db_GetEntry(session->db_certRefSession, 0, &tempKid, &tempData);
			err = DB2SRLerr(err);

			if(err != SRL_SUCCESS)
			{
				SRLi_FreeObjList(&foundCertsList);
				free(found_data->item_ptr);
				free(found_data);
				db_unlock("SRLi_searchCertByDN", __LINE__);
				return(err);
			}

			/* scoop out the enc cert data into the linked list */
			if(atList->encObj.data == NULL)	/* first list entry */
			{
				atList->encObj.data = (uchar *) (tempData->item_ptr);
				atList->encObj.num = tempData->item_len;
				atList->locMask = CLIENT_LOC;
				atList->typeMask = CertType;
				free(tempData);	/* don't need the struct anymore */
			}
			else	/* else we are extending the list */
			{
				atList->next = (EncObject_LL *) calloc(1,sizeof(EncObject_LL));
				if(atList->next == NULL)
				{
					SRLi_FreeObjList(&foundCertsList);
					free(found_data->item_ptr);
					free(found_data);
					free(tempData);
					db_unlock("SRLi_searchCertByDN", __LINE__);
					return(SRL_MEMORY_ERROR);
				}
				atList = atList->next;	/* use the new we created */
				atList->encObj.data = (uchar *) (tempData->item_ptr);
				atList->encObj.num = tempData->item_len;
				atList->typeMask = CertType;
				atList->locMask = CLIENT_LOC;
				atList->next = 0;	/* no next one yet */
				free(tempData);	/* don't need the struct anymore */
			}

		} /* end of while (we have items for this dn in db file) */

	} /* end of if (we found something in local storage) */

	err = SRLi_RemoveDupesInSameObject (foundCertsList);
	if (err != SRL_SUCCESS)
	{
		db_unlock("SRLi_searchCertByDN", __LINE__);
		return (err);
	}
	*Obj_List = foundCertsList;
	if(found_data != 0)
	{
		/* free up the found data, we are done breaking it out */
		if(found_data->item_ptr != 0)
			free(found_data->item_ptr);
		free(found_data);
	}

	
	if(foundCertsList->encObj.data == NULL)	/* no matches at all */
	{
		SRLi_FreeObjList(&foundCertsList);
	}


	*Obj_List = foundCertsList;	/* give caller the linked list */

	db_unlock("SRLi_searchCertByDN", __LINE__);
	return(SRL_SUCCESS);

}
/* 
 * Compare a Data Base Entry to the Match Information passed in
 */
CM_BOOL SRLi_MatchCertEntry (dbCertEntryInfo_LL *the_entry, SRL_CertMatch_struct *matchInfo,
							 long *DBid, uchar *CertType)
{
CM_BOOL matches = TRUE;
Policy_struct	*polyPtr;

	if (matchInfo != NULL)
	{
			/* check each matchInfo field */
			if(matchInfo->algOID != NULL)
			{
				/* compare the given oid string against the cert oid string */
				if(strcmp(the_entry->algOID, matchInfo->algOID ) == 0)
					matches &= TRUE;
				else
					matches &= FALSE;
			}
			
			if(matchInfo->validOnDate != NULL)
			{
				/* check cert date bounds */
				if ((strcmp(the_entry->validFrom[0], matchInfo->validOnDate[0] ) < 0) &&
					(strcmp(the_entry->validTill[0], matchInfo->validOnDate[0] ) >= 0))
					matches &= TRUE;
				else
					matches &= FALSE;
			}
			
			if(matchInfo->issuerDN != NULL)
			{
				if(SRLDNcmp(the_entry->issuer_DN, matchInfo->issuerDN) == 0)
					matches &= TRUE;
				else
					matches &= FALSE;
			}
			if (matchInfo->emailAddr != NULL)
			{
				/* Compare and ignore case */
				if ( SRLDNcmp (the_entry->emailAddr, matchInfo->emailAddr) == 0)
					matches &= TRUE;
				else
					matches &= FALSE;
			}
			if (matchInfo->serialNum != NULL)
			{
				if (matchInfo->serialNum->num == the_entry->serialNum->num)
				{
					/* Number compares */
					if ((memcmp (the_entry->serialNum->data, matchInfo->serialNum->data, matchInfo->serialNum->num) == 0))
						matches &= TRUE;
					else
						matches &= FALSE;
				}
				else
					matches &= FALSE;
			}
			if (matchInfo->pkeyLen != 0)
			{
				if (matchInfo->pkeyLen == the_entry->pkey_len)
					matches &= TRUE;
				else
					matches &= FALSE;
			}
			if (matchInfo->subjKMID != NULL)
			{
				if (matchInfo->subjKMID->num == the_entry->sub_kmid->num)
				{
					if ((memcmp (the_entry->sub_kmid->data, 
								the_entry->sub_kmid->data, the_entry->sub_kmid->num) == 0))
						matches &= TRUE;
					else
						matches &= FALSE;
				}
				else
				{
					matches &= FALSE;
				}
			}
			if(matchInfo->policies != NULL)
			{
				//polyPtr = SRLi_GetPolyPtr(cert);
				polyPtr = the_entry->poly;
				while(polyPtr != NULL)
				{
					if(strcmp(polyPtr->policy_id, matchInfo->policies->policy_id) == 0)
					{
						matches &= TRUE;
					}
					else
						matches &= FALSE;

					polyPtr = polyPtr->next;
				}
								
			}
			if (matchInfo->CertType != 0)
			{
				if (the_entry->CertType == matchInfo->CertType)
					matches &= TRUE;
			}

	} /* Endif matchInfo */
	else
		matches = FALSE;
	if (matches)
	{
		*DBid = the_entry->DBid;
		*CertType = the_entry->CertType;
	}
	return (matches);
}


/* 
 * Compare a Data Base Entry to the Match Information passed in
 */
CM_BOOL SRLi_MatchCRLEntry (dbCRLEntryInfo_LL *the_entry, SRL_CRLMatch_struct *matchInfo,
							long *DBid)
{
CM_BOOL matches = TRUE;

	if (matchInfo != NULL)
	{
			/* check each matchInfo field */
			if(matchInfo->signature != NULL)
			{
				/* compare the given oid string against the cert oid string */
				if(strcmp(the_entry->signature, matchInfo->signature ) == 0)
					matches &= TRUE;
				else
					matches &= FALSE;
			}
			
			if(matchInfo->issueAfter != NULL)
			{
				/* check CRL date bounds */
				if (strcmp(&the_entry->nextDate[0], matchInfo->issueAfter[0] ) >= 0)
					matches &= TRUE;
				else
					matches &= FALSE;
			}
			
			if(matchInfo->issueBefore != NULL)
			{
				/* check CRL date bounds */
				if (strcmp(&the_entry->issueDate[0], matchInfo->issueBefore[0] ) <= 0) 
					matches &= TRUE;
				else
					matches &= FALSE;
			}


	} /* Endif matchInfo */
	else
		matches = FALSE;
	/* Pass Back the DBid */
	if (matches)
		*DBid = the_entry->DBid;

	return (matches);
}

short SRLi_RemoveDupesInSameObject(EncObject_LL *checkList)
{
	EncObject_LL *atList, *prevList;
	if (checkList == NULL)
		return (SRL_SUCCESS);
	prevList = checkList;
	atList = checkList->next;
	while(checkList != NULL)
	{
		while(atList != NULL)
		{
			if (checkList->encObj.num == atList->encObj.num)		 	
		 	{
		 		/* yep, compare the data */
			 	if(memcmp(checkList->encObj.data, atList->encObj.data,
					checkList->encObj.num) == 0)
			 	{
			 		/* identical, remove this one, patch the links */
			 		free(atList->encObj.data);
			 		prevList->next = atList->next;
			 		free(atList);
			 		atList = prevList;
			 	}
			}
			prevList = atList;
			atList = atList->next;	/* move onto next */
		 	
		 }
		 /* move to next and reset */
		 checkList = checkList->next;	/* next top of the list */
		 if(checkList)
		 {
		 	prevList = checkList;	/* start prev at top again */
		 	atList = checkList->next;	/* start comparing against the next link */
		 }

	}
	return (SRL_SUCCESS);
}
short SRLi_BuildObjectListFmCertList (EncObject_LL **Obj_List, EncCert_LL *cert_list, 
			                           long typeMask, short location) 
{
EncObject_LL *temp_obj_ptr;
EncObject_LL *new_obj_ptr;
EncCert_LL *temp_cert_ptr = cert_list;

    if (Obj_List == NULL)
		return SRL_NULL_POINTER;
	
	/* Go to end of list - this routine can append data */
	temp_obj_ptr = *Obj_List;
	while (temp_obj_ptr && (temp_obj_ptr->next != NULL))
	{
		temp_obj_ptr = temp_obj_ptr->next;
	}


	/* 
	 * Start adding the cert list to the Object List
	 * adding the type and location masks
	 */
	while (temp_cert_ptr != NULL)
	{
			
	    new_obj_ptr = calloc (1, sizeof (EncObject_LL));

		/* Add the Bytes_struct to the Cert list */
        new_obj_ptr->encObj.data = temp_cert_ptr->encCert.data;
		new_obj_ptr->encObj.num = temp_cert_ptr->encCert.num;
		new_obj_ptr->typeMask = typeMask;
		new_obj_ptr->locMask = location;
		temp_cert_ptr->encCert.data = NULL;
		temp_cert_ptr = temp_cert_ptr->next;
		if(temp_obj_ptr == NULL)
		{
			*Obj_List = new_obj_ptr;
		}
		else
			temp_obj_ptr->next = new_obj_ptr;
		temp_obj_ptr = new_obj_ptr;
	}
	return (SRL_SUCCESS);
} /* End of function */


short SRLi_BuildObjectListFmCRLList (EncObject_LL **Obj_List, EncCRL_LL *crl_list, 
			                           long typeMask, short location) 
{
EncObject_LL *temp_obj_ptr;
EncObject_LL *new_obj_ptr;
EncCRL_LL *temp_crl_ptr = crl_list;

    if (Obj_List == NULL)
		return SRL_NULL_POINTER;
	
	/* Go to end of list - this routine can append data */
	temp_obj_ptr = *Obj_List;
	while (temp_obj_ptr && (temp_obj_ptr->next != NULL))
	{
		temp_obj_ptr = temp_obj_ptr->next;
	}


	/* 
	 * Start adding the cert list to the Object List
	 * adding the type and location masks
	 */
	while (temp_crl_ptr != NULL)
	{
			
	    new_obj_ptr = calloc (1, sizeof (EncObject_LL));

		/* Add the Bytes_struct to the Cert list */
        new_obj_ptr->encObj.data = temp_crl_ptr->encCRL.data;
		new_obj_ptr->encObj.num = temp_crl_ptr->encCRL.num;
		new_obj_ptr->typeMask = typeMask;
		new_obj_ptr->locMask = location;
		temp_crl_ptr->encCRL.data = NULL;
		temp_crl_ptr = temp_crl_ptr->next;
		if(temp_obj_ptr == NULL)
		{
			*Obj_List = new_obj_ptr;
		}
		else
			temp_obj_ptr->next = new_obj_ptr;
		temp_obj_ptr = new_obj_ptr;
	}
	return (SRL_SUCCESS);
} /* End of function */


short SRLi_FilterRemoteObject(EncObject_LL **remoteObjPtr,EncObject_LL *localObjptr)
{
	short err = SRLi_RemoveDupesInSameObject (*remoteObjPtr);
	if (err != SRL_SUCCESS)
		return err;
	return SRLi_RemoveDupesInTwoObjects (localObjptr, remoteObjPtr);
}


/*
 * This routine will compare the encoded data in two different
 * links, removing the duplicates from the "secondList" that
 * appear in "originalList". Since the top link of "secondList"
 * may be pruned, the caller passes us the ** so that we can
 * update their ref.
 */
short SRLi_RemoveDupesInTwoObjects(EncObject_LL *originalList, EncObject_LL **secondListPtr)
{
	EncObject_LL *filtList, *atList, *prevList;

	atList = filtList = prevList = NULL;
	/* loop through the originalList list and compare any that
	 * are in the secondListPtr list - remove duplicates from
	 * the secondListPtr list.
	 */
	filtList = originalList;
	if (*secondListPtr != NULL)
	{
		atList	= prevList = *secondListPtr;	/* compare to in here */
		while(filtList != NULL)	/* for each in the orig list */
		{
		
			/* compare all the others to this one */
			while(atList != NULL)
			{
		 		if (atList->encObj.num != 0)
				{
			 		if(atList->encObj.num == filtList->encObj.num)	/* are they the same size */	
			 		{
			 			/* yep, compare the data */
				 		if(memcmp(filtList->encObj.data, atList->encObj.data,
							atList->encObj.num) == 0)
				 		{
				 			/* identical, remove this one, patch the links */
				 			if(prevList != atList) /* not at the top */
				 			{
			 					prevList->next = atList->next; /* skip this linkage */
			 					free(atList);	/* remove the link */
			 					atList = prevList;	/* set to skip the one we removed */
				 			}
				 			else
				 			{
				 				*secondListPtr = prevList = atList->next; /* rem top, so reset */
			 					free(atList); /* remove the link */
			 					atList = prevList;
			 					prevList = NULL;	/* so we know we have a new top */
			 				}
						}
					}
				}
				if(prevList == NULL)	/* did we set up a new top link */
				{
					prevList = atList;	/* loop with both pointing at top */
				}
				else /* past top, so set up to move down the linked list */
				{
					prevList = atList;	/* will be new previous link */
					if(atList != NULL)	/* if not at the end already */
						atList = atList->next;	/* move onto next link */
				}
			 }
			 /* move to next and reset */
			 filtList = filtList->next;	/* next one in the orig listing */
			 /* start at top of remote list again */
			 prevList = atList = *secondListPtr;
	
		} /* end of while entries in local listing */
	} /* End if */
	return(SRL_SUCCESS);
}

short SRL_StoreObjs(ulong sessionID, short loc, EncObject_LL* ppObjList)
/* 
 * This function is used to store object in the specified location. Typically, 
 * this function is used to add objects to the loca database. The
 * type flag in the EncObject_LL, must be correctly set.
 *
 * Function Returns:
 *
 * Value					Description
 * SRL_MEMORY_ERROR			Out of memory
 * SRL_INVALID_PARAMETER	Bad parameter passed in
 * SRL_SESSION_NOT_VALID	Indicated session does not exist
 * SRL_NULL_POINTER			Internal error - NULL pointer discovered
 * SRL_ASN_ERROR			The object was not correctly ASN.1 encoded
 * SRL_DB_IO_ERROR			I/O error occured while accessing the database
 * SRL_UNKNOW_LOCATION		The location is unknown to the SRL
 *
 * Calls:
 * short SRL_DatabaseAdd(ulong SRLSession, Bytes_struct *asn1Obj, AsnTypeFlag type)
 */
{
	Bytes_struct *tempObject;
	short err = SRL_SUCCESS;
	int noDB = 0;
	SRLSession_struct	*session = NULL;
	if (sessionID == 0)
		return (SRL_SESSION_NOT_VALID);

	err =  SRLi_GetSessionFromRef(&session, sessionID);
	if(err != SRL_SUCCESS)
		return(err);
	
	if (loc != CLIENT_LOC)
		return (SRL_INVALID_PARAMETER);

	if (ppObjList == NULL)
		return (SRL_INVALID_PARAMETER);
	
	/* While there is data on the link list, add it to the database */
	while (ppObjList != NULL)
	{
		noDB = 0;
		if (ppObjList->typeMask != SRL_CRL_TYPE)
		{
			if (session->db_certRefSession == 0)
				noDB = 1;
		}
		else
		{
			if (session->db_CRLRefSession == 0)
				noDB = 1;
		}

		/* Point to the ANS.1 Encoded object */
		tempObject = &ppObjList->encObj;
		if (noDB == 0)
		{
			err = SRL_DatabaseAdd (sessionID, tempObject, (AsnTypeFlag)ppObjList->typeMask);
			if (err != SRL_SUCCESS)
				return (err);
		}
		ppObjList = ppObjList->next;
	}
	return (SRL_SUCCESS);
} /* End of function */

short SRLi_FilterRemoteCertsList(EncObject_LL **remoteListPtr,EncObject_LL *localList,
	CM_DN subject, SRL_CertMatch_struct *matchInfo)
{
	EncObject_LL	*filtList, *prevList;
	short		err, remove, tempShort;
	Bytes_struct kmid;
	Cert_struct *cert;
	Policy_struct	*polyPtr;
	char			*email;
	Gen_names_struct *tmpGenName;
	RDN_LL			*parsedDN, *rdn;
				  
	/* since we are modifying the lists, use local copy of the
	 * ptrs here. (we use a ** for the list we are filtering
	 * since we may need to remove the top link and the caller
	 * will need to know that)
	 */
	
	 /* loop through the remote list and remove any that
	  * are the same (may have duplicate items returned
	  * from ldap server for example). Does not effect top
	  * link.
	  */
	err = SRLi_RemoveDupesInSameList(*remoteListPtr);
	if(err != SRL_SUCCESS)
		return(err);
	
	/* loop through the remote list again, this time removing any
	 * item's that are duplicates of the local list (if there
	 * are any in the local list - NOTE you have to check
	 * to see if there is data, not just the link...)
	 */
	if (localList != NULL)
	{
	   if((localList->encObj.data != NULL) && ( *remoteListPtr != NULL)) /* and stuff in remote */
	   {
	 	   /* this call may effect caller's top link, so pass
		    * the double ref.
		    */

		   err = SRLi_RemoveDupesInTwoLists(localList, remoteListPtr);
		   if(err != SRL_SUCCESS)
		  	  return(err);
		
	   } /* end of if locallist exists */
	}
	
	/* make sure that what is left matches on the DN */
	filtList = prevList = *remoteListPtr;
	err = SRL_SUCCESS;
	
	while(filtList != NULL)	/* if we still have something */
	{

		err = CM_DecodeCert(&filtList->encObj, &cert);
//		err = CM_GetEncodedDN(&filtList->encObj, &encodedDN);
		if(err != SRL_SUCCESS)
			break;
		
		/* decode the dn */
//		err = CM_DecodeDN(encodedDN, &decodedDN);
//		free(encodedDN->data);
//		free(encodedDN);
		
		if(err != SRL_SUCCESS)
			break;
		
/*		if(strcmp(decodedDN, subject) != 0)	 if different */
		if (SRLDNcmp(cert->subject, subject) != 0)
		{
			/* this asn1 item should not be in our list, remove it */
			free(filtList->encObj.data);
			if(filtList == *remoteListPtr) /* if at the top */
			{
				*remoteListPtr = prevList = filtList->next;
				free (filtList);
				filtList = prevList;
			}
			else
			{
				prevList->next = filtList->next;
				free(filtList);
				filtList = prevList->next;
			}
			
		}
		else
		{
				prevList = filtList;
				if (filtList)
					filtList = prevList->next;
		}

//		free(decodedDN);
//		decodedDN = NULL;
		CM_FreeCert(&cert);

	}
	if(err != SRL_SUCCESS) return(err);
	
	
	/* if match criteria, need to check the remote list if any left */
	if(matchInfo != NULL )
	{
		/* have to decode each item left in the list and compare */
		filtList = prevList = *remoteListPtr;
		while(filtList != NULL)
		{
			remove = FALSE;	/* start as not needing to remove */
			err = CM_DecodeCert(&filtList->encObj, &cert);
			if(err != SRL_SUCCESS)
				break;
			
			/* check each field */
			if(matchInfo->algOID != NULL)
			{
				/* compare the given oid string against the cert oid string */
				if(strcmp(cert->pub_key.oid, matchInfo->algOID ) != 0)
				{
					remove = TRUE;
					goto check_rem;
				}
			}
			
			if(matchInfo->validOnDate != NULL)
			{
				/* check cert date bounds */
				if( (strcmp(cert->val_not_before, matchInfo->validOnDate[0] ) > 0) ||
					(strcmp(cert->val_not_after, matchInfo->validOnDate[0] ) < 0) )
				{
					remove = TRUE;
					goto check_rem;
				}
			}
			
			if(matchInfo->issuerDN != NULL)
			{
				if(SRLDNcmp(cert->issuer, matchInfo->issuerDN) != 0)
				{
					remove = TRUE;
					goto check_rem;
				}
			}
			
			if(matchInfo->emailAddr != NULL)
			{
				/* first off check against the subjAltName extension,
				 * then check against the subject DN
				 * NOTE: checking here against the subject DN may
				 * be redundant since we supposely already matched
				 * against the DN, in which case searching by email
				 * would not be necessary if it's in the DN...
				 * I'll check anyways here, but it probably could
				 * be removed...
				 */
				
				email = NULL;
				parsedDN = NULL;
			
				if ((cert->exts != NULL) && (cert->exts->subjAltName != NULL))
				{
					tmpGenName = cert->exts->subjAltName->value;
					while ((tmpGenName != NULL) && (email == NULL))
					{
						if (tmpGenName->gen_name.flag == CM_RFC822_NAME)
						{
							email = tmpGenName->gen_name.name.rfc822;
							if(strcmp(matchInfo->emailAddr, email) == 0)
							{
								/* if they matched, no more searching necessary
								 * for emails.
								 * break out.
								 */
								break;
							}
							else email = NULL;	/* keep on looking */
						}
						tmpGenName = tmpGenName->next;
					}
			
				}
			
				if (email == NULL)
				{
					email = strstr(cert->subject, "emailAddress");
				/*	email = strstr(cert->subject, EMAIL_ADDR_OID); */
					if (email != NULL)
					{
						err = SRLi_RetParseRDNSeq(cert->subject, &parsedDN);
						if (err != SRL_SUCCESS)
							break;
			
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
						/*	email += strlen(EMAIL_ADDR_OID) + 1; */
							email += strlen("emailAddress") + 1;
					}
				}
			
				/* Add the length of the e-mail address */
				if (email != NULL)
				{
					if(strcmp(matchInfo->emailAddr, email) != 0)
					{
						SRLi_FreeRDN_LL(&parsedDN);
						remove = TRUE;
						goto check_rem;
					}
					SRLi_FreeRDN_LL(&parsedDN);
				}
				else
				{
					/* nothing to match against */
					SRLi_FreeRDN_LL(&parsedDN);
					remove = TRUE;
					goto check_rem;
				}
			
			
			}
			
			
			if(matchInfo->serialNum != NULL)
			{
				if( (cert->serial_num.num != matchInfo->serialNum->num) ||
					(memcmp(cert->serial_num.data, matchInfo->serialNum->data,
						cert->serial_num.num) != 0) )
				{
					remove = TRUE;
					goto check_rem;
				}
			}
			
			if(matchInfo->policies != NULL)
			{
				/* check for any matching, else remove */
				remove = TRUE;
				polyPtr = SRLi_GetPolyPtr(cert);
				while(polyPtr != NULL)
				{
					if(strcmp(polyPtr->policy_id, matchInfo->policies->policy_id) == 0)
					{
						remove = FALSE;
						break;
					}
					polyPtr = polyPtr->next;
				}
				
				if(remove) goto check_rem;
				
			}
			
			if(matchInfo->subjKMID != NULL)
			{
				/* kmid - differs depending on version */
				/* check the cert version, so we know where the kmid
				 * info should be.
				 */
				kmid.num = 0;	/* def to none */
				kmid.data = 0;
			
				if(cert->version == 1)
				{
					/* check for mosaic algorithm */
					if(0 == strcmp(gDSA_KEA_OID, cert->pub_key.oid))
					{
						kmid.num = CM_KMID_LEN;
						kmid.data = cert->pub_key.key.combo->kmid;
					}
				}
				else	/* for ver 2 or 3 */
				{
					/* if version 3, first check for an extension */
					if (cert->version == 3)
					{
					    if ((cert->exts != NULL) && (cert->exts->subjKeyID != NULL))
			            {                           /* Subject Key ID extension present */
			                kmid.num =
			                    ((Bytes_struct *)cert->exts->subjKeyID->value)->num;
			                kmid.data =
			                    ((Bytes_struct *)cert->exts->subjKeyID->value)->data;
			            }
			        }
				}
				
				/* now do the comparison */
				if( (kmid.num != 0) && ((kmid.num != matchInfo->subjKMID->num) ||
					(memcmp(kmid.data, matchInfo->subjKMID->data, kmid.num) != 0)) )
				{
					remove = TRUE;
					goto check_rem;
				}
				
				
			}
			
			if(matchInfo->pkeyLen != 0)
			{
				/* determine what key alg used so we know which pub key
				 * struct is currently in use.
				 */
				if((strcmp(cert->pub_key.oid, gDSA_OID) == 0) ||
					(strcmp(cert->pub_key.oid, gKEA_OID) == 0) ||
		            (strcmp(cert->pub_key.oid, gOLD_DH_OID) == 0)  ||
		            (strcmp(cert->pub_key.oid, gANSI_DH_OID) == 0)  ||
					(strcmp(cert->pub_key.oid, gOIW_DSA) == 0))
				{
					tempShort = (short)(cert->pub_key.key.y->num * 8);
				}
				else if(strcmp(cert->pub_key.oid, gRSA_OID) == 0)
				{
					/* rsa keys. */
					tempShort = (short)(cert->pub_key.key.rsa->modulus.num * 8);
				}
				else	/* fortezza v.1 cert - combo keys. We will check kea len
							 here (same as dsa right now) */
					tempShort = (short)cert->pub_key.key.combo->kea_y.num;
				
				if(matchInfo->pkeyLen != tempShort)
				{
					remove = TRUE;
					goto check_rem;
				}
			}
	
check_rem:
			if(remove == TRUE) /* if filtered out by match criteria */
			{
				free(filtList->encObj.data);
				if(filtList == *remoteListPtr)	/* is it the top */
					*remoteListPtr = prevList = filtList->next;
				else
					prevList->next = filtList->next;
				
				free(filtList);
				filtList = prevList;
			}
			else
			{
			
				prevList = filtList;
			    if(filtList)
			     filtList = filtList->next;	/* move onto checking next link */
			}
			CM_FreeCert(&cert);
			
		} /* end of while ( items in our linked list of enc certs) */
	
	} /* end of if (there is matchInfo to check against */
	
	/* all done here */
	return(err);
	
}

short SRLi_RemoveDupesInSameList(EncObject_LL *checkList)
{
	EncObject_LL *atList, *prevList;
	ulong		ulen, len2;
	short		err;
	
	if (checkList == NULL)
		return (SRL_SUCCESS);
	prevList = checkList;
	atList = checkList->next;
	while(checkList != NULL)
	{
		err = SRLi_AsnGetLength(checkList->encObj.data, &ulen); /* len of the asn1 obj */
		 if(err != SRL_SUCCESS) return err;
		 
		/* compare rest of links to the one in top/checklist */
		while(atList != NULL)
		{
			/* quick check is just the compare of the lens */
			err = SRLi_AsnGetLength(atList->encObj.data, &len2); /* len of the asn1 obj */
		 	if(err != SRL_SUCCESS) return err;
		 	
		 	if(len2 == ulen)	/* are they the same size */
		 	{
		 		/* yep, compare the data */
			 	if(memcmp(checkList->encObj.data, atList->encObj.data, ulen) == 0)
			 	{
			 		/* identical, remove this one, patch the links */
			 		free(atList->encObj.data);
			 		prevList->next = atList->next;
			 		free(atList);
			 		atList = prevList;
			 	}
			}
			prevList = atList;
			atList = atList->next;	/* move onto next */
		 	
		 }
		 /* move to next and reset */
		 checkList = checkList->next;	/* next top of the list */
		 if(checkList)
		 {
		 	prevList = checkList;	/* start prev at top again */
		 	atList = checkList->next;	/* start comparing against the next link */
		 }
	}
	
	return(SRL_SUCCESS);
}
short SRLi_RemoveDupesInTwoLists(EncObject_LL *originalList, EncObject_LL **secondListPtr)
{
EncObject_LL *filtList, *atList, *prevList;
ulong		ulen, len2;
short		err;

	/* loop through the originalList list and compare any that
	 * are in the secondListPtr list - remove duplicates from
	 * the secondListPtr list.
	 */
	filtList = originalList;
	atList	= prevList = *secondListPtr;	/* compare to in here */
	while(filtList != NULL)	/* for each in the orig list */
	{
		err = SRLi_AsnGetLength(filtList->encObj.data, &ulen); /* len of the asn1 obj */
		if(err != SRL_SUCCESS) return(err);
		
		/* compare all the others to this one */
		while(atList != NULL)
		{
			/* quick check is just the compare of the lens */
			err = SRLi_AsnGetLength(atList->encObj.data, &len2); /* len of the asn1 obj */
		 	if(err != SRL_SUCCESS) return(err);
		 	
		 	if(len2 == ulen)	/* are they the same size */
		 	{
		 		/* yep, compare the data */
			 	if(memcmp(filtList->encObj.data, atList->encObj.data, ulen) == 0)
			 	{
			 		/* identical, remove this one, patch the links */
			 		free(atList->encObj.data);
			 		if(prevList != atList) /* not at the top */
			 		{
			 			prevList->next = atList->next; /* skip this linkage */
			 			free(atList);	/* remove the link */
			 			atList = prevList;	/* set to skip the one we removed */
			 		}
			 		else
			 		{
			 			*secondListPtr = prevList = atList->next; /* rem top, so reset */
			 			free(atList); /* remove the link */
			 			atList = prevList;
			 			prevList = NULL;	/* so we know we have a new top */
			 		}
			 	}
			}
			if(prevList == NULL)	/* did we set up a new top link */
			{
				prevList = atList;	/* loop with both pointing at top */
			}
			else /* past top, so set up to move down the linked list */
			{
				prevList = atList;	/* will be new previous link */
				if(atList != NULL)	/* if not at the end already */
					atList = atList->next;	/* move onto next link */
			}
		 }
		 /* move to next and reset */
		 filtList = filtList->next;	/* next one in the orig listing */
		 /* start at top of remote list again */
		 prevList = atList = *secondListPtr;
	
	} /* end of while entries in local listing */
	
	return(SRL_SUCCESS);
}

short SRLi_FilterRemoteCRLsList(EncObject_LL **remoteListPtr,
							   EncObject_LL *localList,CM_DN issuer, 
							   SRL_CRLMatch_struct *matchInfo, char *mostRecent)
{
	EncObject_LL	*filtList, *prevList;
	short		err, remove;
	CRL_struct 		*crl;
				  
	/* since we are modifying the lists, use local copy of the
	 * ptrs here. (we use a ** for the list we are filtering
	 * since we may need to remove the top link and the caller
	 * will need to know that)
	 * ALSO NOTE: we can cast here to EncCert_LL since it's
	 * struct is the same as the EncCRL_LL, allowing us
	 * to use the same linked list weeding code
	 */
	
	 /* loop through the remote list and remove any that
	  * are the same (may have duplicate items returned
	  * from ldap server for example). Does not effect top
	  * link.
	  */
	err = SRLi_RemoveDupesInSameList((EncObject_LL *) (*remoteListPtr));
	if(err != SRL_SUCCESS)
		return(err);
	
	/* loop through the remote list again, this time removing any
	 * item's that are duplicates of the local list (if there
	 * are any in the local list - NOTE you have to check
	 * to see if there is data, not just the link...)
	 */
	if (localList != NULL)
	{
		if((localList->encObj.data != NULL) && ( *remoteListPtr != NULL)) /* and stuff in remote */
		{
		/* this call may effect caller's top link, so pass
		 * the double ref.
		 */
			err = SRLi_RemoveDupesInTwoLists(localList, remoteListPtr);
			if(err != SRL_SUCCESS)
				return(err);
			
		} /* end of if locallist exists */
	}
	
	/* make sure that what is left matches on the DN and any matching criteria
	 * that the caller provides (if any).
	 */
	filtList = prevList = *remoteListPtr;
	err = SRL_SUCCESS;
	
	while(filtList != NULL)	/* if we still have something */
	{
		remove = FALSE;	/* start as not needing to remove */
		// Decode the crl and the extension, don't decode the revocations
		err = CM_DecodeCRL2(&filtList->encObj, &crl, FALSE, TRUE);
		if(err != SRL_SUCCESS)
			break;
			
	/*	if(strcmp(crl->issuer, issuer) != 0)	 if different */
		if(SRLDNcmp(crl->issuer, issuer) != 0)
		{
			remove = TRUE;
			goto check_rem;
		}
		
		/* if match criteria, need to check the  list against it */
		if(matchInfo != NULL )
		{
			/* check each field */
			if(matchInfo->signature != NULL)
			{
				/* compare the given oid string against the crl oid string */
				if(strcmp(crl->signature, matchInfo->signature ) != 0)
				{
					remove = TRUE;
					goto check_rem;
				}
			}
			
			if(matchInfo->issueAfter != NULL)
			{
				/* check crl date bounds */
				if(strcmp(crl->thisUpdate, matchInfo->issueAfter[0] ) < 0)
				{
					remove = TRUE;
					goto check_rem;
				}
			}
			
			if(matchInfo->issueBefore != NULL)
			{
				/* check crl date bounds */
				if (strcmp(crl->thisUpdate, matchInfo->issueBefore[0] ) > 0)
				{
					remove = TRUE;
					goto check_rem;
				}
			}
			
			/* check special "only return the most recent" flag */
			if(matchInfo->onlyOne != FALSE)
			{
				/* see if the caller has provided as most recent date
				 * already, if not we need to record the date of
				 * this CRL.
				 */
				if(mostRecent[0] == 0)
					strcpy(mostRecent, crl->thisUpdate); /* copy an keep this crl */
				else
				{
					/* depending on what matchInfo date fields are set,
					 * we need to make a comparison and see if this
					 * CRL is wanted "more" than a previously matched one.
					 */
 /* after	before  (with "onlyOne" set to TRUE)
 * -----	------
 *  y		  0		=> CRL issued after y date, closest to y date
 *  y		  x     => most recent CRL issued after y, but no later than x date
 *  0		  x		=> most recent CRL issued before x date
 *  0		  0		=> most recent CRL for the particular issuer
 */
					if(matchInfo->issueAfter && (matchInfo->issueBefore == 0))
					{
						/* see if this date is closer than any previous found */
						if(strcmp(mostRecent, crl->thisUpdate) > 0)/* if last recorded is newer than this CRL */
							strcpy(mostRecent, crl->thisUpdate); /* this CRL is closer */
						else
						{
							remove = TRUE;	/* previously filtered one is closer */
							goto check_rem;
						}
					}
					else /* for other cases we want most recent (bounding done above if requested) */
					{
						if(strcmp(mostRecent, crl->thisUpdate) < 0) /* was prev older than this CRL */
							strcpy(mostRecent, crl->thisUpdate); /* this CRL is closer */
						else
						{
							remove = TRUE;	/* previously filtered one is closer */
							goto check_rem;
						}
					}
					
					/* this one is closer - need to remove the previously keep
					 * one if it is part of the remote list. Since there can
					 * be only one, we know it has to be the previous link if so.
					 */
					if(filtList != prevList) /* not the top */
					{
						*remoteListPtr = filtList; /* new top of list */
						free(prevList->encObj.data);
						free(prevList);
						prevList = NULL;	/* so we know in the check_rem code */
					}
					/* else it's in the local list, it will be removed later */
					
				}
				
			} /* end of if "onlyOne" TRUE */
			
		} /* end of if (there is matchInfo to check against */
	
check_rem:
		if(remove == TRUE) /* if filtered out by match criteria */
		{
			free(filtList->encObj.data);
			if(filtList == *remoteListPtr)	/* is it the top */
				*remoteListPtr = prevList = filtList->next;
			else
				prevList->next = filtList->next;
			
			free(filtList);
			filtList = prevList;
		}	
		CM_FreeCRL(&crl);
		
		if(prevList == NULL)
		{
			prevList = filtList; /* starting at top again */
		}
		else
		{
			prevList = filtList; /* this link will be the prev */
			if(filtList)
				filtList = filtList->next;	/* move onto checking next link */
		}
		
	} /* end of while entries in the list */
	
	/* one last check.
	 * In the case where the caller has provided matchInfo "OnlyOne", 
	 * AND 
	 * there is a local list entry
	 * AND
	 * our filtering selected the remote entry as the TRUE "OnlyOne"
	 *
	 * then we need to remove the entry in the original list so it
	 * will be replaced with the entry in the second list, since our
	 * filtering revealed it as more "wanted"...
	 *
	 */
	if((matchInfo != NULL) &&
		(matchInfo->onlyOne == TRUE) &&
		(localList->encObj.data != NULL) &&
		(*remoteListPtr != NULL))
	{
		/* only can return 1, and the entry in remote overrides the
		 * entry in local.
		 */
		free(localList->encObj.data);
		localList->encObj.data = NULL;
		
		/* caller appends results left in remote list, so 
		 * we leave the single entry in there.
		 */
	}
	/* else it will be handled via the normal code on the caller's
	 * end.
	 */
	
	/* all done here */
	return(err);
	
}


/*
 * Function to filter the cert list based on the type that is requested
 */
static short SRLi_FilterObjectOnType(EncObject_LL *checkList, EncObject_LL **fileterdList, long typeMask)
{
	
	EncObject_LL *bldList = NULL, *tmpList = NULL, *topLst = NULL;
	if (checkList == NULL)
		return (SRL_SUCCESS);

	bldList = (EncObject_LL *)calloc(1, sizeof(EncObject_LL ));
	if (bldList == NULL)
		return SRL_MEMORY_ERROR;
	topLst = bldList;

	tmpList = checkList;

	while(tmpList != NULL)
	{
 
	 	if((tmpList->typeMask & typeMask) != 0)
	 	{
			if (bldList->encObj.data != NULL)
			{
				bldList->next = (EncObject_LL *)calloc(1, sizeof(EncObject_LL ));
				if (bldList->next == NULL)
					return SRL_MEMORY_ERROR;
				bldList = bldList->next;
				bldList->next = NULL;
			}
				bldList->encObj.num = tmpList->encObj.num;
				bldList->encObj.data = tmpList->encObj.data;
				bldList->locMask = tmpList->locMask;
				bldList->typeMask = tmpList->typeMask;

		}
		else
		{
			free (tmpList->encObj.data);
			tmpList->encObj.data = NULL;
		}
		tmpList = tmpList->next;
	}
	*fileterdList = topLst;
	return SRL_SUCCESS;
}
