/*****************************************************************************
File:		SRL_Free.c
Project:	Storage & Retrieval library
Contents:	Free functions for the Storage & Retrieval library

Created:	14 November 2000
Author:		Robin Moeller <Robin.Moeller@DigitalNet.com>

Last Updated:	21 January 2004

Version:	2.4

*****************************************************************************/

#ifdef HPUX32
#include <dl.h>
#define FreeLibrary shl_unload
#elif !defined(WIN32)
#include <dlfcn.h>
#define FreeLibrary dlclose
#endif
#include "SRL_internal.h"

/*
void CMU_FreeBrokenCertPathList(ulong cm_session, CM_CertPath_struct **cp)

This function deallocates memory used for the certification path linked 
list structures.  The function only frees the memory used by the link 
structures themselves and the decoded certs (if they exist).  The 
data in the enc Cert ptr field is left alone.  (The encoded cert ptr 
just points into a large block of asn.1 and was not allocated by the
library.)

Paramters
    cm_session (input)
      The cm session reference.

    cp (input/output)
      Address for the storage of the cert path linked list pointer.  
      It will be set to NULL so no future calls will try to use it.

Return Value
    Nothing.
*/
void SRLi_FreeBrokenCertList(ulong cm_session, SRL_CertList **cp)
{
   SRL_CertList *stepCp, *tmp;
   cm_session = cm_session;

   if(cp == NULL)
      return;

   stepCp = *cp;

   while(stepCp != NULL)
   {
      tmp = stepCp->next;

      if(stepCp->cert != NULL)   /* only free if one exists */
         CM_FreeCert(&stepCp->cert);
      stepCp->asn1cert = NULL;
      free(stepCp);   /* free the struct itself */

      stepCp = tmp;   /* move onto next one */
   }

   *cp = NULL;   /* make sure caller doesn't try to use it anymore */
   return;
}

SRL_API(void) SRL_FreeBytes(Bytes_struct **data)
{

	if ((data == NULL) || (*data == NULL))
		return;
	SRLi_FreeBytes(*data);
	*data = 0;
	return;
}

void SRL_FreeBytesContents(Bytes_struct bytes)
{
    if (bytes.data != NULL)
    {
        free(bytes.data);
        bytes.data = NULL;
    }
    return;
}

void SRLi_FreeBytes(Bytes_struct *bytes)
{
    if (bytes == NULL)
        return;
    SRL_FreeBytesContents(*bytes);
    free(bytes);
    return;
}
void SRLi_FreeRDN_LL(RDN_LL **rdn)
{
    RDN_LL *tempLink;

    while (*rdn != NULL)
    {
        free((*rdn)->rdn);
        (*rdn)->rdn = NULL;
        tempLink = (*rdn)->next;
        (*rdn)->next = NULL;
        free(*rdn);
        *rdn = tempLink;
    }
    return;
}
void SRLi_FreeCRLEntryInfo_LL(dbCRLEntryInfo_LL *listhead)
/*  This routine is called upon to free up the memory used by a linked list
 of ans.1 encoded certificates.  The memory for the list structures and the
 memory for the encoded asn.1 blocks are free'd up. The callers storage ptr
 is also set to NULL for them so they don't try using it for any further
 calls once it is gone.

 parameters:
       listhead (input) = ptr to storage of linked list start ptr

 returns:
    nothing
*/
{
   dbCRLEntryInfo_LL   *atList, *nList;

   if (listhead == NULL)
       return;

   atList = listhead;
   nList = atList->next;

   while(atList != NULL)
   {
      /* get rid of encoded cert buffer if any */
	   if (atList->db_kid != NULL)
	   {
			if(atList->db_kid->data != NULL)
				free(atList->db_kid->data);
			free(atList->db_kid);
	   }

	   if(atList->signature != 0)
		   free(atList->signature);
	  
      nList = atList->next;
      free(atList);   /* get rid of this link */
      atList = nList;   /* move onto next link */
   }

   return;
}

void Ret_FreeQualifiers(Qualifier_struct** qual)
{
	Qualifier_struct* nextQ;

	if (qual == NULL)
		return;

	while (*qual != NULL)
	{
		/* Free the qualifier contents */
		switch ((*qual)->flag)
		{
		case CM_QUAL_CPS:
			if ((*qual)->qual.cpsURI != NULL)
			{
				free((*qual)->qual.cpsURI);
				(*qual)->qual.cpsURI = NULL;
			}
			break;

		case CM_QUAL_UNOTICE:
			if ((*qual)->qual.userNotice != NULL)
			{
				if ((*qual)->qual.userNotice->noticeRef != NULL)
				{
					if ((*qual)->qual.userNotice->noticeRef->org != NULL)
					{
						free((*qual)->qual.userNotice->noticeRef->org);
						(*qual)->qual.userNotice->noticeRef->org = NULL;
					}
					if ((*qual)->qual.userNotice->noticeRef->notices != NULL)
					{
						free((*qual)->qual.userNotice->noticeRef->notices);
						(*qual)->qual.userNotice->noticeRef->notices = NULL;
					}
					(*qual)->qual.userNotice->noticeRef = NULL;
				}
				
				if ((*qual)->qual.userNotice->explicitText != NULL)
				{
					free((*qual)->qual.userNotice->explicitText);
					(*qual)->qual.userNotice->explicitText = NULL;
				}
				(*qual)->qual.userNotice = NULL;
			}
			break;

		case CM_QUAL_UNKNOWN:
			if ((*qual)->qual.unknown != NULL)
			{
				SRLi_FreeBytes((*qual)->qual.unknown);
				(*qual)->qual.unknown = NULL;
			}
			break;

		default:
			(*qual)->qual.unknown = NULL;
		}

		/* Free the qualifier OID */
		if ((*qual)->qualifier_id != NULL)
		{
			free((*qual)->qualifier_id);
			(*qual)->qualifier_id = NULL;
		}

		/* Free the qualifier and move to the next one in the list */
		nextQ = (*qual)->next;
		(*qual)->next = NULL;
		free(*qual);
		*qual = nextQ;
	}
} /* end of CMU_FreeQualifiers() */


void SRL_FreePolicySet(Policy_struct *set)
{
    Policy_struct *tempSet;

    while (set != NULL)
    {
        free(set->policy_id);
        set->policy_id = NULL;

		Ret_FreeQualifiers(&set->qualifiers);

        tempSet = set->next;
        set->next = NULL;
        free(set);
        set = tempSet;
    }
    return;
}


void SRLi_FreedbCertEntryLL(dbCertEntryInfo_LL *certInfoTop)
{
   dbCertEntryInfo_LL   *certInfoNext;

   while(certInfoTop != 0)
   {
      certInfoNext = certInfoTop->next;
      if(certInfoTop->algOID != 0)
         free(certInfoTop->algOID);
      if(certInfoTop->validFrom != 0)
         free(certInfoTop->validFrom);
      if(certInfoTop->validTill != 0)
         free(certInfoTop->validTill);

      if(certInfoTop->issuer_DN != 0)
         free(certInfoTop->issuer_DN);
      if (certInfoTop->emailAddr != 0)
         free(certInfoTop->emailAddr);
      if(certInfoTop->serialNum != 0)
      {
         if(certInfoTop->serialNum->data != 0)
            free(certInfoTop->serialNum->data);
         free(certInfoTop->serialNum);
      }
      if(certInfoTop->sub_kmid != 0)
      {
         if(certInfoTop->sub_kmid->data != 0)
            free(certInfoTop->sub_kmid->data);
         free(certInfoTop->sub_kmid);
      }
      if(certInfoTop->poly != 0)
         SRL_FreePolicySet(certInfoTop->poly);
         
      if(certInfoTop->db_kid != 0)
      {
         if(certInfoTop->db_kid->data != 0)
            free(certInfoTop->db_kid->data);
         free(certInfoTop->db_kid);
      }


      free(certInfoTop);
      certInfoTop = certInfoNext;/* move onto next link if any */
   }
}

	
/* -------------- */
/* SRL_Free_dbList */
/* -------------- */
SRL_API(void) SRL_FreeDBListing(dbEntryList_struct **dbList)
{
	dbEntryList_struct   *listTop;
	dbEntryInfo_LL      *theList, *nextList;
	dbCRLEntryInfo_LL   *crlInfoTop, *crlInfoNext;
	short   typeflag;


	if(dbList == 0) return;
	
	listTop = *dbList;
	if(listTop == 0)
		return;
	
	typeflag = (short) listTop->typeflag;   /* SRL_DB_CERT or SRL_DB_CRL */
	
	theList = listTop->entryList;   /* get start of list */
	free(listTop);   /* don't need the struct anymore */
	*dbList = 0;   /* make sure caller doesn't use it anymore */
	
	while(theList != 0)   /* travel the linked list */
	{
		nextList = theList->next;
		if(theList->entry_DN != 0)
			free(theList->entry_DN);
		
			/* depending on type, work on it's linkage */
			if(typeflag == SRL_DB_CERT)
			{
				SRLi_FreedbCertEntryLL(theList->info.certs);
				
			}
			else /* CRL_TYPE */
			{
				crlInfoTop = theList->info.crls;
				while(crlInfoTop != 0)
				{
					crlInfoNext = crlInfoTop->next;
					if(crlInfoTop->signature != 0)
						free(crlInfoTop->signature);
					if(crlInfoTop->db_kid != 0)
					{
						if(crlInfoTop->db_kid->data != 0)
							free(crlInfoTop->db_kid->data);
						free(crlInfoTop->db_kid);
					}
					
					free(crlInfoTop);
					crlInfoTop = crlInfoNext;/* move onto next link if any */
					
				}
			}
			
		
		free(theList);   /* free up this link's struct */
		theList = nextList;   /* move onto the next */
	}
	
    return;
}

// Just free the Object List not the contents
void SRLi_FreeObjlst(EncObject_LL *objList)
{
	EncObject_LL *tmpList, *pList;

	if (objList == NULL)
		return;
	tmpList = objList;
	while (tmpList != NULL)
	{
		pList = tmpList->next;
		free (tmpList);
		tmpList = pList;
	}
	return;
}

// Free the Object List and the contents
void SRLi_FreeObjList(EncObject_LL **objList)
{
	EncObject_LL	*atList, *nList;

   if (objList == NULL)
       return;
   if (*objList == NULL)
       return;

   atList = *objList;
   nList = atList->next;

   while(atList != NULL)
   {
      /* get rid of encoded cert buffer if any */
      if(atList->encObj.data != NULL)
         free(atList->encObj.data);

      nList = atList->next;
	  free (atList);
      atList = nList;   /* move onto next link */
   }

   *objList = 0;   /* so caller doesn't use any further */
   return;
}

void SRL_FreeEncCRLs(EncCRL_LL **listhead)
{
	EncCRL_LL   *atList, *nList;
	
	if (listhead == NULL)
		return;
	if (*listhead == NULL)
		return;
	
	atList = *listhead;
	nList = atList->next;
	
	while(atList != NULL)
	{
		/* get rid of encoded crl buffer if any */
		if(atList->encCRL.data != NULL)
			free(atList->encCRL.data);
		
		nList = atList->next;
		free(atList);   /* get rid of this link */
		atList = nList;   /* move onto next link */
	}
	
	*listhead = 0;   /* so caller doesn't use any further */
	return;
}

SRL_API(void) SRL_FreeEncCertList(EncCert_LL **pCertList)
/*  This routine is called upon to free up the memory used by a linked list
 of ans.1 encoded certificates.  The memory for the list structures and the
 memory for the encoded asn.1 blocks are free'd up. The callers storage ptr
 is also set to NULL for them so they don't try using it for any further
 calls once it is gone.

 parameters:
       pCertList (input) = ptr to storage of linked list start ptr

 returns:
    nothing
*/
{
	EncCert_LL   *atList, *nList;
	
	if (pCertList == NULL)
		return;
	if (*pCertList == NULL)
		return;
	
	atList = *pCertList;
	nList = atList->next;
	
	while(atList != NULL)
	{
		/* get rid of encoded cert buffer if any */
		if(atList->encCert.data != NULL)
			free(atList->encCert.data);
		
		nList = atList->next;
		free(atList);   /* get rid of this link */
		atList = nList;   /* move onto next link */
	}
	
	*pCertList = 0;   /* so caller doesn't use any further */
	return;
}

void SRLi_FreeLDAPinfo(LDAPInfo_struct **LDAPinfo)
{
	LDAPInfo_struct *pLDAPinfo;

	if ((LDAPinfo == NULL) || (*LDAPinfo == NULL))
		return;

	pLDAPinfo = *LDAPinfo;
	if (pLDAPinfo->LDAPFunctions)
		free (pLDAPinfo->LDAPFunctions);

	if (pLDAPinfo->ldapIDinfo)
	{
		if(pLDAPinfo->ldapIDinfo->internal)
			free (pLDAPinfo->ldapIDinfo);
	}

	if (pLDAPinfo->LDAPServerInfo)
	{
		free (pLDAPinfo->LDAPServerInfo->LDAPserver);
		free (pLDAPinfo->LDAPServerInfo);
	}
		
	if(pLDAPinfo->ldaplibHandle)
	{

		FreeLibrary(pLDAPinfo->ldaplibHandle);
	}

	if (pLDAPinfo->SharedLibraryName)
		free (pLDAPinfo->SharedLibraryName);

	free (pLDAPinfo);
	*LDAPinfo = NULL;
	return;
}

void SRLi_FreeInitSettings (SRL_InitSettings_struct *settings)
{
	if (settings == NULL)
		return;
	if (settings->CertFileName != NULL)
		free (settings->CertFileName);
	if (settings->CRLFileName != NULL)
		free (settings->CRLFileName);
	if (settings->LDAPinfo != NULL)
	{
		/* Free the contents of the LDAP information structure */

		/* LDAP functions are used in the session struct, don't free them here */
		if (settings->LDAPinfo->SharedLibraryName != NULL)
			free (settings->LDAPinfo->SharedLibraryName);
		if (settings->LDAPinfo->LDAPServerInfo != NULL)
		{
			if (settings->LDAPinfo->LDAPServerInfo->LDAPserver != NULL)
				free (settings->LDAPinfo->LDAPServerInfo->LDAPserver);
			free (settings->LDAPinfo->LDAPServerInfo);
		}
	}
	return;
}

void SRLi_FreeDB_Item (DB_Item **DBItem)
{
	DB_Item *pDBItem;
	pDBItem = *DBItem;
	if (pDBItem == NULL)
		return;
	if (pDBItem->item_ptr)
		free (pDBItem->item_ptr);
	free (pDBItem);
	*DBItem = NULL;
	return;
}

void SRLi_FreeURLDescriptor(SRL_URLDescriptor_struct **URLDesc)
{
	SRL_URLDescriptor_struct *ptr;
	if (*URLDesc)
	{
		ptr = *URLDesc;
		if (ptr->hostname)
			free(ptr->hostname);
		if (ptr->attributes)
			free(ptr->attributes);
		if (ptr->URL_DN)
			free(ptr->URL_DN);
		if (ptr->filter)
			free(ptr->filter);
		free(ptr);
	}

	*URLDesc = NULL;
	return;
}


void SRLi_FreeSession(SRLSession_struct *psession)
{
	if (psession == NULL)
	   return;
	if (psession->CertFileName != NULL)
		free (psession->CertFileName);
	if (psession->CRLFileName != NULL)
		free (psession->CRLFileName);
	if (psession->path != NULL)
		free (psession->path);

	/* Free the LDAP pointer */
	if (psession->ldapInfo != NULL)
	{
		if ((psession->ldapInfo->ldapIDinfo != NULL) &&
		     (psession->ldapInfo->ldapIDinfo->internal == TRUE))
		{
			if (psession->ldapInfo->ldapIDinfo->ldapID != NULL)
			{
			   if (psession->ldapInfo->LDAPFunctions->unbind)
			      psession->ldapInfo->LDAPFunctions->unbind(psession->ldapInfo->ldapIDinfo->ldapID);
			}
		}
		 SRLi_FreeLDAPinfo (&psession->ldapInfo);
	}
	free (psession);
}
		
