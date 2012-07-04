/*****************************************************************************
File:     CRL_Free.cpp
Project:  CRL Management Library
Contents: Contains routines need to free space created by the CRL Service DLL. 

Created:  January 2004
Author:   Tom Horvath <Tom.Horvath@DigitalNet.com>

Last Updated:  27 Jan 2005

Version:  2.5

Description: This file contains the following CRL API functions:
	CRL_FreeRevokeStatus

*****************************************************************************/

////////////////////
// Included Files //
////////////////////
#include "CRL_SRVinternal.h"

/////////////////////////
// Function Prototypes //
/////////////////////////
static void freeUnknExtn(Unkn_extn_LL* pExts);
static void freeCRLEntryExtensions(CRL_entry_exts_struct* exts);
static void freeAny(Any_struct* any);
static void freeBytes(Bytes_struct* bytes);
static void freeBytesContents(Bytes_struct bytes);
static void freeGenNameContent(Gen_name_struct* genName);
static void freeGenNames(Gen_names_struct* genNameList);

/************************************************************************
 FUNCTION:  CRL_FreeRevokeStatus()
 
 Description: To Free the RevStatus_LL structure.
*************************************************************************/
void CRL_FreeRevokeStatus(void* handle, RevStatus_LL* pResults,
                          EncRevObject_LL** pRevocationData)
{
	while (pResults != NULL)
	{
		//Free the RevInfo memory
		if (pResults->pRevInfo)
		{
			if (pResults->pRevInfo->nextUpdate)
				free(pResults->pRevInfo->nextUpdate);
			if (pResults->pRevInfo->pRespExts)
				freeUnknExtn(pResults->pRevInfo->pRespExts);			
			if (pResults->pRevInfo->revDate)
				free(pResults->pRevInfo->revDate);
			if (pResults->pRevInfo->revReason)
				free(pResults->pRevInfo->revReason);

			free(pResults->pRevInfo);
			pResults->pRevInfo = NULL;
		}
		pResults = pResults->next;
	}

   if (pRevocationData != NULL)
   {
      EncRevObject_LL* pRevData = *pRevocationData;
      EncRevObject_LL* pNext = NULL;
      while (pRevData != NULL)
      {
         pNext = pRevData->m_pNext;
         //Free the encoded OCSP response
         if (pRevData->m_encObj.data)
            free(pRevData->m_encObj.data);
         free(pRevData);
         pRevData = pNext;
      }
      *pRevocationData = NULL;
   }

}

void CRLSRV::FreeRevCerts_LL(RevCerts_LL* pRevEntries)
{
	while (pRevEntries != NULL)
	{
		RevCerts_LL* pNext = pRevEntries->next;
		
		if (pRevEntries->serialNum.data != NULL)
			free(pRevEntries->serialNum.data);
		if (pRevEntries->revDate != NULL)
			free(pRevEntries->revDate);
		freeCRLEntryExtensions(pRevEntries->exts);
		free(pRevEntries);
		
		pRevEntries = pNext;
	}
}

void freeCRLEntryExtensions(CRL_entry_exts_struct* exts)
{
	if (exts == NULL)
		return;
	
	if (exts->reasonCode != NULL)
	{
		free(exts->reasonCode->oid);
		exts->reasonCode->oid = NULL;
		free(exts->reasonCode->value);
		exts->reasonCode->value = NULL;
		free(exts->reasonCode);
		exts->reasonCode = NULL;
	}
	if (exts->instrCodeOid != NULL)
	{
		free(exts->instrCodeOid->oid);
		exts->instrCodeOid->oid = NULL;
		if (exts->instrCodeOid->value != NULL)
		{
			if (*(CM_OID*)exts->instrCodeOid->value != NULL)
			{
				free(*(CM_OID*)exts->instrCodeOid->value);
				*(CM_OID*)exts->instrCodeOid->value = NULL;
			}
			free(exts->instrCodeOid->value);
			exts->instrCodeOid->value = NULL;
		}
		free(exts->instrCodeOid);
		exts->instrCodeOid = NULL;
	}
	if (exts->invalDate != NULL)
	{
		free(exts->invalDate->oid);
		exts->invalDate->oid = NULL;
		free(exts->invalDate->value);
		exts->invalDate->value = NULL;
		free(exts->invalDate);
		exts->invalDate = NULL;
	}
	if (exts->certIssuer != NULL)
	{
		free(exts->certIssuer->oid);
		exts->certIssuer->oid = NULL;
		freeGenNames((Gen_names_struct*)(exts->certIssuer->value));
		exts->certIssuer->value = NULL;
		free(exts->certIssuer);
		exts->certIssuer = NULL;
	}
	if (exts->unknown != NULL)
		freeUnknExtn(exts->unknown);
	
	free(exts);
	
} // end of freeCRLEntryExtensions()

void freeUnknExtn(Unkn_extn_LL* pExts)
{
	Unkn_extn_LL *temp, *unkn = pExts;
				
	while (unkn != NULL)
	{
		free(unkn->oid);
		unkn->oid = NULL;
		free(unkn->value->data);
		unkn->value->num = 0;
		free(unkn->value);
		unkn->value = NULL;
		temp = unkn->next;
		unkn->next = NULL;
		free(unkn);
		unkn = temp;
	}
}

void freeBytesContents(Bytes_struct bytes)
{
    if (bytes.data != NULL)
    {
        free(bytes.data);
        bytes.data = NULL;
    }
	bytes.num = 0;
    return;
} /* end of freeBytesContents() */

void freeBytes(Bytes_struct *bytes)
{
	if (bytes == NULL)
		return;
	freeBytesContents(*bytes);
	free(bytes);
}

void freeAny(Any_struct *any)
{
    if (any == NULL)
        return;
    free(any->oid);
    freeBytes(any->data);
    any->data = NULL;
    free(any);

} /* end of freeAny() */

void freeGenNameContent(Gen_name_struct *genName)
{
	if ((genName == NULL) || (genName->name.dn == NULL))
		return;
	
	switch (genName->flag)
	{
	case CM_OTHER_NAME:
		freeAny(genName->name.other_name);
		break;
	case CM_RFC822_NAME:
		free(genName->name.rfc822);
		break;
	case CM_DNS_NAME:
		free(genName->name.dns);
		break;
	case CM_X400_ADDR:
		free(genName->name.x400);
		break;
	case CM_X500_NAME:
		free(genName->name.dn);
		break;
	case CM_EDI_NAME:
		free(genName->name.ediParty->name_assigner);
		genName->name.ediParty->name_assigner = NULL;
		free(genName->name.ediParty->party_name);
		genName->name.ediParty->party_name = NULL;
		free(genName->name.ediParty);
		break;
	case CM_URL_NAME:
		free(genName->name.url);
		break;
	case CM_IP_ADDR:
		free(genName->name.ip);
		break;
	case CM_REG_OID:
		free(genName->name.oid);
	}

	genName->name.dn = NULL;

} // end of freeGenNameContent()

void freeGenNames(Gen_names_struct* genNameList)
{
	while (genNameList != NULL)
	{
		Gen_names_struct* next = genNameList->next;

		freeGenNameContent(&(genNameList)->gen_name);
		free(genNameList);

		genNameList = next;
	}
} // end of freeGenNames()