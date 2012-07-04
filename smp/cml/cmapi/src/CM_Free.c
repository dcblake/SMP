/*****************************************************************************
File:     CM_Free.c
Project:  Certificate Management Library
Contents: The high-level (CM_FreeBytes, CM_FreeValidKey, etc.,) and internal
		  (low-level) functions used to free memory that was allocated by 
		  the library.

Created:  25 June 1999
Author:   C. C. McPherson <Clyde.McPherson@GetronicsGov.com> 

Last Updated:  27 Jan 2005

Version:  2.5

*****************************************************************************/

// Set Windows export declaration so data and functions are exported
#ifdef WIN32
#ifndef CM_API
#define CM_API	__declspec(dllexport)
#endif
#endif

/* -------------- */
/* Included Files */
/* -------------- */
#include "cmapi.h"


/* ------------------- */
/* Function Prototypes */
/* ------------------- */
static void freeBytes(Bytes_struct *);
static void freeBytesContents(Bytes_struct);
static void freeExtKeyUsageSet(Ext_key_use_LL *keyUseSet);
static void freePolicyMaps(Pol_maps_struct *maps);


/******************************************************************************
 * FUNCTION:  CMU_FreeRevocationData()
 * 
 * Description: Free the list of CRLs or OCSP responses found in the Validated
 *              Key structure.
 * 
 * Inputs: 
 *    EncRevObject_LL* revDataList  - list of CRLs or OCSP responses used
 *                                    during revocation status checking
 *  
 * Return Value: 
 *    void - no return value
 *****************************************************************************/
void CMU_FreeRevocationData(EncRevObject_LL* revDataList)
{
   EncRevObject_LL* pObj = revDataList;
   EncRevObject_LL* pNext = NULL;

   while (pObj != NULL)
   {
      pNext = pObj->m_pNext;
      CMASN_FreeBytesContents(&pObj->m_encObj);
      free(pObj);
      pObj = pNext;
   }      
} /* end of CMU_FreeRevocationData() */


/* ------------ */
/* CM_FreeBytes */
/* ------------ */
void CM_FreeBytes(Bytes_struct **data)
{
   if (data == NULL)
      return;

   freeBytes(*data);
   *data = NULL;
}


/* ------------------ */
/* CM_FreeEncCertList */
/* ------------------ */
void CM_FreeEncCertList(EncCert_LL **listhead)
{
   EncCert_LL *atList, *nList;

   if ((listhead == NULL) || (*listhead == NULL))
      return;

   atList = *listhead;
   nList = atList->next;

   while (atList != NULL)
   {
      /* get rid of encoded cert buffer if any */
      if (atList->encCert.data != NULL)
         free(atList->encCert.data);

      nList = atList->next;
      free(atList);   /* get rid of this link */
      atList = nList;   /* move onto next link */
   }

   *listhead = 0;   /* so caller doesn't use any further */
   return;
}


/* -------------- */
/* CM_FreeEncCRLs */
/* -------------- */
void CM_FreeEncCRLs(EncCRL_LL **listhead)
{
   EncCRL_LL *atList, *nList;

   if ((listhead == NULL) || (*listhead == NULL))
      return;

   atList = *listhead;
   nList = atList->next;

   while (atList != NULL)
   {
      /* get rid of encoded crl buffer if any */
      if (atList->encCRL.data != NULL)
         free(atList->encCRL.data);

      nList = atList->next;
      free(atList);   /* get rid of this link */
      atList = nList;   /* move onto next link */
   }

   *listhead = 0;   /* so caller doesn't use any further */
   return;
}


/* -------------- */
/* CM_FreeErrInfo */
/* -------------- */
void CM_FreeErrInfo(ErrorInfo_List **errInfo)
{
   ErrorInfo_List *theList, *nextList;

   if (errInfo == 0)
      return;

   theList = *errInfo;
   *errInfo = 0;   /* so caller knows it's gone */
   while (theList != 0)
   {
      nextList = theList->next;   /* record for loop */
      if (theList->dn != 0)
         free(theList->dn);

      if (theList->xinfo != 0)
         free(theList->xinfo);

      free(theList);
      theList = nextList;
   }
}


/* --------------- */
/* CM_FreeValidKey */
/* --------------- */
void CM_FreeValidKey(ValidKey_struct **key)
{
   if ((key == NULL) || (*key == NULL))
      return;

   CMASN_FreePubKeyContents(&(*key)->key);
   if ((*key)->keyUse != NULL)
   {
      free((*key)->keyUse);
      (*key)->keyUse = NULL;
   }
   CMASN_FreePolicySet((*key)->caPolicies);
   (*key)->caPolicies = NULL;
   CMASN_FreePolicySet((*key)->userPolicies);
   (*key)->userPolicies = NULL;
   freePolicyMaps((*key)->mappings);
   (*key)->mappings = NULL;
   freeExtKeyUsageSet((*key)->extKeyUsage);
   (*key)->extKeyUsage = NULL;
   CMU_FreeRevocationData((*key)->m_pRevocationData);
   (*key)->m_pRevocationData = NULL;
   CM_FreeErrInfo(&(*key)->errors);
   free(*key);
   *key = NULL;
   return;
}

#ifdef _v2_0_CODE
/* ----------------- */
/* CMU Free Routines */
/* ----------------- */
void CMU_FreeBytesContents(Bytes_struct *pBytes)
{
   if (pBytes == NULL)
      return;

   if (pBytes->data != NULL)
   {
      free(pBytes->data);
      pBytes->data = NULL;
   }
   pBytes->num = 0;

   return;
}


void CMU_FreeRDN_LL(RDN_LL **rdn)
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
#endif // _v2_0_CODE


/* ---------------------- */
/* Internal Free Routines */
/* ---------------------- */
static void freeBytes(Bytes_struct *bytes)
{
   if (bytes == NULL)
      return;
   freeBytesContents(*bytes);
   free(bytes);
   return;
} /* end of freeBytes() */


static void freeBytesContents(Bytes_struct bytes)
{
   if (bytes.data != NULL)
   {
      free(bytes.data);
      bytes.data = NULL;
   }
   bytes.num = 0;
   return;
} /* end of freeBytesContents() */


static void freeExtKeyUsageSet(Ext_key_use_LL *keyUseSet)
{
   Ext_key_use_LL *temp;

   while (keyUseSet != NULL)
   {
      free(keyUseSet->oid);
      keyUseSet->oid = NULL;
      temp = keyUseSet->next;
      keyUseSet->next = NULL;
      free(keyUseSet);
      keyUseSet = temp;
   }

   return;
} /* end of freeExtKeyUsageSet() */


static void freePolicyMaps(Pol_maps_struct *maps)
{
   Pol_maps_struct *tempPolMap;

   while (maps != NULL)
   {
      free(maps->issuer_pol_id);
      maps->issuer_pol_id = NULL;
      free(maps->subj_pol_id);
      maps->subj_pol_id = NULL;
      tempPolMap = maps->next;
      maps->next = NULL;
      free(maps);
      maps = tempPolMap;
   }
   return;
} /* end of freePolicyMaps() */



/* end of CM_Free.c */
