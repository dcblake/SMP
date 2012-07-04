///////////////////////////////////////////////////////////////////////////////
// File:		      OCSP_free.cpp
// Project:		   Certificate Management Library
// Contents:	   Contains routines needed to free space created by the OCSP
//                revocation status callback library.
// Requirements:  CML Requirements 2.1-5.
// 
// Created:		   13 December 2004
// Author:		   Tom Horvath <Tom.Horvath@BAESystems.com>
// 
// Last Updated:  13 December 2004
// 
// Version:		   2.5
//
// Description: This file contains the following OCSP API functions:
//	   OCSP_FreeRevokeStatus
///////////////////////////////////////////////////////////////////////////////

////////////////////
// Included Files //
////////////////////
#include <ocsp_internal.h> // needed for CML OCSP internal types

/////////////////////////
// Function Prototypes //
/////////////////////////
static void FreeUnknExtn(Unkn_extn_LL* pExts);

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSP_FreeRevokeStatus()
// Description:   To free the RevStatus_LL and EncRevObject_LL linked lists.
// Inputs:        handle, pResults
// Outputs:       (none)
// Return value:  (none)
///////////////////////////////////////////////////////////////////////////////
void OCSP_FreeRevokeStatus(void* handle, RevStatus_LL* pResults,
                           EncRevObject_LL** pRevocationData)
{
	while (pResults != NULL)
	{
		//Free the RevInfo memory
		if (pResults->pRevInfo != NULL)
		{
			if (pResults->pRevInfo->nextUpdate != NULL)
				free(pResults->pRevInfo->nextUpdate);
			if (pResults->pRevInfo->pRespExts != NULL)
				FreeUnknExtn(pResults->pRevInfo->pRespExts);			
			if (pResults->pRevInfo->revDate != NULL)
				free(pResults->pRevInfo->revDate);
			if (pResults->pRevInfo->revReason != NULL)
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
         if (pRevData->m_encObj.data != NULL)
            free(pRevData->m_encObj.data);
         free(pRevData);
         pRevData = pNext;
      }
      *pRevocationData = NULL;
   }

} // END OF OCSP_FreeRevokeStatus()

///////////////////////////////////////////////////////////////////////////////
// Function:      FreeUnknExtn()
// Description:   To free the unknown extensions structure of the RevInfo.
// Inputs:        pExts
// Outputs:       (none)
// Return value:  (none)
///////////////////////////////////////////////////////////////////////////////
void FreeUnknExtn(Unkn_extn_LL* pExts)
{
	Unkn_extn_LL* pTemp = NULL;
   Unkn_extn_LL* pUnkn = pExts;
				
	while (pUnkn != NULL)
	{
		free(pUnkn->oid);
		pUnkn->oid = NULL;
		free(pUnkn->value->data);
		pUnkn->value->num = 0;
		free(pUnkn->value);
		pUnkn->value = NULL;
		pTemp = pUnkn->next;
		pUnkn->next = NULL;
		free(pUnkn);
		pUnkn = pTemp;
	}
} // END OF FreeUnknExtn()

