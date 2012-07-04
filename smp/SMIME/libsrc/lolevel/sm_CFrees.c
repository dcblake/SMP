
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "sm_apic.h"

/*
 *
 * This file contains functions to free the C structures from
 * sm_apic.h.
 *
 */


void free_SM_Str(SM_Str *Ss)
{

   if (Ss == NULL)
      return;
   free_SM_Str_content(Ss);
   free(Ss);
   return;
}

void free_SM_Str_content(SM_Str *Ss)
{

   if (Ss->pchData != NULL)
   {
      free( Ss->pchData );
      Ss->pchData = NULL;
   }
   Ss->lLength = (unsigned int)-1;
   return;
}

/* frees the SM_Buffer structure */
void free_SM_Buf_content(SM_Buffer *buf)
{
   if (buf != NULL)
   {
      free_SM_Str_content(&buf->data);
      memset(buf, 0, sizeof(SM_Buffer));
   }
   return;
}

void free_SM_Buf(SM_Buffer *buf)
{
   if (buf != NULL)
   {
      free_SM_Buf_content(buf);
      free(buf);
   }
   return;
}

/* frees the SM_Content structure */
void free_SM_Cont_content(SM_Content *con)
{
   if (con != NULL)
   {
      if (con->poidType != NULL)
      {
         free(con->poidType);
         con->poidType = NULL;
      }
      free_SM_Buf_content(&con->bufContent);
      memset(con, 0, sizeof(SM_Content));
   }
   return;
}

void free_SM_Cont(SM_Content *con)
{
   if (con != NULL)
   {
      free_SM_Cont_content(con);
      free(con);
   }
   return;
}

/* frees the SM_BufferLst structure */
void free_SM_BufferLst(SM_BufferLst *buflst)
{
   SM_BufferLst *tmp;

   if (buflst == (SM_BufferLst *)NULL)
   {
      return;
   }

   while (buflst != (SM_BufferLst *)NULL)
   {
      free_SM_Buf_content(&(buflst->buffer));
      tmp = buflst->pNext;
      free (buflst);
      buflst = tmp;
   }
}

/* frees the SM_AttribLst structure */
void free_SM_AttribLst(SM_AttribLst *attriblst)
{
   SM_AttribLst *tmp;

   if (attriblst == (SM_AttribLst *)NULL)
   {
      return;
   }

   while (attriblst != (SM_AttribLst *)NULL)
   {
      if (attriblst->poidType != NULL)
      {
         free(attriblst->poidType);
         attriblst->poidType = NULL;
      }
      free_SM_Buf_content(&(attriblst->buffer));
      tmp = attriblst->pNext;
      free (attriblst);
      attriblst = tmp;
   }
}

/* frees the SM_BufferLst structure */
void free_SM_SignerInfoLst(SM_SignerInfoLst *signerinfolst)
{
   SM_SignerInfoLst *tmp;

   if (signerinfolst == (SM_SignerInfoLst *)NULL)
   {
      return;
   }

   while (signerinfolst != (SM_SignerInfoLst *)NULL)
   {
      free_SM_AttribLst(signerinfolst->pSignedAttrs);
      free_SM_AttribLst(signerinfolst->pUnSignedAttrs);
      tmp = signerinfolst->pNext;
      free (signerinfolst);
      signerinfolst = tmp;
   }
}

/* ------------ */
/* free_SM_Bytes */
/* ------------ */
void free_SM_Bytes(Bytes_struct **bytes)
{
   Bytes_struct *temp;

   if (bytes == 0)
      return;
   if (*bytes == 0)
      return;

   temp = *bytes;
   *bytes = 0;

   free(temp->data);
   free(temp);
   return;
}

/*  This routine is called upon to free up the memory used by a linked list
 of ans.1 encoded certificates.  The memory for the list structures and the
 memory for the encoded asn.1 blocks are free'd up. The callers storage ptr
 is also set to NULL for them so they don't try using it for any further
 calls once it is gone. */
void free_SM_EncCertList(EncCert_LL **listhead)
{
   EncCert_LL   *atList, *nList;

   if (listhead == NULL)
       return;
   if (*listhead == NULL)
       return;

   atList = *listhead;
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

   *listhead = 0;   /* so caller doesn't use any further */
   return;
}

/* -------------- */
/* free_SM_EncCRLs */
/* -------------- */
void free_SM_EncCRLs(EncCRL_LL **listhead)
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

/* EOF sm_CFrees.c */
