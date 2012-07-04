/*****************************************************************************
File:     SRL_util.c
Project:  Storage and Retrieval Library
Contents: File containing all of the internal common routines used byt
          Storage and Retrieval Library

Created:  15 November 2000
Author:   Robin Moeller <Robin.Moeller@DigitalNet.com>

Last Updated:  21 January 2004

Version:  2.4

*****************************************************************************/
#include <string.h>
#include "SRL_internal.h"

/*
ASN_DecTag()
short ASN_DecTag(uchar  *b, ulong*   bytesDecoded, ulong *tag)

This routine returns an asn tag in the format we use - the
tag value is shifted up to fill up an unsigned long so that
the first tag byte will appear in the most significant byte
of the long. (allows us to do comparisons easily when dealing
with multibyte tags).

*/
short ASN_SRLDecTag(uchar  *b, ulong*   bytesDecoded, ulong *tag)
{
   ulong   tagid, tmptagid, i;

   /* start off by shifting the tag byte to the top
    * of our long
    */
   tmptagid = (ulong) *b++;
   tagid = tmptagid << ((sizeof(ulong) -1) * 8);
   (*bytesDecoded)++;   /* track bytes we've pulled out of buffer */

   /* check for the long tag format
    *  if tag value is 31 or greater, then lower 5 bits of
    * the first tag byte are set.  We mask out 876 since
    * bits 8 & 7 are the tag class, and bit 6 indicates
    * primitive (0)/constructed(1) encoding
    *
    * Class				  8      7
    * -------------	 	 --      --
    * Universal           0       0
    * Application         0       1
    * Context-specific    1       0
    * Private             1       1
    */

   if((tmptagid & (ulong) 0x1f) != (ulong) 0x1f)
   {
      /* short tag value, shift it up and return */
      *tag = tagid; /* give it to caller */
      return(SRL_SUCCESS);
   }

   i = 2;   /* next tag byte - start on byte two of the tag */

   do
   {
      /* following bytes of the tag have the hi bit set (8)
       * unless it is the last tag byte (no hi bit set)
       */
      tmptagid = (ulong) *b++;   /* get next tag byte */

      /* shift byte up to next loc (1 | 2 | 3 | 4) */
      tagid |= (tmptagid << ((sizeof(ulong) -i) * 8));

      (*bytesDecoded)++; /* track bytes we've pulled out of buffer */

      i++; /* move over to next location */

   }/* while hi bit in tag byte set, and we haven't overflowed */
   while( (tmptagid & (ulong) 0x80) && (i < sizeof(ulong)));

   /* check for illegal tag length (too long, overflowed) */
   if( i > (sizeof(ulong) + 1))
      return(SRL_ASN_ERROR);

   /* all done here */
   *tag = tagid;
   return(SRL_SUCCESS);
}

/*

ASN_SRL_DecLen()
short ASN_SRL_DecLen(uchar *b, ulong* bytesDecoded, ulong *len)

decodes a asn.1 encoded length -

*/

short ASN_SRL_DecLen(uchar *b, ulong* bytesDecoded, ulong *len)
{
   ulong   byte, lenbytes, nen;

   byte = (ulong)(*b++);
   (*bytesDecoded)++;

   if(byte < 128)   /* short length value */
   {
      *len = byte;
      return(SRL_SUCCESS);
   }

   /* indefinate length type (data terminated by EOC = two zero octets)*/
   if(byte == (ulong) 0x80)
   {
      *len = INDEFINITE_LEN;
      return(SRL_SUCCESS);
   }

   /* else we have the long length form.
    * hi bit set (bit 8)
    * bits 7 to 1 indicate the number of subsequent octets
    * making up the length octets.
    */

   /* so strip out the hi bit to find out how many bytes make up the length */
   lenbytes = byte & (ulong) 0x7f;

   if(lenbytes > sizeof(ulong))   /* i don't handle numbers larger than this */
      return(SRL_ASN_ERROR);

   /* update dec count by number of bytes we will extract to make
    * up the length.
    */
    (*bytesDecoded) += lenbytes;

    /* now loop thru and pull them out */
    nen = 0;
    while(lenbytes--)
       nen = (nen << 8) | (ulong) *b++;

    *len = nen;

    return(SRL_SUCCESS);


}

/*  I think rich has a similar routine - replace this later.
 *
 * Function: AsnGetLength()
 *
 * short   AsnGetLength(uchar *asn1data, ulong *numBytes)
 *
 * This routine determines the length of a asn1 block, assuming that the
 * encoded object starts with a type tag...ie no jumping into random area
 * of a asn1 block.  The length will be returned to the caller, upon errors
 * the length returned will be 0...
 *
 * This length is the total length of the asn object pointed at by the passed
 * in param, which means it includes the # of tag and length bytes that start
 * the asn object.
 *
 *    parameters:
 *      asn1data (input) = the asn1data you want to know the length of
 *
 *       numBytes (input/output) = length of data, or 0 if bad data formed...
 *
 * returns:
 *      SRL_SUCCESS - ok dokey
 *      SRL_ASN_ERROR - ill formed asn data
 */
short SRLi_AsnGetLength(uchar *asn1data, ulong *numBytes)
{
   ulong   dec_count, len, tag;
   short      err;

   dec_count = 0;   /* counts bytes read from buffer during decode of tag and len */
   if (asn1data == NULL)
	   return (SRL_MEMORY_ERROR);
   err = ASN_SRLDecTag(asn1data, &dec_count, &tag);
   if(err != SRL_SUCCESS)
      return(err);

   err = ASN_SRL_DecLen(&asn1data[dec_count], &dec_count, &len);
   if(err != SRL_SUCCESS)
      return(err);

   len += dec_count;   /* sum of element len + bytes used for tag and len field */

   *numBytes = len;

   return(SRL_SUCCESS);

}

int SRLDNcmp(CM_DN dn1, CM_DN dn2)
/* This function performs a case-insensitive comparison of the two DNs.  The
result of the comparison is returned and is identical to the standard strcmp()
function:
	< 0		dn1 less than dn2
	= 0		dn1 identical to dn2
	> 0		dn1 greater than dn2
*/
{

	char c1, c2;
	int dn1len = 0;  /* length for first dn */
	int dn2len = 0;  /* length of second dn */
	int x = 0;       /* index for first dn */
	int y = 0;       /* index for second dn */


	/* Check parameters */
	if ((dn1 == NULL) || (dn2 == NULL))
		return SRL_NULL_POINTER;

	/* get the length of the dns and initialize the first character */

	dn1len = strlen(dn1);
	dn2len = strlen(dn2);
	c1 = dn1[x];
	c2 = dn2[y];

	while((x < dn1len) || (y < dn2len))
	{
		/* if the current character is a space, and if the next one */
		/* is a space, skip it for both dns */
		if((x < dn1len) && (dn1[x] == ' '))
		{
			if(dn1[x + 1] == ' ')
			{
				x++;
				continue;
			}
		}
		if((y < dn2len) && (dn2[y] == ' '))
		{
			if(dn2[y + 1] == ' ')
			{
				y++;
				continue;
			}
		}

		/* first make sure we are not at the end of the either dn */
		/* convert each character to lower case then compare if equal */

		c1 = dn1[x];
		c2 = dn2[y];

		if((x < dn1len) && (y < dn2len))
		{
		    if ((c1 >= 'A') && (c1 <= 'Z'))
				c1 += 'a' - 'A';
		
			if ((c2 >= 'A') && (c2 <= 'Z'))
				c2 += 'a' - 'A';
            
			/* if two characters not equal, return strings don't match */
			if(c1 != c2)
				return (c1 - c2);

			/* increment each index for each dn */
			x++;
			y++;
		}
		else
			/* end of either string, return appropriate value */
			return (c1 - c2);
	}
	return (c1 - c2);
			
} /* end of SRLi_DNcmp() */

void num2str(short num, char *numstring)
/* positive values => outputs a string for that number */

{
   short   i;
   char   *s, *e, t;

   i = 0;
   do /* convert in backwards order using mods by 10 */
   {
      numstring[i++] = (char)(num % 10 + '0'); /* get the digit */
   }while( (num /= 10) > 0);   /* shift to next digit if any */

   numstring[i] = 0;   /* null terminate */

   s = numstring;
   e = s + i;

   while(e > s)
   {
      e--;
      t = *s;
      *s = *e;
      *e = t;
      s++;
   }
   return;
}



/* SRLi_DB2CMerr()
 * This routine is used internally to map the database library error codes
 * to CM error codes. Since we only want to present CM error codes to
 * applications which call upon the Certificate manager, this routine
 * isolates db error codes from the app.
 *
 * parameters:
 *		db_err (input) = the error code returned from a db_ call
 *
 *
 * returns:
 *
 * 		the CM error code to pass along
 *
 */
short DB2SRLerr(short db_err)
{
	short err;

	switch(db_err)
	{
		case DB_NO_ERR:
			err = SRL_SUCCESS;
		break;

		case DB_BAD_PARAM:
			err = SRL_INVALID_PARAMETER;
		break;

		case DB_NO_MEM:
			err = SRL_MEMORY_ERROR;
		break;

		case DB_NO_READ:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_NO_INSERT:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_CANT_DELETE:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_NO_WRITE:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_NOT_FOUND:
			err = SRL_NOT_FOUND;
		break;

		case DB_EXISTS:
			err = SRL_DB_ALREADY_EXISTS;
		break;

		case DB_NOT_DB_FILE:
			err = SRL_DB_UNRECOGNIZED_FILE;
		break;

		case DB_OPEN_ERROR:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_DATABASE_EMPTY:
			err = SRL_NOT_FOUND;
		break;

		case DB_BLOCK_SIZE_ERR:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_WRITE_ERR:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_SEEK_ERR:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_READ_ERR:
			err = SRL_DB_IO_ERROR;
		break;

		case DB_BAD_DATA:
			err = SRL_INVALID_PARAMETER;
		break;

		case DB_BAD_KID:
			err = SRL_NOT_FOUND;
		break;

		case DB_COMPACT_FAILED:
			err = SRL_DB_FLUSH_FAILURE;
		break;

		default:
			err = SRL_UNKNOWN_ERROR;
			break;

	}

	return(err);

}

/* SRLi_DecodeCertList()
 *
 * short SRLi_DecodeCertList(ulong SRsession, SRL_CertList *brokenPathList)
 *
 * This routine will step through the linked list of certpath structs
 * and attempt to asn decode the certificates ref'd by each member
 * of the list.  This may be useful after a call to CMU_BreakUpCertPath(),
 * or in the case where a cert path is being created, and we need a
 * decoded version of the certs.
 *
 * If an error occurs during processing, the certificates that were
 * decoded will be free'd up, and the certification path linked list
 * will be returned in it's original state. (The decoded cert ptr members
 * will be once again NULL).
 *
 * paramenters:
 *
 *      SRsession (input) = the session ref for an existing SRL session.
 *
 *      brokenPathList (input/output) = the linked list of cert path structs
 *               that have their encCert filled in with ptr refs to asn.1
 *               encoded certs (could be from a broken up asn1 cert path
 *               block, or individual encoded certs, doesn't matter here).
 *
 *   returns:
 *
 *    SRL_SUCCESS      - worked fine, linked list cert field updated with decoded
 *
 *   others - pass thru errs from the asn decoders.
 */
short SRLi_DecodeCertList(ulong srl_session, SRL_CertList *brokenPathList)
{
   SRL_CertList   *dec_cpath;
   SRLSession_struct *srlSessionInfo = NULL;
   short         err;
	Bytes_struct Object;
   err = SRL_SUCCESS;   /* being optimistic - return on err if none in list here */

   if (srl_session == 0)
	   return (SRL_SESSION_NOT_VALID);

   /* Get the session from the session ID */
   err = SRLi_GetSessionFromRef (&srlSessionInfo, srl_session);
   if (err != SRL_SUCCESS)
	   return (err);
   dec_cpath = brokenPathList;   /* start at the top of the list */

   while(dec_cpath != NULL)   /* do all for now */
   {
	  Object.data = dec_cpath->asn1cert;
	  SRLi_AsnGetLength(dec_cpath->asn1cert, (ulong *)&Object.num);
      err = CM_DecodeCert( &Object, &(dec_cpath->cert));

      if(err != SRL_SUCCESS)
         break;
      dec_cpath = dec_cpath->next;

   }

   if(err != SRL_SUCCESS)
   {
      /* clean up - need to release any that we decoded so that
       * nothing is returned to caller upon an error condition.
       */
      dec_cpath = brokenPathList;   /* start at the top again */

      while(dec_cpath != NULL)
      {
		 if (dec_cpath->cert != NULL)
	         CM_FreeCert(&(dec_cpath->cert)); /* will set field to NULL */
         dec_cpath = dec_cpath->next;
      }

   }

   return(err);   /* tell caller the outcome */
}

short SRLi_CopyBytesContent(Bytes_struct *pDest, const Bytes_struct *pSrc)
{
/* This function will copy the contents of a Bytes_struct from an existing
structure to a new structure.  The new Bytes_struct must already exist. This
function will allocate memory for the data.
*/
    /* Copy the number of bytes of data into the new structure. */
    pDest->num = pSrc->num;

    /* Allocate memory for the new data */
	if (pSrc->num == 0)
		return (SRL_SUCCESS);
    if ((pDest->data = (uchar *)calloc(1,pSrc->num)) == NULL)
        return SRL_MEMORY_ERROR;

    /* Copy the data */
    if ((pDest->data =
        (uchar *)memcpy(pDest->data, pSrc->data, pSrc->num)) == NULL)
    {
        free(pDest->data);
        pDest->data = NULL;
        return SRL_MEMORY_ERROR;
    }

    return SRL_SUCCESS;
}
short SRLi_CopyBytes(Bytes_struct *old, Bytes_struct **new_bytes)
{
/* This function will copy the contents of a Bytes_struct into a new
Bytes_struct.  This function will allocate memory for the new structure.  A
NULL pointer will be returned if a NULL pointer is passed in.
*/
    short errCode;

    /* Check if a NULL pointer was passed in */
    if (old == NULL)
    {
        *new_bytes = NULL;
        return SRL_SUCCESS;
    }
    /* Allocate memory for the new Bytes_struct */
    if (((*new_bytes) = (Bytes_struct *)calloc(1,sizeof(Bytes_struct))) == NULL)
        return SRL_MEMORY_ERROR;

    /* Copy the contents of the Bytes_struct from the old to the new */
    if ((errCode = SRLi_CopyBytesContent(*new_bytes, old)) != CM_NO_ERROR)
    {
        free(*new_bytes);
        *new_bytes = NULL;
        return errCode;
    }

    return SRL_SUCCESS;
}

CM_BOOL SRLisLittleEndian()
/*
 * Function checks the Endian-ness of the process and returns
 * TRUE if the process is Little Endian and FALSE if not little
 * Endian, this alleivates problems with compile defines
 */
{
	long value = 1;

	/* Check which byte the value 1 is in */
	if (*(char *)&value == 1)
		return TRUE;
	else
		return FALSE;
}

/* SRLi_FlipLongs
 *
 * void SRLi_FlipLongs(void* data, long numlongs)
 *
 * This routine is used to convert an array of longs from Big Endian format
 * to Little Endian format, and back.  Used internally to prepare data before
 * writing out to storage, or after reading in data from storage on little
 * endian machines. The conversion is done in place.
 *
 * Parameters:
 *		data (input) = ptr to longs to be manipulated
 *
 * 		numlongs (input) = number of longs to be swapped around
 *
 * Returns: Nothing
 *
 */
void SRLi_FlipLongs(void* data, long numlongs)
{
    int		i;
    ulong   tempnum;
    uchar*  longbuf;
    longbuf = data;

    for ( i = 0; i < numlongs; i++ )
    {
		memcpy(&tempnum, longbuf, sizeof(ulong));
      tempnum = (tempnum << 16) | (tempnum >> 16);
		tempnum = ((tempnum & 0xff00ff00L) >> 8) | ((tempnum & 0x00ff00ffL) << 8);
      memcpy(longbuf, &tempnum, sizeof(ulong));
		longbuf = longbuf + sizeof(ulong);
    }
}

/* similar to above but for shorts */
void SRLi_FlipShorts(void* data, long numshorts)
{
    int		i;
    unsigned short   tempnum;
    uchar*  shortbuf;
    shortbuf = data;

    for ( i = 0; i < numshorts; i++ )
    {
		memcpy(&tempnum, shortbuf, sizeof(unsigned short));
      tempnum = (unsigned short)((tempnum << 8) | (tempnum >> 8));
      memcpy(shortbuf, &tempnum, sizeof(unsigned short));
		shortbuf = shortbuf + sizeof(unsigned short);
    }
}


int SRLi_memicmp(char *mem1, char *mem2, int len)
/* 
   This function performs a case-insensitive comparison of the two memory locations.
   The result of the comparison is returned and is identical to the standard strcmp()
   function:
	< 0		mem1 less than mem2
	= 0		mem1 identical to mem2
	> 0		mem1 greater than mem2
*/
{
	/* Local variables */
	char c1, c2;
	int i = 0;

	/* Check parameters */
	if ((mem1 == NULL) || (mem2 == NULL))
		return -1;

	do
	{
		c1 = *mem1;
		if ((c1 >= 'A') && (c1 <= 'Z'))
				c1 += 'a' - 'A';
		c2 = *mem2;
		if ((c2 >= 'A') && (c2 <= 'Z'))
			c2 += 'a' - 'A';
		i++;
		mem1++;
		mem2++;
	} while ((c1 == c2) && i < len);

	return (c1 - c2);
} 

