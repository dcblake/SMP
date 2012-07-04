/*****************************************************************************
File:     CRL_hash.cpp
Project:  CRL Management Library
Contents: Contains the implementation of the CRL revocation hash table. 

Created:  January 2004
Author:   Tom Horvath <Tom.Horvath@DigitalNet.com>

Last Updated:  9 Febuary 2004

Version:  2.4

*****************************************************************************/
#include <string.h>
#include "CRL_SRVinternal.h"

using namespace CRLSRV;
using namespace CML::ASN;

// NEW HASH

typedef  unsigned long int  u4;   /* unsigned 4-byte type */
typedef  unsigned     char  u1;   /* unsigned 1-byte type */

/* The mixing step */
#define mix(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>13); \
  b=b-c;  b=b-a;  b=b^(a<<8);  \
  c=c-a;  c=c-b;  c=c^(b>>13); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<16); \
  c=c-a;  c=c-b;  c=c^(b>>5);  \
  a=a-b;  a=a-c;  a=a^(c>>3);  \
  b=b-c;  b=b-a;  b=b^(a<<10); \
  c=c-a;  c=c-b;  c=c^(b>>15); \
}


namespace CRLSRV {

static int CRLCheckFor (HashTable *table, ulong hash);
static bool CRLRemoveHashEntry(HashTable *table, ulong hash);

/* The whole new hash function */
ulong CRLMakeHash1(const char *k, ulong length, ulong initval)
// register u1 *k;        /* the key */
// u4           length;   /* the length of the key in bytes */
// u4           initval;  /* the previous hash, or an arbitrary value */
{
   register u4 a,b,c;  /* the internal state */
   u4          len;    /* how many key bytes still need mixing */

   /* Set up the internal state */
   len = length;
   a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
   c = initval;         /* variable initialization of internal state */

   /*---------------------------------------- handle most of the key */
   while (len >= 12)
   {
      a=a+(k[0]+((u4)k[1]<<8)+((u4)k[2]<<16) +((u4)k[3]<<24));
      b=b+(k[4]+((u4)k[5]<<8)+((u4)k[6]<<16) +((u4)k[7]<<24));
      c=c+(k[8]+((u4)k[9]<<8)+((u4)k[10]<<16)+((u4)k[11]<<24));
      mix(a,b,c);
      k = k+12; len = len-12;
   }

   /*------------------------------------- handle the last 11 bytes */
   c = c+length;
   switch(len)              /* all the case statements fall through */
   {
   case 11: c=c+((u4)k[10]<<24);
   case 10: c=c+((u4)k[9]<<16);
   case 9 : c=c+((u4)k[8]<<8);
      /* the first byte of c is reserved for the length */
   case 8 : b=b+((u4)k[7]<<24);
   case 7 : b=b+((u4)k[6]<<16);
   case 6 : b=b+((u4)k[5]<<8);
   case 5 : b=b+k[4];
   case 4 : a=a+((u4)k[3]<<24);
   case 3 : a=a+((u4)k[2]<<16);
   case 2 : a=a+((u4)k[1]<<8);
   case 1 : a=a+k[0];
     /* case 0: nothing left to add */
   }
   mix(a,b,c);
   /*-------------------------------------------- report the result */
   return c;
}

// END OF NEW HASH




/*
 *
 * From sdbm, an ndbm work-alike hashed database library
 * Author: oz@nexus.yorku.ca
 * Status: public domain.
 *
 * polynomial conversion ignoring overflows
 * [this seems to work remarkably well, in fact better
 * then the ndbm hash function. Replace at your own risk]
 * use: 65599   nice.
 *      65587   even better.
 *
 * [In one experiment, this function hashed 84165 symbols (English words
 * plus symbol table values) with no collisions. -bjb]
 *
 */

ulong CRLMakeHash (char *str, ulong len)
{
    ulong n = 0;
#define HASHC   n = *str++ + 65587 * n

    if (len > 0)
    {
        int loop;
        loop = (len + 8 - 1) >> 3;
        switch (len & (8 - 1))
	{
          case 0:            /* very strange! - switch labels in do loop */
            do
	    {
                HASHC;
              case 7: HASHC;
              case 6: HASHC;
              case 5: HASHC;
              case 4: HASHC;
              case 3: HASHC;
              case 2: HASHC;
              case 1: HASHC;
	    } while (--loop);
	}
    }
    return n;
}


/* Creates and clears a new hash slot */
static Slot *NewSlot()
{
  Slot *foo;

  foo =  new Slot;
  if (foo == NULL)
      return NULL;
  memset (foo, 0, sizeof (Slot));
  return foo;
}

/* Create a new cleared hash table */
static HashTable *NewTable()
{
  HashTable *new_table;

  new_table = (HashTable *) new HashTable;
  if (new_table == NULL)
      return NULL;
  memset (new_table, 0, sizeof (HashTable));
  return new_table;
}

/* This routine is used to initialize the hash tables. When it is called
 * it returns a value which is used to identify which hash table
 * a particular request is to operate on.
 */
HashTable *CRLInitHash()
{
  HashTable *table;
  table = NewTable();
  if (table == NULL)
      return 0;
  else
      return table;
}

/*
 * This routing is used to free a HashTable
 */
void CRLDestroyHash(HashTable *&pHashTbl)
{
    Slot *entry;
    Revocation *value;
    int i;
    for (i=0; i < CRL_HASH_TABLESIZE; i++)
    {
		if ((*pHashTbl)[i])
         {
            entry = (Slot *)(*pHashTbl)[i];
            value = (Revocation *)entry->value;
            if (entry->table)
              CRLDestroyHash(entry->table);

            if (value)
			{
				delete value;
				value = NULL;
			}
			if (entry)
			{
	            delete entry;
				entry = NULL;
			}
         }
	}
    delete[] pHashTbl;
    pHashTbl = NULL;
}

/* When a hash collision occurs at a leaf slot this routine is called to
 * split the entry and add a new level to the tree at this point.
 */
static bool SplitAndInsert (Slot *entry, Revocation *element, ulong hash_value)
{
  if (((entry->table = NewTable()) == NULL) ||
      !CRLInsert (entry->table, entry->value, entry->hash >> CRL_HASH_INDEXSHIFT) ||
      !CRLInsert (entry->table, element, hash_value >> CRL_HASH_INDEXSHIFT))
    return false;

  entry->leaf = false;
  return true;
}

/* This routine takes a hash table identifier, an element (value) and the
 * coresponding hash value for that element and enters it into the table
 * assuming it isn't already there.
 */

bool CRLInsert (HashTable *table, Revocation *element, ulong hash_value)
{
	Slot *entry;
	entry = (Slot *) (*table)[hash_value & CRL_HASH_INDEXMASK];

	if (entry == NULL)
	{
		// Ignore revocation if it is remove from CRL
		if (element->GetRevocation() &&
			element->GetRevocation()->exts &&
			element->GetRevocation()->exts->reasonCode &&
			element->GetRevocation()->exts->reasonCode->value &&
			(*(short *)element->GetRevocation()->exts->reasonCode->value & CM_CRL_REMOVE_FROM_CRL))
		{
			// Remove the entry
			delete element;
			return true;
		}

		/* Need to add this element here */
		entry = NewSlot();
		if (entry == NULL)
			return false;
		entry->leaf = true;
		entry->value = element;
		entry->hash = hash_value;
		(*table)[hash_value & CRL_HASH_INDEXMASK] = entry;
		return true;
	}

	if (hash_value == entry->hash)
	{
		// They are the same, compare to  see if duplicate
		if (memcmp(entry->value->GetKey(),
					element->GetKey(), element->GetKeyLen()) == 0)
		{
			if (*entry->value->GetSerialNumber() == *element->GetSerialNumber())
			{
				// Check if we need to remove or update this revocation
				if (element->GetRevocation() &&
					element->GetRevocation()->exts &&
					element->GetRevocation()->exts->reasonCode &&
					element->GetRevocation()->exts->reasonCode->value &&
					(*(short *)element->GetRevocation()->exts->reasonCode->value & CM_CRL_REMOVE_FROM_CRL))
				{
					// Remove the old entry
					delete element;
					return CRLRemoveHashEntry(table, hash_value);
				}
				else
				{
					// Remove the old entry and add the new entry from the delta CRL
					if (CRLRemoveHashEntry(table, hash_value) == false)
						return false;
					return CRLInsert(table, element, hash_value);
				}
			}
			else
				// may want to add a link list here, test first
				return false;
		}
	}

	if (entry->leaf)
	{
		return SplitAndInsert (entry, element, hash_value);
	}

	return CRLInsert (entry->table, element, hash_value >> CRL_HASH_INDEXSHIFT);
}


/* This routine looks to see if a particular hash value is already stored in
 * the table. It returns true if it is and false otherwise.
 */
int CRLCheckFor (HashTable *table, ulong hash)
{
  Slot *entry;
  entry = (Slot *) table[hash & CRL_HASH_INDEXMASK];

  if (entry == NULL)
      return false;
  if (entry->leaf)
      return entry->hash == hash;
		
  return CRLCheckFor (entry->table, 
					(hash >> CRL_HASH_INDEXSHIFT));
}

/* In addition to checking for a hash value in the tree this function also
 * returns the coresponding element value into the space pointed to by
 * the value parameter. If the hash value isn't found false is returned
 * the the space pointed to by value is not changed.
 */
bool CRLCheckForAndReturnValue (HashTable *table, ulong hash, char *key, int keylen, Revocation **value)
{
  Slot *entry;
  if (table)
  {
      entry = (Slot *) (*table)[hash & CRL_HASH_INDEXMASK];

      if (entry == NULL)
          return false;

      if (entry->leaf)
      {
		  // if the hash is the same, then make sure the original key was also the same
          if ((entry->hash == hash) && (memcmp(entry->value->GetKey(), key, keylen) == 0))
          {
			  *value = entry->value;
              return true;
          }
          else
              return false;
      }
      return CRLCheckForAndReturnValue (entry->table, 
		  hash >> CRL_HASH_INDEXSHIFT, key, keylen,
		  value);
  }
  else
     return false;
}

bool CRLRemoveHashEntry(HashTable *table, ulong hash)
{
	Slot *entry;
	if (table)
	{
		entry = (Slot *)(*table)[hash & CRL_HASH_INDEXMASK];
		if (entry == NULL)
			return true;
		if (entry->leaf)
		{
			delete entry->value;
			entry->value = 0;
			entry->leaf = 0;
			entry->hash = 0;
			delete entry;
			(*table)[hash & CRL_HASH_INDEXMASK] = 0;

			return true;
		}
		else
			return false;
	}
	return true;
}

} // end namespace CRLSRV
