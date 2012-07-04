/*****************************************************************************
File:     SRL_db.h
Project:  Storage & Retrieval Library
Contents: Header file to use SRL_db.c routines from an app.

Created:  15 November 2000
Author:   C. C. McPherson <Clyde.McPherson@getronicsgov.com>
Last Updated:  16 November 2000

Version:  1.9

*****************************************************************************/
#ifndef _SRL_DB_H
#define _SRL_DB_H
#if __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <SRL_internal.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif



/*
DB Header version meaning:
	"DBX2" Header version signifies CRL DP Processing 
	 Header version history
	 "DBX1" - Normalization of DN storage
	 "DBX2" - CRL DP Processing
	 "DBX3" - Cert/CRL Hash CRL Time to Live
			  CERT & CRL database now opional.
*/
#define DATA_BASE_HEADER_VERSION_OLD 0x44425858
#define DATA_BASE_HEADER_VERSION1 0x44425831
#define DATA_BASE_HEADER_VERSION2 0x44425832
#define DATA_BASE_HEADER_VERSION3 0x44425833

/* Defines used to normalize the DN or to not normalize the DN */
#define NORMALIZED 1
#define NOT_NORMALIZED 2

/* When storage chunks are freed up and put into an avail table, we
 * will ignore chunks that are equal to or smaller than IGNORE_SIZE
 * since the overhead of dealing with stuff this small is
 * inefficient.  (IGNORE_SIZE is in bytes)
 */
#define IGNORE_SIZE 4

/* For speeding up searching and matching of keying
 * identifiers we keep a small portion of the KID in
 * our cached storage info, the number of bytes keep is
 * SMALL_KID.
 */
#define SMALL_KID	4

/* The storage table tracks up to MAX_AVAIL elements (storage
 * elements that are freed up for use) within it's own block.
 * This is so we can try to store to the currently addressed
 * block rather than having to go back to check the headers
 * associated availability table all the time.
 */
#define MAX_AVAIL 6

/* DEFAULT_CACHESIZE configures how many elements can be held
 * in a sessions cache (basically how many kid/data pairs).
 */
#define DEFAULT_CACHESIZE  100

/* The database file is allocated in chunks of byte size
 * DB_BLOCK_SIZE for efficiency.
 *
 * I Will modify this value when I determine what is best
 * for certficates later.... may make it a parameter? 2048?
 */
#define DB_BLOCK_SIZE 1024 


/* In order to track free space in the database file, we keep a table of
 * available blocks in memory.  This table is stored in the database
 * header, and therefore also stored to disk when the db file header
 * is written out.  As the number of free/available blocks increases,
 * the table expands to fill the "tail" space of the file header block.
 * If we reach the point where the table would be too large to fit, we
 * split the table in half. One half is kept "active", while the other
 * half is pushed onto an availability stack ( written out to
 * the database file in a block other than the header).  The table that
 * sees the most use will be the one currently used and stored in the
 * header. As blocks are used up, the currently used table will then
 * have less blocks marked as free.  When it reaches the point of being
 * all used up (no more marked as available) the availability stack
 * will be "popped", reading it in from the db file, and that table will
 * become the current table (and thus stored in the header of the db file).
 *
 * The availability table is set up in the following manner. Each block
 * that is marked as free in the db file is represented in a structure
 * "avail_elem", which has the size of the available block and also
 * the offset in the file to that free block.  The table itself is defined
 * by a structure "avail_block" which contains info on how many elements
 * will fit into it, how many elements are currently in the table, a file
 * offset (from start) as to where the next table is , and the
 * actual array of "avail_elem" items.
 *
 */

/* define a structure to be used as the elements of the avaliable table.  */
typedef struct avail_elem
{
	long	avail_size;	 /* size of the available block in bytes. */
	long	avail_floc;	 /* file (location) offset of the available block. */

} avail_elem;

/* Define the availability table -
 * NOTE: storage for the array of available elements in the table
 * is allocated at the same time the avail_block with a
 * determined number of possible entries. (if read from disk it's
 * basically the housekeeping values followed by the entries...)
 */
typedef struct avail_block
{
	long	size;	   /* The number of avail elements in the table.*/
	long	count;	  /* The number of entries in the table. */
	long	next_block;	 /* The file address of the next avail block. */
	avail_elem	av_table[1];	/* The table.  An extendable array. */

} avail_block;
/* Storage - each item stored in the database is cataloged using a structure
 * "storage_element". This contains the 31bit hash of the keying identifier
 * for the data, the file offset to the location of the stored kid and its
 * data, the size of the kid, the size of the data, and also a short copy of
 * the kid itself, which is used when we are searching for kid matches
 * without having to read each kid in from the file... (searching is done
 * using the hash, and secondarily short kid, then if we find a possible
 * match, the kid is fully compared against the entry. This means we
 * don't have to read in the full entry if it wasn't cached, and also
 * speeds up the comparisons)
 *
 * To track all the stored elements, a "storage_table" is used.  This
 * structure contains an array of the storage element structures,
 * a count of how many "used" elements we have in the table, an array
 *  of available elements (for filling in a file block), a count
 *  of how many are available in the current file storage block
 * (see the preceeding available description on how this works),
 * and the number of bits that are used from the kid hash for these
 * storage elements in the directory/index array.
 * To speed up writes to the db file, we allocate file blocks with a
 * certain number of available slots open, otherwise we could possibly
 * be allocating more space to the file each time. (depends on the
 * availability of previously deleted elements - the availability
 * table in the header....)
 *
 * When the storage block/table gets full, we go through the same
 * split as described in the availability table description.
 *
 * The contents are split between them by the use of the first few bits
 * of the 31 bit hash function.  The location in a block is the hash
 * value modulo the size of the block.
 */

// 03/07/2002 - 
// The storage element was modified to have both hash values that 
// relate to the cert/crl in memory. These two hash values are for the template, and
// cert/crl raw storage. This gives the application a way to delete based on
// a Database ID (hash value).  
typedef struct storage_element
{
	long	hash_value;		/* 31 bit hash of the kid (DN) */
	long	SiblingHash;	/* 31 bit hash of the kid (Template) */
	char	kid_start[SMALL_KID];   /* Up to the first SMALL_KID bytes of the kid.  */
	long	data_pointer;	   /* the file offset to this entry (kid then data)  */
	long	kid_size;		 /* size of keying identifier in the file. */
	long	data_size;		/* size of associated data in the file. */

} storage_element;


typedef struct storage_table
{
   long	av_count;   /* The number of available entries. */
   avail_elem	storage_avail[MAX_AVAIL];  /* what's available(free) in this block */
   long		storage_bits;  /* The number of dir bits used to get here. */
   long		 count;  /* The number of storage elements in this table */
   storage_element se_table[1]; /* extendable array of Stored Elements */

} storage_table;


/* define the header for the database file.  This tracks the location
 * of the files directory (index of the storage blocks) along with
 * the files current availability table, the next available block,
 * etc.
 */
typedef struct db_file_header
{
	long	header_ident;	/* set to 0x44425831="DBX1" 0x44425858="DBXX" to identify our file type */
	long	block_size;		/* configured block size of i/o ops */
	long	dir_location;	/* file offset to the current storage directory/index block. */
	long	dir_size;		/* Size in bytes of the dir/index array.  */
	long	dir_bits;		/* number of addressing bits used in the table.*/
	long	max_store_elems;/* the number of elements in a storage block (plus one) */
	long	next_block;		/* The next unallocated file block address. */
	avail_block avail;		/* This avail table grows to fill the entire header block. */

} db_file_header;

// 03/07/2002 - 
// The storage element was modified to have both hash values that 
// relate to the cert/crl in memory. These two hash values are for the template, and
// cert/crl raw storage. This gives the application a way to delete based on
// a Database ID (hash value).  

/* information about the cached item */
typedef struct cached_item_info
{
	long	hash_val;		/* hash of this entries kid  */
	long	SiblingHash;	/* 31 bit hash of the related kid (if any) */
	long	data_size;		/* byte size of the data */
	long	kid_size;		/* byte size of the kid */
	char	*dptr;			/* mem location of kid then associated data */
	long	elem_loc;		/* corresponding storage table entry index (se_table[] ) */

}  cached_item_info;

/* house keeping info for each cache entity */
typedef struct cache_elem
{
	storage_table	   *ca_block;	/* mapping in the block to the cached entry */
	long				ca_adr;		/* file offset to this file block */
	char				ca_changed;	/* Data in the cache changed. */
	cached_item_info	ca_data;	/* particulars about this kid & associated data */

} cache_elem;

/* The "global" information for the database manager is contained all
 * in one structure.  This data is all associated with a particular file,
 * so that it's possible to have more than one database file be open
 * at time, each associated with it's particular session.
 */
typedef struct DB_Session_Struct
{

	char	*name;		/* name of the database file connected to this session */
	char	*path;		/* the path to the database file for this session */
	int		useCount;	/* The usage count for this session */
	long	access;		/* access flag for this file/session (read,write, both) */

	int		 file;		/* the file descriptor associated with this session */

	FILE    *fileStream;/* File stream associated with the file descriptor */

	db_file_header  *dbheader;	/* file header information about the database. */

	/* directory is an array of offsets corresponding to each
	 * hashed storage block address in the db file,
	 * block 1 of the file contains the initial dir_table index array.
	 */
	long *dir_table;

	/* fields for tracking the cache */
	cache_elem	*cached_blocks; /* array of cache elements */
	long	cache_size;			 /* how many cached elements we can hold */
	long	idx_of_last_read;	 /* wrap around index of the last one read into memory */

	/* Pointer to the current entry's (kid & data) cache element. */
	cache_elem		*current_cache_entry;

	/* fields for tracking the current storage block */
	storage_table   *storage_map; /* the current storage table for the db file */

	/* The directory entry (index value) used to get the current storage_map. */
	long	storage_map_dir;	/* dir_table[storage_map_dir] => current storage block */


	/* Keep track of modifications so that we know what has to
	 * be written out to the file at the end of updates.
	 */
	char	dbheader_changed;		 /* any of the data in the header block */
	char	directory_changed;	/* directory info changed, duh */
	char	cur_cache_changed;	/* currently pointed at cached block changed */
	char	second_changed;	 /* secondary cached blocks changed */

} DB_Session_Struct;


/* Define a structure to refer to chunks of info for use
 * as keying identifiers and the associated data.
 */
typedef struct DB_Item
{
    long    item_len;               /* length of data pointed at */
    char    *item_ptr;              /* points to items data */

}DB_Item;

/* structure to hold a keying identifier */
/* structure to hold generic data */

typedef DB_Item DB_Data;
typedef DB_Item DB_Kid;

/* structure to hold a keying identifier */
/* structure to hold generic data */


/* database files can be opened with one of the following
 * access flags:
 *
 * DB_READ - file open for reads only, no modifications allowed
 * to be made on callers behalf.
 *
 * DB_WRITE - file open for write only, no reads allowed on behalf
 * of caller.
 *
 * DB_RDWR - file open for read & write.
 *
 * DB_NEW - create a new db file, opened with read & write access.
 *
 * NOTE: the db library itself has access to the file in order to
 * do housekeeping functions, even though the caller might not...
 */
enum DB_ACCESS_FLAG {DB_READ, DB_WRITE, DB_RDWR, DB_NEW};

/* flags used when adding items to the database, either inserting
 * an item, or replacing an item.
 */
enum {DB_INSERT, DB_REPLACE};

/* figure out what data we return for info later */
typedef struct DB_INFO_Struct
{
    long    data;
}DB_INFO_Struct;

/* the error flags returned from the db library */

#define DB_NO_ERR               0
#define DB_BAD_PARAM            -2001
#define DB_NO_MEM               -2002
#define DB_NO_READ              -2003
#define DB_NO_INSERT            -2004
#define DB_CANT_DELETE          -2005
#define DB_NO_WRITE             -2006
#define DB_NOT_FOUND            -2007
#define DB_EXISTS               -2008
#define DB_NOT_DB_FILE          -2009
#define DB_OPEN_ERROR           -2010
#define DB_DATABASE_EMPTY       -2011
#define DB_BLOCK_SIZE_ERR       -2012
#define DB_WRITE_ERR            -2013
#define DB_SEEK_ERR             -2014
#define DB_READ_ERR             -2015
#define DB_BAD_DATA             -2016
#define DB_BAD_KID              -2017
#define DB_COMPACT_FAILED       -2018

/* foreward declaration of the routines */
short db_Open(ulong *db_session,  char *filename, long access,
long blocksize);
short db_dupe(ulong *db_session);

short db_Close(ulong *db_session);
short db_StoreItem(ulong db_session, DB_Kid *kid, DB_Data *data, 
				long *HashValue, long storeFlag);
short db_GetEntry(ulong db_session, long hashValue, DB_Kid *kid, DB_Data **data);
short db_DeleteEntry(ulong db_session, DB_Kid *kid);
short db_GetFirstKid(ulong db_session, DB_Kid **kid);
short db_GetNextKid(ulong db_session, DB_Kid *kid, DB_Kid **next_kid);
short db_Compact(ulong db_session);
short db_Info(ulong db_session, DB_INFO_Struct **info);
short db_ConvertCrlDbFile(ulong db_session);
void db_FreeDBInfo(DB_INFO_Struct **info);
short SRLi_isDN(char a);
short DB2SRLerr(short db_err);
short SRLi_CertInfoFromTemplate(ulong db_session, dbCertEntryInfo_LL **certinfo,DB_Data *ctemplate);
short SRLi_CRLInfoFromTemplate(ulong db_session, dbCRLEntryInfo_LL **crlinfo,DB_Data *ctemplate);
dbEntryInfo_LL *SRLi_SortdbEntryLL(dbEntryInfo_LL *theList);
short ASN_SRLDecTag(uchar  *b, ulong*   bytesDecoded, ulong *tag);
short ASN_RetDecLen(uchar *b, ulong* bytesDecoded, ulong *len);
short SRLi_AsnGetLength(uchar *asn1data, ulong *numBytes);
short SRLi_CompareTemplateSearchCriteria(DB_Data *ex_data, Bytes_struct *ciTemplate);
void SRLi_FreeDB_Item (DB_Item **DBItem);


#if __cplusplus
}
#endif

#endif
