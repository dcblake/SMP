/*****************************************************************************
File:	  SRL_db.c
Project:  Storage & Retrieval Library
Contents: Library of generic database routines which will be used by the
	      Certificate Management local storage routines to convert previous
		  data bases to version 2.1 new data base structure.

Created:  November 2000
Author:   C. C. McPherson <Clyde.McPherson@GetronicsGov.com>
          Shari Bodin <Shari.Bodin@GetroinicsGov.com>

Last Updated:	9 December 2002

Version:  2.2

Description:  The routines in this file are broken into two groups.  Those
		      routines which are meant to be the interface to this database
		      library named "dbV2_xxxxxx",  and routines named "dbuV2_xxxxxxx"
		      which are meant to be only used internally.

		Interface to the db library routines:

		dbV2_Open() - start up a session and open or create db file
		dbV2_close() - close down session, close db file, free up mem
		dbV2_StoreItem() - insert/replace an item to db file
		dbV2_GetEntry() - retrieve a database entry
		dbV2_GetFirstKid() - get keying identifier for first entry in db
           file
		dbV2_GetNextKid() - get a following key identifier (for stepping)
		dbV2_Compact() - compacts the free space in the db file
		dbV2_Info() - retrieve info about the session's db file

		The routines in this file are not meant for general
		use.

*****************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
//#include <time.h>
/* To support moving db files between little and big endian hardware,
 * the routine SRLisLittleEndian is used - this will format data correctly
 * after reading, or before writing. This only applies to data used internally
 * by the db manager code.  Upper level apps are the only ones that know what
 * they are storing, and will have to deal accordingly where necessary.
 */
#ifdef _WINDOWS
	#define _WIN32_WINNT	0x0500
	#pragma warning(disable: 4115)
	#pragma warning(disable: 4127)
	#include <windows.h>
	#include <sys\stat.h>
	#include <io.h>
#else
	#include <unistd.h>
	#ifdef _UNIX
	#include <ctype.h>
	#include <sys/stat.h>
#ifndef NOTHREADS // Used if system doesn't support threads
	#include <pthread.h>
#endif
	#endif
#endif
#include "SRL_internal.h"
#include "cmapi.h"

#define CRLDB 1
#define CERTDB 2

/* 
 * Version 2.01 Data Base structures:
 */

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
#define CERTCVT 1
#define CRLCVT  2
#define DB_TEMPLATE_FLAG		(uchar)0x01
#define DB_NORMALIZED_FLAG		(uchar)0x01

/* these two values will be incremented if fields are 
 * added to their respective formats...
 */
#define CRL_TEMPLATE_VERSION1   (uchar)0x01  // Original version
#define CERT_TEMPLATE_VERSION2	(uchar)0x02  // Normalized DN version
#define CERT_TEMPLATE_VERSION	(uchar)0x03  // CERT Type processing
#define CRL_TEMPLATE_VERSION	(uchar)0x04	 // CRL Type and DP Name processing

/* define a structure to be used as the elements of the avaliable table.  */
typedef struct avail_elemV2
{
	long	avail_size;	 /* size of the available block in bytes. */
	long	avail_floc;	 /* file (location) offset of the available block. */

} avail_elemV2;

/* Define the availability table -
 * NOTE: storage for the array of available elements in the table
 * is allocated at the same time the avail_block with a
 * determined number of possible entries. (if read from disk it's
 * basically the housekeeping values followed by the entries...)
 */
typedef struct avail_blockV2
{
	long	size;	   /* The number of avail elements in the table.*/
	long	count;	  /* The number of entries in the table. */
	long	next_block;	 /* The file address of the next avail block. */
	avail_elemV2	av_table[1];	/* The table.  An extendable array. */

} avail_blockV2;
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
typedef struct storage_elementV2
{
	long	hash_value;		/* 31 bit hash of the kid (DN) */
	char	kid_start[SMALL_KID];   /* Up to the first SMALL_KID bytes of the kid.  */
	long	data_pointer;	   /* the file offset to this entry (kid then data)  */
	long	kid_size;		 /* size of keying identifier in the file. */
	long	data_size;		/* size of associated data in the file. */

} storage_elementV2;


typedef struct storage_tableV2
{
   long	av_count;   /* The number of available entries. */
   avail_elemV2	storage_avail[MAX_AVAIL];  /* what's available(free) in this block */
   long		storage_bits;  /* The number of dir bits used to get here. */
   long		 count;  /* The number of storage elements in this table */
   storage_elementV2 se_table[1]; /* extendable array of Stored Elements */

} storage_tableV2;


/* define the header for the database file.  This tracks the location
 * of the files directory (index of the storage blocks) along with
 * the files current availability table, the next available block,
 * etc.
 */
typedef struct db_file_headerV2
{
	long	header_ident;	/* set to 0x44425831="DBX1" 0x44425858="DBXX" to identify our file type */
	long	block_size;		/* configured block size of i/o ops */
	long	dir_location;	/* file offset to the current storage directory/index block. */
	long	dir_size;		/* Size in bytes of the dir/index array.  */
	long	dir_bits;		/* number of addressing bits used in the table.*/
	long	max_store_elems;/* the number of elements in a storage block (plus one) */
	long	next_block;		/* The next unallocated file block address. */
	avail_blockV2 avail;		/* This avail table grows to fill the entire header block. */

} db_file_headerV2;

// 03/07/2002 - 
// The storage element was modified to have both hash values that 
// relate to the cert/crl in memory. These two hash values are for the template, and
// cert/crl raw storage. This gives the application a way to delete based on
// a Database ID (hash value).  

/* information about the cached item */
typedef struct cached_item_infoV2
{
	long	hash_val;		/* hash of this entries kid  */
	long	data_size;		/* byte size of the data */
	long	kid_size;		/* byte size of the kid */
	char	*dptr;			/* mem location of kid then associated data */
	long	elem_loc;		/* corresponding storage table entry index (se_table[] ) */

}  cached_item_infoV2;

/* house keeping info for each cache entity */
typedef struct cache_elemV2
{
	storage_tableV2	   *ca_block;	/* mapping in the block to the cached entry */
	long				ca_adr;		/* file offset to this file block */
	char				ca_changed;	/* Data in the cache changed. */
	cached_item_infoV2	ca_data;	/* particulars about this kid & associated data */

} cache_elemV2;

/* The "global" information for the database manager is contained all
 * in one structure.  This data is all associated with a particular file,
 * so that it's possible to have more than one database file be open
 * at time, each associated with it's particular session.
 */
typedef struct DB_Session_StructV2
{

	char	*name;		/* name of the database file connected to this session */
	char	*path;		/* the path to the database file for this session */

	long	access;		/* access flag for this file/session (read,write, both) */

	int		 file;		/* the file descriptor associated with this session */

	FILE    *fileStream;/* File stream associated with the file descriptor */

	db_file_headerV2  *dbheader;	/* file header information about the database. */

	/* directory is an array of offsets corresponding to each
	 * hashed storage block address in the db file,
	 * block 1 of the file contains the initial dir_table index array.
	 */
	long *dir_table;

	/* fields for tracking the cache */
	cache_elemV2	*cached_blocks; /* array of cache elements */
	long	cache_size;			 /* how many cached elements we can hold */
	long	idx_of_last_read;	 /* wrap around index of the last one read into memory */

	/* Pointer to the current entry's (kid & data) cache element. */
	cache_elemV2		*current_cache_entry;

	/* fields for tracking the current storage block */
	storage_tableV2  *storage_map; /* the current storage table for the db file */

	/* The directory entry (index value) used to get the current storage_map. */
	long	storage_map_dir;	/* dir_table[storage_map_dir] => current storage block */


	/* Keep track of modifications so that we know what has to
	 * be written out to the file at the end of updates.
	 */
	char	dbheader_changed;		 /* any of the data in the header block */
	char	directory_changed;	/* directory info changed, duh */
	char	cur_cache_changed;	/* currently pointed at cached block changed */
	char	second_changed;	 /* secondary cached blocks changed */

} DB_Session_StructV2;

extern 	void db_lock();
extern 	void db_unlock();
extern short db_CalcHash(ulong db_session, DB_Kid *kid, DB_Kid *data, long norm_type, 
				  long *HashValue,  long relatedHash, long storeFlag);
extern int thread_open(char *fileName, int oflag, int mode);
extern size_t thread_write(int fd, FILE *fdStream, void  *buf, size_t count);
extern size_t thread_read(int fd, void *buf, size_t count);
extern short db_StoreItem(ulong db_session, DB_Kid *kid, DB_Data *data, long *HashValue, long storeFlag);
extern short db_GetHash(DB_Kid *kid, long norm_type, long *HashValue);
extern short dbu_get_block (DB_Session_Struct *session,long dir_index);

/* foreward declaration of the routines */
static short dbV2_open(ulong *db_session, char *filename, long access,
long blocksize);
static short RemoveTempFile(char *Filename);
short time2CMTime(time_t t, char cm_time[CM_TIME_LEN]);
short dbV2_close(ulong *db_session);
short dbV2_StoreItem(ulong db_session, DB_Kid *kid, DB_Data *data, long *HashValue, long storeFlag);
short dbV2_GetEntry(ulong db_session, DB_Kid *kid, DB_Data **data);
short dbV2_GetFirstKid(ulong db_session, DB_Kid **kid);
short dbV2_GetNextKid(ulong db_session, DB_Kid *kid, DB_Kid **next_kid);
short dbV2_Info(ulong db_session, DB_INFO_Struct **info);
void dbV2_FreeDBInfo(DB_INFO_Struct **info);
short dbV2_UpdateHeaderVersion (ulong db_session, char *path, char *dbfile);
short SRLi_TemplateFromCertInfo(DB_Kid *kid, dbCertEntryInfo_LL *certinfo);
short SRLi_TemplateFromCRLInfo(DB_Kid *kid, dbCRLEntryInfo_LL *crlinfo);
short DB2SRLerr(short db_err);
short SRLi_BreakUpCertList(ulong cm_session, uchar *asndata, SRL_CertList **cp);
extern CM_BOOL isRoot(Cert_struct *cert);
extern CM_BOOL CompareBytes(const Bytes_struct *a, const Bytes_struct *b);
short SRLi_GetCertID(ulong sessionID, Bytes_struct *pObject, Cert_struct *dec_cert,CM_BOOL trustedFlag, AsnTypeFlag AsnType, Bytes_struct **CertID);
short SRLi_GetCRLID(ulong sessionID, Bytes_struct *pObject, CRL_struct *dec_crl, long *DBid);
static short ModifyCRLTemplate (DB_Item *CRLtemplate, DB_Item **NewTemplate);
CM_BOOL SRLisLittleEndian();

/* internal use only routines */
//static long dbuV2_getkey (DB_Session_StructV2 *session,DB_Kid *kid,char **dptr,long hash_val);
static short dbuV2_get_next_kid (DB_Session_StructV2 *db_session,long elem_loc, DB_Kid *return_kid);
static short dbuV2_free (DB_Session_StructV2 *session,long file_adr,long num_bytes);
static short dbuV2_push_avail_block (DB_Session_StructV2 *session);
static avail_elemV2 dbuV2_get_avail_elem (long size,avail_elemV2 *av_table,long *av_count);
static long dbuV2_put_avail_elem (avail_elemV2 new_el,avail_elemV2 av_table[],long *av_count);
static avail_elemV2 dbuV2_allocate_block (long size, DB_Session_StructV2 *session);
static void dbuV2_adjust_storage_avail (DB_Session_StructV2 *session);
static void dbuV2_init_storagetable (DB_Session_StructV2 *session,storage_tableV2 *new_storage, long bits);
static short dbuV2_init_cache(DB_Session_StructV2 *session,long size);
static short dbuV2_get_block (DB_Session_StructV2 *session,long dir_index);
static short dbuV2_write_block (DB_Session_StructV2 *session, cache_elemV2 *ca_entry);
static short dbuV2_read_entry (DB_Session_StructV2 *session,long elem_loc, char **eData);
static long dbuV2_hash (long norm_type, DB_Kid *kid);
static long dbuV2_findkey (DB_Session_StructV2 *session,DB_Kid *kid,char **dptr,long *new_hash_val, long norm_type);
static char *LE_PrepLongs(long *longbuff, long numbytes);
static char *LEV2_PrepStorageMap(storage_tableV2 *storage_map, long mapbytes);
static int dbuV2_memicmp(char *mem1, char *mem2, int len);

#ifndef NOTHREADS
	/* Define our externally defined mutex */
	#if defined (WIN32) || defined (WINDOWS)
		extern HANDLE g_srl_db_mutex;
	#else
		extern pthread_mutex_t g_srl_db_mutex;
	#endif
#endif


/*
---------------------------------------------------------------------------
General Database Routines
---------------------------------------------------------------------------

db_Open()

short db_Open(ulong *db_session, char *filepath, char *filename, long access,
long blocksize)

This routine is used to start up a session with the database manager. The
caller will either provide a pre-existing database filename & path or
the name & path to be used for a new database file.  The access parameter is used
to indicate what type of access to the database file the caller wants. The
blocksize parameter is used when creating a new database file to configure
the sized blocks that are allcoated by the db mgr when extending the file. If the
file already exists, then this field will be ignored.

If an error occurs, no new session will be created, and an appropriate
error code will be returned.

parameters
	db_session (in/out) = ptr to storage for session parameter for a newly
		created session with the db manager. Once the session is connected
		to a particular file, all operations with that file must be accompanied
		by the session parameter. (all future calls to the db manager).
		(caller provides storage for a ulong, which will be filled in by this
		routine if everything goes well).

	filepath (input) = the path to an existing db file, or path where a new
		db file will be created (path does not include the filename itself).
		The path must have an ending "/" or ":" or whatever it is that
		your particular file system uses.  (null terminated C string)

	filename (input) = the filename of an existing db file, or name for a new
		db file. (null terminated C string)

	access (input) = access type flags {DB_READ, DB_WRITE, DB_RDWR, DB_NEW}
		DB_READ - open an existing db file for read only access.

		DB_WRITE - open an existing db file for write only access.

		DB_RDWR - open an existing db file for read and write access.

		DB_NEW - If file doesn't exist, create new.  If file already
			exists, report error. (New opened with read and write access.)

	blocksize (input) = the db file is created in multiple chunks of size
		"blocksize" bytes.  Depending on the type of data being stored, this
		value can be tailored to best serve the situation.  If this value is
		less than the default value, then the blocksize will be set to the
		default value DB_BLOCK_SIZE.  If the file already exists, this field
		is ignored.

returns:
	one of the following error codes will be returned

	DB_NO_ERR			- everything fine
	DB_BAD_PARAM		- bad parameter passed to this routine
	DB_EXISTS			- file already exists (can't create new )
	db_Open_ERR			- named db file not found
	DB_READ_ERR			- file read i/o error
	DB_WRITE_ERR		- file write i/o error
	DB_NOT_DB_FILE		- given file is not a database file
	DB_SEEK_ERR			- file seek error (locating dir/storage table )
	DB_NO_MEM			- out of memory
	DB_DATABASE_EMPTY	- when open for read only, and no data exists yet


General Notes:
	It is forseen that in our particular case, we don't have to worry about
	more than one program trying to access the same file - otherwise
	synchronization problems would crop up....the session info would have
	to be tracked differently than is done here.

---------------------------------------------------------------------------
*/

static short dbV2_open(ulong *db_session, char *filename, long access,
long blocksize)
{
	DB_Session_StructV2	*session;
	db_file_header		partial_header;	 /* to verify file type */
	short				err;
	long				length, num_bytes, file_pos;
	ulong				index;
	char				*tempname;		/* temp used when creating/opening file */
	char	*tmpPtr = NULL;

	if((db_session == NULL) || (filename == NULL) )
		return(DB_BAD_PARAM);

	db_lock();
	err = DB_NO_ERR;	/* start out ok */
	/* try to have legal values for blocksize - although we don't
	 * check for a max at this time....
	 */
	if(blocksize < DB_BLOCK_SIZE)
		blocksize = DB_BLOCK_SIZE;

	/* init caller storage to indicate that no session exists yet
	 * in case we fail.
	 */
	*db_session = (ulong) NULL;

	/* allocate storage for this session */
	session = (DB_Session_StructV2 *) malloc(sizeof(DB_Session_StructV2));

	/* check for storage */
	if(session == NULL)
	{
		db_unlock();
		return(DB_NO_MEM);
	}

	/* set fields to empty values to start with (in case we run into
	 * errors and need to clean up before exiting )
	 */
	session->name = NULL;
	session->path = NULL;
	session->dbheader = NULL;
	session->dir_table  = NULL;
	session->cached_blocks = NULL;
	session->cache_size = 0;
	session->storage_map = NULL;
	session->current_cache_entry = NULL;

	/* record the caller's provided name and path of the file. */
	session->name = (char *) calloc (1, strlen(filename) + 1);
	if (session->name == NULL)
	{
		db_unlock();
		free (session);	 /* no mem left, tell caller */
		return(DB_NO_MEM);;
	}
	(void) strcpy (session->name, filename);

	/* create the full name of the file - pathname+filename */
	tempname = filename;

	/* Open the file. (NOTE: even if the caller specifies write only, we must
	 * open the file with read allowed so that we can handle housekeeping type
	 * stuff.)
	 */
	if (access == DB_READ)  /* read only , all writes will fail, can share reads */
		session->file = thread_open (tempname, O_RDONLY | O_BINARY, -1);  /* need unix mode? */

	else if (access == DB_WRITE)	/* write, single entity has exculsive access */
		session->file = thread_open (tempname, O_RDWR | O_BINARY, -1); /* need unix mode? */

	else if (access == DB_NEW)	/* create new,  read & write */
	{
		/* O_EXCL didn't appear to be supported on my platform, so what
		 * I will do here is try to open the file read only, and if
		 * the file does not open we will know it does not exist yet.
		 * If it does open, we will close it and tell the caller that
		 * the file alread exists.
		 */
		session->file = thread_open(tempname, O_RDONLY | O_BINARY, -1);
		if(session->file != -1) /* if we didn't fail */
		{
			/* then the file already exists, close it */
			close(session->file);
			free(session->name);   /* no mem left, tell caller */
			free(session->path);
			free(session);
			return(DB_EXISTS);
		}

#ifdef _WINDOWS
		session->file = thread_open (tempname, O_RDWR|O_CREAT|O_EXCL|O_BINARY,
			_S_IWRITE | _S_IREAD);
#elif defined (_UNIX)
				/* satisfy unix systems.... */
				session->file = thread_open (tempname, O_RDWR|O_CREAT|O_EXCL|O_BINARY,
			S_IWRITE | S_IREAD); /*  need unix mode */

#else /* not _WINDOWS  */
		session->file = thread_open (tempname, O_RDWR|O_CREAT|O_EXCL|O_BINARY, -1);
#endif
		if(session->file == -1) /* if we didn't fail */
			/* then the file already exists, close it */
			err = DB_EXISTS;

		access = DB_RDWR;
		length = 0;		 /* no data yet, we will init header */
	}
	else if(access == DB_RDWR) /* existing file, open read & write  */
	{
		session->file = thread_open (tempname, O_RDWR | O_BINARY, -1);

	}
	else
	{
		/* illegal flag used */
		free(session->name);

		free(session);
		db_unlock();
		return(DB_BAD_PARAM);   /* tell caller */

	}


	/* see if we were able to create the file or open it */
	if ((session->file < 0) || (err != DB_NO_ERR))
	{
		/* free up allocated memory */
		free (session->name);
			free(session->path);
		free (session);
		db_unlock();
		/* tell caller what happened */
		if(err != DB_NO_ERR)
			return(err);	/* the already exists creation error */

		return(DB_OPEN_ERROR);  /* generic problems opening error */
	}

	/* If the file has been opened for read only access, check to
	 * see if there is any data in the file yet, if not we will
	 * report that as an error.
	 */

	/* do a seek to end */
	length = lseek(session->file, 0, SEEK_END);
	if (access == DB_READ)
	{
		if(length <= 0)
		{
			close (session->file);
			/* free up allocated memory */
			free (session->name);
				free(session->path);
			free (session);
			db_unlock();
			return  DB_DATABASE_EMPTY;	/* tell caller what happened */
		}
	}
	/* Get a FILE Pointer */
#if defined(WIN32)
	session->fileStream = _fdopen(session->file, "wb+");
#else
	session->fileStream = fdopen(session->file, "wb+") ;
#endif
	/* go back to the begining */
	(void) lseek(session->file, 0, SEEK_SET);

	/* Remember what access permission the caller asked for */
	session->access = access;

	/* Check to see if we just created a new file, or we have
	 * opened an empty old one (that isn't read only).
	 */
	if (length == 0)
		{
		/* We must init the data base for new files  */

		/* allocate space for the file header information. */
		session->dbheader = (db_file_headerV2 *) malloc (blocksize);
		if (session->dbheader == NULL)
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return DB_NO_MEM;
		}

		/* Set up the header fields. tracks the free space in the file,
		 * and the location of the hashed dir/index info
		 */

		/*
		 * The following line was saved for historical purposes
		 * The new data base is DBX1, which normalizes the DN's
		 *
		 * session->dbheader->header_ident = 0x44425858;
		 */
		session->dbheader->header_ident = DATA_BASE_HEADER_VERSION2; /* "DBX2" so we know it's ours */
		session->dbheader->block_size = blocksize;

		/* Start with an initial hash table  */
		/* for 8 entries we require 3 bits to distinguish between them.
		 * Increase the bits for each jump up in the provided block size.
		 *
		 * One long for each block tracked by the dir_table array, each is the
		 * file offset to the storage block.
		 */
		session->dbheader->dir_size = 8 * sizeof (long);	/* 8 entries (one long each) */
		session->dbheader->dir_bits = 3;
	  		/* 'address' bits in the table */
		while (session->dbheader->dir_size < session->dbheader->block_size)
		{
			session->dbheader->dir_size <<= 1;	/* double for each bit increase */
			session->dbheader->dir_bits += 1;
		}

		/* make sure our directory size calculation above is correct */
		if (session->dbheader->dir_size != session->dbheader->block_size)
		{
			(void) dbV2_close  ((ulong *) &session);
			db_unlock();
			return(DB_BLOCK_SIZE_ERR);
		}

		/* allocate memory for the directory index array. */
		session->dir_table = (long *) malloc (session->dbheader->dir_size);
		if (session->dir_table == NULL)
		{
			(void) dbV2_close  ((ulong *) &session);
			db_unlock();
			return(DB_NO_MEM);
		}
			session->dbheader->dir_location = session->dbheader->block_size;

		/* allocate a temporary hash storage table so that we can store
		 * an initial storage_map in the db file .
		 * NOTE: the value of max_store_elems is one greater than the amount
		 * we can fit, so that when we check during addition of a new items
		 * we can skip adding one during comparisons.
		 */
		session->dbheader->max_store_elems =
			(session->dbheader->block_size - sizeof(storage_tableV2))
			/ sizeof (storage_elementV2) + 1;

		session->storage_map = (storage_tableV2 *) (malloc
					(session->dbheader->block_size));


		if (session->storage_map == NULL)
		{
			(void) dbV2_close  ((ulong *) &session);
			db_unlock();
			return(DB_NO_MEM);
		}

		/* set up the new storage_map with default nothing stored values */
		dbuV2_init_storagetable (session, session->storage_map, 0);

		session->storage_map->av_count = 1;		 /* 1 available entry */

		/* set size of the available block and it's file location (offset) */
		session->storage_map->storage_avail[0].avail_floc =
					3*session->dbheader->block_size;
		session->storage_map->storage_avail[0].avail_size =
					session->dbheader->block_size;

		/* Set up the table entries so they point to the
		 * initial storage_map block.
		 */
		for (index = 0; index < (session->dbheader->dir_size / sizeof(long)); 
			index++)
			session->dir_table[index] = 2*session->dbheader->block_size;

		/* Initialize the active available block. */
		session->dbheader->avail.size = ((session->dbheader->block_size -
			sizeof (db_file_header)) / sizeof (avail_elemV2)) + 1;

		session->dbheader->avail.count = 0;
		session->dbheader->avail.next_block = 0;

		/* the next free block will be the one following the file header block,
		 * plus the initial index of directory blocks, plus the 1st dir block
		 * plus the 1st avail block.
		 */
		session->dbheader->next_block  = 4*session->dbheader->block_size;

		/* Now write out the initial configuration to the file.
		 * Block 0 is the file header and active avail block.
		 */
		if (SRLisLittleEndian())
		{
			tmpPtr = LE_PrepLongs((long *) (session->dbheader), session->dbheader->block_size);
			if(tmpPtr != 0)
			{
				num_bytes = thread_write (session->file, session->fileStream, tmpPtr, session->dbheader->block_size);
				free(tmpPtr);
			}
			else
				num_bytes = 0;	/* ran out of mem... */

		}
		else
			num_bytes = thread_write (session->file, session->fileStream,(char *)(session->dbheader), session->dbheader->block_size);

		if (num_bytes != session->dbheader->block_size)
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_WRITE_ERR);
		}

		/* Block 1 is the initial storage directory. (index of hashed table items) */
		if (SRLisLittleEndian())
		{
			tmpPtr = LE_PrepLongs(session->dir_table, session->dbheader->dir_size);
			if(tmpPtr != 0)
			{
				num_bytes = thread_write (session->file, session->fileStream, tmpPtr, session->dbheader->dir_size);
				free(tmpPtr);
			}
			else
				num_bytes = 0;	/* ran out of mem... */

		}
		else
		{
			num_bytes = thread_write (session->file, session->fileStream, (char *)(session->dir_table),
								session->dbheader->dir_size);
		}

		if (num_bytes != session->dbheader->dir_size)
		{
			(void) dbV2_close  ((ulong *) &session);
			db_unlock();
			return(DB_WRITE_ERR);
		}

		/* Block 2 gets the initial storage table */
		if (SRLisLittleEndian())
		{
			tmpPtr = LEV2_PrepStorageMap(session->storage_map, session->dbheader->block_size);
			if(tmpPtr != 0)
			{
				num_bytes = thread_write (session->file, session->fileStream, tmpPtr, session->dbheader->block_size);
				free(tmpPtr);
			}
			else
				num_bytes = 0;	/* ran out of mem... */

		}
		else
			num_bytes = thread_write (session->file,session->fileStream, (char *)(session->storage_map),
								session->dbheader->block_size);

		if (num_bytes != session->dbheader->block_size)
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_WRITE_ERR);
		}

		/* Make sure that the initial configuration has been written out
		 * to disk.
		 */
		/* fsync (session->file); unistd.h  */

		/* free up the temp storage table memory */
		free (session->storage_map);
		session->storage_map = NULL;

	}
	else
	{
		/* else the file already existed, and now we have it open.
		 * Read in the header information for this db file and
		 * start up the directory index.
		 */

		/* Start off by reading in just enough to determine if we
		 * are reasonably sure it's our file type.  (we don't
		 * read the avail table till we are sure it's our file type
		 * and we know what block size was used for this file).
		 */
		num_bytes = thread_read (session->file,(char *) &partial_header,
			sizeof (db_file_header));

		if (SRLisLittleEndian())
		{
				tmpPtr = LE_PrepLongs((long *) &partial_header, sizeof (db_file_header));
			if(tmpPtr != 0)
			{
				/* just directly copy it back into the struct */
				memcpy((char *) &partial_header, tmpPtr, sizeof (db_file_header));
				free(tmpPtr);
				tmpPtr = 0;	/* not used now */
			}
			else num_bytes = 0;
		}

		if (num_bytes != sizeof (db_file_header))
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_READ_ERR);
		}
		/* check to see if it's our file type */
		if ((partial_header.header_ident != DATA_BASE_HEADER_VERSION_OLD) &&
			(partial_header.header_ident != DATA_BASE_HEADER_VERSION1) &&
			(partial_header.header_ident != DATA_BASE_HEADER_VERSION2))
		{ 
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_NOT_DB_FILE);
		}

		/* allocate storage, then read the rest of the first block. */
		session->dbheader = (db_file_headerV2 *) malloc
			(partial_header.block_size);
		if (session->dbheader == NULL)
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_NO_MEM);
		}

		/* copy over what we already read in (the file header) */
		memcpy (session->dbheader, &partial_header, sizeof
			(db_file_header));

		/* read in the rest of the block (active avail block) */
		num_bytes = thread_read (session->file,(char *)
			&session->dbheader->avail.av_table[1],
			session->dbheader->block_size-sizeof
			(db_file_header));

		if (SRLisLittleEndian())
		{
			SRLi_FlipLongs((&session->dbheader->avail.av_table[1]),
				 (session->dbheader->block_size-sizeof (db_file_header)) >> 2);
		}

		if ((ulong)num_bytes != 
			(session->dbheader->block_size - sizeof(db_file_header)))
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_READ_ERR);
		}

		/* allocate memory for the hash directory array.  */
		session->dir_table = (long *) malloc(session->dbheader->dir_size);
		if (session->dir_table == NULL)
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_NO_MEM);
		}

		/* read in the saved directory index array. */
		file_pos = lseek (session->file, session->dbheader->dir_location, SEEK_SET);

		/* make sure we got there */
		if (file_pos != session->dbheader->dir_location)
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_SEEK_ERR);
		}

		num_bytes = thread_read (session->file, (char *) session->dir_table,
			session->dbheader->dir_size);


		if (SRLisLittleEndian())
			SRLi_FlipLongs((session->dir_table),session->dbheader->dir_size >> 2);


		if (num_bytes != session->dbheader->dir_size)   /* was it all available */
		{
			(void) dbV2_close ((ulong *) &session);
			db_unlock();
			return(DB_READ_ERR);
		}

	}

	/* db file is now open, make sure we set up everything
	 * to reflect that we just opened it, nothing cached yet,
	 * not modified yet, etc.
	 */

	session->idx_of_last_read = -1;		/* no cached storage table entries yet */
	session->storage_map = NULL;		/* no current entries read */
	session->storage_map_dir = 0;		/* no corresponding dir entry for storage yet */
	session->current_cache_entry = NULL;	/* no current block cache entry */
	session->dbheader_changed = FALSE;		/* nothing has been modified yet....*/
	session->directory_changed = FALSE;
	session->cur_cache_changed = FALSE;
	session->second_changed = FALSE;

	/* give caller their session/context ref value */
	*db_session = (ulong) session;

	/* tell caller that everything went fine */
	db_unlock();
	return(DB_NO_ERR);

}


/*
---------------------------------------------------------------------------

dbV2_close()

short dbV2_close(ulong db_session)

This routine is used to close a session with the database manager.  The file
associated with the session will be closed, and any memory used by the session
will be free'd up.  Any cached data/changes will be recorded before closing
by this routine.

parameters:
	db_session (input) = ptr to the session parameter that was returned from a
		call to db_Open().  This will be NULL'd out after closing so the
		caller doesn't try using it in any future calls.

returns:
	one of the following error codes will be returned

	DB_NO_ERR		 - everything fine
	DB_BAD_PARAM	- bad parameter passed to this routine

General Notes:
	The session id will no longer be valid, so if passed in any calls to
	the db mgr after closing, will be reported as a non-existing session.

---------------------------------------------------------------------------
*/

short dbV2_close (ulong *db_session)
{
	DB_Session_StructV2	 *session;
	long				index;

	/* check for legal params */
	if(db_session == NULL)
		return(DB_BAD_PARAM);
	session = (DB_Session_StructV2 *) (*db_session);

	/* NULL out so caller doesn't try using it after we close */
	*db_session = 0;

	/* If the file was set up for writing (or read and write)
	 * make sure that the database is all on disk.
	 */
/*	if ((session->access == DB_WRITE) || (session->access == DB_RDWR))
		fsync (session->file);  unistd.h  */

	/* now that we are sure that the file reflects what's in
	 * memory, close down the file and release the memory
	 * we allocated assocated with this session.
	 */
	close(session->file);

	free(session->name);
		free(session->path);

	if (session->dir_table != NULL) free (session->dir_table);

	/* free up any cached chunks, if we have any */
	if (session->cached_blocks != NULL)
	{
		for (index = 0; index < session->cache_size; index++)
		{
			/* free the storage table info for this element */
			if (session->cached_blocks[index].ca_block != NULL)
				free (session->cached_blocks[index].ca_block);

			/* and free up the corresponding cached data element */
			if (session->cached_blocks[index].ca_data.dptr != NULL)
				free (session->cached_blocks[index].ca_data.dptr);
		}
		/* free up the array for this cache list */
		free (session->cached_blocks);
	}
	/* free up the file information header */
	if ( session->dbheader != NULL ) free (session->dbheader);

	/* and finally the session context (structure) itself */
	free (session);

	/* all done here */
	return(DB_NO_ERR);
}





/*
---------------------------------------------------------------------------

dbV2_GetEntry()

short dbV2_GetEntry(ulong db_session, DB_Kid *kid, DB_Data **data)

This routine is used to get a particular entry from the database associated
with the indicated session.  The entry is identified by the key entry info,
the data for that item will be placed into a new allocated memory block which
the caller will have to free up at some time. (DB_Data structure allocated
and filled in).

Parameters:
	db_session (input) = the session parameter that was returned from a
		call to db_Open().

	kid (input) = the keying identifier (info used to represent the data that
		is to be retrieved.)

	data (in/out) = ptr storage, will point to retrieved data in DB_Data on
		sucessful completion.


returns:
	one of the following error codes will be returned

	DB_NO_ERR		- everything fine
	DB_NO_MEM		- out of memory
	DB_BAD_PARAM	- bad parameter passed to this routine
	DB_BAD_KID		- bad keying identifier
	DB_NOT_FOUND	- no entry for given key info found in database
	DB_NO_READ		- db file not open for reading

---------------------------------------------------------------------------
*/

short dbV2_GetEntry(ulong db_session, DB_Kid *kid, DB_Data **data)
{
	DB_Data			 *foundData = NULL;
	DB_Session_StructV2	 *session;
	long				elem_loc;		 /* The location in the storage_map. */
	char				*find_data;		 /* Returned from find_key. */
	long				hash_val;		 /* Returned from find_key. */
	DB_INFO_Struct		*info = NULL;
	if((db_session == 0) || (kid == NULL) || (data == NULL))
		return(DB_BAD_PARAM);

	if((kid->item_ptr == NULL) || (kid->item_len <= 0))
		return(DB_BAD_KID);

	*data = NULL;   /* start the caller with nothing */
	db_lock();
	/* get the session ref value */
	session = (DB_Session_StructV2 *) db_session;

	/* make sure the caller has read access */
	if(session->access == DB_WRITE) /* basically write only is only non read type */
		return(DB_NO_READ);

	/* allocate our storage for found data */
	foundData = (DB_Data *) calloc(1, sizeof(DB_Data));
	if(foundData == NULL)
	{
		db_unlock();
		return(DB_NO_MEM);
	}

	/* start out with no data found */
	foundData->item_ptr  = NULL;
	foundData->item_len = 0;

	find_data = NULL;	 /* start out empty */

	/* search for the kid - get the index of it's element entry in the
	 * current block, plus get a ptr to it's data and it's hash value.
	 */
	elem_loc = dbuV2_findkey (session, kid, &find_data, &hash_val, NORMALIZED);

	if(elem_loc < 0)	/* did an error occur */
	{
			elem_loc = dbuV2_findkey (session, kid, &find_data, &hash_val, NOT_NORMALIZED);
		dbV2_FreeDBInfo(&info);
		info = NULL;
		if (elem_loc < 0)
		{
			free(foundData);
			db_unlock();
			return (short)elem_loc;	 /* tell caller we failed (not found or 
									other err) */
		}

	}

	/* Found the matching entry, copy the data from the
	 * cache area to new storage for caller use.
	 */
	foundData->item_len = session->storage_map->se_table[elem_loc].data_size;

	/* check to insure that there is indeed data assocated with this
	 * entry.
	 */
	if(foundData->item_len == 0)
	{
		/* for some reason there is no data assocated with this key,
		 * but the key is in the db file..... (perhaps due to an
		 * error on write...)
		 */
		free(foundData);
		db_unlock();
		return(DB_NOT_FOUND);   /* should we indicate otherwise? */
	}

	foundData->item_ptr = (char *) malloc (foundData->item_len);

	if (foundData->item_ptr == NULL)
	{
		free(foundData);
		db_unlock();
		return(DB_NO_MEM);
	}

	/* copy it from the given ref to new storage */
	memcpy ( foundData->item_ptr, find_data, foundData->item_len);

	/* give caller access to the structure */
	*data = foundData;
	db_unlock();
	return(DB_NO_ERR);	/* tell caller we succeeded */

}




/*
---------------------------------------------------------------------------

dbV2_GetFirstKid()

short dbV2_GetFirstKid(ulong db_session, DB_Kid **kid)

This routine will return the keying identifier for the first entry in the
database associated with the given session.  One would use this routine
followed by dbV2_GetNextKid() to sequencially step through the items in
the database. The caller get's their own copy of the kid, and should
free it's data up and the structure after they are done with it.

NOTE: The items in the database are not necessarily in any particular order.

Paramters:
	db_session (input) = the session parameter that was returned from a
		call to db_Open().

	kid (input/output) = ptr to storage for the keying identifier for the
		first entry in the database (info used to represent the data.) If
		there is no first entry in the database, then kid will be null.


returns:
	one of the following error codes will be returned

	DB_NO_ERR		 - everything fine
	DB_BAD_PARAM	- bad parameter passed to this routine

	DB_NOT_FOUND	- no entry for given key info found in database
	DB_NO_READ		- db file not open for reading

NOTE: If the caller wanted the actual data associated with any of the keys
returned, they would then make a call to dbV2_GetEntry() using the kid returned
from their call.
---------------------------------------------------------------------------
*/
short dbV2_GetFirstKid(ulong db_session, DB_Kid **kid)
{
	DB_Session_StructV2	 *session;
	DB_Kid			  *theKeyID;
	short			   err = DB_NO_ERR;

	/* check the paramters */
	if((db_session == 0) || (kid == NULL))
		return(DB_BAD_PARAM);

	// Lock the data base 
	db_lock();


	*kid = NULL;	/* init to empty in case we fail */

	/* get the session ref value */
	session = (DB_Session_StructV2 *) db_session;

	/* allocate storage */
	theKeyID = (DB_Kid *) malloc(sizeof (DB_Kid));
	if(theKeyID == NULL)
	{
		err =DB_NO_MEM;
		goto done;
	}

	theKeyID->item_ptr = NULL;
	theKeyID->item_len = 0;


	/* Make sure that we start searching with the 1st directory/index
	 * entry loaded (ie dir_table[0] )
	 */
	err = dbuV2_get_block (session, 0);
	if(err != DB_NO_ERR)
		goto done;	/* tell caller we failed */

	/* Get the kid for the first entry using dbuV2_get_next_kid
	 *  (-1 => next entry after -1 is entry 0)
	 * We get our own copy if it is found.
	 */
	err = dbuV2_get_next_kid (session, -1, theKeyID);
	if(err != DB_NO_ERR)
	{
		free(theKeyID);
		goto done;
	}

	/* make sure things worked out */
	if((theKeyID->item_ptr == NULL) || (theKeyID->item_len == 0))
	{
		free(theKeyID);
		err = DB_NOT_FOUND;
		goto done;   /* evidently an empty database... */
	}

	/* found it, give it to caller */
	*kid = theKeyID;
done:
	db_unlock();
	return(err);
}


/*
---------------------------------------------------------------------------

dbV2_GetNextKid()

short dbV2_GetNextKid(ulong db_session, DB_Kid *kid, DB_Kid **next_kid)

This routine is used to "walk" through the entries in the database.  Calling
dbV2_GetFirstKid() will return keying information for the first entry, and
then the caller would use dbV2_GetNextKid() to access each suceeding entry
in the database.  The caller get's their own copy of the keying identifier
data, so once they no longer need the kid, they should free up the data and
the kid structure.

NOTE: If the caller wanted the actual data associated with any of the keys
returned, they would then have to make a call to dbV2_GetEntry() using the kid
returned from their call.


Paramters:
	db_session (input) = the session parameter that was returned
		 from a call to db_Open().

	kid (input) = the keying identifier for the entry in the
		database that is the precursor to the one you want.

	next_kid (input/output) = ptr storage for the keying identifier for
		the next entry in the database If there is no next entry, then
		next_kid will be set to NULL, and the error flag will be
		DB_NOT_FOUND.


returns:
	one of the following error codes will be returned

	DB_NO_ERR		 - everything fine
	DB_BAD_PARAM	- bad parameter passed to this routine
	DB_NOT_FOUND	- no entry for given key info found in database
	DB_NO_READ		- db file not open for reading

	other error codes from subroutines are also passed back

---------------------------------------------------------------------------
*/
short dbV2_GetNextKid(ulong db_session, DB_Kid *kid, DB_Kid **next_kid)
{
	DB_Session_StructV2	 *session;
	DB_Kid	  *nextkeyID;
	DB_INFO_Struct		*info = NULL;

	long		elem_loc;		 /* The location in the storage_map. */
	char		*find_data;		 /* Data pointer returned by dbuV2_findkey. */
	long		hash_val;		 /* Returned by dbuV2_findkey. */
	short	   err = DB_NO_ERR;

	/* check the paramters */
	if((db_session == 0) || (kid == NULL) || (next_kid == NULL))
		return(DB_BAD_PARAM);

	if((kid->item_ptr == NULL) || (kid->item_len <= 0))
		return(DB_BAD_KID);

	db_lock();
	/* init caller's to empty in case we don't find a next one */
	*next_kid = NULL;

	/* get the session ref value */
	session = (DB_Session_StructV2 *) db_session;

	/* allocate storage */
	nextkeyID = (DB_Kid *) malloc(sizeof (DB_Kid));
	if(nextkeyID == NULL)
	{
		db_unlock();
		return DB_NO_MEM;
	}

	nextkeyID->item_ptr = NULL;
	nextkeyID->item_len = 0;


	/* start out by finding the given precursor kid
	 * (and make sure it exists).
	 */
	elem_loc = dbuV2_findkey (session, kid, &find_data, &hash_val, NORMALIZED);

	/* see if we found one */
	if (elem_loc < 0) /* not found, or other err */
	{
		(void) dbV2_Info((ulong)session, &info);
		if (info->data == DATA_BASE_HEADER_VERSION_OLD)
		/* Try Non Normalized version */
			elem_loc = dbuV2_findkey (session, kid, &find_data, &hash_val,
								NOT_NORMALIZED);
		dbV2_FreeDBInfo(&info);
		info = NULL;
		if (elem_loc < 0)
		{
			db_unlock();
			return (short)elem_loc; /* Not found or other error */
		}

	}

	/* Now get the next kid. (we will get a copy if found) */
	err = dbuV2_get_next_kid(session, elem_loc, nextkeyID);

	if(err != DB_NO_ERR)
	{
		free(nextkeyID);
		db_unlock();
		return(err);
	}

	/* did we find one ? */
	if((nextkeyID->item_ptr == NULL) || (nextkeyID->item_len <= 0))
	{
		free(nextkeyID);	/* nothing found, clean up */
		db_unlock();
		return(DB_NOT_FOUND);
	}
	db_unlock();
	/* found it, give it to the caller */
	*next_kid = nextkeyID;

	return(DB_NO_ERR);
}


/*
---------------------------------------------------------------------------

dbuV2_get_next_kid()

static void dbuV2_get_next_kid (DB_Session_StructV2 *db_session,long elem_loc,
	 DB_Kid *return_kid)

This low level routine is used to find and read the next entry in the
storage table for the sessions database starting at the given element
location of the current cached storage block.  Since the caller get's their
own COPY of the keying identifier data, they should free up the storage when
they are done with it.

Parameters:

	db_session (input) = the session parameter that was returned from a
		call to db_Open().

	elem_loc (input) = the currently addressd element for which the caller
		wants the following elements kid.

	return_kid	(input) = ptr to kid structure which will be filled in
		with the kids length and data upon success.


returns:
	one of the following error codes will be returned

	DB_NO_ERR		 - This routine indicates sucess thru it's setting
		the fields of "return_kid".  If "return_kid" is not filled in, then
		the next element was not available, but this is still considered
		to be DB_NO_ERR since it's not fatal.

	if other than not found happens (bad errors) the appropriate error
	codes will be returned.

	DB_NO_MEM			 - out of memory

	other codes may be returned by subroutines.

---------------------------------------------------------------------------
*/


static short dbuV2_get_next_kid (DB_Session_StructV2 *db_session,long elem_loc, DB_Kid *return_kid)
{
	long   found;		   /* Have we found the next key. */
	char  *find_data;		 /* Data pointer returned by find_key. */
	short   err;

	return_kid->item_ptr = NULL;	/* init to not found state */
	return_kid->item_len = 0;

	/* go find the next non-empty element in the storage block. */
	found = FALSE;

	while (!found)  /* loop till we find one, or run out of db entries */
	{
		/* Advance to the next entry location in the storage block. */
		elem_loc++;

		/* check to see if we hit the end of current block */
		if (elem_loc == db_session->dbheader->max_store_elems)
		{
			/* we scanned to the end of the current storage block,
			 * time to make the dounuts, I mean load the next one
			 * if any.
			  */
			elem_loc = 0;   /* want 1st of next block */

			/* Get the next block.  It is possible several entries in
			 * the index directory point to the same block file offset, so
			 * move foreward past the last cached block we had.
			 */
			while (((ulong)db_session->storage_map_dir < 
				(db_session->dbheader->dir_size / sizeof(long)))
				&& (db_session->current_cache_entry->ca_adr ==
				db_session->dir_table[db_session->storage_map_dir]))
			{
				/* inc dir table index */
				db_session->storage_map_dir++;
			}
			/* now check to see if there exists a storage block for
			 * this next directory table entry. (haven't passed the end)
			 */
			if ((ulong)db_session->storage_map_dir < 
				(db_session->dbheader->dir_size / sizeof(long)))
			{
				 /* load the block */
				err = dbuV2_get_block (db_session, db_session->storage_map_dir);
				if(err != DB_NO_ERR)
					return(err);	/* tell caller we failed */
			}
			else
				/* no more blocks, hit the end, return to caller */
				return(DB_NO_ERR) ;
		}
		/* see if there is an entry in the current storage
		 * block at elem_loc index
		 */
		found = db_session->storage_map->se_table[elem_loc].hash_value != -1;
	}

	/* we found the next entry, make sure it's loaded/cached,
	 * then read its kid into return_kid.
	 */
	err = dbuV2_read_entry (db_session, elem_loc, &find_data);
	if(err != DB_NO_ERR)
		return(err);

	return_kid->item_len = db_session->storage_map->se_table[elem_loc].kid_size;
	if (return_kid->item_len == 0)
		return(DB_NO_ERR);	/* nothing to give caller */

	return_kid->item_ptr = (char *) malloc (return_kid->item_len);

	if (return_kid->item_ptr == NULL)
	{
		return_kid->item_len = 0;
		return(DB_NO_MEM);	/* tell caller */
	}

	/* give the caller their own copy of the kid data */
	memcpy (return_kid->item_ptr, find_data, return_kid->item_len);

	return(DB_NO_ERR);
}



/*
---------------------------------------------------------------------------

dbV2_Info()

short dbV2_Info(ulong db_session, DB_INFO_Struct **info)

This routine is used to get information about the db manager and the file
associated with a particular session.

Paramters:
	db_session (input) = the session parameter that was returned from a
		call to db_Open(), associated with the a db file.

	info (input/output) = ptr storage, informational struct allocated
		and filled in by this routine.

		info.version = version of this implemenation of the db

		info.entries = number of entrys in database (stored items)

		info.maxkids = max number of cached kids (keying identifiers )

		info.cachekids = number of currently cached kids

returns:
	one of the following error codes will be returned

	DB_NO_ERR		 - everything fine
	DB_BAD_PARAM	- bad parameter passed to this routine

---------------------------------------------------------------------------
*/

/* Figure out what we will do with this routine later */
short dbV2_Info(ulong db_session, DB_INFO_Struct **info)
{
	DB_Session_StructV2	*session_ptr;
    DB_INFO_Struct      *DB_info_ptr;
	if(db_session == 0)
		return(DB_BAD_PARAM);
	/* just set up so caller doesn't think we have given them
	 * anything useful.
	 */
	session_ptr = (DB_Session_StructV2 *)db_session;
	DB_info_ptr = (DB_INFO_Struct *)calloc (1, sizeof (DB_INFO_Struct));
	DB_info_ptr->data = session_ptr->dbheader->header_ident;
	*info = DB_info_ptr;
	return(0);


}


/*
---------------------------------------------------------------------------

dbV2_FreeDBInfo()

void dbV2_FreeDBInfo(DB_INFO_Struct **info)

This routine is used to free db information.

Paramters:
	info (input) = ptr storage, informational struct allocated
		and filled in by this routine.

		info.version = version of this implemenation of the db

		info.entries = number of entrys in database (stored items)

		info.maxkids = max number of cached kids (keying identifiers )

		info.cachekids = number of currently cached kids

---------------------------------------------------------------------------
*/
void dbV2_FreeDBInfo(DB_INFO_Struct **info)
{
	if ((info == NULL) || (*info == NULL))
		return;

	free(*info);
}


/* ---------------------------------------------------------------------------
 *
 * The db utility routines - used internally by the db_ routines, not for
 * use outside the library.
 *
dbuV2_alloc()
dbuV2_free()
dbuV2_pop_avail_block()
dbuV2_push_avail_block()
dbuV2_get_avail_elem()
dbuV2_put_avail_elem()
dbuV2_allocate_block()
dbuV2_adjust_storage_avail()
dbuV2_init_storagetable()
dbuV2_init_cache()
dbuV2_get_block()
dbuV2_split_storageTable()
dbuV2_write_block()
dbuV2_write_header()
dbuV2_end_update()
dbuV2_read_entry()
dbuV2_hash()
dbuV2_findkey()
dbuV2_get_next_kid()

 * ---------------------------------------------------------------------------
 */

/*
---------------------------------------------------------------------------

dbuV2_free()

static void dbuV2_free (DB_Session_StructV2 *session,long file_adr,long num_bytes)

This low level routine is used to free up space of size num_bytes in the
sessions database file, starting at file offset "file_adr".  The space
freed is recorded into the availability table so that it can be re-used
in the future.  Depending on the size of the amount freed, and the status
of the current storage table, the space may be put into either the
current storage tables avail table or the file headers avail table. If
the space is larger than a file block size, the we will add it to the
files header avail table. If smaller than a full file block size, we will
attempt to add it to the current storage tables avail table (if it's
not already maxed out on avail entries).

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

	file_adr (input) = the file offset to the space being freed

	num_bytes (input) = size in bytes of the space being freee.

returns:
	one of the following error codes will be returned

	DB_NO_ERR
	DB_SEEK_ERR
	DB_WRITE_ERR

---------------------------------------------------------------------------
*/

static short dbuV2_free (DB_Session_StructV2 *session,long file_adr,long
num_bytes)
{
	avail_elemV2	temp;
	short	   err;

	/* See if the amount being freed should be ignored
	 * (it's so small that housekeeping for it is not
	 * worth it)
	 */
	if (num_bytes <= IGNORE_SIZE)
		return(DB_NO_ERR);

	/* Set up our temp avail element with the caller's
	 * indicated parameters.
	 */
	temp.avail_size = num_bytes;
	temp.avail_floc = file_adr;

	/* Check to see if the amount is greater than or equal to
	 * a file block sized chunk, if so we will add it to the
	 * files header avail table.
	 */
	if (num_bytes >= session->dbheader->block_size) /* of at least block size */
	{
		/* see if the avail table is full (number of avail elements maxed out).
		 * if so we need to split it, and save out so that we can add more
		 * to the table.
		 */
		if (session->dbheader->avail.count == session->dbheader->avail.size)
		{
			err = dbuV2_push_avail_block (session);   /* split & save it out to disk */
			if(err != DB_NO_ERR)
				return(err);	/* tell caller we failed */
		}

		/* at this point there is room to add another avail element */
		dbuV2_put_avail_elem (temp, session->dbheader->avail.av_table,
			&session->dbheader->avail.count);

		session->dbheader_changed = TRUE;	 /* we modified it */
	}
	else	/* free'ing up less than a block in size */
	{
		/* we will try to put into the current storage block's avail table . */
		if (session->storage_map->av_count < MAX_AVAIL) /* if not maxed out yet */
			dbuV2_put_avail_elem (temp, session->storage_map->storage_avail,
				&session->storage_map->av_count);
		else
		{
			/* else no room in current storage avail table, so fall back to
			 * the file avail table (in the header).  Make sure there is room
			 * first (split if need be).
			 */
			if (session->dbheader->avail.count == session->dbheader->avail.size)
			{
				err = dbuV2_push_avail_block (session);   /* split & save it out to disk */
				if(err != DB_NO_ERR)
					return(err);	/* tell caller we failed */
			}
			dbuV2_put_avail_elem (temp, session->dbheader->avail.av_table,
				&session->dbheader->avail.count);

			session->dbheader_changed = TRUE;
		}
	}

	/* if there wasn't room in the current storage blocks avail table, we
	 * had to update the header, make sure we balance the header's
	 * avail table for writing out.
	 */
	if (session->dbheader_changed)
		dbuV2_adjust_storage_avail (session);

	return(DB_NO_ERR);	/* all done here, return to caller */
}




/*
---------------------------------------------------------------------------

dbuV2_push_avail_block()

static short dbuV2_push_avail_block (DB_Session_StructV2 *session)

This low level routine is used to split the file header avail table
in half and push the (1/2) avail block onto the avail stack.

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

returns:
	one of the following error codes will be returned.  An error here
	is pretty much fatal, your file is corrupted....

	DB_NO_ERR		 - everything fine
	DB_WRITE_ERR	- file write i/o error
	DB_SEEK_ERR		 - file seek error

---------------------------------------------------------------------------
*/

static short dbuV2_push_avail_block (DB_Session_StructV2 *session)
{
	long			num_bytes;
	long			avail_size;
	long			avail_floc;
	long			index;
	long			file_pos;
	avail_blockV2		 *temp;
	avail_elemV2		new_loc;
	short		   err;
	char	*tmpPtr = NULL;

	/* We need to split the current avail block in half, one will be kept,
	 * and we will write the other out to the file.
	 */
	avail_size = ( (session->dbheader->avail.size * sizeof (avail_elem)) >> 1)
		+ sizeof (avail_blockV2);

	/* need "avail_size" number of bytes sized chunk, get avail location
	 * of the file where it will fit. (file offset)
	 */
	new_loc = dbuV2_get_avail_elem (avail_size, session->dbheader->avail.av_table,
		&session->dbheader->avail.count);

	if (new_loc.avail_size == 0)	/* if no room found, allocate some */
		new_loc = dbuV2_allocate_block (avail_size, session);

	avail_floc = new_loc.avail_floc;	/* file offset to where we can write */


	/* Now we will do the split of the avail info */
	temp = (avail_blockV2 *) malloc (avail_size);

	/* The size of the temp avail block must be set to the size
	 * that will be correct AFTER a call to the dbuV2_pop_avail_block
	 * routine.
	 */
	temp->size = session->dbheader->avail.size;
	temp->count = 0;	/* start as full (no entries left) */

	/* link in the next avail block to our temp, and redirect
	 * the current header next avail file offset to address the temp
	 * we are creating from the split.
	 */
	temp->next_block = session->dbheader->avail.next_block;
	session->dbheader->avail.next_block = avail_floc; /* our split output */

	/* walk thru the current avail elements and put the odd index'd
	 * ones into our temp (split out) avail block, shift the even
	 * ones down in the header avail block (they stay after split).
	 */
	for (index = 1; index < session->dbheader->avail.count; index++)
	{
		if ( (index & 0x1) == 1)	/* odd index's get split out */
			temp->av_table[temp->count++] = session->dbheader->avail.av_table[index];
		else
		{
			/* slide evens down in the header avail block */
			session->dbheader->avail.av_table[index>>1] =
				session->dbheader->avail.av_table[index];
		}
	}

	/* At this point we have divided the avail elements between the header's
	 * avail block and our temp avail block, make sure update the header
	 * avail info so that it knows it only has half as many as before.
	 */
	session->dbheader->avail.count >>= 1;

	/* Since our request for avail space may have given us more than
	 * required, free up any left over space.
	 */
	new_loc.avail_floc += avail_size;	 /* increase file offset by amount we used */
	new_loc.avail_size -= avail_size;	 /* dec available space by amount we used */
	err = dbuV2_free (session, new_loc.avail_floc, new_loc.avail_size);
  /* free up remainder */

	if(err != DB_NO_ERR)
	{
		free(temp);
		return(err);	/* tell caller we failed */
	}

	/* Now write out our temp avail block to disk, so it's available for
	 * later "Popping".
	 */
	file_pos = lseek (session->file, avail_floc, SEEK_SET); /* move to correct location */
	if (file_pos != avail_floc)
	{
		free(temp);
		return(DB_SEEK_ERR);
	}

	if (SRLisLittleEndian())
	{
		tmpPtr = LE_PrepLongs((long *)temp, avail_size);
		if(tmpPtr != 0)
		{
			num_bytes = write (session->file, tmpPtr, avail_size);
			free(tmpPtr);
		}
		else
			num_bytes = 0;	/* ran out of mem... */
	}
	else
		num_bytes = write (session->file,(char *) temp, avail_size);	/* write out the avail block */

	if (num_bytes != avail_size)
	{
		free(temp);
		return(DB_WRITE_ERR);
	}

	free(temp);
	/* all done here */
	return(DB_NO_ERR);
}


/*
---------------------------------------------------------------------------

dbuV2_get_avail_elem()

static avail_elem dbuV2_get_avail_elem (long size,avail_elem *av_table,long
*av_count)

This low level routine is used to retrieve an avail element (free space)
from the given avail table which is greater than "size" bytes large. If
an element is found the meets the size requirement, the the table is
adjusted so that the other elements are shifted,  the av_count will be
decremented and the caller gets the element for their use.  If no
element is found, then the returned element will have a zero size and
zero file offset.  No file i/o is done by this routine, it only works
with the avail elements in the table that the caller has provided.


Parameters:

	size (input) = size in bytes that an element is requested to
		be of greater size

	av_table (input) = the table that an avail element is to
		searched for, and used if found

	av_count (input/output) = how many elements are in the
		avail table.  Modified if one is found.

returns:
	Upon sucess, the return element will have the file offset and
	size of the available chunk.  If table does not have any
	entries which meet the size requirement, then the returned
	element will have a file offset of zero, and a size of zero.

---------------------------------------------------------------------------
*/

static avail_elemV2 dbuV2_get_avail_elem (long size,avail_elemV2 *av_table,long *av_count)
{
	long		index;	  /* For searching through the avail block. */
	avail_elemV2	val;		/* The default return value. */

	/* Start out assuming there is no available space in the given
	 * availability table.
	 */
	val.avail_floc = 0;	 /* no offset */
	val.avail_size = 0;	 /* no entries available */

	/* Walk through the avail tables list of entries till
	 * we find one that is greater than or equal to the
	 * callers requested size.  These avail lists are
	 * sorted in ascending size so we will find the first
	 * that minimally meets our criteria.
	 */
	index = 0;
	while (index < *av_count && av_table[index].avail_size < size)
		index++;


	/* Check to see if we didn't find any space, if so we
	 * just return to caller telling them nothing found.
	 */
	if (index >= *av_count) /* scanned all elements */
		return val;

	/* Record the element that matched, pulling it out
	 * of the table (cause it will be used by caller) and
	 * shift the remaining ones down.
	 */
	val = av_table[index];  /* element for caller to use */
	*av_count -= 1;		 /* dec the number of elements count */
	while (index < *av_count)
	{
		/* copy down the elements */
		av_table[index] = av_table[index+1];
		index++;
	}

	return val;	 /* give caller the element to use */
}

/*
---------------------------------------------------------------------------

dbuV2_put_avail_elem()

static long dbuV2_put_avail_elem (avail_elem new_el,avail_elem av_table[],long
*av_count)

This low level routine is used to place a single new avail element (free
space)
into the given avail table.  The table is sorted in ascending order by size,
so the new element will be placed dependant on it's size.  This routine
will only attempt to place the element into the given avail table, and
if it succeeds, then the av_count will be incremented, and the table
adjusted. If the table is full, then this routine will just return, it
does not attempt to do any file i/o.  Upon sucess, we return TRUE, and
if we didn't insert, then we return FALSE.

Parameters:
	new_el (input) = the element to be inserted in the given table

	av_table (input) = the table that the element is to be inserted into

	av_count (input/output) = number of elements in the table, incremented
		if item is actually inserted.

returns:
	TRUE	- if item was added to table
	FALSE   - if item was not added to table (too small )

---------------------------------------------------------------------------
*/


static long dbuV2_put_avail_elem (avail_elemV2 new_el,avail_elemV2 av_table[],long *av_count)
{
	long index;			 /* For searching through the avail table. */
	long index1;

	/* For elements that are of size smaller or equal to IGNORE_SIZE, we
	 * don't bother putting them into the table since the overhead of
	 * tracking them makes it inefficient
	 */
	if (new_el.avail_size <= IGNORE_SIZE)
		return FALSE;   /* tell caller we did not insert (in case they care) */

	/* We store our elements in the list in accending order of size,
	 * so scan forewards through list till we find the insertion point.
	 */
	index = 0;
	while (index < *av_count && av_table[index].avail_size < new_el.avail_size)
		index++;

	/* We found the index to insert at, move the remaining ones in the
	 * table up one slot.
	 */
	index1 = *av_count-1;   /* top of the table */
	while (index1 >= index)
	{
		av_table[index1+1] = av_table[index1]; /* move it up a notch */
		index1--;	 /* walk backwards */
	}

	/* Insert the caller's new element into the table */
	av_table[index] = new_el;

	/* we added one, so inc the avail element counter. */
	*av_count += 1;

	return TRUE;	/* done, tell caller it was inserted */
}


/*
---------------------------------------------------------------------------

dbuV2_allocate_block()

static avail_elem dbuV2_allocate_block (long size, DB_Session_StructV2
*session)

This low level routine is used to allocate new file space at the end of
the sessions database file.  Space added to the file is done in integral
file block sizes (as set in the header).  This insures that data is
stored within a single block in most cases (if smaller than a block).
This routine will allocate enough file blocks to meet the required size.
No actual file i/o is done, just house keeping info (modify header).

Parameters:

	size (input) = the number of bytes requested by the caller to allocate

	db_session (input) = the session parameter that was returned from a
		call to db_Open().


returns:
	This routine will return an avail element with the file offset and
	size of the allocated space.

---------------------------------------------------------------------------
*/

static avail_elemV2 dbuV2_allocate_block (long size, DB_Session_StructV2 *session)
{
	avail_elemV2 val;

	/* Get the current "next" avail block which was recorded
	 * in the file header previously.
	 */
	val.avail_floc = session->dbheader->next_block; /* offset stored in header */
	val.avail_size = session->dbheader->block_size; /* how many bytes it offers */

	/* Check to see if this is enough bytes to meet the callers needs,
	 * if not we will need to increment by block sized chunks till we
	 * fulfill the required size.
	 */
	while (val.avail_size < size)
		val.avail_size += session->dbheader->block_size;	/* inc by whole blocks */

	/* Keep track in our header where the next block will be allocated,
	 * in this case right after the last one we've reserved.
	 */
	session->dbheader->next_block += val.avail_size;

	/* Mark the header as changed so it will be reflected on
	 * disk.
	 */
	session->dbheader_changed = TRUE;

	return val;	 /* give caller the storage */

}

/*
---------------------------------------------------------------------------

dbuV2_adjust_storage_avail()

static void dbuV2_adjust_storage_avail (DB_Session_StructV2 *session)

This low level routine is used to make sure that when are are about to
write out the file header info, we balance the availability tables so
that the avail table in the current storage table is around half full,
and thereby reduce our need to read the header's avail info until
later (hopefully).

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

returns:
	Nothing

---------------------------------------------------------------------------
*/

static void dbuV2_adjust_storage_avail (DB_Session_StructV2 *session)
{
	avail_elemV2	av_el;
	long		third = MAX_AVAIL / 3;

	/* Check to see if the current storage table has room for more
	 * avail elements, if so copy one from the file header table.
	 */
	if (session->storage_map->av_count < third)
	{
		/* less than a third full, so try copying from header avail table */

		if (session->dbheader->avail.count > 0) /* are there any avail elements */
		{
			/* dec the count in the headers avail table, and copy the
			 * last entry in the table to the current storage table's
			 * avail table.
			 */
			session->dbheader->avail.count -= 1;
			av_el = session->dbheader->avail.av_table[session->dbheader->avail.count];
			dbuV2_put_avail_elem (av_el, session->storage_map->storage_avail,
				&session->storage_map->av_count);
			session->cur_cache_changed = TRUE;
		}
		return; /* done adjusting, return to caller */
	}

	/* otherwise the current storage table may be getting more than
	 * half full, see if it should be slimmed down. If so we will
	 * copy to the header avail table if there is room.
	 */
	while (session->storage_map->av_count > MAX_AVAIL-third
		&& session->dbheader->avail.count < session->dbheader->avail.size)
	{
		/* copy some from current storage table to header table as long
		 * as there are elements to copy, and we have less than a 3rd
		 * freed up in the current storage table.
		 */
		av_el = dbuV2_get_avail_elem (0, session->storage_map->storage_avail,
			 &session->storage_map->av_count);
		dbuV2_put_avail_elem (av_el, session->dbheader->avail.av_table,
			&session->dbheader->avail.count);
		session->cur_cache_changed = TRUE;
	}

	/* all done here */
}


/*
---------------------------------------------------------------------------

dbuV2_init_storagetable()

static void dbuV2_init_storagetable(DB_Session_StructV2 *session,storage_tableV2
*new_storage,
	 long bits)

This low level routine is used to set up a new storage table to its
starting empty state.  All it's elements are marked as having a hash
value of -1 (meaning no stored item in that slot yet), and it's
avail table is empty. (no freed space for this storage block yet).

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

	new_storage (input) = ptr to the storage table to be set up

	bits (input) =  how many bits used for indexing the dir index table

returns:
	Nothing

---------------------------------------------------------------------------
*/
static void dbuV2_init_storagetable (DB_Session_StructV2 *session,storage_tableV2 *new_storage, long bits)
{
	long index;

	/* New storage block starts out with no avail elements
	 * (none free'd yet).
	 */
	new_storage->av_count = 0;

	/* set up directory bits used value and the
	 * stored elements count.
	 */
	new_storage->storage_bits = bits;
	new_storage->count = 0;	 /* no stored elements yet */

	/* set up the storage table with all elements having
	 * hash value of -1, meaning nothing stored in that slot
	 * yet.
	 */
	for (index = 0; index < session->dbheader->max_store_elems; index++)
	{
		new_storage->se_table[index].hash_value = -1;
	}
	/* done here */

}


/*
---------------------------------------------------------------------------

dbuV2_init_cache()

static short dbuV2_init_cache(DB_Session_StructV2 *session,long size)

This low level routine is used to set up a cache table to its
starting empty state.  All it's elements are marked as having a hash
value of -1 (meaning no cached item in that slot yet), and having
no associated storage table for the cached element.  Also hooks up
the current storage table to the first cache entry block.  The
cache table will be made large enought to hold "size" number of
cached elements. In the case where the cache for the indicated
session already exists, this routine will just return, but not
indicate any error.


Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

	size (input) = number of elements the cache should be able to
		hold.


returns:
	DB_NO_ERR			 - everything fine
	DB_NO_MEM			 - out of memory

---------------------------------------------------------------------------
*/
static short dbuV2_init_cache(DB_Session_StructV2 *session,long size)
{
	long	index;

	/* only do this if there are not cached blocks yet */
	if (session->cached_blocks == NULL)
	{
		/* allocate mem to hold the requested number of cache elements */
		session->cached_blocks = (cache_elemV2 *) malloc(sizeof(cache_elemV2) * size);
		if(session->cached_blocks == NULL)
			return(DB_NO_MEM);	/* tell caller we failed */

		session->cache_size = size;	 /* record number of elements it can hold */

		/* now allocate a cache info record for each element and init it to
		 * empty.
		 */
		for(index = 0; index < size; index++)
		{
			(session->cached_blocks[index]).ca_block =
				(storage_tableV2 *) malloc (session->dbheader->block_size);
			if ((session->cached_blocks[index]).ca_block == NULL)
			{
				/* I'm not freeing up "session->cached_blocks" here
				 * since this loop may have filled some in...
				 * I'll come back to this later...
				 */
				return(DB_NO_MEM);	/* tell caller we failed */
			}

			/* init the cache info fields */
			(session->cached_blocks[index]).ca_adr = 0; /* no file offset yet */
			(session->cached_blocks[index]).ca_changed = FALSE; /* data not changed yet */
			(session->cached_blocks[index]).ca_data.hash_val = -1;  /* no data, no hash */
			(session->cached_blocks[index]).ca_data.dptr = NULL; /* no ram copy of data yet */

		}	 /* end of loop */

		/* link the current storage map/block to the starting
		 * cache block, and mark this table as current.
		 */
		session->storage_map = session->cached_blocks[0].ca_block;
		session->current_cache_entry = &session->cached_blocks[0];
	}
	return(DB_NO_ERR);	/* tell caller no problem */
}


/*
---------------------------------------------------------------------------

dbuV2_get_block()

static void dbuV2_get_block (DB_Session_StructV2 *session,long dir_index)

This low level routine is called upon to make sure that the block
in the directory at "dir_index" is currently loaded in to memory.
The cache is first checked to see if it already is in memory, and
if not, it will be loaded into the cache, possibly dropping an old
cached block if room is needed.  Once we are sure that the block is
indeed loaded, it is made the current cache block, and the current
storage table is linked up with it.

Parameters:
	session (input) = the session parameter that was returned from a
		call to db_Open().

	dir_index (input) = the directory table index of the block that
		is requested.

returns:
	one of the following error codes will be returned

	DB_NO_ERR			 - everything fine
	DB_READ_ERR			 - file read i/o error
	DB_SEEK_ERR			 - file seek error


---------------------------------------------------------------------------
*/


static short dbuV2_get_block (DB_Session_StructV2 *session,long dir_index)
{
	long	block_adr;	/* The address of the correct hash block.  */
	long	num_bytes;	/* The number of bytes read. */
	long	file_pos;	 /* The return address for lseek. */
	long	index;	  /* Loop index. */
	short   err;
	char *mapPtr = NULL;
	/* update the current storage info so it knows which
	 * dir entry index we are currently using.
	 */
	session->storage_map_dir = dir_index;

	/* get the file offset for the indicated block */
	block_adr = session->dir_table [dir_index];

	/* see if we've previously read in any blocks, if not start up the
	 * cache.
	 */
	if (session->cached_blocks == NULL)	 /* no cache yet */
	{
		err = dbuV2_init_cache(session, DEFAULT_CACHESIZE);

		if(err != DB_NO_ERR)
			return(err);	/* tell caller we failed */
	}

	/* See if the requested block is the currently cached block, if not
	 * we will search for it and make sure it's loaded, and make
	 * it the currently addressed block.
	 */
	if (session->current_cache_entry->ca_adr != block_adr)
	{
		/* Check the cache to see if it's already loaded,
		 * if so we will make it the current block.
		 */
		for (index = 0; index < session->cache_size; index++)
		{
			if (session->cached_blocks[index].ca_adr == block_adr)
			{
				/* we did previously cache it, make it the currently
				 * addressed block, and return to caller.
				 */
				session->storage_map = session->cached_blocks[index].ca_block;
				session->current_cache_entry = &session->cached_blocks[index];

				return(DB_NO_ERR);	/* done here, return to caller */
			}
		}

		/* If we get down here, then the requested block is not in our cache yet,
		 * so we will read it into the cache.
		 *
		 * Move foreward to the next position in our cache, wrapping around to the
		 * begining if need be. (oldest read chunk position is used - so we cache
		 * the most recently used blocks).
		 */
		session->idx_of_last_read = (session->idx_of_last_read + 1) % session->cache_size;

		/* check to see if there is something in the new position in the cache that
		 * needs to be written out before we use this holder.
		 */
		if (session->cached_blocks[session->idx_of_last_read].ca_changed)
		{
			err = dbuV2_write_block (session,&session->cached_blocks[session->idx_of_last_read]);
			if(err != DB_NO_ERR)
				return(err);
		}

		/* requested block will now be set as currently addressed cache block */
		session->cached_blocks[session->idx_of_last_read].ca_adr = block_adr;

		/* storage map will be for the requested block. */
		session->storage_map = session->cached_blocks[session->idx_of_last_read].ca_block;

		session->current_cache_entry = &session->cached_blocks[session->idx_of_last_read];
		session->current_cache_entry->ca_data.elem_loc = -1; /* no kid/data pair loaded */
		session->current_cache_entry->ca_changed = FALSE; /* just read in, not modified yet */

		/* Read the requested block into memory. */
		file_pos = lseek (session->file, block_adr, SEEK_SET);  /* set up file offset */
		if (file_pos != block_adr)
			return(DB_SEEK_ERR);	/* tell caller we failed */

		/* read in the storage block */
		num_bytes = thread_read (session->file, (char *)session->storage_map, session->dbheader->block_size);

		if (SRLisLittleEndian())
		{
			mapPtr = LEV2_PrepStorageMap(session->storage_map,session->dbheader->block_size);
			if(mapPtr != 0)
			{
				memcpy((char *) (session->storage_map), mapPtr, session->dbheader->block_size);
				free(mapPtr);
			}
			else num_bytes = 0;
		}

		if (num_bytes != session->dbheader->block_size)
			return(DB_READ_ERR);	/* tell caller we failed */
	}

	return(DB_NO_ERR);	/* done here, return to caller */
}


/*
---------------------------------------------------------------------------

dbuV2_write_block()

static short dbuV2_write_block (DB_Session_StructV2 *session, cache_elemV2
*ca_entry)

This low level routine is used to write out cached storage blocks. The
caller indicates which block in the cache needs to be written out. This
is the only routine that actually saves this data to the database file.
This routine would be called before reclaiming a cache block for use on
a new storage block to cache, therefore the block is "unlinked" from it's
previously associated data, and marked as unused.

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

	ca_entry (input) = the cache element that is to be written out to
		the database file associated with the given session.

returns:
	one of the following error codes will be returned.

	DB_NO_ERR
	DB_SEEK_ERR
	DB_WRITE_ERR

---------------------------------------------------------------------------
*/

static short dbuV2_write_block (DB_Session_StructV2 *session, cache_elemV2 *ca_entry)
{
	long	num_bytes;	/* The return value for write. */
	long	file_pos;	 /* The return value for lseek. */
	char	*tmpPtr = NULL;

	file_pos = lseek (session->file, ca_entry->ca_adr, SEEK_SET);
	if (file_pos != ca_entry->ca_adr)
		return(DB_SEEK_ERR);

	if (SRLisLittleEndian())
	{
		tmpPtr = LEV2_PrepStorageMap(ca_entry->ca_block, session->dbheader->block_size);
		if(tmpPtr != 0)
		{
			num_bytes = write (session->file, tmpPtr, session->dbheader->block_size);
			free(tmpPtr);
		}
		else
			num_bytes = 0;	/* ran out of mem... */
	}
	else
		num_bytes = write (session->file,(char *) ca_entry->ca_block, session->dbheader->block_size);


	if (num_bytes != session->dbheader->block_size)
		return(DB_WRITE_ERR);

	ca_entry->ca_changed = FALSE;	   /* just written out, so now it's fresh */
	ca_entry->ca_data.elem_loc = -1;	/* no storage element cached for this block */
	ca_entry->ca_data.hash_val = -1;	/* no hash = no entry */

	return(DB_NO_ERR);
}




/*
---------------------------------------------------------------------------

dbuV2_read_entry()

static short dbuV2_read_entry (DB_Session_StructV2 *session,long elem_loc, char
**eData)

This low level routine is called upon to make sure that a given
storage elements kid & data is in memory, if not then we read it in and
make sure it's in the cache.

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

	elem_loc (input) = storage table index for the given element.

	eData (input/output) = upon success this will be filled in with
		the address of the in memory copy of the entrys kid followed
		by the it's data.

returns:

	DB_NO_ERR
	DB_NO_MEM
	DB_SEEK_ERR
	DB_READ_ERR

---------------------------------------------------------------------------
*/

static short dbuV2_read_entry (DB_Session_StructV2 *session,long elem_loc, char **eData)
{
	long	num_bytes;		/* For seeking and reading. */
	long	kid_size;
	long	data_size;
	long	file_pos;
	cached_item_infoV2 *data_ca;

	*eData = NULL;  /* clear in case we fail */

	/* first check to see if we already have the entry info
	 * in our storage cache, if so just pull the ptr from
	 * the cache info.
	 */
	if (session->current_cache_entry->ca_data.elem_loc == elem_loc) /* index same as current */
	{
		*eData = session->current_cache_entry->ca_data.dptr; /* in current addressed cache */
		return (DB_NO_ERR);
	}

	/* otherwise it's not in the currently addressed cache block, so
	 * we need to read in it's data */
	kid_size = session->storage_map->se_table[elem_loc].kid_size;
	data_size = session->storage_map->se_table[elem_loc].data_size;
	data_ca = &session->current_cache_entry->ca_data;	 /* cached item info */

	/* Set up the cache. */
	if (data_ca->dptr != NULL)	/* old mem storage hanging around */
		free (data_ca->dptr);	   /* free it up */

	/* set up our current cache entry for the requested item */
	data_ca->kid_size = kid_size;
	data_ca->data_size = data_size;
	data_ca->elem_loc = elem_loc;
	data_ca->hash_val = session->storage_map->se_table[elem_loc].hash_value;

	/* this shouldn't happen, but if for some reason we come across
	 * a ghost....
	 */
	if (kid_size+data_size == 0)
		data_ca->dptr = (char *) malloc (1);
	else
		data_ca->dptr = (char *) malloc (kid_size+data_size);

	/* check to see if we are out of memory */
	if (data_ca->dptr == NULL)
		return(DB_NO_MEM);


	/* read the requested entry into the storage cache. */
	file_pos = lseek (session->file,
		session->storage_map->se_table[elem_loc].data_pointer, SEEK_SET);
	if (file_pos != session->storage_map->se_table[elem_loc].data_pointer)
		return(DB_SEEK_ERR);

	num_bytes = thread_read (session->file, data_ca->dptr, kid_size+data_size);
	if (num_bytes != kid_size+data_size)
		return(DB_READ_ERR);

	*eData = data_ca->dptr; /* give caller the kid/data pair ptr */

	return(DB_NO_ERR);	/* tell caller everything worked out */
}



/*
---------------------------------------------------------------------------

dbuV2_hash()

static long dbuV2_hash (DB_Kid kid)

This low level routine is used to run the hash function over the
given keying identifier's data.  The routine calculates a 31 bit
hash value, which is used as an index into the directory index
by using the top "n" dir bits.  This hash is also used to figure
out where in a storage block the element resides by taking the
value modulo the storage table size.



Parameters:

	kid (input) = the keying identifier whose data is to be
		hashed (the keying data itself, not the entry data)


returns:
	The 31 bit hash value.


NOTES:  for an in-depth description on the use of hashing for directory
		table use, see:
		Extendible hashing -- a fast access method for dynamic files.
		Ronald Fagin and J³rg Nievergelt and Nicholas Pippenger and H. Raymond Strong.
		ACM Transactions on Database Systems, 4(3):315-344, September 1979.

---------------------------------------------------------------------------
*/


static long dbuV2_hash (long norm_type, DB_Kid *kid)
{
	unsigned long value;	/* Used to compute the hash value. */
	long		index;	  /* Used to cycle through random values. */
	short skip = 0;
    char *key_value = NULL;
	if (norm_type == NORMALIZED)
	{
		/* Normalize the KID (DN) */
		key_value = calloc (1, kid->item_len);
	    for (index = 0; index <kid->item_len; index++)
		{
			if ((unsigned char)kid->item_ptr[index] <= 0x7F)
				key_value[index-skip] = (char)tolower((char)kid->item_ptr[index]);
			else
				key_value[index-skip] = kid->item_ptr[index];
		}
	}
	else
	{
		key_value = kid->item_ptr;
	}
	value = 0x238F13AF * kid->item_len;
	for (index = 0; index < kid->item_len; index++)
		value = (value + (key_value[index] << (index*5 % 24))) & 0x7FFFFFFF;

	value = (1103515243 * value + 12345) & 0x7FFFFFFF;
	if (norm_type == NORMALIZED)
		free (key_value);
	/* Return the value. */
	return((long) value);
}


/*
---------------------------------------------------------------------------

dbuV2_findkey()

static long dbuV2_findkey (DB_Session_StructV2 *session,DB_Kid *kid,char
**dptr,long *new_hash_val)

This low level routine is called upon to locate an entry in the database file
with the given kid.  If a match is found, the storage table for that block is
loaded (if not already cached), and then we insure that the entry for the kid
is also in the cache.  When returning to the caller, we provide the storage
element location of the requested item (or -1 if not found), and fill in the
kid/data pair ptr (dptr) for the caller.  The calculated hash is also returned
since we use it when adding items, and we check first to see if an item
exists using this routine.

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

	kid (input) = keying identifier info we are to match upon

	dptr (input/output) = upon a match, this pointer storage will be
filled
		in with the memory location of the entries key&data.

	new_hash_val (output) = the calculated hash value for the keying
		identifier is returned to the caller.

returns:
	the element index in the current storage table if entry exists in
	the database file.

	otherwise one of the negative error codes will be returned

---------------------------------------------------------------------------
*/
static long dbuV2_findkey (DB_Session_StructV2 *session,DB_Kid *kid,char **dptr,long *new_hash_val, long norm_type)
{
	long	elem_hash_val;  /* elements hash value from the storage table. */
	char	*full_kid;		/* complete keying identifier as stored in the file. */
	long	elem_loc;		 /* The location in the bucket. */
	long	home_loc;		 /* The home location in the bucket. */
	long	kid_size;		 /* Size of the key on the file. */
	short   err;

	/* calculate the hash value of the callers keying identifier
	 * and give caller a copy.
	 */
	*new_hash_val = dbuV2_hash (norm_type, kid);

	/* make sure the storage block for the given kid is currently loaded,
	 * also insuring that this block will be the current cached block.
	 * Hash value shifted down to figure out the index into the directory
	 * offsets array.
	 */
	err = dbuV2_get_block (session, *new_hash_val>> (31-session->dbheader->dir_bits));
	if(err != DB_NO_ERR)
		return(err);

	/* Check to see if the requested item was previosly cached for the
	 * current cache block.
	 */
	if (session->current_cache_entry->ca_data.elem_loc != -1	/* is an element for this cached block also cached */
		&& *new_hash_val == session->current_cache_entry->ca_data.hash_val	/* are calc'd hashes equal */
		&& session->current_cache_entry->ca_data.kid_size == kid->item_len		/* are kids the same size */
		&& session->current_cache_entry->ca_data.dptr != NULL
		  /* do we have corresponding data */
		&& dbuV2_memicmp (session->current_cache_entry->ca_data.dptr, kid->item_ptr, kid->item_len) == 0)	/* is full kid equal value */
	{
		/* we found an exact match, give caller the pair pointer,
		 * and return the storage index for the cached storage element
		 */
		*dptr = session->current_cache_entry->ca_data.dptr+kid->item_len;
		return session->current_cache_entry->ca_data.elem_loc;
	}

	/* :(
	 * not found above - it may be that the item is in the block requested, but
	 * that it was not one of the items cached for that block.
	 * So search the block for the requested item.
	 */

	/* calc the index for the file offset */
	elem_loc = *new_hash_val % session->dbheader->max_store_elems;
	home_loc = elem_loc;	/* remember starting item in this block */

	/* get hash of current item */
	elem_hash_val = session->storage_map->se_table[elem_loc].hash_value;

	/* now search through all the items (-1 no hashed item stored)
	 * in the storage table, and load that particular entry if
	 * found.
	 */
	while (elem_hash_val != -1)
	{
		/* get keying identifier for the item in the storage map for
		 * this block.
		 */
		kid_size = session->storage_map->se_table[elem_loc].kid_size;

		/* now try to match - speed up comparisons my incremental steps
		 *
		 * Go to next item in storage table block if:
		 * hashes don't match
		 * keying identifiers don't match in size
		 * keying identifiers don't match in value (short sized comparison)
		 */
		if (elem_hash_val != *new_hash_val
			|| kid_size != kid->item_len
			|| dbuV2_memicmp(session->storage_map->se_table[elem_loc].kid_start, kid->item_ptr,
				(SMALL_KID < kid_size ? SMALL_KID : kid_size)) != 0)
		{
			/* Current elem_loc index is not the item, go to next item, wrap if necessary */
			elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems;

			/* if we have wrapped around to where we started in this block, then
			 * the item does not exist.  Tell caller not found.
			 */
			if (elem_loc == home_loc) return (DB_NOT_FOUND);

			/* record the entries hash val for our while loop */
			elem_hash_val = session->storage_map->se_table[elem_loc].hash_value;
		}
		else
		{
			/* Otherwise we may have a possible match. For exact match
			 * we have to do a full comparison of the kids.  The block
			 * is cached, but the entry pair may not be, so make sure
			 * it's read in.
			 */

			/* make sure this entry is loaded, and get the kid */
			err = dbuV2_read_entry (session, elem_loc, &full_kid);
			if(err != DB_NO_ERR)
				return(err);

			/* see if we have exact match on kid's */
			if (dbuV2_memicmp (full_kid, kid->item_ptr, kid_size) == 0)
			{
				/* We have found the exact item,
				 * give caller ptr to associated data
				 * and it's index location.
				 */
				*dptr = (char *) ( full_kid+kid->item_len );
				return elem_loc;
			}
			else	/* didn't match up, set up for next loop through */
			{
				/* Inc index, wrap around if necessary. */
				elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems;

				/* if we have wrapped around to where we started, item is not
				 * stored, tell caller not found.
				 */
				if (elem_loc == home_loc) return(DB_NOT_FOUND);

				/* set up with hash of the next kid for the loop */
				elem_hash_val = session->storage_map->se_table[elem_loc].hash_value;
			}

		}/* end of possible match, do in depth comparison */

	} /* end of while(we have items to check against)  loop */

	/* the item requested has not been stored, tell caller not found */
	return (DB_NOT_FOUND);

}


/* -----------------------------------------------------------------------------
 *
 * Little Endian / Big Endian manipulation routines.  These routines are used so
 * that movement of the db files between platforms is possible.
 *
 * -----------------------------------------------------------------------------
 */

/* LE_PrepLongs()
 *
 * char *LE_PrepLongs(long *longbuff, long numbytes)
 *
 * This routine is used to clone the given input data, then flip it around
 * from little endian format to big endian format, or vis versa.
 *
 * Before writing out the header on Little Endian platforms, make a copy and
 * flip it around to Big Endian format. This is to support moving db files
 * between platforms. Same goes for after reading data in from storage on
 * Little Endian machines, call this routine to swap the data around again.
 *
 * New storage is allocated by this routine, same size as the input, and
 * returned to caller for their use.  Caller should free up
 * afterwards.
 *
 * Parameters:
 *		longbuff (input) = the long data to make a copy and manipulate
 *
 *		numbytes (input) = number of bytes in size
 *
 * Returns:
 *
 *		Ptr to data after conversion, - freed by caller. If we fail
 *		to allocate memory, or some other problem, then 0 is returned.
 *
 * NOTES: At this time the header, dir_table, storage table, etc is made up
 * of longs. If any of these change, then this could will have to be upated
 * to handle it. I've warned you.
 *
 */
static char *LE_PrepLongs(long *longbuff, long numbytes)
{
	long	*le_data;
	if(longbuff == 0)
		return(0);

	if(numbytes <= 0)
		return(0);

	if(numbytes % 4 != 0)
		return(0);
	le_data = (long *) malloc(numbytes);
	if(le_data == 0)
		return(0);
	memcpy((char *)le_data, (char *)longbuff, numbytes);

	/* flip the longs up to block size */
	SRLi_FlipLongs(le_data, numbytes >> 2);

	return((char *) le_data);

}

/*
 *
 */
static char *LEV2_PrepStorageMap(storage_tableV2 *storage_map, long mapbytes)
{
	char *result;
	long	dsize;
	storage_elementV2	*table;

	result = malloc(mapbytes);
	if(result == 0)
		return(0);

	memcpy(result, (char *)storage_map, mapbytes);


	/* now only reverse the fields that are longs */
	dsize = sizeof(storage_tableV2) - sizeof(storage_elementV2);
	SRLi_FlipLongs((result), dsize >> 2);

	/* elements contain one field which is not to be endian modified since
	 * it is an array of chars.
	 */
	table =((storage_tableV2 *) result)->se_table;	/* start with first */
	dsize += sizeof(storage_elementV2);
	for(; dsize < mapbytes; dsize += (sizeof(storage_elementV2)))
	{
		SRLi_FlipLongs(&table->hash_value, 1);
		SRLi_FlipLongs(&table->data_pointer, 3); /* 3 long fields here */
		table++;
	}

	return(result);

}


int dbuV2_memicmp(char *mem1, char *mem2, int len)
/* 
   This function performs a case-insensitive comparison of the two memory locations.
   The result of the comparison is returned and is identical to the standard strcmp()
   function:
	< 0		dn1 less than dn2
	= 0		dn1 identical to dn2
	> 0		dn1 greater than dn2
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
	} while ((c1 && (c1 == c2)) && i < len);

	return (c1 - c2);
} 


short SRLi_V2CertInfoFromTemplate(dbCertEntryInfo_LL **certinfo,DB_Data *ctemplate)
{
	dbCertEntryInfo_LL	*theInfo, *prevInfo;
	long			blocklen, len, count, len2;
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


short AddObject(ulong V2Session, ulong db_session, DB_Kid *DNKid, 
				DB_Kid *TemplateKid, DB_Item *Object)
{
	Bytes_struct	ciTemplate, big_block;
	short			err;
	DB_Kid			*entry_kid, *lentry_kid = 0;
	DB_Data			*ex_data, *compare_data;	/* existing data */
	long TempHashValue = 0;
	long DNHashValue = 0;


	lentry_kid = calloc (1, sizeof (DB_Kid));
	if (lentry_kid == NULL)
		return SRL_MEMORY_ERROR;
	entry_kid = DNKid;
	lentry_kid->item_len = entry_kid->item_len;
	lentry_kid->item_ptr = entry_kid->item_ptr;




	ciTemplate.data = (uchar *)TemplateKid->item_ptr;
	ciTemplate.num =  TemplateKid->item_len;

	// Get the Hash of the Template, for storage
	// db_GetHash (TemplateKid, NORMALIZED, &TempHashValue);
	// Get the Hash of the Template, for storage

		db_CalcHash (db_session, TemplateKid, NULL, NORMALIZED,
				&TempHashValue, 0, DB_INSERT);

	/* make sure the storage block for the given kid is currently loaded,
	 * also insuring that this block will be the current cached block.
	 * Hash value shifted down to figure out the index into the directory
	 * offsets array.
	 */
//	session = (DB_Session_Struct *)db_session;
//	err = dbu_get_block (session, TempHashValue>> (31-session->dbheader->dir_bits));
//	if(err != DB_NO_ERR)
//		return(err);


	/*
	* Insert into the db file associated with this session
	* along with the related template hash - It will return
	* the DN Hash
	*/
	err = db_StoreItem(db_session, entry_kid, TemplateKid, 
						&TempHashValue, DB_INSERT);

	// Save off the DN Hash Value
	DNHashValue = TempHashValue;

	/* check to see if we have an existing entry for the given DN */
	if(err == DB_NO_INSERT)
	{
		/* need to retrieve the current entry so we can determine if we
		 * need to add to it.
		 */
		err = db_GetEntry(db_session, 0, entry_kid, &ex_data);
		if(err != DB_NO_ERR)
		{
			return(DB2SRLerr(err));	/* complete failure, tell caller */
		}
		/* got the entry, see if any of it matches our current cert
		 * that we are to add.  This has to be an EXACT match in order
		 * for us to decide not to add it.
		 */
		err = SRLi_CompareTemplateSearchCriteria(ex_data, &ciTemplate);

		if(err == 0)	/* if exact match */
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
			lentry_kid->item_len = ciTemplate.num;			/* the search/match data */
			lentry_kid->item_ptr = (char *) ciTemplate.data;
			err = dbV2_GetEntry(V2Session, lentry_kid,  &compare_data);
			err = DB2SRLerr(err);
			if(err != DB_NO_ERR)
			{
				return(DB2SRLerr(err));	/* complete failure, tell caller */
			}
		
			/* do a mem compare on the asn.1 data itself */
			if(Object->item_len == compare_data->item_len)	/* not different */
			{
				/* see if they are equal */
				if(memcmp(compare_data->item_ptr, Object->item_ptr, compare_data->item_len) == 0)
				{
					/* then exactly the same, no need to modify entry */
					free(compare_data->item_ptr);/* free up stuff we don't need anymore */
					free(compare_data);
					compare_data = NULL;
					free(ex_data->item_ptr);
					free(ex_data);
					ex_data = NULL;
					
					/* we are not going to tell caller that they tried
					 * inserting something that already exists, just
					 * tell them no error. (could change later...)
					 */
					return(SRL_SUCCESS);
				}
				
			}

			/* don't need the db copy of the asn.1 data, free it up */
			free(compare_data->item_ptr);
			free(compare_data);
			
			//db_GetHash (entry_data, NORMALIZED, &TempHashValue);

			db_CalcHash (db_session, lentry_kid, NULL, NORMALIZED,
				&TempHashValue, 0, DB_REPLACE);

			/* else they are different, do a replace. Need to 
			 * save out the asn.1 data using the entries
			 * template.
			 */
			err = db_StoreItem(db_session, lentry_kid, (DB_Item*)Object, 
				&TempHashValue, DB_REPLACE);
			
			/* the existing dn template already contains a ref for this cert, and
			 * we know from our earlier comparison that they already match, so
			 * we only need to free up and return.
			 */
			free(ex_data->item_ptr);	/* got our own copy */
			free(ex_data);

			
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
			free(ciTemplate.data);
			free(ex_data->item_ptr);	/* got our own copy */
			free(ex_data);
			return(SRL_MEMORY_ERROR);
		}

		memcpy(big_block.data, ex_data->item_ptr, ex_data->item_len);
		memcpy( &(big_block.data[ex_data->item_len]),
			ciTemplate.data, ciTemplate.num);

		// db_GetHash (entry_data, NORMALIZED, &DNHashValue);
		db_CalcHash (db_session, lentry_kid, NULL, NORMALIZED,
				&DNHashValue, TempHashValue, DB_REPLACE);

		/* replace the old entry for this DN */
		err = db_StoreItem(db_session, lentry_kid, (DB_Item*)&big_block, 
			&DNHashValue, DB_REPLACE);

		/* clean up stuff we don't need anymore */
		free(big_block.data);
		big_block.data = 0;
		free(ex_data->item_ptr);
		free(ex_data);
		ex_data = 0;

		if(err != DB_NO_ERR)
		{
			return(DB2SRLerr(err));
		}

		/* now fall down to below to store the raw asn.1 encoded cert
		 * into data base
		 */

	}

	if(err == DB_NO_ERR)
	{

		/* dn and searching template added ok.  Now we will add the asn.1
		 * encoded certificate to the database using the search template
		 * as the keying identifier.
		 */
		lentry_kid->item_len = ciTemplate.num;			/* the search/match data */
		lentry_kid->item_ptr = (char *) ciTemplate.data;

		// The storage of the Cert does require the template Hash

		/* insert into data base */
		err = db_StoreItem(db_session, lentry_kid, Object, 
			&DNHashValue, DB_INSERT);
		if (lentry_kid != NULL)
			free(lentry_kid);

	}
	return(DB2SRLerr(err));	/* tell caller what the result is */


}

static short ModifyCRLTemplate (DB_Item *CRLtemplate, DB_Item **NewTemplate)
{
// Routine used to modify the template length and add in the refresh time
	char *tempPtr = NULL, *sizeptr = NULL;
	time_t RefreshTime;
	int len = 0;
	DB_Item *xplate = NULL;
	*NewTemplate = NULL;
	// Allocate a temp item
	xplate = (DB_Item *)calloc (1, sizeof(DB_Item));
	if (xplate == NULL)
		return SRL_MEMORY_ERROR;

	// Adding in refresh time allocate old template + size of time_t
	tempPtr = (char *)calloc(1, CRLtemplate->item_len+sizeof(time_t));
	if (tempPtr == NULL)
		return SRL_MEMORY_ERROR;
	xplate->item_ptr = tempPtr;
		// Get the length
	   sizeptr = CRLtemplate->item_ptr;
	   memcpy(&len, sizeptr, 4); /* length of this template in block */
		if (SRLisLittleEndian())
		  SRLi_FlipLongs(&len, 1);
	   len = len & 0x00FFFFFF;

	   len += sizeof (time_t); // add in the time_t size

	   //Copy into tempPtr
	   	memcpy(tempPtr, &len, sizeof(long));
		if (SRLisLittleEndian())
			SRLi_FlipLongs(tempPtr, 1);

	tempPtr[0] = 4; // add in the version
	tempPtr += 4;

	*tempPtr++ = 4;	/* store the version field */



	memcpy(tempPtr, CRLtemplate->item_ptr+5, (CRLtemplate->item_len)-5);
	tempPtr += (CRLtemplate->item_len)-5;
	RefreshTime = time(NULL);
	memcpy(tempPtr, &(RefreshTime), sizeof(time_t));
	if (SRLisLittleEndian())
			SRLi_FlipLongs(tempPtr, 1);

	tempPtr += sizeof(time_t);
	xplate->item_len = CRLtemplate->item_len + sizeof(time_t);
	*NewTemplate = xplate;
	return SRL_SUCCESS;
}

static short doConvert(ulong V2Session, ulong V3Session, int type)
{
	short			err = 0;
	DB_Kid			*entry_kid = NULL,*prevEntry = NULL;
	DB_Item			*entry_data = NULL, *asnentry_data = NULL;	/* existing data */
	DB_Item			currentTemplate;
	DB_Item			*newentry_data = NULL;
	char			*tempPtr = NULL;
	int				first_time = 0;
	int				addtolen = 0;
	long			len = 0, biglen = 0;
	entry_kid = 0;   /* none retrieved yet */
	prevEntry = 0;
	prevEntry = 0;
	entry_data = 0; /* Template data */
	asnentry_data = 0; /* ASN Blob (in this case - cert) */
	while (TRUE)
	{
		addtolen = 0;
		/* check to see if we need to get first entry in the database */
		if(first_time == 0)   /* if we didn't start list yet */
		{
			 err = dbV2_GetFirstKid(V2Session, &entry_kid);
			 first_time ++;
		}
		else
		{
			 err = dbV2_GetNextKid(V2Session, prevEntry, &entry_kid);

		}
		err = DB2SRLerr(err);

		if(err != SRL_SUCCESS)
		{
			if(err == SRL_NOT_FOUND)   /* are there no more entries */
			{
				err = SRL_SUCCESS;
				break;   /* all done looping */
			}

			return (err);   /* if other errors occured */
		}


      /* if this is a dn entry index type item, record it */
      if( SRLi_isDN(entry_kid->item_ptr[0]))
      {


		/* Get the Data Base Entry for the template */
		 err = dbV2_GetEntry(V2Session, entry_kid,  &entry_data);
         err = DB2SRLerr(err);
         if(err != SRL_SUCCESS)
             return (err);

		 if (type == CRLDB)
		 {
			 // Add in the Refresh Perios to the CRL Template
			 err = ModifyCRLTemplate(entry_data, &newentry_data);
			 if (err != SRL_SUCCESS)
				 return err;
			 addtolen = 4;
		 }
		 else
			 addtolen = 0;
/*once we have the template, we have to determine if it is a single
template or multiple templates. On multiple templates we have to loop on big templates for each 
certificate that may be referenced by the each template:
IE: 
1 Determine if single or multiple templates
2 if single store get the cert and store
3 if multiple
4 Get a single template
5 Get the cert referenced by the template
6 Add to version 3 db
7 do # 4 again until all templates are done*/

	   /* check the length of the block against the length of the first
		* index template entry, if the same we know this is the last one.
		*/
	   tempPtr = entry_data->item_ptr;
	   memcpy(&len, tempPtr, 4); /* length of this template in block */
		if (SRLisLittleEndian())
		  SRLi_FlipLongs(&len, 1);
	   biglen = len & 0x00FFFFFF;
   
	   if(entry_data->item_len !=  biglen)
	   {
			biglen = entry_data->item_len;   /* length of the whole block of mem */

		  /* then there is more than one template
		   * Loop through the templates, storing the
		   * cert based on the templates
		   */
		   while (biglen > 0)
		   {
				memcpy(&len, tempPtr, 4); /* length of this template in block */
				if (SRLisLittleEndian())
					SRLi_FlipLongs(&len, 1);
				len = len & 0x00FFFFFF;

				/*
				 * We now have the length of this template
				 * so we get the entry for this template
				 */	
				currentTemplate.item_len = len;
				currentTemplate.item_ptr = tempPtr;

				 if (type == CRLDB)
				 {

					// Add in the Refresh Perios to the CRL Template
					err = ModifyCRLTemplate(&currentTemplate, &newentry_data);
					if (err != SRL_SUCCESS)
						return err;
					addtolen = 4;
				 }
				 else
					 addtolen = 0;

				/* Get the entry associated with this template */
				err = dbV2_GetEntry(V2Session, &currentTemplate,
									&asnentry_data);
				if (err != SRL_SUCCESS)
					return err;
				err = AddObject (V2Session, V3Session, entry_kid, &currentTemplate,
								asnentry_data);

				// Increment the lenght and pointer
				tempPtr += len;
				biglen -= len;

			   }
	   }

		else
		{
		 /* Get the Data Base entry for the cert */
		 err = dbV2_GetEntry(V2Session, entry_data, &asnentry_data);
         if(err != SRL_SUCCESS)
             return (err);
		
		 /*
		  * We have both the template and cert so
		  * now store into the new Database version
		  */
		 if (type == CRLDB)
		 {
			 // CRL's are modified Free old entry and point to new
			 free(entry_data->item_ptr);
			 free(entry_data);
			 entry_data = newentry_data;
		 }
		err = AddObject (V2Session, V3Session, entry_kid, entry_data, 
			asnentry_data);
		}
	  }
	prevEntry = entry_kid;   /* record for next loop iteration */

	}
//	conversion_done:
	return (err);
	
	
}

/*
 * Converts the Cert Data Base file from the original
 * Data Base version, which only stored the 
 * the hash value to the new version that stores the
 * sibling hash also.
 *
 */
short SRLi_ConvertCertDbFile (SRLSession_struct *SRL_session)
{
	short			err = 0;
	ulong			db_session = 0;
	ulong			dbV2_session = 0;
	if(SRL_session == 0)
		return(SRL_INVALID_PARAMETER);

	err = RemoveTempFile ("./tempV3.db");

	err = db_Open(&db_session, (char *)"./tempV3.db", DB_NEW, 1024);
	if (err == DB_OPEN_ERROR)
	{
		return (SRL_SUCCESS);
	}

	err = dbV2_open(&dbV2_session, SRL_session->CertFileName, DB_RDWR, 1024);
	if((err == DB_NOT_FOUND) || (err == DB_OPEN_ERROR))
	{
		/* db doesn't exist yet, just return no error */
		return(SRL_SUCCESS);
	}
	err = DB2SRLerr(err);
	if(err != SRL_SUCCESS)
		return(err);		/* exists, but some other error */
	err = doConvert(dbV2_session, db_session, CERTDB);

	db_Close(&db_session);	/* close our session with the db manager */
	dbV2_close(&dbV2_session);

	return (err);
}

/*
 * Converts the CRL Data Base file from the original
 * Data Base version, which only stored the 
 * the hash value to the new version that stores the
 * sibling hash also.
 *
 */
short SRLi_ConvertCRLDbFile (SRLSession_struct *SRL_session)
{
	short			err = 0;
	ulong			db_session = 0;
	ulong			dbV2_session = 0;
	if(SRL_session == 0)
		return(SRL_INVALID_PARAMETER);

	remove ("./tempV3.db");
	err = db_Open(&db_session, (char *)"./tempV3.db", DB_NEW, 1024);
	if (err == DB_OPEN_ERROR)
	{
		return (SRL_SUCCESS);
	}

	err = dbV2_open(&dbV2_session, SRL_session->CRLFileName, DB_RDWR, 1024);
	if((err == DB_NOT_FOUND) || (err == DB_OPEN_ERROR))
	{
		/* db doesn't exist yet, just return no error */
		return(SRL_SUCCESS);
	}
	err = DB2SRLerr(err);
	if(err != SRL_SUCCESS)
		return(err);		/* exists, but some other error */
	err = doConvert(dbV2_session, db_session, CRLDB);

	db_Close(&db_session);	/* close our session with the db manager */
	dbV2_close(&dbV2_session);
	return (err);
	
	
}

static short RemoveTempFile(char *Filename)
{

#ifdef WIN32
/* Windows we move to the recycle bin */
int    Result  = 1; /* assume failure */
SHFILEOPSTRUCT  Info    = {NULL};
char            DeletePath[MAX_PATH+2];
char*           Dummy;
DWORD           Status;

	memset (&DeletePath, 0, MAX_PATH+2);
    Status = GetFullPathName(Filename, sizeof(DeletePath),
            DeletePath, &Dummy);
    if(Status != 0)
	{
		Info.wFunc      = FO_DELETE;
		Info.pFrom      = DeletePath;
		Info.fFlags     = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;

		Result          = SHFileOperation(&Info);
		if (Result != 0)
			return SRL_DB_IO_ERROR;
	}
	return SRL_SUCCESS;


#else
	remove(Filename);
	return SRL_SUCCESS;
#endif
}
