/*****************************************************************************
File:	  SRL_db.c
Project:  Storage & Retrieval Library
Contents: Library of generic database routines which will be used by the
	      Certificate Management local storage routines.

Created:  November 2000
Author:   C. C. McPherson <Clyde.McPherson@DigitalNet.com>
          Shari Bodin <Shari.Bodin@DigitalNet.com>

Last Updated:	27 Jan 2005

Version:  2.5

Description:  The routines in this file are broken into two groups.  Those
		      routines which are meant to be the interface to this database
		      library named "db_xxxxxx",  and routines named "dbu_xxxxxxx"
		      which are meant to be only used internally.

		Interface to the db library routines:

		db_Open() - start up a session and open or create db file
		db_Close() - close down session, close db file, free up mem
		db_StoreItem() - insert/replace an item to db file
		db_GetEntry() - retrieve a database entry
		db_DeleteEntry() - remove an entry from the db file
		db_GetFirstKid() - get keying identifier for first entry in db
           file
		db_GetNextKid() - get a following key identifier (for stepping)
		db_Compact() - compacts the free space in the db file
		db_Info() - retrieve info about the session's db file

		The rest of the routines in this file are not meant for general
		use.

*****************************************************************************/

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#ifdef _MSC_VER
	#pragma warning(disable: 4115)
	#pragma warning(disable: 4127)	// Disable conditional expression warning
#endif
#if defined(WIN32) && defined(_DEBUG)
	#define _WIN32_WINNT	0x0500
	#include <windows.h>						// For debugging
	#include <winbase.h>
#endif
//#include <time.h>
/* To support moving db files between little and big endian hardware,
 * the routine SRLisLittleEndian is used - this will format data correctly
 * after reading, or before writing. This only applies to data used internally
 * by the db manager code.  Upper level apps are the only ones that know what
 * they are storing, and will have to deal accordingly where necessary.
 */
#ifdef _WINDOWS
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

/* foreward declaration of the routines */
short db_CalcHash(ulong db_session, DB_Kid *kid, DB_Kid *data, long norm_type, 
				  long *HashValue, long relatedHash, long storeFlag);
short time2CMTime(time_t t, char cm_time[CM_TIME_LEN]);
short db_Close(ulong *db_session);
short db_GetHash(DB_Kid *kid, long norm_type, long *HashValue);
short db_RetrieveHash(ulong db_session, DB_Kid *kid,  
				   long *HashValue);
short db_StoreItem(ulong db_session, DB_Kid *kid, DB_Data *data, long *HashValue, long storeFlag);
short db_GetEntry(ulong db_session, long inHash, DB_Kid *kid, DB_Data **data);
short db_DeleteEntry(ulong db_session, DB_Kid *kid);
short db_GetFirstKid(ulong db_session, DB_Kid **kid);
short db_GetNextKid(ulong db_session, DB_Kid *kid, DB_Kid **next_kid);
short db_Compact(ulong db_session);
short db_Info(ulong db_session, DB_INFO_Struct **info);
void db_FreeDBInfo(DB_INFO_Struct **info);
short db_UpdateHeaderVersion (ulong db_session, char *path, char *dbfile);
short SRLi_TemplateFromCertInfo(DB_Kid *kid, dbCertEntryInfo_LL *certinfo);
short SRLi_TemplateFromCRLInfo(DB_Kid *kid, dbCRLEntryInfo_LL *crlinfo);
short DB2SRLerr(short db_err);
short SRLi_BreakUpCertList(ulong cm_session, uchar *asndata, SRL_CertList **cp);
static CM_BOOL isRoot(Cert_struct *cert);
CM_BOOL CompareBytes(const Bytes_struct *a, const Bytes_struct *b);
short SRLi_GetCertID(ulong sessionID, Bytes_struct *pObject, Cert_struct *dec_cert,CM_BOOL trustedFlag, AsnTypeFlag AsnType, Bytes_struct **CertID);
short SRLi_GetCRLID(ulong sessionID, Bytes_struct *pObject, CRL_struct *dec_crl, long *DBid);

int SRLi_memicmp(char *mem1, char *mem2, int len);
CM_BOOL SRLisLittleEndian();

/* internal use only routines */
static short dbu_getIDKids (DB_Session_Struct *db_session,
								long elem_loc, long kidID, 
								long *sibID,
								DB_Kid *return_kid);
static short cvt_DBitem2Bytes(DB_Item *entry_data, Bytes_struct **retData);
static short db_GetDBItemsByID(ulong db_session, long dbID, 
							   DB_Item **Kid1, DB_Data **data1,
							   DB_Item **Kid2, DB_Data **data2);
//static long dbu_getkey (DB_Session_Struct *session,DB_Kid *kid,char **dptr,long hash_val);
static short dbu_get_next_kid (DB_Session_Struct *db_session,long elem_loc, DB_Kid *return_kid);
static long dbu_alloc (DB_Session_Struct *session,long num_bytes);
static short dbu_free (DB_Session_Struct *session,long file_adr,long num_bytes);
static short dbu_pop_avail_block (DB_Session_Struct *session);
static short dbu_push_avail_block (DB_Session_Struct *session);
static avail_elem dbu_get_avail_elem (long size,avail_elem *av_table,long *av_count);
static long dbu_put_avail_elem (avail_elem new_el,avail_elem av_table[],long *av_count);
static avail_elem dbu_allocate_block (long size, DB_Session_Struct *session);
static void dbu_adjust_storage_avail (DB_Session_Struct *session);
static void dbu_init_storagetable (DB_Session_Struct *session,storage_table *new_storage, long bits);
static short dbu_init_cache(DB_Session_Struct *session,long size);
short dbu_get_block (DB_Session_Struct *session,long dir_index);
static short dbu_split_storageTable (DB_Session_Struct *session, long next_insert);
static short dbu_write_block (DB_Session_Struct *session, cache_elem *ca_entry);
static short dbu_write_header (DB_Session_Struct *session);
static short dbu_end_update (DB_Session_Struct *session);
static short dbu_read_entry (DB_Session_Struct *session,long elem_loc, char **eData);
static long dbu_hash (long norm_type, DB_Kid *kid);
static long dbu_findkey (DB_Session_Struct *session,DB_Kid *kid,char **dptr,long *new_hash_val, long norm_type);
char *LE_PrepLongs(long *longbuff, long numbytes);
char *LE_PrepStorageMap(storage_table *storage_map, long mapbytes);
extern short SLRi_RefreshCRL(ulong sessionID, ulong crl_db_session, dbCRLEntryInfo_LL *oldCRLInfo,
							 char *opt_kid, CM_BOOL isURL);
extern short SRLi_GetCRLIssuerName (CRL_struct* pInput_crl, char** pCrl_issuer);
short AddObjectToDB(ulong db_session, DB_Kid *DNKid, 
				DB_Kid *TemplateKid, DB_Item *Object);
#ifdef SunOS
extern void     flockfile(FILE *);
extern void     funlockfile(FILE *);
#endif
#ifndef NOTHREADS
	/* Define our externally defined mutex */
	#if defined (WIN32) || defined (WINDOWS)
		extern HANDLE g_srl_db_mutex;
	#else
		extern pthread_mutex_t g_srl_db_mutex;
	#endif
#endif

void db_unlock(char *inString, int lineNo)
{
#ifndef NOTHREADS
	inString = inString;
	lineNo = lineNo;
#if defined(WIN32) && defined(_DEBUG) && defined(VERBOSE)
	{
		char debugStr[256];
		sprintf (debugStr,"db_unlock Function %s Line Number %d\n", inString, lineNo);
		if (IsDebuggerPresent() == TRUE)
			OutputDebugString(debugStr);
	}
#endif
#if !defined(WIN32) && defined(_DEBUG) && defined (VERBOSE)
	fprintf (stderr,"db_unlock Function %s Line Number %d\n", inString, lineNo);
#endif
#if defined(WIN32) || defined (WINDOWS)
	ReleaseMutex(g_srl_db_mutex);
#else
	pthread_mutex_unlock(&g_srl_db_mutex);
#endif
#endif //NOTHREADS
	return;	
}

void db_lock(char *inString, int lineNo)
{
#ifndef NOTHREADS
	inString = inString;
	lineNo = lineNo;

#if defined(WIN32) || defined (WINDOWS)
	WaitForSingleObject(g_srl_db_mutex, INFINITE);
#else
	pthread_mutex_lock(&g_srl_db_mutex);
#endif
	
#if defined(WIN32) && defined(_DEBUG) && defined(VERBOSE)
	{
		char debugStr[256];
		sprintf (debugStr,"db_lock Function %s Line Number %d\n", inString, lineNo);
		if (IsDebuggerPresent() == TRUE)
			OutputDebugString(debugStr);
	}
#endif
#if !defined(WIN32) && defined(_DEBUG) && defined (VERBOSE)
	fprintf (stderr,"db_lock Function %s Line Number %d\n", inString, lineNo);
#endif

#endif //NOTHREADS
	return;
}

/* The thread_open, thread_read and thread_write functions ensures that
 * when a cancellation happens, that the open(), read() or write()
 * will end properly. The thread_open and thread_write will lock the file
 * before opening or writing.
 */
size_t thread_read(int fd, void *buf, size_t count)
{ 
#ifndef NOTHREADS
#if defined(WIN32) || defined (WINDOWS)
	return (read(fd, buf, count));
#else
	int oldtype = 0;
	size_t bytes_read = 0;
	// Following 3 lines used to get rid of gcc warnings
	count = count;
	buf = buf;
	fd = fd;
	// Keep the Cancellation pending until oldtype is reenstated
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);
	bytes_read = read (fd, buf, count);
	if (bytes_read < 0)
	{
		return (bytes_read); 
	}
	pthread_setcanceltype(oldtype, NULL); // Reenstate the old cancellation settings
	pthread_testcancel(); // Check for any cancellation
	return (bytes_read);
#endif
#else
	return (read(fd, buf, count));
#endif
}

size_t thread_write(int fd, FILE *fdStream, void  *buf, size_t count)
{ 
size_t bytes_written = 0;
#ifndef NOTHREADS
#if defined(WIN32) || defined (WINDOWS)
	bytes_written = write(fd, buf, count);
	/* Flush the data written */
	if (bytes_written >= 0)
		fflush (fdStream); 
	return (bytes_written);
#else //WIN32
	int oldtype = 0;
	// Following 4 lines used to get rid of gcc warnings
	count = count;
	buf = buf;
	fd = fd;
	fdStream = fdStream;	// Keep the Cancellation pending until oldtype is reenstated
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);
	(void)flockfile(fdStream);  // Lock the file
	bytes_written = write (fd, buf, count); 
	(void)funlockfile(fdStream); // Unlock even on a error
	if (bytes_written < 0)
		return (bytes_written); 
	pthread_setcanceltype(oldtype, NULL); // Reenstate the old cancellation settings
	pthread_testcancel(); // Check for any cancellations
	/* Flush the data to the file */
	fflush (fdStream);
	return (bytes_written);
#endif //WIN32

#else //NOTHREADS
	bytes_written = write (fd, buf,count);
	if (bytes_written >= 0)
		fflush (fdStream);
	return (bytes_written);
#endif //NOTHREADS
}

int thread_open(char *fileName, int oflag, int mode)
{ 
int retval = 0;

#ifndef NOTHREADS
#if defined(WIN32) || defined(WINDOWS)
	if (mode == -1)
		retval = open(fileName, oflag);
	else
		retval = open(fileName, oflag, mode);
	return (retval);
#else //WIN32
	int oldtype = 0; // Save area for old type of cancellation
	// Keep the Cancellation pending until oldtype is reenstated
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &oldtype);
	if (mode == -1)
		retval = open (fileName, oflag);
	else
		retval = open (fileName, oflag, mode);
	
	pthread_setcanceltype(oldtype, NULL); // Reenstate the old cancellation settings
	pthread_testcancel(); // Check for any cancellations
	return (retval);
#endif //WIN32

#else //NOTHREADS
	if (mode == -1)
		retval = open(fileName, oflag);
	else
		retval = open(fileName, oflag, mode);
	return (retval);
#endif	//NOTHREADS
}

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
	DB_OPEN_ERR			- named db file not found
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

short db_Open(ulong *db_session, char *filename, long access,
long blocksize)
{
	DB_Session_Struct	*session;
	db_file_header		partial_header;	 /* to verify file type */
	short				err;
	long				length, num_bytes, file_pos;
	ulong				index;
	char				*tempname;		/* temp used when creating/opening file */
	char	*tmpPtr = NULL;

	if((db_session == NULL) || (filename == NULL) )
		return(DB_BAD_PARAM);

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
	session = (DB_Session_Struct *) calloc(1, sizeof(DB_Session_Struct));

	/* check for storage */
	if(session == NULL)
	{
		return(DB_NO_MEM);
	}


	/* record the caller's provided name and path of the file. */
	session->name = (char *) calloc (1, strlen(filename) + 1);
	if (session->name == NULL)
	{
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
		return(DB_BAD_PARAM);   /* tell caller */

	}


	/* see if we were able to create the file or open it */
	if ((session->file < 0) || (err != DB_NO_ERR))
	{
		/* free up allocated memory */
		free (session->name);
			free(session->path);
		free (session);
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
		session->dbheader = (db_file_header *) calloc (1, blocksize);
		if (session->dbheader == NULL)
		{
			(void) db_Close ((ulong *) &session);
			return DB_NO_MEM;
		}

		/* Set up the header fields. tracks the free space in the file,
		 * and the location of the hashed dir/index info
		 */

		/*
		 * The following line was saved for historical purposes
		 * The new data base is DBX1, which normalizes the DN's
		 * EG:
		 * session->dbheader->header_ident = 0x44425858;
		 */
		session->dbheader->header_ident = DATA_BASE_HEADER_VERSION3; /* "DBX2" so we know it's ours */
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
			(void) db_Close  ((ulong *) &session);
			return(DB_BLOCK_SIZE_ERR);
		}

		/* allocate memory for the directory index array. */
		session->dir_table = (long *) calloc (1, session->dbheader->dir_size);
		if (session->dir_table == NULL)
		{
			(void) db_Close  ((ulong *) &session);
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
			(session->dbheader->block_size - sizeof(storage_table))
			/ sizeof (storage_element) + 1;

		session->storage_map = (storage_table *) (calloc
					(1, session->dbheader->block_size));


		if (session->storage_map == NULL)
		{
			(void) db_Close  ((ulong *) &session);
			return(DB_NO_MEM);
		}

		/* set up the new storage_map with default nothing stored values */
		dbu_init_storagetable (session, session->storage_map, 0);

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
			sizeof (db_file_header)) / sizeof (avail_elem)) + 1;

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
			(void) db_Close ((ulong *) &session);
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
			(void) db_Close  ((ulong *) &session);
			return(DB_WRITE_ERR);
		}

		/* Block 2 gets the initial storage table */
		if (SRLisLittleEndian())
		{
			tmpPtr = LE_PrepStorageMap(session->storage_map, session->dbheader->block_size);
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
			(void) db_Close ((ulong *) &session);
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
			(void) db_Close ((ulong *) &session);
			return(DB_READ_ERR);
		}
		/* check to see if it's our file type */
		if ((partial_header.header_ident != DATA_BASE_HEADER_VERSION_OLD) &&
			(partial_header.header_ident != DATA_BASE_HEADER_VERSION1) &&
			(partial_header.header_ident != DATA_BASE_HEADER_VERSION2) &&
			(partial_header.header_ident != DATA_BASE_HEADER_VERSION3))
		{ 
			(void) db_Close ((ulong *) &session);
			return(DB_NOT_DB_FILE);
		}

		/* allocate storage, then read the rest of the first block. */
		session->dbheader = (db_file_header *) calloc
			(1, partial_header.block_size);
		if (session->dbheader == NULL)
		{
			(void) db_Close ((ulong *) &session);
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
			(void) db_Close ((ulong *) &session);
			return(DB_READ_ERR);
		}

		/* allocate memory for the hash directory array.  */
		session->dir_table = (long *) calloc(1, session->dbheader->dir_size);
		if (session->dir_table == NULL)
		{
			(void) db_Close ((ulong *) &session);
			return(DB_NO_MEM);
		}

		/* read in the saved directory index array. */
		file_pos = lseek (session->file, session->dbheader->dir_location, SEEK_SET);

		/* make sure we got there */
		if (file_pos != session->dbheader->dir_location)
		{
			(void) db_Close ((ulong *) &session);
			return(DB_SEEK_ERR);
		}

		num_bytes = thread_read (session->file, (char *) session->dir_table,
			session->dbheader->dir_size);


		if (SRLisLittleEndian())
			SRLi_FlipLongs((session->dir_table),session->dbheader->dir_size >> 2);


		if (num_bytes != session->dbheader->dir_size)   /* was it all available */
		{
			(void) db_Close ((ulong *) &session);
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
	session->useCount ++;
	/* give caller their session/context ref value */
	*db_session = (ulong) session;

	/* tell caller that everything went fine */
	return(DB_NO_ERR);

}

/* Duplicate a DB Session
 * Currently all we do is increment the Use count
 */
short db_dupe(ulong *db_session)
{
	DB_Session_Struct	*session = (DB_Session_Struct *)*db_session;
	session->useCount++;
	return DB_NO_ERR;
}


/*
---------------------------------------------------------------------------

db_Close()

short db_Close(ulong db_session)

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

short db_Close (ulong *db_session)
{
	DB_Session_Struct	 *session;
	long				index;

	/* check for legal params */
	if(db_session == NULL)
		return(DB_BAD_PARAM);
	session = (DB_Session_Struct *) (*db_session);

	/* NULL out so caller doesn't try using it after we close */
	*db_session = 0;

	/* If the file was set up for writing (or read and write)
	 * make sure that the database is all on disk.
	 */
/*	if ((session->access == DB_WRITE) || (session->access == DB_RDWR))
		fsync (session->file);  unistd.h  */

	if (session->useCount > 1)
	{
		// Decrement the use count and return
		session->useCount --;
		return DB_NO_ERR;
	}
	/* now that we are sure that the file reflects what's in
	 * memory, close down the file and release the memory
	 * we allocated assocated with this session.
	 */
	if (session != NULL)
	{
		close(session->file);

		if (session->name != NULL)
			free(session->name);
		if (session->path != NULL)
			free(session->path);
	}
	if (session->dir_table != NULL) free (session->dir_table);

	/* free up any cached chunks, if we have any */
	if (session->cached_blocks != NULL)
	{
		for (index = 0; index < session->cache_size; index++)
		{
			/* free the storage table info for this element */
			if (session->cached_blocks[index].ca_block != NULL)
				free (session->cached_blocks[index].ca_block);
			if(session->cached_blocks[index].ca_data.dptr != NULL)
					free(session->cached_blocks[index].ca_data.dptr);
		}
		/* free up the array for this cache list */
		free (session->cached_blocks);
	}
	/* free up the file information header */
	if ( session->dbheader != NULL )
		free (session->dbheader);

	/* and finally the session context (structure) itself */
	if (session != NULL)
		free (session);

	/* all done here */
	return(DB_NO_ERR);
}


/*
---------------------------------------------------------------------------

db_StoreItem()

short db_StoreItem(ulong db_session, DB_Kid *kid, DB_Data *data, long
storeFlag)

This routine is used to insert or replace existing data in the database
associated with the indicated db_session.

Parameters:
	db_session (input) = the session parameter that was returned from a
		call to db_Open().

	kid (input) = the keying identifier (info used to represent the data that
		is to be stored).

	data (input) = the data to be stored in the database.

	storeFlag = indicates whether the data is to be inserted or replaced.
		If the data is to be inserted, and there is already an existing data
		item in the db with the same kid, then the caller will be told that
		it could not be inserted.  If the data is to be replaced, the data will be
		placed into the database, replacing any previous matching kid's entry (if
		any).    {DB_INSERT, DB_REPLACE}

returns:
	one of the following error codes will be returned

	DB_NO_ERR		- everything fine
	DB_BAD_PARAM	- bad parameter passed to this routine
	DB_BAD_KID		- bad keying identifier
	DB_BAD_DATA		- bad data contents
	DB_READ_ERR		- file read i/o error
	DB_WRITE_ERR	- file write i/o error
	DB_SEEK_ERR		- file seek error
	DB_NO_INSERT	- entry already exists (could not insert)
	DB_NO_WRITE		- db file not open for writing

General Notes:
	you can not have more than one item in the database with the same
	exact kid info.

---------------------------------------------------------------------------
*/
short db_StoreItem(ulong db_session, DB_Kid *kid, DB_Data *data, long *HashValue, long storeFlag)
{
	DB_Session_Struct	 *session;
	long	new_hash_val = 0;	   /* The new hash value. */
	long	elem_loc;		 /* The location in storage table. */
	long	file_adr;		 /* The offset of new space in the file.  */
	long	file_pos;		 /* The position after a lseek. */
	long	num_bytes;		/* Used for error detection. */
	long	free_adr;		 /* For keeping track of a freed section. */
	long	free_size;		/* how big the free section is in bytes */
	long	saveHash = 0;
	long	new_size = 0;		 /* Used in allocating space. */
	long AssociatedHash = -1;	/* Hash associated with object */
	char	*temp = NULL;		  /* Used in dbu_findkey call. */
	short   err;

	DB_Kid temp_kid;
	/* check caller's parameters */
	if( (db_session == 0) ||
		(kid == NULL) ||
		(data == NULL) )
		return(DB_BAD_PARAM);

	/* get the session ref value */
	session = (DB_Session_Struct *) db_session;

	/* check to see if this session is set for write
	 * access to the file.
	 */
	if ((session->access != DB_WRITE) && (session->access != DB_RDWR))
	{
		return(DB_NO_WRITE)  ;
	}

	/* check to make sure the keying identifier and the data contents
	 * structs have valid ptrs.
	 */
	if((data->item_ptr == NULL) || (data->item_len <= 0))
	{
		return(DB_BAD_DATA);
	}

	if((kid->item_ptr == NULL) || (kid->item_len <= 0))
	{
		return(DB_BAD_KID);
	}

	if (*HashValue != 0)
		AssociatedHash = *HashValue;
	*HashValue = 0;
	/* see if a kid exists in the file that matches the given one.
	 * This will load the corresponding chunk and calculate the
	 * hash at the same time.
	 */

	temp_kid.item_len = kid->item_len;
	temp_kid.item_ptr = kid->item_ptr;

	/* make sure the storage block for the given kid is currently loaded,
	 * also insuring that this block will be the current cached block.
	 * Hash value shifted down to figure out the index into the directory
	 * offsets array.
	 */
//	new_hash_val = dbu_hash (NORMALIZED, kid);

	new_hash_val = 0;
	err = db_RetrieveHash(db_session, &temp_kid, 
				   &new_hash_val);
    if (err == DB_NOT_FOUND)
		db_CalcHash (db_session, &temp_kid, NULL, NORMALIZED, &new_hash_val,
					AssociatedHash, storeFlag);
	err = dbu_get_block (session, new_hash_val>> (31-session->dbheader->dir_bits));
	if(err != DB_NO_ERR)
	{
		return(err);
	}
	elem_loc = dbu_findkey (session, &temp_kid, &temp, &new_hash_val, NORMALIZED); /* ret storage table index val */

	*HashValue = new_hash_val;
	/* either accept a not found, or found, other errors we will
	 * report back to the caller right away.
	 */
	if(elem_loc < 0)
	{
		if(elem_loc != DB_NOT_FOUND)
		{
			if (temp)
			{
				free (temp);
				temp = NULL;
			}
			return (short)elem_loc;		/* contains other err value */
		}

	}

	/* did we find an item that matches */
	if (elem_loc >= 0)		/* neg values  == item not found or other errors */
	{
		/* item exits, did the caller want to replace */
		if (storeFlag == DB_REPLACE)
		{
			/* yep. We only need to replace the
			 * contents. Set up so that when we fall down
			 * below we just add the given contents.
			 */

			/* get the file offset and size of the old data so
			 * that we can mark it as free for future use.
			 */
			 free_adr = session->storage_map->se_table[elem_loc].data_pointer;
			 free_size = session->storage_map->se_table[elem_loc].kid_size
			 + session->storage_map->se_table[elem_loc].data_size;

			/* mark this area in the file as available for future
			 * use.
			 */
			err = dbu_free (session, free_adr, free_size);

			if(err != DB_NO_ERR)
			{
				return(err);	/* tell caller we failed */
			}
		}
		else	/* caller wanted to insert, but kid exists */
		{
			return(DB_NO_INSERT);
		}
	}

	/* Try to allocate storage for this entry in the data base
	 * file. If the item will fit into the free space of the current
	 * cached block, then no new allocation of hard storage must
	 * be made, other wise the file will be appended to...
	 */

	/* calc size of this entry (kid + data size) */
	new_size = kid->item_len + data->item_len;

	/* see if there is room in the current cache chunk, if not
	 * a new block will be appended to the file.
	 */
	file_adr = dbu_alloc (session, new_size);	 /* get file offset to avail space */

	/* make sure we were able to allocate file storage */
	if(file_adr < 0)	/* if err's then value will be a neg error value */
	{
		/* pass the error value back up to caller */
		return (short)file_adr;
	}

	/* Check again to see if our previous search for the given kid found
	 * a match. If not then we need to create a new storage element.
	 */
	if (elem_loc == DB_NOT_FOUND)   /* does this item not exist yet */
	{
		/* this is a new item */

		/* see if we are maxed out on number of entries for the
		 * current storage block.
		 */
		if (session->storage_map->count == session->dbheader->max_store_elems)
		{
			/* Split the current block. */
			err = dbu_split_storageTable (session, new_hash_val);

			if(err != DB_NO_ERR)
			{
				return(err);	/* tell caller we failed */
			}
		}

		/* Find space to insert into storage table and set elem_loc to that place. */
		elem_loc = new_hash_val % session->dbheader->max_store_elems;

		/* skip through the hash entries till we find one that is not
		 * used.
		 */
		saveHash = *HashValue;
		while (session->storage_map->se_table[elem_loc].hash_value != -1)	 /* -1 == empty hash value */
		{
			new_hash_val++;
			elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems; /* make sure we wrap around */
			saveHash ++; // update hash so that we store the correct value
		}

		/* We now have a location to put our new entry into the
		 * storage table, insert it's information.
		 */
		*HashValue = saveHash;
		session->storage_map->count += 1;	 /* inc our count, we are adding one */

		/* store the hash of the new item and the associated hash */
		session->storage_map->se_table[elem_loc].hash_value = new_hash_val;
		session->storage_map->se_table[elem_loc].SiblingHash = AssociatedHash;
		/* we only keep 'SMALL_KID' number of actual key id value bytes in
		 * the hash table for the corresponding hash. (currently 4 bytes)
		 */
		memcpy (session->storage_map->se_table[elem_loc].kid_start,
			kid->item_ptr, (SMALL_KID < kid->item_len ? SMALL_KID :kid->item_len));
	}

	/* done inserting or replacing the entry. */

	/* now we update the current storage table information for
	 * this entry (file offset and sizes).
	 */
	session->storage_map->se_table[elem_loc].data_pointer = file_adr;
	session->storage_map->se_table[elem_loc].kid_size = kid->item_len;
	session->storage_map->se_table[elem_loc].data_size = data->item_len;

	/* move to the correct offset, then write it out */
	file_pos = lseek (session->file, file_adr, SEEK_SET);

	if (file_pos != file_adr)
	{
		return(DB_SEEK_ERR);
	}

	/* save out the keying identifier */
	num_bytes = thread_write (session->file, session->fileStream, kid->item_ptr, kid->item_len);
	if (num_bytes != kid->item_len)
	{
		return(DB_WRITE_ERR);
	}

	/* save out the associated data */
	num_bytes = thread_write (session->file, session->fileStream, data->item_ptr, data->item_len);
	if (num_bytes != data->item_len)
	{
		return(DB_WRITE_ERR);
	}

	/* Current cached block has changed. */
	session->current_cache_entry->ca_changed = TRUE;	/* the particular entry changed */
	session->cur_cache_changed = TRUE;
	/* this cached block changed */

	/* Make sure that directory and other information (header, etc)
	 * is stored to disk as needed.
	 */
	/* Flush the data to the file */
	fflush (session->fileStream);

	err = dbu_end_update (session);

	return(err);	/* tell caller how we worked out */

}




/*
---------------------------------------------------------------------------
	
db_GetHash()

short db_GetHash(DB_Kid *kid, long norm_type, long **HashValue)

  This routine is used to get the 31 bit hash value of the
  Kid that is passed in.

  Parameters:
  DB_Kid (input) = The data to hash.

  norm_type (input) = Normalize Type

  HashValue (output) = The hash value of the data
---------------------------------------------------------------------------
*/	
short db_GetHash(DB_Kid *kid, long norm_type, long *HashValue)
{
	if ((kid == NULL) || (*HashValue != 0))
		return SRL_INVALID_PARAMETER;
	*HashValue = dbu_hash (norm_type, kid);
	return SRL_SUCCESS;
}

/*
---------------------------------------------------------------------------
	
db_CheckItem()

short db_CheckItem(DB_Kid *kid, long norm_type, long relatedHash, long **HashValue)

  This routine is used to check that the hash value is pointing
  to an empty element location for the input item. If not, this
  routine will modify the hash value (HashValue) to the proper hash
  that is related to the element location. If storeFlag is set to 
  DB_REPLACE, then db_CheckItem will try to get the hash out of the
  cache. This function will also ensure that the returned hash value
  is not a value equal to the relatedHash that is passed in.

  Parameters:
  ulong db_session = Data base session

  DB_Kid (input) = The data to hash.

  DB_Data (input) = Data base data 

  relatedHash (input)  = The related hash value
  HashValue (output) = The hash value of the data

  long storeFlag = Type of check INSERT or REPLACE
---------------------------------------------------------------------------
*/
short db_CheckItem(ulong db_session, DB_Kid *kid, DB_Data *data, 
				   long *HashValue, long relatedHash, long storeFlag)
{
   DB_Session_Struct	 *session;
   long	new_hash_val = 0;	   /* The new hash value. */
   long	elem_loc = 0;		 /* The location in storage table. */
   long	saveHash = 0;
   char	*temp = NULL;		  /* Used in dbu_findkey call. */
   short   err = SRL_SUCCESS;


   DB_Kid temp_kid;
   /* check caller's parameters */
   if( (db_session == 0) ||
      (kid == NULL) )
      return(DB_BAD_PARAM);
   data = data;

   /* get the session ref value */
   session = (DB_Session_Struct *) db_session;
   // If DB_REPLACE, then get the hash from storage, don't create it
   if (storeFlag == DB_REPLACE)
   {
      err = db_RetrieveHash(db_session, kid, &new_hash_val);
      if (err == DB_NO_ERR)
         *HashValue = new_hash_val;
   }
   else
   {

      if((kid->item_ptr == NULL) || (kid->item_len <= 0))
      {
         return(DB_BAD_KID);
      }

      if (*HashValue != 0)
         new_hash_val = *HashValue;
      /* see if a kid exists in the file that matches the given one.
      * This will load the corresponding chunk and calculate the
      * hash at the same time.
      */

      temp_kid.item_len = kid->item_len;
      temp_kid.item_ptr = kid->item_ptr;
      elem_loc = dbu_findkey (session, &temp_kid, &temp, &new_hash_val, NORMALIZED); /* ret storage table index val */
      *HashValue = new_hash_val;
      /* either accept a not found, or found, other errors we will
      * report back to the caller right away.
      */



      /* Try to allocate storage for this entry in the data base
      * file. If the item will fit into the free space of the current
      * cached block, then no new allocation of hard storage must
      * be made, other wise the file will be appended to...
      */


      /* Check again to see if our previous search for the given kid found
      * a match. If not then we need to create a new storage element.
      */
      if (elem_loc == DB_NOT_FOUND)   /* does this item not exist yet */
      {
         /* this is a new item */

         /* see if we are maxed out on number of entries for the
         * current storage block.
         */
         if (session->storage_map->count == session->dbheader->max_store_elems)
         {
            /* Split the current block. */
            err = dbu_split_storageTable (session, new_hash_val);

            if(err != DB_NO_ERR)
            {
               return(err);	/* tell caller we failed */
            }
         }
         if (storeFlag == DB_INSERT)
         {
            /* Find space to insert into storage table and set elem_loc to that place. */
            elem_loc = new_hash_val % session->dbheader->max_store_elems;

            /* skip through the hash entries till we find one that is not
            * used.
            */
            saveHash = *HashValue;
            if (saveHash == relatedHash)
            {
               // Bump up
               saveHash ++;
               elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems;
            }
            while (session->storage_map->se_table[elem_loc].hash_value != -1)	 /* -1 == empty hash value */
            {
               new_hash_val++;
               elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems; /* make sure we wrap around */
               saveHash ++; // update hash so that we store the correct value
               if (saveHash == relatedHash)
               {
                  // Bump the hash value and element location up 1
                  saveHash ++;
                  elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems;
               }
            }

            /* We now have a location to put our new entry into the
            * storage table, insert it's information.
            */
            *HashValue = saveHash;
         }
      }
   }
   return(err);	/* tell caller how we worked out */

}

short db_RetrieveHash(ulong db_session, DB_Kid *kid,  
			   long *HashValue)
{
	DB_Session_Struct	 *session;
	char *full_kid;
	long	elem_loc = 0;		 /* The location in storage table. */
	long	max_loc = 0;
	long	kid_size = 0;
	short   err = SRL_SUCCESS;

	/* check caller's parameters */
	if( (db_session == 0) ||
		(kid == NULL) )
		return(DB_BAD_PARAM);


	/* get the session ref value */
	session = (DB_Session_Struct *) db_session;
    // If DB_REPLACE, then get the hash from storage, don't create it
	/* make sure the storage block for the given kid is currently loaded,
	 * also insuring that this block will be the current cached block.
	 * Hash value shifted down to figure out the index into the directory
	 * offsets array.
	 */

		err = dbu_get_block (session, 0);


		elem_loc = -1; // Start at zero

		max_loc = session->dbheader->max_store_elems;
			err = DB_NOT_FOUND;  // Default return value
			while (TRUE)
			{
				full_kid = NULL;
				elem_loc ++;
				if (elem_loc == session->dbheader->max_store_elems)
				{
					// Get the next block
				/* we scanned to the end of the current storage block,
				 * time to make the dounuts, I mean load the next one
				 * if any.
				  */
				elem_loc = -1;   /* want 1st of next block */

				/* Get the next block.  It is possible several entries in
				 * the index directory point to the same block file offset, so
				 * move foreward past the last cached block we had.
				 */
				while (((ulong)session->storage_map_dir < 
					(session->dbheader->dir_size / sizeof(long)))
					&& (session->current_cache_entry->ca_adr ==
					session->dir_table[session->storage_map_dir]))
				{
					/* inc dir table index */
					session->storage_map_dir++;
				}
				/* now check to see if there exists a storage block for
				 * this next directory table entry. (haven't passed the end)
				 */
				if ((ulong)session->storage_map_dir < 
					(session->dbheader->dir_size / sizeof(long)))
				{
					 /* load the block */
					err = dbu_get_block (session, session->storage_map_dir);
					if(err != DB_NO_ERR)
					{
						return(err);	/* tell caller we failed */
					}
				}
				else
				{
					/* no more blocks, hit the end, return to caller */
					return(DB_NOT_FOUND) ;
				}
			}
			if (session->storage_map->se_table[elem_loc].hash_value != -1)
			{
					kid_size = session->storage_map->se_table[elem_loc].kid_size;
					/* skip through the hash entries until we find one that 
					 * matches
					 */
					full_kid = NULL;
					if ((kid_size == kid->item_len)
						&& ((SRLi_memicmp(session->storage_map->se_table[elem_loc].kid_start, kid->item_ptr,
						(SMALL_KID < kid_size ? SMALL_KID : kid_size))) == 0))
					{
							/* Otherwise we may have a possible match. For exact match
							 * we have to do a full comparison of the kids.  The block
							 * is cached, but the entry pair may not be, so make sure
			                 * it's read in.
			                 */

							/* make sure this entry is loaded, and get the kid */
							err = dbu_read_entry (session, elem_loc, &full_kid);
							if(err != DB_NO_ERR)
							{
								return(err);
							}

							/* see if we have exact match on kid's */
//							if (SRLi_memicmp (full_kid, kid->item_ptr, kid_size) == 0)
							if (full_kid)
							{
								if (SRLi_memicmp (full_kid, kid->item_ptr, kid_size) == 0)
								{
									/* We have found the exact item,
									* give caller ptr to associated data
									* and it's index location.
									*/
									*HashValue = session->storage_map->se_table[elem_loc].hash_value;
									err = SRL_SUCCESS;
									return err;
								
								}
								
							

							}/* end of possible match, do in depth comparison */
					}
				}
				/* Inc index, wrap around if necessary. */

		}		
		return(err);	/* tell caller how we worked out */

}

/*
---------------------------------------------------------------------------
	
db_CalcHash()

short db_CalcHash(ulong db_session, DB_Kid *kid, DB_Kid *data, long norm_type, 
				long **HashValue, long relatedHash, long storeflag)

  This routine is used to get the 31 bit hash value of the
  Kid that is passed in. It also ensures that the hash value
  returned equates to a empty elememt location

  Parameters:
  DB_Kid *kid(input) = The data pointer to the kid

  DB_Kid *data(input) = The data pointer to the data

  long norm_type (input) = Normalize Type

  long HashValue (output) = The hash value of the data

  long storeFlag = The type of hash to perform:
					DB_INSERT = Calculate new hash
					DB_REPLACE = Retrieve the hash from the cache


---------------------------------------------------------------------------
*/
	
short db_CalcHash(ulong db_session, DB_Kid *kid, DB_Kid *data, long norm_type, 
				  long *HashValue,  long relatedHash, long storeFlag)
{
	short err = 0;
	long checkHash = 0; // Hash Value from CheckItem
	long tempHash = 0;  // Hash Value from dbu_hash

	if ((kid == NULL) || (*HashValue != 0))
		return SRL_INVALID_PARAMETER;
	tempHash = dbu_hash (norm_type, kid);
	/*
		Ensure that the hash value equates to an empty element location 
		and not a hash value represented by value in HashValue
	*/
	checkHash = tempHash; // Pass in the temporary hash value
	err = db_CheckItem(db_session, kid, data, 
						&checkHash, relatedHash, storeFlag);
	if (err == SRL_SUCCESS)
		*HashValue = checkHash;

	return err;
}


/*
---------------------------------------------------------------------------

db_GetEntry()

short db_GetEntry(ulong db_session, long inHash, DB_Kid *kid, DB_Data **data)

This routine is used to get a particular entry from the database associated
with the indicated session.  The entry is identified by the key entry info,
the data for that item will be placed into a new allocated memory block which
the caller will have to free up at some time. (DB_Data structure allocated
and filled in).

Parameters:
	db_session (input) = the session parameter that was returned from a
		call to db_Open().

    inHash (input) = Hash value to use in getting entry (0 = hash
					 not known).

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

short db_GetEntry(ulong db_session, long inHash, DB_Kid *kid, DB_Data **data)
{
	DB_Data			 *foundData = NULL;
	DB_Session_Struct	 *session;
	long				elem_loc;		 /* The location in the storage_map. */
	char				*find_data;		 /* Returned from find_key. */
	long				hash_val = 0;		 /* Returned from find_key. */
	DB_INFO_Struct		*info = NULL;
	if((db_session == 0) || (kid == NULL) || (data == NULL))
		return(DB_BAD_PARAM);

	if((kid->item_ptr == NULL) || (kid->item_len <= 0))
		return(DB_BAD_KID);

	*data = NULL;   /* start the caller with nothing */

	/* get the session ref value */
	session = (DB_Session_Struct *) db_session;
	/* make sure the caller has read access */
	if(session->access == DB_WRITE) /* basically write only is only non read type */
		return(DB_NO_READ);


	/* allocate our storage for found data */
	foundData = (DB_Data *) calloc(1, sizeof(DB_Data));
	if(foundData == NULL)
	{
		return(DB_NO_MEM);
	}

	/* start out with no data found */
	foundData->item_ptr  = NULL;
	foundData->item_len = 0;

	find_data = NULL;	 /* start out empty */
	(void) lseek(session->file, 0, SEEK_SET);

	/* Two options for inHash:
	 * 1. inHash = 0 let db_GetEntry calcuate the hash
	 * or
	 * 2. inHash is already known, just set the hash_val to inHash
	 */
	if (inHash == 0)
	{
		db_RetrieveHash(db_session, kid, 
				   &hash_val);
	}
	else
		hash_val = inHash;

	/* search for the kid - get the index of it's element entry in the
	 * current block, plus get a ptr to it's data and it's hash value.
	 */
	elem_loc = dbu_findkey (session, kid, &find_data, &hash_val, NORMALIZED);

	if(elem_loc < 0)	/* did an error occur */
	{
//		(void) db_Info((ulong)session, &info);
//		if (info->data == DATA_BASE_HEADER_VERSION_OLD)
//			elem_loc = dbu_findkey (session, kid, &find_data, &hash_val, NOT_NORMALIZED);
		db_FreeDBInfo(&info);
		info = NULL;
		if (elem_loc < 0)
		{
			free(foundData);
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
		return(DB_NOT_FOUND);   /* should we indicate otherwise? */
	}

	foundData->item_ptr = (char *) calloc (1,foundData->item_len);

	if (foundData->item_ptr == NULL)
	{
		free(foundData);
		return(DB_NO_MEM);
	}

	/* copy it from the given ref to new storage */
	memcpy ( foundData->item_ptr, find_data, foundData->item_len);

	/* give caller access to the structure */
	*data = foundData;
	return(DB_NO_ERR);	/* tell caller we succeeded */

}


/*
---------------------------------------------------------------------------

db_DeleteEntry()

short db_DeleteEntry(ulong db_session, DB_Kid *kid)

This routine is used to delete a particular item from the database. The routine
removes the hashed entry in the index directory so that the associated data in the db
file will no longer be accessible.  The database file is updated to reflect the
new directory information before returning.  File space used by this item will
be marked as free for future use.

Paramters:
	db_session (input) = the session parameter that was returned from a
		call to db_Open().

	kid (input) = the keying identifier (info used to represent the data
		that is to be deleted.) for the entry of interest.

returns:
	one of the following error codes will be returned

	DB_NO_ERR		- everything fine
	DB_BAD_PARAM	- bad parameter passed to this routine
	DB_BAD_KID		- bad keying identifier
	DB_NOT_FOUND	- no entry for given kid found in database
	DB_CANT_DELETE  - db file not open for writing, therefore no delete

	other error codes from subroutines are possible
	DB_SEEK_ERR
	DB_WRITE_ERR
	DB_READ_ERR

---------------------------------------------------------------------------
*/

short db_DeleteEntry(ulong db_session, DB_Kid *kid)
{
	DB_Session_Struct	 *session;
	DB_INFO_Struct		*info = NULL;

	long	elem_loc;		 /* The location in the current hash storage_map. */
	long	last_loc;		 /* Last location emptied by the delete.  */
	long	home;		   /* Home position of an item. */
	storage_element elem;   /* The element to be deleted. */
	char	*find_data = NULL;		 /* Return pointer from findkey. */
	long	hash_val = 0;		 /* Returned by findkey. */
	long	free_adr;		 /* Temporary stroage for address and size. */
	long	free_size;
	short   err;
	/* check the paramters */
	if((db_session == 0) || (kid == NULL))
		return(DB_BAD_PARAM);

	/* make sure we have valid key data */
	if((kid->item_ptr == NULL) || (kid->item_len <= 0))
		return(DB_BAD_KID);

	/* get the session ref value */
	session = (DB_Session_Struct *) db_session;

	/* make sure the caller has write access */
	if(session->access == DB_READ)  /* is it read only */
		return(DB_CANT_DELETE);

	err = db_CalcHash(db_session, kid, NULL,  NORMALIZED, 
				  &hash_val, 0, DB_REPLACE);

   if (err != DB_NO_ERR)
      return err;

	/* search the db to see if there is an item with this key */
	elem_loc = dbu_findkey (session, kid, &find_data, &hash_val, NORMALIZED);

	/* see if we found it */
	if (elem_loc < 0)
	{
		(void) db_Info((ulong)session, &info);
		if (info->data == DATA_BASE_HEADER_VERSION_OLD)
			elem_loc = dbu_findkey (session, kid, &find_data, &hash_val, NOT_NORMALIZED);
		db_FreeDBInfo(&info);
		info = NULL;
		if (elem_loc < 0)
		{
			return (short)elem_loc;	 /* tell caller it does not exist, or err */
		}

	}
	/* record it's storage table index for later  */
	elem = session->storage_map->se_table[elem_loc];
	session->storage_map->se_table[elem_loc].SiblingHash = -1;

	/* mark the hash entry as empty (-1 means no has value there)  */
	session->storage_map->se_table[elem_loc].hash_value = -1;

	/* dec our table count, there will be one less entry */
	session->storage_map->count -= 1;

	/* Shift the elements to account for our removal */
	last_loc = elem_loc;	/* start where we removed */

	/* address the next entry */
	elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems; /* wrap if need be */

	/* step through the storage map and shift the entries till we find
	 * the last one (not in use == -1) or we wrap around to our starting point.
	 */
	while (elem_loc != last_loc && session->storage_map->se_table[elem_loc].hash_value != -1)
	{
	/* get the index value */
		home = session->storage_map->se_table[elem_loc].hash_value
		 % session->dbheader->max_store_elems;	/* make sure we wrap */

		if ( (last_loc < elem_loc && (home <= last_loc || home > elem_loc))
			|| (last_loc > elem_loc && home <= last_loc && home > elem_loc))

		{
			/* shift it over */
			session->storage_map->se_table[last_loc] = session->storage_map->se_table[elem_loc];
			session->storage_map->se_table[elem_loc].hash_value = -1;
			session->storage_map->se_table[elem_loc].SiblingHash = -1;
			last_loc = elem_loc;
		}

		/* move onto next one */
		elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems;
	}

	/* Mark this entries file space in the block available for future use. */
	free_adr = elem.data_pointer;	   /* file offset */
	free_size = elem.kid_size + elem.data_size;		 /* how much we are freeing */
	err = dbu_free (session, free_adr, free_size);
	if(err != DB_NO_ERR)
		return(err);	/* tell caller we failed */

	/* The cached data for this block has been modified, set the flag. */
	session->cur_cache_changed = TRUE;

	/* Clear out the data cache for the current cached item. */
	if (session->current_cache_entry->ca_data.dptr != NULL) /* was this pair in cahced mem */
	{
		free (session->current_cache_entry->ca_data.dptr);	/* free it's ram storage */
		session->current_cache_entry->ca_data.dptr = NULL;
	}
	session->current_cache_entry->ca_data.hash_val = -1;	/* mark it - not in use */
	session->current_cache_entry->ca_data.SiblingHash = -1;	/* mark it - not in use */
	session->current_cache_entry->ca_data.kid_size = 0;
	session->current_cache_entry->ca_data.elem_loc = -1;	/* no storage index ref now */

	/* make sure the changes we made for the block are written to
	 * disk,  and other data based on the avail changes we made. (dir, header, etc)
	 */
	err = dbu_end_update (session);

	return(err);	/* tell caller if it worked */
}

/*
---------------------------------------------------------------------------

db_GetDBItemsByID()

db_GetDBItemsByID(ulong db_session, long dbID, DB_Data **data1, DB_Data **data2 )
This routine is used to get a particular entries from the database associated
with database ID.  The entries are identified by the key entry info,
the data for that item will be placed into a new allocated memory block which
the caller will have to free up at some time. (DB_Data structure allocated
and filled in).

Parameters:
	db_session (input) = the session parameter that was returned from a
		call to db_Open().

	dbID (input) = Data Base Id of the associated item

	data1 (in/out) = ptr storage, will point to retrieved data in DB_Data on
		sucessful completion.

  	data2 (in/out) = ptr storage, will point to retrieved data in DB_Data on
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

static short db_GetDBItemsByID(ulong db_session, long dbID, 
							   DB_Item **Kid1, DB_Data **data1,
							   DB_Item **Kid2, DB_Data **data2)
{
	short err;
	DB_Data			 *foundData = NULL, *Sib_data = NULL;
	DB_Session_Struct	 *session;
	DB_Kid            *entry_kid = NULL,*Sib_kid = NULL;
	long				elem_loc;		 /* The location in the storage_map. */
	long				sibID = 0, sibIDs = 0;		 /* Returned from find_key. */
	if((db_session == 0) || (data1 == NULL))
		return(DB_BAD_PARAM);
	/* get the session ref value */
	session = (DB_Session_Struct *) db_session;


	*data1 = NULL;   /* start the caller with nothing */
	*data2 = NULL;   /* start the caller with nothing */

	/* get the session ref value */
	session = (DB_Session_Struct *) db_session;

	/* make sure the caller has read access */
	if(session->access == DB_WRITE) /* basically write only is only non read type */
	{
		return(DB_NO_READ);
	}


	/* Make sure that we start searching with the 1st directory/index
	 * entry loaded (ie dir_table[0] )
	 */
	err = dbu_get_block (session, 0);

	entry_kid = (DB_Kid *)calloc (1, sizeof (DB_Kid));
	sibID = 0;

	elem_loc = -1; // Start at zero

	/* Get the Kid and the sibling ID associated with this ID */
	err = dbu_getIDKids (session, elem_loc, dbID, &sibID, entry_kid);
	if(err != DB_NO_ERR)
	{
		free(entry_kid);
	}
	if (entry_kid->item_ptr == NULL)
	{
		free (entry_kid);
		return DB_NOT_FOUND;
	}

	Sib_kid = (DB_Kid *)calloc (1, sizeof (DB_Kid));

	err = dbu_get_block (session, 0);

	elem_loc = -1; // Start at zero

	sibIDs = sibID;
	// Get sibling information based on the sibID returned
	err = dbu_getIDKids (session, elem_loc, sibIDs, &sibID, Sib_kid);
	if(err != DB_NO_ERR)
	{
		free(entry_kid);
		return err;
	}

   /* get the corresponding data (cert or crl) for this entry */
   err = db_GetEntry(db_session, dbID, entry_kid,  &foundData);
   err = DB2SRLerr(err);

      /* get the corresponding data (cert or crl) for this entry */
   err = db_GetEntry(db_session, 0, Sib_kid,  &Sib_data);
   err = DB2SRLerr(err);

   // Pass data back to caller
	*Kid1 = entry_kid;
	*Kid2 = Sib_kid;
	*data1 = foundData;
	*data2 = Sib_data;

	return err;
}


/*
---------------------------------------------------------------------------

db_GetFirstKid()

short db_GetFirstKid(ulong db_session, DB_Kid **kid)

This routine will return the keying identifier for the first entry in the
database associated with the given session.  One would use this routine
followed by db_GetNextKid() to sequencially step through the items in
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
returned, they would then make a call to db_GetEntry() using the kid returned
from their call.
---------------------------------------------------------------------------
*/
short db_GetFirstKid(ulong db_session, DB_Kid **kid)
{
	DB_Session_Struct	 *session;
	DB_Kid			  *theKeyID;
	short			   err = DB_NO_ERR;

	/* check the paramters */
	if((db_session == 0) || (kid == NULL))
		return(DB_BAD_PARAM);

	// Lock the data base 
	*kid = NULL;	/* init to empty in case we fail */

	/* get the session ref value */
	session = (DB_Session_Struct *) db_session;

	/* allocate storage */
	theKeyID = (DB_Kid *) calloc(1, sizeof (DB_Kid));
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
	err = dbu_get_block (session, 0);
	if(err != DB_NO_ERR)
		goto done;	/* tell caller we failed */

	/* Get the kid for the first entry using dbu_get_next_kid
	 *  (-1 => next entry after -1 is entry 0)
	 * We get our own copy if it is found.
	 */
	err = dbu_get_next_kid (session, -1, theKeyID);
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
	return(err);
}


/*
---------------------------------------------------------------------------

db_GetNextKid()

short db_GetNextKid(ulong db_session, DB_Kid *kid, DB_Kid **next_kid)

This routine is used to "walk" through the entries in the database.  Calling
db_GetFirstKid() will return keying information for the first entry, and
then the caller would use db_GetNextKid() to access each suceeding entry
in the database.  The caller get's their own copy of the keying identifier
data, so once they no longer need the kid, they should free up the data and
the kid structure.

NOTE: If the caller wanted the actual data associated with any of the keys
returned, they would then have to make a call to db_GetEntry() using the kid
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

short db_GetNextKid(ulong db_session, DB_Kid *kid, DB_Kid **next_kid)
{
	DB_Session_Struct	 *session;
	DB_Kid	  *nextkeyID;
	char *find_data = NULL;
	long		elem_loc;		 /* The location in the storage_map. */
	long		hash_val;		 /* Returned by dbu_findkey. */
	short	   err = DB_NO_ERR;

	/* check the paramters */
	if((db_session == 0) || (kid == NULL) || (next_kid == NULL))
		return(DB_BAD_PARAM);

	if((kid->item_ptr == NULL) || (kid->item_len <= 0))
		return(DB_BAD_KID);

	/* init caller's to empty in case we don't find a next one */
	*next_kid = NULL;

	/* get the session ref value */
	session = (DB_Session_Struct *) db_session;

	/* allocate storage */
	nextkeyID = (DB_Kid *) calloc(1, sizeof (DB_Kid));
	if(nextkeyID == NULL)
	{
		return DB_NO_MEM;
	}

	nextkeyID->item_ptr = NULL;
	nextkeyID->item_len = 0;


	/* start out by finding the given precursor kid
	 * (and make sure it exists).
	 */
	err = db_RetrieveHash(db_session, kid, 
				   &hash_val);
	if (err != SRL_SUCCESS)
		return err;

	 elem_loc = dbu_findkey (session, kid, &find_data, &hash_val, NORMALIZED);

	hash_val = 0;

	/* Now get the next kid. (we will get a copy if found) */
	err = dbu_get_next_kid(session, elem_loc, nextkeyID);

	if(err != DB_NO_ERR)
	{
		free(nextkeyID);
		return(err);
	}
	/* did we find one ? */
	if((nextkeyID->item_ptr == NULL) || (nextkeyID->item_len <= 0))
	{
		free(nextkeyID);	/* nothing found, clean up */
		return(DB_NOT_FOUND);
	}
	/* found it, give it to the caller */
	*next_kid = nextkeyID;

	return(DB_NO_ERR);
}


/*
---------------------------------------------------------------------------

dbu_get_next_kid()

static void dbu_get_next_kid (DB_Session_Struct *db_session,long elem_loc,
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


static short dbu_get_next_kid (DB_Session_Struct *db_session,long elem_loc, DB_Kid *return_kid)
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
				err = dbu_get_block (db_session, db_session->storage_map_dir);
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
	err = dbu_read_entry (db_session, elem_loc, &find_data);
	if(err != DB_NO_ERR)
		return(err);
	return_kid->item_len = db_session->storage_map->se_table[elem_loc].kid_size;
	if (return_kid->item_len == 0)
		return(DB_NO_ERR);	/* nothing to give caller */

	return_kid->item_ptr = (char *) calloc (1, return_kid->item_len);

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

db_Compact()

short db_Compact(ulong db_session)

This routine is used to shrink the file space used by the database
associated with db_session. This will be useful when a lot of
deletions may have occured, and the caller wants the database to
be reorganized to free up that space. (The items in the file are not
acually compacted, just the space left from item deletions is
moved around for easy reuse.)


Paramters:
	db_session (input) = the session parameter that was returned from a
		call to db_Open(), associated with the db file to compact.

returns:
	one of the following error codes will be returned

	DB_NO_ERR			 - everything fine
	DB_NO_MEM			 - out of memory
	DB_BAD_PARAM		- bad parameter passed to this routine
	DB_NO_WRITE			 - db file not open for writing
	DB_COMPACT_FAILED	 - could not compact the file

General Notes:
	This routine will creates a new file and copies all the
non-marked-for-deletion items to the new file, renames the new file to be
the same as the old file, then delete the old file.  The index data will
be updated to reflect the new organization of the updated db file. The old
file will be left as is upon any error occurance.

Based on the above, you will not want to call this function too often since
it may take a while....

---------------------------------------------------------------------------
*/


short db_Compact(ulong db_session)
{

	DB_Session_Struct *old_session, *new_session;
	short	   err = 0;
	char		*new_name, *tempname2;
	long		index = 0;

	DB_Kid			*entry_kid = NULL,*prevEntry = NULL;
	DB_Item			*entry_data = NULL, *asnentry_data = NULL;	/* existing data */
	DB_Item			currentTemplate;
	char			*tempPtr = NULL;
	int				first_time = 0;
	int				addtolen = 0;
	long			len = 0, biglen = 0;
	entry_kid = 0;   /* none retrieved yet */
	prevEntry = 0;
	prevEntry = 0;
	entry_data = 0; /* Template data */
	asnentry_data = 0; /* ASN Blob (in this case - cert) */


	/* check the parameter */
	if(db_session == 0)
		return(DB_BAD_PARAM);

	/* get the session ref value */
	old_session = (DB_Session_Struct *) db_session;

	/* make sure the session was set up for write access to the db file */
	if(old_session->access == DB_READ)
		return(DB_NO_WRITE);	/* can't compact (write) if read only */

	/* our new database file will be the original file name + "_tmp" */
   new_name = calloc(1, strlen(old_session->name) + strlen("_tmp") + 1);
	if (new_name == NULL)
		return(DB_NO_MEM);
	sprintf(new_name, "%s_tmp", old_session->name);

	remove(new_name); /* delete the temp file in case one was left out there */

	/* Now we create a temp new data base, add all the
	 * callers database stuff to it
	 */

	err = db_Open((ulong *) &new_session, new_name,
		DB_NEW, old_session->dbheader->block_size);

	if((new_session == NULL) || (err != DB_NO_ERR))
	{
		free(new_name); /* clean up */
		if(err != DB_NO_ERR)
			return(err);

		return(err);
	}

	while (TRUE)
	{
		addtolen = 0;
		/* check to see if we need to get first entry in the database */
		if(first_time == 0)   /* if we didn't start list yet */
		{
			 err = db_GetFirstKid((ulong )old_session, &entry_kid);
			 first_time ++;
		}
		else
		{
			 err = db_GetNextKid((ulong )old_session, prevEntry, &entry_kid);

		}
		err = DB2SRLerr(err);

		if(err != SRL_SUCCESS)
		{
			if(err == SRL_NOT_FOUND)   /* are there no more entries */
			{
				err = SRL_SUCCESS;
				break;   /* all done looping */
			}

			/* couldn't get entry, fail, tell caller */
			(void) db_Close ((ulong *) &new_session);
			remove (new_name);	/* delete our new file */
			free(new_name);

			return(DB_COMPACT_FAILED);
		}


      /* if this is a dn entry index type item, record it */
      if( SRLi_isDN(entry_kid->item_ptr[0]))
      {


		/* Get the Data Base Entry for the template */
		 err = db_GetEntry((ulong )old_session, 0, entry_kid,  &entry_data);
         err = DB2SRLerr(err);
         if(err != SRL_SUCCESS)
		 {
			 /* couldn't get entry, fail, tell caller */
			(void) db_Close ((ulong *) &new_session);
			remove (new_name);	/* delete our new file */
			free(new_name);
			return(DB_COMPACT_FAILED);
		 }

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

				/* Get the entry associated with this template */
				err = db_GetEntry((ulong )old_session, 0, &currentTemplate,
									&asnentry_data);
				if (err != SRL_SUCCESS)
				{
					/* couldn't get entry, fail, tell caller */
					(void) db_Close ((ulong *) &new_session);
					remove (new_name);	/* delete our new file */
					free(new_name);
					return(DB_COMPACT_FAILED);
				}				
				err = AddObjectToDB ((ulong)new_session, entry_kid, &currentTemplate,
								asnentry_data);

				// Increment the lenght and pointer
				tempPtr += len;
				biglen -= len;
			   SRLi_FreeDB_Item(&asnentry_data);
			}
	   }

	   else
	   {
		 /* Get the Data Base entry for the cert */
		 err = db_GetEntry((ulong )old_session, 0, entry_data, &asnentry_data);
         if(err != SRL_SUCCESS)
		 {
			/* couldn't get entry, fail, tell caller */
			(void) db_Close ((ulong *) &new_session);
			remove (new_name);	/* delete our new file */
			free(new_name);
			return(DB_COMPACT_FAILED);
		 }		
		 /*
		  * We have both the template and cert so
		  * now store into the new Database version
		  */

		  err = AddObjectToDB ((ulong)new_session, entry_kid, entry_data, 
			         asnentry_data);
		  SRLi_FreeDB_Item(&asnentry_data);
        SRLi_FreeDB_Item(&entry_data); 
		}
	  }
     SRLi_FreeDB_Item(&prevEntry);
     SRLi_FreeDB_Item(&entry_data);
	  prevEntry = entry_kid;   /* record for next loop iteration */

	}

	/* We finished copying all the entries in the old database
	 * to the new database, now make sure all the directory information
	 * is written out to the new database file.
	 */
	err = dbu_end_update (new_session);
	if(err != DB_NO_ERR)
	{
		/* couldn't get entry, fail, tell caller */
		(void) db_Close ((ulong *) &new_session);
		remove (new_name);	/* delete our new file */
		free(new_name);
		return(DB_COMPACT_FAILED);
	}


	/* Rename the new file so that it uses
	 * the same name as the old file.
	 * (Rename will delete the old copy as we give it
	 * the name).  Create a temp var with the fullpath and
	 * filename of the old database file.
	 */
	close (old_session->file);

	/* we want to rename the new file so that it uses the sessions
	 * file name.  Since this may fail - try to rename the old file
	 * to "original_db_name_old"   while we attempt to rename. IF that
	 * works we will then delete the old file.....
	 */
   tempname2 = calloc (1, strlen(old_session->name) +
                          strlen("_old") + 1);

	if (tempname2 == NULL)
	{
		remove (new_name);	/* delete our new file */
		free(new_name);
		return(DB_NO_MEM);
	}
	sprintf(tempname2, "%s_old", old_session->name);

	remove(tempname2); /* in case there is an old copy lying around, remove it so rename works */
	rename (old_session->name, tempname2); /* temp rename the older before replacing */

	/* have to temp close the new file during rename, else it fails in windows */
	close(new_session->file);

	if (rename (new_name, old_session->name) != 0)	/* existing_oldname, requesting_newname */
	{
		/* failed to rename..... bad day i guess */
		(void) db_Close ((ulong *) &new_session);
		remove (new_name);	/* delete our new file */
		free(new_name);
		return(DB_COMPACT_FAILED);
	}
	/* reopen it */
	new_session->file = thread_open(old_session->name, O_RDWR | O_BINARY, -1);
   new_session->fileStream = fdopen(new_session->file, "wb+");

	remove(tempname2); /* delete old file since rename worked. */
	free(tempname2);

	/* Done with the old file, now start updating with the new information */
	free (old_session->dbheader);   /* will replace with new header info */
	free (old_session->dir_table); /* will replace with new index/dir info */
	free(new_name); 
	new_name = NULL;
	/* free up any memory used by the old cache */
	if (old_session->cached_blocks != NULL)
	{
		for (index = 0; index < old_session->cache_size; index++)
		{
			if (old_session->cached_blocks[index].ca_block != NULL)
				free(old_session->cached_blocks[index].ca_block);
			if (old_session->cached_blocks[index].ca_data.dptr != NULL)
				free(old_session->cached_blocks[index].ca_data.dptr);
		}
		free (old_session->cached_blocks);
	}

	/* copy the new info back into old session for callers
	 * future use.
	 */
	old_session->file                = new_session->file;
   old_session->fileStream          = new_session->fileStream;
	old_session->dbheader            = new_session->dbheader;
	old_session->dir_table           = new_session->dir_table;
	old_session->storage_map         = new_session->storage_map;
	old_session->storage_map_dir     = new_session->storage_map_dir;
	old_session->idx_of_last_read    = new_session->idx_of_last_read;
	old_session->cached_blocks       = new_session->cached_blocks;
	old_session->cache_size          = new_session->cache_size;
	old_session->dbheader_changed    = new_session->dbheader_changed;
	old_session->directory_changed   = new_session->directory_changed;
	old_session->cur_cache_changed   = new_session->cur_cache_changed;
	old_session->second_changed      = new_session->second_changed;
	free (new_session->name);
	free (new_session);	 /* don't need the temp session anymore */

	/* Start the caching back at the begining. */
	old_session->current_cache_entry	= &old_session->cached_blocks[0];

	/* make sure the initial directory is loaded */
	err = dbu_get_block (old_session, 0);   /* load dir_table[0] */

	SRLi_FreeDB_Item(&entry_data);
   SRLi_FreeDB_Item(&asnentry_data);
	SRLi_FreeDB_Item(&prevEntry);
	return (err);
	
	
}
short AddObjectToDB(ulong db_session, DB_Kid *DNKid, 
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

		db_CalcHash (db_session, TemplateKid, NULL, NORMALIZED,
				&TempHashValue, 0, DB_INSERT);

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
			err = db_GetEntry(db_session, 0,lentry_kid,  &compare_data);
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

		big_block.data = calloc(1, big_block.num);

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
/*
---------------------------------------------------------------------------

db_Info()

short db_Info(ulong db_session, DB_INFO_Struct **info)

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
short db_Info(ulong db_session, DB_INFO_Struct **info)
{
	DB_Session_Struct	*session_ptr;
    DB_INFO_Struct      *DB_info_ptr;
	if(db_session == 0)
		return(DB_BAD_PARAM);
	/* just set up so caller doesn't think we have given them
	 * anything useful.
	 */
	session_ptr = (DB_Session_Struct *)db_session;
	DB_info_ptr = (DB_INFO_Struct *)calloc (1, sizeof (DB_INFO_Struct));
	DB_info_ptr->data = session_ptr->dbheader->header_ident;
	*info = DB_info_ptr;
	return(0);


}


/*
---------------------------------------------------------------------------

db_FreeDBInfo()

void db_FreeDBInfo(DB_INFO_Struct **info)

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
void db_FreeDBInfo(DB_INFO_Struct **info)
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
dbu_alloc()
dbu_free()
dbu_pop_avail_block()
dbu_push_avail_block()
dbu_get_avail_elem()
dbu_put_avail_elem()
dbu_allocate_block()
dbu_adjust_storage_avail()
dbu_init_storagetable()
dbu_init_cache()
dbu_get_block()
dbu_split_storageTable()
dbu_write_block()
dbu_write_header()
dbu_end_update()
dbu_read_entry()
dbu_hash()
dbu_findkey()
dbu_get_next_kid()

 * ---------------------------------------------------------------------------
 */

/*
---------------------------------------------------------------------------

dbu_alloc()

static long dbu_alloc (DB_Session_Struct *session,long num_bytes)

This low level routine is used to allocate space in the session database
file for a block that is "num_bytes" in length, returning the
file offset of the new block.  The routine will check the current storage
block to see if it's avail elements will meet the size requirement, and
if so then only this current storage block is effected. If this doesn't
work out, then the files header avail table is searched for elements that
would meet the requirment.  If we don't find available space in the file
avail table, then we actually end up allocating more space to the file
in file block sized chunks.  Any space greater than num_bytes will be
added to the files avail table for future use.

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

	num_bytes (input) = size in bytes of the space the caller is
		requesting for storage.


returns:
	The file offset for storage is returned. If an error occurs then
	the returned value will be one of the negative error values.

---------------------------------------------------------------------------
*/

static long dbu_alloc (DB_Session_Struct *session,long num_bytes)
{
	long		file_adr;		 /* The address of the block.
*/
	avail_elem	av_el;		  /* For temporary use. */
	short	   err;

		err = DB_NO_ERR;
	/* Check the current storage avail block for free space. We need an
	 * element of at least "num_bytes" in size. av_count will be set to
	 * number of elements in the available table.  storage_avail will
	 * be updated if one is found.
	 */
	av_el = dbu_get_avail_elem (num_bytes, session->storage_map->storage_avail,
		&session->storage_map->av_count);

	/* If we did not find some space in the current storage block, then
	 * we will need to check the files availablity table (ref'd off the header)
	 * for file space availability. If there is none that meets our needs, then
	 * we will break down and allocate more storage.
	 */
	if (av_el.avail_size == 0)	/* if no storage element of requested size available */
	{
		/* check to see if the header avail block empty and there is something on the stack. */
		if ((session->dbheader->avail.count == 0)		 /* if no more available in this block */
			&& (session->dbheader->avail.next_block != 0))  /* and a prev avail block was saved to disk */
			err = dbu_pop_avail_block (session);		/* load the stored available block table */

		if(err != DB_NO_ERR)
		{
			/* we either had trouble locating the avail block or
			 * we were unable to load it.
			 * Tell caller that nothing is available.  We could
			 * just try allocating a new one, but the file may be
			 * corrupted at this point, so I'm just returning.
			 */
			return(err);
		}

		/* at this point, either we loaded an avail table from disk (which must have
		 * some entries available) or we had some left in the current file avail table,
		 * so check for free space.
		 */
		av_el = dbu_get_avail_elem (num_bytes, session->dbheader->avail.av_table,
			&session->dbheader->avail.count);

		/* see if none available at all in the whole file, allocate if
		 * need be. (will allocate in multiples of block size so that
		 * all the data will fit and our file stays in block
		 * sized chunks)
		 */
		if (av_el.avail_size == 0)
			av_el = dbu_allocate_block (num_bytes, session); /* Get another full block from end of file. */

		/* mark changes flag since we've modified */
		session->dbheader_changed = TRUE;
	}

	/* At this point we know we have storage area
	 * which is available from which we will allocate
	 * the new space.
	 */
	file_adr = av_el.avail_floc;	/* file offset for the space */

	/* Mark the portion the caller wants as used, and the rest
	 * as available (if any).
	 */
	av_el.avail_floc += num_bytes;  /* inc file offset by amount requested */
	av_el.avail_size -= num_bytes;  /* dec amount available by amount requested */

	err = dbu_free (session, av_el.avail_floc, av_el.avail_size); /* mark unused portion as available */

	if(err != DB_NO_ERR)
		return(err);

	/* return to the caller the file offset */
	return file_adr;

}


/*
---------------------------------------------------------------------------

dbu_free()

static void dbu_free (DB_Session_Struct *session,long file_adr,long num_bytes)

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

static short dbu_free (DB_Session_Struct *session,long file_adr,long
num_bytes)
{
	avail_elem	temp;
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
			err = dbu_push_avail_block (session);   /* split & save it out to disk */
			if(err != DB_NO_ERR)
				return(err);	/* tell caller we failed */
		}

		/* at this point there is room to add another avail element */
		dbu_put_avail_elem (temp, session->dbheader->avail.av_table,
			&session->dbheader->avail.count);

		session->dbheader_changed = TRUE;	 /* we modified it */
	}
	else	/* free'ing up less than a block in size */
	{
		/* we will try to put into the current storage block's avail table . */
		if (session->storage_map->av_count < MAX_AVAIL) /* if not maxed out yet */
			dbu_put_avail_elem (temp, session->storage_map->storage_avail,
				&session->storage_map->av_count);
		else
		{
			/* else no room in current storage avail table, so fall back to
			 * the file avail table (in the header).  Make sure there is room
			 * first (split if need be).
			 */
			if (session->dbheader->avail.count == session->dbheader->avail.size)
			{
				err = dbu_push_avail_block (session);   /* split & save it out to disk */
				if(err != DB_NO_ERR)
					return(err);	/* tell caller we failed */
			}
			dbu_put_avail_elem (temp, session->dbheader->avail.av_table,
				&session->dbheader->avail.count);

			session->dbheader_changed = TRUE;
		}
	}

	/* if there wasn't room in the current storage blocks avail table, we
	 * had to update the header, make sure we balance the header's
	 * avail table for writing out.
	 */
	if (session->dbheader_changed)
		dbu_adjust_storage_avail (session);

	return(DB_NO_ERR);	/* all done here, return to caller */
}


/*
---------------------------------------------------------------------------

dbu_pop_avail_block()

static void dbu_pop_avail_block (DB_Session_Struct *session)

This low level routine is used to pull an avail block off the avail
stack and make it the active availability table (the file header
avail table).

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

returns:
	one of the following error codes will be returned

	DB_NO_ERR			 - everything fine
	DB_SEEK_ERR			 - file seek error
	DB_READ_ERR			 - file read i/o error

---------------------------------------------------------------------------
*/

static short dbu_pop_avail_block (DB_Session_Struct *session)
{
	long		num_bytes;		/* For use with the read system call. */
	long		file_pos;		 /* For use with the lseek system call. */
	avail_elem	temp;

	/* Need to read in the previously stored/pushed "next" avail block */
	temp.avail_floc = session->dbheader->avail.next_block;  /* file offset of avail block */

	/* total numb avail elements that will fit * size of element, div by 2 since
	 *  they are half full (split when written) plus size of the bookkeeping data.
	 */
	temp.avail_size = ( ( (session->dbheader->avail.size * sizeof (avail_elem)) >> 1)
		+ sizeof (avail_block));

	/* now read the block in from the file */
	file_pos = lseek (session->file, temp.avail_floc, SEEK_SET);
	if (file_pos != temp.avail_floc)
		  return(DB_SEEK_ERR);

	num_bytes = thread_read (session->file, (char *) &session->dbheader->avail, temp.avail_size);

	if (SRLisLittleEndian())
		SRLi_FlipLongs((&session->dbheader->avail),temp.avail_size >> 2);


	if (num_bytes != temp.avail_size)
		  return(DB_READ_ERR);

	/* mark that we changed the header. */
	session->dbheader_changed = TRUE;

	/* Free the previous avail block. */
	dbu_put_avail_elem (temp, session->dbheader->avail.av_table,
		&session->dbheader->avail.count);

	return(DB_NO_ERR);
}


/* Splits the header avail block and pushes half onto the avail stack. */
/*
---------------------------------------------------------------------------

dbu_push_avail_block()

static short dbu_push_avail_block (DB_Session_Struct *session)

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

static short dbu_push_avail_block (DB_Session_Struct *session)
{
	long			num_bytes;
	long			avail_size;
	long			avail_floc;
	long			index;
	long			file_pos;
	avail_block		 *temp;
	avail_elem		new_loc;
	short		   err;
	char	*tmpPtr = NULL;

	/* We need to split the current avail block in half, one will be kept,
	 * and we will write the other out to the file.
	 */
	avail_size = ( (session->dbheader->avail.size * sizeof (avail_elem)) >> 1)
		+ sizeof (avail_block);

	/* need "avail_size" number of bytes sized chunk, get avail location
	 * of the file where it will fit. (file offset)
	 */
	new_loc = dbu_get_avail_elem (avail_size, session->dbheader->avail.av_table,
		&session->dbheader->avail.count);

	if (new_loc.avail_size == 0)	/* if no room found, allocate some */
		new_loc = dbu_allocate_block (avail_size, session);

	avail_floc = new_loc.avail_floc;	/* file offset to where we can write */


	/* Now we will do the split of the avail info */
	temp = (avail_block *) calloc (1, avail_size);

	/* The size of the temp avail block must be set to the size
	 * that will be correct AFTER a call to the dbu_pop_avail_block
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
	err = dbu_free (session, new_loc.avail_floc, new_loc.avail_size);
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
			num_bytes = thread_write (session->file, session->fileStream, tmpPtr, avail_size);
			free(tmpPtr);
		}
		else
			num_bytes = 0;	/* ran out of mem... */
	}
	else
		num_bytes = thread_write (session->file,session->fileStream, (char *) temp, avail_size);	/* write out the avail block */

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

dbu_get_avail_elem()

static avail_elem dbu_get_avail_elem (long size,avail_elem *av_table,long
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

static avail_elem dbu_get_avail_elem (long size,avail_elem *av_table,long *av_count)
{
	long		index;	  /* For searching through the avail block. */
	avail_elem	val;		/* The default return value. */

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

dbu_put_avail_elem()

static long dbu_put_avail_elem (avail_elem new_el,avail_elem av_table[],long
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


static long dbu_put_avail_elem (avail_elem new_el,avail_elem av_table[],long *av_count)
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

dbu_allocate_block()

static avail_elem dbu_allocate_block (long size, DB_Session_Struct
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

static avail_elem dbu_allocate_block (long size, DB_Session_Struct *session)
{
	avail_elem val;

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

dbu_adjust_storage_avail()

static void dbu_adjust_storage_avail (DB_Session_Struct *session)

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

static void dbu_adjust_storage_avail (DB_Session_Struct *session)
{
	avail_elem	av_el;
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
			dbu_put_avail_elem (av_el, session->storage_map->storage_avail,
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
		av_el = dbu_get_avail_elem (0, session->storage_map->storage_avail,
			 &session->storage_map->av_count);
		dbu_put_avail_elem (av_el, session->dbheader->avail.av_table,
			&session->dbheader->avail.count);
		session->cur_cache_changed = TRUE;
	}

	/* all done here */
}


/*
---------------------------------------------------------------------------

dbu_init_storagetable()

static void dbu_init_storagetable(DB_Session_Struct *session,storage_table
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
static void dbu_init_storagetable (DB_Session_Struct *session,storage_table *new_storage, long bits)
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
		new_storage->se_table[index].SiblingHash = -1;
	}
	/* done here */

}


/*
---------------------------------------------------------------------------

dbu_init_cache()

static short dbu_init_cache(DB_Session_Struct *session,long size)

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
static short dbu_init_cache(DB_Session_Struct *session,long size)
{
	long	index;

	/* only do this if there are not cached blocks yet */
	if (session->cached_blocks == NULL)
	{
		/* allocate mem to hold the requested number of cache elements */
		session->cached_blocks = (cache_elem *) calloc(1, sizeof(cache_elem) * size);
		if(session->cached_blocks == NULL)
			return(DB_NO_MEM);	/* tell caller we failed */

		session->cache_size = size;	 /* record number of elements it can hold */

		/* now allocate a cache info record for each element and init it to
		 * empty.
		 */
		for(index = 0; index < size; index++)
		{
			(session->cached_blocks[index]).ca_block =
				(storage_table *) calloc (1,session->dbheader->block_size);
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
			(session->cached_blocks[index]).ca_data.SiblingHash = -1;  /* no data, no hash */
			(session->cached_blocks[index]).ca_data.dptr = NULL; /* no ram copy of data yet */
			(session->cached_blocks[index]).ca_data.data_size = 0;
			(session->cached_blocks[index]).ca_data.kid_size = 0;
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

dbu_get_block()

static void dbu_get_block (DB_Session_Struct *session,long dir_index)

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


short dbu_get_block (DB_Session_Struct *session,long dir_index)
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

	//for debug
	/* get the file offset for the indicated block */
	block_adr = session->dir_table [dir_index];

	/* see if we've previously read in any blocks, if not start up the
	 * cache.
	 */
	if (session->cached_blocks == NULL)	 /* no cache yet */
	{
		err = dbu_init_cache(session, DEFAULT_CACHESIZE);

		if(err != DB_NO_ERR)
		{
			return(err);	/* tell caller we failed */
		}
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
			err = dbu_write_block (session,&session->cached_blocks[session->idx_of_last_read]);
			if(err != DB_NO_ERR)
			{
				return(err);
			}
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
		{
			return(DB_SEEK_ERR);	/* tell caller we failed */
		}
		/* read in the storage block */
		num_bytes = thread_read (session->file, (char *)session->storage_map, session->dbheader->block_size);
		if (SRLisLittleEndian())
		{
			mapPtr = LE_PrepStorageMap(session->storage_map,session->dbheader->block_size);
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

dbu_split_storageTable()

static void dbu_split_storageTable (DB_Session_Struct *session, long
next_insert)

This low level routine is called when the current storage table has become
full and needs to be split into two.  The two parts will be split between
two cache blocks (dumping old if need be), and the data copied to them. The
directory and availability tables will be updated to reflect the
reorganization. The directory may also be doubled if we need to expand it
to hold more entries. No disk reads take place during this routine.

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

	next_insert (input) = the hash value for the next entry that will
		be put into the database. These bits are used in indexing the
		directory/index table.

returns:
	One of the following error codes will be returned. If this routine
	fails, it's pretty much a fatal error, your file is corrupt....

	DB_NO_ERR			 - everything fine

	these are pass thru (come from subroutine calls)
	DB_SEEK_ERR			 - file seek error
	DB_READ_ERR			 - file read i/o error
	DB_WRITE_ERR		- file write i/o error


---------------------------------------------------------------------------
*/

static short dbu_split_storageTable (DB_Session_Struct *session, long next_insert)
{
	storage_table *new_tables[2];   /* Pointers to the new storage tables. */
	avail_elem	old_store_av;	   /* Avail info for the old storage table. */
	storage_element *old_el;		/* points at an old storage element from old table */

	long		new_bits;		 /* The number of addressing bits for the new storage. */
	long		cache_0;		/* index in the cache for the split for cache block 0 */
	long		cache_1;		/* index in the cache for the split for cache block 1 */

	long		adr_0;		  /* the file offset for cache block 0 */
	long	adr_1;			/* the file offset for cache block 0 */


	long		dir_start0;		 /* index's - used for reformatting the dir */
	long		dir_start1;		 /* table after splitting. */
	long		dir_end;

	long		*new_dir;		 /* if maxed out dir entries, create new */
	long		dir_adr;		/* file offset for the new directory. */
	long		dir_size;		 /* size in bytes of the new directory. */
	long		old_adr[31];	/* file offsets for the old directorie(s) */
	long		old_size[31];   /* byte size of the old directories. */
	long		old_count;		/* the number of old directories blocks. */

	long		index;		  /* general array indexing vars */
	long		index1;

	long		elem_loc;		 /* used to copy elements to new storage/cache */
	long		select;		 /* used to index new blocks during copying. */


	/* No directories are yet old. */
	old_count = 0;

	/* make sure our caching infomation has started up */
	if (session->cached_blocks == NULL)
	{
		index = dbu_init_cache(session, DEFAULT_CACHESIZE);
		if(index != DB_NO_ERR)
			return (short)index;  /* tell caller we failed */
	}

	/* now we start splitting the current storage table until we have made
	 * some room.
	 */
	while (session->storage_map->count == session->dbheader->max_store_elems)
	{
		/* move through the cache table till we find a block that is not
		 * the currently addressed block by the current storage table.
		 * We will need to use two cache blocks that are not part of the
		 * current storage table to be used for split out info.
		 */
		do
		{
			/* step forward, wrap if necessary. */
			session->idx_of_last_read = (session->idx_of_last_read + 1) % session->cache_size;
			cache_0 = session->idx_of_last_read;	/* record in case it's the one we want */


			/* keep going till not the current addressed block */
		} while (session->cached_blocks[cache_0].ca_block == session->storage_map);

		/* get the storage table for this cached block (mapping of what's used ) */
		new_tables[0] = session->cached_blocks[cache_0].ca_block;

		/* make sure we write out it's current info before we start
		 * screwing around.
		 */
		if (session->cached_blocks[cache_0].ca_changed)
		{
			index = dbu_write_block (session, &session->cached_blocks[cache_0]);
			if(index != DB_NO_ERR)
				return (short)index;
		}

		/* now find a second cache block that we can use */
		do
		{
			session->idx_of_last_read = (session->idx_of_last_read + 1) % session->cache_size;
			cache_1 = session->idx_of_last_read;

		} while (session->cached_blocks[cache_1].ca_block == session->storage_map);

		/* get the storage table for the 2nd block */
		new_tables[1] = session->cached_blocks[cache_1].ca_block;

		/* make sure it's contents are written out if need be */
		if (session->cached_blocks[cache_1].ca_changed)
		{
			index = dbu_write_block (session, &session->cached_blocks[cache_1]);
			if(index != DB_NO_ERR)
				return (short)index;
		}

		new_bits = session->storage_map->storage_bits+1;	/* inc addressing bits for new blocks */

		/* init the storage info for the two blocks we've
		 * grabbed, to be in an unused state.
		 */

		dbu_init_storagetable (session, new_tables[0], new_bits);
		dbu_init_storagetable (session, new_tables[1], new_bits);

		/* get some storage area in the file for each cache block
		 * to be associated with.
		 */
		adr_0 = dbu_alloc (session, session->dbheader->block_size); /* for block 0 */

		adr_1 = dbu_alloc (session, session->dbheader->block_size); /* for block 1 */

		/* check for errors allocating */
		if((adr_0 < 0) || (adr_1 < 0))
		{
			/* had problems loading the avail block,
			 * tell caller we failed.
			 */

			if(adr_0 < 0)
				return (short)adr_0;
			else
				return (short)adr_1;
		}


		session->cached_blocks[cache_0].ca_adr = adr_0;
		session->cached_blocks[cache_1].ca_adr = adr_1;


		/* See if we have maxed out on the directory size, if so
		 * we will need to increase it's size - we will double its
		 * size and get some storage space in the db file...
		 */
		if (session->dbheader->dir_bits == session->storage_map->storage_bits)
		{
			dir_size = session->dbheader->dir_size * 2;
			dir_adr  = dbu_alloc (session, dir_size);	 /* get a file offset */

			if(dir_adr < 0)
				return (short) dir_adr;	/* tell caller what the error is */

			new_dir  = (long *) calloc (1, dir_size);  /* get mem to hold it */
			if (new_dir == NULL)
				return(DB_NO_MEM);

			/* step through our current directory and replicate it's
			 * contents in the new directory. NOTE: we are indexing by
			 * 2^s here since our addressing bits are now increased by
			 * one bit.
			 */
			for (index = 0; (ulong)index < (session->dbheader->dir_size / sizeof(long));
				index++)
			{
				new_dir[2*index]   = session->dir_table[index];
				new_dir[2*index+1] = session->dir_table[index];
			}

			/* Update the file header so it knows what the file
			 * offset is for our new directory.
			 */
			old_adr[old_count] = session->dbheader->dir_location;
			session->dbheader->dir_location = dir_adr;	/* the new dir offset */

			old_size[old_count] = session->dbheader->dir_size;
			session->dbheader->dir_size = dir_size;
			session->dbheader->dir_bits = new_bits;
			old_count++;

			/* Now update session.  */
			session->dbheader_changed = TRUE;

			/* index to the offset in dir_table[] is now doubled. */
			session->storage_map_dir *= 2;

			free (session->dir_table);	/* get rid of old array of offsets */
			session->dir_table = new_dir;   /* and use the new */

		} /* end of directory splitting */

		/* Copy all elements in the current storage table into the new
		 * cache blocks we set up above.
		 */
		for (index = 0; index < session->dbheader->max_store_elems; index++)
		{
			old_el = & (session->storage_map->se_table[index]);

			/* either the 1st or 2nd new cache storage block used */
			select = (old_el->hash_value >> (31-new_bits)) & 1; /* 0, 1 */

			elem_loc = old_el->hash_value % session->dbheader->max_store_elems;

			/* find an empty slot */
			while(new_tables[select]->se_table[elem_loc].hash_value != -1)
				elem_loc = (elem_loc + 1) % session->dbheader->max_store_elems;

			new_tables[select]->se_table[elem_loc] = *old_el;
			new_tables[select]->count += 1;
		}

		/* get some available file space, use index to hold the file
		 * offset while we check for errors.
		 */
		index = dbu_alloc (session, session->dbheader->block_size);

		if(index < 0)
			return (short)index;  /* tell caller what the error was */

		new_tables[1]->storage_avail[0].avail_floc = index;

		new_tables[1]->storage_avail[0].avail_size = session->dbheader->block_size;
		new_tables[1]->av_count = 1;

		/* now copy the avail elements in current storage to new_tables[0]. */
		new_tables[0]->av_count = session->storage_map->av_count;
		index = 0;
		index1 = 0;

		/* see if the current storage had a full avail table (maxed out
		 * on available elements), in which case we will copy one of them
		 * over to the other cache block.
		 */
		if (new_tables[0]->av_count == MAX_AVAIL)
		{
			/* move the first avail element to new_tables[1]. */
			dbu_put_avail_elem (session->storage_map->storage_avail[0],
				new_tables[1]->storage_avail, &new_tables[1]->av_count);
			index = 1;
			new_tables[0]->av_count --;
		}

		for (; index < session->storage_map->av_count; index++)
		{
			new_tables[0]->storage_avail[index1++] = session->storage_map->storage_avail[index];
		}

		/* now update the directory information, along with the storage info
		 * for the two new cache blocks we created.
		 */
		dir_start1 = (session->storage_map_dir >> (session->dbheader->dir_bits - new_bits)) | 1;
		dir_end = (dir_start1 + 1) << (session->dbheader->dir_bits - new_bits);
		dir_start1 = dir_start1 << (session->dbheader->dir_bits - new_bits);
		dir_start0 = dir_start1 - (dir_end - dir_start1);
		for (index = dir_start0; index < dir_start1; index++)
			session->dir_table[index] = adr_0;
		for (index = dir_start1; index < dir_end; index++)
			session->dir_table[index] = adr_1;


		/* Set changed flags. */
		session->cached_blocks[cache_0].ca_changed = TRUE;
		session->cached_blocks[cache_1].ca_changed = TRUE;
		session->cur_cache_changed = TRUE;
		session->directory_changed = TRUE;
		session->second_changed = TRUE;

		/* Now to update the cache */

		/* the current storage index is determined by the hash of
		 * the next item to be added, and therefore giving us the
		 * dir index for the table.
		 */
		session->storage_map_dir = next_insert >> (31-session->dbheader->dir_bits);

		/* get the old storage tables avail info for use down below,
		 * since it won't be hooked to the old storage/cache anymore.
		 */
		old_store_av.avail_floc  = session->current_cache_entry->ca_adr;
		old_store_av.avail_size = session->dbheader->block_size;
		session->current_cache_entry->ca_adr = 0;
		session->current_cache_entry->ca_changed = FALSE;

		/* current storage will be hooked to the first cache block
		 * we set up.
		 */
		if (session->dir_table[session->storage_map_dir] == adr_0)
		{
			session->storage_map = new_tables[0];
			session->current_cache_entry = &session->cached_blocks[cache_0];
			dbu_put_avail_elem (old_store_av,
				new_tables[1]->storage_avail, &new_tables[1]->av_count);
		}
		else
		{
			session->storage_map = new_tables[1];
			session->current_cache_entry = &session->cached_blocks[cache_1];
			dbu_put_avail_elem (old_store_av,
				new_tables[0]->storage_avail, &new_tables[0]->av_count);
		}

	}	 /* end of while(storage maxed out) */

	/* finish up by getting rid of old directories if any. */
	for (index = 0; index < old_count; index++)
	{
		index1 = dbu_free (session, old_adr[index], old_size[index]);
		if(index1 != DB_NO_ERR)
			return (short)index1;
	}


	/* all done here */

	return(DB_NO_ERR);	/* tell caller we worked */
}


/*
---------------------------------------------------------------------------

dbu_write_block()

static short dbu_write_block (DB_Session_Struct *session, cache_elem
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

static short dbu_write_block (DB_Session_Struct *session, cache_elem *ca_entry)
{
	long	num_bytes;	/* The return value for write. */
	long	file_pos;	 /* The return value for lseek. */
	char	*tmpPtr = NULL;

	file_pos = lseek (session->file, ca_entry->ca_adr, SEEK_SET);
	if (file_pos != ca_entry->ca_adr)
		return(DB_SEEK_ERR);

	if (SRLisLittleEndian())
	{
		tmpPtr = LE_PrepStorageMap(ca_entry->ca_block, session->dbheader->block_size);
		if(tmpPtr != 0)
		{
			num_bytes = thread_write (session->file, session->fileStream, tmpPtr, session->dbheader->block_size);
			free(tmpPtr);
		}
		else
			num_bytes = 0;	/* ran out of mem... */
	}
	else
		num_bytes = thread_write (session->file,session->fileStream, (char *) ca_entry->ca_block, session->dbheader->block_size);


	if (num_bytes != session->dbheader->block_size)
		return(DB_WRITE_ERR);

	ca_entry->ca_changed = FALSE;	   /* just written out, so now it's fresh */
	ca_entry->ca_data.elem_loc = -1;	/* no storage element cached for this block */
	ca_entry->ca_data.hash_val = -1;	/* no hash = no entry */
	ca_entry->ca_data.SiblingHash = -1;	/* no hash = sibling */

	return(DB_NO_ERR);
}


/*
---------------------------------------------------------------------------

dbu_write_header()

static short dbu_write_header (DB_Session_Struct *session)

This low level routine is used to write out the database header information
associated with the given session.

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

returns:
	DB_NO_ERR
	DB_SEEK_ERR
	DB_WRITE_ERR

---------------------------------------------------------------------------
*/
static short dbu_write_header (DB_Session_Struct *session)
{
	long	num_bytes;	/* Return value for write. */
	long	file_pos;	 /* Return value for lseek. */
	char	*tmpPtr = NULL;
	/* position ourselves to write the header out,
	 * which happens to be the first block of the file (offset 0)
	 */
	file_pos = lseek (session->file, 0L, SEEK_SET);
	if (file_pos != 0)
		return(DB_SEEK_ERR);

	/* and now write out the full header sized block */

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
		num_bytes = thread_write (session->file,session->fileStream, (char *) session->dbheader, session->dbheader->block_size);

	if (num_bytes != session->dbheader->block_size)
		return(DB_WRITE_ERR);

	/* make sure it's been written to disk before returning */
/*	fsync(session->file); unistd.h  */

	return(DB_NO_ERR);
}


/*
---------------------------------------------------------------------------

dbu_end_update()

static short dbu_end_update (DB_Session_Struct *session)

This low level routine is called upon to make sure we write out
those changes that occured in our memory copy of what is on
disk.  Generally called at the end of updates (duh) that
effect the cached storage blocks ,the directory, and/or the
file header.

Parameters:

	session (input) = the session parameter that was returned from a
		call to db_Open().

returns:

	DB_NO_ERR
	DB_WRITE_ERR
	DB_SEEK_ERR

	other subroutine error codes will be passed along

---------------------------------------------------------------------------
*/

static short dbu_end_update (DB_Session_Struct *session)
{
	long  num_bytes;	/* Return value for write. */
	long file_pos;	  /* Return value for lseek. */
	long index;
	short   err;
	char	*tmpPtr = NULL;

	/* check to see if the current storage block has been
	 * cached, and if it needs saving out (was it modified).
	 */
	if (session->cur_cache_changed && (session->current_cache_entry != NULL))
	{
		err = dbu_write_block (session, session->current_cache_entry);
		if(err != DB_NO_ERR)
			return(err);

		session->cur_cache_changed = FALSE;
	}

	/* Check to see if any of the other cached blocks have been
	 * modified, and if so we will write those out also.
	 */
	if (session->second_changed)	/* other than current modified */
	{
		/* only write out if they actually contain data */
		if(session->cached_blocks != NULL)
		{
			/* scan through and only save the ones that have
			 * actually been modified.
			 */
			for (index = 0; index < session->cache_size; index++)
			{
				if (session->cached_blocks[index].ca_changed)
				{
					err = dbu_write_block (session, &session->cached_blocks[index]);
					if(err != DB_NO_ERR)
						return(err);
				}

				/* the write will flip the ca_changed flag after writing */
			}
		}
		session->second_changed = FALSE;	/* we've cleared the back log */
	}

	/* Check to see if the directory information has been modified,
	 * if so we will write it out also.
	 */
	if (session->directory_changed)
	{
		file_pos = lseek (session->file, session->dbheader->dir_location, SEEK_SET);
		if (file_pos != session->dbheader->dir_location)
			return(DB_SEEK_ERR);

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
			num_bytes = thread_write (session->file, session->fileStream, (char *) session->dir_table, session->dbheader->dir_size);


		if (num_bytes != session->dbheader->dir_size)
			return(DB_WRITE_ERR);

		session->directory_changed = FALSE;

		/* don't flush here if we are going to write the header out
		 * down below, we will just do it then.
		 */
/*		if (!session->dbheader_changed)
			fsync (session->file);  unistd.h  */
	}

	/* and finally we check to see if the database header has
	 * been modified, and if so we will write it out also.
	 */
	if (session->dbheader_changed)
	{
		err = dbu_write_header (session);	 /* it does a final flush for us */
		if(err != DB_NO_ERR)
			return(err);

		session->dbheader_changed = FALSE;	/* not anymore */
	}

	return(DB_NO_ERR);
}

/*
---------------------------------------------------------------------------

dbu_read_entry()

static short dbu_read_entry (DB_Session_Struct *session,long elem_loc, char
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

static short dbu_read_entry (DB_Session_Struct *session,long elem_loc, char **eData)
{
	long	num_bytes;		/* For seeking and reading. */
	long	kid_size;
	long	data_size;
	long	file_pos;
	cached_item_info *data_ca;

	*eData = NULL;  /* clear in case we fail */

	/* first check to see if we already have the entry info
	 * in our storage cache, if so just pull the ptr from
	 * the cache info.
	 */
	if ((session->current_cache_entry->ca_data.elem_loc == elem_loc) &&
       (session->current_cache_entry->ca_data.dptr != NULL))
   /* index same as current */
   {
      *eData = session->current_cache_entry->ca_data.dptr; /* in current addressed cache */
      return (DB_NO_ERR);
   }

	/* otherwise it's not in the currently addressed cache block, so
	 * we need to read in it's data */
	kid_size = session->storage_map->se_table[elem_loc].kid_size;
	data_size = session->storage_map->se_table[elem_loc].data_size;
	data_ca = &session->current_cache_entry->ca_data;	 /* cached item info */

	if (data_ca->dptr != NULL)
		free(data_ca->dptr);

	/* set up our current cache entry for the requested item */
	data_ca->kid_size = kid_size;
	data_ca->data_size = data_size;
	data_ca->elem_loc = elem_loc;
	data_ca->hash_val = session->storage_map->se_table[elem_loc].hash_value;
	data_ca->SiblingHash = session->storage_map->se_table[elem_loc].SiblingHash;


	/* this shouldn't happen, but if for some reason we come across
	 * a ghost....
	 */
	if (kid_size+data_size == 0)
		data_ca->dptr = (char *)calloc(1,1);
	else
	{
		data_ca->dptr = (char *)calloc(1,kid_size+data_size);
	}

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

dbu_hash()

static long dbu_hash (DB_Kid kid)

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


static long dbu_hash (long norm_type, DB_Kid *kid)
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

dbu_findkey()

static long dbu_findkey (DB_Session_Struct *session,DB_Kid *kid,char
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
static long dbu_findkey (DB_Session_Struct *session,DB_Kid *kid,char **dptr,long *new_hash_val, long norm_type)
{
	long	elem_hash_val;  /* elements hash value from the storage table. */
	char	*full_kid;		/* complete keying identifier as stored in the file. */
	long	elem_loc;		 /* The location in the bucket. */
	long	lelem_loc = 0;   /* The location in the bucket in the while loop */
	long	home_loc;		 /* The home location in the bucket. */
	long	kid_size;		 /* Size of the key on the file. */
	long	the_hashValue = 0;
	short   err;

	/* calculate the hash value of the callers keying identifier
	 * and give caller a copy, if the hash value is a -1.
	 */
	if (*new_hash_val == 0)
		*new_hash_val = dbu_hash (norm_type, kid);

	/* make sure the storage block for the given kid is currently loaded,
	 * also insuring that this block will be the current cached block.
	 * Hash value shifted down to figure out the index into the directory
	 * offsets array.
	 */
	err = dbu_get_block (session, *new_hash_val>> (31-session->dbheader->dir_bits));
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
		&& SRLi_memicmp (session->current_cache_entry->ca_data.dptr, kid->item_ptr, kid->item_len) == 0)	/* is full kid equal value */
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
	lelem_loc = *new_hash_val % session->dbheader->max_store_elems;
	home_loc = lelem_loc;	/* remember starting item in this block */
	elem_loc = -1;
	/* get hash of current item */
	elem_hash_val = session->storage_map->se_table[lelem_loc].hash_value;
	the_hashValue = *new_hash_val;

	/* now search through all the items (-1 no hashed item stored)
	 * in the storage table, and load that particular entry if
	 * found.
	 */
	while (elem_loc != home_loc)
	{
		if (elem_loc == -1)
			elem_loc = lelem_loc; // Load in the Loop element location
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
		if (elem_hash_val != the_hashValue
			|| kid_size != kid->item_len
			|| SRLi_memicmp(session->storage_map->se_table[elem_loc].kid_start, kid->item_ptr,
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
			err = dbu_read_entry (session, elem_loc, &full_kid);
			if(err != DB_NO_ERR)
				return(err);

			/* see if we have exact match on kid's */
			if (SRLi_memicmp (full_kid, kid->item_ptr, kid_size) == 0)
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


/*
 * Function used to update the Data Base Version in the Data Base
 * Header
 */
short db_UpdateHeaderVersion (ulong db_session, char *path, char *dbfile)
{
short err = 0;
int file_d = 0;
int num_bytes = 0;

char *tempname = NULL;

DB_Session_Struct *session = NULL;

	if((db_session == 0) || (path == NULL) || (dbfile == NULL) )
		return(DB_BAD_PARAM);
	tempname = (char *) calloc (1, strlen(path) + strlen(dbfile) + 1);
	if (tempname == NULL)
		return (DB_NO_MEM);
	strcat (tempname, path);
	strcat (tempname, dbfile);

	err = DB_NO_ERR;	/* start out ok */
	/* Open the file for read and write */
	file_d = thread_open (tempname, O_RDWR | O_BINARY, -1); 
	if (file_d <= 0)
		return (err);
	/* Make sure we are at the beginning */
	(void) lseek(file_d, 0, SEEK_SET);

	session = (DB_Session_Struct *) calloc(1, sizeof(DB_Session_Struct));
	num_bytes = write (file_d, "DBX3", 4);
	if (num_bytes < 4)
		err = DB_WRITE_ERR;
	close (file_d);
	return (err);

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
char *LE_PrepLongs(long *longbuff, long numbytes)
{
	long	*le_data;
	if(longbuff == 0)
		return(0);

	if(numbytes <= 0)
		return(0);

	if(numbytes % 4 != 0)
		return(0);
	le_data = (long *) calloc(1, numbytes);
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
char *LE_PrepStorageMap(storage_table *storage_map, long mapbytes)
{
	char *result;
	long	dsize;
	storage_element	*table;

	result = calloc(1, mapbytes);
	if(result == 0)
		return(0);

	memcpy(result, (char *)storage_map, mapbytes);


	/* now only reverse the fields that are longs */
	dsize = sizeof(storage_table) - sizeof(storage_element);
	SRLi_FlipLongs((result), dsize >> 2);

	/* elements contain one field which is not to be endian modified since
	 * it is an array of chars.
	 */
	table =((storage_table *) result)->se_table;	/* start with first */
	dsize += sizeof(storage_element);
	for(; dsize < mapbytes; dsize += (sizeof(storage_element)))
	{
		SRLi_FlipLongs(&table->hash_value, 1);
		SRLi_FlipLongs(&table->SiblingHash, 1);
		SRLi_FlipLongs(&table->data_pointer, 3); /* 3 long fields here */
		table++;
	}

	return(result);

}


/*
-------------------------------------------------------------

 SRL_GetDBID()

 This routine gets a Database ID for an object (Certificate or CRL)
 If the object exists already, it will return a new Database ID, based on
 the object and database template. The application has the responsiblity
 of keeping track of the Data Base Id's. If the object does not exist in
 the database, the error SRL_NOT_FOUND will be returned.

 Parameters:

 ulong sessionID (input) = The SRL Session ID

 AsnTypeFlag type (input) = The type of certificate 
							(SRL_TRUSTED_CERT_TYPE or SRL_CERT_TYPE)
							CRL Objects ignore this flag.

 Bytes_struct *Object (input) = The Object to  get the Database ID.

 long (output) ObjectID = The returned object ID.

-------------------------------------------------------------
*/
	
SRL_API(short) SRL_GetDBID (ulong sessionID, AsnTypeFlag type, Bytes_struct *Object, 
							long *DBid)
{
	CM_Time       today;
	AsnTypeFlag AsnType = 0;
   long				 dbid = 0;
	Cert_struct *dec_cert = NULL;
    CRL_struct	*dec_crl = NULL;
	dbEntryList_struct *dblist = NULL;
	dbEntryInfo_LL *tmplist = NULL;
	dbCertEntryInfo_LL *CertListP = NULL;
	dbCRLEntryInfo_LL *CRLListP = NULL;
	SRLSession_struct *session = NULL;
	short trusted = FALSE;
	short err = SRL_SUCCESS;
   DB_Data* p_entry_data = NULL;
   DB_Data* p_entry_data2 = NULL;
   DB_Kid* p_kid = NULL;
   DB_Kid* p_kid2 = NULL;


	if ((sessionID == 0) || (Object == NULL) || (Object->data == NULL) ||
		(DBid == NULL))
		return SRL_INVALID_PARAMETER;

	err =  SRLi_GetRetSessionFromRef(&session, sessionID);
	if(err != SRL_SUCCESS)
		return(err);

	// Get the type and object
	AsnType = type;
	*DBid = 0;
   if((type == SRL_CERT_TYPE) || (type == SRL_TRUSTED_CERT_TYPE))
   {
		// Process according to type of Object (Currently Certificates and CRL's
		err = CM_DecodeCert(Object, &dec_cert);
		if(err == CM_NO_ERROR)
		{
			if (type == SRL_TRUSTED_CERT_TYPE)
			{

				// If cert is a root cert - make more checks and setup the trusted flag
				if (isRoot(dec_cert))
				{
					if(SRLDNcmp(dec_cert->issuer, dec_cert->subject) != 0)
					{
					   CM_FreeCert(&dec_cert);
					   return(SRL_NOT_SELF_SIGNED);
					}
            
					/* additional check: certificate must contain
					 * a signature key - otherwise it adds nothing
					 * (for our purposes) to save this certificate
					 * as a special trusted cert.
					 */
					if((strcmp(dec_cert->pub_key.oid, gDSA_OID) != 0) &&
					   (strcmp(dec_cert->pub_key.oid, gDSA_KEA_OID) != 0) &&
					   (strcmp(dec_cert->pub_key.oid, gOIW_DSA) != 0) &&
					   (strcmp(dec_cert->pub_key.oid, gRSA_OID) != 0))
					{
					   CM_FreeCert(&dec_cert);
					   return(SRL_NOT_SIG_KEY);
            
					}

					/* Only check for known SIG algs here 
					 * which require parameters.
					 */
					if((strcmp(dec_cert->pub_key.oid, gDSA_OID) == 0) ||
					   (strcmp(dec_cert->pub_key.oid, gOIW_DSA) == 0) ||
					   (strcmp(dec_cert->pub_key.oid, gDSA_KEA_OID) == 0))

					{
					   /* need params for these algs, in unionized field,
						* so check any of them for null.
						*/
					   if(dec_cert->pub_key.params.encoded == 0)
					   {
						  CM_FreeCert(&dec_cert);
						  return SRL_MISSING_PARAMETERS;
					   }
					}
       
					/* given that the signature information is good, verify that the
					 * date range is still good.
					 */

					SRLi_GetSRTime(today);

					if(strcmp(dec_cert->val_not_before, today) > 0)
					{
					   CM_FreeCert(&dec_cert);
					   return(SRL_CERT_NOT_YET_VALID);
					}
					if(strcmp(dec_cert->val_not_after, today) < 0)
					{
					   CM_FreeCert(&dec_cert);
					   return(SRL_CERT_EXPIRED);
					}
					trusted = TRUE;
					AsnType = SRL_CA_CERT_TYPE;
					 /* go add the certificate and it's indexing info */
				}
			}
			else
			{
				/* Just decode it and get the Database ID */
				 trusted = FALSE; // Must be a CA Cert LDAP Atribute
				/* Set the type to a normal cert */
				 AsnType = SRL_CERT_TYPE;
			}


			err = SRL_DatabaseList(sessionID, &dblist, SRL_DB_CERT, TRUE);
			if (err != SRL_SUCCESS)
			{
				SRL_FreeDBListing(&dblist);
				return err;
			}

			if ((dblist!= NULL) &&
				(dblist->entryList != NULL)) 
			{
				tmplist = dblist->entryList;
				while ((tmplist != NULL) && (dbid == 0))
				{
					// Check for the Same subject DN
					if (SRLi_memicmp (tmplist->entry_DN,
						dec_cert->subject, strlen(dec_cert->subject)) == 0)
					{
						if (dblist->entryList->info.certs != NULL)
						{
							CertListP = tmplist->info.certs;
							while (CertListP != NULL)
							{
								// Check for the same serial number
								if (CertListP->serialNum->num == dec_cert->serial_num.num)
								{
									// Compare the serial numbers
									if (SRLi_memicmp((char *)CertListP->serialNum->data, (char *)dec_cert->serial_num.data,
												CertListP->serialNum->num) == 0)
									{
										// Also check the trusted flag
										if (CertListP->trusted == trusted)
										{
											// Must have the Template
											dbid = CertListP->DBid;
											break;
										}
									} // End if
								} // End if
								CertListP = CertListP->next;
							} // End while
						} // Endif
					} // end if
					tmplist = tmplist->next;
				} // end while
			} // end if dblist != null
			if (dbid == 0)
				err = SRL_NOT_FOUND;
			*DBid = dbid;
	}
		else
			err = SRL_ASN_ERROR;
	}
   else if (type == SRL_CRL_TYPE)
   {
      // Decode the crl and extensions, don't decode the revocations 
      err = CM_DecodeCRL2(Object, &dec_crl, FALSE, TRUE);
      
      if(err == CM_NO_ERROR)
      {
         
         /* create the CRL List */
         
         err = SRL_DatabaseList(sessionID, &dblist, SRL_DB_CRL, TRUE);
         if (err != SRL_SUCCESS)
         {
            SRL_FreeDBListing(&dblist);
            return err;
         }
         
         if ((dblist!= NULL) &&
            (dblist->entryList != NULL)) 
         {
            // Get the issuer name the CRL would have been stored with
            char* crl_issuer = NULL;
            err = SRLi_GetCRLIssuerName(dec_crl, &crl_issuer);
            if (err == SRL_SUCCESS)
            {
               tmplist = dblist->entryList;
               while ((tmplist != NULL) && (dbid == 0))
               {
                  // Check for the Same subject DN
                  if ((strlen(crl_issuer) == strlen(tmplist->entry_DN)) &&
                      (SRLi_memicmp (tmplist->entry_DN, crl_issuer, 
                                     strlen(crl_issuer)) == 0))
                  {
                     if (dblist->entryList->info.crls != NULL)
                     {
                        CRLListP = tmplist->info.crls;
                        while ((CRLListP != NULL) && (dbid == 0))
                        {
                           // Check for the same time period
                           if (CRLListP->issueDate)
                           {
                              // Compare the issue date
                              if (strcmp((char *)CRLListP->issueDate, (char *)&dec_crl->thisUpdate) == 0)
                              {
                                 // Compare the next update
                                 if (((dec_crl->nextUpdate == NULL) && (strlen((char *)&CRLListP->nextDate) == 0)) ||
                                     (strcmp((char *)&CRLListP->nextDate, (char *)dec_crl->nextUpdate[0]) == 0))
                                 {
                                    // Get the CRL from the DB by its DBid
                                    err = db_GetDBItemsByID(session->db_CRLRefSession, CRLListP->DBid,
                                                            &p_kid, &p_entry_data, 
                                                            &p_kid2, &p_entry_data2);

                                    if (err == SRL_SUCCESS)
                                    {
                                       // Compare the actual data
                                       if ((p_entry_data->item_len == Object->num) &&
                                          (memcmp(p_entry_data->item_ptr, Object->data, Object->num) == 0))
                                       {
                                          // Found a match
                                          dbid = CRLListP->DBid;
                                       }
                                    }
                                    // Free the uneeded resources
                                    SRLi_FreeDB_Item(&p_kid);
                                    SRLi_FreeDB_Item(&p_kid2);
                                    SRLi_FreeDB_Item(&p_entry_data);
                                    SRLi_FreeDB_Item(&p_entry_data2);
                                 } // End if
                              } // End if
                           } // End if
                           CRLListP = CRLListP->next;
                        } // End while
                     } // End if
                  } // End if
                  tmplist = tmplist->next;
               } // end while
            } // end if
            // Free issuer
            free(crl_issuer);
         } // end if
         if (dbid == 0)
            err = SRL_NOT_FOUND;
         *DBid = dbid;
      }
      else
         err = SRL_ASN_ERROR;
   }
   else
   {
      // Object cannot decode into a known format
      err = SRL_UNKNOWN_OBJECT;
   }
   
   // Free the decode structures
   CM_FreeCert(&dec_cert);
   CM_FreeCRL(&dec_crl);
   if (dblist != NULL)
   {
      SRL_FreeDBListing(&dblist);
      return err;
   }
   
   
   return err;
}




/*
-------------------------------------------------------------

Function

SRL_DatabaseRetrieve()

short SRL_DatabaseRetrieve(ulong sessionID, DBTypeFlag entryType,
	dbEntryInfo *entryInfo, Bytes_struct **entryData);

Description

This function will return to the caller the item indicated by the entry
info provided - which will be an ASN.1 encoded certificate, or CRL.

Parameters:

   sessionID (input)
         Session identifier (context) that was created by the calling app
       when starting up a session with the CM.

   entryType (input)
      what type of entry this is, a cert db entry (SRL_CERT_TYPE) or
      a crl db entry (SRL_CRL_TYPE)

   entry info (input)
      The info taken from the entry for the item you wish to get
      from the database. ( entry info discused in SRL_DatabaseList)

   entryData (input/output)
      ptr to storage for a db_data ptr, which will be filled in with
      the data for the indicated db entry. This routine will allocate
      the mem for the DB_Data struct and it's fields. It will be up
      to the caller to free the memory once they are done with the
      data.

Return Value
        The funtion will return one of the following error codes

      SRL_SUCCESS                   no errors
      SRL_INVALID_PARAMETER          Bad parameter passed in
      SRLSession_NOT_VALID           session does not exist
      SRL_MEMORY_ERROR               out of memory

      various db file related errors also possible....

-------------------------------------------------------------
*/

SRL_API(short) SRL_DatabaseRetrieve(ulong sessionID, DBTypeFlag entryType,
									dbEntryInfo *entryInfo,
									Bytes_struct **entryData, long DBid)
{
   SRLSession_struct	*session;
   ulong				db_session;
   short				err = SRL_SUCCESS;
   CM_BOOL				getentry = TRUE;
   DB_Data				*entry_data = NULL;
   DB_Data				*entry_data2 = NULL;
   DB_Kid				entry_kid;
   DB_Kid				*kid1 = NULL;
   DB_Kid				*kid2 = NULL;
   Bytes_struct			*retData = NULL;
   CM_Time				today;
   short				expired = FALSE;
   dbCRLEntryInfo_LL *tmpcrlinfo = NULL, *crlinfo = NULL;
   /* check parameters */
   if((sessionID == 0) || ((entryInfo == 0) && (DBid == 0)) || (entryData == 0))
      return(SRL_INVALID_PARAMETER);

   *entryData = 0;   /* start caller with nothing */

   err =  SRLi_GetRetSessionFromRef(&session, sessionID);
   if(err != SRL_SUCCESS)
      return(err);

   if(entryType == SRL_DB_CERT)
   {
	   if (session->db_certRefSession == 0)
		   return SRL_NO_DB;
	   db_session = session->db_certRefSession;
   }
   else if(entryType == SRL_DB_CRL)
   {
	   if (session->db_CRLRefSession == 0)
		   return SRL_NO_DB;
	   db_session = session->db_CRLRefSession;
   }
   else
	   return(SRL_INVALID_PARAMETER);


	db_lock("SRL_DatabaseRetrieve", __LINE__);
	/* given the info about the entry, either
	* retrieve the entry or construct the indexing template info
	* which in turn will be used as the kid (keying identifier data) for
	* the cert or crl data that corresponds to this item.
	*/
   if(entryType == SRL_DB_CERT)
   {
	   
	   if (DBid > 0)
	   {
		   err = db_GetDBItemsByID(db_session, DBid,
									&kid1, &entry_data, 
									&kid2, &entry_data2 );
		   		   
		   if (err != SRL_SUCCESS)
		   {
			   SRLi_FreeDB_Item(&kid1);
			   SRLi_FreeDB_Item(&kid2);
			   SRLi_FreeDB_Item(&entry_data);
			   SRLi_FreeDB_Item(&entry_data2);
			   err = DB2SRLerr(err);
			   db_unlock("SRL_DatabaseRetrieve", __LINE__);
			   return err;
		   }
		   getentry = FALSE;
	   }
	   else
	   {
		   if(entryInfo->certs == 0)
		   {
			   db_unlock("SRL_DatabaseRetrieve", __LINE__);
			   return(SRL_INVALID_PARAMETER);
		   }

		   err = SRLi_TemplateFromCertInfo(&entry_kid, entryInfo->certs);
	   }
	}
	else if (entryType == SRL_DB_CRL)
	{
	   if (DBid > 0)
	   {
		   err = db_GetDBItemsByID(db_session, DBid,
									&kid1, &entry_data, 
									&kid2, &entry_data2 );

   		   if (err != SRL_SUCCESS)
		   {
			   SRLi_FreeDB_Item(&kid1);
			   SRLi_FreeDB_Item(&kid2);
			   SRLi_FreeDB_Item(&entry_data);
			   SRLi_FreeDB_Item(&entry_data2);
			   err = DB2SRLerr(err);
			   db_unlock("SRL_DatabaseRetrieve", __LINE__);
			   return err;
		   }

			getentry = FALSE;
	   }
	   else
	   {
		   if(entryInfo->crls == 0)
		   {
			   db_unlock("SRL_DatabaseRetrieve", __LINE__);
			   return(SRL_INVALID_PARAMETER);
		   }

		   err = SRLi_TemplateFromCRLInfo(&entry_kid, entryInfo->crls);
	   }
	}
	else
	{
		db_unlock("SRL_DatabaseRetrieve", __LINE__);
		return SRL_INVALID_PARAMETER;
	}

   if(err != SRL_SUCCESS)
   {
	  db_unlock("SRL_DatabaseRetrieve", __LINE__);
      return(err);
   }

	/*
	 * If data base ID was passed, we have the entry already 
	 * so don't try to get the entry
	 */
   if (getentry)
   {
	   /*
	    * get the corresponding data (cert or crl) for this entry 
	    * based on the template kid
	    */
		err = db_GetEntry(db_session, 0, &entry_kid,  &entry_data);
		free(entry_kid.item_ptr);   /* don't need kid data anymore */
		err = DB2SRLerr(err);
		

		if(err != SRL_SUCCESS)
		{
			db_unlock("SRL_DatabaseRetrieve", __LINE__);
			return(err);
		}
   }
   /* worked fine, give back to caller since it's a copy for
    * us to use.
    */
   if (entryType == SRL_DB_CRL)
   {
	   if (entryInfo == NULL)
	   {
		   SRLi_CRLInfoFromTemplate(session->db_CRLRefSession,
			   &tmpcrlinfo, entry_data2);
		   crlinfo = tmpcrlinfo;
	   }	
	   else
		   crlinfo = entryInfo->crls;

	   /* Get today in CM_Time format to check for expired CRLs */
	   SRLi_GetSRTime(today);
	   if (strcmp(&crlinfo->nextDate[0], today) < 0)
	   {
		   /* Check for unspecified next update */
		   if (crlinfo->nextDate[0] == 0)
			   expired = FALSE;
		   else
			   expired = TRUE;
	   }

	   /* If app has refresh period set to LONG_MAX then override if
		* crl is expired */
	   if ( (session->crlRefreshPeriod != LONG_MAX) ||
		    (expired == TRUE))
	   {
		   /*
				If the Refresh time + the refresh Period is greater than
				our current time, then try to refresh the CRL. Also, if
				the CRL has expired try to get new CRL from LDAP.
			*/

		   if  ((crlinfo->RefreshTime+session->crlRefreshPeriod <  time(NULL)) ||
			  (expired == TRUE) < 0)
		   {
			   if (session->ldapInfo != NULL)
			   {
				   err = SLRi_RefreshCRL (sessionID, session->db_CRLRefSession, 
					   crlinfo, NULL, FALSE);
				   if (err == SRL_SUCCESS)
				   {
					   if (entry_data)
					   {
						   if (entry_data->item_ptr)
							   free (entry_data->item_ptr);
						   free(entry_data);
					   }

					   // Data got refreshed get the entry again
					   err = db_GetEntry(db_session, 0, (entryInfo == NULL) ? entry_data2 : &entry_kid,
										 &entry_data);
					   err = DB2SRLerr(err);
				   }
			   }
		   }
	   }
	   if(tmpcrlinfo != NULL)
			SRLi_FreeCRLEntryInfo_LL(tmpcrlinfo);
   }

   err = cvt_DBitem2Bytes(entry_data, &retData);
   // Try freeing our memory
   SRLi_FreeDB_Item(&kid1);
   SRLi_FreeDB_Item(&kid2);
   SRLi_FreeDB_Item(&entry_data);
   SRLi_FreeDB_Item(&entry_data2);
   // Return it to caller 
   *entryData = retData;
   db_unlock("SRL_DatabaseRetrieve", __LINE__);
   return(SRL_SUCCESS);
}
/*
-------------------------------------------------------------

SRL_DatabaseFlush

short SRL_DatabaseFlush(ulong sessionID, DBTypeFlag dbType);

This function is used to shrink the file space used by the database
indicated (cert or crl).  This routine would be called in order to
reorganize a database to compact the actual used space in a db file
after deletions of entries have been made. Depending on the number
of entries in a database, this may take a while.  At this point it is
up to the application to decide when or if this routine should be
called upon.

NOTE: Athough this routine only compacts the the db files at this
time - it was originally thought that we would support the weeding
out of expired, revoked, etc entries.  Maybe later.


Parameters:

   sessionID (input)
      Session identifier which was created by the calling app when
      it started up a session with the Retrieval Library

  dbType (input)
	   Database (cert or crl) to flush.


Return Value
        The funtion will return one of the following error codes

      SRL_SUCCESS                   no errors
      SRL_INVALID_PARAMETER          Bad parameter passed in
      SRLSession_NOT_VALID           session does not exist
      SRL_MEMORY_ERROR               out of memory

      various db file related errors also possible....
      DB_COMPACT_FAILED         could not compact the file
      DB_NO_WRITE               db file not open for writing

-------------------------------------------------------------
*/
SRL_API(short) SRL_DatabaseFlush(ulong sessionID, DBTypeFlag dbType)
{
   SRLSession_struct      *session;
   ulong             db_session;
   short            err;

   err =  SRLi_GetRetSessionFromRef(&session, sessionID);
   if(err != SRL_SUCCESS)
      return(err);

   if(dbType == SRL_DB_CERT)
   {
	   if (session->db_certRefSession == 0)
		   return SRL_NO_DB;
      db_session = session->db_certRefSession;
   }
   else if(dbType == SRL_DB_CRL)
   {
	   if (session->db_CRLRefSession == 0)
		   return SRL_NO_DB;
      db_session = session->db_CRLRefSession;
   }
   else
      return(SRL_INVALID_PARAMETER);

   db_lock("SRL_DatabaseFlush", __LINE__);

   /* at this time we only compact.  Later on we may iterate through
    * the db and look for expired certs, revoked certs, etc and
    * mark them for deletion, then compact the db.  Think about
    * this later.
    */
   err = db_Compact(db_session);
   err = DB2SRLerr(err);
   db_unlock("SRL_DatabaseFlush", __LINE__);
   return(err);   /* tell caller what the result is */

}
/*
-------------------------------------------------------------


SRL_DatabaseList()

short SRL_DatabaseList(ulong sessionID, dbEntryList_struct **dblist,
	DBTypeFlag dbType, CM_BOOL detailsFlag);

Description

Function used to get a linked list of all DNs (with optional info) from
either the certificate or CRL database. This function can be used by those
applications which may want to display a list of the items in the CM
database to a user, allowing them to possibly make a selection, then using
the entry info for further referance for the SRL_DatabaseRemove or
SRL_DatabaseRetrieve calls.  The linked list of DN's are returned in
alphabetically sorted order from low to high (A to Z).

NOTE: Although the collection of the info for the entries is optional, if
the application plans on allowing the user to interact with the list and
thereby select an item to retrieve or delete, then the application must
specify that info is to be gathered, else they won't be able to refer
to a particular entry.


Parameters:

   sessionID (input)
         Session identifier (context) that was created by the calling app
       when starting up a session with the Retrieval Library.

   dblist (input/output)
      storage for a db info ptr which will be filled in with linked list
      of dn's and their information (if asked for).

   dbType (input)
      This parameter allows the caller to specify if a list is to
      be created of all dn's of certificates or crl's. The
      parameter must be SRL_CERT_TYPE, or SRL_CRL_TYPE. (else an error
      of SRL_INVALID_PARAMETER will be returned)

   detailsFlag (input)
      This paramter is set to either TRUE or FALSE.  If TRUE then the
      information for the particular dn will be gathered and put into
      the linked list along with the dn of the entry.  If false, only
      dn's will be returned in the linked list.


Return Value
        The funtion will return one of the following error codes

      SRL_SUCCESS                   no errors
      SRL_INVALID_PARAMETER          Bad parameter passed in
      SRLSession_NOT_VALID           session does not exist
      SRL_MEMORY_ERROR               out of memory

      various db file related errors also possible....

-------------------------------------------------------------

*/

SRL_API(short) SRL_DatabaseList(ulong sessionID, dbEntryList_struct **dblist,
								DBTypeFlag dbType, CM_BOOL detailsFlag)
{
   DB_Kid            *entry_kid, *prevEntry;
   DB_Data            *entry_data;
   short            err, notUsed;
   SRLSession_struct      *session;
   dbEntryInfo_LL      *dbentry, *prev_dbentry;
   dbEntryList_struct   *theList;
   ulong             db_session;

   // Start caller off with nothing
   if (dblist != NULL)
	   *dblist = 0;
   /* check params */
   if((sessionID == 0) || (dblist == NULL))
      return(SRL_INVALID_PARAMETER);



   err =  SRLi_GetRetSessionFromRef(&session, sessionID);
   if(err != SRL_SUCCESS)
      return(err);

   if(dbType == SRL_DB_CERT)
   {
	   if (session->db_certRefSession == 0)
		   return SRL_NO_DB;
      db_session = session->db_certRefSession;
	}
   else if(dbType == SRL_DB_CRL)
   {
	   if (session->db_CRLRefSession == 0)
		   return SRL_NO_DB;
      db_session = session->db_CRLRefSession;
	}
	else
      return(SRL_INVALID_PARAMETER);

   /* allocate the db listing structure to hold the links */
   theList = (dbEntryList_struct *)calloc(1, sizeof(dbEntryList_struct) );
   if(theList == 0)
      return(SRL_MEMORY_ERROR);

   theList->typeflag = dbType;   /* record the list type for future referance */
   theList->entryList = 0;   /* start empty */

   /* now we will loop through all the entries in the database, gathering
    * the name for the entries, and if requested we will gather the
    * information for the named entry's data. For example, if working with
    * the cert db, we will gather all the DN's , and if info is requested,
    * we will also record the indexing info into the entry info struct
    * for each of the certs for that particular DN.
    */

   db_lock("SRL_DatabaseList", __LINE__);

   entry_kid = 0;   /* none retrieved yet */
   prev_dbentry = 0;
   prevEntry = 0;
   notUsed = TRUE;
   while(TRUE)
   {

      /* check to see if we need to get first entry in the database */
      if(entry_kid == 0)   /* if we didn't start list yet */
         err = db_GetFirstKid(db_session, &entry_kid);
      else
      {
         err = db_GetNextKid(db_session, prevEntry, &entry_kid);

         /* once we've asked for the next entry, we will no
          * longer need the ref to the prev entry, so
          * free up it's struct (not always the internal since
          * use that if it's a dn)
          */
         if(prevEntry != 0)
         {
            if( notUsed)
              free(prevEntry->item_ptr);
           free(prevEntry);
           prevEntry = 0;
         }
     }
      prevEntry = entry_kid;   /* record for next loop iteration */
      notUsed = TRUE;

      err = DB2SRLerr(err);

      if(err != SRL_SUCCESS)
      {
         if(err == SRL_NOT_FOUND)   /* are there no more entries */
            break;   /* all done looping */

         goto error_cleanup;   /* if other errors occured */
      }


      /* if this is a dn entry index type item, record it */
   /*   if( isalpha(entry_kid->item_ptr[0])) */
      if( SRLi_isDN(entry_kid->item_ptr[0]))
      {
         notUsed = FALSE;   /* we used it */
         dbentry = (dbEntryInfo_LL*) calloc(1, sizeof(dbEntryInfo_LL));
         if(dbentry == 0)
         {
            err = SRL_MEMORY_ERROR;
            goto error_cleanup;
         }

         if(theList->entryList == 0)   /* if we didn't start list yet */
            theList->entryList = dbentry;   /* top of list */
         else
            prev_dbentry->next = dbentry;   /* add a new link to existing list */

         prev_dbentry = dbentry;   /* record for next loop of while */

         /* init the fields */
         dbentry->info.certs = 0;   /* union'd field */
         dbentry->next = 0;

         /* since entry_kid is our own copy, just put the ptr into
          * the name field.
          */
         dbentry->entry_DN = entry_kid->item_ptr;

         /* if gathering info, need to get the related data for the
          * kid.
          */
         if(detailsFlag == TRUE)
         {

            err = db_GetEntry(db_session, 0, entry_kid,  &entry_data);
            err = DB2SRLerr(err);

            if(err != SRL_SUCCESS)
               goto error_cleanup;
//prevEntry = entry_data;
            /* break up the info template into it's components,
             * since there may be more than one cert/crl for
             * the given dn
             */
            if(dbType == SRL_DB_CERT)
               err = SRLi_CertInfoFromTemplate(db_session, &(dbentry->info.certs), entry_data);
			  
            else /* if(dbType == SRL_CRL_TYPE) */
               err = SRLi_CRLInfoFromTemplate(db_session, &(dbentry->info.crls), entry_data);

            /* we no longer need the entry data - it's copied to
             * new fields.
             */
            free(entry_data->item_ptr);   /* the buffer */
            free(entry_data);   /* the struct */
            entry_data = 0;


            if(err != SRL_SUCCESS)
               goto error_cleanup;

         }
      }

      /* since we are just grabbing each item in the database here, the
       * other kids that are returned may be for the actual data (either
       * certs or crls in their encoded form) which we are not
       * gathering here.
       * so we just skip to the next iteration of the loop.
       */

   }

   /* end of while loop. If we got here, then everything should
    * have worked out fine.  Give the caller a ref to the
    * newly created list. (we will sort it first )
    */

	theList->entryList = SRLi_SortdbEntryLL(theList->entryList);

   *dblist = theList;/* give caller the sorted list */

   db_unlock("SRL_DatabaseList", __LINE__);
   return(SRL_SUCCESS);

error_cleanup:
   if(theList != 0)   /* did we allocate any mem */
      SRL_FreeDBListing(&theList); /* struct and it's LL contents */

   db_unlock("SRL_DatabaseList", __LINE__);
   return(err);
}

/*
-------------------------------------------------------------

Function: SRL_DatabaseAdd()

short SRL_DatabaseAdd(ulong sessionID, Bytes_struct *asn1Obj,
	AsnTypeFlag type);

Description

This function is used to add Certificates, Certification paths, or CRLs to
the RT database.  The objects added are in ASN.1 encoded format.  The
certificate manager will add those items which are not exact duplicates of
items already in the database.

parameters:
   sessionID (input) = the RT session that was previously created with
         the Certificate manager

   asn1Obj (input) = the asn.1 encoded data - a certificate, CRL, or
         a certification path.

   type (input) = the type of encoded item pointed at by asn1_item,
      being one of : SRL_CERT_TYPE, SRL_CERTPATH_TYPE or SRL_CRL_TYPE
      If the item is a cert, and it's public key is to be considered
      trusted, then use the flag SRL_TRUSTED_CERT_TYPE. If the cert is
      not selfsigned, and SRL_TRUSTED_CERT_TYPE is passed, then an error
      of SRL_NOT_SELF_SIGNED will be returned, and the cert will not be
      added to the database.

returns:
   SRL_SUCCESS         - added ok
   SRL_INVALID_PARAMETER      - illegal input parameter
   SRL_ASN_ERROR   - badly formed asn.1 encoding
   SRL_NOT_SELF_SIGNED   - cert is not self signed

   other pass thru errors... later

-------------------------------------------------------------
*/


SRL_API(short) SRL_DatabaseAdd(ulong sessionID, Bytes_struct *asn1Obj,
							   AsnTypeFlag type)
{
	short err;
	db_lock("SRL_DatabaseAdd", __LINE__);
	err = SRLi_DatabaseAdd(sessionID, asn1Obj, type, NULL);
	db_unlock("SRL_DatabaseAdd", __LINE__);

	return err;
}

short SRLi_DatabaseAdd(ulong sessionID, Bytes_struct *asn1Obj,
					   AsnTypeFlag type, const char *kid_str)
{
   Cert_struct			*dec_cert = NULL;
   SRL_CertList			 *dec_cpath = NULL;
   CRL_struct			*dec_crl = NULL;
   Bytes_struct			*asn1data = NULL;
   AsnTypeFlag			addTypeFlag;
   short				err = SRL_SUCCESS;
   CM_Time       today;
   CM_BOOL		trustedFlag = FALSE;
   SRLSession_struct *srlSessionInfo = NULL;

   /* check params */
   if((sessionID == 0) || (asn1Obj == NULL))
      return(SRL_INVALID_PARAMETER);

	/* Point to the Data Object */
   asn1data = asn1Obj;
   addTypeFlag = type;
   trustedFlag = FALSE;   /*most items will not have special status */

  /* Get the session from the session ID */
   err = SRLi_GetSessionFromRef (&srlSessionInfo, sessionID);
   if (err != SRL_SUCCESS)
	   return (err);

   if (type != SRL_CRL_TYPE)
   {
		if (srlSessionInfo->db_certRefSession == 0)
			return SRL_NO_DB;
   }
   else
   {
	   if (srlSessionInfo->db_CRLRefSession == 0)
		   return SRL_NO_DB;
   }

   if (type == SRL_CA_CERT_TYPE)
   {
	   /* ldap will return a SRL_CA_CERT_TYPE for a CA Cert */
      addTypeFlag = SRL_CERT_TYPE;   /* added as a cert */
      trustedFlag = FALSE;         /* with special trusted status */
   }
   else if (type == SRL_TRUSTED_CERT_TYPE)
   {
	   /* ldap will return a SRL_TRUSTED_CERT_TYPE for a Trusted Cert */
      addTypeFlag = SRL_CERT_TYPE;   /* added as a cert */
      trustedFlag = TRUE;         /* with special trusted status */
   }
   else if (type == SRL_ARL_TYPE)
   {
	   /* ldap will return a SRL_ARL_TYPE for a Authority Revocation List */
	   addTypeFlag = SRL_CRL_TYPE;
   }
   else if (type == SRL_DELTA_CRL_TYPE)
   {
	   /* ldap will return a SRL_DELTA_CRL_TYPE for a Delta CRL */
	   addTypeFlag = SRL_CRL_TYPE;
   }

   if((addTypeFlag != SRL_CERT_TYPE) && (addTypeFlag != SRL_CERT_PATH_TYPE) &&
      (addTypeFlag != SRL_CRL_TYPE))
      return(SRL_INVALID_PARAMETER);


   dec_cert = 0;
   dec_cpath = 0;
   dec_crl = 0;
   err = SRL_SUCCESS;


   /* need to decode the asn1 data before we add it to the database */
   if(addTypeFlag == SRL_CERT_TYPE)
   {
	   if (srlSessionInfo->CertFileName == NULL)
	   {
		   return SRL_INVALID_PARAMETER;
	   }
      err = CM_DecodeCert(asn1data, &dec_cert);
      if(err == SRL_SUCCESS)
      {
         /* check to see if the trustedFlag is TRUE (CA Cert), if so we have some
          * limitations we impose - it must be a self signed certificate
          * at this point, and for some algs we require parameters.
          *
          */

         if ((trustedFlag == TRUE) && (isRoot(dec_cert)))
         {
            if(SRLDNcmp(dec_cert->issuer, dec_cert->subject) != 0)
            {
               CM_FreeCert(&dec_cert);
               return(SRL_NOT_SELF_SIGNED);
            }
            
            /* additional check: certificate must contain
             * a signature key - otherwise it adds nothing
             * (for our purposes) to save this certificate
             * as a special trusted cert.
             */
            if( (strcmp(dec_cert->pub_key.oid, gDSA_OID) != 0) &&
               (strcmp(dec_cert->pub_key.oid, gDSA_KEA_OID) != 0) &&
			   (strcmp(dec_cert->pub_key.oid, gOIW_DSA) != 0) &&
               (strcmp(dec_cert->pub_key.oid, gRSA_OID) != 0))
            {
               CM_FreeCert(&dec_cert);
               return(SRL_NOT_SIG_KEY);            
            }

            /* could check for anything other than RSA, but
             * we will check against each we handle - easier
             * to add others later if need be....
             */
             
            /* modification: Only check for known SIG algs here 
             * which require parameters.
             */
            if(/*(strcmp(dec_cert->pub_key.oid, gKEA_OID) == 0) ||
               (strcmp(dec_cert->pub_key.oid, gDH_OID) == 0) || */
               (strcmp(dec_cert->pub_key.oid, gDSA_OID) == 0) ||
				(strcmp(dec_cert->pub_key.oid, gOIW_DSA) == 0) ||
               /*(strcmp(dec_cert->pub_key.oid, gMOSAIC_DSA_OID) == 0) || */
               (strcmp(dec_cert->pub_key.oid, gDSA_KEA_OID) == 0))

            {
               /* need params for these algs, in unionized field,
                * so check any of them for null.
                */
               if(dec_cert->pub_key.params.encoded == 0)
               {
                  CM_FreeCert(&dec_cert);
                  return SRL_MISSING_PARAMETERS;
               }
            }
       
            /* given that the signature is good, verify that the
             * date range is still good.
             */

			SRLi_GetSRTime(today);

            if(strcmp(dec_cert->val_not_before, today) > 0)
            {
               CM_FreeCert(&dec_cert);
               return(SRL_CERT_NOT_YET_VALID);
            }
            if(strcmp(dec_cert->val_not_after, today) < 0)
            {
               CM_FreeCert(&dec_cert);
               return(SRL_CERT_EXPIRED);
            }
			 /* go add the certificate and it's indexing info */
			 err = SRLi_AddCertToDB(sessionID, asn1data, dec_cert,trustedFlag,
				 SRL_CA_CERT_TYPE, kid_str);

		 }
		 else
		 {
			 trustedFlag = FALSE; // Must be a CA Cert LDAP Atribute
			/* go add the certificate and it's indexing info */
			err = SRLi_AddCertToDB(sessionID, asn1data, dec_cert,trustedFlag, 
				SRL_CERT_TYPE, kid_str);
		 }
	  }

	  if(dec_cert != NULL)
			 CM_FreeCert(&dec_cert);
	
   }
   else if(addTypeFlag == SRL_CERT_PATH_TYPE)
   {
   	   if (srlSessionInfo->CertFileName == NULL)
	   {
		   return SRL_INVALID_PARAMETER;
	   }

      /* break up the asn1 coding of the certification path
       * into certificate components. (creates ptrs into
       * the asn1 block for each cert...)
       */
      err = SRLi_BreakUpCertList(sessionID, asn1Obj->data, &dec_cpath);
      if(err == SRL_SUCCESS)
      {

         /* get a decoded version of each of the certs in the
          * path - for adding to the db down below, used in
          * creation of indexing info.
          */
         err = SRLi_DecodeCertList(sessionID, dec_cpath);
         if(err == SRL_SUCCESS)
         {
            /* go add all the certs and indexing info to the db. */
            err = SRLi_AddCertListToDB(sessionID, dec_cpath, SRL_CERT_TYPE);
         }

         /* whether or not there was an error in decoding, we
          * don't need the linked list structure anymore, and
          * it will be released below.
          */
      }

      if(dec_cpath != NULL)
      {
         /* get rid of our linked list of structs, and any
          * certs that may have been decoded (cert structs)
          */
         SRLi_FreeBrokenCertList(sessionID, &dec_cpath);
      }

   }
   else   /* addTypeFlag == SRL_CRL_TYPE */
   {
  	   if (srlSessionInfo->CRLFileName == NULL)
	   {
		   return SRL_INVALID_PARAMETER;
	   }

	  // Decode the crl don't decode the revocations
     err = CM_DecodeCRL2(asn1data, &dec_crl, FALSE, TRUE);

      if(err == SRL_SUCCESS)
      {
         /* go add all the CRL and indexing info to the db */
         err = SRLi_AddCRLToDB(sessionID, asn1data, dec_crl,SRL_CRL_TYPE, kid_str);

      }

      if(dec_crl != NULL)
         CM_FreeCRL(&dec_crl);
   }

	/* Convert CM error to SRL error if necessary */
	if ((err == CM_ASN_ERROR) || (err == CMLASN_UNKNOWN_ERROR))
		err = SRL_ASN_ERROR;

	return err;
}

/*
-------------------------------------------------------------

Function

SRL_DatabaseRemove()

short SRL_DatabaseRemove(ulong sessionID, DBTypeFlag entryType,
	dbEntryInfo_LL *entryInfo, long DBid);

Description

This function will delete the database item indicated by the entry
info provided - which will be an ASN.1 encoded certificate, or CRL.
Once this routine finishes, the item will no longer be retrievable
from the database. (The entry indexing info is and related data is
removed.)

Parameters:

   sessionID (input)
         Session identifier (context) that was created by the calling app
       when starting up a session with the CM.

   entryType (input)
      what type of entry this is, a cert db entry (SRL_CERT_TYPE) or
      a crl db entry (SRL_CRL_TYPE)

   entryInfo (input)
      The info taken from the entry for the item you wish to delete
      from the database. ( entry info discused in SRL_DatabaseList)


Return Value
        The funtion will return one of the following error codes

      SRL_SUCCESS                   no errors
      SRL_INVALID_PARAMETER          Bad parameter passed in
      SRLSession_NOT_VALID           session does not exist
      SRL_MEMORY_ERROR               out of memory

      various db file related errors also possible....

-------------------------------------------------------------

*/

SRL_API(short) SRL_DatabaseRemove(ulong sessionID, DBTypeFlag entryType,
								  dbEntryInfo_LL *entryInfo, long DBid)
{
	short err;
	db_lock("SRL_DatabaseRemove", __LINE__);	
	err = SRLi_DatabaseRemove(sessionID, entryType,
		entryInfo, DBid);
	db_unlock("SRL_DatabaseRemove", __LINE__);

	return err;
}
	

short SRLi_DatabaseRemove(ulong sessionID, DBTypeFlag entryType,
								  dbEntryInfo_LL *entryInfo, long DBid)
{
   ulong             db_session;
   CM_BOOL			getentry = TRUE;
   SRLSession_struct      *session;
   short            err;
   DB_Data            *entry_data = NULL;
   DB_Kid            entry_kid, index_kid;
   DB_Kid		*kid1 = NULL, *kid2 = NULL;
   DB_Data		*entry_data2 = NULL;
   char            *tempPtr;
   long           len = 0, biglen =0, HashValue = 0;

   /* check parameters */
   if (sessionID == 0) 
      return(SRL_INVALID_PARAMETER);

   if ((entryInfo == 0) && (DBid == 0))
	   return(SRL_INVALID_PARAMETER);

   err =  SRLi_GetRetSessionFromRef(&session, sessionID);
   if(err != SRL_SUCCESS)
      return(err);

    if(entryType == SRL_DB_CERT)
    {
	   if (session->db_certRefSession == 0)
		   return SRL_NO_DB;
      db_session = session->db_certRefSession;
	}
    else if(entryType == SRL_DB_CRL)
	{
		if (session->db_CRLRefSession == 0)
			return SRL_NO_DB;
      db_session = session->db_CRLRefSession;
	}
   else
      return(SRL_INVALID_PARAMETER);

   if (entryInfo != NULL)
   {
	   if (entryType != SRL_DB_CRL)
	   {
		if(entryInfo->info.certs == 0)
			  return(SRL_INVALID_PARAMETER);
	   }
	   else
	   {
		   if (entryInfo->info.crls == 0)
			   return(SRL_INVALID_PARAMETER);
	   }
   }
   
	entry_kid.item_ptr = NULL;
	entry_kid.item_len = 0;


   /* given the info about the entry, construct the indexing template info
    * which in turn will be used as the kid (keying identifier data) for
    * the cert or crl data that corresponds to this item.
    */
   if(entryType == SRL_DB_CERT)
   {
	   if (DBid > 0)
	   {
		   
		   err = db_GetDBItemsByID(db_session, DBid,
									&kid1, &entry_data, 
									&kid2, &entry_data2 );
		   if (err != SRL_SUCCESS)
		   {
					if (kid2 != NULL)
						SRLi_FreeDB_Item(&kid2);
					if (entry_data != NULL)
						SRLi_FreeDB_Item(&entry_data);
					if (entry_data2 != NULL)
						SRLi_FreeDB_Item(&entry_data2);
					return err;
		   }

		   getentry = FALSE;
	   }
	   else
			err = SRLi_TemplateFromCertInfo(&entry_kid, entryInfo->info.certs);
   }
   else if (entryType == SRL_DB_CRL)
   {
	   if (DBid)
	   {
		   
		   err = db_GetDBItemsByID(db_session, DBid,
									&kid1, &entry_data, 
									&kid2, &entry_data2 );
		   if (err != SRL_SUCCESS)
		   {
				err = DB2SRLerr(err);
				if (kid1 != NULL)
					SRLi_FreeDB_Item(&kid1);
				if (kid2 != NULL)
					SRLi_FreeDB_Item(&kid2);
				if (entry_data != NULL)
					SRLi_FreeDB_Item(&entry_data);
				if (entry_data2 != NULL)
					SRLi_FreeDB_Item(&entry_data2);
				return err;
		   }

			getentry = FALSE;
	   }
	   else
		   err = SRLi_TemplateFromCRLInfo(&entry_kid, entryInfo->info.crls);
   }
   else
   {
	   return SRL_INVALID_PARAMETER;
   }

   if(err != SRL_SUCCESS)
   {
      return(err);
   }

   if (entry_data != NULL)
   { 
	   SRLi_FreeDB_Item(&entry_data);
   }   

   if (getentry)
	{
	   /* 
		* Based on the template kid, we need to delete the 
		* item (cert or crl) and the corresponding
		* index entry for this particular dn.
		*/
	   err = db_DeleteEntry(db_session, &entry_kid);
	   err = DB2SRLerr(err);

	   /* now get the index info for this dn and update it (if this
		* was the last item for this dn, then we just remove it.)
		*/

	   index_kid.item_ptr = entryInfo->entry_DN;   /* use the name */
	   index_kid.item_len = strlen(entryInfo->entry_DN) + 1;   /* include terminating null */

	   /* get the corresponding index data (cert or crl) for this entry */
	   err = db_GetEntry(db_session, 0, &index_kid,  &entry_data);
	   err = DB2SRLerr(err);

	   if(err != SRL_SUCCESS)
	   {
		  free(entry_kid.item_ptr);   /* don't need the template anymore */
		  return(err);
	   }

	   /* check the length of the block against the length of the first
		* index template entry, if the same we know this is the last one.
		*/
	   tempPtr = entry_data->item_ptr;
	   memcpy(&len, tempPtr, 4); /* length of this template in block */
		if (SRLisLittleEndian())
		  SRLi_FlipLongs(&len, 1);
	   len = len & 0x00FFFFFF;
   
	   if(entry_data->item_len == len)
	   {
		  /* then this is the only entry, remove it */
		  err = db_DeleteEntry(db_session, &index_kid);
		  free(entry_kid.item_ptr);   /* don't need the template anymore */
		  free(entry_data->item_ptr);   /* don't need the data anymore */
		  free(entry_data);   /* or it's struct */
		  err = DB2SRLerr(err);
		  return(err);   /* we are done, either it worked or it didn't */
	   }

	   /* else we need to scan through and find the particular one of
		* interest.
		*/
	   biglen = entry_data->item_len;   /* length of the whole block of mem */

	   while(biglen > 0)   /* scan the block till we find it */
	   {
		  memcpy(&len, tempPtr, 4); /* length of this template in block */
			if (SRLisLittleEndian())
			   SRLi_FlipLongs(&len, 1);
		  len = len & 0x00FFFFFF;
      
		  if(len == entry_kid.item_len)
		  {
			 /* same size, do a comparison */
			 if(memcmp(tempPtr, entry_kid.item_ptr, len) == 0)   /* if they are equal */
			 {
				/* found the one to remove, need to copy any further data
				 * after this template and scrunch it up, then update the
				 * index info into the db file.
				 */
				/* copy remaining data following this template */
				memcpy(tempPtr, tempPtr+len, biglen-len);

				/* that shrunk it down, update the entry info */
				entry_data->item_len -= len;   /* sub how much we removed */

				err = db_StoreItem(db_session, &index_kid, entry_data, &HashValue, DB_REPLACE);

				/* free up our temp data storage, then tell caller
				 * what the result is.
				 */
				free(entry_kid.item_ptr);   /* don't need the template anymore */
				free(entry_data->item_ptr);   /* don't need the data anymore */
				free(entry_data);   /* or it's struct */
				err = DB2SRLerr(err);
				return(err);
			 }

		  }

		  /* move onto the next one, if there is one */
		  tempPtr += len;
		  biglen -= len;

	   }
	} 
	else
	{
	   /* 
		* Based on the template kid, we need to delete the 
		* item (cert or crl) and the corresponding
		* index entry for this particular dn.
		*/
	   err = db_DeleteEntry(db_session, kid1);
	   err = DB2SRLerr(err);

	   tempPtr = entry_data2->item_ptr;

		// Based on the DB Id, return the associated DN kid */
	   index_kid.item_ptr = kid2->item_ptr;   /* use the name */
	   index_kid.item_len = kid2->item_len;   /* include terminating null */


	   /* check the length of the block against the length of the first
		* index template entry, if the same we know this is the last one.
		*/
	   memcpy(&len, tempPtr, 4); /* length of this template in block */
	   if (SRLisLittleEndian())
		   SRLi_FlipLongs(&len, 1);
	   len = len & 0x00FFFFFF;

   
	   if(entry_data2->item_len == len)
	   {
		  /* then this is the only entry, remove it */
		  err = db_DeleteEntry(db_session, &index_kid);
		  if (entry_kid.item_ptr != NULL)
			  free (entry_kid.item_ptr);
		  SRLi_FreeDB_Item (&entry_data);
		  // Free our memory
		  SRLi_FreeDB_Item (&entry_data);
		  SRLi_FreeDB_Item (&entry_data2);
		  SRLi_FreeDB_Item (&kid1);
		  SRLi_FreeDB_Item (&kid2);
		  err = DB2SRLerr(err);
		  return(err);   /* we are done, either it worked or it didn't */

	   }

	   /* else we need to scan through and find the particular one of
		* interest.
		*/
	   biglen = entry_data2->item_len;   /* length of the whole block of mem */

	   while(biglen > 0)   /* scan the block till we find it */
	   {
		  memcpy(&len, tempPtr, 4); /* length of this template in block */
			if (SRLisLittleEndian())
			   SRLi_FlipLongs(&len, 1);
		  len = len & 0x00FFFFFF;
      
		  if(len == kid1->item_len)
		  {
			 /* same size, do a comparison */
			 if(memcmp(tempPtr, kid1->item_ptr, len) == 0)   /* if they are equal */
			 {
				/* found the one to remove, need to copy any further data
				 * after this template and scrunch it up, then update the
				 * index info into the db file.
				 */
				/* copy remaining data following this template */
				memcpy(tempPtr, tempPtr+len, biglen-len);

				/* that shrunk it down, update the entry info */
				entry_data2->item_len -= len;   /* sub how much we removed */

				err = db_StoreItem(db_session, &index_kid, entry_data2, &HashValue, DB_REPLACE);

				/* free up our temp data storage, then tell caller
				 * what the result is.
				 */
				SRLi_FreeDB_Item (&entry_data);
				SRLi_FreeDB_Item (&entry_data2);
				SRLi_FreeDB_Item (&kid1);
				SRLi_FreeDB_Item (&kid2);
				err = DB2SRLerr(err);
				return(err);
			 }

		  }

		  /* move onto the next one, if there is one */
		  tempPtr += len;
		  biglen -= len;

	   }


	}
   /* if we get down here, then we didn't find it, which is a REALLY BAD
    * SIGN.  Better tell caller.
    */
	SRLi_FreeDB_Item (&entry_data);
	SRLi_FreeDB_Item (&entry_data2);
	SRLi_FreeDB_Item (&kid1);
	SRLi_FreeDB_Item (&kid2);
	if (entry_kid.item_ptr != NULL)
		free (entry_kid.item_ptr);
	SRLi_FreeDB_Item(&entry_data);
    return(SRL_DB_INDEX_ERROR);
}


short SRLi_BreakUpCertList(ulong cm_session, uchar *asndata, SRL_CertList **cp)
{
    long    seqDone;
    ulong   totalElmtsLen1;
    ulong   elmtLen1, elmtLen0;
    ulong   tagId1, dec_count;
   ulong   totalCAElmtsLen3, pairDecCount;
   SRL_CertList   *cpath, *head;
   short   err;
   uchar   *certPtr;

/*
last item in the linked list is the subject cert, each
issuer then follows on up the linked list till you get
to the head of the linked list (so head can be the "trusted" cert)

*/

   cpath = NULL;
   head = NULL;
   totalElmtsLen1 = 0;
   dec_count = 0;
   seqDone = FALSE;
   /* caller is providing the whole encoded buffer, thus they did not
    * read the leading SEQ tag, or the length value for the sequence.
    * We will do that here.
    */
   err = ASN_SRLDecTag(asndata, &dec_count, &tagId1);
   totalElmtsLen1 += dec_count;      /* track what we've processed */
   asndata +=    dec_count;   /* inc ptr past what we've processed */
   dec_count = 0;   /* reset each time */

   if(err != SRL_SUCCESS)
      return(err);

   /* make sure it's a sequence tag */
   if(tagId1 != UNIV_CONS_SEQ_TAG)
      return(SRL_ASN_ERROR); /* what they passed us is not a certificate path */


   /* read length of whole user cert portion of the cert path seq (ie does not
    * include CA portion whether or not it is around)
    */

   err = ASN_SRL_DecLen(asndata, &dec_count, &elmtLen0);
   totalElmtsLen1 += dec_count;      /* track what we've processed */
   asndata +=    dec_count;   /* inc ptr past what we've processed */
   dec_count = 0;   /* reset each time */

   if(err != SRL_SUCCESS)
      return(err);

   /* reset the element total count here so that we use it to track
    * the subcontents/elements.
    */
   totalElmtsLen1 = 0;

   /* record the data ptr here, assuming that it will indeed be a
    * cert seq.
    */
   certPtr = asndata;   /* will record into linked list down below if it checks out */

   /* read the next tag in the buffer, should be a tag for subject Certificate seq */
   err = ASN_SRLDecTag(asndata, &dec_count, &tagId1);
   totalElmtsLen1 += dec_count;      /* track what we've processed */
   asndata +=    dec_count;   /* inc ptr past what we've processed */
   dec_count = 0;   /* reset each time */

   if(err != SRL_SUCCESS)
      return(err);

   if(tagId1 != UNIV_CONS_SEQ_TAG)
      return(SRL_ASN_ERROR);

   /* get length of the cert seq element */
   err = ASN_SRL_DecLen(asndata, &dec_count, &elmtLen1);
   totalElmtsLen1 += dec_count;      /* track what we've processed */
   asndata +=    dec_count;   /* inc ptr past what we've processed */
   dec_count = 0;   /* reset each time */
   if(err != SRL_SUCCESS)
      return(err);

   /* record the subject certificate ptr, certPtr should be pointing
    * at the start.
    */
   cpath = (SRL_CertList *) calloc(1, sizeof(SRL_CertList));
   if(cpath == NULL)
      return(SRL_MEMORY_ERROR);

   cpath->asn1cert = certPtr;   /* first is subject cert for now */
   cpath->next = NULL;
   cpath->cert = NULL;

   head = cpath;      /* top of the list right now */

   /* need to inc asnptr here, but since we didn't actually decode
    * need to offset by the len value we decoded above.
    */

   totalElmtsLen1 += elmtLen1;
   asndata += elmtLen1;   /* update ptr  */

   if ( (elmtLen0 != INDEFINITE_LEN) && (totalElmtsLen1 == elmtLen0))
      seqDone = TRUE;   /* no more here */

   else
   {
      err = ASN_SRLDecTag(asndata, &dec_count, &tagId1);
      totalElmtsLen1 += dec_count;      /* track what we've processed */
      asndata +=    dec_count;   /* inc ptr past what we've processed */
      dec_count = 0;   /* reset each time */
      if(err != SRL_SUCCESS)
         goto ErrorExit;

      if ((elmtLen0 == INDEFINITE_LEN) && (tagId1 == EOC_TAG_ID))
      {
         /* pull out the ending zero */
         if(*asndata != 0)
         {
            free(head);   /* free up the only thing we allocated so far */
            return(SRL_ASN_ERROR);
         }
         totalElmtsLen1++;   /* just read another byte above */
         asndata++;   /* update ptr  */

         seqDone = TRUE;
      }
   }

   /* now process the issuer pairs if they exist */
    if ((!seqDone) && ( tagId1 == UNIV_CONS_SEQ_TAG))
    {
      err = ASN_SRL_DecLen(asndata, &dec_count, &elmtLen1);
      totalElmtsLen1 += dec_count;      /* track what we've processed */
      asndata +=    dec_count;   /* inc ptr past what we've processed */
      dec_count = 0;   /* reset each time */


      totalCAElmtsLen3 = 0;
      pairDecCount = 0;
       while (  (pairDecCount < elmtLen1) || (elmtLen1 == INDEFINITE_LEN))
       {
       
         err = SRLi_BreakUpCertPair(asndata,elmtLen1, &totalCAElmtsLen3, &head);
       
          pairDecCount += totalCAElmtsLen3; /* inc running total */
          
          /* inc our buff ptr by amount processed */
          asndata += totalCAElmtsLen3;
          
         totalCAElmtsLen3 = 0;    /* reset count for next loop iteration */
       } /* end of while */

       totalElmtsLen1 += pairDecCount; /* inc the cumulative count */

      seqDone = TRUE;

      if ( elmtLen0 == INDEFINITE_LEN )
      {
         if(asndata[0] == 0 && asndata[1] == 0)
         {
            totalElmtsLen1 += 2;
            asndata += 2;
         }
         else
         {
            err = SRL_ASN_ERROR;
            goto ErrorExit;
         }
      }
      else if (totalElmtsLen1 != elmtLen0)
       {
         err = SRL_ASN_ERROR;
         goto ErrorExit;
      }

    } /* of pairs seq handling */


    if (!seqDone)
    {
      err = SRL_ASN_ERROR;
      goto ErrorExit;
   }

   /* at this point we have recorded all the cert ptrs, if the caller wants
    * the decoded versions of each of the certs, he will need to step through
    * and decode all the certs in the linked list, starting at the head
    * and working his way to the subject cert.
    */

   /* I'm going to assume we got done all fine if we get here */
   *cp = head;   /* give caller access to the new stuff */

   return(SRL_SUCCESS);

ErrorExit:
   /* put clean up code here since I didn't want to have to replicate
    * stepping through the linked list all over the place above for
    * each error flag check. (ok it's a separate routine now...)
    */
   if(head != NULL)
   {
      /* have a partial list, free up all the struct members */
      SRLi_FreeBrokenCertList(cm_session, &head);
   }

   /* done here, tell caller what the error is */
   return(err);

}


SRL_API(short) SRL_GetTrustedCerts(ulong session, EncCert_LL **pCertList)
{
	short err;
	dbEntryList_struct	*dbList = NULL;
	dbEntryInfo_LL		*dbEntry;
	dbCertEntryInfo_LL	*wrkCerts;
	EncCert_LL			*workCertList,
						*prevCert;
	dbEntryInfo			certInfo;
	Bytes_struct		*entryData;

	/* Check parameters */
	if (pCertList == NULL)
		return (SRL_INVALID_PARAMETER);

	/* Initialize resulting list */
	*pCertList = NULL;

	/* Call SRL_DatabaseList to get a list of certs */
	err = SRL_DatabaseList(session, &dbList, SRL_DB_CERT, TRUE);
	if (err != SRL_SUCCESS)
		return err;

	/* Check that the results are correct */
	if ((dbList == NULL) || (dbList->entryList == NULL) ||
		(dbList->typeflag != SRL_DB_CERT))
	{
		SRL_FreeDBListing(&dbList);
		return SRL_NOT_FOUND;
	}

	/* Loop through the entries */
	prevCert = NULL;
	dbEntry = dbList->entryList;
	while (dbEntry != NULL)
	{
		/* Loop through the certs for this entry */
		wrkCerts = dbEntry->info.certs;
		while (wrkCerts != NULL)
		{
			/* If this cert is trusted, add it to the resulting EncCert_LL */
			if (wrkCerts->trusted)
			{
				/* Allocate and clear memory for a new EncCert_LL */
				workCertList = calloc(1, sizeof(EncCert_LL));
				if (workCertList == NULL)
				{
					SRL_FreeEncCertList(pCertList);
					SRL_FreeDBListing(&dbList);
					return SRL_MEMORY_ERROR;
				}

				/* Add this new link to the end of the list */
				if (prevCert == NULL)
					*pCertList = workCertList;
				else
					prevCert->next = workCertList;
				prevCert = workCertList;

				/* Retrieve the ASN.1 encoded cert */
				certInfo.certs = wrkCerts;
				err = SRL_DatabaseRetrieve(session, SRL_DB_CERT, &certInfo,
					&entryData, 0);
				if (err != SRL_SUCCESS)
				{
					SRL_FreeEncCertList(pCertList);
					SRL_FreeDBListing(&dbList);
					return err;
				}

				/* Copy the ASN.1 encoded cert */
				workCertList->encCert.num = entryData->num;
				workCertList->encCert.data = entryData->data;
				entryData->data = NULL;
				free(entryData);
			}

			/* Move to next cert in this entry */
			wrkCerts = wrkCerts->next;

		} /* end of while */

		/* Move to the next entry in the list */
		dbEntry = dbEntry->next;

	} /* end while */

	/* Free the Data Base List */
	SRL_FreeDBListing(&dbList);

	return (SRL_SUCCESS);
}

/* CMU_GetCMTime()
 *
 * This routine fills in the caller provided string with
 * the current time.  The string is filled in with the time
 * in our internally used format of: yyyymmddhhmmssZ
 */
short SRLi_GetSRTime(char *cm_time)
{
	time_t current;

	cm_time[0] = '\0';

	time(&current);			// localized time

	return time2CMTime(current, cm_time);
}


// time2CMTime() converts a local time_t value into a CM_Time string
short time2CMTime(time_t t, char cm_time[CM_TIME_LEN])
{
	struct tm *utc;
	int year, month, day, hour, min, sec;
	// Acquire a handle to the mutex

	// Convert the time value to GM time */
	utc = gmtime(&t);
	if (utc == NULL)
		return SRL_UNKNOWN_ERROR;

	// Initialize the temporary date/time variables
	year = utc->tm_year + 1900;		// tm_year is years since 1900
	month = utc->tm_mon + 1;		// tm_mon is years since Jan
	day = utc->tm_mday;
	hour = utc->tm_hour;
	min = utc->tm_min;
	sec = utc->tm_sec;

	// Create the string
	if (sprintf(cm_time, "%d%02d%02d%02d%02d%02dZ", year, month, day, hour,
		min, sec) != CM_TIME_LEN - 1)
		return SRL_UNKNOWN_ERROR;

	return SRL_SUCCESS;
}
static CM_BOOL isRoot(Cert_struct *cert)
{
/* This function will return TRUE if this certificate is a root cert and FALSE
if not.  To be considered a root cert, a cert must be self-signed, contain a 
signature key, be a CA, and be authorized to sign certs.
*/
	Basic_cons_struct* basicConstraints;
	unsigned short* keyUsage;

	/* Check that the issuer and subject DNs (and v2 Unique IDs if present) 
	match.  If not, return FALSE. */
    if ((SRLDNcmp(cert->issuer, cert->subject) != 0) ||
		!CompareBytes(cert->issuer_id, cert->subj_id))
		return FALSE;

	/* Check that the public key algorithm is a signature algorithm.  If not,
	return FALSE. */
	if ((strcmp(cert->pub_key.oid, gDSA_OID) != 0) &&
		(strcmp(cert->pub_key.oid, gOIW_DSA) != 0) && 
		(strcmp(cert->pub_key.oid, gRSA_OID) != 0) &&
		(strcmp(cert->pub_key.oid, gDSA_KEA_OID) != 0))
		return FALSE;

	/* If the Basic Constraints extension is present, check that the CA flag
	is set. Return FALSE, if the flag is present and not set. */
	if ((cert->exts != NULL) && (cert->exts->basicCons != NULL))
	{
		basicConstraints = cert->exts->basicCons->value;
		if (basicConstraints->cA_flag == FALSE)
			return FALSE;
	}

	/* If the Key Usage extension is present, check that the keyCertSign bit
	is set.  Return FALSE, if the privilege is not authorized. */
	if ((cert->exts != NULL) && (cert->exts->keyUsage != NULL))
	{
		keyUsage = cert->exts->keyUsage->value;
		if (!(*keyUsage & CM_KEY_CERT_SIGN))
			return FALSE;
	}

	return TRUE;
}
CM_BOOL CompareBytes(const Bytes_struct *a, const Bytes_struct *b)
{
	/* If both are NULL, return TRUE */
	if ((a == NULL) && (b == NULL))
		return TRUE;

	/* If only one is NULL, return FALSE */
	if ((a == NULL) || (b == NULL))
		return FALSE;

	/* If both are empty, return TRUE */
	if ((a->num == 0) && (b->num == 0))
		return TRUE;

	/* If the lengths aren't equal, return FALSE */
	if (a->num != b->num)
		return FALSE;

	/* If either one has invalid data, return FALSE (the lengths must be 
	positive and neither pointer can be NULL) */
	if ((a->num < 0) || (a->data == NULL) || (b->data == NULL))
		return FALSE;

	/* Compare the data values, if they are identical, return TRUE, else
	return FALSE. */
	if (memcmp(a->data, b->data, a->num) == 0)
		return TRUE;
	else
		return FALSE;

} /* end of CMU_CompareBytes() */

static short dbu_getIDKids (DB_Session_Struct *db_session,
								long elem_loc, long kidID, 
								long *sibID,
								DB_Kid *return_kid)
								
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
			elem_loc = -1;   /* want 1st of next block */

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
				err = dbu_get_block (db_session, db_session->storage_map_dir);
				if(err != DB_NO_ERR)
					return(err);	/* tell caller we failed */
			}
			else
				/* no more blocks, hit the end, return to caller */
				return(DB_NO_ERR) ;
		}
		else
		{
		/* see if there is an entry in the current storage
		 * block at elem_loc index
		 */
		found = db_session->storage_map->se_table[elem_loc].hash_value != -1;
		if (found)
		{
			// Check the id for a match, if not then continue
			if (db_session->storage_map->se_table[elem_loc].hash_value !=
				kidID)
				found = FALSE;
			else
				*sibID = db_session->storage_map->se_table[elem_loc].SiblingHash;
		}
		}
	}

	/* we found the next entry, make sure it's loaded/cached,
	 * then read its kid into return_kid.
	 */
	err = dbu_read_entry (db_session, elem_loc, &find_data);
	if(err != DB_NO_ERR)
		return(err);

	return_kid->item_len = db_session->storage_map->se_table[elem_loc].kid_size;
	if (return_kid->item_len == 0)
		return(DB_NO_ERR);	/* nothing to give caller */

	return_kid->item_ptr = (char *) calloc (1, return_kid->item_len);

	if (return_kid->item_ptr == NULL)
	{
		return_kid->item_len = 0;
		return(DB_NO_MEM);	/* tell caller */
	}

	/* give the caller their own copy of the kid data */
	memcpy (return_kid->item_ptr, find_data, return_kid->item_len);
	return(DB_NO_ERR);
}

// Convert DB_Item structure to Bytes_structure
static short cvt_DBitem2Bytes(DB_Item *entry_data, Bytes_struct **retData)
{
	Bytes_struct *newBytes = NULL;
	
	if (retData == NULL)
		return SRL_INVALID_PARAMETER;
	if (entry_data != NULL)
	{
		newBytes = (Bytes_struct *)calloc (1, sizeof (Bytes_struct));
		if (newBytes == NULL)
			return SRL_MEMORY_ERROR;
		newBytes->data = (uchar *)calloc (1, entry_data->item_len);
		if (newBytes->data == NULL)
			return SRL_MEMORY_ERROR;
		newBytes->num = entry_data->item_len;
		memcpy(newBytes->data, entry_data->item_ptr, entry_data->item_len);
	}
	*retData = newBytes;
	return SRL_SUCCESS;
}
	

