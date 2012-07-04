/*****************************************************************************
File:		SRL_Mgr.c
Project:	Storage & Retrieval library
Contents:	Management functions for the Storage & Retrieval library

Created:	14 November 2000
Author:		Tom Horvath <Tom.Horvath@DigitalNet.com>
			Robin Moeller <Robin.Moeller@DigitalNet.com>

Last Updated:	27 April 2004

Version:	2.4

*****************************************************************************/

#include "limits.h"
#ifdef WIN32
	#pragma warning(disable: 4115)
#endif

#ifndef WIN32
#ifdef HPUX32
	#include <dl.h>
#else //HPUX
	#include "dlfcn.h"
#endif //HPUX
	#include "sys/param.h"
#ifndef NOTHREADS  // Used if system doesn't support threads
	#include "pthread.h"
#endif //NOTRHEADS
#endif //WIN32

#if defined(WIN32) && defined(_MEMCHECK)
	#include <crtdbg.h>			/* For memory debugging */
#endif
#include "SRL_internal.h"
#include "cmapi.h"

#ifndef NOTHREADS  // Define NOTHREADS if System doesn't support threads
#if defined (WIN32)
	HANDLE g_srl_db_mutex = 0;	// Data Base Mutex
	HANDLE g_srl_session_mutex = 0; // Session Mutex
#else
	pthread_mutex_t g_srl_db_mutex = PTHREAD_MUTEX_INITIALIZER; // Data Base Mutex
	pthread_mutex_t g_srl_session_mutex = PTHREAD_MUTEX_INITIALIZER; // Session Mutex
#endif
#endif //NOTHREADS
void SRLSessionLock(char *inString, int lineNo);
void SRLSessionUnLock(char *inString, int lineNo);
short SRLi_ResetLDAPinfo(SRLSession_struct *session, LDAPInitSettings_struct *LDAPinfo);
short SRLi_RemoveASession(ulong *sessionRefID);
short SRLi_GetLDAPConfigInfo (LDAPInfo_struct *ldapInfo);
extern short dbu_get_block (DB_Session_Struct *session,long dir_index);
extern short SRLi_ConvertCRLDbFile (SRLSession_struct *SRL_session);
extern short SRLi_ConvertCertDbFile (SRLSession_struct *SRL_session);
void SRLi_FreeSession(SRLSession_struct *psession);
short SRLi_GetSessionFromRef(SRLSession_struct **session, ulong sessionRefID);
short DB2SRLerr(short db_err);
static ulong genRandomSessionID(void *session);
static short SRLi_UpdateFileName(char *Filename);
static SRLMgrInfo_struct *gSRLMgrInfo = 0;
static char* SRLi_GetToken(char* strToken, ulong len,
			   char* strDelimit);
short SRLi_ReadConfig(SRL_InitSettings_struct *Settings)
{
        char            tempstring[90];
        char            *tptr, *token, *value, *gpath;
        FILE            *configFile = NULL;
        int             temp, numread;
        short           err;


       err = SRL_SUCCESS;
		gpath = NULL;

		/* Open the Configuration file. Try srl.cfg first, 
		 * and if it doesn't exist try the legacy config file config.cm
		 */
        configFile = fopen("./srl.cfg", "r");
        if(configFile == 0)
        {
			configFile = fopen("./config.cm", "r");
			if (configFile == 0)
                return(SRL_CONFIG_NOT_FOUND);    /* get an appropriate error value later on */
		}

        /* scan one line at a time - our simple stupid parsing */
        while(err == SRL_SUCCESS)
        {
                tptr = 0;
                tptr = fgets(tempstring, 90, configFile);

                if(tptr)        /* will be NULL when eof hit, or upon errors */
                {

                        /* skip comments and blank lines */
                        if(tptr[0] == '#')      /* comment line start, skip this line */
                                continue;

                        /*if(isspace(tptr[0]))   carriage return, blank line, skip it */
                        /* space, tab, CR, newline, vtab, form-feed */
                        if( (tptr[0] == ' ') || (tptr[0] == '\t') || (tptr[0] == '\r')
                                || (tptr[0] == '\n') )
                                continue;
                        /* scan the string for Action Words we understand */
                        /* section started */
                                /* look for our action/command tokens followed by
                                 * the value field.  PATH = xxxxx
                                 */
						SRLSessionLock("SRLi_ReadConfig",__LINE__);
						temp = 0;
						token = tempstring;
                        value = SRLi_GetToken(tempstring, temp, "=");

//                       value =  SRLi_strtok_r(token, temp, "\n\t\r");
						temp = strlen(value);
						value[(temp-1)] = 0;
						SRLSessionUnLock("SRLi_ReadConfig", __LINE__);
                        if(value == NULL)
                                continue;       /* nothing on the line, skip to next line*/
                        /* eat up leading/trailing white space within the
                         * value field.
                         */
                /*      while(isspace(*value)) */
                        while((*value == ' ') || (*value == '\t'))
                                value++;

                        numread = strlen(value);
                /*      while((isspace(value[numread - 1])) && numread > 0) */
                        while(((value[numread - 1] == ' ') || (value[numread - 1] == '\t') ||
							(value[numread - 1] == '\n'))
                                && numread > 0)
                                numread--;

                        if(numread == 0)        /* no input value */
                        {
                                /* should we consider this an error?
                                 * we will skip for now.
                                 */
                                continue;

                        }
									/* find the token action */
						if(strstr(token, "PATH") != 0)
						{
							if (gpath != NULL)
								free (gpath);

							gpath = calloc (1, numread+1);
							strncpy(gpath, value, numread);
						}

                        else if(strstr(token, "CERT_FILE") != 0)
                        {
								/* add in the path size to the numread variable */
								if (gpath != NULL)
									numread = numread + strlen(gpath);
                                Settings->CertFileName = calloc(1, numread +1);
								if (Settings->CertFileName == NULL)
									return (SRL_MEMORY_ERROR);
								/* Strcat in the path */
								if (gpath != NULL)
									strcat (Settings->CertFileName, gpath);
								/* Copy in the file name */
                                strcat (Settings->CertFileName, value);

                        }
                        else if(strstr(token, "CRL_FILE") != 0)

                        {
								/* add in the path */
								if (gpath != NULL)
									numread = numread + strlen(gpath);
                                Settings->CRLFileName = calloc (1,numread +1);
								if (Settings->CRLFileName == NULL)
									return (SRL_MEMORY_ERROR);
								if (gpath != NULL)
									strcat (Settings->CRLFileName, gpath);
                                strcat(Settings->CRLFileName, value);

                        }
                        else if(strstr(token, "USE_LDAP") != 0)
                        {
                            if(strstr(value, "TRUE") != 0)
							{
                                    Settings->LDAPinfo = calloc (1, sizeof (LDAPInitSettings_struct));
									if (Settings->LDAPinfo == NULL)
										return (SRL_MEMORY_ERROR);
							}
                        }
                        else if(strstr(token, "LDAP_DLL_NAME") != 0)
                        {
							if (Settings->LDAPinfo)
							{
                                Settings->LDAPinfo->SharedLibraryName = calloc(1,numread +1);
                                strcpy(Settings->LDAPinfo->SharedLibraryName, value);
							}
						}
                        else if(strstr(token, "LDAP_SERVER") != 0)
                        {
							if (Settings->LDAPinfo)
							{
								if (Settings->LDAPinfo->LDAPServerInfo == NULL)
								{
									Settings->LDAPinfo->LDAPServerInfo = calloc (1, sizeof (LDAPServerInit_struct));
									if (Settings->LDAPinfo->LDAPServerInfo == NULL)
										return (SRL_MEMORY_ERROR);
								}
								Settings->LDAPinfo->LDAPServerInfo->LDAPserver = calloc(1,numread +1);
								if (Settings->LDAPinfo->LDAPServerInfo->LDAPserver == NULL)
									return (SRL_MEMORY_ERROR);
								strcpy(Settings->LDAPinfo->LDAPServerInfo->LDAPserver, value);
							}
						}
                        else if (strstr(token, "LDAP_PORT") != 0)
                        {
							if (Settings->LDAPinfo)
							{
								if (Settings->LDAPinfo->LDAPServerInfo == NULL)
								{
										Settings->LDAPinfo->LDAPServerInfo = calloc (1, sizeof (LDAPServerInit_struct));
										if (Settings->LDAPinfo->LDAPServerInfo == NULL)
											return (SRL_MEMORY_ERROR);
								}
								sscanf(value, "%d", &temp);
								 if(temp < 0)
									  temp = 0;
								  Settings->LDAPinfo->LDAPServerInfo->LDAPport = temp;
							}
						}
						else
                        {
								//break;
						}
                } /* end of if (tptr) */
                else
                {
                        /* hit eof or read error of some sort */
                        break;  /* get out, go with what we have */
                }

        } /* end of while loop */


		/* Free the path */
		if (gpath != NULL)
			free(gpath);

		fclose(configFile);

        return err;
}

short SRLi_Manager_Init()
{
	short err = SRL_SUCCESS;

	if(gSRLMgrInfo != 0) return(SRL_INVALID_PARAMETER);

	gSRLMgrInfo = (SRLMgrInfo_struct *)calloc(1, sizeof(SRLMgrInfo_struct));

	if(gSRLMgrInfo == 0) 
		return(SRL_MEMORY_ERROR);


	/* no sessions yet */
	gSRLMgrInfo->sessionCount = 0;
	gSRLMgrInfo->sessionsList = 0;

#ifndef NOTHREADS
#if defined(WIN32)
	// Create the Session Mutex
	g_srl_session_mutex = CreateMutex(NULL, FALSE, "SRL_Session_mutex");
	if (g_srl_session_mutex == NULL)
		return SRL_UNKNOWN_ERROR;
	
	// Create the Data Base mutex
	g_srl_db_mutex = CreateMutex(NULL, FALSE, "SRL_db_mutex");
	if (g_srl_db_mutex == NULL)
		return SRL_UNKNOWN_ERROR;
#endif
#endif

	return err;

} /* end of SRLi_Manager_Init() */

short SRLi_AddASession(SRLSession_struct *session, ulong *sessionRefID)
{
	short err = 0;
	CM_BOOL opendb = TRUE;
	SRLSessions_Info_LL	**listAddPoint, *listTemp = NULL;
	ulong	ref;
	long	access,blocksize;
	DB_INFO_Struct *db_infop = NULL;

 	/* check params */

	if((session == 0) || (sessionRefID == 0))
		return(SRL_INVALID_PARAMETER);

	*sessionRefID = 0;	/* start caller with nothing */

	/* first check if the management stuff has been set up yet */
	if(gSRLMgrInfo == 0)
	{
		err = SRLi_Manager_Init();
		if(err != SRL_SUCCESS)
		{
			gSRLMgrInfo = 0;
			return(err);
		}

	}

	/* Create a unique ref id for this session */
	ref = genRandomSessionID(session);
	if (ref == 0)
		return SRL_MEMORY_ERROR;

	/* copy the default settings to the session - these can be
	 * over ridden by an app later if need be...
	 */
	session->config.useLDAP = gSRLMgrInfo->useLDAP;
	session->db_certRefSession = 0;
	session->db_CRLRefSession = 0;
	session->config.CRLFName = session->CRLFileName;
	session->config.certFName = session->CertFileName;
	/* Items already in the session struct take presidence */
	/* we should now hook up the session with the default
	 * databases. If there are other sessions using the files,
	 * we just share. 
	 */

	if (session->CertFileName)
	{
		// See if we have this file open already
		if (gSRLMgrInfo->sessionsList != NULL)
			listTemp = gSRLMgrInfo->sessionsList;
		while (listTemp != NULL)
		{
         if (listTemp->sessionInfo->CertFileName && 
             strstr (listTemp->sessionInfo->CertFileName, session->CertFileName))
			{
				session->db_certRefSession = listTemp->sessionInfo->db_certRefSession;
				err = db_dupe (&session->db_certRefSession);
				if (err != DB_NO_ERR)
				{
					err = DB2SRLerr(err);
					goto ErrCleanUp;
				}
				opendb = FALSE;
				break;
			}
			listTemp = listTemp->next;
		}
	}
	listTemp = NULL;

	if (session->CRLFileName)
	{
		if (gSRLMgrInfo->sessionsList)
			listTemp = gSRLMgrInfo->sessionsList;
		while (listTemp != NULL)
		{
			if (listTemp->sessionInfo->CRLFileName && 
             strstr (listTemp->sessionInfo->CRLFileName, session->CRLFileName))
			{
				session->db_CRLRefSession = listTemp->sessionInfo->db_CRLRefSession;
				err = db_dupe (&session->db_CRLRefSession);
				if (err != DB_NO_ERR)
				{
					err = DB2SRLerr(err);
					goto ErrCleanUp;
				}
				opendb = FALSE;
				break;
			}
			listTemp = listTemp->next;
		}
	}


	if (opendb)
	{
	/* if no prev sessions, we know we don't have to worry
	 * about sharing yet. If other sessions, we know the
	 * defauly files are used.  At this time, all sessions
	 * use the same db files, so we will just grab the db
	 * context in use by the first session.
	 */

		/* start up sessions with the local storage manager - in this
		 * case the database.  Need one session for certificate storage,
		 * and another for CRL storage.
		 */
		blocksize = DB_BLOCK_SIZE;	

		if (session->CertFileName != NULL)
		{
			/* assume that the file should exist - if we don't find
			 * it, we will create a new one using the indicated name.
			 */
			access = DB_RDWR;	/* open existing file for read/write */

			err = db_Open(&session->db_certRefSession, 
				 session->CertFileName, access, blocksize);

			if((err == DB_NOT_FOUND) || (err == DB_OPEN_ERROR))
			{
				/* didn't exist, create a new one */
    			access = DB_NEW;

				err = db_Open(&session->db_certRefSession,
			 		session->CertFileName, access, blocksize);
			}
			if(err != DB_NO_ERR)
			{
				/* unable to create new or open existing....
				 */
				err = DB2SRLerr(err);

				goto ErrCleanUp;
			}
			err = db_Info ((ulong)session->db_certRefSession, &db_infop);
			if (err != SRL_SUCCESS)
			{
				db_Close (&session->db_certRefSession);
				err = DB2SRLerr (err);
				goto ErrCleanUp;
			}

			// Check Version of the Certificate Database
			if (db_infop->data != DATA_BASE_HEADER_VERSION3)
			{
				/* Close the DB file */
				db_Close (&session->db_certRefSession);

				/* 
				 * Upgrade data base to newer version
				 */
				err = SRLi_ConvertCertDbFile(session);
				if (err != SRL_SUCCESS)
				{
					goto ErrCleanUp;
				}
				err = SRLi_UpdateFileName(session->CertFileName);
				if (err)
					goto ErrCleanUp;
				access = DB_RDWR;	/* open existing file for read/write */

				err = db_Open(&session->db_certRefSession, 
				 session->CertFileName, access, blocksize);
				if (err != SRL_SUCCESS)
					goto ErrCleanUp;

			}
			db_FreeDBInfo(&db_infop);
			dbu_get_block((DB_Session_Struct *)session->db_certRefSession, 0);
		}
		// CRL File is optional 
		if (session->CRLFileName != NULL)
		{
			access = DB_RDWR;	/* open existing file for read/write */
			err = db_Open(&session->db_CRLRefSession, 
				 session->CRLFileName, access, blocksize);
			if((err == DB_NOT_FOUND) || (err == DB_OPEN_ERROR))
			{
				/* didn't exist, create a new one */
    			access = DB_NEW;

				err = db_Open(&session->db_CRLRefSession, 
					 session->CRLFileName, access, blocksize);
			}
			if(err != DB_NO_ERR)
			{
				db_Close(&session->db_certRefSession);
				err = DB2SRLerr(err);

				goto ErrCleanUp;
			}
			err = db_Info ((ulong)session->db_CRLRefSession, &db_infop);
			if (err != SRL_SUCCESS)
			{
				db_Close (&session->db_CRLRefSession);
				err = DB2SRLerr (err);
				goto ErrCleanUp;
			}
			if (db_infop->data != DATA_BASE_HEADER_VERSION3)
			{
				/* Close the DB file */
				db_Close (&session->db_CRLRefSession);

				/* 
				 * Upgrade data base to newer version
				 */
				err = SRLi_ConvertCRLDbFile(session);
				if (err != SRL_SUCCESS)
				{
					goto ErrCleanUp;
				}
				err = SRLi_UpdateFileName(session->CRLFileName);
				if (err != SRL_SUCCESS)
					goto ErrCleanUp;

				access = DB_RDWR;	/* open existing file for read/write */

				err = db_Open(&session->db_CRLRefSession, 
				 session->CRLFileName, access, blocksize);
				if (err != SRL_SUCCESS)
					goto ErrCleanUp;


			}
			db_FreeDBInfo(&db_infop);
		}

	
	}
	/* add a new pair to management info */
	if(gSRLMgrInfo->sessionCount == 0)
	{
		/* start out the linked list */
		listAddPoint = &gSRLMgrInfo->sessionsList;
	}
	else
	{
		/* existing list, scan tll we find the end */
		listTemp = gSRLMgrInfo->sessionsList;
		while (listTemp->next != NULL)
			listTemp = listTemp->next;

		listAddPoint = &listTemp->next;
	}

	listTemp = (SRLSessions_Info_LL*) malloc(sizeof(SRLSessions_Info_LL));

	if(listTemp == 0)
		goto ErrCleanUp;

	*listAddPoint = listTemp;
	listTemp->sessionInfo = session;
	listTemp->sessionRefID = ref;
	listTemp->next = 0;

	gSRLMgrInfo->sessionCount++;

	*sessionRefID = ref;

	return(SRL_SUCCESS);

ErrCleanUp:
	/* if this is the only session, then we need to shut down
	 * the db sessions. Otherwise it is shared, so we leave it
	 * alone (for now).
	 */
	if(gSRLMgrInfo->sessionCount == 0)	/* none before */
	{
		if(session->db_certRefSession != 0)
			db_Close(&session->db_certRefSession);

		if(session->db_CRLRefSession != 0)
			db_Close(&session->db_CRLRefSession);

	}

	session->config.certFName = 0;
	session->config.CRLFName = 0;
	session->config.path = 0;
	session->db_certRefSession = 0;
	session->db_CRLRefSession = 0;

	return(err);
}

LDAPInfo_struct *SRLi_CopyLDAPInfo()
{
    LDAPInfo_struct *result = calloc (1, sizeof (LDAPInfo_struct));
    if (result) {
		memcpy (result, 
			&gSRLMgrInfo->ldapInfo, sizeof (LDAPInfo_struct));
		result->LDAPServerInfo = NULL;
    }
    return result;
}


/*  
Function: SRL_CreateSession()
 This routine is called upon to start up a session with the Storage Retrieval Library.
 The session returned is used in all further calls to the S&R library.
 When you are done using the certificate manager make sure you release the
 session using the SRL_DestroySession() routine.

 parameters:

    sessionID (input/output) = ptr to storage for a session ref/context value.
       Will be filled in by this routine upon sucessful completion.

    pSettings (input) = pointer to the SRL_InitSettings_struct

 returns:
    SRL_SUCCESS      - shut down fine
    SRL_INVALID_PARAMETER   - bad paramenter sent to this routine

    other pass thru values from db routines.
    other pass thru values from configuration loading routines.

-----------------------------------------------------------------------
*/
SRL_API(short) SRL_CreateSession(ulong *sessionID,
								 SRL_InitSettings_struct *pSettings)
{
	SRLSession_struct *session = NULL;
	SRL_InitSettings_struct *InternalSettings = NULL;
	short err = 0;

#if defined(WIN32) && defined(_MEMCHECK)
	int debugFlag;
	static long memAllocNum = 0;
	
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_DEBUG);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_DEBUG);

	debugFlag = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);
	debugFlag = _CrtSetDbgFlag(debugFlag | _CRTDBG_LEAK_CHECK_DF);

#ifdef _EXTRA_MEMCHECK
	debugFlag = _CrtSetDbgFlag(debugFlag | _CRTDBG_DELAY_FREE_MEM_DF | 
		_CRTDBG_CHECK_ALWAYS_DF);
#endif /* _EXTRA_MEMCHECK */
	/* Set a breakpoint on the allocation request number */
	if (memAllocNum != 0)
		_CrtSetBreakAlloc(memAllocNum);
#endif /* WIN32 and _MEMCHECK */

	/* Check parameters */
	if (sessionID == NULL)
		return SRL_INVALID_PARAMETER;

	if (pSettings == NULL)
	{
		InternalSettings = (SRL_InitSettings_struct *)calloc (1, sizeof (SRL_InitSettings_struct));
		if (InternalSettings == NULL)
		{
			err = SRL_MEMORY_ERROR;
			goto CLEANUP;
		}

		/* Set up the pSettings to data in the Config file */
		err = SRLi_ReadConfig(InternalSettings);

		if (err != SRL_SUCCESS)
		{
			SRLi_FreeInitSettings (InternalSettings);
			goto CLEANUP;			
		}
		InternalSettings->crlRefreshPeriod = LONG_MAX;
		pSettings = InternalSettings;
	}
	
	/* Lock the session Creation */
	SRLSessionLock("SRL_CreateSession", __LINE__);

	session = calloc (1, sizeof (SRLSession_struct ));
	if (session == NULL)
	{
		err = SRL_MEMORY_ERROR;
		goto CLEANUP;
	}

	/* Copy in the CRL and Cert Data Base File names */
	if (pSettings->CertFileName != NULL)
		session->CertFileName = strdup (pSettings->CertFileName);

	if (pSettings->CRLFileName != NULL)
		session->CRLFileName = strdup (pSettings->CRLFileName);

	// If the CRL Refresh Period is set to other than LONG_MAX (ignore), then
	// Error out
	if ((pSettings->crlRefreshPeriod != LONG_MAX) && (pSettings->LDAPinfo == NULL) &&
		(pSettings->CRLFileName == NULL))
	{
		err = SRL_INVALID_PARAMETER;
		goto CLEANUP;
	}

	session->crlRefreshPeriod = pSettings->crlRefreshPeriod;
	session->removeStaleCRL = pSettings->removeStaleCRL;

	/* Process the LDAP info from the Init Settings */
	if ((pSettings->LDAPinfo != NULL) &&
		(pSettings->LDAPinfo->SharedLibraryName != NULL) &&
		(pSettings->LDAPinfo->LDAPServerInfo != NULL))
	{
		if ((pSettings->LDAPinfo->LDAPFunctions != NULL) &&
			(pSettings->LDAPinfo->LDAPFunctions->StructVersion != SRL_LDAP_FUNC_VER))
		{
			err = SRL_LDAP_INIT_FAILED;
			goto CLEANUP;
		}

       /* Set up the session to use LDAP. */
	   if (pSettings->LDAPinfo->LDAPServerInfo->LDAPserver == NULL)
	   {
		   err = SRL_LDAP_INIT_FAILED;
		   goto CLEANUP;
	   }
	   if (pSettings->LDAPinfo->LDAPServerInfo->LDAPport == 0)
	   {
		   err = SRL_LDAP_INIT_FAILED;
		   goto CLEANUP;
	   }

	   err = SRLi_CopyLDAPinfo(&session->ldapInfo, pSettings->LDAPinfo);



	   /* Attempt to dynamically link to the specified LDAP library, 
	    * initialize the LDAP library, and bind to the specified server.
		*/

	   err = SRLi_Link2LDAP(session->ldapInfo);
	   if (err != SRL_SUCCESS)
		   goto CLEANUP;
	   session->ldapInfo->ldapIDinfo = (LDAPIdInfo_struct *)calloc(1, sizeof(LDAPIdInfo_struct));
	   if (session->ldapInfo->ldapIDinfo == NULL)
	   {
		  err = SRL_MEMORY_ERROR;
		  goto CLEANUP;
	   }
	   session->ldapInfo->ldapIDinfo->ldapID = SRLi_LdapInit (session->ldapInfo);
		session->ldapInfo->ldapIDinfo->internal = TRUE;
	   err = SRLi_LdapConnect (session->ldapInfo);
	   if (err != SRL_SUCCESS)
		   goto CLEANUP;


	}
	else if ((pSettings->LDAPinfo != NULL) &&
			(pSettings->LDAPinfo->LDAPFunctions != NULL) &&
			(pSettings->LDAPinfo->LDAPServerInfo != NULL) &&
			(pSettings->LDAPinfo->ldapID == NULL))
	{
		if (pSettings->LDAPinfo->LDAPFunctions->StructVersion != SRL_LDAP_FUNC_VER)
		{
			err = SRL_LDAP_INIT_FAILED;
			goto CLEANUP;
		}
		
		/* The LDAPServerInfo and LDAPFunctions are present.
		 * Attempt to initialize the LDAP library and bind to the 
		 * specified server using the provided LDAP function pointers.
		 */
	   if (pSettings->LDAPinfo->LDAPServerInfo->LDAPport == 0)
	   {
		   err = SRL_LDAP_INIT_FAILED;
		   goto CLEANUP;
	   }
	   err = SRLi_CopyLDAPinfo(&session->ldapInfo, pSettings->LDAPinfo);
	   if (err != SRL_SUCCESS)
	   {
		   err = SRL_LDAP_INIT_FAILED;
		   goto CLEANUP;
	   }
	   session->ldapInfo->ldapIDinfo = (LDAPIdInfo_struct *)calloc(1, sizeof(LDAPIdInfo_struct));
	   if (session->ldapInfo->ldapIDinfo == NULL)
	   {
		err = SRL_MEMORY_ERROR;
		goto CLEANUP;
	   }

		   session->ldapInfo->ldapIDinfo->ldapID = SRLi_LdapInit (session->ldapInfo);
			if (session->ldapInfo->ldapIDinfo->ldapID == NULL)
			{
				err = SRL_LDAP_INIT_FAILED;
				goto CLEANUP;
			}
			err =  SRLi_LdapConnect (session->ldapInfo);
			if (err != SRL_SUCCESS)
				goto CLEANUP;

			session->ldapInfo->ldapIDinfo->internal = TRUE;

	}
	else if ((pSettings->LDAPinfo != NULL) &&
			(pSettings->LDAPinfo->LDAPFunctions != NULL) &&
			(pSettings->LDAPinfo->ldapID != NULL))
	{
		if (pSettings->LDAPinfo->LDAPFunctions->StructVersion != SRL_LDAP_FUNC_VER)
		{
			err = SRL_LDAP_INIT_FAILED;
			goto CLEANUP;
		}


		/*
		 * The LDAPFunctions and ldapID members are present.
		 * Perform no additional initialization of the LDAP library. 
		 * NOTE: The application is responsible for initializing the LDAP 
		 * library and binding to the server prior to calling SRL_CreateSession. 
		 * The application is likewise responsible for calling ldap_unbind() to 
		 * release the LDAP library resources after calling SRL_DestroySession
		 */
	   err = SRLi_CopyLDAPinfo(&session->ldapInfo, pSettings->LDAPinfo);
		session->ldapInfo->ldapIDinfo->internal = FALSE;
	}
   *sessionID = 0;
   /* Create our own CMAPI Session so we can use the decode functions */
   err = SRLi_AddASession(session, sessionID);
   if (err)
	   goto CLEANUP;


CLEANUP:
	if (InternalSettings != NULL)
	{
		/* Clean up our internal settings */
		SRLi_FreeInitSettings (InternalSettings);
		free(InternalSettings);
		InternalSettings = NULL;
		pSettings = NULL;
	}

	if(err != SRL_SUCCESS)
	{
	   /* Destroy the session */
		SRLSessionUnLock("SRL_CreateSession", __LINE__);
		SRL_DestroySession (sessionID);
		SRLi_FreeSession(session);
		session = 0;
		return err;
	}

	SRLSessionUnLock("SRL_CreateSession", __LINE__);
   	return (err);
}


short SRLi_GetRetSessionFromRef(SRLSession_struct **session, ulong sessionRefID)
{
        SRLSessions_Info_LL        *listTemp;

        if(session == 0)
                return(SRL_INVALID_PARAMETER);

		 SRLSessionLock("SRLi_GetRetSessionFromRef", __LINE__);
        listTemp = gSRLMgrInfo->sessionsList;
        while(listTemp != 0)
        {
                if(listTemp->sessionRefID == sessionRefID)      /*found it */
                        break;

                listTemp = listTemp->next;
        }
        if(listTemp == 0)       /* ref not found */
		{
			SRLSessionUnLock("SRLi_GetRetSessionFromRef", __LINE__);
            return(SRL_SESSION_NOT_VALID);   /* should we be more specific */
		}
        *session = listTemp->sessionInfo;
		SRLSessionUnLock("SRLi_GetRetSessionFromRef", __LINE__);
        return(SRL_SUCCESS);

}

short SRLi_GetLDAPConfigInfo (LDAPInfo_struct *ldapInfo)
{
	if (ldapInfo == NULL)
		return SRL_NULL_POINTER;

	if (gSRLMgrInfo->ldapInfo.LDAPServerInfo->LDAPserver == NULL)
		return SRL_NULL_POINTER;

	ldapInfo->LDAPServerInfo->LDAPserver = (char*)
		malloc(strlen(gSRLMgrInfo->ldapInfo.LDAPServerInfo->LDAPserver) + 1);
	if (ldapInfo->LDAPServerInfo->LDAPserver == NULL)
		return SRL_MEMORY_ERROR;
	strcpy(ldapInfo->LDAPServerInfo->LDAPserver,
		gSRLMgrInfo->ldapInfo.LDAPServerInfo->LDAPserver);
	ldapInfo->LDAPServerInfo->LDAPport =
		gSRLMgrInfo->ldapInfo.LDAPServerInfo->LDAPport;

	return SRL_SUCCESS;
}



/*-----------------------------------------------------------------------
 Function: SRL_DestroySession()

 short SRL_DestroySession(ulong *sessionID);

 This routine is called upon to shut down a session with the certificate manager.
 The session param was issued from a CM_CreateSession() call at some point.

 When you are done using the certificate manager make sure you release the
 session by calling this routine.

 NOTE: At this time the routine is not full featured.

 parameters:

    cm_session (input/output) = ptr to storage for a session ref/context value.
       Will be cleared out by this routine upon sucessful completion.

 returns:
    CM_NO_ERROR      - shut down fine
    CM_INVALID_PARAMETER   - bad paramenter sent to this routine

    other pass thru values from db routines.

-----------------------------------------------------------------------
*/
SRL_API(short) SRL_DestroySession(ulong *sessionID)
{
	short   err;
	
	
	if(sessionID == NULL)
		return(SRL_INVALID_PARAMETER);
	
		/* free up stuff - the session manager handles all this for us...
    */
	SRLSessionLock("SRL_DestroySession", __LINE__);
	err = SRLi_RemoveASession(sessionID);
	SRLSessionUnLock("SRL_DestroySession", __LINE__);
	if (err != SRL_SUCCESS)
		return SRL_SESSION_NOT_VALID;
	return(err);
}

/*
 This routine would be called when a session will no longer be
 required, and therefore all the resources tied to the session
 will be freed up.

 If there are other sessions running, and the session that is
 being removed is sharing db files (in our case the same
 files are used by all) then the db files are only closed when
 there are no more sessions using them.
*/
short SRLi_RemoveASession(ulong *sessionRefID)
{
	SRLSessions_Info_LL	*listTemp, *listSubPoint;
	LDAPInfo_struct *LDAPinfoPtr = NULL;
	SRLSession_struct *session;

	short err;

	if(sessionRefID == 0)
		return(SRL_INVALID_PARAMETER);

	if (gSRLMgrInfo == NULL)
		return SRL_SESSION_NOT_VALID;


		/* start at top of linked list */
		listTemp = gSRLMgrInfo->sessionsList;
		listSubPoint = 0;
		while(listTemp != 0)
		{
			if(listTemp->sessionRefID == *sessionRefID)	/*found it */
				break;

			/* keep track of linkage, sub point points at
			 * who we will be deleting.
			 */
			listSubPoint = listTemp;
			listTemp = listTemp->next;
		}

		if(listTemp == 0)	/* ref not found */
			return(SRL_SESSION_NOT_VALID);	/* should we be more specific */

		session = listTemp->sessionInfo;
		err = SRL_SUCCESS;

		/* if this is the last session, we will close down the
		 * db sessions. If the file names are the same, we share
		 * the session with other sessions
		 */

			/* from infc_ */
			if(session->db_certRefSession != 0)
				err = db_Close(&session->db_certRefSession);

			if(session->db_CRLRefSession != 0)
				err = db_Close(&session->db_CRLRefSession);
			err = DB2SRLerr(err);

		/* free up the storage of paths, etc */
	if (session->config.certFName != NULL)
		free(session->config.certFName);
	if (session->config.CRLFName != NULL)
		free(session->config.CRLFName);
	if (session->config.path != NULL)
		free(session->config.path);
	LDAPinfoPtr = session->ldapInfo;
	if (LDAPinfoPtr != NULL)
	{
		if ((LDAPinfoPtr->ldapIDinfo != NULL) && 
				(LDAPinfoPtr->ldapIDinfo->internal == TRUE))
		{
				/* Unbind from the LDAP server */
			LDAPinfoPtr->LDAPFunctions->unbind(LDAPinfoPtr->ldapIDinfo->ldapID);
		}
		SRLi_FreeLDAPinfo (&LDAPinfoPtr);
		session->ldapInfo = NULL;
	}
	if (session->ldapInfo != NULL)
		free (session->ldapInfo);

	/* break out the link */
	if (listSubPoint != NULL)
    	listSubPoint->next = listTemp->next;
	else
		gSRLMgrInfo->sessionsList = listTemp->next;

	/* Free the SRLSession_struct and session link */
	free(session);
	free(listTemp);

	/* Decrement the session count and zeroize the session ID */
	gSRLMgrInfo->sessionCount--;
	*sessionRefID = 0;
	/* If no sessions exist, release the global manager info */
	if (gSRLMgrInfo->sessionCount == 0)
	{
#if !defined(NOTHREADS) && defined(WIN32)
		// Close the Windows mutex handle
		CloseHandle(g_srl_db_mutex);
		CloseHandle(g_srl_session_mutex);
#endif
		free(gSRLMgrInfo);
		gSRLMgrInfo = NULL;
	}
	return(err);
}
/*
 * Provide accessor functions so that other routines can read data from
 * the manager, but not change the internal management data.
 */

short SRLi_GetSessionFromRef(SRLSession_struct **session, ulong sessionRefID)
{
//   SRLSession_struct *srlSessionInfo = NULL;

	SRLSessions_Info_LL	*listTemp = NULL;

	if(session == 0)
		return(SRL_INVALID_PARAMETER);

	if (gSRLMgrInfo != NULL)
	{
		listTemp = gSRLMgrInfo->sessionsList;
		while(listTemp != 0)
		{
			if(listTemp->sessionRefID == sessionRefID)	/*found it */
				break;

			listTemp = listTemp->next;
		}
	}
	if(listTemp == 0)	/* ref not found */
		return(SRL_SESSION_NOT_VALID);	/* should we be more specific */

	*session = listTemp->sessionInfo;
	return(SRL_SUCCESS);

}
short SRLi_CopyLDAPinfo(LDAPInfo_struct **ldapInfo, LDAPInitSettings_struct *LDAPinfo)
{
	LDAPInfo_struct *pLDAPinfo = NULL;

	if (ldapInfo == NULL)
		return (SRL_INVALID_PARAMETER);

	if (LDAPinfo == NULL)
		return (SRL_INVALID_PARAMETER);

	pLDAPinfo = (LDAPInfo_struct *)calloc (1, sizeof (LDAPInfo_struct));
	if (pLDAPinfo == NULL)
		return (SRL_MEMORY_ERROR);

	/* Copy data into the LDAPInfo_struct */
	if (LDAPinfo->LDAPFunctions)
	{
		if (LDAPinfo->LDAPFunctions->StructVersion == SRL_LDAP_FUNC_VER)
		{
			pLDAPinfo->LDAPFunctions = (LDAPFuncPtr_struct *)calloc (1, sizeof (LDAPFuncPtr_struct));
			if (pLDAPinfo->LDAPFunctions == NULL)
			{
				free (pLDAPinfo);
				return (SRL_MEMORY_ERROR);
			}

			/* Copy the Function pointers */
			pLDAPinfo->LDAPFunctions->StructVersion = LDAPinfo->LDAPFunctions->StructVersion;
			pLDAPinfo->LDAPFunctions->count_entries = LDAPinfo->LDAPFunctions->count_entries;
			pLDAPinfo->LDAPFunctions->count_values_len = LDAPinfo->LDAPFunctions->count_values_len;
			pLDAPinfo->LDAPFunctions->first_entry = LDAPinfo->LDAPFunctions->first_entry;
			pLDAPinfo->LDAPFunctions->get_values_len = LDAPinfo->LDAPFunctions->get_values_len;
			pLDAPinfo->LDAPFunctions->init = LDAPinfo->LDAPFunctions->init;
			pLDAPinfo->LDAPFunctions->msgfree = LDAPinfo->LDAPFunctions->msgfree;
			pLDAPinfo->LDAPFunctions->next_entry = LDAPinfo->LDAPFunctions->next_entry;
			pLDAPinfo->LDAPFunctions->search = LDAPinfo->LDAPFunctions->search;
			pLDAPinfo->LDAPFunctions->set_option = LDAPinfo->LDAPFunctions->set_option;
			pLDAPinfo->LDAPFunctions->simple_bind = LDAPinfo->LDAPFunctions->simple_bind;
			pLDAPinfo->LDAPFunctions->unbind = LDAPinfo->LDAPFunctions->unbind;
			pLDAPinfo->LDAPFunctions->value_free_len = LDAPinfo->LDAPFunctions->value_free_len;
			pLDAPinfo->LDAPFunctions->result = LDAPinfo->LDAPFunctions->result;
			pLDAPinfo->LDAPFunctions->abandon = LDAPinfo->LDAPFunctions->abandon;
			pLDAPinfo->LDAPFunctions->result2error = LDAPinfo->LDAPFunctions->result2error;

		}
		else
			// Incorrect Structure version
			return SRL_INVALID_PARAMETER;
	}
	if (LDAPinfo->ldapID)
	{

		/* Copy the ldapID structure */
		pLDAPinfo->ldapIDinfo = (LDAPIdInfo_struct *)calloc (1, sizeof (LDAPIdInfo_struct));
		if (pLDAPinfo->ldapIDinfo == NULL)
		{
			SRLi_FreeLDAPinfo (&pLDAPinfo);
			return (SRL_MEMORY_ERROR);
		}

		pLDAPinfo->ldapIDinfo->ldapID = LDAPinfo->ldapID;
	}
	if (LDAPinfo->LDAPServerInfo)
	{
		/* Copy the server info */
		pLDAPinfo->LDAPServerInfo = (LDAPServerInfo_struct *)calloc (1, sizeof (LDAPServerInfo_struct));
		if (pLDAPinfo->LDAPServerInfo == NULL)
		{
			SRLi_FreeLDAPinfo (&pLDAPinfo);
			return (SRL_MEMORY_ERROR);
		}
		pLDAPinfo->LDAPServerInfo->LDAPport = LDAPinfo->LDAPServerInfo->LDAPport;
		if (LDAPinfo->LDAPServerInfo->LDAPserver)
			pLDAPinfo->LDAPServerInfo->LDAPserver = strdup (LDAPinfo->LDAPServerInfo->LDAPserver);
		else
		{
			SRLi_FreeLDAPinfo (&pLDAPinfo);
			return (SRL_INVALID_PARAMETER);
		}
	}
	if (LDAPinfo->SharedLibraryName)
		pLDAPinfo->SharedLibraryName = strdup (LDAPinfo->SharedLibraryName);

	pLDAPinfo->timeout = LDAPinfo->timeout;

	*ldapInfo = pLDAPinfo;
	return (SRL_SUCCESS);
}


static ulong genRandomSessionID(void *session)
{
//	Bytes_struct inputBytes;
	short errCode;
	CM_HashValue hashBuffer;
	ulong sessionID;
	Bytes_struct InHashBuf;
	CM_BOOL sessionExists;
	SRLSessions_Info_LL* pSessionInfo;

	/* Check parameter */
	if (session == NULL)
		return 0;

	/* Hash the four-byte session pointer */
	InHashBuf.data = (uchar *)&session;
	InHashBuf.num = sizeof (ulong);

	errCode = CM_HashData(&InHashBuf, hashBuffer);
	if (errCode != 0)
		return 0;

	sessionID = *(ulong*)hashBuffer;

	/* If the sessionID already exists, shift it right until a unique value
	is found  */
	do
	{
		sessionExists = FALSE;
		pSessionInfo = gSRLMgrInfo->sessionsList;
		while ((pSessionInfo != NULL) && !sessionExists)
		{
			if (pSessionInfo->sessionRefID == sessionID)
			{
				sessionExists = TRUE;
				sessionID >>= 1;
			}
			pSessionInfo = pSessionInfo->next;
		}
	}
	while (sessionExists && (sessionID != 0));

	return sessionID;

} /* end of genRandomSessionID() */

void SRLSessionLock(char *inString, int lineNo)
{
	inString = inString;
	lineNo = lineNo;
#ifndef NOTHREADS
#if defined(WIN32) && defined(_DEBUG) && defined(VERBOSE)
{
		char debugStr[256];
		sprintf (debugStr,"SRLSessionLock Function %s Line Number %d\n", inString, lineNo);
		if (IsDebuggerPresent() == TRUE)
			OutputDebugString(debugStr);
}
#endif
#if !defined(WIN32) && defined(_DEBUG) && defined (VERBOSE)
	fprintf (stderr,"In SRLSessionLock Function %s Line Number %d\n", inString, lineNo);
#endif

#if defined (WIN32)
	WaitForSingleObject(g_srl_session_mutex, INFINITE);
#else
	pthread_mutex_lock (&g_srl_session_mutex);
#endif
#endif
	return;
}

void SRLSessionUnLock(char *inString, int lineNo)
{
	inString = inString;
	lineNo = lineNo;
#ifndef NOTHREADS
#if defined(WIN32) && defined(_DEBUG) && defined(VERBOSE)
{
		char debugStr[256];
		sprintf (debugStr,"SRLSessionUnLock Function %s Line Number %d\n", inString, lineNo);
		if (IsDebuggerPresent() == TRUE)
			OutputDebugString(debugStr);
}
#endif
#if !defined(WIN32) && defined(_DEBUG) && defined (VERBOSE)
	fprintf (stderr,"In SRLSessionUnLock Function %s Line Number %d\n", inString, lineNo);
#endif


#if defined (WIN32)
		ReleaseMutex(g_srl_session_mutex);
#else
		pthread_mutex_unlock (&g_srl_session_mutex);
#endif
#endif
		return;
}

/*  
Function: SRL_ChangeLDAPInfo()
 This routine is called to change the SRL session LDAP information, without 
 having to destroy the session.

 parameters:

    sessionID (input/output) = ptr to storage for a session ref/context value.
       

    NewSettings (input) = pointer to the LDAPInitSettings_struct

 returns:
    SRL_SUCCESS      - LDAP Change fine
    SRL_INVALID_PARAMETER   - bad paramenter sent to this routine
	SRL_LDAP_INIT_FAILED    - LDAP Initialization failed
    other pass thru values 

-----------------------------------------------------------------------
*/
SRL_API(short) SRL_ChangeLDAPInfo (ulong sessionID, LDAPInitSettings_struct *NewSettings)
{
ushort err = SRL_SUCCESS;
SRLSession_struct *session;

   if((sessionID == 0) || (NewSettings == NULL))
      return(SRL_INVALID_PARAMETER);

  /* Get the session from the session ID */
   err = SRLi_GetSessionFromRef (&session, sessionID);
   if (err != SRL_SUCCESS)
	   return (err);

	// Reload the LDAP Information settings
	// Check to see if app is trying to reset internal connected LDAP
	// Report error if they are
	if ((session->ldapInfo != NULL) &&
		(session->ldapInfo->ldapIDinfo != NULL) &&
		(session->ldapInfo->ldapIDinfo->internal == TRUE))
				return SRL_LDAP_INIT_FAILED;  

	err = SRLi_ResetLDAPinfo(session, NewSettings);
	if (err != SRL_SUCCESS)
		return SRL_LDAP_INIT_FAILED;

	return SRL_SUCCESS;

}

short SRLi_ResetLDAPinfo(SRLSession_struct *session, LDAPInitSettings_struct *LDAPinfo)
{
	LDAPInfo_struct *pLDAPinfo = NULL;

	if (LDAPinfo == NULL)
		return (SRL_INVALID_PARAMETER);

	// Point to the ldap info structure
	pLDAPinfo = session->ldapInfo;

	// Free the old LDAP structure
	SRLi_FreeLDAPinfo(&pLDAPinfo);

	pLDAPinfo = (LDAPInfo_struct *)calloc (1, sizeof (LDAPInfo_struct));
	if (pLDAPinfo == NULL)
		return (SRL_MEMORY_ERROR);

	/* Copy data into the LDAPInfo_struct */
	if (LDAPinfo->LDAPFunctions)
	{
		pLDAPinfo->LDAPFunctions = (LDAPFuncPtr_struct *)calloc (1, sizeof (LDAPFuncPtr_struct));
		if (pLDAPinfo->LDAPFunctions == NULL)
		{
			free (pLDAPinfo);
			return (SRL_MEMORY_ERROR);
		}

		/* Copy the Function pointers */
		pLDAPinfo->LDAPFunctions->count_entries = LDAPinfo->LDAPFunctions->count_entries;
		pLDAPinfo->LDAPFunctions->count_values_len = LDAPinfo->LDAPFunctions->count_values_len;
		pLDAPinfo->LDAPFunctions->first_entry = LDAPinfo->LDAPFunctions->first_entry;
		pLDAPinfo->LDAPFunctions->get_values_len = LDAPinfo->LDAPFunctions->get_values_len;
		pLDAPinfo->LDAPFunctions->init = LDAPinfo->LDAPFunctions->init;
		pLDAPinfo->LDAPFunctions->msgfree = LDAPinfo->LDAPFunctions->msgfree;
		pLDAPinfo->LDAPFunctions->next_entry = LDAPinfo->LDAPFunctions->next_entry;
		pLDAPinfo->LDAPFunctions->search = LDAPinfo->LDAPFunctions->search;
		pLDAPinfo->LDAPFunctions->set_option = LDAPinfo->LDAPFunctions->set_option;
		pLDAPinfo->LDAPFunctions->simple_bind = LDAPinfo->LDAPFunctions->simple_bind;
		pLDAPinfo->LDAPFunctions->unbind = LDAPinfo->LDAPFunctions->unbind;
		pLDAPinfo->LDAPFunctions->value_free_len = LDAPinfo->LDAPFunctions->value_free_len;
		pLDAPinfo->LDAPFunctions->result = LDAPinfo->LDAPFunctions->result;
		pLDAPinfo->LDAPFunctions->abandon = LDAPinfo->LDAPFunctions->abandon;
		pLDAPinfo->LDAPFunctions->result2error = LDAPinfo->LDAPFunctions->result2error;

	}
	if (LDAPinfo->ldapID)
	{

		/* Copy the ldapID structure */
		pLDAPinfo->ldapIDinfo = (LDAPIdInfo_struct *)calloc (1, sizeof (LDAPIdInfo_struct));
		if (pLDAPinfo->ldapIDinfo == NULL)
		{
			SRLi_FreeLDAPinfo (&pLDAPinfo);
			return (SRL_MEMORY_ERROR);
		}

		pLDAPinfo->ldapIDinfo->ldapID = LDAPinfo->ldapID;
		pLDAPinfo->ldapIDinfo->internal = FALSE;
	}
	if (LDAPinfo->LDAPServerInfo)
	{
		/* Copy the server info */
		pLDAPinfo->LDAPServerInfo = (LDAPServerInfo_struct *)calloc (1, sizeof (LDAPServerInfo_struct));
		if (pLDAPinfo->LDAPServerInfo == NULL)
		{
			SRLi_FreeLDAPinfo (&pLDAPinfo);
			return (SRL_MEMORY_ERROR);
		}
		pLDAPinfo->LDAPServerInfo->LDAPport = LDAPinfo->LDAPServerInfo->LDAPport;
		if (LDAPinfo->LDAPServerInfo->LDAPserver)
			pLDAPinfo->LDAPServerInfo->LDAPserver = strdup (LDAPinfo->LDAPServerInfo->LDAPserver);
		else
		{
			SRLi_FreeLDAPinfo (&pLDAPinfo);
			return (SRL_INVALID_PARAMETER);
		}
	}
	if (LDAPinfo->SharedLibraryName)
		pLDAPinfo->SharedLibraryName = strdup (LDAPinfo->SharedLibraryName);

	pLDAPinfo->timeout = LDAPinfo->timeout;
	session->ldapInfo = pLDAPinfo;
	return (SRL_SUCCESS);
}

static short SRLi_UpdateFileName(char *Filename)
{
int    Result  = 1; /* assume failure */

#ifdef WIN32
/* Windows we move to the recycle bin */
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


#else
	remove(Filename);
#endif
	Result = rename("./tempV3.db", Filename);
	if (Result != 0)
		return SRL_DB_IO_ERROR;
	return SRL_SUCCESS;
}


static char* SRLi_GetToken(char* strToken, ulong len,
			   char* strDelimit)
{
	char* end = NULL;

	// Initialize length result
	len = 0;

	// Return NULL if the input string is NULL
	if (strToken == NULL)
		return NULL;

	// Return the length of the string, if no delimiters are specified
	if (strDelimit == NULL)
	{
		len = strlen(strToken);
		return strToken;
	}

	// Find the start of the next token
	while (*strToken != '\0')
	{
		// See if this character matches one of the delimiters
		char* pDelim = strDelimit;
		while ((*pDelim != '\0') && (*strToken != *pDelim))
			pDelim++;

		// If this character didn't match one of the delimiters, then
		// break out of the loop
		if (*pDelim == '\0')
			break;

		strToken++;
	}

	// If no more tokens are present, return NULL
	if (*strToken == '\0')
		return NULL;

	end  = strToken;
	// Find the length of the token
	while (*end != '\0')
	{
		// See if this character matches one of the delimiters
		char* pDelim = strDelimit;
		while ((*pDelim != '\0') && (*end != *pDelim))
			pDelim++;

		// If this character matches one of the delimiters, then break out of
		// the loop
		if (*pDelim != '\0')
			break;
		*end ++;
		len++;
	}
	*end++;
	return end;
} // end of strtok_r()

