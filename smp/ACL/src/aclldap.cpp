//////////////////////////////////////////////////////////////////////////////
// File:     ACL_ldap.c
// Project:  Attribute Certificate Library
// Contents: Internal Attribute Certificate Library functions used to call
//            the standard LDAP library.
// Functions included in file:
//    ACLU_LdapConnect()
//    ACLU_LdapInit()
//    ACLU_LdapRead()
//    ACLU_Link2LDAP()
//
//////////////////////////////////////////////////////////////////////////////

// Windows.h and LDAP32_DYNAMIC_BIND are only needed in Windows when
// dynamically binding to the ldap32.dll at run-time.  Undefine
// LDAP32_DYNAMIC_BIND when statically linking or dynamically linking at
// load-time.
#if defined (_WINDOWS) || defined (SunOS) || defined (Linux)
#define LDAP32_DYNAMIC_BIND
#endif // _WINDOWS

#include <stdio.h> // for debugging cross cert problem
#if defined(SunOS) || defined(Linux)
#include "dlfcn.h"
#endif

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL
_USING_NAMESPACE_SNACC

extern void FreeSRLInitSettings (SRL_InitSettings_struct *settings);
// -----------
// LdapRequest
// -----------
CML::ASN::BytesList *LdapRequest(CML::ASN::DN *pTmpDN,
                           long objectFlag, ulong *sessionID)
{
   CML::ASN::BytesList *pRtnBuf=NULL;
    long typeMask;
    const char *pSnaccDN= (const char *) *pTmpDN;
    EncObject_LL *pObjList = NULL;

    // DN String
    if (pSnaccDN == NULL)
    {
        return(pRtnBuf);
    }

    if (objectFlag == Cacheable::ACSPIF_ID)
    {
        typeMask = SPIF_TYPE;
    }
    else if (objectFlag == Cacheable::ACLRCERT_ID)
    {
        typeMask = USER_CERT_TYPE;
    }
    else
    {
        typeMask = AC_TYPE;
    }

    SRL_RequestObjs(sessionID, (char *)pSnaccDN, typeMask,
					DSA_LOC, &pObjList);      

    // For each certificate attribute returned from the LDAP server, get
    // the attribute's values and copy them to the encoded cert linked list
    while (pObjList != NULL)
    {
		// CONSTRUCT A NEW BUFFER USING THE ENCODED VALUES RETURNED
		// FROM LDAP AND THEN APPEND THAT BUFFER TO THE END OF THE LIST
		if (pRtnBuf == NULL)
		{
         pRtnBuf = new CML::ASN::BytesList;
		}

      pRtnBuf->push_back(pObjList->encObj);

      pObjList = pObjList->next;

    } // end of while loop

    return(pRtnBuf);

} // END OF LdapRequest

void CREATE_LDAP_HANDLE(char *dllFilename, char *serverName,
                         long portNumber, ulong **m_psessionID)
{
   FUNC("CREATE_LDAP_HANDLE()");
   try
   {
       ulong SRLsessionID;
       SRL_InitSettings_struct *pSettings; 
       long error = 0;

       pSettings = (SRL_InitSettings_struct *)calloc(1, 
           sizeof(SRL_InitSettings_struct));
       pSettings->LDAPinfo = (LDAPInitSettings_struct *)calloc(1, 
           sizeof(LDAPInitSettings_struct));
       pSettings->LDAPinfo->LDAPServerInfo = (LDAPServerInit_struct *)calloc(1, 
           sizeof(LDAPServerInit_struct));
       pSettings->LDAPinfo->SharedLibraryName = strdup(dllFilename);
       pSettings->LDAPinfo->LDAPServerInfo->LDAPport = portNumber;
       pSettings->LDAPinfo->LDAPServerInfo->LDAPserver = strdup(serverName);


       // Create an SRL session
       error = SRL_CreateSession(&SRLsessionID, pSettings);   
       if (error != 0)
       {
		  FreeSRLInitSettings(pSettings);
          throw ACL_EXCEPT(ACL_SRL_INVALID_PARAMETER,
            "SRL_CreateSession failed - invalid parameters");
       }
       *m_psessionID = (ulong *)calloc(1, sizeof(ulong));
	   **m_psessionID = SRLsessionID;
   	   FreeSRLInitSettings(pSettings);
   }
   catch (SnaccException &e)
   {
      e.push(STACK_ENTRY);
      throw;
   }
}

void DESTROY_LDAP_HANDLE(ulong *p_sessionID)
{
   if (p_sessionID != NULL)
       SRL_DestroySession(p_sessionID);
}

void FreeSRLInitSettings (SRL_InitSettings_struct *settings)
{
	if (settings == NULL)
		return;
	if (settings->CertFileName != NULL)
		free (settings->CertFileName);
	if (settings->CRLFileName != NULL)
		free (settings->CRLFileName);
	if (settings->LDAPinfo != NULL)
	{
		/* Free the contents of the LDAP information structure */

		/* LDAP functions are used in the session struct, don't free them here */
		if (settings->LDAPinfo->SharedLibraryName != NULL)
			free (settings->LDAPinfo->SharedLibraryName);
		if (settings->LDAPinfo->LDAPServerInfo != NULL)
		{
			if (settings->LDAPinfo->LDAPServerInfo->LDAPserver != NULL)
				free (settings->LDAPinfo->LDAPServerInfo->LDAPserver);
			free (settings->LDAPinfo->LDAPServerInfo);
		}
        free (settings->LDAPinfo);
	}
    free (settings);
	return;
}

_END_NAMESPACE_ACL

// EOF aclldap.cpp
