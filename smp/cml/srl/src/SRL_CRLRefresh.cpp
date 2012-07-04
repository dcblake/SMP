/*****************************************************************************
File:	  SRL_CRLRefresh.cpp
Project:  Storage & Retrieval Library
Contents: Library of routines which will be used by the
	      Storage & Retrieval library to refresh a CRL.

Created:  April 2002
Author:   C. C. McPherson <Clyde.McPherson@GetronicsGov.com>
          Shari Bodin <Shari.Bodin@GetroinicsGov.com>

Last Updated:	9 December 2002

Version:  2.2

Description:  The routines in this file are used in refreshing the CRL and
are not meant for general use.
*****************************************************************************/
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

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
#include "cmlasn.h"

// Using declarations for CRL Refresh
using CML::ASN::Bytes;
using CML::ASN::DN;
using CML::ASN::GenName;
using CML::ASN::Time;
using CML::ASN::CertificateList;
using CML::ASN::CrlExtensions;

#if __cplusplus
extern "C" {
#endif

extern short SRLi_TemplateFromCRLInfo(DB_Kid *kid, dbCRLEntryInfo_LL *crlinfo);

/*
 * Routine to obtain the type of CRL from the
 * extensions
 */
uchar getCRLtype(CrlExtensions *CrlExtn)
{
unsigned char crl_type = 0;
	if ((CrlExtn) && (CrlExtn->pDeltaCRL))
		crl_type = DELTA_CRL_TYPE;
	else if ((CrlExtn) && (CrlExtn->pIssuingDP))
	{
		/* Get the Issuing Distribution Point Pointer */
		CML::ASN::IssuingDistPointExtension *IssDistPts = CrlExtn->pIssuingDP;
		if (IssDistPts != NULL)
		{
			/*
			 * If the issuing points has only CA flag set, then
			 * the CRL type is a ARL
			 */
			if ((IssDistPts->onlyContainsAuthorityCerts) && 
				(IssDistPts->onlyContainsUserCerts == 0))
				crl_type = ARL_TYPE;
			else if (IssDistPts->onlyContainsUserCerts)
				crl_type = CRL_TYPE;
			else
				crl_type = CRL_TYPE;
		}
		else
			// Default to value passed in
			crl_type = (unsigned char)CRL_TYPE;
		
	}
	else
		// Default to CRL_TYPE
		crl_type = (unsigned char)CRL_TYPE;
	return (crl_type);
}

/*
 * Routine to CHeck the CRL to see if it is the one that
 * will be refreshed
 */
bool SRLi_CheckCRLRefresh (DB_Item *oldCRL, Bytes_struct *newCRL, AsnTypeFlag *TypeFlag)
{
	bool match = false;
	uchar CRLType1 = 0;
	uchar CRLType2 = 0;

	if ((oldCRL == NULL) || (newCRL == NULL))
		return false;

	try {
		// Put our DB_Item's into the Bytes class
		Bytes tmp_newCRL(*newCRL);
		Bytes tmp_oldCRL(oldCRL->item_len, (const unsigned char *)oldCRL->item_ptr);

		// Now load in the CRLs
		CertificateList asnOldCRL(tmp_oldCRL);
		CertificateList asnNewCRL(tmp_newCRL);

		// Check for same issuer
		if (asnOldCRL.issuer == asnNewCRL.issuer)
		{
			// Get the CRL extensions
			CrlExtensions oldExts = asnOldCRL.crlExts;
			CrlExtensions newExts = asnNewCRL.crlExts;

			/* 
			 * Now check the extensions to make sure
			 * we have the same CRL, we don't want to refresh
			 * on different CRL's.
			 */
			CRLType1 = getCRLtype(&oldExts);
			CRLType2 = getCRLtype(&newExts);
			if (CRLType1 == CRLType2)
			{
				if ((oldExts.pIssuingDP) && (newExts.pIssuingDP))
				{
					// Make sure the distribution points are the same
					if (*oldExts.pIssuingDP == *newExts.pIssuingDP)
						match = true;
					else
						match = false;
				}
				// if neither have a distribution point and then they are the same
				else if ((!oldExts.pIssuingDP) && (!newExts.pIssuingDP))
				{
					match = true;
				}
			}
			else
				match = false;
		}
		else
			match = false;

		// Check if the CRL is newer than the one in the DB
		if (asnNewCRL.thisUpdate <= asnOldCRL.thisUpdate)
			match = false;
			
		*TypeFlag = (AsnTypeFlag)CRLType2;
		return match;
	}

	// Catch everything and return false if exception happens
	catch (...)
	{
		return false;
	}
}

/* Routine to refresh the CRL */
short SLRi_RefreshCRL(ulong sessionID, ulong crl_db_session, dbCRLEntryInfo_LL *oldCRLInfo, char *opt_kid, CM_BOOL isURL)
{
	AsnTypeFlag CrlType = (AsnTypeFlag)CRL_TYPE;
	short err = SRL_SUCCESS;
	CRL_struct *dec_crl = NULL;
	EncObject_LL *pObjList = NULL, *tmpObjList;
	Bytes_struct CRLObject;
	DB_Data	*oldCRL = NULL;
	DB_Kid refresh_kid;

	if (oldCRLInfo == NULL)
		return SRL_INVALID_PARAMETER;

	err = SRLi_TemplateFromCRLInfo(&refresh_kid, oldCRLInfo);
	if (err != SRL_SUCCESS)
	{
		return err;
	}

	err = db_GetEntry(crl_db_session, 0, &refresh_kid, &oldCRL);
	if (refresh_kid.item_ptr)
		free(refresh_kid.item_ptr);

	if (err != SRL_SUCCESS)
	{
		return err;
	}

	CRLObject.data = (uchar *)oldCRL->item_ptr;
	CRLObject.num = oldCRL->item_len;

	// Decode the crl and the extension, don't decode the revocations
	err = CM_DecodeCRL2(&CRLObject, &dec_crl, FALSE, TRUE);
	if (err != CM_NO_ERROR)
	{
		if (dec_crl)
			CM_FreeCRL(&dec_crl);
		if (oldCRL)
			SRLi_FreeDB_Item(&oldCRL);
		return err;
	}

	// Get the remote CRLs. Don't do a SRL_ReqObjs, because that logic will try to
	// add it to the data base, call ldap independently


	// If we do not have a URL or the optional kid was not passed in find in the directory.
	if ((!isURL) || (!opt_kid))
	{
		err = SRLi_GetLDAPSessionStatus(sessionID);
		if (err != SRL_SUCCESS)
		{
			if (oldCRL)
				SRLi_FreeDB_Item(&oldCRL);
			if (dec_crl)
				CM_FreeCRL(&dec_crl);
			return err;
		}
		err = SRLi_GetRemoteCRLs(sessionID, ((opt_kid != NULL) ? opt_kid : dec_crl->issuer), 
			CRL_TYPE|ARL_TYPE|DELTA_CRL_TYPE, &pObjList);
	}
	else
	{
		err = SRLi_GetRemoteURLCRLs(sessionID, opt_kid,
			CRL_TYPE | ARL_TYPE | DELTA_CRL_TYPE, SERVER_LOC | DSA_LOC,
			&pObjList);
	}

	if (err != SRL_SUCCESS)
	{
		if (pObjList)
			free(pObjList);
		if (oldCRL)
			SRLi_FreeDB_Item(&oldCRL);
		if (dec_crl)
			CM_FreeCRL(&dec_crl);
		if (err == SRL_LDAP_SEARCH_FAILED)
			err = SRL_NOT_FOUND;
		return err;
	}
	if (pObjList == NULL)
	{
		if (oldCRL)
			SRLi_FreeDB_Item(&oldCRL);
		if (dec_crl)
			CM_FreeCRL(&dec_crl);
		return SRL_SUCCESS;
	}
	tmpObjList = pObjList;

	bool match = false;

	// Since the issuer could have multiple CRL's
	// loop through the list until a match or all
	// objects have been looked at
	while ((!match) && (tmpObjList != NULL))
	{
		
		match = SRLi_CheckCRLRefresh (oldCRL, &tmpObjList->encObj, &CrlType);
		if (!match)
			tmpObjList = tmpObjList->next;
	}
	
	if (match)
	{
		// We have a match so remove the old and add the new object
		SRLSession_struct	*session;
		short err = SRL_SUCCESS;

		err =  SRLi_GetSessionFromRef(&session, sessionID);
		if(err != SRL_SUCCESS)
		{
			if (oldCRL)
				SRLi_FreeDB_Item(&oldCRL);
			if (dec_crl)
				CM_FreeCRL(&dec_crl);
			return(err);
		}

		// Build a dbEntryInfo_LL structure
		dbEntryInfo_LL dbentry;
		dbentry.entry_DN = dec_crl->issuer;
		dbentry.info.crls = oldCRLInfo;

		if (session->removeStaleCRL)
		{
			err = SRLi_DatabaseRemove(sessionID, SRL_DB_CRL, &dbentry, 0);
			// Done with the decoded crl - free it
			if (dec_crl)
				CM_FreeCRL(&dec_crl);

			if (err != SRL_SUCCESS)
			{
				if (oldCRL)
					SRLi_FreeDB_Item(&oldCRL);
				if (dec_crl)
					CM_FreeCRL(&dec_crl);
				return err;
			}
		}

		// Add in the new object
		CRLObject.data = (uchar *)tmpObjList->encObj.data;
		CRLObject.num = tmpObjList->encObj.num;

		err = SRLi_DatabaseAdd(sessionID, &CRLObject, CrlType, opt_kid);
		SRLi_FreeObjList(&pObjList);
		
		if (err != SRL_SUCCESS)
		{
			if (oldCRL)
				SRLi_FreeDB_Item(&oldCRL);
			if (dec_crl)
				CM_FreeCRL(&dec_crl);
			return err;
		}
	}
	else
	{
		if (pObjList)
			SRLi_FreeObjList(&pObjList);
		err = SRL_NOT_FOUND;
	}

	if (oldCRL)
		SRLi_FreeDB_Item(&oldCRL);
	if (dec_crl)
		CM_FreeCRL(&dec_crl);
	return err;
}


#if __cplusplus
}
#endif
