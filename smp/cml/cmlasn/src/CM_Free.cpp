/*****************************************************************************
File:     CM_Free.cpp
Project:  Certificate Management Library
Contents: The high-level (CM_FreeCert, CM_FreeCRL, etc.,) and internal
		  (low-level) functions used to free memory that was allocated by 
		  the library.

Created:  25 June 1999
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com> 

Last Updated:	23 October 2003

Version:  2.4

*****************************************************************************/

/* -------------- */
/* Included Files */
/* -------------- */
#include "cmlasn_internal.h"


// Using CML::ASN namespace
using namespace CML::ASN;


/* ------------------- */
/* Function Prototypes */
/* ------------------- */
static void freeAny(Any_struct *);
static void freeBaseRevocationInfo(CM_BaseRevocationInfo *pRevInfo);
static void freeDeltaInfo(DeltaInfo *deltaInfo);
static void freeDistPtNameContent(Dist_pt_name *dpName);
static void freeIssuingDistPt(Iss_pts_struct *pDistPt);
static void freeLongArray(LongArray **pArray);
static void freeMosaicKey(Mosaic_key_struct *combo);
static void freeNumberRange(CM_NumberRange* pRange);
static void freePriv_flags(Priv_flags **priv_flags);
static void freeSigStructContents(Sig_struct& sig);
static void freeSsl(Ssl_privs **Sslprivs);



/* ----------- */
/* CM_FreeCert */
/* ----------- */
void CM_FreeCert(Cert_struct** decCert)
{
	if ((decCert == NULL) || (*decCert == NULL))
		return;

	CMASN_FreeBytesContents(&(*decCert)->serial_num);
	free((*decCert)->signature);
	(*decCert)->signature = NULL;
	free((*decCert)->issuer);
	(*decCert)->issuer = NULL;
	free((*decCert)->subject);
	(*decCert)->subject = NULL;
	CMASN_FreePubKeyContents(&(*decCert)->pub_key);

	if ((*decCert)->issuer_id != NULL)
	{
		Internal::FreeBytes((*decCert)->issuer_id);
		(*decCert)->issuer_id = NULL;
	}
	if ((*decCert)->subj_id != NULL)
	{
		Internal::FreeBytes((*decCert)->subj_id);
		(*decCert)->subj_id = NULL;
	}
	if ((*decCert)->exts != NULL)
	{
		Internal::FreeCertExtensions((*decCert)->exts);
		(*decCert)->exts = NULL;
	}
    
	freeSigStructContents((*decCert)->sig);
	free(*decCert);
	*decCert = NULL;
}


/* ------------------------- */
/* CM_FreeCertPathLinkedList */
/* ------------------------- */
void CM_FreeCertPathLinkedList(Cert_path_LL **decCertPath)
{
	if (decCertPath == NULL)
		return;
	
	while (*decCertPath != NULL)
	{
		Cert_path_LL* next = (*decCertPath)->next;
		CM_FreeCert(&(*decCertPath)->cert);
		free(*decCertPath);
		*decCertPath = next;
	}
}


/* ---------- */
/* CM_FreeCRL */
/* ---------- */
void CM_FreeCRL(CRL_struct **decCRL)
{
	if ((decCRL == NULL) || (*decCRL == NULL))
		return;

	free((*decCRL)->signature);
	(*decCRL)->signature = NULL;
	
	free((*decCRL)->issuer);
	(*decCRL)->issuer = NULL;

	if ((*decCRL)->nextUpdate != NULL)
	{
		free((*decCRL)->nextUpdate);
		(*decCRL)->nextUpdate = NULL;
	}
	
	while ((*decCRL)->revoked != NULL)
	{
		RevCerts_LL* nextItem = (*decCRL)->revoked->next;

		CMASN_FreeBytesContents(&(*decCRL)->revoked->serialNum);
		if ((*decCRL)->revoked->revDate != NULL)
		{
			free((*decCRL)->revoked->revDate);
			(*decCRL)->revoked->revDate = NULL;
		}
		if ((*decCRL)->revoked->exts != NULL)
		{
			Internal::FreeCRLEntryExtensions((*decCRL)->revoked->exts);
			(*decCRL)->revoked->exts = NULL;
		}
		
		free((*decCRL)->revoked);
		(*decCRL)->revoked = nextItem;
	}

	if ((*decCRL)->exts != NULL)
	{
		Internal::FreeCRLExtensions((*decCRL)->exts);
		(*decCRL)->exts = NULL;
	}
	
	freeSigStructContents((*decCRL)->sig);
	free(*decCRL);
	*decCRL = NULL;
} // end of CM_FreeCRL()


/* ------------- */
/* CM_FreeString */
/* ------------- */
void CM_FreeString(char **string)
{
	if ((string == NULL) || (*string == NULL))
		return;

	free(*string);
	*string = NULL;
}


////////////////////////////////////////////////////////////////////////////////
// Function:      CMASN_FreeBytesContents()
// Description:   Free the data contents of a Bytes_struct
// Inputs:        Bytes_struct& bytes - data to be freed.
// Outputs:       (none)
// Return value:  (none)
////////////////////////////////////////////////////////////////////////////////
void CMASN_FreeBytesContents(Bytes_struct* bytes)
{
   if (bytes != NULL)
   {
      if (bytes->data != NULL)
      {
         free(bytes->data);
         bytes->data = NULL;
      }
      bytes->num = 0;
   }
   return;
} /* end of CMASN_FreeBytesContents() */


////////////////////////////
// CMASN_FreeCertPairList //
////////////////////////////
void CMASN_FreeCertPairList(EncCertPair_LL** encCerts)
{
	if (encCerts == NULL)
		return;

	while (*encCerts != NULL)
	{
		EncCertPair_LL* next = (*encCerts)->next;
		free(*encCerts);
		*encCerts = next;
	}
}


/* ------------------- */
/* CMASN_FreePolicySet */
/* ------------------- */
void CMASN_FreePolicySet(Policy_struct* set)
{
	while (set != NULL)
	{
		free(set->policy_id);
		set->policy_id = NULL;
		
		Internal::FreeQualifiers(&set->qualifiers);
		
		Policy_struct* next = set->next;
		set->next = NULL;
		free(set);
		
		set = next;
	}
}


/* ------------------------ */
/* CMASN_FreePubKeyContents */
/* ------------------------ */
void CMASN_FreePubKeyContents(Pub_key_struct* key)
{
	if ((key == NULL) || (key->oid == NULL))
		return;
	
	if ((strcmp(key->oid, gDSA_OID) == 0)||
		(strcmp(key->oid, gOIW_DSA) == 0))
	{
		Internal::FreePQGs(key->params.dsa);
		key->params.dsa = NULL;
		Internal::FreeBytes(key->key.y);
		key->key.y = NULL;
	}
	else if (strcmp(key->oid, gKEA_OID) == 0)
	{
		Internal::FreeBytes(key->params.kea);
		key->params.kea = NULL;
		Internal::FreeBytes(key->key.y);
		key->key.y = NULL;
	}
	else if (strcmp(key->oid, gDSA_KEA_OID) == 0)
	{
		Internal::FreePQGs(key->params.dsa_kea);
		key->params.dsa_kea = NULL;
		freeMosaicKey(key->key.combo);
		key->key.combo = NULL;
	}
	else if (strcmp(key->oid, gRSA_OID) == 0)
	{
		if (key->params.encoded != NULL)
		{
			Internal::FreeBytes(key->params.encoded);
			key->params.encoded = NULL;
		}
		if (key->key.rsa != NULL)
		{
			CMASN_FreeBytesContents(&key->key.rsa->publicExponent);
			CMASN_FreeBytesContents(&key->key.rsa->modulus);
			free(key->key.rsa);
			key->key.rsa = NULL;
		}
	}
	else if ((strcmp(key->oid, gOLD_DH_OID) == 0) ||
		(strcmp(key->oid, gANSI_DH_OID) == 0) ||
		(strcmp(key->oid, gEC_KEY_OID) == 0))
	{
		if (key->params.encoded != NULL)
		{
			Internal::FreeBytes(key->params.encoded);
			key->params.encoded = NULL;
		}
		Internal::FreeBytes(key->key.y);
		key->key.y = NULL;
	}
	else	// Any other algorithm
	{
		if (key->params.encoded != NULL)
		{
			Internal::FreeBytes(key->params.encoded);
			key->params.encoded = NULL;
		}
		Internal::FreeBytes(key->key.encoded);
		key->key.encoded = NULL;
	}
	free(key->oid);
	key->oid = NULL;
} // end of CMASN_FreePubKeyContents()


/* --------------------------------- */
/* CML::ASN::Internal Free Functions */
/* --------------------------------- */
void Internal::FreeAccessDescriptions(AccessDescript_LL* pAccessDesc)
{
	while (pAccessDesc != NULL)
	{
		AccessDescript_LL* next = pAccessDesc->next;

		// Free the method OID
		free(pAccessDesc->method);
		pAccessDesc->method = NULL;

		// Free the location
		FreeGenNameContent(&pAccessDesc->loc);

		free(pAccessDesc);
		pAccessDesc = next;
	}
}


void Internal::FreeAttributes(Attributes_struct* attr)
{
	while (attr != NULL)
	{
		Attributes_struct* next = attr->next;
		
		// Free the OID
		free(attr->oid);
		attr->oid = NULL;
		
		// Free the values according to the type
		switch (attr->type)
		{
		case PRBACINFO:
			FreeClearance(&attr->values.prbac_infop);
			break;
		case CACONSTRAINTS:
			FreeCa_const(&attr->values.ca_const);
			break;
		case SIGORKMPRIVILEGES:
			freePriv_flags(&attr->values.priv_flags);
			break;
		case COMMPRIV:
			FreeBytes(attr->values.comm_priv);
			attr->values.comm_priv = NULL;
			break;
		case UNKNOWN:
			FreeBytes_LL(&attr->values.unkn);
			break;
		}
		
		free(attr);
		attr = next;
	}
} // end of Internal::FreeAttributes()


void Internal::FreeAuthKeyID(Auth_key_struct *authKey)
{
	if (authKey == NULL)
		return;
	if (authKey->id != NULL)
	{
		FreeBytes(authKey->id);
		authKey->id = NULL;
	}
	if (authKey->issuer != NULL)
	{
		FreeGenNames(authKey->issuer);
		authKey->issuer = NULL;
	}
	if (authKey->serial_num != NULL)
	{
		FreeBytes(authKey->serial_num);
		authKey->serial_num = NULL;
	}
	free(authKey);

} // end of Internal::FreeAuthKeyID()


void Internal::FreeBytes(Bytes_struct *bytes)
{
	if (bytes == NULL)
		return;
	CMASN_FreeBytesContents(bytes);
	free(bytes);
}


void Internal::FreeBytes_LL(Bytes_struct_LL** pList)
{
	if (pList == NULL)
		return;
	
	while (*pList != NULL)
	{
		Bytes_struct_LL* next = (*pList)->next;

		FreeBytes((*pList)->bytes_struct);
		(*pList)->bytes_struct = NULL;
		free(*pList);

		*pList = next;
	}
}


void Internal::FreeCa_const(Ca_const **caConst)
{
	Ca_const *atList,
			 *next;

	if ((caConst == NULL) || (*caConst == NULL))
	   return;

	atList = *caConst;
	while (atList != NULL)
	{
		next = atList->next;

		switch (atList->ca_type)
		{
		case PRBACINFO:
			FreeClearance(&atList->ca_val.prbac_infop);
			break;
		case SIGORKMPRIVILEGES:
			freePriv_flags(&atList->ca_val.priv_flags);
			break;
		case COMMPRIV:
			FreeBytes(atList->ca_val.comm_priv);
			atList->ca_val.comm_priv = NULL;
			break;
		}

		free(atList);
		atList = next;
	}

	*caConst = NULL;
	return;

} // end of Internal::FreeCa_const()


void Internal::FreeCertExtensions(Cert_exts_struct *exts)
{
	if (exts->authKeyID != NULL)
	{
		free(exts->authKeyID->oid);
		exts->authKeyID->oid = NULL;
		FreeAuthKeyID((Auth_key_struct*)exts->authKeyID->value);
		exts->authKeyID->value = NULL;
		free(exts->authKeyID);
		exts->authKeyID = NULL;
	}
	if (exts->subjKeyID != NULL)
	{
		free(exts->subjKeyID->oid);
		exts->subjKeyID->oid = NULL;
		FreeBytes((Bytes_struct*)exts->subjKeyID->value);
		exts->subjKeyID->value = NULL;
		free(exts->subjKeyID);
		exts->subjKeyID = NULL;
	}
	if (exts->keyUsage != NULL)
	{
		free(exts->keyUsage->oid);
		exts->keyUsage->oid = NULL;
		free(exts->keyUsage->value);
		exts->keyUsage->value = NULL;
		free(exts->keyUsage);
		exts->keyUsage = NULL;
	}
	if (exts->extKeyUse != NULL)
	{
		free(exts->extKeyUse->oid);
		exts->extKeyUse->oid = NULL;
		FreeOIDList((Ext_key_use_LL*)exts->extKeyUse->value);
		exts->extKeyUse->value = NULL;
		free(exts->extKeyUse);
		exts->extKeyUse = NULL;
	}
	if (exts->privKeyVal != NULL)
	{
		free(exts->privKeyVal->oid);
		exts->privKeyVal->oid = NULL;
		if (exts->privKeyVal->value != NULL)
		{
			Priv_key_val_struct& privKeyVal = 
				*(Priv_key_val_struct*)exts->privKeyVal->value;

			if (privKeyVal.not_before != NULL)
			{
				free(privKeyVal.not_before);
				privKeyVal.not_before = NULL;
			}
			if (privKeyVal.not_after != NULL)
			{
				free(privKeyVal.not_after);
				privKeyVal.not_after = NULL;
			}
			free(exts->privKeyVal->value);
			exts->privKeyVal->value = NULL;
		}
		free(exts->privKeyVal);
		exts->privKeyVal = NULL;
	}
	if (exts->certPolicies != NULL)
	{
		free(exts->certPolicies->oid);
		exts->certPolicies->oid = NULL;
		CMASN_FreePolicySet((Policy_struct*)exts->certPolicies->value);
		exts->certPolicies->value = NULL;
		free(exts->certPolicies);
		exts->certPolicies = NULL;
	}
	if (exts->policyMaps != NULL)
	{
		free(exts->policyMaps->oid);
		exts->policyMaps->oid = NULL;
		FreePolicyMaps((Pol_maps_struct*)exts->policyMaps->value);
		exts->policyMaps->value = NULL;
		free(exts->policyMaps);
		exts->policyMaps = NULL;
	}
	if (exts->subjAltName != NULL)
	{
		free(exts->subjAltName->oid);
		exts->subjAltName->oid = NULL;
		FreeGenNames((Gen_names_struct*)(exts->subjAltName->value));
		exts->subjAltName->value = NULL;
		free(exts->subjAltName);
		exts->subjAltName = NULL;
	}
	if (exts->issuerAltName != NULL)
	{
		free(exts->issuerAltName->oid);
		exts->issuerAltName->oid = NULL;
		FreeGenNames((Gen_names_struct*)(exts->issuerAltName->value));
		exts->issuerAltName->value = NULL;
		free(exts->issuerAltName);
		exts->issuerAltName = NULL;
	}
	if (exts->subjDirAtts != NULL)
	{
		free(exts->subjDirAtts->oid);
		exts->subjDirAtts->oid = NULL;
		FreeAttributes((Attributes_struct*)exts->subjDirAtts->value);
		exts->subjDirAtts->value = NULL;
		free(exts->subjDirAtts);
		exts->subjDirAtts = NULL;
	}
	if (exts->basicCons != NULL)
	{
		free(exts->basicCons->oid);
		exts->basicCons->oid = NULL;
		free(exts->basicCons->value);
		exts->basicCons->value = NULL;
		free(exts->basicCons);
		exts->basicCons = NULL;
	}
	if (exts->nameCons != NULL)
	{
		free(exts->nameCons->oid);
		exts->nameCons->oid = NULL;
		if (exts->nameCons->value != NULL)
		{
			Name_cons_struct& nameCons =
				*(Name_cons_struct*)exts->nameCons->value;
			FreeSubtrees(&nameCons.permitted);
			FreeSubtrees(&nameCons.excluded);
			if (nameCons.basicNames != NULL)
			{
				free(nameCons.basicNames);
				nameCons.basicNames = NULL;
			}
			FreeOIDList(nameCons.otherNames);
			nameCons.otherNames = NULL;
			free(exts->nameCons->value);
			exts->nameCons->value = NULL;
		}
		free(exts->nameCons);
		exts->nameCons = NULL;
	}
	if (exts->policyCons != NULL)
	{
		free(exts->policyCons->oid);
		exts->policyCons->oid = NULL;
		free(exts->policyCons->value);
		exts->policyCons->value = NULL;
		free(exts->policyCons);
		exts->policyCons = NULL;
	}
	if (exts->distPts != NULL)
	{
		free(exts->distPts->oid);
		exts->distPts->oid = NULL;
		FreeDistPts_LL((Dist_pts_struct*)exts->distPts->value);
		exts->distPts->value = NULL;
		free(exts->distPts);
		exts->distPts = NULL;
	}
	if (exts->aia != NULL)
	{
		free(exts->aia->oid);
		exts->aia->oid = NULL;
		FreeAccessDescriptions((AccessDescript_LL*)exts->aia->value);
		exts->aia->value = NULL;
		free(exts->aia);
		exts->aia = NULL;
	}
	if (exts->inhibitAnyPol != NULL)
	{
		free(exts->inhibitAnyPol->oid);
		exts->inhibitAnyPol->oid = NULL;
		free(exts->inhibitAnyPol->value);
		exts->inhibitAnyPol->value = NULL;
		free(exts->inhibitAnyPol);
		exts->inhibitAnyPol = NULL;
	}
	if (exts->freshCRL != NULL)
	{
		free(exts->freshCRL->oid);
		exts->freshCRL->oid = NULL;
		FreeDistPts_LL((Dist_pts_struct*)exts->freshCRL->value);
		exts->freshCRL->value = NULL;
		free(exts->freshCRL);
		exts->freshCRL = NULL;
	}
	if (exts->sia != NULL)
	{
		free(exts->sia->oid);
		exts->sia->oid = NULL;
		FreeAccessDescriptions((AccessDescript_LL*)exts->sia->value);
		exts->sia->value = NULL;
		free(exts->sia);
		exts->sia = NULL;
	}
	if (exts->unknown != NULL)
		FreeUnknExtn(&exts->unknown);
	
	free(exts);

} // end of Internal::FreeCertExtensions()


void Internal::FreeClearance(Clearance_struct **clearance)
{
	if ((clearance == NULL) || (*clearance == NULL))
	   return;

	if ((*clearance)->policyID != NULL)
	{
		free((*clearance)->policyID);
		(*clearance)->policyID = NULL;
	}

	if ((*clearance)->classList != NULL)
	{
		FreeBytes((*clearance)->classList);
		(*clearance)->classList = NULL;
	}

	if ((*clearance)->categories != NULL)
		FreeSecCategories(&(*clearance)->categories);

	free(*clearance);
	*clearance = NULL;

} // end of Internal::FreeClearance()


void Internal::FreeCRLEntryExtensions(CRL_entry_exts_struct *exts)
{
	if (exts == NULL)
		return;
	
	if (exts->reasonCode != NULL)
	{
		free(exts->reasonCode->oid);
		exts->reasonCode->oid = NULL;
		free(exts->reasonCode->value);
		exts->reasonCode->value = NULL;
		free(exts->reasonCode);
		exts->reasonCode = NULL;
	}
	if (exts->instrCodeOid != NULL)
	{
		free(exts->instrCodeOid->oid);
		exts->instrCodeOid->oid = NULL;
		if (exts->instrCodeOid->value != NULL)
		{
			if (*(CM_OID*)exts->instrCodeOid->value != NULL)
			{
				free(*(CM_OID*)exts->instrCodeOid->value);
				*(CM_OID*)exts->instrCodeOid->value = NULL;
			}
			free(exts->instrCodeOid->value);
			exts->instrCodeOid->value = NULL;
		}
		free(exts->instrCodeOid);
		exts->instrCodeOid = NULL;
	}
	if (exts->invalDate != NULL)
	{
		free(exts->invalDate->oid);
		exts->invalDate->oid = NULL;
		free(exts->invalDate->value);
		exts->invalDate->value = NULL;
		free(exts->invalDate);
		exts->invalDate = NULL;
	}
	if (exts->certIssuer != NULL)
	{
		free(exts->certIssuer->oid);
		exts->certIssuer->oid = NULL;
		FreeGenNames((Gen_names_struct*)(exts->certIssuer->value));
		exts->certIssuer->value = NULL;
		free(exts->certIssuer);
		exts->certIssuer = NULL;
	}
	if (exts->unknown != NULL)
		FreeUnknExtn(&exts->unknown);
	
	free(exts);
	
} // end of Internal::FreeCRLEntryExtensions()


void Internal::FreeCRLExtensions(CRL_exts_struct *exts)
{
	if (exts == NULL)
		return;
	
	if (exts->authKeyID != NULL)
	{
		free(exts->authKeyID->oid);
		exts->authKeyID->oid = NULL;
		FreeAuthKeyID((Auth_key_struct*)exts->authKeyID->value);
		exts->authKeyID->value = NULL;
		free(exts->authKeyID);
		exts->authKeyID = NULL;
	}
	if (exts->issuerAltName != NULL)
	{
		free(exts->issuerAltName->oid);
		exts->issuerAltName->oid = NULL;
		FreeGenNames((Gen_names_struct*)(exts->issuerAltName->value));
		exts->issuerAltName->value = NULL;
		free(exts->issuerAltName);
		exts->issuerAltName = NULL;
	}
	if (exts->crlNum != NULL)
	{
		free(exts->crlNum->oid);
		exts->crlNum->oid = NULL;
		FreeBytes((Bytes_struct*)exts->crlNum->value);
		exts->crlNum->value = NULL;
		free(exts->crlNum);
		exts->crlNum = NULL;
	}
	if (exts->issDistPts != NULL)
	{
		free(exts->issDistPts->oid);
		exts->issDistPts->oid = NULL;
		freeIssuingDistPt((Iss_pts_struct*)exts->issDistPts->value);
		exts->issDistPts->value = NULL;
		free(exts->issDistPts);
		exts->issDistPts = NULL;
	}
	if (exts->deltaCRL != NULL)
	{
		free(exts->deltaCRL->oid);
		exts->deltaCRL->oid = NULL;
		FreeBytes((Bytes_struct*)exts->deltaCRL->value);
		exts->deltaCRL->value = NULL;
		free(exts->deltaCRL);
		exts->deltaCRL = NULL;
	}
	if (exts->scope != NULL)
	{
		free(exts->scope->oid);
		exts->scope->oid = NULL;
		FreePerAuthScope((PerAuthScope_LL*)exts->scope->value);
		exts->scope->value = NULL;
		free(exts->scope);
		exts->scope = NULL;
	}
	if (exts->statusRef != NULL)
	{
		free(exts->statusRef->oid);
		exts->statusRef->oid = NULL;
		FreeStatusRef((StatusReferral_LL*)exts->statusRef->value);
		exts->statusRef->value = NULL;
		free(exts->statusRef);
		exts->statusRef = NULL;
	}
	if (exts->streamId != NULL)
	{
		free(exts->streamId->oid);
		exts->streamId->oid = NULL;
		FreeBytes((Bytes_struct*)exts->streamId->value);
		exts->streamId->value = NULL;
		free(exts->streamId);
		exts->streamId = NULL;
	}
	if (exts->ordered != NULL)
	{
		free(exts->ordered->oid);
		exts->ordered->oid = NULL;
		free(exts->ordered->value);
		exts->ordered->value = NULL;
		free(exts->ordered);
		exts->ordered = NULL;
	}
	if (exts->deltaInfo != NULL)
	{
		free(exts->deltaInfo->oid);
		exts->deltaInfo->oid = NULL;
		freeDeltaInfo((DeltaInfo*)exts->deltaInfo->value);
		exts->deltaInfo->value = NULL;
		free(exts->deltaInfo);
		exts->deltaInfo = NULL;
	}
	if (exts->baseUpdate != NULL)
	{
		free(exts->baseUpdate->oid);
		exts->baseUpdate->oid = NULL;
		free(exts->baseUpdate->value);
		exts->baseUpdate->value = NULL;
		free(exts->baseUpdate);
		exts->baseUpdate = NULL;
	}
	if (exts->freshCRL != NULL)
	{
		free(exts->freshCRL->oid);
		exts->freshCRL->oid = NULL;
		FreeDistPts_LL((Dist_pts_struct*)exts->freshCRL->value);
		exts->freshCRL->value = NULL;
		free(exts->freshCRL);
		exts->freshCRL = NULL;
	}
	if (exts->unknown != NULL)
		FreeUnknExtn(&exts->unknown);
	
	free(exts);

} // end of Internal::FreeCRLExtensions()


void Internal::FreeCrlReferral(CRL_referral* ref)
{
	if (ref == NULL)
		return;
	
	if (ref->issuer != NULL)
	{
		FreeGenNameContent(ref->issuer);
		free(ref->issuer);
		ref->issuer = NULL;
	}
	
	if (ref->location != NULL)
	{
		FreeGenNameContent(ref->location);
		free(ref->location);
		ref->location = NULL;
	}
	
	if (ref->deltaRef != NULL)
	{
		freeDeltaInfo(ref->deltaRef);
		ref->deltaRef = NULL;
	}
	
	if (ref->crlScope != NULL)
	{
		FreePerAuthScope(ref->crlScope);
		ref->crlScope = NULL;
	}
	
	if (ref->lastUpdate != NULL)
	{
		free(ref->lastUpdate);
		ref->lastUpdate = NULL;
	}
	
	if (ref->lastChangedCRL != NULL)
	{
		free(ref->lastChangedCRL);
		ref->lastChangedCRL = NULL;
	}
	
	free(ref);
} // end of Internal::FreeCrlReferral()


void Internal::FreeDistPts_LL(Dist_pts_struct* dpList)
{
	while (dpList != NULL)
	{
		Dist_pts_struct* next = dpList->next;
		dpList->next = NULL;

		freeDistPtNameContent(&dpList->dpName);
		
		if (dpList->reasons != NULL)
		{
			free(dpList->reasons);
			dpList->reasons = NULL;
		}
		
		FreeGenNames(dpList->crl_issuer);

		free(dpList);
		dpList = next;
	}
} // end of Internal::FreeDistPts_LL()


void Internal::FreeGenNameContent(Gen_name_struct *genName)
{
	if ((genName == NULL) || (genName->name.dn == NULL))
		return;
	
	switch (genName->flag)
	{
	case CM_OTHER_NAME:
		freeAny(genName->name.other_name);
		break;
	case CM_RFC822_NAME:
		free(genName->name.rfc822);
		break;
	case CM_DNS_NAME:
		free(genName->name.dns);
		break;
	case CM_X400_ADDR:
		free(genName->name.x400);
		break;
	case CM_X500_NAME:
		free(genName->name.dn);
		break;
	case CM_EDI_NAME:
		free(genName->name.ediParty->name_assigner);
		genName->name.ediParty->name_assigner = NULL;
		free(genName->name.ediParty->party_name);
		genName->name.ediParty->party_name = NULL;
		free(genName->name.ediParty);
		break;
	case CM_URL_NAME:
		free(genName->name.url);
		break;
	case CM_IP_ADDR:
		free(genName->name.ip);
		break;
	case CM_REG_OID:
		free(genName->name.oid);
	}

	genName->name.dn = NULL;

} // end of Internal::FreeGenNameContent()


void Internal::FreeGenNames(Gen_names_struct* genNameList)
{
	while (genNameList != NULL)
	{
		Gen_names_struct* next = genNameList->next;

		FreeGenNameContent(&(genNameList)->gen_name);
		free(genNameList);

		genNameList = next;
	}
} // end of Internal::FreeGenNames()


void Internal::FreeOIDList(CM_OID_LL *cmOidList)
{
	while (cmOidList != NULL)
	{
		CM_OID_LL* next = cmOidList->next;

		free(cmOidList->oid);
		cmOidList->oid = NULL;
		free(cmOidList);

		cmOidList = next;
	}
} // end of Internal::FreeOIDList()


void Internal::FreePerAuthScope(PerAuthScope_LL *scope)
{
	while (scope != NULL)
	{
		if (scope->authName != NULL)
		{
			FreeGenNameContent(scope->authName);
			free(scope->authName);
			scope->authName = NULL;
		}
		
		freeDistPtNameContent(&scope->dpName);
		
		if (scope->onlyContains != NULL)
		{
			free(scope->onlyContains);
			scope->onlyContains = NULL;
		}
		
		if (scope->onlySomeReasons != NULL)
		{
			free(scope->onlySomeReasons);
			scope->onlySomeReasons = NULL;
		}
		
		if (scope->serialNumRange != NULL)
		{
			freeNumberRange(scope->serialNumRange);
			scope->serialNumRange = NULL;
		}
		
		if (scope->subjKeyIdRange != NULL)
		{
			freeNumberRange(scope->subjKeyIdRange);
			scope->subjKeyIdRange = NULL;
		}
		
		FreeGenNames(scope->nameSubtrees);
		
		if (scope->baseRevInfo != NULL)
		{
			freeBaseRevocationInfo(scope->baseRevInfo);
			scope->baseRevInfo = NULL;
		}
		
		PerAuthScope_LL* next = scope->next;
		free(scope);
		
		scope = next;
	}
} // end of Internal::FreePerAuthScope()


void Internal::FreePolicyMaps(Pol_maps_struct* maps)
{
	while (maps != NULL)
	{
		free(maps->issuer_pol_id);
		maps->issuer_pol_id = NULL;
		free(maps->subj_pol_id);
		maps->subj_pol_id = NULL;

		Pol_maps_struct* next = maps->next;
		free(maps);

		maps = next;
	}
}

void Internal::FreePQGs(Pqg_params_struct* params)
{
	if (params == NULL)
		return;
	
	CMASN_FreeBytesContents(&params->p);
	CMASN_FreeBytesContents(&params->q);
	CMASN_FreeBytesContents(&params->g);
	free(params);
}


void Internal::FreeQualifiers(Qualifier_struct** qual)
{
	if (qual == NULL)
		return;
	
	while (*qual != NULL)
	{
		// Free the qualifier contents
		switch ((*qual)->flag)
		{
		case CM_QUAL_CPS:
			if ((*qual)->qual.cpsURI != NULL)
			{
				free((*qual)->qual.cpsURI);
				(*qual)->qual.cpsURI = NULL;
			}
			break;
			
		case CM_QUAL_UNOTICE:
			if ((*qual)->qual.userNotice != NULL)
			{
				if ((*qual)->qual.userNotice->noticeRef != NULL)
				{
					if ((*qual)->qual.userNotice->noticeRef->org != NULL)
					{
						free((*qual)->qual.userNotice->noticeRef->org);
						(*qual)->qual.userNotice->noticeRef->org = NULL;
					}
					FreeBytes_LL(&(*qual)->qual.userNotice->noticeRef->notices);
					free((*qual)->qual.userNotice->noticeRef);
					(*qual)->qual.userNotice->noticeRef = NULL;
				}
				
				if ((*qual)->qual.userNotice->explicitText != NULL)
				{
					free((*qual)->qual.userNotice->explicitText);
					(*qual)->qual.userNotice->explicitText = NULL;
				}
				free((*qual)->qual.userNotice);
				(*qual)->qual.userNotice = NULL;
			}
			break;
			
		case CM_QUAL_UNKNOWN:
			if ((*qual)->qual.unknown != NULL)
			{
				FreeBytes((*qual)->qual.unknown);
				(*qual)->qual.unknown = NULL;
			}
			break;
			
		default:
			(*qual)->qual.unknown = NULL;
		}
		
		// Free the qualifier OID
		free((*qual)->qualifier_id);
		(*qual)->qualifier_id = NULL;
		
		// Free the qualifier and move to the next one in the list
		Qualifier_struct* nextQ = (*qual)->next;
		(*qual)->next = NULL;
		free(*qual);

		*qual = nextQ;
	}
} // end of Internal::FreeQualifiers()


#ifdef _v2_0_CODE
void CMU_FreeRDN_LL(RDN_LL **rdn)
{
    RDN_LL *tempLink;

    while (*rdn != NULL)
    {
        CM_Free((*rdn)->rdn);
        (*rdn)->rdn = NULL;
        tempLink = (*rdn)->next;
        (*rdn)->next = NULL;
        CM_Free(*rdn);
        *rdn = tempLink;
    }
    return;
}
#endif // _v2_0_CODE


void Internal::FreeSecCategories(SecCat_LL** categories)
{
	SecCat_LL *pTemp, *pNext;

	if ((categories == NULL) || (*categories == NULL))
		return;

	pTemp = *categories;
	while (pTemp != NULL)
	{
		if (pTemp->oid != NULL)
		{
			free(pTemp->oid);
			pTemp->oid = NULL;
		}

		if (pTemp->type == SecCat_LL::PRBAC_TYPE)
		{
			freeSsl(&pTemp->value.prbac);
		}
		else
		{
			if (pTemp->value.other != NULL)
			{
				Internal::FreeBytes(pTemp->value.other);
				pTemp->value.other = NULL;
			}
		}

		pNext = pTemp->next;
		pTemp->next = NULL;
		free(pTemp);
		pTemp = pNext;
	}

	*categories = NULL;
	return;
} // end of Internal::FreeSecCategories()


void Internal::FreeSectags(Sec_tags** secTags)
{
	Sec_tags *atList, *nList;

	if (secTags == NULL)
	   return;

	atList = *secTags;
	while (atList != NULL)
	{
		if ((atList->tagType == 1) || (atList->tagType == 6))
			Internal::FreeBytes(atList->values.bitFlags);
		else
			freeLongArray(&atList->values.intFlags);
		atList->values.bitFlags = NULL;

		nList = atList->next;
		free(atList);
		atList = nList;
	}

	*secTags = NULL;
	return;
} // end of Internal::FreeSectags()


void Internal::FreeStatusRef(StatusReferral_LL* status_ref)
{
	while (status_ref != NULL)
	{
		if (status_ref->flag == CM_CRL_REFERRAL)
		{
			FreeCrlReferral(status_ref->ref.crl);
			status_ref->ref.crl = NULL;
		}
		else if (status_ref->flag == CM_OTHER_REFERRAL)
		{
			freeAny(status_ref->ref.other);
			status_ref->ref.other = NULL;
		}
		StatusReferral_LL* next = status_ref->next;
		status_ref->next = NULL;
		free(status_ref);
		
		status_ref = next;
	}
} // end of Internal::FreeStatusRef()


void Internal::FreeSubtrees(Subtree_struct** subtree)
{
	while (*subtree != NULL)
	{
		FreeGenNameContent(&(*subtree)->base);

		Subtree_struct* next = (*subtree)->next;
		(*subtree)->next = NULL;
		free(*subtree);

		*subtree = next;
	}
}


void Internal::FreeUnknExtn(Unkn_extn_LL **unkn)
{
    Unkn_extn_LL *temp;

    while (*unkn != NULL)
    {
        free((*unkn)->oid);
        (*unkn)->oid = NULL;
        FreeBytes((*unkn)->value);
        (*unkn)->value = NULL;
        temp = (*unkn)->next;
        (*unkn)->next = NULL;
        free(*unkn);
        *unkn = temp;
    }
    return;
} // end of Internal::FreeUnknExtn()


/* ---------------------- */
/* Internal Free Routines */
/* ---------------------- */
static void freeAny(Any_struct *any)
{
    if (any == NULL)
        return;
    free(any->oid);
    Internal::FreeBytes(any->data);
    any->data = NULL;
    free(any);

} /* end of freeAny() */


static void freeBaseRevocationInfo(CM_BaseRevocationInfo *pRevInfo)
{
	if (pRevInfo == NULL)
		return;

	if (pRevInfo->crlStreamID != NULL)
	{
		Internal::FreeBytes(pRevInfo->crlStreamID);
		pRevInfo->crlStreamID = NULL;
	}

	CMASN_FreeBytesContents(&pRevInfo->crlNum);
	return;
} /* end of freeBaseRevocationInfo() */


static void freeDeltaInfo(DeltaInfo *deltaInfo)
{
	if (deltaInfo == NULL)
		return;

	Internal::FreeGenNameContent(&deltaInfo->deltaLoc);

	if (deltaInfo->issueDate != NULL)
	{
		free(deltaInfo->issueDate);
		deltaInfo->issueDate = NULL;
	}

	free(deltaInfo);

} /* end of freeDeltaInfo() */


static void freeDistPtNameContent(Dist_pt_name *dpName)
{
	if (dpName == NULL)
		return;

	switch (dpName->flag)
	{
	case CM_DIST_PT_FULL_NAME:
		Internal::FreeGenNames(dpName->name.full);
		break;
	case CM_DIST_PT_RELATIVE_NAME:
		if (dpName->name.relative != NULL)
		{
			free(dpName->name.relative);
			dpName->name.relative = NULL;
		}
		break;
		
	case CM_NOT_PRESENT:
	default:
		dpName->name.full = NULL;
	}
} /* end of freeDistPtNameContent() */


static void freeIssuingDistPt(Iss_pts_struct *pDistPt)
{
	if (pDistPt == NULL)
		return;

	freeDistPtNameContent(&pDistPt->dpName);

	if (pDistPt->reasons != NULL)
	{
		free(pDistPt->reasons);
		pDistPt->reasons = NULL;
	}

	free(pDistPt);
	return;

} /* end of freeIssuingDistPt() */


static void freeLongArray(LongArray **pArray)
{
	if ((pArray == NULL) || (*pArray == NULL))
		return;

	if ((*pArray)->array != NULL)
	{
		free((*pArray)->array);
		(*pArray)->array = NULL;
	}
	(*pArray)->num = 0;

	free(*pArray);
	*pArray = NULL;
} /* end of freeLongArray() */


static void freeMosaicKey(Mosaic_key_struct *combo)
{
    if (combo == NULL)
        return;
    CMASN_FreeBytesContents(&combo->dsa_y);
    CMASN_FreeBytesContents(&combo->kea_y);
    CMASN_FreeBytesContents(&combo->dsa_privs);
    CMASN_FreeBytesContents(&combo->kea_privs);
    CMASN_FreeBytesContents(&combo->kea_clearance);
	Internal::FreePQGs(combo->diff_kea);
    combo->diff_kea = NULL;
    free(combo);
    return;
} /* end of freeMosaicKey() */


static void freeNumberRange(CM_NumberRange* pRange)
{
	if (pRange == NULL)
		return;

	if (pRange->startingNum != NULL)
	{
		Internal::FreeBytes(pRange->startingNum);
		pRange->startingNum = NULL;
	}

	if (pRange->endingNum != NULL)
	{
		Internal::FreeBytes(pRange->endingNum);
		pRange->endingNum = NULL;
	}

	if (pRange->modulus != NULL)
	{
		Internal::FreeBytes(pRange->modulus);
		pRange->modulus = NULL;
	}

	return;
} /* end of freeNumberRange() */


static void freePriv_flags(Priv_flags **priv_flags)
{
	if ((priv_flags == NULL) || (*priv_flags == NULL))
		return;

	freeLongArray(&(*priv_flags)->privs);

	free(*priv_flags);
	*priv_flags = NULL;
	return;
} /* end of freePriv_flags */


void freeSigStructContents(Sig_struct& sig)
{
	if (sig.alg != NULL)
	{
		if ((strcmp(sig.alg, gRSA_MD2_OID) == 0) ||
			(strcmp(sig.alg, gRSA_MD4_OID) == 0) ||
			(strcmp(sig.alg, gRSA_MD5_OID) == 0) ||
			(strcmp(sig.alg, gRSA_SHA1_OID) == 0))
		{
			if (sig.value.rsa != NULL)
			{
				Internal::FreeBytes(sig.value.rsa);
				sig.value.rsa = NULL;
			}
		}
		else if ((strcmp(sig.alg, gDSA_SHA1_OID) == 0) ||
			(strcmp(sig.alg, gECDSA_SHA1_OID) == 0) ||
			(strcmp(sig.alg, gECDSA_SHA256_OID) == 0) ||
			(strcmp(sig.alg, gECDSA_SHA384_OID) == 0) ||
			(strcmp(sig.alg, gMOSAIC_DSA_OID) == 0))
		{
			if (sig.value.dsa != NULL)
			{
				CMASN_FreeBytesContents(&sig.value.dsa->r);
				CMASN_FreeBytesContents(&sig.value.dsa->s);
				free(sig.value.dsa);
				sig.value.dsa = NULL;
			}
		}
		else if (sig.value.encoded != NULL)
		{
			Internal::FreeBytes(sig.value.encoded);
			sig.value.encoded = NULL;
		}
		free(sig.alg);
		sig.alg = NULL;
	}
} // end of freeSigStructContents()


static void freeSsl(Ssl_privs **Sslprivs)
{
	Ssl_privs *atList, *nList;
	if (Sslprivs == NULL)
	   return;
	if (*Sslprivs == NULL)
	   return;
	atList = *Sslprivs;
	nList = atList->next;
	while(atList != NULL)
	{
		if (atList->tagSetPrivs)
			Internal::FreeSectags(&atList->tagSetPrivs);
		if (atList->tagSetName)
			free(atList->tagSetName);
		nList = atList->next;
		free(atList);
		atList = nList;
	}
	*Sslprivs = NULL;
	return;
} /* end of freeSsl() */


// end of CM_Free.cpp
