/*****************************************************************************
File:	  CM_Extensions.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the Extensions class, Extension base class, and
		  the classes derived from the Extension class.

Created:  19 July 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>
  
Last Updated:	17 March 2004
	
Version:  2.4
	  
*****************************************************************************/


////////////////////
// Included Files //
////////////////////
#ifdef _MSC_VER
	#pragma warning(disable: 4702)		// Disable unreachable code warning
	#pragma warning(disable: 4710)		// Disable function not inlined warning
	#pragma warning(disable: 4786)		// Disable symbols truncated warning
	#pragma warning(push, 3)			// Save warning level and set level to 3
	#include <map>
	#pragma warning(pop)				// Restore warning level
	#pragma warning(disable: 4018 4146)
#else
	#include <map>
#endif
#include "cmlasn_internal.h"



// Using declarations
using namespace CML::ASN;


//////////////////////
// Type Definitions //
//////////////////////
typedef std::map<int, const Extension*> ExtensionPtrMap;



/////////////////////////
// Function Prototypes //
/////////////////////////
static void buildExtMap(ExtensionPtrMap& map, const CertExtensions& exts);
static void buildExtMap(ExtensionPtrMap& map, const CrlExtensions& exts);
static void buildExtMap(ExtensionPtrMap& map, const CrlEntryExtensions& exts);
static void buildExtMap(ExtensionPtrMap& map, const ACExtensions& exts);
static void* cvt_AsnBitMask(const SNACC::AsnBits& asn,
							size_t cmSize = sizeof(ushort));
static CM_BaseRevocationInfo* cvtBaseRevocationInfo(const SNACC::BaseRevocationInfo& snacc);
static CRL_referral* cvtCrlReferralStruct(const SNACC::CRLReferral& snacc);
static DeltaInfo* cvtDeltaRefInfo(const SNACC::DeltaRefInfo& snacc);
static char* cvtDisplayText(const SNACC::DisplayText& asnText);
static CM_NumberRange* cvtNumberRange(const SNACC::NumberRange& snacc);
static Bytes_struct* cvtIntsToBytes(const SNACC::AsnInt& asnInt);
static void cvtIntToExistingBytes(Bytes_struct& bytes, const SNACC::AsnInt& asnInt);
static PerAuthScope_LL* cvtPerAuthScopeList(const SNACC::CRLScopeSyntax& snacc);
static Priv_flags* cvtPrivFlagsStruct(const SNACC::PrivilegeFlags& snacc);
static CMUserNotice* cvtQualifierToUserNotice(const SNACC::UserNotice& snacc);
static bool dupExtsExist(const UnknownExtensions& unkExts);
static bool checkEmailConstraint(const char *name, const char *constraint, long min, long max);



/////////////////////////////////////////
// CertExtensions class implementation //
/////////////////////////////////////////
CertExtensions::CertExtensions()
{
	// Initialize members
	pSubjKeyID = NULL;
	pAuthKeyID = NULL;
	pKeyUsage = NULL;
	pExtKeyUsage = NULL;
	pPrivKeyPeriod = NULL;
	pSubjAltNames = NULL;
	pIssuerAltNames = NULL;
	pCertPolicies = NULL;
	pPolicyMaps = NULL;
	pBasicCons = NULL;
	pNameCons = NULL;
	pPolicyCons = NULL;
	pInhibitAnyPolicy = NULL;
	pCrlDistPts = NULL;
	pFreshestCRL = NULL;
	pSubjDirAtts = NULL;
	pAuthInfoAccess = NULL;
	pSubjInfoAccess = NULL;
	
	m_extsPresent = false;
}


CertExtensions::CertExtensions(const SNACC::Extensions& snacc)
{
	// Initialize members
	pSubjKeyID = NULL;
	pAuthKeyID = NULL;
	pKeyUsage = NULL;
	pExtKeyUsage = NULL;
	pPrivKeyPeriod = NULL;
	pSubjAltNames = NULL;
	pIssuerAltNames = NULL;
	pCertPolicies = NULL;
	pPolicyMaps = NULL;
	pBasicCons = NULL;
	pNameCons = NULL;
	pPolicyCons = NULL;
	pInhibitAnyPolicy = NULL;
	pCrlDistPts = NULL;
	pFreshestCRL = NULL;
	pSubjDirAtts = NULL;
	pAuthInfoAccess = NULL;
	pSubjInfoAccess = NULL;
	
	operator=(snacc);
}


CertExtensions::CertExtensions(const CertExtensions& that)
{
	// Initialize members
	pSubjKeyID = NULL;
	pAuthKeyID = NULL;
	pKeyUsage = NULL;
	pExtKeyUsage = NULL;
	pPrivKeyPeriod = NULL;
	pSubjAltNames = NULL;
	pIssuerAltNames = NULL;
	pCertPolicies = NULL;
	pPolicyMaps = NULL;
	pBasicCons = NULL;
	pNameCons = NULL;
	pPolicyCons = NULL;
	pInhibitAnyPolicy = NULL;
	pCrlDistPts = NULL;
	pFreshestCRL = NULL;
	pSubjDirAtts = NULL;
	pAuthInfoAccess = NULL;
	pSubjInfoAccess = NULL;
	
	operator=(that);
}


CertExtensions& CertExtensions::operator=(const SNACC::Extensions& snacc)
{
	try {
		Clear();
		
		int unkAny = 0;
		SNACC::Extensions::const_iterator i;
		for (i = snacc.begin(); i != snacc.end(); ++i)
		{
			if (i->extnValue.ai == NULL)
			{
				if (i->extnValue.anyBuf == NULL)
					throw ASN_EXCEPTION("SNACC::Extension::extnValue is NULL");
			
				if (unknownExts.IsPresent(i->extnId))
					throw ASN_EXCEPTION("Duplicate extension found");
				
				// Add the unknown extension to the list and add an identifier
				// to the original order list
				unknownExts.push_back(*i);
				m_origOrder.push_back(--unkAny);
			}
			else  // Known, decoded extension
			{
				if (i->extnValue.value == NULL)
					throw ASN_EXCEPTION("SNACC::Extension::extnValue is NULL");
			
				int tempAnyId = i->extnValue.ai->anyId;
				switch (tempAnyId)
				{
				case SNACC::subjectKeyIdentifier_ANY_ID:
					if (pSubjKeyID != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pSubjKeyID = new SubjKeyIdExtension(*(SNACC::SubjectKeyIdentifier*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::authorityKeyIdentifier_ANY_ID:
					if (pAuthKeyID != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pAuthKeyID = new AuthKeyIdExtension(*(SNACC::AuthorityKeyIdentifier*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::keyUsage_ANY_ID:
					if (pKeyUsage != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pKeyUsage = new KeyUsageExtension(*(SNACC::KeyUsage*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::extKeyUsage_ANY_ID:
					if (pExtKeyUsage != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pExtKeyUsage = new ExtKeyUsageExtension(*(SNACC::ExtKeyUsage*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::privateKeyUsagePeriod_ANY_ID:
					if (pPrivKeyPeriod != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pPrivKeyPeriod = new PrivKeyUsagePeriodExtension(*(SNACC::PrivateKeyUsagePeriod*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::subjectAltName_ANY_ID:
					if (pSubjAltNames != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pSubjAltNames = new SubjAltNamesExtension(*(SNACC::GeneralNames*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::issuerAltName_ANY_ID:
					if (pIssuerAltNames != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pIssuerAltNames = new IssuerAltNamesExtension(*(SNACC::GeneralNames*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::certificatePolicies_ANY_ID:
					if (pCertPolicies != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pCertPolicies = new CertPoliciesExtension(*(SNACC::CertificatePoliciesSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::policyMappings_ANY_ID:
					if (pPolicyMaps != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pPolicyMaps = new PolicyMappingsExtension(*(SNACC::PolicyMappingsSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::basicConstraints_ANY_ID:
					if (pBasicCons != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pBasicCons = new BasicConstraintsExtension(*(SNACC::BasicConstraintsSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::nameConstraints_ANY_ID:    // change ANY_ID to new version
					tempAnyId = SNACC::nameConstraint_ANY_ID;
				case SNACC::nameConstraint_ANY_ID:	   // new version
					if (pNameCons != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pNameCons = new NameConstraintsExtension(i->extnId,
						*(SNACC::NameConstraintsSyntax*)i->extnValue.value,
						i->critical);
					break;
				case SNACC::policyConstraints_ANY_ID:
					if (pPolicyCons != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pPolicyCons = new PolicyConstraintsExtension(*(SNACC::PolicyConstraintsSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::inhibitAnyPolicy_ANY_ID:
					if (pInhibitAnyPolicy != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pInhibitAnyPolicy = new InhibitAnyPolicyExtension(*(SNACC::SkipCerts*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::cRLDistributionPoints_ANY_ID:
					if (pCrlDistPts != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pCrlDistPts = new CrlDistPointsExtension(*(SNACC::CRLDistPointsSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::freshestCRL_ANY_ID:
					if (pFreshestCRL != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pFreshestCRL = new FreshestCrlExtension(*(SNACC::CRLDistPointsSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::subjectDirectoryAttributes_ANY_ID:
					if (pSubjDirAtts != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pSubjDirAtts = new SubjDirAttributesExtension(*(SNACC::AttributesSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::authorityInfoAccess_ANY_ID:
					if (pAuthInfoAccess != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pAuthInfoAccess = new PkixAIAExtension(*(SNACC::AuthorityInfoAccessSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::subjectInfoAccess_ANY_ID:
					if (pSubjInfoAccess != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pSubjInfoAccess = new PkixSIAExtension(*(SNACC::SubjectInfoAccessSyntax*)
						i->extnValue.value, i->critical);
					break;
					
					// Invalid certificate extensions
				case SNACC::issuingDistributionPoint_ANY_ID:
				case SNACC::cRLNumber_ANY_ID:
				case SNACC::reasonCode_ANY_ID:
				case SNACC::holdInstructionCode_ANY_ID:
				case SNACC::invalidityDate_ANY_ID:
				case SNACC::crlScope_ANY_ID:
				case SNACC::statusReferrals_ANY_ID:
				case SNACC::cRLStreamIdentifier_ANY_ID:
				case SNACC::orderedList_ANY_ID:
				case SNACC::deltaInfo_ANY_ID:
				case SNACC::certificateIssuer_ANY_ID:
				case SNACC::deltaCRLIndicator_ANY_ID:
				case SNACC::baseUpdateTime_ANY_ID:
					throw ASN_EXCEPTION("Invalid certificate extension");
					
				default:
					if (unknownExts.IsPresent(i->extnId))
						throw ASN_EXCEPTION("Duplicate extension found");
					
					// Add the unknown extension to the list
					unknownExts.push_back(*i);
					
					// Set the anyID to a negative value to indicate unknown
					tempAnyId = --unkAny;
					break;
			}
			
			// Add this extension's anyID to the original order list
			m_origOrder.push_back(tempAnyId);
			
		 } // end of else
	  } // end of for each extension loop
	  
	  return *this;
   }
   catch (...) {
	   Clear();
	   throw;
   }
} // end of CertExtensions::operator=()


CertExtensions& CertExtensions::operator=(const CertExtensions& other)
{
	if (this != &other)
	{
		if (dupExtsExist(other.unknownExts))
			throw ASN_EXCEPTION("Duplicate extension found");
		
		Clear();
		try {
			m_origOrder = other.m_origOrder;
			m_extsPresent = other.m_extsPresent;
			
			if (other.pSubjKeyID != NULL)
			{
				pSubjKeyID = new SubjKeyIdExtension(*other.pSubjKeyID);
				if (pSubjKeyID == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pAuthKeyID != NULL)
			{
				pAuthKeyID = new AuthKeyIdExtension(*other.pAuthKeyID);
				if (pAuthKeyID == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pKeyUsage != NULL)
			{
				pKeyUsage = new KeyUsageExtension(*other.pKeyUsage);
				if (pKeyUsage == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pExtKeyUsage != NULL)
			{
				pExtKeyUsage = new ExtKeyUsageExtension(*other.pExtKeyUsage);
				if (pExtKeyUsage == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pPrivKeyPeriod != NULL)
			{
				pPrivKeyPeriod = new PrivKeyUsagePeriodExtension(*other.pPrivKeyPeriod);
				if (pPrivKeyPeriod == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pSubjAltNames != NULL)
			{
				pSubjAltNames = new SubjAltNamesExtension(*other.pSubjAltNames);
				if (pSubjAltNames == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pIssuerAltNames != NULL)
			{
				pIssuerAltNames = new IssuerAltNamesExtension(*other.pIssuerAltNames);
				if (pIssuerAltNames == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pCertPolicies != NULL)
			{
				pCertPolicies = new CertPoliciesExtension(*other.pCertPolicies);
				if (pCertPolicies == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pPolicyMaps != NULL)
			{
				pPolicyMaps = new PolicyMappingsExtension(*other.pPolicyMaps);
				if (pPolicyMaps == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pBasicCons != NULL)
			{
				pBasicCons = new BasicConstraintsExtension(*other.pBasicCons);
				if (pBasicCons == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pNameCons != NULL)
			{
				pNameCons = new NameConstraintsExtension(*other.pNameCons);
				if (pNameCons == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pPolicyCons != NULL)
			{
				pPolicyCons = new PolicyConstraintsExtension(*other.pPolicyCons);
				if (pPolicyCons == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pInhibitAnyPolicy != NULL)
			{
				pInhibitAnyPolicy = new InhibitAnyPolicyExtension(*other.pInhibitAnyPolicy);
				if (pInhibitAnyPolicy == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pCrlDistPts != NULL)
			{
				pCrlDistPts = new CrlDistPointsExtension(*other.pCrlDistPts);
				if (pCrlDistPts == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pFreshestCRL != NULL)
			{
				pFreshestCRL = new FreshestCrlExtension(*other.pFreshestCRL);
				if (pFreshestCRL == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pSubjDirAtts != NULL)
			{
				pSubjDirAtts = new SubjDirAttributesExtension(*other.pSubjDirAtts);
				if (pSubjDirAtts == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pAuthInfoAccess != NULL)
			{
				pAuthInfoAccess = new PkixAIAExtension(*other.pAuthInfoAccess);
				if (pAuthInfoAccess == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pSubjInfoAccess != NULL)
			{
				pSubjInfoAccess = new PkixSIAExtension(*other.pSubjInfoAccess);
				if (pSubjInfoAccess == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			unknownExts = other.unknownExts;
	  }
	  catch (...) {
		  Clear();
		  throw;
	  }
   }
   return *this;
}


void CertExtensions::Clear()
{
	m_origOrder.clear();
	m_extsPresent = false;
	
	if (pSubjKeyID != NULL)
	{
		delete pSubjKeyID;
		pSubjKeyID = NULL;
	}
	
	if (pAuthKeyID != NULL)
	{
		delete pAuthKeyID;
		pAuthKeyID = NULL;
	}
	
	if (pKeyUsage != NULL)
	{
		delete pKeyUsage;
		pKeyUsage = NULL;
	}
	
	if (pExtKeyUsage != NULL)
	{
		delete pExtKeyUsage;
		pExtKeyUsage = NULL;
	}
	
	if (pPrivKeyPeriod != NULL)
	{
		delete pPrivKeyPeriod;
		pPrivKeyPeriod = NULL;
	}
	
	if (pSubjAltNames != NULL)
	{
		delete pSubjAltNames;
		pSubjAltNames = NULL;
	}
	
	if (pIssuerAltNames != NULL)
	{
		delete pIssuerAltNames;
		pIssuerAltNames = NULL;
	}
	
	if (pCertPolicies != NULL)
	{
		delete pCertPolicies;
		pCertPolicies = NULL;
	}
	
	if (pPolicyMaps != NULL)
	{
		delete pPolicyMaps;
		pPolicyMaps = NULL;
	}
	
	if (pBasicCons != NULL)
	{
		delete pBasicCons;
		pBasicCons = NULL;
	}
	
	if (pNameCons != NULL)
	{
		delete pNameCons;
		pNameCons = NULL;
	}
	
	if (pPolicyCons != NULL)
	{
		delete pPolicyCons;
		pPolicyCons = NULL;
	}
	
	if (pInhibitAnyPolicy != NULL)
	{
		delete pInhibitAnyPolicy;
		pInhibitAnyPolicy = NULL;
	}
	
	if (pCrlDistPts != NULL)
	{
		delete pCrlDistPts;
		pCrlDistPts = NULL;
	}
	
	if (pFreshestCRL != NULL)
	{
		delete pFreshestCRL;
		pFreshestCRL = NULL;
	}
	
	if (pSubjDirAtts != NULL)
	{
		delete pSubjDirAtts;
		pSubjDirAtts = NULL;
	}
	
	if (pAuthInfoAccess != NULL)
	{
		delete pAuthInfoAccess;
		pAuthInfoAccess = NULL;
	}
	
	if (pSubjInfoAccess != NULL)
	{
		delete pSubjInfoAccess;
		pSubjInfoAccess = NULL;
	}
	
	unknownExts.clear();
}


SNACC::Extensions* CertExtensions::GetSnacc() const
{
	// If none of the extensions are present (and they weren't present in
	// ASN.1), return NULL;
	if (!pSubjKeyID && !pAuthKeyID && !pKeyUsage && !pExtKeyUsage &&
		!pPrivKeyPeriod && !pSubjAltNames && !pIssuerAltNames &&
		!pCertPolicies && !pPolicyMaps && !pBasicCons && !pNameCons &&
		!pPolicyCons && !pInhibitAnyPolicy && !pCrlDistPts &&
		!pFreshestCRL && !pSubjDirAtts && !pAuthInfoAccess &&
		!pSubjInfoAccess && unknownExts.empty() && !m_extsPresent)
		return NULL;
	
	if (dupExtsExist(unknownExts))
		throw ASN_EXCEPTION("Duplicate extension found");
	
	SNACC::Extensions* result = NULL;
	try {
		result = new SNACC::Extensions;
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		// Build a map of the known extensions that are present
		ExtensionPtrMap extMap;
		buildExtMap(extMap, *this);
		
		UnknownExtensions::const_iterator unkExtI = unknownExts.begin();
		
		// Encode any extensions in the same order they were present in the ASN.1
		std::vector<int>::const_iterator i;
		for (i = m_origOrder.begin(); i != m_origOrder.end(); ++i)
		{
			if (*i < 0)    // Unknown extension
			{
				// Check that another unknown extension is present
				if (unkExtI != unknownExts.end())
				{
					// Append a new SNACC extension and fill it with the
					// contents of the next unknown extension
					unkExtI->FillSnaccExtension(*result->append());
					++unkExtI;
				}
			}
			else  // Known extension
			{
				const Extension* pExt;
				switch (*i)
				{
				case SNACC::subjectKeyIdentifier_ANY_ID:
					pExt = pSubjKeyID;
					break;
				case SNACC::authorityKeyIdentifier_ANY_ID:
					pExt = pAuthKeyID;
					break;
				case SNACC::keyUsage_ANY_ID:
					pExt = pKeyUsage;
					break;
				case SNACC::extKeyUsage_ANY_ID:
					pExt = pExtKeyUsage;
					break;
				case SNACC::privateKeyUsagePeriod_ANY_ID:
					pExt = pPrivKeyPeriod;
					break;
				case SNACC::subjectAltName_ANY_ID:
					pExt = pSubjAltNames;
					break;
				case SNACC::issuerAltName_ANY_ID:
					pExt = pIssuerAltNames;
					break;
				case SNACC::certificatePolicies_ANY_ID:
					pExt = pCertPolicies;
					break;
				case SNACC::policyMappings_ANY_ID:
					pExt = pPolicyMaps;
					break;
				case SNACC::basicConstraints_ANY_ID:
					pExt = pBasicCons;
					break;
				case SNACC::nameConstraint_ANY_ID:
					pExt = pNameCons;
					break;
				case SNACC::policyConstraints_ANY_ID:
					pExt = pPolicyCons;
					break;
				case SNACC::inhibitAnyPolicy_ANY_ID:
					pExt = pInhibitAnyPolicy;
					break;
				case SNACC::cRLDistributionPoints_ANY_ID:
					pExt = pCrlDistPts;
					break;
				case SNACC::freshestCRL_ANY_ID:
					pExt = pFreshestCRL;
					break;
				case SNACC::subjectDirectoryAttributes_ANY_ID:
					pExt = pSubjDirAtts;
					break;
				case SNACC::authorityInfoAccess_ANY_ID:
					pExt = pAuthInfoAccess;
					break;
				case SNACC::subjectInfoAccess_ANY_ID:
					pExt = pSubjInfoAccess;
					break;
				default:
					pExt = NULL;
				}
				
				if (pExt != NULL) // If the extension is still present
				{
					// Append a new SNACC extension and fill it with the
					// contents of this extension
					pExt->FillSnaccExtension(*result->append());
					
					// Remove it from the map
					extMap.erase(*i);
				}
				
			} // end of else
		} // end of for loop
		
		// Encode any remaining known extensions
		ExtensionPtrMap::iterator mapI;
		for (mapI = extMap.begin(); mapI != extMap.end(); ++mapI)
		{
			// Append a new SNACC extension and fill it with the
			// contents of the extension
			mapI->second->FillSnaccExtension(*result->append());
		}
		
		// Encode any remaining unknown extensions
		for ( ; unkExtI != unknownExts.end(); ++unkExtI)
		{
			// Append a new SNACC extension and fill it with the
			// contents of this unknown extension
			unkExtI->FillSnaccExtension(*result->append());
		}
		
		return result;
   }
   catch (...) {
	   delete result;
	   throw;
   }
}


// Get the C form of these cert extensions
Cert_exts_struct* CertExtensions::GetCertExtsStruct() const
{
	// If none of the extensions are present, return NULL;
	if (!pSubjKeyID && !pAuthKeyID && !pKeyUsage && !pExtKeyUsage &&
		!pPrivKeyPeriod && !pSubjAltNames && !pIssuerAltNames &&
		!pCertPolicies && !pPolicyMaps && !pBasicCons && !pNameCons &&
		!pPolicyCons && !pInhibitAnyPolicy && !pCrlDistPts && !pFreshestCRL &&
		!pSubjDirAtts && !pAuthInfoAccess && !pSubjInfoAccess &&
		unknownExts.empty())
		return NULL;
	
	Cert_exts_struct* pExts = (Cert_exts_struct*)
		calloc(1, sizeof(Cert_exts_struct));
	if (pExts == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (pSubjKeyID != NULL)
			pExts->subjKeyID = pSubjKeyID->GetExtensionStruct();
		
		if (pAuthKeyID != NULL)
			pExts->authKeyID = pAuthKeyID->GetExtensionStruct();
		
		if (pKeyUsage != NULL)
			pExts->keyUsage = pKeyUsage->GetExtensionStruct();
		
		if (pExtKeyUsage != NULL)
			pExts->extKeyUse = pExtKeyUsage->GetExtensionStruct();
		
		if (pPrivKeyPeriod != NULL)
			pExts->privKeyVal = pPrivKeyPeriod->GetExtensionStruct();
		
		if (pSubjAltNames != NULL)
			pExts->subjAltName = pSubjAltNames->GetExtensionStruct();
		
		if (pIssuerAltNames != NULL)
			pExts->issuerAltName = pIssuerAltNames->GetExtensionStruct();
		
		if (pCertPolicies != NULL)
			pExts->certPolicies = pCertPolicies->GetExtensionStruct();
		
		if (pPolicyMaps != NULL)
			pExts->policyMaps = pPolicyMaps->GetExtensionStruct();
		
		if (pBasicCons != NULL)
			pExts->basicCons = pBasicCons->GetExtensionStruct();
		
		if (pNameCons != NULL)
			pExts->nameCons = pNameCons->GetExtensionStruct();
		
		if (pPolicyCons != NULL)
			pExts->policyCons = pPolicyCons->GetExtensionStruct();
		
		if (pInhibitAnyPolicy != NULL)
			pExts->inhibitAnyPol = pInhibitAnyPolicy->GetExtensionStruct();
		
		if (pCrlDistPts != NULL)
			pExts->distPts = pCrlDistPts->GetExtensionStruct();
		
		if (pFreshestCRL != NULL)
			pExts->freshCRL = pFreshestCRL->GetExtensionStruct();
		
		if (pSubjDirAtts != NULL)
			pExts->subjDirAtts = pSubjDirAtts->GetExtensionStruct();
		
		if (pAuthInfoAccess != NULL)
			pExts->aia = pAuthInfoAccess->GetExtensionStruct();
		
		if (pSubjInfoAccess != NULL)
			pExts->sia = pSubjInfoAccess->GetExtensionStruct();
		
		pExts->unknown = unknownExts.GetUnknownExts();
		
		return pExts;
	}
	catch (...) {
		Internal::FreeCertExtensions(pExts);
		throw;
	}
}


////////////////////////////////////////
// CrlExtensions class implementation //
////////////////////////////////////////
CrlExtensions::CrlExtensions()
{
	// Initialize members
	pAuthKeyID = NULL;
	pIssuerAltNames = NULL;
	pIssuingDP = NULL;
	pFreshestCRL = NULL;
	pCrlNumber = NULL;
	pDeltaCRL = NULL;
	pCrlScope = NULL;
	pStatusRefs = NULL;
	pStreamID = NULL;
	pOrderedList = NULL;
	pDeltaInfo = NULL;
	pBaseUpdate = NULL;
	
	m_extsPresent = false;
}


CrlExtensions::CrlExtensions(const SNACC::Extensions& snacc)
{
	// Initialize members
	pAuthKeyID = NULL;
	pIssuerAltNames = NULL;
	pIssuingDP = NULL;
	pFreshestCRL = NULL;
	pCrlNumber = NULL;
	pDeltaCRL = NULL;
	pCrlScope = NULL;
	pStatusRefs = NULL;
	pStreamID = NULL;
	pOrderedList = NULL;
	pDeltaInfo = NULL;
	pBaseUpdate = NULL;
	
	operator=(snacc);
}


CrlExtensions::CrlExtensions(const CrlExtensions& that)
{
	// Initialize members
	pAuthKeyID = NULL;
	pIssuerAltNames = NULL;
	pIssuingDP = NULL;
	pFreshestCRL = NULL;
	pCrlNumber = NULL;
	pDeltaCRL = NULL;
	pCrlScope = NULL;
	pStatusRefs = NULL;
	pStreamID = NULL;
	pOrderedList = NULL;
	pDeltaInfo = NULL;
	pBaseUpdate = NULL;
	
	operator=(that);
}


CrlExtensions& CrlExtensions::operator=(const SNACC::Extensions& snacc)
{
	try {
		Clear();
		
		int unkAny = 0;
		SNACC::Extensions::const_iterator i;
		for (i = snacc.begin(); i != snacc.end(); ++i)
		{
			if (i->extnValue.ai == NULL)
			{
				if (i->extnValue.anyBuf == NULL)
					throw ASN_EXCEPTION("SNACC::Extension::extnValue is NULL");
				
				if (unknownExts.IsPresent(i->extnId))
					throw ASN_EXCEPTION("Duplicate extension found");
				
				// Add the unknown extension to the list and add an identifier
				// to the original order list
				unknownExts.push_back(*i);
				m_origOrder.push_back(--unkAny);
			}
			else  // Known, decoded extension
			{
				if (i->extnValue.value == NULL)
					throw ASN_EXCEPTION("SNACC::Extension::extnValue is NULL");
			
				int tempAnyId = i->extnValue.ai->anyId;
				switch (tempAnyId)
				{
				case SNACC::authorityKeyIdentifier_ANY_ID:
					if (pAuthKeyID != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pAuthKeyID = new AuthKeyIdExtension(*(SNACC::AuthorityKeyIdentifier*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::issuerAltName_ANY_ID:
					if (pIssuerAltNames != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pIssuerAltNames = new IssuerAltNamesExtension(*(SNACC::GeneralNames*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::issuingDistributionPoint_ANY_ID:
					if (pIssuingDP != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pIssuingDP = new IssuingDistPointExtension(*(SNACC::IssuingDistPointSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::freshestCRL_ANY_ID:
					if (pFreshestCRL != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pFreshestCRL = new FreshestCrlExtension(*(SNACC::CRLDistPointsSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::cRLNumber_ANY_ID:
					if (pCrlNumber != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pCrlNumber = new CRLNumberExtension(*(SNACC::CRLNumber*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::deltaCRLIndicator_ANY_ID:
					if (pDeltaCRL != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pDeltaCRL = new DeltaCRLIndicatorExtension(*(SNACC::BaseCRLNumber*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::crlScope_ANY_ID:
					if (pCrlScope != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pCrlScope = new StdExtension_T<SNACC::CRLScopeSyntax>(*(SNACC::CRLScopeSyntax*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::statusReferrals_ANY_ID:
					if (pStatusRefs != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pStatusRefs = new StdExtension_T<SNACC::StatusReferrals>(*(SNACC::StatusReferrals*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::cRLStreamIdentifier_ANY_ID:
					if (pStreamID != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pStreamID = new StdExtension_T<SNACC::CRLStreamIdentifier>(*(SNACC::CRLStreamIdentifier*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::orderedList_ANY_ID:
					if (pOrderedList != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pOrderedList = new StdExtension_T<SNACC::OrderedListSyntax>(*(SNACC::OrderedListSyntax*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::deltaInfo_ANY_ID:
					if (pDeltaInfo != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pDeltaInfo = new StdExtension_T<SNACC::DeltaInformation>(*(SNACC::DeltaInformation*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::baseUpdateTime_ANY_ID:
					if (pBaseUpdate != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pBaseUpdate = new StdExtension_T<SNACC::GeneralizedTime>(*(SNACC::GeneralizedTime*)
						i->extnValue.value, i->extnId, i->critical);
					break;
					
					// Invalid certificate extensions
				case SNACC::subjectKeyIdentifier_ANY_ID:
				case SNACC::keyUsage_ANY_ID:
				case SNACC::extKeyUsage_ANY_ID:
				case SNACC::privateKeyUsagePeriod_ANY_ID:
				case SNACC::subjectAltName_ANY_ID:
				case SNACC::certificatePolicies_ANY_ID:
				case SNACC::policyMappings_ANY_ID:
				case SNACC::basicConstraints_ANY_ID:
				case SNACC::nameConstraints_ANY_ID:
				case SNACC::policyConstraints_ANY_ID:
				case SNACC::inhibitAnyPolicy_ANY_ID:
				case SNACC::cRLDistributionPoints_ANY_ID:
				case SNACC::subjectDirectoryAttributes_ANY_ID:
				case SNACC::authorityInfoAccess_ANY_ID:
				case SNACC::subjectInfoAccess_ANY_ID:
				case SNACC::reasonCode_ANY_ID:
				case SNACC::holdInstructionCode_ANY_ID:
				case SNACC::invalidityDate_ANY_ID:
				case SNACC::certificateIssuer_ANY_ID:
					throw ASN_EXCEPTION("Invalid CRL extension");
					
				default:
					if (unknownExts.IsPresent(i->extnId))
						throw ASN_EXCEPTION("Duplicate extension found");
					
					// Add the unknown extension to the list
					unknownExts.push_back(*i);
					
					// Set the anyID to a negative value to indicate unknown
					tempAnyId = --unkAny;
					break;
			}
			
			// Add this extension's anyID to the original order list
			m_origOrder.push_back(tempAnyId);
			
		 } // end of else
	  } // end of for each extension loop
	  
	  return *this;
   }
   catch (...) {
	   Clear();
	   throw;
   }
} // end of CrlExtensions::operator=()


CrlExtensions& CrlExtensions::operator=(const CrlExtensions& other)
{
	if (this != &other)
	{
		if (dupExtsExist(other.unknownExts))
			throw ASN_EXCEPTION("Duplicate extension found");
		
		Clear();
		try {
			m_origOrder = other.m_origOrder;
			m_extsPresent = other.m_extsPresent;
			
			if (other.pAuthKeyID != NULL)
			{
				pAuthKeyID = new AuthKeyIdExtension(*other.pAuthKeyID);
				if (pAuthKeyID == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pIssuerAltNames != NULL)
			{
				pIssuerAltNames = new IssuerAltNamesExtension(*other.pIssuerAltNames);
				if (pIssuerAltNames == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pIssuingDP != NULL)
			{
				pIssuingDP = new IssuingDistPointExtension(*other.pIssuingDP);
				if (pIssuingDP == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pFreshestCRL != NULL)
			{
				pFreshestCRL = new FreshestCrlExtension(*other.pFreshestCRL);
				if (pFreshestCRL == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pCrlNumber != NULL)
			{
				pCrlNumber = new CRLNumberExtension(*other.pCrlNumber);
				if (pCrlNumber == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pDeltaCRL != NULL)
			{
				pDeltaCRL = new DeltaCRLIndicatorExtension(*other.pDeltaCRL);
				if (pDeltaCRL == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pCrlScope != NULL)
			{
				pCrlScope = new StdExtension_T<SNACC::CRLScopeSyntax>(*other.pCrlScope);
				if (pCrlScope == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pStatusRefs != NULL)
			{
				pStatusRefs = new StdExtension_T<SNACC::StatusReferrals>(*other.pStatusRefs);
				if (pStatusRefs == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pStreamID != NULL)
			{
				pStreamID = new StdExtension_T<SNACC::CRLStreamIdentifier>(*other.pStreamID);
				if (pStreamID == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pOrderedList != NULL)
			{
				pOrderedList = new StdExtension_T<SNACC::OrderedListSyntax>(*other.pOrderedList);
				if (pOrderedList == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pDeltaInfo != NULL)
			{
				pDeltaInfo = new StdExtension_T<SNACC::DeltaInformation>(*other.pDeltaInfo);
				if (pDeltaInfo == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pBaseUpdate != NULL)
			{
				pBaseUpdate = new StdExtension_T<SNACC::GeneralizedTime>(*other.pBaseUpdate);
				if (pBaseUpdate == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			unknownExts = other.unknownExts;
		}
		catch (...) {
			Clear();
			throw;
		}
	}
	return *this;
}


void CrlExtensions::Clear()
{
	m_origOrder.clear();
	m_extsPresent = false;
	
	if (pAuthKeyID != NULL)
	{
		delete pAuthKeyID;
		pAuthKeyID = NULL;
	}
	
	if (pIssuerAltNames != NULL)
	{
		delete pIssuerAltNames;
		pIssuerAltNames = NULL;
	}
	
	if (pIssuingDP != NULL)
	{
		delete pIssuingDP;
		pIssuingDP = NULL;
	}
	
	if (pFreshestCRL != NULL)
	{
		delete pFreshestCRL;
		pFreshestCRL = NULL;
	}
	
	if (pCrlNumber != NULL)
	{
		delete pCrlNumber;
		pCrlNumber = NULL;
	}
	
	if (pDeltaCRL != NULL)
	{
		delete pDeltaCRL;
		pDeltaCRL = NULL;
	}
	
	if (pCrlScope != NULL)
	{
		delete pCrlScope;
		pCrlScope = NULL;
	}
	
	if (pStatusRefs != NULL)
	{
		delete pStatusRefs;
		pStatusRefs = NULL;
	}
	
	if (pStreamID != NULL)
	{
		delete pStreamID;
		pStreamID = NULL;
	}
	
	if (pOrderedList != NULL)
	{
		delete pOrderedList;
		pOrderedList = NULL;
	}
	
	if (pDeltaInfo != NULL)
	{
		delete pDeltaInfo;
		pDeltaInfo = NULL;
	}
	
	if (pBaseUpdate != NULL)
	{
		delete pBaseUpdate;
		pBaseUpdate = NULL;
	}
	
	unknownExts.clear();
}


SNACC::Extensions* CrlExtensions::GetSnacc() const
{
	// If none of the extensions are present (and they weren't present in
	// ASN.1), return NULL;
	if (!pAuthKeyID && !pIssuerAltNames && !pIssuingDP && !pFreshestCRL &&
		!pCrlNumber && !pDeltaCRL && !pCrlScope && !pStatusRefs &&
		!pStreamID && !pOrderedList && !pDeltaInfo && !pBaseUpdate &&
		unknownExts.empty() && !m_extsPresent)
		return NULL;
	
	if (dupExtsExist(unknownExts))
		throw ASN_EXCEPTION("Duplicate extension found");
	
	SNACC::Extensions* result = new SNACC::Extensions;
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Build a map of the known extensions that are present
		ExtensionPtrMap extMap;
		buildExtMap(extMap, *this);
		
		UnknownExtensions::const_iterator unkExtI = unknownExts.begin();
		
		// Encode any extensions in the same order they were present in the ASN.1
		std::vector<int>::const_iterator i;
		for (i = m_origOrder.begin(); i != m_origOrder.end(); i++)
		{
			if (*i < 0)    // Unknown extension
			{
				// Check that another unknown extension is present
				if (unkExtI != unknownExts.end())
				{
					// Append a new SNACC extension and fill it with the
					// contents of the next unknown extension
					unkExtI->FillSnaccExtension(*result->append());
					++unkExtI;
				}
			}
			else  // Known extension
			{
				const Extension* pExt;
				switch (*i)
				{
				case SNACC::authorityKeyIdentifier_ANY_ID:
					pExt = pAuthKeyID;
					break;
				case SNACC::issuerAltName_ANY_ID:
					pExt = pIssuerAltNames;
					break;
				case SNACC::issuingDistributionPoint_ANY_ID:
					pExt = pIssuingDP;
					break;
				case SNACC::freshestCRL_ANY_ID:
					pExt = pFreshestCRL;
					break;
				case SNACC::cRLNumber_ANY_ID:
					pExt = pCrlNumber;
					break;
				case SNACC::deltaCRLIndicator_ANY_ID:
					pExt = pDeltaCRL;
					break;
				case SNACC::crlScope_ANY_ID:
					pExt = pCrlScope;
					break;
				case SNACC::statusReferrals_ANY_ID:
					pExt = pStatusRefs;
					break;
				case SNACC::cRLStreamIdentifier_ANY_ID:
					pExt = pStreamID;
					break;
				case SNACC::orderedList_ANY_ID:
					pExt = pOrderedList;
					break;
				case SNACC::deltaInfo_ANY_ID:
					pExt = pDeltaInfo;
					break;
				case SNACC::baseUpdateTime_ANY_ID:
					pExt = pBaseUpdate;
					break;
				default:
					pExt = NULL;
				}
				
				if (pExt != NULL) // If the extension is still present
				{
					// Append a new SNACC extension and fill it with the
					// contents of this extension
					pExt->FillSnaccExtension(*result->append());
					
					// Remove it from the map
					extMap.erase(*i);
				}
				
			} // end of else
		} // end of for loop
		
		// Encode any remaining known extensions
		ExtensionPtrMap::iterator mapI;
		for (mapI = extMap.begin(); mapI != extMap.end(); ++mapI)
		{
			// Append a new SNACC extension and fill it with the contents of
			// this extension
			mapI->second->FillSnaccExtension(*result->append());
		}
		
		// Encode any remaining unknown extensions
		for ( ; unkExtI != unknownExts.end(); ++unkExtI)
		{
			// Append a new SNACC extension and fill it with the contents of
			// this unknown extension
			unkExtI->FillSnaccExtension(*result->append());
		}
		
		return result;
   }
   catch (...) {
	   delete result;
	   throw;
   }
}


// Get the C form of these CRL extensions
CRL_exts_struct* CrlExtensions::GetCrlExtsStruct() const
{
	// If none of the extensions are present, return NULL;
	if (!pAuthKeyID && !pIssuerAltNames && !pIssuingDP && !pFreshestCRL &&
		!pCrlNumber && !pDeltaCRL && !pCrlScope && !pStatusRefs &&
		!pStreamID && !pOrderedList && !pDeltaInfo && !pBaseUpdate &&
		unknownExts.empty())
		return NULL;
	
	CRL_exts_struct* pExts = (CRL_exts_struct*)
		calloc(1, sizeof(CRL_exts_struct));
	if (pExts == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (pAuthKeyID != NULL)
			pExts->authKeyID = pAuthKeyID->GetExtensionStruct();
		
		if (pIssuerAltNames != NULL)
			pExts->issuerAltName = pIssuerAltNames->GetExtensionStruct();
		
		if (pIssuingDP != NULL)
			pExts->issDistPts = pIssuingDP->GetExtensionStruct();
		
		if (pFreshestCRL != NULL)
			pExts->freshCRL = pFreshestCRL->GetExtensionStruct();
		
		if (pCrlNumber != NULL)
			pExts->crlNum = pCrlNumber->GetExtensionStruct();
		
		if (pDeltaCRL != NULL)
			pExts->deltaCRL = pDeltaCRL->GetExtensionStruct();
		
		if (pCrlScope != NULL)
			pExts->scope = pCrlScope->GetExtensionStruct();
		
		if (pStatusRefs != NULL)
			pExts->statusRef = pStatusRefs->GetExtensionStruct();
		
		if (pStreamID != NULL)
			pExts->streamId = pStreamID->GetExtensionStruct();
		
		if (pOrderedList != NULL)
			pExts->ordered = pOrderedList->GetExtensionStruct();
		
		if (pDeltaInfo != NULL)
			pExts->deltaInfo = pDeltaInfo->GetExtensionStruct();
		
		if (pBaseUpdate != NULL)
			pExts->baseUpdate = pBaseUpdate->GetExtensionStruct();
		
		pExts->unknown = unknownExts.GetUnknownExts();
		
		return pExts;
	}
	catch (...) {
		Internal::FreeCRLExtensions(pExts);
		throw;
	}
} // end of CrlExtensions::GetCrlExtsStruct()


/////////////////////////////////////////////
// CrlEntryExtensions class implementation //
/////////////////////////////////////////////
CrlEntryExtensions::CrlEntryExtensions()
{
	// Initialize members
	pReason = NULL;
	pHoldCode = NULL;
	pInvalidityDate = NULL;
	pCertIssuer = NULL;
	
	m_extsPresent = false;
}


CrlEntryExtensions::CrlEntryExtensions(const SNACC::Extensions& snacc)
{
	// Initialize members
	pReason = NULL;
	pHoldCode = NULL;
	pInvalidityDate = NULL;
	pCertIssuer = NULL;
	
	operator=(snacc);
}


CrlEntryExtensions::CrlEntryExtensions(const CrlEntryExtensions& that)
{
	// Initialize members
	pReason = NULL;
	pHoldCode = NULL;
	pInvalidityDate = NULL;
	pCertIssuer = NULL;
	
	operator=(that);
}


CrlEntryExtensions& CrlEntryExtensions::operator=(const SNACC::Extensions& snacc)
{
	try {
		Clear();
		
		int unkAny = 0;
		SNACC::Extensions::const_iterator i;
		for (i = snacc.begin(); i != snacc.end(); ++i)
		{
			if (i->extnValue.ai == NULL)
			{
				if (i->extnValue.anyBuf == NULL)
					throw ASN_EXCEPTION("SNACC::Extension::extnValue is NULL");

				if (unknownExts.IsPresent(i->extnId))
					throw ASN_EXCEPTION("Duplicate extension found");
					
					// Add the unknown extension to the list and add an identifier
					// to the original order list
					unknownExts.push_back(*i);
					m_origOrder.push_back(--unkAny);
			}
			else  // Known, decoded extension
			{
				if (i->extnValue.value == NULL)
					throw ASN_EXCEPTION("SNACC::Extension::extnValue is NULL");

				int tempAnyId = i->extnValue.ai->anyId;
				switch (tempAnyId)
				{
				case SNACC::reasonCode_ANY_ID:
					if (pReason != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pReason = new StdExtension_T<SNACC::CRLReason>(*(SNACC::CRLReason*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::holdInstructionCode_ANY_ID:
					if (pHoldCode != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pHoldCode = new StdExtension_T<SNACC::HoldInstruction>(*(SNACC::HoldInstruction*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::invalidityDate_ANY_ID:
					if (pInvalidityDate != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pInvalidityDate = new StdExtension_T<SNACC::GeneralizedTime>(*(SNACC::GeneralizedTime*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::certificateIssuer_ANY_ID:
					if (pCertIssuer != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pCertIssuer = new CertIssuerExtension(*(const SNACC::GeneralNames*)
						i->extnValue.value, i->critical);
					break;
					
					// Invalid certificate extensions
				case SNACC::subjectKeyIdentifier_ANY_ID:
				case SNACC::authorityKeyIdentifier_ANY_ID:
				case SNACC::keyUsage_ANY_ID:
				case SNACC::extKeyUsage_ANY_ID:
				case SNACC::privateKeyUsagePeriod_ANY_ID:
				case SNACC::subjectAltName_ANY_ID:
				case SNACC::issuerAltName_ANY_ID:
				case SNACC::certificatePolicies_ANY_ID:
				case SNACC::policyMappings_ANY_ID:
				case SNACC::basicConstraints_ANY_ID:
				case SNACC::nameConstraints_ANY_ID:
				case SNACC::policyConstraints_ANY_ID:
				case SNACC::inhibitAnyPolicy_ANY_ID:
				case SNACC::cRLDistributionPoints_ANY_ID:
				case SNACC::issuingDistributionPoint_ANY_ID:
				case SNACC::freshestCRL_ANY_ID:
				case SNACC::subjectDirectoryAttributes_ANY_ID:
				case SNACC::authorityInfoAccess_ANY_ID:
				case SNACC::subjectInfoAccess_ANY_ID:
				case SNACC::cRLNumber_ANY_ID:
				case SNACC::deltaCRLIndicator_ANY_ID:
				case SNACC::crlScope_ANY_ID:
				case SNACC::statusReferrals_ANY_ID:
				case SNACC::cRLStreamIdentifier_ANY_ID:
				case SNACC::orderedList_ANY_ID:
				case SNACC::deltaInfo_ANY_ID:
				case SNACC::baseUpdateTime_ANY_ID:
					throw ASN_EXCEPTION("Invalid CRL entry extension");
					
				default:
					if (unknownExts.IsPresent(i->extnId))
						throw ASN_EXCEPTION("Duplicate extension found");
					
					// Add the unknown extension to the list
					unknownExts.push_back(*i);
					
					// Set the anyID to a negative value to indicate unknown
					tempAnyId = --unkAny;
					break;
				}
				
				// Add this extension's anyID to the original order list
				m_origOrder.push_back(tempAnyId);
				
			} // end of else
		} // end of for each extension loop
		
		return *this;
   }
   catch (...) {
	   Clear();
	   throw;
   }
} // end of CrlEntryExtensions::operator=()


CrlEntryExtensions& CrlEntryExtensions::operator=(const CrlEntryExtensions& other)
{
	if (this != &other)
	{
		if (dupExtsExist(other.unknownExts))
			throw ASN_EXCEPTION("Duplicate extension found");
		
		Clear();
		try {
			m_origOrder = other.m_origOrder;
			m_extsPresent = other.m_extsPresent;
			
			if (other.pReason != NULL)
			{
				pReason = new StdExtension_T<SNACC::CRLReason>(*other.pReason);
				if (pReason == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pHoldCode != NULL)
			{
				pHoldCode = new StdExtension_T<SNACC::HoldInstruction>(*other.pHoldCode);
				if (pHoldCode == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pInvalidityDate != NULL)
			{
				pInvalidityDate = new StdExtension_T<SNACC::GeneralizedTime>(*other.pInvalidityDate);
				if (pInvalidityDate == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pCertIssuer != NULL)
			{
				pCertIssuer = new CertIssuerExtension(*other.pCertIssuer);
				if (pCertIssuer == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			unknownExts = other.unknownExts;
		}
		catch (...) {
			Clear();
			throw;
		}
	}
	return *this;
}


void CrlEntryExtensions::Clear()
{
	m_origOrder.clear();
	m_extsPresent = false;
	
	if (pReason != NULL)
	{
		delete pReason;
		pReason = NULL;
	}
	
	if (pHoldCode != NULL)
	{
		delete pHoldCode;
		pHoldCode = NULL;
	}
	
	if (pInvalidityDate != NULL)
	{
		delete pInvalidityDate;
		pInvalidityDate = NULL;
	}
	
	if (pCertIssuer != NULL)
	{
		delete pCertIssuer;
		pCertIssuer = NULL;
	}
	
	unknownExts.clear();
}


SNACC::Extensions* CrlEntryExtensions::GetSnacc() const
{
	// If none of the extensions are present (and they weren't present in
	// ASN.1), return NULL;
	if (!pReason && !pHoldCode && !pInvalidityDate && !pCertIssuer &&
		unknownExts.empty() && !m_extsPresent)
		return NULL;
	
	if (dupExtsExist(unknownExts))
		throw ASN_EXCEPTION("Duplicate extension found");
	
	SNACC::Extensions* result = new SNACC::Extensions;
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Build a map of the known extensions that are present
		ExtensionPtrMap extMap;
		buildExtMap(extMap, *this);
		
		UnknownExtensions::const_iterator unkExtI = unknownExts.begin();
		
		// Encode any extensions in the same order they were present in the ASN.1
		std::vector<int>::const_iterator i;
		for (i = m_origOrder.begin(); i != m_origOrder.end(); ++i)
		{
			if (*i < 0)    // Unknown extension
			{
				// Check that another unknown extension is present
				if (unkExtI != unknownExts.end())
				{
					// Append a new SNACC extension and fill it with the
					// contents of the next unknown extension
					unkExtI->FillSnaccExtension(*result->append());
					++unkExtI;
				}
			}
			else  // Known extension
			{
				const Extension* pExt;
				switch (*i)
				{
				case SNACC::reasonCode_ANY_ID:
					pExt = pReason;
					break;
				case SNACC::holdInstructionCode_ANY_ID:
					pExt = pHoldCode;
					break;
				case SNACC::invalidityDate_ANY_ID:
					pExt = pInvalidityDate;
					break;
				case SNACC::certificateIssuer_ANY_ID:
					pExt = pCertIssuer;
					break;
				default:
					pExt = NULL;
				}
				
				if (pExt != NULL) // If the extension is still present
				{
					// Append a new SNACC extension and fill it with the
					// contents of this extension
					pExt->FillSnaccExtension(*result->append());

					// Remove it from the map
					extMap.erase(*i);
				}
				
			} // end of else
		} // end of for loop
		
		// Encode any remaining known extensions
		ExtensionPtrMap::iterator mapI;
		for (mapI = extMap.begin(); mapI != extMap.end(); ++mapI)
		{
			// Append a new SNACC extension and fill it with the contents of
			// this extension
			mapI->second->FillSnaccExtension(*result->append());
		}
		
		// Encode any remaining unknown extensions
		for ( ; unkExtI != unknownExts.end(); ++unkExtI)
		{
			// Append a new SNACC extension and fill it with the contents of
			// this unknown extension
			unkExtI->FillSnaccExtension(*result->append());
		}
		
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


// Get the C form of these CRL entry extensions
CRL_entry_exts_struct* CrlEntryExtensions::GetCrlEntryExtsStruct() const
{
	// If none of the extensions are present, return NULL;
	if (!pReason && !pHoldCode && !pInvalidityDate && !pCertIssuer &&
		unknownExts.empty())
		return NULL;
	
	CRL_entry_exts_struct* pExts = (CRL_entry_exts_struct*)
		calloc(1, sizeof(CRL_entry_exts_struct));
	if (pExts == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (pReason != NULL)
			pExts->reasonCode = pReason->GetExtensionStruct();
		
		if (pHoldCode != NULL)
			pExts->instrCodeOid = pHoldCode->GetExtensionStruct();
		
		if (pInvalidityDate != NULL)
			pExts->invalDate = pInvalidityDate->GetExtensionStruct();
		
		if (pCertIssuer != NULL)
			pExts->certIssuer = pCertIssuer->GetExtensionStruct();
		
		pExts->unknown = unknownExts.GetUnknownExts();
		
		return pExts;
	}
	catch (...) {
		Internal::FreeCRLEntryExtensions(pExts);
		throw;
	}
}


///////////////////////////////////////
// ACExtensions class implementation //
///////////////////////////////////////
ACExtensions::ACExtensions()
{
	// Initialize members
	pAuthKeyID = NULL;
	pTimeSpec = NULL;
	pTargetInfo = NULL;
	pUserNotice = NULL;
	pPrivPolicies = NULL;
	pCrlDistPts = NULL;
	pRevInfoAvail = NULL;
	pSOA_Id = NULL;
	pDescriptor = NULL;
	pRoleSpec = NULL;
	pBasicCons = NULL;
	pNameCons = NULL;
	pCertPolicies = NULL;
	pAA_Id = NULL;
	pAuthInfoAccess = NULL;
	pAuditIdentity = NULL;

	m_extsPresent = false;
}


ACExtensions::ACExtensions(const SNACC::Extensions& snacc)
{
	// Initialize members
	pAuthKeyID = NULL;
	pTimeSpec = NULL;
	pTargetInfo = NULL;
	pUserNotice = NULL;
	pPrivPolicies = NULL;
	pCrlDistPts = NULL;
	pRevInfoAvail = NULL;
	pSOA_Id = NULL;
	pDescriptor = NULL;
	pRoleSpec = NULL;
	pBasicCons = NULL;
	pNameCons = NULL;
	pCertPolicies = NULL;
	pAA_Id = NULL;
	pAuthInfoAccess = NULL;
	pAuditIdentity = NULL;

	operator=(snacc);
}


ACExtensions::ACExtensions(const ACExtensions& that)
{
	// Initialize members
	pAuthKeyID = NULL;
	pTimeSpec = NULL;
	pTargetInfo = NULL;
	pUserNotice = NULL;
	pPrivPolicies = NULL;
	pCrlDistPts = NULL;
	pRevInfoAvail = NULL;
	pSOA_Id = NULL;
	pDescriptor = NULL;
	pRoleSpec = NULL;
	pBasicCons = NULL;
	pNameCons = NULL;
	pCertPolicies = NULL;
	pAA_Id = NULL;
	pAuthInfoAccess = NULL;
	pAuditIdentity = NULL;

	operator=(that);
}


ACExtensions& ACExtensions::operator=(const SNACC::Extensions& snacc)
{
	try {
		Clear();
		
		int unkAny = 0;
		SNACC::Extensions::const_iterator i;
		for (i = snacc.begin(); i != snacc.end(); ++i)
		{
//			const SNACC::AsnAnyDefinedBy& extnValue = snacc.Curr()->extnValue;
			
			if (i->extnValue.ai == NULL)
			{
				if (i->extnValue.anyBuf == NULL)
					throw ASN_EXCEPTION("SNACC::Extension::extnValue is NULL");
			
				if (unknownExts.IsPresent(i->extnId))
					throw ASN_EXCEPTION("Duplicate extension found");
				
				// Add the unknown extension to the list and add an identifier
				// to the original order list
				unknownExts.push_back(*i);
				m_origOrder.push_back(--unkAny);
			}
			else  // Known, decoded extension
			{
				if (i->extnValue.value == NULL)
					throw ASN_EXCEPTION("SNACC::Extension::extnValue is NULL");
			
				int tempAnyId = i->extnValue.ai->anyId;
				switch (tempAnyId)
				{
				case SNACC::authorityKeyIdentifier_ANY_ID:
					if (pAuthKeyID != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pAuthKeyID = new AuthKeyIdExtension(*(SNACC::AuthorityKeyIdentifier*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::timeSpecification_ANY_ID:
					if (pTimeSpec != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pTimeSpec = new StdExtension_T<SNACC::TimeSpecification>(
						*(SNACC::TimeSpecification*)i->extnValue.value,
						i->extnId, i->critical);
					break;
				case SNACC::targetingInformation_ANY_ID:
					if (pTargetInfo != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pTargetInfo = new StdExtension_T<SNACC::TargetingInformation>(
						*(SNACC::TargetingInformation*)i->extnValue.value,
						i->extnId, i->critical);
					break;
				case SNACC::userNoticeExtension_ANY_ID:
					if (pUserNotice != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pUserNotice = new StdExtension_T<SNACC::UserNoticeExtension>(
						*(SNACC::UserNoticeExtension*)i->extnValue.value,
						i->extnId, i->critical);
					break;
				case SNACC::acceptablePrivilegePolicies_ANY_ID:
					if (pPrivPolicies != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pPrivPolicies = new StdExtension_T<SNACC::AcceptableCertPoliciesSyntax>(
						*(SNACC::AcceptableCertPoliciesSyntax*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::cRLDistributionPoints_ANY_ID:
					if (pCrlDistPts != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pCrlDistPts = new CrlDistPointsExtension(*(SNACC::CRLDistPointsSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::noRevAvail_ANY_ID:
					if (pRevInfoAvail != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pRevInfoAvail = new StdExtension_T<SNACC::AsnNull>(
						*(SNACC::AsnNull*)i->extnValue.value, i->extnId,
						i->critical);
					break;
				case SNACC::sOAIdentifier_ANY_ID:
					if (pSOA_Id != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pSOA_Id = new StdExtension_T<SNACC::AsnNull>(
						*(SNACC::AsnNull*)i->extnValue.value, i->extnId,
						i->critical);
					break;
				case SNACC::attributeDescriptor_ANY_ID:
					if (pDescriptor != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pDescriptor = new StdExtension_T<SNACC::AttributeDescriptorSyntax>(
						*(SNACC::AttributeDescriptorSyntax*)i->extnValue.value,
						i->extnId, i->critical);
					break;
				case SNACC::roleSpecCertIdentifier_ANY_ID:
					if (pRoleSpec != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pRoleSpec = new StdExtension_T<SNACC::RoleSpecCertIdentifierSyntax>(
						*(SNACC::RoleSpecCertIdentifierSyntax*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::basicAttConstraints_ANY_ID:
					if (pBasicCons != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pBasicCons = new ACBasicConstraintsExtension(
						*(SNACC::BasicAttConstraintsSyntax*)i->extnValue.value,
						i->critical);
					break;
				case SNACC::delegatedNameConstraints_ANY_ID:
					if (pNameCons != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pNameCons = new ACNameConstraintsExtension(
						*(SNACC::NameConstraintsSyntax*)i->extnValue.value,
						i->critical);
					break;
				case SNACC::acceptableCertPolicies_ANY_ID:
					if (pCertPolicies != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pCertPolicies = new StdExtension_T<SNACC::AcceptableCertPoliciesSyntax>(
						*(SNACC::AcceptableCertPoliciesSyntax*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::authorityAttributeIdentifier_ANY_ID:
					if (pAA_Id != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pAA_Id = new StdExtension_T<SNACC::AuthorityAttributeIdentifierSyntax>(
						*(SNACC::AuthorityAttributeIdentifierSyntax*)
						i->extnValue.value, i->extnId, i->critical);
					break;
				case SNACC::authorityInfoAccess_ANY_ID:
					if (pAuthInfoAccess != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pAuthInfoAccess = new PkixAIAExtension(*(SNACC::AuthorityInfoAccessSyntax*)
						i->extnValue.value, i->critical);
					break;
				case SNACC::auditIdentity_ANY_ID:
					if (pAuditIdentity != NULL)
						throw ASN_EXCEPTION("Duplicate extension found");
					pAuditIdentity = new StdExtension_T<SNACC::AsnOcts>(
						*(SNACC::AsnOcts*)i->extnValue.value, i->extnId,
						i->critical);
					break;
					
				default:
					throw ASN_EXCEPTION("Invalid attribute certificate extension");
				}
				
				// Add this extension's anyID to the original order list
				m_origOrder.push_back(tempAnyId);
				
		 } // end of else
	  } // end of for each extension loop
	  
	  return *this;
   }
   catch (...) {
	   Clear();
	   throw;
   }
} // end of ACExtensions::operator=()


ACExtensions& ACExtensions::operator=(const ACExtensions& other)
{
	if (this != &other)
	{
		if (dupExtsExist(other.unknownExts))
			throw ASN_EXCEPTION("Duplicate extension found");
		
		Clear();
		try {
			m_origOrder = other.m_origOrder;
			m_extsPresent = other.m_extsPresent;
			
			if (other.pAuthKeyID != NULL)
			{
				pAuthKeyID = new AuthKeyIdExtension(*other.pAuthKeyID);
				if (pAuthKeyID == NULL)
					throw MEMORY_EXCEPTION;
			}
			if (other.pTimeSpec != NULL)
			{
				pTimeSpec = new StdExtension_T<SNACC::TimeSpecification>(
					*other.pTimeSpec);
				if (pTimeSpec == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pTargetInfo != NULL)
			{
				pTargetInfo = new StdExtension_T<SNACC::TargetingInformation>(
					*other.pTargetInfo);
				if (pTargetInfo == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pUserNotice != NULL)
			{
				pUserNotice = new StdExtension_T<SNACC::UserNoticeExtension>(
					*other.pUserNotice);
				if (pUserNotice == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pPrivPolicies != NULL)
			{
				pPrivPolicies = new StdExtension_T<SNACC::AcceptableCertPoliciesSyntax>(
					*other.pPrivPolicies);
				if (pPrivPolicies == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pCrlDistPts != NULL)
			{
				pCrlDistPts = new CrlDistPointsExtension(*other.pCrlDistPts);
				if (pCrlDistPts == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pRevInfoAvail != NULL)
			{
				pRevInfoAvail = new StdExtension_T<SNACC::AsnNull>(
					*other.pRevInfoAvail);
				if (pRevInfoAvail == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pSOA_Id != NULL)
			{
				pSOA_Id = new StdExtension_T<SNACC::AsnNull>(*other.pSOA_Id);
				if (pSOA_Id == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pDescriptor != NULL)
			{
				pDescriptor = new StdExtension_T<SNACC::AttributeDescriptorSyntax>(
					*other.pDescriptor);
				if (pDescriptor == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pRoleSpec != NULL)
			{
				pRoleSpec = new StdExtension_T<SNACC::RoleSpecCertIdentifierSyntax>(
					*other.pRoleSpec);
				if (pRoleSpec == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pBasicCons != NULL)
			{
				pBasicCons = new ACBasicConstraintsExtension(*other.pBasicCons);
				if (pBasicCons == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pNameCons != NULL)
			{
				pNameCons = new ACNameConstraintsExtension(*other.pNameCons);
				if (pNameCons == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pCertPolicies != NULL)
			{
				pCertPolicies = new StdExtension_T<SNACC::AcceptableCertPoliciesSyntax>(
					*other.pCertPolicies);
				if (pCertPolicies == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.pAA_Id != NULL)
			{
				pAA_Id = new StdExtension_T<SNACC::AuthorityAttributeIdentifierSyntax>(
					*other.pAA_Id);
				if (pAA_Id == NULL)
					throw MEMORY_EXCEPTION;
			}

			if (other.pAuthInfoAccess != NULL)
			{
				pAuthInfoAccess = new PkixAIAExtension(*other.pAuthInfoAccess);
				if (pAuthInfoAccess == NULL)
					throw MEMORY_EXCEPTION;
			}

			if (other.pAuditIdentity != NULL)
			{
				pAuditIdentity = new StdExtension_T<SNACC::AsnOcts>(*other.pAuditIdentity);
				if (pAuditIdentity == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			unknownExts = other.unknownExts;
	  }
	  catch (...) {
		  Clear();
		  throw;
	  }
   }
   return *this;
}


void ACExtensions::Clear()
{
	m_origOrder.clear();
	m_extsPresent = false;
	
	if (pAuthKeyID != NULL)
	{
		delete pAuthKeyID;
		pAuthKeyID = NULL;
	}
	
	if (pTimeSpec != NULL)
	{
		delete pTimeSpec;
		pTimeSpec = NULL;
	}
	
	if (pTargetInfo != NULL)
	{
		delete pTargetInfo;
		pTargetInfo = NULL;
	}
	
	if (pUserNotice != NULL)
	{
		delete pUserNotice;
		pUserNotice = NULL;
	}
	
	if (pPrivPolicies != NULL)
	{
		delete pPrivPolicies;
		pPrivPolicies = NULL;
	}
	
	if (pCrlDistPts != NULL)
	{
		delete pCrlDistPts;
		pCrlDistPts = NULL;
	}
	
	if (pRevInfoAvail != NULL)
	{
		delete pRevInfoAvail;
		pRevInfoAvail = NULL;
	}
	
	if (pSOA_Id != NULL)
	{
		delete pSOA_Id;
		pSOA_Id = NULL;
	}
	
	if (pDescriptor != NULL)
	{
		delete pDescriptor;
		pDescriptor = NULL;
	}
	
	if (pRoleSpec != NULL)
	{
		delete pRoleSpec;
		pRoleSpec = NULL;
	}
	
	if (pBasicCons != NULL)
	{
		delete pBasicCons;
		pBasicCons = NULL;
	}
	
	if (pNameCons != NULL)
	{
		delete pNameCons;
		pNameCons = NULL;
	}
	
	if (pCertPolicies != NULL)
	{
		delete pCertPolicies;
		pCertPolicies = NULL;
	}
	
	if (pAA_Id != NULL)
	{
		delete pAA_Id;
		pAA_Id = NULL;
	}

	if (pAuthInfoAccess != NULL)
	{
		delete pAuthInfoAccess;
		pAuthInfoAccess = NULL;
	}

	if (pAuditIdentity != NULL)
	{
		delete pAuditIdentity;
		pAuditIdentity = NULL;
	}
	
	unknownExts.clear();
}


SNACC::Extensions* ACExtensions::GetSnacc() const
{
	// If none of the extensions are present (and they weren't present in
	// ASN.1), return NULL;
	if (!pAuthKeyID && !pTimeSpec && !pTargetInfo && !pUserNotice &&
		!pPrivPolicies && !pCrlDistPts && !pRevInfoAvail && !pSOA_Id &&
		!pDescriptor && !pRoleSpec && !pBasicCons && !pNameCons &&
		!pCertPolicies && !pAA_Id && !pAuthInfoAccess && !pAuditIdentity &&
		unknownExts.empty() && !m_extsPresent)
		return NULL;
	
	if (dupExtsExist(unknownExts))
		throw ASN_EXCEPTION("Duplicate extension found");
	
	SNACC::Extensions* result = NULL;
	try {
		result = new SNACC::Extensions;
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		// Build a map of the known extensions that are present
		ExtensionPtrMap extMap;
		buildExtMap(extMap, *this);
		
		UnknownExtensions::const_iterator unkExtI = unknownExts.begin();
		
		// Encode any extensions in the same order they were present in the ASN.1
		std::vector<int>::const_iterator i;
		for (i = m_origOrder.begin(); i != m_origOrder.end(); i++)
		{
			if (*i < 0)    // Unknown extension
			{
				// Check that another unknown extension is present
				if (unkExtI != unknownExts.end())
				{
					// Append a new SNACC extension and fill it with the
					// contents of the next unknown extension
					unkExtI->FillSnaccExtension(*result->append());
					++unkExtI;
				}
			}
			else  // Known extension
			{
				const Extension* pExt;
				switch (*i)
				{
				case SNACC::authorityKeyIdentifier_ANY_ID:
					pExt = pAuthKeyID;
					break;
				case SNACC::timeSpecification_ANY_ID:
					pExt = pTimeSpec;
					break;
				case SNACC::targetingInformation_ANY_ID:
					pExt = pTargetInfo;
					break;
				case SNACC::userNoticeExtension_ANY_ID:
					pExt = pUserNotice;
					break;
				case SNACC::acceptablePrivilegePolicies_ANY_ID:
					pExt = pPrivPolicies;
					break;
				case SNACC::cRLDistributionPoints_ANY_ID:
					pExt = pCrlDistPts;
					break;
				case SNACC::noRevAvail_ANY_ID:
					pExt = pRevInfoAvail;
					break;
				case SNACC::sOAIdentifier_ANY_ID:
					pExt = pSOA_Id;
					break;
				case SNACC::attributeDescriptor_ANY_ID:
					pExt = pDescriptor;
					break;
				case SNACC::roleSpecCertIdentifier_ANY_ID:
					pExt = pRoleSpec;
					break;
				case SNACC::basicAttConstraints_ANY_ID:
					pExt = pBasicCons;
					break;
				case SNACC::delegatedNameConstraints_ANY_ID:
					pExt = pNameCons;
					break;
				case SNACC::acceptableCertPolicies_ANY_ID:
					pExt = pCertPolicies;
					break;
				case SNACC::authorityAttributeIdentifier_ANY_ID:
					pExt = pAA_Id;
					break;
				case SNACC::authorityInfoAccess_ANY_ID:
					pExt = pAuthInfoAccess;
					break;
				case SNACC::auditIdentity_ANY_ID:
					pExt = pAuditIdentity;
					break;
				default:
					pExt = NULL;
				}
				
				if (pExt != NULL) // If the extension is still present
				{
					// Append a new SNACC extension and fill it with the
					// contents of this extension
					pExt->FillSnaccExtension(*result->append());

					// Remove it from the map
					extMap.erase(*i);
				}
				
			} // end of else
		} // end of for loop
		
		// Encode any remaining known extensions
		ExtensionPtrMap::iterator mapI;
		for (mapI = extMap.begin(); mapI != extMap.end(); ++mapI)
		{
			// Append a new SNACC extension and fill it with the
			// contents of this extension
			mapI->second->FillSnaccExtension(*result->append());
		}
		
		// Encode any remaining unknown extensions
		for ( ; unkExtI != unknownExts.end(); ++unkExtI)
		{
			// Append a new SNACC extension and fill it with the
			// contents of this unknown extension
			unkExtI->FillSnaccExtension(*result->append());
		}
		
		return result;
   }
   catch (...) {
	   delete result;
	   throw;
   }
}


////////////////////////////////////////////
// UnknownExtensions class implementation //
////////////////////////////////////////////
const UnknownExtension* UnknownExtensions::Find(const char* stringOid) const
{
	for (const_iterator i = begin(); i != end(); i++)
	{
		if (i->OID() == stringOid)
			return &(*i);
	}
	return NULL;
}


const UnknownExtension* UnknownExtensions::Find(const SNACC::AsnOid& extOid) const
{
	for (const_iterator i = begin(); i != end(); i++)
	{
		if (i->OID() == extOid)
			return &(*i);
	}
	return NULL;
}


// Get the C list of unknown extensions
Unkn_extn_LL* UnknownExtensions::GetUnknownExts() const
{
	Unkn_extn_LL* pList = NULL;
	try {
		for (const_reverse_iterator i = rbegin(); i != rend(); i++)
		{
			Unkn_extn_LL* pNew = i->GetUnknownExtStruct();
			pNew->next = pList;
			pList = pNew;
		}
		return pList;
	}
	catch (...) {
		Internal::FreeUnknExtn(&pList);
		throw;
	}
}


////////////////////////////////////
// Extension class implementation //
////////////////////////////////////
Extension::Extension(const SNACC::AsnOid& oid,
					 const SNACC::AsnBool* pCriticalFlag) : m_extnId(oid)
{
	if (pCriticalFlag == NULL)
	{
		critical = false;
		m_criticalPresent = false;
	}
	else
	{
		critical = *pCriticalFlag;
		m_criticalPresent = true;
	}
}


Extension& Extension::operator=(const SNACC::Extension& snacc)
{
	m_extnId = snacc.extnId;
	if (snacc.critical == NULL)
	{
		critical = false;
		m_criticalPresent = false;
	}
	else
	{
		critical = *snacc.critical;
		m_criticalPresent = true;
	}
	
	return *this;
}


void Extension::FillSnaccExtension(SNACC::Extension& snacc) const
{
	snacc.extnId = m_extnId;
	if (m_criticalPresent || critical)
	{
		if (snacc.critical != NULL)
			*snacc.critical = critical;
		else
		{
			snacc.critical = new SNACC::AsnBool(critical);
			if (snacc.critical == NULL)
				throw MEMORY_EXCEPTION;
		}
	}
	else if (snacc.critical != NULL)
	{
		delete snacc.critical;
		snacc.critical = NULL;
	}
	
	snacc.extnValue.ai = NULL;
	snacc.extnValue.value = GetSnaccValue();
}


// Get the C form of this extension
Extn_struct* Extension::GetExtensionStruct() const
{
	Extn_struct* pExt = (Extn_struct*)calloc(1, sizeof(Extn_struct));
	if (pExt == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		pExt->oid = m_extnId.GetChar();
		if (critical)
			pExt->critical = TRUE;
		else
			pExt->critical = FALSE;
		pExt->value = GetExtensionValue();
		
		return pExt;
	}
	catch (...) {
		if (pExt->oid != NULL)
			free(pExt->oid);
		free(pExt);
		throw;
	}
}


///////////////////////////////////////////
// UnknownExtension class implementation //
///////////////////////////////////////////
UnknownExtension::UnknownExtension() : Extension(SNACC::AsnOid())
{
}


UnknownExtension::UnknownExtension(const SNACC::Extension& snacc) :
Extension(snacc.extnId, snacc.critical), encValue(snacc.extnValue)
{
}


UnknownExtension::UnknownExtension(const SNACC::AsnOid& asnOid,
								   const SNACC::AsnBool* pAsnBool,
								   const Bytes& asnValue) :
Extension(asnOid, pAsnBool), encValue(asnValue)
{
}


bool UnknownExtension::operator==(const UnknownExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if ((m_extnId == rhs.m_extnId) && (critical == rhs.critical) &&
		(encValue == rhs.encValue))
		return true;
	else
		return false;
}


SNACC::AsnType* UnknownExtension::GetSnaccValue() const
{
	SNACC::AsnAny* result = new SNACC::AsnAny();
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		result->anyBuf = new SNACC::AsnBuf((const char *)encValue.GetData(),
			encValue.Len());
		if (result->anyBuf == NULL)
			throw MEMORY_EXCEPTION;
	}
	catch (...) {
		delete result;
		throw;
	}
	
	return result;
}


// Get the C form of this unknown extension
Unkn_extn_LL* UnknownExtension::GetUnknownExtStruct() const
{
	Unkn_extn_LL* pUnkExt = (Unkn_extn_LL*)calloc(1, sizeof(Unkn_extn_LL));
	if (pUnkExt == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		pUnkExt->oid = m_extnId.GetChar();
		if (critical)
			pUnkExt->critical = TRUE;
		else
			pUnkExt->critical = FALSE;
		pUnkExt->value = encValue.GetBytesStruct();
		
		return pUnkExt;
	}
	catch (...) {
		Internal::FreeUnknExtn(&pUnkExt);
		throw;
	}
}


/////////////////////////////////////////////
// SubjKeyIdExtension class implementation //
/////////////////////////////////////////////
SubjKeyIdExtension::SubjKeyIdExtension(const SNACC::SubjectKeyIdentifier& snacc,
									   const SNACC::AsnBool* pCriticalFlag) :
StdExtension_T<SNACC::SubjectKeyIdentifier>(snacc,
											SNACC::id_ce_subjectKeyIdentifier,
											pCriticalFlag)
{
}


void * SubjKeyIdExtension::GetExtensionValue() const
{
	return Internal::cvtOctsToBytes(*this); 
}

/////////////////////////////////////////////
// AuthKeyIdExtension class implementation //
/////////////////////////////////////////////
AuthKeyIdExtension::AuthKeyIdExtension() :
Extension(SNACC::id_ce_authorityKeyIdentifier)
{
	keyID = NULL;
	authCertIssuer = NULL;
	authCertSerialNum = NULL;
}


AuthKeyIdExtension::AuthKeyIdExtension(const SNACC::AuthorityKeyIdentifier& snacc,
									   const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_authorityKeyIdentifier, pCriticalFlag)
{
	keyID = NULL;
	authCertIssuer = NULL;
	authCertSerialNum = NULL;
	operator=(snacc);
}


AuthKeyIdExtension::AuthKeyIdExtension(const AuthKeyIdExtension& that) :
Extension(that)
{
	keyID = NULL;
	authCertIssuer = NULL;
	authCertSerialNum = NULL;
	operator=(that);
}


AuthKeyIdExtension& AuthKeyIdExtension::operator=(const SNACC::AuthorityKeyIdentifier& snacc)
{
	Clear();
	try {
		if (snacc.keyIdentifier != NULL)
		{
			keyID = (SNACC::KeyIdentifier*)snacc.keyIdentifier->Clone();
			if (keyID == NULL)
				throw MEMORY_EXCEPTION;
		}
		if (snacc.authorityCertIssuer != NULL)
		{
			authCertIssuer = new GenNames(*snacc.authorityCertIssuer);
			if (authCertIssuer == NULL)
				throw MEMORY_EXCEPTION;
		}
		if (snacc.authorityCertSerialNumber != NULL)
			authCertSerialNum = (SNACC::CertificateSerialNumber*)
				snacc.authorityCertSerialNumber->Clone();

		if (((authCertIssuer != NULL) && (authCertSerialNum == NULL)) ||
			((authCertIssuer == NULL) && (authCertSerialNum != NULL)))
			throw ASN_EXCEPTION("Invalid AuthorityKeyIdentifier fields");
		
		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


AuthKeyIdExtension& AuthKeyIdExtension::operator=(const AuthKeyIdExtension& other)
{
	try {
		if (this != &other)
		{
			Clear();
			if (other.keyID != NULL)
			{
				keyID = (SNACC::KeyIdentifier*)other.keyID->Clone();
				if (keyID == NULL)
					throw MEMORY_EXCEPTION;
			}
			if (other.authCertIssuer != NULL)
			{
				authCertIssuer = new GenNames(*other.authCertIssuer);
				if (authCertIssuer == NULL)
					throw MEMORY_EXCEPTION;
			}
			if (other.authCertSerialNum != NULL)
			{
				authCertSerialNum = (SNACC::CertificateSerialNumber*)
					other.authCertSerialNum->Clone();
				if (authCertSerialNum == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


bool AuthKeyIdExtension::operator==(const AuthKeyIdExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	if ((keyID != NULL) && (rhs.keyID != NULL))
	{
		if (*keyID != *rhs.keyID)
			return false;
	}
	else if ((keyID != NULL) || (rhs.keyID != NULL))
		return false;
	// else both are absent
	
	if ((authCertIssuer != NULL) && (rhs.authCertIssuer != NULL))
	{
		if (*authCertIssuer != *rhs.authCertIssuer)
			return false;
	}
	else if ((authCertIssuer != NULL) || (rhs.authCertIssuer != NULL))
		return false;
	// else both are absent
	
	if ((authCertSerialNum != NULL) && (rhs.authCertSerialNum != NULL))
	{
		if (*authCertSerialNum != *rhs.authCertSerialNum)
			return false;
	}
	else if ((authCertSerialNum != NULL) || (rhs.authCertSerialNum != NULL))
		return false;
	// else both are absent
	
	return true;
}


SNACC::AsnType* AuthKeyIdExtension::GetSnaccValue() const
{
	SNACC::AuthorityKeyIdentifier* result = NULL;
	try {
		result = new SNACC::AuthorityKeyIdentifier();
		if (result == NULL)
			throw MEMORY_EXCEPTION;

		if (keyID != NULL)
		{
			result->keyIdentifier = (SNACC::KeyIdentifier*)keyID->Clone();
			if (result->keyIdentifier == NULL)
				throw MEMORY_EXCEPTION;
		}

		if (authCertIssuer != NULL)
			result->authorityCertIssuer = authCertIssuer->GetSnacc();

		if (authCertSerialNum != NULL)
		{
			result->authorityCertSerialNumber = (SNACC::CertificateSerialNumber*)
				authCertSerialNum->Clone();
			if (result->authorityCertSerialNumber == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


// Get the C form of this extension's value
void* AuthKeyIdExtension::GetExtensionValue() const
{
	Auth_key_struct* pExt = (Auth_key_struct*)
		calloc(1, sizeof(Auth_key_struct));
	if (pExt == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (keyID != NULL)
			pExt->id = Internal::cvtOctsToBytes(*keyID);
		if (authCertIssuer != NULL)
			pExt->issuer = authCertIssuer->GetGenNamesList();
		if (authCertSerialNum != NULL)
			Internal::cvtInt2BytesStruct(&pExt->serial_num, *authCertSerialNum);
		return pExt;
	}
	catch (...) {
		Internal::FreeAuthKeyID(pExt);
		throw;
	}
}


void AuthKeyIdExtension::Clear()
{
	if (keyID != NULL)
	{
		delete keyID;
		keyID = NULL;
	}
	if (authCertIssuer != NULL)
	{
		delete authCertIssuer;
		authCertIssuer = NULL;
	}
	if (authCertSerialNum != NULL)
	{
		delete authCertSerialNum;
		authCertSerialNum = NULL;
	}
}


////////////////////////////////////////////
// KeyUsageExtension class implementation //
////////////////////////////////////////////
KeyUsageExtension::KeyUsageExtension() : Extension(SNACC::id_ce_keyUsage),
SNACC::KeyUsage(9)
{
}


KeyUsageExtension::KeyUsageExtension(const SNACC::KeyUsage& snacc,
									 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_keyUsage, pCriticalFlag), SNACC::KeyUsage(snacc)
{
}


bool KeyUsageExtension::operator==(const KeyUsageExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	return (*(const SNACC::KeyUsage*)this == rhs);
}


SNACC::AsnType* KeyUsageExtension::GetSnaccValue() const
{
	SNACC::KeyUsage* result = NULL;
	try {
		result = new SNACC::KeyUsage(*this);
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* KeyUsageExtension::GetExtensionValue() const
{
	return cvt_AsnBitMask(*this);
}


///////////////////////////////////////////////
// ExtKeyUsageExtension class implementation //
///////////////////////////////////////////////
ExtKeyUsageExtension::ExtKeyUsageExtension() :
Extension(SNACC::id_ce_extKeyUsage)
{
}


ExtKeyUsageExtension::ExtKeyUsageExtension(const SNACC::ExtKeyUsage& snacc,
										   const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_extKeyUsage, pCriticalFlag)
{
	operator=(snacc);
}


ExtKeyUsageExtension& ExtKeyUsageExtension::operator=(const SNACC::ExtKeyUsage& snacc)
{
	assign(snacc.begin(), snacc.end());
	return *this;
}


bool ExtKeyUsageExtension::operator==(const ExtKeyUsageExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	const_iterator j = rhs.begin();
	const_iterator i;
	for (i = begin(); (i != end()) && (j != rhs.end()); i++, j++)
	{
		if (*i != *j)
			return false;
	}
	
	if ((i == end()) && (j == rhs.end()))
		return true;
	else
		return false;
}


SNACC::AsnType* ExtKeyUsageExtension::GetSnaccValue() const
{
	SNACC::ExtKeyUsage* result = new SNACC::ExtKeyUsage();
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		result->assign(begin(), end());
		return result;
	}
	catch (...)
	{
		delete result;
		throw;
	}
}


void* ExtKeyUsageExtension::GetExtensionValue() const
{
	Ext_key_use_LL* pList = NULL;
	try {
		std::list<SNACC::KeyPurposeId>::const_reverse_iterator i;
		for (i = rbegin(); i != rend(); i++)
		{
			Ext_key_use_LL* pNew = (Ext_key_use_LL*)
				calloc(1, sizeof(Ext_key_use_LL));
			if (pNew == NULL)
				throw MEMORY_EXCEPTION;
			pNew->next = pList;
			pList = pNew;
			pNew->oid = i->GetChar();
		}
		return pList;
	}
	catch (...) {
		Internal::FreeOIDList(pList);
		throw;
	}
}


//////////////////////////////////////////////////////
// PrivKeyUsagePeriodExtension class implementation //
//////////////////////////////////////////////////////
PrivKeyUsagePeriodExtension::PrivKeyUsagePeriodExtension() :
Extension(SNACC::id_ce_privateKeyUsagePeriod)
{
	notBefore = NULL;
	notAfter = NULL;
}


PrivKeyUsagePeriodExtension::PrivKeyUsagePeriodExtension(const SNACC::PrivateKeyUsagePeriod& snacc,
														 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_privateKeyUsagePeriod, pCriticalFlag)
{
	notBefore = NULL;
	notAfter = NULL;
	operator=(snacc);
}


PrivKeyUsagePeriodExtension::PrivKeyUsagePeriodExtension(const PrivKeyUsagePeriodExtension& that) :
Extension(that)
{
	notBefore = NULL;
	notAfter = NULL;
	operator=(that);
}


PrivKeyUsagePeriodExtension& PrivKeyUsagePeriodExtension::operator=(const SNACC::PrivateKeyUsagePeriod& snacc)
{
	Clear();
	try {
		if (snacc.notBefore != NULL)
			notBefore = new Time(*snacc.notBefore);
		if (snacc.notAfter != NULL)
			notAfter = new Time(*snacc.notAfter);
		
		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


PrivKeyUsagePeriodExtension& PrivKeyUsagePeriodExtension::operator=(const PrivKeyUsagePeriodExtension& other)
{
	if (this != &other)
	{
		Clear();
		
		try {
			if (other.notBefore != NULL)
				notBefore = new Time(*other.notBefore);
			if (other.notAfter != NULL)
				notAfter = new Time(*other.notAfter);
		}
		catch (...) {
			Clear();
			throw;
		}
	}
	
	return *this;
}


bool PrivKeyUsagePeriodExtension::operator==(const PrivKeyUsagePeriodExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	if (((notBefore == NULL) && (rhs.notBefore != NULL)) ||
		((notBefore != NULL) && (rhs.notBefore == NULL)))
		return false;
	else if ((notBefore != NULL) && (rhs.notBefore != NULL))
	{
		if (*notBefore != *rhs.notBefore)
			return false;
	}
	
	if (((notAfter == NULL) && (rhs.notAfter != NULL)) ||
		((notAfter != NULL) && (rhs.notAfter == NULL)))
		return false;
	else if ((notAfter != NULL) && (rhs.notAfter != NULL))
		return (*notAfter == *rhs.notAfter);
	else
		return true;
}


bool PrivKeyUsagePeriodExtension::IsWithin(const Time& time) const
{
	if (notBefore != NULL)
	{
		if (time < *notBefore)
			return false;
	}
	
	if (notAfter != NULL)
	{
		if (time > *notAfter)
			return false;
	}
	return true;
}


SNACC::AsnType* PrivKeyUsagePeriodExtension::GetSnaccValue() const
{
	SNACC::PrivateKeyUsagePeriod* result = NULL;
	try {
		result = new SNACC::PrivateKeyUsagePeriod();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		if (notBefore != NULL)
			result->notBefore = notBefore->GetSnaccGenTime();
		if (notAfter != NULL)
			result->notAfter = notAfter->GetSnaccGenTime();
		
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* PrivKeyUsagePeriodExtension::GetExtensionValue() const
{
	Priv_key_val_struct* pPeriod = (Priv_key_val_struct*)
		calloc(1, sizeof(Priv_key_val_struct));
	if (pPeriod == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (notBefore != NULL)
		{
			pPeriod->not_before = (CM_Time*)malloc(sizeof(CM_Time));
			if (pPeriod->not_before == NULL)
				throw MEMORY_EXCEPTION;
			strcpy(*pPeriod->not_before, *notBefore);
		}
		if (notAfter != NULL)
		{
			pPeriod->not_after = (CM_Time*)malloc(sizeof(CM_Time));
			if (pPeriod->not_after == NULL)
				throw MEMORY_EXCEPTION;
			strcpy(*pPeriod->not_after, *notAfter);
		}
		return pPeriod;
	}
	catch (...) {
		if (pPeriod->not_before != NULL)
			free(pPeriod->not_before);
		if (pPeriod->not_after != NULL)
			free(pPeriod->not_after);
		free(pPeriod);
		throw;
	}
}


void PrivKeyUsagePeriodExtension::Clear()
{
	if (notBefore != NULL)
	{
		delete notBefore;
		notBefore = NULL;
	}
	if (notAfter != NULL)
	{
		delete notAfter;
		notAfter = NULL;
	}
}


////////////////////////////////////////////////
// SubjAltNamesExtension class implementation //
////////////////////////////////////////////////
SubjAltNamesExtension::SubjAltNamesExtension() :
Extension(SNACC::id_ce_subjectAltName)
{
}


SubjAltNamesExtension::SubjAltNamesExtension(const SNACC::GeneralNames& snacc,
											 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_subjectAltName, pCriticalFlag), GenNames(snacc)
{
}


bool SubjAltNamesExtension::operator==(const SubjAltNamesExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	return (GenNames(*this) == rhs);
}


//////////////////////////////////////////////////
// IssuerAltNamesExtension class implementation //
//////////////////////////////////////////////////
IssuerAltNamesExtension::IssuerAltNamesExtension() :
Extension(SNACC::id_ce_issuerAltName)
{
}


IssuerAltNamesExtension::IssuerAltNamesExtension(const SNACC::GeneralNames& snacc,
												 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_issuerAltName, pCriticalFlag), GenNames(snacc)
{
}


bool IssuerAltNamesExtension::operator==(const IssuerAltNamesExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	return (GenNames(*this) == rhs);
}


//////////////////////////////////////////
// PolicyQualifier class implementation //
//////////////////////////////////////////
PolicyQualifier::PolicyQualifier(const SNACC::AsnOid& asnOid) : qualifierId(asnOid)
{
	qualifier = NULL;
}


PolicyQualifier::PolicyQualifier(const SNACC::PolicyQualifierInfo& snacc) :
qualifierId(snacc.policyQualifierId)
{
	if (snacc.qualifier == NULL)
		qualifier = NULL;
	else
		qualifier = new Bytes(*snacc.qualifier, "PolicyQualifierInfo::qualifier");
}


PolicyQualifier::PolicyQualifier(const PolicyQualifier& that)
{
	qualifier = NULL;
	qualifierId = that.qualifierId;
	if (that.qualifier == NULL)
		qualifier = NULL;
	else
	{
		qualifier = new Bytes(*that.qualifier);
		if (qualifier == NULL)
			throw MEMORY_EXCEPTION;
	}
}


PolicyQualifier::~PolicyQualifier()
{
	if (qualifier != NULL)
		delete qualifier;
}


PolicyQualifier& PolicyQualifier::operator=(const PolicyQualifier& other)
{
	if (this != &other)
	{
		delete qualifier;
		qualifier = NULL;
		
		qualifierId = other.qualifierId;
		if (other.qualifier != NULL)
		{
			qualifier = new Bytes(*other.qualifier);
			if (qualifier == NULL)
				throw MEMORY_EXCEPTION;
		}
	}
	return *this;
}


bool PolicyQualifier::operator==(const PolicyQualifier& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (qualifierId != rhs.qualifierId)
		return false;
	
	if ((qualifier == NULL) && (rhs.qualifier == NULL))
		return true;
	else if ((qualifier == NULL) || (rhs.qualifier == NULL))
		return false;
	else
		return (*qualifier == *rhs.qualifier);
}
bool PolicyQualifier::operator<(const PolicyQualifier& rhs) const
{
	if (this == &rhs)
		return false;

	if (qualifierId < rhs.qualifierId)
		return true;

	if (qualifierId == rhs.qualifierId)
	{
		if ((qualifier == NULL) && (rhs.qualifier == NULL))
			return false;
		else if (rhs.qualifier == NULL)
			return false;
		else if (qualifier == NULL)
			return true;
		else if (qualifier < rhs.qualifier)
			return true;
	}
	return false;
}
void PolicyQualifier::FillSnaccQualifier(SNACC::PolicyQualifierInfo& snacc) const
{
	try {
		snacc.qualifier = NULL;
		snacc.policyQualifierId = qualifierId;
		
		if (qualifier != NULL)
		{
			snacc.qualifier = new SNACC::AsnAnyDefinedBy();
			if (snacc.qualifier == NULL)
				throw MEMORY_EXCEPTION;
			
			snacc.qualifier->anyBuf = new SNACC::AsnBuf((const char *)
				qualifier->GetData(), qualifier->Len());
			if (snacc.qualifier->anyBuf == NULL)
				throw MEMORY_EXCEPTION;
		}
	}
	catch (...) {
		delete snacc.qualifier;
		throw;
	}
}


Qualifier_struct* PolicyQualifier::GetQualifierStruct() const
{
	Qualifier_struct* pResult = (Qualifier_struct*)
		calloc(1, sizeof(Qualifier_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		pResult->qualifier_id = qualifierId.GetChar();
		if (qualifierId == gQT_CPS_QUALIFIER_OID)
		{
			pResult->flag = CM_QUAL_CPS;
			if (qualifier != NULL)
			{
				// Decode the SNACC::CPSuri
				SNACC::CPSuri snaccQual;
				qualifier->Decode(snaccQual, "SNACC::CPSuri qualifier");

				// Copy the CPSuri string
				pResult->qual.cpsURI = strdup(snaccQual.c_str());
				if (pResult->qual.cpsURI == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		else if (qualifierId == gQT_UNOTICE_QUALIFIER_OID)
		{
			pResult->flag = CM_QUAL_UNOTICE;
			if (qualifier != NULL)
			{
				// Decode the SNACC::UserNotice
				SNACC::UserNotice snaccQual;
				qualifier->Decode(snaccQual, "SNACC::UserNotice qualifier");

				// Convert the SNACC::UserNotice to the C structure
				pResult->qual.userNotice = cvtQualifierToUserNotice(snaccQual);
			}
		}
		else
		{
			// Copy the unknown qualifier
			pResult->flag = CM_QUAL_UNKNOWN;
			if (qualifier != NULL)
				pResult->qual.unknown = qualifier->GetBytesStruct();
		}
		
		return pResult;
	}
	catch (...) {
		Internal::FreeQualifiers(&pResult);
		throw;
	}
}


/////////////////////////////////////
// CertPolicy class implementation //
/////////////////////////////////////
CertPolicy::CertPolicy(const SNACC::AsnOid& asnOid,
					   const PolicyQualifierList* pQualifiers) : policyId(asnOid)
{
	if (pQualifiers != NULL)
		qualifiers = *pQualifiers;
}


CertPolicy::CertPolicy(const SNACC::PolicyInformation& snacc) :
policyId(snacc.policyIdentifier)
{
	if (snacc.policyQualifiers != NULL)
	{
		SNACC::PolicyInformationSeqOf::const_iterator i =
			snacc.policyQualifiers->begin();
		for ( ; i != snacc.policyQualifiers->end(); ++i)
			qualifiers.push_back(*i);
	}
}


bool CertPolicy::operator==(const CertPolicy& that) const
{
	if (this == &that)
		return true;
	
	if (policyId != that.policyId)
		return false;
	
	return (qualifiers == that.qualifiers);
}

bool CertPolicy::operator<(const CertPolicy& that) const
{
	if (this == &that)
		return false;
	
	if (policyId < that.policyId)
		return true;
	if ((policyId == that.policyId) && (qualifiers < that.qualifiers))
		return true;

	return false;
}

CertPolicy& CertPolicy::operator|=(const PolicyQualifierList& rhs)
{
	PolicyQualifierList::const_iterator pRhsQual;
	for (pRhsQual = rhs.begin(); pRhsQual != rhs.end(); ++pRhsQual)
	{
		PolicyQualifierList::iterator pQual = qualifiers.begin();
		for ( ; (pQual != qualifiers.end()) && (*pRhsQual != *pQual); ++pQual)
			;
		
		// If this qualifier OID isn't already present, add the qualifier
		if (pQual == qualifiers.end())
			qualifiers.push_back(*pRhsQual);
	}
	return *this;
}


void CertPolicy::FillSnaccPolicy(SNACC::PolicyInformation& snacc) const
{
	snacc.policyQualifiers = NULL;
	snacc.policyIdentifier = policyId;
	
	if (!qualifiers.empty())
	{
		snacc.policyQualifiers = new SNACC::PolicyInformationSeqOf();
		if (snacc.policyQualifiers == NULL)
			throw MEMORY_EXCEPTION;
		
		PolicyQualifierList::const_iterator i = qualifiers.begin();
		for ( ; i != qualifiers.end(); ++i)
			i->FillSnaccQualifier(*snacc.policyQualifiers->append());
	}
}


Policy_struct* CertPolicy::GetPolicyStruct() const
{
	Policy_struct* pResult = (Policy_struct*)calloc(1, sizeof(Policy_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		pResult->policy_id = policyId.GetChar();
		PolicyQualifierList::const_reverse_iterator i;
		for (i = qualifiers.rbegin(); i != qualifiers.rend(); ++i)
		{
			Qualifier_struct* pNew = i->GetQualifierStruct();
			pNew->next = pResult->qualifiers;
			pResult->qualifiers = pNew;
		}
		return pResult;
	}
	catch (...) {
		CMASN_FreePolicySet(pResult);
		throw;
	}
}


/////////////////////////////////////////
// CertPolicyList class implementation //
/////////////////////////////////////////
CertPolicyList::CertPolicyList(const SNACC::CertificatePoliciesSyntax& snacc)
{
	operator=(snacc);
}


CertPolicyList& CertPolicyList::operator=(const SNACC::CertificatePoliciesSyntax& snacc)
{
	clear();
	try {
		SNACC::CertificatePoliciesSyntax::const_iterator i;
		for (i = snacc.begin(); i != snacc.end(); ++i)
			push_back(*i);
		
		return *this;
	}
	catch (...) {
		clear();
		throw;
	}
}


bool CertPolicyList::operator==(const CertPolicyList& rhs) const
{
	if (this == &rhs)
		return true;
	
	const_iterator i = begin();
	const_iterator j = rhs.begin();
	for ( ; (i != end()) && (j != rhs.end()); ++i, ++j)
	{
		if (*i != *j)
			return false;
	}
	
	return ((i == end()) && (j == rhs.end()));
}


CertPolicyList::const_iterator CertPolicyList::Find(const SNACC::AsnOid& policyOid) const
{
	const_iterator i;
	for (i = begin(); (i != end()) && (i->policyId != policyOid); i++)
		;
	return i;
}


CertPolicyList::const_iterator CertPolicyList::FindNext(const_iterator iPrev,
														const SNACC::AsnOid& policyOid) const
{
	if (iPrev == NULL)
		return end();
	if (iPrev != end())
	{
		++iPrev;
		for ( ; (iPrev != end()) && (iPrev->policyId != policyOid); ++iPrev)
			;
	}
	return iPrev;
}


SNACC::CertificatePoliciesSyntax* CertPolicyList::GetSnaccValue() const
{
	SNACC::CertificatePoliciesSyntax* pResult = NULL;
	try {
		pResult = new SNACC::CertificatePoliciesSyntax;
		if (pResult == NULL)
			throw MEMORY_EXCEPTION;
		
		for (const_iterator i = begin(); i != end(); ++i)
			i->FillSnaccPolicy(*pResult->append());
		
		return pResult;
	}
	catch (...) {
		delete pResult;
		throw;
	}
}


Policy_struct* CertPolicyList::GetPolicyList() const
{
	Policy_struct* pList = NULL;
	
	try {
		CertPolicyList::const_reverse_iterator i;
		for (i = rbegin(); i != rend(); ++i)
		{
			Policy_struct* pNew = i->GetPolicyStruct();
			pNew->next = pList;
			pList = pNew;
		}
		return pList;
	}
	catch (...) {
		CMASN_FreePolicySet(pList);
		throw;
	}
}


//////////////////////////////
// CertPolicyList Operators //
//////////////////////////////
// Intersect the two policy sets and return the result
CertPolicyList CertPolicyList::operator&(const CertPolicyList& rhs) const
{
	CertPolicyList result;
	
	// If either set is empty, return an empty set
	if (this->empty() || rhs.empty())
		return result;
	
	// If the lhs set is any-policy, combine its qualifiers with the
	// policies in the rhs set
	// Else if the rhs set is any-policy, combine its qualifiers with the
	// policies in the lhs set
	// Else, intersect the policy sets.
	CertPolicyList::const_iterator iLhsAny = this->Find(SNACC::anyPolicy);
	CertPolicyList::const_iterator iRhsAny = rhs.Find(SNACC::anyPolicy);
	if (iLhsAny != this->end())
	{
		// Copy the rhs set
		result = rhs;
		
		// Combine the qualifiers
		CertPolicyList::iterator i;
		for (i = result.begin(); i != result.end(); i++)
			*i |= iLhsAny->qualifiers;
	}
	else if (iRhsAny != rhs.end())
	{
		// Copy this set
		result = *this;
		
		// Combine the qualifiers
		CertPolicyList::iterator i;
		for (i = result.begin(); i != result.end(); i++)
			*i |= iRhsAny->qualifiers;
	}
	else     // Neither set is the any-policy
	{
		// For each of the policies in the lhs set...
		CertPolicyList::const_iterator i;
		for (i = this->begin(); i != this->end(); i++)
		{
			// Find the matching policy OID in the rhs set
			CertPolicyList::const_iterator rhsMatch = rhs.Find(i->policyId);
			
			// If a match was found, copy this policy into the result and
			// combine the qualifiers
			if (rhsMatch != rhs.end())
			{
				CertPolicyList::iterator newPolicy =
					result.insert(result.end(), *i);
				*newPolicy |= rhsMatch->qualifiers;
			}
		}
	}
	
	return result;
}


// Intersect the rhs policy set with the lhs policy set
//CertPolicyList& operator&=(CertPolicyList& lhs, const CertPolicyList& rhs)
//{
//}


// Compute the union of the two policy sets and return the result
//CertPolicyList operator|(const CertPolicyList& lhs, const CertPolicyList& rhs)
//{
//}


// Compute the union of the rhs policy set and the lhs policy set
//CertPolicyList& operator|=(CertPolicyList& lhs, const CertPolicyList& rhs)
//{
//}


////////////////////////////////////////////////
// CertPoliciesExtension class implementation //
////////////////////////////////////////////////
CertPoliciesExtension::CertPoliciesExtension() :
Extension(SNACC::id_ce_certificatePolicies)
{
}


CertPoliciesExtension::CertPoliciesExtension(const SNACC::CertificatePoliciesSyntax& snacc,
											 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_certificatePolicies, pCriticalFlag), CertPolicyList(snacc)
{
}


CertPoliciesExtension& CertPoliciesExtension::operator=(const SNACC::CertificatePoliciesSyntax& snacc)
{
	CertPolicyList::operator=(snacc);
	return *this;
}


bool CertPoliciesExtension::operator==(const CertPoliciesExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	return CertPolicyList::operator==(rhs);
}


////////////////////////////////////////
// PolicyMapping class implementation //
////////////////////////////////////////
PolicyMapping::PolicyMapping(const SNACC::AsnOid& fromPolicy,
							 const SNACC::AsnOid& toPolicy) :
issuerPolicy(fromPolicy), subjectPolicy(toPolicy)
{
}


PolicyMapping::PolicyMapping(const SNACC::PolicyMappingsSyntaxSeq& snacc) :
issuerPolicy(snacc.issuerDomainPolicy), subjectPolicy(snacc.subjectDomainPolicy)
{
}


bool PolicyMapping::operator==(const PolicyMapping& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (issuerPolicy != rhs.issuerPolicy)
		return false;
	return (subjectPolicy == rhs.subjectPolicy);
}

bool PolicyMapping::operator<(const PolicyMapping& that) const
{
	if (this == &that)
		return false;

	if (issuerPolicy < that.issuerPolicy)
		return true;
	if ((issuerPolicy == that.issuerPolicy) && (subjectPolicy < that.subjectPolicy))
		return true;

	return false;
}

void PolicyMapping::FillSnaccMapping(SNACC::PolicyMappingsSyntaxSeq& snacc) const
{
	snacc.issuerDomainPolicy = issuerPolicy;
	snacc.subjectDomainPolicy = subjectPolicy;
}


Pol_maps_struct* PolicyMapping::GetPolicyMapping() const
{
	Pol_maps_struct* pMap = (Pol_maps_struct*)calloc(1, sizeof(Pol_maps_struct));
	if (pMap == NULL)
		throw MEMORY_EXCEPTION;
	try {
		pMap->issuer_pol_id = issuerPolicy.GetChar();
		pMap->subj_pol_id = subjectPolicy.GetChar();
		return pMap;
	}
	catch (...) {
		Internal::FreePolicyMaps(pMap);
		throw;
	}
}


//////////////////////////////////////////////////
// PolicyMappingsExtension class implementation //
//////////////////////////////////////////////////
PolicyMappingsExtension::PolicyMappingsExtension() :
Extension(SNACC::id_ce_policyMappings)
{
}


PolicyMappingsExtension::PolicyMappingsExtension(const SNACC::PolicyMappingsSyntax& snacc,
												 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_policyMappings, pCriticalFlag)
{
	operator=(snacc);
}


PolicyMappingsExtension& PolicyMappingsExtension::operator=(const SNACC::PolicyMappingsSyntax& snacc)
{
	clear();
	
	SNACC::PolicyMappingsSyntax::const_iterator i;
	for (i = snacc.begin(); i != snacc.end(); ++i)
		push_back(*i);
	
	return *this;
}


bool PolicyMappingsExtension::operator==(const PolicyMappingsExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	return (std::list<PolicyMapping>(*this) == rhs);
}


SNACC::AsnType* PolicyMappingsExtension::GetSnaccValue() const
{
	SNACC::PolicyMappingsSyntax* result = NULL;
	try {
		result = new SNACC::PolicyMappingsSyntax();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		for (const_iterator i = begin(); i != end(); i++)
			i->FillSnaccMapping(*result->append());
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* PolicyMappingsExtension::GetExtensionValue() const
{
	Pol_maps_struct* pList = NULL;
	try {
		for (const_reverse_iterator i = rbegin(); i != rend(); i++)
		{
			Pol_maps_struct* pNew = i->GetPolicyMapping();
			pNew->next = pList;
			pList = pNew;
		}
		return pList;
	}
	catch (...) {
		Internal::FreePolicyMaps(pList);
		throw;
	}
}


////////////////////////////////////////////////////
// BasicConstraintsExtension class implementation //
////////////////////////////////////////////////////
BasicConstraintsExtension::BasicConstraintsExtension() :
Extension(SNACC::id_ce_basicConstraints)
{
	isCA = false;
	m_cAFlagPresent = false;
	pathLen = -1;
}


BasicConstraintsExtension::BasicConstraintsExtension(const SNACC::BasicConstraintsSyntax& snacc,
													 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_basicConstraints, pCriticalFlag)
{
	operator=(snacc);
}


BasicConstraintsExtension& BasicConstraintsExtension::operator=(const SNACC::BasicConstraintsSyntax& snacc)
{
	if (snacc.cA == NULL)
	{
		isCA = false;
		m_cAFlagPresent = false;
	}
	else
	{
		isCA = bool(*snacc.cA);
		m_cAFlagPresent = true;
	}
	
	if (snacc.pathLenConstraint == NULL)
		pathLen = -1;
	else
	{
		try {
			pathLen = *snacc.pathLenConstraint;
		}
		catch (SNACC::SnaccException& ) {
			throw ASN_EXCEPTION("SNACC::BasicConstraintsSyntax::pathLenConstraint must be >= 0");
		}
		if (pathLen < 0)
			throw ASN_EXCEPTION("SNACC::BasicConstraintsSyntax::pathLenConstraint must be >= 0");
	}
	return *this;
}


bool BasicConstraintsExtension::operator==(const BasicConstraintsExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	if (isCA != rhs.isCA)
		return false;
	return (pathLen == rhs.pathLen);
}


SNACC::AsnType* BasicConstraintsExtension::GetSnaccValue() const
{
	SNACC::BasicConstraintsSyntax* result = NULL;
	try {
		result = new SNACC::BasicConstraintsSyntax();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		if (isCA || m_cAFlagPresent)
		{
			if (result->cA != NULL)
				*result->cA = isCA;
			else
			{
				result->cA = new SNACC::AsnBool(isCA);
				if (result->cA == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		else if (result->cA != NULL)
		{
			delete result->cA;
			result->cA = NULL;
		}

		if (pathLen >= 0)
		{
			result->pathLenConstraint = new SNACC::BasicConstraintsSyntax::
				PathLenConstraint(pathLen);
			if (result->pathLenConstraint == NULL)
				throw MEMORY_EXCEPTION;
		}
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* BasicConstraintsExtension::GetExtensionValue() const
{
	Basic_cons_struct* pResult = (Basic_cons_struct*)
		malloc(sizeof(Basic_cons_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;
	
	if (isCA)
		pResult->cA_flag = TRUE;
	else
		pResult->cA_flag = FALSE;
	
	if ((pathLen < 0) || (pathLen > SHRT_MAX))
		pResult->max_path = CM_NOT_PRESENT;
	else
		pResult->max_path = short(pathLen);
	
	return pResult;
}


/////////////////////////////////////////
// GeneralSubtree class implementation //
/////////////////////////////////////////
GeneralSubtree::GeneralSubtree()
{
	min = 0;
	max = -1;
}


GeneralSubtree::GeneralSubtree(const GenName& baseGN, long minDistance,
							   long maxDistance) : base(baseGN)
{
	min = minDistance;
	max = maxDistance;
}


GeneralSubtree::GeneralSubtree(const SNACC::GeneralSubtree& snacc)
{
	operator=(snacc);
}


GeneralSubtree& GeneralSubtree::operator=(const SNACC::GeneralSubtree& snacc)
{
	base = snacc.base;
	if (snacc.minimum == NULL)
		min = 0;
	else
		min = *snacc.minimum;
	
	if (snacc.maximum == NULL)
		max = -1;
	else
		max = *snacc.maximum;
	
	return *this;
}


bool GeneralSubtree::operator==(const GeneralSubtree& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (base != rhs.base)
		return false;
	if (min != rhs.min)
		return false;
	return (max == rhs.max);
}


bool GeneralSubtree::IsSameType(const GeneralSubtree& other) const
{
	return (base.GetType() == other.base.GetType());
}

void GeneralSubtree::FillSnaccSubtree(SNACC::GeneralSubtree& snacc) const
{
	base.FillSnaccGenName(snacc.base);

	if (snacc.minimum != NULL)
		*snacc.minimum = min;
	else
	{
		snacc.minimum = new SNACC::BaseDistance(min);
		if (snacc.minimum == NULL)
			throw MEMORY_EXCEPTION;
	}
	
	if (max < 0)
		snacc.maximum = NULL;
	else
	{
		snacc.maximum = new SNACC::BaseDistance(max);
		if (snacc.maximum == NULL)
			throw MEMORY_EXCEPTION;
	}
}


Subtree_struct* GeneralSubtree::GetSubtreeStruct() const
{
	Subtree_struct* pSubtree = (Subtree_struct*)
		calloc(1, sizeof(Subtree_struct));
	if (pSubtree == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		base.FillGenNameStruct(pSubtree->base);
		pSubtree->min = short(min);
		if (max < 0)
			pSubtree->max = CM_NOT_PRESENT;
		else
			pSubtree->max = short(max);
		return pSubtree;
	}
	catch (...) {
		Internal::FreeSubtrees(&pSubtree);
		throw;
	}
}


bool GeneralSubtree::IsNameWithin(const DN& dn) const
{
	if (base.GetType() != GenName::X500)
		return false;

	if (base.GetName().dn == NULL)
		throw EXCEPTION(CMLASN_NULL_POINTER);
			
	// Initialize local RDN list variables
	const std::list<RelativeDN>& baseDnList = base.GetName().dn->GetRDNList();
	const std::list<RelativeDN>& otherDnList = dn.GetRDNList();
			
	// Check that the other DN is part of the base DN's branch in the DIT
	std::list<RelativeDN>::const_iterator iBaseDN = baseDnList.begin();
	std::list<RelativeDN>::const_iterator iOtherDN = otherDnList.begin();
	for ( ; iBaseDN != baseDnList.end(); ++iBaseDN, ++iOtherDN)
	{
		if ((iOtherDN == otherDnList.end()) || (*iBaseDN != *iOtherDN))
			return false;
	}
			
	// Count the number of remaining branches in the other DN
	int numBranches = 0;
	while (iOtherDN != otherDnList.end())
	{
		++numBranches;
		++iOtherDN;
	}
			
	// Return true if the number of remaining branches falls within the
	// min and max values
	if (numBranches < min)
		return false;
	if ((max >= 0) && (numBranches > max))
		return false;
	return true;
};


bool GeneralSubtree::IsNameWithin(const GenName& gn) const
{
	using CML::striEnd;

	if (base.GetType() != gn.GetType())
		return false;
	
	switch (base.GetType())
	{
	case GenName::OTHER:
		if ((gn.GetName().other == NULL) || (base.GetName().other == NULL))
			throw EXCEPTION(CMLASN_NULL_POINTER);
		if (gn.GetName().other->id != base.GetName().other->id)
			return false;
		else
		{
			throw EXCEPTION_STR(CMLASN_NOT_IMPLEMENTED,
				"Name constraints processing for GeneralName::otherName is unsupported");
		}
		break;
		
	case GenName::RFC822:
		{
			// Access the RFC822 name and constraint
			const char* name = gn.GetName().name;
			const char* constraint = base.GetName().name;
			
			return checkEmailConstraint(name, constraint, min, max);
		}
	case GenName::DNS:
		{
			// Access the DNS name and constraint
			const char* name = gn.GetName().name;
			const char* constraint = base.GetName().name;
			
			// Determine if the constraint applies to this name
			const char* pEnd = striEnd(name, constraint);
			if (pEnd == NULL)
				return false;
			
			if (pEnd == name)
			{
				// The constraint exactly matches the name, so return true if
				// min is zero, else return false
				if (min == 0)
					return true;
				else
					return false;
			}
			else if (*(--pEnd) == '.')
			{
				// The constraint specifies a domain, so count the number of
				// unmatched domain components
				int nUnmatched = 1;
				for (const char* pStr = pEnd - 1; pStr != name; pStr--)
				{
					if (*pStr == '.')
						++nUnmatched;
				}
				
				// Return true if the number of unmatched domain components
				// falls within the min and max values
				if ((nUnmatched >= min) && ((max < 0) || (nUnmatched <= max)))
					return true;
				else
					return false;
			}
			else
				return false;
		}
	case GenName::X400:
		throw EXCEPTION_STR(CMLASN_NOT_IMPLEMENTED,
			"Name constraints processing for GeneralName::x400Address is unsupported");
		
	case GenName::X500:
		{
			if ((gn.GetName().dn == NULL) || (base.GetName().dn == NULL))
				throw EXCEPTION(CMLASN_NULL_POINTER);
			
			// Initialize local RDN list variables
			const std::list<RelativeDN>& baseDnList =
				base.GetName().dn->GetRDNList();
			const std::list<RelativeDN>& otherDnList =
				gn.GetName().dn->GetRDNList();
			
			// Check that the other DN is part of the base DN's branch in the DIT
			std::list<RelativeDN>::const_iterator iBaseDN = baseDnList.begin();
			std::list<RelativeDN>::const_iterator iOtherDN = otherDnList.begin();
			for ( ; iBaseDN != baseDnList.end(); iBaseDN++, iOtherDN++)
			{
				if ((iOtherDN == otherDnList.end()) || (*iBaseDN != *iOtherDN))
					return false;
			}
			
			// Count the number of remaining branches in the other DN
			int numBranches = 0;
			while (iOtherDN != otherDnList.end())
			{
				++numBranches;
				++iOtherDN;
			}
			
			// Return true if the number of remaining branches falls within the
			// min and max values
			if (numBranches < min)
				return false;
			if ((max >= 0) && (numBranches > max))
				return false;
			return true;
		}
	case GenName::EDI:
		throw EXCEPTION_STR(CMLASN_NOT_IMPLEMENTED,
			"Name constraints processing for GeneralName::ediPartyName is unsupported");
		
	case GenName::URL:
		{
			// Access the URL host name and constraint
			char* name = CML::ParseHostFromURL(gn.GetName().name);
			const char* constraint = base.GetName().name;
			
			// Determine if the constraint applies to this name
			bool result;
			const char* pEnd = striEnd(name, constraint);
			if (pEnd == NULL)
				result = false;
			else if (pEnd == name)
			{
				// The constraint exactly matches the name, so return true if
				// min is zero, else return false
				if (min == 0)
					result = true;
				else
					result = false;
			}
			else if (*pEnd == '.')
			{
				// The constraint specifies a domain, so count the number of
				// unmatched domain components
				int nUnmatched = 1;
				for (const char* pStr = pEnd - 1; pStr != name; pStr--)
				{
					if (*pStr == '.')
						++nUnmatched;
				}
				
				// Return true if the number of unmatched domain components
				// falls within the min and max values
				if ((nUnmatched >= min) && ((max < 0) || (nUnmatched <= max)))
					result = true;
				else
					result = false;
			}
			else
				result = false;
			
			delete[] name;
			return result;
		}

	case GenName::IP_ADDR:
		{
			// Get the IP Addresses
			const IPAddress* name = gn.GetName().ipAddr;
			const IPAddress* constraint = base.GetName().ipAddr;

			// Check that the IP address and constraint are present
			if ((name == NULL) || (constraint == NULL))
				throw EXCEPTION(CMLASN_NULL_POINTER);

			// Check the constraints
			if (constraint->Matches(*name))
				return true;
			else
				return false;
		}
		
	case GenName::REG_OID:
		throw EXCEPTION_STR(CMLASN_NOT_IMPLEMENTED,
			"Name constraints processing for GeneralName::registeredID is unsupported");
		
	default:
		throw EXCEPTION_STR(CMLASN_UNKNOWN_ERROR,
			"Invalid GeneralName CHOICE in GeneralSubtree");
	}
}


////////////////////////////////////
// NameForms class implementation //
////////////////////////////////////
NameForms& NameForms::operator=(const SNACC::NameForms& snacc)
{
	Clear();
	
	try {
		if (snacc.basicNameForms != NULL)
		{
			basicNames = *snacc.basicNameForms;
			if (basicNames.BitLen() == 0)
				throw ASN_EXCEPTION("BasicNameForms must contain at least one bit");
		}
		else if (snacc.otherNameForms == NULL)
			throw ASN_EXCEPTION("At least one NameForms component must be present");
		
		if (snacc.otherNameForms != NULL)
		{
			if (snacc.otherNameForms->empty())
				throw ASN_EXCEPTION("NameForms::otherNameForms must contain at least one OID");

			SNACC::NameFormsSeqOf::const_iterator i =
				snacc.otherNameForms->begin(); 
			for ( ; i != snacc.otherNameForms->end(); ++i)
				otherNames.push_back(*i);
		}
		
		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


bool NameForms::operator==(const NameForms& rhs) const
{
	if (basicNames != rhs.basicNames)
		return false;
	
	return (otherNames == rhs.otherNames);
}


void NameForms::Clear()
{
	basicNames.Set(0);
	otherNames.clear();
}


bool NameForms::IsNamePresent(const GenNames* names) const
{
	// If none of the name forms are required, return true
	if (IsEmpty())
		return true;
	
	// If the list of GenNames is absent or empty, return false
	if ((names == NULL) || names->empty())
		return false;
	
	// Check if any of the basic name forms are required
	for (int i = SNACC::BasicNameForms::rfc822Name; i <=
		SNACC::BasicNameForms::registeredID; i++)
	{
		if (basicNames.GetBit(i))
		{
			GenName::Type typeToFind = GenName::OTHER;
			switch (i)
			{
			case SNACC::BasicNameForms::rfc822Name:
				typeToFind = GenName::RFC822;
				break;
			case SNACC::BasicNameForms::dNSName:
				typeToFind = GenName::DNS;
				break;
			case SNACC::BasicNameForms::x400Address:
				typeToFind = GenName::X400;
				break;
			case SNACC::BasicNameForms::directoryName:
				typeToFind = GenName::X500;
				break;
			case SNACC::BasicNameForms::ediPartyName:
				typeToFind = GenName::EDI;
				break;
			case SNACC::BasicNameForms::uniformResourceIdentifier:
				typeToFind = GenName::URL;
				break;
			case SNACC::BasicNameForms::iPAddress:
				typeToFind = GenName::IP_ADDR;
				break;
			case SNACC::BasicNameForms::registeredID:
				typeToFind = GenName::REG_OID;
				break;
			}
			
			// If the required name form is present in the list, return true
			if ((typeToFind != GenName::OTHER) &&
				(names->Find(typeToFind) != names->end()))
				return true;
		}
	}
	
	// Check if any of the other name forms are present
	OIDList::const_iterator iOid;
	for (iOid = otherNames.begin(); iOid != otherNames.end(); iOid++)
	{
		GenNames::const_iterator gn = names->Find(GenName::OTHER);
		while (gn != names->end())
		{
			const GenName::Form& name = gn->GetName();
			if ((name.other != NULL) && (*iOid == name.other->id))
				return true;
			
			gn = names->FindNext(gn, GenName::OTHER);
		}
	}
	
	return false;
}


bool NameForms::IsEmpty() const
{
	return (basicNames.IsEmpty() && otherNames.empty());
}


SNACC::NameForms* NameForms::GetSnacc() const
{
	if (IsEmpty())
		return NULL;
	
	SNACC::NameForms* result = new SNACC::NameForms;
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (!basicNames.IsEmpty())
		{
			result->basicNameForms = new SNACC::BasicNameForms(basicNames);
			if (result->basicNameForms == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		if (!otherNames.empty())
		{
			result->otherNameForms = new SNACC::NameFormsSeqOf;
			if (result->otherNameForms == NULL)
				throw MEMORY_EXCEPTION;
			result->otherNameForms->assign(otherNames.begin(),
				otherNames.end());
		}
		
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


//////////////////////////////////////////
// GeneralSubtrees class implementation //
//////////////////////////////////////////
GeneralSubtrees::GeneralSubtrees(const SNACC::GeneralSubtrees& snacc)
{
	operator=(snacc);
}


GeneralSubtrees& GeneralSubtrees::operator=(const SNACC::GeneralSubtrees& snacc)
{
	if (snacc.empty())
		throw ASN_EXCEPTION("GeneralSubtrees must contain at least one GeneralSubtree");
	
	SNACC::GeneralSubtrees::const_iterator i;
	for (i = snacc.begin(); i != snacc.end(); ++i)
		push_back(*i);
	
	return *this;
}


bool GeneralSubtrees::AreNamesWithin(const GenNames& names,
									 bool usePermittedRules) const
{
	GenNames::const_iterator iName;
	for (iName = names.begin(); iName != names.end(); iName++)
	{
		if (IsNameWithin(*iName, usePermittedRules))
		{
			if (!usePermittedRules)
				return true;
		}
		else if (usePermittedRules)
			return false;
	}
	
	if (usePermittedRules)
		return true;
	else
		return false;
}


bool GeneralSubtrees::IsNameWithin(const DN& dn, bool usePermittedRules) const
{
	bool isWithin = usePermittedRules;
	
	for (const_iterator i = begin(); i != end(); i++)
	{
		if (i->base.GetType() == GenName::X500)
		{
			if (i->IsNameWithin(dn))
				return true;
			
			if (isWithin)	// true only when using permitted rules
				isWithin = false;
		} else if (i->base.GetType() == GenName::RFC822)
		{
			// Initialize local RDN list variables
			const std::list<RelativeDN>& otherDnList = dn.GetRDNList();
			std::list<RelativeDN>::const_iterator iOtherDN = otherDnList.begin();
			//check the DN for email addresses
			for ( ; iOtherDN != otherDnList.end(); ++iOtherDN)
			{				
				RelativeDN rdn = *iOtherDN;
				std::string email;
				if (rdn.containsPKCS9EmailAddress(email))
				{
					//This RDN contains a PKCS9 Email Address. Check it against constraints
					if (checkEmailConstraint(email.c_str(), i->base.GetName().name, i->min, i->max))
						return true;
					
					if (isWithin)	// true only when using permitted rules
						isWithin = false;
				}
			}
		}
	}
	return isWithin;
}


bool GeneralSubtrees::IsNameWithin(const GenName& gn,
								   bool usePermittedRules) const
{
	bool isWithin = usePermittedRules;

	for (const_iterator i = begin(); i != end(); i++)
	{
		if (i->base.GetType() == gn.GetType())
		{
			if (i->IsNameWithin(gn))
				return true;
			
			if (isWithin)	// true only when using permitted rules
				isWithin = false;
		}
	}
	return isWithin;
}


SNACC::GeneralSubtrees* GeneralSubtrees::GetSnacc() const
{
	SNACC::GeneralSubtrees* result = new SNACC::GeneralSubtrees();
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		for (const_iterator i = begin(); i != end(); i++)
			i->FillSnaccSubtree(*result->append());
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


Subtree_struct* GeneralSubtrees::GetSubtreeList() const
{
	Subtree_struct* pResult = NULL;
	try {
		for (const_reverse_iterator i = rbegin(); i != rend(); i++)
		{
			Subtree_struct* pNew = i->GetSubtreeStruct();
			pNew->next = pResult;
			pResult = pNew;
		}
		return pResult;
	}
	catch (...) {
		Internal::FreeSubtrees(&pResult);
		throw;
	}
}


///////////////////////////////////////////////////
// NameConstraintsExtension class implementation //
///////////////////////////////////////////////////
NameConstraintsExtension::NameConstraintsExtension(const SNACC::AsnOid& extnId) :
Extension(extnId)
{
}


NameConstraintsExtension::NameConstraintsExtension(const SNACC::AsnOid& extnId,
												   const SNACC::NameConstraintsSyntax& snacc,
												   const SNACC::AsnBool* pCriticalFlag) :
Extension(extnId, pCriticalFlag)
{
	operator=(snacc);
}


NameConstraintsExtension& NameConstraintsExtension::operator=(const SNACC::NameConstraintsSyntax& snacc)
{
	permitted.clear();
	excluded.clear();
	requiredNames.Clear();
	
	try {
		if (snacc.permittedSubtrees != NULL)
			permitted = *snacc.permittedSubtrees;
		
		if (snacc.excludedSubtrees != NULL)
			excluded = *snacc.excludedSubtrees;
		
		if (snacc.requiredNameForms != NULL)
			requiredNames = *snacc.requiredNameForms;
		
		return *this;
	}
	catch (...) {
		permitted.clear();
		excluded.clear();
		requiredNames.Clear();
		throw;
	}
}


bool NameConstraintsExtension::operator==(const NameConstraintsExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	// Need to check OIDs, since there are two different ones
	if (m_extnId != rhs.m_extnId)
		return false;
	
	if (critical != rhs.critical)
		return false;
	
	if (permitted != rhs.permitted)
		return false;
	
	if (excluded != rhs.excluded)
		return false;
	
	return (requiredNames == rhs.requiredNames);
}


SNACC::AsnType* NameConstraintsExtension::GetSnaccValue() const
{
	SNACC::NameConstraintsSyntax* result = NULL;
	try {
		result = new SNACC::NameConstraintsSyntax();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		if (!permitted.empty())
			result->permittedSubtrees = permitted.GetSnacc();
		
		if (!excluded.empty())
			result->excludedSubtrees = excluded.GetSnacc();
		
		// Only include requiredNameForms for new name constraints OID
		if (m_extnId == SNACC::id_ce_nameConstraint)
			result->requiredNameForms = requiredNames.GetSnacc();
		
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* NameConstraintsExtension::GetExtensionValue() const
{
	Name_cons_struct* pNameCons = (Name_cons_struct*)
		calloc(1, sizeof(Name_cons_struct));
	if (pNameCons == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		pNameCons->permitted = permitted.GetSubtreeList();
		pNameCons->excluded = excluded.GetSubtreeList();
		
		if (!requiredNames.basicNames.IsEmpty())
		{
			pNameCons->basicNames = (ushort*)
				cvt_AsnBitMask(requiredNames.basicNames);
		}
		
		if (!requiredNames.otherNames.empty())
		{
			OIDList::const_reverse_iterator i;
			for (i = requiredNames.otherNames.rbegin(); i !=
				requiredNames.otherNames.rend(); i++)
			{
				CM_OID_LL* pNew = (CM_OID_LL*)malloc(sizeof(CM_OID_LL));
				if (pNew == NULL)
					throw MEMORY_EXCEPTION;
				pNew->next = pNameCons->otherNames;
				pNameCons->otherNames = pNew;
				
				pNew->oid = i->GetChar();
			}
		}
		
		return pNameCons;
	}
	catch (...) {
		Internal::FreeSubtrees(&pNameCons->permitted);
		Internal::FreeSubtrees(&pNameCons->excluded);
		if (pNameCons->basicNames != NULL)
			free(pNameCons->basicNames);
		Internal::FreeOIDList(pNameCons->otherNames);
		free(pNameCons);
		throw;
	}
}


/////////////////////////////////////////////////////
// PolicyConstraintsExtension class implementation //
/////////////////////////////////////////////////////
PolicyConstraintsExtension::PolicyConstraintsExtension() :
Extension(SNACC::id_ce_policyConstraints)
{
	requireExplicitPolicy = -1;
	inhibitPolicyMapping = -1;
}


PolicyConstraintsExtension::PolicyConstraintsExtension(const SNACC::PolicyConstraintsSyntax& snacc,
													   const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_policyConstraints, pCriticalFlag)
{
	operator=(snacc);
}



PolicyConstraintsExtension& PolicyConstraintsExtension::operator=(const SNACC::PolicyConstraintsSyntax& snacc)
{
	if (snacc.requireExplicitPolicy == NULL)
		requireExplicitPolicy = -1;
	else
	{
		requireExplicitPolicy = *snacc.requireExplicitPolicy;
		if (requireExplicitPolicy < 0)
			throw ASN_EXCEPTION("SNACC::PolicyConstraintsSyntax::requireExplicitPolicy must be >= 0");
	}
	
	if (snacc.inhibitPolicyMapping == NULL)
		inhibitPolicyMapping = -1;
	else
	{
		inhibitPolicyMapping = *snacc.inhibitPolicyMapping;
		if (inhibitPolicyMapping < 0)
			throw ASN_EXCEPTION("SNACC::PolicyConstraintsSyntax::inhibitPolicyMapping must be >= 0");
	}
	
	return *this;
}


bool PolicyConstraintsExtension::operator==(const PolicyConstraintsExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	if (requireExplicitPolicy != rhs.requireExplicitPolicy)
		return false;
	
	return (inhibitPolicyMapping == rhs.inhibitPolicyMapping);
}


SNACC::AsnType* PolicyConstraintsExtension::GetSnaccValue() const
{
	SNACC::PolicyConstraintsSyntax* result = NULL;
	try {
		result = new SNACC::PolicyConstraintsSyntax();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		if (requireExplicitPolicy >= 0)
		{
			result->requireExplicitPolicy = new
				SNACC::SkipCerts(requireExplicitPolicy);
			if (result->requireExplicitPolicy == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		if (inhibitPolicyMapping >= 0)
		{
			result->inhibitPolicyMapping = new
				SNACC::SkipCerts(inhibitPolicyMapping);
			if (result->inhibitPolicyMapping == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* PolicyConstraintsExtension::GetExtensionValue() const
{
	Pol_cons_struct* pPolicyCons = (Pol_cons_struct*)
		malloc(sizeof(Pol_cons_struct));
	
	if ((requireExplicitPolicy < 0) || (requireExplicitPolicy > SHRT_MAX))
		pPolicyCons->req_explicit_pol = CM_NOT_SET;
	else
		pPolicyCons->req_explicit_pol = short(requireExplicitPolicy);
	
	if ((inhibitPolicyMapping < 0) || (inhibitPolicyMapping > SHRT_MAX))
		pPolicyCons->inhibit_mapping = CM_NOT_SET;
	else
		pPolicyCons->inhibit_mapping = short(inhibitPolicyMapping);
	
	return pPolicyCons;
}


////////////////////////////////////////////////////
// InhibitAnyPolicyExtension class implementation //
////////////////////////////////////////////////////
InhibitAnyPolicyExtension::InhibitAnyPolicyExtension() :
Extension(SNACC::id_ce_inhibitAnyPolicy)
{
	value = 0;
}


InhibitAnyPolicyExtension::InhibitAnyPolicyExtension(const SNACC::SkipCerts& snacc,
													 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_inhibitAnyPolicy, pCriticalFlag)
{
	operator=(snacc);
}


InhibitAnyPolicyExtension& InhibitAnyPolicyExtension::operator=(const SNACC::SkipCerts& snacc)
{
	if (long(snacc) < 0)
		throw ASN_EXCEPTION("SNACC::SkipCerts value must be greater than or equal to zero");
	value = snacc;
	return *this;
}


bool InhibitAnyPolicyExtension::operator==(const InhibitAnyPolicyExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	return ((critical == rhs.critical) && (value == rhs.value));
}


SNACC::AsnType* InhibitAnyPolicyExtension::GetSnaccValue() const
{
	SNACC::SkipCerts* result = new SNACC::SkipCerts(value);
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	return result;
}


void* InhibitAnyPolicyExtension::GetExtensionValue() const
{
	ushort* pValue = (ushort*)malloc(sizeof(ushort));
	if (pValue == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (value > ushort(-1))
			throw ASN_EXCEPTION("SNACC::SkipCerts integer value out of range");
		*pValue = ushort(value);
		return pValue;
	}
	catch (...) {
		free(pValue);
		throw;
	}
}


////////////////////////////////////////
// DistPointName class implementation //
////////////////////////////////////////
DistPointName::DistPointName(const SNACC::DistributionPointName& snacc)
{
	m_type = DIST_PT_FULL_NAME;
	m_name.full = NULL;
	operator=(snacc);
}


DistPointName::DistPointName(const GenNames& fullName)
{
	m_type = DIST_PT_FULL_NAME;
	m_name.full = new GenNames(fullName);
	if (m_name.full == NULL)
		throw MEMORY_EXCEPTION;
}


DistPointName::DistPointName(const RelativeDN& relativeName)
{
	m_type = DIST_PT_REL_NAME;
	m_name.relativeToIssuer = new RelativeDN(relativeName);
	if (m_name.relativeToIssuer == NULL)
		throw MEMORY_EXCEPTION;
}


DistPointName::DistPointName(const DistPointName& that)
{
	m_type = DIST_PT_FULL_NAME;
	m_name.full = NULL;
	operator=(that);
}


DistPointName& DistPointName::operator=(const SNACC::DistributionPointName& snacc)
{
	Clear();
	
	switch (snacc.choiceId)
	{
	case SNACC::DistributionPointName::fullNameCid:
		m_type = DIST_PT_FULL_NAME;
		
		if (snacc.fullName == NULL)
			throw ASN_EXCEPTION("DistributionPointName::fullName field is NULL");
		
		m_name.full = new GenNames(*snacc.fullName);
		if (m_name.full == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case SNACC::DistributionPointName::nameRelativeToCRLIssuerCid:
		m_type = DIST_PT_REL_NAME;
		
		if (snacc.nameRelativeToCRLIssuer == NULL)
			throw ASN_EXCEPTION("DistributionPointName::nameRelativeToCRLIssuer field is NULL");
		
		m_name.relativeToIssuer = new RelativeDN(*snacc.nameRelativeToCRLIssuer);
		if (m_name.relativeToIssuer == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	default:
		throw ASN_EXCEPTION("Invalid CHOICE in DistributionPointName");
	}
	
	return *this;
}


DistPointName& DistPointName::operator=(const GenNames& fullName)
{
	Clear();
	m_type = DIST_PT_FULL_NAME;
	m_name.full = new GenNames(fullName);
	if (m_name.full == NULL)
		throw MEMORY_EXCEPTION;
	return *this;
}


DistPointName& DistPointName::operator=(const RelativeDN& relativeName)
{
	Clear();
	m_type = DIST_PT_REL_NAME;
	m_name.relativeToIssuer = new RelativeDN(relativeName);
	if (m_name.relativeToIssuer == NULL)
		throw MEMORY_EXCEPTION;
	return *this;
}


DistPointName& DistPointName::operator=(const DistPointName& other)
{
	if (this != &other)
	{
		Clear();
		
		m_type = other.GetType();
		switch (m_type)
		{
		case DIST_PT_FULL_NAME:
			m_name.full = new GenNames(*other.m_name.full);
			if (m_name.full == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case DIST_PT_REL_NAME:
			m_name.relativeToIssuer = new
				RelativeDN(*other.m_name.relativeToIssuer);
			if (m_name.relativeToIssuer == NULL)
				throw MEMORY_EXCEPTION;
			break;
		}
	}
	return *this;
}


bool DistPointName::operator==(const DistPointName& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (m_type != rhs.m_type)
		return false;
	
	switch (m_type)
	{
	case DIST_PT_FULL_NAME:
		if ((m_name.full == NULL) || (rhs.m_name.full == NULL))
			throw EXCEPTION(CMLASN_NULL_POINTER);
		return (*m_name.full == *rhs.m_name.full);
		
	case DIST_PT_REL_NAME:
		if ((m_name.relativeToIssuer == NULL) ||
			(rhs.m_name.relativeToIssuer == NULL))
			throw Exception(CMLASN_NULL_POINTER, __FILE__, __LINE__);
		return (*m_name.relativeToIssuer == *rhs.m_name.relativeToIssuer);
		
	default:
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
	}
}


void DistPointName::FillDistPtNameStruct(Dist_pt_name& dpName) const
{
	switch (m_type)
	{
	case DIST_PT_FULL_NAME:
		if (m_name.full == NULL)
			throw EXCEPTION(CMLASN_NULL_POINTER);
		
		dpName.flag = CM_DIST_PT_FULL_NAME;
		dpName.name.full = m_name.full->GetGenNamesList();
		break;
		
	case DIST_PT_REL_NAME:
		if (m_name.relativeToIssuer == NULL)
			throw EXCEPTION(CMLASN_NULL_POINTER);
		
		dpName.flag = CM_DIST_PT_RELATIVE_NAME;
		dpName.name.relative = strdup(*m_name.relativeToIssuer);
		if (dpName.name.relative == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	default:
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
	}
}


SNACC::DistributionPointName* DistPointName::GetSnacc() const
{
	SNACC::DistributionPointName* result = NULL;
	try {
		result = new SNACC::DistributionPointName();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		switch (m_type)
		{
		case DIST_PT_FULL_NAME:
			result->choiceId = SNACC::DistributionPointName::fullNameCid;
			if (m_name.full == NULL)
				throw Exception(CMLASN_NULL_POINTER, __FILE__, __LINE__);
			result->fullName = m_name.full->GetSnacc();
			break;
			
		case DIST_PT_REL_NAME:
			result->choiceId =
				SNACC::DistributionPointName::nameRelativeToCRLIssuerCid;
			if (m_name.relativeToIssuer == NULL)
				throw Exception(CMLASN_NULL_POINTER, __FILE__, __LINE__);
			result->nameRelativeToCRLIssuer = new
				SNACC::RelativeDistinguishedName(m_name.relativeToIssuer->GetSnaccRDN());
			if (result->nameRelativeToCRLIssuer == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}

const GenNames& DistPointName::GetFullName() const
{
	if (m_type != DIST_PT_FULL_NAME)
		throw EXCEPTION(CMLASN_INVALID_PARAMETER);
	if (m_name.full == NULL)
		throw EXCEPTION(CMLASN_NULL_POINTER);
	return *m_name.full;
}


GenNames& DistPointName::GetFullName()
{
	if (m_type != DIST_PT_FULL_NAME)
		throw EXCEPTION(CMLASN_INVALID_PARAMETER);
	if (m_name.full == NULL)
		throw EXCEPTION(CMLASN_NULL_POINTER);
	return *m_name.full;
}


const RelativeDN& DistPointName::GetRelativeName() const
{
	if (m_type != DIST_PT_REL_NAME)
		throw EXCEPTION(CMLASN_INVALID_PARAMETER);
	if (m_name.relativeToIssuer == NULL)
		throw EXCEPTION(CMLASN_NULL_POINTER);
	return *m_name.relativeToIssuer;
}


RelativeDN& DistPointName::GetRelativeName()
{
	if (m_type != DIST_PT_REL_NAME)
		throw EXCEPTION(CMLASN_INVALID_PARAMETER);
	if (m_name.relativeToIssuer == NULL)
		throw EXCEPTION(CMLASN_NULL_POINTER);
	return *m_name.relativeToIssuer;
}


void DistPointName::Clear()
{
	switch (m_type)
	{
	case DIST_PT_FULL_NAME:
		if (m_name.full != NULL)
			delete m_name.full;
		m_name.full = NULL;
		break;
		
	case DIST_PT_REL_NAME:
		if (m_name.relativeToIssuer != NULL)
			delete m_name.relativeToIssuer;
		m_name.relativeToIssuer = NULL;
		break;
	}
}


////////////////////////////////////////////
// DistributionPoint class implementation //
////////////////////////////////////////////
DistributionPoint::DistributionPoint()
{
	distPoint = NULL;
	reasons = NULL;
	crlIssuer = NULL;
}


DistributionPoint::DistributionPoint(const SNACC::DistributionPoint& snacc)
{
	distPoint = NULL;
	reasons = NULL;
	crlIssuer = NULL;
	operator=(snacc);
}


DistributionPoint::DistributionPoint(const DistributionPoint& that)
{
	distPoint = NULL;
	reasons = NULL;
	crlIssuer = NULL;
	operator=(that);
}


DistributionPoint& DistributionPoint::operator=(const SNACC::DistributionPoint& snacc)
{
	Clear();
	try {
		if (snacc.distributionPoint != NULL)
		{
			distPoint = new DistPointName(*snacc.distributionPoint);
			if (distPoint == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		if (snacc.reasons != NULL)
		{
			reasons = new RevocationReasons(*snacc.reasons);
			if (reasons == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		if (snacc.cRLIssuer != NULL)
		{
			crlIssuer = new GenNames(*snacc.cRLIssuer);
			if (crlIssuer == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


DistributionPoint& DistributionPoint::operator=(const DistributionPoint& other)
{
	if (this != &other)
	{
		Clear();
		try {
			if (other.distPoint != NULL)
			{
				distPoint = new DistPointName(*other.distPoint);
				if (distPoint == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.reasons != NULL)
			{
				reasons = new RevocationReasons(*other.reasons);
				if (reasons == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.crlIssuer != NULL)
			{
				crlIssuer = new GenNames(*other.crlIssuer);
				if (crlIssuer == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		catch (...) {
			Clear();
			throw;
		}
	}
	return *this;
}


bool DistributionPoint::operator==(const DistributionPoint& rhs) const
{
	if (this == &rhs)
		return true;
	
	if ((distPoint != NULL) && (rhs.distPoint != NULL))
	{
		if (*distPoint != *rhs.distPoint)
			return false;
	}
	else if ((distPoint != NULL) || (rhs.distPoint != NULL))
		return false;
	
	if ((reasons != NULL) && (rhs.reasons != NULL))
	{
		if (*reasons != *rhs.reasons)
			return false;
	}
	else if ((reasons != NULL) || (rhs.reasons != NULL))
		return false;
	
	if ((crlIssuer == NULL) && (rhs.crlIssuer == NULL))
		return true;
	else if ((crlIssuer == NULL) || (rhs.crlIssuer == NULL))
		return false;
	else
		return (*crlIssuer == *rhs.crlIssuer);
}


void DistributionPoint::FillSnaccDistPoint(SNACC::DistributionPoint& snacc) const
{
	snacc.distributionPoint = NULL;
	snacc.reasons = NULL;
	snacc.cRLIssuer = NULL;
	
	if (distPoint != NULL)
		snacc.distributionPoint = distPoint->GetSnacc();
	
	if (reasons != NULL)
	{
		snacc.reasons = new SNACC::ReasonFlags(*reasons);
		if (snacc.reasons == NULL)
			throw MEMORY_EXCEPTION;
	}
	
	if (crlIssuer != NULL)
		snacc.cRLIssuer = crlIssuer->GetSnacc();
}


Dist_pts_struct* DistributionPoint::GetDistPointStruct() const
{
	Dist_pts_struct* pDistPt = (Dist_pts_struct*)
		calloc(1, sizeof(Dist_pts_struct));
	if (pDistPt == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (distPoint == NULL)
			pDistPt->dpName.flag = CM_NOT_PRESENT;
		else
			distPoint->FillDistPtNameStruct(pDistPt->dpName);
		
		if (reasons != NULL)
			pDistPt->reasons = (ushort*)cvt_AsnBitMask(*reasons);
		
		if (crlIssuer != NULL)
			pDistPt->crl_issuer = crlIssuer->GetGenNamesList();
		
		return pDistPt;
	}
	catch (...) {
		Internal::FreeDistPts_LL(pDistPt);
		throw;
	}
}


void DistributionPoint::Clear()
{
	if (distPoint != NULL)
	{
		delete distPoint;
		distPoint = NULL;
	}
	if (reasons != NULL)
	{
		delete reasons;
		reasons = NULL;
	}
	if (crlIssuer != NULL)
	{
		delete crlIssuer;
		crlIssuer = NULL;
	}
}


/////////////////////////////////////////////////
// CrlDistPointsExtension class implementation //
/////////////////////////////////////////////////
CrlDistPointsExtension::CrlDistPointsExtension() :
Extension(SNACC::id_ce_cRLDistributionPoints)
{
}


CrlDistPointsExtension::CrlDistPointsExtension(const SNACC::CRLDistPointsSyntax& snacc,
											   const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_cRLDistributionPoints, pCriticalFlag)
{
	operator=(snacc);
}


CrlDistPointsExtension& CrlDistPointsExtension::operator=(const SNACC::CRLDistPointsSyntax& snacc)
{
	clear();
	
	SNACC::CRLDistPointsSyntax::const_iterator i;
	for (i = snacc.begin(); i != snacc.end(); ++i)
		push_back(*i);
	
	return *this;
}


bool CrlDistPointsExtension::operator==(const CrlDistPointsExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	const_iterator j = rhs.begin();
	const_iterator i;
	for (i = begin(); (i != end()) && (j != rhs.end()); i++, j++)
	{
		if (*i != *j)
			return false;
	}
	
	return ((i == end()) && (j == rhs.end()));
}


SNACC::AsnType* CrlDistPointsExtension::GetSnaccValue() const
{
	SNACC::CRLDistPointsSyntax* result = new SNACC::CRLDistPointsSyntax();
	if (result == NULL)
		throw MEMORY_EXCEPTION;
		
	try {
		for (const_iterator i = begin(); i != end(); i++)
			i->FillSnaccDistPoint(*result->append());
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* CrlDistPointsExtension::GetExtensionValue() const
{
	Dist_pts_struct* pResult = NULL;
	
	try {
		CrlDistPointsExtension::const_reverse_iterator i;
		for (i = rbegin(); i != rend(); i++)
		{
			Dist_pts_struct* pNew = i->GetDistPointStruct();
			pNew->next = pResult;
			pResult = pNew;
		}
		return pResult;
	}
	catch (...) {
		Internal::FreeDistPts_LL(pResult);
		throw;
	}
}


/////////////////////////////////////////////
// CRLNumberExtension class implementation //
/////////////////////////////////////////////
CRLNumberExtension::CRLNumberExtension(const SNACC::CRLNumber& snacc,
									   const SNACC::AsnBool* pCriticalFlag) :
StdExtension_T<SNACC::CRLNumber>(snacc,
								 SNACC::id_ce_cRLNumber,
								 pCriticalFlag)
{
}


void * CRLNumberExtension::GetExtensionValue() const
{
	Bytes_struct* pBytes = NULL;
	Internal::cvtInt2BytesStruct(&pBytes, *this);
	return pBytes; 
}


/////////////////////////////////////////////
// DeltaCRLIndicatorExtension class implementation //
/////////////////////////////////////////////
DeltaCRLIndicatorExtension::DeltaCRLIndicatorExtension(const SNACC::BaseCRLNumber& snacc,
									   const SNACC::AsnBool* pCriticalFlag) :
StdExtension_T<SNACC::BaseCRLNumber>(snacc,
									 SNACC::id_ce_deltaCRLIndicator,
									 pCriticalFlag)
{
}


void * DeltaCRLIndicatorExtension::GetExtensionValue() const
{
	Bytes_struct* pBytes = NULL;
	Internal::cvtInt2BytesStruct(&pBytes, *this);
	return pBytes; 
}


////////////////////////////////////////////////////
// IssuingDistPointExtension class implementation //
////////////////////////////////////////////////////
IssuingDistPointExtension::IssuingDistPointExtension() :
Extension(SNACC::id_ce_issuingDistributionPoint)
{
	distPoint = NULL;
	onlySomeReasons = NULL;
	onlyContainsUserCerts = false;
	onlyContainsAuthorityCerts = false;
	indirectCRL = false;
	onlyContainsAttributeCerts = false;
	m_userFlagPresent = false;
	m_caFlagPresent = false;
	m_attribFlagPresent = false;
	m_indirectFlagPresent = false;
}


IssuingDistPointExtension::IssuingDistPointExtension(const SNACC::IssuingDistPointSyntax& snacc,
													 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_issuingDistributionPoint, pCriticalFlag)
{
	distPoint = NULL;
	onlySomeReasons = NULL;
	operator=(snacc);
}


IssuingDistPointExtension::IssuingDistPointExtension(const IssuingDistPointExtension& that) :
Extension(that)
{
	distPoint = NULL;
	onlySomeReasons = NULL;
	operator=(that);
}


IssuingDistPointExtension::~IssuingDistPointExtension()
{
	if (distPoint != NULL)
		delete distPoint;
	if (onlySomeReasons != NULL)
		delete onlySomeReasons;
}


IssuingDistPointExtension& IssuingDistPointExtension::operator=(const SNACC::IssuingDistPointSyntax& snacc)
{
	if (distPoint != NULL)
	{
		delete distPoint;
		distPoint = NULL;
	}
	if (onlySomeReasons != NULL)
	{
		delete onlySomeReasons;
		onlySomeReasons = NULL;
	}
	
	try {
		if (snacc.distributionPoint != NULL)
		{
			distPoint = new DistPointName(*snacc.distributionPoint);
			if (distPoint == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		if (snacc.onlyContainsUserCerts == NULL)
		{
			m_userFlagPresent = false;
			onlyContainsUserCerts = false;
		}
		else
		{
			m_userFlagPresent = true;
			onlyContainsUserCerts = bool(*snacc.onlyContainsUserCerts);
		}
		
		if (snacc.onlyContainsAuthorityCerts == NULL)
		{
			m_caFlagPresent = false;
			onlyContainsAuthorityCerts = false;
		}
		else
		{
			m_caFlagPresent = true;
			onlyContainsAuthorityCerts = bool(*snacc.onlyContainsAuthorityCerts);
		}
		
		if (snacc.onlySomeReasons != NULL)
		{
			onlySomeReasons = new RevocationReasons(*snacc.onlySomeReasons);
			if (onlySomeReasons == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		if (snacc.indirectCRL == NULL)
		{
			m_indirectFlagPresent = false;
			indirectCRL = false;
		}
		else
		{
			m_indirectFlagPresent = true;
			indirectCRL = bool(*snacc.indirectCRL);
		}
		
		if (snacc.onlyContainsAttributeCerts == NULL)
		{
			m_attribFlagPresent = false;
			onlyContainsAttributeCerts = false;
		}
		else
		{
			m_attribFlagPresent = true;
			onlyContainsAttributeCerts = bool(*snacc.onlyContainsAttributeCerts);
		}
		
		return *this;
	}
	catch (...) {
		if (distPoint != NULL)
		{
			delete distPoint;
			distPoint = NULL;
		}
		if (onlySomeReasons != NULL)
		{
			delete onlySomeReasons;
			onlySomeReasons = NULL;
		}
		throw;
	}
}


IssuingDistPointExtension& IssuingDistPointExtension::operator=(const IssuingDistPointExtension& other)
{
	if (this != &other)
	{
		if (distPoint != NULL)
		{
			delete distPoint;
			distPoint = NULL;
		}
		if (onlySomeReasons != NULL)
		{
			delete onlySomeReasons;
			onlySomeReasons = NULL;
		}
		
		try {
			if (other.distPoint != NULL)
			{
				distPoint = new DistPointName(*other.distPoint);
				if (distPoint == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.onlySomeReasons != NULL)
			{
				onlySomeReasons = new RevocationReasons(*other.onlySomeReasons);
				if (onlySomeReasons == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			onlyContainsUserCerts = other.onlyContainsUserCerts;
			onlyContainsAuthorityCerts = other.onlyContainsAuthorityCerts;
			indirectCRL = other.indirectCRL;
			onlyContainsAttributeCerts = other.onlyContainsAttributeCerts;
			m_userFlagPresent = other.m_userFlagPresent;
			m_caFlagPresent = other.m_caFlagPresent;
			m_attribFlagPresent = other.m_attribFlagPresent;
			m_indirectFlagPresent = other.m_indirectFlagPresent;
		}
		catch (...) {
			if (distPoint != NULL)
			{
				delete distPoint;
				distPoint = NULL;
			}
			if (onlySomeReasons != NULL)
			{
				delete onlySomeReasons;
				onlySomeReasons = NULL;
			}
			throw;
		}
	}
	return *this;
}


bool IssuingDistPointExtension::operator==(const IssuingDistPointExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	if ((distPoint != NULL) && (rhs.distPoint != NULL))
	{
		if (*distPoint != *rhs.distPoint)
			return false;
	}
	else if ((distPoint != NULL) || (rhs.distPoint != NULL))
		return false;
	
	if ((onlySomeReasons != NULL) && (rhs.onlySomeReasons != NULL))
	{
		if (*onlySomeReasons != *rhs.onlySomeReasons)
			return false;
	}
	else if ((onlySomeReasons != NULL) || (rhs.onlySomeReasons != NULL))
		return false;
	
	return ((onlyContainsUserCerts == rhs.onlyContainsUserCerts) &&
		(onlyContainsAuthorityCerts == rhs.onlyContainsAuthorityCerts) &&
		(onlyContainsAttributeCerts == rhs.onlyContainsAttributeCerts) &&
		(indirectCRL == rhs.indirectCRL));
}


SNACC::AsnType* IssuingDistPointExtension::GetSnaccValue() const
{
	SNACC::IssuingDistPointSyntax* result = NULL;
	try {
		result = new SNACC::IssuingDistPointSyntax();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		if (distPoint != NULL)
			result->distributionPoint = distPoint->GetSnacc();
		
		if (onlyContainsUserCerts || m_userFlagPresent)
		{
			if (result->onlyContainsUserCerts != NULL)
				*result->onlyContainsUserCerts = onlyContainsUserCerts;
			else
			{
				result->onlyContainsUserCerts = new
					SNACC::AsnBool(onlyContainsUserCerts);
				if (result->onlyContainsUserCerts == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		else if (result->onlyContainsUserCerts != NULL)
		{
			delete result->onlyContainsUserCerts;
			result->onlyContainsUserCerts = NULL;
		}
		
		if (onlyContainsAuthorityCerts || m_caFlagPresent)
		{
			if (result->onlyContainsAuthorityCerts != NULL)
			{
				*result->onlyContainsAuthorityCerts =
					onlyContainsAuthorityCerts;
			}
			else
			{
				result->onlyContainsAuthorityCerts = new
					SNACC::AsnBool(onlyContainsAuthorityCerts);
				if (result->onlyContainsAuthorityCerts == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		else if (result->onlyContainsAuthorityCerts != NULL)
		{
			delete result->onlyContainsAuthorityCerts;
			result->onlyContainsAuthorityCerts = NULL;
		}
		
		if (onlySomeReasons != NULL)
		{
			result->onlySomeReasons = new SNACC::ReasonFlags(*onlySomeReasons);
			if (result->onlySomeReasons == NULL)
				throw MEMORY_EXCEPTION;
		}

		if (indirectCRL || m_indirectFlagPresent)
		{
			if (result->indirectCRL != NULL)
				*result->indirectCRL = indirectCRL;
			else
			{
				result->indirectCRL = new SNACC::AsnBool(indirectCRL);
				if (result->indirectCRL == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		else if (result->indirectCRL != NULL)
		{
			delete result->indirectCRL;
			result->indirectCRL = NULL;
		}
		
		if (onlyContainsAttributeCerts || m_attribFlagPresent)
		{
			if (result->onlyContainsAttributeCerts != NULL)
			{
				*result->onlyContainsAttributeCerts =
					onlyContainsAttributeCerts;
			}
			else
			{
				result->onlyContainsAttributeCerts = new
					SNACC::AsnBool(onlyContainsAttributeCerts);
				if (result->onlyContainsAttributeCerts == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		else if (result->onlyContainsAttributeCerts != NULL)
		{
			delete result->onlyContainsAttributeCerts;
			result->onlyContainsAttributeCerts = NULL;
		}
		
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* IssuingDistPointExtension::GetExtensionValue() const
{
	Iss_pts_struct* pIssuingDP = (Iss_pts_struct*)
		calloc(1, sizeof(Iss_pts_struct));
	if (pIssuingDP == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (onlyContainsUserCerts)
			pIssuingDP->only_users_flag = TRUE;
		else
			pIssuingDP->only_users_flag = FALSE;
		
		if (onlyContainsAuthorityCerts)
			pIssuingDP->only_cAs_flag = TRUE;
		else
			pIssuingDP->only_cAs_flag = FALSE;
		
		if (onlySomeReasons != NULL)
		{
			pIssuingDP->reasons = (ushort*)cvt_AsnBitMask(*onlySomeReasons);
		}
		
		if (indirectCRL)
			pIssuingDP->indirect_flag = TRUE;
		else
			pIssuingDP->indirect_flag = FALSE;
		
		if (onlyContainsAttributeCerts)
			pIssuingDP->onlyACsFlag = TRUE;
		else
			pIssuingDP->onlyACsFlag = FALSE;
		
		if (distPoint == NULL)
			pIssuingDP->dpName.flag = CM_NOT_PRESENT;
		else
			distPoint->FillDistPtNameStruct(pIssuingDP->dpName);
		
		return pIssuingDP;
	}
	catch (...) {
		if (pIssuingDP->reasons != NULL)
			free(pIssuingDP->reasons);
		free(pIssuingDP);
		throw;
	}
}


////////////////////////////////////////////
// RevocationReasons class implementation //
////////////////////////////////////////////
RevocationReasons::RevocationReasons(bool setAllBits) :
SNACC::ReasonFlags()
{
	static const uchar allReasons[2] = { 0x7F, 0x80 };
	if (setAllBits)
		Set(allReasons, kNumReasonBits);
	else
		Set(kNumReasonBits);
}


RevocationReasons::RevocationReasons(const SNACC::ReasonFlags& snacc)
{
	operator=(snacc);
}


RevocationReasons& RevocationReasons::operator=(const SNACC::ReasonFlags& snacc)
{
	Set(kNumReasonBits);
	for (unsigned int i = 0; i < snacc.BitLen(); ++i)
	{
		if (snacc.GetBit(i))
			SetBit(i);
	}
	return *this;
}


RevocationReasons RevocationReasons::operator~() const
{
	// Create the resulting reasons
	RevocationReasons result;
	
	// Perform the bitwise-NOT of the bytes
	const unsigned int numBytes = (result.bitLen + 7) / 8;
	for (unsigned int i = 0; i < numBytes; ++i)
	{
		// Perform the bitwise-NOT of the current byte, if present
		if (i < (bitLen + 7) / 8)
			result.bits[i] = char(~bits[i]);
		else
			result.bits[i] = char(~result.bits[i]);
	}
	

	static const uchar kMaskArray[8] = {
		0xFF, 0x80, 0xC0, 0xE0, 0xF0, 0xF8, 0xFC, 0xFE
	};
	
	// Clear the unused reason bit
	result.ClrBit(0);

	// Reset the unused bits in the last byte to zero
	if (result.bitLen > 0)
		result.bits[numBytes - 1] &= kMaskArray[result.bitLen % 8];
	
	return result;
}


RevocationReasons RevocationReasons::operator&(const RevocationReasons& rhs) const
{
	// Check the length of the bit strings
	if ((bitLen != kNumReasonBits) || (rhs.bitLen != kNumReasonBits))
	{
		throw EXCEPTION_STR(CMLASN_INVALID_PARAMETER,
			"Invalid length of RevocationReasons BIT STRING");
	}
	
	// Create the resulting reasons
	RevocationReasons result;
	
	// Perform the bitwise-AND of the bytes
	const unsigned int numBytes = (bitLen + 7) / 8;
	for (unsigned int i = 0; i < numBytes; ++i)
		result.bits[i] = char(bits[i] & rhs.bits[i]);
	
	return result;
}


RevocationReasons& RevocationReasons::operator&=(const RevocationReasons& rhs)
{
	// Check the length of the bit strings
	if ((bitLen != kNumReasonBits) || (rhs.bitLen != kNumReasonBits))
	{
		throw EXCEPTION_STR(CMLASN_INVALID_PARAMETER,
			"Invalid length of RevocationReasons BIT STRING");
	}
	
	// Perform the bitwise-AND of the bytes
	const unsigned int numBytes = (bitLen + 7) / 8;
	for (unsigned int i = 0; i < numBytes; ++i)
		bits[i] &= rhs.bits[i];
	
	return *this;
}


RevocationReasons& RevocationReasons::operator|=(const RevocationReasons& rhs)
{
	// Check the length of the bit strings
	if ((bitLen != kNumReasonBits) || (rhs.bitLen != kNumReasonBits))
	{
		throw EXCEPTION_STR(CMLASN_INVALID_PARAMETER,
			"Invalid length of RevocationReasons BIT STRING");
	}
	
	// Perform the bitwise-inclusive-OR of the bytes
	const unsigned int numBytes = (bitLen + 7) / 8;
	for (unsigned int i = 0; i < numBytes; ++i)
		bits[i] |= rhs.bits[i];
	
	return *this;
}


RevocationReasons& RevocationReasons::operator^=(const RevocationReasons& rhs)
{
	// Check the length of the bit strings
	if ((bitLen != kNumReasonBits) || (rhs.bitLen != kNumReasonBits))
	{
		throw EXCEPTION_STR(CMLASN_INVALID_PARAMETER,
			"Invalid length of RevocationReasons BIT STRING");
	}
	
	// Perform the bitwise-exclusive-OR of the bytes
	const unsigned int numBytes = (bitLen + 7) / 8;
	for (unsigned int i = 0; i < numBytes; ++i)
		bits[i] ^= rhs.bits[i];
	
	// Clear the unused reasons bit
	ClrBit(0);

	return *this;
}


///////////////////////////////////////////////
// FreshestCrlExtension class implementation //
///////////////////////////////////////////////
FreshestCrlExtension::FreshestCrlExtension() :
Extension(SNACC::id_ce_freshestCRL)
{
}


FreshestCrlExtension::FreshestCrlExtension(const SNACC::CRLDistPointsSyntax& snacc,
										   const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_freshestCRL, pCriticalFlag)
{
	operator=(snacc);
}


FreshestCrlExtension& FreshestCrlExtension::operator=(const SNACC::CRLDistPointsSyntax& snacc)
{
	clear();

	SNACC::CRLDistPointsSyntax::const_iterator i;
	for (i = snacc.begin(); i != snacc.end(); ++i)
		push_back(*i);
	
	return *this;
}


bool FreshestCrlExtension::operator==(const FreshestCrlExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	const_iterator j = rhs.begin();
	const_iterator i;
	for (i = begin(); (i != end()) && (j != rhs.end()); i++, j++)
	{
		if (*i != *j)
			return false;
	}
	
	return ((i == end()) && (j == rhs.end()));
}


SNACC::AsnType* FreshestCrlExtension::GetSnaccValue() const
{
	SNACC::CRLDistPointsSyntax* result = new SNACC::CRLDistPointsSyntax();
	if (result == NULL)
		throw MEMORY_EXCEPTION;
		
	try {
		for (const_iterator i = begin(); i != end(); i++)
			i->FillSnaccDistPoint(*result->append());
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* FreshestCrlExtension::GetExtensionValue() const
{
	Dist_pts_struct* pResult = NULL;
	
	try {
		FreshestCrlExtension::const_reverse_iterator i;
		for (i = rbegin(); i != rend(); i++)
		{
			Dist_pts_struct* pNew = i->GetDistPointStruct();
			pNew->next = pResult;
			pResult = pNew;
		}
		return pResult;
	}
	catch (...) {
		Internal::FreeDistPts_LL(pResult);
		throw;
	}
}


////////////////////////////////////
// Attribute class implementation //
////////////////////////////////////
Attribute::Attribute()
{
	m_flag = Other;
	m_values.pOther = NULL;
	m_valuesWithContext = NULL;
}


Attribute::Attribute(const SNACC::AsnOid& attrType) : type(attrType)
{
	m_flag = Other;
	m_values.pOther = NULL;
	m_valuesWithContext = NULL;
}


Attribute::Attribute(const SNACC::AsnOid& attrType, AttrType attrFlag,
					 const AttrUnion& values) : type(attrType)
{
	m_flag = Other;
	m_values.pOther = NULL;
	m_valuesWithContext = NULL;
	Set(attrFlag, values);
}


Attribute::Attribute(const SNACC::Attribute& snacc)
{
	m_flag = Other;
	m_values.pOther = NULL;
	m_valuesWithContext = NULL;
	operator=(snacc);
}


Attribute::Attribute(const Attribute& other)
{
	m_flag = Other;
	m_values.pOther = NULL;
	m_valuesWithContext = NULL;
	operator=(other);
}


Attribute& Attribute::operator=(const SNACC::Attribute& snacc)
{
	Clear();
	
	type = snacc.type;
	if (type == SNACC::id_at_clearance)
	{
		m_flag = Clearance;
		m_values.pClearance = new ClearanceList(snacc.values);
		if (m_values.pClearance == NULL)
			throw MEMORY_EXCEPTION;
	}
	else if (type == SNACC::id_cAClearanceConstraints)
	{
		m_flag = CAClearanceConst;
		m_values.pCACons = NULL;
		
		// Check that exactly one value is present
		if (snacc.values.size() != 1)
			throw ASN_EXCEPTION("SNACC::cAClearanceConstraints is a single-valued attribute");

		if (snacc.values.front().ai == NULL)
		{
			// Check that the encoded value is present
			if (snacc.values.front().anyBuf == NULL)
				throw ASN_EXCEPTION("Attribute::values ANY is NULL");
			
			// Reset the AsnBuf for reading
			snacc.values.front().anyBuf->ResetMode();

			// Decode the CAClearanceConstraints value
			SNACC::CAClearanceConstraints caConstraint;
			SNACC::AsnLen numDecoded;
			if (!caConstraint.BDecPdu(*snacc.values.front().anyBuf, numDecoded))
				throw ASN_EXCEPTION("Error decoding SNACC::Clearance value");

			// Copy the decoded value
			m_values.pCACons = new AttributeList(caConstraint);
		}
		else if (snacc.values.front().ai->anyId ==
			SNACC::cAClearanceConstraints_ANY_ID)
		{
			// Check that the decoded value is present
			if (snacc.values.front().value == NULL)
				throw ASN_EXCEPTION("Attribute::values ANY is NULL");

			// Copy the decoded value
			m_values.pCACons = new AttributeList(
				*(SNACC::CAClearanceConstraints*)snacc.values.front().value);
		}
		else
			throw ASN_EXCEPTION("Error decoding SNACC::CAClearanceConstraints value");
			
		if (m_values.pCACons == NULL)
			throw MEMORY_EXCEPTION;
	}
	else if (type == SNACC::id_sigOrKMPrivileges)
	{
		m_flag = SigOrKMPrivs;
		m_values.pSigKMPrivs = new SigOrKMPrivileges();
		if (m_values.pSigKMPrivs == NULL)
			throw MEMORY_EXCEPTION;
		
		SNACC::AttributeSetOf::const_iterator i;
		for (i = snacc.values.begin(); i != snacc.values.end(); ++i)
		{
			if (i->ai == NULL)
			{
				// Check that the encoded value is present
				if (i->anyBuf == NULL)
					throw ASN_EXCEPTION("Attribute::values ANY is NULL");

				// Reset the AsnBuf for reading
				i->anyBuf->ResetMode();

				// Append a new PrivilegeFlags value to the list
				SNACC::PrivilegeFlags& privFlags =
					*m_values.pSigKMPrivs->insert(m_values.pSigKMPrivs->end(),
					SNACC::PrivilegeFlags());
				
				// Decode the PrivilegeFlags value
				SNACC::AsnLen numDecoded;
				if (!privFlags.BDecPdu(*i->anyBuf, numDecoded))
				{
					m_values.pSigKMPrivs->pop_back();
					throw ASN_EXCEPTION("Error decoding SNACC::PrivilegeFlags value");
				}
			}
			else if (i->ai->anyId == SNACC::sigOrKMPrivileges_ANY_ID)
			{
				// Check that the decoded value is present
				if (i->value == NULL)
					throw ASN_EXCEPTION("Attribute::values ANY is NULL");

				// Append the PrivilegeFlags value to the list
				m_values.pSigKMPrivs->push_back(*(SNACC::PrivilegeFlags*)
					i->value);
			}
			else
				throw ASN_EXCEPTION("Error decoding SNACC::PrivilegeFlags value");
		}
	}
	else if (type == SNACC::id_commPrivileges)
	{
		m_flag = CommPrivs;
		m_values.pCommPrivs = NULL;
		
		// Check that only one value is present
		if (snacc.values.size() != 1)
			throw ASN_EXCEPTION("SNACC::commPrivileges is a single-valued attribute");
		
		if (snacc.values.front().ai == NULL)
		{
			// Check that the encoded value is present
			if (snacc.values.front().anyBuf == NULL)
				throw ASN_EXCEPTION("Attribute::values ANY is NULL");
			
			// Reset the AsnBuf for reading
			snacc.values.front().anyBuf->ResetMode();

			// Decode the CommPrecFlags value
			SNACC::CommPrecFlags commFlags;
			SNACC::AsnLen numDecoded;
			if (!commFlags.BDecPdu(*snacc.values.front().anyBuf, numDecoded))
				throw ASN_EXCEPTION("Error decoding SNACC::Clearance value");

			// Copy the decoded value
			m_values.pCommPrivs = new SNACC::CommPrecFlags(commFlags);
		}
		else if (snacc.values.front().ai->anyId ==
			SNACC::commPrivileges_ANY_ID)
		{
			// Check that the decoded value is present
			if (snacc.values.front().value == NULL)
				throw ASN_EXCEPTION("Attribute::values ANY is NULL");

			// Copy the decoded value
			m_values.pCommPrivs =
				new SNACC::CommPrecFlags(*(SNACC::CommPrecFlags*)
				snacc.values.front().value);
		}
		else
			throw ASN_EXCEPTION("Error decoding SNACC::CommPrecFlags value");
		
		if (m_values.pCommPrivs == NULL)
			throw MEMORY_EXCEPTION;
	}
	else
	{
		m_flag = Other;
		m_values.pOther = new BytesList;
		if (m_values.pOther == NULL)
			throw MEMORY_EXCEPTION;
		
		SNACC::AttributeSetOf::const_iterator i;
		for (i = snacc.values.begin(); i != snacc.values.end(); ++i)
			m_values.pOther->push_back(*i);
	}
	
	if (snacc.valuesWithContext != NULL)
	{
		m_valuesWithContext =
			new SNACC::AttributeSetOf1(*snacc.valuesWithContext);
		if (m_valuesWithContext == NULL)
			throw MEMORY_EXCEPTION;
	}
	
	return *this;
}


Attribute& Attribute::operator=(const Attribute& other)
{
	if (this != &other)
	{
		Clear();
		
		type = other.type;
		
		if (other.m_valuesWithContext != NULL)
		{
			m_valuesWithContext =
				new SNACC::AttributeSetOf1(*other.m_valuesWithContext);
			if (m_valuesWithContext == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		m_flag = other.m_flag;
		switch (m_flag)
		{
		case Clearance:
			if (other.m_values.pClearance != NULL)
			{
				m_values.pClearance =
					new ClearanceList(*other.m_values.pClearance);
				if (m_values.pClearance == NULL)
					throw MEMORY_EXCEPTION;
			}
			break;
			
		case CAClearanceConst:
			if (other.m_values.pCACons != NULL)
			{
				m_values.pCACons =
					new AttributeList(*other.m_values.pCACons);
				if (m_values.pCACons == NULL)
					throw MEMORY_EXCEPTION;
			}
			break;
			
		case SigOrKMPrivs:
			if (other.m_values.pSigKMPrivs != NULL)
			{
				m_values.pSigKMPrivs =
					new SigOrKMPrivileges(*other.m_values.pSigKMPrivs);
				if (m_values.pSigKMPrivs == NULL)
					throw MEMORY_EXCEPTION;
			}
			break;
			
		case CommPrivs:
			if (other.m_values.pCommPrivs != NULL)
			{
				m_values.pCommPrivs =
					new SNACC::CommPrecFlags(*other.m_values.pCommPrivs);
				if (m_values.pCommPrivs == NULL)
					throw MEMORY_EXCEPTION;
			}
			break;
			
		case Other:
			if (other.m_values.pOther != NULL)
			{
				m_values.pOther = new BytesList(*other.m_values.pOther);
				if (m_values.pOther == NULL)
					throw MEMORY_EXCEPTION;
			}
			break;
			
		default:
			throw EXCEPTION_STR(CMLASN_UNKNOWN_ERROR,
				"Unknown Attribute::AttrType enum");
		}
	}
	
	return *this;
}


Attribute::AttrUnion& Attribute::GetValues()
{
	delete m_valuesWithContext;
	m_valuesWithContext = NULL;
	return m_values;
}


void Attribute::Set(AttrType flag, const AttrUnion& values,
					const SNACC::AttributeSetOf1* pValuesWithContext)
{
	Clear();
	
	m_flag = flag;
	switch (m_flag)
	{
	case Clearance:
		type = SNACC::id_at_clearance;
		if (values.pClearance != NULL)
		{
			m_values.pClearance = new ClearanceList(*values.pClearance);
			if (m_values.pClearance == NULL)
				throw MEMORY_EXCEPTION;
		}
		break;
		
	case CAClearanceConst:
		type = SNACC::id_cAClearanceConstraints;
		if (values.pCACons != NULL)
		{
			m_values.pCACons = new AttributeList(*values.pCACons);
			if (m_values.pCACons == NULL)
				throw MEMORY_EXCEPTION;
		}
		break;
		
	case SigOrKMPrivs:
		type = SNACC::id_sigOrKMPrivileges;
		if (values.pSigKMPrivs != NULL)
		{
			m_values.pSigKMPrivs = new SigOrKMPrivileges(*values.pSigKMPrivs);
			if (m_values.pSigKMPrivs == NULL)
				throw MEMORY_EXCEPTION;
		}
		break;
		
	case CommPrivs:
		type = SNACC::id_commPrivileges;
		if (values.pCommPrivs != NULL)
		{
			m_values.pCommPrivs = new SNACC::CommPrecFlags(*values.pCommPrivs);
			if (m_values.pCommPrivs == NULL)
				throw MEMORY_EXCEPTION;
		}
		break;
		
	case Other:
		if (values.pOther != NULL)
		{
			m_values.pOther = new BytesList(*values.pOther);
			if (m_values.pOther == NULL)
				throw MEMORY_EXCEPTION;
		}
		break;
		
	default:
		throw EXCEPTION_STR(CMLASN_UNKNOWN_ERROR, "Unknown Attribute::AttrType enum");
	}

	if (pValuesWithContext != NULL)
	{
		m_valuesWithContext = new SNACC::AttributeSetOf1(*pValuesWithContext);
		if (m_valuesWithContext == NULL)
		{
			Clear();
			throw MEMORY_EXCEPTION;
		}
	}
}


void Attribute::FillSnaccAttribute(SNACC::Attribute& snacc) const
{
	snacc.type = type;
	
	if (m_valuesWithContext == NULL)
		snacc.valuesWithContext = NULL;
	else
	{
		snacc.valuesWithContext =
			new SNACC::AttributeSetOf1(*m_valuesWithContext);
		if (snacc.valuesWithContext == NULL)
			throw MEMORY_EXCEPTION;
	}
	
	switch (m_flag)
	{
	case Clearance:
		if (m_values.pClearance != NULL)
			m_values.pClearance->FillSnacc(snacc.values);
		break;
		
	case CAClearanceConst:
		if (m_values.pCACons != NULL)
		{
			SNACC::AsnAny& snaccValue = *snacc.values.append();
			snaccValue.SetTypeByOid(type);
			snaccValue.value = m_values.pCACons->GetSnaccCAConstraints();
		}
		break;
		
	case SigOrKMPrivs:
		if (m_values.pSigKMPrivs != NULL)
		{
			SigOrKMPrivileges::const_iterator i;
			for (i = m_values.pSigKMPrivs->begin(); i !=
				m_values.pSigKMPrivs->end(); i++)
			{
				SNACC::AsnAny& newValue = *snacc.values.append();
				newValue.SetTypeByOid(type);
				newValue.value = new SNACC::PrivilegeFlags(*i);
				if (newValue.value == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		break;
		
	case CommPrivs:
		if (m_values.pCommPrivs != NULL)
		{
			SNACC::AsnAny& snaccValue = *snacc.values.append();
			snaccValue.SetTypeByOid(type);
			snaccValue.value = new SNACC::CommPrecFlags(*m_values.pCommPrivs);
			if (snaccValue.value == NULL)
				throw MEMORY_EXCEPTION;
		}
		break;
		
	case Other:
		if (m_values.pOther != NULL)
		{
			BytesList::const_iterator i;
			for (i = m_values.pOther->begin(); i != m_values.pOther->end(); ++i)
			{
				SNACC::AsnAny& newValue = *snacc.values.append();
				newValue.anyBuf = new SNACC::AsnBuf((const char*)i->GetData(),
					i->Len());
				if (newValue.anyBuf == NULL)
					throw MEMORY_EXCEPTION;
			}
		}
		break;
		
	default:
		throw EXCEPTION_STR(CMLASN_UNKNOWN_ERROR, "Unknown Attribute::AttrType enum");
	}
}


Attributes_struct* Attribute::GetAttributeStruct() const
{
	Attributes_struct* result = (Attributes_struct*)
		calloc(1, sizeof(Attributes_struct));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		result->oid = type.GetChar();
		switch (m_flag)
		{
		case Clearance:
			// Check that exactly one clearance value is present
			if ((m_values.pClearance == NULL) ||
				(m_values.pClearance->size() != 1))
				throw ASN_EXCEPTION("Clearance attribute must contain exactly one value");
			
			result->type = PRBACINFO;
			result->values.prbac_infop =
				m_values.pClearance->front().GetClearanceStruct();
			break;
			
		case CAClearanceConst:
			// Check that exactly one value is present
			if (m_values.pCACons == NULL)
				throw ASN_EXCEPTION("CAClearanceConstraints attribute must contain exactly one value");
			
			result->type = CACONSTRAINTS;
			result->values.ca_const = m_values.pCACons->GetCAConstList();
			break;
			
		case SigOrKMPrivs:
			// Check that exactly one value is present
			if ((m_values.pSigKMPrivs == NULL) ||
				(m_values.pSigKMPrivs->size() != 1))
				throw ASN_EXCEPTION("SigOrKMPrivileges attribute must contain exactly one value");
			
			result->type = SIGORKMPRIVILEGES;
			result->values.priv_flags =
				cvtPrivFlagsStruct(m_values.pSigKMPrivs->front());
			break;
			
		case CommPrivs:
			// Check that exactly one value is present
			if (m_values.pCommPrivs == NULL)
				throw ASN_EXCEPTION("CommPrivileges attribute must contain exactly one value");
			
			result->type = COMMPRIV;
			result->values.comm_priv =
				Internal::CvtBitsToBytes(*m_values.pCommPrivs);
			break;
			
		case Other:
			result->type = UNKNOWN;
			if (m_values.pOther != NULL)
			{
				const BytesList& list = *m_values.pOther;
				BytesList::const_reverse_iterator i;
				for (i = list.rbegin(); i != list.rend(); i++)
				{
					// Allocate and clear the memory for a new Bytes_struct_LL
					Bytes_struct_LL* pNewBytes = (Bytes_struct_LL*)
						calloc(1, sizeof(Bytes_struct_LL));
					if (pNewBytes == NULL)
						throw MEMORY_EXCEPTION;
					
					// Add this new link to the head of the list
					pNewBytes->next = result->values.unkn;
					result->values.unkn = pNewBytes;
					
					pNewBytes->bytes_struct = i->GetBytesStruct();
				}
			}
			break;
			
		default:
			throw EXCEPTION_STR(CMLASN_UNKNOWN_ERROR, "Unknown Attribute::AttrType enum");
		}
		
		return result;
	}
	catch (...) {
		Internal::FreeAttributes(result);
		throw;
	}
} // end of Attribute::GetAttributeStruct()
  
  
void Attribute::Clear()
{
	switch (m_flag)
	{
	case Clearance:
		delete m_values.pClearance;
		m_values.pClearance = NULL;
		break;
		
	case CAClearanceConst:
		delete m_values.pCACons;
		m_values.pCACons = NULL;
		break;
		
	case SigOrKMPrivs:
		delete m_values.pSigKMPrivs;
		m_values.pSigKMPrivs = NULL;
		break;
		
	case CommPrivs:
		delete m_values.pCommPrivs;
		m_values.pCommPrivs = NULL;
		break;
		
	case Other:
		delete m_values.pOther;
		m_values.pOther = NULL;
		break;
		
	default:
		m_flag = Other;
		m_values.pOther = NULL;
	}
	
	delete m_valuesWithContext;
	m_valuesWithContext = NULL;
}
  
  
////////////////////////////////////////
// AttributeList class implementation //
////////////////////////////////////////
AttributeList::AttributeList(const AsnSeqOf<SNACC::Attribute>& snacc)
{
	operator=(snacc);
}
  
  
AttributeList& AttributeList::operator=(const AsnSeqOf<SNACC::Attribute>& snacc)
{
	clear();

	AsnSeqOf<SNACC::Attribute>::const_iterator i;
	for (i = snacc.begin(); i != snacc.end(); ++i)
	{
		iterator iNew = insert(end(), i->type);
		*iNew = *i;
	}
	return *this;
}
  
void AttributeList::FillSnaccList(AsnSeqOf<SNACC::Attribute>& snacc) const
{
	for (const_iterator i = begin(); i != end(); i++)
		i->FillSnaccAttribute(*snacc.append());
}
  
  
SNACC::AttributesSyntax* AttributeList::GetSnacc() const
{
	SNACC::AttributesSyntax* pSnacc = new SNACC::AttributesSyntax;
	if (pSnacc == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		FillSnaccList(*pSnacc);
		return pSnacc;
	}
	catch (...) {
		delete pSnacc;
		throw;
	}
}


SNACC::CAClearanceConstraints* AttributeList::GetSnaccCAConstraints() const
{
	SNACC::CAClearanceConstraints* pSnacc = new SNACC::CAClearanceConstraints;
	if (pSnacc == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		FillSnaccList(*pSnacc);
		return pSnacc;
	}
	catch (...) {
		delete pSnacc;
		throw;
	}
}


Attributes_struct* AttributeList::GetAttributeList() const
{
	Attributes_struct* result = NULL;
	
	try {
		for (const_reverse_iterator i = rbegin(); i != rend(); i++)
		{
			Attributes_struct* pNew = i->GetAttributeStruct();
			pNew->next = result;
			result = pNew;
		}
		return result;
	}
	catch (...) {
		Internal::FreeAttributes(result);
		throw;
	}
}


Ca_const* AttributeList::GetCAConstList() const
{
	Ca_const* result = NULL;
	try   {
		// For each attribute...
		for (const_reverse_iterator i = rbegin(); i != rend(); i++)
		{
			Ca_const* pNew;
			switch (i->GetType())
			{
			case Attribute::Clearance:
				if (i->GetValues().pClearance == NULL)
					break;

				pNew = i->GetValues().pClearance->GetCAClearanceList();
				pNew->next = result;
				result = pNew;
				break;
				
			case Attribute::SigOrKMPrivs:
				{
					const SigOrKMPrivileges* pValues =
						i->GetValues().pSigKMPrivs;
					if (pValues == NULL)
						break;
					
					// For each value...
					SigOrKMPrivileges::const_reverse_iterator iValue =
						pValues->rbegin();
					for ( ; iValue != pValues->rend(); iValue++)
					{
						// Allocate and clear the memory for a new Ca_const link
						pNew = (Ca_const*)calloc(1, sizeof(Ca_const));
						if (pNew == NULL)
							throw MEMORY_EXCEPTION;
						
						// Add this new link to the head of the list
						pNew->next = result;
						result = pNew;
						
						pNew->ca_type = SIGORKMPRIVILEGES;
						
						// Convert the value to the C structure
						pNew->ca_val.priv_flags = cvtPrivFlagsStruct(*iValue);
					}
				}
				break;
				
			case Attribute::CommPrivs:
				if (i->GetValues().pCommPrivs == NULL)
					break;
				
				// Allocate and clear the memory for a new Ca_const link
				pNew = (Ca_const*)calloc(1, sizeof(Ca_const));
				if (pNew == NULL)
					throw MEMORY_EXCEPTION;
				
				// Add this new link to the head of the list
				pNew->next = result;
				result = pNew;
				
				pNew->ca_type = COMMPRIV;
				
				// Convert the value to the C structure
				pNew->ca_val.comm_priv =
					Internal::CvtBitsToBytes(*i->GetValues().pCommPrivs);
				break;
				
			default:
				throw ASN_EXCEPTION("Invalid Attribute in CAClearanceConstraints");
			}
		} // end of for each attribute loop
		
		return result;
	}
	catch (...) {
		Internal::FreeCa_const(&result);
		throw;
	}
} // end of cvtCAConstraintsList()


AttributeList::const_iterator AttributeList::Find(const SNACC::AsnOid& type) const
{
	const_iterator i;
	for (i = begin(); (i != end()) && (i->type != type); i++)
		;
	return i;
}


AttributeList::const_iterator AttributeList::Find(Attribute::AttrType type) const
{
	const_iterator i;
	for (i = begin(); (i != end()) && (i->GetType() != type); ++i)
		;
	return i;
}


AttributeList::const_iterator AttributeList::FindNext(const_iterator iPrev,
													  const SNACC::AsnOid& type) const
{
	if (iPrev == NULL)
		return end();
	if (iPrev == end())
		return iPrev;
	
	for (++iPrev; (iPrev != end()) && (iPrev->type != type); ++iPrev)
		;
	return iPrev;
}


AttributeList::const_iterator AttributeList::FindNext(const_iterator iPrev,
													  Attribute::AttrType type) const
{
	if (iPrev == NULL)
		return end();
	if (iPrev == end())
		return iPrev;
	
	for (++iPrev; (iPrev != end()) && (iPrev->GetType() != type); iPrev++)
		;
	return iPrev;
}


/////////////////////////////////////////////////////
// SubjDirAttributesExtension class implementation //
/////////////////////////////////////////////////////
SubjDirAttributesExtension::SubjDirAttributesExtension() :
Extension(SNACC::id_ce_subjectDirectoryAttributes)
{
}


SubjDirAttributesExtension::SubjDirAttributesExtension(const SNACC::AttributesSyntax& snacc,
													   const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_subjectDirectoryAttributes, pCriticalFlag), AttributeList(snacc)
{
}


SubjDirAttributesExtension& SubjDirAttributesExtension::operator=(const SNACC::AttributesSyntax& snacc)
{
	AttributeList::operator=(snacc);
	return *this;
}


////////////////////////////////////////////
// AccessDescription class implementation //
////////////////////////////////////////////
AccessDescription::AccessDescription()
{
}


AccessDescription::AccessDescription(const SNACC::AccessDescription& snacc) :
method(snacc.accessMethod), location(snacc.accessLocation)
{
}


AccessDescription::AccessDescription(const SNACC::AsnOid& accessMethod,
									 const GenName& accessLoc) :
method(accessMethod), location(accessLoc)
{
}


AccessDescription& AccessDescription::operator=(const SNACC::AccessDescription& snacc)
{
	method = snacc.accessMethod;
	location = snacc.accessLocation;
	
	return *this;
}


bool AccessDescription::operator==(const AccessDescription& rhs) const
{
	if (this == &rhs)
		return true;
	
	return ((method == rhs.method) && (location == rhs.location));
}

bool AccessDescription::operator<(const AccessDescription& rhs) const
{
	if (this == &rhs)
		return false;
	
	if (method < rhs.method)
		return true;
	if ((method == rhs.method) && (location < rhs.location))
		return true;

	return false;
}
void AccessDescription::FillSnacc(SNACC::AccessDescription& snacc) const
{
	snacc.accessMethod = method;
	location.FillSnaccGenName(snacc.accessLocation);
}


AccessDescript_LL* AccessDescription::GetAccessDescStruct() const
{
	AccessDescript_LL* pResult = (AccessDescript_LL*)
		calloc(1, sizeof(AccessDescript_LL));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		pResult->method = method.GetChar();
		location.FillGenNameStruct(pResult->loc);
		return pResult;
	}
	catch (...) {
		Internal::FreeAccessDescriptions(pResult);
		throw;
	}
}


///////////////////////////////////////////
// PkixAIAExtension class implementation //
///////////////////////////////////////////
PkixAIAExtension::PkixAIAExtension() :
Extension(SNACC::id_pe_authorityInfoAccess)
{
}


PkixAIAExtension::PkixAIAExtension(const SNACC::AuthorityInfoAccessSyntax& snacc,
								   const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_pe_authorityInfoAccess, pCriticalFlag)
{
	operator=(snacc);
}


PkixAIAExtension& PkixAIAExtension::operator=(const SNACC::AuthorityInfoAccessSyntax& snacc)
{
	clear();
	
	SNACC::AuthorityInfoAccessSyntax::const_iterator i;
	for (i = snacc.begin(); i != snacc.end(); ++i)
		push_back(*i);
	
	return *this;
}


bool PkixAIAExtension::operator==(const PkixAIAExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	const_iterator j = rhs.begin();
	const_iterator i;
	for (i = begin(); (i != end()) && (j != rhs.end()); i++, j++)
	{
		if (*i != *j)
			return false;
	}
	
	return ((i == end()) && (j == rhs.end()));
}


SNACC::AsnType* PkixAIAExtension::GetSnaccValue() const
{
	SNACC::AuthorityInfoAccessSyntax* result = NULL;
	try {
		result = new SNACC::AuthorityInfoAccessSyntax();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		for (const_iterator i = begin(); i != end(); i++)
			i->FillSnacc(*result->append());
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* PkixAIAExtension::GetExtensionValue() const
{
	AccessDescript_LL* pResult = NULL;
	
	try {
		PkixAIAExtension::const_reverse_iterator i;
		for (i = rbegin(); i != rend(); i++)
		{
			AccessDescript_LL* pNew = i->GetAccessDescStruct();
			pNew->next = pResult;
			pResult = pNew;
		}
		return pResult;
	}
	catch (...) {
		Internal::FreeAccessDescriptions(pResult);
		throw;
	}
}


///////////////////////////////////////////
// PkixSIAExtension class implementation //
///////////////////////////////////////////
PkixSIAExtension::PkixSIAExtension() :
Extension(SNACC::id_pe_subjectInfoAccess)
{
}


PkixSIAExtension::PkixSIAExtension(const SNACC::SubjectInfoAccessSyntax& snacc,
								   const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_pe_subjectInfoAccess, pCriticalFlag)
{
	operator=(snacc);
}


PkixSIAExtension& PkixSIAExtension::operator=(const SNACC::SubjectInfoAccessSyntax& snacc)
{
	clear();

	SNACC::SubjectInfoAccessSyntax::const_iterator i;
	for (i = snacc.begin(); i != snacc.end(); ++i)
		push_back(*i);
	
	return *this;
}


bool PkixSIAExtension::operator==(const PkixSIAExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	const_iterator j = rhs.begin();
	const_iterator i;
	for (i = begin(); (i != end()) && (j != rhs.end()); i++, j++)
	{
		if (*i != *j)
			return false;
	}
	
	return ((i == end()) && (j == rhs.end()));
}


SNACC::AsnType* PkixSIAExtension::GetSnaccValue() const
{
	SNACC::SubjectInfoAccessSyntax* result = NULL;
	try {
		result = new SNACC::SubjectInfoAccessSyntax();
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		for (const_iterator i = begin(); i != end(); i++)
			i->FillSnacc(*result->append());
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


void* PkixSIAExtension::GetExtensionValue() const
{
	AccessDescript_LL* pResult = NULL;
	
	try {
		PkixSIAExtension::const_reverse_iterator i;
		for (i = rbegin(); i != rend(); i++)
		{
			AccessDescript_LL* pNew = i->GetAccessDescStruct();
			pNew->next = pResult;
			pResult = pNew;
		}
		return pResult;
	}
	catch (...) {
		Internal::FreeAccessDescriptions(pResult);
		throw;
	}
}


//////////////////////////////////////////////
// CertIssuerExtension class implementation //
//////////////////////////////////////////////
CertIssuerExtension::CertIssuerExtension() :
Extension(SNACC::id_ce_certificateIssuer)
{
}


CertIssuerExtension::CertIssuerExtension(const SNACC::GeneralNames& snacc,
										 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_certificateIssuer, pCriticalFlag), GenNames(snacc)
{
}


bool CertIssuerExtension::operator==(const CertIssuerExtension& rhs) const
{
	if (this == &rhs)
		return true;
	
	if (critical != rhs.critical)
		return false;
	
	return (GenNames(*this) == rhs);
}


///////////////////////////////////////////////////
// StdExtension_T template class specializations //
///////////////////////////////////////////////////
void* StdExtension_T<SNACC::CRLScopeSyntax>::GetExtensionValue() const
{
	return cvtPerAuthScopeList(*this);
}

void* StdExtension_T<SNACC::AsnOcts>::GetExtensionValue() const
{
	return Internal::cvtOctsToBytes(*this);
}

void* StdExtension_T<SNACC::StatusReferrals>::GetExtensionValue() const
{
	StatusReferral_LL* result = NULL;
	try {
		for (const_reverse_iterator i = rbegin(); i != rend(); ++i)
		{
			// Allocate and clear the memory for a new StatusReferral_LL link
			StatusReferral_LL* pNew = (StatusReferral_LL*)
				calloc(1, sizeof(StatusReferral_LL));
			if (pNew == NULL)
				throw MEMORY_EXCEPTION;
			
			// Add this new link to the head of the list
			pNew->next = result;
			result = pNew;
			
			// Convert the ASN.1 status referral choice
			if (i->choiceId == SNACC::StatusReferral::cRLReferralCid)
			{
				pNew->flag = CM_CRL_REFERRAL;
				if (i->cRLReferral == NULL)
					throw ASN_EXCEPTION("SNACC::StatusReferral::cRLReferral field is NULL");
				
				pNew->ref.crl = cvtCrlReferralStruct(*i->cRLReferral);
			}
			else if (i->choiceId == SNACC::StatusReferral::otherReferralCid)
			{
				pNew->flag = CM_OTHER_REFERRAL;
				if (i->otherReferral == NULL)
					throw ASN_EXCEPTION("SNACC::StatusReferral::otherReferral field is NULL");
				
				// Allocate and clear the memory for the Any_struct
				pNew->ref.other = (Any_struct*)calloc(1, sizeof(Any_struct));
				if (pNew->ref.other == NULL)
					throw MEMORY_EXCEPTION;
				
				// Convert the Other_Referral
				pNew->ref.other->oid = i->otherReferral->id.GetChar();
				if (i->otherReferral->type.ai == NULL)
				{
					if (i->otherReferral->type.anyBuf == NULL)
						throw ASN_EXCEPTION("SNACC::StatusReferral::otherReferral anyBuf field is NULL");

					pNew->ref.other->data = Internal::CvtAsnBufToBytes(
						*(SNACC::AsnBuf*)i->otherReferral->type.anyBuf);
				}
				else if (i->otherReferral->type.value != NULL)
				{
						// Encode the ANY value
						SNACC::AsnBuf asnBuf;
						SNACC::AsnLen numEnc;
						if (!i->otherReferral->type.BEncPdu(asnBuf, numEnc))
							throw ASN_EXCEPTION("Error encoding SNACC::Other_Referral value");
						
						pNew->ref.other->data =
							Internal::CvtAsnBufToBytes(asnBuf);
				}
				else
					throw ASN_EXCEPTION("SNACC::StatusReferral::otherReferral value field is NULL");
			}
			else
				throw ASN_EXCEPTION("Invalid CHOICE in SNACC::StatusReferral");
		} // end of for loop
		
		// Check that at least one item is present
		if (result == NULL)
			throw ASN_EXCEPTION("SNACC::StatusReferrals must contain at least one StatusReferral");
		
		return result;
	}
	catch (...) {
		Internal::FreeStatusRef(result);
		throw;
	}
}

void* StdExtension_T<SNACC::OrderedListSyntax>::GetExtensionValue() const
{
	short* pValue = (short*)malloc(sizeof(short));
	if (pValue == NULL)
		throw MEMORY_EXCEPTION;
	
	switch (*this) {
	case SNACC::OrderedListSyntax::ascSerialNum:
		*pValue = CM_ORDERED_BY_SERIAL_NUM;
		break;
	case SNACC::OrderedListSyntax::ascRevDate:
		*pValue = CM_ORDERED_BY_DATE;
		break;
	default:
		free(pValue);
		throw ASN_EXCEPTION("Invalid enumerated value in OrderedListSyntax");
	}
	return pValue;
}

void* StdExtension_T<SNACC::DeltaInformation>::GetExtensionValue() const
{
	DeltaInfo* pResult = (DeltaInfo*)calloc(1, sizeof(DeltaInfo));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Convert the GeneralName
		GenName tempGN(deltaLocation);
		tempGN.FillGenNameStruct(pResult->deltaLoc);
		
		// Convert the delta CRL issue date (if present)
		if (nextDelta != NULL)
		{
			// Allocate memory for the delta CRL issue date
			pResult->issueDate = (CM_Time*)malloc(sizeof(CM_Time));
			if (pResult->issueDate == NULL)
				throw MEMORY_EXCEPTION;
			
			Time tempTime(*nextDelta);
			strcpy(*pResult->issueDate, tempTime);
		}
		return pResult;
	}
	catch (...) {
		Internal::FreeGenNameContent(&pResult->deltaLoc);
		if (pResult->issueDate != NULL)
			free(pResult->issueDate);
		free(pResult);
		throw;
	}
}

void* StdExtension_T<SNACC::GeneralizedTime>::GetExtensionValue() const
{
	CM_Time* pTime = (CM_Time*)malloc(sizeof(CM_Time));
	if (pTime == NULL)
		throw MEMORY_EXCEPTION;
	strcpy(*pTime, c_str());
	return pTime;
}

void* StdExtension_T<SNACC::CRLReason>::GetExtensionValue() const
{
	short* pValue = (short*)malloc(sizeof(short));
	if (pValue == NULL)
		throw MEMORY_EXCEPTION;
	
	switch (*this) {
	case SNACC::CRLReason::unspecified:
		*pValue = CM_CRL_UNSPECIFIED;
		break;
	case SNACC::CRLReason::keyCompromise:
		*pValue = CM_CRL_KEY_COMPROMISE;
		break;
	case SNACC::CRLReason::cACompromise:
		*pValue = CM_CRL_CA_COMPROMISE;
		break;
	case SNACC::CRLReason::affiliationChanged:
		*pValue = CM_CRL_AFFILIATION_CHANGED;
		break;
	case SNACC::CRLReason::superseded:
		*pValue = CM_CRL_SUPERSEDED;
		break;
	case SNACC::CRLReason::cessationOfOperation:
		*pValue = CM_CRL_CESSATION_OF_OPERATION;
		break;
	case SNACC::CRLReason::certificateHold:
		*pValue = CM_CRL_CERTIFICATE_HOLD;
		break;
	case SNACC::CRLReason::removeFromCRL:
		*pValue = CM_CRL_REMOVE_FROM_CRL;
		break;
	case SNACC::CRLReason::privilegeWithdrawn:
		*pValue = CM_CRL_PRIVILEGE_WITHDRAWN;
		break;
	case SNACC::CRLReason::aaCompromise:
		*pValue = CM_CRL_AA_COMPROMISE;
		break;
	default:
		free(pValue);
		throw ASN_EXCEPTION("Invalid enumerated value in CRLReason");
	}
	return pValue;
}

void* StdExtension_T<SNACC::AsnOid>::GetExtensionValue() const
{
	CM_OID* pOid = (CM_OID*)malloc(sizeof(CM_OID));
	if (pOid == NULL)
		throw MEMORY_EXCEPTION;
	try {
		*pOid = GetChar();
		return pOid;
	}
	catch (...) {
		free(pOid);
		throw;
	}
}


//////////////////////////////////
// CML::ASN::Internal functions //
//////////////////////////////////
LongArray* Internal::CvtLongArray(const SNACC::SigPrivFlagsSeqOf& snacc)
{
	// Allocate and clear the memory for the result
	LongArray* result = (LongArray*)calloc(1, sizeof(LongArray));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		result->num = snacc.size();
		result->array = (long*)calloc(result->num, sizeof(long));
		if (result->array == NULL)
			throw MEMORY_EXCEPTION;
		
		// Convert the list of integers
		unsigned int i = 0;
		SNACC::SigPrivFlagsSeqOf::const_iterator iFlag;
		for (iFlag = snacc.begin(); iFlag != snacc.end(); ++iFlag)
			result->array[i++] = *iFlag;
		
		return result;
	}
	catch (...) {
		free(result->array);
		free(result);
		throw;
	}
} // end of CvtLongArray()


////////////////////////
// Internal Functions //
////////////////////////
void buildExtMap(ExtensionPtrMap& map, const CertExtensions& exts)
{
	if (exts.pSubjKeyID != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::subjectKeyIdentifier_ANY_ID, exts.pSubjKeyID));
	
	if (exts.pAuthKeyID != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::authorityKeyIdentifier_ANY_ID, exts.pAuthKeyID));
	
	if (exts.pKeyUsage != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::keyUsage_ANY_ID, exts.pKeyUsage));
	
	if (exts.pExtKeyUsage != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::extKeyUsage_ANY_ID, exts.pExtKeyUsage));
	
	if (exts.pPrivKeyPeriod != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::privateKeyUsagePeriod_ANY_ID, exts.pPrivKeyPeriod));
	
	if (exts.pSubjAltNames != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::subjectAltName_ANY_ID, exts.pSubjAltNames));
	
	if (exts.pIssuerAltNames != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::issuerAltName_ANY_ID, exts.pIssuerAltNames));
	
	if (exts.pCertPolicies != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::certificatePolicies_ANY_ID, exts.pCertPolicies));
	
	if (exts.pPolicyMaps != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::policyMappings_ANY_ID, exts.pPolicyMaps));
	
	if (exts.pBasicCons != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::basicConstraints_ANY_ID, exts.pBasicCons));
	
	if (exts.pNameCons != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::nameConstraint_ANY_ID, exts.pNameCons));
	
	if (exts.pPolicyCons != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::policyConstraints_ANY_ID, exts.pPolicyCons));
	
	if (exts.pInhibitAnyPolicy != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::inhibitAnyPolicy_ANY_ID, exts.pInhibitAnyPolicy));
	
	if (exts.pCrlDistPts != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::cRLDistributionPoints_ANY_ID, exts.pCrlDistPts));
	
	if (exts.pFreshestCRL != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::freshestCRL_ANY_ID, exts.pFreshestCRL));
	
	if (exts.pSubjDirAtts != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::subjectDirectoryAttributes_ANY_ID, exts.pSubjDirAtts));
	
	if (exts.pAuthInfoAccess != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::authorityInfoAccess_ANY_ID, exts.pAuthInfoAccess));
	
	if (exts.pSubjInfoAccess != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::subjectInfoAccess_ANY_ID, exts.pSubjInfoAccess));
}


void buildExtMap(ExtensionPtrMap& map, const CrlExtensions& exts)
{
	if (exts.pAuthKeyID != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::authorityKeyIdentifier_ANY_ID, exts.pAuthKeyID));
	
	if (exts.pIssuerAltNames != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::issuerAltName_ANY_ID, exts.pIssuerAltNames));
	
	if (exts.pIssuingDP != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::issuingDistributionPoint_ANY_ID, exts.pIssuingDP));
	
	if (exts.pFreshestCRL != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::freshestCRL_ANY_ID, exts.pFreshestCRL));
	
	if (exts.pCrlNumber != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::cRLNumber_ANY_ID, exts.pCrlNumber));
	
	if (exts.pDeltaCRL != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::deltaCRLIndicator_ANY_ID, exts.pDeltaCRL));
	
	if (exts.pCrlScope != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::crlScope_ANY_ID, exts.pCrlScope));
	
	if (exts.pStatusRefs != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::statusReferrals_ANY_ID, exts.pStatusRefs));
	
	if (exts.pStreamID != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::cRLStreamIdentifier_ANY_ID, exts.pStreamID));
	
	if (exts.pOrderedList != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::orderedList_ANY_ID, exts.pOrderedList));
	
	if (exts.pDeltaInfo != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::deltaInfo_ANY_ID, exts.pDeltaInfo));
	
	if (exts.pBaseUpdate != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::baseUpdateTime_ANY_ID, exts.pBaseUpdate));
}


void buildExtMap(ExtensionPtrMap& map, const CrlEntryExtensions& exts)
{
	if (exts.pReason != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::reasonCode_ANY_ID, exts.pReason));
	
	if (exts.pHoldCode != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::holdInstructionCode_ANY_ID, exts.pHoldCode));
	
	if (exts.pInvalidityDate != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::invalidityDate_ANY_ID, exts.pInvalidityDate));
	
	if (exts.pCertIssuer != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::certificateIssuer_ANY_ID, exts.pCertIssuer));
}


void buildExtMap(ExtensionPtrMap& map, const ACExtensions& exts)
{
	if (exts.pAuthKeyID != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::authorityKeyIdentifier_ANY_ID, exts.pAuthKeyID));
	
	if (exts.pTimeSpec != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::timeSpecification_ANY_ID, exts.pTimeSpec));
	
	if (exts.pTargetInfo != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::targetingInformation_ANY_ID, exts.pTargetInfo));
	
	if (exts.pUserNotice != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::userNoticeExtension_ANY_ID, exts.pUserNotice));
	
	if (exts.pPrivPolicies != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::acceptablePrivilegePolicies_ANY_ID, exts.pPrivPolicies));
	
	if (exts.pCrlDistPts != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::cRLDistributionPoints_ANY_ID, exts.pCrlDistPts));
	
	if (exts.pRevInfoAvail != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::noRevAvail_ANY_ID, exts.pRevInfoAvail));
	
	if (exts.pSOA_Id != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::sOAIdentifier_ANY_ID, exts.pSOA_Id));
	
	if (exts.pDescriptor != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::attributeDescriptor_ANY_ID, exts.pDescriptor));
	
	if (exts.pRoleSpec != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::roleSpecCertIdentifier_ANY_ID, exts.pRoleSpec));
	
	if (exts.pBasicCons != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::basicAttConstraints_ANY_ID, exts.pBasicCons));
	
	if (exts.pNameCons != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::delegatedNameConstraints_ANY_ID, exts.pNameCons));
	
	if (exts.pCertPolicies != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::acceptableCertPolicies_ANY_ID, exts.pCertPolicies));
	
	if (exts.pAA_Id != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::authorityAttributeIdentifier_ANY_ID, exts.pAA_Id));

	if (exts.pAuthInfoAccess != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::authorityInfoAccess_ANY_ID, exts.pAuthInfoAccess));

	if (exts.pAuditIdentity != NULL)
		map.insert(ExtensionPtrMap::value_type(
		SNACC::auditIdentity_ANY_ID, exts.pAuditIdentity));
}


/************************************************************************
FUNCTION:  cvt_AsnBitMask()
  
Description: This function converts the SNACC BIT STRING into the
specified CMAPI integer type (uchar, ushort, ulong).  The bits are
reversed in the CMAPI type (a BIT STRING MSB is a CMAPI LSB flag).
This allows additional CM lib bit flags to be added if bits are added
to the ASN.1 definition, without having to change the existing CMAPI bit
flags.
This function allocates the memory for the CMAPI integer type, which is
returned if the ASN.1 BIT STRING is succesfully converted, otherwise
an exception is thrown.
*************************************************************************/
void* cvt_AsnBitMask(const SNACC::AsnBits& asn, size_t cmSize)
{
	// Check that the ASN.1 bits will fit in the requested size
	if (cmSize < ((asn.BitLen() + 7) / 8))
		throw ASN_EXCEPTION("BIT STRING exceeds storage capacity");
	
	// For each bit in the bit string...
	ulong tmp = 0;
	unsigned int iBit = 0;
	for (iBit = 0; iBit < asn.BitLen(); iBit++)
	{
		// Shift the result to the right
		tmp >>= 1;
		
		// If the bit is set, set the high bit in tmp
		if (asn.GetBit(iBit))
			tmp |= 0x80000000;
	}
	
	// Now the result is in the correct order, but still needs to shifted
	// down to the LSB of the the result
	tmp >>= (sizeof(ulong) * 8) - iBit;
	
	// Allocate memory for the result and set the result
	uchar* result = (uchar*)calloc(cmSize, sizeof(uchar));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	switch (cmSize)
	{
	case sizeof(uchar):
		*result = (uchar)tmp;
		break;
	case sizeof(ushort):
		*(ushort*)result = (ushort)tmp;
		break;
	case sizeof(ulong):
		*(ulong*)result = (ulong)tmp;
		break;
	default:
		delete result;
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
	}
	
	return result;
} // end of cvt_AsnBitMask()


CM_BaseRevocationInfo* cvtBaseRevocationInfo(const SNACC::BaseRevocationInfo& snacc)
{
	CM_BaseRevocationInfo* result = (CM_BaseRevocationInfo*)
		calloc(1, sizeof(CM_BaseRevocationInfo));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Convert the optional cRLStreamIdentifier field if present
		if (snacc.cRLStreamIdentifier != NULL)
			result->crlStreamID = cvtIntsToBytes((const SNACC::AsnInt)*snacc.cRLStreamIdentifier);

		
		// Convert the cRLNumber field
		cvtIntToExistingBytes(result->crlNum, snacc.cRLNumber);
		
		// Convert the baseThisUpdate field
		Time tempTime(snacc.baseThisUpdate);
		strcpy(result->thisUpdate, tempTime);
		
		return result;
	}
	catch (...) {
		if (result->crlStreamID != NULL)
			Internal::FreeBytes(result->crlStreamID);
		if (result->crlNum.data != NULL)
			free(result->crlNum.data);
		free(result);
		throw;
	}
} // end of cvtBaseRevocationInfo()


CRL_referral* cvtCrlReferralStruct(const SNACC::CRLReferral& snacc)
{
	// Allocate and clear the memory for the CRL_referral
	CRL_referral* result = (CRL_referral*)calloc(1, sizeof(CRL_referral));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Convert the optional issuer field if present
		if (snacc.issuer != NULL)
		{
			GenName tempGN(*snacc.issuer);
			result->issuer = tempGN.GetGenNameStruct();
		}
		
		// Convert the optional location field if present
		if (snacc.location != NULL)
		{
			GenName tempGN(*snacc.location);
			result->location = tempGN.GetGenNameStruct();
		}
		
		// Convert the optional deltaRefInfo field if present
		if (snacc.deltaRefInfo != NULL)
			result->deltaRef = cvtDeltaRefInfo(*snacc.deltaRefInfo);
		
		// Convert the cRLScope
		result->crlScope = cvtPerAuthScopeList(snacc.cRLScope);
		
		// Convert the optional lastUpdate field if present
		if (snacc.lastUpdate != NULL)
		{
			// Allocate memory for the CM_Time
			result->lastUpdate = (CM_Time*)malloc(sizeof(CM_Time));
			if (result->lastUpdate == NULL)
				throw MEMORY_EXCEPTION;
			
			Time tempTime(*snacc.lastUpdate);
			strcpy(*result->lastUpdate, tempTime);
		}
		
		// Convert the optional lastChangedCRL field if present
		if (snacc.lastChangedCRL != NULL)
		{
			// Allocate memory for the CM_Time
			result->lastChangedCRL = (CM_Time*)malloc(sizeof(CM_Time));
			if (result->lastChangedCRL == NULL)
				throw MEMORY_EXCEPTION;
			
			Time tempTime(*snacc.lastChangedCRL);
			strcpy(*result->lastChangedCRL, tempTime);
		}
		
		return result;
	}
	catch (...) {
		Internal::FreeCrlReferral(result);
		throw;
	}
} // end of cvtCrlReferralStruct()


DeltaInfo* cvtDeltaRefInfo(const SNACC::DeltaRefInfo& snacc)
{
	DeltaInfo* result = (DeltaInfo*)calloc(1, sizeof(DeltaInfo));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Convert the GeneralName
		GenName tempGN(snacc.deltaLocation);
		tempGN.FillGenNameStruct(result->deltaLoc);
		
		// Convert the lastDelta field if present
		if (snacc.lastDelta != NULL)
		{
			// Allocate memory for the CM_Time
			result->issueDate = (CM_Time*)malloc(sizeof(CM_Time));
			if (result->issueDate == NULL)
				throw MEMORY_EXCEPTION;
			
			Time tempTime(*snacc.lastDelta);
			strcpy(*result->issueDate, tempTime);
		}
		return result;
	}
	catch (...) {
		Internal::FreeGenNameContent(&result->deltaLoc);
		if (result->issueDate != NULL)
			free(result->issueDate);
		free(result);
		throw;
	}
} // end of cvtDeltaRefInfo()

  
char* cvtDisplayText(const SNACC::DisplayText& asnText)
{
	char* result;
	switch (asnText.choiceId)
	{
	case SNACC::DisplayText::ia5StringCid:
		if (asnText.ia5String == NULL)
			throw ASN_EXCEPTION("SNACC::DisplayText::ia5String field is NULL");
		result = strdup(asnText.ia5String->c_str());
		break;
		
	case SNACC::DisplayText::visibleStringCid:
		if (asnText.visibleString == NULL)
			throw ASN_EXCEPTION("SNACC::DisplayText::visibleString field is NULL");
		result = strdup(asnText.visibleString->c_str());
		break;
		
	case SNACC::DisplayText::utf8StringCid:
		if (asnText.utf8String == NULL)
			throw ASN_EXCEPTION("SNACC::DisplayText::utf8String field is NULL");
		result = asnText.utf8String->getAsUTF8();
		break;
		
	case SNACC::DisplayText::bmpStringCid:
		if (asnText.bmpString == NULL)
			throw ASN_EXCEPTION("SNACC::DisplayText::bmpString field is NULL");
		result = asnText.bmpString->getAsUTF8();
		break;
		
	default:
		throw ASN_EXCEPTION("Invalid CHOICE in SNACC::DisplayText");
	}
	
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	return result;
} // end of cvtDisplayText()
  
  
CM_NumberRange* cvtNumberRange(const SNACC::NumberRange& snacc)
{
	CM_NumberRange* result = (CM_NumberRange*)calloc(1, sizeof(CM_NumberRange));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Convert the optional startingNumber field if present
		if (snacc.startingNumber != NULL)
			result->startingNum = cvtIntsToBytes(*snacc.startingNumber);
		
		// Convert the optional endingNumber field if present
		if (snacc.endingNumber != NULL)
			result->endingNum = cvtIntsToBytes(*snacc.endingNumber);
		
		// Convert the optional modulus field if present
		if (snacc.modulus != NULL)
			result->modulus = cvtIntsToBytes(*snacc.modulus);
		
		return result;
	}
	catch (...) {
		Internal::FreeBytes(result->startingNum);
		Internal::FreeBytes(result->endingNum);
		Internal::FreeBytes(result->modulus);
		free(result);
		throw;
	}
} // end of cvtNumberRange()


Bytes_struct* cvtIntsToBytes(const SNACC::AsnInt& theInt)
{
	Bytes_struct* pResult = (Bytes_struct*)malloc(sizeof(Bytes_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		cvtIntToExistingBytes(*pResult, theInt);
		return pResult;
	}
	catch (...) {
		free(pResult);
		throw;
	}
}

void cvtIntToExistingBytes(Bytes_struct& bytes, const SNACC::AsnInt& theInt)
{
	SNACC::AsnInt inInt = theInt;
	bytes.num = inInt.length();
	bytes.data = (uchar*)malloc(bytes.num);
	if (bytes.data == NULL)
		throw MEMORY_EXCEPTION;
	memcpy(bytes.data, (unsigned char *)inInt.c_str(), bytes.num);
}

PerAuthScope_LL* cvtPerAuthScopeList(const SNACC::CRLScopeSyntax& snacc)
{
	PerAuthScope_LL* result = NULL;
	try {
		SNACC::CRLScopeSyntax::const_reverse_iterator i;
		for (i = snacc.rbegin(); i != snacc.rend(); ++i)
		{
			PerAuthScope_LL* pNew = (PerAuthScope_LL*)
				calloc(1, sizeof(PerAuthScope_LL));
			if (pNew == NULL)
				throw MEMORY_EXCEPTION;
			
			// Add to head of the resulting list
			pNew->next = result;
			result = pNew;
			
			// Convert the optional authorityName field (if present)
			if (i->authorityName != NULL)
			{
				GenName tempGN(*i->authorityName);
				pNew->authName = tempGN.GetGenNameStruct();
			}
			
			// Convert the optional distributionPoint field (if present)
			if (i->distributionPoint == NULL)
				pNew->dpName.flag = CM_NOT_PRESENT;
			else
			{
				DistPointName tempDPName(*i->distributionPoint);
				tempDPName.FillDistPtNameStruct(pNew->dpName);
			}
			
			// Convert the optional onlyContains field (if present)
			if (i->onlyContains != NULL)
			{
				pNew->onlyContains = (uchar*)
					cvt_AsnBitMask(*i->onlyContains, sizeof(uchar));
			}
			
			// Convert the optional onlySomeReasons field (if present)
			if (i->onlySomeReasons != NULL)
			{
				pNew->onlySomeReasons = (ushort*)
					cvt_AsnBitMask(*i->onlySomeReasons);
			}
			
			// Convert the optional serialNumberRange field (if present)
			if (i->serialNumberRange != NULL)
				pNew->serialNumRange = cvtNumberRange(*i->serialNumberRange);
			
			// Convert the optional subjectKeyIdRange field (if present)
			if (i->subjectKeyIdRange != NULL)
				pNew->subjKeyIdRange = cvtNumberRange(*i->subjectKeyIdRange);
			
			// Convert the optional nameSubtress field (if present)
			if (i->nameSubtrees != NULL)
			{
				GenNames tempGNs(*i->nameSubtrees);
				pNew->nameSubtrees = tempGNs.GetGenNamesList();
			}
			
			// Convert the optional baseRevocationInfo field (if present)
			if (i->baseRevocationInfo != NULL)
			{
				pNew->baseRevInfo =
					cvtBaseRevocationInfo(*i->baseRevocationInfo);
			}
		} // end of for loop
		
		// Check that at least one item is present
		if (result == NULL)
			throw ASN_EXCEPTION("SNACC::CRLScopeSyntax must contain at least one PerAuthorityScope");
		
		return result;
	}
	catch (...) {
		Internal::FreePerAuthScope(result);
		throw;
	}
} // end of cvtPerAuthScopeList()


Priv_flags* cvtPrivFlagsStruct(const SNACC::PrivilegeFlags& snacc)
{
	Priv_flags* result = (Priv_flags*)calloc(1, sizeof(Priv_flags));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		if (snacc.choiceId == SNACC::PrivilegeFlags::sigFlagsCid)
		{
			result->type = Priv_flags::SIG_FLAGS;
			
			if (snacc.sigFlags == NULL)
				throw ASN_EXCEPTION("SNACC::PrivilegeFlags::sigFlags field is NULL");
			
			if (snacc.sigFlags->sigPrivFlags != NULL)
			{
				result->privs =
					Internal::CvtLongArray(*snacc.sigFlags->sigPrivFlags);
			}
		}
		else if (snacc.choiceId == SNACC::PrivilegeFlags::kmFlagsCid)
		{
			result->type = Priv_flags::KM_FLAGS;
			
			if (snacc.kmFlags == NULL)
				throw ASN_EXCEPTION("SNACC::PrivilegeFlags::kmFlags field is NULL");
			
			if (snacc.kmFlags->kmPrivFlags != NULL)
			{
				result->privs = Internal::CvtLongArray(*(SNACC::SigPrivFlagsSeqOf*)
					snacc.kmFlags->kmPrivFlags);
			}
		}
		else
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::PrivilegeFlags");
		
		return result;
	}
	catch (...) {
		if (result->privs != NULL)
		{
			free(result->privs->array);
			free(result->privs);
		}
		free(result);
		throw;
	}
} // end of cvtPrivFlagsStruct()


CMUserNotice* cvtQualifierToUserNotice(const SNACC::UserNotice& snacc)
{
	CMUserNotice* pResult = (CMUserNotice*)calloc(1, sizeof(CMUserNotice));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Convert the noticeRef if present
		if (snacc.noticeRef != NULL)
		{
			pResult->noticeRef = (NoticeRef*)calloc(1, sizeof(NoticeRef));
			if (pResult->noticeRef == NULL)
				throw MEMORY_EXCEPTION;
			
			pResult->noticeRef->org =
				cvtDisplayText(snacc.noticeRef->organization);
			
			SNACC::NoticeReferenceSeqOf::reverse_iterator i =
				snacc.noticeRef->noticeNumbers.rbegin();
			for ( ; i != snacc.noticeRef->noticeNumbers.rend(); ++i)
			{
				Bytes_struct_LL* pNew = (Bytes_struct_LL*)
					calloc(1, sizeof(Bytes_struct_LL));
				if (pNew == NULL)
					throw MEMORY_EXCEPTION;
				
				pNew->next = pResult->noticeRef->notices;
				pResult->noticeRef->notices = pNew;
				pNew->bytes_struct = cvtIntsToBytes(*i);
			}
		}
		
		// Convert the explicitText if present
		if (snacc.explicitText != NULL)
			pResult->explicitText = cvtDisplayText(*snacc.explicitText);
		
		return pResult;
	}
	catch (...) {
		if (pResult->noticeRef != NULL)
		{
			if (pResult->noticeRef->org != NULL)
				free(pResult->noticeRef->org);
			Internal::FreeBytes_LL(&pResult->noticeRef->notices);
			free(pResult->noticeRef);
		}
		if (pResult->explicitText != NULL)
			free(pResult->explicitText);
		free(pResult);
		throw;
	}
} // end of cvtQualifierToUserNotice()


bool dupExtsExist(const UnknownExtensions& unkExts)
{
	for (UnknownExtensions::const_iterator i = unkExts.begin(); i !=
		unkExts.end(); i++)
	{
		UnknownExtensions::const_iterator j = i;
		for (++j; j != unkExts.end(); j++)
		{
			if (i->OID() == j->OID())
				return true;
		}
	}
	return false;
}

bool checkEmailConstraint(const char *name, const char *constraint, long min, long max)
{
	

	// Determine if the constraint applies to this name
	const char* pEnd = CML::striEnd(name, constraint);
	if (pEnd == NULL)
		return false;
	
	if (pEnd == name)
	{
		// The constraint exactly matches the name, so return true if
		// min is zero, else return false
		if (min == 0)
			return true;
		else
			return false;
	}
	else if (pEnd[-1] == '@')
	{
		// The constraint specifies a particular host, so return true if
		// min is zero or one, and max is at least one (or unspecified)
		if ((min <= 1) && (max != 0))
			return true;
		else
			return false;
	}
	else if (*pEnd == '.')
	{
		// The constraint specifies a domain, so count the number of
		// unmatched domain components
		int nUnmatched = 1;
		for (const char* pStr = pEnd - 1; (*pStr != '@') &&
			(pStr != name); pStr--)
		{
			if (*pStr == '.')
				++nUnmatched;
		}
		
		// Return true if the number of unmatched domain components
		// falls within the min and max values
		if ((nUnmatched >= min) && ((max < 0) || (nUnmatched <= max)))
			return true;
		else
			return false;
	}
	else
		return false;
}



// end of CM_Extensions.cpp
