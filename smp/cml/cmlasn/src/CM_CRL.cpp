/*****************************************************************************
File:     CM_CRL.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the CertificateList, Revocations, and
		  RevokedEntry classes and the CM_DecodeCRL function.

Created:  10 August 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  18 May 2004

Version:  2.4

*****************************************************************************/


////////////////////
// Included Files //
////////////////////
#include "cmlasn_internal.h"


// Using CML::ASN namespace
using namespace CML::ASN;



////////////////////////////
// CM_DecodeCRL2 function //
////////////////////////////
short CM_DecodeCRL2(Bytes_struct* encodedCRL, CRL_struct **decCRL,
					CM_BOOL decRevoked, CM_BOOL decExts)
{
	// Check parameters
	if ((encodedCRL == NULL) || (encodedCRL->data == NULL) || (decCRL == NULL))
		return CMLASN_INVALID_PARAMETER;

	try {
		// Initialize result
		*decCRL = NULL;

		// Construct a temporary Bytes object
		Bytes asnData(encodedCRL->num, encodedCRL->data);

		// Decode and convert the CRL
		CertificateList tmpCRL(asnData);
		*decCRL = tmpCRL.GetCrlStruct((decRevoked != FALSE), (decExts != FALSE));

		return CMLASN_SUCCESS;
	}
	catch (Exception& err) {
		return err;
	}
	catch (SNACC::SnaccException& ) {
		return CMLASN_DECODE_ERROR;
	}
	catch (...) {
		return CMLASN_UNKNOWN_ERROR;
	}
}


///////////////////////////
// CM_DecodeCRL function //
///////////////////////////
short CM_DecodeCRL(Bytes_struct* encodedCRL, CRL_struct **decCRL)
{
	return CM_DecodeCRL2(encodedCRL, decCRL, TRUE, TRUE);
}


//////////////////////////////////////////
// CertificateList class implementation //
//////////////////////////////////////////
CertificateList::CertificateList()
{
	// Initialize default version and pointers
	version = SNACC::Version::v1;
	nextUpdate = NULL;
	m_pEncRevs = NULL;
}


CertificateList::CertificateList(const SNACC::CertificateList& snacc)
{
	// Initialize pointers
	nextUpdate = NULL;
	m_pEncRevs = NULL;

	operator=(snacc);
}


CertificateList::CertificateList(const Bytes& asn)
{
	// Initialize pointers
	nextUpdate = NULL;
	m_pEncRevs = NULL;

	operator=(asn);
}


CertificateList::CertificateList(const CertificateList& that)
{
	// Initialize pointers
	nextUpdate = NULL;
	m_pEncRevs = NULL;

	operator=(that);
}


CertificateList& CertificateList::operator=(const SNACC::CertificateList& snacc)
{
	// Delete existing values in member variables
	Clear();

	try {
		// Set the version
		if (snacc.toBeSigned.version == NULL)
			version = SNACC::Version::v1;
		else
		{
			if (SNACC::Version::v2 != *snacc.toBeSigned.version)
				throw ASN_EXCEPTION("SNACC::CertificateList::version must be v2 if present");
			version = SNACC::Version::v2;
		}
		
		// Set the signature algorithm ID
		signature = snacc.toBeSigned.signature;
		
		// Set the issuer distinguished name
		issuer = snacc.toBeSigned.issuer;
		
		// Set the thisUpdate and optional nextUpdate times
		thisUpdate = snacc.toBeSigned.thisUpdate;
		if (snacc.toBeSigned.nextUpdate != NULL)
		{
			nextUpdate = new Time(*snacc.toBeSigned.nextUpdate);
			if (nextUpdate == NULL)
				throw MEMORY_EXCEPTION;
		}
		else
		{
			delete nextUpdate;
			nextUpdate = NULL;
		}
		
		// Set the revoked certificates
		if (snacc.toBeSigned.revokedCertificates != NULL)
			m_revCerts = *snacc.toBeSigned.revokedCertificates;
		
		// Set the extensions (if present)
		if (snacc.toBeSigned.crlExtensions != NULL)
			crlExts = *snacc.toBeSigned.crlExtensions;

		// Check that the version number is correct
		if ((version == SNACC::Version::v1) && ExtIsCritical())
			throw ASN_EXCEPTION("SNACC::CertificateList::version must be v2 if critical extension present");
		
		// Set the outer signature algorithm ID and signature value
		algorithm = snacc.algorithm;
		sigValue = snacc.signature;
		
		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


CertificateList& CertificateList::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


CertificateList& CertificateList::operator=(const CertificateList& other)
{
	if (this != &other)
	{
		try {
			version = other.version;
			signature = other.signature;
			issuer = other.issuer;
			thisUpdate = other.thisUpdate;
			if (other.nextUpdate != NULL)
			{
				if (nextUpdate == NULL)
				{
					nextUpdate = new Time(*other.nextUpdate);
					if (nextUpdate == NULL)
						throw MEMORY_EXCEPTION;
				}
				else
					*nextUpdate = *other.nextUpdate;
			}
			else
			{
				delete nextUpdate;
				nextUpdate = NULL;
			}
			crlExts = other.crlExts;
			algorithm = other.algorithm;
			sigValue = other.sigValue;

			if (other.m_pEncRevs != NULL)
			{
				// Reset the other AsnBuf for reading
				other.m_pEncRevs->ResetMode();

				if (m_pEncRevs == NULL)
				{
					m_pEncRevs = new SNACC::AsnBuf(*other.m_pEncRevs);
					if (m_pEncRevs == NULL)
						throw MEMORY_EXCEPTION;
				}
				else
					*m_pEncRevs = *other.m_pEncRevs;
			}
			else
			{
				delete m_pEncRevs;
				m_pEncRevs = NULL;
			}
			m_revCerts = other.m_revCerts;
		}
		catch (...) {
			Clear();
			throw;
		}
	}
	return *this;
}


Revocations& CertificateList::GetRevocations()
{
	if (m_pEncRevs != NULL)
	{
		// Decode the encoded list of revoked certs
		m_revCerts = *m_pEncRevs;

		// Delete the encoded ones
		delete m_pEncRevs;
		m_pEncRevs = NULL;
	}

	return m_revCerts;
}


const Revocations& CertificateList::GetRevocations() const
{
	if (m_pEncRevs != NULL)
	{
		// Decode the encoded list of revoked certs
		m_revCerts = *m_pEncRevs;

		// Delete the encoded ones
		delete m_pEncRevs;
		m_pEncRevs = NULL;
	}

	return m_revCerts;
}


void CertificateList::SetRevocations(const Revocations& revCerts)
{
	if (m_pEncRevs != NULL)
	{
		delete m_pEncRevs;
		m_pEncRevs = NULL;
	}
	
	m_revCerts = revCerts;
}


void CertificateList::Clear(void)
{
	version = SNACC::Version::v1;
	signature.Clear();
	issuer = NULL;
	if (nextUpdate != NULL)
	{
		delete nextUpdate;
		nextUpdate = NULL;
	}
	crlExts.Clear();
	algorithm.Clear();
	sigValue.Clear();

	if (m_pEncRevs != NULL)
	{
		delete m_pEncRevs;
		m_pEncRevs = NULL;
	}
	m_revCerts.Clear();
}



ulong CertificateList::Decode(const Bytes& asn)
{
	using namespace SNACC;

	Clear();
	try {
		// Create a SNACC::AsnRvsBuf and install it into the AsnBuf
		AsnRvsBuf asnStream((char*)asn.GetData(), asn.Len());
		AsnBuf b(&asnStream);

		// Decode the outer SEQ tag and length
		AsnLen totalBytesDec = 0;
		AsnTag tag = BDecTag(b, totalBytesDec);
		if (tag != MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
			throw ASN_EXCEPTION("Invalid tag on SNACC::CertificateList");
		AsnLen outerLen = BDecLen(b, totalBytesDec);

		// Decode the inner SEQ tag and length
		AsnLen innerBytesDec = 0;
		tag = BDecTag(b, innerBytesDec);
		if (tag != MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
			throw ASN_EXCEPTION("Invalid tag on SNACC::CertificateListToBeSigned");
		AsnLen innerLen = BDecLen(b, innerBytesDec);

		// Decode and convert the toBeSigned CRL elements
		innerBytesDec += DecodeCrlToSign(b, innerLen);

		// Decode and convert the algorithm identfier
		AlgorithmIdentifier snaccAlgID;
		snaccAlgID.BDec(b, innerBytesDec);
		algorithm = snaccAlgID;

		// Decode and convert the signature value
		AsnBits snaccBits;
		snaccBits.BDec(b, innerBytesDec);
		sigValue = snaccBits;

		/// Decode the EOC tag and length if necessary
		if (outerLen == INDEFINITE_LEN)
			BDecEoc(b, innerBytesDec);
		else if (outerLen != innerBytesDec)
			throw ASN_EXCEPTION("Invalid length on SNACC::CertificateList");
		
		return totalBytesDec + innerBytesDec;
	}
	catch (Exception& ) {
		Clear();
		throw;
	}
	catch (SnaccException& snaccE) {
		Clear();
		throw ASN_EXCEPTION2(snaccE.what(), NULL);
	}
	catch (...) {
		Clear();
		throw;
	}
}


ulong CertificateList::Encode(Bytes& asn) const
{
	// Get the SNACC form of this CRL
	SNACC::CertificateList* pCRL = GetSnacc();

	try {
		// Encode the CRL
		ulong numEncoded = asn.Encode(*pCRL, "SNACC::CertificateList");

		// Delete the temporary variable
		delete pCRL;

		return numEncoded;
	}
	catch (...) {
		delete pCRL;
		throw;
	}
} // end of CertificateList::Encode()


SNACC::CertificateList* CertificateList::GetSnacc() const
{
	// Create the new SNACC::CertificateList
	SNACC::CertificateList* pCRL = NULL;

	try {
		pCRL = new SNACC::CertificateList;
		if (pCRL == NULL)
			throw MEMORY_EXCEPTION;

		// Initialize the pointers
		pCRL->toBeSigned.version = NULL;
		pCRL->toBeSigned.nextUpdate = NULL;
		pCRL->toBeSigned.revokedCertificates = NULL;
		pCRL->toBeSigned.crlExtensions = NULL;

		// Get the SNACC form of the version (if necessary)
		if (ExtIsCritical() || (version == SNACC::Version::v2))
		{
			pCRL->toBeSigned.version = new SNACC::Version(SNACC::Version::v2);
			if (pCRL->toBeSigned.version == NULL)
				throw MEMORY_EXCEPTION;
		}

		// Fill in the SNACC form of the signature AlgID
		signature.FillSnacc(pCRL->toBeSigned.signature);

		// Fill in the SNACC form of the issuer DN
		issuer.FillSnacc(pCRL->toBeSigned.issuer);

		// Get the SNACC form of the thisUpdate and nextUpdate times
		pCRL->toBeSigned.thisUpdate = thisUpdate;
		if (nextUpdate != NULL)
		{
			pCRL->toBeSigned.nextUpdate = new SNACC::Time(*nextUpdate);
			if (pCRL->toBeSigned.nextUpdate == NULL)
				throw MEMORY_EXCEPTION;
		}

		// Get the SNACC form of the revoked certificates
		if (m_pEncRevs != NULL)
		{
			// Allocate memory for the list of revoked certificates
			pCRL->toBeSigned.revokedCertificates = new
				SNACC::CertificateListToBeSignedSeqOf;
			if (pCRL->toBeSigned.revokedCertificates == NULL)
				throw MEMORY_EXCEPTION;

			// Decode the encoded list of revoked certs
			try {
				m_pEncRevs->ResetMode();
				SNACC::AsnLen nBytesDecoded = 0;
				pCRL->toBeSigned.revokedCertificates->BDec(*m_pEncRevs,
					nBytesDecoded);
			}
			catch (...) {
				throw ASN_EXCEPTION("Error decoding SNACC::CertificateListToBeSignedSeqOf");
			}
		}
		else
			pCRL->toBeSigned.revokedCertificates = m_revCerts.GetSnacc();

		// Get the SNACC form of the extensions
		pCRL->toBeSigned.crlExtensions = crlExts.GetSnacc();
		
		// Fill in the SNACC form of the outer signature AlgID and value
		algorithm.FillSnacc(pCRL->algorithm);
		pCRL->signature.Set(sigValue.GetData(), sigValue.BitLen());

		// Return result
		return pCRL;
	}
	catch (...) {
		delete pCRL;
		throw;
	}
} // end of CertificateList::GetSnacc()


// Get the C form of this CRL
CRL_struct* CertificateList::GetCrlStruct(bool incRevocations,
										  bool incExtensions) const
{
	CRL_struct* pCRL = (CRL_struct*)calloc(1, sizeof(CRL_struct));
	if (pCRL == NULL)
		throw MEMORY_EXCEPTION;

	try {
		pCRL->version = short(version + 1);
		pCRL->signature = signature.algorithm.GetChar();

		pCRL->issuer = strdup(issuer);
		if (pCRL->issuer == NULL)
			throw MEMORY_EXCEPTION;

		strcpy(pCRL->thisUpdate, thisUpdate);
		if (nextUpdate != NULL)
		{
			pCRL->nextUpdate = (CM_Time*)malloc(sizeof(CM_Time));
			if (pCRL->nextUpdate == NULL)
				throw MEMORY_EXCEPTION;
			strcpy(*pCRL->nextUpdate, *nextUpdate);
		}

		if (incRevocations)
		{
			if (m_pEncRevs != NULL)
			{
				// Reset the AsnBuf for reading
				m_pEncRevs->ResetMode();

				// Decode the encoded list of revoked certs
				SNACC::CertificateListToBeSignedSeqOf snaccRevs;
				try {
					SNACC::AsnLen nBytesDecoded = 0;
					snaccRevs.BDec(*m_pEncRevs, nBytesDecoded);
				}
				catch (...) {
					throw ASN_EXCEPTION("Error decoding SNACC::CertificateListToBeSignedSeqOf");
				}

				// Convert the SNACC revocations and delete the encoded ones
				m_revCerts = snaccRevs;
				delete m_pEncRevs;
				m_pEncRevs = NULL;
			}
			pCRL->revoked = m_revCerts.GetRevCertsList();
		}

		if (incExtensions)
			pCRL->exts = crlExts.GetCrlExtsStruct();

		pCRL->sig.alg = algorithm.algorithm.GetChar();
		Internal::CvtBytesToSigStruct(pCRL->sig, sigValue);

		return pCRL;
	}
	catch (...) {
		CM_FreeCRL(&pCRL);
		throw;
	}
} // end of CertificateList::GetCrlStruct()



bool CertificateList::IsDelta() const
{
	if ((crlExts.pDeltaCRL != NULL) || (crlExts.pBaseUpdate != NULL))
		return true;

	if (crlExts.pCrlScope != NULL)
	{
		SNACC::CRLScopeSyntax::const_iterator i = crlExts.pCrlScope->begin();
		for ( ; i != crlExts.pCrlScope->end(); ++i)
		{
			if (i->baseRevocationInfo != NULL)
				return true;
		}
	}

	return false;
}


bool CertificateList::MatchesScope(CertType certType, const DN& certIssuer,
								   const DistributionPoint* pDistPt,
								   bool isCritical,
								   const RevocationReasons* pReasons) const
{
	// This CRL does not match scope if the the CRL distribution point passed
	// in is critical and the CRL does not contain an issuing 
	// distibution point.
	if (isCritical && (pDistPt != NULL) && (pDistPt->distPoint != NULL) &&
		(crlExts.pIssuingDP == NULL))
		return false;

	// If the crlIssuer field is absent from the CRL distribution point, check
	// the issuer of the CRL is the same as the issuer of the cert
	if ((pDistPt == NULL) || (pDistPt->crlIssuer == NULL))
	{
		if (issuer != certIssuer)
			return false;

		// If this is a complete CRL, return true
		if (crlExts.pIssuingDP == NULL)
			return true;
	}
	else
	{
		// Check that the issuer of the CRL is one of the names in the
		// crlIssuer field and the indirectCRL flag is set
		if (!pDistPt->crlIssuer->IsPresent(issuer))
			return false;
		if ((crlExts.pIssuingDP == NULL) || !crlExts.pIssuingDP->indirectCRL)
			return false;
	}

	const IssuingDistPointExtension& idp = *crlExts.pIssuingDP;

	// Check if the CRL covers revocations for this type of cert
	if (idp.onlyContainsAuthorityCerts && (certType != CACert))
		return false;
	else if (idp.onlyContainsUserCerts && (certType != EndEntityCert))
		return false;
	else if (idp.onlyContainsAttributeCerts)
		return false;

	// Check if the CRL covers revocations for the specified reasons
	static const ASN::RevocationReasons kNULL_Reasons;
	if (idp.onlySomeReasons != NULL)
	{
		if ((pDistPt != NULL) && (pDistPt->reasons != NULL))
			pReasons = pDistPt->reasons;
		
		if (pReasons != NULL)
		{
			if ((*idp.onlySomeReasons & *pReasons) == kNULL_Reasons)
				return false;
		}
	}

	// If the distribution points are specified, check that one of the
	// names in the distribution point field matches one of the IDP names
	if ((pDistPt != NULL) && (idp.distPoint != NULL))
	{
		// Find the full distribution point names in the distribution
		// point or the crlIssuer fields, or build the full names from
		// the relative name
		const GenNames* pDpNames = NULL;
		std::list<DN> dpDNs;
		if (pDistPt->distPoint != NULL)
		{
			if (pDistPt->distPoint->GetType() ==
				DistPointName::DIST_PT_FULL_NAME)
				pDpNames = &pDistPt->distPoint->GetFullName();
			else	// DIST_PT_REL_NAME
			{
				// Distribution point is relative to either the crlIssuer
				// (if present) or the certificate issuer
				if (pDistPt->crlIssuer != NULL)
				{
					// Copy each of the X.500 DNs into the dpDN list
					GenNames::const_iterator iGN =
						pDistPt->crlIssuer->Find(GenName::X500);
					while (iGN != pDistPt->crlIssuer->end())
					{
						dpDNs.push_back(*iGN->GetName().dn);
						iGN = pDistPt->crlIssuer->FindNext(iGN,
							GenName::X500);
					}
				}
				else	// Copy the cert issuer DN into the dpDN list
					dpDNs.push_back(certIssuer);
				
				// Append the relative name to each of the DNs in the dpDN
				// list
				std::list<DN>::iterator iDN;
				for (iDN = dpDNs.begin(); iDN != dpDNs.end(); ++iDN)
					*iDN += pDistPt->distPoint->GetRelativeName();
			}
		}
		else if (pDistPt->crlIssuer != NULL)
			pDpNames = pDistPt->crlIssuer;
		else	// Distribution point is just the certificate issuer
			dpDNs.push_back(certIssuer);
		
		// Check that one of the distribution point names in the IDP
		// matches a name from the cert's distribution points
		if (idp.distPoint->GetType() == DistPointName::DIST_PT_FULL_NAME)
		{
			if (pDpNames != NULL)
			{
				if (!pDpNames->IsOnePresent(idp.distPoint->GetFullName()))
					return false;
			}
			else
			{
				bool matchFound = false;
				std::list<DN>::const_iterator iDN = dpDNs.begin();
				for ( ; (iDN != dpDNs.end()) && !matchFound; ++iDN)
				{
					if (idp.distPoint->GetFullName().IsPresent(*iDN))
						matchFound = true;
				}
				if (!matchFound)
					return false;
			}
		}
		else	// DIST_PT_REL_NAME
		{
			// Build full IDP name
			DN fullIDPName = issuer;
			fullIDPName += idp.distPoint->GetRelativeName();
			if (pDpNames != NULL)
			{
				if (!pDpNames->IsPresent(fullIDPName))
					return false;
			}
			else
			{
				bool matchFound = false;
				std::list<DN>::const_iterator iDN = dpDNs.begin();
				for ( ; (iDN != dpDNs.end()) && !matchFound; ++iDN)
				{
					if (*iDN == fullIDPName)
						matchFound = true;
				}
				if (!matchFound)
					return false;
			}
		}
	}
	else if (pDistPt == NULL)	// Check this complete CRL
	{
		if (idp.distPoint != NULL)
		{
			// REN -- 2/1/2002 -- Temporary fix for new PKIX part 1 profile:
			// According to X.509, complete CRLs should not have a
			// distribution point in the IDP extension, but PKIX part 1
			// currently allows a DP if it matches the cert issuer's DN.
			//
			// Check that if a complete CRL has a DP name, that it matches
			// the cert issuer's DN
			if (idp.distPoint->GetType() == DistPointName::DIST_PT_FULL_NAME)
			{
				if (!idp.distPoint->GetFullName().IsPresent(certIssuer))
					return false;
			}
			else	// DIST_PT_REL_NAME
			{
				DN fullIssuer = issuer;
				fullIssuer += idp.distPoint->GetRelativeName();
				if (fullIssuer != certIssuer)
					return false;
			}
		}
	}

	return true;
} // end of CertificateList::MatchesScope()


GenName CertificateList::GetDistPtName() const
{
	if ((crlExts.pIssuingDP != NULL) &&
		(crlExts.pIssuingDP->distPoint != NULL))
	{
		const DistPointName& dpName = *crlExts.pIssuingDP->distPoint;
		if (dpName.GetType() == DistPointName::DIST_PT_REL_NAME)
		{
			DN fullName(issuer);
			fullName += dpName.GetRelativeName();
			return fullName;
		}
		else	// DIST_PT_FULL_NAME
		{
			// Return the first X.500 DN (if one is present)
			GenNames::const_iterator iGN =
				dpName.GetFullName().Find(GenName::X500);
			if (iGN != dpName.GetFullName().end())
				return *iGN;

			// Return the first URL (if one is present)
			iGN = dpName.GetFullName().Find(GenName::URL);
			if (iGN != dpName.GetFullName().end())
				return *iGN;
		}
	}

	return issuer;
} // end of CertificateList::GetDistPtName()


bool CertificateList::ExtIsCritical() const
{
	if (((crlExts.pAuthKeyID != NULL) && crlExts.pAuthKeyID->critical) ||
		((crlExts.pIssuerAltNames != NULL) && crlExts.pIssuerAltNames->critical) ||
		((crlExts.pIssuingDP != NULL) && crlExts.pIssuingDP->critical) ||
		((crlExts.pCrlNumber != NULL) && crlExts.pCrlNumber->critical) ||
		((crlExts.pDeltaCRL != NULL) && crlExts.pDeltaCRL->critical) ||
		((crlExts.pCrlScope != NULL) && crlExts.pCrlScope->critical) ||
		((crlExts.pStatusRefs != NULL) && crlExts.pStatusRefs->critical) ||
		((crlExts.pStreamID != NULL) && crlExts.pStreamID->critical) ||
		((crlExts.pOrderedList != NULL) && crlExts.pOrderedList->critical) ||
		((crlExts.pDeltaInfo != NULL) && crlExts.pDeltaInfo->critical) ||
		((crlExts.pBaseUpdate != NULL) && crlExts.pBaseUpdate->critical))
		return true;

	for (UnknownExtensions::const_iterator i = crlExts.unknownExts.begin(); i !=
		crlExts.unknownExts.end(); i++)
	{
		if (i->critical)
			return true;
	}

	return false;
}


ulong CertificateList::DecodeCrlToSign(SNACC::AsnBuf& b,
									   const SNACC::AsnLen& seqLen)
{
	using namespace SNACC;

	try {
		// Decode the next inner tag
		AsnLen seqBytesDec = 0;
		AsnTag tag = BDecTag(b, seqBytesDec);

		// If the version is present, decode and convert it
		if ((tag == MAKE_TAG_ID (UNIV, PRIM, INTEGER_TAG_CODE)))
		{
			AsnLen elmtLen = BDecLen(b, seqBytesDec);
			SNACC::Version snaccVer;
			snaccVer.BDecContent(b, tag, elmtLen, seqBytesDec);

			// Set the version
			if (SNACC::Version::v2 != snaccVer)
				throw ASN_EXCEPTION("SNACC::CertificateList::version must be v2 if present");
			version = SNACC::Version::v2;

			// Decode the next tag
			tag = BDecTag(b, seqBytesDec);
		}
		else	// Set the version to the default
			version = SNACC::Version::v1;

		// Decode and convert the signature algorithm
		if (tag != MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
			throw ASN_EXCEPTION("Tag mismatch in SNACC::CertificateList");
		AsnLen elmtLen = BDecLen(b, seqBytesDec);
		SNACC::AlgorithmIdentifier snaccAlgID;
		snaccAlgID.BDecContent(b, tag, elmtLen, seqBytesDec);
		signature = snaccAlgID;

		// Decode and convert the issuer name
		tag = BDecTag(b, seqBytesDec);
		if (tag != MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
			throw ASN_EXCEPTION("Tag mismatch in SNACC::CertificateList");
		elmtLen = BDecLen(b, seqBytesDec);
		SNACC::Name snaccName;
        snaccName.BDecContent(b, tag, elmtLen, seqBytesDec);
		issuer = snaccName;

		// Decode and convert the thisUpdate time
		tag = BDecTag(b, seqBytesDec);
		if ((tag != MAKE_TAG_ID (UNIV, PRIM, UTCTIME_TAG_CODE)) &&
			(tag != MAKE_TAG_ID (UNIV, CONS, UTCTIME_TAG_CODE)) &&
			(tag != MAKE_TAG_ID (UNIV, PRIM, GENERALIZEDTIME_TAG_CODE)) &&
			(tag != MAKE_TAG_ID (UNIV, CONS, GENERALIZEDTIME_TAG_CODE)))
			throw ASN_EXCEPTION("Tag mismatch in SNACC::CertificateList");
		elmtLen = BDecLen(b, seqBytesDec);
		SNACC::Time snaccTime;
		snaccTime.BDecContent(b, tag, elmtLen, seqBytesDec);
		thisUpdate = snaccTime;

		// Save current read location
		AsnBufLoc bufLoc = b.GetReadLoc();

		// Check if done
		if (seqBytesDec == seqLen)
			return seqBytesDec;
		else
		{
			tag = BDecTag(b, seqBytesDec);
			if ((seqLen == INDEFINITE_LEN) && (tag == EOC_TAG_ID))
			{
				BDEC_2ND_EOC_OCTET(b, seqBytesDec);
				return seqBytesDec;
			}
		}

		// Decode and convert the nextUpdate time if present
		if ((tag == MAKE_TAG_ID (UNIV, PRIM, UTCTIME_TAG_CODE)) ||
			(tag == MAKE_TAG_ID (UNIV, CONS, UTCTIME_TAG_CODE)) ||
			(tag == MAKE_TAG_ID (UNIV, PRIM, GENERALIZEDTIME_TAG_CODE)) ||
			(tag == MAKE_TAG_ID (UNIV, CONS, GENERALIZEDTIME_TAG_CODE)))
		{
			elmtLen = BDecLen(b, seqBytesDec);
			SNACC::Time snaccTime;
            snaccTime.BDecContent(b, tag, elmtLen, seqBytesDec);
			nextUpdate = new ASN::Time(snaccTime);
			if (nextUpdate == NULL)
				throw MEMORY_EXCEPTION;

			// Update current read location
			bufLoc = b.GetReadLoc();

			// Check if done
			if (seqBytesDec == seqLen)
				return seqBytesDec;
			else
			{
				tag = BDecTag(b, seqBytesDec);
				if ((seqLen == INDEFINITE_LEN) && (tag == EOC_TAG_ID))
				{
					BDEC_2ND_EOC_OCTET(b, seqBytesDec);
					return seqBytesDec;
				}
			}
		}

		// Grab the revokedCertificates if present
		if (tag == MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
		{
			// Reset read location and adjust number of bytes decoded
			b.SetReadLoc(bufLoc);
			--seqBytesDec;

			// Create a new AsnBuf for the revoked certs and copy them
			m_pEncRevs = new AsnBuf;
			if (m_pEncRevs == NULL)
				throw MEMORY_EXCEPTION;
			b.GrabAny(*m_pEncRevs, seqBytesDec);

			// Check if done
			if (seqBytesDec == seqLen)
				return seqBytesDec;
			else
			{
				tag = BDecTag(b, seqBytesDec);
				if ((seqLen == INDEFINITE_LEN) && (tag == EOC_TAG_ID))
				{
					BDEC_2ND_EOC_OCTET(b, seqBytesDec);
					return seqBytesDec;
				}
			}
		}

		// Decode and convert the extensions if present
		if (tag == MAKE_TAG_ID (CNTX, CONS, 0))
		{
			elmtLen = BDecLen(b, seqBytesDec);

			tag = BDecTag(b, seqBytesDec);
			if (tag != MAKE_TAG_ID (UNIV, CONS, SEQ_TAG_CODE))
				throw ASN_EXCEPTION("Tag mismatch in SNACC::CertificateList");
			AsnLen innerLen = BDecLen(b, seqBytesDec);

			SNACC::Extensions snaccExts;
			snaccExts.BDecContent(b, tag, innerLen, seqBytesDec);
			crlExts = snaccExts;

			if (elmtLen == INDEFINITE_LEN)
				BDecEoc(b, seqBytesDec);
		}

		if (seqLen == INDEFINITE_LEN)
			BDecEoc(b, seqBytesDec);
		else if (seqLen != seqBytesDec)
			throw ASN_EXCEPTION("Invalid length on SNACC::CertificateList");

		return seqBytesDec;
	}
	catch (Exception& ) {
		Clear();
		throw;
	}
	catch (SnaccException& snaccE) {
		Clear();
		throw ASN_EXCEPTION2(snaccE.what(), NULL);
	}
	catch (...) {
		Clear();
		throw;
	}
} // end of CertificateList::DecodeCrlToSign()


//////////////////////////////////////
// Revocations class implementation //
//////////////////////////////////////
Revocations::Revocations(const SNACC::CertificateListToBeSignedSeqOf& snacc)
{
	operator=(snacc);
}


Revocations& Revocations::operator=(const SNACC::AsnBuf& asnBuf)
{
	Clear();

	// Reset the AsnBuf for reading
	asnBuf.ResetMode();

	// Decode the ASN.1 encoded list of revoked certificates
	SNACC::CertificateListToBeSignedSeqOf snacc;
	SNACC::AsnLen nBytesDecoded = 0;
	try {
		snacc.BDec(asnBuf, nBytesDecoded);
	}
	catch (...) {
		throw ASN_EXCEPTION("Error decoding SNACC::CertificateListToBeSignedSeqOf");
	}

	// Check that the entire AsnBuf was decoded
	asnBuf.ResetMode();
	if (nBytesDecoded != asnBuf.length())
		throw ASN_EXCEPTION("Error decoding SNACC::CertificateListToBeSignedSeqOf");

	operator=(snacc);
	return *this;
}


Revocations& Revocations::operator=(const SNACC::CertificateListToBeSignedSeqOf& snacc)
{
	clear();
	try {
		m_revCertsPresent = true;
		SNACC::CertificateListToBeSignedSeqOf::const_iterator i;
		for (i = snacc.begin(); i != snacc.end(); ++i)
			push_back(*i);

		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


SNACC::CertificateListToBeSignedSeqOf* Revocations::GetSnacc() const
{
	SNACC::CertificateListToBeSignedSeqOf* result = NULL;

	try {
		if (!empty() || m_revCertsPresent)
		{
			result = new SNACC::CertificateListToBeSignedSeqOf();
			if (result == NULL)
				throw MEMORY_EXCEPTION;
			
			for (const_iterator i = begin(); i != end(); i++)
			{
				SNACC::CertificateListToBeSignedSeqOfSeq& newEntry =
					*result->append();
				i->FillSnaccRevEntry(newEntry);
			}
		}
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


// Get the C form of the revoked certificates
RevCerts_LL* Revocations::GetRevCertsList() const
{
	RevCerts_LL* pRevEntries = NULL;

	try {
		for (const_reverse_iterator i = rbegin(); i != rend(); i++)
		{
			RevCerts_LL* pNew = i->GetRevCertsStruct();
			pNew->next = pRevEntries;
			pRevEntries = pNew;
		}
		return pRevEntries;
	}
	catch (...) {
		while (pRevEntries != NULL)
		{
			RevCerts_LL* pNext = pRevEntries->next;

			if (pRevEntries->serialNum.data != NULL)
				free(pRevEntries->serialNum.data);
			if (pRevEntries->revDate != NULL)
				free(pRevEntries->revDate);
			Internal::FreeCRLEntryExtensions(pRevEntries->exts);
			free(pRevEntries);

			pRevEntries = pNext;
		}
		throw;
	}
}


Revocations::const_iterator
Revocations::IsRevoked(const SNACC::AsnInt& serialNumber, const DN& certIssuer,
					   const DN& crlIssuer,
					   const SNACC::OrderedListSyntax* pOrder) const
{
	// Initialize the currentIssuer variable to the CRL issuer
	GenNames currentIssuer;
	currentIssuer.push_back(crlIssuer);
	
	const_iterator i;
	for (i = begin(); i != end(); ++i)
	{
		// If the certificate issuer extension is present in this entry,
		// set the currentIssuer to the value in the extension
		if (i->IsCertIssuerExtPresent())
			currentIssuer = *i->EntryExts().pCertIssuer;

		// If the serial number and names match, break out of the loop
		if ((i->SerialNum() == serialNumber) &&
			currentIssuer.IsPresent(certIssuer))
			break;

		// If the list is in ascending order by serial number and the
		// target serial number is less than the current serial number,
		// then return end()
		if ((pOrder != NULL) &&
			(SNACC::OrderedListSyntax::ascSerialNum == *pOrder) &&
			(serialNumber < i->SerialNum()))
			return end();
	}

	return i;
}


///////////////////////////////////////
// RevokedEntry class implementation //
///////////////////////////////////////
RevokedEntry::RevokedEntry()
{
	m_pSnacc = NULL;
	m_pRevDate = NULL;
	m_pExts = NULL;
}


RevokedEntry::RevokedEntry(const SNACC::CertificateListToBeSignedSeqOfSeq& snacc)
{
	m_pSnacc = NULL;
	m_pRevDate = NULL;
	m_pExts = NULL;

	try {
		m_pSnacc = new SNACC::CertificateListToBeSignedSeqOfSeq;
		if (m_pSnacc == NULL)
			throw MEMORY_EXCEPTION;
		m_pSnacc->serialNumber = snacc.serialNumber;

		m_pRevDate = new Time(snacc.revocationDate);
		if (m_pRevDate == NULL)
			throw MEMORY_EXCEPTION;

		if (snacc.crlEntryExtensions == NULL)
			m_pExts = new CrlEntryExtensions;
		else
			m_pExts = new CrlEntryExtensions(*snacc.crlEntryExtensions);
		if (m_pExts == NULL)
			throw MEMORY_EXCEPTION;
	}
	catch (...) {
		Clear();
		throw;
	}
}


RevokedEntry::RevokedEntry(const SNACC::CertificateSerialNumber& serialNumber,
						   const Time& revocationDate,
						   const CrlEntryExtensions* pExts)
{
	m_pSnacc = NULL;
	m_pRevDate = NULL;
	m_pExts = NULL;

	try {
		m_pSnacc = new SNACC::CertificateListToBeSignedSeqOfSeq;
		if (m_pSnacc == NULL)
			throw MEMORY_EXCEPTION;
		m_pSnacc->serialNumber = serialNumber;

		m_pRevDate = new Time(revocationDate);
		if (m_pRevDate == NULL)
			throw MEMORY_EXCEPTION;

		if (pExts == NULL)
			m_pExts = new CrlEntryExtensions;
		else
			m_pExts = new CrlEntryExtensions(*pExts);
		if (m_pExts == NULL)
			throw MEMORY_EXCEPTION;
	}
	catch (...) {
		Clear();
		throw;
	}
}


RevokedEntry::RevokedEntry(const RevokedEntry& that)
{
	m_pSnacc = NULL;
	m_pRevDate = NULL;
	m_pExts = NULL;
	operator=(that);
}


RevokedEntry& RevokedEntry::operator=(const RevokedEntry& other)
{
	if (this != &other)
	{
		Clear();
		try {
			if (other.m_pSnacc != NULL)
			{
				m_pSnacc = new
					SNACC::CertificateListToBeSignedSeqOfSeq(*other.m_pSnacc);
				if (m_pSnacc == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.m_pRevDate != NULL)
			{
				m_pRevDate = new Time(*other.m_pRevDate);
				if (m_pRevDate == NULL)
					throw MEMORY_EXCEPTION;
			}
			
			if (other.m_pExts != NULL)
			{
				m_pExts = new CrlEntryExtensions(*other.m_pExts);
				if (m_pExts == NULL)
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


RevokedEntry& RevokedEntry::operator=(SNACC::CertificateListToBeSignedSeqOfSeq* pSnacc)
{
	if (pSnacc == NULL)
		throw EXCEPTION(CMLASN_INVALID_PARAMETER);

	m_pSnacc = pSnacc;
	m_pRevDate = NULL;
	m_pExts = NULL;
	return *this;
}

bool RevokedEntry::operator==(const RevokedEntry& rhs) const
{
	if (this == &rhs)
		return true;

	// Check that both SNACC objects are present
	if ((m_pSnacc == NULL) && (rhs.m_pSnacc == NULL))
		return true;
	else if ((m_pSnacc == NULL) || (rhs.m_pSnacc == NULL))
		return false;

	// Check serial numbers
	if (m_pSnacc->serialNumber != rhs.m_pSnacc->serialNumber)
		return false;

	// Check revocation time
	if (RevTime() != rhs.RevTime())
		return false;

	// Skip extensions check, just return
	return true;
}

bool RevokedEntry::operator<(const RevokedEntry& rhs) const
{
	if (this == &rhs)
		return false;

	// Check that both SNACC objects are present
	if ((m_pSnacc == NULL) && (rhs.m_pSnacc == NULL))
		return false;
	else if (rhs.m_pSnacc == NULL)
		return false;
	else if (m_pSnacc == NULL)
		return true;

	// Check serial numbers
	if (m_pSnacc->serialNumber < rhs.m_pSnacc->serialNumber)
		return true;

	// Check revocation time
	if (RevTime() < rhs.RevTime())
		return true;

	// Skip extensions check, just return
	return false;
}

void RevokedEntry::Clear()
{
	delete m_pSnacc;
	m_pSnacc = NULL;
	delete m_pRevDate;
	m_pRevDate = NULL;
	delete m_pExts;
	m_pExts = NULL;
}


const SNACC::CertificateSerialNumber& RevokedEntry::SerialNum() const
{
	if (m_pSnacc == NULL)
	{
		m_pSnacc = new SNACC::CertificateListToBeSignedSeqOfSeq;
		if (m_pSnacc == NULL)
			throw MEMORY_EXCEPTION;
	}
	return m_pSnacc->serialNumber;
}


SNACC::CertificateSerialNumber& RevokedEntry::SerialNum()
{
	if (m_pSnacc == NULL)
	{
		m_pSnacc = new SNACC::CertificateListToBeSignedSeqOfSeq;
		if (m_pSnacc == NULL)
			throw MEMORY_EXCEPTION;
	}
	return m_pSnacc->serialNumber;
}


const Time& RevokedEntry::RevTime() const
{
	if (m_pRevDate == NULL)
	{
		if (m_pSnacc == NULL)
			m_pRevDate = new Time;
		else
			m_pRevDate = new Time(m_pSnacc->revocationDate);
		if (m_pRevDate == NULL)
			throw MEMORY_EXCEPTION;
	}
	return *m_pRevDate;
}


Time& RevokedEntry::RevTime()
{
	if (m_pRevDate == NULL)
	{
		if (m_pSnacc == NULL)
			m_pRevDate = new Time;
		else
			m_pRevDate = new Time(m_pSnacc->revocationDate);
		if (m_pRevDate == NULL)
			throw MEMORY_EXCEPTION;
	}
	return *m_pRevDate;
}


const CrlEntryExtensions& RevokedEntry::EntryExts() const
{
	if (m_pExts == NULL)
	{
		if ((m_pSnacc == NULL) || (m_pSnacc->crlEntryExtensions == NULL))
			m_pExts = new CrlEntryExtensions;
		else
		{
			m_pExts = new CrlEntryExtensions(*m_pSnacc->crlEntryExtensions);
			delete m_pSnacc->crlEntryExtensions;
			m_pSnacc->crlEntryExtensions = NULL;
		}
		if (m_pExts == NULL)
			throw MEMORY_EXCEPTION;
	}
	return *m_pExts;
}


CrlEntryExtensions& RevokedEntry::EntryExts()
{
	if (m_pExts == NULL)
	{
		if ((m_pSnacc == NULL) || (m_pSnacc->crlEntryExtensions == NULL))
			m_pExts = new CrlEntryExtensions;
		else
		{
			m_pExts = new CrlEntryExtensions(*m_pSnacc->crlEntryExtensions);
			delete m_pSnacc->crlEntryExtensions;
			m_pSnacc->crlEntryExtensions = NULL;
		}
		if (m_pExts == NULL)
			throw MEMORY_EXCEPTION;
	}
	return *m_pExts;
}


void RevokedEntry::FillSnaccRevEntry(SNACC::CertificateListToBeSignedSeqOfSeq& snacc) const
{
	snacc.serialNumber = SerialNum();
	snacc.revocationDate = RevTime();
	snacc.crlEntryExtensions = EntryExts().GetSnacc();
}


// Get the C form of this revocation entry
RevCerts_LL* RevokedEntry::GetRevCertsStruct() const
{
	RevCerts_LL* pEntry = (RevCerts_LL*)calloc(1, sizeof(RevCerts_LL));
	if (pEntry == NULL)
		throw MEMORY_EXCEPTION;

	try {
		Internal::CvtAsnIntToExistingBytes(pEntry->serialNum, SerialNum());
		pEntry->revDate = (CM_Time*)malloc(sizeof(CM_Time));
		if (pEntry->revDate == NULL)
			throw MEMORY_EXCEPTION;
		strcpy(*pEntry->revDate, RevTime());
		pEntry->exts = EntryExts().GetCrlEntryExtsStruct();
		return pEntry;
	}
	catch (...) {
		if (pEntry->serialNum.data != NULL)
			free(pEntry->serialNum.data);
		if (pEntry->revDate != NULL)
			free(pEntry->revDate);
		if (pEntry->exts != NULL)
			Internal::FreeCRLEntryExtensions(pEntry->exts);
		free(pEntry);
		throw;
	}
}


bool RevokedEntry::IsCertIssuerExtPresent() const
{
	if (m_pSnacc == NULL)
		return false;

	if (m_pExts != NULL)
	{
		if (m_pExts->pCertIssuer != NULL)
			return true;
	}
	else if (m_pSnacc->crlEntryExtensions != NULL)
	{
		SNACC::Extensions::const_iterator i =
			m_pSnacc->crlEntryExtensions->begin();
		for ( ; i != m_pSnacc->crlEntryExtensions->end(); ++i)
		{
			if (i->extnId == SNACC::id_ce_certificateIssuer)
				return true;
		}
	}

	return false;
}



// end of CM_CRL.cpp
