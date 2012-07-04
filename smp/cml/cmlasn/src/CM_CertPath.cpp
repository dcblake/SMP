/*****************************************************************************
File:     CM_CertPath.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the Cert Path classes and the CM_DecodeCertPath
		  function.

Created:  20 March 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  28 April 2004

Version:  2.4

*****************************************************************************/


////////////////////
// Included Files //
////////////////////
#include "cmlasn_internal.h"


// Using CML::ASN namespace
using namespace CML::ASN;


/////////////////////////
// Function Prototypes //
/////////////////////////
static ulong parseCert(SNACC::AsnBuf& asnBuf);
static ulong parseCertPair(SNACC::AsnBuf& asnBuf, EncCertPair_LL** encCerts,
						   uchar* pStart);



////////////////////////////////
// CM_DecodeCertPath function //
////////////////////////////////
short CM_DecodeCertPath(Bytes_struct* encodedPath, Cert_path_LL **decCertPath)
{
	// Check parameters
	if ((encodedPath == NULL) || (encodedPath->data == NULL) ||
		(decCertPath == NULL))
		return CMLASN_INVALID_PARAMETER;
	
	// Initialize result
	*decCertPath = NULL;
	
	try {
		// Construct a temporary Bytes object
		Bytes asnData(encodedPath->num, encodedPath->data);

		// Decode and convert the certification path
		CertificationPath thePath(asnData);
		*decCertPath = thePath.GetCertPathList();

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


short CMASN_ParseCertPath(const Bytes_struct* encodedPath, ulong* numDecoded,
						  EncCertPair_LL** encCerts)
{
	const SNACC::AsnTag kSEQ_TAG = MAKE_TAG_ID(SNACC::UNIV, SNACC::CONS,
		SNACC::SEQ_TAG_CODE);

	// Check parameters
	if ((encodedPath == NULL) || (numDecoded == NULL) || (encCerts == NULL))
		return CMLASN_INVALID_PARAMETER;

	// Initialize results
	*encCerts = NULL;
	*numDecoded = 0;

	try {
		// Install encoded path into ASN.1 buffer
		SNACC::AsnRvsBuf asnStream((char*)encodedPath->data, encodedPath->num);
		SNACC::AsnBuf asnBuf(&asnStream);

		// Decode the outer SEQ tag
		SNACC::AsnLen numDec = 0;
		SNACC::AsnTag tag = SNACC::BDecTag(asnBuf, numDec);
		if (tag != kSEQ_TAG)
			throw ASN_EXCEPTION("Invalid tag on CertificationPath");

		// Decode the outer length
		SNACC::AsnLen outerLen = SNACC::BDecLen(asnBuf, numDec);

		// Update number of bytes decoded
		*numDecoded += numDec;

		// Allocate memory for the encoded subject cert
		*encCerts = (EncCertPair_LL*)calloc(1, sizeof(EncCertPair_LL));
		if (*encCerts == NULL)
			throw MEMORY_EXCEPTION;

		// Parse the subject cert
		(*encCerts)->forward.num = parseCert(asnBuf);
		(*encCerts)->forward.data = encodedPath->data + numDec;
		*numDecoded += (*encCerts)->forward.num;

		// Return if done
		if ((outerLen != INDEFINITE_LEN) && (*numDecoded == outerLen + numDec))
			return CMLASN_SUCCESS;

		// Decode the SEQ tag around theCACertificates
		numDec = 0;
		tag = SNACC::BDecTag(asnBuf, numDec);
		if ((outerLen == INDEFINITE_LEN) && (tag == EOC_TAG_ID))
		{
			// Decode the end of contents marker and return
			BDEC_2ND_EOC_OCTET(asnBuf, numDec);
			*numDecoded += numDec;
			return CMLASN_SUCCESS;
		}
		else if (tag != kSEQ_TAG)
			throw ASN_EXCEPTION("Invalid tag on CertificationPath::theCACertificates");

		// Decode the length
		SNACC::AsnLen caCertsLen = SNACC::BDecLen(asnBuf, numDec);
		if ((outerLen != INDEFINITE_LEN) && (caCertsLen != INDEFINITE_LEN))
		{
			if (outerLen != ((*encCerts)->forward.num + numDec + caCertsLen))
				throw ASN_EXCEPTION("Invalid length on CertificationPath::theCACertificates");
		}

		// Update number of bytes decoded
		*numDecoded += numDec;

		// For each CA certificate pair...
		numDec = 0;
		EncCertPair_LL* pPrev = *encCerts;
		while ((caCertsLen == INDEFINITE_LEN) || (caCertsLen > numDec))
		{
			// If indefinite-length encoded, check for EOC marker
			if ((caCertsLen == INDEFINITE_LEN) &&
				(asnBuf.PeekByte() == EOC_TAG_ID))
			{
				SNACC::AsnLen eocLen = 0;
				SNACC::BDecEoc(asnBuf, eocLen);
				numDec += eocLen;
				break;
			}

			// Decode the next CA certificate pair
			numDec += parseCertPair(asnBuf, &pPrev->next, encodedPath->data +
				*numDecoded + numDec);
			pPrev = pPrev->next;
		}

		if (outerLen == INDEFINITE_LEN)
			SNACC::BDecEoc(asnBuf, numDec);

		*numDecoded += numDec;
		return CMLASN_SUCCESS;
	}
	catch (Exception& asnErr) {
		CMASN_FreeCertPairList(encCerts);
		return asnErr;
	}
	catch (SNACC::SnaccException& ) {
		CMASN_FreeCertPairList(encCerts);
		return CMLASN_SNACC_ERROR;
	}
	catch (...) {
		CMASN_FreeCertPairList(encCerts);
		return CMLASN_UNKNOWN_ERROR;
	}
}


short CMASN_ParseCertPair(const Bytes_struct* encodedPair, ulong* numDecoded,
						  EncCertPair_LL** encCerts)
{
	// Check parameters
	if ((encodedPair == NULL) || (numDecoded == NULL) || (encCerts == NULL))
		return CMLASN_INVALID_PARAMETER;

	// Initialize results
	*encCerts = NULL;
	*numDecoded = 0;

	try {
		// Install encoded cert pair into ASN.1 buffer
		SNACC::AsnRvsBuf asnStream((char*)encodedPair->data, encodedPair->num);
		SNACC::AsnBuf asnBuf(&asnStream);

		// Parse the cert pair
		*numDecoded = parseCertPair(asnBuf, encCerts, encodedPair->data);
		return CMLASN_SUCCESS;
	}
	catch (Exception& asnErr) {
		return asnErr;
	}
	catch (SNACC::SnaccException& ) {
		return CMLASN_SNACC_ERROR;
	}
	catch (...) {
		return CMLASN_UNKNOWN_ERROR;
	}
}


////////////////////////////////////////////
// CertificationPath class implementation //
////////////////////////////////////////////
CertificationPath::CertificationPath()
{
	m_caCertsPresent = false;
}


CertificationPath::CertificationPath(const Cert& subject)
{
	m_caCertsPresent = false;
	userCert = subject;
}


CertificationPath::CertificationPath(const SNACC::CertificationPath& snacc)
{
	m_caCertsPresent = false;
	operator=(snacc);
}


CertificationPath::CertificationPath(const Bytes& asn)
{
	m_caCertsPresent = false;
	operator=(asn);
}


CertificationPath& CertificationPath::operator=(const SNACC::CertificationPath& snacc)
{
	caCerts.clear();

	try {
		userCert = snacc.userCertificate;
		if (snacc.theCACertificates == NULL)
			m_caCertsPresent = false;
		else
		{
			m_caCertsPresent = true;
			
			SNACC::CertificationPathSeqOf::const_iterator i =
				snacc.theCACertificates->begin();
			for ( ; i != snacc.theCACertificates->end(); ++i)
				caCerts.push_back(*i);
		}
		return *this;
	}
	catch (...) {
		m_caCertsPresent = false;
		caCerts.clear();
		throw;
	}
}


CertificationPath& CertificationPath::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


ulong CertificationPath::Decode(const Bytes& asn)
{
	try {
		// Decode the cert path
		SNACC::CertificationPath certPath;
		SNACC::AsnLen nBytesDecoded = asn.Decode(certPath,
			"SNACC::CertificationPath");

		// Assign this cert path to the newly decoded path
		operator=(certPath);

		return nBytesDecoded;
	}
	catch (...) {
		userCert.Clear();
		caCerts.clear();
		throw;
	}
}


ulong CertificationPath::Encode(Bytes& asn) const
{
	// Get the SNACC form of this certificate
	SNACC::CertificationPath* pCertPath = GetSnacc();

	try {
		// Encode the CertificationPath
		ulong numEncoded = asn.Encode(*pCertPath, "SNACC::CertificationPath");

		// Delete the temporary variable
		delete pCertPath;

		return numEncoded;
	}
	catch (...) {
		delete pCertPath;
		throw;
	}
}


SNACC::CertificationPath* CertificationPath::GetSnacc() const
{
	SNACC::CertificationPath* result = NULL;

	try {
		result = new SNACC::CertificationPath;
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		userCert.FillSnacc(result->userCertificate);

		if (m_caCertsPresent || !caCerts.empty())
		{
			// Create the list of CA certificates
			result->theCACertificates = new SNACC::CertificationPathSeqOf;
			if (result->theCACertificates == NULL)
				throw MEMORY_EXCEPTION;

			// Get the SNACC form of the CA certificates
			for (std::list<CertPair>::const_iterator i = caCerts.begin(); i !=
				caCerts.end(); i++)
			{
				// Create a new SNACC CertPair at the end of the list
				SNACC::CertificatePair& newPair =
					*result->theCACertificates->append();
				i->FillSnaccCertPair(newPair);
			}
		}

		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


// Get the C form of this cert path
Cert_path_LL* CertificationPath::GetCertPathList() const
{
	Cert_path_LL* pPath = NULL;

	try {
		// Add the user certificate to the path
		pPath = (Cert_path_LL*)calloc(1, sizeof(Cert_path_LL));
		if (pPath == NULL)
			throw MEMORY_EXCEPTION;
		pPath->cert = userCert.GetCertStruct();

		// Add each of the issuer certificates to the path
		std::list<CertPair>::const_iterator i;
		for (i = caCerts.begin(); i != caCerts.end(); ++i)
		{
			// If this CertPair doesn't have a forward element, exit the loop
			if (i->forward == NULL)
				break;

			Cert_path_LL* pNew = (Cert_path_LL*)
				calloc(1, sizeof(Cert_path_LL));
			if (pNew == NULL)
				throw MEMORY_EXCEPTION;
			pNew->next = pPath;
			pPath = pNew;
			pNew->cert = i->forward->GetCertStruct();
		}

		return pPath;
	}
	catch (...) {
		CM_FreeCertPathLinkedList(&pPath);
		throw;
	}
}


///////////////////////////////////
// CertPair class implementation //
///////////////////////////////////
CertPair::CertPair(const Cert* pForward, const Cert* pReverse)
{
	forward = NULL;
	reverse = NULL;
	try {
		if (pForward != NULL)
		{
			forward = new Cert(*pForward);
			if (forward == NULL)
				throw MEMORY_EXCEPTION;
		}

		if (pReverse != NULL)
		{
			reverse = new Cert(*pReverse);
			if (reverse == NULL)
				throw MEMORY_EXCEPTION;
		}
	}
	catch (...) {
		if (forward != NULL)
			delete forward;
		if (reverse != NULL)
			delete reverse;
		throw;
	}
}


CertPair::CertPair(const SNACC::CertificatePair& snacc)
{
	// Initialize members
	forward = NULL;
	reverse = NULL;
	operator=(snacc);
}


CertPair::CertPair(const Bytes& asn)
{
	// Initialize members
	forward = NULL;
	reverse = NULL;
	operator=(asn);
}


CertPair::CertPair(const CertPair& that)
{
	// Initialize members
	forward = NULL;
	reverse = NULL;
	operator=(that);
}


CertPair::~CertPair()
{
	if (forward != NULL)
		delete forward;
	if (reverse != NULL)
		delete reverse;
}


CertPair& CertPair::operator=(const SNACC::CertificatePair& snacc)
{
	if ((snacc.forward == NULL) && (snacc.reverse == NULL))
		throw ASN_EXCEPTION("Both the forward and reverse fields in SNACC::CertificatePair are NULL");

	if (forward != NULL)
	{
		delete forward;
		forward = NULL;
	}
	if (reverse != NULL)
	{
		delete reverse;
		reverse = NULL;
	}

	try {
		if (snacc.forward != NULL)
		{
			forward = new Cert(*snacc.forward);
			if (forward == NULL)
				throw MEMORY_EXCEPTION;
		}

		if (snacc.reverse != NULL)
		{
			reverse = new Cert(*snacc.reverse);
			if (reverse == NULL)
				throw MEMORY_EXCEPTION;
		}

		return *this;
	}
	catch (...) {
		if (forward != NULL)
		{
			delete forward;
			forward = NULL;
		}
		if (reverse != NULL)
		{
			delete reverse;
			reverse = NULL;
		}
		throw;
	}
}


CertPair& CertPair::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


CertPair& CertPair::operator=(const CertPair& other)
{
	if ((other.forward == NULL) && (other.reverse == NULL))
		throw ASN_EXCEPTION("At least one of the certs must be present in the CertPair");

	if (forward != NULL)
	{
		delete forward;
		forward = NULL;
	}
	if (reverse != NULL)
	{
		delete reverse;
		reverse = NULL;
	}

	try {
		if (other.forward != NULL)
		{
			forward = new Cert(*other.forward);
			if (forward == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		if (other.reverse != NULL)
		{
			reverse = new Cert(*other.reverse);
			if (reverse == NULL)
				throw MEMORY_EXCEPTION;
		}

		return *this;
	}
	catch (...) {
		if (forward != NULL)
		{
			delete forward;
			forward = NULL;
		}
		if (reverse != NULL)
		{
			delete reverse;
			reverse = NULL;
		}
		throw;
	}
}


ulong CertPair::Decode(const Bytes& asn)
{
	try {
		// Decode the cert pair
		SNACC::CertificatePair certPair;
		SNACC::AsnLen nBytesDecoded = asn.Decode(certPair,
			"SNACC::CertificatePair");

		// Assign this cert pair to the newly decoded CertificatePair
		operator=(certPair);
		
		return nBytesDecoded;
	}
	catch (...) {
		if (forward != NULL)
		{
			delete forward;
			forward = NULL;
		}
		if (reverse != NULL)
		{
			delete reverse;
			reverse = NULL;
		}
		throw;
	}
}


ulong CertPair::Encode(Bytes& asn) const
{
	// Get the SNACC form of this certificate pair
	SNACC::CertificatePair* pCertPair = GetSnacc();

	try {
		// Encode the CertificatePair
		ulong numEncoded = asn.Encode(*pCertPair, "SNACC::CertificatePair");

		// Delete the temporary variable
		delete pCertPair;

		return numEncoded;
	}
	catch (...) {
		delete pCertPair;
		throw;
	}
}


void CertPair::FillSnaccCertPair(SNACC::CertificatePair& snacc) const
{
	snacc.reverse = NULL;
	try {
		if (forward == NULL)
			snacc.forward = NULL;
		else
			snacc.forward = forward->GetSnacc();

		if (reverse != NULL)
			snacc.reverse = reverse->GetSnacc();
	}
	catch (...) {
		if (snacc.forward != NULL)
		{
			delete snacc.forward;
			snacc.forward = NULL;
		}

		if (snacc.reverse != NULL)
		{
			delete snacc.reverse;
			snacc.reverse = NULL;
		}
		throw;
	}
}


SNACC::CertificatePair* CertPair::GetSnacc() const
{
	SNACC::CertificatePair* result = NULL;

	try {
		result = new SNACC::CertificatePair;
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		
		FillSnaccCertPair(*result);
		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


ulong parseCertPair(SNACC::AsnBuf& asnBuf, EncCertPair_LL** ppPair,
					uchar* pStart)
{
	// Check parameter
	if ((ppPair == NULL) || (pStart == NULL))
		throw EXCEPTION(CMLASN_INVALID_PARAMETER);

	// Initialize results
	*ppPair = NULL;

	try {
		// Decode the outer SEQ tag
		SNACC::AsnLen numDec = 0;
		SNACC::AsnTag tag = SNACC::BDecTag(asnBuf, numDec);
		if (tag != MAKE_TAG_ID(SNACC::UNIV, SNACC::CONS, SNACC::SEQ_TAG_CODE))
			throw ASN_EXCEPTION("Invalid tag on CertificatePair");

		// Decode the length of the pair
		SNACC::AsnLen pairLen = SNACC::BDecLen(asnBuf, numDec);
		if (pairLen == 0)
			throw ASN_EXCEPTION("Invalid length of CertificatePair element");

		// Decode each of the elements
		ulong numDecoded = numDec;
		numDec = 0;
		while ((pairLen == INDEFINITE_LEN) || (pairLen > numDec))
		{
			// Allocate memory the for the EncCertPair_LL
			if (*ppPair == NULL)
			{
				*ppPair = (EncCertPair_LL*)calloc(1, sizeof(EncCertPair_LL));
				if (*ppPair == NULL)
					throw MEMORY_EXCEPTION;
			}

			// Decode the tag
			tag = SNACC::BDecTag(asnBuf, numDec);
			Bytes_struct* pTarget = NULL;
			if (tag == MAKE_TAG_ID(SNACC::CNTX, SNACC::CONS, 0))
			{
				if ((*ppPair)->forward.data != NULL)
					throw ASN_EXCEPTION("Invalid CertificatePair content");
				pTarget = &(*ppPair)->forward;
			}
			else if (tag == MAKE_TAG_ID(SNACC::CNTX, SNACC::CONS, 1))
			{
				if ((*ppPair)->reverse.data != NULL)
					throw ASN_EXCEPTION("Invalid CertificatePair content");
				pTarget = &(*ppPair)->reverse;
			}
			else if ((pairLen == INDEFINITE_LEN) && (tag == EOC_TAG_ID))
			{
				BDEC_2ND_EOC_OCTET(asnBuf, numDec);
				break;
			}
			else
				throw ASN_EXCEPTION("Invalid tag in CertificatePair");

			// Decode the element length
			SNACC::AsnLen elmtLen = SNACC::BDecLen(asnBuf, numDec);
			if (elmtLen == 0)
				throw ASN_EXCEPTION("Invalid length of CertificatePair element");

			// Parse the certificate
			pTarget->num = parseCert(asnBuf);
			pTarget->data = pStart + numDecoded + numDec;
			numDec += pTarget->num;

			// Decode the EOC tag for objects with indefinite length
			if (elmtLen == INDEFINITE_LEN)
				SNACC::BDecEoc(asnBuf, numDec);
		}

		if (((*ppPair)->forward.data == NULL) &&
			((*ppPair)->reverse.data == NULL))
			throw ASN_EXCEPTION("Invalid CertificatePair is empty");

		numDecoded += numDec;
		return numDecoded;
	}
	catch (...) {
		if (*ppPair != NULL)
			free(*ppPair);
		throw;
	}
}


ulong parseCert(SNACC::AsnBuf& asnBuf)
{
	const SNACC::AsnTag kSEQ_TAG = MAKE_TAG_ID(SNACC::UNIV, SNACC::CONS,
		SNACC::SEQ_TAG_CODE);
	
	// Decode the certificate's outer SEQ tag
	SNACC::AsnLen numDec = 0;
	SNACC::AsnTag tag = SNACC::BDecTag(asnBuf, numDec);
	if (tag != kSEQ_TAG)
		throw ASN_EXCEPTION("Invalid tag on Certificate");
	
	// Decode the length of the certificate
	SNACC::AsnLen len = SNACC::BDecLen(asnBuf, numDec);
	if (len == INDEFINITE_LEN)
	{
		// Decode the certificate's inner SEQ tag
		tag = SNACC::BDecTag(asnBuf, numDec);
		if (tag != kSEQ_TAG)
			throw ASN_EXCEPTION("Invalid tag on Certificate");

		len = SNACC::BDecLen(asnBuf, numDec);
		if (len == INDEFINITE_LEN)
			throw ASN_EXCEPTION("Invalid length on Certificate");
		try {
			asnBuf.skip(len);
		}
		catch (SNACC::SnaccException& ) {
			throw ASN_EXCEPTION("Invalid length on Certificate");
		}

		SNACC::BDecEoc(asnBuf, numDec);
	}
	else
	{
		try {
			asnBuf.skip(len);
		}
		catch (SNACC::SnaccException& ) {
			throw ASN_EXCEPTION("Invalid length on Certificate");
		}
	}

	// Return the length of the certificate
	return numDec + len;
};



// end of CM_CertPath.cpp
