/*****************************************************************************
File:     CM_Certificate.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the Certificate, PublicKeyInfo, Validity, AlgID,
		  and Time classes and the CM_DecodeCert function.

Created:  20 March 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	28 September 2004

Version:  2.4.1

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
static short time2CMTime(time_t t, char* cmTime);
static Pqg_params_struct* cvtDSAParameters(const SNACC::Dss_Parms& params);
static ulong cvtFortezzaMultiByte(Bytes_struct& bytes, const uchar* data,
								  const uchar* dataEnd);
static Pqg_params_struct* cvtFortezzaParams(const SNACC::Fortezza_Parms& params);
static void cvtFortezzaPubKey(Pub_key_struct& cmPubKey, const Bytes& keyBuf);
static void cvtOctsToExistingBytes(Bytes_struct& bytes,
								   const SNACC::AsnOcts& octs);
static RSAPublicKey_struct* cvtRSAPublicKey(const SNACC::RSAPublicKey& rsaKey);


//////////////////////
// Global Variables //
//////////////////////
const unsigned int gSHA1_HASH_LEN = 160 / 8;
const unsigned int gSHA256_HASH_LEN = 256 / 8;
const unsigned int gSHA384_HASH_LEN = 384 / 8;


////////////////////////////
// CM_DecodeCert function //
////////////////////////////
short CM_DecodeCert(Bytes_struct* encodedCert, Cert_struct **decCert)
{
	// Check parameters
	if ((encodedCert == NULL) || (encodedCert->data == NULL) ||
		(decCert == NULL))
		return CMLASN_INVALID_PARAMETER;

	try {
		// Initialize result
		*decCert = NULL;

		// Construct a temporary Bytes object
		Bytes asnData(encodedCert->num, encodedCert->data);

		// Decode and convert the certificate
		Cert tmpCert(asnData);
		*decCert = tmpCert.GetCertStruct();

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


///////////////////////////////
// Cert class implementation //
///////////////////////////////
Cert::Cert()
{
	// Initialize default version
	version = SNACC::Version::v1;

	// Initialize pointers and private m_versionPresent
	pIssuerUniqueID = NULL;
	pSubjectUniqueID = NULL;
	m_versionPresent = false;
}


Cert::Cert(const SNACC::Certificate& snacc)
{
	// Initialize pointers
	pIssuerUniqueID = NULL;
	pSubjectUniqueID = NULL;

	operator=(snacc);
}


Cert::Cert(const Bytes& asn)
{
	// Initialize pointers
	pIssuerUniqueID = NULL;
	pSubjectUniqueID = NULL;

	operator=(asn);
}


Cert::Cert(const Cert& that)
{
	// Initialize pointers
	pIssuerUniqueID = NULL;
	pSubjectUniqueID = NULL;

	operator=(that);
}


Cert& Cert::operator=(const SNACC::Certificate& snacc)
{
	// Delete existing values in member variables
	Clear();

	try {
		// Set the version if present
		if (snacc.toBeSigned.version != NULL)
		{
			version = *snacc.toBeSigned.version;
			m_versionPresent = true;
		}

		// Set the serial number and signature algorithm ID
		serialNumber = snacc.toBeSigned.serialNumber;
		signature = snacc.toBeSigned.signature;

		// Set the issuer and subject distinguished names
		issuer = snacc.toBeSigned.issuer;
		subject = snacc.toBeSigned.subject;

		// Set the validity dates
		validity = snacc.toBeSigned.validity;

		// Set the public key info
		pubKeyInfo = snacc.toBeSigned.subjectPublicKeyInfo;

		// Set the issuer and subject unique IDs (if present)
		if (snacc.toBeSigned.issuerUniqueIdentifier != NULL)
		{
			pIssuerUniqueID = new
				SNACC::UniqueIdentifier(*snacc.toBeSigned.issuerUniqueIdentifier);
			if (pIssuerUniqueID == NULL)
				throw MEMORY_EXCEPTION;
		}
		if (snacc.toBeSigned.subjectUniqueIdentifier != NULL)
		{
			pSubjectUniqueID = new
				SNACC::UniqueIdentifier(*snacc.toBeSigned.subjectUniqueIdentifier);
			if (pSubjectUniqueID == NULL)
				throw MEMORY_EXCEPTION;
		}

		// Set the extensions (if present)
		if (snacc.toBeSigned.extensions != NULL)
			exts = *snacc.toBeSigned.extensions;

		// Set the outer signature algorithm ID and signature value
		algorithm = snacc.algorithm;
		sigValue = snacc.signature;

		return *this;
	}
	catch (SNACC::SnaccException& e) {
		e.push(__FILE__, __LINE__, "CML::ASN::Cert::operator=");
		throw;
	}
}


Cert& Cert::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


Cert& Cert::operator=(const Cert& other)
{
	if (this != &other)
	{
		// Delete existing values in member variables
		Clear();

		version = other.version;
		m_versionPresent = other.m_versionPresent;
		serialNumber = other.serialNumber;
		signature = other.signature;
		issuer = other.issuer;
		validity = other.validity;
		subject = other.subject;
		pubKeyInfo = other.pubKeyInfo;

		if (other.pIssuerUniqueID != NULL)
		{
			pIssuerUniqueID = new
				SNACC::UniqueIdentifier(*other.pIssuerUniqueID);
			if (pIssuerUniqueID == NULL)
				throw MEMORY_EXCEPTION;
		}
		if (other.pSubjectUniqueID != NULL)
		{
			pSubjectUniqueID = new
				SNACC::UniqueIdentifier(*other.pSubjectUniqueID);
			if (pSubjectUniqueID == NULL)
				throw MEMORY_EXCEPTION;
		}

		exts = other.exts;
		algorithm = other.algorithm;
		sigValue = other.sigValue;
	}
	return *this;
}


/*bool Cert::operator==(const Cert& rhs)
{
	if (this == &rhs)
		return true;

	if (version != rhs.version)
		return false;
	if (m_versionPresent != rhs.m_versionPresent)
		return false;
	if (serialNumber != rhs.serialNumber)
		return false;
	if (signature != rhs.signature)
		return false;
	if (issuer != rhs.issuer)
		return false;
	if (validity != rhs.validity)
		return false;
	if (subject != rhs.subject)
		return false;
	if (pubKeyInfo != rhs.pubKeyInfo)
		return false;

	if (CMU_CompareUniqueIDs(pIssuerUniqueID, rhs.pIssuerUniqueID) == false)
		return false;
	if (CMU_CompareUniqueIDs(pSubjectUniqueID, rhs.pSubjectUniqueID) == false)
		return false;

	if (extensions != rhs.extensions)
		return false;
	if (algorithm != rhs.algorithm)
		return false;
	if (sigValue != (CTIL::CSM_Buffer&)rhs.sigValue)
		return false;

	return true;
}
*/

void Cert::Clear(void)
{
	version = SNACC::Version::v1;
	m_versionPresent = false;
	serialNumber = 0;
	signature.Clear();
	issuer = NULL;
	subject = NULL;
	pubKeyInfo.Clear();
	if (pIssuerUniqueID != NULL)
	{
		delete pIssuerUniqueID;
		pIssuerUniqueID = NULL;
	}
	if (pSubjectUniqueID != NULL)
	{
		delete pSubjectUniqueID;
		pSubjectUniqueID = NULL;
	}
	exts.Clear();
	algorithm.Clear();
	sigValue.Clear();
} // end of Cert::Clear()


ulong Cert::Decode(const Bytes& asn)
{
	// Delete existing values in member variables
	Clear();

	// Decode the cert
	SNACC::Certificate cert;
	SNACC::AsnLen nBytesDecoded = asn.Decode(cert, "SNACC::Certificate");

	// Assign this cert to the newly decoded cert
	operator=(cert);

	return nBytesDecoded;
} // end of Cert::Decode()


ulong Cert::Encode(Bytes& asn) const
{
	// Get the SNACC form of this certificate
	SNACC::Certificate* pCert = GetSnacc();
	try {
		// Encode the certificate
		ulong numEncoded = asn.Encode(*pCert, "SNACC::Certificate");

		// Delete the temporary variable
		delete pCert;

		return numEncoded;
	}
	catch (...) {
		delete pCert;
		throw;
	}
} // end of Cert::Encode()


bool Cert::IsSelfIssued() const
{
	// Compare the subject and issuer DNs
	if (issuer != subject)
		return false;

	// Compare the subject and issuer unique identifiers (if present)
	if ((pIssuerUniqueID != NULL) && (pSubjectUniqueID != NULL))
	{
		if (*pIssuerUniqueID != *pSubjectUniqueID)
			return false;
	}
	else if (pIssuerUniqueID != NULL)
		return false;
	else if (pSubjectUniqueID != NULL)
		return false;
	// else both absent

	// Return false if the alternative names are required, but missing
	if (issuer.IsEmpty() && (exts.pIssuerAltNames == NULL))
		return false;
	if (subject.IsEmpty() && (exts.pSubjAltNames == NULL))
		return false;

	// Compare the subject and issuer alternative names (if both present)
	if ((exts.pIssuerAltNames == NULL) || (exts.pSubjAltNames == NULL))
		return true;
	else
		return exts.pIssuerAltNames->IsOnePresent(*exts.pSubjAltNames);
}


void Cert::FillSnacc(SNACC::Certificate& snacc) const
{
	// Clear the SNACC certificate
	snacc.Clear();

	// Get the SNACC form of the version (if necessary)
	if (m_versionPresent || (version != 0))
	{
		snacc.toBeSigned.version = new SNACC::Version(version);
		if (snacc.toBeSigned.version == NULL)
			throw MEMORY_EXCEPTION;
	}

	// Set the SNACC serial number
	snacc.toBeSigned.serialNumber = serialNumber;
	// Fill in the SNACC form of the signature AlgID
	signature.FillSnacc(snacc.toBeSigned.signature);

	// Fill in the SNACC form of the issuer and subject DNs
	issuer.FillSnacc(snacc.toBeSigned.issuer);
	subject.FillSnacc(snacc.toBeSigned.subject);

	// Fill in the SNACC form of the validity period
	validity.FillSnacc(snacc.toBeSigned.validity);

	// Fill in the SNACC form of the SubjectPublicKeyInfo
	pubKeyInfo.FillSnacc(snacc.toBeSigned.subjectPublicKeyInfo);

	// Copy the issuer and subject unique identifiers if present
	if (pIssuerUniqueID != NULL)
	{
		snacc.toBeSigned.issuerUniqueIdentifier =
			new SNACC::UniqueIdentifier(*pIssuerUniqueID);
		if (snacc.toBeSigned.issuerUniqueIdentifier == NULL)
			throw MEMORY_EXCEPTION;
	}
	if (pSubjectUniqueID != NULL)
	{
		snacc.toBeSigned.subjectUniqueIdentifier =
			new SNACC::UniqueIdentifier(*pSubjectUniqueID);
		if (snacc.toBeSigned.subjectUniqueIdentifier == NULL)
			throw MEMORY_EXCEPTION;
	}

	// Get the SNACC form of the extensions
	snacc.toBeSigned.extensions = exts.GetSnacc();

	// Fill in the SNACC form of the outer signature AlgID and value
	algorithm.FillSnacc(snacc.algorithm);
	snacc.signature.Set(sigValue.GetData(), sigValue.BitLen());
}


SNACC::Certificate* Cert::GetSnacc() const
{
	SNACC::Certificate* pCert = NULL;
	try {
		// Create the new SNACC::Certificate
		pCert = new SNACC::Certificate;
		if (pCert == NULL)
			throw MEMORY_EXCEPTION;

		// Fill in the SNACC::Certificate
		FillSnacc(*pCert);

		// Return result
		return pCert;
	}
	catch (...) {
		if (pCert != NULL)
			delete pCert;
		throw;
	}
} // end of Cert::GetSnacc()


// Get the C form of this certificate
Cert_struct* Cert::GetCertStruct() const
{
	Cert_struct* pCert = (Cert_struct*)calloc(1, sizeof(Cert_struct));
	if (pCert == NULL)
		throw MEMORY_EXCEPTION;

	try {
		pCert->version = short(version + 1);
		Internal::CvtAsnIntToExistingBytes(pCert->serial_num, serialNumber);
		pCert->signature = signature.algorithm.GetChar();

		pCert->issuer = strdup(issuer);
		if (pCert->issuer == NULL)
			throw MEMORY_EXCEPTION;

		strcpy(pCert->val_not_before, validity.notBefore);
		strcpy(pCert->val_not_after, validity.notAfter);

		pCert->subject = strdup(subject);
		if (pCert->subject == NULL)
			throw MEMORY_EXCEPTION;

		pubKeyInfo.FillPubKeyStruct(pCert->pub_key);

		if (pIssuerUniqueID != NULL)
			pCert->issuer_id = Internal::CvtBitsToBytes(*pIssuerUniqueID);
		if (pSubjectUniqueID != NULL)
			pCert->subj_id = Internal::CvtBitsToBytes(*pSubjectUniqueID);

		pCert->exts = exts.GetCertExtsStruct();

		pCert->sig.alg = algorithm.algorithm.GetChar();
		Internal::CvtBytesToSigStruct(pCert->sig, sigValue);

		return pCert;
	}
	catch (...) {
		CM_FreeCert(&pCert);
		throw;
	}
}


////////////////////////////////////////
// PublicKeyInfo class implementation //
////////////////////////////////////////
PublicKeyInfo& PublicKeyInfo::operator=(const SNACC::SubjectPublicKeyInfo& snaccPK)
{
	algorithm = snaccPK.algorithm;
	key = snaccPK.subjectPublicKey;
	return *this;
}


bool PublicKeyInfo::operator==(const PublicKeyInfo& rhs) const
{
	if (this == &rhs)
		return true;

	if (algorithm != rhs.algorithm)
		return false;
	return (key == rhs.key);
}


void PublicKeyInfo::Clear()
{
	algorithm.Clear();
	key.Clear();
}


void PublicKeyInfo::FillSnacc(SNACC::SubjectPublicKeyInfo& snacc) const
{
	algorithm.FillSnacc(snacc.algorithm);
	snacc.subjectPublicKey.Set(key.GetData(), key.BitLen());
}


// Fill in the C form of the SubjectPublicKeyInfo
void PublicKeyInfo::FillPubKeyStruct(Pub_key_struct& pubKey) const
{
	// Initialize Pub_key_struct
	pubKey.oid = NULL;
	pubKey.params.dsa = NULL;
	pubKey.key.y = NULL;

	try {
		pubKey.oid = algorithm.algorithm.GetChar();

		if ((algorithm == gDSA_OID) || (algorithm == gOIW_DSA))
		{
			// Decode the DSA public key
			SNACC::DSAPublicKey dsaPubKey;
			key.Decode(dsaPubKey, "SNACC::DSAPublicKey");

			// Copy the huge integer to a Bytes_struct
			pubKey.key.y = Internal::CvtAsnIntToBytes(dsaPubKey, 8);
		}
		else if (algorithm == gRSA_OID)
		{
			// Decode the RSA public key
			SNACC::RSAPublicKey rsaPubKey;
			key.Decode(rsaPubKey, "SNACC::RSAPublicKey");

			// Convert the RSA public key into an RSAPublicKey_struct
			pubKey.key.rsa = cvtRSAPublicKey(rsaPubKey);
		}
		else if (algorithm == gEC_KEY_OID)
		{
			// Copy the encoded ECDSA or ECDH public key to a Bytes_struct
			pubKey.key.encoded = key.GetBytesStruct();
		}
		else if (algorithm == gKEA_OID)
		{
			// Copy the KEA key to a Bytes_struct
			pubKey.key.y = key.GetBytesStruct();
		}
		else if ((algorithm == gOLD_DH_OID) || (algorithm == gANSI_DH_OID))
		{
			// Decode the DH public key
			SNACC::DHPublicKey dhPubKey;
			key.Decode(dhPubKey, "SNACC::DHPublicKey");

			// Convert the huge integer to a Bytes_struct
			pubKey.key.y = Internal::CvtAsnIntToBytes(dhPubKey, 8);
		}
		else if (algorithm == gDSA_KEA_OID)
		{
			// Decode the Fortezza public key
			cvtFortezzaPubKey(pubKey, key);
		}
		else
		{
			// Copy the unknown encoded public key to a Bytes_struct
			pubKey.key.encoded = key.GetBytesStruct();
		}

		Internal::FillParameters(pubKey, algorithm);
	}
	catch (...) {
		CMASN_FreePubKeyContents(&pubKey);
		throw;
	}
} // end of PublicKeyInfo::FillPubKeyStruct()


// Get the C form of the SubjectPublicKeyInfo
Pub_key_struct* PublicKeyInfo::GetPubKeyStruct() const
{
	Pub_key_struct* result = (Pub_key_struct*)malloc(sizeof(Pub_key_struct));
	if (result == NULL)
		throw MEMORY_EXCEPTION;

	try {
		FillPubKeyStruct(*result);
		return result;
	}
	catch (...) {
		CMASN_FreePubKeyContents(result);
		free(result);
		throw;
	}
}


///////////////////////////////////
// Validity class implementation //
///////////////////////////////////
Validity::Validity(ushort numYears)
{
	// Create a temporary CM_Time from the current time
	CM_Time tempTime;
	strcpy(tempTime, notBefore);

	// Adjust each of the year digits
	for (short i = 3; (i >= 0) && (numYears > 0); i--)
	{
		tempTime[i] = char(tempTime[i] + (numYears % 10));
		numYears = short(numYears / 10);

		if (tempTime[i] > '9')
		{
			tempTime[i] = char(tempTime[i] - 10);
			numYears++;
		}
	}

	// Check that temp CM_Time does not fall on invalid leap day
	if ((strncmp(&tempTime[4], "0229", 4) == 0) && (numYears % 4 != 0))
	{
		// If it does, change the date to Feb 28th
		tempTime[7] = '8';
	}

	// Throw an error if overflow occurred (result > "9999")
	if (numYears != 0)
		throw Exception(CMLASN_INVALID_PARAMETER, __FILE__, __LINE__);

	// Set the notAfter time to the adjusted value
	notAfter = tempTime;
}


Validity::Validity(const SNACC::Validity& snacc)
{
	notBefore = snacc.notBefore;
	notAfter = snacc.notAfter;
}


Validity::Validity(const SNACC::AttCertValidityPeriod& snacc) :
notBefore(snacc.notBeforeTime), notAfter(snacc.notAfterTime)
{
}


Validity::Validity(const Time& begin, const Time& end) :
notBefore(begin), notAfter(end)
{
}


bool Validity::operator==(const Validity& rhs) const
{
	if (this == &rhs)
		return true;

	return ((notBefore == rhs.notBefore) && (notAfter == rhs.notAfter));
}


void Validity::FillSnacc(SNACC::Validity& snacc) const
{
	snacc.notBefore = notBefore;
	snacc.notAfter = notAfter;
}


void Validity::FillAttCertValidity(SNACC::AttCertValidityPeriod& snacc) const
{
	notBefore.FillSnaccGenTime(snacc.notBeforeTime);
	notAfter.FillSnaccGenTime(snacc.notAfterTime);
}


bool Validity::IsValid() const
{
	Time curTime;
	return IsValid(curTime);
}


bool Validity::IsValid(const Time& time) const
{
	return ((time >= notBefore) && (time <= notAfter));
}


////////////////////////////////
// AlgID class implementation //
////////////////////////////////
AlgID::AlgID(const SNACC::AlgorithmIdentifier& snacc)
{
	parameters = NULL;
	operator=(snacc);
}


AlgID::AlgID(const SNACC::AsnOid& oid, const Bytes* pParams) : algorithm(oid)
{
	if (pParams == NULL)
		parameters = NULL;
	else
	{
		parameters = new Bytes(*pParams);
		if (parameters == NULL)
			throw MEMORY_EXCEPTION;
	}
}


AlgID::AlgID(const AlgID& that)
{
	parameters = NULL;
	operator=(that);
}


AlgID& AlgID::operator=(const SNACC::AlgorithmIdentifier& snacc)
{
	Clear();
	algorithm = snacc.algorithm;
	if (snacc.parameters != NULL)
	{
		parameters = new Bytes(*snacc.parameters,
			"SNACC::AlgorithmIdentifier::parameters");
	}
	return *this;
}


AlgID& AlgID::operator=(const SNACC::AsnOid& oid)
{
	Clear();
	algorithm = oid;
	return *this;
}


AlgID& AlgID::operator=(const AlgID& other)
{
	if (this != &other)
	{
		Clear();
		algorithm = other.algorithm;
		if (other.parameters != NULL)
		{
			parameters = new Bytes(*other.parameters);
			if (parameters == NULL)
				throw MEMORY_EXCEPTION;
		}
	}

	return *this;
}


bool AlgID::operator==(const AlgID& rhs) const
{
	if (this == &rhs)
		return true;

	if (algorithm != rhs.algorithm)
		return false;

	if ((parameters == NULL) && (rhs.parameters == NULL))
		return true;
	else if ((parameters == NULL) || (rhs.parameters == NULL))
		return false;
	else
		return (*parameters == *rhs.parameters);
}


void AlgID::Clear()
{
	if (parameters != NULL)
	{
		delete parameters;
		parameters = NULL;
	}
}


void AlgID::FillSnacc(SNACC::AlgorithmIdentifier& snacc) const
{
	snacc.algorithm = algorithm;
	if (parameters != NULL)
	{
		snacc.parameters = new SNACC::AsnAnyDefinedBy();
		if (snacc.parameters == NULL)
			throw MEMORY_EXCEPTION;

		snacc.parameters->anyBuf = new SNACC::AsnBuf((const char*)
			parameters->GetData(), parameters->Len());
		if (snacc.parameters->anyBuf == NULL)
			throw MEMORY_EXCEPTION;
	}
}


bool AlgID::ParametersArePresent() const
{
	static const Bytes asnNull(2, (const uchar*)"\05\00");

	// Return false if the parameters are absent or just an encoded NULL
	if ((parameters == NULL) || (*parameters == asnNull))
		return false;

	// Return true otherwise
	return true;
}


///////////////////////////////
// Time class implementation //
///////////////////////////////
Time::Time(time_t timeVal)
{
	m_snaccTime.choiceId = SNACC::Time::utcTimeCid;
	m_snaccTime.utcTime = NULL;
	operator=(timeVal);
}


Time::Time(const SNACC::Time& snacc)
{
	m_snaccTime.choiceId = SNACC::Time::utcTimeCid;
	m_snaccTime.utcTime = NULL;
	operator=(snacc);
}


Time::Time(const SNACC::GeneralizedTime& snacc)
{
	try {
		m_snaccTime.choiceId = SNACC::Time::generalizedTimeCid;
		m_snaccTime.generalizedTime = new SNACC::GeneralizedTime(snacc);
		if (m_snaccTime.generalizedTime == NULL)
			throw MEMORY_EXCEPTION;

		cvtGenTime2CM_Time(*m_snaccTime.generalizedTime);
	}
	catch (...) {
		if (m_snaccTime.generalizedTime != NULL)
			delete m_snaccTime.generalizedTime;
		throw;
	}
}


Time::Time(const CM_Time& cmTime)
{
	m_snaccTime.choiceId = SNACC::Time::utcTimeCid;
	m_snaccTime.utcTime = NULL;
	operator=(cmTime);
}


Time::Time(const Time& that)
{
	m_snaccTime.choiceId = SNACC::Time::utcTimeCid;
	m_snaccTime.utcTime = NULL;
	operator=(that);
}


Time& Time::operator=(const SNACC::Time& snacc)
{
	m_snaccTime = snacc;
	if (m_snaccTime.utcTime == NULL)
		throw ASN_EXCEPTION("SNACC::Time::utcTime field is NULL");

	if (m_snaccTime.choiceId == SNACC::Time::utcTimeCid)
		cvtUTC2CM_Time(*m_snaccTime.utcTime);
	else
		cvtGenTime2CM_Time(*m_snaccTime.generalizedTime);

	return *this;
}


Time& Time::operator=(time_t timeVal)
{
	Clear();

	short err = time2CMTime(timeVal, m_time);
	if (err != CMLASN_SUCCESS)
		throw Exception(err, __FILE__, __LINE__);

	m_snaccTime.choiceId = SNACC::Time::utcTimeCid;
	m_snaccTime.utcTime = new SNACC::UTCTime(&m_time[2]);
	if (m_snaccTime.utcTime == NULL)
		throw MEMORY_EXCEPTION;

	return *this;
}


Time& Time::operator=(const CM_Time& cmTime)
{
	Clear();
	strcpy(m_time, cmTime);
	if ((strcmp(m_time, "1950") > 0) && (strcmp(m_time, "2050") < 0))
	{
		m_snaccTime.choiceId = SNACC::Time::utcTimeCid;
		m_snaccTime.utcTime = new SNACC::UTCTime(&m_time[2]);
	}
	else
	{
		m_snaccTime.choiceId = SNACC::Time::generalizedTimeCid;
		m_snaccTime.generalizedTime = new SNACC::GeneralizedTime(m_time);
	}
	if (m_snaccTime.utcTime == NULL)
		throw MEMORY_EXCEPTION;

	return *this;
}


Time& Time::operator=(const Time& other)
{
	if (this != &other)
	{
		Clear();
		operator=(other.m_snaccTime);
	}

	return *this;
}


bool Time::operator==(const Time& rhs) const
{
	if (this == &rhs)
		return true;

	return (strcmp(m_time, rhs.m_time) == 0);
}


bool Time::operator<(const Time& rhs) const
{
	return (strcmp(m_time, rhs.m_time) < 0);
}


bool Time::operator>(const Time& rhs) const
{
	return (strcmp(m_time, rhs.m_time) > 0);
}


void Time::Clear()
{
	memset(m_time, 0, CM_TIME_LEN);
	if (m_snaccTime.utcTime == NULL)
	{
		m_snaccTime.choiceId = SNACC::Time::utcTimeCid;
		return;
	}

	if (m_snaccTime.choiceId == SNACC::Time::utcTimeCid)
	{
		delete m_snaccTime.utcTime;
		m_snaccTime.utcTime = NULL;
	}
	else
	{
		delete m_snaccTime.generalizedTime;
		m_snaccTime.generalizedTime = NULL;
	}
}


void Time::FillSnaccGenTime(SNACC::GeneralizedTime& snacc) const
{
	if (m_snaccTime.choiceId == SNACC::Time::utcTimeCid)
		snacc = m_time;
	else if (m_snaccTime.generalizedTime != NULL)
		snacc = *m_snaccTime.generalizedTime;
	else
		throw EXCEPTION(CMLASN_NULL_POINTER);
}


SNACC::GeneralizedTime* Time::GetSnaccGenTime() const
{
	if (m_snaccTime.choiceId == SNACC::Time::utcTimeCid)
	{
		SNACC::GeneralizedTime* result = new SNACC::GeneralizedTime(m_time);
		if (result == NULL)
			throw MEMORY_EXCEPTION;
		return result;
	}
	else
		return new SNACC::GeneralizedTime(*m_snaccTime.generalizedTime);
}


void Time::calcUTCtime(char *s1, char sign, const std::string& s2,
					   std::string::size_type i)
/* This function calculates UTC time from the local time (s1) and the
GMT offset string (s2) and stores the result in s1.  Both s1 and s2 are numeric
strings.  The sign indicates whether s2 is positive or negative.  s1
is four bytes in length and in the form "hhmm".  s2 is checked to ensure that
it is the same length and form.  */
{
	// Check that the length of s2 is correct
	if ((i + 4) != s2.length())
		throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");

	// Check that the numeric characters are in the proper range and convert
	if ((s2[i] < '0') || (s2[i] > '2') ||			// 1st hour digit
		(s2[i + 1] < '0') || (s2[i + 1] > '9') ||	// 2nd hour digit
		(s2[i + 2] < '0') || (s2[i + 2] > '5') ||	// 1st min digit
		(s2[i + 3] < '0') || (s2[i + 3] > '9')) 	// 2nd min digit
		throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");

	// Calculate the UTC minutes
	int v1 = ((s1[2] - '0') * 10) + (s1[3] - '0');
	int v2 = sign * ((s2[2] - '0') * 10) + (s2[3] - '0');

	v1 += v2;

	int carry;
	if (v1 < 0)
	{
		v1 += 60;
		carry = -1;
	}
	else if (v1 > 59)
	{
		v1 -= 60;
		carry = 1;
	}
	else
		carry = 0;

	s1[2] = (char)((v1 / 10) + '0');
	s1[3] = (char)((v1 % 10) + '0');

	// Calculate the UTC hours
	v1 = ((s1[0] - '0') * 10) + (s1[1] - '0');
	v2 = sign * ((s2[0] - '0') * 10) + (s2[1] - '0');

	v1 += v2 + carry;

	if (v1 < 0)
		v1 += 24;
	else if (v1 > 23)
		v1 -= 24;

	s1[2] = (char)((v1 / 10) + '0');
	s1[3] = (char)((v1 % 10) + '0');
}


void Time::cvtGenTime2CM_Time(const std::string& gen)
/* This function copies the time from the Generalized time string and converts
it into a standard CM Library time string (format: "yyyymmddhhmmssZ").
Note:
   Generalized time is formatted according to ISO 8601 and ITU-T X.680:
      "yyyymmddhh" +
         "mm" or "mmss" (optional) +
         "." or "," + "s" (any number of decimal places) (optional) +
         "Z" or "-hh" or "+hh" or "-hhmm" or "+hhmm" (optional)
   When minutes or seconds are omitted, the CM Library time string fills
   in the fields with zeros.  It is rare that the trailing "Z" or local
   time differential will not be present in GeneralizedTime, since then
   the time value cannot be converted to Coordinated Universal Time (UTC).
   The usual GeneralizedTime is expected to be "yyyymmddhhmmssZ".
*/
{
	// Copy "yyyymmddhh" values
	std::string::size_type i;
	for (i = 0; (i < gen.length()) && (i < 10); ++i)
	{
		if ((gen[i] < '0') || (gen[i] > '9'))
			throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");
		else
			m_time[i] = gen[i];
	}

	// Check that there is more to convert
	if (i < gen.length())
	{
		// If the "mm" values aren't present, add 00's, else copy them
		if ((gen[i] < '0') || (gen[i] > '9'))
		{
			m_time[10] = '0';
			m_time[11] = '0';
		}
		else
		{
			m_time[10] = gen[i++];
			if (i < gen.length())		// Check for another minute char
			{
				if ((gen[i] < '0') || (gen[i] > '9'))
					throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");
				else
					m_time[11] = gen[i++];
			}
			else
				throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");
		}

		// If the "ss" values aren't present, add 00's, else copy them
		if ((i >= gen.length()) || (gen[i] < '0') || (gen[i] > '9'))
		{
			m_time[12] = '0';
			m_time[13] = '0';
		}
		else
		{
			m_time[12] = gen[i++];
			if (i < gen.length())		// Check for another seconds char
			{
				if ((gen[i] < '0') || (gen[i] > '9'))
					throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");
				else
					m_time[13] = gen[i++];
			}
			else
				throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");
		}
	}
	else if (i == 10)	// Nothing after the hours, so pad the minutes and
						// seconds with zeros.
	{
		m_time[10] = '0';
		m_time[11] = '0';
		m_time[12] = '0';
		m_time[13] = '0';
	}
	else	// String length ( < 10) is invalid for generalized time
		throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");

	// If the fractional seconds are present, skip over them
	if ((i < gen.length()) && ((gen[i] == '.') || (gen[i] == ',')))
	{
		i++;
		while ((i < gen.length()) && (gen[i] >= '0') && (gen[i] <= '9'))
			i++;
	}

	// Check that there is still more to convert
	if (i < gen.length())
	{
		// If the local offset is present, convert the local time into UTC
		if (gen[i] == '-')
		{
			calcUTCtime(&m_time[8], 1, gen, ++i);
		}
		else if (gen[i] == '+')
		{
			calcUTCtime(&m_time[8], -1, gen, ++i);
		}
		else if ((gen[i] != 'Z') || ((i + 1) != gen.length()))
			throw ASN_EXCEPTION("Invalid SNACC::GeneralizedTime value");
	}
	/* else: This is only a local time!  The CM library will append the 'Z'
	anyway, but local time may not be UTC!	Hopefully, no one will use local
	generalized time. */

	// end of source time, just append our 'Z'
	m_time[14] = 'Z';
	m_time[15] = '\0';
}


void Time::cvtUTC2CM_Time(const std::string& utc)
/* This function copies the time from the UTC time string and converts
it into a standard CM Library time string (format: "yyyymmddhhmmssZ").
Note:
   Coordinated Universal Time (UTC) is formatted according to ITU-T X.680:
      "yymmddhhmm" +
      "ss" (optional) +
      "Z" or "-hhmm" or "+hhmm"
   When seconds are omitted, the CM Library fills in the time string with
   zeros.
*/
{
	// Check length is valid
	if (utc.length() < 11)
		throw ASN_EXCEPTION("Invalid SNACC::UTCTime value");

	// take care of yy to yyyy conversion */
	if (utc[0] < '5')		// Less than 50 is years 2000-2049
	{
		m_time[0] = '2';
		m_time[1] = '0';
	}
	else					// Make it 1950 through 1999
	{
		m_time[0] = '1';
		m_time[1] = '9';
	}

	// Copy "yymmddhhmm" values
	std::string::size_type i;
	for (i = 0; i < 10; ++i)
	{
		if ((utc[i] < '0') || (utc[i] > '9'))
			throw ASN_EXCEPTION("Invalid SNACC::UTCTime value");
		else
			m_time[i + 2] = utc[i];
	}

	// If the "ss" values aren't present, add 00's, else copy them
	if ((utc[i] < '0') || (utc[i] > '9'))
	{
		m_time[12] = '0';
		m_time[13] = '0';
	}
	else
	{
		m_time[12] = utc[i++];
		if ((i >= utc.length()) || (utc[i] < '0') || (utc[i] > '9'))
			throw ASN_EXCEPTION("Invalid SNACC::UTCTime value");
		m_time[13] = utc[i++];
	}

	// Check that there is still more to convert
	if (i < utc.length())
	{
		// If the local offset is present, convert the local time into UTC
		if (utc[i] == '-')
		{
			calcUTCtime(&m_time[8], 1, utc, ++i);
		}
		else if (utc[i] == '+')
		{
			calcUTCtime(&m_time[8], -1, utc, ++i);
		}
		else if ((utc[i] != 'Z') || ((i + 1) != utc.length()))
			throw ASN_EXCEPTION("Invalid SNACC::UTCTime value");
	}
	else
		throw ASN_EXCEPTION("Invalid SNACC::UTCTime value");

	// end of source time, just append our 'Z' and terminate
	m_time[14] = 'Z';
	m_time[15] = 0;
}


///////////////////////////////////
// IntBytes class implementation //
///////////////////////////////////
IntBytes::IntBytes(const SNACC::AsnInt& asnInt, ulong mult)
{
	len = 0;
	data = NULL;
	SetFromInt(asnInt, mult);
}


IntBytes& IntBytes::operator=(const SNACC::AsnBits& asnBits)
{
	Bytes::operator=(asnBits);
	return *this;
}


void IntBytes::Reverse()
{
   if (len == 0)
      return;

   uchar temp;
	uchar* pFront = data;
	uchar* pBack = data + len - 1;
	while (pFront < pBack)
	{
		// Switch the bytes
		temp = *pBack;
		*pBack = *pFront;
		*pFront = temp;

		// Update the pointers
		++pFront;
		--pBack;
	}
}


void IntBytes::ReverseHalves()
{
   if (len == 0)
      return;
	else if ((len % 2) != 0)
	{
		throw EXCEPTION_STR(CMLASN_INVALID_PARAMETER,
			"Length must be a multiple of 2");
	}

	// Reverse the front half
	uchar* pFront = data;
	uchar* pBack = data + (len / 2) - 1;
	uchar temp;
	while (pFront < pBack)
	{
		// Switch the bytes
		temp = *pBack;
		*pBack = *pFront;
		*pFront = temp;

		// Update the pointers
		++pFront;
		--pBack;
	}

	// Reverse the back half
	pFront = data + len / 2;
	pBack = data + len - 1;
	while (pFront < pBack)
	{
		// Switch the bytes
		temp = *pBack;
		*pBack = *pFront;
		*pFront = temp;

		// Update the pointers
		++pFront;
		--pBack;
	}
} // end of IntBytes::ReverseHalves()


void IntBytes::SetFromInt(const SNACC::AsnInt& asnInt, ulong mult)
{
	Clear();

	const uchar* pData = asnInt.c_str();
	len = asnInt.length();

	// Check the leading byte to see if it is zero
	if ((len > 0) && (pData[0] == 0))
	{
		// Skip over the leading zero byte
		pData++;
		len--;
	}

	// Check if integer needs to be padded
	unsigned long pad = 0;
	if (mult > 0)
	{
		pad = mult - (len % mult);
		if (pad == mult)
			pad = 0;
	}
	len += pad;

	// Allocate and clear memory for the data
	Set(len);

	// Copy the integer
	if (len > 0)
		memcpy(&data[pad], pData, len - pad);

} // end of IntBytes::Set()


////////////////////////////////
// Bytes class implementation //
////////////////////////////////
Bytes::Bytes(ulong num, const uchar* data) : CommonBytes(num, data)
{
	unusedBits = 0;
}


Bytes::Bytes(const Bytes_struct& data) : CommonBytes(data.num, data.data)
{
	unusedBits = 0;
}


Bytes::Bytes(const char* fileName) : CommonBytes(fileName)
{
	unusedBits = 0;
}


Bytes::Bytes(const SNACC::AsnOcts& asnOcts)
{
	unusedBits = 0;
	operator=(asnOcts);
}


Bytes::Bytes(const SNACC::AsnAny& asnAny, const char* nameOfAny)
{
	unusedBits = 0;
	SetFromAny(asnAny, nameOfAny);
}


Bytes& Bytes::operator=(const Bytes_struct& data)
{
	Set(data.num, data.data);
	return *this;
}


Bytes& Bytes::operator=(const SNACC::AsnBits& asnBits)
{
	Set(asnBits.length(), asnBits.data());
	unusedBits = asnBits.BitLen() % 8;
	if (unusedBits != 0)
		unusedBits = 8 - unusedBits;
	return *this;
}


Bytes& Bytes::operator=(const SNACC::AsnOcts& asnOcts)
{
	Set(asnOcts.Len(), asnOcts.c_ustr());
	return *this;
}


bool Bytes::operator==(const Bytes_struct& rhs) const
{
	if ((unusedBits != 0) || (len != (unsigned long)rhs.num))
		return false;
	if (rhs.data == NULL)
		return (len == 0);
	return (memcmp(data, rhs.data, len) == 0);
}

void Bytes::Clear()
{
        unusedBits = 0;
	len = 0;
        if (data != NULL)
	{
	   delete[] data;
	   data = NULL;
	}
}

void Bytes::SetFromAny(const SNACC::AsnAny& asnAny, const char* nameOfAny)
{
	if (nameOfAny == NULL)
		nameOfAny = "<Unnamed ANY>";

	// If the AsnAny is decoded, re-encode the object
	if (asnAny.ai != NULL)
	{
		// Check that the decoded value is present
		if (asnAny.value == NULL)
			throw ASN_EXCEPTION2(nameOfAny, " value field is NULL");

		// Re-encode the object
		SNACC::AsnBuf asnBuf;
		SNACC::AsnLen numEncoded;
		if (!asnAny.BEncPdu(asnBuf, numEncoded))
			throw ASN_EXCEPTION2("Error encoding ", nameOfAny);

		// Set this value from the AsnBuf
		SetFromBuf(asnBuf, numEncoded);
	}
	else	// Just copy the contents of the AsnBuf
	{
		// Check that the encoded AsnBuf is present
		if (asnAny.anyBuf == NULL)
			throw ASN_EXCEPTION2(nameOfAny, " anyBuf field is NULL");

		// Set this value from the AsnBuf
		SetFromBuf(*asnAny.anyBuf, asnAny.anyBuf->length());
	}
}


void Bytes::SetFromBuf(const SNACC::AsnBuf& asnBuf, ulong bufLen)
{
	Clear();

	try {
		// Allocate memory for the encoded data
		Set(bufLen);
		if (len > 0)
		{
			// Copy the encoded value
			asnBuf.ResetMode();
			asnBuf.GetSeg((char*)data, len);
		}
	}
	catch (...) {
		Clear();
		throw;
	}
}


ulong Bytes::Decode(SNACC::AsnType& snaccObj, const char* snaccObjName) const
{
	if (snaccObjName == NULL)
		snaccObjName = "<unknown object>";

	// Create a SNACC::AsnRvsBuf and install it into the AsnBuf
	SNACC::AsnRvsBuf asnStream((char*)data, len);
	SNACC::AsnBuf asnBuf(&asnStream);

	// Decode the object
	SNACC::AsnLen numDecoded = 0;
	if (!snaccObj.BDecPdu(asnBuf, numDecoded))
		throw ASN_EXCEPTION2("Error decoding ", snaccObjName);

	// Check that the number of bytes decoded matches the length
	if (numDecoded != len)
		throw ASN_EXCEPTION2(snaccObjName, "not fully decoded");

	return numDecoded;
}


ulong Bytes::Encode(const SNACC::AsnType& snaccObj, const char* snaccObjName)
{
	if (snaccObjName == NULL)
		snaccObjName = "<unknown object>";

	// Encode the SNACC object into a SNACC::AsnBuf
	SNACC::AsnBuf asnBuf;
	SNACC::AsnLen numEncoded;
	if (!snaccObj.BEncPdu(asnBuf, numEncoded))
		throw ASN_EXCEPTION2("Error encoding ", snaccObjName);

	// Set this Bytes object from the SNACC::AsnBuf
	SetFromBuf(asnBuf, numEncoded);

	return numEncoded;
}


// Fill in the Bytes_struct form of this object
void Bytes::FillBytesStruct(Bytes_struct& bytes) const
{
	bytes.data = NULL;
	bytes.num = len;
	if (bytes.num <= 0)
		bytes.num = 0;
	else
	{
		bytes.data = (uchar*)malloc(len);
		if (bytes.data == NULL)
		{
			bytes.num = 0;
			throw MEMORY_EXCEPTION;
		}
		memcpy(bytes.data, data, len);
	}
}

// Get the Bytes_struct form of this object
Bytes_struct* Bytes::GetBytesStruct() const
{
	Bytes_struct* result = (Bytes_struct*)malloc(sizeof(Bytes_struct));
	if (result == NULL)
		throw MEMORY_EXCEPTION;

	try {
		FillBytesStruct(*result);
		return result;
	}
	catch (...) {
		free(result);
		throw;
	}
}


SNACC::AsnOcts* Bytes::GetSnacc() const
{
	SNACC::AsnOcts* result = new SNACC::AsnOcts((const char*)data, len);
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	return result;
}


////////////////////////////////
// Mutex class implementation //
////////////////////////////////
Mutex::Mutex(const char* mutexName)
{
	m_wasCopied = false;

#ifndef NOTHREADS
#ifdef WIN32
	SECURITY_DESCRIPTOR sd;
	if (InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) != 0)
		SetSecurityDescriptorDacl(&sd, TRUE, 0, FALSE);

	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(sa);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = TRUE;
	m_winHandle = CreateMutex(&sa, FALSE, mutexName);
	m_winWriteEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
	m_winReadEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
#else
	pthread_mutex_init((pthread_mutex_t*)&m_mutex, NULL);
	pthread_cond_init((pthread_cond_t*)&m_WriteCondition, NULL);
	pthread_cond_init((pthread_cond_t*)&m_ReadCondition, NULL);
#endif
#endif // NOTHREADS
}

Mutex::Mutex(const Mutex& that)
{
#ifndef NOTHREADS
#ifdef WIN32
	m_winHandle = that.m_winHandle;
	m_winWriteEvent = that.m_winWriteEvent;
	m_winReadEvent	= that.m_winReadEvent;
#else
	m_mutex = that.m_mutex;
	m_WriteCondition = that.m_WriteCondition;
	m_ReadCondition	= that.m_ReadCondition;
#endif
#endif // NOTHREADS
	m_wasCopied = that.m_wasCopied;
	that.m_wasCopied = true;
}


Mutex::~Mutex()
{
	if (m_wasCopied == false)
	{
#ifndef NOTHREADS
#ifdef WIN32
		// Close the Windows mutex handle
		if (m_winHandle != 0)
			CloseHandle(m_winHandle);
		if (m_winWriteEvent != 0)
			CloseHandle(m_winWriteEvent);
		if (m_winReadEvent != 0)
			CloseHandle(m_winReadEvent);
#else
		// Destroy the mutex
		pthread_mutex_destroy((pthread_mutex_t*)&m_mutex);
		pthread_cond_destroy((pthread_cond_t*)&m_WriteCondition);
		pthread_cond_destroy((pthread_cond_t*)&m_ReadCondition);
#endif
#endif // NOTHREADS
	}
}


MutexLock Mutex::AcquireLock() const
{
#ifndef NOTHREADS
#ifdef WIN32
		if (WaitForSingleObject(m_winHandle, INFINITE) == WAIT_FAILED)
#else
		if (pthread_mutex_lock((pthread_mutex_t*)&m_mutex) != 0)
#endif
		{
			throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
		}
#endif // NOTHREADS
	return MutexLock(*this);
}


void Mutex::ReleaseMutex() const
{
	// Signal the waiting threads and Release/unlock the mutex
#ifndef NOTHREADS
#ifdef WIN32
	if (::ReleaseMutex(m_winHandle) == 0)
#else
	if (pthread_mutex_unlock((pthread_mutex_t*)&m_mutex) != 0)
#endif
	{
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
	}
#endif // NOTHREADS
}

Mutex& Mutex::operator=(const Mutex&)
{
	throw Exception(CMLASN_NOT_IMPLEMENTED, __FILE__, __LINE__);
}

////////////////////////////////////
// MutexLock class implementation //
////////////////////////////////////
MutexLock::MutexLock(const MutexLock& that) : m_mutex(that.m_mutex)
{
	m_isReleased = that.m_isReleased;
	that.m_isReleased = true;
}


MutexLock& MutexLock::operator=(const MutexLock& that)
{
	throw Exception(CMLASN_NOT_IMPLEMENTED, __FILE__, __LINE__);
	return *this;
}


void MutexLock::Release()
{
	if (m_isReleased)
		return;

	// Release the lock
	m_mutex.ReleaseMutex();

	m_isReleased = true;
}

/////////////////////////////////////////
// ReadWriteMutex class implementation //
/////////////////////////////////////////
ReadWriteMutex::ReadWriteMutex(const char* mutexName,
										 unsigned int maxReadThreads) :
Mutex(mutexName)
{
	MutexLock lock = Mutex::AcquireLock();
	m_nReads = 0;

	if (maxReadThreads == 0)
		m_maxReads = (unsigned int)-1;
	else
		m_maxReads = maxReadThreads;
}


MutexLock ReadWriteMutex::AcquireLock() const
{
	// Continue when there are no reads and we can acquire a write lock on the mutex.
#ifndef NOTHREADS
#ifdef WIN32
	CONST HANDLE winHandles[] = { m_winWriteEvent, m_winHandle };
	if (WaitForMultipleObjects(2, winHandles, TRUE, INFINITE) == WAIT_FAILED)
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
#else
	if (pthread_mutex_lock((pthread_mutex_t*)&m_mutex) != 0)
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);

	while (m_nReads != 0)
	{
		if (pthread_cond_wait((pthread_cond_t *)&m_WriteCondition, (pthread_mutex_t *)&m_mutex) != 0)
			throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
	}
#endif
#endif // NOTHREADS
	if (m_nReads != 0)
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);

	return MutexLock(*this);
}


ReadLock ReadWriteMutex::AcquireReadLock() const
{
#ifndef NOTHREADS
#ifdef WIN32
	// Acquire or lock the mutex
	if (WaitForSingleObject(m_winHandle, INFINITE) == WAIT_FAILED)
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);

	// If max read threads running, wait for a read thread to finish
	while (m_nReads >= m_maxReads)
	{
		// Release the mutex and wait for another read thread to finish
		::ReleaseMutex(m_winHandle);
		CONST HANDLE winHandles[] = { m_winReadEvent, m_winHandle };
		if (WaitForMultipleObjects(2, winHandles, TRUE, INFINITE) == WAIT_FAILED)
			throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
	}
	// Unsignal the read event on windows so we can signal other read threads
	// when we finish
	ResetEvent(m_winReadEvent);
#else
	// Acquire or lock the mutex
	if (pthread_mutex_lock((pthread_mutex_t*)&m_mutex) != 0)
		throw EXCEPTION(CMLASN_UNKNOWN_ERROR);

	// If max read threads running, wait for a read thread to finish
	while (m_nReads >= m_maxReads)
	{
		if (pthread_cond_wait((pthread_cond_t *)&m_ReadCondition, (pthread_mutex_t *)&m_mutex) != 0)
			throw EXCEPTION(CMLASN_UNKNOWN_ERROR);
	}
#endif //WIN32
#endif //NOTHREADS

	// Increment number of read threads
	m_nReads++;

#ifndef NOTHREADS
#ifdef WIN32
	// First, unsignal the write event on windows so no other writes can occur
	// until the last read is finished
	if (m_nReads == 1)
		ResetEvent(m_winWriteEvent);

	//Release the lock on the mutex
	::ReleaseMutex(m_winHandle);
#else
	//Release the lock on the mutex
	pthread_mutex_unlock((pthread_mutex_t *)&m_mutex);
#endif
#endif //NOTHREADS
	return ReadLock(*this);
}


void ReadWriteMutex::ReleaseLock() const
{
	// Acquire or lock the mutex
	MutexLock lock = Mutex::AcquireLock();

	if (m_nReads > 1)
		--m_nReads;
	else if (m_nReads == 1)
	{
		m_nReads = 0;

		// Signal other waiting write threads
#ifndef NOTHREADS
#ifdef WIN32
		SetEvent(m_winWriteEvent);
#else
		pthread_cond_broadcast((pthread_cond_t*)&m_WriteCondition);
#endif //WIN32
#endif //NOTHREADS
	}
// Signal other waiting read threads
#ifndef NOTHREADS
#ifdef WIN32
	SetEvent(m_winReadEvent);
#else
	pthread_cond_broadcast((pthread_cond_t*)&m_ReadCondition);
#endif //WIN32
#endif //NOTHREADS
}


///////////////////////////////////
// ReadLock class implementation //
///////////////////////////////////
ReadLock::ReadLock(const ReadLock& that) : MutexLock(that)
{
	if (!m_isReleased)
	{
		// Acquire a new read lock
		ReadLock lock = ((const ReadWriteMutex&)m_mutex).AcquireReadLock();

		// Flag the read lock as released, so the read count will be correct
		lock.m_isReleased = true;

		// Reset the released flag in the other ReadLock
		that.m_isReleased = false;
	}
}


void ReadLock::Release()
{
	if (m_isReleased)
		return;

	// Release the lock
	m_mutex.ReleaseLock();

	m_isReleased = true;
}


//////////////////////////////////
// CML::ASN::Internal functions //
//////////////////////////////////
Bytes_struct* Internal::CvtAsnBufToBytes(const SNACC::AsnBuf& buffer)
{
	Bytes_struct* pResult = (Bytes_struct*)calloc(1, sizeof(Bytes_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		CvtAsnBufToBytesStruct(*pResult, buffer);
		return pResult;
	}
	catch (...) {
		free(pResult);
		throw;
	}
}


void Internal::CvtAsnBufToBytesStruct(Bytes_struct& bytes,
									  const SNACC::AsnBuf& buffer)
{
	// Reset the AsnBuf for reading
	buffer.ResetMode();

	bytes.num = buffer.length();
	bytes.data = (uchar*)calloc(bytes.num, sizeof(uchar));
	if (bytes.data == NULL)
	{
		bytes.num = 0;
		throw MEMORY_EXCEPTION;
	}

	buffer.GetSeg((char*)bytes.data, bytes.num);
}


Bytes_struct* Internal::CvtAsnIntToBytes(const SNACC::AsnInt& hugeInt,
										 int mult)
{
	Bytes_struct* pResult = (Bytes_struct*)malloc(sizeof(Bytes_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		CvtAsnIntToExistingBytes(*pResult, hugeInt, mult);
		return pResult;
	}
	catch (...) {
		free(pResult);
		throw;
	}
}


void Internal::CvtAsnIntToExistingBytes(Bytes_struct& bytes,
										const SNACC::AsnInt& hugeInt, int mult)
{
	const uchar* data = hugeInt.c_str();
	bytes.num = hugeInt.length();

	// Check the leading byte to see if it is zero
	if ((bytes.num > 0) && (data[0] == 0))
	{
		// Skip over the leading zero byte
		data++;
		bytes.num--;
	}

	// Check if huge integer needs to be padded
	int pad = 0;
	if (mult > 0)
	{
		pad = mult - (bytes.num % mult);
		if (pad == mult)
			pad = 0;
	}
	bytes.num += pad;

	// Allocate and clear memory for the data
	if (bytes.num > 0)
	{
		bytes.data = (uchar*)calloc(bytes.num, sizeof(uchar));
		if (bytes.data == NULL)
		{
			bytes.num = 0;
			throw MEMORY_EXCEPTION;
		}
		memcpy(&bytes.data[pad], data, bytes.num - pad);
	}
	else
	{
		bytes.num = 0;
		bytes.data = NULL;
	}
}


Bytes_struct* Internal::CvtBitsToBytes(const SNACC::AsnBits& bits)
{
	Bytes_struct* pResult = (Bytes_struct*)malloc(sizeof(Bytes_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	pResult->num = (bits.BitLen() + 7) / 8;
	if (pResult->num == 0)
		pResult->data = NULL;
	else
	{
		pResult->data = (uchar*)calloc(pResult->num, sizeof(uchar));
		if (pResult->data == NULL)
		{
			free(pResult);
			throw MEMORY_EXCEPTION;
		}

		ulong byte = 0;
		uchar mask = 0;
		for (size_t i = 0; i < bits.BitLen(); i++)
		{
			if ((i % 8) == 0)
				mask = 0x80;

			if (bits.GetBit(i))
				pResult->data[byte] |= mask;

			mask >>= 1;
			if (mask == 0)
				byte++;
		}
	}

	return pResult;
}


void Internal::CvtBytesToSigStruct(Sig_struct& sig, const Bytes& encBuf)
{
	// Decode the encoded signature value depending on the OID
	if ((strcmp(sig.alg, gRSA_MD2_OID) == 0) ||
		(strcmp(sig.alg, gRSA_MD4_OID) == 0) ||
		(strcmp(sig.alg, gRSA_MD5_OID) == 0) ||
		(strcmp(sig.alg, gRSA_SHA1_OID) == 0))
	{
		sig.value.rsa = encBuf.GetBytesStruct();
	}
	else if ((strcmp(sig.alg, gDSA_SHA1_OID) == 0) ||
		(strcmp(sig.alg, gECDSA_SHA1_OID) == 0) ||
		(strcmp(sig.alg, gECDSA_SHA256_OID) == 0) ||
		(strcmp(sig.alg, gECDSA_SHA384_OID) == 0))
	{
		// Determine size of hash from OID, default is SHA1
		unsigned int hashLen = gSHA1_HASH_LEN;
		if (strcmp(sig.alg, gECDSA_SHA256_OID) == 0)
			hashLen = gSHA256_HASH_LEN;
		else if (strcmp(sig.alg, gECDSA_SHA384_OID) == 0)
			hashLen = gSHA384_HASH_LEN;

		// Decode the DSA signature value
		SNACC::Dss_Sig_Value dsaSigValue;
		encBuf.Decode(dsaSigValue, "SNACC::Dss_Sig_Value");

		// Allocate memory for the Dsa_sig_struct
		sig.value.dsa = (Dsa_sig_struct*)calloc(1, sizeof(Dsa_sig_struct));
		if (sig.value.dsa == NULL)
			throw MEMORY_EXCEPTION;

		try {
			Internal::CvtAsnIntToExistingBytes(sig.value.dsa->r,
				dsaSigValue.r, hashLen);
			Internal::CvtAsnIntToExistingBytes(sig.value.dsa->s,
				dsaSigValue.s, hashLen);
		}
		catch (...) {
			free(sig.value.dsa->r.data);
			free(sig.value.dsa->s.data);
			free(sig.value.dsa);
			sig.value.dsa = NULL;
			throw;
		}
	}
	else if (strcmp(sig.alg, gMOSAIC_DSA_OID) == 0)
	{
		if (encBuf.Len() != (gSHA1_HASH_LEN * 2))
			throw ASN_EXCEPTION("Invalid length of Fortezza signature value");

		// Allocate memory for the Dsa_sig_struct
		sig.value.dsa = (Dsa_sig_struct*)calloc(1, sizeof(Dsa_sig_struct));
		if (sig.value.dsa == NULL)
			throw MEMORY_EXCEPTION;

		// Set the lengths of the R & S values
		sig.value.dsa->r.num = gSHA1_HASH_LEN;
		sig.value.dsa->s.num = gSHA1_HASH_LEN;

		try {
			// Allocate memory for and copy the R value
			sig.value.dsa->r.data = (uchar*)malloc(sig.value.dsa->r.num);
			if (sig.value.dsa->r.data == NULL)
				throw MEMORY_EXCEPTION;

			memcpy(sig.value.dsa->r.data, encBuf.GetData(),
				sig.value.dsa->r.num);

			// Allocate memory for and copy the S value
			sig.value.dsa->s.data = (uchar*)malloc(sig.value.dsa->s.num);
			if (sig.value.dsa->s.data == NULL)
				throw MEMORY_EXCEPTION;

			memcpy(sig.value.dsa->s.data,
				&encBuf.GetData()[sig.value.dsa->r.num], sig.value.dsa->s.num);
		}
		catch (...) {
			free(sig.value.dsa->r.data);
			free(sig.value.dsa->s.data);
			free(sig.value.dsa);
			sig.value.dsa = NULL;
			throw;
		}
	}
	else	// For all other OIDs, just copy the encoded signature value
		sig.value.encoded = encBuf.GetBytesStruct();
}


void Internal::FillParameters(Pub_key_struct& cmPubKey, const AlgID& algID)
{
	// Initialize parameters union of the Pub_key_struct
	cmPubKey.params.dsa = NULL;

	if (algID.parameters == NULL)
		return;

	if (algID.algorithm == gKEA_OID)
	{
		// Decode the KEA parameter ID
		SNACC::AsnOcts keaIDParam;
		algID.parameters->Decode(keaIDParam, "KEA parameters");

		// Copy the AsnOcts to a Bytes_struct
		cmPubKey.params.kea = cvtOctsToBytes(keaIDParam);
	}
	else if ((algID.algorithm == gDSA_OID) || (algID.algorithm == gOIW_DSA) ||
		(algID.algorithm == gDSA_KEA_OID))
	{
		// Decode the old Fortezza or new DSA parameters
		SNACC::OldOrNewParameters eitherParams;
		algID.parameters->Decode(eitherParams, "DSA parameters");
		if (eitherParams.newParams == NULL)
			throw ASN_EXCEPTION("SNACC::OldOrNewParameters is NULL");

		// Convert the parameters into the correct Pqg_params_struct
		if (eitherParams.choiceId == SNACC::OldOrNewParameters::newParamsCid)
		{
			// Convert the DSA parameters into a Pqg_params_struct
			cmPubKey.params.dsa = cvtDSAParameters(*eitherParams.newParams);
		}
		else if (eitherParams.choiceId ==
			SNACC::OldOrNewParameters::oldParamsCid)
		{
			if (eitherParams.oldParams->differentParms == NULL)
				throw ASN_EXCEPTION("SNACC::Kea_Dss_Parms::differentParms is NULL");

			// Convert the Fortezza parameters into the correct Pqg_params_struct
			if (eitherParams.oldParams->choiceId ==
				SNACC::Kea_Dss_Parms::commonParmsCid)
			{
				cmPubKey.params.dsa_kea =
					cvtFortezzaParams(*eitherParams.oldParams->commonParms);
			}
			else if (eitherParams.oldParams->choiceId ==
				SNACC::Kea_Dss_Parms::differentParmsCid)
			{
				if (cmPubKey.key.combo == NULL)
					throw EXCEPTION(CMLASN_NULL_POINTER);
				cmPubKey.key.combo->diff_kea = NULL;

				cmPubKey.params.dsa_kea = cvtFortezzaParams(
					eitherParams.oldParams->differentParms->dss_Parms);
				cmPubKey.key.combo->diff_kea = cvtFortezzaParams(
					eitherParams.oldParams->differentParms->kea_Parms);
			}
			else
				throw ASN_EXCEPTION("Invalid CHOICE in SNACC::Kea_Dss_Parms");
		}
		else
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::OldOrNewParameters");
	}
	else
	{
		// Copy the encoded parameters to a Bytes_struct
		cmPubKey.params.encoded = algID.parameters->GetBytesStruct();
	}
} // end of Internal::FillParameters()


////////////////////////
// Internal functions //
////////////////////////
Pqg_params_struct* cvtDSAParameters(const SNACC::Dss_Parms& params)
{
	Pqg_params_struct* pResult = (Pqg_params_struct*)
		calloc(1, sizeof(Pqg_params_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		Internal::CvtAsnIntToExistingBytes(pResult->p, params.p, 8);
		Internal::CvtAsnIntToExistingBytes(pResult->q, params.q, 20);
		Internal::CvtAsnIntToExistingBytes(pResult->g, params.g, 8);
		return pResult;
	}
	catch (...) {
		Internal::FreePQGs(pResult);
		throw;
	}
}


ulong cvtFortezzaMultiByte(Bytes_struct& bytes, const uchar* data,
						   const uchar* dataEnd)
{
	if ((data == NULL) || (dataEnd == NULL))
		throw EXCEPTION(CMLASN_NULL_POINTER);

	// Count the number of bytes
	int count = 1;
	while ((count < (dataEnd - data)) && ((data[count] & 0x80) != 0))
		count++;
	if ((data[count] & 0x80) != 0)
		throw ASN_EXCEPTION("Invalid Fortezza public key");

	// Allocate memory for the result
	bytes.num = count;
	bytes.data = (uchar*)malloc(count);
	if (bytes.data == NULL)
		throw MEMORY_EXCEPTION;

	memcpy(bytes.data, data, count);

	return count;
}


Pqg_params_struct* cvtFortezzaParams(const SNACC::Fortezza_Parms& params)
{
	Pqg_params_struct* pResult = (Pqg_params_struct*)
		calloc(1, sizeof(Pqg_params_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		cvtOctsToExistingBytes(pResult->p, params.p);
		cvtOctsToExistingBytes(pResult->q, params.q);
		cvtOctsToExistingBytes(pResult->g, params.g);
		return pResult;
	}
	catch (...) {
		Internal::FreePQGs(pResult);
		throw;
	}
}


void cvtFortezzaPubKey(Pub_key_struct& cmPubKey, const Bytes& keyBuf)
{
	cmPubKey.key.combo = (Mosaic_key_struct*)
		calloc(1, sizeof(Mosaic_key_struct));
	if (cmPubKey.key.combo == NULL)
		throw MEMORY_EXCEPTION;

	Mosaic_key_struct& fortKey = *cmPubKey.key.combo;

	unsigned long keyLen = keyBuf.Len();
	if (keyLen < 275)
		throw ASN_EXCEPTION("Invalid length of Fortezza public key");
	const uchar* keyData = keyBuf.GetData();
	const uchar* bufEnd = keyData + keyLen;

	fortKey.kea_ver = *keyData++;
	if (fortKey.kea_ver != 0)
		throw ASN_EXCEPTION("Invalid Fortezza KEA version");

	fortKey.kea_type = *keyData++;
	if (fortKey.kea_type != 0x01)
		throw ASN_EXCEPTION("Invalid Fortezza KEA type");

	memcpy(fortKey.kmid, keyData, CM_KMID_LEN);
	keyData += CM_KMID_LEN;

	keyData += cvtFortezzaMultiByte(fortKey.kea_clearance, keyData, bufEnd);
	keyData += cvtFortezzaMultiByte(fortKey.kea_privs, keyData, bufEnd);

	if (((bufEnd - keyData) < 263) || (*keyData++ != 0) ||
		(*keyData++ != 0x80))
		throw ASN_EXCEPTION("Invalid length of Fortezza public key");

	fortKey.kea_y.num = 128;
	fortKey.kea_y.data = (uchar*)malloc(128);
	if (fortKey.kea_y.data == NULL)
		throw MEMORY_EXCEPTION;
	memcpy(fortKey.kea_y.data, keyData, 128);
	keyData += 128;

	fortKey.dsa_ver = *keyData++;
	if (fortKey.dsa_ver != 0)
		throw ASN_EXCEPTION("Invalid Fortezza DSA version");

	fortKey.dsa_type = *keyData++;
	if (fortKey.dsa_type != 0x02)
		throw ASN_EXCEPTION("Invalid Fortezza DSA type");

	keyData += cvtFortezzaMultiByte(fortKey.dsa_privs, keyData, bufEnd);

	if (((bufEnd - keyData) != 130) || (*keyData++ != 0) ||
		(*keyData++ != 0x80))
		throw ASN_EXCEPTION("Invalid length of Fortezza public key");

	fortKey.dsa_y.num = 128;
	fortKey.dsa_y.data = (uchar*)malloc(128);
	if (fortKey.dsa_y.data == NULL)
		throw MEMORY_EXCEPTION;
	memcpy(fortKey.dsa_y.data, keyData, 128);

} // end of cvtFortezzaPubKey


Bytes_struct* Internal::cvtOctsToBytes(const SNACC::AsnOcts& octs)
{
	Bytes_struct* pResult = (Bytes_struct*)malloc(sizeof(Bytes_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		cvtOctsToExistingBytes(*pResult, octs);
		return pResult;
	}
	catch (...) {
		free(pResult);
		throw;
	}
}


void cvtOctsToExistingBytes(Bytes_struct& bytes, const SNACC::AsnOcts& octs)
{
	bytes.num = octs.Len();
	bytes.data = (uchar*)malloc(bytes.num);
	if (bytes.data == NULL)
		throw MEMORY_EXCEPTION;
	memcpy(bytes.data, octs.c_ustr(), bytes.num);
}

void Internal::cvtInt2BytesStruct(Bytes_struct **bytes, const SNACC::AsnInt& theInt)
{
	if (*bytes == NULL)
	{
		*bytes = (Bytes_struct *)malloc(sizeof(Bytes_struct));
		if (*bytes == NULL)
			throw MEMORY_EXCEPTION;
	}
	(*bytes)->num = theInt.length();
	(*bytes)->data = (uchar *)malloc ((*bytes)->num);
	if ((*bytes)->data == NULL)
		throw MEMORY_EXCEPTION;
	memcpy((*bytes)->data, theInt.c_str(), (*bytes)->num);
}


RSAPublicKey_struct* cvtRSAPublicKey(const SNACC::RSAPublicKey& rsaKey)
{
	RSAPublicKey_struct* pResult = (RSAPublicKey_struct*)
		calloc(1, sizeof(RSAPublicKey_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		Internal::CvtAsnIntToExistingBytes(pResult->modulus, rsaKey.modulus, 8);
		Internal::CvtAsnIntToExistingBytes(pResult->publicExponent,
			rsaKey.publicExponent);
		return pResult;
	}
	catch (...) {
		free(pResult->modulus.data);
		free(pResult->publicExponent.data);
		free(pResult);
		throw;
	}
}


// Mutex used in time2CMTime()
static Mutex gmTimeMutex;

// time2CMTime() converts a local time_t value into a CM_Time string
short time2CMTime(time_t t, char* cm_time)
{
	// Acquire a handle to the mutex
	MutexLock lock = gmTimeMutex.AcquireLock();

	// Check the time_t for negative and fix to be max for time_t
	if (t < 0)
	{
		t = 1;
		t <<= sizeof(time_t) * 8 - 2;
		t |= t - 1;
	}

	// Convert the time value to GM time */
	struct tm* utc = gmtime(&t);
	if (utc == NULL)
		return CMLASN_UNKNOWN_ERROR;

	// Initialize the temporary date/time variables
	int year = utc->tm_year + 1900;		// tm_year is years since 1900
	int month = utc->tm_mon + 1;		// tm_mon is years since Jan
	int day = utc->tm_mday;
	int hour = utc->tm_hour;
	int min = utc->tm_min;
	int sec = utc->tm_sec;

	// Create the string
	if (sprintf(cm_time, "%d%02d%02d%02d%02d%02dZ", year, month, day, hour,
		min, sec) != CM_TIME_LEN - 1)
		return CMLASN_UNKNOWN_ERROR;

	return CMLASN_SUCCESS;
}

// end of CM_Certificate.cpp
