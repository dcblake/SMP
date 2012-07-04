/*****************************************************************************
File:     CM_AttribCert.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the AttributeCert class and the classes contained
		  within, including the ACExtensions class.

Created:  28 March 2002
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  16 April 2004

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
static Sec_tags* cvtSecTagsList(const SNACC::SecurityTagPrivileges& snacc);
static SecCat_LL* cvtSecurityCategory(const SNACC::SecurityCategory& snacc);


////////////////////////////////////////
// AttributeCert class implementation //
////////////////////////////////////////
AttributeCert::AttributeCert()
{
	// Initialize default version
	version = SNACC::AttCertVersion::v2;

	// Initialize pointer and private m_versionPresent
	pIssuerUniqueID = NULL;
	m_versionPresent = false;
}


AttributeCert::AttributeCert(const SNACC::AttributeCertificate& snacc)
{
	pIssuerUniqueID = NULL;
	operator=(snacc);
}


AttributeCert::AttributeCert(const Bytes& asn)
{
	pIssuerUniqueID = NULL;
	operator=(asn);
}


AttributeCert::AttributeCert(const AttributeCert& that)
{
	pIssuerUniqueID = NULL;
	operator=(that);
}


AttributeCert& AttributeCert::operator=(const SNACC::AttributeCertificate& snacc)
{
	// Delete existing values in member variables
	Clear();

	try {
		// Set the version
		if (snacc.toBeSigned.version == NULL)
            version = SNACC::AttCertVersion::v1;	// Default is v1
		else
		{
			version = *snacc.toBeSigned.version;
			m_versionPresent = true;
		}

		// Set the holder
		if (version == SNACC::AttCertVersion::v1)
		{
			if (snacc.toBeSigned.eitherHolder.choiceId ==
				SNACC::AttributeCertificateInfoChoice::holderCid)
				throw ASN_EXCEPTION("Invalid Holder in v1 SNACC::AttributeCertificate");
		}
		else if (version == SNACC::AttCertVersion::v2)
		{
			if ((snacc.toBeSigned.eitherHolder.choiceId ==
				SNACC::AttributeCertificateInfoChoice::baseCertificateIDCid) ||
				(snacc.toBeSigned.eitherHolder.choiceId ==
				SNACC::AttributeCertificateInfoChoice::subjectNameCid))
				throw ASN_EXCEPTION("Invalid Holder in v2 SNACC::AttributeCertificate");
		}
		else
			throw ASN_EXCEPTION("Invalid SNACC::AttCertVersion");
		holder = snacc.toBeSigned.eitherHolder;

		// Set the attribute cert issuer
		if (version == SNACC::AttCertVersion::v1)
		{
			if (snacc.toBeSigned.issuer.choiceId !=
				SNACC::AttCertIssuer::v1FormCid)
				throw ASN_EXCEPTION("Invalid AttCertIssuer in v1 SNACC::AttributeCertificate");
		}
		else if (version == SNACC::AttCertVersion::v2)
		{
			if (snacc.toBeSigned.issuer.choiceId !=
				SNACC::AttCertIssuer::v2FormCid)
				throw ASN_EXCEPTION("Invalid AttCertIssuer in v2 SNACC::AttributeCertificate");
		}
		else
			throw ASN_EXCEPTION("Invalid SNACC::AttCertVersion");
		issuer = snacc.toBeSigned.issuer;

		// Set the signature algorithm ID amd serial number
		signature = snacc.toBeSigned.signature;
		serialNum = snacc.toBeSigned.serialNumber;

		// Set the validity period
		validity = snacc.toBeSigned.attrCertValidityPeriod;

		// Set the attribute list
		attribs = snacc.toBeSigned.attributes;

		// Set the issuer unique identifier, if present
		if (snacc.toBeSigned.issuerUniqueID == NULL)
			pIssuerUniqueID = NULL;
		else
		{
			pIssuerUniqueID =
				new SNACC::UniqueIdentifier(*snacc.toBeSigned.issuerUniqueID);
			if (pIssuerUniqueID == NULL)
				throw MEMORY_EXCEPTION;
		}

		// Set the extensions if present
		if (snacc.toBeSigned.extensions != NULL)
			exts = *snacc.toBeSigned.extensions;

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


AttributeCert& AttributeCert::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


AttributeCert& AttributeCert::operator=(const AttributeCert& other)
{
	if (this != &other)
	{
		try {
			Clear();

			version = other.version;
			m_versionPresent = other.m_versionPresent;
			holder = other.holder;
			issuer = other.issuer;
			signature = other.signature;
			serialNum = other.serialNum;
			validity = other.validity;
			attribs = other.attribs;
			if (other.pIssuerUniqueID != NULL)
			{
				pIssuerUniqueID =
					new SNACC::UniqueIdentifier(*other.pIssuerUniqueID);
				if (pIssuerUniqueID == NULL)
					throw MEMORY_EXCEPTION;
			}
			exts = other.exts;
			algorithm = other.algorithm;
			sigValue = other.sigValue;
		}
		catch (...) {
			Clear();
			throw;
		}
	}
	return *this;
}


void AttributeCert::Clear()
{
	version = SNACC::AttCertVersion::v2;
	m_versionPresent = false;
	holder.Clear();
	issuer.Clear();
	signature.Clear();
	serialNum = 0;;
	attribs.clear();
	if (pIssuerUniqueID != NULL)
	{
		delete pIssuerUniqueID;
		pIssuerUniqueID = NULL;
	}
	exts.Clear();
	algorithm.Clear();
	sigValue.Clear();
}


ulong AttributeCert::Decode(const Bytes& asn)
{
	// Delete existing values in member variables
	Clear();

	// Decode the attribute cert
	SNACC::AttributeCertificate ac;
	SNACC::AsnLen nBytesDecoded = asn.Decode(ac, "SNACC::AttributeCertificate");

	// Assign this attribute cert to the newly decoded attribute cert
	operator=(ac);

	return nBytesDecoded;
}


ulong AttributeCert::Encode(Bytes& asn) const
{
	// Get the SNACC form of this attribute certificate
	SNACC::AttributeCertificate* pAC = GetSnacc();
		
	try {
		// Encode the attribute certificate
		ulong numEncoded = asn.Encode(*pAC, "SNACC::AttributeCertificate");

		// Delete the temporary variable
		delete pAC;
		
		return numEncoded;
	}
	catch (...) {
		delete pAC;
		throw;
	}
}


SNACC::AttributeCertificate* AttributeCert::GetSnacc() const
{
	SNACC::AttributeCertificate* pACert = NULL;
	try {
		// Create the new SNACC attribute certificate
		pACert = new SNACC::AttributeCertificate;
		if (pACert == NULL)
			throw MEMORY_EXCEPTION;
		
		// Initialize the pointers
		pACert->toBeSigned.version = NULL;
		pACert->toBeSigned.issuerUniqueID = NULL;
		pACert->toBeSigned.extensions = NULL;

		// Get the SNACC form of the version (if necessary)
		if (m_versionPresent || (version != SNACC::AttCertVersion::v1))
		{
			pACert->toBeSigned.version = new SNACC::AttCertVersion(version);
			if (pACert->toBeSigned.version == NULL)
				throw MEMORY_EXCEPTION;
		}

		bool isV2 = (version == SNACC::AttCertVersion::v2);

		// Fill in the SNACC form of the holder and issuer fields
		holder.FillSnacc(pACert->toBeSigned.eitherHolder, isV2);
		issuer.FillSnacc(pACert->toBeSigned.issuer, isV2);
		
		// Fill in the SNACC form of the signature AlgID
		signature.FillSnacc(pACert->toBeSigned.signature);
		
		// Set the SNACC serial number
		pACert->toBeSigned.serialNumber = serialNum;
		// Fill in the SNACC form of the validity period
		validity.FillAttCertValidity(pACert->toBeSigned.attrCertValidityPeriod);
		
        // Get the SNACC form of the attributes
        attribs.FillSnaccList(pACert->toBeSigned.attributes);

		// Copy the issuer unique identifier if present
		if (pIssuerUniqueID != NULL)
		{
			pACert->toBeSigned.issuerUniqueID = 
				new SNACC::UniqueIdentifier(*pIssuerUniqueID);
			if (pACert->toBeSigned.issuerUniqueID == NULL)
				throw MEMORY_EXCEPTION;
		}
		
		// Get the SNACC form of the extensions
		pACert->toBeSigned.extensions = exts.GetSnacc();
		
		// Fill in the SNACC form of the outer signature AlgID and value
		algorithm.FillSnacc(pACert->algorithm);
		pACert->signature.Set(sigValue.GetData(), sigValue.BitLen());
		
		// Return result
		return pACert;
	}
	catch (...) {
		if (pACert != NULL)
			delete pACert;
		throw;
	}
}


//////////////////////////////////////////////////////
// ACBasicConstraintsExtension class implementation //
//////////////////////////////////////////////////////
ACBasicConstraintsExtension::ACBasicConstraintsExtension() :
Extension(SNACC::id_ce_basicAttConstraints)
{
	authority = false;
	m_authFlagPresent = false;
	pathLen = -1;
}


ACBasicConstraintsExtension::ACBasicConstraintsExtension(const SNACC::BasicAttConstraintsSyntax& snacc,
														 const SNACC::AsnBool* pCriticalFlag) :
Extension(SNACC::id_ce_basicAttConstraints, pCriticalFlag)
{
	pathLen = -1;
	operator=(snacc);
}


ACBasicConstraintsExtension::ACBasicConstraintsExtension(const ACBasicConstraintsExtension& that) :
Extension(that)
{
	pathLen = -1;
	operator=(that);
}


ACBasicConstraintsExtension& ACBasicConstraintsExtension::operator=(const SNACC::BasicAttConstraintsSyntax& snacc)
{
	pathLen = -1;
	if (snacc.authority == NULL)
	{
		authority = false;
		m_authFlagPresent = false;
	}
	else
	{
		authority = bool(*snacc.authority);
		m_authFlagPresent = true;
	}

	if (snacc.pathLenConstraint != NULL)
	{
		try {
			pathLen = SNACC::AsnInt(*snacc.pathLenConstraint);
		}
		catch (SNACC::SnaccException& ) {
			throw ASN_EXCEPTION("SNACC::ACBasicConstraintsExtension::pathLenConstraint must be >= 0");
		}
	}
	return *this;
}


ACBasicConstraintsExtension& ACBasicConstraintsExtension::operator=(const ACBasicConstraintsExtension& other)
{
	if (pathLen != -1)
		pathLen = -1;

	authority = other.authority;
	m_authFlagPresent = other.m_authFlagPresent;
	if (other.pathLen != -1)
	{
		pathLen = other.pathLen;
	}
	return *this;
}


bool ACBasicConstraintsExtension::operator==(const ACBasicConstraintsExtension& rhs) const
{
	if (this == &rhs)
		return true;

	if (critical != rhs.critical)
		return false;

	if (authority != rhs.authority)
		return false;
	if ((pathLen == -1) && (rhs.pathLen == -1))
		return true;
	else if ((pathLen == -1) || (rhs.pathLen == -1))
		return false;

	return (pathLen == rhs.pathLen);
}


SNACC::AsnType* ACBasicConstraintsExtension::GetSnaccValue() const
{
	SNACC::BasicAttConstraintsSyntax* result = NULL;
	try {
		result = new SNACC::BasicAttConstraintsSyntax();
		if (result == NULL)
			throw MEMORY_EXCEPTION;

		if (authority || m_authFlagPresent)
		{
			result->authority = new SNACC::AsnBool(authority);
			if (result->authority == NULL)
				throw MEMORY_EXCEPTION;
		}
		if (pathLen != -1)
		{
			result->pathLenConstraint->Set(pathLen); // = pathLen;
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


/////////////////////////////////////////////////////
// ACNameConstraintsExtension class implementation //
/////////////////////////////////////////////////////
ACNameConstraintsExtension::ACNameConstraintsExtension() :
NameConstraintsExtension(SNACC::id_ce_delegatedNameConstraints)
{
}


ACNameConstraintsExtension::ACNameConstraintsExtension(const SNACC::NameConstraintsSyntax& snacc,
													   const SNACC::AsnBool* pCriticalFlag) :
NameConstraintsExtension(SNACC::id_ce_delegatedNameConstraints, snacc, pCriticalFlag)
{
}


ACNameConstraintsExtension& ACNameConstraintsExtension::operator=(const SNACC::NameConstraintsSyntax& snacc)
{
	NameConstraintsExtension::operator=(snacc);
	return *this;
}


bool ACNameConstraintsExtension::operator==(const ACNameConstraintsExtension& rhs) const
{
	return NameConstraintsExtension::operator==(rhs);
}


///////////////////////////////////
// ACHolder class implementation //
///////////////////////////////////
ACHolder::ACHolder()
{
	pBaseCertID = NULL;
	pObjInfo = NULL;
}


ACHolder::ACHolder(const SNACC::AttributeCertificateInfoChoice& eitherHolder)
{
	pBaseCertID = NULL;
	pObjInfo = NULL;
	operator=(eitherHolder);
}


ACHolder::ACHolder(const ACHolder& that)
{
	pBaseCertID = NULL;
	pObjInfo = NULL;
	operator=(that);
}


ACHolder& ACHolder::operator=(const SNACC::AttributeCertificateInfoChoice& eitherHolder)
{
	Clear();

	try {
		switch (eitherHolder.choiceId)
		{
		case SNACC::AttributeCertificateInfoChoice::holderCid:
			if (eitherHolder.holder == NULL)
				throw ASN_EXCEPTION("SNACC::AttributeCertificateInfoChoice::holder is NULL");
			
			if (eitherHolder.holder->baseCertificateID != NULL)
			{
				pBaseCertID =
					new IssuerSerial(*eitherHolder.holder->baseCertificateID);
				if (pBaseCertID == NULL)
					throw MEMORY_EXCEPTION;
			}

			if (eitherHolder.holder->entityName != NULL)
				entityName = *eitherHolder.holder->entityName;

			if (eitherHolder.holder->objectDigestInfo != NULL)
			{
				pObjInfo = new ObjectDigestInfo(*eitherHolder.holder->
					objectDigestInfo);
				if (pObjInfo == NULL)
					throw MEMORY_EXCEPTION;
			}

			break;

		case SNACC::AttributeCertificateInfoChoice::baseCertificateIDCid:
			if (eitherHolder.baseCertificateID == NULL)
				throw ASN_EXCEPTION("SNACC::AttributeCertificateInfoChoice::baseCertificateID is NULL");
			pBaseCertID = new IssuerSerial(*eitherHolder.baseCertificateID);
			if (pBaseCertID == NULL)
				throw MEMORY_EXCEPTION;
			break;

		case SNACC::AttributeCertificateInfoChoice::subjectNameCid:
			if (eitherHolder.subjectName == NULL)
				throw ASN_EXCEPTION("SNACC::AttributeCertificateInfoChoice::subjectName is NULL");
			entityName = *eitherHolder.subjectName;
			break;

		default:
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::AttributeCertificateInfoChoice");
		}

		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


ACHolder& ACHolder::operator=(const ACHolder& other)
{
	if (this != &other)
	{
		Clear();
		
		try {
			if (other.pBaseCertID != NULL)
			{
				pBaseCertID = new IssuerSerial(*other.pBaseCertID);
				if (pBaseCertID == NULL)
					throw MEMORY_EXCEPTION;
			}

			entityName = other.entityName;

			if (other.pObjInfo != NULL)
			{
				pObjInfo = new ObjectDigestInfo(*other.pObjInfo);
				if (pObjInfo == NULL)
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


void ACHolder::Clear()
{
	if (pBaseCertID != NULL)
	{
		delete pBaseCertID;
		pBaseCertID = NULL;
	}

	entityName.clear();

	if (pObjInfo != NULL)
	{
		delete pObjInfo;
		pObjInfo = NULL;
	}
}


void ACHolder::FillSnacc(SNACC::AttributeCertificateInfoChoice& snacc,
						 bool useV2) const
{
	if (!useV2)		// v1 attribute certificate
	{
		// Check that the member variables are valid
		if ((pObjInfo != NULL) ||
			((pBaseCertID != NULL) && !entityName.empty()))
			throw ASN_EXCEPTION("Invalid SNACC::Holder contents for a v1 attribute cert");

		if (pBaseCertID != NULL)
		{
			snacc.choiceId =
				SNACC::AttributeCertificateInfoChoice::baseCertificateIDCid;
			snacc.baseCertificateID = pBaseCertID->GetSnacc();
		}
		else
		{
			snacc.choiceId =
				SNACC::AttributeCertificateInfoChoice::subjectNameCid;
			snacc.subjectName = entityName.GetSnacc();
		}
	}
	else	// v2 attribute certificate
	{
		snacc.choiceId = SNACC::AttributeCertificateInfoChoice::holderCid;
		snacc.holder = new SNACC::Holder;
		if (snacc.holder == NULL)
			throw MEMORY_EXCEPTION;

		if (pBaseCertID != NULL)
			snacc.holder->baseCertificateID = pBaseCertID->GetSnacc();

		if (!entityName.empty())
			snacc.holder->entityName = entityName.GetSnacc();

		if (pObjInfo != NULL)
			snacc.holder->objectDigestInfo = pObjInfo->GetSnacc();
	}
}


///////////////////////////////////
// ACIssuer class implementation //
///////////////////////////////////
ACIssuer::ACIssuer()
{
	pBaseCertID = NULL;
	pObjInfo = NULL;
}


ACIssuer::ACIssuer(const SNACC::AttCertIssuer& snacc)
{
	pBaseCertID = NULL;
	pObjInfo = NULL;
	operator=(snacc);
}


ACIssuer::ACIssuer(const ACIssuer& that)
{
	pBaseCertID = NULL;
	pObjInfo = NULL;
	operator=(that);
}


ACIssuer& ACIssuer::operator=(const SNACC::AttCertIssuer& snacc)
{
	Clear();

	try {
		switch (snacc.choiceId)
		{
		case SNACC::AttCertIssuer::v1FormCid:
			if (snacc.v1Form == NULL)
				throw ASN_EXCEPTION("SNACC::AttCertIssuer::v1Form is NULL");
			issuerName = *snacc.v1Form;
			break;

		case SNACC::AttCertIssuer::v2FormCid:
			if (snacc.v2Form == NULL)
				throw ASN_EXCEPTION("SNACC::AttCertIssuer::v2Form is NULL");

			if (snacc.v2Form->issuerName != NULL)
				issuerName = *snacc.v2Form->issuerName;

			if (snacc.v2Form->baseCertificateID != NULL)
			{
				pBaseCertID = 
					new IssuerSerial(*snacc.v2Form->baseCertificateID);
				if (pBaseCertID == NULL)
					throw MEMORY_EXCEPTION;
			}

			if (snacc.v2Form->objectDigestInfo != NULL)
			{
				pObjInfo = new ObjectDigestInfo(*snacc.v2Form->objectDigestInfo);
				if (pObjInfo == NULL)
					throw MEMORY_EXCEPTION;
			}
			break;

		default:
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::AttCertIssuer");
		}

		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


ACIssuer& ACIssuer::operator=(const ACIssuer& other)
{
	if (this != &other)
	{
		Clear();
		
		try {
			issuerName = other.issuerName;
			
			if (other.pBaseCertID != NULL)
			{
				pBaseCertID = new IssuerSerial(*other.pBaseCertID);
				if (pBaseCertID == NULL)
					throw MEMORY_EXCEPTION;
			}

			if (other.pObjInfo != NULL)
			{
				pObjInfo = new ObjectDigestInfo(*other.pObjInfo);
				if (pObjInfo == NULL)
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


void ACIssuer::Clear()
{
	issuerName.clear();

	if (pBaseCertID != NULL)
	{
		delete pBaseCertID;
		pBaseCertID = NULL;
	}

	if (pObjInfo != NULL)
	{
		delete pObjInfo;
		pObjInfo = NULL;
	}
}


void ACIssuer::FillSnacc(SNACC::AttCertIssuer& snacc, bool useV2) const
{
	if (!useV2)		// v1 attribute certificate
	{
		// Check that the issuerName is present
		if (issuerName.empty())
			throw ASN_EXCEPTION("ACIssuer issuerName field must be present in a v1 attribute cert");
		
		snacc.choiceId = SNACC::AttCertIssuer::v1FormCid;
		snacc.v1Form = issuerName.GetSnacc();
	}
	else			// v2 attribute certificate
	{
		// Check that at least one component is present
		if (issuerName.empty() && (pBaseCertID == NULL) && (pObjInfo == NULL))
			throw ASN_EXCEPTION("At least one component of ACIssuer must be present");
		
		snacc.choiceId = SNACC::AttCertIssuer::v2FormCid;
		snacc.v2Form = new SNACC::AttCertIssuerV2;
		if (snacc.v2Form == NULL)
			throw MEMORY_EXCEPTION;
		
		if (!issuerName.empty())
			snacc.v2Form->issuerName = issuerName.GetSnacc();
		
		if (pBaseCertID != NULL)
			snacc.v2Form->baseCertificateID = pBaseCertID->GetSnacc();
		
		if (pObjInfo != NULL)
			snacc.v2Form->objectDigestInfo = pObjInfo->GetSnacc();
	}
}


///////////////////////////////////////
// IssuerSerial class implementation //
///////////////////////////////////////
IssuerSerial::IssuerSerial(const SNACC::IssuerSerial& snacc)
{
	pIssuerUID = NULL;
	operator=(snacc);
}


IssuerSerial::IssuerSerial(const IssuerSerial& that)
{
	pIssuerUID = NULL;
	operator=(that);
}


IssuerSerial& IssuerSerial::operator=(const SNACC::IssuerSerial& snacc)
{
	if (pIssuerUID != NULL)
	{
		delete pIssuerUID;
		pIssuerUID = NULL;
	}

	issuer = snacc.issuer;
	serialNum = snacc.serial;
	if (snacc.issuerUID != NULL)
	{
		pIssuerUID = new SNACC::UniqueIdentifier(*snacc.issuerUID);
		if (pIssuerUID == NULL)
			throw MEMORY_EXCEPTION;
	}

	return *this;
}


IssuerSerial& IssuerSerial::operator=(const IssuerSerial& that)
{
	if (this != &that)
	{
		if (pIssuerUID != NULL)
		{
			delete pIssuerUID;
			pIssuerUID = NULL;
		}
		
		issuer = that.issuer;
		serialNum = that.serialNum;
		if (that.pIssuerUID != NULL)
		{
			pIssuerUID = new SNACC::UniqueIdentifier(*that.pIssuerUID);
			if (pIssuerUID == NULL)
				throw MEMORY_EXCEPTION;
		}
	}
	return *this;
}


SNACC::IssuerSerial* IssuerSerial::GetSnacc() const
{
	SNACC::IssuerSerial* result = new SNACC::IssuerSerial;
	if (result == NULL)
		throw MEMORY_EXCEPTION;

	try {
		issuer.FillSnacc(result->issuer);
		result->serial = serialNum;
		if (pIssuerUID == NULL)
			result->issuerUID = NULL;
		else
		{
			result->issuerUID = new SNACC::UniqueIdentifier(*pIssuerUID);
			if (result->issuerUID == NULL)
				throw MEMORY_EXCEPTION;
		}

		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


///////////////////////////////////////////
// ObjectDigestInfo class implementation //
///////////////////////////////////////////
ObjectDigestInfo::ObjectDigestInfo(const SNACC::ObjectDigestInfo& snacc)
{
	pOtherObjType = NULL;
	operator=(snacc);
}


ObjectDigestInfo::ObjectDigestInfo(const ObjectDigestInfo& that)
{
	pOtherObjType = NULL;
	operator=(that);
}


ObjectDigestInfo& ObjectDigestInfo::operator=(const SNACC::ObjectDigestInfo& snacc)
{
	if (pOtherObjType != NULL)
	{
		delete pOtherObjType;
		pOtherObjType = NULL;
	}

	objType = snacc.digestedObjectType;
	digestAlg = snacc.digestAlgorithm;
	digest = snacc.objectDigest;

	if (snacc.otherObjectTypeID != NULL)
	{
		pOtherObjType = new SNACC::AsnOid(*snacc.otherObjectTypeID);
		if (pOtherObjType == NULL)
			throw MEMORY_EXCEPTION;
	}

	return *this;
}


ObjectDigestInfo& ObjectDigestInfo::operator=(const ObjectDigestInfo& that)
{
	if (this != &that)
	{
		if (pOtherObjType != NULL)
		{
			delete pOtherObjType;
			pOtherObjType = NULL;
		}

		objType = that.objType;
		digestAlg = that.digestAlg;
		digest = that.digest;

		if (that.pOtherObjType != NULL)
		{
			pOtherObjType = new SNACC::AsnOid(*that.pOtherObjType);
			if (pOtherObjType == NULL)
				throw MEMORY_EXCEPTION;
		}
	}
	return *this;
}


SNACC::ObjectDigestInfo* ObjectDigestInfo::GetSnacc() const
{
	SNACC::ObjectDigestInfo* result = new SNACC::ObjectDigestInfo;
	if (result == NULL)
		throw MEMORY_EXCEPTION;

	try {
		result->digestedObjectType = objType;
		if (pOtherObjType == NULL)
			result->otherObjectTypeID = NULL;
		else
		{
			result->otherObjectTypeID = new SNACC::AsnOid(*pOtherObjType);
			if (result->otherObjectTypeID == NULL)
				throw MEMORY_EXCEPTION;
		}

		digestAlg.FillSnacc(result->digestAlgorithm);
		result->objectDigest.Set(digest.GetData(), digest.BitLen());

		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
}


////////////////////////////////////////
// ClearanceList class implementation //
////////////////////////////////////////
ClearanceList& ClearanceList::operator=(const AsnSetOf<SNACC::AsnAny>& snacc)
{
	clear();

	try {
		// Loop through each of the Clearance values
		AsnSetOf<SNACC::AsnAny>::const_iterator i;
		for (i = snacc.begin(); i != snacc.end(); ++i)
		{
			if (i->ai == NULL)
			{
				// Check that the encoded value is present
				if (i->anyBuf == NULL)
					throw ASN_EXCEPTION("Attribute::values ANY is NULL");

				// Reset the AsnBuf for reading
				i->anyBuf->ResetMode();

				// Decode the Clearance value
				SNACC::OldAndNewClearance snaccClearance;
				SNACC::AsnLen numDecoded;
				if (!snaccClearance.BDecPdu(*i->anyBuf, numDecoded))
					throw ASN_EXCEPTION("Error decoding SNACC::Clearance value");

				// Append the decoded Clearance value to the list
				push_back(snaccClearance);
			}
			else if (i->ai->anyId == SNACC::clearance_ANY_ID)
			{
				// Check that the decoded value is present
				if (i->value == NULL)
					throw ASN_EXCEPTION("Attribute::values ANY is NULL");

				// Append the Clearance value to the list
				push_back(*(SNACC::OldAndNewClearance*)i->value);
			}
			else
				throw ASN_EXCEPTION("Error decoding SNACC::Clearance value");
		}

		return *this;
	}
	catch (...) {
		clear();
		throw;
	}
}


void ClearanceList::FillSnacc(AsnSetOf<SNACC::AsnAny>& snacc) const
{
	try {
		for (const_iterator i = begin(); i != end(); ++i)
		{
			SNACC::AsnAny& newAny = *snacc.append();
			newAny.SetTypeByOid(SNACC::id_at_clearance);
			newAny.value = i->GetSnacc();
			if (newAny.value == NULL)
				throw MEMORY_EXCEPTION;
		}
	}
	catch (...) {
		snacc.clear();
		throw;
	}
}


ClearanceList::const_iterator ClearanceList::Find(const SNACC::AsnOid& secPolicy) const
{
	const_iterator i = begin();
	for ( ; (i != end()) && (i->policyId != secPolicy); ++i)
		;

	return i;
}


ClearanceList::const_iterator ClearanceList::FindNext(const_iterator iPrev,
													  const SNACC::AsnOid& secPolicy) const
{

	if (iPrev != end())
	{
		++iPrev;
		for ( ; (iPrev != end()) && (iPrev->policyId != secPolicy); ++iPrev)
			;
	}
	return iPrev;
}


Ca_const* ClearanceList::GetCAClearanceList() const
{
	Ca_const* pResult = NULL;

	try {
		// For each value...
		const_reverse_iterator iValue = rbegin();
		for ( ; iValue != rend(); ++iValue)
		{
			// Allocate and clear the memory for a new Ca_const link
			Ca_const* pNew = (Ca_const*)calloc(1, sizeof(Ca_const));
			if (pNew == NULL)
				throw MEMORY_EXCEPTION;
			
			// Add this new link to the head of the list
			pNew->next = pResult;
			pResult = pNew;
			
			pNew->ca_type = PRBACINFO;
			
			// Convert the value to the C structure
			pNew->ca_val.prbac_infop = iValue->GetClearanceStruct();
		}

		return pResult;
	}
	catch (...) {
		Internal::FreeCa_const(&pResult);
		throw;
	}
}


////////////////////////////////////
// Clearance class implementation //
////////////////////////////////////
Clearance::Clearance()
{
	// Set the default classification
	classList.Set(6);
	classList.SetBit(SNACC::ClassList::unclassified);
}


Clearance& Clearance::operator=(const SNACC::Clearance& snacc)
{
	// Set the defaults
	classList.Set(6);
	classList.SetBit(SNACC::ClassList::unclassified);
	categories.clear();

	policyId = snacc.policyId;
	if (snacc.classList != NULL)
		classList = *snacc.classList;
	if (snacc.securityCategories != NULL)
	{
		if (snacc.securityCategories->empty())
			throw ASN_EXCEPTION("SNACC::Clearance::securityCategories must contain at least one SecurityCategory");

		categories = *snacc.securityCategories;
	}

	return *this;
}


Clearance& Clearance::operator=(const SNACC::OldAndNewClearance& snacc)
{
	// Set the defaults
	classList.Set(6);
	classList.SetBit(SNACC::ClassList::unclassified);
	categories.clear();

	// Set the policy
	if (snacc.policyId.correct == NULL)
		throw ASN_EXCEPTION("Invalid CHOICE in SNACC::ClearancePolicy");

	if (snacc.policyId.choiceId == SNACC::ClearancePolicy::correctCid)
		policyId = *snacc.policyId.correct;
	else if (snacc.policyId.choiceId == SNACC::ClearancePolicy::oldCid)
		policyId = *snacc.policyId.old;
	else
		throw ASN_EXCEPTION("Invalid CHOICE in SNACC::ClearancePolicy");

	// Set the classification if present
	if (snacc.classList != NULL)
	{
		if (snacc.classList->correct == NULL)
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::Classification");
		if (snacc.classList->choiceId == SNACC::Classification::correctCid)
			classList = *snacc.classList->correct;
		else if (snacc.classList->choiceId == SNACC::Classification::oldCid)
			classList = *snacc.classList->old;
		else
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::Classification");
	}

	// Set the security categories if present
	if (snacc.securityCategories != NULL)
	{
		if (snacc.securityCategories->correct == NULL)
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::ClearanceCategories");
		if (snacc.securityCategories->choiceId ==
			SNACC::ClearanceCategories::correctCid)
			categories = *snacc.securityCategories->correct;
		else if (snacc.securityCategories->choiceId ==
			SNACC::ClearanceCategories::oldCid)
			categories = *snacc.securityCategories->old;
		else
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::ClearanceCategories");
	}

	return *this;
}


void Clearance::FillSnaccClearance(SNACC::Clearance& snacc) const
{
	// Clear any existing data
	snacc.Clear();

	snacc.policyId = policyId;

	snacc.classList = new SNACC::ClassList(classList);
	if (snacc.classList == NULL)
		throw MEMORY_EXCEPTION;

	if (!categories.empty())
	{
		snacc.securityCategories = new SNACC::SecurityCategorySet(categories);
		if (snacc.securityCategories == NULL)
			throw MEMORY_EXCEPTION;
	}
}


SNACC::Clearance* Clearance::GetSnacc() const
{
	SNACC::Clearance* pResult = new SNACC::Clearance;
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		FillSnaccClearance(*pResult);
	}
	catch (...) {
		delete pResult;
		throw;
	}

	return pResult;
}


Clearance_struct* Clearance::GetClearanceStruct() const
{
	Clearance_struct* result = (Clearance_struct*)
		calloc(1, sizeof(Clearance_struct));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		// Convert the policyId field
		result->policyID = policyId.GetChar();
		
		// Convert the classList field
		result->classList = Internal::CvtBitsToBytes(classList);
		
		// Convert the securityCategories field
		SNACC::SecurityCategorySet::const_reverse_iterator i;
		for (i = categories.rbegin(); i != categories.rend(); ++i)
		{
			SecCat_LL* pNew = cvtSecurityCategory(*i);
				
			// Add this security category to the head of the list
			pNew->next = result->categories;
			result->categories = pNew;
		}

		return result;
	}
	catch (...) {
		Internal::FreeClearance(&result);
		throw;
	}
}


////////////////////////
// Internal Functions //
////////////////////////
Sec_tags* cvtSecTagsList(const SNACC::SecurityTagPrivileges& snacc)
{
	Sec_tags* result = NULL;
	
	try {
		SNACC::SecurityTagPrivileges::const_reverse_iterator i;
		for (i = snacc.rbegin(); i != snacc.rend(); ++i)
		{
			// Allocate and clear the memory for the new Sec_tags
			Sec_tags* pNew = (Sec_tags*)calloc(1, sizeof(Sec_tags));
			if (pNew == NULL)
				throw MEMORY_EXCEPTION;
			
			// Add this new link to the head of the list
			pNew->next = result;
			result = pNew;
			
			// Convert the tag depending on its type
			switch (i->choiceId)
			{
			case SNACC::SecurityTagPrivilege::restrictivebitMapCid:
				pNew->tagType = 1;
				if (i->restrictivebitMap == NULL)
					throw ASN_EXCEPTION("SNACC::SecurityTagPrivilege::restrictivebitMap field is NULL");
				pNew->values.bitFlags =
					Internal::CvtBitsToBytes(*i->restrictivebitMap);
				break;
				
			case SNACC::SecurityTagPrivilege::enumeratedAttributesCid:
				pNew->tagType = 2;
				if (i->enumeratedAttributes == NULL)
					throw ASN_EXCEPTION("SNACC::SecurityTagPrivilege::enumeratedAttributes field is NULL");
				pNew->values.intFlags =
					Internal::CvtLongArray(*(SNACC::SigPrivFlagsSeqOf*)
					i->enumeratedAttributes);
				break;
				
			case SNACC::SecurityTagPrivilege::permissivebitMapCid:
				pNew->tagType = 6;
				if (i->permissivebitMap == NULL)
					throw ASN_EXCEPTION("SNACC::SecurityTagPrivilege::permissivebitMap field is NULL");
				pNew->values.bitFlags =
					Internal::CvtBitsToBytes(*i->permissivebitMap);
				break;
				
			default:
				throw ASN_EXCEPTION("Invalid CHOICE in SNACC::SecurityTagPrivilege");
			}
		} // end of for loop
		
		return result;
	}
	catch (...) {
		Internal::FreeSectags(&result);
		throw;
	}
} // end of cvtSecTagsList()


SecCat_LL* cvtSecurityCategory(const SNACC::SecurityCategory& snacc)
{
	// Allocate and clear the memory for the result
	SecCat_LL* result = (SecCat_LL*)calloc(1, sizeof(SecCat_LL));
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	
	try {
		result->oid = snacc.type.GetChar();
		
		if (snacc.type == SNACC::id_sslPrivileges)
		{
			result->type = SecCat_LL::PRBAC_TYPE;
			
			if ((snacc.value.ai == NULL) ||
				(snacc.value.ai->anyId != SNACC::sslPrivileges_ANY_ID))
				throw ASN_EXCEPTION("Error decoding SNACC::SSLPrivileges");
			
			if (snacc.value.value == NULL)
				throw ASN_EXCEPTION("SNACC::SecurityCategory::value field is NULL");
		
			const SNACC::SSLPrivileges& snaccSSL =
				*(SNACC::SSLPrivileges*)snacc.value.value;
			SNACC::SSLPrivileges::const_reverse_iterator i;
			for (i = snaccSSL.rbegin(); i != snaccSSL.rend(); ++i)
			{
				// Allocate and clear the memory for a new Ssl_privs
				Ssl_privs* pNew = (Ssl_privs*)calloc(1, sizeof(Ssl_privs));
				if (pNew == NULL)
					throw MEMORY_EXCEPTION;
				
				// Add this new link to the head of the list
				pNew->next = result->value.prbac;
				result->value.prbac = pNew;
				
				// Convert the TagSetName OID
				pNew->tagSetName = i->tagSetName.GetChar();
				
				// Convert the securityTagPrivileges
				pNew->tagSetPrivs = cvtSecTagsList(i->securityTagPrivileges);
			}
		}
		else
		{
			result->type = SecCat_LL::OTHER_TYPE;
			
			if (snacc.value.ai == NULL)
			{
				if (snacc.value.anyBuf == NULL)
					throw ASN_EXCEPTION("SNACC::SecurityCategory::anyBuf field is NULL");
		
				result->value.other =
					Internal::CvtAsnBufToBytes(*snacc.value.anyBuf);
			}
			else  // Re-encode this known value
			{
				if (snacc.value.anyBuf == NULL)
					throw ASN_EXCEPTION("SNACC::SecurityCategory::value field is NULL");

				SNACC::AsnBuf asnBuf;
				SNACC::AsnLen numEnc;
				if (!snacc.value.value->BEncPdu(asnBuf, numEnc))
					throw ASN_EXCEPTION("Error encoding SNACC::SecurityCategory value");

				result->value.other = Internal::CvtAsnBufToBytes(asnBuf);
			}
		}
		return result;
	}
	catch (...) {
		Internal::FreeSecCategories(&result);
		throw;
	}
} // end of cvtSecurityCategory()



// end of CM_Attribcert.cpp
