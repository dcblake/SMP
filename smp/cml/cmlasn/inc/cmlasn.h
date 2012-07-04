/****************************************************************************
File:     cmlasn.h
Project:  Certificate Management ASN.1 Library
Contents: Header file for the X.509 Certificate Management ASN.1 Library

Created:  6 September 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	14 February 2004

Version:  2.4

*****************************************************************************/
#ifndef _CMLASN_H
#define _CMLASN_H


////////////////////
// Included Files //
////////////////////
#ifdef _MSC_VER
	#pragma warning(disable: 4710)	// Disable function not inlined warning
	#pragma warning(push, 3)		// Save warning level and set level to 3
	#pragma warning(disable: 4018)	// Disable '<' (un)/signed mismatch warning
	#include <vector>
	#pragma warning(pop)			// Restore warning level
#else
	#include <vector>
#endif

#ifdef WIN32
	#pragma warning(push, 3)		// Set warning level to 3 for windows.h
	#include <windows.h>			// Needed for mutex
	#pragma warning(pop)			// Restore warning level
#else
	#ifndef NOTHREADS
		#include <pthread.h>		// Needed for mutex
	#endif
#endif

#include "cmlasn_c.h"
#include "cmlasn_threads.h"
#include "cmlasn_exts.h"


// Begin CML namespace
namespace CML {


/////////////////////////
// Function Prototypes //
/////////////////////////
CM_API_FN(char*) ParseHostFromURL(const char* url);
CM_API_FN(const char*) striEnd(const char* string1, const char* string2);
CM_API_FN(const char*) strtok_r(const char* strToken, ulong& len,
								const char* strDelimit);


// Begin nested ASN namespace
namespace ASN {



//////////////////////
// Type Definitions //
//////////////////////
enum CertType
{
	UnknownCert,
	EndEntityCert,
	CACert
};


///////////////////////////////
// Validity class definition //
///////////////////////////////
class CM_API Validity
{
public:
	// Construct a period from now until numYears from now
	Validity(ushort numYears = 1);
	// Construct from a SNACC Validity
	Validity(const SNACC::Validity& snacc);
	// Construct from a SNACC AttCertValidityPeriod
	Validity(const SNACC::AttCertValidityPeriod& snacc);
	// Construct from two Time objects
	Validity(const Time& begin, const Time& end);

	// Comparison operators
	bool operator==(const Validity& rhs) const;
	bool operator!=(const Validity& rhs) const		{ return !operator==(rhs); }

	// Fill in the SNACC form of Validity
	void FillSnacc(SNACC::Validity& snacc) const;
	// Fill in the SNACC form of the attribute cert validity period
	void FillAttCertValidity(SNACC::AttCertValidityPeriod& snacc) const;
	// Return true if the current time is within the validity period
	bool IsValid() const;
	// Return true if the specified time is within the validity period
	bool IsValid(const Time& time) const;

	// Member variables
	Time notBefore;
	Time notAfter;
};


////////////////////////////////////
// PublicKeyInfo class definition //
////////////////////////////////////
class CM_API PublicKeyInfo
{
public:
	// Default constructor
	PublicKeyInfo()												{}
	// Constructor to create from a SNACC SubjectPublicKeyInfo
	PublicKeyInfo(const SNACC::SubjectPublicKeyInfo& snaccPK)	{ operator=(snaccPK); }

	// Assignment operators
	PublicKeyInfo& operator=(const SNACC::SubjectPublicKeyInfo& snaccPK);	// Assign from a SNACC SubjectPublicKeyInfo

	// Comparison operators
	bool operator==(const PublicKeyInfo& rhs) const;
	bool operator==(const SNACC::AsnOid& oid) const		{ return (algorithm == oid); }
	bool operator==(const char* stringOid) const		{ return (algorithm == stringOid); }
	bool operator!=(const PublicKeyInfo& rhs) const		{ return !operator==(rhs); }
	bool operator!=(const SNACC::AsnOid& oid) const		{ return (algorithm != oid); }
	bool operator!=(const char* stringOid) const		{ return (algorithm != stringOid); }

	// Clear the contents of this PublicKeyInfo
	void Clear();
	// Fill in the SNACC SubjectPublicKeyInfo
	void FillSnacc(SNACC::SubjectPublicKeyInfo& snacc) const;
	// Fill in the C form of the SubjectPublicKeyInfo
	void FillPubKeyStruct(Pub_key_struct& pubKey) const;
	// Get the C form of the SubjectPublicKeyInfo
	Pub_key_struct* GetPubKeyStruct() const;

	// Member variables
	AlgID algorithm;
	Bytes key;					// ASN.1 encoded public key
};


/////////////////////////////////////
// CertExtensions class definition //
/////////////////////////////////////
class CM_API CertExtensions
{
public:
	// Default constructor
	CertExtensions();
	// Construct from SNACC Extensions
	CertExtensions(const SNACC::Extensions& snacc);
	// Copy constructor
	CertExtensions(const CertExtensions& that);
	// Destructor
	virtual ~CertExtensions()							{ Clear(); }

	// Assignment operators
	CertExtensions& operator=(const SNACC::Extensions& snacc);	// Assign from SNACC extensions
	CertExtensions& operator=(const CertExtensions& other);		// Assign from another CertExtensions

	// Clear the contents of these extensions
	void Clear();
	// Get the SNACC form of these cert extensions
	SNACC::Extensions* GetSnacc() const;
	// Get the C form of these cert extensions
	Cert_exts_struct* GetCertExtsStruct() const;

	// Member variables
	SubjKeyIdExtension* pSubjKeyID;
	AuthKeyIdExtension* pAuthKeyID;
	KeyUsageExtension* pKeyUsage;
	ExtKeyUsageExtension* pExtKeyUsage;
	PrivKeyUsagePeriodExtension* pPrivKeyPeriod;
	SubjAltNamesExtension* pSubjAltNames;
	IssuerAltNamesExtension* pIssuerAltNames;
	CertPoliciesExtension* pCertPolicies;
	PolicyMappingsExtension* pPolicyMaps;
	BasicConstraintsExtension* pBasicCons;
	NameConstraintsExtension* pNameCons;
	PolicyConstraintsExtension* pPolicyCons;
	InhibitAnyPolicyExtension* pInhibitAnyPolicy;
	CrlDistPointsExtension* pCrlDistPts;
	FreshestCrlExtension* pFreshestCRL;
	SubjDirAttributesExtension* pSubjDirAtts;
	PkixAIAExtension* pAuthInfoAccess;
	PkixSIAExtension* pSubjInfoAccess;
	UnknownExtensions unknownExts;

private:
	bool m_extsPresent;				// Indicates if extensions were present in ASN.1
	std::vector<int> m_origOrder;	// Original order of extensions in ASN.1
};


///////////////////////////
// Cert class definition //
///////////////////////////
class CM_API Cert
{
public:
	// Default constructor
	Cert();
	// Construct from a SNACC certficate
	Cert(const SNACC::Certificate& snacc);
	// Construct from an ASN.1 encoded certificate
	Cert(const Bytes& asn);
	// Copy constructor
	Cert(const Cert& that);
	// Destructor
	virtual ~Cert()							{ Clear(); }

	// Assignment operators
	Cert& operator=(const SNACC::Certificate& snacc);	// Assign from a SNACC certificate
	Cert& operator=(const Bytes& asn);					// Assign from an ASN.1 encoded certificate
	Cert& operator=(const Cert& other);					// Assign from another Cert

	// Clear the member variables
	void Clear();
	// Decode from an ASN.1 encoded certificate
	virtual ulong Decode(const Bytes& asn);
	// Encode this certificate
	virtual ulong Encode(Bytes& asn) const;
	// Returns true if the certificate is self-issued
	bool IsSelfIssued() const;
	// Fill in the SNACC form of this certificate
	void FillSnacc(SNACC::Certificate& snacc) const;
	// Get the SNACC form of this certificate
	SNACC::Certificate* GetSnacc() const;
	// Get the C form of this certificate
	Cert_struct* GetCertStruct() const;

	// Member variables
	int version;								// Version number
	SNACC::AsnInt serialNumber;					// Serial number
	AlgID signature;							// Inner signature algorithm
	DN issuer;									// Issuer's distinguished name
	Validity validity;							// Validity period
	DN subject;									// Subject's distinguished name
	PublicKeyInfo pubKeyInfo;					// Subject public key
	SNACC::UniqueIdentifier* pIssuerUniqueID;	// Issuer's unique identifier
	SNACC::UniqueIdentifier* pSubjectUniqueID;	// Subject's unique identifier
	CertExtensions exts;						// Extensions
	AlgID algorithm;							// Outer signature algorithm
	Bytes sigValue;								// ASN.1 encoded signature value

private:
	bool m_versionPresent;				// Indicates if ASN.1 version was present
};


/////////////////////////////////////////
// CrlEntryExtensions class definition //
/////////////////////////////////////////
class CM_API CrlEntryExtensions
{
public:
	// Default constructor
	CrlEntryExtensions();
	// Construct from SNACC Extensions
	CrlEntryExtensions(const SNACC::Extensions& snacc);
	// Copy constructor
	CrlEntryExtensions(const CrlEntryExtensions& that);
	// Destructor
	virtual ~CrlEntryExtensions()							{ Clear(); }

	// Assignment operators
	CrlEntryExtensions& operator=(const SNACC::Extensions& snacc);		// Assign from SNACC extensions
	CrlEntryExtensions& operator=(const CrlEntryExtensions& other);		// Assign from another CrlEntryExtensions

	// Clear the contents of these extensions
	void Clear();
	// Get the SNACC form of these CRL entry extensions
	SNACC::Extensions* GetSnacc() const;
	// Get the C form of these CRL entry extensions
	CRL_entry_exts_struct* GetCrlEntryExtsStruct() const;

	// Member variables
	StdExtension_T<SNACC::CRLReason>* pReason;
	StdExtension_T<SNACC::HoldInstruction>* pHoldCode;
	StdExtension_T<SNACC::GeneralizedTime>* pInvalidityDate;
	CertIssuerExtension* pCertIssuer;
	UnknownExtensions unknownExts;

private:
	bool m_extsPresent;				// Indicates if extensions were present in ASN.1
	std::vector<int> m_origOrder;	// Original order of extensions in ASN.1
};


///////////////////////////////////
// RevokedEntry class definition //
///////////////////////////////////
class CM_API RevokedEntry
{
public:
	// Default constructor
	RevokedEntry();
	// Construct from a SNACC revocation entry
	RevokedEntry(const SNACC::CertificateListToBeSignedSeqOfSeq& snacc);
	// Construct from a serial number, time, and optional extensions
	RevokedEntry(const SNACC::CertificateSerialNumber& serialNumber,
		const Time& revocationDate, const CrlEntryExtensions* pExts = NULL);
	// Copy constructor
	RevokedEntry(const RevokedEntry& that);
	// Destructor
	virtual ~RevokedEntry()									{ Clear(); }

	// Assign the contents of this entry from another RevokedEntry
	RevokedEntry& operator=(const RevokedEntry& other);

	// Comparison operators
	bool operator==(const RevokedEntry& rhs) const;
	bool operator!=(const RevokedEntry& rhs) const	{ return !operator==(rhs); }
	bool operator<(const RevokedEntry& rhs) const;

	// Clear the contents of this entry
	void Clear();
	// Access the serial number for this entry
	const SNACC::CertificateSerialNumber& SerialNum() const;
	SNACC::CertificateSerialNumber& SerialNum();
	// Access the date/time the certificate was revoked
	const Time& RevTime() const;
	Time& RevTime();
	// Access this entry's extensions
	const CrlEntryExtensions& EntryExts() const;
	CrlEntryExtensions& EntryExts();

	// Fill in the SNACC form of this revocation entry
	void FillSnaccRevEntry(SNACC::CertificateListToBeSignedSeqOfSeq& snacc) const;
	// Get the C form of this revocation entry
	RevCerts_LL* GetRevCertsStruct() const;

private:
	// Member variables
	mutable SNACC::CertificateListToBeSignedSeqOfSeq* m_pSnacc;		// SNACC form
	mutable Time* m_pRevDate;						// Date certificate revoked
	mutable CrlEntryExtensions* m_pExts;			// CRL entry extensions

	// Assign from a SNACC revocation entry pointer (used by Revocations)
	RevokedEntry& operator=(SNACC::CertificateListToBeSignedSeqOfSeq* pSnacc);

	// Returns true if the cert issuer extension is present in this entry
	bool IsCertIssuerExtPresent() const;

	friend class Revocations;
};


//////////////////////////////////
// Revocations class definition //
//////////////////////////////////
class CM_API Revocations : public std::list<RevokedEntry>
{
public:
	// Default constructor
	Revocations()									{ m_revCertsPresent = false; }
	// Construct from a SNACC list of revoked certificates
	Revocations(const SNACC::CertificateListToBeSignedSeqOf& snacc);

	// Assignment operator
	Revocations& operator=(const SNACC::AsnBuf& asnBuf);	// Assign from an ASN.1 encoded list
	Revocations& operator=(const SNACC::CertificateListToBeSignedSeqOf& snacc);	// Assign from a SNACC entry list

	// Clear the list of revoked certificates
	void Clear()						{ clear(); m_revCertsPresent = false; }
	// Get the SNACC form of the revoked certificates
	SNACC::CertificateListToBeSignedSeqOf* GetSnacc() const;
	// Get the C form of the revoked certificates
	RevCerts_LL* GetRevCertsList() const;

	// Returns a const_iterator to the RevokedEntry for the specified cert if
	// it is revoked or end() if not
	const_iterator IsRevoked(const SNACC::CertificateSerialNumber& serialNumber,
		const DN& certIssuer, const DN& crlIssuer,
		const SNACC::OrderedListSyntax* pOrder = NULL) const;

private:
	bool m_revCertsPresent;		// Indicates if revoked certs were present in ASN.1
};


////////////////////////////////////
// CrlExtensions class definition //
////////////////////////////////////
class CM_API CrlExtensions
{
public:
	// Default constructor
	CrlExtensions();
	// Construct from SNACC Extensions
	CrlExtensions(const SNACC::Extensions& snacc);
	// Copy constructor
	CrlExtensions(const CrlExtensions& that);
	// Destructor
	virtual ~CrlExtensions()							{ Clear(); }

	// Assignment operators
	CrlExtensions& operator=(const SNACC::Extensions& snacc);	// Assign from SNACC extensions
	CrlExtensions& operator=(const CrlExtensions& other);		// Assign from another CrlExtensions

	// Clear the contents of these extensions
	void Clear();
	// Get the SNACC form of these CRL extensions
	SNACC::Extensions* GetSnacc() const;
	// Get the C form of these CRL extensions
	CRL_exts_struct* GetCrlExtsStruct() const;

	// Member variables
	AuthKeyIdExtension* pAuthKeyID;
	IssuerAltNamesExtension* pIssuerAltNames;
	IssuingDistPointExtension* pIssuingDP;
	FreshestCrlExtension* pFreshestCRL;
	CRLNumberExtension *pCrlNumber;
	DeltaCRLIndicatorExtension *pDeltaCRL;
	StdExtension_T<SNACC::CRLScopeSyntax>* pCrlScope;
	StdExtension_T<SNACC::StatusReferrals>* pStatusRefs;
	StdExtension_T<SNACC::CRLStreamIdentifier>* pStreamID;
	StdExtension_T<SNACC::OrderedListSyntax>* pOrderedList;
	StdExtension_T<SNACC::DeltaInformation>* pDeltaInfo;
	StdExtension_T<SNACC::GeneralizedTime>* pBaseUpdate;
	UnknownExtensions unknownExts;

private:
	bool m_extsPresent;				// Indicates if extensions were present in ASN.1
	std::vector<int> m_origOrder;	// Original order of extensions in ASN.1
};


//////////////////////////////////////
// CertificateList class definition //
//////////////////////////////////////
class CM_API CertificateList
{
public:
	// Default constructor
	CertificateList();
	// Construct from a SNACC CRL
	CertificateList(const SNACC::CertificateList& snacc);
	// Construct from an ASN.1 encoded CRL
	CertificateList(const Bytes& asn);
	// Copy constructor
	CertificateList(const CertificateList& that);
	// Destructor
	virtual ~CertificateList()							{ Clear(); }

	// Assignment operators
	CertificateList& operator=(const SNACC::CertificateList& snacc);	// Assign from a SNACC CertificateList
	CertificateList& operator=(const Bytes& asn);						// Assign from an ASN.1 encoded CRL
	CertificateList& operator=(const CertificateList& other);			// Assign from another CertificateList

	// Access the list of revoked certificates
	Revocations& GetRevocations();
	const Revocations& GetRevocations() const;
	// Replace this CRL's list of revoked certificates with the supplied list
	void SetRevocations(const Revocations& revCerts);

	// Clear the member variables
	void Clear();
	// Decode from an ASN.1 encoded CRL
	virtual ulong Decode(const Bytes& asn);
	// Encode this CRL
	virtual ulong Encode(Bytes& asn) const;
	// Get the SNACC form of this CRL
	SNACC::CertificateList* GetSnacc() const;
	// Get the C form of this CRL -- optionally include the revocations
	// and extensions in the CRL_struct
	CRL_struct* GetCrlStruct(bool incRevocations = true,
		bool incExtensions = true) const;
	// Returns true if this is a delta CRL
	bool IsDelta() const;
	// Returns true if this CRL matches the specified scope
	bool MatchesScope(CertType certType, const DN& certIssuer,
		const DistributionPoint* pDistPt, bool isCritical,
		const RevocationReasons* pReasons = NULL) const;

	// Member variables
	int version;						// Version number
	AlgID signature;					// Inner signature algorithm
	DN issuer;							// CRL issuer's distinguished name
	Time thisUpdate;					// Time when CRL issued
	Time *nextUpdate;					// Time when next CRL will be issued
	CrlExtensions crlExts;				// Extensions
	AlgID algorithm;					// Outer signature algorithm
	Bytes sigValue;						// ASN.1 encoded signature value

protected:
	GenName GetDistPtName() const;

private:
	bool ExtIsCritical() const;
	ulong DecodeCrlToSign(SNACC::AsnBuf& b, const SNACC::AsnLen& seqLen);

	// Private members
	mutable SNACC::AsnBuf* m_pEncRevs;	// Encoded list of revoked certificates
	mutable Revocations m_revCerts;		// List of revoked certificates
};


///////////////////////////////
// CertPair class definition //
///////////////////////////////
class CM_API CertPair
{
public:
	// Construct from optional forward and reverse certs
	CertPair(const Cert* pForward = NULL, const Cert* pReverse = NULL);
	// Construct from a SNACC CertificatePair
	CertPair(const SNACC::CertificatePair& snacc);
	// Construct from an ASN.1 encoded CertPair
	CertPair(const Bytes& asn);
	// Copy constructor
	CertPair(const CertPair& that);
	// Destructor
	virtual ~CertPair();

	// Assignment operators
	CertPair& operator=(const SNACC::CertificatePair& snacc);	// Assign from a SNACC CertificatePair
	CertPair& operator=(const Bytes& asn);						// Assign from an ASN.1 encoded CertPair
	CertPair& operator=(const CertPair& other);					// Assign from another CertPair

	// Decode from an ASN.1 encoded CertPair
	ulong Decode(const Bytes& asn);
	// Encode this CertPair
	ulong Encode(Bytes& asn) const;
	// Fill in the SNACC form of this CertPair
	void FillSnaccCertPair(SNACC::CertificatePair& snacc) const;
	// Get the SNACC form of this CertPair
	SNACC::CertificatePair* GetSnacc() const;

	// Member variables
	Cert* forward;				// Forward certificate
	Cert* reverse;				// Reverse certificate
};


////////////////////////////////////////
// CertificationPath class definition //
////////////////////////////////////////
class CM_API CertificationPath
{
public:
	// Default constructor
	CertificationPath();
	// Construct from a subject cert
	CertificationPath(const Cert& subject);
	// Construct from a SNACC CertificationPath
	CertificationPath(const SNACC::CertificationPath& snacc);
	// Construct from an ASN.1 encoded CertPath
	CertificationPath(const Bytes& asn);
	// Destructor
	virtual ~CertificationPath()			{}

	// Assignment operators
	CertificationPath& operator=(const SNACC::CertificationPath& snacc);	// Assign from a SNACC CertificationPath
	CertificationPath& operator=(const Bytes& asn);							// Assign from an ASN.1 encoded CertificationPath

	// Decode from an ASN.1 encoded CertificationPath
	virtual ulong Decode(const Bytes& asn);
	// Encode this cert path
	virtual ulong Encode(Bytes& asn) const;
	// Get the SNACC form of this cert path
	SNACC::CertificationPath* GetSnacc() const;
	// Get the C form of this cert path
	Cert_path_LL* GetCertPathList() const;

	// Member variables
	Cert userCert;					// Subject certificate
	std::list<CertPair> caCerts;	// CA certificates

private:
	bool m_caCertsPresent;			// Indicates if caCerts were present in ASN.1
};


////////////////////////////////////////////
// ObjectDigestInfo class definition
//
// Contains the hash of a public-key, 
// public-key certificate, or another object.
// Used to identify a holder or issuer of an
// attribute certificate.
//
class CM_API ObjectDigestInfo
{
public:
	// Default constructor
	ObjectDigestInfo()								{ pOtherObjType = NULL; }
	// Construct from a SNACC ObjectDigestInfo
	ObjectDigestInfo(const SNACC::ObjectDigestInfo& snacc);
	// Copy constructor
	ObjectDigestInfo(const ObjectDigestInfo& that);
	// Destructor
	virtual ~ObjectDigestInfo()						{ delete pOtherObjType; }
	
	// Assignment operators
	// Assign from a SNACC ObjectDigestInfo
	ObjectDigestInfo& operator=(const SNACC::ObjectDigestInfo& snacc);
	// Assign from another ObjectDigestInfo
	ObjectDigestInfo& operator=(const ObjectDigestInfo& that);

	// Get the SNACC form of this ObjectDigestInfo
	SNACC::ObjectDigestInfo* GetSnacc() const;

	// Member variables
	SNACC::ObjectDigestInfoEnum objType;	// Type of object hashed
	SNACC::AsnOid* pOtherObjType;			// Optional identifier of object
	AlgID digestAlg;						// Hash algorithm
	Bytes digest;							// Hash value
};


////////////////////////////////////////////
// IssuerSerial class definition
//
// Contains the identity of a particular
// public-key certificate
//
class CM_API IssuerSerial
{
public:
	// Default constructor
	IssuerSerial()									{ pIssuerUID = NULL; }
	// Construct from a SNACC IssuerSerial
	IssuerSerial(const SNACC::IssuerSerial& snacc);
	// Copy constructor
	IssuerSerial(const IssuerSerial& that);
	// Destructor
	virtual ~IssuerSerial()							{ delete pIssuerUID; }

	// Assignment operators
	// Assign from a SNACC IssuerSerial
	IssuerSerial& operator=(const SNACC::IssuerSerial& snacc);
	// Assign from another IssuerSerial
	IssuerSerial& operator=(const IssuerSerial& that);

	// Get the SNACC form of this IssuerSerial
	SNACC::IssuerSerial* GetSnacc() const;

	// Member variables
	GenNames issuer;						// Name of certificate issuer 
	SNACC::AsnInt serialNum;						// Serial number of cert
	SNACC::UniqueIdentifier* pIssuerUID;	// Issuer's unique ID (optional)
};


////////////////////////////////////////////
// ACHolder class definition
//
// Contains the identity of the holder of
// the attribute certificate
//
class CM_API ACHolder
{
public:
	// Default constructor
	ACHolder();
	// Construct from a SNACC v1 or v2 Holder CHOICE
	ACHolder(const SNACC::AttributeCertificateInfoChoice& eitherHolder);
	// Copy constructor
	ACHolder(const ACHolder& that);
	// Destructor
	virtual ~ACHolder()									{ Clear(); }

	// Assignment operators
	// Assign from a SNACC v1 or v2 Holder CHOICE
	ACHolder& operator=(const SNACC::AttributeCertificateInfoChoice& eitherHolder);
	// Assign from another ACHolder
	ACHolder& operator=(const ACHolder& other);

	// Clear the member variables
	void Clear();
	// Fill in the SNACC form of this holder
	void FillSnacc(SNACC::AttributeCertificateInfoChoice& snacc,
		bool useV2 = true) const;

	// Member variables
	IssuerSerial* pBaseCertID;		// Identifies holder's public-key cert
	GenNames entityName;			// Name of the holder
	ObjectDigestInfo* pObjInfo;		// Info to identify the holder
};


////////////////////////////////////////////
// ACIssuer class definition
//
// Contains the identity of the attribute
// authority that issued the certificate
//
class CM_API ACIssuer
{
public:
	// Default constructor
	ACIssuer();
	// Construct from a SNACC v1 or v2 attribute cert issuer
	ACIssuer(const SNACC::AttCertIssuer& snacc);
	// Copy constructor
	ACIssuer(const ACIssuer& that);
	// Destructor
	virtual ~ACIssuer()									{ Clear(); }

	// Assignment operators
	// Assign from a SNACC v1 or v2 attribute cert issuer
	ACIssuer& operator=(const SNACC::AttCertIssuer& snacc);
	// Assign from another ACIssuer
	ACIssuer& operator=(const ACIssuer& other);

	// Clear the member variables
	void Clear();
	// Fill in the SNACC form of this attribute cert issuer
	void FillSnacc(SNACC::AttCertIssuer& snacc, bool useV2 = true) const;

	// Member variables
	GenNames issuerName;			// Name of the issuer
	IssuerSerial* pBaseCertID;		// Identifies issuer's public-key cert
	ObjectDigestInfo* pObjInfo;		// Info to identify the issuer
};


////////////////////////////////////////////
// ACExtensions class definition
//
// Contains the extensions found in attribute
// certificates
//
class CM_API ACExtensions
{
public:
	// Default constructor
	ACExtensions();
	// Construct from SNACC Extensions
	ACExtensions(const SNACC::Extensions& snacc);
	// Copy constructor
	ACExtensions(const ACExtensions& that);
	// Destructor
	virtual ~ACExtensions()							{ Clear(); }

	// Assignment operators
	ACExtensions& operator=(const SNACC::Extensions& snacc);	// Assign from SNACC extensions
	ACExtensions& operator=(const ACExtensions& other);			// Assign from another ACExtensions

	// Clear the contents of these extensions
	void Clear();
	// Get the SNACC form of these attribute certificate extensions
	SNACC::Extensions* GetSnacc() const;

	// Member variables
	AuthKeyIdExtension* pAuthKeyID;
	StdExtension_T<SNACC::TimeSpecification>* pTimeSpec;
	StdExtension_T<SNACC::TargetingInformation>* pTargetInfo;
	StdExtension_T<SNACC::UserNoticeExtension>* pUserNotice;
	StdExtension_T<SNACC::AcceptableCertPoliciesSyntax>* pPrivPolicies;
	CrlDistPointsExtension* pCrlDistPts;
	StdExtension_T<SNACC::AsnNull>* pRevInfoAvail;
	StdExtension_T<SNACC::AsnNull>* pSOA_Id;
	StdExtension_T<SNACC::AttributeDescriptorSyntax>* pDescriptor;
	StdExtension_T<SNACC::RoleSpecCertIdentifierSyntax>* pRoleSpec;
	ACBasicConstraintsExtension* pBasicCons;
	ACNameConstraintsExtension* pNameCons;
	StdExtension_T<SNACC::AcceptableCertPoliciesSyntax>* pCertPolicies;
	StdExtension_T<SNACC::AuthorityAttributeIdentifierSyntax>* pAA_Id;
	PkixAIAExtension* pAuthInfoAccess;
	StdExtension_T<SNACC::AsnOcts>* pAuditIdentity;
	UnknownExtensions unknownExts;

private:
	bool m_extsPresent;				// Indicates if extensions were present in ASN.1
	std::vector<int> m_origOrder;	// Original order of extensions in ASN.1
};


////////////////////////////////////////////
// AttributeCert class definition
//
// Used for X.509 attribute certificates
//
class CM_API AttributeCert
{
public:
	// Default constructor
	AttributeCert();
	// Construct from a SNACC AttributeCertificate
	AttributeCert(const SNACC::AttributeCertificate& snacc);
	// Construct from an ASN.1 encoded attribute certificate
	AttributeCert(const Bytes& asn);
	// Copy constructor
	AttributeCert(const AttributeCert& that);
	// Destructor
	virtual ~AttributeCert()							{ Clear(); }

	// Assignment operators
	AttributeCert& operator=(const SNACC::AttributeCertificate& snacc);	// Assign from a SNACC AttributeCertificate
	AttributeCert& operator=(const Bytes& asn);							// Assign from an ASN.1 encoded attribute cert
	AttributeCert& operator=(const AttributeCert& other);				// Assign from another AttributeCert

	// Clear the member variables
	void Clear();
	// Decode from an ASN.1 encoded attribute certificate
	virtual ulong Decode(const Bytes& asn);
	// Encode this attribute certificate
	virtual ulong Encode(Bytes& asn) const;
	// Get the SNACC form of this attribute certificate
	SNACC::AttributeCertificate* GetSnacc() const;

	// Member variables
	int version;						// Version number
	ACHolder holder;					// Holder of this attribute cert
	ACIssuer issuer;					// Issuer of this attribute cert
	AlgID signature;					// Inner signature algorithm
	SNACC::AsnInt serialNum;					// Serial number
	Validity validity;					// Validity period
	AttributeList attribs;				// Attributes associated with holder
	SNACC::UniqueIdentifier*
		pIssuerUniqueID;				// Issuer's unique identifier
	ACExtensions exts;					// Extensions
	AlgID algorithm;					// Outer signature algorithm
	Bytes sigValue;			// ASN.1 encoded signature value

private:
	bool m_versionPresent;				// Indicates if ASN.1 version was present
};


} // end of nested ASN namespace

} // end of CML namespace


#endif // _CMLASN_H
