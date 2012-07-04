/*****************************************************************************
File:     cmapi_cpp.h
Project:  Certificate Management Library
Contents: Header file for the C++ interface to the X.509 Certificate
		  Management Library

Created:  12 July 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	27 Jan 2005

Version:  2.5

*****************************************************************************/
#ifndef _CMAPI_CPP_H
#define _CMAPI_CPP_H


////////////////////
// Included Files //
////////////////////
#ifdef _MSC_VER
	#pragma warning(disable: 4786)	// Disable identifier truncated warning
	#pragma warning(push, 3)
	#pragma warning(disable: 4018)	// Disable signed/unsigned mismatch warning
	#pragma warning(disable: 4146)	// Disable unary minus operator warning
	#include <map>
 	#pragma warning(pop)
	#pragma warning(disable: 4275)	// Disable unexported template warnings
#else
	#include <string>
	#include <map>
#endif
#include "cmapi.h"
#include "cmlasn.h"


// Begin CML namespace
namespace CML {


//////////////////////
// Type Definitions //
//////////////////////
// Forward class declarations
class Certificate;
namespace Internal {
	class CachedCert;
	class PathState;
	class PathStack;
	class PrintXML;

} //end namespace

typedef std::list<CML::Certificate> CertList;


/////////////////////////////////////
// TokenException class definition //
/////////////////////////////////////
class CM_API TokenException : public CML::ASN::ExceptionString
{
public:
	// Construct from a token's error code, file name, line number
	TokenException(unsigned long errCode, const char* fileName, long lineNum,
		bool isWinError = false);

	unsigned long GetErrorCode() const		{ return errorCode; }
	bool IsWindowsError() const				{ return isWindowsError; }

protected:
	// Member variables
	unsigned long errorCode;	// Token-specific error code
	bool isWindowsError;		// Indicates that the code is a Windows error
};


////////////////////////////////
// ErrorInfo class definition //
////////////////////////////////
class CM_API ErrorInfo
{
public:
	// Default constructor
	ErrorInfo();
	// Construct from an error code, DN, and optionally extra information
	ErrorInfo(short errCode, const ASN::DN& dn, const char* optInfo = NULL);
	// Construct from an error code, CML::Certificate, and optionally extra
	// information
	ErrorInfo(short errCode, const ASN::Cert& cert,
		const char* optInfo = NULL);

	// Convert the ErrorInfo to its equivalent ErrorInfo_List C structure
	operator ErrorInfo_List*() const;

	// Comparison operators
	bool operator==(const ErrorInfo& rhs) const;
	bool operator!=(const ErrorInfo& rhs) const		{ return !operator==(rhs); }
	bool operator<(const ErrorInfo& rhs) const;

	// Members
	short			error;		// Extended error code
	ASN::GenNames	name;		// Subject name(s) of certificate or issuer
								// name(s) of CRL that caused the error
	std::string		extraInfo;	// Optional info specific to the error code
};


////////////////////////////////////
// ErrorInfoList class definition //
////////////////////////////////////
class CM_API ErrorInfoList : public std::list<ErrorInfo>
{
public:
	// Add an error to the set of errors, return true if added
	bool AddError(short errCode, const ASN::DN& dn,
		const char* optInfo = NULL);
	bool AddError(short errCode, const ASN::Cert& subjCert,
		const char* optInfo = NULL);
	bool AddError(const RevInfo& revInfo, const ASN::Cert& revCert);

	static bool ErrorIsCRLOutOfDate(const ErrorInfoList& errorList);
	
	// Insert another list of errors into this list
	void Insert(const ErrorInfoList& other);

	// Splice another list of errors into this list
	void Splice(iterator it, ErrorInfoList& other);

	// Convert the error list to its C form
	operator ErrorInfo_List*() const;
};


/////////////////////////////////////////
// RevocationDataList class definition //
/////////////////////////////////////////
class CM_API RevocationDataList : public CML::ASN::BytesList
{
public:
   enum Type 
   {
      EMPTY = 0,
      CRL,
      OCSP_RESP
   }; 

   // Constructor
   RevocationDataList() { m_type = EMPTY; }

   // Assign from the "C" form of the list
   RevocationDataList& operator=(const EncRevObject_LL& that);

   // Return the "C" form of the list
   EncRevObject_LL* GetEncRevObject_LL() const;

   // Clear the list and set type to empty
   void Clear()                                 { clear(); m_type = EMPTY; }

   // Public members
   Type m_type;         // Type of object stored in the list

};


///////////////////////////////////
// ValidatedKey class definition //
///////////////////////////////////
class CM_API ValidatedKey
{
public:
	// Default constructor
	ValidatedKey();
	// Construct from a CMAPI ValidKey_struct
	ValidatedKey(const ValidKey_struct& valKey);
	// Copy constructor
	ValidatedKey(const ValidatedKey& that);
	// Destructor
	virtual ~ValidatedKey();

	// Assignment operator
	ValidatedKey& operator=(const ValidatedKey& that);

	// Access the validated public key info
	const ASN::PublicKeyInfo& pubKeyInfo() const		{ return m_pubKeyInfo; }
	// Clear the contents of this validated public key
	void Clear();
	// Get the CMAPI ValidKey_struct form
	ValidKey_struct* GetValidKeyStruct() const;
	// Return true if no key is present
	bool IsEmpty() const;

	// Member variables
	ASN::CertPolicyList authPolicies;   // Set of authority-contrained policies
	ASN::CertPolicyList userPolicies;   // Set of user-contrained policies
	bool explicitPolicyFlag;            // Indicates if each cert must contain
                                       // an acceptable policy
	ASN::PolicyMappingList mappings;    // Policy mapping details
	ASN::KeyUsageExtension* pKeyUsage;  // Key usage restrictions
	ASN::ExtKeyUsageExtension* pExtKeyUsage;// Extended key usage restrictions
	RevocationDataList	m_revDataList; // list of encoded CRLs/OCSP responses

private:
	// Private member variables
	ASN::PublicKeyInfo m_pubKeyInfo;    // Validated public key 

	// Friends
	friend class Internal::PathState;
	friend class Internal::CachedCert;
};


///////////////////////////////
// CertPath class definition //
///////////////////////////////
class CM_API CertPath : protected ASN::CertificationPath
{
public:
	// Default constructor
	CertPath();
	// Construct from a subject cert
	CertPath(const Certificate& subject);
	// Construct from an ASN::CertificationPath
	CertPath(const ASN::CertificationPath& certPath);
	// Construct from an ASN.1 encoded CertificationPath or Certificate
	CertPath(const ASN::Bytes& asn, bool isCertPath = true);
	// Copy constructor
	CertPath(const CertPath& other);
	// Destructor
	virtual ~CertPath();

	// Assignment operators
	CertPath& operator=(const ASN::CertificationPath& certPath);// Assign from an ASN::CertificationPath
	CertPath& operator=(const ASN::Bytes& asn);					// Assign from an ASN.1 encoded CertificationPath
	CertPath& operator=(const CertPath& other);					// Assign from another CertPath

	// Access the base class form of this cert path
	const ASN::CertificationPath& base() const			{ return *this; }

	// Access the encoded user cert and CA certs
	const ASN::Bytes& GetEncUserCert() const			{ return encUserCert; }
	const ASN::BytesList& GetEncCACerts() const			{ return encCACerts; }

	// Build a path to a trusted cert
	short Build(
	   ulong sessionID,			         // CML Session ID
      SearchBounds boundsFlag,	      // Search local,remote,both,or until found 
	   float minProb = 0,               // Min Probability of acceptable paths
	   ErrorInfoList* pErrors = NULL,   // List of Errors, if any
	   const ASN::Time* pValidationTime = NULL); // Opt Time to use for validation

	// Build another path using the previous values
	short BuildNext(float minProb = 0, ErrorInfoList* pErrors = NULL);
	// Build and validate paths until a valid path is found
	short BuildAndValidate(
	   ulong sessionID,                 // CML Session ID
      SearchBounds boundsFlag,         // Search local,remote,both,until found
	   ErrorInfoList* pErrors = NULL,   // List of errors, if any
	   float minProb = 0,               // Min Probability of acceptable paths       
	   ValidatedKey* pValidKey = NULL,  // 
      const ASN::Time* pValidationTime = NULL, // Opt time to use for validation
	   bool performRevChecking = true); // Perform Revocation Checking

	// Decode from an ASN.1 encoded CertPath
	virtual ulong Decode(const ASN::Bytes& asn);
	// Encode this CertPath
	virtual ulong Encode(ASN::Bytes& asn) const;
	// Validate the current path
	short Validate(ErrorInfoList* pErrors = NULL,
		ValidatedKey* pValidKey = NULL, bool performRevChecking = true) const;

protected:
	ASN::Bytes encUserCert;			// Encoded subject certificate
	ASN::BytesList encCACerts;		// Encoded CA certs

private:
	Internal::PathState* state;		// Path state variable
	Internal::PathStack* curPath;	// CertPath kept as BaseNode pointers
	Internal::PrintXML* m_logXML;	// Log file interface

	void InitLogSettings(ulong sessionID); // Enable logging for path building
	void SetPathFromState();
};


/////////////////////////////////
// Certficate class definition //
/////////////////////////////////
class CM_API Certificate : protected ASN::Cert
{
public:
	// Construct from an ASN::Cert
	Certificate(const ASN::Cert& cert);
	// Construct from an ASN.1 encoded certificate
	Certificate(const ASN::Bytes& asn);
	// Construct from an ASN.1 encoded certificate
	Certificate(const Bytes_struct& asn);

	// Assignment operators
	Certificate& operator=(const ASN::Cert& cert);	// Assign from an ASN::Cert
	Certificate& operator=(const ASN::Bytes& asn);	// Assign from an ASN.1 encoded certificate

	// Access the decoded certificate
	const ASN::Cert& base() const						{ return *this; }
	// Access the encoded certificate
	const ASN::Bytes& GetEnc() const					{ return encCert; }

	// Decode from an ASN.1 encoded certificate
	virtual ulong Decode(const ASN::Bytes& asn);
	// Encode this certificate
	virtual ulong Encode(ASN::Bytes& asn) const;
	// Determine if this certificate is in the cache and is valid.
	bool IsValid(ulong sessionID) const;
	// Sign this certificate
	short Sign(const CM_CryptoToken& tokenHandle,
		CK_OBJECT_HANDLE pkcs11Key = 0, const ASN::AlgID* pSigAlg = NULL);
	// Validate this certificate
	short Validate(
		ulong sessionID,			        // CML Session ID
		SearchBounds boundsFlag,        // Search local,remote,both or until found
		ErrorInfoList* pErrors = NULL,  // List of errors, if any
		ValidatedKey* pValidKey = NULL, // Path Validation results
		CertPath* optPath = NULL,       // Empty CertPath to be filled in
		const ASN::Time* pValidationTime = NULL, // Opt	time to use for validation
      bool performRevChecking = true) const;   // Perform Revocation Checking

	// Verify the signature on this certificate
	short VerifySignature(ulong sessionID, const ValidatedKey& signersKey) const;
	short VerifySignature(ulong sessionID, SearchBounds boundsFlag,
		Certificate& signersCert) const;

protected:
	short VerifySignature(ulong sessionID, const ASN::PublicKeyInfo& publicKey,
		const ASN::Bytes* parameters = NULL) const;

	ASN::Bytes encCert;				// Encoded cert
};


//////////////////////////
// CRL class definition //
//////////////////////////
class CM_API CRL : protected ASN::CertificateList
{
public:
	// Construct from an ASN::CertificateList
	CRL(const ASN::CertificateList& crl);
	// Construct from an ASN.1 encoded CRL
	CRL(const ASN::Bytes& asn);

	// Assignment operators
	CRL& operator=(const ASN::CertificateList& crl);	// Assign from an ASN::CertificateList
	CRL& operator=(const ASN::Bytes& asn);				// Assign from an ASN.1 encoded CRL

	// Conversion operator to access the encoded CRL
	operator const ASN::Bytes&() const					{ return encCrl; }

	// Access the base form of this CRL
	const ASN::CertificateList& base() const			{ return *this; }

	// Decode from an ASN.1 encoded CRL
	virtual ulong Decode(const ASN::Bytes& asn);
	// Encode this CRL
	virtual ulong Encode(ASN::Bytes& asn) const;
	// Check if a cert issued this CRL
	bool IsIssuer(const ASN::Cert& issuer) const;
	// Sign this CRL
	short Sign(const CM_CryptoToken& tokenHandle,
		CK_OBJECT_HANDLE pkcs11Key = 0, const ASN::AlgID* pSigAlg = NULL);
	// Validate this CRL using the optional signer's certificate
	short Validate(
	   ulong sessionID,					      // CML Session ID
	   SearchBounds boundsFlag,            // Search local,remote,both or until found
	   ErrorInfoList* pErrors = NULL,      // List of errors, if any
	   const Certificate* pSigner = NULL,  // Optional Certificate to be used as 
	                                       // issuer cert first
	   bool tryOtherSigners = false,       // Try other signers if true
	   const ASN::Time* pValidationTime = NULL) const; // Opt time to use
                                                      // for validation
	// Validate this CRL using the issuer's validated public key
	short Validate(
	   ulong sessionID,                    // CML Session ID
	   const ValidatedKey& issuersKey,     // Path Validation results
	   ErrorInfoList* pErrors = NULL,      // List of errors, if any
	   const ASN::Time* pValidationTime = NULL) const; // Opt time to use
                                                      // for validation

	// Validate this CRL and return the issuer's certification path
	short Validate(
	   ulong sessionID,               // CML Session ID
	   SearchBounds boundsFlag,       // Search local,remote,both or until found
	   CertPath& issuerPath,          // Empty CertPath to be filled in
	   ErrorInfoList* pErrors = NULL, // List of errors, if any
	   const ASN::Time* pValidationTime = NULL, // Opt time to use for validation
      bool performRevChecking = true) const; // Perform Revocation Checking 

	// Verify the signature on this CRL
	short VerifySignature(ulong sessionID, const ValidatedKey& signersKey) const;

protected:
	ASN::Bytes encCrl;				// Encoded CRL
};


////////////////////////////////
// Signature class definition //
////////////////////////////////
class CM_API Signature
{
public:
	// Default constructor
	Signature()														{}
	// Construct this signature from an algorithm identifier
	Signature(const ASN::AlgID& algorithm) : m_sigAlg(algorithm)	{}

	// Assign this signature to the specified algorithm
	Signature& operator=(const ASN::AlgID& algorithm);

	// Clear the contents of this signature
	void Clear();
	// Decode the signature from an ASN.1 buffer
	ulong Decode(const SNACC::AsnBuf& asnBuf, SNACC::AsnLen& bytesDecoded);
	// Encode this signature into an ASN.1 buffer
	SNACC::AsnLen Encode(SNACC::AsnBuf& asnBuf) const;
	// Encode only the signature value
	void EncodeValue(ASN::Bytes& asn) const;

	// Access the signature algorithm
	const ASN::AlgID& GetAlgorithm() const			{ return m_sigAlg; }
	// Access the big-endian signature value
	const ASN::Bytes& GetValue() const				{ return m_value; }
	// Access the reversed signature value
	const ASN::Bytes& GetCAPIValue() const			{ return m_capiValue; }

	// Set this signature value from the specified value
	void Set(ulong sigLen, const uchar* sigValue, bool isBigEndian = true);

private:
	// Encode only the signature value
	void EncodeValue(SNACC::AsnBits& asnBits) const;

	// Members
	ASN::AlgID m_sigAlg;		// Signature algorithm
	ASN::IntBytes m_value;		// Big-endian, concatenated signature value
	ASN::IntBytes m_capiValue;	// Reversed signature value in CAPI form
};


///////////////////////////////////
// SignedAsnObj class definition //
///////////////////////////////////
class CM_API SignedAsnObj
{
public:
	// Construct from a SIGNED ASN.1 encoded object
	SignedAsnObj(const ASN::Bytes& asn);
	// Construct from an ASN.1 encoded object to be signed and an algorithm
	SignedAsnObj(const ASN::Bytes& asn, const ASN::AlgID& sigAlg);
	// Destructor
	virtual ~SignedAsnObj()												{}

	// Assign from a SIGNED ASN.1 encoded object
	SignedAsnObj& operator=(const ASN::Bytes& asn);

	// Decode from a SIGNED ASN.1 encoded object
	virtual ulong Decode(const ASN::Bytes& asn);
	// Encode this object
	virtual ulong Encode(ASN::Bytes& asn) const;

	// Access the signature algorithm and value
	Signature& GetSignature()								{ return m_sig; }

	// Sign the object
	short Sign(const CM_CryptoToken& tokenHandle,
		CK_OBJECT_HANDLE pkcs11Key = 0, const ASN::AlgID* pSigAlg = NULL);

	// Verify the object's signature
	short VerifySignature(ulong sessionID,
		const ValidatedKey& signersKey) const {
		return VerifySignature(sessionID, signersKey.pubKeyInfo()); }
	short VerifySignature(ulong sessionID, const ASN::PublicKeyInfo& publicKey,
		const ASN::Bytes* parameters = NULL) const;
	short VerifySignature(ulong sessionID, SearchBounds boundsFlag,
		const Certificate& signersCert, ErrorInfoList* pErrors = NULL) const;
	short VerifySignature(const CM_CryptoToken& tokenHandle,
		const ASN::PublicKeyInfo& publicKey,
		const ASN::Bytes* parameters = NULL) const;

protected:
	ASN::Bytes m_sigData;	// Signed data
	Signature m_sig;		// Signature algorithm and value
};


//////////////////////////////////
// TrustAnchor class definition //
//////////////////////////////////
class CM_API TrustAnchor
{
public:
	// Construct from a trusted certificate and indicate if the extensions
	// in the certificate should be used as constraints
	TrustAnchor(const ASN::Bytes& encCert, bool useExts = false);
	TrustAnchor(const ASN::Cert& cert, bool useExts = false);
	// Construct from a trusted public key, DN, and optional key identifier
	TrustAnchor(const ASN::PublicKeyInfo& key, const ASN::DN& dn,
		const ASN::SubjKeyIdExtension* pSubjKeyIdExt = NULL);

	// Conversion operator
	operator const ASN::Bytes&() const		{ return m_encCert; }

	// Comparison operators
	bool operator==(const TrustAnchor& rhs) const	{
		return (m_encCert == rhs.m_encCert); }
	bool operator!=(const TrustAnchor& rhs) const	{
		return (m_encCert != rhs.m_encCert); }
	bool operator<(const TrustAnchor& rhs) const	{
		return (m_encCert < rhs.m_encCert); }

	// Returns true if this trust anchor that created from a public key and DN
	bool IsCreatedFromKey()	const			{ return m_createdFromKey; }

	// Members
	short maxPathLen;						// Maximum length of paths
	ASN::NameConstraintsExtension names;	// Name constraints for paths

protected:
	ASN::Bytes m_encCert;					// Encoded trusted certificate

private:
	bool m_createdFromKey;		// True when created from a public key and DN
};


//////////////////////////////////////
// TrustAnchorList class definition //
//////////////////////////////////////
class TrustAnchorList : public std::list<TrustAnchor>
{
public:
	// Default constructor
	CM_API TrustAnchorList()										{}
	// Construct from a list of encoded trusted certificates
	CM_API TrustAnchorList(const ASN::BytesList& trustedCerts)	{
		operator=(trustedCerts); }

	// Assign from a list of encoded trusted certificates
	CM_API TrustAnchorList& operator=(const ASN::BytesList& trustedCerts);
};

//////////////////////
// Type Definitions //
//////////////////////
struct CertMatchData
{
	const SNACC::AsnOid*	pPubKeyOID;		// Public key algorithm
	const ASN::Time*		pValidOnDate;	// Cert valid on this date
	const ASN::DN*			pIssuer;		// DN of the certificate issuer
	const char*				emailAddr;		// Subject's e-mail address
	const SNACC::AsnInt*	pSerialNum;		// Serial number of the cert
	const ASN::OIDList*		pPolicies;		// Acceptable certificate policies
	const SNACC::AsnOcts*	pSubjKeyID;		// Subject key identifier
	bool					canSignCerts;	// Must have keyCertSign key usage
	bool					canSignCRLs;	// Must have cRLSign key usage
};

struct CRLMatchData
{
	const SNACC::AsnOid*	pSignature;		// Algorithm used to sign CRL
	const ASN::Time*		pIssuedAfter;	// Issued on or after this date
	const ASN::Time*		pIssuedBefore;	// Issued on or before this date
	bool					onlyOne;		// When true, only one CRL returned
};



/////////////////////////
// Function Prototypes //
/////////////////////////
CM_API short RequestCerts(ulong sessionID, ASN::BytesList& certificateList,
						  const ASN::DN& subject,
						  SearchBounds boundsFlag = CM_SEARCH_UNTIL_FOUND,
						  const CertMatchData* pMatchInfo = NULL);
CM_API short RequestCRLs(ulong sessionID, ASN::BytesList& crlList,
						 const ASN::DN* pIssuer,
						 SearchBounds boundsFlag = CM_SEARCH_UNTIL_FOUND,
						 const CRLMatchData* pMatchInfo = NULL,
						 const ASN::DistributionPoint* pDistPoint = NULL);
CM_API void SetPolicy(ulong sessionID, const ASN::OIDList& policies =
					  ASN::OIDList(1, SNACC::anyPolicy),
					  bool requireExplicitPolicy = false,
					  bool inhibitPolicyMapping = false,
					  bool inhibitAnyPolicy = false);
CM_API short SetTrustedCerts(ulong sessionID,
							 const ASN::BytesList& trustedCerts,
							 ErrorInfoList* pErrInfo = NULL);
CM_API short SetTrustAnchors(ulong sessionID,
							 const TrustAnchorList& trustAnchors,
							 ErrorInfoList* pErrInfo = NULL);


} // end of CML namespace


#endif // _CMAPI_CPP_H
