/****************************************************************************
File:     cmlasn_exts.h
Project:  Certificate Management ASN.1 Library
Contents: Header file for the X.509 Certificate Management ASN.1 Library
		  Contains extension classes.

Created:  6 September 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	18 May 2004

Version:  2.4

*****************************************************************************/
#ifndef _CMLASN_EXTS_H
#define _CMLASN_EXTS_H

#ifdef WIN32
	#pragma warning(disable: 4505)
#endif //WIN32

////////////////////
// Included Files //
////////////////////
#include "cmlasn_name.h"



// Begin CML namespace
namespace CML {


// Begin nested ASN namespace
namespace ASN {


////////////////////////////////
// Extension class definition //
////////////////////////////////
class CM_API Extension
{
public:
	// Constructor to create from an OID and an optional criticality flag
	Extension(const SNACC::AsnOid& oid, const SNACC::AsnBool* pCriticalFlag = NULL);
	// Destructor
	virtual ~Extension()	{}

	// Assignment operators
	Extension& operator=(const SNACC::Extension& snacc);	// Assign from a SNACC extension

	// Fill in the SNACC form of this extension
	void FillSnaccExtension(SNACC::Extension& snacc) const;
	// Get the C form of this extension
	Extn_struct* GetExtensionStruct() const;
	// Return the object identifier of this extension
	const SNACC::AsnOid& OID() const					{ return m_extnId; }

	// Member variables
	SNACC::AsnBool critical;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const = 0;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const = 0;

	SNACC::AsnOid m_extnId;		// Object identifier of th extension
	bool m_criticalPresent;		// Indicates if critical was present in ASN.1
};


///////////////////////////////////////
// UnknownExtension class definition //
///////////////////////////////////////
class CM_API UnknownExtension : public Extension 
{
public:
	// Default constructor
	UnknownExtension();
	// Constructor to create from a SNACC Extension
	UnknownExtension(const SNACC::Extension& snacc);
	// Constructor to create from the components of a SNACC Extension
	UnknownExtension(const SNACC::AsnOid& asnOid,
		const SNACC::AsnBool* pAsnBool, const Bytes& asnValue);

	// Comparison operators
	bool operator==(const UnknownExtension& rhs) const;
	bool operator!=(const UnknownExtension& rhs) const	{ return !operator==(rhs); }
	bool operator<(const UnknownExtension& rhs) const {return (encValue < rhs.encValue);}

	// Get the C form of this unknown extension
	Unkn_extn_LL* GetUnknownExtStruct() const;

	// Member variable containing the encoded value
	Bytes encValue;

protected:
	// Get the SNACC form of this extension's value
	SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	void* GetExtensionValue() const			{ return encValue.GetBytesStruct(); }
};


////////////////////////////////////////
// UnknownExtensions class definition //
////////////////////////////////////////
class CM_API UnknownExtensions : public std::list<UnknownExtension>
{
public:
	// Find the requested extension in the list
	const UnknownExtension* Find(const char* stringOid) const;
	// Find the requested extension in the list
	const UnknownExtension* Find(const SNACC::AsnOid& extOid) const;
	// Return true if the requested extension is in the list
	bool IsPresent(const char* stringOid) const			{ return (Find(stringOid) != NULL); }
	// Return true if the requested extension is in the list
	bool IsPresent(const SNACC::AsnOid& extOid) const	{ return (Find(extOid) != NULL); }
	// Get the C list of unknown extensions
	Unkn_extn_LL* GetUnknownExts() const;
};


/////////////////////////////////////////
// AuthKeyIdExtension class definition //
/////////////////////////////////////////
class CM_API AuthKeyIdExtension : public Extension
{
public:
	// Default constructor
	AuthKeyIdExtension();
	// Constructor to create from a SNACC AuthorityKeyIdentifier and criticality flag
	AuthKeyIdExtension(const SNACC::AuthorityKeyIdentifier& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);
	// Copy constructor
	AuthKeyIdExtension(const AuthKeyIdExtension& that);
	// Destructor
	virtual ~AuthKeyIdExtension()								{ Clear(); }

	// Assignment operators
	AuthKeyIdExtension& operator=(const SNACC::AuthorityKeyIdentifier& snacc);	// Assign from a SNACC AuthorityKeyIdentifier
	AuthKeyIdExtension& operator=(const AuthKeyIdExtension& other);				// Assign from another AuthKeyIdExtension

	// Comparison operator
	bool operator==(const AuthKeyIdExtension& rhs) const;

	// Member variables
	SNACC::KeyIdentifier* keyID;
	GenNames* authCertIssuer;
	SNACC::CertificateSerialNumber* authCertSerialNum;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;

private:
	// Clears the contents of this extension
	void Clear();
};


////////////////////////////////////////
// KeyUsageExtension class definition //
////////////////////////////////////////
class CM_API KeyUsageExtension : public Extension, public SNACC::KeyUsage
{
public:
	// Default constructor
	KeyUsageExtension();
	// Constructor to create from a SNACC AsnBits and criticality flag
	KeyUsageExtension(const SNACC::KeyUsage& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Comparison operators
	bool operator==(const KeyUsageExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


///////////////////////////////////////////
// ExtKeyUsageExtension class definition //
///////////////////////////////////////////
class  ExtKeyUsageExtension : public Extension,
	public std::list<SNACC::KeyPurposeId>
{
public:
	// Default constructor
	CM_API ExtKeyUsageExtension();
	// Constructor to create from a SNACC list of KeyPurposeId and criticality flag
	CM_API ExtKeyUsageExtension(const SNACC::ExtKeyUsage& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	CM_API ExtKeyUsageExtension& operator=(const SNACC::ExtKeyUsage& snacc);	// Assign from a SNACC list of KeyPurposeId

	// Comparison operator
	CM_API bool operator==(const ExtKeyUsageExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	CM_API virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	CM_API virtual void* GetExtensionValue() const;
};


//////////////////////////////////////////////////
// PrivKeyUsagePeriodExtension class definition //
//////////////////////////////////////////////////
class CM_API PrivKeyUsagePeriodExtension : public Extension
{
public:
	// Default constructor
	PrivKeyUsagePeriodExtension();
	// Constructor to create from a SNACC PrivateKeyUsagePeriod and criticality flag
	PrivKeyUsagePeriodExtension(const SNACC::PrivateKeyUsagePeriod& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);
	// Copy constructor
	PrivKeyUsagePeriodExtension(const PrivKeyUsagePeriodExtension& that);
	// Destructor
	virtual ~PrivKeyUsagePeriodExtension()							{ Clear(); }

	// Assignment operators
	PrivKeyUsagePeriodExtension& operator=(const SNACC::PrivateKeyUsagePeriod& snacc);	// Assign from a SNACC PrivateKeyUsagePeriod
	PrivKeyUsagePeriodExtension& operator=(const PrivKeyUsagePeriodExtension& other);	// Assign from another PrivKeyUsagePeriodExtension

	// Comparison operator
	bool operator==(const PrivKeyUsagePeriodExtension& rhs) const;

	// Returns true if the specified time falls within the usage period
	bool IsWithin(const Time& time) const;
	
	// Member variables
	Time* notBefore;
	Time* notAfter;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;

private:
	// Clear the contents
	void Clear();
};


////////////////////////////////////////////
// SubjAltNamesExtension class definition //
////////////////////////////////////////////
class CM_API SubjAltNamesExtension : public Extension, public GenNames
{
public:
	// Default constructor
	SubjAltNamesExtension();
	// Constructor to create from a SNACC GeneralNames and criticality flag
	SubjAltNamesExtension(const SNACC::GeneralNames& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Comparison operator
	bool operator==(const SubjAltNamesExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const	{ return GetSnacc(); }
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const			{ return GetGenNamesList(); }
};


//////////////////////////////////////////////
// IssuerAltNamesExtension class definition //
//////////////////////////////////////////////
class CM_API IssuerAltNamesExtension : public Extension, public GenNames
{
public:
	// Default constructor
	IssuerAltNamesExtension();
	// Constructor to create from a SNACC GeneralNames and criticality flag
	IssuerAltNamesExtension(const SNACC::GeneralNames& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Comparison operator
	bool operator==(const IssuerAltNamesExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const	{ return GetSnacc(); }
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const			{ return GetGenNamesList(); }
};


//////////////////////////////////////
// PolicyQualifier class definition //
//////////////////////////////////////
class CM_API PolicyQualifier
{
public:
	// Construct from an OID
	PolicyQualifier(const SNACC::AsnOid& asnOid = SNACC::AsnOid());
	// Construct from a SNACC PolicyQualifierInfo
	PolicyQualifier(const SNACC::PolicyQualifierInfo& snacc);
	// Copy constructor
	PolicyQualifier(const PolicyQualifier& that);
	// Destructor
	virtual ~PolicyQualifier();

	// Assignment operator
	PolicyQualifier& operator=(const PolicyQualifier& other);	// Assign from another PolicyQualifier

	// Comparison operators
	bool operator==(const PolicyQualifier& rhs) const;
	bool operator==(const SNACC::AsnOid& oid) const		{ return (qualifierId == oid); }
	bool operator!=(const PolicyQualifier& rhs) const	{ return !operator==(rhs); }
	bool operator!=(const SNACC::AsnOid& oid) const		{ return (qualifierId != oid); }
	bool operator<(const PolicyQualifier& rhs) const;

	// Fill in the SNACC form of this certificate policy qualifier
	void FillSnaccQualifier(SNACC::PolicyQualifierInfo& snacc) const;
	// Get the C form of this certificate policy qualifier
	Qualifier_struct* GetQualifierStruct() const;

	// Member variables
	SNACC::AsnOid qualifierId;
	Bytes* qualifier;				// ASN.1 encoded qualifier
};



CM_API typedef std::list<PolicyQualifier> PolicyQualifierList;


/////////////////////////////////
// CertPolicy class definition //
/////////////////////////////////
class CM_API CertPolicy
{
public:
	// Construct to create from an OID and optional qualifiers
	CertPolicy(const SNACC::AsnOid& asnOid = SNACC::anyPolicy,
		const PolicyQualifierList* pQualifiers = NULL);
	// Construct to create from a SNACC PolicyInformation
	CertPolicy(const SNACC::PolicyInformation& snacc);

	// Comparison operators
	bool operator==(const CertPolicy& that) const;
	bool operator==(const SNACC::AsnOid& oid) const		{ return (policyId == oid); }
	bool operator!=(const CertPolicy& that) const		{ return !operator==(that); }
	bool operator!=(const SNACC::AsnOid& oid) const		{ return (policyId != oid); }
	bool operator<(const CertPolicy& that) const;

	// Compute the union of the rhs qualifiers and this policy's qualifiers
	CertPolicy& operator|=(const PolicyQualifierList& rhs);

	// Fill in the SNACC form of this certificate policy
	void FillSnaccPolicy(SNACC::PolicyInformation& snacc) const;
	// Get the C form of this certificate policy
	Policy_struct* GetPolicyStruct() const;

	// Member variables
	SNACC::AsnOid policyId;
	PolicyQualifierList qualifiers;
};


/////////////////////////////////////
// CertPolicyList class definition //
/////////////////////////////////////
class CM_API CertPolicyList : public std::list<CertPolicy>
{
public:
	// Default constructor
	CertPolicyList()									{}
	// Construct from a single CertPolicy
	CertPolicyList(const CertPolicy& policy)			{ push_back(policy); }
	// Construct from a SNACC CertificatePoliciesSyntax
	CertPolicyList(const SNACC::CertificatePoliciesSyntax& snacc);

	// Assignment operators
	CertPolicyList& operator=(const SNACC::CertificatePoliciesSyntax& snacc);	// Assign from a SNACC CertificatePoliciesSyntax

	// Comparison operators
	bool operator==(const CertPolicyList& rhs) const;
	bool operator!=(const CertPolicyList& rhs) const		{ return !operator==(rhs); }

	// Intersection operator
	CertPolicyList operator&(const CertPolicyList& rhs) const;

	// Find the CertPolicy in the list with the specified OID
	const_iterator Find(const SNACC::AsnOid& policyOid) const;
	// Find the next CertPolicy in the list with the specified OID
	const_iterator FindNext(const_iterator iPrev,
		const SNACC::AsnOid& policyOid) const;
	// Get the SNACC form of this policy list
	SNACC::CertificatePoliciesSyntax* GetSnaccValue() const;
	// Get the C form of this policy list
	Policy_struct* GetPolicyList() const;
};


// Intersect the rhs policy set with the lhs policy set
CertPolicyList& operator&=(CertPolicyList& lhs, const CertPolicyList& rhs);
// Compute the union of the two policy sets and return the result
CertPolicyList operator|(const CertPolicyList& lhs, const CertPolicyList& rhs);
// Compute the union of the rhs policy set and the lhs policy set
CertPolicyList& operator|=(CertPolicyList& lhs, const CertPolicyList& rhs);



////////////////////////////////////////////
// CertPoliciesExtension class definition //
////////////////////////////////////////////
class CM_API CertPoliciesExtension : public Extension, public CertPolicyList
{
public:
	// Default constructor
	CertPoliciesExtension();
	// Constructor to create from a SNACC CertificatePoliciesSyntax and criticality flag
	CertPoliciesExtension(const SNACC::CertificatePoliciesSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	CertPoliciesExtension& operator=(const SNACC::CertificatePoliciesSyntax& snacc);	// Assign from a SNACC CertificatePoliciesSyntax

	// Comparison operator
	bool operator==(const CertPoliciesExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const	{ return CertPolicyList::GetSnaccValue(); }
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const			{ return GetPolicyList(); }
};


////////////////////////////////////
// PolicyMapping class definition //
////////////////////////////////////
class CM_API PolicyMapping
{
public:
	// Constructor to create a mapping from one policy OID to another
	PolicyMapping(const SNACC::AsnOid& fromPolicy = SNACC::anyPolicy,
		const SNACC::AsnOid& toPolicy = SNACC::anyPolicy);
	// Constructor to create from a SNACC policy mapping
	PolicyMapping(const SNACC::PolicyMappingsSyntaxSeq& snacc);

	// Comparison operators
	bool operator==(const PolicyMapping& rhs) const;
	bool operator==(const SNACC::AsnOid& oid) const		{ return (issuerPolicy == oid); }
	bool operator!=(const PolicyMapping& rhs) const		{ return !operator==(rhs); }
	bool operator!=(const SNACC::AsnOid& oid) const		{ return (issuerPolicy != oid); }
	bool operator<(const PolicyMapping& rhs) const;

	// Fill in the SNACC form of this policy mapping
	void FillSnaccMapping(SNACC::PolicyMappingsSyntaxSeq& snacc) const;
	// Get the C form of the policy mapping
	Pol_maps_struct* GetPolicyMapping() const;

	// Member variables
	SNACC::AsnOid issuerPolicy;
	SNACC::AsnOid subjectPolicy;
};


typedef std::list<PolicyMapping> PolicyMappingList;


//////////////////////////////////////////////
// PolicyMappingsExtension class definition //
//////////////////////////////////////////////
class CM_API PolicyMappingsExtension : public Extension, public PolicyMappingList
{
public:
	// Default constructor
	PolicyMappingsExtension();
	// Constructor to create from a SNACC PolicyMappingsSyntax and criticality flag
	PolicyMappingsExtension(const SNACC::PolicyMappingsSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	PolicyMappingsExtension& operator=(const SNACC::PolicyMappingsSyntax& snacc);	// Assign from a SNACC PolicyMappingsSyntax

	// Comparison operator
	bool operator==(const PolicyMappingsExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


////////////////////////////////////////////////
// BasicConstraintsExtension class definition //
////////////////////////////////////////////////
class CM_API BasicConstraintsExtension : public Extension
{
public:
	// Default constructor
	BasicConstraintsExtension();
	// Constructor to create from a SNACC BasicConstraintsSyntax and criticality flag
	BasicConstraintsExtension(const SNACC::BasicConstraintsSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Operator to assign from a SNACC BasicConstraintsSyntax
	BasicConstraintsExtension& operator=(const SNACC::BasicConstraintsSyntax& snacc);

	// Comparison operator
	bool operator==(const BasicConstraintsExtension& rhs) const;

	// Member variables
	bool isCA;
	long pathLen;				// Set to -1 when not present

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;

private:
	bool m_cAFlagPresent;			// Indicates if cA BOOLEAN was present in ASN.1
};


typedef std::list<SNACC::AsnOid> OIDList;


////////////////////////////////
// NameForms class definition //
////////////////////////////////
class CM_API NameForms
{
public:
	// Default constructor
	NameForms()											{}
	// Construct from a SNACC NameForms
	NameForms(const SNACC::NameForms& snacc)			{ operator=(snacc); }

	// Operator to assign from a SNACC NameForms
	NameForms& operator=(const SNACC::NameForms& snacc);

	// Comparison operator
	bool operator==(const NameForms& rhs) const;

	// Clear these name forms
	void Clear();
	// Return true if at least one required name form is present
	bool IsNamePresent(const GenNames* names) const;
	// Returns true when the none of the name forms are required
	bool IsEmpty() const;
	// Get the SNACC form of these name forms
	SNACC::NameForms* GetSnacc() const;

	// Member variables
	SNACC::BasicNameForms basicNames;	// empty when none are required
	OIDList otherNames;					// empty when no other forms are required
};


///////////////////////////////////////////////
// NameConstraintsExtension class definition //
///////////////////////////////////////////////
class CM_API NameConstraintsExtension : public Extension
{
public:
	// Default constructor -- also used to construct from the specified OID
	NameConstraintsExtension(const SNACC::AsnOid& extnId =
		SNACC::id_ce_nameConstraint);
	// Constructor to create from a SNACC NameConstraintsSyntax and criticality flag
	NameConstraintsExtension(const SNACC::AsnOid& extnId,
		const SNACC::NameConstraintsSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operators
	NameConstraintsExtension& operator=(const SNACC::NameConstraintsSyntax& snacc);	// Assign from a SNACC NameConstraintsSyntax

	// Comparison operator
	bool operator==(const NameConstraintsExtension& rhs) const;

	// Member variables
	GeneralSubtrees permitted;
	GeneralSubtrees excluded;
	NameForms requiredNames;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


/////////////////////////////////////////////////
// PolicyConstraintsExtension class definition //
/////////////////////////////////////////////////
class CM_API PolicyConstraintsExtension : public Extension
{
public:
	// Default constructor
	PolicyConstraintsExtension();    
	// Constructor to create from a SNACC PolicyConstraintsSyntax and criticality flag
	PolicyConstraintsExtension(const SNACC::PolicyConstraintsSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Operator to assign from a SNACC PolicyConstraintsSyntax
	PolicyConstraintsExtension& operator=(const SNACC::PolicyConstraintsSyntax& snacc);

	// Comparison operator
	bool operator==(const PolicyConstraintsExtension& rhs) const;

	// Member variables
	long requireExplicitPolicy;			// Set to -1 when not present
	long inhibitPolicyMapping;			// Set to -1 when not present

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


////////////////////////////////////////////////
// InhibitAnyPolicyExtension class definition //
////////////////////////////////////////////////
class CM_API InhibitAnyPolicyExtension : public Extension
{
public:
	// Default constructor
	InhibitAnyPolicyExtension();
	// Constructor to create from a SNACC SkipCerts value and criticality flag
	InhibitAnyPolicyExtension(const SNACC::SkipCerts& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	InhibitAnyPolicyExtension& operator=(const SNACC::SkipCerts& snacc);	// Assign from a SNACC SkipCerts value

	// Comparison operator
	bool operator==(const InhibitAnyPolicyExtension& rhs) const;

	// Member variable
	ulong value;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


////////////////////////////////////
// DistPointName class definition //
////////////////////////////////////
class CM_API DistPointName
{
public:
	enum Type
	{
		DIST_PT_FULL_NAME	= 1,
		DIST_PT_REL_NAME
	};

	// Construct from a SNACC DistributionPointName
	DistPointName(const SNACC::DistributionPointName& snacc);
	// Construct from a full name
	DistPointName(const GenNames& fullName);
	// Construct from a relative name
	DistPointName(const RelativeDN& relativeName);
	// Copy constructor
	DistPointName(const DistPointName& that);
	// Destructor
	virtual ~DistPointName()									{ Clear(); }

	// Assignment operators
	DistPointName& operator=(const SNACC::DistributionPointName& snacc);	// Assign from a SNACC DistributionPointName
	DistPointName& operator=(const GenNames& fullName);						// Assign from a full name
	DistPointName& operator=(const RelativeDN& relativeName);				// Assign from a relative name
	DistPointName& operator=(const DistPointName& other);					// Assign from another DistPointName

	// Comparison operators
	bool operator==(const DistPointName& rhs) const;
	bool operator!=(const DistPointName& rhs) const		{ return !operator==(rhs); }
	bool operator<(const DistPointName& rhs) const		{ return false; }

	// Fill in the C form of this CRL distribution point name
	void FillDistPtNameStruct(Dist_pt_name& dpName) const;
	// Get the SNACC form of this CRL distribution point name
	SNACC::DistributionPointName* GetSnacc() const;
	// Get the type of DistPointName
	Type GetType() const								{ return m_type; }
	// Get the full name form of this DistPointName
	const GenNames& GetFullName() const;
	GenNames& GetFullName();
	// Get the relative name form of this DistPointName
	const RelativeDN& GetRelativeName() const;
	RelativeDN& GetRelativeName();

protected:
	union DPNameUnion
	{
		GenNames* full;
		RelativeDN* relativeToIssuer;
	} m_name;
	Type m_type;

private:
	// Clears the contents of the DistPointName
	void Clear();
};


////////////////////////////////////////
// RevocationReasons class definition //
////////////////////////////////////////
class CM_API RevocationReasons : public SNACC::ReasonFlags
{
public:
	enum { kNumReasonBits = 9 };

	// Construct and set all or none of the ReasonFlags
	RevocationReasons(bool setAllBits = false);
	// Construct from the SNACC ReasonFlags
	RevocationReasons(const SNACC::ReasonFlags& snacc);

	// Assign from a SNACC ReasonFlags
	RevocationReasons& operator=(const SNACC::ReasonFlags& snacc);

	// Return bitwise-NOT of these reasons
	RevocationReasons operator~() const;
	// Return bitwise-AND of these and the rhs reasons
	RevocationReasons operator&(const RevocationReasons& rhs) const;
	// Perform bitwise-AND assignment
	RevocationReasons& operator&=(const RevocationReasons& rhs);
	// Perform bitwise-inclusive-OR assignment
	RevocationReasons& operator|=(const RevocationReasons& rhs);
	// Perform bitwise-exclusive-OR assignment
	RevocationReasons& operator^=(const RevocationReasons& rhs);
};


////////////////////////////////////////
// DistributionPoint class definition //
////////////////////////////////////////
class CM_API DistributionPoint
{
public:
	// Default constructor
	DistributionPoint();
	// Constructor to create from a SNACC distribution point
	DistributionPoint(const SNACC::DistributionPoint& snacc);
	// Copy constructor
	DistributionPoint(const DistributionPoint& that);
	// Destructor
	virtual ~DistributionPoint()								{ Clear(); }

	// Assignment operators
	DistributionPoint& operator=(const SNACC::DistributionPoint& snacc);	// Assign from a SNACC distribution point
	DistributionPoint& operator=(const DistributionPoint& other);			// Assign from another DistributionPoint

	// Comparison operators
	bool operator==(const DistributionPoint& rhs) const;
	bool operator!=(const DistributionPoint& rhs) const	{ return !operator==(rhs); }
	bool operator<(const DistributionPoint& rhs) const	{ return false; }

	// Fill in the SNACC form of this distribution point
	void FillSnaccDistPoint(SNACC::DistributionPoint& snacc) const;
	// Get the C form of this distribution point
	Dist_pts_struct* GetDistPointStruct() const;

	// Member variables
	DistPointName* distPoint;
	RevocationReasons* reasons;
	GenNames* crlIssuer;

private:
	// Clear the contents of this distribution point
	void Clear();
};


/////////////////////////////////////////////
// CrlDistPointsExtension class definition //
/////////////////////////////////////////////
class CM_API CrlDistPointsExtension : public Extension, public std::list<DistributionPoint>
{
public:
	// Default constructor
	CrlDistPointsExtension();
	// Constructor to create from a SNACC CRLDistPointsSyntax and criticality flag
	CrlDistPointsExtension(const SNACC::CRLDistPointsSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	CrlDistPointsExtension& operator=(const SNACC::CRLDistPointsSyntax& snacc);	// Assign from a SNACC CRLDistPointsSyntax

	// Comparison operator
	bool operator==(const CrlDistPointsExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


////////////////////////////////////////////////
// IssuingDistPointExtension class definition //
////////////////////////////////////////////////
class CM_API IssuingDistPointExtension : public Extension
{
public:
	// Default constructor
	IssuingDistPointExtension();
	// Constructor to create from a SNACC IssuingDistPointSyntax and criticality flag
	IssuingDistPointExtension(const SNACC::IssuingDistPointSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);
	// Copy constructor
	IssuingDistPointExtension(const IssuingDistPointExtension& that);
	// Destructor
	virtual ~IssuingDistPointExtension();

	// Assignment operators
	IssuingDistPointExtension& operator=(const SNACC::IssuingDistPointSyntax& snacc);	// Assign from a SNACC IssuingDistPointSyntax
	IssuingDistPointExtension& operator=(const IssuingDistPointExtension& other);		// Assign from another IssuingDistPointExtension

	// Comparison operator
	bool operator==(const IssuingDistPointExtension& rhs) const;

	// Member variables
	DistPointName* distPoint;
	bool onlyContainsUserCerts;
	bool onlyContainsAuthorityCerts;
	RevocationReasons* onlySomeReasons;
	bool indirectCRL;
	bool onlyContainsAttributeCerts;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;

private:
	bool m_userFlagPresent;			// Indicates if userCerts BOOLEAN was present in ASN.1
	bool m_caFlagPresent;			// Indicates if caCerts BOOLEAN was present in ASN.1
	bool m_attribFlagPresent;		// Indicates if indirectCRL was present in ASN.1
	bool m_indirectFlagPresent;		// Indicates if attribCerts BOOLEAN was present in ASN.1
};


/////////////////////////////////////////////
// FreshestCrlExtension class definition //
/////////////////////////////////////////////
class CM_API FreshestCrlExtension : public Extension, public std::list<DistributionPoint>
{
public:
	// Default constructor
	FreshestCrlExtension();
	// Constructor to create from a SNACC CRLDistPointsSyntax and criticality flag
	FreshestCrlExtension(const SNACC::CRLDistPointsSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	FreshestCrlExtension& operator=(const SNACC::CRLDistPointsSyntax& snacc);	// Assign from a SNACC CRLDistPointsSyntax

	// Comparison operator
	bool operator==(const FreshestCrlExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


/////////////////////////////////////////////////
// SubjDirAttributesExtension class definition //
/////////////////////////////////////////////////
class CM_API SubjDirAttributesExtension : public Extension, public AttributeList
{
public:
	// Default constructor
	SubjDirAttributesExtension();
	// Constructor to create from a SNACC AttributesSyntax and criticality flag
	SubjDirAttributesExtension(const SNACC::AttributesSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	// Assign from a SNACC AttributesSyntax
	SubjDirAttributesExtension& operator=(const SNACC::AttributesSyntax& snacc);

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const	{ return GetSnacc(); }
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const			{ return GetAttributeList(); }
};


////////////////////////////////////////
// AccessDescription class definition //
////////////////////////////////////////
class CM_API AccessDescription
{
public:
	// Default constructor
	AccessDescription();
	// Construct from a SNACC AccessDescription
	AccessDescription(const SNACC::AccessDescription& snacc);
	// Construct from an access method and location
	AccessDescription(const SNACC::AsnOid& accessMethod, const GenName& accessLoc);

	// Assignment operator
	AccessDescription& operator=(const SNACC::AccessDescription& snacc);	// Assign from a SNACC AccessDescription

	// Comparison operators
	bool operator==(const AccessDescription& rhs) const;
	bool operator!=(const AccessDescription& rhs) const		{ return !operator==(rhs); }
	bool operator<(const AccessDescription& rhs) const;

	// Fill in the SNACC form of this access description
	void FillSnacc(SNACC::AccessDescription& snacc) const;
	// Get the C form of this access description
	AccessDescript_LL* GetAccessDescStruct() const;

	// Member variables
	SNACC::AsnOid method;
	GenName location;
};


///////////////////////////////////////
// PkixAIAExtension class definition //
///////////////////////////////////////
class CM_API PkixAIAExtension : public Extension, public std::list<AccessDescription>
{
public:
	// Default constructor
	PkixAIAExtension();
	// Constructor to create from a SNACC AuthorityInfoAccessSyntax and criticality flag
	PkixAIAExtension(const SNACC::AuthorityInfoAccessSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	PkixAIAExtension& operator=(const SNACC::AuthorityInfoAccessSyntax& snacc);	// Assign from a SNACC AuthorityInfoAccessSyntax

	// Comparison operator
	bool operator==(const PkixAIAExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


///////////////////////////////////////
// PkixSIAExtension class definition //
///////////////////////////////////////
class CM_API PkixSIAExtension : public Extension, public std::list<AccessDescription>
{
public:
	// Default constructor
	PkixSIAExtension();
	// Constructor to create from a SNACC SubjectInfoAccessSyntax and criticality flag
	PkixSIAExtension(const SNACC::SubjectInfoAccessSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operator
	PkixSIAExtension& operator=(const SNACC::SubjectInfoAccessSyntax& snacc);	// Assign from a SNACC SubjectInfoAccessSyntax

	// Comparison operator
	bool operator==(const PkixSIAExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};


//////////////////////////////////////////
// CertIssuerExtension class definition //
//////////////////////////////////////////
class CM_API CertIssuerExtension : public Extension, public GenNames
{
public:
	// Default constructor
	CertIssuerExtension();
	// Constructor to create from a SNACC GeneralNames and criticality flag
	CertIssuerExtension(const SNACC::GeneralNames& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Comparison operator
	bool operator==(const CertIssuerExtension& rhs) const;

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const	{ return GetSnacc(); }
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const			{ return GetGenNamesList(); }
};


//////////////////////////////////////////////
// StdExtension_T template class definition //
//////////////////////////////////////////////
template <class T>
class StdExtension_T : public Extension, public T
{
public:
	// Construct from an Extension and the optional SNACC base class
	StdExtension_T<T>(const Extension& extension, const T& snacc = T());
	// Construct from the SNACC base class, AsnOid, and optional criticality flag
	StdExtension_T<T>(const T& snacc, const SNACC::AsnOid& oid,
		const SNACC::AsnBool* pCriticalFlag = NULL);

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const;
};

// The following #define is included for backwards compatibility
#define StandardExtension StdExtension_T


/////////////////////////////////////////
// SubjKeyIdExtension class definition //
/////////////////////////////////////////
class SubjKeyIdExtension : public StdExtension_T<SNACC::SubjectKeyIdentifier>
{
public:
	// Construct from the SNACC SubjectKeyIdentifier, and optional criticality flag
	CM_API SubjKeyIdExtension(const SNACC::SubjectKeyIdentifier& snacc =
		SNACC::SubjectKeyIdentifier(), const SNACC::AsnBool* pCriticalFlag = NULL);

protected:
	// Get the C form of this extension's value
	CM_API virtual void* GetExtensionValue() const; 
};


/////////////////////////////////////////
// CRLNumberExtension class definition //
/////////////////////////////////////////
class CRLNumberExtension : public StdExtension_T<SNACC::CRLNumber>
{
public:
	// Construct from the SNACC CRLNumber, and optional criticality flag
	CM_API CRLNumberExtension(const SNACC::CRLNumber& snacc =
		SNACC::CRLNumber(), const SNACC::AsnBool* pCriticalFlag = NULL);

protected:
	// Get the C form of this extension's value
	CM_API virtual void* GetExtensionValue() const; 
};


/////////////////////////////////////////////////
// DeltaCRLIndicatorExtension class definition //
/////////////////////////////////////////////////
class DeltaCRLIndicatorExtension: public StdExtension_T<SNACC::BaseCRLNumber>
{
public:
	// Construct from the SNACC CRLNumber, and optional criticality flag
	CM_API DeltaCRLIndicatorExtension(const SNACC::BaseCRLNumber& snacc =
		SNACC::BaseCRLNumber(), const SNACC::AsnBool* pCriticalFlag = NULL);

protected:
	// Get the C form of this extension's value
	CM_API virtual void* GetExtensionValue() const; 
};


///////////////////////////////////////////////
// ACBasicConstraintsExtension class definition
//
// Used to carry the attribute certificate basic
// constraints extension
//
class CM_API ACBasicConstraintsExtension : public Extension
{
public:
	// Default constructor
	ACBasicConstraintsExtension();
	// Constructor to create from a SNACC BasicAttConstraintsSyntax and criticality flag
	ACBasicConstraintsExtension(const SNACC::BasicAttConstraintsSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);
	// Copy constructor
	ACBasicConstraintsExtension(const ACBasicConstraintsExtension& that);

	// Assignment operators
	// Assign from a SNACC BasicAttConstraintsSyntax
	ACBasicConstraintsExtension& operator=(const SNACC::BasicAttConstraintsSyntax& snacc);
	// Assign from another ACBasicConstraintsExtension
	ACBasicConstraintsExtension& operator=(const ACBasicConstraintsExtension& other);

	// Comparison operator
	bool operator==(const ACBasicConstraintsExtension& rhs) const;

	// Member variables
	bool authority;
	long pathLen;		// Set to -1 when not present

protected:
	// Get the SNACC form of this extension's value
	virtual SNACC::AsnType* GetSnaccValue() const;
	// Get the C form of this extension's value
	virtual void* GetExtensionValue() const
		{ throw Exception(CMLASN_NOT_IMPLEMENTED, __FILE__, __LINE__); }

private:
	bool m_authFlagPresent;		// Indicates if authority BOOLEAN was present in ASN.1
};


///////////////////////////////////////////////
// ACNameConstraintsExtension class definition
//
// Used to carry the attribute certificate name
// constraints extension
//
class CM_API ACNameConstraintsExtension : public NameConstraintsExtension
{
public:
	// Default constructor
	ACNameConstraintsExtension();
	// Constructor to create from a SNACC NameConstraintsSyntax and criticality flag
	ACNameConstraintsExtension(const SNACC::NameConstraintsSyntax& snacc,
		const SNACC::AsnBool* pCriticalFlag = NULL);

	// Assignment operators
	// Assign from a SNACC NameConstraintsSyntax
	ACNameConstraintsExtension& operator=(const SNACC::NameConstraintsSyntax& snacc);

	// Comparison operator
	bool operator==(const ACNameConstraintsExtension& rhs) const;
};


//////////////////////////////////////////////////
// StdExtension_T template class implementation //
//////////////////////////////////////////////////
template <class T>
StdExtension_T<T>::StdExtension_T(const Extension& extension, const T& snacc) :
Extension(extension), T(snacc)
{
};


template <class T>
StdExtension_T<T>::StdExtension_T(const T& snacc, const SNACC::AsnOid& oid,
									 const SNACC::AsnBool* pCriticalFlag) :
Extension(oid, pCriticalFlag), T(snacc)
{
};


template <class T>
SNACC::AsnType* StdExtension_T<T>::GetSnaccValue() const
{
	T* result = new T(*this);
	if (result == NULL)
		throw Exception(CMLASN_MEMORY_ERROR, __FILE__, __LINE__);
	return result;
};



template <class T>
void* StdExtension_T<T>::GetExtensionValue() const
{
	throw Exception(CMLASN_UNKNOWN_ERROR, __FILE__, __LINE__,
		"Template function must be specialized");
}



} // end of nested ASN namespace

} // end of CML namespace


#endif // _CMLASN_EXTS_H
