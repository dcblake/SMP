/****************************************************************************
File:     cmlasn_general.h
Project:  Certificate Management ASN.1 Library
Contents: Header file for the X.509 Certificate Management ASN.1 Library
		  Contains general class definitions used throughout the library

Created:  6 September 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	18 May 2004

Version:  2.4

*****************************************************************************/
#ifndef _CMLASN_GENERAL_H
#define _CMLASN_GENERAL_H


////////////////////
// Included Files //
////////////////////
//#include <time.h>
#ifdef WIN32
#if (_MSC_VER <= 1200 /* VC++ 6.0*/)
	#pragma warning(disable: 4275)		// Disable unexported template warnings
#endif
#endif //WIN32

// ASN.1 Includes (in SNACC namespace)
#include "asn-incl.h"
#include "UsefulDefinitions.h"
#include "UpperBounds.h"
#include "InformationFramework.h"
#include "SelectedAttributeTypes.h"
#include "ORAddress.h"
#include "X509Common.h"
#include "AuthenticationFramework.h"
#include "CertificateExtensions.h"
#include "PKIX.h"
#include "AttributeCertificateDefinitions.h"
#include "sdn702.h"

#include "cmlasn_c.h"
#include "CommonBytes.h"


// Begin CML namespace
namespace CML {


// Begin nested ASN namespace
namespace ASN {


////////////////////////////////
// Exception class definition //
////////////////////////////////
class CM_API Exception : public SNACC::SnaccException
{
public:
	enum {
		kErrorBase = 2000
	};

	// Construct from an error code, file name, line number, and optional
	// error string
	Exception(short code, const char* fileName, long lineNum,
		const char* errString = NULL);

	// Convert the exception to its equivalent C error code
	operator short() const;

	// Function to get the error string
	virtual const char* what() const throw();

private:
	const char* m_errStr;
};


//////////////////////////////////////
// ExceptionString class definition //
//////////////////////////////////////
class CM_API ExceptionString : public Exception
{
public:
	// Construct from an error code, file name, line number, and two-part
	// error string
	ExceptionString(short code, const char* fileName, long lineNum,
		const char* errString1, const char* errString2);

	// Function to get the error string
	virtual const char* what() const throw();
};


////////////////////////////
// Bytes class definition //
////////////////////////////
class CM_API Bytes : public CommonBytes
{
public:
	// Construct from a length and data buffer
	Bytes(ulong num = 0, const uchar* data = NULL);
	// Construct from a Bytes_struct
	Bytes(const Bytes_struct& data);
	// Construct from a file
	Bytes(const char* fileName);
	// Construct from a SNACC::AsnOcts
	Bytes(const SNACC::AsnOcts& asnOcts);
	// Construct from a SNACC::AsnAny and optionally, its name
	Bytes(const SNACC::AsnAny& asnAny, const char* nameOfAny = NULL);

	// Assignment operators
	Bytes& operator=(const Bytes_struct& data);			// Assign from a Bytes_struct
	Bytes& operator=(const SNACC::AsnBits& asnBits);	// Assign from an AsnBits
	Bytes& operator=(const SNACC::AsnOcts& asnOcts);	// Assign from an AsnOcts

	// Comparison operators
	bool operator==(const Bytes& rhs) const { return CommonBytes::operator==(rhs); }
	bool operator==(const Bytes_struct& rhs) const;
	bool operator!=(const Bytes& rhs) const				{ return !operator==(rhs); }
	bool operator!=(const Bytes_struct& rhs) const		{ return !operator==(rhs); }
	bool operator<(const Bytes& rhs) const	{ return CommonBytes::operator<(rhs); }

	// Clear the contents
	virtual void Clear();
	// Get the length of the data (in bits)
	ulong BitLen() const			{ return len * 8 - unusedBits; }
	// Set these Bytes from the contents of the AsnAny and optionally, its name
	void SetFromAny(const SNACC::AsnAny& asnAny, const char* nameOfAny = NULL);
	// Set these Bytes from the specified number of bytes in the AsnBuf
	void SetFromBuf(const SNACC::AsnBuf& asnBuf, ulong bufLen);

	// Decode these Bytes into the given ASN.1 object with its optional name
	ulong Decode(SNACC::AsnType& snaccObj,
		const char* snaccObjName = NULL) const;
	// Encode the given ASN.1 object into these Bytes with its optional name
	ulong Encode(const SNACC::AsnType& snaccObj,
		const char* snaccObjName = NULL);

	// Fill in the Bytes_struct form of this object
	void FillBytesStruct(Bytes_struct& bytes) const;
	// Get the Bytes_struct form of this object
	Bytes_struct* GetBytesStruct() const;
	// Get the SNACC AsnOcts form of the data
	SNACC::AsnOcts* GetSnacc() const;

protected:
	int unusedBits;		// Number of unused bits in last byte (only used
};						//    when assigned from an AsnBits object)


// BytesList type
typedef std::list<Bytes> BytesList;


///////////////////////////////
// IntBytes class definition //
///////////////////////////////
class CM_API IntBytes : public Bytes
{
public:
	// Default constructor
	IntBytes() : Bytes()										{}
	// Construct from a SNACC::AsnInt and set the length to a multiple of mult
	IntBytes(const SNACC::AsnInt& asnInt, ulong mult = 0);

	// Assignment operators
	IntBytes& operator=(const SNACC::AsnBits& asnBits);	// Assign from an AsnBits

	// Reverse the order of these Bytes
	void Reverse();
	// Reverse the order of each half of these Bytes
	void ReverseHalves();
	// Set these Bytes from the AsnInt contents and strip the leading byte
	// or pad as necessary to reach a length of the multiple
	void SetFromInt(const SNACC::AsnInt& asnInt, ulong mult = 0);
};


///////////////////////////
// Time class definition //
///////////////////////////
class CM_API Time
{
public:
	// Construct from a time_t
	Time(time_t timeVal = time(NULL));
	// Construct from a SNACC Time
	Time(const SNACC::Time& snacc);
	// Construct from a SNACC GeneralizedTime
	Time(const SNACC::GeneralizedTime& snacc);
	// Construct from a CM_Time
	Time(const CM_Time& cmTime);
	// Copy constructor
	Time(const Time& that);

	// Assignment operators
	Time& operator=(const SNACC::Time& snacc);	// Assign from a SNACC Time
	Time& operator=(time_t timeVal);			// Assign from a time_t
	Time& operator=(const CM_Time& cmTime);		// Assign from a CM_Time
	Time& operator=(const Time& other);			// Assign from another Time

	// Conversion operator
	operator const char*() const				{ return m_time; }
	operator const SNACC::Time&() const			{ return m_snaccTime; }

	// Comparison operators
	bool operator==(const Time& rhs) const;
	bool operator!=(const Time& rhs) const		{ return !operator==(rhs); }
	bool operator<(const Time& rhs) const;
	bool operator>(const Time& rhs) const;
	bool operator<=(const Time& rhs) const		{ return !operator>(rhs); }
	bool operator>=(const Time& rhs) const		{ return !operator<(rhs); }

	// Clear the contents of this Time
	void Clear();
	// Fill in the SNACC GeneralizedTime form
	void FillSnaccGenTime(SNACC::GeneralizedTime& snacc) const;
	// Get the SNACC GeneralizedTime form
	SNACC::GeneralizedTime* GetSnaccGenTime() const;

private:
	void cvtGenTime2CM_Time(const std::string& gen);
	void cvtUTC2CM_Time(const std::string& utc);
	static void calcUTCtime(char *s1, char sign, const std::string& s2,
		std::string::size_type i);

	CM_Time m_time;
	SNACC::Time m_snaccTime;
};


////////////////////////////
// AlgID class definition //
////////////////////////////
class CM_API AlgID
{
public:
	// Default constructor
	AlgID()												{ parameters = NULL; }
	// Construct from a SNACC AlgorithmIdentifier
	AlgID(const SNACC::AlgorithmIdentifier& snacc);
	// Construct from a SNACC OID and optional parameters
	AlgID(const SNACC::AsnOid& oid, const Bytes* pParams = NULL);
	// Copy constructor
	AlgID(const AlgID& that);
	// Destructor
	virtual ~AlgID()									{ Clear(); }

	// Assignment operators
	AlgID& operator=(const SNACC::AlgorithmIdentifier& snacc);	// Assign from a SNACC AlgorithmIdentifier
	AlgID& operator=(const SNACC::AsnOid& oid);					// Assign from a SNACC OID
	AlgID& operator=(const AlgID& other);						// Assign from another AlgID

	// Comparison operators
	bool operator==(const AlgID& rhs) const;
	bool operator==(const SNACC::AsnOid& oid) const		{ return (algorithm == oid); }
	bool operator==(const char* stringOid) const		{ return (algorithm == stringOid); }
	bool operator!=(const AlgID& rhs) const				{ return !operator==(rhs); }
	bool operator!=(const SNACC::AsnOid& oid) const		{ return (algorithm != oid); }
	bool operator!=(const char* stringOid) const		{ return (algorithm != stringOid); }

	// Clear the contents of this AlgID 
	void Clear();
	// Fill in the SNACC form of AlgorithmIdentifier
	void FillSnacc(SNACC::AlgorithmIdentifier& snacc) const;
	// Returns true when the parameters are present
	bool ParametersArePresent() const;

	// Member variables
	SNACC::AsnOid algorithm;
	Bytes* parameters;					// ASN.1 encoded parameters
};


////////////////////////////////////////
// Type Definitions for Attribute values
////////////////////////////////////////
typedef std::list <SNACC::PrivilegeFlags> SigOrKMPrivileges;


// Forward class declaration
class AttributeList;
class ClearanceList;


/////////////////////////////
// Attribute class definition
//
// Used for attributes that appear
// in subject directory attributes
// extension and attribute certificates
//
class CM_API Attribute
{
public:
	enum AttrType
	{
		Clearance,				// X.501 Clearance attribute
		CAClearanceConst,		// SDN.702 CAClearanceConstraints attribute
		SigOrKMPrivs,			// SDN.702 SigOrKMPrivileges attribute
		CommPrivs,				// SDN.702 CommPrivileges attribute
		Other					// Any other attribute
	};

	union AttrUnion
	{
		ClearanceList*			pClearance;
		AttributeList*			pCACons;
		SigOrKMPrivileges*		pSigKMPrivs;
		SNACC::CommPrecFlags*	pCommPrivs;
		BytesList*				pOther;		// List of ASN.1 encoded values
	};

	// Default constructor
	Attribute();
	// Construct from an OID
	Attribute(const SNACC::AsnOid& attrType);
	// Construct from specific attribute values
	Attribute(const SNACC::AsnOid& attrType, AttrType attrFlag,
		const AttrUnion& values);
	// Construct from a SNACC Attribute
	Attribute(const SNACC::Attribute& snacc);
	// Copy constructor
	Attribute(const Attribute& other);
	// Destructor
	virtual ~Attribute()								{ Clear(); }

	// Assignment operators
	Attribute& operator=(const SNACC::Attribute& snacc);	// Assign from a SNACC Attribute
	Attribute& operator=(const Attribute& other);			// Assign from another Attribute

	// Comparison operators
	bool operator==(const Attribute& rhs)				{ return false; }
	bool operator<(const Attribute& rhs)				{ return false; }

	// Get the type of this attribute
	AttrType GetType() const							{ return m_flag; }
	// Get the values for this attribute
	const AttrUnion& GetValues() const					{ return m_values; }
	AttrUnion& GetValues();
	// Set this attribute from the type flag, values, and optional SNACC
	// values with context
	void Set(AttrType flag, const AttrUnion& values,
		const SNACC::AttributeSetOf1* pValuesWithContext = NULL);

	// Fill in the SNACC form of this attribute
	void FillSnaccAttribute(SNACC::Attribute& snacc) const;
	// Get the C form of this attribute
	Attributes_struct* GetAttributeStruct() const;

	// Member variables
	SNACC::AsnOid type;

protected:
	AttrType m_flag;
	AttrUnion m_values;
	SNACC::AttributeSetOf1* m_valuesWithContext;

private:
	void Clear();
};


////////////////////////////////////////////
// AttributeList class definition
// 
// Used to carry list of Attributes in the
// subject directory attributes extension or
// in an attribute certificate
//
class CM_API AttributeList : public std::list<Attribute>
{
public:
	// Default constructor
	AttributeList()														{}
	// Construct from a SNACC list of attributes
	AttributeList(const AsnSeqOf<SNACC::Attribute>& snacc);

	// Assignment operator
	// Assign from a SNACC list of attributes
	AttributeList& operator=(const AsnSeqOf<SNACC::Attribute>& snacc);

	// Fill in the SNACC form of these attributes
	void FillSnaccList(AsnSeqOf<SNACC::Attribute>& snacc) const;
	// Get the SNACC form of these attributes
	SNACC::AttributesSyntax* GetSnacc() const;
	// Get the SNACC CAClearanceConstraints form of these attributes
	SNACC::CAClearanceConstraints* GetSnaccCAConstraints() const;
	// Get the C list of these attributes
	Attributes_struct* GetAttributeList() const;
	// Get the C list of these CAClearanceConstraints
	Ca_const* GetCAConstList() const;

	// Find first Attribute of the specified type
	const_iterator Find(const SNACC::AsnOid& type) const;
	const_iterator Find(Attribute::AttrType type) const;
	// Find next Attribute of the specified type beyond previous iterator
	const_iterator FindNext(const_iterator iPrev,
		const SNACC::AsnOid& type) const;
	const_iterator FindNext(const_iterator iPrev,
		Attribute::AttrType type) const;
};


/////////////////////////////
// Clearance class definition
//
// Used to represent values of
// the X.501 Clearance attribute
//
class CM_API Clearance
{
public:
	// Default constructor
	Clearance();
	// Construct from a SNACC Clearance value
	Clearance(const SNACC::Clearance& snacc)			{ operator=(snacc); }
	// Construct from an old or new SNACC clearance value
	Clearance(const SNACC::OldAndNewClearance& snacc)	{ operator=(snacc); }

	// Assignment operators
	Clearance& operator=(const SNACC::Clearance& snacc);			// Assign from a SNACC Clearance
	Clearance& operator=(const SNACC::OldAndNewClearance& snacc);	// Assign from a SNACC OldAndNewClearance

	// Comparison operators
	bool operator==(const Clearance& rhs)				{ return false; }
	bool operator<(const Clearance& rhs)				{ return false; }

	// Fill in the SNACC form of this Clearance value
	void FillSnaccClearance(SNACC::Clearance& snacc) const;
	// Get the SNACC form of this Clearance value
	SNACC::Clearance* GetSnacc() const;
	// Get the C form of this Clearance value
	Clearance_struct* GetClearanceStruct() const;

	// Member variables
	SNACC::AsnOid policyId;
	SNACC::ClassList classList;
	SNACC::SecurityCategorySet categories;
};


/////////////////////////////////
// ClearanceList class definition
//
// Used to represent lists of values
// of the X.501 Clearance attribute
//
class CM_API ClearanceList : public std::list<Clearance>
{
public:
	// Default constructor
	ClearanceList()										{}
	// Construct from a set of AsnAny values
	ClearanceList(const AsnSetOf<SNACC::AsnAny>& snacc)	{ operator=(snacc); }
    
	// Assignment operators
	ClearanceList& operator=(const AsnSetOf<SNACC::AsnAny>& snacc);

	// Fill in the SNACC form of this list of clearance values
	void FillSnacc(AsnSetOf<SNACC::AsnAny>& snacc) const;
	// Find first clearance with the specified security policy
	const_iterator Find(const SNACC::AsnOid& secPolicy) const;
	// Find next clearance with the specified security policy
	// beyond the previous iterator
	const_iterator FindNext(const_iterator iPrev,
		const SNACC::AsnOid& secPolicy) const;
	// Get the C form of this list of clearance values
	Ca_const* GetCAClearanceList() const;
};



} // end of nested ASN namespace

} // end of CML namespace


// Write the Bytes to the specified stream
//CM_API std::ostream& operator<<(std::ostream& os, const CML::ASN::Bytes& bytes);



#endif // _CMLASN_GENERAL_H
