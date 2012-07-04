/****************************************************************************
File:     cmlasn_name.h
Project:  Certificate Management ASN.1 Library
Contents: Header file for the X.509 Certificate Management ASN.1 Library
		  Includes the definitions for the various name classes
		  (GeneralName, DN, RelativeDN, etc.).

Created:  6 September 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	1 March 2004

Version:  2.4

*****************************************************************************/
#ifndef _CMLASN_NAME_H
#define _CMLASN_NAME_H


////////////////////
// Included Files //
////////////////////
#include "cmlasn_general.h"


// Begin CML namespace
namespace CML {


// Begin nested ASN namespace
namespace ASN {


/////////////////////////////////
// RelativeDN class definition //
/////////////////////////////////
class CM_API RelativeDN
{
public:
	// Constructor to create from an RFC 2253 string RDN
	RelativeDN(const char* stringRDN, unsigned int strLen = 0);
	// Constructor to create from a SNACC RelativeDistinguishedName
	RelativeDN(const SNACC::RelativeDistinguishedName& snaccRDN);
	// Copy constructor
	RelativeDN(const RelativeDN& that)				{ operator=(that); }

	// Assignment operators
	RelativeDN& operator=(const char* stringRDN);							// Assign from an RFC 2253 string RDN
	RelativeDN& operator=(const SNACC::RelativeDistinguishedName& snacc);	// Assign from a SNACC RDN
	RelativeDN& operator=(const RelativeDN& other);							// Assign from another DN

	// Conversion operator
	operator const char*() const					{ return m_rdn.c_str(); }

	// Comparison operators
	bool operator==(const RelativeDN& rhs) const;
	bool operator!=(const RelativeDN& rhs) const	{ return !operator==(rhs); }

	// Get the SNACC RelativeDistinguishedName
	const SNACC::RelativeDistinguishedName& GetSnaccRDN() const		{ return m_snaccRDN; }

	// Set this RelativeDN from an RFC 2253 string RDN
	void Set(const char* stringRDN, unsigned int stringLen = 0);

	// Tells whether or not this RelativeDN constains a PKCS9 emailAddress.
	bool containsPKCS9EmailAddress(std::string & email) const;

private:
	// Private members
	std::string m_rdn;
	SNACC::RelativeDistinguishedName m_snaccRDN;
};


/////////////////////////
// DN class definition //
/////////////////////////
class CM_API DN
{
public:
	// Construct from an RFC 2253 string DN
	DN(const char* stringDN = NULL)					{ operator=(stringDN); }
	// Construct from a SNACC Name
	DN(const SNACC::Name& snaccName)				{ operator=(snaccName); }
	// Construct from a SNACC DistinguishedName
	DN(const SNACC::DistinguishedName& snaccDN)		{ operator=(snaccDN); }
	// Construct from an ASN.1 encoded Name
	DN(const Bytes& asn)							{ operator=(asn); }
	// Copy constructor
	DN(const DN& that)								{ operator=(that); }

	// Assignment operators
	DN& operator=(const char* stringDN);					// Assign from an RFC 2253 string DN
	DN& operator=(const SNACC::Name& snaccName);			// Assign from a SNACC Name
	DN& operator=(const SNACC::DistinguishedName& snacc);	// Assign from a SNACC DN
	DN& operator=(const Bytes& asn);						// Assign from an ASN.1 encoded Name
	DN& operator=(const DN& other);							// Assign from another DN

	// Conversion operators
	operator const char*() const					{ return m_strDN.c_str(); }

	// Comparison operators
	bool operator==(const DN& rhs) const;
	bool operator!=(const DN& rhs) const			{ return !operator==(rhs); }
	bool operator<(const DN& rhs) const;

	// Append operators
	DN& operator+=(const DN& rhs);
	DN& operator+=(const RelativeDN& rhs);

	// Decode from an ASN.1 encoded Name
	ulong Decode(const Bytes& asn);
	// Encode this distinguished name
	ulong Encode(Bytes& asn) const;
	// Get the list of RelativeDNs for this DN
	const std::list<RelativeDN>& GetRDNList() const		{ return m_rdnList; }
	// Fill in the SNACC Name form of this DN
	void FillSnacc(SNACC::Name& snacc) const;
	// Get the SNACC Name form of this DN
	SNACC::Name* GetSnacc() const;
	// Get the SNACC DistinguishedName form of this DN
	SNACC::DistinguishedName* GetSnaccDN() const;
	// Return true if the DN is empty
	bool IsEmpty() const;
	// Return number of RDNs that match, starting from the root
	ulong CompareRDNs(const DN& rhs) const;

private:
	// Build the DN string from the list of RelativeDNs
	void BuildDNString(void);

	// Private member
	std::string m_strDN;
	std::list<RelativeDN> m_rdnList;
};


////////////////////////////////
// IPAddress class definition //
////////////////////////////////
class CM_API IPAddress
{
public:
	enum
	{
		IP_ADDRESS_LEN_V4	= 4,
		IP_ADDRESS_LEN_V6	= 16
	};
	
	// Constructors/Destructor
	IPAddress(const SNACC::AsnOcts& snacc);
	IPAddress(const IPAddress& that);
	IPAddress(const uchar* other = NULL, bool IPv6Flag = true,
		uchar* constraint = NULL);
	virtual ~IPAddress()						{ delete[] m_pIpConstraint; };
	
	// Assignment operators
	// Assign from a SNACC AsnOcts
	IPAddress& operator=(const SNACC::AsnOcts& snacc);
	// Assign from another IPAddress
	IPAddress& operator=(const IPAddress& that);
	// Set from a IPv6 IPAddress
	IPAddress& Set(const uchar* other, bool IPv6Flag = true,
		const uchar* constraint = NULL);
	
	// Comparison operators
	bool operator==(const IPAddress& rhs) const;
	bool operator!=(const IPAddress& rhs) const		{ return !operator==(rhs); }
	bool operator<(const IPAddress& rhs) const;
	
	// Get the SNACC AsnOcts form of this IPAddress
	SNACC::AsnOcts* GetSnacc(void) const;
	
	// Compare values, including constraints if necessary.
	bool Matches(const IPAddress& rhs) const;
	
	// Provide access to private data members
	const uchar* GetIPAddress(void) const	{ return m_ipAddress; }
	const uchar* GetConstraint(void) const	{ return m_pIpConstraint; }
	
	// Check for embedded Version 4 IPAddress
	bool IsIP4(void) const					{ return m_ip4Flag; }

	// Convert the IPAddress to its string form
	std::string IPAddrToStr(void) const;
	
protected:
	// Protected Member variables
	uchar         m_ipAddress[IP_ADDRESS_LEN_V6];
	uchar*        m_pIpConstraint;
	bool          m_ip4Flag;
	
private:
	// Private Member function
	void Clear(void);
};


//////////////////////////////
// GenName class definition //
//////////////////////////////
class CM_API GenName
{
public:
	enum Type
	{
		OTHER	= 1,
		RFC822,
		DNS,
		X400,
		X500,
		EDI,
		URL,
		IP_ADDR,
		REG_OID
	};
	union Form
	{
		SNACC::Other_Name* other;		// Other name (ANY) form
		SNACC::ORAddress* x400;			// X.400 O/R Address form
		DN* dn;							// X.500 Distinguished Name form
		SNACC::EDIPartyName* ediParty;	// EC/EDI party name form
		IPAddress* ipAddr;				// IP Adddress
		SNACC::AsnOid* regID;			// Registered ID
		char* name;						// All other forms (email addresses,
    };									//    DNS names, and URLs)

	// Default constructor
	GenName(Type nameType = X500);
	// Construct from a SNACC GeneralName
	GenName(const SNACC::GeneralName& snaccGN);
	// Construct from a specific name form
	GenName(const Form& name, Type type);
	// Construct from a DN
	GenName(const DN& dn);
	// Copy constructor
	GenName(const GenName& that);
	// Destructor
	virtual ~GenName()									{ Clear(); }

	// Assignment operators
	GenName& operator=(const SNACC::GeneralName& snaccGN);	// Assign from a SNACC GeneralName
	GenName& operator=(const DN& dn);						// Assign from a DN
	GenName& operator=(const GenName& other);				// Assign from another GenName

	// Comparison operators
	bool operator==(const GenName& rhs) const;
	bool operator!=(const GenName& rhs) const			{ return !operator==(rhs); }
	bool operator<(const GenName& rhs) const;

	// Returns the type of this GeneralName
	Type GetType() const								{ return m_type; }
	// Returns the name form of this GeneralName
	Form& GetName()										{ return m_name; }
	const Form& GetName() const							{ return m_name; }
	// Set this GenName to the specified name form and type
	void Set(const Form& name, Type type);
	// Fill in the SNACC form of this GeneralName
	void FillSnaccGenName(SNACC::GeneralName& snacc) const;
	// Fill in the C form of this GeneralName
	void FillGenNameStruct(Gen_name_struct& genName) const;
	// Get the C form of this GeneralName
	Gen_name_struct* GetGenNameStruct() const;

protected:
	Type m_type;
	Form m_name;

private:
	void Clear(void);
};


///////////////////////////////
// GenNames class definition //
///////////////////////////////
class CM_API GenNames : public std::list<GenName>
{
public:
	// Default constructor
	GenNames()											{}
	// Constructor to create from a SNACC GeneralNames
	GenNames(const SNACC::GeneralNames& snaccGNs)		{ operator=(snaccGNs); }

	// Assignment operator
	GenNames& operator=(const SNACC::GeneralNames& snaccGNs);	// Assign from a SNACC GeneralNames

	// Fill in the SNACC form of this GenName list
	void FillSnacc(SNACC::GeneralNames& snacc) const;
	// Get the SNACC form of this GenName list
	SNACC::GeneralNames* GetSnacc() const;

	// Returns true if the GenName is present in this list
	bool IsPresent(const GenName& gn) const;
	// Returns true if at least one of GenNames is present in this list
	bool IsOnePresent(const GenNames& that) const;

	// Find first GenName of the specified type
	const_iterator Find(GenName::Type type) const;
	// Find next GenName of the specified type beyond previous iterator
	const_iterator FindNext(const_iterator iPrev, GenName::Type type) const;
	// Get the C list of these GeneralNames
	Gen_names_struct* GetGenNamesList() const;
};


/////////////////////////////////////
// GeneralSubtree class definition //
/////////////////////////////////////
class CM_API GeneralSubtree
{
public:
	// Default constructor
	GeneralSubtree();
	// Construct from a base, min distance, and optional max distance
	GeneralSubtree(const GenName& baseGN, long minDistance,
		long maxDistance = -1);
	// Construct from a SNACC GeneralSubtree
	GeneralSubtree(const SNACC::GeneralSubtree& snacc);

	// Assignment operator
	GeneralSubtree& operator=(const SNACC::GeneralSubtree& snacc);	// Assign from a SNACC GeneralSubtree

	// Comparison operators
	bool operator==(const GeneralSubtree& rhs) const;
	bool operator!=(const GeneralSubtree& rhs) const	{ return !operator==(rhs); }
	bool operator<(const GeneralSubtree& rhs) const		{ return (base < rhs.base); }

	// Returns true if the specified DN is within this subtree
	bool IsNameWithin(const DN& dn) const;
	// Returns true if the specified GenName is within this subtree
	bool IsNameWithin(const GenName& gn) const;
	// Returns true if the other subtree's base has the same name form
	bool IsSameType(const GeneralSubtree& other) const;
	// Fill in the SNACC form of this subtree
	void FillSnaccSubtree(SNACC::GeneralSubtree& snacc) const;
	// Get the C form of this subtree
	Subtree_struct* GetSubtreeStruct() const;

	// Member variables
	GenName base;
	long min;
	long max;				// optional -- set to -1 if no maximum

};


//////////////////////////////////////
// GeneralSubtrees class definition //
//////////////////////////////////////
class CM_API GeneralSubtrees : public std::list<GeneralSubtree>
{
public:
	// Default constructor
	GeneralSubtrees()											{}
	// Construct from a SNACC GeneralSubtrees
	GeneralSubtrees(const SNACC::GeneralSubtrees& snacc);

	// Operator to assign from a SNACC GeneralSubtrees
	GeneralSubtrees& operator=(const SNACC::GeneralSubtrees& snacc);

	// Returns true if the specified GenNames are within these subtrees
	// (using either the rules for permitted or excluded subtrees)
	bool AreNamesWithin(const GenNames& names,
		bool usePermittedRules = true) const;
	// Returns true if the specified DN is within these subtrees
	bool IsNameWithin(const DN& dn, bool usePermittedRules = true) const;
	// Returns true if the specified GenName is within these subtrees
	bool IsNameWithin(const GenName& gn, bool usePermittedRules = true) const;
	// Get the SNACC form of these GeneralSubtrees
	SNACC::GeneralSubtrees* GetSnacc() const;
	// Get the C form of this subtree list
	Subtree_struct* GetSubtreeList() const;
};


} // end of nested ASN namespace

} // end of CML namespace


// Method to output string form of IPAddress
CM_API std::ostream& operator<<(std::ostream& os,
								const CML::ASN::IPAddress& ipAddr);


#endif // _CMLASN_NAME_H
