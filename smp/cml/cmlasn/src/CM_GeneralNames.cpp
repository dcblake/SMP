/*****************************************************************************
File:     CM_GeneralNames.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the GenNames, GenName, and DN classes and the
		  CM_DecodeDN function.

Created:  16 July 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  17 March 2004

Version:  2.4

*****************************************************************************/


////////////////////
// Included Files //
////////////////////
#ifdef WIN32
	#pragma warning(disable: 4018 4146)	// Disable signed/unsigned mismatch warnings
	#pragma warning(disable: 4710)		// Disable function not inlined warning
#else
	#ifdef SCO_SV
		// SCO doesn't have a const char* strccasecmp
		int strcasecmp(const char *, const char *);
	#endif

	#define stricmp strcasecmp
#endif // WIN32
#include "cmlasn_internal.h"

// Using CML::ASN namespace
using namespace CML::ASN;


//////////////////////
// Type Definitions //
//////////////////////
enum AttributeTypeFlag
{
//	BIT_STRING			= 1,
//	OID_TYPE,
//	OCTET_STRING,
//	NUMERIC_STRING,
	PRINTABLE_STRING	= 5,
	IA5_STRING,
	DIRECTORY_STRING,
	UNKNOWN_TYPE,		// ASN.1 encoded types
};

struct AttribOidRec
{
    const char *dotForm;
    const char *abbrev;
	AttributeTypeFlag typeFlag;
};

struct StrElmt
{
	const char* str;
	unsigned int len;
};

typedef std::list<StrElmt> StringList;



/////////////////////////
// Function Prototypes //
/////////////////////////
static bool operator==(const SNACC::DirectoryString& lhs,
					   const SNACC::DirectoryString& rhs);
static bool operator!=(const SNACC::DirectoryString& lhs,
					   const SNACC::DirectoryString& rhs);
static bool operator<(const SNACC::DirectoryString& lhs,
					  const SNACC::DirectoryString& rhs);
static void buildTypeValueString(const SNACC::AsnOid& asnOid,
								 const char* abbrev, std::string& valueStr,
								 bool valueIsHex);
static void cvtAsnValue2Str(std::string& str, const SNACC::AsnBuf& asnBuf);
static bool cvtAttribValue2String(std::string& str,
								  const SNACC::AsnAnyDefinedBy& value);
static void cvtDirectoryString2Str(std::string& utf8String,
								   const SNACC::DirectoryString& dirStr);
static Any_struct* cvtOtherNameToAny(const SNACC::Other_Name& snacc);
static void cvtRDN2String(std::string& strRDN,
						  const SNACC::RelativeDistinguishedName& rdn);
static void cvtStr2RDN(SNACC::RelativeDistinguishedName& rdn,
					   const char* strRDN, unsigned int strLen);
static void cvtStr2ATDV(SNACC::AttributeTypeAndDistinguishedValue& atdv,
						const StrElmt& strATDV);
static void cvtStr2AttribValue(SNACC::AsnAnyDefinedBy& value,
							   const StrElmt& valueStr, unsigned int iStart,
							   AttributeTypeFlag type);
static bool cvtStr2Buffer(std::string& buffer, const StrElmt& valueStr,
						  unsigned int iStart, bool isTypeKnown);
static void cvtAttribValue2IA5String(std::string& str,
									 const SNACC::AsnAnyDefinedBy& value);
static StringList* parseLDAPstring(const char* string, unsigned int len,
								   const char* separatorChars);
//static bool isPrintable(const std::string& str);
static bool isSpecial(char c);
static bool isHexChar(char c);
static uchar hexPair2Bin(char c1, char c2);
static const char* getAttribOID(const char* abbrev, unsigned int len);
static const char* getAttribAbbrev(const SNACC::AsnOid& oid);
static AttributeTypeFlag getAttribType(SNACC::AsnOid& asnOid);


//////////////////////////////
// More Function Prototypes //
//////////////////////////////
static void addAttribute(const char *attr, const char *val,
						 std::string& orAddr);
static void cvtDomainDefAttribs(const SNACC::BuiltInDomainDefinedAttributes& ddAttrs,
								std::string& orAddr);



static char* cvtORAddressToString(const SNACC::ORAddress& addr);
static char* cvtPersonalName2cStr(SNACC::PersonalName& snaccName,
								  bool& oneString);
static void cvtTeletexDomainDefAttribs(const SNACC::TeletexDomainDefinedAttributes& ddAttrs,
									   std::string& orAddr);
static char* cvtTeletexPersonalName2cStr(SNACC::TeletexPersonalName& snaccName,
										 bool& oneString);

const SNACC::AsnAnyDefinedBy* findExtAttrValue(const SNACC::ExtensionAttributes& extAttrs,
											   int extAttrType);


//////////////////////
// Global Variables //
//////////////////////
extern const AttribOidRec gRdnAttribTable[];	// Located at end of this file



//////////////////////////
// CM_DecodeDN function //
//////////////////////////
short CM_DecodeDN(Bytes_struct* encodedDN, char **decodedDN)
{
	// Check parameters
	if ((encodedDN == NULL) || (encodedDN->data == NULL) ||
		(decodedDN == NULL))
		return CMLASN_INVALID_PARAMETER;

	// Initialize result
	*decodedDN = NULL;

	try {
		// Construct a temporary Bytes object
		Bytes asnData(encodedDN->num, encodedDN->data);

		// Decode and copy the DN
		DN tmpDN(asnData);
		*decodedDN = strdup(tmpDN);
		if (*decodedDN == NULL)
			return CMLASN_MEMORY_ERROR;
		
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


///////////////////////////////////
// GenNames class implementation //
///////////////////////////////////
GenNames& GenNames::operator=(const SNACC::GeneralNames& snaccGNs)
{
	if (snaccGNs.empty())
		throw ASN_EXCEPTION("SNACC::GeneralNames must contain at least one GeneralName");

	try {
		clear();	// Clear the existing list

		SNACC::GeneralNames::const_iterator i;
		for (i = snaccGNs.begin(); i != snaccGNs.end(); ++i)
			push_back(*i);

		return *this;
	}
	catch (...) {
		clear();
		throw;
	}
}


bool GenNames::IsOnePresent(const GenNames& that) const
{
	for (GenNames::const_iterator i = that.begin(); i != that.end(); i++)
	{
		if (IsPresent(*i))
			return true;
	}
	return false;
}


void GenNames::FillSnacc(SNACC::GeneralNames& snacc) const
{
	for (const_iterator i = begin(); i != end(); ++i)
		i->FillSnaccGenName(*snacc.append());
}


SNACC::GeneralNames* GenNames::GetSnacc() const
{
	SNACC::GeneralNames* pList = NULL;

	try {
		pList = new SNACC::GeneralNames();
		if (pList == NULL)
			throw MEMORY_EXCEPTION;

		FillSnacc(*pList);
		return pList;
	}
	catch (...) {
		delete pList;
		throw;
	}
}


bool GenNames::IsPresent(const GenName& gn) const
{
	for (const_iterator i = begin(); i != end(); i++)
	{
		if (*i == gn)
			return true;
	}
	return false;
}


GenNames::const_iterator GenNames::Find(GenName::Type type) const
{
	const_iterator i;
	for (i = begin(); (i != end()) && (i->GetType() != type); i++)
		;
	return i;
}


GenNames::const_iterator GenNames::FindNext(const_iterator iPrev,
											GenName::Type type) const
{
	if (iPrev == NULL)
		return end();
	if (iPrev == end())
		return iPrev;

	for (++iPrev; (iPrev != end()) && (iPrev->GetType() != type); iPrev++)
		;
	return iPrev;

}


// Get the C list of these GeneralNames
Gen_names_struct* GenNames::GetGenNamesList() const
{
	Gen_names_struct* result = NULL;
	try {
		for (const_reverse_iterator i = rbegin(); i != rend(); i++)
		{
			Gen_names_struct* pNew = (Gen_names_struct*)
				malloc(sizeof(Gen_names_struct));
			if (pNew == NULL)
				throw MEMORY_EXCEPTION;

			pNew->next = result;
			result = pNew;
			i->FillGenNameStruct(pNew->gen_name);
		}
		return result;
	}
	catch (...) {
		Internal::FreeGenNames(result);
		throw;
	}
}


//////////////////////////////////
// GenName class implementation //
//////////////////////////////////
GenName::GenName(Type nameType)
{
	m_type = nameType;
	switch (m_type)
	{
	case OTHER:
		m_name.other = new SNACC::Other_Name;
		if (m_name.other == NULL)
			throw MEMORY_EXCEPTION;
		break;

	case RFC822:
	case DNS:
	case URL:
		m_name.name = new char[1];
		if (m_name.name == NULL)
			throw MEMORY_EXCEPTION;
		*m_name.name = '\0';
		break;

	case X400:
		m_name.x400 = new SNACC::ORAddress;
		if (m_name.x400 == NULL)
			throw MEMORY_EXCEPTION;
		break;

	case X500:
		m_name.dn = new DN();
		if (m_name.dn == NULL)
			throw MEMORY_EXCEPTION;
		break;

	case EDI:
		m_name.ediParty = new SNACC::EDIPartyName;
		if (m_name.ediParty == NULL)
			throw MEMORY_EXCEPTION;
		break;

	case IP_ADDR:
		m_name.ipAddr = new IPAddress;
		if (m_name.ipAddr == NULL)
			throw MEMORY_EXCEPTION;
		break;

	case REG_OID:
		m_name.regID = new SNACC::AsnOid;
		if (m_name.regID == NULL)
			throw MEMORY_EXCEPTION;
		break;

	default:
		throw EXCEPTION_STR(CMLASN_INVALID_PARAMETER, "Invalid GenName type");
	}
}


GenName::GenName(const SNACC::GeneralName& snaccGN)
{
	m_type = URL;
	m_name.name = NULL;
	operator=(snaccGN);
}


GenName::GenName(const Form& name, Type type)
{
	m_type = URL;
	m_name.name = NULL;
	Set(name, type);
}


GenName::GenName(const DN& dn)
{
	m_type = URL;
	m_name.name = NULL;
	operator=(dn);
}


GenName::GenName(const GenName& that)
{
	m_type = URL;
	m_name.name = NULL;
	operator=(that);
}


GenName& GenName::operator=(const SNACC::GeneralName& snaccGN)
{
	try {
		Clear();

		switch (snaccGN.choiceId)
		{
		case SNACC::GeneralName::otherNameCid:
			m_type = OTHER;
			if (snaccGN.otherName == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::otherName is NULL");
			m_name.other = new SNACC::Other_Name(*snaccGN.otherName);
			if (m_name.other == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case SNACC::GeneralName::rfc822NameCid:
			m_type = RFC822;
			if (snaccGN.rfc822Name == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::rfc822Name is NULL");
			m_name.name = new char[snaccGN.rfc822Name->length() + 1];
			if (m_name.name == NULL)
				throw MEMORY_EXCEPTION;
			strcpy(m_name.name, snaccGN.rfc822Name->c_str());
			break;
			
		case SNACC::GeneralName::dNSNameCid:
			m_type = DNS;
			if (snaccGN.dNSName == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::dNSName is NULL");
			if ((snaccGN.dNSName->length() == 0) ||
				(*snaccGN.dNSName->c_str() == '.'))
				throw ASN_EXCEPTION("Invalid dNSName in SNACC::GeneralName");
			m_name.name = new char[snaccGN.dNSName->length() + 1];
			if (m_name.name == NULL)
				throw MEMORY_EXCEPTION;
			strcpy(m_name.name, snaccGN.dNSName->c_str());
			break;
			
		case SNACC::GeneralName::uniformResourceIdentifierCid:
			m_type = URL;
			if (snaccGN.uniformResourceIdentifier == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::uniformResourceIdentifier is NULL");
			m_name.name = new char[snaccGN.uniformResourceIdentifier->length() + 1];
			if (m_name.name == NULL)
				throw MEMORY_EXCEPTION;
			strcpy(m_name.name, snaccGN.uniformResourceIdentifier->c_str());
			break;
			
		case SNACC::GeneralName::x400AddressCid:
			m_type = X400;
			if (snaccGN.x400Address == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::x400Address is NULL");
			m_name.x400 = new SNACC::ORAddress(*snaccGN.x400Address);
			if (m_name.x400 == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case SNACC::GeneralName::directoryNameCid:
			m_type = X500;
			if (snaccGN.directoryName == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::directoryName is NULL");
			m_name.dn = new DN(*snaccGN.directoryName);
			if (m_name.dn == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case SNACC::GeneralName::ediPartyNameCid:
			m_type = EDI;
			if (snaccGN.ediPartyName == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::ediPartyName is NULL");
			m_name.ediParty = new SNACC::EDIPartyName(*snaccGN.ediPartyName);
			if (m_name.ediParty == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case SNACC::GeneralName::iPAddressCid:
			m_type = IP_ADDR;
			if (snaccGN.iPAddress == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::iPAddress is NULL");
//			if ((snaccGN.iPAddress->Len() != 4) &&
//				(snaccGN.iPAddress->Len() != 8) &&
//				(snaccGN.iPAddress->Len() != 16) &&
//				(snaccGN.iPAddress->Len() != 32))
//				throw ASN_EXCEPTION("Invalid length of SNACC::GeneralName::iPAddress");
			m_name.ipAddr = new IPAddress(*snaccGN.iPAddress);
			if (m_name.ipAddr == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case SNACC::GeneralName::registeredIDCid:
			m_type = REG_OID;
			if (snaccGN.registeredID == NULL)
				throw ASN_EXCEPTION("SNACC::GeneralName::registeredID is NULL");
			m_name.regID = new SNACC::AsnOid(*snaccGN.registeredID);
			if (m_name.regID == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		default:
			throw ASN_EXCEPTION("Unknown CHOICE in SNACC::GeneralName");
		}
		
		return *this;
	}
	catch (...) {
		Clear();
		throw;
	}
}


GenName& GenName::operator=(const DN& dn)
{
	Clear();
	m_type = X500;
	m_name.dn = new DN(dn);
	if (m_name.dn == NULL)
		throw MEMORY_EXCEPTION;
	return *this;
}


GenName& GenName::operator=(const GenName& other)
{
	if (this != &other)
		Set(other.GetName(), other.GetType());

	return *this;
}


bool GenName::operator==(const GenName& rhs) const
{
	if (this == &rhs)
		return true;

	if (m_type != rhs.m_type)
		return false;

	if ((m_name.other == NULL) || (rhs.m_name.other == NULL))
		throw Exception(CMLASN_NULL_POINTER, __FILE__, __LINE__);

	switch (m_type)
	{
	case OTHER:
		throw Exception(CMLASN_NOT_IMPLEMENTED, __FILE__, __LINE__);

	case RFC822:
	case DNS:
	case URL:
		return (stricmp(m_name.name, rhs.m_name.name) == 0);
		
	case X400:
		throw Exception(CMLASN_NOT_IMPLEMENTED, __FILE__, __LINE__);
		
	case X500:
		return (*m_name.dn == *rhs.m_name.dn);
		
	case EDI:
		{
			if ((m_name.ediParty->nameAssigner != NULL) &&
				(rhs.m_name.ediParty->nameAssigner != NULL))
			{
				if (*m_name.ediParty->nameAssigner !=
					*rhs.m_name.ediParty->nameAssigner)
					return false;
			}
			else if ((m_name.ediParty->nameAssigner != NULL) ||
				(rhs.m_name.ediParty->nameAssigner != NULL))
				return false;

			return (m_name.ediParty->partyName ==
				rhs.m_name.ediParty->partyName);
		}
		
	case IP_ADDR:
		return (*m_name.ipAddr == *rhs.m_name.ipAddr);
		
	case REG_OID:
		return (*m_name.regID == *rhs.m_name.regID);

	default:
		return false;
	}
}


bool GenName::operator<(const GenName& rhs) const
{
	if (this == &rhs)
		return false;

	if (m_type < rhs.m_type)
		return true;
	else if (m_type > rhs.m_type)
		return false;

	if ((m_name.other == NULL) || (rhs.m_name.other == NULL))
		throw Exception(CMLASN_NULL_POINTER, __FILE__, __LINE__);

	switch (m_type)
	{
	case OTHER:
		throw Exception(CMLASN_NOT_IMPLEMENTED, __FILE__, __LINE__);

	case RFC822:
	case DNS:
	case URL:
		return (strcmp(m_name.name, rhs.m_name.name) < 0);
		
	case X400:
		throw Exception(CMLASN_NOT_IMPLEMENTED, __FILE__, __LINE__);
		
	case X500:
		return (*m_name.dn < *rhs.m_name.dn);
		
	case EDI:
		{
			if ((m_name.ediParty->nameAssigner != NULL) &&
				(rhs.m_name.ediParty->nameAssigner != NULL))
			{
				if (*rhs.m_name.ediParty->nameAssigner <
					*m_name.ediParty->nameAssigner)
					return false;
			}
			else if ((m_name.ediParty->nameAssigner == NULL) &&
				(rhs.m_name.ediParty->nameAssigner != NULL))
				return true;
			else if ((m_name.ediParty->nameAssigner != NULL) &&
				(rhs.m_name.ediParty->nameAssigner == NULL))
				return false;

			return (m_name.ediParty->partyName <
				rhs.m_name.ediParty->partyName);
		}
		
	case IP_ADDR:
		return (*m_name.ipAddr < *rhs.m_name.ipAddr);

	case REG_OID:
		return (strcmp(*m_name.regID, *rhs.m_name.regID) < 0);

	default:
		return false;
	}
}


void GenName::FillSnaccGenName(SNACC::GeneralName& snacc) const
{
	if (m_name.other == NULL)
		throw Exception(CMLASN_NULL_POINTER, __FILE__, __LINE__);

	switch (m_type)
	{
	case OTHER:
		snacc.choiceId = SNACC::GeneralName::otherNameCid;
		snacc.otherName = new SNACC::Other_Name(*m_name.other);
		if (snacc.otherName == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case RFC822:
		snacc.choiceId = SNACC::GeneralName::rfc822NameCid;
		snacc.rfc822Name = new SNACC::IA5String(m_name.name);
		if (snacc.rfc822Name == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case DNS:
		snacc.choiceId = SNACC::GeneralName::dNSNameCid;
		snacc.dNSName = new SNACC::IA5String(m_name.name);
		if (snacc.dNSName == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case X400:
		snacc.choiceId = SNACC::GeneralName::x400AddressCid;
		snacc.x400Address = new SNACC::ORAddress(*m_name.x400);
		if (snacc.x400Address == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case X500:
		snacc.choiceId = SNACC::GeneralName::directoryNameCid;
		snacc.directoryName = m_name.dn->GetSnacc();
		if (snacc.directoryName == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case EDI:
		snacc.choiceId = SNACC::GeneralName::ediPartyNameCid;
		snacc.ediPartyName = new SNACC::EDIPartyName(*m_name.ediParty);
		if (snacc.ediPartyName == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case URL:
		snacc.choiceId = SNACC::GeneralName::uniformResourceIdentifierCid;
		snacc.uniformResourceIdentifier = new SNACC::IA5String(m_name.name);
		if (snacc.uniformResourceIdentifier == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case IP_ADDR:
		snacc.choiceId = SNACC::GeneralName::iPAddressCid;
		snacc.iPAddress = m_name.ipAddr->GetSnacc();
		if (snacc.iPAddress == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case REG_OID:
		snacc.choiceId = SNACC::GeneralName::registeredIDCid;
		snacc.registeredID = new SNACC::AsnOid(*m_name.regID);
		if (snacc.registeredID == NULL)
			throw MEMORY_EXCEPTION;
		break;
	}
}


void GenName::Set(const Form& name, Type type)
{
	Clear();
		
	m_type = type;
	if (name.other == NULL)
		throw Exception(CMLASN_NULL_POINTER, __FILE__, __LINE__);
		
	switch (m_type)
	{
	case OTHER:
		m_name.other = new SNACC::Other_Name(*name.other);
		if (m_name.other == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case DNS:
		// Check that the DNS name is correct
		if (*name.name == '.')
			throw EXCEPTION_STR(CMLASN_INVALID_PARAMETER, "Invalid DNS name");
	case RFC822:
	case URL:
		m_name.name = new char[strlen(name.name) + 1];
		if (m_name.name == NULL)
			throw MEMORY_EXCEPTION;
		strcpy(m_name.name, name.name);
		break;
		
	case X400:
		m_name.x400 = new SNACC::ORAddress(*name.x400);
		if (m_name.x400 == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case X500:
		m_name.dn = new DN(*name.dn);
		if (m_name.dn == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case EDI:
		m_name.ediParty = new SNACC::EDIPartyName(*name.ediParty);
		if (m_name.ediParty == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case IP_ADDR:
		m_name.ipAddr = new IPAddress(*name.ipAddr);
		if (m_name.ipAddr == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	case REG_OID:
		m_name.regID = new SNACC::AsnOid(*name.regID);
		if (m_name.regID == NULL)
			throw MEMORY_EXCEPTION;
		break;
	}
}


void GenName::Clear(void)
{
	if (m_name.other == NULL)
	{
		m_type = URL;
		return;
	}

	switch (m_type)
	{
	case OTHER:
		delete m_name.other;
		break;

	case RFC822:
	case DNS:
	case URL:
		delete[] m_name.name;
		break;
		
	case X400:
		delete m_name.x400;
		break;
		
	case X500:
		delete m_name.dn;
		break;
		
	case EDI:
		delete m_name.ediParty;
		break;
		
	case IP_ADDR:
		delete m_name.ipAddr;
		break;
		
	case REG_OID:
		delete m_name.regID;
		break;
	}

	m_type = URL;
	m_name.other = NULL;
}


// Fill in the C form of this GeneralName
void GenName::FillGenNameStruct(Gen_name_struct& genName) const
{
	std::string ediPartyName;

	// Initialize result
	genName.flag = CM_X500_NAME;
	genName.name.dn = NULL;

	try {
		switch (m_type)
		{
		case ASN::GenName::OTHER:
			if (m_name.other == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.other is NULL");
			}
			genName.flag = CM_OTHER_NAME;
			genName.name.other_name = cvtOtherNameToAny(*m_name.other);
			break;
			
		case ASN::GenName::RFC822:
			if (m_name.name == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.name is NULL");
			}
			genName.flag = CM_RFC822_NAME;
			genName.name.rfc822 = strdup(m_name.name);
			if (genName.name.rfc822 == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case ASN::GenName::DNS:
			if (m_name.name == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.name is NULL");
			}
			genName.flag = CM_DNS_NAME;
			genName.name.dns = strdup(m_name.name);
			if (genName.name.dns == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case ASN::GenName::X400:
			if (m_name.x400 == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.x400 is NULL");
			}
			genName.flag = CM_X400_ADDR;
			genName.name.x400 = cvtORAddressToString(*m_name.x400);
			break;
			
		case ASN::GenName::X500:
			if (m_name.dn == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.dn is NULL");
			}
			genName.flag = CM_X500_NAME;
			genName.name.dn = strdup(*m_name.dn);
			if (genName.name.dn == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case ASN::GenName::EDI:
			if (m_name.ediParty == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.ediParty is NULL");
			}
			genName.flag = CM_EDI_NAME;
			genName.name.ediParty = (Edi_name_struct*)calloc(1,
				sizeof(Edi_name_struct));
			if (genName.name.ediParty == NULL)
				throw MEMORY_EXCEPTION;
			
			if (m_name.ediParty->nameAssigner != NULL)
			{
				std::string nameAssigner;
				cvtDirectoryString2Str(nameAssigner,
					*m_name.ediParty->nameAssigner);
				genName.name.ediParty->name_assigner =
					strdup(nameAssigner.c_str());
				if (genName.name.ediParty->name_assigner == NULL)
					throw MEMORY_EXCEPTION;
			}
				
			cvtDirectoryString2Str(ediPartyName, m_name.ediParty->partyName);
			genName.name.ediParty->party_name = strdup(ediPartyName.c_str());
			if (genName.name.ediParty->party_name == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case ASN::GenName::URL:
			if (m_name.name == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.name is NULL");
			}
			genName.flag = CM_URL_NAME;
			genName.name.url = strdup(m_name.name);
			if (genName.name.url == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case ASN::GenName::IP_ADDR:
			if (m_name.ipAddr == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.ipAddr is NULL");
			}
			genName.flag = CM_IP_ADDR;
			genName.name.ip = strdup(m_name.ipAddr->IPAddrToStr().c_str());
			if (genName.name.ip == NULL)
				throw MEMORY_EXCEPTION;
			break;
			
		case ASN::GenName::REG_OID:
			if (m_name.regID == NULL)
			{
				throw EXCEPTION_STR(CMLASN_NULL_POINTER,
					"GenName::m_name.regID is NULL");
			}
			genName.flag = CM_REG_OID;
			genName.name.oid = m_name.regID->GetChar();
			break;
		}
	}
	catch (...) {
		Internal::FreeGenNameContent(&genName);
		throw;
	}
} // end of GenName::FillGenNameStruct()


// Get the C form of this GeneralName
Gen_name_struct* GenName::GetGenNameStruct() const
{
	Gen_name_struct* result = (Gen_name_struct*)malloc(sizeof(Gen_name_struct));
	if (result == NULL)
		throw MEMORY_EXCEPTION;

	try {
		FillGenNameStruct(*result);
		return result;
	}
	catch (...) {
		free(result);
		throw;
	}
}


////////////////////////////////////
// IPAddress class implementation //
////////////////////////////////////

// IPAddress Constructor which takes a snacc object
IPAddress::IPAddress(const SNACC::AsnOcts& snacc)
{
	m_ip4Flag = false;
	m_pIpConstraint = NULL;
	operator=(snacc);
}


// IPAddress Constructor which takes an IPAddress object
IPAddress::IPAddress(const IPAddress& that)
{
	m_ip4Flag = false;
	m_pIpConstraint = NULL;
	operator=(that);
}


// IPAddress Constructor which takes an unsigned char array IP Address
// a flag to indicate Version 6 or Version 4 and an optional constraint
IPAddress::IPAddress(const uchar* other, bool IPv6Flag, uchar* constraint)
{
	m_ip4Flag = false;
	m_pIpConstraint = NULL;
	Set(other, IPv6Flag, constraint);
}


// Reset member variables
void IPAddress::Clear()
{
	// Initialize the ip address
	memset(m_ipAddress, 0, IP_ADDRESS_LEN_V6);

	m_ip4Flag = false;

	if (m_pIpConstraint != NULL)
	{
		delete[] m_pIpConstraint;
		m_pIpConstraint = NULL;
	}
}


// Assignment operators
IPAddress& IPAddress::operator=(const SNACC::AsnOcts& snacc)
{
	// Reset member variables
	Clear();

	// Check the length of the incoming snacc object
	if (snacc.Len() == IP_ADDRESS_LEN_V4)
	{
		Set((const uchar*)snacc.c_ustr(), false, NULL);
	}
	else if (snacc.Len() == (IP_ADDRESS_LEN_V4 * 2))
	{
		Set((const uchar*)snacc.c_ustr(), false,
			(const uchar*)snacc.c_ustr() + IP_ADDRESS_LEN_V4);
	}
	else if (snacc.Len() == IP_ADDRESS_LEN_V6)
	{
		Set((const uchar*)snacc.c_ustr());
	}
	else if (snacc.Len() == (IP_ADDRESS_LEN_V6 * 2))
	{
		Set((const uchar*)snacc.c_ustr(), true,
			(const uchar*)snacc.c_ustr() + IP_ADDRESS_LEN_V6);
	}
	else
	{
		// Error - valid iPAddress can only be 4, 8, 16 or 32
		throw ASN_EXCEPTION("Invalid length of SNACC::GeneralName::iPAddress");
	}

	return *this;
}


IPAddress& IPAddress::operator=(const IPAddress& that)
{
	if (this != &that)
	{
		Clear();

		m_ip4Flag = that.m_ip4Flag;
		memcpy(m_ipAddress, that.m_ipAddress, IP_ADDRESS_LEN_V6);

		if (that.m_pIpConstraint != NULL)
		{
			m_pIpConstraint = new uchar[IP_ADDRESS_LEN_V6];
			if (m_pIpConstraint == NULL)
				throw MEMORY_EXCEPTION;
			memcpy(m_pIpConstraint, that.m_pIpConstraint, IP_ADDRESS_LEN_V6);
		}
	}

	return *this;
}


// Set:
// INPUT:  other - unsigned char pointer to 16 characters
//         IPv6Flag - true (default), input is IPv6 address;
//         false, input is IPv4
//         constraint - (optional) unsigned char pointer to 16 characters
// sets internal members based on values passed in
IPAddress& IPAddress::Set(const uchar* other, bool IPv6Flag,
                          const uchar* constraint)
{
	Clear();  // Reset member variables
	
	if (IPv6Flag == true)
	{
		if (other != NULL)
		{
			// Copy other to the ip address
			memcpy(m_ipAddress, other, IP_ADDRESS_LEN_V6);

			// If there is a constraint
			if (constraint != NULL)
			{
				// Create a new constraint
				m_pIpConstraint = new uchar[IP_ADDRESS_LEN_V6];
				if (m_pIpConstraint == NULL)
					throw MEMORY_EXCEPTION;

				// Copy in the constraint
				memcpy(m_pIpConstraint, constraint, IP_ADDRESS_LEN_V6);
			}
		}
	}
	else if (other != NULL)
	{
		m_ip4Flag = true;

		// Copy other to the last 4 characters of the ip address
		memcpy(&m_ipAddress[IP_ADDRESS_LEN_V6 - IP_ADDRESS_LEN_V4],
			other, IP_ADDRESS_LEN_V4);
			
		// If there is a constraint
		if (constraint != NULL)
		{
			// Create a new constraint
			m_pIpConstraint = new uchar[IP_ADDRESS_LEN_V6];
			if (m_pIpConstraint == NULL)
				throw MEMORY_EXCEPTION;
			memset(m_pIpConstraint, 0, IP_ADDRESS_LEN_V6);
			
			// Copy the constraint to the last 4 characters of the constraint
			memcpy(&m_pIpConstraint[IP_ADDRESS_LEN_V6 - IP_ADDRESS_LEN_V4],
				constraint, IP_ADDRESS_LEN_V4);
		}
	}
	
	return *this;
}


// Comparison operator
// This function takes an IPAddress object as a parameter, however no constraints
// are allowed in this parameter, if one exists, then the function will not do a
// comparison check and will return a value of false.  Constraints are only allowed
// on the left-hand-side of this operator.
bool IPAddress::operator==(const IPAddress& rhs) const
{
   // BOTH SIDES MUST HAVE CONSTRAINTS, OR NEITHER SIDE MUST HAVE CONSTRAINTS
	if (((m_pIpConstraint != NULL) && (rhs.m_pIpConstraint == NULL))
		|| ((m_pIpConstraint == NULL) && (rhs.m_pIpConstraint != NULL)))
	{
		return false;
	}

   // Compare the two ip address values
   if (memcmp(m_ipAddress, rhs.m_ipAddress, IP_ADDRESS_LEN_V6))
   {
      return false;
   }

   // LHS HAS CONSTRAINT
   if (m_pIpConstraint != NULL)
   {
      // RHS HAS CONSTRAINT - O.K. COMPARE THEM
      if (memcmp(m_pIpConstraint, rhs.m_pIpConstraint, IP_ADDRESS_LEN_V6))
      {
         return false;
      }
   }

   return true;
}


bool IPAddress::operator<(const IPAddress& rhs) const
{
	return (memcmp(m_ipAddress, rhs.m_ipAddress, IP_ADDRESS_LEN_V6) < 0);
}


// Extract SNACC values
// INPUT: NONE (this)
// OUTPUT: AsnOcts pointer containing 4, 8, 16 or 32 characters depending
//         on whether this is a IPv4 or IPv6 with or without a constraint
SNACC::AsnOcts* IPAddress::GetSnacc(void) const
{
	SNACC::AsnOcts* results;
	char            tmpBuf[(IP_ADDRESS_LEN_V6 * 2)];
	int             len = 0;
	
	// Check version and check for (not a) IPv4-mapped IPv6 address
	if ((IsIP4()) &&
		(!((m_ipAddress[10] == 0xFF) && (m_ipAddress[11] == 0xFF))))
	{
		len = IP_ADDRESS_LEN_V4; // len = 4
		// Only copy the last 4 characters
		memcpy(tmpBuf, &m_ipAddress[(IP_ADDRESS_LEN_V6 - len)], len);
		if (m_pIpConstraint != NULL)
		{
            // Only copy the last 4 characters
            memcpy(&tmpBuf[len], &m_pIpConstraint[(IP_ADDRESS_LEN_V6 - len)],
				len);
            len = len + IP_ADDRESS_LEN_V4; // len = 4 + 4
		}
	}
	else  // If this is either a IPv4-mapped IPv6 address or a IPv6 address
	{     // output Version 6 IP Address
		len = IP_ADDRESS_LEN_V6; // len = 16
		memcpy(tmpBuf, m_ipAddress, IP_ADDRESS_LEN_V6);
		if (m_pIpConstraint != NULL)
		{
			memcpy(&tmpBuf[IP_ADDRESS_LEN_V6], m_pIpConstraint, IP_ADDRESS_LEN_V6);
			len = len + IP_ADDRESS_LEN_V6; // len = 16 + 16
		}
	}
	results = new SNACC::AsnOcts(tmpBuf, len);
	if (results == NULL)
		throw MEMORY_EXCEPTION;
	return results;
}


// Comparison function
// This function takes an IPAddress object as a parameter, however no constraints
// are allowed in this parameter, if one exists, then the function will not do a
// comparison check and will return a value of false.  Constraints are only allowed
// on the left-hand-side of this operator.
bool IPAddress::Matches(const IPAddress& rhs) const
{
	// NO CONSTRAINTS ARE ALLOWED ON THE RIGHT-HAND-SIDE
	if (rhs.m_pIpConstraint != NULL)
	{
		return false;
	}
	
	// Check for illegal addresses
	static const uchar kZeroBuf[IP_ADDRESS_LEN_V6 - 1] =
	{ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	if ((memcmp(m_ipAddress, kZeroBuf, sizeof(kZeroBuf)) == 0) &&
		((m_ipAddress[IP_ADDRESS_LEN_V6] == 0) ||
		(m_ipAddress[IP_ADDRESS_LEN_V6] == 1)))
		return false;
	if ((memcmp(rhs.m_ipAddress, kZeroBuf, sizeof(kZeroBuf)) == 0) &&
		((rhs.m_ipAddress[IP_ADDRESS_LEN_V6] == 0) ||
		(rhs.m_ipAddress[IP_ADDRESS_LEN_V6] == 1)))
		return false;
	
	// Error Can't compare V4 Address with V6 Address
	if (m_ip4Flag != rhs.m_ip4Flag)
		return false;
	
	// If this is IPv4 only compare the last 4 characters
	int startpos = 0;
	if (m_ip4Flag)
		startpos = 12;
	
	if (m_pIpConstraint == NULL)
	{
		// Compare each character
		for (int i = startpos; i < IP_ADDRESS_LEN_V6; i++)
		{
			// If they do not match, we are done!
			if (m_ipAddress[i] != rhs.m_ipAddress[i])
				return false;
		}
	}
	else
	{
		// Has constraint - compare each character
		for (int i = startpos; i < IP_ADDRESS_LEN_V6; i++)
		{
			// If they do not match, we are done!
			if (m_ipAddress[i] != (rhs.m_ipAddress[i] & m_pIpConstraint[i]))
				return false;
		}
	}
	
	return true;
}


// Convert IP Address to string
// Prints either IPv4 or IPv6 address in string form
// Version 6: x:x:x:x:x:x:x:x [x:x:x:x:x:x:x:x]
// Version 4: x:x:x:x:x:x:d.d.d.d [x:x:x:x:x:x:d.d.d.d]
std::string IPAddress::IPAddrToStr() const 
{
	std::string result;
	char tempResult[110];
	
	// Initialize the character array
	memset(tempResult, 0, sizeof(tempResult));
	
	if (IsIP4())
	{
		// Format for Version 4: [x:x:x:x:x:]x:d.d.d.d [[x:x:x:x:x:]x:d.d.d.d]
		// Check for IPv4-mapped IPv6 address (rfc1884)
		if ((m_ipAddress[10] == 0xFF) && (m_ipAddress[11] == 0xFF))
		{
			result.operator +=("FFFF:");
		}
		
		// Format the last four characters as period separated decimal values
		sprintf(tempResult, "%u.%u.%u.%u", m_ipAddress[12],
			m_ipAddress[13], m_ipAddress[14], m_ipAddress[15]);
		// Append this to result string
		result.operator +=(tempResult);
		
		// Check for a constraint
		if (m_pIpConstraint != NULL)
		{
			// Check for IPv4-mapped IPv6 address (rfc1884)
			if ((m_pIpConstraint[10] == 0xFF) && (m_pIpConstraint[11] == 0xFF))
			{
				result.operator +=(" FFFF:");
			}
			// Initialize the character array
			memset(tempResult, 0, sizeof(tempResult));
			// Format the last four characters as period separated decimal values
			// preceeded by a space (result will be two space separated strings)
			sprintf(tempResult, " %u.%u.%u.%u", m_pIpConstraint[12],
				m_pIpConstraint[13], m_pIpConstraint[14], m_pIpConstraint[15]);
			// Append this to result string
			result.operator +=(tempResult);
		}
	}
	else
	{
		// Format for Version 6: x:x:x:x:x:x:x:x [x:x:x:x:x:x:x:x]
		int intArr[IP_ADDRESS_LEN_V6];
		// Initialize the integer array
		memset(intArr, 0, sizeof(intArr));
		// Convert the 16 octal values to 8 hexidecimal values
		// storing each new value in the integer array
		for (ushort i = 0, j = 0; i < (IP_ADDRESS_LEN_V6/2); i++, j++)
		{
			intArr[i] = m_ipAddress[j];
			intArr[i] <<= 8;
			intArr[i] |= m_ipAddress[++j];
		}
		// Format results as 8 colon separaterd hexidecimal values 
		sprintf(tempResult, "%X:%X:%X:%X:%X:%X:%X:%X",
			intArr[0], intArr[1], intArr[2], intArr[3],
			intArr[4], intArr[5], intArr[6], intArr[7]);
		// Append this to result string
		result.operator +=(tempResult);
		
		// Check for a constraint
		if (m_pIpConstraint != NULL)
		{
			// Initialize the integer array
			memset(intArr, 0, sizeof(intArr));
			// Convert the 16 octal values to 8 hexidecimal values
			// storing each new value in the integer array
			for (ushort i = 0, j = 0; i < (IP_ADDRESS_LEN_V6/2); i++, j++)
			{
				intArr[i] = m_pIpConstraint[i];
				intArr[i] <<= 8;
				intArr[i] |= m_pIpConstraint[++j];
			}
			// Initialize the character array
			memset(tempResult, 0, sizeof(tempResult));
			// Format results as 8 colon separaterd hexidecimal values
			// preceeded by a space (result will be two space separated strings)
			sprintf(tempResult, " %X:%X:%X:%X:%X:%X:%X:%X",
				intArr[0], intArr[1], intArr[2], intArr[3],
				intArr[4], intArr[5], intArr[6], intArr[7]);
			// Append this to result string
			result.operator +=(tempResult);
		}
	}
	
	return result;
	
}


std::ostream& operator<<(std::ostream& os, const IPAddress& ipAddr)
{
	return os << ipAddr.IPAddrToStr().c_str();
}


/////////////////////////////
// DN class implementation //
/////////////////////////////
DN& DN::operator=(const SNACC::Name& snaccName)
{
	if (snaccName.rdnSequence == NULL)
		throw ASN_EXCEPTION("SNACC::Name::rdnSequence field is NULL");
	return operator=(*snaccName.rdnSequence);
}


DN& DN::operator=(const SNACC::DistinguishedName& snacc)
{
	m_strDN.erase();
	m_rdnList.clear();

	try {
		SNACC::DistinguishedName::const_iterator i;
		for (i = snacc.begin(); i != snacc.end(); ++i)
			m_rdnList.push_back(*i);

		BuildDNString();
		return *this;
	}
	catch (...) {
		m_strDN.erase();
		m_rdnList.clear();
		throw;
	}
}


DN& DN::operator=(const char* stringDN)
{
	m_strDN.erase();
	m_rdnList.clear();

	StringList* pRDNList = NULL;
	try {
		if (stringDN != NULL)
		{
			pRDNList = parseLDAPstring(stringDN, strlen(stringDN), ",;");

			for (StringList::iterator i = pRDNList->begin(); i !=
				pRDNList->end(); i++)
			{
				RelativeDN tempRDN(i->str, i->len);
				m_rdnList.push_front(tempRDN);
			}

			// Delete temporary RDN string list
			delete pRDNList;
		}

		BuildDNString();
		return *this;
	}
	catch (...) {
		m_strDN.erase();
		m_rdnList.clear();
		delete pRDNList;
		throw;
	}
}


DN& DN::operator=(const Bytes& asn)
{
	Decode(asn);
	return *this;
}


DN& DN::operator=(const DN& other)
{
	if (this != &other)
	{
		try {
			m_rdnList.clear();
			m_strDN = other.m_strDN;

			// Copy the list of RelativeDNs
			std::list<RelativeDN>::const_iterator i;
			for (i = other.m_rdnList.begin(); i != other.m_rdnList.end(); i++)
				m_rdnList.push_back(*i);
		}
		catch (...) {
			m_strDN.erase();
			m_rdnList.clear();
			throw;
		}
	}

	return *this;
}


bool DN::operator==(const DN& rhs) const
{
	if (this == &rhs)
		return true;

	return (stricmp(m_strDN.c_str(), rhs.m_strDN.c_str()) == 0);
}


bool DN::operator<(const DN& rhs) const
{
	if (this == &rhs)
		return false;

	return (stricmp(m_strDN.c_str(), rhs.m_strDN.c_str()) < 0);
}


DN& DN::operator+=(const DN& rhs)
{
	if (rhs.IsEmpty())
		return *this;
	if (IsEmpty())
		return operator=(rhs);

	m_rdnList.insert(m_rdnList.end(), rhs.GetRDNList().begin(),
		rhs.GetRDNList().end());

	// Prepend the rhs DN string to this DN string
	m_strDN.insert(m_strDN.begin(), 1, ',');
	m_strDN.insert(0, rhs.m_strDN);

	return *this;
}


DN& DN::operator+=(const RelativeDN& rhs)
{
	m_rdnList.push_back(rhs);

	if (m_strDN.empty())
	{
		// Copy the RDN's string value
		m_strDN = rhs;
	}
	else
	{
		// Prepend the rhs DN string to this DN string
		m_strDN.insert(m_strDN.begin(), 1, ',');
		m_strDN.insert(0, rhs);
	}

	return *this;
}


ulong DN::Decode(const Bytes& asn)
{
	// Decode the DN
	SNACC::DistinguishedName snaccDN;
	SNACC::AsnLen nBytesDecoded = asn.Decode(snaccDN,
		"SNACC::DistinguishedName");

	// Assign this DN to the newly decoded DistinguishedName
	operator=(snaccDN);

	return nBytesDecoded;
}


ulong DN::Encode(Bytes& asn) const
{
	// Get the SNACC form of this DN
	SNACC::DistinguishedName* pSnaccDN = GetSnaccDN();

	try {
		// Encode the DN
		ulong numEncoded = asn.Encode(*pSnaccDN, "SNACC::DistinguishedName");

		// Delete the temporary variable
		delete pSnaccDN;

		return numEncoded;
	}
	catch (...) {
		delete pSnaccDN;
		throw;
	}
}


void DN::FillSnacc(SNACC::Name& snacc) const
{
	snacc.choiceId = SNACC::Name::rdnSequenceCid;
	snacc.rdnSequence = GetSnaccDN();
}


SNACC::Name* DN::GetSnacc() const
{
	SNACC::Name* pResult = NULL;
	try {
		pResult = new SNACC::Name;
		if (pResult == NULL)
			throw MEMORY_EXCEPTION;

		FillSnacc(*pResult);
		return pResult;
	}
	catch (...) {
		delete pResult;
		throw;
	}
}


SNACC::DistinguishedName* DN::GetSnaccDN() const
{
	SNACC::DistinguishedName* pResult = new SNACC::DistinguishedName();
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		std::list<RelativeDN>::const_iterator i;
		for (i = m_rdnList.begin(); i != m_rdnList.end(); ++i)
			pResult->push_back(i->GetSnaccRDN());
		return pResult;
	}
	catch (...) {
		delete pResult;
		throw;
	}
}


bool DN::IsEmpty() const
{
	if (m_strDN.empty() || m_rdnList.empty())
		return true;
	else
		return false;
}


ulong DN::CompareRDNs(const DN& rhs) const
{
	ulong numEqual = 0;
	std::list<RelativeDN>::const_iterator iLHS = m_rdnList.begin();
	std::list<RelativeDN>::const_iterator iRHS = rhs.m_rdnList.begin();
	while ((iLHS != m_rdnList.end()) && (iRHS != rhs.m_rdnList.end()))
	{
		if (*iLHS != *iRHS)
			break;

		numEqual++;

		iLHS++;
		iRHS++;
	}

	return numEqual;
}


void DN::BuildDNString(void)
{
	m_strDN.erase();

	// Concatenate the strings together
	std::list<RelativeDN>::reverse_iterator i;
	for (i = m_rdnList.rbegin(); i != m_rdnList.rend(); i++)
	{
		if ((const char*)(*i) != NULL)
		{
			if (i == m_rdnList.rbegin())
				m_strDN = *i;
			else
			{
				m_strDN.append(1, ',');
				m_strDN.append(*i);
			}
		}
	}
}


/////////////////////////////////////
// RelativeDN class implementation //
/////////////////////////////////////
RelativeDN::RelativeDN(const char* stringRDN, unsigned int strLen)
{
	Set(stringRDN, strLen);
}


RelativeDN::RelativeDN(const SNACC::RelativeDistinguishedName& snaccRDN)
{
	operator=(snaccRDN);
}


RelativeDN& RelativeDN::operator=(const SNACC::RelativeDistinguishedName& snacc)
{
	try {
		m_rdn.erase();
		m_snaccRDN = snacc;
		cvtRDN2String(m_rdn, m_snaccRDN);
		return *this;
	}
	catch (...) {
		m_snaccRDN.clear();
		m_rdn.erase();
		throw;
	}
}


RelativeDN& RelativeDN::operator=(const char* stringRDN)
{
	Set(stringRDN);
	return *this;
}


RelativeDN& RelativeDN::operator=(const RelativeDN& other)
{
	if (this != &other)
	{
		try {
			m_rdn.erase();

			m_snaccRDN = other.m_snaccRDN;
			m_rdn = other.m_rdn;
		}
		catch (...) {
			m_snaccRDN.clear();
			m_rdn.erase();
			throw;
		}
	}
	return *this;
}


bool RelativeDN::operator==(const RelativeDN& rhs) const
{
	if (this == &rhs)
		return true;

	return (stricmp(m_rdn.c_str(), rhs.m_rdn.c_str()) == 0);
}


void RelativeDN::Set(const char* stringRDN, unsigned int stringLen)
{
	if (stringRDN == NULL)
		throw Exception(CMLASN_INVALID_PARAMETER, __FILE__, __LINE__);

	m_snaccRDN.clear();
	m_rdn.erase();
	try {
		if (stringLen == 0)
			stringLen = strlen(stringRDN);
		cvtStr2RDN(m_snaccRDN, stringRDN, stringLen);
		cvtRDN2String(m_rdn, m_snaccRDN);
	}
	catch (...) {
		m_snaccRDN.clear();
		m_rdn.erase();
		throw;
	}
}


bool RelativeDN::containsPKCS9EmailAddress(std::string& email) const
{
	SNACC::RelativeDistinguishedName::const_iterator i;
	for (i = m_snaccRDN.begin(); i != m_snaccRDN.end(); ++i)
	{
		if (i->type == SNACC::emailAddressAttribute)
		{
			cvtAttribValue2IA5String(email, i->value);
			return true;
		}
	}
	return false;
}


////////////////////////
// Internal Functions //
////////////////////////
bool operator==(const SNACC::DirectoryString& lhs,
				const SNACC::DirectoryString& rhs)
{
	std::string lhsStr, rhsStr;
	cvtDirectoryString2Str(lhsStr, lhs);
	cvtDirectoryString2Str(rhsStr, rhs);
	return (stricmp(lhsStr.c_str(), rhsStr.c_str()) == 0);
}


bool operator!=(const SNACC::DirectoryString& lhs,
				const SNACC::DirectoryString& rhs)
{
	return !operator==(lhs, rhs);
}


bool operator<(const SNACC::DirectoryString& lhs,
			   const SNACC::DirectoryString& rhs)
{
	std::string lhsStr, rhsStr;
	cvtDirectoryString2Str(lhsStr, lhs);
	cvtDirectoryString2Str(rhsStr, rhs);
	return (stricmp(lhsStr.c_str(), rhsStr.c_str()) < 0);
}


void cvtRDN2String(std::string& strRDN,
				   const SNACC::RelativeDistinguishedName& rdn)
{
	// Convert each of the AttributeTypeAndDistinguishedValues
	SNACC::RelativeDistinguishedName::const_iterator i;
	for (i = rdn.begin(); i != rdn.end(); ++i)
	{
		// Check that the AttributeType is valid
		if (i->type.Len() < 1)
			throw ASN_EXCEPTION("SNACC::AttributeTypeAndDistinguishedValue::type OBJECT IDENTIFIER is invalid");

		// Get the AttributeType abbreviation string
		const char* abbrev = getAttribAbbrev(i->type);
		
		// Get the string form of the AttributeValue
		std::string valueStr;
		bool valueIsHex = cvtAttribValue2String(valueStr, i->value);
		
		// Build the AttributeTypeAndValue string
		buildTypeValueString(i->type, abbrev, valueStr, valueIsHex);
		
		// Concatenate this AttributeTypeAndValue string to the end of
		// the RDN string
		if (!strRDN.empty())
			strRDN.append(1, '+');
		strRDN.append(valueStr);
	}
}


void buildTypeValueString(const SNACC::AsnOid& asnOid, const char* abbrev,
						  std::string& valueStr, bool valueIsHex)
/*
 * AttributeTypeAndValue string built in accordance with RFC 2253,
 * LDAP v3: UTF-8 String Representation of Distinguished Names, December 1997.
 *
 * The abbreviation string is used if not NULL.  The valueIsHex boolean
 * indicates if the attribute value string is a hex string and needs to be
 * prefixed with an octothorpe '#'.
 */
{
	// If the attribute value is a hex string, build the string using the
	// OID value instead of the abbreviation and inserting the octothorpe. */
	if (valueIsHex)
	{
		valueStr.insert(0, "=#");
		valueStr.insert(0, asnOid);
	}
	else
	{
		// If the abbreviation is not present, use the OID value
		if (abbrev == NULL)
			abbrev = asnOid;

		// Remove trailing spaces from attribute value string
		std::string::size_type newEnd = valueStr.find_last_not_of(' ');
		if (newEnd != std::string::npos)
			valueStr.resize(newEnd + 1);

		// Skip over any leading spaces in attribute value string
		std::string::iterator i = valueStr.begin();
		while ((i != valueStr.end()) && (*i == ' '))
			i = valueStr.erase(i);

		// Reserve memory for the worst case length of the string
		valueStr.reserve(strlen(abbrev) + 1 + valueStr.length() * 3);

		// Prepend the abbreviation or OID string to the value string
		valueStr.insert(0, "=");
		valueStr.insert(0, abbrev);

		/* Copy each attribute value character into the resulting string,
		converting as necessary.
		- An octothorpe occuring at the beginning of the string is escaped
		  by prefixing it with a backslash.
		- The characters ",", "+", """, "\", "<", ">", and ";" are escaped
		  by prefixing them with a backslash
		- Multiple spaces are condensed into one.
		- Characters ASCII 1-31 and ASCII 127-255 are replaced by a backslash
		  and two hex digits.
		*/
		bool isFirstChar = true;
		bool prevWasSpace = false;
		i = valueStr.begin() + valueStr.find('=') + 1;
		while (i != valueStr.end())
		{
			if ((isFirstChar && (*i == '#')) ||
				(*i == ',') || (*i == '+') ||
				(*i == '\"') || (*i == '\\') ||
				(*i == '<') || (*i == '>') || (*i == ';'))
			{
				valueStr.insert(i, 1, '\\');
				i += 2;
				prevWasSpace = false;
			}
			else if (*i == ' ')
			{
				if (prevWasSpace)
					i = valueStr.erase(i);
				else
				{
					prevWasSpace = true;
					++i;
				}
			}
			else if ((*i == 127) || (*i < 32))
			{
				char escStr[3];
				escStr[0] = '\\';
				escStr[1] = SNACC::numToHexCharTblG[(*i & 0xF0) >> 4];
				escStr[2] = SNACC::numToHexCharTblG[*i & 0x0F];

				valueStr.replace(i, i + 1, escStr, 3);
				i += 3;
				prevWasSpace = false;
			}
			else
			{
				++i;
				prevWasSpace = false;
			}

			isFirstChar = false;
		}
	}
} // end of buildTypeValueString()


bool cvtAttribValue2String(std::string& str,
						   const SNACC::AsnAnyDefinedBy& value)
{
	bool valueIsHex = false;	// Set as default

	if (value.ai == NULL)		// Unknown type (value is encoded)
	{
		if (value.anyBuf == NULL)
			throw ASN_EXCEPTION("SNACC::AsnAnyDefinedBy::anyBuf field is NULL");

		valueIsHex = true;
		cvtAsnValue2Str(str, *value.anyBuf);
	}
	else	// Attribute value is decoded
	{
		if (value.value == NULL)
			throw ASN_EXCEPTION("SNACC::AsnAnyDefinedBy::value field is NULL");

		switch (value.ai->anyId)
		{
		// DirectoryString attribute values
		case SNACC::commonName_ANY_ID:
		case SNACC::surname_ANY_ID:
		case SNACC::givenName_ANY_ID:
		case SNACC::initials_ANY_ID:
		case SNACC::generationQualifier_ANY_ID:
		case SNACC::localityName_ANY_ID:
		case SNACC::stateOrProvinceName_ANY_ID:
		case SNACC::streetAddress_ANY_ID:
		case SNACC::houseIdentifier_ANY_ID:
		case SNACC::organizationName_ANY_ID:
		case SNACC::organizationalUnitName_ANY_ID:
		case SNACC::title_ANY_ID:
		case SNACC::description_ANY_ID:
		case SNACC::businessCategory_ANY_ID:
		case SNACC::postalCode_ANY_ID:
		case SNACC::postOfficeBox_ANY_ID:
		case SNACC::physicalDeliveryOfficeName_ANY_ID:
		case SNACC::useridAttribute_ANY_ID:
		case SNACC::pseudonym_ANY_ID:
			cvtDirectoryString2Str(str, *(SNACC::DirectoryString*)value.value);
			break;

		// IA5String attribute values
		case SNACC::emailAddressAttribute_ANY_ID:
		case SNACC::domainComponentAttribute_ANY_ID:
			str = *(SNACC::IA5String*)value.value;
			break;

		// PrintableString attribute values
		case SNACC::countryName_ANY_ID:
		case SNACC::dnQualifier_ANY_ID:
		case SNACC::serialNumber_ANY_ID:
		case SNACC::telephoneNumber_ANY_ID:
		case SNACC::destinationIndicator_ANY_ID:
			str = *(SNACC::PrintableString*)value.value;
			break;

		default:
			{
				// Re-encode the attribute value
				SNACC::AsnBuf asnBuf;
				SNACC::AsnLen numEnc;
				if (!value.BEncPdu(asnBuf, numEnc))
					throw ASN_EXCEPTION("Error encoding SNACC::AsnAnyDefinedby");

				// Convert the encoded value
				valueIsHex = true;
				cvtAsnValue2Str(str, asnBuf);
			}
		} // end of switch (value.ai->anyId)
	}
	return valueIsHex;
} // end of cvtAttribValue2String()


void cvtAsnValue2Str(std::string& str, const SNACC::AsnBuf& asnBuf)
{
	// Reset the AsnBuf for reading
	asnBuf.ResetMode();

	unsigned long bufLen = asnBuf.length();
	for (unsigned long i = 0; i < bufLen; ++i)
	{
		// Try to get the next byte from the AsnBuf
		char nextByte = asnBuf.GetByte();

		// Convert the byte to its hex string form
		str.append(1, SNACC::numToHexCharTblG[(nextByte & 0xF0) >> 4]);
		str.append(1, SNACC::numToHexCharTblG[nextByte & 0x0F]);
	}
}


void cvtDirectoryString2Str(std::string& utf8String,
							const SNACC::DirectoryString& dirStr)
{
	switch (dirStr.choiceId)
	{
	case SNACC::DirectoryString::teletexStringCid:
		if (dirStr.teletexString == NULL)
			throw ASN_EXCEPTION("SNACC::DirectoryString::teletexString field is NULL");
		utf8String = *dirStr.teletexString;
		break;
		
	case SNACC::DirectoryString::printableStringCid:
		if (dirStr.printableString == NULL)
			throw ASN_EXCEPTION("SNACC::DirectoryString::printableString field is NULL");
		utf8String = *dirStr.printableString;
		break;
		
	case SNACC::DirectoryString::universalStringCid:
		if (dirStr.universalString == NULL)
			throw ASN_EXCEPTION("SNACC::DirectoryString::universalString field is NULL");
		dirStr.universalString->getAsUTF8(utf8String);
		break;
		
	case SNACC::DirectoryString::bmpStringCid:
		if (dirStr.bmpString == NULL)
			throw ASN_EXCEPTION("SNACC::DirectoryString::bmpString field is NULL");
		dirStr.bmpString->getAsUTF8(utf8String);
		break;
		
	case SNACC::DirectoryString::uTF8StringCid:
		if (dirStr.uTF8String == NULL)
			throw ASN_EXCEPTION("SNACC::DirectoryString::uTF8String field is NULL");
		dirStr.uTF8String->getAsUTF8(utf8String);
		break;
		
	default:
		throw ASN_EXCEPTION("Invalid CHOICE in SNACC::DirectoryString");
	}
}


Any_struct* cvtOtherNameToAny(const SNACC::Other_Name& snacc)
{
	Any_struct* pResult = (Any_struct*)calloc(1, sizeof(Any_struct));
	if (pResult == NULL)
		throw MEMORY_EXCEPTION;

	try {
		pResult->oid = snacc.id.GetChar();
		if (snacc.type.ai == NULL)
		{
			if (snacc.type.anyBuf == NULL)
				throw ASN_EXCEPTION("SNACC::Other_Name anyBuf field is NULL");

			pResult->data = Internal::CvtAsnBufToBytes(*snacc.type.anyBuf);
		}
		else if (snacc.type.value != NULL)
		{
			// Encode the ANY value
			SNACC::AsnBuf encValue;
			SNACC::AsnLen numEnc;
			if (!snacc.type.value->BEncPdu(encValue, numEnc))
				throw ASN_EXCEPTION("Error encoding SNACC::Other_Name value");
			
			pResult->data = Internal::CvtAsnBufToBytes(encValue);
		}
		else
			throw ASN_EXCEPTION("SNACC::Other_Name value field is NULL");

		return pResult;
	}
	catch (...) {
		if (pResult->oid != NULL)
			free(pResult->oid);
		if (pResult->data != NULL)
			Internal::FreeBytes(pResult->data);
		free(pResult);
		throw;
	}
}


void cvtAttribValue2IA5String(std::string& str,
							  const SNACC::AsnAnyDefinedBy& value)
{
	if (value.ai == NULL)		// Unknown type (value is encoded)
	{
		if (value.anyBuf == NULL)
			throw ASN_EXCEPTION("SNACC::AsnAnyDefinedBy::anyBuf field is NULL");

		SNACC::IA5String snaccIA5Str;
		unsigned long len;
		snaccIA5Str.BDec(*value.anyBuf, len);
		str = snaccIA5Str;
	}
	else	// Attribute value is decoded
	{
		if (value.value == NULL)
			throw ASN_EXCEPTION("SNACC::AsnAnyDefinedBy::value field is NULL");
		str = *(SNACC::IA5String*)value.value;
	}
} // end of cvtAttribValue2IA5String()


void cvtStr2RDN(SNACC::RelativeDistinguishedName& rdn, const char* strRDN,
				unsigned int strLen)
/* This function uses the C string Relative Distinguished Name (DN) to fill in
the SNACC RelativeDistinguishedName structure.
*/
{
	StringList* pATDVs = parseLDAPstring(strRDN, strLen, "+");

	try {
		StringList::const_iterator i;
		for (i = pATDVs->begin(); i != pATDVs->end(); ++i)
			cvtStr2ATDV(*rdn.append(), *i);

		// Delete temporary ATDV string list
		delete pATDVs;
	}
	catch (...) {
		delete pATDVs;
		throw;
	}
}


void cvtStr2ATDV(SNACC::AttributeTypeAndDistinguishedValue& atdv,
				 const StrElmt& strATDV)
/* This function uses the AttributeTypeAndValue C string to fill in the
SNACC AttributeTypeAndDistinguishedValue object.
*/
{
	// Find the equal sign
	char* pEqualSign = (char*)memchr(strATDV.str, '=', strATDV.len);
	if (pEqualSign == NULL)
		throw EXCEPTION_STR(CMLASN_INVALID_DN, "Missing equal sign in DN");
	
	// Find the start and end of the OID or abbreviation (skip leading spaces)
	unsigned int i = 0;
	while ((i < (unsigned int)(pEqualSign - strATDV.str)) && (strATDV.str[i] == ' '))
		i++;
	
	if (i == (unsigned int)(pEqualSign - strATDV.str))	// OID is missing
		throw EXCEPTION_STR(CMLASN_INVALID_DN, "Missing attribute type in DN");
	
	// If the string starts with "oid." or "OID.", skip over those
	// characters
	if ((i + 4) < strATDV.len)
	{
		if ((memcmp(&strATDV.str[i], "oid.", 4) == 0) ||
			(memcmp(&strATDV.str[i], "OID.", 4) == 0))
			i += 4;
	}
	
	// Decrease the size of the OID if there are trailing spaces
	unsigned int oidLen = pEqualSign - strATDV.str - i;
	while (strATDV.str[oidLen + i - 1] == ' ')
	{
		oidLen--;
		if (oidLen == 0)
		{
			throw EXCEPTION_STR(CMLASN_INVALID_DN,
				"Missing attribute type in DN");
		}
	}
	
	// Set the attribute type OID
	if ((strATDV.str[i] < '0') || (strATDV.str[i] > '2'))
	{
		// If the OID is an abbreviation, look up its OID in the table
		const char* oid = getAttribOID(&strATDV.str[i], oidLen);
		if (oid == NULL)
		{
			throw EXCEPTION_STR(CMLASN_INVALID_DN,
				"Unrecognized attribute type abbreviation in DN");
		}
		
		atdv.type.PutChar(oid);
	}
	else	// Just use the OID dotted-decimal string
	{
		// Make a temporary copy of the OID
		char* tempStr = new char[oidLen + 1];
		if (tempStr == NULL)
			throw MEMORY_EXCEPTION;
		
		memcpy(tempStr, &strATDV.str[i], oidLen);
		tempStr[oidLen] = '\0';
		
		atdv.type.PutChar(tempStr);
		delete[] tempStr;
	}
	
	// Convert the string value to its SNACC form
	cvtStr2AttribValue(atdv.value, strATDV, pEqualSign - strATDV.str + 1,
		getAttribType(atdv.type));
	
	// Set this value's AnyInfo
	atdv.value.SetTypeByOid(atdv.type);
}


void cvtStr2AttribValue(SNACC::AsnAnyDefinedBy& value,
						const StrElmt& valueStr, unsigned int iStart,
						AttributeTypeFlag type)
{
	// Convert the string form of the value to a buffer
	std::string valueString;
	bool isEncoded = cvtStr2Buffer(valueString, valueStr, iStart,
		(type != UNKNOWN_TYPE) ? true : false);

	switch (type)
	{
	case DIRECTORY_STRING:
		{
			SNACC::DirectoryString* pDirStr = new SNACC::DirectoryString;
			if (pDirStr == NULL)
				throw MEMORY_EXCEPTION;
			value.value = pDirStr;

			if (isEncoded)
			{
				// Decode the buffer
				SNACC::AsnBuf buf(valueString.c_str(), valueString.length());
				SNACC::AsnLen numDec;
				if (!pDirStr->BDecPdu(buf, numDec))
				{
					throw EXCEPTION_STR(CMLASN_INVALID_DN,
						"Invalid hex attribute value in DN");
				}
			}
//			else if (isPrintable(valueString))
//			{
//				pDirStr->choiceId =
//					SNACC::DirectoryString::printableStringCid;
//				pDirStr->printableString = new
//					SNACC::PrintableString(valueString);
//			}
			else
			{
				pDirStr->choiceId = SNACC::DirectoryString::uTF8StringCid;
				pDirStr->uTF8String = new
					SNACC::UTF8String(valueString);
			}

			if (pDirStr->uTF8String == NULL)
				throw MEMORY_EXCEPTION;
		}
		break;
		
	case PRINTABLE_STRING:
		value.value = new SNACC::PrintableString;
		if (value.value == NULL)
			throw MEMORY_EXCEPTION;

		if (isEncoded)
		{
			// Decode the buffer
			SNACC::AsnBuf buf(valueString.c_str(), valueString.length());
			SNACC::AsnLen numDec;
			if (!value.value->BDecPdu(buf, numDec))
			{
				throw EXCEPTION_STR(CMLASN_INVALID_DN,
					"Invalid hex attribute value in DN");
			}
		}
		else
			*(SNACC::PrintableString*)value.value = valueString;
		break;
		
	case IA5_STRING:
		value.value = new SNACC::IA5String;
		if (value.value == NULL)
			throw MEMORY_EXCEPTION;

		if (isEncoded)
		{
			// Decode the buffer
			SNACC::AsnBuf buf(valueString.c_str(), valueString.length());
			SNACC::AsnLen numDec;
			if (!value.value->BDecPdu(buf, numDec))
			{
				throw EXCEPTION_STR(CMLASN_INVALID_DN,
					"Invalid hex attribute value in DN");
			}
		}
		else
			*(SNACC::IA5String*)value.value = valueString;
		break;
		
	case UNKNOWN_TYPE:
		value.anyBuf = new SNACC::AsnBuf(valueString.c_str(),
			valueString.length());
		if (value.anyBuf == NULL)
			throw MEMORY_EXCEPTION;
		break;
		
	default:
		throw EXCEPTION(CMLASN_NOT_IMPLEMENTED);
	}
}


bool cvtStr2Buffer(std::string& buffer, const StrElmt& valueStr,
				   unsigned int iStart, bool isTypeKnown)
{
	// Get the index of the last value character
	unsigned int iLast = valueStr.len - 1;
	if (iLast < iStart)
		throw EXCEPTION_STR(CMLASN_INVALID_DN, "Missing attribute value in DN");

	// Skip over leading spaces
	while ((iLast > iStart) && (valueStr.str[iStart] == ' '))
		iStart++;

	// Convert the value into a buffer
	if (valueStr.str[iStart] == '#')		// Hex string value
	{
		if ((iLast == iStart) || (((iLast - iStart) % 2) != 0))
		{
			throw EXCEPTION_STR(CMLASN_INVALID_DN,
				"Invalid hex attribute value in DN");
		}

		// Set the size of the string buffer to hold the hex string
		buffer.resize((iLast - iStart) / 2);

		++iStart;	// Skip over octothrope ('#')

		for (unsigned int i = 0; i < buffer.length(); i++)
		{
			buffer[i] = hexPair2Bin(valueStr.str[iStart],
				valueStr.str[iStart + 1]);
			iStart += 2;
		}

		return true;	// value was encoded
	}
	else	// Quoted string or regular string
	{
		if (!isTypeKnown)
		{
			throw EXCEPTION_STR(CMLASN_INVALID_DN,
				"Unknown string attribute value in DN");
		}

		bool quotedString = false;
		if ((valueStr.str[iStart] == '\"') && (valueStr.str[iLast] == '\"'))
		{
			quotedString = true;
			if ((iStart == iLast) || ((iStart + 1) == iLast))
			{
				throw Exception(CMLASN_INVALID_DN, __FILE__, __LINE__,
					"Empty attribute value in DN");
			}
			iStart++;
			iLast--;
		}

		// Set the size of the string buffer
		unsigned int bufSize = iLast - iStart + 1;
		buffer.resize(bufSize);

		ulong i = 0;
		bool prevWasEsc = false;
		for (; iStart <= iLast; iStart++)
		{
			if (valueStr.str[iStart] == '\\')
			{
				if (prevWasEsc)
					buffer[i++] = valueStr.str[iStart];
				else
					--bufSize;
				prevWasEsc = !prevWasEsc;
			}
			else if (valueStr.str[iStart] == '\"')
			{
				if (!prevWasEsc)
				{
					throw EXCEPTION_STR(CMLASN_INVALID_DN,
						"Unescaped quotation mark in DN");
				}
				buffer[i++] = valueStr.str[iStart];
				prevWasEsc = false;
			}
			else if (isSpecial(valueStr.str[iStart]))
			{
				if (prevWasEsc)
					prevWasEsc = false;
				else if (!quotedString)
				{
					throw EXCEPTION_STR(CMLASN_INVALID_DN, 
						"Unescaped special character in DN");
				}
				buffer[i++] = valueStr.str[iStart];
			}
			else if (prevWasEsc)
			{
				if (iLast == iStart)
				{
					throw EXCEPTION_STR(CMLASN_INVALID_DN,
						"Extra backslash in DN");
				}
				buffer[i++] = hexPair2Bin(valueStr.str[iStart],
					valueStr.str[iStart + 1]);
				iStart++;
				--bufSize;
				prevWasEsc = false;
			}
			else
				buffer[i++] = valueStr.str[iStart];
		} // end of for loop

		// Resize the buffer to match the number of inserted characters
		buffer.resize(bufSize);

		return false;	// value was not encoded

	} // end of else
} // end of cvtStr2Buffer()


StringList* parseLDAPstring(const char* string, unsigned int len,
							const char* separatorChars)
/* This function will parse the LDAP input string into separate component
strings as determined by any of the separator characters.  Any leading and
trailing spaces in each string will be removed.
*/
{
	if ((string == NULL) || (separatorChars == NULL))
		throw Exception(CMLASN_NULL_POINTER, __FILE__, __LINE__);
	
	StringList* result = new StringList;
	if (result == NULL)
		throw MEMORY_EXCEPTION;

	try {
		unsigned int iStart = 0;
		while (iStart < len)
		{
			bool sepFound = false;
			
			// Continue parsing the string until either the next non-escaped
			// separator is found or no more separator characters can be found
			unsigned int iTemp = iStart;
			bool isEsc = false;
			bool inQuotes = false;
			while (!sepFound && (iTemp < len))
			{
				if (isEsc)
				{
					if (isSpecial(string[iTemp]) || (string[iTemp] == '\\') ||
						(string[iTemp] == '\"'))
						isEsc = false;
					else if ((iTemp < (len - 1)) && isHexChar(string[iTemp]) &&
						isHexChar(string[iTemp + 1]))
					{
						iTemp++;
						isEsc = false;
					}
					else	// Invalid escape sequence
					{
						throw EXCEPTION_STR(CMLASN_INVALID_DN,
							"Invalid escaped character in DN");
					}
				}
				else if (inQuotes)
				{
					if (string[iTemp] == '\"')
						inQuotes = false;
				}
				else if (string[iTemp] == '\\')
					isEsc = true;
				else if (string[iTemp] == '\"')
					inQuotes = true;
				else	// Check if this character is a separator
				{
					for (int x = 0; !sepFound &&
						(x < (int)strlen(separatorChars)); x++)
					{
						if (string[iTemp] == separatorChars[x])
							sepFound = true;
					}
				}

				if (!sepFound)
					iTemp++;
			}
				
			if (isEsc)
			{
				throw EXCEPTION_STR(CMLASN_INVALID_DN,
					"Invalid escaped character in DN");
			}
			else if (inQuotes)
			{
				throw EXCEPTION_STR(CMLASN_INVALID_DN,
					"Missing quotation mark in DN");
			}

			unsigned int compLen = iTemp - iStart;

			// Skip past any leading spaces
			while (string[iStart] == ' ')
			{
				iStart++;
				compLen--;
			}
			
			// Ignore unescaped trailing spaces
			// Must check that the string is at least 2 characters long.
			unsigned int nTrailing = 0;
			while ((compLen > 1) && (string[iTemp - nTrailing - 1] == ' ') && 
				(string[iTemp - nTrailing - 2] != '\\'))
			{
				nTrailing++;
				compLen--;
			}

			// Check that the component string is valid
			if (compLen == 0)
			{
				throw EXCEPTION_STR(CMLASN_INVALID_DN,
					"Extra separator character in DN");
			}

			// Add this component string to the StringList
			StrElmt componentStr;
			componentStr.str = &string[iStart];
			componentStr.len = compLen;
			result->push_back(componentStr);

			iStart = iTemp + 1;
			
			// Check that at least one character in the next component string
			// is present
			if (sepFound && (iStart >= len))
			{
				throw EXCEPTION_STR(CMLASN_INVALID_DN,
					"Extra separator character in DN");
			}

		} // while not at end of string

		return result;
	}
	catch (...) {
		delete result;
		throw;
	}
} // end of parseLDAPstring()


/****************************************************************************
 Function:  ParseHostFromURL()
 This function parses the specified URL and returns the host name from the
 URL or NULL if an error occurs.

 Standard URL Schemes:
	ftp://<user>:<password>@<host>:<port>/<cwd1>/<cwd2>/.../<cwdN>/<name>;type=<typecode>
	http://<host>:<port>/<path>?<searchpart>
	gopher://<host>:<port>/<gopher-path>
	mailto:<rfc822-addr-spec>
	news:<newsgroup-name>
	news:<message-id>
	nntp://<host>:<port>/<newsgroup-name>/<article-number>
	telnet://<user>:<password>@<host>:<port>/
	wais://<host>:<port>/<database>
	wais://<host>:<port>/<database>?<search>
	wais://<host>:<port>/<database>/<wtype>/<wpath>
	file://<host>/<path>
	prospero://<host>:<port>/<hostname>;<field>=<value>
*****************************************************************************/
char* CML::ParseHostFromURL(const char* url)
{
	// Internal function type definitions
	enum UrlScheme {
		URL_NONE,
		URL_FTP,
		URL_HTTP,
		URL_GOPHER,
		URL_MAILTO,
		URL_NEWS,
		URL_NNTP,
		URL_TELNET,
		URL_WAIS,
		URL_FILE,
		URL_PROSPERO
	};

	struct UrlSchemeRec
	{
		const char* name;
		UrlScheme type;
	};

	// Internal table
	const UrlSchemeRec kUrlSchemeTable[] = {
		{ "ftp", URL_FTP },
		{ "http", URL_HTTP },
		{ "gopher", URL_GOPHER },
		{ "mailto", URL_MAILTO },
		{ "news", URL_NEWS },
		{ "nntp", URL_NNTP },
		{ "telnet", URL_TELNET },
		{ "wais", URL_WAIS },
		{ "file", URL_FILE },
		{ "prospero", URL_PROSPERO },
		{ NULL, URL_NONE }
	};

	// Parse the scheme name from the URL and copy it
	ulong hostLen;
	const char* scheme = CML::strtok_r(url, hostLen, ":");
	if (scheme == NULL)
		return NULL;
	char* schemeCopy = new char[hostLen + 1];
	if (schemeCopy == NULL)
		return NULL;
	strncpy(schemeCopy, scheme, hostLen);
	schemeCopy[hostLen] = '\0';

	// Update scheme pointer for next strtok_r call
	scheme += hostLen;

	// Match the scheme name copy to a name in the URL scheme table
        const UrlSchemeRec* pRec;
	for (pRec = kUrlSchemeTable; pRec->name != NULL; pRec++)
	{
		if (stricmp(schemeCopy, pRec->name) == 0)
			break;
	}
	delete[] schemeCopy;
	
	// Get the host name from the particular URL scheme
	const char* tempHost;
	switch (pRec->type)
	{
	case URL_FTP:
	case URL_TELNET:
		{
			// Parse out the login part "user:password@host:port"
			scheme = CML::strtok_r(scheme, hostLen, "/");
			if (scheme == NULL)
			{
				tempHost = NULL;
				break;
			}
			// Search the login part for an at-sign.  If there isn't one,
			// reset the temp pointer to the beginning of the login part.
			// Parse the host name
			const char* pTemp = scheme;
			for (ushort i = 0; (i < hostLen) && (*pTemp != '@'); i++)
				;
			if (*pTemp != '@')
				pTemp = scheme;
			tempHost = CML::strtok_r(pTemp, hostLen, "@:/");
			break;
		}
		
	case URL_HTTP:
	case URL_GOPHER:
	case URL_NNTP:
	case URL_WAIS:
	case URL_FILE:
	case URL_PROSPERO:
		tempHost = CML::strtok_r(scheme, hostLen, ":/");
		// For File URLs, set tempHost to NULL if not specified (ie. "file:///<path>
		if ((pRec->type == URL_FILE) && (tempHost != NULL) &&
			((tempHost - scheme) == 4))
			tempHost = NULL;
		break;
		
	case URL_MAILTO:
		tempHost = CML::strtok_r(scheme, hostLen, "@");	// tempHost points at local-part
		if (tempHost != NULL)
		{
			tempHost += hostLen;
			tempHost = CML::strtok_r(tempHost, hostLen, "@");	// tempHost points at the domain
		}
		break;
		
		// Any others are unsupported, so set the tempHost to NULL
	case URL_NEWS:
	default:
		tempHost = NULL;
	}
	
	// If the tempHost is NULL, return NULL
	if (tempHost == NULL)
		return NULL;
	
	// Allocate memory for and copy the host name
	char* hostName = new char[hostLen + 1];
	if (hostName == NULL)
		return NULL;
	strncpy(hostName, tempHost, hostLen);
	hostName[hostLen] = '\0';

	return hostName;
} // end of ParseHostFromURL()



//bool isPrintable(const std::string& str)
//{
//	for (std::string::const_iterator i = str.begin(); i != str.end(); ++i)
//	{
//		if ((*i < 'A') || (*i > 'Z'))
//		{
//			/* Check for a-z */
//			if ((*i < 'a') || (*i > 'z'))
//			{
//				/* Check for 0-9 */
//				if ((*i < '0') || (*i > '9'))
//				{
//					switch (*i)
//					{
//					case ' ':		/* space */
//					case '\'':		/* apostrophe */
//					case '(':		/* left parenthesis */
//					case ')':		/* right parenthesis */
//					case '+':		/* plus sign */
//					case ',':		/* comma */
//					case '-':		/* hyphen */
//					case '.':		/* full stop (period) */
//					case '/':		/* solidus */
//					case ':':		/* colon */
//					case '=':		/* equal sign */
//					case '?':		/* question mark */
//						break;
//
//					default:
//						return false;
//					}
//				}
//			}
//		}
//	}
//	return true;
//}



bool isSpecial(char c)
{
	if ((c == ',') || (c == '=') || (c == '+') || (c == '<') || (c == '>') ||
		(c == '#') || (c == ';'))
		return true;
	else
		return false;
}


bool isHexChar(char c)
{
	if ((c >= '0') && (c <= '9'))
		return true;
	else if ((c >= 'A') && (c <= 'Z'))
		return true;
	else if ((c >= 'a') && (c <= 'z'))
		return true;
	else
		return false;
}


uchar hexPair2Bin(char c1, char c2)
{
	uchar bin;

	if ((c1 >= '0') && (c1 <= '9'))
		bin = uchar(c1 - '0');
	else if ((c1 >= 'a') && (c1 <= 'f'))
		bin = uchar(c1 - 'a' + 10);
	else if ((c1 >= 'A') && (c1 <= 'F'))
		bin = uchar(c1 - 'A' + 10);
	else
	{
		throw Exception(CMLASN_INVALID_DN, __FILE__, __LINE__,
			"Invalid hex character in DN");
	}

	bin <<= 4;	// Shift the value into the higher nibble

	if ((c2 >= '0') && (c2 <= '9'))
		bin |= uchar(c2 - '0');
	else if ((c2 >= 'a') && (c2 <= 'f'))
		bin |= uchar(c2 - 'a' + 10);
	else if ((c2 >= 'A') && (c2 <= 'F'))
		bin |= uchar(c2 - 'A' + 10);
	else
	{
		throw Exception(CMLASN_INVALID_DN, __FILE__, __LINE__,
			"Invalid hex character in DN");
	}

	return bin;
}


/****************************************************************************
 Function:  striEnd()
 The striEnd function performs a case-insensitive comparison of the two
 strings in reverse (starting from the ends).  The function returns a pointer
 to the occurrence of string2 within string1, only if it occurs at the end of
 string1.  This function returns NULL if string2 does not occur at the end of
 string1 or if string1 or string2 is of 0 length.  For example:

	string1 = "The quick brown fox jumped over the lazy dog"
	string2 = "Lazy Dog"
	result = "lazy dog"  (in string1)
*****************************************************************************/
const char* CML::striEnd(const char *string1, const char *string2)
{
    long len1, len2, x;
	char c1, c2;

	if ((string1 == NULL) || (string2 == NULL))
		return NULL;

    len1 = strlen(string1);
    len2 = strlen(string2);

    if ((len1 == 0) || (len2 == 0) || (len2 > len1))
        return NULL;

    x = 1;
	do
	{
		c1 = string1[len1 - x];
		if ((c1 >= 'A') && (c1 <= 'Z'))
			c1 += 'a' - 'A';
		
		c2 = string2[len2 - x];
		if ((c2 >= 'A') && (c2 <= 'Z'))
			c2 += 'a' - 'A';
	}
    while ((c1 == c2) && (len2 > x++));

    if (c1 == c2)
        return (char *)&string1[len1 - len2];
	else
		return NULL;
} // end of striEnd()


const char* CML::strtok_r(const char* strToken, ulong& len,
						  const char* strDelimit)
{
	// Initialize length result
	len = 0;

	// Return NULL if the input string is NULL
	if (strToken == NULL)
		return NULL;

	// Return the length of the string, if no delimiters are specified
	if (strDelimit == NULL)
	{
		len = strlen(strToken);
		return strToken;
	}

	// Find the start of the next token
	while (*strToken != '\0')
	{
		// See if this character matches one of the delimiters
		const char* pDelim = strDelimit;
		while ((*pDelim != '\0') && (*strToken != *pDelim))
			pDelim++;

		// If this character didn't match one of the delimiters, then
		// break out of the loop
		if (*pDelim == '\0')
			break;

		strToken++;
	}

	// If no more tokens are present, return NULL
	if (*strToken == '\0')
		return NULL;

	// Find the length of the token
	while (strToken[len] != '\0')
	{
		// See if this character matches one of the delimiters
		const char* pDelim = strDelimit;
		while ((*pDelim != '\0') && (strToken[len] != *pDelim))
			pDelim++;

		// If this character matches one of the delimiters, then break out of
		// the loop
		if (*pDelim != '\0')
			break;

		len++;
	}
	
	return strToken;
} // end of strtok_r()


const char* getAttribOID(const char* abbrev, unsigned int len)
{
	for (const AttribOidRec* pRec = gRdnAttribTable; pRec->abbrev != NULL; pRec++)
	{
		if (len == strlen(pRec->abbrev))
		{
			unsigned int i;
			for (i = 0; i < len; i++)
			{
				char c = pRec->abbrev[i];
				if (c != abbrev[i])
				{
					// Shift case of c
					if ((c >= 'a') && (c <= 'z'))
						c += 'A' - 'a';
					else if ((c >= 'A') && (c <= 'Z'))
						c += 'a' - 'A';
					else
						break;
					if (c != abbrev[i])
						break;
				}
			}

			// Strings match, so return dotForm
			if (i == len)
				return pRec->dotForm;
		}
	}

	return NULL;
}


const char* getAttribAbbrev(const SNACC::AsnOid& oid)
{
	const AttribOidRec *pRec;
	for (pRec = gRdnAttribTable; (pRec->dotForm != NULL) &&
		(oid != pRec->dotForm); pRec++)
		;

	return pRec->abbrev;
}


AttributeTypeFlag getAttribType(SNACC::AsnOid& asnOid)
{
	const AttribOidRec *pRec;
	for (pRec = gRdnAttribTable; (pRec->dotForm != NULL) &&
		(asnOid != pRec->dotForm); pRec++)
		;

	return pRec->typeFlag;
}


/* RDN Attributes Table */
const AttribOidRec gRdnAttribTable[] = {
    { "2.5.4.3", "CN", DIRECTORY_STRING },			// commonName
    { "2.5.4.3", "commonName", DIRECTORY_STRING },
    { "2.5.4.6", "C", PRINTABLE_STRING },			// countryName
    { "2.5.4.6", "countryName", PRINTABLE_STRING },
    { "2.5.4.7", "L", DIRECTORY_STRING },			// localityName
    { "2.5.4.7", "localityName", DIRECTORY_STRING },
    { "2.5.4.8", "ST", DIRECTORY_STRING },			// stateOrProvinceName
    { "2.5.4.8", "stateOrProvinceName", DIRECTORY_STRING },
    { "2.5.4.9", "street", DIRECTORY_STRING },		// streetAddress
    { "2.5.4.9", "streetAddress", DIRECTORY_STRING },
    { "2.5.4.10", "O", DIRECTORY_STRING },			// organizationName
    { "2.5.4.10", "organizationName", DIRECTORY_STRING },
    { "2.5.4.11", "OU", DIRECTORY_STRING },			// organizationalUnitName
    { "2.5.4.11", "organizationalUnitName", DIRECTORY_STRING },
	{ "2.5.4.4", "SN", DIRECTORY_STRING },			// surname
	{ "2.5.4.4", "surname", DIRECTORY_STRING },
	{ "1.2.840.113549.1.9.1", "emailAddress", IA5_STRING },		// from PKCS 9
	{ "0.9.2342.19200300.100.1.1", "UID", DIRECTORY_STRING },	// userid
	{ "0.9.2342.19200300.100.1.1", "userid", DIRECTORY_STRING },
	{ "0.9.2342.19200300.100.1.3", "MAIL", IA5_STRING },		// rfc822MailBox
	{ "0.9.2342.19200300.100.1.3", "rfc822MailBox", IA5_STRING },
    { "0.9.2342.19200300.100.1.25", "DC", IA5_STRING },			// domainComponent
    { "0.9.2342.19200300.100.1.25", "domainComponent", IA5_STRING },
	{ "2.5.4.5", "serialNumber", PRINTABLE_STRING },
	{ "2.5.4.12", "T", DIRECTORY_STRING },			// title
	{ "2.5.4.12", "title", DIRECTORY_STRING },
	{ "2.5.4.13", "description", DIRECTORY_STRING },
	{ "2.5.4.15", "businessCategory", DIRECTORY_STRING },
	{ "2.5.4.17", "postalCode", DIRECTORY_STRING },
	{ "2.5.4.18", "postOfficeBox", DIRECTORY_STRING },
	{ "2.5.4.19", "physicalDeliveryOfficeName", DIRECTORY_STRING },
	{ "2.5.4.20", "telephoneNumber", PRINTABLE_STRING },
	{ "2.5.4.27", "destinationIndicator", PRINTABLE_STRING },
	{ "2.5.4.42", "GN", DIRECTORY_STRING },			// givenName
	{ "2.5.4.42", "givenName", DIRECTORY_STRING },
	{ "2.5.4.43", "initials", DIRECTORY_STRING },
	{ "2.5.4.44", "generationQualifier", DIRECTORY_STRING },
	{ "2.5.4.46", "dnQualifier", PRINTABLE_STRING },
	{ "2.5.4.51", "houseIdentifier", DIRECTORY_STRING },
	{ "2.5.4.54", "dmdName", DIRECTORY_STRING },
	{ "2.5.4.65", "pseudo", DIRECTORY_STRING },		// pseudonym
	{ "2.5.4.65", "pseudonym", DIRECTORY_STRING },
    { NULL, NULL, UNKNOWN_TYPE }
};


//////////////////////////////////////
// Internal X.400 Address Functions //
//////////////////////////////////////
// Key strings to use for OR Addresses (defined in RFC 1327)
const char COUNTRY_NAME_KEY[]		= "C";
const char ADMD_KEY[]				= "ADMD";
const char PRMD_KEY[]				= "PRMD";
const char NET_ADDR_KEY[]			= "X121";
const char TERM_ID_KEY[]			= "T-ID";
const char ORG_NAME_KEY[]			= "O";
const char ORG_UNIT_NAME_KEY[]		= "OU";
const char NUM_USER_ID_KEY[]		= "UA-ID";
const char PERSONAL_NAME_KEY[]		= "PN";
const char SURNAME_KEY[]			= "S";
const char GIVEN_NAME_KEY[]			= "G";
const char INITIALS_KEY[]			= "I";
const char GEN_QUALIFIER_KEY[]		= "GQ";
const char DOMAIN_DEF_KEY[]			= "DD";
const char COMMON_NAME_KEY[]		= "CN";
const char PDS_NAME_KEY[]			= "PD-SERVICE";
const char PD_COUNTRY_KEY[]			= "PD-C";
const char POSTAL_CODE_KEY[]		= "PD-CODE";
const char PD_OFFICE_NAME_KEY[]		= "PD-OFFICE";
const char PD_OFFICE_NUM_KEY[]		= "PD-OFFICE-NUM";
const char EXT_OR_ADDR_KEY[]		= "PD-EXT-ADDRESS";
const char PD_PERS_NAME_KEY[]		= "PD-PN";
const char PD_ORG_NAME_KEY[]		= "PD-O";
const char EXT_PD_ADDR_KEY[]		= "PD-EXT-DELIVERY";
const char POSTAL_ADDR_KEY[]		= "PD-ADDRESS";
const char STREET_ADDR_KEY[]		= "PD-STREET";
const char PO_BOX_ADDR_KEY[]		= "PD-BOX";
const char POSTE_REST_ADDR_KEY[]	= "PD-RESTANTE";
const char UNIQUE_POSTAL_KEY[]		= "PD-UNIQUE";
const char LOCAL_POSTAL_KEY[]		= "PD-LOCAL";
const char EXT_NET_ADDR_NUM_KEY[]	= "NET-NUM";
const char EXT_NET_ADDR_SUB_KEY[]	= "NET_SUB";
const char EXT_NET_ADDR_PSAP_KEY[]	= "NET-PSAP";
const char TERM_TYPE_KEY[]			= "T-TY";
const char RFC822_KEY[]				= "RFC-822";

// Extension attribute integer values (defined in X.411)
enum ExtAttribute {
	CommonName				= 1,
	TeletexCommonName,
	TeletexOrgName,
	TeletexPersonalName,
	TeletexOrgUnitName,
	TeletexDomainDef,
	PDSName,
	PDCountryName,
	PostalCode,
	PDOfficeName,
	PDOfficeNum,
	ExtORAddress,
	PDPersonalName,
	PDOrgName,
	ExtPDAddress,
	PostalAddress,
	StreetAddress,
	POBoxAddress,
	PosteRestAddress,
	UniquePostal,
	LocalPostal,
	ExtNetAddress,
	TerminalType
};


void addAttribute(const char *attr, const char *val, std::string& orAddr)
{
	// Check parameters
	if ((attr == NULL) || (val == NULL))
		throw EXCEPTION(CMLASN_NULL_POINTER);
	
	// Calc space required to add attribute
	unsigned int attrLen = strlen(attr);
	unsigned int valueLen = strlen(val);
	unsigned int spaceReq = 1 + attrLen + 1 + valueLen;
	unsigned int i = 0;
	for (i = 0; i < attrLen; i++)
	{
		if ((attr[i] == '/') || (attr[i] == '='))	// Will need to escape if found
			spaceReq++;
	}
	for (i = 0; i < valueLen; i++)
	{
		if ((val[i] == '/') || (val[i] == '='))	// Will need to escape if found
			spaceReq++;
	}

	// Insert blank space to the string for the attribute and value
	orAddr.insert(orAddr.begin(), spaceReq, ' ');

	// Insert the "/" as the first character
	orAddr[0] = '/';
			
	// Insert the attribute name string
	std::string::size_type offset = 1;
	for (i = 0; i < attrLen; i++)
	{
		if ((attr[i] == '/') || (attr[i] == '='))
			orAddr[offset++] = '$';
		orAddr[offset++] = attr[i];
	}
			
	// Insert the "=" as the next character
	orAddr[offset++] = '=';
			
	// Insert the value string
	for (i = 0; i < valueLen; i++)
	{
		if ((val[i] == '/') || (val[i] == '='))
			orAddr[offset++] = '$';
		orAddr[offset++] = val[i];
	}

} // end of addAttribute()


void cvtDomainDefAttribs(const SNACC::BuiltInDomainDefinedAttributes& ddAttrs,
						 std::string& orAddr)
{
	/* This function converts the Domain Defined Attributes (part of an X.400
	O/R Address) into the string representation.  The string is formatted
	according to RFC 1327. */

	// For each Domain Defined Attribute, convert it into a string and add
	// it to the orAddr string
	SNACC::BuiltInDomainDefinedAttributes::const_iterator i;
	for (i = ddAttrs.begin(); i != ddAttrs.end(); ++i)
	{
		// Convert the Domain Defined Attribute type into the proper
		// form by prepending "DD." to unregistered types.  Right now, the
		// only registered type is "RFC-822".
		if (strcmp(i->type.c_str(), "RFC-822") == 0)
		{
			addAttribute(i->type.c_str(), i->value.c_str(), orAddr);
		}
		else	// Need to preped "DD."
		{
			char* temp = new char[3 + i->type.length() + 1];
			if (temp == NULL)
				throw MEMORY_EXCEPTION;
			
			strcpy(temp, "DD.");
			strcat(temp, i->type.c_str());
			
			addAttribute(temp, i->value.c_str(), orAddr);
			delete[] temp;
		}
	}
} // end of cvtDomainDefAttribs()


char* cvtORAddressToString(const SNACC::ORAddress& addr)
{
/* This function converts the decoded X.400 O/R Address into the
string representation for use in the CM Library.  The string is
formatted according to RFCs 1278 and 1327.	This function only handles
mnemonic X.400 O/R address forms.  An exception is thrown if another name
form is encountered. */
	
	// Reserve an initial string buffer
	const unsigned int kInitialBufSize = 256;
	std::string oRAddr;
	oRAddr.reserve(kInitialBufSize);
	
	// Start the string with a '/'
	oRAddr = "/";
	
	// Check that none of the prohibited attribute types are present for
	// the mnemonic O/R address form
	// First check the standard attributes
	if ((addr.built_in_standard_attributes.network_address != NULL) ||
		(addr.built_in_standard_attributes.terminal_identifier != NULL) ||
		(addr.built_in_standard_attributes.numeric_user_identifier != NULL))
	{
		throw EXCEPTION_STR(CMLASN_NOT_IMPLEMENTED,
			"Unsupported O/R Address attribute");
	}
	
	// Then check the extension attributes (if any are present)
	if (addr.extension_attributes != NULL)
	{
		SNACC::ExtensionAttributes::const_iterator i =
			addr.extension_attributes->begin();
		for ( ; i != addr.extension_attributes->end(); ++i)
		{
			if (i->extension_attribute_type > 6)
			{
				throw EXCEPTION_STR(CMLASN_NOT_IMPLEMENTED,
					"Unsupported O/R Address extension attribute");
			}
		}
	}
	
	// Convert the "standard" Attributes (includes the teletex versions of
	// organization-name, personal-name, and organizational-unit-names,
	// which may be present when the printable string is absent)
	// 1. Convert the country-name
	if (addr.built_in_standard_attributes.country_name != NULL)
	{
		if (addr.built_in_standard_attributes.country_name->x121_dcc_code ==
			NULL)
			throw ASN_EXCEPTION("SNACC::BuiltInStandardAttributes::country_name is NULL");
		if (addr.built_in_standard_attributes.country_name->choiceId ==
			SNACC::CountryName::x121_dcc_codeCid)
		{
			addAttribute(COUNTRY_NAME_KEY,
				addr.built_in_standard_attributes.country_name->
				x121_dcc_code->c_str(), oRAddr);
		}
		else if (addr.built_in_standard_attributes.country_name->choiceId ==
			SNACC::CountryName::iso_3166_alpha2_codeCid)
		{
			addAttribute(COUNTRY_NAME_KEY,
				addr.built_in_standard_attributes.country_name->
				iso_3166_alpha2_code->c_str(), oRAddr);
		}
		else
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::BuiltInStandardAttributes::country_name");
	}
	
	// 2. Convert the administration-domain-name
	if (addr.built_in_standard_attributes.administration_domain_name != NULL)
	{
		if (addr.built_in_standard_attributes.administration_domain_name->
			numeric == NULL)
			throw ASN_EXCEPTION("SNACC::BuiltInStandardAttributes::administration_domain_name is NULL");
		if (addr.built_in_standard_attributes.administration_domain_name->
			choiceId == SNACC::AdministrationDomainName::numericCid)
		{
			addAttribute(ADMD_KEY, addr.built_in_standard_attributes.
				administration_domain_name->numeric->c_str(), oRAddr);
		}
		else if (addr.built_in_standard_attributes.administration_domain_name->
			choiceId == SNACC::AdministrationDomainName::printableCid)
		{
			addAttribute(ADMD_KEY, addr.built_in_standard_attributes.
				administration_domain_name->printable->c_str(), oRAddr);
		}
		else
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::BuiltInStandardAttributes::administration_domain_name");
	}
	
	// 3. Convert the private-domain-name
	if (addr.built_in_standard_attributes.private_domain_name != NULL)
	{
		if (addr.built_in_standard_attributes.private_domain_name->
			numeric == NULL)
			throw ASN_EXCEPTION("SNACC::BuiltInStandardAttributes::private_domain_name is NULL");
		if (addr.built_in_standard_attributes.private_domain_name->
			choiceId == SNACC::PrivateDomainName::numericCid)
		{
			addAttribute(PRMD_KEY, addr.built_in_standard_attributes.
				private_domain_name->numeric->c_str(), oRAddr);
		}
		else if (addr.built_in_standard_attributes.private_domain_name->
			choiceId == SNACC::PrivateDomainName::printableCid)
		{
			addAttribute(PRMD_KEY, addr.built_in_standard_attributes.
				private_domain_name->printable->c_str(), oRAddr);
		}
		else
			throw ASN_EXCEPTION("Invalid CHOICE in SNACC::BuiltInStandardAttributes::private_domain_name");
	}
	
	// 4. Convert the printable-string version of organization-name
	if (addr.built_in_standard_attributes.organization_name != NULL)
	{
		addAttribute(ORG_NAME_KEY, addr.built_in_standard_attributes.
			organization_name->c_str(), oRAddr);
	}
	
	// 4a. Convert the teletex-string version of organization-name
	const SNACC::AsnAnyDefinedBy* pAny;
	if (addr.extension_attributes == NULL)
		pAny = NULL;
	else
		pAny = findExtAttrValue(*addr.extension_attributes, TeletexOrgName);
	if (pAny != NULL)
	{
		if ((pAny->ai == NULL) || (pAny->value == NULL) ||
			(pAny->ai->anyId != SNACC::teletex_organization_name_ANY_ID))
			throw ASN_EXCEPTION("Invalid SNACC::ExtensionAttribute ANY");
		
		addAttribute(ORG_NAME_KEY, ((SNACC::T61String*)pAny->value)->c_str(),
			oRAddr);
	}
	
	// 5. Convert the printable-string versions of organizational-unit-names
	if (addr.built_in_standard_attributes.organizational_unit_names != NULL)
	{
		const SNACC::OrganizationalUnitNames& orgNames =
			*addr.built_in_standard_attributes.organizational_unit_names;
		SNACC::OrganizationalUnitNames::const_iterator i;
		for (i = orgNames.begin(); i != orgNames.end(); ++i)
			addAttribute(ORG_UNIT_NAME_KEY, i->c_str(), oRAddr);
	}
	
	// 5a. Convert the teletex-string versions of organization-unit-names
	if (addr.extension_attributes == NULL)
		pAny = NULL;
	else
		pAny = findExtAttrValue(*addr.extension_attributes, TeletexOrgUnitName);
	if (pAny != NULL)
	{
		if ((pAny->ai == NULL) || (pAny->value == NULL) ||
			(pAny->ai->anyId != SNACC::teletex_organizational_unit_names_ANY_ID))
			throw ASN_EXCEPTION("Invalid SNACC::ExtensionAttribute ANY");
		
		const SNACC::TeletexOrganizationUnitNames& names =
			*(SNACC::TeletexOrganizationUnitNames*)pAny->value;
		SNACC::TeletexOrganizationUnitNames::const_iterator i;
		for (i = names.begin(); i != names.end(); ++i)
			addAttribute(ORG_UNIT_NAME_KEY, i->c_str(), oRAddr);
	}
	
	// 6. Convert the printable-string version of personal-name
	if (addr.built_in_standard_attributes.personal_name != NULL)
	{
		bool oneAttr;
		char* nameStr = cvtPersonalName2cStr(*addr.built_in_standard_attributes.
			personal_name, oneAttr);
		
		if (oneAttr)
		{
			addAttribute(PERSONAL_NAME_KEY, nameStr, oRAddr);
		}
		else	// Prepend the formatted string to the ORAddress string
			oRAddr.insert(0, nameStr);
		
		free(nameStr);
	}
	
	// 6a. Convert the teletex-string version of personal-name
	if (addr.extension_attributes == NULL)
		pAny = NULL;
	else
		pAny = findExtAttrValue(*addr.extension_attributes, TeletexPersonalName);
	if (pAny != NULL)
	{
		if ((pAny->ai == NULL) || (pAny->value == NULL) ||
			(pAny->ai->anyId != SNACC::teletex_personal_name_ANY_ID))
			throw ASN_EXCEPTION("Invalid SNACC::ExtensionAttribute ANY");
		
		bool oneAttr;
		char* nameStr = cvtTeletexPersonalName2cStr(*(SNACC::TeletexPersonalName*)
			pAny->value, oneAttr);
		
		if (oneAttr)
			addAttribute(PERSONAL_NAME_KEY, nameStr, oRAddr);
		else	// Prepend the formatted string to the ORAddress string
			oRAddr.insert(0, nameStr);
		
		free(nameStr);
	}
	
	// 7. Convert the printable-string version of common-name
	if (addr.extension_attributes == NULL)
		pAny = NULL;
	else
		pAny = findExtAttrValue(*addr.extension_attributes, CommonName);
	if (pAny != NULL)
	{
		if ((pAny->ai == NULL) || (pAny->value == NULL) ||
			(pAny->ai->anyId != SNACC::common_name_ANY_ID))
			throw ASN_EXCEPTION("Invalid SNACC::ExtensionAttribute ANY");
		
		addAttribute(COMMON_NAME_KEY,
			((SNACC::CommonName*)pAny->value)->c_str(), oRAddr);
	}
	
	// 7a. Convert the teletex-string version of common-name
	if (addr.extension_attributes == NULL)
		pAny = NULL;
	else
		pAny = findExtAttrValue(*addr.extension_attributes, TeletexCommonName);
	if (pAny != NULL)
	{
		if ((pAny->ai == NULL) || (pAny->value == NULL) ||
			(pAny->ai->anyId != SNACC::teletex_common_name_ANY_ID))
			throw ASN_EXCEPTION("Invalid SNACC::ExtensionAttribute ANY");
		
		addAttribute(COMMON_NAME_KEY,
			((SNACC::TeletexCommonName*)pAny->value)->c_str(), oRAddr);
	}
	
	// Convert the printable-string Domain Defined attributes if present
	if (addr.built_in_domain_defined_attributes != NULL)
	{
		cvtDomainDefAttribs(*addr.built_in_domain_defined_attributes,
			oRAddr);
	}
	
	// Convert the teletex-string Domain Defined attributes if present
	if (addr.extension_attributes == NULL)
		pAny = NULL;
	else
		pAny = findExtAttrValue(*addr.extension_attributes, TeletexDomainDef);
	if (pAny != NULL)
	{
		if ((pAny->ai == NULL) || (pAny->value == NULL) ||
			(pAny->ai->anyId !=
			SNACC::teletex_domain_defined_attributes_ANY_ID))
			throw ASN_EXCEPTION("Invalid SNACC::ExtensionAttribute ANY");
		{
			cvtTeletexDomainDefAttribs(*(SNACC::TeletexDomainDefinedAttributes*)
				pAny->value, oRAddr);
		}
	}
	
	char* result = strdup(oRAddr.c_str());
	if (result == NULL)
		throw MEMORY_EXCEPTION;

	return result;
} // cvtORAddressToString()


const unsigned int MAX_GIVEN_NAME_LEN	= 16;
const unsigned int MAX_INITIALS_LEN		= 5;
const unsigned int MAX_SURNAME_LEN		= 40;
const unsigned int MAX_PERS_NAME_LEN	= MAX_GIVEN_NAME_LEN + 1 +
(MAX_INITIALS_LEN * 2) + MAX_SURNAME_LEN + 1;


char* cvtPersonalName2cStr(SNACC::PersonalName& snaccName, bool& oneString)
{
	/* This function converts the decoded X.400 Personal Name into its
	string representation.  The string is formatted according to RFC 1327.
	If the Personal Name can be converted into a single attribute string,
	it will be (i.e., "John.A.Doe"), otherwise, it will be converted into 
	a series of attribute strings (i.e., "/G=John/I=A/S=Doe/GQ=III").
	The oneString parameter will be true when the first form is returned. */

	// Reserve an initial string buffer
	const unsigned int kInitialBufSize = MAX_PERS_NAME_LEN * 2;
	std::string strName;
	strName.reserve (kInitialBufSize);
	
	// Start the string with a '/'
	strName = "/";

	// Check that the length of the surname is valid
	if ((snaccName.surname.length() == 0) || 
		(snaccName.surname.length() > MAX_SURNAME_LEN))
		throw ASN_EXCEPTION("Invalid length of SNACC::PersonalName::surname");

	/* Determine if the Personal Name can be encoded into a single
	attribute string.  The following statements must be true:
		1.  There is no generational qualifier.
		2.  Initials contain only letters.
		3.  Given name (if present) is at least two characters long.
		4.  Given name does not contain a "."
		5.  Surname does not contain "." in the first two characters.
		6.  If the surname is the only component, it does not contain a "."
	*/
	oneString = true;
	if (snaccName.generation_qualifier != NULL)					// 1
		oneString = false;
	else if (snaccName.initials != NULL)						// 2
	{
		for (unsigned int i = 0; (i < snaccName.initials->length()) &&
			oneString; i++)
		{
			const char c = (*snaccName.initials)[i];
			oneString = (((c >= 'A') && (c <='Z')) ||
				((c >= 'a') && (c <= 'z')));
		}
	}

	if (oneString && (snaccName.given_name != NULL))
	{
		if (snaccName.given_name->length() < 2)					// 3
			oneString = false;
		else if (snaccName.given_name->find('.') != std::string::npos)	// 4
			oneString = false;
	}

	if (oneString)
	{
		if ((snaccName.surname[0] == '.') ||					// 5
			((snaccName.surname.length() > 1) && (snaccName.surname[1] == '.')))
			oneString = false;
		else if ((snaccName.given_name == NULL) &&				// 6
			(snaccName.initials == NULL) &&
			(snaccName.surname.find('.') != std::string::npos))
			oneString = false;
	}

	if (oneString)	// Can be encoded in a single attribute string
	{
		// Copy the given-name into the string (if present)
		if (snaccName.given_name != NULL)
		{
			if (snaccName.given_name->length() > MAX_GIVEN_NAME_LEN)
				throw ASN_EXCEPTION("Invalid length of SNACC::PersonalName::given_name");
			
			strName = *snaccName.given_name;
			strName += '.';
		}
		
		// Copy each initial into the string (if any)
		if (snaccName.initials != NULL)
		{
			if (snaccName.initials->length() > MAX_INITIALS_LEN)
				throw ASN_EXCEPTION("Invalid length of SNACC::PersonalName::initials");
			
			for (unsigned int i = 0; i < snaccName.initials->length(); i++)
			{
				strName += (*snaccName.initials)[i];
				strName += '.';
			}
		}
		
		// Append the surname to the string
		strName += snaccName.surname;
	}
	else		// Each attribute must be encoded separately
	{
		// Add the generation-qualifier attribute if present
		if (snaccName.generation_qualifier != NULL)
		{
			addAttribute(GEN_QUALIFIER_KEY,
				snaccName.generation_qualifier->c_str(), strName);
		}
		
		// Add the surname
		addAttribute(SURNAME_KEY, snaccName.surname.c_str(), strName);
		
		// Add the initials if present
		if (snaccName.initials != NULL)
		{
			addAttribute(INITIALS_KEY, snaccName.initials->c_str(), strName);
		}
		
		// Add the given-name if present
		if (snaccName.given_name != NULL)
		{
			addAttribute(GIVEN_NAME_KEY, snaccName.given_name->c_str(),
				strName);
		}
	}

	char* result = strdup(strName.c_str());
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	return result;
} // end of cvtPersonalName2cStr()


void cvtTeletexDomainDefAttribs(const SNACC::TeletexDomainDefinedAttributes& ddAttrs,
								std::string& orAddr)
{
/* This function converts the Teletex Domain Defined Attributes (part of
an X.400 O/R Address) into the string representation.  The string is
formatted according to RFC 1327. */

	// For each TeletexDomainDefinedAttribute, convert it into a string
	// and add it to the orAddr string
	SNACC::TeletexDomainDefinedAttributes::const_iterator i;
	for (i = ddAttrs.begin(); i != ddAttrs.end(); ++i)
	{
		// Convert the TeletexDomainDefinedAttribute type into the proper
		// form by prepending "DD." to unregistered types.  Right now, the
		// only registered type is "RFC-822".
		if (i->type.compare("RFC-822") == 0)
		{
			addAttribute(i->type.c_str(), i->value.c_str(), orAddr);
		}
		else	// Need to preped "DD."
		{
			char* temp = new char[3 + i->type.length() + 1];
			if (temp == NULL)
				throw MEMORY_EXCEPTION;
			
			strcpy(temp, "DD.");
			strcat(temp, i->type.c_str());
			
			addAttribute(temp, i->value.c_str(), orAddr);
			delete[] temp;
		}
	}
}


char* cvtTeletexPersonalName2cStr(SNACC::TeletexPersonalName& snaccName,
								  bool& oneString)
{
/* This function converts the decoded X.400 TeletexPersonalName into its
string representation.  The string is formatted according to RFC 1327.
If the Personal Name can be converted into a single attribute string,
it will be (i.e., "John.A.Doe"), otherwise, it will be converted into 
a series of attribute strings (i.e., "/G=John/I=A/S=Doe/GQ=III").
The oneString parameter will be true when the first form is returned. */
	
	// Reserve an initial string buffer
	const unsigned int kInitialBufSize = MAX_PERS_NAME_LEN * 2;
	std::string strName;
	strName.reserve(kInitialBufSize);
	
	// Start the string with a '/'
	strName = "/";
	
	// Check that the length of the surname is valid
	if ((snaccName.surname.length() == 0) || 
		(snaccName.surname.length() > MAX_SURNAME_LEN))
		throw ASN_EXCEPTION("Invalid length of SNACC::TeletexPersonalName::surname");
	
	/* Determine if the Personal Name can be encoded into a single
	attribute string.  The following statements must be true:
		1.  There is no generational qualifier.
		2.  Initials contain only letters.
		3.  Given name (if present) is at least two characters long.
		4.  Given name does not contain a "."
		5.  Surname does not contain "." in the first two characters.
		6.  If the surname is the only component, it does not contain a "."
	*/
	oneString = true;
	if (snaccName.generation_qualifier != NULL)					// 1
		oneString = false;
	else if (snaccName.initials != NULL)						// 2
	{
		for (unsigned int i = 0; (i < snaccName.initials->length()) &&
			oneString; i++)
		{
			const char c = (*snaccName.initials)[i];
			oneString = (((c >= 'A') && (c <='Z')) ||
				((c >= 'a') && (c <= 'z')));
		}
	}
	
	if (oneString && (snaccName.given_name != NULL))
	{
		if (snaccName.given_name->length() < 2)					// 3
			oneString = false;
		else if (snaccName.given_name->find('.') != std::string::npos)	// 4
			oneString = false;
	}
	
	if (oneString)
	{
		if ((snaccName.surname[0] == '.') ||					// 5
			((snaccName.surname.length() > 1) &&
			(snaccName.surname[1] == '.')))
			oneString = false;
		else if ((snaccName.given_name == NULL) &&				// 6
			(snaccName.initials == NULL) &&
			(snaccName.surname.find('.') != std::string::npos))
			oneString = false;
	}
	
	if (oneString)	// Can be encoded in a single attribute string
	{
		// Copy the given-name into the string (if present)
		if (snaccName.given_name != NULL)
		{
			if (snaccName.given_name->length() > MAX_GIVEN_NAME_LEN)
				throw ASN_EXCEPTION("Invalid length of SNACC::TeletexPersonalName::given_name");
			
			strName = *snaccName.given_name;
			strName += '.';
		}
		
		// Copy each initial into the string (if any)
		if (snaccName.initials != NULL)
		{
			if (snaccName.initials->length() > MAX_INITIALS_LEN)
				throw ASN_EXCEPTION("Invalid length of SNACC::TeletexPersonalName::initials");
			
			for (unsigned int i = 0; i < snaccName.initials->length(); i++)
			{
				strName += (*snaccName.initials)[i];
				strName += '.';
			}
		}
		
		// Append the surname to the string
		strName += snaccName.surname;
	}
	else		// Each attribute must be encoded separately
	{
		// Add the generation-qualifier attribute if present
		if (snaccName.generation_qualifier != NULL)
		{
			addAttribute(GEN_QUALIFIER_KEY,
				snaccName.generation_qualifier->c_str(), strName);
		}
		
		// Add the surname
		addAttribute(SURNAME_KEY, snaccName.surname.c_str(), strName);
		
		// Add the initials if present
		if (snaccName.initials != NULL)
		{
			addAttribute(INITIALS_KEY, snaccName.initials->c_str(),
				strName);
		}
		
		// Add the given-name if present
		if (snaccName.given_name != NULL)
		{
			addAttribute(GIVEN_NAME_KEY, snaccName.given_name->c_str(),
				strName);
		}
	}
	
	char* result = strdup(strName.c_str());
	if (result == NULL)
		throw MEMORY_EXCEPTION;
	return result;
} // end of cvtTeletexPersonalName2cStr()


const SNACC::AsnAnyDefinedBy* findExtAttrValue(const SNACC::ExtensionAttributes& extAttrs,
											   int extAttrType)
{
	/* This function searches the list of Extension Attributes for the
	requested attribute type and, if found, returns a pointer to its value.
	The function returns NULL if the type is absent from the list. */
	SNACC::ExtensionAttributes::const_iterator i;
	for (i = extAttrs.begin(); i != extAttrs.end(); ++i)
	{
		if (extAttrType == i->extension_attribute_type)
			return &i->extension_attribute_value;
	}

	return NULL;
}

#ifdef SCO_SV
/* 
 Case insensitive comparison of two strings.
 Function returns:
   < 0    string1 is less than string2
   = 0    string1 is identical to string2
   > 0    string1 is greater than string 2
*/
int strcasecmp (const char *s1, const char *s2)
{
        char c1, c2;
        int s1len = 0;  /* length for first string(s1) */
        int s2len = 0;  /* length of second string(s2) */
        int x = 0;      /* index for first string(s1) */
        int y = 0;      /* index for second string(s2) */


        /* Check parameters */
        if ((s1 == NULL) || (s2 == NULL))
                return 0; /* Both are NULL, normal strcasecmp returns zero */

        /* Get the length of the input strings and initialize the first character */

        s1len = strlen(s1);
        s2len = strlen(s2);
        c1 = s1[x];
        c2 = s2[y];

        while((x < s1len) || (y < s2len))
        {
                /* first make sure we are not at the end of the either string */
                /* convert each character to lower case then compare if equal */

                c1 = s1[x];
                c2 = s2[y];

                if((x < s1len) && (y < s2len))
                {
                    if ((c1 >= 'A') && (c1 <= 'Z'))
                                c1 += 'a' - 'A';

                        if ((c2 >= 'A') && (c2 <= 'Z'))
                                c2 += 'a' - 'A';

                        /* if two characters not equal, return strings don't match */
                        if(c1 != c2)
                                return (c1 - c2);

                        /* increment each index for each string */
                        x++;
                        y++;
                }
                else
                        /* end of either string, return appropriate value */
                        return (c1 - c2);
        }
        return (c1 - c2);

} /* end of strcasecmp() */
#endif

// end of CM_GeneralNames.cpp
