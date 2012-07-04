/*****************************************************************************
File:     Exception.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the Exception class

Created:  10 September 2001
Author:   Rich Nicholas <Richard.Nicholas@GetronicsGov.com>

Last Updated:	17 March 2004

Version:  2.4

*****************************************************************************/


////////////////////
// Included Files //
////////////////////
#include "cmlasn_internal.h"


// Using CML::ASN namespace
using namespace CML::ASN;



////////////////////////////////////
// Exception class implementation //
////////////////////////////////////
Exception::Exception(short code, const char* fileName, long lineNum,
					 const char* errString) :
SNACC::SnaccException(fileName, lineNum, NULL, NULL, code + kErrorBase)
{
	m_errStr = errString;
}


Exception::operator short() const
{
	long err = m_errorCode - kErrorBase;
	if ((err < 0) || (err > SHRT_MAX))
		return CMLASN_UNKNOWN_ERROR;
	else if (err == CMLASN_SNACC_ERROR)
		return CMLASN_DECODE_ERROR;
	else
		return short(err);
}


const char* Exception::what() const throw()
{
	if (m_errStr == NULL)
		return "";
	else
		return m_errStr;
}


//////////////////////////////////////////
// ExceptionString class implementation //
//////////////////////////////////////////
ExceptionString::ExceptionString(short code, const char* fileName,
								 long lineNum, const char* errString1,
								 const char* errString2) :
Exception(code, fileName, lineNum)
{
	if (errString1 != NULL)
		m_whatStr = errString1;
	if (errString2 != NULL)
		m_whatStr += errString2;
}


const char* ExceptionString::what() const throw()
{
	return m_whatStr.c_str();
}



// end of Exception.cpp
