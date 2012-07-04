/****************************************************************************
File:     CommonBytes.h
Project:  Certificate Management ASN.1 Library
Contents: Header file for common, general purpose, bytes class
		  Contains general class definitions used throughout the library

Created:  6 September 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	3 March 2004

Version:  2.4

*****************************************************************************/
#ifndef _COMMON_BYTES_H
#define _COMMON_BYTES_H


// Define the Microsoft-specific storage modifier used to import DLL functions
#ifndef CM_API
	#ifdef _MSC_VER
		#define CM_API  __declspec(dllimport)
	#else
		#define CM_API
	#endif
#endif


////////////////////
// Included Files //
////////////////////
#include <ostream>


//////////////////////
// Type Definitions //
//////////////////////
typedef unsigned char uchar;
#if defined(WIN32) || defined(SCO_SV) || defined(HPUX) || defined(HPUX32)
	typedef unsigned long ulong;
#endif


//////////////////////////////////
// CommonBytes class definition //
//////////////////////////////////
class CM_API CommonBytes
{
public:
	// Construct from a length and data buffer
	CommonBytes(ulong num = 0, const uchar* bytes = NULL);
	// Construct from a file
	CommonBytes(const char* fileName);
	// Copy constructor
	CommonBytes(const CommonBytes& that);
	// Destructor
	virtual ~CommonBytes()							{ Clear(); }

	// Assignment operator to assign this object from another
	CommonBytes& operator=(const CommonBytes& other);

	// Comparison operators
	bool operator==(const CommonBytes& rhs) const;
	bool operator!=(const CommonBytes& rhs) const	{ return !operator==(rhs); }
	bool operator<(const CommonBytes& rhs) const;

	// Operator to append to this object the data from the rhs CommonBytes
	CommonBytes& operator+=(const CommonBytes& rhs);

	// Clear the contents
	virtual void Clear();
	// Get the length of the data (in bytes)
	ulong Len() const							{ return len; }
	// Get a pointer to the data
	const uchar* GetData() const				{ return data; }
	// Set these bytes to the specified data.  If the data is NULL, the
	// function creates an empty buffer of the specified length.
	void Set(ulong newDataLen, const uchar* newData = NULL);

	// Hash this data using the SHA-1 algorithm
	void Hash(CommonBytes& hashResult) const;

protected:
	ulong len;
	uchar* data;
};


// Write the binary data to the specified stream
CM_API std::ostream& operator<<(std::ostream& os, const CommonBytes& bytes);



#endif // _COMMON_BYTES_H
