/*****************************************************************************
File:     CM_PrintXML.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the XML Print class.

Created:  7 April 2003
Author:   Lisa Vracar <Lisa.Vracar@DigitalNet.com>

Last Updated:	17 March 2004

Version:  2.4

*****************************************************************************/

////////////////////
// Included Files //
////////////////////
#include "CM_internal.h"

// Using CML::ASN namespace
using namespace CML::Internal;

PrintXML::PrintXML()
{
	m_os = NULL;
	m_level = CM_LOG_LEVEL_0;
}

// Construct from a thread number and a file name
PrintXML::PrintXML(const char *filename, CMLogLevel level)
{
	if ((filename == NULL) && (level > CM_LOG_LEVEL_0)) 
		throw CML_ERR(CM_INVALID_PARAMETER);

	m_os = NULL;
	m_level = level;
	if (m_level > CM_LOG_LEVEL_0)
		m_os = new std::ofstream(filename);   //output file

	for (int i = 0; i < CM_MAX_NESTING; i++)
	{
		m_count[i] = 0;
	}
	//Initial heading
	if (m_level > CM_LOG_LEVEL_0)
	{
		*m_os << "<?xml version=\"1.0\" encoding=\"ISO-8859-1\" ?>" << std::endl;
		*m_os << "<!--  Log File Generated by CML -->" << std::endl;
		//XML starting tag - can only have one per file
		WriteBegin(level, "PrintXML", 0, "Start of PrintXML logging");
	}
}

// Transfer log level to LHS and turn off logging on RHS to avoid having two log instances
// writing to same file
PrintXML& PrintXML::operator=(const PrintXML& rhs){
	m_level = rhs.m_level;
	rhs.m_level = CM_LOG_LEVEL_0;
	m_os = rhs.m_os;
	rhs.m_os = NULL;
	m_countQueue = rhs.m_countQueue;
	memcpy (m_count, rhs.m_count, CM_MAX_NESTING * sizeof (int));
	return *this;
}

//Write out beginning of XML title
void PrintXML::WriteBegin(CMLogLevel level, const char *lpszTitle, int count,
						  const char *lpszName, const char *optString,
						  const char *lpszName2, const SNACC::AsnInt *sn) const
{ 
	if ((m_level == CM_LOG_LEVEL_0) || (level > m_level))
		return;

	if (count > CM_MAX_NESTING)
		throw CML_ERR(CM_INVALID_PARAMETER);
	
    char tmpbuf[9]; 
	time_t longtime = time(NULL);
	struct tm *time_tm = localtime(&longtime);
	sprintf(tmpbuf, CM_LOG_TIME_FORMAT, time_tm->tm_hour, time_tm->tm_min, time_tm->tm_sec);

	// increment the index of the level requested and zeroize all others that are nested within this index
	m_count[count]++;
	for (int i = count+1; i < CM_MAX_NESTING; i++)
	{
		m_count[i] = 0;
	}
	
	*m_os << "<" << lpszTitle <<"_" << m_count[count];
	*m_os << " time=\"" << tmpbuf << "\" name=\"" << lpszName ;
	if (optString != NULL)
		*m_os << " " << optString;
	if (lpszName2 != NULL)
		*m_os << ", " << lpszName2;
	if (sn != NULL)
		*m_os << " " << *sn;
	*m_os << "\">" <<std::endl;
	m_countQueue.push(m_count[count]); //add count to queue
}

//Write out beginning of XML title - no extra information
void PrintXML::WriteSimpleBegin(CMLogLevel level, const char *lpszTitle) const 
{ 
	if ((m_level == CM_LOG_LEVEL_0) || (level > m_level))
		return;
	
	*m_os << "<" << lpszTitle << ">" <<std::endl;
}

//Write out closing of XML title
void PrintXML::WriteEnd(CMLogLevel level, const char *lpszTitle, int count) const
{ 
	if ((m_level == CM_LOG_LEVEL_0) || (level > m_level))
		return;
	
	int which_count;
	if (count == 0)
		*m_os << "</" << lpszTitle << ">" << std::endl;
    else
	{
		which_count = m_countQueue.top();
		m_countQueue.pop();
		*m_os << "</" << lpszTitle << "_" << which_count << ">" << std::endl;
	}
}

void PrintXML::WriteData(CMLogLevel level, const char *pszLog, const char *optString) const 
{ 
	if ((m_level == CM_LOG_LEVEL_0) || (level > m_level))
		return;
	
    char tmpbuf[9]; 
	time_t longtime = time(NULL);
	struct tm *time_tm = localtime(&longtime);
	sprintf(tmpbuf, CM_LOG_TIME_FORMAT, time_tm->tm_hour, time_tm->tm_min, time_tm->tm_sec);
	*m_os << "<e>" << tmpbuf << " -- " << pszLog;
	if (optString != NULL)
		*m_os << " " << optString;
	*m_os << "</e>" <<std::endl;
}

void PrintXML::WriteData(CMLogLevel level, const char *pszLog, float fNum)  const
{ 
	if ((m_level == CM_LOG_LEVEL_0) || (level > m_level))
		return;
	
    char tmpbuf[9]; 
	time_t longtime = time(NULL);
	struct tm *time_tm = localtime(&longtime);
	sprintf(tmpbuf, CM_LOG_TIME_FORMAT, time_tm->tm_hour, time_tm->tm_min, time_tm->tm_sec);
	*m_os << "<e>" << tmpbuf << " -- " << pszLog;
	if (fNum != NULL)
		*m_os << " " << fNum;
	*m_os << "</e>" <<std::endl;
}

void PrintXML::WriteData(CMLogLevel level, int iNum, const char *pszLog) const
{
	if ((m_level == CM_LOG_LEVEL_0) || (level > m_level))
		return;
	
    char tmpbuf[9]; 
	time_t longtime = time(NULL);
	struct tm *time_tm = localtime(&longtime);
	sprintf(tmpbuf, CM_LOG_TIME_FORMAT, time_tm->tm_hour, time_tm->tm_min, time_tm->tm_sec);
	*m_os << "<e>" << tmpbuf << " -- " << iNum << pszLog;
	*m_os << "</e>" <<std::endl;
}

void PrintXML::WriteData(CMLogLevel level, const char *lpszName, const char *optString,
						 const char *lpszName2, const SNACC::AsnInt& sn,
						 const char *lpszName3, const char *optString2,
						 const char *lpszName4) const
{ 
	if ((m_level == CM_LOG_LEVEL_0) || (level > m_level))
		return;
	
	*m_os << "<e>" << lpszName << optString << ", ";
	*m_os << lpszName2 << sn;
	
	if ((lpszName3 != NULL) && (optString2 != NULL))
		*m_os << ", " << lpszName3 << optString2;
	
	if (lpszName4 != NULL)
		*m_os << " " << lpszName4;
	
	*m_os << "</e>" << std::endl;
}

void PrintXML::WriteInfo(CMLogLevel level, const char *pszLog, float fNum)  const
{ 
	if ((m_level == CM_LOG_LEVEL_0) || (level > m_level))
		return;
	
	*m_os << "<" << pszLog << ">" << fNum;
	*m_os << "</" << pszLog << ">" <<std::endl;
}

PrintXML::~PrintXML(void)
{ 
	//XML ending tag - can only have one per file
	if (m_level > CM_LOG_LEVEL_0)
		*m_os << "</" << "PrintXML" << "_" << "1>" << std::endl;

	if (m_os)
		delete m_os;
}    


// end of CM_PrintXML.cpp