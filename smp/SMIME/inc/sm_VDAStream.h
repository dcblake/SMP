/* @(#) sm_VDAStream.h 1.3 12/22/99 14:24:02 */

//////////////////////////////////////////////////////////////////////////
//
// FILE:  sm_VDAStream.h
// DESCRIPTION:
//   This include file was created to isolate this stream class from other
//   SFL definitions of shared lo-level operations.
//
// CLASSES:
//    VDAStream
//
//////////////////////////////////////////////////////////////////////////
#ifndef sm_VDAStream_h
#define sm_VDAStream_h

#define LIBCERTDLL_API     // HARD-CODE to enforce static build ONLY!
                           //  CHANGED from original design...

#ifndef LIBCERTDLL_API      // DEFINE on compile line to "" for Static refs
#ifdef WIN32
#ifdef LIBCERTDLL_EXPORTS
#define LIBCERTDLL_API __declspec(dllexport)
#else
#define LIBCERTDLL_API __declspec(dllimport)
#endif          // LIBCERTDLL_EXPORTS
#else           // Handle Unix...
#define LIBCERTDLL_API
#endif          // WIN32
#endif          // ifndef LIBCERTDLL_API

// SPECIFY SPECIFIC OVERRIDE STRUCTURE ALIGNMENT FACTOR;
//  NECESSARY TO OVERRIDE ANY OTHER PROJECT SETTINGS in which this include may
//  be referenced.  This alignment forces all references to the SFL structures
//  to be consistent with the DLL/LIB objects.
#ifdef WIN32
#pragma pack(8)
// Used for VDAStream class
#pragma warning(push,3)
#endif

#ifdef RWC_READY_FOR_SSTREAM
#include <sstream>
namespace std {
typedef basic_stringstream<char> strstream;
};
#else //RWC;9/30/03;
#include <strstream>
#endif     // RWC_READY_FOR_SSTREAM

#ifdef WIN32
#pragma warning(pop)
#endif

#if !defined(NO_NAMESPACE) && !defined(_BEGIN_CERT_NAMESPACE)
#define _BEGIN_CERT_NAMESPACE namespace CERT { 
    //using namespace CTIL;
    //using namespace SNACC;
#define _END_CERT_NAMESPACE }
#else
  #if defined(NO_NAMESPACE)
  #define _BEGIN_CERT_NAMESPACE
  #define _END_CERT_NAMESPACE
  #endif
#endif
_BEGIN_CERT_NAMESPACE 

// This class can be used to globally indent output via a member function.
//   It globally overrides the insertion operator (<<) so all output
//   regardless of stream, will be indented according to the the private
//   m_indent value multiplied by the Indent multiplier (2). The product
//   of these two numbers is the number of spaces which will preceed any
//   lines sent an output stream.  The value of m_indent can be set or
//   retrieved through the use of the member functions setIndent(), and
//   getIndent().

class LIBCERTDLL_API VDAStream : public std::strstream
{
private:
    static long m_indent;
    enum m_IndentWidth { m_iMultiplier = 2 };
    char *m_strbuf;
public:
    VDAStream()
    { m_indent=0; m_strbuf=NULL; }
    ~VDAStream();

    char *str();

    void Indent(char *str)
    { IndentStream(*this, str); }

    static void IndentStream(std::ostream &os, char *str);

    static void setIndent(long l)
    { m_indent = l; }

    static long getIndent()
    { return m_indent; }
};

_END_CERT_NAMESPACE 

#endif //sm_VDAStream_h


// EOF sm_VDAStream.h
