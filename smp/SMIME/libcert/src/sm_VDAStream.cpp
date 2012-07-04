
///////////////////////////////////////////////////////////////////////////////
//  sm_VDAStream.cpp
//    These routines support the VDAStream class.
//
//  MEMBER FUNCTIONS FOR VDAStream
//    Destructor
//    IndentStream(ostream &os, char *str)
//    str()
//
//  GLOBAL OVERRIDE DEFINITION THE ostream INSERTION OPERATOR (<<)
//    ostream LIBCERTDLL_API &operator << (ostream &os, char *a)
//
//  NOTICE THE DLL EXPORT STATEMENT (LIBCERTDLL_API) IN THE GLOBAL
//  DEFINITION REFERENCED ABOVE.  WITHOUT THIS EXPORT THERE WOULD BE A
//  LINK FAILURE WHEN BUILDING THIS LIBRARY AS A DLL
///////////////////////////////////////////////////////////////////////////////

// Used for VDAStream class
#include "sm_VDAStream.h"

_BEGIN_CERT_NAMESPACE 

// Initialize the indent value to zero (no indent)
long VDAStream::m_indent=0;

// Destructor for VDAStream
//
VDAStream::~VDAStream()
{
    rdbuf()->freeze ( 0 ); // ALLOW memory to be freed.
    if (m_strbuf != NULL)
        delete[] m_strbuf;
}

// IndentStream:
//   INPUT: ostream &os, char *str
//   OUTPUT: NONE
//   RETURN: N/A
//   This function will take an output stream argument and a carriage-
//   return-terminated string and reformat the output according to the
//   currently set indent.  This formatted output is then sent to the output
//   stream which was passed in.
//   NOTE: The current limitation for the passed in string is 256
//
void VDAStream::IndentStream(std::ostream &os, char *str)
{
   std::strstream inputstream;   // Construct a memory based input stream
    if (str != NULL)
      inputstream << str;      // Fill it with the passed in string
    // Store the size of the contents of the current stream buffer
    long lBufsiz=inputstream.pcount();
    char ptr[256];           // Temporary buffer to format the stream content
    // Flag to indicate the beginning of the buffer or a carriage return was
    // detected.  Static because many strings (or characters) can be streamed
   // without a carriage return.
    static bool b_bol=true;
    bool b_eol=false;        // End of Line Flag (carriage return was detected)
    char *Buf=inputstream.str();  // Buffer to help navigate the current stream
    // Loop through the input stream
    while (lBufsiz != 0 && !inputstream.eof())
    {
        // Get each carriage return terminated line from the input stream
        inputstream.getline(ptr, 256, '\n');
        lBufsiz=inputstream.gcount();  // The number of characters now in ptr
        // As long as there was something in the stream buffer
        if (lBufsiz > 0)
        {
            if (b_bol)       // If this is the beginning of a line
            {                // Indent the appropriate spaces
               for (int iii=0; iii < m_indent*m_iMultiplier; iii++)
                  os << " "; 
                os << "";
                b_bol=false; // Reset the beginning of line flag
            }
            // Search the current Buffer for a carriage return ('\n')
            if (memchr(Buf, '\n', lBufsiz))      // If found
            {
                b_eol=true;  // End of Line flag is TRUE
                b_bol=true;  // Beginning of Line flag is TRUE
            }
            else
                b_eol=false; // End of Line flag is FALSE

            Buf=Buf+lBufsiz; // Move the buffer pointer
            // Output the current string
            os << ptr;
            if (b_eol)       // If the End of Line flag is TRUE
                os << '\n';  // Append a carriage return to the output
        }
    }

    inputstream.rdbuf()->freeze ( 0 ); // ALLOW memory to be freed.

}

// str:
//   INPUT: NONE
//   OUTPUT: NONE
//   RETURN: The current contents of the this stream buffer as a
//           character string
//   This function overrides the strstream::str() function.  It sends the
//   contents of the current stream buffer as a character string to this
//   stream along with a NULL character to ensure the string is terminated.
//   Since there is no automated method for null terminating the stream
//   buffer, this function handles the possibility that the user has not
//   manually added a null to the end of the stream.  There should be no
//   ill effects if the steam has already been null terminated.
//
char *VDAStream::str()
{
    if (m_strbuf != NULL)
        delete[] m_strbuf;
    m_strbuf = new char[(strstream::pcount()+1)];
    memcpy(m_strbuf, strstream::str(), strstream::pcount());
    m_strbuf[strstream::pcount()] = '\0';
    return(m_strbuf);
}


_END_CERT_NAMESPACE 

// END OF sm_VDAStream.cpp
