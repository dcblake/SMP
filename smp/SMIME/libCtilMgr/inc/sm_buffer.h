
#include "asn-config.h"

// PIERCE
//
#ifndef _SM_BUFFER_H_
#define _SM_BUFFER_H_

#ifndef LIBCTILMGRDLL_API      // DEFINE on compile line to "" for Static refs
#ifdef WIN32
#ifdef LIBCTILMGRDLL_EXPORTS
#define LIBCTILMGRDLL_API __declspec(dllexport)
#else
#define LIBCTILMGRDLL_API __declspec(dllimport)
#endif          // LIBCTILMGRDLL_EXPORTS
#else           // Handle Unix...
#define LIBCTILMGRDLL_API
#endif          // WIN32
#endif          // ifndef LIBCTILMGRDLL_API

#ifndef NO_NAMESPACE
#define _BEGIN_CTIL_NAMESPACE namespace CTIL {
#define _END_CTIL_NAMESPACE }
#else
#define _BEGIN_CTIL_NAMESPACE
#define _END_CTIL_NAMESPACE
#endif




#ifdef WIN32
#include <stdlib.h>
#include <stdio.h>
#define SM_FOPEN_WRITE "wb"
#define SM_FOPEN_READ "rb"
#define SM_FOPEN_APPEND "ab"
#else
#ifndef FILE
#include <stdio.h>
#endif  // FILE 
#define SM_FOPEN_WRITE "w"
#define SM_FOPEN_READ "r"
#define SM_FOPEN_APPEND "a"
#endif

#define VDASNACC_ENCDEC_BUFSIZE 100000

#ifndef _SM_APIC_H_
#define NULL_STR (Str_struct *) NULL

#define SM_SIZE_T size_t

/* General data holding structure */
/*typedef struct {
   SM_SIZE_T lLength;
   char *pchData;
} SM_Str;*/

#endif // _SM_APIC_H_
//
// end of PIERCE

_BEGIN_CTIL_NAMESPACE 

//////////////////////////////////////////////////////////////////////////
// CSM_Buffer is the general purpose buffer used throughout the SFL and
// SNACC
class LIBCTILMGRDLL_API CSM_Buffer {
private:
   mutable SM_SIZE_T m_lSize;
   mutable char *m_pMemory;
   char *m_pszFN;
   mutable FILE *m_pFP;
   char *m_pMemFP;
   mutable char *m_pCache;
   mutable SM_SIZE_T m_lCacheSize;
   char *m_pszMode;
   bool m_bTmpFile;     // Temp file flag for deletion.
   mutable unsigned char *m_pAllocPtr;   
                        // This special pointer allows for a larger
                        //  memory allocation, reverse buffer load
                        //  (specifically for SNACC use, performance).
   SM_SIZE_T m_pAllocPtrSize;

   // returns bool value indicating if the buffer is in a file
   bool InFile() const { if (m_pszFN == NULL) return false; else return true; }
   // AllocMoreMem allocates specified more bytes for mem buffer
   void AllocMoreMem(SM_SIZE_T lSize);


public:
   // CONSTRUCTORS
   // use this constructor to create a complete empty buffer
   CSM_Buffer() { Clear(); }
   CSM_Buffer(bool bTmpFileCreate);
   // use this constructor to create a memory buffer of size lSize
   CSM_Buffer(size_t lSize);
   // use this constructor to create a buffer from file pszFileName
   CSM_Buffer(const char *pszFileName);
   // use this constructor to init the memory buffer with a ptr and size
   CSM_Buffer(const char *pBuf, SM_SIZE_T lSize);
   // use this constructor to make a copy of the provided buffer
   // and put it into this buffer
   CSM_Buffer(const CSM_Buffer &b);

   virtual ~CSM_Buffer(); // DESTRUCTOR

   void Clear();

   // ATTRIBUTE MEMBERS
   // return size of the buffer
   SM_SIZE_T Length() const;
   // copy the provided null terminated memory in memory buffer
   void Set(const char *psz);
   // copy the provided memory of size lSize in memory buffer
   void Set(const char *p, SM_SIZE_T lSize);
   // set the length of the buffer
   void SetLength(SM_SIZE_T lSize) { m_lSize = lSize; }
   // copy the provided file name into m_pszFN
   void SetFileName(char *pszFN);
   // Set actual data start within allocated memory buffer;this method added
   //  specifically for SNACC buffer handling performance improvement.
   int SetDataPtr(unsigned char *pMemoryPointer,   // IN,data ptr
                  SM_SIZE_T lSize,                 // IN,size of data
                  unsigned char *pBlkPtr=NULL,     // IN,alloc blk ptr; only
                                                   //  used if replaced.
                  bool bIgnoreExistingMemoryFlag=false);
                                                   // IN,flag to not free 
                                                   //  existing mem if replaced
                                                   //  (DEFAULT is FALSE).
               // RETURNS 0 if successful, 1 if 
               //  specified (char *) is not in range.
   unsigned long Encode(SNACC::AsnType& snaccObj);
   unsigned long Decode(SNACC::AsnType& snaccObj) const;
   // This next method relinquishes control of the allocated memory to the 
   //  application, it will not free this memory on destruction after this 
   //  call; the data will not be accessible through "this" after this call.
   //  Its purpose is to allow an application to re-use our memory, not have 
   //  to copy the memory for performance.
   void GiveApplicationPtrs(unsigned char *&pMemoryPointer,SM_SIZE_T &lSize, 
      unsigned char *&pBlkPtr);
   // allocate memory in the buffer and return ptr to it
   char* Alloc(SM_SIZE_T lSize);
   // compare this with b, return 0 if match
   long Compare(const CSM_Buffer &b) const;
   // ReSet copies b into this
   long ReSet(const CSM_Buffer &b);

   // BUFFER DATA ACCESS MEMBERS
   // return a pointer to the actual data, if in file, call CopyAll
   const char* Access() const;
   // return a null terminated copy of the actual data and return the size
   char* Get(SM_SIZE_T &l) const;
   // return a null terminated copy of the actual data
   char* Get() const { SM_SIZE_T l; return Get(l); }

   // COMPARISON OPERATORS
   bool operator == (const CSM_Buffer &b) const { 
         if (Compare(b) == 0) return true; else return false; }
   bool operator != (const CSM_Buffer &b) const { 
         if (Compare(b) == 0) return false; else return true; }

   // ASSIGNMENT OPERATOR
   CSM_Buffer &operator = (const CSM_Buffer &b) { 
         Set(b.Access(), b.Length()); return *this; }
   
   // BUFFER CONVERSION MEMBERS
   long ConvertFileToMemory();
   long ConvertMemoryToFile(char *pszFN);

   // STREAMING MEMBERS
   long Open(char *pszMode);
   long Seek(SM_SIZE_T lOffset, SM_SIZE_T lOrigin);
   void Close();

   // STREAMING MEMBERS
   long cRead(char *pBuffer, SM_SIZE_T lSize);
   long Write(const char *pBuffer, SM_SIZE_T lSize);
   char* nRead(SM_SIZE_T lSize, SM_SIZE_T &lBytesRead);
   void Flush();

   // Members used to print to output stream a CSM_Buffer in hex
   void ReportHexBuffer(std::ostream &os) const;
   static void HexBufferToString(char *&ptrOut, const char *ptr, int iLen);
   static void ReportHexBuffer(std::ostream &os, const char *ptr, int iLen);
   void reverseOctets(void);
};


_END_CTIL_NAMESPACE 

#endif // _SM_BUFFER_H_
