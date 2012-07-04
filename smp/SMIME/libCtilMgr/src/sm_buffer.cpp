#ifndef NO_SCCS_ID
static char SccsId[ ] = "@(#) sm_buffer.cpp 1.28 02/04/00 01:55:05"; 
#endif

//////////////////////////////////////////////////////////////////////////
// sm_buffer.cpp
// This source file implements various members of the CSM_Buffer class.
// Be careful when you modify these
// members because code is being written based on the characteristics
// of these members...
//////////////////////////////////////////////////////////////////////////

//#include <stdio>
//#include <sys/types.h>
//
#include <sys/stat.h>



#ifdef WIN32
//#pragma warning(disable: 4100)
//#pragma warning(push,3)
//#include <ostream>
//#include <string>
//#pragma warning(pop)
#else
#include <unistd.h>   // for SEEK_CUR and SEEK_END
#include <string>
#endif

//#include "sm_apiCtilMgr.h"
#include "asn-incl.h"
#include "sm_buffer.h"
/*RWC5;#include "snaccexcept.h"
#include "sm_buffer.h"
#include "asn-incl.h"*/

_BEGIN_CTIL_NAMESPACE 

//////////////////////////////////////////////////////////////////////////
void CSM_Buffer::Clear()
{
    m_lSize = 0;
    m_pMemory = NULL;
    m_pszFN = NULL;
    m_pFP = NULL;
    m_pMemFP = NULL;
    m_pCache = NULL;
    m_lCacheSize = 0;
    m_pszMode = NULL;
    m_bTmpFile = false;
    m_pAllocPtr = NULL;
    m_pAllocPtrSize = 0;
    m_pszMode = NULL;
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer::CSM_Buffer(bool bTmpFileCreate)
{ 
    Clear();

    if (bTmpFileCreate)
    {
       char *pTmpName=tmpnam(NULL); // Get tmp name from system.
       m_pszFN = strdup(pTmpName);
       m_bTmpFile = true;           // indicate tmp file for cleanup
    }
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer::CSM_Buffer(size_t lSize)
{ 
    
    Clear();
    
    m_pMemory = (char *)calloc(1, lSize + 1);

    SetLength(lSize);
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer::CSM_Buffer(const char *pszFileName)
{
    const char *_func="CSM_Buffer::CSM_Buffer(char*)";
    try {
    
    Clear();
    
    if (pszFileName == NULL)
        throw SNACC::SnaccException(STACK_ENTRY, "pszFileName is NULL", 27);
    
    if ((m_pszFN = strdup(pszFileName)) == NULL)
        throw SNACC::SnaccException(STACK_ENTRY, pszFileName, 27);
    }

    catch (SNACC::SnaccException &Exception) {
      Exception.push(STACK_ENTRY);
      throw;
    }
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer::CSM_Buffer(const char *pBuf, SM_SIZE_T lSize) 
{
    Clear();
    
    if (pBuf != NULL)
      Set(pBuf, lSize);
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer::CSM_Buffer(const CSM_Buffer &b) 
{
    Clear();
    ReSet(b);
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer::~CSM_Buffer()
{
    if (m_pMemory && (m_pAllocPtr == NULL))
        free (m_pMemory);
    else if (m_pAllocPtr)
        free(m_pAllocPtr);
    if (m_pszFN)
    {
        if (m_bTmpFile)
            remove(m_pszFN);    // REMOVE from the system.
        free (m_pszFN);
    }
    if (m_pFP)
        fclose(m_pFP);
    if (m_pCache && m_pCache != (char *)m_pAllocPtr)
        free (m_pCache);
	if (m_pszMode)
		free(m_pszMode);
    Clear();
}

//////////////////////////////////////////////////////////////////////////
SM_SIZE_T CSM_Buffer::Length() const
{ 
    SM_SIZE_T lRet = 0;
    
    const char *_func="CSM_Buffer::Length";
    try {
    
    if (this->m_pMemory == NULL && InFile())
    {
        // file version
        struct stat statBuf;
        // how big is data in file
        if (stat(m_pszFN, &statBuf) == -1)
        {
           char pBuf[200];
           strcpy(pBuf, m_pszFN);
           throw SNACC::SnaccException(STACK_ENTRY, pBuf, 27);
        }
        lRet = statBuf.st_size;
    }
    else
    {
        // memory version
        lRet = m_lSize;
    }
    }   // END try
    catch (SNACC::SnaccException &Exception) {
      Exception.push(STACK_ENTRY);
      throw;
    }
    return lRet;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Buffer::Set(const char *psz)
{
    if (psz)
        Set(psz, strlen(psz));
}

//////////////////////////////////////////////////////////////////////////
void CSM_Buffer::Set(const char *p, size_t lSize)
{
    if (this->InFile())
    {                   // WRITE to file.
        this->Open(SM_FOPEN_WRITE);
        this->Write(p, lSize);
        this->Close();
    }
    else        // if InFile.
    {
        if (p == NULL)
        {
            if (m_pAllocPtr)
               free(m_pAllocPtr);
            else if (m_pMemory)
               free(m_pMemory);
            m_pAllocPtr = NULL;
            m_pMemory = NULL;
            m_lCacheSize = 0;     // Set exact.
            SetLength(0);
        }
        else
        {
            if (m_pAllocPtr)
               free(m_pAllocPtr);
            else if (m_pMemory)
               free(m_pMemory);
            
            m_pAllocPtr = NULL;
            m_pMemory = NULL;
            m_pCache = NULL;

            this->m_lSize = 0;  // HARD-SET since we just cleared memory.
            AllocMoreMem(lSize+1);
            memcpy(m_pMemory, p, lSize);
            //m_lCacheSize = lSize+1;      //SET at limit.
            SetLength(lSize);
        }
    }       // END if InFile().
}

//////////////////////////////////////////////////////////////////////////
// allocate memory in the cache
char* CSM_Buffer::Alloc(SM_SIZE_T lSize)
{
    if (m_pCache)
    {
        free(m_pCache);
        m_pCache = NULL;
    }
    AllocMoreMem(lSize);
    SetLength(lSize);      // Set for compatibility; up to app to override.
        
    return m_pMemory;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Buffer::AllocMoreMem(SM_SIZE_T lSize)
{
    char *pNew;
    SM_SIZE_T lLength = Length();
    
    pNew = (char *)calloc(1, lLength + lSize);
    if (m_pMemory && lLength)
    {
       memcpy(pNew, m_pMemory, lLength);
    }
    //SetLength(lLength + lSize);
    //   m_pMemFP = pNew + (m_pMemFP - m_pMemory);
    m_pMemFP = pNew + lLength;
    if (m_pAllocPtr == NULL)
    {
       if (m_pMemory)
          free(m_pMemory);
    }
    else
    {
       if (m_pCache == (char *)m_pAllocPtr)
          m_pCache = NULL;
       free(m_pAllocPtr);
       m_pAllocPtr = NULL;
    }
    if (this->m_pCache)
    {
       free(m_pCache);
       m_pCache = NULL;
    }
    m_lCacheSize = lLength + lSize;    // NEW max memory size.
    m_pMemory = pNew;
    m_pAllocPtr = (unsigned char *)pNew;
    m_pAllocPtrSize = m_lCacheSize;

}

//////////////////////////////////////////////////////////////////////////
   // Set actual data start within allocated memory buffer;this method added
   //  specifically for SNACC buffer handling performance improvement.
// This module will re-set/re-allocate memory if the specified pointer is not
//  within our existing buffer.  The return code will indicate that the memory
//  has been re-allocated(1).  This alleviates the calling application from 
//  having to worry about the re-build of a buffer if the SNACC operations 
//  had re-allocated memory.
int CSM_Buffer::SetDataPtr(unsigned char *pMemoryPointer,SM_SIZE_T lSize, 
      unsigned char *pBlkPtr, bool bIgnoreExistingMemoryFlag) 
            // RETURNS 0 if successful, 1 if 
            //  specified (char *) is not in range.
{
   int status=0;

   if (m_pAllocPtr == NULL)
   {
      if (m_pMemory == NULL && m_pCache != NULL)
      {
         m_pMemory = m_pCache;
         m_lSize = m_lCacheSize;
      }
      m_pAllocPtr = (unsigned char *)m_pMemory;   // Keep track of start pointer for free(...).
      m_pAllocPtrSize = m_lSize;
   }
   if (pMemoryPointer >= m_pAllocPtr && 
       pMemoryPointer < (m_pAllocPtr  + m_pAllocPtrSize))
   {        // Within range.
      m_lSize = lSize;
      m_lCacheSize = lSize;     // Set exact.
      m_pMemory = (char *)pMemoryPointer;
   }
   else  // Take the application's memory, after freeing our own.
   {
      //RWC; 10/7/00; DUE TO THE NATURE of the re-assignment when dealing
      //RWC;  with these performance improvements, the original memory has
      //RWC;  already been released by SNACC.  The following logic has been
      //RWC;  disabled.
      if (!bIgnoreExistingMemoryFlag)
      {     // ONLY free existing memory if requested to do so (DEFAULT).
         if (m_pAllocPtr)
         {
            free(m_pAllocPtr);
         }
         if (m_pCache && m_pCache != (char *)m_pAllocPtr)
           free (m_pCache);
      }
      m_pAllocPtr = pBlkPtr; // calloc block start
      m_pCache = NULL;
      m_pMemory = (char *)pMemoryPointer;
      m_lCacheSize = lSize;     // Set exact.
      m_pAllocPtrSize = m_lSize = lSize;
   }

   return(status);
}

// This method relinquishes control of the allocated memory to the application,
//  it will not free this memory on destruction after this call; the data will 
//  not be accessible through "this" after this call.  Its purpose is to allow
//  an application to re-use our memory, not have to copy the memory for 
//  performance.
void CSM_Buffer::GiveApplicationPtrs(unsigned char *&pMemoryPointer,SM_SIZE_T &lSize, 
      unsigned char *&pBlkPtr)
{
      pMemoryPointer = (unsigned char *)m_pMemory;
      lSize = m_lSize;
      if (m_pAllocPtr == NULL)
      {
        pBlkPtr = (unsigned char *)m_pCache;
      }
      else
      {
        pBlkPtr = m_pAllocPtr;
      }
      m_pAllocPtr = NULL;
      m_pCache = NULL;
      m_pMemory = NULL;
      m_lSize = 0;
}
//////////////////////////////////////////////////////////////////////////
const char * CSM_Buffer::Access() const
{
    if (InFile())
    {
        // if the data is in a file AND
        // if there's already memory in m_pMemory then free it
        if (m_pMemory)
        {
           if (m_pAllocPtr == NULL)
           {
              free(m_pMemory);
           }
           else
           {
              free(m_pAllocPtr);
              m_pAllocPtr = NULL;
              this->m_lCacheSize = 0;
              this->m_pCache = NULL;
           }
           m_pMemory = NULL;
        }
        m_pMemory = Get();
        m_lCacheSize = Length();     // Set exact.
    }
    return m_pMemory;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Buffer::SetFileName(char *pszFN)
{
        if (m_pMemory)
        {
           if (m_pAllocPtr == NULL)
           {
              free(m_pMemory);
           }
           else
           {
              free(m_pAllocPtr);
              m_pAllocPtr = NULL;
           }
           m_pMemory = NULL;
        }
        m_pMemory = NULL; 
        m_pszFN = (char *) strdup((const char *) pszFN);
}


//////////////////////////////////////////////////////////////////////////
// return a NULL terminated copy of the actual data and return the size
char* CSM_Buffer::Get(SM_SIZE_T &l) const
{
    char *pRet = NULL;
    const char *_func="CSM_Buffer::Get";
    
    SM_SIZE_T lSize = Length();
 
    try
    {
       if (this->m_pMemory == NULL && InFile()) // data in file
       {
           // allocate memory
           if ((pRet = (char *)calloc(1, lSize + 1)) == NULL)
              throw SNACC::SnaccException(STACK_ENTRY, "pRet", 27);
           // close file if present
           if (m_pFP != NULL)
               fclose(m_pFP);
           // open the file
           if ((m_pFP = fopen(m_pszFN, SM_FOPEN_READ)) == NULL)
           {
              throw SNACC::SnaccException(STACK_ENTRY, m_pszFN, 27);
           }
           // read the data
           long lRead = fread(pRet, 1, lSize, m_pFP);
           if (ferror(m_pFP) != 0)
           {
              throw SNACC::SnaccException(STACK_ENTRY, m_pszFN, 27);
           }
           // close and clear FP
           fclose(m_pFP);
           m_pFP = NULL;
           m_lSize = lRead;
           l = lRead; // store the size that will be returned
       }
       else
       {
           // if there is data, duplicate it
           if (m_pMemory)
           {
               pRet = (char *)calloc(1, lSize + 1);
               memcpy(pRet, m_pMemory, lSize);
               l = lSize; // store the size that will be returned
           }
       }
    } 
    catch (SNACC::SnaccException &Exception) {
      Exception.push(STACK_ENTRY);
      throw;
    }
    catch (...)
    {
       if (pRet != NULL)
           free(pRet);
       if (m_pFP != NULL)
       {
           fclose(m_pFP);
           m_pFP = NULL;
       }
       throw;
    }
    return pRet;
}

//////////////////////////////////////////////////////////////////////////
// compare buffers regardless of memory/file status
long CSM_Buffer::Compare(const CSM_Buffer &b) const
{
    const char *p1 = NULL;
    const char *p2 = NULL;
    long lRet = -2;
    
    // use AccessAll on both buffers for comparison.  If buffer is in
    // file, then this results in a CopyAll which isn't as efficient,
    // but this can be fixed later...
    if ((p1 = Access()) != NULL)
    {
        if ((p2 = b.Access()) != NULL)
        {
            if (Length() == b.Length())
                lRet = (long)memcmp(p1, p2, Length());
            // p1 and p2 are the same as the memory pointers in
            // the buffers so they do not need to be freed, they
            // will be freed by the buffer's destructor
        }
    }
    return lRet;
}

//////////////////////////////////////////////////////////////////////////
// copy b into this
long CSM_Buffer::ReSet(const CSM_Buffer &b)
{
    m_pMemory = m_pszFN = m_pMemFP = NULL;
    m_pFP = NULL;
    SetLength(0);
    m_pCache = NULL;
    m_lCacheSize = 0;
    
    Set(b.Access(), b.Length());
   
    return SNACC_OK;
}

//////////////////////////////////////////////////////////////////////////
// ConvertFileToMemory makes a CSM_Buffer storing its contents in
// file into a CSM_Buffer storing its contents in memory
long CSM_Buffer::ConvertFileToMemory()
{
    Access();        // READ if necessary.
    
    // free the file name
    if (m_bTmpFile)
    {
        remove(m_pszFN);
        m_bTmpFile = false;
    }
    free(m_pszFN);
    m_pszFN = NULL;
    
    return SNACC_OK;
    
}

//////////////////////////////////////////////////////////////////////////
// ConvertMemoryToFile makes a CSM_Buffer storing its contents in
// buffer into a CSM_Buffer storing its contents in file
long CSM_Buffer::ConvertMemoryToFile(char *pszFN)
{
    const char *_func="CSM_Buffer::ConvertMemoryToFile";
    try {
    
    SM_SIZE_T lRet = 0;
    
    if (pszFN == NULL)
        throw SNACC::SnaccException(STACK_ENTRY, "pszFN is NULL", 27);

       if (InFile())
       {
           if (strcmp(m_pszFN, pszFN) == 0)   // we're already in file
               return SNACC_OK;
           else
           {
               SM_SIZE_T lBytesRead;
               SM_SIZE_T lSize=16384;
               char *ptr;
               FILE *fp=fopen(pszFN, SM_FOPEN_WRITE);
               this->Open(SM_FOPEN_READ);
               while ((ptr=this->nRead(lSize, lBytesRead)) != NULL && lBytesRead > 0)
               {
                   fwrite(ptr, 1, lBytesRead, fp);
               }
               this->Close();
               fclose(fp);
               return(SNACC_OK);
           }
       }
    
       // open the new file
       if ((m_pFP = fopen(pszFN, SM_FOPEN_WRITE)) == NULL)
       {
           throw SNACC::SnaccException(STACK_ENTRY, pszFN, 27);
       }
    
       // write the data
       SM_SIZE_T lLength = Length();
       // store the file name
       if ((m_pszFN = strdup(pszFN)) == NULL)
          throw SNACC::SnaccException(STACK_ENTRY, pszFN, 27);
    
       if ((lRet = fwrite(m_pMemory, 1, lLength, m_pFP)) != lLength)
       {
          throw SNACC::SnaccException(STACK_ENTRY, pszFN, 28);
       }
    
       fclose(m_pFP);
       m_pFP = NULL;
    }

    catch (SNACC::SnaccException &Exception) {
       // cleanup/catch code
       if ((m_pszFN != NULL) && (pszFN != NULL))
       {
           free(m_pszFN);
           m_pszFN = NULL;
       }
      Exception.push(STACK_ENTRY);
      throw;
    }
            
    return SNACC_OK;
}

//////////////////////////////////////////////////////////////////////////
long CSM_Buffer::Open(char *pszMode)
{
    const char *_func="CSM_Buffer::Open";
    try {
    
    if (pszMode == NULL)
        throw SNACC::SnaccException(STACK_ENTRY, "pszMode is NULL", 27);
    
    if (m_pszMode != NULL)
        free(m_pszMode);
    
    m_pszMode = strdup(pszMode);
    
    if (!InFile())
    {
        // memory version
        m_pMemFP = m_pMemory; // set current pointer to start
    }
    else
    {
        // file version
        if ((m_pFP = fopen(m_pszFN, pszMode)) == NULL)
        {
           throw SNACC::SnaccException(STACK_ENTRY, m_pszFN, 27);
        }
    }

    if (strcmp(pszMode, SM_FOPEN_WRITE) == 0)
       this->m_lSize = 0;     // RESET counter.

    }       // END try

    catch (SNACC::SnaccException &Exception) {
      Exception.push(STACK_ENTRY);
      throw;
    }

    return SNACC_OK;
}

//////////////////////////////////////////////////////////////////////////
long CSM_Buffer::Seek(SM_SIZE_T lOffset, SM_SIZE_T lOrigin)
{
    
    long lRet = SNACC_OK;
    const char *_func="CSM_Buffer::Seek()";
    try {
    
    if (!InFile())
    {
        // memory version
        char *pSave = m_pMemFP;
        
        if (m_pMemFP == NULL)
        {
           throw SNACC::SnaccException(STACK_ENTRY, "Can not seek on empty buffer", 27);
        }
        
        SM_SIZE_T lLength = Length();
        
        switch (lOrigin)
        {
        case SEEK_CUR:
            m_pMemFP += lOffset;
            break;
        case SEEK_END:
            m_pMemFP = (m_pMemory + lLength - 1) + lOffset;
            break;
        default: // SEEK_SET
            m_pMemFP = m_pMemory + lOffset;
            break;
        }
        if ((m_pMemFP > (m_pMemory + lLength - 1)) ||
            (m_pMemFP < m_pMemory))
        {
            m_pMemFP = pSave;
            lRet = -1;
        }
    }
    else
    {
        // file version
        if (m_pFP == NULL)
        {
           throw SNACC::SnaccException(STACK_ENTRY, "Can not seek on empty buffer", 27);
        }
        
        lRet = fseek(m_pFP, lOffset, lOrigin);
    }
    }       // END try
    
    catch (SNACC::SnaccException &Exception) {
      Exception.push(STACK_ENTRY);
      throw;
    }

    return lRet;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Buffer::Close()
{
    if (m_pszMode != NULL)
    {
        free(m_pszMode);
        m_pszMode = NULL;
    }
    
    if (m_pFP != NULL)
    {
        fclose(m_pFP);
        m_pFP = NULL;
        if (m_pMemory)
        {
           if (m_pAllocPtr == NULL)
           {
              free(m_pMemory);
           }
           else
           {
              free(m_pAllocPtr);
              m_pAllocPtr = NULL;
           }
           m_pMemory = NULL;
           m_lCacheSize = 0;     // Set exact.
        }
    }
    else
        m_pMemFP = NULL;
}

//////////////////////////////////////////////////////////////////////////
long CSM_Buffer::cRead(char *pBuffer, SM_SIZE_T lSize)
{
    
    long lRet = 0;
    
    if ((pBuffer == NULL) || (lSize <= 0))
         return lRet;
    
    if (!InFile())
    {
        // memory version
        if (m_pMemFP == NULL)
           return lRet;
        
        SM_SIZE_T lReadSize = lSize;
        SM_SIZE_T lLength = Length();
        // adjust the read size to what's possible
        if ((m_pMemFP + lReadSize) > (m_pMemory + lLength))
            lReadSize = (m_pMemory + lLength) - m_pMemFP;
        memcpy(pBuffer, m_pMemFP, lReadSize);
        // adjust the current pointer
        if (lReadSize > 0)
        {
            m_pMemFP += lReadSize;
            lRet = lReadSize;
      }
      else
         lRet = 0;
   }
   else
   {
      // file version
      if (m_pFP == NULL)
         return lRet;

      lRet = fread(pBuffer, 1, lSize, m_pFP);
   }

   return lRet;
}

//////////////////////////////////////////////////////////////////////////
long CSM_Buffer::Write(const char *pBuffer, SM_SIZE_T lSize)
{
   
   long lRet = 0;
   bool appendMode = false;
   bool firstTimeFlag = false;

   long lSizeExtra=lSize;
   if (lSizeExtra < 100000)
      lSizeExtra *= 10;
   if (lSizeExtra < 10000)
      lSizeExtra *= 40;    // Allocate extra memory to avoid re-allocing
                           //  and re-copying memory many-many-many times.
   if ((pBuffer == NULL) || (lSize <= 0))
         return lRet;

   if (!InFile())
   {
      // if mode is set check it to make sure we can write
      //
      if (m_pszMode != NULL)
         if (strcmp(m_pszMode, SM_FOPEN_READ) == 0)
         {
            return lRet;
         }
         else if (strcmp(m_pszMode, SM_FOPEN_APPEND) == 0)
            appendMode = true;

      // memory version
      if (m_pMemFP == NULL)
      {
         if (m_pMemory == NULL)

         {
            firstTimeFlag = true;
            // if we get here, we assume that the memory
            // hasn't been allocated yet, allocate it...
            AllocMoreMem(lSizeExtra);
         }
         else
            m_pMemFP = m_pMemory;
      }

      // IF we are not in append mode check to see if we have enough memory
      // to store the data.  If not allocate space for it and write the data
      // starting at the CURRENT location.
      // ELSE allocate enough space to handle the data being written and write
      // it at the END of the buffer.
      //
      if (!appendMode)
      {    
         // do we have enough space to write to this buffer?

         if ((SM_SIZE_T)(((m_pMemory + m_lCacheSize/*Length()*/) - m_pMemFP)) < lSize)
            // nope, get lSize more bytes
            AllocMoreMem(lSizeExtra);
      }
      else if (!firstTimeFlag)
      {
         AllocMoreMem(lSizeExtra);  
         //m_pMemFP = m_pMemory + Length() - lSize;
         //this->m_lCacheSize = 0;
         this->m_pCache = NULL;  // CLEAR since replaced.
      }
      memcpy(m_pMemFP, pBuffer, lSize);
      m_pMemFP += lSize;
      m_lSize += lSize;
      lRet = lSize;
   }
   else
   {
      // file version
      if (m_pFP == NULL)
         return lRet;

      if ((lRet = fwrite(pBuffer, 1, lSize, m_pFP)) > 0)
         SetLength(m_lSize + lRet);
   }

   return lRet;
}

//////////////////////////////////////////////////////////////////////////
char* CSM_Buffer::nRead(SM_SIZE_T lSize, SM_SIZE_T &lBytesRead)
{
   
   char *pRet = NULL;
   const char *_func="CSM_Buffer::nRead";
   try {

   if (lSize <= 0)
      throw SNACC::SnaccException(STACK_ENTRY, "lSize <= 0", 27);

   if (!InFile())
   {
      // memory version
      if (m_pMemFP == NULL)
         throw SNACC::SnaccException(STACK_ENTRY, "Buffer is empty", 27);

      SM_SIZE_T lReadSize = lSize;
      SM_SIZE_T lLength = Length();
      // adjust the read size to what's possible
      if ((m_pMemFP + lReadSize) > (m_pMemory + lLength))
         lReadSize = (m_pMemory + lLength) - m_pMemFP;
      pRet = m_pMemFP;
      // adjust the current pointer
      if (lReadSize > 0)
      {
         m_pMemFP += lReadSize;
         lBytesRead = lReadSize;
      }
      else
         lBytesRead = 0;
   }
   else
   {
      // file version
      if (m_pFP == NULL)
         throw SNACC::SnaccException(STACK_ENTRY, "Buffer is empty", 29);

      // if there's something already in the memory, free it
      if (m_pMemory != NULL && m_pAllocPtr == NULL)
      {
         free (m_pMemory);
         m_pMemory = NULL;
         this->m_lSize = 0;
      }
      else
      {
         if (m_pCache == (char *)m_pAllocPtr)
            m_pCache = NULL;
         free(m_pAllocPtr);
         m_pAllocPtr = NULL;
         m_pMemory = NULL;
         this->m_lSize = 0;
      }
      // allocate memory to receive the read data
      AllocMoreMem(lSize+1);
      // now, read into the memory cache
      lBytesRead = fread(m_pMemory, 1, lSize, m_pFP);
      this->SetLength(lBytesRead);
      // now set what we'll return
      pRet = m_pMemory;
   }
   }    // END try

   catch (SNACC::SnaccException &Exception) {
      Exception.push(STACK_ENTRY);
      throw;
    }

   return pRet;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Buffer::Flush()
{
    if (m_pCache != NULL)
    {
        Write(m_pCache, m_lCacheSize);
        free(m_pCache);
        m_pCache = NULL;
        m_lCacheSize = 0;
    }
}

void CSM_Buffer::ReportHexBuffer(std::ostream &os) const
{
    ReportHexBuffer(os, Access(), Length());
}

void CSM_Buffer::HexBufferToString(char *&ptrOut, const char *ptr, int iLen) 
{
    int i;
    
    ptrOut = (char *) calloc(1, iLen*2+10);
    
    for (i=0; i < iLen; i++)
    {
        sprintf(&ptrOut[i*2], "%2.2x", (unsigned char)ptr[i]);
    }
}

void CSM_Buffer::ReportHexBuffer(std::ostream &os, const char *ptr, int iLen)
{
    char *ptrOut=NULL;
    HexBufferToString(ptrOut, ptr, iLen);
    os << ptrOut << '\0';
    free(ptrOut);
}
// FUNCTION: reverseOctets()
//
// PURPOSE: Used when necessary by crypto operations.  It reverses the octets in the buffer.  
//          I.E. the last octet becomes the first octet.
void CSM_Buffer::reverseOctets(void)
{
   char tmpChar;
   // IF file is used make sure it's loaded into memory
   //
   ConvertFileToMemory();
   for(unsigned int i = Length(); i > Length()/2; i--)
   {
      tmpChar = m_pMemory[Length() - i];
      m_pMemory[Length() - i]= m_pMemory[i-1];
      m_pMemory[i-1] = tmpChar;
   }
}


//
//
unsigned long CSM_Buffer::Decode(SNACC::AsnType& snaccObj) const
{
	SNACC::AsnLen numDecoded = 0;
	if (InFile())
	{
		// Create a SNACC::AsnBuf from the file name
		SNACC::AsnBuf asnBuf(m_pszFN);

		// Decode the file
		snaccObj.BDec(asnBuf, numDecoded);
	}
	else
	{
		// Create a SNACC::AsnRvsBuf and install it into the AsnBuf
		SNACC::AsnRvsBuf asnStream(m_pMemory, m_lSize);
		SNACC::AsnBuf asnBuf(&asnStream);

		// Decode the object
		snaccObj.BDec(asnBuf, numDecoded);
	}

	// Return the number of bytes decoded
	return numDecoded;
}   // END Decode(...)

//
//
unsigned long CSM_Buffer::Encode(SNACC::AsnType& snaccObj)
{
   SNACC::AsnBuf asnBuf;
   asnBuf.ResetMode(std::ios_base::out);
   SNACC::AsnLen istatus=0;
   istatus = snaccObj.BEnc(asnBuf);

   asnBuf.ResetMode();
   SNACC::AsnLen iBytesDecoded = asnBuf.length();
   if(istatus)
   {
      char *ptr=asnBuf.GetSeg(iBytesDecoded);
      if (ptr && iBytesDecoded > 0)
      { 
         this->Set((const char *)ptr, iBytesDecoded);
         delete[] ptr;
      }
   }

   return iBytesDecoded;
}   // END Decode(...)


_END_CTIL_NAMESPACE 
