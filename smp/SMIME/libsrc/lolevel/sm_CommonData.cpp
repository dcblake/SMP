
//////////////////////////////////////////////////////////////////////////
// sm_CommonData.cpp implements the members from CSM_CommonData

#include "zlib.h"
#include "sm_api.h"

#ifndef WIN32
typedef unsigned char byte;
#endif

#define UNCOMPRESS_BUFFER_SIZE 2048

_BEGIN_SFL_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
CSM_CommonData::~CSM_CommonData()
{
   ClearAll();
}
//////////////////////////////////////////////////////////////////////////
void CSM_CommonData::ClearAll()
{
   if (m_pContentFromAsn1)
      delete m_pContentFromAsn1;

   if (m_pEncodedBlob)
      delete m_pEncodedBlob;

   if (m_pszCMLError)
      free(m_pszCMLError);

   if (m_pContentClear)
      delete m_pContentClear;

   // reinitialize variables
   Clear();
}


//////////////////////////////////////////////////////////////////////////
void CSM_CommonData::SetEncodedBlob(const CSM_Buffer *pBlob)
{
   SME_SETUP("CSM_CommonData::SetEncodedBlob");

   if (pBlob)
   {
      if (m_pEncodedBlob)
         delete m_pEncodedBlob;
      if ((m_pEncodedBlob = new CSM_Buffer(*pBlob)) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      /*RWC;4/8/02;REMOVED to allow separate load of content;if (m_pContentFromASN1)
         delete m_pContentFromASN1;
      m_pContentFromASN1 = NULL;**/
   }

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
//
//  Function Name:  AccessEncapContentFromAsn1()
//  
//  Description:  This function checks to see if the m_bCompressData flag 
//                is set to 1, and if so the m_pContentClear data (assigned in fill()
//                during the sign::fill() or encrypt::fill())
//                will be compressed and set into m_pContentFromAsn1 object and
//                then returned.  Else If m_bCompressData flag is not set then
//                this function will return m_pContentClear data and 
//                assign it to m_pContentFromAsn1
//                Else if the compressed data is wanted which has already been compressed
//                previously, then return m_pContentFromAsn1.
//
//  Return:  CSM_Content which is either compressed m_pContentFromAsn1 or just
//           m_pContentFromAsn1 without compressing, (both built from m_pContentClear)  
//           depending on the m_bCompressData flag.
//
const CSM_Content *CSM_CommonData::AccessEncapContentFromAsn1()
{
   CSM_Content *pContentReturned = NULL;

   SME_SETUP("CSM_CommonData::AccessEncapContentFromAsn1()");

    // check the compressDataFlag and compress the data if requested
    if ((GetCompressFlag() == true) && 
       m_pContentClear != NULL && m_pContentFromAsn1 == NULL)
    {
       CSM_Buffer     *pZippedEncodedBuf = NULL;  // will hold the encoded compressed data

       pZippedEncodedBuf = BuildCompressedData();
       if (pZippedEncodedBuf != NULL)
       {
          // assigned to m_pContentFromAsn1
          m_pContentFromAsn1 = new CSM_Content(pZippedEncodedBuf,AsnOid(id_ct_compressedData));
          pContentReturned = m_pContentFromAsn1;

          // clean up
          delete(pZippedEncodedBuf);
       }
       else // failed to compress the data 
          SME_THROW(22, "Failed compression of the content.", NULL);

    }
   else if ((GetCompressFlag() == false) &&
      m_pContentClear != NULL && m_pContentFromAsn1 == NULL)
   {
      // and return with a CSM_Content m_pContentClear
      pContentReturned = m_pContentClear;
   }
   else if (m_pContentFromAsn1 != NULL)
   {
      // return compressed content
      pContentReturned = m_pContentFromAsn1;
   }

   SME_FINISH_CATCH

   return pContentReturned;

} // end AccessEncapContentFromAsn1()  


//////////////////////////////////////////////////////////////////////////
//
//  Function Name:  AccessEncapContentClear()
//  
//  Description:  This function checks to see if the m_pContentFromAsn1 content type oid 
//                is id_ct_compressedData and m_pContentFromClear is null, and if so the 
//                m_pContentFromAsn1 data will be uncompressed and set into the 
//                CSM_Content m_pContentClear  member and then returned. If it is set in 
//                the m_pContentClear object then there will be no further need to decode 
//                the m_pContentFromAsn1 object when called.
//                If the m_pContentFromAsn1 content type oid is id_ct_compressedData,
//                and m_pContentFromClear is not null the the function will return
//                m_pContentClear.  If the m_pContentFromAsn1 content type oid is 
//                not id_ct_compressedData then the function will return m_pContentClear
//                else the function wil return m_pContentFromAsn1.
//
//  Return:  CSM_Content m_pContentClear if content type is id_ct_compressedData 
//                       or m_pContentFromAsn1  
//
const CSM_Content *CSM_CommonData::AccessEncapContentClear()
{
   CSM_Content         *pContentReturned = m_pContentClear;  // set as default
   const SNACC::AsnOid *pOid = NULL;      

   // always uncompress if necessary 
   // check for normal message after the decode and assign it

   SME_SETUP("CSM_CommonData::AccessEncapContentClear()");


   if (m_pContentFromAsn1 != NULL)
      pOid = &m_pContentFromAsn1->m_contentType;

   if ((pOid != NULL) &&
      (*pOid == id_ct_compressedData) && 
      (m_pContentClear == NULL))
   {
      long                lstatus = 0;
      CompressedData      SNACCCompressedData;
      CSM_Buffer          *pCompressedData = NULL;
      CSM_Buffer          *pUncompressedBuf = NULL;
      
      CSM_Buffer CompressedContent(m_pContentFromAsn1->m_content.Access(),
                       m_pContentFromAsn1->m_content.Length());

      // decode the input buffer
      DECODE_BUF_NOFAIL(&SNACCCompressedData, &CompressedContent, lstatus);

      if (lstatus == 0)
      {      
         if ((pCompressedData = new 
            CSM_Buffer(SNACCCompressedData.encapContentInfo.eContent->c_str(),
            SNACCCompressedData.encapContentInfo.eContent->Len())) == NULL)
         {
            SME_THROW(SM_MEMORY_ERROR, "BAD new CSM_Buffer on CompressedData", NULL);
         }    // END if new CSM_Buffer.

         if (SNACCCompressedData.compressionAlgorithm.algorithm != id_alg_zlibCompress)
         {
            SME_THROW(22, "Decompression alg must be id_alg_zlibCompress on CompressedData", NULL);
         }
         // uncompress the data
         lstatus = UncompressData(pCompressedData, pUncompressedBuf);

         if (lstatus == 0)
         {
            // set the uncompressed data 
            SetEncapContentClear(*pUncompressedBuf, 
               SNACCCompressedData.encapContentInfo.eContentType);

            pContentReturned = m_pContentClear;

            if (pCompressedData)
            {
               delete pCompressedData;
               pCompressedData = NULL;
            }
             
            if (pUncompressedBuf)
            {
               delete pUncompressedBuf;
               pUncompressedBuf = NULL;
            }
         }
         else
         {
            if (pCompressedData)
               delete pCompressedData;
            if (pUncompressedBuf)
               delete pUncompressedBuf;
            SME_THROW(22, "Error decoding uncompressed data", NULL);
         }
      } 
      else
      {
            SME_THROW(22, "Error decoding m_pContentFromAsn1 - CompressedData", NULL);
      }
   }
   else if ((pOid != NULL) && 
           (*pOid == id_ct_compressedData) && 
           (m_pContentClear != NULL))
   {
      // content already uncompressed and decoded earlier
      // assign clear content m_pContentFromAsn1
      pContentReturned = m_pContentClear;   

   }
   else if ((pOid != NULL) && 
           (*pOid != id_ct_compressedData) && 
           (m_pContentClear != NULL))
   {
      // content not zipped
      pContentReturned = m_pContentClear;   
   }
   else if (pOid != NULL)
   {
      // there's no data in m_pContentClear

      // content not zipped - assign m_pContentFromAsn1
      pContentReturned = m_pContentFromAsn1;   
   }

  

   SME_FINISH_CATCH

   return pContentReturned;

}

//////////////////////////////////////////////////////////////////////////
void CSM_CommonData::UpdateEncodedBlob(CSM_Buffer *pBlob)
{
   if (m_pEncodedBlob) 
      delete m_pEncodedBlob;
   m_pEncodedBlob = pBlob;
   //RWC;5/3/01;REMOVED to allow re-build ED;if (m_pContentValue) 
   //   delete m_pContentValue;
}

//////////////////////////////////////////////////////////////////////////
//
// NOTE:  need to delete both m_pContentFromAsn1 and m_pContentClear
//        to get rid of old data
//
void CSM_CommonData::SetEncapContentClear(const CSM_Content &EncapContent)
{   
   SME_SETUP("CSM_CommonData::SetEncapContentClear");
   if (m_pContentFromAsn1) 
   {
      delete m_pContentFromAsn1;
      m_pContentFromAsn1 = NULL;  
   }

   if (m_pContentClear)
   {
      delete m_pContentClear;
      m_pContentClear = NULL;
   }

   if ((m_pContentClear = new CSM_Content(EncapContent)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, "Bad new operator of CSM_Content", NULL);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_CommonData::SetEncapContentClear(const CSM_Buffer &EncapContent, 
        const AsnOid &OidType)    // IN, OPTIONAL, Clear content oid if 
                                  //   expected to be compressed
                                  //  (We rely on flag to indicate compression
                                  //   on creating messages, eg Sign)
{
   SME_SETUP("CSM_CommonData::SetEncapContentClear(const CSM_Buffer &,const AsnOid &)");

   const char *pContent = EncapContent.Access();
   if (pContent == NULL)
      SME_THROW(22,"Error setting FromAsn1 Content - does not exist!", NULL);

   CSM_Content AContent(EncapContent.Access(), EncapContent.Length(), OidType);
   SetEncapContentClear(AContent);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_CommonData::SetEncapContentFromAsn1(const CSM_Buffer &EncapContent, 
        const AsnOid &OidType)    // IN, OPTIONAL, Clear content oid if 
                                  //   expected to be compressed
                                  //  (We rely on flag to indicate compression
                                  //   on creating messages, eg Sign)
{
   SME_SETUP("CSM_CommonData::SetEncapContentFromAsn1(const CSM_Buffer &,const AsnOid &)");

   const char *pContent = EncapContent.Access();
   if (pContent == NULL)
      SME_THROW(22,"Error setting FromAsn1 Content - does not exist!", NULL);

   CSM_Content AContent(EncapContent.Access(), EncapContent.Length(), OidType);
   SetEncapContentFromAsn1(AContent);
   
   SME_FINISH_CATCH
}


//////////////////////////////////////////////////////////////////////////
//
//         
//
void CSM_CommonData::SetEncapContentFromAsn1(const CSM_Content &EncapContent)
{
   SME_SETUP("CSM_CommonData::SetEncapContentFromAsn1");
   if (m_pContentFromAsn1) 
   {
      delete m_pContentFromAsn1;
      m_pContentFromAsn1 = NULL;  
   }
   if (m_pContentClear) 
   {
      delete m_pContentClear;
      m_pContentClear = NULL;  
   }

   if ((m_pContentFromAsn1 = new CSM_Content(EncapContent)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, "Bad new operator of CSM_Content", NULL);

   if (EncapContent.m_contentType == id_ct_compressedData)
      this->m_bCompressDataFlag = true;

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_CommonData::setContentType(const AsnOid  &oContentType) 
{
   if (m_pContentFromAsn1)
   { 
      m_pContentFromAsn1->m_contentType = oContentType;
      if (m_pEncodedBlob != NULL)
         delete m_pEncodedBlob;
      m_pEncodedBlob = NULL;
   } 
   else if (m_pContentClear)
   { 
      m_pContentClear->m_contentType = oContentType;
      if (m_pEncodedBlob != NULL)
         delete m_pEncodedBlob;
      m_pEncodedBlob = NULL;
   } 
}

//////////////////////////////////////////////////////////////////////////
//
//  Function Name:  GetContentTypeClear()
//  
//  Description:  This function returns the content type of m_pContentClear
//                member if there is one.
//
//  Return:  AsnOid content oid from m_pContentClear  or 
//           NULL   if m_pContentClear is null
//
const SNACC::AsnOid * CSM_CommonData::GetContentTypeClear()
{
   const AsnOid  *pRet = NULL;

   SME_SETUP("CSM_CommonData::GetContentType");

   const CSM_Content *pContent =  AccessEncapContentClear();
   pRet = &pContent->m_contentType;


   SME_FINISH_CATCH

   return pRet;
}

//////////////////////////////////////////////////////////////////////////
//
//  Function Name:  GetContentTypeFromAsn1()
//  
//  Description:  This function returns the content type of m_pContentFromAsn1
//                member if there is one.
//
//  Return:  AsnOid content oid from m_pContentFromAsn1  or 
//           NULL   if m_pContentFromAsn1 is null
//
const SNACC::AsnOid * CSM_CommonData::GetContentTypeFromAsn1()
{
   const AsnOid  *pRet = NULL;

   SME_SETUP("CSM_CommonData::GetContentType");

   const CSM_Content *pContent =  AccessEncapContentFromAsn1();
   pRet = &pContent->m_contentType;

   SME_FINISH_CATCH

   return pRet;
}


//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CommonData::GetEncodedCI(AsnOid  *pType)
{
   CSM_Buffer *pRet = NULL;

   SME_SETUP("CSM_CommonData::GetEncodedContentInfo");

   if ((pType == NULL) || (m_pEncodedBlob == NULL))
      SME_THROW(SM_MISSING_PARAM, "type or blob not present", NULL);

   ContentInfo snaccCI;
   snaccCI.contentType = *pType;
   SM_ASSIGN_ANYBUF(m_pEncodedBlob, &snaccCI.content);
   ENCODE_BUF((&snaccCI), pRet);

   SME_FINISH_CATCH

   return pRet;
}

//////////////////////////////////////////////////////////////////////////
//
// return m_bCompressFlag if true - compress data
//                        if not true - don't compress data
////////////////////////////////////////////////////////////////////////// 
bool CSM_CommonData::GetCompressFlag()
{
   return m_bCompressDataFlag;
}

/////////////////////////////////////////////////////////////////////////
//
// This function sets  m_bCompressFlag 
//                        
////////////////////////////////////////////////////////////////////////// 

void CSM_CommonData::SetCompressFlag(bool flag)
{
   m_bCompressDataFlag = flag;

}

//////////////////////////////////////////////////////////////////////////
//
//  BuildCompressedData()
//
//  Description:  This functions instantiates a CompressedData object and 
//                assigns the appropriate data and algids, after compressing the 
//                m_pContentClear content data. The compressedData object is then
//                encoded into a CSM_Buffer and returned.
//                
//
CSM_Buffer *CSM_CommonData::BuildCompressedData() 
{
    long       lStatus = 0;
    CSM_Buffer *pEncodedBuf = NULL;

    SME_SETUP("CSM_CommonData::BuildCompressedData type type");
    
    // check for data to compress
    if (m_pContentClear == NULL)
    {
      SME_THROW(22, "BuildCompressedData() NO content to compress!", NULL);
    }

    // create a compressed data instance 
    CompressedData zippedData;
    CSM_Buffer     *pZippedBuf = NULL;

    // set version
    zippedData.version = 0;  // always 0 for compressedData

    // set the compression alg id
    zippedData.compressionAlgorithm.algorithm = id_alg_zlibCompress;
             
    // Compress the content data            
    lStatus = CompressData(m_pContentClear->m_content.Access(), 
                           m_pContentClear->m_content.Length(), pZippedBuf);
    // check return
    if (lStatus != 0 )
    {
       // unsuccessful compression
      SME_THROW(22, "BuildCompressedData() failed compression of the content.", NULL);
    }      
    
    // set content type of the zipped data
    zippedData.encapContentInfo.eContentType =
       m_pContentClear->m_contentType;  // *** CONTENT TYPE of zipped data

    // set it into the encapContentInfo *** Encoded Zipped CONTENT VALUE
    SME(zippedData.encapContentInfo.eContent =
       new AsnOcts(pZippedBuf->Access(),
                   pZippedBuf->Length()));

    // encode the compressedData zippedData
    pEncodedBuf = new CSM_Buffer;
    pEncodedBuf->Encode(zippedData);

    if (pZippedBuf)
       delete pZippedBuf;

    SME_FINISH_CATCH


    return pEncodedBuf;
}



//////////////////////////////////////////////////////////////////////////
long CSM_CommonData::CompressData(const char *pDataToCompress, unsigned long sourceLen, 
                                  CSM_Buffer *&pCompressedDataBuf)
{
   long   status = 0;
   byte   *pbCompressData;
   byte   *pbCompressedData;
   unsigned long destLen;

   SME_SETUP("CSM_CommonData::CompressData(const char *dataToCompress, ...)");
  
   if (pDataToCompress == NULL) 
   {
      SME_THROW(22, "Error No data to compress!\n", NULL);
   }
 
   // get the data assigned to byte *
   pbCompressData = (byte *)pDataToCompress;
   //sourceLen = strlen(pDataToCompress);  input

   // set the length
   // Upon entry, destLen is the total size of the destination buffer, 
   // which must be at least 0.1% larger than sourceLen plus 12 bytes. 
   double perc = sourceLen * 0.1;
   destLen = sourceLen + (int)perc + 13;

   //cout << destLen << " = destLen\n";
   pbCompressedData = (byte*)calloc(1, destLen);

   if (pbCompressedData == NULL)
   {
      SME_THROW(SM_MEMORY_ERROR, "Memory Error!\n", NULL);
   }
 
    // Compresses the dataToCompress buffer into the compressedData buffer. 
    // sourceLen is the byte length of the source buffer. 
    // Upon entry, destLen is the total size of the destination buffer, 
    // which must be at least 0.1% larger than sourceLen plus 12 bytes. 
    // Upon exit, destLen is the actual size of the compressed buffer.
    status = compress(pbCompressedData, &destLen, pbCompressData, sourceLen);
  
    if (status == Z_MEM_ERROR) // -4
    {
      SME_THROW(22, "CompressData() failed to compress data - Memory error.", NULL);
    }
    else if (status == Z_BUF_ERROR) // -5
    {
      SME_THROW(22, "CompressData() failed to compress data - Buffer error.", NULL);
    }

    if (pCompressedDataBuf == NULL)
        pCompressedDataBuf = new CSM_Buffer;

    pCompressedDataBuf->Set((const char *)pbCompressedData, destLen);

    // clean-up
    free(pbCompressedData);

    SME_FINISH_CATCH

    return status;
}

//////////////////////////////////////////////////////////////////////////
long CSM_CommonData::UncompressData(CSM_Buffer *pCompressedData,
                                    CSM_Buffer *&pUncompressedDataBuffer)
{
   int           err;
   unsigned long comprLen = 0;
   unsigned long uncomprLen = 0;
   byte         *pUncompressedData = NULL;
   z_stream     d_stream; /* decompression stream */

   SME_SETUP("CSM_CommonData::UncompressData(CSM_Buffer *, CSM_Buffer *)");

   if (pCompressedData == NULL)
     SME_THROW(22, "No data to uncompress!\n", NULL);

   // initialization
   uncomprLen  = UNCOMPRESS_BUFFER_SIZE;
   pUncompressedData = (byte *)calloc(1,uncomprLen);
   memset(pUncompressedData,uncomprLen,0);
   comprLen = pCompressedData->Length();

   //  Initializes the internal stream state for decompression. The fields
   // next_in, avail_in, zalloc, zfree and opaque must be initialized before by
   // the caller. I
   // inflateInit does not perform any decompression apart from reading
   // the zlib header if present: this will be done by inflate().  (So next_in and
   // avail_in may be modified, but next_out and avail_out are unchanged.)
   d_stream.zalloc = (alloc_func)0;
   d_stream.zfree = (free_func)0;
   d_stream.opaque = (voidpf)0;

   // - Decompress more input starting at next_in and update next_in and avail_in
   //   accordingly.   
   d_stream.next_in  = (unsigned char *)pCompressedData->Access();
   d_stream.avail_in = pCompressedData->Length();
   d_stream.next_out = pUncompressedData;
   d_stream.avail_out = uncomprLen;
   err = inflateInit(&d_stream);
   if (err == Z_MEM_ERROR)
   {
     SME_THROW(22, "Memory Error initializing uncompress buffer inflateInit().", NULL);
   }
   else if (err == Z_VERSION_ERROR)
   {
     SME_THROW(22, "Version Error checking zlib version in inflateInit().", NULL);
   }

   if (pUncompressedDataBuffer == NULL)
      pUncompressedDataBuffer = new CSM_Buffer;

   while (d_stream.total_in < comprLen) 
   {

      // inflate decompresses as much data as possible, and stops when the input
      // buffer becomes empty or the output buffer becomes full. It may some
      // introduce some output latency (reading input without producing any output)
      // except when forced to flush.

      // If not all input can be processed (because there is not
      //   enough room in the output buffer), next_in is updated and processing
      //   will resume at this point for the next call of inflate().

      // inflate() provides as much output as possible, until there
      //   is no more input data or no more space in the output buffer 
       err = inflate(&d_stream, Z_NO_FLUSH);
        
       if (err == Z_STREAM_END)
       {
          // write uncompressed data to pUncompressedDataBuffer
          if (pUncompressedDataBuffer != NULL)
          {
             int uncomprCount = 0;
             if (d_stream.avail_out == 0)
                 uncomprCount = uncomprLen;
             else
                uncomprCount = uncomprLen - d_stream.avail_out;

             pUncompressedDataBuffer->Write((const char *)pUncompressedData, uncomprCount);
           
             // reinitialize the memory
             if (pUncompressedData)
                memset(pUncompressedData,uncomprLen,0);
          }

          // finished no more to uncompress
          break;
       }
       else if (err == Z_STREAM_ERROR) // i.e. if next_in or next_out was NULL
       {
          SME_THROW(22, "Error stream structure may be inconsistent in inflate().", NULL);
       }
       else if (err == Z_DATA_ERROR)
       {
          SME_THROW(22, "Data Error input data may be corrupted in inflate().", NULL);
       }
       else if (err == Z_MEM_ERROR)
       {
          SME_THROW(22, "Memory Error decompressing data in inflate().", NULL);
       }
       else if (err == Z_NEED_DICT)
       {
          SME_THROW(22, "Dictionary Error decompressing data in inflate().", NULL);
       }
       else if (err == Z_BUF_ERROR)
          SME_THROW(22, "Buffer Error decompressing data in inflate().", NULL);

       // write uncompressed data to pUncompressedDataBuffer
       if (pUncompressedDataBuffer != NULL)
       {
          int uncomprCount = 0;
          if (d_stream.avail_out == 0)
              uncomprCount = uncomprLen;
          else
             uncomprCount = uncomprLen - d_stream.avail_out;

          pUncompressedDataBuffer->Write((const char *)pUncompressedData, uncomprCount);
          
          // reinitialize the memory
          if (pUncompressedData)
             memset(pUncompressedData,uncomprLen,0);
       }

       //   Provide more output starting at next_out and update next_out and avail_out
       //   accordingly.         
       d_stream.next_out = pUncompressedData;  // point to next available memory
       d_stream.avail_out = uncomprLen;                 // reinitialize 
   }

   // clean-up
   if (pUncompressedData)
      free(pUncompressedData);

   //  All dynamically allocated data structures for this stream are freed.
   // This function discards any unprocessed input and does not flush any
   // pending output.
   err = inflateEnd(&d_stream); 
   
   //  inflateEnd returns Z_OK if success, Z_STREAM_ERROR if the stream state
   // was inconsistent. In the error case, msg may be set but then points to a
   // static string (which must not be deallocated).
   if (err == Z_STREAM_ERROR)
     SME_THROW(22, "Error with inflateEnd() - stream state inconsistent.", NULL);

   SME_FINISH_CATCH

   return err;
}

void CSM_CommonData::ReportCommonData(std::ostream &os)
{
   os << "CSM_CommonData::ReportCommonData(std::ostream &os)\n";

   const SNACC::AsnOid *pOid = GetContentTypeFromAsn1();
   
   if (pOid == NULL)
      return;
   char *ptr=pOid->GetChar();

   if (ptr == NULL)
      return;

   if (*pOid == id_ct_compressedData)
   {
      // list compressedData oid.
      os << "CompressedData Content OID="
         << ptr  << "\n";
   }
   else
   {
      if (ptr)
         os << "CONTENT OID=" << ptr  << "\n";
   }

   if (ptr)
   {
      free(ptr);
      ptr = NULL;
   }

   const CSM_Content *pContent = AccessEncapContentClear();   
   if (pContent->m_content.Length() > 0)
   {
      os << "\nCONTENT=\n";  
      unsigned char *ptr2=NULL;
      ptr2=(unsigned char *)calloc(1, pContent->m_content.Length()+1);
      memcpy(ptr2, pContent->m_content.Access(), pContent->m_content.Length());
      for (unsigned int i=0; i < pContent->m_content.Length(); i++)
        if (!((ptr2[i] >= 'a' && ptr2[i] <= 'z') || 
              (ptr2[i] >= '0' && ptr2[i] <= '9') ||
              (ptr2[i] >= 'A' && ptr2[i] <= 'Z')) &&
              strchr("~!@#$%^&*()_+|}{[]\';"":/.?><,` ", ptr2[i]) == NULL)
              ptr2[i] = '.';      // ONLY overwrite non-printables.
        os << ptr2;
        os << "\n***END of CONTENT***\n";
        os << "CONTENT in HEX=\n";  
        pContent->m_content.ReportHexBuffer(os, pContent->m_content.Access(),
            pContent->m_content.Length());

        if (ptr2)
           free (ptr2);
        ptr2= NULL;
      
      os << "\n***END of HEX CONTENT***\n\n";
   }

    os.flush();

}

const CSM_Buffer *CSM_CommonData::AccessEncodedBlob() 
{ 
   return m_pEncodedBlob; 
}

#ifdef CML_USED
//////////////////////////////////////////////////////////////////////////
long CSM_CommonData::CMLValidateCert(
      CM_SFLCertificate &ACMLCert,  // IN, may have cert, or just RID.
      CSM_CertificateChoice *pCert) // IN/OUT, optional 
                                    //  (will place inside ACMLCert OR
                                    //   RETURN if retrieved from CML)
{
   long lstatus=0;

   SME_SETUP("CSM_CommonData::CMLValidateCert");

   // The application may have pre-loaded the CML storage previous to calling
   //  with other information (e.g. issuer, CRLs, etc.).
      // check for recipient cert
         ACMLCert.m_lCmlSessionId = this->m_lCmlSessionId;
         ACMLCert.m_lSrlSessionId = this->m_lSrlSessionId;
         if (pCert && pCert->AccessEncodedCert())
         {              // if cert present, use it directly
            Bytes_struct ACertByteStruct;
            ACertByteStruct.data = (unsigned char *)pCert->AccessEncodedCert()->Access();
            ACertByteStruct.num  = pCert->AccessEncodedCert()->Length();
            CML::Certificate ACMLUserCert(ACertByteStruct);
            ACMLCert.SetUserCert(ACMLUserCert);
         }     // END if recip cert is present
         // ELSE if cert is missing, try to use CLM to retrieve.
         lstatus = ACMLCert.Validate();
         if (lstatus != 0)
         {
            CML::ASN::DN *pDN=NULL;
            const char *ptr;
            if (pCert)
            {
               pDN=pCert->GetSubject();
               if (pDN == NULL)
               {
                  SME_THROW(22, "BAD DN BUILD from Signer Cert.", NULL);
               }
               ptr = *pDN;
            }
            else if (ACMLCert.AccessCMLCert())
            {
               ptr = ACMLCert.AccessCMLCert()->base().userCert.subject;
            }
            else 
               ptr = "UNKNOWN";
            char lpsBuf[1000];
            sprintf(lpsBuf, "CSM_CommonData::CMLValidateCert::Validate() DN=|%s|, error=%d.\n", 
               ptr, lstatus);
            if (pDN)
               delete pDN;
            if (m_pszCMLError == NULL)
                m_pszCMLError = strdup(lpsBuf);
            else        // APPEND error string.
            {
               char *ptr=(char *)calloc(1, strlen(m_pszCMLError) + 
                                           strlen(lpsBuf) + 1);
               strcpy(ptr, m_pszCMLError);
               m_pszCMLError = ptr;
               strcat(m_pszCMLError, lpsBuf);
            }     // END if m_pszCMLError
         }        // IF lstatus on CML Validate()
         else     // ON success.
         {
            if (pCert != NULL && pCert->AccessEncodedCert() == NULL)
            {        // USE CML loaded cert for our proecsssing
                     //  (NICE feature, user is allowed to simply specify 
                     //   RID; we might be able to get public information 
                     //   from the CML!)
                     // It must be here, since we succeeded on Validate()!
               pCert->UpdateSNACCCertificate(ACMLCert.AccessCMLCert()->base().userCert.GetSnacc());
            }     // END if cert is NULL
         }        // END if lstatus on CML Validate()


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(lstatus);
}     // END CSM_CommonData::CMLCheckoutCert(...)
#endif //CML_USED



_END_SFL_NAMESPACE

// EOF sm_CommonData.cpp
