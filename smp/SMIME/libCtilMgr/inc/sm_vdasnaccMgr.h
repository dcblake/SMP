
// sm_vdasnaccMgr.h
//
#ifndef _SM_VDASNACC_H_
#define _SM_VDASNACC_H_


/////////////////////////////////////////////////////////////////////
// MACROS 

//
// MACRO: ENCODE_ANY()
// PURPOSE: This macro will encode the 
//          SNACC object "encodedData" into a CSM_Buffer
//          object and then stuff it in the AsnAny's value
//          member.
//
#define ENCODE_ANY(encodedData, asnAny)\
    CSM_Buffer *pBlob2=NULL;\
    SNACC::AsnLen iBytesDecoded=0;\
    if ((encodedData) && (asnAny))\
    { ENCODE_BUF(encodedData, pBlob2); }\
    AsnBuf TmpAsnBuf(pBlob2->Access(), pBlob2->Length());\
    if (pBlob2 && (asnAny))\
    { (asnAny)->BDec(TmpAsnBuf, iBytesDecoded); }

// 
// MACRO: DECODE_ANY()
// PURPOSE: This macro will decode the
//          contents of the asnAny object into the SNACC
//          object decodeData.
//
#define DECODE_ANY(decodeData, asnAny)\
    SNACC::AsnBuf TmpAsnBuf, TmpAsnBuf2;\
     SNACC::AsnLen iBytesDecoded=0;\
    (asnAny)->BEnc(TmpAsnBuf);\
    TmpAsnBuf.GrabAny(TmpAsnBuf2, iBytesDecoded);\
    if (iBytesDecoded)\
    { char *ptr=TmpAsnBuf2.GetSeg(iBytesDecoded);\
      CSM_Buffer TmpBuf(ptr, iBytesDecoded);\
      DECODE_BUF(decodeData, &TmpBuf);\
      delete[] ptr;\
    }

// This macro is usually only necessary if a SNACC AsnBuf is used
//  immediately after being loaded by an application (e.g. consecutive 
//  encode decode operations).
//#define SNACC_BUFRESET_READ(pSnaccBuf)   (pSnaccBuf)->ResetInReadMode();
//#define SNACC_BUFRESET_WRITE(pSnaccBuf)  (pSnaccBuf)->ResetInWriteRvsMode();

#define DECODE_BUF_NOFAIL(decodeData, pBlob, llStatus)\
    {\
      try\
      {\
         llStatus = 0;\
         (pBlob)->Decode(*(decodeData));\
      }\
      catch (...)\
      {\
         llStatus=-1;\
      }\
    }

#define DECODE_BUF(decodeData, pBlob)\
         (pBlob)->Decode(*(decodeData));

/*#define DECODE_BUF(decodeData, pBlob)\
   {SNACC::AsnBuf asnBuf((pBlob)->Access(), (pBlob)->Length());\
    SNACC::AsnLen iBytesDecoded=0;\
    (decodeData)->BDec(asnBuf, iBytesDecoded);\
   }*/

#define ENCODE_BUF(encodeData, pblob)\
    { if ((pblob) == NULL) (pblob) = new CSM_Buffer;\
          (pblob)->Encode(*(encodeData)); }
#define ENCODE_BUF_NO_ALLOC(encodeData, pblob)\
    (pblob)->Encode(*(encodeData));

/*#define ENCODE_BUF_NO_ALLOC(encodeData, blob)\
   {\
   / *static* / SNACC::AsnBuf asnBuf;\
   asnBuf.ResetMode(std::ios_base::out);\
   AsnLen istatus=0;\
   istatus=(encodeData)->BEnc(asnBuf);\
   asnBuf.ResetMode();\
   SNACC::AsnLen iBytesDecoded=asnBuf.length();\
   if(istatus)\
   {\
      char *ptr=asnBuf.GetSeg(iBytesDecoded);\
      if (ptr && iBytesDecoded > 0)\
      { blob->Set((const char *)ptr, iBytesDecoded);\
        delete[] ptr;}\
      else\
      { SME_THROW(33, "BAD SNACC Encode", NULL); }\
   }\
   }*/

#define SM_ASSIGN_ANYBUF(lpBuf, asnAny)\
   {\
     if (lpBuf)\
     {  (lpBuf)->Decode(*(asnAny));  }\
   }

#define SM_EXTRACT_ANYBUF(pSS, asnAny)\
   {\
     if ((asnAny))\
     {  if(pSS==NULL)pSS=new CSM_Buffer; \
        (pSS)->Encode(*(asnAny));  }\
   }


#endif // _SM_VDASNACC_H_

// EOF sm_vdasnaccMgr.h
