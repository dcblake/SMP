// CONSTRUCTOR(s):
//   CSM_DSASignatureValue()
//   CSM_DSASignatureValue(CSM_Buffer *asnSigValue)
// MEMBER FUNCTIONS:
//   Decode(CSM_Buffer *sigValue)
//   Encode(CSM_Buffer *pSigValue)
//   SetRS(const char *buf)
//   GetRS(void)
//////////////////////////////////////////////////////////////////////////////

#include "sm_pkcs11DSASig.h"
#include "sm_fortAsn.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;
// CONSTRUCTOR:
//
CSM_DSASignatureValue::CSM_DSASignatureValue()
{
   // do nothing
} // END OF CONSTRUCTOR

// ALTERNATE CONSTRUCTOR:
//
CSM_DSASignatureValue::CSM_DSASignatureValue(CSM_Buffer *asnSigValue)
{
   SME_SETUP("CSM_DSASignatureValue::CSM_DSASignatureValue()");

   Decode(asnSigValue);

   SME_FINISH_CATCH;
} // END OF ALTERNATE CONSTRUCTOR

// Decode:
//
void CSM_DSASignatureValue::Decode(CSM_Buffer *sigValue)
{
   long error = 0;

   SME_SETUP("CSM_DSASignatureValue::Decode");

   DECODE_BUF_NOFAIL( this, sigValue, error );

   if (error != 0)
      SME_THROW(-1, "Error decoding signature value", NULL);

   SME_FINISH_CATCH;
} // END OF MEMBER FUNCTION Decode

// Encode:
//
void CSM_DSASignatureValue::Encode(CSM_Buffer *pSigValue)
{
   CSM_Buffer *pLocalBuf = NULL;

   SME_SETUP("CSM_DSASignatureValue::Encode");

   ENCODE_BUF(this, pLocalBuf);

   pSigValue->ReSet(*pLocalBuf);

   delete pLocalBuf;

   SME_FINISH_CATCH;
} // END OF MEMBER FUNCTION Encode

// SetRS:
//
void CSM_DSASignatureValue::SetRS(const char *buf)
{
   SME_SETUP("CSM_DSASignatureValue::SetR()");

   r.Set((const unsigned char *)buf, DSA_R_SIZE);
   s.Set((const unsigned char *)buf + DSA_R_SIZE, DSA_S_SIZE);

   SME_FINISH_CATCH;
} // END OF MEMBER FUNCTION SetRS

char * CSM_DSASignatureValue::GetRS(void)
{
   char *bufR = NULL;
   char *bufS = NULL;
   char *bufRS = (char *) calloc(1, DSA_R_SIZE + DSA_S_SIZE);
   unsigned int length = 0;

   SME_SETUP("CSM_DSASignatureValue::GetR()");

   r.getPadded((unsigned char *&)bufR, length, DSA_R_SIZE);
   s.getPadded((unsigned char *&)bufS, length, DSA_S_SIZE);

   memcpy(bufRS, bufR, DSA_R_SIZE);
   memcpy( &bufRS[DSA_R_SIZE], bufS, DSA_S_SIZE);

   delete bufR;
   delete bufS;
   return bufRS;

   SME_FINISH_CATCH;
}

_END_CERT_NAMESPACE

// EOF sm_pkcs11DDSASig.cpp
