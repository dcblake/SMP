// CONSTRUCTOR(s):
//   CSM_DSASignatureValue()
//   CSM_DSASignatureValue(CSM_Buffer *asnSigValue)
// MEMBER FUNCTIONS:
//   Decode(CSM_Buffer *sigValue)
//   Encode(CSM_Buffer *pSigValue)
//   SetRS(const char *buf)
//   GetRS(void)
//////////////////////////////////////////////////////////////////////////////

#include "sm_fort.h"
#include "sm_fortAsn.h"
using namespace CERT;
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

   mFixedR = r;
   mFixedS = s;

   SME_FINISH_CATCH;
} // END OF MEMBER FUNCTION Decode

// Encode:
//
void CSM_DSASignatureValue::Encode(CSM_Buffer *pSigValue)
{
   unsigned char *pfixedBigInt = NULL;
   unsigned int length;
   CSM_Buffer *pLocalBuf = NULL;

   SME_SETUP("CSM_DSASignatureValue::Encode");

   if (mFixedR.length() < 1 || mFixedS.length() < 1)
      SME_THROW(-1, "Invalid R & S size", NULL);

   // AT THIS POINT WE MAY HAVE A ZERO PADDED r VALUE OF A BigInt.  USE
   //   SIZE 0 TO AVOID STRIPPING OFF THIS PADDING IN THE GET FUNCTION
   mFixedR.getPadded/*GetUnSignedBitExtendedData/ *Get*/(pfixedBigInt, length, DSA_R_SIZE); // adjust to big int

   r.Set((const unsigned char *)pfixedBigInt, length);

   // AT THIS POINT WE MAY HAVE A ZERO PADDED s VALUE OF A BigInt.  USE
   //   SIZE 0 TO AVOID STRIPPING OFF THIS PADDING IN THE GET FUNCTION
   mFixedS.getPadded/*GetUnSignedBitExtendedData/ *Get*/(pfixedBigInt, length, DSA_S_SIZE);

   s.Set((const unsigned char *)pfixedBigInt, length);

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

   mFixedR.Set((const unsigned char *)buf, DSA_R_SIZE);
   mFixedS.Set((const unsigned char *)buf + DSA_R_SIZE, DSA_S_SIZE);

   SME_FINISH_CATCH;
} // END OF MEMBER FUNCTION SetRS

char * CSM_DSASignatureValue::GetRS(void)
{
   char *bufR = NULL;
   char *bufS = NULL;
   char *bufRS = (char *) calloc(1, DSA_R_SIZE + DSA_S_SIZE);
   unsigned int length = 0;

   SME_SETUP("CSM_DSASignatureValue::GetR()");

   mFixedR.getPadded/*GetUnSignedBitExtendedData/ *Get*/((unsigned char *&)bufR, length, DSA_R_SIZE);
   mFixedS.getPadded/*GetUnSignedBitExtendedData/ *Get*/((unsigned char *&)bufS, length, DSA_S_SIZE);

   memcpy(bufRS, bufR, DSA_R_SIZE);
   memcpy( &bufRS[DSA_R_SIZE], bufS, DSA_S_SIZE);

   free(bufR);
   free(bufS);
   return bufRS;

   SME_FINISH_CATCH;
}


// EOF sm_forDsaSigvalue.cpp
