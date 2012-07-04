
#ifndef _sm_pkcs11DSASig_
#define _sm_pkcs11DSASig_

#include "sm_pkcs11.h"
//#include "sm_pkcs11Oids.h"
#include "sm_fortAsn.h"
_BEGIN_CERT_NAMESPACE

#define DSA_R_SIZE 20
#define DSA_S_SIZE 20

class CSM_DSASignatureValue;

class CSM_DSASignatureValue : public SNACC::DSASignatureValue
{
public:

   CSM_DSASignatureValue();
   CSM_DSASignatureValue(CSM_Buffer *asnSigValue);
   void Decode(CSM_Buffer *sigValue);
   void Encode(CSM_Buffer *sigValue);
   void SetRS(const char *buf);
   char * GetRS(void);  // return R & S concatenated
};

_END_CERT_NAMESPACE


#endif //

// EOF sm_pkcs11DSASig.h
