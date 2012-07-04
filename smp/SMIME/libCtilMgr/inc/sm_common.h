/* @(#) sm_common.h 1.21 10/25/00 14:44:04 */

////////////////////////////////////////////////////////////////////////////////
//
// File:  sm_common.h
//
// Contents: 
// includes the Common class derived from CSM_TokenInterface.
// This crypto token library header is usually the only include that the C++
// application needs.  Directly included by the C++ app and the fortezza
// crypto token library.
//
// Project:  SMP/libCtilMgr
//
// Req Ref:  SMP RTM #5
//
// Last Updated:	16 December 2004                                       
//                Req Ref:  SMP RTM #5  AES Crypto++                                
//                Sue Beauchamp <Sue.Beauchamp@it.baesystems.com>   
//
//                Took out AES code and put new code using Crypto++ in the 
//                sm_Free3 CTIL.  Removed include file sm_CommonCtil.h.     
//
////////////////////////////////////////////////////////////////////////////////

#ifndef _SM_COMMON_H_
#define _SM_COMMON_H_

#ifdef WIN32
#pragma warning( disable : 4251 )
#pragma warning( disable : 4275 )
#endif
// SHA1 constants

#define SHA1_SIZE 20
#define MASK32    0xffffffff
#define BLOCK     64
#define K1        0x5a827999
#define K2        0x6ed9eba1
#define K3        0x8f1bbcdc
#define K4        0xca62c1d6

// End of SHA1 constants

// SHA1 macros

#define Ls5(num)  (((num)<<5)|((num)>>27))
#define Ls30(num) (((num)<<30)|((num)>>2))

#ifdef NO_ESHA
#define Ls1(num)  (num)
#else
#define Ls1(num)  (((num)<<1) | ((num)>>31)&1)
#endif

#define F0(x,y,z) ((z)^(x)&((y)^(z)))
#define F1(x,y,z) ((x)&((y)^(z))^((z)&(y)))
#define F2(x,y,z) ((x)^(y)^(z))

#define SM_COMMON_RC2_BLOCKSIZE    8
#define SM_COMMON_3DES_KEYLEN 24
#define SM_COMMON_3DES_IVLEN 8
#define SM_COMMON_3DES_BLOCKSIZE 8
#define SM_COMMON_RC2_KEYLEN 16         // byte count 128 bits 
#define SM_COMMON_RC2_BLOCKSIZE  8

// End of SHA1 macros

#ifndef _SM_API_H_
//#include "sm_api.h"
#endif

#include "sm_apiCtilMgr.h"

_BEGIN_CTIL_NAMESPACE 
extern void SM_DoEndian(unsigned long *); /* byte swapper for LITTLE ENDIAN */


class LIBCTILMGRDLL_API CSM_Common : public CSM_BaseTokenInterface
{
private:
public:
   CSM_Common(); // default constructor

   // member access functions
   void SetDefaultOIDLists(CSM_AlgLstVDA *pDigestAlgs, 
                           CSM_AlgLstVDA *pDigestEncryption, 
                           CSM_AlgLstVDA *pKeyEncryption, 
                           CSM_AlgLstVDA *pContentEncryption);
   // The DigestData is forced to be virtual to perform signature verify
   //  (DSA).  Our algorithm may not be adequate to perform other hash algs.
   virtual SM_RET_VAL SMTI_DigestData(CSM_Buffer *pData, CSM_Buffer *pHashValue);
   SM_RET_VAL SMTI_DigestData(CSM_Buffer *pData, CSM_Buffer *pHashValue, 
       const SNACC::AsnOid &digestAlg);
   // new definitions from taking out CSM_CtilCommon
   SM_RET_VAL CSM_Common::SMTI_Sign(
            CSM_Buffer *pData, // input, data to be signed
            CSM_Buffer *pEncryptedDigest, // signature output
            CSM_Buffer *pDigest) // digest
   {   return -1; }
   SM_RET_VAL SMTI_Encrypt(
       CSM_Buffer *pData,         // input (data to be encrypted)
       CSM_Buffer *pEncryptedData,// output
       CSM_Buffer *pParameters,   // OUT, for KeyAgree algs.
       CSM_Buffer *pMEK,          // In/output; may be specified.
       CSM_Buffer *pIV=NULL)      // In, to avoid specific
                                  // alg encoding by app.
   { return -1;} // no longer calling
   // new definitions from taking out CSM_CtilCommon
   SM_RET_VAL SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
                                     //  OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
            CSM_Buffer *pSubjKeyId) // output
   { return -1;}
   SM_RET_VAL SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output (MEK or special phrase)
   { return(-1);}
   SM_RET_VAL SMTI_Decrypt(
       CSM_Buffer *pParameters,   // input, parameters for alg.
       CSM_Buffer *pEncryptedData,// input (data to be decrypted)
       CSM_Buffer *pMEK,          // input (MEK or special phrase)
       CSM_Buffer *pData)          // output (decrypted data)
   { return -1;} // no longer calling the DecryptAES
   virtual SM_RET_VAL SMTI_Verify(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature); // input
   
   static SM_RET_VAL SMTI_DigestDataSHA1(CSM_Buffer *pData, CSM_Buffer *pHashValue);
   static SM_RET_VAL SMTI_DigestDataSHA2(CSM_Buffer   *pData, CSM_Buffer *pHashValue);
   // new definitions from taking out CSM_CtilCommon
   SM_RET_VAL SMTI_Random(
            CSM_Buffer *pSeed,   // input
            CSM_Buffer *pRandom, // input/output
            SM_SIZE_T lLength)   // input
   { return(-1);}
   SM_RET_VAL SMTI_ExtractKeyWrap(
            CSM_Buffer *pData, // Output
            CSM_Buffer *pEncryptedData, // input
            CSM_Buffer *pParameters, // RWC;TBD;REMOVE;IN, for KeyAgree algs.
            CSM_Buffer *pTEK, // IN
            CSM_Buffer *pIV22);  // Used for iv length only
   void CSM_TokenInterfaceDestroy();

   virtual void LoadParams(CSM_Buffer &IV, 
                           CSM_Buffer *pParameters, 
                           int effectiveKeyBits = 0);
   virtual void EncodeRC2Params(CSM_Buffer &out, int keyBits, CSM_Buffer &iv);

   virtual CSM_Buffer * UnloadParams(SNACC::AsnOid *pPrefContentOid, 
                                     CSM_Buffer &pParameters)
   {
      CSM_Buffer *pBuf = NULL;

      int effectiveKeyBits = 0;

      pBuf = UnloadParams(pPrefContentOid, pParameters, effectiveKeyBits);

      return pBuf;
   }
   virtual CSM_Buffer * UnloadParams(SNACC::AsnOid *pPrefContentOid,
                                     CSM_Buffer &parameters, 
                                     int &effectiveKeyBits);
   SM_RET_VAL SMTI_Lock(){ return 0; }
   SM_RET_VAL SMTI_Unlock(){ return 0; }

   virtual bool SMTI_MoreCSInstances() { return 1; };
   bool SMTI_IsKeyAgreement() { return true; };
                                       // TRUE indicates key agreement 
                                       //  encryption, not key transfer.
   void SetCSInst(void *pInst) { m_pInst = pInst;}
   void *AccessCSInst()  {return m_pInst;}
                             // This method returns a "void *" because 
                             //  the CtilInst class that invokes it is
                             //  not aware of this datatype.  It comes
                             //  from the CTIL itself, if available.
protected:
    SM_RET_VAL SMTI_VerifyInternalDSA(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature); // input

   SM_RET_VAL SMTI_GenerateKeyWrapFinish(
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV,  // In, to avoid specific alg encoding by app.
            CSM_Buffer *pCEKICV);
    static SM_RET_VAL SHA1_GetHash(unsigned long  ,
                                   unsigned char *,
                                   unsigned char *);

    static void SHA1_InitializeHash(void);
 
    static long ExtractSignatureR_AND_S(CSM_Buffer &BufSignature,  //INPUT
                             unsigned char *&pR,        //OUTPUT
                             unsigned char *&pS);       //OUTPUT

   void *m_pInst;           // ONLY USED if this specific CTIL supports
                            //  the additional features of CSM_CSInst
                            //  over CSM_CtilInst (e.g. cert handling).
                            //  (LOADED by the CTIL build process.)

private:

    typedef struct {
       unsigned long hashval[5];
       int           initflag;
       unsigned long total;
    } Hash_struct;

    static Hash_struct hash;

        // private member functions
    static void SHA1_SohHash(unsigned long *, unsigned long *);
};

class LIBCTILMGRDLL_API CSM_DSAParams
{
    public: 
       char       *P;
       char       *Q;
       char       *G;

       long m_lParamLength;
   
       CSM_DSAParams();
       ~CSM_DSAParams();
       SM_RET_VAL Decode(CSM_Buffer *pParams);
          
};

_END_CTIL_NAMESPACE 

#endif // _SM_COMMON_H_

// EOF sm_common.h
