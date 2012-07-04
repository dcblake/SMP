////////////////////////////////////////////////////////////////////////////////
//
// File:  sm_common.cpp
//
// Contents: 
// includes the Common class member functions derived from CSM_TokenInterface.
// Directly included by the C++ app and the fortezza crypto token library.
// 
// Project:  SMP/libCtilMgr
//
// Req Ref:  SMP RTM #5
//
// Last Updated:	16 December 2004                                       
//                Req Ref:  SMP RTM #5  AES Crypto++                                
//                Sue Beauchamp <Sue.Beauchamp@it.baesystems.com>        
//
////////////////////////////////////////////////////////////////////////////////
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "sm_common.h"
extern "C" {
#include "sha256.h"
#include "fortezzaVDA.h"
}


#ifndef uchar
typedef unsigned char uchar;
#endif

// RWC;/4/19/02;This odd definition allows the definition of the static
//  member variable of the CSM_Common class WITHOUT A DUMMY class def!
//  It is declared static to allow CTIL access to method from static
//  methods.
struct CTIL::CSM_Common::Hash_struct  CTIL::CSM_Common::hash;

_BEGIN_CTIL_NAMESPACE 
using namespace SNACC; 
// should eventually add an oid parameter to select between
// mutliple common hash algs. PXL 12-9-97
//
SM_RET_VAL CSM_Common::SMTI_DigestData(CSM_Buffer   *pData,
                                    CSM_Buffer *pHashValue)
{
    AsnOid *poidDigest=NULL;
    SM_RET_VAL lRet;

    SME_SETUP("CSM_Common::SMTI_DigestData");
    poidDigest = GetPrefDigest();
    if (poidDigest == NULL)
    {
        SME_THROW(22, "NO GetPrefDigest algorithm!", NULL);
    }

    lRet = SMTI_DigestData(pData, pHashValue, *poidDigest);
    if (poidDigest)
         delete poidDigest;

   SME_FINISH
   SME_CATCH_SETUP
      if (poidDigest)
         delete poidDigest;
   SME_CATCH_FINISH

   return(lRet);

}       // CSM_Common::SMTI_DigestData

//
//
SM_RET_VAL CSM_Common::SMTI_DigestData(CSM_Buffer   *pData,
                                    CSM_Buffer *pHashValue, 
                                    const AsnOid &oidDigest)
{
   SM_RET_VAL status=-1;
   SME_SETUP("CSM_Common::SMTI_DigestData(...AsnOid)");
   if (oidDigest == sha_1 || oidDigest == id_dsa_with_sha1 ||
       oidDigest == sha_1WithRSAEncryption)
   {
      // do SHA1 digest using common CTI
      SME(status = SMTI_DigestDataSHA1(pData, pHashValue));
   }
   else if (oidDigest == id_SHA256 || oidDigest == sha256WithRSAEncryption)
   {
      // do SHA1 digest using common CTI
      SME(status = SMTI_DigestDataSHA2(pData, pHashValue));
   }


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(status);
}       // END CSM_Common::SMTI_DigestData

//
//
SM_RET_VAL CSM_Common::SMTI_DigestDataSHA2(CSM_Buffer   *pData,
                                    CSM_Buffer *pHashValue)
{

   char *pch;
   pHashValue->Open(SM_FOPEN_WRITE);
   pch = pHashValue->Alloc(SHA256_BYTEHASHLEN);
   SHA256_StringProcess ((char *)pData->Access(), pData->Length(), 
            (unsigned long *)pch);
   pHashValue->Flush();
   pHashValue->Close();
   return(SM_NO_ERROR);
}

//
//
SM_RET_VAL CSM_Common::SMTI_DigestDataSHA1(CSM_Buffer   *pData,
                                    CSM_Buffer *pHashValue)
{

   char *pch;
   // TBD, error handling....dave
   pHashValue->Open(SM_FOPEN_WRITE);
   pch = pHashValue->Alloc(SHA1_SIZE);
   SHA1_InitializeHash();
   SHA1_GetHash(pData->Length(), (unsigned char *)pData->Access(), 
         (unsigned char *)pch);
   pHashValue->Flush();
   pHashValue->Close();
   return(SM_NO_ERROR);
}


void CSM_Common::SHA1_InitializeHash(void)
{
   hash.initflag = 1;
   hash.total = 0;

   hash.hashval[0] = 0x67452301;
   hash.hashval[1] = 0xefcdab89;
   hash.hashval[2] = 0x98badcfe;
   hash.hashval[3] = 0x10325476;
   hash.hashval[4] = 0xc3d2e1f0;

} // End of SHA1_InitializeHash

/*
 * FUNCTION: SHA1_GetHash()
 *
 * PURPOSE: Produce a SHA1 hash of the pData.
 *
 *          returns 0 on success
 *          returns 1 on failure
 */
SM_RET_VAL CSM_Common::SHA1_GetHash(unsigned long DataSize,
                                    unsigned char *pData,
                                    unsigned char *pHashValue)
{
   union {
      char          letters[64];
      unsigned long numbers[16];
   } dat;

   unsigned int leftovers;
   char         paddata[64];
   unsigned int  i          = 0;
   unsigned int  arrayindex = 0;
   long          papoose    = 1; /* flag for LITTLE ENDIAN, 
                                  * set if LITTLE ENDIAN
                                  */

   if ((!pData) || (!pHashValue))
      return (1);

   memset(paddata, 0, sizeof(paddata));
   paddata[0] = (char) (unsigned int)128;

   /* run time check of LITTLE ENDIAN or BIG ENDIAN */
   if(*(char *)&papoose != 1)
      papoose = 0;    /* prosessor is BIG ENDIAN */

   while ((arrayindex+64) <= DataSize)
   {
      memcpy(dat.letters, pData+arrayindex, BLOCK);

      if (papoose == 1)
      {
         /* perform little endian byte swap, Intel processor thing */
         for (i = 0; i < 16; i++)
         {
            SM_DoEndian(&(dat.numbers[i])); /* swap bytes */
         }
      }
      SHA1_SohHash(dat.numbers, (unsigned long *) hash.hashval);
      arrayindex += BLOCK;
      hash.total += 512;      /* 512 bits processed */
   } /* end of while */

   leftovers = DataSize - arrayindex;
   memcpy(dat.letters, pData+arrayindex, leftovers);
   memcpy(dat.letters+leftovers, paddata, BLOCK-leftovers);
   if(papoose == 1)
   {
       /* perform little endian byte swap, Intel processor thing */
       for (i = 0; i < 16; i++)
       {
          SM_DoEndian(&(dat.numbers[i])); /* swap bytes */
       }
   }

   if (leftovers >= 56)
   {
      SHA1_SohHash(dat.numbers, (unsigned long *) hash.hashval);
      memset(&dat.letters[0], 0, sizeof(dat)/*BLOCK*/);
   }

   hash.total += (8*leftovers);  /* leftover bits < 512 */

   dat.numbers[15] = hash.total;

   SHA1_SohHash(dat.numbers, (unsigned long *) hash.hashval);

   /* reset hash flags */
   hash.initflag = 0;
   hash.total = 0;

   if(papoose == 1)  /* if LITTLE ENDIAN, INTEL Processor thing */
   {
       /* perform little endian byte swap */
       for (i = 0; i < 5; i++)
       {
          SM_DoEndian(&(hash.hashval[i])); /* swap bytes */
       }

   }
   memcpy(pHashValue, hash.hashval, SHA1_SIZE);

   return (0);
} /* end of SHA1_GetHash() */


/*
 *    Secure Hash Algorithm (SHA)
 *
 * Sha is an algorithm which produces a 160-bit output
 * for any length message.  The purpose of a secure hash algorithm
 * is to redeuce the number of bits to which a signature algorithm
 * must be applied, without affecting the security of the signature.
 *
 * Note: This implementation only accepts messages under 2^32 bits
 * in length.  For messages of larger lengths we suggest that a
 * multiple precision package be used to maintain the size of the
 * message.
 *
*/

void CSM_Common::SHA1_SohHash( unsigned long *M, 
                           unsigned long *data)
{
   unsigned long temp,newa,newb,newc,newd,newe;
   unsigned long W0,W1,W2,W3,W4,W5,W6,W7,W8,W9,W10,W11,W12,W13,W14,W15;
   unsigned long W16,W17,W18,W19,W20,W21,W22,W23,W24,W25,W26,W27,W28,W29,W30,W31
;
   unsigned long W32,W33,W34,W35,W36,W37,W38,W39,W40,W41,W42,W43,W44,W45,W46,W47
;
   unsigned long W48,W49,W50,W51,W52,W53,W54,W55,W56,W57,W58,W59,W60,W61,W62,W63
;
   unsigned long W64,W65,W66,W67,W68,W69,W70,W71,W72,W73,W74,W75,W76,W77,W78,W79
;

   W0 = M[0];
   W1 = M[1];
   W2 = M[2];
   W3 = M[3];
   W4 = M[4];
   W5 = M[5];
   W6 = M[6];
   W7 = M[7];
   W8 = M[8];
   W9 = M[9];
   W10 = M[10];
   W10 = M[10];
   W11 = M[11];
   W12 = M[12];
   W13 = M[13];
   W14 = M[14];
   W15 = M[15];

        W16 = Ls1(W13 ^ W8 ^ W2 ^ W0);
        W17 = Ls1(W14 ^ W9 ^ W3 ^ W1);
        W18 = Ls1(W15 ^ W10 ^ W4 ^ W2);
        W19 = Ls1(W16 ^ W11 ^ W5 ^ W3);
        W20 = Ls1(W17 ^ W12 ^ W6 ^ W4);
        W21 = Ls1(W18 ^ W13 ^ W7 ^ W5);
        W22 = Ls1(W19 ^ W14 ^ W8 ^ W6);
        W23 = Ls1(W20 ^ W15 ^ W9 ^ W7);
        W24 = Ls1(W21 ^ W16 ^ W10 ^ W8);
        W25 = Ls1(W22 ^ W17 ^ W11 ^ W9);
        W26 = Ls1(W23 ^ W18 ^ W12 ^ W10);
        W27 = Ls1(W24 ^ W19 ^ W13 ^ W11);
        W28 = Ls1(W25 ^ W20 ^ W14 ^ W12);
        W29 = Ls1(W26 ^ W21 ^ W15 ^ W13);
        W30 = Ls1(W27 ^ W22 ^ W16 ^ W14);
        W31 = Ls1(W28 ^ W23 ^ W17 ^ W15);
        W32 = Ls1(W29 ^ W24 ^ W18 ^ W16);
        W33 = Ls1(W30 ^ W25 ^ W19 ^ W17);
        W34 = Ls1(W31 ^ W26 ^ W20 ^ W18);
        W35 = Ls1(W32 ^ W27 ^ W21 ^ W19);
        W36 = Ls1(W33 ^ W28 ^ W22 ^ W20);
        W37 = Ls1(W34 ^ W29 ^ W23 ^ W21);
        W38 = Ls1(W35 ^ W30 ^ W24 ^ W22);
        W39 = Ls1(W36 ^ W31 ^ W25 ^ W23);
        W40 = Ls1(W37 ^ W32 ^ W26 ^ W24);
        W41 = Ls1(W38 ^ W33 ^ W27 ^ W25);
        W42 = Ls1(W39 ^ W34 ^ W28 ^ W26);
        W43 = Ls1(W40 ^ W35 ^ W29 ^ W27);
        W44 = Ls1(W41 ^ W36 ^ W30 ^ W28);
        W45 = Ls1(W42 ^ W37 ^ W31 ^ W29);
        W46 = Ls1(W43 ^ W38 ^ W32 ^ W30);
        W47 = Ls1(W44 ^ W39 ^ W33 ^ W31);
        W48 = Ls1(W45 ^ W40 ^ W34 ^ W32);
        W49 = Ls1(W46 ^ W41 ^ W35 ^ W33);
        W50 = Ls1(W47 ^ W42 ^ W36 ^ W34);
        W51 = Ls1(W48 ^ W43 ^ W37 ^ W35);
        W52 = Ls1(W49 ^ W44 ^ W38 ^ W36);
        W53 = Ls1(W50 ^ W45 ^ W39 ^ W37);
        W54 = Ls1(W51 ^ W46 ^ W40 ^ W38);
        W55 = Ls1(W52 ^ W47 ^ W41 ^ W39);
        W56 = Ls1(W53 ^ W48 ^ W42 ^ W40);
        W57 = Ls1(W54 ^ W49 ^ W43 ^ W41);
        W58 = Ls1(W55 ^ W50 ^ W44 ^ W42);
        W59 = Ls1(W56 ^ W51 ^ W45 ^ W43);
        W60 = Ls1(W57 ^ W52 ^ W46 ^ W44);
        W61 = Ls1(W58 ^ W53 ^ W47 ^ W45);
        W62 = Ls1(W59 ^ W54 ^ W48 ^ W46);
        W63 = Ls1(W60 ^ W55 ^ W49 ^ W47);
        W64 = Ls1(W61 ^ W56 ^ W50 ^ W48);
        W65 = Ls1(W62 ^ W57 ^ W51 ^ W49);
        W66 = Ls1(W63 ^ W58 ^ W52 ^ W50);
        W67 = Ls1(W64 ^ W59 ^ W53 ^ W51);
        W68 = Ls1(W65 ^ W60 ^ W54 ^ W52);
        W69 = Ls1(W66 ^ W61 ^ W55 ^ W53);
        W70 = Ls1(W67 ^ W62 ^ W56 ^ W54);
        W71 = Ls1(W68 ^ W63 ^ W57 ^ W55);
        W72 = Ls1(W69 ^ W64 ^ W58 ^ W56);
        W73 = Ls1(W70 ^ W65 ^ W59 ^ W57);
        W74 = Ls1(W71 ^ W66 ^ W60 ^ W58);
        W75 = Ls1(W72 ^ W67 ^ W61 ^ W59);
        W76 = Ls1(W73 ^ W68 ^ W62 ^ W60);
        W77 = Ls1(W74 ^ W69 ^ W63 ^ W61);
        W78 = Ls1(W75 ^ W70 ^ W64 ^ W62);
        W79 = Ls1(W76 ^ W71 ^ W65 ^ W63);

   newa=data[0]; newb=data[1]; newc=data[2]; newd=data[3]; newe=data[4];

   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W0+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W1+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W2+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W3+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W4+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W5+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W6+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W7+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W8+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W9+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W10+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W11+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W12+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W13+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W14+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W15+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W16+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W17+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W18+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F0(newb,newc,newd)+newe+W19+K1;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;

   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W20+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W21+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W22+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W23+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W24+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W25+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W26+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W27+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W28+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W29+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W30+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W31+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W32+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W33+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W34+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W35+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W36+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W37+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W38+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W39+K2;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;

   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W40+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W41+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W42+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W43+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W44+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W45+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W46+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W47+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W48+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W49+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W50+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W51+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W52+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W53+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W54+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W55+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W56+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W57+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W58+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F1(newb,newc,newd)+newe+W59+K3;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;

   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W60+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W61+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W62+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W63+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W64+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W65+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W66+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W67+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W68+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W69+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W70+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W71+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W72+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W73+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W74+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W75+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W76+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W77+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W78+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;   newa = temp;
   temp = Ls5(newa)+F2(newb,newc,newd)+newe+W79+K4;
   newe = newd;   newd = newc;
   newc = Ls30(newb);
   newb = newa;

   data[0] += temp;
   data[1] += newb;
   data[2] += newc;
   data[3] += newd;
   data[4] += newe;
} /* end of SohHash */



//  THIS METHOD ONLY HANDLES the original SFL 3DES and RC2 key wrap common 
//  elements; the AES key wrap is handled differently (no commonality with 
//  3DES or RC2).
SM_RET_VAL CSM_Common::SMTI_GenerateKeyWrapFinish(
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT.
            CSM_Buffer *pMEK, // In; may be specified.
            CSM_Buffer *pIV,  // In, to avoid specific alg encoding by app.
            CSM_Buffer *pCEKICVIN)
{
   SM_RET_VAL status=0;
   CSM_Buffer Iv,PAD;  
   CSM_Buffer *pTEMP1 = NULL;  
   CSM_Buffer *pTEMP2 = NULL;
   CSM_Buffer TEMP3;
   CSM_Buffer tmp;
   CSM_Buffer *pCEKICV=new CSM_Buffer;

   SME_SETUP("CSM_Common::SMTI_GenerateKeyWrapFinish");

   //CMS KeyWrap Step 2(3DES)/4(RC2) Create Checksum.
   // Compute 20 octet SHA1 message digest on the content-encryption key (CEK).
   char pICV[20];
   SHA1_InitializeHash();
   SHA1_GetHash(pCEKICVIN->Length(), (unsigned char *)pCEKICVIN->Access(), 
       (unsigned char *)pICV);
   SME(pCEKICV->Open(SM_FOPEN_WRITE));
   SME(pCEKICV->Write(pCEKICVIN->Access(), pCEKICVIN->Length()));
   SME(pCEKICV->Write((char *)pICV, 8));
   pCEKICV->Close();

   // CMS Steps 1-4 performed by specific library handling the 
   //   encryption algorithm.

   //CMS-11 Steps 5A Generate Random IV.
   SME(SMTI_Random(NULL, &Iv, pIV->Length()));

   // Output parameter
   pTEMP1 = new CSM_Buffer();

   //CMS-11 Steps 4,5B Padding and Encryption is done by SMTI_Encrypt. 
   // RWC;TBD;   Parameter check.
   SME(status = SMTI_Encrypt(pCEKICV, pTEMP1, pParameters, 
      pMEK, &Iv));

   //CMS-11 Steps 6 Concatenate TEMP and Iv to make TEMP2.
   pTEMP2 = new CSM_Buffer();
   SME(pTEMP2->Open(SM_FOPEN_WRITE));
   SME(pTEMP2->Write(Iv.Access(),Iv.Length()));
   SME(pTEMP2->Write(pTEMP1->Access(), pTEMP1->Length()));
   pTEMP2->Close();

   //CMS-11 Steps 7 Reverse order of octets in TEMP2.
   pTEMP2->reverseOctets();
   /*
   char *pTemp2 = pTEMP2->Access();

   CSM_Buffer tmp(pTEMP2->Length());
   char *pTemp3 = tmp.Access();

   for(i = pTEMP2->Length() - 1,j = 0; i >= 0; i--,j++)
   {
      pTemp3[j] = pTemp2[i];
   }
   */

   CSM_Buffer TEMP3(*pTEMP2);

   // CMS-11 Step 8 pIV is a constant loaded prior to
   // this call by SMTI_GenerateKeyWrapIV.
   SME(status = SMTI_Encrypt(&TEMP3, pEncryptedData, pParameters, 
      pMEK, pIV));

   delete pTEMP1;
   delete pTEMP2;
   delete pCEKICV;

   SME_FINISH
   SME_CATCH_SETUP
   delete pCEKICV;
   SME_CATCH_FINISH

   return(status);
}           // END CSM_Common::SMTI_GenerateKeyWrapFinish(...)


////////////////////////////////////////////////////////////////////////////////
// 
// Function:  SMTI_ExtractKeyWrap
//
// Description:
//
//  This logic is separated out to handle KARI and KEK CMS processing which
//  both use the same KeyWrap algorithm and processing.
//  The CSM_Common class handling of the KeyWrap only performs the beginning
//  algorithm details, independent of the final algorithm specific handling.
//
//  Function no longer handles AES 
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Common::SMTI_ExtractKeyWrap(
            CSM_Buffer *pData, // Output
            CSM_Buffer *pEncryptedData, // input
            CSM_Buffer *pParameters, // RWC;TBD;REMOVE;IN, for KeyAgree algs.
            CSM_Buffer *pTEK, // IN
            CSM_Buffer *pIV22)  // Used for iv length only
{
   SM_RET_VAL status=0;
   CSM_Buffer IV,pIV;
   CSM_Buffer TEMP3, TEMP2, TEMP1, CEKICVPAD, ParamDerived, CEK, ICV;
   bool bParametersAllocatedFlag=false;
   int  IVSize = 0;
   AsnOid        *pPreferredOID = GetPrefContentEncryption();

   SME_SETUP("CSM_Common::SMTI_ExtractKeyWrap");

   // get the size of the iv, rc2 and 3des = 8, aes = 16
   if (pIV22)
       IVSize = pIV22->Length();
   else
       IVSize = 8;

   // LOAD hardcoded IV. CMS-11 defines the length of the hard coded value
   // to be 8, IVSize is defaulted to 8.  If AES then the size is 16
   
//   char Ivhard[] = {0x4a,0xdd,0xa2,0x2c,0x79,0xe8,0x21,0x05};
   //char Ivhard[] = {(char)0x05,(char)0x21,(char)0xe8,(char)0x79,(char)0x2c,(char)0xa2,(char)0xdd,(char)0x4a};
   // if AES the first 8 will be the following with the next 8 having 0
   //     0x 4a dd a2 2c 79 e8 21 05 00 00 00 00 00 00 00 00
   unsigned char *IvHard = (unsigned char *) calloc(1, IVSize); 
   unsigned char tmpArray[]={(unsigned char)0x4a,(unsigned char)0xdd,
                  (unsigned char)0xa2,(unsigned char)0x2c,(unsigned char)0x79,
                  (unsigned char)0xe8,(unsigned char)0x21,(unsigned char)0x05};
   memcpy(IvHard,tmpArray,8);

   //0x 4a dd a2 2c 79 e8 21 05
   // CMS-11 defines the length of the hard coded value to be 8.
   // AES needs length to be 16
   // copy the hardcoded IV (size 8) to pIV
   // should end up with 0x 4a dd a2 2c 79 e8 21 05 00 00 00 00 00 00 00 00 in pIV
   //memcpy(pIV.Access(),Ivhard,8);

   CSM_Buffer pIV((char *)IvHard,(size_t)IVSize); 
   if (IvHard)
      free (IvHard);

   if(pParameters == NULL)
   {
      bParametersAllocatedFlag = true;
      pParameters = new CSM_Buffer();
   }

   LoadParams(pIV, pParameters); // load into CTIL Param format for Decrypt.

   //#################################
   // SPECIAL CHECK FOR 3DES due to recent Million Message Attack UPDATES!
   // UPDATE intermediate results; SMTI_ExtractKeyWrapFinish(...) will properly
   //  update final 3DES key.
   if (*pPreferredOID == AsnOid("1.2.840.113549.1.9.16.3.6")) //id_alg_CMS3DESwrap)
   {
      // NOW, set parity since this calculation does not produce parity proper 
      //  results for 3DES.  This logic was removed from 3DES decrypt in order
      //  to support Million Message Attack issues (RFC3218).
      unsigned char *ptr3=(unsigned char *)pTEK->Access();
      unsigned long value;
      unsigned int ii2;
      for (unsigned long ii=0; ii < pTEK->Length(); ii++)
      {
          value = (unsigned long)ptr3[ii];
          for (ii2=8*sizeof(value)/2; ii2>0; ii2/=2)
		    value ^= value >> ii2;
          if (!(value & 1))   // IF ODD Parity, change LOWEST bit.
              ptr3[ii] ^= 0x01;
      }
   }        // END IF 3DES


   // UNWRAP STEP 2; DECRYPT using pParameters; expected to be constant.
   SME(SMTI_Decrypt(pParameters, pEncryptedData, pTEK, &TEMP3));

   // UNWRAP STEP 3; Reverse order of octets in TEMP3.
   TEMP3.reverseOctets();
   TEMP2 = TEMP3;

   if (TEMP2.Length() > (unsigned long)IVSize)
   {
     // UNWRAP STEP 4; split decrypted result into DATA || IV.
     TEMP1.Set(&TEMP2.Access()[IVSize], TEMP2.Length()-IVSize);
     IV.Set(TEMP2.Access(),IVSize);

     // UNWRAP STEP 5; decrypt result into CEKICVPAD.
     LoadParams(IV, &ParamDerived); // load into CTIL Param format for Decrypt.
     SME(SMTI_Decrypt(&ParamDerived, &TEMP1/*RWC;pEncryptedData*/, pTEK, &CEKICVPAD));

     if (CEKICVPAD.Access() == NULL)
     {
        SME_THROW(22,"Empty CEKICV for DH key decryption.\n", NULL);
     }
        // this is the hash at the end of the content encryption data
        ICV.Set(&CEKICVPAD.Access()[CEKICVPAD.Length() - 8], 8);

        if (ICV.Access() == NULL)
        {
           SME_THROW(22,"Empty IV for DH key decryption.\n", NULL);
        }


        // UNWRAP STEP 8; Checksum/Hash computation and compare; 
        char pICV2[20];
        SHA1_InitializeHash();
        SHA1_GetHash(CEKICVPAD.Length()-8, (unsigned char *)CEKICVPAD.Access(),
            (unsigned char *)pICV2);

        // Comparison against old checksum to see if hash comes out to be the same.
        if(memcmp(ICV.Access(), pICV2, 8) != 0)
        {
#ifdef MSTEST
          SME_THROW(22,"Checksum computation doesn't match Encrypt's Checksum.\n", NULL);
#else
           printf("Bad Hash KEK\n");
#endif
        }

        // FINISH algorithm specific processing.
        TEMP2.Set(CEKICVPAD.Access(), CEKICVPAD.Length()-8);    // re-use TEMP2
        status = SMTI_ExtractKeyWrapFinish(pData, TEMP2);

        if (status == 0)
        {
           //RWC;NOTE: not all CTILs check for resulting length; this is 
           //  because CTILs linke Fortezza cannot access the MEK, so it
           //  it will be 0 length and still work.  This check works 
           //  because the Frotezza CTIL overrides this method.
         if (pData->Length() == 0)
           SME_THROW(22,"Bad MEK Length returned!",NULL);
        }       // END IF status

      if (bParametersAllocatedFlag)
         delete pParameters;
   }    // END if size large enough to handle initialization vector.
   else
   {
       SME_THROW(22,"Bad data length for initialization vector.", NULL);
       // bad decrypted length.
   }

   if (pPreferredOID)
       delete pPreferredOID;

   SME_FINISH
   SME_CATCH_SETUP
      if (bParametersAllocatedFlag && pParameters)
         delete pParameters;
      if (pPreferredOID)
         delete pPreferredOID;
   SME_CATCH_FINISH
   return(status);
}       // END CSM_Common::SMTI_ExtractKeyWrap(...)



//////////////////////////////////////////////////////////////////////////
CSM_Common::CSM_Common()
{
    this->m_ThreadLock.threadLock();
    m_pInst = NULL;
}


void CSM_Common::CSM_TokenInterfaceDestroy()
{
   this->m_ThreadLock.threadUnlock();
   delete this;   
}



//////////////////////////////////////////////////////////////////////////

void SM_DoEndian(unsigned long *in_data)
{
   unsigned long temp_long = 0;
   int i = 0;

   /*
    * Shift the word 16 bits
    */
   temp_long  = (in_data[i] << 16) | (in_data[i] >> 16);

   /*
    * Include the sign bit for each byte in the word
    */
   in_data[i] = ((temp_long & 0xff00ff00L) >> 8) | ((temp_long & 0x00ff00ffL) << 8);
}

//
//
void CSM_Common::LoadParams(CSM_Buffer &IV, CSM_Buffer *Parameters, int effectiveKeyBytes)
{
   SME_SETUP("CSM_Common::LoadParams");

   AsnOid *pPreferredOID = GetPrefContentEncryption();  

   // determine 3des or rc2 loading of parameters
   if (*pPreferredOID == rc2_cbc || *pPreferredOID == id_alg_CMSRC2wrap)
   {
      // effective key bytes * 8  use in EncodeRC2params call.
      EncodeRC2Params(*Parameters, effectiveKeyBytes * 8, IV);
   }
   else  // 3des side and for AES NIST (for now  01-22-01) 
         // until data type is specified
   { 
      TDESParameters snaccParams(IV.Access(), IV.Length());
      ENCODE_BUF_NO_ALLOC(&snaccParams, Parameters);
   }
   if (pPreferredOID)
      delete pPreferredOID;
   SME_FINISH_CATCH 
}
//////////////////////////////////////////////////////////////////////////
void CSM_Common::EncodeRC2Params(CSM_Buffer &out, int keyBits, CSM_Buffer &iv)
{
   RC2_CBC_parameter snaccMSOEParams;  // OLD RSA Params encoding.
                                       //  (RWC;by MS Outlook Express).
   long status=1;
   
   SME_SETUP("CSM_Common::EncodeRC2Params");

      if (keyBits == 0 && out.Length())   
      {           // THEN try to extract for RC2.
         status = 0;
         DECODE_BUF_NOFAIL(&snaccMSOEParams, &out, status);
      }

      if (status != 0)     // Load specified entry if not decoded directly.
      {
          if (keyBits == 40)   // MSOE old use!!
              snaccMSOEParams.rc2ParameterVersion = 160;
          else if (keyBits == 64)   // MSOE old use!!
              snaccMSOEParams.rc2ParameterVersion = 120;
          else if (keyBits == 128)   // MSOE old use!!
              snaccMSOEParams.rc2ParameterVersion = 58;
          else
             snaccMSOEParams.rc2ParameterVersion = keyBits;
      }     // END if status != 0
      snaccMSOEParams.iv.Set(iv.Access(), iv.Length());//SM_COMMON_RC2_BLOCKSIZE);
      ENCODE_BUF_NO_ALLOC((&snaccMSOEParams), (&out));

   SME_FINISH_CATCH
}
///////////////////////////////////////////////////////////////////////////////////
CSM_Buffer * CSM_Common::UnloadParams(AsnOid *pPrefContentOid,
                                      CSM_Buffer &parameters, 
                                      int &effectiveKeyBits)
{
   CSM_Buffer *pBuf = new CSM_Buffer();

   SME_SETUP("CSM_Common::UnloadParams");

   if ((*pPrefContentOid == rc2_cbc) || (*pPrefContentOid == id_alg_CMSRC2wrap))
   {
      RC2CBCParameter snaccParams;
      int status;
                                       //  (RWC;by MS Outlook Express).
      DECODE_BUF_NOFAIL((&snaccParams), (&parameters), status);

      if (status == 0)
      {
        if (snaccParams.iv.Len() == SM_COMMON_RC2_BLOCKSIZE)
        {
           pBuf->Set(snaccParams.iv.c_str(), SM_COMMON_RC2_BLOCKSIZE);
          
           if (snaccParams.rc2ParameterVersion == 160)
             effectiveKeyBits = 40;   // MSOE old use!!
           else if (snaccParams.rc2ParameterVersion == 120)
             effectiveKeyBits = 64;   // MSOE old use!!
           else if (snaccParams.rc2ParameterVersion == 58)
             effectiveKeyBits = 128;   // MSOE old use!!
           else
           {
             if (snaccParams.rc2ParameterVersion == 0)
               effectiveKeyBits = 128;
             else
               effectiveKeyBits = snaccParams.rc2ParameterVersion;
             //RWC;
           }
        }
        else
        {
          delete pBuf;
          pBuf = NULL;
          effectiveKeyBits = 0;
        }

      }
      else
      {
         delete pBuf;
         pBuf = NULL;
         effectiveKeyBits = 0;
      }
   }
   else
   {
      if (parameters.Length() > 2 && 
        !(parameters.Access()[0] == 0x05 && parameters.Access()[0] == 0x05 ))
      {
         // ASN.1 decode the parameters that contain the IV
         TDESParameters snaccParams;
         long lstat=0;

         DECODE_BUF_NOFAIL(&snaccParams, &parameters, lstat);
         if (lstat)//RWC;PRE-R2.2;!decodeBuf(snaccParams,parameters))
         {
            delete pBuf;
            pBuf = NULL;
         }
         else
            pBuf->Set(snaccParams.c_str(), snaccParams.Len());
      }
      else
      {
         delete pBuf;
         pBuf = NULL;
      }
   }

   SME_FINISH
      SME_CATCH_SETUP
      if (pBuf)
         delete pBuf;
      pBuf = NULL;

   SME_CATCH_FINISH

   return(pBuf);
}

SM_RET_VAL CSM_Common::SMTI_Verify(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
    return SMTI_VerifyInternalDSA(pSignerKey, pDigestAlg, pSignatureAlg, 
            pData, pSignature);
}
//
//
//
SM_RET_VAL CSM_Common::SMTI_VerifyInternalDSA(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA    *pDigestAlg, // input
            CSM_AlgVDA    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   unsigned char *pP=NULL, *pQ=NULL, *pG=NULL;
   unsigned char *pY=NULL;
   unsigned char *pHashValue=NULL;
   unsigned char *pR=NULL, *pS=NULL;
   CSM_Buffer bufferDigest;
   CSM_Buffer *pParams;
   AsnOid *palgoid=NULL;
   AsnOid *pdigoid=NULL;


   SME_SETUP("CSM_Common::SMTI_VerifyInternalDSA");

   if ((pData == NULL) || (pSignerKey == NULL) || (pSignature == NULL) ||
         (pSignatureAlg == NULL))
      SME_THROW(SM_MISSING_PARAM, "Missing Parameter", NULL);

   palgoid = pSignatureAlg->GetId();
   if (palgoid && (*palgoid == id_dsa_with_sha1 || *palgoid == id_dsa ||
      *palgoid == id_OIW_secsig_algorithm_dsa))
   {
      if (pDigestAlg)
         pdigoid = pDigestAlg->GetId();
      else
         pdigoid = new AsnOid(*palgoid);

      // Set the preferred digest
      if (pdigoid)
     {
         BTISetPreferredCSInstAlgs(pdigoid, NULL, NULL, NULL);
       delete pdigoid;
     }
      if ((pParams = pSignatureAlg->GetParams()) != NULL &&
         !(pParams->Length() == 2 && pParams->Access()[0] == 0x05))
               // IGNORE if NULL ASN.1 encoded.
      {
        CSM_DSAParams dsaParameters;

        SME(dsaParameters.Decode(pParams));
        pP = (unsigned char *)dsaParameters.P;
        pQ = (unsigned char *)dsaParameters.Q;
        pG = (unsigned char *)dsaParameters.G;
        AsnInt/*RWC;CSM_BigIntegerStr*/ sm_YY;
        DECODE_BUF(&sm_YY, pSignerKey);
        //sm_YY.Buffer2BigIntegerStr((unsigned char *)pSignerKey->Access(), 
        //   pSignerKey->Length(), true);//RWC;Decode(pSignerKey);
        size_t len=0;
        size_t iPLength=128;           // DEFAULT key length 128.
        if (pSignerKey->Length() <= 70) // THEN must be short signature key
            iPLength = 64;
        sm_YY.getPadded/*RWC;Get*/(pY, len, iPLength);
        // For this next call, we are assuming that the "virtual" definition has
        //  been over-ridden with valid digest processing logic AND that the user
        //  has already setup the appropriate algorithm to digest with.  We are
        //  not necessarily relying on algorithms performed by this CSM_Common
        //  class.
        SME(SMTI_DigestData(pData, &bufferDigest));
        pHashValue = (unsigned char *)bufferDigest.Access();
        //RWC;For some reason the hash buffer is word (4 byte) re-aligned.
        unsigned char jj;
        for (int i=0; i < (int)bufferDigest.Length()/4; i++)
        {
            jj = pHashValue[i*4];
            pHashValue[i*4] = pHashValue[i*4+3];
            pHashValue[i*4+3] = jj;
            jj = pHashValue[i*4+1];
            pHashValue[i*4+1] = pHashValue[i*4+2];
            pHashValue[i*4+2] = jj;
        }


        //  Extract different versions of the pR and pS signature values.
        lRet=ExtractSignatureR_AND_S(*pSignature, pR, pS);
        if (lRet == 0)
          lRet = F_sig_check(pP, pQ, pG, pY, pHashValue, pR, pS
                     /*RWC;added back in, iPLength; then removed later.*/);
        if (pParams)
           delete pParams;
        if (pY)
            free(pY);
      }
      else
      {
        SME_THROW(22, "Signature Algorithmn has no params", NULL);
      }
   }
   else
   {
      SME_THROW(22, "Signature Algorithmn oid is not recognized!", NULL);
   }

   if (palgoid)
       delete palgoid;

   SME_FINISH
   SME_CATCH_SETUP
   if (palgoid)
       delete palgoid;
   if (pR)
       free(pR);
   if (pS)
       free(pS);
   SME_CATCH_FINISH

   if (pR)
       free(pR);
   if (pS)
       free(pS);
#ifdef WIN32
    pDigestAlg; // AVOIDS compiler warning.
#endif
   return lRet;
}

//
//
//RWC;TBD;2/14/01;REMOVE sm_free3.cpp logic and call this function.
#define DSA_SIG_LEN 40
long CSM_Common::ExtractSignatureR_AND_S(CSM_Buffer &BufSignature, //INPUT
                                    unsigned char *&pR,            //OUTPUT
                                    unsigned char *&pS)            //OUTPUT
{
   long status=-1;

   SME_SETUP("CSM_Common::ExtractSignatureR_AND_S");

   if (BufSignature.Length() == DSA_SIG_LEN)  // OLD STYLE DSA sig value.
   {                    // r and s are simply con-catenated.
      if (pR == NULL) pR = (unsigned char *)calloc(DSA_SIG_LEN/2,1);
      if (pS == NULL) pS = (unsigned char *)calloc(DSA_SIG_LEN/2,1);
      memcpy(pR, &BufSignature.Access()[0], DSA_SIG_LEN/2);
      memcpy(pS, &BufSignature.Access()[20], DSA_SIG_LEN/2);
      status = 0;
   }
   else
   {
      AsnInt/*RWC;CSM_BigIntegerStr*/ bufR;
      AsnInt/*RWC;CSM_BigIntegerStr*/ bufS; 
      Dss_Sig_ValueVDA SNACCDSA_r_s;   // in sm_free3_asn.asn
      // RWC; NOW recreate 2 values r=20 bytes, s=20bytes from
      // RWC;  encoded DSA signature accroding to PKIX.
      DECODE_BUF(&SNACCDSA_r_s, &BufSignature);
      bufR.Set(SNACCDSA_r_s.r.c_str(), SNACCDSA_r_s.r.length());
      bufS.Set(SNACCDSA_r_s.s.c_str(), SNACCDSA_r_s.s.length());
      size_t lLengthR, lLengthS;
      bufR.getPadded(pR, lLengthR, 20);
      bufS.getPadded(pS, lLengthS, 20);
      if (lLengthR != 20 || lLengthS != 20)
      {
          SME_THROW(22, "BAD SNACC GetUnSignedBitExtendedData(...) length=20!", 
              NULL);
      }
      /*// Load Signature with R and S.
      int startReadIndex=0;
      int startIndex = DSA_SIG_LEN/2 - bufR.Len();
      if (startIndex < 0)
      {
          startReadIndex = -startIndex;
          startIndex = 0;
      }
      if (pR == NULL) pR = (unsigned char *)calloc(DSA_SIG_LEN/2,1);
      if (pS == NULL) pS = (unsigned char *)calloc(DSA_SIG_LEN/2,1);
      memcpy(pR, &bufR[startReadIndex], DSA_SIG_LEN/2 - startIndex);
      startReadIndex = 0;
      startIndex = DSA_SIG_LEN/2 - bufS.Len();
      if (startIndex < 0)
      {
          startReadIndex = -startIndex;
          startIndex = DSA_SIG_LEN/2;   // start exactly half way
      }
      else
          startIndex += DSA_SIG_LEN/2;
      memcpy(pS, &bufS[startReadIndex], DSA_SIG_LEN - startIndex);*/
      status = 0;
   }

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH


    return(status);
}


////
//// This method will load all of the common supported algorithms directly in 
////  Alg Lists.  This facilitates that any CTIL can instantly load the common
////  supported algs directly into its own set in 1 call.
void CSM_Common::SetDefaultOIDLists(CSM_AlgLstVDA *pDigestAlgs, 
                                    CSM_AlgLstVDA *pDigestEncryption, 
                                    CSM_AlgLstVDA *pKeyEncryption, 
                                    CSM_AlgLstVDA *pContentEncryption)
{
   SME_SETUP("CSM_Common::SetDefaultOIDLists");

   // put the AsnOids in AsnOids
   AsnOid ENDOID("0.0.0");
   AsnOid oidHash[] = { 
       sha_1, 
       id_SHA256,
       sha256WithRSAEncryption,
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption,
       id_dsa_with_sha1,
       ENDOID };
   AsnOid oidSignDSA[] = { 
       id_dsa,  
       id_dsa_with_sha1, 
       id_OIW_secsig_algorithm_dsa,
       ENDOID };
   AsnOid oidContentEncrypt[] = { 
      //aes,
       id_aes128_CBC,
       id_aes256_CBC,
       id_aes192_CBC,
       id_aes128_wrap,
       id_aes192_wrap,
       id_aes256_wrap,
       /**RWC;5/10/01;id_aes128_ECB,
       id_aes128_OFB,
       id_aes128_CFB,
       id_aes192_ECB,
       id_aes192_OFB,
       id_aes192_CFB,
       id_aes256_ECB,*/
       /**RWC;5/10/01;id_aes256_OFB,
       id_aes256_CFB,*/
       ENDOID };
   /*AsnOid oidKeyEncrypt[] = { 
       ENDOID };            NOT YET SUPPORTED as a common alg.*/
   CSM_AlgVDA *pAlg;
   int i;

   // Produce list of separate alg lists.
     if (pDigestAlgs)
       for (i=0; oidHash[i] != ENDOID; i++)
       {
           //pAlg = new CSM_AlgVDA(oidHash[i]);
           pAlg = &(*pDigestAlgs->append());
           pAlg->algorithm = oidHash[i];
       }

   if (pDigestEncryption)
     for (i=0; oidSignDSA[i] != ENDOID; i++)
     {
       //pAlg = new CSM_AlgVDA(oidSignDSA[i]);
       pAlg = &(*pDigestEncryption->append());
       pAlg->algorithm = oidSignDSA[i];
     }

   if (pContentEncryption)
     for (i=0; oidContentEncrypt[i] != ENDOID; i++)
     {
           //pAlg = new CSM_AlgVDA(oidContentEncrypt[i]);
           pAlg = &(*pContentEncryption->append());
           pAlg->algorithm = oidContentEncrypt[i];
     }
   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
#ifdef WIN32
   pKeyEncryption;  // Avoids compiler warning.
#endif
}

////////////////////////////////////////////////////////////////////////////////
//
// sib 12/10/04 Following code are changes for stripping AES out of common. Took 
// out CSM_CommCTIL.h/cpp files in which the CSM_DSAParams was located and put  
// that class in CSM_Common class files.
// 
////////////////////////////////////////////////////////////////////////////////

// FUNCTION: CSM_DSAParams Constructor
//
// PURPOSE: Initialize P,Q,G private members to 0.
//
////////////////////////////////////////////////////////////////////////////////
CSM_DSAParams::CSM_DSAParams()
{
   P = NULL;
   Q = NULL;
   G = NULL;
   m_lParamLength = 128;		// DEFAULT
}

//
//
CSM_DSAParams::~CSM_DSAParams()
{
   if (P) free(P);
   if (Q) free(Q);
   if (G) free(G);
}


// FUNCTION: DecodeParams
//
// PURPOSE: To decoded the ASN.1 encoded DSAWithSHA1Parameters from
//          pParams into the private member variable m_pSnaccParams
//
SM_RET_VAL CSM_DSAParams::Decode(CSM_Buffer *pParams)
{
   SM_RET_VAL status = SM_NO_ERROR;
   DSAWithSHA1Parameters *pSnaccV3CertParams;
   Kea_Dss_ParmsVDA           *pSnaccV1CertParams;
   size_t                 paramLen = 0;
   long error =  0;
   int pParamSize=0;
   unsigned char *ptr;

   SME_SETUP("CSM_DSAParams::Decode()");

   // V3 Certificate style parameters
   //
   pSnaccV3CertParams = new DSAWithSHA1Parameters;

   DECODE_BUF_NOFAIL(pSnaccV3CertParams, pParams,  error);
   
   // IF no error then use CSM_BigIntegerStr class to 
   //    perform big integer processing on  P, Q, and G.
   //
   //    note: this is only necessary for V3 certs
   //
   if (error == 0)
   {
       if (pSnaccV3CertParams->p.length() <= 65)
           pParamSize = 64;     // Smaller signature.
       else
           pParamSize = SM_DSA_P_LEN; // larger signature.
       pSnaccV3CertParams->p.getPadded/*RWC;Get*/(ptr, 
          paramLen, pParamSize);
       if (paramLen && ptr)
       {
           P = (char *)calloc(1, paramLen);
           memcpy(P, ptr, paramLen);
           free(ptr);
           ptr = NULL;
       }
       pSnaccV3CertParams->q.getPadded/*RWC;Get*/(ptr, 
          paramLen, (unsigned int) SM_DSA_Q_LEN);
       if (paramLen && ptr)
       {
           Q = (char *)calloc(1, paramLen);
           memcpy(Q, ptr, paramLen);
           free(ptr);
           ptr = NULL;
       }
       pSnaccV3CertParams->g.getPadded/*RWC;Get*/(ptr, 
          paramLen, (unsigned int) pParamSize);
       if (paramLen && ptr)
       {
           G = (char *)calloc(1, paramLen);
           memcpy(G, ptr, paramLen);
           free(ptr);
           ptr = NULL;
       }
       m_lParamLength = paramLen;
   }
   else
   {
      // Try V1 Certificate style DSS Parameters
      //
      P = (char *) calloc(1, SM_DSA_P_LEN);
      Q = (char *) calloc(1, SM_DSA_Q_LEN);
      G = (char *) calloc(1, SM_DSA_G_LEN);

      pSnaccV1CertParams = new Kea_Dss_ParmsVDA;
      DECODE_BUF_NOFAIL(pSnaccV1CertParams, pParams, error);

      if (error)
         SME_THROW(error,"Error decoding Subject Public Key parameters", NULL);

      if ( pSnaccV1CertParams->choiceId == pSnaccV1CertParams->different_ParmsVDACid )
      {
         if ( (pSnaccV1CertParams->different_ParmsVDA->dss_ParmsVDA.p.Len() != SM_DSA_P_LEN) ||
              (pSnaccV1CertParams->different_ParmsVDA->dss_ParmsVDA.q.Len() != SM_DSA_Q_LEN) ||  
              (pSnaccV1CertParams->different_ParmsVDA->dss_ParmsVDA.g.Len() != SM_DSA_G_LEN) )
            
         {
            SME_THROW(-1,"Invalid DSS Parameters", NULL);
         }
         else
         {
            memcpy(P, pSnaccV1CertParams->different_ParmsVDA->dss_ParmsVDA.p.c_str(), 
                                                                     SM_DSA_P_LEN);
            memcpy(Q, pSnaccV1CertParams->different_ParmsVDA->dss_ParmsVDA.q.c_str(), 
                                                                     SM_DSA_Q_LEN);
            memcpy(G, pSnaccV1CertParams->different_ParmsVDA->dss_ParmsVDA.g.c_str(), 
                                                                     SM_DSA_G_LEN);
         }
      }
      else if ( pSnaccV1CertParams->choiceId == pSnaccV1CertParams->common_ParmsCid )
      {
         if ( (pSnaccV1CertParams->common_Parms->p.Len() != SM_DSA_P_LEN) ||
              (pSnaccV1CertParams->common_Parms->q.Len() != SM_DSA_Q_LEN) ||
              (pSnaccV1CertParams->common_Parms->g.Len() != SM_DSA_G_LEN) )
         {
            SME_THROW(-1,"Invalid DSS Parameters", NULL);
         }
         else
         {
            memcpy(P, pSnaccV1CertParams->common_Parms->p.c_str(), SM_DSA_P_LEN);
            memcpy(Q, pSnaccV1CertParams->common_Parms->q.c_str(), SM_DSA_Q_LEN);
            memcpy(G, pSnaccV1CertParams->common_Parms->g.c_str(), SM_DSA_G_LEN);
         }
      }
      delete pSnaccV1CertParams;
      m_lParamLength = SM_DSA_P_LEN;
   }

   delete pSnaccV3CertParams;

   return status;

   SME_FINISH_CATCH;
}
 
// end of addition for stripping out AES from commmon

_END_CTIL_NAMESPACE 
//
// EOF sm_common.cpp
