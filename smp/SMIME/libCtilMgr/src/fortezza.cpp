/*****************************************************************************
File:     fortezza.cpp
Project:  Certificate Management Library
Contents: Hash and signature algorithm functions for the FORTEZZA algorithms.

Created:  June 1997
Author:   David Dalkowski <dadalko@missi.ncsc.mil>
          Rich Nicholas <rnich@jgvandyke.com>

Last Updated:  31 January 2001

Version:  1.9

Description:  F_sig_check(), FlipReverse(), F_sha1_hash(), & reverseParms() are new
functions, other routines are mostly in their original GFE state.

revision: 23Jan98 - DAD -
   split F_sig_check up so that sha1 hash is seperate, thus allowing the hash
   routine to be called on its own, and F_sig_check expecting caller to 
   provide a caclulated hash.

*****************************************************************************/
#include "asn-incl.h"

#include <memory.h>
#include <string.h>

extern "C" {

#include "fortezzaVDA.h"
/*****************************************************************************
    Constants
 ****************************************************************************/

#define NEG_ONE  0xFFFFFFFFL

#define MASK32   0xFFFFFFFFL
#define MASKU16  0xFFFF0000L
#define MASKL16  0x0000FFFFL
#define BLOCK    64
#define L_BLOCK  (BLOCK/sizeof(long))

#define Ls5(num)  (((num)<<5)|((num)>>27))
#define Ls30(num) (((num)<<30)|((num)>>2))


#define Ls1(num)  ( ( (num) << 1 ) | ( ( (num) >> 31 ) & 1 ) )

#define F0(x,y,z) ( (z) ^ ( (x) & ( (y) ^ (z) ) ) )
#define F1(x,y,z) ( ( (x) & ( (y) ^ (z) ) ) ^ ( (z) & (y) ) )
#define F2(x,y,z) ((x)^(y)^(z))

#define K1 0x5A827999L
#define K2 0x6ED9EBA1L
#define K3 0x8F1BBCDCL
#define K4 0xCA62C1D6L

/*****************************************************************************
    Local Data
 ****************************************************************************/
static unsigned char paddata[64] = {
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};


short isLittleEndian()
/*
 * Function checks the Endian-ness of the process and returns
 * TRUE if the process is Little Endian and FALSE if not little
 * Endian, this alleivates problems with compile defines
 */
{
 long value = 1;

   /* Check which byte the value 1 is in */
   if (*(char *)&value == 1)
      return 1;
   else
      return 0;
}


#define mult32(u1,u2,accum)             \
{                                       \
  unsigned  long x0, x1, x2, x3;        \
  unsigned  long ul, vl, uh, vh;        \
                                        \
  ul = (u1&0xffff);                     \
  uh = u1>>16;                          \
  vl = (u2&0xffff);                     \
  vh = u2>>16;                          \
  x0 = (ulong) ul * vl;         \
  x1 = (ulong) ul * vh;         \
  x2 = (ulong) uh * vl;         \
  x3 = (ulong) uh * vh;         \
                                        \
  x1 = x1 + (x0>>16);                   \
  x1 = x1 + x2;                         \
  if(x1 < x2)                           \
    x3 += 0x10000L;                     \
  uh = x3 + (x1>>16);                   \
  ul = (x1<<16) + (x0&0xffff);          \
                                        \
  accum[0] += ul;                       \
  x0=x1=0;                              \
  if(accum[0]<ul)                       \
    x0=1;                               \
                                        \
  accum[1] += uh;                       \
  if(accum[1]<uh)                       \
    accum[2]++;                         \
                                        \
  if((accum[1]==0xffffffffL)&&(x0==1))  \
    accum[2]++;                         \
  accum[1] += x0;                       \
                                        \
}


/* forward func declarations */
void reverseParms(uchar *data, ulong byteSize);
short dss_verify(ulong p[],ulong q[],ulong g[],ulong y[],ulong hash[],ulong r[],ulong s[] );
int HashBuffer(uchar *pData,ulong DataSize,ulong *hash );
static int sha_init(ulong  hash[]);
static int sha_hash(ulong M[],ulong hash[] );
void reduce_p(ulong a[], int alen, ulong  p[], ulong  array[] );
void reduce_q(ulong  a[],int alen,ulong q[],ulong array[] );
ulong neg_Inverse(ulong in[] );
void mpsub(ulong a[],ulong b[],ulong c[],int num );
void QExpo(ulong temp[],ulong base[],ulong e[],ulong m[],ulong minv,ulong rval[],int esize );
void mpmult(ulong  ans[],ulong  a[],ulong  b[],ulong  m[], ulong  minv,ulong  rval[],int bsize, ulong  ONE[] );
void DualExpo(ulong  temp[],ulong b1[],ulong e1[],ulong b2[],ulong e2[],ulong m[],ulong minv,ulong rval[],int esize );
void Mult16(unsigned int a[],unsigned int b[],unsigned int n[],unsigned int nInv,int maxSegs,unsigned int c[] );
void QSquare16(unsigned int a[],unsigned int b[],unsigned int n[],unsigned int nInv,int maxSegs,unsigned int c[] );
void montMult(ulong a[],ulong b[],ulong n[],ulong nInv,int maxSegs,ulong c[] );
void Square16( unsigned int a[],unsigned int b[],unsigned int n[],unsigned int nInv,int maxSegs,unsigned int c[] );
void FlipReverse(uchar *data, ulong byteSize);


/* 
 * F_sha1_hash()
 *
 * Routine called to do a sha1 hash on the given message data.
 *
 * msgdata = ptr to data that is to be hashed
 * msgsize = how many bytes in size
 * hashValue = caller provides an array of size 20 bytes for return value
 *
 * returns CM_NO_ERROR if hash was calculated
 * else error value.
 *
 * NOTE: the hash value is returned in it's calculated orientation,
 * and may need to be flipped around (adjusted,whatever) when passed
 * onto a particular sig checking routine.
 *
 */
short F_sha1_hash(uchar *msgdata, long msgsize, unsigned char *hashValue)
{
   short result;
   
   if((msgdata == 0) || (hashValue == 0) || (msgsize <= 0))
      return(F_INVALID_PARAMETER);
   
   /* the caller could just call HashBuffer() directly, but
    * we do the additional parameter checking above...
    */
   result = (short)HashBuffer(msgdata, msgsize, (ulong *)hashValue);
   
   return(result);
   
}



/*
 F_sig_check()

 routine to perform DSA  -
   p - Digital Signature Algorithm parameter p
   q - Digital Signature Algorithm parameter q
   g - Digital Signature Algorithm parameter g
   y - Public key of originator of the signature
   hashValue - hashed value of message
   r - 1/2 the sig
   s - other 1/2 of the sig
   
   NOTE: we assume the hash is 20 bytes in size....
   (sha1 orientation)
   
 */
short F_sig_check(uchar *p, uchar *q,uchar *g,uchar *y,uchar *hashValue,uchar *r,uchar *s)
{
   unsigned char   pHashValue[20];
   short result;
   /* since we need to screw around with the parameters here, we will have to make
    * copies for our use.
    */
   uchar xp[128], xq[20],xg[128];
   uchar xy[128],xr[20],xs[20];

   /* check parms here for now */
   if((p == 0) || (q == 0) || (g == 0) || (y== 0) ||
      (hashValue == 0)  || (r == 0) || (s == 0))
      return(F_INVALID_PARAMETER);

   /* make copies - so we don't mess up caller's values */
   memcpy(pHashValue, hashValue, 20);  
   memcpy(xp, p, 128);
   memcpy(xq, q, 20);
   memcpy(xg, g, 128);
   memcpy(xy, y, 128);
   memcpy(xr, r, 20);
   memcpy(xs, s, 20);

   /* have to reverse each of the arrays in groups of 4,
    */
   if (isLittleEndian())
   {
      FlipReverse(xp, 128);
      FlipReverse(xq, 20);
      FlipReverse(xg, 128);
      FlipReverse(xy, 128);
      FlipReverse(xr, 20);
      FlipReverse(xs, 20);
   }
   else
      FlipReverse(pHashValue, 20);

   reverseParms(xp, 128);
   reverseParms(xq, 20);
   reverseParms(xg, 128);
   reverseParms(xy, 128);
   reverseParms(pHashValue, 20);
   reverseParms(xr, 20);
   reverseParms(xs, 20);


   result = dss_verify((ulong *)xp,(ulong *)xq,(ulong *)xg,
      (ulong *)xy,(ulong *)pHashValue, (ulong *)xr, (ulong *)xs);

   if(result == 0)
      return(F_NO_ERROR);
   else
      return(F_SIG_NOT_VALID);   /* what to return here */



}

void reverseParms(uchar *data, ulong byteSize)
{
   ulong *cp, *end, tmp;

   cp = (ulong *)data;
   data+= byteSize;
   end = (ulong *)data;
   while(end > cp)
   {
      end--;
      tmp = *cp;
      *cp = *end;
      *end = tmp;
      cp++;
   }
}

void FlipReverse(uchar *data, ulong byteSize)
{
    ulong      i;
    ulong   tempnum, *longbuf;
    longbuf = (ulong *)data;
    byteSize /= sizeof(ulong);   /* num of longs to work on */

    for ( i = 0; i < byteSize; i++ ) {
        tempnum = (longbuf[i] << 16) | (longbuf[i] >> 16);
           longbuf[i] = ((tempnum & 0xff00ff00L) >> 8) |
                       ((tempnum & 0x00ff00ffL) << 8);
    }
}


static int sha_init(ulong hash[])
{
    hash[0]=0x67452301L;
    hash[1]=0xEFCDAB89L;
    hash[2]=0x98BADCFEL;
    hash[3]=0x10325476L;
    hash[4]=0xC3D2E1F0L;

    return( F_NO_ERROR );
} /* sha_init */


static int sha_hash(ulong M[],ulong hash[] )
{
    ulong   temp;
    ulong   newa, newb, newc, newd, newe;
    ulong   W0,  W1,  W2,  W3,  W4,  W5,  W6,  W7;
    ulong   W8,  W9,  W10, W11, W12, W13, W14, W15;
    ulong   W16, W17, W18, W19, W20, W21, W22, W23;
    ulong   W24, W25, W26, W27, W28, W29, W30, W31;
    ulong   W32, W33, W34, W35, W36, W37, W38, W39;
    ulong   W40, W41, W42, W43, W44, W45, W46, W47;
    ulong   W48, W49, W50, W51, W52, W53, W54, W55;
    ulong   W56, W57, W58, W59, W60, W61, W62, W63;
    ulong   W64, W65, W66, W67, W68, W69, W70, W71;
    ulong   W72, W73, W74, W75, W76, W77, W78, W79;


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

    newa=hash[0]; newb=hash[1]; newc=hash[2]; newd=hash[3]; newe=hash[4];

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W0+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W1+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W2+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W3+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W4+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W5+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W6+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W7+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W8+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W9+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W10+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W11+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W12+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W13+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W14+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W15+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W16+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W17+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W18+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F0(newb,newc,newd)+newe+W19+K1;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W20+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W21+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W22+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W23+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W24+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W25+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W26+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W27+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W28+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W29+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W30+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W31+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W32+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W33+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W34+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W35+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W36+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W37+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W38+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W39+K2;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W40+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W41+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W42+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W43+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W44+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W45+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W46+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W47+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W48+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W49+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W50+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W51+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W52+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W53+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W54+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W55+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W56+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W57+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W58+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F1(newb,newc,newd)+newe+W59+K3;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W60+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W61+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W62+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W63+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W64+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W65+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W66+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W67+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W68+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W69+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W70+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W71+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W72+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W73+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W74+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W75+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W76+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W77+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W78+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;    newa = temp;

    temp = Ls5(newa)+F2(newb,newc,newd)+newe+W79+K4;
    newe = newd;    newd = newc;
    newc = Ls30(newb);
    newb = newa;

    hash[0] += temp;
    hash[1] += newb;
    hash[2] += newc;
    hash[3] += newd;
    hash[4] += newe;

    return( F_NO_ERROR );
} /* sha_hash */


int HashBuffer(uchar *pData,ulong DataSize,ulong *hash )
{
    int      i = 0;
    ulong   tempnum = 0;
    int      leftovers;
    int      blocksred = 0;
    ulong   arrayindex = 0;
    int      status;

    /* union for reading in bytes and hashing in 32 bit blocks */
    union {
        char   lets[BLOCK];
        ulong   nums[L_BLOCK];
    } buff;


    /* Hash data in groups of 64 bytes */
    status = sha_init( hash );
    if ( status != F_NO_ERROR ) {
       return( status );
    }
    while ((arrayindex+64) <= DataSize) {
        memcpy( buff.lets, pData+(int)arrayindex, BLOCK );

      if (isLittleEndian())
      {
         /* perform little endian byte swap */
         for ( i = 0; i < 16; i++ ) {
            tempnum = (buff.nums[i] << 16) | (buff.nums[i] >> 16);
            buff.nums[i] = ((tempnum & 0xff00ff00L) >> 8) |
                        ((tempnum & 0x00ff00ffL) << 8);
         }
      }
        status = sha_hash( buff.nums, hash );
        if ( status != F_NO_ERROR ) {
            return( status );
        }
        arrayindex+=BLOCK;
        blocksred++;
    }

    /* Calculate Final Hash */
    leftovers = (int) (DataSize-arrayindex);

    memcpy(buff.lets, pData+(int)arrayindex, leftovers);
    memcpy(buff.lets+leftovers,paddata,BLOCK-leftovers);

   if (isLittleEndian())
   {
    /* perform little endian byte swap */
      for (i=0; i<16; i++) {
         tempnum = (buff.nums[i] << 16) | (buff.nums[i] >> 16);
         buff.nums[i] = ((tempnum & 0xff00ff00L) >> 8) |
                     ((tempnum & 0x00ff00ffL) << 8);
      }
   }

    if (leftovers >= 56) {
        status = sha_hash( buff. nums, hash );
       if ( status != F_NO_ERROR ) {
          return( status );
       }
        memset(buff.nums, 0, 16*sizeof(long)); /* Clear out nums for last pass */
    }

    buff.nums[15] = (512*blocksred)+(8*leftovers);

    status = sha_hash( buff.nums, hash );
    return( status );
}



short dss_verify(ulong p[],ulong q[],ulong g[],ulong y[],ulong hash[],ulong r[],ulong s[])
{
    ulong w[5],qminus2[5], tempa[32];
    ulong u1[5],u2[5],v[5];
    ulong bigR[65], smallR[11], Rmodp[32], Rmodq[5];
    ulong ONE[65],pinv, qinv;
    ulong result;
    int i;

    SNACC::threadLock();       //RWC; Locked to avoid "static" variable issues.

    /********* Initialize ONE ******************************************/
    memset( ONE, 0, sizeof( ONE ) );
    ONE[0] = 0x00000001L;

    /********* Big R is defined to be ((2^32)^32)^2 or 2^2048***********/
    memset( bigR, 0, sizeof( bigR ) );
    bigR[64] = 0x00000001L;

    /********* Small R is defined to be ((2^5)^5)^2 or 2^50***********/
    memset( smallR, 0, sizeof( smallR ) );
    smallR[10] = 0x00000001L;

    /********* This reduces BigR mod p and mod q for Montgomery ******/
    reduce_p(bigR, 65, p, Rmodp);
    reduce_q(smallR, 11, q, Rmodq);

    /**** Calculate the negative inverses of p and q mod r.***********/
    pinv = neg_Inverse(p);
    qinv = neg_Inverse(q);

    /*****Start the DSS Verification process********************/
    /* Create q - 2 */
   memset( qminus2, 0xff, sizeof( qminus2 ) );
    qminus2[0] = 0xfffffffeL;
    mpsub(qminus2,q,qminus2,(int)5);

    /* w = s^(q-2) mod q */
    QExpo(w,s,qminus2,q,qinv,Rmodq,(int)5);

    /* Create u1 = hash*w mod q */
    mpmult(u1,hash,w,q,qinv,Rmodq,(int)5,ONE);

    /* Create u2 = r*w mod q */
    mpmult(u2,r,w,q,qinv,Rmodq,(int)5,ONE);

    /* tempa = (g^u1*y^u2)mod p */
    DualExpo(tempa,g,u1,y,u2,p,pinv,Rmodp,(int)5);

    reduce_q(tempa,32,q,v);  /* v = tempa mod q */

    result = 0;
    for(i=0;i<5;i++) {
        result |= (v[i]^r[i]);
    };

    SNACC::threadUnlock();       //RWC; Locked to avoid "static" variable issues.

    return( (short)result );
}   /* end DSS_VERIFY */

void reduce_p(ulong a[], int alen, ulong  p[], ulong  array[] )
{
  register int i,j,k,m,aptr,carry;
  ulong lastbit,tmp[32];

  for(i=0;i<32;i++) /* tmp = -p */
    tmp[i] = ~p[i];
  carry = 1;
  for(i=0;i<32;i++)
    {
    tmp[i] += carry;
    if (tmp[i] < (unsigned int)carry)
       carry = 1;
    else
       carry = 0;
    }


  for(i=0;i<32;i++)
    array[i] = a[alen-32+i];
  aptr = alen-33;
  lastbit = 0;

  for(k=0;k<(alen-32);k++)
    {
      for(i=0;i<32;i++)
    {
      if(lastbit)
        {
          mpsub(array,tmp,array,32);
          lastbit = 0;
        }
      else
        {
        for(j=31;j>=0;j--)
            if(array[j]!=p[j])
                break;

        if(array[j]>p[j])
            mpsub(array,tmp,array,32);
        }

      lastbit = (array[31]>>31);
      for(m=31;m>0;m--)
            array[m] = (array[m]<<1)^(array[m-1]>>31);
      array[0] = (array[0]<<1)^(a[aptr]>>31);
      a[aptr]<<=1;
    }
      aptr--;
    }
  if(lastbit)
    mpsub(array,tmp,array,32);
  else
    {
    for(j=31;j>=0;j--)
        if(array[j]!=p[j])
            break;

    if(array[j]>p[j])
        mpsub(array,tmp,array,32);
    }

} /* reduce_p */

void reduce_q(ulong  a[],int alen,ulong q[],ulong array[] )
{
  register int i,j,k,aptr,carry;
  ulong lastbit,tmp[5];

  for(i=0;i<5;i++) /* tmp = -q */
    tmp[i] = ~q[i];
  carry = 1;
  for(i=0;i<5;i++)
    {
    tmp[i] += carry;
    if (tmp[i] < (unsigned int)carry)
       carry = 1;
    else
       carry = 0;
    }


  for(i=0;i<5;i++)
    array[i] = a[alen-5+i];
  aptr = alen-6;
  lastbit = 0;

  for(k=0;k<(alen-5);k++)
    {
      for(i=0;i<32;i++)
    {
      if(lastbit)
        {
          mpsub(array,tmp,array,5);
          lastbit = 0;
        }
      else
        {
        for(j=4;j>=0;j--)
            if(array[j]!=q[j])
                break;

        if(array[j]>q[j])
            mpsub(array,tmp,array,5);
        }

      lastbit = (array[4]>>31);
      array[4] = (array[4]<<1)^(array[3]>>31);
      array[3] = (array[3]<<1)^(array[2]>>31);
      array[2] = (array[2]<<1)^(array[1]>>31);
      array[1] = (array[1]<<1)^(array[0]>>31);
      array[0] = (array[0]<<1)^(a[aptr]>>31);
      a[aptr]<<=1;
    }
      aptr--;
    }
  if(lastbit)
    mpsub(array,tmp,array,5);
  else
    {
    for(j=4;j>=0;j--)
        if(array[j]!=q[j])
            break;

    if(array[j]>q[j])
        mpsub(array,tmp,array,5);
    }

} /* reduce_q */

ulong neg_Inverse(ulong in[] )
{
  int i;
  ulong u,v,y;

  u = in[0]+0xFFFFFFFFL;
  v = -((long)u);
  y = 1 + v;

  for(i=0;i<5;i++)
    {
      u *= u;
      v = u + 1;
      y *= v;
    };

  return((~y) + (ulong)1);

} /* neg_Inverse  */

void mpsub(ulong a[],ulong b[],ulong c[],int num )
{
  register int i;
  register ulong carry, temp;

  carry = 0;
  for(i=0;i<num;i++)
  {
      temp = b[i] + carry;
      c[i] = a[i] + temp;
      if ((temp < b[i]) | (c[i] < temp))
         carry = 1;
      else
         carry = 0;
  }
} /* mpsub */


void QExpo(ulong temp[],ulong base[],ulong e[],ulong m[],ulong minv,ulong rval[],int esize )
{
    register int i,j,k;
    static unsigned int b[16][10];
    static unsigned int ebits[160];
    static int          bsize;
    static unsigned int n16[10],ans[10],inv16;
    static unsigned int one1[65];

    register int ri,rj;


  memset((char *)one1,0,sizeof(one1));
  one1[0] = (unsigned int)1;

  for(rj=0,ri=0;ri<5;ri++,rj+=2) {
     n16[rj] = (unsigned int)(m[ri]&0xffff);
     n16[rj+1] = (unsigned int)(m[ri]>>16);
     ans[rj] = (unsigned int)(rval[ri]&0xffff); /* Temp for Montgomery R */
     ans[rj+1] = (unsigned int)(rval[ri]>>16);
     b[1][rj] = (unsigned int)(base[ri]&0xffff);  /* Q */
     b[1][rj+1] = (unsigned int)(base[ri]>>16);
  }

  inv16 = (unsigned int)(minv&0xffff);
  bsize = 10;

  /* Q */
  Mult16(b[1],ans,n16,inv16,bsize,b[1]);

  /* Q^2 */
  QSquare16(b[1],b[1],n16,inv16,bsize,b[2]);

  /* Q^3 */
  Mult16(b[1],b[2],n16,inv16,bsize,b[3]);

  /* Q^4 */
  QSquare16(b[2],b[2],n16,inv16,bsize,b[4]);

  /* Q^5 */
  Mult16(b[1],b[4],n16,inv16,bsize,b[5]);

  /* Q^6 */
  Mult16(b[2],b[4],n16,inv16,bsize,b[6]);

  /* Q^7 */
  Mult16(b[3],b[4],n16,inv16,bsize,b[7]);

  /* Q^8 */
  QSquare16(b[4],b[4],n16,inv16,bsize,b[8]);

  /* Q^9 */
  Mult16(b[1],b[8],n16,inv16,bsize,b[9]);

  /* Q^10 */
  Mult16(b[2],b[8],n16,inv16,bsize,b[10]);

   /* Q^11 */
  Mult16(b[3],b[8],n16,inv16,bsize,b[11]);

   /* Q^12 */
  Mult16(b[4],b[8],n16,inv16,bsize,b[12]);

   /* Q^13 */
  Mult16(b[5],b[8],n16,inv16,bsize,b[13]);

   /* Q^14 */
  Mult16(b[6],b[8],n16,inv16,bsize,b[14]);

   /* Q^15 */
  Mult16(b[7],b[8],n16,inv16,bsize,b[15]);

  for(k=159,i=esize-1;i>=0;i--) {
    for(j=0;j<32;j++) {
      ebits[k] = (unsigned int)((e[i]>>(31-j))&1);
      k--;
    }
  }

  k=159;
  while(ebits[k]==0) {
    k--;
  }
  i=(ebits[k]<<3)^(ebits[k-1]<<2)^(ebits[k-2]<<1)^ebits[k-3];
  for(j=0;j<bsize;j++) {
    ans[j] = b[i][j];
  }
  k-=4;
  while (k > 2) {
    if(ebits[k]==0) {
      QSquare16(ans,ans,n16,inv16,bsize,ans);
      k--;
    }
    else {
      QSquare16(ans,ans,n16,inv16,bsize,ans);
      QSquare16(ans,ans,n16,inv16,bsize,ans);
      QSquare16(ans,ans,n16,inv16,bsize,ans);
      QSquare16(ans,ans,n16,inv16,bsize,ans);
      i=(ebits[k]<<3)^(ebits[k-1]<<2)^(ebits[k-2]<<1)^ebits[k-3];
      Mult16(ans,b[i],n16,inv16,bsize,ans);
      k-=4;
    }
  }

  if (k == 2) {
      QSquare16(ans,ans,n16,inv16,bsize,ans);
      QSquare16(ans,ans,n16,inv16,bsize,ans);
      QSquare16(ans,ans,n16,inv16,bsize,ans);
      i=(ebits[k]<<2)^(ebits[k-1]<<1)^ebits[k-2];
      if (i > 0) {
        Mult16(ans,b[i],n16,inv16,bsize,ans);
      }
  }
  else if (k == 1) {
    QSquare16(ans,ans,n16,inv16,bsize,ans);
    QSquare16(ans,ans,n16,inv16,bsize,ans);
    i=(ebits[k]<<1)^ebits[k-1];
    if (i > 0) {
      Mult16(ans,b[i],n16,inv16,bsize,ans);
    }
  }
  else if (k == 0) {
    QSquare16(ans,ans,n16,inv16,bsize,ans);
    i=ebits[k];
    if (i > 0) {
      Mult16(ans,b[i],n16,inv16,bsize,ans);
    }
  }

  /* Place answer back into Montgomery Form */
  Mult16(ans,one1,n16,inv16,bsize,ans);

  for(i=0;i<5;i++) {
    temp[i] = (ans[(i<<1)])^(((ulong)ans[(i<<1)+1])<<16);
  }
} /* QExpo */

void mpmult(ulong  ans[],ulong  a[],ulong  b[],ulong  m[], ulong  minv,ulong  rval[],int bsize, ulong  ONE[] )
{
  ulong temp[32];

  /* Put A In Montgomery Form */
  montMult(a,rval,m,minv,bsize,ans);

  /* Put B In Montgomery Form */
  montMult(b,rval,m,minv,bsize,temp);

  /* Multiply a and b */
  montMult(ans,temp,m,minv,bsize,ans);

  /* Place answer back into normal form */
  montMult(ans,ONE,m,minv,bsize,ans);

}

void DualExpo(ulong temp[],ulong b1[],ulong e1[],ulong b2[],ulong e2[],ulong m[],ulong minv,ulong rval[],int esize )
{
  register int i,j,k;
  register int ri,rj;
  static unsigned int b[16][64];
  static int e1bits[160],e2bits[160],eorr[160],bsize;
  static unsigned int n16[64],ans[64],inv16;
  static unsigned int one1[65];


  memset((char *)one1,0, sizeof(one1));
  one1[0] = (unsigned int)1;

  for(rj=0,ri=0;ri<32;ri++,rj+=2)
    {
     n16[rj] = (unsigned int)(m[ri]&0xffff);
     n16[rj+1] = (unsigned int)(m[ri]>>16);
     ans[rj] = (unsigned int)(rval[ri]&0xffff); /* Temp for Montgomery R */
     ans[rj+1] = (unsigned int)(rval[ri]>>16);
     b[4][rj] = (unsigned int)(b1[ri]&0xffff);  /* G */
     b[4][rj+1] = (unsigned int)(b1[ri]>>16);
     b[1][rj] = (unsigned int)(b2[ri]&0xffff);  /* Y */
     b[1][rj+1] = (unsigned int)(b2[ri]>>16);
    }

  inv16 = (unsigned int)(minv&0xffff);
  bsize = 64;

  /* G */
  Mult16(b[4],ans,n16,inv16,bsize,b[4]);

  /* G^2 */
  Square16(b[4],b[4],n16,inv16,bsize,b[8]);

  /* G^3 */
  Mult16(b[8],b[4],n16,inv16,bsize,b[12]);

  /* Y */
  Mult16(b[1],ans,n16,inv16,bsize,b[1]);

  /* Y^2 */
  Square16(b[1],b[1],n16,inv16,bsize,b[2]);

  /* Y^3 */
  Mult16(b[2],b[1],n16,inv16,bsize,b[3]);

  /* G*Y */
  Mult16(b[4],b[1],n16,inv16,bsize,b[5]);

  /* G * Y^2 */
  Mult16(b[4],b[2],n16,inv16,bsize,b[6]);

  /* G * Y^3 */
  Mult16(b[4],b[3],n16,inv16,bsize,b[7]);

  /* G^2 * Y */
  Mult16(b[8],b[1],n16,inv16,bsize,b[9]);

  /* G^2 * Y^2 */
  Mult16(b[8],b[2],n16,inv16,bsize,b[10]);

  /* G^2 * Y^3 */
  Mult16(b[8],b[3],n16,inv16,bsize,b[11]);

  /* G^3 * Y */
  Mult16(b[12],b[1],n16,inv16,bsize,b[13]);

  /* G^3 * Y^2 */
  Mult16(b[12],b[2],n16,inv16,bsize,b[14]);

  /* G^3 * Y^3 */
  Mult16(b[12],b[3],n16,inv16,bsize,b[15]);

  for(k=159,i=esize-1;i>=0;i--)
    for(j=0;j<32;j++)
      {
    e1bits[k] = (unsigned int)((e1[i]>>(31-j))&1);
    e2bits[k] = (unsigned int)((e2[i]>>(31-j))&1);
    eorr[k] = e1bits[k]|e2bits[k];
    k--;
      }

  k=159;
  while(eorr[k]==0)
    k--;
  i=(e1bits[k]<<3)^(e1bits[k-1]<<2)^(e2bits[k]<<1)^(e2bits[k-1]);
  for(j=0;j<bsize;j++)
    ans[j] = b[i][j];
  k-=2;
  do {
    if(eorr[k]==0)
    {
      Square16(ans,ans,n16,inv16,bsize,ans);
      k--;
    }
        else if(k>=(int)1)
        {
         Square16(ans,ans,n16,inv16,bsize,ans);
         Square16(ans,ans,n16,inv16,bsize,ans);
         i=(e1bits[k]<<3)^(e1bits[k-1]<<2)^(e2bits[k]<<1)^(e2bits[k-1]);
         Mult16(ans,b[i],n16,inv16,bsize,ans);
         k-=2;
        }
        else
        {
     i=(e1bits[k]<<2)^(e2bits[k]);
     Square16(ans,ans,n16,inv16,bsize,ans);
     Mult16(ans,b[i],n16,inv16,bsize,ans);
     k--;
    }
    }while(k>=(int)(0));

  /* Place answer back into Montgomery Form */
  Mult16(ans,one1,n16,inv16,bsize,ans);

  for(i=0;i<32;i++)
    temp[i] = (ans[(i<<1)])^(((ulong)ans[(i<<1)+1])<<16);
} /* DualExpo */

void Mult16(unsigned int a[],unsigned int b[],unsigned int n[],unsigned int nInv,int maxSegs,unsigned int c[] )
{
  static unsigned int stored_m[65],tmp_res[66];
  register ulong tmp,accl,acch;
  ulong carry,tmp1,tmp2;
  register int i,j,res;

  accl = acch = 0;

  memset((char *)tmp_res,0,sizeof(tmp_res));

  for(i=0;i<maxSegs;++i)
    {
     for (j=0;j<i;++j)
        {
        tmp = (ulong)((ulong)a[j]*(ulong)b[i-j]);
        accl += tmp;
        if(accl<tmp)
           acch++;
        tmp = (ulong)((ulong)stored_m[j]*(ulong)n[i-j]);
        accl += tmp;
        if(accl<tmp)
           acch++;
        } /* end for j */
     tmp = (ulong)((ulong)a[i]*(ulong)b[0]);
     accl += tmp;
     if(accl<tmp)
        acch++;
     /** compute the stored m value **/
     stored_m[i] = (unsigned int)(((ulong)accl*(ulong)nInv)&0xffff);

     tmp = (ulong)((ulong)stored_m[i]*(ulong)n[0]);
     accl += tmp;
     if(accl<tmp)
        acch++;

     /** shift accumulator - 0th word should be 0 **/
     accl = (acch<<16)^(accl>>16);
     acch = 0;

    }/* end for i */

  tmp_res[0] = (unsigned int)(accl&0xffff);
  tmp_res[1] = (unsigned int)(accl>>16);

    for (res=0,i= maxSegs;i<(maxSegs<<1);++i,res++) {
        for (j = i- maxSegs+1;j< maxSegs;++j) {
            tmp = (ulong)((ulong)a[j]*(ulong)b[i-j]);
            accl += tmp;
            if(accl<tmp) {
                acch++;
            }
            tmp = (ulong)((ulong)stored_m[j]*(ulong)n[i-j]);
            accl += tmp;
            if(accl<tmp) {
                acch++;
            }
        }/* end for j */

        tmp_res[res] = (unsigned int)(accl&0xffff);
        tmp_res[res+1] = (unsigned int)(accl>>16);
        tmp_res[res+2] = (unsigned int)acch;
        accl = (acch<<16)^(accl>>16);
        acch = 0;
    }  /* end for i */

  if(!tmp_res[maxSegs])
     for(i=maxSegs-1;i>=0;i--)
       if(tmp_res[i]!=n[i])
         break;

  if(tmp_res[maxSegs]||(tmp_res[i]>n[i]))
     {
      carry = 0;
      for (i=0;i<maxSegs;i++)
        {
         tmp1 = (ulong)tmp_res[i];
         tmp2 = (ulong)n[i];
         carry += tmp1-tmp2;
         c[i] = (unsigned int)(carry & 0xffff);
         if (carry & 0xffff0000L) carry = NEG_ONE;
         else carry = 0;
        }
      }
  else
    for(i=0;i<maxSegs;i++)
        c[i] = tmp_res[i];
} /* Mult16 */


void QSquare16(unsigned int a[],unsigned int b[],unsigned int n[],unsigned int nInv,int maxSegs,unsigned int c[] )
{
  unsigned int stored_m[11],tmp_res[12];
  register ulong accl,acch,tmp;
  register ulong taccl,tacch;
  ulong carry,tmp1,tmp2;
  register int i,j,k,res;

  memset((char *)tmp_res,0,sizeof(tmp_res));

  accl = acch = 0;

  for(i=0;i<maxSegs;++i)
    {
      if(i==0)
       {
         tmp = (ulong)a[0]*(ulong)b[0];
         accl = tmp;
       }
      else if(i&1)
       {
         j=0;
         k = (i+1)>>1;
         taccl=tacch=0;
         do{
            tmp = (ulong)a[j]*(ulong)b[i-j];
            taccl += tmp;
            if(taccl<tmp)
              tacch++;
            j++;
         }while(j < k);

         accl+=taccl;
         if(accl<taccl)
           acch++;
         accl+=taccl;
         if(accl<taccl)
           acch++;
         acch += (tacch<<1);
       }/* end elseif */
      else
       {
         j=0;
         k = i>>1;
         tacch = taccl = 0;
         do{
           tmp = (ulong)a[j]*(ulong)b[i-j];
           taccl += tmp;
           if(taccl<tmp)
              tacch++;
           j++;
         }while(j < k);

       accl += taccl;
       if(accl<taccl)
          acch++;
       accl += taccl;
       if(accl<taccl)
          acch++;
       acch += (tacch<<1);

       tmp = (ulong)a[k]*(ulong)a[k];
       accl += tmp;
       if(accl<tmp)
          acch++;
       } /* end else */

     for (j=0;j<i;++j)
        {
          tmp = (ulong)stored_m[j]*(ulong)n[i-j];
          accl += tmp;
          if(accl<tmp)
            acch++;
        }
     /** compute the stored m value **/
     stored_m[i] = (unsigned int)(((ulong)accl*(ulong)nInv)&0xffff);

     tmp = (ulong)((ulong)stored_m[i]*(ulong)n[0]);
     accl += tmp;
     if(accl<tmp)
        acch++;

     /** shift accumulator - 0th word should be 0 **/
     accl = (acch<<16)^(accl>>16);
     acch = 0;

    }/* end for i */


  tmp_res[0] = (unsigned int)(accl&0xffff);
  tmp_res[1] = (unsigned int)(accl>>16);

     for (res=0,i=maxSegs;i<19;++i)
      {
       if(i==19)
        {
         tmp = (ulong)a[9]*(ulong)b[9];
         accl += tmp;
         if(accl<tmp)
           acch++;
        }
       else if(i&1)
        {
         k = i-maxSegs+1;
         taccl=tacch=0;
         for (j = i-9;j<10;j+=2)
          {
           tmp = (ulong)a[k]*(ulong)b[i-k];
           taccl += tmp;
           if(taccl<tmp)
             tacch++;
           k++;
          }
         accl += taccl;
         if(accl<taccl)
            acch++;
         accl += taccl;
         if(accl<taccl)
            acch++;
         acch += (tacch<<1);
        }/* end elseif */
       else
        {
         taccl=tacch=0;
         k = i-maxSegs+1;
         for (j = i-9;j<9;j+=2)
          {
           tmp = (ulong)a[k]*(ulong)b[i-k];
           taccl += tmp;
           if(taccl<tmp)
             tacch++;
           k++;
          }
         accl += taccl;
         if(accl<taccl)
            acch++;
         accl += taccl;
         if(accl<taccl)
            acch++;
         acch += (tacch<<1);

         tmp = (ulong)a[k]*(ulong)b[k];
         accl += tmp;
         if(accl<tmp)
          acch++;
        }/* end else */

       for (j = i-9;j<10;++j)
         {
          tmp = (ulong)stored_m[j]*(ulong)n[i-j];
          accl += tmp;
          if(accl<tmp)
           acch++;
         }/* end for j */

      tmp_res[res] = (unsigned int)(accl&0xffff);
      tmp_res[res+1] = (unsigned int)(accl>>16);
      tmp_res[res+2] = (unsigned int)(acch&0xffff);
      res++;
      accl = (acch<<16)^(accl>>16);
      acch = 0;
      }/* end for i */

   if(!tmp_res[maxSegs])
   {
    for(i=maxSegs-1;i>=0;i--)
     {
       if(tmp_res[i]!=n[i])
          break;
     } /* end for */
    }/* end if */

  if(tmp_res[maxSegs]||(tmp_res[i]>n[i]))
    {
      carry = 0;
      for (i=0;i<maxSegs;i++)
        {
         tmp1 = (ulong)tmp_res[i];
         tmp2 = (ulong)n[i];
         carry += tmp1-tmp2;
         c[i] = (unsigned int)(carry & 0xffff);
         if (carry & 0xffff0000L) carry = NEG_ONE;
         else carry = 0;
        }/* end for i */
    } /* end if */
  else
    {
    for(i=0;i<maxSegs;i++)
        c[i] = tmp_res[i];

    }/* end else */

} /* QSquare16 */

void montMult(ulong a[],ulong b[],ulong n[],ulong nInv,int maxSegs,ulong c[] )
{
    ulong stored_m[33],tmp_res[34];
    ulong negmod[32];
    register int i,j;
    register ulong *res;
    register ulong ca,cb,pa,pb,carry,tmp;


    memset( (char *)tmp_res, 0, sizeof( tmp_res ) );

    for( i = 0; i < maxSegs; ++i ) {
        for ( j = 0; j < i; ++j ) {
            mult32(a[j],b[i-j],tmp_res);
        }
        for ( j = 0; j < i; ++j ) {
            mult32(stored_m[j],n[i-j],tmp_res);
        }

        mult32(a[i],b[0],tmp_res);

        /** compute the stored m value **/
        stored_m[i] = tmp_res[0]*nInv;

        mult32(stored_m[i],n[0],tmp_res);

        /** shift accumulator - 0th word should be 0 **/
        tmp_res[0] = tmp_res[1];
        tmp_res[1] = tmp_res[2];
        tmp_res[2] = 0;

    }/* end for i */

    res = tmp_res;
    for ( i = maxSegs; i< (maxSegs << 1 ); ++i, ++res ) {
        for ( j = i - maxSegs + 1; j < maxSegs; ++j ) {
            mult32(a[j],b[i-j],res);
        }
        for ( j = i - maxSegs + 1; j < maxSegs; ++j ) {
            mult32(stored_m[j],n[i-j],res);
        }
    }

    if(!tmp_res[maxSegs]) {
        for( i = maxSegs - 1; i >= 0; i-- ) {
            if(tmp_res[i]!=n[i]) {
                break;
            }
        }
    }

    if((tmp_res[maxSegs]) || (tmp_res[i] > n[i])) {
        for ( i = 0; i < maxSegs; i++) {
            negmod[i] = ~(n[i]);
        }
        negmod[0]++;
        carry = 0;
        for ( i = 0; i < maxSegs; i++ ) {
            ca = (tmp_res[i] & 0x80000000L);
            cb = (negmod[i] & 0x80000000L);
            pa = tmp_res[i] & 0x7fffffffL;
            pb = negmod[i] & 0x7fffffffL;
            c[i] = pa + pb + carry;
            tmp = c[i] >> 31;
            c[i] = c[i] ^ ca ^ cb;
            ca >>= 31;
            cb >>= 31;
            carry = (ca + cb + tmp) >> 1;
        }
    }
    else {
        for( i = 0; i < maxSegs; i++ ) {
            c[i] = tmp_res[i];
        }
    }
} /* montMult */


void Square16( unsigned int a[],unsigned int b[],unsigned int n[],unsigned int nInv,int maxSegs,unsigned int c[] )
{
  unsigned int stored_m[65],tmp_res[66];
  register ulong accl,acch,tmp;
  ulong taccl,tacch;
  register int i,j,k,res;
  register ulong carry,tmp1,tmp2;

  memset((char *)tmp_res,0,sizeof(tmp_res));

  accl = acch = 0;

  for(i=0;i<maxSegs;++i)
    {
      if (i==0)
       {
         tmp = (ulong)a[0]*(ulong)b[0];
         accl = tmp;
       }
      else if(i&1)
      {
       j=0;
       k = (i+1)>>1;
       taccl=tacch=0;
       do{
          tmp = (ulong)a[j]*(ulong)b[i-j];
          taccl += tmp;
          if(taccl<tmp)
            tacch++;
          j++;
         }while(j < k);
       accl+=taccl;
       if(accl<taccl)
          acch++;
       accl+=taccl;
       if(accl<taccl)
          acch++;
       acch += (tacch<<1);
      }/* end elseif */
     else
      {
       j=0;
       k = i>>1;
       tacch = taccl = 0;
       do{
          tmp = (ulong)a[j]*(ulong)b[i-j];
          taccl += tmp;
          if(taccl<tmp)
             tacch++;
          j++;
         }while(j < k);

       accl += taccl;
       if(accl<taccl)
          acch++;
       accl += taccl;
       if(accl<taccl)
          acch++;
       acch += (tacch<<1);

       tmp = (ulong)a[k]*(ulong)a[k];
       accl += tmp;
       if(accl<tmp)
       acch++;
      }/* end else */

      for (j=0;j<i;++j)
        {
          tmp = (ulong)stored_m[j]*(ulong)n[i-j];
          accl += tmp;
          if(accl<tmp)
             acch++;
        }/* end for j */

      /** compute the stored m value **/
      stored_m[i] = (unsigned int)(((ulong)accl*(ulong)nInv)&0xffff);

      tmp = (ulong)((ulong)stored_m[i]*(ulong)n[0]);
      accl += tmp;
      if(accl<tmp)
         acch++;

      /** shift accumulator - 0th word should be 0 **/
      accl = (acch<<16)^(accl>>16);
      acch = 0;

    }/* end for i */
  tmp_res[0] = (unsigned int)(accl&0xffff);
  tmp_res[1] = (unsigned int)(accl>>16);

 for (res=0,i=maxSegs;i<127;++i)
  {
   if(i==127)
    {
     tmp = (ulong)a[63]*(ulong)b[63];
     accl += tmp;
     if(accl<tmp)
      acch++;
    }
   else if(i&1)
    {
     k = i-maxSegs+1;
     taccl=tacch=0;
     for (j = i-63;j<64;j+=2)
      {
       tmp = (ulong)a[k]*(ulong)b[i-k];
       taccl += tmp;
       if(taccl<tmp)
         tacch++;
       k++;
      }/* end for j */

     accl += taccl;
     if(accl<taccl)
        acch++;
     accl += taccl;
     if(accl<taccl)
     acch++;
     acch += (tacch<<1);
    }/* end elseif */
   else
    {
     taccl=tacch=0;
     k = i-maxSegs+1;
     for (j = i-63;j<63;j+=2)
      {
       tmp = (ulong)a[k]*(ulong)b[i-k];
       taccl += tmp;
       if(taccl<tmp)
         tacch++;
       k++;
      } /* end for j */

     accl += taccl;
     if(accl<taccl)
        acch++;
     accl += taccl;
     if(accl<taccl)
        acch++;
     acch += (tacch<<1);

     tmp = (ulong)a[k]*(ulong)b[k];
     accl += tmp;
     if(accl<tmp)
      acch++;
    }/* end else */

   for (j = i-63;j<64;++j)
     {
      tmp = (ulong)stored_m[j]*(ulong)n[i-j];
      accl += tmp;
      if(accl<tmp)
       acch++;
     }/* end for j*/

   tmp_res[res] = (unsigned int)(accl&0xffff);
   tmp_res[res+1] = (unsigned int)(accl>>16);
   tmp_res[res+2] = (unsigned int)(acch&0xffff);
   res++;
   accl = (acch<<16)^(accl>>16);
   acch = 0;
  }/* end for i */

   if(!tmp_res[maxSegs])
    {
    for(i=maxSegs-1;i>=0;i--)
     {
       if(tmp_res[i]!=n[i])
         break;
     }/* end for i */
    }/* end if */

   if(tmp_res[maxSegs]||(tmp_res[i]>n[i]))
    {
      carry = 0;
      for (i=0;i<maxSegs;i++)
        {
         tmp1 = (ulong)tmp_res[i];
         tmp2 = (ulong)n[i];
         carry += tmp1-tmp2;
         c[i] = (unsigned int)(carry & 0xffff);
         if (carry & 0xffff0000L) carry = NEG_ONE;
         else carry = 0;
     }/* end for i*/
    }/* end if */
   else
    {
    for(i=0;i<maxSegs;i++)
        c[i] = tmp_res[i];
    }/* end else */


} /* Square16 */

}       //END extern "C"
