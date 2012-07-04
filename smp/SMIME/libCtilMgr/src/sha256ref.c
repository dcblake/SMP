
#include <stdio.h>
#include <string.h>
#include "sha256.h"

//#define	DEBUG_SHA256

ULONG	K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};


void SHA256_ProcessBlock(SHA256_CTX *ctx)
{
	int		j;
	ULONG	T1, T2, a, b, c, d, e, f, g, h;
	ULONG	W[16];

	for (j=0; j<16; j++)
		W[j] = ctx->Mblock[j];

	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];
	f = ctx->H[5];
	g = ctx->H[6];
	h = ctx->H[7];
#ifdef DEBUG_SHA256
printf("init:    \t%0lx  %0lx  %0lx  %0lx\n", a, b, c, d);
printf("         \t%0lx  %0lx  %0lx  %0lx\n", e, f, g, h);
#endif

	/*  Changed the following from "j<64" to "j<4" for testing purposes */
	for (j=0; j<64; j++) {
		if ( j > 15 )
			W[j%16] += SmallSigma1(W[(j-2)%16]) + W[(j-7)%16] + SmallSigma0(W[(j-15)%16]);
		T1 = h + CapSigma1(e) + Ch(e,f,g) + K[j] + W[j%16];
#ifdef DEBUG_SHA256_2
printf("CapSigma1(e) is <%0lx>\n", CapSigma1(e));
printf("Ch(e,f,g) is <%0lx>\n", Ch(e,f,g));
printf("K[%d] is <%0lx>\n", j, K[j]);
printf("W[%d] is <%0lx>\n", j, W[j%16]);
printf("T1 is <%0lx>\n", T1);
#endif
		T2 = CapSigma0(a) + Maj(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
#ifdef DEBUG_SHA256
printf("t = %02d\t%08lx  %08lx  %08lx  %08lx", j, a, b, c, d);
printf("  %08lx  %08lx  %08lx  %08lx\n", e, f, g, h);
#endif
		}
	ctx->H[0] += a;
	ctx->H[1] += b;
	ctx->H[2] += c;
	ctx->H[3] += d;
	ctx->H[4] += e;
	ctx->H[5] += f;
	ctx->H[6] += g;
	ctx->H[7] += h;
	}

/**********************************************************************/
/*  Performs byte reverse for PC based implementation (little endian) */
/*     len in ULONGs                                                  */
/**********************************************************************/

void byteReverse(ULONG *buffer, int len)
{
	ULONG	value;
	int		count;

	for( count = 0; count < len; count++ ) {
		value = ( buffer[ count ] << 16 ) | ( buffer[ count ] >> 16 );
		buffer[ count ] = ( ( value & 0xFF00FF00L ) >> 8 ) | ( ( value & 0x00FF00FFL ) << 8 );
		}
	}

/**********************************************************************/
/*	 SHA256_Init initialization routine.                              */
/*		Clears all fields in the SHA Context structure and primes the */
/*		hash with the initialization vector.                          */
/**********************************************************************/

int SHA256_Init(SHA256_CTX *ctx)
{
	int i;
	ULONG IH[SHA256_ULONGHASHLEN] = {
			0x6a09e667L, 0xbb67ae85L, 0x3c6ef372L, 0xa54ff53aL,
			0x510e527fL, 0x9b05688cL, 0x1f83d9abL, 0x5be0cd19L
			};

	ctx->MsgLen[0] = 0;
	ctx->MsgLen[1] = 0;
	ctx->Numbits = 0;
	for (i=0; i<SHA256_ULONGBLOCKLEN; i++)
		ctx->Mblock[i] = 0x00000000L;
	for (i=0; i<SHA256_ULONGHASHLEN ;i++)
		ctx->H[i] = IH[i];
	return 0;
	}

/**********************************************************************/
/*	 SHA256_Init2 initialization routine.                             */
/*		Clears all fields in the SHA Context structure and primes the */
/*		hash with the user supplied initialization vector.            */
/**********************************************************************/

int SHA256_Init2(SHA256_CTX *ctx, ULONG *IH)
{
	int i;

	ctx->MsgLen[0] = 0;
	ctx->MsgLen[1] = 0;
	ctx->Numbits = 0;
	for (i=0; i<SHA256_ULONGBLOCKLEN; i++)
		ctx->Mblock[i] = (ULONG) 0L;
	for (i=0; i<SHA256_ULONGHASHLEN ;i++)
		ctx->H[i] = IH[i];
	return 0;
	}

/**********************************************************************/
/*	 SHA256_Update hashes full 512 bit blocks. Assumes that           */
/*	 bitcount is a multiple of SHA256_BLOCKLEN until the final        */
/*	 buffer is being processed. In this case, the data has            */
/*	 less than 512 bits then it saves the data for a                  */
/*	 subsequent call to SHA256_Final.                                 */
/**********************************************************************/
int SHA256_Update(SHA256_CTX *ctx, unsigned char *buffer, int bitcount)
{
	int		offsetBytes, offsetBits;
  	BYTE	tbuf[SHA256_BYTEBLOCKLEN+1];

	while ( (bitcount+ctx->Numbits) >= SHA256_BLOCKLEN ) {
	   	offsetBytes = ctx->Numbits / 8;
   		offsetBits = ctx->Numbits % 8;

		/* increment Message Length counter  */
		if ( (ctx->MsgLen[1] + 512) < ctx->MsgLen[1] )
			ctx->MsgLen[0]++;
		ctx->MsgLen[1] += 512;

		/* Process full block now */
		if ( offsetBits == 0 ) {
			memcpy((BYTE *) ctx->Mblock+offsetBytes, buffer, SHA256_BYTEBLOCKLEN-offsetBytes);
			}
		else {
			BYTE	tbuf[SHA256_BYTEBLOCKLEN+4];
			int		i;

			memset(tbuf, '\0', SHA256_BYTEBLOCKLEN+4);
			memcpy(tbuf+offsetBytes, buffer, SHA256_BYTEBLOCKLEN-offsetBytes);
			for ( i=0; i<offsetBits; i++ )
				bshrULONG((ULONG *)tbuf, SHA256_ULONGBLOCKLEN+1);
			xor(ctx->Mblock, ctx->Mblock, (ULONG *)tbuf, SHA256_ULONGBLOCKLEN);
			ctx->Numbits += bitcount;
			}

#ifdef LITTLE_ENDIANSFL
byteReverse(ctx->Mblock, SHA256_ULONGBLOCKLEN);
#endif

		/* Process full block  */
		SHA256_ProcessBlock(ctx);
		if ( offsetBits != 0 ) {
			ctx->Numbits = offsetBits;
			memcpy((BYTE *) ctx->Mblock, tbuf+SHA256_BYTEBLOCKLEN, 1);
			}
		else
			ctx->Numbits = 0; 
		buffer += (SHA256_BYTEBLOCKLEN-offsetBytes);
		bitcount -= ((SHA256_BYTEBLOCKLEN-offsetBytes)*8);
		}

	/* Save partial block for subsequent invocation of SHAFinal */
	if ( bitcount )
        {
		if ( (ctx->Numbits%8) == 0 ) {
			memcpy((BYTE *) ctx->Mblock+(ctx->Numbits/8), buffer, (bitcount+7)/8);
			ctx->Numbits += bitcount;
			}
		else {
			BYTE			tbuf[SHA256_BYTEBLOCKLEN];
			unsigned int	offset, i;

			memset(tbuf, '\0', SHA256_BYTEBLOCKLEN);
			offset = ctx->Numbits/8;
			memcpy(tbuf+offset, buffer, (bitcount+7)/8);
			for ( i=0; i<ctx->Numbits%8; i++ )
				bshrULONG((ULONG *)tbuf, SHA256_ULONGBLOCKLEN);
			xor(ctx->Mblock, ctx->Mblock, (ULONG *)tbuf, SHA256_ULONGBLOCKLEN);
			ctx->Numbits += bitcount;
			}
        }

	return 0;
	}

/**********************************************************************/
/*	 SHA256_Final does the hashing of the last block of the message.  */
/*	 It is this routine that does the necessary padding of zeros      */
/*	 and sets the length of the data at the end.                      */
/**********************************************************************/
int SHA256_Final(SHA256_CTX *ctx)
{
	int     i, k, numsub;
	ULONG   numbits;
	ULONG   padbits=0x80000000L, padbits2=0xFFFFFFFFL;

	
#ifdef LITTLE_ENDIANSFL
byteReverse(ctx->Mblock, SHA256_ULONGBLOCKLEN);
#endif

	numbits=ctx->Numbits;
	numsub=(int)numbits/32;

	/* put in the "1" bit  */
	padbits >>= numbits % 32L;
	padbits2 <<= (31L - (numbits % 32L));
	ctx->Mblock[numsub] |= padbits;
	ctx->Mblock[numsub] &= padbits2;

	/* put in the zero bits  */
	for (k=numsub+1; k<SHA256_ULONGBLOCKLEN; k++)
		ctx->Mblock[k] = (ULONG)0L;

	/* If more than 447 data bits in last block, there isn't enough room for
		the 1 bit and size field.  Fill this block out with zeros and Process it.
		Then fill another block with zeros and be ready to insert the length
		field.  */
	if ( numsub > 13 ) {
		SHA256_ProcessBlock(ctx);
		for (i=0; i<14; i++) ctx->Mblock[i] = (ULONG)0L;
		}
	
	/*  Put in the length field of the data hashed.  */
	/* increment Message Length counter  */
	if ( (ctx->MsgLen[1] + numbits) < ctx->MsgLen[1] )
		ctx->MsgLen[0]++;
	ctx->MsgLen[1] += numbits;
	ctx->Mblock[14] = ctx->MsgLen[0];
	ctx->Mblock[15] = ctx->MsgLen[1];

	/*
	ctx->Mblock[14] = (ULONG)((ctx->Numblocks[0] << 9) + (ctx->Numblocks[1] >> 23));
	ctx->Mblock[15] = (ULONG)(ctx->Numblocks[1] << 9) + numbits;
	*/

	SHA256_ProcessBlock(ctx);

	return 0;
	}


/*******************************************************/
/** bshrULONG - shifts array right by one bit.         */
/**                                                    */
/** x = x / 2                                          */
/**                                                    */
/** Parameters:                                        */
/**                                                    */
/**  x      Address of array x                         */
/**  len    Length array x in ULONGs                   */
/*******************************************************/
void bshrULONG(ULONG *x, int len)
{
	ULONG	*p;
	int		c1,c2;

	p = x;
	c1 = 0;
	c2 = 0;
	while (p != x+len-1) {
		if (*p & (ULONG)LSBITNULONG)
			c2 = 1;
		*p >>= 1;  /* shift the word right once (ms bit = 0) */
		if (c1)
			*p |= (ULONG)MSBITNULONG;
		c1 = c2;
		c2 = 0;
		p++;
		}
	*p >>= 1;  /* shift the word right once (ms bit = 0) */
	if (c1)
		*p |= (ULONG)MSBITNULONG;
	}


/******************************************/
/** xor - xor one array into another      */
/**                                       */
/** Parameters:                           */
/**                                       */
/**  A      Address of the result         */
/**  x      Address of array x            */
/**  y      Address of array y            */
/**  len    Amount of ULONGs to copy      */
/******************************************/
void xor(ULONG *A, ULONG *x, ULONG *y, int len)
{
	while (len--)
		A[len] = x[len] ^ y[len];
	}


int SHA256_StringProcess (char *inString, int len, ULONG *result)
{
	SHA256_CTX		ctx;
	int				i;

	SHA256_Init (&ctx);
	SHA256_Update (&ctx, (unsigned char *)inString, len*8);
	SHA256_Final (&ctx);
	for (i=0;i<SHA256_ULONGHASHLEN;i++)
		result[i] = ctx.H[i];
	/* zeroize for security */
	memset(&ctx, (char)0, sizeof(ctx));
	return 0;
}

