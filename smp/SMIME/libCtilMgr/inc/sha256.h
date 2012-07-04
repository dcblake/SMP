
#ifndef _SHA256_H_
#define _SHA256_H_

typedef	unsigned long	ULONG;
typedef	unsigned int	UINT;
typedef unsigned char	BYTE;

#define LITTLE_ENDIANSFL

#define SHA256_ULONGBLOCKLEN	16
#define	SHA256_BYTEBLOCKLEN		(SHA256_ULONGBLOCKLEN*4)
#define	SHA256_BLOCKLEN			(SHA256_BYTEBLOCKLEN*8)
#define	SHA256_ULONGHASHLEN		8
#define SHA256_BYTEHASHLEN		(SHA256_ULONGHASHLEN*4)
#define SHA256_HASHLEN			(SHA256_BYTEHASHLEN*8)


#define	MSBITNULONG		0x80000000
#define	LSBITNULONG		0x00000001


typedef struct {
	ULONG	Numbits;
	ULONG	MsgLen[2];
	ULONG	Mblock[SHA256_ULONGBLOCKLEN];
	ULONG	H[SHA256_ULONGHASHLEN];
} SHA256_CTX;


#define	ROT(X,Y)		((X>>Y) | (X<<(32-Y)))

#define	Ch(X, Y, Z)		((X & Y) ^ (~X & Z))
#define Maj(X, Y, Z)	((X & Y) ^ (X & Z) ^ (Y & Z))

#define	CapSigma0(X)	(ROT(X,2) ^ ROT(X,13) ^ ROT(X,22))
#define CapSigma1(X)	(ROT(X,6) ^ ROT(X,11) ^ ROT(X,25))
#define SmallSigma0(X)	(ROT(X,7) ^ ROT(X,18) ^ (X>>3))
#define SmallSigma1(X)	(ROT(X,17) ^ ROT(X,19) ^ (X>>10))

void	SHA256_ProcessBlock(SHA256_CTX *ctx);
void	byteReverse(ULONG *buffer, int byteCount);
int		SHA256_Init(SHA256_CTX *ctx);
int		SHA256_Init2(SHA256_CTX *ctx, ULONG *IH);
int		SHA256_Update(SHA256_CTX *ctx, unsigned char *buffer, int bitcount);
int		SHA256_Final(SHA256_CTX *ctx);
void	bshrULONG(ULONG *x, int len);
//RWC;5/2/01;ADDED ifdef to avoid Linux compiler error.
#ifdef WIN32
void	xor(ULONG *A, ULONG *x, ULONG *y, int len);
#endif

int SHA256_StringProcess (char *inString, int len, ULONG *result);

#endif  /*  _SHA256_H_  */
