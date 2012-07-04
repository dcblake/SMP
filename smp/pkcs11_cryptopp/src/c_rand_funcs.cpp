/************************ PKCS #11 Random Functions ************************
 *
 * This source file contains the following slot and token functions:
 *  + C_SeedRandom
 *  + C_GenerateRandom
 */

#include "p11cryptopp_internal.h"


CryptoPP::RandomPool gRNG;


/*
CryptoPP::RandomPool & GlobalRNG2()
{
	static bool firstTime=true;
	static CryptoPP::RandomPool randomPool;

	if (firstTime)
	{
		firstTime = false;
		
		std::string timeSeed;
		timeSeed = CryptoPP::IntToString(time(NULL));
		Bytes dth;
		Bytes hd;
		memset(&dth, 0, sizeof(Bytes));
		memset(&hd, 0, sizeof(Bytes));

		dth.data = (unsigned char *)timeSeed.data();
		dth.len = timeSeed.length();
		
		createHash(NULL, ALG_SHA_1, &dth, &hd);
		randomPool.Put((byte *)hd.data, hd.len);
	}
	return randomPool;
}
*/


/* C_SeedRandom 
 * mixes additional seed material into the token’s random number generator.
 * hSession is the session’s handle; pSeed points to the seed material; and ulSeedLen is the length
 * in bytes of the seed material.
 */
CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_BYTE_PTR       pSeed,     /* the seed material */
		CK_ULONG          ulSeedLen)  /* length of seed material */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check the seed arguments
	if ((pSeed == NULL_PTR) || (ulSeedLen == 0))
		return CKR_ARGUMENTS_BAD;

	// Find the specified session
	if (GetSessionFromHandle(hSession) == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	gRNG.Put(pSeed, ulSeedLen);
	return CKR_OK;
}


/* C_GenerateRandom
 * generates random or pseudo-random data. hSession is the session’s
 * handle; pRandomData points to the location that receives the random data; and ulRandomLen
 * is the length in bytes of the random or pseudo-random data to be generated.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_BYTE_PTR       RandomData,  /* receives the random data */
		CK_ULONG          ulRandomLen)  /* # of bytes to generate */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check the arguments
	if ((RandomData == NULL_PTR) || (ulRandomLen == 0))
		return CKR_ARGUMENTS_BAD;

	// Find the specified session
	if (GetSessionFromHandle(hSession) == NULL)
		return CKR_SESSION_HANDLE_INVALID;

	gRNG.GenerateBlock(RandomData, ulRandomLen);
	return CKR_OK;
}
