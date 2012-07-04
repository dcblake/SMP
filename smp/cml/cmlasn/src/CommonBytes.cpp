/*****************************************************************************
File:     CommonBytes.cpp
Project:  Certificate Management ASN.1 Library
Contents: Implementation of the CommonBytes class and the CM_HashData
          function.

Created:  20 March 2001
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:	17 March 2004

Version:  2.4

*****************************************************************************/

////////////////////
// Included Files //
////////////////////
#ifdef _MSC_VER
	#pragma warning(disable: 4710)	// Disable function not inlined warning
	#pragma warning(push, 3)		// Save and set warning level to 3
	#include <fstream>				// Needed for ifstream
	#pragma warning(pop)			// Restore warning level
#else
	#include <fstream>				// Needed for ifstream
#endif
#include <sys/types.h>				// Needed for stat()
#include <sys/stat.h>				// Needed for stat()

#include "cmlasn_internal.h"


/////////////////////////
// Function Prototypes //
/////////////////////////
static void hashBuffer(uchar* pData, ulong dataSize, ulong* hash);
static void sha_init(ulong hash[]);
static void sha_hash(ulong M[], ulong hash[]);
static bool isLittleEndian();


////////////////////////////
// CM_HashData() function //
////////////////////////////
short CM_HashData(Bytes_struct* pData, CM_HashValue hash)
{
	if ((pData == NULL) || (hash == NULL) || (pData->num == 0) ||
		(pData->data == NULL))
		return CMLASN_INVALID_PARAMETER;

	// Hash the input data
	hashBuffer(pData->data, pData->num, (ulong*)hash);
	return CMLASN_SUCCESS;
}


//////////////////////////////////////
// CommonBytes class implementation //
//////////////////////////////////////
CommonBytes::CommonBytes(ulong num, const uchar* bytes)
{
	len = 0;
	data = NULL;
	Set(num, bytes);
}


CommonBytes::CommonBytes(const char* fileName)
{
	if (fileName == NULL)
		throw EXCEPTION_STR(CMLASN_INVALID_PARAMETER, "invalid parameter");

	len = 0;
	data = NULL;

    struct stat buf;
    int result = stat(fileName, &buf);
    if ((result != 0) || (buf.st_size < 0))
        throw EXCEPTION_STR(CMLASN_FILE_IO_ERROR, "unable to get file status");

	// Allocate a buffer for the data
	len = buf.st_size;
	if (len > 0)
	{
		data = new uchar[buf.st_size];
		if (data == NULL)
			throw MEMORY_EXCEPTION;
		try {
#ifdef WIN32
			std::ifstream inFile(fileName, std::ios_base::in |
				std::ios_base::binary);
#else
			std::ifstream inFile(fileName);
#endif
			inFile.read((char*)data, len);
			if (inFile.fail())
				throw EXCEPTION_STR(CMLASN_FILE_IO_ERROR, "error reading file");
		}
		catch (...) {
			len = 0;
			delete[] data;
			data = NULL;
			throw EXCEPTION_STR(CMLASN_FILE_IO_ERROR, "error reading file");
		}
	}
}


CommonBytes::CommonBytes(const CommonBytes& that)
{
	len = 0;
	data = NULL;
	Set(that.len, that.data);
}


CommonBytes& CommonBytes::operator=(const CommonBytes& other)
{
	if (this != &other)
		Set(other.len, other.data);

	return *this;
}


bool CommonBytes::operator==(const CommonBytes& rhs) const
{
	if (this == &rhs)
		return true;

	if (len != rhs.len)
		return false;
	return (memcmp(data, rhs.data, len) == 0);
}


bool CommonBytes::operator<(const CommonBytes& rhs) const
{
	if (len < rhs.len)
		return (memcmp(data, rhs.data, len) <= 0);
	else
		return (memcmp(data, rhs.data, rhs.len) < 0);
}


CommonBytes& CommonBytes::operator+=(const CommonBytes& rhs)
{
	if (rhs.len > 0)
	{
		uchar* newBuf = new uchar[len + rhs.len];
		if (newBuf == NULL)
			throw MEMORY_EXCEPTION;

		if (len > 0)
		{
			memcpy(newBuf, data, len);
			delete[] data;
		}
		memcpy(&newBuf[len], rhs.data, rhs.len);

		data = newBuf;
		len += rhs.len;
	}

	return *this;
}


void CommonBytes::Clear()
{
	len = 0;
	if (data != NULL)
	{
		delete[] data;
		data = NULL;
	}
}


void CommonBytes::Set(ulong newDataLen, const uchar* newData)
{
	Clear();
	len = newDataLen;
	if (len > 0)
	{
		data = new uchar[len];
		if (data == NULL)
			throw MEMORY_EXCEPTION;

		if (newData == NULL)
			memset(data, 0, len);
		else
			memcpy(data, newData, len);
	}
}


void CommonBytes::Hash(CommonBytes& hashResult) const
{
	// Clear and set the hash result to the correct size for the SHA-1 hash
	hashResult.Set(CM_HASH_LEN);

	// Hash the data
	hashBuffer(data, len, (ulong*)hashResult.data);
}


// Write the contents to the specified stream
std::ostream& operator<<(std::ostream& os, const CommonBytes& bytes)
{
	return os.write((const char*)bytes.GetData(), bytes.Len());
}


////////////////////////
// Internal functions //
////////////////////////
void hashBuffer(uchar* pData, ulong dataSize, ulong* hash)
{
	// Constants
	const ushort BLOCK = 64;
	const ushort L_BLOCK = BLOCK / sizeof(long);
	const unsigned char paddata[64] = {
		0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  };

	// Union for reading in bytes and hashing in 32 bit blocks
	union {
		char	lets[BLOCK];
		ulong	nums[L_BLOCK];
	} buff;
	
	// Initialize the hash function
	sha_init(hash);

	// Hash data in groups of 64 bytes
	ulong arrayIndex = 0;
	int blocksRead = 0;
	while ((arrayIndex + 64) <= dataSize)
	{
		memcpy(buff.lets, pData + arrayIndex, BLOCK);
		
		if (isLittleEndian())
		{
			// Perform little endian byte swap
			for (unsigned int i = 0; i < 16; i++)
			{
				ulong tempnum = (buff.nums[i] << 16) | (buff.nums[i] >> 16);
				buff.nums[i] = ((tempnum & 0xff00ff00L) >> 8) |
					((tempnum & 0x00ff00ffL) << 8);
			}
		}

		sha_hash(buff.nums, hash);
		arrayIndex += BLOCK;
		blocksRead++;
	}
	
	// Calculate final hash
	ulong nBytesLeft = dataSize - arrayIndex;
	
	memcpy(buff.lets, pData + arrayIndex, nBytesLeft);
	memcpy(buff.lets + nBytesLeft, paddata, BLOCK - nBytesLeft);
	
	if (isLittleEndian())
	{
		// Perform little endian byte swap
		for (unsigned int i = 0; i < 16; i++)
		{
			ulong tempnum = (buff.nums[i] << 16) | (buff.nums[i] >> 16);
			buff.nums[i] = ((tempnum & 0xff00ff00L) >> 8) |
				((tempnum & 0x00ff00ffL) << 8);
		}
	}
	
	if (nBytesLeft >= 56)
	{
		sha_hash(buff. nums, hash);
		memset(buff.nums, 0, 16 * sizeof(long)); // Clear out nums for last pass
	}
	
	buff.nums[15] = (512 * blocksRead) + (8 * nBytesLeft);
	
	sha_hash(buff.nums, hash);

} // end of hashBuffer()


void sha_init(ulong hash[])
{
	hash[0] = 0x67452301L;
	hash[1] = 0xEFCDAB89L;
	hash[2] = 0x98BADCFEL;
	hash[3] = 0x10325476L;
	hash[4] = 0xC3D2E1F0L;
} // end of sha_init()


#define Ls5(num)  (((num)<<5)|((num)>>27))
#define Ls30(num) (((num)<<30)|((num)>>2))
#define Ls1(num)  ( ( (num) << 1 ) | ( ( (num) >> 31 ) & 1 ) )

#define F0(x,y,z) ( (z) ^ ( (x) & ( (y) ^ (z) ) ) )
#define F1(x,y,z) ( ( (x) & ( (y) ^ (z) ) ) ^ ( (z) & (y) ) )
#define F2(x,y,z) ((x)^(y)^(z))


void sha_hash(ulong M[], ulong hash[])
{
	const long K1 = 0x5A827999L;
	const long K2 = 0x6ED9EBA1L;
	const long K3 = 0x8F1BBCDCL;
	const long K4 = 0xCA62C1D6L;

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

} // end of sha_hash()



// FUNCTION:  isLittleEndian()
// This function returns true if the operating system is little-endian
// or false if it is big-endian.
//
inline bool isLittleEndian()
{
	long value = 1;

	// Check which byte the value 1 is in
	if (*(char *)&value == 1)
		return true;
	else
		return false;
}



// end of CommonBytes.cpp