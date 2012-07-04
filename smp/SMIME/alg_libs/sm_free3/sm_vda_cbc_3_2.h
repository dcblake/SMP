/* @(#) sm_vda_cbc_3_2.h 1.2 09/26/00 15:07:09 */

#ifndef VDA_CRYPTOPP_CBC_3_2_H
#define VDA_CRYPTOPP_CBC_3_2_H

#include "filters.h"
#include "modes.h"

NAMESPACE_BEGIN(CryptoPP)

/// CBC mode encryptor with padding

/** Compatible with RFC 2040.
*/
class VDA_CBCNotPaddedEncryptor_3_2 : protected CipherMode, public FilterWithBufferedInput
{
public:
   VDA_CBCNotPaddedEncryptor_3_2(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue = NULL);

protected:
   void NextPut(const byte *inString, unsigned int length);
   void LastPut(const byte *inString, unsigned int length);
};

class VDA_CBCNotPaddedDecryptor_3_2 : protected CipherMode, public FilterWithBufferedInput
{
public:
   VDA_CBCNotPaddedDecryptor_3_2(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue = NULL);

protected:
   void NextPut(const byte *inString, unsigned int length);
   void LastPut(const byte *inString, unsigned int length);
};

NAMESPACE_END

#endif
