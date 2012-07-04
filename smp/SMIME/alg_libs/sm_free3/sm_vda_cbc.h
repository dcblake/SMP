/* @(#) sm_vda_cbc.h 1.2 8/18/99 13:45:23 */
#ifndef CRYPTOPP_5_0

#ifndef VDACRYPTOPP_CBC_H
#define VDACRYPTOPP_CBC_H

#include "filters.h"
#include "modes.h"

NAMESPACE_BEGIN(CryptoPP)


/// VDA_CBC mode encryptor with no padding 
//  crypto++ library class CBC_CTS_Encryptor does not handle the no padding case

/** Compatible with RFC 2040.
*/
class VDA_CBCNotPaddedEncryptor : public Filter, 
#ifndef CRYPTOPP_5_0
        protected CipherMode
#else   // CRYPTOPP_5_0
        protected SymmetricCipher
#endif  // CRYPTOPP_5_0
{
public:
   VDA_CBCNotPaddedEncryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue = NULL);

   void Put(byte inByte);
   void Put(const byte *inString, unsigned int length);
   void InputFinished();

private:
   void ProcessBuf();
   unsigned int counter;
};

class VDA_CBCNotPaddedDecryptor : public Filter, 
#ifndef CRYPTOPP_5_0
        protected CipherMode
#else   // CRYPTOPP_5_0
        protected CipherModeBase
#endif  // CRYPTOPP_5_0
{
public:
   VDA_CBCNotPaddedDecryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue = NULL);

   void Put(byte inByte);
   void Put(const byte *inString, unsigned int length);
   void InputFinished();

private:
   friend class DefaultDecryptor;   // need access to ProcessBuf()
   void ProcessBuf();
   unsigned int counter;
   SecByteBlock temp;
};

NAMESPACE_END

#endif
//#endif
#endif   // CRYPTOPP_5_0
