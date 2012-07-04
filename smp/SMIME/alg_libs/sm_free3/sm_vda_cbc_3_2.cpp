
// sm_vda_cbc_3.2.cpp was written to redefine the padding process perform in 
// the crypto++3.2 library (it MIGHT be applicable to future crypto releases)


#ifdef CRYPTOPP_3_2

#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#endif

#include "pch.h"
#include "sm_vda_cbc_3_2.h"

#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif

NAMESPACE_BEGIN(CryptoPP)

VDA_CBCNotPaddedEncryptor_3_2::VDA_CBCNotPaddedEncryptor_3_2(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue)
   : CipherMode(cipher, IV), FilterWithBufferedInput(0, S, 0, outQueue)
{
}

void VDA_CBCNotPaddedEncryptor_3_2::NextPut(const byte *inString, unsigned int)
{
   xorbuf(reg, inString, S);
   cipher.ProcessBlock(reg);
   AttachedTransformation()->Put(reg, S);
}

void VDA_CBCNotPaddedEncryptor_3_2::LastPut(const byte *inString, unsigned int length)
{
   // pad last block
   assert(length < (unsigned int)S);
   xorbuf(reg, inString, length);
  /*
   byte pad = S-length;
   for (unsigned int i=0; i<pad; i++)
      reg[length+i] ^= pad;
  */
   if (length)
   {
      cipher.ProcessBlock(reg);
      //AttachedTransformation()->Put(reg, S);
      AttachedTransformation()->Put(reg, length);
   }

}

VDA_CBCNotPaddedDecryptor_3_2::VDA_CBCNotPaddedDecryptor_3_2(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue)
   : CipherMode(cipher, IV), FilterWithBufferedInput(0, S, S, outQueue)
{
}

void VDA_CBCNotPaddedDecryptor_3_2::NextPut(const byte *inString, unsigned int)
{
   cipher.ProcessBlock(inString, buffer);
   xorbuf(buffer, reg, S);
   AttachedTransformation()->Put(buffer, S);
   memcpy(reg, inString, S);
}

void VDA_CBCNotPaddedDecryptor_3_2::LastPut(const byte *inString, unsigned int length)
{
/*
   if (length >= S)
   {
*/
      cipher.ProcessBlock(inString, buffer);
      //xorbuf(buffer, reg, S);
      if (length)
      {
         xorbuf(buffer, reg, length);
/*
      if (buffer[S-1] > S)
         buffer[S-1] = 0;    // something's wrong with the padding
*/
      //AttachedTransformation()->Put(buffer, S-buffer[S-1]);
         AttachedTransformation()->Put(buffer, length);
      }
/*   
   }
*/ 
}


NAMESPACE_END

#endif
