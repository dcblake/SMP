#ifdef CRYPTOPP_3

#ifndef CRYPTOPP_5_0

// sm_vda_cbc.cpp 
#ifdef CRYPTOPP_3

#include "pch.h"
#include "sm_vda_cbc.h"


NAMESPACE_BEGIN(CryptoPP)

// sib vda added code CBC_CTS_Encryptor/Decryptor does not handle no padding, therefore we 
// added the following to handle no padding, used for key wrap.
VDA_CBCNotPaddedEncryptor::VDA_CBCNotPaddedEncryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue)
   : Filter(outQueue), CipherMode(cipher, IV), counter(0)
{
}

void VDA_CBCNotPaddedEncryptor::ProcessBuf()
{
   cipher.ProcessBlock(reg);
   outQueue->Put(reg, S);
   counter = 0;
}

void VDA_CBCNotPaddedEncryptor::Put(byte inByte)
{
   reg[counter++] ^= inByte;
   if (counter == (unsigned int)S)
      ProcessBuf();
}

void VDA_CBCNotPaddedEncryptor::Put(const byte *inString, unsigned int length)
{
   while (counter && length)
   {
      VDA_CBCNotPaddedEncryptor::Put(*inString++);
      length--;
   }

   while (length >= (unsigned int)S)
   {
      xorbuf(reg, inString, S);
      ProcessBuf();
      inString += S;
      length -= S;
   }

   while (length--)
      VDA_CBCNotPaddedEncryptor::Put(*inString++);
}

void VDA_CBCNotPaddedEncryptor::InputFinished()
{
   // pad last block
//   byte pad = S-counter;
//    do
//      Put(pad);
   //while (counter != 0);
}

VDA_CBCNotPaddedDecryptor::VDA_CBCNotPaddedDecryptor(const BlockTransformation &cipher, const byte *IV, BufferedTransformation *outQueue)
   : Filter(outQueue), CipherMode(cipher, IV), counter(0), temp(S)
{
}

void VDA_CBCNotPaddedDecryptor::ProcessBuf()
{
   cipher.ProcessBlock(buffer, temp);
   xorbuf(temp, reg, S);
   outQueue->Put(temp, S);
   reg.swap(buffer);
   counter = 0;
}

void VDA_CBCNotPaddedDecryptor::Put(byte inByte)
{
   if (counter == (unsigned int)S)
      ProcessBuf();
   buffer[counter++] = inByte;
}

void VDA_CBCNotPaddedDecryptor::Put(const byte *inString, unsigned int length)
{
   while (counter!=(unsigned int)S && length)
   {
      VDA_CBCNotPaddedDecryptor::Put(*inString++);
      length--;
   }

   while (length >= (unsigned int)S)
   {
      ProcessBuf();
      memcpy(buffer, inString, S);
      counter = S;
      inString += S;
      length -= S;
   }

   while (length--)
      VDA_CBCNotPaddedDecryptor::Put(*inString++);
}

void VDA_CBCNotPaddedDecryptor::InputFinished()
{
   // unpad last block
   cipher.ProcessBlock(buffer);
   xorbuf(buffer, reg, S);
//   if (buffer[S-1] > S)
//      buffer[S-1] = 0;     // something's wrong with the padding
   outQueue->Put(buffer, S);
}

NAMESPACE_END

#endif
#endif     // CRYPTOPP_3
#endif     // CRYPTOPP_5_0
