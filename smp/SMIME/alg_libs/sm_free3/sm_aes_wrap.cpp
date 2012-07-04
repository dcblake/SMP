//////////////////////////////////////////////////////////////////////////////
// File:     sm_aes_wrap.cpp
// Project:  Crypto++ Crypto Token Interface Library (CTIL), aka SM_Free3
// Contents: SM_AES_KeyWrap() and SM_AES_KeyUnwrap() functions used to
//           encrypt AES content encryption keys in accordance with RFC 3394.
//           Crypto++ is used to perform the raw AES encryption and
//           decryption.
// Req Ref:  SMP RTM #5
//
// Created:  29 November 2004
// Author:   Rich Nicholas <Richard.Nicholas@it.baesystems.com>
//
// $Revision: 1.6 $
// $Date: 2004/12/22 18:47:45 $
//
//////////////////////////////////////////////////////////////////////////////

////////////////////
// Included Files //
////////////////////
#include "sm_aes_wrap.h"      // Needed for prototypes and error codes
#ifdef _MSC_VER
   #pragma warning(push, 3)
   #include <vector>          // Needed for std::vector<>
   #include "aes.h"           // Needed for AES algorithm in Crypto++ library
   #pragma warning(pop)
#else
   #include <vector>          // Needed for std::vector<>
   #include "aes.h"           // Needed for AES algorithm in Crypto++ library
#endif


///////////////////////
// Defined Constants //
///////////////////////
const int AES_BLOCK_SIZE_BITS =  128;               // Size of AES block in bits
const int AES_BLOCK_SIZE = AES_BLOCK_SIZE_BITS / 8; // Size of AES block in bytes


//////////////////////
// Type Definitions //
//////////////////////

// AESWrapBlock Class
// Used to represent a 64-bit block of AES key wrap data
class AESWrapBlock
{
public:
   enum {
      SIZE = AES_BLOCK_SIZE / 2     // Size of the key wrap block in bytes
   };

   // Constructors:
   // Default constructor to create a block without setting the contents
   AESWrapBlock()                                                            {}
   // Constructor to create a block and fill it with specified array of chars
   AESWrapBlock(const char* array)                 { Set((const byte*)array); }

   // Assignment operators:
   // Assign the contents of this block to the specified array of bytes
   AESWrapBlock& operator=(const byte* array)     { Set(array); return *this; }
   // Assign the contents of this block to the specified character array
   AESWrapBlock& operator=(const char* array) {
      Set((const byte*)array); return *this; }

   // Operator to convert this block to an array of bytes
   operator const byte*() const                            { return m_pBlock; }

   // Comparison operators:
   // Returns true if the contents of each block are identical
   bool operator==(const AESWrapBlock& rhs) const {
      return (memcmp(m_pBlock, rhs.m_pBlock, SIZE) == 0); }
   // Returns true if the contents of each block differ
   bool operator!=(const AESWrapBlock& rhs) const  { return !operator==(rhs); }

   // Operator to perform a bitwise exclusive-or with the rhs integer
   AESWrapBlock& operator^=(unsigned int rhs);

   // Set all of the bytes in this block to the specified value
   void Set(const byte& value)               { memset(m_pBlock, value, SIZE); }
   // Set this block of bytes to the specified array of bytes
   void Set(const byte* array)               { memcpy(m_pBlock, array, SIZE); }

private:
   byte m_pBlock[SIZE];    // Contents of the block
};


//////////////////////////////////////////////////////////////////////////////
// FUNCTION:  SM_AES_KeyWrap
//
// Description: Encrypts the input data in accordance with the AES key wrap
// algorithm defined in RFC 3394 (repeated below).
//
// Inputs:  Plaintext, n 64-bit values {P1, P2, ..., Pn}, and
//          Key, K (the KEK).
// Outputs: Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}.
//
// 1) Initialize variables.
//
//     Set A = IV, an initial value (see 2.2.3)
//     For i = 1 to n
//         R[i] = P[i]
//
// 2) Calculate intermediate values.
//
//     For j = 0 to 5
//         For i=1 to n
//             B = AES(K, A | R[i])
//             A = MSB(64, B) ^ t where t = (n*j)+i
//             R[i] = LSB(64, B)
//
// 3) Output the results.
//
//     Set C[0] = A
//     For i = 1 to n
//         C[i] = R[i]
//
// Parameters:
// (I) key           CSM_Buffer containing the AES key to encrypt with 
// (I) inputData     CSM_Buffer containing the data to encrypt
// (O) wrappedData   CSM_Buffer to be filled in with the encrypted data
// (I) pIV           Optional CSM_Buffer pointer containing the IV to use
// 
// Returns 0 if successful or one of the above error codes.
//////////////////////////////////////////////////////////////////////////////
int SM_AES_KeyWrap(const CTIL::CSM_Buffer& key,
                   const CTIL::CSM_Buffer& inputData,
                   CTIL::CSM_Buffer& wrappedData, const CTIL::CSM_Buffer* pIV)
{
   // Check that the key length is supported
   if ((key.Length() != 128 / 8) && (key.Length() != 192 / 8) &&
      (key.Length() != 256 / 8))
      return ERROR_BAD_KEY_MAT;

   // Check that the inputData is the correct length
   if ((inputData.Length() < AES_BLOCK_SIZE) ||
      ((inputData.Length() % AESWrapBlock::SIZE) != 0))
      return ERROR_BAD_INPUT;

   // If the optional IV is present, check that its length is correct
   if ((pIV != NULL) && (pIV->Length() != AESWrapBlock::SIZE))
      return ERROR_BAD_IV_LEN;

   // Create the Crypto++ AESEncryption object
   CryptoPP::AESEncryption aesCipher((const byte*)key.Access(), key.Length());

   // 1) Initialize variables.
   // Set A = IV
   AESWrapBlock aValue;       // The A value used in the key wrap algorithm
   if (pIV != NULL)
      aValue = pIV->Access();
   else  // Use the default value (A6A6A6A6A6A6A6A6)
      aValue.Set(0xA6);

   int i;                                    // loop variable
   const int n = inputData.Length() /        // n is the number of 64-bit
      AESWrapBlock::SIZE;                    // blocks of input data
   std::vector<AESWrapBlock> rValue(n + 1);  // The R value array
                                             // NOTE:  rValue[0] is not used
   // For i = 1 to n
   //    R[i] = P[i]
   for (i = 1; i <= n; i++)
      rValue[i] = &inputData.Access()[(i - 1) * AESWrapBlock::SIZE];

   // 2) Calculate intermediate values.
   byte bValue[AES_BLOCK_SIZE];              // B value used in algorithm

   // For j = 0 to 5
   for (int j = 0; j < 6; j++)
   {
      // For i=1 to n
      for (i = 1; i <= n; i++)
      {
         // B = AES(K, A | R[i])
         memcpy(bValue, aValue, AESWrapBlock::SIZE);
         memcpy(&bValue[AESWrapBlock::SIZE], rValue[i], AESWrapBlock::SIZE);
         aesCipher.ProcessBlock(bValue);

         // A = MSB(64, B) ^ t where t = (n*j)+i
         aValue = bValue;
         aValue ^= (n * j) + i;

         // R[i] = LSB(64, B)
         rValue[i] = &bValue[AESWrapBlock::SIZE];
      }
   }

   // 3) Output the results.
   // Allocate memory for the C value, a temporary array of wrapped data
   byte* pCValue = new byte[(n + 1) * AESWrapBlock::SIZE];
   if (pCValue == NULL)
      return ERROR_OUT_OF_MEMORY;

   // Set C[0] = A
   memcpy(pCValue, aValue, AESWrapBlock::SIZE);

   // For i = 1 to n
   //    C[i] = R[i]
   for (i = 1; i <= n; i++)
   {
      memcpy(&pCValue[i * AESWrapBlock::SIZE], rValue[i],
         AESWrapBlock::SIZE);
   }

   // Copy the C value into the wrappedData output parameter
   wrappedData.Set((const char*)pCValue, (n + 1) * AESWrapBlock::SIZE);

   // Delete the temporary C value and return success
   delete[] pCValue;
   return 0;
} // end of SM_AES_KeyWrap()


//////////////////////////////////////////////////////////////////////////////
// FUNCTION:  SM_AES_KeyUnwrap
//
// Description: Decrypts the wrapped data in accordance with the AES key wrap
// algorithm defined in RFC 3394 (repeated below) and compares the resulting
// IV with the expected value.
//
// Inputs:  Ciphertext, (n+1) 64-bit values {C0, C1, ..., Cn}, and
//          Key, K (the KEK).
// Outputs: Plaintext, n 64-bit values {P0, P1, K, Pn}.
//
// 1) Initialize variables.
//
//     Set A = C[0]
//     For i = 1 to n
//         R[i] = C[i]
//
// 2) Compute intermediate values.
//
//     For j = 5 to 0
//         For i = n to 1
//             B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
//             A = MSB(64, B)
//             R[i] = LSB(64, B)
//
// 3) Output results.
//
//     If A is an appropriate initial value (see 2.2.3),
//     Then
//         For i = 1 to n
//             P[i] = R[i]
//     Else
//         Return an error
//
// Parameters:
// (I) key           CSM_Buffer containing the AES key to decrypt with 
// (I) wrappedData   CSM_Buffer containing the data to decrypt
// (O) outputData    CSM_Buffer to be filled in with the decrypted data
// (I) pExpectedIV   Optional CSM_Buffer pointer containing the expected IV
// 
// Returns 0 if successful or one of the above error codes.
//////////////////////////////////////////////////////////////////////////////
int SM_AES_KeyUnwrap(const CTIL::CSM_Buffer& key,
                     const CTIL::CSM_Buffer& wrappedData,
                     CTIL::CSM_Buffer& outputData,
                     const CTIL::CSM_Buffer* pExpectedIV)
{
   // Check that the key length is supported
   if ((key.Length() != 128 / 8) && (key.Length() != 192 / 8) &&
      (key.Length() != 256 / 8))
      return ERROR_BAD_KEY_MAT;

   // Check that the wrappedData is the correct length
   if ((wrappedData.Length() < (AES_BLOCK_SIZE + AESWrapBlock::SIZE)) ||
      ((wrappedData.Length() % AESWrapBlock::SIZE) != 0))
      return ERROR_BAD_INPUT;

   // If the optional IV is present, check that its length is correct
   if ((pExpectedIV != NULL) && (pExpectedIV->Length() != AESWrapBlock::SIZE))
      return ERROR_BAD_IV_LEN;

   // Create the Crypto++ AESDecryption object
   CryptoPP::AESDecryption aesCipher((const byte*)key.Access(), key.Length());

   // 1) Initialize variables.
   // Set A = C[0]
   AESWrapBlock aValue = wrappedData.Access(); // The A value used in algorithm

   const int n = (wrappedData.Length() /     // n is the number of 64-bit
      AESWrapBlock::SIZE) - 1;               // blocks of unwrapped data
   std::vector<AESWrapBlock> rValue(n + 1);  // The R value array
                                             // NOTE:  rValue[0] is not used
   // For i = 1 to n
   //    R[i] = C[i]
   int i;                                    // loop variable
   for (i = 1; i <= n; i++)
      rValue[i] = &wrappedData.Access()[i * AESWrapBlock::SIZE];

   // 2) Compute intermediate values.
   byte bValue[AES_BLOCK_SIZE];              // B value used in algorithm

   // For j = 5 to 0
   for (int j = 5; j >= 0; j--)
   {
      // For i = n to 1
      for (i = n; i > 0; i--)
      {
         // B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
         aValue ^= (n * j) + i;
         memcpy(bValue, aValue, AESWrapBlock::SIZE);
         memcpy(&bValue[AESWrapBlock::SIZE], rValue[i], AESWrapBlock::SIZE);
         aesCipher.ProcessBlock(bValue);

         // A = MSB(64, B)
         aValue = bValue;

         // R[i] = LSB(64, B)
         rValue[i] = &bValue[AESWrapBlock::SIZE];
      }
   }

   // 3) Output results.
   AESWrapBlock iv;                 // Temporary expected IV value
   if (pExpectedIV != NULL)
      iv = pExpectedIV->Access();   // Use the provided IV value
   else
      iv.Set(0xA6);                 // Use the default value (A6A6A6A6A6A6A6A6)

   // If A matches the initial value,
   // Then
   if (aValue == iv)
   {
      // Allocate memory for the P value, a temporary array of plaintext data
      byte* pPValue = new byte[n * AESWrapBlock::SIZE];
      if (pPValue == NULL)
         return ERROR_OUT_OF_MEMORY;
   
      // For i = 1 to n
         // P[i] = R[i]
      for (i = 0; i < n; i++)
      {
         memcpy(&pPValue[i * AESWrapBlock::SIZE], rValue[i + 1],
            AESWrapBlock::SIZE);
      }

      // Copy the P value into the outputData parameter
      outputData.Set((const char*)pPValue, n * AESWrapBlock::SIZE);

      // Delete the temporary P value and return success
      delete[] pPValue;
      return 0;
   }
   else // Else
   {
      // Return an error indicating the IV doesn't match the expected value
      return ERROR_IV_MISMATCH;
   }
} // end of SM_AES_KeyUnwrap()


//////////////////////////////////////////////////////////////////////////////
// FUNCTION:  AESWrapBlock::operator^=()
//
// Description: Performs the bitwise exclusive OR of this AESWrapBlock with
// the integer operand on the right-hand side and stores the result in this
// AESWrapBlock.
//
// Parameters:
// (I) rhs     integer operand
// 
// Returns a reference to this AESWrapBlock.
//////////////////////////////////////////////////////////////////////////////
AESWrapBlock& AESWrapBlock::operator^=(unsigned int rhs)
{
   // Convert the rhs operand to an array of bytes
   byte op[SIZE] = { 0 };
   int i = SIZE;
   while (rhs > 0)
   {
      op[--i] = byte(rhs & 0xFF);
      rhs >>= 8;  // Right shift the remaining data one byte for next iteration
   }

   // Perform the bitwise exclusive-or of each byte in the array
   for (i = 0; i < SIZE; i++)
      m_pBlock[i] ^= op[i];

   return *this;
}


// end of sm_aes_wrap.cpp
