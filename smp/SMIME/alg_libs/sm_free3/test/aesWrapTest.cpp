//////////////////////////////////////////////////////////////////////////////
// File:     aesWrapTest.cpp
// Project:  Crypto++ Crypto Token Interface Library (CTIL), aka SM_Free3
// Contents: Test driver for testing the AES key wrapping code in SM_Free3.
// Req Ref:  SMP RTM #5
//
// Created:  22 December 2004
// Author:   Rich Nicholas <Richard.Nicholas@it.baesystems.com>
//
// $Revision: 1.1 $
// $Date: 2004/12/22 18:47:44 $
//
//////////////////////////////////////////////////////////////////////////////

////////////////////
// Included Files //
////////////////////
#include "sm_aes_wrap.h"      // Needed for prototypes and error codes
#include "CommonBytes.h"      // Needed for CommonBytes class
#include "config.h"           // Needed for byte type from Crypto++ library


//////////////////////
// Type Definitions //
//////////////////////

/////////////////////////////////////////////////////////////////////////////
// LargeInteger Class
// Used to represent an integer that could be larger than the operating
// system natively supports.  Useful for converting a string of characters
// into an array of bytes.
/////////////////////////////////////////////////////////////////////////////
class LargeInteger : public CommonBytes
{
public:
   enum Base
   {
      BINARY,        // Base 2   -- string example:  "01001101"
      OCTAL,         // Base 8   -- string example:  "04266371"
      DECIMAL,       // Base 10  -- string example:  "346820"
      HEXADECIMAL    // Base 16  -- string example:  "9F3Cb2f1"
   };

   // Constructor to create a LargeInteger from its string representation and
   // optional length and optional base flag
   LargeInteger(const char* stringForm, size_t length = 0,
      Base base = DECIMAL);

private:
   // Private function to return the decimal equivalent of the hex character
   static byte hexChar2Byte(char hexChar);
};


// FUNCTION:  LargeInteger::LargeInteger()
// 
LargeInteger::LargeInteger(const char* stringForm, size_t length, Base base)
{
   // Determine length if not passed in
   if (length == 0)
      length = strlen(stringForm);

   switch (base)
   {
   case HEXADECIMAL:
      // Initialize the array of bytes
      Set((length + 1) / 2);

      // Convert the string form to a binary array
      for (size_t i = 0; i < length; i++)
      {
         data[i / 2] |= hexChar2Byte(*stringForm++);
         if ((i % 2) == 0)
            data[i / 2] <<= 4;
      }
      break;

   default:
      throw "Unsupported option";
   }
}


// FUNCTION:  LargeInteger::hexChar2Byte()
// 
byte LargeInteger::hexChar2Byte(char hexChar)
{
   if ((hexChar >= '0') && (hexChar <= '9'))
		return byte(hexChar - '0');
	else if ((hexChar >= 'a') && (hexChar <= 'f'))
		return byte(hexChar - 'a' + 10);
	else if ((hexChar >= 'A') && (hexChar <= 'F'))
		return byte(hexChar - 'A' + 10);
	else
		throw "Invalid hex character";
}


/////////////////////////////////////////////////////////////////////////////
// Main function for testing AES key wrap functions
/////////////////////////////////////////////////////////////////////////////
int main(int argc, const char* argv[])
{
   using namespace std;
   using CTIL::CSM_Buffer;

   struct TestData
   {
      int keyLen;                // Length of key in bits
      int keyDataLen;            // Length of key data in bits
      const char* wrappedKey;    // Expected cipertext result
   };
   const TestData TestTable[] = {
      { 128, 128, "1FA68B0A8112B447" "AEF34BD8FB5A7B82" "9D3E862371D2CFE5" },
      { 192, 128, "96778B25AE6CA435" "F92B5B97C050AED2" "468AB8A17AD84E5D" },
      { 256, 128, "64E8C3F9CE0F5BA2" "63E9777905818A2A" "93C8191E7D6E8AE7" },
      { 192, 192, "031D33264E15D332" "68F24EC260743EDC" "E1C6C7DDEE725A93" "6BA814915C6762D2" },
      { 256, 192, "A8F9BC1612C68B3F" "F6E6F4FBE30E71E4" "769C8B80A32CB895" "8CD5D17D6B254DA1" },
      { 256, 256, "28C9F404C4B810F4" "CBCCB35CFB87F826" "3F5786E2D80ED326" "CBC7F0E71A99F43B" "FB988B9B7A02DD21" },
      { 0, 0, NULL }
   };
   const char testKey[]  = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
   const char testData[] = "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F";
   const char binaryIV[] = "\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6";
   const CSM_Buffer externalIV(binaryIV, sizeof(binaryIV) - 1);

   cout << "\nRunning AES key wrapping tests..." << endl;

   // Loop through test vector tests twice, first with internal IV and then
   // with external IV
   for (int i = 0; i < 2; i++)
   {
      const char* pInExStr = "in";
      const CSM_Buffer* pIV = NULL;
      if (i == 1)
      {
         pInExStr = "ex";
         pIV = &externalIV;
      }

      cout << "\nRunning test vector tests with ";
      cout << pInExStr << "ternal IV..." << endl;

      const TestData* pTest = TestTable;
      while (pTest->wrappedKey != NULL)
      {
         cout << pTest->keyDataLen << " bits of key data with a " <<
            pTest->keyLen << "-bit KEK:" << endl;

         // Build KEK and key data
         LargeInteger keyBytes(testKey, pTest->keyLen / 4,
            LargeInteger::HEXADECIMAL);
         LargeInteger keyDataBytes(testData, pTest->keyDataLen / 4,
            LargeInteger::HEXADECIMAL);

         // Load KEK and key data into CSM_Buffers
         CSM_Buffer key((const char*)keyBytes.GetData(), keyBytes.Len());
         CSM_Buffer keyData((const char*)keyDataBytes.GetData(),
            keyDataBytes.Len());

         // Wrap the key
         cout << "\tWrapping...";
         CSM_Buffer wrappedData;
         CSM_Buffer unwrappedKeyData;
         int result = SM_AES_KeyWrap(key, keyData, wrappedData, pIV);
         if (result != 0)
            cout << "\bFAILED!  Error: " << result << endl;
         else
         {
            // Build the expected result
            LargeInteger expectedBytes(pTest->wrappedKey, 0,
               LargeInteger::HEXADECIMAL);
            CTIL::CSM_Buffer expectedOutput((const char*)expectedBytes.GetData(),
               expectedBytes.Len());

            // Compare the actual result with the expected result
            if (wrappedData != expectedOutput)
               cout << "FAILED!  Ciphertext does not match expected result.";
            else
            {
               cout << "succeeded" << endl;
               cout << "\tUnwrapping...";
               result = SM_AES_KeyUnwrap(key, wrappedData, unwrappedKeyData,
                  pIV);
               if (result != 0)
                  cout << "FAILED!  Error: " << result;
               else if (unwrappedKeyData != keyData)
                  cout << "FAILED!  Unwrapped data does not match original data.";
               else
                  cout << "succeeded";
            }
         }

         // Add carriage-return
         cout << endl;

         // Move to next test
         pTest++;
      }
   }

   // Running negative tests
   CSM_Buffer goodKey(size_t(16));
   CSM_Buffer goodInput(size_t(16));
   CSM_Buffer wrappedKey(size_t(24));
   CSM_Buffer output;
   CSM_Buffer shortIV(size_t(7));
   CSM_Buffer largeIV(size_t(9));
   cout << "\nRunning negative test cases..." << endl;

   // Bad key length tests
   cout << "\nBad key length tests:" << endl;
   cout << "\tPassed to SM_AES_KeyWrap()...";
   if (SM_AES_KeyWrap(CSM_Buffer(), goodInput, wrappedKey, NULL) !=
      ERROR_BAD_KEY_MAT)
   {
      cout << "FAILED!  Zero length key" << endl;
   }
   else if (SM_AES_KeyWrap(CSM_Buffer(size_t(64)), goodInput, wrappedKey, NULL) !=
      ERROR_BAD_KEY_MAT)
   {
      cout << "FAILED!  512-bit length key" << endl;
   }
   else
      cout << "succeeded" << endl;

   cout << "\tPassed to SM_AES_KeyUnwrap()...";
   if (SM_AES_KeyUnwrap(CSM_Buffer(), goodInput, wrappedKey, NULL) !=
      ERROR_BAD_KEY_MAT)
   {
      cout << "FAILED!  Zero length key" << endl;
   }
   else if (SM_AES_KeyUnwrap(CSM_Buffer(size_t(64)), goodInput, wrappedKey, NULL) !=
      ERROR_BAD_KEY_MAT)
   {
      cout << "FAILED!  512-bit length key" << endl;
   }
   else
      cout << "succeeded" << endl;

   // Bad input tests
   cout << "\nBad input data tests:" << endl;
   cout << "\tPassed to SM_AES_KeyWrap()...";
   if (SM_AES_KeyWrap(goodKey, CSM_Buffer(size_t(15)), wrappedKey, NULL) !=
      ERROR_BAD_INPUT)
   {
      cout << "FAILED!  Input length too short" << endl;
   }
   else if (SM_AES_KeyWrap(goodKey, CSM_Buffer(size_t(17)), wrappedKey, NULL) !=
      ERROR_BAD_INPUT)
   {
      cout << "FAILED!  Input length invalid" << endl;
   }
   else
      cout << "succeeded" << endl;

   cout << "\tPassed to SM_AES_KeyUnwrap()...";
   if (SM_AES_KeyUnwrap(goodKey, CSM_Buffer(size_t(16)), output, NULL) !=
      ERROR_BAD_INPUT)
   {
      cout << "FAILED!  Input length too short" << endl;
   }
   else if (SM_AES_KeyUnwrap(goodKey, CSM_Buffer(size_t(17)), output, NULL) !=
      ERROR_BAD_INPUT)
   {
      cout << "FAILED!  Input length invalid" << endl;
   }
   else
      cout << "succeeded" << endl;

   // Bad IV tests
   cout << "\nBad IV tests:" << endl;
   cout << "\tPassed to SM_AES_KeyWrap()...";
   if (SM_AES_KeyWrap(goodKey, goodInput, wrappedKey, &shortIV) !=
      ERROR_BAD_IV_LEN)
   {
      cout << "FAILED!  IV length too short" << endl;
   }
   else if (SM_AES_KeyWrap(goodKey, goodInput, wrappedKey, &largeIV) !=
      ERROR_BAD_IV_LEN)
   {
      cout << "FAILED!  IV length too large" << endl;
   }
   else
      cout << "succeeded" << endl;

   cout << "\tPassed to SM_AES_KeyUnwrap()...";
   if (SM_AES_KeyUnwrap(goodKey, wrappedKey, output, &shortIV) !=
      ERROR_BAD_IV_LEN)
   {
      cout << "FAILED!  IV length too short" << endl;
   }
   else if (SM_AES_KeyUnwrap(goodKey, wrappedKey, output, &largeIV) !=
      ERROR_BAD_IV_LEN)
   {
      cout << "FAILED!  IV length too large" << endl;
   }
   else
      cout << "succeeded" << endl;

   cout << "\nTesting finished." << endl;
   return 0;
} // end of main()
