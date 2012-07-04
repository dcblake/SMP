/****************************************************************************
 * File:     sm_aes_wrap.h
 * Project:  Crypto++ Crypto Token Interface Library (CTIL), aka SM_Free3
 * Contents: Prototypes for SM_AES_KeyWrap() and SM_AES_KeyUnwrap()
 *           functions.
 * Req Ref:  SMP RTM #5
 *
 * Created:  7 December 2004
 * Author:   Rich Nicholas <Richard.Nicholas@it.baesystems.com>
 *
 * $Revision: 1.2 $
 * $Date: 2004/12/22 18:47:45 $
 *
 ****************************************************************************/
#ifndef _SM_AES_WRAP_H_
#define _SM_AES_WRAP_H_

////////////////////
// Included Files //
////////////////////
#include "asn-incl.h"         // Needed for SNACC C++ library
#include "sm_buffer.h"        // Needed for CTIL::CSM_Buffer class


/////////////////////
// Error Constants //
/////////////////////
const int ERROR_IV_MISMATCH   = -1;    // IV does not match expected value
const int ERROR_BAD_KEY_MAT   = -2;    // Invalid key length
const int ERROR_BAD_INPUT     = -3;    // Invalid input length
const int ERROR_BAD_IV_LEN    = -4;    // Unsupported IV length
const int ERROR_OUT_OF_MEMORY = -5;    // Out of memory error


/////////////////////////
// Function Prototypes //
/////////////////////////

// Encrypts the input data in accordance with the AES key wrap algorithm
// defined in RFC 3394
int SM_AES_KeyWrap(
                   const CTIL::CSM_Buffer& key,       // AES key to use
                   const CTIL::CSM_Buffer& inputData, // Data to encrypt
                   CTIL::CSM_Buffer& wrappedData,     // Encrypted data
                   const CTIL::CSM_Buffer* pIV = NULL // Optional IV
                   );

// Decrypts the wrapped data in accordance with the AES key wrap algorithm
// defined in RFC 3394 and compares the resulting IV with the expected value
int SM_AES_KeyUnwrap(
                     const CTIL::CSM_Buffer& key,           // AES key to use
                     const CTIL::CSM_Buffer& wrappedData,   // Data to decrypt
                     CTIL::CSM_Buffer& outputData,          // Decrypted data
                     const CTIL::CSM_Buffer* pExpectedIV = NULL // Optional IV
                     );

#endif // _SM_AES_WRAP_H_
