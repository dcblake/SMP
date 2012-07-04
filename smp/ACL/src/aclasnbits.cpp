//////////////////////////////////////////////////////////////////////////////
// aclasnbits.cpp
// These routines support the CAsnBits Class
// MEMBER FUNCTIONS:
//   And(AsnBits *result, AsnBits &userBits, AsnBits &caBits)
//   checkBit(AsnBits &bits, size_t &bit)
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// And:
//
// Performs a bitwise and of the passed in User Bits and CA Cert Bits
// into result.
//
void CAsnBits::And(AsnBits *result, AsnBits &userBits, AsnBits &caBits)
{
   // NEED TO CHECK THE LENGTH OF BOTH userBits AND caBits THEN LOOP THROUGH
   // EACH CHECKING FOR CASES WHERE THE CORRESPONDING BITS ARE SET IN BOTH
   // IN WHICH CASE THE CORRESPONDING BIT WILL BE SET IN THE result

   // SET BitLength TO WHICHEVER BITS (used OR ca) ARE SHORTER
   size_t lBitLength = (userBits.BitLen()) <= (caBits.BitLen()) ?
                        userBits.BitLen() : caBits.BitLen();
   AsnBits tmpBits(lBitLength);

   // Loop through the bits
   for (size_t i = 0 ; i < lBitLength; i++)
   {
      // Wherever there is a match, set the corresponding bit in tmpBits
      if ( (CAsnBits::checkBit(userBits, i))
        && (CAsnBits::checkBit(caBits, i)) )
      {
         tmpBits.SetBit(i);
      }
   }

   // Set results to tmpBits
   result->Set(tmpBits);

} //  END OF MEMBER FUNCTION And

// checkBit:
//
// returns true if "bit" is set in "bits".  Returns false otherwise
//
bool CAsnBits::checkBit(AsnBits &bits, AsnIntType bit)
{
   return bits.GetBit(bit);
} // END OF MEMBER FUNCTION checkBit

// FUNCTION: isEmpty()
//
// Returns true if the bit string has no bits set.
// Returns false otherwise.
//
bool CAsnBits::isEmpty(AsnBits &bits)
{
   bool flag = true;

   // Loop through the bits
   for (AsnIntType i = 0 ; i < (AsnIntType)(bits.BitLen()); i++)
   {
      if ( CAsnBits::checkBit(bits, i) )
      {
         flag = false;
         break;
      }
   }

   return flag;
}

_END_NAMESPACE_ACL

// EOF aclasnbits.cpp

