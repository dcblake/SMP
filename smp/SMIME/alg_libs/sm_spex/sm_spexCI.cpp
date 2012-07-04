#ifndef NO_SCCS_ID
static char SccsId[ ] = "@(#) sm_spexCI.cpp 1.3 7/22/99 16:15:27"; 
#endif

#include "sm_spex.h"
_BEGIN_CERT_NAMESPACE

// extend this as necessary
//
// Get Usage Equipement specifier from label and return
// the appropriate LabelType
//
LabelType CSM_SPEXCardInfo::GetUE( void )
{
   LabelType labelType = BADLABEL;
   char *pCertLabel = NULL;
   char UE[5];

   memset(UE, 0, 5);
   pCertLabel = GetCertLabel();
   memcpy(UE, pCertLabel, 4);

   if (UE[0] != '\0')
   {
      if (strstr("RSAK", UE) != NULL)
         labelType = RSA;
   }
 
   return labelType;
}

_END_CERT_NAMESPACE

// EOF sm_specCI.cpp
