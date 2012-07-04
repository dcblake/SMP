
//////////////////////////////////////////////////////////////////////////
//  sm_CSInst.cpp
//  This set of C++ routines support the CSM_CtilInst class.
//

#include "sm_apiCtilMgr.h"
#include "string.h"  // strdup()

_BEGIN_CTIL_NAMESPACE 
using namespace SNACC; 

// CONSTRUCTOR FOR CSM_CtilInst
//
CSM_CtilInst::CSM_CtilInst()
{
    Clear();
}

// DESTRUCTOR FOR CSM_CtilInst
//
CSM_CtilInst::~CSM_CtilInst()
{
   // m_pTokenInterface must be freed by a CTI Shutdown function
   if (m_pszCSInstID)
      free(m_pszCSInstID);
   if (m_pTokenInterface)
      m_pTokenInterface->CSM_TokenInterfaceDestroy();  // Virtual destructor
                                // THIS call MUST BE VIRTUAL so that the
                                //  individual CTIL libraries properly shutdown
                                //  the instance.
}

// SetTokenInterface:
//
void CSM_CtilInst::SetTokenInterface(CSM_TokenInterface *pTokenInterface)
{
   m_pTokenInterface = pTokenInterface;
}

// SetID:
//
void CSM_CtilInst::SetID(char *pszSessionID)
{
    m_pszCSInstID = strdup(pszSessionID);
}


// SetPreferrredSessionAlgs:
//   Sets the preferred encryption and signing algorithms by OID.  They
//   must be part of the listed algorithms supported algorithms by OID.
//   They must be part of the listed algorithms supported by this session
//   or the member function will return an error (non-zero).  NULL
//   parameter are acceptable to allow the default session algorithms.
void CSM_CtilInst::SetPreferredCSInstAlgs(AsnOid *oidDigest,
            AsnOid *oidDigestEncryption,
            AsnOid *oidKeyEncryption,
            AsnOid *oidContentEncryption)
{
   // RWC; TBD; check that these OIDs reside in alglists.
   m_pTokenInterface->BTISetPreferredCSInstAlgs(oidDigest,
         oidDigestEncryption, oidKeyEncryption, oidContentEncryption);
}

// GetPreferredCSInstAlgs:
//
void CSM_CtilInst::GetPreferredCSInstAlgs(AsnOid *oidDigest,
                                        AsnOid *oidDigestEncryption,
                                        AsnOid *oidKeyEncryption,
                                        AsnOid *oidContentEncryption)
{
   m_pTokenInterface->BTIGetPreferredCSInstAlgs(oidDigest,
         oidDigestEncryption, oidKeyEncryption, oidContentEncryption);
}

// SetAlgIDs:
//
void CSM_CtilInst::SetAlgIDs(CSM_AlgLstVDA *pdigestAlgID,
            CSM_AlgLstVDA *pdigestEncryptionAlgID,
            CSM_AlgLstVDA *pkeyEncryptionAlgID,
            CSM_AlgLstVDA *pcontentEncryptionAlgID)
{
   m_pTokenInterface->BTISetAlgIDs(pdigestAlgID,
         pdigestEncryptionAlgID,
         pkeyEncryptionAlgID,
         pcontentEncryptionAlgID);
}

// GetAlgIDs:
//
void CSM_CtilInst::GetAlgIDs(CSM_AlgLstVDA *&pdigestAlgID,
            CSM_AlgLstVDA *&pdigestEncryptionAlgID,
            CSM_AlgLstVDA *&pkeyEncryptionAlgID,
            CSM_AlgLstVDA *&pcontentEncryptionAlgID)
{
   CSM_AlgLstVDA **ppdigestAlgID=NULL,
         **ppdigestEncryptionAlgID=NULL,
         **ppkeyEncryptionAlgID=NULL,
         **ppcontentEncryptionAlgID=NULL;
   if (pdigestAlgID)
      ppdigestAlgID = &pdigestAlgID;
   if (pdigestEncryptionAlgID)
      ppdigestEncryptionAlgID = &pdigestEncryptionAlgID;
   if (pkeyEncryptionAlgID)
      ppkeyEncryptionAlgID = &pkeyEncryptionAlgID;
   if (pcontentEncryptionAlgID)
      ppcontentEncryptionAlgID = &pcontentEncryptionAlgID;
   m_pTokenInterface->BTIGetAlgIDs(ppdigestAlgID,
         ppdigestEncryptionAlgID,
         ppkeyEncryptionAlgID,
         ppcontentEncryptionAlgID);
}

// FindAlgIds:
// This function searches for any specified algorithm IDs
// in the appropriate private members algorithm lists for the specified
// algorithm.  If all specified algorithms are found, a TRUE is returned.
// Any of the parameters can be NULL; it is expected that at least one is
// not NULL.
//
bool CSM_CtilInst::FindAlgIds(CSM_AlgVDA *pdigestAlgID,
            CSM_AlgVDA *pdigestEncryptionAlgID,
            CSM_AlgVDA *pkeyEncryptionAlgID,
            CSM_AlgVDA *pcontentEncryptionAlgID)
{
   return (m_pTokenInterface->BTIFindAlgIds(pdigestAlgID,
         pdigestEncryptionAlgID, pkeyEncryptionAlgID,
         pcontentEncryptionAlgID));
}

#ifdef NOT_USED   //RWC;
// IsSigner:
//
bool CSM_CtilInst::IsSigner()
{
    bool result=false;
    CSM_AlgLstVDA *pNullValue = NULL;
    CSM_AlgLstVDA *pDigestEncryptionAlgID = NULL;
    long count = 0;
    long i = 0;

    SME_SETUP("CSM_CtilInst::IsSigner()");

    pDigestEncryptionAlgID = new CSM_AlgLstVDA;

   // add a generic try and catch incase GetAlgIDs throws an
   // exception.  IsSigner() should just return true or false.
   //
   try 
   {
      GetAlgIDs(pNullValue, pDigestEncryptionAlgID,
       pNullValue,
       pNullValue);
   } catch(CSM_Exception *e) { delete e; }

    // PIERCE it's not necessary to check oids below.  Just check to see
    // if a digest encryption algorithm is present.
    //

    // ADDED A CHECK TO BE SURE THERE IS AN ALGORITHM ID
    if ( pDigestEncryptionAlgID != NULL )
   {
        if ( (count = pDigestEncryptionAlgID->CountL()) > 0)
        {
                    result = true;
        }       // END if signature algs present.
    }

    delete pDigestEncryptionAlgID;

    return result;

    SME_FINISH_CATCH;
}
#endif   //RWC;NOT_USED

_END_CTIL_NAMESPACE 

// EOF sm_CSInst.cpp
