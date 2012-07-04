// sm_BaseTokenInterface.cpp
#include <string.h>
#include "sm_apiCtilMgr.h"
_BEGIN_CTIL_NAMESPACE 
using namespace SNACC; 
//////////////////////////////////////////////////////////////////////////
CSM_BaseTokenInterface::~CSM_BaseTokenInterface()
{
   if (m_pDigestAlgorithms)
      delete m_pDigestAlgorithms;
   if (m_pDigestEncryptionAlgorithms)
      delete m_pDigestEncryptionAlgorithms;
   if (m_pKeyEncryptionAlgorithms)
      delete m_pKeyEncryptionAlgorithms;
   if (m_pContentEncryptionAlgorithms)
      delete m_pContentEncryptionAlgorithms;
}

//////////////////////////////////////////////////////////////////////////
AsnOid* CSM_BaseTokenInterface::GetPrefDigest() 
{
    SMTI_Lock();
    AsnOid *pReturnOid=new AsnOid(m_digestOID);
    SMTI_Unlock();
   return (pReturnOid);
}

//////////////////////////////////////////////////////////////////////////
AsnOid* CSM_BaseTokenInterface::GetPrefDigestEncryption() 
{ 
    SMTI_Lock();
    AsnOid *pReturnOid=new AsnOid(m_digestEncryptionOID);
    SMTI_Unlock();
   return (pReturnOid);
}

//////////////////////////////////////////////////////////////////////////
AsnOid* CSM_BaseTokenInterface::GetPrefKeyEncryption() 
{ 
    SMTI_Lock();
    AsnOid *pReturnOid=new AsnOid(m_keyEncryptionOID);
    SMTI_Unlock();
   return (pReturnOid);
}

//////////////////////////////////////////////////////////////////////////
AsnOid* CSM_BaseTokenInterface::GetPrefContentEncryption() 
{ 
    SMTI_Lock();
    AsnOid *pReturnOid=new AsnOid(m_contentEncryptionOID);
    SMTI_Unlock();
   return (pReturnOid);
}

//////////////////////////////////////////////////////////////////////////
AsnOid* CSM_BaseTokenInterface::GetLocalKeyAlg() 
{ 
   return (new AsnOid(m_localKeyOID)); 
}

//////////////////////////////////////////////////////////////////////////
void CSM_BaseTokenInterface::SetLocalKeyAlg(AsnOid *poid) 
{ 
   SME_SETUP("CSM_BaseTokenInterface::SetLocalKeyAlg");

   if (poid == NULL)
      SME_THROW(SM_MISSING_PARAM, "no local key alg specified", NULL);
   m_localKeyOID = *poid;

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// make sure the requested algorithm is in the support alg list, if so,
// make it the preferred alg
void CSM_BaseTokenInterface::BTISetPreferredCSInstAlgs(AsnOid *oidDigest,
            AsnOid *oidDigestEncryption,
            AsnOid *oidKeyEncryption,
            AsnOid *oidContentEncryption)
{
   CSM_AlgLstVDA::iterator itTmpAlg;
   this->SMTI_Lock();  //RWC; MUST LOCK access to the preferred OID, one of
                       //RWC;  only a few places where the internal OIDs are 
                       //RWC;  updated.  (Causes crashes if not protected!)
   // for each alg category, search through all algs in list, if match
   // is found, then set the preferred algorithm
   if (oidDigest != NULL)
   {
      if (m_pDigestAlgorithms)
      {
         for (itTmpAlg =  m_pDigestAlgorithms->begin(); 
              itTmpAlg != m_pDigestAlgorithms->end();
              ++itTmpAlg)
			{
            if (*(itTmpAlg->AccessSNACCId()) == *oidDigest)
				{
					m_digestOID = *oidDigest;
					break;
				}
			}
      }
   }

   if (oidDigestEncryption != NULL)
   {
      if (m_pDigestEncryptionAlgorithms)
      {
         for (itTmpAlg =  m_pDigestEncryptionAlgorithms->begin(); 
              itTmpAlg != m_pDigestEncryptionAlgorithms->end();
              ++itTmpAlg)
			{
            if (*(itTmpAlg->AccessSNACCId()) == *oidDigestEncryption)
				{
					m_digestEncryptionOID = *oidDigestEncryption;
					break;
				}
			}
      }
   }

   if (oidKeyEncryption != NULL)
   {
      if (m_pKeyEncryptionAlgorithms)
      {
         for (itTmpAlg =  m_pKeyEncryptionAlgorithms->begin(); 
              itTmpAlg != m_pKeyEncryptionAlgorithms->end();
              ++itTmpAlg)
			{
            if (*(itTmpAlg->AccessSNACCId()) == *oidKeyEncryption)
				{
	            m_keyEncryptionOID = *oidKeyEncryption;
					break;
				}
			}
      }
   }

   if (oidContentEncryption != NULL)
   {
      if (m_pContentEncryptionAlgorithms)
      {
         for (itTmpAlg =  m_pContentEncryptionAlgorithms->begin(); 
              itTmpAlg != m_pContentEncryptionAlgorithms->end();
              ++itTmpAlg)
			{
            if (*(itTmpAlg->AccessSNACCId()) == *oidContentEncryption)
				{
					m_contentEncryptionOID = *oidContentEncryption;
					break;
				}
			}
      }
   }
   this->SMTI_Unlock();
}

//////////////////////////////////////////////////////////////////////////
// This function returns the preferred OIDs from the base token interface.
// if any of the incoming pointers to references are Null, that one is
// not set....
void CSM_BaseTokenInterface::BTIGetPreferredCSInstAlgs(AsnOid *&oidDigest,
            AsnOid *&oidDigestEncryption,
            AsnOid *&oidKeyEncryption,
            AsnOid *&oidContentEncryption)
{
    this->SMTI_Lock();
   if (oidDigest != NULL)
      *oidDigest = m_digestOID;
   if (oidDigestEncryption != NULL)
      *oidDigestEncryption = m_digestEncryptionOID;
   if (oidKeyEncryption != NULL)
      *oidKeyEncryption = m_keyEncryptionOID;
   if (oidContentEncryption != NULL)
      *oidContentEncryption = m_contentEncryptionOID;
   this->SMTI_Unlock();
}

//////////////////////////////////////////////////////////////////////////
// if any parameter to this function is NULL then it ignores that part of
// processing.  This function allows the caller to set the alg ID lists
// in the base token interface.  If an alg id list is already in the
// base token interface, then this function free's it before setting
// the new one
void CSM_BaseTokenInterface::BTISetAlgIDs(CSM_AlgLstVDA *pdigestAlgID, 
            CSM_AlgLstVDA *pdigestEncryptionAlgID,
            CSM_AlgLstVDA *pkeyEncryptionAlgID,
            CSM_AlgLstVDA *pcontentEncryptionAlgID)
{
    this->SMTI_Lock();
   if (pdigestAlgID != NULL)
   {
      if (m_pDigestAlgorithms != NULL && 
          m_pDigestAlgorithms != pdigestAlgID)
         delete m_pDigestAlgorithms;
      m_pDigestAlgorithms = new CSM_AlgLstVDA(*pdigestAlgID);
   }
   if (pdigestEncryptionAlgID != NULL)
   {
      if (m_pDigestEncryptionAlgorithms != NULL && 
          m_pDigestEncryptionAlgorithms != pdigestEncryptionAlgID)
         delete m_pDigestEncryptionAlgorithms;
      m_pDigestEncryptionAlgorithms = new CSM_AlgLstVDA(*pdigestEncryptionAlgID);
   }
   if (pkeyEncryptionAlgID != NULL)
   {
      if (m_pKeyEncryptionAlgorithms != NULL &&
          m_pKeyEncryptionAlgorithms != pkeyEncryptionAlgID)
         delete m_pKeyEncryptionAlgorithms;
      m_pKeyEncryptionAlgorithms = new CSM_AlgLstVDA(*pkeyEncryptionAlgID);
   }
   if (pcontentEncryptionAlgID != NULL)
   {
      if (m_pContentEncryptionAlgorithms != NULL &&
          m_pContentEncryptionAlgorithms != pcontentEncryptionAlgID)
         delete m_pContentEncryptionAlgorithms;
      m_pContentEncryptionAlgorithms = new CSM_AlgLstVDA(*pcontentEncryptionAlgID);
   }
    this->SMTI_Unlock();
}

//////////////////////////////////////////////////////////////////////////
// if any parameter to this function is NULL then this function ignores
// that part of the processing.  This function allows the caller to
// retrieve the alg ID lists from the base token interface.
void CSM_BaseTokenInterface::BTIGetAlgIDs(CSM_AlgLstVDA **ppdigestAlgID, 
            CSM_AlgLstVDA **ppdigestEncryptionAlgID,
            CSM_AlgLstVDA **ppkeyEncryptionAlgID,
            CSM_AlgLstVDA **ppcontentEncryptionAlgID)
{
    this->SMTI_Lock();
   if ( (ppdigestAlgID != NULL) && (m_pDigestAlgorithms != NULL))
   {
      if (*ppdigestAlgID == NULL)
         *ppdigestAlgID = new CSM_AlgLstVDA;
      **ppdigestAlgID = *m_pDigestAlgorithms;
   }
   if ((ppdigestEncryptionAlgID != NULL) && 
      (m_pDigestEncryptionAlgorithms != NULL))
   {
      if (*ppdigestEncryptionAlgID == NULL)
         *ppdigestEncryptionAlgID = new CSM_AlgLstVDA;
      **ppdigestEncryptionAlgID = *m_pDigestEncryptionAlgorithms;
   }
   if ((ppkeyEncryptionAlgID != NULL) && 
       (m_pKeyEncryptionAlgorithms != NULL))
   {
      if (*ppkeyEncryptionAlgID == NULL)
         *ppkeyEncryptionAlgID = new CSM_AlgLstVDA;
      **ppkeyEncryptionAlgID = *m_pKeyEncryptionAlgorithms;
   }
   if ((ppcontentEncryptionAlgID != NULL) && 
      (m_pContentEncryptionAlgorithms != NULL))
   {
      if (*ppcontentEncryptionAlgID == NULL)
         *ppcontentEncryptionAlgID = new CSM_AlgLstVDA;
      **ppcontentEncryptionAlgID = *m_pContentEncryptionAlgorithms;
   }
    this->SMTI_Unlock();
}

//
//
void printThese(char *p1, char *p2, bool bFound)
{
#ifdef BOB
      std::cout << "BTIFindAlgIds: pTemp=" << p1 <<
                       "  pcontentEncryptionAlgID=" << 
                       p2 <<  "  bFound=" << bFound << " \n";
#else
    printf("BTIFindAlgIds: pTemp= %s, pcontentEncryptionAlgID=%s bFound=%d\n",
                     p1, p2, bFound);
#endif
}
//////////////////////////////////////////////////////////////////////////
// BTIFindAlgIds will return true if all of the specified algorithm ids 
// are in this base token interface.  Parameters that are null are 
// ignored.
// TBD, maybe we should just pass OIDs in instead of AlgIDs???
bool CSM_BaseTokenInterface::BTIFindAlgIds(CSM_AlgVDA *pdigestAlgID, 
            CSM_AlgVDA *pdigestEncryptionAlgID,
            CSM_AlgVDA *pkeyEncryptionAlgID,
            CSM_AlgVDA *pcontentEncryptionAlgID)
{
   bool bRet = true;
   bool bFoundThisOne;
   CSM_AlgLstVDA::iterator itTmpAlg;


   //while (true)
   {
      // find out if the requested digest alg is in the list
      if (pdigestAlgID != NULL)
      {
         if (m_pDigestAlgorithms != NULL)
         {
            // search for matching digest alg
            itTmpAlg = m_pDigestAlgorithms->begin();
            bFoundThisOne = false;
            while (itTmpAlg != m_pDigestAlgorithms->end() && !bFoundThisOne)
            {
               if (*itTmpAlg == *pdigestAlgID)
               {
                  bFoundThisOne = true;
                  //break;
               }
               else
                  ++itTmpAlg;
            }
            if (!bFoundThisOne)
            {
               // requested oid not found in list
               bRet = false;
               //break;
            }
         }
         else
         {
            // requested oid not found in list because list doesn't exist
            bRet = false;
            //break;
         }
      }     // END if pdigestAlgID

      // find out if the requested digest encryption alg is in the list
      if (bRet && pdigestEncryptionAlgID != NULL)
      {
         if (m_pDigestEncryptionAlgorithms != NULL)
         {
            // search for matching digest encryption alg
            itTmpAlg = m_pDigestEncryptionAlgorithms->begin();
            bFoundThisOne = false;
            while (itTmpAlg != m_pDigestEncryptionAlgorithms->end() && !bFoundThisOne)
            {
               if (*itTmpAlg == *pdigestEncryptionAlgID)
               {
                  bFoundThisOne = true;
                  //break;
               }
               else
                  ++itTmpAlg;
            }
            if (!bFoundThisOne)
            {
               // requested oid not found in list
               bRet = false;
               //break;
            }
         }
         else
         {
            // requested oid not found in list because list doesn't exist
            bRet = false;
            //break;
         }
      }     // END if pdigestEncryptionAlgID

      // find out if the requested key encryption alg is in the list
      if (pkeyEncryptionAlgID != NULL)
      {
         if (m_pKeyEncryptionAlgorithms != NULL)
         {
            // search for matching key encryption alg
            itTmpAlg = m_pKeyEncryptionAlgorithms->begin();
            bFoundThisOne = false;
            while (itTmpAlg != m_pKeyEncryptionAlgorithms->end() && !bFoundThisOne)
            {
               if (*itTmpAlg == *pkeyEncryptionAlgID)
               {
                  bFoundThisOne = true;
                  //break;
               }
               else
                  ++itTmpAlg;
            } 
            if (!bFoundThisOne)
            {
               // requested oid not found in list
               bRet = false;
               //break;
            }
         }
         else
         {
            // requested oid not found in list because list doesn't exist
            bRet = false;
            //break;
         }
      }        // END if pkeyEncryptionAlgID

      // find out if the requested content encryption alg is in the list
      if (bRet && pcontentEncryptionAlgID != NULL)
      {
         if (m_pContentEncryptionAlgorithms != NULL)
         {
            // search for matching content encryption alg
            itTmpAlg = m_pContentEncryptionAlgorithms->begin();
            bFoundThisOne = false;
            while (itTmpAlg != m_pContentEncryptionAlgorithms->end() && !bFoundThisOne)
            {
               //RWC; ONLY Check OID, since RC2 +++ params are dynamic.
               //RWC; if (*pTemp == *pcontentEncryptionAlgID)
               if (itTmpAlg->algorithm == pcontentEncryptionAlgID->algorithm)
               {
                  bFoundThisOne = true;
                  //RWC;CAUSED RELEASE BUILD FAILURES...break;
               }     // IF our pcontentEncryptionAlgID
               else
               {
                  ++itTmpAlg;
                  if (itTmpAlg != m_pContentEncryptionAlgorithms->end())
                  {
                    //printThese(pTemp->algorithm->GetChar(), 
                    // pcontentEncryptionAlgID->algorithm.GetChar(), bFoundThisOne);
#ifdef BOB
                    std::cout << "BTIFindAlgIds: pTemp=" << itTmpAlg->algorithm.GetChar() <<
                          "pcontentEncryptionAlgID=" << 
                          pcontentEncryptionAlgID->algorithm.GetChar()<< "\n";
#endif
                  }     // END if pTemp
               }     // END IF our pcontentEncryptionAlgID
            }        // END while pTemp 
            if (!bFoundThisOne)
            {
               // requested oid not found in list
               bRet = false;
               //break;
            }  // END if bFoundThisOne
         }     // IF m_pContentEncryptionAlgorithms
         else
         {
            // requested oid not found in list because list doesn't exist
            bRet = false;
            //break;
         }     // END IF m_pContentEncryptionAlgorithms
      }        // END if pcontentEncryptionAlgID

      //break; // break out under normal condition
   }

   return bRet;
}     // END BTIFindAlgIds(...)


//////////////////////////////////////////////////////////////////////////
void CSM_BaseTokenInterface::ClearDigestEncryptionCapability()
{
   AsnOid oidEmpty;

   m_digestEncryptionOID = oidEmpty;
   if (m_pDigestEncryptionAlgorithms)
   {
      delete(m_pDigestEncryptionAlgorithms);
      m_pDigestEncryptionAlgorithms = NULL;
   }
}

//
//
void CSM_BaseTokenInterface::ClearKeyEncryptionCapability()
{
   AsnOid oidEmpty;
   //RWC; BAD NEWS!!!memset(&m_keyEncryptionOID, 0, sizeof(AsnOid));
   m_keyEncryptionOID = oidEmpty;
   if (m_pKeyEncryptionAlgorithms)
   {
      delete(m_pKeyEncryptionAlgorithms);
      m_pKeyEncryptionAlgorithms = NULL;
   }
}

//
//
SM_RET_VAL CSM_TokenInterface::SMTI_DigestData(
       CTIL::CSM_Buffer *pData,    // input
       CTIL::CSM_Buffer *pDigest,  // output 
       SNACC::AsnOid &OidDigest)    // input
{
   long lStatus;

   if (OidDigest.Len())
      BTISetPreferredCSInstAlgs(&OidDigest, NULL, NULL, NULL);
   lStatus = SMTI_DigestData(pData, pDigest);

   return(lStatus);
}        // END SMTI_DigestData(...)



_END_CTIL_NAMESPACE 

extern "C" {

#ifdef ADDED_DOUBLE_QUOTE_PROCESSING
//
//  THIS function is used by the DLLs.
long LIBCTILMGRDLL_API Make_argv(char *string, int *pargc, char ***pargv)
{
  long status=0;
  unsigned char *ptr=(unsigned char *)string;
  unsigned char *ptr2;
  int i=0;
  
  if (string[strlen(string)-1] == ' ')
      string[strlen(string)-1] = '\0';
  *pargv = (char **)calloc(1, 30*sizeof(char *));
            /* I do not expect more than 30 params. */
  /** FIRST, remove all duplicate spaces. **/
  for (i=0; i < (int)strlen(string); i++)
    if (string[i] == ' ' && string[i+1] == ' ')
      strcpy(&string[i], &string[i+1]);
  i = 0;
  while (ptr && i < 30)
  {
     if ((ptr2 = (unsigned char *)strchr((const char *)ptr, ' ')) == NULL)  /** find end of word. **/
       ptr2 = (unsigned char *)&string[strlen(string)];       /** point to end of word.**/
     (*pargv)[i] = (char *)calloc(1, (ptr2-ptr)+1);
     strncpy((*pargv)[i], (const char *)ptr, (ptr2-ptr));
     (*pargv)[i][(ptr2-ptr)] = '\0';
     i++;
     ptr = (unsigned char *)strchr((const char *)ptr, ' ');
     if (ptr)
          ptr++;   /* point past ' '. */
  }
  if (i>=30)
    fprintf(stderr, "tcpControl:ERROR Make_argv: more than 30 parameters, fix!\n");
  *pargc = i;
  return(status);
}
#endif      // ADDED_DOUBLE_QUOTE_PROCESSING
//
//  THIS function is used by the DLLs.
long LIBCTILMGRDLL_API Make_argv(char *string, int *pargc, char ***pargv)
{
  long status=0;
  unsigned char *ptr=(unsigned char *)string;
  unsigned char *ptr2;
  int i=0;
  
  if (string[strlen(string)-1] == ' ')
      string[strlen(string)-1] = '\0';
  *pargv = (char **)calloc(1, 30*sizeof(char *));
            /* I do not expect more than 30 params. */
  //RWC; DO NOT REMOVE extra ' ', since may be part of "" quoted params.
  i = 0;
  while (ptr && i < 30)
  {
     if (ptr[0] == '"')
     {
        ptr++;    // POINT past "".
        if ((ptr2 = (unsigned char *)strchr((const char *)ptr, '"')) == NULL)  /** find end of parameter. **/
          ptr2 = (unsigned char *)&string[strlen(string)];       /** point to end of word, ignore missing "".**/
     }
     else if ((ptr2 = (unsigned char *)strchr((const char *)ptr, ' ')) == NULL)  /** find end of word. **/
       ptr2 = (unsigned char *)&string[strlen(string)];       /** point to end of word.**/
     (*pargv)[i] = (char *)calloc(1, (ptr2-ptr)+1);
     strncpy((*pargv)[i], (const char *)ptr, (ptr2-ptr));
     (*pargv)[i][(ptr2-ptr)] = '\0';
     i++;
     ptr = (unsigned char *)strchr((const char *)ptr2, ' ');
     while (ptr && *ptr == ' ')    // RWC; HERE, remove extra ' ' between params.
     {
        ptr++;   /* point past ' '. */
     }
  }
  if (i>=30)
    fprintf(stderr, "tcpControl:ERROR Make_argv: more than 30 parameters, fix!\n");
  *pargc = i;
  return(status);
}

//
//
void LIBCTILMGRDLL_API Delete_argv(int argc, char **pargv)
{
    if (argc > 0 && pargv)
    {   
        for (int i=0; i < argc; i++)
            free(pargv[i]);
        free(pargv);
    }
}
}   //END Extern "C"
// EOF sm_BaseTokenInterface.cpp
