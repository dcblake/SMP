
//////////////////////////////////////////////////////////////////////////
//
//  File:  CSM_CSMime.cpp
//  These routines support the CSMIME class.
//
// Contents: Contains CSMIME member functions.
// 
// Project:  SMP/libCert
//
// Req Ref:  SMP RTM #5
//
// Last Updated:	16 December 2004                                       
//                Req Ref:  SMP RTM #5  AES Crypto++                                
//                Sue Beauchamp <Sue.Beauchamp@it.baesystems.com>        
//
////////////////////////////////////////////////////////////////////////////////
#include <string.h>
#include "sm_apiCert.h"
#include "sm_common.h"
#include "sm_AppLogin.h"
_BEGIN_CERT_NAMESPACE 

using namespace CTIL;//SNACC;
using SNACC::SnaccException;
//////////////////////////////////////////////////////////////////////////
CSMIME::CSMIME() 
{
}



//////////////////////////////////////////////////////////////////////////
CSMIME::~CSMIME()
{ 
}           // END ~CSMIME

//////////////////////////////////////////////////////////////////////////
CSM_CSInst *CSMIME::FindInstByDN_SignerOrEncrypter(char *pDn, bool bSignerFlag)
{
   CSM_CtilInstLst::iterator itInst;
   CSM_CSInst *pInstCS = NULL;
   CSM_DN *pDn2 = NULL;
   char *pszDn = ConvertDNString(pDn);  //CONVERT to "," delimited form  
   CSM_DN Dn2(pszDn);
   bool found = false;

   for (itInst = m_pCSInsts->begin(); 
        itInst != m_pCSInsts->end() && !found;
        ++itInst)
   {
      pInstCS = (CSM_CSInst *)(*itInst)->AccessTokenInterface()->AccessCSInst();
      if (pInstCS)
      {
        pDn2 = pInstCS->AccessSubjectDN();
         if (pDn2)
         {
           const char *pszDn2=*pDn2;   //DEBUG only.
           if (pszDn)
           {
             if (strcmp(pszDn, pszDn2) == 0 ||
                 Dn2 == *pDn2)
             {
                if (bSignerFlag && pInstCS->IsSigner())          // Signer
                   found = true;
                else if (!bSignerFlag && pInstCS->IsEncrypter())   // Encrypter
                   found = true;
             }    // END if DN strings match
           }
         }
      }        // END IF instance handles certificates.
   }        // END FOR each instance
   
   if (pszDn)
      free(pszDn);
   if (found == false)
      pInstCS = NULL;

   return pInstCS;
}     // END CSMIME::FindInstByDN_SignerOrEncrypter(...)

//////////////////////////////////////////////////////////////////////////
CSM_CSInst *CSMIME::FindInstByDN(char *pDn)
{
   CSM_CSInst *pInstCS   = NULL;
   CSM_DN *pDn2    = NULL;
   char *pszDn = ConvertDNString(pDn);  //CONVERT to "," delimited form  
   CSM_DN Dn2(pszDn);
   bool found = false;

   if (m_pCSInsts == NULL)
       return(pInstCS);
       
   for (m_itInst = m_pCSInsts->begin();     // SET the first item in the list.
        m_itInst != m_pCSInsts->end() && !found;
        ++m_itInst)
   {
      pInstCS = (CSM_CSInst *)(*m_itInst)->AccessTokenInterface()->AccessCSInst();
      if (pInstCS)
      {
         pDn2 = pInstCS->AccessSubjectDN();
         if (pDn2)
         {
           const char *pszDn2=*pDn2;   //DEBUG only.
           if (pszDn)
           {
             if (strcmp(pszDn, pszDn2) == 0 ||
                 Dn2 == *pDn2)
                found = true;
           }
         }
      }  // END IF instance handles certificates.
   }  // END FOR each instance in list
   
   if (pszDn)
      free(pszDn);
   if (found == false)
      pInstCS = NULL;

   return pInstCS;
}     // END CSMIME::FindInstByDN(...)


//////////////////////////////////////////////////////////////////////////
// IT IS ASSUMED that FindInstByDN(...) has already been called to set 1st 
// DN by string search.  This routine allows a search for multiple logins
//  with the same DN name.
CSM_CSInst *CSMIME::FindNextInstByDN(char *pDn)
{
   CSM_CSInst *pInstCS = NULL;
   CSM_DN *pDn2 = NULL;
   char *pszDn = ConvertDNString(pDn);  //CONVERT to "," delimited form  
   CSM_DN Dn2(pszDn);
   bool found = false;

   if (m_pCSInsts == NULL || m_itInst == m_pCSInsts->end())
       return(NULL);

   for (; // don't increment just look at next inst
        m_itInst != m_pCSInsts->end() && !found;
        ++m_itInst)
   {
      pInstCS = (CSM_CSInst *)(*m_itInst)->AccessTokenInterface()->AccessCSInst();
      if (pInstCS)
      {
         pDn2 = pInstCS->AccessSubjectDN();
         if (pDn2)
         {
           const char *pszDn2=*pDn2;   //DEBUG only.
           if (pszDn)
           {
             if (strcmp(pszDn, pszDn2) == 0 ||
                 Dn2 == *pDn2)
                found=true;
           }
         }
      }        // END IF instance handles certificates.
      pDn2 = NULL; 
   }           // END FOR each instance in list.
   
   if (pszDn)
      free(pszDn);

   if (found == false)
      pInstCS = NULL;
   return pInstCS;
}   // END CSMIME::FindNextInstByDN(...)


//////////////////////////////////////////////////////////////////////////
// 
//  Function:  SetDefaultCTIL()
//
//  NOTE:  Replaced CSM_CommonCtil with CSM_Common for AES Requirement to
//         strip out CSM_CommonCTIL class
//
//////////////////////////////////////////////////////////////////////////
void CSMIME::SetDefaultCTIL() 
{
   CSM_CSInst *pNewInstance = NULL;
   CSM_CtilInst *pNewInstanceReturned = NULL;

   SME_SETUP("SetDefaultCTIL");

   if ((pNewInstance = new CSM_CSInst) == NULL)
          SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   CSM_Common *pCommon=new CSM_Common;
   pCommon->SetCSInst(pNewInstance); // ALLOW access to the CSM_CSInst 
                                         //  beyond CSM_TokenInterface.
                                         //  (This feature is optional, but
                                         //  necessary for cert access).

   pNewInstanceReturned = GLOBALAddLoginFinishCTIL(*this, pNewInstance, 
       pCommon, "Common");

   //this->m_pCSInsts->FirstL()
   pNewInstanceReturned->SetApplicable();
   //this->m_pCSInsts->FirstL()
   pNewInstanceReturned->SetUseThis();
            // PRE-Load a common CTIL entry for access to certain algs.

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}



_END_CERT_NAMESPACE 

// EOF CSM_CSMime.cpp
