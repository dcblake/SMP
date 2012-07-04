
////////////////////////////////////////////////////////////////////////////////
//
// File:  sm_CtilMgr.cpp
//
// Contents: 
// These routines support the CSM_CtilMgr class.

// Project:  SMP/libCtilMgr
//
// Req Ref:  SMP RTM #5
//
// Last Updated:	16 December 2004                                       
//                Req Ref:  SMP RTM #5  AES Crypto++                                
//                Sue Beauchamp <Sue.Beauchamp@it.baesystems.com>        
//
////////////////////////////////////////////////////////////////////////////////
#include "sm_apiCtilMgr.h"
#include "sm_common.h"

_BEGIN_CTIL_NAMESPACE 
using namespace SNACC; 
//RWC;5/22/04;typedef CSM_ListC<CSM_CtilInst> CSM_CtilInstLstInternal;
CSM_LstTokenInterfaceDLL CSM_CtilMgr::m_TIList; // "static" definition
CSM_ThreadLock CSM_CtilMgr::m_ThreadLock;       // "static" definition

//////////////////////////////////////////////////////////////////////////
CSM_CtilMgr::CSM_CtilMgr() 
{
    m_pCSInsts = NULL; 
}

//////////////////////////////////////////////////////////////////////////
// 
//  Function:  SetDefaultCTIL()
//
//  NOTE:  Replaced CSM_CommonCtil with CSM_Common for AES Requirement to
//         strip out CSM_CommonCTIL class
//
//////////////////////////////////////////////////////////////////////////
void CSM_CtilMgr::SetDefaultCTIL() 
{
    CSM_Common *pCommonCTIL=new CSM_Common;
    GLOBALAddLoginFinishCTIL(*this, pCommonCTIL, "CommonCTIL");
    (*m_pCSInsts->begin())->SetApplicable();
    (*m_pCSInsts->begin())->SetUseThis();
            // PRE-Load a common CTIL entry for access to certain algs.
}


//////////////////////////////////////////////////////////////////////////
CSM_CtilMgr::~CSM_CtilMgr()
{ 
   if (m_pCSInsts) 
   {
       CSM_CtilInstLst::iterator itInst;
       for (itInst =  m_pCSInsts->begin();
            itInst != m_pCSInsts->end();
            ++itInst)
        {
            delete *itInst;     //RWC; MUST BE explicitely deleted since pointer.
        }   // END FOR each instance in the list.
      delete m_pCSInsts;
   }       // END IF m_pCSInsts
}

//////////////////////////////////////////////////////////////////////////
void CSM_CtilMgr::ClearFlag(char chClearFlag)
{
   CSM_CtilInstLst::iterator itTmpInst;

   SME_SETUP("CSM_CtilMgr::ClearFlag");

   if (m_pCSInsts)
   {
      for (itTmpInst = m_pCSInsts->begin(); 
           itTmpInst != m_pCSInsts->end();
           ++itTmpInst)
      {
         if ((chClearFlag & SM_INST_APPLICABLE) || 
               (chClearFlag & SM_INST_ALL))
            (*itTmpInst)->SetApplicable(false);
         if ((chClearFlag & SM_INST_USE_THIS) || 
               (chClearFlag & SM_INST_ALL))
            (*itTmpInst)->SetUseThis(false);
      } // END FOR each instance in list
   }    // END IF m_pCSInsts
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
//Sets the UseThis flag on all signing capable logins
void CSM_CtilMgr::UseAll()                                      
{
   CSM_CtilInstLst::iterator itTmpInst;

   SME_SETUP("CSM_CtilMgr::UseAll");

   if (m_pCSInsts)
   {
      for (itTmpInst = m_pCSInsts->begin(); 
           itTmpInst != m_pCSInsts->end();
           ++itTmpInst)
         (*itTmpInst)->SetUseThis(true);
   }
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
//Sets the UseThis and Applicable flags on all signing capable logins
//////////////////////////////////////////////////////////////////////////
void CSM_CtilMgr::UseAllEncryptors()                                      
{
   CSM_CtilInstLst::iterator itTmpInst;

   SME_SETUP("CSM_CtilMgr::UseAll");

   if (m_pCSInsts)
   {
      for (itTmpInst = m_pCSInsts->begin(); 
           itTmpInst != m_pCSInsts->end();
           ++itTmpInst)
      {
         (*itTmpInst)->SetUseThis(true);
         (*itTmpInst)->SetApplicable();  
      }

   }
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// FindCSInstAlgIds
// This function searches for any specified algorithm IDs
// in the appropriate private members algorithm lists for the specified
// algorithm.  If all specified algorithms are found, a TRUE is returned.
// Any of the parameters can be NULL; it is expected that at least one is 
// not NULL.
CSM_CtilInst  *CSM_CtilMgr::FindCSInstAlgIds(CSM_AlgVDA *pdigestAlgID, 
            CSM_AlgVDA *pdigestEncryptionAlgID,
            CSM_AlgVDA *pkeyEncryptionAlgID,
            CSM_AlgVDA *pcontentEncryptionAlgID)
{
   CSM_CtilInstLst::iterator itTmpInst;

   SME_SETUP("CSM_CtilMgr::FindCSInstAlgIds");

   if (m_pCSInsts)
   {
      for (itTmpInst =  m_pCSInsts->begin(); 
           itTmpInst != m_pCSInsts->end() &&
           !(*itTmpInst)->FindAlgIds(pdigestAlgID, 
               pdigestEncryptionAlgID, pkeyEncryptionAlgID, 
                pcontentEncryptionAlgID);
           ++itTmpInst);
   }
   SME_FINISH_CATCH
   return (*itTmpInst);
}

//////////////////////////////////////////////////////////////////////////
void CSM_CtilMgr::InstanceLock(char chLockFlag)
{
   CSM_CtilInstLst::iterator itTmpInst;

   SME_SETUP("CSM_CtilMgr::InstanceLock");

   if (m_pCSInsts)
   {
      for (itTmpInst = m_pCSInsts->begin(); 
           itTmpInst != m_pCSInsts->end();
           ++itTmpInst)
      {
         if (chLockFlag & SM_INST_ALL)
            (*itTmpInst)->AccessTokenInterface()->SMTI_Lock();
         else
         {
            if ((chLockFlag & SM_INST_APPLICABLE) && ((*itTmpInst)->
                  IsApplicable()))
               (*itTmpInst)->AccessTokenInterface()->SMTI_Lock();
            if ((chLockFlag & SM_INST_USE_THIS) && ((*itTmpInst)->
                  IsThisUsed()))
               (*itTmpInst)->AccessTokenInterface()->SMTI_Lock();
         }
      }
   }
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
void CSM_CtilMgr::InstanceUnlock(char chLockFlag)
{
   CSM_CtilInstLst::iterator itTmpInst;

   SME_SETUP("CSM_CtilMgr::InstanceUnlock");

   if (m_pCSInsts)
   {
      for (itTmpInst = m_pCSInsts->begin(); 
           itTmpInst != m_pCSInsts->end();
           ++itTmpInst)
      {
         if (chLockFlag & SM_INST_ALL)
            (*itTmpInst)->AccessTokenInterface()->SMTI_Unlock();
         else
         {
            if ((chLockFlag & SM_INST_APPLICABLE) && ((*itTmpInst)->
                  IsApplicable()))
               (*itTmpInst)->AccessTokenInterface()->SMTI_Unlock();
            if ((chLockFlag & SM_INST_USE_THIS) && ((*itTmpInst)->
                  IsThisUsed()))
               (*itTmpInst)->AccessTokenInterface()->SMTI_Unlock();
         }
      }
   }
   SME_FINISH_CATCH
}


CSM_CtilInst * CSM_CtilMgr::FindInstByID(char *pId)
{
   return (FindInst(pId, FIND_TYPE_ID));
}

CSM_CtilInst *CSM_CtilMgr::FindInst(char *pStr, FindType type)
{
   CSM_CtilInstLst::iterator itTmpInst;
   char       *pId     = NULL;
   bool        found   = false;
   itTmpInst = m_pCSInsts->begin();
   while ( ((itTmpInst != m_pCSInsts->end()) != NULL) && (found == false) )
   {
      switch (type)
      {
      case FIND_TYPE_ID:
         if ((*itTmpInst)->AccessID())
         {
           pId = (*itTmpInst)->AccessID();
           if (strcmp(pId, pStr) == 0)
             found=true;
         }
         break;
      }
      if (!found)
        ++itTmpInst;;
   }        // END while each instance in list

   if (found == false)
      return (CSM_CtilInst *) NULL;
   else
      return *itTmpInst;
}


//////////////////////////////////////////////////////////////////////////
// THIS ROUTINE converts "@" formatted DN Strings to "," delimited strings
//  as used by the CML (according to the RFC specification).
//  (This modification was made to accommodate recent SFL integration with CML.
char *CSM_CtilMgr::ConvertDNString(char *pszDn)
{
    char *ptr=NULL;
    char *p3;

    if (pszDn && (p3=strchr(pszDn, ',')) == NULL)  // IF any "@" chars are present.
    {
        char *pszSource=strdup(pszDn);
        char *p1;
        bool bStop=false;
        ptr = (char *)calloc(1, strlen(pszSource)+1);
        while(!bStop && (p1=strrchr(pszSource, '@')) != NULL)
        {
            if (strrchr(p1, '=') == NULL)  // CHECK for special case 
                                                  //of e-mail address in RDN.
                                                  //it will be missing '='.
            {
                char *p2 = p1;
                *p2 = 'A';                          // TMP, override
                p1 = strrchr(pszSource, '@');       // SKIP one.
                *p2 = '@';                          // TMP, replace '@'
            }
            if (p1)
            {
                strcat(ptr, &p1[1]);    // COPY just the RDN (e.g. CN=Bob).
                strcat(ptr, ",");
                *p1 = '\0';              // Terminate working string at "@".
            }
            else
               bStop = true;
        }
        // NOW, take care of the 1st entry.
        strcat(ptr, pszSource);
        if (pszSource)
           free(pszSource);
    }
    if (ptr == NULL && pszDn)  // THEN simply fill in original
        ptr = strdup(pszDn);
    return(ptr);
}



//
//
// Perform CTIL independent operations
CSM_CtilInst LIBCTILMGRDLL_API *GLOBALAddLoginFinishCTIL(CSM_CtilMgr &Csmime,
   CSM_TokenInterface *pTokenInterface, // IN, actual instance, setup to 
                                        //  specific CTIL.
   char *lpszID)        // IN,OUT id of specific login.
{
   CSM_CtilInst *pNewInstance = NULL;

   SME_SETUP("GLOBALAddLoginFinishCTIL");

   if ((pNewInstance = new CSM_CtilInst) == NULL)
          SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   pNewInstance = GLOBALAddLoginFinishCTIL(Csmime, pNewInstance, 
       pTokenInterface, lpszID);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return(pNewInstance);

}

CSM_CtilInst LIBCTILMGRDLL_API *GLOBALAddLoginFinishCTIL(CSM_CtilMgr &Csmime,
   CSM_CtilInst *pNewInstance,     // INPUT
   CSM_TokenInterface *pTokenInterface, // IN, actual instance, setup to 
                                        //  specific CTIL.
   char *lpszID)        // IN,OUT id of specific login.
{
   //RWC;3/22/04;CSM_CtilInstLstInternal *pCSInstsInternal;
   SME_SETUP("GLOBALAddLoginFinishCTIL new Instance");

      if (Csmime.m_pCSInsts == NULL)
      {
         if ((Csmime.m_pCSInsts = new CSM_CtilInstLst) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
      }
      //RWC;3/22/04;pCSInstsInternal= (CSM_CtilInstLstInternal *)Csmime.m_pCSInsts;
      //RWC;5/12/02; SPECIAL NOTE; using SFL version of list here in order
      //  to specially load the CTIL MGR version of the list with the same
      //  sub-class pointer as the CSMIME libCert version.
      //RWC;5/12/02;pCSInstsInternal->AppendL(pNewInstance);
      Csmime.m_pCSInsts->insert(Csmime.m_pCSInsts->end(), pNewInstance);
      // now, fill in what we can in the instance
      // store token interface pointer
      pNewInstance->SetTokenInterface(pTokenInterface);
      // set an id
      pNewInstance->SetID(&lpszID[0]);
      pNewInstance->SetUseThis();

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return(pNewInstance);

}




CSM_CtilInst *CSM_CtilMgr::AddLogin(char *lpszDLLName, char *lpszBuildupArgs)
{
    return AddDLLLibrary(lpszDLLName, lpszBuildupArgs);  // Loads Lib and adds CSInst.
}

//
//
CSM_CtilInst *CSM_CtilMgr::AddDLLLibrary(char *lpszDLLName, char *lpszBuildupArgs)
{
    CSM_LstTokenInterfaceDLL::iterator itTmpDLLIF;

    SME_SETUP("CSM_AppLogin::AddDLLLibrary(DLLName,StartupArgs)");
    // FIRST, attempt to access this DLL.
                                    //"sm_free3DLL.DLL");

    // FIRST, check to see if this DLL library is already loaded.
    m_ThreadLock.threadLock();  //control access to "static" list of 
                                //  .so/.DLL objects.
    for (itTmpDLLIF =  m_TIList.begin(); 
         itTmpDLLIF != m_TIList.end() && 
              strncmp(itTmpDLLIF->m_lpszDLLFileName, lpszDLLName, strlen(lpszDLLName)) != 0;
        ++itTmpDLLIF);     // SEARCH for our DLL already loaded

    // NEXT, IF not loaded, then create a new reference.
    if (itTmpDLLIF == m_TIList.end())       // NONE present yet.
    {
        //SME(ptmpDLLIF = new CSM_TokenInterfaceDLL(*this,lpszDLLName,lpszBuildupArgs));
        itTmpDLLIF = m_TIList.append();
        if (itTmpDLLIF != m_TIList.end())
           itTmpDLLIF->LoadDLL(lpszDLLName,lpszBuildupArgs);
    }       // END if ptmpDLLIF == NULL
    
    // NEXT, In both cases, load our CSM_CSInst details.
    if (itTmpDLLIF != m_TIList.end())       // present and ready for use.
    {
        if ((itTmpDLLIF->m_pDLLBuildTokenInterface)(*this, lpszBuildupArgs) != 0)
                                        // FILL Csmime with instances of 
                                        //  this DLL Using the lpszBuildupArgs.
        {
           char buf[1024];
           sprintf(buf, "DYNAMIC DLL m_pDLLBuildTokenInterface failed, |%s|.", 
                   lpszBuildupArgs);
           SME_THROW(24, buf, NULL);
        }
    }
    m_ThreadLock.threadUnlock();

    //#####################################################
    SME_FINISH
    SME_CATCH_SETUP
    m_ThreadLock.threadUnlock();
    SME_CATCH_FINISH
    //#####################################################

    CSM_CtilInst *newInst=NULL;
    if (m_pCSInsts && itTmpDLLIF != m_TIList.end())
        newInst = m_pCSInsts->back();

    return newInst;

}


//
//
CSM_TokenInterface *CSM_CtilMgr::LookupDLLLibrary(SNACC::AlgorithmIdentifierVDA *pAlgID)
                        // Algorithm for CTIL of interest.
{
    CSM_LstTokenInterfaceDLL::iterator itTmpDLLIF;
    CSM_TokenInterface *pResultTI=NULL;
    CSM_AlgVDA AlgId(*pAlgID);
                                    //"sm_free3DLL.DLL");

    // FIRST, check to see if this DLL library is already loaded.
    for (itTmpDLLIF = m_TIList.begin(); 
         itTmpDLLIF != m_TIList.end() && 
            (pResultTI == NULL); 
         ++itTmpDLLIF)     
                                          // SEARCH for our DLL already loaded!!
        {
            // Check to see if this CTIL supports our algorithm.
            if (itTmpDLLIF->m_pEmptyTokenInterface)
            {
                if (itTmpDLLIF->m_pEmptyTokenInterface->BTIFindAlgIds(NULL, 
                    &AlgId, NULL, NULL))    // CHECK Signature Algs.
                   pResultTI = itTmpDLLIF->m_pEmptyTokenInterface;
                else if (itTmpDLLIF->m_pEmptyTokenInterface->BTIFindAlgIds(NULL, 
                    NULL, &AlgId, NULL))    // CHECK Key Encryption Algs.
                   pResultTI = itTmpDLLIF->m_pEmptyTokenInterface;
            }
        }

    return pResultTI;
}

//#####################################################
// THIS special class was created for the sole purpose of
//  copying the "const char *" data (stack included) from the
//  SNACC::SnaccException.  This is only necessary if the
//  DLL that threw the exception was unloaded before the 
//  application can access the data.

CTILException::CTILException(const CTILException &that) throw()
{
   operator=(that);
}
CTILException::CTILException(const SNACC::SnaccException &that) throw()
{
   operator=(that);
} 

CTILException & CTILException::operator=(const SNACC::SnaccException &that)
{
   m_whatStr = that.what();
   that.getCallStack(m_ss);
	return *this;
}

CTILException & CTILException::operator=(const CTILException &that)
{
	m_ss.flush();
	m_ss << that.m_ss.rdbuf();
   m_whatStr = that.what();
   that.getCallStack(m_ss);
	return *this;
}

CTILException::~CTILException() throw()
{
   // do nothing
}

void CTILException::getCallStack(std::ostream &os) const
{
   SnaccException::getCallStack(os);
   os << m_ss.rdbuf();
}

_END_CTIL_NAMESPACE 


// EOF CSM_CSMime.cpp
