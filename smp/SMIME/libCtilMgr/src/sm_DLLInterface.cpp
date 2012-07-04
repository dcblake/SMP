//
//  sm_DLLInterface.cpp
//
//

#include <string.h>
#include "sm_apiCtilMgr.h"
#if defined(WIN32) && !defined(_WINDOWS_)  //RWC;special check for MFC GUI apps.
#include <windows.h>
#endif


#ifndef WIN32
#include <dlfcn.h>
#endif

_BEGIN_CTIL_NAMESPACE 
using namespace SNACC; 

//
//
CSM_TokenInterfaceDLL::CSM_TokenInterfaceDLL()
{
    Clear();
}

//
//
CSM_TokenInterfaceDLL::CSM_TokenInterfaceDLL(
    CSM_CtilMgr &Csmime,
    char *lpszDLLFileName, 
    char *lpszBuildArgs)
{
    Clear();
    LoadDLL(lpszDLLFileName, lpszBuildArgs);
    //CreateLogins(Csmime);
#ifdef WIN32
    Csmime; // AVOIDS warning.
#endif
}

//
//
CSM_TokenInterfaceDLL::CSM_TokenInterfaceDLL(char *lpszDLLFileName, 
                                             char *lpszBuildArgs)
{
    Clear();
    LoadDLL(lpszDLLFileName, lpszBuildArgs);
}
//
//
void CSM_TokenInterfaceDLL::LoadDLL(char *lpszDLLFileName, 
                                    char *lpszBuildArgs)
{
    CSM_Buffer CertBuf; // Tmp empty cert buffer for empty CTIL.
      //HINSTANCE LoadLibrary(
        //LPCTSTR lpLibFileName   // file name of module
        //);
    SME_SETUP("CSM_TokenInterfaceDLL::LoadDLL");

    m_lpszDLLFileName = (char *) calloc(1, strlen(lpszDLLFileName) + 5);
    strcpy(m_lpszDLLFileName, lpszDLLFileName);
#ifdef WIN32
   strcat(m_lpszDLLFileName, ".DLL");
    HINSTANCE TmpInstance = LoadLibrary(m_lpszDLLFileName);
    m_TokenDLLInstance = TmpInstance;  //RWC; done to allow removal of #include
                     //  of windows.h from all include files.
#elif  defined (Linux) || defined (SunOS) || defined (SCO_SV)
    strcat(m_lpszDLLFileName, ".so");
    m_TokenDLLInstance = dlopen(m_lpszDLLFileName, RTLD_NOW);
#elif  defined (HPUX) 
    strcat(m_lpszDLLFileName, ".sl");
    m_TokenDLLInstance = dlopen(m_lpszDLLFileName, RTLD_NOW);
#else
    SME_THROW(22, "Shared library not supported on this platform.", NULL);
#endif

   if (m_TokenDLLInstance ==  NULL) 
   {     
      char bbb[10000];
        sprintf(bbb, "Unable to load DLL: %s", m_lpszDLLFileName);
#if defined (Linux) || defined (SunOS) || defined (SCO_SV)
        strcat(bbb,"\nDLERROR= ");
        strcat(bbb,dlerror());
#endif
        SME_THROW(22, bbb, NULL);
    }

    //FARPROC GetProcAddress(
  //HMODULE hModule,    // handle to DLL module
  //LPCSTR lpProcName   // name of function
#ifdef WIN32
    m_pDLLBuildTokenInterface =
        (DLLBuildTokenInterface_DEF)GetProcAddress((HINSTANCE)m_TokenDLLInstance, 
        "DLLBuildTokenInterface");
    m_pDLLMallocDiag = (DLLMallocDiag_DEF)GetProcAddress((HINSTANCE)m_TokenDLLInstance, "DLLMallocDiag");
    m_pDLLGetId = (DLLGetId_DEF)GetProcAddress((HINSTANCE)m_TokenDLLInstance, "DLLGetId");
#else
    m_pDLLBuildTokenInterface = 
        (DLLBuildTokenInterface_DEF)dlsym(m_TokenDLLInstance, 
        "DLLBuildTokenInterface");
    m_pDLLMallocDiag = (DLLMallocDiag_DEF)dlsym(m_TokenDLLInstance, "DLLMallocDiag");
    m_pDLLGetId = (DLLGetId_DEF)dlsym(m_TokenDLLInstance, "DLLGetId");
#endif
    if (m_pDLLBuildTokenInterface == NULL || m_pDLLGetId == NULL) 
    {
        char bbb[1000];
        sprintf(bbb, "BAD DLL Address LOADs, %s", m_lpszDLLFileName);
#if defined (Linux) || defined (SunOS) || defined (SCO_SV)
        strcat(bbb,"\nDLERROR= ");
        strcat(bbb,dlerror());
#endif
        SME_THROW(22, bbb, NULL);
    }
    //if (m_pDLLGetId)
    //  cout << "CTIL ID = " <<(m_pDLLGetId()) << "\n";
    //else
    //    cout << "CTIL ID Function not present.";
    if (lpszBuildArgs)
        m_lpszBuildArgs = strdup(lpszBuildArgs);
    else
        m_lpszBuildArgs = NULL;

	// check if models are same on both sides of interface
	// NOTE TO USER: 
	// If an exception occurs during CheckMallocDiag() processing, there is an
    // inconsistent memory model:  Release application loads debug CTIL DLL (or vice-versa)
	// We tried to catch this exception, but the compiler interferes with the catch processing.
    CheckMallocDiag();


#ifdef PIERCE
    CSM_CtilMgr TmpCsmime;   // Tmp empty CSInst container.
    if (m_pDLLGetId)
    {    
     char *ptr;
      ptr = (m_pDLLGetId)();
      char ptr2[100];
      ptr2[0] = '\0';
      strcat(ptr2, ptr);  // MUST HAVE ID Match to create Login.
      strcat(ptr2, " NULL NULL NULL BLOBTESTID");
      (m_pDLLBuildTokenInterface)(TmpCsmime, ptr2);
    }
    // KEEP LOCAL copy of the empty CSInst.
    if (TmpCsmime.m_pCSInsts)
    {
      m_pEmptyTokenInterface = TmpCsmime.m_pCSInsts->SetCurrToFirst()->
            AccessTokenInterface();
      TmpCsmime.m_pCSInsts->SetCurrToFirst()->SetTokenInterface(NULL);    
            // CLEAR to prevent CMIME destructor from removing from our memory.
    }
#endif
    SME_FINISH
    SME_CATCH_SETUP

      // catch/cleanup logic as necessary
    SME_CATCH_FINISH
}

//
//
CSM_TokenInterfaceDLL::~CSM_TokenInterfaceDLL()
{
    if (m_lpszDLLFileName)
      free(m_lpszDLLFileName);
    if (m_TokenDLLInstance)
#ifdef WIN32
      FreeLibrary((HINSTANCE)m_TokenDLLInstance); 
#else
      dlclose(m_TokenDLLInstance);
#endif
      if (m_lpszBuildArgs)
          free(m_lpszBuildArgs);
}


//
//  This method is automatically called by the constructor if there
//  are any arguments.
void CSM_TokenInterfaceDLL::CreateLogins(CSM_CtilMgr &Csmime)
{
    if (m_pDLLBuildTokenInterface && m_lpszBuildArgs && strlen(m_lpszBuildArgs))
    {
        (m_pDLLBuildTokenInterface)(Csmime, m_lpszBuildArgs);
        //cout << "CSM_TokenInterfaceDLL::CreateLogins: " << (m_pDLLGetId)() << "\n";
    }
}

long CSM_TokenInterfaceDLL::CheckMallocDiag()
{
   char *ptr;
   long lstatus = 0;
   try 
   {

      if (m_pDLLMallocDiag)
	  {
	     ptr = (m_pDLLMallocDiag)();
         if (ptr)
		 {
	   	    //cout << "CSM_TokenInterfaceDLL::CheckMallocDiag: Checking for inconsistent memory model\n " 
			//     << (m_pDLLGetId)() << "\n";
            free(ptr);
		 }
	  }
   }

   // NOTE TO USER: 
   // Inconsistent memory model:  Release application loads debug CTIL DLL (or vice-versa)
   // This catch doesn't work properly, we try to catch the exception anyway.
   catch (...) 
   {
	  SME_SETUP("CSM_TokenInterfaceDLL::CheckMallocDiag");
      char buf[100];
	  char *id = (m_pDLLGetId)();
      sprintf(buf,"Inconsistent memory model:  RELEASE application loads DEBUG ctil DLL (or vice-versa) for:  %s.",
              id);

	  //cout << "\nid = " << id << endl;
	  //cout.flush();
	  SME_THROW(23, buf, NULL );
      //SME_THROW(23,"Inconsistent memory model:  RELEASE application loads DEBUG ctil DLL (or vice-versa).", NULL );
      free (id);
      
	  SME_FINISH
      SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      SME_CATCH_FINISH

	}

   return(lstatus);
}

_END_CTIL_NAMESPACE 

// EOF sm_DLLInterface.cpp
