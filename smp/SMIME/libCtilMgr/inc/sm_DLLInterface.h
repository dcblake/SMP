/* @(#) sm_DLLInterface.h 1.5 12/13/99 16:18:15 */

// 
//  sm_DLLInterface.h
//

#ifndef CSM_TokenInterfaceDLL_DEF
#define CSM_TokenInterfaceDLL_DEF

#ifdef WIN32_NOT_USED
#if defined(WIN32) && !defined(_WINDOWS_)  //RWC;special check for MFC GUI apps.
#include <windows.h>
#endif
#endif

_BEGIN_CTIL_NAMESPACE 

class CSM_CtilMgr;
class CSM_TokenInterface;

typedef SM_RET_VAL (*DLLBuildTokenInterface_DEF)(CSM_CtilMgr &Csmime, char *lpszBuildArgs); 
typedef char * (*DLLGetId_DEF)(); 
typedef char * (*DLLMallocDiag_DEF)(); 


class LIBCTILMGRDLL_API CSM_TokenInterfaceDLL
{
private:
   //FOR MS Windows platforms, this member variable is actually a 
   //  HINSTANCE m_TokenDLLInstance;   // MS CALL. DLL Load instance.
   //  It was defined as a "void *" to remove the #include of the windows.h.
    void *m_TokenDLLInstance;   //Unix CALL. DLL Load instance.
    void Clear(){ m_lpszDLLFileName = NULL; m_TokenDLLInstance = NULL;                  m_lpszBuildArgs = NULL; m_pEmptyTokenInterface = NULL;}
public:
    CSM_TokenInterfaceDLL();
    CSM_TokenInterfaceDLL(
        CSM_CtilMgr &Csmime,
        char *lpszDLLFileName, 
        char *lpszBuildArgs);
    CSM_TokenInterfaceDLL(
        char *lpszDLLFileName, 
        char *lpszBuildArgs);
    void LoadDLL(char *lpszDLLFileName, char *lpszStartupArgs);
    void CreateLogins(CSM_CtilMgr &Csmime);
    long CheckMallocDiag();
    void *GetTokenDLLInstance(){ return m_TokenDLLInstance; }
    ~CSM_TokenInterfaceDLL();
    // DECLARE global functions exported from the DLL for ID and creation of class objects.
    DLLBuildTokenInterface_DEF m_pDLLBuildTokenInterface;
    DLLGetId_DEF m_pDLLGetId;
	DLLMallocDiag_DEF m_pDLLMallocDiag;


    char *m_lpszDLLFileName;
    char *m_lpszBuildArgs;

    CSM_TokenInterface *m_pEmptyTokenInterface;   // Meant for Alg lookup.
};

_END_CTIL_NAMESPACE 

#endif
// EOF sm_DLLInterface.h
