// sm_rsaDLL.cpp : Defines the entry point for the DLL application.
//
#ifdef WIN32

#include "stdafx.h"
#include "sm_rsaDLL.h"

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
    }
#ifdef WIN32
    lpReserved; // AVOIDS compiler warning
    hModule;
#endif
    return TRUE;
}


// This is an example of an exported variable
SM_RSADLL_API int nSm_rsaDLL=0;

// This is an example of an exported function.
SM_RSADLL_API int fnSm_rsaDLL(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see sm_rsaDLL.h for the class definition
CSm_rsaDLL::CSm_rsaDLL()
{ 
	return; 
}

#endif // WIN32
