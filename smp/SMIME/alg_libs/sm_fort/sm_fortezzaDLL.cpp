// sm_fortezzaDLL.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "sm_fortezzaDLL.h"

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
    lpReserved;hModule;//AVOIDS warning.
    return TRUE;
}


// This is an example of an exported variable
SM_FORTEZZADLL_API int nSm_fortezzaDLL=0;

// This is an example of an exported function.
SM_FORTEZZADLL_API int fnSm_fortezzaDLL(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see sm_fortezzaDLL.h for the class definition
CSm_fortezzaDLL::CSm_fortezzaDLL()
{ 
	return; 
}

