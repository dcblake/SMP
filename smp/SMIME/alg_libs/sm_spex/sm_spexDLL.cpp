// sm_spexDLL.cpp : Defines the entry point for the DLL application.
//

#include "aaastdafx.h"
#include "sm_spexDLL.h"

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
SM_SPEXDLL_API int nSm_spexDLL=0;

// This is an example of an exported function.
SM_SPEXDLL_API int fnSm_spexDLL(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see sm_spexDLL.h for the class definition
CSm_spexDLL::CSm_spexDLL()
{ 
	return; 
}

