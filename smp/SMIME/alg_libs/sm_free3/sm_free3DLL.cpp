// sm_free3DLL.cpp : Defines the entry point for the DLL application.
//
#ifdef WIN32
#include "stdafx.h"
#endif
#include "sm_free3DLL.h"

#ifdef WIN32
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
    lpReserved;hModule; //AVOIDS warning.
    return TRUE;
}

#endif

// This is an example of an exported variable
SM_FREE3DLL_API int nSm_free3DLL=0;

// This is an example of an exported function.
SM_FREE3DLL_API int fnSm_free3DLL(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see sm_free3DLL.h for the class definition
CSm_free3DLL::CSm_free3DLL()
{ 
	return; 
}



//#include "sm_free3.cpp"
