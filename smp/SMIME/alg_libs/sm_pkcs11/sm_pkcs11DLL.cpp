// sm_pkcs11DLL.cpp : Defines the entry point for the DLL application.
//

#include "sm_pkcs11DLL.h"
// Insert your headers here
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#include <windows.h>

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
    return TRUE;
}


// This is an example of an exported variable
SM_PKCS11DLL_API int nSm_pkcs11DLL=0;

// This is an example of an exported function.
SM_PKCS11DLL_API int fnSm_pkcs11DLL(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see sm_pkcs11DLL.h for the class definition
CSm_pkcs11DLL::CSm_pkcs11DLL()
{ 
	return; 
}

