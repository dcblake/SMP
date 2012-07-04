// sm_pkcs11Free3DLL.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "sm_pkcs11Free3DLL.h"

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
SM_PKCS11FREE3DLL_API int nSm_pkcs11Free3DLL=0;

// This is an example of an exported function.
SM_PKCS11FREE3DLL_API int fnSm_pkcs11Free3DLL(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see sm_pkcs11Free3DLL.h for the class definition
CSm_pkcs11Free3DLL::CSm_pkcs11Free3DLL()
{ 
	return; 
}

