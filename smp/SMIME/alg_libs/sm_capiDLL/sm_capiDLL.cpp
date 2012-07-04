// sm_capiDLL.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "sm_capiDLL.h"
#include "sm_capi.h"

CERT::CSM_Capi DummyCapiInstance;

BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    switch (ul_reason_for_call)
	{
		case DLL_PROCESS_DETACH:
         if (CERT::CSM_Capi::m_hDataKeyModule)
         {
            //RWC;ONLY UNLOAD AT END, otherwise it causes crash upon any exception
            //RWC;  in DataKey CSP.
            FreeLibrary(CERT::CSM_Capi::m_hDataKeyModule);
         }
         break;

		case DLL_PROCESS_ATTACH:
         CERT::CSM_Capi::m_hDataKeyModule = NULL;
         break;

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;

    }
    return TRUE;
}


// This is an example of an exported variable
SM_CAPIDLL_API int nSm_capiDLL=0;

// This is an example of an exported function.
SM_CAPIDLL_API int fnSm_capiDLL(void)
{
	return 42;
}

// This is the constructor of a class that has been exported.
// see sm_capiDLL.h for the class definition
CSm_capiDLL::CSm_capiDLL()
{ 
	return; 
}

