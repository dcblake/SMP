
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SM_FREE3DLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SM_FREE3DLL_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef WIN32
#ifdef SM_FREE3DLL_EXPORTS
#define SM_FREE3DLL_API __declspec(dllexport)
#else
#define SM_FREE3DLL_API __declspec(dllimport)
#endif
#else
#define SM_FREE3DLL_API 
#endif

// This class is exported from the sm_free3DLL.dll
class SM_FREE3DLL_API CSm_free3DLL {
public:
	CSm_free3DLL(void);
	// TODO: add your methods here.
};

extern SM_FREE3DLL_API int nSm_free3DLL;

SM_FREE3DLL_API int fnSm_free3DLL(void);

