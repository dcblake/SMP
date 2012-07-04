
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SM_SPEXDLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SM_SPEXDLL_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef SM_SPEXDLL_EXPORTS
#define SM_SPEXDLL_API __declspec(dllexport)
#else
#define SM_SPEXDLL_API __declspec(dllimport)
#endif

// This class is exported from the sm_spexDLL.dll
class SM_SPEXDLL_API CSm_spexDLL {
public:
	CSm_spexDLL(void);
	// TODO: add your methods here.
};

extern SM_SPEXDLL_API int nSm_spexDLL;

SM_SPEXDLL_API int fnSm_spexDLL(void);

