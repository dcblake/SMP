
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SM_RSADLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SM_RSADLL_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef SM_RSADLL_EXPORTS
#define SM_RSADLL_API __declspec(dllexport)
#else
#define SM_RSADLL_API __declspec(dllimport)
#endif

// This class is exported from the sm_rsaDLL.dll
class SM_RSADLL_API CSm_rsaDLL {
public:
	CSm_rsaDLL(void);
	// TODO: add your methods here.
};

extern SM_RSADLL_API int nSm_rsaDLL;

SM_RSADLL_API int fnSm_rsaDLL(void);

