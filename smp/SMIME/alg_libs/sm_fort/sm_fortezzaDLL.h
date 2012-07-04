
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SM_FORTEZZADLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SM_FORTEZZADLL_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef SM_FORTEZZADLL_EXPORTS
#define SM_FORTEZZADLL_API __declspec(dllexport)
#else
#define SM_FORTEZZADLL_API __declspec(dllimport)
#endif

// This class is exported from the sm_fortezzaDLL.dll
class SM_FORTEZZADLL_API CSm_fortezzaDLL {
public:
	CSm_fortezzaDLL(void);
	// TODO: add your methods here.
};

extern SM_FORTEZZADLL_API int nSm_fortezzaDLL;

SM_FORTEZZADLL_API int fnSm_fortezzaDLL(void);

