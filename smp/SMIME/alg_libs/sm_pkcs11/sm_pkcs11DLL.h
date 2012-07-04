
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the SM_PKCS11DLL_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// SM_PKCS11DLL_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef WIN32
#ifdef SM_PKCS11DLL_EXPORTS
  #define SM_PKCS11DLL_API __declspec(dllexport)
#else
  #define SM_PKCS11DLL_API __declspec(dllimport)
#endif  //SM_PKCS11DL_EXPORTS in WIN32
#else   // WIN32
  #define SM_PKCS11DLL_API 
#endif  // WIN32

// This class is exported from the sm_pkcs11DLL.dll
class SM_PKCS11DLL_API CSm_pkcs11DLL {
public:
	CSm_pkcs11DLL(void);
	// TODO: add your methods here.
};

extern SM_PKCS11DLL_API int nSm_pkcs11DLL;

SM_PKCS11DLL_API int fnSm_pkcs11DLL(void);

