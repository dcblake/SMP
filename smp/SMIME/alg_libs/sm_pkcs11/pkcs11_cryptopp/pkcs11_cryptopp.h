
// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the PKCS11_CRYPTOPP_EXPORTS
// symbol defined on the command line. this symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// PKCS11_CRYPTOPP_API functions as being imported from a DLL, wheras this DLL sees symbols
// defined with this macro as being exported.
#ifdef PKCS11_CRYPTOPP_EXPORTS
#define PKCS11_CRYPTOPP_API __declspec(dllexport)
#else
#define PKCS11_CRYPTOPP_API __declspec(dllimport)
#endif

// This class is exported from the pkcs11_cryptopp.dll
class PKCS11_CRYPTOPP_API CPkcs11_cryptopp {
public:
	CPkcs11_cryptopp(void);
	// TODO: add your methods here.
};

extern PKCS11_CRYPTOPP_API int nPkcs11_cryptopp;

PKCS11_CRYPTOPP_API int fnPkcs11_cryptopp(void);

