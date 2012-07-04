
// sm_pkcs11Template.cpp

/*#ifndef WIN32
#include <stream.h>
#endif
#include <string.h>
#include <strstrea.h>*/
#pragma warning( disable : 4661)  //RWC; HOPEFULLY this still works fine...
#include "sm_pkcs11.h"

_BEGIN_CERT_NAMESPACE

template class CERT::List<CSM_Pkcs11Slot>;
template class CERT::List<CSM_Pkcs11MechanismInfo>;

_END_CERT_NAMESPACE

// EOF sm_pkcs11Template.cpp
