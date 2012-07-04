
// List template instantiation file

#include "sm_apiCert.h"
#include "sm_tlistC.h"
#include "sm_DLLInterface.h"
_BEGIN_CERT_NAMESPACE 
using namespace SNACC;

// TBD, warning 4660 on from MSVC++ is "template-class specialization 
// 'identifier' is already instantiated"...currently, it comes
// up on CSM_Buffer, CSM_CertificateChoice, CSM_DN, and CSM_MsgSignerInfos
// It seems to be triggered by another class using parts of
// the warning classes...where ambiguity exists, the compiler appears
// to temporarily instantiate the warning class so when these
// explicit instantiations occur, a warning comes up...an example is
// CSM_Recipient's dual overridden constructors, one initializing
// the inherited CSM_CertificateChoice....Hope to resolve this
// without the use of a pragma ASAP
#ifdef WIN32
#pragma warning( disable : 4660 )
#endif
// template class  CTIL::CSM_ListC<CSM_CSInst>;
// template class  CTIL::CSM_ListC<MAB_Entrydef>;
// //RWC;11/11/98;template class CSM_List<CSM_Ml>;
// template class  CTIL::CSM_ListC<CSM_GeneralName>;
// template class  CTIL::CSM_ListC<CSM_CertificateChoice>;
// template class  CTIL::CSM_ListC<CSM_CertificateList>;

#ifdef WIN32
#pragma warning( default : 4660 )
#endif

_END_CERT_NAMESPACE 

// EOF sm_listCert.cpp
