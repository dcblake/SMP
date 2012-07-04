//////////////////////////////////////////////////////////////////////////////
// aclerror.cpp
// These routines support the ACL_Exception Class
// CONSTRUCTOR(s):
//   ACL_Exception(SM_RET_VAL err_num)
// MEMBER FUNCTIONS:
//////////////////////////////////////////////////////////////////////////////

#include "aclinternal.h"

_USING_NAMESPACE_SNACC
_BEGIN_NAMESPACE_ACL

// ALTERNATIVE CONSTRUCTOR:
//
ACL_Exception::ACL_Exception(long err_num) throw() :SnaccException(err_num)
{
   m_pCMLerror = NULL;
} // END OF ALTERNATIVE CONSTRUCTOR:

ACL_Exception::ACL_Exception(const char *file, long line_number, const char *function,
                             const char *whatStr, long errorCode) throw() 
                             :SnaccException(file, line_number, function, whatStr, 
															errorCode)
{
   m_pCMLerror = NULL;
}

ACL_Exception::ACL_Exception(const CML::ASN::Exception &cmlErr, long lineNo,
                             const char *pszFuncName, const char *pszFileName) throw()
		                      :SnaccException(pszFileName, lineNo, pszFuncName, 
													     "CML Exception", ACL_CML_ERROR)
{
   m_pCMLerror = new CML::ASN::Exception(cmlErr);
}

ACL_Exception::ACL_Exception(const ACL_Exception &o)
{
	m_pCMLerror = NULL;
   operator=(o);
}

ACL_Exception::~ACL_Exception() throw()
{
   delete m_pCMLerror;
}

const CML::ASN::Exception * ACL_Exception::getCMLError()
{
   return m_pCMLerror;
}

ACL_Exception & ACL_Exception::operator=(const ACL_Exception &o)
{
   if (o.m_pCMLerror != NULL)
   {
      if (m_pCMLerror != NULL)
         *m_pCMLerror = *o.m_pCMLerror;
      else
         m_pCMLerror = new CML::ASN::Exception(*o.m_pCMLerror);
   }
   SnaccException::operator=(o);
   return *this;
}
 

void ACL_Exception::setErrorString(const char *errStr)
{
   m_whatStr = errStr;
}

_END_NAMESPACE_ACL

// END OF aclerror.cpp
