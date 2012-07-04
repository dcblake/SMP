#include "aclinternal.h"
#include <stdlib.h>

_BEGIN_NAMESPACE_ACL

// OPERATOR OVERLOAD <<
//
AclString& operator<<(AclString &o, const char *str)
{
   o.append(str);
   return o;
} // END OF OPERATOR OVERLOAD <<

// OPERATOR OVERLOAD <<
//
AclString& operator<<(AclString &o,long lch)
{

   char buffer[20];
   sprintf(buffer, "%li", lch);
   o += buffer;
   return o;
} // END OF OPERATOR OVERLOAD <<

_END_NAMESPACE_ACL

// EOF aclstring.cpp

