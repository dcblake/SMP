
// sm_Content.cpp
#include "sm_api.h"
_BEGIN_SFL_NAMESPACE


//////////////////////////////////////////////////////////////////////////
void CSM_Content::SetContent(char *pszContent)
{
   m_content.Set(pszContent);
   m_contentType = SNACC::id_data;

}

//////////////////////////////////////////////////////////////////////////
void CSM_Content::SetContent(CTIL::CSM_Buffer *pContent)
{
   m_contentType = SNACC::id_data;
   m_content = *pContent;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Content::SetContent(CTIL::CSM_Buffer *pContent, const SNACC::AsnOid  &tOID)
{
  // m_content = *pContent;  causes a memory leak
   m_content.Set(pContent->Access(), pContent->Length());
   m_contentType = tOID;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Content::SetContent(const char *pContentChar, long length, 
                             const SNACC::AsnOid  tOID)
{
   m_content.Set(pContentChar, length);
   m_contentType = tOID;
}

//////////////////////////////////////////////////////////////////////////
void CSM_Content::SetContent(CSM_Content *pContent)
{
   *this = *pContent;
}

_END_SFL_NAMESPACE

// EOF sm_Content.cpp
