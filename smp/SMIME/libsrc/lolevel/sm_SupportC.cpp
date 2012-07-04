
// C Wrapper Support Functions

#include "sm_api.h"

    using namespace SFL;
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;

/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL SM_CreateCSMIME(SM_OBJECT **ppCSMIME)
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   CSMIME *pRet = NULL;

   if (ppCSMIME == NULL)
      lRet = SM_MISSING_PARAM;
   else
   {
      if ((pRet = new CSMIME) == NULL)
         lRet = SM_MEMORY_ERROR;
      else
         *ppCSMIME = (SM_OBJECT *)pRet;
   }

   return lRet;
}

/////////////////////////////////////////////////////////////////////////////
void SM_DeleteCSMIME(SM_OBJECT *pCSMIME)
{
   if (pCSMIME)
      delete ((CSMIME *)pCSMIME);
}

/////////////////////////////////////////////////////////////////////////////
/*RWC;SM_RET_VAL SM_GetError(SM_OBJECT *pCSMIME, SM_ErrorBuf **ppError)
{
   SM_RET_VAL lRet = SM_NO_ERROR;

   if ((pCSMIME == NULL) || (ppError == NULL))
      lRet = SM_MISSING_PARAM;
   else
   {
      if ((*ppError = (SM_ErrorBuf *)calloc(1, sizeof(SM_ErrorBuf))) == NULL)
         lRet = SM_MEMORY_ERROR;
      else
      {
         // copy pCSMIME->AccessErrorBuf into *ppError
         /*(*ppError)->lErrorCode = 
               ((CSMIME *)pCSMIME)->AccessErrorBuf()->m_lErrorCode;
         (*ppError)->pszDebug = strdup(((CSMIME *)pCSMIME)->
               AccessErrorBuf()->m_pszDebug);
         (*ppError)->strError.pchData = 
               ((CSMIME *)pCSMIME)->AccessErrorBuf()->m_ErrorBuf.Get();
         if ((*ppError)->strError.pchData)
            (*ppError)->strError.lLength =
                  ((CSMIME *)pCSMIME)->AccessErrorBuf()->m_ErrorBuf.Length();* /
      }
   }

   return lRet;
}*/

/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL SM_GetInstCount(SM_OBJECT *pCSMIME, long *plInstCount)
{
   SM_RET_VAL lRet = SM_NO_ERROR;

   SME_SETUP("SM_GetInstCount");

   if ((pCSMIME == NULL) || (plInstCount == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   *plInstCount = 0;
   if (((CSMIME *)pCSMIME)->m_pCSInsts)
      *plInstCount = ((CSMIME *)pCSMIME)->m_pCSInsts->size();

   SME_FINISH
   SME_CATCH_SETUP
      /* cleanup code */
      lRet = -1;
   SME_CATCH_FINISH_C

   return lRet;
}

/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL SM_SetInstUseThisFlag(SM_OBJECT *pCSMIME, long lInstIndex,
      short bFlag)
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   CSM_CtilInstLst::iterator itInst;
   CSMIME *pCS = (CSMIME *)pCSMIME;
   int i;

   SME_SETUP("SM_SetInstUseThisFlag");

   if (pCSMIME == NULL || pCS->m_pCSInsts == NULL)
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMETER", NULL);

   for (itInst =  pCS->m_pCSInsts->begin(), i=0;
        itInst != pCS->m_pCSInsts->end() && i < lInstIndex;
        ++itInst, i++);
   if (itInst != pCS->m_pCSInsts->end())
   {
      if (bFlag)
         (*itInst)->SetUseThis(true);
      else
         (*itInst)->SetUseThis(false);
   }
   else
      SME_THROW(SM_INVALID_INDEX, "couldn't find instance", NULL);
   
   SME_FINISH
   SME_CATCH_SETUP
      /* cleanup code */
      lRet = -1;
   SME_CATCH_FINISH_C

   return lRet;
}

/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL SM_GetInstUseThisFlag(SM_OBJECT *pCSMIME, long lInstIndex,
      short *pbFlag)
{
   CSM_CtilInstLst::iterator itInst;
   CSMIME *pCS = (CSMIME *)pCSMIME;
   SM_RET_VAL lRet = SM_NO_ERROR;
   int i;

   SME_SETUP("SM_GetInstUseThisFlag");

   if (pCSMIME == NULL || pbFlag == NULL || pCS->m_pCSInsts == NULL)
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMETER", NULL);

   for (itInst =  pCS->m_pCSInsts->begin(), i=0;
        itInst != pCS->m_pCSInsts->end() && i < lInstIndex;
        ++itInst, i++);
   if (itInst != pCS->m_pCSInsts->end())
   {
      if ((*itInst)->IsThisUsed())
         *pbFlag = 1;
      else
         *pbFlag = 0;
   }
   else
      SME_THROW(SM_INVALID_INDEX, "couldn't find instance", NULL);

   SME_FINISH
   SME_CATCH_SETUP
      /* cleanup code */
      lRet = -1;
   SME_CATCH_FINISH_C

   return lRet;
}

/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL SM_SetInstApplicableFlag(SM_OBJECT *pCSMIME, 
      long lInstIndex, short bFlag)
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   CSM_CtilInstLst::iterator itInst;
   CSMIME *pCS = (CSMIME *)pCSMIME;
   int i;

   SME_SETUP("SM_SetInstApplicableFlag");

   if (pCSMIME == NULL || pCS->m_pCSInsts == NULL)
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMETERS", NULL);

   for (itInst =  pCS->m_pCSInsts->begin(), i=0;
        itInst != pCS->m_pCSInsts->end() && i < lInstIndex;
        ++itInst, i++);
   if (itInst != pCS->m_pCSInsts->end())
   {
      if (bFlag)
         (*itInst)->SetApplicable(true);
      else
         (*itInst)->SetApplicable(false);
   }
   else
      SME_THROW(SM_INVALID_INDEX, "couldn't find instance", NULL);
   
   SME_FINISH
   SME_CATCH_SETUP
      /* cleanup code */
      lRet = -1;
   SME_CATCH_FINISH_C

   return lRet;
}

/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL SM_GetInstApplicableFlag(SM_OBJECT *pCSMIME,
      long lInstIndex, short *pbFlag)
{
   CSM_CtilInstLst::iterator itInst;
   CSMIME *pCS = (CSMIME *)pCSMIME;
   int i;
   SM_RET_VAL lRet = SM_NO_ERROR;

   SME_SETUP("SM_GetInstApplicableFlag");

   if (pCSMIME == NULL || pbFlag == NULL || pCS->m_pCSInsts == NULL)
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMETER", NULL);

   for (itInst =  pCS->m_pCSInsts->begin(), i=0;
        itInst != pCS->m_pCSInsts->end() && i < lInstIndex;
        ++itInst, i++);
   if (itInst != pCS->m_pCSInsts->end())
   {
      if ((*itInst)->IsApplicable())
         *pbFlag = 1;
      else
         *pbFlag = 0;
   }
   else
      SME_THROW(SM_INVALID_INDEX, "couldn't find instance", NULL);

   SME_FINISH
   SME_CATCH_SETUP
      /* cleanup code */
      lRet = -1;
   SME_CATCH_FINISH_C

   return lRet;
}

// EOF sm_SupportC.cpp
