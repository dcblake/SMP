
//////////////////////////////////////////////////////////////////////////
// sm_Alg.cpp
//////////////////////////////////////////////////////////////////////////

#include "sm_apiCtilMgr.h"

_BEGIN_CTIL_NAMESPACE
using namespace SNACC; 
//////////////////////////////////////////////////////////////////////////
CSM_AlgVDA::CSM_AlgVDA(AlgorithmIdentifierVDA &SNACCAlgId) 
{
   SME_SETUP("CSM_AlgVDA::CSM_AlgVDA(AlgorithmIdentifierVDA &)");

   algorithm = SNACCAlgId.algorithm;

   if (SNACCAlgId.parameters)
   {
      /*RWC;CSM_Buffer *p=NULL;
      long lA = SNACCAlgId.parameters->anyBuf->length();
      SM_EXTRACT_ANYBUF(p, SNACCAlgId.parameters);
      if ((parameters = new AsnAny) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      SM_ASSIGN_ANYBUF(p, parameters);
      if (p)
         delete p;*/
      parameters = new AsnAny;
      *parameters = *SNACCAlgId.parameters;
   }

   SME_FINISH_CATCH;
}

//////////////////////////////////////////////////////////////////////////
CSM_AlgVDA::CSM_AlgVDA(const CSM_AlgVDA &alg)
{
   SME_SETUP("CSM_AlgVDA::CSM_AlgVDA(CSM_AlgVDA)");

   algorithm = alg.algorithm;

   if (alg.parameters)
   {
      /*RWC;CSM_Buffer *p=NULL;
      SM_EXTRACT_ANYBUF(p, alg.parameters);
      if ((parameters = new AsnAny) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      SM_ASSIGN_ANYBUF(p, parameters);
      if (p)
         delete p;*/
      parameters = new AsnAny;
      *parameters = *alg.parameters;
   }

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
CSM_AlgVDA::CSM_AlgVDA(AsnOid &AlgOid, CSM_Buffer &buffer)
{
   SME_SETUP("CSM_AlgVDA::CSM_AlgVDA(AsnOid &, CSM_Buffer &)");

   algorithm = AlgOid;

   if ((parameters = new AsnAny) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME(buffer.ConvertFileToMemory());
   SM_ASSIGN_ANYBUF((&buffer), parameters);

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
AsnOid* CSM_AlgVDA::GetId()
{
   AsnOid *pRet;

   SME_SETUP("CSM_AlgVDA::GetId");

   SME(pRet = new AsnOid(algorithm));

   SME_FINISH_CATCH
   return pRet; 
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_AlgVDA::GetParams()
{
   CSM_Buffer *pRet = NULL;

   SME_SETUP("CSM_AlgVDA::GetParams");

   if (parameters)
      SM_EXTRACT_ANYBUF(pRet, parameters);

   SME_FINISH_CATCH
   return pRet;
}

//////////////////////////////////////////////////////////////////////////
AlgorithmIdentifierVDA* CSM_AlgVDA::GetSNACCAlgId() 
{
   AlgorithmIdentifierVDA *pRet;

   SME_SETUP("CSM_AlgVDA::GetSNACCAlgId");

   if ((pRet = new AlgorithmIdentifierVDA) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   pRet->algorithm = algorithm;
   if (parameters)
   {
      CSM_Buffer *p=NULL;
      SM_EXTRACT_ANYBUF(p, parameters);
      pRet->parameters = new AsnAny;
      SM_ASSIGN_ANYBUF(p, pRet->parameters);
      if (p)
         delete p;
   }

   SME_FINISH_CATCH
   return pRet;
}

//////////////////////////////////////////////////////////////////////////
bool CSM_AlgVDA::operator == (CSM_AlgVDA &AlgId) 
{
   bool bResult = false;
   CSM_Buffer *pBufParameters=NULL;
   CSM_Buffer *pBufAlgIdParameters=NULL;

   SME_SETUP("CSM_AlgVDA::==");

   if (algorithm == AlgId.algorithm)
   {
      if ((parameters) && (AlgId.parameters))
      {
         SM_EXTRACT_ANYBUF(pBufParameters, parameters);
         SM_EXTRACT_ANYBUF(pBufAlgIdParameters, AlgId.parameters);
         if (*pBufParameters == *pBufAlgIdParameters)
            bResult = true;
         if (pBufParameters)
            delete pBufParameters;
         if (pBufAlgIdParameters)
            delete pBufAlgIdParameters;
      }
      else
         bResult = true;
   }

   SME_FINISH_CATCH
   return bResult;
}

//////////////////////////////////////////////////////////////////////////
//RWC;bool CSM_AlgVDA::operator != (CSM_AlgVDA &AlgId) 
//RWC;{ 
//RWC;   return !(*this == AlgId); 
//RWC;}

//////////////////////////////////////////////////////////////////////////
void CSM_AlgVDA::SetSNACCAlgId(AlgorithmIdentifierVDA *pSNACCAlgId)
{
   SME_SETUP("CSM_AlgVDA::SetSNACCAlgId");

   if (pSNACCAlgId == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   algorithm = pSNACCAlgId->algorithm;

   if (pSNACCAlgId->parameters)
   {
      CSM_Buffer *p=NULL;
      SM_EXTRACT_ANYBUF(p, pSNACCAlgId->parameters);
      parameters = new AsnAny;
      SM_ASSIGN_ANYBUF(p, parameters);
      if (p)
         delete p;
   }

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
//RWC;CSM_AlgVDA & CSM_AlgVDA::operator = (CSM_AlgVDA &AlgId) 
//RWC;{
//RWC;   algorithm = AlgId.algorithm;

   //RWC;if (AlgId.parameters)
   //RWC;{
   //RWC;   CSM_Buffer *p;
   //RWC;   SM_EXTRACT_ANYBUF(p, AlgId.parameters);
   //RWC;   parameters = new AsnAny;
   //RWC;   SM_ASSIGN_ANYBUF(p, parameters);
   //RWC;   delete p;
   //RWC;}
   //RWC;*this = AlgId.SetSNACCAlgId((AlgorithmIdentifierVDA)AlgId);

   //RWC;return *this;
//RWC;}

//////////////////////////////////////////////////////////////////////////
//RWC;CSM_AlgVDA & CSM_AlgVDA::operator = (AlgorithmIdentifierVDA &snaccAlg) 
//RWC;{
//RWC;   algorithm = snaccAlg.algorithm;

//RWC;   if (snaccAlg.parameters)
//RWC;   {
//RWC;      CSM_Buffer *p;
//RWC;      SM_EXTRACT_ANYBUF(p, snaccAlg.parameters);
//RWC;      parameters = new AsnAny;
//RWC;      SM_ASSIGN_ANYBUF(p, parameters);
//RWC;      delete p;
//RWC;   }

//RWC;   return *this;
//RWC;}

long CSM_AlgVDA::LoadNullParams()
{
   return(LoadNullParams((AlgorithmIdentifierVDA *)this));
}


long CSM_AlgVDA::LoadNullParams(AlgorithmIdentifierVDA *pAlg)
{
   CSM_Buffer *pCBuf;

      // RWC; ADD NULL parameter for SMIME compliance.
      if (pAlg->parameters == NULL)  // ONLY IF EMPTY.
      {
         pAlg->parameters = new AsnAny;
      }     // END IF parameters empty

      if (pAlg->parameters->value == NULL)
      {
         pCBuf = GetNullParams();
         SM_ASSIGN_ANYBUF(pCBuf, pAlg->parameters);
         delete pCBuf;
      }     // END IF asnValue empty

      return(0);
}

bool CSM_AlgVDA::HasNullParams()
{
   bool bResult=true;
   CSM_Buffer *pCBuf=NULL;

   SME_SETUP("CSM_AlgVDA::HasNullParams");
      // RWC; ADD NULL parameter for SMIME compliance.
      if (parameters != NULL)
      {
         SM_EXTRACT_ANYBUF(pCBuf, parameters);
         if (pCBuf)
         {
             unsigned char *ptr=(unsigned char *)pCBuf->Access();
             if (ptr)
             {
                if (pCBuf->Length() == 2 && *ptr == 5 && *(ptr+1) == 0)
                {                               // NULL Parameters
                   bResult = true;
                }
                else
                {
                   bResult = false;
                }
             }
             else
                 bResult = false;

             delete pCBuf;
         }
      }

   SME_FINISH_CATCH
      return(bResult);
}

CSM_Buffer *CSM_AlgVDA::GetNullParams()
{
   char ptr[]={0x05,0x00};
   CSM_Buffer *pCBuf=new CSM_Buffer(&ptr[0], 2);
   return(pCBuf);
}

_END_CTIL_NAMESPACE 

// EOF sm_Alg.cpp
