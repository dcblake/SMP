//PIERCE added include

#include "sm_fort.h"
#include "sm_fortAsn.h"
#include "sm_usefulTypes.h"
#include "sm_VDASupport_asn.h"
using namespace CERT;
using namespace SNACC;

// FUNCTION: CSM_FortDSAParams Constructor
//
// PURPOSE: Initialize P,Q,G private members to 0.
//
CSM_FortDSAParams::CSM_FortDSAParams()
{
   P = NULL;
   Q = NULL;
   G = NULL;
}

CSM_FortDSAParams::~CSM_FortDSAParams()
{
  if (P)
    free(P);
  if (Q)
    free(Q);
  if (G)
    free(G);
}

// FUNCTION: DecodeParams
//
// PURPOSE: To decoded the ASN.1 encoded DSAWithSHA1Parameters from
//          pParams into the private member variable m_pSnaccParams
//      RWC;6/13/01; This method now returns the param length for P and G.
//                  This was necessary for certain DSA sigs of 40x or 64 
//                  bytes in length; different from the 128 byte Fortezza.
SM_RET_VAL CSM_FortDSAParams::Decode(CSM_Buffer *pParams)
{

   DSAWithSHA1Parameters *pSnaccV3CertParams=NULL;
   Kea_Dss_Parms           *pSnaccV1CertParams=NULL;
   AsnInt                bigIntStr;
   size_t                paramLen = 0;
   long                  error =  0;
   int                   pParamSize=0;

   SME_SETUP("CSM_FortDSAParams::DecodeParams()");

   // V3 Certificate style parameters
   //
   pSnaccV3CertParams = new DSAWithSHA1Parameters;

   DECODE_BUF_NOFAIL(pSnaccV3CertParams, pParams,  error);
   
   // IF no error then use AsnInt class to 
   //    perform big integer processing on  P, Q, and G.
   //
   //    note: this is only necessary for V3 certs
   //
   if (error == 0)
   {
       if (pSnaccV3CertParams->p.length() <= 65)
           pParamSize = 64;     // Smaller signature.
       else
           pParamSize = CI_P_SIZE; // larger signature.
       bigIntStr = pSnaccV3CertParams->p;
       bigIntStr.getPadded/*GetUnSignedBitExtendedData/ *Get*/( (unsigned char *&)P, paramLen, pParamSize);
       bigIntStr = pSnaccV3CertParams->q;
       bigIntStr.getPadded/*GetUnSignedBitExtendedData/ *Get*/( (unsigned char *&)Q, paramLen, (unsigned int) CI_Q_SIZE);
       bigIntStr = pSnaccV3CertParams->g;
       bigIntStr.getPadded/*GetUnSignedBitExtendedData/ *Get*/( (unsigned char *&)G, paramLen, (unsigned int) pParamSize);
   }
   else
   {
      // Try V1 Certificate style DSS Parameters
      //
      P = (char *) calloc(1, CI_P_SIZE);
      Q = (char *) calloc(1, CI_Q_SIZE);
      G = (char *) calloc(1, CI_G_SIZE);

      pSnaccV1CertParams = new Kea_Dss_Parms;
      DECODE_BUF_NOFAIL(pSnaccV1CertParams, pParams, error);

      if (error)
         SME_THROW(error,"Error decoding Subject Public Key parameters", NULL);

      if ( pSnaccV1CertParams->choiceId == pSnaccV1CertParams->differentParmsCid )
      {
         if ( (pSnaccV1CertParams->differentParms->dss_Parms.p.Len() != CI_P_SIZE) ||
              (pSnaccV1CertParams->differentParms->dss_Parms.q.Len() != CI_Q_SIZE) ||
              (pSnaccV1CertParams->differentParms->dss_Parms.g.Len() != CI_G_SIZE) )
            
         {
            SME_THROW(FORT_INV_PARM,"Invalid DSS Parameters", NULL);
         }
         else
         {

            memcpy(P, pSnaccV1CertParams->differentParms->dss_Parms.p.c_str(), CI_P_SIZE);
            memcpy(Q, pSnaccV1CertParams->differentParms->dss_Parms.q.c_str(), CI_Q_SIZE);
            memcpy(G, pSnaccV1CertParams->differentParms->dss_Parms.g.c_str(), CI_G_SIZE);
         }
      } else if ( pSnaccV1CertParams->choiceId == pSnaccV1CertParams->commonParmsCid )
      {
         if ( (pSnaccV1CertParams->commonParms->p.Len() != CI_P_SIZE) ||
              (pSnaccV1CertParams->commonParms->q.Len() != CI_Q_SIZE) ||
              (pSnaccV1CertParams->commonParms->g.Len() != CI_G_SIZE) )
         {
            SME_THROW(FORT_INV_PARM,"Invalid DSS Parameters", NULL);
         }
         else
         {
            memcpy(P, pSnaccV1CertParams->commonParms->p.c_str(), CI_P_SIZE);
            memcpy(Q, pSnaccV1CertParams->commonParms->q.c_str(), CI_Q_SIZE);
            memcpy(G, pSnaccV1CertParams->commonParms->g.c_str(), CI_G_SIZE);
         }
      }
      pParamSize = CI_P_SIZE;
   }
   if (pSnaccV3CertParams)
       delete pSnaccV3CertParams;
   if (pSnaccV1CertParams)
       delete pSnaccV1CertParams;

   return pParamSize;

   SME_FINISH_CATCH;
}


// EOF sm_fortDsaParams.cpp