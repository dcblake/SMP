
//////////////////////////////////////////////////////////////////////////////
//  sm_timeStamp.cpp
//  10/31/03
//
// The following routines support the CSM_TimeStampTokenInfo class.                      
//
// CONSTRUCTOR FOR CSM_TimeStampReq:
//
// DESTRUCTOR FOR CSM_TimeStampReq:
//
// MEMBER FUNCTIONS FOR CSM_TimeStampReq:
//     Clear()
//
// -----------------------------------------------------------------------------
//
// The following routines support the CSM_TimeStampReq class.                      
//
// CONSTRUCTOR FOR CSM_TimeStampReq:
//
// DESTRUCTOR FOR CSM_TimeStampReq:
//
// MEMBER FUNCTIONS FOR CSM_TimeStampReq:
//     Clear()
//
//
// -----------------------------------------------------------------------------
//
// The following routines support the CMS_TimeStampResp class:   
//                   
// CONSTRUCTOR FOR CSM_TimeStampResp:
//
// DESTRUCTOR FOR CSM_TimeStampResp:
//
//
// MEMBER FUNCTIONS FOR CSM_TimeStampResp:
//     Clear()
//
//
//////////////////////////////////////////////////////////////////////////////
#include "sm_timeStamp.h"
#include "sm_pkixtsp.h"
#include "sm_api.h"
#include <time.h>


_BEGIN_SFL_NAMESPACE
using namespace SNACC;
using namespace CERT;


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CSM_TimeStampReq
//
// Description:  This constructor function calls the Clear() member function to
//               initialize the member variables and then calls Set to set the
//               member variables with the data in the parameters.
// 
// Inputs:   pCsmime - not optional
//           pSnaccSD - defaults to NULL
//           HashOid - defaults to sha_1
//           ReqPolicyOid - defaults to NULL
//           pNonce - defaults to NULL
//           bCertReq - defaults to false
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
// constructor
CSM_TimeStampReq::CSM_TimeStampReq(                   
      CSMIME *pCsmime,                   // for login if needed 
      SignedData *pSnaccSD,              // original SignedData message
      const SNACC::AsnOid &HashOid,     // hash oid
      const SNACC::AsnOid *pReqPolicyOid,// TSA policy under which 
                                         //   TST should be provided
      CSM_Buffer *pNonce,                // 64 bit integer create by 
                                         //   user optional
      bool  bCertReq)                    // if true, the TSA's public key
                                         // certificate that is referenced by the
                                         // ESSCertID inside a signing cert attr
                                         // in reponse must be provided by TSA
{
   Clear();
   Set(pCsmime, pSnaccSD, HashOid, pReqPolicyOid, pNonce, bCertReq);

}  // end of constructor

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CSM_TimeStampReq
//
// Description:  copy Constructor
// 
// Inputs: 
//   CSM_TimeStampReq &that - TimeStampReq data
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampReq::CSM_TimeStampReq(const CSM_TimeStampReq& that)  
{
	*this = that;

}  // end of copy constructor

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  operator =
//
// Description:  
// 
// Inputs: 
//   CSM_TimeStampReq &TSR - TimeStampReq data
//
// Outputs:  NONE
//
// Returns:  this - CSM_TimeStampReq
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampReq & CSM_TimeStampReq::operator = (const CSM_TimeStampReq &TSR)
{
	if (TSR.certReq)
	   certReq = new AsnBool(TSR.certReq);
	if (TSR.extensions)
	   this->extensions = new Extensions(*TSR.extensions);
	messageImprint = TSR.messageImprint;
	if (TSR.nonce)
	   nonce  = new AsnInt(*TSR.nonce);
	if (TSR.reqPolicy)
	   reqPolicy = new AsnOid(*TSR.reqPolicy);
	if (TSR.version)
	   version.Set(TSR.version);

   return(*this);
}


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  Set
//
// Description:  Sets the members in the inherited
//               SNACC::TimeStampReq with input data.
//
// 
// Inputs:   pCsmime 
//           pSnaccSD 
//           HashOid 
//           ReqPolicyOid 
//           pNonce 
//           bCertReq 
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
void CSM_TimeStampReq::Set(                         
      CSMIME *pCsmime,                   // for login if needed 
      SignedData *pSnaccSD,              // original SignedData message
      const SNACC::AsnOid &HashOid,      // hash oid
      const SNACC::AsnOid *pReqPolicyOid, // TSA policy under which 
                                         //   TST should be provided
      CSM_Buffer *pNonce,                // 64 bit integer create by 
                                         //   user optional
      bool  bCertReq)                    // if true, the TSA's public key
                                         // certificate that is referenced by the
                                         // ESSCertID inside a signing cert attr
                                         // in reponse must be provided by TSA
{
   SME_SETUP("CSM_TimeStampReq::Set");

   // check input arguments
    
   // check for null pCSMIME and m_pCSInsts
   if (pCsmime == NULL || pCsmime->m_pCSInsts == NULL)
   {
      // error 
      SME_THROW(SM_MISSING_PARAM, "Input Error with login instance", NULL);
   }

   TSTInfoInt ver(1);

   // set version
   version.Set(ver);

   // set message imprint
   if (pSnaccSD)
   {
      this->LoadMessageImprint(pSnaccSD);
   }
   else
   {
      // error 
      SME_THROW(SM_MISSING_PARAM, "Input Error with hash data", NULL);
   }

   // set reqPolicy
   if (pReqPolicyOid)
      reqPolicy = new AsnOid(*pReqPolicyOid);

   // set nonce
   if (pNonce && pNonce->Length() > 0)
      nonce = new AsnInt(pNonce->Access());

   // set CertReq
   certReq = new AsnBool(bCertReq);

   SME_FINISH_CATCH;

}  // end of Set



////////////////////////////////////////////////////////////////////////////////
//
// Member function:  LoadMessageImprint
//
// Description:  This member function will load the messageImprint member 
//               with the hash of the original datum to be time-stamped.
//               The hash algorithm should be one-way and collision resistant.
//               If the hash algorithm is unknown or weak, then an error of 
//               'bad_alg' is returned in pkiStatusInfo.
//
//               Function can either load the oid and sd hash from the 
//               original signed data if pSnaccSD is supplied
//               by the user, or load the pHashOid and hash the  
//               data in pBuf if supplied by user. 
// 
// Inputs:   SNACC::SignedData *pSnaccSD - original SignedData message
//
// Outputs:  NONE
//
// Returns:  status 1 - messageImprint not loaded
//                  0 - messageImprint loaded
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_TimeStampReq::LoadMessageImprint(
      SNACC::SignedData   *pSnaccSD)
{
   long        status = 1;  // message imprint not loaded
   SignerInfos::iterator itTmpSNACCSI;
   CSM_Buffer  *pMessageDigest = NULL;

   SME_SETUP("CSM_TimeStampReq::LoadMessageImprint()");

   // check for original pSnaccSD
   if (pSnaccSD)
   {
      // check for original hash value of the pSnaccSD digested data
      // find the message digest data and get it out of the original
      for (itTmpSNACCSI = pSnaccSD->signerInfos.begin();
           itTmpSNACCSI != pSnaccSD->signerInfos.end();
           ++itTmpSNACCSI)
      {
         if (itTmpSNACCSI->signedAttrs != NULL)
         {
           CSM_MsgSignerInfo ptmpSI(&(*itTmpSNACCSI));

           // get the hash value
           if ((pMessageDigest=ptmpSI.m_pSignedAttrs->GetMessageDigest()) != NULL)
           {
              // put the original message digest into messageImprint.hashedMessage
              messageImprint.hashedMessage.Set(pMessageDigest->Access(),
                 pMessageDigest->Length());

              messageImprint.hashAlgorithm.algorithm.Set(itTmpSNACCSI->digestAlgorithm.algorithm);
    		  status = 0;  // messageImprint loaded
           }
           else
           {
              SME_THROW(SM_MISSING_PARAM,
                 "ERROR:  No MessageDigest value to load for MessageImprint", NULL);
           }

           // found it no need to look further
           break;

         }  // end if signedAttrs
      }  // end for signerInfos
   }  // end if pSnaccSD
   else
   {
      SME_THROW(22,"ERROR: Must have signed data",NULL);
   }

   SME_FINISH_CATCH;
   
   return status;

}  // end of LoadMessageImprint


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  LoadMessageImprint
//
// Description:  This member function will load the messageImprint member 
//               with the hash of the original datum to be time-stamped.
//               The hash algorithm should be one-way and collision resistant.
//
//               Function can either load the oid and sd hash from the 
//               original signed data if pSnaccSD is supplied
//               by the user, or load the pHashOid and hash the  
//               data in pBuf if supplied by user. 
// 
// Inputs:  CSMIME *pCsmime
//          const CSM_Buffer *pBuf
//          const SNACC::AsnOid HashOid
//
// Outputs:  NONE
//
// Returns:  1 - messageImprint not loaded
//           0 - messageImprint loaded
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_TimeStampReq::LoadMessageImprint(
      CSMIME              *pCsmime,
      const CSM_Buffer    *pBuf,
      const SNACC::AsnOid HashOid)
{
   long        status = 1;  // messageImprint not loaded
   CSM_Buffer  MessageDigest;

   SME_SETUP("CSM_TimeStampReq::LoadMessageImprint()");

   // check for original pSnaccSD
   if(pBuf == NULL || pBuf->Length() == 0 || pCsmime == NULL)
   {
      SME_THROW(22, "Error:  no data to hash or pCsmime", NULL);
   }

   AsnOid tmpOid(HashOid);
   CSM_Alg tmpAlg(tmpOid);
   CSM_CtilInst *pInst = pCsmime->FindCSInstAlgIds(&tmpAlg, NULL, NULL, NULL);
   
   // if we have a MessageDigest value then load it
   if (pInst)
   {
      pInst->AccessTokenInterface()->SMTI_DigestData((CSM_Buffer *)pBuf,
         &MessageDigest, tmpOid);
      messageImprint.hashedMessage.Set(MessageDigest.Access(), MessageDigest.Length());

	  status = 0;  // messageImprint loaded
   }
   else
   {
      SME_THROW(22,
         "ERROR:  No Instance to perform hash", NULL);
   }

   // load the message digest algorithm
   
   messageImprint.hashAlgorithm.algorithm.Set(HashOid);
     
   SME_FINISH_CATCH;
   
   return status;

}  // end of LoadMessageImprint


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CSM_TimeStampResp
//
// Description:  Constructor
// 
// Inputs: 
//   CSMIME *pCsmime - Login list of certs
//   CSM_TimeStampReq &TSReq - TimeStampReq data
//   char *lpszLogin - TSA dn name
//   char *pTSSnFn - Serial Number file name
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampResp::CSM_TimeStampResp(
	  CERT::CSMIME *pCsmime, 
      CSM_TimeStampReq &TSReq, 
      char *lpszLogin,
	  int serialNum,
	  CSM_CertificateChoice *&pSigningCert,
      AsnOid *pPolicyOid) 
{
   CSM_Buffer *pTmpCIBuf = NULL;

   SME_SETUP("CSM_TimeStampResp::CSM_TimeStampResp()");

   // create a PKIStatusInfo for error reporting
   // create the timeStampToken
   pTmpCIBuf  = CreateTimeStampToken(pCsmime, TSReq, lpszLogin, serialNum, pSigningCert, pPolicyOid);

   if (WasSuccessful() && pTmpCIBuf != NULL)
   {
      // set data into the timeStampToken
      if (timeStampToken != NULL)
         delete timeStampToken;
      timeStampToken = new ContentInfo;

      pTmpCIBuf->Decode(*timeStampToken); 

      // clean-up
      delete pTmpCIBuf; 
   }

   // if error handle error processing
   SME_FINISH_CATCH;

}

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CSM_TimeStampResp
//
// Description:  copy Constructor
// 
// Inputs: 
//   CSM_TimeStampResp &that - TimeStampResp data
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampResp::CSM_TimeStampResp(const CSM_TimeStampResp& that)  
{
	*this = that;

}  // end of copy constructor

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  operator =
//
// Description:  
// 
// Inputs: 
//   CSM_TimeStampResp &TSResp - TimeStampResp data
//
// Outputs:  NONE
//
// Returns:  this - CSM_TimeStampResp
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampResp & CSM_TimeStampResp::operator = (const CSM_TimeStampResp &TSResp)
{
	status = TSResp.status;
	if (TSResp.timeStampToken)
	   this->timeStampToken = new ContentInfo(*TSResp.timeStampToken);

   return(*this);
}

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  DetermineTSAInstance
//
// Description:  This function takes the input lpszLogin and finds the instance
//               in input parameter pCsmime if lpszLogin is not null.  If an error 
//               occurred, pErrorStr is set with error data.  If lpszLogin is 
//               NULL then the pCsmime input parameter is searched for the TSA.
//               An instance has to be applicable, have certificates, has to be 
//               a signer, a TSA, and the first one to be returned.    
//               A count is kept for the number of TSA's in the pCsmime data and 
//               an error is returned appropriately according to the count.
// 
// Inputs:   CSMIME *pCsmime  - logins
//           char *lpszLogin  - TSA dn string
//
// Outputs:  const char *&pErrorStr - Error String if Error occurred
//
// Returns:  pInst - Instance found using lpszLogin
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_CSInst *CSM_TimeStampResp::DetermineTSAInstance(
    CSMIME *pCsmime, char *lpszLogin, const char *&pErrorStr, bool bChkApplicable)
{
   CSM_CSInst *pInst = NULL;

   // set tsa general Name
   if(lpszLogin != NULL)
   {
      pCsmime->ClearFlag(SM_INST_ALL);
      pInst = pCsmime->FindInstByDN((char *)lpszLogin);  // don't delete pInst, just a pointer
      if (pInst == NULL)
      {   
         pErrorStr = strdup("ERROR:	DN not in instance list");
      }
      else
      {
         // check if the instance is a tsa
         if (pInst->IsTSA())
         {
            pInst->SetUseThis();
            pInst->SetApplicable();
         }
         else
         {
            pErrorStr = strdup("ERROR:	This Cert Authority is not a Time Stamp Authority");
         }
      }	 
   }
   else
   {
      // check that there is only 1 signer specified by user
      // go thru for loop pcsmime and error out if more than 1 signer
      CSM_CtilInstLst::iterator itTmpInst;
      CSM_CSInst *ptmpInst2;
	  int moreThan1 = 0;

      for(itTmpInst =  pCsmime->m_pCSInsts->begin();
          itTmpInst != pCsmime->m_pCSInsts->end();
          ++itTmpInst)
      {
       
          // IF SESSION REQUESTED TO SIGN THIS TimeStamp Request
          ptmpInst2 = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
          if (ptmpInst2 && /*ptmpInst2->IsApplicable() && */
            ptmpInst2->HasCertificates() && ptmpInst2->IsSigner())
                             // Check that this instance can sign as a TSA
          {
             if (ptmpInst2->IsTSA())
             {
				 if (moreThan1 == 0) // if first one found return pointer to it
				    pInst = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
                 
				 // if the applicable flag already set there should only be 1 tsa
				 if (ptmpInst2->IsApplicable())
				 {
                    moreThan1++;
				 }
             }
          }       // END for each instance.
	  }
	  
	  if (moreThan1 > 1)
	  {
         pErrorStr = strdup("ERROR:	More than 1 TSA for Time Stamping");
	  }
	  else if (moreThan1 == 0)
	  {
         pErrorStr = strdup("ERROR:	NO TSA specified for Time Stamping");
	  }
   }

   return pInst;
 }

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  AssignFirstTsa
//
// Description:  This function calls DetermineTSAInstance to find the first TSA
//               instance in the pCsmime data and sets the useThis and applicable
//               flags if the TSA instance is returned.  Otherwise an error is 
//               returned.
// 
// Inputs:   CSMIME *pCsmime  - certs from logins
//
// Outputs:  const char *&pErrorStr - Error String if Error occurred
//
// Returns:  status of assignment 0 - successful 
//                                1 - not successful
//
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_TimeStampResp::AssignFirstTSA(CSMIME *pCsmime, const char *&pErrorStr)
{
   CSM_CSInst *pInst = NULL;
   SM_RET_VAL status = 1;

   // set tsa general Name
   if(pCsmime != NULL)
   {
      pInst = DetermineTSAInstance(pCsmime, NULL, pErrorStr);
	   
	   // check if the instance is a tsa
	   if (pInst && pInst->IsTSA())
      {
		   status = 0;
		   pInst->SetUseThis();
         pInst->SetApplicable();
      }

   }

   return status;
 }



////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CreateTimeStampToken
//
// Description:  Member function builds the CSM_TimeStampResp by using the data
//               from the CSM_TimeStampReq TSReq input.  It checks lpszLogin for
//               the TSA by calling DetermineTSAInstance.  This Function
//               makes checks on the data and sets any error with appropriate 
//               error and failure codes if any occurs.  If an error occurs then
//               the function returns a NULL and the status member will be filled
//               with appropriate data according to failure.
// 
// Inputs:   CSMIME *pCsmime - login list
//           CSM_TimeStampReq &TSReq - TimeStampReq data
//           char *lpszLogin - DN of TSA
//           char *pTSSnFn - serial number file name
//
// Outputs:  NONE
//
// Returns:  If successful function returns a CSM_Buffer with an encoded
//                ContentInfo of the timeStampToken.  
//           Null if not successful.  The status member will be filled in with
//                the error information
//
////////////////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_TimeStampResp::CreateTimeStampToken(
    CSMIME *pCsmime, CSM_TimeStampReq &TSReq,  char *lpszLogin, int serialNum,
    CSM_CertificateChoice *&pSigningCert, AsnOid *pPolicyOid)
{
   SM_RET_VAL retVal = 0;
   CSM_Buffer *pCIResponseBuf = NULL;
   CSM_CSInst *pInst = NULL;
   CSM_MsgToSign tmpMsgToSign;
   CSM_TimeStampTokenInfo *pTSTInfo = NULL;

   SME_SETUP("CSM_TimeStampResp::CreateTimeStampToken()");

   // set the content to be signed tstInfoBuf already created
   if ((pTSTInfo = new CSM_TimeStampTokenInfo(TSReq)) == NULL)
   {
	   SetStatusError(SNACC::PKIStatus::rejection , "ERROR:  Creating TimeStampTokenInfo", 
		   SNACC::PKIFailureInfo::addInfoNotAvailable);
   }

   // set tsa general Name
   if (status.status == SNACC::PKIStatus::granted ||
	   status.status == SNACC::PKIStatus::grantedWithMods)
   {
      const char *pErrorStr = NULL;
      pInst = DetermineTSAInstance(pCsmime, lpszLogin, pErrorStr, true);

      if (pErrorStr)
      {
	      SetStatusError(SNACC::PKIStatus::rejection , pErrorStr, 
		        SNACC::PKIFailureInfo::addInfoNotAvailable);
      }
   }


   if (status.status == SNACC::PKIStatus::granted ||
	   status.status == SNACC::PKIStatus::grantedWithMods)
   {
	   if (pInst && (pInst->AccessUserCertificate() == NULL))
      {
          SME_THROW(22, "Error getting the user certificate before checking the cert policy id!", NULL);
      }

		// set the pTSTInfo tsa general name 
		if (pTSTInfo->tsa != NULL)
			delete pTSTInfo->tsa;
 
		CSM_GeneralName *pGN = new CSM_GeneralName(*pInst->AccessSubjectDN());

	  	if ((pTSTInfo->tsa = new GeneralName(*pGN)) == NULL)
		{
			SME_THROW(SM_MEMORY_ERROR, "Error creating TSA generalName!", NULL);
		}

      // clean up
      if (pGN)
         delete pGN;

	   const SNACC::Certificate *pCert = pInst->AccessUserCertificate()->AccessSNACCCertificate();

      // check the policy id of the tsa against the user requested policy id if present
      if (pCert && TSReq.reqPolicy != NULL)
      {
         if ((CheckPolicyId(pCert->toBeSigned.extensions, *TSReq.reqPolicy)) == true)
         {
             pTSTInfo->policy = *TSReq.reqPolicy;
         }
		   else
         {
               char buf[100];
			   sprintf(buf, "Error:  Unaccepted Policy Id, %s", TSReq.reqPolicy->GetChar());
			   std::cout << buf << std::endl;
			   SetStatusError(SNACC::PKIStatus::rejection , buf, 
				  SNACC::PKIFailureInfo::unacceptedPolicy);
         }
      }
	   else
      {
         if (pPolicyOid && CheckPolicyId(pCert->toBeSigned.extensions, *pPolicyOid))
         {
            pTSTInfo->policy = *pPolicyOid;
         }
         else
         {
		 	   SetStatusError(SNACC::PKIStatus::rejection , "ERROR:  No TSA Policy ID", 
		          SNACC::PKIFailureInfo::unacceptedPolicy);
         }
      }
   }

   if (status.status == SNACC::PKIStatus::granted ||
	   status.status == SNACC::PKIStatus::grantedWithMods)
   {
      retVal = CheckMessageImprint(&TSReq.messageImprint);
   }

   if (status.status == SNACC::PKIStatus::granted ||
	   status.status == SNACC::PKIStatus::grantedWithMods)
   {
      // set serialNumber
      // Time-Stamping users MUST be ready to accommodate integers up to 160 bits
      if ((retVal = pTSTInfo->SetSerialNumber(serialNum)) != SM_NO_ERROR)
      {
	      SetStatusError(SNACC::PKIStatus::rejection , "ERROR: Creating a Unique Serial Number", 
		      SNACC::PKIFailureInfo::addInfoNotAvailable);
      }
   }

   if (status.status == SNACC::PKIStatus::granted ||
	   status.status == SNACC::PKIStatus::grantedWithMods)
   {
      // set genTime
      CSM_Buffer *pTmpTime = pTSTInfo->GetUntrustedTime();

      if (pTmpTime->Length() == 0)
      {
	      SetStatusError(SNACC::PKIStatus::rejection , "ERROR: Creating an Untrusted Time", 
		     SNACC::PKIFailureInfo::timeNotAvailable);
      }
      else
      {
         pTSTInfo->genTime = pTmpTime->Access();
         delete pTmpTime;
      }
   }

   // set accuracy - We don't support this yet

   // set ordering - We don't support this yet

   // set the extensions if any TBD
   
   if (status.status == SNACC::PKIStatus::granted ||
	   status.status == SNACC::PKIStatus::grantedWithMods)
   {
      // encode the TSTInfo data
      // encode the TSTInfo data
      CSM_Buffer TSTInfoBuf;
      TSTInfoBuf.Encode(*pTSTInfo);
#ifdef _DEBUG
      TSTInfoBuf.ConvertMemoryToFile("./TimeStampTokenInfo.out");
#endif

       tmpMsgToSign.SetEncapContentClear(TSTInfoBuf, id_ct_TSTInfo);

       //  WE ARE SAYING THERE IS ONLY ONE CSInst
       if (pInst != NULL)
       {
          CSM_IssuerAndSerialNumber *ptmpIssSN = pInst->AccessIssuerAndSerialNumber();
          tmpMsgToSign.m_pSignedAttrs = new CSM_MsgAttributes;

		  // set the signing certificate into the attr - should always be done
          CSM_Buffer *pCertBuf = (CSM_Buffer *)pInst->AccessUserCertificate()->AccessEncodedCert();
          if (pCertBuf->Length() == 0)
          {
 	         SetStatusError(SNACC::PKIStatus::rejection , "ERROR: With TSA Certificate", 
		        SNACC::PKIFailureInfo::addInfoNotAvailable);
          }
		  else
		  {

             CSM_SigningCertificate signCert(*pCsmime, *pCertBuf, *ptmpIssSN);

             // create signingCertificate attribute
             CSM_Attrib tmpAttr(&signCert);
             tmpMsgToSign.m_pSignedAttrs->AddAttrib(tmpAttr);

             // if certReq then set the flag to include the originator certificate     
             if(TSReq.certReq && *TSReq.certReq) 
			 {
                 // add the certs to the certificate member
				 tmpMsgToSign.SetIncludeOrigCertsFlag(true); 
			 }
             else
			 {
			    // send back the signing certificate for use in verification later since 
				// the certificate will not be in the signedData
			    if (pSigningCert != NULL)
				   delete pSigningCert;
			    pSigningCert = new CSM_CertificateChoice(*pInst->AccessUserCertificate());
             
			    // don't include the cert in the certificate member
			    tmpMsgToSign.SetIncludeOrigCertsFlag(false);
			 }
		  }

          // sign and check
          if(( retVal = tmpMsgToSign.Sign(pCsmime)) != 0)
          {
  	            SetStatusError(SNACC::PKIStatus::rejection , "ERROR: Signing timeStampToken", 
		           SNACC::PKIFailureInfo::addInfoNotAvailable);
          }
          else
          {
             // set granted status
             status.status = SNACC::PKIStatus::granted;
             status.statusString = new PKIFreeText;
             UTF8String TmpStr("Granted");
             status.statusString->append(TmpStr); 
             
             // get the TimeStampToken ContentInfoBuffer 
             pCIResponseBuf = tmpMsgToSign.GetEncodedContentInfo();

#ifdef _DEBUG
              
             pCIResponseBuf->ConvertMemoryToFile("./TimeStampToken.out");
#endif
          }
       }   
       else
       {
  	      SetStatusError(SNACC::PKIStatus::rejection , "ERROR: no applicable login for TimeStampToken", 
		     SNACC::PKIFailureInfo::addInfoNotAvailable);
       }
   }


   // clean up
   if (pTSTInfo)
	   delete pTSTInfo;
   SME_FINISH_CATCH;

   return pCIResponseBuf;
}


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CheckPolicyId
//
// Description:  Member function searches through the extensions list for the
//               certificate policies.  Then searches through the certificate
//               policies for the input policyId and returns true or false
//               depending whether it was found or not.  If the policy was not
//               found then the status member is set with error information.
// 
// Inputs:   Extensions *pExtensions from Cert
//           SNACC::AsnOid &policyId - to check for
//
// Outputs:  NONE
//
// Returns:  bool  - True if Policy Id is found in certPolicyList, otherwise
//                   False
//
////////////////////////////////////////////////////////////////////////////////
bool CSM_TimeStampResp::CheckPolicyId(Extensions *pExtensions, SNACC::AsnOid &policyId)
{
  	 bool                      policyFound = false;
     Extensions::iterator      itSNACCExt;
    CertificatePoliciesSyntax *pCertPolicies = NULL;
	 
    if (pExtensions)
    {
        for(itSNACCExt = pExtensions->begin();
            itSNACCExt != pExtensions->end() && !policyFound;
            ++itSNACCExt)
        {
#ifdef _DEBUG
           std::cout << "\nCertificate Extension Id:  ";
	       std::cout << itSNACCExt->extnId.GetChar();
#endif
           if(itSNACCExt->extnId == id_ce_certificatePolicies)
           {
              pCertPolicies = (CertificatePoliciesSyntax *)itSNACCExt->extnValue.value;
			     CML::ASN::CertPolicyList *pPolicyInfoList = new CML::ASN::CertPolicyList(*pCertPolicies);
			     CML::ASN::CertPolicyList::const_iterator idPtr = pPolicyInfoList->Find(policyId);
			
              if (idPtr != pPolicyInfoList->end())
              {
				     policyFound = true;
              }

			     // clean up
			     if (pPolicyInfoList)
				    delete pPolicyInfoList;
           }
       }
#ifdef _DEBUG
               std::cout << std::endl;
#endif

    } // end if pExtensions

	 return policyFound;
}





////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CheckMessageImprint
//
// Description:  Member function checks the messageImprint pMsgImprint parameter
//               and makes sure that the size of the hash value matches the expected
//	             size of the hash algorithm identified in hashAlgorithm             
// 
// Inputs:   SNACC::MessageImprint *pMsgImprint
//
// Outputs:  NONE
//
// Returns:  0 - check successful
//           1 - Bad Alg
//
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_TimeStampResp::CheckMessageImprint(MessageImprint *pMsgImprint)
{

	SM_RET_VAL status = 0;

    // check the messageImprint and make sure that the 
	// size of the hash value matches the expected
	// size of the hash algorithm identified in hashAlgorithm
    if (pMsgImprint->hashAlgorithm.algorithm == md5)
	{
        // md5 length should be 16 bytes
		if (pMsgImprint->hashedMessage.length() != 0x10)
		{
	        SetStatusError(SNACC::PKIStatus::rejection , "ERROR:  BadAlg", 
		        SNACC::PKIFailureInfo::badAlg);
			status = 1;
		}
	}
	else if (pMsgImprint->hashAlgorithm.algorithm == sha_1)
	{
        // sha_1 length should be 20 bytes
		if (pMsgImprint->hashedMessage.length() != 0x14)
		{
	        SetStatusError(SNACC::PKIStatus::rejection , "ERROR:  BadAlg", 
		        SNACC::PKIFailureInfo::badAlg);
			status = 1;
		}
	}
	else 
	{
	   SetStatusError(SNACC::PKIStatus::rejection , "ERROR:  BadAlg", 
		   SNACC::PKIFailureInfo::badAlg);
	   status = 1;
    }
   
    return status;
}


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  AccessTimeStampToken
//
// Description:  
// 
// Inputs:  NONE
//
// Outputs:  NONE
//
// Returns:  CSM_Buffer of the TimeStampToken
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_TimeStampResp::AccessTimeStampToken()
{
   CSM_Buffer *pEncCITSTBuf = NULL;

   SME_SETUP("CSM_TimeStampResp::AccessTimeStampToken()");

   
   SME_FINISH_CATCH;

   return pEncCITSTBuf;

}


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  WasSuccessful()
//
// Description:  Member function checks the status error and if set to granted
//               or grantedWithMods function will return true, otherwise false.
// 
// Inputs:  NONE
//
// Outputs:  NONE
//
// Returns:  bool stat  - Status whether or not an error occurred during the 
//                        building of the timeStampToken
//
//
////////////////////////////////////////////////////////////////////////////////
bool CSM_TimeStampResp::WasSuccessful()  
{
   bool stat = false;

   if (status.status == SNACC::PKIStatus::granted ||
	   status.status == SNACC::PKIStatus::grantedWithMods)
      stat = true;

   return stat;

}  // end of WasSuccessful


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  void SetStatusError(int errorCode,
//                                      const char *pStatusStr, int FailureInfo)
//
// Description:  This function sets the error code, status string and failure
//               info into the status member variable
// 
// Inputs:  int errorCode
//          const char *pStatusStr
//          int FailureInfo
//
// Outputs:  Status member changed with input data
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
void CSM_TimeStampResp::SetStatusError(int errorCode , const char *pStatusStr, int FailureInfo)
{
   status.status = errorCode;
   status.statusString = new PKIFreeText;
   UTF8String TmpStr(pStatusStr);
   *status.statusString->append(TmpStr);   
   status.failInfo = new PKIFailureInfo;
   status.failInfo->Set(FailureInfo);

}

_END_SFL_NAMESPACE
