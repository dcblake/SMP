//////////////////////////////////////////////////////////////////////////////
//
// sm_TimeStampToken.cpp
//
// These routines support the CSM_MsgToTimeStamp class.
//
// DESTRUCTOR FOR CSM_MsgToTimeStamp
//     ~CSM_MsgToTimeStamp()
//
// CONSTRUCTOR FOR CSM_MsgToTimeStamp
//     CSM_MsgToTimeStamp(CSMIME *pCSMIME, CSM_Buffer *pBlob,
//                          bool bVerifySignatureFlag) :
//         CSM_MsgToAddSignatures(pCSMIME, pBlob, bVerifySignatureFlag)
//
// MEMBER FUNCTIONS FOR CSM_MsgToTimeStamp
//     Clear()
//     SetTimeStampAttr(CSM_Buffer *pBuf, const char *lpszLogin, bool bAddCert)
//
//////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "sm_api.h"

_BEGIN_SFL_NAMESPACE
using namespace SNACC;



// DESTRUCTOR FOR CSM_MsgToTimeStamp
////////////////////////////////////////////////////////////////////////////////
//
// Member function:  ~CSM_MsgToTimeStamp
//
// Description:  Destructor
//
// Input:    NONE
//
// Output:   NONE
//
// Returns:  NONE
// 
////////////////////////////////////////////////////////////////////////////////
CSM_MsgToTimeStamp::~CSM_MsgToTimeStamp()
{
	if (m_pSID)
		delete m_pSID;
}

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CSM_MsgToTimeStamp
//
// Description:  Constructor
//   Constructor using a Content Info Message as input to create a Message
//   to CounterSign.  Pass all the arguments to the inherited
//   CSM_MsgToAddSignatures constructor which takes the same three objects.
//
// Input:   CSMIME *pCSMIME,              // logins
//          CSM_Buffer &SDBlob            // original SD
//          bool bVerifySignatureFlag     // to verify original SD
//
// Output:   NONE
//
// Returns:  NONE
// 
////////////////////////////////////////////////////////////////////////////////
CSM_MsgToTimeStamp::CSM_MsgToTimeStamp(CSMIME *pCSMIME, 
       const CSM_Buffer &SDBlob,  // original SD
       bool bVerifySignatureFlag,       
       bool bCMLUseToValidate, 
       bool bCMLFatalFail, 
       long lCmlSessionId, 
       long lSrlSessionId) :  // to verify original SD
    CSM_MsgToAddSignatures(pCSMIME, &SDBlob, bVerifySignatureFlag,       
        bCMLUseToValidate, 
        bCMLFatalFail, 
        lCmlSessionId, 
        lSrlSessionId)
{ 
       Clear();
}

// Clear:
//   FUNCTION TO INITIALIZE THE DATA MEMBERS OF THIS CLASS
//   INPUT:  NONE
//   OUTPUT: NONE
//   STATUS: NONE
//
////////////////////////////////////////////////////////////////////////////////
//
// Member function:  Clear
//
// Description:  This function sets member variable to intial condition
//
// Input:    NONE
//
// Output:   NONE
//
// Returns:  NONE
// 
////////////////////////////////////////////////////////////////////////////////
void CSM_MsgToTimeStamp::Clear()
{
   m_pSID = NULL;
};


///////////////////////////////////////////////////////////////////////////////
//
// Member function:  SetSITimeStamp
//
// Description:  This function sets the m_pSID member variable 
//
// Input:   CSM_RecipientIdentifier &RecipId
//
// Output:   NONE
//
// Returns:  status 0
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_MsgToTimeStamp::SetSID(CSM_RecipientIdentifier &RecipId)
{
    SM_RET_VAL ret = SM_NO_ERROR;

    m_pSID = new CSM_RecipientIdentifier(RecipId);

    return ret;
} // END OF MEMBER FUNCTION SetSITimeStamp

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  AccessSignerInfoToTimeStamp
//
// Description:  This function returns the SignerInfo specified by the m_pSid 
//
// Input:   NONE
//
// Output:   NONE
//
// Returns:  SNACC::SignerInfo  or NULL
//
////////////////////////////////////////////////////////////////////////////////
SNACC::SignerInfo *CSM_MsgToTimeStamp::AccessSignerInfoToTimeStamp()
{
   SignerInfo        *pTmpSNACC_SI = NULL;
   SignerInfos::iterator itTmpSNACC_SI;

   SME_SETUP("CSM_MsgToTimeStamp::AccessSignerInfoToTimeStamp");

   if (m_pSID == NULL)
   {
      if (m_SnaccSignedData.signerInfos.size())
         itTmpSNACC_SI = m_SnaccSignedData.signerInfos.begin();
      else
          itTmpSNACC_SI = m_SnaccSignedData.signerInfos.end();
   }
   else
   {
      // LOOP THROUGH THE LOW LEVEL SNACC SignedData TO ISOLATE THE ONE
      //   WHICH HAS A Signer ID MATCHING THE ONE IN THE MsgToTimeStamp
      for (itTmpSNACC_SI = m_SnaccSignedData.signerInfos.begin();
           itTmpSNACC_SI != m_SnaccSignedData.signerInfos.end();
           ++itTmpSNACC_SI)
      {
         // Pull the Signer ID for this MsgSignerInfo
         CSM_RecipientIdentifier tmpSID(itTmpSNACC_SI->sid);

#ifdef _DEBUG

		   if (tmpSID.AccessIssuerAndSerial() &&
			   tmpSID.AccessIssuerAndSerial()->AccessSNACCIssuerAndSerialNumber())
         {
            CSM_IssuerAndSerialNumber *pIss = (CSM_IssuerAndSerialNumber *)tmpSID.AccessIssuerAndSerial();
            CSM_DN *pDN = pIss->GetIssuer();
            char *ptr = strdup(*pDN);
            CSM_Buffer *pBuf = pIss->GetSerialNo();

            std::cout << std::endl << "SI Issuer:  " << ptr;
			   std::cout << "SI serialNumber:  "; 
            pBuf->ReportHexBuffer(std::cout);
            std::cout << std::endl;

            if (pBuf)
               delete pBuf;
            if (pDN)
               delete pDN;
            if (ptr)
               free(ptr);
         }

		   if (tmpSID.AccessSubjectKeyIdentifier())
			   std::cout << "SI SubjectPubKeyID:  " 
                      << tmpSID.AccessSubjectKeyIdentifier()->Access() << std::endl;
#endif

         // CHECK THIS Signer ID AGAINST THE ONE FOR THE timeStamping
         if (*m_pSID == tmpSID)
         {
            break;
         }
      }
   }
   
   if (itTmpSNACC_SI != m_SnaccSignedData.signerInfos.end())
       pTmpSNACC_SI = &(*itTmpSNACC_SI);    // RETURN actual indexed SI in list.


    SME_FINISH
    SME_CATCH_SETUP
    // local cleanup logic
    SME_CATCH_FINISH

    return pTmpSNACC_SI;
}

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  LoadSignerInfoWithTST
//
// Description:  This function loads the SignerInfo with TimeStampToken after 
//               finding the right signerInfo sid
//
// Input:   TimeStampToken &snaccTST
//
// Output:   NONE
//
// Returns:  status 0 if signerInfo was loaded with TST otherwise 1
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_MsgToTimeStamp::LoadSignerInfoWithTST(TimeStampToken &snaccTST)
{
   SM_RET_VAL        status = 1;  // No signer loaded yet
   SignerInfo        *pTmpSNACC_SI = AccessSignerInfoToTimeStamp();

   SME_SETUP("CSM_MsgToTimeStamp::LoadSignerInfoWithTST");

   if (pTmpSNACC_SI)
   {
         // set the timeStamptoken into the signerInfo unsigned attr list
         // has to do with inheritance structure
         // call static function SetTimeStampAttr to add the timeStampToken to the first signerInfo
          CSM_MsgSignerInfo::SetTimeStampAttr(*pTmpSNACC_SI, snaccTST);

          status = 0;  // signer loaded
   }


    SME_FINISH
    SME_CATCH_SETUP
    // local cleanup logic
    SME_CATCH_FINISH

    return status;

}

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  VerifyTimeStampToken
//
// Description:  This function the CSM_MsgToVerify::VerifyTimeStampToken to
//               verify the TimeStampToken
//
// Input:   CSMIME *pCsmime, 
//          SNACC::TimeStampToken &snaccTSTTimeStampToken &snaccTST
//
// Output:   NONE
//
//   RETURN: SM_NO_ERROR                    success
//           SM_NOT_SIGNED                  input parameter data snaccTST
//           SM_SNACCTST_ENCODE_ERR         input Data building MsgToVerify    
//           SM_CONTENT_HAS_NO_TSTINFO      encapsulated content type from the 
//                                          snaccTST
//           SM_SIG_NOT_VERIFIED            snaccTST TimeStampToken did not verify
//                                          outer SignedData
//           SM_CONTENT_NOT_TSTINFO         ContentType of unsignedAttributed from /
//                                          SignerInfo  not id_ct_TSTInfo
//           SM_NO_TSTINFO_CONTENT          with data of id_ct_TSTInfo 
//                                          TimeStampTokenInfo
//           SM_SIG_DOES_NOT_MATCH_HASH     Signature does not match 
//                                          hashedMessage from MessageImprint
//           SM_GENTIME_NOT_VERIFIED        genTime did not verify against the 
//                                          TSA's signer Cert validity period
//           SM_CML_NOT_AVAILABLE -         Everything verified except the TSA's
//                                          signer Cert because ACL/CML not available
//                                          or tsa signingCert or rid not available
//                  
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_MsgToTimeStamp::VerifyTimeStampToken(CSMIME *pCsmime, 
                                                    std::ostream *pOstrm)                                                
{
   SM_RET_VAL        status = 0;
   SignerInfo        *pTmpSI;
   ContentInfo       *pContentInfo;

   SME_SETUP("CSM_MsgToTimeStamp::VerifyTimeStampToken");

   // sib can not call due to sign side having timeStampToken not Verify side
   // status = CSM_MsgToVerify::VerifyTimeStampToken(pCsmime, pOstrm);

   // assume User verified original SignedData
   
   pTmpSI = AccessSignerInfoToTimeStamp();
   if (pTmpSI && pTmpSI->unsignedAttrs)
   {
      CSM_MsgAttributes tmpMsgAttribs(*pTmpSI->unsignedAttrs);
      pContentInfo = tmpMsgAttribs.GetTimeStampToken();
      if (pContentInfo)
      {
         status = CSM_MsgSignerInfo::VerifyTimeStampToken(*pTmpSI,pCsmime,
           *pContentInfo, m_pTimeStampCertificate, pOstrm, m_bCMLFatalFail, 
           m_bCMLUseToValidate, m_lCmlSessionId, m_lSrlSessionId);

#ifdef _DEBUG
         // flush all stream reports
         if (pOstrm)
		 {
		    std::cout << "status:  " << status << "  ";
            pOstrm->flush();
		 }
#endif

         delete pContentInfo;
      }
   }

   SME_FINISH
   SME_CATCH_SETUP
   // local cleanup logic
   SME_CATCH_FINISH

   return status;
}


_END_SFL_NAMESPACE

// EOF sm_TimeStampToken.cpp

