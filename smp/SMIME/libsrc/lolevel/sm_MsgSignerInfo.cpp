
//////////////////////////////////////////////////////////////////////////////
// sm_MsgSignerInfo.cpp
//  These routines support CSM_MsgSignerInfo and CSM_MsgSignerInfos classes.
//
// CONSTRUCTOR FOR CSM_MsgSignerInfo
//     CSM_MsgSignerInfo(SignerInfo *pSignerInfo)
//
// DESTRUCTOR FOR CSM_MsgSignerInfo
//     ~CSM_MsgSignerInfo()
//
// MEMBER FUNCTIONS FOR CSM_MsgSignerInfo
//     UpdateSignerInfoCerts(CSM_CertificateChoiceLst *pCerts)
//     SetSignerInfo(SignerInfo &iSignerInfo)
//     SetSignerInfoCerts(CSM_CertificateChoiceLst &Certs)
//     GetSignerIdentifier()
//     GetIssuerAndSerial()
//     GetCerts()
//     AccessCerts()
//     GetDigestId()
//     GetSignatureId()
//     LoadSICertPath(CSM_MsgCertCrls *pMsgCertCrls)
//     VerifySignerInfoCSs(CSMIME *pCsmime,
//                         CSM_MsgCertCrls *pMsgCertCrls,
//                         ostream *pos)
//     ReportMsgData(ostream &os) (FOR CSM_MsgSignerInfo)
//     Verify(CSMIME *pCSMIME,
//            CSM_Buffer *pOriginalEncapContent,
//            EncapsulatedContentInfo *encapContentInfo,
//            CSM_CertificateChoiceLst *pCerts,
//            CSM_MsgAttributes *pSignedAttrs)
//     GetCSVerifyDescription(long lResults)
//     CSM_MsgSignerInfo &operator = (CSM_MsgSignerInfo &msgSI)
//
// MEMBER FUNCTIONS FOR CSM_MsgSignerInfos
//     VerifyMsgCSs(CSMIME *pCsmime,
//                  CSM_MsgCertCrls *pMsgCertCrls,
//                  ostream *pos)
//     ReportMsgData(ostream &os) (FOR CSM_MsgSignerInfos)
//////////////////////////////////////////////////////////////////////////////

#include "sm_api.h"
#include "sm_VDAStream.h"
#include <fstream>
#include <iostream>

_BEGIN_SFL_NAMESPACE
using namespace SNACC;

// BEGIN CSM_MsgSignerInfo FUNCTION DEFINITIONS

// CSM_MsgSignerInfo:
//     CONSTRUCTOR FOR CSM_MsgSignerInfo using SNACC SignerInfo
//
CSM_MsgSignerInfo::CSM_MsgSignerInfo(SignerInfo *pSignerInfo)
{
    Clear();
    if (pSignerInfo)
        SetSignerInfo(*pSignerInfo);
} // END OF CONSTRUCTOR FOR CSM_MsgSignerInfo

// ~CSM_MsgSignerInfo:
//     DESTRUCTOR FOR CSM_MsgSignerInfo
//
CSM_MsgSignerInfo::~CSM_MsgSignerInfo()
{
    if (m_pCerts)
        delete m_pCerts;
    if (m_pSignedAttrs)
        delete m_pSignedAttrs;
    if (m_pSignerInfo)
        delete m_pSignerInfo;
    if (m_pUnsignedAttrs)
        delete m_pUnsignedAttrs;
    if (m_pPreHashBuffer)
        delete m_pPreHashBuffer;
} // END OF DESTRUCTOR FOR CSM_MsgSignerInfo

// UpdateSignerInfoCerts:
//
void CSM_MsgSignerInfo::UpdateSignerInfoCerts(CSM_CertificateChoiceLst *pCerts)
{
    SME_SETUP("CSM_MsgSignerInfo::UpdateSignerInfoCerts");

    if (m_pCerts)
        delete m_pCerts;
    m_pCerts = pCerts;      // Take caller's memory for "pCerts".

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION UpdateSignerInfoCerts

// SetSignerInfo:
//
void CSM_MsgSignerInfo::SetSignerInfo(SignerInfo &iSignerInfo)
{
    SME_SETUP("CSM_MsgSignerInfo::SetSignerInfoCerts");
    if (m_pSignerInfo == NULL)
    {
        m_pSignerInfo = new SignerInfo;
    }
    *m_pSignerInfo = iSignerInfo;
    // LOAD Signed Attributes
    if (m_pSignerInfo->signedAttrs != NULL)
    {
        if (m_pSignedAttrs) delete m_pSignedAttrs;
        if ((m_pSignedAttrs = new CSM_MsgAttributes) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

        m_pSignedAttrs->
            UnLoadSNACCSignedAttrs(*m_pSignerInfo->signedAttrs);
    }

    // LOAD Unsigned Attributes
    if (m_pSignerInfo->unsignedAttrs != NULL)
    {
        if (m_pUnsignedAttrs) delete m_pUnsignedAttrs;
        if ((m_pUnsignedAttrs = new CSM_MsgAttributes) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

        m_pUnsignedAttrs->UnLoadSNACCUnsignedAttrs(
            *m_pSignerInfo->unsignedAttrs);
    }
    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetSignerInfo

// SetSignerInfoCerts:
//
void CSM_MsgSignerInfo::SetSignerInfoCerts(CSM_CertificateChoiceLst &Certs)
{
    SME_SETUP("CSM_MsgSignerInfo::SetSignerInfoCerts");
    if ((m_pCerts = new CSM_CertificateChoiceLst(Certs)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION SetSignerInfoCerts

///////////////////////////////////////////////////////////////////
//
// Member Function:  SetTimeStampAttr
//
// Description:  Function takes TimeStampToken and checks 
//               the SignerInfo unsignedAttrs list input for another 
//               TimeStampToken, before adding the new one.
//               If another TimeStampToken is found then
//               an error occurred.  There can only be one
//               TimeStampTokenin the unsignedAttrs list.
// 
// Input:  SignerInfo &msgSI - SignerInfo to add the token to
//         TimeStampToken &snaccTST - TimeStampToken to add to si
// 
// Output: msgSI will have the TimeStampTokenAdded to the unsigned
//               attribute list
//
//   RETURN: status 0  - success
//                  -1 - failed to add attribute
//
////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_MsgSignerInfo::SetTimeStampAttr(SignerInfo &msgSI,
                                               TimeStampToken &snaccTST)
{
    SM_RET_VAL      status=0;
    CSM_Attrib      TmpTSAttrib;
    CSM_Buffer      *pEncodedAttr = NULL;
    AsnOid          *poid = NULL;

    SME_SETUP("CSM_MsgSignerInfo::SetTimeStampAttr()");

    // Check for Unsigned Attributes in the current SNACC Signer Info
    if (msgSI.unsignedAttrs == NULL)
    {
       // If there are none create a place holder.
       msgSI.unsignedAttrs = new UnsignedAttributes;
    }
    else
    {
       TimeStampToken *pTST = NULL;

       CSM_MsgAttributes msgAttrs(*msgSI.unsignedAttrs);

	    // make sure there are no timeStampToken attrs already in the 
		 // unsignedAttrs list and if so error out
       if ((pTST = msgAttrs.GetTimeStampToken()) != NULL)
       {
          delete pTST;
          SME_THROW(22, "Error:  Multiple timeStampTokens", NULL);
       }
       
    }

    // At this point there are no other TimeStampTokens in the unsignedAttrs list 
    // so add it
    // Create a place holder for the new SNACC attribute
    UnsignedAttributes::iterator TmpSNACCUnsignedAttr;
    TmpSNACCUnsignedAttr = msgSI.unsignedAttrs->append();

    TmpTSAttrib.SetTimeStampToken(&snaccTST);

    TmpTSAttrib.GetEncodedAttr(poid, pEncodedAttr);
	 if (poid && pEncodedAttr)
    {
        TmpSNACCUnsignedAttr->type = *poid;

        // Create a place holder for the new SNACC attribute value
        AttributeSetOf::iterator  TmpSNACCAttrValue;
        TmpSNACCAttrValue = TmpSNACCUnsignedAttr->values.append();

        // Dump the encoded Buffer into the SNACC attribute value
        SM_ASSIGN_ANYBUF(pEncodedAttr, TmpSNACCAttrValue);
    }
    else
    {
       status = -1;  // error
    }

    // CLEAN UP
    if (poid)
    {
        delete poid;
        poid = NULL;
    }
    if (pEncodedAttr)
    {
        delete pEncodedAttr; //   MUST delete since MACRO copies;
                             //   created by GetEncodedAttr().
        pEncodedAttr = NULL;
    }

    SME_FINISH
    SME_CATCH_SETUP
    // local cleanup logic
    SME_CATCH_FINISH

    return(status);

} // END OF MEMBER FUNCTION SetTimeStampAttr

///////////////////////////////////////////////////////////////////
//
// Member Function:  VerifyTimeStampToken
//
// Description:  Function takes TimeStampToken and verifys it:
//
// The time-stamp token itself MUST be verified and it MUST be 
// verified that it applies to the signature of the signer. 
//
// Then verifies the SignerInfo unsignedAttrs TimeStampToken
// and it's data:
//
// The value of the messageImprint field within TimeStampToken 
// shall be a hash of the value of signature field within SignerInfo 
// for the signedData being time-stamped
// 
// The date/time indicated by the TSA MUST be within the validity period
// of the signer's certificate
//
// The revocation information about that certificate, at the date/time of 
// the Time-Stamping operation, MUST be retrieved
//
// Should the certificate be revoked, then the date/time of revocation shall 
// be later than the date/time indicated by the TSA
//
// If all the above conditions are successful, then the digital signature
// shall be declared as valid.
//
// 
// Input:  SignerInfo     &msgSI - SignerInfo to add the token to
//         CSMIME         *pCsmime - For Logins
//         TimeStampToken &snaccTST - TimeStampToken to add to si
//         std::ostream   *pOstrm - For output of status
// 
// Output: NONE
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
//                                          signer Cert because ACL/CML not
//                                          available or tsa signingCert or 
//                                          rid not available
//                  
//
//
////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_MsgSignerInfo::VerifyTimeStampToken(SignerInfo &msgSI, 
												   CSMIME *pCsmime, 
                                       SNACC::TimeStampToken &snaccTST,
												   CSM_CertificateChoice* pSigningCert,
                                       std::ostream *pOstrm,			 
												   bool bCMLFatalFail,
												   bool bCMLUseToValidate,
												   unsigned long ulCmlSessionId,
                                       unsigned long ulSrlSessionId)                                                
{  
   CSM_Buffer        Buf;
   CSM_Buffer*       pTSTInfoBuf = NULL;
   CSM_Buffer        tstBuf;
   CSM_MsgToVerify*  pDataToVerify = NULL;
   SNACC::TSTInfo    snaccTSTInfo;
   SM_RET_VAL        status = SM_NO_ERROR;
   SM_RET_VAL        retStatus = 0;

   // assume User verified original SignedData
  
   SME_SETUP("CSM_MsgSignerInfo::VerifyTimeStampToken");

   if (snaccTST.contentType != id_signedData)
   {
      status = SM_NOT_SIGNED;
      if (pOstrm)
         *pOstrm << "Error:  Input parameter snaccTST is not signedData\n.";
   }
  
   if ((retStatus = Buf.Encode(snaccTST.content)) > 0)
   {
      retStatus = 0;  // wipe away the encoded length
      pDataToVerify = new CSM_MsgToVerify(pCsmime, &Buf, bCMLUseToValidate, 
                                          bCMLFatalFail, 
                                          ulCmlSessionId, 
                                          ulSrlSessionId);
   }  
   else
   {
	   // Error with snaccTST input data
	   status = SM_SNACCTST_ENCODE_ERR;
      if (pOstrm)
        *pOstrm << "Error:  Encoding input parameter snaccTST\n.";
   }
   
   if (status == SM_NO_ERROR && pDataToVerify && 
	   pDataToVerify->m_pSnaccSignedData!= NULL)
   {
      // check the content type of the encapsulated info to be TSTInfo type       
      if (pDataToVerify->m_pSnaccSignedData->encapContentInfo.eContentType != id_ct_TSTInfo)
      {
	      status = SM_CONTENT_HAS_NO_TSTINFO;
         if (pOstrm)
           *pOstrm << "Error:  Content doesn't contain TSTInfo\n";  
      }

      // The time-stamp token itself MUST be verified and it MUST be verified
      // that it applies to the signature of the signer?

      // make sure we have the certs that signed in the certs bucket
      // certReq was null so we need to fill in the signing certificate externally
	   if (pSigningCert && pSigningCert->AccessSNACCCertificate())  
		  // signingCert should only be filled when certReq is 0
	   {
	      if (pDataToVerify->m_pMsgCertCrls == NULL)
             pDataToVerify->m_pMsgCertCrls = new CSM_MsgCertCrls;
         pDataToVerify->m_pMsgCertCrls->AddCert(pSigningCert);
         pDataToVerify->SetSICerts(NULL);        //RWC:THIS WILL ALIGN CERTS WITH SIs.
	   }

      // verify the digital signature of the timeStampToken 
      if ((status == SM_NO_ERROR) && (retStatus = pDataToVerify->Verify(pCsmime)) != 0)
      {
         retStatus = 0;
	      status = SM_SIG_NOT_VERIFIED;
         if (pOstrm)
            *pOstrm << "Error:  Verify signature on TimeStampToken\n";  
      }
#ifdef _DEBUG
      if (pOstrm)
      {
         *pOstrm << "***Begin TimeStampToken Report***\n";
         pDataToVerify->ReportMsgData(*pOstrm);
      }
#endif

      // check content type
      if (status == SM_NO_ERROR && 
		   pDataToVerify->m_pSnaccSignedData->encapContentInfo.eContentType != id_ct_TSTInfo)
      {
		   status = SM_CONTENT_NOT_TSTINFO;
         if (pOstrm)
            *pOstrm << "Error:  Encapsulated Content Type not TSTInfo id_ct_TSTInfo!\n";
      }

      // get the timeStampTokenInfo for verifying the rest of the data
      if (status == SM_NO_ERROR && pDataToVerify->m_pSnaccSignedData->encapContentInfo.eContent != NULL)
      {
         pTSTInfoBuf = new CSM_Buffer(pDataToVerify->AccessEncapContentFromAsn1()->m_content);
         if (pTSTInfoBuf->Length() == 0)
         {
            // there is no tstInfo error out
            status = SM_NO_TSTINFO_CONTENT;
            if (pOstrm)
               *pOstrm << "Error:  No TSTInfo Content!\n";
         }

         // decode the input buffer
         if ((retStatus = pTSTInfoBuf->Decode(snaccTSTInfo)) == 0)
         {
            // there is no tstInfo error out
            status = SM_NO_TSTINFO_CONTENT;
            if (pOstrm)
               *pOstrm << "Error:  Decoding TSTInfo Content!\n";
         }
      }
      else
      {
          // there is no tstInfo error out
		   if (status == SM_NO_ERROR)  // skip if earlier error
		   {
            status = SM_NO_TSTINFO_CONTENT;
            if (pOstrm)
              *pOstrm << "Error:  No TSTInfo Content!\n";
		   }
      }

      // The value of the messageImprint field within TimeStampToken shall be a hash 
      // of the value of signature field within SignerInfo for the signedData being 
      // time-stamped

      // check MessageImprint 
	   if (status == SM_NO_ERROR)
	   {
         CSM_Alg tmpAlg(snaccTSTInfo.messageImprint.hashAlgorithm);
         CSM_CtilInst *pInst = pCsmime->FindCSInstAlgIds(&tmpAlg, NULL, NULL, NULL);
         CSM_Buffer *pBuf = new CSM_Buffer;
         CSM_Buffer sigBuf;
         sigBuf.Set(msgSI.signature.c_str(),msgSI.signature.length());
         if (pInst)
         {
            // hash the signature before comparing with hashedMessage
            pInst->AccessTokenInterface()->SMTI_DigestData(&sigBuf,
                pBuf, snaccTSTInfo.messageImprint.hashAlgorithm.algorithm);
         }

         // compare signature with the hashedMessage
         CSM_Buffer tmpBuf(snaccTSTInfo.messageImprint.hashedMessage.c_str(),
                        snaccTSTInfo.messageImprint.hashedMessage.length());
         if (tmpBuf == *pBuf)
         {
#ifdef _DEBUG
            if (pOstrm)
            {
               *pOstrm << "\nVerifying MessageImprint and Signature:  \n" 
                      << "    MessageImprint the same as Signature in SignerInfo \n";
            }
#endif
         }
         else
         {
            status = SM_SIG_DOES_NOT_MATCH_HASH;
            if (pOstrm)
               *pOstrm << "Error:  Signature does not match hashedMessage from MessageImprint!\n";
         }

         // clean up
         if (pBuf)
            delete pBuf;
	  }
	   

#ifndef DISABLE_CML_ACL

     
     // Appendix B requirements that will be verified by the CML:
	  // 
     // The date/time indicated by the TSA MUST be within the validity period of 
	  // the signer’s certificate.
	  //
	  // The revocation information about that certificate, at the date/time of 
	  // the Time-Stamping operation, MUST be retrieved.
	  //
     // Should the certificate be revoked, then the date/time of the revocation 
	  // shall be later than the date/time indicated by the TSA.


#ifdef _DEBUG
            if (pOstrm)
            {
               *pOstrm << "\nVerifying Signer's Cert/Crl:  \n"; 
            }
#endif

      CM_SFLCertificate ACMLCert;
      bool timeStampNotOk = true;

	   if (pSigningCert != NULL)
         ACMLCert.m_pRID = pSigningCert->GetRid(true);
      if (ACMLCert.m_pRID != NULL)
      {
			CM_Interface cmlInterface(ulCmlSessionId, ulSrlSessionId);

	   	CML::ASN::Time timeStampTime(snaccTSTInfo.genTime);
		   timeStampNotOk = ACMLCert.Validate(cmlInterface, &timeStampTime);

         if (timeStampNotOk != false)
         {
            // Certificate was revoked, The timeStampTime is not in TSA's 
		      // signer certificate validity period.
            status = SM_GENTIME_NOT_VERIFIED;
            if (pOstrm)
		      {
		         *pOstrm << "   Error:  date/time not in TSA's signer certificate\n";
				   *pOstrm << "validity period! SM Error:" << status << "\n";  
		      }  
         }
         else 
         {
            status = SM_NO_ERROR;   // everything is fine
			   if (pOstrm)
			   {
				   *pOstrm << "   TimeStampTime Validated\n";
			   }
         }
      }
      else
      {
	      status = SM_CML_NOT_AVAILABLE;
         if (pOstrm)
         {
            *pOstrm << "Error:  TSA's signing certificate and/or rid not available !\n";
            *pOstrm << "        Certificate & CRL check could not be done!\n";
         }

      }
	      
#else
     // DISABLE_CML_ACL defined
	  if (status == SM_NO_ERROR)
	  {
        // everything up to this point verified but cannot perform the 
        // verification of genTime against the TSA's signer 
		  // certificate validity period
	     status = SM_CML_NOT_AVAILABLE;
        if (pOstrm)
        {
           *pOstrm << "Error:  CML not available to check the Signer's Certificate Crl!\n";
           *pOstrm << "        However everything up to this point verifies ok!\n";
        }
	  }
#endif

#ifdef _DEBUG
	  if (pDataToVerify->m_bCMLUseToValidate == false)
	  {
	     std::cout << "\n****** CML was not used to verify the TSA Certificate *******\n";
		  std::cout << "                 CRL check is not being done\n";
	  }
	  else
	     std::cout << "\n****** CML was used to verify the TSA Certificate *******\n";

#endif

      // If all the above conditions are successful (status = 0), 
	  // then the digital signature shall be declared as valid.
	  if (status == SM_NO_ERROR)
	  {
        if (pOstrm)
        *pOstrm << "TimeStampToken IS Verified and Valid!\n";
	  }
	  delete pDataToVerify;
  }

   if (pTSTInfoBuf != NULL)
  {
     delete pTSTInfoBuf;
     pTSTInfoBuf = NULL;
  }

   SME_FINISH
   SME_CATCH_SETUP
   // local cleanup logic
   if (pTSTInfoBuf)
  {
     delete pTSTInfoBuf;
  }
   SME_CATCH_FINISH

      
#ifdef _DEBUG
   if (pOstrm)
   {
      *pOstrm << "***End TimeStampToken Report***\n";
   }
#endif

   return status;
}


// GetSignerIdentifier:
//
CSM_RecipientIdentifier *CSM_MsgSignerInfo::GetSignerIdentifier()
{
    CSM_RecipientIdentifier *pSNACCRecipIdentifier;

    SME_SETUP("CSM_MsgSignerInfo::GetSignerIdentifier");

    pSNACCRecipIdentifier = new CSM_RecipientIdentifier(m_pSignerInfo->sid);

    SME_FINISH_CATCH

    return(pSNACCRecipIdentifier);

} // END OF MEMBER FUNCTION GetSignerIdentifier

// GetIssuerAndSerial:
//
CSM_IssuerAndSerialNumber *CSM_MsgSignerInfo::GetIssuerAndSerial()
{
    CSM_IssuerAndSerialNumber *pResultIss=NULL;
    SME_SETUP("CSM_IssuerAndSerialNumber::GetIssuerAndSerial");
    if (m_pSignerInfo)
    {

        if (m_pSignerInfo->sid.choiceId ==
            SignerIdentifier::issuerAndSerialNumberCid)
        {
            if ((pResultIss = new CSM_IssuerAndSerialNumber(
                *m_pSignerInfo->sid.issuerAndSerialNumber)) == NULL)
                SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
        }
        else
            SME_THROW(22, "SI SubjectKeyIdentifier NOT SUPPORTED YET.", NULL);
    }

    SME_FINISH_CATCH
    return(pResultIss);

} // END OF MEMBER FUNCTION GetIssuerAndSerial

// GetCerts:
//
CSM_CertificateChoiceLst *CSM_MsgSignerInfo::GetCerts()
{
    CSM_CertificateChoiceLst *pResultCerts=NULL;

    SME_SETUP("CSM_MsgSignerInfo::GetCerts");
    if (m_pCerts)
    {
        if ((pResultCerts = new CSM_CertificateChoiceLst(*m_pCerts)) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
    }

    SME_FINISH_CATCH

    return(pResultCerts);

} // END OF MEMBER FUNCTION GetCerts

// AccessCerts:
//
CSM_CertificateChoiceLst *CSM_MsgSignerInfo::AccessCerts()
{
    return(m_pCerts);
} // END OF MEMBER FUNCTION AccessCerts

// GetDigestId:
//
CSM_Alg* CSM_MsgSignerInfo::GetDigestId()
{
    CSM_Alg *pRet = NULL;

    SME_SETUP("CSM_MsgSignerInfo::GetDigestId");

    if (m_pSignerInfo)
    {
        if ((pRet = new CSM_Alg(m_pSignerInfo->digestAlgorithm)) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
    }

    SME_FINISH_CATCH

    return(pRet);

} // END OF MEMBER FUNCTION GetDigestId

// GetSignatureId:
//
CSM_Alg* CSM_MsgSignerInfo::GetSignatureId()
{
    CSM_Alg *pRet = NULL;

    SME_SETUP("CSM_MsgSignerInfo::GetSignatureId");

    if (m_pSignerInfo)
    {
        if ((pRet = new CSM_Alg(m_pSignerInfo->signatureAlgorithm)) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
    }

    SME_FINISH_CATCH

    return(pRet);

} // END OF MEMBER FUNCTION GetSignatureId

// LoadSICertPath:
//
SM_RET_VAL CSM_MsgSignerInfo::LoadSICertPath(CSM_MsgCertCrls *pMsgCertCrls)
{
    SM_RET_VAL                lStatus=0;
    CSM_CertificateChoiceLst *pCertPath=NULL;
    CSM_RecipientIdentifier  *pRid = NULL;

    SME_SETUP("LoadSICertPath(CSM_MsgCertCrls *pMsgCertCrls)");

    if ((pRid = GetSignerIdentifier()) != NULL)
    {
        // if there are Crls then load the certificates using the pRid
        if (pMsgCertCrls)
        {
            lStatus = CSM_SignBuf::
                LoadCertificatePath(pRid, pMsgCertCrls, pCertPath);
        }

        // clean up memory from GetSignerIdentifier()
        if (pRid)
            delete pRid;

        if (pCertPath)    // THEN load into CSM_MsgSignerInfo
        {
            UpdateSignerInfoCerts(pCertPath);
            // RWC: DO NOT FREE pCertPath memory
        }
    }
    else
    {
        // there is no signer recipient identifier
        SME_THROW(SM_NO_SIGNER_IDENTIFIER, NULL, NULL);
    }

    SME_FINISH
    SME_CATCH_SETUP
        if (pRid)
            delete pRid;
    SME_CATCH_FINISH


    return(lStatus);

} // END OF MEMBER FUNCTION LoadSICertPath

// VerifySignerInfoCSs:
//   INPUT: CSMIME *pCSMIME,
//          CSM_MsgCertCrls *pMsgCertCrls,
//          ostream *pos
//   OUTPUT: NONE
//   RETURN: SM_RET_VAL lSIStatus
// This function loops through the list of Unsigned Attributes in the current
// SignerInfo for each CounterSignature.  With each CounterSignature it finds
// it fills a new MsgSignerInfo using this CounterSignature (which is a SNACC
// SignerInfo), loads the appropriate certificates from MsgCertCrls, extracts
// the Signature value, and passes these and any associated SignedAttributes
// to the Verify function.  NOTE: if there is a valid ostream pointer passed
// in, it is fill with output for CounterSignature Verifications for this
// MsgSignerInfo.  This status will be displayed as a character string
// representing one of the enum status from this class; All Succeeded,
// Some Succeeded, Some Failed, All Failed, None Present, None Verified
//
SM_RET_VAL CSM_MsgSignerInfo::VerifySignerInfoCSs(CSMIME *pCsmime,
                                                 CSM_MsgCertCrls *pMsgCertCrls,
                                                 std::ostream *pos)
{
    SM_RET_VAL lStatus = NONE_PRESENT;
    SM_RET_VAL lSIStatus = NONE_VERIFIED;
    long lCSCount=0;
    Countersignature *tmpCS;
    CSM_RecipientIdentifier *pTmpSID=NULL;
    CSM_MsgSignerInfo *tmpSI=NULL;

    SME_SETUP("CSM_MsgSignerInfo::VerifySignerInfoCSs(CSMIME *pCsmime,CSM_MsgCertCrls *pMsgCertCrls,ostream *pos)");

    // If there is an ostream send it information on what follows
    if (pos != NULL)
    {
        VDAStream::setIndent(VDAStream::getIndent()+1);
        *pos << "Verifying CounterSignatures for this SignerInfo:\n";
        pTmpSID =
         new CSM_RecipientIdentifier(m_pSignerInfo->sid);
        pTmpSID->ReportMsgData(*pos);
        if (pTmpSID)
            delete pTmpSID;
    }

    // Loop through the attribute list CounterSignature by CounterSignature
    for(tmpCS = m_pUnsignedAttrs->AccessFirstCS(); tmpCS != NULL;
        tmpCS = m_pUnsignedAttrs->AccessNextCS())
    {
        // If there is an ostream send it information on what follows
#ifdef RWC_MUST_ADD_FUNCTIONALITY_IF_THIS_EXPECTED
        if (pos != NULL)
        {
            VDAStream::setIndent(VDAStream::getIndent()+1);
            *pos << "Found CounterSignature in attribute "
                 <<  m_pUnsignedAttrs->m_lAttrValueIndex+1
                 << ", "
                 << m_pUnsignedAttrs->m_lMultiAttrIndex+1
                 << "\n";
        }
#endif  // RWC_MUST_ADD_FUNCTIONALITY_IF_THIS_EXPECTED
        // Create a new CSM_MsgSignerInfo for this CounterSignature
        tmpSI = new CSM_MsgSignerInfo(tmpCS);
        // Now Fill in the Certs Path from the message Certificate list
        if (pMsgCertCrls != NULL)
        {
            tmpSI->LoadSICertPath(pMsgCertCrls);

            CSM_Buffer tmpSigCSData(AccessSignerInfo()->signature.c_str(),
                                 AccessSignerInfo()->signature.Len());

            lCSCount++;
            lStatus = tmpSI->Verify(pCsmime, &tmpSigCSData, NULL,
                                    tmpSI->m_pCerts, tmpSI->m_pSignedAttrs);

            // If there is an ostream send it status information for this
            // CounterSignature Verification
            if (pos != NULL)
            {
                VDAStream::setIndent(VDAStream::getIndent()+1);
                *pos << "CounterSignature verification results: ";
                switch (lStatus)
                {
                    case 0:
                        *pos << "Successful\n";
                        break;
                    case 2:
                        *pos << "Login instance not found\n";
                        break;
                    default:
                        *pos << "Failed (" << lStatus << ")\n";
                        break;
                }
                VDAStream::setIndent(VDAStream::getIndent()-2);
                pos->flush();
            }

            switch (lSIStatus)
            {
                case ALL_SUCCEEDED:
                case SOME_SUCCEEDED:
                    if (lStatus != SM_NO_ERROR)
                        lSIStatus = SOME_FAILED;
                    break;
                case ALL_FAILED:
                    if (lStatus == SM_NO_ERROR)
                        lSIStatus = SOME_FAILED;
                    break;
                case NONE_PRESENT:
                case NONE_VERIFIED:
                    if (lStatus != SM_NO_ERROR)
                        lSIStatus = ALL_FAILED;
                    else
                        lSIStatus = ALL_SUCCEEDED;
                    break;
            }
            delete tmpSI;
        }
        else
        {
            lStatus = NONE_VERIFIED;
            if (lSIStatus == NONE_PRESENT)
                lSIStatus = NONE_VERIFIED;
        }
    }
    if (lStatus == NONE_PRESENT)
        lSIStatus = NONE_PRESENT;

    // If there is an ostream send it summary MsgSignerInfo status information
    if (pos != NULL)
    {
        *pos << "Status of CounterSignature Verification"
             << " for this SignerInfo:\n";
        VDAStream::setIndent(VDAStream::getIndent()+1);
        char *ptr=GetCSVerifyDescription(lSIStatus);
        *pos << "CounterSignature results: "
             << ptr
             << "(" << lCSCount << ")\n";
        free(ptr);
        VDAStream::setIndent(VDAStream::getIndent()-2);
        pos->flush();
    }

    SME_FINISH
    SME_CATCH_SETUP
        if (pTmpSID)
            delete pTmpSID;
        if (tmpSI)
            delete tmpSI;
    SME_CATCH_FINISH


    return(lSIStatus);

} // END OF MEMBER FUNCTION VerifySignerInfoCSs

// ReportMsgData:
//
void CSM_MsgSignerInfo::ReportMsgData(std::ostream &os)
{
    SignerInfo *pSignerInfo = NULL;

    SME_SETUP("CSM_MsgSignerInfo::ReportMsgData(ostream &os)");

    os << "CSM_MsgSignerInfo::ReportMsgData(ostream &os)\n";

    if ((pSignerInfo = AccessSignerInfo()) != NULL)
    {
        VDAStream::setIndent(VDAStream::getIndent()+1);
        if (m_Verified)
			os << "### SIGNER INFO VERIFIED\n" ;
		else
			os << "### SIGNER INFO DID NOT VERIFY\n" ;

		// First, display Signer ID info.
        CSM_RecipientIdentifier *pTmpSID;
        pTmpSID = new CSM_RecipientIdentifier(pSignerInfo->sid);
        pTmpSID->ReportMsgData(os);
        if (pTmpSID)
            delete pTmpSID;

        // Next, list digest and signature algorithms.
        char *ptr2=AsnOid (AccessSignerInfo()->digestAlgorithm.algorithm).GetChar();
        os << "digestAlgorithm OID=" << ptr2  << "\n";
        free(ptr2);
        ptr2=AsnOid (AccessSignerInfo()->signatureAlgorithm.algorithm).GetChar();
        os << "signatureAlgorithm OID=" << ptr2  << "\n";
        VDAStream::setIndent(VDAStream::getIndent()-1);
        free(ptr2);
    }

    // Next, list signed attributes.
    if (m_pSignedAttrs)
    {       // list attributes and data.
        os << "Signed Attributes: #### ";
        m_pSignedAttrs->Report(os);
    }

    // Next, list unsigned attributes.
    if (m_pUnsignedAttrs)
    {       // list attributes and data.
        os << "Unsigned Attributes: #### ";
        m_pUnsignedAttrs->Report(os);
    }

    VDAStream::setIndent(VDAStream::getIndent()-1);
    os.flush();

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION ReportMsgData

// Verify:
//   INPUT: CSMIME *pCSMIME,
//          CSM_Buffer *pOriginalEncapContent,
//          EncapsulatedContentInfo *encapContentInfo,
//          CSM_CertificateChoiceLst *pCerts,
//          CSM_MsgAttributes *pSignedAttrs
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE (Zero/NonZero)
//
SM_RET_VAL CSM_MsgSignerInfo::Verify(
    CSMIME                   *pCSMIME,     // IN list of logons
    CSM_Buffer               *pOriginalEncapContent,// IN optional content
    EncapsulatedContentInfo  *encapContentInfo,// IN SNACC encapContentInfo
    CSM_CertificateChoiceLst *pCerts,      // IN Originator(s) certs+++
    CSM_MsgAttributes        *pSignedAttrs,// IN optional signed attributes
    CSM_Buffer            *pSignerPublicKeyIN,// IN optional, if pre-processed
    CSM_Alg               *palgSig)    // IN optional, if pre-processed
{
    SM_RET_VAL             lStatus=2;      // default INSTANCE not found
    CSM_CSInst            *pInst=NULL;
    CSM_Buffer            *dataToVerify=NULL;
    CSM_Alg                alg1(AccessSignerInfo()->digestAlgorithm);
    CSM_Alg                alg2(AccessSignerInfo()->signatureAlgorithm);
    AsnOid                 oidDigest, *pTmpOid;
    CSM_CertificateChoice *pCert;
    CSM_Buffer            *pSignerPublicKey=pSignerPublicKeyIN;

    SME_SETUP(
  "Verify(pCSMIME,pOriginalEncapContent,encapContentInfo,pCerts,pSignedAttrs)");

    if (palgSig == NULL)
       palgSig = &alg2;       //DO NOT DELETE.

    // match up the SignerInfo to a logon instance
    if ((pInst = CSM_SignBuf::GetFirstInstance(pCSMIME, &alg1, palgSig)) != NULL)
    {
           pInst->GetPreferredCSInstAlgs(&oidDigest, NULL, NULL, NULL);

            CSM_Buffer tmpSig(AccessSignerInfo()->signature.c_str(),
                AccessSignerInfo()->signature.Len());

            // IF the Signed attributes are present THEN
            //    * calculate the digest of the encapsulated content and
            //      compare it to the required message digest attribute
            //    * signature verification is performed on the DER ASN.1
            //      encoding of the Signed attributes
            // ELSE
            //    * signature verification is on the digest of the
            //      encapsulated content only
            //
            if (AccessSignerInfo()->signedAttrs)
            {
                CSM_Buffer encapContentDigest;
                CSM_Buffer encapContent;
                CSM_Buffer *pMessageDigest = NULL;

                // Make sure message digest attribute and encapsulated
                // content are present.  If not error out
                //
                // RWC; OPTIONAL
                if ((encapContentInfo != NULL) &&
                    (encapContentInfo->eContent != NULL))
                {
                    encapContent.Set(encapContentInfo->eContent->c_str(),
                        encapContentInfo->eContent->Len());
                }
                else if (pOriginalEncapContent != NULL)
                    // MUST BE PRESENT if not in SD msg
                {   // pOriginalEncapContent provided by caller
                    encapContent = *pOriginalEncapContent;
                }
                else
                {
                    SME_THROW(SM_MISSING_PARAM,
                        "encapsulated content not present in MSG OR param",
                        NULL);
                }

                // calculate digest of encapsulated content and compare it to
                // message disgest attribute
                //
                //RWC;TBD; 6/7/00
                if (m_pPreHashBuffer == NULL)    // Perform Hash calculation.
                {
                  pTmpOid = alg1.GetId();
                  pInst->SetPreferredCSInstAlgs(pTmpOid, NULL, NULL, NULL);
                  delete pTmpOid;
                  if ((lStatus = pInst->AccessTokenInterface()->
                      SMTI_DigestData(&encapContent, &encapContentDigest)) != SM_NO_ERROR)
                      SME_THROW(lStatus, "SMTI_Digest returned error.", NULL);
                }
                else
                {
                     encapContentDigest = *m_pPreHashBuffer;
                }

                // note: pMessageDigest must be delete'd to clean it up
                //
                pMessageDigest = pSignedAttrs->GetMessageDigest();
                if (pMessageDigest == NULL)
                {
                    SME_THROW(SM_MISSING_PARAM,
                              "message digest attribute not present", NULL);
                }

                if (pMessageDigest->Compare( encapContentDigest ) != 0)
                {
#ifndef TMP_IGNORE_FOR_TEST
                    delete pMessageDigest;
                    SME_THROW(
                        SM_DIGEST_MISMATCH,
                      "encapsulated content digest != message digest attribute",
                        NULL);
#else
                    cout << "encapsulated content digest !="
                         << " message digest attribute\n";
#endif
                }

                delete pMessageDigest;

                SME(ENCODE_BUF(AccessSignerInfo()->signedAttrs,
                    dataToVerify));
               /*RWC;#ifdef _DEBUG
               if (dataToVerify)
                    dataToVerify->ConvertMemoryToFile("./SignedAttrsReEncoded.bin");
               #endif*/
            }
            else
            {
                if ((encapContentInfo != NULL) &&
                    (encapContentInfo->eContent != NULL))
                {
                    dataToVerify =
                        new CSM_Buffer(encapContentInfo->eContent->c_str(),
                        encapContentInfo->eContent->Len());
                }
                else if (pOriginalEncapContent != NULL)
                    // MUST BE PRESENT if not in SD msg
                {   // pOriginalEncapContent provided by caller
                    dataToVerify = new CSM_Buffer(*pOriginalEncapContent);
                }
                else
                {
                    SME_THROW(SM_MISSING_PARAM,
                        "encapsulated content not present in MSG OR param",
                        NULL);
                }
                lStatus = 0;        // RESET to continue processing.
            }


            CSM_RecipientIdentifier RID(AccessSignerInfo()->sid);
            if (pCerts && pSignerPublicKey == NULL)
            {
               CSM_MsgCertCrls msgCerts(&*pCerts);
               if ((pCert = msgCerts.FindCert(RID)) != NULL)
               {
                   pSignerPublicKey = pCert->GetPublicKey();
               }
               if (pSignerPublicKey && pCert && palgSig &&
                   palgSig->HasNullParams())// extract from certificate if present
               {
                    msgCerts.UpdateParams(*palgSig, *pCert);
               }

                 const CML::ASN::Cert  cmlCert(*pCert->AccessSNACCCertificate());
                 if (cmlCert.exts.pKeyUsage) // may be null
                 {
                    if (!cmlCert.exts.pKeyUsage->GetBit(KeyUsage::digitalSignature) &&
                        !cmlCert.exts.pKeyUsage->GetBit(KeyUsage::nonRepudiation)) 
                    {
                        lStatus = 45;     //indicate special failure.
                        //SME_THROW(45, "User Certificate DOES NOT HAVE digitalSignature OR nonRepudiation keyUsage bit set!", NULL);
                    }
                 }  // END IF pCert.exts.pKeyUsage
               // delete memory from FindCert call
               if (pCert)
                   delete pCert;
            }     // END if pCerts && pSignerPublicKey == NULL

            // Verify the signature of this particular SignerInfo
            if (lStatus == 0 && pSignerPublicKey != NULL)
            {
               char *lpszError=NULL;
                SME_SETUP("Verify 1st Cut");
                SME(lStatus = pInst->AccessTokenInterface()->
                    SMTI_Verify(pSignerPublicKey, &alg1, palgSig, dataToVerify,
                    &tmpSig));
                SME_FINISH
                SME_CATCH_SETUP
                SME_CATCH_FINISH_C2(lpszError);
                if (lpszError)
                {
                   lStatus = 1;     //indicate failure for 2nd attempt.
                }    // END if lpszError, failed signature

                if (lStatus != 0 && pSignedAttrs) // TRY actual binary data before actually failing
                {
                   CSM_Buffer *pTmpEncodedAttrsFromMessage;
                       free(lpszError); //IGNORE.
                       lpszError = NULL;

                       pTmpEncodedAttrsFromMessage = pSignedAttrs->AccessEncodedAttrsFromMessage();
                       if (pTmpEncodedAttrsFromMessage)
                       {
                          char *ptr=(char *)pTmpEncodedAttrsFromMessage->Access();
                          if (ptr)
                             ptr[0] = 0x31;      //OVERRIDE ASN.1 tag with SEQUENCE.
                          SME(lStatus = pInst->AccessTokenInterface()->
                              SMTI_Verify(pSignerPublicKey, &alg1, palgSig, 
                              pTmpEncodedAttrsFromMessage, &tmpSig));
                          if (lStatus)
                          {  //RWC;6/5/02;SMTI should throw an exception
                             //  but this is a tmp patch for exception prob.
                             SME_THROW(lStatus, "BAD SMTI_Verify CALL!", NULL);
                          }
                       }    // END if pTmpEncodedAttrsFromMessage

                }       // END if status failed
                else if (lpszError)
                {
                   char pszTmpChar[4096];
                   if (strlen(lpszError) < 4096)
                      strcpy(pszTmpChar, lpszError);
                   else
                   {
                      memcpy(pszTmpChar, lpszError, 4095);
                      pszTmpChar[4095] = '\0';
                   }
                   free(lpszError); //IGNORE.
                   SME_THROW(22, pszTmpChar, NULL);
                }
            }           // END if pSignerPublicKey
            else
            {
                if (lStatus == 0)   // OTHERWISE ignore previous error(s)
                    SME_THROW(SM_MISSING_PARAM,
                          "MUST HAVE SignerPublicKey from certificate", NULL);
            }
            //Reset back to original HASH oid.
            pInst->SetPreferredCSInstAlgs(&oidDigest, NULL, NULL, NULL);   
            if (dataToVerify)
                delete dataToVerify;
            // RWC; TBD; Add logic to flag successfully verified SignerInfos

    }
#ifdef NODEF
    else
        cout << "CSM_DataToVerify::Verify:"
             << " no session instance found for SignerInfo.\n";
#endif

    if (pSignerPublicKey != NULL && pSignerPublicKey != pSignerPublicKeyIN)
        delete pSignerPublicKey; // ONLY delete if not input...

    SME_FINISH
    SME_CATCH_SETUP
    if (pSignerPublicKey != NULL && pSignerPublicKey != pSignerPublicKeyIN)
           delete pSignerPublicKey;
       if (dataToVerify)
           delete dataToVerify;
    SME_CATCH_FINISH

    return(lStatus);

} // END OF MEMBER FUNCTION Verify

// GetCSVerifyDescription:
//   INPUT: long lResults
//   OUTPUT: NONE
//   RETURN: char *ptr
// Based on the results passed in (enum return value from Verify process)
//   this function will return a pointer to the appropriate string description.
//
char *CSM_MsgSignerInfo::GetCSVerifyDescription(long lResults)
{
    char   *ptr=NULL;
    switch (lResults)
    {
        case ALL_SUCCEEDED:
            ptr = strdup("All Succeeded");
            break;
        case SOME_SUCCEEDED:
            ptr = strdup("Some Succeeded");
            break;
        case SOME_FAILED:
            ptr = strdup("Some Failed");
            break;
        case ALL_FAILED:
            ptr = strdup("All Failed");
            break;
        case NONE_PRESENT:
            ptr = strdup("None Present");
            break;
        case NONE_VERIFIED:
            ptr = strdup("None Verified");
            break;
        default:
            ptr = strdup("Unrecognized Status");
            break;
    }
    return(ptr);
} // END OF MEMBER FUNCTION GetCSVerifyDescription

// operator =:
// = (equal) operator definition
//
CSM_MsgSignerInfo &CSM_MsgSignerInfo::operator = (CSM_MsgSignerInfo &msgSI)
{
    SME_SETUP("CSM_MsgSignerInfo::operator =");

    if (msgSI.m_pSignedAttrs)
        m_pSignedAttrs = new CSM_MsgAttributes(*msgSI.m_pSignedAttrs);
    if (msgSI.m_pUnsignedAttrs)
        m_pUnsignedAttrs =
        new CSM_MsgAttributes(*msgSI.m_pUnsignedAttrs);
    m_pCerts = msgSI.GetCerts();
    m_pSignerInfo = new SignerInfo;
    *m_pSignerInfo = * msgSI.AccessSignerInfo();

    SME_FINISH_CATCH

    return(*this);
} // END OF MEMBER FUNCTION operator =

// END OF CSM_MsgSignerInfo FUNCTION DEFINITIONS

// BEGIN CSM_MsgSignerInfos FUNCTION DEFINITIONS

// VerifyMsgCSs:
//   INPUT: CSMIME *pCSMIME,
//          CSM_MsgCertCrls *pMsgCertCrls,
//          ostream *pos
//   OUTPUT: NONE
//   RETURN: SM_RET_VAL lSIStatus
// This function loops through the list of MsgSignerInfos in the current
// Message.  With each MsgSignerInfo it finds
// it calls the VerifySignerInfoCSs to verify any CounterSignatures in
// each MsgSignerInfo.  NOTE: if there is a valid ostream pointer passed
// in, it is filled with output for CounterSignature Verifications for
// the current list of MsgSignerInfos.  This overall status will be
// displayed as a character string representing one of the enum status
// from this class; All Succeeded, Some Succeeded, Some Failed, All Failed,
// None Present, None Verified
//
SM_RET_VAL CSM_MsgSignerInfos::VerifyMsgCSs(CSMIME *pCsmime,
                                            CSM_MsgCertCrls *pMsgCertCrls,
                                            std::ostream *pos)
{
    SM_RET_VAL lSIStatus = CSM_MsgSignerInfo::NONE_PRESENT;
    SM_RET_VAL lMsgStatus = CSM_MsgSignerInfo::NONE_VERIFIED;
    CSM_MsgSignerInfos::iterator itTmpSI;

    SME_SETUP("CSM_MsgSignerInfos::VerifyMsgCSs(CSMIME *pCsmime,CSM_MsgCertCrls *pMsgCertCrls,ostream *pos)");

    // If there is an ostream send it information about what follows
    if (pos != NULL)
    {
        VDAStream::setIndent(VDAStream::getIndent()+1);
        *pos << "Verifying all CounterSignatures for all SignerInfos . . .\n";
    }

    // If there are any SignerInfos in the current list
    if (this != NULL)
    {
        // Loop through each SignerInfo
        for(itTmpSI = begin(); 
            itTmpSI != end();
            ++itTmpSI)
        {
            // If there are Unsigned Attributes, attempt to verify
            // any CounterSignatures
            if (itTmpSI->m_pUnsignedAttrs)
            {
                // Call the appropriate funtion to Verify all
                // CounterSignatures in this SignerInfo
                if (pos != NULL)
                {
                    lSIStatus = itTmpSI->VerifySignerInfoCSs(pCsmime,
                                                           pMsgCertCrls, pos);
                }
                else
                {
                    lSIStatus = itTmpSI->VerifySignerInfoCSs(pCsmime,
                                                           pMsgCertCrls);
                }
                // Consolidate each SignerInfo CounterSignature verification
                // into a Message CounterSignature verification status
                switch (lMsgStatus)
                {
                    case CSM_MsgSignerInfo::ALL_SUCCEEDED:
                        switch (lSIStatus)
                        {
                            case CSM_MsgSignerInfo::SOME_SUCCEEDED:
                                lMsgStatus =
                                    CSM_MsgSignerInfo::SOME_SUCCEEDED;
                                break;
                            case CSM_MsgSignerInfo::ALL_FAILED:
                            case CSM_MsgSignerInfo::SOME_FAILED:
                                lMsgStatus = CSM_MsgSignerInfo::SOME_FAILED;
                                break;
                            case CSM_MsgSignerInfo::NONE_PRESENT:
                            case CSM_MsgSignerInfo::NONE_VERIFIED:
                                break;
                        }
                        break;
                    case CSM_MsgSignerInfo::SOME_SUCCEEDED:
                        switch (lSIStatus)
                        {
                            case CSM_MsgSignerInfo::ALL_FAILED:
                            case CSM_MsgSignerInfo::SOME_FAILED:
                                lMsgStatus = CSM_MsgSignerInfo::SOME_FAILED;
                                break;
                        }
                        break;
                    case CSM_MsgSignerInfo::ALL_FAILED:
                        switch (lSIStatus)
                        {
                            case CSM_MsgSignerInfo::ALL_SUCCEEDED:
                            case CSM_MsgSignerInfo::SOME_SUCCEEDED:
                            case CSM_MsgSignerInfo::SOME_FAILED:
                                lMsgStatus = CSM_MsgSignerInfo::SOME_FAILED;
                                break;
                        }
                        break;
                    case CSM_MsgSignerInfo::NONE_PRESENT:
                    case CSM_MsgSignerInfo::NONE_VERIFIED:
                        lMsgStatus = lSIStatus;
                        break;
                }
            }
        }
    }
    else
        lMsgStatus = CSM_MsgSignerInfo::NONE_PRESENT;

    // If there is an ostream send it summary message status information
    if (pos != NULL)
    {
        *pos << "Status of CounterSignature Verification"
             << " for all SignerInfos:\n";
        VDAStream::setIndent(VDAStream::getIndent()+1);
        if (begin() != end())
        {
            char *ptr=begin()->GetCSVerifyDescription(lMsgStatus);
            *pos << "All CounterSignature results: "
                 << ptr
                 << "\n";
            free(ptr);
        }       // END if any present.
        VDAStream::setIndent(VDAStream::getIndent()-2);
        pos->flush();
    }

    SME_FINISH_CATCH

    return(lMsgStatus);

} // END OF MEMBER FUNCTION VerifyMsgCSs

// ReportMsgData:
//
void CSM_MsgSignerInfos::ReportMsgData(std::ostream &os)
{
    CSM_MsgSignerInfos::iterator itTmpSI;
    long lCount;

    SME_SETUP("CSM_MsgSignerInfos::ReportMsgData(ostream &os)");

    os << "CSM_MsgSignerInfos::ReportMsgData(ostream &os)\n";

    VDAStream::setIndent(VDAStream::getIndent()+1);
    lCount = 0;
    if (this != NULL)
    {
        for (itTmpSI =  begin();
             itTmpSI != end(); 
             ++itTmpSI)
        {
            if (itTmpSI->IsVerified())
            {
                os << "\nNumber "
                    << ++lCount
                    << " signer info WAS VERIFIED.\n";
            }
            else
            {
                os << "Did not verify number "
                    <<  ++lCount << " signer info.\n";
                if (itTmpSI->m_lProcessingResults == 45)  // SPECIAL flag.
                  os << "**** User Certificate DOES NOT HAVE digitalSignature OR nonRepudiation keyUsage bit set!\n";
            }
            // Display this signer info
            VDAStream::setIndent(VDAStream::getIndent()+1);
            itTmpSI->ReportMsgData(os);
            VDAStream::setIndent(VDAStream::getIndent()-1);
        } // end for loop
    } // end if
    else
        os << "No SignerInfos were present or verified.\n";

    VDAStream::setIndent(VDAStream::getIndent()-1);
    os.flush();

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION ReportMsgData

// END OF CSM_MsgSignerInfos FUNCTION DEFINITIONS

_END_SFL_NAMESPACE

// EOF sm_MsgSignerInfo.cpp
