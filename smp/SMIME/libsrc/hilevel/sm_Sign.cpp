
//////////////////////////////////////////////////////////////////////////////
//  sm_Sign.cpp
//  These routines support the CSM_Sign class.
//
// DESTRUCTOR FOR CSM_MsgToSign
//     ~CSM_MsgToSign()
//
// MEMBER FUNCTIONS FOR CSM_MsgToSign
//     Sign(CSMIME *pCsmime)
//     GetEncodedContentInfo()
//     UpdateSignedDataSIs(CSMIME *pCsmime)
//     ProduceSignerInfo(CSM_CSInst *pCSInst,
//     PutSignerInfo(CSM_CSInst *pCSInst,
//     PutSignerInfoCommon(CSM_CSInst *pCSInst,
//     SignCalculateHash(CSM_CSInst *tmpCSInst,
//
// MEMBER FUNCTIONS FOR CSM_DataToSign
//     Sign(CSMIME *pCSMIME, CSM_MsgCertCrls *pMsgCertCrls,
//          CSM_Buffer *&pEncodedBlob)
//////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

// DESTRUCTOR FOR CSM_MsgToSign
//
CSM_MsgToSign::~CSM_MsgToSign()
{
    if (m_pMsgCertCrls)
        delete m_pMsgCertCrls;
    if (m_pUnsignedAttrs)
        delete m_pUnsignedAttrs;
    if (m_pSignedAttrs)
        delete m_pSignedAttrs;
}


// These methods are post-processing checks of SignedData/SignerInfo data
//  intended to be used after the creation of the SNACC 
//  SignedData; they will assign the appropriate CMSVersion numbers based
//  on data elements loaded into the SignedData (and SignerInfos).
void CSM_MsgToSign::SetSignerInfoVersion(SignerInfo &SnaccSI)
{
   long lVersion = 1;      // Default, unless conditions are met for Version 3
   // check subjectKey Identifier to set version number
   if (SnaccSI.sid.choiceId == SignerIdentifier::subjectKeyIdentifierCid)
         lVersion = 3;
   //RWC;TBD;CHECK to see if we need to check certain attributes presence to 
   //RWC;TBD;  set version.
   SnaccSI.version.Set(lVersion);
}
////////////////////////////////////////////////////////////////////////////////
// 
// Function Name:  SetVersion
//
// Description:
//
//    FROM RFC3852 CMS specification:
//
//       IF ((certificates is present) AND
//           (any certificates with a type of other are present )) OR
//           ((crls is present) AND
//            (any crls with a type of other are present))
//       THEN version MUST be 5
//       ELSE 
//         IF (certificates is present) AND
//             (any version 2 attribute certificates are present)
//         THEN version MUST be 4
//         ELSE
//           IF ((certificates is present ) AND
//               (any version 1 attribute certificates are present)) OR
//               (any SignerInfoStructures are version 3) OR
//               (encapsulatedContentInfo eContentType is other that id-data)
//           THEN version MUST be 3
//           ELSE version MUST be 1
//           
//               
// Inputs:    NONE
//
// Outputs    NONE
//
// Returns:   NONE
//
////////////////////////////////////////////////////////////////////////////////
void CSM_MsgToSign::SetVersion()
{
   long                                lVersion = 1;    
   CSM_RevocationInfoChoices::iterator itRevInfoChoices;

   // check if certs contain otherCertFormats
   if ( m_pMsgCertCrls && m_pMsgCertCrls->AccessOtherCertFormats() != NULL )
   {
      // there is a certificate of type other present
      lVersion = 5;
   }
   
   // check if there is a CRL list
   if (m_pMsgCertCrls && m_pMsgCertCrls->AccessCRLLst() != NULL) 
   {
      // check crl list for a type of other
      for (itRevInfoChoices =  m_pMsgCertCrls->AccessCRLLst()->begin();
           itRevInfoChoices != m_pMsgCertCrls->AccessCRLLst()->end();
           ++itRevInfoChoices)
      {
         if (itRevInfoChoices->AccessOtherOid()  != NULL)
         {
            // there is a crl of type other present
            lVersion = 5;
            break;
         }
      }
   }

   //  check if AttributeCertificates are present, only in Version 3
   if (lVersion < 5 && m_pMsgCertCrls && (m_pMsgCertCrls->AccessACs()) != NULL)
   {
      lVersion = 3; // SET to default as 3, ONLY set to 4 if AC v2 present.
       CSM_CertificateChoiceLst *pACertList=m_pMsgCertCrls->AccessACs();
       CSM_CertificateChoiceLst::iterator itAC;
       for (itAC =  pACertList->begin(); itAC != pACertList->end(); ++itAC)
       {
          if (itAC->AccessSNACCAttrCertificate() &&
              itAC->AccessSNACCAttrCertificate()->toBeSigned.version &&
              *itAC->AccessSNACCAttrCertificate()->toBeSigned.version == 1/*v2*/)
             lVersion = 4;   // NEW for RFC3369
       }       // END for each AC in list.
   }       // END if AttributeCertificate(s) present...
   
   // NEXT, check if the ContentType is other than id-data OID, Version 3
   if(lVersion < 4)
   {
      if (AccessEncapContentFromAsn1()->m_contentType != id_data &&  // CHECK both locations
          m_SnaccSignedData.encapContentInfo.eContentType  != id_data)
         lVersion = 3;
       
      // LASTLY, check the attribute list for any non-SMIME V2 Attributes
      //  (This check relies on the CSM_MsgToSign logic properly assigning the
      //  SignerInfo->version number based on attributes loaded and SID, etc.
      //  SEE SetSignerInfoVersion(...)).
      SignerInfos::iterator itSignerInfo;
      for (itSignerInfo = m_SnaccSignedData.signerInfos.begin();
           itSignerInfo != m_SnaccSignedData.signerInfos.end();
           ++itSignerInfo)
      {
         SetSignerInfoVersion(*itSignerInfo);

         if (itSignerInfo->version == 3)
            lVersion = 3;
      }
   }       // END IF lVersion < 4

   m_SnaccSignedData.version.Set(lVersion);

}   // end SetVersion()

// Sign:
//  This function expects the following member variables to be loaded before
//  execution:
//      pCSM_MsgCertCrls (OPTIONAL), mp_UnsignedAttrs (OPTIONAL),
//      mp_SignedAttrs (OPTIONAL), CSM_CommonData::m_contentValue
//      (for content to sign)
//  The result is stored in the member variable "CSM_CommonData::m_EncodedBlob".
//  It is expected that at least one session is valid for processing (as many
//  SignerInfos will be added to the resulting SignedData ASN.1 structure as
//  there are flagged sessions in the pCsmime structure).
SM_RET_VAL CSM_MsgToSign::Sign(CSMIME *pCsmime)
{
    SM_RET_VAL lStatus=SM_NO_ERROR;
 
    SME_SETUP("Sign");

    if (AccessEncapContentFromAsn1() != NULL)
    {
        if ((lStatus = UpdateSignedDataSIs(pCsmime)) == 0)
        {
            lStatus = CheckSignedDataAttrs(pCsmime);
        }
    }
    else
    {
        SME_THROW(22,
            "SignedData->contentInfo->content bad content type", NULL);
        // report_error, bad content type; OK to have SignedData OID and ASN.1
        //  encoded content, but "type" must be OCTET or ANY.

    }

    SME_FINISH
    SME_CATCH_SETUP
    SME_CATCH_FINISH

    //delete tmpOcts;

    return(lStatus);

} // END OF MEMBER FUNCTION Sign

// GetEncodedContentInfo:
//   INPUT: NONE
//   OUTPUT: NONE
//   RETURN: CSM_Buffer
//
CSM_Buffer *CSM_MsgToSign::GetEncodedContentInfo()
{
   const CSM_Content *pEncapContent;

    SME_SETUP("GetEncodedContentInfo()");

    AsnOid oidSignedData(id_signedData);
        if (!m_IncludeContent && 
            CSM_DataToSign::m_SnaccSignedData.encapContentInfo.eContent != NULL)
        {
            delete CSM_DataToSign::m_SnaccSignedData.encapContentInfo.eContent;
            CSM_DataToSign::m_SnaccSignedData.encapContentInfo.eContent = NULL;
        }
    else if(this->m_IncludeContent && 
       CSM_DataToSign::m_SnaccSignedData.encapContentInfo.eContent == NULL &&
       (pEncapContent = AccessEncapContentFromAsn1()) != NULL)     
    {
      CSM_DataToSign::m_SnaccSignedData.encapContentInfo.eContent =new AsnOcts;
      CSM_DataToSign::m_SnaccSignedData.encapContentInfo.eContent->Set(
         pEncapContent->m_content.Access(),
         pEncapContent->m_content.Length());
    }
    else if (CSM_DataToSign::m_SnaccSignedData.encapContentInfo.eContent == NULL) 
    {
  
       // this is a special case where only certificates are present
       CSM_DataToSign::m_SnaccSignedData.encapContentInfo.eContentType = id_data;
    }

    if (m_pEncodedBlob != NULL)
    {
        delete m_pEncodedBlob;
        m_pEncodedBlob = NULL;
    }
    CSM_DataToSign::Sign(NULL, m_pMsgCertCrls, m_pEncodedBlob);

    return (GetEncodedCI(&oidSignedData));

    SME_FINISH
    SME_CATCH_SETUP
    SME_CATCH_FINISH

}

// UpdateSignedDataSIs:
//   INPUT: CSMIME
//   OUTPUT: NONE
//   RETURN: SM_RET_VAL
//
SM_RET_VAL CSM_MsgToSign::UpdateSignedDataSIs(CSMIME *pCsmime)
{
    SM_RET_VAL lStatus=SM_NO_ERROR;
    CSM_CSInst   *tmpCSInst;
    CSM_CtilInstLst::iterator itTmpInst;
    bool bAtLeastOneSigner;
    SignedData *lpSignedData=&m_SnaccSignedData;
    SignerInfo *lpSNACCSignerInfo;

    SME_SETUP("UpdateSignedDataSIs");

    // assign eContent by calling AccessEncapContentFromAsn1() that will determine
    // which content object to return 
    //   - just return the right one compressed or uncompressed
    SME(lpSignedData->encapContentInfo.eContent =        
        new AsnOcts(AccessEncapContentFromAsn1()->m_content.Access(),
        AccessEncapContentFromAsn1()->m_content.Length()));  

    // ***** NOTE *****
    // assign content type - to be done AFTER the AccessEncapContentFromAsn1 to be
    // sure that the m_pContentFromAsn1 field has been filled!!!

    lpSignedData->encapContentInfo.eContentType = *GetContentTypeFromAsn1(); // *** CONTENT TYPE


    // FOR EACH SESSION MARKED TO SIGN THIS MESSAGE, LOAD A SignerInfo
    //  (BE SURE TO ONLY COMPUTE THE COMMON HASH CODE ONCE FOR ANY Signers
    //   THAT HAPPEN TO USE THE SAME HASH COMPUTATION.)
    bAtLeastOneSigner = false;

    // check for null pCSMIME and m_pCSInsts
    if (pCsmime != NULL && pCsmime->m_pCSInsts != NULL)
    {
       // FOR EACH SESSION MARKED TO SIGN THIS MESSAGE, LOAD A SignerInfo
       //  (BE SURE TO ONLY COMPUTE THE COMMON HASH CODE ONCE FOR ANY Signers
       //   THAT HAPPEN TO USE THE SAME HASH COMPUTATION.)

       for (itTmpInst =  pCsmime->m_pCSInsts->begin();
            itTmpInst != pCsmime->m_pCSInsts->end();
            ++itTmpInst)
       {
           lpSNACCSignerInfo=NULL;

           // IF SESSION REQUESTED TO SIGN THIS MESSAGE
           tmpCSInst = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
#ifdef _DEBUG

		   if (tmpCSInst &&tmpCSInst->AccessUserCertificate())
		   {
		      CML::ASN::DN *p2 = ((CSM_CertificateChoice *)tmpCSInst->AccessUserCertificate())->GetSubject();
			  const char *p3= *p2;
              #ifdef _WIN32
              p3;   // REMOVES MS Windows warning.
              #endif  // _WIN32 
              delete p2;


		   }
#endif
           if (tmpCSInst && tmpCSInst->IsApplicable() && 
               tmpCSInst->HasCertificates() && tmpCSInst->IsSigner())
                                // Check that this instance can sign, not an
                                //  empty CTIL for algs only.
           {
               // CREATE A SIGNED SignerInfo FOR THIS SESSION
               if (ProduceSignerInfo(tmpCSInst, lpSignedData,
                                   lpSNACCSignerInfo) == SM_NO_ERROR)
                  bAtLeastOneSigner = true;
           }// END if Applicable() && IsSigner()
       }    // END for each instance. 
    }       // END check on pCsmime

    if (!m_IncludeContent)     // ONLY use for Hash.
    {
        delete lpSignedData->encapContentInfo.eContent;
        lpSignedData->encapContentInfo.eContent = NULL;
    }

    if (m_pEncodedBlob)             // delete old definition.
        delete m_pEncodedBlob;
    m_pEncodedBlob = NULL;
    if (!bAtLeastOneSigner)     // ONLY necessary if there are no SIs.
      SetVersion();
    lStatus = CSM_DataToSign::Sign(pCsmime, m_pMsgCertCrls, m_pEncodedBlob);
    // The "m_pMsgCertCrls" variable contains optional certs
    //  and CRLs specified by the application, not those
    //  available from the logon instances.
    SME_FINISH
    SME_CATCH_SETUP
    SME_CATCH_FINISH

    return(lStatus);

} // END OF MEMBER FUNCTION UpdateSignedDataSIs

// ProduceSignerInfo:
//   INPUT: CSM_CSInst *pCSInst,
//          SignedData *pSignedData,
//          SignerInfo *&lpSNACCSignerInfo,
//          CSM_Buffer *pDigestInput
//   OUTPUT: SignedData
//   RETURN: SM_RET_VAL
SM_RET_VAL CSM_MsgToSign::ProduceSignerInfo(CSM_CSInst *pCSInst,
                                            SignedData *pSignedData,
                                            SignerInfo *&lpSNACCSignerInfo,
                                            CSM_Buffer *pDigestInput)
{
    SM_RET_VAL lStatus=SM_NO_ERROR;
    CSM_Buffer *pEncContent=NULL;
    CSM_Buffer *pDigest=NULL;
    CSM_Buffer *pSigBuf=NULL;
    CSM_HashDefLst *pHash=NULL;

    SME_SETUP("ProduceSignerInfo");

#ifdef CML_USED
    CM_SFLCertificate ACMLCert;
    //############################################
    // IF requested, then CML validate the signer certificate.
    if (this->m_bCMLUseToValidate && pCSInst->HasCertificates())
    {              // if cert present, use it directly
            lStatus = CMLValidateCert(ACMLCert, (CSM_CertificateChoice *)pCSInst->AccessUserCertificate()); 
            if (lStatus != 0 && m_bCMLFatalFail)
            {
               char pszBuf[1000];
               strncpy(pszBuf, m_pszCMLError, 999);
               SME_THROW(22, pszBuf, NULL);
            }        // IF lstatus on CML VerifySignature()
    }    // END if m_bCMLUseToValidate AND cert is present
#ifdef ACL_USED         // IN THIS CASE, MUST HAVE CML AS WELL!
       if (m_bACLUseToValidate && pCSInst->AccessUserCertificate() &&
           pCSInst->AccessUserCertificate()->AccessEncodedCert() &&
           m_pSignedAttrs != NULL)     // BE SURE we at least have SignedAttrs.
       {               // Validate Signer cert, if available from CML!
          if (m_pSignedAttrs)
           {
             CSM_SecLbl *pCSM_SecLbl = m_pSignedAttrs->GetSecurityLabel();
             if (pCSM_SecLbl)       // ONLY return if present.
             {
                 SNACC::ESSSecurityLabel *pSNACCSecLbl = 
                                          pCSM_SecLbl->GetSNACCSecLbl();
                 if (pSNACCSecLbl)
                 {
                    CSM_Buffer *pACLMsgLabel=NULL;
                    ENCODE_BUF(pSNACCSecLbl, pACLMsgLabel);
                                        // Create extracted security label
                    if (pACLMsgLabel)
                    {
                        m_ACLInterface.setACLMsgLabel(*pACLMsgLabel);
                        delete pACLMsgLabel;
                    }       // END if pACLMsgLabel
                    delete pSNACCSecLbl;
                 }      // END IF pSNACCSecLbl built.
                 delete pCSM_SecLbl;
             }  // END IF security label present in SignedAttrs
           }    // END if SignerInfo AND SignedAttrs present.
           lStatus = m_ACLInterface.Check_ACLOutgoingOrig(ACMLCert,
                  *pCSInst->AccessUserCertificate()->AccessEncodedCert());
           char ptrData[4096];
           if (lStatus != 0 && m_bACLFatalFail) 
           {
                if (m_ACLInterface.m_lpszError)
                {
                     int icout=strlen(m_ACLInterface.m_lpszError);
                     strcpy(ptrData, "ACL validation fails, FATAL flag set.");
                     if (strlen(m_ACLInterface.m_lpszError) > 4000)
                       icout = 4000;
                     strncat(ptrData, m_ACLInterface.m_lpszError, icout);
                 }
                 else
                     strcpy(ptrData, "ACL validation fails, FATAL flag set (no error string).");
                 SME_THROW(25, ptrData, NULL);
           }      // END ACL lstatus failure check.
       }        // END if m_bACLUseToValidate
#endif // ACL_USED
#endif // CML_USED

    if (pDigestInput)
    {
        pEncContent = new CSM_Buffer(*pDigestInput);
        // PROCESS THE CONTENT AND PRODUCE A HASH VALUE PASSING IN THE CONTENT
        SignCalculateHash(pCSInst, pSignedData, pHash,
                          pEncContent, pDigest);
    }
    else
    {
        // ENSURE THERE IS AN ENCAPSULATED CONTENT
        if (pSignedData->encapContentInfo.eContent)
        {
            // PROCESS THE CONTENT AND PRODUCE A HASH VALUE.
            SignCalculateHash(pCSInst, pSignedData, pHash,
                              pEncContent, pDigest);
        }
    }
    // check the signingTime for proper type and convert if necessary
    if (m_pSignedAttrs != NULL)
    {
        CSM_Buffer errorBuffer;
        char AChar[1024];
        lStatus = UpdateSigningTimeAttr(&errorBuffer);
        if (lStatus == -1)
        {
           strcpy(AChar, errorBuffer.Access());
           SME_THROW(22, AChar, NULL);
        }
    }

    // PUT THE SignerInfo INTO THE SignedData
    SME(lStatus = PutSignerInfo(pCSInst, pSignedData, lpSNACCSignerInfo));

    // RWC; TBD; DO SAME FOR UNSIGNED ATTRIBUTES

    // IF THERE ARE SIGNED ATTRIBUTES, THEY WILL BE HASHED TO PRODUCE THE
    // SIGNATURE VALUE. (IF THE CONTENT WAS HASHED THIS VALUE WILL BE IN THE
    // THE SignedAttrs.)
    if (m_pSignedAttrs != NULL)
    {
        // CLEAR ANY EARLIER USE OF pEncContent
        if (pEncContent)
        {
            delete pEncContent;
            pEncContent = NULL;
        }
        // LOAD THE SNACC SignedAttr INTO THIS SignerInfo
        lpSNACCSignerInfo->signedAttrs =
            m_pSignedAttrs->GetSNACCSignedAttributes();
        // ENCODE THE SignerInfo SignedAttrs IN pEncContent
        ENCODE_BUF(lpSNACCSignerInfo->signedAttrs, pEncContent);
        if (pDigest)
        {
            delete pDigest;
            pDigest = new CSM_Buffer;   // Make blank to trigger CTIL
                                        //  to regen hash, not use content.
        }
    }

    // NOW Sign THE pEncContent (EITHER THE CONTENT OR SIGNED ATTRIBUTES)
    if (pEncContent != NULL)    // CONTENT may be NULL
    {
        AlgorithmIdentifier *pSNACCDigestAlg = &lpSNACCSignerInfo->digestAlgorithm;
        AlgorithmIdentifier *pSNACCSigAlg = &lpSNACCSignerInfo->signatureAlgorithm;
        SME(CSM_SignBuf::SignBuf(pCSInst, pEncContent, pDigest,
            pSigBuf, pSNACCDigestAlg, pSNACCSigAlg ));
        // RWC;5/8/03; According to recent CMS specifications (ignore MSG spec).
        if (lpSNACCSignerInfo->signatureAlgorithm.algorithm == id_dsa)
            lpSNACCSignerInfo->signatureAlgorithm.algorithm = id_dsa_with_sha1;
        if (lpSNACCSignerInfo->signatureAlgorithm.algorithm == rsaEncryption)
            CSM_Alg::LoadNullParams(&lpSNACCSignerInfo->signatureAlgorithm);   
        if (lpSNACCSignerInfo->signatureAlgorithm.algorithm == rsa)
            lpSNACCSignerInfo->signatureAlgorithm.algorithm = rsaEncryption;
                           //OVERRIDE, SignBuf works on both certs & SignerInfo
        // LOAD THE digestAlgorithm INTO THIS SignedData
        AddDigestAlgorithm(pSignedData, lpSNACCSignerInfo->digestAlgorithm);
        // LOAD THE Signature VALUE INTO THIS SignedData
        lpSNACCSignerInfo->signature.Set(pSigBuf->Access(),
            pSigBuf->Length());
        // SET THE FLAG TO SHOW SIGNING WAS SUCCESSFUL
        lStatus = SM_NO_ERROR;
    }
    SetVersion();

    // CLEAN UP
    if (pEncContent != NULL)
        delete pEncContent;
    if (pDigest != NULL)
        delete pDigest;
    if (pSigBuf != NULL)
        delete pSigBuf;
    if (pHash)
        delete pHash;

    SME_FINISH
    SME_CATCH_SETUP
       if (pEncContent != NULL)
           delete pEncContent;
       if (pDigest != NULL)
           delete pDigest;
       if (pSigBuf != NULL)
           delete pSigBuf;
       if (pHash)
           delete pHash;
    SME_CATCH_FINISH

    return lStatus;

} // END OF MEMBER FUNCTION ProduceSignerInfo

// PutSignerInfo:
//   INPUT: CSM_CSInst *pCSInst,
//          SignedData *lpSignedData,
//          SignerInfo *&lpSNACCSignerInfo
//   OUTPUT:
//   RETURN: long
//
SM_RET_VAL CSM_MsgToSign::PutSignerInfo(CSM_CSInst *pCSInst,
                                        SignedData *lpSignedData,
                                        SignerInfo *&lpSNACCSignerInfo)
{
    SM_RET_VAL lRet=0;
    CSM_Attrib *pAttr=NULL;
    AsnOid *pOID=NULL;

    SME_SETUP("PutSignerInfo");

    lRet = PutSignerInfoCommon(pCSInst, lpSignedData, lpSNACCSignerInfo);

    // IF THERE ARE Signed ATTRIBUTES
    if (m_pSignedAttrs != NULL)
    {
        
        // SEARCH FOR THE Content Type ATTRIBUTE
        AsnOid SNACCTmpContentOid(id_contentType);
        CSM_AttribLst::iterator *pitAttrs = m_pSignedAttrs->FindAttrib(SNACCTmpContentOid);
        CSM_Attrib *pAttr = NULL;
        if (pitAttrs)
        {
            if (*pitAttrs == m_pSignedAttrs->m_pAttrs->end())      // IF IT IS NOT IN THE CURRENT LIST ADD IT
            {
                pOID = new AsnOid(lpSignedData->encapContentInfo.eContentType);
                pAttr = new CSM_Attrib(pOID);
                SME(m_pSignedAttrs->AddAttrib(*pAttr));
                delete pAttr;
                pAttr = NULL;
                delete pOID;
                // RWC; CANNOT DELETE, taken by m_pSignedAttrs: delete pAttr;
            }
        }
        else
            pAttr = &(*(*pitAttrs));
        delete pitAttrs;
        

       // check for a smimeCapabilities attribute and if there then 
       // add to it the id_alg_zlibCompression algorithm identifier
       // else add the smimeCapability attrib with id_alg_zlibCompression algo id
       if (this->GetCompressFlag() == true)
       {
          AsnOid SNACCTmpCapabilities(smimeCapabilities);
          CSM_AttribLst::iterator *pitSmimeCapabilityLst = m_pSignedAttrs->FindAttrib(SNACCTmpCapabilities);

          if (pitSmimeCapabilityLst == NULL || 
             *pitSmimeCapabilityLst == m_pSignedAttrs->m_pAttrs->end())      // IF IT IS NOT IN THE CURRENT LIST ADD IT
          {
             CSM_SmimeCapabilityLst *pTmpSmimeCapLst = NULL;

             if ((pTmpSmimeCapLst = new CSM_SmimeCapabilityLst) == NULL)
                SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);

             CSM_SmimeCapability *pTmpSmimeCap = NULL;
             if ((pTmpSmimeCap = &(*pTmpSmimeCapLst->append())) == NULL)
                SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);
      
             // set the oid
             pTmpSmimeCap->m_capabilityID = id_alg_zlibCompress;

             // parameters are OPTIONAL
             pTmpSmimeCap->m_pParameters = NULL;;

             // set smime capabilities
             pAttr = &(*m_pSignedAttrs->m_pAttrs->append());
             pAttr->SetSMIMECapabilities(pTmpSmimeCapLst);
             delete pTmpSmimeCapLst;
             pAttr = NULL;
            
          }
          else
          {
             // found an smimeCapabilities attr; 
             // first check to see if list has id_alg_zlibCompression
             // and if not just add to it
             // an smimeCapabilities attribute with the 
             // d_alg_zlibCompression algorithm identifier

             CSM_AttribLst::iterator itTmpAttrib;
             bool          foundOne = false;

             for (itTmpAttrib =  m_pSignedAttrs->m_pAttrs->begin();
                  itTmpAttrib != m_pSignedAttrs->m_pAttrs->end();
                  ++itTmpAttrib)
             {
                 if(itTmpAttrib->m_poid  && (*itTmpAttrib->m_poid == id_alg_zlibCompress))
                 {
                    foundOne = true;
                    break;
                 }
             }

             if (foundOne)
             {
                CSM_SmimeCapability *pTmpSmimeCap = NULL;
                if ((pTmpSmimeCap = (CSM_SmimeCapability *)&(*m_pSignedAttrs->m_pAttrs->append()))
                    == NULL)
                   SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);
      
                // set the oid
                pTmpSmimeCap->m_capabilityID = id_alg_zlibCompress;

                // parameters are OPTIONAL
                pTmpSmimeCap->m_pParameters = NULL;
             }
          }
       } // end if compressedData


        // else RWC;TBD; check that existing matches expected.
    }

    SME_FINISH
    SME_CATCH_SETUP
      if (pAttr)
         delete pAttr;
      if (pOID)
         delete pOID;
    SME_CATCH_FINISH

    return lRet;

} // END OF MEMBER FUNCTION PutSignerInfo

// PutSignerInfoCommon:
//   INPUT: CSM_CSInst *pCSInst,
//          SignedData *lpSignedData,
//          SignerInfo *&lpSNACCSignerInfo
//   OUTPUT:
//   RETURN: long
//
SM_RET_VAL CSM_MsgToSign::PutSignerInfoCommon(CSM_CSInst *pCSInst,
                                              SignedData *lpSignedData,
                                              SignerInfo *&lpSNACCSignerInfo)
{
    SM_RET_VAL lStatus=SM_NO_ERROR;
    //RWC9;CSM_IssuerAndSerialNumber *tmpIssSN;
    //RWC9;CSM_CertificateChoice *tmpCert=NULL;
    //RWC9;CSM_CertificateChoice *tmpCert2=NULL;
    //RWC9;CSM_CertificateChoiceLst *tmpCertList=NULL;
    //RWC9;CertificateList *tmpSNACCCertList=NULL;
    //RWC9;CSM_BufferLst *tmpCRLs=NULL;
    //RWC9;CSM_Buffer *pbufCRL=NULL;
    CSM_RecipientIdentifier *pRecipientId = NULL;
    CSM_Identifier *pTmpId;

    SME_SETUP("PutSignerInfoCommon");

    // check for Signer RecipientIdentifier for this instance
    if ((pTmpId = pCSInst->GetRid(m_bIssOrSki)) != NULL)
    {
        pRecipientId = new CSM_RecipientIdentifier(*pTmpId);
        delete pTmpId;
        pTmpId = NULL;
        // IF A SNACC SignerInfo IS PASSED IN THEN THIS MUST BE A
        // COUNTERSIGNATURE, WHICH WILL BE LOADED INTO AN EXISTING
        // SignerInfo, NOT ADDED TO THE CURRENT LIST; OTHERWISE
        // LOAD IT FROM THE SignedData WHICH WAS PASSED IN
        if (lpSNACCSignerInfo == NULL)
            lpSNACCSignerInfo = &(*lpSignedData->signerInfos.append());

        // get the sid
        SignerIdentifier *pSNACCSignerID = pRecipientId->GetSignerIdentifier(m_bIssOrSki);
        if (pSNACCSignerID)
        {
            lpSNACCSignerInfo->sid = *pSNACCSignerID;
            delete pSNACCSignerID;
        }       // END IF pSNACCSignerID

        // clean up pRecipientId from GetRid()
        if (pRecipientId)
        {
            delete pRecipientId;
            pRecipientId = NULL;    // FLAG already deleted.
        }      // END if pRecipientId


        // load unsigned attributes
        if (m_pUnsignedAttrs)
            lpSNACCSignerInfo->unsignedAttrs =
                m_pUnsignedAttrs->GetSNACCUnsignedAttributes();

        // AlgIds for preferred algorithms loaded
        // by call to CSM_SignBuf::SignBuf().
        // RWC; TBD; Hash and sign these results, save appropriately.
        // RWC; TBD;m_pSignedAttrs->encodeSNACC();
        //lpSNACCSignerInfo->SignedAttributes =
        //                 m_pSignedAttrs->GetSNACCSignedAttributes();
        // RWC; TBD; PERFORM SIGNING operation on
        // SignerInfo component, when finished.
        //lpSNACCSignerInfo->
        //    signature.Set((const char *)lpsm_SignerInfo->signature.str,
        //                  (size_t)lpsm_SignerInfo->signature.lgth);

        if (m_bIncludeOrigCertsFlag)
        {
            //  Then all Buf_fileLst items can be loaded as files or bufs.
            //  ALSO, handle for decodes where temporary file created if large.
            //RWC9;if ((tmpCRLs=pCSInst->AccessCRLs()) != NULL)
            if (pCSInst->HasCRLs())
            {
                pCSInst->LoadCRLs(lpSignedData->crls);
                /*RWC9;if ((lpSignedData->crls =
                    new RevocationInfoChoices) == NULL)
                {
                    SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
                }
                for (tmpCRLs->SetCurrToFirst(), pbufCRL=tmpCRLs->Curr(); pbufCRL;
                     pbufCRL = tmpCRLs->GoNext())
                {   // For each CRL in list, add to SNACC structure
                    SME(tmpSNACCCertList = lpSignedData->crls->Append());
                    SME(DECODE_BUF(tmpSNACCCertList, pbufCRL));
                    // Assign each CRL buffer to the SNACC structure.
                }*RWC9;*/
            }
            // Load certificates into SNACC structure.
            //RWC9;if ((tmpCertList=pCSInst->AccessCertificates()) != NULL)
            if (pCSInst->HasCertificates())
            {
                // Add each Login certificate (OR certificate path) into the
                //  general message bucket of certificates to be added to the
                //  SNACC ASN.1 SignedData->certificates component.  (Later
                //  processing will remove all duplicate certs).
                pCSInst->LoadCertificates(m_pMsgCertCrls);
                /*RWC9;if (m_pMsgCertCrls == NULL)
                    m_pMsgCertCrls = new CSM_MsgCertCrls;
                for(tmpCertList->SetCurrToFirst(), tmpCert=tmpCertList->Curr();
                    tmpCert; tmpCert = tmpCertList->GoNext())
                {
                    SME(tmpIssSN = new CSM_IssuerAndSerialNumber(*tmpCert->
                        AccessSNACCCertificate()));
                    tmpCert2 = m_pMsgCertCrls->FindCert(*tmpIssSN);
                    if (tmpCert2 == NULL)// ONLY if not already present
                    {
                        m_pMsgCertCrls->AddCert(tmpCert);
                    }
                    else
                        delete tmpCert2;
                    delete tmpIssSN;
                }*RWC9;*/
            }
        }
    }
    //RWC;else  THIS CONDITION is not a Fatal error; we have blank CTIL logins.
    
    SME_FINISH
    SME_CATCH_SETUP
        if (pRecipientId)
            delete pRecipientId;
    SME_CATCH_FINISH

    return(lStatus);

} // END OF MEMBER FUNCTION PutSignerInfoCommon

//
//
void CSM_MsgToSign::AddDigestAlgorithm(SignedData *lpSignedData,
                        DigestAlgorithmIdentifier &SNACCDigestAlgorithm)
{
    CSM_Alg digestAlgorithm(SNACCDigestAlgorithm);
    DigestAlgorithmIdentifiers::iterator itTmpSNACCDigest;
    // ONLY ADD if not already in the list.
    for (itTmpSNACCDigest = lpSignedData->digestAlgorithms.begin();
         itTmpSNACCDigest != lpSignedData->digestAlgorithms.end();
         ++itTmpSNACCDigest)
    {
        CSM_Alg TmpDigest(*itTmpSNACCDigest);
        if (TmpDigest == digestAlgorithm)
            break;
    }
    if (itTmpSNACCDigest == lpSignedData->digestAlgorithms.end())    // ONLY if not present.
        lpSignedData->digestAlgorithms.append(SNACCDigestAlgorithm);
}

// SignCalculateHash:
//   INPUT: CSM_CSInst *tmpCSInst,
//          SignedData *lpSignedData,
//          CSM_HashDefLst *&pHash,
//          CSM_Buffer *&pContent,
//          CSM_Buffer *&pHashResult
//      NOTE THAT pContent CAN CONTAIN A HASH VALUE FROM A SIGNER INFO TO
//      BE COUNTERSIGNED.
//   OUTPUT:
//   RETURN: long
//
SM_RET_VAL CSM_MsgToSign::SignCalculateHash(CSM_CSInst *tmpCSInst,
                                            SignedData *lpSignedData,
                                            CSM_HashDefLst *&pHash,
                                            CSM_Buffer *&pContent,
                                            CSM_Buffer *&pHashResult)
{
    SM_RET_VAL lStatus=SM_NO_ERROR;
    CSM_TokenInterface *tmpTokenIF;
    CSM_HashDefLst::iterator itTmpHash;
    CSM_HashDef *pHashItem = NULL;
    AsnOid *pTmpTokeinIFOID=NULL;

    SME_SETUP("CSM_MsgToSign::SignCalculateHash");

    if ((pHashResult = new CSM_Buffer) == NULL)
        SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);

    tmpTokenIF = tmpCSInst->AccessTokenInterface();
    pTmpTokeinIFOID = tmpTokenIF->GetPrefDigest();
    // THIS IS A CHECK TO SEE IF THERE IS A PRE-LOADED SIGNATURE
    // VALUE FROM A SIGNERINFO TO BE COUNTERSIGNED
    if (pContent == NULL)
    {
        if ((pContent = new CSM_Buffer) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
        SME(pContent->Set(lpSignedData->encapContentInfo.eContent->c_str(),
            lpSignedData->encapContentInfo.eContent->Len()));
    }

    if (pHash)
    {
        for(itTmpHash =  pHash->begin();
            itTmpHash != pHash->end() && *itTmpHash->m_pOID != *pTmpTokeinIFOID;
            ++itTmpHash); // Search for our Hash Algorithm.
                          //  Avoids recomputing!!!
    }

    if (pHash== NULL || itTmpHash == pHash->end())
    {               // NONE found, we need to compute Hash
        if ((lStatus = tmpTokenIF->
                           SMTI_DigestData(pContent, pHashResult)) != SM_NO_ERROR)
            SME_THROW(lStatus, "SMTI_DigestData returned error.", NULL);

        if (pHash == NULL)    // First one in list
            if ((pHash = new CSM_HashDefLst) == NULL)
                SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
        if ((pHashItem = &(*pHash->append())) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
        pHashItem->m_pHash = new CSM_Buffer(*pHashResult);
        pHashItem->m_pOID = new AsnOid(*pTmpTokeinIFOID);
    }
    else
    {                     // Already Hashed.
        *pHashResult = *itTmpHash->m_pHash;
    }

    // If there are SignedAttributes AND not a "messageDigest" attribute
    //    add one after computing the hash of the content before the call to
    //    "PutSignerInfo()".
    if (m_pSignedAttrs)
    {
        AsnOid SNACCmd(id_messageDigest);
        CSM_AttribLst::iterator *pitAttrs = m_pSignedAttrs->FindAttrib(SNACCmd);

        if (pitAttrs && m_pSignedAttrs->m_pAttrs)
        {
            if (*pitAttrs != m_pSignedAttrs->m_pAttrs->end())
            {           // Then load our newly generated Hash.
                m_pSignedAttrs->m_pAttrs->erase(*pitAttrs);
            }
            delete pitAttrs;
        }

        CSM_Attrib *pTmpAttrib = new CSM_Attrib(pHashResult);
        if (pTmpAttrib == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
        m_pSignedAttrs->AddAttrib(*pTmpAttrib);
        delete pTmpAttrib;

        // ENCODE the Signed attributes
    }

    if (pTmpTokeinIFOID)
        delete pTmpTokeinIFOID;
    SME_FINISH
    SME_CATCH_SETUP
       if (pContent)
       {
           delete pContent;
           pContent = NULL;
       }
       if (pTmpTokeinIFOID)
           delete pTmpTokeinIFOID;
    SME_CATCH_FINISH

    return lStatus;

} // END OF MEMBER FUNCTION SignCalculateHash

// Sign:
// This method assumes that the calling application has loaded all of the
//  appropriate SNACC information, including SignerInfo and signatures, into
//  the SNACC "SignedData m_SnaccSignedData" member variable for encoding.
//
SM_RET_VAL CSM_DataToSign::Sign(
    CSMIME *pCSMIME,               // IN,logged-on Instance list
    CSM_MsgCertCrls *pMsgCertCrls, // IN,Originator(s) certs (May be NULL).
    CSM_Buffer *&pEncodedBlob)      // OUT, Resulting SignedData/ContentInfo.
{
    SM_RET_VAL lStatus=SM_NO_ERROR;

    SME_SETUP("Sign");

    if (pMsgCertCrls)       // Then fill in the appropriate SNACC element.
    {
       if (m_SnaccSignedData.certificates)   // CHECK for original duplicates...
       {            // RWC;THIS LOGIC IS ONLY USEFUL FOR Additional Signatures.
                    //   Where certs have been pre-loaded.
          CertificateSet::iterator itTmpSNACCCert;
          CSM_CertificateChoice *pCertChoice = NULL;
          for (itTmpSNACCCert = m_SnaccSignedData.certificates->begin();
               itTmpSNACCCert != m_SnaccSignedData.certificates->end();
               ++itTmpSNACCCert)
          {
             pCertChoice = new CSM_CertificateChoice(*itTmpSNACCCert);
             pMsgCertCrls->AddCert(pCertChoice);   
             delete pCertChoice; // sib 9/27/02 AddCert no longer deletes pCertChoice
             pCertChoice = NULL;
          }       // END for each cert in original message (if present).
          delete m_SnaccSignedData.certificates;
          m_SnaccSignedData.certificates = NULL;
       }    // END if m_SnaccSignedData.certificates

       if (m_SnaccSignedData.crls)   // CHECK for original duplicates...
       {            // RWC;THIS LOGIC IS ONLY USEFUL FOR Additional Signatures.
                    //   Where certs have been pre-loaded.
          List<SNACC::AsnAny>::iterator itTmpSNACCCrl;
          CSM_RevocationInfoChoice *pCrlChoice = NULL;
          for (itTmpSNACCCrl = m_SnaccSignedData.crls->begin();
               itTmpSNACCCrl != m_SnaccSignedData.crls->end();
               ++itTmpSNACCCrl)
          {
             pCrlChoice = new CSM_RevocationInfoChoice(*itTmpSNACCCrl);
             pMsgCertCrls->AddCRL(pCrlChoice);   
             delete pCrlChoice; 
             pCrlChoice = NULL;
          }       // END for each cert in original message (if present).
          delete m_SnaccSignedData.crls;
          m_SnaccSignedData.crls = NULL;
       }    // END if m_SnaccSignedData.certificates
        pMsgCertCrls->PutSNACCCerts(m_SnaccSignedData.certificates);
        pMsgCertCrls->PutSNACCCRLLst(m_SnaccSignedData.crls);
    }
    SME(ENCODE_BUF(&m_SnaccSignedData, pEncodedBlob));

    SME_FINISH
    SME_CATCH_SETUP
    // local cleanup logic
    SME_CATCH_FINISH

#ifdef WIN32
    pCSMIME; // AVOIDS warning.
#endif
    return(lStatus);

} // END OF CSM_DataToSign MEMBER FUNCTION Sign


SM_RET_VAL CSM_MsgToSign::ExtractSignerInfo(
    AsnOid    &SignatureOid,   // to look for 
    SignerInfo *&pSNACCSignerInfo)
{
    SM_RET_VAL lStatus = ExtractSignerInfo(m_SnaccSignedData, SignatureOid, 
        pSNACCSignerInfo);
    return(lStatus);
}

//###############################################
//
SM_RET_VAL CSM_MsgToSign::ExtractSignerInfo(SignedData &SNACCSignedData,
                                    AsnOid    &SignatureOid,   // to look for
                                    SignerInfo *&pSNACCSignerInfo)
{
    SM_RET_VAL     lStatus=-1;

    SME_SETUP("ExtractSignerInfo");

    // Traverse the signer info lst until you find one with the
    // matching Oid
    pSNACCSignerInfo = NULL;        // INITIALLY.
    SignerInfos::iterator itTmpSignerInfo;
    for (itTmpSignerInfo = SNACCSignedData.signerInfos.begin();
         itTmpSignerInfo != SNACCSignedData.signerInfos.end();
         ++itTmpSignerInfo)
    {
       if (SignatureOid == itTmpSignerInfo->signatureAlgorithm.algorithm )
       {
            lStatus = 0;     // RETURN Success.
            pSNACCSignerInfo = &(*itTmpSignerInfo);
       }
    }

    SME_FINISH
    SME_CATCH_SETUP
    SME_CATCH_FINISH

    return lStatus;

} // END OF MEMBER FUNCTION ExtractSignerInfo

//###############################################
//
const SignerInfo *CSM_MsgToSign::GetFirstSIWithThisDigestOid(AsnOid &HashOid)
{
    SignerInfo *pSNACCSignerInfo=NULL;
    SM_RET_VAL lStatus=-1;

    SME_SETUP("GetFirstSIWithThisDigestOid");

    // Traverse the signer info lst until you find one with the
    // matching Oid
    pSNACCSignerInfo = NULL;        // INITIALLY.
    SignerInfos::iterator itSignerInfo;
    for (itSignerInfo = m_SnaccSignedData.signerInfos.begin();
         itSignerInfo != m_SnaccSignedData.signerInfos.end();
         ++itSignerInfo)
    {
       if (itSignerInfo->digestAlgorithm.algorithm &&
           itSignerInfo->digestAlgorithm.algorithm == HashOid &&
           itSignerInfo->signedAttrs)        // MUST have attributes present.
       {
            lStatus = 0;     // RETURN Success.
            pSNACCSignerInfo = &(*itSignerInfo);
       }
    }

    SME_FINISH
    SME_CATCH_SETUP
    SME_CATCH_FINISH

    return pSNACCSignerInfo;
} // END OF MEMBER FUNCTION GetFirstSIWithThisDigestOid


//  This method handles checking that the newly built message follows
//  CMS rules for attributes before successfully returning.  
//  In particular it checks that all SignerInfos contain the same security 
//  label AND if a security label is present that all SIs contain the same
//  security label.  
//  It also checks for the Mail List History attribute; if any SI contains
//  one, all must contain the same mail List History.  
//  This method also check the signingTime attribute and changes it if 
//  necessary from generalized to utc time.
//
//  This method returns 0 if all attributes are coherent, -1 if the signing
//  time was not correct, -2 if the ESSSecurityLabel was not consistent, 
//  -3 if the mail list history was not consistent.
//
SM_RET_VAL CSM_MsgSignedDataCommon::CheckSignedDataAttrs(CSMIME *pCsmime, 
   SNACC::SignerInfos &signerInfos, CSM_Buffer *pbufError)
{
    SM_RET_VAL lStatus=SM_NO_ERROR;
    CSM_MsgAttributes MAttrs;
    CSM_Buffer *pTmpBuf=NULL;
    bool bThisSIHadOneESS;
    bool bThisSIHadOneMLH;
    CSM_Buffer *pEncodedSnaccSecLabel=NULL;
    CSM_Buffer *pEncodedSnaccMailListHistory=NULL;  
    char errbuf[1000];
    char *pszErrorOid;


    SME_SETUP("CheckSignedDataAttrs");
    // For each SignerInfo, check the security label attribute.
    SignerInfos::iterator itSignerInfo;
    for (itSignerInfo = signerInfos.begin();
         itSignerInfo != signerInfos.end();
         ++itSignerInfo)
         {
             bThisSIHadOneESS = false;
             bThisSIHadOneMLH = false;
             if (itSignerInfo->signedAttrs)
             {          // ONLY check if there are any SignerInfos.
                SignedAttributes &SNACCSignedAttributes=
                    *itSignerInfo->signedAttrs;
                // We are going to look for this attribute directly, we wish
                //  the encoded result.
                // Loop through current SNACC Signed Attributes list
                SignedAttributes::iterator itTmpSNACCSignedAttr;
                for(itTmpSNACCSignedAttr = SNACCSignedAttributes.begin();
                    itTmpSNACCSignedAttr != SNACCSignedAttributes.end();
                    ++itTmpSNACCSignedAttr)
                {
                  if(itTmpSNACCSignedAttr->type == id_aa_securityLabel)
                  {
                       bThisSIHadOneESS = true;
                       AttributeSetOf::iterator itAttrSetOf = itTmpSNACCSignedAttr->values.begin();
                       pTmpBuf = NULL;
                       AsnAny *pSNACCAny = &(*itAttrSetOf);
                       SM_EXTRACT_ANYBUF(pTmpBuf, pSNACCAny);
                       if (pEncodedSnaccSecLabel)
                       {
                         if (*pTmpBuf != *pEncodedSnaccSecLabel)
                         {
                           lStatus = -2;
                           delete pTmpBuf;
                           delete pEncodedSnaccSecLabel;

                            if (pbufError != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                            {
                               // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                               // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                               pszErrorOid=itTmpSNACCSignedAttr->type.GetChar();
                               sprintf(errbuf, "%s ESSSecurityLabel is not identical in all SignerInfos.",
                                   pszErrorOid);
                               pbufError->Write(errbuf, strlen(errbuf));  // WRITE IT TO THE
                               pbufError->Write("\n", 1);
                               free(pszErrorOid);
                            }
                         }
                         delete pTmpBuf;    // ONLY delete if not assigned to 1st.
                         pTmpBuf = NULL;    // FLAG already deleted.
                       }      // ELSE if pEncodedSnaccSecLabel
                       else
                           pEncodedSnaccSecLabel = pTmpBuf;

                  } // end if id_aa_securityLabel

                  else if(itTmpSNACCSignedAttr->type == id_signingTime)
                  {
                        AttributeSetOf::iterator itAttrSetOf = itTmpSNACCSignedAttr->values.begin();
                        pTmpBuf = NULL;
                        ENCODE_BUF(itAttrSetOf, pTmpBuf);
                        CSM_Attrib signingAttr(itTmpSNACCSignedAttr->type, *pTmpBuf);
                        delete pTmpBuf;
                        // check the signingTime for proper type and convert if necessary
                        lStatus = signingAttr.CheckSigningTime();
                    
                        if (lStatus == -1) // error with time; cannot be converted
                        {
                           if (pbufError != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                           {
                                // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                                // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                                pszErrorOid=itTmpSNACCSignedAttr->type.GetChar();
                                sprintf(errbuf, "%s Signing Time Invalid Error!",
                                    pszErrorOid);
                                if (signingAttr.m_pSigningTime->m_lpszTime)
                                   sprintf(errbuf, "%s:  %s",errbuf, 
                                     signingAttr.m_pSigningTime->m_lpszTime);
                                pbufError->Write(errbuf, strlen(errbuf));  // WRITE IT TO THE
                                pbufError->Write("\n", 1);
                                free(pszErrorOid);
                           } // END if pbufError

                        }  // end invalid signingTime
                        else
                        {
                           lStatus = 0;
                        }
                  } // end if id_signingTime

                  else if(itTmpSNACCSignedAttr->type == id_aa_mlExpandHistory)
                  {
                        bThisSIHadOneMLH = true;
                        AttributeSetOf::iterator itAttrSetOf = itTmpSNACCSignedAttr->values.begin();
                        pTmpBuf = NULL;
                        ENCODE_BUF(itAttrSetOf, pTmpBuf);
                        CSM_Attrib mlHistAttr(itTmpSNACCSignedAttr->type, *pTmpBuf);
                       if (pEncodedSnaccMailListHistory)
                       {
                         if (*pTmpBuf != *pEncodedSnaccMailListHistory)
                         {
                           lStatus = -3;
                           delete pTmpBuf;
                           delete pEncodedSnaccMailListHistory;

                            if (pbufError != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                            {
                               // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                               // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                               pszErrorOid = itTmpSNACCSignedAttr->type.GetChar();
                               sprintf(errbuf, "%s MLExpansionHistory is not identical in all SignerInfos.",
                                   pszErrorOid);
                               pbufError->Write(errbuf, strlen(errbuf));  // WRITE IT TO THE
                               pbufError->Write("\n", 1);
                               free(pszErrorOid);
                            }
                         }       // END if not matching eariler MLH.
                         delete pTmpBuf;    // ONLY delete if not assigned to 1st.
                         pTmpBuf = NULL;    // FLAG already deleted.
                       }      // ELSE if pEncodedSnaccMailListHistory
                       else
                           pEncodedSnaccMailListHistory = pTmpBuf;
                  } // end if id_aa_mlExpandHistory
                } // END for loop of each attr


                //###################NOW, CHECK for attrs that were here, 
                //###################  but now missing in this SI!!!
                if (!bThisSIHadOneESS && pEncodedSnaccSecLabel)  
                {               // THIS can only happen if an earlier SI 
                                //  had a security label AND this one does
                                //  not!
                   lStatus = -2;
                   delete pEncodedSnaccSecLabel;
                   pEncodedSnaccSecLabel = NULL;
                   if (pbufError != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                   {
                        // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                        // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                        sprintf(errbuf, "%s ESSSecurityLabel is in 1 SI, but not in all SignerInfos.",
                            id_aa_securityLabel);
                        pbufError->Write(errbuf, strlen(errbuf));  // WRITE IT TO THE
                        pbufError->Write("\n", 1);
                   }   // END if pbufError
                }      // END if check on MISSING encodedSecLabel
                if (!bThisSIHadOneMLH && pEncodedSnaccMailListHistory)  
                {               // THIS can only happen if an earlier SI 
                                //  had a MailListHistory AND this one does
                                //  not!
                   lStatus = -3;
                   delete pEncodedSnaccMailListHistory;
                   pEncodedSnaccMailListHistory = NULL;
                   if (pbufError != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                   {
                        // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                        // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                        sprintf(errbuf, "%s MLExpansionHistory is in 1 SI, but not in all SignerInfos.",
                            id_aa_mlExpandHistory);
                        pbufError->Write(errbuf, strlen(errbuf));  // WRITE IT TO THE
                        pbufError->Write("\n", 1);
                   }   // END if pbufError
                }      // END if check on MISSING !bThisSIHadOneMLH

             }  // end if signedAttrs
         }  // end for loop

         if (pEncodedSnaccMailListHistory)
            delete pEncodedSnaccMailListHistory;
         if (pEncodedSnaccSecLabel)
            delete pEncodedSnaccSecLabel;
         if ((pbufError != NULL) && pbufError->Length() > 0)
           pbufError->Write("\0", 1);


#ifdef WIN32
    pCsmime; // AVOIDS warning.
#endif
    SME_FINISH
    SME_CATCH_SETUP
      if (pEncodedSnaccSecLabel && pTmpBuf && pEncodedSnaccSecLabel != pTmpBuf)
         delete pTmpBuf;
      if (pEncodedSnaccSecLabel)
         delete pEncodedSnaccSecLabel;
      if (pEncodedSnaccMailListHistory)
         delete pEncodedSnaccMailListHistory;
    SME_CATCH_FINISH
    return(lStatus);
}

SM_RET_VAL CSM_MsgToSign::UpdateSigningTimeAttr(CSM_Buffer *pbufError)
{
    SM_RET_VAL lStatus = SM_NO_ERROR;
    int valTime = 0;  // signing time ok

    SME_SETUP("UpdateSigningTimeAttr()");

    // IF THERE ARE Signed ATTRIBUTES
    if (m_pSignedAttrs != NULL)
    {
        // SEARCH FOR THE signingTime ATTRIBUTE
        AsnOid SNACCTmpSigningTime(id_signingTime);
        CSM_AttribLst::iterator *pitAttrs = m_pSignedAttrs->FindAttrib(SNACCTmpSigningTime);
        if (pitAttrs && *pitAttrs != m_pSignedAttrs->m_pAttrs->end())
        {           // if it is in the list
            // check if time is invalid
           if ((valTime = (*pitAttrs)->CheckSigningTime()) == 1)
           {   
              // if so then change gen time to utc time
              CSM_Time tmptime(&(*pitAttrs)->m_pSigningTime->m_lpszTime[2], 
                               strlen((*pitAttrs)->m_pSigningTime->m_lpszTime)-2, 
                               SigningTime::utcTimeCid);
              m_pSignedAttrs->m_pAttrs->erase(*pitAttrs);

              CSM_Attrib *pTmpAttrib = new CSM_Attrib(tmptime);
              if (pTmpAttrib == NULL)
                 SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
              m_pSignedAttrs->AddAttrib(*pTmpAttrib);

              if (pbufError != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
              {
                    // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                    // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                    char errbuf[1000];

                    char *errAttr=pTmpAttrib->m_poid->GetChar();
                    sprintf(errbuf, 
                        "%s Signing Time Invalid;  Changed Generalized Time to UTC Time!",
                        errAttr);
                    sprintf(errbuf, "%s:  %s",errbuf, tmptime.m_lpszTime);
                    pbufError->Write(errbuf, strlen(errbuf));  // WRITE IT TO THE
                    pbufError->Write("\n\0", 2);
                    free(errAttr);
              }
              delete pTmpAttrib;
           }
           else if (valTime == -1)
           {
               if (pbufError != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
               {
                    // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                    // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                    char errbuf[1000];

                    char *errAttr=(*pitAttrs)->m_poid->GetChar();
                    sprintf(errbuf, "%s Signing Time Error",
                        errAttr);
                    if ((*pitAttrs)->m_pSigningTime->m_lpszTime)
                       sprintf(errbuf, "%s:  %s",errbuf, 
                           (*pitAttrs)->m_pSigningTime->m_lpszTime);
                    pbufError->Write(errbuf, strlen(errbuf));  // WRITE IT TO THE
                    pbufError->Write("\n\0", 2);
                    free(errAttr);
               }
           }

        }
        if (pitAttrs)
          delete pitAttrs;
       
    }

    if (valTime != -1)
       lStatus = 0;
    else
       lStatus = valTime;

    SME_FINISH
    SME_CATCH_SETUP
    // local cleanup logic

    SME_CATCH_FINISH

    return(lStatus);

}



_END_SFL_NAMESPACE


// EOF sm_Sign.cpp
