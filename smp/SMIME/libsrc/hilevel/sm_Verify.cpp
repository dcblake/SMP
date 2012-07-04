
//////////////////////////////////////////////////////////////////////////////
//  sm_Verify.cpp
//  These routines support the CSM_MsgToVerify class
//
// CONSTRUCTORS FOR CSM_MsgToVerify
//     CSM_MsgToVerify()
//     CSM_MsgToVerify(CSM_ContentInfoMsg *pCIM)
//     CSM_MsgToVerify(CSM_Content *pMsgBlob)
//     CSM_MsgToVerify(CSM_Buffer *pBlob)
//     CSM_MsgToVerify(CSMIME *pCSMIME, CSM_Buffer *pBlob)
// DESTRUCTOR FOR CSM_MsgToVerify
//     ~CSM_MsgToVerify()
// MEMBER FUNCTIONS FOR CSM_MsgToVerify
//     Clear()
//     Verify(CSMIME *pCSMIME, CSM_Buffer &CSMBlob)
//     Verify(CSMIME *pCsmime)
//     PreProc(CSMIME *pCSMIME)
//     PreProc(CSMIME *pCSMIME, CSM_Buffer *pCSMBlob)
//     CSSIDCertCheck(CSM_RecipientIDLst *pSIDLst)
//     ReceiptRequested(void)
//     GetSignedReceipt(CSMIME *pCsmime,
//                      CSM_MsgAttributes *pSignedAttrs,
//                      CSM_MsgAttributes *pUnsignedAttrs)
//     ReportMsgData(ostream &os)
//     SetSICerts(CSMIME *pCsmime)
//     GetSignedReceipt(CSMIME *pCsmime,
//     ReceiptFromUs(CSMIME *m_pCsmime)
//
//  These routines support the CSM_DataToVerify class
// CONSTRUCTORS FOR CSM_MsgToVerify
// DESTRUCTOR FOR CSM_DataToVerify
//     ~CSM_DataToVerify()
// MEMBER FUNCTIONS FOR CSM_MsgToVerify
//     PreProc(CSM_Buffer *pEncodedBlob)
//     PreProc(CSMIME *pCSMIME, CSM_Buffer *pEncodedBlob)
//     PreProc(CSMIME *pCSMIME)
//     Verify(CSMIME *pCSMIME, CSM_Buffer *pOriginalEncapContent,
//            CSM_MsgCertCrls *pMsgCertCrls,
//            CSM_MsgSignerInfos *pMsgSignerInfos)
//     Verify(CSMIME *pCSMIME,
//            CSM_Buffer *pOriginalEncapContent,
//            CSM_MsgCertCrls *pMsgCertCrls,
//            CSM_MsgSignerInfos *pMsgSignerInfos)
//     Verify(CSMIME *pCSMIME,
//            SignerInfo *pSI,
//            CSM_CertificateChoiceLst *pCerts,
//            CSM_MsgAttributes *pSignedAttrs)
//     Verify(CSMIME *pCSMIME,
//            SignerInfo *pSI,
//            CSM_Buffer *pOriginalEncapContent,
//            CSM_CertificateChoiceLst *pCerts,
//            CSM_MsgAttributes *pSignedAttrs)
//////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "sm_api.h"
#include <time.h>
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

// BEGIN CSM_MsgToVerify FUNCTION DEFINITIONS

// DEFAULT CONSTRUCTOR
//
CSM_MsgToVerify::CSM_MsgToVerify()
{
    Clear();
} // END OF CONSTRUCTOR FOR CSM_MsgToVerify

// ALTERNATE CONSTRUCTOR WITH CSM_ContentInfoMsg
//
CSM_MsgToVerify::CSM_MsgToVerify(const CSM_ContentInfoMsg *pCIM)
{
    SME_SETUP("CSM_MsgToVerify::CSM_MsgToVerify(CSM_ContentInfoMsg)");
    Clear();
    if (pCIM)
    {
        SME(SetEncodedBlob( &((CSM_ContentInfoMsg *)pCIM)->AccessEncapContentFromAsn1()->m_content ));
        if (m_pEncodedBlob)
        {
            if (m_pSnaccSignedData)
                delete m_pSnaccSignedData;
            m_pSnaccSignedData = new SignedData;
            SME(DECODE_BUF(m_pSnaccSignedData, m_pEncodedBlob));
        }
    }
    SME_FINISH_CATCH
} // END OF CONSTRUCTOR FOR CSM_MsgToVerify

// ALTERNATE CONSTRUCTOR WITH CSM_Content
//
CSM_MsgToVerify::CSM_MsgToVerify(const CSM_Content *pMsgBlob)
{
    SME_SETUP("CSM_MsgToVerify::CSM_MsgToVerify(CSM_Content)");
    Clear();
    if (pMsgBlob)
        SME(SetEncodedBlob(&pMsgBlob->m_content));
    SME_FINISH_CATCH
} // END OF CONSTRUCTOR FOR CSM_MsgToVerify

// ALTERNATE CONSTRUCTOR WITH CSM_Buffer
//
CSM_MsgToVerify::CSM_MsgToVerify(const CSM_Buffer *pBlob)
{
    SME_SETUP("CSM_MsgToVerify::CSM_MsgToVerify(CSM_Buffer)");
    Clear();
    if (pBlob)
    {
        SME(SetEncodedBlob(pBlob));
        if (m_pEncodedBlob)
        {
            if (m_pSnaccSignedData)
                delete m_pSnaccSignedData;
            m_pSnaccSignedData = new SignedData;
            SME(DECODE_BUF(m_pSnaccSignedData, m_pEncodedBlob));
        }
    }
    SME_FINISH_CATCH
} // END OF CONSTRUCTOR FOR CSM_MsgToVerify

// ALTERNATE CONSTRUCTOR WITH CSMIME AND CSM_Buffer
//   the constructor below also pre-processes the content using the
//   CSMIME/CSInst classes so it can mark applicable instances for use
//
CSM_MsgToVerify::CSM_MsgToVerify(CSMIME *pCSMIME, const CSM_Buffer *pBlob,     
       bool bCMLUseToValidate, 
       bool bCMLFatalFail, 
       unsigned long lCmlSessionId, 
       unsigned long lSrlSessionId)
{
    SME_SETUP("CSM_MsgToVerify::CSM_MsgToVerify(CSMIME*, CSM_Buffer*)");
    Clear();

    m_bCMLUseToValidate = bCMLUseToValidate;
    m_bCMLFatalFail = bCMLFatalFail;
    m_lCmlSessionId = lCmlSessionId; 
    m_lSrlSessionId = lSrlSessionId;

    if (pBlob)
    {
        if (pCSMIME)
        {
            SME(PreProc(pCSMIME, pBlob));  
        }
        else
        {
           SME(PreProc(pBlob));
        }
    }
    SME_FINISH_CATCH
} // END OF CONSTRUCTOR FOR CSM_MsgToVerify

// DESTRUCTOR FOR CSM_MsgToVerify
//
CSM_MsgToVerify::~CSM_MsgToVerify()
{
    SME_SETUP("CSM_MsgToVerify::~CSM_MsgToVerify");
    if (m_pMsgCertCrls)
        delete m_pMsgCertCrls;
    if (m_pSignerInfos)
    {
        delete m_pSignerInfos;
    }

	if (m_pTimeStampCertificate)
		delete m_pTimeStampCertificate;

   if (m_pTimeStampSid)
      delete m_pTimeStampSid;

    SME_FINISH_CATCH
} // END OF DESTRUCTOR FOR CSM_MsgToVerify

//  Clear:
//
void CSM_MsgToVerify::Clear()
{
    m_pMsgCertCrls = NULL;
    m_pSignerInfos = NULL;
    m_pTimeStampCertificate = NULL;
    m_pTimeStampSid = NULL;

} // END OF MEMBER FUNCTION Clear

// Verify:
//   This verify does the preproc and then calls the other verify
//
SM_RET_VAL CSM_MsgToVerify::Verify(CSMIME *pCSMIME, CSM_Buffer &CSMBlob)
{
    SM_RET_VAL lRet = SM_NO_ERROR;

    SME_SETUP("CSM_MsgToVerify::Verify(CSMIME*, CSM_Buffer&)");

    SME(PreProc(pCSMIME, &CSMBlob));
    SME(lRet = Verify(pCSMIME));

    SME_FINISH_CATCH
    return(lRet);

} // END OF MEMBER FUNCTION Verify

// Verify:
//   This member function will verify the signature of the specified
//   SignerInfos of an ASN.1 encoded SignedData message
//
SM_RET_VAL CSM_MsgToVerify::Verify(CSMIME *pCsmime, bool bVerifyTST)
{
    SM_RET_VAL  lStatus=SM_NO_ERROR;
    CSM_Buffer *pBuf=NULL;

    SME_SETUP("CSM_MsgToVerify::Verify(pCsmime)");

    // Find cert path for each signer
    SetSICerts(pCsmime);

    if (AccessEncapContentFromAsn1() == NULL && this->m_pSignerInfos != NULL)
        SME_THROW(SM_MEMORY_ERROR,
            "Encapsulated content MUST BE PRESENT.", NULL);

    pBuf = (CSM_Buffer *)&AccessEncapContentFromAsn1()->m_content;
    if (m_pSnaccSignedData != NULL)     // IF PreProc() was called
    {
        if (pBuf)
            lStatus = CSM_DataToVerify::Verify(pCsmime, pBuf, m_pMsgCertCrls,
                m_pSignerInfos);
        else
            lStatus = CSM_DataToVerify::Verify(pCsmime, NULL, m_pMsgCertCrls,
                m_pSignerInfos);

        if  (m_pTimeStampCertificate == NULL && lStatus == 0 && 
             m_pSignerInfos && m_pSignerInfos->size())
        {
           if (m_pSignerInfos->begin()->m_pUnsignedAttrs != NULL)
               
           {
              SNACC::TimeStampToken *pTst = 
                 m_pSignerInfos->begin()->m_pUnsignedAttrs->GetTimeStampToken();  
                
              // if there is a timeStampToken then save the signers cert for use in 
              // verifying the tst later on
              if (pTst != NULL)
              {
                 CSM_ContentInfoMsg tscontentInfo(*pTst);
                 if (tscontentInfo.IsSignedData())
                 {
                    CSM_MsgToVerify timeStampVerify(pCsmime, 
                          &tscontentInfo.AccessEncapContentFromAsn1()->m_content,
                          NULL, NULL, NULL, NULL);

                    if (timeStampVerify.m_pSignerInfos->begin()->AccessCerts() && 
                         (timeStampVerify.m_pSignerInfos->begin()->AccessCerts()->begin() != 
                         timeStampVerify.m_pSignerInfos->begin()->AccessCerts()->end()) )
                    {
                 
                       m_pTimeStampCertificate = 
                            new CSM_CertificateChoice
                             (*timeStampVerify.m_pSignerInfos->begin()->AccessCerts()->begin());

                       m_pTimeStampSid = timeStampVerify.m_pSignerInfos->begin()->GetSignerIdentifier();
                       if (bVerifyTST == true)
                          // call method if we are verifying the Timestamp
                          lStatus = VerifyTimeStampToken(pCsmime, &std::cout);
                    } 
                 }                
#ifdef DEBUG
                 else
                    std::cout << "Error:  TST content doesn't contain a SignedData\n"; 
#endif
                 // clean up
                 delete pTst;

              } // end if pTst
           }
        } // end if m_pTimeStampCertificate
    }

    SME_FINISH
    SME_CATCH_SETUP
        // local cleanup logic
    SME_CATCH_FINISH

    return(lStatus);

} // END OF MEMBER FUNCTION Verify

// PreProc:
//   INPUT: CSMIME *pCSMIME
//   OUTPUT: NONE
//   RETURN: lStatus
//
SM_RET_VAL CSM_MsgToVerify::PreProc(CSMIME *pCSMIME)
{
    CSM_Buffer Buf;
    SM_RET_VAL lStatus;

    lStatus = CSM_DataToVerify::PreProc(pCSMIME);
    if (m_pSnaccSignedData->encapContentInfo.eContent != NULL)
    {
        Buf.Set(m_pSnaccSignedData->encapContentInfo.eContent->c_str(),
            m_pSnaccSignedData->encapContentInfo.eContent->Len());
        SetEncapContentFromAsn1(Buf, m_pSnaccSignedData->encapContentInfo.eContentType);
    }
    return(lStatus);

} // END OF MEMBER FUNCTION PreProc

// PreProc:
//   INPUT: CSMIME *pCSMIME
//          CSM_Buffer *pCSMBlob
//          CSM_RecipientIDLst *pCSSIDLst (Optional)
//   OUTPUT: NONE
//   RETURN: lStatus
//
SM_RET_VAL CSM_MsgToVerify::PreProc(CSMIME *pCSMIME, const CSM_Buffer *pCSMBlob,
                                    CSM_RecipientIDLst *pCSSIDLst)
{
    SM_RET_VAL         lStatus=SM_NO_ERROR;
    CSM_Buffer         Buf;

    SME_SETUP("CSM_MsgToVerify::PreProc");

    SME(lStatus = PreProc(pCSMBlob));

    SME(lStatus = CSM_DataToVerify::PreProc(pCSMIME));

    if (lStatus == SM_NO_ERROR)
    {
        // If there were CounterSignatures present, search for Certs
        // for each from the Message Certificate List
        if (pCSSIDLst && (pCSSIDLst->size() > 0))
            // Check the list of CounterSignature SIDs for those which
            // have certificates and remove them from the list so that
            // when this function returns pCSSIDLst Will contain only
            // the CounterSignature SIDs which have no certificates
            CSSIDCertCheck(pCSSIDLst);
    }

    SME_FINISH
    SME_CATCH_SETUP
        // local cleanup logic
    SME_CATCH_FINISH
    return(lStatus);

} // END OF MEMBER FUNCTION PreProc

// PreProc: Use in case when you don't have pCSMIME
//   INPUT: CSM_Buffer *pCSMBlob
//   OUTPUT: NONE
//   RETURN: lStatus
//
SM_RET_VAL CSM_MsgToVerify::PreProc(const CSM_Buffer *pCSMBlob)
{
    SM_RET_VAL         lStatus=SM_NO_ERROR;
    CSM_MsgSignerInfo *tmpSI;
    CSM_Buffer         Buf;

    SME_SETUP("CSM_MsgToVerify::PreProc");

    SME(SetEncodedBlob(pCSMBlob));
    SME(lStatus = CSM_DataToVerify::PreProc(pCSMBlob));

    if (lStatus == 0 && m_pSnaccSignedData)
    {

        // LOAD content data, if present
        if (m_pSnaccSignedData->encapContentInfo.eContent != NULL)
        {
            Buf.Set(m_pSnaccSignedData->encapContentInfo.eContent->c_str(),
                m_pSnaccSignedData->encapContentInfo.eContent->Len());
            SetEncapContentFromAsn1(Buf,m_pSnaccSignedData->encapContentInfo.eContentType);
        }

        if (m_pMsgCertCrls)
        {
            delete m_pMsgCertCrls;
            m_pMsgCertCrls = NULL; // Flag missing in case not present in SNACC
        }

        // LOAD certificates
        if (m_pSnaccSignedData->certificates)
        {
            SME(m_pMsgCertCrls =
                new CSM_MsgCertCrls(m_pSnaccSignedData->certificates));
#ifdef CML_USED
           if (m_bCMLUseToValidate)
           {               // LOAD each cert into the CML/SRL database.
              CSM_CertificateChoiceLst::iterator itCert;

              CSM_RevocationInfoChoices::iterator itRevInfoChoices;
              CM_Interface CMLInterface(m_lCmlSessionId, m_lSrlSessionId);
              if (m_pMsgCertCrls->AccessCertificates())
              {
                for (itCert =  m_pMsgCertCrls->AccessCertificates()->begin();
                     itCert != m_pMsgCertCrls->AccessCertificates()->end();
                     ++itCert)
                {
                   if (itCert->AccessEncodedCert())   // IGNORE ACs (for now).
                      CMLInterface.dbAddCert(*itCert->AccessEncodedCert());
                }    // END FOR each cert in list.    
              }      // END if AccessCertificates()

              if (m_pMsgCertCrls->AccessCRLLst())
              {
                for (itRevInfoChoices =  m_pMsgCertCrls->AccessCRLLst()->begin();
                     itRevInfoChoices != m_pMsgCertCrls->AccessCRLLst()->end();
                     ++itRevInfoChoices)
                {
                   if (itRevInfoChoices->IsCrlPresent())
                      CMLInterface.dbAddCRL(itRevInfoChoices->AccessEncodedRevInfo());
                }
              }      // END if AccessCRLs()
               //long CM_Interface::dbAddCert(CSM_Buffer &BufCert);
           }      // END if m_bCMLUseToValidate
#endif // CML_USED
        }       // END if certificates in SNACC SignedData.

        if (m_pSnaccSignedData->crls)
        {
            if (m_pMsgCertCrls)
            {
                m_pMsgCertCrls->SetSNACCCRLst(m_pSnaccSignedData->crls);
            }
            else
            {
                SME(m_pMsgCertCrls =
                    new CSM_MsgCertCrls(m_pSnaccSignedData->crls));
            }
        }

        //RWC;3/19/02; The following logic was enhanced to provide the original
        //RWC;  binary encoding of each SignerInfo::SignedAttrs for verification.
        //RWC;  It was discovered that our DER re-encoding sometimes caused 
        //RWC;  failures.  It is expected that the ALTERNATE decoding has the 
        //RWC;  decoded SignerInfos in the same order and count (same library).
        //RWC;  DUE TO SNACC ASN.1 DECODE issues, it was necessary to remove the
        //RWC;  OPTIONAL tag from the signedAttrs definition, therefore they
        //RWC;  MUST BE PRESENT before attempting to decode/extract the binary 
        //RWC;  element.
        // LOAD SignerInfos for application use.
        VDASignedData VDASD;
        //VDASignerInfo *pVDATmpSignerInfo=NULL;
        SignerInfos::iterator itSignerInfo = m_pSnaccSignedData->signerInfos.begin();
        VDASignerInfos::iterator itVDASignerInfo;
        if (itSignerInfo != m_pSnaccSignedData->signerInfos.end() && 
            itSignerInfo->signedAttrs != NULL)
        {               // ALSO, does not handle some with signedAttrs and 
                        //  some without; all must have in this case.
           DECODE_BUF(&VDASD, pCSMBlob);  // TMP decode.
           itVDASignerInfo = VDASD.signerInfos.begin();
        }            // END if VDASD.signerInfos.Count().
        for (itSignerInfo = m_pSnaccSignedData->signerInfos.begin();
             itSignerInfo != m_pSnaccSignedData->signerInfos.end();
             ++itSignerInfo)
        {
            if (m_pSignerInfos == NULL)
                if ((m_pSignerInfos = new CSM_MsgSignerInfos) == NULL)
                    SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            if ((tmpSI = &(*m_pSignerInfos->append())) == NULL)
                SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);
            tmpSI->SetSignerInfo(*itSignerInfo);

           //RWC;3/19/02; LASTLY get the actual binary SignedAttrs encoding 
           //RWC;         from the message.
            //RWC;2/04; NOT SURE IF "iterator" is initialized to "end()", may have to check additional boolean.
           if (itVDASignerInfo != VDASD.signerInfos.end() && tmpSI->m_pSignedAttrs)
           {
              CSM_Buffer *pSAEncodedBuffer=NULL;
              // by ASN.1 definition this cannot be an ANY DEFINED BY, 
              //  always buffer.
              SM_EXTRACT_ANYBUF(pSAEncodedBuffer, &itVDASignerInfo->signedAttrs);
              if (pSAEncodedBuffer)
              {
                  tmpSI->m_pSignedAttrs->SetEncodedAttrsFromMessage(pSAEncodedBuffer);
                  delete pSAEncodedBuffer;
              }   // END if pSAEncodedBuffer
              ++itVDASignerInfo;
           }      // END if everything is non-NULL for binary SignedAttrs load.
        }

        // Should now determine if any of the certificates in
        // the SignedData message belong to this SignerInfo component
        // and load into the "m_pSignerInfos" class
        SetSICerts(NULL);

    }       // END if (lStatus == 0 && m_pSnaccSignedData)

    SME_FINISH
    SME_CATCH_SETUP
        // local cleanup logic
    SME_CATCH_FINISH
    return(lStatus);

} // END OF MEMBER FUNCTION PreProc

// CSSIDCertCheck:
//   INPUT: CSM_RecipientIDLst *pSIDLst
//   OUTPUT: NONE
//   RETURN: NONE
//     This function is a destructive check for Certificates for
//     CounterSignature SIDs.  When a Cert is found that SID is
//     removed from the list.  Once the entire list is examined what
//     remains are those CounterSignature SIDs which have no Cert
//
void CSM_MsgToVerify::CSSIDCertCheck(CSM_RecipientIDLst *pSIDLst)
{
    CSM_CertificateChoice *pCert=NULL;
    CSM_RecipientIDLst::iterator itTmpSID;

    SME_SETUP("CSM_MsgToVerify::CSSIDCertCheck(CSM_RecipientIDLst *pSIDLst)");

    // Initialize pTmpSID to the first Signer ID in the list
    itTmpSID =  pSIDLst->begin();
    while (itTmpSID != pSIDLst->end())
    for (;
         itTmpSID != pSIDLst->end();
         ++itTmpSID)
    {   // Loop until there are no more Signer IDs in the list
        // If there is a Cert for this SID, remove it from the list and
        // check again (Curr becomes the next one on the list)
        if ((pCert = m_pMsgCertCrls->FindCert(*itTmpSID)) != NULL)
        {
            pSIDLst->erase(itTmpSID);
            itTmpSID =  pSIDLst->begin();
            delete pCert;
        }
    }

    SME_FINISH
    SME_CATCH_SETUP
        // local cleanup logic
    SME_CATCH_FINISH

} // END OF MEMBER FUNCTION CSSIDCertCheck

// ReceiptRequested:
//   INPUT: NONE
//   RETURN: TRUE/FALSE
//
bool CSM_MsgToVerify::ReceiptRequested(void)
{
    if (m_Receipt.m_pSnaccReceipt != NULL)
        return(true);
    else
        return(false);
} // END OF MEMBER FUNCTION ReceiptRequested

// SetSICerts:
//   Determines if any of the certificates in the message belongs to this
//   SignerInfo component and loads it into the "m_pSignerInfos" class
//
void CSM_MsgToVerify::SetSICerts(CSMIME *pCsmime)
{
    CSM_MsgSignerInfoLst::iterator itTmpSI;

    SME_SETUP("CSM_MsgToVerify::SetSICerts");

    if (m_pSignerInfos != NULL)
    {
        // FOR each SignerInfo, return 1st that we can verify
        for (itTmpSI =  m_pSignerInfos->begin(); 
             itTmpSI != m_pSignerInfos->end();
             ++itTmpSI)
        {
            itTmpSI->LoadSICertPath(this->m_pMsgCertCrls);
        }// end for every signer info
    }

    SME_FINISH_CATCH
#ifdef WIN32
    pCsmime;   // AVOIDS warning.
#endif
} // END OF MEMBER FUNCTION SetSICerts

// ReceiptFromUs:
//   INPUT: CSMIME *pCsmime
//   RETURN: sendReceipt (TRUE/FALSE)
//
bool CSM_MsgToVerify::ReceiptFromUs(CSMIME *m_pCsmime)
{
    CSM_GeneralNames   *pTmpGNs       = NULL;
    CSM_GeneralNames   *pTmpCsmGNs    = NULL;
    CSM_ReceiptRequest *pTmpRR        = NULL;
    CSM_MsgSignerInfoLst::iterator itTmpSI;
    MLExpansionHistory::reverse_iterator itrTmpSNACCMl;
    MLExpansionHistory *tmpSNACCMlExpHist = NULL;
    long                fromCount     = 0;
    bool                sendReceipt   = false;
    MLReceiptPolicySeqOf::iterator itMSRecPolicy;

    SME_SETUP("CSM_MsgToVerify::ReceiptFromUs(CSMIME *)");

    //  loop through all signer infos trying to get the receiptRequest
    for (itTmpSI =  m_pSignerInfos->begin();
         pTmpRR == NULL && itTmpSI != m_pSignerInfos->end();
         ++itTmpSI)
    {
        // get 1st receiptRequest (all receipt requests in each signer
        // info are the same according to the specs
        // Be sure to delete the receipt request list
        pTmpRR = itTmpSI->m_pSignedAttrs->GetReceiptRequest();
        if (pTmpRR)
           break;
    }

    //  if there is a receiptRequest then
    //    access the receiptsFrom list
    if (pTmpRR != NULL)
    {
        // point to the ReceiptsFrom list of general names
        pTmpGNs = pTmpRR->AccessReceiptsFrom();
    }

    if (itTmpSI != m_pSignerInfos->end())
    {
        // get the mlExpansionHistory
        tmpSNACCMlExpHist = itTmpSI->m_pSignedAttrs->GetMailList();
    }

    if (tmpSNACCMlExpHist)
    {
        itrTmpSNACCMl = tmpSNACCMlExpHist->rbegin();
    }

    // Do we have an mlExpansionHistory and a receipt policy
    if (tmpSNACCMlExpHist && 
        itrTmpSNACCMl != tmpSNACCMlExpHist->rend() &&
        itrTmpSNACCMl->mlReceiptPolicy)
    {
#ifdef NODEF
        cout << "  mlExpandHistory and receiptPolicy present!\n";
#endif

        // determine case of mlReceiptPolicy value
        switch (itrTmpSNACCMl->mlReceiptPolicy->choiceId)
        {
            case MLReceiptPolicy::noneCid:
                // mail list supersedes originator's request and
                // receipts must not be returned
                break;
            case MLReceiptPolicy::insteadOfCid:

#ifdef NODEF
                cout << "      mlReceiptPolicy=insteadOfCid\n";
#endif
                // do not send if firstTierOnly according to ess spec
                // If an mlExpansionHistory is present, then recipient
                // is not a first tier recipient and a receipt MUST NOT
                // be sent
                if ((pTmpGNs == NULL) &&
                    (pTmpRR->AccessfirstTierRecipients()->firstTierRecipients ==
					*pTmpRR->AccessfirstTierRecipients()))
                {
                    break;
                }

                // reset applicable instances
                m_pCsmime->ClearFlag(SM_INST_APPLICABLE);

                // set curr mail list data
                // loop through every general name list
                for (itMSRecPolicy = itrTmpSNACCMl->mlReceiptPolicy->insteadOf->begin();
                     itMSRecPolicy != itrTmpSNACCMl->mlReceiptPolicy->insteadOf->end();
                     ++itMSRecPolicy)
                {
                    // Generate a CSM_GeneralNames list
                    pTmpCsmGNs = new CSM_GeneralNames(*itMSRecPolicy);

                    // use the mlPolicy list to set applicable instance
                    fromCount += CSM_SignBuf::SetApplicableInstances(m_pCsmime,
                        NULL, NULL, pTmpCsmGNs, true);
                    delete pTmpCsmGNs;
                }

                if (fromCount > 0)
                    sendReceipt = true;

                break;
            case MLReceiptPolicy::inAdditionToCid:
#ifdef NODEF
                cout << "      mlReceiptPolicy=inAdditionTo\n";
#endif
                // call to set applicable instance according to
                // the receiptsFrom list sendReceipt represents
                // number of receiptsFrom
                if (pTmpGNs)
                {
                    // reset applicable
                    m_pCsmime->ClearFlag(SM_INST_APPLICABLE);

                    fromCount = CSM_SignBuf::SetApplicableInstances(m_pCsmime,
                        NULL, NULL, pTmpGNs, true);
                }
                else if (pTmpRR->AccessfirstTierRecipients()->firstTierRecipients ==
					*pTmpRR->AccessfirstTierRecipients())
                {
#ifdef NODEF
                    cout << "CSM_MsgToVerify::ReceiptFromUs:"
                         << " receiptRequest firstTierRecipients= "
                         << *pTmpRR->AccessfirstTierRecipients()
                         << "\n";
#endif
                    sendReceipt = true;

                    // applicable instances are expected
                    // to be set from the verify process
                    // so there's no need to set them here

                }
                else if (pTmpRR->AccessfirstTierRecipients()->allReceipts ==
					*pTmpRR->AccessfirstTierRecipients())// use all
                {
#ifdef NODEF
                    cout << "CSM_MsgToVerify::ReceiptFromUs:"
                         << " receiptRequest allReceipts= "
                         << *pTmpRR->AccessfirstTierRecipients()
                         << "\n";
#endif

                    sendReceipt = true;

                    // set all applicable instance
                    m_pCsmime->UseAll();
                }

                // set curr mail list data
                itMSRecPolicy = itrTmpSNACCMl->mlReceiptPolicy->inAdditionTo->begin();

                // Get the csm general names list
                pTmpCsmGNs = new CSM_GeneralNames(*itMSRecPolicy);

                // SetApplicableInstances call
                if (pTmpCsmGNs)
                {
                    // use the mlPolicy list in addition to
                    fromCount += CSM_SignBuf::SetApplicableInstances(m_pCsmime,
                        NULL, NULL, pTmpCsmGNs, true);
                    delete pTmpCsmGNs;
                }

                if (fromCount > 0)
                    sendReceipt = true;

                break;
            default:
                break;
        } // end of switch
    }
    else        //  else no expansion history or an
    {           //  expansion history and no receipt policy
        // if there is a general names list use it
        if (pTmpGNs)
        {
            // reset applicable instances
            m_pCsmime->ClearFlag(SM_INST_APPLICABLE);

            // call to set applicable instance according to the receiptsFrom
            // list sendReceipt set to true if receiptsFrom count is at least 1
            fromCount = CSM_SignBuf::SetApplicableInstances(m_pCsmime,
                NULL, NULL, pTmpGNs, true);

            // set sendReceipt
            if (fromCount > 0)
                sendReceipt = true;
        }
        else if ((pTmpRR) && (pTmpRR->AccessfirstTierRecipients()->allReceipts ==
			*pTmpRR->AccessfirstTierRecipients()))  // use all
        {
#ifdef NODEF
            cout << "CSM_MsgToVerify::ReceiptFromUs:"
                 << " receiptRequest allReceipts = "
                 << *pTmpRR->AccessfirstTierRecipients()
                 << "\n";
#endif

            sendReceipt = true;

            // applicable instances are expected
            // to be set from the verify process
            // so there's no need to set them here
            CSM_SignBuf::ClearEncryptApplicableInstances(m_pCsmime);
        }
        else if ((pTmpRR) && (pTmpRR->AccessfirstTierRecipients()->firstTierRecipients ==
			*pTmpRR->AccessfirstTierRecipients())) // use first tier
        {
#ifdef NODEF
            cout << "CSM_MsgToVerify::ReceiptFromUs:"
                 << " receiptRequest firstTierRecipients = "
                 << *pTmpRR->AccessfirstTierRecipients()
                 << "\n";
#endif

            sendReceipt = true;

            // applicable instances are expected
            // to be set from the verify process
            // so there's no need to set them here
            CSM_SignBuf::ClearEncryptApplicableInstances(m_pCsmime);
        }

    } // end else no expansion history

    // clean up memory from GetReceiptRequest() call
    if (pTmpRR != NULL)
        delete pTmpRR;

    // clean up memory from GetMailList() call
    if (tmpSNACCMlExpHist)
        delete tmpSNACCMlExpHist;

    SME_FINISH_CATCH

    return(sendReceipt);

} // END OF MEMBER FUNCTION ReceiptFromUs

// GetSignedReceipt:
//   INPUT: CSMIME *pCsmime
//          CSM_MsgAttributes *pSignedAttrs
//          CSM_MsgAttributes *pUnsignedAttrs
//   RETURN: pbufReceipt
//
CSM_Buffer *CSM_MsgToVerify::GetSignedReceipt(CSMIME *pCsmime,
                                              CSM_MsgAttributes *pSignedAttrs,
                                              CSM_MsgAttributes *pUnsignedAttrs)
{
    CSM_MsgToSign     *pSignedReceiptMsg = NULL;
    CSM_Buffer        *pEncapContent = NULL;
    AsnOid            idCtReceipt(id_ct_receipt);
    CSM_MsgAttributes *pCopyOfpSignedAttrs = NULL;
    CSM_Buffer        *pbufReceipt = NULL;

    SME_SETUP("CSM_MsgToVerify::GetSignedReceipt");

    if (m_Receipt.m_pSnaccReceipt == NULL)
    {
        SME_THROW(SM_MISSING_PARAM, "Receipt not present", NULL);
    }
    if (pSignedAttrs)
        pCopyOfpSignedAttrs = new CSM_MsgAttributes(*pSignedAttrs);

    // Encode Receipt into buffer
    //
    ENCODE_BUF(m_Receipt.m_pSnaccReceipt, pEncapContent);

    if (pEncapContent == NULL)
    {
        SME_THROW(SM_MEMORY_ERROR,
            "Error encoding Receipt encapsulated content.", NULL);
    }

    pSignedReceiptMsg = new CSM_MsgToSign();

    pSignedReceiptMsg->SetIncludeOrigCertsFlag(true);

    // Set the encapsulated content
    //
    pSignedReceiptMsg->SetEncapContentClear(*pEncapContent, idCtReceipt);
    delete pEncapContent;
    pEncapContent = NULL;

    // load attributes
    //
    pSignedReceiptMsg->m_pUnsignedAttrs = pUnsignedAttrs;
    pSignedReceiptMsg->m_pSignedAttrs = m_Receipt.m_pMust;
    if (pCopyOfpSignedAttrs)
        pSignedReceiptMsg->m_pSignedAttrs->m_pAttrs->
         insert(pSignedReceiptMsg->m_pSignedAttrs->m_pAttrs->end(),
                pCopyOfpSignedAttrs->m_pAttrs->begin(),
                pCopyOfpSignedAttrs->m_pAttrs->end());

    // Add contentType Signed attribute.  This assumes the app. doesn't
    // gives us a contentType attribute in pSignedAttrs
    //
    if (pSignedReceiptMsg->m_pSignedAttrs)
    {
        CSM_Attrib *pcontentTypeAttr=
             &(*pSignedReceiptMsg->m_pSignedAttrs->m_pAttrs->append());
        pcontentTypeAttr->SetContentType(&idCtReceipt);
    }    // END if m_pSignedAttrs

    // RWC;3/3/00; Added SigningTime logic to add to SignedAttrs
       CSM_AttribLst::iterator *pitAttrs = 
           pSignedReceiptMsg->m_pSignedAttrs->FindAttrib(AsnOid(id_signingTime));
        long ltime;
        struct tm *today;
        char tmpbuf[200];
        CSM_Attrib *pAttr;
        if (pitAttrs != NULL)
        {
            if ((*pitAttrs) != pSignedReceiptMsg->m_pSignedAttrs->m_pAttrs->end())
            {        // Then load our new SigningTime.
                pSignedReceiptMsg->m_pSignedAttrs->m_pAttrs->erase((*pitAttrs));
            }
            delete pitAttrs;
        }
            char strFormat[30];    // Def and code to avoid SCCS replacement
            strcpy(strFormat,"%Y");
            strcat(strFormat,"%m");
            strcat(strFormat,"%d");
            strcat(strFormat,"%H");
            strcat(strFormat,"%M00Z");
        time( &ltime );
        today = gmtime( &ltime );
        strftime( tmpbuf, 128, strFormat, today );
        CSM_Time tmptime(tmpbuf, strlen(tmpbuf),SigningTime::generalizedTimeCid);
        pAttr = &(*pSignedReceiptMsg->m_pSignedAttrs->m_pAttrs->append());
        pAttr->SetSigningTime(tmptime);

    SME( pSignedReceiptMsg->Sign(pCsmime) );

    pbufReceipt = pSignedReceiptMsg->GetEncodedContentInfo( );

    SME_FINISH
    SME_CATCH_SETUP

    if (pSignedReceiptMsg)
    {
        pSignedReceiptMsg->m_pUnsignedAttrs = NULL;
        pSignedReceiptMsg->m_pSignedAttrs = NULL;
        delete pSignedReceiptMsg;
    }
    SME_CATCH_FINISH

    // local cleanup logic
    if (pSignedReceiptMsg)
    {
        pSignedReceiptMsg->m_pUnsignedAttrs = NULL;
        pSignedReceiptMsg->m_pSignedAttrs = NULL;
        delete pSignedReceiptMsg;
    }

    return(pbufReceipt);

} // END OF MEMBER FUNCTION GetSignedReceipt

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  VerifyTimeStampToken
//
// Description:  This function verifies the TimeStampToken data
//
// Input:   CSMIME *pCsmime, 
//          SNACC::TimeStampToken &snaccTSTTimeStampToken &snaccTST
//          std::ostream* pOstrm
//
// Output:   NONE
//
// Returns:  status whether the TimeStampToken verified okay or not
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
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_MsgToVerify::VerifyTimeStampToken(CSMIME *pCsmime, 
                                                    std::ostream *pOstrm)                                                
{
   SM_RET_VAL        lretStatus = 0;
   SignerInfos::iterator itTmpSI;
   ContentInfo       *pContentInfo;
 
   // assume User verified original SignedData

   SME_SETUP("CSM_MsgToVerify::VerifyTimeStampToken");

   for (itTmpSI = m_pSnaccSignedData->signerInfos.begin();
        itTmpSI != m_pSnaccSignedData->signerInfos.end();
        ++itTmpSI)
   {
       if (itTmpSI->unsignedAttrs)
       {
           CSM_MsgAttributes tmpMsgAttribs(*itTmpSI->unsignedAttrs);
           pContentInfo = tmpMsgAttribs.GetTimeStampToken();
           if (pContentInfo)
           {
             CSM_ContentInfoMsg tmpCI(*pContentInfo);

             if (!tmpCI.IsSignedData())
             {
                SME_THROW(22, "TimeStampToken is not SignedData", NULL);
             }

             lretStatus = CSM_MsgSignerInfo::VerifyTimeStampToken(*itTmpSI, pCsmime,
                 *pContentInfo, m_pTimeStampCertificate, pOstrm, 
				 m_bCMLFatalFail, m_bCMLUseToValidate, m_lCmlSessionId, m_lSrlSessionId);
   
             delete pContentInfo;

           }        // END IF pContentInfo
       }            // END IF unsignedAttrs
   }                // END FOR each SignerInfo

  
   SME_FINISH
   SME_CATCH_SETUP
   // local cleanup logic
   SME_CATCH_FINISH

   return lretStatus;
}               // END CSM_MsgToVerify::VerifyTimeStampToken(...)

// ReportMsgData:
//   INPUT: ostream &os
//
void CSM_MsgToVerify::ReportMsgData(std::ostream &os)
{
    SME_SETUP("CSM_MsgToVerify::ReportMsgData(ostream &os)");

    os << "CSM_MsgToVerify::ReportMsgData(ostream &os)\n";

    // report on CSM_Common
    ReportCommonData(os);

    // report CSM_MsgCertCrls

    // report CSM_MsgSignerInfos data
    m_pSignerInfos->ReportMsgData(os);

    os.flush();

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION ReportMsgData

// END OF CSM_MsgToVerify FUNCTION DEFINITIONS

// BEGIN CSM_DataToVerify FUNCTION DEFINITIONS

// ************************************************************
// THE FOLLOWING DEFINITIONS SUPPORT THE CSM_DataToVerify CLASS
// ************************************************************

// DESTRUCTOR FOR CSM_DataToVerify
//
CSM_DataToVerify::~CSM_DataToVerify()
{
    SME_SETUP("CSM_DataToVerify::~CSM_DataToVerify");
    if (m_pSnaccSignedData)
        delete m_pSnaccSignedData;
    if (m_pACLLocalCert)
        delete m_pACLLocalCert;

    SME_FINISH_CATCH
} // END OF DESTRUCTOR FOR CSM_DataToVerify

// PreProc:
//   INPUT:  CSM_Buffer - Resulting SignedData/ContentInfo
//
SM_RET_VAL CSM_DataToVerify::PreProc(const CSM_Buffer *pEncodedBlob)
{
    long status=0;
    VDASignedDataReceiptOnly *pB=NULL;
    SME_SETUP("PreProc");
    if (pEncodedBlob)
    {
        if (m_pSnaccSignedData)
            delete m_pSnaccSignedData;
        m_pSnaccSignedData = new SignedData;
        SME(DECODE_BUF_NOFAIL(m_pSnaccSignedData, pEncodedBlob, status));
#ifndef RWC_TEST_ANY_ENCAPCONTENT
        if (status != 0)
        {
            CSM_Buffer *pBuf=NULL;
            pB = new VDASignedDataReceiptOnly;
            SME(DECODE_BUF(pB, pEncodedBlob));
            m_pSnaccSignedData->certificates = pB->certificates;
            pB->certificates = NULL;    // Take memory.
            m_pSnaccSignedData->crls = pB->crls;
            pB->crls = NULL;    // Take memory.
            m_pSnaccSignedData->signerInfos = pB->signerInfos;
            m_pSnaccSignedData->digestAlgorithms = pB->digestAlgorithms;
            m_pSnaccSignedData->version = pB->version;
            m_pSnaccSignedData->encapContentInfo.eContentType = 
                pB->encapContentInfo.eContentType;
            SM_EXTRACT_ANYBUF(pBuf, pB->encapContentInfo.eContent)
            if (pBuf)
            {
                m_pSnaccSignedData->encapContentInfo.eContent = new AsnOcts;
                m_pSnaccSignedData->encapContentInfo.eContent->
                    Set(&pBuf->Access()[3], pBuf->Length()-3);
                    //RWC;10/13/00; ATTEMPT to skip Receipt tag/length...
                delete pBuf;
            }
            delete pB;
        }
#endif     //RWC_TEST_ANY_ENCAPCONTENT
    }
    SME_FINISH
    SME_CATCH_SETUP
       if (pB)
          delete pB;
       if (m_pSnaccSignedData)
       {
           delete m_pSnaccSignedData;
           m_pSnaccSignedData = NULL;
       }
    SME_CATCH_FINISH
    return(0);
} // END OF MEMBER FUNCTION PreProc

// PreProc:
//   INPUT:  CSMIME pCSMIME,
//           CSM_Buffer *pEncodedBlob - Resulting SignedData/ContentInfo
//   RETURN: integer
//
SM_RET_VAL CSM_DataToVerify::PreProc(CSMIME *pCSMIME, const CSM_Buffer *pEncodedBlob)
{
    PreProc(pEncodedBlob);
    return(PreProc(pCSMIME));
} // END OF MEMBER FUNCTION PreProc

// PreProc:
//   INPUT:  CSMIME pCSMIME
//   RETURN: integer
//
SM_RET_VAL CSM_DataToVerify::PreProc(CSMIME *pCSMIME)
{
    SignerInfos::iterator itTmpSI;
    CSM_Alg     *palg1;
    CSM_Alg     *palg2;

    if (m_pSnaccSignedData != NULL)
    {
        pCSMIME->ClearFlag(SM_INST_APPLICABLE);   // RWC; CLEAR before SI check
        for (itTmpSI = m_pSnaccSignedData->signerInfos.begin();
             itTmpSI != m_pSnaccSignedData->signerInfos.end();
             ++itTmpSI)
        {           // for each SignerInfo
            palg1 = new CSM_Alg(itTmpSI->digestAlgorithm);
            palg2 = new CSM_Alg(itTmpSI->signatureAlgorithm);
            CSM_SignBuf::SetApplicableInstances(pCSMIME, palg1, palg2);
            delete palg1;
            delete palg2;
        }
    }
    return(0);
} // END OF MEMBER FUNCTION PreProc

// Verify:
//   INPUT:  CSMIME pCSMIME
//           CSM_MsgCertCrls *pMsgCertCrls
//           CSM_MsgSignerInfos *pMsgSignerInfos
//   RETURN: lStatus
//
SM_RET_VAL CSM_DataToVerify::Verify(
    CSMIME             *pCSMIME,         // IN, logged-on Instance list
    CSM_MsgCertCrls    *pMsgCertCrls,    // IN, Originator(s) certs+++
    CSM_MsgSignerInfos *pMsgSignerInfos) // IN, Support class for SNACC SIs
{
    SM_RET_VAL lStatus = SM_NO_ERROR;

    lStatus = CSM_DataToVerify::Verify(pCSMIME, NULL, pMsgCertCrls,
                                       pMsgSignerInfos);

    return(lStatus);
} // END OF MEMBER FUNCTION Verify

// Verify:
//   INPUT:  CSMIME pCSMIME
//           CSM_Buffer *pOriginalEncapContent
//           CSM_MsgCertCrls *pMsgCertCrls
//           CSM_MsgSignerInfos *pMsgSignerInfos
//   RETURN: lStatus
//
SM_RET_VAL CSM_DataToVerify::Verify(
    CSMIME          *pCSMIME,              // IN, logged-on Instance list
    CSM_Buffer      *pOriginalEncapContent,// IN, optional content if not in SD
    CSM_MsgCertCrls *pMsgCertCrls,         // IN, Originator(s) certs+++
    CSM_MsgSignerInfos *pMsgSignerInfos)   // IN, Support class for SNACC SIs
{
    SM_RET_VAL         lStatus = SM_NO_ERROR;
    SignerInfo        *psnacc_tmpSI = NULL;
    CSM_MsgSignerInfos::iterator itTmpSI;
    CSM_MsgAttributes *pTmpSignedAttrs = NULL;

    SME_SETUP("CSM_DataToVerify::Verify(CSM_MsgSignerInfos)");

    if (m_pSnaccSignedData)
    {
        // Loop through all SignerInfos and call "Verify()"
        //
        if (pMsgSignerInfos)
        for (itTmpSI =  pMsgSignerInfos->begin();
             itTmpSI != pMsgSignerInfos->end() && lStatus == SM_NO_ERROR;
             ++itTmpSI)
        {
            if (itTmpSI->AccessCerts())
            {
                SME(psnacc_tmpSI = itTmpSI->AccessSignerInfo());

                pTmpSignedAttrs = itTmpSI->m_pSignedAttrs;

                SME(lStatus = Verify(pCSMIME, psnacc_tmpSI,
                    pOriginalEncapContent,
                    itTmpSI->AccessCerts(), pTmpSignedAttrs));

                // this lStatus check is probably redundent
                // do not SME_THROW on signature verification failure
                if (lStatus == 0)
                {
                    itTmpSI->SetVerified(true);
                    m_lProcessingResults |= msgSignatureVerified;
                   if (m_Receipt.m_ProcessReceipt)
                    {
                        m_Receipt.ProcessRecReq(&(*itTmpSI));
                        // This method may return
                        //  a non-zero lStatus
                        //  indicating that a
                        //  receiptRequest
                        //  SignedAttr was not
                        //  present.  This is not
                        //  an error
                    }
                }       // IF lStatus == 0
                else
                    itTmpSI->m_lProcessingResults = lStatus;  // KEEP track of error code.
            }

            // reinitialize lStatus to original state
            lStatus = 0;
        }

        // If a receipt was requested initialize the receipt
        //
        if (m_Receipt.m_pSIRecReq != NULL)
        {
            m_Receipt.InitReceipt(pCSMIME, m_pSnaccSignedData,
                                  pOriginalEncapContent);
            m_lProcessingResults |= receiptProduced;
        }
    }

    lStatus = -1;  // INDICATE failure, EVEN IF NO SignerInfo(s) present...
    if (pMsgSignerInfos)
    {
       for (itTmpSI =  pMsgSignerInfos->begin();
            itTmpSI != pMsgSignerInfos->end() && lStatus != SM_NO_ERROR;
            ++itTmpSI)  // CHECK each to see if at 
                        //  least 1 succeeded!
        {
            if (itTmpSI->IsVerified())
                lStatus = SM_NO_ERROR;  // INDICATE overall success
        }       // END FOR
    }           // IF pMsgSignerInfos
    else
        lStatus = -2;  // INDICATE failure, EVEN IF NO SignerInfo(s) present.
                       //  FLAG  -2 to indicate no SignerInfo(s) present...
    SME_FINISH_CATCH
#ifdef WIN32
    pMsgCertCrls; // AVOIDS warning.
#endif

    return(lStatus);

} // END OF MEMBER FUNCTION Verify

// Verify:
//   INPUT: CSMIME *pCSMIME,
//          SignerInfo *pSI,
//          CSM_CertificateChoiceLst *pCerts,
//          CSM_MsgAttributes *pSignedAttrs
//   This method verifies the specified logon instance, if a matching
//   SignerInfo is located
//
SM_RET_VAL CSM_DataToVerify::Verify(
    CSMIME                   *pCSMIME,     // IN list of logons
    SignerInfo               *pSI,         // IN specific SignerInfo to process
    CSM_CertificateChoiceLst *pCerts,      // IN Originator(s) certs+++
    CSM_MsgAttributes        *pSignedAttrs)// IN optional signed attributes
{
    SM_RET_VAL lStatus=2;         // default return INSTANCE not found

    SME_SETUP("Verify(pCSMIME,pSI,pCerts,pSignedAttrs)");

    lStatus = Verify(pCSMIME, pSI, NULL, pCerts, pSignedAttrs);

    SME_FINISH_CATCH

    return(lStatus);

} // END OF MEMBER FUNCTION Verify

// Verify:
//   INPUT: CSMIME *pCSMIME,
//          SignerInfo *pSI,
//          CSM_Buffer *pOriginalEncapContent,
//          CSM_CertificateChoiceLst *pCerts,
//          CSM_MsgAttributes *pSignedAttrs
//
SM_RET_VAL CSM_DataToVerify::Verify(
    CSMIME                   *pCSMIME,     // IN list of logons
    SignerInfo               *pSI,         // IN specific SignerInfo to process
    CSM_Buffer      *pOriginalEncapContent,// IN optional content if not in SD
    CSM_CertificateChoiceLst *pCerts,      // IN Originator(s) certs+++
    CSM_MsgAttributes        *pSignedAttrs)// IN optional signed attributes
{
    SM_RET_VAL             lStatus=2;      // default return INSTANCE not found
    CSM_MsgSignerInfo      tmpSI(pSI);
    CSM_Buffer            *pSignerPublicKey=NULL;
    CSM_Alg               *palgSig=NULL;

    SME_SETUP("Verify(pCSMIME,pSI,pOriginalEncapContent,pCerts,pSignedAttrs)");
  
    // Call the CSM_MsgSignerInfo Verify Member Function with all passed in
    // parameters except we indirectly reference the SNACC SignerInfo which
    // was passed in by loading it into a CSM_MsgSignerInfo which will in turn
    // use its Verify Member function to verify this SNACC data.  Also pass in
    // the CSM_DataToVerify SNACC data member (m_pSnaccSignedData->
   // encapContentInfo)
#ifdef CML_USED
    CM_SFLCertificate      ACMLCert;
    CSM_CertificateChoice *pCert=NULL;
    if (m_bCMLUseToValidate)
    {            // PRE-Fill pSignerPublicKey AND palgSig if possible
                 //  as well as validate cert(s) using CML.
       // FIRST, determine appropriate cert to be validated.
       //pCert = ;
       // SECOND, validate this cert.
       ACMLCert.m_pRID = tmpSI.GetSignerIdentifier();
       lStatus = CMLValidateCert(ACMLCert,  pCert);
       // THIRD, check to see if we must fail fatal on failed validation
       if ((lStatus != 0 && m_bCMLFatalFail) || 
		   (lStatus == SM_TOO_MANY_CERTS_FOUND_IN_DB))
       {
          if (m_bCMLFatalFail)
          {
             static char pszBuf[1000];
             strncpy(pszBuf, m_pszCMLError, 999);
             SME_THROW(22, pszBuf, NULL);
          }      // END fatal CML check.
       }
       else
       {
		   const CML::ASN::PublicKeyInfo& pubKey =
			   ACMLCert.AccessCMLCert()->base().userCert.pubKeyInfo;

		   // Copy the public key and algorithm
		   pSignerPublicKey = new CSM_Buffer((const char *)pubKey.key.GetData(), pubKey.key.Len());
		   if (pubKey.algorithm.parameters == NULL)
			   palgSig = new CSM_Alg((AsnOid&)pubKey.algorithm.algorithm);
		   else
		   {
               CSM_Buffer BufParams((const char *)pubKey.algorithm.parameters->GetData(), 
                                     pubKey.algorithm.parameters->Len());
			   palgSig = new CSM_Alg((AsnOid&)pubKey.algorithm.algorithm,
				   BufParams);
		   }
       }      // END status check.
    }      // END if m_bCMLUseToValidate
#ifdef ACL_USED         // IN THIS CASE, MUST HAVE CML AS WELL!
   if (m_bACLUseToValidate && ACMLCert.AccessCMLCert() && ACMLCert.AccessCMLCert()->GetEncUserCert().Len())
   {               // Validate Signer cert, if available from CML!
      const uchar *pData=ACMLCert.AccessCMLCert()->GetEncUserCert().GetData();
      CSM_Buffer BufCert((const char *)pData, ACMLCert.AccessCMLCert()->GetEncUserCert().Len());
      acl::SPIF *pSpif = NULL;
      if (pSignedAttrs)
       {
         CSM_SecLbl *pCSM_SecLbl = pSignedAttrs->GetSecurityLabel();
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
                    if (m_pACLLocalCert)
                    {
                        // NOW, get the locally associated SPIF from the 
                        //   app provided reference certifiate 
                        //   (our signing/encrypting cert).
                        lStatus = m_ACLInterface.Check_ACLIncommingRecip(
                                            ACMLCert, *m_pACLLocalCert, pSpif);
                            // To get the right SPIF (or a closely matched
                            //  equivalent SPIF), we call the Incomming Orig
                            //  logic, which returns a SPIF we can work 
                            //  with.
                    }
                    else         // THEN perform backup plan, using sec
                    {            //  label policy directly (may not work).
                        //RWC; THIS CALL MAY NOT BE VALID HERE, this user may 
                        //    not use this policy SPIF.  In this case we 
                        //    expect the user to supply his origination cert
                        //    as a reference check to determine our local SPIF.
                        pSpif = m_ACLInterface.lookupSpif(pCSM_SecLbl->m_PolicyId);
                                //RWC;NOTE:Normally we would not have to 
                                //  pre-lookup the SPIF, but for Incomming
                                //  Originator check, we must...(???)
                    }
                    delete pACLMsgLabel;
                }       // END if pACLMsgLabel
                delete pSNACCSecLbl;
             }      // END IF pSNACCSecLbl built.
             delete pCSM_SecLbl;
         }  // END IF security label present in SignedAttrs
       }    // END if SignerInfo AND SignedAttrs present.
       if (pSpif)
       {
          lStatus = m_ACLInterface.Check_ACLIncommingOrig(ACMLCert, BufCert, *pSpif);
          delete pSpif;
       }
       else
           lStatus = -1;        // INDICATE failure, since no SPIF.
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
#endif  //CML_USED

    lStatus = tmpSI.Verify(pCSMIME, pOriginalEncapContent,
                           &m_pSnaccSignedData->encapContentInfo,
                           pCerts, pSignedAttrs, pSignerPublicKey, 
                           palgSig);

    if (palgSig)
       delete palgSig;
    if (pSignerPublicKey)
       delete pSignerPublicKey;

    SME_FINISH
    SME_CATCH_SETUP
       if (pSignerPublicKey)
          delete pSignerPublicKey;
    SME_CATCH_FINISH

    return(lStatus);

} // END OF MEMBER FUNCTION Verify

// END OF CSM_DataToVerify FUNCTION DEFINITIONS

_END_SFL_NAMESPACE

// EOF sm_Verify.cpp
