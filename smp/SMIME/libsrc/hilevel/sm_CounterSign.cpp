
//////////////////////////////////////////////////////////////////////////////
//  sm_CounterSign.cpp
//  These routines support the CSM_CounterSign class.
//
// CONSTRUCTOR FOR CSM_MsgToAddSignatures
//     CSM_MsgToAddSignatures(CSMIME *pCSMIME, CSM_Buffer *pBlob,
//                            bool bVerifySignatureFlag) :
//                            CSM_MsgToVerify(pCSMIME, pBlob)
//
// DESTRUCTOR FOR CSM_MsgToCounterSign
//     ~CSM_MsgToCounterSign()
//
// CONSTRUCTOR FOR CSM_MsgToCounterSign
//     CSM_MsgToCounterSign(CSMIME *pCSMIME, CSM_Buffer *pBlob,
//                          bool bVerifySignatureFlag) :
//         CSM_MsgToAddSignatures(pCSMIME, pBlob, bVerifySignatureFlag)
//
// MEMBER FUNCTIONS FOR CSM_MsgToCounterSign
//     Clear()
//     ProduceCounterSignature(CSMIME *pCSMIME)
//     LoadCounterSignature(CSM_MsgSignerInfo CSSignerInfo)
//     PutSignerInfo(CSM_CSInst *pCSInst, SignedData *lpSignedData,
//                   SignerInfo *&lpSNACCSignerInfo)
//////////////////////////////////////////////////////////////////////////////

#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

// CONSTRUCTOR FOR CSM_MsgToAddSignatures
// This is a constructor for CSM_MsgToAddSignatures which will be used by
//  CSM_MsgToCountersign in one of its constructors.  It is the only
//  CSM_MsgToAddSignatures function defined outside the header file (sm_api.h)
//  and so is included here.  The bVerifySignatureFlag parameter, which will
//  default to false, is checked before a Verify is performed.  If it is false
//  the value of the class data member m_SignatureVerifyStatus is updated to
//  0 (Not verified), otherwise a Verify is attempted on the pCSMIME parameter.
//  If the verify is successful the m_SignatureVerifyStatus data member is set
//  to 1, if it fails it is set to -1.
//
CSM_MsgToAddSignatures::CSM_MsgToAddSignatures(CSMIME *pCSMIME,
       const CSM_Buffer *pBlob,
       bool bVerifySignatureFlag,       
       bool bCMLUseToValidate, 
       bool bCMLFatalFail, 
       long lCmlSessionId, 
       long lSrlSessionId) 
       : CSM_MsgToVerify(pCSMIME, pBlob,
          bCMLUseToValidate, 
           bCMLFatalFail , 
           lCmlSessionId , 
           lSrlSessionId)
{
    Clear();
    //RWC; CAREFUL with this logic; the following statement copies the
    //  decoded verify component for SNACC SignedData into the
    //  CSM_MsgToSign::SNACC SignedData aggregated memory
    m_SnaccSignedData = *m_pSnaccSignedData;
    if (bVerifySignatureFlag)  // TRUE - PERFORM Verify; FALSE - NO Verify
    {
        if (Verify(pCSMIME) != 0)
        {
            m_SignatureVerifyStatus = -1;   // FAILED
        }
        else
        {
            m_SignatureVerifyStatus = 1;    // VERIFIED
        }
    }
    else
    {
        m_SignatureVerifyStatus = 0;        // NOT VERIFIED
    }

    // RWC; At this point, we need to copy the special SignedAttrs that must be
    //  present in every SignerInfo if they are present at all.  This includes
    //  Mail List Expansion History AND the ESS Security Label attributes.
    //  We are assuming here that the message is built correctly and every SI
    //  contains either or both if at all.
    if (CSM_MsgToVerify::m_pSignerInfos && CSM_MsgToVerify::m_pSignerInfos->begin()->m_pSignedAttrs)
    {
       CSM_MsgAttributes *pTmpAttrs=CSM_MsgToVerify::m_pSignerInfos->begin()->m_pSignedAttrs;
       CSM_Attrib *pTmpAttr;
       AsnOid SNACCTmpSecurityLabel(id_aa_securityLabel);
       CSM_AttribLst::iterator *pitTmpSecurityLabel = 
                          pTmpAttrs->FindAttrib(SNACCTmpSecurityLabel);
       if (pitTmpSecurityLabel && *pitTmpSecurityLabel != pTmpAttrs->m_pAttrs->end())
       {          // THEN add to our soon-to-be-signed attribute list.
          if (CSM_MsgToSign::m_pSignedAttrs == NULL)
              CSM_MsgToSign::m_pSignedAttrs = new CSM_MsgAttributes;
          pTmpAttr = new CSM_Attrib(*(*pitTmpSecurityLabel));
          this->CSM_MsgToSign::m_pSignedAttrs->AddAttrib(*pTmpAttr);
                         // DO NOT DELETE pTmpAttr since taken by AddAttrib().
          delete pitTmpSecurityLabel;
          pitTmpSecurityLabel = NULL;
       }       // END if pTmpSecurityLabel
       if (pitTmpSecurityLabel != NULL)
          delete pitTmpSecurityLabel;
       
       AsnOid SNACCTmpMlExpansionHistory(id_aa_mlExpandHistory);
       CSM_AttribLst::iterator  *pitTmpMailListHistory = 
                          pTmpAttrs->FindAttrib(SNACCTmpMlExpansionHistory);
       if (pitTmpMailListHistory && *pitTmpMailListHistory != pTmpAttrs->m_pAttrs->end())
       {          // THEN add to our soon-to-be-signed attribute list.
          if (this->CSM_MsgToSign::m_pSignedAttrs == NULL)
             this->CSM_MsgToSign::m_pSignedAttrs = new CSM_MsgAttributes;
          pTmpAttr = new CSM_Attrib(*(*pitTmpMailListHistory));
          this->CSM_MsgToSign::m_pSignedAttrs->AddAttrib(*pTmpAttr);
                         // DO NOT DELETE pTmpAttr since taken by AddAttrib().
          delete pitTmpMailListHistory;
          pitTmpMailListHistory = NULL;
       }       // END if pTmpSecurityLabel
       if (pitTmpMailListHistory != NULL)
          delete pitTmpMailListHistory;

    }    // END if any SIs AND SignedAttrs.
}

// DESTRUCTOR FOR CSM_MsgToCounterSign
//
CSM_MsgToCounterSign::~CSM_MsgToCounterSign()
{
    if (m_pSID)
    {
        delete m_pSID;
    }
    if (m_bCSMultiValueAttrFlag)
    {
        m_bCSMultiValueAttrFlag=0;
    }
}

// CONSTRUCTOR FOR CSM_MsgToCounterSign
//   INPUT: CSMIME, CSM_Buffer
//   OUTPUT: NONE
//   RETURN: N/A
//   Constructor using a Content Info Message as input to create a Message
//   to CounterSign.  Pass all the arguments to the inherited
//   CSM_MsgToAddSignatures constructor which takes the same three objects.
//
CSM_MsgToCounterSign::CSM_MsgToCounterSign(CSMIME *pCSMIME, CSM_Buffer *pBlob,
                                           bool bVerifySignatureFlag) :
    CSM_MsgToAddSignatures(pCSMIME, pBlob, bVerifySignatureFlag)
{ Clear(); }

// Clear:
//   FUNCTION TO INITIALIZE THE DATA MEMBERS OF THIS CLASS
//   INPUT:  NONE
//   OUTPUT: NONE
//   STATUS: NONE
//
void CSM_MsgToCounterSign::Clear()
{
    m_bCSMultiValueAttrFlag = false;
    m_pSID = NULL;
};

// ProduceCounterSignature:
//   INPUT: CSMIME
//   OUTPUT: NONE
//   RETURN: STATUS (SM_RET_VAL)
//
SM_RET_VAL CSM_MsgToCounterSign::ProduceCounterSignature(CSMIME *pCSMIME)
{
    SM_RET_VAL status=0;
    CSM_CSInst *tmpCSInst=NULL;
    bool bAtLeastOneSigner;
    CSM_Buffer *pSigBuf=NULL;
    SignerInfo *tmpSNACCSignerInfo=new SignerInfo;
    SignedData *lpSignedData=&m_SnaccSignedData;
    CSM_MsgSignerInfos::iterator itTmpMsgSI;

    SME_SETUP("ProduceCounterSignature");

    if (m_pSignerInfos == NULL)
        return(0);
    // LOOP THROUGH ALL THE SignerInfos IN THE CURRENT MESSAGE
    for (itTmpMsgSI =  CSM_MsgToVerify::m_pSignerInfos->begin();
         itTmpMsgSI != CSM_MsgToVerify::m_pSignerInfos->end() && 
             status == SM_NO_ERROR;
         ++itTmpMsgSI)
    {
        // PULL THE Signer ID FROM THIS SignerInfo
        CSM_RecipientIdentifier *pTmpSID=itTmpMsgSI->GetSignerIdentifier();
        CSM_RecipientIdentifier tmpSID(*pTmpSID);
        delete pTmpSID;
        // COMPARE IT TO THE ONE IDENTIFIED EARLIER TO Countersign
        if (*m_pSID == tmpSID)
        {
            // WHEN A MATCH IS FOUND EXTRACT THE SIGNATURE VALUE
            //   (THIS IS WHAT WE ARE GOING TO SIGN)
            pSigBuf = new CSM_Buffer(itTmpMsgSI->AccessSignerInfo()->
                signature.c_str(), itTmpMsgSI->AccessSignerInfo()->signature.Len());
            break;
        }
    }

    // THROW ERROR IF THERE IS NO SIGNATURE VALUE FOR THE REQUESTED SignerInfo
    if (pSigBuf == NULL)
    {
        SME_THROW(SM_NO_MATCHING_SIGNATURE,
            "ProduceCounterSignature: no Signature to Countersign", NULL);
    }

    bAtLeastOneSigner = false;

    // FOR NOW WE ARE SAYING THERE IS ONLY GOING TO BE ONE CSInst
    //   IN THE CURRENT CSMIME OBJECT.  LOOP UNTIL YOU FIND IT.
    // FOR EACH SESSION MARKED TO SIGN THIS MESSAGE, LOAD A SignerInfo
    //  (BE SURE TO ONLY COMPUTE THE COMMON HASH CODE ONCE FOR ANY Signers
    //   THAT HAPPEN TO USE THE SAME HASH COMPUTATION.)
    CSM_CtilInstLst::iterator itTmpInst;
    for(itTmpInst =  pCSMIME->m_pCSInsts->begin();
        itTmpInst != pCSMIME->m_pCSInsts->end();
        ++itTmpInst)
    {
      tmpCSInst = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
      if (tmpCSInst)
      {
        if (tmpCSInst->IsApplicable() && tmpCSInst->IsSigner())
        {
            break;
        }
        else
            tmpCSInst = NULL;
      }        // END IF instance handles certificates.
    }          // END FOR each instance.

    // WAS AN INSTANCE FOUND?
    if (tmpCSInst != NULL)
    {
        // CREATE A SIGNED SignerInfo FOR THIS SESSION
        if (ProduceSignerInfo(tmpCSInst, lpSignedData,
                              tmpSNACCSignerInfo, pSigBuf) == SM_NO_ERROR)
        {
            CSM_MsgToSign::SetSignerInfoVersion(*tmpSNACCSignerInfo);
            m_CounterSignatureSI.SetSignerInfo(*tmpSNACCSignerInfo);
#ifdef CSDEBUG
            CSM_Buffer *pBuf=NULL;
            ENCODE_BUF(m_CounterSignatureSI.AccessSignerInfo(), pBuf);
            pBuf->ConvertMemoryToFile("C:/TEMP/CS.out");
#endif
            LoadCounterSignature(m_CounterSignatureSI);
            bAtLeastOneSigner = true;
        }
    }
    else
    {
        SME_THROW(SM_NO_MATCHING_SIGNATURE,
            "ProduceCounterSignature: no applicable login for this algorithm",
            NULL);
    }

    // THIS SIGN ENCODES THE SIGNED DATA, DOES NOT PERFORM A SIGNING OPERATION
    if (m_pEncodedBlob)      // DELETE ANY EXISTING DEFINITION.
        delete m_pEncodedBlob;
    m_pEncodedBlob = NULL;
    status = CSM_DataToSign::Sign(pCSMIME, CSM_MsgToSign::m_pMsgCertCrls,
                                  m_pEncodedBlob);
                 // The "m_pMsgCertCrls" variable contains optional certs
                 //  and CRLs specified by the application, not those
                 //  available from the logon instances.
    if (tmpSNACCSignerInfo)
        delete tmpSNACCSignerInfo;
    if (pSigBuf)
        delete pSigBuf;

    SME_FINISH
    SME_CATCH_SETUP
    // local cleanup logic
    SME_CATCH_FINISH

    return(status);

} // END OF MEMBER FUNCTION ProduceCounterSignature

// LoadCounterSignature:
//   INPUT: CSM_MsgSignerInfo
//   OUTPUT: NONE
//   RETURN: STATUS (SM_RET_VAL)
//   Loads the countersignature value, possibly from an external source
//
SM_RET_VAL CSM_MsgToCounterSign::
    LoadCounterSignature(CSM_MsgSignerInfo &CSSignerInfo)
{
    SM_RET_VAL       status=0;
    CSM_Attrib      *pTmpCSAttrib=NULL;
    AsnOid          *pOid = NULL;
    CSM_Buffer      *pEncodedAttr = NULL;

    // TBD THIS FUNCTION WILL HAVE TO BE MODIFIED TO HANDLE CREATION OF
    //   MULTIVALUE COUNTERSIGNATURE ATTRIBUTES.  FIRST IT WILL BE NECESSARY
    //   TO CHECK THE m_bCSMultiValueAttrFlag.  THEN IT WILL BE NECESSARY TO
    //   KEEP TRACK OF THE PREVIOUSLY LOADED UNSIGNED ATTRIBUTE TYPE (OID)
    //   AND IF IT IS THE SAME AS THE CURRENT ONE, SKIP THE ASSIGNMENT OF
    //   THE ATTRIBUTE TYPE AND APPEND THE CURRENT VALUE TO THE PREVIOUS
    //   SNACC ATTRIBUTE - bg

    SME_SETUP("LoadCounterSignature");

    // Using the CSM_Attrib constructor for a SNACC SignerInfo
    // (Countersignature) create the counterSignature Attribute
    // from the CSM_MsgSignerInfo which was passed in.  This will be
    // loaded as an Unsigned Attribute into the appropriate SignerInfo
    if ((pTmpCSAttrib =
        new CSM_Attrib(CSSignerInfo.AccessSignerInfo())) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    // LOOP THOUGH THE LOW LEVEL SNACC SignedData TO ISOLATE THE ONE
    //   WHICH HAS A Signer ID MATCHING THE ONE IN THE MsgToCounterSign
    SignerInfos::iterator TmpSNACCCSSI;
    for (TmpSNACCCSSI = m_SnaccSignedData.signerInfos.begin();
         TmpSNACCCSSI != m_SnaccSignedData.signerInfos.end() &&
         status == SM_NO_ERROR; ++TmpSNACCCSSI)
    {
            // Pull the Signer ID for this MsgSignerInfo
        CSM_RecipientIdentifier tmpSID(TmpSNACCCSSI->sid);
            // CHECK THIS Signer ID AGAINST THE ONE FOR THE MsgToCounterSign
        if (*m_pSID == tmpSID)
        {
            // Check for Unsigned Attributes in the current SNACC Signer Info
            if (TmpSNACCCSSI->unsignedAttrs == NULL)
            {
                // If there are none create a place holder
                TmpSNACCCSSI->unsignedAttrs = new UnsignedAttributes;
            }

            // Create a place holder for the new SNACC attribute
            Attribute &TmpSNACCUnsignedAttr = *TmpSNACCCSSI->unsignedAttrs->append();

            // Pull the OID and the encoded Buffer from the CS CSM_Attrib
            pTmpCSAttrib->GetEncodedAttr(pOid, pEncodedAttr);

            // Set the attribute type in the SNACC Attribute
            TmpSNACCUnsignedAttr.type = *pOid;

            // Create a place holder for the new SNACC attribute value
            AttributeValue  &TmpSNACCAttrValue = *TmpSNACCUnsignedAttr.values.append();
            // Dump the encoded Buffer into the SNACC attribute value
            SM_ASSIGN_ANYBUF(pEncodedAttr, &TmpSNACCAttrValue);

            // CLEAN UP
            if (pOid)
            {
                delete pOid;
                pOid = NULL;
            }
            if (pEncodedAttr)
            {
                delete pEncodedAttr;  // RWC;MUST delete since MACRO copies;
                                      //   created by GetEncodedAttr().
                                      //   (CAREFUL where this is deleted,
                                      //   it is re-used in the loop after
                                      //   the 1st run if not set to NULL.
                pEncodedAttr = NULL;
            }
        }
    }
    if (pTmpCSAttrib)
        delete pTmpCSAttrib;

    SME_FINISH
    SME_CATCH_SETUP
    // local cleanup logic
    SME_CATCH_FINISH

    return(status);

} // END OF MEMBER FUNCTION LoadCounterSignature

// PutSignerInfo:
//   INPUT: CSM_CSInst, SignedData, SignerInfo
//   OUTPUT:
//   RETURN: long
//
SM_RET_VAL CSM_MsgToCounterSign::PutSignerInfo(CSM_CSInst *pCSInst,
                                        SignedData *lpSignedData,
                                        SignerInfo *&lpSNACCSignerInfo)
{
    SM_RET_VAL lRet=0;

    lRet = PutSignerInfoCommon(pCSInst, lpSignedData, lpSNACCSignerInfo);

    return lRet;

} // END OF MEMBER FUNCTION PutSignerInfo

// ***************************************************************************
// SetSICounterSigner:
//
// ***************************************************************************
SM_RET_VAL CSM_MsgToCounterSign::SetSICounterSigner(
                                    CSM_RecipientIdentifier &RecipId)
{
    SM_RET_VAL ret = SM_NO_ERROR;

    m_pSID = new CSM_RecipientIdentifier(RecipId);

    return ret;
} // END OF MEMBER FUNCTION SetSICounterSigner

_END_SFL_NAMESPACE

// EOF sm_CounterSign.cpp

