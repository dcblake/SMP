
// sm_Attr.cpp
// This support file handles the Attribute class functionality for the SMIME
//  library.

#include "sm_api.h"
#include "sm_VDAStream.h"
#include <time.h>

_BEGIN_SFL_NAMESPACE
using namespace SNACC;
using namespace CERT;

// The most recent changes to this source made use of the following version
// of the Enhanced Security Services for S/MIME Specifications.
// Internet Draft                              Editor: Paul Hoffman
// draft-ietf-smime-ess-12.txt                 Internet Mail Consortium
// March 29, 1999
// These changes include the CSM_Attrib Check-Attr functions and the
// CSM_MsgAttributes Check-Attrs functions.

// NOTE:
// DESTRUCTOR IS MISSING CONDITIONS FOR id_aa_signingCertificate,
// id_aa_encrypKeyPref

CSM_PolicyQualifierInfo::
    CSM_PolicyQualifierInfo(const CSM_PolicyQualifierInfo &sPolicyQualifierInfo)
{
    m_pQualifier = NULL;
    *this = sPolicyQualifierInfo;
}

CSM_PolicyQualifierInfo &CSM_PolicyQualifierInfo::
    operator = (const CSM_PolicyQualifierInfo &sPolicyQualifierInfo)
{
    m_PolicyQualifierId = sPolicyQualifierInfo.m_PolicyQualifierId;
    if (m_pQualifier == NULL && sPolicyQualifierInfo.m_pQualifier)
        m_pQualifier = new CSM_Buffer(*sPolicyQualifierInfo.m_pQualifier);
    else
        if (sPolicyQualifierInfo.m_pQualifier)
            *m_pQualifier = *sPolicyQualifierInfo.m_pQualifier;

    return(*this);
}

CSM_PolicyInfo::CSM_PolicyInfo(const CSM_PolicyInfo &sPolicyInfo)
{
    m_pPolicyQualifiers = NULL;
    *this = sPolicyInfo;
}

CSM_PolicyInfo &CSM_PolicyInfo::operator = (const CSM_PolicyInfo &sPolicyInfo)
{
    m_CertPolicyId = sPolicyInfo.m_CertPolicyId;
    if (m_pPolicyQualifiers == NULL && sPolicyInfo.m_pPolicyQualifiers)
        m_pPolicyQualifiers =
            new CSM_PolicyQualifierLst(*sPolicyInfo.m_pPolicyQualifiers);
    else
        if (sPolicyInfo.m_pPolicyQualifiers)
            *m_pPolicyQualifiers = *sPolicyInfo.m_pPolicyQualifiers;

    return(*this);
}

CSM_SigningCertificate::CSM_SigningCertificate(CSMIME &csmime, const CSM_Buffer &CertBuf, 
                                             const CSM_IssuerAndSerialNumber &CertIssSN)
{
  SME_SETUP("CSM_SigningCertificate::CSM_SigningCertificate");
  
  AsnOid tmpOid(sha_1);
  CSM_Alg sha1Alg(tmpOid);
  CSM_CtilInst *pInst = csmime.FindCSInstAlgIds(&sha1Alg, NULL, NULL, NULL);

  if (pInst)
  {
     // sib may need to set the policies here
     m_pPolicies=NULL;
     
     CSM_Buffer tmpBuf;
     CSM_CertID *pTmpCertID;
     pInst->AccessTokenInterface()->SMTI_DigestData((CSM_Buffer *)&CertBuf, 
        &tmpBuf, tmpOid);


     if ((pTmpCertID = &(*m_Certs.append())) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

     pTmpCertID->m_CertHash = tmpBuf;
     pTmpCertID->m_pIssuerSerial = new SNACC::IssuerSerial;
 
     CML::ASN::DN tmpDN(CertIssSN.AccessSNACCIssuerAndSerialNumber()->issuer);
     CSM_GeneralName tmpGN(tmpDN);


     GeneralName &SNACCGN = *pTmpCertID->m_pIssuerSerial->issuer.append();
     SNACCGN = (GeneralName) tmpGN;

      pTmpCertID->m_pIssuerSerial->serial =      
         CertIssSN.AccessSNACCIssuerAndSerialNumber()->serial;
  }

  SME_FINISH_CATCH

}


CSM_SigningCertificate::CSM_SigningCertificate(const CSM_SigningCertificate &sCert)
{
    m_pPolicies = NULL;
    *this = sCert;
}

CSM_SigningCertificate &CSM_SigningCertificate::operator = (const CSM_SigningCertificate &sCert)
{
    m_Certs = sCert.m_Certs;
    if (m_pPolicies == NULL && sCert.m_pPolicies)
        m_pPolicies = new CSM_PolicyInfoLst(*sCert.m_pPolicies);
    else
        if (sCert.m_pPolicies)
            *m_pPolicies = *sCert.m_pPolicies;

    return(*this);
}

SM_RET_VAL CSM_SigningCertificate::LoadNextCertId(const char *pszLogin, CSMIME *pCsmime)
{
   SM_RET_VAL status = SM_NO_ERROR;

   if (pCsmime != NULL)
   {
       CSM_CSInst *pInst = pCsmime->FindInstByDN((char *)pszLogin);
	    if (pInst == NULL)
       {
          status = -1;  // cert not found in login list
	    }
       else
       {
          // acces user cert for the next call
          CSM_CertificateChoice *pTmpCert = (CSM_CertificateChoice *)pInst->AccessUserCertificate();
          status = LoadNextCertId(pTmpCert, pCsmime);
       }
   }        // END IF pCsmime present

   return status;
}

SM_RET_VAL CSM_SigningCertificate::LoadNextCertId(CSM_CertificateChoice *pCertChoice,
                                                  CSMIME *pCsmime)
{
   SM_RET_VAL status = SM_NO_ERROR;
   CSM_Buffer tmpBuf;
   CSM_CertID *pTmpCertID = NULL;
   CSM_Buffer *pCert = NULL;
   CSM_CtilInst *pInst = NULL;

   SME_SETUP("CSM_SigningCertificate::LoadNextCertId");
   
   //m_Certs.SetCurrToLast();
   if ((pTmpCertID = &(*m_Certs.append())) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   pCert = (CSM_Buffer *)pCertChoice->AccessEncodedCert();
   
   // has the cert
   AsnOid tmpOid(sha_1);
   CSM_Alg tmpAlg(tmpOid);
   pInst = pCsmime->FindCSInstAlgIds(&tmpAlg, NULL, NULL, NULL);
   SME(pInst->AccessTokenInterface()->SMTI_DigestData(
      pCert, &tmpBuf, tmpOid));
  
   if (tmpBuf.Length() > 0)
   {
		// assign  hash 
		pTmpCertID->m_CertHash.Set(tmpBuf.Access(), tmpBuf.Length());

		// get memory for issuerSerial
		if (pTmpCertID->m_pIssuerSerial)
			delete pTmpCertID->m_pIssuerSerial;
		if ((pTmpCertID->m_pIssuerSerial = new SNACC::IssuerSerial) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

      // build certs general names list for issuer and assign
		CSM_IssuerAndSerialNumber *pIssSN = (CSM_IssuerAndSerialNumber *)pCertChoice->GetIssuerAndSerialNumber();
      CML::ASN::DN tmpDN(pIssSN->AccessSNACCIssuerAndSerialNumber()->issuer);
      CSM_GeneralName tmpGN(tmpDN);
      GeneralName &SNACCGN = *pTmpCertID->m_pIssuerSerial->issuer.append();
      SNACCGN = (GeneralName) tmpGN;

      // assign serialNum 
      pTmpCertID->m_pIssuerSerial->serial.Set(pIssSN->AccessSNACCIssuerAndSerialNumber()->serial);
      
      // assign IssuerUid
     // pTmpCertID->m_pIssuerSerial->issuerUID = pCertChoice->;

   }
   else
   {
      status = -1;  // error with hash 
   }

   SME_FINISH_CATCH

   return status;

}

SM_RET_VAL CSM_SigningCertificate::LoadPolicyLst(const char *policy, 
                                                  CSM_PolicyQualifierLst *pQualList)
{ 
    SM_RET_VAL status = SM_NO_ERROR;
    CSM_PolicyInfo *pTmpPolicyInfo = NULL;

    SME_SETUP("CSM_SigningCertificate::LoadNextPolicy");

    if (m_pPolicies == NULL)
    {   
       if ((m_pPolicies = new CSM_PolicyInfoLst) == NULL)
          SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
    }
 
    if ((pTmpPolicyInfo = &(*m_pPolicies->append())) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    SME(pTmpPolicyInfo->m_CertPolicyId = AsnOid(policy));


    if (pQualList)
    {
       pTmpPolicyInfo->m_pPolicyQualifiers = pQualList;
    }


   SME_FINISH_CATCH

   return status;

} // End of LoadNextPolicy


CSM_CertID &CSM_CertID::operator = (const CSM_CertID &ID)
{   m_CertHash = ID.m_CertHash;
    if (ID.m_pIssuerSerial)
    {
            m_pIssuerSerial = new IssuerSerial;
            *m_pIssuerSerial = *ID.m_pIssuerSerial;
    }
    return(*this);
};


//
//
CSM_Attrib::CSM_Attrib(const CSM_Attrib &Attrib)
{
    Clear();
    *this = Attrib;
}

//
//
CSM_Attrib & CSM_Attrib::operator=(const CSM_Attrib &Attrib)
{
   CSM_Buffer *pTmpBuf=NULL;

   AttribDestroy();     // CLEAR original contents if any.
   ((CSM_Attrib &)Attrib).GetEncodedAttr(pTmpBuf);
   if (pTmpBuf && Attrib.m_poid)
   {
      this->SetAttribByOid(*Attrib.m_poid, *pTmpBuf);
      delete pTmpBuf;
   }     // END if pTmpBuf
   return(*this);
}        // END CSM_Attrib::CSM_Attrib(CSM_Attrib &)


// DESTRUCTOR FOR CSM_Attrib
//
CSM_Attrib::~CSM_Attrib()
{
    AttribDestroy(false);   // inherited elements destroyed later.
}

//
//
void CSM_Attrib::AttribDestroy(bool bDestroyEncoded)
{
  SME_SETUP("CSM_Attrib::~CSM_Attrib");

  if (bDestroyEncoded && m_pEncodedAttrib)
  {
        delete m_pEncodedAttrib;
        m_pEncodedAttrib = NULL;
        if (m_poid)
        {
            delete m_poid;
            m_poid = NULL;
        }   // END if m_poid
  }     // END if bDestroyEncoded

  if (m_poid)
  {
    if(*m_poid == id_messageDigest && m_pMessageDigest)
    {
        delete m_pMessageDigest;
    }
    else if(*m_poid== id_aa_msgSigDigest && m_pMsgSigDigest)
    {
        delete m_pMsgSigDigest;
    }
    else if(*m_poid== id_signingTime && m_pSigningTime)
    {
        delete m_pSigningTime;
    }
    else if(*m_poid== id_countersignature && m_pSNACCCounterSignature)
    {
        delete m_pSNACCCounterSignature;
    }
    else if(*m_poid== id_aa_receiptRequest && m_pReceiptRequest)
    {
        delete m_pReceiptRequest;
    }
    else if(*m_poid== id_aa_contentHint && m_pContentHints)
    {
        delete m_pContentHints;
    }
    else if(*m_poid== id_aa_contentReference && m_pContentReference)
    {
        delete m_pContentReference;
    }
    else if(*m_poid== id_aa_securityLabel && m_pSecurityLabel)
    {
        delete m_pSecurityLabel;
    }
    else if(*m_poid== id_aa_equivalentLabels && m_pEqulbls)
    {
        delete m_pEqulbls;
    }
    else if(*m_poid== id_contentType && m_pContentType)
    {
        delete m_pContentType;
    }
    else if(*m_poid== id_aa_contentIdentifier && m_pContentIdentifier)
    {
        delete m_pContentIdentifier;
    }
    else if(*m_poid== id_aa_mlExpandHistory && m_pSNACCMlExpHist)
    {
        delete m_pSNACCMlExpHist;
    }
    else if(*m_poid == smimeCapabilities)
    {
        if (m_pSmimeCapLst)
            delete m_pSmimeCapLst;
    }
    else if(*m_poid == id_aa_signingCertificate)
    {
        if (m_pSigningCertificate)
        {
            delete m_pSigningCertificate;
            m_pSigningCertificate = NULL;
        }
    }
    else if (*m_poid == id_aa_timeStampToken)
    {
       if (m_pTimeStampToken)
	   {
          delete m_pTimeStampToken;
		  m_pTimeStampToken = NULL;
	   }
    }
    // TBD NEED CONDITION FOR id_aa_encrypKeyPref
//      else if(*m_poid == id_aa_encrypKeyPref)
//      {
//          if (???)
//              delete ???;
//      }
    else
    {
        if (m_pGeneralAsnLst)
            delete m_pGeneralAsnLst;
    }
  }

  if (m_pszCSInst)
        free(m_pszCSInst);

  SME_FINISH_CATCH
} // END OF CSM_Attrib DESTRUCTOR

CSM_Attrib::CSM_Attrib(CSM_Buffer *pMessageDigest)
{
    Clear();
    SetMessageDigest(pMessageDigest);
} // END OF CSM_Attrib MessageDigest CONSTRUCTOR

//#define DEBUG_ONLY
CSM_Attrib::CSM_Attrib(const AsnOid  &Oid, const CSM_Buffer &SNACCAnyBuf)
{
    SM_RET_VAL status = 0;

    SME_SETUP("CSM_Attrib::CSM_Attrib");
    Clear();

    status = SetAttribByOid(Oid, SNACCAnyBuf);
    if (status)   // bad return
    {
#ifdef DEBUG_ONLY       // RWC; ACCEPT BAD Security label decode tmp...
        m_pGeneralAsnLst = new CSM_GeneralAsnLst;
        m_pGeneralAsnLst->AppendL(new CSM_Buffer(SNACCAnyBuf));
        m_poid = new AsnOid (Oid);
        if(m_pEncodedAttrib)
            delete m_pEncodedAttrib;
        m_pEncodedAttrib = new CSM_Buffer(SNACCAnyBuf);
#else
        char buf[200];
        char *errAttr=Oid.GetChar();
        sprintf(buf, "The following attribute (oid) failed: %s", errAttr);
        free(errAttr);
        SME_THROW(22, buf, NULL);
#endif
    }

    SME_FINISH_CATCH
} // END OF CSM_Attrib CONSTRUCTOR BY AsnOid  AND CSM_Buffer

void CSM_Attrib::SetContentIdentifier(CSM_Buffer *pContentIdentifier)
{
    ContentIdentifier snaccCID;

    SME_SETUP("CSM_Attrib::SetContentIdentifier");

    if (m_pContentIdentifier)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_pContentIdentifier = new CSM_Buffer(*pContentIdentifier);

    m_poid = new AsnOid (id_aa_contentIdentifier);

    snaccCID.Set((const char *)m_pContentIdentifier->Access(),
        (size_t)m_pContentIdentifier->Length());

    ENCODE_BUF((&snaccCID), m_pEncodedAttrib);

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetContentIdentifier

void CSM_Attrib::SetMessageDigest(CSM_Buffer *pMessageDigest)
{
    MessageDigest snaccMD;


    SME_SETUP("CSM_Attrib::SetMessageDigest");

    if (m_pMessageDigest)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_pMessageDigest = new CSM_Buffer(*pMessageDigest);

    m_poid = new AsnOid (id_messageDigest);

    snaccMD.Set((const char *)m_pMessageDigest->Access(),
        (size_t)m_pMessageDigest->Length());

    ENCODE_BUF((&snaccMD), m_pEncodedAttrib);

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetMessageDigest

//////////////////////////////////////////////////////////////////////////
// This method builds a Message Signature Digest attribute (see ESS)
// from the provided buffer
void CSM_Attrib::SetMsgSigDigest(CSM_Buffer *pMsgSigDigest)
{
    MsgSigDigest snaccMSD;

    SME_SETUP("CSM_Attrib::SetMsgSigDigest");

    if (pMsgSigDigest == NULL)
        SME_THROW(SM_MISSING_PARAM, NULL, NULL);

    if (m_pMsgSigDigest)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    if ((m_pMsgSigDigest = new CSM_Buffer(*pMsgSigDigest)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    if ((m_poid = new AsnOid (id_aa_msgSigDigest)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    snaccMSD.Set((const char *)m_pMsgSigDigest->Access(),
        (size_t)m_pMsgSigDigest->Length());

    SME(ENCODE_BUF((&snaccMSD), m_pEncodedAttrib));

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetMsgSigDigest

CSM_Attrib::CSM_Attrib(const CSM_Time &cSigningTime)
{
    Clear();
    SetSigningTime(cSigningTime);
} // END OF CSM_Attrib CSM_Time CONSTRUCTOR

void CSM_Attrib::SetSigningTime(const CSM_Time &cSigningTime)
{
    SigningTime snaccST;

    SME_SETUP("CSM_Attrib::SetSigningTime");

    snaccST.choiceId = (Time::ChoiceIdEnum)cSigningTime.m_type;

    if (m_pSigningTime)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_pSigningTime = new CSM_Time(cSigningTime);

    m_poid = new AsnOid (id_signingTime);

    if (cSigningTime.m_type == SigningTime::generalizedTimeCid)
        snaccST.generalizedTime = new GeneralizedTime((const char *)
        m_pSigningTime->m_lpszTime);
    else if (cSigningTime.m_type == SigningTime::utcTimeCid)
        snaccST.utcTime = new UTCTime((const char *)
        m_pSigningTime->m_lpszTime);
    else
        SME_THROW(SM_MISSING_PARAM, "Bad General/UTC Time type ID.", NULL);

    ENCODE_BUF((&snaccST), m_pEncodedAttrib);

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetSigningTime

// Countersignature:
// Constructor for a CounterSignature (unsigned attribute - SNACC SignerInfo)
//
CSM_Attrib::CSM_Attrib(Countersignature *pSNACCCounterSignature)
{
    Clear();
    SetCounterSignature(pSNACCCounterSignature);
} // END OF CSM_Attrib CounterSignature CONSTRUCTOR

// SetCounterSignature:
//
void CSM_Attrib::SetCounterSignature(Countersignature *pSNACCCounterSignature)
{
    SME_SETUP("CSM_Attrib::SetCounterSignature");

    if (m_pSNACCCounterSignature)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_pSNACCCounterSignature = new Countersignature;

    *m_pSNACCCounterSignature = *pSNACCCounterSignature;

    m_poid = new AsnOid (id_countersignature);

    ENCODE_BUF(m_pSNACCCounterSignature, m_pEncodedAttrib);

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetCounterSignature

CSM_Attrib::CSM_Attrib(CSM_ReceiptRequest *pReceiptRequest)
{
    Clear();
    SetReceiptRequest(pReceiptRequest);
} // END OF CSM_Attrib CSM_ReceiptRequest CONSTRUCTOR

void CSM_Attrib::SetReceiptRequest(CSM_ReceiptRequest *pReceiptRequest)
{
    ReceiptRequest   snaccRR;

    SME_SETUP("CSM_Attrib::SetReceiptRequest");

    if (m_pReceiptRequest)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_pReceiptRequest = new CSM_ReceiptRequest(*pReceiptRequest);

    m_poid = new AsnOid (id_aa_receiptRequest);

    m_pEncodedAttrib = m_pReceiptRequest->GetEncodedReceiptRequest();

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetReceiptRequest

CSM_Attrib::CSM_Attrib(CSM_SigningCertificate *pSigningCertificate)
{
    Clear();
    SetSigningCertificate(pSigningCertificate);
} // END OF CSM_Attrib CSM_SigningCertificate CONSTRUCTOR

void CSM_Attrib::SetSigningCertificate(CSM_SigningCertificate
                                       *pSigningCertificate)
{
    SigningCertificate  snaccSC;
    CSM_CertIDLst::iterator itTmpCertID;
    CSM_PolicyInfoLst::iterator itTmpPolicyInfo;

    SME_SETUP("CSM_Attrib::SetSigningCertificate");

    if (m_pSigningCertificate)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    // The following line invokes the copy constructor provided by C++
    m_pSigningCertificate = new CSM_SigningCertificate(*pSigningCertificate);

    m_poid = new AsnOid (id_aa_signingCertificate);

    for(itTmpCertID =  m_pSigningCertificate->m_Certs.begin();
        itTmpCertID != m_pSigningCertificate->m_Certs.end();
        ++itTmpCertID)
    {
        ESSCertID &tmpSNACCCertID = *snaccSC.certs.append();
        tmpSNACCCertID.certHash.Set((const char *)itTmpCertID->
            m_CertHash.Access(), itTmpCertID->m_CertHash.Length());
        tmpSNACCCertID.issuerSerial = new IssuerSerial;
        if (itTmpCertID->m_pIssuerSerial)
           *tmpSNACCCertID.issuerSerial = *itTmpCertID->m_pIssuerSerial;
    }

    // m_pPolicies is an OPTIONAL field
    if (m_pSigningCertificate->m_pPolicies)
    {
        CSM_PolicyQualifierLst::iterator itTmpPolicyQualifier;

        if ((snaccSC.policies = new SigningCertificateSeqOf1) == NULL)
                SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

        for(itTmpPolicyInfo =  m_pSigningCertificate->m_pPolicies->begin();
            itTmpPolicyInfo != m_pSigningCertificate->m_pPolicies->end();
            ++itTmpPolicyInfo)
        {
            PolicyInformation &tmpSNACCPolicyInfo = *snaccSC.policies->append();

            //Get PolicyId (oid)
            tmpSNACCPolicyInfo.policyIdentifier.Set(itTmpPolicyInfo->m_CertPolicyId);

            //PolicyQualfiers is an OPTIONAL field
            if (itTmpPolicyInfo->m_pPolicyQualifiers)
            {
                if ((tmpSNACCPolicyInfo.policyQualifiers =
                                         new PolicyInformationSeqOf) == NULL)
                {
                    SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);
                }

                for (itTmpPolicyQualifier =  itTmpPolicyInfo->m_pPolicyQualifiers->begin();
                     itTmpPolicyQualifier != itTmpPolicyInfo->m_pPolicyQualifiers->end();
                     ++itTmpPolicyQualifier)
                {
                    PolicyQualifierInfo &snaccPolicyQualifier =
                          *tmpSNACCPolicyInfo.policyQualifiers->append();

                    //Extract OID
                    snaccPolicyQualifier.policyQualifierId =
                        itTmpPolicyQualifier->m_PolicyQualifierId;

                    if (itTmpPolicyQualifier->m_pQualifier)
                    {
                        if (snaccPolicyQualifier.qualifier == NULL)
                            snaccPolicyQualifier.qualifier = new AsnAny;
                        // ASN.1 encoded buffer
                        SM_ASSIGN_ANYBUF(itTmpPolicyQualifier->m_pQualifier,
                            snaccPolicyQualifier.qualifier);
                    }
                }
            }
        }
    }

    ENCODE_BUF((&snaccSC), m_pEncodedAttrib);

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetSigningCertificate

CSM_Attrib::CSM_Attrib(SNACC::ContentHints &SNACCContentHints)
{
    Clear();
    SetContentHints(SNACCContentHints);
} // END OF CSM_Attrib CSM_ContentHints CONSTRUCTOR

void CSM_Attrib::SetContentHints(SNACC::ContentHints &SNACCContentHints)
{
    SME_SETUP("CSM_Attrib::CSM_Attrib");

    if (m_pContentHints)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_poid = new AsnOid (id_aa_contentHint);
    m_pContentHints = new SNACC::ContentHints();
    *m_pContentHints = SNACCContentHints;


    ENCODE_BUF((&SNACCContentHints), m_pEncodedAttrib);

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetContentHints

CSM_Attrib::CSM_Attrib(CSM_ContentReference *pContentReference)
{
    Clear();
    SetContentReference(pContentReference);
} // END OF CSM_Attrib CSM_ContentReference CONSTRUCTOR

void CSM_Attrib::SetContentReference(CSM_ContentReference *pContentReference)
{
    ContentReference snaccCR;

    SME_SETUP("CSM_Attrib::CSM_Attrib");

    if (m_pContentReference)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_pContentReference = new CSM_ContentReference(*pContentReference);

    m_poid = new AsnOid (id_aa_contentReference);

    snaccCR.signedContentIdentifier.Set((const char *)m_pContentReference->
        m_SignedContentIdentifier.Access(),
        m_pContentReference->m_SignedContentIdentifier.Length());

    snaccCR.originatorSignatureValue.Set((const char *)m_pContentReference->
        m_OriginatorSignatureValue.Access(),
        m_pContentReference->m_OriginatorSignatureValue.Length());

    m_pContentReference->m_OID.Set(pContentReference->m_OID);

    snaccCR.contentType = m_pContentReference->m_OID;

    ENCODE_BUF((&snaccCR), m_pEncodedAttrib);

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetContentReference

CSM_Attrib::CSM_Attrib(CSM_SecLbl *pSecLbl)
{
    Clear();
    SetSecLbl(pSecLbl);
} // END OF CSM_Attrib CSM_SecLbl CONSTRUCTOR

void CSM_Attrib::SetSecLbl(CSM_SecLbl *pSecLbl)
{
    ESSSecurityLabel *psnaccSL;

    SME_SETUP("CSM_Attrib::SetSecLbl");

    if (m_pSecurityLabel)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_pSecurityLabel = new CSM_SecLbl(*pSecLbl);

    m_poid = new AsnOid (id_aa_securityLabel);

    psnaccSL = pSecLbl->GetSNACCSecLbl();

    ENCODE_BUF((psnaccSL), m_pEncodedAttrib);
    delete psnaccSL;

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetSecLbl

CSM_Attrib::CSM_Attrib(const SMIMEEncryptionKeyPreference &sek)
{
    Clear();
    SetSMIMEEncryptionKeyPreference(sek);
} // END OF CSM_Attrib SMIMEEncryptionKeyPreference CONSTRUCTOR

void CSM_Attrib::
    SetSMIMEEncryptionKeyPreference(const SMIMEEncryptionKeyPreference &sek)
{
    SME_SETUP("CSM_Attrib::SetSMIMEEncryptionKeyPreference");

    AttribDestroy();
    if ((m_poid = new AsnOid (id_aa_encrypKeyPref)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    SME(ENCODE_BUF((&(SMIMEEncryptionKeyPreference &)sek), m_pEncodedAttrib));

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION SetSMIMEEncryptionKeyPreference

CSM_Attrib::CSM_Attrib(CSM_EquivalentLabels *pEqulbls)
{
    Clear();
    SetEquivalentLabels(pEqulbls);
} // END OF CSM_Attrib CSM_EquivalentLabels CONSTRUCTOR

void CSM_Attrib::SetEquivalentLabels(CSM_EquivalentLabels *pEqulbls)
{
    EquivalentLabels  snaccELS;
    CSM_EquivalentLabels::iterator itTmpSL;
    ESSSecurityLabel *psnaccSL;

    if(m_pEncodedAttrib)
        free(m_pEncodedAttrib);

    SME_SETUP("CSM_Attrib::SetEquivalentLabels");

    if (pEqulbls == NULL)
        SME_THROW(SM_MISSING_PARAM, NULL, NULL);

    if (m_pEqulbls)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    if ((m_pEqulbls = new CSM_EquivalentLabels(*pEqulbls)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    if ((m_poid = new AsnOid (id_aa_equivalentLabels)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    for(itTmpSL =  pEqulbls->begin(); 
        itTmpSL != pEqulbls->end();
        ++itTmpSL)
    {
        psnaccSL = itTmpSL->GetSNACCSecLbl();
        snaccELS.append(*psnaccSL);
        delete psnaccSL;
    }

    SME(ENCODE_BUF((&snaccELS), m_pEncodedAttrib));

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetEquivalentLabels

CSM_Attrib::CSM_Attrib(CSM_SmimeCapabilityLst *pSmimeCapLst)
{
    Clear();
    SetSMIMECapabilities(pSmimeCapLst);
} // END OF CSM_Attrib CSM_SmimeCapabilityLst CONSTRUCTOR

void CSM_Attrib::SetSMIMECapabilities(CSM_SmimeCapabilityLst *pSmimeCapLst)
{
    SMIMECapabilities    snaccSCS;
    CSM_SmimeCapabilityLst::iterator itTmpSC;

    SME_SETUP("CSM_Attrib::SetSMIMECapabilities");

    if (pSmimeCapLst == NULL)
        SME_THROW(SM_MISSING_PARAM, NULL, NULL);

    if (m_pSmimeCapLst)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    if ((m_pSmimeCapLst = new CSM_SmimeCapabilityLst(*pSmimeCapLst)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    if ((m_poid = new AsnOid (smimeCapabilities)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

    for(itTmpSC =  pSmimeCapLst->begin(); 
        itTmpSC != pSmimeCapLst->end();
        ++itTmpSC)
    {
        SMIMECapability &tmpSNACCSMIMECapability = *snaccSCS.append();

        tmpSNACCSMIMECapability.capabilityID = itTmpSC->m_capabilityID;

        if (itTmpSC->m_pParameters)
        {
            tmpSNACCSMIMECapability.parameters = new AsnAny;
            SM_ASSIGN_ANYBUF(itTmpSC->m_pParameters,
                tmpSNACCSMIMECapability.parameters);
        }
    }

    SME(ENCODE_BUF((&snaccSCS), m_pEncodedAttrib));

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetSMIMECapabilities

//
//
CSM_Attrib::CSM_Attrib(MLExpansionHistory *pMlLst)
{
    Clear();
    SetMLExpansionHistory(pMlLst);
} // END OF CSM_Attrib MLExpansionHistory CONSTRUCTOR

//
//
void CSM_Attrib::SetMLExpansionHistory(MLExpansionHistory *pSNACCMlLst)
{
    SME_SETUP("CSM_Attrib::SetMLExpansionHistory");

    if (m_pSNACCMlExpHist)
        AttribDestroy();
    m_poid = new AsnOid (id_aa_mlExpandHistory);
    m_pSNACCMlExpHist = new MLExpansionHistory;
    *m_pSNACCMlExpHist = *pSNACCMlLst;

    SME(ENCODE_BUF(m_pSNACCMlExpHist, m_pEncodedAttrib));

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetMLExpansionHistory

//
//
CSM_Attrib::CSM_Attrib(AsnOid  *pContentType)
{
    Clear();
    SetContentType(pContentType);
} // END OF CSM_Attrib ContentType CONSTRUCTOR

//
//
void CSM_Attrib::SetContentType(AsnOid  *pContentType)
{
    AsnOid snaccCT;

    SME_SETUP("CSM_Attrib::SetContentType");

    if (m_pContentType)
        AttribDestroy();

    m_pContentType = new AsnOid (*pContentType);

    m_poid = new AsnOid (id_contentType);

    snaccCT = *m_pContentType;

    ENCODE_BUF((&snaccCT), m_pEncodedAttrib);

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetContentType

//
//
CSM_Attrib::CSM_Attrib(CSM_GeneralAsnLst *pGeneralAsnLst)
{
    Clear();
    SetGeneralASN(pGeneralAsnLst);
} // END OF CSM_Attrib CSM_GeneralAsnLst CONSTRUCTOR

//
//
void CSM_Attrib::SetGeneralASN(CSM_GeneralAsnLst *pGeneralAsnLst)
{
    SME_SETUP("CSM_Attrib::SetGeneralASN");

    if (m_pGeneralAsnLst)   // AN ATTRIB is already loaded, destroy it...
        AttribDestroy();
    m_pGeneralAsnLst = new CSM_GeneralAsnLst(*pGeneralAsnLst);

    m_pEncodedAttrib = new CSM_Buffer(*m_pGeneralAsnLst->begin());
    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION SetGeneralASN



//
CSM_Attrib::CSM_Attrib(SNACC::TimeStampToken *pTimeStampToken)
{
    Clear();
    SetTimeStampToken(pTimeStampToken);
} // END OF CSM_Attrib CSM_TimeStampToken CONSTRUCTOR

void CSM_Attrib::SetTimeStampToken(SNACC::TimeStampToken
                                       *pTimeStampToken)
{
    SME_SETUP("CSM_Attrib::SetTimeStamptoken");

    // If the timeStampTokenBuf has data then decode it to assign to m_pEncodedAttrib 
    if (pTimeStampToken)
    {
		if (m_pTimeStampToken)   // AN ATTRIB is already loaded, destroy it...
		   AttribDestroy();

		m_poid = new AsnOid (id_aa_timeStampToken);
		m_pEncodedAttrib = new CSM_Buffer;

        m_pEncodedAttrib->Encode(*(TimeStampToken *)pTimeStampToken);

        m_pTimeStampToken = new TimeStampToken;
		*m_pTimeStampToken = *pTimeStampToken;
	}
 
    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION SetTimeStampToken

//
//
CSM_Attrib::CSM_Attrib()
{
    m_lAttrValueIndex=0;
    m_lMultiAttrIndex=0;
    Clear();
} // END OF CSM_Attrib DEFAULT CONSTRUCTOR

// SetAttribByOid:
//
SM_RET_VAL CSM_Attrib::SetAttribByOid(const AsnOid  &attrType,
                                      const CSM_Buffer &SNACCAnyBuf)
{
    SM_RET_VAL status = SM_NO_ERROR;

    SME_SETUP("CSM_Attrib::SetAttribByOid");

    AttribDestroy();        // CLEAR out previous contents if present....

    if(attrType == id_messageDigest)
    {
        MessageDigest SnaccMD;
        CSM_Buffer    tmpBuf;

        DECODE_BUF_NOFAIL(&SnaccMD,&SNACCAnyBuf,status);
        if (status)
           return(status);

        tmpBuf.Set(SnaccMD.c_str(), SnaccMD.Len());

        SetMessageDigest(&tmpBuf);
    }
    else if(attrType == id_aa_contentIdentifier)
    {
        ContentIdentifier SnaccCI;
        CSM_Buffer    tmpBuf;

        DECODE_BUF_NOFAIL(&SnaccCI,&SNACCAnyBuf,status);
        if (status)
           return(status);

        tmpBuf.Set(SnaccCI.c_str(), SnaccCI.Len());

        SetContentIdentifier(&tmpBuf);
    }
    else if(attrType == id_aa_msgSigDigest)
    {
        MsgSigDigest SnaccMSD;
        CSM_Buffer   tmpBuf;

        DECODE_BUF_NOFAIL(&SnaccMSD,&SNACCAnyBuf,status);
        if (status)
           return(status);

        tmpBuf.Set(SnaccMSD.c_str(), SnaccMSD.Len());

        SetMsgSigDigest(&tmpBuf);
    }
    else if(attrType == id_signingTime)
    {
        SigningTime SnaccST;

        DECODE_BUF_NOFAIL(&SnaccST,&SNACCAnyBuf,status);
        //DEBUG;status=1;
        if (status)
            return(status);

        if(SnaccST.choiceId == Time::generalizedTimeCid)
        {
            CSM_Time tmptime(SnaccST.generalizedTime->c_str(),
                SnaccST.generalizedTime->length(), SigningTime::generalizedTimeCid);
            SetSigningTime(tmptime);
        }
        else if(SnaccST.choiceId == Time::utcTimeCid)
        {
            CSM_Time tmptime2(SnaccST.utcTime->c_str(),
                SnaccST.utcTime->length(), SigningTime::utcTimeCid);
            SetSigningTime(tmptime2);
        }
        else
        {
            SME_THROW(22,"Unrecognized Time,",NULL);
        }
    }
    else if(attrType == id_countersignature)
    {
        Countersignature   SnaccCS;

        DECODE_BUF_NOFAIL(&SnaccCS,&SNACCAnyBuf,status);
        if (status)
           return(status);

        SetCounterSignature(&SnaccCS);
    }
    else if(attrType == id_aa_receiptRequest)
    {
        ReceiptRequest      SnaccRR;
        CSM_ReceiptRequest *tmpRR;
        ReceiptsFromSeqOf::iterator tmpSNACCFromNames;
        ReceiptRequestSeqOf::iterator tmpSNACCToNames;
        CSM_GeneralNames *ptmpGnLst = NULL;

        DECODE_BUF_NOFAIL(&SnaccRR,&SNACCAnyBuf,status);
        if (status)
           return(status);

        tmpRR = new CSM_ReceiptRequest;

        if (SnaccRR.signedContentIdentifier.Len())
        {
            tmpRR->
                m_SignedContentIdentifier.Set(SnaccRR.signedContentIdentifier.c_str(),
                    SnaccRR.signedContentIdentifier.Len());
        }

        if(SnaccRR.receiptsFrom.choiceId == ReceiptsFrom::receiptListCid)
        {
            ptmpGnLst = new CSM_GeneralNames;

            for(tmpSNACCFromNames = SnaccRR.receiptsFrom.receiptList->begin();
                tmpSNACCFromNames != SnaccRR.receiptsFrom.receiptList->end(); 
                ++tmpSNACCFromNames)
            {
                ptmpGnLst->append(*tmpSNACCFromNames->begin());
                // memory is now controlled by CSM_ReceiptRequest
            }
            tmpRR->UpdateReceiptsFrom(ptmpGnLst);        
        }
        else if (SnaccRR.receiptsFrom.choiceId ==
            ReceiptsFrom::allOrFirstTierCid)
        {
            if (AllOrFirstTier::allReceipts ==
				*SnaccRR.receiptsFrom.allOrFirstTier)
                tmpRR->SetallReceipts();
            else if (AllOrFirstTier::firstTierRecipients ==
				*SnaccRR.receiptsFrom.allOrFirstTier)
                tmpRR->SetfirstTierRecipients();
        }

        for(tmpSNACCToNames = SnaccRR.receiptsTo.begin();
            tmpSNACCToNames != SnaccRR.receiptsTo.end(); ++tmpSNACCToNames)
        {
            // sib implementing new data structure for m_ReceiptsTo
            tmpRR->m_ReceiptsTo.append(*tmpSNACCToNames);

        }
        SetReceiptRequest(tmpRR);
        delete tmpRR; // delete tmp memory, copied by SetReceiptRequest(...)
    }
    else if(attrType == id_aa_contentHint)
    {
        ContentHints      SnaccCH;

        DECODE_BUF_NOFAIL(&SnaccCH,&SNACCAnyBuf,status);
        if (status)
           return(status);

        SetContentHints(SnaccCH);
    }
    else if(attrType == id_aa_contentReference)
    {
        ContentReference  SnaccCR;
        CSM_ContentReference  tmpCR;

        DECODE_BUF_NOFAIL(&SnaccCR,&SNACCAnyBuf,status);
        if (status)
           return(status);

        if (SnaccCR.signedContentIdentifier.Len())
            tmpCR.m_SignedContentIdentifier.
                Set(SnaccCR.signedContentIdentifier.c_str(),
                    SnaccCR.signedContentIdentifier.Len());

        tmpCR.m_OriginatorSignatureValue.Set(SnaccCR.originatorSignatureValue.c_str(),
            SnaccCR.originatorSignatureValue.Len());

        tmpCR.m_OID = SnaccCR.contentType;

        SetContentReference(&tmpCR);
    }
    else if(attrType == id_aa_securityLabel)
    {
        ESSSecurityLabel    SnaccSL;
        SecurityCategories::iterator tmpSNACCSecCatsInst;
        CSM_SecCat          *tmpSecCat;
        CSM_SecLbl          securityLabel;

        DECODE_BUF_NOFAIL(&SnaccSL,&SNACCAnyBuf,status);
        if (status)
           return(status);

        securityLabel.m_PolicyId = SnaccSL.security_policy_identifier;

        if (SnaccSL.security_classification)
            securityLabel.m_plSecClass =
                new long(*SnaccSL.security_classification);

        if (SnaccSL.privacy_mark &&
            SnaccSL.privacy_mark->choiceId == ESSPrivacyMark::pStringCid)
        {
            securityLabel.m_pPmark = new CSM_Buffer(
               SnaccSL.privacy_mark->pString->c_str(), 
               SnaccSL.privacy_mark->pString->length());
        }

        if (SnaccSL.security_categories)
        {
            securityLabel.m_pSecCats = new CSM_SecCatLst;  // ONLY create if present.

            for(tmpSNACCSecCatsInst = SnaccSL.security_categories->begin();
                tmpSNACCSecCatsInst != SnaccSL.security_categories->end();
                ++tmpSNACCSecCatsInst)
            {
                tmpSecCat = &(*securityLabel.m_pSecCats->append());

                tmpSecCat->m_Type = tmpSNACCSecCatsInst->type;

                SM_EXTRACT_ANYBUF(tmpSecCat->
                    m_pValue,&tmpSNACCSecCatsInst->value);

            }
        }
        SetSecLbl(&securityLabel);
    }
    else if(attrType == id_aa_equivalentLabels)
    {
        EquivalentLabels::iterator tmpSnaccSL;
        SecurityCategories::iterator tmpSNACCSecCatsInst;
        CSM_SecCat          *tmpSecCat;
        CSM_SecLbl          *tmpSecLbl;
        EquivalentLabels    SnaccEL;
        CSM_EquivalentLabels eqLbl;

        DECODE_BUF_NOFAIL(&SnaccEL,&SNACCAnyBuf,status);
        if (status)
           return(status);

        for(tmpSnaccSL = SnaccEL.begin();
            tmpSnaccSL != SnaccEL.end(); 
            ++tmpSnaccSL)
        {
            tmpSecLbl = &(*eqLbl.append());

            tmpSecLbl->m_PolicyId = tmpSnaccSL->security_policy_identifier;

            if (tmpSnaccSL->security_classification)
                tmpSecLbl->m_plSecClass =
                    new long(*tmpSnaccSL->security_classification);

            if (tmpSnaccSL->privacy_mark->choiceId ==
                ESSPrivacyMark::pStringCid)
            {
                tmpSecLbl->m_pPmark = new CSM_Buffer(
                   tmpSnaccSL->privacy_mark->pString->c_str(),
                   tmpSnaccSL->privacy_mark->pString->length());
            }

            if (tmpSnaccSL->security_categories)
            {
               tmpSecLbl->m_pSecCats = new CSM_SecCatLst;

               for(tmpSNACCSecCatsInst = tmpSnaccSL->security_categories->begin();
                   tmpSNACCSecCatsInst != tmpSnaccSL->security_categories->end();
                   ++tmpSNACCSecCatsInst)
               {
                   tmpSecCat = &(*tmpSecLbl->m_pSecCats->append());

                   tmpSecCat->m_Type = tmpSNACCSecCatsInst->type;

                   SM_EXTRACT_ANYBUF(tmpSecCat->
                       m_pValue, &tmpSNACCSecCatsInst->value);

               }     // END for each security_categories
            }        // END if any security_categories
        }            // END for each security label.
        SetEquivalentLabels(&eqLbl);
    }
    else if(attrType == smimeCapabilities)
    {
        SMIMECapabilities::iterator tmpSnaccSC;
        CSM_SmimeCapability *tmpSmimeCap;
        SMIMECapabilities   SnaccCaps;
        CSM_SmimeCapabilityLst smimeCapLst;

        DECODE_BUF_NOFAIL(&SnaccCaps,&SNACCAnyBuf,status);
        if (status)
           return(status);

        for(tmpSnaccSC = SnaccCaps.begin();
            tmpSnaccSC != SnaccCaps.end();
            ++tmpSnaccSC)
        {
            tmpSmimeCap = &(*smimeCapLst.append());

            tmpSmimeCap->m_capabilityID = tmpSnaccSC->capabilityID;

            if (tmpSnaccSC->parameters)
            {
                SM_EXTRACT_ANYBUF(tmpSmimeCap->
                    m_pParameters, tmpSnaccSC->parameters);
            }

        }
        SetSMIMECapabilities(&smimeCapLst);
    }
    else if(attrType == id_contentType)
    {
        ContentType SnaccCT;
        AsnOid      ptmpCT;       //Content Type

        DECODE_BUF_NOFAIL(&SnaccCT,&SNACCAnyBuf,status);
        //DEBUG;status=1;
        if (status)
            return(status);

        ptmpCT = AsnOid (SnaccCT);

        SetContentType(&ptmpCT);
    }
    else if(attrType == id_aa_mlExpandHistory)
    {
        MLExpansionHistory SnaccML;

        DECODE_BUF_NOFAIL(&SnaccML,&SNACCAnyBuf,status);
        if (status)
           return(status);

        SetMLExpansionHistory(&SnaccML);
    }
    else if(attrType == id_aa_signingCertificate)
    {
        CSM_CertIDLst *certIDLst = NULL;
        CSM_CertID *certID = NULL;
        SigningCertificate tmpSnaccSigCert;
        SigningCertificateSeqOf::iterator tmpSnaccCert;
        CSM_SigningCertificate *tmpSigCert;

        tmpSigCert = new CSM_SigningCertificate;

        DECODE_BUF_NOFAIL(&tmpSnaccSigCert, &SNACCAnyBuf, status);
        if (status)
           return(status);

        if (certIDLst == NULL)
        {
            if ((certIDLst = new CSM_CertIDLst) == NULL)
            {
                SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            }
        }

        if (&tmpSnaccSigCert.certs)
        {
            for(tmpSnaccCert = tmpSnaccSigCert.certs.begin();
                tmpSnaccCert != tmpSnaccSigCert.certs.end();
                ++tmpSnaccCert)
            {
                if ((certID = &(*certIDLst->append())) == NULL)
                {
                    SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
                }

                certID->m_CertHash.Set(tmpSnaccCert->certHash.c_str());
                // IssuerSerial1 is an OPTIONAL field
                if (tmpSnaccCert->issuerSerial)
                {
                    certID->m_pIssuerSerial = new IssuerSerial;
                    *certID->m_pIssuerSerial = *tmpSnaccCert->issuerSerial;
                }
            }

            tmpSigCert->m_Certs = *certIDLst;

            CSM_PolicyInfo *policy = NULL;
            CSM_PolicyInfoLst *policyLst = NULL;
            CSM_PolicyQualifierInfo *qualifier = NULL;
            CSM_PolicyQualifierLst *qualifierLst = NULL;
            SigningCertificateSeqOf1::iterator tmpSnaccPolicy;
            PolicyInformationSeqOf::iterator tmpSnaccQualifier;

            // policies is an OPTIONAL field
            if (tmpSnaccSigCert.policies)
            {
                if ((policyLst = new CSM_PolicyInfoLst) == NULL)
                {
                    SME_THROW(SM_MEMORY_ERROR, NULL, NULL)
                }

                if ((qualifierLst = new CSM_PolicyQualifierLst) == NULL)
                {
                    SME_THROW(SM_MEMORY_ERROR, NULL, NULL)
                }

                for(tmpSnaccPolicy = tmpSnaccSigCert.policies->begin();
                    tmpSnaccPolicy != tmpSnaccSigCert.policies->end();
                    ++tmpSnaccPolicy)
                {
                    if ((policy = &(*policyLst->append())) == NULL)
                    {
                        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
                    }

                    policy->m_CertPolicyId = tmpSnaccPolicy->
                        policyIdentifier;

                    if (tmpSnaccPolicy->policyQualifiers)
                    {
                        for(tmpSnaccQualifier = tmpSnaccPolicy->policyQualifiers->begin();
                            tmpSnaccQualifier != tmpSnaccPolicy->policyQualifiers->end();
                            ++tmpSnaccQualifier)
                        {
                            if ((qualifier = &(*qualifierLst->append())) == NULL)
                            {
                                SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
                            }

                            qualifier->m_PolicyQualifierId =
                                tmpSnaccQualifier->policyQualifierId;

                            SM_EXTRACT_ANYBUF(qualifier->m_pQualifier,
                                tmpSnaccQualifier->qualifier);
                        }

                        policy->m_pPolicyQualifiers = qualifierLst;
                    }
                }

                tmpSigCert->m_pPolicies = policyLst;
            }

            SetSigningCertificate(tmpSigCert);

            if (tmpSigCert)
            {
                delete tmpSigCert;
            }
        }
        else
        {
           std::cout << "Certs field is NULL in SigningCertificate Attribute\n";
        }
        if (certIDLst)
        {
            delete certIDLst;
        }
    }
    else if(attrType == id_aa_timeStampToken)  
    {
       SNACC::TimeStampToken SnaccTST;

        DECODE_BUF_NOFAIL(&SnaccTST,&SNACCAnyBuf,status);
        if (status)
           return(status);

        SetTimeStampToken(&SnaccTST);
    }
    else //RWC;4/9/02;LEFT AS GeneralAsn;if (attrType != id_aa_encrypKeyPref)
    {
        m_pGeneralAsnLst = new CSM_GeneralAsnLst;
        CSM_Buffer *pTmpBuf=&(*m_pGeneralAsnLst->append());
        *pTmpBuf = SNACCAnyBuf;
        m_poid = new AsnOid (attrType );
        if(m_pEncodedAttrib)
            free(m_pEncodedAttrib);
        m_pEncodedAttrib = new CSM_Buffer(SNACCAnyBuf);
    }
    SME_FINISH_CATCH;
    return(status);
} // END OF SetAttribByOid

// Clear:
//
void CSM_Attrib::Clear()
{
    m_pMessageDigest = NULL;
    m_pMsgSigDigest = NULL;
    m_pSigningTime = NULL;
    m_pSNACCCounterSignature = NULL;
    m_pReceiptRequest = NULL;
    m_pSigningCertificate = NULL;
    m_pContentHints = NULL;
    m_pContentReference = NULL;
    m_pSecurityLabel = NULL;
    m_pEqulbls = NULL;
    m_pSNACCMlExpHist = NULL;
    m_pGeneralAsnLst = NULL;
    m_pContentType = NULL;
    m_pszCSInst = NULL;
    m_pTimeStampToken = NULL;
} // END OF Clear

// This method is intended for reporting specific errors or information
//  to a general "ostream", which may be standard out.  The application
//  can reference the produced buffer of attribute data, including the
//  attribute type, through "(char *)os".
//  RWC: Intended use of this routine, not just for standard out
//      #include <stdio.h>
//      ofstream ostrm("resultingFile.out")
//      pAttr->Report(ostrm)
void CSM_Attrib::Report(std::ostream &os)
{
    CSM_Buffer &SNACCAnyBuf=*m_pEncodedAttrib;
    AsnOid     *&pAttrType=m_poid;
    char       *lpszBuf=NULL;
    CSM_Buffer *pTmpBuf;
    SM_RET_VAL  status = 0;

    SME_SETUP("CSM_Attrib::Report");
    VDAStream::setIndent(VDAStream::getIndent()+1);
    os << "####################  ATTRIBUTE ("
       << m_lAttrValueIndex+1 << ", " << m_lMultiAttrIndex+1 << ") ::::\n";
    if (pAttrType == NULL)
    {
        os << "***** NOT OID IN Attribute!!!! ******\n";
    }
    else if(*pAttrType == id_messageDigest)
    {
        MessageDigest snaccMD;

        DECODE_BUF_NOFAIL(&snaccMD,&SNACCAnyBuf,status);
        if (status)
            os << "****** messageDigest attribute FAILED DECODE ******\n";
        else
        {
            os << "messageDigest=";
            
            // PIERCE 9-04-2001 
            //   all octet strings inherit CSM_Buffer now
            //
            //ReportHexBuffer(os, (char *)snaccMD, snaccMD.Len());
            snaccMD.Print(os);
        }
    }
    else if(*pAttrType == id_aa_msgSigDigest)
    {
        MsgSigDigest SnaccMSD;

        DECODE_BUF_NOFAIL(&SnaccMSD,&SNACCAnyBuf,status);
        if (status)
            os << "****** msgSigDigest attribute FAILED DECODE ******\n";
        else
        {
            os << "msgSigDigest=";
            //ReportHexBuffer(os, (char *)SnaccMSD, SnaccMSD.Len());
            SnaccMSD.Print(os);
        }
    }
    else if(*pAttrType == id_signingTime)
    {
        SigningTime   SnaccST;

        DECODE_BUF_NOFAIL(&SnaccST,&SNACCAnyBuf,status);
        if (status)
            os << "****** signingTime attribute FAILED DECODE ******\n";
        else
        {
            os << "signingTime=";
            if(SnaccST.choiceId == Time::generalizedTimeCid)
            {
                os << *SnaccST.generalizedTime << "\n";
            }
            else if(SnaccST.choiceId == Time::utcTimeCid)
            {
                os << *SnaccST.utcTime << "\n";
            }
            else
            {
                SME_THROW(22,"Unrecognized Time,",NULL);
            }
        }
    }
    else if(*pAttrType == id_countersignature)
    {
        Countersignature   SnaccCS;
        CSM_MsgSignerInfo *pTmpCSSI;

        DECODE_BUF_NOFAIL(&SnaccCS, &SNACCAnyBuf, status);
        if (status)
            os << "****** countersignature attribute"
               << " FAILED DECODE ******\n";
        else
        {
            // Reporting of the info in a CounterSignature Attribute
            // making use of MsgSignerInfo Class member function
            os << "countersignature attribute (SignerInfo)\n";
            pTmpCSSI = new CSM_MsgSignerInfo(&SnaccCS);
            VDAStream::setIndent(VDAStream::getIndent()+1);
            pTmpCSSI->ReportMsgData(os);
            VDAStream::setIndent(VDAStream::getIndent()-1);
            if (pTmpCSSI)
                delete pTmpCSSI;
        }
    }
    else if(*pAttrType == id_aa_receiptRequest)
    {
        ReceiptRequest   SnaccRR;
        ReceiptsFromSeqOf::iterator tmpSNACCFromNames;
        ReceiptRequestSeqOf::iterator tmpSNACCToNames;
        CSM_GeneralName *csmGN=NULL;
        CSM_DN          *tmpDN = NULL;

        DECODE_BUF_NOFAIL(&SnaccRR, &SNACCAnyBuf, status);
        if (status)
            os << "****** receiptRequest attribute FAILED DECODE ******\n";
        else
        {
            os << "receiptRequest=\n";
            VDAStream::setIndent(VDAStream::getIndent()+1);
            os << "signedContentIdentifier=";
            SnaccRR.signedContentIdentifier.Print(os);
           
            /*
            ReportHexBuffer(os, (char *)SnaccRR.signedContentIdentifier,
               SnaccRR.signedContentIdentifier.Len());
            */
 
            if(SnaccRR.receiptsFrom.choiceId == ReceiptsFrom::receiptListCid)
            {
                os << "receiptsFrom=\n";
                for(tmpSNACCFromNames = SnaccRR.receiptsFrom.receiptList->begin();
                    tmpSNACCFromNames != SnaccRR.receiptsFrom.receiptList->end();
                    ++tmpSNACCFromNames)
                {
                    GeneralName &tmpSNACCGName = *(*tmpSNACCFromNames).begin();

                    // Must convert from GeneralName to CSM_GeneralName
                    csmGN = new CSM_GeneralName(tmpSNACCGName);

                    VDAStream::setIndent(VDAStream::getIndent()+1);
                    if (tmpSNACCGName.choiceId == GeneralName::directoryNameCid)
                    {
                        tmpDN = csmGN->GetGenNameDN();
                        const char *pA = *tmpDN;
                        os << "DN=" << pA << "\n";
                        delete tmpDN;
                        // clean up memory allocated with Get call
                    }
                    else if (tmpSNACCGName.choiceId ==
                        GeneralName::rfc822NameCid)
                    {
                        lpszBuf = csmGN->GetGenNameRFC822();
                        os << "RFC822=" << lpszBuf << "\n";
                        free(lpszBuf);
                    }
                    else if (tmpSNACCGName.choiceId ==
                        GeneralName::uniformResourceIdentifierCid)
                    {
                        lpszBuf = csmGN->GetGenNameURI();
                        os << "URI=" << lpszBuf << "\n";
                        free(lpszBuf);
                    }
                    else if (tmpSNACCGName.choiceId ==
                        GeneralName::dNSNameCid)
                    {
                        lpszBuf = csmGN->GetGenNameDNS();
                        os << "DNS=" << lpszBuf << "\n";
                        free(lpszBuf);
                    }
                    else
                    {
                        os << "<<<GeneralName choiceId not Supported, "
                            << (int)tmpSNACCGName.choiceId << ">>>\n";
                    }
                    VDAStream::setIndent(VDAStream::getIndent()-1);
                    if (csmGN)
                    {
                        delete csmGN;
                        csmGN = NULL;
                    }
                }
            }
            else if (SnaccRR.receiptsFrom.choiceId ==
                ReceiptsFrom::allOrFirstTierCid)
            {
                VDAStream::setIndent(VDAStream::getIndent()+1);
                if (AllOrFirstTier::allReceipts ==
					*SnaccRR.receiptsFrom.allOrFirstTier)
                {
                    os << "receiptsFrom=allReceipts\n";
                }
                else if (AllOrFirstTier::firstTierRecipients ==
					*SnaccRR.receiptsFrom.allOrFirstTier)
                {
                    os << "receiptsFrom=firstTierRecipients\n";
                }
                VDAStream::setIndent(VDAStream::getIndent()-1);
            }

            int index=1;
            for(tmpSNACCToNames = SnaccRR.receiptsTo.begin();
                tmpSNACCToNames != SnaccRR.receiptsTo.end();
                ++tmpSNACCToNames)
            {
               os << "receiptsTo=" <<  index++ << "\n";
               GeneralNames::iterator tmpSNACCGName;
               for (tmpSNACCGName = tmpSNACCToNames->begin();
                    tmpSNACCGName != tmpSNACCToNames->end();
                    ++tmpSNACCGName)
               {
                   // Must convert from GeneralName to CSM_GeneralName
                   if (csmGN)
                       delete csmGN;
                   csmGN = new CSM_GeneralName(*tmpSNACCGName);

                   VDAStream::setIndent(VDAStream::getIndent()+1);
                   if (tmpSNACCGName->choiceId == GeneralName::directoryNameCid)
                   {
                       tmpDN = csmGN->GetGenNameDN();
                       const char *pA=*tmpDN;
                       os << "DN=" << pA << "\n";
                       // clean up memory allocated with Get call
                       delete tmpDN;
                   }
                   else if (tmpSNACCGName->choiceId ==
                       GeneralName::rfc822NameCid)
                   {
                       lpszBuf = csmGN->GetGenNameRFC822();
                       os << "RFC822=" << lpszBuf << "\n";
                       free(lpszBuf);
                   }
                   else if (tmpSNACCGName->choiceId ==
                       GeneralName::uniformResourceIdentifierCid)
                   {
                       lpszBuf = csmGN->GetGenNameURI();
                       os << "URI=" << lpszBuf << "\n";
                       free(lpszBuf);
                   }
                   else if (tmpSNACCGName->choiceId == GeneralName::dNSNameCid)
                   {
                       lpszBuf = csmGN->GetGenNameDNS();
                       os << "DNS=" << lpszBuf << "\n";
                       free(lpszBuf);
                   }
                   else
                   {
                       os << "<<<GeneralName choiceId not Supported, "
                           << (int)tmpSNACCGName->choiceId << ">>>\n";
                   }
                   VDAStream::setIndent(VDAStream::getIndent()-1);
                   if (csmGN)
                   {
                       delete csmGN;
                       csmGN = NULL;
                   }
               }        // FOR each tmpSNACCToNames in list
            }           // FOR each SnaccRR.receiptsTo
        }               // END IF receiptRequest decoded
    }                   // IF receiptRequest attribute
    else if(*pAttrType == id_aa_contentHint)
    {
        ContentHints SnaccCH;

        DECODE_BUF_NOFAIL(&SnaccCH,&SNACCAnyBuf,status);
        if (status)
            os << "****** contentHint attribute FAILED DECODE ******\n";
        else
        {
            os << "contentHint=";

            VDAStream::setIndent(VDAStream::getIndent()+2);
            if(SnaccCH.contentDescription != NULL)
            {
                os << "\ncontentDescription=";

                char  *utf8Str = NULL;
                utf8Str = SnaccCH.contentDescription->getAsUTF8();

                os << utf8Str << "\n";

                if (utf8Str)
                   free(utf8Str);

            }
            AsnOid  tmpOID(SnaccCH.contentType);
            VDAStream::setIndent(VDAStream::getIndent()-1);
            char *ptr=tmpOID.GetChar();
            os << "contentType=" << ptr << "\n";
            if (ptr)
               free(ptr);
            VDAStream::setIndent(VDAStream::getIndent()-1);
        }
    }
    else if(*pAttrType == id_aa_contentReference)
    {
        ContentReference SnaccCR;
        AsnOid           tmpOID;

        DECODE_BUF_NOFAIL(&SnaccCR,&SNACCAnyBuf,status);
        if (status)
            os << "****** contentReference attribute"
               << " FAILED DECODE ******\n";
        else
        {
            os << "contentReference=\n";
            VDAStream::setIndent(VDAStream::getIndent()+1);
            os << "signedContentIdentifier=";
            SnaccCR.signedContentIdentifier.Print(os);
            /*
            ReportHexBuffer(os, (char *)SnaccCR.signedContentIdentifier,
                SnaccCR.signedContentIdentifier.Len());
            */
            os << "originatorSignatureValue=";
            SnaccCR.originatorSignatureValue.Print(os);
            /*
            ReportHexBuffer(os, (char *)SnaccCR.originatorSignatureValue,
                SnaccCR.originatorSignatureValue.Len());
            */

            tmpOID = SnaccCR.contentType;
            char *ptr = tmpOID.GetChar();
            os << "contentType=" << ptr << "\n";
            if (ptr)
               free(ptr);
            VDAStream::setIndent(VDAStream::getIndent()-1);
        }
    }
    else if(*pAttrType == id_aa_contentIdentifier)
    {
        ContentIdentifier SnaccCI;

        DECODE_BUF_NOFAIL(&SnaccCI,&SNACCAnyBuf,status);
        if (status)
            os << "****** contentIdentifier attribute FAILED DECODE ******\n";
        else
        {
            os << "contentIdentifier=";
            SnaccCI.Print(os);
            /*
            ReportHexBuffer(os, (char *)SnaccCI, SnaccCI.Len());
            */
        }
    }
    else if(*pAttrType == id_aa_securityLabel)
    {
        ESSSecurityLabel  SnaccSL;
        SecurityCategories::iterator tmpSNACCSecCatsInst;

        DECODE_BUF_NOFAIL(&SnaccSL,&SNACCAnyBuf,status);
        if (status)
            os << "****** securityLabel attribute FAILED DECODE ******\n";
        else
        {
            os << "securityLabel=\n";

            AsnOid  tmpOID(SnaccSL.security_policy_identifier);
            VDAStream::setIndent(VDAStream::getIndent()+1);
            char *ptr=tmpOID.GetChar();
            os << "security_policy_identifier="
               << ptr << "\n";
            if (ptr)
               free(ptr);

            if (SnaccSL.security_classification)
            {
                os << "security_classification="
                    << *SnaccSL.security_classification << "\n";
            }

            if (SnaccSL.privacy_mark &&
                SnaccSL.privacy_mark->choiceId == ESSPrivacyMark::pStringCid)
            {
                os << "pMark=";
                lpszBuf =
                    (char *)calloc(1,SnaccSL.privacy_mark->pString->length()+1);
                ::memcpy(lpszBuf, SnaccSL.privacy_mark->pString->c_str(),
                    SnaccSL.privacy_mark->pString->length());
                os << lpszBuf << "\n";
                free(lpszBuf);
            }
            else
            {
                os << "<<<Unsupported privacy_mark->choiceId>>>.\n";
            }

            if (SnaccSL.security_categories)
            {
                os << "security_categories=";
                VDAStream::setIndent(VDAStream::getIndent()+1);
                for(tmpSNACCSecCatsInst = SnaccSL.security_categories->begin();
                    tmpSNACCSecCatsInst != SnaccSL.security_categories->end();
                    ++tmpSNACCSecCatsInst)
                {
                    AsnOid  tmpOID(tmpSNACCSecCatsInst->type);
                    char *ptr=tmpOID.GetChar();
                    os << "type=" << ptr << "\n";
                    if (ptr)
                        free(ptr);
                    pTmpBuf = NULL;
                    SM_EXTRACT_ANYBUF(pTmpBuf, &tmpSNACCSecCatsInst->value);
                    pTmpBuf->ReportHexBuffer(os);
                    delete pTmpBuf;
                }
                VDAStream::setIndent(VDAStream::getIndent()-1);
            }
            VDAStream::setIndent(VDAStream::getIndent()-1);
        }
    }
    else if(*pAttrType == id_aa_equivalentLabels)
    {
        EquivalentLabels::iterator tmpSnaccSL;
        SecurityCategories::iterator tmpSNACCSecCatsInst;
        EquivalentLabels  SnaccEL;

        DECODE_BUF_NOFAIL(&SnaccEL,&SNACCAnyBuf,status);
        if (status)
            os << "****** equivalentLabels attribute"
               << " FAILED DECODE ******\n";
        else
        {
            os << "equivalentLabels=\n";

            for(tmpSnaccSL = SnaccEL.begin();
                tmpSnaccSL != SnaccEL.end();
                ++tmpSnaccSL)
            {
                VDAStream::setIndent(VDAStream::getIndent()+1);
                os << "Label=\n";
                AsnOid  tmpOID(tmpSnaccSL->security_policy_identifier);
                VDAStream::setIndent(VDAStream::getIndent()+1);
                char *ptr=tmpOID.GetChar();
                if (ptr == NULL)
                    ptr = strdup("(NOT PRESENT)");
                os << "security_policy_identifier="
                    << ptr << "\n";
                if (ptr)
                   free(ptr);
                VDAStream::setIndent(VDAStream::getIndent()-1);

                if (tmpSnaccSL->security_classification)
                {
                    os << "security_classification="
                        << *tmpSnaccSL->security_classification << "\n";
                }

                if (tmpSnaccSL->privacy_mark->choiceId ==
                    ESSPrivacyMark::pStringCid)
                {
                    VDAStream::setIndent(VDAStream::getIndent()+1);
                    os << "pMark=";
                    os << tmpSnaccSL->privacy_mark->pString->c_str(),
                    VDAStream::setIndent(VDAStream::getIndent()-1);
                }
                else
                {
                    os << "Unsupported privacy_mark->choiceId.\n";
                }

                os << "security_categories=";
                for(tmpSNACCSecCatsInst = tmpSnaccSL->security_categories->begin();
                    tmpSNACCSecCatsInst != tmpSnaccSL->security_categories->end();
                    ++tmpSNACCSecCatsInst)
                {
                    AsnOid  tmpOID(tmpSNACCSecCatsInst->type);
                    VDAStream::setIndent(VDAStream::getIndent()+1);
                    char *ptr=tmpOID.GetChar();
                    os << "type=" << ptr << "\n";
                    if (ptr)
                       free(ptr);

                    pTmpBuf = NULL;
                    SM_EXTRACT_ANYBUF(pTmpBuf, &tmpSNACCSecCatsInst->value);
                    ReportHexBuffer(os, (char *)pTmpBuf->Access(), pTmpBuf->Length());
                    VDAStream::setIndent(VDAStream::getIndent()-1);
                    delete pTmpBuf;
                }
                VDAStream::setIndent(VDAStream::getIndent()-1);
            }
        }
    }
    else if(*pAttrType == smimeCapabilities)
    {
        SMIMECapabilities::iterator tmpSnaccSC;
        SMIMECapabilities  SnaccCaps;

        DECODE_BUF_NOFAIL(&SnaccCaps,&SNACCAnyBuf,status);
        if (status)
            os << "****** sMIMECapabilities attribute"
               << " FAILED DECODE ******\n";
        else
        {
            os << "sMIMECapabilities=\n";

            for(tmpSnaccSC = SnaccCaps.begin();
                tmpSnaccSC != SnaccCaps.end();
                ++tmpSnaccSC)
            {
                VDAStream::setIndent(VDAStream::getIndent()+1);
                AsnOid  tmpOID(tmpSnaccSC->capabilityID);
                char *ptr=tmpOID.GetChar();
                os << "capabilityID=" << ptr << "\n";
                if (ptr)
                   free(ptr);

                if (tmpSnaccSC->parameters)
                {
                    VDAStream::setIndent(VDAStream::getIndent()+1);
                    os << "parameters=";
                    pTmpBuf = NULL;
                    SM_EXTRACT_ANYBUF(pTmpBuf,tmpSnaccSC->parameters);
                    ReportHexBuffer(os, (char *)pTmpBuf->Access(), pTmpBuf->Length());
                    VDAStream::setIndent(VDAStream::getIndent()-1);
                    delete pTmpBuf;
                }
                VDAStream::setIndent(VDAStream::getIndent()-1);
            }
        }
    }
    else if(*pAttrType == id_aa_encrypKeyPref)
    {
        SMIMEEncryptionKeyPreference  SnaccSEK;

        DECODE_BUF_NOFAIL(&SnaccSEK,&SNACCAnyBuf,status);
        if (status)
           os << "****** SMIMEEncryptionKeyPreference attribute"
              << " FAILED DECODE ******\n";
        else
        {
           os << "SMIMEEncryptionKeyPreference=\n";
           SnaccSEK.Print(os);
        }
    }
    else if(*pAttrType == id_contentType)
    {
        ContentType SnaccCT;

        DECODE_BUF_NOFAIL(&SnaccCT,&SNACCAnyBuf,status);
        if (status)
            os << "****** contentType attribute FAILED DECODE ******\n";
        else
        {
            os << "contentType=";

            AsnOid  tmpOID(SnaccCT);
            char *ptr=tmpOID.GetChar();
            os << ptr << "\n";
            free(ptr);
        }
    }
    else if(*pAttrType == id_aa_mlExpandHistory)
    {
        MLExpansionHistory::iterator tmpSNACCMl;
        char *ptr,*ptr2;

        ptr2 = pAttrType->GetChar();
        os << "mlExpandHistoryOID=" << ptr2 << "\n";
        for(tmpSNACCMl =  m_pSNACCMlExpHist->begin(); 
            tmpSNACCMl != m_pSNACCMlExpHist->end();
            ++tmpSNACCMl)
        {
            VDAStream::setIndent(VDAStream::getIndent()+1);
            os << "MailData=" << "\n";
            VDAStream::setIndent(VDAStream::getIndent()+1);
            if (tmpSNACCMl->mailListIdentifier.choiceId ==
                EntityIdentifier::issuerAndSerialNumberCid)
            {
                CSM_IssuerAndSerialNumber b(*tmpSNACCMl->
                    mailListIdentifier.issuerAndSerialNumber);
                CSM_DN *pDn=b.GetIssuer();
                CSM_Buffer *pBuf=b.GetSerialNo();
                os << "issuerAndSerialNumber=" << *pDn << "\n";
                ReportHexBuffer(os, (char *)pBuf->Access(), pBuf->Length());
                if (pDn)
                    delete pDn;
                if (pBuf)
                    delete pBuf;
            }
            else if (tmpSNACCMl->mailListIdentifier.choiceId ==
                EntityIdentifier::subjectKeyIdentifierCid)
            {
                CSM_Buffer Buf((char *)
                    tmpSNACCMl->mailListIdentifier.subjectKeyIdentifier,
                    tmpSNACCMl->mailListIdentifier.subjectKeyIdentifier->Len());
                os << "subjectKeyIdentifier=";
                ReportHexBuffer(os, (char *)Buf.Access(), Buf.Length());
            }
            else
            {
                SME_THROW(22,
                    "Unrecognized tmpSNACCMl->mailListIdentifier,", NULL);
            }
            VDAStream::setIndent(VDAStream::getIndent()-1);

            // Handle expansionTime.
            os << "expansionTime=";
            char buf[100];
            ::memcpy(buf, (char *)tmpSNACCMl->expansionTime.c_str(),
                tmpSNACCMl->expansionTime.length());
            buf[tmpSNACCMl->expansionTime.length()] = '\0';
            os << buf << "\n";

            // handle mlReceiptPolicy
            if (tmpSNACCMl->mlReceiptPolicy)
            {
                MLReceiptPolicySeqOf::iterator SNACCTmpGNs;
                GeneralNames::iterator SNACCTmpGN;
                CSM_GeneralName *pTmpGn=NULL;
                int i=0;
                if (tmpSNACCMl->mlReceiptPolicy->choiceId ==
                    MLReceiptPolicy::insteadOfCid)
                {
                    VDAStream::setIndent(VDAStream::getIndent()+1);
                    os << "mlReceiptPolicy=insteadOfCid\n";
                    for(SNACCTmpGNs =  tmpSNACCMl->mlReceiptPolicy->insteadOf->begin();
                        SNACCTmpGNs != tmpSNACCMl->mlReceiptPolicy->insteadOf->end();
                        ++SNACCTmpGNs)
                    {
                        VDAStream::setIndent(VDAStream::getIndent()+1);
                        os << "insteadOf[" << i++ << "] = \n";
                        for(SNACCTmpGN = SNACCTmpGNs->begin();
                            SNACCTmpGN != SNACCTmpGNs->end();
                            ++SNACCTmpGN)
                        {
                            VDAStream::setIndent(VDAStream::getIndent()+1);
                            pTmpGn = (CSM_GeneralName *)&(*SNACCTmpGN);
                            ptr = this->GetGenNameString(*pTmpGn);
                            os << ptr << "\n";
                            VDAStream::setIndent(VDAStream::getIndent()-1);
                            free(ptr);
                        }
                        VDAStream::setIndent(VDAStream::getIndent()-1);
                    }
                    VDAStream::setIndent(VDAStream::getIndent()-1);
                }
                else if (tmpSNACCMl->mlReceiptPolicy->choiceId ==
                    MLReceiptPolicy::inAdditionToCid)
                {
                    VDAStream::setIndent(VDAStream::getIndent()+1);
                    i = 0;
                    os << "mlReceiptPolicy=inAdditionToCid\n";
                    for(SNACCTmpGNs  = tmpSNACCMl->mlReceiptPolicy->inAdditionTo->begin();
                        SNACCTmpGNs != tmpSNACCMl->mlReceiptPolicy->inAdditionTo->end();
                        ++SNACCTmpGNs)
                    {
                        VDAStream::setIndent(VDAStream::getIndent()+1);
                        os << "inAdditionTo[" << i++ << "] = \n";
                        for(SNACCTmpGN =  SNACCTmpGNs->begin();
                            SNACCTmpGN != SNACCTmpGNs->end();
                            ++SNACCTmpGN)
                        {
                            VDAStream::setIndent(VDAStream::getIndent()+1);
                            pTmpGn = (CSM_GeneralName *)&(*SNACCTmpGN);
                            ptr = this->GetGenNameString(*pTmpGn);
                            os << ptr << "\n";
                            VDAStream::setIndent(VDAStream::getIndent()-1);
                            free(ptr);
                        }
                        VDAStream::setIndent(VDAStream::getIndent()-1);
                    }
                    VDAStream::setIndent(VDAStream::getIndent()-1);
                }
                else if (tmpSNACCMl->mlReceiptPolicy->choiceId ==
                    MLReceiptPolicy::noneCid)
                {
                    VDAStream::setIndent(VDAStream::getIndent()+1);
                    os << "mlReceiptPolicy=noneCid\n";
                    VDAStream::setIndent(VDAStream::getIndent()-1);
                }
                else
                {
                    SME_THROW(22, "Unrecognized mlReceiptPolicy,", NULL);
                }
            }
            VDAStream::setIndent(VDAStream::getIndent()-1);
        }
        if (ptr2)
        {
            free(ptr2);
        }
    }
    else if(*pAttrType == id_aa_signingCertificate)
    {
        SigningCertificate tmpSnaccSigCert;

        DECODE_BUF_NOFAIL(&tmpSnaccSigCert, &SNACCAnyBuf, status);
        if (status)
            os << "****** SigningCertificate attribute"
               << " FAILED DECODE ******\n";
        else
        {
            os << "SigningCertificate : \n";
            std::strstream TmpStream;
            tmpSnaccSigCert.Print(TmpStream);
            TmpStream << "\n" << '\0';
            os << TmpStream.str();
            TmpStream.rdbuf()->freeze ( 0 );
        }
    }
    else if(*pAttrType == id_aa_timeStampToken) // sib 
    {
        TimeStampToken *pTmpSnaccTST = new TimeStampToken;

        DECODE_BUF_NOFAIL(pTmpSnaccTST, &SNACCAnyBuf, status);
        if (status)
        {
            os << "****** TimeStampToken attribute"
               << " FAILED DECODE ******\n";
        }
        else
        {
            os << "TimeStampToken Attribute: \n";
            std::strstream TmpStream;
                 
            if (pTmpSnaccTST && pTmpSnaccTST->contentType != id_signedData)
            {
               os << "Wrong Content Type for TimeStampToken Encapsulated Content\n";
            }
            else
            {
               if (pTmpSnaccTST)
               {
                  TSTInfo *pSnaccTSTInfo = NULL;
                  CSM_TimeStampToken tmpTST(*pTmpSnaccTST);
                  pSnaccTSTInfo =  tmpTST.GetTimeStampTokenInfo(); 
              
                  if (pSnaccTSTInfo)
                  {
                     VDAStream::setIndent(VDAStream::getIndent()+1);               
                     pSnaccTSTInfo->Print(TmpStream);
                     VDAStream::setIndent(VDAStream::getIndent()-1);

                     delete pSnaccTSTInfo;
                  }
                  else
                     TmpStream << "NO TimeStampTokenInfo data\n";
               }
            }
            TmpStream << "\n" << '\0';
            os << TmpStream.str();
            TmpStream.rdbuf()->freeze ( 0 );
        }
       
        // clean up
        if (pTmpSnaccTST != NULL)
           delete pTmpSnaccTST;
    }
    else
    {
        char *ptr=pAttrType->GetChar();
        os << "GeneralAsnOID=" << ptr << "\n";
        if (ptr)
            free(ptr);
        ReportHexBuffer(os, (char *)SNACCAnyBuf.Access(), SNACCAnyBuf.Length());
    }
    VDAStream::setIndent(VDAStream::getIndent()-1);

    SME_FINISH_CATCH;

} // END OF MEMBER FUNCTION Report

void CSM_Attrib::ReportHexBuffer(std::ostream &os, char *ptr, int iLen)
{
    char buf[100];
    int  i;

    for (i=0; i < iLen; i++)
    {
        sprintf(buf, "%2.2x", (unsigned char)ptr[i]);
        os << buf;
    }
    os << " HEX\n";
} // END OF MEMBER FUNCTION ReportHexBuffer

char *CSM_Attrib::GetGenNameString(CSM_GeneralName &GenName)
{
    char   *ptr=NULL;
    char    buf[1024];
    char   *ptr2;
    CSM_DN *pTmpDn;

    if ((pTmpDn=GenName.GetGenNameDN()) != NULL)
    {
        const char *ptr3 = *pTmpDn;
        sprintf(buf, "DN:%s", ptr3/**pTmpDn*/);
        ptr = strdup(buf);
        delete pTmpDn;
    }
    else if ((ptr2=GenName.GetGenNameRFC822()) != NULL)
    {
        sprintf(buf, "RFC822:%s", ptr2);
        ptr = strdup(buf);
        free(ptr2);
    }
    else if ((ptr2=GenName.GetGenNameDNS()) != NULL)
    {
        sprintf(buf, "DNS:%s", ptr2);
        ptr = strdup(buf);
        free(ptr2);
    }
    else if ((ptr2=GenName.GetGenNameURI()) != NULL)
    {
        sprintf(buf, "URI:%s", ptr2);
        ptr = strdup(buf);
        free(ptr2);
    }
    else
    {
        ptr = strdup("DN NOT SUPPORTED");
    }

    return(ptr);
} // END OF MEMBER FUNCTION GetGenNameString

bool CSM_Attrib::operator == (const CSM_Attrib &that)
{
   bool bResult=false;
   if (this->m_poid && that.m_poid && *this->m_poid == *that.m_poid)
   {
      CSM_Buffer *pBufOurs=NULL;
      CSM_Buffer *pBufThat=NULL;
      this->GetEncodedAttr(pBufOurs);
      ((CSM_Attrib &)that).GetEncodedAttr(pBufThat);
      if (pBufOurs && pBufThat && *pBufOurs == *pBufThat)
         bResult = true;
      delete pBufThat;
      delete pBufOurs;
   }
   
   return(bResult);
}


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

The following paragraph is taken from the draft-ietf-smime-ess-12.txt, dated
March 29, 1999 and is the basis for the attribute functions defined below:
   CheckSignedAttrs
   CheckUnsignedAttrs
   CheckUnprotectedAttrs
   CheckSignedAttr
   CheckUnsignedAttr
   CheckUnprotectedAttr
   CheckCounterSignatureSignedAttrs
   CheckCounterSignatureUnsignedAttrs

1.3.4 Placement of Attributes

Certain attributes should be placed in the inner or outer SignedData
message; some attributes can be in either. Further, some attributes
must be signed, while signing is optional for others, and some
attributes must not be signed. ESS defines several types of attributes.
ContentHints and ContentIdentifier MAY appear in any list of
attributes. contentReference, equivalentLabel, eSSSecurityLabel and
mlExpansionHistory MUST be carried in a SignedAttributes or
AuthAttributes type, and MUST NOT be carried in a UnsignedAttributes,
UnauthAttributes or UnprotectedAttributes type. msgSigDigest,
receiptRequest and signingCertificate MUST be carried in a
SignedAttributes, and MUST NOT be carried in a AuthAttributes,
UnsignedAttributes, UnauthAttributes or UnprotectedAttributes type.

                  |                              |Inner or  |
Attribute         |OID                           |outer     |Signed  |Multiples
------------------|----------------------------- |----------|--------|---------
contentHints      |id-aa-contentHint [ESS]       |either    |MAY     |MUST NOT
contentIdentifier |id-aa-contentIdentifier [ESS] |either    |MAY     |MUST NOT
contentReference  |id-aa-contentReference [ESS]  |either    |MUST    |MUST NOT
contentType       |id-contentType [CMS]          |either    |MUST    |MUST NOT
counterSignature  |id-countersignature [CMS]     |either    |MUST NOT|MAY
equivalentLabel   |id-aa-equivalentLabels [ESS]  |either    |MUST    |MUST NOT
eSSSecurityLabel  |id-aa-securityLabel [ESS]     |either    |MUST    |MUST NOT
messageDigest     |id-messageDigest [CMS]        |either    |MUST    |MUST NOT
msgSigDigest      |id-aa-msgSigDigest [ESS]      |inner only|MUST    |MUST NOT
mlExpansionHistory|id-aa-mlExpandHistory [ESS]   |outer only|MUST    |MUST NOT
receiptRequest    |id-aa-receiptRequest [ESS]    |inner only|MUST    |MUST NOT
signingCertificate|id-aa-signingCertificate [ESS]|either    |MUST    |MUST NOT
signingTime       |id-signingTime [CMS]          |either    |MUST    |MUST NOT
smimeCapabilities |smimeCapabilities [MSG]       |either    |MUST    |MUST NOT
sMIMEEncryption-
  KeyPreference   |id-aa-encrypKeyPref [MSG]     |either    |MUST    |MUST NOT

CMS defines signedAttrs as a SET OF Attribute and defines unsignedAttrs
as a SET OF Attribute. ESS defines the contentHints, contentIdentifier,
eSSecurityLabel, msgSigDigest, mlExpansionHistory, receiptRequest,
contentReference, equivalentLabels and signingCertificate attribute
types. A signerInfo MUST NOT include multiple instances of any of the
attribute types defined in ESS. Later sections of ESS specify further
restrictions that apply to the receiptRequest, mlExpansionHistory and
eSSecurityLabel attribute types.

 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
*/

// CSM_Attrib::CheckSignedAttr
//   INPUT:  NONE
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function checks to see if the attribute value of the current
//   CSM_Attrib object is a valid Signed attribute and then returns true
//   if it is or false if it is not.  OF the 15 currently defined
//   attributes only id_countersignature CANNOT be a signed attribute.
//   Any unrecognized attribute will be allowed to be signed.
//
bool CSM_Attrib::CheckSignedAttr()
{
    bool bSigned=true;       // DEFAULT TO TRUE

    // If this is a countersignature set return value to FALSE
    // Otherwise set it to TRUE
    if (m_poid && *m_poid == id_countersignature)
        bSigned = false;

    return(bSigned);         // TRUE OR FALSE
} // END OF CheckSignedAttr


// CSM_Attrib::CheckSigningTime
//   INPUT:  NONE
//   OUTPUT: NONE
//  
//   RETURN:  0 if valid century and type
//           -1 if error for time - time isn't convertable report
//            1 if invalid century or invalid time type
//              but can be converted from generalized to utc time
//    Dates between 1 January 1950 and 
//    31 December 2049 (inclusive) must be  encoded as UTCTime.  
//    Any dates with year values before 1950 or after
//    2049 must be encoded as GeneralizedTime.

//     Where YY is greater than or equal to 50, the year shall be
//   interpreted as 19YY; and
//   Where YY is less than 50, the year shall be interpreted as 20YY.
//
int CSM_Attrib::CheckSigningTime()
{

   int bValid = 1;       // DEFAULT TO invalid

   // check for valid data
   if ((m_pSigningTime->m_type == SigningTime::generalizedTimeCid ||
        m_pSigningTime->m_type == SigningTime::utcTimeCid) &&
       (m_pSigningTime->m_lpszTime != NULL) )
       
   { 
       //  if dates before 1950 and after 2049 gen time
       if ( m_pSigningTime->m_type == SigningTime::generalizedTimeCid && m_pSigningTime->m_lpszTime)
       {
           // dates before 1950 and after 2049 represented YYYY
           // copy first 4 numbers
           char century[5];
           strncpy(century, m_pSigningTime->m_lpszTime, 4);
           century[4] = '\0';

           if ( isdigit(century[0]) &&
                isdigit(century[1]) &&
                isdigit(century[2]) &&
                isdigit(century[3]) )
           {
               // checking the length for correctness, and
               // checking for a Z in last position
               // calling it valid

               int len = strlen(m_pSigningTime->m_lpszTime);

               if (len != 15)   // YYMMDD000000Z
               {
                   bValid = -1;
               }
               else if ((strncmp(&m_pSigningTime->m_lpszTime[len -1], "Z", 1) != 0) && 
                   (strncmp(&m_pSigningTime->m_lpszTime[len -1], "z", 1) != 0) )
               {
                  bValid = -1;
               }

               // check the year
               int year = atoi(century);
               if (bValid && (year >= 0) && (year < 1950) || (year > 2049))
               {
                   bValid = 0;
               }
           }
           else
           {
               bValid = -1;    // real error, time can't be converted
           }

       }
       else if ( m_pSigningTime->m_type == SigningTime::utcTimeCid && m_pSigningTime->m_lpszTime)
       {
           // dates on or after 1950 and on or before 2049 represented YY
           // copy first 2 numbers
           char century[3];
           strncpy(century, m_pSigningTime->m_lpszTime, 2);
           century[2] = '\0';
           if (isdigit(century[0]) && isdigit(century[1]))
           {
               // too difficult to check for correct utc time
               //  have to rely on user to be correct with this data
               // just making sure first 2 numbers are digits,
               // checking the length for correctness, and
               // checking for a Z in last position
               // calling it valid
               bValid = 0;

               int len = strlen(m_pSigningTime->m_lpszTime);

               if (len != 13)   // YYMMDD000000Z
               {
                   bValid = -1;
               }
               else if ((strncmp(&m_pSigningTime->m_lpszTime[len -1], "Z", 1) != 0) && 
                   (strncmp(&m_pSigningTime->m_lpszTime[len -1], "z", 1) != 0) )
               {
                  bValid = -1;
               }

           }
           else
           {
               bValid = -1;   // real error, time can't be converted
           }
       }
   }
   else
   {
       bValid = -1;  // real error, time can't be converted
   }

   return bValid;

}


// CSM_Attrib::CheckUnsignedAttr
//   INPUT:  NONE
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function checks to see if the attribute value of the current
//   CSM_Attrib object is a valid Unsigned attribute and then returns
//   true if it is or false if it is not.  OF the 15 currently defined
//   attributes only id_aa_contentHint, id_aa_contentIdentifier, id_aa_timeStampToken
//   and id_countersignature can be unsigned attributes.  Any unrecognized
//   attribute will be allowed to be unsigned.
//
bool CSM_Attrib::CheckUnsignedAttr()
{
    bool bUnsigned=true;     // DEFAULT RESULTS TO TRUE

    // SET THE FLAG TO FALSE IF ATTRIBUTE MATCHES ANY KNOWN EXCEPT
    //   id_aa_contentHint, id_aa_contentIdentifier, id_countersignature
    //   which are the only VALID Unsigned attributes

    if (m_poid == NULL)
       return false;
    bUnsigned = !(*m_poid == id_aa_contentReference);
    if (bUnsigned)
    {
        // NOTE bSigned is set to FALSE if it is contentType otherwise TRUE.
        // And if it is TRUE we need to check for another known OID . . .

        bUnsigned = !(*m_poid == id_contentType);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_aa_equivalentLabels);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_aa_securityLabel);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_messageDigest);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_aa_msgSigDigest);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_aa_mlExpandHistory);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_aa_receiptRequest);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_aa_signingCertificate);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_signingTime);
        if (bUnsigned)
            bUnsigned = !(*m_poid == smimeCapabilities);
        if (bUnsigned)
            bUnsigned = !(*m_poid == id_aa_encrypKeyPref);
    }

    return(bUnsigned);
} // END OF CheckUnsignedAttr

// CSM_Attrib::CheckUnprotectedAttr
//   INPUT:  NONE
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function checks to see if the attribute value of the current
//   CSM_Attrib object is a valid Unprotected attribute and then returns
//   true if it is or false if it is not.  OF the 15 currently defined
//   attributes only contentReference, equivalentLabel, eSSSecurityLabel,
//   mlExpansionHistory, msgSigDigest, receiptRequest, signingCertificate
//   can be Unprotected attributes.
//
//   This means that the following attributes are VALID Unprotected
//   attributes: ContentHints, ContentIdentifier, contentType,
//   counterSignature, msgDigest, signingTime, smimeCapabilities,
//   sMIMEEncryptionKeyPreference.
//
//   Any unrecognized attribute will be allowed to be unprotected.
//

    // SET THE FLAG TO FALSE IF ATTRIBUTE MATCHES ANY KNOWN EXCEPT
    //   id_aa_contentHint, id_aa_contentIdentifier
// TBD . . .
// SPOKE TO JOHN 6/4 AND WE REVIEWED EACH OF THE 15 ATTRIBUTES.  OTHER THAN
// THE SEVEN ATTRIBUTES EXPLICICTLY PROSCRIBED FROM BEING UNPROTECTED
// (contentReference, equivalentLabel, eSSSecurityLabel, mlExpansionHistory,
// msgSigDigest, receiptRequest and signingCertificate) JOHN BELIEVES THAT
// MOST OF THE REMAINING ATTRIBUTES SHOULD ALSO NOT BE UNPROTECTED.  THE ONLY
// EXCEPTIONS ARE ContentHints and ContentIdentifier.  HE WILL CHECK OF THIS
// AND LET ME KNOW
bool CSM_Attrib::CheckUnprotectedAttr()
{
    bool bUnprotected=true;     // DEFAULT RESULTS TO TRUE

    // SET THE FLAG TO FALSE IF ATTRIBUTE IS contentReference,
    // equivalentLabel, eSSSecurityLabel, mlExpansionHistory, msgSigDigest,
    // receiptRequest,  or signingCertificate

    if (m_poid == NULL)
       return false;
    bUnprotected = !(*m_poid == id_aa_contentReference);
    if (bUnprotected)
    {
        // NOTE bSigned is set to FALSE if it is contentType otherwise TRUE.
        // And if it is TRUE we need to check for another known OID . . .

        bUnprotected = !(*m_poid == id_contentType);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_countersignature);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_aa_equivalentLabels);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_aa_securityLabel);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_messageDigest);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_aa_msgSigDigest);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_aa_mlExpandHistory);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_aa_receiptRequest);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_aa_signingCertificate);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_signingTime);
        if (bUnprotected)
            bUnprotected = !(*m_poid == smimeCapabilities);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_aa_encrypKeyPref);
        if (bUnprotected)
            bUnprotected = !(*m_poid == id_aa_timeStampToken);
    }

    return(bUnprotected);
} // END OF CheckUnprotectedAttr

// CSM_Attrib::CheckCounterSignatureSignedAttr
//   INPUT:  NONE
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function checks to see if the attribute value of the current
//   CSM_Attrib object is a valid Signed attribute for a counterSignature
//   SignerInfo and then returns true if it is or false if it is not.  OF
//   the 15 currently defined attributes only id_aa_messageDigest,
//   id-signingTime or id-aa-signingCertificate are valid Signed attributes
//   for a counterSignature SignerInfo.  Any unrecognized attribute will
//   be allowed to be a counter signature signed attribute.
//
bool CSM_Attrib::CheckCounterSignatureSignedAttr()
{
    bool bCSSigned=true;     // DEFAULT TO TRUE

    // SET THE FLAG TO FALSE IF ATTRIBUTE MATCHES ANY KNOWN EXCEPT
    //   id_aa_messageDigest, id-signingTime or id-aa-signingCertificate
    //   which are the only VALID Signed attributes for a counterSignature
    //   SignerInfo

    if (m_poid == NULL)
       return false;
    bCSSigned = !(*m_poid == id_aa_contentHint);
    if (bCSSigned)
    {
        // NOTE bCSSigned is set to FALSE if it is contentType otherwise TRUE.
        // And if it is TRUE we need to check for another known OID . . .

        bCSSigned = !(*m_poid == id_aa_contentIdentifier);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_aa_contentReference);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_contentType);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_aa_equivalentLabels);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_aa_securityLabel);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_aa_msgSigDigest);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_aa_mlExpandHistory);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_aa_receiptRequest);
        if (bCSSigned)
            bCSSigned = !(*m_poid == smimeCapabilities);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_aa_encrypKeyPref);
        if (bCSSigned)
            bCSSigned = !(*m_poid == id_aa_timeStampToken);
    }

    return(bCSSigned);       // TRUE OR FALSE
} // END OF CheckCounterSignatureSignedAttr

// CSM_Attrib::CheckCounterSignatureUnsignedAttr
//   INPUT:  NONE
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function checks to see if the attribute value of the current
//   CSM_Attrib object is a valid Unsigned attribute for a counterSignature
//   SignerInfo and then returns true if it is or false if it is not.  OF
//   the 15 currently defined attributes id_aa_countersignature,
//   id_aa_contentHint, id_aa_contentIdentifier are the only valid Unsigned
//   attributes for a counterSignature SignerInfo. Any unrecognized attribute
//   will be allowed to be a counter signature unsigned attribute.
//
bool CSM_Attrib::CheckCounterSignatureUnsignedAttr()
{
    bool bCSUnsigned=true;     // DEFAULT TO TRUE

    // CAREFUL:  The GCC 2.7.2 compiler on SUN 4.1.3 gives an internal
    //    compiler error if the AsnOid /AsnOid compares are all on a single
    //    line.

    // If this is a countersignature set return value to TRUE
    // Otherwise set it to FALSE

    if (m_poid == NULL)
       return false;
    bCSUnsigned = (*m_poid == id_countersignature);
    if (!bCSUnsigned)
    {
        bCSUnsigned = (*m_poid == id_aa_contentHint);
        if (!bCSUnsigned)
            bCSUnsigned = (*m_poid == id_aa_contentIdentifier);
    }

    // If it is set to FALSE check each known attribute OID.  If it is
    // not known the this logic will set the return value back to true
    if (!bCSUnsigned)
    {
        // NOTE bCSUnsigned is set to FALSE if it is contentType otherwise TRUE.
        // And if it is TRUE we need to check for another known OID . . .

        bCSUnsigned = !(*m_poid == id_aa_contentReference);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_contentType);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_aa_equivalentLabels);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_aa_securityLabel);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_messageDigest);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_aa_msgSigDigest);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_aa_mlExpandHistory);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_aa_receiptRequest);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_aa_signingCertificate);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_signingTime);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == smimeCapabilities);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_aa_encrypKeyPref);
        if (bCSUnsigned)
            bCSUnsigned = !(*m_poid == id_aa_timeStampToken);
    }

    return(bCSUnsigned);       // TRUE OR FALSE
} // END OF MEMBER FUNCTION CheckCounterSignatureUnsignedAttr

// END OF CSM_Attrib FUNCTION DEFINITIONS

// BEGIN CSM_MsgAttributes FUNCTION DEFINITIONS

// Constructor
//
CSM_MsgAttributes::CSM_MsgAttributes()
{
    m_pAttrs=NULL;
    m_pEncodedAttrs=NULL;
    m_pCurrentCS=NULL;
    m_lAttributeIndex=0;
    m_pEncodedAttrsFromMessage = NULL;
} // END OF CSM_MsgAttributes DEFAULT CONSTRUCTOR

// Constructor using SignedAttributes
//
CSM_MsgAttributes::CSM_MsgAttributes(SignedAttributes
                                     &SNACCSignedAttributes)
{
    SignedAttributes::iterator TmpSNACCSignedAttr;
    long        lMultiAttrIndex=0;

    m_pAttrs=NULL;
    m_pEncodedAttrs=NULL;
    m_pCurrentCS=NULL;
    m_lAttributeIndex=0;
    m_pEncodedAttrsFromMessage = NULL;

    // Loop through current SNACC Signed Attributes list
    for(lMultiAttrIndex=0, TmpSNACCSignedAttr =  SNACCSignedAttributes.begin();
        TmpSNACCSignedAttr != SNACCSignedAttributes.end();
        lMultiAttrIndex++, ++TmpSNACCSignedAttr)
    {
        // Load this SNACC Attribute into a CSM_Attrib/CSM_AttribLst.
        ExtractSNACCAttr(*TmpSNACCSignedAttr, lMultiAttrIndex);
    }
} // END OF MEMBER FUNCTION constructor

// Constructor using UnsignedAttributes
//
CSM_MsgAttributes::CSM_MsgAttributes(UnsignedAttributes
                                      &SNACCUnsignedAttributes)
{
    SignedAttributes::iterator TmpSNACCUnsignedAttr;
    long        lMultiAttrIndex=0;

    m_pAttrs=NULL;
    m_pEncodedAttrs=NULL;
    m_pCurrentCS=NULL;
    m_lAttributeIndex=0;
    m_pEncodedAttrsFromMessage = NULL;

    // Loop through current SNACC Unsigned Attributes list
    for(lMultiAttrIndex=0, TmpSNACCUnsignedAttr = SNACCUnsignedAttributes.begin();
        TmpSNACCUnsignedAttr != SNACCUnsignedAttributes.end();
        lMultiAttrIndex++, ++TmpSNACCUnsignedAttr)
    {
        // Load this SNACC Attribute into a CSM_Attrib/CSM_AttribLst.
        ExtractSNACCAttr(*TmpSNACCUnsignedAttr, lMultiAttrIndex);
    }

} // END OF CSM_MsgAttributes  CONSTRUCTOR


// DESTRUCTOR FOR CSM_MsgAttributes
//
CSM_MsgAttributes::~CSM_MsgAttributes()
{
    if (m_pAttrs)
        delete m_pAttrs;
    if (m_pEncodedAttrs)
        delete m_pEncodedAttrs;
    if (m_pEncodedAttrsFromMessage)
       delete m_pEncodedAttrsFromMessage;
} // END OF CSM_MsgAttributes DESTRUCTOR

// GetContentIdentifier:
//
CSM_Buffer *CSM_MsgAttributes::GetContentIdentifier()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_Buffer *pContentIdentifier = NULL;

    for(itTmpAttrib =  m_pAttrs->begin();
        itTmpAttrib != m_pAttrs->end() && !pContentIdentifier;
        ++itTmpAttrib)
    {
        if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_contentIdentifier))
            pContentIdentifier =
                new CSM_Buffer(*itTmpAttrib->m_pContentIdentifier);
    }
    return(pContentIdentifier);
} // END OF MEMBER FUNCTION GetContentIdentifier

// GetMessageDigest:
//
CSM_Buffer *CSM_MsgAttributes::GetMessageDigest()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_Buffer *pMessageDigest = NULL;

    for(itTmpAttrib =  m_pAttrs->begin();
        itTmpAttrib != m_pAttrs->end() && !pMessageDigest; 
        ++itTmpAttrib)
    {
        if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_messageDigest))
            pMessageDigest = new CSM_Buffer(*itTmpAttrib->m_pMessageDigest);
    }
    return(pMessageDigest);
} // END OF MEMBER FUNCTION GetMessageDigest

// GetTimeStampToken:
// Use this method to get the TimeStampToken from the list of 
// attributes
TimeStampToken *CSM_MsgAttributes::GetTimeStampToken()
{
    CSM_AttribLst::iterator itTmpAttrib;
    ContentInfo *pTimeStampToken = NULL;
    if (m_pAttrs)
       for(itTmpAttrib =  m_pAttrs->begin();
        itTmpAttrib != m_pAttrs->end() && !pTimeStampToken; 
        ++itTmpAttrib)
		{
           if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_timeStampToken))
               pTimeStampToken = new TimeStampToken(*itTmpAttrib->m_pTimeStampToken);
		}
    return(pTimeStampToken);
} // END OF MEMBER FUNCTION GetTimeStampToken

// GetMsgSigDigest:
// use this method to get the message sig digest (see ESS) from the list
// of attributes
CSM_Buffer *CSM_MsgAttributes::GetMsgSigDigest()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_Buffer *pMessageDigest = NULL;

    SME_SETUP("CSM_MsgAttributes::GetMsgSigDigest");

    for(itTmpAttrib =  m_pAttrs->begin();
        itTmpAttrib != m_pAttrs->end() && !pMessageDigest;
        ++itTmpAttrib)
    {
        if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_msgSigDigest))
            if ((pMessageDigest = new CSM_Buffer(
                *itTmpAttrib->m_pMessageDigest)) == NULL)
                SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
    }

    SME_FINISH_CATCH

    return(pMessageDigest);
} // END OF MEMBER FUNCTION GetMsgSigDigest

// GetSigningTime:
//
CSM_Time *CSM_MsgAttributes::GetSigningTime()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_Time   *pSigningTime = NULL;

    if(m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
            itTmpAttrib != m_pAttrs->end() && pSigningTime == NULL;
            ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_signingTime))
                pSigningTime = new CSM_Time(*itTmpAttrib->m_pSigningTime);
                // Make copy.
        }
    }
    return(pSigningTime);
} // END OF MEMBER FUNCTION GetSigningTime

// GetCounterSignature:
//
Countersignature *CSM_MsgAttributes::GetCounterSignature()
{
    CSM_AttribLst::iterator itTmpAttrib;
    Countersignature *pSNACCCounterSignature = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pSNACCCounterSignature == NULL;
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_countersignature))
                pSNACCCounterSignature = new Countersignature(*itTmpAttrib->
                    m_pSNACCCounterSignature);
        }
    }
    return(pSNACCCounterSignature);
} // END OF MEMBER FUNCTION GetCounterSignature

// GetReceiptRequest:
//
CSM_ReceiptRequest *CSM_MsgAttributes::GetReceiptRequest()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_ReceiptRequest *pReceiptRequest = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pReceiptRequest == NULL;
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid  && *itTmpAttrib->m_poid == id_aa_receiptRequest)
                pReceiptRequest =
                    new CSM_ReceiptRequest(*itTmpAttrib->m_pReceiptRequest);
        }
    }
    return(pReceiptRequest);
} // END OF MEMBER FUNCTION GetReceiptRequest

// GetContentHints:
//
SNACC::ContentHints *CSM_MsgAttributes::GetContentHints()
{
    CSM_AttribLst::iterator itTmpAttrib;
    SNACC::ContentHints *pContentHints = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pContentHints == NULL;
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_contentHint))
            {
                pContentHints = new SNACC::ContentHints;
                *pContentHints = (*itTmpAttrib->m_pContentHints);
            }       // END if contentHint OID
        }           // END for each attr in list
    }               // END if m_pAttrs present.
    return(pContentHints);
} // END OF MEMBER FUNCTION GetContentHints

// GetContentReference:
//
CSM_ContentReference *CSM_MsgAttributes::GetContentReference()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_ContentReference *pContentReference = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pContentReference == NULL;
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_contentReference))
                pContentReference =
                    new CSM_ContentReference(*itTmpAttrib->m_pContentReference);
        }
    }
    return(pContentReference);
} // END OF MEMBER FUNCTION GetContentReference

// GetSecurityLabel:
//
CSM_SecLbl *CSM_MsgAttributes::GetSecurityLabel()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_SecLbl *pSecurityLabel = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pSecurityLabel == NULL;
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_securityLabel))
                pSecurityLabel = new CSM_SecLbl(*itTmpAttrib->m_pSecurityLabel);
        }
    }
    return(pSecurityLabel);
} // END OF MEMBER FUNCTION GetSecurityLabel

// GetSigningCertificate:
//
CSM_SigningCertificate *CSM_MsgAttributes::GetSigningCertificate()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_SigningCertificate *pSigningCertificate = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pSigningCertificate == NULL;
             ++itTmpAttrib)
        {
            if (itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_signingCertificate))
                pSigningCertificate =
                    new CSM_SigningCertificate(*itTmpAttrib->m_pSigningCertificate);
        }
    }
    return(pSigningCertificate);
} // END OF MEMBER FUNCTION GetSigningCertificate

// GetEquivalentLabels:
//
CSM_EquivalentLabels *CSM_MsgAttributes::GetEquivalentLabels()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_EquivalentLabels *pEqulbls = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pEqulbls == NULL; 
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_equivalentLabels))
                pEqulbls = new CSM_EquivalentLabels(*itTmpAttrib->m_pEqulbls);
        }
    }
    return(pEqulbls);
} // END OF MEMBER FUNCTION GetEquivalentLabels

// GetSmimeCapabilityLst:
//
CSM_SmimeCapabilityLst *CSM_MsgAttributes::GetSmimeCapabilityLst()
{
    CSM_AttribLst::iterator itTmpAttrib;
    CSM_SmimeCapabilityLst *pSmimeCapLst = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pSmimeCapLst == NULL; 
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == smimeCapabilities))
                pSmimeCapLst =
                    new CSM_SmimeCapabilityLst(*itTmpAttrib->m_pSmimeCapLst);
        }
    }
    return(pSmimeCapLst);
} // END OF MEMBER FUNCTION GetSmimeCapabilityLst

SMIMEEncryptionKeyPreference *CSM_MsgAttributes::
    GetSMIMEEncryptionKeyPreference()
{
    CSM_AttribLst::iterator itTmpAttrib;
    SMIMEEncryptionKeyPreference *pSEK= NULL;

    SME_SETUP("CSM_MsgAttributes::GetSMIMEEncryptionKeyPreference");
    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pSEK == NULL; 
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_encrypKeyPref))
            {
                pSEK = new SMIMEEncryptionKeyPreference;
                DECODE_BUF(pSEK, itTmpAttrib->m_pEncodedAttrib);
            }

        }
    }
    SME_FINISH_CATCH
    return(pSEK);
} // END OF MEMBER FUNCTION GetSMIMEEncryptionKeyPreference

// GetMailList:
//
MLExpansionHistory *CSM_MsgAttributes::GetMailList()
{
    CSM_AttribLst::iterator itTmpAttrib;
    MLExpansionHistory *pMlExpHist=NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pMlExpHist == NULL; 
             ++itTmpAttrib)
        {
            if (itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_aa_mlExpandHistory))
            {
                pMlExpHist = new MLExpansionHistory;
                *pMlExpHist = *(itTmpAttrib->m_pSNACCMlExpHist);
            }
        }
    }
    return(pMlExpHist);
} // END OF MEMBER FUNCTION GetMailList

// GetContentType:
//
AsnOid  *CSM_MsgAttributes::GetContentType()
{
    CSM_AttribLst::iterator itTmpAttrib;
    AsnOid     *pContentType = NULL;

    if (m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && pContentType == NULL; 
             ++itTmpAttrib )
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_contentType))
                pContentType = new AsnOid (*itTmpAttrib->m_pContentType);
        }
    }
    return(pContentType);
} // END OF MEMBER FUNCTION GetContentType

// IsAllowedMultipleAttribs:
//   INPUT:  AttribOID
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function is passed an AttribOID, which it will compare with
//   each attribute OID currently defined.  If it is one of the ones
//   other than the countersignature attribute OID this function will
//   return FALSE. For the countersignature attribute OID and any other
//   which is not defined this function will return TRUE.
//   The countersignature attribute is the only one of the 15 defined
//   attributes which is specified as allowing multiples.
bool CSM_MsgAttributes::IsAllowedMultipleAttribs(AsnOid  &AttribOID)
{
    bool bmultiple=true;     // DEFAULT TO TRUE

    // CAREFUL:  The GCC 2.7.2 compiler on SUN 4.1.3 gives an internal
    //    compiler error if the AsnOid /AsnOid compares are all on a single
    //    line.

    // If this is a countersignature set return value to TRUE
    // Otherwise set it to FALSE
    bmultiple = (AttribOID == id_countersignature);

    // If it is set to FALSE check each known attribute OID.  If it is
    // not known the this logic will set the return value back to true
    if (!bmultiple)
    {
        // NOTE bmultiple is set to FALSE if it is contentType otherwise TRUE.
        // And if it is TRUE we need to check for another known OID . . .
        bmultiple = !(AttribOID == id_contentType);
        if (bmultiple)
            bmultiple = !(AttribOID == id_messageDigest);
        if (bmultiple)
            bmultiple = !(AttribOID == id_signingTime);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_receiptRequest);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_contentIdentifier);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_contentHint);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_contentReference);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_securityLabel);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_mlExpandHistory);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_equivalentLabels);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_msgSigDigest);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_signingCertificate);
        if (bmultiple)
            bmultiple = !(AttribOID == smimeCapabilities);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_encrypKeyPref);
        if (bmultiple)
            bmultiple = !(AttribOID == id_aa_timeStampToken);

    }

    return(bmultiple);       // TRUE OR FALSE
} // END OF MEMBER FUNCTION IsAllowedMultipleAttribs

// FindAttrib:
//
CSM_AttribLst::iterator *CSM_MsgAttributes::FindAttrib(const AsnOid  &coid)
{
    CSM_AttribLst::iterator *pitTmpAttrib=new CSM_AttribLst::iterator;

    SME_SETUP("CSM_MsgAttributes::FindAttrib");

    if(m_pAttrs)
    {
        for (*pitTmpAttrib =  m_pAttrs->begin();
             *pitTmpAttrib != m_pAttrs->end(); 
             ++*pitTmpAttrib)
        {
            if((*pitTmpAttrib)->m_poid  && (*(*pitTmpAttrib)->m_poid == coid))
            {
                break;
            }
        }
    }

    SME_FINISH_CATCH

    return pitTmpAttrib;
} // END OF MEMBER FUNCTION FindAttrib

// AddAttrib:
//
void CSM_MsgAttributes::AddAttrib(CSM_Attrib &Attrib)
{
    CSM_AttribLst::iterator itTmpAttrib;
    bool        found=false;

    SME_SETUP("CSM_MsgAttributes::AddAttrib");

    if(CSM_MsgAttributes::m_pAttrs)
    {
        for (itTmpAttrib =  m_pAttrs->begin();
             itTmpAttrib != m_pAttrs->end() && found; 
             ++itTmpAttrib)
        {
            if(itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == *Attrib.m_poid))
                found = true;
        }
    }

    // ERROR, can have only 1 attribute (in most cases).
    if (found && !IsAllowedMultipleAttribs(*Attrib.m_poid))
    {
        char buf[200];
        char *ptr=Attrib.m_poid->GetChar();

        sprintf(buf, "AddAttrib:  CAN Have only a single attribute,OID=%s.\n",
            ptr);
        if (ptr)
            free(ptr);

        SME_THROW(SM_DUPLICATE_ATTRIBS, buf, NULL);
    }
    else
    {
        if (m_pEncodedAttrs)
        {
            delete m_pEncodedAttrs;
            m_pEncodedAttrs = NULL;
        }

        if (m_pAttrs == NULL)
            // create list if first time
            m_pAttrs = new CSM_AttribLst;
        m_pAttrs->append(Attrib);   //... NORMAL PROCESSING...
    }

    SME_FINISH_CATCH
} // END OF MEMBER FUNCTION AddAttrib

// UnLoadSNACCSignedAttrs:
//   INPUT: SignedAttributes &SNACCUnprotectedAttributes
//   OUTPUT: None
//   RETURN: None
//   Loop through each Attribute in the current list of SNACC Signed
//   Attributes and load it into a CSM_Attrib and then into a CSM_AttribLst.
//   Set the CSM_Attrib::m_lAttrValueIndex to the number of Attribute Values
//   for each SNACC Signed Attribute (returned from LoadCSMAttrs).
//
void CSM_MsgAttributes::UnLoadSNACCSignedAttrs(SignedAttributes
                                               &SNACCSignedAttributes)
{
    SignedAttributes::iterator TmpSNACCSignedAttr;
    long        lMultiAttrIndex=0;

    // INITIALIZE CURRENT ENCODED ATTRIBUTE BUFFER
    if(m_pEncodedAttrs)
    {
        free(m_pEncodedAttrs);
        m_pEncodedAttrs= NULL;
    }

    // INITIALIZE CURRENT ATTRIBUTE LIST
    if(m_pAttrs)
    {
        delete m_pAttrs;
        m_pAttrs = NULL;
    }

    // Loop through current SNACC Signed Attributes list
    for(lMultiAttrIndex=0, TmpSNACCSignedAttr = SNACCSignedAttributes.begin();
        TmpSNACCSignedAttr != SNACCSignedAttributes.end();
        lMultiAttrIndex++, ++TmpSNACCSignedAttr)
    {
        // Load this SNACC Attribute into a CSM_Attrib/CSM_AttribLst.
        ExtractSNACCAttr(*TmpSNACCSignedAttr, lMultiAttrIndex);
    }
} // END OF MEMBER FUNCTION UnLoadSNACCSignedAttrs

// UnLoadSNACCUnsignedAttrs:
//   INPUT: UnsignedAttributes &SNACCUnprotectedAttributes
//   OUTPUT: None
//   RETURN: None
//   Loop through each Attribute in the current list of SNACC Unsigned
//   Attributes and load it into a CSM_Attrib and then into a CSM_AttribLst.
//   Set the CSM_Attrib::m_lAttrValueIndex to the number of Attribute Values
//   for each SNACC Unsigned Attribute (returned from LoadCSMAttrs).
//
//
void CSM_MsgAttributes::UnLoadSNACCUnsignedAttrs(UnsignedAttributes
                                                 &SNACCUnsignedAttributes)
{
    SignedAttributes::iterator TmpSNACCUnsignedAttr;
    long        lMultiAttrIndex=0;

    // INITIALIZE CURRENT ENCODED ATTRIBUTE BUFFER
    if(m_pEncodedAttrs)
    {
        free(m_pEncodedAttrs);
        m_pEncodedAttrs = NULL;
    }

    // INITIALIZE CURRENT ATTRIBUTE LIST
    if(m_pAttrs)
    {
        delete m_pAttrs;
        m_pAttrs = NULL;
    }

    // Loop through current SNACC Unsigned Attributes list
    for(lMultiAttrIndex=0, TmpSNACCUnsignedAttr = SNACCUnsignedAttributes.begin();
        TmpSNACCUnsignedAttr != SNACCUnsignedAttributes.end();
        lMultiAttrIndex++, ++TmpSNACCUnsignedAttr)
    {
        // Load this SNACC Attribute into a CSM_Attrib/CSM_AttribLst.
        ExtractSNACCAttr(*TmpSNACCUnsignedAttr, lMultiAttrIndex);
    }
} // END OF MEMBER FUNCTION UnLoadSNACCUnsignedAttrs

// UnLoadSNACCUnprotectedAttrs:
//   INPUT: UnprotectedAttributes &SNACCUnprotectedAttributes
//   OUTPUT: None
//   RETURN: None
//   Loop through each Attribute in the current list of SNACC Unprotected
//   Attributes and load it into a CSM_Attrib and then into a CSM_AttribLst.
//   Set the CSM_Attrib::m_lAttrValueIndex to the number of Attribute Values
//   for each SNACC Unprotected Attribute (returned from LoadCSMAttrs).
//
void CSM_MsgAttributes::
    UnLoadSNACCUnprotectedAttrs(UnprotectedAttributes
                                &SNACCUnprotectedAttributes)
{
    SignedAttributes::iterator TmpSNACCUnprotectedAttr;
    long        lMultiAttrIndex=0;

    // INITIALIZE CURRENT ENCODED ATTRIBUTE BUFFER
    if(m_pEncodedAttrs)
    {
        free(m_pEncodedAttrs);
        m_pEncodedAttrs= NULL;
    }

    // INITIALIZE CURRENT ATTRIBUTE LIST
    if(m_pAttrs)
    {
        delete m_pAttrs;
        m_pAttrs = NULL;
    }

    // Loop through current SNACC Unprotected Attributes list
    for(lMultiAttrIndex=0, TmpSNACCUnprotectedAttr = SNACCUnprotectedAttributes.begin();
        TmpSNACCUnprotectedAttr != SNACCUnprotectedAttributes.end();
        lMultiAttrIndex++, ++TmpSNACCUnprotectedAttr)
    {
        // Extract the value(s) of this SNACC Attribute into a
        // CSM_Attrib/CSM_AttribLst and set the CSM_Attrib member variable
        // m_lAttrValueIndex to the number of values extracted
        ExtractSNACCAttr(*TmpSNACCUnprotectedAttr, lMultiAttrIndex);
    }
} // END OF MEMBER FUNCTION UnLoadSNACCUnprotectedAttrs

// ExtractSNACCAttrs:
//   INPUT: Attribute1 *pSNACCAttr
//   OUTPUT: None
//   RETURN: None
//   Loop through all the values of the passed SNACC Attribute.  Currently
//   CounterSignature is the only attribute defined which can have multiple
//   values.  What this function is doing is extracting multi-values and
//   loading them as single value entries in the current CSM_MsgAttribute
//   list.  The depth of these multi-value attributes is tracked in the
//   CSM_Attrib::m_lAttrValueIndex member variable (assigned near the end
//   of this function).  It is expected that most attributes will have a
//   m_lAttrValueIndex value of 1.
//
void CSM_MsgAttributes::ExtractSNACCAttr(Attribute &SNACCAttr,
                                         long lMultiAttrIndex)
{
    AttributeSetOf::iterator TmpSNACCAttr;
    long             lAttrValueIndex=0;
    CSM_Attrib      *pTmpCSMAttr;
    AsnOid          *pOid;
    CSM_Buffer      *pTmpBuf=NULL;

    SME_SETUP("CSM_MsgAttributes::ExtractSNACCAttrs(Attribute &SNACCAttr)");

    // Loop through all the values of this attribute (most attributes will
    // have only one value).
    for(lAttrValueIndex=0, TmpSNACCAttr = SNACCAttr.values.begin(); 
        TmpSNACCAttr != SNACCAttr.values.end();
        lAttrValueIndex++, ++TmpSNACCAttr)
    {
        pOid = new AsnOid (SNACCAttr.type);

        AsnAny &TmpAny = *TmpSNACCAttr;
        SM_EXTRACT_ANYBUF(pTmpBuf, &TmpAny);

        if(m_pAttrs == NULL)
            m_pAttrs = new CSM_AttribLst;
        pTmpCSMAttr = &(*m_pAttrs->append());
        pTmpCSMAttr->SetAttribByOid(*pOid, *pTmpBuf);

        // DO NOT DELETE pTmpCSMAttr!!!

        // Set the values of the CSM_Attrib::m_lMultiAttrIndex and
        // CSM_Attrib::m_lAttrValueIndex member variable to the value of the
        // loop counters (m_lMultiAttrIndex is the outer loop - count of this
        // attribute in the SNACC list; m_lAttrValueIndex is the inner loop -
        // count of values in each SNACC attribute - of recognized attributes
        // only CounterSignature attributes may be multi-value.
        pTmpCSMAttr->m_lAttrValueIndex = lAttrValueIndex;
        pTmpCSMAttr->m_lMultiAttrIndex = lMultiAttrIndex;

        delete pOid;
        if (pTmpBuf)
           delete pTmpBuf;
        pTmpBuf = NULL;
        }

    SME_FINISH
    SME_CATCH_SETUP
    // local cleanup logic
    SME_CATCH_FINISH
} // END OF MEMBER FUNCTION ExtractSNACCAttr

// GetSignedEncodedAttrs:
//
CSM_Buffer *CSM_MsgAttributes::GetSignedEncodedAttrs()
{
    SignedAttributes *pSNACCSignedAttributes;
    SME_SETUP("CSM_MsgAttributes::GetSignedEncodedAttrs");

    if(m_pEncodedAttrs == NULL)
    {
        if((pSNACCSignedAttributes=GetSNACCSignedAttributes()) != NULL)
            ENCODE_BUF(pSNACCSignedAttributes, m_pEncodedAttrs);
    }

    SME_FINISH_CATCH

    return(m_pEncodedAttrs);
} // END OF MEMBER FUNCTION GetSignedEncodedAttrs

// GetUnsignedEncodedAttrs:
//
CSM_Buffer *CSM_MsgAttributes::GetUnsignedEncodedAttrs()
{
    UnsignedAttributes *pSNACCUnsignedAttributes;
    SME_SETUP("CSM_MsgAttributes::GetUnsignedEncodedAttrs");

    if(m_pEncodedAttrs == NULL)
    {
        if((pSNACCUnsignedAttributes=GetSNACCUnsignedAttributes()) != NULL)
            ENCODE_BUF(pSNACCUnsignedAttributes, m_pEncodedAttrs);
    }

    SME_FINISH_CATCH

    return(m_pEncodedAttrs);
} // END OF MEMBER FUNCTION GetUnsignedEncodedAttrs

// SetSignedEncodedAttrs:
//
void CSM_MsgAttributes::SetSignedEncodedAttrs(CSM_Buffer *pSignedBuf)
{
    SignedAttributes SNACCSignedAttributes;
    SME_SETUP("CSM_MsgAttributes::SetSignedEncodedAttrs");

    if(m_pEncodedAttrs)
        delete m_pEncodedAttrs;

    m_pEncodedAttrs = new CSM_Buffer(*pSignedBuf);

    DECODE_BUF(&SNACCSignedAttributes, m_pEncodedAttrs);

    UnLoadSNACCSignedAttrs(SNACCSignedAttributes);

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION SetSignedEncodedAttrs


/////////////////////////////////////////////////////////////////////
//
CSM_Buffer *CSM_MsgAttributes::AccessEncodedAttrsFromMessage()
{

    return m_pEncodedAttrsFromMessage;

}

/////////////////////////////////////////////////////////////////////
//
void CSM_MsgAttributes::SetEncodedAttrsFromMessage(CSM_Buffer *pSignedBuf)
{
    SME_SETUP("CSM_MsgAttributes::SetEncodedAttrsFromMessage");

    if (m_pEncodedAttrsFromMessage)
        delete m_pEncodedAttrsFromMessage;

    m_pEncodedAttrsFromMessage = new CSM_Buffer(*pSignedBuf);

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION SetSignedEncodedAttrs


// SetUnsignedEncodedAttrs:
//   UnLoadSNACCUnsignedAttrs
//
void CSM_MsgAttributes::SetUnsignedEncodedAttrs(CSM_Buffer *pUnsignedBuf)
{
    UnsignedAttributes SNACCUnsignedAttributes;
    SME_SETUP("CSM_MsgAttributes::SetUnsignedEncodedAttrs");

    if(m_pEncodedAttrs)
        delete m_pEncodedAttrs;

    m_pEncodedAttrs = new CSM_Buffer(*pUnsignedBuf);

    DECODE_BUF(&SNACCUnsignedAttributes, m_pEncodedAttrs);

    UnLoadSNACCUnsignedAttrs(SNACCUnsignedAttributes);

    SME_FINISH_CATCH

} // END OF MEMBER FUNCTION SetUnsignedEncodedAttrs

// GetSNACCSignedAttributes:
//
SignedAttributes *CSM_MsgAttributes::GetSNACCSignedAttributes()
{
    CSM_AttribLst::iterator itTmpCSMAttr;
    SignedAttributes *pSNACCSignedAttributes = new SignedAttributes;
    AsnOid           *pOid = NULL;        // FLAG for automatic allocation.
    CSM_Buffer       *pEncodedAttr = NULL;// FLAG for automatic allocation.

    for(itTmpCSMAttr =  m_pAttrs->begin(); 
        itTmpCSMAttr != m_pAttrs->end();
        ++itTmpCSMAttr)
    {
        Attribute &TmpSNACCSignedAttr = *pSNACCSignedAttributes->append();

        itTmpCSMAttr->GetEncodedAttr(pOid, pEncodedAttr);

        if (pEncodedAttr && pEncodedAttr->Length() && 
            pOid && pOid->Len())
        {
           TmpSNACCSignedAttr.type = *pOid;
           AttributeValue &TmpSNACCAttr1 = *TmpSNACCSignedAttr.values.append();
           SM_ASSIGN_ANYBUF(pEncodedAttr, &TmpSNACCAttr1);
           if (pOid)
           {
               delete pOid;
               pOid = NULL;
           }   // END if pOid.
        }      // END if ATTR is present.
        if (pEncodedAttr)
        {
            delete pEncodedAttr;  // RWC:MUST delete since MACRO copies
                                  //   created by GetEncodedAttr().
                                  //   (CAREFUL where this is deleted,
                                  //   it is re-used in the loop after
                                  //   the 1st run if not set to NULL.
            pEncodedAttr = NULL;
        }   // END if pEncodedAttr
    }       // END for pTmpCSMattr

    return(pSNACCSignedAttributes);

} // END OF MEMBER FUNCTION GetSNACCSignedAttributes

// GetSNACCUnprotectedAttributes:
//
UnprotectedAttributes *CSM_MsgAttributes::GetSNACCUnprotectedAttributes()
{
    CSM_AttribLst::iterator itTmpCSMAttr;
    UnprotectedAttributes *pSNACCUnprotectedAttributes =
        new UnprotectedAttributes;
    AsnOid                *pOid = NULL;
    CSM_Buffer            *pEncodedAttr = NULL;

    for(itTmpCSMAttr =  m_pAttrs->begin(); 
        itTmpCSMAttr != m_pAttrs->end();
        ++itTmpCSMAttr)
    {
        Attribute &TmpSNACCUnprotectedAttr = *pSNACCUnprotectedAttributes->append();

        itTmpCSMAttr->GetEncodedAttr(pOid,pEncodedAttr);

        TmpSNACCUnprotectedAttr.type = *pOid;

        AttributeValue &TmpSNACCAttr1 = *TmpSNACCUnprotectedAttr.values.append();

        SM_ASSIGN_ANYBUF(pEncodedAttr, &TmpSNACCAttr1);

        if (pOid)
        {
            delete pOid;
            pOid = NULL;
        }
        if (pEncodedAttr)
        {
            delete pEncodedAttr;  // RWC:MUST delete since MACRO copies
                                  //   created by GetEncodedAttr().
                                  //   (CAREFUL where this is deleted,
                                  //   it is re-used in the loop after
                                  //   the 1st run if not set to NULL.
            pEncodedAttr = NULL;
        }
    }

    return(pSNACCUnprotectedAttributes);

} // END OF MEMBER FUNCTION GetSNACCUnprotectedAttributes

// GetSNACCUnsignedAttributes:
//
UnsignedAttributes *CSM_MsgAttributes::GetSNACCUnsignedAttributes()
{
    CSM_AttribLst::iterator itTmpCSMAttr;
    UnsignedAttributes *pSNACCUnsignedAttributes = new UnsignedAttributes;
    AsnOid             *pOid = NULL;        // FLAG for automatic allocation.
    CSM_Buffer         *pEncodedAttr = NULL;// FLAG for automatic allocation.

    for(itTmpCSMAttr =  m_pAttrs->begin(); 
        itTmpCSMAttr != m_pAttrs->end();
        ++itTmpCSMAttr)
    {
        Attribute &TmpUnsignedAttr = *pSNACCUnsignedAttributes->append();

        itTmpCSMAttr->GetEncodedAttr(pOid, pEncodedAttr);

        TmpUnsignedAttr.type = *pOid;

        AttributeValue &TmpSNACCAttr1= *TmpUnsignedAttr.values.append();

        SM_ASSIGN_ANYBUF(pEncodedAttr, &TmpSNACCAttr1);

        if (pOid)
        {
            delete pOid;
            pOid = NULL;
        }
        if (pEncodedAttr)
        {
            delete pEncodedAttr;  // RWC:MUST delete since MACRO copies
                                  //   created by GetEncodedAttr().
                                  //   (CAREFUL where this is deleted,
                                  //   it is re-used in the loop after
                                  //   the 1st run if not set to NULL.
            pEncodedAttr = NULL;
        }
    }

    return(pSNACCUnsignedAttributes);
} // END OF MEMBER FUNCTION GetSNACCUnsignedAttributes

// TBD
//   AT SOME POINT THE COMMON CODE FROM THE FOLLOWING 5 FUNCTIONS SHOULD
//   BE CONSOLODATED:  THE FUNCTIONS WILL REMAIN, BUT THERE WILL BE AN
//   ADDITIONAL PRIVATE METHOD WHICH WILL ACCEPT ANY PASSED INPUT
//   (CSM_Buffer), AND A INDICATOR FOR WHICH CHECK FUNCTION TO PERFORM
//   AND A STRING TO USE IN ERROR OUTPUT (OR PERHAPS AN OUTPUT STREAM).
//      CheckSignedAttrs
//      CheckUnsignedAttrs
//      CheckUnprotectedAttrs
//      CheckCounterSignatureSignedAttrs
//      CheckCounterSignatureUnsignedAttrs

// CheckSignedAttrs:
//   INPUT:  CSM_Buffer (optional)
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function will check each attribute in the current list to ensure
//   that there are no attributes which are not valid signed attributes.
//   It makes use of the low level (CSM_Attrib) CheckSignedAttr() method.
//   If the optional CSM_Buffer is passed to this method, it will be filled
//   with a list of invalid signed attributes.  If any invalid signed
//   attribute is detected this function returns false.  Otherwise it
//   returns true.  NOTE:  if there are no Signed Attributes in the current
//   list this function still returns true.
//
bool CSM_MsgAttributes::CheckSignedAttrs(CSM_Buffer *pbuf)
{
    CSM_AttribLst::iterator itTmpAttr;
    bool        status=true;

    if (m_pAttrs)            // IF THERE ARE SIGNED ATTRIBUTES
    {
        if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT FOR APPEND
        {
            pbuf->Open(SM_FOPEN_APPEND);
        }
        for(itTmpAttr =  m_pAttrs->begin();
            itTmpAttr != m_pAttrs->end();
            ++itTmpAttr)   // ATTRIBUTE LIST
        {
            if(!itTmpAttr->CheckSignedAttr())      // IF IT IS NOT SIGNED
            {
                if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                {
                    // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                    // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                    char *errAttr=itTmpAttr->m_poid->GetChar();
                    pbuf->Write(errAttr, strlen(errAttr));  // WRITE IT TO THE
                    pbuf->Write("\n", 1);
                    free(errAttr);
                }
                status = false;        // AN INVALID SIGNED ATTRIBUTE(FAILURE)
            }
        }
        
        if (pbuf != NULL)              // IF A BUFFER WAS PASSED IN AND . . .
        {
            if (status == false)       // IF ANY ATTRIBUTE(S) FAILED
            {
                pbuf->Write("\0", 1);  // NULL TERMINATE THE BUFFER
            }
            pbuf->Close();             // CLOSE THE BUFFER
        }
    }
    return(status);          // RETURN TRUE OR FALSE
} // END OF CheckSignedAttrs

// CheckUnsignedAttrs:
//   INPUT:  CSM_Buffer (optional)
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function will check each attribute in the current list to ensure
//   that there are no attributes which are not valid unsigned attributes.
//   It makes use of the low level (CSM_Attrib) CheckUnsignedAttr() method.
//   If the optional CSM_Buffer is passed to this method, it will be filled
//   with a list of invalid unsigned attributes.  If any invalid unsigned
//   attribute is detected this function returns false.  Otherwise it
//   returns true.  NOTE:  if there are no Unsigned Attributes in the current
//   list this function still returns true.
//
bool CSM_MsgAttributes::CheckUnsignedAttrs(CSM_Buffer *pbuf)
{
    CSM_AttribLst::iterator itTmpAttr;
    bool        status=true;

    if (m_pAttrs)            // IF THERE ARE UNSIGNED ATTRIBUTES
    {
        if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT FOR APPEND
        {
            pbuf->Open(SM_FOPEN_APPEND);
        }
        for(itTmpAttr =  m_pAttrs->begin();
            itTmpAttr != m_pAttrs->end();
            ++itTmpAttr)   // ATTRIBUTE LIST
        {
            if(!itTmpAttr->CheckUnsignedAttr())    // IF IT IS NOT UNSIGNED
            {
                if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                {
                    // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                    // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                    char *errAttr=itTmpAttr->m_poid->GetChar();
                    pbuf->Write(errAttr, strlen(errAttr));  // WRITE IT TO THE
                    pbuf->Write("\n", 1);
                    free(errAttr);
                }
                status = false;        // INVALID UNSIGNED ATTRIBUTE (FAILURE)
            }
        }
        if (pbuf != NULL)              // IF A BUFFER WAS PASSED IN AND . . .
        {
            if (status == false)       // IF ANY ATTRIBUTE(S) FAILED
            {
                pbuf->Write("\0", 1);  // NULL TERMINATE THE BUFFER
            }
            pbuf->Close();             // CLOSE THE BUFFER
        }
    }
    return(status);          // RETURN TRUE OR FALSE
} // END OF CheckUnsignedAttrs

// CheckUnprotectedAttrs:
//   INPUT:  CSM_Buffer (optional)
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function will check each attribute in the current list to ensure
//   that there are no attributes which are not valid unprotected attributes.
//   It makes use of the low level (CSM_Attrib) CheckUnprotectedAttr() method.
//   If the optional CSM_Buffer is passed to this method, it will be filled
//   with a list of invalid unprotected attributes.  If any invalid
//   unprotected attribute is detected this function returns false.
//   Otherwise it returns true.  NOTE:  if there are no Unprotected
//   Attributes in the current
//
bool CSM_MsgAttributes::CheckUnprotectedAttrs(CSM_Buffer *pbuf)
{
    CSM_AttribLst::iterator itTmpAttr;
    bool        status=true;

    if (m_pAttrs)            // IF THERE ARE UNPROTECTED ATTRIBUTES
    {
        if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT FOR APPEND
        {
            pbuf->Open(SM_FOPEN_APPEND);
        }
        for(itTmpAttr =  m_pAttrs->begin();
            itTmpAttr != m_pAttrs->end();
            ++itTmpAttr) // ATTRIBUTE LIST
        {
            if(!itTmpAttr->CheckUnprotectedAttr()) // IF IT IS NOT UNPROTECTED
            {
                if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                {
                    // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                    // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                    char *errAttr=itTmpAttr->m_poid->GetChar();
                    pbuf->Write(errAttr, strlen(errAttr));  // WRITE IT TO THE
                    pbuf->Write("\n", 1);
                    free(errAttr);
                }
                status = false;   // AN INVALID UNPROTECTED ATTRIBUTE(FAILURE)
            }
        }
        if (pbuf != NULL)              // IF A BUFFER WAS PASSED IN AND . . .
        {
            if (status == false)       // IF ANY ATTRIBUTE(S) FAILED
            {
                pbuf->Write("\0", 1);  // NULL TERMINATE THE BUFFER
            }
            pbuf->Close();             // CLOSE THE BUFFER
        }
    }
    return(status);          // RETURN TRUE OR FALSE
} // END OF CheckUnprotectedAttrs

// CheckCounterSignatureSignedAttrs:
//   INPUT:  CSM_Buffer (optional)
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function will check each attribute in the current list to ensure
//   that there are no attributes which are not valid signed attributes.
//   It makes use of the low level (CSM_Attrib)
//   CheckCounterSignatureSignedAttr() method.  If the optional CSM_Buffer
//   is passed to this method, it will be filled with a list of invalid
//   signed attributes.  If any invalid signed attribute is detected this
//   function returns false.  Otherwise it returns true.  NOTE:  if there
//   are no Signed Attributes in the current list this function still
//   returns true.
//
bool CSM_MsgAttributes::CheckCounterSignatureSignedAttrs(CSM_Buffer *pbuf)
{
    CSM_AttribLst::iterator itTmpAttr;
    bool        status=true;

    if (m_pAttrs)            // IF THERE ARE SIGNED ATTRIBUTES
    {
        if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT FOR APPEND
        {
            pbuf->Open(SM_FOPEN_APPEND);
        }
        for(itTmpAttr =  m_pAttrs->begin();
            itTmpAttr != m_pAttrs->end();
            ++itTmpAttr) // ATTRIBUTE LIST
        {
            if(!itTmpAttr->CheckCounterSignatureSignedAttr())// IF NOT SIGNED
            {
                if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                {
                    // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                    // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                    char *errAttr=itTmpAttr->m_poid->GetChar();
                    pbuf->Write(errAttr, strlen(errAttr));  // WRITE IT TO THE
                    pbuf->Write("\n", 1);
                    free(errAttr);
                }
                status = false;        // AN INVALID SIGNED ATTRIBUTE(FAILURE)
            }
        }
        if (pbuf != NULL)              // IF A BUFFER WAS PASSED IN AND . . .
        {
            if (status == false)       // IF ANY ATTRIBUTE(S) FAILED
            {
                pbuf->Write("\0", 1);  // NULL TERMINATE THE BUFFER
            }
            pbuf->Close();             // CLOSE THE BUFFER
        }
    }
    return(status);          // RETURN TRUE OR FALSE
} // END OF CheckCounterSignatureSignedAttrs

// CheckCounterSignatureUnsignedAttrs:
//   INPUT:  CSM_Buffer (optional)
//   OUTPUT: NONE
//   RETURN: TRUE/FALSE
//   This function will check each attribute in the current list to ensure
//   that there are no attributes which are not valid unsigned attributes.
//   It makes use of the low level (CSM_Attrib)
//   CheckCounterSignatureUnsignedAttr() method.  If the optional CSM_Buffer
//   is passed to this method, it will be filled with a list of invalid
//   unsigned attributes.  If any invalid unsigned attribute is detected this
//   function returns false.  Otherwise it returns true.  NOTE:  if there
//   are no Unsigned Attributes in the current list this function still
//   returns true.
//
bool CSM_MsgAttributes::CheckCounterSignatureUnsignedAttrs(CSM_Buffer *pbuf)
{
    CSM_AttribLst::iterator itTmpAttr;
    bool        status=true;

    if (m_pAttrs)            // IF THERE ARE UNSIGNED ATTRIBUTES
    {
        if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT FOR APPEND
        {
            pbuf->Open(SM_FOPEN_APPEND);
        }
        for(itTmpAttr =  m_pAttrs->begin();
            itTmpAttr != m_pAttrs->end();
            ++itTmpAttr) // ATTRIBUTE LIST
        {
            if(!itTmpAttr->CheckCounterSignatureUnsignedAttr()) // NOT UNSIGNED
            {
                if (pbuf != NULL)    // IF A BUFFER WAS PASSED IN OPEN IT
                {
                    // GET THE DESCRIPTION OF THIS ATTRIBUTES' OID THEN
                    // APPEND IT TO THE BUFFER ALONG WITH A CARRIAGE RETURN
                    char *errAttr=itTmpAttr->m_poid->GetChar();
                    pbuf->Write(errAttr, strlen(errAttr));  // WRITE IT TO THE
                    pbuf->Write("\n", 1);
                    free(errAttr);
                }
                status = false;   // AN INVALID UNSIGNED ATTRIBUTE (FAILURE)
            }
        }
        if (pbuf != NULL)              // IF A BUFFER WAS PASSED IN AND . . .
        {
            if (status == false)       // IF ANY ATTRIBUTE(S) FAILED
            {
                pbuf->Write("\0", 1);  // NULL TERMINATE THE BUFFER
            }
            pbuf->Close();             // CLOSE THE BUFFER
        }
    }
    return(status);          // RETURN TRUE OR FALSE
} // END OF CheckCounterSignatureUnsignedAttrs

// AccessFirstCS:
//
Countersignature *CSM_MsgAttributes::AccessFirstCS()
{
    // Initialize the CounterSignature Attribute Index
    m_lAttributeIndex = 0;
    return(AccessNextCS());
} // END OF AccessFirstCS

// AccessNextCS:
//
Countersignature *CSM_MsgAttributes::AccessNextCS()
{
    CSM_AttribLst::iterator itTmpAttrib;
    long        lAttrIndex=0;

    // Ensure there are attributes
    if (m_pAttrs)
    {
        // INITIALZE THE CURRENT COUNTERSIGNATURE POINTER
        m_pCurrentCS=NULL;

        // Position Curr() to the next CS Attribute
        // (m_lAttributeIndex) to check
        for(itTmpAttrib =  m_pAttrs->begin(), lAttrIndex=0;
            itTmpAttrib != m_pAttrs->end() && (lAttrIndex != m_lAttributeIndex);
            ++itTmpAttrib, lAttrIndex++);

        // Starting from the current Attribute loop through the current list
        // of CSM_Attrib searching for the next Countersignature Attribute
        // incrementing the m_lAttributeIndex
        for(; 
            itTmpAttrib != m_pAttrs->end() && itTmpAttrib->m_poid && 
                 (*itTmpAttrib->m_poid != id_countersignature);
            ++itTmpAttrib, m_lAttributeIndex++);

        // We should now be looking at the next Countersignature
        if (itTmpAttrib != m_pAttrs->end())
        {
            if (itTmpAttrib->m_poid && (*itTmpAttrib->m_poid == id_countersignature))
            {
                m_pCurrentCS = itTmpAttrib->m_pSNACCCounterSignature;
            }
        }
        m_lAttributeIndex++;
    }

    return(m_pCurrentCS);
} // END OF AccessNextCS

// Report:
//
void CSM_MsgAttributes::Report(std::ostream &os)
{
    CSM_AttribLst::iterator itTmpAttrib;

    SME_SETUP("CSM_MsgAttributes::Report(ostream &os)");

    os << "CSM_MsgAttributes::Report(ostream &os)\n";

    if(m_pAttrs == NULL)
		return;
    for(itTmpAttrib =  m_pAttrs->begin(); 
        itTmpAttrib != m_pAttrs->end();
        ++itTmpAttrib)
    {
        itTmpAttrib->Report(os);
    }
    os.flush();

    SME_FINISH_CATCH

} // END OF Report

// END OF CSM_MsgAttributes FUNCTION DEFINITIONS

// BEGIN CSM_ReceiptRequest FUNCTION DEFINITIONS

// SetallReceipts:
//
void CSM_ReceiptRequest::SetallReceipts()
{
    if(m_pallOrFirstTier==NULL)
        m_pallOrFirstTier = new AllOrFirstTier(AllOrFirstTier::allReceipts);
    else
        *m_pallOrFirstTier = AllOrFirstTier::allReceipts;

    if(m_pReceiptsFrom)
        delete m_pReceiptsFrom;

    m_pReceiptsFrom = NULL;
} // END OF MEMBER FUNCTION SetallReceipts

// SetfirstTierRecipients:
//
void CSM_ReceiptRequest::SetfirstTierRecipients()
{
    if(m_pallOrFirstTier==NULL)
        m_pallOrFirstTier =
            new AllOrFirstTier(AllOrFirstTier::firstTierRecipients);
    else
        *m_pallOrFirstTier = AllOrFirstTier::firstTierRecipients;

    if(m_pReceiptsFrom)
        delete m_pReceiptsFrom;

    m_pReceiptsFrom = NULL;
} // END OF MEMBER FUNCTION SetfirstTierRecipients

// UpdateReceiptsFrom:
//
void CSM_ReceiptRequest::UpdateReceiptsFrom(CSM_GeneralNames *pReceiptGNs)
{
    if(m_pReceiptsFrom)
        delete m_pReceiptsFrom;

    m_pReceiptsFrom = pReceiptGNs;

    if(m_pallOrFirstTier)
        delete m_pallOrFirstTier;

    m_pallOrFirstTier = NULL;
} // END OF MEMBER FUNCTION UpdateReceiptsFrom

// DESTRUCTOR FOR CSM_ReceiptRequest
//
CSM_ReceiptRequest::~CSM_ReceiptRequest()
{
    if (m_pallOrFirstTier)
        delete m_pallOrFirstTier;
    m_pallOrFirstTier = NULL;
    if (m_pReceiptsFrom)
        delete m_pReceiptsFrom;
} // END OF CSM_ReceiptRequest DESTRUCTOR

// CONSTRUCTOR FOR CSM_ReceiptRequest
//
CSM_ReceiptRequest::CSM_ReceiptRequest(CSM_ReceiptRequest &CRecReq)
{
    m_pallOrFirstTier = NULL;
    m_pReceiptsFrom   = NULL;

    SME_SETUP("CSM_ReceiptRequest::CSM_ReceiptRequest(CSM_ReceiptRequest &");

    if(CRecReq.AccessfirstTierRecipients() != NULL)
    {
        m_pallOrFirstTier = new AllOrFirstTier;

        *m_pallOrFirstTier = *CRecReq.AccessfirstTierRecipients();
    }
    else if (CRecReq.AccessReceiptsFrom() != NULL)
    {
        m_pReceiptsFrom =
            new CSM_GeneralNames(*CRecReq.AccessReceiptsFrom());
    }
    else
    {
        SME_THROW(SM_MISSING_PARAM, NULL, NULL);
    }

    if (CRecReq.m_SignedContentIdentifier.Length())
        m_SignedContentIdentifier = CRecReq.m_SignedContentIdentifier;
    else
        m_SignedContentIdentifier.Set("TEST RR SCID", strlen("TEST RR SCID"));
    m_ReceiptsTo = CRecReq.m_ReceiptsTo;

    SME_FINISH_CATCH
} // END OF CSM_ReceiptRequest CONSTRUCTOR


CSM_Buffer *CSM_ReceiptRequest::GetEncodedReceiptRequest()
{
    ReceiptRequest   snaccRR;
    CSM_Buffer      *pEncodedAttrib = NULL;
    CSM_GeneralNames::iterator itTmpGN;

    SME_SETUP("CSM_Attrib::GetEncodedReceiptRequest");

    if (this->m_SignedContentIdentifier.Length())
    {
        snaccRR.signedContentIdentifier.Set((const char *)this->
            m_SignedContentIdentifier.Access(),
            this->m_SignedContentIdentifier.Length());
    }
    else        // MUST BE PRESENT
    {
        snaccRR.signedContentIdentifier.Set("TEST2 RR SCID",
            strlen("TEST2 RR SCID"));
    }

    if (this->AccessfirstTierRecipients())
    {
        snaccRR.receiptsFrom.choiceId = ReceiptsFrom::allOrFirstTierCid;
        snaccRR.receiptsFrom.allOrFirstTier = new AllOrFirstTier(
                        *this->AccessfirstTierRecipients());
    }
    else if (this->AccessReceiptsFrom())
    {
        snaccRR.receiptsFrom.choiceId = ReceiptsFrom::receiptListCid;
        if (snaccRR.receiptsFrom.receiptList == NULL)
            snaccRR.receiptsFrom.receiptList = new ReceiptsFromSeqOf;
        for(itTmpGN =  AccessReceiptsFrom()->begin();
            itTmpGN != AccessReceiptsFrom()->end();
            ++itTmpGN)
        {
            GeneralNames &tmpSNACCNames = *snaccRR.receiptsFrom.receiptList->append();
            tmpSNACCNames.append(*itTmpGN);
        }
    }
    else
        SME_THROW(SM_NO_RECEIPTS_FROM, "MUST Have receiptFrom data.", 0);

    CSM_GeneralNamesLst::iterator itTmpGNs = m_ReceiptsTo.begin();
    if (itTmpGNs == m_ReceiptsTo.end())
    {
        SME_THROW(SM_MISSING_PARAM, "MUST HAVE ReceiptTo data!!", NULL);
    }
    else
    {
        // sib implementing new data structure for m_ReceiptsTo
        // get the SNACC GeneralNames list and append it to snaccRR for encoding
        // and append it to snaccRR which will be encoded into pEncodedAttrib
        for(;
            itTmpGNs != m_ReceiptsTo.end();
            ++itTmpGNs)
        {
            GeneralNames &tmpSNACCNames = *snaccRR.receiptsTo.append();
            itTmpGNs->GetSNACCGeneralNames(tmpSNACCNames);     
        }

    }

    ENCODE_BUF((&snaccRR), pEncodedAttrib);

    SME_FINISH_CATCH
    
    // return the encoded Receipt Request attribute data
    return pEncodedAttrib;

} // END OF MEMBER FUNCTION 

// END OF CSM_ReceiptRequest FUNCTION DEFINITIONS

// BEGIN CSM_SecLbl FUNCTION DEFINITIONS

// CSM_SecLbl::operator =:
//
CSM_SecLbl &CSM_SecLbl::operator = (const CSM_SecLbl &pseclabel)
{
    m_PolicyId = pseclabel.m_PolicyId;

    if (pseclabel.m_plSecClass)
    {
        m_plSecClass = new long (*pseclabel.m_plSecClass);
    }
    else
        m_plSecClass = NULL;
    if (pseclabel.m_pPmark)
    {
        m_pPmark = new CSM_Buffer(*pseclabel.m_pPmark);
    }
    else
        m_pPmark = NULL;
    if (pseclabel.m_pSecCats)
    {
        m_pSecCats = new CSM_SecCatLst(*pseclabel.m_pSecCats);
    }
    else
        m_pSecCats = NULL;
    return *this;
} // END OF = OPERATOR OVERLOAD MEMBER FUNCTION

CSM_SecLbl::CSM_SecLbl(const CSM_SecLbl &qqq)
{
    *this = qqq;
}


CSM_SecLbl::~CSM_SecLbl()
{
    if (m_plSecClass)
    {
        delete m_plSecClass;
    }
    if (m_pPmark)
    {
        delete m_pPmark;
    }
    if (m_pSecCats)
    {
        delete m_pSecCats;
    }
}

// GetSNACCSecLbl:
//
ESSSecurityLabel *CSM_SecLbl::GetSNACCSecLbl()
{
    ESSSecurityLabel *psnaccSL = new ESSSecurityLabel;
    CSM_SecCatLst::iterator itTmpSecCat;

    psnaccSL->security_policy_identifier = m_PolicyId;

    if (m_plSecClass)
        psnaccSL->security_classification =
            new SecurityClassification(*m_plSecClass);

    if (m_pPmark)
    {
        psnaccSL->privacy_mark = new ESSPrivacyMark;

        psnaccSL->privacy_mark->choiceId = ESSPrivacyMark::pStringCid;

        psnaccSL->privacy_mark->pString = new SNACC::ESSPrivacyMark::PString;
        *psnaccSL->privacy_mark->pString = m_pPmark->Access();
    }


    if (m_pSecCats)
    {
        psnaccSL->security_categories = new SecurityCategories;
        for(itTmpSecCat =  m_pSecCats->begin();
            itTmpSecCat != m_pSecCats->end();
            ++itTmpSecCat)
        {
            SecurityCategory &tmpSNACCSecurityCat = *psnaccSL->security_categories->append();

            tmpSNACCSecurityCat.type = itTmpSecCat->m_Type;

            SM_ASSIGN_ANYBUF(itTmpSecCat->m_pValue, &tmpSNACCSecurityCat.value);
        }
    }
    return (psnaccSL);
} // END OF MEMBER FUNCTION GetSNACCSecLbl

// END OF CSM_SecLbl FUNCTION DEFINITIONS

CSM_SecCat::~CSM_SecCat()
{
   if (m_pValue)
      delete m_pValue;
}
CSM_SecCat & CSM_SecCat::operator = (const CSM_SecCat &secCat)
{
   if (secCat.m_pValue)
      m_pValue = new CSM_Buffer(*secCat.m_pValue);
   m_Type = secCat.m_Type;
   return(*this);
}


//
//
CSM_SmimeCapability::~CSM_SmimeCapability()
{
   if (m_pParameters)
      delete m_pParameters;
}
CSM_SmimeCapability & CSM_SmimeCapability::operator = (const CSM_SmimeCapability &smimeCapability)
{
   m_capabilityID = smimeCapability.m_capabilityID;
   if (smimeCapability.m_pParameters)
      m_pParameters = new CSM_Buffer(*smimeCapability.m_pParameters);
   return(*this);
}



//
//
CSM_Time::CSM_Time(const char *lpszTime, int len, int iType)
{
    char buf[1000];
    bool bUTCTime=true;
    m_lpszTime = NULL;
    if (iType == SNACC::SigningTime::generalizedTimeCid)
        bUTCTime = false;
    if (len < 1000)     // ASSUME incomming buffer is not NULL terminated.
    {
        memcpy(buf, lpszTime, len);
        buf[len] = '\0';    // NULL terminate incomming string.
        SetTime(buf, bUTCTime);
    }       // END if len < 1000
}

//
//
CSM_Time::CSM_Time(const char *lpszTime, bool bUTCTime)
{
    SetTime(lpszTime, bUTCTime);
}


//
//  This routine checks for the special string "NOW" with day offset index.
//  e.g. "NOW+30" would be 30 days from NOW.  This routine assumes that 
//  the incomming "lpszTime" parameter is NULL terminated.
void CSM_Time::SetTime(const char *lpszTime, bool bUTCTime)
{
    long lOffsetValue=0;
    long ltime=0;
    struct tm *today;
    char tmpbuf[2000];

    m_lpszTime = NULL;
    if (strncmp(lpszTime, "NOW", 3) == 0)
    {               // THEN process with current time...
        char strFormat[30];    // Def and code to avoid SCCS replacement
        if (bUTCTime)
            strcpy(strFormat,"%y");
        else        // GENERALIZED TIME
            strcpy(strFormat,"%Y");
        strcat(strFormat,"%m");
        strcat(strFormat,"%d");
        strcat(strFormat,"%H");
        strcat(strFormat,"%M00Z");
        time( &ltime );
        if (strlen(lpszTime) > 4 && lpszTime[3] == '+')
        {
           lOffsetValue = atoi(&lpszTime[4]); // ASSUME NULL terminated.
           lOffsetValue *= (24 * 60 * 60);   // COMPUTE seconds from days
        }       // END if NOW+...
        ltime += lOffsetValue;
        today = gmtime( &ltime );
        strftime( tmpbuf, 128, strFormat, today );
        this->m_lpszTime = strdup(tmpbuf);
    }   // IF "NOW".
    else
    {
       // JUST LOAD USER SPECIFIED BUFFER.
       if (strlen(lpszTime))
       {
           m_lpszTime = (char *)calloc(1, strlen(lpszTime)+1);
           memcpy(m_lpszTime, lpszTime, strlen(lpszTime));
           m_lpszTime[strlen(lpszTime)] = '\0';
           if (bUTCTime)
              m_type = SNACC::SigningTime::utcTimeCid;
           else
              m_type = SNACC::SigningTime::generalizedTimeCid;
       }    // END if any data in user string.
    }       // END if "NOW".
}       // END CSM_Time constructor of string.

//
// begin CSM_TimeStampTokenInfo Class member functions:


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  void CSM_TimeStampTokenInfo
//
// Description:  constructor
// 
// Inputs:   SNACC::TimeStampReq &RSReq
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampTokenInfo::CSM_TimeStampTokenInfo(     // constructor
   SNACC::TimeStampReq &TSReq)
{
   //long status = 0;
   SME_SETUP("CSM_TimeStampTokenInfo::CSM_TimeStampTokenInfo(SNACC::TimeStampReq &TSReq)");

   TSTInfoInt ver(1);

   // set version
   version.Set(ver);

   // set reqPolicy
   if (TSReq.reqPolicy != NULL)
      policy.Set(*TSReq.reqPolicy);

   // set message imprint
   // if we have a MessageDigest value then load it
   if (TSReq.messageImprint.hashedMessage.length())
   {
      messageImprint = TSReq.messageImprint;
   }
   else
   {
      // tbd other error processing 
      SME_THROW(SM_MISSING_PARAM,
         "ERROR:  No MessageDigest value to load for MessageImprint", NULL);
   }

   // set nonce
   if (TSReq.nonce && TSReq.nonce->length() > 0)
      nonce = new AsnInt(*TSReq.nonce);

   // set extensions


   SME_FINISH_CATCH;

}  // end of constructor for CSM_TimeStampTokenInfo
   



////////////////////////////////////////////////////////////////////////////////
//
// Member function:  GetUntrustedTime()
//
// Description:  Returns a CSM_Buffer with the formatted Generalize time which
//               is untrusted.
// 
// Inputs:   NONE
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
CTIL::CSM_Buffer *CSM_TimeStampTokenInfo::GetUntrustedTime(void)
{
   CSM_Buffer *pUntrustedTime = NULL;
   long ltime=0;
   struct tm *today;
   char tmpbuf[2000];
   char strFormat[30];    

   // GENERALIZED TIME  sib may need refinement for milliseconds
   strcpy(strFormat,"%Y");
   strcat(strFormat,"%m");
   strcat(strFormat,"%d");   
   strcat(strFormat,"%H");
   strcat(strFormat,"%M");
   strcat(strFormat,"%SZ");
   time( &ltime );
   today = gmtime( &ltime );

   strftime( tmpbuf, 128, strFormat, today);
   pUntrustedTime = new CSM_Buffer(tmpbuf, strlen(tmpbuf));
   
   return pUntrustedTime;

}  // end of CSM_TimeStampTokenInfo::GetUntrustedTime
   

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  LoadCertInfo
//
// Description:  
//   The TSA's public key certificate that is referenced by the
//   ESSCertID identifier inside a signingCertificate attribute
//   in the response MUST be provided by the TSA in the certificates 
//   field from the SignedData structure in that response. That
//   field may also contain other certificates.
//
// Inputs:  SNACC::GeneralName &snaccTsa
//
// Outputs:
//
// Returns:status
//
////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_TimeStampTokenInfo::LoadCertInfo(SNACC::GeneralName &snaccTsa)
{
   long status = 0;

   SME_SETUP("CSM_TimeStampTokenInfo::LoadCertInfo()");

   // retrieve TimeStampAuthority cert
   if (tsa != NULL)
      delete tsa;

   if ((tsa = new SNACC::GeneralName(snaccTsa)) == NULL)
      SME_THROW(22,"Error loading TSA's GeneralName", NULL);

   SME_FINISH_CATCH;
   
   return status;

}  // end of CSM_TimeStampTokenInfo::LoadCertInfo



////////////////////////////////////////////////////////////////////////////////
//
// Member function:  SetPolicyId
//
// Description:  This function finds the certificatePolicies extension and 
//               sets the TSTInfo policyId member with the policy id
//
// Input:   Extensions *pExtensions
//
// Output:   NONE
//
// Returns:  status 1 - policyId not set
//                  0 - policyID set
// 
////////////////////////////////////////////////////////////////////////////////
SNACC::AsnOid *CSM_TimeStampTokenInfo::GetFirstPolicyIdFromCert
   (const SNACC::Certificate &Cert)
{
    Extensions::iterator      SNACCExt;
    CertificatePoliciesSyntax *pCertPolicies = NULL;
    Extensions                *pExtensions = Cert.toBeSigned.extensions;
	 AsnOid                    *pPolicyOid = NULL;

    if (pExtensions)
    {
        for (SNACCExt = pExtensions->begin();
             SNACCExt != pExtensions->end();
             ++SNACCExt)
		{
           if(SNACCExt->extnId == id_ce_certificatePolicies)
		   {
              pCertPolicies = (CertificatePoliciesSyntax *)SNACCExt->extnValue.value;
              if (pCertPolicies && pCertPolicies->size())
              {
                 pPolicyOid = new AsnOid(pCertPolicies->begin()->policyIdentifier);
              }
		   }
		}
	}

	return pPolicyOid;

}  // end CSM_TimeStampTokenInfo::SetPolicyId()


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  SetSerialNumber
//
// Description:  This function changes serialNum to a char string and then the
//               serialNum member is set.
// 
// Inputs:   int serialNum  next serial number
//
// Outputs:  NONE
//
// Returns: 0 - success
//
////////////////////////////////////////////////////////////////////////////////   
SM_RET_VAL CSM_TimeStampTokenInfo::SetSerialNumber(int serialNum)
{
   long status = 0;
   unsigned char serNum[50];

   SME_SETUP("CSM_TimeStampResp::SetSerialNumber()");

      // add 1 to serial number
      sprintf((char *)serNum, "%d", serialNum);

      // set serial number 
      serialNumber.Set((const unsigned char *)serNum, strlen((char *)serNum), true);


   SME_FINISH_CATCH;

   return status;
}


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CSM_TimeStampToken
//
// Description:  copy constructor
// 
// Inputs:   const CSM_TimeStampToken &TSToken
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampToken::CSM_TimeStampToken(const CSM_TimeStampToken &TSToken)
{
   Clear();
    *this = TSToken;
}

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  CSM_TimeStampToken
//
// Description:  constructor
// 
// Inputs:   const SNACC::TimeStampToken &TSToken
//
// Outputs:  NONE
//
// Returns:  NONE
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampToken::CSM_TimeStampToken(const TimeStampToken &TSToken)
{   
   m_pTimeStampToken = new TimeStampToken(TSToken);
}

////////////////////////////////////////////////////////////////////////////////
//
// Member function:  operator = 
//
// Description:  Sets left hand side with TSToken
// 
// Inputs:   const CSM_TimeStampToken &TSToken
//
// Outputs:  NONE
//
// Returns:  *this
//
//
////////////////////////////////////////////////////////////////////////////////
CSM_TimeStampToken &CSM_TimeStampToken::operator = (const CSM_TimeStampToken &TSToken)
{
    if (m_pTimeStampToken == NULL && TSToken.m_pTimeStampToken)
        m_pTimeStampToken = new ContentInfo(*TSToken.m_pTimeStampToken);
    else
        if (TSToken.m_pTimeStampToken)
            *m_pTimeStampToken = *TSToken.m_pTimeStampToken;

    return(*this);
}


////////////////////////////////////////////////////////////////////////////////
//
// Member function:  GetTimeStampTokenInfo
//
// Description:  
// 
// Inputs:   NONE
//
// Outputs:  NONE
//
// Returns:  pTSToken TimeStampToken
//
//
////////////////////////////////////////////////////////////////////////////////
TSTInfo *CSM_TimeStampToken::GetTimeStampTokenInfo()
{
   long              status = 0;
   TSTInfo           *pTSTokenInfo = NULL;
   SignedData        sd;

   SNACC::TimeStampToken *pTSToken = GetTimeStampToken();

   // find the timeStampTokenInfo
   if (pTSToken)
   {
      CSM_ContentInfoMsg *ptmpCIMsg = NULL;
      ptmpCIMsg = new CSM_ContentInfoMsg(*pTSToken);
      if (ptmpCIMsg)
      {
         CSM_Buffer *pTSTInfoBuf = NULL;
         CSM_Buffer *pSIBuf = new CSM_Buffer(ptmpCIMsg->AccessEncapContentClear()->m_content);
         if (pSIBuf->Length() != 0)
         {
            pSIBuf->Decode(sd);
            pTSTInfoBuf = new CSM_Buffer(sd.encapContentInfo.eContent->c_str(),
               sd.encapContentInfo.eContent->length());
            if (pTSTInfoBuf->Length() != 0)
            {
               // decode the input buffer
               pTSTokenInfo = new TSTInfo;
               status = pTSTInfoBuf->Decode(*pTSTokenInfo);
            }
         }
         if (pSIBuf)
            delete pSIBuf;
         if (pTSTInfoBuf)
            delete pTSTInfoBuf;

      }

      // clean up
      if (ptmpCIMsg)
         delete ptmpCIMsg;   
   }

   if (pTSToken)
      delete pTSToken;

   return pTSTokenInfo;
}


////////////////////////////////////////////////////////////////////////////////
//
// Member function: GetTimeStampToken
//
// Description:  This functions decodes m_pTimeStampTokenBuf CSM_Buffer and this
//               data is what is returned.
// 
// Inputs:   NONE
//
// Outputs:  NONE
//
// Returns:  psnaccTST copy of ContentInfo TimeStampToken
//
//
////////////////////////////////////////////////////////////////////////////////
TimeStampToken *CSM_TimeStampToken::GetTimeStampToken()
{
   TimeStampToken     *psnaccTST = NULL;
   
   SME_SETUP("CSM_Attrib::GetTimeStampToken");

   if (m_pTimeStampToken)
   {
       psnaccTST = new ContentInfo(*m_pTimeStampToken);
   }


   SME_FINISH_CATCH;

   return psnaccTST;
}


////////////////////////////////////////////////////////////////////////////////
//
// Member function: AccessTimeStampToken
//
// Description:  This functions 
//
// Inputs:   NONE
//
// Outputs:  NONE
//
// Returns:  pointer to m_pTimeStampToken
//
//
////////////////////////////////////////////////////////////////////////////////
TimeStampToken *CSM_TimeStampToken::AccessTimeStampToken()
{  
   return m_pTimeStampToken;
}
_END_SFL_NAMESPACE


// EOF sm_Attr.cpp
