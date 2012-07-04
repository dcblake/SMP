//
// sm_SignBuf.cpp
// This support class handles the signing/verification of a buffer, given
// the CSInstance to sign/verify with.

#include "sm_apiCert.h"
_BEGIN_CERT_NAMESPACE 
using namespace SNACC;


CSM_Alg *CSM_SignBuf::GetPreferredKeyEncryptionAlg(CSM_CSInst &cInst)
{ 
   CSM_AlgLstVDA *pDummy1 = NULL;
   CSM_AlgLstVDA *pkeyEncryptionAlgId = new CSM_AlgLstVDA();
   CSM_AlgLstVDA::iterator itTmpAlg;
   CSM_Alg    *pResult = NULL;
   AsnOid    *ptmpOid;

   SME_SETUP("CSM_SignBuf::GetPreferredKeyEncryptionAlg");

   cInst.GetAlgIDs(pDummy1,pDummy1,pkeyEncryptionAlgId,pDummy1);
   ptmpOid = cInst.AccessTokenInterface()->GetPrefKeyEncryption();
   for (itTmpAlg =  pkeyEncryptionAlgId->begin();
        itTmpAlg != pkeyEncryptionAlgId->end();
        ++itTmpAlg)
   {
      if(*itTmpAlg->AccessSNACCId() == *ptmpOid)
      {
         pResult = new CSM_Alg(*itTmpAlg);
      }
   }

   delete ptmpOid;
   if (pkeyEncryptionAlgId)
       delete pkeyEncryptionAlgId;

   SME_FINISH_CATCH
   return(pResult);
}
// Set all CSInstances that can handle verification of the specified
//  signature algIDs.  Returns how many times SetApplicable was called
//  If there is a GeneralNameLst then
long CSM_SignBuf::SetApplicableInstances(CSMIME *pCSMIME, CSM_Alg *pdigestAlgorithm,
        CSM_Alg *psignatureAlgorithm, CSM_GeneralNames *genNames, bool bSignerOnlyFlag)
{
   CSM_CtilInstLst::iterator  itTmpInst;
   CSM_CSInst       *tmpInstCS;
   long             setcount = 0;

   SME_SETUP("CSM_SignBuf::SetApplicableInstance");


   if (pCSMIME->m_pCSInsts)
   {
   // check specified OIDs against signature possibilities of
   //  CSMIME list of logon instances.
   for (itTmpInst =  pCSMIME->m_pCSInsts->begin(); 
        itTmpInst != pCSMIME->m_pCSInsts->end();
        ++itTmpInst)
   {
      tmpInstCS = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
      if (tmpInstCS)
      {
      // if digest and signature algorithms are null, just check the 
      // genNameLst for matching subject dns
       if (pdigestAlgorithm == NULL && psignatureAlgorithm == NULL)
      {
         // check the general name list (input: from list of the ReceiptRequest)
         // If tmpInst is in the general name list then SetApplicable() 
         if (genNames != NULL)
         {
            // get the subject for the instance
            if (genNames->FindSubjectDN(tmpInstCS))
            {             
               // Check useThis flag to see if we have a login for this subject
               if (tmpInstCS->IsThisUsed() && tmpInstCS->HasCertificates() && 
                   (!bSignerOnlyFlag || tmpInstCS->IsSigner()))
               {
                  tmpInstCS->SetApplicable();
                  setcount++;
               }
            }
         }
         else // all parameters are null
         {  
            if (tmpInstCS->IsThisUsed() &&  tmpInstCS->HasCertificates() &&
               (!bSignerOnlyFlag || tmpInstCS->IsSigner()))
            {
               // If the message Signature algs are found in this 
               //   logon instance.
               tmpInstCS->SetApplicable();
               setcount++;
            }
         }
      }
      else //pdigestAlgorithm and psignatureAlgorithm are not null
      {
           if(tmpInstCS->FindAlgIds(pdigestAlgorithm, 
            psignatureAlgorithm, NULL, NULL) ) 
           {
               if (tmpInstCS->IsThisUsed()  && /*RWC;NOT NECESSARY;tmpInstCS->AccessCertificates() && */
                  (!bSignerOnlyFlag || tmpInstCS->IsSigner()))
               {
                 // If the message Signature algs are found in this 
                  //   logon instance.
                  tmpInstCS->SetApplicable();
                  setcount++;
               }
           }
      }        // END IF digest and signature algs present.
      }        // END IF instance handles certificates.

   }           // END FOR each instance.

   CSM_SignBuf::ClearEncryptApplicableInstances(pCSMIME);
   }        // END if any instances to process.
   SME_FINISH_CATCH

   return setcount;
}

void CSM_SignBuf::ClearEncryptApplicableInstances(CSMIME *pCSMIME)
{
    CSM_CtilInstLst::iterator  itTmpInst;
   CSM_CSInst       *tmpInstCS;

   SME_SETUP("CSM_SignBuf::ClearEncryptApplicableInstances");

   for (itTmpInst =  pCSMIME->m_pCSInsts->begin(); 
        itTmpInst != pCSMIME->m_pCSInsts->end();
        ++itTmpInst)
   {
      tmpInstCS = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
      if (tmpInstCS)
      {
               // Check useThis flag to see if we have a login for this subject
               if (tmpInstCS->IsThisUsed()  && tmpInstCS->HasCertificates() && 
                  !tmpInstCS->IsSigner())
               {
                  tmpInstCS->SetApplicable(false);
               }
      }        // END IF instance handles certificates.
   }
   SME_FINISH_CATCH

}

// Determine specific (1st in list) CSInstance for verification.
CSM_CSInst *CSM_SignBuf::GetFirstInstance(CSMIME *pCSMIME, 
    CSM_Alg *pdigestAlgorithm, CSM_Alg *psignatureAlgorithm)
{
   CSM_CtilInstLst::iterator  itTmpInst;
   CSM_CSInst   *tmpInstCS;
   CSM_CSInst   *pResultInst=NULL;

   SME_SETUP("CSM_SignBuf::GetFirstInstance");
   
   if (pCSMIME->m_pCSInsts == NULL)
      return(pResultInst);

   for (itTmpInst =  pCSMIME->m_pCSInsts->begin(); 
     itTmpInst != pCSMIME->m_pCSInsts->end() && pResultInst == NULL;
     ++itTmpInst)
   {
      if ((*itTmpInst)->IsApplicable() && 
               (*itTmpInst)->FindAlgIds(pdigestAlgorithm, 
               psignatureAlgorithm, NULL, NULL))
      {
         tmpInstCS = (CSM_CSInst *)(*itTmpInst)->AccessTokenInterface()->AccessCSInst();
         if (tmpInstCS)    // ONLY assign if Certificate based CTIL.
            pResultInst = tmpInstCS;
      }     // END IF Applicable and algs match
         // If the message Signature algs are found in this 
         //   logon instance.
   }
   SME_FINISH_CATCH
   return(pResultInst);
}


// Sign buffer blob with specified CSInstance.
long CSM_SignBuf::SignBuf(CSM_CSInst *pCSInst,   // IN, Instance for hash/sig ops
      CSM_Buffer *pSigContentBuf,       // IN, buffer to hash/sign
      CSM_Buffer *&pDigest,             // OUT, resulting hash value.
      CSM_Buffer *&pSigBuf,             // OUT, resulting signature.
      AlgorithmIdentifier *&digestAlgorithm,        // OUT, Actual hash AlgID used.
      AlgorithmIdentifier *&signatureAlgorithm)     // OUT, Actual sig AlgID used.
{
    long status=0;
    AsnOid oidDigestEncryption; // tmp OID for each pCSInst signing alg
    AsnOid oidDigest;
    CSM_AlgLstVDA *pdigestEncryptionAlgID=NULL;
    CSM_AlgLstVDA *pdigestAlgID=NULL;
    CSM_AlgLstVDA::iterator itTmpAlg;
    AsnOid *pTmpAlg=NULL;
    CSM_TokenInterface *tmpTokenIF;

    SME_SETUP("CSM_SignBuf::SignBuf");
    if (!pCSInst->IsSigner())
          SME_THROW(22, "INSTANCE MUST BE SIGNER", NULL);
    if (pDigest == NULL)
      pDigest = new CSM_Buffer;
    if (pSigBuf == NULL)
        pSigBuf = new CSM_Buffer;
    tmpTokenIF = pCSInst->AccessTokenInterface();
    // NOW, process the content and produce a signature.
    //  if (pDigest->Length() > 0)
    {
         SME(tmpTokenIF->SMTI_Sign(pSigContentBuf, 
             pSigBuf,                // returned result
             pDigest));               // data digest (Hash of Content)
    }

    pCSInst->GetPreferredCSInstAlgs(&oidDigest, &oidDigestEncryption, 
              NULL, NULL);
    pCSInst->AccessTokenInterface()->BTIGetAlgIDs(&pdigestAlgID, &pdigestEncryptionAlgID, 
              NULL,NULL);
    if (signatureAlgorithm == NULL)
        signatureAlgorithm = new AlgorithmIdentifier;
    // Locate our AlgIds for preferred algorithms
    for (itTmpAlg =  pdigestEncryptionAlgID->begin(); 
         itTmpAlg != pdigestEncryptionAlgID->end();
         ++itTmpAlg) 
    {
         pTmpAlg = itTmpAlg->GetId();
         if (*pTmpAlg == oidDigestEncryption)
         {
             break;
         }
    }
    if (itTmpAlg != pdigestEncryptionAlgID->end())
    {                // if the preferred OID is found.
        CSM_AlgVDA *pAlgVDA = &(*itTmpAlg);
        *signatureAlgorithm = *(CSM_Alg *)pAlgVDA;
    }
    if (pTmpAlg)
       delete pTmpAlg;

    if (digestAlgorithm == NULL)
        digestAlgorithm = new AlgorithmIdentifier;

    // Locate our AlgIds for preferred algorithms
    for (itTmpAlg = pdigestAlgID->begin(); 
         itTmpAlg != pdigestAlgID->end();
         ++itTmpAlg)
    {
         pTmpAlg = itTmpAlg->GetId();
         if (pTmpAlg && *pTmpAlg == oidDigest)
         {
             delete pTmpAlg;
             break;
         }
         else
             delete pTmpAlg;
    }
    if (itTmpAlg != pdigestAlgID->end())        // if the preferred OID is found.
    {
        CSM_AlgVDA *pAlgVDA = &(*itTmpAlg);
       *digestAlgorithm = *(CSM_Alg *)pAlgVDA;
    }       // END IF itTmpAlg
    if (pdigestAlgID)
    {
       delete pdigestAlgID;
       pdigestAlgID = NULL;
    }
    if (pdigestEncryptionAlgID)
    {
       delete pdigestEncryptionAlgID;
       pdigestEncryptionAlgID = NULL;
    }

    SME_FINISH
    SME_CATCH_SETUP
        // local cleanup logic
    SME_CATCH_FINISH
    
    return(status);
}
///////////////////////////////////////////////////////////////////////////////////////////
//  This function returns the certificate path for the passed-in Rid
//  from passed-in certificate bucket (in pCertCrls)
SM_RET_VAL CSM_SignBuf::LoadCertificatePath(
    CSM_Identifier *pRid, // IN, user DN & SN.
    CSM_MsgCertCrls         *pCertCrls,            // IN, Cert Bucket to search.
    CSM_CertificateChoiceLst *&pCertPath)        // OUT, resulting CertPath.
{
   SM_RET_VAL status = SM_NO_ERROR;    // NOT FOUND or no certs available.
   CSM_DN *pSubjectDN = NULL;
   CSM_DN *pIssuerDN = NULL;

   SME_SETUP("CSM_SignBuf::LoadCertificatePath");

   CSM_CertificateChoice *pCert = NULL;

   // We will start with an empty path.  Then we will search the bucket to find a cert for
   // pRid, if it is found, the certificate will be added to the path and then we will attempt
   // to climb its path and adding each certificate along the way until we get to the root cert
   // or no more certificates.
   pCertPath = NULL;

    // Locate the user cert if possible.
    if ((pCert = pCertCrls->FindCert(*pRid)) != NULL)
   {
       if ((pCertPath = new CSM_CertificateChoiceLst) == NULL)
          SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

       CSM_CertificateChoice *pCert2 = &(*pCertPath->append());
       *pCert2 = *pCert;
       delete pCert;
       pCert = pCert2;

      // Get user certificate path.
      {
         CSM_CertificateChoiceLst::iterator itTmpCertChoice;
         // Access pointer to cert bucket in SignedData.
         CSM_CertificateChoiceLst *pCertLst = pCertCrls->AccessCertificates();

         CSM_DN *pTmpDN = NULL;
         pIssuerDN = pCert->GetIssuer();
         pSubjectDN = pCert->GetSubject();
         if (pSubjectDN && pIssuerDN )
         {
            // Loop until no pTmpCert or until we have processed    
            // the root PCA/CA cert IssuerDN = SubjectDN
            while (*pSubjectDN != *pIssuerDN)
            {
               // Every time the outer loop is executed, we need a pointer
               // to the first cert in the bucket.
               for (itTmpCertChoice =  pCertLst->begin();
                    itTmpCertChoice != pCertLst->end();
                    ++itTmpCertChoice)
               {
                  if ((pTmpDN = itTmpCertChoice->GetSubject()) != NULL)
                  {      
                     // Is itTmpCertChoice the cert for the issuer of pTmpSubjCert?
                     if (*pIssuerDN == *pTmpDN)
                     {
                        // Found cert for issuer of pTmpSubjCert; so, make copy and
                        // append to cert path.
                        pCertPath->append(*itTmpCertChoice);
                        break;
                     }
                     delete pTmpDN;
                  }               
               }        // END FOR each cert in list.

               if (itTmpCertChoice == pCertLst->end())
                   break;       // NO MORE CERTS to process.

              delete pSubjectDN;
              pSubjectDN = itTmpCertChoice->GetSubject();

              delete pIssuerDN;
              pIssuerDN = itTmpCertChoice->GetIssuer();
            }       // END while root cert not located.
         }
      }
   }

    if (pSubjectDN)
       delete pSubjectDN;
    if (pIssuerDN)
       delete pIssuerDN;

    SME_FINISH
    SME_CATCH_SETUP
      // local cleanup logic
      if (pSubjectDN)
         delete pSubjectDN;
      if (pIssuerDN)
         delete pIssuerDN;
    SME_CATCH_FINISH

    return(status);
}

_END_CERT_NAMESPACE 

// EOF sm_SignBuf.cpp
