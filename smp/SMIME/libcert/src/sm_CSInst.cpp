
//////////////////////////////////////////////////////////////////////////
//
//  File:  sm_CSInst.cpp
//  This set of C++ routines support the CSM_CSInst class.
//
// Contents: Contains CSM_CSInst member functions.
// 
// Project:  SMP/libCert
//
// Req Ref:  SMP RTM #5
//
// Last Updated:	16 December 2004                                       
//                Req Ref:  SMP RTM #5  AES Crypto++                                
//                Sue Beauchamp <Sue.Beauchamp@it.baesystems.com>        
//
////////////////////////////////////////////////////////////////////////////////
#include "sm_apiCert.h"
using namespace SNACC;
using namespace CML;


_BEGIN_CERT_NAMESPACE 

// CONSTRUCTOR FOR CSM_CSInst
//
CSM_CSInst::CSM_CSInst()
{
   Clear();
}

// DESTRUCTOR FOR CSM_CSInst
//
CSM_CSInst::~CSM_CSInst()
{
   // m_pTokenInterface must be freed by a CTI Shutdown function
   if (m_pCertificates)
      delete m_pCertificates;
   if (m_pCRLs)
      delete m_pCRLs;
   if (m_pIssuerAndSerialNumber)
      delete m_pIssuerAndSerialNumber;
   if (m_pSubjectDN)
      delete m_pSubjectDN;
   if (m_pIssOrSki)
      delete m_pIssOrSki;
   Clear();
}


// SetCertificates:
//   This method assumes all specified Certs are certificates, not
//   Attribute Certs nor Extended Certs.
void CSM_CSInst::SetCertificates(CSM_BufferLst  *pCertificateBufs)
{
   CSM_BufferLst::iterator itBufTmp;

   SME_SETUP("CSM_CSInst::SetCertificates");

   for (itBufTmp = pCertificateBufs->begin(); 
        itBufTmp != pCertificateBufs->end();
        ++itBufTmp)
   {
      if (m_pCertificates == NULL)
      {
         if ((m_pCertificates = new CSM_CertificateChoiceLst)
               == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);
      }     // END IF m_pCertificates
      CSM_CertificateChoice &tmpCert = *this->m_pCertificates->append();
      tmpCert.SetEncodedCert(*itBufTmp);
   }        // END FOR certs in list

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
}       // END CSM_CSInst::SetCertificates(...)


// SetCertificates:
//   This method assumes all specified Certs are certificates, not
//   Attribute Certs nor Extended Certs.
void CSM_CSInst::SetCertificates(CSM_CertificateChoice *pCertificateChoice)
{
   SME_SETUP("CSM_CSInst::SetCertificates");
   CSM_CertificateChoice *pCert2;

   if (AccessTokenInterface())
    AccessTokenInterface()->SMTI_Lock();  // LOCK if possible to protect
                                         //  access to m_pCRLs CURR.
   if (m_pCertificates == NULL)
      if ((m_pCertificates = new CSM_CertificateChoiceLst) == NULL)
              SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   pCert2 = &(*m_pCertificates->append());
   *pCert2 = *pCertificateChoice;
   if (AccessTokenInterface())
       AccessTokenInterface()->SMTI_Unlock();

   SME_FINISH
   SME_CATCH_SETUP
     if (AccessTokenInterface())
        AccessTokenInterface()->SMTI_Unlock();
   SME_CATCH_FINISH
}
// UpdateCertificates:
//
void CSM_CSInst::UpdateCertificates(CSM_CertificateChoiceLst *pCertificates)
{
    SME_SETUP("CSM_CSInst::UpdateCertificates");
    AccessTokenInterface()->SMTI_Lock();  // LOCK if possible to protect
                                          //  access to Curr.
    if (m_pCertificates)
        delete m_pCertificates;
    m_pCertificates = pCertificates;
    AccessTokenInterface()->SMTI_Unlock();
   SME_FINISH
   SME_CATCH_SETUP
    AccessTokenInterface()->SMTI_Unlock();
   SME_CATCH_FINISH
}

////////////////////////////////////////////////////////////////////////////////
//
//  Function Name:  UpdateCRLs(CSM_BufferLst *pCRLs)
//
//  Description:    Member function that copies the data of the input 
//                  parameter into the member variable m_pCRLs, by calling its
//                  constructor and sending in the CSM_BufferLst as an input
//                  parameter.
//
//  Inputs:         CSM_BufferLst *pCRLs 
// 
//  Outputs:        NONE
//
//  Return Value:   NONE
//
////////////////////////////////////////////////////////////////////////////////
void CSM_CSInst::UpdateCRLs(CSM_BufferLst *pCRLs)
{
   SME_SETUP("CSM_CSInst::UpdateCertificates");
   
   AccessTokenInterface()->SMTI_Lock();  // LOCK if possible to protect
   
   if (pCRLs != NULL)  // check input parameter for data to update with
   {     
      // clear old crls if any
      if (m_pCRLs != NULL)
      {
         delete m_pCRLs;
         m_pCRLs = NULL;
      }
   
      // create a new CSM_revocationInfoChoices with the CSM_BufferLst
      m_pCRLs = new CSM_RevocationInfoChoices(*pCRLs);

   }  // end if
   
   AccessTokenInterface()->SMTI_Unlock();

   SME_FINISH
   SME_CATCH_SETUP
    AccessTokenInterface()->SMTI_Unlock();
   SME_CATCH_FINISH

} // end UpdateCRLs



// SetIssuerAndSerialNumber:
//
void CSM_CSInst::SetIssuerAndSerialNumber(CSM_IssuerAndSerialNumber
            *pIssuerAndSerialNumber)
{
   SME_SETUP("CSM_CSInst::SetIssuerAndSerialNumber");

   if (m_pIssuerAndSerialNumber)
      delete m_pIssuerAndSerialNumber;
   if ((m_pIssuerAndSerialNumber = new
         CSM_IssuerAndSerialNumber(*pIssuerAndSerialNumber)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   SME_FINISH_CATCH
}

// AccessIssuerAndSerialNumber:
//
CSM_IssuerAndSerialNumber *CSM_CSInst::AccessIssuerAndSerialNumber()
{
   CSM_CertificateChoiceLst::iterator itTmpCert;
   const CSM_Buffer *pbuf=NULL;

   SME_SETUP("CSM_CSInst::AccessIssuerAndSerialNumber");

   if (m_pIssuerAndSerialNumber) // remove old if present.
   {
      delete m_pIssuerAndSerialNumber;
      m_pIssuerAndSerialNumber = NULL;
   }
   if (m_pCertificates)
   {
      for (itTmpCert =   m_pCertificates->begin(); 
           itTmpCert !=  m_pCertificates->end() && 
               (pbuf=itTmpCert->AccessEncodedCert()) == NULL;
           ++itTmpCert);
      if (itTmpCert != m_pCertificates->end())
      {                   if (itTmpCert != m_pCertificates->end())
         if ((m_pIssuerAndSerialNumber =
               new CSM_IssuerAndSerialNumber((CSM_Buffer *)pbuf)) == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      }     // END IF tmpCert
   }        // END IF m_pCertificates

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(m_pIssuerAndSerialNumber);
}


// GetRid:
//   INPUT:  NONE
//   OUTPUT:  NONE
//   RETURN:  CSM_Identifier *pRID (Result of Call to GetRid(int iStat)
CSM_Identifier *CSM_CSInst::GetRid()
{
    // GetRid WITH NO ARGUMENTS WILL RETURN BOTH IssuerAndSerialNumber
    //   AND SubjectKeyIdentifier IF THEY ARE PRESENT
    int iBoth = 2;
    return GetRid(iBoth);
}

// GetRid:
//   INPUT:  bool m_bIssOrSki (0 - SKI, 1 - Iss)
//   OUTPUT:  NONE
//   RETURN:  CSM_Identifier *pRID (Result of Call to GetRid(int iStat)
CSM_Identifier *CSM_CSInst::GetRid(bool bIssOrSki)
{
    int iStat;
    if (bIssOrSki)
        iStat = 1;
    else
        iStat = 0;    
    return GetRid(iStat);
}

// GetRid:
//   INPUT:  int iStat (0 - SKI, 1 - Iss, 2 - Both)
//   OUTPUT:  NONE
//   RETURN:  CSM_Identifier *pRID
CSM_Identifier *CSM_CSInst::GetRid(int iStat)
{
    CSM_Identifier *pRID=NULL;
    CSM_CertificateChoiceLst::iterator itTmpCert;
    const CSM_Buffer *pbuf=NULL;

    SME_SETUP("CSM_CSInst::GetRid");

    if (m_pIssuerAndSerialNumber) // remove old if present.
    {
      delete m_pIssuerAndSerialNumber;
      m_pIssuerAndSerialNumber = NULL;
    }
    if (m_pCertificates)
    {
        for (itTmpCert =  m_pCertificates->begin(); 
             itTmpCert != m_pCertificates->end() && 
                 (pbuf=itTmpCert->AccessEncodedCert()) == NULL;
             ++itTmpCert);
        if (itTmpCert != m_pCertificates->end())
        {               // If there is a User certificate.
            // IF 0 - SKI OR 2 - BOTH, LOAD SKI
            if ((iStat == 0) || (iStat == 2))
            {
                CSM_CertificateChoice gCert((CSM_Buffer &)*pbuf);
                CSM_Buffer *pSKI = gCert.GetSubjectKeyIdentifier();

                if (pSKI)
                {
                    pRID = new CSM_Identifier(*pSKI);
                    delete pSKI;
                }
            }

            // IF 1 - ISS (MIGHT BE IN ADDITION TO SKI (BOTH)), LOAD IssASN
            if ((iStat != 0) || (pRID == NULL))
            {
                // Constructor with &cert is Cert
                CSM_CertificateChoice gCert((CSM_Buffer &)*pbuf);
                //       with *cert is AttrCert
                CSM_IssuerAndSerialNumber *pIAS =
                    gCert.GetIssuerAndSerialNumber();
                if (pIAS)
                {
                    // RID MIGHT BE THERE (BOTH)
                    if (pRID)
                    {
                        pRID->SetIssuerAndSerial(*pIAS);
                    }
                    else
                    {
                        pRID = new CSM_Identifier(*pIAS);
                    }
                    delete pIAS;
                }   // END IF pIAS
            }   // END IF iStat
        }       // END IF tmpCert
    }       // END IF m_pCertificates
   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

    return pRID;
}

// GetRid:
//   INPUT:  CSM_Identifier &Rid
//   OUTPUT:  NONE
//   RETURN:  CSM_Identifier *pRID (Result of Call to GetRid(bool m_bIssOrSki)
//
CSM_Identifier *CSM_CSInst::GetRid(CSM_Identifier &Rid)
{
   bool bIss = false;
   CSM_IssuerAndSerialNumber *pTmpIssSN=NULL;

   pTmpIssSN = Rid.GetIssuerAndSerial();
   // IF INCOMING RID CONTAINS AN Issuer And Serial Number
   //   THEN SET bIss TO TRUE IF NOT THEN DEFAULTS TO false AND
   //   Recipient Identifier IS A Subject Key Identifier.
   if (pTmpIssSN)
   {
     bIss = true;
     delete pTmpIssSN;
   }

   return GetRid(bIss);
}

// AccessSubjectDN:
//
CSM_DN *CSM_CSInst::AccessSubjectDN()
{
   const SNACC::Certificate *pTmpSNACCCert=NULL;
   CSM_CertificateChoiceLst::iterator itTmpCert;

   SME_SETUP("CSM_CSInst::AccessSubjectDN");

   if (m_pCertificates != NULL)
   {
      for (itTmpCert = m_pCertificates->begin();
           itTmpCert != m_pCertificates->end();
           ++itTmpCert)
      {
         if ((pTmpSNACCCert = itTmpCert->AccessSNACCCertificate()) != NULL)
            break;
      } // END for certs in list

      if (pTmpSNACCCert != NULL) // If there is a User certificate.
      {
         if (m_pSubjectDN)
            delete m_pSubjectDN;
         m_pSubjectDN = NULL;
        if ((m_pSubjectDN = new
              CSM_DN(pTmpSNACCCert->toBeSigned.subject)) == NULL)
           SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      } // END IF pTmpSNACCCert
      pTmpSNACCCert = NULL;
   }    // END IF m_pCertificates

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return m_pSubjectDN;
}

//
//
bool CSM_CSInst::IsSigner()
{
   bool bResult = false;

   bResult = CheckSignerEncrypter(true);

   return(bResult);
}     // END CSM_CSInst::IsSigner()

//
//
bool CSM_CSInst::IsEncrypter()
{
   bool bResult = false;

   bResult = CheckSignerEncrypter(false);

   return(bResult);
}     // END CSM_CSInst::IsSigner()


//
//
bool CSM_CSInst::CheckSignerEncrypter(bool bSignerRequest)
{
    bool result=false;
    const SNACC::Certificate *pTmpSNACCCert = NULL;
    CSM_CertificateChoiceLst::iterator itTmpCert;
    CSM_AlgLstVDA *pNullValue = NULL;
    CSM_AlgLstVDA *pDigestEncryptionAlgID = NULL;
    CSM_AlgLstVDA *pEncryptionAlgID = NULL;
    CSM_AlgLstVDA *pAlgIDs = NULL;
    CSM_AlgLstVDA::iterator itAlgId;
    long count = 0;
    long i = 0;

    SME_SETUP("CSM_CSInst::IsSigner()");

    pAlgIDs = new CSM_AlgLstVDA;

   // add a generic try and catch incase GetAlgIDs throws an
   // exception.  IsSigner() should just return true or false.
   //
   if (bSignerRequest)
   {
      pDigestEncryptionAlgID = pAlgIDs;
   }
   else
   {
      pEncryptionAlgID = pAlgIDs;
   }

   try 
   {
      GetAlgIDs(pNullValue, pDigestEncryptionAlgID,
       pEncryptionAlgID, pNullValue);
   } catch(...) {  }    // IGNORE any error/exception here.

    // PIERCE it's not necessary to check oids below.  Just check to see
    // if a digest encryption algorithm is present.
    //

    // ADDED A CHECK TO BE SURE THERE IS AN ALGORITHM ID
    if ( pAlgIDs != NULL )
    {
        if ( (count = pAlgIDs->size()) > 0)
        {
           if (m_pCertificates)
           {
             itTmpCert = m_pCertificates->begin();
             if (itTmpCert != m_pCertificates->end() && 
                (pTmpSNACCCert = itTmpCert->AccessSNACCCertificate()) != NULL)
             {
               itAlgId = pAlgIDs->begin();
               for (i = 0; i < count ; i++)
               {
                 if (pTmpSNACCCert->toBeSigned.
                       subjectPublicKeyInfo.algorithm.algorithm == 
                       *itAlgId->AccessSNACCId())
                 {
                    // PERFORM final check for special case of RSA, be sure 
                    //  that keyUsage is either missing OR set explicitely for
                    //  signing (RWC; 5/29/02; added for multiple logins of
                    //  same DN but 1 for signing, 1 for encrypting).
                    if (bSignerRequest)
                    {
                      if (CheckKeyUsageBit(SNACC::KeyUsage::digitalSignature) ||
                          CheckKeyUsageBit(SNACC::KeyUsage::keyCertSign) ||
                          CheckKeyUsageBit(SNACC::KeyUsage::cRLSign))
                        result = true;
                    }
                    else
                    {
                      if (CheckKeyUsageBit(SNACC::KeyUsage::keyEncipherment) ||
                          CheckKeyUsageBit(SNACC::KeyUsage::dataEncipherment) ||
                          CheckKeyUsageBit(SNACC::KeyUsage::encipherOnly) ||
                          CheckKeyUsageBit(SNACC::KeyUsage::decipherOnly) ||
                          CheckKeyUsageBit(SNACC::KeyUsage::keyAgreement))
                        result = true;
                    }
                    break;
                 }  // END IF correct algorithm.
                 else
                    ++itAlgId;
               }    // END FOR count
             }      // END if SNACC cert.
           }    // END if certificates
           else
              result = false;    // ALLOWS verification.

        }       // END if signature algs present.
    }

    delete pAlgIDs;

#ifdef PIERCE

    tmpCert = m_pCertificates->SetCurrToFirst();
    if ((pTmpSNACCCert = tmpCert->AccessSNACCCertificate()) != NULL)
    {
        if (pTmpSNACCCert->certificateToSign->subjectPublicKeyInfo->
               algorithm->algorithm == id_dsa ||
            pTmpSNACCCert->certificateToSign->subjectPublicKeyInfo->
               algorithm->algorithm == rsa ||
            pTmpSNACCCert->certificateToSign->subjectPublicKeyInfo->
               algorithm->algorithm == AsnOid("1.2.840.113549.1.2") ||
            pTmpSNACCCert->certificateToSign->subjectPublicKeyInfo->
               algorithm->algorithm == rsaEncryption ||
            pTmpSNACCCert->certificateToSign->subjectPublicKeyInfo->
               algorithm->algorithm == AsnOid("1.2.3.4443"))
                             // MUST BE SIGNER.
           result = true;
    }

#endif
   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

    return result;
}       // END CSM_CSInst::CheckSignerEncrypter(...)

//
//
CSM_Alg *CSM_CSInst::DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert)
{               // This call interprets KARI certificate params into CMS Msg
                //  Param format for algorithms.  It is up to the CTIL to 
                //  properly interpret algorithm specific formats for both.
   CSM_Alg *pAlg=NULL;
   CSM_Alg *pCertAlg;

   SME_SETUP("CSM_CSInst::DeriveMsgAlgFromCert");
   // The incomming parameters are from the certificate using a different 
   //  ASN.1 definition than the CMS encryption format.
   if ((pCertAlg = Cert.GetPublicKeyAlg()) != NULL)
   {
       pAlg = (CSM_Alg *)this->AccessTokenInterface()->DeriveMsgAlgFromCert(*pCertAlg);
      delete pCertAlg;
   }
   else
      SME_THROW(22, "Missing PublicKeyAlg in cert.", NULL);

   SME_FINISH_CATCH
   return(pAlg);
}

//
bool CSM_CSInst::CheckKeyUsageBit(int checkBit)
{
   bool bResult = true;

   //  RWC; No lock is necessary here since the Curr() is not referenced
   //  RWC;  (it may change in a threaded application).
   SME_SETUP("CSM_CSInst::CheckKeyUsageBit");

   if (m_pCertificates && m_pCertificates->begin()->AccessSNACCCertificate())
   {
      const SNACC::Certificate *pSnaccCert = m_pCertificates->begin()->AccessSNACCCertificate();

      // The incomming parameters are from the certificate using a different 
      //  ASN.1 definition than the CMS encryption format.
      if (pSnaccCert != NULL)
      {
         const CML::ASN::Cert  Cert(*pSnaccCert);   

         if (Cert.exts.pKeyUsage) // may be null
         {
            /** KeyUsage Bits:
                     SNACC::KeyUsage::digitalSignature (0),
                     SNACC::KeyUsage::nonRepudiation   (1),
                     SNACC::KeyUsage::keyEncipherment  (2),
                     SNACC::KeyUsage::dataEncipherment (3),
                     SNACC::KeyUsage::keyAgreement     (4),
                     SNACC::KeyUsage::keyCertSign      (5),
                     SNACC::KeyUsage::cRLSign          (6),
                     SNACC::KeyUsage::encipherOnly     (7),
                     SNACC::KeyUsage::decipherOnly     (8) **/
            if (!Cert.exts.pKeyUsage->GetBit(checkBit)) 
            {
               bResult = false;
            }
         }  // END IF pCert.exts.pKeyUsage
      }     // END IF pSnaccCert
   }     // IF cert pressent.
   else
      bResult = false;     // DO NOT USE if cert missing.

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(bResult);
}       // END CSM_CSInst::CheckKeyUsageBit(...)

//
//
bool CSM_CSInst::IsTSA()
{
   bool bResult = false;


   // must check the extendedKeyUsage extension for id_kp_timeStamping 1.3.6.1.5.5.7.3.8
   // id and it must be critical

   SME_SETUP("CSM_CSInst::IsTSA");

   if (m_pCertificates && m_pCertificates->begin()->AccessSNACCCertificate())
   {
      const SNACC::Certificate *pSnaccCert = m_pCertificates->begin()->AccessSNACCCertificate();

      // The incomming parameters are from the certificate using a different 
      //  ASN.1 definition than the CMS encryption format.
      if (pSnaccCert != NULL)
      {
	   	 // using CML
         const CML::ASN::Cert  Cert(*pSnaccCert);  

         if (Cert.exts.pExtKeyUsage) // may be null
         {
		    // iterate through the extKeyUsage list
			std::list<SNACC::KeyPurposeId>::const_iterator i;
			for (i = Cert.exts.pExtKeyUsage->begin(); i != Cert.exts.pExtKeyUsage->end(); i++)
			{
				// If the key usage isn't recognized, record an error with the OID.
				// This allows the application to recognize one of the OIDs and
				// possibly continue processing
				if ((*i == gEXT_KEY_USE_timeStamping) /* sib tbd &&
					(*i.critical == true)*/ )
				{
				   bResult = true;
				}
			}
         }  // END IF pCert.exts.pExtKeyUsage
      }     // END IF pSnaccCert
   }     // IF cert pressent.

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(bResult);
}     // END CSM_CSInst::IsSigner()

//
//
const CSM_CertificateChoice *CSM_CSInst::AccessUserCertificate()
{
    //  RWC; No lock is necessary here since the Curr() is not referenced
    //  RWC;  (it may change in a threaded application).
    const CSM_CertificateChoice *pCert=NULL;
    
    if (m_pCertificates)
       pCert = &(*m_pCertificates->begin());
    return pCert;
}       // END CSM_CSInst::AccessUserCertificate()

//
//
void CSM_CSInst::LoadCertificates(CSM_MsgCertCrls *&pMsgCertCrls)
{
    SME_SETUP("CSM_CSInst::SetCertificates");

    if (pMsgCertCrls == NULL)
        pMsgCertCrls = new CSM_MsgCertCrls;
    
    if (m_pCertificates)
    {
        AccessTokenInterface()->SMTI_Lock();// LOCK if possible to protect
                                            //  access to m_pCertificates CURR.
        pMsgCertCrls->SetCertificates(m_pCertificates);
        AccessTokenInterface()->SMTI_Unlock();
    }


   SME_FINISH
   SME_CATCH_SETUP
    AccessTokenInterface()->SMTI_Unlock();
   SME_CATCH_FINISH

}       // END CSM_CSInst::LoadCertificates()


//
//
void CSM_CSInst::LoadCRLs(RevocationInfoChoices *&pSNACCCrls)
{

   SME_SETUP("CSM_CSInst::LoadCRLs");

   AccessTokenInterface()->SMTI_Lock();  // LOCK if possible to protect
                                          //  access to m_pCRLs CURR.

   pSNACCCrls = m_pCRLs->GetSNACCRevInfoChoices();

   AccessTokenInterface()->SMTI_Unlock();

   SME_FINISH
   SME_CATCH_SETUP
    AccessTokenInterface()->SMTI_Unlock();
   SME_CATCH_FINISH
}       // END CSM_CSInst::LoadCRLs(...)


_END_CERT_NAMESPACE 

// EOF sm_CSInst.cpp
