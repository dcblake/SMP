
//////////////////////////////////////////////////////////////////////////
// sm_MsgCertCrls.cpp
// methods for the CSM_MsgCertCrls class

#include "sm_apiCert.h"
_BEGIN_CERT_NAMESPACE 
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
CSM_MsgCertCrls::~CSM_MsgCertCrls()
{
   ClearCerts();
   ClearACs();
   ClearCRLLst(); 
   ClearOtherCertFormats();
   ClearExtCerts();
}
//////////////////////////////////////////////////////////////////////////
void CSM_MsgCertCrls::ClearCerts()
{
   if (m_pCerts)
   {
      delete (m_pCerts);
      m_pCerts = NULL;
   }
}

//////////////////////////////////////////////////////////////////////////
void CSM_MsgCertCrls::ClearACs()
{
   if (m_pACs)
   {
      delete (m_pACs);
      m_pACs = NULL;
   }
}

//////////////////////////////////////////////////////////////////////////
void CSM_MsgCertCrls::ClearOtherCertFormats()
{
   if (m_pOtherCertFormats)
   {
      delete (m_pOtherCertFormats);
      m_pOtherCertFormats = NULL;
   }
}


//////////////////////////////////////////////////////////////////////////
void CSM_MsgCertCrls::ClearExtCerts()
{
   if (m_pExtCerts)
   {
      delete (m_pExtCerts);
      m_pExtCerts = NULL;
   }
}
//////////////////////////////////////////////////////////////////////////
void CSM_MsgCertCrls::ClearCRLLst()
{
    if (m_pCRLLst)
    {
        delete (m_pCRLLst);
        m_pCRLLst = NULL;
    }
}
//////////////////////////////////////////////////////////////////////////
// SetCertificates COPIES the Buffers from the provided buffer list into
// a list of cert choice classes.  In other words, each buffer from the
// provided list is duplicated and added to or placed into a new list
// of cert choice classes.  Therefore, the caller can delete the provided
// buffer list after SetCertificates returns
void CSM_MsgCertCrls::SetCertificates(CSM_BufferLst *pCerts)
{
   CSM_BufferLst::iterator itBufTemp;
   CSM_CertificateChoice *pTmpNewCert;

   SME_SETUP("CSM_MsgCertCrls::SetCertificates(CSM_BufferLst*)");

   if (pCerts)
   {
      for (itBufTemp =  pCerts->begin();
           itBufTemp != pCerts->end();
           ++itBufTemp)
      {
         // place the new buffer (cert) into a CSM_CertificateChoice
         // create a new list of CSM_CertificateChoices if necessary
         if (m_pCerts == NULL)
         {
            if ((m_pCerts = new CSM_CertificateChoiceLst) 
                  == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
         }
         // add the cert choice to the end of the list
         if ((pTmpNewCert = &(*m_pCerts->append())) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
         pTmpNewCert->SetEncodedCert(*itBufTemp);
      }         // END FOR each cert buffer.
   }
   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
// SetCertificates COPIES the CertChoices from the provided list into
// the right list of cert choice classes.  In other words, each cert choice
// from the provided list is duplicated and added or placed into a new
// list of cert choice classes depending on the type of the given
// cert choice (cert or AC), therefore, the caller can delete the provided
// cert choice list after SetCertificates returns
void CSM_MsgCertCrls::SetCertificates(CSM_CertificateChoiceLst *pCerts)
{
   CSM_CertificateChoiceLst::iterator itCert;

   SME_SETUP("CSM_MsgCertCrls::SetCertificates(CSM_CertificateChoiceLst*)");

   if (pCerts)
   {
      for (itCert =  pCerts->begin();
           itCert != pCerts->end();
           ++itCert)
      {
         CSM_CertificateChoice *pNewCert = new CSM_CertificateChoice(*itCert);
         SME(AddCert(pNewCert));
         delete pNewCert; 
      }         // END FOR each cert in list.
   }
   SME_FINISH_CATCH
}
//////////////////////////////////////////////////////////////////////////
// SetCRLLst COPIES the CSM_RevocationInfoChoices from the provided list into
// the object's CSM_CertificateListLst member variable.  In other words, 
// each RevocationInfoChoice from the provided list is duplicated and added 
// or placed into a new list of CSM_RevocationInfoChoices, therefore, the 
//////////////////////////////////////////////////////////////////////////
void CSM_MsgCertCrls::SetCRLLst(CSM_RevocationInfoChoices *pCRLs)
{
   List<CSM_RevocationInfoChoice>::iterator iRevInfo; // list iterator

   SME_SETUP("CSM_MsgCertCrls::SetCRLLst(CSM_RevocationInfoChoices*)");

   if (pCRLs)
   {
      for (iRevInfo =  pCRLs->begin();
           iRevInfo != pCRLs->end();
           ++iRevInfo)
      {
         // add the new RevocationInfoChoice to the list
         SME(AddCRL(&*iRevInfo));

      }  // END FOR each RevocationInfoChoice in list.
   }
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// AddCert adds the provided cert to the m_pCerts, m_pACs, other,
// or extendedCert according to the type of the provided cert.  This 
// function no longer deletes the input parameter pCert
void CSM_MsgCertCrls::AddCert(CSM_CertificateChoice *pCert)
{
   CSM_Identifier *pRID=NULL;
   CSM_CertificateChoice *pCertAlreadyHere=NULL;
   bool bLoadCert=true;

   SME_SETUP("CSM_MsgCertCrls::AddCert");

   // check if we have snacc OtherCertFormat, v1AttrCert or ExtendedCert
   // this will fill in the corresponding member from the snacc member
   // then bypass getting the rid and cert
   if (pCert->AccessSNACCOtherCertificateFormat() != NULL)
   {
      // load m_pOtherCertFormat
      if (pCert->AccessEncodedOther() != NULL)
      {
         // create a new list of CSM_CertificateChoices if necessary
         if (m_pOtherCertFormats == NULL)
            if ((m_pOtherCertFormats = new CSM_CertificateChoiceLst) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);

         // determine if this OtherCertificateFormat is already in 
         // the list
         CSM_CertificateChoiceLst::iterator itCert;
         for (itCert =  m_pOtherCertFormats->begin(); 
              itCert != m_pOtherCertFormats->end(); ++itCert)
         {
            if (*pCert->AccessEncodedOther() == *(*itCert).AccessEncodedOther())
            {
               bLoadCert = false;
            }
         }

         // add the cert choice to the end of the list
         if (bLoadCert == true)
         {
            m_pOtherCertFormats->append(*pCert);
         }
      } // end if AccessEncodedOther
   }
   else if (pCert->AccessSNACCExtendedCertificate() != NULL)
   {
      // load m_pExtCerts
      if (pCert->AccessEncodedExtCert() != NULL)
      {
         // create a new list of CSM_CertificateChoices if necessary
         if (m_pExtCerts == NULL)
            if ((m_pExtCerts = new CSM_CertificateChoiceLst) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);

        // determine if this ExtendedCertificate is already in 
         // the list
         CSM_CertificateChoiceLst::iterator itCert;
         for (itCert =  m_pExtCerts->begin(); 
              itCert != m_pExtCerts->end(); ++itCert)
         {
            if (*pCert->AccessEncodedExtCert() == *(*itCert).AccessEncodedExtCert())
            {
               bLoadCert = false;
            }
         }

         // add the cert choice to the end of the list
         if (bLoadCert == true)
         {
            m_pExtCerts->append(*pCert);
         }

      }
   }
   else
   {
      // check to see if the cert and/or attributeCert is already in the list
      pRID = pCert->GetRid(true);
      if (pRID)
      {
         pCertAlreadyHere = FindCert(*pRID);
         delete pRID;
      }
      if (pCertAlreadyHere == NULL && pCert->AccessSNACCAttrCertificate())
      {            // TRY looking for Attr cert specifically, if possible.
          pCertAlreadyHere = FindCert(*pCert);
      }
      // depending on the type, add it accordingly
      if (pCertAlreadyHere)      // MAY not be loading this new cert, already here.
      {              // CHECK that the certs/ACs are consistent.
          if (pCertAlreadyHere->AccessEncodedCert() && //Be sure both certs.
              pCert->AccessEncodedCert())
              bLoadCert = false;    // not opposite AC.
          else if (pCertAlreadyHere->AccessEncodedAttrCert() && //Be sure both ACs.
              pCert->AccessEncodedAttrCert())
              bLoadCert = false;    // not opposite cert.
          delete pCertAlreadyHere;
          pCertAlreadyHere = NULL;
      }
      // load the m_pCerts member if there is one
      if (bLoadCert && pCert->AccessEncodedCert() != NULL)
      {
         // create a new list of CSM_CertificateChoices if necessary
         if (m_pCerts == NULL)
            if ((m_pCerts = new CSM_CertificateChoiceLst) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         // add the cert choice to the end of the list
         m_pCerts->append(*pCert);
      }
      // load the m_pACs member if there is one
      else if (bLoadCert && pCert->AccessEncodedAttrCert() != NULL)

      {
         // create a new list of CSM_CertificateChoices if necessary
         if (m_pACs == NULL)
            if ((m_pACs = new CSM_CertificateChoiceLst) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);
         // add the cert choice to the end of the list
         m_pACs->append(*pCert);
      }
   }

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
// AddCRL adds the provided RevInfoChoice to the m_pCRLLst.  
//  
void CSM_MsgCertCrls::AddCRL(CSM_RevocationInfoChoice* pCRL)
{
   bool bFound=false;
   List<CSM_RevocationInfoChoice>::iterator itTmpCRL;

   SME_SETUP("CSM_MsgCertCrls::AddCRL");

   if (m_pCRLLst == NULL)
   {
      if ((m_pCRLLst = new CSM_RevocationInfoChoices) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
   }

   // check if crl is in the list
   for (itTmpCRL =  m_pCRLLst->begin(); 
        itTmpCRL != m_pCRLLst->end() && !bFound; 
        ++itTmpCRL)
   {
      if (itTmpCRL->AccessEncodedRevInfo() == pCRL->AccessEncodedRevInfo())
          bFound = true;
   }

   // if crl not in list add it
   if (!bFound)
   {
       // add the crl to the end of the list
       m_pCRLLst->push_back(*pCRL);
   }


   SME_FINISH_CATCH
}
//////////////////////////////////////////////////////////////////////////
// PutSNACCCerts ASN.1 decodes the m_pCerts, Attribute Certificates, AND
//  OtherCertificateFormat
//  then returns them in the provided pCertificateSet
void CSM_MsgCertCrls::PutSNACCCerts(CertificateSet *&pCertificateSet)
{
   CSM_CertificateChoiceLst::iterator itCert;
   AttributeCertificate*              pSNACCAttrCert = NULL;
   Certificate*                       pSNACCCert = NULL;
   OtherCertificateFormat*            pSNACCOther = NULL;
   AsnAny*                            pSNACCAny = NULL;
   ExtendedCertificate*               pSNACCExtCert = NULL;

   SME_SETUP("CSM_MsgCertCrls::PutSNACCCerts");

   if (pCertificateSet == NULL)    // initialize for application
      if ((pCertificateSet = new CertificateSet) == NULL)
            SME_THROW(SM_MEMORY_ERROR, 
                  "SNACC Certificate bad memory alloc", NULL);

   if (pCertificateSet)
   {
      // we can only do this if we have ASN.1 encoded certs
      if (m_pCerts)
      {
         // loop through the m_pCerts here
         for (itCert =  m_pCerts->begin();
              itCert != m_pCerts->end();
              ++itCert)
         { // For each cert buffer, load into SNACC cert list.
           CertificateChoices &tmnSNACCCertChoices = *pCertificateSet->append();

            // do a regular cert
            if ((pSNACCCert = itCert->GetSNACCCertificate()) != NULL)
            {
               // set the type to cert
               tmnSNACCCertChoices.choiceId = 
                     CertificateChoices::certificateCid;
               // allocate a snacc cert class
               tmnSNACCCertChoices.certificate = pSNACCCert;
            }
         }  // END for each cert in list
      }     // END IF m_pCerts

      if (m_pACs)
      {
         for (itCert =  m_pACs->begin(); 
              itCert != m_pACs->end();
              ++itCert)
         { // For each cert buffer, load into SNACC cert list.
            CertificateChoices &tmnSNACCCertChoices = *pCertificateSet->append();
            // do an attribute cert
            if ((pSNACCAttrCert = itCert->GetSNACCAttrCertificate()) 
                     != NULL)
            {
               if (pSNACCAttrCert->toBeSigned.issuer.choiceId == 
                     AttCertIssuer::v1FormCid)
               {
                  // set the type to attribute cert
                  tmnSNACCCertChoices.choiceId = 
                        CertificateChoices::v1AttrCertCid;
                  // allocate a snacc attribute cert class
                  tmnSNACCCertChoices.v1AttrCert = pSNACCAttrCert;
               }
               else if (pSNACCAttrCert->toBeSigned.issuer.choiceId == 
                  AttCertIssuer::v2FormCid)
               {
                  // set the type to attribute cert
                  tmnSNACCCertChoices.choiceId = 
                        CertificateChoices::v2AttrCertCid;
                  // allocate a snacc attribute cert class
                  tmnSNACCCertChoices.v2AttrCert = pSNACCAttrCert;
               }
            }
            // extended cert not handled
         }  // END for each Attribute cert in list
      }     // END IF m_pAttrCerts


      if (m_pOtherCertFormats)
      {
         for (itCert =  m_pOtherCertFormats->begin(); 
              itCert != m_pOtherCertFormats->end();
              ++itCert)
         { // For each cert buffer, load into SNACC cert list.
            CertificateChoices &tmnSNACCCertChoices = *pCertificateSet->append();
            // do an attribute cert
            if ((pSNACCOther = itCert->GetSNACCOtherCertificateFormat()) 
                     != NULL)
            {
               // set the type to attribute cert
               tmnSNACCCertChoices.choiceId = 
                     CertificateChoices::otherCid;
               // allocate a snacc attribute cert class
               tmnSNACCCertChoices.other = pSNACCOther;
            }

         }  // END for each otherCertificateFormat in list
      }     // END IF m_pOtherCertFormats

      // add extended certs  
      if (m_pExtCerts)
      {
         for (itCert =  m_pExtCerts->begin(); 
              itCert != m_pExtCerts->end();
              ++itCert)
         { // For each cert buffer, load into SNACC cert list.
            CertificateChoices &tmnSNACCCertChoices = *pCertificateSet->append();
            // do an attribute cert
            if ((pSNACCExtCert = itCert->GetSNACCExtendedCertificate()) 
                     != NULL)
            {
               // set the type to attribute cert
               tmnSNACCCertChoices.choiceId = 
                     CertificateChoices::extendedCertificateCid;
               // allocate a snacc attribute cert class
               tmnSNACCCertChoices.extendedCertificate = pSNACCExtCert;
            }
            // extended cert not handled
         }  // END for each Attribute cert in list
      }     // END IF m_pExtCerts  
   }        // END IF pCertificateSet
   SME_FINISH_CATCH
}       // END CSM_MsgCertCrls::PutSNACCCerts(...)


//////////////////////////////////////////////////////////////////////////
// PutSNACCCRLLst ASN.1 decodes the m_pCRLLst and returns them in the
// provided pCRLLst parameter
void CSM_MsgCertCrls::PutSNACCCRLLst(RevocationInfoChoices*& pCRLLst)
{     
   SME_SETUP("CSM_MsgCertCrls::PutSNACCCRLLst");

   if (m_pCRLLst != NULL && pCRLLst == NULL)    // initialize for application
      if ((pCRLLst = new RevocationInfoChoices) == NULL)
         SME_THROW(SM_MEMORY_ERROR, 
                   "SNACC RevocationInfoChoices bad memory alloc", NULL);

   // we can only do this if we have ASN.1 encoded crls
   if (m_pCRLLst != NULL)
   {
      pCRLLst = m_pCRLLst->GetSNACCRevInfoChoices();
   }

   SME_FINISH_CATCH
}       // END CSM_MsgCertCrls::PutSNACCCRLLst(...)



//////////////////////////////////////////////////////////////////////////
// SetSNACCCerts places the provided snacc decoded certs
// into this appropriately
void CSM_MsgCertCrls::SetSNACCCerts(CertificateSet *pCertificateSet)
{
    CertificateSet::iterator piTmpSNACCCert;
   CSM_CertificateChoice *pCertChoice;

   SME_SETUP("CSM_MsgCertCrls::SetSNACCCerts");

   if (pCertificateSet == NULL)
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   for (piTmpSNACCCert = pCertificateSet->begin();
        piTmpSNACCCert != pCertificateSet->end(); ++piTmpSNACCCert)
   {
      if ((pCertChoice = new CSM_CertificateChoice(*piTmpSNACCCert)) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      SME(AddCert(pCertChoice));
      delete pCertChoice; 
   }
   SME_FINISH
   SME_CATCH_SETUP
      // local cleanup logic
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
// SetSNACCCRLLst COPIES the snacc CRLs provided in  
// RevocationInfoChoices into a list of CSM_RevocationInfoChoices. This 
// gives the caller access to functions in CSM_RevocationInfoChoice that 
// allow her to retrieve specific data in the CSM_RevocationInfoChoice.
void CSM_MsgCertCrls::SetSNACCCRLst(RevocationInfoChoices *pRevInfoChoices)
{
   List<AsnAny>::iterator iTmpSNACCCRL;
   CSM_RevocationInfoChoice* pTmpRevInfoChoice = NULL;

   SME_SETUP("CSM_MsgCertCrls::SetSNACCCRLst");

   if (pRevInfoChoices == NULL)
        SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // clear out old list if any
   if (m_pCRLLst != NULL)
   {
      delete m_pCRLLst;
      m_pCRLLst = NULL;
   }

   // create a new list
   m_pCRLLst = new CSM_RevocationInfoChoices;
   
   if (m_pCRLLst == NULL)
   {
      SME_THROW(SM_MEMORY_ERROR, "Memory error with CSM_RevocationInfoChoices",
         NULL);
   }

   for (iTmpSNACCCRL = pRevInfoChoices->begin();
        iTmpSNACCCRL != pRevInfoChoices->end(); ++iTmpSNACCCRL)
   {   
      // for each RevInfoChoice create a CSM_RevocationInfoChoice to add to the list
      pTmpRevInfoChoice = new CSM_RevocationInfoChoice(*iTmpSNACCCRL);
      if (pTmpRevInfoChoice == NULL)
            SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
       SME(AddCRL(pTmpRevInfoChoice));
       delete pTmpRevInfoChoice; 
   }

    SME_FINISH
    SME_CATCH_SETUP

    SME_CATCH_FINISH
}



//////////////////////////////////////////////////////////////////////////
// this method returns a pointer to the specific requested certificate,
//  IMPORTANT:  The application MUST not free the memory pointer returned.
CSM_CertificateChoice *CSM_MsgCertCrls::FindCert(CSM_Buffer &SKI)
{
   CSM_CertificateChoice *pCert=NULL;
   
   SME_SETUP("CSM_MsgCertCrls::FindCert(CSM_Buffer &SKI)");

   CSM_Identifier RID(SKI);
   pCert = FindCert(RID);
      SME_FINISH_CATCH

   return(pCert);
}

//////////////////////////////////////////////////////////////////////////
// this method returns a pointer to the specific requested certificate,
//  IMPORTANT:  The application MUST not free the memory pointer returned.
CSM_CertificateChoice *CSM_MsgCertCrls::FindCert(CSM_IssuerAndSerialNumber
&IssSN)
{
   CSM_CertificateChoice *pCert=NULL;
 
   SME_SETUP("CSM_MsgCertCrls::FindCert(CSM_IssuerAndSerialNumber &IssSN)");

   CSM_Identifier RID(IssSN);
   pCert = FindCert(RID);
      SME_FINISH_CATCH

   return(pCert);
}

//////////////////////////////////////////////////////////////////////////
// this method returns a pointer to the specific requested certificate,
//  IMPORTANT:  The application MUST not free the memory pointer returned.
CSM_CertificateChoice *CSM_MsgCertCrls::FindCert(CSM_Identifier &RID)
{
   CSM_CertificateChoiceLst *pCerts = NULL;
   CSM_CertificateChoice    *pResultCert=NULL;
   CSM_Identifier  *pTmpRID;

   SME_SETUP("CSM_MsgCertCrls::FindCert(CSM_Identifier &RID)");

   // move certs from this to pRet
   if ((pCerts = AccessCertificates()) != NULL)
   {
       CSM_CertificateChoiceLst::iterator itCert;
       for (itCert =  pCerts->begin();
            itCert != pCerts->end();
            ++itCert)
      {
         SME(pTmpRID = itCert->GetRid(RID));
         if (pTmpRID)
         {
            if (*pTmpRID == RID)
            {
               delete pTmpRID;
               pTmpRID = NULL;
               break;
            }
            else
            {
               if (pTmpRID)
                  delete pTmpRID;
            }
         }   
         
      }     // END FOR each cert in list
      if (itCert != pCerts->end())
         pResultCert = new CSM_CertificateChoice (*itCert);
   }

   SME_FINISH_CATCH

   return(pResultCert);
}           // END CSM_MsgCertCrls::FindCert(CSM_Identifier &RID)

//////////////////////////////////////////////////////////////////////////
CSM_CertificateChoice *CSM_MsgCertCrls::FindCert(CSM_DN &DN)
{
   CSM_CertificateChoiceLst *pCerts = NULL;
   CSM_CertificateChoice    *pResultCert=NULL;
   CSM_DN  *pTmpDN;

   SME_SETUP("CSM_MsgCertCrls::FindCert(CSM_DN &DN)");

   // move certs from this to pRet
   if ((pCerts = AccessCertificates()) != NULL)
   {
       CSM_CertificateChoiceLst::iterator itCert;
       for (itCert =  pCerts->begin();
            itCert != pCerts->end();
            ++itCert)
      {
         SME(pTmpDN = itCert->GetSubject());
         if (pTmpDN)
         {
            if (*pTmpDN == DN)
            {
               delete pTmpDN;
               break;
            }
            else
            {
               if (pTmpDN)
                  delete pTmpDN;
            }
         }   
      }     // END FOR each cert in list
      if (itCert != pCerts->end())
         pResultCert = new CSM_CertificateChoice (*itCert);
   }

   SME_FINISH_CATCH

   return(pResultCert);
}       // END CSM_MsgCertCrls::FindCert(CSM_DN &DN)

//////////////////////////////////////////////////////////////////////////
CSM_CertificateChoice *CSM_MsgCertCrls::FindCert(CSM_CertificateChoice &AttrCert)
{
   CSM_CertificateChoiceLst *pCerts = NULL;
   CSM_CertificateChoice    *pResultCert=NULL;

   SME_SETUP("CSM_MsgCertCrls::FindCert(CSM_CertificateChoice &AttrCert)");

   if (AttrCert.AccessEncodedAttrCert() == NULL)
       return(pResultCert); // IGNORE if not available.

   // move certs from this to pRet
   if ((pCerts = this->AccessACs()) != NULL)
   {
       CSM_CertificateChoiceLst::iterator itCert;
       for (itCert =  pCerts->begin();
            itCert != pCerts->end();
            ++itCert)
      {
         if (itCert->AccessEncodedAttrCert()  && 
            *itCert->AccessEncodedAttrCert() == *AttrCert.AccessEncodedAttrCert())
         {
                 break;
         }      // END IF pointer available
      }     // END FOR each cert in list.
      if (itCert != pCerts->end())
         pResultCert = new CSM_CertificateChoice (*itCert);
   }

   SME_FINISH_CATCH

   return(pResultCert);
}       // END CSM_MsgCertCrls::FindCert(SNACC::AttributeCertificateInfoChoice *pSNACCEitherHolder)


//////////////////////////////////////////////////////////////////////////
// UpdateParams
// This method attempts to load DSA ONLY algorithm parameters from the 
//  specified certificate.  If not found, it attempts to search the internal
//  list for the issuer and so on.
bool CSM_MsgCertCrls::UpdateParams(CSM_Alg &alg, CSM_CertificateChoice &Cert, CSM_DN *pTopDN)
{
    bool bResult=false;
    CSM_CertificateChoice *pCert = NULL;
    CSM_Buffer *pCBuf=NULL;
    CSM_IssuerAndSerialNumber *pIssSN;
     CSM_DN *pSubjectDN;
    
    SME_SETUP("CSM_MsgCertCrls::UpdateParams");

//	changed by DHT ( cryptovision ) , 2k+1.05.17
//	change was neccesary for ECDSA-support.
//
//	  if ((alg.algorithm == id_dsa || alg.algorithm == id_dsa_with_sha1 ||
//         alg.algorithm == *CSM_Alg(tmpoid).AccessSNACCId()) &&
//              alg.HasNullParams())        // Attempt to search cert path.
//
	if ( alg.HasNullParams() )           // Attempt to search cert path.
    {
      // FIRST, the user certificate (passed-in as an argument in Cert) will be
      // checked for the parameters.  NEXT, if the parameters are not found, we 
      // will go up the cert-path until they are found OR we run-out of certs.
        pCert = &Cert;

        while (!bResult && pCert)
        {        
         // Search for parameters
         if (pCert->AccessSNACCCertificate()->toBeSigned.
                    subjectPublicKeyInfo.algorithm.parameters)
            {
                SM_EXTRACT_ANYBUF(pCBuf, pCert->AccessSNACCCertificate()->toBeSigned.
                           subjectPublicKeyInfo.algorithm.parameters);

                if (alg.parameters)
                  delete alg.parameters;
                  //RWC;11/14/02;delete (AsnAnyBuffer *)alg.parameters->value;
                //RWC;11/14/02;else
                alg.parameters = new AsnAny;

                SM_ASSIGN_ANYBUF(pCBuf, alg.parameters);
                delete pCBuf;
                pCBuf = NULL;
                bResult = !alg.HasNullParams();
            }

            if (!bResult)
            {
              if ((pIssSN = pCert->GetIssuerAndSerialNumber()) != NULL)
              {
               // Get the subjectDN for the issuer so we can use it 
               // in FindCert.
               pSubjectDN = pIssSN->GetIssuer();
               CSM_DN *pActualSubjectDN=pCert->GetSubject();
               if (*pSubjectDN == *pActualSubjectDN)
               {
                   delete pActualSubjectDN;
                   if (pCert != &Cert)     // Ignore first Cert.
                      delete pCert;
                   if (pSubjectDN)
                      delete pSubjectDN;
                   delete pIssSN;
                   break;           // FINISHED.
               }
               else
                   delete pActualSubjectDN;

               if (pCert != &Cert)     // Ignore first Cert.
                  delete pCert;
   
               if (pSubjectDN && pTopDN)
               {
                  *pTopDN = *pSubjectDN;
               }

               pCert = FindCert(*pSubjectDN); 

               if (pSubjectDN)
                  delete pSubjectDN;
               delete pIssSN;
              }
              else
              {
                 pCert = NULL;
              }
            }
            else
            {
                if (pCert != &Cert)     // Ignore first Cert.
                {
                    delete pCert;
                    pCert = NULL;
                }
            }
       }
    }

   SME_FINISH_CATCH

   return(bResult);
}       // END CSM_MsgCertCrls::UpdateParams(...)


//////////////////////////////////////////////////////////////////////////
// this method builds a SM_StrLst of the ASN.1 encoded certs and ACs in
// this object
SM_StrLst* CSM_MsgCertCrls::GetStrLstOfCerts()
{
   SM_StrLst *pRet = NULL;
   SM_StrLst *pTemp = NULL;
   CSM_CertificateChoiceLst *pCerts;
   CSM_CertificateChoiceLst::iterator itCert;

   SME_SETUP("CSM_MsgCertCrls::GetStrLstOfCerts");

   // move certs from this to pRet
   if ((pCerts = AccessCertificates()) != NULL)
   {
      for (itCert =  pCerts->begin();
           itCert != pCerts->end();
           ++itCert)
      {
         // allocate memory for the ASN.1 encoded cert
         if (pTemp)
         {
            pTemp->pNext = (SM_StrLst *)calloc(1, sizeof(SM_StrLst));
            pTemp = pTemp->pNext;
         }
         else
            pTemp = pRet = (SM_StrLst *)calloc(1, sizeof(SM_StrLst));
         if (pTemp == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);
         SME(pTemp->str.pchData = itCert->AccessEncodedCert()->
               Get(pTemp->str.lLength));
      }     // END FOR each cert in list.
   }

   // move ACs from this to pRet
   if ((pCerts = AccessACs()) != NULL)
   {
      for (itCert =  pCerts->begin();
           itCert != pCerts->end();
           ++itCert)
      {
         // allocate memory for the ASN.1 encoded cert
         if (pTemp)
         {
            pTemp->pNext = (SM_StrLst *)calloc(1, sizeof(SM_StrLst));
            pTemp = pTemp->pNext;
         }
         else
            pTemp = pRet = (SM_StrLst *)calloc(1, sizeof(SM_StrLst));
         if (pTemp == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY ALLOCATION ERROR", NULL);

         SME(pTemp->str.pchData = itCert->AccessEncodedAttrCert()->
               Get(pTemp->str.lLength));
      }     // END FOR each AC in list.
   }

   SME_FINISH_CATCH

   return pRet;
}

_END_CERT_NAMESPACE 

// EOF sm_MsgCertCrls.cpp
