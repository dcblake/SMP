
//////////////////////////////////////////////////////////////////////////
// sm_certChoice.cpp
// methods for the CSM_CertificateChoice class

#include "sm_apiCert.h"
using namespace SNACC;
using SNACC::SnaccException;
_BEGIN_CERT_NAMESPACE 
//////////////////////////////////////////////////////////////////////////
// clear method
void CSM_CertificateChoice::Clear()
{
   m_pCert                 = NULL;
   m_pAttrCert             = NULL;
   m_pOther                = NULL;
   m_pExtCert              = NULL;
   m_pSNACCCert            = NULL;
   m_pSNACCAttrCert        = NULL;
   m_pSNACCOtherCertFormat = NULL;
   m_pSNACCExtCert         = NULL;
   m_bIssOrSki             = true;
}

//////////////////////////////////////////////////////////////////////////
void CSM_CertificateChoice::ClearAllMembers()
{
   // free memory if necessary
   if (m_pCert)
      delete m_pCert;      
   m_pCert = NULL;

   if (m_pAttrCert)
      delete m_pAttrCert;      
   m_pAttrCert = NULL;

   if (m_pOther)
      delete m_pOther;      
   m_pOther = NULL;

   if (m_pExtCert)
      delete m_pExtCert;      
   m_pExtCert = NULL;

   if (m_pSNACCCert)
      delete m_pSNACCCert;      
   m_pSNACCCert = NULL;

   if (m_pSNACCAttrCert)
      delete m_pSNACCAttrCert;      
   m_pSNACCAttrCert = NULL;

   if (m_pSNACCOtherCertFormat)
      delete m_pSNACCOtherCertFormat;      
   m_pSNACCOtherCertFormat = NULL;

   if (m_pSNACCExtCert)
      delete m_pSNACCExtCert;      
   m_pSNACCExtCert = NULL;
}

//////////////////////////////////////////////////////////////////////////
CSM_CertificateChoice::CSM_CertificateChoice(const Certificate &SNACCCert)
{
   Clear();
   m_pSNACCCert = new Certificate;
   *m_pSNACCCert = SNACCCert;
}

//////////////////////////////////////////////////////////////////////////
CSM_CertificateChoice::CSM_CertificateChoice(const CSM_Buffer &Cert)
{
   Clear();
   SetEncodedCert(Cert);
}

//////////////////////////////////////////////////////////////////////////
CSM_CertificateChoice::CSM_CertificateChoice(const CertificateChoices &SNACCCertChoices)
{
   Clear();
   SetSNACCCertChoices(SNACCCertChoices);
}

//////////////////////////////////////////////////////////////////////////
CSM_CertificateChoice::CSM_CertificateChoice(const CSM_CertificateChoice &certChoice)
{
   Clear();
   const CSM_Buffer *pBuf=certChoice.AccessEncodedCert();
   const CSM_Buffer *pAttrBuf=certChoice.AccessEncodedAttrCert();
   const CSM_Buffer *pOtherBuf = certChoice.AccessEncodedOther();
   const CSM_Buffer *pExtCertBuf = certChoice.AccessEncodedExtCert();


   if (pBuf)
     m_pCert = new CSM_Buffer(*pBuf);
   if (pAttrBuf)
    m_pAttrCert = new CSM_Buffer(*pAttrBuf);

   // if there is other data input, copy it
   if (pOtherBuf != NULL)
      m_pOther = new CSM_Buffer(*pOtherBuf);

   // if there is extCert data input, copy it
   if (pExtCertBuf != NULL)
      m_pExtCert = new CSM_Buffer(*pExtCertBuf);   

}

//
//
CSM_CertificateChoice::CSM_CertificateChoice(char *lpszFile, long choiceId)
{

   SME_SETUP("CSM_CSInst::CSM_CertificateChoice(char *,long)");

   Clear();

   const CSM_Buffer tmpBuf(lpszFile);

   if (choiceId == CertificateChoices::certificateCid)
   {
      SetEncodedCert(tmpBuf);
   }
   else if ( (choiceId == CertificateChoices::v2AttrCertCid) ||
             (choiceId == CertificateChoices::v1AttrCertCid) )
   {
      SetEncodedAttrCert(tmpBuf);
   }
   else if (choiceId == CertificateChoices::otherCid)  // otherCid = 4
   {
      SetEncodedOther(tmpBuf);
   }  
   else if (choiceId == CertificateChoices::extendedCertificateCid)  
   {
      SetEncodedExtCert(tmpBuf);      
   }
   else
   {
      SME_THROW(28, "Bad SNACC::CertificateChoices::??:?Cid value", NULL);
   }
   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
CSM_CertificateChoice::~CSM_CertificateChoice()
{
   // free memory if necessary
   ClearAllMembers();

}

//////////////////////////////////////////////////////////////////////////
void CSM_CertificateChoice::SetEncodedCert(const CSM_Buffer &Cert)
{
   SME_SETUP("CSM_CertificateChoice::SetEncodedCert");

   ClearAllMembers();

   m_pCert = new CSM_Buffer;
   *m_pCert = Cert;

   AccessSNACCCertificate();

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
}

//////////////////////////////////////////////////////////////////////////
void CSM_CertificateChoice::SetEncodedAttrCert(const CSM_Buffer &AttrCert)
{
   SME_SETUP("CSM_CertificateChoice::SetEncodedAttrCert");

   ClearAllMembers();

   m_pAttrCert = new CSM_Buffer;
   *m_pAttrCert = AttrCert;
   AccessSNACCAttrCertificate();

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     SetEncodedOther
// 
// Description:  Processing sets member variables to NULL and then 
//               obtains memory for m_pOther member variable and then
//               assigns input buffer, "Other" into the m_pOther member
//               variable
//
// Inputs:       CSM_Buffer& data containing OtherCertificateFormat
//
// Outputs:      NONE
// 
// Returns:      NONE
//
////////////////////////////////////////////////////////////////////////////////
void CSM_CertificateChoice::SetEncodedOther(const CSM_Buffer &Other)
{
   SME_SETUP("CSM_CertificateChoice::SetEncodedOther");

   ClearAllMembers();

   m_pOther = new CSM_Buffer;
   *m_pOther = Other;
   AccessSNACCOtherCertificateFormat();

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     SetEncodedExtCert
// 
// Description:  Processing sets member variables to NULL and then 
//               obtains memory for m_pExtCert member variable and then
//               assigns input buffer, "extCert" into the m_pExtCert member
//               variable.  The access function is called to assign the 
//               member m_pSNACCExtCert.
//
// Inputs:       CSM_Buffer& data containing ExtendedCertificate
//
// Outputs:      NONE
// 
// Returns:      NONE
//
////////////////////////////////////////////////////////////////////////////////
void CSM_CertificateChoice::SetEncodedExtCert(const CSM_Buffer &extCert)
{
   SME_SETUP("CSM_CertificateChoice::SetEncodedExtCert");
 
   ClearAllMembers();

   m_pExtCert = new CSM_Buffer;
   *m_pExtCert = extCert;
   AccessSNACCExtendedCertificate();
   
   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
 
}


//////////////////////////////////////////////////////////////////////////
void CSM_CertificateChoice::Decode() const
{

   SME_SETUP("CSM_CertificateChoice::Decode");

   // error if it isn't present
   if (m_pCert != NULL && m_pCert->Length() > 0)
   {
     if (m_pSNACCCert)
         delete m_pSNACCCert;
     m_pSNACCCert = NULL;
     if ((m_pSNACCCert = new Certificate) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

     // decode the certificate
     SME(DECODE_BUF(m_pSNACCCert, m_pCert));
   }
   else if (m_pAttrCert != NULL && m_pAttrCert->Length() > 0)
   {
     if (m_pSNACCAttrCert)
         delete m_pSNACCAttrCert;
     m_pSNACCAttrCert = NULL;
     if ((m_pSNACCAttrCert = new AttributeCertificate) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

     // decode the certificate
     SME(DECODE_BUF(m_pSNACCAttrCert, m_pAttrCert));
   }
   else if (m_pOther != NULL && m_pOther->Length() > 0)
   {
      if (m_pSNACCOtherCertFormat)
         delete m_pSNACCOtherCertFormat;
      m_pSNACCOtherCertFormat = NULL;
      if ((m_pSNACCOtherCertFormat = new OtherCertificateFormat) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

     // decode the certificate
     SME(DECODE_BUF(m_pSNACCOtherCertFormat, m_pOther));
   }  
   else if (m_pExtCert != NULL && m_pExtCert->Length() > 0)
   {
      if (m_pSNACCExtCert)
         delete m_pSNACCExtCert;
      m_pSNACCExtCert = NULL;
      if ((m_pSNACCExtCert = new ExtendedCertificate) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

     // decode the certificate
     SME(DECODE_BUF(m_pSNACCExtCert, m_pExtCert));
   }  
   else
   {
       SME_THROW(SM_NO_CERT_SET, "encoded cert/AttrCert/Other missing", NULL);
   }

   SME_FINISH_CATCH;
}

//////////////////////////////////////////////////////////////////////////
AsnOid *CSM_CertificateChoice::GetKeyOID()
{
   AsnOid *pKeyOID=NULL;
   SME_SETUP("CSM_CertificateChoice::GetKeyOID");

   // if m_pKeyOID is null, then the cert has not been decoded
   // and we must decode it before we can return the requested value
   if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
      SME(Decode());
   if (m_pSNACCCert != NULL)
   {
       if ((pKeyOID = new AsnOid(m_pSNACCCert->toBeSigned.
          subjectPublicKeyInfo.algorithm.algorithm)) == NULL)
          SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }

   SME_FINISH_CATCH;
   return pKeyOID;
}

CSM_Buffer *CSM_CertificateChoice::GetPublicKey()
{
   CSM_Buffer *pRet = NULL;

   SME_SETUP("CSM_CertificateChoice::GetPublicKey");

   // if m_pSnaccCert is null then the cert has not been decoded
   // and we must decode it before we can return the requested value
   if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
      SME(Decode());

   if (m_pSNACCCert != NULL)
   {
     pRet = GetPublicKey(m_pSNACCCert->toBeSigned.subjectPublicKeyInfo.subjectPublicKey);
   }

   SME_FINISH_CATCH;
   return pRet;
}

CSM_Buffer *CSM_CertificateChoice::GetPublicKey(AsnBits &SNACCBits)
{
   CSM_Buffer *pRet = NULL;

   SME_SETUP("CSM_CertificateChoice::GetPublicKey");

   AsnBits *pY = &SNACCBits;

   pRet = new CSM_Buffer((const char *)SNACCBits.data(), SNACCBits.length());

   SME_FINISH_CATCH;
   return pRet;
}
//////////////////////////////////////////////////////////////////////////
CSM_Alg *CSM_CertificateChoice::GetPublicKeyAlg()
{
   CSM_Alg *pRet = NULL;

   SME_SETUP("CSM_CertificateChoice::GetPublicKeyAlg");

   // if m_pSnaccCert is null then the cert has not been decoded
   // and we must decode it before we can return the requested value
   if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
      SME(Decode());

   if (m_pSNACCCert != NULL)
   {
     if ((pRet = new CSM_Alg(m_pSNACCCert->toBeSigned.
         subjectPublicKeyInfo.algorithm)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }

   SME_FINISH_CATCH;
   return pRet;
}


////////////////////////////////////////////////////////////////////////////
//   This method returns the issuer of a Certificate or an Attribute Certificate as
//  a CSM_DN pointer.  When an AttributeCertificate is been processed, also a list
//  of CSM_GeneralNames is constructed, then this list is searched to find if a
//  CSM_DN is available.  
//   NOTE : The fact that an issuer in the form of a CSM_DN is not found for an 
//         AttributeCertificate should NOT be interpreted by the caller as an 
//         indication of NO issuer provided.
CSM_DN * CSM_CertificateChoice::GetIssuer(CSM_GeneralNameLst *pIssuers)
{
   CSM_DN *pIssuer = NULL;

   SME_SETUP("CSM_CertificateChoice::GetIssuer");

   // if m_pSNACCCert and m_pSNACCAttrCert are null, then no objects 
   // have been decoded; so, call Decode
   if ((m_pSNACCCert == NULL) && (m_pSNACCAttrCert == NULL))
      SME(Decode());

   if (m_pSNACCAttrCert != NULL)
   {
      if (m_pSNACCAttrCert->toBeSigned.issuer.choiceId == AttCertIssuer::v2FormCid)
      {
         if (m_pSNACCAttrCert->toBeSigned.issuer.v2Form->issuerName->begin() == 0)
            SME_THROW(SM_CERT_DEC_ERROR, "Attribute Certificate missing V2 issuer", NULL);

         if (pIssuers)
            delete pIssuers;

         pIssuers = new CSM_GeneralNameLst;

         GeneralNames::iterator piIssuerName;
         for (piIssuerName = m_pSNACCAttrCert->toBeSigned.issuer.v2Form->issuerName->begin();
              piIssuerName != m_pSNACCAttrCert->toBeSigned.issuer.v2Form->issuerName->end();
              ++piIssuerName)
         {
            CSM_GeneralNameLst::iterator itGeneralName = pIssuers->append();
            *itGeneralName = *piIssuerName;

         
            if (pIssuer == NULL)
               pIssuer = itGeneralName->GetGenNameDN();
         }
      }
      else if (m_pSNACCAttrCert->toBeSigned.issuer.choiceId == AttCertIssuer::v1FormCid)
      { 
         if (m_pSNACCAttrCert->toBeSigned.issuer.v1Form->begin() == 0)
            SME_THROW(SM_CERT_DEC_ERROR, "V1 Attribute Certificate obsolete missing valid issuer", NULL);

         // if no errors go ahead and give data
         if (pIssuers)
            delete pIssuers;

         pIssuers = new CSM_GeneralNameLst;

         GeneralNames::iterator piIssuerName;
         for (piIssuerName = m_pSNACCAttrCert->toBeSigned.issuer.v1Form->begin();
              piIssuerName != m_pSNACCAttrCert->toBeSigned.issuer.v1Form->end();
              ++piIssuerName)
         {
            CSM_GeneralNameLst::iterator itGeneralName = pIssuers->append();
            *itGeneralName = *piIssuerName;

         
            if (pIssuer == NULL)
               pIssuer = itGeneralName->GetGenNameDN();
         }
      }
      else
      {
         SME_THROW(SM_CERT_DEC_ERROR, "Attribute Certificate missing issuer", NULL);
      }
   }

   if (m_pSNACCCert != NULL)
   {
      pIssuer = new CSM_DN(m_pSNACCCert->toBeSigned.issuer);
   }

   SME_FINISH_CATCH;

   return pIssuer;
}
//////////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_CertificateChoice::GetEncodedIssuer()
{
   CSM_Buffer *pEncodedIssuer=NULL;

   SME_SETUP("CSM_CertificateChoice::GetEncodedIssuer");

   // if m_pIssuer is null, then the Cert has not been decoded
   // and we must decode it before we can return the requested value
   if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
      SME(Decode());

   if (m_pSNACCCert != NULL)
   {
        ENCODE_BUF(&m_pSNACCCert->toBeSigned.issuer, pEncodedIssuer);
   }

   SME_FINISH_CATCH;
   return pEncodedIssuer;
}

////////////////////////////////////////////////////////////////////////////
//   This method returns the subject of a Certificate or an Attribute Certificate as
//  a CSM_DN pointer.  When an AttributeCertificate is being processed, also a list
//  of CSM_GeneralNames is constructed, then this list is searched to find if a
//  CSM_DN is available.  
//   NOTE : The fact that an subject in the form of a CSM_DN is not found for an 
//         AttributeCertificate should NOT be interpreted by the caller as an 
//         indication of NO subject provided.
CSM_DN * CSM_CertificateChoice::GetSubject(CSM_GeneralNameLst *pIssuers)
{   
   CSM_DN *pSubject=NULL;
   GeneralNames::iterator piIssuer;
 

   SME_SETUP("CSM_CertificateChoice::GetSubject");

   // if m_pSNACCCert and m_pSNACCAttrCert are null, then nothing has been decoded
   // so we must call to decode before we can return the requested value
   if ((m_pSNACCCert == NULL) && (m_pSNACCAttrCert == NULL))
      SME(Decode());

   if (m_pSNACCCert != NULL)
   {
     if ((pSubject = new CSM_DN(m_pSNACCCert->toBeSigned.subject)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }
   else if (m_pSNACCAttrCert != NULL)
   {
      if (pIssuers == NULL)
         pIssuers = new CSM_GeneralNameLst;

      // The Subject of an AttributeCertificate is a choice between holder, baseCertificate
      // (which contains a GeneralName list, a serialNumber and a UniqueIdentifier)
      // and a subjectName (which is a list of General Names).
       if (m_pSNACCAttrCert->toBeSigned.eitherHolder.choiceId == 
                         AttributeCertificateInfoChoice::baseCertificateIDCid) // V1(0)
       {
          // IssuerSerial
          GeneralNames names;
          names = m_pSNACCAttrCert->toBeSigned.
                                     eitherHolder.baseCertificateID->issuer;
 
          // Make list of CSM_GeneralNames from list of GeneralNames for the issuer (a list of 
          // issuers does NOT mean multiple issuers, it means different representations of the
          // same isssuer).
          for (piIssuer = names.begin(); piIssuer != names.end(); ++piIssuer)
          {
             CSM_GeneralNameLst::iterator itGeneralName = pIssuers->append();
             *itGeneralName = *piIssuer;

            if (pSubject == NULL)
               pSubject = itGeneralName->GetGenNameDN();
          }
       }
       else if (m_pSNACCAttrCert->toBeSigned.eitherHolder.choiceId == 
                         AttributeCertificateInfoChoice::holderCid) // V2(1)
       {
          // IssuerSerial
          GeneralNames names;

          if (m_pSNACCAttrCert->toBeSigned.eitherHolder.holder != NULL &&
              m_pSNACCAttrCert->toBeSigned.eitherHolder.holder->entityName != NULL)
          {
             names = *m_pSNACCAttrCert->toBeSigned.
                                     eitherHolder.holder->entityName;
          }  
          else if (m_pSNACCAttrCert->toBeSigned.eitherHolder.holder != NULL &&
              m_pSNACCAttrCert->toBeSigned.eitherHolder.holder->baseCertificateID != NULL)
          {

             names = m_pSNACCAttrCert->toBeSigned.
                                     eitherHolder.holder->baseCertificateID->issuer;
          }
 
          // Make list of CSM_GeneralNames from list of GeneralNames for the issuer (a list of 
          // issuers does NOT mean multiple issuers, it means different representations of the
          // same isssuer).
          for (piIssuer = names.begin(); piIssuer != names.end(); ++piIssuer)
          {
              CSM_GeneralNameLst::iterator itGeneralName = pIssuers->append();
              *itGeneralName = *piIssuer;

              if (pSubject == NULL)
                 pSubject = itGeneralName->GetGenNameDN();
          }
       }     
       else if (m_pSNACCAttrCert->toBeSigned.eitherHolder.choiceId ==
                               AttributeCertificateInfoChoice::subjectNameCid)
       {
          // GeneralNames
         GeneralNames *pNames = NULL;

         if ((pNames = m_pSNACCAttrCert->toBeSigned.eitherHolder.subjectName) != NULL)
         {      
            for (piIssuer = pNames->begin(); piIssuer != pNames->end(); ++piIssuer)
            {
                CSM_GeneralNameLst::iterator itGeneralName = pIssuers->append();
                *itGeneralName = *piIssuer;

                if (pSubject == NULL)
                   pSubject = itGeneralName->GetGenNameDN();
            }
         }
       }
   }
 
    SME_FINISH_CATCH;

   return pSubject;
}
//////////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_CertificateChoice::GetEncodedSubject()
{
   CSM_Buffer *pEncodedSubject=NULL;

   SME_SETUP("CSM_CertificateChoice::GetEncodedSubject");

   // if m_pSubject is null, then the Cert has not been decoded
   // and we must decode it before we can return the requested value
   if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
      SME(Decode());
      // store subject
   if (m_pSNACCCert != NULL)
   {
       ENCODE_BUF(&m_pSNACCCert->toBeSigned.subject, pEncodedSubject);
   }

   SME_FINISH_CATCH;
   return pEncodedSubject;
}
//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CertificateChoice::GetSerial()
{
   CSM_Buffer *pRet = NULL;

   SME_SETUP("CSM_CertificateChoice::GetSerial");

   // if m_pSnaccCert and m_pSnaccAttrCert are null then no object 
   // has been decoded; so, call Decode
   if ( (m_pSNACCCert == NULL) && (m_pSNACCAttrCert == NULL) )
      SME(Decode());

   // Do we have a Cert ?
   if (m_pSNACCCert != NULL)
   {
     if ((pRet = new CSM_Buffer(
         (const char *)m_pSNACCCert->toBeSigned.serialNumber.c_str(),
         m_pSNACCCert->toBeSigned.serialNumber.length())) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }
   else if (m_pSNACCAttrCert != NULL)
   {
      if ((pRet = new CSM_Buffer(
         (const char *)m_pSNACCAttrCert->toBeSigned.serialNumber.c_str(),
         m_pSNACCAttrCert->toBeSigned.serialNumber.length())) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }

   SME_FINISH_CATCH;
   return pRet;
}
///////////////////////////////////////////////////////////////////////////
// GetRid member function
CSM_Identifier *CSM_CertificateChoice::GetRid(CSM_Identifier &RID)
{
   CSM_Identifier *pRID=NULL;

   SME_SETUP("CSM_CertificateChoice::GetRid(CSM_Identifier &)");

   if (RID.AccessSubjectKeyIdentifier())
       pRID = GetRid(false);
   else
       pRID = GetRid(true);

   SME_FINISH_CATCH;
   return(pRID);
}

///////////////////////////////////////////////////////////////////////////
// GetRid member function
CSM_Identifier *CSM_CertificateChoice::GetRid(bool m_bIssOrSki)
{
    CSM_Identifier *pRID=NULL;

    SME_SETUP("CSM_Identifier::GetRid(bool)"); 

    // if m_pSnaccCert is null then the cert has not been decoded
    // and we must decode it before we can return the requested value
    if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
    {
       SME(Decode());
    }

    if (!m_bIssOrSki)
    {
     CSM_Buffer *pSki = NULL;
     
     pSki = GetSubjectKeyIdentifier();

     if(pSki)
     {
        pRID = new CSM_Identifier(*pSki);
        delete pSki;
     }  // END IF pSki
    }   // END IF !m_bIssOrSki
   //Issuer and Serial Number is Loaded if Subject Key Identifier is
   //missing from certificate.
   if (m_bIssOrSki)
   {
     CSM_IssuerAndSerialNumber *pIas = NULL;

      pIas = GetIssuerAndSerialNumber();

      if(pIas)
      {
          pRID = new CSM_Identifier(*pIas);
          delete pIas;
      }
   }

    SME_FINISH_CATCH
    return pRID;
}
///////////////////////////////////////////////////////////////////////////
// GetIssuerAndSerialNumber member function
CSM_IssuerAndSerialNumber *CSM_CertificateChoice::GetIssuerAndSerialNumber()
{
    CSM_IssuerAndSerialNumber *pResult=NULL;

    SME_SETUP("CSM_CertificateChoice::GetIssuerAndSerialNumber");

   // if m_pSnaccCert is null then the cert has not been decoded
   // and we must decode it before we can return the requested value
   if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
   {
       SME(Decode());
   }

   if(m_pSNACCCert)
   {
      pResult = new  CSM_IssuerAndSerialNumber;

      pResult->SetIssuer(m_pSNACCCert->toBeSigned.issuer);
      pResult->SetSerialNo(m_pSNACCCert->toBeSigned.serialNumber);
   }

    SME_FINISH_CATCH
    return pResult;
}

///////////////////////////////////////////////////////////////////////////
// GetSubjectKeyIdentifier member function
CSM_Buffer *CSM_CertificateChoice::GetSubjectKeyIdentifier()
{
    CSM_Buffer *pResult=NULL;
    Extensions::iterator piSNACCExt;
    SubjectKeyIdentifier *pSNACCSKI;

    SME_SETUP("CSM_CertificateChoice::GetSubjectKeyIdentifier");

   // if m_pSnaccCert and m_pSnaccAttrCert are null then no object has been decoded
   // and we must decode one before we can return the requested value
   if ((m_pSNACCCert == NULL) && (m_pSNACCAttrCert == NULL))    // Decode result.
   {
       SME(Decode());
   }

   Extensions *pExtensions = NULL;

   if(m_pSNACCCert)
   {
      if (m_pSNACCCert->toBeSigned.extensions)
        pExtensions = m_pSNACCCert->toBeSigned.extensions;
   }
   else if (m_pSNACCAttrCert)
   {
      if (m_pSNACCAttrCert->toBeSigned.extensions)
         pExtensions = m_pSNACCAttrCert->toBeSigned.extensions;
   }

   if (pExtensions)
   {
      for(piSNACCExt = pExtensions->begin(); piSNACCExt != pExtensions->end(); ++piSNACCExt)
      {
         if(piSNACCExt->extnId == id_ce_subjectKeyIdentifier)
         {
            pSNACCSKI = (SubjectKeyIdentifier *)piSNACCExt->extnValue.value;
            //RWC;DECODE_BUF(&snaccInt, pTmpBuf);
            pResult = new CSM_Buffer(pSNACCSKI->c_str(), pSNACCSKI->Len());
         }
      }
   }

    SME_FINISH_CATCH
    return pResult;
}


//////////////////////////////////////////////////////////////////////////
void CSM_CertificateChoice::SetSNACCCertChoices(
    const CertificateChoices &SNACCCertChoices)
{
   SME_SETUP("CSM_CertificateChoice::SetSNACCCertChoices");
   
   ClearAllMembers();

   if (SNACCCertChoices.choiceId == CertificateChoices::certificateCid)
   {
      if ((m_pSNACCCert = new Certificate) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      *m_pSNACCCert = *SNACCCertChoices.certificate;
   }
   else if ( (SNACCCertChoices.choiceId == CertificateChoices::v2AttrCertCid) ||
             (SNACCCertChoices.choiceId == CertificateChoices::v1AttrCertCid) )
   {
      if ((m_pSNACCAttrCert = new AttributeCertificate) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

      if(SNACCCertChoices.choiceId == CertificateChoices::v2AttrCertCid)
      {
         *m_pSNACCAttrCert = *SNACCCertChoices.v2AttrCert;
      }
      else if (SNACCCertChoices.choiceId == CertificateChoices::v1AttrCertCid) 
      {
         *m_pSNACCAttrCert = *SNACCCertChoices.v1AttrCert;
      
      }
   }
   else if (SNACCCertChoices.choiceId == CertificateChoices::otherCid)
   {
      if ((m_pSNACCOtherCertFormat = new OtherCertificateFormat) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      *m_pSNACCOtherCertFormat = *SNACCCertChoices.other;
   }  
   else if (SNACCCertChoices.choiceId == CertificateChoices::extendedCertificateCid)
   {
      if ((m_pSNACCExtCert = new ExtendedCertificate) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
      *m_pSNACCExtCert = *SNACCCertChoices.extendedCertificate;
   }
   else
   {
      SME_THROW(SM_MEMORY_ERROR, 
            "Unsupported or Obsolete Certificate Choice!", NULL);
   }

   SME_FINISH_CATCH;
}

//////////////////////////////////////////////////////////////////////////
// Make a copy of our SNACC Certificate.
Certificate *CSM_CertificateChoice::GetSNACCCertificate()
{
    Certificate *pSNACCCert=NULL;
    SME_SETUP("CSM_CertificateChoice::GetSNACCCertificate");

    if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
        Decode();
    if (m_pSNACCCert)
    {
      pSNACCCert=new Certificate;
      *pSNACCCert = *AccessSNACCCertificate();
    }

    SME_FINISH_CATCH;
    return pSNACCCert;
}


//////////////////////////////////////////////////////////////////////////
// Access internal SNACC Certificate.
const Certificate *CSM_CertificateChoice::AccessSNACCCertificate() const
{
   SME_SETUP("CSM_CertificateChoice::AccessSNACCCertificate");
   if (m_pSNACCCert == NULL && m_pCert != NULL)    // Decode result.
   {
       Decode();
   }

   SME_FINISH_CATCH;
   return m_pSNACCCert;
}


//////////////////////////////////////////////////////////////////////////
// Make a copy of our SNACC Certificate.
AttributeCertificate *CSM_CertificateChoice::GetSNACCAttrCertificate()
{
    AttributeCertificate *pSNACCAttrCert=NULL;
    SME_SETUP("CSM_CertificateChoice::GetSNACCAttrCertificate");

    if (m_pSNACCCert == NULL && m_pSNACCAttrCert == NULL)    // Decode result.
        Decode();
    if (m_pSNACCAttrCert)
    {
       pSNACCAttrCert=new AttributeCertificate;
       *pSNACCAttrCert = *AccessSNACCAttrCertificate();
    }

    SME_FINISH_CATCH;
    return pSNACCAttrCert;
}


//////////////////////////////////////////////////////////////////////////
// Access internal SNACC Certificate.
const AttributeCertificate *CSM_CertificateChoice::AccessSNACCAttrCertificate() const
{
   SME_SETUP("CSM_CertificateChoice::AccessSNACCAttrCertificate");
   if (m_pSNACCAttrCert == NULL && m_pAttrCert != NULL)    // Decode result.
   {
       Decode();
   }

   SME_FINISH_CATCH;
   return m_pSNACCAttrCert;
}


//////////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_CertificateChoice::GetEncodedAttrCert() 
{ 
    CSM_Buffer *pBuf=NULL;

    if (AccessEncodedAttrCert() != NULL)
        pBuf = new CSM_Buffer(*AccessEncodedAttrCert());
    return pBuf;
}

//////////////////////////////////////////////////////////////////////////
const CSM_Buffer *CSM_CertificateChoice::AccessEncodedAttrCert() const
{ 
    SME_SETUP("CSM_CertificateChoice::AccessEncodedAttrCert");
    if (m_pAttrCert == NULL && m_pSNACCAttrCert != NULL)
       ENCODE_BUF(m_pSNACCAttrCert, m_pAttrCert);
    SME_FINISH_CATCH;
    return m_pAttrCert; 
}

//////////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_CertificateChoice::GetEncodedCert() 
{ 
    CSM_Buffer *pBuf=NULL;

    if (AccessEncodedCert() != NULL)
        pBuf = new CSM_Buffer(*AccessEncodedCert());
    return pBuf;
}

//////////////////////////////////////////////////////////////////////////
const CSM_Buffer *CSM_CertificateChoice::AccessEncodedCert() const
{ 
    SME_SETUP("CSM_CertificateChoice::AccessEncodedCert");

    if (m_pCert == NULL && m_pSNACCCert != NULL)
       SME(ENCODE_BUF(m_pSNACCCert, m_pCert));
    
    SME_FINISH_CATCH;
    return m_pCert; 
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     GetEncodedOther
// 
// Description:  Processing calls AccessEncodedOther to obtain data from member 
//               variable m_pOther.  If there is data present, processing copies 
//               the data and returns a pointer to it.  
//
// Inputs:       NONE
//
// Outputs:      Pointer to a copy of CSM_Buffer* m_pOther data
// 
// Returns:      NONE
//
////////////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CertificateChoice::GetEncodedOther() 
{ 
    CSM_Buffer* pBuf = NULL;

    if (AccessEncodedOther() != NULL)
        pBuf = new CSM_Buffer(*AccessEncodedOther());
    return pBuf;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     AccessEncodedOther
// 
// Description:  Processing returns a const pointer to the member variable 
//               m_pOther.  First the function checks to see if there is data
//               in the m_pSNACCOtherCertFormat member to determine if it is 
//               necessary to encode the data into the m_pOther member.
//
// Inputs:       NONE
//
// Outputs:      NONE
// 
// Returns:      A constant pointer to data in member m_pOther variable.
//
////////////////////////////////////////////////////////////////////////////////
const CSM_Buffer* CSM_CertificateChoice::AccessEncodedOther() const
{ 

    SME_SETUP("CSM_CertificateChoice::AccessEncodedOther");

    if (m_pOther == NULL && m_pSNACCOtherCertFormat != NULL)
       SME(ENCODE_BUF(m_pSNACCOtherCertFormat, m_pOther));
    
    SME_FINISH_CATCH;

    return m_pOther; 
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     GetSNACCOtherCertificateFormat
// 
// Description:  Processing calls Decode if necessary to obtain data from member 
//               variable m_pOther.  Processing copies the data and returns a 
//               pointer to it.  
//
// Inputs:       NONE
//
// Outputs:      NONE
// 
// Returns:      Pointer to a copy of OtherCertificateFormat* 
//                  m_pSNACCOtherCertFormat data
//
////////////////////////////////////////////////////////////////////////////////
OtherCertificateFormat *CSM_CertificateChoice::GetSNACCOtherCertificateFormat()
{
   OtherCertificateFormat *pSNACCOther = new OtherCertificateFormat;

   SME_SETUP("CSM_CertificateChoice::GetSNACCOtherCertificateFormat");

   if (m_pSNACCOtherCertFormat == NULL && m_pOther != NULL)
   {    
      // Decode it into m_pSNACCOtherCertFormat if data is there
      Decode();
   }

   // copy data to return if data is there
   if (m_pSNACCOtherCertFormat)
      *pSNACCOther = *AccessSNACCOtherCertificateFormat();

   SME_FINISH_CATCH;
   
   return pSNACCOther;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     AccessSNACCOtherCertificateFormat
// 
// Description:  Access internal SNACC OtherCertificateFormat data.  
//
// Inputs:       NONE
//
// Outputs:      NONE
// 
// Returns:      Constant pointer to m_pSNACCOtherCertFormat data
//
////////////////////////////////////////////////////////////////////////////////
const OtherCertificateFormat* 
   CSM_CertificateChoice::AccessSNACCOtherCertificateFormat() const
{
   SME_SETUP("CSM_CertificateChoice::AccessSNACCOtherCertificateFormat");

   if (m_pSNACCOtherCertFormat == NULL && m_pOther != NULL)    
   {
      // Decode it into m_pSNACCOtherCertFormat
      Decode();
   }

   SME_FINISH_CATCH;

   return m_pSNACCOtherCertFormat;
}


////////////////////////////////////////////////////////////////////////////////
//
// Function:     GetEncodedExtCert
// 
// Description:  Processing calls AccessEncodedExtCert to obtain data from member 
//               variable m_pExtCert.  If there is data present, processing copies 
//               the data and returns a pointer to it.  
//
// Inputs:       NONE
//
// Outputs:      Pointer to a copy of CSM_Buffer* m_pExtCert data
// 
// Returns:      NONE
//
////////////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CertificateChoice::GetEncodedExtCert() 
{ 
    CSM_Buffer* pBuf = NULL;

    if (AccessEncodedExtCert() != NULL)
        pBuf = new CSM_Buffer(*AccessEncodedExtCert());
    return pBuf;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     AccessEncodedExtCert
// 
// Description:  Processing returns a const pointer to the member variable 
//               m_pExtCert.  First the function checks to see if there is data
//               in the m_pSNACCExtCert member to determine if it is 
//               necessary to encode the data into the m_pExtCert member.
//
// Inputs:       NONE
//
// Outputs:      NONE
// 
// Returns:      A constant pointer to data in member m_pExtCert variable.
//
////////////////////////////////////////////////////////////////////////////////
const CSM_Buffer* CSM_CertificateChoice::AccessEncodedExtCert() const
{ 

    SME_SETUP("CSM_CertificateChoice::AccessEncodedExtCert");

    if (m_pExtCert == NULL && m_pSNACCExtCert != NULL)
       SME(ENCODE_BUF(m_pSNACCExtCert, m_pExtCert));
    
    SME_FINISH_CATCH;

    return m_pExtCert; 
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     GetSNACCExtendedCertificate
// 
// Description:  Processing calls Decode if necessary to obtain data from member 
//               variable m_pExtCert.  Processing copies the data and returns a 
//               pointer to it.  
//
// Inputs:       NONE
//
// Outputs:      NONE
// 
// Returns:      Pointer to a copy of ExtendedCertificate* 
//                  m_pSNACCExtCert data
//
////////////////////////////////////////////////////////////////////////////////
ExtendedCertificate *CSM_CertificateChoice::GetSNACCExtendedCertificate()
{
   ExtendedCertificate *pSNACCExtCert = NULL;

   SME_SETUP("CSM_CertificateChoice::GetSNACCExtendedCertificate");

   if (m_pSNACCExtCert == NULL && m_pExtCert != NULL)
   {    
      // Decode it into m_pSNACCExtCert if data is there
      Decode();
   }

   // copy data to return if data is there
   if (m_pSNACCExtCert)
   {
      pSNACCExtCert = new ExtendedCertificate;
      *pSNACCExtCert = *AccessSNACCExtendedCertificate();
   }

   SME_FINISH_CATCH;
   
   return pSNACCExtCert;
}

////////////////////////////////////////////////////////////////////////////////
//
// Function:     AccessSNACCExtendedCertificate
// 
// Description:  Access internal SNACC ExtendedCertificate data.  
//
// Inputs:       NONE
//
// Outputs:      NONE
// 
// Returns:      Constant pointer to m_pSNACCExtCert data
//
////////////////////////////////////////////////////////////////////////////////
const ExtendedCertificate* 
   CSM_CertificateChoice::AccessSNACCExtendedCertificate() const
{
   SME_SETUP("CSM_CertificateChoice::AccessSNACCExtendedCertificate");

   if (m_pSNACCExtCert == NULL && m_pExtCert != NULL)    
   {
      // Decode it into m_pSNACCExtCert
      Decode();
   }

   SME_FINISH_CATCH;

   return m_pSNACCExtCert;
}


void CSM_CertificateChoice::UpdateSNACCCertificate(Certificate *Cert)
{
   if (Cert != NULL)
   {
      if (m_pSNACCCert)
         delete m_pSNACCCert;      
      m_pSNACCCert = NULL;

      m_pSNACCCert = Cert;
   }
}

void CSM_CertificateChoice::UpdateSNACCAttrCertificate(AttributeCertificate *pAttrCert)
{
   if (pAttrCert != NULL)
   {
      if (m_pSNACCAttrCert)
         delete m_pSNACCAttrCert;      
      m_pSNACCAttrCert = NULL;

      m_pSNACCAttrCert = pAttrCert;
   }
}

CSM_CertificateChoice &CSM_CertificateChoice::operator= (const CSM_CertificateChoice &CertChoice)
{
   ClearAllMembers();
   m_bIssOrSki = CertChoice.m_bIssOrSki;

   // if necessary assign AttrCert
   if (CertChoice.AccessEncodedAttrCert())
   {
      m_pAttrCert = new CSM_Buffer(*CertChoice.AccessEncodedAttrCert());
   }   
 
   // if necessary assign Cert
   if (CertChoice.AccessEncodedCert())
   {
       m_pCert = new CSM_Buffer(*CertChoice.AccessEncodedCert());
   }  
  
   // if necessary assign OtherCertificateFormat
   if (CertChoice.AccessEncodedOther())
   {
       m_pOther = new CSM_Buffer(*CertChoice.AccessEncodedOther());
   }   
  
   // if necessary assign ExtendedCertificate
   if (CertChoice.AccessEncodedExtCert())
   {
      m_pExtCert = new CSM_Buffer(*CertChoice.AccessEncodedExtCert());
   }    
    
   return(*this);
}

SM_RET_VAL CSM_CertificateChoice::GetAttrCertSubjectSerialNumber(CertificateSerialNumber &serialNumber)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_CertificateChoice::GetAttrCertSubjectSerialNumber");

   if ((m_pSNACCAttrCert == NULL) && (m_pSNACCCert == NULL))
      SME(Decode());

   if (m_pSNACCAttrCert)
   {
      if (m_pSNACCAttrCert->toBeSigned.eitherHolder.choiceId ==
                        AttributeCertificateInfoChoice::baseCertificateIDCid)
      {
         if (m_pSNACCAttrCert->toBeSigned.
                                    eitherHolder.baseCertificateID != NULL)
         {
            serialNumber = m_pSNACCAttrCert->toBeSigned.
                                    eitherHolder.baseCertificateID->serial;
         }
         else
            status = -1;
      }
      else if (m_pSNACCAttrCert->toBeSigned.eitherHolder.choiceId ==
                        AttributeCertificateInfoChoice::holderCid)
      {
         if (m_pSNACCAttrCert->toBeSigned.
                                    eitherHolder.baseCertificateID != NULL)
         {
            serialNumber = m_pSNACCAttrCert->toBeSigned.
                                    eitherHolder.holder->baseCertificateID->serial;
         }
         else 
            status = -1;
      }
   }
   else
   {
      // No AttributeCertificate available; should not be fatal error at this point
      status = -1;
   }

   SME_FINISH_CATCH;

   return status;
}

SM_RET_VAL CSM_CertificateChoice::GetAttrCertSubjectIssuerUID(UniqueIdentifier *&pIssuerUID)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP("CSM_CertificateChoice::GetAttrCertSubjectIssuerUID");

   if ((m_pSNACCAttrCert == NULL) && (m_pSNACCCert == NULL))
      SME(Decode());

   if (m_pSNACCAttrCert)
   {
      if (m_pSNACCAttrCert->toBeSigned.eitherHolder.choiceId ==
                        AttributeCertificateInfoChoice::baseCertificateIDCid)
      {
         pIssuerUID = m_pSNACCAttrCert->toBeSigned.
                              eitherHolder.baseCertificateID->issuerUID;
      }
      else if (m_pSNACCAttrCert->toBeSigned.eitherHolder.choiceId ==
                        AttributeCertificateInfoChoice::holderCid)
      {
         pIssuerUID = m_pSNACCAttrCert->toBeSigned.
                     eitherHolder.holder->baseCertificateID->issuerUID;
      }
      else 
         status = -1;
   }
   else
   {
      // No AttributeCertificate available; should not be fatal error at this point
      status = -1;
   }

   SME_FINISH_CATCH;

   return status;
}   // END CSM_CertificateChoice::GetAttrCertSubjectIssuerUID(...)

////////////////////////////////////////////////////////////////////////////
// THIS routine returns the FIRST rfc822 type GeneralName located in this
//  certificate's AlgSubjectName extension.
char *CSM_CertificateChoice::pszGetAltSubjectName_rfc822()
{
    char *pszResult=NULL;

     Extensions *pExtensions=m_pSNACCCert->toBeSigned.extensions;
     Extensions::iterator piSNACCExt;
     // Loading of Extentsions Listbox values always the same.
     for(piSNACCExt = pExtensions->begin(); piSNACCExt != pExtensions->end(); ++piSNACCExt)
      {
          if(piSNACCExt->extnId == id_ce_subjectAltName)
          {
               SNACC::GeneralNames *pSNACCsubjAltNames=(SNACC::GeneralNames *)piSNACCExt->extnValue.value;
               SNACC::GeneralNames::iterator piSNACCsubjAltName;
               bool bDoneFlag=false;
               for (piSNACCsubjAltName = pSNACCsubjAltNames->begin(); 
                    !bDoneFlag && piSNACCsubjAltName != pSNACCsubjAltNames->end();
                    ++piSNACCsubjAltName)
               {
                  if (piSNACCsubjAltName->choiceId == SNACC::GeneralName::rfc822NameCid)
                  {
                     pszResult = strdup(piSNACCsubjAltName->rfc822Name->c_str()); 
                     break;
                  }  // END if rfc822NameCid
               }     // END for (each subjAltName GeneralName in subjectAltName extension
          }    // END IF subjectAltName
      }        // END FOR each extension in the cert.

    return(pszResult);
}       // EOF CSM_CertificateChoice::pszGetAltSubjectName_rfc822()


////////////////////////////////////////////////////////////////////////////
//
//   This method returns the issuerSerial of an Attribute Certificate 
//
//   Also the following output parameters are filled in when data is present: 
//      GeneralNames             *pIssuerSerial
//      CertificateSerialNumber  *sn
//      UniqueIdentifier         *uniqueId
//
////////////////////////////////////////////////////////////////////////////
long CSM_CertificateChoice::GetIssuersBaseCert( SNACC::IssuerSerial *&pIssSN)
{
   long status = 0;
   IssuerSerial *pIssuerSerial = NULL;

   SME_SETUP("CSM_CertificateChoice::GetIssuerBaseCert");

   // if m_pSNACCCert and m_pSNACCAttrCert are null, then no objects 
   // have been decoded; so, call Decode
   if ((m_pSNACCCert == NULL) && (m_pSNACCAttrCert == NULL))
      SME(Decode());

   if (m_pSNACCAttrCert != NULL)
   {
      if (m_pSNACCAttrCert->toBeSigned.issuer.choiceId == AttCertIssuer::v2FormCid) 
      {  
         if (pIssSN)
            delete pIssSN;

         pIssSN = new SNACC::IssuerSerial(*m_pSNACCAttrCert->toBeSigned.issuer.
            v2Form->baseCertificateID);
      }
   }

   SME_FINISH_CATCH;

   return status;
}


_END_CERT_NAMESPACE 

// EOF sm_certChoice.cpp
