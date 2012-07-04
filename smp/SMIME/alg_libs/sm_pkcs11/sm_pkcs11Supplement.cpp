#ifndef NO_SCCS_ID
static char SccsId[ ] = "@(#) sm_pkcs11Supplement.cpp 1.8 08/17/00 14:46:57"; 
#endif

#include "sm_pkcs11.h"
_BEGIN_CERT_NAMESPACE
using namespace CTIL;
using namespace SNACC;


///////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::SetCertificate(CK_OBJECT_HANDLE hCertificate)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP ("CSM_Pkcs11::SetCertificate");

   CK_ULONG ulAttributeCount;

   CK_ATTRIBUTE certTemplate [] = {
        {CKA_VALUE, NULL_PTR, 0},      // BER encoding of the certificate
        {CKA_SUBJECT, NULL_PTR, 0},
        {CKA_ID, NULL_PTR, 0},
        {CKA_LABEL, NULL_PTR, 0}
   };

   // Devide the size of the template by the size of CK_ATTRIBUTE to determine
   // how many attributes were defined.
   ulAttributeCount = sizeof(certTemplate) / sizeof(CK_ATTRIBUTE);

   // After the first call to GetAttributeValue, we will know how much space to 
   // allocate for each attribute.  Then we will call GetAttributeValue again to 
   // actually get the data.
   if ((status = GetAttributeValue(m_hSession, hCertificate,
                           certTemplate, ulAttributeCount)) == SM_NO_ERROR)
   {
      CK_BYTE_PTR pValue = NULL_PTR;
      CK_ULONG valueLen = 0;
      CK_BYTE_PTR pSubject = NULL_PTR;
      CK_ULONG subjectLen = 0;
      CK_BYTE_PTR pId = NULL_PTR;
      CK_ULONG idLen = 0;
      CK_BYTE_PTR pLabel = NULL_PTR;
      CK_ULONG labelLen = 0;

      for (CK_ULONG i = 0; i < ulAttributeCount; i++)
      {
         if (certTemplate[i].type == CKA_VALUE)
         {
            pValue = (CK_BYTE_PTR) malloc (certTemplate[i].ulValueLen);
            valueLen = certTemplate[i].ulValueLen;
         }
         else if (certTemplate[i].type == CKA_SUBJECT)
         {
             pSubject = (CK_BYTE_PTR) malloc (certTemplate[i].ulValueLen);
            subjectLen = certTemplate[i].ulValueLen;
         }
         else if (certTemplate[i].type == CKA_ID)
         {
             pId = (CK_BYTE_PTR) malloc (certTemplate[i].ulValueLen);
            idLen = certTemplate[i].ulValueLen;
         }
         else if (certTemplate[i].type == CKA_LABEL)
         {
             pLabel = (CK_BYTE_PTR) malloc (certTemplate[i].ulValueLen);
            labelLen = certTemplate[i].ulValueLen;
         }
      }

      CK_ATTRIBUTE certTemplate1 [] = {
        {CKA_VALUE, pValue, valueLen},
        {CKA_SUBJECT, pSubject, subjectLen},
        {CKA_ID, pId, idLen},
        {CKA_LABEL, pLabel, labelLen}
      };

      if ((status = GetAttributeValue(m_hSession, hCertificate, 
                         certTemplate1, ulAttributeCount)) == SM_NO_ERROR)  
      {
         CSM_Buffer *pCertBuffer = NULL;

         // This buffer represents an encoded certificate
         pCertBuffer = new CSM_Buffer((char *) pValue,
                                          (SM_SIZE_T) valueLen);

         Certificate *pSnaccCert = new Certificate;

         SME(DECODE_BUF(pSnaccCert, pCertBuffer));

#ifdef PKCS11_PRINT
         std::cout << "\n" << "****** CERTIFICATE INFORMATION ******\n";
#endif
         // Store certificate as CSM_CertificateChoice so SFL can handle 
         // the data.
         if ((status = SetCertificate(*pSnaccCert)) == SM_NO_ERROR)
         {
            SetSubject(pSubject);
            m_subjectLen = subjectLen;

            if (pId != NULL_PTR)
            {
               // This id, along with the subject, can be used to 
               // find the private/public key.
               m_pId = (CK_BYTE_PTR) malloc (idLen);
               memcpy(m_pId, pId, idLen);

               m_idLen = idLen;
            }

            if (pLabel != NULL_PTR)
            {
               // The label along with the subject and the id is SOMETIMES
               // used by SOME Pkcs11 library to match privateKeys and Certificates
               m_pLabel = (CK_BYTE_PTR) malloc (labelLen);
               memcpy(m_pLabel, pLabel, labelLen);

               m_labelLen = labelLen;
            }

            m_hCertificate = hCertificate;

            // We need a private key to create a full instance 
            // for the SFL.
            status = SetPrivateKey();

         }
         else
         {
            status = -1;
         }
      }
      else
      {
         status = -1;
      }

      if (pValue)
         free (pValue);
      if (pSubject)
         free (pSubject);
      if (pId)
         free (pId);
      if (pLabel)
         free (pLabel);
   }
   else
   {
      status = -1;
   }

   SME_FINISH_CATCH;

   return status;
}
//////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::SetCertificate(CSM_Buffer &bufferCert)
{
   SME_SETUP("CSM_Pkcs11::SetCertificate");

   if (m_pCertificateChoice != NULL)
      delete m_pCertificateChoice;
   
   if ((m_pCertificateChoice = new CSM_CertificateChoice(bufferCert)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   
   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}
////////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::SetCertificate(Certificate &snaccCert)
{
   SME_SETUP("CSM_Pkcs11::SetCertificate");

   if (m_pCertificateChoice != NULL)
      delete m_pCertificateChoice;

   if ((m_pCertificateChoice = new CSM_CertificateChoice(snaccCert)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

#ifdef PKCS11_PRINT

   AsnOid *pOid = m_pCertificateChoice->GetKeyOID();
   char * pOidDescription = pOid->GetChar();
   std::cout << "Public Key OID " << pOidDescription << "\n";

   AsnOid certAlgOid(snaccCert.algorithm.algorithm);
   char *pOidCertAlg = certAlgOid.GetChar();

   AsnOid certToSign(snaccCert.toBeSigned.signature.algorithm);
   char *pOidCertToSign = certToSign.GetChar();

   CSM_DN *pSubject = m_pCertificateChoice->GetSubject();
   std::cout << "Certificate Subject DN " << *pSubject << " \n";

   CSM_DN *pIssuer = m_pCertificateChoice->GetIssuer();
   std::cout << "Certificate Issuer DN " << *pIssuer << " \n";

   if (pOid)
      delete pOid;
   if (pOidDescription)
      free(pOidDescription);
   if (pOidCertToSign)
      free(pOidCertToSign);
   if (pSubject)
      delete pSubject;
   if (pIssuer)
      delete pIssuer;
#endif

   SME_FINISH
      SME_CATCH_SETUP
      SME_CATCH_FINISH

   return SM_NO_ERROR;
}
////////////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::SetPrivateKey()
{
   SM_RET_VAL status = SM_NO_ERROR;

   bool found = false;

   CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
   CK_ULONG ulAttributeCount;
   CK_OBJECT_HANDLE_PTR phObject = NULL_PTR;
   CK_ULONG ulObjectCount;
   CK_ATTRIBUTE *pfindKeyTemplate;

   CK_ATTRIBUTE findKeyTemplate[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_SUBJECT, m_pSubject, m_subjectLen},            
      {CKA_ID, m_pId, m_idLen},                      
      {CKA_LABEL, m_pLabel, m_labelLen},
   };

   CK_ATTRIBUTE findKeyTemplate_NO_ID[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)},
      {CKA_SUBJECT, m_pSubject, m_subjectLen},            
      {CKA_LABEL, m_pLabel, m_labelLen},
   };



   // Devide the size of the template by the size of an entry (CK_ATTRIBUTE)
   // to calculate the number of attributes defined.
   if (m_idLen)
   {
       pfindKeyTemplate = (CK_ATTRIBUTE *)&findKeyTemplate;
       ulAttributeCount = sizeof(findKeyTemplate) / sizeof (CK_ATTRIBUTE);
   }        // IF m_idLen
   else
   {
       pfindKeyTemplate = (CK_ATTRIBUTE *)&findKeyTemplate_NO_ID;
       ulAttributeCount = sizeof(findKeyTemplate_NO_ID) / sizeof (CK_ATTRIBUTE);
   }        // END if m_idLen

   // The private key will be searched using the following logic: a searched will
   // preformed using four Attributes (CKA_CLASS, CKA_SUBJECT, CKA_ID, and 
   // CKA_LABEL), if a unique private key is not found, a second search will be
   // performed with three attributes (CKA_CLASS, CKA_SUBJECT and CKA_ID); 
   // if a unique private key is not found,
   // a last search will be performed using two attributes 
   // (CKA_CLASS and CKA_SUBJECT). NOTE : It is therefore VERY IMPORTANT that the
   // attributes specified in the template above be kept in the following order
   // (CKA_CLASS, CKA_SUBJECT, CKA_ID and CKA_LABEL).
   while (!found && (ulAttributeCount >= 2))
   {
      if ((status = FindObjects(m_hSession,
                                pfindKeyTemplate,
                                ulAttributeCount,
                                2,  // Set the max number to two so we can
                                    // make sure that the key is unique 
                                    // (ulObjectCount = 1).
                                ulObjectCount,
                                phObject)) == SM_NO_ERROR)
      {
         if (ulObjectCount > 0)
         {
            if (ulObjectCount == 1)
            {
               m_hPrivateKey = *phObject;
               found = true;

               // Make sure status reflects success 
               // in finding private-key.
               status = SM_NO_ERROR;
            }
            else
               status = SM_PKCS11_NONE_UNIQUE_PRIV_KEY;
         }
         else
            status = SM_PKCS11_NO_PRIVATE_KEY;
      }

      if (phObject)
      {
         free (phObject);
         phObject = NULL_PTR;
      }

      ulAttributeCount--;

   }

   if ((ulAttributeCount < 2) && (status == SM_PKCS11_NO_PRIVATE_KEY))
   {
      // search for id only
     
      CK_ATTRIBUTE findKeyTemplate2[] = 
      {
         {CKA_CLASS, &keyClass, sizeof(keyClass)},         
         {CKA_ID, m_pId, m_idLen}                      
      }; 
      
      ulAttributeCount = 2;
      if ((status = FindObjects(m_hSession,
                                findKeyTemplate2,
                                ulAttributeCount,
                                2,  // Set the max number to two so we can
                                    // make sure that the key is unique 
                                    // (ulObjectCount = 1).
                                ulObjectCount,
                                phObject)) == SM_NO_ERROR)
      {
         if (ulObjectCount > 0)
         {
            if (ulObjectCount == 1)
            {
               m_hPrivateKey = *phObject;
               found = true;

               // Make sure status reflects success 
               // in finding private-key.
               status = SM_NO_ERROR;
            }
            else
               status = SM_PKCS11_NONE_UNIQUE_PRIV_KEY;
         }
         else
            status = SM_PKCS11_NO_PRIVATE_KEY;
      }

   }

   return status;
}
///////////////////////////////////////////////////////////////////////////////////
CK_MECHANISM_PTR CSM_Pkcs11::GetMechanismStruct(AsnOid *pOid)
{
   bool foundMechanism = FALSE;
   CK_MECHANISM_PTR pMechanismStruct = NULL_PTR;
   CSM_Pkcs11MechanismInfoLst::iterator itMechanismInfo;

   CSM_Pkcs11MechanismInfoLst *pMechanismInfoLst = m_pSlot->AccessMechanismLst();
   
   if (pMechanismInfoLst)
   for (itMechanismInfo =  pMechanismInfoLst->begin();
        itMechanismInfo != pMechanismInfoLst->end() && !foundMechanism;
        ++itMechanismInfo)
   {
      if (itMechanismInfo->AccessOid())
      {
         if (*itMechanismInfo->AccessOid() == *pOid)
         {
            pMechanismStruct = itMechanismInfo->GetMechanismStruct();
            foundMechanism = TRUE;
         }
      }
   }    // END FOR each mechanismInfo in list.

   return pMechanismStruct;
}
///////////////////////////////////////////////////////////////////////////////////
CK_MECHANISM_INFO_PTR CSM_Pkcs11::GetMechanismInfo(AsnOid *pOid)
{
   bool foundMechanism = FALSE;
   CK_MECHANISM_INFO_PTR pMechanismInfo = NULL_PTR;
   CSM_Pkcs11MechanismInfoLst::iterator itPkcs11MechanismInfo;

   CSM_Pkcs11MechanismInfoLst *pPkcs11MechanismInfoLst = 
                                    m_pSlot->AccessMechanismLst();
   
   if (pPkcs11MechanismInfoLst)
   for (itPkcs11MechanismInfo =  pPkcs11MechanismInfoLst->begin();
        itPkcs11MechanismInfo != pPkcs11MechanismInfoLst->end() && 
            !foundMechanism;
        ++itPkcs11MechanismInfo)
   {
      if (itPkcs11MechanismInfo->AccessOid())
      {
         if (pOid && *itPkcs11MechanismInfo->AccessOid() == *pOid)
         {
            pMechanismInfo = itPkcs11MechanismInfo->GetMechanismInfo();
            foundMechanism = TRUE;
         }
         else if (pOid == NULL && 
                 *itPkcs11MechanismInfo->AccessOid() == rsaEncryption)
         {
            pMechanismInfo = itPkcs11MechanismInfo->GetMechanismInfo();
            foundMechanism = TRUE;
         }
      }
   }        // END FOR mechanismInfos in list.

   return pMechanismInfo;
}
SM_RET_VAL CSM_Pkcs11::DecodeRSAPublicKey(CSM_Buffer *pPublicKey,
                                          CK_BYTE_PTR &pModulus,
                                          CK_ULONG &ulModulusLen,
                                          CK_BYTE_PTR &pExponent,
                                          CK_ULONG &ulExponentLen)
{
   SM_RET_VAL status = SM_NO_ERROR;

   RSAPublicKey SnaccRSAPublicKey;
   //RWC;CSM_Buffer *pTmpModulus = new CSM_Buffer;

   SME_SETUP("CSM_Pkcs11::DecodeRSAPublicKey");

   // Decode public key into snacc class so we can access the 
   // modulus and exponent values for the public key template.
   SME(DECODE_BUF(&SnaccRSAPublicKey, pPublicKey));

   AsnInt tmpModulus(SnaccRSAPublicKey.modulus);

   // Hardcode true length.
   ulModulusLen = SnaccRSAPublicKey.modulus.length(); //RWC;9/5/02;128;

   unsigned char *ptr=NULL;
   unsigned int length=0;
   tmpModulus.getPadded(ptr/**pTmpModulus*/, length, ulModulusLen);  

   if ((pModulus = (CK_BYTE_PTR) ptr/*RWC;pTmpModulus->Get()*/) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   ulExponentLen = SnaccRSAPublicKey.publicExponent.length();

   if ((pExponent = (CK_BYTE_PTR) malloc(ulExponentLen)) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   memcpy(pExponent, SnaccRSAPublicKey.publicExponent.c_str(), ulExponentLen);

   //RWC;if (pTmpModulus)
   //RWC;   delete pTmpModulus;

   SME_FINISH
      SME_CATCH_SETUP
      //RWC;if (pTmpModulus)
      //RWC;   delete pTmpModulus;
      SME_CATCH_FINISH

   return status;
}

_END_CERT_NAMESPACE

// EOF sm_pkcs11Supplement.cpp
