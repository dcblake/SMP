
#pragma warning( disable : 4702 )   // MUST IGNORE, since even catch (...) 
                                    //  indicates "unreachable code", but 
                                    //  NULL pointer refs can crash.
#include "sm_api.h"
using namespace SNACC;
_BEGIN_SFL_NAMESPACE

//////////////////////////////////////////////////////////////////////////
// sm_RecipientInfo.cpp
// implementation of methods from:
//   CSM_RecipientInfo
//////////////////////////////////////////////////////////////////////////
//
//

CSM_RecipientInfo::CSM_RecipientInfo(const CSM_RecipientInfo &RI)
{
        *this = RI;
}   // CSM_RecipientInfo COPY constructor

//
//
CSM_RecipientInfo & CSM_RecipientInfo::operator =(const CSM_RecipientInfo &RI)
{
   Clear();

   if (this != &RI)
   {
      if (RI.m_pCert)
         m_pCert = new CSM_CertificateChoice(*RI.m_pCert);
       
      if (RI.m_pUkmBuf)
         m_pUkmBuf = new CSM_Buffer(RI.m_pUkmBuf);

      if (RI.m_pbufSharedUKMParams)
         m_pbufSharedUKMParams = new CSM_Buffer(RI.m_pbufSharedUKMParams);

      if (RI.m_pencryptionAlgOid)
         m_pencryptionAlgOid = new AsnOid(*RI.m_pencryptionAlgOid);

      if (RI.m_pbufParams)
         m_pbufParams = new CSM_Buffer(RI.m_pbufParams);

      if (RI.m_pKEKDetails)
         m_pKEKDetails = new CSM_KEKDetails(*RI.m_pKEKDetails);

      if (RI.m_pPWRIDetails)
         m_pPWRIDetails = new CSM_PWRIDetails(*RI.m_pPWRIDetails);

      if (RI.m_pOrigRID)
         m_pOrigRID = new CSM_RecipientIdentifier(RI.m_pOrigRID);

      if (RI.m_pKeyDerivationAlgOid)
         m_pKeyDerivationAlgOid = new AsnOid(*RI.m_pKeyDerivationAlgOid);

      if (RI.m_pKeyEncryptionAlgOid)
         m_pKeyEncryptionAlgOid = new AsnOid(*RI.m_pKeyEncryptionAlgOid);

      if (RI.m_pRecipientEncryptedKeysIterator)
      {
         m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
         m_pRecipientEncryptedKeysIterator = RI.m_pRecipientEncryptedKeysIterator;
      }
   }

   return(*this);
}   // CSM_RecipientInfo COPY constructor

CSM_RecipientInfo::~CSM_RecipientInfo()
{
   if (m_pCert)
      delete m_pCert;
   if (m_pUkmBuf)
      delete m_pUkmBuf;
   if (m_pbufSharedUKMParams)
       delete m_pbufSharedUKMParams;
   if (m_pencryptionAlgOid)
      delete m_pencryptionAlgOid;
   if (m_pbufParams)
      delete m_pbufParams;
   if (m_pKEKDetails)
      delete m_pKEKDetails;
   if (m_pPWRIDetails)
      delete m_pPWRIDetails;
   if (m_pOrigRID)
      delete m_pOrigRID;
   if (m_pKeyDerivationAlgOid)
      delete m_pKeyDerivationAlgOid;
   if (m_pKeyEncryptionAlgOid)
      delete m_pKeyEncryptionAlgOid;
   if (m_pRecipientEncryptedKeysIterator)
       delete m_pRecipientEncryptedKeysIterator;
}

//
//
KeyEncryptionAlgorithmIdentifier *CSM_RecipientInfo::AccesskeyEncryptionAlgorithm()
{
   KeyEncryptionAlgorithmIdentifier *pAccesskeyEncryptionAlgorithm=NULL;

   SME_SETUP("CSM_RecipientInfo::AccesskeyEncryptionAlgorithm");
   if (choiceId == RecipientInfo::ktriCid)
   {
      //  Version1      version;
      //  RecipientIdentifier      *rid;
      //  KeyEncryptionAlgorithmIdentifier      *keyEncryptionAlgorithm;
      //  EncryptedKey      encryptedKey;
      pAccesskeyEncryptionAlgorithm = &ktri->keyEncryptionAlgorithm;
   }
   else if (choiceId == RecipientInfo::kariCid)
   {
      //  Version1      version;
      //  OriginatorIdentifierOrKey      *originator;
      //  UserKeyingMaterial      *ukm;
      //  KeyEncryptionAlgorithmIdentifier      *keyEncryptionAlgorithm;
      //  RecipientEncryptedKeys      recipientEncryptedKeys;
      pAccesskeyEncryptionAlgorithm = &kari->keyEncryptionAlgorithm;
   }
   else if (choiceId == RecipientInfo::kekriCid)
   {
      pAccesskeyEncryptionAlgorithm = &kekri->keyEncryptionAlgorithm;
   }
   else if (choiceId == RecipientInfo::pwriCid)
   {
      // CMSVersion		version;
      // KeyDerivationAlgorithmIdentifier		*keyDerivationAlgorithm;
      // KeyEncryptionAlgorithmIdentifier		*keyEncryptionAlgorithm;
      // EncryptedKey		encryptedKey;      
      pAccesskeyEncryptionAlgorithm = &pwri->keyEncryptionAlgorithm;
   }


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return pAccesskeyEncryptionAlgorithm;
}

//
// AccessKeyDerivationAlgorithm
//
// returns:  KeyDerivationAlgorithmIdentifier
//
KeyDerivationAlgorithmIdentifier *CSM_RecipientInfo::AccesskeyDerivationAlgorithm()
{
   KeyDerivationAlgorithmIdentifier *pAccesskeyDerivationAlgorithm=NULL;

   SME_SETUP("CSM_RecipientInfo::AccesskeyDerivationAlgorithm");
   if (choiceId == RecipientInfo::pwriCid)
   {
      // CMSVersion		version;
      // KeyDerivationAlgorithmIdentifier		*keyDerivationAlgorithm;
      // KeyEncryptionAlgorithmIdentifier		*keyEncryptionAlgorithm;
      // EncryptedKey		encryptedKey;      
      pAccesskeyDerivationAlgorithm = pwri->keyDerivationAlgorithm;
   }


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return pAccesskeyDerivationAlgorithm;
}

//
//
EncryptedKey *CSM_RecipientInfo::AccessEncryptedKey()
{
   EncryptedKey *pAccessEncryptedKey=NULL;

   SME_SETUP("CSM_RecipientInfo::AccessEncryptedKey");
   if (choiceId == RecipientInfo::ktriCid)
   {
      pAccessEncryptedKey = &ktri->encryptedKey;
   }
   else if (choiceId == RecipientInfo::kariCid)
   {
      if (m_pRecipientEncryptedKeysIterator &&
          *m_pRecipientEncryptedKeysIterator != kari->recipientEncryptedKeys.end())
      {
         pAccessEncryptedKey = &(*m_pRecipientEncryptedKeysIterator)->encryptedKey;
      }
   }
   else if (choiceId == RecipientInfo::kekriCid)
   {
      pAccessEncryptedKey = &kekri->encryptedKey;
   }
   else if (choiceId == RecipientInfo::pwriCid)
   {
      pAccessEncryptedKey = &pwri->encryptedKey;
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return(pAccessEncryptedKey);
}

OriginatorIdentifierOrKey *CSM_RecipientInfo::AccessOriginatorCertID()
{
   OriginatorIdentifierOrKey *pSNACCId=NULL;

   SME_SETUP("CSM_RecipientInfo::AccessOriginatorCertID");
   if (choiceId == RecipientInfo::kariCid)
   {
      pSNACCId = &kari->originator;
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return(pSNACCId);
}


CSM_RecipientIdentifier *CSM_RecipientInfo::GetRid()
{
   CSM_RecipientIdentifier *pRid=NULL;
   CSM_IssuerAndSerialNumber *pIss;
   SME_SETUP("CSM_RecipientInfo::GetRid");

   if ((ktri == NULL ||                               // structure is empty.
      (m_RID.AccessSubjectKeyIdentifier() == NULL &&
       m_RID.AccessIssuerAndSerial() == NULL &&
       m_RID.AccessOrigPubKey() == NULL))  &&    // OR ID is empty.
       m_pCert != NULL && 
       m_pCert->AccessEncodedCert() != NULL)       //IF RecipientInfo RID is empty (UNION)
   {
      if (m_bIssOrSki)
      {
         const CSM_Buffer *pCert = m_pCert->AccessEncodedCert();
         if (pCert != NULL)
         {
            if ((pIss = new CSM_IssuerAndSerialNumber((CSM_Buffer *)pCert)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            pRid = new CSM_RecipientIdentifier(*pIss);
            delete pIss;
         }
         else
            SME_THROW(SM_MEMORY_ERROR, "No Certificate or pre-loaded RID", 
              NULL);
      }
      else
      {
         CSM_Identifier *pTmpRid = m_pCert->GetRid(m_bIssOrSki);
         if (pTmpRid)
         {
            pRid = new CSM_RecipientIdentifier(*pTmpRid);
            delete pTmpRid;
         }
         

      }

   }           // END IF RecipientInfo RID is empty
   else if (choiceId == RecipientInfo::ktriCid && ktri)
   {
      pRid = new CSM_RecipientIdentifier(ktri->rid);
         //RWC;alternative?;pRid = new CSM_RecipientIdentifier(m_RID);
   }
   else if (choiceId == RecipientInfo::kariCid && kari)
   {
      if (m_pRecipientEncryptedKeysIterator &&
          *m_pRecipientEncryptedKeysIterator != kari->recipientEncryptedKeys.end())
      {
         pRid = new CSM_RecipientIdentifier((*m_pRecipientEncryptedKeysIterator)->rid);
      }
   }
   else if (choiceId == RecipientInfo::kekriCid && kekri != NULL)
   {
      if (kekri->kekid.keyIdentifier.Len() > 0)
         pRid = new CSM_RecipientIdentifier(kekri->kekid);      
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return(pRid);
}


void CSM_RecipientInfo::SetKeyEncryptionAlgorithm(AsnOid &SNACCAlgId, 
                                                  CSM_Buffer &Params)
{
   SME_SETUP("CSM_RecipientInfo::SetKeyEncryptionAlgorithm");
   if (choiceId != RecipientInfo::ktriCid && choiceId != RecipientInfo::kariCid
       && choiceId != RecipientInfo::kekriCid)      // SET TO DEFAULT.
   {
      choiceId = RecipientInfo::kariCid;
      kari = new KeyAgreeRecipientInfo;
   }
   if (choiceId == RecipientInfo::ktriCid)
   {
      ktri->keyEncryptionAlgorithm.algorithm = SNACCAlgId;
      if (Params.Access() != NULL)
      {
        if ((ktri->keyEncryptionAlgorithm.parameters = new AsnAny) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
        SM_ASSIGN_ANYBUF((&Params), ktri->keyEncryptionAlgorithm.parameters);
      }
   }
   else if (choiceId == RecipientInfo::kariCid)
   {
      kari->keyEncryptionAlgorithm.algorithm = SNACCAlgId;
      if (Params.Access() != NULL)
      {
        if (kari->keyEncryptionAlgorithm.parameters == NULL)
        {
            if ((kari->keyEncryptionAlgorithm.parameters = new AsnAny) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
        }
        SM_ASSIGN_ANYBUF((&Params), kari->keyEncryptionAlgorithm.parameters);
      }
   }
   else if (choiceId == RecipientInfo::kekriCid)
   {
      kekri->keyEncryptionAlgorithm.algorithm = SNACCAlgId;
      if (Params.Access() != NULL)
      {
        if ((kekri->keyEncryptionAlgorithm.parameters = new AsnAny) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
        SM_ASSIGN_ANYBUF((&Params), kekri->keyEncryptionAlgorithm.parameters);
      }
   }
   else if (choiceId == RecipientInfo::pwriCid)
   {
      pwri->keyEncryptionAlgorithm.algorithm = SNACCAlgId;
      if (Params.Access() != NULL)
      {
        if ((pwri->keyEncryptionAlgorithm.parameters = new AsnAny) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
        SM_ASSIGN_ANYBUF((&Params), pwri->keyEncryptionAlgorithm.parameters);
      }
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

}

//
//
void CSM_RecipientInfo::SetRid(IssuerAndSerialNumber &SNACCIssuer)
{
   RecipientIdentifier SNACCRid;
   SNACCRid.choiceId = RecipientIdentifier::issuerAndSerialNumberCid;

   SME_SETUP("CSM_RecipientInfo::SetRid(Issuer)");
   
   if ((SNACCRid.issuerAndSerialNumber = new IssuerAndSerialNumber) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   *SNACCRid.issuerAndSerialNumber = SNACCIssuer;
   SetRid(SNACCRid);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}

//
//
void CSM_RecipientInfo::SetRid(CSM_Buffer &KeyId)
{
   RecipientIdentifier SNACCRid;

   SME_SETUP("CSM_RecipientInfo::SetRid(Csm_Buffer)");

   SNACCRid.choiceId = RecipientIdentifier::subjectKeyIdentifierCid;
   if ((SNACCRid.subjectKeyIdentifier = new SubjectKeyIdentifier) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   SNACCRid.subjectKeyIdentifier->Set(KeyId.Access(), KeyId.Length());
   SetRid(SNACCRid);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}

//
//
void CSM_RecipientInfo::SetRid(RecipientIdentifier &SNACCRid)
{
   SME_SETUP("CSM_RecipientInfo::SetRid(RecipientIdentifier)");
   if (choiceId == RecipientInfo::ktriCid)
   {
      ktri->rid = SNACCRid;
   }
   else //RWC; ALL OTHERS SHOULD FAIL.if (choiceId == RecipientInfo::kariCid)
   {
         SME_THROW(SM_MEMORY_ERROR, "Bad RecipientIdentifier to other than KTRI"
            , NULL);
   }


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}

//
//
void CSM_RecipientInfo::SetRid(CSM_RecipientIdentifier &Rid)
{
   SME_SETUP("CSM_RecipientInfo::SetRid(CSM_RecipientIdentifier)");
   if (choiceId == RecipientInfo::ktriCid)
   {
      if (ktri == NULL)
          ktri = new KeyTransRecipientInfo;
      RecipientIdentifier *pSNACCRid = Rid.GetRecipientIdentifier();
      if (pSNACCRid)
      {
         ktri->rid = *pSNACCRid;
         delete pSNACCRid;
      }     // END IF pSNACCRid
   }
   else if (choiceId == RecipientInfo::kariCid)
   {
      if (kari == NULL)
      {
          if ((kari = new KeyAgreeRecipientInfo) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
      }     // END IF kari == NULL
      if (m_pRecipientEncryptedKeysIterator == NULL)
      {
          if ((m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator) 
              == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL);
          kari->recipientEncryptedKeys.append();    // CREATE 1st entry by default.
          *m_pRecipientEncryptedKeysIterator = kari->recipientEncryptedKeys.begin();
      }     // END IF m_pRecipientEncryptedKeysIterator == NULL
      if (*m_pRecipientEncryptedKeysIterator != kari->recipientEncryptedKeys.end())
      {
          KeyAgreeRecipientIdentifier *pSNACCRid = Rid.GetKeyAgreeRecipientIdentifier();
          if (pSNACCRid)
          {
             (*m_pRecipientEncryptedKeysIterator)->rid = *pSNACCRid;
             delete pSNACCRid;
          }     // END IF pSNACCRid
      }
   }
   else if (choiceId == RecipientInfo::kekriCid)
   {
      if (kekri == NULL)
          kekri = new KEKRecipientInfo;
      KEKIdentifier *pSNACCRid = Rid.GetKEKIdentifier();
      if (pSNACCRid)
      {
         kekri->kekid = *pSNACCRid;
         delete pSNACCRid;
      }     // END IF pSNACCRid
   }


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}

//
//
void CSM_RecipientInfo::SetRid(KeyAgreeRecipientIdentifier &SNACCKARid)
{

   SME_SETUP("CSM_RecipientInfo::SetRid(KeyAgreeRecipientIdentifier)");
   if (choiceId == RecipientInfo::kariCid)
   {
      if (m_pRecipientEncryptedKeysIterator &&
          *m_pRecipientEncryptedKeysIterator != kari->recipientEncryptedKeys.end())
      {
         (*m_pRecipientEncryptedKeysIterator)->rid = SNACCKARid;
      }
   }
   else
   {
         SME_THROW(SM_MEMORY_ERROR, "Bad KeyAgreeRecipientIdentifier to other "
            "than KARI", NULL);
   }


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}

void CSM_RecipientInfo::SetEncryptedKey(CSM_Buffer &bufEMEK)
{
   SME_SETUP("CSM_RecipientInfo::SetEncryptedKey");

   if (choiceId == RecipientInfo::ktriCid)
   {
      ktri->encryptedKey.Set(bufEMEK.Access(), bufEMEK.Length());
   }
   else if (choiceId == RecipientInfo::kariCid)
   {
      if (m_pRecipientEncryptedKeysIterator == NULL ||
          *m_pRecipientEncryptedKeysIterator == kari->recipientEncryptedKeys.end())
      {
          if (m_pRecipientEncryptedKeysIterator == NULL)
              m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
          *m_pRecipientEncryptedKeysIterator = kari->recipientEncryptedKeys.append();
      }     // END IF m_pRecipientEncryptedKeysIterator empty or at end()

      (*m_pRecipientEncryptedKeysIterator)->encryptedKey.Set(bufEMEK.Access(), bufEMEK.Length());
   }
   else if (choiceId == RecipientInfo::kekriCid)
   {
      kekri->encryptedKey.Set(bufEMEK.Access(), bufEMEK.Length());
   }
   else if (choiceId == RecipientInfo::pwriCid)
   {
      pwri->encryptedKey.Set(bufEMEK.Access(), bufEMEK.Length());
   }


   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

}

void CSM_RecipientInfo::SetEncryptedKey(RecipientInfo &SNACCRecipientInfo)
{
   SME_SETUP("CSM_RecipientInfo::SetEncryptedKey()");

   if (SNACCRecipientInfo.choiceId == RecipientInfo::ktriCid)
   {
      SNACCRecipientInfo.ktri->encryptedKey.Set(m_bufEMEK.Access(), 
         m_bufEMEK.Length());
      if (m_pencryptionAlgOid)
      {
         SNACCRecipientInfo.ktri->keyEncryptionAlgorithm.algorithm = *m_pencryptionAlgOid;
      }
      if (m_pbufParams && m_pbufParams->Access() != NULL)
      {
        if (SNACCRecipientInfo.ktri->keyEncryptionAlgorithm.parameters == NULL)
        {
            if ((SNACCRecipientInfo.ktri->keyEncryptionAlgorithm.parameters = new AsnAny) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
        }
        else
        {
            if (SNACCRecipientInfo.ktri->keyEncryptionAlgorithm.parameters->value)
                delete (CSM_Buffer *)SNACCRecipientInfo.ktri->
                                      keyEncryptionAlgorithm.parameters->value;
        }
        SM_ASSIGN_ANYBUF(m_pbufParams, SNACCRecipientInfo.ktri->keyEncryptionAlgorithm.parameters);
      }
   }
   else if (SNACCRecipientInfo.choiceId == RecipientInfo::kariCid)
   {
      if (m_pRecipientEncryptedKeysIterator == NULL ||
          *m_pRecipientEncryptedKeysIterator == SNACCRecipientInfo.kari->recipientEncryptedKeys.end())
      {
          if (m_pRecipientEncryptedKeysIterator == NULL)
             m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
          *m_pRecipientEncryptedKeysIterator = SNACCRecipientInfo.kari->recipientEncryptedKeys.append();
      }
      (*m_pRecipientEncryptedKeysIterator)->encryptedKey.Set(m_bufEMEK.Access(), m_bufEMEK.Length());
      if (m_pencryptionAlgOid)
      {
         SNACCRecipientInfo.kari->keyEncryptionAlgorithm.algorithm = *m_pencryptionAlgOid;
      }
        if (SNACCRecipientInfo.kari->keyEncryptionAlgorithm.parameters ==NULL)
        {
            if ((SNACCRecipientInfo.kari->keyEncryptionAlgorithm.parameters = new 
               AsnAny) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
        }
        else
        {
            if (SNACCRecipientInfo.kari->keyEncryptionAlgorithm.parameters->value)
                delete (CSM_Buffer *)SNACCRecipientInfo.kari->keyEncryptionAlgorithm.
                    parameters->value;
        }
      if (m_pbufParams && m_pbufParams->Access() != NULL)
      {
        SM_ASSIGN_ANYBUF(m_pbufParams, 
            SNACCRecipientInfo.kari->keyEncryptionAlgorithm.parameters);
      }     // END IF m_pbufParams
   }
   else if (SNACCRecipientInfo.choiceId == RecipientInfo::kekriCid)
   {
      if (m_pencryptionAlgOid)
      {
         SNACCRecipientInfo.kekri->keyEncryptionAlgorithm.algorithm = *m_pencryptionAlgOid;
      }
      if (m_pbufParams && m_pbufParams->Access() != NULL)
      {
        if (SNACCRecipientInfo.kekri->keyEncryptionAlgorithm.parameters ==NULL)
        {
            if ((SNACCRecipientInfo.kekri->keyEncryptionAlgorithm.parameters = new 
               AsnAny) == NULL)
               SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
        }
        else
        {
            if (SNACCRecipientInfo.kekri->keyEncryptionAlgorithm.parameters->value)
                delete (CSM_Buffer *)SNACCRecipientInfo.kekri->keyEncryptionAlgorithm.
                    parameters->value;
        }
        SM_ASSIGN_ANYBUF(m_pbufParams, 
           SNACCRecipientInfo.kekri->keyEncryptionAlgorithm.parameters);
      }
      SNACCRecipientInfo.kekri->encryptedKey.Set(m_bufEMEK.Access(), 
                                m_bufEMEK.Length());
   }
   else if (SNACCRecipientInfo.choiceId == RecipientInfo::pwriCid)
   {
    
      // key derivation and keyEncryption Algs oids are set prior to this in the
      // calling function.

      if (SNACCRecipientInfo.pwri->keyEncryptionAlgorithm.parameters ==NULL)
      {
         if ((SNACCRecipientInfo.pwri->keyEncryptionAlgorithm.parameters = new 
            AsnAny) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY allocation", NULL);
      }
      else
      {
         if (SNACCRecipientInfo.pwri->keyEncryptionAlgorithm.parameters->value)
                delete (CSM_Buffer *)SNACCRecipientInfo.pwri->keyEncryptionAlgorithm.
                    parameters->value;
      }
      SM_ASSIGN_ANYBUF(m_pbufParams, 
           SNACCRecipientInfo.pwri->keyEncryptionAlgorithm.parameters);

      SNACCRecipientInfo.pwri->encryptedKey.Set(m_bufEMEK.Access(), 
         m_bufEMEK.Length());
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

}

void CSM_RecipientInfo::GetEncryptedKey()
{
   SME_SETUP("CSM_RecipientInfo::GetEncryptedKey()");

   if (choiceId == RecipientInfo::ktriCid)
   {
      m_pencryptionAlgOid = new AsnOid(ktri->keyEncryptionAlgorithm.algorithm);
      ktri->keyEncryptionAlgorithm.algorithm = *m_pencryptionAlgOid;
      if (ktri->keyEncryptionAlgorithm.parameters)
      {
        SM_EXTRACT_ANYBUF(m_pbufParams, ktri->keyEncryptionAlgorithm.parameters);
      }
      m_bufEMEK.Set(ktri->encryptedKey.c_str(), ktri->encryptedKey.Len());
   }
   else if (choiceId == RecipientInfo::kariCid)
   {
      if (m_pRecipientEncryptedKeysIterator == NULL ||
          *m_pRecipientEncryptedKeysIterator == kari->recipientEncryptedKeys.end())
      {
         if (m_pRecipientEncryptedKeysIterator == NULL)
             m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
         *m_pRecipientEncryptedKeysIterator = kari->recipientEncryptedKeys.begin();
         if (*m_pRecipientEncryptedKeysIterator == kari->recipientEncryptedKeys.end())
             SME_THROW(SM_MEMORY_ERROR, "EMPTY RI key list", NULL);
      }
      m_pencryptionAlgOid = new AsnOid(kari->keyEncryptionAlgorithm.algorithm);
      if (kari->keyEncryptionAlgorithm.parameters)
      {
        SM_EXTRACT_ANYBUF(m_pbufParams, kari->keyEncryptionAlgorithm.parameters);
      }
      m_bufEMEK.Set((*m_pRecipientEncryptedKeysIterator)->encryptedKey.c_str(), 
                    (*m_pRecipientEncryptedKeysIterator)->encryptedKey.Len());
   }
   else if (choiceId == RecipientInfo::kekriCid)
   {
      m_pencryptionAlgOid = new AsnOid(kekri->keyEncryptionAlgorithm.algorithm);
      if (kekri->keyEncryptionAlgorithm.parameters)
      {
        SM_EXTRACT_ANYBUF(m_pbufParams, kekri->keyEncryptionAlgorithm.parameters);
      }
      m_bufEMEK.Set(kekri->encryptedKey.c_str(), kekri->encryptedKey.Len());
   }
   else if (choiceId == RecipientInfo::pwriCid)
   {
      m_pKeyEncryptionAlgOid = new AsnOid(pwri->keyEncryptionAlgorithm.algorithm);
      if (pwri->keyEncryptionAlgorithm.parameters)
      {
        SM_EXTRACT_ANYBUF(m_pbufParams, pwri->keyEncryptionAlgorithm.parameters);
      }

      m_bufEMEK.Set(pwri->encryptedKey.c_str(), pwri->encryptedKey.Len());      
      
      if (pwri->keyDerivationAlgorithm)
      {
        m_pKeyDerivationAlgOid = new AsnOid(pwri->keyDerivationAlgorithm->algorithm);
      } 
      
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

}


void CSM_RecipientInfo::SetOriginatorID(CSM_RecipientIdentifier &Orig)
{
   SME_SETUP("CSM_RecipientInfo::SetOriginatorID");

   if (choiceId == RecipientInfo::kariCid)
   {
      OriginatorIdentifierOrKey *pSNACCKey = Orig.GetOrigIdentOrKey();
      if (pSNACCKey)
      {
        kari->originator = *pSNACCKey;
        delete pSNACCKey;
      }     // END IF pSNACCKey
   }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
}


//
//
void CSM_RecipientInfo::AssignSNACCRI(const RecipientInfo &SNACCRi)
{
   choiceId = SNACCRi.choiceId;
   if (choiceId == RecipientInfo::ktriCid)
   {
      ktri = new KeyTransRecipientInfo;
      *ktri = *SNACCRi.ktri;
   }
   else if (choiceId == RecipientInfo::kariCid)
   {
      kari = new KeyAgreeRecipientInfo;
      *kari = *SNACCRi.kari;
      // RWC;NOTE; The SNACC copy operation clears the recip encrypted keys
      //  index; MUST BE RESET in both variables!!!
      if (m_pRecipientEncryptedKeysIterator == NULL)
          m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
      *m_pRecipientEncryptedKeysIterator = kari->recipientEncryptedKeys.begin();
   }
   else if (choiceId == RecipientInfo::kekriCid)
   {
      kekri = new KEKRecipientInfo;
      *kekri = *SNACCRi.kekri;
   }
   else if (choiceId == RecipientInfo::pwriCid)
   {
      pwri = new PasswordRecipientInfo;
      *pwri = *SNACCRi.pwri;
   }
   if (m_pCert)
   {
      delete m_pCert;
      m_pCert = NULL;
   }
   if (m_pKEKDetails)
   {
      delete m_pKEKDetails;
      m_pKEKDetails = NULL;
   }
   if (m_pPWRIDetails)
   {
      delete m_pPWRIDetails;
      m_pPWRIDetails = NULL;
   }
   if (m_pUkmBuf)
   {
      delete m_pUkmBuf;
      m_pUkmBuf = NULL;
   }
   if (m_pKeyDerivationAlgOid)
   {
      delete m_pKeyDerivationAlgOid;
      m_pKeyDerivationAlgOid = NULL;
   }
   if (m_pKeyEncryptionAlgOid)
   {
      delete m_pKeyEncryptionAlgOid;
      m_pKeyEncryptionAlgOid = NULL;
   }

}

//
//  RWC; For comparison of RecipientInfos, only compare Recipient IDs.
bool CSM_RecipientInfo::operator == (CSM_RecipientInfo &RI)
{
   bool bFlag=false;
   CSM_RecipientIdentifier *p2;

   p2 = RI.GetRid();
   bFlag = (*this == *p2);
   delete p2;

   return(bFlag);
}

//
//  RWC; For comparison of RecipientInfos, only compare Recipient IDs.
bool CSM_RecipientInfo::operator == (CSM_RecipientIdentifier &Rid)
{
   bool bFlag=false;
   CSM_RecipientIdentifier *p1;

   p1 = GetRid();
   bFlag = (*p1 == Rid);

   /*if (p1->choiceId == SNACC_RID.choiceId)
   {
         switch (p1->choiceId)
         {
         case RecipientIdentifier::issuerAndSerialNumberCid:
            {
               if(SNACC_RID.choiceId == RecipientIdentifier::issuerAndSerialNumberCid)
               {
                  CSM_IssuerAndSerialNumber p3(*p1->issuerAndSerialNumber);
                  CSM_IssuerAndSerialNumber p4(*SNACC_RID.issuerAndSerialNumber);
                  bFlag = (p3 == p4);
               }
            }
            break;

         case RecipientIdentifier::subjectKeyIdentifierCid:
            { 
               if(SNACC_RID.choiceId == RecipientIdentifier::subjectKeyIdentifierCid)
               {
                 CSM_Buffer p5((char *)p1->subjectKeyIdentifier, 
                   p1->subjectKeyIdentifier->Len());
                 CSM_Buffer p6((char *)SNACC_RID.subjectKeyIdentifier, 
                   SNACC_RID.subjectKeyIdentifier->Len());
                 bFlag = (p5 == p6);
               }
            }
            break;
         }
   }*/

   if (p1) delete p1;

   return(bFlag);
}


//
//  RWC; For comparison of RecipientInfos, only compare Recipient IDs.
bool CSM_RecipientInfo::operator == (IssuerAndSerialNumber &SNACC_Issuer)
{
   bool bFlag=false;
   CSM_RecipientIdentifier *p1;
   CSM_IssuerAndSerialNumber *p2;
   CSM_IssuerAndSerialNumber tmpISN(SNACC_Issuer);

   p1 = GetRid();
   p2 = p1->GetIssuerAndSerial();
   bFlag = (p2 && *p2 == tmpISN);
      
         /*switch (p1->choiceId)
         {
         case RecipientIdentifier::issuerAndSerialNumberCid:
            {
              CSM_IssuerAndSerialNumber p3(*p1->issuerAndSerialNumber);
              CSM_IssuerAndSerialNumber p4(SNACC_Issuer);
              bFlag = (p3 == p4);
            }
            break;

         case RecipientIdentifier::subjectKeyIdentifierCid:
            // RWC; NOT the same.
            break;
         }*/
   if (p1) 
      delete p1;
   if (p2) 
      delete p2;

   return(bFlag);
}

RecipientInfo * CSM_RecipientInfo::GetSharedRI(
                          RecipientInfos &SNACCRecipientInfos,  
                          CSM_Alg &keyEncryptionAlgId,
                          CSM_RecipientInfoLst   *pRecipients)
{
   CSM_RecipientInfo *pRI = NULL;
   RecipientInfo *pSNACCRecipientInfo = NULL;
   RecipientInfos::iterator itSnaccRI;

     pSNACCRecipientInfo = NULL;
     for(itSnaccRI =  SNACCRecipientInfos.begin();
         itSnaccRI != SNACCRecipientInfos.end();
         ++itSnaccRI)
     {
        pRI = new CSM_RecipientInfo(*itSnaccRI);
        CSM_RecipientIdentifier *pTmpSnaccRid=pRI->GetRid();
        CSM_RecipientIdentifier tmpRID(*pTmpSnaccRid);
        delete pTmpSnaccRid;
        CSM_RecipientIdentifier *pTmpRID2;
        CSM_Alg *pTmpAlg=NULL;
        CSM_RecipientInfoLst::iterator itTmpRecip;
        //if (m_pbufSharedUKMParams)  // THEN replace CMS Params with specific
        {                           //  for this RI set, since not directly 
                                    //  loaded into the RI for each RECIPIENT.
           for(itTmpRecip =  pRecipients->begin();
               itTmpRecip != pRecipients->end();
               ++itTmpRecip) //LOOK for this DH RI
           {
              if (*(pTmpRID2=itTmpRecip->GetRid()) == tmpRID && 
                    itTmpRecip->m_pbufSharedUKMParams) 
              {
                  pTmpAlg = new CSM_Alg(*itTmpRecip->m_pencryptionAlgOid, 
                        *itTmpRecip->m_pbufSharedUKMParams);
                  delete pTmpRID2;
                  break;
              }
              else
              {
                  pTmpAlg = new CSM_Alg(*itTmpRecip->m_pencryptionAlgOid);
                  delete pTmpRID2;
                  break;
              }
           }

            if(keyEncryptionAlgId == *pTmpAlg)
            {
               pSNACCRecipientInfo = &(*itSnaccRI);
            }
            if (pTmpAlg)
                delete pTmpAlg;
        }
        //RWC; GET PROPER Parameters from original Cert, no longer in ESDH AlgId.
     }      // END for SNACC RIs

     // clean-up
     if (pRI)
        delete pRI;

  return(pSNACCRecipientInfo);
}

//
// This routine loads a SNACC RecipientInfo instead of returning one since 
//  it may actually load an existing RecipientInfo with an additional shared
//  entry.
void CSM_RecipientInfo::LoadSNACCRecipientInfo(
   CSM_CSInst &csInst,                    // In, for KeyAgree check
   RecipientInfos &SNACCRecipientInfos,   // In/Out, "this" is loaded.
   bool bSharedUkms,                      // In, flag to share Ukm, Dynamic key
   CSM_Alg &ProcessingAlg,
   CSM_RecipientInfoLst   *pRecipients)
{

   RecipientInfo *pSNACCRecipientInfo=NULL;
   //CSM_RecipientInfo *pSnaccRI;
   CSM_Alg *pkeyEncryptionAlgId = NULL;
    CSM_Buffer *pBuf;


   SME_SETUP("CSM_RecipientInfo::LoadSNACCRecipieintInfo"); 


   if(bSharedUkms && csInst.AccessTokenInterface()->SMTI_IsKeyAgreement() && 
      m_pKEKDetails == NULL)
   {
     // Loop through RecipientInfo for cInst KeyEncryptionAlgorithm
     pkeyEncryptionAlgId = CSM_SignBuf::GetPreferredKeyEncryptionAlg(csInst);
     if ((pBuf=ProcessingAlg.GetParams()) != NULL)
     {
         if (pkeyEncryptionAlgId->parameters == NULL)
             pkeyEncryptionAlgId->parameters = new AsnAny;
         SM_ASSIGN_ANYBUF(pBuf, pkeyEncryptionAlgId->parameters);
         delete pBuf;
     }

     pSNACCRecipientInfo = GetSharedRI(SNACCRecipientInfos,*pkeyEncryptionAlgId
         , pRecipients);

     delete pkeyEncryptionAlgId;
   }


   //if(!bSharedUkms || !cInst.AccessTokenInterface()->SMTI_IsKeyAgreement())
   if (m_pKEKDetails == NULL &&  // not kek or pwri
       m_pPWRIDetails == NULL)   // MUST be kari OR ktri.
   {
      if (csInst.AccessTokenInterface()->SMTI_IsKeyAgreement())
      {
         RecipientEncryptedKey *pSNACCKARiKey;
         if (pSNACCRecipientInfo == NULL)   // May already be set.
         {
            RecipientInfo &SNACCRecipientInfo = *SNACCRecipientInfos.append();
            pSNACCRecipientInfo = &SNACCRecipientInfo;
            pSNACCRecipientInfo->choiceId = RecipientInfo::kariCid;
            pSNACCRecipientInfo->kari = new KeyAgreeRecipientInfo;
            pSNACCRecipientInfo->kari->version = 3;  // SEE ASN.1 specification
            if (m_pbufSharedUKMParams != NULL)  // ONLY FOR NEW RI!!!
                delete m_pbufSharedUKMParams;
            m_pbufSharedUKMParams = ProcessingAlg.GetParams();
         }
      
         if(m_pOrigRID) // FOR ESDH Shared UKM, the key pair is re-used
         {
             // BE sure it is not already present for Shared UKM.
             OriginatorIdentifierOrKey *pSNACCRID2 = m_pOrigRID->GetOrigIdentOrKey(&csInst);
             pSNACCRecipientInfo->kari->originator = *pSNACCRID2;
             delete pSNACCRID2;
         }
         else
           SME_THROW(SM_MEMORY_ERROR, "Bad Originator ID", NULL);

         if (pSNACCRecipientInfo->kari->ukm == NULL && m_pUkmBuf)
         {                     // May aleady be set, if sharing UKMs.
              pSNACCRecipientInfo->kari->ukm = new UserKeyingMaterial;
              pSNACCRecipientInfo->kari->ukm->Set(m_pUkmBuf->Access(), 
                                    m_pUkmBuf->Length());
         }
         if (m_pRecipientEncryptedKeysIterator == NULL)
             m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
         *m_pRecipientEncryptedKeysIterator = pSNACCRecipientInfo->kari->recipientEncryptedKeys.append();
         pSNACCKARiKey = &(*(*m_pRecipientEncryptedKeysIterator));

         CSM_RecipientIdentifier *pTmpRid = GetRid();
         KeyAgreeRecipientIdentifier *pRID2 = pTmpRid->GetKeyAgreeRecipientIdentifier();
         pSNACCKARiKey->rid = *pRID2;
         delete pRID2;
         delete pTmpRid;
      }
      else                       // RWC; symmetric encryption alg, key transfer.
      {
         pSNACCRecipientInfo = &(*SNACCRecipientInfos.append());
         pSNACCRecipientInfo->choiceId = RecipientInfo::ktriCid;
         pSNACCRecipientInfo->ktri = new KeyTransRecipientInfo;
         CSM_RecipientIdentifier *pTmpRid = GetRid();
         RecipientIdentifier *pRID2 = pTmpRid->GetRecipientIdentifier();
         pSNACCRecipientInfo->ktri->rid = *pRID2;
         delete pRID2;
         delete pTmpRid;
         if (pSNACCRecipientInfo->ktri->rid.choiceId == 
             RecipientIdentifier::issuerAndSerialNumberCid)
         {              // 0 for Iss&SN, 2 for SubjKeyId.
             pSNACCRecipientInfo->ktri->version = 0;  //SEE ASN.1 specification
         }
         else
         {
             pSNACCRecipientInfo->ktri->version = 2;  //SEE ASN.1 specification
         }
      }
   
   }
   else  if ( m_pKEKDetails != NULL)  // MUST be KEK.
   {
       pSNACCRecipientInfo = &(*SNACCRecipientInfos.append());
       pSNACCRecipientInfo->choiceId = RecipientInfo::kekriCid;
       pSNACCRecipientInfo->kekri = new KEKRecipientInfo;
       pSNACCRecipientInfo->kekri->version = 4;
       KEKIdentifier *pRID2 = m_pKEKDetails->m_RID.GetKEKIdentifier();
       pSNACCRecipientInfo->kekri->kekid = *pRID2;
       delete pRID2;
   }
   else if (m_pPWRIDetails != NULL)  // MUST be PWRI
   {
       pSNACCRecipientInfo = &(*SNACCRecipientInfos.append());
       pSNACCRecipientInfo->choiceId = RecipientInfo::pwriCid;
       pSNACCRecipientInfo->pwri = new PasswordRecipientInfo;
       pSNACCRecipientInfo->pwri->version = 0;
       
       if(m_pPWRIDetails->m_pKeyDerivationAlgorithm != NULL)
          pSNACCRecipientInfo->pwri->keyDerivationAlgorithm = new AlgorithmIdentifier(*m_pPWRIDetails->m_pKeyDerivationAlgorithm);
       pSNACCRecipientInfo->pwri->keyEncryptionAlgorithm = *m_pPWRIDetails->m_pKeyEncryptionAlgorithm;
   }

   SetEncryptedKey(*pSNACCRecipientInfo);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      // cleanup based on bSomethingLoaded
   SME_CATCH_FINISH
}        //CSM_DataToEncrypt::SetRecipientInfo


void CSM_RecipientInfo::UnloadSNACCRecipientInfo()
{
   SME_SETUP("CSM_RecipientInfo::UnloadSNACCRecipieintInfo"); 



   if (choiceId == RecipientInfo::kariCid)   // MUST be kari OR ktri.
   {
      
         m_pOrigRID = new CSM_RecipientIdentifier(kari->originator);

         if (kari->ukm != NULL)
         {
              m_pUkmBuf = new CSM_Buffer(kari->ukm->c_str(),
                 kari->ukm->Len());
         }
         if (m_pRecipientEncryptedKeysIterator == NULL ||
             *m_pRecipientEncryptedKeysIterator == kari->recipientEncryptedKeys.end())
         {
            if (m_pRecipientEncryptedKeysIterator == NULL)
                m_pRecipientEncryptedKeysIterator = new RecipientEncryptedKeys::iterator;
            *m_pRecipientEncryptedKeysIterator = kari->recipientEncryptedKeys.begin();
         }
         if (*m_pRecipientEncryptedKeysIterator != kari->recipientEncryptedKeys.end())
         {
            CSM_RecipientIdentifier p((*m_pRecipientEncryptedKeysIterator)->rid);
            m_RID = p;
         }
   }
   else if (choiceId == RecipientInfo::ktriCid)
   {                   // RWC; symmetric encryption alg, key transfer.
      CSM_RecipientIdentifier p(ktri->rid);
      m_RID = p;
   }
   else if (choiceId == RecipientInfo::kekriCid)
   {
     CSM_RecipientIdentifier p(kekri->kekid);
     m_pKEKDetails = new CSM_KEKDetails;
     m_pKEKDetails->m_RID = p;
     CSM_Alg *pAlg=new CSM_Alg(*AccesskeyEncryptionAlgorithm());
     m_pKEKDetails->m_keyEncryptionAlgorithm = *pAlg;
                    // redundant, but used as flag.
     delete pAlg;
     // MUST BE LOADED BY APP;m_pKEKDetails->m_UserEncryptionData
     // CALLER MUST CHECK FOR APP loaded details matching ID of 
     // m_pKEKDetails->m_RID.  This ID takes the place of cert Iss & SN.
     //  (e.g. for testing we use a password for recipientInfo encrypted "MEK" 
     //   stored locally in "m_pKEKDetails->m_UserEncryptionData" and a string
     //   to ID in "kekri->kekid->keyIdentifier").
     //  "m_pKEKDetails->m_UserEncryptionData" should be loaded by caller after
     //  return from this routine from application loaded data for proper
     //  KEK decryption of this recipientInfo.
   }
   else if (choiceId == RecipientInfo::pwriCid)
   {
      if (m_pPWRIDetails == NULL)
      {
         m_pPWRIDetails = new CSM_PWRIDetails;
         m_pPWRIDetails->m_pKeyDerivationAlgorithm = NULL;
         m_pPWRIDetails->m_pKeyEncryptionAlgorithm = new CSM_Alg;
      }

      // get memory for encrytion algorithm and assign parameters
      CSM_Alg *pAlg=new CSM_Alg(*AccesskeyEncryptionAlgorithm());

      *m_pPWRIDetails->m_pKeyEncryptionAlgorithm = *pAlg;
      delete pAlg;
      if (pwri->keyEncryptionAlgorithm.parameters)
      {
        m_pPWRIDetails->m_pKeyEncryptionAlgorithm->parameters =  new AsnAny;
        *m_pPWRIDetails->m_pKeyEncryptionAlgorithm->parameters =
           *pwri->keyEncryptionAlgorithm.parameters;

        CSM_Buffer *pTmpKEAlgBuf = m_pPWRIDetails->m_pKeyEncryptionAlgorithm->GetParams();
      
        // determine content encryption
        if (pTmpKEAlgBuf)
        {
           CSM_Alg CEAlg;
           pTmpKEAlgBuf->Decode(CEAlg);
           delete pTmpKEAlgBuf;
           
           // find algid before setting
           m_pPWRIDetails->m_pKeyEncryptContentWrapOid = new AsnOid(CEAlg.algorithm);

           // set the content encryption by
        //  BTISetPreferredCSInstAlgs(NULL, NULL, NULL, CEAlg.GetId());

           // extract the iv - put it in pIV
        //  pIV = CEAlg.GetParams();
        }

      }

      // get memory for derivation algorithm and assign parameters
      if (AccesskeyDerivationAlgorithm())
      {
         m_pPWRIDetails->m_pKeyDerivationAlgorithm = new CSM_Alg;

         pAlg=new CSM_Alg(*AccesskeyDerivationAlgorithm());

         *m_pPWRIDetails->m_pKeyDerivationAlgorithm = *pAlg;
         delete pAlg;

         if (pwri->keyDerivationAlgorithm->parameters)
         {
           m_pPWRIDetails->m_pKeyDerivationAlgorithm->parameters =  new AsnAny;
           *m_pPWRIDetails->m_pKeyDerivationAlgorithm->parameters = 
              *pwri->keyDerivationAlgorithm->parameters;
         }
      }
   }
   else
       SME_THROW(SM_MEMORY_ERROR, "Unknown RecipientInfo", NULL);

   GetEncryptedKey();



   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
      // cleanup based on bSomethingLoaded
   SME_CATCH_FINISH
}        //CSM_DataToEncrypt::SetRecipientInfo

//
//
#ifdef bob
bool CSM_RecipientInfo::operator == (CSM_RecipientInfo &Recipient)
{
   bool bFlag=false;
   RecipientIdentifier *p2;

   p2 = Recipient.AccessRID();
   bFlag = (*this == *p2);

   return(bFlag);
}
#endif


_END_SFL_NAMESPACE

//EOF sm_RecipientInfo.cpp
