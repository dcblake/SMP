#ifndef NO_SCCS_ID
static char SccsId[ ] = "@(#) sm_spex.cpp 1.17 10/13/00 15:27:02"; 
#endif
#include "sm_spex.h"
//#include "sm_spex_asn.h"
//#include "sm_VDASupport_asn.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;

//
// This is the Initialization routine for C
//
extern "C" {
SM_RET_VAL SMSPEXInit(void *pCtilMgr, char *pszPin,
                         long nSocket)
{
   CSM_CtilMgr *pUsepCtilMgr = (CSM_CtilMgr *) pCtilMgr;

   SME_SETUP("SMSPEXInit()");

   CSM_SPEX spex(pUsepCtilMgr, pszPin, nSocket);

   return SM_NO_ERROR;   
   
   SME_FINISH_CATCH;

}
} // end extern 'C'

CSM_SPEX::CSM_SPEX(void)
{
   SetDefaultOids();
   m_hashMode = 0;
}

CSM_SPEX::CSM_SPEX(CSM_CtilMgr *pCtilMgr, 
                   char *pszPin, 
                   long nSocket)
{
   SME_SETUP("CSM_SPEX::CSM_SPEX()");
   
   m_hashMode = 0;
   
   if (pCtilMgr == NULL)
      SME_THROW(SM_MISSING_PARAM,"pCtilMgr is NULL", NULL);

   if (SetSocket(nSocket) != 0)
      SME_THROW(-1, "No Card Present", NULL);

   SME(Login(pszPin));


   // Extended Oids set by Fortezza CTIL
   SetDefaultOids();

   SME(CreateInstances(pCtilMgr));

   SME_FINISH_CATCH;
}

SM_RET_VAL CSM_SPEX::CreateInstances(CSM_CtilMgr *pCtilMgr)
{
   //CSM_CSInstLst    *pNewCsInsts = new CSM_CSInstLst;
   CSM_CSInst       *pNewNode = NULL;
   CSM_SPEX         *pSpex = NULL;
   char              algStr[5];
   CSM_BufferLst    *pCertBufLst = NULL;
   CSM_Buffer       *pNewCertBuf = NULL; 
   SNACC::AsnOid    oidRsaWithSha1(sha1WithRSAEncryption/*spex_id_rsa_with_sha1*/);
   AsnOid          oidRsaWithMd2(md2WithRSAEncryption/*spex_id_rsa_with_md2*/);
   AsnOid          oidRsaWithMd5(md5WithRSAEncryption/*id_rsa_with_md5*/);
   AsnOid          oidRsaMd5(md5/*spex_id_md5*/);
  
   char instID[30];
   int  slot = 0;
   LabelType ue;

   // Let Fortezza CTIL load up DSA and KEA Instances
   //
   CSM_Fortezza::CreateInstances(pCtilMgr);

   mp_cardInfo = new CSM_SPEXCardInfo;
   mp_cardInfo->Set(*CSM_Fortezza::mp_cardInfo);

   if (pCtilMgr->m_pCSInsts == NULL)
   {
      pCtilMgr->m_pCSInsts = new CSM_CtilInstLst;
   }

   // Load RSA and DH Instances
   //
   mp_cardInfo->FirstSlot();
   while ((slot = mp_cardInfo->GetSlot()) > 0)
   {
      ue = mp_cardInfo->GetUE();

      if ( (ue == RSA) )
      {         
         
         pSpex = new CSM_SPEX(*mp_cardInfo);

         switch (ue)
         {
            case RSA:
               sprintf(algStr, "RSA");

               // FIX THIS
               pSpex->SetEncryptorIndex(slot);
               pSpex->SetSignerIndex(slot);

               pSpex->BTISetPreferredCSInstAlgs(&oidRsaMd5,
                                         &oidRsaWithMd5,
                               NULL, NULL);
            break;
         }
         sprintf(instID,"%02d:%s:%s", slot, algStr, mp_cardInfo->AccessLabel());

         pNewNode = new CSM_CSInst;
         pNewNode->SetID(instID);

         pSpex->mp_cardInfo = new CSM_SPEXCardInfo(*mp_cardInfo);

         pNewNode->SetTokenInterface((CSM_TokenInterface *) pSpex);
         pSpex->SetCSInst(pNewNode);// Set CSM_CSInst for cert based access.

            //RWC;5/12/02; SPECIAL NOTE; using SFL version of list here in order
            //  to specially load the CTIL MGR version of the list with the same
            //  sub-class pointer as the CSMIME libCert version.
            // put it in the instance list in pCSMIME
            pCtilMgr->m_pCSInsts->append(pNewNode);  // ADD to end of list.

         // Add user certificate to instance
         //
         pCertBufLst = new CSM_BufferLst;
         pNewCertBuf = &(*pCertBufLst->append());
         mp_cardInfo->GetCertificate(*pNewCertBuf);

         pNewNode->SetCertificates(pCertBufLst);
      }
      mp_cardInfo->NextSlot();
   }
  

   return 0;
}

void CSM_SPEX::SetDefaultOids()
{
   // RSA OIDS
   //  Digital Signature Algs. supported by SPEX
   //   note: DSA with SHA1 is inherited from CSM_Fortezza
   //
/*   AsnOid oidRsaWithSha1(sha1WithRSAEncryption/*spex_id_rsa_with_sha1* /);
   AsnOid oidRsaWithMd2(md2WithRSAEncryption);
   AsnOid oidRsaWithMd5(md5WithRSAEncryption);
   AsnOid oidRsa(rsa/*spex_id_rsa* /);

   AsnOid oid3Des(des_ede3_cbc);
   AsnOid oidBogusDES("1.2.4.4.4.4");      // Bogus oid to test DES encryption
   AsnOid oidRsaTransport(rsa/*id_rsa* /);
   
   // Digest OIDs
   AsnOid oidMd5(md5/*id_md5* /);
   AsnOid oidSha1(sha_1);

   CSM_Alg *rsaWithSha1 = new CSM_Alg(oidRsaWithSha1);
   CSM_Alg *rsaWithMd2 = new CSM_Alg(oidRsaWithMd2);
   CSM_Alg *rsaWithMd5 = new CSM_Alg(oidRsaWithMd5);
   CSM_Alg *rsa = new CSM_Alg(oidRsa);

   CSM_Alg *Md5digest = new CSM_Alg(oidMd5);
   CSM_Alg *Sha1digest = new CSM_Alg(oidSha1);

   CSM_Alg *spex3Des = new CSM_Alg(oid3Des);
   CSM_Alg *spexBogusDES = new CSM_Alg(oidBogusDES);
   CSM_Alg *rsaTransport = new CSM_Alg(oidRsaTransport);
*/
   CSM_AlgLstVDA *pDigestAlgLst = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pDigestEncryptionAlgLst = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pKeyEncryptionAlgLst = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pContentEncryptionAlgLst = new CSM_AlgLstVDA;

   SME_SETUP("CSM_SPEX::SetDefaultOids()");
   
   // PIERCE FIX THIS
   //   Shouldn't need to call these from SPEX.
   //
   SetKeyEncryptionOids();
   SetContentEncryptionOids();
   SetDigestEncryptionOids();
   SetDigestOids();
 
   // Get existing algorithm lists
   //
   BTIGetAlgIDs(&pDigestAlgLst, &pDigestEncryptionAlgLst,
      &pKeyEncryptionAlgLst, &pContentEncryptionAlgLst);

   // Add to digest alg list (hashing)
   //
   CSM_AlgVDA *pAlgmd5Digest = &(*pDigestAlgLst->append());
   pAlgmd5Digest->algorithm = md5;
   CSM_AlgVDA *pAlg = &(*pDigestAlgLst->append());
   pAlg->algorithm = sha_1;
   pAlg = &(*pDigestAlgLst->append());
   pAlg->algorithm = sha1WithRSAEncryption;
   pAlg = &(*pDigestAlgLst->append());
   pAlg->algorithm = md2WithRSAEncryption;
   CSM_AlgVDA *pAlgmd5RSADigest = &(*pDigestAlgLst->append());
   pAlgmd5RSADigest->algorithm = md5WithRSAEncryption;

   // Add to digest encryption list (digitial signature)
   //
   pAlg = &(*pDigestEncryptionAlgLst->append());
   pAlg->algorithm = sha1WithRSAEncryption;
   pAlg = &(*pDigestEncryptionAlgLst->append());
   pAlg->algorithm = md2WithRSAEncryption;
   pAlg = &(*pDigestEncryptionAlgLst->append());
   pAlg->algorithm = md5WithRSAEncryption;
   pAlg = &(*pDigestEncryptionAlgLst->append());
   pAlg->algorithm = rsa;

   // Add to key encryption list (3DES, RC2) TBD
   //
   pAlg = &(*pKeyEncryptionAlgLst->append());
   pAlg->algorithm = rsa;

   // Add to content encryption list (RSA only?) TBD
   //
   pAlg = &(*pContentEncryptionAlgLst->append());
   pAlg->algorithm = des_ede3_cbc;
   //pContentEncryptionAlgLst->AppendL(spexBogusDES);

   BTISetAlgIDs(pDigestAlgLst, pDigestEncryptionAlgLst,
                pKeyEncryptionAlgLst, pContentEncryptionAlgLst);

   BTISetPreferredCSInstAlgs((SNACC::AsnOid *)&md5, 
                         (SNACC::AsnOid *)&md5WithRSAEncryption, NULL, NULL);

   SME_FINISH_CATCH;
}

// FUNCTION: SMTI_Sign()
//
// PURPOSE: To produce a digitial signature on the data pointed to by pData.
//
// INPUT DESCRIPTION:
//   Type/Class     Name             I/O    Description
//
//   CSM_Buffer *   pData             I     Binary or Ascii Data to be signed.
//   CSM_Buffer *   pEncryptedDigest  O     Signature Value
//   CSM_Buffer *   pDigest           O     Hash Value
//
SM_RET_VAL CSM_SPEX::SMTI_Sign(CSM_Buffer *pData,
                               CSM_Buffer *pEncryptedDigest,
                               CSM_Buffer *pDigest)
{
   long             error = SM_NO_ERROR;
   CSM_Buffer      *pHashValue = NULL;
   CSM_FortDSAParams dsaParams;
   AsnOid         *pPrefDigestEncryption = NULL;
   unsigned int     signatureSize = 512; // PIERCE FIX THIS: Should be Modulus + 32          
   unsigned char    signatureValue[512]; // for RSA & 40 for DSA

   SME_SETUP("CSM_SPEX::SMTI_Sign");

   if (pData == NULL || pEncryptedDigest == NULL)
      SME_THROW(SM_MISSING_PARAM,"Missing required parameters", NULL);

   pPrefDigestEncryption = GetPrefDigestEncryption();


   if (*pPrefDigestEncryption == id_dsa_with_sha1)
   {
      CSM_Fortezza::SMTI_Sign(pData, pEncryptedDigest, pDigest);
   }
   else
   {
     if (IsAlgSupported(*pPrefDigestEncryption, CIS_SIGNATURE_TYPE))
     {

        // Generate hash
        //

      // First try to set the Hash mode based on the DigestEncryption
      // algorithm (which normally includes hash being used).
      // This gives the app. the ability to only set the preferred
      // digestEncryption algorithm; assuming they select an oid that
      // includes both hash and signing algorithms.
      //

      // This prevents SMTI_DigestData() from trying to change the
      // hash mode
      //    
       /*
       LockHashMode();

      try {
          SetMode(*pPrefDigestEncryption, CIS_HASH_TYPE, hashMode);
      } catch (CSM_Exception *pException) {pException=NULL;}
      */

      if (pDigest == NULL)
      {
         pHashValue = new CSM_Buffer;
      }
      else
         pHashValue = pDigest;

      if (pHashValue->Length() == 0)
      {
         SMTI_DigestData(pData, pHashValue);
      }


      error = CIS_SetCurrentMode(CIS_SIGNATURE_TYPE, CIS_RSA_SIGNATURE_MODE);

      if (error != CI_OK)
      {
         SME_THROW(error, "CIS_SetCurrentMode()", NULL);
      }

      error = CIS_Sign(pDigest->Length(), m_hashMode, 
             (unsigned char *) pHashValue->Access(), &signatureSize,
           &signatureValue[0]);

      //  UnLockHashMode();

      if (error != CI_OK)
        {
           SME_THROW(error, "CIS_Sign() failed", NULL);
        }

     }
     else
     {
         SME_THROW(-1, "Unsupported Digest Encryption Algorithm", NULL);
     }
   }


   pEncryptedDigest->Set( (char *) &signatureValue[0], signatureSize);

   if (pHashValue != pDigest)
      delete pHashValue;

   SME_FINISH_CATCH;

   return SM_NO_ERROR;
}

SM_RET_VAL CSM_SPEX::SMTI_DigestData(CSM_Buffer *pData, CSM_Buffer *pHashValue)
{
   AsnOid *pPrefHashAlg=GetPrefContentEncryption();
   long error = 0;
   SME_SETUP("CSM_SPEX::SMTI_DigestData()");

       if (pPrefHashAlg && 
           (*pPrefHashAlg == sha1WithRSAEncryption/*spex_id_rsa_with_sha1*/ ||
            *pPrefHashAlg == sha_1 ||
            *pPrefHashAlg == md2WithRSAEncryption/*spex_id_rsa_with_md2*/ ||
            *pPrefHashAlg == md5WithRSAEncryption/*id_rsa_with_md5*/))
       {              // check locally supported algs.
          SME((error = SMTI_DigestDataSPEX(pData, pHashValue)));
       }
       else
       {
          SME((error = CSM_Common::SMTI_DigestData(pData, pHashValue)));
       }

       if (pPrefHashAlg)
           delete pPrefHashAlg;

   return error;
   SME_FINISH_CATCH;
}



#define BLOCK_SIZE 64
SM_RET_VAL CSM_SPEX::SMTI_DigestDataSPEX(CSM_Buffer *pData, CSM_Buffer *pHashValue)
{
   AsnOid      *pPrefHashAlg = NULL;
   long          error = 0;
   long          hashMode = 0;

   SME_SETUP("CSM_SPEX::SMTI_DigestData()");

   // Check for missing parameters
   //
   if (pHashValue == NULL)
   {
      SME_THROW(SM_MISSING_PARAM, "pHashValue is missing (null)", NULL);
   }

   // Set personality to index used for signing/verification.  This
   // determines what the default algorithms are for this instance.
   //
   error = CI_SetPersonality(this->m_nSignerIndex);
   if (error != CI_OK)
   {
      SME_THROW(error, "CI_SetPersonality() failed!", NULL);
   }


   // check perferrred hashing algorithm. Call SetCurrentMode() to set the 
   // current hashing algorithm.
   //
   pPrefHashAlg = GetPrefDigest();

   SetMode(*pPrefHashAlg, CIS_HASH_TYPE, hashMode);

   // Initialize 
   //
   error = CI_InitializeHash();
   if (error != CI_OK)
   {
      SME_THROW(error, "CI_InitializeHash() failed!", NULL);
   }


   BlockDigest(pData, pHashValue);

   return error;

   SME_FINISH_CATCH;

}

// FUNCTION: SMTI_Verify()
//
// PURPOSE: To verify the signuature within a SignedData
//
// INPUTS:   pSignerPublicKey --> Signer's X.509 Certificate
//           pData      --> 
//

SM_RET_VAL CSM_SPEX::SMTI_Verify(CSM_Buffer *pSignerPublicKey,
                                     CSM_AlgVDA    *pDigestAlg,
                                     CSM_AlgVDA    *pSignatureAlg,
                                     CSM_Buffer *pData,
                                     CSM_Buffer *pSignature)
{
   long              error = SM_NO_ERROR;
   CSM_Buffer        hashValue;
   CSM_FortDSAParams FortDSAParams;
   CSM_Buffer        *pLocalEncodedPubKey = NULL;
   AsnOid           *pSigAlg;
   AsnOid            dsaWithSha1Oid(id_dsa_with_sha1);
   RSAPublicKey/*SpexRsaPublicKey*/   spexRsaPublicKey;

//   AsnOid oidRsa(spex-id-rsa);
//   AsnOid oidRsaWithSha1(sha1WithRSAEncryption/*spex_id_rsa_with_sha1*/);
//   AsnOid oidRsaWithMd2(md2WithRSAEncryption/*spex_id_rsa_with_md2*/);
//   AsnOid oidRsaWithMd5(md5WithRSAEncryption/*id_rsa_with_md5*/);
   
   SME_SETUP("CSM_SPEX::SMTI_Verify");

   if (pDigestAlg == NULL || pSignatureAlg == NULL || 
      pData == NULL || pSignature == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing parameters for signature verification", 
                NULL);

   // IF signature algorithm is DSA w/ SHA1 use 
   //    Fortezza CTIL for DSA with SHA1
   //
   pSigAlg = pSignatureAlg->GetId();
   // IF an RSA Signature Algorithm is specified.
   //    figure out which hashing algorithm to use.
   // 
   if ( IsAlgSupported(*pSigAlg, CIS_SIGNATURE_TYPE) )
   {
      // Determine if Public Key is Present
      //
      if (pSignerPublicKey == NULL)
      {
         // PIERCE: Add code to get public key from cert in signerIndex
         //
         pLocalEncodedPubKey = GetEncodedPublicKey();
      }
      else 
         pLocalEncodedPubKey = pSignerPublicKey;

      // Set personality to index used for signing/verification.  This
      // determines what the default algorithms are for this instance.
      //
      error = CI_SetPersonality(this->m_nSignerIndex);
      if (error != CI_OK)
      {
         SME_THROW(error, "CI_SetPersonality() failed!", NULL);
      }


      // Calculate Digest (hash)
      //

 //    LockHashMode();

         // PIERCE: I should probably lock here
         //
         //  set preferred hashing alg for this instance so SMTI_DigestData()
         //  will know what algorithm to use.
         //

      AsnOid *pDigestOid = NULL;
     
      if ((pDigestOid = pDigestAlg->GetId()) == NULL)
        SME_THROW(-1,"Unable to GetId for digest oid", NULL);

      BTISetPreferredCSInstAlgs( pDigestOid, NULL, NULL, NULL);

      delete pDigestOid;

      SME(SMTI_DigestData(pData, &hashValue));

      // Make sure the RSA Public Key is decodable
      //
      DECODE_BUF_NOFAIL( &spexRsaPublicKey, pLocalEncodedPubKey, error);
      if (error != 0)
         SME_THROW(-1, "Invalid RSA Public Key Encoding", NULL);

      // Set current signature algorithm to RSA.  Eventually this should
      // be a call to SetMode().
      //
      error = CIS_SetCurrentMode(CIS_SIGNATURE_TYPE, CIS_RSA_SIGNATURE_MODE);
      if (error != CI_OK)
      {
         SME_THROW(error, "CIS_SetCurrentMode() failed!", NULL);
      }

      error = CIS_VerifySignature( hashValue.Length(), 
         m_hashMode,
         (unsigned char *) hashValue.Access(),
         pLocalEncodedPubKey->Length(), 
         (unsigned char *) pLocalEncodedPubKey->Access(),
         pSignature->Length(),
         (unsigned char *) pSignature->Access());

      if (error != CI_OK)
         SME_THROW(error, "CIS_VerifySignature() failed", NULL);
   }
   else
   {
      error = CSM_Fortezza::SMTI_Verify(pSignerPublicKey,
         pDigestAlg, pSignatureAlg, pData, pSignature);
                            // THIS will include CSM_Common verify algs.
      if (error)
      {
         SME_THROW(-1, "UNSUPPORT ALGORITHM", NULL);
      }
   }

   SME_FINISH_CATCH;

   return error;
}

// FUNCTION: IsAlgSupported()
// PURPOSE:  Determine if the algorithm OID is supported
//
// NOTE: May want to derive whether or not the OID is supported
//       from token/instance information.
//
//       i.e. if this is an RSA instance should I verify a DSA?
//

bool CSM_SPEX::IsAlgSupported(const AsnOid &oid, long algType)
{
   bool result = false;

   switch (algType)
   {
      case CIS_SIGNATURE_TYPE:

        result = ((oid == rsa/*id_rsa*/)     || 
           (oid == sha1WithRSAEncryption/*spex_id_rsa_with_sha1*/)  ||
           (oid == md2WithRSAEncryption/*spex_id_rsa_with_md2*/)   ||
           (oid == md5WithRSAEncryption/*id_rsa_with_md5*/) );
        break;

      case CIS_HASH_TYPE:
        result = ((oid == sha1WithRSAEncryption/*spex_id_rsa_with_sha1*/) ||
           (oid == md2WithRSAEncryption/*spex_id_rsa_with_md2*/)         ||
           (oid == md5WithRSAEncryption/*id_rsa_with_md5*/)         ||
           (oid == md5/*id_md5*/)                  ||
           (oid == sha_1)                   ||
           (oid == id_md2) );
        break;
   }

   return result;
}

/* FUNCTION: SetMode()
 * PURPOSE :  Use CIS_SetCurrentMode() to set the current hashing
 *            algorithm to whatever is specified by the incoming
 *            OID.
 * RETURNS : 0 -- success, or 1 -- failure
 */
void CSM_SPEX::SetMode(const AsnOid &oid, long modeType, long &mode)
{
   long error = 0;

   SME_SETUP("CSM_SPEX::SetMode()");

   switch(modeType)
   {
     case CIS_HASH_TYPE:
//      if (m_hashModeLock == true && m_hashMode != 0)
      {
         if ( (oid == sha1WithRSAEncryption/*spex_id_rsa_with_sha1*/) ||
             (oid == sha_1) )
            mode = CIS_SHA1_HASH_MODE;
         else if (oid == md2WithRSAEncryption/*spex_id_rsa_with_md2*/)
            mode = CIS_MD2_HASH_MODE;
         else if ( (oid == md5WithRSAEncryption/*id_rsa_with_md5*/) ||
                 (oid == md5/*id_md5*/) )
            mode = CIS_MD5_HASH_MODE;
         else 
            SME_THROW(-1, "Unsupported Hash Algorithm", NULL);
      
         // Mode has been set at this point.  If locked set 
         // m_hashMode to current mode.
         // 
//         if (m_hashModeLock)
            m_hashMode = mode;
      }
      break;

    case CIS_DECRYPT_TYPE:
     case CIS_ENCRYPT_TYPE:
        if ( AsnOid(des_ede3_cbc)==oid )//RWC;DOES NOT COMPILE!!!id_3des_cbc64) )
           mode = CIS_DES3_EDE3_CBC64_MODE;
      else if ( AsnOid("1.2.4.4.4.4") == oid) // LTM;Bogus oid to test DES content encryption
         mode = CIS_DES_CBC64_MODE;
        else
           SME_THROW(-1, "Unsupport Content Encryption algorithm", NULL);
        break;

     case CIS_TRANSPORT_TYPE:
        if ( (oid == rsa/*id_rsa*/) )
           mode = CIS_RSA_TRANSPORT_MODE;
        else
           SME_THROW(-1, "Unsupported key transport/agreement algorithm", NULL);
        break;

     default:
        // PIERCE: added OID to error information
        //
        SME_THROW(-1, "Unsupported mode type", NULL);
        break;
   }
     
   if (mode == CIS_DES3_EDE3_CBC64_MODE && modeType == CIS_DECRYPT_TYPE ) 
   { 
      error = CIS_SetCurrentMode(CIS_ENCRYPT_TYPE, CIS_DES3_EDE3_CBC64_MODE); 
      error |= CIS_SetCurrentMode(CIS_DECRYPT_TYPE, CIS_DES3_EDE3_CBC64_MODE); 
   } 
   else 
   { 
      error = CIS_SetCurrentMode(modeType, mode); 
   } 

   if (error != CI_OK)
      SME_THROW(error, "CIS_SetCurrentMode() failed", NULL);

   SME_FINISH_CATCH;
}


////
////
SM_RET_VAL CSM_SPEX::SMTI_Encrypt(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV)       // In, to avoid specific
{
   long error = 0;
   AsnOid *pCEAlg = GetPrefContentEncryption();
   SME_SETUP("CSM_SPEX::SMTI_Encrypt()");

   if ( pCEAlg  &&  
      (*pCEAlg == AsnOid(des_ede3_cbc) ||
       *pCEAlg == AsnOid("1.2.4.4.4.4"))) // LTM;Bogus oid to test DES content encryption
   {
       error = SMTI_EncryptSPEX(pData, pEncryptedData, pParameters, pMEK, pIV);
   }
   else     // check CSM_Common supported algs.
   {
       error = CSM_Common::SMTI_Encrypt(pData, pEncryptedData, pParameters, 
           pMEK, pIV);
       if (error)
       {
           SME_THROW(-1, "Unsupported key content encryption algorithm", NULL);
       }
   }

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
   return error;
}

////
////
SM_RET_VAL CSM_SPEX::SMTI_EncryptSPEX(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV)       // In, to avoid specific
{
   Skipjack_Parm skipjackParams;

   long error = 0;
   AsnOid *pCEAlg = GetPrefContentEncryption();
   CSM_Buffer localIV;
   CI_IV      ciIV;
   long       encryptMode = -1;
   CSM_Buffer *pTmpPaddedData = new CSM_Buffer;
   CSM_Buffer *pLocalBuf = new CSM_Buffer;

   SME_SETUP("CSM_SPEX::SMTI_Encrypt()");

   if (pData == NULL || pEncryptedData == NULL || pParameters == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing Parameters", NULL);

   error = CI_SetPersonality(this->m_nEncryptorIndex );
   if (error != CI_OK)
      SME_THROW(error, "CI_SetPersonality() failed", NULL);


   // Set Encryption mode
   SetMode( *pCEAlg, CIS_ENCRYPT_TYPE, encryptMode);

   // Copy Plain Text into temporary padded Data buffer
   *pTmpPaddedData = *pData;

   // Pad data to be ecnrypted
   GeneratePad( *pTmpPaddedData, 8);

   // Generate the message encryption key
   CI_DeleteKey(MEK_REG); // Matt Cooper <<<<<< the fix
   error = CI_GenerateMEK(MEK_REG, 0);

   if (error != CI_OK)
      SME_THROW(error, "CI_GenerateMEK() failed", NULL);

   error = CI_SetKey(MEK_REG);
   if (error != CI_OK)
      SME_THROW(error, "CI_SetKey() failed", NULL);

   // If IV was passed in load it.  
   // Else generate it
   //
   if (pIV != NULL)
   {
      error = CI_LoadIV( (unsigned char *) pIV->Access());
      if (error != CI_OK)
         SME_THROW(error, "Error loading supplied IV", NULL);
   }
   else
   {

      error = CI_GenerateIV(ciIV);
      if (error != CI_OK)
         SME_THROW(error, "CI_GenerateIV() failed.", NULL);

      localIV.Set( (char *) &ciIV[0], sizeof(CI_IV));

     if ((pIV = new CSM_Buffer(localIV)) == NULL)
        SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   }

   if (*pCEAlg == des_ede3_cbc)
   {
      LoadParams(*pIV, pLocalBuf);
/*     AsnOcts octs;
     octs.Set( (char *) ciIV,      8);
     ENCODE_BUF(&octs, pLocalBuf);*/
   }
   else if(*pCEAlg == id_fortezzaConfidentialityAlgorithm)
   {
     skipjackParams.initialization_vector.Set( (char *) ciIV,
      8);

     ENCODE_BUF(&skipjackParams, pLocalBuf);
   }
   else
      SME_THROW(-1,"Unsupported Content Encryption Alg.", NULL);

   *pParameters = *pLocalBuf;

   BlockEncryption(pTmpPaddedData, pEncryptedData);

   if (pCEAlg)
      delete pCEAlg;
   if (pLocalBuf)
      delete pLocalBuf;
   if (pTmpPaddedData)
      delete pTmpPaddedData;

   SME_FINISH
   SME_CATCH_SETUP
      if (pCEAlg)
         delete pCEAlg;
      if (pLocalBuf)
         delete pLocalBuf;
      if (pTmpPaddedData)
         delete pTmpPaddedData;
   SME_CATCH_FINISH

   return error;

   pMEK;    //AVOIDS warning.
}   


/******************* KEY TRANSPORT **********************/

SM_RET_VAL CSM_SPEX::SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // input, parameters for alg.
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // output, ukm, if applicable
            CSM_Buffer *pSubjKeyId) // output
{
   long error = 0;
   unsigned char pWrappedCEK[2048];
   unsigned int wrappedCEKLen = 2048;
   char nullParams[2];


   SME_SETUP("CSM_SPEX::SMTI_GenerateEMEK()");

   // PIERCE: note this assumes 3DES wrapping
   //
   error = CIS_ConcealKey(MEK_REG, CIS_DES3_KEY_TYPE, 192,
      pRecipient->Length(), (unsigned char *) pRecipient->Access(), 
      &wrappedCEKLen,
      pWrappedCEK);

   if (error != CI_OK)
   {
      SME_THROW(error, "CIS_ConcealKey() failed", NULL);
   }

   pEMEK->Set( (char *) &pWrappedCEK[0], wrappedCEKLen);

   nullParams[0] = 0x05;
   nullParams[1] = 0x00;

   pParameters->Set( (char *) &nullParams[0], 2);

   return error;  

   pSubjKeyId;pUKM;pMEK;    //AVOIDS warning.
   SME_FINISH_CATCH;
}
  
SM_RET_VAL CSM_SPEX::SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input, parameters for alg.
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output
{
   SM_RET_VAL error = 0;

   SME_SETUP("CSM_SPEX::SMTI_ExtractMEK()");

   if (pEMEK == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing EMEK.", NULL);

   // Set Personality
   if ((error = CI_SetPersonality(m_nEncryptorIndex)) != CI_OK)
      SME_THROW(error, "CI_SetPersonality() failed", NULL);

   if ((error = CI_DeleteKey(MEK_REG)) != CI_OK)
      SME_THROW(error, "CI_DeleteKey() failed", NULL);

   // PIERCE: Note this assume 3DES unwrapping

   if ((error = CIS_RevealKey(MEK_REG, CIS_DES3_KEY_TYPE, pEMEK->Length(),
                           (unsigned char *) pEMEK->Access())) != CI_OK)
      SME_THROW(error, "CIS_RevealKey() failed", NULL);

   return error;

   pMEK;pUKM;pParameters;pOriginator;    //AVOIDS warning.
   SME_FINISH_CATCH;
}
  
 
/******************** KEY AGREEMENT **********************/
SM_RET_VAL CSM_SPEX::SMTI_GenerateKeyWrap(
            CSM_Buffer *pData,          // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters,    // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK,           // In/output; may be specified.
            CSM_Buffer *pIV)            // In, to avoid specific
                                        // alg encoding by app.
{

   // PIERCE: TBD initially doing keyTransport only
   //
   pIV;pMEK;pParameters;pEncryptedData;pData;    //AVOIDS warning.
   return -1;
}

SM_RET_VAL CSM_SPEX::SMTI_ExtractKeyWrap(
            CSM_Buffer *pData,          // Output
            CSM_Buffer *pEncryptedData, // input
            CSM_Buffer *pParameters,    // IN, for KeyAgree algs.
            CSM_Buffer *pTEK,           // output
            CSM_Buffer *pIV)           // In
{

   // PIERCE: TBD initially doing keyTransport only
   //
   pData;pEncryptedData;pParameters;pTEK;pIV;    //AVOIDS warning.
   return -1;
}

SM_RET_VAL CSM_SPEX::SMTI_GenerateKeyAgreement(
            CSM_Buffer *pRecipient,    // input, Y of recip
            CSM_Buffer *pParameters,   // IN,OUT may be passed in for shared
                                       //  use OR for ESDH. (p, g, and/or IV).
            CSM_Buffer *pUKM,     // input/output may be passed in for shared
                                  //   use.  UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,     // input/output may be passed in for
                                       //   shared use. Initialization vector,
                                       //   part of DH params.
            AsnOid *pEncryptionOID,   // IN, specified encryption of key,
                                       //   used here in key generation,
                                       //   but alg not implemented.
            CSM_Buffer *pbufKeyAgree,  // output, encryption key for this recip.
            long lKekLength)           // Input, for OtherInfo load.
{

   // PIERCE: TBD initially doing keyTransport only
   //
   lKekLength;pbufKeyAgree;pEncryptionOID;pbufferIV;pUKM;pParameters;
   pRecipient;    //AVOIDS warning.
   return -1;
}

SM_RET_VAL CSM_SPEX::SMTI_ExtractKeyAgreement(
            CSM_Buffer *pOriginator,   // input, Y of originator
            CSM_Buffer *pUKM,          // input/output may be passed in for shared use.
                                       //   UserKeyMaterial (random number).
            CSM_Buffer *pbufferIV,     // input/output may be passed in for
                                       //   shared use. Initialization vector,
                                       //   part of DH params.
            AsnOid *pEncryptionOID,   // IN, specified encryption of key,
                                       //   used here in key generation,
                                       //   but alg not implemented.
            CSM_Buffer *pbufKeyAgree,  // output, encryption key for this recip.
            long lKekLength)           // Output, from OtherInfo load.
{

   // PIERCE: TBD initially doing keyTransport only
   //
   pOriginator;pUKM;pbufferIV;pEncryptionOID;pbufKeyAgree;lKekLength;    
                        //AVOIDS warning.
   return -1;
}

CSM_Buffer * CSM_SPEX::SMTI_GenerateKeyWrapIV(
           long &lKekLength,       // OUT, returned algorithm specific length
           CSM_AlgVDA *pWrapAlg)   // OUT, returned since params are alg
{

   // PIERCE: TBD initially doing keyTransport only
   //
   lKekLength;pWrapAlg;    //AVOIDS warning.
   return (CSM_Buffer *) NULL;

}
  
SM_RET_VAL CSM_SPEX::SMTI_Decrypt(
            CSM_Buffer *pParameters,    // input, parameters for alg.
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK,           // input (MEK or special phrase)
            CSM_Buffer *pData)      // output (decrypted data)
{
   long error = 0;
   AsnOid *pCEAlg = GetPrefContentEncryption();
   SME_SETUP("CSM_SPEX::SMTI_Decrypt()");
   if (pCEAlg  && 
     (*pCEAlg == des_ede3_cbc ||
      *pCEAlg == id_fortezzaConfidentialityAlgorithm))
   {
        error = SMTI_Decrypt(pParameters, pEncryptedData, pMEK, 
            pData);
   }
   else
   {
        error = CSM_Common::SMTI_Decrypt(pParameters, pEncryptedData, pMEK, 
            pData);
        if (error)
        {
          SME_THROW(-1, "Unsupported Content Encryption Alg.", NULL);
        }
   }

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
   return error;
}

////
////
SM_RET_VAL CSM_SPEX::SMTI_DecryptSPEX(
            CSM_Buffer *pParameters,    // input, parameters for alg.
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK,           // input (MEK or special phrase)
            CSM_Buffer *pData)      // output (decrypted data)
{
   long error = 0;
   AsnOid *pCEAlg = GetPrefContentEncryption();
   long  decryptMode;
   Skipjack_Parm skipjackParams;
   CI_IV ciIV;
   CSM_Buffer *pIv = NULL;

   SME_SETUP("CSM_SPEX::SMTI_Decrypt()");

   if (pParameters == NULL || pEncryptedData == NULL || pData == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing required parameters", NULL);
   
   // Set Decryption mode
   SetMode( *pCEAlg, CIS_DECRYPT_TYPE, decryptMode);

   // LTM : Currently decoding into skipjack_Param structure.  Should 
   // be modified for support of other algs.
   //RWC;1/17/00; TBD, check for RC2 as well as 3DES. CHANGE OID to "des_ede3_cbc" when updated.

   if (*pCEAlg == des_ede3_cbc)
   {
      if ((pIv = UnloadParams(pCEAlg, *pParameters)) == NULL)
         SME_THROW(SM_SPEX_PARAM_DECODE_ERROR, NULL, NULL);

      memcpy( ciIV, (char *) pIv->Access(), pIv->Length());

      /*
     AsnOcts octs;
     DECODE_BUF(&octs, pParameters);
     memcpy( ciIV, (char *) octs, 8);
     */
   }
   else if (*pCEAlg == id_fortezzaConfidentialityAlgorithm)
   {
     DECODE_BUF (&skipjackParams, pParameters);

     memcpy( ciIV, skipjackParams.initialization_vector.c_str(), 8);
   }
   else
      SME_THROW(-1, "Unsupported Content Encryption Alg.", NULL);

   if ((error = CI_SetKey(MEK_REG)) != CI_OK)
      SME_THROW(error, "CI_SetKey() failed", NULL);

   if ((error = CI_LoadIV( ciIV )) != CI_OK)
      SME_THROW(error, "CI_LoadIV() failed", NULL);

   BlockDecryption(pEncryptedData, pData);

   ExtractPad(*pData);

   if (pCEAlg)
      delete pCEAlg;
   if (pIv)
      delete pIv;

   SME_FINISH
   SME_CATCH_SETUP
      if (pCEAlg)
         delete pCEAlg;
      if (pIv)
         delete pIv;
   SME_CATCH_FINISH

   pMEK;    //AVOIDS warning.
   return error;
}

SM_RET_VAL CSM_SPEX::SMTI_Random(
            CSM_Buffer *pSeed,
            CSM_Buffer *pRandom,
            SM_SIZE_T lLength)
{
   pSeed;pRandom;lLength;    //AVOIDS warning.
   return 0;
}


//
//
CSM_AlgVDA *CSM_SPEX::DeriveMsgAlgFromCert(CSM_AlgVDA &Alg) 
{   
	return new CSM_AlgVDA(Alg); 
}

//
void CSM_SPEX::BlockDigest(CSM_Buffer *pData, CSM_Buffer *pHashValue)
{
   long             error = 0;
   unsigned long    blockSize = 0;
   unsigned long    largestBlockSize = 0;
   unsigned long    bytesRead = 0;
   unsigned long    totalBytesRead = 0;
   char            *block = NULL;
   char             localHashValue[CI_HASHVALUE_SIZE];
   long             hashValueSize = CI_HASHVALUE_SIZE;


   SME_SETUP("CSM_SPEX::BlockDigest");

   memset( &localHashValue[0], 0, CI_HASHVALUE_SIZE);

   largestBlockSize = blockSize = mp_cardInfo->GetLargestBlockSize();

   block = (char *) calloc(1, blockSize);
   
   pData->Open(SM_FOPEN_READ);
   
   if (pData->Length() > largestBlockSize )
   {
      while (totalBytesRead != pData->Length())
      {
         bytesRead = pData->cRead( block, blockSize);
         totalBytesRead += bytesRead;

         if (bytesRead == largestBlockSize)
         {
            error = CI_Hash (largestBlockSize, (unsigned char *) block);
         }
         else
         {
            error = CIS_GetHash( bytesRead, (unsigned char *) block,
                                 (unsigned int *) &hashValueSize, 
                                 (unsigned char *) &localHashValue[0]);
         }

         if (error != CI_OK)
            SME_THROW(error, "CI[S]_Hash() failed", NULL);

         blockSize = (pData->Length() - totalBytesRead);

         if (blockSize > largestBlockSize)
            blockSize = largestBlockSize;
      }
   }
   else
   {
      error = CIS_GetHash( pData->Length(), (unsigned char *) pData->Access(),
                           (unsigned int *) &hashValueSize, 
                           (unsigned char *) &localHashValue[0]);
      if (error != CI_OK)
         SME_THROW(error, "CI_Encrypt() failed", NULL);
   }

   pData->Close();

   pHashValue->Set(&localHashValue[0], hashValueSize);

   SME_FINISH_CATCH;
}

#ifndef NO_DLL
#if  defined(WIN32)
extern "C" {
long Make_argv(char *string, int *pargc, char ***pargv);

SM_SPEXDLL_API SM_RET_VAL DLLBuildTokenInterface(CSM_CtilMgr &Csmime,
    char *lpszBuildArgs)
{
    SM_RET_VAL status = 0;
    int argc1=0;
    char **argv1;
    char ptr[30];
    long nSocket=0;

    memset(ptr, '\0', 30);
    for (int i=0; i < (int)strlen("sm_SpexDLL"); i++)
        ptr[i] = (char)toupper(lpszBuildArgs[i]);
    // Preliminary check that this request is for our library.
    if (strncmp(ptr, "SM_SPEXDLL", strlen("sm_SpexDLL")) == 0)
    {
        Make_argv(lpszBuildArgs, &argc1, &argv1);
        if (argc1 >= 2)
        {
           // Pass char *pszPassword, char *pszAddressBook, char *pszPrefix
           if (argc1 > 2)
             nSocket = atoi(argv1[2]);
           if (strcmp(argv1[1], "NULL") != 0 && strcmp(argv1[1], "NULL") != 0)
           {
             SMSPEXInit(&Csmime, argv1[1], nSocket);
           }
        }
        else    // OTHER MODELS to be supported.
        {
            status = -1;
        }

    }
    else
    {
        status = -1;
        std::cout << "DLL1BuildTokenInterface failed!!!\n";
    }
    //return new CSM_Free3;
    return(status);
}

SM_SPEXDLL_API char * DLLGetId()
{
    return(strdup("sm_SpexDLL"));
}

}       // END extern "C"

#endif
#endif

_END_CERT_NAMESPACE

// EOF sm_spex.cpp

