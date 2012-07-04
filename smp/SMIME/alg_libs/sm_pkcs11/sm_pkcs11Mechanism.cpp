#ifndef NO_SCCS_ID
static char SccsId[ ] = "%Z% %M% %I% %G% %U%"; 
#endif

#include "sm_pkcs11.h"
#include "sm_pkcs11Oids.h"
#include "sm_fortAsn.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;


//////////////////////////////////////////////////////////////////////////////////
//
// CSM_Pkcs11MechanismInfo : Stores mechanism information for each slot
//
//////////////////////////////////////////////////////////////////////////////////
CSM_Pkcs11MechanismInfo::CSM_Pkcs11MechanismInfo()
{
    SME_SETUP("CSM_Pkcs11MechanismInfo::CSM_Pkcs11MechanismInfo")

    Clear();

    SME_FINISH_CATCH
}
CSM_Pkcs11MechanismInfo::~CSM_Pkcs11MechanismInfo()
{
    if (m_pOid)
        delete m_pOid;
    if (m_pDigestAlg)
        delete m_pDigestAlg;
    if (m_pDigestEncryptionAlg)
        delete m_pDigestEncryptionAlg;
    if (m_pKeyEncryptionAlg)
        delete m_pKeyEncryptionAlg;
    if (m_pContentEncryptionAlg)
        delete m_pContentEncryptionAlg;
    if (m_pMechanismStruct)
       free (m_pMechanismStruct);
}
void CSM_Pkcs11MechanismInfo::Clear ()
{  
    m_slotId = -1; 

    m_pOid = NULL;

    m_pDigestAlg = NULL;
    m_pDigestEncryptionAlg = NULL;
    m_pKeyEncryptionAlg = NULL;
    m_pContentEncryptionAlg = NULL;

    m_pMechanismStruct = NULL_PTR;
    m_pMechanismInfo = NULL_PTR;
}
SM_RET_VAL CSM_Pkcs11MechanismInfo::LoadMechanismInfo(CK_MECHANISM_TYPE &mechanismType)
{
    SM_RET_VAL status = SM_NO_ERROR;

    CK_RV rv;

    SME_SETUP("CSM_Pkcs11MechanismInfo::LoadMechanismInfo")

    m_pMechanismInfo = (CK_MECHANISM_INFO_PTR) malloc(sizeof(CK_MECHANISM_INFO));

    if ((rv = sfl_c_getMechanismInfo
                           (m_slotId, mechanismType, m_pMechanismInfo)) == CKR_OK)
    {
      // SFL will be unable to use mechanism if oid not found.
      // However, this should not be a fatal error.
      if ((m_pOid = MatchMechTypeToOid(mechanismType)) != NULL)
      { 
#ifdef PKCS11_PRINT
         char *pOidString = NULL;
         if ((pOidString = m_pOid->GetChar()) != NULL)
         {
            //printf("Oid Description is %s \n", pOidString);
            std::cout << "Oid Description is " << pOidString << "\n";
            std::cout.flush();
            free(pOidString);
         }
#endif

         if (m_pMechanismInfo->flags & CKF_DIGEST)
         {
#ifdef PKCS11_PRINT
            std::cout << "Slot can Digest.\n";
            std::cout.flush();
#endif

            if (m_pDigestAlg != NULL)
               delete m_pDigestAlg;

            if ((m_pDigestAlg = new CSM_Alg(*m_pOid)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         }

         if (m_pMechanismInfo->flags & CKF_ENCRYPT)
         {
            // Exclude rsaEncryption from the content encryption 
            // alg list.
            // sib there is no harm in keeping rsaEncryption so take the following if out 
            // to keep it in the list  smti_encrypt does not support rsa encryption yet
            // this will need to be added
            if (*m_pOid != rsaEncryption)
            {
#ifdef PKCS11_PRINT
               std::cout << "Slot can Encrypt. \n";
               std::cout.flush();
#endif
               if (m_pContentEncryptionAlg != NULL)
                  delete m_pContentEncryptionAlg;

               if ((m_pContentEncryptionAlg = new CSM_Alg(*m_pOid)) == NULL)
                  SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
            }
         }

         if (m_pMechanismInfo->flags & CKF_SIGN)
         {
#ifdef  PKCS11_PRINT
            std::cout << "Slot Can Sign.\n";
            std::cout.flush();
#endif

            if (m_pDigestEncryptionAlg != NULL)
               delete m_pDigestEncryptionAlg;

            if ((m_pDigestEncryptionAlg = new CSM_Alg(*m_pOid)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
         }

         if (m_pMechanismInfo->flags & CKF_WRAP)
         {
#ifdef PKCS11_PRINT
            std::cout << "Slot Can Wrap.\n";
            std::cout.flush();
#endif

            if(m_pKeyEncryptionAlg != NULL)
               delete m_pKeyEncryptionAlg;

            if ((m_pKeyEncryptionAlg = new CSM_Alg(*m_pOid)) == NULL)
               SME_THROW(SM_MEMORY_ERROR, NULL, NULL)
         }

         if (m_pMechanismInfo->flags & CKF_DECRYPT)
         {
#ifdef PKCS11_PRINT
            std::cout << "Slot can Decrypt.\n";
            std::cout.flush();
#endif
         }

         if (m_pMechanismInfo->flags & CKF_GENERATE)
         {
#ifdef PKCS11_PRINT
            std::cout << "Slot  can GenerateKey. \n";
            std::cout.flush();
#endif
         }

         if (m_pMechanismInfo->flags & CKF_GENERATE_KEY_PAIR)
         {
#ifdef PKCS11_PRINT
            std::cout << "Slot can GenerateKeyPair. \n";   
            std::cout.flush();
#endif
         }

         if (m_pMechanismInfo->flags & CKF_UNWRAP)
         {
#ifdef PKCS11_PRINT
            std::cout << "Slot can UnWrap.\n";
            std::cout.flush();
#endif
         }

         if (m_pMechanismInfo->flags & CKF_VERIFY)
         {
#ifdef PKCS11_PRINT
            std::cout << "Slot can Verify.\n";
            std::cout.flush();
#endif
         }

         LoadMechanismStruct (mechanismType);
      }
    }       // IF sfl_c_getMechanismInfo
    else
    {
      std::cout << "Unsuccessful sfl_c_getMechanismInfo.  Return value = " << rv << ".\n";
      std::cout.flush();
      status = -1;
    }       // END IF sfl_c_getMechanismInfo

    SME_FINISH_CATCH

    return status;
}
void CSM_Pkcs11MechanismInfo::LoadMechanismStruct(CK_MECHANISM_TYPE mechanismType)
{
   SME_SETUP("CSM_Pkcs11MechanismInfo::LoadMechanismStruct");

   if ((m_pMechanismStruct = 
                  (CK_MECHANISM_PTR) malloc (sizeof(CK_MECHANISM))) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   switch (mechanismType)
   {
   case (CKM_MD5):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_MD5.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_MD2):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_MD2.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_SHA_1):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_SHA_1.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_DSA):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_DSA.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_RSA_9796):
   case (CKM_RSA_PKCS):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_RSA_PKCS/CKM_RSA_9796.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_MD2_RSA_PKCS):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_MD2_RSA_PKCS.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_MD5_RSA_PKCS):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_MD5_RSA_PKCS.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_SHA1_RSA_PKCS):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_SHA1_RSA_PKCS.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_DSA_SHA1):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_DSA_SHA1.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_SKIPJACK_CBC64):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_SKIPJACK_CBC64.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_SKIPJACK_KEY_GEN):
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_SKIPJACK_KEY_GEN.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_SKIPJACK_WRAP):  // Mechanism requires parameters that will be
                              // specified when it is used.
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_SKIPJACK_WRAP.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   case (CKM_KEA_KEY_DERIVE): // Mechanism requires parameters that will be
                              // specified when it is used.
#ifdef PKCS11_PRINT
      std::cout << "Token supports CKM_KEA_KEY_DERIVE.\n";
      std::cout.flush();
#endif
      m_pMechanismStruct->pParameter = NULL;
      m_pMechanismStruct->ulParameterLen = 0;
      break;
   default:
#ifdef PKCS11_PRINT
      std::cout.flags(std::ios::hex);
      std::cout << "Mechanism type not supported by CTIL " << mechanismType << " \n";
      std::cout.flush();
#endif
      break;
   }

   m_pMechanismStruct->mechanism = mechanismType;

   SME_FINISH_CATCH;
}
AsnOid * CSM_Pkcs11MechanismInfo::MatchMechTypeToOid (CK_MECHANISM_TYPE mechanismType)
{
    AsnOid *pOid = NULL;

    SME_SETUP ("CSM_Pkcs11MechanismInfo::MatchMechTypeToOid");

    switch (mechanismType)
    {
    case (CKM_RSA_PKCS_KEY_PAIR_GEN) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_RSA_PKCS_KEY_PAIR_GEN mechanism.\n";
#endif
       break;
    case (CKM_RSA_9796):
    case (CKM_RSA_PKCS) :
       pOid = new AsnOid(rsaEncryption);
       break;
    case (CKM_MD2) :
        pOid = new AsnOid(spex_id_md2);
        break;
    case (CKM_MD5) :
        pOid = new AsnOid(md5);
        break;
    case (CKM_DSA) :
        pOid = new AsnOid(id_dsa);   
        break;
    case (CKM_DSA_SHA1) :
        pOid = new AsnOid(id_dsa_with_sha1);
        break;
    case (CKM_SHA_1) :
        pOid = new AsnOid(sha_1);
        break;
   case (CKM_SHA1_RSA_PKCS) :
      pOid = new AsnOid(sha_1WithRSAEncryption);
      break;
   case (CKM_MD5_RSA_PKCS) :
      pOid = new AsnOid(md5WithRSAEncryption);
      break;
   case (CKM_RSA_X_509) :
      pOid = new AsnOid(rsaEncryption);
      break;
    case (CKM_SKIPJACK_KEY_GEN) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_KEY_GEN mechanism.\n";
#endif
      break;
    case (CKM_SKIPJACK_ECB64) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_ECB64 mechanism.\n";
#endif
      break;
    case (CKM_SKIPJACK_CBC64) :
      pOid = new AsnOid(id_fortezzaConfidentialityAlgorithm);
      break;
    case (CKM_SKIPJACK_OFB64) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_OFB62 mechanism.\n";
#endif
      break;
    case (CKM_SKIPJACK_CFB64) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_CFB64 mechanism.\n";
#endif
      break;
    case (CKM_SKIPJACK_CFB32) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_CFB32 mechanism.\n";
#endif
      break;
    case (CKM_SKIPJACK_CFB16) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_CFB16 mechanism.\n";
#endif
      break;
    case (CKM_SKIPJACK_CFB8) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_CFB8 mechanism.\n";
#endif
      break;
    case (CKM_SKIPJACK_WRAP) :
      pOid = new AsnOid(id_fortezzaWrap80);
      break;
    case (CKM_SKIPJACK_PRIVATE_WRAP) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_PRIVATE_WRAP mechanism.\n";
#endif
      break;
    case (CKM_SKIPJACK_RELAYX) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_SKIPJACK_RELAYX mechanism.\n";
#endif
      break;
    case (CKM_KEA_KEY_PAIR_GEN) :
#ifdef PKCS11_PRINT
      std::cout << "Unable to match oid for CKM_KEA_KEY_PAIR_GEN mechanism.\n";
#endif
      break;
    case (CKM_KEA_KEY_DERIVE) :
      pOid = new AsnOid(id_keyExchangeAlgorithm);
        break;
    default :
#ifdef PKCS11_PRINT
        std::cout.flags(std::ios::hex);
        std::cout << "No match for mechanism type -> " << mechanismType 
                                       << ".  Possibly vendor defined.\n";
#endif
        break;
    }

    std::cout.flush();

    SME_FINISH_CATCH

    return pOid;
}
CK_MECHANISM_PTR CSM_Pkcs11MechanismInfo::GetMechanismStruct()
{
   CK_MECHANISM_PTR pMechanismStruct = NULL_PTR;

   SME_SETUP("CSM_Pkcs11MechanismInfo::GetMechanismStruct");

   if (m_pMechanismStruct)
   {
      if ((pMechanismStruct = 
               (CK_MECHANISM_PTR) malloc (sizeof(CK_MECHANISM))) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

      memcpy(pMechanismStruct, m_pMechanismStruct, sizeof(CK_MECHANISM));
   }

   SME_FINISH_CATCH

   return pMechanismStruct;
}
CK_MECHANISM_INFO_PTR CSM_Pkcs11MechanismInfo::GetMechanismInfo()
{
   CK_MECHANISM_INFO_PTR pMechanismInfo = NULL_PTR;

   SME_SETUP("CSM_Pkcs11MechanismInfo::GetMechanismInfo");

   if (m_pMechanismInfo)
   {
      if ((pMechanismInfo = 
             (CK_MECHANISM_INFO_PTR) malloc (sizeof(CK_MECHANISM_INFO))) == NULL)
         SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

      memcpy(pMechanismInfo, m_pMechanismInfo, sizeof(CK_MECHANISM_INFO));
   }

   SME_FINISH_CATCH

   return pMechanismInfo;
}
void CSM_Pkcs11MechanismInfo::SetDllFunctions(SFL_C_GetMechanismInfo getMechanismInfo)
{
   sfl_c_getMechanismInfo = getMechanismInfo;
}


_END_CERT_NAMESPACE

// EOF sm_pkcs11Mechanism.cpp
