
//DEBUG ONLY...#define PKCS11_OUTPUT_CERTS  //RWC;

#include "sm_pkcs11.h"
_BEGIN_CERT_NAMESPACE
using namespace CTIL;
using namespace SNACC;

// static global which SHOULD only be accessible to this module.
CK_BBOOL CSM_Pkcs11::Pkcs11LibIsInitialized = FALSE;

//
// This is the Initialization routine for C
//
extern "C" {
SM_RET_VAL SMPkcs11Init(void *pCSMIME, int slotId, char *pUserPin, char *pDllName)
{
   CSM_CtilMgr *pUseCSMIME = (CSM_CtilMgr *) pCSMIME;

   SME_SETUP("SMPkcs11Init()");

   // generate a new fortezza class
   // Call Pkcs11 CTIL contructor to load up pCSMIME
   // with instances.
   CSM_Pkcs11 pkcs11(pUseCSMIME, (CK_SLOT_ID) slotId, pUserPin, pDllName);

   return SM_NO_ERROR;   
   
   SME_FINISH_CATCH;
}
} // end extern 'C'

// Initialization routines (Constructors) for C++
//
CSM_Pkcs11::CSM_Pkcs11()                    
{
   SME_SETUP("CSM_Pkcs11::CSM_Pkcs11()");

   Clear();

   SME_FINISH_CATCH;
}
////////////////////////////////////////////////////////////////////////////////////
// The following constructor requires the slot where the Pkcs11 token "resides" 
// (this does not neccessarily mean hardware slot (see Pkcs11 document), the 
// UserPin required by C_Login to have access to certain functions (i.e. crypto 
// functions) and the name of the Pkcs11 DLL.  The instance created by this 
// constructor will hold data that will be copied to instances created for each 
// certificate/Private key pair found on the token.  
////////////////////////////////////////////////////////////////////////////////////
CSM_Pkcs11::CSM_Pkcs11(CSM_CtilMgr *pCSMIME, 
                       CK_SLOT_ID slotId,
                       char *pUserPin, 
                       char *pDllName)
{
   long status = 0;
   SME_SETUP("CSM_Pkcs11::CSM_Pkcs11");
 
   if (pCSMIME == NULL || pUserPin == NULL)
      SME_THROW(SM_MISSING_PARAM, "Missing parameter.", NULL);

   Clear();
      
   // Load function pointers into class variables.
   LoadDllFunctions(pDllName);

   SME(status = Initialize());

   if (status != 0 && status != -2)  // CHECK for special NULL login as well
   {
      SME_THROW(22, "Bad Initialize call.", NULL);
   }

   SME(status = CreateInstances(pCSMIME, pUserPin, slotId));

   SME_FINISH_CATCH;
}
///////////////////////////////////////////////////////////////////////////////////
// The following constructor could be used to create an instance (personality)
// in a Pkcs11 token.
///////////////////////////////////////////////////////////////////////////////////
CSM_Pkcs11::CSM_Pkcs11 (CSM_Buffer &Certificate, CSM_Buffer *pPrivateKey, 
                        char *pPin, CK_SLOT_ID slotId)
{
    SME_SETUP("CSM_Pkcs11::CSM_Pkcs11");

    // Unfinished constructor

    SME_FINISH_CATCH;
}
CSM_Pkcs11::~CSM_Pkcs11()
{
   //sfl_c_finalize(NULL_PTR);
   //sfl_c_closeSession(m_hSession);
   if (m_pId)
      free (m_pId);
   if (m_pSubject)
      free (m_pSubject);
   if (m_pSlot)
      delete m_pSlot;

   if (m_pLabel)  
      free(m_pLabel);

   if (m_pCertificateChoice != NULL)
      delete m_pCertificateChoice;

   if(m_pPkcs11DllName)
      free (m_pPkcs11DllName);
}
void CSM_Pkcs11::Clear()
{
   m_slotId = -1;
   m_hSession = SM_PKCS11_INVALID_HANDLE;
   m_hCertificate = SM_PKCS11_INVALID_HANDLE;
   m_hPrivateKey = SM_PKCS11_INVALID_HANDLE;
   m_hSecretKey = SM_PKCS11_INVALID_HANDLE;
   m_hPinObject = SM_PKCS11_INVALID_HANDLE;

   m_subjectLen = 0;
   m_idLen = 0;

   m_pPkcs11DllName = NULL;
   m_pSlot = NULL;
   m_pId = NULL_PTR;
   m_pSubject = NULL_PTR;
   m_pLabel = NULL_PTR;
   m_pCertificateChoice = NULL;

   m_pSlotList = NULL;

   // Function pointers for each Pkcs11 function (Version 2.1)
   sfl_c_initialize = NULL;
   sfl_c_finalize = NULL;
   sfl_c_getInfo = NULL;
   sfl_c_getFunctionList = NULL;
   sfl_c_getSlotList = NULL;
   sfl_c_getSlotInfo = NULL;
   sfl_c_getTokenInfo = NULL;
   sfl_c_getMechanismList = NULL;
   sfl_c_getMechanismInfo = NULL;
   sfl_c_initToken = NULL;
   sfl_c_initPIN = NULL;
   sfl_c_setPIN = NULL;
   sfl_c_openSession = NULL;
   sfl_c_closeSession = NULL;
   sfl_c_closeAllSessions = NULL;
   sfl_c_getSessionInfo = NULL;
   sfl_c_getOperationState = NULL;
   sfl_c_setOperationState = NULL;
   sfl_c_login = NULL;
   sfl_c_logout = NULL;
   sfl_c_createObject = NULL;
   sfl_c_copyObject = NULL;
   sfl_c_destroyObject = NULL;
   sfl_c_getObjectSize = NULL;
   sfl_c_getAttributeValue = NULL;
   sfl_c_setAttributeValue = NULL;
   sfl_c_findObjectsInit = NULL;
   sfl_c_findObjects = NULL;
   sfl_c_findObjectsFinal = NULL;
   sfl_c_encryptInit = NULL;
   sfl_c_encrypt = NULL;
   sfl_c_encryptUpdate = NULL;
   sfl_c_encryptFinal = NULL;
   sfl_c_decryptInit = NULL;
   sfl_c_decrypt = NULL;
   sfl_c_decryptUpdate = NULL;
   sfl_c_decryptFinal = NULL;
   sfl_c_digestInit = NULL;
   sfl_c_digest = NULL;
   sfl_c_digestUpdate = NULL;
   sfl_c_digestKey = NULL;
   sfl_c_digestFinal = NULL;
   sfl_c_signInit = NULL;
   sfl_c_sign = NULL;
   sfl_c_signUpdate = NULL;
   sfl_c_signFinal = NULL;
   sfl_c_signRecoverInit = NULL;
   sfl_c_signRecover = NULL;
   sfl_c_verifyInit = NULL;
   sfl_c_verify = NULL;
   sfl_c_verifyUpdate = NULL;
   sfl_c_verifyFinal = NULL;
   sfl_c_verifyRecoverInit = NULL;
   sfl_c_verifyRecover = NULL;
   sfl_c_digestEncryptUpdate = NULL;
   sfl_c_decryptDigestUpdate = NULL;
   sfl_c_signEncryptUpdate = NULL;
   sfl_c_decryptVerifyUpdate = NULL;
   sfl_c_generateKey = NULL;
   sfl_c_generateKeyPair = NULL;
   sfl_c_wrapKey = NULL;
   sfl_c_unwrapKey = NULL;
   sfl_c_deriveKey = NULL;
   sfl_c_seedRandom = NULL;
   sfl_c_generateRandom = NULL;
   sfl_c_getFunctionStatus = NULL;
   sfl_c_cancelFunction = NULL;
}
SM_RET_VAL CSM_Pkcs11::Initialize ()
{
    SM_RET_VAL status = SM_NO_ERROR;

    SME_SETUP("CSM_Pkcs11::Initialize");

    CK_VOID_PTR pReserved = NULL_PTR;

    if (!Pkcs11LibIsInitialized)
    {
       status = Initialize (pReserved);

       // Initialize SHOULD only be called once so a static Boolean
       // will be used to indicate initialization has been performed.
       if (status == 0 || status == -2)  // CHECK for special NULL login
           Pkcs11LibIsInitialized = TRUE;
    }

    if (status == SM_NO_ERROR && m_pSlotList == NULL)
    {
        status = LoadSlotList();
        if (status != SM_NO_ERROR && status != -2)  // CHECK for special NULL login
            SME_THROW(status, "Unable to LoadSlotList.", NULL);
    }       // END IF status && m_pSlotList

    SME_FINISH_CATCH;

    return status;
}
// FUNCTION: CreateInstances
//
// PURPOSE: Create an instance for each certificate
//          in the Token.
//
SM_RET_VAL CSM_Pkcs11::CreateInstances(CSM_CtilMgr *pCSMIME, char *pUserPin, int slotId)
{
#define MAX_NUMBER_OF_CERTS 100
#define MAX_NUMBER_OF_PRIVATE_KEYS   100

   SM_RET_VAL status = SM_NO_ERROR;

   CSM_CSInst *pNewInst = NULL;
   CSM_Pkcs11 *pNewPkcs11 = NULL;
   CSM_BufferLst *pCertBufLst = NULL;
   CSM_Buffer *pNewCertBuf = NULL; 

   // A unique ID will be built for each certificate using 
   // the pkcs11 dll, the slotId and the certificate index.
   char *pInstID = 
      (char *) malloc(strlen(m_pPkcs11DllName) + 
                                 2 /*slotId*/ + 2 /*cert index*/ + 3 
                                 + 22); //ADD some extra, in case NULL is used.

   CK_ULONG ulObjectCount;
   CK_SESSION_HANDLE hSession;
   CK_OBJECT_HANDLE_PTR phObject = NULL_PTR;
   CK_OBJECT_HANDLE_PTR ptmphObject = NULL_PTR;
   // CKF_SERIAL_SESSION  must always be set for backward compatability
   // first time for open session should be masked with CKF_RW_SESSION
   CK_FLAGS sessionFlags = CKF_RW_SESSION | CKF_SERIAL_SESSION;

   SME_SETUP("CSM_Pkcs11::CreateInstances");

   if ((status = OpenSession((CK_SLOT_ID) slotId,
                             sessionFlags,
                             NULL_PTR,
                             NULL_PTR,
                             &hSession)) != SM_NO_ERROR)
   {
      // try opening session in read only mode.  This means that there  
      // was a read write session already opened and another one couldn't be opened.
      // read only is the false setting for mask CKF_RW_SESSION (0x00000002)
      sessionFlags = CKF_SERIAL_SESSION;

      status = OpenSession((CK_SLOT_ID) slotId,
                             sessionFlags,
                             NULL_PTR,
                             NULL_PTR,
                             &hSession);
   }

   if (status == SM_NO_ERROR && 
      (pUserPin == NULL || strncmp(pUserPin, "NULL_LOGIN", 10) != 0))
   {
      status = Login(hSession, 
                          CKU_USER, 
                          (CK_CHAR_PTR) pUserPin, 
                          strlen(pUserPin));
      if (status == SM_NO_ERROR || status == CKR_USER_ALREADY_LOGGED_IN)
      {   
         // Some extra oids might be available from CSM_Free3 if 
         // this method is being called withing CSM_Pkcs11Free3.
         LoadExtraOids();

         //  Find all X-509 Certificates in the token and create an 
         //  instance for each one.
         CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
         CK_CERTIFICATE_TYPE certType = CKC_X_509;

         CK_ATTRIBUTE certTemplate[] = {
            {CKA_CLASS, &objClass, sizeof(objClass)},
            {CKA_CERTIFICATE_TYPE, &certType, sizeof(certType)}};

         CK_ULONG ulAttributeCount = sizeof(certTemplate) / sizeof(CK_ATTRIBUTE);
         
         if ((status = FindObjects(hSession,
                                   certTemplate,
                                   ulAttributeCount,
                                   MAX_NUMBER_OF_CERTS,
                                   ulObjectCount,
                                   phObject)) == SM_NO_ERROR)
         {
            // phObject points to a list (array) of object handles.
            // Copy the pointer into a temporary variable so we can
            // advance it (ptmphObject++) but still keep phObject
            // so the memory can be freed at the end of the loop.
            ptmphObject = phObject;

            for (CK_ULONG i = 1; i <= ulObjectCount; i++)
            {
               std::cout << "Certificate #" << i << ".\n";
               std::cout.flush();

               //  NOTE : This method might be called from a
               //         CSM_Pkcs11Free3 or CSM_Pkcs11 instance,
               //         GetInstancePointer will create the appropriate
               //         instance (of "this") and will then return
               //         a CSM_Pkcs11 pointer.

               // Get new pointer for each certificate.
               pNewPkcs11 = GetInstancePointer();

               // Copy information from the orignal instance 
               // into each new instance.
               // NOTE : The session handle and the dll functions MUST
               //        be copied before any other information.
               pNewPkcs11->SetSession(hSession);
               pNewPkcs11->SetDllFunctions(this);

               // Using the object handle (returned from call to FindObjects)
               // create a CSM_CertificateChoice in every instance. SetCertificate
               // will return an error if no private key is found to match
               // the certificate in which case the instance will be delete.
               if (pNewPkcs11->SetCertificate(*ptmphObject) == SM_NO_ERROR)
               {
                  pNewPkcs11->SetPin(pUserPin);
                  // Set processed slot list into each instance.
                  pNewPkcs11->SetSlotLst(m_pSlotList);
                  pNewPkcs11->SetSlot((CK_SLOT_ID) slotId);
                  pNewPkcs11->SetAlgsAndOids();

                  if ((pNewInst = new CSM_CSInst) == NULL)
                    SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

                  pNewInst->SetCertificates(pNewPkcs11->m_pCertificateChoice);

                  // Build unique ID for each certificate.
                  sprintf(pInstID,"%s-%02d-%02d", m_pPkcs11DllName, slotId, i);

                  pNewInst->SetID(pInstID);

                  pNewInst->SetTokenInterface((CSM_TokenInterface *) pNewPkcs11);
                  AsnOid *pSignOid = pNewPkcs11->GetPrefDigestEncryption();
                  CSM_AlgLstVDA *pkeyEncryptionAlgID = NULL;
                  pNewPkcs11->BTIGetAlgIDs(NULL, NULL, &pkeyEncryptionAlgID, NULL);
                  if (pSignOid && (*pSignOid == rsa || *pSignOid == rsaEncryption) && 
                      pkeyEncryptionAlgID == NULL && 
                      pNewInst->CheckKeyUsageBit(KeyUsage::keyEncipherment))
                  {             // RWC;SPECIAL CASE, GemPlus in particular 
                                //  indicates both signer and encrypter with 
                                //  CKF_SIGN/CKF_VERIFY not with CKF_WRAP as 
                                //  expected to indicate both, must check cert 
                                //  to determine if both signing/encrypting 
                                //  are valid.
                      pkeyEncryptionAlgID = new CSM_AlgLstVDA;
                      CSM_AlgVDA *pAlg = &(*pkeyEncryptionAlgID->append());
                      *pAlg = *pSignOid;
                      pNewPkcs11->BTISetAlgIDs(NULL, NULL, pkeyEncryptionAlgID, NULL);
                  }
                  if (pSignOid)
                      delete pSignOid;

// Turn on this define block to create a file for each 
// certificate found in the token.
#ifdef PKCS11_OUTPUT_CERTS

                  char *pCertName = 
                     (char *) calloc(1,strlen(pInstID) + strlen("Cert.out") + 1);
              
                  strcpy(pCertName, pInstID);

                  strcat(pCertName,"Cert.out");

                  char *pFilePathAndName = 
                     (char *) calloc(1,strlen("./sm_pkcs11/Recipients/") + 
                                                           strlen(pCertName) + 1);
                
                  //strcpy(pFilePathAndName, "./sm_pkcs11/Recipients/");

                  strcat(pFilePathAndName, pCertName);

                  const CSM_Buffer *tmpBuffer = pNewInst->AccessUserCertificate()->
                                        /*pNewPkcs11->m_pCertificateChoice->*/
                                        AccessEncodedCert();

                  long status = ((CSM_Buffer *)tmpBuffer)->ConvertMemoryToFile(pFilePathAndName);

                  free (pCertName);
                  free (pFilePathAndName);
#endif  // PKCS11_OUTPUT_CERTS
               }
               else
               {
                  // Unable to complete instance so delete memory.
                  delete pNewPkcs11;
               }
            
               // Next object handle
               ptmphObject++;

               if (pNewInst != NULL)
               {
                  if (pCSMIME->m_pCSInsts == NULL)
                     pCSMIME->m_pCSInsts = new CSM_CtilInstLst;

               //RWC;5/12/02; SPECIAL NOTE; using SFL version of list here in order
               //  to specially load the CTIL MGR version of the list with the same
               //  sub-class pointer as the CSMIME libCert version.
               // put it in the instance list in pCSMIME
               pCSMIME->m_pCSInsts->append(pNewInst);  // ADD to end of list.
               //sib
			      pNewPkcs11->SetCSInst(pNewInst);   
                  // SINCE we generated a CSM_CSInst, not a CSM_CtilInst.
                  //  (THIS member is not used by the CTIL, but by the
                  //   application if a CSMIME (not CSM_CtilMgr) 
                  //   container is used for certificate access.

               }
               else
               {
                  std::cout << "No instances created.\n";
               }
            }     // END FOR ulObjectCount of certificates in PKCS11
         }        // END IF FindObjects

         if (phObject)
            free (phObject);
         phObject = NULL_PTR;
      }     // IF Already logged in
      else
      {
         // Close the session since the user was unable to Login.
         sfl_c_closeSession(hSession);
         sfl_c_finalize(NULL_PTR);
      }     // END IF Already logged in
    }       // IF status AND "NULL_LOGIN"
    else if (pUserPin && strncmp(pUserPin, "NULL_LOGIN", 10) == 0)
    {
         // Some extra oids might be available from CSM_Free3 if 
         // this method is being called withing CSM_Pkcs11Free3.
         LoadExtraOids();

               // Get new pointer for each certificate.
               pNewPkcs11 = GetInstancePointer();

               // Copy information from the orignal instance 
               // into each new instance.
               // NOTE : The session handle and the dll functions MUST
               //        be copied before any other information.
               pNewPkcs11->SetSession(hSession);
               pNewPkcs11->SetDllFunctions(this);

                  pNewPkcs11->SetPin(pUserPin);
                  // Set processed slot list into each instance.
                  pNewPkcs11->SetSlotLst(m_pSlotList);
                  pNewPkcs11->SetSlot((CK_SLOT_ID) slotId);
                  pNewPkcs11->SetAlgsAndOids();

                  if ((pNewInst = new CSM_CSInst) == NULL)
                    SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

                  // Build unique ID for each certificate.
                  sprintf(pInstID,"%s-%02d-NULL", m_pPkcs11DllName, slotId);

                  pNewInst->SetID(pInstID);

                  pNewInst->SetTokenInterface((CSM_TokenInterface *) pNewPkcs11);
                  CSM_AlgLstVDA *pkeyEncryptionAlgID = NULL;

               if (pNewInst != NULL)
               {
                  if (pCSMIME->m_pCSInsts == NULL)
                     pCSMIME->m_pCSInsts = new CSM_CtilInstLst;

                   //RWC;5/12/02; SPECIAL NOTE; using SFL version of list here in order
                   //  to specially load the CTIL MGR version of the list with the same
                   //  sub-class pointer as the CSMIME libCert version.
                   // put it in the instance list in pCSMIME
                   pCSMIME->m_pCSInsts->append(pNewInst);  // ADD to end of list.
                   //sib
                   pNewPkcs11->SetCSInst(pNewInst);   
                   // SINCE we generated a CSM_CSInst, not a CSM_CtilInst.
                   //  (THIS member is not used by the CTIL, but by the
                   //   application if a CSMIME (not CSM_CtilMgr) 
                   //   container is used for certificate access.
                 if (strstr(pUserPin, "DUMP") != NULL)
                 {      // DEBUG ONLY dump of card contents to "std::cout"
                     //Extracting CKO_PUBLIC_KEY from card to see all attributes/object
                     pNewPkcs11->sm_PKCS11_DUMP();
                 }  // END IF pUserPin=="DUMP"
               }
               else
               {
                  std::cout << "No instances created.\n";
               }
    }       // IF status AND "NULL_LOGIN"
    else
    {
       // fatal error couldn't open the session
       SME_THROW(status, "Couldn't open a session!", NULL);
    }       // END IF status AND "NULL_LOGIN"

   if (phObject)
      free (phObject);
   if (pInstID)
      free(pInstID);

   SME_FINISH
    SME_CATCH_SETUP
       // catch/cleanup logic as necessary
       if (phObject)
          free (phObject);
       if (pInstID)
          free(pInstID);
    SME_CATCH_FINISH

    return status;
}

//
//
CSM_Pkcs11 * CSM_Pkcs11::GetInstancePointer()
{
   CSM_Pkcs11 *pPkcs11 = NULL;

   SME_SETUP("CSM_Pkcs11::GetInstancePointer")

   if ((pPkcs11 = new CSM_Pkcs11) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   SME_FINISH_CATCH;

   return pPkcs11;
}
void CSM_Pkcs11::SetSlotLst(CSM_Pkcs11SlotLst *pSlotList)
{
   if (m_pSlotList)
      delete m_pSlotList;

   m_pSlotList = pSlotList;
}

//
//
SM_RET_VAL CSM_Pkcs11::SetSlot (CK_SLOT_ID slotId)
{
   SM_RET_VAL status = SM_NO_ERROR;

   SME_SETUP ("CSM_Pkcs11::SetSlot");

   CSM_Pkcs11SlotLst::iterator itSlot;

   if (m_pSlotList == NULL)
      status = -1;
   else
   {
       for (itSlot =  m_pSlotList->begin();
            itSlot != m_pSlotList->end();
            ++itSlot)
       {
          if (itSlot->AccessSlotId() == slotId)
          {
             m_pSlot = &(*itSlot);
             break;
          }
       }

       if (itSlot == m_pSlotList->end())
          status = -1;
   }        // END IF m_pSlotList

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return status;
}       // END CSM_Pkcs11::SetSlot (...)

//
//
SM_RET_VAL CSM_Pkcs11::LoadSlotList ()
{
   SM_RET_VAL status = SM_NO_ERROR;

   CK_ULONG ulCount = 0;
   CK_SLOT_ID_PTR pSlotList = NULL_PTR;
   CK_BBOOL tokenPresent = TRUE;   // we are only interested in slots with tokens

   SME_SETUP("CSM_Pkcs11::LoadSlotList")

   if ((status = GetSlotList(tokenPresent, pSlotList, ulCount)) == SM_NO_ERROR)
      status = ProcessSlotList(pSlotList, ulCount);
 
   if (pSlotList)
      free (pSlotList);

   SME_FINISH_CATCH

   return status;
}
SM_RET_VAL CSM_Pkcs11::ProcessSlotList (CK_SLOT_ID_PTR pSlotList,
                                        CK_ULONG slotCount)
{
    SM_RET_VAL status = SM_NO_ERROR;
    CSM_Pkcs11Slot *pSlot;
    CK_SLOT_ID_PTR pCurrSlot = pSlotList;

    SME_SETUP("CSM_Pkcs11::ProcessSlotList");

    for (CK_ULONG i = 0; i < slotCount; i++)
    {
        pSlot = NULL;

        if (m_pSlotList == NULL)
            if ((m_pSlotList = new CSM_Pkcs11SlotLst) == NULL)
                SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

        if ((pSlot = &(*m_pSlotList->append())) == NULL)
            SME_THROW(SM_MEMORY_ERROR, "MEMORY", NULL)

        pSlot->SetDllFunctions(sfl_c_getSlotList,
                                sfl_c_getSlotInfo, 
                                sfl_c_getTokenInfo,
                                sfl_c_getMechanismInfo,
                                sfl_c_getMechanismList);

        pSlot->SetSlotId(*pCurrSlot);
        pSlot->GetSlotInfo();
        pSlot->GetTokenInfo();

        // Load mechanisms available in the slot.
        pSlot->LoadMechanisms();
        
        pCurrSlot++; // Next Slot
    }

    SME_FINISH_CATCH

    return status;
}
void CSM_Pkcs11::SetPin (char *pPin)
{
   SME_SETUP("CSM_Pkcs11::SetPin");

   CK_OBJECT_HANDLE hObj;
   CK_ULONG ulObjAttributeCount;

   CK_OBJECT_CLASS objClass = CKO_DATA;
   CK_CHAR label [] = "Data object for Pin";

   CK_BYTE_PTR pPinValue = (CK_BYTE_PTR) pPin;
   CK_ULONG valueLen = (CK_ULONG) strlen(pPin);
   CK_BBOOL isSensitive = TRUE;
   CK_BBOOL isExtractable = FALSE;
   CK_BBOOL isTokenObj = TRUE;

   CK_ATTRIBUTE objTemplate[] = {
      {CKA_CLASS, &objClass, sizeof(objClass)},
      {CKA_TOKEN, &isTokenObj, sizeof(isTokenObj)},
      {CKA_LABEL, label, sizeof(label - 1)},
      {CKA_EXTRACTABLE, &isExtractable, sizeof(isExtractable)},
      {CKA_SENSITIVE, &isSensitive, sizeof(isSensitive)},
      {CKA_VALUE, pPinValue, valueLen}
   };

   ulObjAttributeCount = sizeof(objTemplate) / sizeof(CK_ATTRIBUTE);

   if (CreateObject
            (m_hSession, objTemplate, ulObjAttributeCount, hObj) == SM_NO_ERROR)
      m_hPinObject = hObj;

    SME_FINISH_CATCH
}
/////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Pkcs11::SetAlgsAndOids()
{
   SM_RET_VAL status = SM_NO_ERROR;

   AsnOid *pTmpDigestOid = NULL;
   AsnOid *pDigestOid = NULL;
   AsnOid *pDigestEncryptionOid = NULL;
   AsnOid *pKeyEncryptionOid = NULL;
   AsnOid *pContentEncryptionOid = NULL;

   CSM_AlgLstVDA *pDigestEncryptionAlgLst = NULL;
   CSM_AlgLstVDA *pKeyEncryptionAlgLst = NULL;

   SME_SETUP("CSM_Pkcs11::SetAlgsAndOids");

   if (m_pSlot == NULL)
       SME_THROW(22, "BAD m_pSlot, NULL.", NULL);
   // ASSUME we can support all digest and content encryption 
   // algorithms supported by the token.
   CSM_AlgLstVDA *pDigestAlgLst = m_pSlot->AccessDigestAlgLst();
   CSM_AlgLstVDA *pContentEncryptionAlgLst = m_pSlot->AccessContentEncryptionAlgLst();

   // Retrieve oid from SubjectPulicKeyInfo in Certificate.
   AsnOid *pPublicKeyOID = NULL;
   if (m_pCertificateChoice)
       pPublicKeyOID = m_pCertificateChoice->GetKeyOID();

   // Default preferred Digest oid and Content encryption oid 
   // to first one found in list.
   if (pDigestAlgLst != NULL)
   {
       CSM_AlgLstVDA::iterator itDIgestAlg=pDigestAlgLst->begin();
      pDigestOid = new AsnOid(itDIgestAlg->algorithm);

      // If the first digest Oid supported is MD2 check if there is an
      // alternative since MD2 has been, in most crypto libraries, replaced 
      // (more than likely with MD5).
      if (*pDigestOid == id_md2 || *pDigestOid == "1.2.840.113549.2.2")
      {
         //AsnOid pasnoid = pDigestAlgLst->NextL()->algorithm;
         ++itDIgestAlg;
         if ((pDigestAlgLst->size() > 1 ) && 
            ((pTmpDigestOid = new AsnOid(itDIgestAlg->algorithm)) != NULL))
         {
            delete pDigestOid;
            pDigestOid = pTmpDigestOid;
         }
      }
   }

   if (pContentEncryptionAlgLst != NULL)
      pContentEncryptionOid = 
            new AsnOid(pContentEncryptionAlgLst->begin()->algorithm);

   CK_MECHANISM_INFO_PTR pMechInfo = GetMechanismInfo(pPublicKeyOID);

   if (((pMechInfo->flags & CKF_SIGN) != 0) ||
       ((pMechInfo->flags & CKF_VERIFY) !=0))
   {
      // Set preferred oid for signing
      if (pPublicKeyOID != NULL)
          pDigestEncryptionOid = pPublicKeyOID;
      else      // SET default...
          pDigestEncryptionOid = new AsnOid(rsaEncryption);


      // Create CSM_Alg entry to insert into AlgIds list for this instance.
       pDigestEncryptionAlgLst = new CSM_AlgLstVDA();
       CSM_AlgVDA *pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
       pDigestEncryptionAlg->algorithm = *pDigestEncryptionOid;
       if (*pDigestEncryptionOid == rsa || *pDigestEncryptionOid == rsaEncryption)
       {
            pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
            pDigestEncryptionAlg->algorithm = sha_1WithRSAEncryption;
            pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
            pDigestEncryptionAlg->algorithm = sha_1WithRSAEncryption_ALT;
            pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
            pDigestEncryptionAlg->algorithm = AsnOid("1.2.840.113549.1.2");
            pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
            pDigestEncryptionAlg->algorithm = rsaEncryption;
            pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
            pDigestEncryptionAlg->algorithm = md5WithRSAEncryption;
            pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
            pDigestEncryptionAlg->algorithm = AsnOid("1.3.14.3.2.3"); //md5WithRSAEncryptionOIW;
       }       // IF RSA
       else if (*pDigestEncryptionOid == id_dsa)
       {
            pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
            pDigestEncryptionAlg->algorithm = id_dsa_with_sha1;
            pDigestEncryptionAlg = &(*pDigestEncryptionAlgLst->append());
            pDigestEncryptionAlg->algorithm = id_OIW_secsig_algorithm_dsa;
       }       // END IF RSA/DSA check.
  }             // END IF SIGN or VERIFY mechanism.

   if ( ((pMechInfo->flags & CKF_WRAP) != 0) ||
        ((pMechInfo->flags & CKF_UNWRAP) != 0) )
   {
       pKeyEncryptionOid = pPublicKeyOID;

       pKeyEncryptionAlgLst = new CSM_AlgLstVDA();
       CSM_AlgVDA *pKeyEncryptionAlg = &(*pKeyEncryptionAlgLst->append());
       pKeyEncryptionAlg->algorithm = *pKeyEncryptionOid;
   }

   BTISetAlgIDs(pDigestAlgLst,
             pDigestEncryptionAlgLst,
             pKeyEncryptionAlgLst,
             pContentEncryptionAlgLst);

   BTISetPreferredCSInstAlgs(pDigestOid,
                        pDigestEncryptionOid,
                       pKeyEncryptionOid,
                       pContentEncryptionOid);

    SME_FINISH_CATCH

   return status;
}       // END CSM_Pkcs11::SetAlgsAndOids()

//////////////////////////////////////////////////////////////////////////
bool CSM_Pkcs11::IsOidSupported(AsnOid oid)
{
    bool oidSupported = false;
    CSM_Pkcs11MechanismInfoLst::iterator itMechanism;

    for (itMechanism = m_pSlot->AccessMechanismLst()->begin();
         itMechanism != m_pSlot->AccessMechanismLst()->end() && 
             !oidSupported;
         ++itMechanism)
    {
        if (oid == *itMechanism->AccessOid())
            oidSupported = TRUE;
    }
    
   return oidSupported;
}

//
//
CSM_AlgVDA *CSM_Pkcs11::DeriveMsgAlgFromCert(CSM_AlgVDA &Alg) 
{   
	return new CSM_AlgVDA(Alg); 
}

//

CSM_Alg * CSM_Pkcs11::DeriveMsgAlgFromCert(CSM_CertificateChoice &cert)
{ 
   CSM_Alg *pubKeyAlg = NULL;

   pubKeyAlg = cert.GetPublicKeyAlg();
 
   return(pubKeyAlg);
}
//////////////////////////////////////////////////////////////////////////
// This function restores or sets the default OIDs in the BTI
void CSM_Pkcs11::SetDefaultOIDs()
{
   SME_SETUP("CSM_Pkcs11::SetDefaultOIDs");

   /*******************
   // make Md5, RsaEncryption, RsaEncryption, and RC2Encryption the
   // preferred algs
   AsnOid oidMd5(bsafe_id_md5);
   AsnOid oidSha1(sha_1);
   AsnOid oidRsaEncr(rsaEncryption);
   AsnOid oidRc2Encr(bsafe_id_rc2_encr);
   BTISetPreferredCSInstAlgs(&oidSha1, &oidRsaEncr, &oidRsaEncr, &oidRc2Encr);
  *******************************/

   SME_FINISH_CATCH
}
/////////////////////////////////////////////////////////////////////////////////////////////////////

#ifndef NO_DLL
#ifdef WIN32
extern "C" {
   long Make_argv(char *string, int *pargc, char ***pargv);

   //
   //
   SM_PKCS11DLL_API SM_RET_VAL DLLBuildTokenInterface(CSMIME &Csmime,
      char *lpszBuildArgs)
   {
      SM_RET_VAL status = 0;
      int argc1 = 0;
      char **argv1;
      char ptr[30];

      memset(ptr, '\0', 30);
      for (int i = 0; i < (int)strlen("sm_Pkcs11DLL"); i++)
         ptr[i] = toupper(lpszBuildArgs[i]);
      // Preliminary check that this request if for out library
      if (strncmp(ptr, "SM_PKCS11DLL", strlen("sm_Pkcs11DLL")) == 0)
      {
         Make_argv(lpszBuildArgs, &argc1, &argv1);
         if (argc1 == 4)
         {
            // Pass char *pszAddressBook, char *pUserPin
            SMPkcs11Init(&Csmime, atoi(argv1[1]), argv1[2], argv1[3]);
         }
         else
         {
            status = -1;
         }
      }
      else
      {
         status = -1;
         std::cout << "DLLBuildTokenInterface failed!!!\n";
      }

      return(status);
   }    // END DLLBuildTokenInterface(...)

   //
   //
   SM_PKCS11DLL_API char *DLLGetId()
   {
      return (strdup("sm_Pkcs11DLL"));
   }    // END DLLGetId()
}       // END extern "C"

//
//
void CSM_Pkcs11::sm_PKCS11_DUMP()
{
    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount;
    CK_RV rv;
	CK_OBJECT_CLASS keyClass = -22;

    rv = sfl_c_findObjectsInit(m_hSession, NULL_PTR, 0);  // ACCESS ALL objects
    if (rv != CKR_OK)
        return;

    //
    while (1) 
    {
      rv = sfl_c_findObjects(m_hSession, &hObject, 1, &ulObjectCount);
      if (rv != CKR_OK || ulObjectCount == 0)
        break;

      CK_ATTRIBUTE template1[] = {
          {CKA_CLASS, &keyClass, sizeof(keyClass)}
      };
      std::cout << "**** START PKCS11 DUMP." << std::endl;
      //if (sfl_c_getAttributeValue != NULL)
      rv = sfl_c_getAttributeValue(m_hSession, hObject, template1, 1);
      if (rv == 0)
      {
          switch (keyClass)
          {
          case CKO_DATA:
                  std::cout << "   CKO_DATA." << std::endl;
              break;

          case CKO_CERTIFICATE:
                  std::cout << "   CKO_CERTIFICATE." << std::endl;
              break;

          case CKO_PUBLIC_KEY:
                  std::cout << "   CKO_PUBLIC_KEY." << std::endl;
                  sm_PKCS11_DUMP_Attributes(hObject);
              break;

          case CKO_PRIVATE_KEY:
                  std::cout << "   CKO_PRIVATE_KEY." << std::endl;
              break;

          case CKO_SECRET_KEY:
                  std::cout << "   CKO_SECRET_KEY." << std::endl;
              break;

          case CKO_VENDOR_DEFINED:
                  std::cout << "   CKO_VENDOR_DEFINED." << std::endl;
              break;

          default:
                  std::cout << "   DEFAULT." << std::endl;
              break;

          }    // END SWITCH object type...
      }        // END IF GetAttributeValue(...)
    }          // END WHILE (1)

    rv = sfl_c_findObjectsFinal(m_hSession);
    if (rv != CKR_OK)
        return;
}       // END  sm_PKCS11_DUMP()

//
//
void CSM_Pkcs11::sm_PKCS11_DUMP_Attributes(CK_OBJECT_HANDLE hObject)
{
    CK_RV rv;
	CK_OBJECT_CLASS keyClass = -22;
/*
#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_APPLICATION        0x00000010
#define CKA_VALUE              0x00000011
#define CKA_CERTIFICATE_TYPE   0x00000080
#define CKA_ISSUER             0x00000081
#define CKA_SERIAL_NUMBER      0x00000082
#define CKA_KEY_TYPE           0x00000100
#define CKA_SUBJECT            0x00000101
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_ENCRYPT            0x00000104
#define CKA_DECRYPT            0x00000105
#define CKA_WRAP               0x00000106
#define CKA_UNWRAP             0x00000107
#define CKA_SIGN               0x00000108
#define CKA_SIGN_RECOVER       0x00000109
#define CKA_VERIFY             0x0000010A
#define CKA_VERIFY_RECOVER     0x0000010B
#define CKA_DERIVE             0x0000010C
#define CKA_START_DATE         0x00000110
#define CKA_END_DATE           0x00000111
#define CKA_MODULUS            0x00000120
#define CKA_MODULUS_BITS       0x00000121
#define CKA_PUBLIC_EXPONENT    0x00000122
#define CKA_PRIVATE_EXPONENT   0x00000123
#define CKA_PRIME_1            0x00000124
#define CKA_PRIME_2            0x00000125
#define CKA_EXPONENT_1         0x00000126
#define CKA_EXPONENT_2         0x00000127
#define CKA_COEFFICIENT        0x00000128
#define CKA_PRIME              0x00000130
#define CKA_SUBPRIME           0x00000131
#define CKA_BASE               0x00000132
#define CKA_VALUE_BITS         0x00000160
#define CKA_VALUE_LEN          0x00000161
#define CKA_EXTRACTABLE        0x00000162
#define CKA_LOCAL              0x00000163
#define CKA_NEVER_EXTRACTABLE  0x00000164
#define CKA_ALWAYS_SENSITIVE   0x00000165
#define CKA_MODIFIABLE         0x00000170
#define CKA_ECDSA_PARAMS       0x00000180
#define CKA_EC_POINT           0x00000181
#define CKA_VENDOR_DEFINED     0x80000000
*/
      std::cout << "    Attribute list." << std::endl;
      CK_ULONG ulValueLen=1000;//0;
      CK_VOID_PTR pValue=(CK_VOID_PTR)calloc(1, 1000); //NULL;
      ulValueLen = 4;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_TOKEN, pValue, ulValueLen, "CKA_TOKEN");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_PRIVATE, pValue, ulValueLen, "CKA_PRIVATE");
      ulValueLen = 1000;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_LABEL, pValue, ulValueLen, "CKA_LABEL");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_APPLICATION, pValue, ulValueLen, "CKA_APPLICATION");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_VALUE, pValue, ulValueLen, "CKA_VALUE");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_CERTIFICATE_TYPE, pValue, ulValueLen, "CKA_CERTIFICATE_TYPE");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_ISSUER, pValue, ulValueLen, "CKA_ISSUER");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_SERIAL_NUMBER, pValue, ulValueLen, "CKA_SERIAL_NUMBER");
      ulValueLen = 4;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_KEY_TYPE, pValue, ulValueLen, "CKA_KEY_TYPE");
      ulValueLen = 1000;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_SUBJECT, pValue, ulValueLen, "CKA_SUBJECT");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_ID, pValue, ulValueLen, "CKA_ID");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_SENSITIVE, pValue, ulValueLen, "CKA_SENSITIVE");
      ulValueLen = 4;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_ENCRYPT, pValue, ulValueLen, "CKA_ENCRYPT");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_DECRYPT, pValue, ulValueLen, "CKA_DECRYPT");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_WRAP, pValue, ulValueLen, "CKA_WRAP");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_UNWRAP, pValue, ulValueLen, "CKA_UNWRAP");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_SIGN, pValue, ulValueLen, "CKA_SIGN");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_SIGN_RECOVER, pValue, ulValueLen, "CKA_SIGN_RECOVER");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_VERIFY, pValue, ulValueLen, "CKA_VERIFY");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_VERIFY_RECOVER, pValue, ulValueLen, "CKA_VERIFY_RECOVER");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_DERIVE, pValue, ulValueLen, "CKA_DERIVE");
      ulValueLen = 1000;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_START_DATE, pValue, ulValueLen, "CKA_START_DATE");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_END_DATE, pValue, ulValueLen, "CKA_END_DATE");
      ulValueLen = 4;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_MODULUS_BITS, pValue, ulValueLen, "CKA_MODULUS_BITS");
      if (rv == 0)
      {
          unsigned long ulModulusBits = *((unsigned long *)pValue) / 8;  // MUST be byte count.
          rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_MODULUS, pValue, ulModulusBits, "CKA_MODULUS");
      }     // END IF rv successful
      ulValueLen = 1000;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_PUBLIC_EXPONENT, pValue, ulValueLen, "CKA_PUBLIC_EXPONENT");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_PRIVATE_EXPONENT, pValue, ulValueLen, "CKA_PRIVATE_EXPONENT");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_PRIME_1, pValue, ulValueLen, "CKA_PRIME_1");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_PRIME_2, pValue, ulValueLen, "CKA_PRIME_2");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_COEFFICIENT, pValue, ulValueLen, "CKA_COEFFICIENT");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_PRIME, pValue, ulValueLen, "CKA_PRIME");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_SUBPRIME, pValue, ulValueLen, "CKA_SUBPRIME");
      ulValueLen = 4;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_VALUE_LEN, pValue, ulValueLen, "CKA_VALUE_LEN");
      if (rv == 0)
      {
          unsigned long ulValueLen = *((unsigned long *)pValue);
          rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_VALUE_BITS, pValue, ulValueLen, "CKA_VALUE_BITS");
      }     // END IF rv successful
      ulValueLen = 4;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_EXTRACTABLE, pValue, ulValueLen, "CKA_EXTRACTABLE");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_LOCAL, pValue, ulValueLen, "CKA_LOCAL");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_NEVER_EXTRACTABLE, pValue, ulValueLen, "CKA_NEVER_EXTRACTABLE");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_ALWAYS_SENSITIVE, pValue, ulValueLen, "CKA_ALWAYS_SENSITIVE");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_MODIFIABLE, pValue, ulValueLen, "CKA_MODIFIABLE");
      ulValueLen = 1000;
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_ECDSA_PARAMS, pValue, ulValueLen, "CKA_ECDSA_PARAMS");
      rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_EC_POINT, pValue, ulValueLen, "CKA_EC_POINT");
      //rv = sm_PKCS11_DUMP_GET_Attribute(hObject, CKA_VENDOR_DEFINED, pValue, ulValueLen, "CKA_VENDOR_DEFINED");
}           // END CSM_Pkcs11::sm_PKCS11_DUMP_Attributes(...)

//
//
int CSM_Pkcs11::sm_PKCS11_DUMP_GET_Attribute(CK_OBJECT_HANDLE hObject, 
        CK_ATTRIBUTE_TYPE lType, CK_VOID_PTR &pValue, CK_ULONG &ulValueLen, 
        char *pszType)
{
    CK_RV rv;
    //CK_ULONG ulValueLen3=1000;

      /*RWC;does not appear to work...*/
      /*CK_ATTRIBUTE template1[] = {{lType, NULL, ulValueLen3}};
      rv = sfl_c_getAttributeValue(m_hSession, hObject, template1, 1);
      if (rv == 0 && ulValueLen > 0)
      {
          if (pValue)
              free(pValue);
          pValue = (CK_VOID_PTR)calloc(1, ulValueLen);
          */
          CK_ATTRIBUTE template2[] = {{lType, pValue, ulValueLen}};
          rv = sfl_c_getAttributeValue(m_hSession, hObject, template2, 1);
          if (rv == 0 && pszType != NULL)
          {
              char pszInt[200];
              unsigned char *ptr=(unsigned char *)pValue;
              std::cout.flags(std::ios::hex);
              std::cout << "    " << pszType << ":";
              if (ulValueLen <= 4)
              {
                  sprintf(pszInt, "%2.2x%2.2x%2.2x%2.2x", ptr[3], ptr[2], 
                                                          ptr[1], ptr[0]);
                  std::cout << pszInt << "x" << std::endl;
              }
              else
              {
                  for (int ii=0; ii < ulValueLen; ii++)
                  {
                    sprintf(pszInt, "%2.2x", ptr[ii]);
                    std::cout << pszInt;
                  }     // END FOR each char
                  std::cout << "x" << std::endl;
              }     // END IF ulValueLen < 4
              std::cout.flags(std::ios::dec);
          } // END return of sfl_c_getAttributeValue(...)
      //}     // END return check for sfl_c_getAttributeValue
      if (rv != 0 && rv != CKR_ATTRIBUTE_TYPE_INVALID)
      {             // REPORT other errors, probably not enough buffer space.
          std::cout.flags(std::ios::hex);
          std::cout << "*** BAD error return from c_getAttributeValue(...), rv=" << rv << std::endl;
          std::cout.flags(std::ios::dec);
      }     // END if error check
      return(rv);
}           // END CSM_Pkcs11::sm_PKCS11_DUMP_GET_Attribute(...)


_END_CERT_NAMESPACE


#endif  // WIN32
#endif  // NO_DLL
