// checkCreate.cpp
//

//RWC;#include <stdio.h>
//RWC;#include <stdlib.h>
#include "sm_api.h"
#include "sm_AppLogin.h"

//#define DISABLE_CML_ACL

using namespace SFL;
using namespace CERT;
using namespace CTIL;
using namespace SNACC;


// RWC; NO PATH ON THESE FILES...
#define TMPFirstSignedDataBinary      "TMPFirstSignedDataBinary.dat"
#define TMPSecondEnvelopedDataBinary  "TMPSecondEnvelopedDataBinary.dat"

void checkCreate(CSMIME *pAppLogin, char *pszCertificateFileNamesForEncrypters[], 
                            const char *msgData, long msgLength, AsnOid *pmsgOidIn,
                            CSM_Buffer *pACLMsgLabel=NULL,   // OPTIONAL
                            acl::Session *pACLsession=NULL,
                            long lCMLSessionIdIN=0, long lSRLSessionIdIN=0)
{
    char *lpszError=NULL;
    AsnOid msgOid(id_data);      // Default is id-data, unless pmsgOidIn specified
    CSM_Buffer *pFirstSignedDataBuffer=NULL;
    CSM_Buffer *pSecondEnvelopedDataBuffer=NULL;

    SME_SETUP("checkCreate");
         // construct message to encrypt.
    // Login and setup our instance.

   if (pmsgOidIn != NULL)
   {
       msgOid = *pmsgOidIn;
   }
   if (msgData == NULL)
   {
       msgData = "Content-Type: Text/Plain\nContent-Transfer-Encoding:7bit\n\rTestMessage\n\r";
       msgLength = strlen(msgData) + 1;
   }


        pAppLogin->UseAll();
        pAppLogin->UseAllEncryptors();


        ////////////////////////////////////////////////////////////////
        // FIRST setup SignedData class, and sign results
        CSM_MsgToSign MsgToSign;
        const CSM_Buffer EncapContent(msgData, msgLength);// single (char *) is file.
        MsgToSign.SetEncapContentClear((const CSM_Buffer &)EncapContent, msgOid);
        MsgToSign.SetIncludeContentFlag(true);
        MsgToSign.SetIncludeOrigCertsFlag(true);
        MsgToSign.m_bCMLFatalFail = true;
#ifdef DISABLE_CML_ACL
        MsgToSign.m_bCMLUseToValidate = false;
#else   // DISABLE_CML_ACL
        MsgToSign.m_bCMLUseToValidate = true;
#endif  // DISABLE_CML_ACL
        MsgToSign.m_lCmlSessionId = lCMLSessionIdIN;
        MsgToSign.m_lSrlSessionId = lSRLSessionIdIN;
        if (pACLsession)     // SETUP decrypter to ACL validate 
        {                    //   originator AND us.
#ifdef DISABLE_CML_ACL
           MsgToSign.m_bACLUseToValidate = false;
#else       // DISABLE_CML_ACL
           MsgToSign.m_bACLUseToValidate = true;
#endif      // 
           MsgToSign.m_bACLFatalFail = true;  // No need to check error 
                                              //   string on return, it 
                                              //   will throw an exception.
           MsgToSign.m_ACLInterface.setACLSession(*pACLsession);
           //NOTE:Auto loaded in this case;MsgToDecrypt.m_ACLInterface.setACLMsgLabel(*pACLMsgLabel);
           /*RWC;CTIL::CSM_BufferLst BufLst;
           CSM_Buffer *pbufCert = BufLst.Append();
           //RWC;pbufCert->SetFileName("./nistCARoot@nist.gov.sig");  //RWC;COULD NOT GET ACL TO READ CML ISSUER!
           pbufCert->SetFileName("./TestCARSA@test.gov.cer");  //RWC;COULD NOT GET ACL TO READ CML ISSUER!*/
           //RWC11;CML::ASN::Bytes CMLcpBuf("./TestCARSA@test.gov.cer");
           //RWC11;CML::ASN::CertificationPath CMLCertPath(CMLcpBuf);
           //RWC11;MsgToSign.m_ACLInterface.setPathBufs(CMLCertPath);  // OPTIONAL cert path buffers (normally looked up).
        }      // END if pACLsession

            /////////////////////
            // Demonstrate setting attribute.
            if (MsgToSign.m_pSignedAttrs == NULL)
               MsgToSign.m_pSignedAttrs = new CSM_MsgAttributes;
            if (MsgToSign.m_pSignedAttrs->m_pAttrs == NULL)
               MsgToSign.m_pSignedAttrs->m_pAttrs = new CSM_AttribLst;
            CSM_Time *ptmptime=new CSM_Time("01101010", strlen("01101010"),
                    SigningTime::generalizedTimeCid);
            CSM_Attrib *pAttr = &(*MsgToSign.m_pSignedAttrs->m_pAttrs->append());
            pAttr->SetSigningTime(*ptmptime);
            delete ptmptime;

            if (pACLMsgLabel)   // OPTIONALLY add security label, if requested.
            {
                pAttr = &(*MsgToSign.m_pSignedAttrs->m_pAttrs->append());
                pAttr->SetAttribByOid(id_aa_securityLabel, *pACLMsgLabel);
            }       // END IF optional pACLMsgLabel

            CSM_Buffer ErrBuf;
            if (!MsgToSign.m_pSignedAttrs->CheckSignedAttrs(&ErrBuf))
               std::cout << "checkCreate: WARNING! We loaded an invalid attribute into the SignedAttrs.\n ";
               // CAN CHECK unsigned, enveloped and encrypted in a similar manner.

             if (MsgToSign.Sign(pAppLogin) == SM_NO_ERROR)
             {
                  std::cout << "checkCreate:  Signing operation worked fine.\n";
                  std::cout.flush();

                 // WRITES TMP OUTPUT FILE
                 //MUST be called to force final signing operation.
                 CSM_Buffer *pbufContent = MsgToSign.GetEncodedContentInfo();
                 delete pbufContent;
                 if (MsgToSign.AccessEncodedBlob())
                 {

                       pFirstSignedDataBuffer = new CSM_Buffer(
                          MsgToSign.AccessEncodedBlob()->Access(), MsgToSign.AccessEncodedBlob()->Length());
                       ((CSM_Buffer *)MsgToSign.AccessEncodedBlob())->ConvertMemoryToFile(TMPFirstSignedDataBinary);
                 }
             }
             else
             {
                SME_THROW(22, "checkCreate: MsgToSign.Sign(...) failed.", NULL);
             }

        ////////////////////////////////////////////////////////////////
        // SECOND, setup EnvelopedData class and encrypt SignedData.
        if (pFirstSignedDataBuffer)
        {
            CSM_MsgToEncrypt MsgToEncrypt;
            SME(MsgToEncrypt.SetEncapContentClear(*pFirstSignedDataBuffer, 
               AsnOid(id_signedData)));
            AsnOid oidContentEncryption(des_ede3_cbc); // OID definition in .ASN file(s)
            MsgToEncrypt.SetContentEncryptOID(&oidContentEncryption);
            MsgToEncrypt.SetIncludeOrigCertsFlag(false); 
                                 //DEFAULT, should only be necessary for DH.
            MsgToEncrypt.SetAddOriginatorAsRecipient(false);
            MsgToEncrypt.m_bCMLFatalFail = true;
#ifdef DISABLE_CML_ACL
            MsgToEncrypt.m_bCMLUseToValidate = false;
#else      // DISABLE_CML_ACL
            MsgToEncrypt.m_bCMLUseToValidate = true;
#endif      // DISABLE_CML_ACL
            MsgToEncrypt.m_lCmlSessionId = lCMLSessionIdIN;
            MsgToEncrypt.m_lSrlSessionId = lSRLSessionIdIN;
            if (pACLsession && pACLMsgLabel)
            {
#ifdef DISABLE_CML_ACL
               MsgToEncrypt.m_bACLUseToValidate = false;
#else          // DISABLE_CML_ACL
               MsgToEncrypt.m_bACLUseToValidate = true;
#endif          // DISABLE_CML_ACL
               MsgToEncrypt.m_bACLFatalFail = true;
               MsgToEncrypt.m_ACLInterface.setACLSession(*pACLsession);
               MsgToEncrypt.m_ACLInterface.setACLMsgLabel(*pACLMsgLabel);
               //RWC;NOTE;The following should not be necessary, but for some reason the ACL
               //         logic cannot properly locate the path, so we OPTIONALLY provide 
               //         it here.
               /*RWC;CTIL::CSM_BufferLst BufLst;
               CSM_Buffer *pbufCert = BufLst.Append();
               //RWC;BROKEN;pbufCert->SetFileName("./nistCARoot@nist.gov.sig");  //RWC;COULD NOT GET ACL TO READ CML ISSUER!
               pbufCert->SetFileName("./TestCARSA@test.gov.cer");  //RWC;COULD NOT GET ACL TO READ CML ISSUER!*/
               //RWC11;CML::ASN::Bytes CMLcpBuf("./TestCARSA@test.gov.cer");
               //RWC11;CML::ASN::CertificationPath CMLCertPath(CMLcpBuf);
               //RWC11;MsgToEncrypt.m_ACLInterface.setPathBufs(CMLCertPath);  // OPTIONAL cert path buffers.
            }       // END if pACLsession

            // NOW, load RecipientInfo list from certificate files.
            CSM_Buffer *pbufCert;
            CSM_RecipientInfo *pRecipInfo;
            char *ptr = pszCertificateFileNamesForEncrypters[0];
            for (int ii=1; ptr != NULL && strlen(ptr) > 0; ii++)
            {
                                    // COULD be any recipient cert, in this 
                                    //  case ONE MUST BE the originator cert
                                    //  so that we can decrypt the results.
               pbufCert = new CSM_Buffer(ptr);  //Create buffer with file contents.
               /////////////////////
               // Demonstrate Loading RSA recipient (can load any Cert-based 
               //   recip this way).  KEK is slightly more detailed.
               if (MsgToEncrypt.m_pRecipients == NULL)   // ONLY if we have at least 1.
                  if ((MsgToEncrypt.m_pRecipients = new CSM_RecipientInfoLst) == NULL)
                     SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
               pRecipInfo = &(*MsgToEncrypt.m_pRecipients->append());
               pRecipInfo->m_pCert = new CSM_CertificateChoice(*pbufCert);

               delete pbufCert;   //new CSM_RecipientInfo(*pbufCert);
               ptr = pszCertificateFileNamesForEncrypters[ii]; // GET next cert file name.
            }     // END for each recipient certificate file to load.
            // MsgToEncrypt.m_pUnprotectedAttrs AND 
            // MsgToEncrypt.m_pUnprotectedAttrs->CheckUnprotectedAttrs(&ErrBuf) 
            //  can be filled and checked as in CSM_MsgToSign.
            SME(MsgToEncrypt.Encrypt(pAppLogin));
            std::cout << "checkCreate:  Encrypting operation worked fine.\n" << std::endl;
            if ((pSecondEnvelopedDataBuffer = MsgToEncrypt.GetEncodedContentInfo()) 
                != NULL)
            {
               pSecondEnvelopedDataBuffer->ConvertMemoryToFile(
                  TMPSecondEnvelopedDataBinary);
               delete pSecondEnvelopedDataBuffer;
            }
            delete pFirstSignedDataBuffer;
        }      // END if (pFirstSignedDataBuffer)


        ////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////


   SME_FINISH
   SME_CATCH_SETUP
      Exception.getCallStack(std::cout);
   SME_CATCH_FINISH_C2(lpszError)
    if (lpszError)
       std::cout << "EXCEPTION IN PROCESSING:  " << lpszError << "\n";
}


// EOF    checkCreate.cpp

