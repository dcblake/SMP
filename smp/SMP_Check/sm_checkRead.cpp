
// checkRead.cpp
//
#include "sm_api.h"
#include "sm_AppLogin.h"

//#define DISABLE_CML_ACL

using namespace SFL;
using namespace CERT;
using namespace CTIL;
using namespace SNACC;

#define TMPSecondSignedDataBinary "./TMPSecondSignedDataBinaryU.dat"  
#define TMPFirstEnvelopedDataBinary  "./TMPSecondEnvelopedDataBinary.dat" 

void    checkRead(CSMIME *pAppLogin, 
                  const char *msgData, long msgLength,
                  acl::Session *pACLsession,
                  long lCMLSessionIdIN, long lSRLSessionIdIN)
{
    char *lpszError=NULL;
    CSM_Buffer *pFirstEnvelopedDataBuffer=NULL;
    CSM_Buffer *pSecondSignedDataBuffer=NULL;
    CSM_MsgToDecrypt MsgToDecrypt;
    CSM_MsgToVerify MsgToVerify2;
    CSM_Buffer *pACLMsgLabel=NULL;
    long lstatus=0;
    const CSM_Buffer *pACLSignerCert=NULL;

    SME_SETUP("checkRead");

    pAppLogin->UseAll();
    pAppLogin->UseAllEncryptors();

         // construct message to encrypt.
        char *lpszExpected_msgStr = "Content-Type: Text/Plain\nContent-Transfer-Encoding:7bit\n\rTestMessage\n\r";
        // Login and setup our instance.

        CSM_Buffer CIBuf(TMPFirstEnvelopedDataBinary);  
                                 // FROM Wrap test in this project.
        CSM_ContentInfoMsg contentInfo(&CIBuf);
        if (!contentInfo.IsEnvelopedData())
        {
           SME_THROW(SM_UNKNOWN_ERROR, "content doesn't contain an EnvelopedData", NULL);
        }
        pFirstEnvelopedDataBuffer = new CSM_Buffer(
           contentInfo.AccessEncapContentClear()->m_content.Access(),
           contentInfo.AccessEncapContentClear()->m_content.Length());



        ////////////////////////////////////////////////////////////////
        // FIRST, decrypt EnvelopedData class and save SignedData.
        if (pFirstEnvelopedDataBuffer)
        {
            /*RWC;THIS LOGIC IS UNNECESSARY SINCE RSA IS USED, originator cert 
                  is not checked.
            MsgToDecrypt.m_bCMLFatalFail = true;
            MsgToDecrypt.m_bCMLUseToValidate = true;
            MsgToDecrypt.m_lCmlSessionId = lCMLSessionIdIN;
            MsgToDecrypt.m_lSrlSessionId = lSRLSessionIdIN;*/
            /* RWC; NORMALLY, EnvelopedData is encapsulated in a ContentInfo.
            //  IN this case, it is raw, not wrapped.  This is how to handle it
            //  if it is wrapped:
            CSM_ContentInfoMsg contentInfo(pFirstEnvelopedDataBuffer);
            if (!contentInfo.IsEnvelopedData())
               SME_THROW(SM_UNKNOWN_ERROR, "content doesn't contain an EnvelopedData",
                  NULL);*/

               // Pre Process the encoded blob
            SME(MsgToDecrypt.PreProc(pAppLogin, pFirstEnvelopedDataBuffer));
            SME(MsgToDecrypt.Decrypt(pAppLogin));
            // FINISHED decrypting; the PreProc will align only the 1st valid 
            //  RecipientInfo.  This logic checks which RecipientInfo was 
            //  decrypted.
            MsgToDecrypt.ReportMsgData(std::cout);
            std::cout << "checkRead:  Decrypting operation worked fine.\n";
            std::cout.flush();

            // THE ACL VALIDATION MUST WAIT FOR THE Inner-Content SignedData 
            //  processing in order to extract the Mesage Securtiy Label (and
            //  optionally the originator certificate).

            pSecondSignedDataBuffer = new CSM_Buffer(
               MsgToDecrypt.AccessEncapContentFromAsn1()->m_content.Access(), 
               MsgToDecrypt.AccessEncapContentFromAsn1()->m_content.Length());
            pSecondSignedDataBuffer->ConvertMemoryToFile(TMPSecondSignedDataBinary);
            delete pFirstEnvelopedDataBuffer;

            // NOTE:: BE SURE NOT TO DELETE MsgToDecrypt, since it will be used
            //        for ACL validation after the SignedData content is 
            //        processed!
        }      // END if pFirstEnvelopedDataBuffer


        ////////////////////////////////////////////////////////////////
        // SECOND, setup SignedData class and sign the EnvelopedData results.
        pAppLogin->UseAll();     // RESET for last verification.
        if (pSecondSignedDataBuffer &&
            MsgToDecrypt.AccessEncapContentFromAsn1()->m_contentType == id_signedData)

        {
           /* RWC; NORMALLY, SignedData is encapsulated in a ContentInfo.
            // IN this case, it is raw, not wrapped...
           CSM_ContentInfoMsg contentInfo(pFirstSignedDataBuffer);
           if (!contentInfo.IsSignedData())
           {
              SME_THROW(SM_UNKNOWN_ERROR, "content doesn't contain a SignedData", NULL);
           }*/
           // Pre-process the message in case the application must fill in other info.
           if (msgData == NULL || msgLength == 0)
           {                 // CHECK result with test wrap operation.
             MsgToVerify2.m_bCMLFatalFail = true;
#ifdef DISABLE_CML_ACL
             MsgToVerify2.m_bCMLUseToValidate = false;
#else      // DISABLE_CML_ACL
             MsgToVerify2.m_bCMLUseToValidate = true;
#endif      // DISABLE_CML_ACL
             MsgToVerify2.m_lCmlSessionId = lCMLSessionIdIN;
             MsgToVerify2.m_lSrlSessionId = lSRLSessionIdIN;
             if (pACLsession)     // SETUP decrypter to ACL validate 
             {                    //   originator AND us.
#ifdef DISABLE_CML_ACL
               MsgToVerify2.m_bACLUseToValidate = false;
#else           // DISABLE_CML_ACL
               MsgToVerify2.m_bACLUseToValidate = true;
#endif          // DISABLE_CML_ACL
               MsgToVerify2.m_bACLFatalFail = true;  // No need to check error 
                                                  //   string on return, it 
                                                  //   will throw an exception.
               MsgToVerify2.m_ACLInterface.setACLSession(*pACLsession);
               //NOTE:Auto loaded in this case;MsgToDecrypt.m_ACLInterface.setACLMsgLabel(*pACLMsgLabel);
               /*RWC;CTIL::CSM_BufferLst BufLst;
               CSM_Buffer *pbufCert = BufLst.Append();
               //RWC;BROKEN;pbufCert->SetFileName("./nistCARoot@nist.gov.sig");  //RWC;COULD NOT GET ACL TO READ CML ISSUER!
               pbufCert->SetFileName("./TestCARSA@test.gov.cer");  //RWC;COULD NOT GET ACL TO READ CML ISSUER!*/
               //RWC11;CML::ASN::Bytes CMLcpBuf("./TestCARSA@test.gov.cer");
               //RWC11;CML::ASN::CertificationPath CMLCertPath(CMLcpBuf);
               //RWC11;MsgToVerify2.m_ACLInterface.setPathBufs(CMLCertPath);  // OPTIONAL cert path buffers (normally looked up).
             }      // END if pACLsession
             if (MsgToVerify2.PreProc(pAppLogin, pSecondSignedDataBuffer, NULL) == 
                 SM_NO_ERROR)
             {
              //  Perform the signature verification.
               if (pACLsession &&      // SETUP decrypter to ACL validate 
                   MsgToVerify2.m_pSignerInfos &&
                   MsgToVerify2.m_pSignerInfos->begin()->AccessCerts() && 
                   MsgToVerify2.m_pSignerInfos->begin()->AccessCerts()->size())
                   MsgToVerify2.m_pACLLocalCert = new CSM_Buffer(
                       *MsgToVerify2.m_pSignerInfos->begin()->AccessCerts()->
                        begin()->AccessEncodedCert());     // SETUP AFTER PreProc(...)
              if (MsgToVerify2.Verify(pAppLogin) == SM_NO_ERROR)
              {
                  std::cout << "########### OUTER SIGNED DATA RESULTS. ########\n";
                  MsgToVerify2.ReportMsgData(std::cout);  // SIMPLY report success/failure.
                  CSM_Buffer *pOrigContent = new CSM_Buffer(
                     MsgToVerify2.AccessEncapContentClear()->m_content.Access(), 
                     MsgToVerify2.AccessEncapContentClear()->m_content.Length());
                  if (strcmp(pOrigContent->Access(), lpszExpected_msgStr) == 0)
                     std::cout << "####### OUTER SIGNED DATA CONTENT matched original.\n";
                  else
                     std::cout << "####### OUTER SIGNED DATA CONTENT DID NOT matched original.\n";
                  delete pOrigContent;
                  std::cout.flush();
              }
              else
              {
                 SME_THROW(22, "checkRead:  Verify(...) failed.", NULL);
              }
              delete pSecondSignedDataBuffer;
             }      // END if pFirstSignedDataBuffer.
           }         // END if no user content specified.
           else
           {      // OPTIONALLY compare original passed in by user.
               CSM_Buffer ABUF(msgData, msgLength);
               if (MsgToVerify2.AccessEncapContentClear()->m_content == ABUF)  // BINARY compare.
                  std::cout << "####### OUTER SIGNED DATA CONTENT matched user specified buffer.\n";
               else
                  std::cout << "####### OUTER SIGNED DATA CONTENT DID NOT matched user specified buffer.\n";
           }
        }      // END if (pSecondSignedDataBuffer)



        ////////////////////////////////////////////////////////////////
        // PERFORM ACL Validation on Decrypted Message (now that we have 
        //  processed the inner SignedData and can access the Message Security 
        //  Label).  This ACL validation IS NOT PERFORMED ON THE SignedData here;
        //  the SignedData was validated in CSM_MsgToVerify::PreProc(...) earlier.
        //  This set of logic ONLY PROCESSES THE EnvelopedData Recipient AND
        //  Originator.
              // GET security label AND optional signer certificate as originator.
              if (MsgToVerify2.m_pSignerInfos && MsgToVerify2.m_pSignerInfos->size() &&
                  MsgToVerify2.m_pSignerInfos->begin()->m_pSignedAttrs)
              {
                 CSM_SecLbl *pCSM_SecLbl =
                     MsgToVerify2.m_pSignerInfos->begin()->m_pSignedAttrs->GetSecurityLabel();
                 if (pCSM_SecLbl)       // ONLY return if present.
                 {
                     SNACC::ESSSecurityLabel *pSNACCSecLbl = 
                                              pCSM_SecLbl->GetSNACCSecLbl();
                     if (pSNACCSecLbl)
                     {
                        ENCODE_BUF(pSNACCSecLbl, pACLMsgLabel);
                                            // Create extracted security label
                        delete pSNACCSecLbl;
                     }      // END IF pSNACCSecLbl built.
                     delete pCSM_SecLbl;
                 }  // END IF security label present in SignedAttrs
                 CSM_CertificateChoiceLst *pSignerCerts=
                        MsgToVerify2.m_pSignerInfos->begin()->AccessCerts();
                 if (pSignerCerts)  // THEN get signer cert.
                 {
                     pACLSignerCert = pSignerCerts->begin()->AccessEncodedCert();
                            // DO NOT DELETE, since pointing directly to 
                            //  certs of MsgToVerify2.
                 }      // END if pSignerCerts
              }     // END IF SignedAttrs present.
            // NOW, perform ACL setup/check.
            if (pACLsession && pACLMsgLabel)        // SETUP decrypter to ACL validate 
                                    //   originator AND us.
            {
#ifdef DISABLE_CML_ACL
               MsgToDecrypt.m_bACLUseToValidate = false;
#else           //  DISABLE_CML_ACL
               MsgToDecrypt.m_bACLUseToValidate = true;
               MsgToDecrypt.m_lCmlSessionId = lCMLSessionIdIN;
               MsgToDecrypt.m_lSrlSessionId = lSRLSessionIdIN;
#endif          // DISABLE_CML_ACL
               MsgToDecrypt.m_bACLFatalFail = true;  // No need to check error 
                                                  //   string on return, it 
                                                  //   will throw an exception.
               MsgToDecrypt.m_ACLInterface.setACLSession(*pACLsession);
               MsgToDecrypt.m_ACLInterface.setACLMsgLabel(*pACLMsgLabel);
                                 // pACLMsgLabel extracted from SignedData content.
               if (pACLSignerCert)      // OPTIONAL as originator of Encrypted Msg.
                   MsgToDecrypt.m_pACLOriginatorCertBuf = new CSM_Buffer(*pACLSignerCert);
               // NOTE: for the originator cert load, "m_pACLOriginatorCertBuf;
               //  in this case, the load is unnecessary since this originator
               //  was already validated against this security label in the 
               //  SignedData processing (see ACL flags above in verify).  It
               //  is being double checked as an Incomming Originator in 
               //  MsgToDecrypt by loading this buffer.
               /*RWC;CTIL::CSM_BufferLst BufLst;
               CSM_Buffer *pbufCert = BufLst.Append();
               //RWC;BROKEN;pbufCert->SetFileName("./nistCARoot@nist.gov.sig");  //RWC;COULD NOT GET ACL TO READ CML ISSUER!
               pbufCert->SetFileName("./TestCARSA@test.gov.cer");  //RWC;COULD NOT GET ACL TO READ CML ISSUER!*/
               //RWC11;CML::ASN::Bytes CMLcpBuf("./TestCARSA@test.gov.cer");
               //RWC11;CML::ASN::CertificationPath CMLCertPath(CMLcpBuf);
               //RWC11;MsgToDecrypt.m_ACLInterface.setPathBufs(CMLCertPath);  // OPTIONAL cert path buffers (normally looked up).
               lstatus = MsgToDecrypt.ACLCheckoutCerts();
            }       // END if pACLsession
            if (pACLMsgLabel)
               delete pACLMsgLabel;

        ////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////////


    SME_FINISH
    SME_CATCH_SETUP
      Exception.getCallStack(std::cout);
    SME_CATCH_FINISH_C2(lpszError);
    if (lpszError)
       std::cout << "EXCEPTION IN PROCESSING:  " << lpszError << "\n";

}           // END checkRead(...)




// EOF    checkRead

