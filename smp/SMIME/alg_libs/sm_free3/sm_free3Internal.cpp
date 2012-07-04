
//////////////////////////////////////////////////////////////////////////
// sm_Free3Internal.cpp
//
// This file contains some internal routines; specifically PKCS12 support.
//
//  Author:  Robert.Colestock@getronicsgov.com
//  
//
//////////////////////////////////////////////////////////////////////////

#ifdef WIN32
#pragma  warning( disable : 4505 4512 4100 4511 4516 4663 4018 4245 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#include <process.h>
#include <winsock2.h>
#elif defined (SunOS) || defined (SOLARIS)
#include <unistd.h>
#include <arpa/inet.h>
#elif defined(Linux) || defined (SCO_SV)
#include <unistd.h>
#include <netinet/in.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include "sm_free3.h"
#include "sm_CryptoKeys.h"  //RWC;only included to undef SM_FREE3DLL_API.
#include "sm_cms.h"
#include "rsa.h"     // From cryptopp.
#include "rc2.h"     // From cryptopp.
#include "randpool.h"
RandomPool rndRandom2;

#include "sm_CryptoKeysDsaExport.h"
#include "sm_CryptoKeysECDsaExport.h"
#include "sm_CryptoKeysDHExport.h"
#include "sm_CryptoKeysF3RsaExport.h"
#include "sm_free3_asn.h"
#include "sm_apiCert.h"
//#include "sm_AppLogin.h"


#ifdef CRYPTOPP_5_0
#include "pwdbased.h"
typedef CBC_Mode_ExternalCipher::Encryption CBCPaddedEncryptor;
typedef CBC_Mode_ExternalCipher::Decryption CBCPaddedDecryptor;
#endif // CRYPTOPP_5_0


long Pkcs12_Decode(char *lpszPkcs12, CERT::CSMIME *pCsmime);

using namespace SNACC;
_BEGIN_CERT_NAMESPACE

CSM_Buffer *EncryptPKCS12Blob(const char *pszPasswordIn, 
   AlgorithmIdentifier &EncryptionAlgorithm, const CSM_Buffer &bufClearKey);
CSM_Buffer *EncryptPKCS12CreateCertSafeBag(
    const CSM_PrivDataLst &PrivateKeyList, // IN, cert(s)/private Key list
    const char *pszPasswordIN,    // IN, 
    CSM_Buffer *&pencryptedPrivDataBuf); // OUT, for private keys, encrypted 
                                  //  at the same time as the certificate 
                                  //  SafeBag(s).
void EncryptPKCS12CreatePrivSafeBag(
    const CSM_Buffer &BufPriv,   // IN, Private Key to be loaded
    const char *pszPasswordIN,   // IN, 
    SafeContents &SafeBags,      // OUT, resulting PrivateKey added to SafeBag.
    Attributes *pSNACCAttributes);// IN, Actual setting for this Private key's
                                  //   matching certificate(s).

#ifdef OPENSSL_PKCS12_ENABLED
extern "C" {
#include "SFLpkcs12_support.h"
long SFLFree3PKCS12Init(CSM_CtilMgr &Csmime, char *pszPassword, char *pszPFXFile,
                        CSM_MsgCertCrls *pCertPathIN);
}
#endif   //OPENSSL_PKCS12_ENABLED

#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif

#define OIDSafeBag_certBag                "1.2.840.113549.1.12.10.1.3"
#define OIDSafeBag_keyBag                 "1.2.840.113549.1.12.10.1.1"
#define OIDSafeBag_pkcs8ShroudedKeyBag    "1.2.840.113549.1.12.10.1.2"
#define OIDSafeBagContent_x509Certificate "1.2.840.113549.1.9.22.1"


#ifdef OPENSSL_PKCS12_ENABLED

extern "C" {

#ifdef _DEBUG      // ONLY in DEBUG mode to avoid security issues.
// This global exported function is intended for diagnostics only; it
//  will decode a PKCS12 file, and export the private key and certificate
//  in the clear in the same directory as the file, returning the cert and
//  clear private key file names.
SM_FREE3DLL_API int DLLSFLExportClearPKCS12(char *pszPassword,char *pszPFXFile,
        char *&lpszCertFile, char *&lpszClearPrivateKey)
{
    long status=0;
    char *lpszPrivateKeyOut=NULL;
    int lPrivateKeyOutLen;
    char **lppszCertOut=NULL;
    int *lpCertOutLen=NULL;
    int lCertCount=0;
    CSM_Buffer *pCertBufFIRST=NULL;
    CSM_Buffer *pPrivateKey=NULL;
    CSM_Alg *pPublicKeyAlg=NULL;
    char **lppszCRLOutRETURN;
    int *lpCRLOutLenRETURN;
    int lCRLCountRETURN;
    static int count=0;
    int iDOTest=0;

#ifdef _DEBUG
    if (iDOTest)
    {
       CSM_Free3 Free3Inst;
       CSM_PrivDataLst PrivateKeyList;
       CSM_Buffer PFXBuf(pszPFXFile);
       status = Free3Inst.DecryptPKCS12PrivateKey(&PFXBuf, pszPassword, PrivateKeyList);
       //status = Pkcs12_Decode(pszPFXFile, NULL);
       return(status);
    }
#endif //_DEBUG



    // FIRST extract the private key and cert using OPEN-SSL
    status = SM_ExtractPrivateKeyFromPkcs12(pszPFXFile, pszPassword, 
        &lpszPrivateKeyOut, &lPrivateKeyOutLen,
        &lppszCertOut, &lpCertOutLen, &lCertCount,
        &lppszCRLOutRETURN,  // OUT, CRL buffer list (if present)
        &lpCRLOutLenRETURN,    // OUT, individual CRL buffer length(s)
        &lCRLCountRETURN);      // OUT, CRL count.


    if (status == 0 && lCertCount)   // ONLY if we have at lease 1 certificate
    {
            // SECOND, create appropriate data structures for Private key and Cert(s).
            //CSM_MsgCertCrls *pCertPath=new CSM_MsgCertCrls;
            if (lppszCertOut[0] != NULL)
            {
              pCertBufFIRST = new CSM_Buffer(lppszCertOut[0], lpCertOutLen[0]);
              lpszCertFile=strdup(pszPFXFile);
              lpszCertFile[strlen(pszPFXFile)-3] = '\0';
              strcat(lpszCertFile, "cer");
              pCertBufFIRST->ConvertMemoryToFile(lpszCertFile);
              /*for (int ii=1; ii < lCertCount; ii++)
              {
                 pCertBuf = new CSM_Buffer(lppszCertOut[ii], lpCertOutLen[ii]);
                 pCert=new CSM_CertificateChoice(*pCertBuf);
                 delete pCertBuf;
                 pCertPath->AddCert(pCert);    // MEMORY taken by "AddCert"
              }*/
            }
            if (lpszPrivateKeyOut !=  NULL)
            {
              pPrivateKey =new CSM_Buffer(lpszPrivateKeyOut,lPrivateKeyOutLen);
              lpszClearPrivateKey=strdup(pszPFXFile);
              lpszClearPrivateKey[strlen(pszPFXFile)-3] = '\0';
              strcat(lpszClearPrivateKey, "prv");
              pPrivateKey->ConvertMemoryToFile(lpszClearPrivateKey);
            }
    }
       if (lpszPrivateKeyOut)
           free(lpszPrivateKeyOut);
       if (pPrivateKey)
           delete pPrivateKey;
       if (pPublicKeyAlg)
           delete pPublicKeyAlg;

       status = SM_DeletePrivateKeyCerts(lppszCertOut, lpCertOutLen, lCertCount);
       status = SM_DeletePrivateKeyCerts(lppszCRLOutRETURN, lpCRLOutLenRETURN, 
                    lCRLCountRETURN);

       return(status);
}
#endif

//
//
long SFLFree3PKCS12Init(CSM_CtilMgr &Csmime, char *pszINPassword, char *pszPFXFile,
                        CSM_MsgCertCrls *pCertPathIN)
{
    long status=0;
    char lpszID[50];
    char *lpszPrivateKeyOut=NULL;
    int lPrivateKeyOutLen;
    char **lppszCertOut=NULL;
    int *lpCertOutLen=NULL;
    int lCertCount=0;
    CSM_Buffer *pCertBuf=NULL;
    CSM_Buffer *pCertBufFIRST=NULL;
    CSM_Buffer *pPrivateKey=NULL;
    CSM_TokenInterface  *pTokenInterface=NULL;
    CSM_Alg *pPublicKeyAlg=NULL;
    char **lppszCRLOutRETURN;
    int *lpCRLOutLenRETURN;
    int lCRLCountRETURN;
    static int count=0;
    char *pszPassword=NULL;

    SME_SETUP("SFLFree3PKCS12Init");
    // FIRST extract the private key and cert using OPEN-SSL
    status = SM_ExtractPrivateKeyFromPkcs12(pszPFXFile, pszINPassword, 
        &lpszPrivateKeyOut, &lPrivateKeyOutLen,
        &lppszCertOut, &lpCertOutLen, &lCertCount,
        &lppszCRLOutRETURN,  // OUT, CRL buffer list (if present)
        &lpCRLOutLenRETURN,    // OUT, individual CRL buffer length(s)
        &lCRLCountRETURN);      // OUT, CRL count.


    if (strlen(pszINPassword) < 8) // IMPORTANT, change ONLY after PKCS12 
    {                                //   extracted.
        pszPassword = (char *)calloc(1, 9);
        strcpy(pszPassword, pszINPassword);
        memset(&pszPassword[strlen(pszINPassword)], 'X', 
            8 - strlen(pszINPassword)); // STRETCH to at least 8 chars.
    }
    else
    {
        pszPassword = (char *)calloc(1, strlen(pszINPassword)+1);
        strcpy(pszPassword, pszINPassword);
    }

    if (status == 0 && lCertCount)   // ONLY if we have at lease 1 certificate
    {
            // SECOND, create appropriate data structures for Private key and Cert(s).
            CSM_MsgCertCrls *pCertPath=new CSM_MsgCertCrls;
            if (lppszCertOut[0] != NULL)
            {
              pCertBufFIRST = new CSM_Buffer(lppszCertOut[0], lpCertOutLen[0]);
              CSM_CertificateChoice *pCert=new CSM_CertificateChoice(*pCertBufFIRST);
              pPublicKeyAlg = pCert->GetPublicKeyAlg();
              pCertPath->AddCert(pCert);    // MEMORY NO LONGER taken by "AddCert"
              delete pCert;
              for (int ii=1; ii < lCertCount; ii++)
              {
                 pCertBuf = new CSM_Buffer(lppszCertOut[ii], lpCertOutLen[ii]);
                 pCert=new CSM_CertificateChoice(*pCertBuf);
                 delete pCertBuf;
                 pCertPath->AddCert(pCert);    // MEMORY taken by "AddCert"
                 delete pCert;
              }
            }

            // NOW add optional user specified certs, expected to be cert-path.
            CSM_CertificateChoice *pCertChoice;
            if (pCertPathIN && pCertPathIN->AccessCertificates())
            {
              pCertPathIN->AccessCertificates()->SetCurrToFirst();
              for (pCertChoice = pCertPathIN->AccessCertificates()->Curr(); 
                   pCertChoice; 
                   pCertChoice=pCertPathIN->AccessCertificates()->GoNext())
              {
                 pCertPath->AddCert(pCertChoice); // MEMORY NO LONGER taken by "AddCert"
              }            // END for each cert in this private key set.
            }       // END IF pCertPath

            if (lpszPrivateKeyOut !=  NULL)
              pPrivateKey =new CSM_Buffer(lpszPrivateKeyOut,lPrivateKeyOutLen);
            //pPrivateKey->ConvertMemoryToFile("./certs/config.d/PrivatePKCS12.bin");
                            //DEBUG send to file...
       // THIRD, we must re-wrap this clear private key in a format compatible with
       // the CTIL (a fudge, since we should directly interpret the PKCS12, but time
       // time presses on).
       // (NOTE::: IGNORE the CSM_CryptoKeysDSA class definition below, we simply 
       //  use the inherited component "CSM_CryptoKeysFree3Base" to wrap any clear
       //  Private key, including RSA.  We never defined an RSA class for Free3, 
       //  maybe later).
       CSM_CryptoKeysDsaExport /*CSM_CryptoKeysFree3Base*/ A;
       CSM_Buffer *pPrivateKeyWrapped = NULL;
       if (pPrivateKey)
       {
           // SIMPLY wrap this clear Key.
           pPrivateKeyWrapped  = A.WrapPrivateKey(*pPrivateKey, pszPassword, 
               pPublicKeyAlg );
       }

       // FINALLY, create login entry for this private key and cert.
       if (pCertBufFIRST) // && pPrivateKeyWrapped)
       {
           count++;
           sprintf(&lpszID[0], "PKCS12%d", count);
           pTokenInterface  = CSM_Free3::AddLoginStatic(NULL, *pCertBufFIRST,
                pPrivateKeyWrapped, pszPassword, lpszID, pCertPath);
           delete pCertBufFIRST;    // DELETE User cert.
       }

       if (lpszPrivateKeyOut)
           free(lpszPrivateKeyOut);
       if (pPrivateKeyWrapped)
           delete pPrivateKeyWrapped;
       if (pPrivateKey)
           delete pPrivateKey;
       if (pPublicKeyAlg)
           delete pPublicKeyAlg;
       if (pszPassword)
           free(pszPassword);

       // DO NOT FREE pCertPath, it is taken by AddLoginStatic(...)
       GLOBALAddLoginFinish(Csmime, pTokenInterface, lpszID, pCertPath);

       status = SM_DeletePrivateKeyCerts(lppszCertOut, lpCertOutLen, lCertCount);
       status = SM_DeletePrivateKeyCerts(lppszCRLOutRETURN, lpCRLOutLenRETURN, 
                    lCRLCountRETURN);
    }          // END if lCertCount
    else
    {
       char buf[1000];
       if (status != 0)
       {
         sprintf(buf, "Bad PKCS12 Decode/Decrypt, file=%s.", pszPFXFile);
         SME_THROW(29, buf, NULL);
       }
       else    // Certificate count in PKCS12 was 0
       {
         sprintf(buf, "Certificate count in PKCS12 was 0, file=%s.", pszPFXFile);
         SME_THROW(30, buf, NULL);
       }
    }

    SME_FINISH
    SME_CATCH_SETUP
       if (lpszPrivateKeyOut)
           free(lpszPrivateKeyOut);
       if (pPrivateKey)
           delete pPrivateKey;
       if (pPublicKeyAlg)
           delete pPublicKeyAlg;
       if (pszPassword)
           free(pszPassword);
       SM_DeletePrivateKeyCerts(lppszCertOut, lpCertOutLen, lCertCount);
       SM_DeletePrivateKeyCerts(lppszCRLOutRETURN, lpCRLOutLenRETURN, 
                    lCRLCountRETURN);
    SME_FREE3_CATCH_FINISH


    return(status);
}

// THIS function is called by an application to create a PKCS12 file given
//  a private key file, certificate file, and a password.
//  RWC;3/27/01; THIS function MUST be updated to accommodate certifcate(s)
//  for the path, AND extract DSA Params (p, q, g) from an issuer if necessary.
SM_FREE3DLL_API int DLLSFLCreatePKCS12(char *lpszCertFile, 
    char *lpszClearPrivateKey, char *pszPassword, char *pszPFXFile) 
{
    long status=0;
    CSM_Buffer *pP=NULL, *pQ=NULL, *pG=NULL;
    CSM_CryptoKeysDsa *pCryptoDSA = NULL;
    CSM_CryptoKeysF3Rsa *pCryptoF3RSA = NULL;
    SME_SETUP("CCertWindowDlg::CreatePkcs12PrivateKey()");
    CSM_Buffer BufCertFile(lpszCertFile);
    CSM_CertificateChoice A(BufCertFile);
    CSM_Alg *pAlg=A.GetPublicKeyAlg();
    CSM_Buffer *pPublicKey=A.GetPublicKey();
    char *pPubKeyFilename = "pkcs12certpubkey.out";



	// sib
	// see if we have a decodable privateKeyInfo object and if so then just get the 
	// integer of the private key and save to the private key file
	// This was done to have a correct private key file for example-07 testing
	int status = -1;
    PrivateKeyInfo snaccPKI;
    CSM_Buffer *pbufFileIn=new CSM_Buffer(lpszClearPrivateKey);
	DECODE_BUF_NOFAIL(&snaccPKI, pbufFileIn, status);
    if (!status)
	{
		CSM_Buffer bufFileOut(snaccPKI.privateKey.c_str(),
			                  snaccPKI.privateKey.Len());
		bufFileOut.ConvertMemoryToFile(lpszClearPrivateKey);
	}
    delete pbufFileIn;


    if (pPublicKey)
    {
    pPublicKey->ConvertMemoryToFile(pPubKeyFilename);
    
    if (*pAlg->AccessSNACCId() == id_dsa || 
        *pAlg->AccessSNACCId() == id_dsa_with_sha1)
    {
         pCryptoDSA = SM_BuildCryptoKeysDSA(NULL, pszPassword);
          // call will write the EncryptedPrivateKeyInfo to output file pencPrvKeyFilename
         if(pP == NULL && pQ == NULL && pG == NULL)
         {     // ONLY if still blank, not on display; extract from issuer.
             //CSM_MsgCertCrls B;
            CSM_Buffer *pParams=pAlg->GetParams();
            if (pParams)
                pCryptoDSA->ExtractDSAParams(*pParams, pP, pQ, pG);
         }
         if(pP == NULL)
         {
             SME_THROW(25, "MUST HAVE DSA PARAMS TO BUILD PKCS12 PACKET, not in cert",
                 NULL);
         }
         CSM_Buffer *pPKCS12Buf=pCryptoDSA->WrapPkcs12(lpszClearPrivateKey, 
           pPubKeyFilename, lpszCertFile, pszPassword, *pP, 
           *pQ, *pG, pszPFXFile);
         delete pPKCS12Buf;  // RESULT already stored in optional "pencPrvKeyFilename".

    }
    else if (*pAlg->AccessSNACCId() == rsa ||
             *pAlg->AccessSNACCId() == rsaEncryption ||
             *pAlg->AccessSNACCId() == sha_1WithRSAEncryption ||
             *pAlg->AccessSNACCId() == sha_1WithRSAEncryption_ALT ||
             *pAlg->AccessSNACCId() == md5WithRSAEncryption ||
             *pAlg->AccessSNACCId() == AsnOid("1.2.840.113549.1.2"))
    {
         CSM_Buffer bufRawPKI;
         CSM_Buffer bufPKIPrivateKey(lpszClearPrivateKey);
         PrivateKeyInfo snaccPKI;
         char *pBufRawPKIFile = NULL;
         pCryptoF3RSA = SM_BuildCryptoKeysF3Rsa(NULL, pszPassword);
         DECODE_BUF_NOFAIL((&snaccPKI), &bufPKIPrivateKey, status);
         if (status == 0)       // Then this message is PrivateKeyInfo 
         {                      //  WE MUST UNWRAP BEFORE calling PKCS12
           char *ptr=(char *)calloc(1, strlen(lpszClearPrivateKey)+5);
           strcpy(ptr, lpszClearPrivateKey);
           strcat(ptr, "RAW");
           bufRawPKI.Set(snaccPKI.privateKey.c_str(), 
                         snaccPKI.privateKey.Len());
           bufRawPKI.ConvertMemoryToFile (ptr);
           pBufRawPKIFile = ptr;
         }  
         else  // ELSE ignore it, the format is already correct.
             pBufRawPKIFile = strdup(lpszClearPrivateKey);
         CSM_Buffer *pPKCS12Buf=pCryptoF3RSA->WrapPkcs12(pBufRawPKIFile, 
            lpszCertFile, pszPassword, pszPFXFile);
         if (pPKCS12Buf)
           delete pPKCS12Buf;  // RESULT already stored in optional "pencPrvKeyFilename".
         if (pBufRawPKIFile)
             free(pBufRawPKIFile);
    }

    }   // end if public key present.

   SME_FINISH
   SME_CATCH_SETUP
 
   SME_FREE3_CATCH_FINISH
   return(status);
}

}     // END extern "C"

#endif      // OPENSSL_PKCS12_ENABLED


//##################################################################################
//  Factory definitions for creating private keys: DSA, ECDSA, DH, RSA.
SM_FREE3DLL_API CSM_CryptoKeysDsa * SM_BuildCryptoKeysDSA(CSM_CertificateChoice *pCert, 
    char *lpszPassword)
{
   CSM_CryptoKeysDsa *pDSA_CK;
   if(pCert == NULL)
   {
      pDSA_CK= new CSM_CryptoKeysDsaExport();
      pDSA_CK->SetPassword(lpszPassword);
   }
   else
      pDSA_CK= new CSM_CryptoKeysDsaExport(pCert, lpszPassword);

   return(pDSA_CK);
}

#ifdef CRYPTOPP_5_0
//
//
SM_FREE3DLL_API CSM_CryptoKeysECDsa * SM_BuildCryptoKeysECDsa(CSM_CertificateChoice *pCert, 
    char *lpszPassword)
{
   CSM_CryptoKeysECDsa *pECDSA_CK;
   if(pCert == NULL)
   {
      pECDSA_CK= new CSM_CryptoKeysECDsaExport();
      pECDSA_CK->SetPassword(lpszPassword);
   }
   else
      pECDSA_CK= new CSM_CryptoKeysECDsaExport(pCert, lpszPassword);

   return(pECDSA_CK);
}       // END SM_BuildCryptoKeysECDsa(...)

//
//
SM_FREE3DLL_API CSM_CryptoKeysECDH * SM_BuildCryptoKeysECDH(char *lpszPassword)
{
   CSM_CryptoKeysECDH *pECDH_CK= new CSM_CryptoKeysECDHExport();
   pECDH_CK->SetPassword(lpszPassword);

   return(pECDH_CK);
}       // END SM_BuildCryptoKeysECDH(...)

#endif //CRYPTOPP_5_0

SM_FREE3DLL_API CSM_CryptoKeysDH * SM_BuildCryptoKeysDH(CSM_CertificateChoice *pCert, 
    char *lpszPassword)
{
   CSM_CryptoKeysDH *pDH_CK;
   if(pCert == NULL)
   {
      pDH_CK= new CSM_CryptoKeysDHExport();
      pDH_CK->SetPassword(lpszPassword);
   }
   else
      pDH_CK= new CSM_CryptoKeysDHExport(pCert, lpszPassword);

   return(pDH_CK);
}

SM_FREE3DLL_API CSM_CryptoKeysF3Rsa *SM_BuildCryptoKeysF3Rsa(CSM_CertificateChoice *pCert, 
    char *lpszPassword)
{
   CSM_CryptoKeysF3Rsa *pRsa_CK;
   if(pCert == NULL)
   {
      pRsa_CK = new CSM_CryptoKeysF3RsaExport;
      pRsa_CK->SetPassword(lpszPassword);
   }
   else
      pRsa_CK = new CSM_CryptoKeysF3RsaExport(pCert, lpszPassword);

   return(pRsa_CK);
}
//##################################################################################



//RWC;DEBUG OF HMAC ONLY;#define TEST_HMAC
#ifdef TEST_HMAC
//////////////////////////////////////////////////////////////////////////
void TestHmac()
{
    CSM_Buffer *pBuf;
    /*************************************************************************
     FROM RFC2104
      key =         0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
      key_len =     16 bytes
      data =        "Hi There"
      data_len =    8  bytes
      digest =      0x9294727a3638bb1c13f48ef8158bfc9d
    */
    char ptrKey1[]={(char)0x0b, (char)0x0b, (char)0x0b, (char)0x0b, (char)0x0b, 
                   (char)0x0b, (char)0x0b, (char)0x0b, (char)0x0b, (char)0x0b, 
                   (char)0x0b, (char)0x0b, (char)0x0b, (char)0x0b, (char)0x0b, 
                   (char)0x0b};
    CSM_Buffer BufKey1(ptrKey1, sizeof(ptrKey1));
    CSM_Buffer Data1("Hi There", strlen("Hi There"));
    unsigned char ptrExpected1[]={(unsigned char)0x92, (unsigned char)0x94, (unsigned char)0x72, (unsigned char)0x7a, 
                        (unsigned char)0x36, (unsigned char)0x38, (unsigned char)0xbb, (unsigned char)0x1c, 
                        (unsigned char)0x13, (unsigned char)0xf4, (unsigned char)0x8e, (unsigned char)0xf8, 
                        (unsigned char)0x15, (unsigned char)0x8b, (unsigned char)0xfc, (unsigned char)0x9d};
    CSM_Buffer BufExpected1((const char *)ptrExpected1, sizeof(ptrExpected1));
    pBuf = CSM_Free3::ComputePkcs12MACHash(md5, BufKey1, Data1);
    if (pBuf)
    {
        if (*pBuf == BufExpected1)
            std::cout << "EncryptPKCS12Blob: 1st SUCCESSFUL!" << std::endl;
        else
            std::cout << "EncryptPKCS12Blob: 1st UNSUCCESSFUL!" << std::endl;
        delete pBuf;
    }       // END IF pBuf


    /*************************************************************************
      key =         "Jefe"
      data =        "what do ya want for nothing?"
      data_len =    28 bytes
      digest =      0x750c783e6ab0b503eaa86e310a5db738
    */
    char ptrKey2[]="Jefe";
    CSM_Buffer BufKey2(ptrKey2, strlen(ptrKey2));
    CSM_Buffer Data2("what do ya want for nothing?", strlen("what do ya want for nothing?"));
    unsigned char ptrExpected2[]={(unsigned char)0x75, (unsigned char)0x0c, 
        (unsigned char)0x78, (unsigned char)0x3e, (unsigned char)0x6a, 
        (unsigned char)0xb0, (unsigned char)0xb5, (unsigned char)0x03, 
        (unsigned char)0xea, (unsigned char)0xa8, (unsigned char)0x6e, 
        (unsigned char)0x31, (unsigned char)0x0a, (unsigned char)0x5d, 
        (unsigned char)0xb7, (unsigned char)0x38 };
    CSM_Buffer BufExpected2((const char *)ptrExpected2, sizeof(ptrExpected2));
    pBuf = CSM_Free3::ComputePkcs12MACHash(md5, BufKey2, Data2);
    if (pBuf)
    {
        if (*pBuf == BufExpected2)
            std::cout << "EncryptPKCS12Blob: 2nd SUCCESSFUL!" << std::endl;
        else
            std::cout << "EncryptPKCS12Blob: 2nd UNSUCCESSFUL!" << std::endl;
        delete pBuf;
    }       // END IF pBuf


    /*************************************************************************
      key =         0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      key_len       16 bytes
      data =        0xDDDDDDDDDDDDDDDDDDDD...
                    ..DDDDDDDDDDDDDDDDDDDD...
                    ..DDDDDDDDDDDDDDDDDDDD...
                    ..DDDDDDDDDDDDDDDDDDDD...
                    ..DDDDDDDDDDDDDDDDDDDD
      data_len =    50 bytes
      digest =      0x56be34521d144c88dbb8c733f0e8b3f6
      */
    CSM_Buffer BufKey3((size_t)16);
    char *ptrKey3=(char *)BufKey3.Access();
    for (int iiii=0; iiii < 16; iiii++) ptrKey3[iiii] = (char)(unsigned char)0xaa;
    CSM_Buffer Data3((size_t)50);
    char *ptrData3=(char *)Data3.Access();
    for (int iii=0; iii < 50; iii++) ptrData3[iii] = (char)(unsigned char)0xDD;
    unsigned char ptrExpected3[]={(unsigned char)0x56, (unsigned char)0xbe, 
        (unsigned char)0x34, (unsigned char)0x52, (unsigned char)0x1d, 
        (unsigned char)0x14, (unsigned char)0x4c, (unsigned char)0x88, 
        (unsigned char)0xdb, (unsigned char)0xb8, (unsigned char)0xc7, 
        (unsigned char)0x33, (unsigned char)0xf0, (unsigned char)0xe8, 
        (unsigned char)0xb3, (unsigned char)0xf6 };
    CSM_Buffer BufExpected3((const char *)ptrExpected3, sizeof(ptrExpected3));
    pBuf = CSM_Free3::ComputePkcs12MACHash(md5, BufKey3, Data3);
    if (pBuf)
    {
        if (*pBuf == BufExpected3)
            std::cout << "EncryptPKCS12Blob: 3rd SUCCESSFUL!" << std::endl;
        else
            std::cout << "EncryptPKCS12Blob: 3rd UNSUCCESSFUL!" << std::endl;
        delete pBuf;
    }       // END IF pBuf


}           // END TestHmac(...)
#endif //TEST_HMAC

//////////////////////////////////////////////////////////////////////////
//
// RWC; WORK IN PROGRESS...
/* RWC;NOTES for our general PKCS12 files:
   for (pSNACCCSafeBag=SeqContentInfos.Curr(); pSNACCCSafeBag; 
        pSNACCCSafeBag=SeqContentInfos.GoNext())
   1st packet, blob is 
            if (pSNACCCSafeBag->safeBagType == id_encryptedData)
         THEN, within this blob, decrypted
            if (pencryptedData &&
                pencryptedData->encryptedContentInfo->contentType == id_data)
                WHICH contains a cert, extracted in DecryptPKCS12Cert() 
                calls DecryptPKCS12_ProcessBags(), decoding SafeBag
                if (pTmpSafeBag->safeBagType == oidSafeBag_certBag)
                   CertCRLBag, if (pCertBag->bagId == oidSafeBagContent_x509Certificate)
    2nd packet is
         else if (pSNACCCSafeBag->safeBagType == id_data)
               lStatus = DecryptPKCS12_ProcessBags(*pDataBuf, pszPassword, 
                                                  BufPrivList, BufCertList);
               WHICH contains a single private key, decoding SafeBag
               else if (pTmpSafeBag->safeBagType == oidSafeBag_pkcs8ShroudedKeyBag)

 */
long EncryptPKCS12PrivateKey(
         CSM_Buffer *&pEncryptedPrivateKeyInfo, // OUT
         const char *pszPassword,               // IN
         CSM_PrivDataLst &PrivateKeyList)       // IN
{
    EncryptedData *pencryptedData=NULL;
    AsnOcts SNACCOcts;
    CSM_Buffer *pBuf=NULL;
    PFX Pfx;
    //EncryptedData *pencryptedData=NULL;
    CSM_Buffer *pencryptedPrivDataBuf=NULL;
    SafeContents SeqContentInfos;  // Actually not SafeContents, but
                                    //   convenient definition.
    CSM_Buffer *pPKCS12Buf=NULL;
    CSM_Buffer *pPkcs12MAC=NULL;
    long lStatus=-1;       // Default failure.


   SME_SETUP("CSM_Free3::EncryptPKCS12PrivateKey");

#ifdef TEST_HMAC
   CSM_PrivDataLst PrivList;
   CSM_Buffer EncryptedPrivateKeyInfo("./bobX_12_OPENSSL.pfx");
   DecryptPKCS12PrivateKey(&EncryptedPrivateKeyInfo, "password", PrivList);
   TestHmac();
#endif // TEST_HMAC

   if (pszPassword == NULL)
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMS", NULL);

   if (pEncryptedPrivateKeyInfo == NULL)
       pEncryptedPrivateKeyInfo = new CSM_Buffer;

   // NEXT, load all certificates into a safe bag of the PKCS12.
   SafeBag *pSNACCCSafeBag;
   CSM_Buffer *pSNACCCSafeBagBuf=NULL;
   pSNACCCSafeBag = &(*SeqContentInfos.append());
   pSNACCCSafeBag->safeBagType = id_encryptedData;
   CSM_Buffer *pencryptedDataBuf = EncryptPKCS12CreateCertSafeBag(
                    PrivateKeyList, pszPassword, pencryptedPrivDataBuf);
            // EncryptedPKCS12CreateCertSafeBag(...) MUST create the private 
            //  key element as well due to the need for both IDs to match...
            //  It returns "pencryptedDataBuf".
   pencryptedData = new EncryptedData;
   DECODE_BUF(&pencryptedData->encryptedContentInfo, pencryptedDataBuf);
   ENCODE_BUF(pencryptedData, pSNACCCSafeBagBuf);
   DECODE_BUF(&pSNACCCSafeBag->safeBagContent, pSNACCCSafeBagBuf);
   delete pSNACCCSafeBagBuf;
   pSNACCCSafeBagBuf = NULL;
   delete pencryptedData;
   delete pencryptedDataBuf;

   // NEXT, load all of the private keys into a protected safe bag of the PCKS12
   pSNACCCSafeBag = &(*SeqContentInfos.append());
   pSNACCCSafeBag->safeBagType = id_data;
   //pencryptedDataBuf = EncryptPKCS12CreatePrivSafeBag(BufPrivList, 
   //                                 pszPassword);
   if (pencryptedPrivDataBuf)
   {
       SNACCOcts.Set(pencryptedPrivDataBuf->Access(), pencryptedPrivDataBuf->Length());
       ENCODE_BUF(&SNACCOcts, pBuf);
       DECODE_BUF(&pSNACCCSafeBag->safeBagContent, pBuf);
       delete pencryptedPrivDataBuf;
   }        // IF pencryptedDataBuf
   else
   {
       SME_THROW(29, "BAD EncryptPKCS12CreatePrivSafeBag call.", NULL);
   }        // END IF pencryptedDataBuf
   delete pBuf;
   pBuf = NULL;
   delete pSNACCCSafeBagBuf;

   // NEXT, encode the PKCS12 data for MAC computation.
   ENCODE_BUF(&SeqContentInfos, pPKCS12Buf);

   // FINALLY, encode the PKCS12 data element.
   Pfx.authSafe.contentType = id_data;
   Pfx.version = 3; //RWC; for compatibility with OpenSSL.
   Pfx.macData = new MacData;
   /*DigestInfo ::= SEQUENCE {
      digestAlgorithm DigestAlgorithmIdentifier,
      digest          Digest
        }*/
   CSM_Buffer bufSalt;
   pPkcs12MAC = CSM_Free3::ComputePkcs12MAC(bufSalt, sha_1, pszPassword, *pPKCS12Buf);
   if (pPkcs12MAC)
   {
       Pfx.macData->macSalt.Set(bufSalt.Access(), bufSalt.Length());
       Pfx.macData->safeMac.digestAlgorithm.algorithm = sha_1; //DigestInfo
       CSM_Alg::LoadNullParams(&Pfx.macData->safeMac.digestAlgorithm);
       //Pfx.macData->macIterationCount = 1;   // DEFAULT to 1, MUST BE MISSING for integration.
       Pfx.macData->safeMac.digest.Set(pPkcs12MAC->Access(), pPkcs12MAC->Length());
       delete pPkcs12MAC; pPkcs12MAC = NULL;

       SNACCOcts.Set(pPKCS12Buf->Access(), pPKCS12Buf->Length());
       delete pPKCS12Buf; pPKCS12Buf = NULL;
       ENCODE_BUF(&SNACCOcts, pBuf);
       DECODE_BUF(&Pfx.authSafe.content, pBuf);
       delete pBuf; pBuf = NULL;
       ENCODE_BUF(&Pfx, pEncryptedPrivateKeyInfo);
   }        // END IF ComputePkcs12MAC(...)

   SME_FINISH
   SME_CATCH_SETUP
    if (pPkcs12MAC)
        delete pPkcs12MAC;
   SME_FREE3_CATCH_FINISH

   return lStatus;
}     // END CSM_Free3::EncryptPKCS12PrivateKey(...)

//////////////////////////////////////////////////////////////////////////
//
CSM_Buffer *EncryptPKCS12CreateCertSafeBag(
    const CSM_PrivDataLst &PrivateKeyList, // IN, cert(s)/private Key list
    const char *pszPasswordIN,    // IN, 
    CSM_Buffer *&pencryptedPrivDataBuf)  // OUT, for private keys, encrypted 
                                  //  at the same time as the certificate 
                                  //  SafeBag(s).
{
    CSM_BufferLst::const_iterator itBufCert;
    CSM_PrivDataLst::const_iterator itPrivData;
    CSM_Buffer *pBufCert2=NULL;
    CSM_Buffer bufEncodedBags;
    VDASafeBlob vDASafeBlob;
    CSM_Buffer *pTmpBuf;
    CSM_Buffer *pbufEncryptedKey;
    AsnOid  oidSafeBag_certBag(OIDSafeBag_certBag);
    AsnOid  oidSafeBagContent_x509Certificate(OIDSafeBagContent_x509Certificate);
    SafeBag *pTmpSafeBag=NULL;
    SafeContents SafeBags;
    SafeContents SafeBagsPriv;
    CertCRLBag *pCertBag;
    EncryptedContentInfo snaccEncryptedCI;
    CSM_Buffer *pEncryptedCert=NULL;
    SNACC::Attribute *pSNACCAttribute;
    SNACC::AsnAny *pTmpAny;
    BMPString TmpBmpString;
    char *pCharBmpString="My Certificate";
    SNACC::AsnOcts TmpOctString;
    CSM_Buffer TmpBuf, TmpDigest;

    SME_SETUP("CSM_Free3::EncryptPKCS12CreateCertSafeBag");

    if (pszPasswordIN == NULL)
       SME_THROW(SM_MISSING_PARAM, "MISSING PARAMS", NULL);

    for (itPrivData =  PrivateKeyList.begin(); 
         itPrivData != PrivateKeyList.end();
         ++itPrivData)
    {
        pTmpSafeBag = NULL;
        for (itBufCert =  itPrivData->m_BufCertList.begin(); 
             itBufCert != itPrivData->m_BufCertList.end();
             ++itBufCert)
        {
            pTmpSafeBag = &(*SafeBags.append());
            pTmpSafeBag->safeBagType = oidSafeBag_certBag;
            pCertBag = new CertCRLBag;
            pBufCert2 = NULL;
            pCertBag->bagId = oidSafeBagContent_x509Certificate;
            vDASafeBlob.Set(itBufCert->Access(), itBufCert->Length());
            ENCODE_BUF(&vDASafeBlob, pBufCert2);
            if (pBufCert2)
            {
               DECODE_BUF(&pCertBag->value, pBufCert2);
                delete pBufCert2;
            }
            pTmpBuf = NULL;
            ENCODE_BUF(pCertBag, pTmpBuf);
            if (pTmpBuf)
            {
                DECODE_BUF(&pTmpSafeBag->safeBagContent, pTmpBuf);//RWC;11/15/02;.GetUndecodedAny();
                delete pTmpBuf;
            }   // END IF pTmpBuf

            //********************************************
            // LOAD attributes, including unique ID for this Cert.
            //   (that seem to be expected by MS Outlook)
            pTmpSafeBag->safeBagAttributes = new Attributes;
            pSNACCAttribute = &(*pTmpSafeBag->safeBagAttributes->append());
            pSNACCAttribute->type = pkcs_9_at_friendlyName;
            pTmpAny = &(*pSNACCAttribute->values.append());
            TmpBmpString.set(pCharBmpString);
            TmpBuf.Encode(TmpBmpString);
            TmpBuf.Decode(*pTmpAny);

            pSNACCAttribute = &(*pTmpSafeBag->safeBagAttributes->append());
            pSNACCAttribute->type = pkcs_9_at_localKeyId;
            pTmpAny = &(*pSNACCAttribute->values.append());
            CSM_Common::SMTI_DigestDataSHA1((CSM_Buffer *)&(*itBufCert), &TmpDigest);
            TmpOctString.Set(TmpDigest.Access(), TmpDigest.Length());
            TmpBuf.Encode(TmpOctString);
            TmpBuf.Decode(*pTmpAny);
        }      // END for each cert in this particular list (list within list).


        //********************************************
        // Take care of associated Private Key for this list of certs.
        if (pTmpSafeBag)    // ONLY if we loaded at least 1 cert.
           EncryptPKCS12CreatePrivSafeBag(itPrivData->m_BufPriv, pszPasswordIN, 
               SafeBagsPriv, pTmpSafeBag->safeBagAttributes);
    }       // END FOR each private key/cert in list.

    bufEncodedBags.Encode(SafeBags);
    snaccEncryptedCI.contentEncryptionAlgorithm.algorithm = pbewithSHAAnd40BitRC2_CBC;
    pbufEncryptedKey = EncryptPKCS12Blob(pszPasswordIN, 
         snaccEncryptedCI.contentEncryptionAlgorithm, bufEncodedBags);
   if (pbufEncryptedKey)
   {
       snaccEncryptedCI.contentType = id_data;
       snaccEncryptedCI.encryptedContent = new AsnOcts;
       snaccEncryptedCI.encryptedContent->Set(pbufEncryptedKey->Access(), pbufEncryptedKey->Length());
       ENCODE_BUF(&snaccEncryptedCI, pEncryptedCert);
   }        // END IF pbufEncryptedKey


   //******************************************************
   // Encode Private Key encodings, if present.  This is necessary to align the
   //  specific Certificate ID with the associated Private Key ID.
    // ENCODE final private key SafeBag.  They are loaded in-sync.
    ENCODE_BUF(&SafeBagsPriv, pencryptedPrivDataBuf);


   


    SME_FINISH
    SME_CATCH_SETUP
    SME_FREE3_CATCH_FINISH

    return pEncryptedCert;
}     // END CSM_Free3::EncryptPKCS12CreateCertSafeBag(...)

//////////////////////////////////////////////////////////////////////////
//
// NOTE::: THIS ROUTINE HAS NOT BEEN TESTED WITH SEVERAL PRIVATE KEYS.  May
//  need minor modifications.
void EncryptPKCS12CreatePrivSafeBag(
    const CSM_Buffer &BufPriv,   // IN, Private Key to be loaded
    const char *pszPasswordIN,   // IN, 
    SafeContents &SafeBags,      // OUT, resulting PrivateKey added to SafeBag.
    Attributes *pSNACCAttributes) // IN, Actual setting for this Private key's
                                  //   matching certificate(s).
{
    CSM_Buffer Buf;
    CSM_Buffer *pBufTmpPriv=NULL;
    AsnOid  oidSafeBag_pkcs8ShroudedKeyBag(OIDSafeBag_pkcs8ShroudedKeyBag);
    SafeBag *pTmpSafeBag;

    SME_SETUP("CSM_Free3::EncryptPKCS12CreatePrivSafeBag");

    if (pszPasswordIN == NULL)
       SME_THROW(SM_MISSING_PARAM, "MISSING PARAMS", NULL);

    EncryptedPrivateKeyInfo snaccEncryptedX;

        snaccEncryptedX.encryptionAlgorithm.algorithm = pbeWithSHAAnd3_KeyTripleDES_CBC;
        AlgorithmIdentifier DecryptAlgId;
        DecryptAlgId.algorithm = snaccEncryptedX.encryptionAlgorithm.algorithm;
        pBufTmpPriv = EncryptPKCS12Blob(pszPasswordIN, DecryptAlgId, BufPriv);
        if (DecryptAlgId.parameters)
        {
           snaccEncryptedX.encryptionAlgorithm.parameters = DecryptAlgId.parameters;
           DecryptAlgId.parameters = NULL; 
                             //CLEAR DO NOT DELETE, since given away
        }
        snaccEncryptedX.encryptedData.Set(pBufTmpPriv->Access(), pBufTmpPriv->Length());
        Buf.Encode(snaccEncryptedX);
        delete pBufTmpPriv;
        pBufTmpPriv = NULL;
        pTmpSafeBag = &(*SafeBags.append());
        pTmpSafeBag->safeBagType = oidSafeBag_pkcs8ShroudedKeyBag;
        Buf.Decode(pTmpSafeBag->safeBagContent);
        if (pSNACCAttributes)
        {
            pTmpSafeBag->safeBagAttributes = new Attributes;
            *pTmpSafeBag->safeBagAttributes = *pSNACCAttributes;
        }       // END IF pSNACCAttributes


    SME_FINISH
    SME_CATCH_SETUP
    SME_FREE3_CATCH_FINISH

}     // END CSM_Free3::EncryptPKCS12CreatePrivSafeBag(...)


//////////////////////////////////////////////////////////////////////////
// RETURNS encrypted Blob.
CSM_Buffer *EncryptPKCS12Blob(const char *pszPasswordIn, 
   AlgorithmIdentifier &EncryptionAlgorithm, const CSM_Buffer &bufClearKey)
{
   CSM_Buffer *pK = NULL;
   CSM_Buffer *pIV = NULL;
   CSM_Buffer *pbufEncodedEncryptionParams=NULL;
   int blocksize = 0;
   AsnOid oidHash;
   int iLength = 20;
   int iPBEKeyBits=SM_FREE_RC2_DEFAULT_PBE_KEYBITS;
   EncryptedContentInfo snaccEncryptedCI;
   char *pszPassword=NULL;
   long lPassword2=(strlen(pszPasswordIn)+1)*2;
   PBEParameter snaccEncryptionParams;
   CSM_Buffer *pbufOut=NULL;
   long lRequestedLength=0;



   RC2Encryption *pRC2encryption=NULL;
   CBCPaddedEncryptor *pcbc_PADencryption=NULL;
#ifndef CRYPTOPP_5_0
   DES_EDE3_Encryption *pencryption=NULL;
   Filter *pcbc_encryption=NULL;
   CBCRawEncryptor *pcbc_NotPaddedEncryption=NULL;;
#else // CRYPTOPP_5_0
   StreamTransformation *pcbc_encryption=NULL;
#endif // CRYPTOPP_5_0

   SME_SETUP("CSM_Free3::EncryptPKCS12Blob");

   if (pszPasswordIn == NULL)
      SME_THROW(SM_MISSING_PARAM, "MISSING PARAMS", NULL);

   pszPassword=(char *)calloc(1, lPassword2);
   for (int iii=0; iii < strlen(pszPasswordIn); iii++)
        pszPassword[iii*2+1] = pszPasswordIn[iii];

   if (EncryptionAlgorithm.algorithm != pbewithSHAAnd40BitRC2_CBC &&
       EncryptionAlgorithm.algorithm != pbeWithSHAAnd3_KeyTripleDES_CBC)
   {
      SME_THROW(33, "EncryptionAlgorithm not supported, ONLY pbewithSHAAnd40BitRC2_CBC.", NULL);
   }


   // Create the SALT for encryption algorithm parameters
   CSM_Buffer bufSalt("        ", 8);
   // create lLength random bytes of data
   #ifndef CRYPTOPP_5_0
   rndRandom2.GetBlock((unsigned char *)bufSalt.Access(), 8);
   #else // CRYPTOPP_5_0
   char *p=(char *)bufSalt.Access();
   for (int ii=0; ii < 8; ii++)
       p[ii] = (char)rndRandom2.GenerateByte();
   #endif // CRYPTOPP_5_0
    //TEST;memcpy(p, "abcdefgh", 8);                      //RWC;TEST

   int nIterCount = 2048;

   if (EncryptionAlgorithm.algorithm == pbewithSHAAnd40BitRC2_CBC ||
       EncryptionAlgorithm.algorithm == pbeWithSHAAnd3_KeyTripleDES_CBC)
   {
       oidHash = sha_1;
       iLength = 20;
       blocksize = SM_COMMON_RC2_BLOCKSIZE;//iPBEKeyBits/8;
       if (EncryptionAlgorithm.algorithm == pbeWithSHAAnd3_KeyTripleDES_CBC)
          lRequestedLength = 24;    // MUST request larger value since SHA-1
                                    //  only provides 20 bytes...
      // generate the key using the salt, the iteration count, and the password
      SME(pK = CSM_Free3::GeneratePKCS12PBEKey(&bufSalt, nIterCount, 0x01, pszPassword, 
               oidHash, iLength, lPassword2, 0x40, lRequestedLength));

      //pK->SetLength(3); // SET only necessary key length.
      SME(pIV = CSM_Free3::GeneratePKCS12PBEKey(&bufSalt, nIterCount, 0x02, pszPassword, 
               oidHash, iLength, lPassword2, 0x40));

       snaccEncryptionParams.iterationCount = nIterCount;
       snaccEncryptionParams.salt.Set(bufSalt.Access(), bufSalt.Length());
       ENCODE_BUF(&snaccEncryptionParams, pbufEncodedEncryptionParams);
       if (EncryptionAlgorithm.parameters == NULL)
           EncryptionAlgorithm.parameters = new AsnAny;
       DECODE_BUF(EncryptionAlgorithm.parameters, pbufEncodedEncryptionParams);
                    // RETURN to application...
       delete pbufEncodedEncryptionParams;
       pbufEncodedEncryptionParams = NULL;
   }
   else
   {
      SME_THROW(22, "EncryptionAlgorithm not recognized!", NULL);
   }

   if (EncryptionAlgorithm.algorithm == pbewithSHAAnd40BitRC2_CBC)
   {
      blocksize = SM_COMMON_RC2_BLOCKSIZE;//iPBEKeyBits/8;
      iPBEKeyBits = 40;
      // create the rc2 cipher 
      pRC2encryption = new RC2Encryption((const unsigned char*)pK->Access(), 
             iPBEKeyBits/8, iPBEKeyBits);
      pcbc_PADencryption=new CBCPaddedEncryptor(*pRC2encryption,  
              (const unsigned char*)pIV->Access());
      pcbc_encryption = pcbc_PADencryption;
   }
   else if (EncryptionAlgorithm.algorithm == pbeWithSHAAnd3_KeyTripleDES_CBC)
   {
      // create the 3DES cipher 
      // BE SURE TO ADJUST THE PARITY!!!!!!
      unsigned char *ptr3=(unsigned char *)calloc(1, pK->Length());
      memcpy(ptr3, pK->Access(), pK->Length());
      for (int iii=0; iii < 24; iii++)
      {
         if (!CryptoPP::Parity((unsigned long)ptr3[iii]))
            ptr3[iii] ^= 0x01;
      }
#ifndef CRYPTOPP_5_0
      DES_EDE3_Encryption encryption((const unsigned char*)pK->Access());
      pcbc_PADencryption=new CBCPaddedEncryptor(encryption,  
          (const unsigned char*)pIV->Access());
      pcbc_encryption = pcbc_PADencryption;
#else // CRYPTOPP_5_0
      CBC_Mode<DES_EDE3>::Encryption *pTmpEncryption = new CBC_Mode<DES_EDE3>::Encryption;
      pTmpEncryption->SetKeyWithIV((const unsigned char*)pK->Access(), 24, 
                    (const unsigned char *)pIV->Access());
      pcbc_encryption = pTmpEncryption;
#endif // CRYPTOPP_5_0
      free(ptr3);
   }        // END IF algorithm check.
   pbufOut = new CSM_Buffer;
   CSM_Free3::RawEncrypt((CSM_Buffer *)&bufClearKey, pbufOut, pcbc_encryption, blocksize);

/*#ifdef _DEBUG
   CSM_Buffer *pResultBack=DecryptPKCS12Blob(pszPasswordIn, EncryptionAlgorithm
         , *pbufOut);
   if (pResultBack && *pResultBack != bufClearKey) //RWC;padding not removed!!!
       std::cout << "BAD NEWS from PKCS12 encryption of Cert!" << std::endl;
#endif*/

   if (pszPassword)
      free(pszPassword);
   if (pK)
      delete pK;
   if (pcbc_encryption)
       delete pcbc_encryption;
   if (pIV && pIV != pK)
       delete pIV;

   SME_FINISH
   SME_CATCH_SETUP
      if (pK)
         delete pK;
      if (pbufEncodedEncryptionParams)
         delete pbufEncodedEncryptionParams;
      if (pIV && pIV != pK)
          delete pIV;
      if (pcbc_encryption)
          delete pcbc_encryption;
      if (pbufOut)
         delete pbufOut;
      if (pszPassword)
         free(pszPassword);
   SME_FREE3_CATCH_FINISH

   return pbufOut;
}       // END CSM_Free3::EncryptPKCS12Blob(...)


_END_CERT_NAMESPACE




// EOF sm_Free3Internal.cpp
