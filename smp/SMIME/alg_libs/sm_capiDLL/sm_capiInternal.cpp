
//
// sm_capiInternal.cpp
/*#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#include <process.h>
#include <winsock2.h>
#elif defined(SUNOS) || defined (SunOS)
#include <unistd.h>
#include <arpa/inet.h>
#elif defined(Linux)
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
//#include <setjmp.h>
#include <sys/stat.h>*/
#include "sm_capi.h"
//#include "sm_cms.h"
//#include "sm_VDASupport_asn.h"
//#include "sm_AppLogin.h"
//#include "sm_CtilCommon.h"
//#include "sm_free3_asn.h"

_BEGIN_CERT_NAMESPACE
using namespace SNACC;
using CTIL::CSM_Buffer;
/*#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif*/

/////////////////////////////////////////////////////////////////////
HCRYPTKEY CSM_Capi::FormatRSAPublicKeyHandleFromCert(CSM_Buffer &BufRsaPublicCert,
        DWORD dSpecKeyOrSignature)    // AT_SIGNATURE or AT_KEYEXCHANGE
{
   HCRYPTKEY hKey=0;
   SME_SETUP("CSM_Capi::FormatRSAPublicKeyHandleFromCert");
   CSM_CertificateChoice AA(BufRsaPublicCert);
   CSM_Buffer *pBuf = AA.GetPublicKey();
   if (pBuf)
      hKey = FormatRSAPublicKeyHandle(*pBuf, dSpecKeyOrSignature);

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(hKey);
}

/////////////////////////////////////////////////////////////////////
HCRYPTKEY CSM_Capi::FormatRSAPublicKeyHandle(CSM_Buffer &BufRsaPublicKey, 
      DWORD dSpecKeyOrSignature)    // AT_SIGNATURE or AT_KEYEXCHANGE
{
   PUBLICKEYSTRUC HeaderPublicKeyStruc;
   RSAPUBKEY HeaderRsaPubKey;
   HCRYPTKEY hKey=0;
   char *pRSAKey=NULL;
   RSAPublicKey	SNACCRSAPublicKey; /*::=  SEQUENCE {
	   modulus			[UNIVERSAL 2] IMPLICIT OCTET STRING,  -- n - originally just INTEGER
	   publicExponent	[UNIVERSAL 2] IMPLICIT OCTET STRING } -- e - originally just INTEGER*/

   SME_SETUP("CSM_Capi::FormatRSAPublicKeyHandle");
   pRSAKey=(char *)calloc(1, sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + BufRsaPublicKey.Length());
     // MUST first ASN.1 decode the RSA Public key: RSAPublicKey from sm_VDASupport_asn.asn.
     //  RSAPublicKey.modulus
     //  RSAPublicKey.publicExponent
     // 1st set of data
   DECODE_BUF(&SNACCRSAPublicKey, &BufRsaPublicKey);
   HeaderPublicKeyStruc.bType = PUBLICKEYBLOB;
   HeaderPublicKeyStruc.bVersion = 0x02;
   HeaderPublicKeyStruc.reserved = 0;
   if (dSpecKeyOrSignature == AT_SIGNATURE)
      HeaderPublicKeyStruc.aiKeyAlg = CALG_RSA_SIGN;
   else if (dSpecKeyOrSignature == AT_KEYEXCHANGE)
      HeaderPublicKeyStruc.aiKeyAlg = CALG_RSA_KEYX;
   else
      HeaderPublicKeyStruc.aiKeyAlg = CALG_RSA_SIGN; // DEFAULT
   //HeaderPublicKeyStruc must be of size 8.
   // 2nd set of data
   HeaderRsaPubKey.magic = 0x31415352; // RSA Public key ID.
   long lLength = SNACCRSAPublicKey.modulus.length();
   const unsigned char *pModulus = SNACCRSAPublicKey.modulus.c_str();
   if ((lLength & 0x0001) && *pModulus == NULL)
   {                 // ODD length, remove leading 0.
      lLength -= 1;
      pModulus++;    // Point past NULL.
   }
   HeaderRsaPubKey.bitlen = lLength * 8;//512;    //Public key bit length.
   if (SNACCRSAPublicKey.publicExponent.length() <= sizeof(HeaderRsaPubKey.pubexp))
   {
       long lA = 0;
       const unsigned char *ptr=SNACCRSAPublicKey.publicExponent.c_str();
       for (long ii3=0; ii3 < SNACCRSAPublicKey.publicExponent.length(); ii3++)
           lA += ((unsigned char)ptr[ii3] << (8*ii3));
       //lA = 0x11000000;
       HeaderRsaPubKey.pubexp = lA;//0x00010001;
   }
   // 3rd set of data is the public key itself.
   // RSA public key modulus MUST be HeaderRsaPubKey.bitlen / 8 byte count.
   memcpy(pRSAKey, &HeaderPublicKeyStruc, sizeof(HeaderPublicKeyStruc));
   memcpy(&pRSAKey[sizeof(HeaderPublicKeyStruc)], &HeaderRsaPubKey, 
      sizeof(HeaderRsaPubKey));
   //RWC;I BELIEVE THIS SHOULD BE REVERSED IN ORDER; after checking 
   //RWC;  CryptExportPublicKeyInfo(...), the byte order is reversed, bits 
   //RWC;  intact.
#ifndef BOB_QUESTIONED
   char *pp2=&pRSAKey[sizeof(HeaderPublicKeyStruc) + sizeof(HeaderRsaPubKey)];
   for (int ii2=0; ii2 < lLength; ii2++)
      pp2[ii2] = pModulus[lLength-ii2-1]; //LOAD in reverse order.
#else
   memcpy(&pRSAKey[sizeof(HeaderPublicKeyStruc) + sizeof(HeaderRsaPubKey)], 
      pModulus, lLength);
#endif
   if (CryptImportKey(this->m_hCryptProv, (BYTE *)pRSAKey, 
      sizeof(HeaderPublicKeyStruc) + sizeof(HeaderRsaPubKey) + 
      lLength, 0, CRYPT_EXPORTABLE, &hKey))
   {
#ifdef _DEBUG
      CSM_Buffer AAA(pRSAKey, sizeof(HeaderPublicKeyStruc) + sizeof(HeaderRsaPubKey) + 
      SNACCRSAPublicKey.modulus.length());
      AAA.ConvertMemoryToFile("./sm_capi/DataOut/RSAPublicKeyHandle.bin");
#endif
      // DANG, it worked!!!
   }
   else
   {
      SME_THROW(GetLastError(), "CryptImportKey failed!", NULL); 
   }
   //CALG_RSA_KEYX


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH


   return(hKey);
}

/////////////////////////////////////////////////////////////////////
CSM_Buffer *CSM_Capi::ExtractRSAPublicKeyFromBlob(CSM_Buffer &BufRsaPublicKeyBlob)
{
   CSM_Buffer *pBuf=NULL;
   PUBLICKEYSTRUC *pHeaderPublicKeyStruc;
   RSAPUBKEY *pHeaderRsaPubKey;
   //HCRYPTKEY hKey=0;
   const char *pRSAKeyPtr=BufRsaPublicKeyBlob.Access();
   RSAPublicKey	SNACCRSAPublicKey; /*::=  SEQUENCE {
	   modulus			[UNIVERSAL 2] IMPLICIT OCTET STRING,  -- n - originally just INTEGER
	   publicExponent	[UNIVERSAL 2] IMPLICIT OCTET STRING } -- e - originally just INTEGER*/

   SME_SETUP("CSM_Capi::ExtractRSAPublicKeyFromBlob");

   if (BufRsaPublicKeyBlob.Length() < sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY))
   {
      SME_THROW(22, "BufRsaPublicKeyBlob length is TOO small!", NULL); 
   }
   pHeaderPublicKeyStruc = (PUBLICKEYSTRUC *)pRSAKeyPtr; // 1st structure.
   if (pHeaderPublicKeyStruc->bType != PUBLICKEYBLOB ||
       pHeaderPublicKeyStruc->bVersion != 0x02 ||
       pHeaderPublicKeyStruc->reserved != 0 ||
      (pHeaderPublicKeyStruc->aiKeyAlg != CALG_RSA_KEYX &&
       pHeaderPublicKeyStruc->aiKeyAlg != CALG_RSA_SIGN))
   {
      SME_THROW(22, "pHeaderPublicKeyStruc items not as expected!", NULL); 
   }
   pHeaderRsaPubKey = (RSAPUBKEY *)&pRSAKeyPtr[sizeof(PUBLICKEYSTRUC)]; 
                                                         // 2nd structure.
   // 2nd set of data
   if (pHeaderRsaPubKey->magic != 0x31415352 || // RSA Public key ID.
       pHeaderRsaPubKey->bitlen/8 > 
         BufRsaPublicKeyBlob.Length()-sizeof(PUBLICKEYSTRUC)-sizeof(RSAPUBKEY))
                              //512;    //Public key bit length.
   {
      SME_THROW(22, "pHeaderRsaPubKey LENGTH > remaining buffer length!", NULL); 
   }
   SNACCRSAPublicKey.publicExponent.Set((const unsigned char *)&pHeaderRsaPubKey->pubexp, 
              sizeof(pHeaderRsaPubKey->pubexp));

   // 3rd set of data is the public key itself.
   // RSA public key modulus MUST be HeaderRsaPubKey.bitlen / 8 byte count.
   SNACCRSAPublicKey.modulus.Set((const unsigned char *)&pRSAKeyPtr[sizeof(PUBLICKEYSTRUC)+sizeof(RSAPUBKEY)], 
            pHeaderRsaPubKey->bitlen/8);

   ENCODE_BUF(&SNACCRSAPublicKey, pBuf);


     //  RSAPublicKey.modulus
     //  RSAPublicKey.publicExponent


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH


   return(pBuf);
}



/////////////////////////////////////////////////////////////////////
// NOT USED YET...
#ifdef NOT_USED_YET
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

long CSM_Capi::CapiSetupCertStore_GetPublicKeyHandle(
   HCERTSTORE  hSystemStore,           // IN,The system store handle.
   HCERTSTORE  &hMemoryStore,          // IN/OUT,A memory store handle.
   char *lpszCertFileToLoad,           // In, cert to be loaded.
   //HANDLE for public key of cert
)
{
   //--------------------------------------------------------------------
   // Declare and initialize variables.

   PCCERT_CONTEXT  pDesiredCert = NULL;   // Set to NULL for the first 
                                          // call to
                                          // CertFindCertificateInStore.
   PCCERT_CONTEXT  pCertContext;
   HANDLE  hStoreFileHandle ;             // Output file handle.
   LPCSTR  pszFileName = "TestStor.sto";  // Output file name.

   //-------------------------------------------------------------------
   // Open a new certificate store in memory.

   if(hMemoryStore = CertOpenStore(
         CERT_STORE_PROV_MEMORY,    // A memory store.
         0,                         // Encoding type. 
                                    // Not used with a memory store.
         NULL,                      // Use the default provider.
         0,                         // No flags.
         NULL))                     // Not needed.
   {
      printf("Opened a memory store. \n");
   }
   else
   {
      HandleError( "Error opening a memory store.");
   }
   //-------------------------------------------------------------------
   // Open the MY system store using CertOpenStore.

   if(hSystemStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM, // The system store will be a 
                                // virtual store.
        0,                      // Encoding type not need with this PROV.
        NULL,                   // Accept the default HCRYPTPROV. 
        CERT_SYSTEM_STORE_CURRENT_USER,
                                // Set the system store location in the
                                // registry.
        L"MY"))                 // Could have used other predefined 
                                // system stores
                                // including Trust, CA, or Root.
   {
      printf("Opened the MY system store. \n");
   }
   else
   {
      HandleError( "Could not open the MY system store.");
   }
   //--------------------------------------------------------------------
   //-------------------------------------------------------------------
   // Get a certificate that has the string "Microsoft" in its subject. 

   if(pDesiredCert=CertFindCertificateInStore(
         hSystemStore,
         MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING.
         0,                           // No dwFlags needed. 
         CERT_FIND_SUBJECT_STR,       // Find a certificate with a
                                      // subject that matches the string
                                      // in the next parameter.
         L"Microsoft",                // The Unicode string to be found
                                      // in a certificate's subject.
         NULL))                       // NULL for the first call to the
                                      // function. In all subsequent
                                      // calls, it is the last pointer
                                      // returned by the function.
   {
     printf("The desired certificate was found. \n");
   }
   else
   {
      HandleError("Could not find the desired certificate.");
   }
   //-------------------------------------------------------------------
   // pDesiredCert is a pointer to a certificate with a subject that 
   // includes the string "Microsoft", the string passed as parameter
   // #5 to the function.

   //------------------------------------------------------------------ 
   //  Create a new certificate from the encoded part of
   //  an available certificate.

   if(pCertContext = CertCreateCertificateContext(
       MY_ENCODING_TYPE  ,            // The encoding type
       pDesiredCert->pbCertEncoded,   // The encoded data from
                                      // the certificate retrieved
       pDesiredCert->cbCertEncoded))  // The length of the encoded data
   {
     printf("A new certificate as been created.\n");
   }
   else
   {
     HandleError("A new certificate could not be created.");
   }

   //--------------------------------------------------------------------
   // Add the certificate from the MY store to the new memory store.

   if(CertAddCertificateContextToStore(
         hMemoryStore,                // The store handle
         pDesiredCert,                // The pointer to a certificate
         CERT_STORE_ADD_USE_EXISTING,
         NULL))
   {
      printf("Certificate added to the memory store. \n");
   }
   else
   {
      HandleError("Could not add the certificate to the memory store.");
   }
   //-------------------------------------------------------------------
   //  Find a different certificate in the MY store and add a link to it
   //  to the memory store.

   //-------------------------------------------------------------------
   // Find the certificate context just added to the memory store.

   if(pDesiredCert=CertFindCertificateInStore(
         hSystemStore,
         MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING.
         0,                           // No dwFlags needed. 
         CERT_FIND_SUBJECT_STR,       // Find a certificate with a
                                      // subject that matches the string
                                      // in the next parameter.
         L"TEST CERTIFICATE",         // The Unicode string to be found
                                      // in a certificate's subject.
         NULL))                       // NULL for the first call to the
                                      // function. In all subsequent
                                      // calls, it is the last pointer
                                      // returned by the function.
   {
     printf("The TEST CERTIFICATE certificate was found. \n");
   }
   else
   {
      HandleError("Could not find the TEST CERTIFICATE certificate.");
   }
   //--------------------------------------------------------------------
   // Add a link to the TEST CERTIFICATE certificate from the MY store to 
   // the new memory store.

   if(CertAddCertificateLinkToStore(
         hMemoryStore,           // The store handle
         pDesiredCert,           // The pointer to a certificate
         CERT_STORE_ADD_USE_EXISTING,
         NULL))
   {
      printf("Certificate link added to the memory store. \n");
   }
   else
   {
      HandleError("Could not add the certificate link to the memory store.");
   }
   //--------------------------------------------------------------------
   // Find the first certificate in the memory store.

   if(pDesiredCert=CertFindCertificateInStore(
         hMemoryStore,
         MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING.
         0,                           // No dwFlags needed. 
         CERT_FIND_SUBJECT_STR,       // Find a certificate with a
                                      // subject that matches the string
                                      // in the next parameter.
         L"Microsoft",                // The Unicode string to be found
                                      // in a certificate's subject.
         NULL))                       // NULL for the first call to the
                                      // function. In all subsequent
                                      // calls, it is the last pointer
                                      // returned by the function.
   {
     printf("The desired certificate was found in the memory store. \n");
   }
   else
   {
      printf("Certificate not in the memory store.\n");
   }
   //--------------------------------------------------------------------
   //  Find the certificate link in the memory store.

   if(pDesiredCert=CertFindCertificateInStore(
         hMemoryStore,
         MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING.
         0,                           // No dwFlags needed. 
         CERT_FIND_SUBJECT_STR,       // Find a certificate with a
                                      // subject that matches the string
                                      // in the next parameter.
         L"TEST CERTIFICATE",         // The Unicode string to be found
                                      // in a certificate's subject.
         NULL))                       // NULL for the first call to the
                                      // function. In all subsequent
                                      // calls, it is the last pointer
                                      // returned by the function.
   {
     printf("The TEST CERTIFICATE certificate link was found in the memory store. \n");
   }
   else
   {
      printf("The certificate link was not in the memory store.\n");
   }
   //-------------------------------------------------------------------
   // Create a file to save the new store and certificate into.

   if(hStoreFileHandle = CreateFile(
         pszFileName,        // File path
         GENERIC_WRITE,      // Access mode
         0,                  // Share mode
         NULL,               // Security 
         CREATE_ALWAYS,      // How to create the file
         FILE_ATTRIBUTE_NORMAL,
                             // File attributes
         NULL))              // Template
   {
      printf("Created a new file on disk. \n");
   }
   else
   {
      HandleError("Could not create a file on disk.");
   }
   //-------------------------------------------------------------------
   // hStoreFileHandle is the output file handle.
   // Save the memory store and its certificate to the output file.

   if( CertSaveStore(
         hMemoryStore,        // Store handle.
         0,                   // Encoding type not needed here.
         CERT_STORE_SAVE_AS_STORE,
         CERT_STORE_SAVE_TO_FILE,
         hStoreFileHandle,    // This is the handle of an open disk file.
         0))                  // dwFlags. No flags needed here.
   {
      printf("Saved the memory store to disk. \n");
   }
   else
   {
      HandleError("Could not save the memory store to disk.");
   }
   //-------------------------------------------------------------------
   // Close the stores and the file. Reopen the file store, and check its
   // contents.

   if(hMemoryStore)
       CertCloseStore(
           hMemoryStore, 
           CERT_CLOSE_STORE_CHECK_FLAG);

   if(hSystemStore)
       CertCloseStore(
           hSystemStore, 
           CERT_CLOSE_STORE_CHECK_FLAG);

   if(hStoreFileHandle)
        CloseHandle(hStoreFileHandle);

   printf("All of the stores and files are closed. \n");

   //-------------------------------------------------------------------
   //  Reopen the file store.

   if(hMemoryStore = CertOpenStore(
          CERT_STORE_PROV_FILENAME,    // The store provider type.
          MY_ENCODING_TYPE,            // If needed, use the usual
                                       // encoding types.
          NULL,                        // Use the default HCRYPTPROV.
          0,                           // Accept the default for all
                                       // dwFlags.
          L"TestStor.sto" ))           // The name of an existing file
                                       // as a Unicode string.
   {
        printf("The file store has been reopened. \n");
   }
   else
   {
       printf("The file store could not be reopened. \n");
   }
   //--------------------------------------------------------------------
   //  Find the certificate link in the reopened file store.

   if(pDesiredCert=CertFindCertificateInStore(
         hMemoryStore,
         MY_ENCODING_TYPE,            // Use X509_ASN_ENCODING.
         0,                           // No dwFlags needed. 
         CERT_FIND_SUBJECT_STR,       // Find a certificate with a
                                      // subject that matches the string
                                      // in the next parameter.
         L"FULL TEST CERT",           // The Unicode string to be found
                                      // in a certificate's subject.
         NULL))                       // NULL for the first call to the
                                      // function. In all subsequent
                                      // calls, it is the last pointer
                                      // returned by the function.
   {
     printf("The certificate link was found in the file store. \n");
   }
   else
   {
      printf("The certificate link was not in the file store.\n");
   }
   //-------------------------------------------------------------------
   // Clean up memory and end.

   if(pDesiredCert)
       CertFreeCertificateContext(pDesiredCert);
   if(hMemoryStore)
       CertCloseStore(
           hMemoryStore, 
           CERT_CLOSE_STORE_CHECK_FLAG);
   if(hSystemStore)
       CertCloseStore(
           hSystemStore, 
           CERT_CLOSE_STORE_CHECK_FLAG);
   if(hStoreFileHandle)
        CloseHandle(hStoreFileHandle);
   printf("All of the stores and files are closed. \n");
   return;
} // End of main

//--------------------------------------------------------------------
//  This example uses the function HandleError, a simple error
//  handling function, to print an error message to the standard error 
//  (stderr) file and exit the program. 
//  For most applications, replace this function with one 
//  that does more extensive error reporting.

/*void HandleError(char *s)
{
    fprintf(stderr,"An error occurred in running the program. \n");
    fprintf(stderr,"%s\n",s);
    fprintf(stderr, "Error number %x.\n", GetLastError());
    fprintf(stderr, "Program terminating. \n");
    exit(1);
} // End of HandleError*/


HCRYPTKEY ExtractRSAPublicKeyFromCertificate(CSM_Buffer &Cert)
{
   //------------------------------------------------------------------ 
   //  Create a new certificate from the encoded part of
   //  an available certificate.
   if(pCertContext = CertCreateCertificateContext(
       (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),
       pDesiredCert->pbCertEncoded,   // The encoded data from
                                      // the certificate retrieved
       pDesiredCert->cbCertEncoded))  // The length of the encoded data
   {
     printf("A new certificate as been created.\n");
   }
}
#endif  //NOT_USED_YET


HCRYPTKEY CSM_Capi::ExtractRSAPublicKeyFromPKI(CSM_Buffer &BufPublicKeyInfo, ALG_ID CAPIAlg)
{
    HCRYPTKEY hKey=0;
    SME_SETUP("CSM_CAPI::ExtractRSAPublicKeyFromPKI");

    /*typedef struct _CERT_PUBLIC_KEY_INFO {
        CRYPT_ALGORITHM_IDENTIFIER  Algorithm;
        CRYPT_BIT_BLOB              PublicKey;
    } CERT_PUBLIC_KEY_INFO
    BOOL WINAPI CryptImportPublicKeyInfoEx(
      HCRYPTPROV hCryptProv,            // in
      DWORD dwCertEncodingType,         // in
      PCERT_PUBLIC_KEY_INFO pInfo,      // in
      ALG_ID aiKeyAlg,                  // in
      DWORD dwFlags,                    // in
      void *pvAuxInfo,                  // in, optional
      HCRYPTKEY *phKey                  // out
    );
    typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
        LPSTR                          pszObjId;
        CRYPT_OBJID_BLOB               Parameters;
    } CRYPT_ALGORITHM_IDENTIFIER
    */
    CRYPT_ALGORITHM_IDENTIFIER msRSAOid;
    CERT_PUBLIC_KEY_INFO msRSAPublicKeyInfo;
    memset(&msRSAOid, '\0', sizeof(msRSAOid));
    memset(&msRSAPublicKeyInfo, '\0', sizeof(msRSAPublicKeyInfo));
    msRSAOid.pszObjId = szOID_RSA_RSA;
    msRSAPublicKeyInfo.Algorithm = msRSAOid;
    msRSAPublicKeyInfo.PublicKey.cbData = BufPublicKeyInfo.Length();
    msRSAPublicKeyInfo.PublicKey.pbData = (unsigned char *)BufPublicKeyInfo.Access();

    if (!CryptImportPublicKeyInfoEx(this->m_hCryptProv, 
      (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING), 
      &msRSAPublicKeyInfo, CAPIAlg/*CALG_RSA_SIGN/*CALG_RSA_KEYX*/,
      0, NULL, &hKey))
    {
        SME_THROW(GetLastError(), "BAD CryptImportPublicKeyInfoEx(...) call.", NULL);
    }

    SME_FINISH
    SME_CATCH_SETUP
    SME_CATCH_FINISH

    return hKey;
}


//
//
//RWC;NOTE:: I HAVE NOT SEEN THIS FUNCTION WORK YET!  According to the 
// CAPI documentation, KP_CERTIFICATE is not used on this call.  It does
// not work with CAPI using the DataKey CSP nor the MS default provider(s).
// (It will be removed later.)
// RWC;5/29/02;NOW FAILS WITH BETA DataKey Drivers;Version: - 4.7.00.007 - 05/16/02
bool CSM_Capi::TryToGetCertificate(bool bSigner, BYTE *&pbCertificate, 
                                   DWORD &dwCertLength)
{
   bool bResult=false;
   HCRYPTKEY hKey2I;
   DWORD CAPIKeyTypeId=AT_SIGNATURE; //AT_KEYEXCHANGE
   DWORD dStatus=0;

   if (bSigner)
   {
      CAPIKeyTypeId = AT_SIGNATURE;
   }
   else
   {
       CAPIKeyTypeId = AT_KEYEXCHANGE;
   }     // END if bSigner

   dwCertLength = 4096;
   if(CryptGetUserKey(this->m_hCryptProv, CAPIKeyTypeId/*AT_SIGNATURE/*AT_KEYEXCHANGE*/, &hKey2I))
   {
      if (CryptGetKeyParam(hKey2I, KP_CERTIFICATE, NULL, &dwCertLength, 0) &&
          dwCertLength > 0)
      {
         pbCertificate = (BYTE *)calloc(1, dwCertLength);
         if (CryptGetKeyParam(hKey2I, KP_CERTIFICATE, pbCertificate, &dwCertLength, 0))
         {
            // WOW!  It actually works!
         }
         else
         {
            dStatus = GetLastError();
            free(pbCertificate);
         }
      }
      else
         dStatus = GetLastError();
      CryptDestroyKey(hKey2I);
   }

   return(bResult);
}

//
//  This routine checks the given context with the internal public key.
//  It also checks for signer consistency if possible (cert keyUsage).
bool CSM_Capi::CompareCertToInternalKey(PCCERT_CONTEXT pCertContext, 
      bool bSigner, HCRYPTKEY *phKey, HCRYPTKEY *phKey2)
{
   bool bResult=false;
   ALG_ID CAPIAlg=CALG_RSA_SIGN;
   BYTE *pbData;
   DWORD dwDataLen=0;
   BYTE *pbData2;       
   DWORD dwDataLen2=0;
   HCRYPTKEY *phKeyI=phKey;
   HCRYPTKEY *phKey2I=phKey2;
   DWORD CAPIKeyTypeId=AT_SIGNATURE; //AT_KEYEXCHANGE

   SME_SETUP("CSM_CAPI::CompareCertToInternalKey");

   if (phKey2I == NULL)
      phKey2I = new HCRYPTKEY;
   if (phKeyI == NULL)
      phKeyI = new HCRYPTKEY;
   // FIRST, check that the certificate has a signer's OID in public key.
   if ((strcmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId,
        id_dsa/*szOID_X957_DSA*/) == 0 ||
        strcmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, 
        szOID_OIWSEC_dsa) == 0) )
   {
      if (!bSigner)
         return bResult; // signer requested, but cert public key alg not signer.
      CAPIAlg = CALG_DSS_SIGN;       // DSA; default is RSA signing.
      CAPIKeyTypeId = AT_SIGNATURE;
   }
   else if (!bSigner)
   {
       CAPIAlg = CALG_RSA_KEYX;
       CAPIKeyTypeId = AT_KEYEXCHANGE;
   }


   // SECOND, access the public key of the specified certificate in a way we can 
   //  compare to the internal key.
    if (!CryptImportPublicKeyInfoEx(this->m_hInternalMSKey, 
      (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING), 
      &pCertContext->pCertInfo->SubjectPublicKeyInfo, 
      CAPIAlg/*CALG_RSA_SIGN/*CALG_RSA_KEYX*/, 0, NULL, phKeyI))
    {
       return(false);    // IGNORE failure here, not ours.
        //SME_THROW(GetLastError(), "BAD CryptImportPublicKeyInfoEx(...) call.", NULL);
    }

    // THIRD, extract the appropriate internal key and the cert key in binary 
    //  format
       CryptExportKey(*phKeyI, NULL, PUBLICKEYBLOB, 0, NULL, &dwDataLen);
       pbData = (BYTE *)calloc(1, dwDataLen);
       if (dwDataLen && 
           CryptExportKey(*phKeyI, NULL, PUBLICKEYBLOB, 0, pbData, &dwDataLen))
       {
          // FOURTH, get appropriate internal key and extract data.
          if(!CryptGetUserKey(this->m_hCryptProv, CAPIKeyTypeId/*AT_SIGNATURE/*AT_KEYEXCHANGE*/, phKey2I))
          {
              #ifdef _DEBUG
              long lError=GetLastError();
              std::cout << "CSM_Capi::CompareCertToInternalKey: error=" <<  lError << "\n";
              #endif  //_DEBUG
#ifdef BOB
            SME_THROW(GetLastError(), "Bad CryptGetUserKey(...) localPublicKey call.", NULL);
#else       // TRY to align private key first, to see if error can be avoided.
            HCRYPTHASH hHash=0;
            CSM_Buffer bufferDigest;
            CSM_Buffer *pTempDigest = &bufferDigest;
            CSM_Buffer Data("string test", strlen("string test"));
            DWORD dwSigLen=0;
            if (SMTI_DigestDataInternal(&Data, pTempDigest, hHash) == 0 &&
                CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen))
            {
                if(!CryptGetUserKey(this->m_hCryptProv, CAPIKeyTypeId/*AT_SIGNATURE/*AT_KEYEXCHANGE*/, phKey2I))
                   return(false);  //SOFT failure for this test(DEBUG).
            }
            else
               return(false);  //SOFT failure for this test(DEBUG).
#endif
          }
          CryptExportKey(*phKey2I, 0, PUBLICKEYBLOB, 0, NULL, &dwDataLen2);
          pbData2 = (BYTE *)calloc(1, dwDataLen2);
          if (dwDataLen2 && 
              CryptExportKey(*phKey2I, 0, PUBLICKEYBLOB, 0, pbData2, &dwDataLen2))
          {
             if (dwDataLen == dwDataLen2 &&
                 memcmp(pbData, pbData2, dwDataLen2) == 0)
             {
#ifdef TO_BE_DELETED
	               // Now lets see if there is a Key Usage
                  LPBYTE pbKU = new unsigned char[ 1 ];
                  ULONG	 cbKU = 1;
	               if ( CertGetIntendedKeyUsage (	X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				               pCertContext->pCertInfo, pbKU, cbKU ) )
	               {
		               if ( bSigner && ( *pbKU & CERT_DIGITAL_SIGNATURE_KEY_USAGE ) )
			               bResult = true;
		               else if ( !bSigner && ( *pbKU & CERT_KEY_ENCIPHERMENT_KEY_USAGE ) )
			               bResult = true;
		               else
                     {
			               bResult = false;
                        return(bResult);  // Inconsistent setting.
                     }
	               } 
                  // else ignore missing entry.
	               delete [] pbKU;
#endif      //TO_BE_DELETED
                if (CheckThisPrivateKeyForSignEncyrpt(CAPIKeyTypeId, bSigner, 
                     pCertContext))
                   bResult = true;
             }
             free(pbData2);
          }
          else
          {
            SME_THROW(GetLastError(), "Bad CryptExportKey(...) 2 Internal key call.", NULL);
          }
          free(pbData);
       }
       else
       {
          long lStatus=GetLastError();
          return(false);   // IGNORE failure here, not our cert
                           // (RWC;May be CA or issuer, etc.).
          //RWC;8/19/02;SME_THROW(lStatus, "Bad CryptExportKey(...) certificate key call.", NULL);
       }
       if (phKey == NULL && phKeyI != NULL)
       {
         CryptDestroyKey(*phKeyI);
         free(phKeyI);
       }
       if (phKey2 == NULL && phKey2I != NULL)
       {
         CryptDestroyKey(*phKey2I);
         free(phKey2I);
       }



    SME_FINISH
    SME_CATCH_SETUP
    SME_CATCH_FINISH

   return bResult;
}

_END_CERT_NAMESPACE


// EOF sm_capiInternal.cpp
