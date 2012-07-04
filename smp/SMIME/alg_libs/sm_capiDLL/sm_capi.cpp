
//////////////////////////////////////////////////////////////////////////
// sm_capi.cpp
//
// This CTI Library implements DSA, 3DES, and RC2, RSA using MS CAPI interface.
//
//  Author:  Robert.Colestock@getronicsgov.com
//  
//
// RWC; DOC NOTES:::
//  ALL SME_THROW exceptions show the GetLastError() code for the corresponding
//    CAPI cryptXXX(...) call.
//  SMTI_Login() must be updated to accommodate various MS CAPI init calls.
//  Due to the frequency of looking up error NUMBERS, not strings, the 
//   following list some common codes:
//      ERROR_INVALID_HANDLE              6L
//      ERROR_INVALID_PARAMETER          87L
//      NTE_BAD_ALGID            0x80090008L
//      ERROR_MORE_DATA                 234L
//            (are all defined in \PROGRAM FILES\MICROSOFT VISUAL STUDIO\VC98\Include\WINERROR.H).        
//
// Last Updated:	16 December 2004                                       
//                Req Ref:  SMP RTM #5  AES Crypto++                                
//                Sue Beauchamp <Sue.Beauchamp@it.baesystems.com>  
//
//////////////////////////////////////////////////////////////////////////

#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
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
#include <sys/stat.h>
#include "sm_capi.h"
#include "sm_cms.h"
#include "sm_VDASupport_asn.h"
#include "sm_AppLogin.h"
#include "sm_Common.h"
#include "sm_free3_asn.h"
#ifdef WIN32
#include <direct.h>      // for getcwd
#else
#include <unistd.h>
#endif

#ifdef _DEBUG
#define DEBUG_PRINT     // COMMENT OUT TO REMOVE PRINTOUTS.
#endif

_BEGIN_CERT_NAMESPACE
using namespace SNACC;

HMODULE CSM_Capi::m_hDataKeyModule; //RWC; MUST BE RE-DECLARED since static.

#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif

#define CERTIFICATE_STORE_NAME L"MY"
#define DATAKEY_PROVIDER_NAME_RSA "Datakey RSA CSP"
#define DATAKEY_PROVIDER_NAME_DSA "Datakey DSA CSP"
#define DataKey_SignerKeyContainerName "Signing Key"
#define DataKey_EncryptKeyContainerName "Private Keys"
#define DataKey_CAKeyContainerName "CA Certificates"
//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_Login(char *lpszCertSubjectName, char *lpszProviderName, bool bSigner)
{
   SME_SETUP("CSM_Capi::SMTI_Login");
   char lpszStoreBuf[100];
   char *pszContainer=NULL;
   LPCTSTR pProviderName=MS_DEF_PROV;
	unsigned long providerType=PROV_RSA_FULL;
   bool bUseThisCert=false;

   lpszStoreBuf[0] = '\0';    // TAKE default
   strcpy(lpszStoreBuf, /*"Signing Key"*/"MY");
   if (m_hInternalMSKey != m_hCryptProv && m_hInternalMSKey != 0)
   {
       CryptReleaseContext(m_hInternalMSKey, 0);
       m_hInternalMSKey = 0;
   }

   if (strcmp(lpszProviderName, "NULL") == 0)
      lpszProviderName = NULL;//RWC;MS_ENHANCED_PROV"; // SET DEFAULT...

   if (strcmp(lpszCertSubjectName, "UseInternalKey") == 0)
      this->m_bUseInternalPublicKey = true;
   else if (strcmp(lpszCertSubjectName, "Signer") == 0)
   {
      bSigner = true;
      this->m_bSigner = bSigner;
   }
   else if (strcmp(lpszCertSubjectName, "Encrypter") == 0)
   {
      bSigner = false;
      this->m_bSigner = bSigner;
   }
   else
      bSigner = this->m_bSigner;    // Specified by the user.
   // else ignore and use specified lpszCertSubjectName as specified (RWC;TBD).
   if (lpszProviderName && strcmp(lpszProviderName, "NULL") != 0)
   {
       if (strncmp(lpszProviderName, "DATAKEY", 7) == 0) // ANY DataKey Provider
       {
           OPTIONAL_DataKey_CertificateLoads(); // ATTEMPT to load certs.
           if(!CryptAcquireContext(&m_hInternalMSKey, NULL, MS_ENHANCED_PROV, 
                providerType, 0)) // RWC; GET Extra context for odd ops.
           {
              if(!CryptAcquireContext(&m_hInternalMSKey, NULL, MS_ENHANCED_PROV, 
                 providerType, CRYPT_NEWKEYSET)) 
              {
                 SME_THROW(GetLastError(), "Error during CryptAcquireContext!", NULL);
              } // END IF !CryptAcquireContext(...)
           }   // END IF CryptAcquireContext
       }       // END IF DataKey provider.

       if (strcmp(lpszProviderName, "DATAKEY_DSA") == 0)
       {
           pProviderName = DATAKEY_PROVIDER_NAME_DSA;
           providerType = PROV_DSS;
           if (bSigner)
              pszContainer = DataKey_SignerKeyContainerName;
           else
              pszContainer = DataKey_EncryptKeyContainerName;
           AsnOid DSA(id_dsa);
           SetDefaultOIDs(&DSA);
       }
       else if (strcmp(lpszProviderName, "DATAKEY_RSA") == 0 ||
                strcmp(lpszProviderName, "DATAKEY") == 0)
       {
           pProviderName = DATAKEY_PROVIDER_NAME_RSA;
           if (bSigner)
              pszContainer = DataKey_SignerKeyContainerName;
           else
              pszContainer = DataKey_EncryptKeyContainerName;
           AsnOid RSA(rsa);
           SetDefaultOIDs(&RSA);
       }
       else if (strcmp(lpszProviderName, "MS_ENHANCED_PROV") == 0)
       {
           pProviderName = MS_ENHANCED_PROV;
           AsnOid RSA(rsa);
           SetDefaultOIDs(&RSA);
       }
       else if (strcmp(lpszProviderName, "MS_DEF_DSS_PROV") == 0)
       {
           pProviderName = MS_DEF_DSS_PROV;
           providerType = PROV_DSS;
           AsnOid DSA(id_dsa);
           SetDefaultOIDs(&DSA);
       }
       else if (strlen(pProviderName))
           pProviderName = lpszProviderName;
       else
       {
           pProviderName = MS_ENHANCED_PROV;
           AsnOid RSA(rsa);
           SetDefaultOIDs(&RSA);
       }
   }
   else
        pProviderName = NULL;
   if (lpszProviderName)
     m_pszProviderName = strdup(lpszProviderName);


   if (m_hCryptProv != 0)
   {
       CryptReleaseContext(m_hCryptProv, 0);
       m_hCryptProv = 0;
   }
   // Get handle to the default provider. 
   if(!CryptAcquireContext(
         &m_hCryptProv, 
         pszContainer/*NULL*/, 
         pProviderName/*MS_ENHANCED_PROV*//*NULL*/, 
         providerType, 
         0))
   {
      if ((strstr(pProviderName, "Datakey") != NULL) ||   
          (strstr(pProviderName, "DATAKEY") != NULL))
                                          // ONLY re-try for non-DataKey
      {
        /*if (!CryptAcquireContext(
         &m_hCryptProv, 
         NULL, //"ce96308090670dc4b65219250dd8d7b1cd49e9cb",//AA,//"0731effba2ff63dc89dd3c42e1e1cd19775f90fb", 
         pProviderName, 
         providerType, 
         0))               //Access default container, if present for DataKey.*/
        {
           SME_THROW(GetLastError(), "Error during CryptAcquireContext (DataKey)!", NULL); 
        }
      }
      else
      {
        if (!CryptAcquireContext(
         &m_hCryptProv, 
         pszContainer/*NULL*/, 
         pProviderName/*MS_ENHANCED_PROV*//*NULL*/, 
         providerType, 
         CRYPT_NEWKEYSET))    // ATTEMPT to generate a default container.
        {
           SME_THROW(GetLastError(), "Error during CryptAcquireContext!", NULL); 
        }
      }     // END IF DataKey, last attempt.
   }        // END IF CryptAcquireContext(...)
#ifdef DEBUG_PRINT
   {  unsigned long dwUserNameLen=1000;
      BYTE *szUserName=(BYTE *)calloc(1, 1000);
      bool bMore=true;
      std::cout << "####CryptGetProvParam: PP_ENUMCONTAINERS Listed:\n";
      while (bMore)
      {
         dwUserNameLen=1000;
         if(CryptGetProvParam(m_hCryptProv, PP_ENUMCONTAINERS, (BYTE *)szUserName,
            &dwUserNameLen, 0))  
         {
            std::cout << "####CryptGetProvParam: PP_ENUMCONTAINERS name=" << szUserName << "\n";
         }
         else
         {
            long lstatus2=GetLastError();
            bMore = false;
         }
      }     // END WHILE bMore
   }
   std::cout.flush();
#endif // DEBUG_PRINT
   if (m_hInternalMSKey == 0)    // THEN assign this entry.
      m_hInternalMSKey = m_hCryptProv;

      LPTSTR pszNameString;
      ULONG cbName;
	   if((m_hStoreHandle = CertOpenSystemStore(m_hCryptProv, lpszStoreBuf/*"MY"*/)) == 0)
	   {
		   SME_THROW(GetLastError(), "Error getting store handle.", NULL);
	   }
      PCCERT_CONTEXT pTMPSignerCertContext=NULL;
      m_pSignerCertContext = NULL;
      if ((strcmp(lpszCertSubjectName, "UseInternalKey") == 0) ||
          (strcmp(lpszCertSubjectName, "Signer") == 0) ||
          (strcmp(lpszCertSubjectName, "Encrypter") == 0) ||
          (strcmp(lpszCertSubjectName, "NULL") == 0))
      {
         BYTE *pbCertificate=NULL;
         DWORD dwCertLength=0;
         //RWC;5/29/02;NOW FAILS WITH BETA DataKey Drivers;Version: - 4.7.00.007 - 05/16/02
         //RWC;/5/29/02;8/19/02;bUseThisCert = TryToGetCertificate(bSigner, pbCertificate, dwCertLength);
         if (bUseThisCert)
         {
            m_pSignerCertContext = CertCreateCertificateContext(X509_ASN_ENCODING,
               pbCertificate, dwCertLength);
            bUseThisCert = true; // FLAG that already determinted which cert to use.
            if (pbCertificate)
               free(pbCertificate);
         }
      }       // IF public key
      if (!bUseThisCert)  // ONLY search if necessary.
      {
        do {
         pTMPSignerCertContext = CertEnumCertificatesInStore(m_hStoreHandle, pTMPSignerCertContext);
         /*pTMPSignerCertContext = CertFindCertificateInStore(
          m_hStoreHandle, PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
          0, CERT_FIND_ANY, NULL, pTMPSignerCertContext);*/
         if (pTMPSignerCertContext && 
             lpszCertSubjectName && strcmp(lpszCertSubjectName, "NULL") != 0)
         {        // ONLY check for public key in cert if private key expected
            //CertGetNameString(m_pSignerCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            //   0, NULL, pszNameString, 100);
             cbName = CertNameToStr(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
               &(pTMPSignerCertContext->pCertInfo->Subject), CERT_SIMPLE_NAME_STR, 
               NULL, 0);
             if (0 == cbName || !(pszNameString = (char *)malloc(cbName)))
             {
	            SME_THROW(GetLastError(), "Getting length of name OR memory allocation failed.", NULL);
             }
             CertNameToStr(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
               &(pTMPSignerCertContext->pCertInfo->Subject), CERT_SIMPLE_NAME_STR, 
               pszNameString, cbName);
             #ifdef DEBUG_PRINT
             std::cout << "CertGetNameString: CERT_NAME_SIMPLE_DISPLAY_TYPE name=" << pszNameString << "\n";
             #endif //_DEBUG
             if (m_pSignerCertContext == NULL && 
                (strcmp(lpszCertSubjectName, "UseInternalKey") == 0 ||
                 strcmp(lpszCertSubjectName, "Signer") == 0 ||
                 strcmp(lpszCertSubjectName, "Encrypter") == 0) &&
                 CompareCertToInternalKey(pTMPSignerCertContext, bSigner))
             {
                 bUseThisCert = true;
             }
             else       // check for specific DN OR partial RDN string 
               if (strcmp(lpszCertSubjectName, "UseInternalKey") != 0 &&
                   strcmp(lpszCertSubjectName, "Signer") != 0 &&
                   strcmp(lpszCertSubjectName, "Encrypter") != 0 &&
                   strcmp(lpszCertSubjectName, "NULL") != 0)
             {
                if (strchr(lpszCertSubjectName, '=') != 0)      // THIS must be a full DN.
                {
                   char *lpszConvertedSubjectName=ConvertDNStringToCapiInternal(lpszCertSubjectName);
                   if (lpszConvertedSubjectName != NULL)
                   {
                      if (strcmp(lpszConvertedSubjectName, pszNameString) == 0)
                         bUseThisCert = true;
                      free(lpszConvertedSubjectName);
                   }
                }       // END if '=' DN check
                else
                {
                   if (strstr(pszNameString, lpszCertSubjectName) != NULL)  // THIS is our cert...
                      bUseThisCert = true;
                }       // END if '=' DN check

                if (bUseThisCert)
                {
                   //RWC2;#ifndef SM_VDA_NOT_WIN2K
                   DWORD dwKeySpec;
                   if (bSigner)  dwKeySpec=AT_SIGNATURE;
                   else          dwKeySpec=AT_KEYEXCHANGE;
                   HCRYPTPROV hTmpCryptProv;
                   HINSTANCE TmpInstance = GetModuleHandle("CRYPT32.DLL");//LoadLibrary("CRYPT32.DLL");
                   if (TmpInstance != NULL)
                   {
                       CryptAcquireCertificatePrivateKey_DEF pCryptAcquireCertificatePrivateKey = 
                          (CryptAcquireCertificatePrivateKey_DEF)GetProcAddress(
                                  TmpInstance, "CryptAcquireCertificatePrivateKey");

                       BOOL bfCallerFreeProv;
                       if (pCryptAcquireCertificatePrivateKey &&
                         !(pCryptAcquireCertificatePrivateKey)(pTMPSignerCertContext, 
                            CRYPT_ACQUIRE_COMPARE_KEY_FLAG,    // WE SEEK this exact entry,
                                                       //  not just the DN 
                                                       // (careful, we are not yet checking
                                                       //  KeyUsage here, so maybe encrypt).
                          NULL, &hTmpCryptProv, &dwKeySpec, &bfCallerFreeProv))
                       {       // ONLY if it failed above, we will attemp to 
                               //  reverse signer/encrypter.
                          if (GetLastError() == NTE_BAD_PUBLIC_KEY)
                          {
                             bUseThisCert = false;     // CONTINUE LOOKING.
                          }
                          else
                          {
                             SME_THROW(GetLastError(), "Bad CryptAcquireCertificatePrivateKey(...) call.", NULL);
                          }    //END IF NTE_BAD_PUBLIC_KEY.
                       }    // END if CryptAcquireCertificatePrivateKey(...)
                       if (bUseThisCert && 
                          !CheckThisPrivateKeyForSignEncyrpt(dwKeySpec, bSigner, pTMPSignerCertContext))
                       {       //THEN this is not our particular certificate; check again...
                          bUseThisCert = false;     // CONTINUE LOOKING.
                       }
                       else    // dwKeySpec != AT_SIGNATURE
                       {
                          if (m_hCryptProv != 0)
                              CryptReleaseContext(m_hCryptProv, 0);
                          m_hCryptProv = hTmpCryptProv;   // REPLACE original, regardless of CSP.
                       }    // IF dwKeySpec != AT_SIGNATURE
                       /*RWC2;#else //SM_VDA_NOT_WIN2K
                       char buf[1024];
                       sprintf(buf, "CAPI:  CryptAcquireCertificatePrivateKey(...) not available, CANNOT USE THIS LOGIN FEATURE FOR |%s|.", 
                               lpszCertSubjectName);
                       SME_THROW(24, buf, NULL);
                       #endif //SM_VDA_NOT_WIN2K *RWC2;*/
                   }    // tmp dynamic load of crypt32.dll.
                   else
                   {
                        bUseThisCert = false;     // CONTINUE LOOKING.
                   }    // END tmp dynamic load of crypt32.dll.
                }       // END bUseThisCert
             }          // END if COMPARE public key OR DN OR RDN string.
             //
             if (bUseThisCert)
             {       // CHECK that requested Cert name is NULL OR   
                     // CHECK that public key of this cert matches internal key.
                     // (RWC;OBSOLETE)CHECK that requested ID is in this cert name
                 m_pSignerCertContext = pTMPSignerCertContext; // ONLY 1st.
                 if (strcmp(m_pSignerCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, 
                    szOID_RSA_RSA) == 0) 
                 {
                    AsnOid RSA(rsa);
                    SetDefaultOIDs(&RSA);    // over-ride constructed setting.
                 }
                 else if (strcmp(m_pSignerCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, 
                    id_dsa/*szOID_X957_DSA*/) == 0 ||
                    strcmp(m_pSignerCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, 
                    szOID_OIWSEC_dsa) == 0)
                 {
                    AsnOid DSA(id_dsa);
                    SetDefaultOIDs(&DSA);    // over-ride constructed setting.
                    // RWC; ALSO remember params to be returned to application.
                    if (m_pSignerCertContext->pCertInfo->SubjectPublicKeyInfo.
                        Algorithm.Parameters.cbData)
                    {
                       //X509_DSS_PARAMETERS;
                    }
                 }   // if RSA/DSA algids.
                #ifdef BOB5
                if (bInTestDirectory())
                {
                   CSM_Buffer AAA((const char *)pTMPSignerCertContext->pbCertEncoded, 
                                  pTMPSignerCertContext->cbCertEncoded);
                   char pszBuf[1024];
                   sprintf(pszBuf, "./sm_capi/DataOut/StoredCert%s.cer", 
                      lpszCertSubjectName);
                   AAA.ConvertMemoryToFile(pszBuf);
                   sprintf(pszBuf, "./sm_capi/DataOut/StoredCertPubKey%s.cer", 
                      lpszCertSubjectName);
                   CSM_Buffer ABB((const char *)(((*(pTMPSignerCertContext->pCertInfo)).SubjectPublicKeyInfo).PublicKey).pbData, 
                      (((*(pTMPSignerCertContext->pCertInfo)).SubjectPublicKeyInfo).PublicKey).cbData);
                   ABB.ConvertMemoryToFile(pszBuf);
                }
                #endif //BOB5

                    // Load into CTIL's memory for app access.
                if (m_pCertPath == NULL)
                   m_pCertPath = new CSM_MsgCertCrls;
                CSM_Buffer Buf33((const char *)
                   pTMPSignerCertContext->pbCertEncoded, 
                   pTMPSignerCertContext->cbCertEncoded);
                CSM_CertificateChoice *pCert=new CSM_CertificateChoice(Buf33);
                m_pCertPath->AddCert(pCert); // ADD cert to login.
                                             //  (DO NOT DELETE)
             }     // END bUseThisCert
             //
            if (lpszCertSubjectName && strcmp(lpszCertSubjectName, "DELETE") == 0)
               if (!CertDeleteCertificateFromStore(pTMPSignerCertContext))
               {
                  SME_THROW(GetLastError(), "Bad CertDeleteCertificateFromStore(...) call.", NULL);
               }
            if (pszNameString)
               free(pszNameString);
            pszNameString = NULL;
         }     // END if pTMPSignerCertContext && lpszCertSubjectName 
        } while (pTMPSignerCertContext && m_pSignerCertContext == NULL);

        /*#ifdef _DEBUG
         BYTE *pbCertificate=NULL;
         DWORD dwCertLength=0;
         bUseThisCert = TryToGetCertificate(bSigner, pbCertificate, dwCertLength);
        #endif*/
      }      // END if cert already present.
             // MUST stop early to avoid over-writing the valid m_pSignerCertContext

      // NOW, once all initialization is completed, check to see that we have found
      //  a certificate (or we are using internal settings).
      if (m_pSignerCertContext == NULL &&
          strcmp(lpszCertSubjectName, "UseInternalKey") != 0 &&
          strcmp(lpszCertSubjectName, "NULL") != 0 &&
         (strncmp("DATAKEY", lpszProviderName, 7) == 0 || //DataKey Signer/Encrypter 
         (strncmp("DATAKEY", lpszProviderName, 7) != 0 && //  MUST HAVE CERT.
          strcmp(lpszCertSubjectName, "Signer") != 0 &&
          strcmp(lpszCertSubjectName, "Encrypter") != 0 )))
      {
          char pbuf[1024];
          sprintf(pbuf, "CAPI:: No Certificate found, login fails for |%s|.", 
                  lpszCertSubjectName);
          SME_THROW(24, pbuf, NULL);
      }
#ifdef DEBUG_PRINT
   unsigned long dwUserNameLen=1000;
   BYTE *szUserName=(BYTE *)calloc(1, 1000);
   if(CryptGetProvParam(
    m_hCryptProv,               // Handle to the CSP
    PP_CONTAINER,             // Get the key container name 
    (BYTE *)szUserName,       // Pointer to the key container name
    &dwUserNameLen,           // Length of name, preset to 100
    0))  
   {
      std::cout << "CryptGetProvParam: PP_CONTAINER name=" << szUserName << "\n";
   }
   dwUserNameLen=1000;
   if(CryptGetProvParam(
    m_hCryptProv,               // Handle to the CSP
    PP_VERSION,                 // Get the version 
    (BYTE *)szUserName,       // Pointer to the key container name
    &dwUserNameLen,           // Length of name, preset to 100
    0))  
   {
      std::cout << "CryptGetProvParam: PP_VERSION name=";
      if (*(WORD *)szUserName == 0x0200)
         std::cout << "VERSION 2.0  ";
      std::cout << "(VERSION = " << *(WORD *)szUserName << ")\n";
   }
   free(szUserName);
#endif

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
bool CSM_Capi::CheckThisPrivateKeyForSignEncyrpt(DWORD dwKeySpec, bool bSigner,
                                                 PCCERT_CONTEXT pCertContext)
{
   bool bResult=false;

   // FIRST, check the certificate keyUsage (overrides dsKeySpec, since 
   //  unreliable from CAPI).
   LPBYTE pbKU = new unsigned char[ 1 ];
   ULONG	 cbKU = 1;
	if ( CertGetIntendedKeyUsage (	X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				pCertContext->pCertInfo, pbKU, cbKU ) )
	{
		if ( bSigner && ( *pbKU & CERT_DIGITAL_SIGNATURE_KEY_USAGE ) )
			bResult = true;
		else if ( !bSigner && 
         (( *pbKU & CERT_KEY_ENCIPHERMENT_KEY_USAGE ) ||
          ( *pbKU & CERT_DATA_ENCIPHERMENT_KEY_USAGE ) ))
			bResult = true;
		else
      {
         delete [] pbKU;
			bResult = false;
         return(bResult);  // Inconsistent setting.
      }
      delete [] pbKU;
	} 
   else        // HANDLE missing entry any way user wants.
   {
      delete [] pbKU;
      if (strcmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, 
         szOID_RSA_RSA) == 0)
         bResult = true;      // REGARDLESS of bSigner flag, both valid.
      else if (strcmp(pCertContext->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, 
         id_dsa /*szOID_X957_DSA*/) == 0 && bSigner)
         bResult = true;      // ONLY if bSigner
      return(bResult);     // ALWAYS good in this case.
   }

   // ALLOW keyUsage result to override this check, if decided.
   if (!bResult && (    // usually only if keyUsage not defined.
      (dwKeySpec == AT_SIGNATURE && bSigner) ||
      (dwKeySpec == AT_KEYEXCHANGE && !bSigner)))
   {
      bResult = true;      //Valid settings.
   }     // END consistency check.  

   return(bResult);
}     // END CheckThisPrivateKeyForSignEncyrpt(...)



//////////////////////////////////////////////////////////////////////////
// It is up to the calling routine to free this memory.
char *CSM_Capi::ConvertDNStringToCapiInternal(const char *lpszSFLDNStringInput)
{
   char *lpszResult=NULL;
   char *ptr, *ptr3;
   char *ptrResult;
   char *lpszSFLDNString=strdup(lpszSFLDNStringInput);   // create working copy

   if (strchr(lpszSFLDNString, '=') == NULL)
      return lpszResult;         // NOT in a format to be processed.

   // We must turn the string around (i.e. C=US comes first) and remove
   //  the C= or OID= component.
   lpszResult = (char *)calloc(1, strlen(lpszSFLDNString)+1);     // ALLOCATE plenty of memory.
   ptrResult = lpszResult;
   do 
   {
      if ((ptr = strrchr(lpszSFLDNString, ',')) != NULL)
      {
         if ((ptr3 = strchr(ptr, '=')) != NULL)
         {
            ptr3++;
            strcat(lpszResult, ptr3);   // GET last RDN data only.
            strcat(lpszResult, ", ");
         }           // END if '='
         *ptr = '\0';   // destructive, TERMINATE string at last ','
      }
      else        // MUST be beginning of string
      {
         if ((ptr3 = strchr(lpszSFLDNString, '=')) != NULL)
         {
            ptr3++;
            strcat(lpszResult, ptr3);   // GET last RDN data only.
            break;            //FINISHED...
         }           // END if '='
      }              // END if ','
   }  while (ptr3 != NULL);

   free(lpszSFLDNString);
   return lpszResult;
}     // END CSM_Capi::ConvertDNStringToCapiInternal(...)

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_Sign(
            CSM_Buffer *pData, // input, data to be signed
            CSM_Buffer *pEncryptedDigest, // signature output
            CSM_Buffer *pDigest) // digest
{
   AsnOid             *pSigOID=NULL;
   AsnOid             *pDigOID=NULL;
   CSM_Buffer          bufferDigest;
   CSM_Buffer          *pTempDigest = &bufferDigest;
   CSM_Buffer          tmpEncryptedDigest;
   DigestInfo          rsaDigestInfo;
   CSM_Buffer          *pTempBuf = NULL;
   pSigOID=GetPrefDigestEncryption();
   pDigOID=GetPrefDigest();
   DWORD dwSigLen=0;
   BYTE *pbSignature;
   HCRYPTHASH hHash=0;
   long status = -1;

   SME_SETUP("CSM_Capi::SMTI_Sign");

   m_ThreadLock.threadLock();
#ifdef TEST_OTHER_EXCEPTION
char *ptr55=NULL; char cA=*ptr55;
#endif   // TEST_OTHER_EXCEPTION
   if ((pData == NULL) || (pEncryptedDigest == NULL))
   {
      SME_THROW(SM_MISSING_PARAM, "NULL PARAMETERS", NULL)
   }
   if (!((*pSigOID == rsa && *pDigOID == sha_1) ||
         (*pSigOID == rsa && *pDigOID == md5) ||
         (*pSigOID == rsa && *pDigOID == id_md2) ||
            *pSigOID == rsaEncryption ||
            *pSigOID == sha_1WithRSAEncryption ||
            *pSigOID == sha_1WithRSAEncryption_ALT ||
            *pSigOID == md5WithRSAEncryption ||
            *pSigOID == AsnOid("1.2.840.113549.1.2") ||
            *pSigOID == id_dsa   ||  
            *pSigOID == id_OIW_secsig_algorithm_dsa ||
            *pSigOID == id_dsa_with_sha1 ))
   {
      SME_THROW(22, "SigAlg NOT SUPPORTED IN CAPI CTIL.\n", NULL);
   }

   // if pDigest was passed in, use it, otherwise, use local temp
   if (pDigest != NULL && pDigest->Length())
   {
#ifdef RWC_TBD_SETUP_INCOMMING_HASH
      pTempDigest = pDigest;
#else  //RWC_TBD_SETUP_INCOMMING_HASH
       //RWC;IGNORE;SME_THROW(22, "CSM_Capi::SMTI_SIGN: incomming digest not supported!", NULL);
#endif //RWC_TBD_SETUP_INCOMMING_HASH
   }

   // digest the incoming data
   if (pTempDigest == NULL || !pTempDigest->Length())
   {
        SME(status = SMTI_DigestDataInternal(pData, pTempDigest, hHash)); 
   }


   //--------------------------------------------------------------------
   // Determine the size of the signature and allocate memory.
   if (hHash)
   { 
      DWORD dwKeySpec=AT_SIGNATURE;
      if (!CryptSignHash(hHash, dwKeySpec, NULL, 0, NULL, &dwSigLen))
      {
         dwKeySpec = AT_KEYEXCHANGE;
         if (!CryptSignHash(hHash, dwKeySpec, NULL, 0, NULL, &dwSigLen))
         {
            SME_THROW(GetLastError(), "CryptSignHash failed (length, AT_KEYEXCHANGE)", NULL);
         }
      }
      //--------------------------------------------------------------------
      // Allocate memory for the signature buffer.
      pbSignature = (BYTE *)calloc(1, dwSigLen);
      //--------------------------------------------------------------------
      // Sign the hash object.
      if(dwSigLen && pbSignature)
      {
         if (CryptSignHash(
              hHash, dwKeySpec, NULL, 0, pbSignature, &dwSigLen)) 
         {
            BYTE *pbSignatureIN=(BYTE *)calloc(1, dwSigLen);
            if ((*pSigOID ==  id_dsa_with_sha1 ||
                 *pSigOID ==  id_dsa) && dwSigLen == 40)
            {
               //TRY reversing r, then reversing s (only 1/2).
               for (int ii3=0; ii3 < dwSigLen/2; ii3++)
               {
                          pbSignatureIN[ii3] = pbSignature[dwSigLen/2-ii3-1];
                          pbSignatureIN[dwSigLen/2+ii3] = pbSignature[dwSigLen-ii3-1];
               }     // END for reversing.
               //RWC;TBD;INTEGRATION TESTING FAILS on DSA at this time (2/21/02)
               //RWC:  SUSPECT we need to prep public key better or params????
               //RWC;  NOT SURE SIGNATURE RESULT NEEDS TO BE REVERSED!!!!
               AsnInt bufR;
               AsnInt bufS;
               bufR.Set(pbSignatureIN, dwSigLen/2, true);
               bufS.Set(&pbSignatureIN[dwSigLen/2], dwSigLen/2, true);
               Dss_Sig_Value SNACCDSA_r_s;   // in sm_free3_asn.asn
               SNACCDSA_r_s.r = bufR;
               SNACCDSA_r_s.s = bufS;
               ENCODE_BUF_NO_ALLOC(&SNACCDSA_r_s, pEncryptedDigest);
            }
            else     // IF DSA && short length
            {
               for (int ii3=0; ii3 < dwSigLen; ii3++)
                          pbSignatureIN[ii3] = pbSignature[dwSigLen-ii3-1];
               pEncryptedDigest->Set((const char *)pbSignatureIN, dwSigLen);
            }     // END IF DSA && short length
            free(pbSignatureIN);
            status = 0;
         }
         else
         {
            SME_THROW(GetLastError(), "CryptSignHash failed", NULL);
         }
         free(pbSignature);
      }  // END length and sig buffer.
   }     // END if hHash


   if (pSigOID)
      delete pSigOID;
   if (pDigOID)
       delete pDigOID;
   if (hHash) 
     CryptDestroyHash(hHash);



   SME_FINISH
   SME_CATCH_SETUP
      if (pSigOID)
         delete pSigOID;
      if (pDigOID)
         delete pDigOID;
      if (hHash) 
        CryptDestroyHash(hHash);
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH2
      if (pSigOID)
         delete pSigOID;
      if (pDigOID)
         delete pDigOID;
      if (hHash) 
        CryptDestroyHash(hHash);
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH_END

   m_ThreadLock.threadUnlock();

   return status;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_Verify(
            CSM_Buffer *pSignerKey, // input
            CSM_AlgVDA *pDigestAlg, // input
            CSM_AlgVDA *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   AsnOid *palgoid=NULL;

   SME_SETUP("CSM_Capi::SMTI_Verify");

   m_ThreadLock.threadLock();
   if ((pData == NULL) || (pSignerKey == NULL) || (pSignature == NULL) ||
         (pSignatureAlg == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   palgoid = pSignatureAlg->GetId();

   // determine rsa or dsa and call appropriate verify routine
   if (palgoid && (*palgoid == sha_1WithRSAEncryption     || 
       *palgoid == rsa ||
       *palgoid == sha_1WithRSAEncryption_ALT || 
       *palgoid == AsnOid("1.2.840.113549.1.2") ||
       *palgoid == rsaEncryption ||
       *palgoid == md2WithRSAEncryption ||
       *palgoid == md5WithRSAEncryption))
   {
      lRet = SMTI_VerifyRSA(pSignerKey, (CSM_Alg *)pDigestAlg, (CSM_Alg *)pSignatureAlg, pData, pSignature);
   }
   else     // Try the CSM_Common supported classes.
   {
       lRet = CSM_Common::SMTI_Verify(pSignerKey, pDigestAlg, 
           pSignatureAlg, pData, pSignature);
       if (lRet != 0)
       {
          SME_THROW(lRet, "Signature Verification Failed!", NULL);
       }
   }

   if (palgoid)
       delete palgoid;
   if (lRet != 0)
   {
       SME_THROW(lRet, "CSM_Capi CTIL SMTI_Verify failed.", NULL);
   }


   SME_FINISH
   SME_CATCH_SETUP
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH2
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH_END

   m_ThreadLock.threadUnlock();
   return lRet;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_VerifyRSA(
            CSM_Buffer *pSignerKey, // input
            CSM_Alg    *pDigestAlg, // input
            CSM_Alg    *pSignatureAlg, // input
            CSM_Buffer *pData, // input
            CSM_Buffer *pSignature) // input
{
   CSM_Buffer          bufferDigest;
   SM_RET_VAL          lRet = -1;      //DEFAULT signature verify failure.
   AsnOid              *palgoid=NULL;
   AsnOid              *pdigoid=NULL;
   DigestInfo          rsaDigestInfo;
   CSM_Buffer          *pTempBuf = NULL;
   HCRYPTHASH          hHash=0;
   HCRYPTKEY           hRsaKey=0;


   SME_SETUP("CSM_Capi::SMTI_VerifyRSA");

   // get the alg oid
   palgoid = pSignatureAlg->GetId();
   if (pDigestAlg)
      pdigoid = pDigestAlg->GetId();
   else
       pdigoid = new AsnOid(*palgoid);
   if (*pdigoid == md5WithRSAEncryption)    // IDIOTS creating certs.
       *pdigoid = md5;

   // Set the preferred digest
   BTISetPreferredCSInstAlgs(pdigoid, NULL, NULL, NULL);

   // digest incoming data
   SME(SMTI_DigestDataInternal(pData, &bufferDigest, hHash));

   // determine rsa algorithm
   if (*palgoid == sha_1WithRSAEncryption || 
       *palgoid == sha_1WithRSAEncryption_ALT || 
      ((*palgoid == rsaEncryption ||
        *palgoid == rsa ||
        *palgoid == AsnOid("1.2.840.113549.1.2")) && *pdigoid == sha_1) )
   {
      // prepare the DigestInfo object with null parameters 
      rsaDigestInfo.digestAlgorithm.algorithm = sha_1;
      CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm);
      rsaDigestInfo.digest.Set(bufferDigest.Access(), bufferDigest.Length());
      ENCODE_BUF(&rsaDigestInfo,pTempBuf);

   }
   else if (*palgoid == md5WithRSAEncryption ||
      ((*palgoid == rsaEncryption ||
        *palgoid == rsa ||
        *palgoid == AsnOid("1.2.840.113549.1.2")) && *pdigoid == md5))
   {
      // prepare the DigestInfo object with null parameters
      rsaDigestInfo.digestAlgorithm.algorithm = md5;
      CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm);
      rsaDigestInfo.digest.Set(bufferDigest.Access(), bufferDigest.Length());
      ENCODE_BUF(&rsaDigestInfo,pTempBuf);

   }
   else if (*palgoid == md2WithRSAEncryption ||
      ((*palgoid == rsaEncryption ||
        *palgoid == rsa ||
        *palgoid == AsnOid("1.2.840.113549.1.2")) && *pdigoid == id_md2))
   {
       // prepare the DigestInfo object with null parameters
      rsaDigestInfo.digestAlgorithm.algorithm = id_md2;
      CSM_Alg::LoadNullParams(&rsaDigestInfo.digestAlgorithm);
      rsaDigestInfo.digest.Set(bufferDigest.Access(), bufferDigest.Length());
      ENCODE_BUF(&rsaDigestInfo,pTempBuf);
   }

   // re-format raw RSA public key to handle.
#ifdef RWC_DOES_NOT_WORK_FOR_SOME_REASON
   hRsaKey = FormatRSAPublicKeyHandle(*pSignerKey, /*AT_KEYEXCHANGE/*RWC;FOR DATAKEY ONLY;*/AT_SIGNATURE);
#else
   hRsaKey = ExtractRSAPublicKeyFromPKI(*pSignerKey, CALG_RSA_SIGN);
#endif

   // finally, perform verification process.
   if (hHash && hRsaKey)
   {
#ifdef _DEBUG
      if (m_bUseInternalPublicKey)  // OVERRIDE incomming cert public key to 
                                    //  encrypt to; for DEBUG only.
      {
        BYTE *pbData;       
        DWORD dwDataLen=0;
       CryptExportKey(hRsaKey, 0, PUBLICKEYBLOB, 0, NULL, &dwDataLen);
       pbData = (BYTE *)calloc(1, dwDataLen);
       if (dwDataLen && 
           CryptExportKey(hRsaKey, 0, PUBLICKEYBLOB, 0, pbData, &dwDataLen))
       {
          if (bInTestDirectory())
          {
          CSM_Buffer AAAA((const char *)pbData, dwDataLen);
          AAAA.ConvertMemoryToFile("./sm_capi/DataOut/signerPublicKeyREFORMATTED.keyblob");
          }
       }
       else
       {
         SME_THROW(GetLastError(), "Bad CryptExportKey(...) signerPublicKeyREFORMATTED call.", NULL);
       }
      CryptDestroyKey(hRsaKey); 
      //RWC;DEBUG TEST ONLY, should use above "hRsaKey"
      if(!CryptGetUserKey(this->m_hCryptProv, /*AT_SIGNATURE/*/AT_KEYEXCHANGE, &hRsaKey))
      {
         SME_THROW(GetLastError(), "Bad CryptGetUserKey(...) localPublicKey call.", NULL);
      }
       CryptExportKey(hRsaKey, 0, PUBLICKEYBLOB, 0, NULL, &dwDataLen);
       pbData = (BYTE *)calloc(1, dwDataLen);
       if (dwDataLen && 
           CryptExportKey(hRsaKey, 0, PUBLICKEYBLOB, 0, pbData, &dwDataLen))
       {
          if (bInTestDirectory())
          {
          CSM_Buffer AAAA((const char *)pbData, dwDataLen);
          AAAA.ConvertMemoryToFile("./sm_capi/DataOut/localPublicKey.keyblob");
          }
       }
       else
       {
         SME_THROW(GetLastError(), "Bad CryptExportKey(...) call.", NULL);
       }
       DWORD cbData2=0;
       BYTE *pbData2=NULL;
       PCERT_PUBLIC_KEY_INFO pInfo;
       CryptExportPublicKeyInfo(m_hCryptProv, AT_SIGNATURE/*/AT_KEYEXCHANGE*/, X509_ASN_ENCODING,
           NULL, &cbData2);
       if (cbData2)
       {
          pInfo/*pbData2*/ = (PCERT_PUBLIC_KEY_INFO)calloc(1, cbData2);
       }
       if (cbData2 && !CryptExportPublicKeyInfo(m_hCryptProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
           pInfo, &cbData2))
       {
          SME_THROW(22, "CryptExportPublicKeyInfo failed!!!!", NULL);
       }
       CSM_Buffer AAA5((const char *)pInfo, cbData2);
       if (bInTestDirectory())
       {
       AAA5.ConvertMemoryToFile("./sm_capi/DataOut/ExportPublicKeyInfo2.bin");
       }
       CryptDestroyKey(hRsaKey); 
       if (!CryptImportKey(this->m_hCryptProv, pbData, dwDataLen, 0, 
            CRYPT_EXPORTABLE, &hRsaKey))
       {
          SME_THROW(22, "_DEBUG CryptImportKey(...) failed!!!!", NULL);
       }
      }  // END m_bUseInternalPublicKey
#endif //DEBUG
      BYTE *pbSignature=(BYTE *)pSignature->Access();
      BYTE *pbSignatureIN=(BYTE *)calloc(1, pSignature->Length());
      for (int ii3=0; ii3 < pSignature->Length(); ii3++)
            pbSignatureIN[ii3] = pbSignature[pSignature->Length()-ii3-1];
      if(CryptVerifySignature(hHash, pbSignatureIN, pSignature->Length(), hRsaKey,
            NULL, 0)) 
      {
         lRet = 0;
      }
      else
      {
         // RWC;11/5/01; JUST FOR DataKey....  Attempt to use CALG_RSA_KEYX
         CryptDestroyKey(hRsaKey); 
         hRsaKey = ExtractRSAPublicKeyFromPKI(*pSignerKey, CALG_RSA_KEYX);
         if(CryptVerifySignature(hHash, pbSignatureIN, pSignature->Length(), hRsaKey,
               NULL, 0)) 
         {
            lRet = 0;
         }
         else
         {
            unsigned long lA=GetLastError();
            if (strncmp(m_pszProviderName, "DATAKEY", strlen("DATAKEY")) == 0 &&
                pSignature->Length() != 2048)
            {           // SPECIAL ERROR (JUST FOR DataKey) since they seem not
                        //   to handle other than 2048 bit key verification 
                        //  (probably related to card bit length).
               SME_THROW(lA, "General CryptVerifySignature failure:  Probably DataKey Verify key length not 2048.", 
                  NULL);
            }

            if (lA == NTE_BAD_SIGNATURE)
            {
               SME_THROW(lA, "NTE_BAD_SIGNATURE, CryptVerifySignature failed", NULL);
            }
            else
            {
               SME_THROW(lA, "General CryptVerifySignature failure", NULL);
            }
         }
      }
      free(pbSignatureIN);
   }
   else
   {
      SME_THROW(22, "RSA OID Unknown or Not Handled Yet!", NULL);
   }

   if (pTempBuf)
      delete pTempBuf;
   if (hHash) 
      CryptDestroyHash(hHash);
   if (hRsaKey)
      CryptDestroyKey(hRsaKey); 
   if (palgoid)
       delete palgoid;
   if (pdigoid)
       delete pdigoid;

   SME_FINISH
   SME_CATCH_SETUP
      if (pTempBuf)
         delete pTempBuf;
      if (hHash) 
         CryptDestroyHash(hHash);
      if (hRsaKey)
         CryptDestroyKey(hRsaKey); 
      if (palgoid)
          delete palgoid;
      if (pdigoid)
          delete pdigoid;
   SME_CATCH_FINISH

   return lRet;
}

//////////////////////////////////////////////////////////////////////////
// This routine now handles 3DES and RC2 AES content encryption algs.
SM_RET_VAL CSM_Capi::SMTI_Encrypt(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *pIV)  // In, to avoid specific alg encoding by app.
{
   long status = SM_NO_ERROR;
   AsnOid *pPreferredOID = GetPrefContentEncryption();
   bool bDeletepIVFlag=false;    // FLAG local deletion of variable.

   SME_SETUP("CSM_Capi::SMTI_Encrypt");

   if (pIV == NULL)
      bDeletepIVFlag = true;

   m_ThreadLock.threadLock();
   // check incoming parameters
   if ((pData == NULL) || (pEncryptedData == NULL) ||
       (pParameters == NULL) || (pMEK == NULL))
      SME_THROW(SM_CAPI_MISSING_PARAM, "MISSING Parameters", NULL);

   // try CryptoPP
   SME(status = SMTI_EncryptCapi(pData, pEncryptedData, pParameters, pMEK, pIV));

   if (status == 2) 
   {
	  status = 0;

	  // try AES encryption
      SME(status = CSM_Common::SMTI_Encrypt(pData, pEncryptedData, pParameters, pMEK, pIV));
   }

   if (status == 2)
   {
	   SME_THROW(99,"Encryption ERROR invalid Alogrithm oid", NULL);
   }

   if (pPreferredOID )
      delete pPreferredOID;


   SME_FINISH
   SME_CATCH_SETUP
       if (pPreferredOID )
          delete pPreferredOID ;
       if (pIV && bDeletepIVFlag)
          delete pIV;
       m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH2
       if (pPreferredOID )
          delete pPreferredOID ;
       if (pIV && bDeletepIVFlag)
          delete pIV;
       m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH_END

   if (pIV && bDeletepIVFlag)
       delete pIV;

   m_ThreadLock.threadUnlock();
   return SM_NO_ERROR;
}
//////////////////////////////////////////////////////////////////////////
// This routine now handles 3DES and RC2 content encryption algs.
SM_RET_VAL CSM_Capi::SMTI_EncryptCapi(
            CSM_Buffer *pData, // input (data to be encrypted)
            CSM_Buffer *pEncryptedData, // output
            CSM_Buffer *pParameters, // OUT, for KeyAgree algs.
            CSM_Buffer *pMEK, // In/output; may be specified.
            CSM_Buffer *&pIV)  // In, to avoid specific alg encoding by app.
{
   int CBC_Length=0, CBC_KeyLength = 0;;
   AsnOid *pPreferredOID = GetPrefContentEncryption();
   HCRYPTKEY hKey=0;
   DWORD dwDataLen=0;

   SME_SETUP("CSM_Capi::SMTI_EncryptCapi");

   // check incoming parameters
   if ((pData == NULL) || (pEncryptedData == NULL) ||
       (pParameters == NULL) || (pMEK == NULL))
      SME_THROW(SM_CAPI_MISSING_PARAM, "MISSING Parameters", NULL);

   // check algorithm oids
   if (! ((*pPreferredOID == des_ede3_cbc) ||
	      //RWC;(*pPreferredOID == dES_CBC) || 
	      (*pPreferredOID == rc2_cbc)))
   {
	   // algorithm not valid
	   if (pPreferredOID)
		   delete pPreferredOID;
	   return 2;
   }


      if (*pPreferredOID == des_ede3_cbc) 
      {
         if (!CryptGenKey(m_hCryptProv, CALG_3DES, CRYPT_EXPORTABLE, &hKey))
         {
            SME_THROW(GetLastError(), "Bad CryptGenKey(...)", NULL);
         }
         CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
         CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
      }
      else if (*pPreferredOID == rc2_cbc)
      {
         if (!CryptGenKey(m_hCryptProv, CALG_RC2, CRYPT_EXPORTABLE, &hKey))
         {
            SME_THROW(GetLastError(), "Bad CryptGenKey(...)", NULL);
         }
         CBC_Length = SM_COMMON_RC2_BLOCKSIZE; // 8
         CBC_KeyLength = SM_COMMON_RC2_KEYLEN; // byte count 16 
      }
      /*RWC;else if (*pPreferredOID == dES_CBC)
      {
         CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
         CBC_KeyLength = 8;                     // for DES.
      }*/
      else          // Default to 3DES length.
      {
         /*RWC;CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
         CBC_KeyLength = SM_COMMON_3DES_KEYLEN;*/
         SME_THROW(22, "Content Encryption not supported!", NULL);
      }

   if (pMEK->Length())
   {
      SME_THROW(SM_CAPI_MISSING_PARAM, "CANNOT handle pre-defined ContentEncryption Key in CAPI CTIL.", NULL);
   }

   if (hKey)
   {
      DWORD dwCount=22; // FOR DATAKEY, this value MUST NOT BE 0.
      //-------------------------------------------------------------
      //  Get the length of the initialization vector.
      if(!CryptGetKeyParam(hKey, KP_IV, NULL, &dwCount, 0)) 
      {        // 234L = ERROR_MORE_DATA
         SME_THROW(GetLastError(), "Bad CryptGetKeyParam(...KP_IV...) call.", NULL);
      }
      // generate a IV AND load into CAPI crypto Key handle.
      if (dwCount && pIV == NULL || !pIV->Length())
      {
         if (pIV == NULL)
         {
            //deleteFlag = true;
            pIV = new CSM_Buffer;
         }
         SME(SMTI_Random(NULL, pIV, dwCount/*CBC_Length*/));
      }
      if(!CryptSetKeyParam(hKey, KP_IV, (unsigned char *)pIV->Access(), 0))
      {
         SME_THROW(GetLastError(), "Bad CryptSetKeyParam(...KP_IV...) call.", NULL);
      }
      // perform encryption operation.
      DWORD dwCountRead=0;             // TOTAL data actually Read.
      DWORD dwCountInput = pData->Length();
                                       // TOTAL to be Input.
      DWORD dwBufLen=0;
      bool bFinal=false;
      char *ptr2=(char *)calloc(1, 16384/*DataKey BROKEN;65536*/);
      int lenInput = 16384/*65536*/ - CBC_Length; // ALLOW for encrypt padding.
      if (dwCountInput < lenInput)
      {
         lenInput = dwCountInput;
         bFinal = true;    // ONLY 1 iteration through loop.
      }     // END < 65535
      const char *pDataIn=pData->Access();
      memcpy(ptr2, pDataIn, lenInput);
      pEncryptedData->Open(SM_FOPEN_WRITE);
      while (dwCountRead < dwCountInput)
      {
         /*dwCount = lenInput;
         if(!CryptEncrypt(hKey, 0, 
              bFinal, 0, NULL, &dwCount, 0))
         {
            SME_THROW(GetLastError(), "Bad CryptEncrypt(...) call, length.", NULL);
         }*/
         dwBufLen = 16384/*65536*/;//dwCount;
         dwCount = lenInput;
         if(!CryptEncrypt(hKey, 0,  //no hash (for signing).
              bFinal, 0, (unsigned char *)ptr2, &dwCount, dwBufLen))
         {
            SME_THROW(GetLastError(), "Bad CryptEncrypt(...) call.", NULL);
         }     // END if CryptEncrypt(...)
         if (dwCount > 0)
         {
            /*TMP;IMMEDIATE DECRYPT TEST for Debug ONLY!
            if(dwCount && !CryptDecrypt(hKey, 0,
                 bFinal, 0, (unsigned char *)ptr2, &dwCount))
            {
               SME_THROW(GetLastError(), "Bad CryptDecrypt(...) call.", NULL);
            }
            /TMP;*/
            pEncryptedData->Write/*Set*/(ptr2, dwCount);
             dwCountRead += dwCount;
         }     // END if dwCount
         else
            break;      // ABORT operations.
         if (dwCountRead < dwCountInput)
         {                 // if still processing input data.
            if (dwCountRead+lenInput >= dwCountInput) // LOOK ahead to last buffer.
            {
               lenInput = dwCountInput - dwCountRead; // REMAINDER only
               bFinal = true;
            }     // END dwCountExpected
            memcpy(ptr2, &pDataIn[dwCountRead], lenInput);//pData->Length());
         }        // END if still processing input data.
      }           // END while reading...
      if (ptr2)      // DELETE only when finished.
         free(ptr2);
      pEncryptedData->Close();
      LoadParams(*pIV, pParameters, CBC_KeyLength); // FOR return.
      // NOW setup key to export (BE CAREFUL, not clear key, but password
      //  encrypted inthe CAPI way.
#ifdef ONLY_ON_WIN2k_NOT_USED
      BYTE *pbData;
      HCRYPTKEY hExpKey;
      hExpKey = ComputeInternalPasswordKey();
      if (!CryptExportKey(hKey, hExpKey, SIMPLEBLOB, 0, NULL, &dwDataLen))
      {
         SME_THROW(GetLastError(), "Bad CryptExportKey(...) size call.", NULL);
      }
      if (dwDataLen)
      {
         pbData = (BYTE *)calloc(1, dwDataLen);
         if (!CryptExportKey(hKey, hExpKey, SIMPLEBLOB, 0, pbData, &dwDataLen))
         {
            SME_THROW(SM_CAPI_MISSING_PARAM, "Bad CryptExportKey(...) call.", NULL);
         }
         pMEK->Set((const char *)pbData, dwDataLen);    //RETURN CAPI specific key.
      }
      CryptDestroyKey(hExpKey);
#else    //ONLY_ON_WIN2k_NOT_USED
      pMEK->Set((const char *)&hKey, sizeof(hKey));    
                  //RETURN CAPI specific handle to key. IMPORTANT; only valid 
                  //  for CAPI interface!!!!!  DO NOT DESTROY HERE! 
      if (m_hKeyEncryption != 0)
         CryptDestroyKey(m_hKeyEncryption);
      m_hKeyEncryption = hKey;      // REMEMBER for cleanup.
#endif   //ONLY_ON_WIN2k
   }
   else     // RWC; DEFAULT; if (*pPreferredOID == des_ede3_cbc) 
   {
         SME_THROW(22, "Content Encryption handle not created!", NULL);
   }

    if (pPreferredOID )
       delete pPreferredOID ;


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}



//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_GenerateEMEK(
            CSM_Buffer *pRecipient, // input, Y of recip
            CSM_Buffer *pParameters, // IN,OUT may be passed in for shared use
            CSM_Buffer *pMEK, // input, MEK or special phrase
            CSM_Buffer *pEMEK, // output, encrypted MEK
            CSM_Buffer *pUKM, // input/output may be passed in for shared use.
            CSM_Buffer *pSubjKeyId) // output
{
   // 
   SM_RET_VAL status = -1;
   HCRYPTKEY hRsaKey;

   SME_SETUP("CSM_Capi::SMTI_GenerateEMEK");

   m_ThreadLock.threadLock();
   // check incoming parameters
   if ((pRecipient == NULL) || (pEMEK == NULL))
      SME_THROW(22, "MISSING PARAMETERS", NULL);
   if (pMEK->Length() != sizeof(HCRYPTKEY))
   {
      SME_THROW(23, "MEK MUST BE CREATED by this CAPI CTIL, not another CTIL!!!", NULL);
   }

#ifdef RWC_DOES_NOT_WORK_FOR_SOME_REASON
   hRsaKey = FormatRSAPublicKeyHandle(*pRecipient, AT_KEYEXCHANGE);
#else
   hRsaKey = ExtractRSAPublicKeyFromPKI(*pRecipient, CALG_RSA_KEYX);
#endif
   if (hRsaKey)
   {
      DWORD dwCount;
      dwCount = pMEK->Length();
#ifdef BOB
 unsigned long dwBlobLen=0;
 unsigned char *pbKeyBlob;
 HCRYPTKEY hPubKey;
 HCRYPTKEY hRsaKeyCopy;
 CryptDestroyKey(hRsaKey); 
 if(!CryptGetUserKey(this->m_hCryptProv, AT_KEYEXCHANGE, &hRsaKey))
 {
         SME_THROW(GetLastError(), "Bad CryptGetUserKey(...) call(DEBUG ONLY), length.", NULL);
 }
 CryptExportKey(hRsaKey, NULL, PUBLICKEYBLOB, 0, NULL, &dwBlobLen); 
 pbKeyBlob = (BYTE*)malloc(dwBlobLen);
 if(dwBlobLen > 0 &&
    !CryptExportKey(hRsaKey, NULL, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen))
         SME_THROW(GetLastError(), "Bad CryptExportKey(...) call(DEBUG ONLY), length.", NULL);
 hRsaKeyCopy = hRsaKey;
 if(!CryptImportKey(m_hCryptProv, pbKeyBlob, dwBlobLen, 0, 0, &hPubKey))
         SME_THROW(GetLastError(), "Bad CryptImportKey(...) call(DEBUG ONLY), length.", NULL);
 hRsaKey = hPubKey;
#endif  //BOB
      unsigned long dwDataLen=0;
      BYTE *pbKeyBlob;
#ifdef _DEBUG
      if (m_bUseInternalPublicKey)  // OVERRIDE incomming cert public key to 
                                    //  encrypt to; for DEBUG only.
      {
         //RWC:DEBUG TEST ONLY, SHOULD be using above Format... key.
         CryptDestroyKey(hRsaKey);
         if(!CryptGetUserKey(this->m_hCryptProv, /*AT_SIGNATURE/*/AT_KEYEXCHANGE, &hRsaKey))
         {
            SME_THROW(GetLastError(), "Bad CryptGetUserKey(...) call.", NULL);
         }
         CryptExportKey(hRsaKey, 0, PUBLICKEYBLOB, 0, NULL, &dwDataLen); 
         if (dwDataLen)
               pbKeyBlob = (BYTE *)calloc(1, dwDataLen+200);
         if (dwDataLen > 0 && 
             !CryptExportKey(hRsaKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwDataLen)) 
         {
             SME_THROW(GetLastError(), "Bad CryptExportKey(...) call.", NULL);
         }
         CSM_Buffer AAA4((const char *)pbKeyBlob, dwDataLen);
         if (bInTestDirectory())
         { AAA4.ConvertMemoryToFile("./sm_capi/DataOut/ExportKey.bin"); }
         DWORD cbData2=0;
         BYTE *pbData2=NULL;
         PCERT_PUBLIC_KEY_INFO pInfo;
         CryptExportPublicKeyInfo(m_hCryptProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
             NULL, &cbData2);
         if (cbData2)
         {
            pInfo/*pbData2*/ = (PCERT_PUBLIC_KEY_INFO)calloc(1, cbData2);
         }
         if (cbData2 && !CryptExportPublicKeyInfo(m_hCryptProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
             pInfo, &cbData2))
         {
            SME_THROW(22, "CryptExportPublicKeyInfo failed!!!!", NULL);
         }
         CSM_Buffer AAA5((const char *)pInfo, cbData2);
         if (bInTestDirectory())
         {AAA5.ConvertMemoryToFile("./sm_capi/DataOut/ExportPublicKeyInfo.bin");}
      }   //END m_bUseInternalPublicKey
#endif //_DEBUG

      HCRYPTKEY hKey = *(HCRYPTKEY *)pMEK->Access(); // ORIGINAL Content Encryption key.
      if (!CryptExportKey(hKey, hRsaKey, SIMPLEBLOB, 0, NULL, &dwDataLen))
      {
         hRsaKey = ExtractRSAPublicKeyFromPKI(*pRecipient, CALG_RSA_SIGN);
         if (hRsaKey <= 0)
         {
            SME_THROW(GetLastError(), "Bad ExtractRSAPublicKeyFromPKI(...) 2nd signer token generation length call.", NULL);
         }     // END 2nd hRsaKey
         if (!CryptExportKey(hKey, hRsaKey, SIMPLEBLOB, 0, NULL, &dwDataLen))
         {
            SME_THROW(GetLastError(), "Bad CryptExportKey(...) 2nd token generation length call.", NULL);
         }
      }
      if (dwDataLen)
      {
         pbKeyBlob = (BYTE *)calloc(1, dwDataLen+200);
         dwDataLen += 200;
      }
      else
      {
         SME_THROW(GetLastError(), "Bad CryptExportKey(...) token generation length call.", NULL);
      }
      if (dwDataLen > 0 && 
         !CryptExportKey(hKey, hRsaKey, SIMPLEBLOB, 0, pbKeyBlob, &dwDataLen))
      {
         SME_THROW(GetLastError(), "Bad CryptExportKey(...) token generation call.", NULL);
      }

      if (dwDataLen > sizeof(PUBLICKEYSTRUC) + sizeof(ALG_ID))
      {           // Since pbKeyBlob is a CAPI BLOB, we must remove the 
                  //  preceding PUBLICKEYSTRUC data and get just the key.
                  //  (See SMTI_ExtractMEK(...) comments.)
          char *pConvertedEMEK=(char *)calloc(1, dwDataLen); //Slightly over-sized.
          for (int iii=0; iii < (dwDataLen-sizeof(PUBLICKEYSTRUC)-sizeof(ALG_ID)); iii++)
            pConvertedEMEK[iii] = pbKeyBlob[dwDataLen-iii-1]; 
                                   // REVERSE byte order (MS convention!!!)
          pEMEK->Set((const char *)pConvertedEMEK, 
             dwDataLen - (sizeof(PUBLICKEYSTRUC) + sizeof(ALG_ID)));
          status = 0;      // indicate success.
          free(pConvertedEMEK);
      }
      free(pbKeyBlob);
      CryptDestroyKey(hRsaKey); 
      //status = 0;    // INDICATE success.
   }  // END RSA key handle generation.

   // RWC;2/7/00; If successful, load NULL PARAMS according to spec
   // ONLY FOR RSA.
   if (pParameters)
   {
       CSM_Buffer *pTmpBuf=CSM_AlgVDA::GetNullParams();
       *pParameters = *pTmpBuf;
       delete pTmpBuf;
   }

   SME_FINISH
   SME_CATCH_SETUP
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH2
       m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH_END

#ifdef WIN32
    pSubjKeyId;pUKM; //AVOIDS warning.
#endif

   m_ThreadLock.threadUnlock();
   return status;
}



///////////////////////////////////////////////////////////////////////////////
//--------------------------------------------------------------------
// GetRecipientCert enumerates the certificates in a store and finds
// the first certificate that has an AT_EXCHANGE key. If a certificate 
// is found, a pointer to that certificate is returned.  

PCCERT_CONTEXT CSM_Capi::GetRecipientCert(CSM_Buffer &CertBuf)
{ 
   //-------------------------------------------------------------------- 
   // Declare and initialize local variables. 

   PCCERT_CONTEXT pCertContext = NULL; 
   BOOL fMore = TRUE; 
   DWORD dwSize = NULL; 
   CRYPT_KEY_PROV_INFO* pKeyInfo = NULL; 
   DWORD PropId = CERT_KEY_PROV_INFO_PROP_ID; 

   //-------------------------------------------------------------------- 
   // Find certificates in the store until the end of the store 
   // is reached or a certificate with an AT_KEYEXCHANGE key is found. 

   /*while(fMore && (pCertContext= CertFindCertificateInStore( 
      hCertStore, // Handle of the store to be searched. 
      0,          // Encoding type. Not used for this search. 
      0,          // dwFindFlags. Special find criteria. 
                  // Not used in this search. 
      CERT_FIND_PROPERTY, 
                  // Find type. Determines the kind of search 
                  // to be done. In this case, search for 
                  // certificates that have a specific 
                  // extended property. 
      &PropId,    // pvFindPara. Gives the specific 
                  // value searched for, here the identifier 
                  // of an extended property. 
      pCertContext))) 
                  // pCertContext is NULL for the  
                  // first call to the function. 
                  // If the function were being called 
                  // in a loop, after the first call 
                  // pCertContext would be the pointer 
                  // returned by the previous call. */
   pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
      (const BYTE *)CertBuf.Access(), CertBuf.Length());
   if (pCertContext)
   { 
      //------------------------------------------------------------- 
      // For simplicity, this code only searches 
      // for the first occurrence of an AT_KEYEXCHANGE key. 
      // In many situations, a search would also look for a 
      // specific subject name as well as the key type. 

      //------------------------------------------------------------- 
      // Call CertGetCertificateContextProperty once to get the 
      // returned structure size. 

      if(!(CertGetCertificateContextProperty( 
           pCertContext, 
           CERT_KEY_PROV_INFO_PROP_ID, 
           NULL, &dwSize))) 
      { 
           printf("Error getting key property."); 
      } 

      //-------------------------------------------------------------- 
      // Allocate memory for the returned structure. 

      if(pKeyInfo) 
          free(pKeyInfo); 
      if(!(pKeyInfo = (CRYPT_KEY_PROV_INFO*)malloc(dwSize))) 
      { 
           printf("Error allocating memory for pKeyInfo."); 
      } 

      //-------------------------------------------------------------- 
      // Get the key information structure. 

      if(!(CertGetCertificateContextProperty( 
         pCertContext, 
         CERT_KEY_PROV_INFO_PROP_ID, 
         pKeyInfo, 
         &dwSize))) 
      { 
          printf("The second call to the function failed."); 
      } 

      //------------------------------------------- 
      // Check the dwKeySpec member for an exchange key. 

      if(pKeyInfo->dwKeySpec == AT_KEYEXCHANGE) 
      { 
          printf("dwKeySpec == AT_KEYEXCHANGE."); 
      }    // End of while loop 
   }

   if(pKeyInfo) 
         free(pKeyInfo); 
   return (pCertContext); 
} // End of GetRecipientCert 




/////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_Decrypt(
            CSM_Buffer *pParameters, // input (initialization vector)
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK, // input (MEK or special phrase)
            CSM_Buffer *pData) // output (decrypted data)
{
   long status = SM_NO_ERROR;
   CSM_Buffer *pParamDecodedBuf=NULL;
   AsnOid *pPreferredOID = GetPrefContentEncryption();

   SME_SETUP("CSM_Capi::SMTI_Decrypt");

   m_ThreadLock.threadLock();
   // check incoming parameters
   if ((pData == NULL) || (pEncryptedData == NULL) || (pParameters == NULL)
         || (pMEK == NULL) || pMEK->Access() == NULL)
      SME_THROW(SM_CAPI_MISSING_PARAM, "MISSING Parameters", NULL);

   SME(status = SMTI_DecryptCapi(pParameters, pEncryptedData, pMEK, pData));

   if (status == 2)
   {
	   SME_THROW(99,"Decryption ERROR invalid Alogrithm oid", NULL);
   }

   if (pPreferredOID )
      delete pPreferredOID;

   if (pParamDecodedBuf)
	   delete (pParamDecodedBuf);

   SME_FINISH
   SME_CATCH_SETUP
      if (pPreferredOID )
         delete pPreferredOID;
      if (pParamDecodedBuf)
	      delete (pParamDecodedBuf);
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH2
      if (pPreferredOID )
         delete pPreferredOID;
      if (pParamDecodedBuf)
	      delete (pParamDecodedBuf);
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH_END

   m_ThreadLock.threadUnlock();
   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_DecryptCapi(
            CSM_Buffer *pParameters, // input (initialization vector)
            CSM_Buffer *pEncryptedData, // input (data to be decrypted)
            CSM_Buffer *pMEK, // input (MEK or special phrase)
            CSM_Buffer *pData) // output (decrypted data)
{
   //char *pIV;
   int i;
   int CBC_Length, CBC_KeyLength; 
   CSM_Buffer *pParamDecodedBuf=NULL;
   CSM_Buffer *pIv = NULL;
   HCRYPTKEY hKey=0;
   DWORD dwDataLen=0;
   DWORD dwCount=0;
   char *ptr2=NULL;

   SME_SETUP("CSM_Capi::SMTI_DecryptCryptoPP");

   // check incoming parameters
   if ((pData == NULL) || (pEncryptedData == NULL) || (pParameters == NULL)
         || (pMEK == NULL) || pMEK->Access() == NULL)
      SME_THROW(SM_CAPI_MISSING_PARAM, "MISSING Parameters", NULL);

   // check for valid MEK
   if (strncmp(pMEK->Access(), SM_CAPI_FORTENC, 
         strlen(SM_CAPI_FORTENC)) == 0)
      SME_THROW(SM_CAPI_UNSUPPORTED_ALG, 
            "Cannot use skipjack MEK", NULL);
   if (pMEK->Length() != sizeof(DWORD))   // NOT FROM CAPI...
      SME_THROW(SM_CAPI_UNSUPPORTED_ALG, 
          "Cannot use non-CAPI Content Encrption MEK", NULL);
   
   AsnOid *pPreferredOID = GetPrefContentEncryption();

   // check algorithm oids
   if (! ((*pPreferredOID == des_ede3_cbc) ||
	      (*pPreferredOID == dES_CBC) || 
	      (*pPreferredOID == rc2_cbc)))
   {
	   // algorithm not valid
	   if (pPreferredOID)
		  delete (pPreferredOID);
	   return 2;
   }

   // set block size and key length
   if (*pPreferredOID == des_ede3_cbc) 
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
      hKey = *((DWORD *)pMEK->Access());    // endian issues irrelevant due to 
                                            //  local session only.
   }
   else if (*pPreferredOID == rc2_cbc)
   {
      CBC_Length = SM_COMMON_RC2_BLOCKSIZE; // 8
      CBC_KeyLength = SM_COMMON_RC2_KEYLEN; // 16 byte count 128 bits;
      hKey = *((DWORD *)pMEK->Access());    // endian issues irrelevant due to 
                                            //  local session only.
   }
   else if (*pPreferredOID == dES_CBC) 
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = 8;                    // FOR DES.
      hKey = *((DWORD *)pMEK->Access());    // endian issues irrelevant due to 
                                            //  local session only.
   } 
   else          // Default to 3DES length.
   {
      CBC_Length = SM_COMMON_3DES_BLOCKSIZE;
      CBC_KeyLength = SM_COMMON_3DES_KEYLEN;
      hKey = *((DWORD *)pMEK->Access());    // endian issues irrelevant due to 
                                            //  local session only.
   } 

   // check for preferred oid content encryption or key wrap oid
   if (*pPreferredOID == rc2_cbc || *pPreferredOID == des_ede3_cbc)
   {  
      int keybits = 0;

      // decode the parameters to get the keybits and the IV  
      pIv = UnloadParams(pPreferredOID, *pParameters, keybits);
      if (pIv)
      {
         if (keybits != 0)
         {
            CBC_KeyLength = keybits/8;  // bytes
         }
         if (pIv->Access() == NULL)
            SME_THROW(22, "Missing IV in preparation for decryption!", NULL);
         if(!CryptSetKeyParam(hKey, KP_IV, (unsigned char *)pIv->Access(), 0))
         {
            SME_THROW(GetLastError(), "Bad CryptSetKeyParam(...KP_IV...) call.", NULL);
         }
         delete pIv;
         pIv = NULL;
      }     // END if pIv.

      DWORD dwCountRead=0;             // TOTAL data actually Read.
      DWORD dwCountInput = pEncryptedData->Length();
                                       // TOTAL to be Input.
      bool bFinal=false;
      char *ptr2=(char *)calloc(1, 65536);
      int lenInput = 16384/*RWC;DataKey BROKEN;65536*/ - CBC_Length; // ALLOW for encrypt padding.
      if (dwCountInput < lenInput)
      {
         lenInput = dwCountInput;
         bFinal = true;    // ONLY 1 iteration through loop.
      }     // END < 65535
      const char *pDataIn=pEncryptedData->Access();
      memcpy(ptr2, pDataIn, lenInput);
      pData->Open(SM_FOPEN_WRITE);
      while (dwCountRead + CBC_Length < dwCountInput) // MAY BE PADDED.
      {
         dwCount = lenInput;
         // FIRST, ONLY get length.
         /*if (!CryptDecrypt(hKey, 0,  bFinal, 0, NULL, &dwCount))
         {
            SME_THROW(GetLastError(), "Bad CryptEncrypt(...) call, length.", NULL);
         }*/
         //dwCount = lenInput;
         if(dwCount && !CryptDecrypt(hKey, 0,  //no hash (for signing).
              bFinal, 0, (unsigned char *)ptr2, &dwCount))  // GET LENGTH.
         {
            SME_THROW(GetLastError(), "Bad CryptDecrypt(...) call.", NULL);
         }
         if (dwCount > 0)
         {
             pData->Write/*Set*/(ptr2, dwCount);
             dwCountRead += dwCount;
         }     // END if dwCount
         else
            break;      // ABORT operations.
         if (dwCountRead < dwCountInput)
         {                 // if still processing input data.
            if (dwCountRead+lenInput >= dwCountInput) // LOOK ahead to last buffer.
            {
               lenInput = dwCountInput - dwCountRead; // REMAINDER only
               bFinal = true;
            }     // END dwCountExpected
            memcpy(ptr2, &pDataIn[dwCountRead], lenInput);//pData->Length());
         }        // END if still processing input data.
      }        // END while data to be read.
      if (ptr2)      // DELETE only when finished.
         free(ptr2);
      pData->Close();

#ifdef RWC_ORIGINAL_CODE //####################################################
      dwCount = pEncryptedData->Length();
      /*if(!CryptDecrypt(hKey, 0,  //no hash (for signing).
           true, 0, NULL, &dwCount))    // GET LENGTH.
      {
         SME_THROW(GetLastError(), "Bad CryptDecrypt(...) call, length.", NULL);
      }*/
      CryptDecrypt(hKey, 0,  true, 0, NULL, &dwCount);  // GET LENGTH.
      DWORD dwTmpCount=dwCount;// REMEMBER old size (RWC; For some reason the 
                           //   Datakey CAPI returns 0x0000ff28 instead of 
                           //   0x00000028 on the next call??).

      if (dwCount)
        ptr2=(char *)calloc(1, dwCount);
      if (dwCount && ptr2)
      {
         memcpy(ptr2, pEncryptedData->Access(), pEncryptedData->Length());
         if(dwCount && !CryptDecrypt(hKey, 0,  //no hash (for signing).
              true, 0, (unsigned char *)ptr2, &dwCount))  // GET LENGTH.
         {
            SME_THROW(GetLastError(), "Bad CryptDecrypt(...) call.", NULL);
         }
         if (dwTmpCount > dwCount)
            dwTmpCount = dwCount;
         if (dwCount)
         {
             pData->Set(ptr2, dwTmpCount);   // RWC:AVOIDS crash on Datakey.
         }
         free(ptr2);
         ptr2 = NULL;
      }        // END if dwCoutn && ptr2
#endif //##################################################################

      // decrypt the data sending in the block length
   }
   else  
   {
      // unload the parameters
      pParamDecodedBuf = UnloadParams(pPreferredOID, *pParameters);

      if (pParamDecodedBuf == NULL)
         SME_THROW(SM_CAPI_PARAM_DEC_ERROR, "MUST HAVE 3DES PARAMS.", NULL);

      if (*pPreferredOID != dES_CBC &&
           pMEK->Length() < (unsigned int)CBC_KeyLength) //FIX IT;key should be
      {                                         //  24 for best encryption.
         CSM_Buffer *pTmpBuf2=new CSM_Buffer((size_t)CBC_KeyLength);
         pTmpBuf2->SetLength(CBC_KeyLength);
         memcpy((void *)pTmpBuf2->Access(), pMEK->Access(), pMEK->Length());
         char *ptr3=(char *)pTmpBuf2->Access();
         for (i=(int)pMEK->Length(); i < (int)pTmpBuf2->Length(); i++)
            ptr3[i] = '\0';      // zero fill key
         *pMEK = *pTmpBuf2;  //RWC; check for memory leak
         delete pTmpBuf2;
      }

      // Check parity for incomming 3DES key.
      // RWC;4/4/01;CHECK to see if DES requires parity update, may need to be
      //   moved under "des_ede3_cbc" OID check!!!!!!!
      unsigned char *ptr3=(unsigned char *)pMEK->Access();
      for (i=0; i < (int)pMEK->Length(); i++)
      {
         //if (!CryptoPP::Parity((unsigned long)ptr3[i]))
            ptr3[i] ^= 0x01;
      }

      // create cbc object
      if (*pPreferredOID == des_ede3_cbc) 
      {
      }
      else if (*pPreferredOID == dES_CBC) 
      {
      }
      else      // NO PADDING on KeyWrap.
      {
      }

      // decrypt the data
   } // end 3des perferred oid

   delete pPreferredOID;
   delete pParamDecodedBuf;

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic
      // cleanup pMEK, in, out
      // close these if open
      if (pData)
        pData->Close();
      if (pEncryptedData)
        pEncryptedData->Close();
      if (pParamDecodedBuf)
         delete pParamDecodedBuf;
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_ExtractMEK(
            CSM_Buffer *pOriginator, // input, Y of originator
            CSM_Buffer *pParameters, // input
            CSM_Buffer *pEMEK, // input, encrypted MEK
            CSM_Buffer *pUKM, // input
            CSM_Buffer *pMEK) // output (MEK or special phrase)
{
   SM_RET_VAL status = -1;
   HCRYPTKEY hPrivKey=0;
   HCRYPTKEY hKey=0;

   SME_SETUP("CSM_Capi::SMTI_ExtractMEK");

   m_ThreadLock.threadLock();
#ifdef BUFFER_NOT_DEFINED_IN_CAPI_WHY_NOT
   DWORD dwKeySpec=AT_KEYEXCHANGE;
   BOOL bfCallerFreeProv;
   HCRYPTPROV hCryptProv;
   if (!CryptAcquireCertificatePrivateKey(m_pSignerCertContext, 0,
      NULL, &hCryptProv, &dwKeySpec, &bfCallerFreeProv))
   {
      SME_THROW(GetLastError(), "Bad CryptAcquireCertificatePrivateKey(...) call.", NULL);
   }
#endif //BUFFER_NOT_DEFINED_IN_CAPI_WHY_NOT

   if(!CryptGetUserKey(this->m_hCryptProv, AT_KEYEXCHANGE, &hPrivKey))
   {
#ifdef _DEBUG
      if(!CryptGetUserKey(this->m_hCryptProv, AT_SIGNATURE, &hPrivKey))
#endif   // _DEBUG
         SME_THROW(GetLastError(), "Bad CryptGetUserKey(...) call.", NULL);
   }

   // FROM MS Documentation.
   /*Simple-Key BLOBs
     Simple key BLOBs, type SIMPLEBLOB, are used to store and transport 
     session keys outside a CSP. Base provider simple-key BLOBs are always 
     encrypted with a key exchange public key. The pbData member of the 
     SIMPLEBLOB is a sequence of bytes in the following format:

       PUBLICKEYSTRUC  publickeystruc ;
       ALG_ID algid;
       BYTE encryptedkey[rsapubkey.bitlen/8]; */

   // pOriginator is unnecessary for RSA algorithm processing.
   int iPubKeySize = sizeof(PUBLICKEYSTRUC);
   int iALG_IDSize = sizeof(ALG_ID);
   PUBLICKEYSTRUC AA;
   ALG_ID AA2;
   bool bStatus;
   char *pEmekData=(char *)calloc(1, iPubKeySize + iALG_IDSize + pEMEK->Length());
   AA.bType = SIMPLEBLOB;
   AA.bVersion = 0x02;
   AA.reserved = 0x00;
   // MUST ALIGN THIS CORRECTLY, since this call will work, but the decrypt will
   //  fail if the aiKeyAlg is improperly loaded.  Check GetPreferredAlg.
   //  IMPORTANT::: The calling routine MUST be sure that the associated content
   //  encryption OID was already set before calling the RecipientInfo encrypt 
   //  call.  This is usually not a problem since the calls are made in 
   //  consecutive order, but...
   AA2 = CALG_RSA_KEYX;//CALG_RSA_SIGN;
   AsnOid *pPreferredContentOID = GetPrefContentEncryption();
   if (pPreferredContentOID)
   {
      if (*pPreferredContentOID == rc2_cbc)
         AA.aiKeyAlg = CALG_RC2;
      else if (*pPreferredContentOID == des_ede3_cbc)
         AA.aiKeyAlg = CALG_3DES;
      else if (*pPreferredContentOID == dES_CBC)
         AA.aiKeyAlg = CALG_DES;
      delete pPreferredContentOID;
      pPreferredContentOID = NULL;
   }
   else              //GUESS.
      AA.aiKeyAlg = CALG_3DES;
   memcpy(pEmekData, &AA, iPubKeySize);
   memcpy(&pEmekData[iPubKeySize], &AA2, iALG_IDSize);
   const char *pOrigEMEK=pEMEK->Access();
   int iEMEKLength=pEMEK->Length();
   for (int iii=0; iii < iEMEKLength; iii++) // REVERSE byte order (MS convention!!!)
      pEmekData[iPubKeySize+iALG_IDSize+iii] = pOrigEMEK[iEMEKLength-iii-1];
   //memcpy(&pEmekData[iPubKeySize+iALG_IDSize], pEMEK->Access(), pEMEK->Length());
   bStatus = CryptImportKey(this->m_hCryptProv, (BYTE *)pEmekData, 
        pEMEK->Length() + iPubKeySize + iALG_IDSize, hPrivKey, 
        CRYPT_EXPORTABLE, &hKey);

   if (bStatus)
   {
      pMEK->Set((const char *)&hKey, sizeof(hKey));
                     // RETURN handle to decrypted MEK as handle in CAPI CTIL.
      status = 0;    // indicate success.
   }
   else
   {
#ifdef _DEBUG //_DOESNT_WORK
      CryptDestroyKey(hPrivKey);
      if(!CryptGetUserKey(this->m_hCryptProv, AT_SIGNATURE, &hPrivKey))
      {
         bStatus = CryptImportKey(this->m_hCryptProv, (BYTE *)pEmekData, 
           pEMEK->Length() + sizeof(PUBLICKEYSTRUC) + sizeof(AA2), hPrivKey, 
           CRYPT_EXPORTABLE, &hKey);
         if (bStatus)
         {
            pMEK->Set((const char *)&hKey, sizeof(hKey));
                           // RETURN handle to decrypted MEK as handle in CAPI CTIL.
            status = 0;    // indicate success.
         }
         else
           SME_THROW(GetLastError(), "Bad CryptImportKey(...) call.", NULL);
      }
      else
#endif   // _DEBUG
        SME_THROW(GetLastError(), "Bad CryptImportKey(...) call.", NULL);
   }
   free(pEmekData);
   CryptDestroyKey(hPrivKey);


   SME_FINISH
   SME_CATCH_SETUP
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH2
      m_ThreadLock.threadUnlock();
   SFL_CATCH_FINISH_END

   m_ThreadLock.threadUnlock();
   return status;
}

//
//
CSM_AlgVDA *CSM_Capi::DeriveMsgAlgFromCert(CSM_AlgVDA &Alg)
{               // This call interprets KARI certificate params into CMS Msg
                //  Param format for algorithms.  It is up to the CTIL to 
                //  properly interpret algorithm specific formats for both.
   CSM_AlgVDA *pAlg=new CSM_AlgVDA(Alg);
   CSM_Buffer *pbufParams=NULL;
   CSM_Buffer *pParameters=NULL;
   long stat1;

   SME_SETUP("CSM_Capi::DeriveMsgAlgFromCert(Alg)");
   // The incomming parameters are from the certificate using a different 
   //  ASN.1 definition than the CMS encryption format.
   if (pAlg != NULL)
   {
      if (pAlg->algorithm == dh_public_number ||
          pAlg->algorithm == id_dhStatic)
      {                    // SUPPORT DH params from cert TO msg.
         DHParameters snaccDHParameters;      // ASN.1 Msg param format
         //DHPublicKeyParams snaccCertDHParams; // ASN.1 Cert param format
         DomainParameters snaccCertDHParams; // ASN.1 Cert param format
         SM_EXTRACT_ANYBUF(pbufParams, pAlg->parameters);  // Get cert params.
         DECODE_BUF_NOFAIL(&snaccCertDHParams, pbufParams, stat1);
         if (stat1 == 0)
         {
             snaccDHParameters.p = snaccCertDHParams.p;
             snaccDHParameters.g = snaccCertDHParams.g;
                        // IGNORE "q" for DH handling.
         }
         else       // OLD style for our test environment comaptibility.
         {
            DHPublicKeyParams snaccCertDHParams2; // ASN.1 Cert param format
            DECODE_BUF(&snaccCertDHParams2, pbufParams);
            snaccDHParameters.p = snaccCertDHParams2.p;
            snaccDHParameters.g = snaccCertDHParams2.g;
         }
         //Leave empty;snaccDHParameters.iv.Set();
         ENCODE_BUF((&snaccDHParameters), pParameters);
         if (pAlg->parameters->value != NULL)
         {
             delete pAlg->parameters->value;
             pAlg->parameters->value = NULL;
         }
         SM_ASSIGN_ANYBUF(pParameters, pAlg->parameters);
		 if (pbufParams)
             delete pbufParams;
		 if (pParameters)
             delete pParameters;
      }
      // else; return NULL indicating not supported for specified cert alg.
   }
   else
      SME_THROW(22, "Missing PublicKeyAlg in cert.", NULL);

   SME_FINISH_CATCH
   return(pAlg);
}

//
//
CSM_Alg *CSM_Capi::DeriveMsgAlgFromCert(CSM_CertificateChoice &Cert)
{               // This call interprets KARI certificate params into CMS Msg
                //  Param format for algorithms.  It is up to the CTIL to 
                //  properly interpret algorithm specific formats for both.
   CSM_Alg *pAlg=NULL;
   CSM_Alg *pAlgReturn=NULL;

   SME_SETUP("CSM_Capi::DeriveMsgAlgFromCert");
   // The incomming parameters are from the certificate using a different 
   //  ASN.1 definition than the CMS encryption format.
   if ((pAlg = Cert.GetPublicKeyAlg()) != NULL)
   {
        pAlgReturn = (CSM_Alg *)DeriveMsgAlgFromCert(*(CSM_AlgVDA *)pAlg);
   }
   else
      SME_THROW(22, "Missing PublicKeyAlg in cert.", NULL);

   SME_FINISH_CATCH
   return(pAlgReturn);
}



//////////////////////////////////////////////////////////////////////////
// SMTI_DigestData uses CSM_Common for SHA1 and Crypto++ for MD5
SM_RET_VAL CSM_Capi::SMTI_DigestData(
            CSM_Buffer *pData, // input
            CSM_Buffer *pDigest) // output
{
   HCRYPTHASH hHash=0;
   SM_RET_VAL status;
   status = SMTI_DigestDataInternal(pData, pDigest, hHash);
   if (hHash)
      CryptDestroyHash(hHash);

   return(status);
}

//////////////////////////////////////////////////////////////////////////
// SMTI_DigestData uses CSM_Common for SHA1 and Crypto++ for MD5
SM_RET_VAL CSM_Capi::SMTI_DigestDataInternal(
            CSM_Buffer *pData,   // Input
            CSM_Buffer *pDigest, // Output
            HCRYPTHASH &hHash)   // Ouput
{
   AsnOid *poidDigest = GetPrefDigest();
   long status = -1;
   int iDigestSize=0;
   ALG_ID HashAlg=0;
   //RWC;TBD;SETUP size based on algorithm.....
   SME_SETUP("CSM_Capi::SMTI_DigestData");

   if (*poidDigest == md5 ||
       *poidDigest == md5WithRSAEncryption)
   {
      HashAlg = CALG_MD5;
   }
   else if (*poidDigest == id_md2 ||
            *poidDigest == md2WithRSAEncryption)
   {
      HashAlg = CALG_MD2;
   }
   else if (*poidDigest == sha_1 ||
            *poidDigest == sha_1WithRSAEncryption ||
            *poidDigest == sha_1WithRSAEncryption_ALT)
   {
      HashAlg = CALG_SHA1;
   }

   if (HashAlg)
   {
      if(!CryptCreateHash(this->m_hCryptProv, HashAlg, 0, 0, &hHash)) 
      {
         SME_THROW(GetLastError(), "Bad CryptCreateHash(...) call", NULL)
      }
      //--------------------------------------------------------------------
      // Compute the cryptographic hash of the buffer.
      if(!CryptHashData(hHash, (const unsigned char *)pData->Access(), pData->Length(), 0)) 
      {
         SME_THROW(GetLastError(), "Bad CryptHashData(...) call", NULL)
      }
      // NOW get the actual data.
      DWORD dHashByteCount;
      BYTE *pbData=(BYTE *)&dHashByteCount;
      DWORD dwDataLen=sizeof(dHashByteCount);
      CryptGetHashParam(hHash, HP_HASHSIZE, pbData, &dwDataLen,0);
      pbData = (BYTE *)calloc(1,dHashByteCount);
      dwDataLen = dHashByteCount;
      if (dHashByteCount > 0)
      {
          CryptGetHashParam(hHash, HP_HASHVAL, pbData, &dwDataLen, 0);
          pDigest->Set((const char *)pbData, dwDataLen);
          status = 0;    // indicate success.
      }
      free(pbData);
      //--------------------------------------------------------------------
      // Destroy the hash object.
   }
   else     // Attempt the CSM_Common algorithm set...
   {
      SME((status = CSM_Common::SMTI_DigestData(pData, pDigest)));
   }

   if (status != 0)
   {
       SME_THROW(SM_CAPI_UNSUPPORTED_ALG, 
           "CSM_Capi::SMTI_DigestData:Unsupported alg", NULL);
   }

   delete poidDigest;

   SME_FINISH
   SME_CATCH_SETUP
      if (poidDigest)
         delete poidDigest;
   SME_CATCH_FINISH

   return status;
}

//////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_Capi::SMTI_Random(
            CSM_Buffer *pSeed,   // input
            CSM_Buffer *pRandom, // input/output
            SM_SIZE_T lLength)   // input
{
   char *p = NULL;

   SME_SETUP("CSM_Capi::SMTI_Random");

   // TBD:  Use pSeed

   if (pRandom == NULL)
      SME_THROW(SM_CAPI_MISSING_PARAM, "MISSING Parameters", NULL);

   // open the buffer
   SME(pRandom->Open(SM_FOPEN_WRITE));
   // allocate memory for use in the buffer
   SME(p = pRandom->Alloc(lLength));

   // create lLength random bytes of data
   //m_pRng->GetBlock((unsigned char *)p, lLength);
   if (!CryptGenRandom(this->m_hCryptProv, lLength, (unsigned char *)p))
   {
      SME_THROW(SM_CAPI_MISSING_PARAM, "CSM_Capi::SMTI_Random: CryptGenRandom(...) failed.", NULL);
   }

   // flush and close
   pRandom->Flush();
   pRandom->Close();

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

#ifdef WIN32
    pSeed;    //AVOIDS warning.
#endif
   return SM_NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////
CSM_Capi::~CSM_Capi()
{
   PCCERT_CONTEXT pTMPSignerCertContext=NULL;

   if (m_pszPrefix != NULL)
      free(m_pszPrefix);
   if (m_pCertPath)
       delete m_pCertPath;
   if (m_lpszPin)
      free(m_lpszPin);
   if (m_pszProviderName)
      free(m_pszProviderName);
   if (m_hKeyEncryption != 0)
      CryptDestroyKey(m_hKeyEncryption);

   if (m_hStoreHandle > 0)
   {     // handle closing the system store and OPTIONALLY deleting the certs.
#ifdef DO_NOT_PERFORM_YET_TO_BE_FIXED_TO_DELETE_ONLY_NEW_CERTS
      // NOTE:::: THE FOLLOWING LOGIC should only be executed if DataKey is used
      //   and certs were sucessfully loaded.  THIS DISALLOWS the use of the MS 
      //   default certificate store for ANY OTHER APPLICATION.  IT IS ASSUMED
      //   THAT ANY APPLICATION USING DataKey DOES NOT USE THE MS Default 
      //   Providers.  (THIS WAS DONE because the DataKey SDK provided no means
      //   to exactly determine which certs to unload).
      if (this->m_bDataKeyCertificatesLoaded)
      {        // handle deleting the loaded certs to avoid clutter; it is 
               // assumed that this flag is ONLY set on DataKey smartcard reads
               // AND this CTIL was successful in loading the DataKey SDK DLL 
               // to transfer certs from the DataKey smartcard to the system
               // store.  This cleanup is necessary to avoid clutter from 
               // various users loading cards.
         m_pSignerCertContext = NULL;
         do {           // DELETE ALL CERTS
            pTMPSignerCertContext = CertEnumCertificatesInStore(m_hStoreHandle, NULL);
            if (pTMPSignerCertContext)
               CertDeleteCertificateFromStore(pTMPSignerCertContext);

         } while (pTMPSignerCertContext);

      }     // END if m_bDataKeyCertificatesLoaded
#endif //RWC;DO_NOT_PERFORM_YET_TO_BE_FIXED_TO_DELETE_ONLY_NEW_CERTS
      CertCloseStore(m_hStoreHandle, CERT_CLOSE_STORE_FORCE_FLAG);
      m_hStoreHandle = 0;
   }        // END if m_hStoreHandle

   if (m_hInternalMSKey != 0 && m_hInternalMSKey != m_hCryptProv)
       CryptReleaseContext(m_hInternalMSKey, 0);   // RWC; ONLY if 2nd created.
   if (m_hCryptProv != 0)
       CryptReleaseContext(m_hCryptProv, 0);

   /**RWC;IN .DLL Load/Unload;
   if (m_hDataKeyModule)
   {
      //RWC;ONLY UNLOAD AT END, otherwise it causes crash upon any exception
      //RWC;  in DataKey CSP.
      FreeLibrary(m_hDataKeyModule);
   }
   **RWC;*/

}


//////////////////////////////////////////////////////////////////////////
void CSM_Capi::CSM_TokenInterfaceDestroy()
{
   delete this;
}


//////////////////////////////////////////////////////////////////////////
CSM_Capi::CSM_Capi(AsnOid CertAlgOid){ m_hCryptProv = 0; m_hInternalMSKey = 0; Setup(CertAlgOid); };
//////////////////////////////////////////////////////////////////////////
CSM_Capi::CSM_Capi() { m_hCryptProv = 0; m_hInternalMSKey = 0; Setup(rsa);};
//////////////////////////////////////////////////////////////////////////
void CSM_Capi::Setup(AsnOid CertAlgOid)
{
   SME_SETUP("CSM_Capi::CSM_Capi");

   Clear();

   time_t t;
   time(&t); // use time to seed rng
   // store it in the seed member
   char pch[10];
   if (pch == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   memcpy(&pch[0], &t, 4);
   //m_seed.Set(&pch[0], (SM_SIZE_T) 4);
   // use this key for the random cipher...TBD???
   //byte rngKey[] = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0x12, 0x23, 0x77};

   // clear other members
   m_pbufPassword = NULL;
   m_pszPrefix = NULL;
   //if ((m_pRandomData = new CSM_Buffer) == NULL)
   //   SME_THROW(SM_MEMORY_ERROR, NULL, NULL);

   // construct random components
   //m_pRandomCipher = new DES(&rngKey[0], ENCRYPTION);;
   //m_pRng = new X917RNG(m_pRandomCipher, (unsigned char *)m_seed.Access());

   // set up algs
   //DONE ON CASE-BY-CASE;SME(SetDefaultOIDs(&CertAlgOid));

   // load up some random data
   //RWC;CAPI Handle NOT INITIALIZED YET;SME(SMTI_Random(NULL, m_pRandomData, SM_FREE_RANDSIZE));

   SME_FINISH_CATCH
}

//////////////////////////////////////////////////////////////////////////
#ifdef SEED_CODE_IN_PLACE
CSM_Capi::CSM_Capi(char *pszSeed)
{
   // store provided seed in the seed member
   m_seed.Set(pszSeed, strlen(pszSeed));
   // use this key for the random cipher...TBD???
   //byte rngKey[] = {0xab, 0xbc, 0xcd, 0xde, 0xef, 0x12, 0x23, 0x77};

   // clear other members
   m_pszPassword = NULL;
   m_pszPrefix = NULL;
   m_pAB = NULL;

   // construct random components
   //m_pRandomCipher = new DES(&rngKey[0], ENCRYPTION);;
   //m_pRng = new X917RNG(m_pRandomCipher, (unsigned char *)m_seed.Access());

   // set up algs
   SetDefaultOIDs();
}
#endif
//////////////////////////////////////////////////////////////////////////
// This function restores or sets the default OIDs in the BTI
//  THE PARAMETER designates the specific algorithms of the supported CTIL
//  list that are valid for this certificate:  RSA, DSA, DH or RSA ktri.
//  RWC;12/6/00; This method is now smart enough to pre-load existing algs if 
//      present OR load the initial algs.  This allows an app to load 
//      additional algs (e.g. for verify, DSA & RSA).
void CSM_Capi::SetDefaultOIDs(const AsnOid *pCertAlgOid)
{
   AsnOid *pSignOid = NULL;
   AsnOid *pEncryptOid = NULL;
   AsnOid *pKeyEncryptOid=NULL;

   SME_SETUP("CSM_Capi::SetDefaultOIDs");

   // RWC;TBD, Make the OID choices dynamic based on Crypto login.
   // put the AsnOids in AsnOids
   AsnOid ENDOID("0.0.0");
   AsnOid oidHash[] = { 
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption, 
       md5, 
       md5WithRSAEncryption,
       id_md2,
       md2WithRSAEncryption,
       id_OIW_secsig_algorithm_dsa, 
       ENDOID };
   AsnOid oidSignRSA[] = {
       rsa, 
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption,
       md5WithRSAEncryption,
       md2WithRSAEncryption,
       rsaEncryption,
       "1.2.840.113549.1.2",    // bsafe rsa encryption oid
       ENDOID };
   AsnOid oidSignDSA[] = { 
       id_dsa,  
       id_dsa_with_sha1, 
       "1.3.14.3.2.12", 
       ENDOID };
   AsnOid oidContentEncrypt[] = { 
       des_ede3_cbc,
       rc2_cbc,
       dES_CBC,
       ENDOID };
   AsnOid oidKeyEncryptDH[] = { 
       ENDOID };
   AsnOid oidKeyEncryptRSA[] = { 
       rsa,
       rsaEncryption,
       sha_1WithRSAEncryption_ALT,
       sha_1WithRSAEncryption,
       "1.2.840.113549.1.2",    // bsafe rsa encryption oid
       ENDOID };
   CSM_AlgVDA *pAlg;
   int i;
   int bAlreadyLoaded = 0;  // FALSE initially.
   CSM_AlgLstVDA *pDigestAlgs = new CSM_AlgLstVDA;
   CSM_AlgLstVDA *pKeyEncryption=NULL;
   CSM_AlgLstVDA *pContentEncryption=NULL;
   CSM_AlgLstVDA *pDigestEncryption = NULL;
   if (!this->m_bSigner)      // ONLY if Encrypter to avoid CAPI issues.
   {
      pContentEncryption = new CSM_AlgLstVDA;
      pKeyEncryption = new CSM_AlgLstVDA;    // Also disable key encrypt in signer.
                              // (RWC;Encrypt handle MUST reside in RSA
                              //  wrap instance.)
   }
   else
   {
      pDigestEncryption = new CSM_AlgLstVDA;
   }


   BTIGetAlgIDs(&pDigestAlgs, &pDigestEncryption, &pKeyEncryption,
            &pContentEncryption);   // pre-load
   if ((pDigestEncryption && pDigestEncryption->size()) || 
       (pKeyEncryption && pKeyEncryption->size()))
   {                // ONLY if already present.
        bAlreadyLoaded = true;
   }

   // Produce list of separate alg lists.
   if (!bAlreadyLoaded)
   {
       CSM_Common::SetDefaultOIDLists(pDigestAlgs, pDigestEncryption, 
          pKeyEncryption, pContentEncryption); //SET all CSM_Common supplied algs.
       for (i=0; oidHash[i] != ENDOID; i++)
       {
           pAlg = &(*pDigestAlgs->append());
           pAlg->algorithm = oidHash[i];
       }
       if (!this->m_bSigner)      // ONLY if Encrypter to avoid CAPI issues.
       {
          for (i=0; oidContentEncrypt[i] != ENDOID; i++)
          {
              pAlg = &(*pContentEncryption->append());
              pAlg->algorithm = oidContentEncrypt[i];
          }
       }
   }

   if (pDigestEncryption)
   {
      if (pCertAlgOid == NULL || *pCertAlgOid == id_dsa)
      {
        for (i=0; oidSignDSA[i] != ENDOID; i++)
        {
           pAlg = &(*pDigestEncryption->append());
           pAlg->algorithm = oidSignDSA[i];
        }
        pSignOid = new AsnOid(id_dsa_with_sha1);     
      }
      else if (pCertAlgOid == NULL ||  
               *pCertAlgOid == rsa || 
               *pCertAlgOid == rsaEncryption ||
               *pCertAlgOid == md2WithRSAEncryption ||
               *pCertAlgOid == md5WithRSAEncryption ||
               *pCertAlgOid == sha_1WithRSAEncryption ||
               *pCertAlgOid == AsnOid( "1.2.840.113549.1.2"))
      {
        for (i=0; oidSignRSA[i] != ENDOID; i++)
        {
           pAlg = &(*pDigestEncryption->append());
           pAlg->algorithm = oidSignRSA[i];
        }   // END for oidSignRSA count
        if (pCertAlgOid)
        {
          pSignOid =  new AsnOid(*pCertAlgOid);
        }// END if pCertAlgOid
      }  // END if id_dsa
   }     // END IF pDigestEncryption

   if (!this->m_bSigner &&          // ONLY if Encrypter to avoid CAPI issues.
       pKeyEncryption != NULL &&    // ONLY if encrypter flag set.
      (pCertAlgOid == NULL ||
      *pCertAlgOid == rsa || 
      *pCertAlgOid == rsaEncryption ||
      *pCertAlgOid == md2WithRSAEncryption ||
      *pCertAlgOid == md5WithRSAEncryption ||
      *pCertAlgOid == sha_1WithRSAEncryption ||
      *pCertAlgOid == AsnOid( "1.2.840.113549.1.2")))
   {
     for (i=0; oidKeyEncryptRSA[i] != ENDOID; i++)
     {
        pAlg = &(*pKeyEncryption->append());
        pAlg->algorithm = oidKeyEncryptRSA[i];
     }
     pEncryptOid =  new AsnOid(*pCertAlgOid);
     pKeyEncryptOid = new AsnOid(*pCertAlgOid);
   }

   // put the CSM_AlgLsts in the base token interface
   SME(BTISetAlgIDs(pDigestAlgs, pDigestEncryption, pKeyEncryption, 
         pContentEncryption));
   if (pDigestAlgs)
   {
      delete pDigestAlgs;
      pDigestAlgs = NULL;
   }
   if (pDigestEncryption)
   {
      delete pDigestEncryption;
      pDigestEncryption = NULL;
   }
   if (pKeyEncryption)
   {
      delete pKeyEncryption;
      pKeyEncryption = NULL;
   }
   if (pContentEncryption)
   {
      delete pContentEncryption;
      pContentEncryption = NULL;
   }
   // make sha1, dsa, dh, and tdes the preferred algs
   AsnOid oidSha1(sha_1);
   // AsnOid oidDsa(id_dsa);
   AsnOid *poidTdes = NULL;
   if (!this->m_bSigner)      // ONLY if Encrypter to avoid CAPI issues.
      poidTdes = new AsnOid(rc2_cbc);
   //AsnOid oidDh(id_dhStatic);
   //AsnOid oidDhPublicNumber(dh_public_number);

   SME(BTISetPreferredCSInstAlgs(&oidSha1, pSignOid, pKeyEncryptOid, poidTdes));
   // set the local key alg
   //SME(SetLocalKeyAlg(&oidDhPublicNumber));

   if (pSignOid)
      delete pSignOid;
   if (pEncryptOid)
      delete pEncryptOid;
   if (poidTdes)
      delete poidTdes;
   if (pKeyEncryptOid)
      delete pKeyEncryptOid;

   SME_FINISH_CATCH
}




//////////////////////////////////////////////////////////////////////////
// DecodeCertificate accepts a pointer to a Certificate that will
// receive the decoded certificate.  It needs the buffer containing
// the encoded certificate.  It returns a pointer to the issuer,
// a pointer to the subject key info alg id, and a pointer to the subject
// public key.
SM_RET_VAL CSM_Capi::DecodeCertificate(CSM_Buffer *pEncodedCert,
      Certificate *pSnaccCertificate, Name **ppIssuer,
      AlgorithmIdentifier **ppAlgID, AsnBits **ppY)
{
   SME_SETUP("CSM_Capi::DecodeCertificate");

   if ((pEncodedCert == NULL) || (pSnaccCertificate == NULL)
         || (ppIssuer == NULL) || (ppAlgID == NULL) ||
         (ppY == NULL))
      SME_THROW(SM_MISSING_PARAM, NULL, NULL);

   // decode the certificate
   DECODE_BUF(pSnaccCertificate, pEncodedCert);

   if (*ppAlgID != NULL)
      delete *ppAlgID;
   if ((*ppAlgID = new AlgorithmIdentifier) == NULL)
      SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
   **ppAlgID = pSnaccCertificate->toBeSigned.subjectPublicKeyInfo.algorithm;
   if (*ppAlgID == NULL)
      SME_THROW(SM_CERT_DEC_ERROR, "Certificate missing subj pub key alg",
            NULL);
   *ppIssuer = &pSnaccCertificate->toBeSigned.issuer;
   if (*ppIssuer == NULL)
      SME_THROW(SM_CERT_DEC_ERROR, "Certificate missing issuer", NULL);
   *ppY = &(pSnaccCertificate->toBeSigned.subjectPublicKeyInfo.subjectPublicKey);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

   return SM_NO_ERROR;
}


//////////////////////////////////////////////////////////////////////////
// This CTI will override BTIFindAlgIds because in CEA and KEA's
// case, we only want to compare OIDs and are not interested in 
// comparing the parameters part of the AlgId
bool CSM_Capi::BTIFindAlgIds(CSM_AlgVDA *pdigestAlgID, 
            CSM_AlgVDA *pdigestEncryptionAlgID,
            CSM_AlgVDA *pkeyEncryptionAlgID,
            CSM_AlgVDA *pcontentEncryptionAlgID)
{
   CSM_Alg *ptmpCEAlgID = NULL;
   CSM_Alg *ptmpKEAlgID = NULL;
   bool bRet = false;

   SME_SETUP("CSM_Capi:BTIFindAlgIds");

   // if we have a content encryption AlgId, create a temporary AlgID with
   // only the OID from the one we got from the caller
   if (pcontentEncryptionAlgID)
   {
      AsnOid tmpoid = (*(pcontentEncryptionAlgID->AccessSNACCId()));
      if ((ptmpCEAlgID = new CSM_Alg(tmpoid)) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "couldn't duplicate CEA OID", NULL);
   }

   // if we have a key encryption AlgId, create a temporary AlgID with
   // only the OID from the one we got from the caller
   if (pkeyEncryptionAlgID)
   {
      AsnOid tmpoid = (*(pkeyEncryptionAlgID->AccessSNACCId()));
      if ((ptmpKEAlgID = new CSM_Alg(tmpoid)) == NULL)
         SME_THROW(SM_MEMORY_ERROR, "couldn't duplicate KEA OID", NULL);
   }

   // call the lolevel BTIFindAlgIds with our modified CEA and/or KEA AlgId
   SME(bRet = CSM_BaseTokenInterface::BTIFindAlgIds(pdigestAlgID, 
         pdigestEncryptionAlgID, ptmpKEAlgID, ptmpCEAlgID));

   // delete the modified CE and/or KE Alg ID if it exists (cleanup)
   if (ptmpCEAlgID)
      delete ptmpCEAlgID;
   if (ptmpKEAlgID)
      delete ptmpKEAlgID;

   SME_FINISH_CATCH


   return bRet;
}


//
//
CSM_TokenInterface *CSM_Capi::AddLoginStatic(
      char *lpszCertSubjectName, 
      char *lpszProviderName,
      CSM_MsgCertCrls *&pCertPath,
      bool bUseInternalPublicKey, 
      char *lpszPin,
      long lSocket,
      char *pszFlag)
{
   CSM_TokenInterface *pTokenInterface=NULL;
   CSM_AlgLstVDA *pDigestAlgs=NULL;
   CSM_AlgLstVDA *pKeyEncryption=NULL;
   CSM_AlgLstVDA *pDigestEncryption=NULL;
   CSM_AlgLstVDA *pContentEncryption=NULL;
   AlgorithmIdentifier *pAlgID=NULL;
   CSM_Capi *pCapi=NULL;
   char lpszTmpId[100];
   static int iCapiCtilCount=1;


   SME_SETUP("CSM_Capi::AddLoginStatic");


   if (pCapi == NULL)
   {  
      // THIS MEMORY will be returned in the CSM_Tokeninterface *.
      // generate a new FREE CTI class
      if ((pCapi = new CSM_Capi(rsa)) == NULL)    // DEFAULT DSA
         SME_THROW(SM_MEMORY_ERROR, "AddLoginStatic: bad new CSM_Capi.", NULL);
         // CSM_Capi constructor set's Alg IDs
   }

   pCapi->m_bUseInternalPublicKey = bUseInternalPublicKey; // DEBUG use only.
   pCapi->m_lpszPin = lpszPin;
   pCapi->m_lSocket = lSocket;
   if (pszFlag != NULL && strcmp(pszFlag, "signer") == 0)
      pCapi->m_bSigner = true;
   else if (pszFlag != NULL && strcmp(pszFlag, "encrypter") == 0)
      pCapi->m_bSigner = false;

   sprintf(lpszTmpId, "Capi%d", iCapiCtilCount++);
   // store the prefix
   pCapi->m_pszPrefix = strdup(lpszTmpId);
   // RWC; Set custom parameters from cert algorithm if necessary.
   // pAlgID was set by GetParamsAndY.  We store the parameters in
   // the instance so they may be used as necessary later on
   pCapi->BTIGetAlgIDs(&pDigestAlgs, &pDigestEncryption, 
       &pKeyEncryption, &pContentEncryption);   

   if (pDigestAlgs)
   {
      delete pDigestAlgs;
      pDigestAlgs = NULL;
   }
   if (pDigestEncryption)
   {
      delete pDigestEncryption;
      pDigestEncryption = NULL;
   }
   if (pKeyEncryption)
   {
      delete pKeyEncryption;
      pKeyEncryption = NULL;
   }
   if (pContentEncryption)
   {
      delete pContentEncryption;
      pContentEncryption = NULL;
   }
   if (pAlgID)
       delete pAlgID;

   pCapi->SMTI_Login(lpszCertSubjectName, lpszProviderName);
    if (pCapi->m_pSignerCertContext)
    {
       CSM_Buffer AAA((const char *)
           pCapi->m_pSignerCertContext->pbCertEncoded, 
           pCapi->m_pSignerCertContext->cbCertEncoded);
       pCertPath = new CSM_MsgCertCrls;
       CSM_CertificateChoice *pCert=new CSM_CertificateChoice(AAA);
       if (pCert)
       {
          pCertPath->AddCert(pCert);    // MEMORY taken by "AddCert"
       }    // END IF pCert
    }       // END IF m_pSignerCertContext
    
   pTokenInterface = pCapi;  // setup for generic load into instance array

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH


   return(pTokenInterface);
}

// determines if preferred oid is RSA (which is key transfer) and returns false, else this
// returns true its a key agreement
bool CSM_Capi::SMTI_IsKeyAgreement() 
{  
   bool keyAgree = false;
   AsnOid *oidKE = NULL;

   oidKE = GetPrefKeyEncryption();
   /*if (*oidKE == rsa || *oidKE == AsnOid("1.2.840.113549.1.2") ||
       *oidKE == rsaEncryption)
   {
      keyAgree = false;
   }*/

   // clean up oid
   if (oidKE)
      delete oidKE;

   return (keyAgree);
}

//
//
bool CSM_Capi::bInTestDirectory()
{
   bool bResult=false;
   char *lpszError=NULL;

#ifdef DEBUG_PRINT
   char current_directory[1024]; 
   char *ptr;
   if (getcwd(current_directory, 1024) != 0)
   {
       if ((ptr=strstr(current_directory, "test")) != NULL &&
            strcmp(ptr, "test") == 0)     // BE sure at end of dir name.
       {
           SME_SETUP("CSM_Capi::bInTestDirectory");
           CSM_Buffer AA("this is a testDir", strlen("this is a testDir"));
           AA.ConvertMemoryToFile("./sm_capi/DataOut/testDir.out");  // BE sure this dir exists.
           bResult = true;
           SME_FINISH
           SME_CATCH_SETUP
           SME_CATCH_FINISH_C2(lpszError);
           if (lpszError)
              free(lpszError);  //IGNORE error, DO NOT SET bResult.
       }
   }
#endif      //DEBUG_PRINT
   return(bResult);
}

_END_CERT_NAMESPACE

#ifndef NO_DLL
    using namespace CERT;
    using namespace CTIL;
    using namespace SNACC;
extern "C" {

long Make_argv(char *string, int *pargc, char ***pargv);
void Delete_argv(int argc, char **pargv);

SM_CAPIDLL_API SM_RET_VAL DLLBuildTokenInterface(CSM_CtilMgr &Csmime, 
    char *lpszBuildArgs)
{
    SM_RET_VAL status = 0;
    int argc1=0;
    char **argv1;
    char ptr[30];
    char *lpszPin=NULL;
    char *pszFlag=NULL;
    long lSocket=1;
    CSM_MsgCertCrls *pCertPath=NULL;

    SME_SETUP("DLLBuildTokenInterface");
    memset(ptr, '\0', 30);
    if (lpszBuildArgs && strlen(lpszBuildArgs))
    {
      for (int i=0; i < (int)strlen("sm_CapiDLL"); i++)
        ptr[i] = (char)toupper(lpszBuildArgs[i]);
      // Preliminary check that this request is for our library.
      if (strncmp(ptr, "SM_CAPIDLL", strlen("SM_CAPIDLL")) == 0)
      {
        Make_argv(lpszBuildArgs, &argc1, &argv1);

        char *lpszCertSubjectName=NULL;
        char *lpszProviderName=NULL;
        CSM_TokenInterface  *pTokenInterface;
        bool bUseInternalPublicKey = false;

        if (argc1 > 1)
            lpszCertSubjectName = argv1[1];
        if (argc1 > 2)
            lpszProviderName = argv1[2];
        if (argc1 > 3 && strcmp(argv1[3], "UseInternalPublicKey") == 0)
           bUseInternalPublicKey = true;
        if (argc1 > 3)
        {
           char *ptr2;
           for (int ii=3; ii < argc1; ii++)
           {
              if ((ptr2=strstr(argv1[ii], "PIN=")) != NULL ||
                  (ptr2=strstr(argv1[ii], "pin=")) != NULL)
              {
                 lpszPin = strdup(&ptr2[4]);
                 if ((ptr2=strchr(lpszPin, ' ')) != NULL)
                    *ptr2 = '\0';   // Terminate string after PIN, if necessary.
              }      // END if PIN= as arg
              else if ((ptr2=strstr(argv1[ii], "SOCKET=")) != NULL ||
                  (ptr2=strstr(argv1[ii], "socket=")) != NULL)
              {
                 lSocket = atoi(&ptr2[7]);
              }      // END if PIN= as arg
              else if ((ptr2=strstr(argv1[ii], "FLAG=")) != NULL ||
                  (ptr2=strstr(argv1[ii], "flag=")) != NULL)
              {
                 pszFlag = strdup(&ptr2[5]);
              }      // END if FLAG= as arg
           }         // END for (argc1 > 3)
        }            // END 3 args
        pTokenInterface  = CSM_Capi::AddLoginStatic(lpszCertSubjectName, 
            lpszProviderName, pCertPath, bUseInternalPublicKey, lpszPin, 
            lSocket, pszFlag);
        char lpszCAPIIdName[1000];
        strcpy(lpszCAPIIdName, "CAPI");
        if (lpszCertSubjectName)
           strcat(lpszCAPIIdName, lpszCertSubjectName);    
        if (pszFlag)       // IN Case we have 2 SAME DNs: signer/encrypter. 
           strcat(lpszCAPIIdName, pszFlag);
                 // FOR DataKey, this will indicate either encyrpter/signer.
                 // For other CSP indications, it will probably be subject DNs.
        GLOBALAddLoginFinish(Csmime, pTokenInterface, lpszCAPIIdName, pCertPath);

        Delete_argv(argc1, argv1);

        if ( pCertPath )
           delete pCertPath;

        if (pszFlag)
           free(pszFlag);
      }
      else
      {
        status = -1;
        std::cout << "DLL1BuildTokenInterface failed!!!\n";
      }
    }
    else    // if buildargs present
    {
        CSM_Capi *pF3TokenInterface;
          if ((pF3TokenInterface = new CSM_Capi(rsa)) == NULL)    // DEFAULT DSA
             SME_THROW(SM_MEMORY_ERROR, NULL, NULL);
          AsnOid RSA(rsa);
          pF3TokenInterface->SetDefaultOIDs(&RSA);  // LOAD 2nd set of algs for verify.
          pF3TokenInterface->m_pszPrefix = strdup("CapiNULL");
          GLOBALAddLoginFinish(Csmime, pF3TokenInterface, pF3TokenInterface->m_pszPrefix, NULL);
    }       // END if buildargs present.

    SME_FINISH
    SME_CATCH_SETUP
      // catch/cleanup logic as necessary
    SME_CATCH_FINISH

    return(status);
}


SM_CAPIDLL_API char * DLLMallocDiag()
{
	return((char *) calloc(1,1));
}

SM_CAPIDLL_API char * DLLGetId()
{
    return(strdup("sm_CapiDLL"));
}

}   //extern "C"

#endif      //NO_DLL



#ifdef FULL_MESSAGE_LEVEL_ENCRYPT_NOT_USED
///////////////////////////////////////////////////////////////////////////////
long CSM_Capi::CapiMsgEncryptEncode(CSM_Buffer &CertBuf)
{
   long status=0;
   PCCERT_CONTEXT pRecipientCert;
   PCCERT_CONTEXT RecipientCertArray[1];
   DWORD EncryptAlgSize;
   CRYPT_ALGORITHM_IDENTIFIER EncryptAlgorithm;
   CRYPT_ENCRYPT_MESSAGE_PARA EncryptParams;
   DWORD EncryptParamsSize;
   BYTE*    pbEncryptedBlob;
   DWORD    cbEncryptedBlob;

   pRecipientCert = GetRecipientCert(CertBuf);
   RecipientCertArray[0] = pRecipientCert;

   //--------------------------------------------------------------------
   // Initialize the algorithm identifier structure.
   EncryptAlgSize = sizeof(EncryptAlgorithm);
   //--------------------------------------------------------------------
   // Initialize the structure to zero.
   memset(&EncryptAlgorithm, 0, EncryptAlgSize);
   //--------------------------------------------------------------------
   // Set the necessary member.
   EncryptAlgorithm.pszObjId = szOID_RSA_RC2CBC;
   //--------------------------------------------------------------------
   // Initialize the CRYPT_ENCRYPT_MESSAGE_PARA structure. 
   EncryptParamsSize = sizeof(EncryptParams);
   memset(&EncryptParams, 0, EncryptParamsSize);
   EncryptParams.cbSize =  EncryptParamsSize;
   EncryptParams.dwMsgEncodingType = MY_ENCODING_TYPE;
   EncryptParams.hCryptProv = this->m_hCryptProv;
   EncryptParams.ContentEncryptionAlgorithm = EncryptAlgorithm;

   //--------------------------------------------------------------------
   // Call CryptEncryptMessage.

   //RWC:TBD: fix to enter data through CSM_Buffer param and return data 
   //  through CSM_Buffer. ALSO, must add const CSM_Buffer *pCertBuf=NULL
   //  to SMTI_GenerateEMEK(...) for ALL CTILs (base...)
   unsigned char *pbContent=(unsigned char *)"blobasdfasdfasdf           df";
   unsigned long cbContent=20;
   if(CryptEncryptMessage(&EncryptParams, 1, RecipientCertArray, pbContent,
             cbContent, NULL, &cbEncryptedBlob))
      pbEncryptedBlob = (BYTE*)malloc(cbEncryptedBlob);
   //--------------------------------------------------------------------
   // Call CryptEncryptMessage again to encrypt the content.

   if(cbEncryptedBlob && 
      CryptEncryptMessage(&EncryptParams, 1, RecipientCertArray,
             pbContent, cbContent, pbEncryptedBlob, &cbEncryptedBlob))
   {
      status = 0;
   }
   else
   {
      status = -1;
   }

   return(status);
}


//////////////////////////////////////////////////////////////////////////
HCRYPTKEY CSM_Capi::ComputeInternalPasswordKey()
{
   HCRYPTKEY hKey=0; 
   HCRYPTHASH hHash=0;
   char szPass[100];

   SME_SETUP("CSM_Capi::ComputeInternalPasswordKey");
   szPass[0] = 'C';
   szPass[0] = 'A';
   szPass[0] = 'P';
   szPass[0] = 'I';
   szPass[0] = 'd';
   szPass[0] = 'd';
   szPass[0] = 'd';
   szPass[0] = 'd';
   szPass[0] = 'd';
   szPass[0] = 'd';
   szPass[0] = 'd';
   szPass[0] = 'd';
   szPass[0] = 'd';
   szPass[0] = '\0';
   if(!CryptCreateHash(this->m_hCryptProv, CALG_MD5, 0, 0, &hHash))
   {
       SME_THROW(22, "Bad CSM_Capi::ComputeInternalPasswordKey: CryptCreateHash(...).", NULL);
   }

   //--------------------------------------------------------------------
   // Hash the password. 
   if(!CryptHashData(hHash,  (BYTE *)szPass, strlen(szPass), 0))
   {
       SME_THROW(22, "Bad CSM_Capi::ComputeInternalPasswordKey: CryptHashData(...).", NULL);
   }
   //--------------------------------------------------------------------
   // Derive a session key from the hash object. 
   if(!CryptDeriveKey(this->m_hCryptProv,  CALG_RC2, hHash, CRYPT_EXPORTABLE, &hKey))
   {
       SME_THROW(22, "Bad CSM_Capi::ComputeInternalPasswordKey: CryptDeriveKey(...).", NULL);
   }

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return(hKey);
}


#endif    // FULL_MESSAGE_LEVEL_ENCRYPT_NOT_USED

#include "BuildContainers.h"     // DataKey smartcard specific include.
typedef int (*DK_Initialize_DEF)(); 
typedef int (*DK_Session_DEF)(int slot); 
typedef int (*DK_Login_DEF)(char *Pin); 
typedef int (*DK_AddCertToSystem_DEF)(char *containername); 
typedef int (*DK_AddCACertToSystem_DEF)(char *label); 
typedef void(*DK_Finalize_DEF)(); 
void CSM_Capi::OPTIONAL_DataKey_CertificateLoads()
{
   DK_Initialize_DEF pDK_Initialize;
   DK_Session_DEF pDK_Session;
   DK_Login_DEF pDK_Login;
   DK_AddCertToSystem_DEF pDK_AddCertToSystem;
   DK_AddCACertToSystem_DEF pDK_AddCACertToSystem;
   DK_Finalize_DEF pDK_Finalize;
   //int slotnbr=1;
   char *lpszPin=NULL;     // RWC; try with nothing to see if user is prompted.

   SME_SETUP("CSM_Capi::OPTIONAL_DataKey_CertificateLoads");
   if (m_lpszPin == NULL)
      return;     // Assume not available, or already loaded.
   // LOAD module, if possible.
   if (m_hDataKeyModule == NULL)  //ONLY load once
      m_hDataKeyModule = LoadLibrary(OPTIONAL_DataKey_DLLFileName);
   if (m_hDataKeyModule != NULL)
   {
      // GET individual function addresses to invoke.
      pDK_Initialize =
           (DK_Initialize_DEF)GetProcAddress(m_hDataKeyModule, 
           "DK_Initialize");
      pDK_Session  =
           (DK_Session_DEF)GetProcAddress(m_hDataKeyModule, 
           "DK_Session");
      pDK_Login =
           (DK_Login_DEF)GetProcAddress(m_hDataKeyModule, 
           "DK_Login");
      pDK_AddCertToSystem =
           (DK_AddCertToSystem_DEF)GetProcAddress(m_hDataKeyModule, 
           "DK_AddCertToSystem");
      pDK_AddCACertToSystem =
           (DK_AddCACertToSystem_DEF)GetProcAddress(m_hDataKeyModule, 
           "DK_AddCACertToSystem");
      pDK_Finalize = 
           (DK_Finalize_DEF)GetProcAddress(m_hDataKeyModule, 
           "DK_Finalize");

      // NEXT, invoke the functions to perform the certificate loads.
      if (pDK_Initialize && pDK_Session && pDK_Login && pDK_AddCertToSystem &&
          pDK_AddCACertToSystem)    // check that all are present.
      {
        if ((pDK_Initialize)() == DK_OK)
        {
           if ((pDK_Session)(this->m_lSocket) != DK_OK)
           {
             return;      // assume not available.
           }      // END if pDK_Session
           // PIN MUST BE identified, the DataKey DLL does not auto-
           //  prompt as the CAPI I/F does.
           if ((pDK_Login)(m_lpszPin) == DK_OK)
           {
              (pDK_AddCertToSystem)(DataKey_SignerKeyContainerName);
              (pDK_AddCertToSystem)(DataKey_EncryptKeyContainerName);
              (pDK_AddCACertToSystem)(DataKey_CAKeyContainerName);
              (pDK_Finalize)(); // close session (hopefully leaving CAPI open)
              m_bDataKeyCertificatesLoaded = true;
           }      // IF login OK
           else
           {
              SME_THROW(22, "Bad DataKey pDK_Login call (possibly password?)!",
                        NULL);
           }   // END if login OK
        }      // END if pDK_Initialize
      }        // END if all function pointers loaded.
      //RWC;ONLY UNLOAD AT END, otherwise it causes crash upon any exception
      //RWC;  in DataKey CSP.FreeLibrary(m_hDataKeyModule);
   }           // END if

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH
}              // END OPTIONAL_DataKey_CertificateLoads(...)

// EOF sm_capi.cpp
