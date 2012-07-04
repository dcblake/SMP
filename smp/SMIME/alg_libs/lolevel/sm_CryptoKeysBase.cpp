//SM_FREE3_USED,SM_RSA_USED
//  sm_CryptoKeysBase.cpp
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#ifdef SM_RSA_USED
#include "sm_CryptoKeys.h"
#include "sm_CryptoKeysRsa.h"
#endif
#ifdef SM_FREE3_USED
#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4516 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#endif
#include "sm_CryptoKeysF3RsaExport.h"
#endif
#ifdef OPENSSL_PKCS12_ENABLED
extern "C" {
#include "SFLpkcs12_support.h"
}
#endif
//prototype
_BEGIN_CERT_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
CSM_CryptoKeysBase * CSM_CryptoKeysBase::CreateCryptoObject(AsnOid &AlgOid,
           CSM_CertificateChoice *pCert, char *lpszPassword)
{ 

   CSM_CryptoKeysBase *p_CryptoKey = NULL;

   SME_SETUP("CSM_CryptoKeysBase::CreateCryptoObject()");

   if (AlgOid == rsa)   // use RSA
      {}
   else if (AlgOid == dh_public_number)   // use FREE3 DH
      {}
   else if (AlgOid == id_dsa_with_sha1)   // use FREE3 DSA
      {}
   else 
      SME_THROW(22, NULL, NULL);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

#ifdef WIN32
   lpszPassword;pCert; //AVOIDS warning.
#endif // WIN32
   return p_CryptoKey;
}

CTIL::CSM_Buffer *CSM_CryptoKeysBase::WrapPkcs12(char *pBufX, char *pCertFile,
         char *pszPassword, char *pencPrvKeyFilename)  //OPTIONAL input.
{
   CTIL::CSM_Buffer *pPKCS12Buf = NULL;

   SME_SETUP("CSM_CryptoKeysBase::WrapPkcs12");

   char *pencPrvKeyFilename2=NULL;

   if (pencPrvKeyFilename == NULL)
   {
       pencPrvKeyFilename2 = tmpnam("pkcs");
   }
   else
   {
       pencPrvKeyFilename2 = pencPrvKeyFilename;
   }
#ifdef SM_FREE3_USED
#ifdef OPENSSL_PKCS12_ENABLED
   int lDEBUG_FLAG_ONLY = 1;
   if (lDEBUG_FLAG_ONLY == 1)   
   {
       char pBufX2[100]; strcpy(pBufX2, pBufX); strcat(pBufX2, "AA");
   if (SM_BuildPkcs12PrivateKey(
		pencPrvKeyFilename2, pszPassword, 
		pBufX2,   	pCertFile,
		NULL, 0, NULL, 0) == 0)
   {
        pPKCS12Buf = new CTIL::CSM_Buffer(pencPrvKeyFilename);
        pPKCS12Buf->Access();   // FORCE read of data.
   }
   } //lDEBUG_FLAG_ONLY
#else   //OPENSSL_PKCS12_ENABLED
   CSM_PrivDataLst PrivateKeyList;
   CSM_PrivData *pPrivData = &(*PrivateKeyList.append());
   CSM_Buffer *pTmpBufCert = &(*pPrivData->m_BufCertList.append());
   pTmpBufCert->SetFileName(pCertFile);
   pPrivData->m_BufPriv.SetFileName(pBufX);
   EncryptPKCS12PrivateKey(pPKCS12Buf, pszPassword, PrivateKeyList);
   if (pPKCS12Buf)
   {
        pPKCS12Buf->ConvertMemoryToFile(pencPrvKeyFilename2);
#ifdef _DEBUG
        CSM_PrivDataLst PrivateKeyList2;
        CSM_Free3::DecryptPKCS12PrivateKey(pPKCS12Buf, pszPassword, PrivateKeyList2);
#endif  //_DEBUG
   }
#endif
#endif  //SM_FREE3_USED
/*#ifdef WIN32
   pBufX; pCertFile; pszPassword; pencPrvKeyFilename;   // REMOVES warning.
#endif
   SME_THROW(22, "PKCS12 NOT SUPPORTED BY THIS CTIL.", NULL);
#endif*/
    if (pencPrvKeyFilename == NULL && pencPrvKeyFilename2 != NULL)
    {
        remove(pencPrvKeyFilename2);    // DELETE tmp file.
    }

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH
   return pPKCS12Buf;
}

_END_CERT_NAMESPACE

// EOF sm_CryptoKeysBase.cpp
