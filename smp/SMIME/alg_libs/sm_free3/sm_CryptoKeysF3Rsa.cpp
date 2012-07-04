//  sm_CryptoKeysF3Rsa.cpp
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#ifndef SM_FREE3_RSA_INCLUDED
#define SM_FREE3_RSA_INCLUDED
#endif  //SM_FREE3_RSA_INCLUDED

#ifdef SM_FREE3_RSA_INCLUDED
#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#endif

#include "sm_CryptoKeysF3RsaExport.h"
#include "rsa.h"     // From cryptopp3.
#include "rc2.h"     // From cryptopp3.
_BEGIN_CERT_NAMESPACE
using namespace SNACC;

#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif


//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CryptoKeysF3RsaExport::GetPublicKey()        
{

   SME_SETUP("CSM_CryptoKeysF3RsaExport::GetPublicKey");

       SME_THROW(22, "TBD", NULL);

   SME_FINISH_CATCH
      
   return NULL;
}

/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_CryptoKeysF3RsaExport::GenerateRsaKeys(CSM_Buffer *bufferX, CSM_Buffer *bufferY)        
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   byte b[2048];
   unsigned int nLen;
   long nKeyBits=2048;//RWC;1024;
   CryptoPP::ByteQueue  byteQueueBuffer;

   SME_SETUP("CSM_CryptoKeysF3RsaExport::GenerateKeys");

   /*
	RandomPool randPool;
	randPool.Put((byte *)seed, strlen(seed));

	RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
	HexEncoder privFile(new FileSink(privFilename));
	priv.DEREncode(privFile);
	privFile.Close();

	RSAES_OAEP_SHA_Encryptor pub(priv);
	HexEncoder pubFile(new FileSink(pubFilename));
	pub.DEREncode(pubFile);
	pubFile.Close();
    byteQueueBuffer.Put((unsigned char *)pRecipient->Access(), pRecipient->Length());
   */
#ifndef RWC_NOT_IN_CRYPTOPP3
   RSASSA_PKCS1v15_SHA_Signer rsaPriv(*(m_FreeCTI.m_pRng), nKeyBits);
   rsaPriv.DEREncode(byteQueueBuffer); 
   nLen = byteQueueBuffer.Get((unsigned char *)&b[0], 2048);
#endif
   bufferX->Set((char *)(&b[0]), nLen);
   //m_FreeCTI.SetX(bufferX);

#ifndef RWC_NOT_IN_CRYPTOPP3
   RSASSA_PKCS1v15_SHA_Verifier rsaPub(rsaPriv);
   rsaPub.DEREncode(byteQueueBuffer); 
   nLen = byteQueueBuffer.Get((unsigned char *)&b[0], 2048);
#endif
   bufferY->Open(SM_FOPEN_WRITE);
   bufferY->Write((char *)(&b[0]), nLen);
   bufferY->Close();
   //m_FreeCTI.SetRsaY(bufferY);
   //bufferX->ConvertMemoryToFile("i:\\devel.d\\tmp.d\\priv.out");
   //bufferY->ConvertMemoryToFile("i:\\devel.d\\tmp.d\\pub.out");


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return lRet;
}


CSM_Buffer *CSM_CryptoKeysF3RsaExport::WrapPkcs12(
       char *pBufX, char *pCertFile, // File Names
       char *pszPassword, 
       char *pencPrvKeyFilename)  //OPTIONAL input.
{
   CSM_Buffer *pPKCS12Buf = NULL;
   SME_SETUP("CSM_CryptoKeysF3RsaExport::WrapPkcs12");

   pPKCS12Buf = CSM_CryptoKeysFree3Base::WrapPkcs12(
       pBufX, pCertFile, pszPassword, pencPrvKeyFilename );

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return pPKCS12Buf;
}

_END_CERT_NAMESPACE

#endif  // SM_FREE3_RSA_INCLUDED
// EOF sm_CryptoKeysF3Rsa.cpp
