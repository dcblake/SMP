//  sm_CryptoKeysDsa.cpp
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#endif

#include "sm_CryptoKeysDsaExport.h"
_BEGIN_CERT_NAMESPACE
using namespace SNACC;

#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif


//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CryptoKeysDsaExport::GetPublicKey()        
{

   SME_SETUP("CSM_CryptoKeys::GetFree3DSAPublicKey");

   SME_FINISH_CATCH

   return m_FreeCTI.GetDSAY();
}

/////////////////////////////////////////////////////////////////////////////
void CSM_CryptoKeysDsaExport::ExtractDSAParams(CSM_Buffer &Parameters, CSM_Buffer *&pDSAP, 
    CSM_Buffer *&pDSAQ, CSM_Buffer *&pDSAG)
{
   SME_SETUP("CSM_Free3::ExtractParams");

   FREE_DSAParameters snaccDSAParams;
      DECODE_BUF((&snaccDSAParams), &Parameters);
      // extract P
      pDSAP = CSM_Free3::ComputeBigIntegerBuf(snaccDSAParams.p, 128);
      // extract Q
      pDSAQ = CSM_Free3::ComputeBigIntegerBuf(snaccDSAParams.q, 20);
      // extract G
      pDSAG = CSM_Free3::ComputeBigIntegerBuf(snaccDSAParams.g, 128);

   SME_FINISH
   SME_CATCH_SETUP
      // catch/cleanup logic as necessary
   SME_CATCH_FINISH

}

/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_CryptoKeysDsaExport::GenerateKeys(CSM_Buffer *pbufferX, 
      CSM_Buffer *pbufferY, CSM_Buffer *pbufferP, CSM_Buffer *pbufferG, 
      CSM_Buffer *pbufferQ, int nKeyBits, 
      bool bReadParameters, CSM_Buffer *pbufferParams)        
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   bool bGenParams = false;
   Integer *p=NULL, *q=NULL, *g=NULL;
   CSM_SFLDSAPrivateKey *x = NULL;
   byte b[2048];
   unsigned int nLen;

   SME_SETUP("CSM_CryptoKeysDsaExport::GenerateKeys");

   if (nKeyBits > 0)
      bGenParams = true;      // ONLY if keybits are present.
   if ((!bGenParams) || (bReadParameters))
                                  // only if keybits not present.
   {
       if (bReadParameters)
       {
         p = sm_Free3CryptoppBERDecode(pbufferP->Access(), pbufferP->Length());
         q = sm_Free3CryptoppBERDecode(pbufferQ->Access(), pbufferQ->Length());
         g = sm_Free3CryptoppBERDecode(pbufferG->Access(), pbufferG->Length());
       }
       else
       {
          // convert parameters to crypto++ integers
          pbufferP->ConvertFileToMemory();
          p = new Integer((const unsigned char*)pbufferP->Access(), 
                pbufferP->Length());
          pbufferQ->ConvertFileToMemory();
          q = new Integer((const unsigned char*)pbufferQ->Access(), 
               pbufferQ->Length());
          pbufferG->ConvertFileToMemory();
          g = new Integer((const unsigned char*)pbufferG->Access(), 
                pbufferG->Length());
       }
     
       // now we're ready to generate the key pair

       x = new CSM_SFLDSAPrivateKey(*(m_FreeCTI.m_pRng), *p, *q, *g);
   }
   else
   {
      x = new CSM_SFLDSAPrivateKey(*(m_FreeCTI.m_pRng), nKeyBits);
   }

   nLen = sm_Free3CryptoppDEREncode(*x->Access_x(), &b[0], 2048);
   pbufferX->Open(SM_FOPEN_WRITE);
   pbufferX->Write((char *)(&b[0]), nLen);
   pbufferX->Close();
   m_FreeCTI.SetX(*pbufferX);

   nLen = sm_Free3CryptoppDEREncode(*x->Access_y(), &b[0], 2048);
   pbufferY->Open(SM_FOPEN_WRITE);
   pbufferY->Write((char *)(&b[0]), nLen);
   pbufferY->Close();
   m_FreeCTI.SetDSAY(*pbufferY);

   // write params if necessary
   if ((bGenParams) && (!bReadParameters))
   {
      // write P to file
      nLen = sm_Free3CryptoppDEREncode(*x->Access_p(), &b[0], 2048);
      pbufferP->Open(SM_FOPEN_WRITE);
      pbufferP->Write((char *)(&b[0]), nLen);
      pbufferP->Close();
      // write Q to file
      nLen = sm_Free3CryptoppDEREncode(*x->Access_q(), &b[0], 2048);
      pbufferQ->Open(SM_FOPEN_WRITE);
      pbufferQ->Write((char *)(&b[0]), nLen);
      pbufferQ->Close();
      // write G to file
      nLen = sm_Free3CryptoppDEREncode(*x->Access_g(), &b[0], 2048);
      pbufferG->Open(SM_FOPEN_WRITE);
      pbufferG->Write((char *)(&b[0]), nLen);
      pbufferG->Close();
   }

   // encode parameters into file
   if (pbufferParams)
   {
      // parameters requested to be encoded into file
      FREE_DSAParameters snaccParams;
      //AsnInt BI;
      nLen = x->Access_p()->Encode(&b[0], 128);
      //BI.Set((const char *)&b[0], 128);

      snaccParams.p.Set(&b[0], 128, true);
      //RWC4;snaccParams.p.Set((const char *)BI, BI.Len());

      nLen = x->Access_q()->Encode(&b[0], 20);
      //BI.Set((const char *)&b[0], 20);
      snaccParams.q.Set(&b[0], 20, true);
      //RWC4;snaccParams.q.Set((const char *)BI, BI.Len());

      nLen = x->Access_g()->Encode(&b[0], 128);
      //BI.Set((const char *)&b[0], 128);
      snaccParams.g.Set(&b[0], 128, true);
      //RWC4;snaccParams.g.Set((const char *)BI, BI.Len());

      ENCODE_BUF_NO_ALLOC((&snaccParams), (pbufferParams));
   }

   if (x)
      delete x;
   if (p)
      delete p;
   if (q)
      delete q;
   if (g)
      delete g;

   SME_FINISH
   SME_CATCH_SETUP
   if (x)
      delete x;
   if (p)
      delete p;
   if (q)
      delete q;
   if (g)
      delete g;

   SME_CATCH_FINISH

   return lRet;
}

CSM_Buffer *CSM_CryptoKeysDsaExport::WrapPkcs12(
       char *pBufX, char *pBufY, char *pCertFile,             // File Names
       char *pszPassword, 
       CSM_Buffer &p, CSM_Buffer &q, CSM_Buffer &g,
       char *pencPrvKeyFilename)  //OPTIONAL input.
{
   CSM_Buffer *pPKCS12Buf = NULL;
   SME_SETUP("CSM_CryptoKeysDsaExport::WrapPkcs12");
   char *pTmpFile;
   CSM_Buffer *privKeyBuf = NULL;
   CSM_Buffer bufferX(pBufX);
   pTmpFile = tmpnam(NULL);
//#ifdef OPENSSL_PKCS12_ENABLED
   int lDEBUG_FLAG_ONLY = 1;
   if (lDEBUG_FLAG_ONLY == 1)   {
   VDAOpenSSLDSAPrivateKey DSAPrivKey;  //FORMAT specific to OpenSSL processing...
   CSM_Buffer bufferY(pBufY);

   // build the private key to the way the SSL code expects to see it
   DSAPrivKey.version = 0;
   DSAPrivKey.p.Set((const unsigned char *)p.Access(), p.Length());
   DSAPrivKey.q.Set((const unsigned char *)q.Access(), q.Length());
   DSAPrivKey.g.Set((const unsigned char *)g.Access(), g.Length());
   DSAPrivKey.pubKey.Set((const unsigned char *)bufferY.Access(), bufferY.Length());
   // integer asn encoded < 127 bytes, take off tag length
   DSAPrivKey.privKey.Set((const unsigned char *)&(bufferX.Access())[2], bufferX.Length() - 2);
   ENCODE_BUF(&DSAPrivKey, privKeyBuf);
       char pBufX2[100]; strcpy(pBufX2, pTmpFile); strcat(pBufX2, "AA");
   privKeyBuf->ConvertMemoryToFile(pBufX2);
   delete privKeyBuf; privKeyBuf = NULL;
   }    // lDEBUG_FLAG_ONLY
//#else
   /*else*/ {// lDEBUG_FLAG_ONLY
   PrivateKeyInfo DSAPrivKey;
   DSAWithSHA1Parameters Params;
   CSM_Buffer BufParams;
   DSAPrivKey.privateKeyAlgorithm.algorithm = id_dsa;
   Params.p.Set((const unsigned char *)p.Access(), p.Length());
   Params.q.Set((const unsigned char *)q.Access(), q.Length());
   Params.g.Set((const unsigned char *)g.Access(), g.Length());
   BufParams.Encode(Params);
   DSAPrivKey.privateKeyAlgorithm.parameters = new AsnAny;
   BufParams.Decode(*DSAPrivKey.privateKeyAlgorithm.parameters);
   DSAPrivKey.privateKey.Set(bufferX.Access(), bufferX.Length());
   
   ENCODE_BUF(&DSAPrivKey, privKeyBuf);
   privKeyBuf->ConvertMemoryToFile(pTmpFile);
   }    // lDEBUG_FLAG_ONLY
//#endif


   //RWC;TBD; now that we are no longer using OpenSSL, change parameter to CSM_Buffer
   //         to avoid file creation...
   pPKCS12Buf = CSM_CryptoKeysFree3Base::WrapPkcs12(
       pTmpFile, //SEND temporary processed private key.
       pCertFile, pszPassword, pencPrvKeyFilename );

   remove(pTmpFile);    // Delete temporary file.
   delete privKeyBuf;

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return pPKCS12Buf;
}


#ifdef CRYPTOPP_5_0

//
//
Integer *CSM_SFLDSAPrivateKey::Access_x() 
{
      //KeyClass &keyA=AccessKey();
      //PrivateKey &pubA=AccessPrivateKey();
      //DigestSigner &dsSigner = GetDigestSignatureScheme();//AccessDigestSignatureScheme();
      //dsSigner.GetPrivateKey().
      //dsSigner.SignDigest();
      //const DL_PrivateKey<T> &key = GetKeyInterface();
      //alg.Sign(params, key.GetPrivateExponent(), k, e, r, s);
      m_CSMx = AccessKey().GetPrivateExponent();
      //*px = GetDigestSignatureScheme().GetKeyInterface().GetPrivateExponent();
#ifdef _DEBUG_NOT_PRINTED
      ByteQueue bt, bt2, bt3, bt4;
      m_CSMx.DEREncode(bt);
      unsigned char ppp[2048]; 
      int len=bt.Get(ppp, 2048); 
      CSM_Buffer bufPrivateKey((char *)ppp, len);
      bufPrivateKey.ConvertMemoryToFile("./m_CSMx.bin");
      AccessKey().Save(bt2);
      len = bt2.Get(ppp, 2048); 
      bufPrivateKey.Set((char *)ppp, len);
      bufPrivateKey.ConvertMemoryToFile("./m_CSMx_Save.bin");
      DSAPublicKey pubKey(*this);
      pubKey.AccessPublicKey().Save(bt3);
      len = bt3.Get(ppp, 2048); 
      bufPrivateKey.Set((char *)ppp, len);
      bufPrivateKey.ConvertMemoryToFile("./m_CSMx_PublicExtract.bin");
      //
      DSAPrivateKey dsaX2(*Access_p(), *Access_q(), *Access_g(), m_CSMx);
      DSAPublicKey pubKey2(dsaX2);
      pubKey2.AccessPublicKey().Save(bt4);
      len = bt4.Get(ppp, 2048); 
      bufPrivateKey.Set((char *)ppp, len);
      bufPrivateKey.ConvertMemoryToFile("./m_CSMx2_PublicExtract.bin");
#endif //_DEBUG_NOT_PRINTED
      return &m_CSMx;
}   // END CSM_SFLDSAPrivateKey::Access_x()


//
//
Integer *CSM_SFLDSAPrivateKey::Access_y() 
{
#if !defined(CRYPTOPP_5_0) && !defined(CRYPTOPP_5_1)
    CryptoPP::DSAPublicKey pubKey(*this);
#else
    CryptoPP::DSA::Verifier pubKey(*this);
#endif
      ByteQueue bt;
      ByteQueue btKeyOnly;
      //pubKey.GetKey().GetKeyInterface().GetPublicElement().DEREncodeKey(bt);
      pubKey.AccessPublicKey().//GetPublicElement().DEREncodeKey(bt); //RWC;WORKS but produces ASN.1 encode X509PublicKey/SubjectPublicKeyInfo
                             Save(bt);
        //m_CSMy = AccessPublicKey().AccessPublicPrecomputation()/*GetPublicPrecomputation()*/; return &m_CSMy; 
        //AccessDigestSignatureScheme()
      unsigned char ppp[2048]; 
      int len=bt.Get(ppp, 2048); 
      CSM_Buffer bufPublicKey((char *)ppp, len);
#ifdef _DEBUG
      bufPublicKey.ConvertMemoryToFile("./m_CSMy.bin");
#endif  //_DEBUG
      //RWC;TBD;DECODE as SubjectPublicKeyInfo and extract ->subjectPublicKey as Integer...
      SubjectPublicKeyInfo snaccSubjectPublicKeyInfo;
      DECODE_BUF(&snaccSubjectPublicKeyInfo, &bufPublicKey);
      btKeyOnly.Put((unsigned char *)
                    snaccSubjectPublicKeyInfo.subjectPublicKey.data(), 
                    snaccSubjectPublicKeyInfo.subjectPublicKey.length());
      m_CSMy.BERDecode(btKeyOnly);
      return &m_CSMy;
}       // END CSM_SFLDSAPrivateKey::Access_y()

//
//
FREE_DSAParameters *CSM_SFLDSAPrivateKey::GetParams() 
{
    FREE_DSAParameters *psnaccParams=new FREE_DSAParameters;
    ByteQueue bt;
    AccessKey().AccessGroupParameters().Save(bt); 
    unsigned char ppp[2048]; 
    int len=bt.Get(ppp, 2048); 
    CSM_Buffer bufParams((char *)ppp, len);
    //bufParams.ConvertMemoryToFile("./BOBParams.bin");
    DECODE_BUF(psnaccParams, &bufParams);
    return psnaccParams; 
}       // END CSM_SFLDSAPrivateKey::GetParams()

//
//
Integer *CSM_SFLDSAPrivateKey::Access_p() 
{
    FREE_DSAParameters *psnaccParams=GetParams();
    if (psnaccParams)
    {
        m_CSMp = Integer/*.Set*/(psnaccParams->p.c_str(), psnaccParams->p.length());
        delete psnaccParams;
    }       // END if psnaccParams
    return &m_CSMp; 
}       // END CSM_SFLDSAPrivateKey::Access_p() //GP & AccessGroupParameters()
//
//
Integer *CSM_SFLDSAPrivateKey::Access_q()
{
    FREE_DSAParameters *psnaccParams=GetParams();
    if (psnaccParams)
    {
        m_CSMq = Integer/*.Set*/(psnaccParams->q.c_str(), psnaccParams->q.length());
        delete psnaccParams;
    }       // END if psnaccParams
        return &m_CSMq; 
}       // END CSM_SFLDSAPrivateKey::Access_q()

//
//
Integer *CSM_SFLDSAPrivateKey::Access_g()
{
    FREE_DSAParameters *psnaccParams=GetParams();
    if (psnaccParams)
    {
        m_CSMg = Integer/*.Set*/(psnaccParams->g.c_str(), psnaccParams->g.length());
        delete psnaccParams;
    }       // END if psnaccParams
        return &m_CSMg;
}       // END CSM_SFLDSAPrivateKey::Access_g()

#endif // CRYPTOPP_5_0

_END_CERT_NAMESPACE

// EOF sm_CryptoKeysDsa.cpp
