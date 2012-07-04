//  sm_CryptoKeysDH.cpp
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#include <string>
#ifdef WIN32
#pragma  warning( disable : 4512 4100 4511 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#endif
#include "sm_CryptoKeysDsaExport.h"
#include "sm_CryptoKeysDHExport.h"
#include "randpool.h"
RandomPool rndRandom3;
#ifdef WIN32
#pragma  warning( default: 4512 4100 4511 )  // IGNORE warnings from MS includes? 
#endif
_BEGIN_CERT_NAMESPACE
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
CSM_Buffer* CSM_CryptoKeysDHExport::GetPublicKey()        
{
   CSM_Buffer *pbufPublicKey=NULL;
   SME_SETUP("CSM_CryptoKeys::GetFree3DHPublicKey");

   pbufPublicKey = m_Free3CTI.GetBufY();
   SME_FINISH_CATCH

   return (pbufPublicKey);
}

/////////////////////////////////////////////////////////////////////////////
// note : bufferQ parameter not used with DH
SM_RET_VAL CSM_CryptoKeysDHExport::GenerateKeys(CSM_Buffer *pbufferX, 
      CSM_Buffer *pbufferY, CSM_Buffer *&pbufferP, CSM_Buffer *&pbufferG, 
      CSM_Buffer *&pbufferQ, int nKeyBits, 
      bool bReadParameters, CSM_Buffer *pbufferParams)        
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   bool bGenParams = false;
   Integer *p = NULL;
   Integer *g = NULL;
   byte b[3000];
   unsigned int nLen;
   Integer y;

   SME_SETUP("GenerateDHKeys");

   if (nKeyBits > 0)
      bGenParams = true;      // ONLY if keybits are present.
   if ((!bGenParams) || (bReadParameters))
                                  // only if keybits not present.
   {
       if (bReadParameters)
       {
         p = sm_Free3CryptoppBERDecode(pbufferP->Access(), pbufferP->Length());
         g = sm_Free3CryptoppBERDecode(pbufferG->Access(), pbufferP->Length());
       }
       else
       {
          // convert parameters to crypto++ integers
          pbufferP->ConvertFileToMemory();
          p = new Integer((const unsigned char*)pbufferP->Access(), 
                pbufferP->Length());
          pbufferG->ConvertFileToMemory();
          g = new Integer((const unsigned char*)pbufferG->Access(), 
                pbufferG->Length());
       }
       if (m_pDH == NULL)
            m_pDH = new DH(*p, *g); // create based on preset params  
   }
   else
   {
      m_pDH = new DH((RandomNumberGenerator &)rndRandom3, nKeyBits);
      p = new Integer(m_pDH->GetGroupParameters().GetModulus());
      g = new Integer(m_pDH->GetGenerator());
   }

   // generate the key pair
   SecByteBlock priv1(m_pDH->PrivateKeyLength());
   SecByteBlock pub1(m_pDH->PublicKeyLength());
   m_pDH->GenerateKeyPair(*(m_Free3CTI.m_pRng), priv1, pub1);
#ifdef VALIDATE_KEY
    {
    //RWC;in filters.h;member_ptr<BufferedTransformation> outQueue;
        ByteQueue bt;
        ByteQueue bt2;
        DH *pDH2 = new DH(*p, *g);
        bool TestAgree;
       SecByteBlock priv2(pDH2->PrivateKeyLength());
       SecByteBlock pub2(pDH2->PublicKeyLength());

        pDH2->GenerateKeyPair(*(m_Free3CTI.m_pRng), priv2, pub2);
        SecByteBlock val(pDH->AgreedValueLength());
      TestAgree = pDH->Agree(val, priv1, pub1);
        if (!TestAgree)
            printf("TestAgree failed 1.\n");
      TestAgree = pDH->Agree(val, priv2, pub2);
        if (!TestAgree)
            printf("TestAgree failed 2.\n");
      TestAgree = pDH->Agree(val, priv1, pub2);
        if (!TestAgree)
            printf("TestAgree failed 3.\n");
      TestAgree = pDH->Agree(val, priv2, pub1);
        if (!TestAgree)
            printf("TestAgree failed 4.\n");
        //delete pRng;
        delete pDH2;
        //delete pRandomCipher;
    }
#else
    {
        SecByteBlock val(m_pDH->AgreedValueLength());
      bool TestAgree = m_pDH->Agree(val, priv1, pub1);
        if (!TestAgree)     // JUST test our own.
            printf("*********DH Key TestAgree failed**********.\n");
    }
#endif      // VALIDATE_KEY
    // RWC;execute storage of DH specific details; SHOULD NOT BE NECESSARY,
    //  BUT.... I cannot get this process to work if a new DH is generated
    //  even with the same p, g....  Pain in the neck!!!!!  This bt3 precom
    //  MUST be re-loaded each time an encryption/decryption is performed;
    //  I expect to be able to solve at some time in the future (either
    //  through our efforts or with the author of the crypto++3.0).
    ByteQueue bt3;
    CSM_Buffer bb;
    char buf[3000];
    int size;
#ifndef CRYPTOPP_5_0
    pDH->SavePrecomputation(bt3);
#endif  // CRYPTOPP_5_0
    size = bt3.Get((unsigned char *)&buf[0], 3000);
    bb.Set(buf, size);
    bb.ConvertMemoryToFile("./free_ab_DHPrecomp.dat");
    // decode the y value from b into y
#ifndef CRYPTOPP_5_0
    y.Decode(pub1.ptr, pub1.size);
#else  // CRYPTOPP_5_0
    y.Decode(pub1, pub1.m_size);
#endif      // CRYPTOPP_5_0
   // DEREncode the public value from Y back into b, then write it
   nLen = sm_Free3CryptoppDEREncode(y, &b[0], 3000);//y.DEREncode(&b[0]);
   pbufferY->Open(SM_FOPEN_WRITE);
   pbufferY->Write((char *)(&b[0]), nLen);
   pbufferY->Close();
   m_Free3CTI.SetBufY(*pbufferY);

   // TBD, had to make DH.x public to do this
  Integer xPRIV;
#ifndef CRYPTOPP_5_0
    xPRIV.Decode(priv1.ptr, priv1.size);
#else  // CRYPTOPP_5_0
    xPRIV.Decode(priv1, priv1.m_size);
#endif      // CRYPTOPP_5_0
  nLen = sm_Free3CryptoppDEREncode(xPRIV, &b[0], 3000);//y.DEREncode(&b[0]);
        //xPRIV.DEREncode(&b[0]);
   pbufferX->Open(SM_FOPEN_WRITE);
   pbufferX->Write((char *)(&b[0]), nLen);
   pbufferX->Close();
   m_Free3CTI.SetX(*pbufferX);

   // write params if necessary
   if (bGenParams)
   {
      // write P to file
      nLen = sm_Free3CryptoppDEREncode(m_pDH->GetGroupParameters().GetModulus(),
               &b[0], m_pDH->GetGroupParameters().GetModulus().MinEncodedSize());
      //nLen = sm_Free3CryptoppDEREncode(pDH->GetPrime(), &b[0], 2048);
            //pDH->GetPrime().DEREncode(&b[0]);
      if (pbufferP == NULL)
          pbufferP = new CSM_Buffer;
      pbufferP->Open(SM_FOPEN_WRITE);
      pbufferP->Write((char *)(&b[0]), nLen);
      pbufferP->Close();
      // write G to file
      nLen = sm_Free3CryptoppDEREncode(m_pDH->GetGenerator(), &b[0], 
          m_pDH->GetGenerator().MinEncodedSize());
        //pDH->GetGenerator().DEREncode(&b[0]);
      if (pbufferG == NULL)
          pbufferG = new CSM_Buffer;
      pbufferG->Open(SM_FOPEN_WRITE);
      pbufferG->Write((char *)(&b[0]), nLen);
      pbufferG->Close();
   }

   //RWC; ALWAYS re-set Q for return value, since not part of DH constructor
   //  DO NOT ASSUME incomming is valid..
   if (pbufferQ == NULL)
       pbufferQ = new CSM_Buffer;
   nLen = m_pDH->GetGroupParameters().GetSubgroupOrder().Encode(&b[0], 
          m_pDH->GetGroupParameters().GetSubgroupOrder().MinEncodedSize());
   pbufferQ->Set((const char *)&b[0], nLen);

   // encode parameters into file
   if (pbufferParams)
   {
      // parameters requested to be encoded into file
      DomainParameters snaccParams;
      // RWC; HERE WE MUST load into the ASN.1 buffer as a BigIntegerStr
      // RWC;  ASN.1 Integer data type, e.g. not 128 bytes of '0's with a '2'
      // RWC;  but strip off leading '0's.
      nLen = m_pDH->GetGroupParameters().GetModulus()/*GetPrime()*/.Encode(&b[0], 
               m_pDH->GetGroupParameters().GetModulus().MinEncodedSize());
      snaccParams.p.Set(&b[0], nLen);
      nLen = m_pDH->GetGenerator().Encode(&b[0], 
             m_pDH->GetGenerator().MinEncodedSize());
      snaccParams.g.Set(&b[0], nLen);
      if (pbufferQ)
         snaccParams.q.Set((unsigned char *)pbufferQ->Access(), pbufferQ->Length());
      pbufferParams->Encode(snaccParams);
   }        // END IF pbufferParams

   if (p)
      delete p;
   if (g)
      delete g;

   SME_FINISH
   SME_CATCH_SETUP
   if (p)
      delete p;
   if (g)
      delete g;

   SME_CATCH_FINISH

   return lRet;
}


//*****************************************************
CSM_Buffer *CSM_CryptoKeysDHExport::WrapPkcs12(
       char *pBufX, char *pBufY, char *pCertFile,             // File Names
       char *pszPassword, 
       CSM_Buffer &p, CSM_Buffer &g, CSM_Buffer &q, 
       char *pencPrvKeyFilename)  //OPTIONAL input.
{
   CSM_Buffer *pPKCS12Buf = NULL;
   CSM_Buffer bufferX(pBufX);

   SME_SETUP("CSM_CryptoKeysDHExport::WrapPkcs12");

   // SETUP DH private key, complete with DomainParameters (p, g, q) and
   //  the private key.
       DomainParameters snaccParams;
       CSM_Buffer privKeyBuf;
       snaccParams.p.Set((const unsigned char *)p.Access(), p.Length());
       snaccParams.g.Set((const unsigned char *)g.Access(), g.Length());
       //int nLen=m_pDH->GetGroupParameters().GetSubgroupOrder().Encode(&b[0], 128);
       snaccParams.q.Set((const unsigned char *)q.Access(), q.Length());

   PrivateKeyInfo DHPrivKey;
   CSM_Buffer BufParams;
   DHPrivKey.privateKeyAlgorithm.algorithm = dh_public_number;
   BufParams.Encode(snaccParams);
   DHPrivKey.privateKeyAlgorithm.parameters = new AsnAny;
   BufParams.Decode(*DHPrivKey.privateKeyAlgorithm.parameters);
   DHPrivKey.privateKey.Set(bufferX.Access(), bufferX.Length());

   privKeyBuf.Encode(DHPrivKey);
   char *pTmpFile = tmpnam(NULL);
   privKeyBuf.ConvertMemoryToFile(pTmpFile);


   //RWC;TBD; now that we are no longer using OpenSSL, change parameter to CSM_Buffer
   //         to avoid file creation...
   pPKCS12Buf = CSM_CryptoKeysFree3Base::WrapPkcs12(
       pTmpFile, //SEND temporary processed private key.
       pCertFile, pszPassword, pencPrvKeyFilename );


   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return pPKCS12Buf;
}       // END CSM_CryptoKeysDsaExport::WrapPkcs12(...)




_END_CERT_NAMESPACE


// EOF sm_CryptoKeysDH.cpp
