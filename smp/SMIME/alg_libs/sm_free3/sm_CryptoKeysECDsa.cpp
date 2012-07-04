//  sm_CryptoKeysECDsa.cpp
//
//  This class definition handles the specific CTILs supported by the SFL.
//  It attempts to provide a simpler interface to the crypto keys. 

#ifdef WIN32
#pragma  warning( disable : 4100 4245 4511 4512 4516 4663 4018 4244 4146 4097 ) 
                                    // IGNORE warnings from MS includes? 
                                    //  (?WHY present in MSVC?).
#endif

#include "sm_free3.h"       // TO GET Crypto version define
#ifdef CRYPTOPP_5_0

#include "sm_CryptoKeysECDsaExport.h"
#include "eccrypto.h"
#include "ecp.h"
#include "ec2n.h"
#include "oids.h"
#include "hex.h"
#include "randpool.h"
RandomPool rndRandom4;

_BEGIN_CERT_NAMESPACE
using namespace SNACC;

#ifdef WIN32
#pragma  warning( default: 4512 4511 )  // IGNORE warnings from MS includes? 
#endif


/////////////////////////////////////////////////////////////////////////////
CSM_Buffer  *CSM_CryptoKeysECDsaExport::DetermineECParams(
                CSM_ECParams &ECParams,      // IN, parameters to cnovert.
                bool &bECPFlag)              // OUT, indicates ECP or EC2N
{
   CSM_Buffer *pbufferParams=NULL;
   ECIES<ECP>::Decryptor     *pcprivECP2 = NULL;
   ECIES<EC2N>::Decryptor     *pcprivEC2N = NULL;
   
   SME_SETUP("CSM_CryptoKeysECDsaExport::DetermineECParams");

//#if defined(_WIN32) || (defined(CRYPTOPP_5_0) && !defined(CRYPTOPP_5_1))
#if defined(CRYPTOPP_5_0) 
    CryptoPP::ByteQueue bt, bt2, bt3, bt4; //BufferedTransformation;
    unsigned char PBufChar[2048];
    int len;

    bECPFlag=true;  // ECP or EC2N type of Elliptic Curve.
    if (ECParams.m_pECBuiltInOID)
    {       // ATTEMPT TO HANDLE Crypto++ Built-in OID
        OID *pAnOID = ECDSA_StringToOid(ECParams.m_pECBuiltInOID, bECPFlag);
        if (pAnOID)
        {
            CryptoPP::ByteQueue bt;
            if (bECPFlag)
            {
                pcprivECP2 = new ECIES<ECP>::Decryptor(rndRandom4, *pAnOID);
            }   // IF bECPFlag
            else
            {
                pcprivEC2N = new ECIES<EC2N>::Decryptor(rndRandom4, *pAnOID);
            }   // END IF bECPFlag
            delete pAnOID;
        }       // IF pAnOID (for ECP/EC2N, built-in support)
        else
        {
            char pszBuf[1024];
            sprintf(pszBuf, "Built-in EC OID not supported, %s!", ECParams.m_pECBuiltInOID);
            SME_THROW(22, pszBuf, NULL);
        }       // END IF pAnOID
    }           // IF m_pECBuiltInOID
    else if (ECParams.GetEncodedECParams())
    {       // HANDLE ASN.1 encoded Parameter(s)
        const CSM_Buffer *pBufParams=ECParams.GetEncodedECParams();
        CryptoPP::ByteQueue bt5;
        bt5.Put((unsigned char *)pBufParams->Access(), pBufParams->Length());
        bECPFlag = true;        // ASSUME ECP type for encoded params (may not be true).
        try {
		   //RWC5;CRYPTOPP_5_1
           //RWC;CryptoPP::Integer cppInt(bt5);
           pcprivECP2 = new ECIES<ECP>::Decryptor;
           pcprivECP2->AccessKey().AccessGroupParameters().BERDecode(bt5);
        }
        catch (...){ bECPFlag = false; }       // error indicates EC2N type, not ECP (Oh Well!)
        if (!bECPFlag)                         // NOW, attempt EC2N ONLY if ECP fails.
        {                                      //  (if EC2N fails, the failure is fatal!)
            CryptoPP::ByteQueue bt6;
            bt6.Put((unsigned char *)pBufParams->Access(), pBufParams->Length());
			//RWC5;CRYPTOPP_5_1
                //RWC;CryptoPP::Integer cppInt(bt6);
                pcprivEC2N = new ECIES<EC2N>::Decryptor;
                pcprivEC2N->AccessKey().AccessGroupParameters().BERDecode(bt6);
        }
    }
    else if (ECParams.m_pszModulus_p)
    {       // HANDLE ECP individual parameter strings from user.
	    Integer modulus(ECParams.m_pszModulus_p);
            //"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFh");
	    Integer b(ECParams.m_pszB);
            //"5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604Bh");
	    Integer x(ECParams.m_pszGx);
            //"6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296h");
	    Integer y(ECParams.m_pszGy);
            //"4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5h");
	    Integer r(ECParams.m_pszR);
            //"FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
	    Integer k(1);
	    //Integer d("76572944925670636209790912427415155085360939712345");
        /*###################
	    // construct from BER encoded parameters
	    // this constructor will decode and extract the the fields fieldID and curve of the sequence ECParameters
	    ECP(BufferedTransformation &bt);
	    // encode the fields fieldID and curve of the sequence ECParameters
	    void DEREncode(BufferedTransformation &bt) const;
        */
        //RWC;NOTE; COMPUTE "a" as "modulus - 3".
        Integer a;
        bECPFlag = true;
        if (ECParams.m_pszA == NULL || strlen(ECParams.m_pszA) == 0)
        {
            Integer INTThree(3);
            a = modulus - INTThree;
        }
        else
        {
           Integer aTmp(ECParams.m_pszA);
           a = aTmp;
        }
	    ECP ec(modulus, a, b);
        //ec.DEREncodePoint(BufferedTransformation &bt, ECPPoint &P, bool compressed);
        //ec.EncodePoint(BufferedTransformation &bt, ECPPoint &P, bool compressed);
	    ECP::Point P(x, y);
	    P = ec.Multiply(k, P);
	    //ECP::Point Q(ec.Multiply(d, P));
	    pcprivECP2 = new ECIES<ECP>::Decryptor(rndRandom4, ec, P, r);//, d);
    }       // IF ECP strings from user.
    else if (ECParams.m_pszTFields)
    {       // HANDLE EC2N individual parameter strings from user.
        unsigned int t0=0, t1=0, t2=0, t3=0, t4=0;
        //Integer a(ECParams.m_pszA);
	    //Integer b(ECParams.m_pszB);
	    //Integer x(ECParams.m_pszGx);
	    //Integer y(ECParams.m_pszGy);
	    Integer r(ECParams.m_pszR);
        bECPFlag = false;
        // WE must parse out the "t?" values from "TFields" for the EC constructor
        // For example: TFields=163, 7, 6, 3, 0 OR TFields=409, 87, 0
        char *pTmpTFields=strdup(ECParams.m_pszTFields);
        char *pszField, *pszField2=NULL;
        sscanf(pTmpTFields, "%d", &t4);
        if ((pszField = strchr(pTmpTFields, ',')) != NULL)
        {
            pszField++;
            sscanf(pszField, "%d", &t3);
            pszField2 = pszField;
        }
        if ((pszField = strchr(pszField2, ',')) != NULL)
        {
            pszField++;
            sscanf(pszField, "%d", &t2);
            pszField2 = pszField;
        }
        if ((pszField = strchr(pszField2, ',')) != NULL)
        {
            pszField++;
            sscanf(pszField, "%d", &t1);
            pszField2 = pszField;
        }
        if ((pszField = strchr(pszField2, ',')) != NULL)
        {
            pszField++;
            sscanf(pszField, "%d", &t0);
            pszField2 = pszField;
        }
	    EC2N *pec;
		StringSource ssA((const char *)ECParams.m_pszA, true, new HexDecoder);
		StringSource ssB((const char *)ECParams.m_pszB, true, new HexDecoder);
        if (t1 == 0)
        {
           pec = new EC2N(GF2NT(t4, t3, t2), 
               EC2N::FieldElement(ssA, ssA.MaxRetrievable()),
                   //DOES NOT WORK;(byte *)ECParams.m_pszA, strlen(ECParams.m_pszA), 
               EC2N::FieldElement(ssB, ssB.MaxRetrievable()) );
                   //(byte *)ECParams.m_pszB, strlen(ECParams.m_pszB)));
	       //pec = new EC2N(t2, t3, t4, a, b);
        }
        else
        {
           pec = new EC2N(GF2NPP(t0, t1, t2, t3, t4), 
               EC2N::FieldElement(ssA, ssA.MaxRetrievable()),
                   //DOES NOT WORK;(byte *)ECParams.m_pszA, strlen(ECParams.m_pszA), 
               EC2N::FieldElement(ssB, ssB.MaxRetrievable()) );
                   //(byte *)ECParams.m_pszB, strlen(ECParams.m_pszB)));
	       //pec = new EC2N(t0, t1, t2, t3, t4, a, b);
        }
        // RWC; IN ORDER TO Insert Gx, Gy, we must encode them.
        char *pGPointBuf=(char *)calloc(1, 3 + strlen(ECParams.m_pszGx) + strlen(ECParams.m_pszGy));
        strcpy(pGPointBuf, "04");
        strcat(pGPointBuf, ECParams.m_pszGx);
        strcat(pGPointBuf, ECParams.m_pszGy);
		//StringSource ssGx((const char *)ECParams.m_pszGx, true, new HexDecoder);
		//StringSource ssGy((const char *)ECParams.m_pszGy, true, new HexDecoder);
	    StringSource ssG((const char *)pGPointBuf, true, new HexDecoder);
        free(pGPointBuf);
	    EC2N::Point/*Element*/ G;
	    bool bResult = pec->/*GetCurve().*/DecodePoint(G, ssG, ssG.MaxRetrievable());
        if (!bResult)
        {
            SME_THROW(22, "BAD EC G DecodePoint!", NULL);
        }
	    //pec->SetSubgroupGenerator(G);
	    /*EC2N::Point P(
               EC2N::FieldElement(ssGx, ssGx.MaxRetrievable()),
                    //(byte *)ECParams.m_pszGx, strlen(ECParams.m_pszGx), 
               EC2N::FieldElement(ssGy, ssGy.MaxRetrievable()) );
                    //(byte *)ECParams.m_pszGy, strlen(ECParams.m_pszGy)));
	    //P = pec->Multiply(k, P);*/
	    pcprivEC2N = new ECIES<EC2N>::Decryptor(rndRandom4, *pec, G/*P*/, r);
        delete pec;
    }       // IF EC2N strings from user.
    else
    {
        SME_THROW(22, "BAD EC Params.", NULL);
    }

    //#############################
    // CHECK for ECP or EC2N and build appropriate Signer/Verifier.
    if (bECPFlag)
    {
        if (pcprivECP2 == NULL)
        {
            SME_THROW(22, "Crypto++ ECP Decrypter did not build correctly!", NULL);
        }
        // GET encoded private key for params
        pcprivECP2->AccessKey().AccessGroupParameters().DEREncode(bt4);//.DEREncodeKey(bt4);
    }   // IF bECPFlag
    else
    {
        if (pcprivEC2N == NULL)
        {
            SME_THROW(22, "Crypto++ EC2N Decrypter did not build correctly!", NULL);
        }
        // GET encoded private key for params
        pcprivEC2N->AccessKey().AccessGroupParameters().DEREncode(bt4);//.DEREncodeKey(bt4);
    }   // END IF bECPFlag

    // ##### EXTRACT params
    len = bt4.Get(PBufChar, 2048); 
    if (len)
    {
        CSM_Buffer BufSave((char *)PBufChar, len);
        ECParams.SetEncodedECParams(BufSave);
        pbufferParams = new CSM_Buffer(*ECParams.GetEncodedECParams());
#ifdef _DEBUG
        BufSave.ConvertMemoryToFile("./ECDSAGroupParams.bin");
#endif  // _DEBUG
    }

    if (pcprivECP2)
        delete pcprivECP2;
    if (pcprivEC2N)
        delete pcprivEC2N;

   SME_FINISH
   SME_CATCH_SETUP
    if (pcprivECP2)
        delete pcprivECP2;
    if (pcprivEC2N)
        delete pcprivEC2N;
#else  //_WIN32
       SME_THROW(22, "ECParmas only available on MS Windows (temporarily)!", NULL);
      SME_FINISH
      SME_CATCH_SETUP
#endif //_WIN32

   SME_CATCH_FINISH


   return pbufferParams;
}       // END CSM_CryptoKeysECDsaExport::DetermineECParams(...)


/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_CryptoKeysECDsaExport::GenerateKeys(
      CSM_Buffer &bufferX, CSM_Buffer &bufferY,     // OUT, returned
      CSM_ECParams &ECParams,                       // IN, OUT
      CSM_Buffer *pbufferParams)                     // OUT, OPTIONAL
{
   SM_RET_VAL lRet = SM_NO_ERROR;
   CSM_Buffer *pbufferParams2=NULL;

   SME_SETUP("CSM_CryptoKeysECDsaExport::GenerateKeys");

//RWC;#if defined(_WIN32) || (defined(CRYPTOPP_5_0) && !defined(CRYPTOPP_5_1))
#if (defined(CRYPTOPP_5_0) )//&& !defined(CRYPTOPP_5_1))
    const PrivateKey *pPrivateKeyRef=NULL;
    const PublicKey  *pPublicKeyRef=NULL;
    ECIES<ECP>::Decryptor     *pcprivECP2 = NULL;
    ECDSA<ECP, SHA>::Signer   *psprivECP2 = NULL;
    ECDSA<ECP, SHA>::Verifier *pspubECP2 = NULL;
    ECIES<EC2N>::Decryptor     *pcprivEC2N = NULL;
    ECDSA<EC2N, SHA>::Signer   *psprivEC2N = NULL;
    ECDSA<EC2N, SHA>::Verifier *pspubEC2N = NULL;
    CryptoPP::ByteQueue bt, bt2, bt3; //BufferedTransformation;
    unsigned char PBufChar[2048];
    bool bECPFlag=true;  // ECP or EC2N type of Elliptic Curve.
    int len;

    // READY to generate the key pair



    pbufferParams2 = DetermineECParams(ECParams, bECPFlag);

    if (pbufferParams2 == NULL)
    {
        SME_THROW(22, "BAD EC Params.", NULL);
    }

    //#############################
    // CHECK for ECP or EC2N and build appropriate Signer/Verifier.
    CryptoPP::ByteQueue bt5;
    bt5.Put((unsigned char *)pbufferParams2->Access(), pbufferParams2->Length());
    if (bECPFlag)
    {
#ifdef _WIN32 
        pcprivECP2 = new ECIES<ECP>::Decryptor(rndRandom4, bt5);
#else
        DL_GroupParameters_EC<ECP> params(bt5);
        pcprivECP2 = new ECIES<ECP>::Decryptor(rndRandom4, params);
#endif
        if (pcprivECP2 == NULL)
        {
            SME_THROW(22, "Crypto++ ECP Decrypter did not build correctly!", NULL);
        }
        psprivECP2 = new ECDSA<ECP, SHA>::Signer(*pcprivECP2);
        //RWC;DL_PrivateKey_EC<ECP> &APrivateKey=(DL_PrivateKey_EC<ECP> &)psprivECP2->AccessPrivateKey();
        //RWC;APrivateKey.AccessGroupParameters().BERDecode(bt5);
        pspubECP2 = new ECDSA<ECP, SHA>::Verifier(*psprivECP2);
        const PrivateKey &PrivateKeyRef = psprivECP2->GetPrivateKey();
        pPrivateKeyRef = &PrivateKeyRef;
        const PublicKey &PublicKeyRef = pspubECP2->GetPublicKey();
        pPublicKeyRef = &PublicKeyRef;
        // GET encoded private key for params
        //DL_PrivateKey_EC<ECP> &APrivateKey=(DL_PrivateKey_EC<ECP> &)psprivECP2->AccessPrivateKey();
        //APrivateKey.AccessGroupParameters().DEREncode(bt4);//.DEREncodeKey(bt4);
    }   // IF bECPFlag
    else
    {
#ifdef _WIN32
        pcprivEC2N = new ECIES<EC2N>::Decryptor(rndRandom4, bt5);
#else
        DL_GroupParameters_EC<EC2N> params(bt5);
        pcprivEC2N = new ECIES<EC2N>::Decryptor(rndRandom4, params);
#endif
       //pcprivEC2N = new ECIES<EC2N>::Decryptor(rndRandom4, bt5);//RWC;CryptoPP::Integer(bt5));//RWC5;cppInt);
        if (pcprivEC2N == NULL)
        {
            SME_THROW(22, "Crypto++ EC2N Decrypter did not build correctly!", NULL);
        }
        psprivEC2N = new ECDSA<EC2N, SHA>::Signer(*pcprivEC2N);
        //RWC;DL_PrivateKey_EC<EC2N> &APrivateKey=(DL_PrivateKey_EC<EC2N> &)psprivEC2N->AccessPrivateKey();
        //RWC;APrivateKey.AccessGroupParameters().BERDecode(bt5);
        pspubEC2N = new ECDSA<EC2N, SHA>::Verifier(*psprivEC2N);
        const PrivateKey &PrivateKeyRef = psprivEC2N->GetPrivateKey();
        pPrivateKeyRef = &PrivateKeyRef;
        const PublicKey &PublicKeyRef = pspubEC2N->GetPublicKey();
        pPublicKeyRef = &PublicKeyRef;
        // GET encoded private key for params
    }   // END IF bECPFlag

    //#############################
    // NOW that we have a private key, PROCESS public and access/package both.
    if (pPrivateKeyRef)//pcprivECP2)
    {
        //PublicKey &APublicKey=sprivECP2.AccessPublicKey();
        //CryptoMaterial &ACryptoMaterial=sprivECP2.AccessMaterial();
        //DS::KeyClass &AKeyClass=spubECP2.AccessKey();//RWC;DOES NOT WORK
        //PrivateKey &APrivateKey = psprivECP2->AccessPrivateKey();
        //RWC;DOES NOT WORK;spubECP2.GetGroupParameters();
        //TOO SPECIFIC;DL_Keys_EC<ECP>::PublicKey &APublicKey=(DL_Keys_EC<ECP>::PublicKey &)spubECP2.AccessPublicKey();
        //DL_PublicKey_EC<ECP> &APublicKey=(DL_PublicKey_EC<ECP> &)pspubECP2->AccessPublicKey();
        // privateKey.Put((unsigned char *)pbufX->Access(), pbufX->Length());

        // GET public AND private key binary
        // GET encoded parameters directly from private key
        //DL_PrivateKey_EC<ECP> &APrivateKey=(DL_PrivateKey_EC<ECP> &)pcprivECP2->AccessPrivateKey();
        //pPrivateKeyRef->AccessGroupParameters().DEREncode(bt3);
        // GET encoded public key
        /*APublicKey.DEREncode(bt2);
        APublicKey.DEREncodeKey(bt3);*/
        pPublicKeyRef->Save(bt);
        len = bt.Get(PBufChar, 2048); 
        bufferY.Set((char *)PBufChar, len);
        pPrivateKeyRef->Save(bt2);
        len = bt2.Get(PBufChar, 2048); 
        bufferX.Set((char *)PBufChar, len);
#ifdef _DEBUG
        bufferY.ConvertMemoryToFile("./ECDSAPrivateKey.bin");
        bufferX.ConvertMemoryToFile("./ECDSAPublicKey.bin");
#endif  // _DEBUG
    }       // END if pcprivECP2

    if (pcprivECP2)
        delete pcprivECP2;
    if (psprivECP2)
        delete psprivECP2;
    if (pspubECP2)
        delete pspubECP2;
    if (pcprivEC2N)
        delete pcprivEC2N;
    if (psprivEC2N)
        delete psprivEC2N;
    if (pspubEC2N)
        delete pspubEC2N;

    //###################
    /*EC2N notes
      ... FROM eccrypto.cpp, EcRecommendedParameters<EC2N>
		StringSource ssA(a, true, new HexDecoder);
		StringSource ssB(b, true, new HexDecoder);
		if (t0 == 0)
			return new EC2N(GF2NT(t2, t3, t4), EC2N::FieldElement(ssA, ssA.MaxRetrievable()), EC2N::FieldElement(ssB, ssB.MaxRetrievable()));
		else
			return new EC2N(GF2NPP(t0, t1, t2, t3, t4), EC2N::FieldElement(ssA, ssA.MaxRetrievable()), EC2N::FieldElement(ssB, ssB.MaxRetrievable()));
	// construct from BER encoded parameters
	// this constructor will decode and extract the the fields fieldID and curve of the sequence ECParameters
	EC2N(BufferedTransformation &bt);
	// encode the fields fieldID and curve of the sequence ECParameters
	void DEREncode(BufferedTransformation &bt) const;
      ALSO, See Crypto++5.0 validat2.cpp, ValidateECDSA() to load t2, t3, t4.
      ###################*/

   // encode parameters into file
   if (pbufferParams && pbufferParams2)
   {
       *pbufferParams = *pbufferParams2;
       delete pbufferParams2;
   }


   SME_FINISH
   SME_CATCH_SETUP
     if (pbufferParams2)
        delete pbufferParams2;
#else  //_WIN32
       SME_THROW(22, "Key Generation only available on MS Windows (temporarily)!", NULL);
      SME_FINISH
      SME_CATCH_SETUP
#endif //_WIN32

   SME_CATCH_FINISH

   return lRet;
}       // END CSM_CryptoKeysECDsaExport::GenerateKeys(...)



// VALID ECP OIDs: , , , , secp112r2, secp160r1, secp160k1, secp256k1, secp128r1, secp128r2, secp160r2, secp192k1, secp224k1, secp224r1, secp384r1, secp521r1
void CSM_CryptoKeysECDsaExport::ECDSA_ListOids(std::ostream &os)
{
    ECIES<ECP>::Decryptor cpriv;
    OID oid;
    ByteQueue oidbt;
    byte oidString[100];
    unsigned int iOidLength;
    int ii;
    char *ptr;

    //RWC;WORKS;cpriv.AccessKey().AccessGroupParameters().GetNextRecommendedParametersOID(oid);
	while (!(oid = DL_GroupParameters_EC<ECP>::GetNextRecommendedParametersOID(oid)).m_values.empty())
	{
        ptr = (char *)ECDSA_ListOids_Name(oid);
        oid.DEREncode(oidbt);
        iOidLength = oidbt.Get(oidString, 100);
        os << "ECP OID=";
        for (ii=0; ii < oid.m_values.size(); ii++)
        {
            if (ii != 0)
                os << ".";
            os << oid.m_values[ii];
        }
        if (ptr)        // IF name is known.
            os << "(" << ptr << ")";
        os << std::endl;
		/*DL_GroupParameters_EC<ECP> params(oid);
		bool fail = !params.Validate(GlobalRNG(), 2);
		cout << (fail ? "FAILED" : "passed") << "    " << dec << params.GetCurve().GetField().MaxElementBitLength() << " bits" << endl;
		pass = pass && !fail;*/
	}
	while (!(oid = DL_GroupParameters_EC<EC2N>::GetNextRecommendedParametersOID(oid)).m_values.empty())
	{
        ptr = (char *)ECDSA_ListOids_Name(oid);
        os << "EC2N OID=";
        for (ii=0; ii < oid.m_values.size(); ii++)
        {
            if (ii != 0)
                os << ".";
            os << oid.m_values[ii];
        }
        if (ptr)        // IF name is known.
            os << "(" << ptr << ")";
        os << std::endl;
		/*ECParameters<EC2N> params(oid);
		bool fail = !params.ValidateParameters(GlobalRNG());
		cout << (fail ? "FAILED" : "passed") << "    " << params.GetCurve().GetField().MaxElementBitLength() << " bits" << endl;
		pass = pass && !fail;*/
	}


    /*const EcRecommendedParameters<ECP/*EllipticCurve* /> *begin, *end, *pTmpParam;
	cpriv.GetRecommendedParameters(begin, end);
    //const EcRecommendedParameters<EllipticCurve> *it = std::lower_bound(begin, end, oid, OIDLessThan());
    pTmpParam = begin;
    while (pTmpParam != end)
	  pTmpParam->oid;*/

}       // END CSM_SFLECDSAPrivateKey::ECDSA_ListOids(...)


//
//  THIS method lists the known OID names from the table.  It may have to be 
//  updated as the Crypto++ library is updated, since new OIDs may be 
//  added/supported.  It lists the hard-coded OID names from the "eccrypto.cpp"
//  source file of Cyrpto++5.0:  GetRecommendedParameters(...)
//  DO NOT FREE THE RETURNED "char *".
const char *CSM_CryptoKeysECDsaExport::ECDSA_ListOids_Name(OID &oid)
{
    const char *pszResult=NULL;

    // LIST ECP types first
    if (oid == ASN1::secp192r1())
        pszResult = "secp192r1";
    else if (oid == ASN1::secp256r1())
        pszResult = "secp256r1";
    else if (oid == ASN1::secp112r1())
        pszResult = "secp112r1";
    else if (oid == ASN1::secp112r2())
        pszResult = "secp112r2";
    else if (oid == ASN1::secp160r1())
        pszResult = "secp160r1";
    else if (oid == ASN1::secp160k1())
        pszResult = "secp160k1";
    else if (oid == ASN1::secp256k1())
        pszResult = "secp256k1";
    else if (oid == ASN1::secp128r1())
        pszResult = "secp128r1";
    else if (oid == ASN1::secp128r2())
        pszResult = "secp128r2";
    else if (oid == ASN1::secp160r2())
        pszResult = "secp160r2";
    else if (oid == ASN1::secp192k1())
        pszResult = "secp192k1";
    else if (oid == ASN1::secp224k1())
        pszResult = "secp224k1";
    else if (oid == ASN1::secp224r1())
        pszResult = "secp224r1";
    else if (oid == ASN1::secp384r1())
        pszResult = "secp384r1";
    else if (oid == ASN1::secp521r1())
        pszResult = "secp521r1";

    // CHECK for EC2N types next
    else if (oid == ASN1::sect163k1())
        pszResult = "sect163k1";
    else if (oid == ASN1::sect163r1())
        pszResult = "sect163r1";
    else if (oid == ASN1::sect239k1())
        pszResult = "sect239k1";
    else if (oid == ASN1::sect113r1())
        pszResult = "sect113r1";
    else if (oid == ASN1::sect113r2())
        pszResult = "sect113r2";
    else if (oid == ASN1::sect283k1())
        pszResult = "sect283k1";
    else if (oid == ASN1::sect283r1())
        pszResult = "sect283r1";
    else if (oid == ASN1::sect131r1())
        pszResult = "sect131r1";
    else if (oid == ASN1::sect131r2())
        pszResult = "sect131r2";
    else if (oid == ASN1::sect193r1())
        pszResult = "sect193r1";
    else if (oid == ASN1::sect193r2())
        pszResult = "sect193r2";
    else if (oid == ASN1::sect233k1())
        pszResult = "sect233k1";
    else if (oid == ASN1::sect233r1())
        pszResult = "sect233r1";
    else if (oid == ASN1::sect409k1())
        pszResult = "sect409k1";
    else if (oid == ASN1::sect409r1())
        pszResult = "sect409r1";
    else if (oid == ASN1::sect571k1())
        pszResult = "sect571k1";
    else if (oid == ASN1::sect571r1())
        pszResult = "sect571r1";

    return pszResult;
}       // END CSM_SFLECDSAPrivateKey::ECDSA_ListOids_Name(...)

//
//  This method will return the Crypto++ OID defined by the string input.
OID *CSM_CryptoKeysECDsaExport::ECDSA_StringToOid(
        const char *pszOidStringIN,   // IN
        bool &bECPFlag)             // OUT
{
    OID *poidResult=NULL;
    char *pszOidString = strdup(pszOidStringIN);

    for (int ii=0; ii < strlen(pszOidString); ii++)
        pszOidString[ii] = tolower(pszOidString[ii]);

    bECPFlag = false;       // DEFAULT to EC2N.

    // LIST ECP types first
    if (strcmp(pszOidString, "secp192r1") == 0)
        poidResult = new OID(ASN1::secp192r1());
    else if (strcmp(pszOidString, "secp256r1") == 0)
        poidResult = new OID(ASN1::secp256r1());
    else if (strcmp(pszOidString, "secp112r1") == 0)
        poidResult = new OID(ASN1::secp112r1());
    else if (strcmp(pszOidString, "secp112r2") == 0)
        poidResult = new OID(ASN1::secp112r2());
    else if (strcmp(pszOidString, "secp160r1") == 0)
        poidResult = new OID(ASN1::secp160r1());
    else if (strcmp(pszOidString, "secp160k1") == 0)
        poidResult = new OID(ASN1::secp160k1());
    else if (strcmp(pszOidString, "secp256k1") == 0)
        poidResult = new OID(ASN1::secp256k1());
    else if (strcmp(pszOidString, "secp128r1") == 0)
        poidResult = new OID(ASN1::secp128r1());
    else if (strcmp(pszOidString, "secp128r2") == 0)
        poidResult = new OID(ASN1::secp128r2());
    else if (strcmp(pszOidString, "secp160r2") == 0)
        poidResult = new OID(ASN1::secp160r2());
    else if (strcmp(pszOidString, "secp192k1") == 0)
        poidResult = new OID(ASN1::secp192k1());
    else if (strcmp(pszOidString, "secp224k1") == 0)
        poidResult = new OID(ASN1::secp224k1());
    else if (strcmp(pszOidString, "secp224r1") == 0)
        poidResult = new OID(ASN1::secp224r1());
    else if (strcmp(pszOidString, "secp384r1") == 0)
        poidResult = new OID(ASN1::secp384r1());
    else if (strcmp(pszOidString, "secp521r1") == 0)
        poidResult = new OID(ASN1::secp521r1());

    if (poidResult)
        bECPFlag = true;
    else
    {
        // CHECK for EC2N types next
        if (strcmp(pszOidString, "sect163k1") == 0)
            poidResult = new OID(ASN1::sect163k1());
        else if (strcmp(pszOidString, "sect163r1") == 0)
            poidResult = new OID(ASN1::sect163r1());
        else if (strcmp(pszOidString, "sect239k1") == 0)
            poidResult = new OID(ASN1::sect239k1());
        else if (strcmp(pszOidString, "sect113r1") == 0)
            poidResult = new OID(ASN1::sect113r1());
        else if (strcmp(pszOidString, "sect113r2") == 0)
            poidResult = new OID(ASN1::sect113r2());
        else if (strcmp(pszOidString, "sect283k1") == 0)
            poidResult = new OID(ASN1::sect283k1());
        else if (strcmp(pszOidString, "sect283r1") == 0)
            poidResult = new OID(ASN1::sect283r1());
        else if (strcmp(pszOidString, "sect131r1") == 0)
            poidResult = new OID(ASN1::sect131r1());
        else if (strcmp(pszOidString, "sect131r2") == 0)
            poidResult = new OID(ASN1::sect131r2());
        else if (strcmp(pszOidString, "sect163r2") == 0)
            poidResult = new OID(ASN1::sect163r2());
        else if (strcmp(pszOidString, "sect193r1") == 0)
            poidResult = new OID(ASN1::sect193r1());
        else if (strcmp(pszOidString, "sect193r2") == 0)
            poidResult = new OID(ASN1::sect193r2());
        else if (strcmp(pszOidString, "sect233k1") == 0)
            poidResult = new OID(ASN1::sect233k1());
        else if (strcmp(pszOidString, "sect233r1") == 0)
            poidResult = new OID(ASN1::sect233r1());
        else if (strcmp(pszOidString, "sect409k1") == 0)
            poidResult = new OID(ASN1::sect409k1());
        else if (strcmp(pszOidString, "sect409r1") == 0)
            poidResult = new OID(ASN1::sect409r1());
        else if (strcmp(pszOidString, "sect571k1") == 0)
            poidResult = new OID(ASN1::sect571k1());
        else if (strcmp(pszOidString, "sect571r1") == 0)
            poidResult = new OID(ASN1::sect571r1());
    }

    free(pszOidString);

    return poidResult;
}       // END CSM_SFLECDSAPrivateKey::ECDSA_StringToOid(...)

CSM_Buffer *CSM_CryptoKeysECDsaExport::WrapPkcs12(
       char *pBufX, char *pBufY, char *pCertFile,             // File Names
       char *pszPassword, 
       CERT::CSM_ECParams &ECParams,
       char *pencPrvKeyFilename)  //OPTIONAL input.
{
   CSM_Buffer *pPKCS12Buf = NULL;
   SME_SETUP("CSM_CryptoKeysECDsaExport::WrapPkcs12");

   //RWC;TBD; now that we are no longer using OpenSSL, change parameter to CSM_Buffer
   //         to avoid file creation...
   pPKCS12Buf = CSM_CryptoKeysFree3Base::WrapPkcs12(pBufX, pCertFile, 
                                            pszPassword, pencPrvKeyFilename );

   SME_FINISH
   SME_CATCH_SETUP
   SME_CATCH_FINISH

   return pPKCS12Buf;
}       // END CSM_CryptoKeysECDsaExport::WrapPkcs12(...)


/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
// NEW CLASS METHOD FOLLOWS for "CSM_CryptoKeysECDHExport", ECDH
/////////////////////////////////////////////////////////////////////////////
SM_RET_VAL CSM_CryptoKeysECDHExport::GenerateKeys(
      CSM_Buffer &bufferX, CSM_Buffer &bufferY,     // OUT, returned
      CSM_ECParams &ECParams,                       // IN, OUT
      CSM_Buffer *pbufferParams)                     // OUT, OPTIONAL
{
   SM_RET_VAL lRet = SM_NO_ERROR;
    SecByteBlock *ppriv1=NULL;
    SecByteBlock *ppub1=NULL;
    bool bECPFlag=true;  // ECP or EC2N type of Elliptic Curve.
    CSM_Buffer *pbufferParams2=NULL;
    SimpleKeyAgreementDomain *pGenericECDH=NULL;

   SME_SETUP("CSM_CryptoKeysECDHExport::GenerateKeys");


    // READY to generate the key pair



    pbufferParams2 = DetermineECParams(ECParams, bECPFlag);
    if (pbufferParams2 == NULL)
    {
        SME_THROW(22, "BAD EC Params.", NULL);
    }

    //#############################
    // CHECK for ECP or EC2N and build appropriate ECDH instance.
    CryptoPP::ByteQueue bt5;
    bt5.Put((unsigned char *)pbufferParams2->Access(), pbufferParams2->Length());
    if (bECPFlag)
    {
        ECDH<ECP>::Domain *pDomain = new ECDH<ECP>::Domain;
        pDomain->AccessGroupParameters().BERDecode(bt5);
        pGenericECDH = pDomain;
        if (pGenericECDH == NULL)
        {
            SME_THROW(22, "Crypto++ ECP ECDH did not build correctly!", NULL);
        }
    }   // IF bECPFlag
    else
    {
        ECDH<EC2N>::Domain *pDomain = new ECDH<EC2N>::Domain;
        pDomain->AccessGroupParameters().BERDecode(bt5);
        pGenericECDH = pDomain;
        if (pGenericECDH == NULL)
        {
            SME_THROW(22, "Crypto++ EC2N ECDH did not build correctly!", NULL);
        }
    }   // END IF bECPFlag

    ppub1 = new SecByteBlock(pGenericECDH->PublicKeyLength());
    ppriv1 = new SecByteBlock(pGenericECDH->PrivateKeyLength());
    pGenericECDH->GenerateKeyPair(rndRandom4, *ppriv1, *ppub1); 
    //#############################
    // NOW that we have keys, PROCESS public and access/package both.
        bufferY.Set((const char *)ppub1->data(), ppub1->m_size);
        bufferX.Set((const char *)ppriv1->data(), ppriv1->m_size);
#ifdef _DEBUG
        bufferY.ConvertMemoryToFile("./ECDHPublicKey.bin");
        bufferX.ConvertMemoryToFile("./ECDHPrivateKey.bin");
#endif  // _DEBUG

      if (pGenericECDH)
          delete pGenericECDH;
      if (ppub1)
           delete ppub1;
      if (ppriv1)
           delete ppriv1;


   // encode parameters into file
   if (pbufferParams && pbufferParams2)
   {
       *pbufferParams = *pbufferParams2;
       delete pbufferParams2;
   }


   SME_FINISH
   SME_CATCH_SETUP
     if (pbufferParams2)
        delete pbufferParams2;
      if (pGenericECDH)
          delete pGenericECDH;
      if (ppub1)
           delete ppub1;
      if (ppriv1)
           delete ppriv1;
   SME_CATCH_FINISH

   return lRet;
}       // END CSM_CryptoKeysECDHExport::GenerateKeys(...)



_END_CERT_NAMESPACE

#endif // CRYPTOPP_5_0


// EOF sm_CryptoKeysDsa.cpp
