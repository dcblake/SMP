
#include "sm_api.h"
_BEGIN_SFL_NAMESPACE
using namespace SNACC;

///////////////////////////////////////////////////////////////////////////////
// sm_RecipientIdent.cpp
// implementation of methods from:
//   CSM_RecipientIdentifier
//
// Constructors for CSM_RecipientIdentifier
//   CSM_RecipientIdentifier(CSM_Identifier &Rid)
//   CSM_RecipientIdentifier(CSM_RecipientIdentifier &Rid)
//   CSM_RecipientIdentifier(CSM_Buffer &SubjKeyId, CSM_Buffer *pDate,
//                           CSM_Attrib *pAttrib)
//   CSM_RecipientIdentifier(CSM_Buffer &OrigPubKey, CSM_Alg &OrigPubKeyAlg)
//   CSM_RecipientIdentifier(KeyAgreeRecipientIdentifier &SNACCkarid)
//   CSM_RecipientIdentifier(RecipientIdentifier &SNACCRid)
//   CSM_RecipientIdentifier (SignerIdentifier &SNACCsid)
//   CSM_RecipientIdentifier (KEKIdentifier &SNACCkekid)
//   CSM_RecipientIdentifier(OriginatorIdentifierOrKey &SNACCoidokey)
// Destructor for CSM_RecipientIdentifier
//   ~CSM_RecipientIdentifier()
// Member Functions for CSM_RecipientIdentifier
//   CSM_Buffer *GetOrigPubKey()
//   CSM_Alg *GetOrigPubKeyAlg()
//   CSM_Buffer *GetDate()
//   CSM_Attrib *CGetAttrib()
//   void SetOrigPubKey(CSM_Buffer &origPubKey)
//   void SetOrigPubKeyAlg(CSM_Alg &origPubKeyAlg)
//   void SetDate(CSM_Buffer &date)
//   void SetAttrib(CSM_Attrib &attr)
//   void CReportMsgData(ostream &os)
//   KeyAgreeRecipientIdentifier *GetKeyAgreeRecipientIdentifier()
//   RecipientIdentifier *GetRecipientIdentifier()
//   SignerIdentifier *GetSignerIdentifier()
//   SignerIdentifier *GetSignerIdentifier(bool bIssOrSki)
//   KEKIdentifier *GetKEKIdentifier()
//   OriginatorIdentifierOrKey *GetOrigIdentOrKey(CSM_CSInst *inst)
//   bool operator == (CSM_RecipientIdentifier &CRid)
//   CSM_RecipientIdentifier &operator = (CSM_RecipientIdentifier &Rid)
///////////////////////////////////////////////////////////////////////////////

// Constructor for CSM_RecipientIdentifier
//
CSM_RecipientIdentifier::CSM_RecipientIdentifier(const CSM_Identifier &Rid)
{
    SME_SETUP("CSM_RecipientIdentifier::CSM_Identifier &");

    Clear();
    if (Rid.AccessSubjectKeyIdentifier())
        this->SetSubjectKeyIdentifier(*Rid.AccessSubjectKeyIdentifier());
    if (Rid.AccessIssuerAndSerial())
        this->SetIssuerAndSerial(*Rid.AccessIssuerAndSerial());

    SME_FINISH_CATCH
}

// Constructor for CSM_RecipientIdentifier
// use this constructor to make a new this CSM structure
//
CSM_RecipientIdentifier::CSM_RecipientIdentifier(const CSM_RecipientIdentifier &Rid)
{
    SME_SETUP("CSM_RecipientIdentifier::CSM_RecipientIdentifier &");

    Clear();
    *this = Rid;

    SME_FINISH_CATCH
}

// Constructor for CSM_RecipientIdentifier
//
CSM_RecipientIdentifier::CSM_RecipientIdentifier(const CSM_Buffer &SubjKeyId,
                                                 CSM_Buffer *pDate,
                                                 CSM_Attrib *pAttrib)
{
    SME_SETUP("CSM_RecipientIdentifier::CSM_Buffer &SubjKeyId,CSM_Buffer *pDate,CSM_Attrib *pAttrib");

    Clear();

    this->SetSubjectKeyIdentifier(SubjKeyId);

    if(pDate)
    {
        this->SetDate(*pDate);
    }

    if(pAttrib)
    {
        this->SetAttrib(*pAttrib);
    }

    SME_FINISH_CATCH
}

// Constructor for CSM_RecipientIdentifier
//
CSM_RecipientIdentifier::CSM_RecipientIdentifier(const CSM_Buffer &OrigPubKey,
                                                 const CSM_Alg &OrigPubKeyAlg)
{
    SME_SETUP(
      "CSM_RecipientIdentifier::CSM_Buffer &OrigPubKey,CSM_Alg &OrigPubKeyAlg");

    Clear();

    this->SetOrigPubKeyAlg(OrigPubKeyAlg);

    this->SetOrigPubKey(OrigPubKey);

    SME_FINISH_CATCH
}

// Constructor for CSM_RecipientIdentifier
// use this constructor to make a CSM_RecipientIdentifier
//   from KeyAgreeRecipientIdentifier
//
CSM_RecipientIdentifier::
    CSM_RecipientIdentifier(const KeyAgreeRecipientIdentifier &SNACCkarid)
{
    SME_SETUP("CSM_RecipientIdentifier::KeyAgreeRecipientIdentifier &");

    Clear();

    if (SNACCkarid.choiceId ==
        KeyAgreeRecipientIdentifier::issuerAndSerialNumberCid)
    {
        CSM_IssuerAndSerialNumber tmpISN(*SNACCkarid.issuerAndSerialNumber);
        this->SetIssuerAndSerial(tmpISN);
    }
    else if(SNACCkarid.choiceId == KeyAgreeRecipientIdentifier::rKeyIdCid)
    {
        if(SNACCkarid.rKeyId)
        {
            CSM_Buffer tmpbuf(SNACCkarid.rKeyId->subjectKeyIdentifier.c_str(),
                SNACCkarid.rKeyId->subjectKeyIdentifier.Len());
            this->SetSubjectKeyIdentifier(tmpbuf);

            if(SNACCkarid.rKeyId->date)
            {
                if (m_pDate)
                    delete m_pDate;
                m_pDate = new CSM_Buffer((char *)SNACCkarid.rKeyId->date->c_str(),
                                         SNACCkarid.rKeyId->date->length());
            }

            if(SNACCkarid.rKeyId->other)
            {
                if (m_pAttribs)
                    delete m_pAttribs;
                m_pAttribs = new CSM_Attrib;
                m_pAttribs->m_poid =
                    new AsnOid(SNACCkarid.rKeyId->other->keyAttrId);
                SM_EXTRACT_ANYBUF(m_pAttribs->m_pEncodedAttrib,
                                  SNACCkarid.rKeyId->other->keyAttr);
            }
        }
    }

    SME_FINISH_CATCH
}

// Constructor for CSM_RecipientIdentifier
// use this constructor to make a CSM_RecipientIdentifier
//   from RecipientIdentifier
//
CSM_RecipientIdentifier::CSM_RecipientIdentifier(const RecipientIdentifier &SNACCRid)
{
    SME_SETUP("CSM_RecipientIdentifier::RecipientIdentifier &");

    Clear();

    if (SNACCRid.choiceId == RecipientIdentifier::issuerAndSerialNumberCid)
    {
        CSM_IssuerAndSerialNumber tmpISN(*SNACCRid.issuerAndSerialNumber);
        this->SetIssuerAndSerial(tmpISN);
    }
    else if(SNACCRid.choiceId == RecipientIdentifier::subjectKeyIdentifierCid)
    {
        CSM_Buffer tmpbuf(SNACCRid.subjectKeyIdentifier->c_str(),
            SNACCRid.subjectKeyIdentifier->Len());
        this->SetSubjectKeyIdentifier(tmpbuf);
    }

    SME_FINISH_CATCH
}

// Constructor for CSM_RecipientIdentifier
// use this constructor to make a CSM_RecipientIdentifier from SignerIdentifier
//
CSM_RecipientIdentifier::CSM_RecipientIdentifier(const SignerIdentifier &SNACCsid)
{
    SME_SETUP("CSM_RecipientIdentifier::KeyAgreeRecipientIdentifier &");

    Clear();

    if (SNACCsid.choiceId == SignerIdentifier::issuerAndSerialNumberCid)
    {
        CSM_IssuerAndSerialNumber tmpISN(*SNACCsid.issuerAndSerialNumber);
        this->SetIssuerAndSerial(tmpISN);
    }
    else if(SNACCsid.choiceId == SignerIdentifier::subjectKeyIdentifierCid)
    {
        CSM_Buffer tmpbuf(SNACCsid.subjectKeyIdentifier->c_str(),
            SNACCsid.subjectKeyIdentifier->Len());
        this->SetSubjectKeyIdentifier(tmpbuf);
    }

    SME_FINISH_CATCH
}

// Constructor for CSM_RecipientIdentifier
//
CSM_RecipientIdentifier::CSM_RecipientIdentifier(const KEKIdentifier &SNACCkekid)
{
    SME_SETUP("CSM_RecipientIdentifier::KEKIdentifier &");

    Clear();

    CSM_Buffer tmpbuf(SNACCkekid.keyIdentifier.c_str(),
        SNACCkekid.keyIdentifier.Len());
    this->SetSubjectKeyIdentifier(tmpbuf);

    if(SNACCkekid.date)
    {
        if (m_pDate)
            delete m_pDate;
        m_pDate = new CSM_Buffer((char *)SNACCkekid.date->c_str(),
                                 SNACCkekid.date->length());
    }

    if(SNACCkekid.other)
    {
        if (m_pAttribs)
            delete m_pAttribs;
        m_pAttribs = new CSM_Attrib;
        m_pAttribs->m_poid = new AsnOid(SNACCkekid.other->keyAttrId) ;
        SM_EXTRACT_ANYBUF(m_pAttribs->m_pEncodedAttrib,
                          SNACCkekid.other->keyAttr);
    }

    SME_FINISH_CATCH

}

// Constructor for CSM_RecipientIdentifier
// use this constructor to make a CSM_RecipientIdentifier
//   from OriginatorIdentifierOrKey
//
CSM_RecipientIdentifier::
    CSM_RecipientIdentifier(const OriginatorIdentifierOrKey &SNACCoidokey)
{
    SME_SETUP("CSM_RecipientIdentifier::OriginatorIdentifierOrKey &");

    Clear();

    if (SNACCoidokey.choiceId ==
        OriginatorIdentifierOrKey::issuerAndSerialNumberCid)
    {
        CSM_IssuerAndSerialNumber tmpISN(*SNACCoidokey.issuerAndSerialNumber);
        this->SetIssuerAndSerial(tmpISN);
    }
    else if(SNACCoidokey.choiceId ==
        OriginatorIdentifierOrKey::subjectKeyIdentifierCid)
    {
        CSM_Buffer tmpbuf(SNACCoidokey.subjectKeyIdentifier->c_str(),
            SNACCoidokey.subjectKeyIdentifier->Len());
        this->SetSubjectKeyIdentifier(tmpbuf);
    }
    else if(SNACCoidokey.choiceId ==
        OriginatorIdentifierOrKey::originatorKeyCid)
    {
        m_pOrigPubKeyAlg = new CSM_Alg(SNACCoidokey.originatorKey->algorithm);
        m_pOrigPubKey = CSM_CertificateChoice::GetPublicKey(SNACCoidokey.originatorKey->publicKey);
    }
    SME_FINISH_CATCH

}

//Destructor
//
CSM_RecipientIdentifier::~CSM_RecipientIdentifier()
{
    if (m_pOrigPubKey != NULL)
        delete m_pOrigPubKey;
    if (m_pDate != NULL)
        delete m_pDate;
    if (m_pAttribs != NULL)
        delete m_pAttribs;
    if (m_pOrigPubKeyAlg != NULL)
        delete m_pOrigPubKeyAlg;
    Clear();

}

// GetOrigKey member function
//
CSM_Buffer *CSM_RecipientIdentifier::GetOrigPubKey()
{
    CSM_Buffer *ptmpOrigPubKey = NULL;

    SME_SETUP("CSM_RecipientIdentifier::GetOrigKey");

    ptmpOrigPubKey = new CSM_Buffer(*m_pOrigPubKey);

    SME_FINISH_CATCH
        return ptmpOrigPubKey;
}

// GetOrigPubKeyAlg member function
//
CSM_Alg *CSM_RecipientIdentifier::GetOrigPubKeyAlg()
{
    CSM_Alg *ptmpOrigPubKeyAlg = NULL;

    SME_SETUP("CSM_RecipientIdentifier::GetOrigPubKeyAlg");

    ptmpOrigPubKeyAlg = new CSM_Alg(*m_pOrigPubKeyAlg);

    SME_FINISH_CATCH
        return ptmpOrigPubKeyAlg;
}

// GetDate member function
//
CSM_Buffer *CSM_RecipientIdentifier::GetDate()
{
    CSM_Buffer *ptmpDate = NULL;

    SME_SETUP("CSM_RecipientIdentifier::GetDate");

    ptmpDate = new CSM_Buffer(*m_pDate);

    SME_FINISH_CATCH
        return ptmpDate;
}

// GetAttrib member function
//
CSM_Attrib *CSM_RecipientIdentifier::GetAttrib()
{
    CSM_Attrib *ptmpAttr = NULL;

    SME_SETUP("CSM_RecipientIdentifier::GetAttrib");

    ptmpAttr = new CSM_Attrib(*m_pAttribs);

    SME_FINISH_CATCH
        return ptmpAttr;
}

// CSM_RecipientIdentifier Set member functions:

// set this private variable with a CSM_Buffer origKey
//
void CSM_RecipientIdentifier::SetOrigPubKey(const CSM_Buffer &origPubKey)
{
    SME_SETUP(
      "CSM_RecipientIdentifier::SetOriginatorPubKey(CSM_Buffer &origPubKey)");

    if (m_pOrigPubKey == NULL)
        m_pOrigPubKey = new CSM_Buffer(origPubKey);

    SME_FINISH_CATCH
}

// set this private variable with a CSM_Buffer origKey
//
void CSM_RecipientIdentifier::SetOrigPubKeyAlg(const CSM_Alg &origPubKeyAlg)
{
    SME_SETUP(
        "CSM_RecipientIdentifier::SetOrigPubKeyAlg(CSM_Buffer &origPubKeyAlg)");

    if (m_pOrigPubKeyAlg == NULL)
        m_pOrigPubKeyAlg = new CSM_Alg(origPubKeyAlg);
    else
        *m_pOrigPubKeyAlg = origPubKeyAlg;

    SME_FINISH_CATCH
}

// set this private variable with a CSM_Buffer date
//
void CSM_RecipientIdentifier::SetDate(const CSM_Buffer &date)
{
    SME_SETUP("CSM_RecipientIdentifier::SetDate(CSM_Buffer &date)");

    if (m_pDate == NULL)
        m_pDate = new CSM_Buffer(date);
    else
        *m_pDate = date;

    SME_FINISH_CATCH
}

// SetAttrib:
// set this private variable with a CSM_Attrib attr
//
void CSM_RecipientIdentifier::SetAttrib(const CSM_Attrib &attr)
{
    SME_SETUP("CSM_RecipientIdentifier::SetDate(CSM_Attrib &attr)");

    if (m_pAttribs == NULL)
        m_pAttribs = new CSM_Attrib(attr);

    SME_FINISH_CATCH
}

// ReportMsgData:
//
void CSM_RecipientIdentifier::ReportMsgData(std::ostream &os)
{
    char *ptr=NULL;
    SME_SETUP("CSM_RecipientIdentifier::Report");

    if(this->AccessIssuerAndSerial())
    {
        CSM_IssuerAndSerialNumber tmpIaS;
        CSM_DN           *ptmpDN = NULL;
        CSM_Buffer       *ptmpSNbf = NULL;

        tmpIaS = *this->AccessIssuerAndSerial();

        ptmpDN = tmpIaS.GetIssuer();
        ptmpSNbf = tmpIaS.GetSerialNo();

        os << "CSM_RecipientIdentifier::Report(IssuerAndSerialNumber)\n";
        const char *pA = *ptmpDN;
        os << "Issuer = " <<  pA << "\nSerial Number = ";
        ptr = NULL;
        ptmpSNbf->HexBufferToString(ptr, ptmpSNbf->Access(),
                                    ptmpSNbf->Length());
        os << ptr << "\n";
        free(ptr);
        ptr = NULL;

        if(ptmpDN)
            delete ptmpDN;
        if (ptmpSNbf)
            delete ptmpSNbf;
    }

    if(this->AccessSubjectKeyIdentifier())
    {
        CSM_Buffer tmpSKIbf(*this->AccessSubjectKeyIdentifier());
        os << "SubjectKeyIdentifier = ";
        tmpSKIbf.HexBufferToString(ptr, tmpSKIbf.Access(), tmpSKIbf.Length());
        os << ptr << "\n";
        free(ptr);
        ptr = NULL;
    }

    if(this->m_pOrigPubKey)
    {
        CSM_Buffer tmpOkbf(*this->m_pOrigPubKey);
        os << "OriginatorKey = ";
        tmpOkbf.HexBufferToString(ptr, tmpOkbf.Access(), tmpOkbf.Length());
        os << ptr << "\n";
        free(ptr);
        ptr = NULL;
    }

    if(this->m_pDate)
    {
        CSM_Buffer tmpDbf(*this->m_pDate);
        os << "Date = ";
        tmpDbf.HexBufferToString(ptr, tmpDbf.Access(), tmpDbf.Length());
        os << ptr << "\n";
        free(ptr);
        ptr = NULL;
    }

    if(ptr)
        free(ptr);

    if(this->m_pAttribs)
    {
        CSM_Attrib ptmpAttr;
        ptmpAttr = CSM_Attrib(*this->m_pAttribs);
        ptmpAttr.Report(os);
    }

    os.flush();

    SME_FINISH_CATCH
}

// GetKeyAgreeRecipientIdentifier:
//
KeyAgreeRecipientIdentifier *CSM_RecipientIdentifier::
    GetKeyAgreeRecipientIdentifier()
{
    KeyAgreeRecipientIdentifier *SNACCkarid = NULL;

    SNACCkarid = new KeyAgreeRecipientIdentifier;

    if (this->AccessIssuerAndSerial())
    {
        SNACCkarid->choiceId = KeyAgreeRecipientIdentifier::
            issuerAndSerialNumberCid;
        SNACCkarid->issuerAndSerialNumber =
            ((CSM_IssuerAndSerialNumber *)this->AccessIssuerAndSerial())->GetSNACCIssuerAndSerialNumber();
    }
    else if(this->AccessSubjectKeyIdentifier())
    {
        SNACCkarid->choiceId = KeyAgreeRecipientIdentifier::rKeyIdCid;
        SNACCkarid->rKeyId = new RecipientKeyIdentifier;
        SNACCkarid->rKeyId->subjectKeyIdentifier.Set(
            this->AccessSubjectKeyIdentifier()->Access(),
            this->AccessSubjectKeyIdentifier()->Length());

        if(m_pDate)
        {
            SNACCkarid->rKeyId->date = new GeneralizedTime;
            *SNACCkarid->rKeyId->date = m_pDate->Access();
        }

        if(m_pAttribs)
        {
            SNACCkarid->rKeyId->other = new OtherKeyAttribute;
            SNACCkarid->rKeyId->other->keyAttrId = *m_pAttribs->m_poid;
            SNACCkarid->rKeyId->other->keyAttr = new AsnAny;
            SM_ASSIGN_ANYBUF(m_pAttribs->m_pEncodedAttrib,
                             SNACCkarid->rKeyId->other->keyAttr);
        }

        // In this case, leave optional elements NULL.
    }

    return(SNACCkarid);
}

// GetRecipientIdentifier:
//
RecipientIdentifier *CSM_RecipientIdentifier::GetRecipientIdentifier()
{
    RecipientIdentifier *pSNACCRecipientIdentifier;

    pSNACCRecipientIdentifier = new RecipientIdentifier;

    if (this->AccessIssuerAndSerial())
    {
        pSNACCRecipientIdentifier->choiceId = RecipientIdentifier::
            issuerAndSerialNumberCid;
        pSNACCRecipientIdentifier->issuerAndSerialNumber =
            ((CSM_IssuerAndSerialNumber *)this->AccessIssuerAndSerial())->GetSNACCIssuerAndSerialNumber();
    }
    else if(this->AccessSubjectKeyIdentifier())
    {
        pSNACCRecipientIdentifier->choiceId = RecipientIdentifier::
            subjectKeyIdentifierCid;
        pSNACCRecipientIdentifier->subjectKeyIdentifier =
            new SubjectKeyIdentifier;
        pSNACCRecipientIdentifier->subjectKeyIdentifier->Set(
            this->AccessSubjectKeyIdentifier()->Access(),
            this->AccessSubjectKeyIdentifier()->Length());
        // In this case, leave optional elements NULL.
    }

    return(pSNACCRecipientIdentifier);
}

// GetSignerIdentifier:
//
SignerIdentifier *CSM_RecipientIdentifier::GetSignerIdentifier()
{
    SignerIdentifier *pSNACCSignerIdentifier;

    pSNACCSignerIdentifier = new SignerIdentifier;

    if (this->AccessIssuerAndSerial())
    {
        pSNACCSignerIdentifier->choiceId = SignerIdentifier::
            issuerAndSerialNumberCid;
        pSNACCSignerIdentifier->issuerAndSerialNumber =
            ((CSM_IssuerAndSerialNumber *)this->AccessIssuerAndSerial())->GetSNACCIssuerAndSerialNumber();
    }
    else if(this->AccessSubjectKeyIdentifier())
    {
        pSNACCSignerIdentifier->choiceId = SignerIdentifier::
            subjectKeyIdentifierCid;
        pSNACCSignerIdentifier->subjectKeyIdentifier =
            new SubjectKeyIdentifier;
        pSNACCSignerIdentifier->subjectKeyIdentifier->Set(
            this->AccessSubjectKeyIdentifier()->Access(),
            this->AccessSubjectKeyIdentifier()->Length());
        // In this case, leave optional elements NULL.
    }

    return(pSNACCSignerIdentifier);
}

// GetSignerIdentifier:
//
SignerIdentifier *CSM_RecipientIdentifier::GetSignerIdentifier(bool bIssOrSki)
{
    SignerIdentifier *pSNACCSignerIdentifier;

    pSNACCSignerIdentifier = new SignerIdentifier;

    if ((bIssOrSki == false || (this->AccessIssuerAndSerial() == NULL)) && 
        this->AccessSubjectKeyIdentifier() && pSNACCSignerIdentifier)
    {
        pSNACCSignerIdentifier->choiceId =
            SignerIdentifier::subjectKeyIdentifierCid;
        pSNACCSignerIdentifier->subjectKeyIdentifier =
            new SubjectKeyIdentifier;
        pSNACCSignerIdentifier->subjectKeyIdentifier->Set(
            this->AccessSubjectKeyIdentifier()->Access(),
            this->AccessSubjectKeyIdentifier()->Length());

    }
    else if (this->AccessIssuerAndSerial() && pSNACCSignerIdentifier)
    {
        pSNACCSignerIdentifier->choiceId = SignerIdentifier::
            issuerAndSerialNumberCid;
        pSNACCSignerIdentifier->issuerAndSerialNumber =
            ((CSM_IssuerAndSerialNumber *)this->AccessIssuerAndSerial())->GetSNACCIssuerAndSerialNumber();
    }

    return(pSNACCSignerIdentifier);
}

// GetKEKIdentifier:
//
KEKIdentifier *CSM_RecipientIdentifier::GetKEKIdentifier()
{
    KEKIdentifier *pSNACCKEKIdentifier;

    pSNACCKEKIdentifier = new KEKIdentifier;

    if(this->AccessSubjectKeyIdentifier())
    {
        pSNACCKEKIdentifier->keyIdentifier.Set(
            this->AccessSubjectKeyIdentifier()->Access(),
            this->AccessSubjectKeyIdentifier()->Length());
    }

    if(m_pDate)
    {
        pSNACCKEKIdentifier->date = new GeneralizedTime;
        *pSNACCKEKIdentifier->date = m_pDate->Access();
    }

    if(m_pAttribs)
    {
        pSNACCKEKIdentifier->other = new OtherKeyAttribute;
        pSNACCKEKIdentifier->other->keyAttrId = *m_pAttribs->m_poid;
        pSNACCKEKIdentifier->other->keyAttr = new AsnAny;
        SM_ASSIGN_ANYBUF(m_pAttribs->m_pEncodedAttrib,
                         pSNACCKEKIdentifier->other->keyAttr);
    }

    return(pSNACCKEKIdentifier);
}


// GetOrigIdentOrKey:
//
OriginatorIdentifierOrKey *CSM_RecipientIdentifier::
    GetOrigIdentOrKey(CSM_CSInst *inst)
{
    OriginatorIdentifierOrKey *pSNACCOidOrKey = NULL;
    bool bissorski = true;

    if (inst == NULL)
       return pSNACCOidOrKey;

    if ((this->AccessSubjectKeyIdentifier() != NULL) &&
        (this->AccessIssuerAndSerial() == NULL) &&
        (this->AccessOrigPubKey() == NULL) )
        bissorski = false;

    CSM_Identifier *pB = inst->GetRid(bissorski);

    if ( !bissorski && pB && pB->AccessSubjectKeyIdentifier()
          /* inst->UseOriginatorSKI()*/  )
    {
        pSNACCOidOrKey = new OriginatorIdentifierOrKey;

        pSNACCOidOrKey->choiceId = OriginatorIdentifierOrKey::
            subjectKeyIdentifierCid;
        pSNACCOidOrKey->subjectKeyIdentifier = new SubjectKeyIdentifier;
        pSNACCOidOrKey->subjectKeyIdentifier->Set(
            this->AccessSubjectKeyIdentifier()->Access(),
            this->AccessSubjectKeyIdentifier()->Length());

        // In this case, leave optional elements NULL.
    }
    else if ( (inst && inst->UseOrignatorPublicKey()) ||
        ( (this->AccessSubjectKeyIdentifier() == NULL) &&
        (this->AccessIssuerAndSerial() == NULL) &&
        (this->AccessOrigPubKey() != NULL) ) )
    {
        pSNACCOidOrKey = new OriginatorIdentifierOrKey;

        pSNACCOidOrKey->choiceId = OriginatorIdentifierOrKey::
            originatorKeyCid;
        pSNACCOidOrKey->originatorKey = new OriginatorPublicKey;

        if(m_pOrigPubKeyAlg)
        {
            pSNACCOidOrKey->originatorKey->algorithm = *m_pOrigPubKeyAlg;
        }

        pSNACCOidOrKey->originatorKey->
            publicKey.Set((const unsigned char *)m_pOrigPubKey->Access(),m_pOrigPubKey->Length()*8);
    }
    else if (this->AccessIssuerAndSerial())
    {
        pSNACCOidOrKey = new OriginatorIdentifierOrKey;

        pSNACCOidOrKey->choiceId = OriginatorIdentifierOrKey::
            issuerAndSerialNumberCid;
        pSNACCOidOrKey->issuerAndSerialNumber =
            ((CSM_IssuerAndSerialNumber *)this->AccessIssuerAndSerial())->GetSNACCIssuerAndSerialNumber();
    }

    if (pB)
       delete pB;

    return(pSNACCOidOrKey);
}

// bool comparison operator ==:
//
bool CSM_RecipientIdentifier:: operator == (const CSM_RecipientIdentifier &CRid)
{
    bool result = true;

    if (this->AccessIssuerAndSerial() && CRid.AccessIssuerAndSerial())
    {
        result =
            ((CSM_IssuerAndSerialNumber &)*this->AccessIssuerAndSerial() == *CRid.AccessIssuerAndSerial());
    }
    else
    {
        result = !((this->AccessIssuerAndSerial() == NULL &&
                    CRid.AccessIssuerAndSerial()) ||
                   (this->AccessIssuerAndSerial() &&
                    CRid.AccessIssuerAndSerial() == NULL));
    }

    if (result)
    {
        if (this->AccessSubjectKeyIdentifier() &&
        CRid.AccessSubjectKeyIdentifier())
        {
            result = (*this->AccessSubjectKeyIdentifier() ==
                      *CRid.AccessSubjectKeyIdentifier());
        }
        else
        {
            result = !((this->AccessSubjectKeyIdentifier() == NULL &&
                        CRid.AccessSubjectKeyIdentifier()) ||
                       (this->AccessSubjectKeyIdentifier() &&
                        CRid.AccessSubjectKeyIdentifier() == NULL));
        }
    }

    if (result)
    {
        if (m_pOrigPubKey && CRid.AccessOrigPubKey())
        {
            result = (*m_pOrigPubKey == *CRid.AccessOrigPubKey());
        }
        else
        {
            result = !((m_pOrigPubKey == NULL && CRid.AccessOrigPubKey()) ||
                (m_pOrigPubKey && CRid.AccessOrigPubKey() == NULL));
        }
    }

    if (result)
    {
        if (m_pDate && CRid.AccessDate())
        {
            result = (*m_pDate == *CRid.AccessDate());
        }
        else
        {
            result = !((m_pDate == NULL && CRid.AccessDate()) ||
                (m_pDate && CRid.AccessDate() == NULL));
        }
    }

    if (result)
    {
        if (m_pAttribs && CRid.AccessAttrib())
        {
            result = (*m_pAttribs == *CRid.AccessAttrib());
        }
        else
        {
            result = !((m_pAttribs == NULL && CRid.AccessAttrib()) ||
                (m_pAttribs && CRid.AccessAttrib() == NULL));
        }
    }

    return result;
}

// assignment operator =:
//
CSM_RecipientIdentifier &CSM_RecipientIdentifier::
    operator = (const CSM_RecipientIdentifier &Rid)
{

    if (Rid.AccessIssuerAndSerial())
    {
        CSM_IssuerAndSerialNumber tmpISN(*Rid.AccessIssuerAndSerial());
        this->SetIssuerAndSerial(tmpISN);
    }

    if (Rid.AccessSubjectKeyIdentifier())
    {
        CSM_Buffer tmpbuf(*Rid.AccessSubjectKeyIdentifier());
        this->SetSubjectKeyIdentifier(tmpbuf);
    }

    if (Rid.AccessOrigPubKey())
    {
        if (m_pOrigPubKey)
            delete m_pOrigPubKey;

        m_pOrigPubKey = new CSM_Buffer(*Rid.AccessOrigPubKey());
    }

    if (Rid.AccessDate())
    {
        if (m_pDate)
            delete m_pDate;

        m_pDate = new CSM_Buffer(*Rid.AccessDate());
    }

    if (Rid.AccessAttrib())
    {
        if (m_pAttribs)
            delete m_pAttribs;

        m_pAttribs = new CSM_Attrib(*Rid.AccessAttrib());
    }

    return(*this);
}

_END_SFL_NAMESPACE

// EOF for sm_RecipientIdent.cpp
