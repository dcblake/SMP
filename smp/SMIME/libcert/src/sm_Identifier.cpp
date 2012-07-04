
#include "sm_apiCert.h"
_BEGIN_CERT_NAMESPACE 
using namespace SNACC;

//////////////////////////////////////////////////////////////////////////
// sm_Identifier.cpp
// implementation of methods from:
//   CSM_Identifier
//////////////////////////////////////////////////////////////////////////

// use this constructor to make a new this CSM structure
CSM_Identifier::CSM_Identifier (const CSM_Identifier &Rid)
{
    SME_SETUP("CSM_Identifier::CSM_Identifier &");

    Clear();
    *this = Rid;

    SME_FINISH_CATCH
}

// CONSTRUCTOR FOR CSM_Identifier USING Subject Key Identifier
//
CSM_Identifier::CSM_Identifier(const CSM_Buffer &SubjKeyId)
{
    Clear();

    this->SetSubjectKeyIdentifier(SubjKeyId);
}

// DESTRUCTOR FOR CSM_Identifier
//
CSM_Identifier::~CSM_Identifier()
{
    if (m_pIssASN)
        delete m_pIssASN;
    if (m_pSubjKeyId)
        delete m_pSubjKeyId;

}

// GetIssuerAndSerial:
// returns a pointer to the CSM_IssuerAndSerialNumber class for IssuerAndSerial
CSM_IssuerAndSerialNumber *CSM_Identifier::GetIssuerAndSerial()
{
    CSM_IssuerAndSerialNumber *ptmpIASN = NULL;

    SME_SETUP("CSM_Identifier::GetIssuerAndSerial()");

    if (m_pIssASN)
        ptmpIASN = new CSM_IssuerAndSerialNumber(*m_pIssASN);

    SME_FINISH_CATCH
    return ptmpIASN;
}

// GetSubjectKeyIdentifier:
//   member function to return the SKI from local memory
CSM_Buffer *CSM_Identifier::GetSubjectKeyIdentifier()
{
    CSM_Buffer *ptmpSubjKeyId = NULL;

    SME_SETUP("CSM_Identifier::GetSubjectKeyId");

    if (m_pSubjKeyId != NULL)
      ptmpSubjKeyId = new CSM_Buffer(*m_pSubjKeyId);

    SME_FINISH_CATCH
    return ptmpSubjKeyId;
}

// CSM_Identifier Set member functions:

// SetIssuerAndSerial:
//   set this private variable with a CSM_IssuerAndSerialNumber
void CSM_Identifier::SetIssuerAndSerial(const CSM_IssuerAndSerialNumber &iasn)
{
    SME_SETUP("CSM_Identifier::SetIssuerAndSerial(CSM_IssuerAndSerialNumber &");

    if (m_pIssASN == NULL)
        m_pIssASN = new CSM_IssuerAndSerialNumber(iasn);
    else
       *m_pIssASN = iasn;

    SME_FINISH_CATCH
}

// SetSubjectKeyIdentifier:
//   set this private variable with a CSM_Buffer subjKeyID
void CSM_Identifier::SetSubjectKeyIdentifier(const CSM_Buffer &subjKeyId)
{
    SME_SETUP("CSM_Identifier::SetSubjectKeyId(CSM_Buffer &subjKeyId)");

    if (m_pSubjKeyId == NULL)
        m_pSubjKeyId = new CSM_Buffer(subjKeyId);

    SME_FINISH_CATCH
}

// COMPARISON OPERATOR (==)
//
bool CSM_Identifier:: operator == (CSM_Identifier &CRid)
{
    bool result = true;

    // IF PASSED RECIPIENT IDENTIFIER DOES NOT HAVE EITHER IssASN OR SKI AND
    // AND ALSO LOCAL MEMORY DOES NOT HAVE EITHER IssASN OR SKI
    // (BOTH SIDES ARE NULL) THEN NOTHING = NOTHING, RETURN TRUE
    if (((CRid.AccessIssuerAndSerial() == NULL) &&
         (CRid.AccessSubjectKeyIdentifier() == NULL)) &&
        ((m_pIssASN == NULL) && (m_pSubjKeyId == NULL)))
    {
       result = true;
    }
    else
    {
      // OK WE NOW KNOW BOTH SIDES ARE NOT NULL
      // IF JUST PASSED RECIPIENT IDENTIFIER DOES NOT HAVE EITHER IssASN
        // OR SKI OR JUST LOCAL MEMORY DOES NOT HAVE EITHER IssASN OR SKI
      // (ONE SIDE IS NULL THE OTHER NOT NULL) THEN SOMETHING != NOTHING
      // RETURN FALSE
        if (((CRid.AccessIssuerAndSerial() == NULL) &&
             (CRid.AccessSubjectKeyIdentifier() == NULL)) ||
            ((m_pIssASN == NULL) && (m_pSubjKeyId == NULL)))
        {
           result = false;
        }
        else
        {
            // IF LOCAL MEMORY AND PASSED RECIPIENT IDENTIFIER ARE IssASN
            if (m_pIssASN && CRid.AccessIssuerAndSerial())
            {
                // THE RESULTS CAN BE THE COMPARISON OF THE TWO VALUES
                result = (*m_pIssASN == *CRid.AccessIssuerAndSerial());
            }
            else
            {
                // IF LOCAL MEMORY HAS NO IssASN (ASSUMES IT HAS SKI) AND
                // PASSED RECIPIENT IDENTIFIER HAS IssASN, BUT NO SKI
                // OR
                // IF LOCAL MEMORY HAS IssASN AND PASSED RECIPIENT IDENTIFIER
                // HAS NO IssASN, BUT DOES HAVE SKI
                // **  IF EITHER OF THESE CASES IS TRUE
                // **  THEN NEGATE THE RESULT (CANNOT COMPARE VALUES)
                result = !((m_pIssASN == NULL &&
                            CRid.AccessIssuerAndSerial() &&
                            CRid.AccessSubjectKeyIdentifier() == NULL) ||
                           (m_pIssASN &&
                            CRid.AccessIssuerAndSerial() == NULL &&
                            CRid.AccessSubjectKeyIdentifier()));
            }

            // IF TRUE CHECK OTHER POSSIBLE FAILURES
            if (result)
            {
                // IF LOCAL MEMORY AND PASSED RECIPIENT IDENTIFIER ARE SKI
                if(m_pSubjKeyId && CRid.AccessSubjectKeyIdentifier())
                {
                    // THE RESULTS CAN BE THE COMPARISON OF THE TWO VALUES
                    result =
                        (*m_pSubjKeyId == *CRid.AccessSubjectKeyIdentifier());
                }
                else
                {
                    // IF LOCAL MEMORY HAS NO SKI (ASSUMES IT HAS IssASN) AND
                    // PASSED RECIPIENT IDENTIFIER HAS SKI, BUT NO IssASN
                    // OR
                    // IF LOCAL MEMORY HAS SKI AND PASSED RECIPIENT IDENTIFIER
                    // HAS NO SKI, BUT DOES HAVE IssASN
                    // **  IF EITHER OF THESE CASES IS TRUE
                    // **  THEN NEGATE THE RESULT (CANNOT COMPARE VALUES)
                    result = !((m_pSubjKeyId == NULL &&
                                CRid.AccessSubjectKeyIdentifier() &&
                                CRid.AccessIssuerAndSerial() == NULL) ||
                               (m_pSubjKeyId &&
                                CRid.AccessSubjectKeyIdentifier() == NULL &&
                                CRid.AccessIssuerAndSerial()));
                }
            }
        }
    }

    return result;
}

// ASSIGNMENT OPERATORY (=)
//
CSM_Identifier& CSM_Identifier::operator = (const CSM_Identifier &Rid)
{

    if (Rid.AccessIssuerAndSerial())
    {
        if(m_pIssASN)
            delete m_pIssASN;

        m_pIssASN = new CSM_IssuerAndSerialNumber(*Rid.AccessIssuerAndSerial());
    }

    if (Rid.AccessSubjectKeyIdentifier())
    {
        if(m_pSubjKeyId)
            delete m_pSubjKeyId;

        m_pSubjKeyId = new CSM_Buffer(*Rid.AccessSubjectKeyIdentifier());
    }

    return(*this);
}

_END_CERT_NAMESPACE 

// EOF for sm_Identifier.cpp
