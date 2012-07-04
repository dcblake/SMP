
//
//  sm_CM_Interface.cpp
//
//################


#include "sm_api.h"
#include "sm_CM_Interface.h"


// Using declarations
using namespace SNACC;
using namespace CTIL;
using namespace CERT;


_BEGIN_SFL_NAMESPACE


///////////////////////////////////////////////////////////////////////////////
CM_Interface::CM_Interface(ulong lCmlSessionId, ulong lSrlSessionId)
{
	m_lCmlSessionId = lCmlSessionId;
	m_lSrlSessionId = lSrlSessionId;
}


void CM_Interface::SetSessions(ulong lCmlSessionId, ulong lSrlSessionId)
{
	m_lCmlSessionId = lCmlSessionId;
	m_lSrlSessionId = lSrlSessionId;
}


////////////////////////////////////////////////////////////////////////////////////////////////
//
// dbFileAdd 
//
//    Calls SRL_DatabaseAdd to add the file input in pAsnData to the database.  
//    fileType indicates the asn1 type, either cert or crl.
//
// returns result from SRL_DatabaseAdd call
//
////////////////////////////////////////////////////////////////////////////////////////////////
short CM_Interface::dbFileAdd(Bytes_struct* pAsnData, AsnTypeFlag fileType)           
{
	return SRL_DatabaseAdd(m_lSrlSessionId, pAsnData, fileType);
}


//
//
short CM_Interface::dbAddCert(const CTIL::CSM_Buffer& bufCert)
{
	Bytes_struct certBytes;
	certBytes.num = bufCert.Length();
	certBytes.data = (unsigned char*)bufCert.Access();

   return dbFileAdd(&certBytes, SRL_CERT_TYPE);
}     // END CM_Interface::dbAddCRL(...)


//
//
short CM_Interface::dbAddCRL(const CTIL::CSM_Buffer& bufCrl)
{ 
	Bytes_struct crlBytes;
	crlBytes.num = bufCrl.Length();
	crlBytes.data = (unsigned char*)bufCrl.Access();

   return dbFileAdd(&crlBytes, SRL_CRL_TYPE);
}     // END CM_Interface::dbAddCRL(...)


//
//
void CM_Interface::ConvertErrorList(std::string& errStr,
												const CML::ErrorInfoList& cmlErrors)
{
	std::ostringstream os;
	int i = 0;

	CML::ErrorInfoList::const_iterator iError;
	for (iError = cmlErrors.begin(); iError != cmlErrors.end(); ++iError)
	{
		// Output the start of the info for this error
		os << "pErrorInfo: " << ++i << ", DN= ";

		// Output the best string name form to use for this error
		CML::ASN::GenNames::const_iterator iGN =
			iError->name.Find(CML::ASN::GenName::X500);
		if (iGN != iError->name.end())
			os << *iGN->GetName().dn;
		else
		{
			iGN = iError->name.Find(CML::ASN::GenName::RFC822);
			if (iGN == iError->name.end())
				iGN = iError->name.Find(CML::ASN::GenName::DNS);
			if (iGN == iError->name.end())
				iGN = iError->name.Find(CML::ASN::GenName::URL);
			if (iGN != iError->name.end())
				os << iGN->GetName().name;
			else
				os << "<Unsupported Name Form>";
		}

		// Output the extra error info if present
		if (!iError->extraInfo.empty())
			os << " xinfo=" << iError->extraInfo;

		// Output the error string
		os << " errorString=" << CMU_GetErrorString(iError->error) << std::endl;
	}

	// Append the string of CML errors to the input parameter string
	errStr += os.str();
}        // END CM_Interface::getErrInfo(...)


//
//  This method will attempt to retrieve the user cert based on the information
//  contained in this class instance (e.g. IssuerAndSerialNumber OR SKI) if the dbType 
//  input parameter is set to SRL_DB_CERT; or this method will attempt to retrieve the
//  crl based on the information contained in this class instance if the dbType input parameter
//  is set to SRL_DB_CRL
long CM_SFLCertificate::GetUserCert(const CM_Interface& cmlInterface)//, DBTypeFlag dbType)
{
	SME_SETUP("CM_SFLCertificate::GetUserCert");

	if (m_pRID == NULL)
		SME_THROW(28, "m_pRID identifier not set.", NULL);

	// Delete any existing cert
	if (m_pCMLCert != NULL)
	{
		delete m_pCMLCert;
		m_pCMLCert = NULL;
	}

	// Get the issuer/serial number pair and the subject key ID from the RID
   const CERT::CSM_IssuerAndSerialNumber* pIssuerSN =
		m_pRID->AccessIssuerAndSerial();
   const CSM_Buffer* pTmpSKIBuf = m_pRID->AccessSubjectKeyIdentifier();
	if ((pIssuerSN == NULL) && (pTmpSKIBuf == NULL))
	{
		SME_THROW(28, "m_pRID identifier not supported (not IssSN OR SKI).",
			NULL);
	}

	// Initialize the dbSearchStruct and SRL_CertMatch_struct
	dbSearch_struct dbSearchInfo;
	SRL_CertMatch_struct certMatchInfo;
	memset(&certMatchInfo, 0, sizeof(SRL_CertMatch_struct));
	dbSearchInfo.dbType = SRL_DB_CERT;
	dbSearchInfo.matchInfo.cert = &certMatchInfo;

	// Local variables to hold CertMatchData info
	std::auto_ptr<CML::ASN::DN> issuerDN;
	std::auto_ptr<CSM_Buffer> serialNumBuf;
	Bytes_struct serialNum;
	Bytes_struct subjKeyID;

	if (pIssuerSN != NULL)
	{
		// Set the issuer/serial number in the CertMatchData
      std::auto_ptr<CML::ASN::DN> issuerDN2(pIssuerSN->GetIssuer());
      std::auto_ptr<CSM_Buffer> serialNumBuf2(pIssuerSN->GetSerialNo());
		issuerDN = issuerDN2;
		serialNumBuf = serialNumBuf2;
		serialNum.data = (uchar*)serialNumBuf->Access();
		serialNum.num = serialNumBuf->Length();
		certMatchInfo.issuerDN = (CM_DN)issuerDN.get()->operator const char*();
		certMatchInfo.serialNum = &serialNum;
	}

	if (pTmpSKIBuf != NULL)
	{
		// Set the subject key ID in the CertMatchData
		subjKeyID.data = (uchar*)pTmpSKIBuf->Access();
		subjKeyID.num = pTmpSKIBuf->Length();
		certMatchInfo.subjKMID = &subjKeyID;
	}

	// Search the database
	EncObject_LL* pObjList;
	short srlResult = SRL_DatabaseSearch(cmlInterface.GetSRLSessionID(), NULL,
		SRL_DB_CERT, &dbSearchInfo, &pObjList);

	// Throw if an
	if (srlResult != CM_NO_ERROR)
		return srlResult;
	else if (pObjList->next != NULL)
	{
	   SRL_FreeObjs(NULL, &pObjList);
	   return SM_TOO_MANY_CERTS_FOUND_IN_DB;
	}

	// Create the private member cert from the one found in the DB
	m_pCMLCert = new CM_SFLInternalCertificate(pObjList->encObj, false);
   SRL_FreeObjs(NULL, &pObjList);

   SME_FINISH_CATCH
	return 0;

} // end of CM_SFLCertificate::GetUserCert()


//
//
void CM_SFLCertificate::SetUserCert(const CSM_Buffer& BufCert)
{
    Bytes_struct ACertByteStruct;
    ACertByteStruct.data = (unsigned char*)BufCert.Access();
    ACertByteStruct.num  = BufCert.Length();
    SetUserCert(ACertByteStruct);
}       // END CM_SFLCertificate::SetUserCert(...)


/************************************************************************
 FUNCTION:  CM_SFLCertificate::Validate
 
 Description: Calls CML Build And Validate to validate a certificate

 Inputs: 
	CML::ASN::Time*  pTimeStampTime  -  Optional. Points to a date/time that 
                                        must be used when checking revocation
                                        status if present

 Return Value: 
	short result - result of Certificate Validation

*************************************************************************/
long CM_SFLCertificate::Validate(const CM_Interface& cmlInterface,
											const CML::ASN::Time* pValidationTime)
{
	// Find the user cert first if necessary
	if (m_pCMLCert == NULL)
	{
		long result = GetUserCert(cmlInterface);
		if (m_pCMLCert == NULL)
			return result;
	}

	CML::ErrorInfoList Errors;
	short sReturn = m_pCMLCert->BuildAndValidate(cmlInterface.GetCMLSessionID(),
		m_boundsFlag, &Errors, 0, NULL, pValidationTime);
	if (sReturn != 0)
	{
		// If an existing error is present, append a CRLF
		if (!m_errorString.empty())
			m_errorString.append("\n");

		// Convert the errors to string form and append them to the string
		cmlInterface.ConvertErrorList(m_errorString, Errors);
	}

	return sReturn;
}


_END_SFL_NAMESPACE
// END CM_Interface.cpp
