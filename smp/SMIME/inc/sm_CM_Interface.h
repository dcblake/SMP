//////////////////////////////////////////////////////////////////////////
//
// FILE:  sm_CM_Interface.h
//
// DESCRIPTION:   CLASS description for CM_Interface
//
//  The design intent of this include file definitions is to provide an 
//  Insecure class to initialize the CML/SRL sessions for an example 
//  demonstration.  It is intended to provide a minimal CML interface,
//  where the user is expected to provide a fully secure set of policy
//  definitions, etc. as described in the CML documentation.
//
//  The SFL use of these classes intends to load certificates from an
//  incomming message (e.g. in PreProc(...)) into the SRL, then access
//  these certificates in the actual Sign/Verify/Encrypt/Decrypt operations
//  after validation if requested.
//        
//
//////////////////////////////////////////////////////////////////////////
#ifndef __CM_INTERFACE_H
#define __CM_INTERFACE_H

#ifdef CML_USED

#include "cmapi_cpp.h"  // Needed for CML 
#include "srlapi.h"     // Needed for SRL


#define SM_TOO_MANY_CERTS_FOUND_IN_DB	190


//_BEGIN_SFL_NAMESPACE
#ifndef NO_NAMESPACE
namespace SFL {
#endif // NO_NAMESPACE


//########################################################################
//  THIS SPECIAL CLASS uses the default settings to initialize the CML
//  session.   WITHOUT PROPER SETUP, VALIDATION MAY RETURN INVALID RESULTS!!!
//  (see the CML API document for details).
class CM_Interface
{
public:
	CM_Interface()                 { m_lCmlSessionId = 0; m_lSrlSessionId = 0; }
	CM_Interface(ulong lCmlSessionId, ulong lSrlSessionId);

	ulong GetSRLSessionID() const                    { return m_lSrlSessionId; }
	ulong GetCMLSessionID() const                    { return m_lCmlSessionId; }
	void  SetSessions(ulong lCmlSessionId, ulong lSrlSessionId);
	bool  UsingCML()                          { return (m_lCmlSessionId != 0); }

	short dbFileAdd(Bytes_struct* pAsnData, AsnTypeFlag fileType);
	short dbAddCert(const CTIL::CSM_Buffer& bufCert);
	short dbAddCRL(const CTIL::CSM_Buffer& bufCrl);

	static void ConvertErrorList(std::string& errStr,
		const CML::ErrorInfoList& cmlErrors);

private:
	ulong m_lCmlSessionId;
	ulong m_lSrlSessionId;
};


// THIS special class was created to access the CML protected method that
//  returns the validated public key and params (esepcially nice for DSA).
class CM_SFLInternalCertificate: public CML::CertPath//RWC;Certificate
{
private:
    //CML::ASN::Cert m_CMLcert;
public:
   CM_SFLInternalCertificate(const CML::Certificate& cert): CertPath(cert)
   { m_pParameters=NULL;}
   //RWC;CM_SFLInternalCertificate(const CML::ASN::Cert& cert): CertPath(cert)
   //RWC;{ m_pParameters=NULL;}
	CM_SFLInternalCertificate(const CML::ASN::Bytes& asn, bool isCertPath = true): CertPath(asn, isCertPath)
   { m_pParameters=NULL;}
   //RWC;CM_SFLInternalCertificate(const Bytes_struct& asn): CertPath(asn)
   //RWC;{ m_pParameters=NULL;}
    //~CM_SFLInternalCertificate() { if (m_pCMLcert) delete m_pCMLcert; }


	/*RWC;short VerifySignature(ulong sessionID) const
   { return Certificate::VerifySignature(sessionID, m_publicKey/ *PRE2.4, m_pParameters* /); }*/

   //const CML::ASN::DN &AccessIssuer() { return m_pCMLcert->issuer; }
   //const CML::ASN::Cert &AccessCMLCert() { return m_CMLcert; }
   CML::ASN::PublicKeyInfo m_publicKey;
   CTIL::CSM_Buffer *m_pParameters;
};

#ifdef NODEF
class CM_SFLInternalCRL
{
public:
   CM_SFLInternalCRL() { Clear(); };

   void Clear() 
   { pSignature = NULL; pIssuedAfter = NULL; 
     pIssuedBefore=NULL;  onlyOne = false; 
   }



	const SNACC::AsnOid*	   pSignature;		// Algorithm used to sign CRL
	const CML::ASN::Time*	pIssuedAfter;	// Issued on or after this date
	const CML::ASN::Time*	pIssuedBefore;	// Issued on or before this date
	bool				      	onlyOne;		// When true, only one CRL returned
}
#endif

// 
//########################################################################
// SFL users are welcome to call the CML class interface methods directly 
//  (since public) OR use the SFL version, that will automatically look up
//  the End Entity certificate if possible using the CML/SRL.  This class
//  was created to allow the SFL to specify just an IssuerAndSerialNumber
//  and be able to perform validation and retrieval when necessary to verify
//  the message signature.
class CM_SFLCertificate 
{
private:
   CM_SFLInternalCertificate/*CML::Certificate*/ *m_pCMLCert;
 //  CML::CRLMatchData       *m_pCMLCrl;
public:
   CM_SFLCertificate() {
		m_pCMLCert = NULL; m_pRID = NULL; m_boundsFlag = CM_SEARCH_UNTIL_FOUND; }
	CM_SFLCertificate(const CERT::CSM_IssuerAndSerialNumber& IssuerSN) {
		m_pCMLCert = NULL; m_boundsFlag = CM_SEARCH_UNTIL_FOUND;
		m_pRID = new CERT::CSM_Identifier(IssuerSN); }
	CM_SFLCertificate(const CERT::CSM_Identifier& RID) {
		m_pCMLCert = NULL; m_boundsFlag = CM_SEARCH_UNTIL_FOUND;
		m_pRID = new CERT::CSM_Identifier(RID); }
	CM_SFLCertificate(const CTIL::CSM_Buffer& BufCert) {
		m_pCMLCert = NULL; m_pRID = NULL; m_boundsFlag = CM_SEARCH_UNTIL_FOUND; 
		SetUserCert(BufCert); }
	~CM_SFLCertificate()                                            { Clear(); }

   void Clear() {
		delete m_pCMLCert; m_pCMLCert = NULL; delete m_pRID; m_pRID = NULL;
		m_boundsFlag = CM_SEARCH_UNTIL_FOUND; /*m_lCmlSessionId = 0;*/
		m_errorString = m_errorString.erase();}

	const CML::CertPath* AccessCMLCert() const            { return m_pCMLCert; }
   long GetUserCert(const CM_Interface& cmlInterface);
	void SetSKI(const CTIL::CSM_Buffer& BufSKI) {
		Clear(); m_pRID = new CERT::CSM_Identifier(BufSKI); }
   void SetUserCert(const CTIL::CSM_Buffer& BufCert);
	void SetUserCert(const CML::Certificate& CMLCert) {
		Clear(); m_pCMLCert = new CM_SFLInternalCertificate(CMLCert); }
	long Validate(const CM_Interface& cmlInterface,
		const CML::ASN::Time* pValidationTime = NULL);

   // 
   // 
	CERT::CSM_Identifier* m_pRID;   // used to get the Cert
//	CM_DN*        m_pDN;            // used to get the Crl
	SearchBounds  m_boundsFlag;     // USER is welcome to over-ride!
//	unsigned long m_lCmlSessionId;
//	unsigned long m_lSrlSessionId;
	std::string   m_errorString;
};


//_END_SFL_NAMESPACE
#ifndef NO_NAMESPACE
}          // END namespace
#endif // NO_NAMESPACE

#endif //CML_USED


#endif      // __CM_INTERFACE_H
