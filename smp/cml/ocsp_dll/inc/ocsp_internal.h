///////////////////////////////////////////////////////////////////////////////
// File:		      ocsp_internal.h
// Project:		   Certificate Management Library
// Contents:	   Header file for the OCSP revocation status callback internal
//                functionality
// Requirements:  CML Requirements 2.1-5.
// 
// Created:		   13 December 2004
// Author:		   Tom Horvath <Tom.Horvath@BAESystems.com>
// 
// Last Updated:  13 December 2004
// 
// Version:		   2.5
///////////////////////////////////////////////////////////////////////////////
#ifndef _OCSP_INTERNAL_H
#define _OCSP_INTERNAL_H

#ifdef _MSC_VER
	#pragma warning(disable: 4786)	// Disable identifier truncated warning
#endif
////////////////////
// Included Files //
////////////////////
#include <ocspapi.h>          // needed for CML OCSP types
#include <openssl/ossl_typ.h> // needed for OpenSSL types
#include <openssl/x509.h>     // needed for OpenSSL X.509 types
#include <openssl/ocsp.h>     // needed for OpenSSL OCSP types
#include <openssl/err.h>      // needed for OpenSSL Error types
#include <openssl/engine.h>   // needed for OpenSSL types
#include <map>                // needed for std::map

// Map of OCSP CERTIDs added to an OCSP request ordered by certificate's hash
typedef std::map<CML::ASN::Bytes, OCSP_CERTID*> CertIDMap;      
// Map of OCSP Requests ordered by URL of the responder
typedef std::map<std::string, OCSP_REQUEST*> RequestMap;
// Map of OCSP Responses ordered by URL of the responder
typedef std::map<std::string, OCSP_RESPONSE*> ResponseMap;

// The OCSPState class contains state information for each
// revocation status request.
class OCSPState
{
public:
   
   ~OCSPState(); // Destructor

   // Members
   CertIDMap m_certIDMap;     // OCSP_CERTIDs used in a single revocation
                              // status request
   RequestMap m_requestMap;   // OCSP_REQUESTs used in a single revocation
                              // status request
   ResponseMap m_responseMap; // OCSP_RESPONSES used in a single revocation
                              // status request
   CML::ASN::BytesList m_issuerList;   // The list of issuer certificates used
                              // in a single revocation status request
   CML::ASN::BytesList m_encodedResponseList;   // The list of ASN encoded
                              // OCSP responses used to determine the status
                              // of all of the certificates in a single 
                              // revocations status request.
};

//The TrustedCert class constains the information needed to store a 
// trusted certificate
class TrustedCert
{
public:
   TrustedCert::TrustedCert(const CML::ASN::Bytes& cert, 
      bool trustExplicit = false) :
      m_trustExplicit(trustExplicit), m_encCert(cert) {} 
   const bool              m_trustExplicit;  // Only set for paths containing a
                                             // trusted global responder
   const CML::ASN::Bytes   m_encCert;        // encoded certficate
};

typedef std::list<TrustedCert> TACertList;
 
// Utility function prototypes
int OCSPi_find_signer(X509 **pSigner, OCSP_BASICRESP *pBasicResp, 
                      STACK_OF(X509) *pCerts, X509_STORE *pStore,
                      unsigned long flags);

#endif //_OCSP_INTERNAL_H
