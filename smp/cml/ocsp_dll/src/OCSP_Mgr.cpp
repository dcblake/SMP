///////////////////////////////////////////////////////////////////////////////
// File:		      OCSP_Mgr.cpp
// Project:		   Certificate Management Library
// Contents:	   Implementation of the OCSP revocation status callback code.
// Requirements:  CML Requirements 2.1-5.
// 
// Created:		   13 December 2004
// Author:		   Tom Horvath <Tom.Horvath@BAESystems.com>
// 
// Last Updated:  27 Jan 2005
// 
// Version:		   2.5
//
// Description: This file contains the following OCSP API functions:
//	   OCSP_Init
//    OCSP_Destroy
//	   OCSP_RequestRevokeStatus
//
///////////////////////////////////////////////////////////////////////////////

////////////////////
// Included Files //
////////////////////
#include <ocsp_internal.h> // needed for CML OCSP internal types

///////////////
// Constants //
///////////////

// This library does not currently support CRL-based revocation status checking  
// of an OCSP responder certificate. Therefore, the extension id-pkix-ocsp-nocheck
// must be present in non-default global OCSP responder certificates.

// PKIX OCSP No Check Extension
static const char *id_pkix_ocsp_nocheck = "1.3.6.1.5.5.7.48.1.5";

// This needs to be here because the OpenSSL library does not have a cast 
// for this parameter, i2d_OCSP_RESPONSE, in the i2d_OCSP_RESPONSE_bio macro.
#define i2d_OCSP_RESPONSE (int (*)())i2d_OCSP_RESPONSE  

/////////////////
// Name Spaces //
/////////////////
using namespace CML::ASN;
using namespace std;

//////////////////////
// Global Variables //
//////////////////////
string         gDefResponderURL;          // Default OCSP global responder URL
Bytes          gDefResponderCert;         // Default OCSP global responder cert
TACertList     gTrustedCertList;          // Trusted certificates
bool           gDoNonce = true;           // Nonce processing setting
long           gNsec = 0;                 // Used for validity period test
long           gMaxAge = -1;              // Used for validity period test
bool           gInitialized = false;      // Determines the state of library

/////////////////////////
// Function Prototypes //
/////////////////////////
static X509_STORE* OCSPi_CreateCertStore(OCSPState& state);
static short OCSPi_AddCertToStore(const Bytes& cert, 
                                  X509_STORE& store, 
                                  bool isTrusted);
static X509* OCSPi_DecodeCert(const Bytes& cert);
static short OCSPi_GetResponderURL(const Bytes_struct& encCert,
                                   string& responderURL);
static short OCSPi_GenerateRequests(const RevStatus_LL* pRequestData,
                                    OCSPState& state);
static short OCSPi_GenerateAndAddCertID(const Bytes_struct& encCert,
                                        const Bytes_struct& encIssuerCert,
                                        RequestMap::iterator iReq,
                                        OCSPState& state);
static short OCSPi_AddNonce(RequestMap& requestMap);
static void OCSPi_TransmitRequests(OCSPState& state);
static short OCSPi_ValidateResponses(OCSPState& state, bool wantBack);
static short OCSPi_VerifyBasicResponse(OCSP_BASICRESP& basicResp,
                                       OCSPState& state);
static short OCSPi_FillRevInfos(RevStatus_LL* pRequestData,
                               OCSPState& state);
static short OCSPi_FillSingleRevInfo(const Bytes_struct& encCert,
                                     RevInfo& RevInfo, OCSPState& state,
                                     const string& responderURL);
static short OCSPi_ProcessWantBacks(const OCSPState& state, 
                                    EncRevObject_LL** pRevocationData);
static bool OCSPi_OCSPNoCheckExtPresent(X509& encCert);
static bool OCSPi_IsResponderValid(X509& responder, X509& issuer);
static X509* OCSPi_GetIssuerByName(X509& pSubject, OCSP_BASICRESP& basicResp, X509_STORE& pStore);


///////////////////////////////////////////////////////////////////////////////
// Function:      OCSP_Init()
// Description:   Initialize the OCSP revocation callback library for use
// Inputs:        serverSettings
// Outputs:       (none)
// Return value:  OCSP_SUCCESS      - library has been successfully initialized
//                OCSP_INIT_ERROR   - initialization has failed
///////////////////////////////////////////////////////////////////////////////
 
short OCSP_Init(OSCPDLLInitSettings_struct* serverSettings)
{
   // check if library is already initialized
   if (gInitialized == true)
      return OCSP_INIT_ERROR;

   // Check the parameters
   if ((serverSettings == NULL) || (serverSettings->m_trustedCACerts == NULL))
      return OCSP_INIT_ERROR;

   // Initialize the library for use.
   //
   // Set the default resonder if it was provided
   if (serverSettings->m_defResponderURL != NULL)
      gDefResponderURL = serverSettings->m_defResponderURL;

   // Set the global responder certificate if it was provided
   try
   {
      if (serverSettings->m_defResponderCert != NULL)
      {
         gDefResponderCert = *serverSettings->m_defResponderCert;
      }
   }
	catch (...)
   {
      return OCSP_INIT_ERROR;
	}

   // Set the nonce processing flag, and validity period window settings
   gDoNonce = serverSettings->m_doNonce;
   if (serverSettings->m_nSec != 0)
      gNsec = serverSettings->m_nSec;
   if (serverSettings->m_maxAge != 0)
      gMaxAge = serverSettings->m_maxAge;

   // Create trusted cert list
   const EncTrustedCert_LL* pEncCert = serverSettings->m_trustedCACerts;
   while(pEncCert != NULL)
   {
      try
      {
         if (pEncCert->m_trustExplicit == FALSE)
            gTrustedCertList.push_back(TrustedCert(pEncCert->m_encCert, false));
         else if (pEncCert->m_trustExplicit == TRUE)
            gTrustedCertList.push_back(TrustedCert(pEncCert->m_encCert, true));
         else
            throw OCSP_INVALID_PARAMETER;
      } 
      catch (...)
      {
         return OCSP_INIT_ERROR;
      }
      pEncCert = pEncCert->m_next;
   }

   // OpenSSL initialization
   ERR_load_crypto_strings();
   OpenSSL_add_all_algorithms();

   gInitialized = true;
   return OCSP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSP_Destroy()
// Description:   Deallocate any resources created by the OCSP revocation
//                callback library. Should be called at application exit.
// Inputs:        (none)
// Outputs:       (none)
// Return value:  (none)
///////////////////////////////////////////////////////////////////////////////
void OCSP_Destroy()
{
   if (gInitialized == true)
   {
      // Free OpenSSL resources
      EVP_cleanup();
      CRYPTO_cleanup_all_ex_data();
      ERR_free_strings();
      gInitialized = false;
   }
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSP_RequestRevokeStatus()
// Description:   To get the revocation status of a cert, or a list of certs.
// Inputs:        handle, timeout, pRequestData, pTimeStampTime
// Outputs:       pRequestData
// Return value:  CRLResponseCode - from cmapiCallbacks.h
///////////////////////////////////////////////////////////////////////////////
short OCSP_RequestRevokeStatus(void* handle, time_t timeout, 
							  RevStatus_LL* pRequestData, 
							  CM_TimePtr pTimeStampTime,
                       CM_BOOL wantBack,
                       EncRevObject_LL** pRevocationData)
{
   short ret = CRL_RESP_SUCCESS;

   // Check the parameters
   if ((handle != NULL) ||
       (timeout != 0) ||
       (pRequestData == NULL) ||
       (pTimeStampTime != NULL) ||
       ((wantBack == TRUE) && (pRevocationData == NULL)))
      return CRL_RESP_MALFORMED;

   // The following state variable will keep track of all of the OCSP cert IDs,
   // requests and responses used during this revocation status request.
   OCSPState state;
 
   // Generate OCSP request(s).
   if (OCSPi_GenerateRequests(pRequestData, state) != OCSP_SUCCESS)
      ret = CRL_RESP_MALFORMED;

   // Transmit OCSP request(s) and recieve OCSP responses.
   if (ret == CRL_RESP_SUCCESS)
      OCSPi_TransmitRequests(state);

   // Validate OCSP response(s).
   if ((ret == CRL_RESP_SUCCESS) && 
       (OCSPi_ValidateResponses(state, wantBack) != OCSP_SUCCESS))
      ret = CRL_RESP_INTERNAL_ERR;

   // Populate Revocation Status information.
   if ((ret == CRL_RESP_SUCCESS) && 
       (OCSPi_FillRevInfos(pRequestData, state) != OCSP_SUCCESS))
      ret = CRL_RESP_INTERNAL_ERR;

   // Process want backs if requested
   if ((ret == CRL_RESP_SUCCESS) && (wantBack == TRUE))
   {
      if (OCSPi_ProcessWantBacks(state, pRevocationData) != OCSP_SUCCESS)
         ret =  CRL_RESP_INTERNAL_ERR;
   }
  
   if (ret != CRL_RESP_SUCCESS)
   {
      OCSP_FreeRevokeStatus(handle, pRequestData, pRevocationData);
   }
   
   ERR_remove_state(0);
   return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Internal support class implementations
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
//
// Destructor
//
// Description:   Destroy the resources used during a single revocation status
//                request  
// Inputs:        (none)
// Outputs:       (none)
// Return value:  (none)
//
///////////////////////////////////////////////////////////////////////////////

OCSPState::~OCSPState()
{
   // Free the requests
   RequestMap::iterator iReq = m_requestMap.begin();
   for (; iReq != m_requestMap.end(); iReq++)
   {
      OCSP_REQUEST_free(iReq->second);
   }

   // Free the responses
   ResponseMap::iterator iResp = m_responseMap.begin();
   for (; iResp != m_responseMap.end(); iResp++)
   {
      OCSP_RESPONSE_free(iResp->second);
   }

   // Do not have the free the OCSP_CERTIDs, they are not on the heap.
}

///////////////////////////////////////////////////////////////////////////////
// Internal Functions
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_CreateCertStore()
// Description:   Create an OpenSSL trusted certificate store using the 
//                global trusted certificate list and the list of issuers
//                of each of the certificates to be verified.
// Inputs:        state
// Outputs:       (none)
// Return value:  pointer to the new certificate store
///////////////////////////////////////////////////////////////////////////////
X509_STORE* OCSPi_CreateCertStore(OCSPState& state)
{
   // Make sure we have trusted certs
   if (gTrustedCertList.empty() == true)
      return NULL;

   X509_STORE* store = X509_STORE_new();
 	
   // Make sure the certificate store was allocated
   if(store == NULL)
      return NULL;

   // Decode each trused certificate and add it to the store
   TACertList::const_iterator iCert = gTrustedCertList.begin();
   for (; iCert != gTrustedCertList.end(); iCert++)
   {
      if (OCSPi_AddCertToStore((*iCert).m_encCert, *store,
                               (*iCert).m_trustExplicit) != OCSP_SUCCESS)
      {
         X509_STORE_free(store);
         return NULL;
      }
   }

   // It is possible that the OCSP response may not contain the certificate
   // that issued the OCSP responder certificate. We add any issuer 
   // certificates we used in generating the original request in hopes
   // that one may be the issuer of the OCSP responder certificiate as well.
   // It is not a fatal error if we cannot add an issuer certificate.
   BytesList::const_iterator iIssuer = state.m_issuerList.begin();
   for (; iIssuer != state.m_issuerList.end(); iIssuer++)
   {
      OCSPi_AddCertToStore(*iIssuer, *store, false);
   }

   return store;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_AddCertToStore()
// Description:   Add a certfificate the OpenSSL X509 certficate store. 
// Inputs:        cert, store, isTrusted
// Outputs:       store
// Return value:  short - status of request.
///////////////////////////////////////////////////////////////////////////////
short OCSPi_AddCertToStore(const Bytes& cert, X509_STORE& store, bool isTrusted)
{
   // Decode the certificate
   X509* pDecCert = OCSPi_DecodeCert(cert);
   if (pDecCert == NULL)
   {
	   return OCSP_MEMORY_ERROR;
   }

   // If this is an explicitly trusted certificate then trust this cert 
   // for OCSP signing.
   if (isTrusted == true)
   {
      ASN1_OBJECT* objtmp = OBJ_nid2obj(NID_OCSP_sign);
      X509_add1_trust_object(pDecCert, objtmp);
   }

   // Add the decoded cert to the store
   int i=X509_STORE_add_cert(&store, pDecCert);
   if (i == 0)
   {
      X509_free(pDecCert);
      return OCSP_UNKNOWN_ERROR;
   }

   // Free decoded certificate
   X509_free(pDecCert);
   return OCSP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_DecodeCert()
// Description:   Decode a certificate into on OpenSSL X509 structure. 
// Inputs:        cert
// Outputs:       (none)
// Return value:  pointer to the decoded certificate.
///////////////////////////////////////////////////////////////////////////////
X509* OCSPi_DecodeCert(const Bytes& cert)
{
   BIO* pBio = BIO_new_mem_buf((void*)cert.GetData(),
      cert.Len());
   if (pBio == NULL)
   {      
      return NULL;
   }
   
   // Decode the certificate
   X509* pDecCert = d2i_X509_bio(pBio,NULL);

   BIO_free_all(pBio);
   return pDecCert;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_GetResponderURL()
// Description:   Get the URL of the OCSP responder responsible for revocation
//                status for a single certificate.
// Inputs:        encCert, responderURL
// Outputs:       responderURL
// Return value:  short - status of request
///////////////////////////////////////////////////////////////////////////////
short OCSPi_GetResponderURL(const Bytes_struct& encCert, string& responderURL)
{
   short ret = OCSP_UNKNOWN_ERROR;
   // Decode the certificate so that we can determine the URL of the
   // OCSP responder.
   try
   {
      Cert decCert(encCert);
      if (decCert.exts.pAuthInfoAccess != NULL)
      {
         const PkixAIAExtension& extAIA = *decCert.exts.pAuthInfoAccess;
         // Loop through each access description in the list 
         list<AccessDescription>::const_iterator iDesc = extAIA.begin();
         for (; iDesc != extAIA.end(); iDesc++)
         {
            // We found one if the method is OCSP and the form is URL.
            if ((iDesc->method == SNACC::id_ad_ocsp) &&
                (iDesc->location.GetType() == GenName::URL))
            {
               responderURL = iDesc->location.GetName().name;
               ret = OCSP_SUCCESS; 
               break;
            }
         }
      }
    }
   catch (...)
   {
      ret = OCSP_UNKNOWN_ERROR;
   }
   
   // If we did not find the URL in the cert, then use the default
   // responder if set.
   if ((ret != OCSP_SUCCESS) && (gDefResponderURL.size() > 0))
   {
      responderURL = gDefResponderURL;
      ret = OCSP_SUCCESS;
   }

   return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_GenerateRequests()
// Description:   Generate one or more OCSP requests for the certificates
//                presented in the original revocation status request.
// Inputs:        pRequestData, state
// Outputs:       state
// Return value:  short - status of request
///////////////////////////////////////////////////////////////////////////////
short OCSPi_GenerateRequests(const RevStatus_LL* pRequestData, OCSPState& state)
{
   // Check parameters.
   if ((pRequestData == NULL) || (pRequestData->m_pEncIssuerCert == NULL))
      return OCSP_INVALID_PARAMETER;
   
   // The issuer of the certificate being processed
   const Bytes_struct* pEncIssuerCert = NULL;
   // The previous certificate to be processed
   const Bytes_struct* pPrevCert = NULL;

   // Loop through each certificate to be processed in the RevStatus_LL list
   const RevStatus_LL* pData = pRequestData;
   while (pData != NULL)
	{
      // Determine the URL of the OCSP responder to contact to get this
      // certificate’s revocation status information.
      string responderURL;
      if (OCSPi_GetResponderURL(pData->encCert, responderURL) != OCSP_SUCCESS)
      {
         // if we could not find one, skip this certificate.
         pPrevCert = &pData->encCert;
         pData = pData->next;
         continue;
      }

      // Check the OCSP Request map to see if we already have a request
      // for this responder.
      RequestMap::iterator iReq = state.m_requestMap.find(responderURL);
      
      // If we do not have a request already, generate a new one and add it
      // to the map.
      if (iReq == state.m_requestMap.end())
      {
         OCSP_REQUEST* pReq = OCSP_REQUEST_new();
         if (pReq == NULL)
         {
            pPrevCert = &pData->encCert;
            pData = pData->next;
            continue;
         }
         iReq = state.m_requestMap.insert(iReq,
                RequestMap::value_type(responderURL, pReq));
         // if we could not add the request to the map, continue
         if (iReq == state.m_requestMap.end())
         {
            OCSP_REQUEST_free(pReq);
            pPrevCert = &pData->encCert;
            pData = pData->next;
            continue;
         }
      }
     
      // Choose the issuer certificate. It is either the issuer certficate
      // (pEncIssuerCert) in the request or the previous certificate processed
      // if the issuer was not provided. 
      if (pData->m_pEncIssuerCert != NULL)
         pEncIssuerCert = pData->m_pEncIssuerCert;
      else
         pEncIssuerCert = pPrevCert;

      // Generate a Cert ID for this certificate and add it to the proper 
      // OCSP request. 
      OCSPi_GenerateAndAddCertID(pData->encCert, *pEncIssuerCert,
                                 iReq, state);

      // set pointers to next certificate to be processed
      pPrevCert = &pData->encCert;
      pData = pData->next; 
   }

   // Add a nonce to each request if required
   if (gDoNonce == true)
   {
      if (OCSPi_AddNonce(state.m_requestMap) != OCSP_SUCCESS)
         return OCSP_UNKNOWN_ERROR;
   }

   return OCSP_SUCCESS; 
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_GenerateAndAddCertID()
// Description:   Generate a CertID for the certificate passed in encCert and
//                add it to the OCSP request designated by the iterator iReq.
// Inputs:        encCert, encIssuerCert, iReq, state
// Outputs:       state
// Return value:  short - status of request
///////////////////////////////////////////////////////////////////////////////
short OCSPi_GenerateAndAddCertID(const Bytes_struct& encCert,
                                        const Bytes_struct& encIssuerCert,
                                        RequestMap::iterator iReq,
                                        OCSPState& state)
{
   // Generate the OCSP Cert ID for the encCert. First generate a BIO for
   // the target and issuer certficates.
   BIO* pTargetBio = BIO_new_mem_buf(encCert.data, encCert.num);
   if (pTargetBio == NULL)
      return OCSP_MEMORY_ERROR;

   BIO* pIssuerBio = BIO_new_mem_buf(encIssuerCert.data, encIssuerCert.num);
   if (pIssuerBio == NULL)
   {
      BIO_free_all(pTargetBio);
      return OCSP_MEMORY_ERROR;
   }

   // Decode the target certificate
   X509* pDecTarget = d2i_X509_bio(pTargetBio,NULL);
   if (pDecTarget == NULL)
   {
      BIO_free_all(pTargetBio);
      BIO_free_all(pIssuerBio);
      return OCSP_MEMORY_ERROR;
   }

   // Decode the issuer certificate
   X509* pDecIssuer = d2i_X509_bio(pIssuerBio,NULL);
   if (pDecIssuer == NULL)
   {
      BIO_free_all(pTargetBio);
      BIO_free_all(pIssuerBio);
      X509_free(pDecTarget);
      return OCSP_MEMORY_ERROR;
   }

   // Create the Cert ID
   OCSP_CERTID* pCertID = OCSP_cert_to_id(NULL, pDecTarget, pDecIssuer);
   if (pCertID == NULL)
   {
      BIO_free_all(pTargetBio);
      BIO_free_all(pIssuerBio);
      X509_free(pDecTarget);
      X509_free(pDecIssuer);
      return OCSP_MEMORY_ERROR;
   }

   // Add the Cert ID to the map of Cert IDs by it's SHA-1 hash value
   Bytes encCertBytes(encCert);
   Bytes hash;
   encCertBytes.Hash(hash);
   state.m_certIDMap.insert(CertIDMap::value_type(hash, pCertID));

   // Add the Cert ID to the correct OCSP request
   OCSP_ONEREQ* pOneReq = OCSP_request_add0_id(iReq->second, pCertID); 
   if (pOneReq == NULL)
   {
      BIO_free_all(pTargetBio);
      BIO_free_all(pIssuerBio);
      X509_free(pDecTarget);
      X509_free(pDecIssuer);
      OCSP_CERTID_free(pCertID);
      return OCSP_MEMORY_ERROR;
   }

   // Add the issuer to the issuer list so that we can use it later when
   // verifying the response.
   state.m_issuerList.push_back(encIssuerCert);
  
   // Free uneeded resources
   BIO_free_all(pTargetBio);
   BIO_free_all(pIssuerBio);
   X509_free(pDecTarget);
   X509_free(pDecIssuer);

   return OCSP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_AddNonce()
// Description:   Add a NONCE extension with a random NONCE value to each
//                OCSP request in the request map.
// Inputs:        requestMap
// Outputs:       (none)
// Return value:  short - status of request
///////////////////////////////////////////////////////////////////////////////
short OCSPi_AddNonce(RequestMap& requestMap)
{
   // Loop through each request in the request map and add a 
   // NONCE extension with a random value.
   RequestMap::iterator iReq = requestMap.begin();
   for (; iReq != requestMap.end(); iReq++)
   {
      if (OCSP_request_add1_nonce(iReq->second, NULL, -1) != 1)
         // if a nonce could not be added, then abort and return error
         return OCSP_UNKNOWN_ERROR;
   }
   return OCSP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_TransmitRequests()
// Description:   Transmit each OCSP request in the request map to the 
//                appropriate responder and store the response in the
//                the response map
// Inputs:        state
// Outputs:       state
// Return value:  (none)
///////////////////////////////////////////////////////////////////////////////
void OCSPi_TransmitRequests(OCSPState& state)
{
   char* pHost = NULL;  // Hostname of OCSP responder.
   char* pPort = NULL;  // Port responder is listening on.
   char* pPath = NULL;  // Path component of URL
   int use_ssl = -1;    // Do not use SSL.

   // Loop through each request in the request map
   RequestMap::iterator iReq = state.m_requestMap.begin();
   for (; iReq != state.m_requestMap.end(); iReq++)
   {
      // Parse the URL
      if (OCSP_parse_url((char*)iReq->first.c_str(), &pHost, &pPort, &pPath,
                         &use_ssl) != 1)
      {
         // skip this request, the URL is bad
         continue;
      }

      // Set up a socket for the connection to the resonder
      BIO* pBio = BIO_new_connect(pHost);
		if (pBio == NULL)
		{
         // skip this request, could not connect to responder
         OPENSSL_free(pHost);
         OPENSSL_free(pPort);
         OPENSSL_free(pPath);
         continue;
		}
		
      // If a port was specified set it for the connection
      if (pPort != NULL)
         BIO_set_conn_port(pBio, pPort);

      // Make an actual socket connection to the responder 
  		if (BIO_do_connect(pBio) <= 0)
      {
         // skip this request, we could not connect
         OPENSSL_free(pHost);
         OPENSSL_free(pPort);
         OPENSSL_free(pPath);
         BIO_free_all(pBio);
         continue;
      }

      // Send the OCSP request and retrieve the OCSP response
      OCSP_RESPONSE* pResp = OCSP_sendreq_bio(pBio, pPath, iReq->second);
      if (pResp != NULL)
      {
         try
         {
            // Save the response in the response map.
            state.m_responseMap.insert(ResponseMap::value_type(iReq->first, pResp));
         } 
         catch (...)
         {
            // skip this request, we could not add it to the map
         }
      }

      // Free uneeded resources
      OPENSSL_free(pHost);
      OPENSSL_free(pPort);
      OPENSSL_free(pPath);
      BIO_free_all(pBio);
   }
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_ValidateResponses()
// Description:   Validate each OCSP response in the response map. Remove any
//                from the map that fail to validate.
// Inputs:        state, wantBack
// Outputs:       state
// Return value:  short - status of request
///////////////////////////////////////////////////////////////////////////////
short OCSPi_ValidateResponses(OCSPState& state, bool wantBack)
{
   // Loop through each response in the response map
   ResponseMap::iterator iTmpResp;
   ResponseMap::iterator iResp = state.m_responseMap.begin();
   while(iResp != state.m_responseMap.end())
   {
      // Check the status on this response, if it was not successful,
      // remove it from the map
      if(OCSP_response_status(iResp->second) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
      {
         // remove the response
         OCSP_RESPONSE_free(iResp->second);
         iTmpResp = iResp++;
         state.m_responseMap.erase(iTmpResp);
         continue;
      }

      // Extract the basic response from the response, if it cannot
      // be extracted for some reason, remove the response.
      OCSP_BASICRESP* pBasicResp = OCSP_response_get1_basic(iResp->second);
      if (pBasicResp == NULL)
      {
         // remove the response
         OCSP_RESPONSE_free(iResp->second);
         iTmpResp = iResp++;
         state.m_responseMap.erase(iTmpResp);
         continue;
      }

      // If NONCE processing is enabled, validate the NONCE value
      if (gDoNonce == true)
      {
         // Lookup the original request by URL
         RequestMap::iterator iReq = state.m_requestMap.find(iResp->first);
         // if the original request is found, check the NONCE in the basic
         // response using the original request.
         if ((iReq == state.m_requestMap.end()) ||
             (OCSP_check_nonce(iReq->second, pBasicResp) <= 0))
         {
            // Either the original request could not be found or the NONCE
            // was invalid, remove the response.
            OCSP_RESPONSE_free(iResp->second);
            iTmpResp = iResp++;
            state.m_responseMap.erase(iTmpResp);
            continue;
          }
      }

      // Verify the basic response
      if (OCSPi_VerifyBasicResponse(*pBasicResp, state) != OCSP_SUCCESS)
      {
         // remove the response
         OCSP_RESPONSE_free(iResp->second);
         iTmpResp = iResp++;
         state.m_responseMap.erase(iTmpResp);
         continue;
       }

      // The response is now considered valid. If the wantback flag is set,
      // copy the original encoded response to the list of responses in the 
      // OCSPstate class. It is a fatal error if we cannot copy the response
      // since it was requested.
      if (wantBack == true)
      {
         // Encode the response using a memory BIO
         BIO* pBio = BIO_new(BIO_s_mem());
         if (pBio == NULL)
         {
            OCSP_BASICRESP_free(pBasicResp);
            return OCSP_UNKNOWN_ERROR;
         }
         if (i2d_OCSP_RESPONSE_bio(pBio, iResp->second) != 1)
         {
            OCSP_BASICRESP_free(pBasicResp);
            BIO_free(pBio);
            return OCSP_UNKNOWN_ERROR;
         }
         // Create a CML Bytes object from memory BIO and copy it
         // to the list of encoded OCSP responses to be returned.
         try
         {
            BUF_MEM* pBuf; // This is just a reference to the actual data
            BIO_ctrl(pBio, BIO_C_GET_BUF_MEM_PTR, 0, &pBuf);
            state.m_encodedResponseList.push_back(Bytes(pBuf->length,
               (const uchar*)pBuf->data));
         } 
         catch (...)
         {
            OCSP_BASICRESP_free(pBasicResp);
            BIO_free(pBio);
            return OCSP_UNKNOWN_ERROR;
         }
         // Free the BIO
         BIO_free(pBio);
      }
      // Free the basic response
      OCSP_BASICRESP_free(pBasicResp);
      iResp++;
   }
   return OCSP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_VerifyBasicResponse()
// Description:   Verify a single basic response.
// Inputs:        basicResp, state
// Outputs:       (none)
// Return value:  short - status of verification
///////////////////////////////////////////////////////////////////////////////
short OCSPi_VerifyBasicResponse(OCSP_BASICRESP& basicResp, OCSPState& state)
{
   X509* pDefResponderCert = NULL;
   X509_STORE* pStore = NULL;
   STACK_OF(X509)* pDefaultResponders = NULL;
   short ret = OCSP_UNKNOWN_ERROR;
   const int valFlags = 0; // perform full validation
   
   try
   {
      // Create a X509 certificate store necessary to perform the verify
      pStore = OCSPi_CreateCertStore(state);
      if (pStore == NULL)
      {
         throw OCSP_MEMORY_ERROR;
      }
      
      // Set up the trusted default responder if we have one.
      if (gDefResponderCert.Len() > 0)
      {
         // Decode the default responder certificate
         pDefResponderCert = OCSPi_DecodeCert(gDefResponderCert);
         if (pDefResponderCert == NULL)
         {
            throw OCSP_MEMORY_ERROR;
         }
         
         // Create a X509 stack to hold the default responder
         pDefaultResponders = sk_X509_new_null();
         if (pDefaultResponders == NULL)
         {
            throw OCSP_MEMORY_ERROR;
         }
         
         // Add the default responder to the X509 stack
         if (sk_X509_push(pDefaultResponders, pDefResponderCert) == 0)
         {
            throw OCSP_UNKNOWN_ERROR;
         }
      }
      
      // Verify the basic response.
      if (OCSP_basic_verify(&basicResp, pDefaultResponders, pStore, valFlags) <= 0)
      {
         // The verification failed.
         throw OCSP_VERIFY_ERROR;
      }
      
      X509 *pSigner = NULL; // No memory is allocated for this resource
      
      // Find the signer's (OCSP Responder's) certificate
      int status = OCSPi_find_signer(&pSigner, &basicResp, pDefaultResponders, 
                                     pStore, valFlags);
      if ((status == 0) || (pSigner == NULL))
      {  
         // Signer was not found, set the return value
         throw OCSP_UNKNOWN_ERROR;
      }
      
      // Check if signer is the default responder
      if ((pDefResponderCert != NULL) &&
         (X509_cmp(pSigner, pDefResponderCert) == 0))
      {
         // Signer is the default responder, OCSP response is valid
         ret = OCSP_SUCCESS;
      }
      else
      {
         // No default responder or signer is not default responder,
         // check signer for extension id-pkix-ocsp-nocheck
         if (OCSPi_OCSPNoCheckExtPresent(*pSigner) == true)
         {
            // Signer has extension id-pkix-ocsp-nocheck, OCSP response is valid
            ret = OCSP_SUCCESS;
         }
         else
         {
            // Get the issuer of the responder's certificate.
            // (note: pIssuer is not on the heap and does not to be freed.)
            X509* pIssuer = OCSPi_GetIssuerByName(*pSigner, basicResp, *pStore);
            if (pIssuer == NULL)
            {
               throw OCSP_UNKNOWN_ERROR;
            }

            // Extension id-pkix-ocsp-nocheck is not present, check revocation status
            // of signer
            // 
            if (OCSPi_IsResponderValid(*pSigner, *pIssuer))
            {
               // Signer is valid (i.e. not revoked)
               ret = OCSP_SUCCESS;
            } 
         }
      }
   }
   catch (...)
   {
      ret = OCSP_UNKNOWN_ERROR;
   }
 
   // Free uneeded resources
   if (pDefaultResponders != NULL)
      sk_X509_free(pDefaultResponders);
   if (pDefResponderCert != NULL)
      X509_free(pDefResponderCert);
   if (pStore != NULL)
      X509_STORE_free(pStore);       
   
   return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_FillRevInfos()
// Description:   Fill in the revocation status information for each certificate
//                in the original revocation status request.
// Inputs:        pRequestData, state
// Outputs:       (none)
// Return value:  short - status of request to fill in RevInfos
///////////////////////////////////////////////////////////////////////////////
short OCSPi_FillRevInfos(RevStatus_LL* pRequestData,
                         OCSPState& state)
{
   // Check parameters.
   if (pRequestData == NULL)
      return OCSP_INVALID_PARAMETER;

    // Loop through each certificate to be processed in the RevStatus_LL list
   RevStatus_LL* pData = pRequestData;
   while (pData != NULL)
	{
      // Create space for the revocation status information for this certificate
      pData->pRevInfo = (RevInfo*)calloc(1, sizeof(RevInfo));
		if (pData->pRevInfo == NULL)
			return CRL_RESP_INTERNAL_ERR;

      // Set the status of this certficate to unknown until we know
      // if it is revoked or good.
      pData->pRevInfo->status = CM_STATUS_UNKNOWN;

      // Determine the URL of the OCSP responder we contacted to get this
      // certificate’s revocation status information.
      string responderURL;
      if (OCSPi_GetResponderURL(pData->encCert, responderURL) != OCSP_SUCCESS)
      {
         // if we could not find one, then leave status as CM_STATUS_UNKNOWN
         // and skip to next certificate.
         pData = pData->next;
         continue;
      }

      // Fill in the revocation status information for this certficate using 
      // the appropriate OCSP response.
      if (OCSPi_FillSingleRevInfo(pData->encCert, *pData->pRevInfo, state,
          responderURL) != OCSP_SUCCESS)
      {
         // if a failure occured, then leave status as CM_STATUS_UNKNOWN
         // and skip to next certificate.
         pData = pData->next;
         continue;
      }
      
      pData = pData->next;
   }
 
   return OCSP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_FillSingleRevInfo()
// Description:   Fill in the revocation status information for a single 
//                certificate.
// Inputs:        encCert, revInfo, state, responderURL
// Outputs:       (none)
// Return value:  short - status of request to fill in RevInfo
///////////////////////////////////////////////////////////////////////////////
short OCSPi_FillSingleRevInfo(const Bytes_struct& encCert, RevInfo& revInfo, 
                              OCSPState& state, const string& responderURL)
{
   int status;
   int reason;
	// Do not free these as they are pointers directly into the response
   ASN1_GENERALIZEDTIME* pRev = NULL; 
   ASN1_GENERALIZEDTIME* pThisupd = NULL;
   ASN1_GENERALIZEDTIME* pNextupd = NULL;

   // Locate the appropriate OCSP response
   ResponseMap::iterator iResp = state.m_responseMap.find(responderURL);
   if (iResp == state.m_responseMap.end())
      return OCSP_UNKNOWN_ERROR;

   // Locate the Cert ID for this certificate using the SHA-1 hash
   CertIDMap::iterator iCertID;
   try
   {
      Bytes encCertBytes(encCert);
      Bytes hash;
      encCertBytes.Hash(hash);
      iCertID = state.m_certIDMap.find(hash);
      if (iCertID == state.m_certIDMap.end())
         throw OCSP_UNKNOWN_ERROR;
   }
   catch (...)
   {
      return OCSP_UNKNOWN_ERROR;
   }

   // Extract the basic response from the response, if it cannot
   // be extracted for some reason, return an error.
   OCSP_BASICRESP* pBasicResp = OCSP_response_get1_basic(iResp->second);
   if (pBasicResp == NULL)
   {
      return OCSP_UNKNOWN_ERROR;
   }

   // Retrieve the status information from the basic response for this 
   // certificate.
   if (OCSP_resp_find_status(pBasicResp, iCertID->second, &status, &reason,
                             &pRev, &pThisupd, &pNextupd) == 0)
   {
      OCSP_BASICRESP_free(pBasicResp);
      return OCSP_UNKNOWN_ERROR;
   }

   // Check validity period on the response
   if (OCSP_check_validity(pThisupd, pNextupd, gNsec, gMaxAge) == 0)
   {
      OCSP_BASICRESP_free(pBasicResp);
      return OCSP_UNKNOWN_ERROR;
   }

   // Fill in the RevInfo fields
   switch (status)
   {
   case V_OCSP_CERTSTATUS_GOOD:
      revInfo.status = CM_STATUS_GOOD;
      break;
   case V_OCSP_CERTSTATUS_REVOKED:
      // Set the status code
      revInfo.status = CM_STATUS_REVOKED;
      revInfo.revReason = (short*)calloc(1, sizeof(short));
      if (revInfo.revReason == NULL)
      {
         OCSP_BASICRESP_free(pBasicResp);
         return OCSP_MEMORY_ERROR;
      }
      // Copy the reason code
      *revInfo.revReason = (short)reason;
      // Create memory for the revocation date and copy it
      revInfo.revDate = (CM_TimePtr)calloc(1, sizeof(CM_Time));
      if (revInfo.revDate == NULL)
      {
         OCSP_BASICRESP_free(pBasicResp);
         return OCSP_MEMORY_ERROR;
      }
      memcpy(revInfo.revDate, pRev->data, sizeof(CM_Time));
      break;
   case V_OCSP_CERTSTATUS_UNKNOWN:
      revInfo.status = CM_STATUS_UNKNOWN;
      break;
   }

   // Fill in the this update time from the OCSP response
   if (pThisupd != NULL)
      memcpy(revInfo.thisUpdate, pThisupd->data, sizeof(CM_Time));

   // Fill in the next update time from the OCSP response
   if (pNextupd != NULL)
   {
      revInfo.nextUpdate = (CM_TimePtr)calloc(1, sizeof(CM_Time));
      if (revInfo.nextUpdate == NULL)
      {
         OCSP_BASICRESP_free(pBasicResp);
         return OCSP_MEMORY_ERROR;
      }
      memcpy(revInfo.nextUpdate, pNextupd->data, sizeof(CM_Time));
   }

   OCSP_BASICRESP_free(pBasicResp);
    
   return OCSP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_ProcessWantBacks()
// Description:   Create the linked list of encoded OCSP responses which is
//                to be returned with the revocation status request.
// Inputs:        state
// Outputs:       pRevocationData
// Return value:  short - status of request to process the want backs 
///////////////////////////////////////////////////////////////////////////////
short OCSPi_ProcessWantBacks(const OCSPState& state, 
                             EncRevObject_LL** pRevocationData)
{
   // Check parameters
   if (pRevocationData == NULL)
      return OCSP_INVALID_PARAMETER;

   EncRevObject_LL* pRevObj = NULL;

   // Loop through each encoded response in the response list and
   // add it to a new linked list.
   BytesList::const_iterator iResp = state.m_encodedResponseList.begin();
   for (; iResp != state.m_encodedResponseList.end(); iResp++)
   {
      // Create space for the next item in the linked list
      EncRevObject_LL* pTempObj =
         (EncRevObject_LL*)calloc(1, sizeof(EncRevObject_LL));
      if (pTempObj == NULL)
         return OCSP_MEMORY_ERROR;

     	// Add this link to the head of the list
		pTempObj->m_pNext = pRevObj;
		pRevObj = pTempObj;

      // Fill in the encoded data
      iResp->FillBytesStruct(pRevObj->m_encObj);
      // Set the type
      pRevObj->m_typeMask = REV_OCSP_TYPE;
   }
   *pRevocationData = pRevObj;

   return OCSP_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_IsResponderValid()
// Description:   Check if a responder certificate is valid
// Inputs:        responder, issuer
// Outputs:       (none)
// Return value:  true  - responder cert is valid
//                false - responder cert is not valid
///////////////////////////////////////////////////////////////////////////////
bool OCSPi_IsResponderValid(X509& responder, X509& issuer)
{
   bool ret;
   RevStatus_LL revStatus;
   Bytes_struct issuerCertBytes;
   revStatus.m_pEncIssuerCert = &issuerCertBytes;
   revStatus.encCert.data = NULL;
   revStatus.m_pEncIssuerCert->data = NULL;
   BIO* pRespBio = NULL;
   BIO* pIssuerBio = NULL;
   
   try
   {
      // Encode the responder certificate using a memory BIO
      pRespBio = BIO_new(BIO_s_mem());
      if (pRespBio == NULL)
      {
         throw OCSP_MEMORY_ERROR;
      }
      if (i2d_X509_bio(pRespBio, &responder) != 1)
      {      
         throw OCSP_UNKNOWN_ERROR;
      }
      
      // Encode the issuer's certificate using a memory BIO
      pIssuerBio = BIO_new(BIO_s_mem());
      if (pIssuerBio == NULL)
      {
         throw OCSP_MEMORY_ERROR;
      }
      if (i2d_X509_bio(pIssuerBio, &issuer) != 1)
      {      
         throw OCSP_UNKNOWN_ERROR;
      }
      // Fill in the RevStatus_LL
      // Create the responder's CML Bytes_struct in the RevStatus_LL from a memory BIO
      BUF_MEM* pBuf; // This is just a reference to the actual data
      BIO_ctrl(pRespBio, BIO_C_GET_BUF_MEM_PTR, 0, &pBuf);
      
      revStatus.encCert.num = pBuf->length;
      revStatus.encCert.data = (unsigned char*)malloc(pBuf->length);
      if (revStatus.encCert.data == NULL)
      {
         throw OCSP_MEMORY_ERROR;
      }
      memcpy(revStatus.encCert.data, (const uchar*)pBuf->data, pBuf->length);
      
      // Create the issuer's CML Bytes_struct in the RevStatus_LL from a memory BIO
      BIO_ctrl(pIssuerBio, BIO_C_GET_BUF_MEM_PTR, 0, &pBuf);
      revStatus.m_pEncIssuerCert->num = pBuf->length;
      revStatus.m_pEncIssuerCert->data = (unsigned char*)malloc(pBuf->length);
      if (revStatus.m_pEncIssuerCert->data == NULL)
      {
         throw OCSP_MEMORY_ERROR;
      }
      memcpy(revStatus.m_pEncIssuerCert->data, (const uchar*)pBuf->data, pBuf->length);

      // Fill in the other members in the RevStatus_LL
      revStatus.next = NULL;
      revStatus.pReqExts = NULL;
      revStatus.pRevInfo = NULL;
      
      // Perform revocation check of OCSP responder cert
      short err = OCSP_RequestRevokeStatus(NULL, 0, 
         &revStatus, NULL, FALSE, NULL);
      
      if (err != CRL_RESP_SUCCESS)
      {
         throw OCSP_UNKNOWN_ERROR;
      }
      
      // Make sure the revInfo has been filled in.
      if (revStatus.pRevInfo == NULL)
      {
         throw OCSP_UNKNOWN_ERROR;
      }
      
      //Check the status of the responder certificate
      if (revStatus.pRevInfo->status == CM_STATUS_GOOD)
      {
         // responder is valid
         ret = true;
      }
      else
      {
         // responder is invalid
         ret = false;
      }
      
      // Free the RevInfo in the RevStatus_LL
      OCSP_FreeRevokeStatus(NULL, &revStatus, NULL);
      
   }
   catch (...)
   {
      // responder is invalid
      ret = false;
   }
   
   // Free resources and return
   if (pRespBio != NULL)
      BIO_free(pRespBio);
   if (pIssuerBio != NULL)
      BIO_free(pIssuerBio);
   if (revStatus.encCert.data != NULL)
      free(revStatus.encCert.data);
   if (revStatus.m_pEncIssuerCert->data != NULL)
      free(revStatus.m_pEncIssuerCert->data);

   return ret;
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_OCSPNoCheckExtPresent()
// Description:   Check if a certificate contains the id_pkix_ocsp_nocheck 
//                extension.
// Inputs:        encCert
// Outputs:       (none)
// Return value:  true  - when the cert contains the id_pkix_ocsp_nocheck ext.
//                false - when the cert does not contain this extension
///////////////////////////////////////////////////////////////////////////////
bool OCSPi_OCSPNoCheckExtPresent(X509& encCert)
{
   BIO* pBio = NULL;
   try
   {
      // Encode the certificate using a memory BIO
      pBio = BIO_new(BIO_s_mem());
      if (pBio == NULL)
      {
         return false;
      }
      if (i2d_X509_bio(pBio, &encCert) != 1)
      {
         BIO_free(pBio);
         return false;
      }

      // Create a CML Bytes object from memory BIO
      BUF_MEM* pBuf; // This is just a reference to the actual data
      BIO_ctrl(pBio, BIO_C_GET_BUF_MEM_PTR, 0, &pBuf);
      Bytes encCertBytes(pBuf->length, (const uchar*)pBuf->data);
      BIO_free(pBio);

      // Decode the certificate
      Cert decCert(encCertBytes);

      // Check if the certificate contains the id_pkix_ocsp_nocheck 
      // extension in the list of unknown extensions.
      return decCert.exts.unknownExts.IsPresent(id_pkix_ocsp_nocheck);
   }
   catch (...)
   {
      if (pBio != NULL)
         BIO_free(pBio);

      return false;
   }
}

///////////////////////////////////////////////////////////////////////////////
// Function:      OCSPi_GetIssuerByName()
// Description:   Get the certificate that issued "subject" by searching the 
//                certificates in an OCSP basic response or a certificate store.
// Inputs:        subject, basicResp, store
// Outputs:       (none)
// Return value:  The address of the issuer certificate or NULL if not found
///////////////////////////////////////////////////////////////////////////////
X509* OCSPi_GetIssuerByName(X509& subject, OCSP_BASICRESP& basicResp, X509_STORE& store)
{
   X509* pIssuer = NULL;

   // Get the issuer name of the OCSP responder cert's issuer
   // (note: pIssuerName is not on the heap and does not need to be freed.)
   X509_NAME* pIssuerName = X509_get_issuer_name(&subject);
   // Find the issuer in the basic response by name.
   pIssuer = X509_find_by_subject(basicResp.certs, pIssuerName);
   // If found in the response return
   if (pIssuer != NULL)
      return pIssuer;
      
   // Issuer was not found, check the cert store
   X509_STORE_CTX ctx;
   STACK_OF(X509) *chain = NULL;
   try
   {
      // Build and validate the certificate path of subject
      if (X509_STORE_CTX_init(&ctx, &store, &subject, NULL) != 1)
         throw OCSP_UNKNOWN_ERROR;
      if (X509_STORE_CTX_set_purpose(&ctx, X509_PURPOSE_OCSP_HELPER) != 1)
         throw OCSP_UNKNOWN_ERROR; 
      if (X509_verify_cert(&ctx) <= 0)
         throw OCSP_UNKNOWN_ERROR;
      chain = X509_STORE_CTX_get1_chain(&ctx);
      if (chain == NULL)
         throw OCSP_UNKNOWN_ERROR;
      // the issuer of subject is in position 1 in the chain
      pIssuer = sk_X509_value(chain, 1);
   }
   catch (...)
   {
      // error occurred in path validation, NULL will be returned
      // after cleanup.
   }

   X509_STORE_CTX_cleanup(&ctx);
   if(chain != NULL) 
      sk_X509_pop_free(chain, X509_free);

   return pIssuer;
}



