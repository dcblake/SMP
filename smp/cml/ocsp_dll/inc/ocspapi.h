/******************************************************************************
 * File:		      ocspapi.h
 * Project:		   Certificate Management Library
 * Contents:	   Header file for the OCSP revocation status callback
 * Requirements:  CML Requirements 2.1-5.
 * 
 * Created:		   13 December 2004
 * Author:		   Tom Horvath <Tom.Horvath@BAESystems.com>
 * 
 * Last Updated:  13 December 2004
 * 
 * Version:		   2.5
/******************************************************************************/
#ifndef _OSCP_API_H_
#define _OSCP_API_H_

/* Included Files */
#include "cmlasn.h"           /* include for CML ASN types */
#include "cmapiCallbacks.h"   /* include for CML Callback types */

#ifdef WIN32
   #ifndef OCSP_API
      #define OCSP_API  __declspec(dllexport) 
   #endif
#else
   #define OCSP_API 
#endif


#if __cplusplus
extern "C" {
#endif

/* Error constants */

#define OCSP_SUCCESS                   0
#define OCSP_UNKNOWN_ERROR             401
#define OCSP_INIT_ERROR                402
#define OCSP_MEMORY_ERROR              403
#define OCSP_INVALID_PARAMETER         404
#define OCSP_NULL_POINTER              405
#define OCSP_VERIFY_ERROR              406

/* EncTrustedCert_LL
 * This structure is used to contain the linked lists of asn.1 encoded 
 * trusted certificates.
 */
typedef struct encTrustedCert_LL
{
   CM_BOOL        m_trustExplicit; /* Only set for paths containing a global responder */
   Bytes_struct   m_encCert;       /* Pointer & len of the ASN.1 encoded cert */
   struct encTrustedCert_LL* m_next; /* next in linked list, NULL if last */
} EncTrustedCert_LL;


/* Runtime settings for the OCSP library */

typedef struct 
{
   char* m_defResponderURL;         /* An optional URL of the default OCSP
                                     * trusted responder. */
   Bytes_struct* m_defResponderCert;/* An optional encoded CA signer 
                                     * certificate of the default trusted 
                                     * responder. */
   EncTrustedCert_LL* m_trustedCACerts; /* The list of encoded trusted CA 
                                     * certificates. */
   CM_BOOL m_doNonce;               /* A flag specifying whether or not nonce
                                     * processing will be performed. */
   long m_nSec;                     /* The range of time, in seconds, which
                                     * will be tolerated in an OCSP response. 
                                     * Each certificate status response 
                                     * includes a notBefore time and an 
                                     * optional notAfter time. The current time
                                     * should fall between these two values, 
                                     * but the interval between the two times 
                                     * may be only a few seconds. In practice 
                                     * the OCSP responder and clients clocks 
                                     * may not be precisely synchronized and so
                                     * such a check may fail.  To avoid this, 
                                     * this setting can be used to specify an 
                                     * acceptable error range in seconds. */
   long m_maxAge;                   /* The time in seconds to add to the 
                                     * notBefore time in the OCSP response when
                                     * the notAfter time is omitted from the 
                                     * response.  If the notAfter time is 
                                     * omitted from a response then this means 
                                     * that new status information is 
                                     * immediately available. In this case the
                                     * age of the notBefore field is checked to
                                     * see it is not older than this many 
                                     * seconds old. By default this additional
                                     * check is not performed. */
} OSCPDLLInitSettings_struct;

/* Function Prototypes */

OCSP_API short OCSP_Init
(
   OSCPDLLInitSettings_struct* serverSettings /* Runtime settings for the OCSP
                                               * library */
);

OCSP_API void OCSP_Destroy
(
);

OCSP_API short OCSP_RequestRevokeStatus
(
   void* handle,                 /* An optional, generic handle used by the
                                  * callback for session specific information.
                                  * (currently not used) */
   time_t timeout,               /* The timeout period for the entire request
                                  * (currently not used) */
   RevStatus_LL* pRequestData,   /* A linked list of the certificates and their 
                                  * revocation status, which was filled in by 
                                  * the check revocation status callback. */
   CM_TimePtr pTimeStampTime,    /* An optional pointer to the time at which 
                                  * revocation status information should be
                                  * retrieved.  If not present, then current
                                  * time is used */
   CM_BOOL wantBack,             /* Flag that specifies if encoded OCSP 
                                  * responses should be returned */
   EncRevObject_LL** pRevocationData /* The linked list of encoded OCSP
                                  * responses */
);

OCSP_API void OCSP_FreeRevokeStatus
(
   void* handle,                 /* An optional, generic handle used by the 
                                  * callback for session specific information
                                  * (currently not used) */
   RevStatus_LL* pResults,       /* A linked list of the certificates and their
                                  * revocation status, which was filled in by
                                  * the check revocation status callback. */
   EncRevObject_LL** pRevocationData /* The linked list of encoded OCSP
                                  * responses */
);

#if __cplusplus
}
#endif

#endif /* _OSCP_API_H_ */

