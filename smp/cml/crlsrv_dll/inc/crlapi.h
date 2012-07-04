/*************************************************************************
File:     crlapi.h
Project:  Certificate Management Library
Contents: Header file for the CRL used in the
          Certificate Management Library

Created:  9 February 2004
Author:   Tom Horvath <Tom.Horvath@DigitalNet.com>

Last Updated:  27 Jan 2005

Version:  2.5

*****************************************************************************/
#ifndef _CRLAPI_H
#define _CRLAPI_H

/* Included Files */
#include "cmapi.h"
#include "cmapiCallbacks.h"

#ifdef WIN32
	#ifndef CRL_API
		#define CRL_API  __declspec(dllexport) 
	#endif
#else
	#define CRL_API 
#endif


#if __cplusplus
extern "C" {
#endif

/* Initialization settings */

#define CRL_SUCCESS								000
#define CRL_SESSION_NOT_VALID					301
#define CRL_UNKNOWN_ERROR						302
#define CRL_INIT_ERROR							303
#define CRL_MEMORY_ERROR						304
#define CRL_INVALID_PARAMETER					305
#define CRL_NULL_POINTER						306
#define CRL_CERT_REVOKED						307
#define CRL_REV_REASONS_NOT_CHECKED			308
#define CRL_NOT_AVAIL							309
#define CRL_CRITICAL_KEY_COMPROMISE_NOT_CHECKED 310
#define CRL_PATH_NOT_FOUND						311
#define CRL_NOT_VALID							312

typedef struct
{
   void*             extHandle;     /* Handle to external library for callbacks */
   ExtGetObjFuncPtr  pGetObj;       /* External get callback function */
   ExtFreeObjFuncPtr pFreeObj;      /* External free callback function */
   ExtUrlGetObjFuncPtr  pUrlGetObj; /* External URL get callback function */
} SRLCallbackFunctions;

/* Runtime settings for this CRL server */
typedef struct 
{
	/* The following members are used only when initializing the */
   /* CRL service DLL for local revocation checking             */
	SearchBounds	boundsFlag;
	ulong			   cmlSessionID;		/* CML Session ID */
	EncCert_LL*		crlList;			   /* List of CRLs that will be added */
                                    /* to CRL status table at startup  */
	time_t			crlRefreshPeriod; /* How long to wait between CRL updates */
	time_t			crlGracePeriod;	/* Maximim time that a CRL is      */
                                    /* considered to be valid after    */
										      /* the Next Update time has passed */
	SRLCallbackFunctions* srlFuncs;	/* SRL callback functions */

	/* The following members are used only when          */
   /* initializing the socket based client-end callback */
	char			*CRLserver;			/* CRL Server Name */
	long			CRLport;			   /* CRL Port Number */
} CRLDLLInitSettings_struct;

CRL_API short CRL_Destroy(ulong* crl_session);
CRL_API void CRL_EmptyCRLCache(ulong crl_session);
CRL_API void CRL_FreeRevokeStatus(void* handle, RevStatus_LL* pResults,
                                  EncRevObject_LL** pRevocationData);
CRL_API short CRL_Init(ulong* crl_session, 
                       CRLDLLInitSettings_struct* serverSettings);
CRL_API short CRL_RequestRevokeStatus(void* handle, time_t timeout,
									           RevStatus_LL* pRequestData, 
                                      CM_TimePtr pValidationTime, 
                                      CM_BOOL wantBack,
                                      EncRevObject_LL** pRevocationData);


#if __cplusplus
}
#endif

#endif /*_CRLAPI_H */

