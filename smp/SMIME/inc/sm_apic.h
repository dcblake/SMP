/* @(#) sm_apic.h 1.36 12/13/99 16:10:38 */

/*************************************************************************/
/* sm_apic.h                                                             */
/*  C Header file for the SFL C API library                              */
/* This file is intended for the C application to include. It should     */
/* have no C++ code in it.                                               */
/*************************************************************************/

#ifndef _SM_APIC_H_
#define _SM_APIC_H_

#if defined (WIN32) || (!defined (__cplusplus))
#include "stddef.h"
#endif

#ifndef WIN32
#include <sys/types.h>
#endif

//#define USE_CML_R201
#ifndef USE_CML_R201
#include "cmlasn_c.h"
#endif //USE_CML_R201

#ifdef SEARCH_ALL
#undef SEARCH_ALL
#endif // SEARCH_ALL

#include "cmapiCallbacks.h"//RWC;cmapiCommon.h"   /* Certificate Management Library header */
#include "sm_apicCtilMgr.h"

/* data holding structure with flag to indicate file or memory use */
/* if flag == SM_FILE_USED then data.pchData is the file name */
/* if flag == SM_BUFFER_USED then data.pchData is a memory pointer to the */
/*   buffer and data.lLength is the length of the memory buffer */
typedef struct {
   short flag;
   SM_Str data;
} SM_Buffer;

/* list of buffers */
typedef struct SM_BufferLstStruct {
   SM_Buffer buffer;
   struct SM_BufferLstStruct *pNext;
} SM_BufferLst;

/* list of attributes */
typedef struct SM_AttribLstStruct {
   SM_OID *poidType;
   SM_Buffer buffer;
   struct SM_AttribLstStruct *pNext;
} SM_AttribLst;

/* list of signer infos */
typedef struct SM_SignerInfoLstStruct {
   SM_AttribLst *pSignedAttrs;
   SM_AttribLst *pUnSignedAttrs;
   struct SM_SignerInfoLstStruct *pNext;
} SM_SignerInfoLst;

/* general content class where poidType identifies what is in bufContent */
typedef struct {
   SM_OID *poidType;
   SM_Buffer bufContent;
} SM_Content;


#ifndef _SM_ERROR_H_    // ONLY if sm_error.h not included earlier.
/* General error information structure */
typedef struct {
    long lErrorCode;     /* Identifies the error and how to interpret */
                         /*      * the "errorBuf". */
    SM_Str strError;     /* May be an ASN.1 encoded buffer. */
    char *pszDebug;      /* Debug string; cummulative. */
} SM_ErrorBuf;
#endif //_SM_ERROR_H_

/**********************/
/* HILEVEL PROTOTYPES */
/**********************/

/* SM_Decrypt accepts a CMS ContentInfo->EnvelopedData and uses pCSMIME */
/* and other input parameters to decrypt the content */
SM_RET_VAL SM_Decrypt(
      SM_OBJECT *pCSMIME,/* CSMIME that will be used to process this */
      SM_Content **pContent, /* output */
      EncCert_LL **pRecipients, /* list of certs of recipients */
      Bytes_struct *pInput /* Input must be a contentinfo wrapped enveloped data */
);  

/* SM_Encrypt creates a CMS ContentInfo containing an EnvelopedData */
SM_RET_VAL SM_Encrypt(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      SM_Content *pContent, /* content and type of content */
      SM_OID *poidContentEncryption, /* specified content encryption id */
      EncCert_LL *pRecipients, /* list of certs of recipients */
      short bIncludeOrigCerts, /* include originator certs from CSMIME? */
      short bIncludeOrigAsRecip, /* auto include originator as recip? */
      Bytes_struct *pOutput); /* ASN.1 encoded result */

/* SM_PreProc should be called prior to calling SM_Decrypt or SM_Verify to */
/* "pre-process" the message providing various outputs from the message */
/* that the app may want to use (e.g. originator cert) */
SM_RET_VAL SM_PreProc(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      SM_Buffer *pbufInput, /* ASN.1 encoded ContentInfo */
      SM_StrLst **ppCerts, /* certs from the cert bag */
      SM_Content **ppContent); /* unprocessed content from pbufInput blob */

/* SM_Sign creates a CMS ContentInfo containing a SignedData */
SM_RET_VAL SM_Sign(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */ 
      SM_Content *pContent, /* content and type of content */
      SM_SignerInfoLst *pSignerInfos, /* optional list of SignerInfos */
      EncCert_LL *pCerts, /* list of certs */
      SM_BufferLst *pACs, /* list of attribute certs */
      EncCRL_LL *pCrls, /* list of crls */
      short bIncludeOrigCerts, /* include originator certs from CSMIME? */
      short bIncludeContent, /* include Content from CSMIME? */
      Bytes_struct *pOutput); /* ASN.1 encoded result */

/* SM_Verify calls SM_VerifyC_Support which accepts a CMS ContentInfo->
   SignedData and uses pCSMIME and other input parameters to verify the
   signature(s) */
SM_RET_VAL SM_Verify(
     SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */ 
     SM_Content **pContent, /* input or output */
     Bytes_struct *pInput, /* ASN.1 encoded SignedData */
     SM_SignerInfoLst **pSignerInfos, /* optional list of SignerInfos */
     EncCert_LL **pCerts, /* list of certs */
     SM_BufferLst **pACs, /* list of attribute certs */
     EncCRL_LL **pCrls, /* list of crls */
     SM_Buffer *pSignedRec, /* Signed Receipt File Name */
     long *receiptreq);       /* is a receipt requested */

/* SM_VerRec calls SM_VerifyC_Support which accepts a CMS ContentInfo->
   Signed Receipt and uses pCSMIME and other input parameters to verify the
   receipt */
SM_RET_VAL SM_VerRec(
      SM_OBJECT *pCSMIME, /* CSMIME that will be used to process this */
      Bytes_struct *pInput, /* ASN.1 encoded Signed Receipt */
      Bytes_struct *pOrigSD, /* Original Signed Data */
      SM_SignerInfoLst **pSignerInfos, /* optional list of SignerInfos */
      EncCert_LL **pCerts, /* list of certs */
      SM_BufferLst **pACs, /* list of attribute certs */
      EncCRL_LL **pCrls); /* list of crls */

      
/**********************/
/* LOLEVEL PROTOTYPES */
/**********************/

SM_RET_VAL SM_CreateCSMIME(
  SM_OBJECT **ppCSMIME,  /* OUT,Returned pointer to struct for crypto calls. */
  char *lpszDLLFile,      /* IN, DLL file load for Win32.*/
  char *lpszArgList);      /* IN, Argument list for DLL Load.*/
  /*Bytes_struct *pCert,       IN, used to specify the algs for login.*/
  /*Bytes_struct *pPrivateKey,   IN, OPTIONAL private key for */
  /*                             sign/encrypt/decrypt. */
  /*                      (library can perform verification without key). */
  /*char *lpszPassword)       IN, OPTIONAL, password to access "pPrivateKey"*/ 
  /*                          in SFL stored format (flavor of PKCS 8).  */

void SM_DeleteCSMIME(SM_OBJECT *pCSMIME);

SM_RET_VAL SM_GetError(SM_OBJECT *pCSMIME, SM_ErrorBuf **ppError);

SM_RET_VAL SM_GetInstCount(SM_OBJECT *pCSMIME, long *plInstCount);

SM_RET_VAL SM_SetInstUseThisFlag(SM_OBJECT *pCSMIME, long lInstIndex,
      short bFlag);

SM_RET_VAL SM_GetInstUseThisFlag(SM_OBJECT *pCSMIME, long lInstIndex,
      short *pbFlag);

SM_RET_VAL SM_SetInstApplicableFlag(SM_OBJECT *pCSMIME, 
      long lInstIndex, short bFlag);

SM_RET_VAL SM_GetInstApplicableFlag(SM_OBJECT *pCSMIME,
      long lInstIndex, short *pbFlag);

/* The following are C free functions
 */
void free_SM_Str(SM_Str *Ss);
void free_SM_Str_content(SM_Str *Ss);
void free_SM_Buf_content(SM_Buffer *buf);
void free_SM_Buf(SM_Buffer *buf);
void free_SM_Cont_content(SM_Content *con);
void free_SM_Cont(SM_Content *con);
void free_SM_BufferLst(SM_BufferLst *buflst);
void free_SM_AttribLst(SM_AttribLst *attriblst);
void free_SM_SignerInfoLst(SM_SignerInfoLst *signerinfolst);
void free_SM_Bytes(Bytes_struct **bytes);
void free_SM_EncCertList(EncCert_LL **listhead);
void free_SM_EncCRLs(EncCRL_LL **listhead);

#endif /* _SM_APIC_H_ */

/* EOF sm_apic.h */
