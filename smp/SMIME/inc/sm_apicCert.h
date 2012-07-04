/* @(#) sm_apicCert.h 1.3 04/05/00 14:11:10 */


/*************************************************************************/
/* sm_apicCert.h                                                             */
/*  C Header file for the SFL C API library                              */
/* This file is intended for the C application to include. It should     */
/* have no C++ code in it.                                               */
/*************************************************************************/

#ifndef _SM_APICCERT_H_
#define _SM_APICCERT_H_

/***************************/
/* GENERAL PURPOSE DEFINES */
/***************************/

#ifndef SM_SIZE_T
#define SM_SIZE_T size_t
#endif
#ifndef SM_RET_VAL
#define SM_RET_VAL long
#endif

#define SM_FILE_USED 1
#define SM_BUFFER_USED 2

/*******************/
/* ERROR CONSTANTS */
/*******************/

#define SM_UNKNOWN_ERROR                9999
#define SM_NO_ERROR                     0

/* HIGH LEVEL ERROR CONSTANTS 1000-1999 */
#define SM_MEMORY_ERROR                 1000
#define SM_FILEIO_ERROR                 1001
#define SM_NO_FILENAME                  1002
#define SM_MISSING_PARAM                1003
#define SM_MAB_ERROR                    1004
#define SM_NO_INSTANCES                 1005
#define SM_NO_SUPPORTING_INSTANCE       1006
#define SM_ENCRYPTION_UNPREPARED        1009
#define SM_INVALID_INDEX                1010
#define SM_ASN1_DECODE_ERROR            1011
#define SM_INVL_PREPROC_TYPE            1012
#define SM_ORIGMSG_NOT_SIGNEDDATA       1013
#define SM_NO_MATCHING_SIGNATURE        1014
#define SM_VALRECERR_MSG_SIG_DIGEST     1015
#define SM_VALRECERR_MSG_DIGEST         1016
#define SM_DIGEST_MISMATCH              1017 
#define SM_RECREQ_ERROR                 1018
#define SM_NO_RECEIPTS_FROM             1019
#define SM_UNKNOWN_ATTRIBUTE            1020
#define SM_DUPLICATE_ATTRIBS            1021
#define SM_NOT_FOUND                    1022
#define SM_UNKNOWN_CID                  1023
#define SM_NO_SIGNER_IDENTIFIER         1024
#define SM_INVALID_CRL                  1025
#define SM_NO_CRL_SET                   1026
#define SM_CRL_DEC_ERROR                1027
#define SM_INVALID_OID_STRING           1028
#define SM_UNKNOWN_DATA                 1029 // unknown data from decode
#define SM_LIST_ERROR                   1030 // data not in list


// AES errors
#define SM_AES_ENCRYPT_ERROR            1100
#define SM_AES_DECRYPT_ERROR            1101
#define SM_AES_MISALIGNED_DATA          1103
#define SM_AES_KEYINST_ERROR            1104
#define SM_AES_PAD_ERROR                1105
#define SM_AES_CIPHER_ERROR             1106



/* ASN.1 ERROR CONSTANTS 2000-2999 */
#define SM_ENV_DATA_DEC_ERROR           2001

/***************************/
/* TYPEDEFs and STRUCTURES */
/***************************/

typedef void SM_OBJECT; /* e.g. used for CSMIME */
typedef char SM_OID; /* always used as a pointer, e.g. SM_OID * */

/* General data holding structure RWC; DEFINED in snacc/c++/sm_buffer.h*/
#ifndef _SM_BUFFER_H_
typedef struct {
   SM_SIZE_T lLength;
   char *pchData;
} SM_Str;
#endif

typedef struct SM_StrLstStruct {
   SM_Str str;
   struct SM_StrLstStruct *pNext;
} SM_StrLst;


#endif      //_SM_APICCERT_H_


// EOF sm_apicCert.h
