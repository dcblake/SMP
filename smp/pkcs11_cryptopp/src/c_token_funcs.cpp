/************************ PKCS #11 Slot and Token Functions ************************
 *
 * This source file contains the following slot and token functions:
 *  + C_GetSlotList
 *  + C_GetSlotInfo
 *  + C_GetTokenInfo
 *  + C_WaitForSlotEvent
 *  + C_GetMechanismList
 *  + C_GetMechanismInfo
 *  + C_InitToken
 *  + C_InitPIN
 *  + C_SetPIN
 */

/* This source file contains the Cryptoki functions used with tokens.  This implmentation
 * of PKCS11 is for Crypto++ where no token is present.  Therefore these functions are
 * stubbed out to return CKR_FUNCTION_NOT_SUPPORTED.
 */

#include "cryptoki.h"
#include "p11cryptopp_internal.h"

/** Supported Mechanisms **/
#define gMechTblSize 7
CK_MECHANISM_TYPE gMechTbl[gMechTblSize]={
CKM_SHA_1,
CKM_SHA_256,
CKM_SHA_384,
CKM_DSA_SHA1,
CKM_ECDSA_SHA1,
CKM_ECDSA_SHA256,
CKM_ECDSA_SHA384
};

/* Slot and token management */
const CK_ULONG kNUM_SLOTS = 1;


/* C_GetSlotList obtains a list of slots in the system. */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList) (
							CK_BBOOL       tokenPresent,  /* only slots with tokens? */
							CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
							CK_ULONG_PTR   pulCount)      /* receives number of slots */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check the arguments
	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	// If the array of slot IDs is NULL, just return the number of slots
	if (pSlotList == NULL_PTR)
	{
		*pulCount = kNUM_SLOTS;
	}
	else if (*pulCount < kNUM_SLOTS)	// else buffer too small
	{
		*pulCount = kNUM_SLOTS;
		return CKR_BUFFER_TOO_SMALL;
	}
	else	// return the array of slot IDs
	{
		*pulCount = kNUM_SLOTS;
		pSlotList[0] = 0;
	}

	return CKR_OK;
}


/* C_GetSlotInfo obtains information about a particular slot in
 * the system. */
CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
							CK_SLOT_ID       slotID,  /* the ID of the slot */
							CK_SLOT_INFO_PTR pInfo)   /* receives the slot information */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check the arguments
	if (pInfo == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	// Check that the slot ID is valid
	if (slotID != 0)
		return CKR_SLOT_ID_INVALID;

	// Fill in the CK_SLOT_INFO fields
	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	const char kSlotString[64] = "Software Token";
	memcpy(pInfo->slotDescription, kSlotString, strlen(kSlotString));

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, kManufacturerName, strlen(kManufacturerName));

	pInfo->flags = CKF_TOKEN_PRESENT;

	pInfo->hardwareVersion.major = 1;
	pInfo->hardwareVersion.minor = 0;

	pInfo->firmwareVersion.major = 1;
	pInfo->firmwareVersion.minor = 0;

	return CKR_OK;
}


/* C_GetTokenInfo obtains information about a particular token
 * in the system. */
CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(
							CK_SLOT_ID        slotID,  /* ID of the token's slot */
							CK_TOKEN_INFO_PTR pInfo)   /* receives the token information */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur. */
CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(
							CK_FLAGS flags,        /* blocking/nonblocking flag */
							CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
							CK_VOID_PTR pRserved)  /* reserved.  Should be NULL_PTR */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token. */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(
							CK_SLOT_ID            slotID,          /* ID of token's slot */
							CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
							CK_ULONG_PTR          pulCount)        /* gets # of mechs. */
{
	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pMechanismList == NULL_PTR)
	{
		*pulCount = gMechTblSize;
		return CKR_OK;
	}

	if (*pulCount < gMechTblSize)
		return CKR_BUFFER_TOO_SMALL;

	*pulCount = gMechTblSize;
	memcpy(pMechanismList, &gMechTbl[0], gMechTblSize * sizeof(CK_MECHANISM_TYPE));

	return CKR_OK;
}


/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token. */
CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(
							CK_SLOT_ID            slotID,  /* ID of the token's slot */
							CK_MECHANISM_TYPE     type,    /* type of mechanism */
							CK_MECHANISM_INFO_PTR pInfo)   /* receives mechanism info */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_InitToken initializes a token. */
CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(
							CK_SLOT_ID      slotID,    /* ID of the token's slot */
							CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
							CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
							CK_UTF8CHAR_PTR pLabel)    /* 32-byte token label (blank padded) */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_InitPIN initializes the normal user's PIN. */
CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(
							CK_SESSION_HANDLE hSession,  /* the session's handle */
							CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
							CK_ULONG          ulPinLen)  /* length in bytes of the PIN */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(
							CK_SESSION_HANDLE hSession,  /* the session's handle */
							CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
							CK_ULONG          ulOldLen,  /* length of the old PIN */
							CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
							CK_ULONG          ulNewLen)  /* length of the new PIN */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
