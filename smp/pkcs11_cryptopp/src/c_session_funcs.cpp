/************************ PKCS #11 Session Functions ************************
 *
 * This source file contains the following session management functions:
 * + C_OpenSession
 * + C_CloseSession
 * + C_CloseAllSessions
 * + C_GetSessionInfo
 * + C_GetOperationState
 * + C_SetOperationState
 * + C_Login
 * + C_Logout
 */

#include "p11cryptopp_internal.h"


/* C_OpenSession()
 * opens a session between an application and a token in a particular slot.
 * slotID is the slot’s ID; flags indicates the type of session; pApplication is an 
 * application defined pointer to be passed to the notification callback; Notify is 
 * the address of the notification
 */
CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(
			CK_SLOT_ID            slotID,        /* the slot's ID */
			CK_FLAGS              flags,         /* from CK_SESSION_INFO */
			CK_VOID_PTR           pApplication,  /* passed to callback */
			CK_NOTIFY             Notify,        /* callback function */
			CK_SESSION_HANDLE_PTR phSession)     /* gets session handle */
{
	// Check that the library has been initialized
	if (!LibraryIsInitialized())
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	// Check that the session handle pointer is not NULL
	if (phSession == NULL)
		return CKR_ARGUMENTS_BAD;

	// Check that the slotID is valid
	if (slotID != 0)
		return CKR_SLOT_ID_INVALID;

	// Check that CKF_SERIAL_SESSION flag is set (for legacy reasons)
	if ((flags & CKF_SERIAL_SESSION) == 0)
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	// Try to create a new session
	std::pair<SessionMap::iterator, bool> iNew = CreateNewSession();
	if (!iNew.second)
		return CKR_GENERAL_ERROR;

	// Set the session handle and notification callbacks
	*phSession = iNew.first->first;
	iNew.first->second.SetNotificationCallbacks(Notify, pApplication);

	return CKR_OK;
}


/* C_CloseSession
 * closes a session between an application and a token. hSession is the
 * session’s handle.
 */
CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(
			CK_SESSION_HANDLE hSession)  /* the session's handle */
{
	return CloseSession(hSession);
}


/* C_CloseAllSessions
 * closes all sessions an application has with a token. slotID specifies the
 * token’s slot. 
 */
CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(
			CK_SLOT_ID     slotID)  /* the token's slot */
{
	return CloseAllSessions(slotID);
}


/* C_GetSessionInfo
 * obtains information about a session. hSession is the session’s handle;
 * pInfo points to the location that receives the session information.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(
		CK_SESSION_HANDLE   hSession,  /* the session's handle */
		CK_SESSION_INFO_PTR pInfo)      /* receives session info */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_GetOperationState
 * obtains a copy of the cryptographic operations state of a session,
 * encoded as a string of bytes. hSession is the session’s handle; pOperationState points to the
 * location that receives the state; pulOperationStateLen points to the location that receives 
 * the length in bytes of the state.
 */
CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(
		CK_SESSION_HANDLE hSession,             /* session's handle */
		CK_BYTE_PTR       pOperationState,      /* gets state */
		CK_ULONG_PTR      pulOperationStateLen)  /* gets state length */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SetOperationState 
 * restores the cryptographic operations state of a session from a string of
 * bytes obtained with C_GetOperationState. hSession is the session’s handle;
 * pOperationState points to the location holding the saved state; ulOperationStateLen holds the
 * length of the saved state; hEncryptionKey holds a handle to the key which will be used for an
 * ongoing encryption or decryption operation in the restored session (or 0 if no encryption or
 * decryption key is needed, either because no such operation is ongoing in the stored session or
 * because all the necessary key information is present in the saved state); hAuthenticationKey
 * holds a handle to the key which will be used for an ongoing signature, MACing, or verification
 * operation in the restored session (or 0 if no such key is needed, either because no such
 * operation is ongoing in the stored session or because all the necessary key information is 
 * present in the saved state).
 */
CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(
		CK_SESSION_HANDLE hSession,            /* session's handle */
		CK_BYTE_PTR      pOperationState,      /* holds state */
		CK_ULONG         ulOperationStateLen,  /* holds state length */
		CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
		CK_OBJECT_HANDLE hAuthenticationKey)    /* sign/verify key */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_Login
 * logs a user into a token. hSession is a session handle; userType is the user type;
 * pPin points to the user’s PIN; ulPinLen is the length of the PIN. This standard allows PIN
 * values to contain any valid UTF8 character, but the token may impose subset restrictions.
 */
 CK_DEFINE_FUNCTION(CK_RV, C_Login)(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_USER_TYPE      userType,  /* the user type */
		CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
		CK_ULONG          ulPinLen)   /* the length of the PIN */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_Logout 
 * logs a user out from a token.  hSession is the session’s handle.
 */
CK_DEFINE_FUNCTION(CK_RV,C_Logout)(
		CK_SESSION_HANDLE hSession)  /* the session's handle */
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* Parallel function management (obsolete) */

/* C_GetFunctionStatus is a legacy function; it obtains an
 * updated status of a function running in parallel with an
 * application. */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(
		CK_SESSION_HANDLE hSession)  /* the session's handle */
{
	return CKR_FUNCTION_NOT_PARALLEL;
}


/* C_CancelFunction is a legacy function; it cancels a function
 * running in parallel. */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(
		CK_SESSION_HANDLE hSession)  /* the session's handle */
{
	return CKR_FUNCTION_NOT_PARALLEL;
}
