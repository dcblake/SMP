/*****************************************************************************
File:     CM_CAPI.cpp
Project:  Certificate Management Library
Contents: Classes and functions to interface with Microsoft CAPI functions

Created:  January 2004
Author:   Rich Nicholas <Richard.Nicholas@DigitalNet.com>

Last Updated:  16 September 2004

Version:  2.4.1

*****************************************************************************/
#ifdef WIN32
////////////////////
// Included Files //
////////////////////
#include "CM_internal.h"


// Using declarations
using namespace CML;
using namespace CML::Internal;


//////////////////////
// Debugging Macros //
//////////////////////
#define OUTPUT_LAST_WINDOWS_ERROR(str) \
	OUTPUT_WINDOWS_ERROR(GetLastError(), str)
#ifdef _DEBUG
	#define OUTPUT_WINDOWS_ERROR(err, str)	outputWinError(err, str)
#else
	#define OUTPUT_WINDOWS_ERROR(err, str)
#endif // _DEBUG


/////////////////////////
// Function Prototypes //
/////////////////////////
#ifdef _DEBUG
	static void outputWinError(DWORD lastError, const char* functionName);
#endif // _DEBUG



////////////////////////////////////////
// MS_CSP_Handle class implementation //
////////////////////////////////////////
MS_CSP_Handle::MS_CSP_Handle(HCRYPTPROV handle, bool cmlCreated)
{
	m_handle = handle;
	m_createdInternally = cmlCreated;

	// Get the supported algorithms
	BYTE algInfo[1000];
	DWORD algInfoSize = sizeof(algInfo);
	DWORD firstFlag = CRYPT_FIRST;
	while (CryptGetProvParam(m_handle, PP_ENUMALGS, algInfo, &algInfoSize,
		firstFlag))
	{
		// Reset first flag
		firstFlag = 0;

		// Add this algorithm identifier to the list of ones supported
	    m_supportedAlgs.insert(*(ALG_ID *)algInfo);
	}
}


MS_CSP_Handle::~MS_CSP_Handle()
{
	if (m_createdInternally)
		CryptReleaseContext(m_handle, 0);
}


short MS_CSP_Handle::LoadPublicKey(const ASN::PublicKeyInfo& pubKey,
								   const ASN::Bytes* pubKeyParams,
								   HCRYPTKEY* phKey) const
{
	// Check required parameter
	if (phKey == NULL)
		return CM_NULL_POINTER;

   // Create a temporary copy of the public key info, adding or replacing
   // the optional, external parameters, if present
   ASN::PublicKeyInfo pubKeyToUse(pubKey);
	if (pubKeyParams != NULL)
	{
		// Copy the specified parameters into the temporary public key
		if (pubKeyToUse.algorithm.parameters == NULL)
		{
			// Create and copy the parameters if parameters don't exist
			pubKeyToUse.algorithm.parameters = new ASN::Bytes(*pubKeyParams);
			if (pubKeyToUse.algorithm.parameters == NULL)
				return CM_MEMORY_ERROR;
		}
		else	// Just copy the specified parameters
			*pubKeyToUse.algorithm.parameters = *pubKeyParams;
	}

	// If the public key is from a Fortezza v1 certificate, convert the
	// public key and parameters to the normal DSA public key format
	if (pubKeyToUse.algorithm == gDSA_KEA_OID)
	{
      // Check that the required parameters are present
      if (pubKeyToUse.algorithm.parameters == NULL)
         return CM_MISSING_PARAMETERS;

		Pub_key_struct* pComboKey = NULL;
		try {
			// Decode and convert the C++ public key to the C version
			pComboKey = pubKeyToUse.GetPubKeyStruct();

			// Set the algorithm OID to the standard DSA OID
         pubKeyToUse.algorithm.algorithm = SNACC::id_dsa;

			// Fill in the new DSA public key
			SNACC::DSAPublicKey dsaPubKey((char*)pComboKey->key.combo->dsa_y.data,
				pComboKey->key.combo->dsa_y.num, true);

			// Fill in the new DSA parameters
			SNACC::Dss_Parms dsaParams;
			dsaParams.p.Set(pComboKey->params.dsa_kea->p.data,
				pComboKey->params.dsa_kea->p.num);
			dsaParams.q.Set(pComboKey->params.dsa_kea->q.data,
				pComboKey->params.dsa_kea->q.num);
			dsaParams.g.Set(pComboKey->params.dsa_kea->g.data,
				pComboKey->params.dsa_kea->g.num);

			// Encode and replace the parameters and public key
			pubKeyToUse.algorithm.parameters->Encode(dsaParams);
			pubKeyToUse.key.Encode(dsaPubKey);
		}
		catch (...) {
			CMASN_FreePubKeyContents(pComboKey);
			free(pComboKey);
			return CM_ASN_ERROR;
		}

      // Free the temporary C Pub_key_struct
      CMASN_FreePubKeyContents(pComboKey);
      free(pComboKey);
	}

	// Build the CAPI public key info
	CERT_PUBLIC_KEY_INFO pubKeyInfo;
	pubKeyInfo.Algorithm.pszObjId = (LPSTR)
		(const char*)pubKeyToUse.algorithm.algorithm;
	if (pubKeyToUse.algorithm.parameters != NULL)
	{
		pubKeyInfo.Algorithm.Parameters.cbData =
			pubKeyToUse.algorithm.parameters->Len();
		pubKeyInfo.Algorithm.Parameters.pbData =
			(unsigned char*)pubKeyToUse.algorithm.parameters->GetData();
	}
	else	// Parameters are absent
	{
		pubKeyInfo.Algorithm.Parameters.cbData = 0;
		pubKeyInfo.Algorithm.Parameters.pbData = NULL;
	}

	pubKeyInfo.PublicKey.cbData = pubKeyToUse.key.Len();
	pubKeyInfo.PublicKey.pbData = (unsigned char*)pubKeyToUse.key.GetData();
	pubKeyInfo.PublicKey.cUnusedBits = pubKeyToUse.key.Len() * 8 -
		pubKeyToUse.key.BitLen();

	// Import the public key into the CSP
	if (!CryptImportPublicKeyInfo(m_handle, X509_ASN_ENCODING, &pubKeyInfo,
		phKey))
	{
		OUTPUT_LAST_WINDOWS_ERROR("CryptImportPublicKeyInfo");
		return CM_ASN_ERROR;
	}

	return CM_NO_ERROR;
} // end of MS_CSP_Handle::LoadPublicKey()


short MS_CSP_Handle::Sign(const ASN::Bytes& dataToSign,
						  Signature& signature) const
{
	// Split the signature algorithm 
	const char* pHashAlg;
	const char* pPubKeyAlg =
		SplitSigHashAlg(signature.GetAlgorithm().algorithm, &pHashAlg);

	// Return an error if the algorithm is not supported
	if ((pHashAlg == NULL) || (pPubKeyAlg == NULL))
		return CM_NOT_IMPLEMENTED;

	// Get the CAPI algorithm IDs for the public key and hash algorithms
	ALG_ID hashAlg = GetCAPI_AlgID(pHashAlg);
	ALG_ID pubKeyAlg = GetCAPI_AlgID(pPubKeyAlg);

	// Return an error if either algorithm is not supported
	if ((hashAlg == 0) || (pubKeyAlg == 0))
		return CM_NOT_IMPLEMENTED;

	// Check that both algorithms are supported by this CSP
	if ((m_supportedAlgs.find(hashAlg) == m_supportedAlgs.end()) ||
		(m_supportedAlgs.find(pubKeyAlg) == m_supportedAlgs.end()))
		return CM_NO_TOKENS_SUPPORT_SIG_ALG;

	HCRYPTHASH hHash = NULL;
	BYTE* pBuf = NULL;
	try {
		// Create the hash
		if (!CryptCreateHash(m_handle, hashAlg, 0, 0, &hHash))
			throw CAPI_ERR;

		// Hash the dataToSign
		if (!CryptHashData(hHash, dataToSign.GetData(), dataToSign.Len(), 0))
			throw CAPI_ERR;

		// Determine the size of the signature value
		DWORD bufSize;
		if (CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &bufSize) !=
			ERROR_MORE_DATA)
			throw CAPI_ERR;

		// Allocate the buffer for the signature value
		pBuf = new BYTE[bufSize];
		if (pBuf == NULL)
			throw CML_MEMORY_ERR;

		// Sign the hash
		if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pBuf, &bufSize))
			throw CAPI_ERR;

		// Copy the signature value
		signature.Set(bufSize, pBuf);

		// Destroy the temporary objects
		delete[] pBuf;
		CryptDestroyHash(hHash);

		return CM_NO_ERROR;
	}
	catch (...) {
		// Destroy the temporary objects
		delete[] pBuf;
		CryptDestroyHash(hHash);
		throw;
	}
}


short MS_CSP_Handle::Verify(const ASN::Bytes& signedData,
							const Signature& signature,
							const ASN::PublicKeyInfo& pubKey,
							const ASN::Bytes* pubKeyParams) const
{
	// Split the signature algorithm 
	const char* pHashAlg;
	const char* pPubKeyAlg =
		SplitSigHashAlg(signature.GetAlgorithm().algorithm, &pHashAlg);

	// Return an error if the algorithm is not supported
	if ((pHashAlg == NULL) || (pPubKeyAlg == NULL))
		return CM_NOT_IMPLEMENTED;

	// Get the CAPI algorithm IDs for the public key and hash algorithms
	ALG_ID hashAlg = GetCAPI_AlgID(pHashAlg);
	ALG_ID pubKeyAlg = GetCAPI_AlgID(pPubKeyAlg);

	// Return an error if either algorithm is not supported by the CML
	if ((hashAlg == 0) || (pubKeyAlg == 0))
		return CM_NOT_IMPLEMENTED;

	// Check that both algorithms are supported by this CSP
	if ((m_supportedAlgs.find(hashAlg) == m_supportedAlgs.end()) ||
		(m_supportedAlgs.find(pubKeyAlg) == m_supportedAlgs.end()))
		return CM_NO_TOKENS_SUPPORT_SIG_ALG;

	// Convert and load the public key into the CSP
	HCRYPTKEY hPubKey = 0;
	short rc = LoadPublicKey(pubKey, pubKeyParams, &hPubKey);
	if (rc != CM_NO_ERROR)
		return rc;

	// Create the hash object
	HCRYPTHASH hHash = 0;
	if ((rc == 0) && !CryptCreateHash(m_handle, hashAlg, 0, 0, &hHash))
	{
		OUTPUT_LAST_WINDOWS_ERROR("CryptCreateHash");
		rc = CM_NOT_IMPLEMENTED;
	}

	// Hash the data
	if ((rc == 0) && !CryptHashData(hHash, signedData.GetData(),
		signedData.Len(), 0))
	{
		OUTPUT_LAST_WINDOWS_ERROR("CryptHashData");
		rc = CM_NOT_IMPLEMENTED;
	}

	// Verify the signature
	if ((rc == 0) && !CryptVerifySignature(hHash,
		signature.GetCAPIValue().GetData(), signature.GetCAPIValue().Len(),
		hPubKey, NULL, 0))
	{
		DWORD lastErr = GetLastError();
		OUTPUT_WINDOWS_ERROR(lastErr, "CryptVerifySignature");
		if (lastErr == NTE_BAD_SIGNATURE)
			rc = CM_SIGNATURE_INVALID;
		else
			rc = CM_NOT_IMPLEMENTED;
	}

	// Destroy the public key
	if (hPubKey != 0)
		CryptDestroyKey(hPubKey);

	// Destroy the hash object
	if (hHash != 0)
		CryptDestroyHash(hHash);

	// Return the result code
	return rc;
}


////////////////////////
// Internal functions //
////////////////////////
#ifdef _DEBUG
void outputWinError(DWORD lastError, const char* functionName)
{
	if (IsDebuggerPresent())
	{
		LPVOID lpMsgBuf;
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
			FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, lastError, 
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR)&lpMsgBuf, 0, NULL);

		// Send the string to the Output window
		OutputDebugString(functionName);
		OutputDebugString("() returned:  ");
		OutputDebugString((LPCTSTR)lpMsgBuf);

		// Free the buffer.
		LocalFree(lpMsgBuf);
	}
}
#endif // _DEBUG
#endif


// end of CM_CAPI.cpp
