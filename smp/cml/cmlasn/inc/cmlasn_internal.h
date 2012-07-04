/*************************************************************************
File:     cmlasn_internal.h
Project:  Certificate Management Library
Contents: Header file for the internal (low-level) functions used in the
          Certificate Management ASN.1 Library

Created:  21 March 2002
Author:   Rich Nicholas <Richard.Nicholas@GetronicsGov.com>

Last Updated:	30 December 2003

Version:  2.4

*****************************************************************************/
#ifndef _CMLASN_INTERNAL_H
#define _CMLASN_INTERNAL_H


// Define the CML ASN.1 Library export modifier
#if !defined(CM_API) && defined(WIN32)
	#define CM_API		__declspec(dllexport)
#endif


////////////////////
// Included Files //
////////////////////
#include "cmlasn.h"


//////////////////////
// Exception Macros //
//////////////////////
#define EXCEPTION_STR(e, str)	CML::ASN::Exception((e), __FILE__, __LINE__, (str))
#define EXCEPTION(e)			EXCEPTION_STR((e), NULL)
#define MEMORY_EXCEPTION		EXCEPTION_STR(CMLASN_MEMORY_ERROR, "out of memory")
#define ASN_EXCEPTION(str)		EXCEPTION_STR(CMLASN_DECODE_ERROR, (str))
#define ASN_EXCEPTION2(s1, s2)	CML::ASN::ExceptionString(CMLASN_DECODE_ERROR, \
									__FILE__, __LINE__, (s1), (s2))


// Begin nested CML::ASN::Internal namespace
namespace CML {
namespace ASN {
namespace Internal {



/////////////////////////
// Function Prototypes //
/////////////////////////
Bytes_struct* CvtAsnBufToBytes(const SNACC::AsnBuf& buffer);
void CvtAsnBufToBytesStruct(Bytes_struct& bytes,
							const SNACC::AsnBuf& buffer);
Bytes_struct* CvtAsnIntToBytes(const SNACC::AsnInt& hugeInt, int mult = 0);
void CvtAsnIntToExistingBytes(Bytes_struct& bytes,
							  const SNACC::AsnInt& hugeInt, int mult = 0);
Bytes_struct* CvtBitsToBytes(const SNACC::AsnBits& bits);
//Bytes_struct* CvtBufferToBytes(const CTIL::CSM_Buffer& buffer);
//void CvtBufferToBytesStruct(Bytes_struct& bytes,
//							const CTIL::CSM_Buffer& buffer);
void CvtBytesToSigStruct(Sig_struct& sig, const Bytes& encBuf);
void CvtBytesToStruct(Bytes_struct& cmBytes, const ASN::Bytes& bytes);
void CvtDistPointName(Dist_pt_name& cmDPName,
					  const ASN::DistPointName& dpName);
void CvtGenNameToStruct(Gen_name_struct& cmGN,
						const ASN::GenName& genName);
LongArray* CvtLongArray(const SNACC::SigPrivFlagsSeqOf& snacc);
void CvtPolicyStructToList(ASN::CertPolicyList& list,
						   const Policy_struct* policyList);
void CvtPubKeyToStruct(Pub_key_struct& cmPubKey,
					   const ASN::PublicKeyInfo& pubKeyInfo);
void cvtInt2BytesStruct(Bytes_struct **bytes, const SNACC::AsnInt& theInt);
Bytes_struct* cvtOctsToBytes(const SNACC::AsnOcts& octs);

void FillParameters(Pub_key_struct& cmPubKey, const ASN::AlgID& algID);
void FreeAccessDescriptions(AccessDescript_LL* pAccessDesc);
void FreeAttributes(Attributes_struct* attr);
void FreeAuthKeyID(Auth_key_struct* authKey);
void FreeBytes(Bytes_struct *bytes);
void FreeBytes_LL(Bytes_struct_LL **listhead);
void FreeCa_const(Ca_const **caConst);
void FreeCertExtensions(Cert_exts_struct *exts);
void FreeClearance(Clearance_struct **clearance);
void FreeCRLEntryExtensions(CRL_entry_exts_struct *exts);
void FreeCRLExtensions(CRL_exts_struct *exts);
void FreeCrlReferral(CRL_referral* ref);
void FreeDistPts_LL(Dist_pts_struct *dpList);
void FreeGenNameContent(Gen_name_struct *genName);
void FreeGenNames(Gen_names_struct* genNameList);
void FreeOIDList(CM_OID_LL *cmOidList);
void FreePerAuthScope(PerAuthScope_LL *scope);
void FreePolicyMaps(Pol_maps_struct *);
void FreePQGs(Pqg_params_struct *params);
void FreeQualifiers(Qualifier_struct** qual);
void FreeSecCategories(SecCat_LL** categories);
void FreeSectags(Sec_tags** secTags);
void FreeStatusRef(StatusReferral_LL *status_ref);
void FreeSubtrees(Subtree_struct **subtree);
void FreeUnknExtn(Unkn_extn_LL **unkn);
AccessDescript_LL* GetAccessDescriptList(const std::list<ASN::AccessDescription>& descList);
AccessDescript_LL* GetAccessDescriptStruct(const ASN::AccessDescription& desc);
Attributes_struct* GetAttributesList(const std::list<ASN::Attribute>& attribList);
Attributes_struct* GetAttributesStruct(const ASN::Attribute& attribute);
Auth_key_struct* GetAuthKeyStruct(const ASN::AuthKeyIdExtension& authKeyExt);
Bytes_struct* GetBytesStruct(const ASN::Bytes& bytes);
Cert_exts_struct* GetCertExts(const ASN::CertExtensions& exts);
Cert_path_LL* GetCertPathList(const ASN::CertificationPath& path);
Cert_struct* GetCertStruct(const ASN::Cert& cert);
CRL_entry_exts_struct* GetCrlEntryExts(const ASN::CrlEntryExtensions& exts);
CRL_exts_struct* GetCrlExts(const ASN::CrlExtensions& exts);
CRL_struct* GetCrlStruct(const ASN::CertificateList& crl);
Dist_pts_struct* GetDistPoint(const ASN::DistributionPoint& dp);
Dist_pts_struct* GetDistPtsList(const std::list<ASN::DistributionPoint>& dpList);
Extn_struct* GetExtStruct(const ASN::Extension& ext);
Gen_names_struct* GetGenNamesList(const ASN::GenNames& genNames);
Gen_name_struct* GetGenNameStruct(const ASN::GenName& genName);
ASN::CertPolicyList GetInitialPolicySet(ulong sessionID);
Policy_struct* GetPolicyList(const ASN::CertPolicyList& policies);
Pol_maps_struct* GetPolicyMapping(const ASN::PolicyMapping& mapping);
Policy_struct* GetPolicyStruct(const ASN::CertPolicy& policy);
Qualifier_struct* GetQualifierStruct(const ASN::PolicyQualifier& qual);
RevCerts_LL* GetRevCert(const ASN::RevokedEntry& revEntry);
RevCerts_LL* GetRevCertsList(const ASN::Revocations& revocations);
Subtree_struct* GetSubtreesList(const ASN::GeneralSubtrees& subtrees);
Subtree_struct* GetSubtreeStruct(const ASN::GeneralSubtree& subtree);
Unkn_extn_LL* GetUnkExtnStruct(const ASN::UnknownExtension& unkExt);
Unkn_extn_LL* GetUnknExts(const ASN::UnknownExtensions& unkExts);

void NumToString(short num, char* numstring);

} // end of nested Internal namespace
} // end of nested ASN namespace
} // end of CML namespace


#endif // _CMLASN_INTERNAL_H
