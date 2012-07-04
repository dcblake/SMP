SMP v2.5 Patch 2

Files Changed:
smp/smp.sln [CR-58]
smp/smp.dsw [CR-58]
smp/Makefile.in
smp/ACL/ACL.vcproj [CR-57]
smp/ACL/inc/acl_api.h [CR-57,CR-58]
smp/ACL/inc/aclinternal.h [CR-58]
smp/ACL/src/Makefile.in
smp/ACL/src/aclsession.cpp [CR-57]
smp/ACL/src/aclsectag.cpp [CR-47,CR-58]
smp/ACL/src/aclclearcert.cpp [CR-36]
smp/cml/crlsrv_dll/crlsrv_dll.vcproj
smp/cml/crlsrv_dll/crlsrv_dll.dsp
smp/cml/crlsrv_dll/inc/CRL_SRVinternal.h [CR-58]
smp/cml/crlsrv_dll/src/CRL_Mgr.cpp [CR-41,CR-42,CR-45,CR-48,CR-58]
smp/cml/cmlasn/cmlasn.vcproj [CR-57]
smp/cml/cmlasn/src/CM_globals.c [CR-46]
smp/cml/cmlasn/src/CM_Certificate.cpp [CR-57]
smp/cml/cmlasn/src/CM_AttribCert.cpp [CR-58]
smp/cml/cmlasn/src/CM_Extensions.cpp [CR-58]
smp/cml/cmlasn/src/CM_GeneralNames.cpp [CR-58]
smp/cml/cmlasn/inc/cmlasn_c.h [CR-46]
smp/cml/cmlasn/inc/cmlasn_exts.h [CR-58]
smp/cml/cmapi/cmapi_dll.vcproj
smp/cml/cmapi/cmapi_dll.dsp
smp/cml/cmapi/inc/CM_internal.h [CR-57]
smp/cml/cmapi/inc/PathBuild.h [CR-58]
smp/cml/cmapi/inc/CM_cache.h [CR-58]
smp/sml/cmapi/src/Makefile.in
smp/cml/cmapi/src/CM_RetrieveKey.cpp [CR-46,CR-58]
smp/cml/cmapi/src/CM_Mgr.cpp [CR-46,CR-51,CR-57]
smp/cml/cmapi/src/CM_srl.cpp [CR-51,CR-57]
smp/cml/cmapi/src/CM_CRL.cpp [CR-37,CR-51,CR-57]
smp/cml/cmapi/src/CM_CertPath.cpp [CR-34]
smp/cml/ocsp_dll/inc/ocsp_internal.h [CR-58]
smp/cml/ocsp_dll/inc/ocspapi.h [CR-58]
smp/cml/srl/srl.dsp
smp/cml/srl/srl.vcproj
smp/cml/srl/inc/SRL_internal.h
smp/cml/srl/inc/SRL_ldap.h
smp/cml/srl/src/SRL_Socket.c
smp/cml/srl/src/SRL_http.c
smp/cml/srl/src/SRL_store.c [CR-49]
smp/cml/srl/src/SRL_db.c [CR-49,CR-59]
smp/cml/srl/src/SRL_ReqOps.c [CR-33]
smp/cml/srl/src/SRL_ldap.c [CR-35]
smp/cryptlib_smp/cryptlib_smp.vcproj [CR-58]
smp/cryptlib_smp/cryptlib_smp.dsp [CR-58]
smp/SMIME/libsm.dsp
smp/SMIME/libsm.vcproj
smp/SMIME/libsmutil.dsp
smp/SMIME/libsmutil.vcproj [CR-57]
smp/SMIME/alg_libs/sm_free3/sm_free3.cpp [CR-58]
smp/SMIME/alg_libs/sm_free3/sm_free3_RSA.cpp [CR-36,CR-58]
smp/SMIME/alg_libs/sm_free3/sm_free3DLL.vcproj [CR-58]
smp/SMIME/alg_libs/sm_free3/sm_free3.h [CR-58]
smp/SMIME/alg_libs/lolevel/sm_CryptoKeys.h [CR-58]
smp/SMIME/alg_libs/sm_rsa/Makefile.in
smp/SMIME/alg_libs/sm_rsa/sm_rsaDLL.vcproj
smp/SMIME/alg_libs/sm_capiDLL/sm_capiDLL.vcproj
smp/SMIME/alg_libs/sm_fort/sm_fortezzaDLL.vcproj
smp/SMIME/alg_libs/sm_fort/sm_fortezzaDLL.dsp
smp/SMIME/alg_libs/sm_pkcs11/sm_pkcs11DLL.vcproj
smp/SMIME/alg_libs/sm_pkcs11Free3DLL/sm_pkcs11Free3DLL.vcproj
smp/SMIME/alg_libs/sm_pkcs11Free3DLL/sm_pkcs11Free3DLL.dsp
smp/SMIME/alg_libs/sm_spex/sm_spexDLL.vcproj
smp/SMIME/inc/sm_apiCert.h [CR-57]
smp/SMIME/inc/sm_CM_Interface.h [CR-57]
smp/SMIME/inc/sm_api.h  [CR-58]
smp/SMIME/libcert/src/sm_SignBuf.cpp [CR-36]
smp/SMIME/libcert/src/sm_Issuer.cpp [CR-57]
smp/SMIME/libcert/src/sm_certChoice.cpp [CR-58]
smp/SMIME/libsrc/hilevel/sm_Decrypt.cpp [CR-57]
smp/SMIME/libsrc/hilevel/sm_Verify.cpp [CR-57]
smp/SMIME/libsrc/hilevel/Makefile.in
smp/SMIME/libsrc/lolevel/Makefile.in
smp/SMIME/libsrc/lolevel/sm_CM_Interface.cpp [CR-57]
smp/SMIME/libsrc/lolevel/sm_CommonData.cpp [CR-57]
smp/SMIME/libsrc/lolevel/sm_MsgSignerInfo.cpp [CR-57]
smp/SMIME/libsrc/lolevel/sm_ContentInfo.cpp [CR-58]
smp/SMIME/libCtilMgr/inc/sm_apiCtilMgr.h [CR-58]
smp/SMIME/libCtilMgr/inc/sm_common.h [CR-58]
smp/SMIME/libCtilMgr/src/sm_common.cpp [CR-58]
smp/SMIME/libCtilMgr/inc/sm_tlistC.h [CR-58]
smp/SMP_Check/Makefile.in
smp/SMP_Check/SMP_Check.vcproj [CR-57]
smp/SMP_Check/SMP_Check.dsp
smp/SMP_Check/sm_checkCreate.cpp
smp/SMP_Check/sm_checkRead.cpp [CR-57]
smp/SMP_Check/SMP_Check.cpp [CR-57]

Fixes:
CR-33: Corrected a bug where certificates added to the database from a URL are not found locally with the SRL_RequestObjs() function.
CR-34: Corrected a bug where certificates added to the database from a URL do not include the flag to include the crossCertificatePair directory attribute.
CR-35: Set the default LDAP client behavior from v2 to v3.
CR-36: Removed memory leaks from the ACL and SFL libraries.
CR-37: Fixed the incorrect algorithm in Findcrlissuer() function that was causing performance problems.
CR-41: Fixed a code bug where the base class for a CRL is added to the cache instead of the derived class.
CR-42: Delta CRL processing now occurs if the freshest extension is in the CRL, not just in the certificate.
CR-45: CRL processing code now works around not having an AsnInt::operator >() function by using < and == operators.  Also fixed a problem with a delta CRL being issued at the same time as a base CRL.
CR-46: Added support to more extended key usages in the CML.
CR-47: Removed a memory leak from the ACL.
CR-48: The code now considers a delta CRL applicable to a base CRL if the CRLNumbers in the delta and base are equal.
CR-49: Fixed a problem with CRL updates to the database using improper hash values.
CR-51: Can now build CML into static libraries.
CR-57: Various fixes in the ACL, CML, and SFL libraries.
CR-58: Now supports Crypto++ 5.2.1 and GCC v4.1.1 and below.
CR-59: Fixed a bug in the dbu_read_entry.

The patch has been tested on Linux/Windows without issue.
