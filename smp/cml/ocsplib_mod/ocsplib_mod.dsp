# Microsoft Developer Studio Project File - Name="ocsplib_mod" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=ocsplib_mod - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "ocsplib_mod.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "ocsplib_mod.mak" CFG="ocsplib_mod - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "ocsplib_mod - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "ocsplib_mod - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /Zi /O2 /I "..\..\..\SMPDist\include\ocsp" /I "..\..\..\SMPDist\include\ocsp\openssl" /D "NDEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /D "MK1MF_BUILD" /D "_WIN32" /FD /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\..\SMPDist\lib\ocsplib_mod.lib"

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm- /GX /ZI /Od /I "..\..\..\SMPDist\include\ocsp" /I "..\..\..\SMPDist\include\ocsp\openssl" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_LIB" /D "MK1MF_BUILD" /D "_WIN32" /FR /FD /GZ /c
# SUBTRACT CPP /YX
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\..\SMPDist\lib\ocsplib_mod_d.lib"

!ENDIF 

# Begin Target

# Name "ocsplib_mod - Win32 Release"
# Name "ocsplib_mod - Win32 Debug"
# Begin Group "Crypto Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_bitstr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_bool.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_bytes.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_d2i_fp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_digest.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_dup.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_enum.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_gentm.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_hdr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_i2d_fp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_int.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_mbstr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_meth.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_object.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_octet.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_print.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_set.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_sign.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_strex.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_strnid.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_time.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_type.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_utctm.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_utf8.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\a_verify.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes_cbc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes_cfb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes_core.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes_ctr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes_ecb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes_misc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes_ofb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\asn1_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\asn1_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\asn1_par.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\asn_moid.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\asn_pack.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\b_dump.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\b_print.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\b_sock.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bf_buff.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bf\bf_cfb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bf\bf_ecb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bf\bf_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bf_lbuf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bf_nbio.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bf_null.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bf\bf_ofb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bf\bf_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\bio_b64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bio_cb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\bio_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bio_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bio_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\bio_md.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\bio_ok.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_add.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_asm.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_blind.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_ctx.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_div.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_exp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_exp2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_gcd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_kron.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_mod.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_mont.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_mpi.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_mul.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_prime.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_print.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_rand.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_recp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_shift.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_sqr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_sqrt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_word.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_acpt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_bio.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_conn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_fd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_file.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_log.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_mem.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_null.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bss_sock.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\buffer\buf_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\buffer\buffer.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\by_dir.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\by_file.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\c_all.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\c_allc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\c_alld.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cast\c_cfb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cast\c_ecb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cast\c_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cast\c_ofb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\comp\c_rle.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cast\c_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\comp\c_zlib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\cbc3_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\cbc_cksm.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\cbc_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\cfb64ede.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\cfb64enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\cfb_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\comp\comp_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\comp\comp_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_api.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_def.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_mall.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_mod.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_sap.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cpt_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cryptlib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cversion.c
# ADD CPP /D "NO_WINDOWS_BRAINDEATH"
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\d2i_pr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\d2i_pu.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\des_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\des_old.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\des_old2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dh\dh_asn1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dh\dh_check.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dh\dh_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dh\dh_gen.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dh\dh_key.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dh\dh_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\digest.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa_asn1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa_gen.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa_key.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa_ossl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa_sign.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa_vrf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso_dl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso_dlfcn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso_null.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso_openssl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso_vms.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso_win32.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_aes.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_bf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_cast.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_des.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_des3.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_idea.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_null.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_rc2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_rc4.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_rc5.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\e_xcbc_d.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ebcdic.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ec_cvt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ec_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ec_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ec_mult.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\ecb3_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\ecb_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ecp_mont.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ecp_nist.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ecp_recp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ecp_smpl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\ede_cbcm_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\enc_read.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\enc_writ.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\encode.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_all.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_cnf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_ctrl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_dyn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_fat.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_init.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_list.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_openssl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_pkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_table.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\err\err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\err\err_all.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\err\err_prn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp_acnf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\evp_asn1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp_key.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp_pbe.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp_pkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ex_data.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\example.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\f_enum.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\f_int.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\f_string.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\fcrypt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\fcrypt_b.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\hmac\hmac.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_4758_cca.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_4758_cca_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_aep.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_aep_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_atalla.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_atalla_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_cryptodev.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_cswift.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_cswift_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_ncipher.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_ncipher_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_nuron.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_nuron_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_sureware.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_sureware_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_ubsec.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_ubsec_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\i2d_pr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\i2d_pu.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\idea\i_cbc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\idea\i_cfb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\idea\i_ecb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\idea\i_ofb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\idea\i_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\krb5\krb5_asn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\lhash\lh_stats.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\lhash\lhash.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_dss.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_dss1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_md2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_md4.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_md5.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_mdc2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_null.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_ripemd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_sha.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\m_sha1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md2\md2_dgst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md2\md2_one.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md4\md4_dgst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md4\md4_one.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md5\md5_dgst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md5\md5_one.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rand\md_rand.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\mdc2\mdc2_one.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\mdc2\mdc2dgst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\mem.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\mem_clr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\mem_dbg.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\n_pkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\names.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\nsseq.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\objects\o_names.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\o_time.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\objects\obj_dat.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\objects\obj_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\objects\obj_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_asn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_cl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_ext.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_ht.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_prn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_srv.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp_vfy.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\ofb64ede.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\ofb64enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\ofb_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\openbsd_hw.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_add.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_asn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_attr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_crpt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_crt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_decr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_init.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_key.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_kiss.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_mutl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_npas.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_p8d.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_p8e.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\p12_utl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p5_crpt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p5_crpt2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\p5_pbe.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\p5_pbev2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\p8_pkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p_dec.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p_open.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p_seal.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p_sign.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\p_verify.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\pcbc_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_all.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_info.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_oth.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_pk8.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_pkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_seal.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_sign.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_x509.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem_xaux.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\pk12err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pk7_asn1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pk7_attr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pk7_dgst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pk7_doit.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pk7_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pk7_mime.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pk7_smime.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pkcs7err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\qud_cksm.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rand\rand_egd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rand\rand_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\rand_key.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rand\rand_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rand\rand_win.c
# ADD CPP /D _WIN32_WINNT=0x0400
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rand\randfile.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc2\rc2_cbc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc2\rc2_ecb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc2\rc2_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc2\rc2cfb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc2\rc2ofb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc4\rc4_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc4\rc4_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc5\rc5_ecb.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc5\rc5_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc5\rc5_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc5\rc5cfb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc5\rc5ofb64.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\read2pwd.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ripemd\rmd_dgst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ripemd\rmd_one.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\rpc_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_asn1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_chk.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_eay.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_gen.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_none.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_null.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_oaep.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_pk1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_saos.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_sign.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa_ssl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\set_key.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\sha\sha1_one.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\sha\sha1dgst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\sha\sha_dgst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\sha\sha_one.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\stack\stack.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\str2key.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\t_bitst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\t_crl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\t_pkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\t_req.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\t_spki.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\t_x509.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\t_x509a.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\tasn_dec.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\tasn_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\tasn_fre.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\tasn_new.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\tasn_typ.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\tasn_utl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\tb_cipher.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\tb_dh.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\tb_digest.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\tb_dsa.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\tb_rand.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\tb_rsa.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\tmdiff.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\txt_db\txt_db.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ui\ui_compat.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ui\ui_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ui\ui_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ui\ui_openssl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ui\ui_util.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\uid.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_akey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_akeya.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_alt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_bcons.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_bitst.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_conf.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_cpols.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_crld.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_enum.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_extku.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_genn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_ia5.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_info.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_int.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_ocsp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_pku.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_prn.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_purp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_skey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_sxnet.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3_utl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\v3err.c
# End Source File
# Begin Source File

SOURCE="..\..\..\openssl\crypto\bn\vms-helper.c"
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_att.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_cmp.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_d2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_def.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_ext.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_lu.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_obj.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_r2x.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_req.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_set.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_trs.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_txt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_v3.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_vfy.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509cset.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509name.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509rset.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509spki.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509type.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_algor.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x_all.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_attrib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_bignum.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_crl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_exten.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_info.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_long.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_name.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_pkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_pubkey.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_req.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_sig.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_spki.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_val.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_x509.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\x_x509a.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\xcbc_enc.c
# End Source File
# End Group
# Begin Group "Crypto Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\aes\aes.h
InputName=aes

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\aes\aes.h
InputName=aes

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\aes\aes_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\aes\aes_locl.h
InputName=aes_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\aes\aes_locl.h
InputName=aes_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\asn1.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\asn1\asn1.h
InputName=asn1

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\asn1\asn1.h
InputName=asn1

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\asn1_mac.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\asn1\asn1_mac.h
InputName=asn1_mac

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\asn1\asn1_mac.h
InputName=asn1_mac

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\asn1t.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\asn1\asn1t.h
InputName=asn1t

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\asn1\asn1t.h
InputName=asn1t

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bf\bf_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bf\bf_locl.h
InputName=bf_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bf\bf_locl.h
InputName=bf_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bf\bf_pi.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bf\bf_pi.h
InputName=bf_pi

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bf\bf_pi.h
InputName=bf_pi

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bio\bio.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bio\bio.h
InputName=bio

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bio\bio.h
InputName=bio

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bf\blowfish.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bf\blowfish.h
InputName=blowfish

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bf\blowfish.h
InputName=blowfish

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bn\bn.h
InputName=bn

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bn\bn.h
InputName=bn

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_lcl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bn\bn_lcl.h
InputName=bn_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bn\bn_lcl.h
InputName=bn_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\bn\bn_prime.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bn\bn_prime.h
InputName=bn_prime

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\bn\bn_prime.h
InputName=bn_prime

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\buffer\buffer.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\buffer\buffer.h
InputName=buffer

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\buffer\buffer.h
InputName=buffer

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cast\cast.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\cast\cast.h
InputName=cast

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\cast\cast.h
InputName=cast

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cast\cast_lcl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\cast\cast_lcl.h
InputName=cast_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\cast\cast_lcl.h
InputName=cast_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cast\cast_s.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\cast\cast_s.h
InputName=cast_s

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\cast\cast_s.h
InputName=cast_s

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\asn1\charmap.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\asn1\charmap.h
InputName=charmap

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\asn1\charmap.h
InputName=charmap

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\comp\comp.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\comp\comp.h
InputName=comp

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\comp\comp.h
InputName=comp

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\conf\conf.h
InputName=conf

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\conf\conf.h
InputName=conf

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_api.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\conf\conf_api.h
InputName=conf_api

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\conf\conf_api.h
InputName=conf_api

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\conf\conf_def.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\conf\conf_def.h
InputName=conf_def

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\conf\conf_def.h
InputName=conf_def

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\cryptlib.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\cryptlib.h
InputName=cryptlib

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\cryptlib.h
InputName=cryptlib

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\crypto.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\crypto.h
InputName=crypto

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\crypto.h
InputName=crypto

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\des.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\des.h
InputName=des

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\des.h
InputName=des

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\des_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\des_locl.h
InputName=des_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\des_locl.h
InputName=des_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\des_old.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\des_old.h
InputName=des_old

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\des_old.h
InputName=des_old

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\des_ver.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\des_ver.h
InputName=des_ver

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\des_ver.h
InputName=des_ver

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dh\dh.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\dh\dh.h
InputName=dh

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\dh\dh.h
InputName=dh

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dsa\dsa.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\dsa\dsa.h
InputName=dsa

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\dsa\dsa.h
InputName=dsa

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\dso\dso.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\dso\dso.h
InputName=dso

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\dso\dso.h
InputName=dso

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\e_os.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\e_os.h
InputName=e_os

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\e_os.h
InputName=e_os

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\e_os2.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\e_os2.h
InputName=e_os2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\e_os2.h
InputName=e_os2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ebcdic.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ebcdic.h
InputName=ebcdic

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ebcdic.h
InputName=ebcdic

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ec.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ec\ec.h
InputName=ec

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ec\ec.h
InputName=ec

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ec\ec_lcl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ec\ec_lcl.h
InputName=ec_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ec\ec_lcl.h
InputName=ec_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\eng_int.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\eng_int.h
InputName=eng_int

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\eng_int.h
InputName=eng_int

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\engine.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\engine.h
InputName=engine

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\engine.h
InputName=engine

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\err\err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\err\err.h
InputName=err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\err\err.h
InputName=err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\evp\evp.h
InputName=evp

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\evp\evp.h
InputName=evp

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\evp\evp_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\evp\evp_locl.h
InputName=evp_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\evp\evp_locl.h
InputName=evp_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\example.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pkcs7\example.h
InputName=example

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pkcs7\example.h
InputName=example

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\ext_dat.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\x509v3\ext_dat.h
InputName=ext_dat

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\x509v3\ext_dat.h
InputName=ext_dat

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\fips\fips.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\fips\fips.h
InputName=fips

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\fips\fips.h
InputName=fips

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\fips\rand\fips_rand.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\fips\rand\fips_rand.h
InputName=fips_rand

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\fips\rand\fips_rand.h
InputName=fips_rand

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\hmac\hmac.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\hmac\hmac.h
InputName=hmac

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\hmac\hmac.h
InputName=hmac

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_4758_cca_err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_4758_cca_err.h
InputName=hw_4758_cca_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_4758_cca_err.h
InputName=hw_4758_cca_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_aep_err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_aep_err.h
InputName=hw_aep_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_aep_err.h
InputName=hw_aep_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_atalla_err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_atalla_err.h
InputName=hw_atalla_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_atalla_err.h
InputName=hw_atalla_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_cswift_err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_cswift_err.h
InputName=hw_cswift_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_cswift_err.h
InputName=hw_cswift_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_ncipher_err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_ncipher_err.h
InputName=hw_ncipher_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_ncipher_err.h
InputName=hw_ncipher_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_nuron_err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_nuron_err.h
InputName=hw_nuron_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_nuron_err.h
InputName=hw_nuron_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_sureware_err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_sureware_err.h
InputName=hw_sureware_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_sureware_err.h
InputName=hw_sureware_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\engine\hw_ubsec_err.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_ubsec_err.h
InputName=hw_ubsec_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\engine\hw_ubsec_err.h
InputName=hw_ubsec_err

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\idea\idea.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\idea\idea.h
InputName=idea

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\idea\idea.h
InputName=idea

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\idea\idea_lcl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\idea\idea_lcl.h
InputName=idea_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\idea\idea_lcl.h
InputName=idea_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\krb5\krb5_asn.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\krb5\krb5_asn.h
InputName=krb5_asn

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\krb5\krb5_asn.h
InputName=krb5_asn

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\lhash\lhash.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\lhash\lhash.h
InputName=lhash

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\lhash\lhash.h
InputName=lhash

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md2\md2.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md2\md2.h
InputName=md2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md2\md2.h
InputName=md2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md32_common.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md32_common.h
InputName=md32_common

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md32_common.h
InputName=md32_common

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md4\md4.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md4\md4.h
InputName=md4

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md4\md4.h
InputName=md4

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md4\md4_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md4\md4_locl.h
InputName=md4_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md4\md4_locl.h
InputName=md4_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md5\md5.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md5\md5.h
InputName=md5

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md5\md5.h
InputName=md5

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\md5\md5_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md5\md5_locl.h
InputName=md5_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\md5\md5_locl.h
InputName=md5_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\mdc2\mdc2.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\mdc2\mdc2.h
InputName=mdc2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\mdc2\mdc2.h
InputName=mdc2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\o_time.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\o_time.h
InputName=o_time

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\o_time.h
InputName=o_time

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\objects\obj_dat.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\objects\obj_dat.h
InputName=obj_dat

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\objects\obj_dat.h
InputName=obj_dat

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\objects\obj_mac.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\objects\obj_mac.h
InputName=obj_mac

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\objects\obj_mac.h
InputName=obj_mac

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\objects\objects.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\objects\objects.h
InputName=objects

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\objects\objects.h
InputName=objects

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ocsp\ocsp.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ocsp\ocsp.h
InputName=ocsp

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ocsp\ocsp.h
InputName=ocsp

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\opensslconf.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\opensslconf.h
InputName=opensslconf

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\opensslconf.h
InputName=opensslconf

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\opensslv.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\opensslv.h
InputName=opensslv

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\opensslv.h
InputName=opensslv

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ossl_typ.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ossl_typ.h
InputName=ossl_typ

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ossl_typ.h
InputName=ossl_typ

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pem\pem.h
InputName=pem

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pem\pem.h
InputName=pem

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pem\pem2.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pem\pem2.h
InputName=pem2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pem\pem2.h
InputName=pem2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs12\pkcs12.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pkcs12\pkcs12.h
InputName=pkcs12

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pkcs12\pkcs12.h
InputName=pkcs12

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\pkcs7\pkcs7.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pkcs7\pkcs7.h
InputName=pkcs7

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\pkcs7\pkcs7.h
InputName=pkcs7

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rand\rand.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rand\rand.h
InputName=rand

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rand\rand.h
InputName=rand

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rand\rand_lcl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rand\rand_lcl.h
InputName=rand_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rand\rand_lcl.h
InputName=rand_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc2\rc2.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc2\rc2.h
InputName=rc2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc2\rc2.h
InputName=rc2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc2\rc2_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc2\rc2_locl.h
InputName=rc2_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc2\rc2_locl.h
InputName=rc2_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc4\rc4.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc4\rc4.h
InputName=rc4

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc4\rc4.h
InputName=rc4

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc4\rc4_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc4\rc4_locl.h
InputName=rc4_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc4\rc4_locl.h
InputName=rc4_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc5\rc5.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc5\rc5.h
InputName=rc5

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc5\rc5.h
InputName=rc5

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rc5\rc5_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc5\rc5_locl.h
InputName=rc5_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rc5\rc5_locl.h
InputName=rc5_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ripemd\ripemd.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ripemd\ripemd.h
InputName=ripemd

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ripemd\ripemd.h
InputName=ripemd

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ripemd\rmd_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ripemd\rmd_locl.h
InputName=rmd_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ripemd\rmd_locl.h
InputName=rmd_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ripemd\rmdconst.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ripemd\rmdconst.h
InputName=rmdconst

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ripemd\rmdconst.h
InputName=rmdconst

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\rpc_des.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\rpc_des.h
InputName=rpc_des

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\rpc_des.h
InputName=rpc_des

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\rsa\rsa.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rsa\rsa.h
InputName=rsa

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\rsa\rsa.h
InputName=rsa

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\stack\safestack.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\stack\safestack.h
InputName=safestack

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\stack\safestack.h
InputName=safestack

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\sha\sha.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\sha\sha.h
InputName=sha

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\sha\sha.h
InputName=sha

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\sha\sha_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\sha\sha_locl.h
InputName=sha_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\sha\sha_locl.h
InputName=sha_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\des\spr.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\spr.h
InputName=spr

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\des\spr.h
InputName=spr

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\stack\stack.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\stack\stack.h
InputName=stack

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\stack\stack.h
InputName=stack

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\symhacks.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\symhacks.h
InputName=symhacks

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\symhacks.h
InputName=symhacks

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\tmdiff.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\tmdiff.h
InputName=tmdiff

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\tmdiff.h
InputName=tmdiff

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\txt_db\txt_db.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\txt_db\txt_db.h
InputName=txt_db

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\txt_db\txt_db.h
InputName=txt_db

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ui\ui.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ui\ui.h
InputName=ui

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ui\ui.h
InputName=ui

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ui\ui_compat.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ui\ui_compat.h
InputName=ui_compat

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ui\ui_compat.h
InputName=ui_compat

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\ui\ui_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ui\ui_locl.h
InputName=ui_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\ui\ui_locl.h
InputName=ui_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\x509\x509.h
InputName=x509

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\x509\x509.h
InputName=x509

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509\x509_vfy.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\x509\x509_vfy.h
InputName=x509_vfy

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\x509\x509_vfy.h
InputName=x509_vfy

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\crypto\x509v3\x509v3.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\x509v3\x509v3.h
InputName=x509v3

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\crypto\x509v3\x509v3.h
InputName=x509v3

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "SSL Source Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\..\openssl\ssl\bio_ssl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\kssl.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s23_clnt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s23_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s23_meth.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s23_pkt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s23_srvr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s2_clnt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s2_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s2_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s2_meth.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s2_pkt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s2_srvr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s3_both.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s3_clnt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s3_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s3_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s3_meth.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s3_pkt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\s3_srvr.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_algs.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_asn1.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_cert.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_ciph.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_err.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_err2.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_rsa.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_sess.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_stat.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_txt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\t1_clnt.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\t1_enc.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\t1_lib.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\t1_meth.c
# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\t1_srvr.c
# End Source File
# End Group
# Begin Group "SSL Header Files"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\..\openssl\ssl\kssl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\kssl.h
InputName=kssl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\kssl.h
InputName=kssl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\kssl_lcl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\kssl_lcl.h
InputName=kssl_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\kssl_lcl.h
InputName=kssl_lcl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl.h
InputName=ssl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl.h
InputName=ssl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl2.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl2.h
InputName=ssl2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl2.h
InputName=ssl2

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl23.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl23.h
InputName=ssl23

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl23.h
InputName=ssl23

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl3.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl3.h
InputName=ssl3

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl3.h
InputName=ssl3

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\ssl_locl.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl_locl.h
InputName=ssl_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\ssl_locl.h
InputName=ssl_locl

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\openssl\ssl\tls1.h

!IF  "$(CFG)" == "ocsplib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\tls1.h
InputName=tls1

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ELSEIF  "$(CFG)" == "ocsplib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\..\..\openssl\ssl\tls1.h
InputName=tls1

"..\..\..\SMPDist\include\ocsp\openssl\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\ocsp\openssl

# End Custom Build

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
