# Microsoft Developer Studio Project File - Name="sm_free3DLL" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=sm_free3DLL - Win32 Debug OpenSSL
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sm_free3DLL.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sm_free3DLL.mak" CFG="sm_free3DLL - Win32 Debug OpenSSL"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sm_free3DLL - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sm_free3DLL - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sm_free3DLL - Win32 Debug OpenSSL" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sm_free3DLL - Win32 Release OpenSSL" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "sm_free3DLL"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FREE3DLL_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../../../../SMPDist/Algs/crypto++" /I "../../../../SMPDist/include/esnacc/c++" /I "../sm_free3" /I "../lolevel" /I "../../inc/cmapi" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../libCtilMgr/AES" /I "../../../cml/cmlasn/inc" /I "../../../../SMPDist/include/smp" /I "../../../pkcs11_cryptopp/inc" /I "../../../../SMPDist/include/pkcs11" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FREE3DLL_EXPORTS" /D "SM_FREE3_USED" /D "WIN32" /D "SFLPKCS12_ENABLED" /D "SM_FREE3_RSA_INCLUDED" /D DSA_1024_BIT_MODULUS_ONLY=0 /FD /Zm400 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 wsock32.lib ../../../../SMPDist/lib/cryptlib.lib Advapi32.lib /nologo /dll /pdb:none /machine:I386 /out:"../../../../SMPDist/lib/sm_free3DLL.dll "
# Begin Custom Build
TargetName=sm_free3DLL
InputPath=\devel.d\vda_snacc.d\deliverR2.5.d\devel.60\SMPDist\lib\sm_free3DLL.dll
InputName=sm_free3DLL
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\sm_free3DLL.dll $(windir)\system32 
	copy RELEASE\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FREE3DLL_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W4 /GX /Zi /Od /I "../../../../SMPDist/Algs/crypto++" /I "../../../../SMPDist/include/esnacc/c++" /I "../sm_free3" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /I "../../../../SMPDist/include/smp" /I "../../../pkcs11_cryptopp/inc" /D "_DEBUG" /D DSA_1024_BIT_MODULUS_ONLY=0 /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FREE3DLL_EXPORTS" /D "SM_FREE3_USED" /D "WIN32" /D "SFLPKCS12_ENABLED" /D "SM_FREE3_RSA_INCLUDED" /FR /FD /GZ /Zm400 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 wsock32.lib ../../../../SMPDist/lib/cryptlib_d.lib ../../../../SMPDist/lib/libCtilMgrd.lib Advapi32.lib /nologo /dll /profile /debug /machine:I386 /out:"../../../../SMPDist/lib/sm_free3DLLd.dll"
# Begin Custom Build
TargetName=sm_free3DLLd
InputPath=\devel.d\vda_snacc.d\deliverR2.5.d\devel.60\SMPDist\lib\sm_free3DLLd.dll
InputName=sm_free3DLLd
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\sm_free3DLLd.dll $(windir)\system32 
	copy DEBUG\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	echo "NAME=" $(InputName) 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "sm_free3DLL___Win32_Debug_OpenSSL"
# PROP BASE Intermediate_Dir "sm_free3DLL___Win32_Debug_OpenSSL"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "sm_free3DLL___Win32_Debug_OpenSSL"
# PROP Intermediate_Dir "sm_free3DLL___Win32_Debug_OpenSSL"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W4 /GX /Zi /Od /I "../../../SMPDist/Algs/crypto++4.2" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../SNACC" /I "../../../SNACC/c++-lib/inc" /I "../../inc/cmapi" /I "../../../cml/cmlasn/inc" /I "../sm_free3" /I "../../../SMPDist/util/SFLPkcs12" /I "../lolevel" /D "_WINDOWS" /D "_USRDLL" /D "SM_FREE3DLL_EXPORTS" /D "SM_FREE3_USED" /D "SFLPKCS12_ENABLED" /D "SM_FREE3_RSA_INCLUDED" /D "_DEBUG" /D "_MBCS" /D "WIN32" /FR /FD /GZ /c
# SUBTRACT BASE CPP /YX /Yc /Yu
# ADD CPP /nologo /MDd /W4 /GX /Zi /Od /I "../../../../SMPDist/util/SFLPkcs12" /I "../../../../SMPDist/Algs/crypto++" /I "../../../../SMPDist/include/esnacc/c++" /I "../sm_free3" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /D "_DEBUG" /D "OPENSSL_PKCS12_ENABLED" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FREE3DLL_EXPORTS" /D "SM_FREE3_USED" /D "WIN32" /D "SFLPKCS12_ENABLED" /D "SM_FREE3_RSA_INCLUDED" /D DSA_1024_BIT_MODULUS_ONLY=0 /FR /FD /GZ /Zm200 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ../../../SMPDist/Algs/crypto++4.2/debug/cryptlib.lib ../../../SMPDist/util/SFLPkcs12/SFLPkcs12Libd.lib ../../libcert\libCertDLL\Debug/libCertDLLd.lib wsock32.lib ../../lib/libCtilMgrd.lib ../../../SNACC/c++-lib/cppasn1/Debug/snaccCpp_d.lib ../../../cml/lib/cmlasn_d.lib /nologo /dll /profile /debug /machine:I386 /out:"../../test/sm_free3DLLd.dll"
# SUBTRACT BASE LINK32 /map
# ADD LINK32 ../../../../SMPDist/lib/cryptlib_d.lib ../../../../SMPDist/util/SFLPkcs12/SFLPkcs12Libd.lib wsock32.lib Advapi32.lib /nologo /dll /profile /debug /machine:I386 /out:"../../../../SMPDist/lib/sm_free3DLLOpenSSLd.dll"
# SUBTRACT LINK32 /map
# Begin Custom Build
OutDir=.\sm_free3DLL___Win32_Debug_OpenSSL
TargetName=sm_free3DLLOpenSSLd
InputPath=\devel.d\vda_snacc.d\deliverR2.5.d\devel.60\SMPDist\lib\sm_free3DLLOpenSSLd.dll
InputName=sm_free3DLLOpenSSLd
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(TargetName).dll $(windir)\system32 
	copy $(OutDir)\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	echo "NAME=" $(OutDir)/$(TargetName) 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "sm_free3DLL___Win32_Release_OpenSSL"
# PROP BASE Intermediate_Dir "sm_free3DLL___Win32_Release_OpenSSL"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "sm_free3DLL___Win32_Release_OpenSSL"
# PROP Intermediate_Dir "sm_free3DLL___Win32_Release_OpenSSL"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "../../../SMPDist/Algs/crypto++4.2" /I "../sm_free3" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../SMPDist/esnacc/c++/inc" /I "../../../cml/cmlasn/inc" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FREE3DLL_EXPORTS" /D "SM_FREE3_USED" /D "WIN32" /D "SFLPKCS12_ENABLED" /D "SM_FREE3_RSA_INCLUDED" /FD /Zm200 /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../../../../SMPDist/util/SFLPkcs12" /I "../../../../SMPDist/Algs/crypto++" /I "../../../../SMPDist/include/esnacc/c++" /I "../sm_free3" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /D "NDEBUG" /D "OPENSSL_PKCS12_ENABLED" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FREE3DLL_EXPORTS" /D "SM_FREE3_USED" /D "WIN32" /D "SFLPKCS12_ENABLED" /D "SM_FREE3_RSA_INCLUDED" /D DSA_1024_BIT_MODULUS_ONLY=0 /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ../../../SMPDist/Algs/crypto++4.2/release/cryptlib.lib wsock32.lib /nologo /dll /machine:I386 /out:"../../../SMPDist/sfl/alg_libs/sm_free3/sm_free3DLL.dll "
# ADD LINK32 ../../../../SMPDist/lib/cryptlib.lib wsock32.lib ../../../../SMPDist/util/SFLPkcs12/SFLPkcs12Libd.lib Advapi32.lib /nologo /dll /machine:I386 /out:"../../../../SMPDist/lib/sm_free3DLLOpenSSL.dll"
# Begin Custom Build
OutDir=.\sm_free3DLL___Win32_Release_OpenSSL
TargetName=sm_free3DLLOpenSSL
InputPath=\devel.d\vda_snacc.d\deliverR2.5.d\devel.60\SMPDist\lib\sm_free3DLLOpenSSL.dll
InputName=sm_free3DLLOpenSSL
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(TargetName).dll $(windir)\system32 
	copy $(OutDir)\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	echo "NAME=" $(InputName) 
	
# End Custom Build

!ENDIF 

# Begin Target

# Name "sm_free3DLL - Win32 Release"
# Name "sm_free3DLL - Win32 Debug"
# Name "sm_free3DLL - Win32 Debug OpenSSL"
# Name "sm_free3DLL - Win32 Release OpenSSL"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\sm_aes_wrap.cpp
# End Source File
# Begin Source File

SOURCE=..\..\libsrc\asn1\sm_cms.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# SUBTRACT BASE CPP /YX /Yc /Yu
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\lolevel\sm_CryptoKeysBase.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# SUBTRACT BASE CPP /YX /Yc /Yu
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_CryptoKeysDH.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1
# ADD CPP /W3

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# ADD BASE CPP /W3
# ADD CPP /W3

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# SUBTRACT BASE CPP /YX /Yc /Yu
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_CryptoKeysDsa.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1
# ADD CPP /W3

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# ADD BASE CPP /W3
# ADD CPP /W3

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# SUBTRACT BASE CPP /YX /Yc /Yu
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_CryptoKeysECDsa.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_CryptoKeysF3Rsa.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1
# ADD CPP /W3

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# ADD BASE CPP /W3
# ADD CPP /W3

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_CryptoKeysFree3Base.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1
# ADD CPP /W3

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# ADD BASE CPP /W3
# ADD CPP /W3

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# SUBTRACT BASE CPP /YX /Yc /Yu
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_free3.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# ADD CPP /W3 /Z7
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# ADD BASE CPP /W3
# SUBTRACT BASE CPP /YX /Yc /Yu
# ADD CPP /W3
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# SUBTRACT BASE CPP /YX /Yc /Yu
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_free3_asn.asn1

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_FR="..\..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
InputPath=.\sm_free3_asn.asn1
InputName=sm_free3_asn

BuildCmds= \
	copy "$(InputPath)"  ..\..\..\..\SMPDist\include\Modules \
	..\..\..\..\SMPDist\bin\esnacc -C -I ../../libcert/asn1 -I ../../libsrc/asn1 -I ../../libCtilMgr/src -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_FR="..\..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
InputPath=.\sm_free3_asn.asn1
InputName=sm_free3_asn

BuildCmds= \
	copy "$(InputPath)"  ..\..\..\..\SMPDist\include\Modules \
	..\..\..\..\SMPDist\bin\esnaccd -C -I ../../libcert/asn1 -I ../../libsrc/asn1 -I ../../libCtilMgr/src -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_FR="..\..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
IntDir=.\..\..\..\..\SMPDist\include\modules
InputPath=.\sm_free3_asn.asn1
InputName=sm_free3_asn

BuildCmds= \
	copy "$(InputPath)" $(IntDir) \
	..\..\..\..\SMPDist\bin\esnaccd -D -C -I ../../libcert/asn1 -I ../../libsrc/asn1 -I ../../libCtilMgr/src -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_FR="..\..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
IntDir=.\..\..\..\..\SMPDist\include\modules
InputPath=.\sm_free3_asn.asn1
InputName=sm_free3_asn

BuildCmds= \
	copy "$(InputPath)" $(IntDir) \
	..\..\..\..\SMPDist\bin\esnacc -D -C -I ../../libcert/asn1 -I ../../libsrc/asn1 -I ../../libCtilMgr/src -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_free3_asn.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_free3_RSA.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# ADD CPP /W3
# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# ADD BASE CPP /W3
# SUBTRACT BASE CPP /YX
# ADD CPP /W3
# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# SUBTRACT BASE CPP /YX /Yc /Yu
# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_free3DLL.cpp
# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_free3Internal.cpp

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1
# ADD CPP /Z7

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

!ENDIF 

# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\config.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\cryptlib.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\des.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\dh.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\dh2.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\dsa.h"
# End Source File
# Begin Source File

SOURCE=..\..\..\..\cryptopp50\ec2n.h
# End Source File
# Begin Source File

SOURCE=..\..\..\..\cryptopp50\eccrypto.h
# End Source File
# Begin Source File

SOURCE=..\..\..\..\cryptopp50\ecp.h
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\gfpcrypt.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\integer.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\md2.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\md5.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\modes.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\pubkey.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\queue.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\rc2.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\rijndael.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\ripemd.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\rng.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\rsa.h"
# End Source File
# Begin Source File

SOURCE="..\..\..\..\SMPDist\Algs\crypto++\sha.h"
# End Source File
# Begin Source File

SOURCE=.\sm_aes_wrap.h
# End Source File
# Begin Source File

SOURCE=..\..\inc\sm_cms.h
# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_free3.h

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_free3\sm_free3.h
InputName=sm_free3

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_free3\sm_free3.h
InputName=sm_free3

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# Begin Custom Build
InputPath=..\sm_free3\sm_free3.h
InputName=sm_free3

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# Begin Custom Build
InputPath=..\sm_free3\sm_free3.h
InputName=sm_free3

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_free3_asn.h

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_free3\sm_free3_asn.h
InputName=sm_free3_asn

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_free3\sm_free3_asn.h
InputName=sm_free3_asn

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# Begin Custom Build
InputPath=..\sm_free3\sm_free3_asn.h
InputName=sm_free3_asn

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# Begin Custom Build
InputPath=..\sm_free3\sm_free3_asn.h
InputName=sm_free3_asn

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_free3DLL.h

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# Begin Custom Build
InputPath=.\sm_free3DLL.h
InputName=sm_free3DLL

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=.\sm_free3DLL.h
InputName=sm_free3DLL

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# Begin Custom Build
InputPath=.\sm_free3DLL.h
InputName=sm_free3DLL

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# Begin Custom Build
InputPath=.\sm_free3DLL.h
InputName=sm_free3DLL

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_vda_cbc.h

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_free3\sm_vda_cbc.h
InputName=sm_vda_cbc

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_free3\sm_vda_cbc.h
InputName=sm_vda_cbc

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# Begin Custom Build
InputPath=..\sm_free3\sm_vda_cbc.h
InputName=sm_vda_cbc

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# Begin Custom Build
InputPath=..\sm_free3\sm_vda_cbc.h
InputName=sm_vda_cbc

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Group "libs"

# PROP Default_Filter "*.lib"
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgr.lib

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCertd.lib

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCert.lib

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgrd.lib

!IF  "$(CFG)" == "sm_free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Debug OpenSSL"

!ELSEIF  "$(CFG)" == "sm_free3DLL - Win32 Release OpenSSL"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# End Target
# End Project
