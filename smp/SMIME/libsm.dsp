# Microsoft Developer Studio Project File - Name="libsm" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=LIBSM - WIN32 DEBUG
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libsm.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libsm.mak" CFG="LIBSM - WIN32 DEBUG"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libsm - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libsm - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libsm - Win32 StaticSnacc Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libsm - Win32 StaticSnacc Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "libsm"
# PROP Scc_LocalPath "."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libsm - Win32 Release"

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
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MD /W4 /GX /O2 /I "../cml/cmapi/inc" /I "../cml/srl/inc" /I "../../SMPDist/include/esnacc/c++" /I "./libsrc/zlib/src" /I "./libCtilMgr/inc" /I "./inc" /I "../cml/cmlasn/inc" /I "../acl/inc" /I "../pkcs11_cryptopp/inc" /I "../cml/crlsrv_dll/inc/" /D "NDEBUG" /D "_WINDOWS" /D "NO_SCCS_ID" /D "WIN32" /YX /FD /Zm300 /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"../../SMPDist/lib/libsm.lib"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "./obj/debug"
# PROP Intermediate_Dir "./obj/debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MDd /W4 /GX /Z7 /I "../cml/cmapi/inc" /I "../cml/srl/inc" /I "../../SMPDist/include/esnacc/c++" /I "./libsrc/zlib/src" /I "./libCtilMgr/inc" /I "./inc" /I "../cml/cmlasn/inc" /I "../acl/inc" /I "../pkcs11_cryptopp/inc" /I "../cml/crlsrv_dll/inc/" /D "_DEBUG" /D "_WINDOWS" /D "NO_SCCS_ID" /D "WIN32" /FR /YX /FD /Zm300 /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"../../SMPDist/lib/libsmd.lib"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libsm___Win32_StaticSnacc_Debug"
# PROP BASE Intermediate_Dir "libsm___Win32_StaticSnacc_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "libsm___Win32_StaticSnacc_Debug"
# PROP Intermediate_Dir "libsm___Win32_StaticSnacc_Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Z7 /I "./include" /I "./include/snacc/c++" /I "./include/cmapi" /I "./libcert/include" /D "_DEBUG" /D "NO_SCCS_ID" /D "SNACC_DEEP_COPY" /D "VDADER_RULES" /D "_WINDOWS" /D "WIN32" /FR /YX /FD /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /I "../SMPDist/esnacc/c++/inc" /I "./libCtilMgr/inc" /I "./inc" /I "../cml/cmlasn/inc" /I "../acl/inc" /I "../pkcs11_cryptopp/inc" /D "_DEBUG" /D LIBCERTDLL_API="" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /D "_WINDOWS" /D "NO_SCCS_ID" /D "WIN32" /FR /YX /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"./lib/libsmd.lib"
# ADD LIB32 /nologo /out:"./lib/libsmdSTATICd.lib"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "libsm___Win32_StaticSnacc_Release"
# PROP BASE Intermediate_Dir "libsm___Win32_StaticSnacc_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "libsm___Win32_StaticSnacc_Release"
# PROP Intermediate_Dir "libsm___Win32_StaticSnacc_Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "./libcert/include" /I "./include" /I "../SMPDist/util/VDASnacc/cpplib/inc" /I "./include/cmapi" /D "NDEBUG" /D "_WINDOWS" /D "NO_SCCS_ID" /D "SNACC_DEEP_COPY" /D "VDADER_RULES" /D "WIN32" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../SMPDist/esnacc/c++/inc" /I "./libCtilMgr/inc" /I "./inc" /I "../cml/cmlasn/inc" /I "../acl/inc" /I "../pkcs11_cryptopp/inc" /D "NDEBUG" /D LIBCERTDLL_API="" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /D "_WINDOWS" /D "NO_SCCS_ID" /D "WIN32" /YX /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"./lib/libsm.lib"
# ADD LIB32 /nologo /out:"./lib/libsmdSTATIC.lib"

!ENDIF 

# Begin Target

# Name "libsm - Win32 Release"
# Name "libsm - Win32 Debug"
# Name "libsm - Win32 StaticSnacc Debug"
# Name "libsm - Win32 StaticSnacc Release"
# Begin Group "asn"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\libsrc\asn1\sm_cms.asn1

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputDir=.\libsrc\asn1
InputPath=.\libsrc\asn1\sm_cms.asn1
InputName=sm_cms

BuildCmds= \
	type $(InputPath) > ..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd $(InputDir) \
	attrib -r $(InputName).cpp \
	attrib -r ..\..\inc\$(InputName).h \
	..\..\..\..\SMPDist\bin\esnacc -C -I .\ -I ..\..\libCtilMgr\src -I ..\..\libcert\asn1 -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputDir=.\libsrc\asn1
InputPath=.\libsrc\asn1\sm_cms.asn1
InputName=sm_cms

BuildCmds= \
	type $(InputPath) > ..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd $(InputDir) \
	attrib -r $(InputName).cpp \
	attrib -r ..\..\inc\$(InputName).h \
	..\..\..\..\SMPDist\bin\esnaccd -C -I .\ -I ..\..\libCtilMgr\src -I ..\..\libcert\asn1 -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\libsrc\asn1\sm_cms.asn1
InputName=sm_cms

BuildCmds= \
	type "$(InputPath)" > ..\..\SMPDist\include\modules\$(InputName).asn1

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\libsrc\asn1\sm_cms.asn1
InputName=sm_cms

BuildCmds= \
	type "$(InputPath)" > ..\..\SMPDist\include\modules\$(InputName).asn1

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\asn1\sm_ess.asn1

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputDir=.\libsrc\asn1
InputPath=.\libsrc\asn1\sm_ess.asn1
InputName=sm_ess

BuildCmds= \
	type $(InputPath) > ..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd $(InputDir) \
	attrib -r $(InputName).cpp \
	attrib -r ..\..\inc\$(InputName).h \
	..\..\..\..\SMPDist\bin\esnacc -C -I .\ -I ..\..\libCtilMgr\src -I ..\..\libcert\asn1 -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputDir=.\libsrc\asn1
InputPath=.\libsrc\asn1\sm_ess.asn1
InputName=sm_ess

BuildCmds= \
	type $(InputPath) > ..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd $(InputDir) \
	attrib -r $(InputName).cpp \
	attrib -r ..\..\inc\$(InputName).h \
	..\..\..\..\SMPDist\bin\esnaccd -C -I .\ -I ..\..\libCtilMgr\src -I ..\..\libcert\asn1 -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\libsrc\asn1\sm_ess.asn1
InputName=sm_ess

BuildCmds= \
	type "$(InputPath)" > ..\..\SMPDist\include\modules\$(InputName).asn1

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\libsrc\asn1\sm_ess.asn1
InputName=sm_ess

BuildCmds= \
	type "$(InputPath)" > ..\..\SMPDist\include\modules\$(InputName).asn1

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\asn1\sm_pkixtsp.asn1

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputDir=.\libsrc\asn1
InputPath=.\libsrc\asn1\sm_pkixtsp.asn1
InputName=sm_pkixtsp

BuildCmds= \
	type $(InputPath) > ..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd $(InputDir) \
	attrib -r $(InputName).cpp \
	attrib -r ..\..\inc\$(InputName).h \
	..\..\..\..\SMPDist\bin\esnacc -C -I .\ -I ..\..\libCtilMgr\src -I ..\..\libcert\asn1 -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputDir=.\libsrc\asn1
InputPath=.\libsrc\asn1\sm_pkixtsp.asn1
InputName=sm_pkixtsp

BuildCmds= \
	type $(InputPath) > ..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd $(InputDir) \
	attrib -r $(InputName).cpp \
	attrib -r ..\..\inc\$(InputName).h \
	..\..\..\..\SMPDist\bin\esnaccd -C -I .\ -I ..\..\libCtilMgr\src -I ..\..\libcert\asn1 -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"libsrc\asn1\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# End Group
# Begin Group "Source Files"

# PROP Default_Filter ".cpp,.c"
# Begin Source File

SOURCE=.\libsrc\zlib\gzstream\gzstream.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_AC_Interface.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_Attr.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_CFrees.c
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_CM_Interface.cpp

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# ADD CPP /I "../cml/cmapi/inc" /I "../cml/srl/inc" /I "../SMPDist/util/ldap/include"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# ADD CPP /I "../cml/cmapi/inc" /I "../cml/srl/inc" /I "../SMPDist/util/ldap/include"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\asn1\sm_cms.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_CommonData.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_Content.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_ContentInfo.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_CounterSign.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_CSupport.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_Decrypt.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_DecryptC.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_DecryptEncData.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_Encrypt.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_EncryptC.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_EncryptEncData.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\asn1\sm_ess.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_MsgSignerInfo.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_OriginatorInfo.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\asn1\sm_pkixtsp.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_PreProcC.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_ReceiptData.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_RecipientIdent.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_RecipientInfo.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_Sign.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_SignC.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_SupportC.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\lolevel\sm_timeStamp.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_TimeStampToken.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_Verify.cpp

!IF  "$(CFG)" == "libsm - Win32 Release"

# ADD CPP /Z7 /Od

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_VerifyC.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_VerifyC_Support.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_VerRec.cpp
# End Source File
# Begin Source File

SOURCE=.\libsrc\hilevel\sm_VerRecC.cpp
# End Source File
# End Group
# Begin Group "Include Files"

# PROP Default_Filter ".h"
# Begin Source File

SOURCE=..\cml\cmlasn\inc\AttributeCertificateDefinitions.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\include\AttributeCertificateDefinitions.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\AuthenticationFramework.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\CertificateExtensions.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmapi\inc\cmapi_cpp.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\include\cmlasn.h
# End Source File
# Begin Source File

SOURCE=.\inc\gzstream.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\InformationFramework.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\ORAddress.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\PKIX.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\sdn702.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\include\SelectedAttributeTypes.h
# End Source File
# Begin Source File

SOURCE=.\inc\sm_AC_Interface.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_AC_Interface.h
InputName=sm_AC_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_AC_Interface.h
InputName=sm_AC_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_AC_Interface.h
InputName=sm_AC_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_AC_Interface.h
InputName=sm_AC_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_api.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_api.h
InputName=sm_api

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_api.h
InputName=sm_api

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_api.h
InputName=sm_api

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_api.h
InputName=sm_api

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_apic.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_apic.h
InputName=sm_apic

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_apic.h
InputName=sm_apic

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_apic.h
InputName=sm_apic

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_apic.h
InputName=sm_apic

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_apiCert.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_apiCert.h
InputName=sm_apiCert

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_apiCert.h
InputName=sm_apiCert

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_apiCert.h
InputName=sm_apiCert

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_apiCert.h
InputName=sm_apiCert

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libCtilMgr\inc\sm_apiCtilMgr.h
# End Source File
# Begin Source File

SOURCE=.\inc\sm_AppLogin.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_AppLogin.h
InputName=sm_AppLogin

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_AppLogin.h
InputName=sm_AppLogin

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_AppLogin.h
InputName=sm_AppLogin

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_AppLogin.h
InputName=sm_AppLogin

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_CM_Interface.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_CM_Interface.h
InputName=sm_CM_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_CM_Interface.h
InputName=sm_CM_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_CM_Interface.h
InputName=sm_CM_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_CM_Interface.h
InputName=sm_CM_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_cms.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_cms.h
InputName=sm_cms

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_cms.h
InputName=sm_cms

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_cms.h
InputName=sm_cms

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_cms.h
InputName=sm_cms

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_ess.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_ess.h
InputName=sm_ess

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_ess.h
InputName=sm_ess

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_ess.h
InputName=sm_ess

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_ess.h
InputName=sm_ess

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_pkixtsp.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_pkixtsp.h
InputName=sm_pkixtsp

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_pkixtsp.h
InputName=sm_pkixtsp

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_timeStamp.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_timeStamp.h
InputName=sm_timeStamp

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_timeStamp.h
InputName=sm_timeStamp

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_VDAStream.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_VDAStream.h
InputName=sm_VDAStream

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_VDAStream.h
InputName=sm_VDAStream

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_VDAStream.h
InputName=sm_VDAStream

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_VDAStream.h
InputName=sm_VDAStream

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_VDASupport_asn.h

!IF  "$(CFG)" == "libsm - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_VDASupport_asn.h
InputName=sm_VDASupport_asn

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_VDASupport_asn.h
InputName=sm_VDASupport_asn

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

# Begin Custom Build
InputPath=.\inc\sm_VDASupport_asn.h
InputName=sm_VDASupport_asn

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

# Begin Custom Build
InputPath=.\inc\sm_VDASupport_asn.h
InputName=sm_VDASupport_asn

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\UpperBounds.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\UsefulDefinitions.h
# End Source File
# Begin Source File

SOURCE=..\cml\cmlasn\inc\X509Common.h
# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\zconf.h
# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\zlib.h
# End Source File
# End Group
# Begin Group "zlib"

# PROP Default_Filter ""
# Begin Source File

SOURCE=.\libsrc\zlib\src\adler32.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\compress.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# ADD CPP /FAs
# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\crc32.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\deflate.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\example.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\gzio.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\infblock.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\infcodes.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\inffast.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\inflate.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\inftrees.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\infutil.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\trees.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\uncompr.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\libsrc\zlib\src\zutil.c

!IF  "$(CFG)" == "libsm - Win32 Release"

!ELSEIF  "$(CFG)" == "libsm - Win32 Debug"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Debug"

!ELSEIF  "$(CFG)" == "libsm - Win32 StaticSnacc Release"

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
