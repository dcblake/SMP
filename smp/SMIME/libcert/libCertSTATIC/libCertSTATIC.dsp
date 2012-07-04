# Microsoft Developer Studio Project File - Name="libCertSTATIC" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libCertSTATIC - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libCertSTATIC.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libCertSTATIC.mak" CFG="libCertSTATIC - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libCertSTATIC - Win32 StaticSnacc Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libCertSTATIC - Win32 StaticSnacc Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libCertSTATIC - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "libCertSTATIC - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "libCertSTATIC"
# PROP Scc_LocalPath "..\.."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libCertSTATIC___Win32_StaticSnacc_Debug"
# PROP BASE Intermediate_Dir "libCertSTATIC___Win32_StaticSnacc_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "StaticSnacc_Debug"
# PROP Intermediate_Dir "StaticSnacc_Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /I "../include" /I "../../include/snacc/c++" /I "../../include/cmapi" /I "../" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D LIBCERTDLL_API="" /D VDASNACCDLL_API_EXPORTS="" /D "SNACC_DEEP_COPY" /D "VDADER_RULES" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "../../../SNACC" /I "../../../SNACC/c++-lib/inc" /I "../../inc/cmapi" /I "../../inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /D LIBCERTDLL_API="" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /D "VDASNACCDLL_API_EXPORTS" /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\..\lib\libCertSTATICd.lib"

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libCertSTATIC___Win32_StaticSnacc_Release"
# PROP BASE Intermediate_Dir "libCertSTATIC___Win32_StaticSnacc_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "StaticSnacc_Release"
# PROP Intermediate_Dir "StaticSnacc_Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "../include" /I "../../include/snacc/c++" /I "../../include/cmapi" /I "../" /D "_MBCS" /D "_LIB" /D "_DEBUG" /D "SNACC_DEEP_COPY" /D "VDADER_RULES" /D "WIN32" /D LIBCERTDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /YX /FD /GZ /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../../../SMPDist/pct/include" /I "../../../SNACC" /I "../../../SNACC/c++-lib/inc" /I "../../inc/cmapi" /I "../../inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /D LIBCERTDLL_API="" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /D "VDASNACCDLL_API_EXPORTS" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\..\lib\libCertSTATICd.lib"
# ADD LIB32 /nologo /out:"..\..\lib\libCertSTATIC.lib"

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libCertSTATIC___Win32_Debug"
# PROP BASE Intermediate_Dir "libCertSTATIC___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Z7 /Od /I "../../inc/cmapi" /I "../../inc" /I "../../../SNACC" /I "../../../SNACC/c++-lib/inc" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /D LIBCERTDLL_API="" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "../../../../SMPDist/include/esnacc/c++" /I "../../inc/cmapi" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /I "../../../cml/cmapi/inc" /I "../../../pkcs11_cryptopp/inc" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /FR /YX /FD /GZ /Zm200 /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\..\lib\libCertSTATICd.lib"
# ADD LIB32 /nologo /out:"../../../../SMPDist/lib/libCertd.lib"

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "libCertSTATIC___Win32_Release"
# PROP BASE Intermediate_Dir "libCertSTATIC___Win32_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MD /W3 /GX /O2 /I "../../../SMPDist/pct/include" /I "../../inc/cmapi" /I "../../inc" /I "../../../SNACC" /I "../../../SNACC/c++-lib/inc" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /D LIBCERTDLL_API="" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../../inc/cmapi" /I "../../inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /I "../../../cml/cmapi/inc" /I "../../../pkcs11_cryptopp/inc" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D "WIN32" /YX /FD /Zm200 /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\..\lib\libCertSTATIC.lib"
# ADD LIB32 /nologo /out:"../../../../SMPDist/lib/libCert.lib"

!ENDIF 

# Begin Target

# Name "libCertSTATIC - Win32 StaticSnacc Debug"
# Name "libCertSTATIC - Win32 StaticSnacc Release"
# Name "libCertSTATIC - Win32 Debug"
# Name "libCertSTATIC - Win32 Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\src\sm_AppLogin.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_AttrBase.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_certChoice.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_CertificateList.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_CSInst.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_CSMime.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_GenName.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_Identifier.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_Issuer.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_mabRout.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_MsgCertCrls.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_RevocationInfoChoice.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_RevocationInfoChoices.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_SignBuf.cpp
# End Source File
# Begin Source File

SOURCE=..\src\sm_VDAStream.cpp
# End Source File
# Begin Source File

SOURCE=..\asn1\sm_VDASupport_asn.asn1

!IF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_VD="..\..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
InputDir=\devel.d\vda_snacc.d\devel.cur\smp\SMIME\libcert\asn1
IntDir=.\..\..\..\..\SMPDist\include\modules
InputPath=..\asn1\sm_VDASupport_asn.asn1
InputName=sm_VDASupport_asn

BuildCmds= \
	type $(InputPath) > ..\..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd "$(InputDir)" \
	..\..\..\..\SMPDist\bin\esnaccd -D -C -I $(IntDir) $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"..\..\inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_VD="..\..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
InputDir=\devel.d\vda_snacc.d\devel.cur\smp\SMIME\libcert\asn1
IntDir=.\..\..\..\..\SMPDist\include\modules
InputPath=..\asn1\sm_VDASupport_asn.asn1
InputName=sm_VDASupport_asn

BuildCmds= \
	type $(InputPath) > ..\..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd "$(InputDir)" \
	..\..\..\..\SMPDist\bin\esnacc -D -C -I $(IntDir) $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"..\..\inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_VD="..\..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
InputDir=\devel.d\vda_snacc.d\devel.cur\smp\SMIME\libcert\asn1
InputPath=..\asn1\sm_VDASupport_asn.asn1
InputName=sm_VDASupport_asn

BuildCmds= \
	type $(InputPath) > ..\..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd "$(InputDir)" \
	..\..\..\..\SMPDist\bin\esnaccd -a 900 -C -I ..\..\libCtilMgr\src  -I ..\..\..\cml\cmlasn\Modules  $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"..\..\inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_VD="..\..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
InputDir=\devel.d\vda_snacc.d\devel.cur\smp\SMIME\libcert\asn1
InputPath=..\asn1\sm_VDASupport_asn.asn1
InputName=sm_VDASupport_asn

BuildCmds= \
	type $(InputPath) > ..\..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd "$(InputDir)" \
	..\..\..\..\SMPDist\bin\esnacc -C -I ..\..\libCtilMgr\src  -I ..\..\..\cml\cmlasn\Modules  $(InputName).asn1 \
	move $(InputName).h ..\..\inc \
	

"..\..\inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\asn1\sm_VDASupport_asn.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\..\inc\sm_apicCert.h

!IF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_apicCert.h
InputName=sm_apicCert

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_apicCert.h
InputName=sm_apicCert

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_apicCert.h
InputName=sm_apicCert

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_apicCert.h
InputName=sm_apicCert

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\inc\sm_apiCert.h

!IF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_apiCert.h
InputName=sm_apiCert

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_apiCert.h
InputName=sm_apiCert

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_apiCert.h
InputName=sm_apiCert

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_apiCert.h
InputName=sm_apiCert

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\inc\sm_AppLogin.h

!IF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_AppLogin.h
InputName=sm_AppLogin

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_AppLogin.h
InputName=sm_AppLogin

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_AppLogin.h
InputName=sm_AppLogin

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_AppLogin.h
InputName=sm_AppLogin

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\inc\sm_VDAStream.h

!IF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_VDAStream.h
InputName=sm_VDAStream

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_VDAStream.h
InputName=sm_VDAStream

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_VDAStream.h
InputName=sm_VDAStream

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_VDAStream.h
InputName=sm_VDAStream

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\inc\sm_VDASupport_asn.h

!IF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_VDASupport_asn.h
InputName=sm_VDASupport_asn

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 StaticSnacc Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_VDASupport_asn.h
InputName=sm_VDASupport_asn

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_VDASupport_asn.h
InputName=sm_VDASupport_asn

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "libCertSTATIC - Win32 Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputPath) to $(IntDir)
IntDir=.\..\..\..\..\SMPDist\include\smp
InputPath=..\..\inc\sm_VDASupport_asn.h
InputName=sm_VDASupport_asn

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
