# Microsoft Developer Studio Project File - Name="libsmutil" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=libsmutil - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libsmutil.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libsmutil.mak" CFG="libsmutil - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libsmutil - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "libsmutil - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "libsmutil"
# PROP Scc_LocalPath "."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libsmutil - Win32 Release"

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
# ADD CPP /nologo /MD /W4 /GX /O2 /I "../../SMPDist/util/ldap/windows/include" /I "../../SMPDist/include/esnacc/c++" /I "./testsrc/inc" /I "../cml/cmapi/inc" /I "../cml/srl/inc" /I "../cml/crlsrv_dll/inc" /I "./libCtilMgr/inc" /I "./inc" /I "../cml/cmlasn/inc" /I "../acl/inc" /I "../SMP_Check" /I "../../SMPDist/include/pkcs11" /I "../pkcs11_cryptopp/inc" /D "NDEBUG" /D "_WINDOWS" /D "NO_SCCS_ID" /D "WIN32" /YX /FD /Zm300 /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"../../SMPDist/lib/libsmutil.lib"

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

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
# ADD CPP /nologo /MDd /W3 /GX /Z7 /I "../../SMPDist/util/ldap/windows/include" /I "../../SMPDist/include/esnacc/c++" /I "./testsrc/inc" /I "../cml/cmapi/inc" /I "../cml/srl/inc" /I "../cml/crlsrv_dll/inc" /I "./libCtilMgr/inc" /I "./inc" /I "../cml/cmlasn/inc" /I "../acl/inc" /I "../SMP_Check" /I "../../SMPDist/include/pkcs11" /I "../pkcs11_cryptopp/inc" /D "_DEBUG" /D "_WINDOWS" /D "NO_SCCS_ID" /D "WIN32" /FR /YX /FD /Zm300 /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"../../SMPDist/lib/libsmutild.lib"

!ENDIF 

# Begin Target

# Name "libsmutil - Win32 Release"
# Name "libsmutil - Win32 Debug"
# Begin Group "Headers"

# PROP Default_Filter "*.h"
# Begin Source File

SOURCE=.\testsrc\inc\sm_client.h

!IF  "$(CFG)" == "libsmutil - Win32 Release"

# Begin Custom Build
InputPath=.\testsrc\inc\sm_client.h
InputName=sm_client

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

# Begin Custom Build
InputPath=.\testsrc\inc\sm_client.h
InputName=sm_client

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_CM_Interface.h

!IF  "$(CFG)" == "libsmutil - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_CM_Interface.h
InputName=sm_CM_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_CM_Interface.h
InputName=sm_CM_Interface

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\testsrc\inc\sm_Report.h

!IF  "$(CFG)" == "libsmutil - Win32 Release"

# Begin Custom Build
InputPath=.\testsrc\inc\sm_Report.h
InputName=sm_Report

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

# Begin Custom Build
InputPath=.\testsrc\inc\sm_Report.h
InputName=sm_Report

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\testsrc\inc\sm_util.h

!IF  "$(CFG)" == "libsmutil - Win32 Release"

# Begin Custom Build
InputPath=.\testsrc\inc\sm_util.h
InputName=sm_util

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

# Begin Custom Build
InputPath=.\testsrc\inc\sm_util.h
InputName=sm_util

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\testsrc\inc\sm_utilc.h

!IF  "$(CFG)" == "libsmutil - Win32 Release"

# Begin Custom Build
InputPath=.\testsrc\inc\sm_utilc.h
InputName=sm_utilc

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

# Begin Custom Build
InputPath=.\testsrc\inc\sm_utilc.h
InputName=sm_utilc

"..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Source File

SOURCE=.\testsrc\util\sm_AutoCf.c
# ADD CPP /I "../../SMPDist/util/ldap/include"
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_Autohif.cpp
# ADD CPP /D "MIMESFL_INCLUDED"
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_Autolof.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CCfgCheckDecrypt.c
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CCfgCheckEncrypt.c
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CCfgCheckLogin.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CCfgCheckRecVerify.c
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CCfgCheckSign.c
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CCfgCheckVerify.c
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CertTest.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgCert.cpp
# ADD CPP /I "./alg_libs/lolevel"
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgCheckAttribs.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgCheckContentInfo.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgCheckDN.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgCheckGenName.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgCheckIss.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgCheckRecipientId.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgDriver.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgLogins.cpp

!IF  "$(CFG)" == "libsmutil - Win32 Release"

# ADD CPP /I "../cryptopp3"

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgLolevelAddRecip.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgLolevelDemo.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CfgSupport.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CFillDecrypt.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CFillEncrypt.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CFillRecVerify.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CFillSign.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CFillVerify.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLCfgCrls.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLMsgBase.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLMsgToCounterSign.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLMsgToDecrypt.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLMsgToDecryptEncData.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLMsgToEncrypt.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLMsgToEncryptEncData.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLMsgToSign.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLMsgToVerify.cpp

!IF  "$(CFG)" == "libsmutil - Win32 Release"

# ADD CPP /Z7 /O2
# SUBTRACT CPP /Fr

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLReceiptMsgToVerify.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CLReportSupport.cpp

!IF  "$(CFG)" == "libsmutil - Win32 Release"

# ADD CPP /I "../cryptopp3"

!ELSEIF  "$(CFG)" == "libsmutil - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_CReportVerify.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_EDTimingTest.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_gfsi.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_SFLThreadTests.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_snaccMain.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_StrFuncs.cpp
# End Source File
# Begin Source File

SOURCE=.\testsrc\util\sm_TestCML_Interface.cpp
# End Source File
# Begin Source File

SOURCE=.\testutil\testTripleWrap\testTripleWrap.cpp
# ADD CPP /I "testutil/mimelib" /D "NON_MAIN"
# End Source File
# End Target
# End Project
