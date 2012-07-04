# Microsoft Developer Studio Project File - Name="autoAlg" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=autoAlg - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "autoAlg.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "autoAlg.mak" CFG="autoAlg - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "autoAlg - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "autoAlg - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "autoAlg"
# PROP Scc_LocalPath ".."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "autoAlg - Win32 Release"

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
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MD /W4 /GX /O2 /I "../alg_libs/sm_spex" /I "../alg_libs/sm_fort" /I "../../../SMPDist/Algs/crypto++4.2" /I "../alg_libs/sm_capiDLL" /I "../../../SMPDist/Algs/bsafe42/library/include" /I "../alg_libs/sm_rsa" /I "../libCtilMgr/inc" /I "../alg_libs/sm_free3" /I "../inc" /I "../../../SMPDist/include/eSnacc/c++" /I "../testsrc/inc" /I "../../cml/cmlasn/inc" /I "../../cml/cmapi/inc" /I "../../cml/srl/inc" /D "_CONSOLE" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "SM_FREE3_USED" /D "SM_FREE3_RSA_INCLUDED" /YX /FD /Zm200 /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 ../../../SMPDist/Algs/crypto++4.2/release/cryptlib.lib ../../SMPDist/Algs/bsafe42/library/lib/bsafe42.lib wsock32.lib /nologo /subsystem:console /machine:I386 /out:"../test/autoAlg.exe"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

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
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "../alg_libs/sm_spex" /I "../alg_libs/sm_fort" /I "../../../SMPDist/Algs/crypto++" /I "../alg_libs/sm_capiDLL" /I "../../../SMPDist/Algs/bsafe42/library/include" /I "../alg_libs/sm_rsa" /I "../libCtilMgr/inc" /I "../alg_libs/sm_free3" /I "../inc" /I "../../../SMPDist/include/eSnacc/c++" /I "../testsrc/inc" /I "../../cml/cmlasn/inc" /I "../../cml/cmapi/inc" /I "../../cml/srl/inc" /I "../../acl/inc" /D "OPENSSL_PKCS12_ENABLED" /D "NO_SCCS_ID" /D "DW_NO_DLL" /D "_CONSOLE" /D "_DEBUG" /D "_MBCS" /D "WIN32" /D "SM_FREE3_USED" /D "SM_FREE3_RSA_INCLUDED" /FR /FD /GZ /Zm200 /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ../../../SMPDist/Algs/crypto++/debug/cryptlib.lib wsock32.lib /nologo /subsystem:console /debug /machine:I386 /out:"../test/autoAlgd.exe" /pdbtype:sept

!ENDIF 

# Begin Target

# Name "autoAlg - Win32 Release"
# Name "autoAlg - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\testsrc\hilevel\sm_AutoAlg.cpp

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# ADD CPP /I "../alg_libs/sm_fortezza"
# SUBTRACT CPP /YX

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\testsrc\utilAlgs\sm_AutoAlgf.cpp

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# ADD CPP /I "../alg_libs/sm_fortezza"
# SUBTRACT CPP /YX

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\testsrc\utilalgs\sm_CfgCapi.cpp

!IF  "$(CFG)" == "autoAlg - Win32 Release"

# ADD CPP /I "../../SMPDist/Algs/crypto++4.1"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\testsrc\utilAlgs\sm_CfgFree.cpp

!IF  "$(CFG)" == "autoAlg - Win32 Release"

# ADD CPP /W3

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# ADD CPP /I "../alg_libs/sm_fortezza"
# SUBTRACT CPP /YX

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\testsrc\utilAlgs\sm_CfgLoginsAlg.cpp

!IF  "$(CFG)" == "autoAlg - Win32 Release"

# SUBTRACT CPP /YX

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# ADD CPP /I "../alg_libs/sm_fortezza"
# SUBTRACT CPP /YX

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\testsrc\utilAlgs\sm_CfgRsa.cpp

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# ADD CPP /I "../alg_libs/sm_fortezza"
# SUBTRACT CPP /YX

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\testsrc\utilAlgs\sm_CfgSpex.cpp

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# ADD CPP /I "../sm_fort"
# SUBTRACT CPP /YX

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\testsrc\utilAlgs\sm_CTILAppLogin.cpp

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# ADD CPP /I "../alg_libs/sm_fortezza" /I "../../../../SMPDist/Algs/crypto++4.2" /I "../../../../SMPDist/Algs/bsafe42/library/include" /U "SM_SPEX_USED"
# SUBTRACT CPP /YX

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\alg_libs\sm_free3\sm_free3_asn.cpp
# End Source File
# Begin Source File

SOURCE=..\alg_libs\sm_rsa\sm_rsa_asn.cpp
# End Source File
# Begin Source File

SOURCE=..\alg_libs\sm_rsa\sm_tstdlib.c

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# ADD CPP /I "../alg_libs/sm_fortezza"

!ENDIF 

# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\testsrc\include\sm_CTILAppLogin.h
# End Source File
# Begin Source File

SOURCE=..\testsrc\include\sm_utilc.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Group "libs"

# PROP Default_Filter "*.lib"
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\libCert.lib

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\libCtilMgr.lib

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cmlasn_d.lib
# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\libCertd.lib
# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\libCtilMgrd.lib
# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cppasn1_d.lib
# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cmapi_d.lib
# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cmapi.lib

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\srlapi_d.lib
# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\srlapi.lib

!IF  "$(CFG)" == "autoAlg - Win32 Release"

!ELSEIF  "$(CFG)" == "autoAlg - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\alg_libs\sm_free3\sm_free3DLL___Win32_Debug_OpenSSL\sm_free3DLLOpenSSLd.lib
# End Source File
# End Group
# End Target
# End Project
