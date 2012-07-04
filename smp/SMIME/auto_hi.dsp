# Microsoft Developer Studio Project File - Name="auto_hi" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=AUTO_HI - WIN32 RELEASE
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "auto_hi.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "auto_hi.mak" CFG="AUTO_HI - WIN32 RELEASE"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "auto_hi - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "auto_hi - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "auto_hi"
# PROP Scc_LocalPath "."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "auto_hi - Win32 Release"

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
# ADD CPP /nologo /MD /W4 /GX /O2 /I "../cml/srl/inc" /I "../../SMPDist/include/esnacc/c++" /I "./testsrc/inc" /I "../cml/cmapi/inc" /I "./libCtilMgr/inc" /I "./inc" /I "../cml/cmlasn/inc" /I "../ACL/inc" /I "../SMP_Check" /I "../../SMPDist/include/pkcs11" /I "../pkcs11_cryptopp/inc" /D "_CONSOLE" /D "WIN32" /D "NDEBUG" /D "_MBCS" /FR /YX /FD /Zm300 /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 wsock32.lib /nologo /subsystem:console /machine:I386 /out:"./test/auto_hi.exe"

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "./obj/debug"
# PROP Intermediate_Dir "./obj/debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MDd /W4 /GX /Z7 /I "../cml/srl/inc" /I "../../SMPDist/include/esnacc/c++" /I "./testsrc/inc" /I "../cml/cmapi/inc" /I "./libCtilMgr/inc" /I "./inc" /I "../cml/cmlasn/inc" /I "../ACL/inc" /I "../SMP_Check" /I "../../SMPDist/include/pkcs11" /I "../pkcs11_cryptopp/inc" /D "_CONSOLE" /D "_DEBUG" /D "_MBCS" /D "WIN32" /FR /YX /FD /Zm300 /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 wsock32.lib /nologo /subsystem:console /debug /machine:I386 /out:"./test/auto_hid.exe"
# SUBTRACT LINK32 /profile

!ENDIF 

# Begin Target

# Name "auto_hi - Win32 Release"
# Name "auto_hi - Win32 Debug"
# Begin Group "libs"

# PROP Default_Filter "*.lib"
# Begin Source File

SOURCE=..\..\SMPDist\lib\srlapi.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\srlapi_d.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cmapi.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cmapi_d.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libCtilMgrd.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libCertd.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libCtilMgr.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libCert.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\acld.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\ACL.lib

!IF  "$(CFG)" == "auto_hi - Win32 Release"

!ELSEIF  "$(CFG)" == "auto_hi - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libsmd.lib
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libsmutild.lib
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\mimelibd.lib
# PROP Exclude_From_Build 1
# End Source File
# End Group
# Begin Source File

SOURCE=.\testsrc\hilevel\sm_Autohi.cpp
# ADD CPP /I "testutil/mimelib"
# End Source File
# End Target
# End Project
