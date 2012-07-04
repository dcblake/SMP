# Microsoft Developer Studio Project File - Name="SMP_Check" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Console Application" 0x0103

CFG=SMP_Check - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "SMP_Check.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "SMP_Check.mak" CFG="SMP_Check - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "SMP_Check - Win32 Release" (based on "Win32 (x86) Console Application")
!MESSAGE "SMP_Check - Win32 Debug" (based on "Win32 (x86) Console Application")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "SMP_Check"
# PROP Scc_LocalPath ".."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

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
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../acl/inc" /I "../SMIME/mimelib" /I "../../SMPDist/include/eSNACC/c++" /I "../SMIME/inc" /I "../SMIME/libCtilMgr/inc" /I "../cml/cmlasn/inc" /I "../cml/srl/inc" /I "../cml/cmapi/inc" /I "../pkcs11_cryptopp/inc" /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_MBCS" /YX /FD /Zm300 /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /machine:I386

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

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
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "../acl/inc" /I "../SMIME/mimelib" /I "../../SMPDist/include/eSNACC/c++" /I "../SMIME/inc" /I "../SMIME/libCtilMgr/inc" /I "../cml/cmlasn/inc" /I "../cml/srl/inc" /I "../cml/cmapi/inc" /I "../pkcs11_cryptopp/inc" /D "WIN32" /D "_DEBUG" /D "_CONSOLE" /D "_MBCS" /FR /YX /FD /GZ /Zm300 /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:console /debug /machine:I386 /pdbtype:sept

!ENDIF 

# Begin Target

# Name "SMP_Check - Win32 Release"
# Name "SMP_Check - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\sm_checkCreate.cpp

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# ADD CPP /FR

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_checkRead.cpp

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# ADD CPP /FR

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_CM_AC_Support.cpp
# End Source File
# Begin Source File

SOURCE=.\SMP_Check.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\SMIME\inc\sm_AC_Interface.h
# End Source File
# Begin Source File

SOURCE=.\sm_CM_AC_Support.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Group "libs"

# PROP Default_Filter "*.lib"
# Begin Source File

SOURCE=..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libCert.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libCtilMgr.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libCertd.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libCtilMgrd.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cmapi_d.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\cmapi.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\srlapi_d.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\srlapi.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libsmd.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\libsm.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\acld.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\lib\ACL.lib

!IF  "$(CFG)" == "SMP_Check - Win32 Release"

!ELSEIF  "$(CFG)" == "SMP_Check - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
