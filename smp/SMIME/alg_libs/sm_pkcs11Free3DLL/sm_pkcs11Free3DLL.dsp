# Microsoft Developer Studio Project File - Name="sm_pkcs11Free3DLL" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=sm_pkcs11Free3DLL - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sm_pkcs11Free3DLL.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sm_pkcs11Free3DLL.mak" CFG="sm_pkcs11Free3DLL - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sm_pkcs11Free3DLL - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sm_pkcs11Free3DLL - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "sm_pkcs11Free3DLL"
# PROP Scc_LocalPath "..\.."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_PKCS11FREE3DLL_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "./" /I "../../../../SMPDist/Algs/crypto++" /I "../sm_fort" /I "../sm_pkcs11" /I "../sm_free3" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../../cml/cmlasn/inc" /I "../../../../SMPDist/include/smp" /I "../../../../SMPDist/sfl/alg_libs/sm_pkcs11" /I "../../../../SMPDist/include/pkcs11" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_PKCS11FREE3DLL_EXPORTS" /D "SM_FREE3DLL_EXPORTS" /D "SM_FREE3_USED" /D "SFLPKCS12_ENABLED" /D "SM_FREE3_RSA_INCLUDED" /FD /Zm300 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 ../../../../SMPDist/lib/cryptlib.lib ../sm_free3/Release/sm_free3DLL.lib ../sm_pkcs11/Release/sm_pkcs11DLL.lib wsock32.lib /nologo /dll /machine:I386 /out:"../../../SMPDist/sfl/alg_libs/sm_pkcs11/sm_pkcs11Free3DLL.dll"
# Begin Custom Build
TargetName=sm_pkcs11Free3DLL
InputPath=\src\smp\SMPDist\sfl\alg_libs\sm_pkcs11\sm_pkcs11Free3DLL.dll
InputName=sm_pkcs11Free3DLL
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(InputName).dll $(windir)\system32 
	copy DEBUG\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_PKCS11FREE3DLL_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "./" /I "../../../../SMPDist/Algs/crypto++" /I "../sm_fort" /I "../sm_pkcs11" /I "../sm_free3" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../../cml/cmlasn/inc" /I "../../../../SMPDist/include/smp" /I "../../../../SMPDist/include/pkcs11" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_PKCS11FREE3DLL_EXPORTS" /D "WIN32" /D "PKCS11_PRINT" /D "SM_FREE3DLL_EXPORTS" /D "SM_FREE3_USED" /D "SFLPKCS12_ENABLED" /D "SM_FREE3_RSA_INCLUDED" /FR /FD /GZ /Zm300 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ../../../../SMPDist/lib/cryptlib_d.lib ../sm_free3/Debug/sm_free3DLLd.lib ../sm_pkcs11/Debug/sm_pkcs11DLLd.lib wsock32.lib /nologo /dll /debug /machine:I386 /out:"../../../SMPDist/sfl/alg_libs/sm_pkcs11/sm_pkcs11Free3DLLd.dll" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetName=sm_pkcs11Free3DLLd
InputPath=\src\smp\SMPDist\sfl\alg_libs\sm_pkcs11\sm_pkcs11Free3DLLd.dll
InputName=sm_pkcs11Free3DLLd
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(InputName).dll $(windir)\system32 
	copy DEBUG\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ENDIF 

# Begin Target

# Name "sm_pkcs11Free3DLL - Win32 Release"
# Name "sm_pkcs11Free3DLL - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\sm_pkcs11Free3\sm_pkcs11Free3.cpp
# End Source File
# Begin Source File

SOURCE=.\sm_pkcs11Free3DLL.cpp
# End Source File
# Begin Source File

SOURCE=..\sm_pkcs11Free3\sm_pkcs11Template.cpp
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\sm_pkcs11\pkcs11.h

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_pkcs11\pkcs11.h
InputName=pkcs11

"..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_pkcs11\pkcs11.h
InputName=pkcs11

"..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_pkcs11\pkcs11f.h

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_pkcs11\pkcs11f.h
InputName=pkcs11f

"..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_pkcs11\pkcs11f.h
InputName=pkcs11f

"..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_pkcs11\pkcs11t.h

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_pkcs11\pkcs11t.h
InputName=pkcs11t

"..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_pkcs11\pkcs11t.h
InputName=pkcs11t

"..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_pkcs11\sm_pkcs11.h

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_pkcs11\sm_pkcs11.h
InputName=sm_pkcs11

"..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_pkcs11\sm_pkcs11.h
InputName=sm_pkcs11

"..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_pkcs11Free3\sm_pkcs11Free3.h

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_pkcs11Free3\sm_pkcs11Free3.h
InputName=sm_pkcs11Free3

"..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_pkcs11Free3\sm_pkcs11Free3.h
InputName=sm_pkcs11Free3

"..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_pkcs11Free3DLL.h

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# Begin Custom Build
InputPath=.\sm_pkcs11Free3DLL.h
InputName=sm_pkcs11Free3DLL

"..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# Begin Custom Build
InputPath=.\sm_pkcs11Free3DLL.h
InputName=sm_pkcs11Free3DLL

"..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\StdAfx.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Group "libs"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgr.lib

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCertd.lib

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCert.lib

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgrd.lib

!IF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_pkcs11Free3DLL - Win32 Debug"

!ENDIF 

# End Source File
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# End Target
# End Project
