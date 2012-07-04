# Microsoft Developer Studio Project File - Name="sm_fortezzaDLL" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=sm_fortezzaDLL - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sm_fortezzaDLL.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sm_fortezzaDLL.mak" CFG="sm_fortezzaDLL - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sm_fortezzaDLL - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sm_fortezzaDLL - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "sm_fortezzaDLL"
# PROP Scc_LocalPath "..\.."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FORTEZZADLL_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "./" /I "../../../../SMPDist/Algs/Fortezza" /I "../../../../SMPDist/include/smp" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../../cml/cmlasn/inc" /I "../../../../SMPDist/include/pkcs11" /D "_WINDOWS" /D "_USRDLL" /D "SM_FORTEZZADLL_EXPORTS" /D "WIN32" /D "NDEBUG" /D "_MBCS" /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 ../../../../SMPDist/algs/fortezza/TSSP32.lib wsock32.lib /nologo /dll /machine:I386 /out:"../../../../SMPDist/lib/sm_fortDLL.dll"
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetName=sm_fortDLL
InputPath=\src\SMPDist\lib\sm_fortDLL.dll
InputName=sm_fortDLL
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(InputName).dll $(windir)\system32 
	copy RELEASE\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_FORTEZZADLL_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W4 /GX /Z7 /Od /I "./" /I "../../../../SMPDist/Algs/Fortezza" /I "../../../../SMPDist\include\smp" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../../cml/cmlasn/inc" /I "../../../../SMPDist/include/smp" /I "../../../../SMPDist/include/pkcs11" /D "_WINDOWS" /D "_USRDLL" /D "SM_FORTEZZADLL_EXPORTS" /D "_DEBUG" /D "_MBCS" /D "WIN32" /FR /FD /GZ /Zm200 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ../../../../SMPDist/algs/fortezza/TSSP32.lib wsock32.lib /nologo /dll /debug /machine:I386 /out:"../../../../SMPDist/lib/sm_fortDLLd.dll" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetName=sm_fortDLLd
InputPath=\src\SMPDist\lib\sm_fortDLLd.dll
InputName=sm_fortDLLd
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(InputName).dll $(windir)\system32 
	copy DEBUG\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ENDIF 

# Begin Target

# Name "sm_fortezzaDLL - Win32 Release"
# Name "sm_fortezzaDLL - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\sm_fort\sm_fort.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortAsn.asn1

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

# Begin Custom Build
IntDir=.\Release
InputPath=..\sm_fort\sm_fortAsn.asn1
InputName=sm_fortAsn

BuildCmds= \
	copy "$(InputPath)"  ..\..\..\..\SMPDist\include\Modules \
	copy "$(InputPath)" $(IntDir) \
	..\..\..\..\SMPDist\bin\esnacc -C -I ../../libcert/asn1 -I ../../libsrc/asn1 -I ../../libCtilMgr/src -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

# Begin Custom Build
IntDir=.\Debug
InputPath=..\sm_fort\sm_fortAsn.asn1
InputName=sm_fortAsn

BuildCmds= \
	copy "$(InputPath)"  ..\..\..\..\SMPDist\include\Modules \
	copy "$(InputPath)" $(IntDir) \
	..\..\..\..\SMPDist\bin\esnaccd -C -I ../../libcert/asn1 -I ../../libsrc/asn1 -I ../../libCtilMgr/src -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortAsn.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortCI.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortDsaParams.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortDsaSigvalue.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=.\sm_fortezzaDLL.cpp
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE="..\..\..\SMPDist\util\VDASnacc\cpplib\inc\asn-incl.h"
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fort.h

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_fort\sm_fort.h
InputName=sm_fort

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_fort\sm_fort.h
InputName=sm_fort

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortAsn.h

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_fort\sm_fortAsn.h
InputName=sm_fortAsn

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_fort\sm_fortAsn.h
InputName=sm_fortAsn

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_fortezzaDLL.h
# End Source File
# Begin Source File

SOURCE=.\StdAfx.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgr.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCertd.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCert.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmapi_d.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmapi.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgrd.lib

!IF  "$(CFG)" == "sm_fortezzaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_fortezzaDLL - Win32 Debug"

!ENDIF 

# End Source File
# End Target
# End Project
