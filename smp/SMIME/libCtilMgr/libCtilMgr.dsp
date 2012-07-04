# Microsoft Developer Studio Project File - Name="libCtilMgr" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=libCtilMgr - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "libCtilMgr.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "libCtilMgr.mak" CFG="libCtilMgr - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "libCtilMgr - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "libCtilMgr - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "libCtilMgr"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "..\..\..\SMPDist\lib"
# PROP Intermediate_Dir "Release"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBCTILMGR_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "./inc" /I "./AES" /I "../../../SMPDist/include/esnacc/c++" /D "LIBCTILMGRDLL_EXPORTS" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "VDASNACCDLL_API_EXPORTS" /FA /FD /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 /nologo /dll /pdb:none /map /machine:I386
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\devel.d\vda_snacc.d\devel.cur\SMPDist\lib\libCtilMgr.dll
InputName=libCtilMgr
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\..\SMPDist\lib"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBCTILMGR_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "./inc" /I "../../../SMPDist/include/esnacc/c++" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "LIBCTILMGRDLL_EXPORTS" /D "VDASNACCDLL_API_EXPORTS" /FR /FD /GZ /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 /nologo /dll /pdb:none /debug /machine:I386 /out:"..\..\..\SMPDist\lib/libCtilMgrd.dll"
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\devel.d\vda_snacc.d\devel.cur\SMPDist\lib\libCtilMgrd.dll
InputName=libCtilMgrd
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ENDIF 

# Begin Target

# Name "libCtilMgr - Win32 Release"
# Name "libCtilMgr - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\src\fortezza.cpp
# End Source File
# Begin Source File

SOURCE=.\libCtilMgr.cpp
# End Source File
# Begin Source File

SOURCE=.\src\sha256ref.c
# End Source File
# Begin Source File

SOURCE=.\src\sm_Alg.cpp
# End Source File
# Begin Source File

SOURCE=.\src\sm_BaseTokenInterface.cpp

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# ADD CPP /Od

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\sm_buffer.cpp
# End Source File
# Begin Source File

SOURCE=.\src\sm_common.cpp
# End Source File
# Begin Source File

SOURCE=.\src\sm_CtilInst.cpp
# End Source File
# Begin Source File

SOURCE=.\src\sm_CtilMgr.cpp
# End Source File
# Begin Source File

SOURCE=.\src\sm_CTthreads.cpp
# End Source File
# Begin Source File

SOURCE=.\src\sm_DLLInterface.cpp
# End Source File
# Begin Source File

SOURCE=.\src\sm_usefulTypes.asn1

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_US="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling $(InputPath)
InputDir=.\src
InputPath=.\src\sm_usefulTypes.asn1
InputName=sm_usefulTypes

BuildCmds= \
	type $(InputPath)  > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd $(InputDir) \
	attrib -r $(InputName).cpp \
	attrib -r ..\inc\$(InputName).h \
	..\..\..\..\SMPDist\bin\esnacc -VDAexport -C -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_US="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling $(InputPath)
InputDir=.\src
InputPath=.\src\sm_usefulTypes.asn1
InputName=sm_usefulTypes

BuildCmds= \
	type $(InputPath)  > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd $(InputDir) \
	attrib -r $(InputName).cpp \
	attrib -r ..\inc\$(InputName).h \
	..\..\..\..\SMPDist\bin\esnaccd -VDAexport -C -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\sm_usefulTypes.cpp
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\inc\fortezzaVDA.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\fortezzaVDA.h
InputName=fortezzaVDA

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\fortezzaVDA.h
InputName=fortezzaVDA

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sha256.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sha256.h
InputName=sha256

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sha256.h
InputName=sha256

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_apicCtilMgr.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_apicCtilMgr.h
InputName=sm_apicCtilMgr

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_apicCtilMgr.h
InputName=sm_apicCtilMgr

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_apiCtilMgr.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_apiCtilMgr.h
InputName=sm_apiCtilMgr

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_apiCtilMgr.h
InputName=sm_apiCtilMgr

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_buffer.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_buffer.h
InputName=sm_buffer

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_buffer.h
InputName=sm_buffer

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_common.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_common.h
InputName=sm_common

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_common.h
InputName=sm_common

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_DLLInterface.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_DLLInterface.h
InputName=sm_DLLInterface

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_DLLInterface.h
InputName=sm_DLLInterface

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_usefulTypes.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_usefulTypes.h
InputName=sm_usefulTypes

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_usefulTypes.h
InputName=sm_usefulTypes

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\sm_vdasnaccMgr.h

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# Begin Custom Build
InputPath=.\inc\sm_vdasnaccMgr.h
InputName=sm_vdasnaccMgr

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# Begin Custom Build
InputPath=.\inc\sm_vdasnaccMgr.h
InputName=sm_vdasnaccMgr

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "libCtilMgr - Win32 Release"

!ELSEIF  "$(CFG)" == "libCtilMgr - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# End Target
# End Project
