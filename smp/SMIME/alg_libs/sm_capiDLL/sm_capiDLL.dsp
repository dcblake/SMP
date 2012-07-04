# Microsoft Developer Studio Project File - Name="sm_capiDLL" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=sm_capiDLL - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sm_capiDLL.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sm_capiDLL.mak" CFG="sm_capiDLL - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sm_capiDLL - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sm_capiDLL - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "sm_capiDLL"
# PROP Scc_LocalPath "..\.."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_CAPIDLL_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../sm_free3" /I "../../inc/cmapi" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../../cml/cmlasn/inc" /I "../../../cml/cmapi/inc" /I "../../../pkcs11_cryptopp/inc" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_CAPIDLL_EXPORTS" /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 Crypt32.Lib Advapi32.lib wsock32.lib /nologo /dll /machine:I386 /out:"../../../../SMPDist/lib/sm_capiDLL.dll"
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetName=sm_capiDLL
InputPath=\devel.d\vda_snacc.d\devel.cur\SMPDist\lib\sm_capiDLL.dll
InputName=sm_capiDLL
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(InputName).dll $(windir)\system32 
	copy RELEASE\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_CAPIDLL_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "../sm_free3" /I "../../inc/cmapi" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../../cml/cmlasn/inc" /I "../../../cml/cmapi/inc" /I "../../../pkcs11_cryptopp/inc" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_CAPIDLL_EXPORTS" /FR /FD /Zm200 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 Crypt32.Lib Advapi32.lib wsock32.lib /nologo /dll /debug /machine:I386 /out:"../../../../SMPDist/lib/sm_capiDLLd.dll" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetName=sm_capiDLLd
InputPath=\devel.d\vda_snacc.d\devel.cur\SMPDist\lib\sm_capiDLLd.dll
InputName=sm_capiDLLd
SOURCE="$(InputPath)"

"$(windir)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(InputName).dll $(windir)\system32 
	copy DEBUG\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ENDIF 

# Begin Target

# Name "sm_capiDLL - Win32 Release"
# Name "sm_capiDLL - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\sm_capi.cpp

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

# SUBTRACT CPP /YX /Yc /Yu

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_capiDLL.cpp
# End Source File
# Begin Source File

SOURCE=.\sm_capiInternal.cpp
# End Source File
# Begin Source File

SOURCE=..\..\libsrc\asn1\sm_cms.cpp

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

# SUBTRACT CPP /YX /Yc /Yu

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_free3_asn.asn1

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_FR="..\..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
InputDir=\devel.d\vda_snacc.d\devel.cur\smp\SMIME\alg_libs\sm_free3
InputPath=..\sm_free3\sm_free3_asn.asn1
InputName=sm_free3_asn

BuildCmds= \
	cd $(InputDir) \
	..\..\..\..\SMPDist\bin\esnacc -C -I ../../libcert/asn1 -I ../../libsrc/asn1 -I ../../libCtilMgr/src  -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SM_FR="..\..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputPath)
InputDir=\devel.d\vda_snacc.d\devel.cur\smp\SMIME\alg_libs\sm_free3
InputPath=..\sm_free3\sm_free3_asn.asn1
InputName=sm_free3_asn

BuildCmds= \
	copy "$(InputPath)"  ..\..\..\..\SMPDist\include\Modules \
	cd $(InputDir) \
	..\..\..\..\SMPDist\bin\esnaccd -C -I ../../libcert/asn1 -I ../../libsrc/asn1 -I ../../libCtilMgr/src  -I ..\..\..\cml\cmlasn\modules $(InputName).asn1 $(InputName).asn1 \
	

"$(InputDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputDir)\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_free3\sm_free3_asn.cpp
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp
# ADD CPP /Yc"stdafx.h"
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\Sm_capi.h

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

# Begin Custom Build
InputPath=.\Sm_capi.h
InputName=Sm_capi

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

# Begin Custom Build
InputPath=.\Sm_capi.h
InputName=Sm_capi

"..\..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_capiDLL.h
# End Source File
# Begin Source File

SOURCE=.\StdAfx.h
# End Source File
# Begin Source File

SOURCE=.\WincryptRWC.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\ReadMe.txt
# End Source File
# Begin Source File

SOURCE=.\ReadmeDevel.txt
# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgrd.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCert.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCertd.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgr.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmapi.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmapi_d.lib

!IF  "$(CFG)" == "sm_capiDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_capiDLL - Win32 Debug"

!ENDIF 

# End Source File
# End Target
# End Project
