# Microsoft Developer Studio Project File - Name="sm_rsaDLL" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=sm_rsaDLL - Win32 Debug Bsafe60
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sm_rsaDLL.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sm_rsaDLL.mak" CFG="sm_rsaDLL - Win32 Debug Bsafe60"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sm_rsaDLL - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sm_rsaDLL - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "sm_rsaDLL - Win32 Debug Bsafe60" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "sm_rsaDLL"
# PROP Scc_LocalPath "..\.."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_RSADLL_EXPORTS" /Yu"stdafx.h" /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../../../../SMPDist/Algs/bsafe60/library/include" /I "../sm_rsa" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../../cml/cmlasn/inc" /I "../../../../SMPDist/include/smp" /I "../../../../SMPDist/include/pkcs11" /D "_WINDOWS" /D "_USRDLL" /D "SM_RSADLL_EXPORTS" /D "SM_RSA_USED" /D "WIN32" /D "NDEBUG" /D "_MBCS" /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 ../../../../SMPDist/Algs/bsafe60/Library/lib/bsafe60.lib wsock32.lib /nologo /dll /machine:I386 /out:"../../../../SMPDist/lib/sm_rsaDLL.dll"
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetName=sm_rsaDLL
InputPath=\src\SMPDist\lib\sm_rsaDLL.dll
InputName=sm_rsaDLL
SOURCE="$(InputPath)"

"..\..\..\..\SMPDist\include\modules\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(InputName).dll $(windir)\system32 
	copy RELEASE\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SM_RSADLL_EXPORTS" /Yu"stdafx.h" /FD /GZ /c
# ADD CPP /nologo /MDd /W4 /GX /Z7 /Od /I "../../../../SMPDist/Algs/bsafe60/library/include" /I "../sm_rsa" /I "../lolevel" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../../SMPDist/include/esnacc/c++" /I "../../../cml/cmlasn/inc" /I "../../../../SMPDist/include/smp" /I "../../../../SMPDist/include/pkcs11" /D "_WINDOWS" /D "_USRDLL" /D "SM_RSADLL_EXPORTS" /D "BOOL_BUILTIN" /D USE_NIBBLE_MEMORY=0 /D "USE_GEN_BUF" /D "NO_SCCS_ID" /D "SM_RSA_USED" /D "_DEBUG" /D "_MBCS" /D "WIN32" /FR /FD /GZ /Zm200 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ../../../../SMPDist/Algs/bsafe60/Library/lib/bsafe60.lib wsock32.lib /nologo /dll /debug /machine:I386 /out:"../../../../SMPDist/lib/sm_rsaDLLd.dll" /pdbtype:sept
# SUBTRACT LINK32 /pdb:none
# Begin Custom Build
TargetName=sm_rsaDLLd
InputPath=\src\SMPDist\lib\sm_rsaDLLd.dll
InputName=sm_rsaDLLd
SOURCE="$(InputPath)"

"..\..\..\..\SMPDist\include\modules\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy ..\..\..\..\SMPDist\lib\$(InputName).dll $(windir)\system32 
	copy DEBUG\$(TargetName).lib ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "sm_rsaDLL___Win32_Debug_Bsafe60"
# PROP BASE Intermediate_Dir "sm_rsaDLL___Win32_Debug_Bsafe60"
# PROP BASE Ignore_Export_Lib 0
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "sm_rsaDLL___Win32_Debug_Bsafe60"
# PROP Intermediate_Dir "sm_rsaDLL___Win32_Debug_Bsafe60"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W4 /GX /Z7 /Od /I "../../../SMPDist/Algs/bsafe42/library/include" /I "../sm_rsa" /I "../../include" /I "../../libcert/include" /I "../../libCtilMgr/include" /I "../lolevel" /I "../../../SMPDist/util/VDASnacc/cpplib/inc" /I "../../include/cmapi" /I "../../../SMPDist/CML/include" /D "_WINDOWS" /D "_USRDLL" /D "SM_RSADLL_EXPORTS" /D "BOOL_BUILTIN" /D USE_NIBBLE_MEMORY=0 /D "USE_GEN_BUF" /D "NO_SCCS_ID" /D "SM_RSA_USED" /D "_DEBUG" /D "_MBCS" /D "WIN32" /FD /GZ /c
# SUBTRACT BASE CPP /YX /Yc /Yu
# ADD CPP /nologo /MDd /W4 /GX /Z7 /Od /I "../../../SMPDist/Algs/bsafe60/Include" /I "../../include" /I "../../libcert/include" /I "../../libCtilMgr/include" /I "../../../SMPDist/util/VDASnacc/cpplib/inc" /I "../../include/cmapi" /I "../../../SMPDist/CML/include" /I "../../../SMPDist/Algs/bsafe42/library/include" /I "../sm_rsa" /I "../lolevel" /I "../../inc/cmapi" /I "../../inc" /I "../../libCtilMgr/inc" /I "../../../SMPDist/esnacc/c++/inc" /I "../../../cml/cmlasn/inc" /D "_WINDOWS" /D "_USRDLL" /D "SM_RSADLL_EXPORTS" /D "BOOL_BUILTIN" /D USE_NIBBLE_MEMORY=0 /D "USE_GEN_BUF" /D "NO_SCCS_ID" /D "SM_RSA_USED" /D "_DEBUG" /D "_MBCS" /D "WIN32" /FD /GZ /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 ../../../SMPDist/Algs/bsafe42/Library/lib/bsafe42.lib ../../libCert/libCertDLL/Debug/libCertDLLd.lib wsock32.lib ../../../SMPDist/Cml/lib/cmlasn_d.lib ../../lib/libCtilMgrd.lib ../../../SMPDist/util/VDASnacc/cpplib/lib/snaccCpp_d.lib /nologo /dll /debug /machine:I386 /out:"../../test/sm_rsaDLLd.dll" /pdbtype:sept
# ADD LINK32 ../../../SMPDist/Algs/bsafe60/lib/intel_ia32/bsafe60.lib ../../libCert/libCertDLL/Debug/libCertDLLd.lib wsock32.lib ../../../SMPDist/Cml/lib/cmlasn_d.lib ../../lib/libCtilMgrd.lib ../../../SMPDist/util/VDASnacc/cpplib/lib/snaccCpp_d.lib /nologo /dll /debug /machine:I386 /out:"../../test/sm_rsaDLLd.dll" /pdbtype:sept

!ENDIF 

# Begin Target

# Name "sm_rsaDLL - Win32 Release"
# Name "sm_rsaDLL - Win32 Debug"
# Name "sm_rsaDLL - Win32 Debug Bsafe60"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\..\libsrc\asn1\sm_cms.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\lolevel\sm_CryptoKeysBase.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\sm_rsa\sm_CryptoKeysRsa.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=..\sm_rsa\sm_rsa.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=.\sm_rsa_asn.asn1

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# Begin Custom Build
InputPath=.\sm_rsa_asn.asn1
InputName=sm_rsa_asn

BuildCmds= \
	copy "$(InputPath)"  ..\..\..\..\SMPDist\include\Modules \
	..\..\..\..\SMPDist\bin\esnacc -a 600 -C $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# Begin Custom Build
InputPath=.\sm_rsa_asn.asn1
InputName=sm_rsa_asn

BuildCmds= \
	copy "$(InputPath)"  ..\..\..\..\SMPDist\include\Modules \
	..\..\..\..\SMPDist\bin\esnaccd -a 600 -C $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

# Begin Custom Build
IntDir=.\sm_rsaDLL___Win32_Debug_Bsafe60
InputPath=.\sm_rsa_asn.asn1
InputName=sm_rsa_asn

BuildCmds= \
	copy "$(InputPath)"  ..\..\..\..\SMPDist\include\Modules \
	copy "$(InputPath)" $(IntDir) \
	..\..\..\..\SMPDist\bin\esnaccd -a 600 -D -C $(InputName).asn1 \
	

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_rsa\sm_rsa_asn.cpp
# SUBTRACT CPP /YX /Yc /Yu
# End Source File
# Begin Source File

SOURCE=.\sm_rsaDLL.cpp
# End Source File
# Begin Source File

SOURCE=.\StdAfx.cpp

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# SUBTRACT CPP /YX /Yc

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# SUBTRACT CPP /YX /Yc

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

# ADD CPP /Yc"stdafx.h"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\Algs\Bsafe60\Library\Source\tstdlib.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\sm_rsa\sm_CryptoKeysRsa.h

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_rsa\sm_CryptoKeysRsa.h
InputName=sm_CryptoKeysRsa

"..\..\..\..\SMPDist\include\smp\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_rsa\sm_CryptoKeysRsa.h
InputName=sm_CryptoKeysRsa

"..\..\..\SMPDist\include\smp\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

# Begin Custom Build
InputPath=..\sm_rsa\sm_CryptoKeysRsa.h
InputName=sm_CryptoKeysRsa

"..\..\..\SMPDist\sfl\alg_libs\sm_rsa\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_rsa

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_rsa\sm_CryptoKeysRsaExport.h

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_rsa\sm_CryptoKeysRsaExport.h
InputName=sm_CryptoKeysRsaExport

"..\..\..\..\SMPDist\include\smp\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_rsa\sm_CryptoKeysRsaExport.h
InputName=sm_CryptoKeysRsaExport

"..\..\..\SMPDist\include\smp\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

# Begin Custom Build
InputPath=..\sm_rsa\sm_CryptoKeysRsaExport.h
InputName=sm_CryptoKeysRsaExport

"..\..\..\SMPDist\sfl\alg_libs\sm_rsa\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_rsa

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\sm_rsa\sm_rsa.h

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# Begin Custom Build
InputPath=..\sm_rsa\sm_rsa.h
InputName=sm_rsa

"..\..\..\..\SMPDist\include\smp\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# Begin Custom Build
InputPath=..\sm_rsa\sm_rsa.h
InputName=sm_rsa

"..\..\..\SMPDist\include\smp\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

# Begin Custom Build
InputPath=..\sm_rsa\sm_rsa.h
InputName=sm_rsa

"..\..\..\SMPDist\sfl\alg_libs\sm_rsa\$(InputName).asn" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) ..\..\..\SMPDist\sfl\alg_libs\sm_rsa

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\sm_rsaDLL.h
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

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCertd.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCert.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\libCtilMgrd.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmapi_d.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\..\SMPDist\lib\cmapi.lib

!IF  "$(CFG)" == "sm_rsaDLL - Win32 Release"

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "sm_rsaDLL - Win32 Debug Bsafe60"

!ENDIF 

# End Source File
# End Target
# End Project
