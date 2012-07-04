# Microsoft Developer Studio Project File - Name="cmlasn" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=CMLASN - WIN32 DEBUG
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "cmlasn.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "cmlasn.mak" CFG="CMLASN - WIN32 DEBUG"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cmlasn - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "cmlasn - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "cmlasn"
# PROP Scc_LocalPath "..\.."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "cmlasn - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CPPASN_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W4 /GX /O2 /I "inc" /I "..\..\..\SMPDist\include\esnacc\c++" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "EXPORT_GENSNACC_EXPORTS" /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /pdb:none /map /machine:I386
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\src\SMPDist\lib\cmlasn.dll
InputName=cmlasn
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CPPASN_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W4 /GX /Z7 /Od /I "inc" /I "..\..\..\SMPDist\include\esnacc\c++" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "EXPORT_GENSNACC_EXPORTS" /FR /FD /GZ /Zm200 /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo /o"Debug/cmlasn.bsc"
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /profile /debug /machine:I386 /out:"..\..\..\SMPDist\lib/cmlasn_d.dll"
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\src\SMPDist\lib\cmlasn_d.dll
InputName=cmlasn_d
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ENDIF 

# Begin Target

# Name "cmlasn - Win32 Release"
# Name "cmlasn - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat;y;l"
# Begin Source File

SOURCE=.\src\AttributeCertificateDefinitions.cpp
# End Source File
# Begin Source File

SOURCE=.\src\AuthenticationFramework.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\CertificateExtensions.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\CM_AttribCert.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_Certificate.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_CertPath.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_CRL.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_Extensions.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_Free.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_GeneralNames.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_globals.c
# End Source File
# Begin Source File

SOURCE=.\src\cmlasn.rc
# End Source File
# Begin Source File

SOURCE=.\src\CommonBytes.cpp
# End Source File
# Begin Source File

SOURCE=.\src\EnhancedSecurity.cpp
# End Source File
# Begin Source File

SOURCE=.\src\Exception.cpp
# End Source File
# Begin Source File

SOURCE=.\src\InformationFramework.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\ORAddress.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\PKIX.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\sdn702.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\SelectedAttributeTypes.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\UpperBounds.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\UsefulDefinitions.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\X509Common.cpp

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# ADD CPP /D "USE_EXP_BUF"

!ENDIF 

# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\inc\AttributeCertificateDefinitions.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\AttributeCertificateDefinitions.h
InputName=AttributeCertificateDefinitions

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\AttributeCertificateDefinitions.h
InputName=AttributeCertificateDefinitions

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\AuthenticationFramework.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\AuthenticationFramework.h
InputName=AuthenticationFramework

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\AuthenticationFramework.h
InputName=AuthenticationFramework

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\CertificateExtensions.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\CertificateExtensions.h
InputName=CertificateExtensions

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\CertificateExtensions.h
InputName=CertificateExtensions

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\cmlasn.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn.h
InputName=cmlasn

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn.h
InputName=cmlasn

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\cmlasn_c.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_c.h
InputName=cmlasn_c

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_c.h
InputName=cmlasn_c

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\cmlasn_exts.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_exts.h
InputName=cmlasn_exts

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_exts.h
InputName=cmlasn_exts

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\cmlasn_general.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_general.h
InputName=cmlasn_general

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_general.h
InputName=cmlasn_general

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\cmlasn_internal.h
# End Source File
# Begin Source File

SOURCE=.\inc\cmlasn_name.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_name.h
InputName=cmlasn_name

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_name.h
InputName=cmlasn_name

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\cmlasn_threads.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_threads.h
InputName=cmlasn_threads

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmlasn_threads.h
InputName=cmlasn_threads

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\CommonBytes.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# Begin Custom Build
InputPath=.\inc\CommonBytes.h
InputName=CommonBytes

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)"  ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# Begin Custom Build - Copying $(InputName).h to $(IntDir)
InputPath=.\inc\CommonBytes.h
InputName=CommonBytes

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)"  ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\EnhancedSecurity.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\EnhancedSecurity.h
InputName=EnhancedSecurity

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\EnhancedSecurity.h
InputName=EnhancedSecurity

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\InformationFramework.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\InformationFramework.h
InputName=InformationFramework

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\InformationFramework.h
InputName=InformationFramework

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\ORAddress.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\ORAddress.h
InputName=ORAddress

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\ORAddress.h
InputName=ORAddress

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\PKIX.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\PKIX.h
InputName=PKIX

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\PKIX.h
InputName=PKIX

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\resource.h
# End Source File
# Begin Source File

SOURCE=.\inc\sdn702.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\sdn702.h
InputName=sdn702

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\sdn702.h
InputName=sdn702

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\SelectedAttributeTypes.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\SelectedAttributeTypes.h
InputName=SelectedAttributeTypes

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\SelectedAttributeTypes.h
InputName=SelectedAttributeTypes

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\UpperBounds.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\UpperBounds.h
InputName=UpperBounds

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\UpperBounds.h
InputName=UpperBounds

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\UsefulDefinitions.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\UsefulDefinitions.h
InputName=UsefulDefinitions

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\UsefulDefinitions.h
InputName=UsefulDefinitions

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\X509Common.h

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\X509Common.h
InputName=X509Common

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\X509Common.h
InputName=X509Common

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Modules"

# PROP Default_Filter ".asn1"
# Begin Source File

SOURCE=.\Modules\AttributeCertificateDefinitions.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__ATTRI="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\AttributeCertificateDefinitions.asn1
InputName=AttributeCertificateDefinitions

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__ATTRI="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\AttributeCertificateDefinitions.asn1
InputName=AttributeCertificateDefinitions

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -a 900  -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\AuthenticationFramework.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__AUTHE="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\AuthenticationFramework.asn1
InputName=AuthenticationFramework

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__AUTHE="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\AuthenticationFramework.asn1
InputName=AuthenticationFramework

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\CertificateExtensions.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__CERTI="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\CertificateExtensions.asn1
InputName=CertificateExtensions

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -a 100 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__CERTI="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\CertificateExtensions.asn1
InputName=CertificateExtensions

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -a 100 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\EnhancedSecurity.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__ENHAN="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\EnhancedSecurity.asn1
InputName=EnhancedSecurity

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -a 200 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__ENHAN="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\EnhancedSecurity.asn1
InputName=EnhancedSecurity

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -a 200 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\InformationFramework.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__INFOR="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\InformationFramework.asn1
InputName=InformationFramework

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -a 300 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__INFOR="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\InformationFramework.asn1
InputName=InformationFramework

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -a 300 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\ORAddress.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__ORADD="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\ORAddress.asn1
InputName=ORAddress

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -a 400 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__ORADD="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\ORAddress.asn1
InputName=ORAddress

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -a 400 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\PKIX.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__PKIX_="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\PKIX.asn1
InputName=PKIX

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -a 500 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__PKIX_="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\PKIX.asn1
InputName=PKIX

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -a 500 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\sdn702.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SDN70="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\sdn702.asn1
InputName=sdn702

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -a 600 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SDN70="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\sdn702.asn1
InputName=sdn702

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -a 600 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\SelectedAttributeTypes.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SELEC="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\SelectedAttributeTypes.asn1
InputName=SelectedAttributeTypes

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -a 700 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__SELEC="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\SelectedAttributeTypes.asn1
InputName=SelectedAttributeTypes

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -a 700 -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\UpperBounds.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__UPPER="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\UpperBounds.asn1
InputName=UpperBounds

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__UPPER="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\UpperBounds.asn1
InputName=UpperBounds

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\UsefulDefinitions.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__USEFU="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\UsefulDefinitions.asn1
InputName=UsefulDefinitions

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__USEFU="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\UsefulDefinitions.asn1
InputName=UsefulDefinitions

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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

SOURCE=.\Modules\X509Common.asn1

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__X509C="..\..\..\SMPDist\bin\esnacc.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\X509Common.asn1
InputName=X509Common

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnacc.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
	move $(InputName).h ..\inc \
	

"src\$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"inc\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"..\..\..\SMPDist\include\Modules\$(InputName).asn1" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\modules"
# PROP Ignore_Default_Tool 1
USERDEP__X509C="..\..\..\SMPDist\bin\esnaccd.exe"	
# Begin Custom Build - Compiling ASN.1 module:  $(InputName).asn1
InputPath=.\Modules\X509Common.asn1
InputName=X509Common

BuildCmds= \
	type $(InputPath) > ..\..\..\SMPDist\include\Modules\$(InputName).asn1 \
	cd Modules \
	..\..\..\..\SMPDist\bin\esnaccd.exe -C -I . -VDAexport=EXPORT_GENSNACC -l -1000 $(InputName).asn1 \
	move $(InputName).cpp ..\src \
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
# End Group
# Begin Group "Library Files"

# PROP Default_Filter "lib"
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "cmlasn - Win32 Release"

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "cmlasn - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "cmlasn - Win32 Debug"

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
