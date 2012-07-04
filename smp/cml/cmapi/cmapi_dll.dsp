# Microsoft Developer Studio Project File - Name="cmapi_dll" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=CMAPI_DLL - WIN32 DEBUG
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "cmapi_dll.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "cmapi_dll.mak" CFG="CMAPI_DLL - WIN32 DEBUG"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cmapi_dll - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "cmapi_dll - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "cmapi_dll"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "cmapi_dll - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MD /W4 /GX /O2 /I "inc" /I "..\cmlasn\inc" /I "..\crlsrv_dll\inc" /I "..\..\..\SMPDist\include\esnacc\c++" /I "..\..\pkcs11_cryptopp\inc" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_USING_MS_LDAP" /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /o /win32 "NUL"
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib advapi32.lib shell32.lib crypt32.lib /nologo /subsystem:windows /dll /profile /map /machine:I386 /out:"..\..\..\SMPDist\lib/cmapi.dll"
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\src\SMPDist\lib\cmapi.dll
InputName=cmapi
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ELSEIF  "$(CFG)" == "cmapi_dll - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /Zi /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MDd /W4 /GX /Z7 /Od /I "inc" /I "..\cmlasn\inc" /I "..\crlsrv_dll\inc" /I "..\..\..\SMPDist\include\esnacc\c++" /I "..\..\pkcs11_cryptopp\inc" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_USING_MS_LDAP" /FR /FD /Zm200 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /o /win32 "NUL"
# ADD MTL /nologo /D "_DEBUG" /Oicf /o /win32 "NUL"
# SUBTRACT MTL /mktyplib203
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo /o"Debug/cmapi_dll.bsc"
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /subsystem:windows /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib advapi32.lib shell32.lib crypt32.lib /nologo /subsystem:windows /dll /profile /debug /machine:I386 /out:"..\..\..\SMPDist\lib/cmapi_d.dll"
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\src\SMPDist\lib\cmapi_d.dll
InputName=cmapi_d
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ENDIF 

# Begin Target

# Name "cmapi_dll - Win32 Release"
# Name "cmapi_dll - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "c;cpp"
# Begin Source File

SOURCE=.\src\CM_cache.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_CAPI.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_Certificate.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_CertPath.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_certPolicies.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_CRL.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_Free.c
# End Source File
# Begin Source File

SOURCE=.\src\CM_infc.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_Mgr.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_PrintXML.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_ReqOps.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_RetrieveKey.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_Signature.cpp
# End Source File
# Begin Source File

SOURCE=.\src\CM_srl.cpp
# ADD CPP /I "..\srl\inc"
# End Source File
# Begin Source File

SOURCE=.\src\cmapi.rc
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h"
# Begin Source File

SOURCE=.\inc\CM_cache.h
# End Source File
# Begin Source File

SOURCE=.\inc\CM_internal.h
# End Source File
# Begin Source File

SOURCE=.\inc\cmapi.h

!IF  "$(CFG)" == "cmapi_dll - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmapi.h
InputName=cmapi

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmapi_dll - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmapi.h
InputName=cmapi

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\cmapi_cpp.h

!IF  "$(CFG)" == "cmapi_dll - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmapi_cpp.h
InputName=cmapi_cpp

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmapi_dll - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmapi_cpp.h
InputName=cmapi_cpp

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\cmapiCallbacks.h

!IF  "$(CFG)" == "cmapi_dll - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmapiCallbacks.h
InputName=cmapiCallbacks

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ELSEIF  "$(CFG)" == "cmapi_dll - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
IntDir=.\..\..\..\SMPDist\include\smp
InputPath=.\inc\cmapiCallbacks.h
InputName=cmapiCallbacks

"$(IntDir)\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" $(IntDir)

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\PathBuild.h
# End Source File
# Begin Source File

SOURCE=.\src\resource.h
# End Source File
# End Group
# Begin Group "Library Files"

# PROP Default_Filter "lib"
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "cmapi_dll - Win32 Release"

!ELSEIF  "$(CFG)" == "cmapi_dll - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cppasn1.lib

!IF  "$(CFG)" == "cmapi_dll - Win32 Release"

!ELSEIF  "$(CFG)" == "cmapi_dll - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "cmapi_dll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "cmapi_dll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cppasn1_d.lib

!IF  "$(CFG)" == "cmapi_dll - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "cmapi_dll - Win32 Debug"

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
