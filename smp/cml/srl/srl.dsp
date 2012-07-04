# Microsoft Developer Studio Project File - Name="srl" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=srl - Win32 Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "srl.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "srl.mak" CFG="srl - Win32 Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "srl - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "srl - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "srl"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "srl - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SRL_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W4 /GX /Od /I "inc" /I "..\cmapi\inc" /I "..\cmlasn\inc" /I "..\..\..\SMPDist\include\esnacc\c++" /I "..\..\..\SMPDist\util\ldap\windows\include" /I "..\..\pkcs11_cryptopp\inc" /D "NDEBUG" /D "SRL_EXPORTS" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "I386" /D "_USING_MS_LDAP" /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 shell32.lib ws2_32.lib /nologo /dll /profile /map /machine:I386 /out:"..\..\..\SMPDist\lib\srlapi.dll"
# Begin Custom Build - Copying DLL to system32 directory...
InputPath=\src\SMPDist\lib\srlapi.dll
InputName=srlapi
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ELSEIF  "$(CFG)" == "srl - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "SRL_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W4 /GX /Z7 /Od /I "inc" /I "..\cmapi\inc" /I "..\cmlasn\inc" /I "..\..\..\SMPDist\include\esnacc\c++" /I "..\..\..\SMPDist\util\ldap\windows\include" /I "..\..\pkcs11_cryptopp\inc" /D "_DEBUG" /D "SRL_EXPORTS" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "_USING_MS_LDAP" /FR /FD /GZ /Zm200 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo /o"Debug/srlapi.bsc"
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 shell32.lib ws2_32.lib /nologo /dll /profile /debug /machine:I386 /out:"..\..\..\SMPDist\lib\srlapi_d.dll"
# Begin Custom Build - Copying DLL to system32 directory...
InputPath=\src\SMPDist\lib\srlapi_d.dll
InputName=srlapi_d
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ENDIF 

# Begin Target

# Name "srl - Win32 Release"
# Name "srl - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\src\SRL_CRLRefresh.cpp
# End Source File
# Begin Source File

SOURCE=.\src\SRL_cvtdb.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_db.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_Free.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_ftp.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_http.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_ldap.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_Mgr.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_ReqOps.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_Socket.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_store.c
# End Source File
# Begin Source File

SOURCE=.\src\SRL_util.c
# End Source File
# Begin Source File

SOURCE=.\srlapi.rc
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\resource.h
# End Source File
# Begin Source File

SOURCE=.\inc\SRL_db.h
# End Source File
# Begin Source File

SOURCE=.\inc\SRL_http.h
# End Source File
# Begin Source File

SOURCE=.\inc\SRL_internal.h
# End Source File
# Begin Source File

SOURCE=.\inc\SRL_ldap.h

!IF  "$(CFG)" == "srl - Win32 Release"

# Begin Custom Build
InputPath=.\inc\SRL_ldap.h
InputName=SRL_ldap

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "srl - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
InputPath=.\inc\SRL_ldap.h
InputName=SRL_ldap

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\inc\srlapi.h

!IF  "$(CFG)" == "srl - Win32 Release"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
InputPath=.\inc\srlapi.h
InputName=srlapi

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\smp

# End Custom Build

!ELSEIF  "$(CFG)" == "srl - Win32 Debug"

# PROP Intermediate_Dir "..\..\..\SMPDist\include\smp"
# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to $(IntDir)
InputPath=.\inc\srlapi.h
InputName=srlapi

"..\..\..\SMPDist\include\smp\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\smp

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Libraries"

# PROP Default_Filter "*.lib"
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cmlasn_d.lib

!IF  "$(CFG)" == "srl - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "srl - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\..\..\SMPDist\lib\cmlasn.lib

!IF  "$(CFG)" == "srl - Win32 Release"

!ELSEIF  "$(CFG)" == "srl - Win32 Debug"

# PROP Exclude_From_Build 1

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
