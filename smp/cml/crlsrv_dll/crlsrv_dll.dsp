# Microsoft Developer Studio Project File - Name="crlsrv_dll" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=crlsrv_dll - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "crlsrv_dll.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "crlsrv_dll.mak" CFG="crlsrv_dll - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "crlsrv_dll - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "crlsrv_dll - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "smp/cml/crlsrv_dll"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "crlsrv_dll - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CRLSRV_DLL_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MT /W4 /GX /Z7 /Od /I "inc" /I "..\cmapi\inc" /I "..\cmlasn\inc" /I "..\srl\inc" /I "..\..\..\SMPDist\include\esnacc\c++" /I "..\..\pkcs11_cryptopp\inc" /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CRLSRV_DLL_EXPORTS" /D "_USING_MS_LDAP" /FD /Zm200 /c
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386 /out:"..\..\..\SMPDist\lib/crlapi.dll"
# Begin Custom Build
InputPath=\src\SMPDist\lib\crlapi.dll
InputName=crlapi
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ELSEIF  "$(CFG)" == "crlsrv_dll - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "crlsrv_dll___Win32_Debug"
# PROP BASE Intermediate_Dir "crlsrv_dll___Win32_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "..\..\..\SMPDist\lib"
# PROP Intermediate_Dir "Debug"
# PROP Ignore_Export_Lib 0
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CRLSRV_DLL_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W4 /GX /Z7 /Od /I "inc" /I "..\cmapi\inc" /I "..\cmlasn\inc" /I "..\srl\inc" /I "..\..\..\SMPDist\include\esnacc\c++" /I "..\..\pkcs11_cryptopp\inc" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "CRLSRV_DLL_EXPORTS" /D "_USING_MS_LDAP" /FR /FD /GZ /Zm200 /c
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /Oicf /o /win32 "NUL"
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /fo"Debug/crlsrv.res" /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo /o"Debug/crlsrv_dll.bsc"
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib ws2_32.lib /nologo /dll /profile /debug /machine:I386 /out:"..\..\..\SMPDist\lib/crlapi_d.dll"
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\src\SMPDist\lib\crlapi_d.dll
InputName=crlapi_d
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ENDIF 

# Begin Target

# Name "crlsrv_dll - Win32 Release"
# Name "crlsrv_dll - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\src\CRL_free.cpp

!IF  "$(CFG)" == "crlsrv_dll - Win32 Release"

# ADD CPP /MD

!ELSEIF  "$(CFG)" == "crlsrv_dll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\CRL_hash.cpp

!IF  "$(CFG)" == "crlsrv_dll - Win32 Release"

# ADD CPP /MD

!ELSEIF  "$(CFG)" == "crlsrv_dll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\CRL_Mgr.cpp

!IF  "$(CFG)" == "crlsrv_dll - Win32 Release"

# ADD CPP /MD /Od

!ELSEIF  "$(CFG)" == "crlsrv_dll - Win32 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\src\crlapi.rc
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\inc\CRL_SRVinternal.h
# End Source File
# Begin Source File

SOURCE=.\inc\crlapi.h
# End Source File
# End Group
# End Target
# End Project
