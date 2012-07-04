# Microsoft Developer Studio Project File - Name="pkcs11_cryptopp_dll" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Dynamic-Link Library" 0x0102

CFG=pkcs11_cryptopp_dll - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "pkcs11_cryptopp_dll.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "pkcs11_cryptopp_dll.mak" CFG="pkcs11_cryptopp_dll - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "pkcs11_cryptopp_dll - Win32 Release" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE "pkcs11_cryptopp_dll - Win32 Debug" (based on "Win32 (x86) Dynamic-Link Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "smp/pkcs11_cryptopp"
# PROP Scc_LocalPath "."
CPP=cl.exe
MTL=midl.exe
RSC=rc.exe

!IF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Release"

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
# ADD BASE CPP /nologo /MT /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PKCS11_CRYPTOPP_DLL_EXPORTS" /YX /FD /c
# ADD CPP /nologo /MD /W4 /GR /GX /O2 /I "..\inc" /I "..\..\..\cryptopp" /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PKCS11_CRYPTOPP_DLL_EXPORTS" /D "CRYPTOKI_EXPORTS" /FD /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "NDEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /machine:I386
# ADD LINK32 ..\..\..\SMPDist\lib\cryptlib.lib /nologo /dll /pdb:none /machine:I386 /out:"..\..\..\SMPDist\lib\pkcs11_cryptopp.dll"
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\src\SMPDist\lib\pkcs11_cryptopp.dll
InputName=pkcs11_cryptopp
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ELSEIF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Debug"

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
# ADD BASE CPP /nologo /MTd /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PKCS11_CRYPTOPP_DLL_EXPORTS" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W4 /GR /GX /Z7 /Od /I "..\inc" /I "..\..\..\cryptopp" /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "_MBCS" /D "_USRDLL" /D "PKCS11_CRYPTOPP_DLL_EXPORTS" /D "CRYPTOKI_EXPORTS" /FR /FD /GZ /c
# SUBTRACT CPP /YX
# ADD BASE MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD MTL /nologo /D "_DEBUG" /mktyplib203 /win32
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LINK32=link.exe
# ADD BASE LINK32 kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /nologo /dll /debug /machine:I386 /pdbtype:sept
# ADD LINK32 ..\..\..\SMPDist\lib\cryptlib_d.lib /nologo /dll /profile /debug /machine:I386 /out:"..\..\..\SMPDist\lib\pkcs11_cryptopp_d.dll"
# SUBTRACT LINK32 /force
# Begin Custom Build - Copying $(InputPath) to system32 directory...
InputPath=\src\SMPDist\lib\pkcs11_cryptopp_d.dll
InputName=pkcs11_cryptopp_d
SOURCE="$(InputPath)"

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32

# End Custom Build

!ENDIF 

# Begin Target

# Name "pkcs11_cryptopp_dll - Win32 Release"
# Name "pkcs11_cryptopp_dll - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\src\c_digest_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_dual_use_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_encrypt_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_general_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_key_funcs.cpp
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=..\src\c_key_mgmt_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_object_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_rand_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_session_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_sign_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_token_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\c_verify_funcs.cpp
# End Source File
# Begin Source File

SOURCE=..\src\CKSession.cpp
# End Source File
# Begin Source File

SOURCE=..\src\create_dsa_signer.cpp
# End Source File
# Begin Source File

SOURCE=..\src\create_rsa_objects.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\inc\cryptoki.h

!IF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to SMPDist...
InputPath=..\inc\cryptoki.h
InputName=cryptoki

"..\..\..\SMPDist\include\pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to SMPDist...
InputPath=..\inc\cryptoki.h
InputName=cryptoki

"..\..\..\SMPDist\include\pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\inc\p11cryptopp_internal.h
# PROP Exclude_From_Build 1
# End Source File
# Begin Source File

SOURCE=..\inc\pkcs11.h

!IF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to SMPDist...
InputPath=..\inc\pkcs11.h
InputName=pkcs11

"..\..\..\SMPDist\include\pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to SMPDist...
InputPath=..\inc\pkcs11.h
InputName=pkcs11

"..\..\..\SMPDist\include\pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\inc\pkcs11f.h

!IF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to SMPDist...
InputPath=..\inc\pkcs11f.h
InputName=pkcs11f

"..\..\..\SMPDist\include\pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to SMPDist...
InputPath=..\inc\pkcs11f.h
InputName=pkcs11f

"..\..\..\SMPDist\include\pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\pkcs11

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\inc\pkcs11t.h

!IF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Release"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to SMPDist...
InputPath=..\inc\pkcs11t.h
InputName=pkcs11t

"..\..\..\SMPDist\include\pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\pkcs11

# End Custom Build

!ELSEIF  "$(CFG)" == "pkcs11_cryptopp_dll - Win32 Debug"

# PROP Ignore_Default_Tool 1
# Begin Custom Build - Copying $(InputName).h to SMPDist...
InputPath=..\inc\pkcs11t.h
InputName=pkcs11t

"..\..\..\SMPDist\include\pkcs11\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" ..\..\..\SMPDist\include\pkcs11

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# End Target
# End Project
