# Microsoft Developer Studio Project File - Name="cmlasnSTATIC" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=cmlasnSTATIC - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "cmlasnSTATIC.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "cmlasnSTATIC.mak" CFG="cmlasnSTATIC - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cmlasnSTATIC - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "cmlasnSTATIC - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "cmlasnSTATIC - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "..\..\SMPDist\util\ldap\windows\include" /I "..\..\SMPDist\SFL\include" /I "..\..\SMPDist\util\VDASnacc\cpplib\inc" /I "..\cmapi\includes" /I "..\cmlasn\include" /I "..\srl\include" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /D CMLASN_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D LIBCTILMGRDLL_API="" /D EXPORT_GENSNACC="" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\lib\cmlasnSTATIC.lib"

!ELSEIF  "$(CFG)" == "cmlasnSTATIC - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "Debug"
# PROP BASE Intermediate_Dir "Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "Debug"
# PROP Intermediate_Dir "Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /Gm /GX /ZI /Od /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "..\..\SMPDist\util\ldap\windows\include" /I "..\..\SMPDist\SFL\include" /I "..\..\SMPDist\util\VDASnacc\cpplib\inc" /I "..\cmapi\includes" /I "..\cmlasn\include" /I "..\srl\include" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D CMLASN_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D LIBCTILMGRDLL_API="" /D EXPORT_GENSNACC="" /YX /FD /GZ = "" /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\lib\cmlasnSTATICd.lib"

!ENDIF 

# Begin Target

# Name "cmlasnSTATIC - Win32 Release"
# Name "cmlasnSTATIC - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\cmlasn\src\AttributeCertificateDefinitions.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\AuthenticationFramework.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\CertificateExtensions.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\CM_Certificate.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\CM_CertPath.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\CM_CRL.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\CM_Extensions.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\CM_GeneralNames.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\cmlasn.rc
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\Exception.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\InformationFramework.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\ORAddress.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\PKIX.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\sdn702.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\SelectedAttributeTypes.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\UpperBounds.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\UsefulDefinitions.cpp
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\X509Common.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\cmlasn\include\AttributeCertificateDefinitions.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\AuthenticationFramework.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\CertificateExtensions.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\cmlasn.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\InformationFramework.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\ORAddress.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\PKIX.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\src\resource.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\sdn702.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\SelectedAttributeTypes.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\UpperBounds.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\UsefulDefinitions.h
# End Source File
# Begin Source File

SOURCE=..\cmlasn\include\X509Common.h
# End Source File
# End Group
# End Target
# End Project
