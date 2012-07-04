# Microsoft Developer Studio Project File - Name="sm_fortezzaSTATIC" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=sm_fortezzaSTATIC - Win32 StaticSnacc Release
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sm_fortezzaSTATIC.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sm_fortezzaSTATIC.mak" CFG="sm_fortezzaSTATIC - Win32 StaticSnacc Release"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sm_fortezzaSTATIC - Win32 StaticSnacc Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "sm_fortezzaSTATIC - Win32 StaticSnacc Release" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "sm_fortezzaSTATIC"
# PROP Scc_LocalPath "..\sm_fort"
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "sm_fortezzaSTATIC - Win32 StaticSnacc Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "sm_fortezzaSTATIC___Win32_StaticSnacc_Debug"
# PROP BASE Intermediate_Dir "sm_fortezzaSTATIC___Win32_StaticSnacc_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "sm_fortezzaSTATIC___Win32_StaticSnacc_Debug"
# PROP Intermediate_Dir "sm_fortezzaSTATIC___Win32_StaticSnacc_Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "./" /I "../../include" /I "../../libcert/include" /I "../lolevel" /I "../../../SMPDist/util/VDASnacc/cpplib/inc" /I "../../include/cmapi" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D SM_FORTEZZADLL_EXPORTS="" /D LIBCERTDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D "SNACC_DEEP_COPY" /D "VDADER_RULES" /FR /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "./" /I "../../inc" /I "../../libcert/inc" /I "../../../SMPDist/Algs/Fortezza" /I "../../../SNACC" /I "../../../SNACC/c++-lib/inc" /I "../../inc/cmapi" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /I "../lolevel" /D "_DEBUG" /D "WIN32" /D "_MBCS" /D "_LIB" /D SM_FORTEZZADLL="" /D LIBCERTDLL_API="" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /FR /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"sm_fortezzaSTATIC___Win32_StaticSnacc_Debug\sm_fortezzaSTATICd.lib"

!ELSEIF  "$(CFG)" == "sm_fortezzaSTATIC - Win32 StaticSnacc Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "sm_fortezzaSTATIC___Win32_StaticSnacc_Release"
# PROP BASE Intermediate_Dir "sm_fortezzaSTATIC___Win32_StaticSnacc_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "sm_fortezzaSTATIC___Win32_StaticSnacc_Release"
# PROP Intermediate_Dir "sm_fortezzaSTATIC___Win32_StaticSnacc_Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "./" /I "../../include" /I "../../libcert/include" /I "../lolevel" /I "../../../SMPDist/util/VDASnacc/cpplib/inc" /I "../../include/cmapi" /I "../../../SMPDist/Algs/Fortezza" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /D SM_FORTEZZADLL_EXPORTS="" /D LIBCERTDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D "SNACC_DEEP_COPY" /D "VDADER_RULES" /FR /YX /FD /GZ /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "./" /I "../../inc" /I "../../libcert/inc" /I "../../../SMPDist/Algs/Fortezza" /I "../../../SNACC" /I "../../../SNACC/c++-lib/inc" /I "../../inc/cmapi" /I "../../libCtilMgr/inc" /I "../../../cml/cmlasn/inc" /I "../lolevel" /D "WIN32" /D "_MBCS" /D "_LIB" /D SM_FORTEZZADLL="" /D LIBCERTDLL_API="" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /YX /FD /c
# SUBTRACT CPP /Fr
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ENDIF 

# Begin Target

# Name "sm_fortezzaSTATIC - Win32 StaticSnacc Debug"
# Name "sm_fortezzaSTATIC - Win32 StaticSnacc Release"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\sm_fort\sm_fort.cpp
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortAsn.cpp
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortCI.cpp
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortDsaParams.cpp
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortDsaSigvalue.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=..\sm_fort\sm_fort.h
# End Source File
# Begin Source File

SOURCE=..\sm_fort\sm_fortAsn.h
# End Source File
# End Group
# End Target
# End Project
