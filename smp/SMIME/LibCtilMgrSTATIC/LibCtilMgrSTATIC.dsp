# Microsoft Developer Studio Project File - Name="LibCtilMgrSTATIC" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=LibCtilMgrSTATIC - Win32 StaticSnacc Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "LibCtilMgrSTATIC.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "LibCtilMgrSTATIC.mak" CFG="LibCtilMgrSTATIC - Win32 StaticSnacc Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "LibCtilMgrSTATIC - Win32 StaticSnacc Release" (based on "Win32 (x86) Static Library")
!MESSAGE "LibCtilMgrSTATIC - Win32 StaticSnacc Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "LibCtilMgrSTATIC - Win32 StaticSnacc Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "LibCtilMgrSTATIC___Win32_StaticSnacc_Release"
# PROP BASE Intermediate_Dir "LibCtilMgrSTATIC___Win32_StaticSnacc_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "LibCtilMgrSTATIC___Win32_StaticSnacc_Release"
# PROP Intermediate_Dir "LibCtilMgrSTATIC___Win32_StaticSnacc_Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /I "../libCtilMgr/inc" /I "../../SNACC" /I "../../SNACC/c++-lib/inc" /D "_MBCS" /D "_LIB" /D "WIN32" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../libCtilMgr/inc" /I "../../SNACC" /I "../../SNACC/c++-lib/inc" /D "_MBCS" /D "_LIB" /D "WIN32" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /YX /FD /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\lib\LibCtilMgrSTATIC.lib"
# ADD LIB32 /nologo /out:"..\lib\LibCtilMgrSTATIC.lib"

!ELSEIF  "$(CFG)" == "LibCtilMgrSTATIC - Win32 StaticSnacc Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "LibCtilMgrSTATIC___Win32_StaticSnacc_Debug"
# PROP BASE Intermediate_Dir "LibCtilMgrSTATIC___Win32_StaticSnacc_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "LibCtilMgrSTATIC___Win32_StaticSnacc_Debug"
# PROP Intermediate_Dir "LibCtilMgrSTATIC___Win32_StaticSnacc_Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MDd /W3 /GX /Z7 /Od /I "../libCtilMgr/inc" /I "../../SNACC" /I "../../SNACC/c++-lib/inc" /D "_MBCS" /D "_LIB" /D "WIN32" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /YX /FD /GZ /c
# ADD CPP /nologo /MDd /W3 /GX /Z7 /Od /I "../libCtilMgr/inc" /I "../../SNACC" /I "../../SNACC/c++-lib/inc" /D "_MBCS" /D "_LIB" /D "WIN32" /D LIBCTILMGRDLL_API="" /D SNACCDLL_API="" /D VDASNACCDLL_API="" /D EXPORT_GENSNACC="" /D CMLASN_API="" /YX /FD /GZ /c
# ADD BASE RSC /l 0x409 /d "_DEBUG"
# ADD RSC /l 0x409 /d "_DEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo /out:"..\lib\LibCtilMgrSTATICd.lib"
# ADD LIB32 /nologo /out:"..\lib\LibCtilMgrSTATICd.lib"

!ENDIF 

# Begin Target

# Name "LibCtilMgrSTATIC - Win32 StaticSnacc Release"
# Name "LibCtilMgrSTATIC - Win32 StaticSnacc Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=..\libCtilMgr\src\fortezza.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\libCtilMgr.cpp
# End Source File
# Begin Source File

SOURCE="..\libCtilMgr\AES\rijndael-alg-ref.c"
# End Source File
# Begin Source File

SOURCE="..\libCtilMgr\AES\rijndael-api-ref.c"
# End Source File
# Begin Source File

SOURCE="..\libCtilMgr\AES\rijndaeltest-ref.c"
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\AES\sha256ref.c
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\AES\sm_aes.c
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_Alg.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_BaseTokenInterface.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_common.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_commonCTIL.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_CtilCommon.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_CtilInst.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_CtilMgr.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_CTthreads.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_DLLInterface.cpp
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_usefulTypes.asn
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\src\sm_usefulTypes.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE="..\..\SMPDist\util\VDASnacc\cpplib\inc\asn-incl.h"
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\AttributeCertificateDefinitions.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\AuthenticationFramework.h
# End Source File
# Begin Source File

SOURCE="..\libCtilMgr\include\boxes-ref.h"
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\CertificateExtensions.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\cmapi.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\cmapi_cpp.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\cmapiCommon.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\cmlasn.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\include\fortezza.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\include\fortezzaRWC_64ByteAttemptFailed.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\InformationFramework.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\ORAddress.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\PKIX.h
# End Source File
# Begin Source File

SOURCE="..\libCtilMgr\include\rijndael-alg-ref.h"
# End Source File
# Begin Source File

SOURCE="..\libCtilMgr\include\rijndael-api-ref.h"
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\sdn702.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\SelectedAttributeTypes.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\include\sha256.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\include\sm_aes.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\inc\sm_apicCtilMgr.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\inc\sm_apiCtilMgr.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\inc\sm_common.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\inc\sm_CtilCommon.h
# End Source File
# Begin Source File

SOURCE=..\libCtilMgr\inc\sm_DLLInterface.h
# End Source File
# Begin Source File

SOURCE=..\..\SMPDist\CML\include\srlapi.h
# End Source File
# End Group
# End Target
# End Project
