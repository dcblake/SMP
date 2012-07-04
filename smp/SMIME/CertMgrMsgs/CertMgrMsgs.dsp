# Microsoft Developer Studio Project File - Name="CertMgrMsgs" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=CertMgrMsgs - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "CertMgrMsgs.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "CertMgrMsgs.mak" CFG="CertMgrMsgs - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "CertMgrMsgs - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "CertMgrMsgs - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName "CertMgrMsgs"
# PROP Scc_LocalPath "."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "CertMgrMsgs - Win32 Release"

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
# ADD CPP /nologo /MD /W3 /GX /O2 /I "../inc" /I "../../../SMPDist/include/esnacc/c++" /I "../libCtilMgr/inc" /I "../../cml/cmlasn/inc" /D "WIN32" /D "NDEBUG" /D "_MBCS" /D "_LIB" /YX /FD /Zm200 /c
# ADD BASE RSC /l 0x409 /d "NDEBUG"
# ADD RSC /l 0x409 /d "NDEBUG"
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo

!ELSEIF  "$(CFG)" == "CertMgrMsgs - Win32 Debug"

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
# ADD CPP /nologo /MDd /W3 /Gm /GX /ZI /Od /I "../inc" /I "../../../SMPDist/include/esnacc/c++" /I "../libCtilMgr/inc" /I "../../cml/cmlasn/inc" /D "WIN32" /D "_DEBUG" /D "_MBCS" /D "_LIB" /YX /FD /GZ /Zm200 /c
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

# Name "CertMgrMsgs - Win32 Release"
# Name "CertMgrMsgs - Win32 Debug"
# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\EnrollmentMessageSyntax.asn1

!IF  "$(CFG)" == "CertMgrMsgs - Win32 Release"

# Begin Custom Build
InputPath=.\EnrollmentMessageSyntax.asn1
InputName=EnrollmentMessageSyntax

BuildCmds= \
	attrib -r $(InputName).cpp \
	attrib -r $(InputName).h \
	..\..\..\SMPDist\bin\esnacc -C -I .\ -I ..\libCtilMgr\src -I ..\libcert\asn1 -I ..\..\cml\cmlasn\modules -I ..\libsrc\asn1 $(InputName).asn1 \
	

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ELSEIF  "$(CFG)" == "CertMgrMsgs - Win32 Debug"

# Begin Custom Build
InputPath=.\EnrollmentMessageSyntax.asn1
InputName=EnrollmentMessageSyntax

BuildCmds= \
	attrib -r $(InputName).cpp \
	attrib -r $(InputName).h \
	..\..\..\SMPDist\bin\esnaccd -C -I .\ -I ..\libCtilMgr\src -I ..\libcert\asn1 -I ..\..\cml\cmlasn\modules -I ..\libsrc\asn1 $(InputName).asn1 \
	

"$(InputName).cpp" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)

"$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
   $(BuildCmds)
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=.\EnrollmentMessageSyntax.cpp

!IF  "$(CFG)" == "CertMgrMsgs - Win32 Release"

!ELSEIF  "$(CFG)" == "CertMgrMsgs - Win32 Debug"

# ADD CPP /MDd

!ENDIF 

# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=.\EnrollmentMessageSyntax.h
# End Source File
# End Group
# End Target
# End Project
