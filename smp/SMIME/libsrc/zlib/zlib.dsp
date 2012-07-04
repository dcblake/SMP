# Microsoft Developer Studio Project File - Name="zlib" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Generic Project" 0x010a

CFG=zlib - Win32 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "zlib.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "zlib.mak" CFG="zlib - Win32 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "zlib - Win32 Release" (based on "Win32 (x86) Generic Project")
!MESSAGE "zlib - Win32 Debug" (based on "Win32 (x86) Generic Project")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""
MTL=midl.exe

!IF  "$(CFG)" == "zlib - Win32 Release"

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

!ELSEIF  "$(CFG)" == "zlib - Win32 Debug"

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

!ENDIF 

# Begin Target

# Name "zlib - Win32 Release"
# Name "zlib - Win32 Debug"
# Begin Group "libs"

# PROP Default_Filter ""
# Begin Source File

SOURCE=".\libcharset-1.dll"

!IF  "$(CFG)" == "zlib - Win32 Release"

# Begin Custom Build
InputPath=".\libcharset-1.dll"
InputName=libcharset-1

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32 
	copy "$(InputPath)" ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "zlib - Win32 Debug"

# Begin Custom Build
InputPath=".\libcharset-1.dll"
InputName=libcharset-1

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32 
	copy "$(InputPath)" ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=".\libiconv-2.dll"

!IF  "$(CFG)" == "zlib - Win32 Release"

# Begin Custom Build
InputPath=".\libiconv-2.dll"
InputName=libiconv-2

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32 
	copy "$(InputPath)" ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "zlib - Win32 Debug"

# Begin Custom Build
InputPath=".\libiconv-2.dll"
InputName=libiconv-2

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32 
	copy "$(InputPath)" ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=".\libintl-2.dll"

!IF  "$(CFG)" == "zlib - Win32 Release"

# Begin Custom Build
InputPath=".\libintl-2.dll"
InputName=libintl-2

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32 
	copy "$(InputPath)" ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ELSEIF  "$(CFG)" == "zlib - Win32 Debug"

# Begin Custom Build
InputPath=".\libintl-2.dll"
InputName=libintl-2

"$(WINDIR)\system32\$(InputName).dll" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy "$(InputPath)" %WINDIR%\system32 
	copy "$(InputPath)" ..\..\..\..\SMPDist\lib 
	
# End Custom Build

!ENDIF 

# End Source File
# End Group
# End Target
# End Project
