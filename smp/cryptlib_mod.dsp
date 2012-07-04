# Microsoft Developer Studio Project File - Name="cryptlib_mod" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) Static Library" 0x0104

CFG=cryptlib_mod - Win32 FIPS 140 Debug
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "cryptlib_mod.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "cryptlib_mod.mak" CFG="cryptlib_mod - Win32 FIPS 140 Debug"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "cryptlib_mod - Win32 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "cryptlib_mod - Win32 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE "cryptlib_mod - Win32 FIPS 140 Release" (based on "Win32 (x86) Static Library")
!MESSAGE "cryptlib_mod - Win32 FIPS 140 Debug" (based on "Win32 (x86) Static Library")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""$/cryptlib_mod", BAAAAAAA"
# PROP Scc_LocalPath "."
CPP=cl.exe
RSC=rc.exe

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "cryptlib_mod"
# PROP BASE Intermediate_Dir "cryptlib_mod"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "release"
# PROP Intermediate_Dir "release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /O2 /D "WIN32" /D "NDEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MD /W3 /GX /Zi /O2 /D "NDEBUG" /D "_WINDOWS" /D "USE_PRECOMPILED_HEADERS" /D "WIN32" /D DSA_1024_BIT_MODULUS_ONLY=0 /FD /Zm200 /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\SMPDist\lib\cryptlib.lib"

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "cryptli0"
# PROP BASE Intermediate_Dir "cryptli0"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "debug"
# PROP Intermediate_Dir "debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /W3 /GX /Z7 /Od /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /YX /FD /c
# ADD CPP /nologo /MDd /W3 /GX /ZI /Od /D "_DEBUG" /D "_WINDOWS" /D "USE_PRECOMPILED_HEADERS" /D "WIN32" /D DSA_1024_BIT_MODULUS_ONLY=0 /FR /FD /Zm200 /c
# SUBTRACT CPP /YX /Yc /Yu
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"..\SMPDist\lib\cryptlib_d.lib"

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "cryptlib_mod___Win32_FIPS_140_Release"
# PROP BASE Intermediate_Dir "cryptlib_mod___Win32_FIPS_140_Release"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "FIPS_140_Release"
# PROP Intermediate_Dir "FIPS_140_Release"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /G5 /Gz /MT /W3 /GX /Zi /O2 /D "NDEBUG" /D "WIN32" /D "_WINDOWS" /D "USE_PRECOMPILED_HEADERS" /Yu"pch.h" /FD /c
# ADD CPP /nologo /G5 /Gz /MT /W3 /GX /Zi /O2 /D "NDEBUG" /D "_WINDOWS" /D "USE_PRECOMPILED_HEADERS" /D "WIN32" /D CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2=1 /Yu"pch.h" /Fd"FIPS_140_Release/cryptopp" /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"FIPS_140_Release\cryptopp.lib"

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 1
# PROP BASE Output_Dir "cryptlib_mod___Win32_FIPS_140_Debug"
# PROP BASE Intermediate_Dir "cryptlib_mod___Win32_FIPS_140_Debug"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 1
# PROP Output_Dir "FIPS_140_Debug"
# PROP Intermediate_Dir "FIPS_140_Debug"
# PROP Target_Dir ""
# ADD BASE CPP /nologo /MTd /W3 /GX /ZI /Od /D "_DEBUG" /D "WIN32" /D "_WINDOWS" /D "USE_PRECOMPILED_HEADERS" /Yu"pch.h" /FD /c
# ADD CPP /nologo /G5 /Gz /MDd /W3 /GX /ZI /Od /D "_DEBUG" /D "_WINDOWS" /D "USE_PRECOMPILED_HEADERS" /D "WIN32" /D CRYPTOPP_ENABLE_COMPLIANCE_WITH_FIPS_140_2=1 /Yu"pch.h" /Fd"FIPS_140_Debug/cryptopp" /FD /c
# ADD BASE RSC /l 0x409
# ADD RSC /l 0x409
BSC32=bscmake.exe
# ADD BASE BSC32 /nologo
# ADD BSC32 /nologo
LIB32=link.exe -lib
# ADD BASE LIB32 /nologo
# ADD LIB32 /nologo /out:"FIPS_140_Debug\cryptopp.lib"

!ENDIF 

# Begin Target

# Name "cryptlib_mod - Win32 Release"
# Name "cryptlib_mod - Win32 Debug"
# Name "cryptlib_mod - Win32 FIPS 140 Release"
# Name "cryptlib_mod - Win32 FIPS 140 Debug"
# Begin Group "Source Files"

# PROP Default_Filter ".cpp"
# Begin Source File

SOURCE=..\cryptopp\3way.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\adler32.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\algebra.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\algparam.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\arc4.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\asn.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\base64.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\basecode.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\bfinit.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\blowfish.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\blumshub.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\cast.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\casts.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\channels.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\crc.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\cryptlib.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\datatest.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\default.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\des.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\dessp.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\dh.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\dh2.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\diamond.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\diamondt.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\dsa.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\ec2n.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\eccrypto.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\ecp.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\elgamal.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\eprecomp.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\esign.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\files.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\filters.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\fips140.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\fipstest.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\gf256.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\gf2_32.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\gf2n.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\gfpcrypt.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\gost.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\gzip.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\haval.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\hex.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\hrtimer.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\ida.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\idea.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\integer.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\iterhash.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\luc.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\mars.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\marss.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\md2.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\md4.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\md5.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\md5mac.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\misc.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\modes.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\modexppc.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\mqueue.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\mqv.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\nbtheory.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\network.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\oaep.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\osrng.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\panama.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\pch.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\pkcspad.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\polynomi.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\pssr.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\pubkey.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\queue.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rabin.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\randpool.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rc2.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rc5.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rc6.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rdtables.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\regtest.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rijndael.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\ripemd.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rng.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rsa.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\rw.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\safer.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\seal.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\serpent.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\sha.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\shark.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\sharkbox.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\simple.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\skipjack.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\socketft.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\square.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\squaretb.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\strciphr.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\tea.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\tftables.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\tiger.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\tigertab.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\trdlocal.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\twofish.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\wait.cpp

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# PROP Exclude_From_Build 1

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\wake.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\winpipes.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\xtr.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\xtrcrypt.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\zdeflate.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\zinflate.cpp
# End Source File
# Begin Source File

SOURCE=..\cryptopp\zlib.cpp
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter ".;.h"
# Begin Source File

SOURCE=..\cryptopp\3way.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\3way.h
InputName=3way

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\3way.h
InputName=3way

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\3way.h
InputName=3way

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\3way.h
InputName=3way

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\adler32.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\adler32.h
InputName=adler32

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\adler32.h
InputName=adler32

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\adler32.h
InputName=adler32

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\adler32.h
InputName=adler32

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\aes.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\aes.h
InputName=aes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\aes.h
InputName=aes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\aes.h
InputName=aes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\aes.h
InputName=aes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\algebra.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\algebra.h
InputName=algebra

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\algebra.h
InputName=algebra

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\algebra.h
InputName=algebra

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\algebra.h
InputName=algebra

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\algparam.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\algparam.h
InputName=algparam

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\algparam.h
InputName=algparam

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\algparam.h
InputName=algparam

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\algparam.h
InputName=algparam

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\arc4.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\arc4.h
InputName=arc4

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\arc4.h
InputName=arc4

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\arc4.h
InputName=arc4

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\arc4.h
InputName=arc4

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\argnames.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\argnames.h
InputName=argnames

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\argnames.h
InputName=argnames

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\argnames.h
InputName=argnames

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\argnames.h
InputName=argnames

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\asn.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\asn.h
InputName=asn

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\asn.h
InputName=asn

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\asn.h
InputName=asn

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\asn.h
InputName=asn

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\base64.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\base64.h
InputName=base64

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\base64.h
InputName=base64

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\base64.h
InputName=base64

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\base64.h
InputName=base64

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\basecode.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\basecode.h
InputName=basecode

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\basecode.h
InputName=basecode

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\basecode.h
InputName=basecode

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\basecode.h
InputName=basecode

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\bench.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\bench.h
InputName=bench

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\bench.h
InputName=bench

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\bench.h
InputName=bench

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\bench.h
InputName=bench

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\blowfish.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\blowfish.h
InputName=blowfish

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\blowfish.h
InputName=blowfish

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\blowfish.h
InputName=blowfish

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\blowfish.h
InputName=blowfish

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\blumshub.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\blumshub.h
InputName=blumshub

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\blumshub.h
InputName=blumshub

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\blumshub.h
InputName=blumshub

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\blumshub.h
InputName=blumshub

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\cast.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\cast.h
InputName=cast

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\cast.h
InputName=cast

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\cast.h
InputName=cast

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\cast.h
InputName=cast

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\cbcmac.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\cbcmac.h
InputName=cbcmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\cbcmac.h
InputName=cbcmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\cbcmac.h
InputName=cbcmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\cbcmac.h
InputName=cbcmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\channels.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\channels.h
InputName=channels

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\channels.h
InputName=channels

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\channels.h
InputName=channels

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\channels.h
InputName=channels

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\config.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\config.h
InputName=config

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\config.h
InputName=config

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\config.h
InputName=config

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\config.h
InputName=config

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\crc.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\crc.h
InputName=crc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\crc.h
InputName=crc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\crc.h
InputName=crc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\crc.h
InputName=crc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\cryptlib.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\cryptlib.h
InputName=cryptlib

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\cryptlib.h
InputName=cryptlib

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\cryptlib.h
InputName=cryptlib

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\cryptlib.h
InputName=cryptlib

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\default.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\default.h
InputName=default

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\default.h
InputName=default

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\default.h
InputName=default

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\default.h
InputName=default

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\des.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\des.h
InputName=des

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\des.h
InputName=des

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\des.h
InputName=des

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\des.h
InputName=des

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\dh.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\dh.h
InputName=dh

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\dh.h
InputName=dh

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\dh.h
InputName=dh

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\dh.h
InputName=dh

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\dh2.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\dh2.h
InputName=dh2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\dh2.h
InputName=dh2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\dh2.h
InputName=dh2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\dh2.h
InputName=dh2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\diamond.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\diamond.h
InputName=diamond

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\diamond.h
InputName=diamond

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\diamond.h
InputName=diamond

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\diamond.h
InputName=diamond

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\dmac.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\dmac.h
InputName=dmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\dmac.h
InputName=dmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\dmac.h
InputName=dmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\dmac.h
InputName=dmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\dsa.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\dsa.h
InputName=dsa

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\dsa.h
InputName=dsa

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\dsa.h
InputName=dsa

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\dsa.h
InputName=dsa

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\ec2n.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\ec2n.h
InputName=ec2n

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\ec2n.h
InputName=ec2n

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\ec2n.h
InputName=ec2n

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\ec2n.h
InputName=ec2n

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\eccrypto.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\eccrypto.h
InputName=eccrypto

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\eccrypto.h
InputName=eccrypto

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\eccrypto.h
InputName=eccrypto

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\eccrypto.h
InputName=eccrypto

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\ecp.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\ecp.h
InputName=ecp

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\ecp.h
InputName=ecp

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\ecp.h
InputName=ecp

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\ecp.h
InputName=ecp

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\elgamal.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\elgamal.h
InputName=elgamal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\elgamal.h
InputName=elgamal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\elgamal.h
InputName=elgamal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\elgamal.h
InputName=elgamal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\eprecomp.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\eprecomp.h
InputName=eprecomp

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\eprecomp.h
InputName=eprecomp

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\eprecomp.h
InputName=eprecomp

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\eprecomp.h
InputName=eprecomp

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\esign.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\esign.h
InputName=esign

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\esign.h
InputName=esign

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\esign.h
InputName=esign

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\esign.h
InputName=esign

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\factory.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\factory.h
InputName=factory

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\factory.h
InputName=factory

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\factory.h
InputName=factory

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\factory.h
InputName=factory

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\files.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\files.h
InputName=files

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\files.h
InputName=files

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\files.h
InputName=files

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\files.h
InputName=files

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\filters.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\filters.h
InputName=filters

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\filters.h
InputName=filters

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\filters.h
InputName=filters

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\filters.h
InputName=filters

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\fips140.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\fips140.h
InputName=fips140

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\fips140.h
InputName=fips140

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\fips140.h
InputName=fips140

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\fips140.h
InputName=fips140

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\fltrimpl.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\fltrimpl.h
InputName=fltrimpl

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\fltrimpl.h
InputName=fltrimpl

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\fltrimpl.h
InputName=fltrimpl

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\fltrimpl.h
InputName=fltrimpl

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\gf256.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\gf256.h
InputName=gf256

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gf256.h
InputName=gf256

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\gf256.h
InputName=gf256

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gf256.h
InputName=gf256

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\gf2_32.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\gf2_32.h
InputName=gf2_32

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gf2_32.h
InputName=gf2_32

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\gf2_32.h
InputName=gf2_32

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gf2_32.h
InputName=gf2_32

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\gf2n.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\gf2n.h
InputName=gf2n

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gf2n.h
InputName=gf2n

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\gf2n.h
InputName=gf2n

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gf2n.h
InputName=gf2n

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\gfpcrypt.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\gfpcrypt.h
InputName=gfpcrypt

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gfpcrypt.h
InputName=gfpcrypt

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\gfpcrypt.h
InputName=gfpcrypt

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gfpcrypt.h
InputName=gfpcrypt

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\gost.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\gost.h
InputName=gost

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gost.h
InputName=gost

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\gost.h
InputName=gost

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gost.h
InputName=gost

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\gzip.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\gzip.h
InputName=gzip

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gzip.h
InputName=gzip

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\gzip.h
InputName=gzip

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\gzip.h
InputName=gzip

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\haval.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\haval.h
InputName=haval

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\haval.h
InputName=haval

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\haval.h
InputName=haval

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\haval.h
InputName=haval

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\hex.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\hex.h
InputName=hex

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\hex.h
InputName=hex

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\hex.h
InputName=hex

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\hex.h
InputName=hex

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\hmac.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\hmac.h
InputName=hmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\hmac.h
InputName=hmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\hmac.h
InputName=hmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\hmac.h
InputName=hmac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\hrtimer.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\hrtimer.h
InputName=hrtimer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\hrtimer.h
InputName=hrtimer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\hrtimer.h
InputName=hrtimer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\hrtimer.h
InputName=hrtimer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\ida.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\ida.h
InputName=ida

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\ida.h
InputName=ida

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\ida.h
InputName=ida

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\ida.h
InputName=ida

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\idea.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\idea.h
InputName=idea

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\idea.h
InputName=idea

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\idea.h
InputName=idea

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\idea.h
InputName=idea

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\integer.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\integer.h
InputName=integer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\integer.h
InputName=integer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\integer.h
InputName=integer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\integer.h
InputName=integer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\iterhash.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\iterhash.h
InputName=iterhash

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\iterhash.h
InputName=iterhash

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\iterhash.h
InputName=iterhash

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\iterhash.h
InputName=iterhash

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\lubyrack.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\lubyrack.h
InputName=lubyrack

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\lubyrack.h
InputName=lubyrack

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\lubyrack.h
InputName=lubyrack

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\lubyrack.h
InputName=lubyrack

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\luc.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\luc.h
InputName=luc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\luc.h
InputName=luc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\luc.h
InputName=luc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\luc.h
InputName=luc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\mars.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\mars.h
InputName=mars

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\mars.h
InputName=mars

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\mars.h
InputName=mars

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\mars.h
InputName=mars

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\md2.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\md2.h
InputName=md2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\md2.h
InputName=md2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\md2.h
InputName=md2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\md2.h
InputName=md2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\md4.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\md4.h
InputName=md4

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\md4.h
InputName=md4

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\md4.h
InputName=md4

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\md4.h
InputName=md4

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\md5.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\md5.h
InputName=md5

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\md5.h
InputName=md5

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\md5.h
InputName=md5

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\md5.h
InputName=md5

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\md5mac.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\md5mac.h
InputName=md5mac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\md5mac.h
InputName=md5mac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\md5mac.h
InputName=md5mac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\md5mac.h
InputName=md5mac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\mdc.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\mdc.h
InputName=mdc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\mdc.h
InputName=mdc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\mdc.h
InputName=mdc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\mdc.h
InputName=mdc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\misc.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\misc.h
InputName=misc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\misc.h
InputName=misc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\misc.h
InputName=misc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\misc.h
InputName=misc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\modarith.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\modarith.h
InputName=modarith

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\modarith.h
InputName=modarith

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\modarith.h
InputName=modarith

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\modarith.h
InputName=modarith

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\modes.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\modes.h
InputName=modes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\modes.h
InputName=modes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\modes.h
InputName=modes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\modes.h
InputName=modes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\modexppc.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\modexppc.h
InputName=modexppc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\modexppc.h
InputName=modexppc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\modexppc.h
InputName=modexppc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\modexppc.h
InputName=modexppc

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\mqueue.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\mqueue.h
InputName=mqueue

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\mqueue.h
InputName=mqueue

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\mqueue.h
InputName=mqueue

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\mqueue.h
InputName=mqueue

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\mqv.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\mqv.h
InputName=mqv

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\mqv.h
InputName=mqv

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\mqv.h
InputName=mqv

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\mqv.h
InputName=mqv

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\nbtheory.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\nbtheory.h
InputName=nbtheory

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\nbtheory.h
InputName=nbtheory

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\nbtheory.h
InputName=nbtheory

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\nbtheory.h
InputName=nbtheory

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\network.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\network.h
InputName=network

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\network.h
InputName=network

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\network.h
InputName=network

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\network.h
InputName=network

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\nr.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\nr.h
InputName=nr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\nr.h
InputName=nr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\nr.h
InputName=nr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\nr.h
InputName=nr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\oaep.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\oaep.h
InputName=oaep

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\oaep.h
InputName=oaep

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\oaep.h
InputName=oaep

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\oaep.h
InputName=oaep

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\oids.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\oids.h
InputName=oids

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\oids.h
InputName=oids

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\oids.h
InputName=oids

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\oids.h
InputName=oids

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\osrng.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\osrng.h
InputName=osrng

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\osrng.h
InputName=osrng

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\osrng.h
InputName=osrng

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\osrng.h
InputName=osrng

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\panama.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\panama.h
InputName=panama

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\panama.h
InputName=panama

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\panama.h
InputName=panama

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\panama.h
InputName=panama

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\pch.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\pch.h
InputName=pch

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pch.h
InputName=pch

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\pch.h
InputName=pch

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pch.h
InputName=pch

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\pkcspad.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\pkcspad.h
InputName=pkcspad

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pkcspad.h
InputName=pkcspad

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\pkcspad.h
InputName=pkcspad

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pkcspad.h
InputName=pkcspad

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\polynomi.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\polynomi.h
InputName=polynomi

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\polynomi.h
InputName=polynomi

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\polynomi.h
InputName=polynomi

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\polynomi.h
InputName=polynomi

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\pssr.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\pssr.h
InputName=pssr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pssr.h
InputName=pssr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\pssr.h
InputName=pssr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pssr.h
InputName=pssr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\pubkey.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\pubkey.h
InputName=pubkey

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pubkey.h
InputName=pubkey

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\pubkey.h
InputName=pubkey

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pubkey.h
InputName=pubkey

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\pwdbased.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\pwdbased.h
InputName=pwdbased

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pwdbased.h
InputName=pwdbased

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\pwdbased.h
InputName=pwdbased

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\pwdbased.h
InputName=pwdbased

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\queue.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\queue.h
InputName=queue

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\queue.h
InputName=queue

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\queue.h
InputName=queue

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\queue.h
InputName=queue

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\rabin.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\rabin.h
InputName=rabin

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rabin.h
InputName=rabin

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\rabin.h
InputName=rabin

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rabin.h
InputName=rabin

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\randpool.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\randpool.h
InputName=randpool

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\randpool.h
InputName=randpool

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\randpool.h
InputName=randpool

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\randpool.h
InputName=randpool

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\rc2.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\rc2.h
InputName=rc2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rc2.h
InputName=rc2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\rc2.h
InputName=rc2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rc2.h
InputName=rc2

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\rc5.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\rc5.h
InputName=rc5

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rc5.h
InputName=rc5

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\rc5.h
InputName=rc5

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rc5.h
InputName=rc5

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\rc6.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\rc6.h
InputName=rc6

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rc6.h
InputName=rc6

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\rc6.h
InputName=rc6

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rc6.h
InputName=rc6

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\rijndael.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\rijndael.h
InputName=rijndael

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rijndael.h
InputName=rijndael

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\rijndael.h
InputName=rijndael

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rijndael.h
InputName=rijndael

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\ripemd.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\ripemd.h
InputName=ripemd

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\ripemd.h
InputName=ripemd

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\ripemd.h
InputName=ripemd

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\ripemd.h
InputName=ripemd

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\rng.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\rng.h
InputName=rng

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rng.h
InputName=rng

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\rng.h
InputName=rng

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rng.h
InputName=rng

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\rsa.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\rsa.h
InputName=rsa

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rsa.h
InputName=rsa

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\rsa.h
InputName=rsa

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rsa.h
InputName=rsa

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\rw.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\rw.h
InputName=rw

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rw.h
InputName=rw

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\rw.h
InputName=rw

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\rw.h
InputName=rw

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\safer.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\safer.h
InputName=safer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\safer.h
InputName=safer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\safer.h
InputName=safer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\safer.h
InputName=safer

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\seal.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\seal.h
InputName=seal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\seal.h
InputName=seal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\seal.h
InputName=seal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\seal.h
InputName=seal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\secblock.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\secblock.h
InputName=secblock

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\secblock.h
InputName=secblock

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\secblock.h
InputName=secblock

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\secblock.h
InputName=secblock

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\seckey.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\seckey.h
InputName=seckey

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\seckey.h
InputName=seckey

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\seckey.h
InputName=seckey

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\seckey.h
InputName=seckey

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\serpent.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\serpent.h
InputName=serpent

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\serpent.h
InputName=serpent

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\serpent.h
InputName=serpent

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\serpent.h
InputName=serpent

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\sha.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\sha.h
InputName=sha

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\sha.h
InputName=sha

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\sha.h
InputName=sha

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\sha.h
InputName=sha

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\shark.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\shark.h
InputName=shark

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\shark.h
InputName=shark

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\shark.h
InputName=shark

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\shark.h
InputName=shark

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\simple.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\simple.h
InputName=simple

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\simple.h
InputName=simple

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\simple.h
InputName=simple

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\simple.h
InputName=simple

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\skipjack.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\skipjack.h
InputName=skipjack

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\skipjack.h
InputName=skipjack

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\skipjack.h
InputName=skipjack

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\skipjack.h
InputName=skipjack

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\smartptr.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\smartptr.h
InputName=smartptr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\smartptr.h
InputName=smartptr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\smartptr.h
InputName=smartptr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\smartptr.h
InputName=smartptr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\socketft.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\socketft.h
InputName=socketft

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\socketft.h
InputName=socketft

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\socketft.h
InputName=socketft

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\socketft.h
InputName=socketft

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\square.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\square.h
InputName=square

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\square.h
InputName=square

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\square.h
InputName=square

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\square.h
InputName=square

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\strciphr.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\strciphr.h
InputName=strciphr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\strciphr.h
InputName=strciphr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\strciphr.h
InputName=strciphr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\strciphr.h
InputName=strciphr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\tea.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\tea.h
InputName=tea

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\tea.h
InputName=tea

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\tea.h
InputName=tea

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\tea.h
InputName=tea

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\tiger.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\tiger.h
InputName=tiger

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\tiger.h
InputName=tiger

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\tiger.h
InputName=tiger

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\tiger.h
InputName=tiger

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\trdlocal.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\trdlocal.h
InputName=trdlocal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\trdlocal.h
InputName=trdlocal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\trdlocal.h
InputName=trdlocal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\trdlocal.h
InputName=trdlocal

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\trunhash.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\trunhash.h
InputName=trunhash

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\trunhash.h
InputName=trunhash

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\trunhash.h
InputName=trunhash

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\trunhash.h
InputName=trunhash

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\twofish.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\twofish.h
InputName=twofish

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\twofish.h
InputName=twofish

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\twofish.h
InputName=twofish

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\twofish.h
InputName=twofish

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\validate.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\validate.h
InputName=validate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\validate.h
InputName=validate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\validate.h
InputName=validate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\validate.h
InputName=validate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\wait.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\wait.h
InputName=wait

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\wait.h
InputName=wait

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\wait.h
InputName=wait

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\wait.h
InputName=wait

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\wake.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\wake.h
InputName=wake

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\wake.h
InputName=wake

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\wake.h
InputName=wake

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\wake.h
InputName=wake

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\winpipes.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\winpipes.h
InputName=winpipes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\winpipes.h
InputName=winpipes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\winpipes.h
InputName=winpipes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\winpipes.h
InputName=winpipes

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\words.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\words.h
InputName=words

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\words.h
InputName=words

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\words.h
InputName=words

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\words.h
InputName=words

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\xormac.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\xormac.h
InputName=xormac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\xormac.h
InputName=xormac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\xormac.h
InputName=xormac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\xormac.h
InputName=xormac

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\xtr.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\xtr.h
InputName=xtr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\xtr.h
InputName=xtr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\xtr.h
InputName=xtr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\xtr.h
InputName=xtr

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\xtrcrypt.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\xtrcrypt.h
InputName=xtrcrypt

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\xtrcrypt.h
InputName=xtrcrypt

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\xtrcrypt.h
InputName=xtrcrypt

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\xtrcrypt.h
InputName=xtrcrypt

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\zdeflate.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\zdeflate.h
InputName=zdeflate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\zdeflate.h
InputName=zdeflate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\zdeflate.h
InputName=zdeflate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\zdeflate.h
InputName=zdeflate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\zinflate.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\zinflate.h
InputName=zinflate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\zinflate.h
InputName=zinflate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\zinflate.h
InputName=zinflate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\zinflate.h
InputName=zinflate

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# Begin Source File

SOURCE=..\cryptopp\zlib.h

!IF  "$(CFG)" == "cryptlib_mod - Win32 Release"

# Begin Custom Build
InputPath=..\cryptopp\zlib.h
InputName=zlib

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 Debug"

# Begin Custom Build
InputPath=..\cryptopp\zlib.h
InputName=zlib

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Release"

# Begin Custom Build
InputPath=..\cryptopp\zlib.h
InputName=zlib

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ELSEIF  "$(CFG)" == "cryptlib_mod - Win32 FIPS 140 Debug"

# Begin Custom Build
InputPath=..\cryptopp\zlib.h
InputName=zlib

"..\SMPDist\Algs\crypto++\$(InputName).h" : $(SOURCE) "$(INTDIR)" "$(OUTDIR)"
	copy $(InputPath) "..\SMPDist\Algs\crypto++"

# End Custom Build

!ENDIF 

# End Source File
# End Group
# Begin Group "Miscellaneous"

# PROP Default_Filter ""
# Begin Source File

SOURCE=..\cryptopp\GNUmakefile
# End Source File
# Begin Source File

SOURCE=..\cryptopp\License.txt
# End Source File
# Begin Source File

SOURCE=..\cryptopp\Readme.txt
# End Source File
# End Group
# End Target
# End Project
