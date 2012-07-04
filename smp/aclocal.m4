dnl
dnl File: aclocal.m4
dnl Project: Secure Message Protocol (SMP)
dnl Contents:
dnl Local defined autoconf macros, used to tweak the configure script
dnl
dnl Created 27 February 2003
dnl
dnl Author: C. C. McPherson <Clyde.McPherson@digitalnet.com>
dnl
dnl Last Updated: 24 March 2003
dnl Version 2.2
dnl
dnl $Log: aclocal.m4,v $
dnl Revision 1.58  2005/02/25 20:22:06  BeauchaS
dnl Added BSAFE processing for the bsafe include, source and library.
dnl
dnl Revision 1.57  2005/02/17 14:48:15  HorvathT
dnl changes to find OpenSSL in any directory other than the default.
dnl
dnl Revision 1.56  2005/02/15 19:16:38  HorvathT
dnl changes for OpenSSL/OCSP Makefiles
dnl
dnl Revision 1.55  2005/02/14 18:20:42  BeauchaS
dnl Added changes for Bsafe.
dnl
dnl Revision 1.54  2004/06/30 12:51:49  horvatht
dnl Changes for HPUX port.
dnl
dnl Revision 1.53  2003/10/08 19:38:00  leonberp
dnl fixed GCC version checking
dnl
dnl Revision 1.52  2003/10/01 10:43:30  leonberp
dnl Solaris build updates
dnl
dnl Revision 1.51  2003/09/30 18:23:25  leonberp
dnl fixed cryptopp lookup
dnl
dnl Revision 1.50  2003/07/18 20:38:10  beauchas
dnl [RWC] Updated to remove obsolete "-D" esnacc command line option when
dnl building individual Makefile(s).
dnl
dnl Revision 1.49  2003/06/03 16:35:21  mcphersc
dnl fixed cryptopp and snacc directory
dnl
dnl Revision 1.48  2003/04/08 18:33:43  leonberp
dnl fixed options for HPUX
dnl
dnl Revision 1.47  2003/04/04 11:44:06  mcphersc
dnl took out some echos
dnl
dnl Revision 1.46  2003/04/01 11:16:24  mcphersc
dnl bug in aclocal in checking threading model, took out
dnl
dnl Revision 1.45  2003/03/28 18:43:37  mcphersc
dnl Added history
dnl
dnl Default auto configure adds a -g to CFLAGS, this macro does not. This macro 
dnl should be called after AC_PROG_CC. Debug builds should not be the default, 
dnl but the GNU configure folks don't want to change it. 
dnl AC_PROG_CC_NO_G
dnl -----------------
dnl CFLAGS by default contain the -g -O2 options. We only need -O2 
dnl defaulting configure to debug is dumb
dnl
AC_DEFUN(AC_PROG_CC_NO_G,
[AC_BEFORE([$0], [AC_PROG_CPP])dnl
AC_CHECK_PROG(CC, gcc, gcc)
if test -z "$CC"; then
  AC_CHECK_PROG(CC, cc, cc, , , /usr/ucb/cc)
  test -z "$CC" && AC_MSG_ERROR([no acceptable cc found in \$PATH])
fi
 GCC=yes
 ac_test_CFLAGS="${CFLAGS+set}"
  if test "$mydebug" = 1; then
	USEDEBUGLIB="yes"
    	CFLAGS="$CFLAGS -ggdb -fPIC -D_DEBUG -Wall"
  elif test "$ac_test_CFLAGS" = 1; then
	USEDEBUGLIB="no"
	CFLAGS="$CFLAGS -fPIC -Wall"
  else
	USEDEBUGLIB="no"
    	CFLAGS="$CFLAGS -Wall"
  fi
  COMP_TYPE=`uname -s`
  if test $COMP_TYPE = "HP-UX"; then
        CFLAGS="$CFLAGS -fPIC"
  fi
  if test $COMP_TYPE = "SCO_SV"; then
        CFLAGS="$CFLAGS -fPIC"
  fi

AC_SUBST(USEDEBUGLIB)
AC_SUBST(CFLAGS)
])

dnl AC_PROG_CXX_NO_G
dnl -----------------
dnl CXXFLAGS by default contain the -g -O2 options. We only need -O2 
dnl defaulting configure to debug is dumb
AC_DEFUN(AC_PROG_CXX_NO_G,
[AC_BEFORE([$0], [AC_PROG_CXX])dnl
AC_CHECK_PROGS(ac_cxxnog, c++ g++)
if test -z "$ac_cxxnog"; then
  AC_MSG_ERROR([no acceptable c++ found in \$PATH])
fi
 GCC=yes
 ac_test_CXXFLAGS="${CXXFLAGS+set}"
 ac_save_CXXFLAGS="$CXXFLAGS"
  if test "$mydebug" = 1; then
	USEDEBUGLIB="yes"
    	CXXFLAGS="$CXXFLAGS -ggdb -fPIC -D_DEBUG"
  elif test "$ac_test_CXXFLAGS" = 1; then
	USEDEBUGLIB="no"
	CXXFLAGS="$CXXFLAGS -fPIC -Wall"
  else
	USEDEBUGLIB="no"
    	CXXFLAGS="$CXXFLAGS -fPIC -Wall"
  fi
  COMP_TYPE=`uname -s`
AC_SUBST(USEDEBUGLIB)
AC_SUBST(CXXFLAGS)
])


dnl
dnl
dnl Add system type to the CFLAGS and CXXFLAGS variable
dnl AC_PROG_ADD_SYS
dnl ---------------
 AC_DEFUN(AC_PROG_ADD_SYS,
 [AC_CHECK_PROG(CC, gcc, gcc)
 if test -z "$CC"; then
   AC_CHECK_PROG(CC, cc, cc, , , /usr/ucb/cc)
   test -z "$CC" && AC_MSG_ERROR([no acceptable cc found in \$PATH])
 fi
  GCC=yes
   ac_test_CFLAGS="${CFLAGS+set}"
   ac_save_CFLAGS="$CFLAGS"

   if test -z "$GOSTYPE"; then
     OS_TYPE=`uname -s`
   else
     OS_TYPE="$GOSTYPE"
   fi
   dnl
   dnl Default Shared Library Extension
   SHEXT="so"
   dnl
   dnl Special case for HP UX systems
   dnl
   if test "$OS_TYPE" = "HPUX32"; then
      SHEXT="sl"
      SOLIB="-ldld"
   fi
   if test "$OS_TYPE" = "HP-UX"; then
	OS_TYPE="HPUX";
	dnl
	dnl HP Shared Library extension
	SHEXT="sl"
	SOLIB="-ldld"
   fi
   if test "$ac_test_CFLAGS" = set; then
     CFLAGS="$CFLAGS -D$OS_TYPE"
   else
     CFLAGS="$CFLAGS -D$OS_TYPE"
   fi
   if test $ac_test_CXXFLAGS = set; then
   	CXXFLAGS="$CXXFLAGS -D$OS_TYPE"
   else
   	CXXFLAGS="$CXXFLAGS -D$OS_TYPE"
   fi
   AC_SUBST(OS_TYPE)
   AC_SUBST(SHEXT)
   AC_SUBST(CFLAGS)
   AC_SUBST(CXXFLAGS)
 ])
 
 dnl
 dnl
 dnl Add SNACC executable to the SNACC variable if it exists
 dnl
 dnl AC_GET_SNACC
 dnl ----------------
 AC_DEFUN(AC_GET_SNACC,
 [dnl
 if test -z "$SNACCDIREXEC" ; then
   Hassnaccdirexec=no;
 fi
 if test "$Hassnaccdirexec" = no; then
   AC_PATH_PROG(ac_cv_snacc_prog, esnacc, 99)
   if test "$ac_cv_snacc_prog" = 99; then
	HAVE_SNACC=no
 	ac_cv_snacc_present=0
 	AC_MSG_WARN([no path to ASN Compiler - SNACC executable not found])
   else
 	SNACCDIREXEC=$SNACCDIREXEC
 	ac_cv_snacc_present=yes
	HAVE_SNACC=yes
 	SNACCFLAGS="-C"
	AC_SUBST(SNACCFLAGS)
   fi
   AC_SUBST(ac_cv_snacc_present)
 else
  HAVE_SNACC=yes
  ac_cv_snacc_present=yes
  SNACCFLAGS="-C"
  AC_SUBST(SNACCFLAGS)
  AC_SUBST(ac_cv_snacc_present)
 fi
 AC_SUBST(SNACCDIREXEC) 
  AC_SUBST(HAVE_SNACC)
 ])

 dnl
 dnl
 dnl Check gcc version, if not 3.2 then error
 dnl
 dnl AC_CHECK_GCC_VERSION
 AC_DEFUN(AC_CHECK_GCC_VERSION,
[lgcc_version=`gcc -v 2>&1|egrep 'version'|sed 's/gcc version //'|awk -F. ' { if (($"1" >= 3) && ($"2" >= 1)) print "yes";else print "no"}'`
 AC_MSG_CHECKING("Checking GNU compiler version")
 if test $lgcc_version = no; then
        AC_MSG_ERROR([Incorrect version of GNU - Should be version 3.2])
 else
        AC_MSG_RESULT([Correct version])
 fi
 ])

dnl
dnl
dnl Check gcc thread model, if single then set SMP for single thread
dnl
dnlAC_DEFUN(AC_CHECK_GCC_THREAD,
dnl[lgcc_thread=`gcc -v 2>&1|egrep 'Thread model'|sed 's/Thread model: //'|awk -F. '{if ($$"1" == "single") print "no"; else print "yes"}'`
dnl  AC_MSG_CHECKING("Checking GNU Thread Model")
dnl  if test $lgcc_thread = yes; then
dnl	THREAD_MODEL="yes"
dnl	AC_MSG_RESULT([yes])
dnl  dnlelse
dnl	THREAD_MODEL="no"
dnl	AC_MSG_RESULT([no])
dnl  fi
dnl  AC_SUBST(THREAD_MODEL)
dnl ])dnl




dnl
dnl Check for the correct version of SNACC
dnl snacc version should be 1.5
dnl
dnl AC_CHECK_SNACC_VERSION
AC_DEFUN(AC_CHECK_SNACC_VERSION,
[llsnacc_version=`$SNACCDIREXEC/esnacc 2>&1|egrep 'version'|sed 's/Version //'|awk -F. '{if ($$"1" >= 1) ;if ($$"2" >= 5) print "yes";else print "no"}'`
  AC_MSG_CHECKING([SNACC Compiler version for 1.5])
  if test $lsnacc_version=yes; then
	AC_MSG_RESULT([yes])
  else
	AC_MSG_ERROR([Incorrect version of SNACC - Should be 1.5])
  fi
])

dnl
dnl Check for crypto++ in /usr/local include and then in /usr/include
dnl
dnl if user specified another location, use that location
dnl Using AC_CHECK_FILE instead of AC_CHECK_HEADER because
dnl AC_CHECK_HEADER tries a compile and cryplib.h produces errors when
dnl compiled alone
dnl
dnl AC_SMP_CHECK_CRYPTOPP
dnl --------------------
AC_DEFUN(AC_SMP_CHECK_CRYPTOPP,
[dnl
 AC_MSG_CHECKING([Crypto++ ])
if test -z "$CRYPTOPPINCDIR"; then
  AC_CHECK_FILE(/usr/local/include/cryptopp/cryptlib.h,LocalCryptoPP=9,LocalCryptoPP=0)
else
   cryptofile=$CRYPTOPPINCDIR/cryptlib.h
   AC_CHECK_FILE($cryptofile, LocalCryptoPP=9,LocalCryptoPP=0)
fi
if test "$LocalCryptoPP" = 9; then
	HasCryptoPP=yes
else
	HasCryptoPP=no
fi
if test "$LocalCryptoPP" = 9; then
  HasCryptoPP=yes
elif test "$SysCryptoPP" = 9; then
  HasCryptoPP=yes
else
  HasCryptoPP=no
fi
if test "$HasCrytoPP" = no; then
 AC_MSG_WARN([Configure could not find the optional Crypto++ API])
fi
 AC_SUBST(HasCryptoPP)
 AC_SUBST(CRYPTOPPDIR)
])dnl

dnl
dnl Check for BSAFE
dnl This macro will also pass the
dnl BSAFE Directory environment back
dnl into configure, if it is set.
dnl
dnl AC_SMP_CHECK_BSAFE
dnl
AC_DEFUN(AC_SMP_CHECK_BSAFE,
[dnl
if test $BSAFEINCDIR = no; then
   HasBSAFE=no
elif test -z "$BSAFEINCDIR"; then
 AC_CHECK_FILE(bsafe.h, HasBSAFE=yes,HasBSAFE=no)
else
 bsafe_include=$BSAFEINCDIR/bsafe.h
 AC_CHECK_FILE($bsafe_include, HasBSAFE=yes,HasBSAFE=no)
fi
AC_SUBST(HasBSAFE)
AC_SUBST(BSAFEINCDIR)
AC_SUBST(BSAFESRCDIR)
AC_SUBST(BSAFELIBDIR)
if test "$HasBSAFE" = no; then
 AC_MSG_WARN([Configure could not find the optional BSAFE API])
fi
])dnl

dnl
dnl Check for OpenSSL
dnl This macro will also pass the
dnl OPENSSL Directory environment back
dnl into configure, if it is set.
dnl
dnl AC_SMP_CHECK_OPENSSL
dnl
AC_DEFUN(AC_SMP_CHECK_OPENSSL,
[dnl
if test $OPENSSLDIR = no; then
   HasOpenSSL=no
elif test -z "$OPENSSLDIR"; then
 openssl_include=opensslconf.h
 AC_CHECK_FILE($openssl_include, HasOPENSSL=yes,HasOPENSSL=no)
else
 openssl_include=$OPENSSLDIR/include/openssl/opensslconf.h
 AC_CHECK_FILE($openssl_include, HasOPENSSL=yes,HasOPENSSL=no)
fi
AC_SUBST(HasOPENSSL)
AC_SUBST(OPENSSLDIR)
if test "$HasOPENSSL" = no; then
 AC_MSG_WARN([Configure could not find the optional OpenSSL API])
fi
])dnl

dnl
dnl Check for Cryptint.h  Fortezza
dnl AC_SMP_CHECK_FORTEZZA
dnl
AC_DEFUN(AC_SMP_CHECK_FORTEZZA,
[dnl
if test -z "$FORTEZZADIR"; then
 AC_CHECK_HEADER(Cryptint.h, HasFORTEZZA=yes,HasFORTEZZA=no)
else
 ac_fortezzadir=$FORTEZZADIR/include/cryptint/Cryptint.h
 AC_CHECK_HEADER($ac_fortezzadir, HasFORTEZZA=yes,HasFORTEZZA=no)
fi
AC_SUBST(HasFORTEZZA)
if test "$HasFORTEZZA" = no; then
 AC_MSG_WARN([Configure could not find the optional Fortezza API])
fi
])dnl
dnl
dnl
dnl AC_GET_LD_FLAG()
dnl Set according to supported system
dnl ===============
AC_DEFUN(AC_GET_LD_FLAG,
[dnl
dnl Set default
SOLIB="-ldl"
SMP_LD_FLAG="-shared -rdynamic"
 if test "$OS_TYPE" = "Linux"; then
   SMP_LDFLAG="-shared"
   LD='$(CXX)'
 elif test "$OS_TYPE" = "HPUX"; then
   SMP_LDFLAG="-fPIC -shared"
   SOLIB="-ldld"
   LD='$(CXX)'
 elif test "$OS_TYPE" = "HPUX32"; then
   SMP_LDFLAG="-fPIC -shared"
   SOLIB="-ldld" 
   LD='$(CXX)'
 elif test "$OS_TYPE" = "SunOS"; then
   SMP_LDFLAG="-G"
   LD='$(CXX)'
 elif test "$OS_TYPE" = "SCO_SV"; then
   SMP_LDFLAG="-G  -Wl,-Bexport" 
	LD='$(CXX)'
 fi
AC_SUBST(LD)
AC_SUBST(SMP_LDFLAG)
AC_SUBST(SOLIB)
])dnl
dnl
dnl End of aclocal.m4
dnl

