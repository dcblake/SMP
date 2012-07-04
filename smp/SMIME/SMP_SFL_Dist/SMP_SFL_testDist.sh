#
# SMP_SFL_testDist.sh
#
echo
if test ! -d ../../SMPDist
then
  mkdir ../../SMPDist
fi
if test ! -d ../../SMPDist/sfl
then
  mkdir ../../SMPDist/sfl
fi
if test ! -d ../../SMPDist/sfl/alg_libs
then
  mkdir ../../SMPDist/sfl/alg_libs
fi
if test ! -d ../../SMPDist/sfl/alg_libs/sm_free3
then
  mkdir ../../SMPDist/sfl/alg_libs/sm_free3
fi
if test ! -d ../../SMPDist/sfl/lib
then
  mkdir ../../SMPDist/sfl/lib
fi
#
#
#
#
cp   ../lib/libsm_free3DLLOpenSSL.so ../../SMPDist/sfl/alg_libs/sm_free3
cp  ../alg_libs/sm_free3/*.h   ../../SMPDist/sfl/alg_libs/sm_free3
cp ../testutil/mimelib/*.h ../../SMPDist/sfl/inc
cp ../testutil/mimelib/*.a ../../SMPDist/sfl/lib
cp ../testsrc/inc/*.h ../../SMPDist/sfl/inc
cp ../lib/libsmutil.a ../../SMPDist/sfl/lib

echo ####### SMIME Test DISTRIBUTION FINISHED ######


# EOF SMP_SFL_testDist.sh
