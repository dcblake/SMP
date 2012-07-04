#
# SMP_SFL_Dist.sh
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
if test ! -d ../../SMPDist/sfl/alg_libs/sm_fort
then
  mkdir ../../SMPDist/sfl/alg_libs/sm_fort
fi
if test ! -d ../../SMPDist/sfl/alg_libs/sm_free3
then
  mkdir ../../SMPDist/sfl/alg_libs/sm_free3
fi
if test ! -d ../../SMPDist/sfl/alg_libs/sm_rsa
then
  mkdir ../../SMPDist/sfl/alg_libs/sm_rsa
fi
if test ! -d ../../SMPDist/sfl/alg_libs/sm_pkcs11
then
  mkdir ../../SMPDist/sfl/alg_libs/sm_pkcs11
fi
if test ! -d ../../SMPDist/sfl/alg_libs/sm_spex
then
  mkdir ../../SMPDist/sfl/alg_libs/sm_spex
fi
if test ! -d ../../SMPDist/sfl/inc
then
  mkdir ../../SMPDist/sfl/inc
fi
if test ! -d ../../SMPDist/sfl/lib
then
  mkdir ../../SMPDist/sfl/lib
fi
#
#
#
#
#cp   ../lib/libsm_fortDLL.so ../../SMPDist/sfl/alg_libs/sm_fort
cp  ../alg_libs/sm_fort/*.h   ../../SMPDist/sfl/alg_libs/sm_fort
cp   ../lib/libsm_free3DLL.so ../../SMPDist/sfl/alg_libs/sm_free3
cp  ../alg_libs/sm_free3/*.h   ../../SMPDist/sfl/alg_libs/sm_free3
#cp  ../alg_libs/sm_pkcs11/*.so  ../../SMPDist/sfl/alg_libs/sm_pkcs11
cp  ../alg_libs/sm_pkcs11/*.h   ../../SMPDist/sfl/alg_libs/sm_pkcs11
cp   ../lib/libsm_rsaDLL.so ../../SMPDist/sfl/alg_libs/sm_rsa
cp  ../alg_libs/sm_rsa/*.h   ../../SMPDist/sfl/alg_libs/sm_rsa
#cp  ../alg_libs/sm_spex/*.so  ../../SMPDist/sfl/alg_libs/sm_spex
cp  ../alg_libs/sm_spex/*.h   ../../SMPDist/sfl/alg_libs/sm_spex
cp  ../inc/*.h   ../../SMPDist/sfl/inc
cp  ../lib/libsm*.a        ../../SMPDist/sfl/lib

#cd ../libcert/SMP_libcert_Dist
#. ./SMP_libcert_Dist.sh
cp ../libcert/*.a ../../SMPDist/sfl/lib
cd ../libCtilMgr/SMP_libCtilMgr_Dist
. ./SMP_libCtilMgr_Dist.sh
cd ../../SMP_SFL_Dist

#cp ../testutil/mimelib/*.h ../../SMPDist/sfl/inc
#cp ../testutil/mimelib/*.a ../../SMPDist/sfl/lib
#cp ../testsrc/inc/*.h ../../SMPDist/sfl/inc
#cp ../lib/libsmutil.a ../../SMPDist/sfl/lib

echo ####### SMIME DISTRIBUTION FINISHED ######


# EOF SMP_SFL_Dist.sh
