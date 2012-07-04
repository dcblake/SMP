rem  genasnCert.bat
rem
rem echo on
set SNACC=..\..\..\SMPDist\bin\snacc.exe -D -C 
cd ..\asn1
echo Building libcert ASN.1 Modules
%SNACC% -VDAexport -u..\..\..\SMPDist\util\VDASnacc\cpplib\asn1\asn-usefulVDA.asn1 sm_vdatypes.asn sm_x501ud.asn  sm_x411ub.asn sm_x411mtsas.asn sm_x501if.asn  sm_x520sa.asn sm_x509cmn.asn sm_x509af.asn sm_x509ce.asn  sm_VDASupport_asn.asn
if exist sm_vdatypes.h copy sm_vdatypes.h ..\include
if exist sm_vdatypes.cpp del sm_vdatypes.cpp
copy sm_vdatypes.C sm_vdatypes.cpp
if exist sm_x501ud.h copy sm_x501ud.h ..\include
if exist sm_x501ud.cpp del sm_x501ud.cpp
copy sm_x501ud.C sm_x501ud.cpp
if exist sm_x411ub.h copy sm_x411ub.h ..\include
if exist sm_x411ub.cpp del sm_x411ub.cpp
copy sm_x411ub.C sm_x411ub.cpp
if exist sm_x411mtsas.h copy sm_x411mtsas.h ..\include
if exist sm_x411mtsas.cpp del sm_x411mtsas.cpp
copy sm_x411mtsas.C sm_x411mtsas.cpp
if exist sm_x501if.h copy sm_x501if.h ..\include
if exist sm_x501if.cpp del sm_x501if.cpp
copy sm_x501if.C sm_x501if.cpp
if exist sm_x520sa.h copy sm_x520sa.h ..\include
if exist sm_x520sa.cpp del sm_x520sa.cpp
copy sm_x520sa.C sm_x520sa.cpp
if exist sm_x509cmn.h copy sm_x509cmn.h ..\include
if exist sm_x509cmn.cpp del sm_x509cmn.cpp
copy sm_x509cmn.C sm_x509cmn.cpp
if exist sm_x509af.h copy sm_x509af.h ..\include
if exist sm_x509af.cpp del sm_x509af.cpp
copy sm_x509af.C sm_x509af.cpp
if exist sm_x509ce.h copy sm_x509ce.h ..\include
if exist sm_x509ce.cpp del sm_x509ce.cpp
copy sm_x509ce.C sm_x509ce.cpp
if exist sm_VDASupport_asn.h copy sm_VDASupport_asn.h ..\include
if exist sm_VDASupport_asn.cpp del sm_VDASupport_asn.cpp
copy sm_VDASupport_asn.C sm_VDASupport_asn.cpp
rem
rem  EOF genasnClean.bat