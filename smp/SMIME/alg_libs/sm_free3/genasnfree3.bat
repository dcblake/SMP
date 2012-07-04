rem
attrib -r sm_free3_asn.cpp
attrib -r sm_free3_asn.h
echo on 
REM copy ..\..\..\cml\cmlasn\modules\*.asn1 
REM copy ..\..\libCtilMgr\src\sm_usefulTypes.asn 
REM copy ..\..\libcert\asn1\sm_VDASupport_asn.asn 
REM copy ..\..\libsrc\asn1\sm_cms.asn 
REM ..\..\..\..\SMPDist\bin\esnaccd.exe  -D -l -1000 -C sm_usefulTypes.asn UsefulDefinitions.asn1 UpperBounds.asn1 InformationFramework.asn1 SelectedAttributeTypes.asn1 ORAddress.asn1 X509Common.asn1 AuthenticationFramework.asn1 CertificateExtensions.asn1 PKIX.asn1 AttributeCertificateDefinitions.asn1 sdn702.asn1 sm_VDASupport_asn.asn sm_cms.asn sm_free3_asn.asn
..\..\..\..\SMPDist\bin\esnaccd.exe -I ..\..\libCtilMgr\src -I ..\..\libcert\asn1 -I ../../libsrc/asn1 -I ..\..\..\cml\cmlasn\modules  -D -C sm_free3_asn.asn1 
REM del UsefulDefinitions.* UpperBounds.* InformationFramework.* SelectedAttributeTypes.* ORAddress.* X509Common.* AuthenticationFramework.* CertificateExtensions.* AttributeCertificateDefinitions.* sdn702.* PKIX.* 
REM del sm_usefulTypes.* 
REM del sm_cms.* 
REM del sm_VDASupport_asn.* 
rem
pause