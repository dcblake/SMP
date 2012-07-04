rem
attrib -r sm_VDASupport_asn.cpp 
attrib -r ..\..\inc\sm_VDASupport_asn.h 
echo on 
REM copy ..\..\..\cml\cmlasn\modules\*.asn1 
REM copy ..\..\libCtilMgr\src\sm_usefulTypes.asn1 
rem -VDAexport=LIBCERT RWC;OLD definition, no longer .dll export definition.
rem -u..\..\..\SMPDist\util\VDASnacc\cpplib\asn1\asn-usefulVDA.asn1 
..\..\..\..\SMPDist\bin\snaccd.exe -a 600 -I ..\..\libCtilMgr\src -I ..\..\..\cml\cmlasn\modules -D -C  sm_VDASupport_asn.asn1
REM ..\..\..\SMPDist\esnacc\bin\snaccd.exe -D -C sm_usefulTypes.asn UsefulDefinitions.asn1 UpperBounds.asn1 InformationFramework.asn1 SelectedAttributeTypes.asn1 ORAddress.asn1 X509Common.asn1 AuthenticationFramework.asn1 CertificateExtensions.asn1 PKIX.asn1 AttributeCertificateDefinitions.asn1 sdn702.asn1 sm_VDASupport_asn.asn 
del UsefulDefinitions.* UpperBounds.* InformationFramework.* SelectedAttributeTypes.* ORAddress.* X509Common.* AuthenticationFramework.* CertificateExtensions.* AttributeCertificateDefinitions.* sdn702.* PKIX.* EnhancedSecurity.asn1
REM del sm_usefulTypes.* 
REM del ..\..\inc\sm_VDASupport_asn.h 
move sm_VDASupport_asn.h ..\..\inc 
rem
pause