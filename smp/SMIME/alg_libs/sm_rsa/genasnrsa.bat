rem
attrib -r sm_rsa_asn.cpp
attrib -r sm_rsa_asn.h
echo on 
REM copy ..\..\..\cml\cmlasn\modules\*.asn1 
REM copy ..\..\libCtilMgr\src\sm_usefulTypes.asn 
REM copy ..\..\libcert\asn1\sm_VDASupport_asn.asn
rem -u..\..\..\SMPDist\util\VDASnacc\cpplib\asn1\asn-usefulVDA.asn1  
REM ..\..\..\SMPDist\esnacc\bin\snaccd.exe -D -C sm_usefulTypes.asn UsefulDefinitions.asn1 UpperBounds.asn1 InformationFramework.asn1 SelectedAttributeTypes.asn1 ORAddress.asn1 X509Common.asn1 AuthenticationFramework.asn1 CertificateExtensions.asn1 PKIX.asn1 AttributeCertificateDefinitions.asn1 sdn702.asn1 sm_VDASupport_asn.asn sm_rsa_asn.asn 
..\..\..\..\SMPDist\bin\snaccd.exe -I ..\..\libCtilMgr\src -I ..\..\libcert\asn1 -I ../../libsrc/asn1 -I ..\..\..\cml\cmlasn\modules -D -C sm_rsa_asn.asn1
REM del UsefulDefinitions.* UpperBounds.* InformationFramework.* SelectedAttributeTypes.* ORAddress.* X509Common.* AuthenticationFramework.* CertificateExtensions.* AttributeCertificateDefinitions.* sdn702.* PKIX.* 
REM del sm_usefulTypes.* 
REM del sm_VDASupport_asn.* 
rem
pause