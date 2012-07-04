rem
attrib -r sm_fortAsn.cpp 
attrib -r sm_fortAsn.h 
echo on 
copy ..\..\..\cml\cmlasn\modules\*.asn1 
copy ..\..\libCtilMgr\src\sm_usefulTypes.asn 
copy ..\..\libcert\asn1\sm_VDASupport_asn.asn 
rem -u..\..\..\SMPDist\util\VDASnacc\cpplib\asn1\asn-usefulVDA.asn1
..\..\..\SMPDist\esnacc\bin\snaccd.exe -D -C sm_usefulTypes.asn UsefulDefinitions.asn1 UpperBounds.asn1 InformationFramework.asn1 SelectedAttributeTypes.asn1 ORAddress.asn1 X509Common.asn1 AuthenticationFramework.asn1 CertificateExtensions.asn1 PKIX.asn1 AttributeCertificateDefinitions.asn1 sdn702.asn1 sm_VDASupport_asn.asn sm_fortAsn.asn 
del UsefulDefinitions.* UpperBounds.* InformationFramework.* SelectedAttributeTypes.* ORAddress.* X509Common.* AuthenticationFramework.* CertificateExtensions.* AttributeCertificateDefinitions.* sdn702.* PKIX.* 
del sm_usefulTypes.* 
del sm_VDASupport_asn.* 
rem
pause