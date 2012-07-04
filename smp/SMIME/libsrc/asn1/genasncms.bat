rem
echo on 
REM copy ..\..\..\cml\cmlasn\modules\*.asn1 
REM copy ..\..\libCtilMgr\src\sm_usefulTypes.asn 
REM copy ..\..\libCert\asn1\sm_VDASupport_asn.asn 
attrib -r sm_cms.cpp
attrib -r sm_ess.cpp 
rem -u..\..\..\SMPDist\util\VDASnacc\cpplib\asn1\asn-usefulVDA.asn1 
..\..\..\..\SMPDist\bin\esnaccd.exe -a 600 -I ..\..\libCtilMgr\src -I ..\..\..\cml\cmlasn\modules -I ..\..\libcert\asn1 -D -C  sm_cms.asn1 sm_ess.asn1 
REM del UsefulDefinitions.* UpperBounds.* InformationFramework.* SelectedAttributeTypes.* ORAddress.* X509Common.* AuthenticationFramework.* CertificateExtensions.* AttributeCertificateDefinitions.* sdn702.* PKIX.* 
REM del sm_usefulTypes.* sm_VDASupport_asn.* 
attrib -r ..\..\inc\sm_cms.h 
attrib -r ..\..\inc\sm_ess.h 
del ..\..\inc\sm_cms.h 
del ..\..\inc\sm_ess.h 
move sm_cms.h ..\..\inc 
move sm_ess.h ..\..\inc 
rem
pause