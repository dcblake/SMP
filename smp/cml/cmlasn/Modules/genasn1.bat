copy ..\..\..\SMIME\libCtilMgr\src\sm_usefulTypes.asn1 .
..\..\..\..\SMPDist\bin\snacc.exe -D -l -1000 -VDAexport=EXPORT_GENSNACC -C UsefulDefinitions.asn1 UpperBounds.asn1 InformationFramework.asn1 SelectedAttributeTypes.asn1 sm_usefulTypes.asn1 ORAddress.asn1 X509Common.asn1 AuthenticationFramework.asn1 CertificateExtensions.asn1 PKIX.asn1 AttributeCertificateDefinitions.asn1 sdn702.asn1
del sm_usefulTypes.*
pause