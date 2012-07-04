rem
attrib -r sm_usefulTypes.cpp 
attrib -r ..\inc\sm_usefulTypes.h 
echo on  
REM OLD ..\..\..\SMPDist\esnacc\bin\snaccd.exe -D -C -VDAexport -u..\..\..\SMPDist\util\VDASnacc\cpplib\asn1\asn-usefulVDA.asn1 sm_usefulTypes.asn  
..\..\..\..\SMPDist\bin\snaccd.exe -D -C -VDAexport sm_usefulTypes.asn1  
cd ..  
del .\inc\sm_usefulTypes.h  
move src\sm_usefulTypes.h .\inc
rem
pause