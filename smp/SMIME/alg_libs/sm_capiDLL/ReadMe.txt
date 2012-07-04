CAPI README NOTES

2/29/02 NOTES
IMPORTANT::: IN ORDER TO USE CERTAIN FEATURES IN THIS CTIL,
the MSDN Platform SDK Security component MUST BE INSTALLED.
This installation places certain DLLs into the system 
directories that allow the "CryptAcquireCertificatePrivateKey(...)"
call to be used on MS Win 2k systems.  Without this 
installation you will see the error:

    CAPI:  CryptAcquireCertificatePrivateKey(...) not available, 
        CANNOT USE THIS LOGIN FEATURE FOR |%s|.


1/17/02 NOTES
To use this CTIL; the following parameters are allowed:

	sm_ctilDLLd CertSubjectName ProviderName

The "CertSubjectName" parameter can be set, but is untested.
Normally this is set to "NULL" (this may be improved as customers
start to use this CTIL).

The "ProviderName" parameter can be set to a specific PROVIDER
NAME (no spaces).  Currently, only the Default (no parameter present),
"DATAKEY" (for the DataKey smart card reader interface, "Datakey RSA CSP"), 
and "MS_ENHANCED_PROV" which uses the Microsoft enhanced provider string.

Other parameters may be added as user's start using this CTIL.

Some example build arguments for the CAPI CTIL:

	sm_capiDLLd Test5 MS_ENHANCED_PROV UseInternalPublicKey
	sm_capiDLLd NULL MS_ENHANCED_PROV UseInternalPublicKey
	sm_capiDLLd NULL MS_ENHANCED_PROV
	sm_capiDLLd NULL MS_DEF_DSS_PROV
	sm_capiDLLd Signer MS_DEF_DSS_PROV
	sm_capiDLLd Encrypter MS_DEF_DSS_PROV
	sm_capiDLLd
	sm_capiDLLd Colestock MS_ENHANCED_PROV flag=signer
	sm_capiDLLd "emailAddress=Robert.Colestock@getronicsgov.com,CN=Robert Colestock,OU=VDA,O=US Government,C=US" MS_ENHANCED_PROV flag=signer

In the final 2 entries, "Colestock" is a part of the subject DN OR the full DN
with double quotes (THIS IS CASE SENSITIVE, so be sure to check the actual
subject DN of the intended user certificate) of the desired
certificate/private key pair.  The software will attempt to align that
certificate, if specified (as in this example).  The "flag=" may be 
necessary if there are several certificates of the same DN.  
"FLAG=encrypter" can also be specified.

The next section of this readme file describes the DataKey CSP specific processing.
Any such detailed logic can be added to the SFL CAPI CTIL, specific to a CSP.
It is important that no external library be linked to the CAPI CTIL to avoid
losing the generality.  If you need to link in custom loigic it can be 
accomplished (as in the DataKey case) by dynamically loading the logic of interest
and executing selectively (i.e. if the dynamic load was successful, indicating that
the .dll was in the system path and present on the system).  See 
"CSM_Capi::OPTIONAL_DataKey_CertificateLoads()" in 
./SMIME/alg_libs/sm_capiDLL/sm_capi.cpp.  This is a very powerful feature; we can 
add such non-intrusive CSP modifications to the sm_capi baseline if you are 
interested.

IMPORTANT NOTE:::::
In order to use the MS Windows 2k features mentioned in the documentation, it is 
important to load the MS Platform SDK.  Otherwise the proper #include definitions
and .dll entries are not present.  I have not yet figured out which particular
.dll files are affected (Robert.Colestock@getronicsgov.com).



DataKey CSP Specific Details:::::::::::::::::

IMPORTANT::::
In order to handle some internal and MS CAPI issues, it is important that the 
DataKey Encrypter login be setup before the DataKey Signer login.  Both must
be defined in order to perform signing and encryption operations.  The Encyrpter
MUST be defined before the Signer in order to align the 3DES/RC2 content 
encryption handle with the EXACT login that performs the RSA Key Encryption.
It seems that the CAPI instances cannot perform the RSA Key Encryption on another
instances (provider handle) content encryption.  In our SFL test environment, this
simply means that the Encryption login be defined before the Signer login AND that
there be no MS CSP Provider logins mixed with the DataKey logins.

A recent update handles the attempted DataKey SDK DLL load in order to move
certificates from the DataKey smartcard to the system registry ("MY").
If the DataKey CSP is specified AND the DLL is successfully loaded 
("BuildContainers.dll" MUST BE in the path) AND the calls to transfer the
certs was successful, then the code will have access to the certs from the
3 default Entrust generated containers on the smartcard 
("Signing Key", "Private Keys", "CA Certificates").  


RWC;NOTE:::: THIS FEATURE HAS BEEN TEMPORARILY DISABLED FOR THE DataKey CSP.
WE NO LONGER DELETE THE REGISTRY CERTIFICIATES!!!!
<<<<<Upon CTIL destruction, 
ALL SYSTEM REGISTRY CERTS (in "MY") will be deleted (this is necessary since
the code cannot determine which certs were loaded by the DataKey DLL calls
in order to be selective).>>>>>


For the DataKey CSP, in order to use this logic, some additional 
information is necessary on initialization:  PIN and Socket Number:

	sm_capiDLLd Encrypter DATAKEY PIN=datakrsa2user1 SOCKET=1

The default SOCKET is 1.  There is not default PIN.  If this information is
not provided, or the appropriate DLLs are not present, then the SFL CAPI
CTIL will simply ignore this operation and continue normally.  It might
fail aligning an appropriate certificate that matches the public key, which
will cause a failure.  (Of course, the user could hand-transfer a cert, or
load a certificate through the Internet Explorer, OR it could already be
present in the system registry; all of which will allow normal execution.)

DataKey????? 
Another recent update attempts to extract the certificate from the CAPI 
environment using the "CryptGetKeyParam(...)" call using "KP_CERTIFICATE".
This appears not to work on either the DataKey CSP nor either of the MS
default CSPs.  The logic simply ignores a failure on this attempt and
performs the above logic to attempt to align a certificate from the registry
to the public key.

DataKey????? Are you aware of any way to ask the DataKey drivers, through the 
CAPI interface to pre-login?  If so I could use the PIN above to avoid the
secondary prompt to the user (through CAPI Sign/Decrypt calls).  We needed
the PIN for transfer of certs from the DataKey card to the system registry.

